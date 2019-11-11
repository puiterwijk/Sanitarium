// +build runwithgorun

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// The Microsoft published list of trusted TPM EK CAs
	// Source: https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates
	TPMCABURL = "https://go.microsoft.com/fwlink/?linkid=2097925"

	FileHeader = `// Code generated by extractor.go; DO NOT EDIT.

package tpmcas

`

	BytesPerLine = 20
)

func getcab() string {
	fmt.Println("Downloading TPM CA cab file")

	cabfile, err := ioutil.TempFile("", "sanitarium-tpmcas-extract.*.cab")
	if err != nil {
		panic(err)
	}
	defer cabfile.Close()

	resp, err := http.Get(TPMCABURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(cabfile, resp.Body)
	if err != nil {
		panic(err)
	}

	return cabfile.Name()
}

func extractcab(cabpath string) string {
	fmt.Println("Extracting TPM CA cab file")

	extrdir, err := ioutil.TempDir("", "sanitarium-tpmcas-extract")
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(
		"cabextract",
		cabpath,
		"--directory", extrdir,
	)
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	return extrdir
}

func getcertpathsfortype(vendortypedir string) (certs []string) {
	certfiles, err := ioutil.ReadDir(vendortypedir)
	if os.IsNotExist((err)) {
		// Some vendors don't have intermediates, that's fine.
		return
	}
	if err != nil {
		panic(err)
	}

	for _, cert := range certfiles {
		certs = append(
			certs,
			filepath.Join(vendortypedir, cert.Name()),
		)
	}

	return
}

func getcertpaths(rootdir string) (roots, intermediates []string) {
	vendors, err := ioutil.ReadDir(rootdir)
	if err != nil {
		panic(err)
	}

	for _, vendordir := range vendors {
		if !vendordir.IsDir() {
			continue
		}

		vendor_roots := getcertpathsfortype(
			filepath.Join(rootdir, vendordir.Name(), "RootCA"),
		)
		vendor_intermediates := getcertpathsfortype(
			filepath.Join(rootdir, vendordir.Name(), "IntermediateCA"),
		)

		roots = append(roots, vendor_roots...)
		intermediates = append(intermediates, vendor_intermediates...)
	}

	return
}

func writebytes(out io.Writer, cts []byte) {
	const hextable = "0123456789abcdef"

	var err error
	var inline int

	for _, bt := range cts {
		if inline == BytesPerLine {
			_, err = fmt.Fprintf(out, "\n    ")
			if err != nil {
				panic(err)
			}
			inline = 0
		}

		chr1 := string(hextable[bt>>4])
		chr2 := string(hextable[bt&0x0f])

		_, err = fmt.Fprintf(out, "0x%s%s, ", chr1, chr2)

		if err != nil {
			panic(err)
		}

		inline++
	}
}

func generatefile(outdir string, outvars map[string][]byte) string {
	outfile, err := ioutil.TempFile(outdir, "certificates.extracting.*.tmp")
	if err != nil {
		panic(err)
	}
	defer outfile.Close()

	_, err = outfile.Write([]byte(FileHeader))
	if err != nil {
		panic(err)
	}

	for varname, cts := range outvars {
		_, err = outfile.Write([]byte(fmt.Sprintf(`var %s = []byte{
    `, varname)))
		if err != nil {
			panic(err)
		}

		writebytes(outfile, cts)

		_, err = outfile.Write([]byte(`
}
`))
	}

	return outfile.Name()
}

func certerrorfatal(certpath string, err error) bool {
	// Allow some invalidly encoded STM Micro intermediate certificates to not be fatal
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM ECC Intermediate CA 01.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM EK Intermediate CA 01.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM EK Intermediate CA 02.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM EK Intermediate CA 03.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM EK Intermediate CA 04.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	if strings.HasSuffix(certpath, "STMicro/IntermediateCA/STM TPM EK Intermediate CA 05.crt") && err.Error() == "asn1: structure error: integer not minimally-encoded" {
		return false
	}
	return true
}

func concatcerts(paths []string) (out []byte) {
	var haderror bool

	for _, path := range paths {
		cts, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}

		if cts[0] == '-' {
			// Assume this is PEM
			block, rest := pem.Decode(cts)
			if block == nil {
				fmt.Fprintf(os.Stderr, "Error in certificate %s (assumed PEM): no block returned (FATAL)\n", path)
				haderror = true
			}
			if len(rest) != 0 {
				fmt.Fprintf(os.Stderr, "Error in certificate %s: extra contents found (FATAL)\n", path)
				haderror = true
			}
			if block.Type != "CERTIFICATE" {
				fmt.Fprintf(os.Stderr, "Error in certificate %s: PEM block type %s != CERTIFICATE (FATAL)\n", path, block.Type)
			}
			cts = block.Bytes
		}

		_, err = x509.ParseCertificate(cts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in certificate %s: %s ", path, err)
			// There may be certificates with known parse errors we ignore for now
			if certerrorfatal(path, err) {
				haderror = true
				fmt.Fprintf(os.Stderr, "(FATAL)\n")
			} else {
				fmt.Fprintf(os.Stderr, "(Allowed)\n")
				// Do not embed this certificate
				continue
			}
		}

		out = append(out, cts...)
	}

	if haderror {
		// Make sure that all certs are exported or we error out
		panic("Failed to parse all certs")
	}
	return
}

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	fmt.Println("Grabbing cabinet file...")
	cabfile := getcab()
	defer os.Remove(cabfile)

	fmt.Println("Extracting cabinet file...")
	extrdir := extractcab(cabfile)
	defer os.RemoveAll(extrdir)

	fmt.Println("Listing certificates...")
	rootpaths, intermediatepaths := getcertpaths(extrdir)

	// Sort so that the list of certificates is constant between exports
	sort.Strings(rootpaths)
	sort.Strings(intermediatepaths)

	fmt.Println("Parsing certificates...")
	roots := concatcerts(rootpaths)
	intermediates := concatcerts(intermediatepaths)

	fmt.Println("Generating file...")
	generated := generatefile(cwd, map[string][]byte{
		"rootcas":         roots,
		"intermediatecas": intermediates,
	})

	fmt.Println("Putting in the correct place...")
	outfile := filepath.Join(cwd, "certificates.generated.go")
	err = os.Rename(generated, outfile)

	if err != nil {
		panic(err)
	}
}
