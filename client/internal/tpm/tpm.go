package tpm

import (
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket)")
	// Default value is defined in section 7.8, "NV Memory" of the latest version pdf on:
	// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
	certIndex = flag.Uint("cert-index", 0x01C00002, "NVRAM index of the certificate file")
)

func GetEKCert() (*x509.Certificate, error) {
	return readEKCert(*tpmPath, uint32(*certIndex))
}

func readEKCert(path string, certIdx uint32) (*x509.Certificate, error) {
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM at %q: %v", path, err)
	}
	defer rwc.Close()
	ekCert, err := tpm2.NVRead(rwc, tpmutil.Handle(certIdx))
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}

	return cert, nil
}
