package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	oidc "github.com/coreos/go-oidc"

	"github.com/puiterwijk/sanitarium/client/internal"
	int_cache "github.com/puiterwijk/sanitarium/client/internal/cache"
	"github.com/puiterwijk/sanitarium/client/internal/config"
	service "github.com/puiterwijk/sanitarium/client/internal/service"
	"github.com/puiterwijk/sanitarium/shared/security"
)

var (
	provider      oidc.Provider
	cache         *int_cache.Cache
	sshServerName string
)

var (
	serverRoot = os.Getenv("SERVER_ROOT")

	attemptTPM         = false
	attemptMeasurement = false
)

func determineHostname() string {
	var inArg bool

	for _, arg := range os.Args[1:] {
		if inArg {
			inArg = false
			continue
		}
		if strings.HasPrefix(arg, "--") {
			inArg = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}

		split := strings.Split(arg, "@")
		if len(split) == 1 {
			return split[0]
		} else if len(split) == 2 {
			return split[1]
		} else {
			log.Fatalf("Error parsing possible hostname: %s", arg)
		}
	}
	return ""
}

var cfgFileLocations = []string{"/etc/sanitarium/server.cfg", "~/.sanitarium/server.cfg"}

func getServerFromCfgFile() string {
	for _, loc := range cfgFileLocations {
		if strings.Contains(loc, "~") {
			user, err := user.Current()
			if err != nil {
				log.Printf("Error getting user homedir: %s", err)
				continue
			}
			loc = strings.Replace(loc, "~", user.HomeDir, 1)
		}

		cts, err := ioutil.ReadFile(loc)
		if err == nil {
			return strings.TrimSpace(string(cts))
		} else if os.IsNotExist(err) {
			continue
		} else {
			log.Printf("Error reading config file %s: %s", loc, err)
		}
	}
	return ""
}

func main() {
	if serverRoot == "" {
		serverRoot = getServerFromCfgFile()
		if serverRoot == "" {
			serverRoot = config.DefaultServerRoot
		}
	}

	if len(os.Args) < 2 {
		fmt.Println("Welcome to Sanitarium")
		fmt.Println("To use, just add the standard SSH arguments to the command")
		fmt.Println("This build has default server:", config.DefaultServerRoot)
		fmt.Println("Configured hostname (/etc/sanitarium-server.cfg, ~/.sanitarium/server.cfg):", serverRoot)

		log.Fatalf("No hostname provided")
	}
	sshServerName = determineHostname()
	if sshServerName == "" {
		log.Fatalf("No hostname detected")
	}

	cache = int_cache.New(serverRoot)
	defer cache.Close()

	cert, key := getSSHCertAndKey(cache)
	executeSSH(cert, key)
}

func executeSSH(cert, key string) {
	cmd, err := exec.LookPath("ssh")
	if err != nil {
		log.Fatalf("Unable to find SSH: %s", err)
	}
	args := []string{
		"ssh",
		"-i",
		key,
	}
	args = append(args, os.Args[1:]...)

	syscall.Exec(
		cmd,
		args,
		os.Environ(),
	)
}

func getSSHCertAndKeyFromIntermediate(cache *int_cache.Cache, svc *service.Service) (string, string, error) {
	fmt.Fprintln(os.Stderr, "Getting SSH cert and key with intermediate cert")

	err := svc.RetrieveSSHCertificate(sshServerName)
	if err != nil {
		log.Fatalf("Error retrieving SSH certificate with intermediate: %s", err)
	}
	return cache.GetSSHCert(sshServerName)
}

func getSSHCertAndKey(cache *int_cache.Cache) (string, string) {
	// First: Check whether we already have an SSH cert
	cert, key, err := cache.GetSSHCert(sshServerName)
	if err == nil {
		return cert, key
	}

	// We have no SSH cert, initiate service
	svc, err := service.GetService(context.Background(), cache, serverRoot)
	if err != nil {
		log.Fatalf("Error getting service info: %s", err)
	}

	// Second: Check if we have an intermediate certificate
	_, err = cache.GetIntermediateCertificate()
	if err == nil {
		// We have a usable intermediate
		cert, key, err := getSSHCertAndKeyFromIntermediate(cache, svc)
		if err == nil {
			return cert, key
		}
		fmt.Fprintln(os.Stderr, "Error using existing intermediate cert: ", err, " (Getting new one)")
	}
	if !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No valid intermediate cert:", err)
	}

	// Last: Get a new intermediate certificate
	authzcode, err := svc.GetAuthorizationCode()
	if err != nil {
		log.Fatalf("Error getting authorization code: %s", err)
	}

	nonce := security.CalculateNonce(authzcode)
	attestation, err := internal.CreateAttestation(
		cache,
		nonce,
		attemptTPM,
		attemptMeasurement,
	)
	if err != nil {
		log.Fatalf("Error creating attestation: %s", err)
	}

	if err := svc.RetrieveIntermediateCertificate(authzcode, attestation); err != nil {
		log.Fatalf("Error retrieving intermediate certificate: %s", err)
	}

	// We have a usable intermediate
	cert, key, err = getSSHCertAndKeyFromIntermediate(cache, svc)
	if err == nil {
		return cert, key
	}
	log.Fatal("Error using just-received intermediate certificate: ", err)

	return "", ""
}
