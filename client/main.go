package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	oidc "github.com/coreos/go-oidc"

	"github.com/puiterwijk/dendraeck/client/internal"
	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	service "github.com/puiterwijk/dendraeck/client/internal/service"
	"github.com/puiterwijk/dendraeck/shared/security"
)

var (
	provider      oidc.Provider
	cache         *int_cache.Cache
	sshServerName string
)

const (
	// TODO: Get from somewhere
	serverRoot = "http://localhost:8080"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("No hostname provided?")
	}
	if strings.HasPrefix(os.Args[1], "-") {
		log.Fatalf("Please use hostname as first argument (fixing this is TODO)")
	}
	sshServerName = os.Args[1]

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
	fmt.Println("Getting SSH cert and key with intermediate cert")

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
		fmt.Println("Error using existing intermediate cert: ", err, " (Getting new one)")
	}
	if !os.IsNotExist(err) {
		fmt.Println("No valid intermediate cert:", err)
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
		svc.RequiresTPM(),
		svc.RequiresMeasurement(),
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
