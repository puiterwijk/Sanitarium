package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	oidc "github.com/coreos/go-oidc"

	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	service "github.com/puiterwijk/dendraeck/client/internal/service"
)

var (
	provider oidc.Provider
	cache    *int_cache.Cache
)

const (
	// TODO: Get from somewhere
	serverURL = "http://localhost:8080/"
)

func main() {
	flag.Parse()

	cert, key := getSSHCertAndKey()
	executeSSH(cert, key)
}

func executeSSH(cert, key string) {
	fmt.Println("Executing SSH with cert", cert, "key", key)
}

func getSSHCertAndKey() (string, string) {
	// TODO: Customize the name here based on binary name
	cache = int_cache.New("~/sshcache")

	// First: Check whether we already have an SSH cert
	cert, key, err := cache.GetTemporarySSHCert()
	if err == nil {
		return cert, key
	} else if !os.IsNotExist(err) {
		log.Fatalf("Error while checking cache for temp key: %s", err)
	}

	svc, err := service.GetService(context.TODO(), serverURL)
	if err != nil {
		log.Fatalf("Error getting service info: %s", err)
	}

	authzcode, err := svc.GetAuthorizationCode()
	if err != nil {
		log.Fatalf("Error getting authorization code: %s", err)
	}

	// TODO: Perform TPM dance

	if err := svc.RetrieveIntermediateCertificate(authzcode, ""); err != nil {
		log.Fatalf("Error retrieving intermediate certificate: %s", err)
	}

	log.Fatal("Was unable to get an SSH key")
	return "", ""
}
