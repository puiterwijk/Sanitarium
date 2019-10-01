package main

import (
	"flag"
	"fmt"
	"log"

	oidc "github.com/coreos/go-oidc"

	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	tpm "github.com/puiterwijk/dendraeck/client/internal/tpm"
)

var (
	provider oidc.Provider
	cache    *int_cache.Cache
)

func main() {
	flag.Parse()

	// TODO: Customize the name here based on binary name
	cache = int_cache.New("~/sshcache")

	ekcert, err := tpm.GetEKCert()
	if err != nil {
		log.Fatalf("Error getting EKCert: %s", err)
	}
	fmt.Println(ekcert)
}
