package main

import (
	"fmt"

	oidc "github.com/coreos/go-oidc"

	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	tpm "github.com/puiterwijk/dendraeck/client/internal/tpm"
)

var (
	provider oidc.Provider
	cache    *int_cache.Cache
)

func main() {
	// TODO: Customize the name here based on binary name
	cache = int_cache.New("~/sshcache")

	fmt.Println("Hello")

	tpm.GetPubEK()
}
