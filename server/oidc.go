package main

import (
	"context"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	oidcProvider *oidc.Provider
	oauth2config oauth2.Config
)

func init() {
	oidcProvider, err := oidc.NewProvider(context.Background(), serviceinfo.OIDC.ProviderRoot)
	if err != nil {
		panic(err)
	}
	oauth2config = oauth2.Config{
		ClientID:     serviceinfo.OIDC.ClientID,
		ClientSecret: serviceinfo.OIDC.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       serviceinfo.OIDC.RequiredScopes,
		// TODO: Maybe accept local URL
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob",
	}
}
