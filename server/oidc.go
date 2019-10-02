package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	oidcProvider *oidc.Provider
	oauth2config oauth2.Config
	verifier     *oidc.IDTokenVerifier
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
	if !serviceinfo.OIDC.SupportsOOB {
		oauth2config.RedirectURL = serviceinfo.Root + "/token"
	}
	verifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: serviceinfo.OIDC.ClientID,
	})
}

type tokenInfo struct {
	Azp    string `json:"azp"`
	Aud    string `json:"aud"`
	Sub    string `json:"sub"`
	Scopes string `json:"scope"`
}

func setMin(required, provided []string) []string {
	requiredmap := make(map[string]string)

	for _, req := range required {
		requiredmap[req] = ""
	}

	for _, prov := range provided {
		delete(requiredmap, prov)
	}

	var missing []string
	for needed := range requiredmap {
		missing = append(missing, needed)
	}
	return missing
}

func checkTokenScopes(ctx context.Context, accesstoken string) error {
	resp, err := http.PostForm(
		tokenInfoURL,
		url.Values{
			"token":         {accesstoken},
			"access_token":  {accesstoken},
			"client_id":     {serviceinfo.OIDC.ClientID},
			"client_secret": {serviceinfo.OIDC.ClientSecret},
		},
	)
	if err != nil {
		return fmt.Errorf("Error retrieving token info: %s", err)
	}
	var info tokenInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Error parsing token info: %s", err)
	}

	scopes := strings.Split(info.Scopes, " ")

	missingScopes := setMin(serviceinfo.OIDC.RequiredScopes, scopes)

	if len(missingScopes) == 0 {
		return nil
	}
	return fmt.Errorf("Missing scopes: %s", missingScopes)
}

func exchangeAuthzCode(ctx context.Context, authzcode string) (string, error) {
	oauth2token, err := oauth2config.Exchange(ctx, authzcode)
	if err != nil {
		return "", err
	}

	if err = checkTokenScopes(ctx, oauth2token.AccessToken); err != nil {
		return "", err
	}

	rawIDToken, ok := oauth2token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("No id token in response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", err
	}

	if idToken.AccessTokenHash != "" {
		err = idToken.VerifyAccessToken(oauth2token.AccessToken)
		if err != nil {
			return "", err
		}
	}

	var claims map[string]interface{}
	err = idToken.Claims(&claims)
	if err != nil {
		return "", err
	}

	rusername, ok := claims[usedClaim]
	if !ok {
		return "", errors.New("Username claim is not in token")
	}
	username, ok := rusername.(string)
	if !ok {
		return "", errors.New("Username claim is not a string")
	}

	return username, nil
}
