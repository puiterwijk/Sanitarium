package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type Service struct {
	info         ServiceInfo
	provider     *oidc.Provider
	oauth2config oauth2.Config
}

func GetService(ctx context.Context, serverroot string) (*Service, error) {
	resp, err := http.Get(serverroot + "/info")
	if err != nil {
		return nil, err
	}

	cts, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var service Service
	err = json.Unmarshal(cts, &service.info)
	if err != nil {
		return nil, err
	}

	service.provider, err = oidc.NewProvider(ctx, service.info.OIDC.ProviderRoot)
	if err != nil {
		return nil, err
	}
	service.oauth2config = oauth2.Config{
		ClientID:     service.info.OIDC.ClientID,
		ClientSecret: service.info.OIDC.ClientSecret,
		Endpoint:     service.provider.Endpoint(),
		Scopes:       service.info.OIDC.RequiredScopes,
		// TODO: Maybe accept local URL
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob",
	}
	return &service, nil
}

func (s *Service) GetAuthorizationCode() (string, error) {
	fmt.Println("Please visit ", s.oauth2config.AuthCodeURL("nostate"))
	// TODO: Maybe accept local url
	return s.acceptManualAuthzCode()
}

func (s *Service) acceptManualAuthzCode() (string, error) {
	fmt.Printf("Please enter authz code: ")

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}
