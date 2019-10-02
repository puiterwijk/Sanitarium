package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	"github.com/puiterwijk/dendraeck/shared/types"
)

type Service struct {
	cache *int_cache.Cache

	info         types.ServiceInfo
	provider     *oidc.Provider
	oauth2config oauth2.Config
}

func GetService(ctx context.Context, cache *int_cache.Cache, serverroot string) (*Service, error) {
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
	service.cache = cache
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

func (s *Service) GetServerRoot() string {
	return s.info.Root
}

func (s *Service) RequiresAIK() bool {
	return s.info.Requirements.AIK
}

func (s *Service) RequiresMeasurement() bool {
	return s.info.Requirements.Measurements
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

type apiError struct {
	message string
}

func (a apiError) Error() string {
	return fmt.Sprintf("API Error: %s", a.message)
}

func (s *Service) performRequest(relurl string, request interface{}, response interface{}) error {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(request)
	if err != nil {
		return err
	}
	resp, err := http.Post(s.info.Root+relurl, "text/json", &buf)
	if err != nil {
		return err
	}
	var apiresp types.APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiresp)
	if err != nil {
		return err
	}
	if !apiresp.Success {
		return apiError{
			message: apiresp.Error,
		}
	}
	return json.Unmarshal(apiresp.Response, response)
}

func (s *Service) RetrieveIntermediateCertificate(authzcode string, attestation *types.IntermediateCertificateRequestAttestation) error {
	var request types.IntermediateCertificateRequest

	request.AuthorizationCode = authzcode
	request.Attestation = *attestation

	var response string

	if err := s.performRequest("/cert/intermediate", request, &response); err != nil {
		return err
	}

	return s.cache.SaveIntermediateCertificate(response, s.info.Root)
}
