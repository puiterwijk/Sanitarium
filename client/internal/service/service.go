package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-attestation/attest"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/crypto/ssh"
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
	service.cache.SetSSHPublicKey(service.info.SSHPubKey)

	service.provider, err = oidc.NewProvider(ctx, service.info.OIDC.ProviderRoot)
	if err != nil {
		return nil, err
	}
	redirurl := "urn:ietf:wg:oauth:2.0:oob"
	if !service.info.OIDC.SupportsOOB {
		redirurl = service.info.Root + "/token"
	}
	service.oauth2config = oauth2.Config{
		ClientID:     service.info.OIDC.ClientID,
		ClientSecret: service.info.OIDC.ClientSecret,
		Endpoint:     service.provider.Endpoint(),
		Scopes:       service.info.OIDC.RequiredScopes,
		// TODO: Maybe accept local URL
		RedirectURL: redirurl,
	}
	return &service, nil
}

func (s *Service) GetServerRoot() string {
	return s.info.Root
}

func (s *Service) RequiresTPM() bool {
	return s.info.Requirements.TPM
}

func (s *Service) RequiresMeasurement() bool {
	return s.info.Requirements.Measurements
}

func (s *Service) GetAuthorizationCode() (string, error) {
	fmt.Fprintln(os.Stderr, "Please visit ", s.oauth2config.AuthCodeURL("nostate"))
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

	var response types.IntermediateCertificateResponse

	if err := s.performRequest("/cert/intermediate", request, &response); err != nil {
		return err
	}

	return s.cache.SaveIntermediateCertificate(response.IntermediateCertificate)
}

func (s *Service) RetrieveSSHCertificate(servername string) error {
	intcert, err := s.cache.GetIntermediateCertificate()
	if err != nil {
		return fmt.Errorf("Error while retrieving intermediate cert: %s", intcert)
	}

	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Error generating new private key: %s", err)
	}
	keybytes, err := x509.MarshalPKCS8PrivateKey(rsakey)
	if err != nil {
		return fmt.Errorf("Error marshalling key to PKCS8: %s", err)
	}
	privkey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keybytes,
	})
	pubsshkey, err := ssh.NewPublicKey(rsakey.Public())
	if err != nil {
		return fmt.Errorf("Error generating SSH public key: %s", err)
	}

	var (
		request  types.SSHCertRequest
		response types.SSHCertResponse
	)
	request.IntermediateCert = intcert
	request.PublicKey = pubsshkey.Marshal()
	request.Servername = servername

	if err := s.performRequest("/cert/ssh", request, &response); err != nil {
		return err
	}

	if response.Certificate.IsCrypted {
		response.Certificate.Contents, err = s.activateCredential(
			response.Certificate.CryptedContents.EncryptedCredential,
			response.Certificate.CryptedContents.Nonce,
			response.Certificate.CryptedContents.Contents,
		)
		if err != nil {
			return fmt.Errorf("Error activating credential: %s", err)
		}
	}

	return s.cache.SaveSSHCert(servername, privkey, response.Certificate.Contents)
}

func (s *Service) activateCredential(ec *attest.EncryptedCredential, nonce, encrypted []byte) ([]byte, error) {
	aik, err := s.cache.GetAIK()
	if err != nil {
		return nil, fmt.Errorf("Unable to get AIK: %s", err)
	}
	defer s.cache.CloseAIK(aik)
	secret, err := aik.ActivateCredential(s.cache.GetTPM(), *ec)
	if err != nil {
		return nil, fmt.Errorf("Unable to activate credential: %s", err)
	}

	blockcipher, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("Error creating AES cipher: %s", err)
	}
	aead, err := cipher.NewGCM(blockcipher)
	if err != nil {
		return nil, fmt.Errorf("Error creating GCM cipher: %s", err)
	}

	return aead.Open(
		nil,
		nonce,
		encrypted,
		nil,
	)
}
