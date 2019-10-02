package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jose "github.com/square/go-jose/v3"
	"golang.org/x/crypto/ssh"

	"github.com/puiterwijk/dendraeck/shared/types"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome. Please use the SSH client to use this service"))
}

var (
	serviceinfo = types.ServiceInfo{
		Root: getEnvironReq("SERVICE_ROOT"),
		OIDC: types.ServiceInfoOIDC{
			ProviderRoot:   getEnvironReq("OIDC_PROVIDER_ROOT"),
			ClientID:       getEnvironReq("OIDC_CLIENT_ID"),
			ClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
			SupportsOOB:    getEnvironBool("OIDC_SUPPORTS_OOB", true),
			RequiredScopes: strings.Split(getEnvironString("OIDC_REQUIRED_SCOPES", "openid"), ","),
		},
		Requirements: types.ServiceInfoRequirements{
			TPM:          getEnvironBool("REQUIRE_TPM", true),
			Measurements: getEnvironBool("REQUIRE_MEASUREMENT", false),
		},
	}
	tokenInfoURL                 = getEnvironReq("OIDC_TOKEN_INFO_URL")
	usedClaim                    = getEnvironString("OIDC_USERNAME_CLAIM", "sub")
	intermediateValidityDuration = getEnvironString("INTERMEDIATE_CERT_VALIDITY", "8h")
	intermediateSigningKeyPath   = getEnvironReq("INTERMEDIATE_SIGNING_KEY_PATH")
	certValidityDuration         = getEnvironString("SSH_CERT_VALIDITY", "5m")
	sshSignerPath                = getEnvironReq("SSH_CERT_SIGNING_KEY_PATH")
	addGitHubOption              = getEnvironBool("SSH_CERT_ADD_GITHUB", false)
)

var (
	intermediatePublicKey *rsa.PublicKey
	intermediateSigner    jose.Signer
	intermediateValidity  time.Duration
	certValidity          time.Duration
	sshSigner             ssh.Signer
)

func getEnvironBool(envname string, def bool) bool {
	envval := strings.ToLower(os.Getenv(envname))
	switch envval {
	case "":
		return def

	case "yes":
		return true
	case "1":
		return true
	case "true":
		return true

	case "no":
		return false
	case "0":
		return false
	case "false":
		return false

	default:
		log.Fatalf("Environment variable %s is set to %s, which is not a valid bool value", envname, envval)
	}
	return def
}

func getEnvironString(envname string, def string) string {
	envval := os.Getenv(envname)
	if envval == "" {
		return def
	}
	return envval
}

func getEnvironReq(envname string) string {
	envval := os.Getenv(envname)
	if envval == "" {
		panic(fmt.Errorf("Required configuration setting %s not set", envname))
	}
	return envval
}

func init() {
	var err error
	intermediateValidity, err = time.ParseDuration(intermediateValidityDuration)
	if err != nil {
		panic(fmt.Errorf("Error parsing intermediate validity: %s", err))
	}

	certValidity, err = time.ParseDuration(certValidityDuration)
	if err != nil {
		panic(fmt.Errorf("Error parsing cert validity: %s", err))
	}

	intkey, err := ioutil.ReadFile(intermediateSigningKeyPath)
	if err != nil {
		panic(fmt.Errorf("Error reading intermediate signing key: %s", err))
	}
	block, rest := pem.Decode(intkey)
	if len(rest) != 0 {
		panic("More data found in intermediate signing key")
	}
	if block.Type != "RSA PRIVATE KEY" {
		panic(fmt.Errorf("Unexpected key type found for intermediate key: %s", block.Type))
	}
	intermediateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("Unable to parse private intermediate key: %s", err))
	}
	intpubkey := intermediateKey.Public()
	var ok bool
	intermediatePublicKey, ok = intpubkey.(*rsa.PublicKey)
	if !ok {
		panic("Non-RSA public key?")
	}

	intermediateSigner, err = jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.PS256,
			Key:       intermediateKey,
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(fmt.Errorf("Error creating signer: %s", err))
	}
	serviceinfo.IntermediatePublicKey = x509.MarshalPKCS1PublicKey(intermediatePublicKey)

	privkey, err := ioutil.ReadFile(sshSignerPath)
	if err != nil {
		panic(fmt.Errorf("Error reading private SSH key: %s", err))
	}
	sshSigner, err = ssh.ParsePrivateKey(privkey)
	if err != nil {
		panic(fmt.Errorf("Error parsing private SSH key: %s", err))
	}

	serviceinfo.SSHPubKey = strings.Replace(string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey())), "\n", "", -1)
}

func serviceInfoHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(serviceinfo)
}

func tokenReturnHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `Hi. Please copy this token to your client: %s`, r.URL.Query().Get("code"))
}
