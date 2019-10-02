package main

import (
	"encoding/json"
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
		Root: os.Getenv("SERVICE_ROOT"),
		OIDC: types.ServiceInfoOIDC{
			ProviderRoot:   os.Getenv("OIDC_PROVIDER_ROOT"),
			ClientID:       os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
			SupportsOOB:    getEnvironBool("OIDC_SUPPORTS_OOB", true),
			RequiredScopes: strings.Split(os.Getenv("OIDC_REQUIRED_SCOPES"), ","),
		},
		Requirements: types.ServiceInfoRequirements{
			TPM:          getEnvironBool("REQUIRE_TPM", true),
			Measurements: getEnvironBool("REQUIRE_MEASUREMENT", false),
		},
	}
	tokenInfoURL                 = os.Getenv("OIDC_TOKEN_INFO_URL")
	usedClaim                    = getEnvironString("OIDC_USERNAME_CLAIM", "sub")
	intermediateValidityDuration = getEnvironString("INTERMEDIATE_CERT_VALIDITY", "8h")
	intermediateSigningSecret    = os.Getenv("INTERMEDIATE_SIGNING_SECRET")
	certValidityDuration         = getEnvironString("SSH_CERT_VALIDITY", "5m")
	sshSignerPath                = os.Getenv("SSH_CERT_SIGNER_KEY_PATH")
	addGitHubOption              = getEnvironBool("SSH_CERT_ADD_GITHUB", false)
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

var (
	intermediateSigner   jose.Signer
	intermediateValidity time.Duration
	certValidity         time.Duration
	sshSigner            ssh.Signer
)

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

	intermediateSigner, err = jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       []byte(intermediateSigningSecret),
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(fmt.Errorf("Error creating signer: %s", err))
	}

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
