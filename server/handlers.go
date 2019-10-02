package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	// TODO: Configurable
	serviceinfo = types.ServiceInfo{
		Root: "https://server-dendraeck.e4ff.pro-eu-west-1.openshiftapps.com",
		OIDC: types.ServiceInfoOIDC{
			//ProviderRoot:   "https://accounts.google.com",
			//ClientID:       "764142782493-lclqihkqp60ru43plumj5vpi81opcluo.apps.googleusercontent.com",
			//ClientSecret:   "i-NLsLi0qCKT7oSrOpntwiYh",
			ProviderRoot:   "https://iddev.fedorainfracloud.org/openidc/",
			ClientID:       "sshcerttest",
			ClientSecret:   "AAL37W2nbPTLuHdniCNJFlksyXW1yaoK",
			SupportsOOB:    false,
			RequiredScopes: []string{"openid", "profile"},
		},
		Requirements: types.ServiceInfoRequirements{
			TPM:          true,
			Measurements: false,
		},
	}
	//tokenInfoURL                 = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	tokenInfoURL                 = "https://iddev.fedorainfracloud.org/openidc/TokenInfo"
	usedClaim                    = "sub"
	intermediateValidityDuration = "8h"
	intermediateSigningSecret    = "foo"
	certValidityDuration         = "10m"
	sshSignerPath                = os.Getenv("SIGNER_KEY_PATH")
	addGitHubOption              = true
)

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
