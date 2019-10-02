package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/go-attestation/attest"

	jose "github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"

	"github.com/puiterwijk/dendraeck/server/internal"
	"github.com/puiterwijk/dendraeck/shared/security"
	"github.com/puiterwijk/dendraeck/shared/types"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome. Please use the SSH client to use this service"))
}

var (
	// TODO: Configurable
	serviceinfo = types.ServiceInfo{
		Root: "http://localhost:8080",
		OIDC: types.ServiceInfoOIDC{
			ProviderRoot:   "https://accounts.google.com",
			ClientID:       "764142782493-lclqihkqp60ru43plumj5vpi81opcluo.apps.googleusercontent.com",
			ClientSecret:   "i-NLsLi0qCKT7oSrOpntwiYh",
			RequiredScopes: []string{"openid"},
		},
		Requirements: types.ServiceInfoRequirements{
			TPM:          true,
			Measurements: false,
		},
	}
	tokenInfoURL                 = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	usedClaim                    = "sub"
	intermediateValidityDuration = "8h"
	intermediateSigningSecret    = "foo"
	certValidityDuration         = "10m"
)

var (
	intermediateSigner   jose.Signer
	intermediateValidity time.Duration
	certValidity         time.Duration
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
}

func serviceInfoHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(serviceinfo)
}

func returnAPIError(w http.ResponseWriter, errmsg string) {
	resp := types.APIResponse{
		Success: false,
		Error:   errmsg,
	}
	json.NewEncoder(w).Encode(resp)
}

func returnAPISuccess(w http.ResponseWriter, response interface{}) {
	marshalled, err := json.Marshal(response)
	if err != nil {
		returnAPIError(w, "Error encoding response")
		return
	}
	resp := types.APIResponse{
		Success:  true,
		Response: json.RawMessage(marshalled),
	}
	json.NewEncoder(w).Encode(resp)
}

type intermediateCertInfo struct {
	Username string `json:"username"`

	TPMVersion  attest.TPMVersion            `json:"tpmversion"`
	EKPublicKey []byte                       `json:"ekpubkey"`
	AIK         attest.AttestationParameters `json:"aik"`
}

func handleIntermediateCertAuth(ctx context.Context, authzcode string) (string, error) {
	// TODO: Remove this shortcut
	return "puiterwijk", nil

	subj, err := exchangeAuthzCode(ctx, authzcode)
	if err != nil {
		log.Printf("Error exchanging authz code: %s", err)
		return "", errors.New("Error with authorization code")
	}
	return subj, nil
}

func handleIntermediateCertRequest(ctx context.Context, req types.IntermediateCertificateRequest) (*intermediateCertInfo, error) {
	var out intermediateCertInfo

	subj, err := handleIntermediateCertAuth(ctx, req.AuthorizationCode)
	if err != nil {
		return nil, fmt.Errorf("Error getting auth subject: %s", err)
	}
	out.Username = subj

	ekpubkey, err := internal.ValidateAttestation(
		&serviceinfo,
		security.CalculateNonce(req.AuthorizationCode),
		&req.Attestation,
	)
	if err != nil {
		return nil, fmt.Errorf("Error during validation of TPM assertion: %s", err)
	}
	if serviceinfo.Requirements.TPM {
		out.TPMVersion = req.Attestation.Static.TPMVersion
		out.EKPublicKey = ekpubkey
		out.AIK = req.Attestation.AIK
	}

	return &out, nil
}

func intermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		returnAPIError(w, "Invalid request method")
		return
	}

	var req types.IntermediateCertificateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	r.Body.Close()
	if err != nil {
		returnAPIError(w, "Invalid request")
		return
	}

	resp, err := handleIntermediateCertRequest(r.Context(), req)
	if err != nil {
		log.Printf("Error handling request: %s", err)
		returnAPIError(w, "Error handling request")
		return
	}

	cl := jwt.Claims{
		Subject:   resp.Username,
		Audience:  jwt.Audience{serviceinfo.Root},
		Issuer:    serviceinfo.Root,
		NotBefore: jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(intermediateValidity)),
	}

	signed, err := jwt.
		Signed(intermediateSigner).
		Claims(cl).
		Claims(resp).
		CompactSerialize()

	if err != nil {
		returnAPIError(w, "Error creating intermediate certificate")
		return
	}

	returnAPISuccess(w, signed)
}
