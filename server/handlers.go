package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/puiterwijk/dendraeck/shared/types"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome. Please use the SSH client to use this service"))
}

var (
	// TODO: Configurable
	serviceinfo = types.ServiceInfo{
		OIDC: types.ServiceInfoOIDC{
			ProviderRoot:   "https://accounts.google.com",
			ClientID:       "764142782493-lclqihkqp60ru43plumj5vpi81opcluo.apps.googleusercontent.com",
			ClientSecret:   "i-NLsLi0qCKT7oSrOpntwiYh",
			RequiredScopes: []string{"openid"},
		},
	}
	tokenInfoURL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	usedClaim    = "sub"
)

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

func handleIntermediateCertRequest(ctx context.Context, req types.IntermediateCertificateRequest) (string, error) {
	subj, err := exchangeAuthzCode(ctx, req.AuthorizationCode)
	if err != nil {
		log.Printf("Error exchanging authz code: %s", err)
		return "", errors.New("Error with authorization code")
	}
	return subj, nil
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

	returnAPISuccess(w, resp)
}
