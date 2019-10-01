package main

import (
	"encoding/json"
	"net/http"

	"github.com/puiterwijk/dendraeck/server/types"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome. Please use the SSH client to use this service"))
}

var (
	serviceinfo = types.ServiceInfo{
		OIDC: types.ServiceInfoOIDC{
			ProviderRoot:   "https://accounts.google.com",
			ClientID:       "764142782493-lclqihkqp60ru43plumj5vpi81opcluo.apps.googleusercontent.com",
			ClientSecret:   "",
			RequiredScopes: []string{"openid", "profile"},
		},
	}
)

func serviceInfoHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(serviceinfo)
}

func intermediateCertHandler(w http.ResponseWriter, r *http.Request) {

}
