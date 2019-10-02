package main

import (
	"encoding/json"
	"net/http"

	"github.com/puiterwijk/dendraeck/shared/types"
)

func sshCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		returnAPIError(w, "Invalid request method")
		return
	}

	var req types.SSHCertRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	r.Body.Close()
	if err != nil {
		returnAPIError(w, "Invalid request")
		return
	}

}
