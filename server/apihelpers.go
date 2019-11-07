package main

import (
	"encoding/json"
	"net/http"

	"github.com/puiterwijk/sanitarium/shared/types"
)

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
