package types

import "encoding/json"

type ServiceInfoOIDC struct {
	ProviderRoot   string   `json:"providerroot"`
	ClientID       string   `json:"clientid"`
	ClientSecret   string   `json:"clientsecret"`
	RequiredScopes []string `json:"requiredscopes"`
}

type ServiceInfo struct {
	OIDC ServiceInfoOIDC `json:"oidc"`
}

type APIResponse struct {
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

type IntermediateCertificateRequest struct {
	AuthorizationCode string `json:"authorizationcode"`
}
