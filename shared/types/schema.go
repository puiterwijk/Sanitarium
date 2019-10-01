package types

type ServiceInfoOIDC struct {
	ProviderRoot   string   `json:"providerroot"`
	ClientID       string   `json:"clientid"`
	ClientSecret   string   `json:"clientsecret"`
	RequiredScopes []string `json:"requiredscopes"`
}

type ServiceInfo struct {
	OIDC ServiceInfoOIDC `json:"oidc"`
}

type IntermediateCertificateRequest struct {
}
