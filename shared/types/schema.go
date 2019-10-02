package types

import (
	"encoding/json"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

type ServiceInfoOIDC struct {
	ProviderRoot   string   `json:"providerroot"`
	ClientID       string   `json:"clientid"`
	ClientSecret   string   `json:"clientsecret"`
	RequiredScopes []string `json:"requiredscopes"`
}

type ServiceInfoRequirements struct {
	AIK          bool `json:"aik"`
	Measurements bool `json:"measurements"`
}

type ServiceInfo struct {
	Root         string                  `json:"root"`
	OIDC         ServiceInfoOIDC         `json:"oidc"`
	Requirements ServiceInfoRequirements `json:"requirements"`
}

type APIResponse struct {
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

type IntermediateCertificateRequestAttestation struct {
	Static struct {
		TPMVersion attest.TPMVersion `json:"tpmversion"`
		EKPem      []byte            `json:"ekpem"`
	} `json:"static"`

	AIK attest.AttestationParameters `json:"aik"`

	Quote struct {
		Alg       attest.HashAlg `json:"alg"`
		Quote     []byte         `json:"quote"`
		Signature []byte         `json:"signature"`
	} `json:"quote"`

	Log struct {
		PCRs   []attest.PCR   `json:"pcrs"`
		PCRAlg tpm2.Algorithm `json:"algorithm"`
		Raw    []byte         `json:"raw"`
	} `json:"log"`
}

type IntermediateCertificateRequest struct {
	AuthorizationCode string                                    `json:"authorizationcode"`
	Attestation       IntermediateCertificateRequestAttestation `json:"attestation"`
}
