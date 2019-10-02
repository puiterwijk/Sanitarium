package types

import (
	"encoding/json"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

type ServiceInfoOIDC struct {
	ProviderRoot   string   `json:"providerroot"`
	SupportsOOB    bool     `json:"supportsoob"`
	ClientID       string   `json:"clientid"`
	ClientSecret   string   `json:"-"`
	RequiredScopes []string `json:"requiredscopes"`
}

type ServiceInfoRequirements struct {
	TPM          bool `json:"tpm"`
	Measurements bool `json:"measurements"`
}

type ServiceInfo struct {
	Root         string                  `json:"root"`
	SSHPubKey    string                  `json:"sshpubkey"`
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

	Quote attest.Quote `json:"quote"`

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

type IntermediateCertificateResponse struct {
	IntermediateCertificate string `json:"intermediatecert"`
}

type SSHCertRequest struct {
	IntermediateCert string `json:"intermediatecert"`
	PublicKey        []byte `json:"publickey"`

	Servername string `json:"servername"`
}

type SSHCertResponse struct {
	Restrictions struct {
		Servername string `json:"servername"`
	} `json:"restrictions"`

	Certificate struct {
		IsCrypted       bool   `json:"crypted"`
		Contents        []byte `json:"contents"`
		CryptedContents struct {
			Contents            []byte                      `json:"contents"`
			Nonce               []byte                      `json:"nonce"`
			EncryptedCredential *attest.EncryptedCredential `json:"encrypted"`
		} `json:"cryptedcontents"`
	} `json:"certificate"`
}
