package types

import (
	"crypto"
	"encoding/json"
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
	Root                  string                  `json:"root"`
	SSHPubKey             string                  `json:"sshpubkey"`
	IntermediatePublicKey []byte                  `json:"intermediatepubkey"`
	OIDC                  ServiceInfoOIDC         `json:"oidc"`
	Requirements          ServiceInfoRequirements `json:"requirements"`
}

type APIResponse struct {
	Success  bool            `json:"success"`
	Error    string          `json:"error,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

type PCRVal struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash
}

type IntermediateCertificateRequestAttestation struct {
	Static struct {
		TPMVersion uint8  `json:"tpmversion"`
		EKPem      []byte `json:"ekpem"`
	} `json:"static"`

	AIK struct {
		Public                  []byte
		UseTCSDActivationFormat bool
		CreateData              []byte
		CreateAttestation       []byte
		CreateSignature         []byte
	} `json:"aik"`

	Quote struct {
		Quote     []byte
		Signature []byte
	} `json:"quote"`

	Log struct {
		PCRs []PCRVal `json:"pcrs"`
		Raw  []byte   `json:"raw"`
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

type SSHCertResponseEncryptedCredential struct {
	Credential []byte
	Secret     []byte
}

type SSHCertResponse struct {
	Restrictions struct {
		Servername string `json:"servername"`
	} `json:"restrictions"`

	Certificate struct {
		IsCrypted       bool   `json:"crypted"`
		Contents        []byte `json:"contents"`
		CryptedContents struct {
			Contents            []byte                              `json:"contents"`
			Nonce               []byte                              `json:"nonce"`
			EncryptedCredential *SSHCertResponseEncryptedCredential `json:"encrypted"`
		} `json:"cryptedcontents"`
	} `json:"certificate"`
}
