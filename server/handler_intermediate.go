package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/square/go-jose/v3/jwt"

	"github.com/puiterwijk/sanitarium/server/internal"
	"github.com/puiterwijk/sanitarium/shared/security"
	"github.com/puiterwijk/sanitarium/shared/types"
)

type intermediateCertInfo struct {
	Username string `json:"username"`

	TPMVersion  attest.TPMVersion            `json:"tpmversion"`
	EKPublicKey []byte                       `json:"ekpubkey"`
	AK          attest.AttestationParameters `json:"ak"`
}

func handleIntermediateCertAuth(ctx context.Context, authzcode string) (string, error) {
	subj, err := exchangeAuthzCode(ctx, authzcode)
	if err != nil {
		return "", fmt.Errorf("Error with authorization code: %s", err)
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
		out.TPMVersion = attest.TPMVersion(req.Attestation.Static.TPMVersion)
		out.EKPublicKey = ekpubkey
		out.AK = req.Attestation.AK
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

	log.Println("Signing intermediate certificate for", resp.Username)
	signed, err := jwt.
		Signed(intermediateSigner).
		Claims(cl).
		Claims(resp).
		CompactSerialize()

	if err != nil {
		returnAPIError(w, "Error creating intermediate certificate")
		return
	}

	var certresp types.IntermediateCertificateResponse
	certresp.IntermediateCertificate = signed

	returnAPISuccess(w, certresp)
}
