package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/puiterwijk/dendraeck/server/internal"
	"github.com/puiterwijk/dendraeck/shared/security"
	"github.com/puiterwijk/dendraeck/shared/types"
	"github.com/square/go-jose/v3/jwt"
)

type intermediateCertInfo struct {
	Username string `json:"username"`

	TPMVersion  attest.TPMVersion            `json:"tpmversion"`
	EKPublicKey []byte                       `json:"ekpubkey"`
	AIK         attest.AttestationParameters `json:"aik"`
}

func handleIntermediateCertAuth(ctx context.Context, authzcode string) (string, error) {
	subj, err := exchangeAuthzCode(ctx, authzcode)
	if err != nil {
		log.Printf("Error exchanging authz code: %s", err)
		return "", errors.New("Error with authorization code")
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
		out.TPMVersion = req.Attestation.Static.TPMVersion
		out.EKPublicKey = ekpubkey
		out.AIK = req.Attestation.AIK
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

	signed, err := jwt.
		Signed(intermediateSigner).
		Claims(cl).
		Claims(resp).
		CompactSerialize()

	if err != nil {
		returnAPIError(w, "Error creating intermediate certificate")
		return
	}

	returnAPISuccess(w, signed)
}
