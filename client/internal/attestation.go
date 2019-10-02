package internal

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	"github.com/puiterwijk/dendraeck/shared/types"
)

func rsaEKPEM(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed to read EKs: %v", err)
	}

	var (
		pk  *rsa.PublicKey
		buf bytes.Buffer
	)
	for _, ek := range eks {
		if pub, ok := ek.Public.(*rsa.PublicKey); ok {
			pk = pub
			break
		}
	}

	if pk == nil {
		return nil, errors.New("no EK available")
	}

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pk)}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode: %v", err)
	}
	return buf.Bytes(), nil
}

func CreateAttestation(cache *int_cache.Cache, nonce []byte, doaik, domeasurements bool) (*types.IntermediateCertificateRequestAttestation, error) {
	var err error
	var out types.IntermediateCertificateRequestAttestation

	if !doaik {
		return &out, nil
	}

	tpm := cache.GetTPM()

	// Add static info
	out.Static.TPMVersion = tpm.Version()
	if out.Static.EKPem, err = rsaEKPEM(tpm); err != nil {
		return nil, fmt.Errorf("Unable to get EKPEM: %s", err)
	}

	// Add AIK
	aik, err := cache.GetAIK()
	if err != nil {
		return nil, fmt.Errorf("Unable to get AIK: %s", err)
	}
	defer cache.CloseAIK(aik)
	out.AIK = aik.AttestationParameters()

	if !domeasurements {
		return &out, nil
	}

	// Add Quote
	out.Quote.Alg = attest.HashSHA256
	q, err := aik.Quote(tpm, nonce, attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("Unable to get quote: %s", err)
	}
	out.Quote.Quote = q.Quote
	out.Quote.Signature = q.Signature

	// Add log
	if out.Log.Raw, err = tpm.MeasurementLog(); err != nil {
		return nil, fmt.Errorf("Unable to get measurement log: %s", err)
	}

	// Add PCR values
	if out.Log.PCRs, err = tpm.PCRs(attest.HashSHA256); err != nil {
		return nil, fmt.Errorf("Unable to get PCR values: %s", err)
	}

	return &out, nil
}
