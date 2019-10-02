package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"

	int_cache "github.com/puiterwijk/dendraeck/client/internal/cache"
	"github.com/puiterwijk/dendraeck/shared/types"
)

func rsaEKPEM(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed to read EKs: %v", err)
	}

	var cert *x509.Certificate
	for _, ek := range eks {
		if _, ok := ek.Public.(*rsa.PublicKey); ok {
			cert = ek.Certificate
			break
		}
	}

	if cert == nil {
		return nil, errors.New("no RSA EK available")
	}

	return cert.Raw, nil
}

func CreateAttestation(cache *int_cache.Cache, nonce []byte, dotpm, domeasurements bool) (*types.IntermediateCertificateRequestAttestation, error) {
	var err error
	var out types.IntermediateCertificateRequestAttestation

	if !dotpm {
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
	q, err := aik.Quote(tpm, nonce, attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("Unable to get quote: %s", err)
	}
	out.Quote = *q

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
