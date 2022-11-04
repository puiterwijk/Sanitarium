//go:build linux
// +build linux

package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"

	int_cache "github.com/puiterwijk/sanitarium/client/internal/cache"
	"github.com/puiterwijk/sanitarium/shared/types"
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
	out.Static.TPMVersion = uint8(tpm.Version())
	if out.Static.EKPem, err = rsaEKPEM(tpm); err != nil {
		return nil, fmt.Errorf("Unable to get EKPEM: %s", err)
	}

	// Add AK
	ak, err := cache.GetAK()
	if err != nil {
		return nil, fmt.Errorf("Unable to get AK: %s", err)
	}
	defer cache.CloseAK(ak)
	out.AK = ak.AttestationParameters()

	if !domeasurements {
		return &out, nil
	}

	// Add Quote
	q, err := ak.Quote(tpm, nonce, attest.HashSHA256)
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
	var pcrs []attest.PCR
	if pcrs, err = tpm.PCRs(attest.HashSHA256); err != nil {
		return nil, fmt.Errorf("Unable to get PCR values: %s", err)
	}
	for _, pcr := range pcrs {
		out.Log.PCRs = append(
			out.Log.PCRs,
			types.PCRVal{
				Index:     pcr.Index,
				Digest:    pcr.Digest,
				DigestAlg: pcr.DigestAlg,
			},
		)
	}

	return &out, nil
}
