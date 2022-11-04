package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-attestation/attest"

	"github.com/puiterwijk/sanitarium/server/internal/tpmcas"
	"github.com/puiterwijk/sanitarium/shared/types"
)

var (
	tpmVerifyOpts *x509.VerifyOptions
)

func init() {
	var err error

	tpmVerifyOpts, err = tpmcas.GetTPMEKVerifyOptions()
	if err != nil {
		panic(err)
	}
}

func validateTPMEKCert(cert *x509.Certificate) ([]byte, error) {
	pkey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Non-RSA EK cert")
	}

	pubkey := x509.MarshalPKCS1PublicKey(pkey)

	cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	_, err := cert.Verify(*tpmVerifyOpts)
	return pubkey, err
}

func validateEvents(event []attest.Event) error {
	return errors.New("TPM event validation TODO")
}

func ValidateAttestation(serviceinfo *types.ServiceInfo, nonce []byte, attestation *types.IntermediateCertificateRequestAttestation) ([]byte, error) {
	var ekpubkey []byte

	if !serviceinfo.Requirements.TPM {
		return nil, nil
	}

	ekcert, err := attest.ParseEKCertificate(attestation.Static.EKPem)
	if err != nil {
		return nil, fmt.Errorf("Error parsing EK Certificate: %s", err)
	}
	if ekpubkey, err = validateTPMEKCert(ekcert); err != nil {
		return nil, fmt.Errorf("Error validating TPM EK Certificate: %s", err)
	}

	ak, err := attest.ParseAKPublic(
		attest.TPMVersion(attestation.Static.TPMVersion),
		attestation.AK.Public,
	)
	if err != nil {
		return nil, fmt.Errorf("Error parsing AK Public: %s", err)
	}

	if !serviceinfo.Requirements.Measurements {
		return ekpubkey, nil
	}

	q := attest.Quote{
		Version:   attest.TPMVersion(attestation.Static.TPMVersion),
		Quote:     attestation.Quote.Quote,
		Signature: attestation.Quote.Signature,
	}
	pcrs := make([]attest.PCR, 0)
	for _, pcr := range attestation.Log.PCRs {
		pcrs = append(
			pcrs,
			attest.PCR{
				Index:     pcr.Index,
				Digest:    pcr.Digest,
				DigestAlg: pcr.DigestAlg,
			},
		)
	}

	if err := ak.Verify(q, pcrs, nonce); err != nil {
		return nil, fmt.Errorf("Error validating quote: %s", err)
	}

	eventlog, err := attest.ParseEventLog(attestation.Log.Raw)
	if err != nil {
		return nil, fmt.Errorf("Error parsing event log: %s", err)
	}
	fmt.Println("PCRs:", attestation.Log.PCRs)
	events, err := eventlog.Verify(pcrs)
	if err != nil {
		return nil, fmt.Errorf("Error verifying measurement log: %s", err)
	}
	if err := validateEvents(events); err != nil {
		return nil, fmt.Errorf("Error validating measurement events: %s", err)
	}

	return ekpubkey, nil
}
