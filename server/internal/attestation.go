package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-attestation/attest"
	"github.com/puiterwijk/dendraeck/shared/types"
)

var (
	tpmCertPool = x509.NewCertPool()
)

func init() {
	// TODO: Load trusted certs from somewhere
	certdata, err := ioutil.ReadFile("OptigaRsaMfrCA035.crt")
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certdata)
	if err != nil {
		panic(err)
	}
	tpmCertPool.AddCert(cert)
}

func validateTPMEKCert(cert *x509.Certificate) ([]byte, error) {
	pkey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Non-RSA EK cert")
	}

	pubkey := x509.MarshalPKCS1PublicKey(pkey)

	cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     tpmCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
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

	aik, err := attest.ParseAIKPublic(
		attest.TPMVersion(attestation.Static.TPMVersion),
		attestation.AIK.Public,
	)
	if err != nil {
		return nil, fmt.Errorf("Error parsing AIK Public: %s", err)
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

	if err := aik.Verify(q, pcrs, nonce); err != nil {
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
