//go:generate go run extractor.go
package tpmcas

import (
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
)

var verifyopts *x509.VerifyOptions

// GetTPMEKVerifyOptions returns a x509.VerifyOptions instance that has the Roots
// and Intermediates populated with the embedded certificates
func GetTPMEKVerifyOptions() (*x509.VerifyOptions, error) {
	if verifyopts == nil {
		rootcerts, err := x509.ParseCertificates(rootcas)
		if err != nil {
			return nil, fmt.Errorf("Error parsing root CAs: %s", err)
		}
		rootpool := x509.NewCertPool()
		for _, cert := range rootcerts {
			rootpool.AddCert(cert)
		}

		intermediatecerts, err := x509.ParseCertificates(intermediatecas)
		if err != nil {
			return nil, fmt.Errorf("Error parsing intermediate CAs: %s", err)
		}
		intermediatepool := x509.NewCertPool()
		for _, cert := range intermediatecerts {
			intermediatepool.AddCert(cert)
		}

		verifyopts = &x509.VerifyOptions{
			Roots: rootpool,
			Intermediates: intermediatepool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
	}
	return verifyopts, nil
}
