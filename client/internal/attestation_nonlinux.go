// +build !linux

package internal

import (
	"fmt"

	int_cache "github.com/puiterwijk/sanitarium/client/internal/cache"
	"github.com/puiterwijk/sanitarium/shared/types"
)

func CreateAttestation(cache *int_cache.Cache, nonce []byte, dotpm, domeasurements bool) (*types.IntermediateCertificateRequestAttestation, error) {
	var out types.IntermediateCertificateRequestAttestation

	if dotpm {
		fmt.Println("This platform does not support TPM attestation")
	}
	return &out, nil
}
