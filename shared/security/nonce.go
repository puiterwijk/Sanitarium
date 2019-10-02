package security

import (
	"crypto/sha256"
)

func CalculateNonce(authzcode string) []byte {
	digest := sha256.Sum256([]byte(authzcode))
	return digest[:8]
}
