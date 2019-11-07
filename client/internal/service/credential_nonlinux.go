// +build !linux

package service

import (
	"fmt"

	"github.com/puiterwijk/sanitarium/shared/types"
)

func (s *Service) activateCredential(ec *types.SSHCertResponseEncryptedCredential, nonce, encrypted []byte) ([]byte, error) {
	return nil, fmt.Errorf("Encrypted credentials are not supported on this platform")
}
