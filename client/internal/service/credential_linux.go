//go:build linux
// +build linux

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/puiterwijk/sanitarium/shared/types"

	"github.com/google/go-attestation/attest"
)

func (s *Service) activateCredential(ec *types.SSHCertResponseEncryptedCredential, nonce, encrypted []byte) ([]byte, error) {
	ak, err := s.cache.GetAK()
	if err != nil {
		return nil, fmt.Errorf("Unable to get AK: %s", err)
	}
	defer s.cache.CloseAK(ak)

	rawec := attest.EncryptedCredential{
		Credential: ec.Credential,
		Secret:     ec.Secret,
	}
	secret, err := ak.ActivateCredential(s.cache.GetTPM(), rawec)
	if err != nil {
		return nil, fmt.Errorf("Unable to activate credential: %s", err)
	}

	blockcipher, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("Error creating AES cipher: %s", err)
	}
	aead, err := cipher.NewGCM(blockcipher)
	if err != nil {
		return nil, fmt.Errorf("Error creating GCM cipher: %s", err)
	}

	return aead.Open(
		nil,
		nonce,
		encrypted,
		nil,
	)
}
