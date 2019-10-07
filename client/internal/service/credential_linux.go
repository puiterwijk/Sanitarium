// +build linux

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/google/go-attestation/attest"
)

func (s *Service) activateCredential(ec *attest.EncryptedCredential, nonce, encrypted []byte) ([]byte, error) {
	aik, err := s.cache.GetAIK()
	if err != nil {
		return nil, fmt.Errorf("Unable to get AIK: %s", err)
	}
	defer s.cache.CloseAIK(aik)
	secret, err := aik.ActivateCredential(s.cache.GetTPM(), *ec)
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
