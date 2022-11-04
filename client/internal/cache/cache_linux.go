//go:build linux
// +build linux

package cache

import (
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/google/go-attestation/attest"
)

type Cache struct {
	cacheBase

	tpm *attest.TPM
}

func (c *Cache) Close() {
	if c.tpm != nil {
		c.tpm.Close()
	}
}

func (c *Cache) ensureTPM() {
	if c.tpm == nil {
		var err error
		c.tpm, err = attest.OpenTPM(&attest.OpenConfig{})
		if err != nil {
			log.Fatalf("Error opening TPM: %s", err)
		}
	}
}

func (c *Cache) GetTPM() *attest.TPM {
	c.ensureTPM()
	return c.tpm
}

func (c *Cache) createAK() (*attest.AK, error) {
	c.ensureTPM()

	k, err := c.tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		return nil, err
	}
	b, err := k.Marshal()
	if err != nil {
		k.Close(c.tpm)
		return nil, err
	}
	err = ioutil.WriteFile(path.Join(c.dir, "ak.json"), b, 0600)
	if err != nil {
		k.Close(c.tpm)
		return nil, err
	}
	return k, nil
}

func (c *Cache) GetAK() (*attest.AK, error) {
	c.ensureTPM()

	b, err := ioutil.ReadFile(path.Join(c.dir, "ak.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return c.createAK()
		}
		return nil, err
	}
	k, err := c.tpm.LoadAK(b)
	return k, err
}

func (c *Cache) CloseAK(k *attest.AK) {
	c.ensureTPM()

	err := k.Close(c.tpm)
	if err != nil {
		log.Printf("Error closing AK: %s", err)
	}
}
