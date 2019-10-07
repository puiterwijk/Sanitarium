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

func (c *Cache) createAIK() (*attest.AIK, error) {
	c.ensureTPM()

	k, err := c.tpm.NewAIK(&attest.AIKConfig{})
	if err != nil {
		return nil, err
	}
	b, err := k.Marshal()
	if err != nil {
		k.Close(c.tpm)
		return nil, err
	}
	err = ioutil.WriteFile(path.Join(c.dir, "aik.json"), b, 0600)
	if err != nil {
		k.Close(c.tpm)
		return nil, err
	}
	return k, nil
}

func (c *Cache) GetAIK() (*attest.AIK, error) {
	c.ensureTPM()

	b, err := ioutil.ReadFile(path.Join(c.dir, "aik.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return c.createAIK()
		}
		return nil, err
	}
	k, err := c.tpm.LoadAIK(b)
	return k, err
}

func (c *Cache) CloseAIK(k *attest.AIK) {
	c.ensureTPM()

	err := k.Close(c.tpm)
	if err != nil {
		log.Printf("Error closing AIK: %s", err)
	}
}
