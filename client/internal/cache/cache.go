package cache

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/square/go-jose/v3/jwt"
)

func getHome() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	user, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user home: %s", user)
	}
	return user.HomeDir
}

func ensureDir(dir string) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.Mkdir(dir, 0700)
	}
	if err != nil {
		log.Fatalf("Error creating cache directory: %s", err)
	}
}

func getCacheDir(serverroot string) string {
	cachedir := path.Join(getHome(), ".ddcache")
	ensureDir(cachedir)

	serverroot = strings.Replace(serverroot, "/", "_", -1)
	serverroot = strings.Replace(serverroot, ":", "_", -1)

	cachedir = path.Join(cachedir, serverroot)
	ensureDir(cachedir)

	return cachedir
}

type Cache struct {
	dir        string
	serverroot string
	tpm        *attest.TPM
}

func New(serverroot string) *Cache {
	return &Cache{
		serverroot: serverroot,
		dir:        getCacheDir(serverroot),
	}
}

func (c *Cache) Close() {
	if c.tpm != nil {
		c.tpm.Close()
	}
}

func (c *Cache) GetTemporarySSHCert() (string, string, error) {
	certpath := path.Join(c.dir, "sshcert.pem")
	keypath := path.Join(c.dir, "sshkey.pem")

	cert, err := ioutil.ReadFile(certpath)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(keypath); err != nil {
		return "", "", err
	}
	// TODO: Check whether certificate is still valid
	_ = cert
	return certpath, keypath, nil
}

func (c *Cache) validateIntermediateCertificate(rawtoken, serverroot string) error {
	// Validate that this is an intermediate cert by the correct service, and still valid
	token, err := jwt.ParseSigned(rawtoken)
	if err != nil {
		return fmt.Errorf("Error parsing intermediate cert: %s", err)
	}

	var claims jwt.Claims
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return fmt.Errorf("Error parsing intermediate certificate: %s", err)
	}
	err = claims.Validate(jwt.Expected{
		Issuer: serverroot,
	})
	if err != nil {
		return fmt.Errorf("Error with the intermediate certificate: %s", err)
	}
	return nil
}

func (c *Cache) SaveIntermediateCertificate(rawtoken, serverroot string) error {
	if err := c.validateIntermediateCertificate(rawtoken, serverroot); err != nil {
		return fmt.Errorf("Error validating intermediate certificate for storage: %s", err)
	}

	intcertpath := path.Join(c.dir, "intermediatecert.jwt")
	return ioutil.WriteFile(intcertpath, []byte(rawtoken), 0600)
}

func (c *Cache) GetIntermediateCertificate(serverroot string) (string, error) {
	intcertpath := path.Join(c.dir, "intermediatecert.jwt")
	cert, err := ioutil.ReadFile(intcertpath)
	if err != nil {
		return "", err
	}

	rawtoken := string(cert)
	err = c.validateIntermediateCertificate(rawtoken, serverroot)
	if err != nil {
		return "", fmt.Errorf("Error validating intermediate certificate: %s", err)
	}

	return rawtoken, nil
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
