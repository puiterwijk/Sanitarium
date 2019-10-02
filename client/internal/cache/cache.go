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
	"golang.org/x/crypto/ssh"
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
	sshpubkey  ssh.PublicKey
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

func (c *Cache) SetSSHPublicKey(stringkey string) {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(stringkey))
	if err != nil {
		panic(fmt.Errorf("Error parsing server public SSH key: %s", err))
	}
	c.sshpubkey = pubkey
}

func (c *Cache) validateSSHCert(certcontents []byte) error {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(certcontents)
	if err != nil {
		return fmt.Errorf("Error parsing public key: %s", err)
	}
	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("Error parsing certificate as such")
	}

	intuser, err := c.GetIntermediateCertificateUsername()
	if err != nil {
		return fmt.Errorf("Error getting intermediate username: %s", err)
	}

	checker := new(ssh.CertChecker)
	err = checker.CheckCert(intuser, cert)
	if err != nil {
		return fmt.Errorf("Error checking certificate: %s", err)
	}
	return nil
}

func (c *Cache) GetSSHCert(servername string) (string, string, error) {
	certpath := path.Join(c.dir, servername+".sshkey-cert.pub")
	keypath := path.Join(c.dir, servername+".sshkey")

	cert, err := ioutil.ReadFile(certpath)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(keypath); err != nil {
		return "", "", err
	}
	err = c.validateSSHCert(cert)
	if err != nil {
		return "", "", err
	}
	return certpath, keypath, nil
}

func (c *Cache) SaveSSHCert(servername string, privkey, pubcert []byte) error {
	if err := c.validateSSHCert(pubcert); err != nil {
		return fmt.Errorf("Error validating ssh cert before saving: %s", err)
	}
	certpath := path.Join(c.dir, servername+".sshkey-cert.pub")
	keypath := path.Join(c.dir, servername+".sshkey")

	if err := ioutil.WriteFile(certpath, pubcert, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(keypath, privkey, 0600); err != nil {
		return err
	}
	return nil
}

func (c *Cache) validateIntermediateCertificate(rawtoken string) (string, error) {
	// Validate that this is an intermediate cert by the correct service, and still valid
	token, err := jwt.ParseSigned(rawtoken)
	if err != nil {
		return "", fmt.Errorf("Error parsing intermediate cert: %s", err)
	}

	var claims jwt.Claims
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", fmt.Errorf("Error parsing intermediate certificate: %s", err)
	}
	err = claims.Validate(jwt.Expected{
		Issuer: c.serverroot,
	})
	if err != nil {
		return "", fmt.Errorf("Error with the intermediate certificate: %s", err)
	}
	return claims.Subject, nil
}

func (c *Cache) SaveIntermediateCertificate(rawtoken string) error {
	if _, err := c.validateIntermediateCertificate(rawtoken); err != nil {
		return fmt.Errorf("Error validating intermediate certificate for storage: %s", err)
	}

	intcertpath := path.Join(c.dir, "intermediatecert.jwt")
	return ioutil.WriteFile(intcertpath, []byte(rawtoken), 0600)
}

func (c *Cache) GetIntermediateCertificate() (string, error) {
	intcertpath := path.Join(c.dir, "intermediatecert.jwt")
	cert, err := ioutil.ReadFile(intcertpath)
	if err != nil {
		return "", err
	}

	rawtoken := string(cert)
	_, err = c.validateIntermediateCertificate(rawtoken)
	if err != nil {
		return "", fmt.Errorf("Error validating intermediate certificate: %s", err)
	}

	return rawtoken, nil
}

func (c *Cache) GetIntermediateCertificateUsername() (string, error) {
	intcertpath := path.Join(c.dir, "intermediatecert.jwt")
	cert, err := ioutil.ReadFile(intcertpath)
	if err != nil {
		return "", err
	}

	rawtoken := string(cert)
	username, err := c.validateIntermediateCertificate(rawtoken)
	if err != nil {
		return "", fmt.Errorf("Error validating intermediate certificate: %s", err)
	}

	return username, nil
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
