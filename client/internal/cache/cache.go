package cache

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"strings"

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

type cacheBase struct {
	dir                string
	serverroot         string
	sshpubkey          ssh.PublicKey
	intermediatepubkey *rsa.PublicKey
}

func New(serverroot string) *Cache {
	return &Cache{
		cacheBase{
			serverroot: serverroot,
			dir:        getCacheDir(serverroot),
		},
	}
}

func (c *Cache) SetSSHPublicKey(stringkey string) {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(stringkey))
	if err != nil {
		panic(fmt.Errorf("Error parsing server public SSH key: %s", err))
	}
	c.sshpubkey = pubkey
}

func (c *Cache) SetIntermediatePublicKey(pkcs1key []byte) {
	var err error
	c.intermediatepubkey, err = x509.ParsePKCS1PublicKey(pkcs1key)
	if err != nil {
		panic(fmt.Errorf("Error parsing server public intermediate key: %s", err))
	}
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
	if c.intermediatepubkey == nil {
		// If we didn't get the pubkey yet, we have no way to verify signature
		err = token.UnsafeClaimsWithoutVerification(&claims)
	} else {
		err = token.Claims(c.intermediatepubkey, &claims)
	}
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
