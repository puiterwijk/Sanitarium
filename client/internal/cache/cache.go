package cache

import (
	"log"
	"os"
	"os/user"
	"path"
	"strings"
)

func expandPath(dir string) string {
	if !strings.HasPrefix(dir, "~/") {
		return dir
	}
	user, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user for tilde expansion: %s", user)
	}
	return path.Join(user.HomeDir, dir[2:])
}

type Cache struct {
	dir string
}

func New(dir string) *Cache {
	dir = expandPath(dir)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.Mkdir(dir, 0700)
		if err != nil {
			log.Fatalf("Error creating cache directory: %s", err)
		}
	}

	return &Cache{
		dir: dir,
	}
}

func (c *Cache) GetTemporarySSHCert() (string, string, error) {
	certpath := path.Join(c.dir, "sshcert.pem")
	keypath := path.Join(c.dir, "sshkey.pem")

	certf, err := os.Open(certpath)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(keypath); err != nil {
		return "", "", err
	}
	// TODO: Check whether certificate is still valid
	_ = certf
	return certpath, keypath, nil
}
