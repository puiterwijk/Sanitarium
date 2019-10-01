package cache

import (
	"log"
	"os"
	"os/user"
	"strings"
)

func expandPath(path string) string {
	if !strings.Contains(path, "~") {
		return path
	}
	user, err := user.Current()
	if err != nil {
		log.Fatalf("Error getting current user for tilde expansion: %s", user)
	}
	return strings.Replace(path, "~", user.HomeDir, 1)
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
