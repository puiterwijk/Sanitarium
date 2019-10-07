// +build !linux

package cache

type Cache struct {
	cacheBase
}

func (c *Cache) Close() {
}
