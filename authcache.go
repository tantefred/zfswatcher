//
// authcache.go
//
// This file is part of zfswatcher.
//
// Zfswatcher is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Zfswatcher is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with zfswatcher. If not, see <http://www.gnu.org/licenses/>.
//

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"sync"
	"time"
)

const (
	authCacheTTL        = 5 * time.Minute
	authCacheMaxEntries = 1000
)

type authCacheEntry struct {
	p       Principal
	expires time.Time
}

// authCache remembers successful credential checks for a few minutes, so
// that browsers which send the credentials with every request do not cost
// a bcrypt check each time. Only an HMAC of the Authorization header is
// kept as key, never the header itself.
type authCache struct {
	mu      sync.Mutex
	now     func() time.Time
	key     [32]byte
	forCfg  *cfgType // the cache is only valid for this configuration
	entries map[[sha256.Size]byte]authCacheEntry
}

func newAuthCache() *authCache {
	c := &authCache{now: time.Now, entries: make(map[[sha256.Size]byte]authCacheEntry)}
	if _, err := rand.Read(c.key[:]); err != nil {
		panic("zfswatcher: no random numbers: " + err.Error())
	}
	return c
}

// cacheKey derives the key. The kind of path is part of it, because tokens
// are only valid under the API path.
func (c *authCache) cacheKey(r *http.Request) ([sha256.Size]byte, bool) {
	var k [sha256.Size]byte
	h := r.Header.Get("Authorization")
	if h == "" {
		return k, false
	}
	m := hmac.New(sha256.New, c.key[:])
	if isAPIPath(r.URL.Path) {
		m.Write([]byte{1})
	} else {
		m.Write([]byte{0})
	}
	m.Write([]byte(h))
	copy(k[:], m.Sum(nil))
	return k, true
}

// get returns the cached principal of a request.
func (c *authCache) get(r *http.Request) *Principal {
	k, ok := c.cacheKey(r)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forCfg != cfg {
		c.entries = make(map[[sha256.Size]byte]authCacheEntry)
		c.forCfg = cfg
		return nil
	}
	e, ok := c.entries[k]
	if !ok {
		return nil
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, k)
		return nil
	}
	p := e.p
	return &p
}

// put stores a successfully checked principal.
func (c *authCache) put(r *http.Request, p *Principal) {
	k, ok := c.cacheKey(r)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.forCfg != cfg {
		c.entries = make(map[[sha256.Size]byte]authCacheEntry)
		c.forCfg = cfg
	}
	if len(c.entries) >= authCacheMaxEntries {
		var oldest [sha256.Size]byte
		var ot time.Time
		first := true
		for key, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, key)
			} else if first || e.expires.Before(ot) {
				oldest, ot, first = key, e.expires, false
			}
		}
		if len(c.entries) >= authCacheMaxEntries {
			delete(c.entries, oldest)
		}
	}
	c.entries[k] = authCacheEntry{p: *p, expires: now.Add(authCacheTTL)}
}

// flush forgets everything (configuration reload).
func (c *authCache) flush() {
	c.mu.Lock()
	c.entries = make(map[[sha256.Size]byte]authCacheEntry)
	c.mu.Unlock()
}

// webAuthCache is used by requireRoleWith.
var webAuthCache = newAuthCache()

// eof
