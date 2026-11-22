//
// loginguard.go
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
	"fmt"
	"sync"
	"time"
)

// Defaults and limits of the login backoff ([www] loginfailures,
// loginwindow, loginlockout).
const (
	defaultLoginFailures = 5
	defaultLoginWindow   = 60
	defaultLoginLockout  = 60
	maxLoginSeconds      = 24 * 60 * 60
	maxLoginFailures     = 1000

	// maxLoginEntries bounds the memory used for the per-client counters.
	maxLoginEntries = 10000
)

// checkLoginBackoff validates the three login backoff settings.
func checkLoginBackoff(failures, window, lockout int) error {
	if failures < 0 || failures > maxLoginFailures {
		return fmt.Errorf("invalid value %d, must be 0 (off) or 1 to %d", failures, maxLoginFailures)
	}
	if failures == 0 {
		return nil
	}
	if window < 1 || window > maxLoginSeconds {
		return fmt.Errorf("invalid window %d, must be 1 to %d seconds", window, maxLoginSeconds)
	}
	if lockout < 1 || lockout > maxLoginSeconds {
		return fmt.Errorf("invalid lockout %d, must be 1 to %d seconds", lockout, maxLoginSeconds)
	}
	return nil
}

type loginEntry struct {
	count       int
	start       time.Time // first failure of the current window
	lockedUntil time.Time // zero if not locked
}

// loginGuard counts failed logins per client address and locks a client
// out for a while after too many of them. It is safe for concurrent use.
type loginGuard struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	entries    map[string]*loginEntry
}

func newLoginGuard() *loginGuard {
	return &loginGuard{
		now:        time.Now,
		maxEntries: maxLoginEntries,
		entries:    make(map[string]*loginEntry),
	}
}

// expired reports whether the entry no longer has any effect.
func (e *loginEntry) expired(now time.Time, window time.Duration) bool {
	if !e.lockedUntil.IsZero() {
		return !now.Before(e.lockedUntil)
	}
	return !now.Before(e.start.Add(window))
}

// blocked reports whether the client is locked out and for how many more
// seconds (rounded up).
func (g *loginGuard) blocked(ip string) (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[ip]
	if !ok || e.lockedUntil.IsZero() {
		return 0, false
	}
	now := g.now()
	if !now.Before(e.lockedUntil) {
		delete(g.entries, ip)
		return 0, false
	}
	d := e.lockedUntil.Sub(now)
	return int((d + time.Second - 1) / time.Second), true
}

// fail records a failed login and reports whether this one locked the
// client out.
func (g *loginGuard) fail(ip string, failures int, window, lockout time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	e, ok := g.entries[ip]
	if ok && e.expired(now, window) {
		delete(g.entries, ip)
		ok = false
	}
	if !ok {
		g.makeRoom(now, window)
		e = &loginEntry{start: now}
		g.entries[ip] = e
	}
	if !e.lockedUntil.IsZero() {
		return false // already locked, no new message
	}
	e.count++
	if e.count >= failures {
		e.lockedUntil = now.Add(lockout)
		return true
	}
	return false
}

// makeRoom ensures that one more entry fits: expired entries go first, then
// the oldest ones.
func (g *loginGuard) makeRoom(now time.Time, window time.Duration) {
	if len(g.entries) < g.maxEntries {
		return
	}
	for k, e := range g.entries {
		if e.expired(now, window) {
			delete(g.entries, k)
		}
	}
	for len(g.entries) >= g.maxEntries {
		var oldest string
		var ot time.Time
		for k, e := range g.entries {
			if oldest == "" || e.start.Before(ot) {
				oldest, ot = k, e.start
			}
		}
		delete(g.entries, oldest)
	}
}

// success forgets the failures of the client.
func (g *loginGuard) success(ip string) {
	g.mu.Lock()
	delete(g.entries, ip)
	g.mu.Unlock()
}

// size returns the number of tracked clients.
func (g *loginGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

// webLoginGuard is the guard used by requireRoleWith.
var webLoginGuard = newLoginGuard()

// eof
