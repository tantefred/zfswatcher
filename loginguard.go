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
	"net/netip"
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
	count       int       // failures in the current window
	pending     int       // attempts in flight
	start       time.Time // first failure of the current window
	lockedUntil time.Time // zero if not locked
}

func (e *loginEntry) locked() bool { return !e.lockedUntil.IsZero() }

// expired reports whether the entry no longer has any effect.
func (e *loginEntry) expired(now time.Time, window time.Duration) bool {
	if e.locked() {
		return !now.Before(e.lockedUntil)
	}
	return !now.Before(e.start.Add(window))
}

// loginGuard counts failed logins per client and locks a client out for a
// while after too many of them. Successful logins do not reset the counter
// (otherwise a user with a valid password could guess other passwords
// without limit); the counters only expire with the window. It is safe for
// concurrent use.
type loginGuard struct {
	mu         sync.Mutex
	now        func() time.Time
	maxEntries int
	entries    map[string]*loginEntry
	overflow   bool       // the table is full of locked clients, reported once
	shared     loginEntry // all clients that do not fit into the table
}

func newLoginGuard() *loginGuard {
	return &loginGuard{
		now:        time.Now,
		maxEntries: maxLoginEntries,
		entries:    make(map[string]*loginEntry),
	}
}

// loginKey maps a client address to the key of its counter: IPv4 addresses
// individually, IPv6 addresses by their /64 prefix (a client usually owns
// a whole /64, so it could otherwise use endless addresses). Text which is
// not an address (with or without port) is used as is.
func loginKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		ap, err2 := netip.ParseAddrPort(ip)
		if err2 != nil {
			return ip
		}
		a = ap.Addr()
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// loginVerdict is the result of begin.
type loginVerdict int

const (
	loginAllow loginVerdict = iota
	loginDeny               // locked out, no attempts left
)

// lockedFor reports whether the client is locked out and for how many more
// seconds.
func (g *loginGuard) lockedFor(ip string) (int, bool) {
	key := loginKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[key]
	if !ok || !e.locked() {
		return 0, false
	}
	now := g.now()
	if !now.Before(e.lockedUntil) {
		return 0, false
	}
	return ceilSeconds(e.lockedUntil.Sub(now)), true
}

// sharedLoginKey is the key of the entry shared by all clients which do not
// fit into the table (not a valid address, so it cannot collide).
const sharedLoginKey = "shared"

// begin reserves an attempt slot for the client. With loginAllow the caller
// must call end exactly once. Otherwise it returns the seconds to wait.
// If the table is full of locked clients, an unknown client counts against
// the shared entry sharedLoginKey instead (same rules as for one client);
// first is true the first time this happens, to be reported once.
func (g *loginGuard) begin(ip string, failures int, window time.Duration) (key string, v loginVerdict, retry int, first bool) {
	key = loginKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	e, ok := g.entries[key]
	if ok && e.expired(now, window) {
		if e.pending == 0 {
			delete(g.entries, key)
			ok = false
		} else {
			*e = loginEntry{pending: e.pending, start: now}
		}
	}
	if !ok {
		if g.makeRoom(now, window) {
			e = &loginEntry{start: now}
			g.entries[key] = e
		} else {
			// Table full of locked clients: all unknown clients share
			// one entry outside of the table, which is never evicted.
			first = !g.overflow
			g.overflow = true
			key = sharedLoginKey
			e = &g.shared
			if e.expired(now, window) && e.pending == 0 {
				*e = loginEntry{start: now}
			}
		}
	}
	if e.locked() {
		return key, loginDeny, ceilSeconds(e.lockedUntil.Sub(now)), false
	}
	if e.count+e.pending >= failures {
		return key, loginDeny, ceilSeconds(e.start.Add(window).Sub(now)), false
	}
	e.pending++
	return key, loginAllow, 0, first
}

func ceilSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// end releases the slot taken by begin. Only a failed login (failed) is
// counted; it returns true if that locked the client out.
func (g *loginGuard) end(key string, failed bool, failures int, window, lockout time.Duration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	e, ok := g.entries[key]
	if key == sharedLoginKey {
		e, ok = &g.shared, true
	}
	if !ok {
		// evicted while in flight
		if !failed || !g.makeRoom(now, window) {
			return false
		}
		e = &loginEntry{start: now}
		g.entries[key] = e
	} else if e.pending > 0 {
		e.pending--
	}
	locked := false
	if failed && !e.locked() {
		if e.expired(now, window) {
			e.count, e.start = 0, now
		}
		e.count++
		if e.count >= failures {
			e.lockedUntil = now.Add(lockout)
			locked = true
		}
	}
	if key != sharedLoginKey && e.count == 0 && e.pending == 0 && !e.locked() {
		delete(g.entries, key)
	}
	return locked
}

// makeRoom ensures that one more entry fits: expired entries go first, then
// the oldest unlocked ones. Locked entries are never evicted; it returns
// false if only those are left.
func (g *loginGuard) makeRoom(now time.Time, window time.Duration) bool {
	if len(g.entries) < g.maxEntries {
		g.overflow = false
		return true
	}
	for k, e := range g.entries {
		if e.pending == 0 && e.expired(now, window) {
			delete(g.entries, k)
		}
	}
	for len(g.entries) >= g.maxEntries {
		var oldest string
		var ot time.Time
		for k, e := range g.entries {
			if !e.locked() && (oldest == "" || e.start.Before(ot)) {
				oldest, ot = k, e.start
			}
		}
		if oldest == "" {
			return false
		}
		delete(g.entries, oldest)
	}
	g.overflow = false
	return true
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
