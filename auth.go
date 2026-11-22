//
// auth.go
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
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/tantefred/zfswatcher/notifier"
)

const authRealm = "zfswatcher"

// dummyBcryptHash is compared against when the user is unknown or disabled,
// so that the response time does not reveal which user names exist. The
// password it was made from is irrelevant (and never matches).
const dummyBcryptHash = "$2y$10$UixQGmoY3RV64c3a.CNpOuBDX31Sr9dYBuRAs0cchTcDXazwH0f1i"

func isBcryptHash(hash string) bool {
	for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
		if strings.HasPrefix(hash, p) {
			return true
		}
	}
	return false
}

func isMD5CryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$1$")
}

// checkPassword verifies the password against a bcrypt ("$2a$", "$2b$",
// "$2y$") or MD5 crypt ("$1$") hash. Other formats never match.
func checkPassword(hash, password string) bool {
	switch {
	case isBcryptHash(hash):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	case isMD5CryptHash(hash):
		parts := strings.Split(hash, "$")
		if len(parts) != 4 || parts[2] == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(md5Crypt(password, parts[2])), []byte(hash)) == 1
	}
	return false
}

// Role is the authorization level of a web user or API token. The roles are
// ordered: a higher role may do everything a lower one may.
type Role int

// The zero value is deliberately not a valid role.
const (
	RoleViewer   Role = iota + 1 // dashboard, status, usage, statistics, enclosure, about
	RoleOperator                 // additionally logs and LED locate
	RoleAdmin                    // everything (nothing more for now)
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return fmt.Sprintf("Role(%d)", int(r))
}

// parseRole converts the configuration value to a Role.
func parseRole(s string) (Role, error) {
	switch s {
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	}
	return 0, fmt.Errorf("invalid role %q, must be viewer, operator or admin", s)
}

// configRole converts the "role" parameter of a configuration section. An
// empty value means admin, which is the behaviour from before roles existed.
func configRole(s string) (Role, error) {
	if s == "" {
		return RoleAdmin, nil
	}
	return parseRole(s)
}

// wwwUserCfg is a "[wwwuser]" section.
type wwwUserCfg struct {
	Enable   bool
	Password string
	Role     string
}

// apiTokenCfg is an "[apitoken]" section.
type apiTokenCfg struct {
	Enable bool
	Hash   string
	Role   string
}

// Authentication methods of a Principal.
const (
	methodBasic = "basic"
	methodToken = "token"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	Name   string
	Role   Role
	Method string // methodBasic or methodToken
}

// Authenticator extracts and checks the credentials of a request. It returns
// a nil Principal and no error if the request carries no credentials (of the
// kind it handles), and an error if credentials are present but wrong. The
// error text completes the phrase "web login failed for ...".
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

type principalKey struct{}

// principalFrom returns the authenticated principal stored by requireRole.
// It is nil if the request did not pass through requireRole.
func principalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// roleOf returns the role of the request's principal. Without a principal
// the lowest role is assumed.
func roleOf(r *http.Request) Role {
	if p := principalFrom(r.Context()); p != nil {
		return p.Role
	}
	return RoleViewer
}

// lookupUser verifies the credentials against the enabled web users.
func lookupUser(username, password string) (Role, bool) {
	hash := ""
	var user *wwwUserCfg
	if u, ok := cfg.Wwwuser[username]; ok && u.Enable {
		user = u
		hash = u.Password
	}
	if hash == "" || (!isBcryptHash(hash) && !isMD5CryptHash(hash)) {
		// burn the same time as a real check
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		return 0, false
	}
	if !checkPassword(hash, password) {
		return 0, false
	}
	role, err := configRole(user.Role)
	if err != nil {
		role = RoleViewer // cannot happen, the configuration is validated; fail closed
	}
	return role, true
}

// truncateRunes shortens s to at most n runes, so that a client cannot flood
// the log with a huge user name.
func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// basicAuthenticator checks HTTP Basic credentials against [wwwuser].
type basicAuthenticator struct{}

func (basicAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	role, ok := lookupUser(username, password)
	if !ok {
		return nil, fmt.Errorf("user %q", truncateRunes(username, 64))
	}
	return &Principal{Name: username, Role: role, Method: methodBasic}, nil
}

// tokenPrefix starts every generated API token.
const tokenPrefix = "zfsw_"

// tokenHashPrefix starts the "hash" parameter of an [apitoken] section.
const tokenHashPrefix = "sha256:"

// hashToken returns the configuration value ("sha256:<hex>") for a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return tokenHashPrefix + hex.EncodeToString(sum[:])
}

// parseTokenHash decodes the value of the "hash" parameter.
func parseTokenHash(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	hexpart, ok := strings.CutPrefix(s, tokenHashPrefix)
	if !ok || len(hexpart) != 2*sha256.Size {
		return out, errors.New(`invalid hash, expected "sha256:" followed by 64 hex digits`)
	}
	b, err := hex.DecodeString(hexpart)
	if err != nil {
		return out, errors.New(`invalid hash, expected "sha256:" followed by 64 hex digits`)
	}
	copy(out[:], b)
	return out, nil
}

// bearerToken returns the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// tokenAuthenticator checks Bearer tokens against [apitoken].
type tokenAuthenticator struct{}

func (tokenAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	token, ok := bearerToken(r)
	if !ok {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(token))
	var found *Principal
	// Compare against every token, so that the time does not depend on
	// which one (if any) matches.
	for name, t := range cfg.Apitoken {
		if !t.Enable {
			continue
		}
		want, err := parseTokenHash(t.Hash)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 && found == nil {
			role, err := configRole(t.Role)
			if err != nil {
				role = RoleViewer // validated in getCfg; fail closed
			}
			found = &Principal{Name: name, Role: role, Method: methodToken}
		}
	}
	if found == nil {
		return nil, errors.New("API token")
	}
	return found, nil
}

// isTokenPath reports whether tokens are accepted for the path: below
// "<rootdir>/api/" and for the Prometheus endpoint "<rootdir>/metrics".
func isTokenPath(path string) bool {
	root := cfg.Www.Rootdir
	if path == root+"/api" || strings.HasPrefix(path, root+"/api/") {
		return true
	}
	return cfg.Www.Metrics && path == root+"/metrics"
}

// chainAuthenticator tries Basic first; for token paths it falls back to
// tokens. Everything else accepts Basic only.
type chainAuthenticator struct {
	basic, token Authenticator
}

func newAuthenticator() Authenticator {
	return chainAuthenticator{basic: basicAuthenticator{}, token: tokenAuthenticator{}}
}

func (c chainAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	if p, err := c.basic.Authenticate(r); p != nil || err != nil {
		return p, err
	}
	if isTokenPath(r.URL.Path) {
		return c.token.Authenticate(r)
	}
	return nil, nil
}

// errorRenderer writes an error response; the API uses its own one to
// answer with JSON.
type errorRenderer func(w http.ResponseWriter, r *http.Request, code int, msg string)

func plainError(w http.ResponseWriter, _ *http.Request, code int, msg string) {
	http.Error(w, msg, code)
}

// requireRole wraps the handler: the request needs valid credentials and at
// least the given role. Errors are plain text.
func requireRole(min Role, h http.HandlerFunc) http.HandlerFunc {
	return requireRoleWith(newAuthenticator(), plainError, min, h)
}

// requireRoleWith is requireRole with explicit authenticator and error
// renderer.
func requireRoleWith(a Authenticator, render errorRenderer, min Role, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
		if p == nil {
			if err != nil && notify != nil {
				notify.Printf(notifier.WARNING, "web login failed for %s from %s", err, clientIP(r))
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`", charset="UTF-8"`)
			render(w, r, http.StatusUnauthorized, "401 Unauthorized")
			return
		}
		if p.Role < min {
			render(w, r, http.StatusForbidden, "403 Forbidden")
			return
		}
		h(w, r.WithContext(withPrincipal(r.Context(), p)))
	}
}

// eof
