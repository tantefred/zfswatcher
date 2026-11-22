package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingAuth accepts the password "good" and counts its calls.
type countingAuth struct{ calls int }

func (a *countingAuth) Authenticate(r *http.Request) (*Principal, error) {
	a.calls++
	u, p, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	if p != "good" {
		return nil, errors.New("user " + strconv.Quote(u))
	}
	return &Principal{Name: u, Role: RoleAdmin, Method: methodBasic}, nil
}

// backoffSetup installs a fresh guard with a fake clock and the default
// backoff settings.
func backoffSetup(t *testing.T) (*fakeClock, *countingAuth, http.HandlerFunc) {
	t.Helper()
	oldGuard, oldCfg := webLoginGuard, cfg
	t.Cleanup(func() { webLoginGuard, cfg = oldGuard, oldCfg })
	cfg = &cfgType{}
	cfg.Www.Loginfailures = 3
	cfg.Www.Loginwindow = 60
	cfg.Www.Loginlockout = 120
	cfg.Severity.Loginlockout = notifier.ERR
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	webLoginGuard = newLoginGuard()
	webLoginGuard.now = clk.now
	a := &countingAuth{}
	h := requireRoleWith(a, plainError, RoleViewer, func(w http.ResponseWriter, _ *http.Request) {})
	return clk, a, h
}

func loginReq(h http.HandlerFunc, remote, pass string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/x", nil)
	r.RemoteAddr = remote + ":1234"
	if pass != "" {
		r.SetBasicAuth("u", pass)
	}
	w := httptest.NewRecorder()
	proxyHeaders(nil, h).ServeHTTP(w, r) // as in the web server
	return w
}

func TestLoginBackoffLockout(t *testing.T) {
	clk, a, h := backoffSetup(t)
	msgs := captureNotify(t)
	for i := 0; i < 3; i++ {
		if w := loginReq(h, "192.0.2.1", "bad"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	calls := a.calls
	w := loginReq(h, "192.0.2.1", "good") // even the right password is refused
	if w.Code != 429 || w.Header().Get("Retry-After") != "120" {
		t.Fatalf("got %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	clk.advance(30 * time.Second)
	w = loginReq(h, "192.0.2.1", "bad")
	if w.Code != 429 || w.Header().Get("Retry-After") != "90" {
		t.Fatalf("got %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if a.calls != calls {
		t.Error("credentials were checked during the lockout")
	}
	// another client is not affected
	if w := loginReq(h, "192.0.2.2", "good"); w.Code != 200 {
		t.Errorf("other client: %d", w.Code)
	}
	// lockout over: checked again
	clk.advance(91 * time.Second)
	if w := loginReq(h, "192.0.2.1", "good"); w.Code != 200 {
		t.Errorf("after lockout: %d", w.Code)
	}
	got := msgs()
	want := strconv.Itoa(int(notifier.ERR)) + " web login: client 192.0.2.1 locked out for 120s after 3 failed attempts"
	if len(got) != 4 || got[3] != want { // 3 failed-login warnings + one lockout
		t.Errorf("messages %q, want last %q", got, want)
	}
	n := 0
	for _, m := range got {
		if strings.Contains(m, "locked out") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d lockout messages, want 1", n)
	}
}

func TestLoginBackoffSuccessDoesNotReset(t *testing.T) {
	_, _, h := backoffSetup(t)
	// a valid login in between must not reset the counter: 3rd failure locks
	loginReq(h, "192.0.2.1", "bad")
	loginReq(h, "192.0.2.1", "good")
	loginReq(h, "192.0.2.1", "bad")
	loginReq(h, "192.0.2.1", "good")
	loginReq(h, "192.0.2.1", "bad")
	if w := loginReq(h, "192.0.2.1", "good"); w.Code != 429 {
		t.Errorf("got %d, want 429", w.Code)
	}
}

func TestLoginBackoffWindowExpires(t *testing.T) {
	clk, _, h := backoffSetup(t)
	loginReq(h, "192.0.2.1", "bad")
	loginReq(h, "192.0.2.1", "bad")
	clk.advance(61 * time.Second)
	loginReq(h, "192.0.2.1", "bad") // counts as the first again
	loginReq(h, "192.0.2.1", "bad")
	if w := loginReq(h, "192.0.2.1", "good"); w.Code != 200 {
		t.Errorf("got %d, the window should have expired", w.Code)
	}
}

func TestLoginBackoffMissingCredentialsNotCounted(t *testing.T) {
	_, _, h := backoffSetup(t)
	for i := 0; i < 10; i++ {
		if w := loginReq(h, "192.0.2.1", ""); w.Code != 401 {
			t.Fatalf("got %d", w.Code)
		}
	}
	if webLoginGuard.size() != 0 {
		t.Error("requests without credentials were counted")
	}
}

func TestLoginBackoffDisabled(t *testing.T) {
	_, a, h := backoffSetup(t)
	cfg.Www.Loginfailures = 0
	for i := 0; i < 20; i++ {
		if w := loginReq(h, "192.0.2.1", "bad"); w.Code != 401 {
			t.Fatalf("got %d", w.Code)
		}
	}
	if a.calls != 20 || webLoginGuard.size() != 0 {
		t.Errorf("calls %d, entries %d", a.calls, webLoginGuard.size())
	}
}

func guardWithClock(max int) (*loginGuard, *fakeClock) {
	g := newLoginGuard()
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	g.now = clk.now
	g.maxEntries = max
	return g, clk
}

// attempt runs one failed login through the guard.
func attempt(g *loginGuard, ip string, failed bool) (loginVerdict, bool) {
	key, v, _, _ := g.begin(ip, 5, time.Minute)
	if v != loginAllow {
		return v, false
	}
	return v, g.end(key, failed, 5, time.Minute, time.Minute)
}

func TestLoginGuardMaxEntries(t *testing.T) {
	g, clk := guardWithClock(50)
	for i := 0; i < 500; i++ {
		attempt(g, "10.0."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250), true)
		clk.advance(time.Millisecond)
		if g.size() > 50 {
			t.Fatalf("%d entries", g.size())
		}
	}
	clk.advance(time.Hour) // expired entries are dropped first
	attempt(g, "203.0.113.1", true)
	if g.size() != 1 {
		t.Errorf("%d entries after expiry, want 1", g.size())
	}
}

func TestLoginGuardLockedEntriesSurvive(t *testing.T) {
	g, clk := guardWithClock(10)
	for i := 0; i < 5; i++ { // lock out one client
		attempt(g, "192.0.2.1", true)
	}
	if _, _, secs, _ := g.begin("192.0.2.1", 5, time.Minute); secs != 60 {
		t.Fatalf("not locked: %d", secs)
	}
	for i := 0; i < 100; i++ { // flood with single failures from other clients
		attempt(g, "10.0.0."+strconv.Itoa(i), true)
		clk.advance(time.Millisecond)
	}
	if _, v, _, _ := g.begin("192.0.2.1", 5, time.Minute); v != loginDeny {
		t.Errorf("locked client was evicted: %v", v)
	}
}

func TestLoginGuardOverflowSharedEntry(t *testing.T) {
	g, clk := guardWithClock(3)
	for i := 0; i < 3; i++ {
		for j := 0; j < 5; j++ {
			attempt(g, "10.0.0."+strconv.Itoa(i), true)
		}
	}
	// unknown clients are checked, sharing one entry outside the table
	key, v, _, first := g.begin("10.9.9.9", 5, time.Minute)
	if v != loginAllow || key != sharedLoginKey || !first {
		t.Fatalf("first: %v %q first %v", v, key, first)
	}
	g.end(key, false, 5, time.Minute, time.Minute)
	if g.size() != 3 {
		t.Errorf("table size %d, the shared entry must not count", g.size())
	}
	// failures of different unknown clients add up and lock all of them
	locked := 0
	for i := 0; i < 5; i++ {
		_, l := attempt(g, "10.9.8."+strconv.Itoa(i), true)
		if l {
			locked++
		}
	}
	if locked != 1 {
		t.Errorf("%d lockouts, want 1", locked)
	}
	if _, v, secs, first := g.begin("10.9.7.1", 5, time.Minute); v != loginDeny || secs != 60 || first {
		t.Errorf("shared entry locked: %v, %d, first %v", v, secs, first)
	}
	// known locked clients stay locked and nothing was evicted
	if _, v, _, _ := g.begin("10.0.0.0", 5, time.Minute); v != loginDeny || g.size() != 3 {
		t.Errorf("known client: %v, size %d", v, g.size())
	}
	clk.advance(2 * time.Minute) // everything expired: normal again
	if v, _ := attempt(g, "10.9.9.9", false); v != loginAllow {
		t.Errorf("after expiry: %v", v)
	}
	if k, _, _, _ := g.begin("10.9.9.10", 5, time.Minute); k == sharedLoginKey {
		t.Error("still using the shared entry although there is room")
	}
}

func TestLoginKeyIPv6Prefix(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":                  "192.0.2.1",
		"192.0.2.1:99":               "192.0.2.1",
		"::ffff:192.0.2.1":           "192.0.2.1",
		"2001:db8:1:2:aaaa::1":       "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::2":       "2001:db8:1:2::/64",
		"[2001:db8:1:2:cccc::3]:443": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":            "2001:db8:1:3::/64",
		"not an address":             "not an address",
	}
	for in, want := range cases {
		if got := loginKey(in); got != want {
			t.Errorf("loginKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginOverflowSharedEntryHTTP(t *testing.T) {
	_, _, h := cacheSetup(t)
	webLoginGuard.maxEntries = 2
	cfg.Www.Loginfailures = 3
	msgs := captureNotify(t)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} { // fill the table with locked clients
		for i := 0; i < 3; i++ {
			loginReq(h, ip, "bad")
		}
	}
	// a valid unknown client gets in and is cached
	if w := loginReq(h, "192.0.2.3", "good"); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	// failures of unknown clients lock out all unknown clients
	for i := 0; i < 3; i++ {
		if w := loginReq(h, "198.51.100."+strconv.Itoa(i), "bad"); w.Code != 401 {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	if w := loginReq(h, "198.51.100.50", "bad"); w.Code != 429 || w.Header().Get("Retry-After") != "120" {
		t.Errorf("got %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	// the cached credential still works (cache hit, no slot)
	if w := loginReq(h, "192.0.2.3", "good"); w.Code != 200 {
		t.Errorf("cache hit: %d", w.Code)
	}
	webAuthCache.flush()
	if w := loginReq(h, "198.51.100.51", "good"); w.Code != 429 {
		t.Errorf("valid new client: %d, want 429", w.Code)
	}
	full, shared := 0, 0
	for _, m := range msgs() {
		if strings.Contains(m, "table full") {
			full++
		}
		if strings.Contains(m, "untracked clients locked out for 120s after 3") {
			shared++
		}
	}
	if full != 1 || shared != 1 {
		t.Errorf("messages: table full %d, shared lockout %d, want 1 and 1", full, shared)
	}
}

func TestLoginGuardConcurrent(t *testing.T) {
	g, _ := guardWithClock(100)
	var wg sync.WaitGroup
	var checks atomic.Int32
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, v, _, _ := g.begin("192.0.2.1", 5, time.Minute)
			if v != loginAllow {
				return
			}
			checks.Add(1) // the expensive password check
			g.end(key, true, 5, time.Minute, time.Minute)
		}()
	}
	wg.Wait()
	if n := checks.Load(); n > 5 {
		t.Errorf("%d password checks, at most 5 allowed", n)
	}
}

func TestLoginBackoffAPIJSONAndBearer(t *testing.T) {
	roleTestSetup(t)
	oldGuard := webLoginGuard
	t.Cleanup(func() { webLoginGuard = oldGuard })
	webLoginGuard = newLoginGuard()
	cfg.Www.Loginfailures = 2
	cfg.Www.Loginwindow = 60
	cfg.Www.Loginlockout = 30
	cfg.Severity.Loginlockout = notifier.WARNING
	h := newWebHandler(false)
	get := func(tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/zw/api/v1/info", nil)
		r.RemoteAddr = "192.0.2.9:1"
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	get("zfsw_wrong")
	get("zfsw_wrong")
	w := get("zfsw_viewer")
	if w.Code != 429 || w.Header().Get("Retry-After") != "30" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !strings.Contains(w.Body.String(), "429") {
		t.Errorf("got %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	// /healthz is not subject to the lockout
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.RemoteAddr = "192.0.2.9:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 429 {
		t.Error("/healthz was locked out")
	}
}

func TestLoginBackoffUsesTrustedProxyClient(t *testing.T) {
	roleTestSetup(t)
	oldGuard := webLoginGuard
	t.Cleanup(func() { webLoginGuard = oldGuard })
	webLoginGuard = newLoginGuard()
	cfg.Www.Trustedproxies = "192.0.2.1"
	cfg.Www.Loginfailures = 2
	cfg.Www.Loginwindow = 60
	cfg.Www.Loginlockout = 30
	h := newWebHandler(false)
	get := func(peer, client, pass string) int {
		r := httptest.NewRequest("GET", "/zw/about/", nil)
		r.RemoteAddr = peer + ":1"
		r.Header.Set("X-Forwarded-For", client)
		r.SetBasicAuth("v", pass)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	get("192.0.2.1", "198.51.100.7", "bad")
	get("192.0.2.1", "198.51.100.7", "bad")
	if c := get("192.0.2.1", "198.51.100.7", "toor"); c != 429 {
		t.Errorf("forwarded client: %d, want 429", c)
	}
	if c := get("192.0.2.1", "198.51.100.8", "toor"); c != 200 {
		t.Errorf("other forwarded client: %d, want 200", c)
	}
	// an untrusted peer cannot choose its identity (or frame somebody else)
	get("203.0.113.5", "198.51.100.8", "bad")
	get("203.0.113.5", "198.51.100.8", "bad")
	if c := get("192.0.2.1", "198.51.100.8", "toor"); c != 200 {
		t.Errorf("forged header locked out a third party: %d", c)
	}
	if c := get("203.0.113.5", "198.51.100.99", "toor"); c != 429 {
		t.Errorf("untrusted peer: %d, want 429", c)
	}
}

func TestGetCfgLoginBackoff(t *testing.T) {
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	load := func(body string) *cfgType {
		cfgFile = filepath.Join(t.TempDir(), "z.conf")
		if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return getCfg()
	}
	c := load("")
	if c == nil || c.Www.Loginfailures != 5 || c.Www.Loginwindow != 60 || c.Www.Loginlockout != 60 ||
		c.Severity.Loginlockout != notifier.WARNING {
		t.Fatalf("defaults: %+v", c)
	}
	if c := load("[www]\nloginfailures = 0\nloginwindow = 0\n"); c == nil || c.Www.Loginfailures != 0 {
		t.Errorf("0 must switch it off: %+v", c)
	}
	if c := load("[www]\nloginfailures = 3\nloginwindow = 10\nloginlockout = 20\n[severity]\nloginlockout = crit\n"); c == nil ||
		c.Www.Loginfailures != 3 || c.Severity.Loginlockout != notifier.CRIT {
		t.Errorf("valid: %+v", c)
	}
	for _, v := range []string{
		"loginfailures = -1", "loginfailures = 100000", "loginwindow = 0", "loginwindow = -5",
		"loginlockout = 0", "loginlockout = 86401", "loginwindow = 86401",
	} {
		if load("[www]\n"+v+"\n") != nil {
			t.Errorf("getCfg accepted %q", v)
		}
	}
}

// cacheSetup is backoffSetup plus a fresh credential cache with a fake clock.
func cacheSetup(t *testing.T) (*fakeClock, *countingAuth, http.HandlerFunc) {
	t.Helper()
	clk, a, h := backoffSetup(t)
	old := webAuthCache
	t.Cleanup(func() { webAuthCache = old })
	webAuthCache = newAuthCache()
	webAuthCache.now = clk.now
	return clk, a, h
}

func TestAuthCacheParallelNeverRateLimited(t *testing.T) {
	_, a, h := cacheSetup(t)
	if w := loginReq(h, "192.0.2.1", "good"); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := loginReq(h, "192.0.2.1", "good"); w.Code != 200 {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d requests were refused", bad.Load())
	}
	if a.calls != 1 {
		t.Errorf("%d credential checks, want 1", a.calls)
	}
}

func TestAuthCacheLockedIPStillRefused(t *testing.T) {
	_, _, h := cacheSetup(t)
	loginReq(h, "192.0.2.1", "good") // cached
	for i := 0; i < 3; i++ {
		loginReq(h, "192.0.2.1", "bad")
	}
	if w := loginReq(h, "192.0.2.1", "good"); w.Code != 429 {
		t.Errorf("got %d, want 429", w.Code)
	}
}

func TestAuthCacheTTLAndFlush(t *testing.T) {
	clk, a, h := cacheSetup(t)
	loginReq(h, "192.0.2.1", "good")
	loginReq(h, "192.0.2.1", "good")
	if a.calls != 1 {
		t.Fatalf("calls %d", a.calls)
	}
	clk.advance(authCacheTTL + time.Second)
	loginReq(h, "192.0.2.1", "good")
	if a.calls != 2 {
		t.Errorf("calls %d after TTL, want 2", a.calls)
	}
	webAuthCache.flush()
	loginReq(h, "192.0.2.1", "good")
	if a.calls != 3 {
		t.Errorf("calls %d after flush, want 3", a.calls)
	}
	// a new configuration object invalidates it too
	cfg2 := *cfg
	cfg = &cfg2
	loginReq(h, "192.0.2.1", "good")
	if a.calls != 4 {
		t.Errorf("calls %d after reload, want 4", a.calls)
	}
}

func TestAuthCacheWrongPasswordNeverHits(t *testing.T) {
	_, a, h := cacheSetup(t)
	loginReq(h, "192.0.2.1", "good")
	if w := loginReq(h, "192.0.2.2", "bad"); w.Code != 401 {
		t.Errorf("got %d, want 401", w.Code)
	}
	if a.calls != 2 {
		t.Errorf("calls %d, want 2", a.calls)
	}
}

func TestAuthCacheLimitAndTokenPath(t *testing.T) {
	c := newAuthCache()
	cfg = &cfgType{}
	t.Cleanup(func() { cfg = nil })
	for i := 0; i < authCacheMaxEntries+50; i++ {
		r := httptest.NewRequest("GET", "/x", nil)
		r.SetBasicAuth("u", strconv.Itoa(i))
		c.put(r, &Principal{Name: "u", Role: RoleViewer}, c.token())
	}
	if len(c.entries) > authCacheMaxEntries {
		t.Errorf("%d entries", len(c.entries))
	}
	// a Bearer header cached for the API path does not hit elsewhere
	api := httptest.NewRequest("GET", cfg.Www.Rootdir+"/api/v1/info", nil)
	api.Header.Set("Authorization", "Bearer t")
	c.put(api, &Principal{Name: "t", Role: RoleViewer, Method: methodToken}, c.token())
	web := httptest.NewRequest("GET", "/about/", nil)
	web.Header.Set("Authorization", "Bearer t")
	if c.get(api) == nil || c.get(web) != nil {
		t.Error("token cache entry leaked to non API path")
	}
}

// A reload between the credential check and put must not leave a result
// of the old configuration in the cache.
func TestAuthCacheReloadDuringCheck(t *testing.T) {
	cfg = &cfgType{}
	t.Cleanup(func() { cfg = nil })
	c := newAuthCache()
	r := httptest.NewRequest("GET", "/x", nil)
	r.SetBasicAuth("u", "pw")
	p := &Principal{Name: "u", Role: RoleAdmin}

	tok := c.token()
	c.flush() // reconfigure()
	c.put(r, p, tok)
	if c.get(r) != nil {
		t.Error("principal checked before flush was cached")
	}
	tok = c.token()
	cfg = &cfgType{} // new configuration object
	c.put(r, p, tok)
	if c.get(r) != nil {
		t.Error("principal checked with the old cfg was cached")
	}
	c.put(r, p, c.token())
	if c.get(r) == nil {
		t.Error("regular put does not work")
	}
}
