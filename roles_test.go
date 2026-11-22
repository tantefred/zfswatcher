package main

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/tantefred/zfswatcher/notifier"
)

func TestRoleParseAndString(t *testing.T) {
	for _, c := range []struct {
		s string
		r Role
	}{{"viewer", RoleViewer}, {"operator", RoleOperator}, {"admin", RoleAdmin}} {
		r, err := parseRole(c.s)
		if err != nil || r != c.r || r.String() != c.s {
			t.Errorf("parseRole(%q) = %v, %v", c.s, r, err)
		}
	}
	for _, s := range []string{"", "Admin", "root", "viewer ", "0"} {
		if _, err := parseRole(s); err == nil {
			t.Errorf("parseRole(%q) accepted", s)
		}
	}
	if RoleViewer >= RoleOperator || RoleOperator >= RoleAdmin {
		t.Error("roles are not ordered")
	}
	if Role(0).String() != "Role(0)" {
		t.Errorf("Role(0).String() = %q", Role(0).String())
	}
	// an empty role in the configuration means admin
	if r, err := configRole(""); err != nil || r != RoleAdmin {
		t.Errorf("configRole(\"\") = %v, %v", r, err)
	}
	if _, err := configRole("bogus"); err == nil {
		t.Error("configRole accepted bogus")
	}
}

func TestConfigRolesAndTokens(t *testing.T) {
	good := testTokenHash("zfsw_x")
	c := cfgWithMain(t, `
[wwwuser "default"]
enable = true
password = x
[wwwuser "v"]
role = viewer
[apitoken "t"]
enable = true
hash = `+good+`
role = operator
[apitoken "off"]
enable = false
`)
	if c == nil {
		t.Fatal("valid configuration rejected")
	}
	if r, _ := configRole(c.Wwwuser["default"].Role); r != RoleAdmin {
		t.Errorf("default role = %v, want admin", r)
	}
	if r, _ := configRole(c.Wwwuser["v"].Role); r != RoleViewer {
		t.Errorf("role = %v, want viewer", r)
	}
	if got := c.Apitoken["t"]; got.Hash != good || got.Role != "operator" || !got.Enable {
		t.Errorf("token = %+v", got)
	}

	for name, body := range map[string]string{ //nolint:gosec // test data, no credentials
		"invalid user role":     "[wwwuser \"a\"]\nrole = superuser\n",
		"invalid token role":    "[apitoken \"a\"]\nenable = true\nhash = " + good + "\nrole = god\n",
		"missing hash":          "[apitoken \"a\"]\nenable = true\n",
		"no prefix":             "[apitoken \"a\"]\nenable = true\nhash = " + strings.TrimPrefix(good, "sha256:") + "\n",
		"short hash":            "[apitoken \"a\"]\nenable = true\nhash = sha256:abcd\n",
		"not hex":               "[apitoken \"a\"]\nenable = true\nhash = sha256:" + strings.Repeat("zz", 32) + "\n",
		"bad hash while off":    "[apitoken \"a\"]\nenable = false\nhash = nonsense\n",
		"other algorithm":       "[apitoken \"a\"]\nenable = true\nhash = sha512:" + strings.Repeat("00", 32) + "\n",
		"uppercase prefix":      "[apitoken \"a\"]\nenable = true\nhash = SHA256:" + strings.Repeat("00", 32) + "\n",
		"role only wrong token": "[apitoken \"a\"]\nenable = false\nrole = nobody\n",
	} {
		if cfgWithMain(t, body) != nil {
			t.Errorf("%s: configuration accepted", name)
		}
	}
}

func testTokenHash(token string) string {
	return hashToken(token)
}

// roleTestSetup builds the real handler tree with one user per role and
// tokens for each role.
func roleTestSetup(t *testing.T) http.Handler {
	t.Helper()
	goldenSetup(t)
	cfg.Www.Resourcedir = t.TempDir()
	cfg.Wwwuser = map[string]*wwwUserCfg{
		"v":       {Enable: true, Password: testToorBcryptHash, Role: "viewer"},
		"o":       {Enable: true, Password: testToorBcryptHash, Role: "operator"},
		"a":       {Enable: true, Password: testToorBcryptHash, Role: "admin"},
		"default": {Enable: true, Password: testToorBcryptHash},
		"off":     {Enable: false, Password: testToorBcryptHash, Role: "admin"},
	}
	cfg.Apitoken = map[string]*apiTokenCfg{
		"tv":  {Enable: true, Hash: hashToken("zfsw_viewer"), Role: "viewer"},
		"to":  {Enable: true, Hash: hashToken("zfsw_operator"), Role: "operator"},
		"td":  {Enable: true, Hash: hashToken("zfsw_default")},
		"off": {Enable: false, Hash: hashToken("zfsw_off"), Role: "admin"},
	}
	return newWebHandler(false)
}

func roleReq(h http.Handler, method, path, user string) *httptest.ResponseRecorder {
	var body *strings.Reader
	hdr := http.Header{}
	if method == "POST" {
		body = strings.NewReader(url.Values{"dev": {"nonexistent"}, "state": {"on"}}.Encode())
		hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		hdr.Set("Origin", "http://zfs.example")
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	r.Host = "zfs.example"
	r.Header = hdr
	if user != "" {
		r.SetBasicAuth(user, "toor")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRoleMatrix(t *testing.T) {
	h := roleTestSetup(t)
	routes := []struct {
		method, path string
		min          Role
	}{
		{"GET", "/zw/", RoleViewer},
		{"GET", "/zw/status/", RoleViewer},
		{"GET", "/zw/usage/tank", RoleViewer},
		{"GET", "/zw/statistics/", RoleViewer},
		{"GET", "/zw/enclosure/", RoleViewer},
		{"GET", "/zw/about/", RoleViewer},
		{"GET", "/zw/logs/", RoleOperator},
		{"POST", "/zw/locate/", RoleOperator},
		{"GET", "/zw/api/anything", RoleViewer},
	}
	users := []struct {
		name string
		role Role // 0: no access
	}{
		{"", 0}, {"v", RoleViewer}, {"o", RoleOperator}, {"a", RoleAdmin}, {"default", RoleAdmin}, {"off", 0},
	}
	for _, rt := range routes {
		for _, u := range users {
			w := roleReq(h, rt.method, rt.path, u.name)
			want := 0
			switch {
			case u.role == 0:
				want = http.StatusUnauthorized
			case u.role < rt.min:
				want = http.StatusForbidden
			}
			if want != 0 && w.Code != want {
				t.Errorf("%s %s as %q: got %d, want %d", rt.method, rt.path, u.name, w.Code, want)
			}
			if want == 0 && (w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden) {
				t.Errorf("%s %s as %q: denied with %d", rt.method, rt.path, u.name, w.Code)
			}
			if w.Code == http.StatusUnauthorized && !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), `Basic realm="zfswatcher"`) {
				t.Errorf("%s %s: no challenge", rt.method, rt.path)
			}
			if w.Code == http.StatusForbidden && w.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("%s %s as %q: 403 with challenge", rt.method, rt.path, u.name)
			}
		}
	}
}

func TestPublicRoutesNeedNoLogin(t *testing.T) {
	h := roleTestSetup(t)
	for _, p := range []string{"/zw/healthz", "/zw/resources/missing.css"} {
		if w := roleReq(h, "GET", p, ""); w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func bearerReq(h http.Handler, path, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestTokenAuth(t *testing.T) {
	h := roleTestSetup(t)
	cases := []struct {
		name, path, authz string
		want              int
	}{
		{"viewer token on API", "/zw/api/x", "Bearer zfsw_viewer", http.StatusNotFound},
		{"scheme case", "/zw/api/x", "bearer zfsw_viewer", http.StatusNotFound},
		{"operator token", "/zw/api/x", "Bearer zfsw_operator", http.StatusNotFound},
		{"token without role is admin", "/zw/api/x", "Bearer zfsw_default", http.StatusNotFound},
		{"API root", "/zw/api/", "Bearer zfsw_viewer", http.StatusNotFound},
		{"unknown token", "/zw/api/x", "Bearer zfsw_nope", http.StatusUnauthorized},
		{"disabled token", "/zw/api/x", "Bearer zfsw_off", http.StatusUnauthorized},
		{"empty token", "/zw/api/x", "Bearer ", http.StatusUnauthorized},
		{"hash instead of token", "/zw/api/x", "Bearer " + hashToken("zfsw_viewer"), http.StatusUnauthorized},
		{"wrong scheme", "/zw/api/x", "Token zfsw_viewer", http.StatusUnauthorized},
		{"token without scheme", "/zw/api/x", "zfsw_viewer", http.StatusUnauthorized},
		{"no header", "/zw/api/x", "", http.StatusUnauthorized},
		{"token on page", "/zw/about/", "Bearer zfsw_viewer", http.StatusUnauthorized},
		{"admin token on dashboard", "/zw/", "Bearer zfsw_default", http.StatusUnauthorized},
		{"token on logs", "/zw/logs/", "Bearer zfsw_operator", http.StatusUnauthorized},
		{"token on prefix lookalike", "/zw/apix/", "Bearer zfsw_viewer", http.StatusUnauthorized},
	}
	for _, c := range cases {
		if w := bearerReq(h, c.path, c.authz); w.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.want)
		}
	}
	// Basic works for the API as well
	if w := roleReq(h, "GET", "/zw/api/x", "v"); w.Code != http.StatusNotFound {
		t.Errorf("basic on API: %d", w.Code)
	}
	// wrong Basic credentials are not rescued by a valid token
	r := httptest.NewRequest("GET", "/zw/api/x", nil)
	r.SetBasicAuth("v", "wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong basic: %d", w.Code)
	}
}

func TestTokenRolesEnforced(t *testing.T) {
	roleTestSetup(t)
	auth := newAuthenticator()
	var seen *Principal
	h := requireRoleWith(auth, plainError, RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		seen = principalFrom(r.Context())
	})
	for _, c := range []struct {
		token string
		want  int
		name  string
	}{
		{"zfsw_viewer", http.StatusForbidden, ""},
		{"zfsw_operator", http.StatusOK, "to"},
		{"zfsw_default", http.StatusOK, "td"},
	} {
		seen = nil
		r := httptest.NewRequest("GET", "/zw/api/x", nil)
		r.Header.Set("Authorization", "Bearer "+c.token)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d", c.token, w.Code)
		}
		if c.want == http.StatusOK && (seen == nil || seen.Name != c.name || seen.Method != methodToken) {
			t.Errorf("%s: principal %+v", c.token, seen)
		}
	}
	if principalFrom(httptest.NewRequest("GET", "/", nil).Context()) != nil {
		t.Error("principal without middleware")
	}
}

func TestErrorRendererHook(t *testing.T) {
	roleTestSetup(t)
	var codes []int
	render := func(w http.ResponseWriter, r *http.Request, code int, msg string) {
		codes = append(codes, code)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
	}
	h := requireRoleWith(newAuthenticator(), render, RoleAdmin, func(http.ResponseWriter, *http.Request) {})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/zw/api/x", nil))
	r := httptest.NewRequest("GET", "/zw/api/x", nil)
	r.Header.Set("Authorization", "Bearer zfsw_viewer")
	w2 := httptest.NewRecorder()
	h(w2, r)
	if len(codes) != 2 || codes[0] != 401 || codes[1] != 403 ||
		w.Header().Get("Content-Type") != "application/json" || w2.Header().Get("Content-Type") != "application/json" {
		t.Errorf("codes %v", codes)
	}
}

func TestFailedLoginLogged(t *testing.T) {
	roleTestSetup(t)
	oldNotify := notify
	t.Cleanup(func() { notify = oldNotify })
	notify = notifier.New()
	var mu sync.Mutex
	var msgs []string
	if err := notify.AddLoggerCallback(notifier.DEBUG, func(m *notifier.Msg) {
		if m.MsgType == notifier.MSGTYPE_MESSAGE {
			mu.Lock()
			msgs = append(msgs, m.Text)
			mu.Unlock()
		}
	}); err != nil {
		t.Fatal(err)
	}
	h := newWebHandler(false)
	r := httptest.NewRequest("GET", "/zw/api/x", nil)
	r.Header.Set("Authorization", "Bearer zfsw_wrong")
	h.ServeHTTP(httptest.NewRecorder(), r)
	r = httptest.NewRequest("GET", "/zw/about/", nil)
	r.SetBasicAuth("v", "bad")
	h.ServeHTTP(httptest.NewRecorder(), r)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/zw/about/", nil)) // no credentials: no log
	<-notify.Close()
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "web login failed for API token from") ||
		!strings.Contains(joined, `web login failed for user "v" from`) || len(msgs) != 2 {
		t.Errorf("log: %q", msgs)
	}
	if strings.Contains(joined, "zfsw_wrong") {
		t.Error("token written to the log")
	}
}

func TestTokenAuthenticatorUsesHashOnly(t *testing.T) {
	roleTestSetup(t)
	// a broken stored hash never matches (and does not panic)
	cfg.Apitoken["broken"] = &apiTokenCfg{Enable: true, Hash: "sha256:zz"}
	r := httptest.NewRequest("GET", "/zw/api/x", nil)
	r.Header.Set("Authorization", "Bearer sha256:zz")
	if p, err := (tokenAuthenticator{}).Authenticate(r); p != nil || err == nil {
		t.Errorf("got %v, %v", p, err)
	}
	// the first token wins nothing special: all enabled tokens are compared
	r.Header.Set("Authorization", "Bearer zfsw_viewer")
	if p, err := (tokenAuthenticator{}).Authenticate(r); err != nil || p == nil || p.Name != "tv" || p.Role != RoleViewer {
		t.Errorf("got %v, %v", p, err)
	}
}

func TestGenerateToken(t *testing.T) {
	var out, errOut strings.Builder
	if rc := wwwGenerateToken(&out, &errOut); rc != 0 || errOut.Len() != 0 {
		t.Fatalf("rc %d: %s", rc, errOut.String())
	}
	lines := strings.Split(out.String(), "\n")
	var token, hashLine string
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "zfsw_"):
			token = l
		case strings.HasPrefix(l, "hash = "):
			hashLine = l
		}
	}
	// 5 + base64url(32 bytes) without padding = 43 characters
	if len(token) != len("zfsw_")+43 || strings.ContainsAny(token, "+/=") {
		t.Errorf("token %q", token)
	}
	if hashLine != "hash = "+hashToken(token) {
		t.Errorf("hash line %q does not match the token", hashLine)
	}
	if _, err := parseTokenHash(strings.TrimPrefix(hashLine, "hash = ")); err != nil {
		t.Error(err)
	}
	if !strings.Contains(out.String(), "only once") {
		t.Error("no hint to store the token")
	}
	// two runs give different tokens
	var out2 strings.Builder
	wwwGenerateToken(&out2, &errOut)
	if out.String() == out2.String() {
		t.Error("tokens repeat")
	}
	// the hash is SHA-256 of the token
	sum := sha256.Sum256([]byte(token))
	if !strings.HasSuffix(hashLine, hexOf(sum[:])) {
		t.Error("not a SHA-256 hash")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestGenerateTokenRandomFailure(t *testing.T) {
	var out, errOut strings.Builder
	if rc := generateToken(iotest.ErrReader(errors.New("no entropy")), &out, &errOut); rc != 1 || out.Len() != 0 ||
		!strings.Contains(errOut.String(), "no entropy") {
		t.Errorf("rc=%d out=%q err=%q", rc, out.String(), errOut.String())
	}
	if rc := generateToken(strings.NewReader("short"), &out, &errOut); rc != 1 {
		t.Errorf("short read: rc=%d", rc)
	}
}

func TestIsAPIPath(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = &cfgType{}
	for root, cases := range map[string]map[string]bool{
		"/zw": {"/zw/api": true, "/zw/api/": true, "/zw/api/v1/x": true, "/zw/apix": false, "/zw/": false, "/api/": false},
		"":    {"/api/x": true, "/api": true, "/apix": false, "/": false},
	} {
		cfg.Www.Rootdir = root
		for p, want := range cases {
			if got := isAPIPath(p); got != want {
				t.Errorf("root %q path %q: %v", root, p, got)
			}
		}
	}
}
