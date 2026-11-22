package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// webUITestHandler builds the real handler tree with the golden fixtures,
// the locate buttons enabled and users of each role (see roleTestSetup).
func webUITestHandler(t *testing.T) http.Handler {
	t.Helper()
	goldenLedSetup(t)
	cfg.Www.Resourcedir = t.TempDir()
	cfg.Wwwuser = map[string]*wwwUserCfg{
		"v": {Enable: true, Password: testToorBcryptHash, Role: "viewer"},
		"o": {Enable: true, Password: testToorBcryptHash, Role: "operator"},
	}
	return newWebHandler(false)
}

func TestFragmentRoutes(t *testing.T) {
	h := webUITestHandler(t)

	for _, path := range []string{"/zw/?fragment=1", "/zw/status/zfsw_mix?fragment=1"} {
		w := roleReq(h, "GET", path, "o")
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		if strings.Contains(body, "<html") || strings.Contains(body, "<nav") || strings.Contains(body, "<body") {
			t.Errorf("%s: fragment contains the page frame", path)
		}
		if !strings.Contains(body, "zfsw_mix") {
			t.Errorf("%s: fragment lacks the pool", path)
		}
		if w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: headers %v", path, w.Header())
		}
		// the same page without the fragment query is the whole page
		full := roleReq(h, "GET", strings.TrimSuffix(path, "?fragment=1"), "o").Body.String()
		if !strings.Contains(full, "<html") || !strings.Contains(full, strings.TrimSpace(strings.SplitN(body, "\n", 3)[1])) {
			t.Errorf("%s: full page does not contain the fragment", path)
		}
	}
	if w := roleReq(h, "GET", "/zw/?fragment=1", "o"); !strings.Contains(w.Body.String(), "load averages") {
		t.Error("dashboard fragment lacks the load averages")
	}

	// roles: the fragment of the status page has the locate buttons for the
	// operator only
	op := roleReq(h, "GET", "/zw/status/zfsw_mix?fragment=1", "o").Body.String()
	vw := roleReq(h, "GET", "/zw/status/zfsw_mix?fragment=1", "v")
	if vw.Code != 200 {
		t.Fatalf("viewer: status %d", vw.Code)
	}
	if !strings.Contains(op, "/zw/locate/") || strings.Contains(vw.Body.String(), "/zw/locate/") {
		t.Error("locate buttons in the fragment do not follow the role")
	}

	// without login the fragments answer 401 like the pages
	for _, path := range []string{"/zw/?fragment=1", "/zw/status/zfsw_mix?fragment=1"} {
		if w := roleReq(h, "GET", path, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without login: got %d", path, w.Code)
		}
	}

	// errors stay errors
	if w := roleReq(h, "GET", "/zw/status/nonexistent?fragment=1", "o"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown pool: got %d", w.Code)
	}

	// no pools: the fragment shows the notice
	goldenSetState(t, nil, nil)
	for _, path := range []string{"/zw/?fragment=1", "/zw/status/x?fragment=1"} {
		w := roleReq(h, "GET", path, "o")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "There are no pools.") || strings.Contains(w.Body.String(), "<html") {
			t.Errorf("%s without pools: %d %q", path, w.Code, w.Body.String())
		}
	}
}

// usesHTMX reports whether a page loads htmx or has htmx attributes (the
// about page only names htmx in its license text).
func usesHTMX(body string) bool {
	return strings.Contains(body, " hx-") || strings.Contains(body, "htmx.min.js") || strings.Contains(body, "htmx-config")
}

func TestRefreshAttributes(t *testing.T) {
	h := webUITestHandler(t)

	live := map[string]string{
		"/zw/":                "/zw/?fragment=1",
		"/zw/status/zfsw_mix": "/zw/status/zfsw_mix?fragment=1",
	}
	for path, frag := range live {
		body := roleReq(h, "GET", path, "o").Body.String()
		for _, want := range []string{
			`hx-get="` + frag + `"`, `hx-trigger="every 10s"`, `hx-swap="innerHTML"`,
			`name="htmx-config"`, `"allowEval":false`, `"includeIndicatorStyles":false`, `"selfRequestsOnly":true`,
			`/zw/resources/htmx/htmx.min.js`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: %q missing", path, want)
			}
		}
	}
	cfg.Www.Refresh = 30
	if body := roleReq(h, "GET", "/zw/", "o").Body.String(); !strings.Contains(body, `hx-trigger="every 30s"`) {
		t.Error("the interval is not taken from the configuration")
	}

	// pages without a live part do not load htmx
	cfg.Www.Refresh = 10
	if body := roleReq(h, "GET", "/zw/about/", "o").Body.String(); usesHTMX(body) {
		t.Error("the about page uses htmx")
	}

	// refresh = 0: no hx attributes, no htmx
	cfg.Www.Refresh = 0
	for _, path := range []string{"/zw/", "/zw/status/zfsw_mix", "/zw/status/zfsw_mix?fragment=1", "/zw/about/", "/zw/logs/"} {
		w := roleReq(h, "GET", path, "o")
		if w.Code != 200 {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		if body := w.Body.String(); usesHTMX(body) {
			t.Errorf("%s: htmx is still used with refresh = 0", path)
		}
	}
}

func TestSecurityHeadersCSP(t *testing.T) {
	if strings.Contains(webCSP, "unsafe-inline") || strings.Contains(webCSP, "unsafe-eval") {
		t.Errorf("CSP allows inline code: %s", webCSP)
	}
	for _, want := range []string{"script-src 'self'", "style-src 'self';", "default-src 'self'"} {
		if !strings.Contains(webCSP, want) {
			t.Errorf("CSP lacks %q: %s", want, webCSP)
		}
	}
	h := webUITestHandler(t)
	if got := roleReq(h, "GET", "/zw/about/", "v").Header().Get("Content-Security-Policy"); got != webCSP {
		t.Errorf("CSP header %q", got)
	}
}

var (
	tagRE     = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	commentRE = regexp.MustCompile(`(?s)<!--.*?-->`)
)

var voidElements = map[string]bool{"meta": true, "link": true, "input": true, "br": true, "hr": true, "img": true}

// checkWellFormed checks the basic structure of a page: doctype, balanced
// elements and the elements every page needs.
func checkWellFormed(t *testing.T, name, body string) {
	t.Helper()
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Errorf("%s: no doctype", name)
	}
	body = commentRE.ReplaceAllString(body, "")
	var stack []string
	for _, m := range tagRE.FindAllStringSubmatch(body, -1) {
		tag := strings.ToLower(m[2])
		switch {
		case voidElements[tag]:
		case m[1] == "/":
			if len(stack) == 0 || stack[len(stack)-1] != tag {
				t.Errorf("%s: unexpected </%s>, open: %v", name, tag, stack)
				return
			}
			stack = stack[:len(stack)-1]
		case strings.HasSuffix(m[3], "/"):
		default:
			stack = append(stack, tag)
		}
	}
	if len(stack) != 0 {
		t.Errorf("%s: unclosed elements %v", name, stack)
	}
	for _, want := range []string{"<html lang=", "<title>zfswatcher</title>", `name="viewport"`, "<nav ", "<main ", "</main>", "bootstrap.bundle.min.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s: %q missing", name, want)
		}
	}
	// the CSP forbids inline scripts and styles
	if strings.Contains(body, " style=") {
		t.Errorf("%s: inline style", name)
	}
	for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(m, " src=") {
			t.Errorf("%s: inline script %s", name, m)
		}
	}
	if regexp.MustCompile(` on[a-z]+=`).MatchString(body) || strings.Contains(body, "<style") {
		t.Errorf("%s: inline handler or style element", name)
	}
	if strings.Contains(strings.ToLower(body), "jquery") {
		t.Errorf("%s: mentions jquery", name)
	}
}

func TestAllPagesWellFormed(t *testing.T) {
	h := webUITestHandler(t)
	cfg.Chassis.Enable = true
	cfg.Chassis.Chassis45drives45 = true
	cfg.Chassis.Chassis45drives30 = true
	for _, role := range []string{"v", "o"} {
		for _, path := range []string{
			"/zw/", "/zw/status/", "/zw/status/zfsw_mix", "/zw/enclosure/",
			"/zw/statistics/", "/zw/about/", "/zw/logs/",
		} {
			w := roleReq(h, "GET", path, role)
			if role == "v" && path == "/zw/logs/" {
				if w.Code != http.StatusForbidden {
					t.Errorf("viewer %s: %d", path, w.Code)
				}
				continue
			}
			if path == "/zw/status/" {
				if w.Code != http.StatusSeeOther {
					t.Errorf("%s: %d", path, w.Code)
				}
				continue
			}
			if w.Code != 200 {
				t.Errorf("%s as %s: status %d", path, role, w.Code)
				continue
			}
			checkWellFormed(t, role+" "+path, w.Body.String())
		}
	}
	// the pages without data
	goldenSetState(t, nil, nil)
	for _, path := range []string{"/zw/", "/zw/status/"} {
		w := roleReq(h, "GET", path, "o")
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		checkWellFormed(t, "empty "+path, w.Body.String())
	}
}

// The templates must not use jQuery or inline code and every resource they
// refer to must exist.
func TestTemplatesAndResources(t *testing.T) {
	files, err := filepath.Glob("www/templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	resRE := regexp.MustCompile(`\{\{ \.Root \}\}/resources/([^"' ]+)`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if strings.Contains(strings.ToLower(text), "jquery") && filepath.Base(f) != "about.html" {
			t.Errorf("%s refers to jquery", f)
		}
		if strings.Contains(text, " style=") || strings.Contains(text, "<style") {
			t.Errorf("%s has inline styles", f)
		}
		for _, m := range resRE.FindAllStringSubmatch(text, -1) {
			if _, err := os.Stat(filepath.Join("www", "resources", m[1])); err != nil { //nolint:gosec // paths from our own templates
				t.Errorf("%s: resource %s: %v", f, m[1], err)
			}
		}
	}
	for _, old := range []string{"bootstrap/js/jquery.min.js", "bootstrap/js/bootstrap.min.js", "enclosure.js", "bootstrap/css/bootstrap-theme.min.css"} {
		if _, err := os.Stat(filepath.Join("www", "resources", old)); err == nil {
			t.Errorf("obsolete resource %s still exists", old)
		}
	}
	for _, lic := range []string{"bootstrap/LICENSE", "htmx/LICENSE"} {
		if _, err := os.Stat(filepath.Join("www", "resources", lic)); err != nil {
			t.Errorf("license file: %v", err)
		}
	}
}

// Every class the pages use for bar widths and indentation exists in the
// stylesheet.
func TestStylesheetHasDynamicClasses(t *testing.T) {
	raw, err := os.ReadFile("www/resources/zfswatcher.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)
	for p := 0; p <= 100; p++ {
		if c := "." + barClass(p) + " {"; !strings.Contains(css, c) {
			t.Fatalf("stylesheet lacks %s", c)
		}
	}
	for d := 0; d <= maxDepthClass; d++ {
		if c := "." + devIndentClass(d) + " {"; !strings.Contains(css, c) {
			t.Fatalf("stylesheet lacks %s", c)
		}
	}
	for _, state := range []string{"ONLINE", "OFFLINE", "REMOVED", "FAULTED", "SPLIT", "UNAVAIL", "DEGRADED", "UNKNOWN", "INUSE", "AVAIL", "SUSPENDED", "bogus"} {
		if c := "." + slotClass(true, state); !strings.Contains(css, c) {
			t.Errorf("stylesheet lacks %s", c)
		}
	}
	if !strings.Contains(css, "."+slotClass(false, "")) {
		t.Error("stylesheet lacks the empty slot")
	}
}

func TestBarAndIndentClass(t *testing.T) {
	for in, want := range map[int]string{-5: "pct-0", 0: "pct-0", 42: "pct-42", 100: "pct-100", 250: "pct-100"} {
		if got := barClass(in); got != want {
			t.Errorf("barClass(%d) = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[int]string{-1: "depth-0", 0: "depth-0", 3: "depth-3", 12: "depth-12", 40: "depth-12"} {
		if got := devIndentClass(in); got != want {
			t.Errorf("devIndentClass(%d) = %s, want %s", in, got, want)
		}
	}
}
