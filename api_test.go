package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// apiSetup builds the real handler tree for the given root directory with a
// fixture state (golden pools and usage, two log events).
func apiSetup(t *testing.T, root string) http.Handler {
	t.Helper()
	roleTestSetup(t)
	cfg.Www.Rootdir = root
	goldenSetState(t, goldenPools(t), goldenUsageMap())
	wwwLogMutex.Lock()
	wwwLogBuffer = []Event{
		{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Severity: "warning", Text: "one"},
		{Time: time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC), Severity: "crit", Text: "two", Attachment: "att"},
		{Time: time.Date(2026, 1, 2, 3, 4, 7, 0, time.UTC), Severity: "info", Text: "three"},
	}
	wwwLogMutex.Unlock()
	return newWebHandler(false)
}

func apiReq(h http.Handler, method, path, user, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "zfs.example"
	if user != "" {
		r.SetBasicAuth(user, "toor")
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func apiGet(t *testing.T, h http.Handler, path, user string, v any) *httptest.ResponseRecorder {
	t.Helper()
	w := apiReq(h, "GET", path, user, "")
	if w.Code != 200 {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
	}
	checkJSONHeaders(t, w)
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("GET %s: %v\n%s", path, err, w.Body)
	}
	return w
}

func checkJSONHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	if w.Header().Get("X-Content-Type-Options") == "" {
		t.Errorf("security headers missing")
	}
}

func checkAPIError(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, want %d (%s)", w.Code, code, w.Body)
	}
	checkJSONHeaders(t, w)
	var e struct{ Error string }
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error == "" {
		t.Errorf("not an error document: %q", w.Body)
	}
}

func TestAPIPools(t *testing.T) {
	h := apiSetup(t, "/zw")
	var res struct{ Pools []Pool }
	apiGet(t, h, "/zw/api/v1/pools", "v", &res)
	if len(res.Pools) != len(goldenPools(t)) || len(res.Pools) == 0 {
		t.Fatalf("%d pools", len(res.Pools))
	}
	deep := false
	for _, p := range res.Pools {
		if p.Name == "" || p.Devices == nil {
			t.Errorf("pool %+v", p)
		}
		p.Walk(func(d Device, depth int) {
			if depth > 0 {
				deep = true
			}
		})
	}
	if !deep {
		t.Error("no nested devices")
	}
	var raw map[string][]map[string]any
	apiGet(t, h, "/zw/api/v1/pools", "v", &raw)
	for _, k := range []string{"name", "state", "devices", "scan"} {
		if _, ok := raw["pools"][0][k]; !ok {
			t.Errorf("field %q missing", k)
		}
	}
}

func TestAPIPool(t *testing.T) {
	h := apiSetup(t, "/zw")
	name := goldenPools(t)[0].name
	var p Pool
	apiGet(t, h, "/zw/api/v1/pools/"+name, "v", &p)
	if p.Name != name || len(p.Devices) == 0 {
		t.Errorf("%+v", p)
	}
	checkAPIError(t, apiReq(h, "GET", "/zw/api/v1/pools/nonexistent", "v", ""), 404)
	checkAPIError(t, apiReq(h, "GET", "/zw/api/v1/pools/", "v", ""), 404)
	checkAPIError(t, apiReq(h, "GET", "/zw/api/v1/pools/a/b", "v", ""), 404)
}

func TestAPIUsage(t *testing.T) {
	h := apiSetup(t, "/zw")
	var res struct{ Usage []Usage }
	apiGet(t, h, "/zw/api/v1/usage", "v", &res)
	if len(res.Usage) < 2 {
		t.Fatalf("%d entries", len(res.Usage))
	}
	for i := 1; i < len(res.Usage); i++ {
		if res.Usage[i-1].Name >= res.Usage[i].Name {
			t.Errorf("not sorted: %q before %q", res.Usage[i-1].Name, res.Usage[i].Name)
		}
	}
	var raw map[string][]map[string]any
	apiGet(t, h, "/zw/api/v1/usage", "v", &raw)
	if _, ok := raw["usage"][0]["used_percent"].(float64); !ok {
		t.Errorf("used_percent: %v", raw["usage"][0])
	}
}

func TestAPIInfo(t *testing.T) {
	h := apiSetup(t, "/zw")
	var raw map[string]any
	apiGet(t, h, "/zw/api/v1/info", "v", &raw)
	for _, k := range []string{"version", "hostname", "zfswatcher_uptime_seconds", "system_uptime_seconds", "load_average", "last_zpool_query"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("field %q missing", k)
		}
	}
}

func TestAPIEvents(t *testing.T) {
	h := apiSetup(t, "/zw")
	var res struct{ Events []Event }
	apiGet(t, h, "/zw/api/v1/events", "o", &res)
	if len(res.Events) != 3 || res.Events[0].Text != "one" || res.Events[1].Attachment != "att" {
		t.Errorf("%+v", res.Events)
	}
	w := apiReq(h, "GET", "/zw/api/v1/events", "o", "")
	if !strings.Contains(w.Body.String(), `"time":"2026-01-02T03:04:05Z"`) {
		t.Errorf("time not RFC3339: %s", w.Body)
	}
	apiGet(t, h, "/zw/api/v1/events?limit=2", "o", &res)
	if len(res.Events) != 2 || res.Events[0].Text != "two" || res.Events[1].Text != "three" {
		t.Errorf("limit 2: %+v", res.Events)
	}
	apiGet(t, h, "/zw/api/v1/events?limit=100", "o", &res)
	if len(res.Events) != 3 {
		t.Errorf("limit 100: %+v", res.Events)
	}
	for _, q := range []string{"limit=0", "limit=-1", "limit=abc", "limit=", "limit=1.5"} {
		checkAPIError(t, apiReq(h, "GET", "/zw/api/v1/events?"+q, "o", ""), 400)
	}
}

func TestAPIRoles(t *testing.T) {
	h := apiSetup(t, "/zw")
	paths := []struct {
		path string
		min  Role
	}{
		{"/zw/api/v1/info", RoleViewer},
		{"/zw/api/v1/pools", RoleViewer},
		{"/zw/api/v1/pools/nonexistent", RoleViewer},
		{"/zw/api/v1/usage", RoleViewer},
		{"/zw/api/v1/events", RoleOperator},
		{"/zw/api/v1/nothing", RoleViewer},
	}
	users := []struct {
		basic, token string
		role         Role
	}{
		{"", "", 0}, {"v", "", RoleViewer}, {"o", "", RoleOperator}, {"a", "", RoleAdmin},
		{"", "zfsw_viewer", RoleViewer}, {"", "zfsw_operator", RoleOperator},
		{"", "zfsw_off", 0}, {"", "zfsw_bogus", 0},
	}
	for _, p := range paths {
		for _, u := range users {
			w := apiReq(h, "GET", p.path, u.basic, u.token)
			switch {
			case u.role == 0:
				checkAPIError(t, w, 401)
				if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
					t.Errorf("%s: no challenge", p.path)
				}
			case u.role < p.min:
				checkAPIError(t, w, 403)
				if w.Header().Get("WWW-Authenticate") != "" {
					t.Errorf("%s: 403 with challenge", p.path)
				}
			case p.path == "/zw/api/v1/nothing":
				checkAPIError(t, w, 404)
			default:
				if w.Code != 200 && w.Code != 404 {
					t.Errorf("%s as %v: %d", p.path, u, w.Code)
				}
			}
		}
	}
}

func TestAPIUnknownPaths(t *testing.T) {
	h := apiSetup(t, "/zw")
	for _, p := range []string{"/zw/api/", "/zw/api", "/zw/api/v2/pools", "/zw/api/v1/", "/zw/api/v1/pools/x/y", "/zw/api/v1/infoo"} {
		if p == "/zw/api" {
			continue // the mux redirects to /zw/api/
		}
		checkAPIError(t, apiReq(h, "GET", p, "v", ""), 404)
	}
	checkAPIError(t, apiReq(h, "GET", "/zw/api/x", "", ""), 401)
}

func TestAPIMethods(t *testing.T) {
	h := apiSetup(t, "/zw")
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		for _, p := range []string{"/zw/api/v1/info", "/zw/api/v1/pools", "/zw/api/v1/pools/x", "/zw/api/v1/usage", "/zw/api/v1/events", "/zw/api/v1/other"} {
			w := apiReq(h, m, p, "a", "")
			checkAPIError(t, w, 405)
			if a := w.Header().Get("Allow"); a != "GET, HEAD" {
				t.Errorf("%s %s: Allow %q", m, p, a)
			}
		}
	}
	checkAPIError(t, apiReq(h, "POST", "/zw/api/v1/info", "", ""), 401)
	w := apiReq(h, "HEAD", "/zw/api/v1/pools", "v", "")
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", w.Code, w.Body)
	}
	checkJSONHeaders(t, w)
}

func TestAPIEmptyState(t *testing.T) {
	h := apiSetup(t, "/zw")
	goldenSetState(t, nil, nil)
	wwwLogMutex.Lock()
	wwwLogBuffer = nil
	wwwLogMutex.Unlock()
	for path, want := range map[string]string{
		"/zw/api/v1/pools":  `{"pools":[]}`,
		"/zw/api/v1/usage":  `{"usage":[]}`,
		"/zw/api/v1/events": `{"events":[]}`,
	} {
		w := apiReq(h, "GET", path, "o", "")
		if strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("%s: %s", path, w.Body)
		}
	}
}

func TestAPIRootdirs(t *testing.T) {
	for _, root := range []string{"", "/zw", "/a/b"} {
		h := apiSetup(t, root)
		var res struct{ Pools []Pool }
		apiGet(t, h, root+"/api/v1/pools", "v", &res)
		if len(res.Pools) == 0 {
			t.Errorf("root %q: no pools", root)
		}
		var p Pool
		apiGet(t, h, root+"/api/v1/pools/"+res.Pools[0].Name, "v", &p)
		checkAPIError(t, apiReq(h, "GET", root+"/api/v1/zzz", "v", ""), 404)
		checkAPIError(t, apiReq(h, "POST", root+"/api/v1/pools", "v", ""), 405)
		// the web pages still work
		if w := apiReq(h, "GET", root+"/about/", "v", ""); w.Code != 200 {
			t.Errorf("root %q: about page %d", root, w.Code)
		}
	}
}
