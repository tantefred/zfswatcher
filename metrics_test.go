package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var metricsTestQuery = ZpoolQuery{Seen: true, OK: true, Time: time.Unix(1700000000, 500e6)}

func TestGoldenMetrics(t *testing.T) {
	goldenSetup(t)
	goldenSetState(t, goldenPools(t), goldenUsageMap())
	pools, usage := snapshotState()
	var b strings.Builder
	if err := writeMetrics(&b, "0.9.0", pools, usage, metricsTestQuery); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "metrics.txt", b.String())
}

func TestMetricsEscaping(t *testing.T) {
	if got := escapeLabelValue("a\\b\"c\nd"); got != `a\\b\"c\nd` {
		t.Errorf("escapeLabelValue = %q", got)
	}
	pools := []Pool{{Name: "p\"1", State: "ONLINE", Devices: []Device{
		{Name: "dev\\x\ny", State: "ONLINE", Read: 1, Write: 2, Cksum: 3, Children: []Device{}},
	}}}
	var b strings.Builder
	if err := writeMetrics(&b, "v\"1", pools, nil, ZpoolQuery{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`zfswatcher_build_info{version="v\"1"} 1`,
		`zfswatcher_pool_state{pool="p\"1",state="ONLINE"} 1`,
		`zfswatcher_device_read_errors{pool="p\"1",device="dev\\x\ny"} 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "last_check") || strings.Contains(out, "pool_usable_bytes{") {
		t.Errorf("unexpected series without query and usage:\n%s", out)
	}
}

func TestMetricsUnknownStateAndMissingValues(t *testing.T) {
	pools := []Pool{{Name: "p", State: "WEIRD", Devices: []Device{
		{Name: "p", State: "WEIRD", Read: 0, Write: -1, Cksum: -1},
		{Name: "logs", State: "", Read: -1, Write: -1, Cksum: -1},
	}}}
	var b strings.Builder
	_ = writeMetrics(&b, "x", pools, map[string]Usage{"p": {Name: "p", Used: -1, Avail: 5}}, metricsTestQuery)
	out := b.String()
	for _, want := range []string{
		`zfswatcher_pool_state{pool="p",state="WEIRD"} 1`,
		`zfswatcher_pool_state{pool="p",state="ONLINE"} 0`,
		`zfswatcher_device_read_errors{pool="p",device="p"} 0`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{`device="logs"`, "write_errors{", "pool_available_bytes{"} {
		if strings.Contains(out, bad) {
			t.Errorf("unexpected %q", bad)
		}
	}
}

func metricsRoleSetup(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	goldenSetup(t)
	cfg.Www.Metrics = enabled
	cfg.Www.Resourcedir = t.TempDir()
	cfg.Wwwuser = map[string]*wwwUserCfg{"v": {Enable: true, Password: testToorBcryptHash, Role: "viewer"}}
	cfg.Apitoken = map[string]*apiTokenCfg{"tv": {Enable: true, Hash: hashToken("zfsw_viewer"), Role: "viewer"}}
	goldenSetState(t, goldenPools(t)[:1], goldenUsageMap())
	return newWebHandler(false)
}

func metricsDo(h http.Handler, method, path string, setup func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "zfs.example"
	if setup != nil {
		setup(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMetricsAuth(t *testing.T) {
	h := metricsRoleSetup(t, true)
	basic := func(r *http.Request) { r.SetBasicAuth("v", "toor") }
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer zfsw_viewer") }

	if w := metricsDo(h, "GET", "/zw/metrics", nil); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") || strings.Contains(w.Body.String(), "zfswatcher_") {
		t.Errorf("no auth: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	for name, setup := range map[string]func(*http.Request){"basic": basic, "bearer": bearer} {
		w := metricsDo(h, "GET", "/zw/metrics", setup)
		if w.Code != 200 || w.Header().Get("Content-Type") != metricsContentType ||
			!strings.Contains(w.Body.String(), "# TYPE zfswatcher_pool_state gauge") {
			t.Errorf("%s: %d %q", name, w.Code, w.Header().Get("Content-Type"))
		}
	}
	if w := metricsDo(h, "HEAD", "/zw/metrics", bearer); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d body bytes", w.Code, w.Body.Len())
	}
	if w := metricsDo(h, "GET", "/zw/metrics", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }); w.Code != 401 {
		t.Errorf("wrong token: %d", w.Code)
	}
	// tokens stay limited to the API and the metrics
	if w := metricsDo(h, "GET", "/zw/", bearer); w.Code != 401 {
		t.Errorf("bearer on dashboard: %d", w.Code)
	}
	if w := metricsDo(h, "GET", "/zw/status/", bearer); w.Code != 401 {
		t.Errorf("bearer on status: %d", w.Code)
	}
	if w := metricsDo(h, "GET", "/zw/api/v1/info", bearer); w.Code != 200 {
		t.Errorf("bearer on api: %d", w.Code)
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		w := metricsDo(h, m, "/zw/metrics", func(r *http.Request) {
			basic(r)
			r.Header.Set("Origin", "http://zfs.example")
		})
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d allow %q", m, w.Code, w.Header().Get("Allow"))
		}
	}
}

func TestMetricsDisabled(t *testing.T) {
	h := metricsRoleSetup(t, false)
	for _, setup := range []func(*http.Request){
		func(r *http.Request) { r.SetBasicAuth("v", "toor") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer zfsw_viewer") },
	} {
		w := metricsDo(h, "GET", "/zw/metrics", setup)
		if w.Header().Get("Content-Type") == metricsContentType || strings.Contains(w.Body.String(), "zfswatcher_") ||
			strings.Contains(w.Body.String(), "# TYPE") {
			t.Errorf("metrics served although disabled: %d", w.Code)
		}
		if w.Code == 200 && w.Header().Get("Authorization") == "" && strings.Contains(w.Body.String(), "zfswatcher_pool_state") {
			t.Error("metric content")
		}
	}
	// a bearer token must not open the catch-all page either
	if w := metricsDo(h, "GET", "/zw/metrics", func(r *http.Request) { r.Header.Set("Authorization", "Bearer zfsw_viewer") }); w.Code != 401 {
		t.Errorf("bearer with metrics off: %d", w.Code)
	}
}
