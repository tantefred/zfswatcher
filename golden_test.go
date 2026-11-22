package main

import (
	"flag"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

// The golden tests pin down the HTML of the server-side rendered pages. They
// run the real handlers against fixtures, so that refactoring of the data
// layer below the handlers can not change the pages unnoticed. Run
// "go test -run Golden -update" to rewrite the golden files after an
// intended change.
var updateGolden = flag.Bool("update", false, "rewrite the golden files in test/golden")

// goldenFixtures lists the "zpool status" fixtures used for the pages.
var goldenFixtures = []string{
	"zpool-status-vdev-classes.txt",
	"zpool-status-degraded.txt",
	"zpool-status-resilver-replacing.txt",
	"zpool-status-proxmox.txt",
	"zpool-status-draid-spare.txt",
	"zpool-status-data-corruption.txt",
	"zpool-status-raidz2-two-faulted.txt",
	"zpool-status-flag-g.txt",
}

// goldenUsage has columns name, avail, used, logicalused, usedsnap, usedds,
// usedrefreserv, usedchild, refer, mountpoint, compressratio. The last pool
// uses the legacy 9 column format; zfsw_draid has no entry at all.
var goldenUsage = strings.Join([]string{
	"zfsw_mix\t1G\t1G\t3G\t0B\t512M\t0B\t512M\t512M\t/zfsw_mix\t1.50x",
	"zfsw_mix/data\t1G\t512M\t1G\t0B\t512M\t0B\t0B\t512M\t/zfsw_mix/data\t1.00x",
	"test\t9G\t1G\t1G\t0B\t1G\t0B\t0B\t1G\t/test\t1.00x",
	"zfsw_mirror\t1G\t9G\t18G\t1G\t8G\t0B\t0B\t8G\t/zfsw_mirror\t2.00x",
	"datis\t7G\t3G\t4G\t0B\t3G\t0B\t0B\t3G\t/datis\t1.35x",
	"rpool\t1G\t79G\t80G\t1G\t78G\t0B\t0B\t78G\t/rpool\t1.10x",
	"secundus\t100G\t1G\t1G\t0B\t1G\t0B\t0B\t1G\t/secundus\t1.00x",
	"zfsw_susp\t3G\t7G\t7G\t0B\t7G\t0B\t0B\t7G\t/zfsw_susp\t1.00x",
	"zfsw_rz2\t1M\t1M\t2M\t0B\t1M\t0B\t0B\t1M\t/zfsw_rz2\t1.00x",
}, "\n") + "\n"

const goldenLegacyUsage = "zfsw_opt\t4G\t1G\t0B\t1G\t0B\t0B\t1G\t/zfsw_opt\n"

func goldenSetup(t *testing.T) {
	t.Helper()
	oldCfg := cfg
	cfg = &cfgType{}
	t.Cleanup(func() { cfg = oldCfg })
	cfg.Www.Rootdir = "/zw"
	cfg.Www.Logbuffer = 5
	cfg.Www.Refresh = 10
	cfg.Www.Severitycssclassmap = severityToWwwClassMap{
		notifier.CRIT: "table-danger", notifier.ERR: "table-danger", notifier.WARNING: "table-warning", notifier.INFO: "table-info",
	}
	cfg.Www.Poolstatecssclassmap = stringToStringMap{"ONLINE": "text-success", "DEGRADED": "text-warning", "FAULTED": "text-danger"}
	cfg.Www.Devstatecssclassmap = stringToStringMap{"ONLINE": "text-success", "DEGRADED": "text-warning", "FAULTED": "text-danger", "AVAIL": "text-info"}
	cfg.Www.Usedstatecssclassmap = severityToWwwClassMap{notifier.INFO: "bg-info", notifier.WARNING: "bg-warning", notifier.CRIT: "bg-danger"}
	cfg.Severity.Usedspace = percentageToSeverityMap{0: notifier.INFO, 70: notifier.WARNING, 90: notifier.CRIT}

	oldTemplates := templates
	tpl, err := template.New("zfswatcher").Funcs(template.FuncMap{"nicenumber": niceNumber}).ParseGlob("www/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	templates = tpl
	t.Cleanup(func() { templates = oldTemplates })

	currentState.mutex.Lock()
	oldState, oldUsage := currentState.state, currentState.usage
	currentState.state, currentState.usage = nil, nil
	currentState.mutex.Unlock()
	t.Cleanup(func() {
		currentState.mutex.Lock()
		currentState.state, currentState.usage = oldState, oldUsage
		currentState.mutex.Unlock()
	})
	wwwLogMutex.Lock()
	wwwLogBuffer = nil
	wwwLogMutex.Unlock()
	t.Cleanup(func() {
		wwwLogMutex.Lock()
		wwwLogBuffer = nil
		wwwLogMutex.Unlock()
	})
}

func goldenSetState(t *testing.T, pools []*PoolType, usage map[string]*PoolUsageType) {
	t.Helper()
	currentState.mutex.Lock()
	currentState.state, currentState.usage = pools, usage
	currentState.mutex.Unlock()
}

func goldenPools(t *testing.T) []*PoolType {
	t.Helper()
	var pools []*PoolType
	for _, f := range goldenFixtures {
		p, err := parseZpoolStatus(readFixture(t, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		pools = append(pools, p...)
	}
	return pools
}

func goldenUsageMap() map[string]*PoolUsageType {
	u := parseZfsList(goldenUsage)
	for k, v := range parseZfsList(goldenLegacyUsage) {
		u[k] = v
	}
	return u
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("test", "golden", name)
	// dashboard.html has CRLF line ends in parts; git may normalize them
	got = strings.ReplaceAll(got, "\r\n", "\n")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
		t.Errorf("%s differs from the golden file; run with -update if the change is intended\n--- got ---\n%s", name, got)
	}
}

// render runs the handler as the given role.
func renderAs(role Role, h http.HandlerFunc, path string) (int, string) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", path, nil)
	r = r.WithContext(withPrincipal(r.Context(), &Principal{Name: "test", Role: role, Method: methodBasic}))
	h(w, r)
	return w.Code, w.Body.String()
}

// render runs the handler as admin, the role of the golden files.
func render(h http.HandlerFunc, path string) (int, string) {
	return renderAs(RoleAdmin, h, path)
}

func TestGoldenStatus(t *testing.T) {
	goldenSetup(t)
	pools := goldenPools(t)
	goldenSetState(t, pools, goldenUsageMap())
	var b strings.Builder
	for _, p := range pools {
		code, body := render(statusHandler, "/zw/status/"+p.name)
		if code != 200 {
			t.Fatalf("pool %s: status %d", p.name, code)
		}
		b.WriteString("<!-- ===== " + p.name + " ===== -->\n" + body)
	}
	checkGolden(t, "status-many.html", b.String())

	// a single pool uses another template
	goldenSetState(t, pools[:1], goldenUsageMap())
	_, body := render(statusHandler, "/zw/status/"+pools[0].name)
	checkGolden(t, "status-single.html", body)

	// no pools at all
	goldenSetState(t, nil, nil)
	_, body = render(statusHandler, "/zw/status/")
	checkGolden(t, "status-none.html", body)
}

func TestGoldenStatusRedirectAndErrors(t *testing.T) {
	goldenSetup(t)
	goldenSetState(t, goldenPools(t), nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/zw/status/", nil)
	statusHandler(w, r.WithContext(withPrincipal(r.Context(), &Principal{Role: RoleAdmin})))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/zw/status/zfsw_mix" {
		t.Errorf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	if code, _ := render(statusHandler, "/zw/status/nonexistent"); code != http.StatusBadRequest {
		t.Errorf("unknown pool: got %d", code)
	}
	if code, _ := render(statusHandler, "/zw/status/bad%20name"); code != http.StatusBadRequest {
		t.Errorf("illegal pool name: got %d", code)
	}
}

func goldenLedSetup(t *testing.T) []*PoolType {
	t.Helper()
	goldenSetup(t)
	cfg.Leds.Enable = true
	devLedsMutex.Lock()
	old := devLeds
	devLeds = map[string]*devLed{
		"/var/tmp/zfsw-collect/c1": {},
		"/var/tmp/zfsw-collect/c2": {locate: true},
		"mirror-0":                 {}, // not a leaf: must not be queried
	}
	devLedsMutex.Unlock()
	t.Cleanup(func() {
		devLedsMutex.Lock()
		devLeds = old
		devLedsMutex.Unlock()
	})
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-vdev-classes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	goldenSetState(t, pools, goldenUsageMap())
	return pools
}

func TestGoldenStatusLeds(t *testing.T) {
	goldenLedSetup(t)
	_, body := render(statusHandler, "/zw/status/zfsw_mix")
	checkGolden(t, "status-leds.html", body)
}

// A viewer sees neither the Logs menu entry nor the locate buttons.
func TestGoldenViewer(t *testing.T) {
	goldenLedSetup(t)
	code, body := renderAs(RoleViewer, statusHandler, "/zw/status/zfsw_mix")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	checkGolden(t, "status-leds-viewer.html", body)
	if strings.Contains(body, "/zw/locate/") || strings.Contains(body, "/zw/logs/") {
		t.Error("viewer page contains locate or logs")
	}
	_, body = renderAs(RoleViewer, dashboardHandler, "/zw/")
	checkGolden(t, "dashboard-viewer.html", volatileRE.ReplaceAllString(body, "${1}</dt>${2}VOLATILE"))
	if strings.Contains(body, "/zw/logs/") {
		t.Error("viewer dashboard links the logs")
	}

	// the operator gets both
	_, body = renderAs(RoleOperator, statusHandler, "/zw/status/zfsw_mix")
	if !strings.Contains(body, "/zw/locate/") || !strings.Contains(body, "/zw/logs/") {
		t.Error("operator page lacks locate or logs")
	}
}

// volatileRE matches the values of the dashboard which change on every run.
var volatileRE = regexp.MustCompile(`(load averages|system uptime|zfswatcher uptime)</dt>(\s*<dd class="[^"]*">)[^<\n]*`)

func TestGoldenDashboard(t *testing.T) {
	goldenSetup(t)
	pools := goldenPools(t)
	goldenSetState(t, pools, goldenUsageMap())
	code, body := render(dashboardHandler, "/zw/")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	checkGolden(t, "dashboard.html", volatileRE.ReplaceAllString(body, "${1}</dt>${2}VOLATILE"))

	goldenSetState(t, nil, nil)
	_, body = render(dashboardHandler, "/zw/")
	checkGolden(t, "dashboard-none.html", volatileRE.ReplaceAllString(body, "${1}</dt>${2}VOLATILE"))
}

func TestGoldenUsage(t *testing.T) {
	goldenSetup(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "zfslist.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat '"+mustAbs(t, "test/zfs-list-all-debian.txt")+"'\n"), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	cfg.Main.Zfslistusagecmd = script
	code, body := render(usageHandler, "/zw/usage/zfsw_mirror")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	checkGolden(t, "usage.html", body)

	legacy := filepath.Join(dir, "legacy.sh")
	if err := os.WriteFile(legacy, []byte("#!/bin/sh\nprintf '"+strings.ReplaceAll(strings.ReplaceAll(goldenLegacyUsage, "\t", "\\t"), "\n", "\\n")+"'\n"), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	cfg.Main.Zfslistusagecmd = legacy
	_, body = render(usageHandler, "/zw/usage/zfsw_opt")
	checkGolden(t, "usage-legacy.html", body)

	if code, _ := render(usageHandler, "/zw/usage/"); code != http.StatusBadRequest {
		t.Errorf("empty pool: got %d", code)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGoldenLogs(t *testing.T) {
	goldenSetup(t)
	cfg.Www.Logbuffer = 4
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.Local)
	msg := func(typ notifier.MsgType, sev notifier.Severity, text string, sec int) *notifier.Msg {
		return &notifier.Msg{Time: ts.Add(time.Duration(sec) * time.Second), MsgType: typ, Severity: sev, Text: text}
	}
	for _, m := range []*notifier.Msg{
		msg(notifier.MSGTYPE_MESSAGE, notifier.INFO, "dropped by the limit", 0),
		msg(notifier.MSGTYPE_MESSAGE, notifier.CRIT, "pool <b>tank</b> degraded", 1),
		msg(notifier.MSGTYPE_ATTACHMENT, notifier.CRIT, "zpool status output\n  line 2", 2),
		msg(notifier.MSGTYPE_ATTACHMENT, notifier.CRIT, "second attachment gets its own row", 3),
		msg(notifier.MSGTYPE_MESSAGE, notifier.WARNING, "plain warning", 4),
		msg(notifier.MSGTYPE_MESSAGE, notifier.DEBUG, "severity without css class", 5),
		msg(notifier.MSGTYPE_FLUSH, notifier.INFO, "ignored", 6),
	} {
		wwwLogReceiver(m)
	}
	code, body := render(logsHandler, "/zw/logs/")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	checkGolden(t, "logs.html", body)
}

const goldenEnclosure = `  pool: encl
 state: DEGRADED
config:

	NAME        STATE     READ WRITE CKSUM
	encl        DEGRADED     0     0     0
	  raidz1-0  DEGRADED     0     0     0
	    1-3     ONLINE       0     0     0
	    1-1     ONLINE       0     0     0
	    1-2     FAULTED      0     0     0
	    2-2     ONLINE       0     0     0
	    2-1     DEGRADED     0     0     0
	    sda     ONLINE       0     0     0
	logs
	  1-10      ONLINE       0     0     0

errors: No known data errors
`

func TestGoldenEnclosure(t *testing.T) {
	goldenSetup(t)
	cfg.Chassis.Enable = true
	cfg.Chassis.Chassis45drives45 = true
	pools, err := parseZpoolStatus(goldenEnclosure)
	if err != nil {
		t.Fatal(err)
	}
	more, err := parseZpoolStatus(readFixture(t, "zpool-status-flag-g.txt"))
	if err != nil {
		t.Fatal(err)
	}
	goldenSetState(t, append(pools, more...), nil)
	code, body := render(enclosureHandler, "/zw/enclosure/")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	checkGolden(t, "enclosure.html", body)

	cfg.Chassis.Enable = false
	_, body = render(enclosureHandler, "/zw/enclosure/")
	checkGolden(t, "enclosure-disabled.html", body)
}

// The fragments of the automatic refresh are the content of the live part of
// the pages; with refresh = 0 the pages have no htmx attributes.
func TestGoldenFragmentsAndNoRefresh(t *testing.T) {
	goldenLedSetup(t)
	_, body := render(dashboardHandler, "/zw/?fragment=1")
	checkGolden(t, "dashboard-fragment.html", volatileRE.ReplaceAllString(body, "${1}</dt>${2}VOLATILE"))
	_, body = render(statusHandler, "/zw/status/zfsw_mix?fragment=1")
	checkGolden(t, "status-fragment.html", body)

	cfg.Www.Refresh = 0
	_, body = render(statusHandler, "/zw/status/zfsw_mix")
	checkGolden(t, "status-leds-norefresh.html", body)
	_, body = render(dashboardHandler, "/zw/")
	checkGolden(t, "dashboard-norefresh.html", volatileRE.ReplaceAllString(body, "${1}</dt>${2}VOLATILE"))
}
