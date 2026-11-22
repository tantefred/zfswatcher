package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tantefred/zfswatcher/notifier"
)

func TestTranslateCSSClass(t *testing.T) {
	for _, c := range []struct {
		in   string
		rows bool
		want string
	}{
		{"text-error", false, "text-danger"},
		{"text-warning", false, "text-warning"},
		{"text-muted", false, "text-body-secondary"},
		{"progress-bar-info", false, "bg-info"},
		{"progress-bar-warning", false, "bg-warning"},
		{"progress-bar-danger", false, "bg-danger"},
		{"progress-bar-success", false, "bg-success"},
		{"bar-warning", false, "bg-warning"},
		{"progress-bar-striped progress-bar-danger", false, "progress-bar-striped bg-danger"},
		{"error", true, "table-danger"},
		{"danger", true, "table-danger"},
		{"warning", true, "table-warning"},
		{"info", true, "table-info"},
		{"success", true, "table-success"},
		{"warning", false, "warning"},
		{"table-danger", true, "table-danger"},
		{"bg-danger", false, "bg-danger"},
		{"", true, ""},
		{"my-own-class", true, "my-own-class"},
	} {
		if got := translateCSSClass(c.in, c.rows); got != c.want {
			t.Errorf("translateCSSClass(%q, %v) = %q, want %q", c.in, c.rows, got, c.want)
		}
	}
}

func TestTranslateLegacyCSSClasses(t *testing.T) {
	c := &cfgType{}
	c.Www.Severitycssclassmap = severityToWwwClassMap{notifier.CRIT: "error", notifier.WARNING: "warning", notifier.DEBUG: ""}
	c.Www.Poolstatecssclassmap = stringToStringMap{"FAULTED": "text-error", "ONLINE": "text-success"}
	c.Www.Devstatecssclassmap = stringToStringMap{"AVAIL": "text-muted", "DEGRADED": "warning"}
	c.Www.Usedstatecssclassmap = severityToWwwClassMap{notifier.INFO: "progress-bar-info", notifier.CRIT: "progress-bar-danger"}
	translateLegacyCSSClasses(c)
	if want := (severityToWwwClassMap{notifier.CRIT: "table-danger", notifier.WARNING: "table-warning", notifier.DEBUG: ""}); !reflect.DeepEqual(c.Www.Severitycssclassmap, want) {
		t.Errorf("severity map: %v", c.Www.Severitycssclassmap)
	}
	if want := (stringToStringMap{"FAULTED": "text-danger", "ONLINE": "text-success"}); !reflect.DeepEqual(c.Www.Poolstatecssclassmap, want) {
		t.Errorf("pool map: %v", c.Www.Poolstatecssclassmap)
	}
	// plain "warning" is not a row class in the device state map
	if want := (stringToStringMap{"AVAIL": "text-body-secondary", "DEGRADED": "warning"}); !reflect.DeepEqual(c.Www.Devstatecssclassmap, want) {
		t.Errorf("dev map: %v", c.Www.Devstatecssclassmap)
	}
	if want := (severityToWwwClassMap{notifier.INFO: "bg-info", notifier.CRIT: "bg-danger"}); !reflect.DeepEqual(c.Www.Usedstatecssclassmap, want) {
		t.Errorf("used map: %v", c.Www.Usedstatecssclassmap)
	}
	// translating twice changes nothing
	translateLegacyCSSClasses(c)
	if c.Www.Poolstatecssclassmap["FAULTED"] != "text-danger" {
		t.Error("not idempotent")
	}
	translateLegacyCSSClasses(&cfgType{}) // nil maps
}

// An old configuration with Bootstrap 3 names is translated when loaded.
func TestGetCfgTranslatesOldClasses(t *testing.T) {
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	cfgFile = filepath.Join(t.TempDir(), "z.conf")
	body := `[www]
severitycssclassmap = crit:error err:warning info:info
poolstatecssclassmap = FAULTED:text-error
usedstatecssclassmap = none:progress-bar-info crit:progress-bar-danger
`
	if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := getCfg()
	if c == nil {
		t.Fatal("configuration rejected")
	}
	if got := c.Www.Severitycssclassmap[notifier.CRIT]; got != "table-danger" {
		t.Errorf("severity class %q", got)
	}
	if got := c.Www.Poolstatecssclassmap["FAULTED"]; got != "text-danger" {
		t.Errorf("pool class %q", got)
	}
	if got := c.Www.Usedstatecssclassmap[notifier.CRIT]; got != "bg-danger" {
		t.Errorf("used class %q", got)
	}
}

func TestCheckWwwRefresh(t *testing.T) {
	for _, c := range []struct {
		sec int
		ok  bool
	}{{0, true}, {1, false}, {2, true}, {10, true}, {3600, true}, {3601, false}, {-1, false}} {
		if err := checkWwwRefresh(c.sec); (err == nil) != c.ok {
			t.Errorf("checkWwwRefresh(%d) = %v, ok want %v", c.sec, err, c.ok)
		}
	}
}

func TestGetCfgWwwRefresh(t *testing.T) {
	load := func(t *testing.T, body string) *cfgType {
		t.Helper()
		old := cfgFile
		t.Cleanup(func() { cfgFile = old })
		cfgFile = filepath.Join(t.TempDir(), "z.conf")
		if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return getCfg()
	}
	if c := load(t, "[www]\n"); c == nil || c.Www.Refresh != 10 {
		t.Errorf("default: %+v", c)
	}
	if c := load(t, "[www]\nrefresh = 0\n"); c == nil || c.Www.Refresh != 0 {
		t.Errorf("off: %+v", c)
	}
	if c := load(t, "[www]\nrefresh = 30\n"); c == nil || c.Www.Refresh != 30 {
		t.Errorf("30: %+v", c)
	}
	for _, v := range []string{"1", "3601", "-3"} {
		if load(t, "[www]\nrefresh = "+v+"\n") != nil {
			t.Errorf("accepted refresh = %s", v)
		}
	}
}

// The example configurations load, set the refresh and use no Bootstrap 2/3
// class names, so that they do not rely on the translation.
func TestExampleConfigsUseCurrentClasses(t *testing.T) {
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	for _, f := range []string{"etc/zfswatcher.conf", "etc/zfswatcher-illumos.conf"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, l := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(l, ";") {
				code = append(code, l)
			}
		}
		text := strings.ReplaceAll(strings.Join(code, "\n"), "bg-", "")
		for _, legacy := range []string{"text-error", "text-muted", "progress-bar-", "bar-info", ":error", "alert:error"} {
			if strings.Contains(text, legacy) {
				t.Errorf("%s still contains %q", f, legacy)
			}
		}
		cfgFile = f
		c := getCfg()
		if c == nil {
			t.Fatalf("%s: configuration rejected", f)
		}
		if c.Www.Refresh != defaultWwwRefresh {
			t.Errorf("%s: refresh %d", f, c.Www.Refresh)
		}
	}
}
