package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

func unprivilegedPort(t *testing.T, addr string) {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad address %q: %v", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 1024 {
		t.Errorf("address %q must use a port above 1024", addr)
	}
}

// The service runs without root, so the default must not need port 80.
func TestDefaultWwwBind(t *testing.T) {
	unprivilegedPort(t, defaultWwwBind)
}

func TestSampleConfigsBind(t *testing.T) {
	re := regexp.MustCompile(`(?m)^bind\s*=\s*(\S+)`)
	for _, f := range []string{"etc/zfswatcher.conf", "etc/zfswatcher-illumos.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(b)
		if m == nil {
			t.Errorf("%s: no bind setting", f)
			continue
		}
		unprivilegedPort(t, string(m[1]))
	}
}

func TestCheckCommandTimeout(t *testing.T) {
	for _, c := range []struct {
		sec int
		ok  bool
	}{{0, false}, {-1, false}, {1, true}, {60, true}, {3600, true}, {3601, false}} {
		if err := checkCommandTimeout(c.sec); (err == nil) != c.ok {
			t.Errorf("checkCommandTimeout(%d) = %v, ok want %v", c.sec, err, c.ok)
		}
	}
}

func cfgWithMain(t *testing.T, body string) *cfgType {
	t.Helper()
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	cfgFile = filepath.Join(t.TempDir(), "z.conf")
	if err := os.WriteFile(cfgFile, []byte("[main]\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return getCfg()
}

func TestGetCfgCommandTimeout(t *testing.T) {
	old := commandTimeout
	commandTimeout = 60 * time.Second
	t.Cleanup(func() { commandTimeout = old })
	if c := cfgWithMain(t, ""); c == nil || c.Main.Commandtimeout != 60 {
		t.Errorf("default: got %+v, want 60", c)
	}
	if c := cfgWithMain(t, "commandtimeout = 120\n"); c == nil || c.Main.Commandtimeout != 120 {
		t.Errorf("valid value: got %+v, want 120", c)
	}
	for _, v := range []string{"0", "3601", "-5"} {
		if cfgWithMain(t, "commandtimeout = "+v+"\n") != nil {
			t.Errorf("getCfg accepted commandtimeout = %s", v)
		}
	}
}

func TestWarnObsoleteOptions(t *testing.T) {
	c := cfgWithMain(t, "zpooliostatcmd = zpool iostat -v 1\n")
	if c == nil {
		t.Fatal("old configuration with zpooliostatcmd must still load")
	}
	msgs := captureNotify(t)
	warnObsoleteOptions(c)
	got := msgs()
	if len(got) != 1 || !strings.Contains(got[0], "zpooliostatcmd") ||
		got[0][:len(strconv.Itoa(int(notifier.WARNING)))] != strconv.Itoa(int(notifier.WARNING)) {
		t.Errorf("got %q, want one WARNING about zpooliostatcmd", got)
	}

	msgs = captureNotify(t)
	warnObsoleteOptions(cfgWithMain(t, ""))
	if got := msgs(); len(got) != 0 {
		t.Errorf("no warning expected without the option, got %q", got)
	}
}

// cfgFromText writes a complete configuration file and loads it.
func cfgFromText(t *testing.T, text string) *cfgType {
	t.Helper()
	old := cfgFile
	t.Cleanup(func() { cfgFile = old })
	cfgFile = filepath.Join(t.TempDir(), "z.conf")
	if err := os.WriteFile(cfgFile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return getCfg()
}

func TestGetCfgWebhook(t *testing.T) {
	ok := "[webhook \"a\"]\nenable = true\nlevel = warning\nurl = https://ntfy.example.org/zfs\npreset = ntfy\ntoken = tk\nthrottle = 30\n"
	c := cfgFromText(t, ok)
	if c == nil {
		t.Fatal("valid webhook rejected")
	}
	w := c.Webhook["a"]
	if w == nil || !w.Enable || w.Level != notifier.WARNING || w.Preset != "ntfy" || w.Token != "tk" || w.Throttle != 30 {
		t.Errorf("bad webhook config %+v", w)
	}
	// preset is optional
	if cfgFromText(t, "[webhook \"a\"]\nenable = true\nlevel = err\nurl = http://localhost/x\n") == nil {
		t.Error("webhook without preset rejected")
	}
	for name, body := range map[string]string{
		"no url":        "enable = true\nlevel = err\n",
		"ftp":           "enable = true\nlevel = err\nurl = ftp://h/x\n",
		"unknown":       "enable = true\nlevel = err\nurl = https://h/x\npreset = teams\n",
		"neg throttle":  "enable = true\nlevel = err\nurl = https://h/x\nthrottle = -1\n",
		"unknown field": "enable = true\nurl = https://h/x\nfoo = 1\n",
	} {
		if cfgFromText(t, "[webhook \"a\"]\n"+body) != nil {
			t.Errorf("%s: invalid webhook accepted", name)
		}
	}
	// disabled sections are not validated
	if cfgFromText(t, "[webhook \"a\"]\nenable = false\nurl = nonsense\n") == nil {
		t.Error("disabled webhook was validated")
	}
}

func TestRunTestNotify(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		code := status
		mu.Unlock()
		w.WriteHeader(code)
	}))
	defer srv.Close()

	oldHost := hostname
	hostname = "testhost"
	defer func() { hostname = oldHost }()

	text := "[webhook \"a\"]\nenable = true\nlevel = emerg\nurl = " + srv.URL + "/h\n"
	c := cfgFromText(t, text)
	if c == nil {
		t.Fatal("config rejected")
	}
	var out bytes.Buffer
	if code := runTestNotify(c, &out); code != 0 {
		t.Fatalf("exit code %d: %s", code, out.String())
	}
	mu.Lock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "test notification") || !strings.Contains(bodies[0], "emerg") {
		t.Errorf("bodies %q", bodies)
	}
	status = 400
	mu.Unlock()

	out.Reset()
	if code := runTestNotify(c, &out); code == 0 || !strings.Contains(out.String(), "failed") {
		t.Errorf("failing webhook: exit code %d, output %q", code, out.String())
	}

	// no outputs configured: nothing to fail
	out.Reset()
	if code := runTestNotify(&cfgType{}, &out); code != 0 {
		t.Errorf("empty config: exit code %d", code)
	}
}
