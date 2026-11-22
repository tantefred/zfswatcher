//
// logger_webhook_test.go
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

package notifier

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorded struct {
	method, path, query string
	header              http.Header
	body                string
}

type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

func (r *recorder) get() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

// newRecorder starts a server answering with the given status codes in turn
// (the last one repeats).
func newRecorder(t *testing.T, codes ...int) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		rec.mu.Lock()
		i := len(rec.reqs)
		rec.reqs = append(rec.reqs, recorded{req.Method, req.URL.Path, req.URL.RawQuery, req.Header.Clone(), string(b)})
		rec.mu.Unlock()
		if i >= len(codes) {
			i = len(codes) - 1
		}
		w.WriteHeader(codes[i])
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// runWebhook sends the messages followed by a flush and waits for the end.
func runWebhook(t *testing.T, o *WebhookOutput, level Severity, sends func(n *Notifier)) {
	t.Helper()
	o.Host = "testhost"
	n := New()
	if err := n.AddOutput(level, o); err != nil {
		t.Fatal(err)
	}
	sends(n)
	select {
	case <-n.Close():
	case <-time.After(20 * time.Second):
		t.Fatal("notifier did not close")
	}
}

func shortRetry(t *testing.T) {
	old := webhookRetrySleep
	webhookRetrySleep = time.Millisecond
	t.Cleanup(func() { webhookRetrySleep = old })
}

func TestWebhookGenericBundling(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	o := NewWebhookOutput(srv.URL+"/hook", "", "", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) {
		n.Print(INFO, "one")
		n.Print(ERR, "two")
		_ = n.Attach(ERR, "ignored attachment")
		n.Flush()
	})
	reqs := rec.get()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != "POST" || r.path != "/hook" || r.header.Get("Content-Type") != "application/json" {
		t.Errorf("bad request: %+v", r)
	}
	var p struct {
		Host, Severity, Title string
		Messages              []struct{ Time, Severity, Text string }
	}
	if err := json.Unmarshal([]byte(r.body), &p); err != nil {
		t.Fatal(err)
	}
	if p.Host != "testhost" || p.Severity != "err" || !strings.Contains(p.Title, "err") || len(p.Messages) != 2 {
		t.Errorf("bad payload: %s", r.body)
	}
	if p.Messages[1].Text != "two" || p.Messages[1].Severity != "err" {
		t.Errorf("bad message: %s", r.body)
	}
	if _, err := time.Parse(time.RFC3339, p.Messages[0].Time); err != nil {
		t.Errorf("time not RFC3339: %v", err)
	}
	if strings.Contains(r.body, "attachment") {
		t.Error("attachment was sent")
	}
	if o.LastError() != nil {
		t.Errorf("unexpected error %v", o.LastError())
	}
}

func TestWebhookNoMessagesNoRequest(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	runWebhook(t, NewWebhookOutput(srv.URL, "", "", 0), DEBUG, func(n *Notifier) {
		n.Flush()
	})
	if len(rec.get()) != 0 {
		t.Error("request without messages")
	}
}

func TestWebhookSentOnClose(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	runWebhook(t, NewWebhookOutput(srv.URL, "", "", 0), DEBUG, func(n *Notifier) {
		n.Print(WARNING, "no flush")
	})
	if len(rec.get()) != 1 {
		t.Errorf("got %d requests, want 1", len(rec.get()))
	}
}

func TestWebhookNtfy(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	runWebhook(t, NewWebhookOutput(srv.URL+"/topic", "ntfy", "tk_secret", 0), DEBUG, func(n *Notifier) {
		n.Print(WARNING, "first")
		n.Print(CRIT, "second")
		n.Flush()
	})
	r := rec.get()[0]
	if r.method != "POST" || r.path != "/topic" {
		t.Errorf("bad request: %+v", r)
	}
	if r.header.Get("Priority") != "5" || r.header.Get("Authorization") != "Bearer tk_secret" ||
		!strings.Contains(r.header.Get("Title"), "[crit]") || !strings.Contains(r.header.Get("Tags"), "rotating_light") {
		t.Errorf("bad headers: %v", r.header)
	}
	lines := strings.Split(r.body, "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "[warning] first") || !strings.HasSuffix(lines[1], "[crit] second") {
		t.Errorf("bad body %q", r.body)
	}
}

func TestWebhookPriorityMapping(t *testing.T) {
	ntfy := map[Severity]string{EMERG: "5", ALERT: "5", CRIT: "5", ERR: "4", WARNING: "3", NOTICE: "2", INFO: "1", DEBUG: "1"}
	gotify := map[Severity]int{EMERG: 10, ALERT: 10, CRIT: 10, ERR: 8, WARNING: 5, NOTICE: 3, INFO: 1, DEBUG: 1}
	for s, want := range ntfy {
		if got := ntfyPriority(s); got != want {
			t.Errorf("ntfy %s: %s, want %s", s, got, want)
		}
	}
	for s, want := range gotify {
		if got := gotifyPriority(s); got != want {
			t.Errorf("gotify %s: %d, want %d", s, got, want)
		}
	}
}

func TestWebhookGotify(t *testing.T) {
	for _, base := range []string{"", "/", "/message"} {
		srv, rec := newRecorder(t, 200)
		runWebhook(t, NewWebhookOutput(srv.URL+base, "gotify", "apptoken", 0), DEBUG, func(n *Notifier) {
			n.Print(ERR, "disk failed")
			n.Flush()
		})
		r := rec.get()[0]
		if r.path != "/message" || r.header.Get("X-Gotify-Key") != "apptoken" {
			t.Errorf("base %q: path %q header %v", base, r.path, r.header)
		}
		var p struct {
			Title, Message string
			Priority       int
		}
		if err := json.Unmarshal([]byte(r.body), &p); err != nil {
			t.Fatal(err)
		}
		if p.Priority != 8 || !strings.Contains(p.Message, "disk failed") || p.Title == "" {
			t.Errorf("bad body %s", r.body)
		}
	}
}

func TestWebhookDiscordAndSlack(t *testing.T) {
	for _, tc := range []struct{ preset, key string }{{"discord", "content"}, {"slack", "text"}} {
		srv, rec := newRecorder(t, 204)
		runWebhook(t, NewWebhookOutput(srv.URL+"/w", tc.preset, "", 0), DEBUG, func(n *Notifier) {
			n.Print(WARNING, "pool degraded")
			n.Flush()
		})
		r := rec.get()[0]
		var p map[string]string
		if err := json.Unmarshal([]byte(r.body), &p); err != nil {
			t.Fatal(err)
		}
		if len(p) != 1 || !strings.Contains(p[tc.key], "pool degraded") {
			t.Errorf("%s: bad body %s", tc.preset, r.body)
		}
	}
}

func TestWebhookDiscordTruncation(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	runWebhook(t, NewWebhookOutput(srv.URL, "discord", "", 0), DEBUG, func(n *Notifier) {
		for i := 0; i < 100; i++ {
			n.Print(ERR, strings.Repeat("ä", 50))
		}
		n.Flush()
	})
	var p map[string]string
	if err := json.Unmarshal([]byte(rec.get()[0].body), &p); err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(p["content"])); got > 2000 {
		t.Errorf("content has %d characters", got)
	}
	if !strings.HasSuffix(p["content"], "(truncated)") {
		t.Error("no truncation note")
	}
	if s := "short"; truncateRunes(s, 10) != s {
		t.Error("short text changed")
	}
}

func TestWebhookRetryOnce(t *testing.T) {
	shortRetry(t)
	// 500 then 200: two requests, success.
	srv, rec := newRecorder(t, 500, 200)
	o := NewWebhookOutput(srv.URL, "", "", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	if len(rec.get()) != 2 || o.LastError() != nil {
		t.Errorf("requests %d, err %v", len(rec.get()), o.LastError())
	}
	// Always 503: exactly two requests, error.
	srv, rec = newRecorder(t, 503)
	o = NewWebhookOutput(srv.URL, "", "", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	if len(rec.get()) != 2 || o.LastError() == nil {
		t.Errorf("requests %d, err %v", len(rec.get()), o.LastError())
	}
	// 404 is not retried.
	srv, rec = newRecorder(t, 404)
	o = NewWebhookOutput(srv.URL, "", "", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	if len(rec.get()) != 1 || o.LastError() == nil {
		t.Errorf("requests %d, err %v", len(rec.get()), o.LastError())
	}
}

func TestWebhookTimeoutDoesNotHang(t *testing.T) {
	shortRetry(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)
	o := NewWebhookOutput(srv.URL, "", "", 0)
	o.Client = &http.Client{Timeout: 100 * time.Millisecond}
	start := time.Now()
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	if time.Since(start) > 5*time.Second {
		t.Error("took too long")
	}
	if o.LastError() == nil {
		t.Error("no error for timeout")
	}
}

func TestWebhookConnectionRefused(t *testing.T) {
	shortRetry(t)
	srv, _ := newRecorder(t, 200)
	u := srv.URL
	srv.Close()
	o := NewWebhookOutput(u+"/hook?secret=abc", "", "", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	if o.LastError() == nil {
		t.Fatal("no error")
	}
	if strings.Contains(o.LastError().Error(), "secret") {
		t.Errorf("query leaked: %v", o.LastError())
	}
}

func TestWebhookThrottle(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	o := NewWebhookOutput(srv.URL, "", "", 300*time.Millisecond)
	runWebhook(t, o, DEBUG, func(n *Notifier) {
		n.Print(ERR, "a")
		n.Flush()
		time.Sleep(50 * time.Millisecond)
		n.Print(ERR, "b")
		n.Flush()
		n.Print(ERR, "c")
		n.Flush()
		time.Sleep(50 * time.Millisecond)
		if got := len(rec.get()); got != 1 {
			t.Errorf("before throttle expired: %d requests", got)
		}
		time.Sleep(500 * time.Millisecond)
		if got := len(rec.get()); got != 2 {
			t.Errorf("after throttle expired: %d requests", got)
		}
	})
	reqs := rec.get()
	if len(reqs) != 2 || !strings.Contains(reqs[1].body, `"text":"b"`) ||
		!strings.Contains(reqs[1].body, `"text":"c"`) {
		t.Errorf("throttled batch wrong: %d requests", len(reqs))
	}
}

func TestWebhookLevelFilter(t *testing.T) {
	srv, rec := newRecorder(t, 200)
	runWebhook(t, NewWebhookOutput(srv.URL, "", "", 0), ERR, func(n *Notifier) {
		n.Print(INFO, "dropped")
		n.Flush()
	})
	if len(rec.get()) != 0 {
		t.Error("message below level was sent")
	}
}

func TestWebhookTokenNotLogged(t *testing.T) {
	shortRetry(t)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	srv, _ := newRecorder(t, 500)
	o := NewWebhookOutput("http://user:pw@"+strings.TrimPrefix(srv.URL, "http://")+"/t?key=querysecret", "ntfy", "tk_supersecret", 0)
	runWebhook(t, o, DEBUG, func(n *Notifier) { n.Print(ERR, "x"); n.Flush() })
	log := buf.String()
	if !strings.Contains(log, "webhook delivery failed") {
		t.Fatalf("no log entry: %q", log)
	}
	for _, s := range []string{"tk_supersecret", "querysecret", "user", "pw@"} {
		if strings.Contains(log, s) {
			t.Errorf("log contains %q: %s", s, log)
		}
	}
}

func TestValidateWebhook(t *testing.T) {
	for _, tc := range []struct {
		url, preset, want string
		ok                bool
	}{
		{"https://ntfy.sh/x", "", "generic", true},
		{"http://localhost:8080/x", "NTFY", "ntfy", true},
		{"https://h/x", "gotify", "gotify", true},
		{"https://h/x", "discord", "discord", true},
		{"https://h/x", "slack", "slack", true},
		{"", "generic", "", false},
		{"ftp://h/x", "generic", "", false},
		{"/just/a/path", "generic", "", false},
		{"http://", "generic", "", false},
		{"https://h/x", "teams", "", false},
	} {
		got, err := ValidateWebhook(tc.url, tc.preset)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%q %q: %q, %v", tc.url, tc.preset, got, err)
		}
	}
}

func TestAddLoggerWebhookErrors(t *testing.T) {
	n := New()
	defer func() { <-n.Close() }()
	if _, err := n.AddLoggerWebhook(Severity(99), "https://h/x", "", "", 0); err == nil {
		t.Error("invalid severity accepted")
	}
	if _, err := n.AddLoggerWebhook(ERR, "https://h/x", "", "", -time.Second); err == nil {
		t.Error("negative throttle accepted")
	}
	if _, err := n.AddLoggerWebhook(ERR, "gopher://h/x", "", "", 0); err == nil {
		t.Error("bad url accepted")
	}
}

func TestSafeURL(t *testing.T) {
	if got := safeURL("https://u:p@h:1/a/b?k=v#f"); got != "https://h:1/a/b" {
		t.Errorf("got %q", got)
	}
	if got := safeURL("http://[::1"); got != "(unparsable URL)" {
		t.Errorf("got %q", got)
	}
}

// eof
