//
// logger_webhook.go
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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Presets of the webhook output.
const (
	WebhookGeneric = "generic"
	WebhookNtfy    = "ntfy"
	WebhookGotify  = "gotify"
	WebhookDiscord = "discord"
	WebhookSlack   = "slack"
)

// webhookTimeout limits one HTTP request (connect, send and response).
const webhookTimeout = 10 * time.Second

// webhookRetrySleep is the pause before the single retry (variable so tests
// can shorten it).
var webhookRetrySleep = 500 * time.Millisecond

// discordMaxContent is the maximum length of a Discord message in characters.
const discordMaxContent = 2000

// WebhookPresets lists the valid values for the preset.
func WebhookPresets() []string {
	return []string{WebhookGeneric, WebhookNtfy, WebhookGotify, WebhookDiscord, WebhookSlack}
}

// ValidateWebhook checks the URL (http or https with a host) and the preset
// (empty means generic). It returns the normalized preset.
func ValidateWebhook(rawurl, preset string) (string, error) {
	preset = strings.ToLower(strings.TrimSpace(preset))
	if preset == "" {
		preset = WebhookGeneric
	}
	known := false
	for _, p := range WebhookPresets() {
		if p == preset {
			known = true
		}
	}
	if !known {
		return "", fmt.Errorf(`unknown preset %q, must be one of %s`, preset, strings.Join(WebhookPresets(), ", "))
	}
	if rawurl == "" {
		return "", errors.New(`"url" not defined`)
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", errors.New(`invalid "url": ` + safeURL(rawurl))
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New(`"url" must be an http:// or https:// URL`)
	}
	return preset, nil
}

// safeURL returns raw without userinfo and query string, for logging.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparsable URL)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// WebhookOutput collects the messages of one check run and sends them as
// one HTTP POST request on MSGTYPE_FLUSH (and when the output is closed),
// optionally throttled. Attachments are not sent: they are long raw
// command outputs which do not fit into push messages.
type WebhookOutput struct {
	acceptTypes
	// Client is used for the requests; the default has a timeout of 10 s.
	Client *http.Client
	// Host is reported as the sending host; the default is the hostname.
	Host string

	url, preset, token string
	throttle           time.Duration

	wg      sync.WaitGroup // pending deliveries
	mu      sync.Mutex
	lastErr error
}

// NewWebhookOutput returns an Output which POSTs to rawurl in the format of
// preset. The arguments must have been checked with ValidateWebhook.
func NewWebhookOutput(rawurl, preset, token string, throttle time.Duration) *WebhookOutput {
	host, _ := os.Hostname()
	if preset == "" {
		preset = WebhookGeneric
	}
	return &WebhookOutput{
		acceptTypes: acceptTypes{attachment: false, flush: true},
		Client:      &http.Client{Timeout: webhookTimeout},
		Host:        host,
		url:         rawurl, preset: strings.ToLower(preset), token: token, throttle: throttle,
	}
}

// LastError returns the error of the last delivery (nil if it succeeded or
// nothing has been sent yet).
func (o *WebhookOutput) LastError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastErr
}

func (o *WebhookOutput) setErr(err error) {
	o.mu.Lock()
	o.lastErr = err
	o.mu.Unlock()
}

// Run implements Output. It returns after all deliveries have finished.
func (o *WebhookOutput) Run(ch <-chan *Msg) {
	defer o.wg.Wait()
	var buf []*Msg
	var lastFlush time.Time
	var throttleTimer *time.Timer

	for {
		var throttleC <-chan time.Time
		if throttleTimer != nil {
			throttleC = throttleTimer.C
		}
		var m *Msg
		var ok bool
		select {
		case m, ok = <-ch:
		case <-throttleC:
			m = &Msg{MsgType: MSGTYPE_FLUSH}
			ok = true
			throttleTimer = nil
		}
		if !ok {
			break
		}
		switch m.MsgType {
		case MSGTYPE_MESSAGE:
			buf = append(buf, m)
		case MSGTYPE_FLUSH:
			if len(buf) == 0 {
				continue
			}
			if o.throttle != 0 && !lastFlush.IsZero() && time.Since(lastFlush) < o.throttle {
				if throttleTimer == nil {
					throttleTimer = time.NewTimer(o.throttle - time.Since(lastFlush))
				}
				continue
			}
			batch := buf
			buf = nil
			lastFlush = time.Now()
			if throttleTimer != nil {
				throttleTimer.Stop()
				throttleTimer = nil
			}
			o.wg.Add(1)
			go o.deliver(batch)
		}
	}
	if throttleTimer != nil {
		throttleTimer.Stop()
	}
	if len(buf) > 0 {
		o.wg.Add(1)
		go o.deliver(buf)
	}
}

func (o *WebhookOutput) deliver(msgs []*Msg) {
	defer o.wg.Done()
	err := o.send(msgs)
	o.setErr(err)
	if err != nil {
		// Not reported through the notifier: that could loop.
		slog.Error("webhook delivery failed", "component", "notifier",
			"url", safeURL(o.url), "err", err)
	}
}

// worst returns the most important severity of msgs.
func worst(msgs []*Msg) Severity {
	w := DEBUG
	for _, m := range msgs {
		if m.Severity < w {
			w = m.Severity
		}
	}
	return w
}

func ntfyPriority(s Severity) string {
	switch {
	case s <= CRIT:
		return "5"
	case s == ERR:
		return "4"
	case s == WARNING:
		return "3"
	case s == NOTICE:
		return "2"
	}
	return "1"
}

func gotifyPriority(s Severity) int {
	switch {
	case s <= CRIT:
		return 10
	case s == ERR:
		return 8
	case s == WARNING:
		return 5
	case s == NOTICE:
		return 3
	}
	return 1
}

func ntfyTag(s Severity) string {
	switch {
	case s <= CRIT:
		return "rotating_light"
	case s <= WARNING:
		return "warning"
	}
	return "information_source"
}

// truncateRunes shortens s to at most max characters, ending with a note.
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	const note = "\n... (truncated)"
	return string(r[:max-len([]rune(note))]) + note
}

type webhookMessage struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

// buildRequest returns the request URL, content type, extra headers and body.
func (o *WebhookOutput) buildRequest(msgs []*Msg) (target, ctype string, hdr map[string]string, body []byte, err error) {
	sev := worst(msgs)
	title := fmt.Sprintf("zfswatcher [%s] [%s]", o.Host, sev)
	lines := make([]string, len(msgs))
	for i, m := range msgs {
		lines[i] = m.TimeString()
	}
	text := strings.Join(lines, "\n")
	target, ctype = o.url, "application/json"
	hdr = map[string]string{}

	switch o.preset {
	case WebhookNtfy:
		ctype = "text/plain; charset=utf-8"
		body = []byte(text)
		hdr["Title"] = title
		hdr["Priority"] = ntfyPriority(sev)
		hdr["Tags"] = ntfyTag(sev) + ",zfswatcher"
		if o.token != "" {
			hdr["Authorization"] = "Bearer " + o.token
		}
	case WebhookGotify:
		if u, perr := url.Parse(o.url); perr == nil && !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/message") {
			u.Path = strings.TrimRight(u.Path, "/") + "/message"
			u.RawPath = ""
			target = u.String()
		}
		if o.token != "" {
			hdr["X-Gotify-Key"] = o.token
		}
		body, err = json.Marshal(map[string]any{"title": title, "message": text, "priority": gotifyPriority(sev)})
	case WebhookDiscord:
		body, err = json.Marshal(map[string]string{"content": truncateRunes(title+"\n"+text, discordMaxContent)})
	case WebhookSlack:
		body, err = json.Marshal(map[string]string{"text": title + "\n" + text})
	default:
		out := make([]webhookMessage, len(msgs))
		for i, m := range msgs {
			out[i] = webhookMessage{m.Time.Format(time.RFC3339), m.Severity.String(), m.Text}
		}
		body, err = json.Marshal(map[string]any{
			"host": o.Host, "severity": sev.String(), "title": title, "messages": out,
		})
		if o.token != "" {
			hdr["Authorization"] = "Bearer " + o.token
		}
	}
	return
}

// send performs the request, with one retry on network errors and 5xx.
func (o *WebhookOutput) send(msgs []*Msg) error {
	target, ctype, hdr, body, err := o.buildRequest(msgs)
	if err != nil {
		return err
	}
	var retryable bool
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(webhookRetrySleep)
		}
		retryable, err = o.post(target, ctype, hdr, body)
		if err == nil || !retryable {
			return err
		}
	}
	return err
}

func (o *WebhookOutput) post(target, ctype string, hdr map[string]string, body []byte) (retryable bool, err error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("cannot build request")
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "zfswatcher")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		// net/http errors embed the URL (with query); keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return resp.StatusCode >= 500, fmt.Errorf("HTTP status %s", resp.Status)
	}
	return false, nil
}

// AddLoggerWebhook adds a webhook output. The returned output reports the
// last delivery error through LastError. preset may be empty (generic).
func (n *Notifier) AddLoggerWebhook(s Severity, rawurl, preset, token string, throttle time.Duration) (*WebhookOutput, error) {
	if s < severity_MIN || s > severity_MAX {
		return nil, errors.New(`invalid "severity"`)
	}
	if throttle < 0 {
		return nil, errors.New(`invalid "throttle"`)
	}
	preset, err := ValidateWebhook(rawurl, preset)
	if err != nil {
		return nil, err
	}
	o := NewWebhookOutput(rawurl, preset, token, throttle)
	return o, n.AddOutput(s, o)
}

// eof
