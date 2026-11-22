//
// webpagehandlers.go
//
// Copyright © 2012-2013 Damicon Kraa Oy
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

package main

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

var templates *template.Template

type severityToWwwClassMap map[notifier.Severity]string

// Implement fmt.Scanner interface.
func (scmapp *severityToWwwClassMap) Scan(state fmt.ScanState, verb rune) error {
	smap := stringToStringMap{}
	err := smap.Scan(state, verb)
	if err != nil {
		return err
	}
	scmap := make(severityToWwwClassMap)
	for a, b := range smap {
		var severity notifier.Severity
		if n, err := fmt.Sscan(a, &severity); n != 1 {
			return err
		}
		scmap[severity] = b
	}
	*scmapp = scmap
	return nil
}

type webNav struct {
	// active main menu entry
	Dashboard  bool
	PoolStatus bool
	Statistics bool
	Logs       bool
	About      bool
	Enclosure  bool
	Root       string
	// what the role of the user allows
	CanLogs   bool
	CanLocate bool
	// automatic refresh of the live part of the page (dashboard, pool
	// status): the interval in seconds, 0 for none, and the URL of the
	// fragment which is loaded
	Refresh    int
	RefreshURL string
}

// newWebNav returns the navigation for the user of the request. The
// handlers set the active menu entry.
func newWebNav(r *http.Request) webNav {
	role := roleOf(r)
	return webNav{
		Root:      cfg.Www.Rootdir,
		CanLogs:   role >= RoleOperator,
		CanLocate: role >= RoleOperator,
	}
}

// live enables the automatic refresh of the page content, which is loaded
// from the fragment of the given path. The refresh is off with
// "refresh = 0".
func (wn *webNav) live(path string) {
	if cfg.Www.Refresh > 0 {
		wn.Refresh = cfg.Www.Refresh
		wn.RefreshURL = path + "?" + fragmentQuery
	}
}

// fragmentQuery selects the fragment of a page: just the live part of the
// content, as loaded by the automatic refresh.
const fragmentQuery = "fragment=1"

func isFragment(r *http.Request) bool {
	return r.URL.Query().Get("fragment") == "1"
}

// executeFragment renders the named template of a fragment response.
func executeFragment(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// executePoolGone answers the refresh of a pool page whose pool has
// vanished. A 4xx answer would not be swapped by htmx and the page would
// stay stale, so the answer is 200 with a notice. The HX-Retarget and
// HX-Reswap headers make htmx replace the whole live container, including
// its hx-get and hx-trigger attributes, so the polling stops. This needs no
// script and nothing the CSP forbids, and keeps the notice on the page
// (HX-Redirect would load another page without telling why).
func executePoolGone(w http.ResponseWriter, pool string) {
	w.Header().Set("HX-Retarget", "#live")
	w.Header().Set("HX-Reswap", "outerHTML")
	executeFragment(w, "pool-gone", map[string]string{
		"Name": pool,
		"Root": cfg.Www.Rootdir,
	})
}

// DefaultPasswordWarning tells the header template whether to show the
// warning about the example password.
func (webNav) DefaultPasswordWarning() bool {
	return defaultPasswordInUse.Load()
}

type webSubNav struct {
	Name   string
	Active bool
}

type webData struct {
	Nav    webNav
	SubNav []webSubNav
	Data   interface{}
}

type devStatusWeb struct {
	IndentClass string
	Name        string
	EnableLed   bool
	Locate      bool
	State       string
	StateClass  string
	Read        int64
	Write       int64
	Cksum       int64
	Rest        string
	Root        string
	Return      string
}

type poolStatusWeb struct {
	N             int
	Name          string
	State         string
	StateClass    string
	Status        string
	Action        string
	See           string
	Scan          string
	Devs          []devStatusWeb
	Errors        string
	Used          int64
	Logicalused   int64
	UsedPercent   int
	UsedClass     string
	UsedBar       string
	Avail         int64
	AvailPercent  int
	AvailBar      string
	Total         int64
	Root          string
	Compressratio string
}

type dashboardWeb struct {
	SysUptime        string
	ZfswatcherUptime string
	SysLoadaverage   [3]float32
	Pools            []*poolStatusWeb
}

type enclosureWeb struct {
	ChassisEnable bool
	Layouts       []enclosureView
}

// wwwLogBuffer keeps the most recent log messages for the logs page and the
// API; wwwLogMutex protects it.
var (
	wwwLogBuffer []Event
	wwwLogMutex  sync.RWMutex
)

func wwwLogReceiver(m *notifier.Msg) {
	wwwLogMutex.Lock()
	if wwwLogBuffer == nil {
		wwwLogBuffer = make([]Event, 0, cfg.Www.Logbuffer+1)
	}
	wwwLogBuffer = eventsAppend(wwwLogBuffer, m, cfg.Www.Logbuffer)
	wwwLogMutex.Unlock()
}

// logTimeFormat is the format of the time column of the logs page (the same
// as in the log files).
const logTimeFormat = "2006-01-02 15:04:05"

// logMsgWeb is a row of the logs page.
type logMsgWeb struct {
	Time       string
	Severity   string
	Class      string
	Text       string
	Attachment string
}

func makeLogMsgWeb(e Event) logMsgWeb {
	w := logMsgWeb{
		Time:       e.Time.Format(logTimeFormat),
		Severity:   e.Severity,
		Text:       e.Text,
		Attachment: e.Attachment,
	}
	if sev, ok := severityFromName(e.Severity); ok {
		w.Class = cfg.Www.Severitycssclassmap[sev]
	}
	return w
}

// The functions below form the presentation layer: they turn the data of the
// model (Pool, Device, Usage, Event) into the structures used by the
// templates (CSS classes, indentation, URLs).

// maxDepthClass is the deepest indentation which has a css class.
const maxDepthClass = 12

// devIndentClass is the css class which indents a device at the given tree
// depth.
func devIndentClass(depth int) string {
	return "depth-" + strconv.Itoa(min(max(depth, 0), maxDepthClass))
}

// barClass is the css class for a bar of the given width in percent.
func barClass(percent int) string {
	return "pct-" + strconv.Itoa(min(max(percent, 0), 100))
}

func makePoolStatusWeb(pool Pool, usage map[string]Usage, canLocate bool) *poolStatusWeb {
	statusWeb := &poolStatusWeb{
		Name:       pool.Name,
		State:      pool.State,
		StateClass: cfg.Www.Poolstatecssclassmap[pool.State],
		Status:     pool.Status,
		Action:     pool.Action,
		See:        pool.See,
		Scan:       pool.Scan,
		Errors:     pool.Errors,
		Root:       cfg.Www.Rootdir,
	}
	statusWeb.Avail = -1
	statusWeb.Used = -1
	statusWeb.Total = -1
	statusWeb.Logicalused = -1
	if u, ok := usage[pool.Name]; ok {
		statusWeb.Avail = u.Avail
		statusWeb.AvailPercent = u.AvailPercent
		statusWeb.Used = u.Used
		statusWeb.Logicalused = u.Logicalused
		statusWeb.Compressratio = u.Compressratio
		statusWeb.UsedPercent = u.UsedPercent
		statusWeb.Total = u.Avail + u.Used
		usedSeverity, _ := cfg.Severity.Usedspace.GetByPercentage(u.UsedPercent)
		statusWeb.UsedClass = cfg.Www.Usedstatecssclassmap[usedSeverity]
	}
	statusWeb.UsedBar = barClass(statusWeb.UsedPercent)
	statusWeb.AvailBar = barClass(statusWeb.AvailPercent)

	pool.Walk(func(dev Device, depth int) {
		devw := devStatusWeb{
			IndentClass: devIndentClass(depth),
			Name:        dev.Name,
			State:       dev.State,
			StateClass:  cfg.Www.Devstatecssclassmap[dev.State],
			Read:        dev.Read,
			Write:       dev.Write,
			Cksum:       dev.Cksum,
			Rest:        dev.Info,
			Root:        cfg.Www.Rootdir,
			Return:      cfg.Www.Rootdir + "/status/" + url.PathEscape(pool.Name),
		}
		if canLocate && cfg.Leds.Enable && len(dev.Children) == 0 {
			loc, err := locateQuery(dev.Name)
			if err == nil {
				slog.Debug("locate query succeeded", "device", dev.Name)
				devw.EnableLed = true
				devw.Locate = loc
			}
		}
		statusWeb.Devs = append(statusWeb.Devs, devw)
	})
	return statusWeb
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.PoolStatus = true

	pool := r.URL.Path[len(cfg.Www.Rootdir+"/status/"):]

	if !legalPoolName(pool) && pool != "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	state, usage := snapshotState()

	if len(state) == 0 {
		if isFragment(r) {
			if pool != "" {
				executePoolGone(w, pool)
			} else {
				executeFragment(w, "no-pools", nil)
			}
			return
		}
		err := templates.ExecuteTemplate(w, "status-none.html", &webData{Nav: wn})
		if err != nil {
			notify.Printf(notifier.ERR, "error executing template: %s", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	subnav := make([]webSubNav, 0, len(state))
	match := -1

	for n, s := range state {
		active := s.Name == pool
		subnav = append(subnav, webSubNav{Name: s.Name, Active: active})
		if active {
			match = n
		}
	}
	if pool == "" {
		http.Redirect(w, r, cfg.Www.Rootdir+"/status/"+subnav[0].Name, http.StatusSeeOther)
		return
	}
	if match == -1 {
		if isFragment(r) {
			executePoolGone(w, pool)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ws := makePoolStatusWeb(state[match], usage, wn.CanLocate)

	if isFragment(r) {
		executeFragment(w, "status-pool.html", ws)
		return
	}
	wn.live(cfg.Www.Rootdir + "/status/" + url.PathEscape(pool))

	var err error

	switch {
	case len(subnav) > 1: // more than one pool
		err = templates.ExecuteTemplate(w, "status-many.html",
			&webData{Nav: wn, SubNav: subnav, Data: ws})
	case len(subnav) == 1: // a single pool
		err = templates.ExecuteTemplate(w, "status-single.html",
			&webData{Nav: wn, SubNav: subnav, Data: ws})
	}
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func usageHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r) // not available in menu

	pool := r.URL.Path[len(cfg.Www.Rootdir+"/usage/"):]

	if pool == "" || !legalPoolName(pool) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	zfsListOutput, err := getCommandOutput(cfg.Main.Zfslistusagecmd + " " + pool)
	if err != nil {
		notify.Print(notifier.ERR, "getting ZFS disk usage failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	usage := usageList(usageMapFromParsed(parseZfsList(zfsListOutput)))
	err = templates.ExecuteTemplate(w, "usage.html", &webData{Nav: wn, Data: usage})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.Dashboard = true

	host := hostInfo()
	state, usage := snapshotState()

	var ws []*poolStatusWeb

	for n, s := range state {
		ws = append(ws, makePoolStatusWeb(s, usage, wn.CanLocate))
		ws[n].N = n
	}

	d := &dashboardWeb{
		SysUptime:        myDurationString(time.Duration(host.SystemUptimeSeconds) * time.Second),
		ZfswatcherUptime: myDurationString(time.Duration(host.ZfswatcherUptimeSeconds) * time.Second),
		SysLoadaverage:   host.LoadAverage,
		Pools:            ws,
	}

	if isFragment(r) {
		executeFragment(w, "dashboard-content", d)
		return
	}
	wn.live(cfg.Www.Rootdir + "/")

	err := templates.ExecuteTemplate(w, "dashboard.html", &webData{Nav: wn, Data: d})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func statisticsHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.Statistics = true
	err := templates.ExecuteTemplate(w, "statistics.html", &webData{Nav: wn})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.Logs = true
	events := snapshotEvents()
	rows := make([]logMsgWeb, 0, len(events))
	for _, e := range events {
		rows = append(rows, makeLogMsgWeb(e))
	}
	err := templates.ExecuteTemplate(w, "logs.html", &webData{Nav: wn, Data: rows})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.About = true
	err := templates.ExecuteTemplate(w, "about.html",
		&webData{Nav: wn,
			Data: map[string]string{
				"Version":       buildVersion,
				"GoEnvironment": getGoEnvironment(),
			}})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func locateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	dev := r.PostFormValue("dev")
	state := r.PostFormValue("state")

	if !locateKnown(dev) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	var err error
	switch state {
	case "on":
		err = locateOn(dev)
	case "off":
		err = locateOff(dev)
	default:
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err != nil {
		notify.Printf(notifier.WARNING, "locate %s %s failed: %s", dev, state, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, locateRedirectTarget(r.PostFormValue("return")), http.StatusSeeOther)
}

// locateRedirectTarget returns the page to go back to after a locate
// request. Only paths below the web root are accepted, anything else
// (other hosts, schemes, protocol-relative URLs) falls back to the
// enclosure page.
func locateRedirectTarget(ret string) string {
	def := cfg.Www.Rootdir + "/enclosure/"
	if !strings.HasPrefix(ret, cfg.Www.Rootdir+"/") ||
		strings.Contains(ret, "//") || strings.Contains(ret, "\\") ||
		strings.ContainsAny(ret, "\r\n") {
		return def
	}
	u, err := url.Parse(ret)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return def
	}
	return ret
}

func enclosureHandler(w http.ResponseWriter, r *http.Request) {
	wn := newWebNav(r)
	wn.Enclosure = true

	ewd := &enclosureWeb{ChassisEnable: cfg.Chassis.Enable}
	if ewd.ChassisEnable {
		states := deviceStates(snapshotPools())
		for _, l := range enclosureLayouts() {
			ewd.Layouts = append(ewd.Layouts, fillEnclosureLayout(l, states))
		}
	}

	err := templates.ExecuteTemplate(w, "enclosure.html", &webData{Nav: wn, Data: ewd})
	if err != nil {
		notify.Printf(notifier.ERR, "error executing template: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// eof
