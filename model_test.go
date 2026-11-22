package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

func parseFixturePools(t *testing.T, name string) []*PoolType {
	t.Helper()
	pools, err := parseZpoolStatus(readFixture(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return pools
}

// outline renders the device tree as "name/state" lines indented by depth.
func outline(p Pool) []string {
	var l []string
	p.Walk(func(d Device, depth int) {
		l = append(l, strings.Repeat("  ", depth)+d.Name+" "+d.State)
	})
	return l
}

func TestPoolFromParsedClasses(t *testing.T) {
	p := poolFromParsed(parseFixturePools(t, "zpool-status-vdev-classes.txt")[0])
	if p.Name != "zfsw_mix" || p.State != "ONLINE" || p.Errors != "No known data errors" {
		t.Fatalf("pool header: %+v", p)
	}
	want := []string{
		"zfsw_mix ONLINE",
		"  raidz1-0 ONLINE",
		"    /var/tmp/zfsw-collect/c1 ONLINE",
		"    /var/tmp/zfsw-collect/c2 ONLINE",
		"    /var/tmp/zfsw-collect/c3 ONLINE",
		"dedup ",
		"  /var/tmp/zfsw-collect/c8 ONLINE",
		"special ",
		"  /var/tmp/zfsw-collect/c7 ONLINE",
		"logs ",
		"  /var/tmp/zfsw-collect/c4 ONLINE",
		"cache ",
		"  /var/tmp/zfsw-collect/c5 ONLINE",
		"spares ",
		"  /var/tmp/zfsw-collect/c6 AVAIL",
	}
	// the pool itself is the first top level device, the class sections
	// follow as its siblings
	got := outline(p)
	if len(got) != len(want) {
		t.Fatalf("got %d devices, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	if len(p.Devices) != 6 {
		t.Errorf("top level entries = %d, want 6 (pool + 5 classes), got %v", len(p.Devices), got)
	}
	for _, name := range []string{"dedup", "special", "logs", "cache", "spares"} {
		var found *Device
		for i := range p.Devices {
			if p.Devices[i].Name == name {
				found = &p.Devices[i]
			}
		}
		if found == nil {
			t.Fatalf("class section %q missing in %v", name, got)
		}
		if found.Read != -1 || found.Write != -1 || found.Cksum != -1 || found.State != "" {
			t.Errorf("class %q: %+v, want -1 counters and no state", name, *found)
		}
		if len(found.Children) != 1 {
			t.Errorf("class %q has %d children", name, len(found.Children))
		}
	}
}

func TestPoolFromParsedNesting(t *testing.T) {
	pools := parseFixturePools(t, "zpool-status-resilver-replacing.txt")
	p := poolFromParsed(pools[0])
	// mirror nesting plus a "replacing" vdev inside a mirror
	var maxDepth int
	p.Walk(func(d Device, depth int) { maxDepth = max(maxDepth, depth) })
	if maxDepth < 3 {
		t.Errorf("max depth = %d, want at least 3:\n%s", maxDepth, strings.Join(outline(p), "\n"))
	}
	// the tree walk must give the order of the flat parser list
	var flat []string
	for _, d := range pools[0].devs {
		flat = append(flat, d.name)
	}
	var walked []string
	p.Walk(func(d Device, _ int) { walked = append(walked, d.Name) })
	if !reflect.DeepEqual(flat, walked) {
		t.Errorf("walk order %v, parser order %v", walked, flat)
	}
}

// Every fixture must keep its device count, order and depth when converted.
func TestPoolFromParsedAllFixtures(t *testing.T) {
	files := []string{
		"zpool-status-2pools.txt", "zpool-status-checkpoint.txt", "zpool-status-data-corruption.txt",
		"zpool-status-degraded.txt", "zpool-status-draid-spare.txt", "zpool-status-draid.txt",
		"zpool-status-faulted.txt", "zpool-status-flag-g.txt", "zpool-status-multi-pool.txt",
		"zpool-status-proxmox.txt", "zpool-status-raidz2-two-faulted.txt", "zpool-status-spare-resilver.txt",
		"zpool-status-unavail.txt", "zpool-status-vdev-classes.txt", "zpool-status-resilver-replacing.txt",
	}
	for _, f := range files {
		for _, pp := range parseFixturePools(t, f) {
			p := poolFromParsed(pp)
			var names []string
			var depths []int
			p.Walk(func(d Device, depth int) {
				names = append(names, d.Name)
				depths = append(depths, depth)
			})
			if len(names) != len(pp.devs) {
				t.Errorf("%s/%s: %d devices, parser has %d", f, pp.name, len(names), len(pp.devs))
				continue
			}
			for i, e := range pp.devs {
				depth := 0
				for d := i; pp.devs[d].parentDev != -1; d = pp.devs[d].parentDev {
					depth++
				}
				if names[i] != e.name || depths[i] != depth {
					t.Errorf("%s/%s: device %d is %q depth %d, want %q depth %d",
						f, pp.name, i, names[i], depths[i], e.name, depth)
				}
			}
		}
	}
}

func TestPoolFromParsedGUIDAndInfo(t *testing.T) {
	p := poolFromParsed(parseFixturePools(t, "zpool-status-unavail.txt")[0])
	var found bool
	p.Walk(func(d Device, _ int) {
		if d.Name == "14974271720844242149" {
			found = true
			if d.State != "UNAVAIL" || d.Info != "was /var/tmp/zfsw-collect/u2" {
				t.Errorf("GUID device: %+v", d)
			}
		}
	})
	if !found {
		t.Error("GUID device not found")
	}
	g := poolFromParsed(parseFixturePools(t, "zpool-status-flag-g.txt")[0])
	if g.Devices[0].Children[0].Name != "13093892248541598013" {
		t.Errorf("zpool status -g: %+v", g.Devices[0])
	}
}

func TestPoolFromParsedFields(t *testing.T) {
	pp := &PoolType{name: "n", state: "s", status: "st", action: "a", see: "se", scan: "sc", errors: "e", extra: "x", infostr: "ignored"}
	got := poolFromParsed(pp)
	want := Pool{Name: "n", State: "s", Status: "st", Action: "a", See: "se", Scan: "sc", Errors: "e", Extra: "x", Devices: []Device{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestPoolFromParsedIgnoresBadLinks(t *testing.T) {
	// a sub device index pointing backwards or out of range must not loop
	pp := &PoolType{name: "bad", devs: []*DevEntry{
		{name: "a", parentDev: -1, subDevs: []int{0, 7, 1}},
		{name: "b", parentDev: 0},
	}}
	p := poolFromParsed(pp)
	if got := outline(p); !reflect.DeepEqual(got, []string{"a ", "  b "}) {
		t.Errorf("got %q", got)
	}
}

func TestPoolJSON(t *testing.T) {
	p := poolFromParsed(parseFixturePools(t, "zpool-status-vdev-classes.txt")[0])
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "state", "status", "action", "see", "scan", "errors", "extra", "devices"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %q missing in %s", k, b)
		}
	}
	dev := m["devices"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "state", "read", "write", "cksum", "info", "children"} {
		if _, ok := dev[k]; !ok {
			t.Errorf("device key %q missing", k)
		}
	}
	if !strings.Contains(string(b), `"children":[]`) {
		t.Error("leaf devices must have an empty children array, not null")
	}
	empty, _ := json.Marshal(poolFromParsed(&PoolType{}))
	if !strings.Contains(string(empty), `"devices":[]`) {
		t.Errorf("empty pool: %s", empty)
	}
}

func TestUsageFromParsed(t *testing.T) {
	m := parseZfsList("tank\t3G\t1G\t4G\t0B\t1G\t0B\t0B\t1G\t/tank\t1.50x\n" +
		"zero\t0\t0\t-\t-\t-\t-\t-\t-\t-\t-\n" +
		"legacy\t1G\t3G\t0B\t3G\t0B\t0B\t3G\t/legacy\n")
	u := usageMapFromParsed(m)
	tank := u["tank"]
	if tank.UsedPercent != 25 || tank.AvailPercent != 75 {
		t.Errorf("percents %d/%d", tank.UsedPercent, tank.AvailPercent)
	}
	if tank.Used != 1<<30 || tank.Avail != 3<<30 || tank.Logicalused != 4<<30 || tank.Mountpoint != "/tank" || tank.Compressratio != "1.50x" || tank.Name != "tank" {
		t.Errorf("tank: %+v", tank)
	}
	if z := u["zero"]; z.UsedPercent != 0 || z.AvailPercent != 0 {
		t.Errorf("empty usage: %+v", z)
	}
	if l := u["legacy"]; l.Logicalused != -1 || l.Compressratio != "-" || l.UsedPercent != 75 {
		t.Errorf("legacy: %+v", l)
	}
	// percentages are the ones of the existing methods
	for name, p := range m {
		if p.Avail+p.Used == 0 {
			continue
		}
		if u[name].UsedPercent != p.GetUsedPercent() || u[name].AvailPercent != p.GetAvailPercent() {
			t.Errorf("%s: percent differs from methods", name)
		}
	}
	names := []string{}
	for _, e := range usageList(u) {
		names = append(names, e.Name)
	}
	if !reflect.DeepEqual(names, []string{"legacy", "tank", "zero"}) {
		t.Errorf("usageList order %v", names)
	}
	b, _ := json.Marshal(tank)
	for _, k := range []string{`"used_percent":25`, `"avail_percent":75`, `"usedsnap"`, `"usedds"`, `"usedrefreserv"`, `"usedchild"`, `"logicalused"`, `"compressratio"`, `"mountpoint"`, `"refer"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("%s missing in %s", k, b)
		}
	}
}

func TestEventsAppend(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	msg := func(typ notifier.MsgType, sev notifier.Severity, text string) *notifier.Msg {
		return &notifier.Msg{Time: ts, MsgType: typ, Severity: sev, Text: text}
	}
	var buf []Event
	buf = eventsAppend(buf, msg(notifier.MSGTYPE_MESSAGE, notifier.CRIT, "one"), 10)
	buf = eventsAppend(buf, msg(notifier.MSGTYPE_ATTACHMENT, notifier.CRIT, "att1"), 10)
	buf = eventsAppend(buf, msg(notifier.MSGTYPE_ATTACHMENT, notifier.ERR, "att2"), 10) // previous has one already
	buf = eventsAppend(buf, msg(notifier.MSGTYPE_FLUSH, notifier.INFO, "ignored"), 10)
	buf = eventsAppend(buf, msg(notifier.MSGTYPE_REOPEN, notifier.INFO, "ignored"), 10)
	want := []Event{
		{Time: ts, Severity: "crit", Text: "one", Attachment: "att1"},
		{Time: ts, Severity: "err", Attachment: "att2"},
	}
	if !reflect.DeepEqual(buf, want) {
		t.Fatalf("got %+v", buf)
	}
	if s, ok := severityFromName(buf[1].Severity); !ok || s != notifier.ERR {
		t.Errorf("severityFromName = %v, %v", s, ok)
	}
	if _, ok := severityFromName("bogus"); ok {
		t.Error("bogus severity accepted")
	}
	// an attachment without any message creates an entry
	first := eventsAppend(nil, msg(notifier.MSGTYPE_ATTACHMENT, notifier.INFO, "lonely"), 3)
	if len(first) != 1 || first[0].Attachment != "lonely" || first[0].Text != "" {
		t.Errorf("lonely attachment: %+v", first)
	}
}

func TestEventsAppendLimit(t *testing.T) {
	var buf []Event
	for i := range 10 {
		buf = eventsAppend(buf, &notifier.Msg{MsgType: notifier.MSGTYPE_MESSAGE, Severity: notifier.INFO, Text: string(rune('a' + i))}, 3)
		if len(buf) > 3 {
			t.Fatalf("buffer has %d entries", len(buf))
		}
	}
	if len(buf) != 3 || buf[0].Text != "h" || buf[2].Text != "j" {
		t.Errorf("got %+v", buf)
	}
}

func TestSnapshotPoolsAreCopies(t *testing.T) {
	pools := parseFixturePools(t, "zpool-status-vdev-classes.txt")
	setTestState(t, pools, map[string]*PoolUsageType{"zfsw_mix": {Name: "zfsw_mix", Avail: 1, Used: 1, Mountpoint: "/m"}})

	snap := snapshotPools()
	if len(snap) != 1 || snap[0].Name != "zfsw_mix" {
		t.Fatalf("snapshot: %+v", snap)
	}
	snap[0].Name = "changed"
	snap[0].Devices[0].Name = "changed"
	snap[0].Devices[0].Children[0].State = "changed"
	snap[0].Devices = append(snap[0].Devices[:0], Device{Name: "x"})

	again := snapshotPools()
	if again[0].Name != "zfsw_mix" || again[0].Devices[0].Name != "zfsw_mix" || again[0].Devices[0].Children[0].State != "ONLINE" || len(again[0].Devices) != 6 {
		t.Errorf("live state changed through the snapshot: %+v", again[0].Devices[0])
	}
	if pools[0].name != "zfsw_mix" || pools[0].devs[0].name != "zfsw_mix" {
		t.Error("parsed pool changed")
	}

	p, ok := snapshotPool("zfsw_mix")
	if !ok || p.Name != "zfsw_mix" {
		t.Fatalf("snapshotPool: %v %+v", ok, p)
	}
	p.Devices[0].Name = "changed"
	if q, _ := snapshotPool("zfsw_mix"); q.Devices[0].Name != "zfsw_mix" {
		t.Error("snapshotPool returned a reference")
	}
	if _, ok := snapshotPool("nope"); ok {
		t.Error("unknown pool found")
	}

	u := snapshotUsage()
	if u["zfsw_mix"].UsedPercent != 50 {
		t.Errorf("usage: %+v", u)
	}
	u["zfsw_mix"] = Usage{}
	delete(u, "zfsw_mix")
	if snapshotUsage()["zfsw_mix"].Mountpoint != "/m" {
		t.Error("usage snapshot is not a copy")
	}
}

func TestSnapshotState(t *testing.T) {
	pools := parseFixturePools(t, "zpool-status-vdev-classes.txt")
	setTestState(t, pools, map[string]*PoolUsageType{"zfsw_mix": {Name: "zfsw_mix", Avail: 3, Used: 1}})
	p, u := snapshotState()
	if len(p) != 1 || u["zfsw_mix"].UsedPercent != 25 {
		t.Fatalf("%+v %+v", p, u)
	}
	u["zfsw_mix"] = Usage{}
	p[0].Name = "x"
	if p2, u2 := snapshotState(); p2[0].Name != "zfsw_mix" || u2["zfsw_mix"].Used != 1 {
		t.Error("snapshotState returned references")
	}
}

func TestSnapshotEmptyState(t *testing.T) {
	setTestState(t, nil, nil)
	if p := snapshotPools(); p == nil || len(p) != 0 {
		t.Errorf("snapshotPools = %#v, want empty non-nil", p)
	}
	if u := snapshotUsage(); len(u) != 0 {
		t.Errorf("usage = %v", u)
	}
}

// setTestState replaces the live state for the duration of a test.
func setTestState(t *testing.T, pools []*PoolType, usage map[string]*PoolUsageType) {
	t.Helper()
	currentState.mutex.Lock()
	oldState, oldUsage := currentState.state, currentState.usage
	currentState.state, currentState.usage = pools, usage
	currentState.mutex.Unlock()
	t.Cleanup(func() {
		currentState.mutex.Lock()
		currentState.state, currentState.usage = oldState, oldUsage
		currentState.mutex.Unlock()
	})
}

func TestSnapshotRace(t *testing.T) {
	pools := parseFixturePools(t, "zpool-status-vdev-classes.txt")
	setTestState(t, pools, map[string]*PoolUsageType{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			currentState.mutex.Lock()
			currentState.state = parseFixturePools(t, "zpool-status-vdev-classes.txt")
			currentState.usage = map[string]*PoolUsageType{"zfsw_mix": {Avail: 1, Used: int64(i)}}
			currentState.mutex.Unlock()
		}
	}()
	for i := 0; i < 200; i++ {
		_ = snapshotPools()
		_, _ = snapshotPool("zfsw_mix")
		_ = snapshotUsage()
	}
	<-done
}

func TestHostInfo(t *testing.T) {
	old := startTime
	startTime = time.Now().Add(-90 * time.Second)
	defer func() { startTime = old }()
	oldHost := hostname
	hostname = "h1"
	defer func() { hostname = oldHost }()
	setHealth(t, true, true, time.Minute)

	h := hostInfo()
	if h.Version != buildVersion || h.Hostname != "h1" {
		t.Errorf("%+v", h)
	}
	if h.ZfswatcherUptimeSeconds < 90 || h.ZfswatcherUptimeSeconds > 100 {
		t.Errorf("uptime = %d", h.ZfswatcherUptimeSeconds)
	}
	if !h.LastZpoolQuery.Seen || !h.LastZpoolQuery.OK || time.Since(h.LastZpoolQuery.Time) < time.Minute {
		t.Errorf("query: %+v", h.LastZpoolQuery)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "hostname", "zfswatcher_uptime_seconds", "system_uptime_seconds", "load_average", "last_zpool_query"} {
		if !strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s missing in %s", k, b)
		}
	}
}

func TestSeverityNamesRoundTrip(t *testing.T) {
	for s := notifier.EMERG; s <= notifier.DEBUG; s++ {
		got, ok := severityFromName(s.String())
		if !ok || got != s {
			t.Errorf("severity %d: name %q parsed as %d, %v", s, s.String(), got, ok)
		}
	}
}

func TestWwwLogReceiverAndSnapshotEvents(t *testing.T) {
	goldenSetup(t) // sets cfg and clears the buffer
	cfg.Www.Logbuffer = 2
	ts := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	for i, text := range []string{"a", "b", "c"} {
		wwwLogReceiver(&notifier.Msg{Time: ts.Add(time.Duration(i) * time.Second), MsgType: notifier.MSGTYPE_MESSAGE, Severity: notifier.WARNING, Text: text})
	}
	wwwLogReceiver(&notifier.Msg{Time: ts, MsgType: notifier.MSGTYPE_ATTACHMENT, Severity: notifier.WARNING, Text: "att"})

	ev := snapshotEvents()
	if len(ev) != 2 || ev[0].Text != "b" || ev[1].Text != "c" || ev[1].Attachment != "att" || ev[1].Severity != "warning" {
		t.Fatalf("events: %+v", ev)
	}
	if !ev[1].Time.Equal(ts.Add(2 * time.Second)) {
		t.Errorf("time %v", ev[1].Time)
	}
	ev[0].Text = "changed"
	ev[1].Attachment = "changed"
	_ = append(ev[:0], Event{Text: "x"})
	again := snapshotEvents()
	if again[0].Text != "b" || again[1].Attachment != "att" {
		t.Errorf("buffer changed through the snapshot: %+v", again)
	}
	b, _ := json.Marshal(again[0])
	if !strings.Contains(string(b), `"severity":"warning"`) || !strings.Contains(string(b), `"time":"2026-05-06T07:08:10Z"`) {
		t.Errorf("json %s", b)
	}
}

func TestSnapshotEventsEmpty(t *testing.T) {
	goldenSetup(t)
	if ev := snapshotEvents(); ev == nil || len(ev) != 0 {
		t.Errorf("got %#v, want empty non-nil", ev)
	}
}

func TestWwwLogRace(t *testing.T) {
	goldenSetup(t)
	cfg.Www.Logbuffer = 10
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			wwwLogReceiver(&notifier.Msg{MsgType: notifier.MSGTYPE_MESSAGE, Severity: notifier.INFO, Text: "x"})
			wwwLogReceiver(&notifier.Msg{MsgType: notifier.MSGTYPE_ATTACHMENT, Severity: notifier.INFO, Text: "y"})
		}
	}()
	for i := 0; i < 300; i++ {
		_ = snapshotEvents()
	}
	<-done
}

func TestMakeLogMsgWeb(t *testing.T) {
	goldenSetup(t)
	ts := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	w := makeLogMsgWeb(Event{Time: ts, Severity: "crit", Text: "t", Attachment: "a"})
	want := logMsgWeb{Time: "2026-05-06 07:08:09", Severity: "crit", Class: "danger", Text: "t", Attachment: "a"}
	if w != want {
		t.Errorf("got %+v", w)
	}
	if w := makeLogMsgWeb(Event{Severity: "bogus"}); w.Class != "" {
		t.Errorf("unknown severity got class %q", w.Class)
	}
}
