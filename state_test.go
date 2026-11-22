package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

// captureState replaces the global notifier and returns a function which
// stops it and returns the messages (not attachments) as "SEVERITY text".
func captureState(t *testing.T) func() []string {
	t.Helper()
	old := notify
	oldCfg := cfg
	notify = notifier.New()
	cfg = &cfgType{}
	var mu sync.Mutex
	var msgs []string
	_ = notify.AddLoggerCallback(notifier.DEBUG, func(m *notifier.Msg) {
		if m.MsgType == notifier.MSGTYPE_MESSAGE {
			mu.Lock()
			msgs = append(msgs, m.Text)
			mu.Unlock()
		}
	})
	restored := false
	restore := func() {
		if !restored {
			restored = true
			notify = old
			cfg = oldCfg
		}
	}
	t.Cleanup(restore)
	return func() []string {
		<-notify.Close()
		restore()
		mu.Lock()
		defer mu.Unlock()
		return msgs
	}
}

func parseFixture(t *testing.T, name string) []*PoolType {
	t.Helper()
	pools, err := parseZpoolStatus(readFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return pools
}

func TestStateFileRoundtrip(t *testing.T) {
	pools := parseFixture(t, "zpool-status-degraded.txt")
	usage := parseZfsList(readFixture(t, "zfs-list.txt"))
	path := filepath.Join(t.TempDir(), "state.json")

	sf := newStateFile(pools, usage)
	if err := writeStateFile(path, sf); err != nil {
		t.Fatal(err)
	}
	got, err := loadStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.sameAs(sf) {
		t.Errorf("roundtrip changed the state: %+v vs %+v", got, sf)
	}
	if len(got.Usage) != len(usage) {
		t.Errorf("usage entries: got %d, want %d", len(got.Usage), len(usage))
	}
	back := got.poolTypes()
	if len(back) != len(pools) {
		t.Fatalf("got %d pools, want %d", len(back), len(pools))
	}
	for i, p := range pools {
		if back[i].name != p.name || back[i].state != p.state ||
			back[i].status != p.status || len(back[i].devs) != len(p.devs) {
			t.Errorf("pool %d differs after roundtrip", i)
		}
		for j, d := range p.devs {
			b := back[i].devs[j]
			if b.name != d.name || b.state != d.state || b.read != d.read ||
				b.write != d.write || b.cksum != d.cksum || b.rest != d.rest ||
				(len(b.subDevs) != 0) != (len(d.subDevs) != 0) {
				t.Errorf("device %s differs after roundtrip", d.name)
			}
		}
	}
}

func TestStateFileMissing(t *testing.T) {
	_, err := loadStateFile(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("want ErrNotExist, got %v", err)
	}
}

func TestStateFileBroken(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"garbage":   "{not json",
		"empty":     "",
		"version0":  `{"pools":[]}`,
		"version99": `{"version":99,"pools":[]}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadStateFile(path)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: want a format error, got %v", name, err)
		}
	}
}

func TestLoadPreviousMessages(t *testing.T) {
	dir := t.TempDir()
	done := captureState(t)
	newStatePersister(filepath.Join(dir, "missing.json")).loadPrevious()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("xx"), 0o600)
	if newStatePersister(bad).loadPrevious() != nil {
		t.Error("broken file must not yield a state")
	}
	msgs := done()
	if len(msgs) != 2 || !strings.Contains(msgs[0], "no state file") ||
		!strings.Contains(msgs[1], "ignoring state file") {
		t.Errorf("unexpected messages: %q", msgs)
	}
	var np *statePersister
	if np.loadPrevious() != nil || newStatePersister("") != nil {
		t.Error("empty path must disable persistence")
	}
	np.update(nil, nil) // must not panic
}

func TestWriteStateFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	sf := newStateFile(parseFixture(t, "zpool-status-degraded.txt"), nil)
	if err := writeStateFile(path, sf); err != nil {
		t.Fatal(err)
	}
	// replace it: no temporary files may remain, mode must be 0640
	if err := writeStateFile(path, newStateFile(parseFixture(t, "zpool-status-2pools.txt"), nil)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("leftover files in state directory: %v", entries)
	}
	if st, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640", st.Mode().Perm())
	}
	// a failed write must leave the old file intact and no temp file behind
	if err := writeStateFile(filepath.Join(dir, "no-such-dir", "state.json"), sf); err == nil {
		t.Error("write into a missing directory must fail")
	}
	got, err := loadStateFile(path)
	if err != nil || len(got.Pools) == 0 {
		t.Fatalf("old file damaged: %v", err)
	}
}

func TestPersisterWritesOnlyOnChange(t *testing.T) {
	done := captureState(t)
	path := filepath.Join(t.TempDir(), "state.json")
	p := newStatePersister(path)
	pools := parseFixture(t, "zpool-status-degraded.txt")

	p.update(pools, nil)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	p.update(pools, nil) // unchanged: not rewritten
	if _, err := os.Stat(path); err == nil {
		t.Error("unchanged state was written again")
	}
	p.update(parseFixture(t, "zpool-status-2pools.txt"), nil)
	if _, err := os.Stat(path); err != nil {
		t.Error("changed state was not written")
	}
	if msgs := done(); len(msgs) != 0 {
		t.Errorf("unexpected messages: %q", msgs)
	}
}

func TestPersisterErrorLoggedOncePerFailure(t *testing.T) {
	done := captureState(t)
	dir := t.TempDir()
	// "sub" is a regular file, so neither MkdirAll nor the write can work
	sub := filepath.Join(dir, "sub")
	if err := os.WriteFile(sub, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "state.json")
	p := newStatePersister(path)
	pools := parseFixture(t, "zpool-status-degraded.txt")

	p.update(pools, nil)
	p.update(pools, nil)
	p.update(pools, nil)
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	p.update(pools, nil) // recovers (creates the directory)
	msgs := done()
	if len(msgs) != 2 || !strings.Contains(msgs[0], "cannot write state file") ||
		!strings.Contains(msgs[1], "writable again") {
		t.Errorf("unexpected messages: %q", msgs)
	}
}

// degraded fixture with the pool healthy: what the previous run saw.
func healthyVariant(t *testing.T) []*PoolType {
	t.Helper()
	s := readFixture(t, "zpool-status-degraded.txt")
	s = strings.ReplaceAll(s, "UNAVAIL", "ONLINE")
	s = strings.ReplaceAll(s, "DEGRADED", "ONLINE")
	pools, err := parseZpoolStatus(s)
	if err != nil {
		t.Fatal(err)
	}
	return pools
}

func TestDiffAfterLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeStateFile(path, newStateFile(healthyVariant(t), nil)); err != nil {
		t.Fatal(err)
	}
	prev, err := loadStateFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// pool became DEGRADED while the daemon was down
	done := captureState(t)
	checkZpoolStatus(prev.poolTypes(), parseFixture(t, "zpool-status-degraded.txt"))
	msgs := strings.Join(done(), "\n")
	if !strings.Contains(msgs, `pool "test" state changed: ONLINE -> DEGRADED`) {
		t.Errorf("pool state change not reported:\n%s", msgs)
	}
	if !strings.Contains(msgs, `device "B0" state changed: ONLINE -> UNAVAIL`) {
		t.Errorf("device state change not reported:\n%s", msgs)
	}
	if strings.Contains(msgs, `device "A1"`) {
		t.Errorf("unchanged device reported:\n%s", msgs)
	}

	// nothing changed: silence
	done = captureState(t)
	same := newStateFile(parseFixture(t, "zpool-status-degraded.txt"), nil)
	checkZpoolStatus(same.poolTypes(), parseFixture(t, "zpool-status-degraded.txt"))
	if msgs := done(); len(msgs) != 0 {
		t.Errorf("unchanged state reported: %q", msgs)
	}
}

func TestUsageDiffAfterLoad(t *testing.T) {
	done := captureState(t)
	cfg.Severity.Usedspace = percentageToSeverityMap{80: notifier.WARNING}
	sf := newStateFile(nil, map[string]*PoolUsageType{"tank": {Name: "tank", Avail: 30, Used: 70}})
	now := map[string]*PoolUsageType{"tank": {Name: "tank", Avail: 10, Used: 90}}
	checkZfsUsage(sf.usageTypes(), now)
	msgs := done()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "usage reached 80%") {
		t.Errorf("unexpected messages: %q", msgs)
	}
}

func TestStateFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	big := make([]byte, maxStateFileSize+1)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStateFile(path); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("want too large error, got %v", err)
	}
	done := captureState(t)
	if newStatePersister(path).loadPrevious() != nil {
		t.Error("oversized file must not yield a state")
	}
	msgs := done()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "ignoring state file") {
		t.Errorf("unexpected messages: %q", msgs)
	}
}

func TestPersisterCreatesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "state.json")
	done := captureState(t)
	sp := newStatePersister(path)
	sp.update(parseFixture(t, "zpool-status-degraded.txt"), nil)
	if msgs := done(); len(msgs) != 0 {
		t.Errorf("unexpected messages: %q", msgs)
	}
	if _, err := loadStateFile(path); err != nil {
		t.Errorf("state file not written: %v", err)
	}
}

func TestStaleTempFilesRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	stale := filepath.Join(dir, ".state.json.tmp12345")
	other := filepath.Join(dir, "other.txt")
	for _, f := range []string{stale, other} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	done := captureState(t)
	newStatePersister(path).loadPrevious()
	done()
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temp file still there: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("unrelated file removed: %v", err)
	}
}

func testEvents(n int) []Event {
	ts := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var ev []Event
	for i := 0; i < n; i++ {
		ev = append(ev, Event{Time: ts.Add(time.Duration(i) * time.Minute),
			Severity: "warning", Text: fmt.Sprintf("event %d", i)})
	}
	ev[n-1].Attachment = "attachment"
	return ev
}

func TestStateFileEventsRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	sf := newStateFile(parseFixture(t, "zpool-status-degraded.txt"), nil)
	sf.Events = testEvents(3)
	if err := writeStateFile(path, sf); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"time": "2026-11-01T10:00:00Z"`) {
		t.Errorf("time is not RFC3339: %s", raw)
	}
	got, err := loadStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !eventsEqual(got.Events, sf.Events) || !got.sameAs(sf) {
		t.Errorf("events changed by the roundtrip: %+v", got.Events)
	}
	other := *sf
	other.Events = testEvents(4)
	if got.sameAs(&other) {
		t.Error("different events must not be the same state")
	}
}

func TestStateFileWithoutEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.json")
	old := `{"version":1,"pools":[{"name":"tank","state":"ONLINE"}],"future":true}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	sf, err := loadStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.Events) != 0 || len(sf.Pools) != 1 {
		t.Errorf("unexpected content: %+v", sf)
	}
}

func TestPersisterWritesEvents(t *testing.T) {
	goldenSetup(t)
	cfg.Www.Logbuffer = 3
	path := filepath.Join(t.TempDir(), "state.json")
	pools := parseFixture(t, "zpool-status-degraded.txt")
	sp := newStatePersister(path)
	sp.update(pools, nil)
	if sf, _ := loadStateFile(path); len(sf.Events) != 0 {
		t.Fatalf("unexpected events %+v", sf.Events)
	}
	ts := time.Date(2026, 11, 1, 10, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		wwwLogReceiver(&notifier.Msg{Time: ts.Add(time.Duration(i) * time.Second),
			MsgType: notifier.MSGTYPE_MESSAGE, Severity: notifier.INFO, Text: fmt.Sprintf("m%d", i)})
	}
	sp.update(pools, nil)
	sf, err := loadStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.Events) != 3 || sf.Events[0].Text != "m2" || sf.Events[2].Text != "m4" {
		t.Fatalf("events in file: %+v", sf.Events)
	}
	// unchanged: no new write
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	sp.update(pools, nil)
	if _, err := os.Stat(path); err == nil {
		t.Error("written again although nothing changed")
	}
}

func TestRestoreEvents(t *testing.T) {
	goldenSetup(t)
	cfg.Www.Logbuffer = 4
	wwwLogReceiver(&notifier.Msg{Time: time.Now(), MsgType: notifier.MSGTYPE_MESSAGE, Severity: notifier.INFO, Text: "starting"})
	restoreEvents(testEvents(5), 4)
	ev := snapshotEvents()
	if len(ev) != 4 || ev[0].Text != "event 2" || ev[3].Text != "starting" {
		t.Fatalf("got %+v", ev)
	}
	restoreEvents(nil, 4)
	restoreEvents(testEvents(2), 0)
	if len(snapshotEvents()) != 4 {
		t.Error("empty input or limit 0 changed the buffer")
	}
}

func TestRestoredEventsNotNotified(t *testing.T) {
	goldenSetup(t)
	cfg.Www.Logbuffer = 10
	done := captureState(t)
	cfg.Www.Logbuffer = 10
	restoreEvents(testEvents(3), 10)
	if msgs := done(); len(msgs) != 0 {
		t.Errorf("restoring sent notifications: %q", msgs)
	}
	if len(snapshotEvents()) != 3 {
		t.Error("events not in the buffer")
	}
}
