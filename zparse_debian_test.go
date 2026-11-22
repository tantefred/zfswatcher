package main

import (
	"strings"
	"sync"
	"testing"

	"github.com/tantefred/zfswatcher/notifier"
)

// Fixtures in test/ named *-vdev-classes, *-spare-resilver etc. were captured
// with scripts/collect-zfs-fixtures.sh on Debian 13 (OpenZFS 2.3.9).
func TestParseZpoolStatusDebian(t *testing.T) {
	tests := []struct {
		file     string
		pool     string
		state    string
		scan     string // prefix
		extra    string // prefix
		numDevs  int
		devName  string // a device that must exist ...
		devState string // ... in this state
		devRest  string // ... with this comment
	}{
		{"zpool-status-offline.txt", "zfsw_mirror", "DEGRADED", "", "", 4,
			"/var/tmp/zfsw-collect/m2", "OFFLINE", ""},
		{"zpool-status-faulted.txt", "zfsw_mirror", "DEGRADED", "resilvered 18K", "", 4,
			"/var/tmp/zfsw-collect/m2", "FAULTED", "external device fault"},
		{"zpool-status-scrub-repairing.txt", "zfsw_mirror", "ONLINE", "scrub in progress", "", 4,
			"/var/tmp/zfsw-collect/m1", "ONLINE", "(repairing)"},
		{"zpool-status-scrub-repaired.txt", "zfsw_mirror", "ONLINE", "scrub repaired 7.08M", "", 4,
			"/var/tmp/zfsw-collect/m1", "ONLINE", ""},
		{"zpool-status-resilver-replacing.txt", "zfsw_mirror", "ONLINE", "resilver in progress", "", 6,
			"/var/tmp/zfsw-collect/m3", "ONLINE", "(resilvering)"},
		{"zpool-status-checkpoint.txt", "zfsw_mirror", "ONLINE", "resilvered 401M", "checkpoint: created", 6,
			"replacing-1", "ONLINE", ""},
		{"zpool-status-removal.txt", "zfsw_rem", "ONLINE", "", "remove: Evacuation", 7,
			"mirror-1", "ONLINE", "(removing)"},
		{"zpool-status-removal-done.txt", "zfsw_rem", "ONLINE", "", "remove: Removal of vdev 1", 4,
			"mirror-0", "ONLINE", ""},
		{"zpool-status-raidz-expand.txt", "zfsw_exp", "ONLINE", "", "expand: expansion of raidz1-0", 6,
			"raidz1-0", "ONLINE", ""},
		{"zpool-status-raidz-expand-scrub.txt", "zfsw_exp", "ONLINE", "scrub in progress", "expand: expanded raidz1-0", 6,
			"raidz1-0", "ONLINE", ""},
		{"zpool-status-vdev-classes.txt", "zfsw_mix", "ONLINE", "", "", 15,
			"/var/tmp/zfsw-collect/c6", "AVAIL", ""},
		{"zpool-status-spare-resilver.txt", "zfsw_mix", "DEGRADED", "resilver in progress", "", 17,
			"spare-1", "DEGRADED", ""},
		{"zpool-status-unavail.txt", "zfsw_un", "DEGRADED", "", "", 4,
			"14974271720844242149", "UNAVAIL", "was /var/tmp/zfsw-collect/u2"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			pools, err := parseZpoolStatus(readFixture(t, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if len(pools) != 1 {
				t.Fatalf("got %d pools, want 1", len(pools))
			}
			p := pools[0]
			if p.name != tt.pool || p.state != tt.state {
				t.Errorf("pool %q state %q, want %q %q", p.name, p.state, tt.pool, tt.state)
			}
			if !strings.HasPrefix(p.scan, tt.scan) {
				t.Errorf("scan = %q, want prefix %q", p.scan, tt.scan)
			}
			if !strings.HasPrefix(p.extra, tt.extra) {
				t.Errorf("extra = %q, want prefix %q", p.extra, tt.extra)
			}
			if len(p.devs) != tt.numDevs {
				t.Errorf("got %d devices, want %d", len(p.devs), tt.numDevs)
			}
			found := false
			for _, d := range p.devs {
				if d.name == tt.devName {
					found = true
					if d.state != tt.devState || d.rest != tt.devRest {
						t.Errorf("%s: state %q rest %q, want %q %q",
							d.name, d.state, d.rest, tt.devState, tt.devRest)
					}
				}
			}
			if !found {
				t.Errorf("device %q not found", tt.devName)
			}
		})
	}
}

func TestParseZpoolStatusDebianCounters(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-scrub-repaired.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range pools[0].devs {
		if d.name == "/var/tmp/zfsw-collect/m1" && d.cksum != 131 {
			t.Errorf("cksum = %d, want 131", d.cksum)
		}
	}
}

func TestZpoolIostatParserVdevClasses(t *testing.T) {
	table := ZpoolIostatParser(readFixture(t, "zpool-iostat-v-classes.txt"))
	if table == nil {
		t.Fatal("parse error")
	}
	rows := (*table)["zfsw_mix"]
	// pool, raidz1-0, 3 disks, 4 class headers and 4 class devices
	if len(rows) != 13 {
		t.Errorf("got %d rows, want 13", len(rows))
	}
	if r := rows["/var/tmp/zfsw-collect/c5"]; r == nil || r.CapacityAlloc != unniceNumber("69.5M") {
		t.Errorf("cache device row missing or wrong: %+v", r)
	}
}

func TestParseZfsListAllDebian(t *testing.T) {
	m := parseZfsList(readFixture(t, "zfs-list-all-debian.txt"))
	if len(m) != 9 {
		t.Fatalf("got %d entries, want 9", len(m))
	}
	if u := m["zfsw_mirror/vol"]; u == nil || u.Usedrefreserv != 67<<20 {
		t.Errorf("vol entry: %+v", u)
	}
	if u := m["zfsw_mirror/data@snap1"]; u == nil || u.Used != 0 {
		t.Errorf("snapshot entry: %+v", u)
	}
}

func TestParseZpoolStatusScrubStates(t *testing.T) {
	tests := []struct{ file, scan string }{
		{"zpool-status-scrub-paused.txt", "scrub paused since"},
		{"zpool-status-scrub-canceled.txt", "scrub canceled on"},
	}
	for _, tt := range tests {
		pools, err := parseZpoolStatus(readFixture(t, tt.file))
		if err != nil {
			t.Fatalf("%s: %v", tt.file, err)
		}
		if !strings.HasPrefix(pools[0].scan, tt.scan) {
			t.Errorf("%s: scan = %q, want prefix %q", tt.file, pools[0].scan, tt.scan)
		}
	}
	// A paused scrub also prints when it was started.
	pools, _ := parseZpoolStatus(readFixture(t, "zpool-status-scrub-paused.txt"))
	if !strings.Contains(pools[0].scan, "scrub started on") {
		t.Errorf("scan = %q, missing start time", pools[0].scan)
	}
}

func TestParseZpoolStatusScrubAndResilver(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-draid-spare.txt"))
	if err != nil {
		t.Fatal(err)
	}
	scan := pools[0].scan
	if !strings.HasPrefix(scan, "scrub in progress") || !strings.Contains(scan, "\nresilvered (draid1:2d:5c:1s-0) 16.0M") {
		t.Errorf("scan = %q", scan)
	}
}

func TestParseZpoolStatusMultiPool(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-multi-pool.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, state string }{
		{"zfsw_draid", "DEGRADED"}, {"zfsw_rz2", "DEGRADED"}, {"zfsw_rz3", "ONLINE"},
	}
	if len(pools) != len(want) {
		t.Fatalf("got %d pools, want %d", len(pools), len(want))
	}
	for i, w := range want {
		if pools[i].name != w.name || pools[i].state != w.state {
			t.Errorf("pool %d = %s %s, want %s %s", i, pools[i].name, pools[i].state, w.name, w.state)
		}
	}
}

func TestParseZpoolStatusDraidLayouts(t *testing.T) {
	for _, tt := range []struct {
		file    string
		numDevs int
	}{
		{"zpool-status-raidz2-two-faulted.txt", 6},
		{"zpool-status-draid.txt", 9},
		{"zpool-status-draid-spare.txt", 11},
		{"zpool-status-features.txt", 2},
		{"zpool-status-flag-s.txt", 4},
		{"zpool-status-flag-g.txt", 4},
		{"zpool-status-flag-t.txt", 4},
	} {
		pools, err := parseZpoolStatus(readFixture(t, tt.file))
		if err != nil {
			t.Errorf("%s: %v", tt.file, err)
			continue
		}
		if len(pools[0].devs) != tt.numDevs {
			t.Errorf("%s: got %d devices, want %d", tt.file, len(pools[0].devs), tt.numDevs)
		}
	}
}

func TestParseZpoolStatusFeaturesHint(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-features.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pools[0].status, "Some supported and requested features are not enabled") {
		t.Errorf("status = %q", pools[0].status)
	}
	if !strings.Contains(pools[0].action, "zpool upgrade") {
		t.Errorf("action = %q", pools[0].action)
	}
}

func TestZpoolIostatParserMultiPool(t *testing.T) {
	table := ZpoolIostatParser(readFixture(t, "zpool-iostat-v-multi-pool.txt"))
	if table == nil {
		t.Fatal("parse error")
	}
	for pool, rows := range map[string]int{"zfsw_draid": 9, "zfsw_rz2": 6, "zfsw_rz3": 7} {
		if got := len((*table)[pool]); got != rows {
			t.Errorf("%s: %d rows, want %d", pool, got, rows)
		}
	}
}

// Scenario F (zinject): a device degraded with "too many errors" and a pool
// with write errors printed with an SI-style suffix ("1.34K").
func TestParseZpoolStatusInjected(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-inject-degrade.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	p := pools[0]
	if p.name != "zfsw_inj" || p.state != "DEGRADED" {
		t.Errorf("pool %q state %q", p.name, p.state)
	}
	if !strings.Contains(p.status, "unrecoverable error") {
		t.Errorf("status = %q", p.status)
	}
	if p.errors != "No known data errors" {
		t.Errorf("errors = %q", p.errors)
	}
	if len(p.devs) != 4 {
		t.Fatalf("got %d devices, want 4", len(p.devs))
	}
	d := p.devs[3]
	if d.name != "/var/tmp/zfsw-collect/i2" || d.state != "DEGRADED" ||
		d.rest != "too many errors" || d.read != 0 || d.write != 0 || d.cksum != 0 {
		t.Errorf("unexpected device %+v", *d)
	}
}

func TestParseZpoolStatusDataCorruption(t *testing.T) {
	pools, err := parseZpoolStatus(readFixture(t, "zpool-status-data-corruption.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	p := pools[0]
	if p.state != "ONLINE" || !strings.Contains(p.status, "error resulting in data") {
		t.Errorf("state %q status %q", p.state, p.status)
	}
	if want := "121 data errors, use '-v' for a list"; p.errors != want {
		t.Errorf("errors = %q, want %q", p.errors, want)
	}
	if len(p.devs) != 2 {
		t.Fatalf("got %d devices, want 2", len(p.devs))
	}
	d := p.devs[1]
	// 1.34K = 1.34 * 1024 = 1372.16, truncated.
	if d.read != 0 || d.write != 1372 || d.cksum != 0 || d.state != "ONLINE" || d.rest != "" {
		t.Errorf("unexpected device %+v", *d)
	}
}

// The daemon must report the new errors line and the increased write errors.
func TestCheckZpoolStatusDataCorruption(t *testing.T) {
	healthy := strings.Replace(readFixture(t, "zpool-status-data-corruption.txt"), "1.34K", "0", 1)
	healthy = strings.Replace(healthy, "121 data errors, use '-v' for a list",
		"No known data errors", 1)
	oldPools, err := parseZpoolStatus(healthy)
	if err != nil {
		t.Fatal(err)
	}
	newPools, err := parseZpoolStatus(readFixture(t, "zpool-status-data-corruption.txt"))
	if err != nil {
		t.Fatal(err)
	}

	oldCfg, oldNotify := cfg, notify
	t.Cleanup(func() { cfg, notify = oldCfg, oldNotify })
	cfg = &cfgType{}
	cfg.Severity.Poolerrorschanged = notifier.WARNING
	cfg.Severity.Devwriteerrorsincreased = notifier.ERR
	var mu sync.Mutex
	var msgs []string
	notify = notifier.New()
	if err := notify.AddLoggerCallback(notifier.DEBUG, func(m *notifier.Msg) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, m.Text)
	}); err != nil {
		t.Fatal(err)
	}
	checkZpoolStatus(oldPools, newPools)
	<-notify.Close()

	mu.Lock()
	defer mu.Unlock()
	all := strings.Join(msgs, "\n")
	for _, want := range []string{
		`new errors: 121 data errors, use '-v' for a list`,
		`write errors increased: 0 -> 1372`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing notification %q in:\n%s", want, all)
		}
	}
}
