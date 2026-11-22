//
// model.go
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

// The data layer: exported, presentation free types which can be encoded as
// JSON as they are (no CSS classes, no URLs, no indentation), and the
// functions which produce them from the live state. The web pages (and later
// the JSON API) are built from copies made by the snapshot functions, never
// from pointers into the live state.

import (
	"fmt"
	"sort"
	"time"

	"github.com/tantefred/zfswatcher/notifier"
)

// Pool is a ZFS pool as reported by "zpool status". Devices is the device
// tree: the top level entries are the pool itself, the class sections
// (logs, cache, spares, ...) and the vdevs.
type Pool struct {
	Name    string   `json:"name"`
	State   string   `json:"state"`
	Status  string   `json:"status"`
	Action  string   `json:"action"`
	See     string   `json:"see"`
	Scan    string   `json:"scan"`
	Errors  string   `json:"errors"`
	Extra   string   `json:"extra"`
	Devices []Device `json:"devices"`
}

// Device is a vdev, a disk or a class section of a pool. Read, Write and
// Cksum are -1 where zpool prints no counters (the class sections).
type Device struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Read     int64    `json:"read"`
	Write    int64    `json:"write"`
	Cksum    int64    `json:"cksum"`
	Info     string   `json:"info"`
	Children []Device `json:"children"`
}

// Usage is the space usage of a pool or dataset as reported by "zfs list".
// All sizes are bytes; -1 means "not available" (zfs prints "-").
// UsedPercent and AvailPercent are rounded integers.
type Usage struct {
	Name          string `json:"name"`
	Avail         int64  `json:"avail"`
	Used          int64  `json:"used"`
	Usedsnap      int64  `json:"usedsnap"`
	Usedds        int64  `json:"usedds"`
	Usedrefreserv int64  `json:"usedrefreserv"`
	Usedchild     int64  `json:"usedchild"`
	Refer         int64  `json:"refer"`
	Logicalused   int64  `json:"logicalused"`
	Mountpoint    string `json:"mountpoint"`
	Compressratio string `json:"compressratio"`
	UsedPercent   int    `json:"used_percent"`
	AvailPercent  int    `json:"avail_percent"`
}

// Event is an entry of the in-memory log buffer. Severity is the name of the
// severity level ("crit", "warning", ...).
type Event struct {
	Time       time.Time `json:"time"`
	Severity   string    `json:"severity"`
	Text       string    `json:"text"`
	Attachment string    `json:"attachment"`
}

// ZpoolQuery tells how the most recent "zpool status" query went.
type ZpoolQuery struct {
	Seen bool      `json:"seen"` // a query was made at all
	OK   bool      `json:"ok"`   // command ran and its output was parsed
	Time time.Time `json:"time"`
}

// HostInfo describes the daemon and the machine it runs on. The uptimes are
// whole seconds, 0 if unknown.
type HostInfo struct {
	Version                 string     `json:"version"`
	Hostname                string     `json:"hostname"`
	ZfswatcherUptimeSeconds int64      `json:"zfswatcher_uptime_seconds"`
	SystemUptimeSeconds     int64      `json:"system_uptime_seconds"`
	LoadAverage             [3]float32 `json:"load_average"`
	LastZpoolQuery          ZpoolQuery `json:"last_zpool_query"`
}

// Walk calls fn for every device of the pool in display order (depth first,
// parents before their children) together with its depth; the top level
// devices have depth 0.
func (p Pool) Walk(fn func(d Device, depth int)) {
	walkDevices(p.Devices, 0, fn)
}

func walkDevices(devs []Device, depth int, fn func(d Device, depth int)) {
	for _, d := range devs {
		fn(d, depth)
		walkDevices(d.Children, depth+1, fn)
	}
}

// poolFromParsed converts a parsed pool into the Pool type. The flat device
// list of the parser (subDevs/parentDev links) becomes a tree; nothing in the
// result refers to the parsed data.
func poolFromParsed(p *PoolType) Pool {
	pool := Pool{
		Name:    p.name,
		State:   p.state,
		Status:  p.status,
		Action:  p.action,
		See:     p.see,
		Scan:    p.scan,
		Errors:  p.errors,
		Extra:   p.extra,
		Devices: []Device{},
	}
	for i, d := range p.devs {
		if d.parentDev == -1 {
			pool.Devices = append(pool.Devices, deviceFromParsed(p.devs, i))
		}
	}
	return pool
}

// deviceFromParsed builds the device devs[i] with all its descendants.
// Sub device indexes always point forward in the list; entries which do not
// are skipped, so that damaged input can not cause endless recursion.
func deviceFromParsed(devs []*DevEntry, i int) Device {
	e := devs[i]
	d := Device{
		Name:     e.name,
		State:    e.state,
		Read:     e.read,
		Write:    e.write,
		Cksum:    e.cksum,
		Info:     e.rest,
		Children: []Device{},
	}
	for _, sub := range e.subDevs {
		if sub > i && sub < len(devs) {
			d.Children = append(d.Children, deviceFromParsed(devs, sub))
		}
	}
	return d
}

// usageFromParsed converts parsed "zfs list" data into the Usage type. A
// usage without any space (avail + used is 0) has 0 percent.
func usageFromParsed(u *PoolUsageType) Usage {
	r := Usage{
		Name:          u.Name,
		Avail:         u.Avail,
		Used:          u.Used,
		Usedsnap:      u.Usedsnap,
		Usedds:        u.Usedds,
		Usedrefreserv: u.Usedrefreserv,
		Usedchild:     u.Usedchild,
		Refer:         u.Refer,
		Logicalused:   u.Logicalused,
		Mountpoint:    u.Mountpoint,
		Compressratio: u.Compressratio,
	}
	if u.Avail+u.Used != 0 {
		r.UsedPercent = u.GetUsedPercent()
		r.AvailPercent = u.GetAvailPercent()
	}
	return r
}

// usageList returns the usage entries sorted by name.
func usageList(m map[string]Usage) []Usage {
	l := make([]Usage, 0, len(m))
	for _, u := range m {
		l = append(l, u)
	}
	sort.Slice(l, func(i, j int) bool { return l[i].Name < l[j].Name })
	return l
}

// usageMapFromParsed converts the result of parseZfsList. The map key is the
// dataset name as in the input.
func usageMapFromParsed(m map[string]*PoolUsageType) map[string]Usage {
	r := make(map[string]Usage, len(m))
	for name, u := range m {
		r[name] = usageFromParsed(u)
	}
	return r
}

// eventsAppend adds a message to the event buffer and returns the new buffer
// which holds at most limit entries (the oldest ones are dropped). An
// attachment is merged into the preceding event unless that already has one;
// message types other than message and attachment are ignored.
func eventsAppend(buf []Event, m *notifier.Msg, limit int) []Event {
	switch m.MsgType {
	case notifier.MSGTYPE_MESSAGE:
		buf = append(buf, Event{Time: m.Time, Severity: m.Severity.String(), Text: m.Text})
	case notifier.MSGTYPE_ATTACHMENT:
		if n := len(buf); n > 0 && buf[n-1].Attachment == "" {
			// add the attachment to the previous message
			buf[n-1].Attachment = m.Text
		} else {
			// make a new entry only with the attachment
			buf = append(buf, Event{Time: m.Time, Severity: m.Severity.String(), Attachment: m.Text})
		}
	}
	if len(buf) > limit {
		buf = buf[len(buf)-limit:]
	}
	return buf
}

// severityFromName is the inverse of notifier.Severity.String().
func severityFromName(name string) (notifier.Severity, bool) {
	var s notifier.Severity
	if n, err := fmt.Sscan(name, &s); n != 1 || err != nil {
		return notifier.SEVERITY_NONE, false
	}
	return s, true
}

// snapshotPools returns copies of all pools in the order of "zpool status".
func snapshotPools() []Pool {
	currentState.mutex.RLock()
	defer currentState.mutex.RUnlock()
	pools := make([]Pool, 0, len(currentState.state))
	for _, p := range currentState.state {
		pools = append(pools, poolFromParsed(p))
	}
	return pools
}

// snapshotState returns the pools and the usage entries of one and the same
// moment.
func snapshotState() ([]Pool, map[string]Usage) {
	currentState.mutex.RLock()
	defer currentState.mutex.RUnlock()
	pools := make([]Pool, 0, len(currentState.state))
	for _, p := range currentState.state {
		pools = append(pools, poolFromParsed(p))
	}
	return pools, usageMapFromParsed(currentState.usage)
}

// snapshotPool returns a copy of the pool with the given name.
func snapshotPool(name string) (Pool, bool) {
	currentState.mutex.RLock()
	defer currentState.mutex.RUnlock()
	for _, p := range currentState.state {
		if p.name == name {
			return poolFromParsed(p), true
		}
	}
	return Pool{}, false
}

// snapshotUsage returns copies of the usage entries by pool name; see
// usageList for a sorted list.
func snapshotUsage() map[string]Usage {
	currentState.mutex.RLock()
	defer currentState.mutex.RUnlock()
	return usageMapFromParsed(currentState.usage)
}

// snapshotEvents returns a copy of the log buffer, oldest event first.
func snapshotEvents() []Event {
	wwwLogMutex.RLock()
	defer wwwLogMutex.RUnlock()
	return append([]Event{}, wwwLogBuffer...)
}

// snapshotZpoolQuery returns what recordZpoolQuery stored.
func snapshotZpoolQuery() ZpoolQuery {
	zpoolHealth.mutex.Lock()
	defer zpoolHealth.mutex.Unlock()
	return ZpoolQuery{Seen: zpoolHealth.seen, OK: zpoolHealth.ok, Time: zpoolHealth.at}
}

// hostInfo collects the host and daemon information. Failing to read the
// system uptime or load average is logged and leaves the value at 0.
func hostInfo() HostInfo {
	h := HostInfo{
		Version:                 buildVersion,
		Hostname:                hostname,
		ZfswatcherUptimeSeconds: int64(time.Since(startTime) / time.Second),
		LastZpoolQuery:          snapshotZpoolQuery(),
	}
	uptime, err := getSystemUptime()
	if err != nil {
		notify.Printf(notifier.ERR, "can not get system uptime: %s", err)
	}
	h.SystemUptimeSeconds = int64(uptime / time.Second)
	h.LoadAverage, err = getSystemLoadaverage()
	if err != nil {
		notify.Printf(notifier.ERR, "can not get system load average: %s", err)
	}
	return h
}

// eof
