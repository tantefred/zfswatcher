//
// metrics.go
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

// The Prometheus endpoint "<rootdir>/metrics" (text exposition format
// 0.0.4, written by hand: the format is simple and needs no dependency). It
// is built from the same snapshots as the web pages and the JSON API.

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// metricPoolStates and metricDeviceStates are the states which always get a
// series (0 or 1, "one-hot"), so that an alert on state != ONLINE works and
// a series does not appear and vanish on a state change. A state outside the
// list gets an additional series while it lasts.
var (
	metricPoolStates   = []string{"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SUSPENDED"}
	metricDeviceStates = []string{"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED"}
)

// metricLabel is one label of a sample; labels are written in the given order.
type metricLabel struct{ name, value string }

// escapeLabelValue escapes backslash, double quote and line feed.
func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

type metricsWriter struct {
	w strings.Builder
}

func (m *metricsWriter) header(name, help, typ string) {
	help = strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(help)
	fmt.Fprintf(&m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *metricsWriter) sample(name string, value string, labels ...metricLabel) {
	m.w.WriteString(name)
	if len(labels) > 0 {
		m.w.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				m.w.WriteByte(',')
			}
			m.w.WriteString(l.name + `="` + escapeLabelValue(l.value) + `"`)
		}
		m.w.WriteByte('}')
	}
	m.w.WriteByte(' ')
	m.w.WriteString(value)
	m.w.WriteByte('\n')
}

func boolValue(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func intValue(n int64) string { return strconv.FormatInt(n, 10) }

func floatValue(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// stateSeries returns the states to report for the current state: the
// known ones plus the current one if it is not among them.
func stateSeries(known []string, current string) []string {
	for _, s := range known {
		if s == current {
			return known
		}
	}
	return append(append([]string{}, known...), current)
}

type deviceMetric struct {
	pool string
	dev  Device
}

// writeMetrics writes all metrics. The output is sorted, so that it is
// stable for equal input. Devices without a state (the class sections
// "logs", "cache", ...) and counters of -1 ("not available") are left out.
func writeMetrics(out io.Writer, version string, pools []Pool, usage map[string]Usage, q ZpoolQuery) error {
	m := &metricsWriter{}

	pools = append([]Pool{}, pools...)
	sort.SliceStable(pools, func(i, j int) bool { return pools[i].Name < pools[j].Name })

	m.header("zfswatcher_build_info", "Version of zfswatcher.", "gauge")
	m.sample("zfswatcher_build_info", "1", metricLabel{"version", version})

	if q.Seen {
		m.header("zfswatcher_last_check_timestamp_seconds",
			"Unix time of the last \"zpool status\" query.", "gauge")
		m.sample("zfswatcher_last_check_timestamp_seconds", strconv.FormatFloat(float64(q.Time.UnixMilli())/1000, 'f', 3, 64))
		m.header("zfswatcher_last_check_success",
			"1 if the last \"zpool status\" query succeeded, 0 if it failed.", "gauge")
		m.sample("zfswatcher_last_check_success", boolValue(q.OK))
	}

	m.header("zfswatcher_pool_state", "Pool state, 1 for the current state and 0 for the other known ones.", "gauge")
	for _, p := range pools {
		for _, s := range stateSeries(metricPoolStates, p.State) {
			m.sample("zfswatcher_pool_state", boolValue(s == p.State),
				metricLabel{"pool", p.Name}, metricLabel{"state", s})
		}
	}

	var devs []deviceMetric
	seen := map[[2]string]bool{}
	for _, p := range pools {
		p.Walk(func(d Device, _ int) {
			key := [2]string{p.Name, d.Name}
			if d.State == "" || seen[key] {
				return
			}
			seen[key] = true
			devs = append(devs, deviceMetric{p.Name, d})
		})
	}
	sort.SliceStable(devs, func(i, j int) bool {
		if devs[i].pool != devs[j].pool {
			return devs[i].pool < devs[j].pool
		}
		return devs[i].dev.Name < devs[j].dev.Name
	})

	m.header("zfswatcher_device_state", "Device state, 1 for the current state and 0 for the other known ones.", "gauge")
	for _, d := range devs {
		for _, s := range stateSeries(metricDeviceStates, d.dev.State) {
			m.sample("zfswatcher_device_state", boolValue(s == d.dev.State),
				metricLabel{"pool", d.pool}, metricLabel{"device", d.dev.Name}, metricLabel{"state", s})
		}
	}

	counters := []struct {
		name, help string
		get        func(Device) int64
	}{
		{"zfswatcher_device_read_errors", "Read errors of the device as shown by zpool status.", func(d Device) int64 { return d.Read }},
		{"zfswatcher_device_write_errors", "Write errors of the device as shown by zpool status.", func(d Device) int64 { return d.Write }},
		{"zfswatcher_device_cksum_errors", "Checksum errors of the device as shown by zpool status.", func(d Device) int64 { return d.Cksum }},
	}
	for _, c := range counters {
		m.header(c.name, c.help, "gauge") // gauge: "zpool clear" resets them
		for _, d := range devs {
			if v := c.get(d.dev); v >= 0 {
				m.sample(c.name, intValue(v), metricLabel{"pool", d.pool}, metricLabel{"device", d.dev.Name})
			}
		}
	}

	// Space of the pool's root dataset as in "zfs list": used plus available.
	type poolSpace struct {
		name        string
		used, avail int64
	}
	var spaces []poolSpace
	for _, p := range pools {
		if u, ok := usage[p.Name]; ok && u.Used >= 0 && u.Avail >= 0 {
			spaces = append(spaces, poolSpace{p.Name, u.Used, u.Avail})
		}
	}
	space := []struct {
		name, help string
		get        func(poolSpace) string
	}{
		{"zfswatcher_pool_usable_bytes", "Usable space of the pool root dataset (used plus available, as in zfs list).",
			func(s poolSpace) string { return intValue(s.used + s.avail) }},
		{"zfswatcher_pool_used_bytes", "Used space of the pool root dataset as in zfs list.",
			func(s poolSpace) string { return intValue(s.used) }},
		{"zfswatcher_pool_available_bytes", "Available space of the pool root dataset as in zfs list.",
			func(s poolSpace) string { return intValue(s.avail) }},
		{"zfswatcher_pool_used_ratio", "Used share of the usable space, 0 to 1.",
			func(s poolSpace) string {
				if s.used+s.avail == 0 {
					return "0"
				}
				return floatValue(float64(s.used) / float64(s.used+s.avail))
			}},
	}
	for _, sp := range space {
		m.header(sp.name, sp.help, "gauge")
		for _, s := range spaces {
			m.sample(sp.name, sp.get(s), metricLabel{"pool", s.name})
		}
	}

	_, err := io.WriteString(out, m.w.String())
	return err
}

// metricsHandler serves the Prometheus metrics. GET and HEAD only; errors
// are plain text (requireRole).
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	pools, usage := snapshotState()
	w.Header().Set("Content-Type", metricsContentType)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_ = writeMetrics(w, buildVersion, pools, usage, snapshotZpoolQuery())
}

// registerMetrics adds "<rootdir>/metrics" if "[www] metrics" is enabled.
func registerMetrics(mux *http.ServeMux) {
	if cfg.Www.Metrics {
		mux.HandleFunc(cfg.Www.Rootdir+"/metrics", requireRole(RoleViewer, metricsHandler))
	}
}

// eof
