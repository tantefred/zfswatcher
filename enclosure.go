//
// enclosure.go
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
	"strconv"
	"strings"
)

// An enclosure layout describes the slots of a chassis as data: rows of slot
// names as they appear on the front of the unit. The template renders any
// layout in the same way, so more chassis models only need another
// enclosureLayout. A slot is filled by the pool device of the same name
// (for the 45Drives chassis "1-<n>" and "2-<n>").
type enclosureLayout struct {
	Title    string
	Subtitle string
	// Rows lists the slot names of each row from left to right. A layout
	// without rows has no known slot arrangement yet.
	Rows [][]string
}

// enclosureSlot is a slot of a rendered layout.
type enclosureSlot struct {
	Name    string // slot name, e.g. "1-3"
	Present bool   // a device of this name exists in a pool
	State   string // state of the device, empty for an empty slot
	Class   string // css class of the slot, see zfswatcher.css
}

// enclosureView is a layout filled with the current device states.
type enclosureView struct {
	Title    string
	Subtitle string
	HasRows  bool
	Rows     [][]enclosureSlot
	Devices  int // number of slots with a device
}

// slotNames returns the slot names prefix-from .. prefix-to, counting down
// if to < from.
func slotNames(prefix string, from, to int) []string {
	var names []string
	step := 1
	if to < from {
		step = -1
	}
	for n := from; ; n += step {
		names = append(names, prefix+"-"+strconv.Itoa(n))
		if n == to {
			break
		}
	}
	return names
}

func concatSlots(parts ...[]string) []string {
	var all []string
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}

// enclosureLayouts returns the layouts enabled in the [chassis] section, in
// the order of the menu of the 45Drives models. Only the S45 has a slot
// arrangement so far, for the other models the page shows just the name.
func enclosureLayouts() []enclosureLayout {
	var layouts []enclosureLayout
	if cfg.Chassis.Chassis45drives15 {
		layouts = append(layouts, enclosureLayout{Title: "45Drives AV15"})
	}
	if cfg.Chassis.Chassis45drives30 {
		layouts = append(layouts, enclosureLayout{Title: "45Drives Q30"})
	}
	if cfg.Chassis.Chassis45drives45l {
		layouts = append(layouts, enclosureLayout{Title: "45Drives S45 lite"})
	}
	if cfg.Chassis.Chassis45drives45 {
		layouts = append(layouts, enclosureLayout{
			Title:    "45Drives S45 Enclosure",
			Subtitle: "Front of unit",
			Rows: [][]string{
				slotNames("1", 1, 15),
				concatSlots(slotNames("2", 6, 1), slotNames("1", 24, 16)),
				slotNames("2", 7, 21),
			},
		})
	}
	if cfg.Chassis.Chassis45drives60 {
		layouts = append(layouts, enclosureLayout{Title: "45Drives XL60"})
	}
	return layouts
}

// slotClass returns the css class of a slot for a device state; states which
// are not known get a neutral class. The class is not taken from the
// configuration because the slot colours are part of the layout.
func slotClass(present bool, state string) string {
	if !present {
		return "slot-empty"
	}
	switch s := strings.ToUpper(state); s {
	case "ONLINE", "OFFLINE", "REMOVED", "FAULTED", "SPLIT", "UNAVAIL",
		"DEGRADED", "UNKNOWN", "INUSE", "AVAIL", "SUSPENDED":
		return "slot-" + strings.ToLower(s)
	}
	return "slot-unknown"
}

// deviceStates maps the names of all devices of the pools to their state.
// If a name occurs more than once the first one wins.
func deviceStates(pools []Pool) map[string]string {
	states := make(map[string]string)
	for _, p := range pools {
		p.Walk(func(dev Device, _ int) {
			if _, ok := states[dev.Name]; !ok {
				states[dev.Name] = dev.State
			}
		})
	}
	return states
}

// fillEnclosureLayout puts the device states into the slots of a layout.
func fillEnclosureLayout(l enclosureLayout, states map[string]string) enclosureView {
	v := enclosureView{Title: l.Title, Subtitle: l.Subtitle, HasRows: len(l.Rows) > 0}
	for _, names := range l.Rows {
		row := make([]enclosureSlot, 0, len(names))
		for _, name := range names {
			state, present := states[name]
			if present {
				v.Devices++
			}
			row = append(row, enclosureSlot{
				Name: name, Present: present, State: state,
				Class: slotClass(present, state),
			})
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}
