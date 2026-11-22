package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestSlotNames(t *testing.T) {
	if got := slotNames("1", 1, 3); !reflect.DeepEqual(got, []string{"1-1", "1-2", "1-3"}) {
		t.Errorf("up: %v", got)
	}
	if got := slotNames("2", 3, 1); !reflect.DeepEqual(got, []string{"2-3", "2-2", "2-1"}) {
		t.Errorf("down: %v", got)
	}
	if got := slotNames("2", 5, 5); !reflect.DeepEqual(got, []string{"2-5"}) {
		t.Errorf("single: %v", got)
	}
}

func TestEnclosureLayouts(t *testing.T) {
	goldenSetup(t)
	if l := enclosureLayouts(); len(l) != 0 {
		t.Errorf("no model enabled: %v", l)
	}

	cfg.Chassis.Chassis45drives45 = true
	l := enclosureLayouts()
	if len(l) != 1 || l[0].Title != "45Drives S45 Enclosure" || l[0].Subtitle != "Front of unit" || len(l[0].Rows) != 3 {
		t.Fatalf("S45: %+v", l)
	}
	// 45 distinct slots: 1-1..1-24 and 2-1..2-21, in the order of the front
	seen := map[string]bool{}
	for _, row := range l[0].Rows {
		if len(row) != 15 {
			t.Errorf("row %v has %d slots", row, len(row))
		}
		for _, n := range row {
			if seen[n] {
				t.Errorf("slot %s twice", n)
			}
			seen[n] = true
		}
	}
	if len(seen) != 45 || !seen["1-24"] || !seen["2-21"] || seen["1-25"] || seen["2-22"] {
		t.Errorf("slots: %d", len(seen))
	}
	if r := l[0].Rows[1]; r[0] != "2-6" || r[5] != "2-1" || r[6] != "1-24" || r[14] != "1-16" {
		t.Errorf("second row: %v", r)
	}

	cfg.Chassis.Chassis45drives45 = false
	cfg.Chassis.Chassis45drives15 = true
	cfg.Chassis.Chassis45drives30 = true
	cfg.Chassis.Chassis45drives45l = true
	cfg.Chassis.Chassis45drives60 = true
	var titles []string
	for _, x := range enclosureLayouts() {
		titles = append(titles, x.Title)
		if len(x.Rows) != 0 {
			t.Errorf("%s: unexpected slot rows", x.Title)
		}
	}
	if want := []string{"45Drives AV15", "45Drives Q30", "45Drives S45 lite", "45Drives XL60"}; !reflect.DeepEqual(titles, want) {
		t.Errorf("titles %v", titles)
	}
}

func TestSlotClass(t *testing.T) {
	for _, c := range []struct {
		present bool
		state   string
		want    string
	}{
		{true, "ONLINE", "slot-online"}, {true, "faulted", "slot-faulted"}, {true, "INUSE", "slot-inuse"},
		{true, "", "slot-unknown"}, {true, "x y\"", "slot-unknown"}, {false, "ONLINE", "slot-empty"},
	} {
		if got := slotClass(c.present, c.state); got != c.want {
			t.Errorf("slotClass(%v, %q) = %s, want %s", c.present, c.state, got, c.want)
		}
	}
}

func TestFillEnclosureLayout(t *testing.T) {
	pools, err := parseZpoolStatus(goldenEnclosure)
	if err != nil {
		t.Fatal(err)
	}
	var ps []Pool
	for _, p := range pools {
		ps = append(ps, poolFromParsed(p))
	}
	states := deviceStates(ps)
	if states["1-2"] != "FAULTED" || states["sda"] != "ONLINE" || states["raidz1-0"] != "DEGRADED" {
		t.Errorf("states: %v", states)
	}

	l := enclosureLayout{Title: "t", Rows: [][]string{{"1-1", "1-2", "1-4"}, {"2-1", "sda"}}}
	v := fillEnclosureLayout(l, states)
	if !v.HasRows || v.Devices != 4 || len(v.Rows) != 2 {
		t.Fatalf("view: %+v", v)
	}
	want := [][]enclosureSlot{
		{{"1-1", true, "ONLINE", "slot-online"}, {"1-2", true, "FAULTED", "slot-faulted"}, {"1-4", false, "", "slot-empty"}},
		{{"2-1", true, "DEGRADED", "slot-degraded"}, {"sda", true, "ONLINE", "slot-online"}},
	}
	if !reflect.DeepEqual(v.Rows, want) {
		t.Errorf("rows: %+v", v.Rows)
	}
	if v := fillEnclosureLayout(enclosureLayout{Title: "x"}, states); v.HasRows || len(v.Rows) != 0 {
		t.Errorf("layout without rows: %+v", v)
	}
}

// The 45drives30 model has no slot arrangement yet: the page shows the name
// and a note, with all other models of the section enabled together.
func TestEnclosurePageLayouts(t *testing.T) {
	goldenSetup(t)
	cfg.Chassis.Enable = true
	cfg.Chassis.Chassis45drives30 = true
	pools, err := parseZpoolStatus(goldenEnclosure)
	if err != nil {
		t.Fatal(err)
	}
	goldenSetState(t, pools, nil)
	code, body := render(enclosureHandler, "/zw/enclosure/")
	if code != 200 || !strings.Contains(body, "45Drives Q30") || !strings.Contains(body, "No slot layout is available") ||
		strings.Contains(body, "enclosure-slot") {
		t.Errorf("Q30 page: %d\n%s", code, body)
	}

	cfg.Chassis.Chassis45drives30 = false
	_, body = render(enclosureHandler, "/zw/enclosure/")
	if !strings.Contains(body, "No chassis model is enabled") {
		t.Error("missing hint without a model")
	}

	cfg.Chassis.Chassis45drives45 = true
	_, body = render(enclosureHandler, "/zw/enclosure/")
	if n := strings.Count(body, `class="enclosure-slot `); n != 45 {
		t.Errorf("S45 page has %d slots, want 45", n)
	}
	for _, want := range []string{`class="enclosure-slot slot-online" title="1-3: ONLINE"`,
		`class="enclosure-slot slot-faulted" title="1-2: FAULTED"`,
		`class="enclosure-slot slot-degraded" title="2-1: DEGRADED"`,
		`class="enclosure-slot slot-empty" title="2-21: empty"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}
