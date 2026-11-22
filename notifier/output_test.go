package notifier

import (
	"sync"
	"testing"
)

// fakeOutput records everything it receives.
type fakeOutput struct {
	mu   sync.Mutex
	msgs []Msg
	done bool
}

func (f *fakeOutput) Run(ch <-chan *Msg) {
	for m := range ch {
		f.mu.Lock()
		f.msgs = append(f.msgs, *m)
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.done = true
	f.mu.Unlock()
}

// filteredFake adds the optional MsgFilter interface.
type filteredFake struct {
	fakeOutput
	acceptTypes
}

func (f *fakeOutput) types() []MsgType {
	f.mu.Lock()
	defer f.mu.Unlock()
	var t []MsgType
	for _, m := range f.msgs {
		t = append(t, m.MsgType)
	}
	return t
}

func TestAddOutputDeliveryAndClose(t *testing.T) {
	n := New()
	f := &fakeOutput{}
	if err := n.AddOutput(INFO, f); err != nil {
		t.Fatal(err)
	}
	_ = n.Send(INFO, "a\nb")
	_ = n.Attach(INFO, "att")
	n.Flush()
	n.Reopen()
	<-n.Close()

	if !f.done {
		t.Error("Run did not return after Close")
	}
	want := []MsgType{MSGTYPE_MESSAGE, MSGTYPE_ATTACHMENT, MSGTYPE_FLUSH, MSGTYPE_REOPEN}
	got := f.types()
	if len(got) != len(want) {
		t.Fatalf("types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("types = %v, want %v", got, want)
		}
	}
	if f.msgs[0].Text != "a b" {
		t.Errorf("text = %q", f.msgs[0].Text)
	}
}

func TestAddOutputSeverityFilter(t *testing.T) {
	n := New()
	warn, dbg := &fakeOutput{}, &fakeOutput{}
	_ = n.AddOutput(WARNING, warn)
	_ = n.AddOutput(DEBUG, dbg)
	_ = n.Send(ERR, "err")
	_ = n.Send(WARNING, "warn")
	_ = n.Send(INFO, "info")
	_ = n.Send(DEBUG, "debug")
	_ = n.Send(SEVERITY_NONE, "dropped")
	<-n.Close()

	if len(warn.msgs) != 2 {
		t.Errorf("warning output got %d messages, want 2", len(warn.msgs))
	}
	if len(dbg.msgs) != 4 {
		t.Errorf("debug output got %d messages, want 4", len(dbg.msgs))
	}
}

func TestAddOutputMsgFilter(t *testing.T) {
	n := New()
	plain := &filteredFake{}                                   // messages and reopen only
	all := &filteredFake{acceptTypes: acceptTypes{true, true}} // everything
	_ = n.AddOutput(DEBUG, plain)
	_ = n.AddOutput(DEBUG, all)
	_ = n.Send(INFO, "m")
	_ = n.Attach(INFO, "a")
	n.Flush()
	n.Reopen()
	<-n.Close()

	if got := plain.types(); len(got) != 2 || got[0] != MSGTYPE_MESSAGE || got[1] != MSGTYPE_REOPEN {
		t.Errorf("plain types = %v", got)
	}
	if got := all.types(); len(got) != 4 {
		t.Errorf("all types = %v", got)
	}
}

func TestAddOutputErrors(t *testing.T) {
	n := New()
	defer func() { <-n.Close() }()
	if err := n.AddOutput(severity_MAX+1, &fakeOutput{}); err == nil {
		t.Error("invalid severity accepted")
	}
	if err := n.AddOutput(INFO, nil); err == nil {
		t.Error("nil output accepted")
	}
}

func TestAddLoggerCallback(t *testing.T) {
	n := New()
	var got []string
	if err := n.AddLoggerCallback(INFO, func(m *Msg) { got = append(got, m.Text) }); err != nil {
		t.Fatal(err)
	}
	_ = n.Send(INFO, "x")
	_ = n.Attach(INFO, "y")
	n.Flush() // not delivered to callbacks
	<-n.Close()
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf("got %q", got)
	}
}
