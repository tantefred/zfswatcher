//
// output.go
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

import "errors"

// Output is a notification channel (log file, syslog, e-mail, ...).
//
// Run is started by the Notifier in its own goroutine and receives all
// messages of the output on ch, in order. It must return once ch has been
// closed, after finishing any pending work (for example sending a last
// e-mail); Notifier.Close waits for that. The message types are:
//
//   - MSGTYPE_MESSAGE and MSGTYPE_ATTACHMENT: deliver the message.
//   - MSGTYPE_FLUSH: deliver whatever was buffered (see MsgFilter).
//   - MSGTYPE_REOPEN: reopen files and connections (log rotation).
//
// The severity filter is applied by the Notifier before delivery, so an
// Output does not need to look at Severity (except to display it).
type Output interface {
	Run(ch <-chan *Msg)
}

// MsgFilter can optionally be implemented by an Output to tell the
// Notifier which message types it wants. An Output without it receives
// all message types.
type MsgFilter interface {
	Accepts(t MsgType) bool
}

// AddOutput registers o and starts it as a goroutine. Messages with a
// severity at least as important as s (and of a type accepted by o) are
// delivered to it. Outputs should be added before messages are sent.
func (n *Notifier) AddOutput(s Severity, o Output) error {
	if s < severity_MIN || s > severity_MAX {
		return errors.New(`invalid "severity"`)
	}
	if o == nil {
		return errors.New(`"output" not defined`)
	}
	ch := make(chan *Msg, chan_SIZE)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		o.Run(ch)
	}()
	out := notifyOutput{severity: s, ch: ch}
	if f, ok := o.(MsgFilter); ok {
		out.filter = f
	}
	n.out = append(n.out, out)
	return nil
}

// acceptTypes is a helper for MsgFilter implementations.
type acceptTypes struct{ attachment, flush bool }

func (a acceptTypes) Accepts(t MsgType) bool {
	switch t {
	case MSGTYPE_ATTACHMENT:
		return a.attachment
	case MSGTYPE_FLUSH:
		return a.flush
	}
	return true
}

// eof
