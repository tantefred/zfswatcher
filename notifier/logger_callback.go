//
// logger_callback.go
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

package notifier

// CallbackOutput calls a function for every message and attachment.
type CallbackOutput struct {
	acceptTypes
	f func(*Msg)
}

// NewCallbackOutput returns an Output which calls f for each message. f
// runs in the output's goroutine.
func NewCallbackOutput(f func(*Msg)) *CallbackOutput {
	return &CallbackOutput{acceptTypes: acceptTypes{attachment: true}, f: f}
}

// Run implements Output.
func (o *CallbackOutput) Run(ch <-chan *Msg) {
	for m := range ch {
		o.f(m)
	}
}

// AddLoggerCallback adds an output which calls f for each message.
func (n *Notifier) AddLoggerCallback(s Severity, f func(*Msg)) error {
	return n.AddOutput(s, NewCallbackOutput(f))
}

// eof
