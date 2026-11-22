//
// logger_file.go
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

import (
	"errors"
	"os"
	"strings"
)

// logFileMode is used when a log file is created (before the umask).
const logFileMode = 0o640

// FileOutput appends messages and attachments to a log file. It reopens the
// file on MSGTYPE_REOPEN (log rotation).
type FileOutput struct {
	acceptTypes
	filename string
}

// NewFileOutput returns an Output which appends to the file filename.
func NewFileOutput(filename string) *FileOutput {
	return &FileOutput{acceptTypes: acceptTypes{attachment: true}, filename: filename}
}

// Run implements Output.
func (o *FileOutput) Run(ch <-chan *Msg) {
	filename := o.filename
	var fileopen bool

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, logFileMode) //nolint:gosec // path from admin config

	if err == nil {
		fileopen = true
	} else {
		checkInternalError("error opening log file", err)
		fileopen = false
	}

	for m := range ch {
		switch m.MsgType {
		case MSGTYPE_MESSAGE:
			if !fileopen {
				continue
			}
			_, err = f.WriteString(m.String() + "\n")
			checkInternalError("error writing log file", err)
		case MSGTYPE_ATTACHMENT:
			if !fileopen {
				continue
			}
			_, err = f.WriteString(">" +
				strings.ReplaceAll(strings.TrimRight(m.Text, "\n"), "\n", "\n>") +
				"\n")
			checkInternalError("error writing log file", err)
		case MSGTYPE_REOPEN:
			if fileopen {
				err = f.Close()
				checkInternalError("error closing log file", err)
			}
			f, err = os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, logFileMode) //nolint:gosec // path from admin config
			if err == nil {
				fileopen = true
			} else {
				checkInternalError("error re-opening log file", err)
				fileopen = false
			}
		}
	}
	if fileopen {
		err = f.Close()
		checkInternalError("error closing log file", err)
	}
}

// AddLoggerFile adds a file based logging output.
// AddLoggerFile adds a file logging output.
func (n *Notifier) AddLoggerFile(s Severity, file string) error {
	switch {
	case s < severity_MIN || s > severity_MAX:
		return errors.New(`invalid "severity"`)
	case file == "":
		return errors.New(`"file" not defined`)
	}
	return n.AddOutput(s, NewFileOutput(file))
}
