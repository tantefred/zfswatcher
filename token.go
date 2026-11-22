//
// token.go
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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// tokenRandomBytes is the amount of randomness in a generated API token.
const tokenRandomBytes = 32

// newToken returns a new API token read from the random source r.
func newToken(r io.Reader) (string, error) {
	b := make([]byte, tokenRandomBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// wwwGenerateToken implements "zfswatcher -T": it prints a new API token
// once, together with the configuration line holding its hash.
func wwwGenerateToken(out, errOut io.Writer) int {
	return generateToken(rand.Reader, out, errOut)
}

func generateToken(random io.Reader, out, errOut io.Writer) int {
	token, err := newToken(random)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "Error:", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "API token (it is shown only once, store it now):\n\n%s\n\n", token)
	_, _ = fmt.Fprintf(out, "Put this line into an [apitoken \"name\"] section of the configuration file:\n\nhash = %s\n", hashToken(token))
	return 0
}

// eof
