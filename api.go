//
// api.go
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

import "net/http"

// registerAPI registers the handlers below "<rootdir>/api/". There are no API
// endpoints yet; the placeholder makes sure that unknown API paths are not
// answered by the dashboard. Authentication (Basic or Bearer token) is
// already in place for this tree.
func registerAPI(mux *http.ServeMux) {
	mux.HandleFunc(cfg.Www.Rootdir+"/api/", requireRole(RoleViewer, http.NotFound))
}

// eof
