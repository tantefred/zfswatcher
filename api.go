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

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// The JSON API, version 1: read only, GET (and HEAD) requests below
// "<rootdir>/api/v1/". Sizes are bytes, names are snake_case, errors are
// {"error": "..."}. Authentication is the same as for the web pages (Basic
// or Bearer token), see requireRoleWith.

// apiError writes a JSON error document. It is also the errorRenderer of
// the API, so 401 and 403 are JSON as well.
func apiError(w http.ResponseWriter, _ *http.Request, code int, msg string) {
	apiWriteJSON(w, nil, code, map[string]string{"error": msg})
}

// apiWriteJSON writes v as the JSON body with the given status. The body is
// left out for HEAD requests.
func apiWriteJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func apiHandler(min Role, h http.HandlerFunc) http.HandlerFunc {
	return requireRoleWith(newAuthenticator(), apiError, min, h)
}

func apiInfo(w http.ResponseWriter, r *http.Request) {
	apiWriteJSON(w, r, http.StatusOK, hostInfo())
}

func apiPools(w http.ResponseWriter, r *http.Request) {
	apiWriteJSON(w, r, http.StatusOK, struct {
		Pools []Pool `json:"pools"`
	}{snapshotPools()})
}

func apiPool(w http.ResponseWriter, r *http.Request) {
	p, ok := snapshotPool(r.PathValue("name"))
	if !ok {
		apiError(w, r, http.StatusNotFound, "no such pool")
		return
	}
	apiWriteJSON(w, r, http.StatusOK, p)
}

func apiUsage(w http.ResponseWriter, r *http.Request) {
	apiWriteJSON(w, r, http.StatusOK, struct {
		Usage []Usage `json:"usage"`
	}{usageList(snapshotUsage())})
}

func apiEvents(w http.ResponseWriter, r *http.Request) {
	events := snapshotEvents()
	if v, ok := r.URL.Query()["limit"]; ok {
		n, err := strconv.Atoi(v[0])
		if err != nil || n < 1 {
			apiError(w, r, http.StatusBadRequest, "limit must be a positive number")
			return
		}
		if n < len(events) {
			events = events[len(events)-n:]
		}
	}
	apiWriteJSON(w, r, http.StatusOK, struct {
		Events []Event `json:"events"`
	}{events})
}

// apiFallback answers everything below "<rootdir>/api/" which is not an
// endpoint (this includes endpoints requested with the wrong method, which
// the mux would otherwise answer with a text/plain 405).
func apiFallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, r, http.StatusMethodNotAllowed, "405 Method Not Allowed")
		return
	}
	apiError(w, r, http.StatusNotFound, "404 Not Found")
}

// registerAPI registers the handlers below "<rootdir>/api/".
func registerAPI(mux *http.ServeMux) {
	root := cfg.Www.Rootdir
	mux.HandleFunc("GET "+root+"/api/v1/info", apiHandler(RoleViewer, apiInfo))
	mux.HandleFunc("GET "+root+"/api/v1/pools", apiHandler(RoleViewer, apiPools))
	mux.HandleFunc("GET "+root+"/api/v1/pools/{name}", apiHandler(RoleViewer, apiPool))
	mux.HandleFunc("GET "+root+"/api/v1/usage", apiHandler(RoleViewer, apiUsage))
	mux.HandleFunc("GET "+root+"/api/v1/events", apiHandler(RoleOperator, apiEvents))
	mux.HandleFunc(root+"/api/", apiHandler(RoleViewer, apiFallback))
}

// eof
