//
// webcss.go
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
	"strings"
)

// The web interface uses Bootstrap 5. Configuration files written for the
// Bootstrap 2/3 templates (the example configuration up to version 0.7) name
// classes which no longer exist; they are translated when the configuration
// is loaded, so that old files keep working unchanged.

// legacyCSSClasses maps the Bootstrap 2/3 class names used in the css class
// maps to their Bootstrap 5 equivalent.
var legacyCSSClasses = map[string]string{
	"text-error":           "text-danger",
	"text-muted":           "text-body-secondary",
	"progress-bar-success": "bg-success",
	"progress-bar-info":    "bg-info",
	"progress-bar-warning": "bg-warning",
	"progress-bar-danger":  "bg-danger",
	"bar-success":          "bg-success",
	"bar-info":             "bg-info",
	"bar-warning":          "bg-warning",
	"bar-danger":           "bg-danger",
}

// legacyRowClasses are the table row classes of Bootstrap 2/3 ("error",
// "warning", ...), which are translated for the log lines only: for the other
// maps a plain "warning" would be ambiguous.
var legacyRowClasses = map[string]string{
	"error":   "table-danger",
	"danger":  "table-danger",
	"warning": "table-warning",
	"info":    "table-info",
	"success": "table-success",
}

// translateCSSClass translates the space separated class names of s. Names
// without an entry are kept. With rows set the table row classes are
// translated as well.
func translateCSSClass(s string, rows bool) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if n, ok := legacyCSSClasses[f]; ok {
			fields[i] = n
		} else if n, ok := legacyRowClasses[f]; ok && rows {
			fields[i] = n
		}
	}
	return strings.Join(fields, " ")
}

// translateCSSMap returns a copy of m with translated class names.
func translateCSSMap(m stringToStringMap, rows bool) stringToStringMap {
	if m == nil {
		return nil
	}
	res := make(stringToStringMap, len(m))
	for k, v := range m {
		res[k] = translateCSSClass(v, rows)
	}
	return res
}

// translateSeverityCSSMap is translateCSSMap for a map keyed by severity.
func translateSeverityCSSMap(m severityToWwwClassMap, rows bool) severityToWwwClassMap {
	if m == nil {
		return nil
	}
	res := make(severityToWwwClassMap, len(m))
	for k, v := range m {
		res[k] = translateCSSClass(v, rows)
	}
	return res
}

// translateLegacyCSSClasses translates the class maps of the configuration
// to the Bootstrap 5 names.
func translateLegacyCSSClasses(c *cfgType) {
	c.Www.Severitycssclassmap = translateSeverityCSSMap(c.Www.Severitycssclassmap, true)
	c.Www.Poolstatecssclassmap = translateCSSMap(c.Www.Poolstatecssclassmap, false)
	c.Www.Devstatecssclassmap = translateCSSMap(c.Www.Devstatecssclassmap, false)
	c.Www.Usedstatecssclassmap = translateSeverityCSSMap(c.Www.Usedstatecssclassmap, false)
}
