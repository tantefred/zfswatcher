//
// setup.go
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

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/tantefred/zfswatcher/notifier"
	"gopkg.in/gcfg.v1"
)

// Config file processing.

// Default configuration file path.
const CFGFILE = "/etc/zfs/zfswatcher.conf"

// Global for configuration file.
var cfgFile string

// Points to the global current configuration.
var cfg *cfgType

// Holder for global configuration information. Filled in by "gcfg".
type cfgType struct {
	Main struct {
		Zpoolstatusrefresh int
		Commandtimeout     int
		Zpoolstatuscmd     string
		Zfslistrefresh     int
		Zfslistcmd         string
		Zfslistusagecmd    string
		Zpooliostatcmd     string // obsolete, only accepted so old configs still load
		Pidfile            string
		Statefile          string
	}
	Severity struct {
		Poolstatemap             stateToSeverityMap
		Pooladded                notifier.Severity
		Poolremoved              notifier.Severity
		Poolstatuschanged        notifier.Severity
		Poolstatuscleared        notifier.Severity
		Poolerrorschanged        notifier.Severity
		Devstatemap              stateToSeverityMap
		Devadded                 notifier.Severity
		Devremoved               notifier.Severity
		Devreaderrorsincreased   notifier.Severity
		Devwriteerrorsincreased  notifier.Severity
		Devcksumerrorsincreased  notifier.Severity
		Devadditionalinfochanged notifier.Severity
		Devadditionalinfocleared notifier.Severity
		Usedspace                percentageToSeverityMap
		Loginlockout             notifier.Severity
	}
	Leds struct {
		Enable      bool
		Ledctlcmd   string
		Devstatemap devStateToIbpiMap
	}
	Logfile map[string]*struct {
		Enable bool
		Level  notifier.Severity
		File   string
	}
	Syslog map[string]*struct {
		Enable   bool
		Level    notifier.Severity
		Server   string
		Facility notifier.SyslogFacility
	}
	Email map[string]*struct {
		Enable   bool
		Level    notifier.Severity
		Server   string
		Username string
		Password string
		From     string
		To       string
		Subject  string
		Throttle int64
	}
	Www struct {
		Enable               bool
		Level                notifier.Severity
		Logbuffer            int
		Refresh              int
		Bind                 string
		Certfile             string
		Keyfile              string
		Templatedir          string
		Resourcedir          string
		Rootdir              string
		Trustedproxies       string
		Loginfailures        int
		Loginwindow          int
		Loginlockout         int
		Severitycssclassmap  severityToWwwClassMap
		Poolstatecssclassmap stringToStringMap
		Devstatecssclassmap  stringToStringMap
		Usedstatecssclassmap severityToWwwClassMap
	}
	Wwwuser  map[string]*wwwUserCfg
	Apitoken map[string]*apiTokenCfg
	Chassis  struct {
		Enable             bool
		Chassis45drives15  bool
		Chassis45drives30  bool
		Chassis45drives45l bool
		Chassis45drives45  bool
		Chassis45drives60  bool
	}
}

type stringToStringMap map[string]string

// Implement fmt.Scanner interface.
func (smapp *stringToStringMap) Scan(state fmt.ScanState, verb rune) error {
	smap := make(stringToStringMap)
	for {
		tok, err := state.Token(true, nil)
		if err != nil {
			return err
		}
		if len(tok) == 0 { // end of string
			break
		}
		str := string(tok)
		pair := strings.SplitN(str, ":", 2)
		if len(pair) != 2 {
			return errors.New(`invalid map entry "` + str + `"`)
		}
		smap[pair[0]] = pair[1]
	}
	*smapp = smap
	return nil
}

type stateToSeverityMap map[string]notifier.Severity

// Implement fmt.Scanner interface on top of two other fmt.Scanner interfaces.
func (ssmapp *stateToSeverityMap) Scan(state fmt.ScanState, verb rune) error {
	smap := stringToStringMap{}
	err := smap.Scan(state, verb)
	if err != nil {
		return err
	}
	ssmap := make(stateToSeverityMap)
	for a, b := range smap {
		var severity notifier.Severity
		if n, err := fmt.Sscan(b, &severity); n != 1 {
			return err
		}
		ssmap[a] = severity
	}
	*ssmapp = ssmap
	return nil
}

// Finds an entry in stateToSeverityMap, returns INFO as default.
func (ssmap stateToSeverityMap) getSeverity(str string) notifier.Severity {
	sev, ok := ssmap[str]
	if !ok {
		sev = notifier.INFO
	}
	return sev
}

type percentageToSeverityMap map[int]notifier.Severity

// Implement fmt.Scanner interface.
func (psmapp *percentageToSeverityMap) Scan(state fmt.ScanState, verb rune) error {
	ssmap := stateToSeverityMap{}
	err := ssmap.Scan(state, verb)
	if err != nil {
		return err
	}
	psmap := make(percentageToSeverityMap)
	for a, b := range ssmap {
		if len(a) < 2 || a[len(a)-1] != '%' || a[0] == '-' {
			return errors.New(`invalid percentage entry "` + a + `"`)
		}
		var percentage int
		if n, err := fmt.Sscan(a[:len(a)-1], &percentage); n != 1 {
			return err
		}
		psmap[percentage] = b
	}
	*psmapp = psmap
	return nil
}

// Get severity level based on used percentage level.
// Returns notifier.SEVERITY_NONE and ok = false if the percentage
// does not reach any listed level.
func (psmapp *percentageToSeverityMap) GetByPercentage(used int) (severity notifier.Severity, ok bool) {
	maxlevel := -1
	for level := range *psmapp {
		if used >= level && level > maxlevel {
			maxlevel = level
		}
	}
	if maxlevel != -1 {
		return (*psmapp)[maxlevel], true
	}
	return notifier.SEVERITY_NONE, false
}

// Check for and notify about configuration error.
func checkCfgErr(cfgfile, sect, prof, param string, err error, errorSeen *bool) {
	if err == nil {
		return
	}
	var sectprof string
	switch {
	case sect != "" && prof != "":
		sectprof = ` [` + sect + ` "` + prof + `"]`
	case sect != "":
		sectprof = ` [` + sect + `]`
	}
	if param != "" {
		param = ` parameter "` + param + `"`
	}
	fmt.Fprintf(os.Stderr, "%s: Error in %s%s%s: %s\n", os.Args[0], cfgfile, sectprof, param, err)
	if notify != nil {
		notify.Printf(notifier.CRIT, "Error in %s%s%s: %s", cfgfile, sectprof, param, err)
	}
	*errorSeen = true
}

// Read configuration.
// Default listening address of the web interface: an unprivileged port on the
// loopback interface, meant for a reverse proxy.
const defaultWwwBind = "127.0.0.1:8081"

// Allowed range of the refresh intervals in seconds. The upper limit also
// keeps the conversion to time.Duration far away from overflowing.
const (
	minRefreshSeconds = 1
	maxRefreshSeconds = 24 * 60 * 60
)

// Allowed range of the command timeout in seconds.
const (
	minCommandTimeoutSeconds = 1
	maxCommandTimeoutSeconds = 3600
)

// checkCommandTimeout validates a command timeout given in seconds.
func checkCommandTimeout(sec int) error {
	if sec < minCommandTimeoutSeconds || sec > maxCommandTimeoutSeconds {
		return fmt.Errorf("value %d out of range, must be between %d and %d seconds",
			sec, minCommandTimeoutSeconds, maxCommandTimeoutSeconds)
	}
	return nil
}

// Allowed range of the web page refresh in seconds; 0 switches it off.
const (
	minWwwRefreshSeconds = 2
	maxWwwRefreshSeconds = 3600
)

// defaultWwwRefresh is the default refresh interval of the web pages.
const defaultWwwRefresh = 10

// checkWwwRefresh validates the automatic refresh interval of the web pages.
func checkWwwRefresh(sec int) error {
	if sec != 0 && (sec < minWwwRefreshSeconds || sec > maxWwwRefreshSeconds) {
		return fmt.Errorf("value %d out of range, must be 0 (off) or between %d and %d seconds",
			sec, minWwwRefreshSeconds, maxWwwRefreshSeconds)
	}
	return nil
}

// checkRefresh validates a refresh interval given in seconds.
func checkRefresh(sec int) error {
	if sec < minRefreshSeconds || sec > maxRefreshSeconds {
		return fmt.Errorf("value %d out of range, must be between %d and %d seconds",
			sec, minRefreshSeconds, maxRefreshSeconds)
	}
	return nil
}

// checkAuthCfg validates the roles of the web users and the roles and hashes
// of the API tokens.
func checkAuthCfg(c *cfgType, errorSeen *bool) {
	for _, name := range sortedKeys(c.Wwwuser) {
		_, err := configRole(c.Wwwuser[name].Role)
		checkCfgErr(cfgFile, "wwwuser", name, "role", err, errorSeen)
	}
	for _, name := range sortedKeys(c.Apitoken) {
		t := c.Apitoken[name]
		_, err := configRole(t.Role)
		checkCfgErr(cfgFile, "apitoken", name, "role", err, errorSeen)
		if t.Enable || t.Hash != "" {
			_, err = parseTokenHash(t.Hash)
			checkCfgErr(cfgFile, "apitoken", name, "hash", err, errorSeen)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func getCfg() *cfgType {
	var c cfgType
	var errorSeen bool

	// set up some sane default configuration settings:
	c.Main.Zpoolstatusrefresh = 10
	c.Main.Commandtimeout = int(commandTimeout / time.Second)
	c.Main.Zpoolstatuscmd = "zpool status"
	c.Main.Zfslistrefresh = 60
	c.Main.Zfslistcmd = "zfs list -H -o name,avail,used,logicalused,usedsnap,usedds,usedrefreserv,usedchild,refer,mountpoint,compressratio -d 0"
	c.Main.Zfslistusagecmd = "zfs list -H -o name,avail,used,logicalused,usedsnap,usedds,usedrefreserv,usedchild,refer,mountpoint,compressratio -r -t all"
	c.Main.Statefile = defaultStatefile
	c.Leds.Ledctlcmd = "ledctl"
	// Without this the web server would listen on port 80.
	c.Www.Bind = defaultWwwBind
	c.Www.Refresh = defaultWwwRefresh
	c.Www.Loginfailures = defaultLoginFailures
	c.Www.Loginwindow = defaultLoginWindow
	c.Www.Loginlockout = defaultLoginLockout
	c.Severity.Loginlockout = notifier.WARNING
	c.Severity.Pooladded = notifier.INFO
	c.Severity.Poolremoved = notifier.INFO
	c.Severity.Poolstatuschanged = notifier.INFO
	c.Severity.Poolstatuscleared = notifier.INFO
	c.Severity.Poolerrorschanged = notifier.INFO
	c.Severity.Devadded = notifier.INFO
	c.Severity.Devremoved = notifier.INFO
	c.Severity.Devreaderrorsincreased = notifier.INFO
	c.Severity.Devwriteerrorsincreased = notifier.INFO
	c.Severity.Devcksumerrorsincreased = notifier.INFO
	c.Severity.Devadditionalinfochanged = notifier.INFO
	c.Severity.Devadditionalinfocleared = notifier.INFO

	// read configuration settings:
	err := gcfg.ReadFileInto(&c, cfgFile)
	checkCfgErr(cfgFile, "", "", "", err, &errorSeen)
	checkCfgErr(cfgFile, "main", "", "zpoolstatusrefresh", checkRefresh(c.Main.Zpoolstatusrefresh), &errorSeen)
	checkCfgErr(cfgFile, "main", "", "zfslistrefresh", checkRefresh(c.Main.Zfslistrefresh), &errorSeen)
	_, err = parseTrustedProxies(c.Www.Trustedproxies)
	checkCfgErr(cfgFile, "www", "", "trustedproxies", err, &errorSeen)
	checkCfgErr(cfgFile, "main", "", "commandtimeout", checkCommandTimeout(c.Main.Commandtimeout), &errorSeen)
	checkCfgErr(cfgFile, "www", "", "refresh", checkWwwRefresh(c.Www.Refresh), &errorSeen)
	checkCfgErr(cfgFile, "www", "", "loginfailures", checkLoginBackoff(c.Www.Loginfailures, c.Www.Loginwindow, c.Www.Loginlockout), &errorSeen)
	checkAuthCfg(&c, &errorSeen)
	translateLegacyCSSClasses(&c)

	if errorSeen {
		return nil
	}
	return &c
}

// Setup logging.
func setupLog(c *cfgType) *notifier.Notifier {
	var errorSeen bool

	n := notifier.New()
	if optDebug {
		_ = n.AddLoggerStdout(notifier.DEBUG) // fails only for an invalid severity
	}

	for prof, s := range c.Logfile {
		if s.Enable {
			err := n.AddLoggerFile(s.Level, s.File)
			checkCfgErr(cfgFile, "logfile", prof, "", err, &errorSeen)
		}
	}
	for prof, s := range c.Syslog {
		if s.Enable {
			err := n.AddLoggerSyslog(s.Level, s.Server, s.Facility)
			checkCfgErr(cfgFile, "syslog", prof, "", err, &errorSeen)
		}
	}
	for prof, s := range c.Email {
		if s.Enable {
			err := n.AddLoggerEmailSMTP(s.Level,
				s.Server, s.Username, s.Password, s.From, s.To, s.Subject,
				time.Second*time.Duration(s.Throttle))
			checkCfgErr(cfgFile, "email", prof, "", err, &errorSeen)
		}
	}
	if c.Www.Enable && c.Www.Logbuffer > 0 {
		err := n.AddLoggerCallback(c.Www.Level, wwwLogReceiver)
		checkCfgErr(cfgFile, "www", "", "", err, &errorSeen)
	}
	return n
}

// Initial setup when the program starts.
func setup() {
	// ensure that zpool/zfs commands do not use localized messages:
	if err := os.Setenv("LC_ALL", "C"); err != nil {
		fmt.Fprintf(os.Stderr, "%s: cannot set LC_ALL: %s\n", os.Args[0], err)
	}

	// command line flags:
	pflag.StringVarP(&cfgFile, "conf", "c", CFGFILE, "configuration file path")
	pflag.BoolVarP(&optDebug, "debug", "d", false, "debug mode: messages also to stdout, diagnostics at debug level to stderr")
	optHashPassword := pflag.BoolP("passwordhash", "P", false, "read a password and print its bcrypt hash")
	optGenerateToken := pflag.BoolP("generate-token", "T", false, "generate an API token and print it with its hash")
	optTest := pflag.BoolP("test", "t", false, "test configuration and exit")
	optVersion := pflag.BoolP("version", "v", false, "print version information and exit")

	pflag.Parse()

	if pflag.NArg() > 0 {
		pflag.Usage()
		os.Exit(2)
	}
	if *optVersion {
		version()
		os.Exit(0)
	}
	if *optHashPassword {
		os.Exit(wwwHashPassword(os.Stdin, os.Stdout, os.Stderr))
	}

	if *optGenerateToken {
		os.Exit(wwwGenerateToken(os.Stdout, os.Stderr))
	}

	// initialize logging & notification:

	if *optTest {
		optDebug = true
	}

	setupSlog(optDebug)

	cfg = getCfg()
	if cfg == nil {
		os.Exit(2)
	}
	// Applied at startup only: running goroutines read the value.
	commandTimeout = time.Duration(cfg.Main.Commandtimeout) * time.Second
	notify = setupLog(cfg)
	warnObsoleteOptions(cfg)

	if *optTest {
		notifyCloseC := notify.Close()
		select { // wait max 1 second for loggers to finish
		case <-notifyCloseC:
		case <-time.After(time.Second):
		}
		os.Exit(0)
	}
}

// warnObsoleteOptions logs a warning for every removed option that is still
// set in the configuration. The options are ignored.
func warnObsoleteOptions(c *cfgType) {
	if c.Main.Zpooliostatcmd != "" {
		notify.Print(notifier.WARNING, "option \"zpooliostatcmd\" was removed and is ignored")
	}
}

// Reconfigure event (usually SIGHUP).
// persisterPath returns the state file used since startup ("" if disabled).
func persisterPath() string {
	if persister == nil {
		return ""
	}
	return persister.path
}

func reconfigure() {
	newcfg := getCfg()
	if newcfg == nil {
		notify.Print(notifier.CRIT, "invalid configuration ", cfgFile, ", keeping old configuration")
		return
	}
	if persisterPath() != newcfg.Main.Statefile {
		notify.Print(notifier.WARNING, "statefile change needs a restart (still using \"", persisterPath(), "\")")
	}
	if time.Duration(newcfg.Main.Commandtimeout)*time.Second != commandTimeout {
		notify.Print(notifier.WARNING, "commandtimeout change needs a restart")
	}
	warnObsoleteOptions(newcfg)
	cfg = newcfg
	webAuthCache.flush()
	newNotify := setupLog(cfg)
	if newNotify == nil {
		notify.Print(notifier.CRIT, "error setting up logs, keeping old logging configuration")
	}
	oldnotify := notify
	notify = newNotify
	oldnotify.Close()
	notify.Print(notifier.INFO, "configuration reloaded")
	// XXX restart web
}

// eof
