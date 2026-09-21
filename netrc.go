package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// netrcPath resolves the netrc file `go` itself would read, mirroring
// cmd/go/internal/auth.netrcPath exactly: an explicit NETRC env var wins,
// otherwise it's $HOME/.netrc, except on Windows where $HOME/_netrc is
// preferred if it exists (falling back to $HOME/.netrc otherwise).
func netrcPath() string {
	if env := os.Getenv("NETRC"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		legacy := filepath.Join(home, "_netrc")
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return filepath.Join(home, ".netrc")
}

// privatePrefixesFromNetrc parses netrc-format data for "machine" entries
// that carry a full login+password pair, mirroring cmd/go/internal/
// auth.parseNetrc field-for-field: a "machine" token resets the current
// entry, and only a triple with machine+login+password all present is used
// — `go` itself silently ignores a machine entry missing a login or
// password, and treating one as a signal here would flag configs the real
// fetch path never actually authenticates with. A "macdef" section is
// skipped without being scanned for the same reason: `go`'s own parser
// stops processing regular tokens once inside one.
func privatePrefixesFromNetrc(data []byte) []string {
	var prefixes []string
	seen := map[string]bool{}
	var machine, login, password string
	inMacro := false
	for _, line := range strings.Split(string(data), "\n") {
		if inMacro {
			if line == "" {
				inMacro = false
			}
			continue
		}

		f := strings.Fields(line)
		i := 0
		for ; i < len(f)-1; i += 2 {
			switch f[i] {
			case "machine":
				machine, login, password = f[i+1], "", ""
			case "login":
				login = f[i+1]
			case "password":
				password = f[i+1]
			case "macdef":
				inMacro = true
			}
			if machine != "" && login != "" && password != "" {
				if !isKnownPublicHost(machine) && !seen[machine] {
					seen[machine] = true
					prefixes = append(prefixes, machine)
				}
				machine, login, password = "", "", ""
			}
		}

		if i < len(f) && f[i] == "default" {
			// "There can be only one default token, and it must be after
			// all machine tokens" — go stops processing here too.
			break
		}
	}
	return prefixes
}

// goauthUsesNetrc reports whether the effective GOAUTH value (a
// semicolon-separated command list, default "netrc" per `go help goauth`)
// includes the netrc auth command. If it doesn't — e.g. GOAUTH=off, or a
// custom command list that dropped the default — `go` never reads netrc at
// all, and treating its contents as a private-auth signal would be a false
// positive rather than the real thing it's meant to catch.
func goauthUsesNetrc(goauth string) bool {
	for _, cmd := range strings.Split(goauth, ";") {
		fields := strings.Fields(cmd)
		if len(fields) > 0 && fields[0] == "netrc" {
			return true
		}
	}
	return false
}
