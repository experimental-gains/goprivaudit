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
// that carry a login and/or a password, mirroring the tokenization
// cmd/go/internal/auth.parseNetrc uses (a "machine" token resets the
// current entry; a "macdef" section is skipped without being scanned,
// since a real parser stops processing regular tokens once inside one) —
// but NOT parseNetrc's own completeness rule, which requires machine,
// login, AND password all present before using an entry. That rule is
// right for what parseNetrc itself feeds: GOAUTH=netrc, `go`'s own HTTP
// client credential source (`go help goauth`). It is wrong for what this
// function feeds instead — the netrc consultation `git`, invoked as a
// subprocess for a direct VCS fetch, always performs on its own via
// libcurl's CURLOPT_NETRC, per this package's main.go doc comment. Verified
// live with real `git` (and, underneath it, the same libcurl netrc reader
// curl itself uses) against a Basic-Auth-challenging HTTP server: a netrc
// entry with a "login" line but no "password" line at all sent
// "Authorization: Basic <login>:<empty>" on retry after the 401, and one
// with a "password" line but no "login" sent "Basic <empty>:<password>" —
// both real, successful authentications, neither requiring the other field.
// Only a "machine" entry with neither login nor password set at all (a
// bare "machine host" with nothing else) produced no Authorization header
// and made a real `git ls-remote` fail outright ("could not read
// Username"). So the real completeness bar for a git-subprocess-authenticated
// fetch is machine set AND (login set OR password set) — requiring both,
// as the pre-fix code did (mirroring parseNetrc verbatim), silently missed
// a real sumdb-leak signal for the common slip of a netrc entry with one of
// the two fields left unset.
//
// Because "login set OR password set" can't tell a complete entry from an
// incomplete one the moment a single field arrives the way parseNetrc's
// "wait for all three" rule could, this can't commit eagerly inline the way
// the pre-fix code (and parseNetrc itself) did — a "login" line might still
// be followed by its own "password" line before the entry is actually
// done. Instead, the pending entry is only finalized (commit) when it's
// unambiguously done: right before a new "machine" token starts the next
// entry, or at end of input/on the "default" stop condition.
func privatePrefixesFromNetrc(data []byte) []string {
	var prefixes []string
	seen := map[string]bool{}
	var machine, login, password string
	inMacro := false

	commit := func() {
		if machine == "" || (login == "" && password == "") {
			return
		}
		if !isKnownPublicHost(machine) && !seen[machine] {
			seen[machine] = true
			prefixes = append(prefixes, machine)
		}
	}

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
				commit()
				machine, login, password = f[i+1], "", ""
			case "login":
				login = f[i+1]
			case "password":
				password = f[i+1]
			case "macdef":
				inMacro = true
			}
		}

		if i < len(f) && f[i] == "default" {
			// "There can be only one default token, and it must be after
			// all machine tokens" — go stops processing here too.
			break
		}
	}
	commit()
	return prefixes
}
