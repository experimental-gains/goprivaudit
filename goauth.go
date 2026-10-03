package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// goAuthConfigError reports the error real cmd/go's own GOAUTH parsing
// (runGoAuth, cmd/go/internal/auth/auth.go) Fatals with for raw before the
// very *first* HTTPS request of the entire process — cmd/go/internal/web's
// fetch helper calls auth.AddCredentials unconditionally ahead of every
// request with an "https" scheme, and auth.AddCredentials parses the whole
// GOAUTH value (via a sync.Once) the first time it's ever called. Since the
// checksum database this tool exists to warn about is only ever reached
// over HTTPS (the default sum.golang.org, or any GOSUMDB/GOPROXY override —
// both are required to be HTTPS by the real toolchain), a malformed GOAUTH
// Fatals before that query can ever be sent, entirely offline, regardless
// of what GOPRIVATE/GONOSUMDB say and regardless of whether the module in
// question is otherwise a genuine, uncovered private-auth leak.
//
// nil when raw parses cleanly: "netrc" alone (the default), "off" alone, a
// custom auth command, a well-formed "git <absolute-dir>", or any
// semicolon-separated combination of those that isn't one of the specific
// Fatal shapes below.
//
// Confirmed live (2026-10-03), entirely offline and reproduced against this
// tool's own "private-auth signal uncovered by GOPRIVATE" scenario (a
// go.mod require with a git insteadOf rewrite for its host, no matching
// GOPRIVATE/GONOSUMDB pattern): with a well-formed GOAUTH, `GOFLAGS=-mod=mod
// go build` against a module cached via a prior GONOSUMDB-covered download
// (so the content is already local, but go.sum doesn't yet record it) sends
// a genuine `GET https://sum.golang.org/lookup/<module>@<version>` request —
// the exact leak this tool exists to catch. With `GOAUTH="off;netrc"` in the
// identical setup, the process Fatals with the message below the instant it
// would otherwise have issued that request (confirmed via `go build -x`:
// the "# get https://sum.golang.org/lookup/..." trace line never completes),
// so the leak cannot happen. Also confirmed `GOAUTH="netrc;;netrc"` (a
// stray doubled semicolon, a natural copy-paste/templating typo) Fatals the
// same way. Before this check existed, goprivaudit had zero GOAUTH
// awareness and reported a false SUMDB LEAK for exactly this scenario.
//
// GOAUTH is otherwise irrelevant to this tool's own private-auth signals
// (insteadOf, credential.helper, extraHeader, netrc) — see the package doc
// comment and run()'s own comment where those are collected for why GOAUTH
// only ever governs go's *own* HTTP client, never a `git` subprocess fetch —
// this check exists purely because a malformed GOAUTH also blocks the
// *leaking* sumdb request itself, a completely separate effect from
// anything GOAUTH does or doesn't do to the private fetch.
//
// Deliberately only two of runGoAuth's Fatal conditions are modeled as
// "empty command"/"off combined with other commands" above the switch, plus
// the three "git <dir>" argument-shape ones below — every one of them is a
// property of the GOAUTH string (plus, for "git", the local filesystem)
// alone, checkable with zero network access. The "netrc"/custom-command
// cases are deliberately NOT modeled: a bad netrc file or a failing custom
// auth command is only discovered later, non-fatally, if that specific
// credential set is actually needed — not an unconditional offline Fatal
// the way these are. Ported from goproxycheck's own goAuthConfigError
// (run #628/technique #117), which had already found and fixed this exact
// gap for goproxycheck's differently-shaped "would the fetch succeed"
// question; goprivaudit's own, independent "can a leak happen at all"
// question needed the identical check.
func goAuthConfigError(raw string) error {
	cmds := strings.Split(raw, ";")
	// Real go processes commands in reverse order (runGoAuth's own comment:
	// "GOAUTH commands are processed in reverse order to prioritize
	// credentials in the order they were specified") — mirrored here so
	// that, when more than one entry is independently malformed, this
	// reports the same one a real `go` run would Fatal on first.
	for i := len(cmds) - 1; i >= 0; i-- {
		command := strings.TrimSpace(cmds[i])
		words := strings.Fields(command)
		if len(words) == 0 {
			return fmt.Errorf("GOAUTH encountered an empty command (GOAUTH=%s)", raw)
		}
		switch words[0] {
		case "off":
			if len(cmds) != 1 {
				return fmt.Errorf("GOAUTH=off cannot be combined with other authentication commands (GOAUTH=%s)", raw)
			}
			return nil
		case "git":
			if len(words) != 2 {
				return fmt.Errorf("GOAUTH=git dir method requires an absolute path to the git working directory")
			}
			dir := words[1]
			if !filepath.IsAbs(dir) {
				return fmt.Errorf("GOAUTH=git dir method requires an absolute path to the git working directory, dir is not absolute")
			}
			fi, statErr := os.Stat(dir)
			if statErr != nil {
				return fmt.Errorf("GOAUTH=git encountered an error; cannot stat %s: %v", dir, statErr)
			}
			if !fi.IsDir() {
				return fmt.Errorf("GOAUTH=git dir method requires an absolute path to the git working directory, dir is not a directory")
			}
		}
	}
	return nil
}
