package main

import (
	"os"
	"strconv"
	"strings"
)

// vendorModeActive reports whether `go build`/`go install`/`go test` (or
// anything else driven by the real go command) will resolve this module's
// dependencies from a committed vendor/ directory instead of the network,
// matching the go command's own vendor-auto-detection rules (see `go help
// modules`, the "vendor directories" section):
//
//   - An explicit `-mod=` value — set via GOFLAGS, since that's the only
//     place this tool can observe it (it has no visibility into a
//     command-line flag some other invocation of `go` might pass) —
//     always wins over the auto-default, in either direction: `-mod=vendor`
//     forces vendor mode even without a vendor/ directory (go itself then
//     fails outright, a separate problem this tool doesn't need to detect),
//     and `-mod=mod`/`-mod=readonly` forces the normal network-resolving
//     path even when a vendor/ directory is sitting right there. Verified
//     live: with a real vendor/modules.txt present and a go.mod pinned to
//     go 1.24, `GOFLAGS=-mod=mod go build` with an unreachable GOPROXY still
//     fails trying to reach it — the explicit flag suppresses the auto-vendor
//     default entirely.
//   - Absent an explicit override, vendor mode is the default exactly when
//     vendorModulesTxtPath exists AND the go.mod's own `go` directive is
//     1.14 or higher — but ONLY outside an active workspace. Verified live:
//     the identical vendor/modules.txt with the go.mod's `go` directive
//     lowered to 1.13 does NOT auto-vendor (`go build` with an unreachable
//     GOPROXY fails trying to fetch from it, exactly like the
//     no-vendor-directory case); separately, the identical qualifying
//     per-module vendor/modules.txt (go >= 1.14, directory present) is ALSO
//     ignored the moment GOWORK points at a real workspace file — `go
//     build` inside that member module still reaches the network exactly
//     as if no vendor/ existed at all. Workspace-wide vendoring is a
//     distinct, opt-in mechanism (`go work vendor`, producing a single
//     vendor/ at the workspace root) that always requires an explicit
//     `-mod=vendor`, already covered by the branch above — so gowork being
//     non-empty (and not "off") suppresses only the auto-default, never an
//     explicit override in either direction.
//
// This matters because a vendor-mode build never consults the module proxy
// or sum.golang.org at all — verified live: `go build` with vendor mode
// active (via either the auto-default or an explicit `-mod=vendor`)
// succeeds even with GOPROXY pointed at an unreachable address and GOSUMDB
// left at its default, while the identical build one flag away (`-mod=mod`)
// fails immediately trying to reach the network. So a private-auth signal
// left uncovered by GOPRIVATE/GONOSUMDB cannot leak anything to the public
// checksum database in this mode — the same "this query structurally cannot
// happen" reasoning the existing GOSUMDB=off skip already applies, just
// reached via a different mechanism (vendoring bypasses the network
// entirely, rather than a config flag disabling one specific check on it).
//
// gowork uses the same convention as goWorkReplaces: the path from `go env
// GOWORK` (or a test override), where "" or "off" means no workspace.
func vendorModeActive(goflags, goVersion, vendorModulesTxtPath, gowork string) bool {
	if mod, ok := explicitModFlag(goflags); ok {
		return mod == "vendor"
	}
	if gowork != "" && gowork != "off" {
		return false
	}
	if _, err := os.Stat(vendorModulesTxtPath); err != nil {
		return false
	}
	return goVersionAtLeast(goVersion, 1, 14)
}

// explicitModFlag scans a GOFLAGS-style flag list for a "-mod=..." (or
// "--mod=...") entry and returns its value. If more than one is present,
// the last one wins, matching how the flag package resolves a repeated flag
// when GOFLAGS values are prepended to a real argv.
func explicitModFlag(goflags string) (value string, ok bool) {
	for _, tok := range quotedFields(goflags) {
		tok = strings.TrimPrefix(tok, "--")
		tok = strings.TrimPrefix(tok, "-")
		if v, found := strings.CutPrefix(tok, "mod="); found {
			value, ok = v, true
		}
	}
	return value, ok
}

// quotedFields splits a GOFLAGS-style value the way the real go command does
// — cmd/go/internal/base.InitGOFLAGS feeds $GOFLAGS through
// cmd/internal/quoted.Split, not strings.Fields — allowing a whole flag to be
// wrapped in single or double quotes so it can carry an embedded space (`go
// help environment` documents exactly this, e.g. GOFLAGS='"-tags=a b"'). The
// quote is only honored when it's the very first character of a field (a
// quote elsewhere, e.g. mid-token, is not special and is left as a literal
// character) — reimplemented here field-for-field rather than imported,
// since cmd/internal/quoted is a compiler-internal package no external
// module can import, and this tool stays dependency-free by design (see
// matchesPrefixPattern's comment).
//
// A plain strings.Fields split (this function's pre-fix form) disagreed
// with this whenever GOFLAGS contained a whole-token-quoted flag: verified
// live with a real vendor/modules.txt (go >= 1.14, no workspace — the exact
// auto-vendor conditions vendorModeActive checks) and an empty module
// cache: GOFLAGS=`"-mod=mod"` (quoted, a realistic defensive-quoting habit)
// made a real `go build` fetch `rsc.io/quote` over the network and fail
// against an unreachable GOPROXY — proving the quoted override really does
// suppress the vendor auto-default in real go — while strings.Fields, which
// doesn't strip the surrounding quotes, produced the single token
// `"-mod=mod"` that this function's own mod=-prefix match then failed to
// recognize at all (TrimPrefix("-") is a no-op on a token starting with `"`,
// not `-`). That made explicitModFlag report no explicit override present,
// so vendorModeActive fell through to the auto-default and (with a real
// vendor/ dir on disk) concluded vendor mode was active — the tool then
// skipped its own audit outright as "cannot leak", exactly backwards: the
// real go command was about to make a genuine network query for an
// uncovered private module, the worst class of bug this practice looks
// for (an active wrong claim, not just a missed check), same severity tier
// as the run #384 goproxycheck retract-range fix.
func quotedFields(s string) []string {
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
	var f []string
	for len(s) > 0 {
		for len(s) > 0 && isSpace(s[0]) {
			s = s[1:]
		}
		if len(s) == 0 {
			break
		}
		if s[0] == '"' || s[0] == '\'' {
			quote := s[0]
			s = s[1:]
			i := 0
			for i < len(s) && s[i] != quote {
				i++
			}
			if i >= len(s) {
				// Unterminated quote: real go Fatals parsing $GOFLAGS before
				// ever building anything, so no query can happen either —
				// stop scanning rather than guess at the malformed rest.
				break
			}
			f = append(f, s[:i])
			s = s[i+1:]
			continue
		}
		i := 0
		for i < len(s) && !isSpace(s[i]) {
			i++
		}
		f = append(f, s[:i])
		s = s[i:]
	}
	return f
}

// goVersionAtLeast reports whether a go.mod "go" directive's version string
// (e.g. "1.24.4" or "1.14") is at least major.minor. Returns false for an
// empty or unparsable version (a go.mod missing its `go` directive predates
// modules.txt-based vendoring anyway).
func goVersionAtLeast(version string, major, minor int) bool {
	parts := strings.SplitN(strings.TrimSpace(version), ".", 3)
	if len(parts) < 2 {
		return false
	}
	vMajor, err1 := strconv.Atoi(parts[0])
	vMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if vMajor != major {
		return vMajor > major
	}
	return vMinor >= minor
}
