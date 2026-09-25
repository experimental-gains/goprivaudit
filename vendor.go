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

// explicitModFlag scans a GOFLAGS-style space-separated flag list for a
// "-mod=..." (or "--mod=...") entry and returns its value. If more than one
// is present, the last one wins, matching how the flag package resolves a
// repeated flag when GOFLAGS values are prepended to a real argv.
func explicitModFlag(goflags string) (value string, ok bool) {
	for _, tok := range strings.Fields(goflags) {
		tok = strings.TrimPrefix(tok, "--")
		tok = strings.TrimPrefix(tok, "-")
		if v, found := strings.CutPrefix(tok, "mod="); found {
			value, ok = v, true
		}
	}
	return value, ok
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
