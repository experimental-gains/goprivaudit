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
// "--mod=...") entry and returns its resolved value plus whether -mod
// counts as having been set explicitly at all.
//
// value always reflects the LAST "-mod=" occurrence, even an empty one
// ("-mod="), matching how the flag package resolves a repeated flag when
// GOFLAGS values are prepended to a real argv. But ok does NOT simply
// track "was any -mod= token present": it mirrors cmd/go's own
// explicitStringFlag.Set (go/src/cmd/go/internal/base/flag.go), the Var
// implementation the real -mod flag is registered with:
//
//	func (f explicitStringFlag) Set(v string) error {
//		*f.value = v
//		if v != "" {
//			*f.explicit = true
//		}
//		return nil
//	}
//
// *explicit is only ever assigned true — never reset to false — and only
// when the value being set is non-empty. So "ok" here is true iff ANY
// "-mod=" occurrence anywhere in goflags had a non-empty value, regardless
// of what a later occurrence set value to.
//
// This matters for a real, live-verified divergence: pre-fix, this
// function treated a single "-mod=" (empty value) the same as any other
// explicit "-mod=X" — reporting (value="", ok=true) — which made
// vendorModeActive treat it as an explicit override to non-vendor mode
// (mod == "vendor" is false), when real go's cfg.BuildModExplicit is
// simply never set for it at all, so go instead falls through to the
// normal vendor auto-default exactly as if -mod had been omitted entirely.
// Confirmed live: with a real vendor/modules.txt present (go >= 1.14, no
// workspace) and GOPROXY pointed at an unreachable address,
// `GOFLAGS=-mod= go list -m all` fails with "go: can't compute 'all'
// using the vendor directory" — proof real go auto-vendored and never
// touched the network — both inside and outside an active go.work
// workspace, the exact opposite of what the pre-fix (value="", ok=true)
// result made vendorModeActive conclude. That's an active wrong claim
// (SUMDB LEAK reported for a query that structurally cannot happen), the
// same severity class goflagsInvalidModValue's own "-mod=Vendor" fix
// closed.
//
// The sticky-ok/last-value split also matters for a second real go
// behavior verified live: `GOFLAGS="-mod=vendor -mod="` inside an active
// workspace (value ends up "", but ok is true because "vendor" was
// non-empty) still Fatals with go's workspace-mode "-mod may only be set
// to readonly or vendor" error — exactly as goflagsModRejectedInWorkspace
// (see below) computes from these two return values, and exactly unlike
// a bare "-mod=" alone (ok=false), which does not Fatal and instead
// auto-vendors as described above.
func explicitModFlag(goflags string) (value string, ok bool) {
	for _, tok := range quotedFields(goflags) {
		tok = strings.TrimPrefix(tok, "--")
		tok = strings.TrimPrefix(tok, "-")
		if v, found := strings.CutPrefix(tok, "mod="); found {
			value = v
			if v != "" {
				ok = true
			}
		}
	}
	return value, ok
}

// goflagsInvalidModValue reports whether goflags contains an explicit
// "-mod=" (or "--mod=") entry whose value isn't one of the four the real
// go command actually accepts. Per cmd/go/internal/work.buildModeInit's own
// switch (go/src/cmd/go/internal/work/init.go), anything other than
// ""/"mod"/"readonly"/"vendor" hits its default case and Fatals with
// `-mod=<value> not supported (can be ”, 'mod', 'readonly', or 'vendor')`
// — verified live: `GOFLAGS=-mod=Vendor go list -m` (a very plausible
// mistake: the correct value is lowercase, but a shell variable, a
// generated CI config, or simple habit can easily capitalize it) exits 1
// with exactly that message, before resolving a single module, for every
// module-aware go subcommand (list, build, get, mod download, test, ...),
// not just build — they all funnel through work.BuildInit, which calls
// buildModeInit right after modload.Init(), before anything module-aware
// happens. Confirmed live end-to-end against the actual goprivaudit
// binary, pre-fix: a go.mod with a real, otherwise-uncovered
// private-auth-signaled require plus GOFLAGS=-mod=Vendor was reported
// "SUMDB LEAK" — an active wrong claim for a checksum-database query that
// structurally cannot happen, the same failure class goflagsMalformed and
// goflagsRejectedByGo already close for the other two invalid-GOFLAGS
// shapes (a non-flag-shaped token, and a shape-valid but unregistered flag
// name / missing required value).
//
// Unlike goflagsRejectedByGo's cases, this rejection message never
// mentions "$GOFLAGS"/"%GOFLAGS%" at all (verified live, see above), so
// goflagsRejectedByGo's stderr-substring probe doesn't catch it — hence a
// separate function rather than widening that one's match. And unlike
// goflagsRejectedByGo's registered-flag-name/missing-argument checks
// (which ask a live `go` binary specifically because the full set of
// registered flag names and which of them are boolean shifts across go
// versions and isn't otherwise enumerable from outside cmd/go), the
// accepted `-mod` values are a small, stable, and already fully documented
// part of the go command's interface (`go help build`) that hasn't
// changed since modules were introduced — so this is checked directly,
// the same static-check style as goflagsMalformed, rather than by paying
// for another `go list -m` subprocess that could only ever confirm the
// same fixed set.
func goflagsInvalidModValue(goflags string) bool {
	mod, ok := explicitModFlag(goflags)
	if !ok {
		return false
	}
	switch mod {
	case "", "mod", "readonly", "vendor":
		return false
	default:
		return true
	}
}

// goflagsModRejectedInWorkspace reports whether goflags carries an explicit
// -mod value that the real go command rejects specifically because an
// active go.work workspace is narrower than plain module mode: per
// modload.setDefaultBuildMod's own check (go/src/cmd/go/internal/modload/
// init.go):
//
//	if cfg.BuildModExplicit {
//		if inWorkspaceMode() && cfg.BuildMod != "readonly" && cfg.BuildMod != "vendor" {
//			base.Fatalf("go: -mod may only be set to readonly or vendor " +
//				"when in workspace mode, but it is set to %q...")
//		}
//	}
//
// -mod=mod — perfectly valid outside a workspace, and one of the four
// values goflagsInvalidModValue itself accepts — Fatals immediately inside
// one, before resolving a single module. Verified live: with a real go.work
// naming the module and GOPROXY pointed at an unreachable address,
// `GOFLAGS=-mod=mod go list -m all` (and `go build`) both exit 1 with
// exactly that "-mod may only be set to readonly or vendor when in
// workspace mode" message, while the identical GOFLAGS outside the
// workspace (GOWORK=off) builds normally. Before this function existed,
// goprivaudit had no way to know this: goflagsInvalidModValue accepts
// "mod" unconditionally (correct outside a workspace), and vendorModeActive
// only checks whether the resolved value equals "vendor" — so a go.mod
// with a real, otherwise-uncovered private-auth-signaled require, an active
// go.work, and GOFLAGS=-mod=mod (a common way to force dependency updates,
// e.g. in CI) was reported "SUMDB LEAK" — an active wrong claim for a
// checksum-database query that structurally cannot happen, the same
// failure class goflagsInvalidModValue's own "-mod=Vendor" fix closed, just
// reached via workspace mode rather than a bare invalid value.
//
// Deliberately checked ahead of (and independently from)
// goflagsInvalidModValue: since explicitModFlag's "ok" is sticky (see its
// own doc comment) while its "value" is last-write-wins even when that
// last write is empty, a compound GOFLAGS like "-mod=vendor -mod=" also
// Fatals with this exact message inside a workspace (verified live) even
// though its resolved value ("") is one goflagsInvalidModValue itself
// treats as valid — so this check cannot simply be folded into that
// function's existing switch.
func goflagsModRejectedInWorkspace(goflags, gowork string) bool {
	if gowork == "" || gowork == "off" {
		return false
	}
	mod, ok := explicitModFlag(goflags)
	if !ok {
		return false
	}
	return mod != "readonly" && mod != "vendor"
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

// goflagsMalformed reports whether goflags contains an entry the real go
// command's own $GOFLAGS validation rejects outright, mirroring
// cmd/go/internal/base.InitGOFLAGS's shape check field-for-field: every
// token must itself look like a flag ("-x", "--x", "-x=value", or
// "--x=value"); anything else — a bare word, a lone "-"/"--"/"---", or an
// "="-only token like "-=" / "--=" — is invalid on its own, since GOFLAGS
// entries are never re-paired with a following token the way a real argv's
// "-flag value" form is.
//
// This matters because InitGOFLAGS calls Fatalf("go: parsing $GOFLAGS:
// non-flag %q", f) the instant it finds one, for every go subcommand except
// `go env`/`go bug` (which deliberately swallow the error so a user
// debugging their environment can still see it) — verified live: a
// perfectly natural-looking mistake, GOFLAGS="-mod mod" (copying the
// command-line spacing of `go build -mod mod`, which is a two-token argv
// pair there but a single self-contained GOFLAGS entry here — GOFLAGS
// entries are never re-paired with a following token), makes `go build`,
// `go list -m all`, and `go mod download` all fail immediately with `go:
// parsing $GOFLAGS: non-flag "mod"` (confirmed both with and without a
// reachable network), while the identical `GOFLAGS="-mod=mod"` (the "="
// form) works exactly as documented. Before this function existed,
// explicitModFlag simply didn't recognize "-mod"/"mod" as a "-mod="
// prefix match, so vendorModeActive silently fell through to the
// auto-vendor default — reporting whatever that default happened to
// compute (vendor mode active, or not) as if the build would actually run,
// when in fact `go` dies before ever resolving a single module, so no
// sumdb query can happen either way. Confirmed live end-to-end against the
// actual goprivaudit binary: with no vendor/ directory present (so the
// auto-default is false) and a real insteadOf-based private-auth signal
// uncovered by GOPRIVATE, goprivaudit reported "SUMDB LEAK" for exactly
// this GOFLAGS value — a false positive for a checksum-database query that
// structurally cannot happen, since the real go command never gets past
// parsing its own flags.
//
// Deliberately scoped to exactly InitGOFLAGS's shape check, not
// SetFromGOFLAGS's separate "flag needs an argument" check: a bare "-mod"
// with no "=value" at all is shaped like a valid flag (so InitGOFLAGS lets
// it through) but SetFromGOFLAGS still fails a real `go list`/`go build`
// outright once it tries to apply it (verified live: exit status 2, "flag
// needs an argument: -mod"). That's a real divergence too, but a much
// narrower typo (omitting "=value" entirely, not just writing it with a
// space) than the "-mod mod" shape this function targets, and detecting it
// generically would require knowing which of every go subcommand's flags
// are boolean vs. value-taking — out of scope here.
func goflagsMalformed(goflags string) bool {
	for _, f := range quotedFields(goflags) {
		switch {
		case !strings.HasPrefix(f, "-"),
			f == "-", f == "--", strings.HasPrefix(f, "---"),
			strings.HasPrefix(f, "-="), strings.HasPrefix(f, "--="):
			return true
		}
	}
	return false
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
