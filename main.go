// Command goprivaudit audits a Go module's GOPRIVATE/GONOSUMDB
// configuration against its go.mod dependencies, git insteadOf rewrites,
// git credential helpers, URL-scoped extra HTTP headers, and netrc
// credentials, catching two silent misconfigurations:
//
//   - A dependency has a private-auth signal — a git insteadOf rewrite for
//     its host/path (the standard way to authenticate `go get` to a
//     private host over SSH), a URL-scoped git credential helper for its
//     host/path (see `git help gitcredentials`; the mechanism `go`'s own
//     subprocess `git clone`/`git fetch` uses to authenticate a plain,
//     unrewritten HTTPS URL — e.g. the config `gh auth setup-git` writes),
//     a URL-scoped `http.<url>.extraHeader` (the mechanism `actions/
//     checkout` uses by default to persist a CI job's token — a genuine
//     signal when scoped to a private host, e.g. a self-hosted GitHub/
//     GitLab Enterprise instance), or a netrc `machine` entry for its host
//     (also consulted by `git`'s own subprocess fetch, unconditionally —
//     see `go help goauth`: GOAUTH only governs the `go` command's own
//     HTTP client, not a `git` subprocess) — but isn't covered by
//     GOPRIVATE/GONOSUMDB, so `go` still queries the configured checksum
//     database for it (sum.golang.org by default, but GOSUMDB can point
//     elsewhere — see sumdbName) — leaking the module's path and version
//     even though the source fetch itself goes over a private,
//     authenticated connection.
//   - GOPRIVATE/GONOSUMDB contains an overly broad pattern (bare "*") that
//     disables sumdb verification for every dependency, not just the
//     intended private ones, quietly removing supply-chain protection for
//     public packages too.
//
// It checks require entries and, on a go.mod with an uncovered `tool`
// directive (Go 1.24+ — see `go help tool`), that tool's package path
// too. It makes no network calls: everything it checks is the local
// go.mod, git config, netrc file, and `go env` output.
//
// Both checks are skipped when GOSUMDB=off: that setting disables the
// checksum database entirely, for every module, so neither an uncovered
// private module nor an overly broad GOPRIVATE/GONOSUMDB pattern can leak
// or over-trust anything — there's no sumdb query happening at all. Both
// are also skipped when the module resolves dependencies from a committed
// vendor/ directory instead of the network (see vendorModeActive): that
// build path never contacts sum.golang.org either, for the same reason.
// That vendor auto-default does not apply inside an active go.work
// workspace, so it's only honored when GOWORK is unset/"off" (or an
// explicit -mod=vendor override is present, which applies either way).
// Both are also skipped when GOFLAGS itself is rejected outright by the
// real go command's own validation — a malformed shape (goflagsMalformed),
// an explicit "-mod=" value that isn't one of the four real go accepts
// (goflagsInvalidModValue, checked statically since that set is small,
// stable, and already documented), a shape-valid entry whose flag name
// isn't registered by any go subcommand at all, or is registered but
// missing its required value (goflagsRejectedByGo, asked of a real `go
// list -m` since the exact registered-flag set isn't something this tool
// can enumerate itself), or an otherwise-valid "-mod=" value an active
// go.work workspace narrows further (goflagsModRejectedInWorkspace:
// "-mod=mod" is fine standalone but Fatals inside a workspace, per
// go's own setDefaultBuildMod) — every module-aware go subcommand Fatals
// before resolving anything in any of these cases, so no sumdb query can
// happen either. Both are also skipped
// when the go.mod being audited itself contains a bare "/*" outside a
// quoted string (see goModHasBlockComment) — go.mod's grammar only allows
// "//" comments, and every module-aware go subcommand Fatals parsing the
// file itself in that case, before resolving anything. Both are also
// skipped when the go.mod's own `go` directive line is malformed (see
// goModHasInvalidGoDirective) — an argument not shaped like a real go
// version, or a missing/extra argument — for the identical reason: the real
// go command's strict go.mod parser Fatals before resolving anything. Both
// are also skipped when go.mod's own `toolchain` directive line is malformed
// (see goModHasInvalidToolchainDirective) — an argument not shaped like a
// real toolchain name (missing the "go" prefix, or not "default"), or a
// missing/extra argument — for the identical reason, the sibling directive
// to `go` sharing its exact validation shape in the real parser. Both are
// also skipped when go.mod contains any top-level line whose first token
// isn't one of the real parser's recognized directive keywords (see
// goModHasUnknownDirective) — a typo like "requires" instead of "require",
// or any other unrecognized verb — for the same reason, one level more
// general than the go/toolchain-directive-specific checks just above. Both
// are also skipped when go.mod contains a require/exclude/tool directive
// (single-line or block-entry form) with the wrong number of arguments —
// see goModHasInvalidDirectiveArgCount — a missing version, a stray extra
// token, or a tool line naming more than one package, all of which the real
// parser Fatals on before resolving anything, for the identical "cannot
// leak" reason. Both are also skipped when an ACTIVE go.work file (not the
// go.mod being audited) itself contains one of these same unparsable
// shapes — a stray block comment, a malformed go/toolchain directive, or an
// unrecognized top-level verb under go.work's own, narrower set of
// recognized directives (go, toolchain, use, replace) — see
// goWorkHasUnparseableDirective: go.work shares go.mod's strict parser, so
// the identical "Fatals before resolving anything" reasoning applies one
// file up, and this tool's own go.mod-side checks alone never noticed a
// broken go.work at all.
//
// GOPROXY=off (or an "off"-first proxy chain) does NOT get the same
// skip, even though an earlier version of this tool treated it exactly
// like GOSUMDB=off/vendor mode above. Verified live (2026-09): with
// GOPROXY=off, GOSUMDB left at its default, and a required module's exact
// pinned version already sitting in the local module cache (a completely
// ordinary state — e.g. a shared $GOMODCACHE warmed by an earlier, online
// CI stage, or by building an unrelated module first) but not yet
// recorded in go.sum, a real `GOFLAGS=-mod=mod go build` still sent a
// genuine `/lookup/<module>@<version>` request straight to GOSUMDB's
// configured URL — bypassing GOPROXY entirely, since the sumdb client
// falls back to a *direct* connection the moment every proxy in the chain
// reports "off"/"direct"/not-found, per cmd/go/internal/modfetch/
// sumdb.go's dbClient.initBase. GOPROXY=off only prevents the leak in the
// narrower case this was originally tested against: the module isn't yet
// in the local cache at all, so the fetch itself fails before any hash is
// ever computed to look up. Since this tool has no visibility into
// $GOMODCACHE's contents (a purely local, transient, machine-specific
// state it was never meant to inspect), it can't tell those two cases
// apart — and unlike GOSUMDB=off/vendor mode, which are unconditional
// regardless of cache state, GOPROXY=off is not a reliable "cannot leak"
// guarantee. Silently reporting "no issues found" on the strength of a
// guess would be exactly backwards for a module already sitting in a
// pre-warmed cache — the mainstream reason anyone sets GOPROXY=off in the
// first place (a hermetic/network-locked-down build stage that relies on
// an earlier online stage having already populated the cache) — so this
// tool now always runs the audit regardless of GOPROXY, the same
// fail-open-on-a-guess convention gitProtocolAllowed and schemeOf already
// use elsewhere in this codebase.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("goprivaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	gomodPath := fs.String("gomod", "go.mod", "path to the go.mod file to audit")
	privateOverride := fs.String("private", "", "override GOPRIVATE instead of reading it from `go env`")
	nosumdbOverride := fs.String("nosumdb", "", "override GONOSUMDB instead of reading it from `go env`")
	goworkOverride := fs.String("gowork", "", "override the go.work path instead of reading GOWORK from `go env`")
	sumdbOverride := fs.String("sumdb", "", "override GOSUMDB instead of reading it from `go env`")
	goflagsOverride := fs.String("goflags", "", "override GOFLAGS instead of reading it from `go env`")
	proxyOverride := fs.String("proxy", "", "override GOPROXY instead of reading it from `go env`")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	data, err := os.ReadFile(*gomodPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "goprivaudit: %v\n", err)
		return 2
	}

	privateSet, nosumdbSet, goworkSet, sumdbSet, goflagsSet, proxySet := false, false, false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "private":
			privateSet = true
		case "nosumdb":
			nosumdbSet = true
		case "gowork":
			goworkSet = true
		case "sumdb":
			sumdbSet = true
		case "goflags":
			goflagsSet = true
		case "proxy":
			proxySet = true
		}
	})

	// moduleDir must be resolved before any goEnv call below: several of
	// the variables being read (GOWORK above all, since its default is
	// "search upward from the current directory for a go.work file" per
	// `go help environment`) are directory-dependent, not global. Every
	// `go env` invocation is run with cmd.Dir set to moduleDir so it
	// reflects the go.mod actually being audited, not whatever directory
	// this process happened to be launched from — verified live that a
	// perfectly normal invocation shape (a wrapper script fixed at one
	// cwd, auditing a target module via `-gomod /path/to/other/go.mod`,
	// the same "audit script" pattern the run #333 modslop cmd.Dir fix
	// called out) previously made GOWORK auto-discovery resolve against
	// the wrong directory tree entirely, silently missing a real
	// workspace-level replace and reporting "no issues found" on a real
	// SUMDB LEAK — a false negative on the tool's core signal, the exact
	// scenario the go.work support added in run #298 exists to catch.
	moduleDir := filepath.Dir(*gomodPath)

	gowork := *goworkOverride
	if !goworkSet {
		gowork = goEnv(moduleDir, "GOWORK")
	}

	requires := parseRequires(data)
	replaces := mergeReplaces(parseReplaces(data), goWorkReplaces(gowork))
	modules := resolveEffectiveModules(requires, replaces)
	modules = append(modules, effectiveToolModules(parseTools(data), requires)...)

	goprivate := *privateOverride
	if !privateSet {
		goprivate = goEnv(moduleDir, "GOPRIVATE")
	}
	gonosumdb := *nosumdbOverride
	if !nosumdbSet {
		gonosumdb = goEnv(moduleDir, "GONOSUMDB")
	}
	if gonosumdb == "" {
		gonosumdb = goprivate // GOPRIVATE is the fallback default for GONOSUMDB
	}

	// One shared slots/credSlots/httpSlots set threaded across every tier
	// (and, last, the GIT_CONFIG_COUNT/KEY/VALUE env form) instead of
	// scanning each independently and concatenating the results: real git
	// resolves credential.helper/http.extraHeader as one continuous,
	// ordered scan across tiers, so a later tier's reset (an empty value)
	// must be able to cancel an earlier tier's real setting, and vice
	// versa — see privatePrefixesFromConfigFileInto's doc comment for the
	// real false positive this fixes.
	visited := map[string]bool{}
	var slots []*prefixSlot
	credSlots := map[string]*prefixSlot{}
	httpSlots := map[string]*prefixSlot{}
	for _, p := range gitConfigCandidates(moduleDir) {
		privatePrefixesFromConfigFileInto(p, moduleDir, visited, &slots, credSlots, httpSlots)
	}
	privatePrefixesFromEnvInto(os.Getenv, &slots, credSlots, httpSlots)
	var prefixes []string
	for _, s := range slots {
		if s.active {
			prefixes = append(prefixes, s.value)
		}
	}

	// A netrc `machine` entry is treated as a signal unconditionally, the
	// same as the insteadOf/credential-helper signals above — GOAUTH does
	// NOT gate this the way an earlier version of this tool assumed. GOAUTH
	// (`go help goauth`) only governs the `go` command's *own* HTTP client
	// (go-import discovery, GOPROXY mirror requests); it has no effect on
	// `git` invoked as a subprocess for a direct VCS fetch (the dominant
	// fetch path for a private, non-proxy-compliant host, and the exact
	// scenario the credential-helper signal above already covers without
	// any GOAUTH check). Verified live: with GOAUTH=off and no credential
	// helper or insteadOf configured, a bare `git` HTTPS fetch against a
	// Basic-Auth-protected server still succeeds purely via ~/.netrc — git
	// has no notion of GOAUTH at all and always consults netrc itself —
	// and a real `go get` reproduces the same thing end to end: it
	// resolves the module and starts downloading it via the netrc-
	// authenticated fetch, GOAUTH=off notwithstanding. So a module reachable
	// only via netrc creds is just as privately-fetched, and just as much
	// of a sumdb-leak risk if GOPRIVATE/GONOSUMDB doesn't cover it, whether
	// or not GOAUTH happens to mention netrc.
	if p := netrcPath(); p != "" {
		if data, err := os.ReadFile(p); err == nil {
			prefixes = append(prefixes, privatePrefixesFromNetrc(data)...)
		}
	}

	prefixes = suppressProtocolBlockedInsteadOf(prefixes, moduleDir, os.Getenv)

	gosumdb := *sumdbOverride
	if !sumdbSet {
		gosumdb = goEnv(moduleDir, "GOSUMDB")
	}

	goflags := *goflagsOverride
	if !goflagsSet {
		goflags = goEnv(moduleDir, "GOFLAGS")
	}
	vendorModulesTxt := filepath.Join(moduleDir, "vendor", "modules.txt")
	vendorActive := vendorModeActive(goflags, parseGoVersion(data), vendorModulesTxt, gowork)
	goflagsBad := goflagsMalformed(goflags) || goflagsInvalidModValue(goflags) || goflagsRejectedByGo(moduleDir, goflags) || goflagsModRejectedInWorkspace(goflags, gowork)

	// GOPROXY is still read here purely so the long-documented -proxy flag
	// keeps parsing for any existing caller that passes it explicitly; its
	// value no longer changes the audit result — see this package's own
	// doc comment for why GOPROXY=off is not a reliable "cannot leak"
	// guarantee the way GOSUMDB=off and vendor mode (below) are.
	goproxy := *proxyOverride
	if !proxySet {
		goproxy = goEnv(moduleDir, "GOPROXY")
	}
	_ = goproxy

	var r Report
	switch {
	case goWorkHasUnparseableDirective(gowork):
		// An active go.work file that itself contains a stray "/*" block
		// comment, a malformed `go`/`toolchain` directive, or a line whose
		// verb isn't one of go.work's own four recognized directives (go,
		// toolchain, use, replace) makes every module-aware go subcommand
		// Fatal parsing go.work itself, before it ever resolves a single one
		// of moduleDir's own requires — see goWorkHasUnparseableDirective's
		// doc comment for the live-verified error messages. Same "cannot
		// leak" reasoning as every other malformed-go.mod skip below, just
		// reached because the *workspace* file never finishes parsing,
		// checked ahead of moduleOutsideWorkspace since a go.work this
		// broken can't even be trusted to answer "is moduleDir a member" in
		// the first place.
	case moduleOutsideWorkspace(gowork, moduleDir):
		// An active go.work workspace that doesn't `use` moduleDir (or
		// reach it via a member's local replace) makes every standard
		// build/list/vet/test command Fatal before it ever resolves a
		// single one of moduleDir's own requires — see
		// moduleOutsideWorkspace's doc comment for the live-verified
		// error messages and the exact commands checked. Same "cannot
		// leak" reasoning as goflagsBad/gosumdb==off/vendorActive below,
		// just reached because the workspace itself refuses to consider
		// this go.mod at all.
	case goModHasBlockComment(data):
		// A go.mod containing a bare "/*" outside a quoted string, anywhere
		// in the file, makes every module-aware go subcommand Fatal while
		// parsing go.mod itself — "mod files must use // comments (not /*
		// */ comments)" — before it resolves a single module (see
		// goModHasBlockComment). Same "cannot leak" reasoning as
		// goflagsBad/gosumdb==off/vendorActive below, just reached because
		// the go.mod never finishes parsing at all.
	case goModHasInvalidGoDirective(data):
		// A go.mod whose `go` directive line real go's own strict parser
		// rejects — an argument that doesn't match modfile's GoVersionRE
		// ("go 1.9x"), a missing/extra argument ("go", "go 1.14 extra"), or
		// a mistaken "go (...)" block attempt — makes every module-aware go
		// subcommand Fatal parsing go.mod itself, before it resolves a
		// single module (see goModHasInvalidGoDirective). Same "cannot leak"
		// reasoning as goModHasBlockComment above, just reached via a
		// different unparsable-go.mod shape.
	case goModHasInvalidToolchainDirective(data):
		// A go.mod whose `toolchain` directive line real go's own strict
		// parser rejects — an argument that doesn't match modfile's
		// ToolchainRE ("toolchain 1.24.4", missing the "go" prefix a real
		// toolchain name always carries), or a missing/extra argument
		// ("toolchain", "toolchain go1.24.4 extra") — makes every
		// module-aware go subcommand Fatal parsing go.mod itself, before it
		// resolves a single module (see goModHasInvalidToolchainDirective).
		// Same "cannot leak" reasoning as goModHasInvalidGoDirective just
		// above, for the sibling directive that shares its exact
		// len(args)!=1-then-regex validation shape in the real parser.
	case goModHasUnknownDirective(data):
		// A go.mod containing any top-level line whose first token isn't
		// one of the real parser's recognized directive keywords (see
		// goModHasUnknownDirective) — a typo'd verb ("requires" for
		// "require"), a case mismatch ("GO" for "go"), or outright garbage —
		// makes every module-aware go subcommand Fatal with "unknown
		// directive: %s" parsing go.mod itself, before it resolves a single
		// module. Same "cannot leak" reasoning as goModHasInvalidGoDirective
		// just above, one level more general: that check only ever catches a
		// malformed *argument* to a recognized "go" line, not an entirely
		// unrecognized verb anywhere else in the file.
	case goModHasInvalidDirectiveArgCount(data):
		// A go.mod containing a require/exclude/tool directive (single-line
		// or block-entry form) with the wrong number of arguments — see
		// goModHasInvalidDirectiveArgCount — makes every module-aware go
		// subcommand Fatal parsing go.mod itself ("usage: require
		// module/path v1.2.3", "usage: exclude module/path v1.2.3", or "tool
		// directive expects exactly one argument"), before it resolves a
		// single module. Same "cannot leak" reasoning as
		// goModHasUnknownDirective just above, one level more specific:
		// recognizing "require"/"exclude"/"tool" as valid verbs doesn't mean
		// their own argument count was ever validated.
	case goflagsBad:
		// A GOFLAGS entry the real go command's own validation rejects
		// outright — a malformed shape (goflagsMalformed), an explicit
		// "-mod=" value that isn't one of the four real values
		// (goflagsInvalidModValue), a shape-valid but unregistered flag
		// name or missing required value (goflagsRejectedByGo), or an
		// otherwise-valid "-mod=" value an active go.work workspace
		// narrows further (goflagsModRejectedInWorkspace: "-mod=mod" is
		// fine standalone but Fatals inside a workspace) — makes every
		// module-aware go subcommand — build, list, get, mod
		// download, mod tidy, test, everything except `go env`/`go bug` —
		// Fatal immediately (with "go: parsing $GOFLAGS: non-flag ...",
		// "go: parsing $GOFLAGS: unknown flag ...", "-mod=X not
		// supported (can be '', 'mod', 'readonly', or 'vendor')", or "-mod
		// may only be set to readonly or vendor when in workspace mode")
		// before it ever resolves a single module, let alone queries a
		// checksum database. Same "cannot leak" reasoning as GOSUMDB=off
		// and vendor mode below, just reached
		// because the build never gets past parsing its own flags.
	case gosumdb == "off":
		// GOSUMDB=off disables the checksum database entirely, for every
		// module — per `go help module-auth`, no sumdb query is ever made
		// in that mode. Skipping the audit in that case isn't just
		// "nothing to report": running it would actively misreport a
		// SUMDB LEAK / BROAD PATTERN finding for a query that structurally
		// cannot happen (verified live: with GOSUMDB=off, a private module
		// uncovered by GOPRIVATE/GONOSUMDB is not a leak, since `go` never
		// contacts sum.golang.org for it or anything else).
	case vendorActive:
		// A vendor-mode build (see vendorModeActive) never contacts the
		// module proxy or sum.golang.org either — same "cannot leak"
		// reasoning as GOSUMDB=off above, just reached because the build
		// reads everything off the committed vendor/ directory instead of
		// the network, rather than because sumdb checking was turned off.
	default:
		r = audit(modules, prefixes, splitPatterns(gonosumdb))
	}
	printReport(stdout, r, sumdbName(gosumdb))
	if !r.Clean() {
		return 1
	}
	return 0
}

// sumdbName extracts the checksum database's name from a GOSUMDB value,
// stripping the optional "+<key>" suffix and " <url>" field documented in
// `go help environment` (GOSUMDB="name[+key] [url]"). An empty GOSUMDB
// (unset) means the documented default, sum.golang.org. This is purely for
// display: it lets the SUMDB LEAK message name the database that will
// actually be queried instead of assuming it's always sum.golang.org —
// verified live that GOSUMDB's URL field fully controls the query
// destination (`GOSUMDB="sum.golang.org+<realkey> http://127.0.0.1:PORT"`
// against a real private-auth-uncovered dependency sent the lookup request
// to that local URL, not sum.golang.org), so a custom GOSUMDB — a
// documented, supported way to run a private/self-hosted checksum database
// specifically to keep module info off Google's infrastructure — makes the
// old hardcoded "public checksum database" wording actively wrong, not just
// imprecise.
func sumdbName(gosumdb string) string {
	if gosumdb == "" {
		return "sum.golang.org"
	}
	name, _, _ := strings.Cut(gosumdb, " ")
	name, _, _ = strings.Cut(name, "+")
	return name
}

// suppressProtocolBlockedInsteadOf removes SUMDB-LEAK-signal prefixes whose
// only source is an insteadOf rewrite to a transport git itself would
// refuse to use — see gitProtocolAllowed for the exact GIT_ALLOW_PROTOCOL/
// protocol.allow/protocol.<name>.allow precedence this checks. A fetch that
// can never complete can never leak a module path/version to
// sum.golang.org either: verified live that a real `go mod download`/`go
// get` fails with e.g. "fatal: transport 'ssh' not allowed" *before* ever
// computing a hash to send to the checksum database — the same "cannot
// leak" reasoning run() already applies to GOSUMDB=off and vendor-mode
// builds, just reached via a different mechanism (a blocked git transport
// instead of sumdb verification being off or bypassed entirely). This is
// a real, mainstream scenario, not a contrived one: `GIT_ALLOW_PROTOCOL=
// https` (SSH disabled org-wide, a common modern hardening pattern now
// that short-lived HTTPS tokens have widely replaced long-lived SSH keys)
// combined with a leftover ssh:// insteadOf rewrite — go.dev's own
// documented private-auth pattern, and the primary example in this file's
// own doc comments — makes every `go get` for that module fail outright,
// yet pre-fix goprivaudit still reported SUMDB LEAK unconditionally.
//
// Only removes as many occurrences of a prefix as have a confirmed-blocked
// insteadOf source (blockedInsteadOfPrefixCounts counts them per prefix,
// and each occurrence is removed at most once): a prefix that's ALSO
// signaled by an unblocked insteadOf rule, a credential helper, an
// extraHeader, or a netrc entry keeps enough occurrences to stay flagged.
// This only ever narrows a false positive, never suppresses a real leak.
func suppressProtocolBlockedInsteadOf(prefixes []string, moduleDir string, getenv func(string) string) []string {
	blocked := blockedInsteadOfPrefixCounts(moduleDir, getenv)
	if len(blocked) == 0 {
		return prefixes
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if blocked[p] > 0 {
			blocked[p]--
			continue
		}
		out = append(out, p)
	}
	return out
}

// blockedInsteadOfPrefixCounts scans the same git config sources
// gitConfigCandidates/privatePrefixesFromEnv do for insteadOf rewrites
// (via insteadOfSchemesFromConfigFile/insteadOfSchemesFromEnv, which
// additionally capture each rewrite's target transport scheme), resolves
// the effective protocol.allow policy from the same config files
// (protocolAllowFromConfigFile) plus GIT_ALLOW_PROTOCOL, and counts, per
// module-path prefix, how many of its insteadOf rewrites target a
// transport git would refuse.
func blockedInsteadOfPrefixCounts(moduleDir string, getenv func(string) string) map[string]int {
	protocolAllow := map[string]string{}
	visitedProto := map[string]bool{}
	for _, p := range gitConfigCandidates(moduleDir) {
		for k, v := range protocolAllowFromConfigFile(p, moduleDir, visitedProto) {
			protocolAllow[k] = v
		}
	}

	schemes := map[string][]string{}
	visitedSchemes := map[string]bool{}
	for _, p := range gitConfigCandidates(moduleDir) {
		for prefix, ss := range insteadOfSchemesFromConfigFile(p, moduleDir, visitedSchemes) {
			schemes[prefix] = append(schemes[prefix], ss...)
		}
	}
	for prefix, ss := range insteadOfSchemesFromEnv(getenv) {
		schemes[prefix] = append(schemes[prefix], ss...)
	}

	counts := map[string]int{}
	for prefix, ss := range schemes {
		for _, s := range ss {
			if !gitProtocolAllowed(s, protocolAllow, getenv) {
				counts[prefix]++
			}
		}
	}
	return counts
}

func gitConfigCandidates(moduleDir string) []string {
	var out []string
	// git-config(1): the system-wide $(prefix)/etc/gitconfig file is git's
	// lowest-precedence config tier — read before the global/local tiers
	// below, and consulted for a plain, unrewritten `git` invocation exactly
	// like they are (git-config(1), "FILES"). It was never checked at all
	// before this fix. Verified live (2026-09): an insteadOf rewrite placed
	// only in /etc/gitconfig genuinely rewrites a real `git ls-remote` fetch
	// to the ssh transport (confirmed via GIT_TRACE=1 showing the ssh
	// subprocess invocation), both at git's compiled-in default path and via
	// an explicit GIT_CONFIG_SYSTEM override. This is a real, mainstream
	// scenario: baking an org-wide insteadOf rewrite or credential helper
	// into a container base image or CI runner image via /etc/gitconfig,
	// specifically so it applies to every job/user on the machine
	// regardless of $HOME (which may be unset, unwritable, or ephemeral in a
	// container) — a pattern several real base-image and CI-hardening
	// guides recommend for exactly that reason.
	//
	// `git var GIT_CONFIG_SYSTEM` (rather than hardcoding "/etc/gitconfig",
	// which is only this platform's compiled-in default — Homebrew git on
	// macOS instead defaults to a path under /opt/homebrew or /usr/local)
	// delegates both the platform-specific default path resolution AND the
	// GIT_CONFIG_NOSYSTEM boolean parsing to git itself: verified live that
	// it prints the resolved path and exits 0 when the system tier is
	// active, but prints nothing and exits nonzero the moment
	// GIT_CONFIG_NOSYSTEM is set to any of git's recognized truthy boolean
	// forms (1/true/yes/on, case-insensitively) — exactly mirroring real
	// git's own "skip the system file entirely" behavior confirmed
	// separately via GIT_TRACE. gitVar's existing "treat a failed/empty
	// invocation as no value" convention (same as goEnv) already does the
	// right thing here with no separate boolean-parsing code of this tool's
	// own needed.
	if sys := gitVar("GIT_CONFIG_SYSTEM"); sys != "" {
		out = append(out, sys)
	}
	if override := os.Getenv("GIT_CONFIG_GLOBAL"); override != "" {
		// git-config(1): GIT_CONFIG_GLOBAL "take[s] the configuration from
		// the given file[] instead from global ... configuration" — verified
		// live that this replaces BOTH normal global locations entirely
		// (neither $XDG_CONFIG_HOME/git/config nor ~/.gitconfig is read at
		// all once it's set, even if they exist with real content). Reading
		// them anyway would risk two different wrong results: missing a
		// real private-auth signal kept only in the override file, or
		// flagging a stale signal from a file git itself no longer
		// consults for this process at all.
		out = append(out, override)
	} else {
		// git-config(1): the "global" config tier is actually two files,
		// not one — $XDG_CONFIG_HOME/git/config (defaulting to
		// ~/.config/git/config) is read first, then ~/.gitconfig;
		// single-valued keys in the latter override the former, but
		// section entries like insteadOf are additive from both (verified
		// live: a `git config --get-regexp insteadof` run with a rewrite
		// placed only in ~/.config/git/config, and no ~/.gitconfig at all,
		// still surfaces it). The pre-fix code only ever checked
		// ~/.gitconfig, so a rewrite kept in the XDG location (git's own
		// documented alternative, and the default for XDG-dotfiles-style
		// setups) was silently invisible — a real false negative on the
		// sumdb-leak check, not just an untested path.
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			out = append(out, filepath.Join(xdg, "git", "config"))
		} else if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, ".config", "git", "config"))
		}
		if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, ".gitconfig"))
		}
	}
	// The local tier's file lives at the repo's "common dir", not always at
	// moduleDir/.git/config directly: a linked worktree's moduleDir/.git is
	// a file naming a separate per-worktree $GIT_DIR that itself points at
	// a shared common dir (almost always the main checkout's .git) via a
	// "commondir" file — git reads the shared config from there, since
	// config isn't a per-worktree file by default. A submodule's
	// moduleDir/.git is also a file, naming its own relocated $GIT_DIR
	// under the superproject's .git/modules/<name>, which owns its config
	// directly (see resolveGitDir). Falls back to the plain
	// moduleDir/.git/config guess (harmless if it doesn't exist) when
	// resolution fails outright, e.g. moduleDir isn't a git repo at all.
	if gitDir, commonDir, ok := resolveGitDir(moduleDir); ok {
		out = append(out, filepath.Join(commonDir, "config"))
		// git-config(1): once "extensions.worktreeConfig" is turned on
		// (git-worktree(1)'s own documented mechanism for a per-worktree
		// credential/insteadOf setup — e.g. isolating a private-registry
		// auth setup to just one worktree building against a different
		// private branch/fork), a fourth config file — $GIT_DIR/
		// config.worktree, at the *current* worktree's own $GIT_DIR, not
		// the shared common dir the local tier above just read — is read
		// after the local tier and can carry the exact same
		// insteadOf/credential.helper/http.extraHeader signals. Verified
		// live: with extensions.worktreeConfig enabled, `git config
		// --worktree url.<ssh>.insteadOf <https>` run in a linked
		// worktree makes a real `git ls-remote` there rewrite to ssh,
		// while the *other* worktree (sharing the same commonDir/config,
		// but with its own isolated config.worktree) still fetches over
		// plain, unrewritten HTTPS — a real signal this tool would
		// otherwise miss entirely for any repo using this mechanism,
		// since $GIT_DIR/config.worktree lives outside every tier this
		// function previously read as a source at all. The flag itself
		// can be set anywhere in the chain built so far (most commonly,
		// but not exclusively, the local config file), so worktreeConfigEnabled
		// checks the whole of out, not just the entry just appended.
		if worktreeConfigEnabled(out, moduleDir) {
			out = append(out, filepath.Join(gitDir, "config.worktree"))
		}
	} else {
		out = append(out, filepath.Join(moduleDir, ".git", "config"))
	}
	return out
}

// goEnv runs `go env <name>` with cmd.Dir set to dir, so directory-dependent
// values (GOWORK's default auto-discovery above all — see the comment
// where moduleDir is computed in run()) reflect the module actually being
// audited rather than this process's own working directory.
func goEnv(dir, name string) string {
	cmd := exec.Command("go", "env", name)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// goflagsRejectedByGo asks a real go subcommand whether it rejects goflags
// outright for a reason goflagsMalformed's static shape check can't see:
// cmd/go/internal/base.InitGOFLAGS doesn't stop at the shape check (every
// token looks like "-x"/"-x=value") — after that, it also Fatals with `go:
// parsing $GOFLAGS: unknown flag -x` the moment a shape-valid entry's flag
// name isn't registered by ANY go subcommand at all (hasFlag walks the
// whole command tree: build, get, list, mod, test, everything). Verified
// live: GOFLAGS="-notarealflag=vendor" (shape-valid — goflagsMalformed
// waves it through — and a very plausible typo of "-mod=vendor", the same
// mistake class run #439's "-mod mod" fix already covers one shape of)
// makes a real `go build`/`go list -m all`/`go mod download` Fatal
// immediately with exactly that "unknown flag" message, before resolving a
// single module — yet pre-fix goprivaudit still ran its own audit and
// reported a SUMDB LEAK for a checksum-database query that can never
// actually happen, the same "active wrong claim" failure class as every
// other goflagsBad/vendorActive/GOSUMDB=off skip in this file.
//
// This tool can't replicate hasFlag's check statically without importing
// cmd/go's own internal packages (not importable from outside the go
// toolchain, and the exact registered-flag set shifts across go versions
// anyway) — so instead of guessing, it asks the real `go` binary on PATH
// directly: `go list -m`, bare, with no module pattern, only ever reports
// the current directory's own main module straight off go.mod (`go help
// list`) — it never resolves a require, so it never contacts GOPROXY or
// GOSUMDB and returns instantly even with GOPROXY pointed at an
// unreachable address (verified live), while still running through the
// exact same InitGOFLAGS/SetFromGOFLAGS validation every other
// module-aware subcommand does, since that check happens before any
// subcommand-specific work at all. A failure for any other reason (a
// broken go.mod, `go` missing from PATH, a permission error) doesn't
// mention GOFLAGS at all and is treated as "not a GOFLAGS rejection" —
// fail open, same convention goEnv/gitVar already use elsewhere in this
// file. Skipped entirely when goflags is empty (the common case — no
// GOFLAGS set at all), so an ordinary run doesn't pay for an extra
// subprocess it can't possibly need.
//
// The check below matches on "$GOFLAGS"/"%GOFLAGS%" appearing anywhere in
// stderr, not just the "parsing $GOFLAGS:" prefix InitGOFLAGS itself uses
// (that narrower check is this function's own pre-fix form) — because
// InitGOFLAGS's shape/registered-flag check isn't the only real go
// validation a shape-valid, registered flag can fail. Per
// cmd/go/internal/base.SetFromGOFLAGS (go/src/cmd/go/internal/base/
// goflags.go), a GOFLAGS entry that names a real, registered,
// non-boolean flag but omits its "=value" entirely — e.g. GOFLAGS="-mod"
// (bare, missing the "=vendor"/"=mod"/"=readonly" a real command-line
// "-mod value" pair would supply, since GOFLAGS entries are never
// re-paired with a following token) — passes InitGOFLAGS's shape check
// clean (it looks exactly like a valid "-x" boolean flag) and so was never
// flagged by goflagsMalformed either, whose own doc comment calls this
// exact gap out as "out of scope" for a *static* check. But
// SetFromGOFLAGS Fatals it anyway once it tries to apply the flag,
// printing "go: flag needs an argument: -mod (from $GOFLAGS)" (verified
// live: `GOFLAGS=-mod go build`/`go list -m` both exit 2 immediately with
// that exact message, before resolving a single module) — a message this
// function's pre-fix "parsing $GOFLAGS:" substring check didn't catch, so
// goflagsRejectedByGo silently returned false, vendorModeActive fell
// through to whatever the vendor auto-default computed, and the tool ran
// its own audit for a query the real go command can never make — a false
// SUMDB LEAK for a checksum-database query that structurally cannot
// happen, the exact "active wrong claim" failure class this function
// exists to close. Every real SetFromGOFLAGS rejection (missing argument,
// invalid value, invalid boolean value/flag) shares the same "(from
// $GOFLAGS)"/"(from %GOFLAGS%)" suffix (see the `where` variable in
// goflags.go), so matching on the bare env-var name/token — rather than
// InitGOFLAGS's one specific "parsing $GOFLAGS:" prefix — catches both
// validation stages asking the real go binary was already meant to cover.
func goflagsRejectedByGo(dir, goflags string) bool {
	if goflags == "" {
		return false
	}
	cmd := exec.Command("go", "list", "-m")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS="+goflags)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run()
	out := stderr.String()
	return strings.Contains(out, "$GOFLAGS") || strings.Contains(out, "%GOFLAGS%")
}

// gitVar shells out to `git var <name>`, the same "ask the real tool
// instead of guessing" pattern goEnv already uses for `go env`. Returns ""
// on any error (including a nonzero exit, which `git var GIT_CONFIG_SYSTEM`
// itself uses to report that the system config tier is disabled — see
// gitConfigCandidates), so callers can't distinguish "not applicable" from
// "git itself failed", but every current caller only needs a fail-open
// empty-means-no-signal result anyway.
func gitVar(name string) string {
	out, err := exec.Command("git", "var", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func printReport(w *os.File, r Report, sumdbName string) {
	if r.Clean() {
		_, _ = fmt.Fprintln(w, "goprivaudit: no issues found")
		return
	}
	for _, m := range r.SumdbLeaks {
		_, _ = fmt.Fprintf(w, "SUMDB LEAK: %s has a private-auth signal (git insteadOf rewrite, git credential helper, extraHeader, or netrc credentials) but is not covered by GOPRIVATE/GONOSUMDB — its path and version will be sent to the %s checksum database\n", m, sumdbName)
	}
	for _, p := range r.BroadPatterns {
		_, _ = fmt.Fprintf(w, "BROAD PATTERN: GOPRIVATE/GONOSUMDB pattern %q matches every module, disabling sumdb verification for public dependencies too\n", p)
	}
}
