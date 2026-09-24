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
// or over-trust anything — there's no sumdb query happening at all. Both are
// also skipped when GOPROXY's effective first chain entry is "off" (see
// goproxyEffectivelyOff): that disables all module-proxy-protocol network
// access, sumdb lookups included, before a query could ever be sent. Both
// are also skipped when the module resolves dependencies from a committed
// vendor/ directory instead of the network (see vendorModeActive): that
// build path never contacts sum.golang.org either, for the same reason.
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

	gowork := *goworkOverride
	if !goworkSet {
		gowork = goEnv("GOWORK")
	}

	requires := parseRequires(data)
	replaces := mergeReplaces(parseReplaces(data), goWorkReplaces(gowork))
	modules := resolveEffectiveModules(requires, replaces)
	modules = append(modules, effectiveToolModules(parseTools(data), requires)...)

	goprivate := *privateOverride
	if !privateSet {
		goprivate = goEnv("GOPRIVATE")
	}
	gonosumdb := *nosumdbOverride
	if !nosumdbSet {
		gonosumdb = goEnv("GONOSUMDB")
	}
	if gonosumdb == "" {
		gonosumdb = goprivate // GOPRIVATE is the fallback default for GONOSUMDB
	}

	moduleDir := filepath.Dir(*gomodPath)
	visited := map[string]bool{}
	var prefixes []string
	for _, p := range gitConfigCandidates(moduleDir) {
		prefixes = append(prefixes, privatePrefixesFromConfigFile(p, moduleDir, visited)...)
	}
	prefixes = append(prefixes, privatePrefixesFromEnv(os.Getenv)...)

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
		gosumdb = goEnv("GOSUMDB")
	}

	goflags := *goflagsOverride
	if !goflagsSet {
		goflags = goEnv("GOFLAGS")
	}
	vendorModulesTxt := filepath.Join(moduleDir, "vendor", "modules.txt")
	vendorActive := vendorModeActive(goflags, parseGoVersion(data), vendorModulesTxt)

	goproxy := *proxyOverride
	if !proxySet {
		goproxy = goEnv("GOPROXY")
	}
	proxyOff := goproxyEffectivelyOff(goproxy)

	var r Report
	switch {
	case gosumdb == "off":
		// GOSUMDB=off disables the checksum database entirely, for every
		// module — per `go help module-auth`, no sumdb query is ever made
		// in that mode. Skipping the audit in that case isn't just
		// "nothing to report": running it would actively misreport a
		// SUMDB LEAK / BROAD PATTERN finding for a query that structurally
		// cannot happen (verified live: with GOSUMDB=off, a private module
		// uncovered by GOPRIVATE/GONOSUMDB is not a leak, since `go` never
		// contacts sum.golang.org for it or anything else).
	case proxyOff:
		// GOPROXY's effective first entry (comma/pipe-separated chain,
		// same precedence goproxycheck's own localGoproxyOff uses) being
		// "off" disables ALL module-proxy-protocol network access,
		// including sumdb lookups — not just GOPROXY=off on its own, but
		// any chain whose first reachable entry is the literal "off"
		// keyword. Verified live with a local logging HTTP server standing
		// in for GOSUMDB's URL: with a real, reachable GOPROXY, `go get`
		// sent a real `/lookup/<module>@<version>` request to it (the
		// exact leak this tool warns about); with GOPROXY=off and the
		// identical GOSUMDB target, `go get` failed immediately with
		// "module lookup disabled by GOPROXY=off" and the logging server
		// received no request at all — no lookup ever happens, so no leak
		// can happen, the same "cannot leak" reasoning as GOSUMDB=off and
		// vendor mode above, just reached via a config surface this tool
		// didn't check before. (A module already recorded in go.sum can
		// still build successfully under GOPROXY=off from the local module
		// cache without any network call at all, regardless of this flag —
		// same general caveat that already applies to every finding this
		// tool reports.)
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
	out = append(out, filepath.Join(moduleDir, ".git", "config"))
	return out
}

// goproxyEffectivelyOff reports whether a GOPROXY value's first
// comma-separated ("try next on not-found") or pipe-separated ("try next
// on any error") chain entry is the literal keyword "off" — the same
// precedence `cmd/go` itself applies (a later "off" in the chain is never
// reached unless every earlier entry fails first, so only the *first*
// entry being "off" makes the whole fetch structurally impossible up
// front). Mirrors goproxycheck's own localGoproxyOff/firstGoproxyEntry,
// which this project's companion tool already verified live against the
// real go command.
//
// Empty entries (a leading/interior/trailing comma or pipe, e.g. from
// `GOPROXY="$UNSET_VAR,off"`) don't count as an entry at all — verified
// live against real `go`: `GOPROXY=",off"` disables lookups exactly like
// `GOPROXY=off` does (cmd/go's own proxyList walk skips blank entries, see
// goproxycheck's parseGoproxyChain, which already gets this right). The
// naive "trim once, split on the first separator" version below used to
// treat the first entry as the empty string and never reach "off" at all,
// so a stray leading comma made this tool misreport a real, structurally
// impossible SUMDB leak.
func goproxyEffectivelyOff(goproxy string) bool {
	rest := goproxy
	for rest != "" {
		var entry string
		if i := strings.IndexAny(rest, ",|"); i >= 0 {
			entry, rest = rest[:i], rest[i+1:]
		} else {
			entry, rest = rest, ""
		}
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		return entry == "off"
	}
	return false
}

func goEnv(name string) string {
	out, err := exec.Command("go", "env", name).Output()
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
