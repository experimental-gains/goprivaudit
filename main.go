// Command goprivaudit audits a Go module's GOPRIVATE/GONOSUMDB
// configuration against its go.mod dependencies, git insteadOf rewrites,
// and netrc credentials, catching two silent misconfigurations:
//
//   - A dependency has a private-auth signal — a git insteadOf rewrite for
//     its host/path (the standard way to authenticate `go get` to a
//     private host over SSH), or a netrc `machine` entry for its host
//     (the default GOAUTH mechanism `go` uses for HTTPS module fetches,
//     see `go help goauth`) — but isn't covered by GOPRIVATE/GONOSUMDB, so
//     `go` still queries the public sum.golang.org checksum database for
//     it — leaking the module's path and version even though the source
//     fetch itself goes over a private, authenticated connection.
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
// or over-trust anything — there's no sumdb query happening at all.
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
	goauthOverride := fs.String("goauth", "", "override GOAUTH instead of reading it from `go env`")
	sumdbOverride := fs.String("sumdb", "", "override GOSUMDB instead of reading it from `go env`")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	data, err := os.ReadFile(*gomodPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "goprivaudit: %v\n", err)
		return 2
	}

	privateSet, nosumdbSet, goworkSet, goauthSet, sumdbSet := false, false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "private":
			privateSet = true
		case "nosumdb":
			nosumdbSet = true
		case "gowork":
			goworkSet = true
		case "goauth":
			goauthSet = true
		case "sumdb":
			sumdbSet = true
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

	goauth := *goauthOverride
	if !goauthSet {
		goauth = goEnv("GOAUTH")
	}
	if goauth == "" {
		goauth = "netrc" // `go help goauth`: default is netrc when GOAUTH is unset
	}
	if goauthUsesNetrc(goauth) {
		if p := netrcPath(); p != "" {
			if data, err := os.ReadFile(p); err == nil {
				prefixes = append(prefixes, privatePrefixesFromNetrc(data)...)
			}
		}
	}

	gosumdb := *sumdbOverride
	if !sumdbSet {
		gosumdb = goEnv("GOSUMDB")
	}

	var r Report
	if gosumdb != "off" {
		// GOSUMDB=off disables the checksum database entirely, for every
		// module — per `go help module-auth`, no sumdb query is ever made
		// in that mode. Skipping the audit in that case isn't just
		// "nothing to report": running it would actively misreport a
		// SUMDB LEAK / BROAD PATTERN finding for a query that structurally
		// cannot happen (verified live: with GOSUMDB=off, a private module
		// uncovered by GOPRIVATE/GONOSUMDB is not a leak, since `go` never
		// contacts sum.golang.org for it or anything else).
		r = audit(modules, prefixes, splitPatterns(gonosumdb))
	}
	printReport(stdout, r)
	if !r.Clean() {
		return 1
	}
	return 0
}

func gitConfigCandidates(moduleDir string) []string {
	var out []string
	// git-config(1): the "global" config tier is actually two files, not
	// one — $XDG_CONFIG_HOME/git/config (defaulting to ~/.config/git/config)
	// is read first, then ~/.gitconfig; single-valued keys in the latter
	// override the former, but section entries like insteadOf are additive
	// from both (verified live: a `git config --get-regexp insteadof` run
	// with a rewrite placed only in ~/.config/git/config, and no
	// ~/.gitconfig at all, still surfaces it). The pre-fix code only ever
	// checked ~/.gitconfig, so a rewrite kept in the XDG location (git's
	// own documented alternative, and the default for XDG-dotfiles-style
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
	out = append(out, filepath.Join(moduleDir, ".git", "config"))
	return out
}

func goEnv(name string) string {
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func printReport(w *os.File, r Report) {
	if r.Clean() {
		_, _ = fmt.Fprintln(w, "goprivaudit: no issues found")
		return
	}
	for _, m := range r.SumdbLeaks {
		_, _ = fmt.Fprintf(w, "SUMDB LEAK: %s has a private-auth signal (git insteadOf rewrite or netrc credentials) but is not covered by GOPRIVATE/GONOSUMDB — its path and version will be sent to the public checksum database\n", m)
	}
	for _, p := range r.BroadPatterns {
		_, _ = fmt.Fprintf(w, "BROAD PATTERN: GOPRIVATE/GONOSUMDB pattern %q matches every module, disabling sumdb verification for public dependencies too\n", p)
	}
}
