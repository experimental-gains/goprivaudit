package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrivatePrefixesFromGitConfig(t *testing.T) {
	src := `[user]
	name = someone
	email = someone@example.com

[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/

[url "ssh://git@example.com/"]
	pushInsteadOf = https://example.com/

[core]
	editor = vim
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// git config section names are case-insensitive (only the quoted
// subsection is case-sensitive) — confirmed live: `git config -l` against
// a `[URL "..."]`-headed config normalizes it to `url....insteadof=...`
// exactly like a lowercase header, so real git honors an uppercase or
// mixed-case section name identically. Before this fix urlSectionRe was a
// bare case-sensitive literal, silently dropping the whole section (and
// its insteadOf-derived private prefix) whenever a hand-edited gitconfig
// used anything but exactly "url" — a false negative on the signal this
// tool exists to catch.
func TestPrivatePrefixesFromGitConfigCaseInsensitiveSection(t *testing.T) {
	src := `[URL "ssh://git@github.com/myorg/"]
	insteadOf = https://github.com/myorg/
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigIgnoresPushInsteadOf covers a common
// personal/CI git config pattern: fetch anonymously over public HTTPS,
// but push over authenticated SSH, scoped to a specific org (not just a
// bare host, so the run #53 known-public-host exclusion alone wouldn't
// catch this). Verified against real git behavior (`git ls-remote`/`git
// fetch` with only pushInsteadOf configured still hit the original public
// HTTPS URL) that pushInsteadOf never affects the fetch path `go get`
// uses, so it can't create a sumdb leak and shouldn't be treated as a
// private-auth signal at all — found by testing against a real module
// (github.com/kubernetes/client-go) with this exact org-scoped
// pushInsteadOf-only config, which the pre-fix code flagged as a leak.
func TestPrivatePrefixesFromGitConfigIgnoresPushInsteadOf(t *testing.T) {
	src := `[url "git@github.com:kubernetes/"]
	pushInsteadOf = https://github.com/kubernetes/
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (pushInsteadOf-only doesn't affect fetch), got %v", got)
	}
}

// TestPrivatePrefixesFromGitConfigIgnoresBlanketPublicHostRewrite covers
// the exact snippet go.dev's own FAQ recommends for "Why does 'go get'
// use HTTPS when cloning a repository?" — rewriting all of github.com to
// SSH for auth convenience. It names no org, so it isn't a private-auth
// signal for any specific module; treating it as one made every public
// GitHub-hosted dependency look like a sumdb leak (found by testing
// against a real go.mod with this exact, officially-documented config).
func TestPrivatePrefixesFromGitConfigIgnoresBlanketPublicHostRewrite(t *testing.T) {
	src := `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (blanket host rewrite isn't a private signal), got %v", got)
	}
}

// A bare-host rewrite for a host that isn't a known public multi-tenant
// code host (e.g. a private GitHub Enterprise instance) still counts —
// there's no public use of that host to confuse it with.
func TestPrivatePrefixesFromGitConfigKeepsBlanketPrivateHostRewrite(t *testing.T) {
	src := `[url "ssh://git@github.mycompany.com/"]
	insteadOf = https://github.mycompany.com/
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.mycompany.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPrivatePrefixesFromGitConfigNoURLSections(t *testing.T) {
	src := "[user]\n\tname = someone\n"
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestNormalizeToModulePrefix(t *testing.T) {
	cases := map[string]string{
		"https://github.com/myorg/":     "github.com/myorg",
		"https://github.com/myorg":      "github.com/myorg",
		"https://github.com/myorg.git":  "github.com/myorg",
		"git@github.com:myorg":          "github.com/myorg",
		"git@github.com:myorg/repo.git": "github.com/myorg/repo",
		"ssh://git@example.com/myorg":   "example.com/myorg",
		"":                              "",
		// Boundary cases for the "@"/":" index checks below: an empty
		// username segment is not something any real git tool writes into
		// a config (the documented go.dev FAQ snippet and `git@host:path`
		// shorthand both always carry a real username), but a hand-edited
		// config could still contain one. The function already handles all
		// three correctly (strips the empty-user "@", or produces a
		// prefix a real module path could never match for the empty-host
		// case) — these pin that down with a regression test instead of
		// leaving it unverified.
		"https://@example.com/org": "example.com/org", // scheme case, "@" at index 0
		"@example.com:org":         "example.com/org", // shorthand case, "@" at index 0
		"git@:org":                 "/org",            // shorthand case, ":" at index 0 (empty host)
	}
	for in, want := range cases {
		if got := normalizeToModulePrefix(in); got != want {
			t.Errorf("normalizeToModulePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIncludes(t *testing.T) {
	src := `[user]
	name = someone

[include]
	path = ~/.gitconfig-private

[includeIf "gitdir:~/work/"]
	path = ~/.gitconfig-work

[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`
	got := parseIncludes([]byte(src))
	want := []includeDirective{
		{cond: "", path: "~/.gitconfig-private"},
		{cond: "gitdir:~/work/", path: "~/.gitconfig-work"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestIncludeIfMatchesGitdir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cases := []struct {
		cond   string
		dir    string
		want   bool
		reason string
	}{
		{"gitdir:" + home + "/work/", home + "/work/app", true, "exact prefix"},
		{"gitdir:" + home + "/work/", home + "/personal/app", false, "outside prefix"},
		{"gitdir:~/work/", home + "/work/app", true, "tilde expansion"},
		{"gitdir:" + home + "/work/", home + "/workshop/app", false, "sibling dir sharing a string prefix must not match ('work' vs 'workshop')"},
		{"gitdir/i:" + strings.ToUpper(home) + "/WORK/", home + "/work/app", true, "case-insensitive variant"},
		{"onbranch:main", home + "/work/app", false, "unsupported condition kind never matches"},
	}
	for _, c := range cases {
		if got := includeIfMatches(c.cond, c.dir); got != c.want {
			t.Errorf("includeIfMatches(%q, %q) = %v, want %v (%s)", c.cond, c.dir, got, c.want, c.reason)
		}
	}
}

func TestPrivatePrefixesFromConfigFileFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "included.gitconfig", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "config", `[include]
	path = ./included.gitconfig
`)
	got := privatePrefixesFromConfigFile(filepath.Join(dir, "config"), dir, map[string]bool{})
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestMatchGitdirGlobExactNoWildcard covers a pattern with no "**" segment
// at all, fully consumed segment-by-segment down to zero — reachable in
// practice via an includeIf gitdir pattern with no trailing "/" (per
// git-config(1), a trailing "/" is what makes expandGitdirPattern append
// "**"; without one, the pattern matches only that exact directory, no
// recursion). globMatchSegs' loop must stop exactly when pSegs empties,
// not attempt one more iteration and index pSegs[0] on an empty slice.
func TestMatchGitdirGlobExactNoWildcard(t *testing.T) {
	if !matchGitdirGlob("a/b", "a/b") {
		t.Error("matchGitdirGlob(\"a/b\", \"a/b\") = false, want true (exact match)")
	}
	if matchGitdirGlob("a/b", "a/b/c") {
		t.Error("matchGitdirGlob(\"a/b\", \"a/b/c\") = true, want false (pattern shorter than target, no wildcard)")
	}
}

// TestPrivatePrefixesFromGitConfigInlineComments covers a hand-edited
// dotfile pattern: inline comments on both a section header and a value
// line, both of which `git config --get` still parses correctly (verified
// live — see stripLineComment's doc comment). Before stripLineComment
// existed, the section-header comment made the whole section invisible
// (the section regexes require the line to end right after "]") and the
// value-line comment would have been appended onto the parsed prefix,
// so this covers the more severe of the two failure modes.
func TestPrivatePrefixesFromGitConfigInlineComments(t *testing.T) {
	src := `[url "git@github.com:myorg/"] ; ssh rewrite for private org
	insteadOf = https://github.com/myorg/ # keep on HTTPS elsewhere
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigLineContinuation covers a real,
// git-accepted way to keep a long insteadOf URL readable in a hand-edited
// dotfile: a trailing unescaped backslash immediately before the newline
// continues the value onto the next physical line. Verified against real
// git (`git config --file ... --get-regexp '.*'` on this exact input
// resolves to `url.git@github.com:myorg/.insteadof https://github.com/myorg/`,
// one continued value, not two garbled lines). Before the
// splitLogicalLines fix, the line-based scanner treated each physical
// line independently: `https://git` (unterminated, no real match) on the
// first line and `hub.com/myorg/` (no `=`, dropped by splitKV) on the
// second — losing the real private-module signal entirely, a false
// negative of the same shape as the case-sensitivity and bare "."/".."
// gaps fixed in prior runs.
func TestPrivatePrefixesFromGitConfigLineContinuation(t *testing.T) {
	src := "[url \"git@github.com:myorg/\"]\n\tinsteadOf = https://git\\\nhub.com/myorg/\n"
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigLineContinuationCRLF is the same
// real-git-verified case as above, on a CRLF gitconfig (common on
// Windows) — the continuation trigger is a backslash immediately before
// "\r\n", not just a bare "\n".
func TestPrivatePrefixesFromGitConfigLineContinuationCRLF(t *testing.T) {
	src := "[url \"git@github.com:myorg/\"]\r\n\tinsteadOf = https://git\\\r\nhub.com/myorg/\r\n"
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigContinuationNotHonoredInComment
// confirms the scanner matches real git's actual behavior rather than
// over-generalizing: a trailing backslash inside a comment does NOT
// continue onto the next line (verified live — real git raises a syntax
// error on the dangling next line in this exact input, rather than
// joining it into the comment). The tool's best-effort scanner doesn't
// need to error on malformed input, but it must not silently misjoin a
// comment tail with the following, unrelated line either.
func TestPrivatePrefixesFromGitConfigContinuationNotHonoredInComment(t *testing.T) {
	src := "[url \"git@github.com:myorg/\"]\n\tinsteadOf = https://github.com/myorg/ # trailing\\\nstill comment?\n"
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestStripLineComment(t *testing.T) {
	cases := []struct{ in, want string }{
		{`insteadOf = https://x/`, `insteadOf = https://x/`},
		{`insteadOf = https://x/#note`, `insteadOf = https://x/`},
		{`insteadOf = https://x/ # note`, `insteadOf = https://x/ `},
		{`insteadOf = https://x/;note`, `insteadOf = https://x/`},
		{`[url "x"] ; note`, `[url "x"] `},
		{`val = "quoted # not a comment ; still not"`, `val = "quoted # not a comment ; still not"`},
		{`val = "a\"#b" # real comment`, `val = "a\"#b" `},
	}
	for _, c := range cases {
		if got := stripLineComment(c.in); got != c.want {
			t.Errorf("stripLineComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPrivatePrefixesFromConfigFileIncludeCycleTerminates(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.gitconfig", `[include]
	path = ./b.gitconfig
`)
	writeFile(t, dir, "b.gitconfig", `[include]
	path = ./a.gitconfig
`)
	// Must return (not hang) even though a includes b includes a.
	got := privatePrefixesFromConfigFile(a, dir, map[string]bool{})
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
