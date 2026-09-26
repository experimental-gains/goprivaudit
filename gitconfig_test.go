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

// TestPrivatePrefixesFromGitConfigCredentialHelperOrgScoped covers a
// URL-scoped git credential helper (gitcredentials(7)) — a separate real
// private-auth mechanism from insteadOf: `go`'s subprocess `git
// clone`/`git fetch` authenticates a plain, unrewritten HTTPS URL through
// whatever credential helper is configured for that context, no insteadOf
// rewrite required. Confirmed against real git (`git config --file ...
// --get-all credential.https://github.com/myorg.helper`) that this is
// exactly how a URL-scoped [credential "..."] section resolves.
func TestPrivatePrefixesFromGitConfigCredentialHelperOrgScoped(t *testing.T) {
	src := `[credential "https://github.com/myorg"]
	helper = store
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigCredentialHelperGhAuthSetupGit
// reproduces `gh auth setup-git`'s actual real-world output verbatim
// (confirmed against its --help text and gitcredentials(7)): an empty
// "helper = " line to clear any inherited default, followed by the real
// helper. Bare-host-scoped ("https://github.com", no org/path) — the
// same "public multi-tenant host" case knownPublicGitHosts already
// excludes for insteadOf, and for the same reason here: treating it as a
// signal would flag every public GitHub-hosted dependency as a leak.
func TestPrivatePrefixesFromGitConfigCredentialHelperGhAuthSetupGit(t *testing.T) {
	src := `[credential "https://github.com"]
	helper =
	helper = !/usr/bin/gh auth git-credential
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (bare-host credential context isn't a private signal), got %v", got)
	}
}

// An empty helper value clears an inherited helper rather than
// configuring one — it authenticates nothing, so it isn't a signal.
func TestPrivatePrefixesFromGitConfigCredentialHelperEmptyValueIgnored(t *testing.T) {
	src := `[credential "https://github.com/myorg"]
	helper =
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (empty helper value clears, doesn't configure), got %v", got)
	}
}

// A bare, unscoped [credential] section (no URL context) applies to
// every fetch, not just a specific host — an even broader false-positive
// risk than the bare-host [url]/[credential] case, so it must not be
// treated as a signal at all.
func TestPrivatePrefixesFromGitConfigCredentialHelperUnscopedIgnored(t *testing.T) {
	src := `[credential]
	helper = store
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (unscoped [credential] isn't a per-host signal), got %v", got)
	}
}

// TestPrivatePrefixesFromGitConfigExtraHeaderPrivateHost reproduces the
// exact config `actions/checkout` (the default way almost every GitHub
// Actions Go workflow checks out code) writes for a self-hosted GitHub
// Enterprise Server instance — verified against its real source
// (git-auth-helper.ts, `GitAuthHelper.configureToken`): a URL-scoped
// `http.<serverUrl origin>/.extraheader` set to
// `AUTHORIZATION: basic <base64 x-access-token:token>`. Reproduced live
// with the real `git config --file` sequence that code runs, confirming
// git itself resolves `http.<url>.extraheader` from exactly this section
// form. Before this fix, `privatePrefixesFromGitConfig` had zero
// awareness of `[http "..."]` sections at all, so a module hosted on that
// same private Enterprise host — authenticated on every fetch by this
// mechanism, no insteadOf or credential helper required — was invisible
// to the sumdb-leak check entirely: a real false negative confirmed
// end-to-end via the built CLI (see TestExtraHeaderPrivateHostEndToEnd in
// main_test.go), not just this unit-level check.
func TestPrivatePrefixesFromGitConfigExtraHeaderPrivateHost(t *testing.T) {
	src := `[http "https://github.mycorp.example/"]
	extraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.mycorp.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// The default, far more common case: actions/checkout against plain
// github.com (or another known public multi-tenant host). Bare-host, so
// exempted the same way a blanket insteadOf rewrite is — otherwise every
// public dependency checked out in an ordinary GitHub Actions job would
// falsely look like a sumdb leak.
func TestPrivatePrefixesFromGitConfigExtraHeaderIgnoresBlanketPublicHost(t *testing.T) {
	src := `[http "https://github.com/"]
	extraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (blanket public-host extraheader isn't a private signal), got %v", got)
	}
}

// An empty extraheader value configures no header at all, same reasoning
// as an empty credential helper.
func TestPrivatePrefixesFromGitConfigExtraHeaderEmptyValueIgnored(t *testing.T) {
	src := `[http "https://github.mycorp.example/"]
	extraheader =
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (empty extraheader value configures nothing), got %v", got)
	}
}

// A non-empty helper followed by an empty one for the SAME URL context —
// the reverse of gh auth setup-git's own empty-then-real order — leaves no
// credential helper active for that host at all: per gitcredentials(7),
// "If credential.helper is configured to the empty string, this resets the
// helper list to empty", regardless of which side of an earlier non-empty
// entry the reset appears on. Verified live: with
// `[credential "https://x"] helper = /path/to/helper` followed by a second
// `helper =` line in the same section, `git credential fill` never invokes
// the helper at all and fails with "could not read Username ... No such
// device or address" — so this must not be treated as a signal, the same
// as a lone empty helper line already isn't.
func TestPrivatePrefixesFromGitConfigCredentialHelperResetAfterSet(t *testing.T) {
	src := `[credential "https://mycorp.example"]
	helper = /path/to/real-helper
	helper =
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (a later empty helper line resets an earlier non-empty one), got %v", got)
	}
}

// The reset must be scoped to its own URL context: a second, unrelated
// [credential "..."] section's helper must survive a different section's
// reset.
func TestPrivatePrefixesFromGitConfigCredentialHelperResetIsPerURL(t *testing.T) {
	src := `[credential "https://mycorp.example/reset-me"]
	helper = /path/to/real-helper
	helper =

[credential "https://mycorp.example/keep-me"]
	helper = /path/to/real-helper
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"mycorp.example/keep-me"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// http.<url>.extraHeader documents the identical reset-on-empty behavior
// (git-config(1): "an empty value will reset the extra headers to the
// empty list") — verified live with a local HTTP server standing in for
// the remote: a real `git ls-remote` sent no custom header at all once a
// second, empty `extraheader =` line followed a first real one in the
// same [http "..."] section.
func TestPrivatePrefixesFromGitConfigExtraHeaderResetAfterSet(t *testing.T) {
	src := `[http "https://github.mycorp.example/"]
	extraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==
	extraheader =
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (a later empty extraheader line resets an earlier non-empty one), got %v", got)
	}
}

// Both signals can coexist and are independently detected.
func TestPrivatePrefixesFromGitConfigInsteadOfAndCredentialHelperBoth(t *testing.T) {
	src := `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/

[credential "https://example.com/otherorg"]
	helper = store
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg", "example.com/otherorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
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

// TestIncludeIfMatchesActionsCheckoutGitdirPattern reproduces the exact,
// literal (non-wildcard, ".git"-suffixed) gitdir pattern `actions/
// checkout` generates for its own includeIf entries — verified against
// its real source (git-auth-helper.ts: `gitDir =
// path.join(workingDirectory, '.git')`, then
// `includeIf.gitdir:${gitDir}.path = credentialsConfigPath`). Per
// git-config(1), "gitdir:" matches against the absolute path of the
// repository's .git directory, not the working tree — the pre-fix code
// matched against moduleDir itself, which happened to still work for the
// common hand-written wildcard-terminated pattern style ("gitdir:~/work/"
// tested above) since its trailing "**" absorbs the "/.git" difference
// regardless, but never matched this literal non-wildcard form: a real
// false negative on the single most common real-world source of a
// gitdir-scoped includeIf (a GitHub Actions Go CI job), confirmed live
// against the real generated .git/config before this fix.
func TestIncludeIfMatchesActionsCheckoutGitdirPattern(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.ToSlash(filepath.Join(dir, ".git"))
	cond := "gitdir:" + gitDir
	if !includeIfMatches(cond, dir) {
		t.Errorf("includeIfMatches(%q, %q) = false, want true (actions/checkout's exact literal .git-suffixed pattern)", cond, dir)
	}
	other := t.TempDir()
	if includeIfMatches(cond, other) {
		t.Errorf("includeIfMatches(%q, %q) = true, want false (different module dir must not match)", cond, other)
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

func TestSplitConfigKey(t *testing.T) {
	cases := []struct {
		in                        string
		section, subsection, name string
		ok                        bool
	}{
		{"url.https://x-access-token@github.example.com/.insteadof", "url", "https://x-access-token@github.example.com/", "insteadof", true},
		{"credential.https://github.example.com.helper", "credential", "https://github.example.com", "helper", true},
		{"http.https://github.example.com/.extraheader", "http", "https://github.example.com/", "extraheader", true},
		{"user.name", "", "", "", false},   // no subsection — can't be a URL-scoped signal
		{"core.editor", "", "", "", false}, // same
		{"nodothere", "", "", "", false},
	}
	for _, c := range cases {
		section, subsection, name, ok := splitConfigKey(c.in)
		if ok != c.ok {
			t.Errorf("splitConfigKey(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if section != c.section || subsection != c.subsection || name != c.name {
			t.Errorf("splitConfigKey(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.in, section, subsection, name, c.section, c.subsection, c.name)
		}
	}
}

// TestPrivatePrefixesFromEnv covers the GIT_CONFIG_COUNT/GIT_CONFIG_KEY_<n>/
// GIT_CONFIG_VALUE_<n> environment-variable form of git config — a real,
// documented (git-config(1)) file-free way to inject config, verified live
// (see the run-#238-era decision log) that a real `git ls-remote`/`fetch`
// honors an insteadOf rewrite set this way exactly like one from a file.
// Before this fix, privatePrefixesFromGitConfig only ever read files, so a
// private-auth signal set purely via these variables — the documented
// selling point being "spawn multiple git commands with a common
// configuration but cannot depend on a configuration file" — was completely
// invisible, even though `go get`'s own git subprocess inherits and honors
// them exactly like any other environment variable.
func TestPrivatePrefixesFromEnv(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "3",
		"GIT_CONFIG_KEY_0":   "url.https://x-access-token@github.example.com/.insteadof",
		"GIT_CONFIG_VALUE_0": "https://github.example.com/",
		"GIT_CONFIG_KEY_1":   "credential.https://gitlab.mycorp.example.helper",
		"GIT_CONFIG_VALUE_1": "store",
		"GIT_CONFIG_KEY_2":   "core.editor", // no subsection, must not match anything
		"GIT_CONFIG_VALUE_2": "vim",
	}
	got := privatePrefixesFromEnv(func(k string) string { return env[k] })
	want := []string{"github.example.com", "gitlab.mycorp.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromEnvIgnoresKnownPublicHost mirrors
// TestPrivatePrefixesFromGitConfigIgnoresBlanketPublicHostRewrite for the
// env-var form: a bare-host insteadOf rewrite of github.com itself (go.dev's
// own documented SSH-auth-convenience pattern) must not be treated as a
// private-auth signal here either.
func TestPrivatePrefixesFromEnvIgnoresKnownPublicHost(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "1",
		"GIT_CONFIG_KEY_0":   "url.ssh://git@github.com/.insteadof",
		"GIT_CONFIG_VALUE_0": "https://github.com/",
	}
	if got := privatePrefixesFromEnv(func(k string) string { return env[k] }); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// TestPrivatePrefixesFromEnvCredentialHelperResetAfterSet mirrors
// TestPrivatePrefixesFromGitConfigCredentialHelperResetAfterSet for the
// GIT_CONFIG_COUNT/KEY/VALUE env-var form: verified live that these
// entries are processed with real git's identical sequential
// reset-or-append list semantics (a credential.<url>.helper set via index
// 0 and reset to "" via index 1 leaves `git credential fill` invoking no
// helper at all, same as the equivalent two-line config-file form).
func TestPrivatePrefixesFromEnvCredentialHelperResetAfterSet(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "2",
		"GIT_CONFIG_KEY_0":   "credential.https://mycorp.example.helper",
		"GIT_CONFIG_VALUE_0": "/path/to/real-helper",
		"GIT_CONFIG_KEY_1":   "credential.https://mycorp.example.helper",
		"GIT_CONFIG_VALUE_1": "",
	}
	if got := privatePrefixesFromEnv(func(k string) string { return env[k] }); got != nil {
		t.Errorf("got %v, want nil (a later empty helper value resets an earlier non-empty one)", got)
	}
}

// TestPrivatePrefixesFromEnvExtraHeaderResetAfterSet mirrors
// TestPrivatePrefixesFromGitConfigExtraHeaderResetAfterSet for the env-var
// form.
func TestPrivatePrefixesFromEnvExtraHeaderResetAfterSet(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "2",
		"GIT_CONFIG_KEY_0":   "http.https://github.mycorp.example/.extraheader",
		"GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==",
		"GIT_CONFIG_KEY_1":   "http.https://github.mycorp.example/.extraheader",
		"GIT_CONFIG_VALUE_1": "",
	}
	if got := privatePrefixesFromEnv(func(k string) string { return env[k] }); got != nil {
		t.Errorf("got %v, want nil (a later empty extraheader value resets an earlier non-empty one)", got)
	}
}

// TestPrivatePrefixesFromEnvEmptyOrMissingCount covers git's own documented
// rule that an empty/absent GIT_CONFIG_COUNT means zero pairs, not "read
// until a key is missing" or a panic on out-of-range formatting.
func TestPrivatePrefixesFromEnvEmptyOrMissingCount(t *testing.T) {
	cases := []map[string]string{
		{},
		{"GIT_CONFIG_COUNT": ""},
		{"GIT_CONFIG_COUNT": "0"},
		{"GIT_CONFIG_COUNT": "not-a-number", "GIT_CONFIG_KEY_0": "url.x.insteadof", "GIT_CONFIG_VALUE_0": "https://y/"},
	}
	for _, env := range cases {
		if got := privatePrefixesFromEnv(func(k string) string { return env[k] }); got != nil {
			t.Errorf("env=%v: got %v, want nil", env, got)
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
