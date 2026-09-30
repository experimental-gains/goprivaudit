package main

import (
	"os"
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

// TestPrivatePrefixesFromGitConfigCredentialSectionEscapedQuote is a
// unit-level pin on parseQuotedSection's escape handling at the
// [credential "..."] section level (see
// TestPrivatePrefixesFromConfigFileIncludeIfGitdirEscapedQuote below for the
// end-to-end, unambiguously real-world-reachable case this fix's main
// motivation rests on — a filesystem path, unlike a URL, can genuinely
// contain a raw '"' byte on a real system). git-config(1)'s "Syntax"
// section states subsection names "can contain any characters except
// newline and the null byte. Doublequote \" and backslash can be included
// by escaping them as \" and \\, respectively" — the same escaping rule
// cd2f62e (v0.1.41) already ported to VALUE-side quoting
// (unquoteConfigValue) but never ported to the section-header side.
// Verified live: `git config --file` with exactly `[credential
// "https://git.corp.example/team\"x\"/"]` resolves its subsection to the
// literal `https://git.corp.example/team"x"/` (confirmed via `git config
// --list`), and a real `git credential fill` against that exact host+path
// invokes the configured helper. Before this fix, the section-header
// regexes' bare `[^"]*` capture stopped at the escaped quote's own '"'
// byte, leaving unmatched trailing text before the line's real closing `"]`
// and failing the whole-line match — silently dropping the ENTIRE
// [credential "..."] section (and the helper's signal in it) as
// unrecognized syntax.
func TestPrivatePrefixesFromGitConfigCredentialSectionEscapedQuote(t *testing.T) {
	src := `[credential "https://git.corp.example/team\"x\"/"]
	helper = /path/to/real-helper
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{`git.corp.example/team"x"`}
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

// TestPrivatePrefixesFromGitConfigCredentialHelperSchemeOmitted covers a
// [credential "..."]/[http "..."] section whose context pattern omits the
// scheme entirely (e.g. "git.corp.example.com", not
// "https://git.corp.example.com") — a real, git-documented shape, not a
// malformed one: per gitcredentials(7) ("CREDENTIAL CONTEXTS") and the
// http.<url>.* matching rules, dropping the scheme from a context pattern
// means "match this host under any protocol". Verified live against real
// git: `git config credential."git.corp.example.com".helper store` (no
// scheme at all) is invoked by `git credential fill` for both a
// protocol=https request and a protocol=http request to that host.
//
// Before this fix, setSignalSlot fed the section URL straight to
// normalizeToModulePrefix, which only recognizes an explicit
// "scheme://host..." prefix or a "user@host:path" shorthand and returns ""
// for anything else — so this real signal was silently dropped
// (privatePrefixesFromGitConfig returned nil) as if the config had no
// credential helper at all, a false negative independent of any
// GIT_ALLOW_PROTOCOL/protocol.allow policy.
func TestPrivatePrefixesFromGitConfigCredentialHelperSchemeOmitted(t *testing.T) {
	src := `[credential "git.corp.example.com"]
	helper = store
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"git.corp.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigCredentialHelperDeprecatedDotSyntax
// covers git-config(1)'s OTHER, deprecated subsectioned-header syntax —
// "[section.subsection]", no space, no quotes — which is a real, still
// fully supported form distinct from the quoted "[section \"subsection\"]"
// form every other test in this file uses. Live-verified against real git
// 2.47.3: `git config --file <f> --list` on a file containing exactly
// `[credential.git.corp.example.com]\n\thelper = store\n` resolves to
// `credential.git.corp.example.com.helper=store` with no parse error at
// all — and a real `git credential fill` for a
// protocol=https/host=git.corp.example.com request against that exact file
// genuinely invokes the configured helper. Before this fix,
// scanConfigSignals recognized only the quoted section form for
// credential/http/url, so this equally-real syntax was silently treated as
// an unrecognized section (section reset to ""), dropping the whole
// credential.helper signal with no trace. See parseDotSection's doc
// comment for why only a bare hostname (no org/path segment) can be
// expressed this way at all — real git Fatals parsing the file the
// instant the subsection contains '/', ':', '@', '~', or '_'.
func TestPrivatePrefixesFromGitConfigCredentialHelperDeprecatedDotSyntax(t *testing.T) {
	src := `[credential.git.corp.example.com]
	helper = store
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"git.corp.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigHTTPExtraHeaderDeprecatedDotSyntax is
// TestPrivatePrefixesFromGitConfigCredentialHelperDeprecatedDotSyntax's
// counterpart for http.extraHeader, and also confirms git's own
// case-insensitive-subsection rule for this syntax (git-config(1): "the
// subsection name is case insensitive as well", unlike the quoted form) —
// live-verified: `[http.GIT.CORP.EXAMPLE.COM]` resolves via real git to
// the lowercased key `http.git.corp.example.com.extraheader`.
func TestPrivatePrefixesFromGitConfigHTTPExtraHeaderDeprecatedDotSyntax(t *testing.T) {
	src := `[http.GIT.CORP.EXAMPLE.COM]
	extraHeader = Authorization: Bearer secret-token
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"git.corp.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigHTTPExtraHeaderSchemeOmittedOrgPath is
// TestPrivatePrefixesFromGitConfigCredentialHelperSchemeOmitted's
// counterpart for http.extraHeader and a section pattern that also
// includes a path segment (org-scoped, not just host-scoped) — confirming
// the fallback normalizes a scheme-omitted "host/path" pattern the same
// way an explicit "https://host/path" one already does.
func TestPrivatePrefixesFromGitConfigHTTPExtraHeaderSchemeOmittedOrgPath(t *testing.T) {
	src := `[http "git.corp.example.com/myorg"]
	extraHeader = Authorization: Bearer secret-token
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"git.corp.example.com/myorg"}
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

// TestPrivatePrefixesFromGitConfig_PortScopedCredential reproduces the real,
// live-verified setup for a self-hosted git server (e.g. GHES/GitLab)
// fronted by a non-default HTTPS port: a [credential "..."] context scoped
// to that exact host:port authenticates the real fetch (confirmed live —
// see stripHostPort's doc comment — a `git credential fill` query for the
// same host without the port fails outright), while the go.mod module path
// for it is inevitably port-less, since golang.org/x/mod/module.CheckPath
// rejects ':' in a module path. Before stripHostPort existed, the derived
// prefix was "git.internal.corp:8443" and this module never leaked its way
// into audit's SumdbLeaks at all — a real, non-redundant miss, since
// (unlike a ssh insteadOf's port, which lives only on the rewritten side
// never used for prefix derivation) nothing else in this file derives a
// port-less signal for a bare credential/extraHeader-only setup.
func TestPrivatePrefixesFromGitConfig_PortScopedCredential(t *testing.T) {
	src := `[credential "https://git.internal.corp:8443"]
	helper = store
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"git.internal.corp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	r := audit([]string{"git.internal.corp/org/repo"}, got, nil)
	if !reflect.DeepEqual(r.SumdbLeaks, []string{"git.internal.corp/org/repo"}) {
		t.Errorf("audit SumdbLeaks = %v, want a flagged leak on git.internal.corp/org/repo", r.SumdbLeaks)
	}
}

// TestPrivatePrefixesFromGitConfig_UsernameScopedCredentialNotASignal
// reproduces a real false positive: a [credential "..."]/[http "..."]
// section whose context URL embeds an explicit username (a real,
// hand-written pattern for scoping a PAT-based helper to one service
// account, e.g. "https://svcuser@git.corp.example/org") never actually
// authenticates a plain module fetch. Verified live with real git (see
// sectionURLHasExplicitUser's doc comment): `git credential fill` for a
// request with no "username=" line at all — exactly what git's own HTTP
// backend sends for the plain, anonymous-looking URL `go get`'s
// subprocess git constructs on its own — never invokes the configured
// helper, and `git config --get-urlmatch http.extraheader` against the
// same userless URL fails outright too. Before sectionURLHasExplicitUser
// existed, both sections here were treated exactly like their userless
// equivalents (normalizeToModulePrefix silently drops the "user@" part
// when deriving the module-path prefix), so this module was reported as a
// SUMDB LEAK even though nothing in this config can ever authenticate the
// plain fetch go itself performs.
func TestPrivatePrefixesFromGitConfig_UsernameScopedCredentialNotASignal(t *testing.T) {
	src := `[credential "https://svcuser@git.corp.example/org"]
	helper = store

[http "https://otheruser@git.corp.example/org2"]
	extraheader = AUTHORIZATION: basic ZmFrZQ==
`
	got := privatePrefixesFromGitConfig([]byte(src))
	if len(got) != 0 {
		t.Errorf("got %v, want no signal for a username-scoped credential/http section", got)
	}

	r := audit([]string{"git.corp.example/org/repo", "git.corp.example/org2/repo"}, got, nil)
	if len(r.SumdbLeaks) != 0 {
		t.Errorf("audit SumdbLeaks = %v, want none: username-scoped sections never authenticate a userless module fetch", r.SumdbLeaks)
	}
}

// TestPrivatePrefixesFromEnv_UsernameScopedCredentialNotASignal is
// TestPrivatePrefixesFromGitConfig_UsernameScopedCredentialNotASignal's
// counterpart for the GIT_CONFIG_COUNT/KEY/VALUE env-var config mechanism,
// which funnels through the same setSignalSlot helper.
func TestPrivatePrefixesFromEnv_UsernameScopedCredentialNotASignal(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "1",
		"GIT_CONFIG_KEY_0":   "credential.https://svcuser@git.corp.example/org.helper",
		"GIT_CONFIG_VALUE_0": "store",
	}
	got := privatePrefixesFromEnv(func(k string) string { return env[k] })
	if len(got) != 0 {
		t.Errorf("got %v, want no signal for a username-scoped credential subsection", got)
	}
}

func TestSectionURLHasExplicitUser(t *testing.T) {
	cases := map[string]bool{
		"https://git.corp.example/org":         false,
		"https://svcuser@git.corp.example/org": true,
		"https://git.corp.example:8443/org":    false,
		"git.corp.example/org":                 false,
		"svcuser@git.corp.example/org":         true,
		"https://svcuser@git.corp.example":     true,
		"https://@git.corp.example/org":        true, // empty user is still "explicit" syntactically
	}
	for in, want := range cases {
		if got := sectionURLHasExplicitUser(in); got != want {
			t.Errorf("sectionURLHasExplicitUser(%q) = %v, want %v", in, got, want)
		}
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

		// A self-hosted git server reached over a non-standard SSH port
		// (see stripHostPort's doc comment): the port is a transport
		// detail, never part of the module path a real go.mod declares.
		"ssh://git@example.com:2222/org/repo.git": "example.com/org/repo",
		"ssh://git@example.com:2222/":             "example.com",
		"https://example.com:8443/org/repo":       "example.com/org/repo",
		// A bracketed IPv6 host is left untouched rather than mishandled:
		// not a valid module path host either way.
		"ssh://git@[::1]:2222/org": "[::1]:2222/org",
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
		{"hasconfig:remote.*.url:*github*", home + "/work/app", false, "unsupported condition kind never matches"},
	}
	for _, c := range cases {
		if got := includeIfMatches(c.cond, c.dir, ""); got != c.want {
			t.Errorf("includeIfMatches(%q, %q) = %v, want %v (%s)", c.cond, c.dir, got, c.want, c.reason)
		}
	}
}

// TestIncludeIfMatchesGitdirRelativeToConfigFile pins the "gitdir:./..."
// form (git-config(1): resolved relative to the directory containing the
// config file the [includeIf] directive itself lives in, NOT the audited
// module directory) — see expandGitdirPattern's doc comment for the real
// false negative this fixes.
func TestIncludeIfMatchesGitdirRelativeToConfigFile(t *testing.T) {
	configFileDir := t.TempDir() // stands in for e.g. $HOME, where ~/.gitconfig lives
	cases := []struct {
		cond          string
		moduleDir     string
		configFileDir string
		want          bool
		reason        string
	}{
		{
			"gitdir:./work/", filepath.Join(configFileDir, "work", "app"), configFileDir, true,
			"module dir under configFileDir/work/ matches",
		},
		{
			"gitdir:./work/", filepath.Join(configFileDir, "personal", "app"), configFileDir, false,
			"module dir outside configFileDir/work/ must not match",
		},
		{
			"gitdir:./work/", filepath.Join(t.TempDir(), "work", "app"), configFileDir, false,
			"a same-named work/ dir under an unrelated tree must not match — the pattern is anchored at configFileDir, not just any 'work' ancestor",
		},
		{
			"gitdir:./work/myrepo/.git", filepath.Join(configFileDir, "work", "myrepo"), configFileDir, true,
			"no trailing slash still resolves relative to configFileDir for an exact literal .git-suffixed pattern (verified live against real git: a bare 'gitdir:./work', no .git suffix, does NOT match a repo at .../work/.git — real git requires an exact segment match without a wildcard/trailing slash, same as the non-relative literal form TestIncludeIfMatchesActionsCheckoutGitdirPattern covers)",
		},
		{
			"gitdir:./work/", filepath.Join(configFileDir, "work", "app"), "", false,
			"an empty configFileDir (e.g. a caller that never learned it) must not silently match everything",
		},
	}
	for _, c := range cases {
		if got := includeIfMatches(c.cond, c.moduleDir, c.configFileDir); got != c.want {
			t.Errorf("includeIfMatches(%q, moduleDir=%q, configFileDir=%q) = %v, want %v (%s)",
				c.cond, c.moduleDir, c.configFileDir, got, c.want, c.reason)
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
	if !includeIfMatches(cond, dir, "") {
		t.Errorf("includeIfMatches(%q, %q) = false, want true (actions/checkout's exact literal .git-suffixed pattern)", cond, dir)
	}
	other := t.TempDir()
	if includeIfMatches(cond, other, "") {
		t.Errorf("includeIfMatches(%q, %q) = true, want false (different module dir must not match)", cond, other)
	}
}

// TestIncludeIfMatchesLinkedWorktreeGitdir pins that a "gitdir:" pattern
// naming a linked worktree's own real $GIT_DIR (e.g. the literal
// "<main-repo>/.git/worktrees/<name>" actions/checkout-style pattern, but
// pointed at a worktree instead of a plain checkout) matches against that
// real path, not against worktreeDir/.git — which for a worktree is a
// *file*, not the directory the pre-fix code assumed. See resolveGitDir's
// doc comment for how this was confirmed live against real
// `git worktree add`.
func TestIncludeIfMatchesLinkedWorktreeGitdir(t *testing.T) {
	mainRepo := t.TempDir()
	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "wt")
	if err := os.MkdirAll(worktreeGitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+worktreeGitDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cond := "gitdir:" + filepath.ToSlash(worktreeGitDir)
	if !includeIfMatches(cond, worktree, "") {
		t.Errorf("includeIfMatches(%q, %q) = false, want true (pattern names the worktree's real $GIT_DIR)", cond, worktree)
	}

	staleCond := "gitdir:" + filepath.ToSlash(filepath.Join(worktree, ".git"))
	if includeIfMatches(staleCond, worktree, "") {
		t.Errorf("includeIfMatches(%q, %q) = true, want false (worktree/.git is a file, not the real $GIT_DIR, and must not match)", staleCond, worktree)
	}
}

// TestIncludeIfMatchesGitdirSymlinkedAncestor pins git-config(1)'s
// documented dual-form gitdir matching rule ("Both the symlink & realpath
// versions of paths will be matched outside of $GIT_DIR. E.g. if ~/git is
// a symlink to /mnt/storage/git, both gitdir:~/git and
// gitdir:/mnt/storage/git will match."). Verified live: with a real
// symlinked ancestor directory and a real repo underneath it, `git config
// --get-regexp` (invoked from the symlinked path) resolves an
// `[includeIf "gitdir:<realpath>/**"]` entry written using the fully
// resolved (symlink-free) path — not just the literal, as-given symlinked
// path already covered by every other includeIf test in this file. Before
// this fix, includeIfMatchesGitdir only ever tried the literal path
// (resolveGitDir's return value, computed via filepath.Abs, which never
// resolves symlinks), so a module checked out under a symlinked ancestor
// directory — a real, mainstream setup: macOS's /tmp is a symlink to
// /private/tmp, NixOS profiles and Nix-managed dev shells are pervasively
// symlink-based, and a Docker bind mount or a monorepo's symlink-farmed
// package layout are both common too — silently missed a real
// credential-helper/insteadOf/extraHeader signal gated by a realpath-based
// includeIf pattern, exactly the false-negative failure class this
// practice looks for.
func TestIncludeIfMatchesGitdirSymlinkedAncestor(t *testing.T) {
	real := t.TempDir()
	parent := t.TempDir()
	symlinked := filepath.Join(parent, "symlinked")
	if err := os.Symlink(real, symlinked); err != nil {
		t.Skipf("symlinks not supported on this filesystem: %v", err)
	}
	moduleDir := filepath.Join(symlinked, "myrepo")
	if err := os.MkdirAll(filepath.Join(moduleDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	realPattern := "gitdir:" + filepath.ToSlash(real) + "/**"
	if !includeIfMatches(realPattern, moduleDir, "") {
		t.Errorf("includeIfMatches(%q, %q) = false, want true (real git also matches the realpath-resolved form of a gitdir path reached through a symlinked ancestor)", realPattern, moduleDir)
	}

	literalPattern := "gitdir:" + filepath.ToSlash(symlinked) + "/**"
	if !includeIfMatches(literalPattern, moduleDir, "") {
		t.Errorf("includeIfMatches(%q, %q) = false, want true (the literal, as-given symlinked form must still match, same as before this fix)", literalPattern, moduleDir)
	}

	other := t.TempDir()
	unrelatedPattern := "gitdir:" + filepath.ToSlash(other) + "/**"
	if includeIfMatches(unrelatedPattern, moduleDir, "") {
		t.Errorf("includeIfMatches(%q, %q) = true, want false (an unrelated realpath must not match)", unrelatedPattern, moduleDir)
	}
}

// writeHEAD writes a gitDir/HEAD file, either a symbolic ref to branch (if
// branch != "") or a detached-HEAD-style raw commit SHA (if branch == "").
func writeHEAD(t *testing.T, gitDir, branch string) {
	t.Helper()
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n"
	if branch != "" {
		content = "ref: refs/heads/" + branch + "\n"
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestIncludeIfMatchesOnbranch pins the "onbranch:"/"onbranch/i:" condition
// kinds added alongside "gitdir:" — verified live first (see
// includeIfMatchesOnbranch's doc comment) against a real `git checkout`
// before writing these fixture-based cases: a real credential.helper
// scoped via "[includeIf \"onbranch:feature/*\"]" was active with
// "feature/x" checked out and inactive on "main", confirming both that real
// git branch-scopes includeIf this way and that the pre-fix code (which
// unconditionally returned false for any "onbranch:" condition) silently
// missed it — a false negative on a real SUMDB LEAK.
func TestIncludeIfMatchesOnbranch(t *testing.T) {
	cases := []struct {
		cond   string
		branch string
		want   bool
		reason string
	}{
		{"onbranch:feature/x", "feature/x", true, "exact match"},
		{"onbranch:feature/x", "main", false, "different branch"},
		{"onbranch:feature/*", "feature/x", true, "glob wildcard"},
		{"onbranch:feature/", "feature/x", true, "trailing slash matches hierarchically"},
		{"onbranch:feature/", "feature", false, "trailing slash requires something under the prefix"},
		{"onbranch:foo", "bar/foo", false, "bare pattern is NOT auto-prefixed with **/ unlike gitdir"},
		{"onbranch/i:FEATURE/X", "feature/x", true, "case-insensitive variant"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		gitDir := filepath.Join(dir, ".git")
		writeHEAD(t, gitDir, c.branch)
		if got := includeIfMatches(c.cond, dir, ""); got != c.want {
			t.Errorf("%s: includeIfMatches(%q) on branch %q = %v, want %v", c.reason, c.cond, c.branch, got, c.want)
		}
	}
}

func TestIncludeIfMatchesOnbranchDetachedHEAD(t *testing.T) {
	dir := t.TempDir()
	writeHEAD(t, filepath.Join(dir, ".git"), "")
	cond := "onbranch:*"
	if includeIfMatches(cond, dir, "") {
		t.Errorf("includeIfMatches(%q, detached HEAD) = true, want false (git-config(1): no branch name to match against)", cond)
	}
}

func TestIncludeIfMatchesOnbranchNoRepo(t *testing.T) {
	dir := t.TempDir() // no .git at all
	if includeIfMatches("onbranch:*", dir, "") {
		t.Error("includeIfMatches(\"onbranch:*\", no-repo dir) = true, want false")
	}
}

func TestCurrentBranchNonBranchRef(t *testing.T) {
	gitDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/tags/v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := currentBranch(gitDir); ok {
		t.Error("currentBranch on a HEAD pointing at refs/tags/... = ok, want !ok (not a branch ref)")
	}
}

func TestCurrentBranchUnreadableHEAD(t *testing.T) {
	gitDir := t.TempDir() // no HEAD file at all
	if _, ok := currentBranch(gitDir); ok {
		t.Error("currentBranch with no HEAD file = ok, want !ok")
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

// TestPrivatePrefixesFromConfigFileIncludeIfGitdirEscapedQuote is the
// end-to-end, concretely-real-world-reachable case behind this fix: an
// includeIf "gitdir:..." condition whose pattern needs to match a real
// $GIT_DIR path containing a literal '"' byte. Unlike the [url "..."]
// subsection case a prior pass (see run #154 in STRATEGY_ARCHIVE.md)
// deliberately left unfixed — reasoned there to be unreachable because a
// valid git remote URL can never contain a raw '"' — a gitdir pattern's
// data is an ordinary filesystem path, and a real Unix directory name CAN
// legally contain a double quote (unusual, but not invalid: unlike '/' and
// NUL, '"' has no special meaning to the filesystem). git-config(1)
// requires the exact same \"/\\ escaping for ANY subsection value
// regardless of what kind of string it holds, so this is the same
// underlying parser gap, just in the one context where the "no realistic
// input can trigger it" argument doesn't hold.
//
// Verified live end-to-end against the real, built goprivaudit binary
// before writing this test (not just reasoned about): a repository at a
// path containing a literal '"' segment, with a real global gitconfig
// reading `[includeIf "gitdir:<path-with-escaped-quote>/**"] path = ...`
// pointing at a file with a credential.helper for an otherwise-uncovered
// module's host, made the pre-fix binary print "goprivaudit: no issues
// found" and the fixed binary correctly print "SUMDB LEAK: ..." for the
// identical go.mod/GOPRIVATE setup — confirming this isn't just a unit-level
// regex nuance but a real false negative on the tool's core signal.
func TestPrivatePrefixesFromConfigFileIncludeIfGitdirEscapedQuote(t *testing.T) {
	dir := t.TempDir()
	quotedRepo := filepath.Join(dir, `team"x"`, "repo")
	if err := os.MkdirAll(filepath.Join(quotedRepo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	includedPath := writeFile(t, dir, "included.gitconfig", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	escapedPattern := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(quotedRepo) + "/**"
	globalPath := writeFile(t, dir, "global.gitconfig",
		`[includeIf "gitdir:`+escapedPattern+`"]`+"\n\tpath = "+includedPath+"\n")

	got := privatePrefixesFromConfigFile(globalPath, quotedRepo, map[string]bool{})
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromConfigFileIncludeResetOrdering covers a real false
// positive the old "scan this file's own lines, then append each include's
// independently-scanned result" architecture had: a credential.helper
// reset (an empty value) living in an included file couldn't cancel a real
// helper set earlier in the file that includes it, because each file's
// slots were tracked independently and only merged by concatenation
// afterward. Verified live with `git credential fill` against a real fake
// credential-helper script: with the real helper set before the [include]
// line and the included file resetting that same URL context, git invokes
// no helper at all — exactly as if the two files were one continuous file,
// which is how git actually reads an include's contents. Both directions
// matter and are covered here: a reset that comes after the set via the
// include, and a reset that comes before a set that arrives via the
// include.
func TestPrivatePrefixesFromConfigFileIncludeResetOrdering(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "reset.gitconfig", `[credential "https://github.com/myorg"]
	helper =
`)
	writeFile(t, dir, "set-then-include-reset", `[credential "https://github.com/myorg"]
	helper = /path/to/real-helper
[include]
	path = ./reset.gitconfig
`)
	if got := privatePrefixesFromConfigFile(filepath.Join(dir, "set-then-include-reset"), dir, map[string]bool{}); got != nil {
		t.Errorf("set-then-include-reset: got %v, want nil (the included file's reset must cancel the real helper set before it)", got)
	}

	writeFile(t, dir, "set.gitconfig", `[credential "https://github.com/myorg"]
	helper = /path/to/real-helper
`)
	writeFile(t, dir, "include-set-then-reset", `[include]
	path = ./set.gitconfig
[credential "https://github.com/myorg"]
	helper =
`)
	if got := privatePrefixesFromConfigFile(filepath.Join(dir, "include-set-then-reset"), dir, map[string]bool{}); got != nil {
		t.Errorf("include-set-then-reset: got %v, want nil (a reset after the include must cancel the real helper the include set)", got)
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

// TestMatchGitdirGlobBangNegation pins that a "[!...]" bracket-class
// negation in an includeIf gitdir pattern segment is honored the way real
// git's wildmatch() honors it (POSIX fnmatch-style "!" negation), not
// silently treated as an ordinary literal-character class the way Go's
// path.Match treats "!" on its own (verified live: `git config --file`
// resolves `includeIf "gitdir:**/proj[!0-9]/**"` for a directory named
// "projA", and separately, real git does NOT treat "[^0-9]" as negation —
// so translating "^" instead of "!" would not be a usable workaround for a
// real gitconfig either). See gitBangToCaret's doc comment for the
// path.Match divergence this covers.
func TestMatchGitdirGlobBangNegation(t *testing.T) {
	if !matchGitdirGlob("**/proj[!0-9]/**", "home/projA/repo") {
		t.Error(`matchGitdirGlob("**/proj[!0-9]/**", "home/projA/repo") = false, want true ("!" negation: "projA" has no digit where the class is)`)
	}
	if matchGitdirGlob("**/proj[!0-9]/**", "home/proj1/repo") {
		t.Error(`matchGitdirGlob("**/proj[!0-9]/**", "home/proj1/repo") = true, want false ("proj1" has a digit where the negated class forbids one)`)
	}
	// "[^...]" is an ordinary (non-negated) class to real git, containing a
	// literal "^" plus the listed characters — it must stay untranslated.
	if matchGitdirGlob("**/proj[^0-9]/**", "home/projA2/repo") {
		t.Error(`matchGitdirGlob("**/proj[^0-9]/**", "home/projA2/repo") = true, want false (real git does not treat "[^...]" as negation)`)
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

// TestUnquoteConfigValue exercises git-config(1)'s value quoting/escaping
// grammar directly — see unquoteConfigValue's doc comment for the live
// verification against real `git config --file` this mirrors (bare
// quote-toggling and \"/\\ escapes both confirmed there).
func TestUnquoteConfigValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{`https://github.com/myorg/`, `https://github.com/myorg/`},
		{`"https://github.com/myorg/"`, `https://github.com/myorg/`},
		{`"gh:"`, `gh:`},
		{`ab"cd ef"gh`, `abcd efgh`},
		{`a\"b\\c`, `a"b\c`},
		{`"a\"b\\c"`, `a"b\c`},
		{`"line1\nline2\ttabbed"`, "line1\nline2\ttabbed"},
		{``, ``},
		{`""`, ``},
	}
	for _, c := range cases {
		if got := unquoteConfigValue(c.in); got != c.want {
			t.Errorf("unquoteConfigValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPrivatePrefixesFromGitConfigQuotedInsteadOfValue reproduces, at the
// privatePrefixesFromGitConfig level, the real false negative confirmed
// live against github.com/mathiasbynens/dotfiles (a widely-forked public
// dotfiles repo whose .gitconfig quotes an insteadOf value purely as a
// style choice, not because the value needs escaping) and against a
// synthetic exploit-shaped version of the same pattern — see
// unquoteConfigValue's doc comment for the full GIT_TRACE-verified rewrite
// confirmation. Before unquoteConfigValue existed, splitKV left the
// wrapping quotes in value, so normalizeToModulePrefix's scheme-prefix
// check (HasPrefix(url, "https://")) never matched a value starting with
// '"' and this private-auth signal was silently dropped.
func TestPrivatePrefixesFromGitConfigQuotedInsteadOfValue(t *testing.T) {
	src := `[url "git@github.com:myorg/"]
	insteadOf = "https://github.com/myorg/"
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestPrivatePrefixesFromGitConfigQuotedEmptyResetsCredentialHelper is the
// quoted counterpart to TestPrivatePrefixesFromGitConfigCredentialHelperResetAfterSet:
// git-config(1) allows an empty value to be spelled `helper = ""`
// (a fully-quoted empty string) as well as the bare `helper =`, and real
// git treats both identically as a reset — confirmed live with a logging
// credential-helper stand-in: `git credential fill` invoked no helper at
// all once a real helper = line was followed by helper = "" in the same
// section, the identical result as the unquoted reset form. Before
// unquoteConfigValue existed, splitKV's raw value for a quoted empty
// string was the two-character literal `""`, not Go's empty string, so
// setSignalSlot's `value == ""` reset check never matched it and the
// helper stayed wrongly recorded as active.
func TestPrivatePrefixesFromGitConfigQuotedEmptyResetsCredentialHelper(t *testing.T) {
	src := `[credential "https://mycorp.example"]
	helper = /path/to/real-helper
	helper = ""
`
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil (a later quoted-empty helper value resets an earlier non-empty one), got %v", got)
	}
}

func TestWorktreeConfigValueFromGitConfig(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantValue string
		wantOK    bool
	}{
		{"absent", "[core]\n\teditor = vim\n", "", false},
		{"explicit true", "[extensions]\n\tworktreeConfig = true\n", "true", true},
		// Bare key with no "=" at all is git's documented implicit-true
		// spelling (verified live: `git config --bool` prints "true" for
		// it) — splitKV alone would silently drop this line since it
		// requires an "=".
		{"bare key", "[extensions]\n\tworktreeConfig\n", "true", true},
		// Case-insensitive section AND key name, like every other section
		// this tool reads.
		{"case insensitive", "[EXTENSIONS]\n\tWorktreeConfig = TRUE\n", "TRUE", true},
		// Explicit empty value is a documented FALSE spelling, distinct
		// from the key being absent (wantOK must still be true here).
		{"explicit empty", "[extensions]\n\tworktreeConfig =\n", "", true},
		// Last assignment in the file wins, same as every other scalar
		// key elsewhere in this file.
		{"last wins", "[extensions]\n\tworktreeConfig = true\n\tworktreeConfig = false\n", "false", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			value, ok := worktreeConfigValueFromGitConfig([]byte(c.src))
			if value != c.wantValue || ok != c.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", value, ok, c.wantValue, c.wantOK)
			}
		})
	}
}

func TestGitConfigBoolTrue(t *testing.T) {
	trueCases := []string{"true", "True", "TRUE", "yes", "on", "1"}
	for _, v := range trueCases {
		if !gitConfigBoolTrue(v) {
			t.Errorf("gitConfigBoolTrue(%q) = false, want true", v)
		}
	}
	falseCases := []string{"false", "no", "off", "0", "", "  ", "garbage"}
	for _, v := range falseCases {
		if gitConfigBoolTrue(v) {
			t.Errorf("gitConfigBoolTrue(%q) = true, want false", v)
		}
	}
}

// TestWorktreeConfigValueFromConfigFileOwnFileOverridesInclude pins the
// same "a file's own settings take precedence over its includes'"
// precedence protocolAllowFromConfigFile already applies, for this new
// scalar: an included file enabling the extension shouldn't survive a
// later explicit disable in the including file itself.
func TestWorktreeConfigValueFromConfigFileOwnFileOverridesInclude(t *testing.T) {
	dir := t.TempDir()
	incPath := writeFile(t, dir, "included", "[extensions]\n\tworktreeConfig = true\n")
	mainPath := writeFile(t, dir, "main", "[include]\n\tpath = "+incPath+"\n[extensions]\n\tworktreeConfig = false\n")

	value, ok := worktreeConfigValueFromConfigFile(mainPath, dir, map[string]bool{})
	if !ok || gitConfigBoolTrue(value) {
		t.Errorf("got (%q, %v), want a false-resolving value with ok=true", value, ok)
	}
}
