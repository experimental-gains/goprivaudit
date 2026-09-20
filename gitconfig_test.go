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
