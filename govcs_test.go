package main

import "testing"

func TestParseGovcsRules(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   []govcsRule
		wantOK bool
	}{
		{"empty", "", nil, true},
		{
			"single",
			"github.com:git",
			[]govcsRule{{pattern: "github.com", allowed: []string{"git"}}},
			true,
		},
		{
			"multi vcs and multi entry",
			"github.com:git,evil.com:off,*:git|hg",
			[]govcsRule{
				{pattern: "github.com", allowed: []string{"git"}},
				{pattern: "evil.com", allowed: []string{"off"}},
				{pattern: "*", allowed: []string{"git", "hg"}},
			},
			true,
		},
		{"whitespace around entries and fields", " github.com : git , *:all ", []govcsRule{
			{pattern: "github.com", allowed: []string{"git"}},
			{pattern: "*", allowed: []string{"all"}},
		}, true},
		{"missing colon", "off", nil, false},
		{"empty entry", "github.com:git,,evil.com:off", nil, false},
		{"empty pattern", ":git", nil, false},
		{"empty vcs list", "github.com:", nil, false},
		{"empty vcs name in list", "github.com:git|", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseGovcsRules(c.input)
			if ok != c.wantOK {
				t.Fatalf("parseGovcsRules(%q) ok = %v, want %v", c.input, ok, c.wantOK)
			}
			if !ok {
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("parseGovcsRules(%q) = %+v, want %+v", c.input, got, c.want)
			}
			for i := range got {
				if got[i].pattern != c.want[i].pattern {
					t.Errorf("rule %d pattern = %q, want %q", i, got[i].pattern, c.want[i].pattern)
				}
				if len(got[i].allowed) != len(c.want[i].allowed) {
					t.Fatalf("rule %d allowed = %v, want %v", i, got[i].allowed, c.want[i].allowed)
				}
				for j := range got[i].allowed {
					if got[i].allowed[j] != c.want[i].allowed[j] {
						t.Errorf("rule %d allowed[%d] = %q, want %q", i, j, got[i].allowed[j], c.want[i].allowed[j])
					}
				}
			}
		})
	}
}

// TestGovcsAllowsGitExplicitBlock covers the core case: a GOVCS entry
// naming the module's own host with an allowed-VCS list that doesn't
// include "git" (or "all") blocks it, live-verified against real go1.24.4
// (`GOVCS='*:off' go mod download` Fatals with "GOVCS disallows using git
// for public ..." before any network access).
func TestGovcsAllowsGitExplicitBlock(t *testing.T) {
	if govcsAllowsGit("github.com/myorg/internal-tool", "github.com:off", "") {
		t.Error("expected GOVCS to disallow git for a host-matching :off rule")
	}
}

// TestGovcsAllowsGitExplicitAllow is the companion negative case: an
// explicit GOVCS entry that DOES list "git" for the matching pattern must
// not be treated as a block, proving the check doesn't overreach into
// disallowing every GOVCS-configured module.
func TestGovcsAllowsGitExplicitAllow(t *testing.T) {
	if !govcsAllowsGit("github.com/myorg/internal-tool", "github.com:git", "") {
		t.Error("expected GOVCS to allow git for a host-matching :git rule")
	}
}

// TestGovcsAllowsGitUnrelatedPatternDoesNotBlock proves a GOVCS entry for
// a different host doesn't suppress an unrelated module's finding: only
// the earliest MATCHING pattern applies, and a non-matching pattern earlier
// in the list must fall through to a later (or default) rule instead of
// being treated as if it matched.
func TestGovcsAllowsGitUnrelatedPatternDoesNotBlock(t *testing.T) {
	if !govcsAllowsGit("github.com/myorg/internal-tool", "evil.com:off", "") {
		t.Error("a GOVCS rule for a different host must not block this module")
	}
}

// TestGovcsAllowsGitDefaultRules covers real go's own built-in fallback
// (no explicit GOVCS set at all): public modules may use git (and hg), so
// an uncovered module — the only kind that can ever appear in a SUMDB LEAK
// finding — is never blocked by an empty/unset GOVCS.
func TestGovcsAllowsGitDefaultRules(t *testing.T) {
	if !govcsAllowsGit("github.com/myorg/internal-tool", "", "") {
		t.Error("expected the default public:git|hg rule to allow git")
	}
}

// TestGovcsAllowsGitPublicPrivatePseudoPatterns covers GOVCS's "public"/
// "private" special patterns, defined via GOPRIVATE coverage (`go help
// private`): a module NOT matching GOPRIVATE is "public" for GOVCS
// purposes even if GOVCS itself never mentions its literal host.
func TestGovcsAllowsGitPublicPrivatePseudoPatterns(t *testing.T) {
	// "public:off" blocks our GOPRIVATE-uncovered (hence public) module...
	if govcsAllowsGit("github.com/myorg/internal-tool", "public:off", "") {
		t.Error("expected public:off to block a GOPRIVATE-uncovered module")
	}
	// ...but "private:off" must not, since the module isn't private, and
	// the default public:git|hg fallback still applies.
	if !govcsAllowsGit("github.com/myorg/internal-tool", "private:off", "") {
		t.Error("private:off must not block a module GOPRIVATE doesn't cover")
	}
	// Once GOPRIVATE covers it, "private" is the matching pseudo-pattern
	// instead.
	if govcsAllowsGit("github.com/myorg/internal-tool", "private:off", "github.com/myorg/*") {
		t.Error("expected private:off to block a GOPRIVATE-covered module")
	}
}

// TestGovcsAllowsGitMalformedFailsOpen covers parseGovcsRules returning
// ok=false: this tool has no effective ruleset to apply in that case (real
// go Fatals on its own malformed-GOVCS error before resolving anything
// needing one), so it must fail open rather than guess either way.
func TestGovcsAllowsGitMalformedFailsOpen(t *testing.T) {
	if !govcsAllowsGit("github.com/myorg/internal-tool", "not-well-formed", "") {
		t.Error("expected a malformed GOVCS value to fail open (not block)")
	}
}

// TestGovcsAllowsGitPatternPastGithubRepoRoot is the direct unit-level
// regression test for the githubRepoRoot fix: an explicit GOVCS pattern
// naming a github.com module's full import path (its real "/v2"
// subdirectory included) must not be treated as matching, since real
// cmd/go's checkGOVCS always classifies against the two-segment VCS repo
// root, never the full path. See govcsAllowsGit's doc comment for the live
// verification this mirrors.
func TestGovcsAllowsGitPatternPastGithubRepoRoot(t *testing.T) {
	if !govcsAllowsGit("github.com/googleapis/gax-go/v2", "github.com/googleapis/gax-go/v2:off", "") {
		t.Error("expected a GOVCS pattern naming the full module path (past the real repo root) to NOT block git")
	}
}

// TestGovcsAllowsGitPatternAtGithubRepoRoot is the companion proving the
// fix doesn't overreach: a GOVCS pattern naming exactly the module's real
// VCS repo root (no "/v2" suffix) must still block it.
func TestGovcsAllowsGitPatternAtGithubRepoRoot(t *testing.T) {
	if govcsAllowsGit("github.com/googleapis/gax-go/v2", "github.com/googleapis/gax-go:off", "") {
		t.Error("expected a GOVCS pattern naming the real repo root to block git")
	}
}

// TestGovcsAllowsGitNonGithubHostUnaffected proves the githubRepoRoot/
// bitbucketRepoRoot truncation is scoped to those two hosts only: an
// arbitrary, non-statically-rooted host module with an extra path segment
// past its first two components still matches an explicit pattern naming
// its own full path exactly, unchanged from before this fix — this tool
// has no way to resolve an arbitrary host's real VCS repo root offline, so
// it deliberately keeps matching those hosts' patterns against the full
// import path, same as every other non-public/private GOVCS pattern
// already does.
func TestGovcsAllowsGitNonGithubHostUnaffected(t *testing.T) {
	if govcsAllowsGit("example.com/owner/repo/v2", "example.com/owner/repo/v2:off", "") {
		t.Error("expected a non-github.com GOVCS pattern matching the full path to still block git")
	}
}

// TestGovcsAllowsGitPatternPastBitbucketRepoRoot is bitbucket.org's
// sibling of TestGovcsAllowsGitPatternPastGithubRepoRoot: an explicit GOVCS
// pattern naming a bitbucket.org module's full import path (a subdirectory
// package past its real two-segment repo root) must not be treated as
// matching, since real cmd/go's checkGOVCS always classifies against the
// VCS repo root — bitbucket.org has its own static, two-segment-root entry
// in cmd/go/internal/vcs's vcsPaths table, the same as github.com. See
// govcsAllowsGit's doc comment for the live verification this mirrors.
func TestGovcsAllowsGitPatternPastBitbucketRepoRoot(t *testing.T) {
	if !govcsAllowsGit("bitbucket.org/owner/repo/subpkg", "bitbucket.org/owner/repo/subpkg:off", "") {
		t.Error("expected a GOVCS pattern naming the full module path (past the real repo root) to NOT block git")
	}
}

// TestGovcsAllowsGitPatternAtBitbucketRepoRoot is the companion proving the
// fix doesn't overreach: a GOVCS pattern naming exactly a bitbucket.org
// module's real VCS repo root (no extra subdirectory segment) must still
// block it.
func TestGovcsAllowsGitPatternAtBitbucketRepoRoot(t *testing.T) {
	if govcsAllowsGit("bitbucket.org/owner/repo/subpkg", "bitbucket.org/owner/repo:off", "") {
		t.Error("expected a GOVCS pattern naming the real repo root to block git")
	}
}

// TestGovcsAllowsGitPatternPastGeneralVCSSuffixRoot is
// generalVCSSuffixPattern's sibling of
// TestGovcsAllowsGitPatternPastGithubRepoRoot/
// TestGovcsAllowsGitPatternPastBitbucketRepoRoot: an explicit GOVCS pattern
// naming a self-hosted module's full import path — including a subdirectory
// past its real ".git"-suffixed VCS repo root — must not be treated as
// matching, since real cmd/go's checkGOVCS always classifies against the
// VCS repo root, and cmd/go/internal/vcs's vcsPaths table resolves this
// shape offline for ANY host, not just github.com/bitbucket.org. See
// generalVCSSuffixPattern's doc comment for the live verification this
// mirrors.
func TestGovcsAllowsGitPatternPastGeneralVCSSuffixRoot(t *testing.T) {
	if !govcsAllowsGit("example.com/foo/bar.git/sub", "example.com/foo/bar.git/sub:off", "") {
		t.Error("expected a GOVCS pattern naming the full module path (past the real .git-suffixed repo root) to NOT block git")
	}
}

// TestGovcsAllowsGitPatternAtGeneralVCSSuffixRoot is the companion proving
// the fix doesn't overreach: a GOVCS pattern naming exactly the module's
// real, ".git"-suffixed VCS repo root (no extra subdirectory segment) must
// still block it.
func TestGovcsAllowsGitPatternAtGeneralVCSSuffixRoot(t *testing.T) {
	if govcsAllowsGit("example.com/foo/bar.git/sub", "example.com/foo/bar.git:off", "") {
		t.Error("expected a GOVCS pattern naming the real .git-suffixed repo root to block git")
	}
}

// TestGovcsAllowsGitPatternPastHubJazzNetRepoRoot is hub.jazz.net/git's
// sibling of TestGovcsAllowsGitPatternPastGithubRepoRoot: an explicit GOVCS
// pattern naming a hub.jazz.net/git module's full import path (a
// subdirectory package past its real four-segment repo root) must not be
// treated as matching, since real cmd/go's checkGOVCS always classifies
// against the VCS repo root — hub.jazz.net/git has its own static,
// four-segment-root entry in cmd/go/internal/vcs's vcsPaths table. See
// hubJazzNetRepoPattern's doc comment for the live verification this
// mirrors.
func TestGovcsAllowsGitPatternPastHubJazzNetRepoRoot(t *testing.T) {
	if !govcsAllowsGit("hub.jazz.net/git/abc123/myproject/subpkg", "hub.jazz.net/git/abc123/myproject/subpkg:off", "") {
		t.Error("expected a GOVCS pattern naming the full module path (past the real repo root) to NOT block git")
	}
}

// TestGovcsAllowsGitPatternAtHubJazzNetRepoRoot is the companion proving the
// fix doesn't overreach: a GOVCS pattern naming exactly a hub.jazz.net/git
// module's real VCS repo root (no extra subdirectory segment) must still
// block it.
func TestGovcsAllowsGitPatternAtHubJazzNetRepoRoot(t *testing.T) {
	if govcsAllowsGit("hub.jazz.net/git/abc123/myproject/subpkg", "hub.jazz.net/git/abc123/myproject:off", "") {
		t.Error("expected a GOVCS pattern naming the real repo root to block git")
	}
}

// TestGovcsAllowsGitPatternPastOpenstackRepoRoot is git.openstack.org's
// sibling of TestGovcsAllowsGitPatternPastBitbucketRepoRoot: an explicit
// GOVCS pattern naming a git.openstack.org module's full import path (a
// subdirectory package past its real two-segment repo root) must not be
// treated as matching, since real cmd/go's checkGOVCS always classifies
// against the VCS repo root — git.openstack.org has its own static,
// two-segment-root entry in cmd/go/internal/vcs's vcsPaths table, whose
// ".git" suffix (unlike git.apache.org's sibling entry) is optional. See
// openstackRepoPattern's doc comment for the live verification this
// mirrors.
func TestGovcsAllowsGitPatternPastOpenstackRepoRoot(t *testing.T) {
	if !govcsAllowsGit("git.openstack.org/openstack/nova/subpkg", "git.openstack.org/openstack/nova/subpkg:off", "") {
		t.Error("expected a GOVCS pattern naming the full module path (past the real repo root) to NOT block git")
	}
}

// TestGovcsAllowsGitPatternAtOpenstackRepoRoot is the companion proving the
// fix doesn't overreach: a GOVCS pattern naming exactly a git.openstack.org
// module's real VCS repo root (no extra subdirectory segment) must still
// block it.
func TestGovcsAllowsGitPatternAtOpenstackRepoRoot(t *testing.T) {
	if govcsAllowsGit("git.openstack.org/openstack/nova/subpkg", "git.openstack.org/openstack/nova:off", "") {
		t.Error("expected a GOVCS pattern naming the real repo root to block git")
	}
}

// TestGovcsAllowsGitNonVCSSuffixHostStillUnaffected proves
// generalVCSSuffixPattern is scoped to paths that actually spell out a
// literal VCS-suffix segment: a non-github.com/bitbucket.org host with no
// such suffix anywhere in its path still has no statically-known repo root,
// and keeps matching an explicit pattern against its own full import path
// unchanged — same as TestGovcsAllowsGitNonGithubHostUnaffected already
// covers for the pre-existing two-host scope.
func TestGovcsAllowsGitNonVCSSuffixHostStillUnaffected(t *testing.T) {
	if govcsAllowsGit("example.com/owner/repo/v2", "example.com/owner/repo/v2:off", "") {
		t.Error("expected a non-VCS-suffix GOVCS pattern matching the full path to still block git")
	}
}

func TestFilterGovcsDisallowed(t *testing.T) {
	modules := []string{"github.com/myorg/internal-tool", "example.com/other/mod"}

	t.Run("empty GOVCS keeps everything", func(t *testing.T) {
		got := filterGovcsDisallowed(modules, "", "", "direct")
		if len(got) != 2 {
			t.Errorf("got %v, want both modules kept", got)
		}
	})

	t.Run("blocks only the matching module when goproxy forces direct", func(t *testing.T) {
		got := filterGovcsDisallowed(modules, "", "github.com:off", "direct")
		want := []string{"example.com/other/mod"}
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps everything when goproxy has a real proxy entry, even if GOVCS blocks git", func(t *testing.T) {
		// See goproxyForcesDirect's own doc comment for the live
		// verification this mirrors: with a real proxy entry ahead of
		// "direct" in the chain, GOVCS blocking a direct git fetch never
		// gets a chance to matter — the proxy fetch (unaffected by GOVCS)
		// still happens, and the module can still leak to GOSUMDB.
		got := filterGovcsDisallowed(modules, "", "github.com:off", "https://proxy.golang.org,direct")
		if len(got) != 2 {
			t.Errorf("got %v, want both modules kept (a real proxy entry precedes direct)", got)
		}
	})

	t.Run("keeps everything when goproxy is off", func(t *testing.T) {
		// GOPROXY=off alone (no "direct" anywhere in the chain) means
		// there is no fallback to a direct VCS fetch at all, so GOVCS is
		// never even consulted for this module in real go either.
		got := filterGovcsDisallowed(modules, "", "github.com:off", "off")
		if len(got) != 2 {
			t.Errorf("got %v, want both modules kept (GOPROXY=off has no direct fallback)", got)
		}
	})
}

func TestGoproxyForcesDirect(t *testing.T) {
	cases := []struct {
		goproxy string
		want    bool
	}{
		{"direct", true},
		{"off", false}, // no fallback to direct at all: GOVCS is never even consulted
		{" direct ", true},
		{"https://proxy.golang.org,direct", false},
		{"https://proxy.golang.org", false},
		{"https://proxy.golang.org|direct", false},
		{"off,direct", false},                     // real go breaks at "off"; "direct" is dead code, never reached
		{"direct,https://proxy.golang.org", true}, // real go stops at "direct", never reaches what follows
		{"", false},
	}
	for _, c := range cases {
		if got := goproxyForcesDirect(c.goproxy); got != c.want {
			t.Errorf("goproxyForcesDirect(%q) = %v, want %v", c.goproxy, got, c.want)
		}
	}
}
