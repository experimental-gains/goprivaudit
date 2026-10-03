package main

import (
	"regexp"
	"strings"
)

// githubRepoPattern captures exactly the "github.com/owner/repo" prefix of a
// module path — the VCS repo root cmd/go's own vcsPaths table resolves for
// any github.com-hosted import path, discarding everything past it,
// including a major-version suffix like "/v2" or a monorepo subdirectory
// (confirmed against go1.24.4's vendored golang.org/x/mod/internal/vcs
// source: the github.com entry's regexp is anchored to exactly two path
// segments after the host). Originally scoped to just github.com and
// bitbucket.org (see bitbucketRepoPattern below), mirroring goproxycheck's
// own githubRepoPattern/githubRepoRoot (run #476's twin fix, ported here —
// see govcsAllowsGit's doc comment): both are hardcoded, static entries in
// cmd/go/internal/vcs's own vcsPaths table (go1.24.4 source), unlike most
// other hosts, which fall back to a dynamic <meta name="go-import"> HTTP
// fetch to discover their actual root — a request this offline tool can't
// make, so those hosts' modules are matched against their own full import
// path unchanged. A THIRD shape is also statically, offline-resolvable for
// ANY host, not just these two: see generalVCSSuffixPattern below, added
// once a module path spelling out a literal VCS-suffix segment (run #689)
// was found to share the identical false-negative bug class this file's
// github.com/bitbucket.org fixes had already closed.
var githubRepoPattern = regexp.MustCompile(`^github\.com/([^/]+)/([^/]+)`)

// bitbucketRepoPattern is githubRepoPattern's sibling for bitbucket.org —
// also a static, two-segment-root entry in cmd/go/internal/vcs's vcsPaths
// table (`^(?P<root>bitbucket\.org/[\w.\-]+/[\w.\-]+)(/[\w.\-]+)*$`,
// go1.24.4 source), truncating any path segment past "owner/repo" the
// identical way github.com's entry does. Live-verified (2026-10-03,
// go1.24.4): with GOVCS="bitbucket.org/owner/repo/subpkg:off" (naming a
// bitbucket.org import path's own subdirectory package, not its two-segment
// repo root) and GOSUMDB left at its default, `go mod download` for
// bitbucket.org/owner/repo/subpkg@<version> does NOT hit the "GOVCS
// disallows" Fatal at all — it proceeds straight to an ordinary git
// fetch attempt against bitbucket.org (reaching the network, then failing
// on the repo's own absence/credentials, exactly like a real leak would
// reach sum.golang.org next) — while GOVCS="bitbucket.org/owner/repo:off"
// (naming exactly the truncated root) Fatals immediately with "GOVCS
// disallows using git for public bitbucket.org/owner/repo". Before this
// fix, govcsAllowsGit matched a bitbucket.org GOVCS pattern against the
// full modulePath directly, the same false-negative bug class run #476/
// govcsAllowsGit's github.com fix (the gax-go/v2 case) already closed for
// github.com but never ported to bitbucket.org, the other host sharing the
// identical static-root guarantee.
var bitbucketRepoPattern = regexp.MustCompile(`^bitbucket\.org/([^/]+)/([^/]+)`)

// hubJazzNetRepoPattern is githubRepoPattern's sibling for IBM DevOps
// Services' old JazzHub — a THIRD hardcoded, static-root entry in
// cmd/go/internal/vcs's vcsPaths table (go1.24.4 source):
// `^(?P<root>hub\.jazz\.net/git/[a-z0-9]+/[\w.\-]+)(/[\w.\-]+)*$`, truncating
// any path segment past "git/<user>/<project>" exactly the way github.com's
// and bitbucket.org's entries truncate past "owner/repo". Live-verified
// (2026-10-03, go1.24.4): with
// GOVCS="hub.jazz.net/git/abc123/myproject/subpkg:off" (naming a
// subdirectory package past the real 4-segment repo root, not the root
// itself) and GOSUMDB left at its default, `go mod download` for
// hub.jazz.net/git/abc123/myproject/subpkg@<version> does NOT hit the
// "GOVCS disallows" Fatal — it proceeds straight to a real git-fetch
// attempt (confirmed reaching the network: `git remote add origin --
// https://hub.jazz.net/git/abc123/myproject` in the -x trace) — while
// GOVCS="hub.jazz.net/git/abc123/myproject:off" (naming exactly the
// truncated root) Fatals immediately with "GOVCS disallows using git for
// public hub.jazz.net/git/abc123/myproject". Before this fix,
// vcsStaticRepoRoot had no entry for this host at all (unlike
// generalVCSSuffixPattern's catch-all, a hub.jazz.net/git path spells out no
// literal VCS-suffix segment anywhere, so that catch-all can't resolve it
// either) and matched every GOVCS pattern against the module's full import
// path directly — the identical false-negative bug class already closed for
// github.com/bitbucket.org/the general-suffix catch-all, just a fourth
// vcsPaths entry none of those three fixes had enumerated yet.
var hubJazzNetRepoPattern = regexp.MustCompile(`^hub\.jazz\.net/git/[a-z0-9]+/([^/]+)`)

// openstackRepoPattern is githubRepoPattern's sibling for the old
// git.openstack.org — a FIFTH hardcoded, static-root entry in
// cmd/go/internal/vcs's vcsPaths table (go1.24.4 source):
// `^(?P<root>git\.openstack\.org/[\w.\-]+/[\w.\-]+)(\.git)?(/[\w.\-]+)*$`,
// truncating any path segment past "<project>/<repo>" the same way
// bitbucket.org's entry truncates past "owner/repo" — and, unlike
// git.apache.org's sibling entry in the same table (whose repo name must
// always literally end in ".git", so it's always also reachable via
// generalVCSSuffixPattern's any-host catch-all below), git.openstack.org's
// ".git" suffix is optional, so a path with no literal VCS-suffix segment
// at all (the common case) has no other static entry to resolve it through.
// Live-verified (2026-10-03, go1.24.4): with
// GOVCS="git.openstack.org/openstack/nova/subpkg:off" (naming a
// subdirectory package past the real two-segment repo root) and GOSUMDB
// left at its default, `go mod download` for
// git.openstack.org/openstack/nova/subpkg@<version> does NOT hit the
// "GOVCS disallows" Fatal — it proceeds straight to a real git-fetch
// attempt (confirmed reaching the network in the -x trace) — while
// GOVCS="git.openstack.org/openstack/nova:off" (naming exactly the
// truncated root) Fatals immediately with "GOVCS disallows using git for
// public git.openstack.org/openstack/nova". Before this fix,
// vcsStaticRepoRoot had no entry for this host either.
var openstackRepoPattern = regexp.MustCompile(`^git\.openstack\.org/([^/]+)/([^/]+)`)

// generalVCSSuffixPattern mirrors cmd/go/internal/vcs's vcsPaths table's
// last entry — "General syntax for any server", explicitly comment-marked
// "Must be last." in the go1.24.4 source — which resolves an import path to
// a fixed VCS repo root for literally ANY host, not just github.com/
// bitbucket.org/hub.jazz.net/git.openstack.org, whenever the path itself
// spells out a literal ".bzr"/".fossil"/".git"/".hg"/".svn" suffix on one of
// its segments:
// `(?P<root>(?P<repo>([a-z0-9.\-]+\.)+[a-z0-9.\-]+(:[0-9]+)?(/~?[\w.\-]+)+?)\.(?P<vcs>bzr|fossil|git|hg|svn))(/~?[\w.\-]+)*$`.
// This is documented, intentional Go tooling behavior (`go help
// importpath`'s "repository.vcs" remote-import-path form), used by
// self-hosted git/hg/svn/bzr/fossil servers that don't publish a <meta
// name="go-import"> tag — and critically, exactly like github.com's and
// bitbucket.org's own dedicated entries (see githubRepoPattern/
// bitbucketRepoPattern above), it is resolvable by this pure regex alone,
// with NO live go-import discovery HTTP request needed, for any host
// whatsoever — the same "resolvable offline with certainty" property those
// two entries were scoped around, just not limited to two specific hosts.
//
// Live-verified (2026-10-03, go1.24.4): go.mod requiring
// "example.com/foo/bar.git/sub@v1.0.0", GOPROXY=direct, GOSUMDB=off, no
// GOPRIVATE coverage. GOVCS="example.com/foo/bar.git/sub:off" (the module's
// own full, uncollapsed import path) does NOT block it — `go mod download
// -x` proceeds straight to an ordinary direct git-fetch attempt against
// example.com (confirmed reaching the network: the command hangs on a dial
// rather than Fatal-ing). GOVCS="example.com/foo/bar.git:off" (the
// regex-truncated root, dropping the "/sub" subdirectory) DOES block it:
// `go: example.com/foo/bar.git/sub@v1.0.0: GOVCS disallows using git for
// public example.com/foo/bar.git; see 'go help vcs'`, Fatal, zero network
// access. Before this fix, govcsAllowsGit had no way to resolve this host's
// real VCS repo root at all and matched every GOVCS pattern against the
// module's full import path directly — the identical false-negative bug
// class technique #103-ish's github.com/bitbucket.org fixes (622281b/
// 02a7b33) already closed for those two hosts, but never generalized to
// this catch-all, any-host entry that sits right alongside them in cmd/go's
// own vcsPaths table.
var generalVCSSuffixPattern = regexp.MustCompile(`^(([a-z0-9.\-]+\.)+[a-z0-9.\-]+(:[0-9]+)?(/~?[\w.\-]+)+?\.(?:bzr|fossil|git|hg|svn))(/~?[\w.\-]+)*$`)

// githubRepoRoot returns modulePath's "github.com/owner/repo" prefix, or ""
// if modulePath isn't github.com-hosted.
func githubRepoRoot(modulePath string) string {
	return githubRepoPattern.FindString(modulePath)
}

// bitbucketRepoRoot returns modulePath's "bitbucket.org/owner/repo" prefix,
// or "" if modulePath isn't bitbucket.org-hosted. See bitbucketRepoPattern.
func bitbucketRepoRoot(modulePath string) string {
	return bitbucketRepoPattern.FindString(modulePath)
}

// hubJazzNetRepoRoot returns modulePath's "hub.jazz.net/git/user/project"
// prefix, or "" if modulePath isn't hub.jazz.net/git-hosted. See
// hubJazzNetRepoPattern.
func hubJazzNetRepoRoot(modulePath string) string {
	return hubJazzNetRepoPattern.FindString(modulePath)
}

// openstackRepoRoot returns modulePath's "git.openstack.org/project/repo"
// prefix, or "" if modulePath isn't git.openstack.org-hosted. See
// openstackRepoPattern.
func openstackRepoRoot(modulePath string) string {
	return openstackRepoPattern.FindString(modulePath)
}

// generalVCSSuffixRoot returns modulePath's VCS repo root per
// generalVCSSuffixPattern — the segment up to and including its literal
// ".bzr"/".fossil"/".git"/".hg"/".svn" suffix — or "" if modulePath contains
// no such suffix at all.
func generalVCSSuffixRoot(modulePath string) string {
	m := generalVCSSuffixPattern.FindStringSubmatch(modulePath)
	if m == nil {
		return ""
	}
	return m[1]
}

// vcsStaticRepoRoot returns the statically-known VCS repo root for
// modulePath — see githubRepoPattern/bitbucketRepoPattern/
// hubJazzNetRepoPattern/openstackRepoPattern/generalVCSSuffixPattern — or ""
// if modulePath doesn't match any of the shapes this tool can resolve
// offline with certainty (github.com, bitbucket.org, hub.jazz.net/git,
// git.openstack.org, or any host spelling out a literal VCS-suffix segment).
// git.apache.org and chiselapp.com — cmd/go/internal/vcs's remaining two
// pathPrefix-gated vcsPaths entries — are deliberately NOT added here:
// git.apache.org's repo name must always literally end in ".git"
// (`^(?P<root>git\.apache\.org/[a-z0-9_.\-]+\.git)(/[\w.\-]+)*$`), so every
// valid path for it is already resolved correctly by
// generalVCSSuffixPattern's any-host catch-all below; chiselapp.com's own
// regexp (`^(?P<root>chiselapp\.com/user/[A-Za-z0-9]+/repository/[\w.\-]+)$`)
// is anchored with a trailing "$" and allows no subdirectory past its root
// at all, so its "root" and "full import path" are always identical
// strings — there is no truncation for a dedicated entry to perform, and
// the pre-existing "" fallback (match the full path, unchanged) already
// gives the correct answer for every valid chiselapp.com module path.
func vcsStaticRepoRoot(modulePath string) string {
	if root := githubRepoRoot(modulePath); root != "" {
		return root
	}
	if root := bitbucketRepoRoot(modulePath); root != "" {
		return root
	}
	if root := hubJazzNetRepoRoot(modulePath); root != "" {
		return root
	}
	if root := openstackRepoRoot(modulePath); root != "" {
		return root
	}
	return generalVCSSuffixRoot(modulePath)
}

// govcsRule is a single GOVCS entry: a pattern (a GOPRIVATE-style glob
// prefix pattern, or the special literal "public"/"private") paired with
// its pipe-separated list of allowed VCS names (or "all") — see `go help
// vcs`.
type govcsRule struct {
	pattern string
	allowed []string
}

// parseGovcsRules parses a GOVCS environment value into its ordered rule
// list, mirroring cmd/go/internal/vcs.parseGOVCS's grammar exactly: a
// comma-separated list of "pattern:vcs1|vcs2|..." entries. Malformed input
// (an empty entry, a missing colon, an empty pattern or VCS list) reports
// ok=false so the caller can fail open rather than guess at an "effective"
// ruleset — the real go command Fatals outright on malformed GOVCS the
// moment it ever needs a direct VCS fetch for ANY module, public or
// private, so there's no ruleset this tool could apply here that real go
// would ever actually reach either. Same scope choice goflagsRejectedByGo
// already makes for a GOFLAGS shape this tool doesn't attempt to validate
// itself: asked of real go instead, not guessed at.
//
// Unlike real go's own parseGOVCS, this deliberately doesn't reject a
// repeated pattern ("unreachable pattern in GOVCS") — a cosmetic
// well-formedness check real go applies that has no bearing on which rule
// an EARLIER, non-repeated entry resolves to, the only thing
// govcsAllowsGit needs.
func parseGovcsRules(s string) (rules []govcsRule, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, true
	}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, false
		}
		pattern, list, found := strings.Cut(item, ":")
		if !found {
			return nil, false
		}
		pattern = strings.TrimSpace(pattern)
		list = strings.TrimSpace(list)
		if pattern == "" || list == "" {
			return nil, false
		}
		var allowed []string
		for _, a := range strings.Split(list, "|") {
			a = strings.TrimSpace(a)
			if a == "" {
				return nil, false
			}
			allowed = append(allowed, a)
		}
		rules = append(rules, govcsRule{pattern: pattern, allowed: allowed})
	}
	return rules, true
}

// defaultGovcsRules is real go's own built-in fallback
// (cmd/go/internal/vcs's defaultGOVCS), implicitly appended after any
// explicit GOVCS entries: a private module (one matching GOPRIVATE) may
// use any VCS, a public one is restricted to git or hg. "The rationale
// behind allowing only Git and Mercurial is that these two systems have
// had the most attention to issues of being run as clients of untrusted
// servers" (`go help vcs`).
var defaultGovcsRules = []govcsRule{
	{pattern: "private", allowed: []string{"all"}},
	{pattern: "public", allowed: []string{"git", "hg"}},
}

// govcsAllowsGit reports whether GOVCS permits a direct (non-proxy) git
// fetch of modulePath. A path is "private" for GOVCS's own "public"/
// "private" pseudo-patterns exactly when it matches goprivate's patterns —
// not gonosumdb's, a distinct resolved value from the one audit() checks —
// per `go help private`: "The GOPRIVATE variable is also used to define
// the 'public' and 'private' patterns for the GOVCS variable." Rules are
// tried in order, explicit GOVCS entries first, real go's own default
// rules (private:all, public:git|hg) last — the earliest matching pattern
// wins and no later rule is ever consulted, exactly mirroring
// cmd/go/internal/vcs's govcsConfig.allow, including its use of the
// identical module.MatchPrefixPatterns algorithm matchesPrefixPattern
// already reimplements here for GOPRIVATE/GONOSUMDB matching — confirmed
// against go's own source (vcs.go's govcsConfig.allow calls
// module.MatchPrefixPatterns for every non-public/private pattern, the
// same function GOPRIVATE matching uses).
//
// An unparseable GOVCS value (see parseGovcsRules) fails open (reports
// true, "not confirmed blocked") rather than guessing: a malformed GOVCS
// makes every module-aware go subcommand needing a direct VCS fetch Fatal
// on ITS OWN malformed-environment error, before resolving anything — a
// different "cannot leak" skip this package doesn't attempt to
// special-case (see parseGovcsRules).
//
// Matches patterns (both the GOPRIVATE-derived public/private classification
// and any explicit, non-public/private GOVCS entry) against
// vcsStaticRepoRoot(modulePath) whenever modulePath resolves to one (github.
// com- or bitbucket.org-hosted, or any host spelling out a literal VCS-
// suffix segment — see generalVCSSuffixPattern), not modulePath itself: real
// cmd/go's checkGOVCS
// (internal/vcs/vcs.go) always classifies and matches against the
// VCS-resolved repo root (see githubRepoPattern's/bitbucketRepoPattern's doc
// comments), so a GOPRIVATE/GOVCS pattern more specific than that root —
// naming a "/v2"-suffixed or monorepo-nested import path exactly, rather
// than just the bare owner/repo — can match modulePath directly while never
// matching the truncated root real go actually checks it against.
// Live-verified (2026-10-02, go1.24.4) for github.com: with
// GOVCS="github.com/googleapis/gax-go/v2:off" (naming the exact import path
// of a real module that lives in an actual "v2" subdirectory of its repo)
// and no GOPRIVATE coverage, `go mod download -x
// github.com/googleapis/gax-go/v2@v2.12.0` performs a completely ordinary
// git clone (root "github.com/googleapis/gax-go" doesn't match the
// "/v2"-suffixed pattern) and goes on to query
// `sum.golang.org/lookup/github.com/googleapis/gax-go/v2@v2.12.0` — a real
// leak. Live-verified again (2026-10-03, go1.24.4) for bitbucket.org, the
// other statically-rooted host (see bitbucketRepoPattern): with
// GOVCS="bitbucket.org/owner/repo/subpkg:off" and no GOPRIVATE coverage,
// `go mod download` for bitbucket.org/owner/repo/subpkg@<version> likewise
// skips the "GOVCS disallows" Fatal and proceeds to an ordinary git fetch
// attempt, while GOVCS="bitbucket.org/owner/repo:off" (the truncated root)
// Fatals immediately. Before this fix, govcsAllowsGit matched a github.com
// OR bitbucket.org ":off" rule against the full modulePath directly,
// reported git as disallowed, and filterGovcsDisallowed silently dropped
// the exact module from the SUMDB LEAK audit in both cases — a false
// negative on a real, uncovered private-auth signal. Live-verified again
// (2026-10-03, go1.24.4) for generalVCSSuffixPattern's any-host, literal-
// VCS-suffix shape (e.g. "example.com/foo/bar.git/sub"): see that pattern's
// own doc comment for the exact commands and output. Scoped to
// vcsStaticRepoRoot's own scope (github.com, bitbucket.org, or any host
// with a literal VCS-suffix segment): every other host keeps matching
// against modulePath unchanged, same as before this fix.
func govcsAllowsGit(modulePath, govcs, goprivate string) bool {
	rules, ok := parseGovcsRules(govcs)
	if !ok {
		return true
	}
	matchPath := modulePath
	if root := vcsStaticRepoRoot(modulePath); root != "" {
		matchPath = root
	}
	private := matchesAnyPattern(matchPath, splitPatterns(goprivate))
	for _, rule := range append(rules, defaultGovcsRules...) {
		matched := false
		switch rule.pattern {
		case "public":
			matched = !private
		case "private":
			matched = private
		default:
			matched = matchesPrefixPattern(rule.pattern, matchPath)
		}
		if !matched {
			continue
		}
		for _, a := range rule.allowed {
			if a == "git" || a == "all" {
				return true
			}
		}
		return false
	}
	return true // unreachable: defaultGovcsRules always matches something
}

// filterGovcsDisallowed drops any module GOVCS disallows fetching via a
// direct git invocation — see govcsAllowsGit. Every private-auth signal
// this tool recognizes (a git insteadOf rewrite, a URL-scoped credential
// helper, an extraHeader, or a netrc entry) only ever authenticates a
// direct `git` fetch; none of them do anything for a module served through
// a GOPROXY module proxy instead, which `go help vcs` confirms is "always
// permitted" regardless of GOVCS ("When downloading modules from a proxy,
// 'go get' uses the proxy protocol instead"). So a module GOVCS blocks
// git for can never reach the one fetch path any of this tool's signals
// apply to — real go Fatals with "GOVCS disallows using git for ..." the
// moment it would otherwise attempt that fetch, before ever computing a
// hash to send to the checksum database. This is a real, documented
// hardening pattern (`go help vcs` itself recommends GOVCS=*:off-style
// restrictions "to balance the functionality and security concerns" of
// running arbitrary VCS commands against untrusted servers), not a
// contrived one — e.g. GOVCS=*:off forcing every fetch through a trusted
// proxy, left in place alongside a leftover insteadOf rewrite from before
// that hardening was adopted.
//
// Like filterGoSumCovered, this narrows the modules considered for a
// SUMDB LEAK finding rather than skipping the whole audit: a GOVCS
// restriction this narrow (one host/org, not every module) leaves every
// other require's own sumdb-leak exposure untouched.
func filterGovcsDisallowed(modules []string, goprivate, govcs string) []string {
	if govcs == "" {
		return modules
	}
	out := make([]string, 0, len(modules))
	for _, m := range modules {
		if !govcsAllowsGit(m, govcs, goprivate) {
			continue
		}
		out = append(out, m)
	}
	return out
}
