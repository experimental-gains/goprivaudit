package main

import "strings"

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
func govcsAllowsGit(modulePath, govcs, goprivate string) bool {
	rules, ok := parseGovcsRules(govcs)
	if !ok {
		return true
	}
	private := matchesAnyPattern(modulePath, splitPatterns(goprivate))
	for _, rule := range append(rules, defaultGovcsRules...) {
		matched := false
		switch rule.pattern {
		case "public":
			matched = !private
		case "private":
			matched = private
		default:
			matched = matchesPrefixPattern(rule.pattern, modulePath)
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
