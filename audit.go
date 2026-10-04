package main

import "sort"

// Report is the result of auditing a module's dependencies against its
// GOPRIVATE-family configuration.
type Report struct {
	// SumdbLeaks are modules that have a private-auth signal (a git
	// insteadOf rewrite, URL-scoped credential helper, or URL-scoped
	// extraHeader pointing at their host/path, or a netrc machine entry
	// for their host, when GOAUTH
	// actually consults netrc) but aren't covered by GOPRIVATE or
	// GONOSUMDB. Even though the source
	// fetch itself is authenticated, `go` still queries the public
	// checksum database (sum.golang.org) for these modules unless they're
	// excluded, leaking the module's path and version to Google.
	SumdbLeaks []string
	// BroadPatterns are GOPRIVATE/GONOSUMDB patterns that match every
	// module path regardless of host, which silently disables sumdb
	// verification for public dependencies too, not just private ones.
	BroadPatterns []string
}

func (r Report) Clean() bool {
	return len(r.SumdbLeaks) == 0 && len(r.BroadPatterns) == 0
}

// audit checks each required module against the effective GOPRIVATE and
// GONOSUMDB pattern lists. Per `go help goproxy`, GOPRIVATE is a fallback
// default for GONOSUMDB (and GONOPROXY) when they're not set explicitly, so
// the caller passes the already-resolved effective values.
func audit(modules []string, privatePrefixes []string, gonosumdb []string) Report {
	var r Report

	leaking := map[string]bool{}
	for _, m := range modules {
		if !matchesAnyPattern(m, privatePrefixes) {
			continue // no private-auth signal for this module at all
		}
		if matchesAnyPattern(m, gonosumdb) {
			continue // covered, no leak
		}
		if !leaking[m] {
			leaking[m] = true
			r.SumdbLeaks = append(r.SumdbLeaks, m)
		}
	}
	sort.Strings(r.SumdbLeaks)

	seen := map[string]bool{}
	for _, p := range gonosumdb {
		if isOverlyBroadPattern(p) && !seen[p] {
			seen[p] = true
			r.BroadPatterns = append(r.BroadPatterns, p)
		}
	}
	sort.Strings(r.BroadPatterns)

	return r
}

// suppressInsteadOfSignals narrows leaks based on git's real handling of
// the single insteadOf rule that actually applies to each module (see
// insteadOfApplicableRule, which implements git's documented
// longest-match-wins precedence):
//
//   - no insteadOf rule matches the module at all: its finding is backed
//     entirely by an independent signal (credential.helper,
//     http.extraHeader, or netrc) and is left untouched.
//   - the applicable rule's target transport is blocked by
//     protocol.allow/GIT_ALLOW_PROTOCOL (see gitProtocolAllowed): git's
//     own URL rewriting is unconditional, applied before any transport is
//     ever chosen — once it resolves to a blocked scheme, the whole fetch
//     Fatals (e.g. "fatal: transport 'ssh' not allowed") and NEVER falls
//     back to attempting the original, unrewritten URL. Live-verified
//     (2026-10-04, git 2.47.3): with an insteadOf rewrite to a blocked ssh
//     target AND an independent credential helper scoped to the exact
//     same (un-rewritten) https URL, `git ls-remote` on that URL still
//     fails with "fatal: transport 'ssh' not allowed" — the credential
//     helper is never even reached. So the module is dropped
//     unconditionally here, regardless of otherPrefixes: an "independent"
//     signal for the same URL the insteadOf rule rewrites away from can
//     never actually be reached either.
//   - the applicable rule is a no-op (rewrites the URL to itself, see
//     isInsteadOfNoop): git performs no rewrite at all, so the ordinary
//     fetch of the original URL proceeds — an independent signal for the
//     same module (otherPrefixes) keeps its finding, since it authenticates
//     that same, un-rewritten fetch; the insteadOf rule itself contributes
//     no signal of its own.
//   - otherwise: a genuine, allowed, non-no-op insteadOf rewrite — the
//     finding stands.
func suppressInsteadOfSignals(leaks []string, rules []insteadOfRule, otherPrefixes []string, protocolAllow map[string]string, getenv func(string) string) []string {
	if len(rules) == 0 {
		return leaks
	}
	out := make([]string, 0, len(leaks))
	for _, m := range leaks {
		r, ok := insteadOfApplicableRule(m, rules)
		if !ok {
			out = append(out, m)
			continue
		}
		if !gitProtocolAllowed(r.scheme, protocolAllow, getenv) {
			continue
		}
		if !r.noop || matchesAnyPattern(m, otherPrefixes) {
			out = append(out, m)
		}
	}
	return out
}
