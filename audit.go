package main

import "sort"

// Report is the result of auditing a module's dependencies against its
// GOPRIVATE-family configuration.
type Report struct {
	// SumdbLeaks are modules that have a private-auth signal (a git
	// insteadOf rewrite pointing at their host/path, or a netrc machine
	// entry for their host, when GOAUTH actually consults netrc) but
	// aren't covered by GOPRIVATE or GONOSUMDB. Even though the source
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
