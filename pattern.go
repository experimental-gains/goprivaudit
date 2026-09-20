package main

import (
	"path"
	"strings"
)

// matchesPrefixPattern reports whether modulePath is covered by pattern,
// using the same glob-per-path-segment, prefix-match semantics that the go
// command applies to GOPRIVATE/GONOPROXY/GONOSUMDB (see `go help
// goproxy`): each comma-separated pattern is split on "/", each segment is
// matched against the corresponding module path segment with path.Match,
// and a pattern with fewer segments than the module path still matches (it
// covers everything under that prefix).
func matchesPrefixPattern(pattern, modulePath string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return false
	}
	pSegs := strings.Split(pattern, "/")
	mSegs := strings.Split(modulePath, "/")
	if len(pSegs) > len(mSegs) {
		return false
	}
	for i, p := range pSegs {
		ok, err := path.Match(p, mSegs[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// matchesAnyPattern reports whether modulePath is covered by any pattern in
// the comma-separated GOPRIVATE-style pattern list.
func matchesAnyPattern(modulePath string, patterns []string) bool {
	for _, p := range patterns {
		if matchesPrefixPattern(p, modulePath) {
			return true
		}
	}
	return false
}

// splitPatterns splits a GOPRIVATE/GONOPROXY/GONOSUMDB-style comma
// separated env value into its individual patterns, dropping empties.
func splitPatterns(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isOverlyBroadPattern reports whether pattern matches essentially every
// module path regardless of host/org, which silently disables sumdb
// checksum verification for public dependencies too, not just the intended
// private ones.
func isOverlyBroadPattern(pattern string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	segs := strings.Split(pattern, "/")
	return len(segs) == 1 && (segs[0] == "*" || segs[0] == "**")
}
