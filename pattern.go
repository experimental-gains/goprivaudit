package main

import (
	"path"
	"strings"
)

// matchesPrefixPattern reports whether modulePath is covered by pattern,
// mirroring golang.org/x/mod/module.MatchPrefixPatterns exactly (the same
// algorithm the real `go` command applies to GOPRIVATE/GONOPROXY/
// GONOSUMDB, see `go help goproxy`): count the path separators in pattern
// to find how many leading segments of modulePath to keep as a prefix,
// then run a single path.Match of pattern against that whole prefix — not
// a per-segment path.Match, which silently breaks backslash-escaped
// separators and bracket expressions containing "/" (both valid
// path.Match glob syntax the real go command still honors correctly). A
// fuzz pass diffing an earlier per-segment implementation against the
// real x/mod oracle found exactly this divergence: matchesPrefixPattern
// ("*\\/0", "0.0/0") returned false while go's own algorithm returns
// true. Reimplemented locally rather than importing x/mod at runtime —
// this tool audits supply-chain/dependency-configuration risk, so it
// stays dependency-free by design; x/mod is only a test-only dependency
// (see fuzz_test.go).
func matchesPrefixPattern(pattern, modulePath string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return false
	}
	n := strings.Count(pattern, "/")
	prefix := modulePath
	for i := 0; i < len(modulePath); i++ {
		if modulePath[i] == '/' {
			if n == 0 {
				prefix = modulePath[:i]
				break
			}
			n--
		}
	}
	if n > 0 {
		return false // modulePath has fewer segments than pattern requires
	}
	ok, err := path.Match(pattern, prefix)
	return err == nil && ok
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
// private ones. A pattern is broad if every one of its segments is a bare
// wildcard ("*" or "**") — per matchesPrefixPattern's prefix semantics
// (mirroring the real `go` command's golang.org/x/mod/module.
// MatchPrefixPatterns, verified live), such a pattern imposes no actual
// host/org constraint at all, just a minimum segment count, and almost
// every real module path (github.com/org/repo, gopkg.in/pkg.vN, ...) has
// at least 2-3 segments. Confirmed empirically: GONOSUMDB="*/*" matches
// github.com/sirupsen/logrus, golang.org/x/mod, and gopkg.in/yaml.v2 alike
// — just as broad as a bare "*" in practice, not the more-targeted pattern
// its extra "/*" suggests to a human reading it.
func isOverlyBroadPattern(pattern string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	for _, s := range strings.Split(pattern, "/") {
		if s != "*" && s != "**" {
			return false
		}
	}
	return true
}
