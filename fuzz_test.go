package main

import (
	"strings"
	"testing"

	"golang.org/x/mod/module"
)

// FuzzMatchesPrefixPattern diffs matchesPrefixPattern against
// golang.org/x/mod/module.MatchPrefixPatterns, the Go team's own
// implementation of the same GOPRIVATE/GONOPROXY/GONOSUMDB prefix-glob
// algorithm (see pattern.go's doc comment). Restricts the target to inputs
// module.CheckPath accepts, since those are the only module paths a real
// go.mod could ever hand this tool — the same restriction run #81 used for
// goproxycheck's fuzz targets, after an earlier unrestricted run turned up
// only toolchain-unreachable inputs. Also excludes patterns containing a
// raw comma: matchesPrefixPattern is only ever called with an
// already-comma-split pattern (see splitPatterns in pattern.go and its
// call site in main.go), while module.MatchPrefixPatterns treats a comma
// as a multi-pattern separator — comparing the two on a pattern with a
// literal comma tests an input goprivaudit never actually receives, as an
// initial unrestricted run confirmed (matchesPrefixPattern("*,", "0.0")
// disagreeing with the oracle, which is expected given the different
// comma handling, not a real bug).
func FuzzMatchesPrefixPattern(f *testing.F) {
	seeds := []struct{ pattern, target string }{
		{"*", "github.com/foo/bar"},
		{"*/*", "github.com/foo/bar"},
		{"*/**", "github.com/foo/bar"},
		{"github.com/*", "github.com/foo/bar"},
		{"github.com/foo/*", "github.com/foo/bar"},
		{"github.com/foo", "github.com/foo/bar"},
		{"gopkg.in/*.v1", "gopkg.in/yaml.v1"},
		{"a[/]b", "a/b/c"},
		{"**", "x"},
		{"*.corp.example.com", "eng.corp.example.com/tools"},
		{"github.com/myorg/", "github.com/myorg/foo"},
		{"[", "github.com/foo/bar"},
		{`*\/0`, "0.0/0"}, // the backslash-escape case this fuzz target found and fixed
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.target)
	}
	f.Fuzz(func(t *testing.T, pattern, target string) {
		if pattern == "" || target == "" || strings.Contains(pattern, ",") {
			return
		}
		if err := module.CheckPath(target); err != nil {
			return
		}
		got := matchesPrefixPattern(pattern, target)
		want := module.MatchPrefixPatterns(pattern, target)
		if got != want {
			t.Fatalf("matchesPrefixPattern(%q, %q) = %v, want %v (oracle: x/mod MatchPrefixPatterns)",
				pattern, target, got, want)
		}
	})
}

// FuzzOverlyBroadPatternConsistency checks that isOverlyBroadPattern's
// classification agrees with what the pattern actually matches, per the
// real x/mod oracle: a pattern it calls "broad" must match every real
// module path a bare "*" would (that's the whole point of flagging it —
// it silently disables sumdb verification just as widely). Run #80 found
// and fixed a false negative in this exact function by hand-checking one
// pattern ("*/*") against x/mod; this generalizes that check across many
// patterns and targets instead of relying on hand-picked cases.
func FuzzOverlyBroadPatternConsistency(f *testing.F) {
	seeds := []struct{ pattern, target string }{
		{"*", "github.com/foo/bar"},
		{"*/*", "github.com/foo/bar"},
		{"*/**", "gopkg.in/yaml.v2"},
		{"**/**/**", "github.com/foo/bar/baz"},
		{"github.com/myorg/*", "github.com/myorg/foo"},
		{"github.com/*", "github.com/foo/bar"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.target)
	}
	f.Fuzz(func(t *testing.T, pattern, target string) {
		if pattern == "" || target == "" || strings.Contains(pattern, ",") {
			return
		}
		if err := module.CheckPath(target); err != nil {
			return
		}
		if !isOverlyBroadPattern(pattern) {
			return
		}
		// A pattern like "*/*/*" is still "broad" in the sense this
		// function means (no real host/org constraint) but, per its own
		// doc comment, only imposes a minimum segment count — it can't
		// match a target with fewer segments than the pattern has. Only
		// assert the property against targets with enough segments,
		// same floor the pattern itself is subject to.
		if strings.Count(target, "/") < strings.Count(pattern, "/") {
			return
		}
		starMatches := module.MatchPrefixPatterns("*", target)
		patternMatches := module.MatchPrefixPatterns(pattern, target)
		if starMatches && !patternMatches {
			t.Fatalf("isOverlyBroadPattern(%q) = true, but it doesn't match %q even though a bare \"*\" does (oracle: x/mod MatchPrefixPatterns) — false claim of broadness",
				pattern, target)
		}
	})
}
