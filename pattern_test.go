package main

import "testing"

func TestMatchesPrefixPattern(t *testing.T) {
	cases := []struct {
		pattern, module string
		want            bool
	}{
		{"github.com/myorg/*", "github.com/myorg/foo", true},
		{"github.com/myorg/*", "github.com/myorg/foo/bar", true},
		{"github.com/myorg/*", "github.com/otherorg/foo", false},
		{"github.com/myorg", "github.com/myorg/foo", true}, // prefix match, fewer segments
		{"github.com/myorg", "github.com/myorgtypo/foo", false},
		{"*", "anything.com/x/y", true},
		{"*.corp.example.com", "eng.corp.example.com/tools", true},
		{"*.corp.example.com", "example.com/tools", false},
		{"github.com/myorg/", "github.com/myorg/foo", true}, // trailing slash ignored
		{"", "github.com/myorg/foo", false},
		// A backslash-escaped "/" inside a pattern segment is valid
		// path.Match glob syntax; the real go command's algorithm (which
		// truncates modulePath by raw slash count in pattern, then runs
		// one path.Match on the whole prefix) honors the escape. A prior
		// per-segment implementation split on "/" before matching,
		// silently breaking this. Found by a fuzz pass diffing against
		// golang.org/x/mod/module.MatchPrefixPatterns (see fuzz_test.go).
		{`*\/0`, "0.0/0", true},
	}
	for _, c := range cases {
		got := matchesPrefixPattern(c.pattern, c.module)
		if got != c.want {
			t.Errorf("matchesPrefixPattern(%q, %q) = %v, want %v", c.pattern, c.module, got, c.want)
		}
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	patterns := []string{"github.com/myorg/*", "example.com/other"}
	if !matchesAnyPattern("github.com/myorg/foo", patterns) {
		t.Error("expected match on first pattern")
	}
	if !matchesAnyPattern("example.com/other/sub", patterns) {
		t.Error("expected match on second pattern (prefix)")
	}
	if matchesAnyPattern("github.com/unrelated/foo", patterns) {
		t.Error("expected no match")
	}
	if matchesAnyPattern("github.com/myorg/foo", nil) {
		t.Error("expected no match against empty pattern list")
	}
}

// TestSplitPatterns checks that splitPatterns only splits on comma and
// drops genuinely empty entries, without trimming surrounding whitespace
// from the patterns it keeps — real `go`'s own
// golang.org/x/mod/module.MatchPrefixPatterns never trims a glob either,
// so a leading/trailing space around a pattern is part of the glob, not
// noise to clean up. A version of this test that expected trimming used
// to lock in a real divergence from `go`'s behavior; see splitPatterns'
// doc comment and TestSplitPatterns_LeadingSpaceBreaksMatch below.
func TestSplitPatterns(t *testing.T) {
	got := splitPatterns(" github.com/myorg/*, example.com/other ,,")
	want := []string{" github.com/myorg/*", " example.com/other "}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
	if splitPatterns("") != nil {
		t.Error("expected nil for empty input")
	}
}

// TestSplitPatterns_LeadingSpaceBreaksMatch is the regression case for the
// real bug goproxycheck v0.1.23 found and fixed first (live differential
// testing against golang.org/x/mod and `go mod download -x`): a pattern
// with a leading space (as produced by a comma-separated list written
// with ", " for readability, e.g. GONOSUMDB="nomatch/*, golang.org/x/text")
// must NOT match the unspaced module path, exactly like real `go` — so
// goprivaudit must not silently treat that module as covered by
// GOPRIVATE/GONOSUMDB when real `go` still sends it to the checksum
// database.
func TestSplitPatterns_LeadingSpaceBreaksMatch(t *testing.T) {
	patterns := splitPatterns("nomatch/*, golang.org/x/text")
	if matchesAnyPattern("golang.org/x/text", patterns) {
		t.Errorf("matchesAnyPattern matched %q against patterns %v, but real `go` does not match a glob with a leading space against an unspaced module path", "golang.org/x/text", patterns)
	}
}

func TestIsOverlyBroadPattern(t *testing.T) {
	broad := []string{"*", "**", "*/", "*/*", "*/**", "**/**", "*/*/*"}
	for _, p := range broad {
		if !isOverlyBroadPattern(p) {
			t.Errorf("expected %q to be flagged as overly broad", p)
		}
	}
	notBroad := []string{"github.com/myorg/*", "*.corp.example.com", "github.com", "github.com/*"}
	for _, p := range notBroad {
		if isOverlyBroadPattern(p) {
			t.Errorf("expected %q to NOT be flagged as overly broad", p)
		}
	}
}
