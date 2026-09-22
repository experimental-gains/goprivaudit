package main

import (
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
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

// FuzzIsDirectoryPath diffs isDirectoryPath (gomod.go) against
// golang.org/x/mod/modfile.IsDirectoryPath, the real go.mod parser's own
// function for the exact same question — isDirectoryPath's doc comment
// already claims to mirror it (bare "."/".." plus the "./"/"../"/absolute
// forms), but that claim had never actually been checked against the real
// thing, only against a handful of hand-picked cases in
// TestIsDirectoryPath. Unlike gitconfig.go's real-git-subprocess oracle,
// this one's a direct importable function — x/mod is already a dependency
// (see pattern.go's fuzz targets above) — so no subprocess or corpus
// generation is needed, just the diff.
func FuzzIsDirectoryPath(f *testing.F) {
	seeds := []string{
		".", "..", "./foo", "../foo", "../../foo", "/abs/path",
		"...", "..foo", ".foo", "foo/..", "foo/.", "github.com/foo/bar",
		"", "/", "//", "./", "../", "...//foo", "C:\\foo", `.\foo`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		// Windows-style forms (a "C:" drive prefix, a backslash right
		// after a leading "."/".." component, or a bare leading
		// backslash) are excluded, matching isDirectoryPath's own doc
		// comment (".\", "..\", bare "\", a drive letter"): confirmed
		// live above, for all three shapes, that modfile.Parse itself
		// rejects any go.mod replace line whose target takes this form
		// ("replacement directory appears to be Windows path (on a
		// non-windows system)"), on this tool's own Linux host, before
		// isDirectoryPath ever runs on it — this tool's own callers can
		// never observe that input.
		if len(path) >= 2 && path[1] == ':' {
			return // drive-letter form, e.g. "C:\foo"
		}
		if strings.HasPrefix(path, "\\") || strings.HasPrefix(path, ".\\") || strings.HasPrefix(path, "..\\") {
			return
		}
		got := isDirectoryPath(path)
		want := modfile.IsDirectoryPath(path)
		if got != want {
			t.Fatalf("isDirectoryPath(%q) = %v, want %v (oracle: x/mod modfile.IsDirectoryPath)", path, got, want)
		}
	})
}

// stdlibNetrcLine and stdlibParseNetrc are a direct port of cmd/go/
// internal/auth.parseNetrc (BSD-licensed, part of the Go toolchain
// distributed at $GOROOT/src/cmd/go/internal/auth/netrc.go) — that
// package is internal and can't be imported, so this fuzz target copies
// its exact algorithm to use as a real oracle for
// privatePrefixesFromNetrc, the same job golang.org/x/mod/module does for
// the pattern-matching fuzz targets above where an importable oracle
// existed. netrc.go's own doc comment already claimed field-for-field
// parity with this algorithm; this is the first time that claim has
// actually been checked against the real thing rather than by hand.
type stdlibNetrcLine struct {
	machine, login, password string
}

func stdlibParseNetrc(data string) []stdlibNetrcLine {
	var nrc []stdlibNetrcLine
	var l stdlibNetrcLine
	inMacro := false
	for _, line := range strings.Split(data, "\n") {
		if inMacro {
			if line == "" {
				inMacro = false
			}
			continue
		}
		f := strings.Fields(line)
		i := 0
		for ; i < len(f)-1; i += 2 {
			switch f[i] {
			case "machine":
				l = stdlibNetrcLine{machine: f[i+1]}
			case "default":
				// no-op, matching the real source's inert `break` here
			case "login":
				l.login = f[i+1]
			case "password":
				l.password = f[i+1]
			case "macdef":
				inMacro = true
			}
			if l.machine != "" && l.login != "" && l.password != "" {
				nrc = append(nrc, l)
				l = stdlibNetrcLine{}
			}
		}
		if i < len(f) && f[i] == "default" {
			break
		}
	}
	return nrc
}

func FuzzPrivatePrefixesFromNetrc(f *testing.F) {
	seeds := []string{
		"machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n",
		"machine git.privatecorp.internal login builder password s3cr3t",
		"machine github.com\nlogin x\npassword y\n",
		"macdef mymacro\nmachine fake.internal login x password y\n\nmachine real.internal\nlogin builder\npassword s3cr3t\n",
		"machine before.internal\nlogin x\npassword y\ndefault\nlogin anon\npassword anon\nmachine after.internal\nlogin x\npassword y\n",
		"machine a.internal\nlogin x\npassword y\nmachine a.internal\nlogin x2\npassword y2\n",
		"login x\nmachine a.internal\npassword y\n",
		"machine\nlogin x\npassword y\n",
		"macdef m\n",
		"default\nmachine a.internal\nlogin x\npassword y\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		got := privatePrefixesFromNetrc([]byte(data))

		var want []string
		seen := map[string]bool{}
		for _, l := range stdlibParseNetrc(data) {
			if !isKnownPublicHost(l.machine) && !seen[l.machine] {
				seen[l.machine] = true
				want = append(want, l.machine)
			}
		}
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("privatePrefixesFromNetrc(%q) = %v, want %v (oracle: cmd/go/internal/auth.parseNetrc)", data, got, want)
		}
	})
}
