package main

import (
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

// curlParseNetrc is a from-scratch, independently-structured port of the
// installed curl 8.14.1's real lib/netrc.c parsenetrc token/state machine
// (fetched from https://github.com/curl/curl/blob/curl-8_14_1/lib/netrc.c
// and read directly, 2026-09 — the exact version this box's curl/git ship;
// confirmed against a newer libcurl master snapshot too, which rewrote this
// into a lexer but preserved the same tokenization primitives), generalized
// from "scan for one specific host, and stop the instant its credentials
// are fully found" (all curl itself needs) to "collect every machine entry
// in the file" (what this oracle needs) — the underlying token mechanics
// are unchanged: blanks (space/tab only) are skipped before each token, a
// token is any run of bytes greater than 0x20, and the scan for the next
// token unconditionally advances exactly one byte past the one just
// consumed, so landing that one byte on a '\n' resumes scanning at the very
// start of the next physical line rather than stopping — the exact
// mechanic privatePrefixesFromNetrc's own nextToken ports (see its doc
// comment for the live GIT_CURL_VERBOSE verification this is modeling).
//
// "default" is ported as the netrcDefaultMachine ("*") sentinel
// privatePrefixesFromNetrc itself now uses (see that const's doc comment
// for the live GIT_CURL_VERBOSE verification that a real "default" entry's
// login/password really do authenticate a fetch to ANY host with no
// matching "machine" line): an isolated "default" — nothing else queued
// after it on its own physical line, the conventional way it's written and
// the shape both curl's and cmd/go's docs describe ("must be after all
// machine tokens") — starts a pseudo-entry keyed on "*" the same way a
// "machine" token starts a real one, and a subsequent "machine" token once
// already inside that pseudo-entry ends scanning entirely (inDefault),
// matching the mainline shape real curl itself stops at too (parsenetrc's
// own "machine" case inside HOSTVALID stops the instant `found &
// FOUND_PASSWORD` is already set — see netrc.go's own "machine"/inDefault
// case for the fuller citation). This oracle and the function under test
// share that one deliberate, documented design choice by construction
// rather than by coincidence.
//
// Unlike stdlibParseNetrc above (kept for its own documentation value —
// it's what cmd/go's GOAUTH=netrc client, a real but DIFFERENT consumer of
// this same file, actually implements), this is the authoritative oracle
// for privatePrefixesFromNetrc specifically, since that function claims to
// model curl/git's real netrc consultation, not cmd/go's — so this fuzz
// target checks it for an EXACT match, not just a subset. It exists
// because an earlier draft of privatePrefixesFromNetrc's whitespace-
// spanning rewrite (before this oracle existed) shipped with two real bugs
// this fuzz target caught within seconds: a "macdef" line with no macro
// name at all incorrectly swallowed the next real machine entry as
// unscanned macro body (real curl does not: verified live, see
// netrc.go's doc comment), and cmd/go's own line-positional token PAIRING
// (every two tokens on a line form a key/value pair, recognized or not)
// was mistakenly carried over into a keyword-triggered design where it
// doesn't belong, silently swallowing a real "machine"/"login"/"password"
// keyword as an unrecognized preceding token's discarded "value" — a
// quirk of cmd/go's specific implementation loop that real curl's
// parser — confirmed directly from its source, which examines and
// dispatches on exactly one token at a time regardless of whether the
// previous one was recognized — does not share.
func curlParseNetrc(data string) []stdlibNetrcLine {
	const (
		stNothing = iota
		stHostFound
		stHostValid
	)
	const (
		kwNone = iota
		kwLogin
		kwPassword
	)
	state := stNothing
	keyword := kwNone
	inMacro := false
	inDefault := false
	var out []stdlibNetrcLine
	var l stdlibNetrcLine

	commit := func() {
		if l.machine != "" && (l.login != "" || l.password != "") {
			out = append(out, l)
		}
		l = stdlibNetrcLine{}
		keyword = kwNone
	}

	// startDefault mirrors netrc.go's "default" case: commit whatever entry
	// was pending, then start a new pseudo-entry keyed on the same "*"
	// sentinel netrcDefaultMachine defines, so a following login/password
	// (read the same way a real machine's are, via stHostValid) becomes
	// this oracle's ground truth for privatePrefixesFromNetrc's own "*"
	// signal.
	startDefault := func() {
		commit()
		l.machine = netrcDefaultMachine
		inDefault = true
		state = stHostValid
	}

	// isBlank matches netrc.go's own deliberate, documented choice (see
	// privatePrefixesFromNetrc's isBlank) to treat only space/tab/CR/
	// vtab/formfeed as inter-token separators, rather than real curl's
	// literal "any byte <= 0x20" boundary — which, for a raw low control
	// byte (a real curl SYNTAX_ERROR case, verified against curl's own
	// source: `if(!len) retcode=NETRC_SYNTAX_ERROR`), produces a
	// zero-length token neither this oracle nor netrc.go has any
	// principled use for. Since this oracle exists specifically to check
	// privatePrefixesFromNetrc against what it claims to model, it shares
	// that one deliberate simplification rather than chasing exact
	// byte-for-byte curl fidelity into a corner both implementations
	// agree isn't worth it.
	isBlank := func(b byte) bool {
		switch b {
		case ' ', '\t', '\r', '\v', '\f':
			return true
		default:
			return false
		}
	}

	i, n := 0, len(data)
	for i < n {
		for i < n && isBlank(data[i]) {
			i++
		}
		if inMacro && i < n && data[i] == '\n' {
			inMacro = false
		}
		if i >= n || data[i] == '\n' {
			nl := strings.IndexByte(data[i:], '\n')
			if nl < 0 {
				break
			}
			i += nl + 1
			continue
		}
		start := i
		for i < n && !isBlank(data[i]) && data[i] != '\n' {
			i++
		}
		tok := data[start:i]
		j := i
		for j < n && isBlank(data[j]) {
			j++
		}
		atEOL := j >= n || data[j] == '\n'
		if i < n {
			i++
		}

		if inMacro {
			continue
		}

		switch state {
		case stNothing:
			switch tok {
			case "macdef":
				inMacro = true
			case "machine":
				commit()
				state = stHostFound
			case "default":
				if atEOL {
					startDefault()
				}
			}
		case stHostFound:
			l.machine = tok
			state = stHostValid
		case stHostValid:
			switch {
			case keyword == kwLogin:
				l.login = tok
				keyword = kwNone
			case keyword == kwPassword:
				l.password = tok
				keyword = kwNone
			case tok == "login":
				keyword = kwLogin
			case tok == "password":
				keyword = kwPassword
			case tok == "machine":
				if inDefault {
					commit()
					return out
				}
				commit()
				state = stHostFound
			case tok == "default":
				if atEOL {
					if inDefault {
						commit()
						return out
					}
					startDefault()
				}
			}
		}
	}
	commit()
	return out
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
		"machine a.internal\nlogin\nbuilder\npassword\ns3cr3t\n",
		"macdef \nmachine a.internal login x password y\n",
		"default 0 machine a.internal login x password y\n",
		"0 password machine a.internal login x password y\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		got := privatePrefixesFromNetrc([]byte(data))
		gotSet := map[string]bool{}
		for _, m := range got {
			gotSet[m] = true
		}

		// curlParseNetrc is the authoritative, exact-match oracle now —
		// see its own doc comment for why it, not stdlibParseNetrc
		// (cmd/go's own, DIFFERENT real netrc consumer), is what
		// privatePrefixesFromNetrc actually claims to model.
		want := map[string]bool{}
		for _, l := range curlParseNetrc(data) {
			if !isKnownPublicHost(l.machine) {
				want[l.machine] = true
			}
		}
		for m := range want {
			if !gotSet[m] {
				t.Fatalf("privatePrefixesFromNetrc(%q) = %v, missing %q found by curlParseNetrc", data, got, m)
			}
		}
		for m := range gotSet {
			if !want[m] {
				t.Fatalf("privatePrefixesFromNetrc(%q) = %v, extra %q not found by curlParseNetrc", data, got, m)
			}
		}
	})
}
