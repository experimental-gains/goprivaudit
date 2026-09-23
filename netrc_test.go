package main

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestPrivatePrefixesFromNetrc(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "complete entry",
			data: "machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n",
			want: []string{"git.privatecorp.internal"},
		},
		{
			name: "one-line form",
			data: "machine git.privatecorp.internal login builder password s3cr3t",
			want: []string{"git.privatecorp.internal"},
		},
		{
			name: "missing password ignored, matching go's own parser",
			data: "machine git.privatecorp.internal\nlogin builder\n",
			want: nil,
		},
		{
			name: "missing login ignored, matching go's own parser",
			data: "machine git.privatecorp.internal\npassword s3cr3t\n",
			want: nil,
		},
		{
			name: "known public host excluded",
			data: "machine github.com\nlogin builder\npassword s3cr3t\n",
			want: nil,
		},
		{
			name: "multiple entries, deduped",
			data: "machine a.internal\nlogin x\npassword y\n" +
				"machine b.internal\nlogin x\npassword y\n" +
				"machine a.internal\nlogin x2\npassword y2\n",
			want: []string{"a.internal", "b.internal"},
		},
		{
			name: "macdef body not scanned for machine tokens",
			data: "macdef mymacro\nmachine fake.internal login x password y\n\n" +
				"machine real.internal\nlogin builder\npassword s3cr3t\n",
			want: []string{"real.internal"},
		},
		{
			// Regression test (mutation testing, run #125): a LIVED
			// CONDITIONALS_NEGATION mutant on `line == ""` (the macro-exit
			// check) went undetected by the single-body-line case above,
			// because on the very first non-blank body line, both the
			// correct code and the `!=` mutant hit the same `continue` —
			// one via "still in macro, skip this line", the other via
			// "macro just ended, skip this line too". The mutant only
			// diverges on the *second* body line: it wrongly treats the
			// macro as already closed and parses that line as real config.
			// A two-line macro body is the minimum case that catches it.
			name: "multi-line macdef body not scanned for machine tokens",
			data: "macdef mymacro\nmachine fake1.internal login x password y\n" +
				"machine fake2.internal login x password y\n\n" +
				"machine real.internal\nlogin builder\npassword s3cr3t\n",
			want: []string{"real.internal"},
		},
		{
			name: "default token stops processing",
			data: "machine before.internal\nlogin x\npassword y\n" +
				"default\nlogin anon\npassword anon\n" +
				"machine after.internal\nlogin x\npassword y\n",
			want: []string{"before.internal"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := privatePrefixesFromNetrc([]byte(tt.data))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("privatePrefixesFromNetrc(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// TestRunFindsLeakViaNetrc covers a private-module auth path this tool
// previously missed entirely: netrc credentials, the default GOAUTH
// mechanism (`go help goauth`) `go` uses for HTTPS module fetches, with no
// git insteadOf rewrite involved at all. Verified live (see decision log)
// that the pre-fix tool reported "no issues found" for exactly this setup
// — the private-auth signal it looked for was insteadOf-only, so a module
// authenticated purely via ~/.netrc, with GOPRIVATE not covering it, was a
// real, silent sumdb leak the tool gave a clean bill of health.
func TestRunFindsLeakViaNetrc(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".netrc", "machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n")
	t.Setenv("HOME", home)

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.privatecorp.internal/team/widgets v1.2.3
`)

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod, "-private", "", "-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.privatecorp.internal/team/widgets") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakViaNetrcEvenWithGoauthOff is the regression test for the
// bug fixed here: an earlier version of this tool only treated a netrc
// `machine` entry as a signal when the effective GOAUTH value included
// "netrc", on the theory that GOAUTH=off means "`go` never reads netrc at
// all." That's false for the common case this tool exists to catch — a
// direct VCS fetch of an uncovered private module, which `go` hands off to
// a `git` subprocess. GOAUTH (`go help goauth`) only governs the `go`
// command's own HTTP client (go-import discovery, GOPROXY mirror auth); it
// has no effect on `git`, which has no notion of GOAUTH and always
// consults ~/.netrc itself for a plain HTTPS remote. Verified live (see
// decision log): with GOAUTH=off and no credential helper or insteadOf
// configured, a bare `git` fetch against a Basic-Auth-protected HTTPS
// server still succeeds via ~/.netrc alone, and a real `go get` against a
// GOINSECURE-allowed HTTP git server reproduces the same thing end to end
// — it resolves and starts downloading the module via the netrc-
// authenticated fetch despite GOAUTH=off. So the pre-fix tool's "off means
// skip it" behavior was a false negative: exactly the setup
// TestRunFindsLeakViaNetrc covers, just with GOAUTH explicitly set to
// "off", used to report a clean bill of health.
func TestRunFindsLeakViaNetrcEvenWithGoauthOff(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".netrc", "machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n")
	t.Setenv("HOME", home)
	t.Setenv("GOAUTH", "off")

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.privatecorp.internal/team/widgets v1.2.3
`)

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod, "-private", "", "-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.privatecorp.internal/team/widgets") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunRespectsNETRCEnvOverride covers the NETRC env var, which both
// go's own auth package and this tool's netrcPath honor in place of
// $HOME/.netrc.
func TestRunRespectsNETRCEnvOverride(t *testing.T) {
	dir := t.TempDir()
	netrcFile := writeFile(t, dir, "custom-netrc", "machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n")
	t.Setenv("HOME", t.TempDir()) // no ~/.netrc
	t.Setenv("NETRC", netrcFile)

	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.privatecorp.internal/team/widgets v1.2.3
`)

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod, "-private", "", "-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.privatecorp.internal/team/widgets") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestNetrcPathIgnoresLegacyUnderscoreNetrcOnNonWindows directly unit-tests
// netrcPath's GOOS branch: cmd/go/internal/auth.netrcPath prefers
// $HOME/_netrc over $HOME/.netrc only on Windows. This box's GOOS is never
// "windows", so the real, unmutated code should ignore an existing _netrc
// file and resolve to .netrc regardless of what's on disk — but no test
// created a _netrc file to actually verify that, so a mutation (run #126,
// gremlins) flipping the GOOS comparison survived: without a _netrc file
// present, both the correct and the inverted condition produce the same
// $HOME/.netrc result, since the Stat check simply never finds anything.
// This doesn't need cross-compiling or mocking GOOS — the assertion is
// about the false side of the branch, which real Linux/macOS test runs
// exercise directly.
func TestNetrcPathIgnoresLegacyUnderscoreNetrcOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test asserts non-Windows behavior specifically")
	}
	home := t.TempDir()
	writeFile(t, home, ".netrc", "machine example.com\nlogin a\npassword b\n")
	writeFile(t, home, "_netrc", "machine example.com\nlogin c\npassword d\n")
	t.Setenv("HOME", home)
	t.Setenv("NETRC", "")

	want := home + "/.netrc"
	if got := netrcPath(); got != want {
		t.Errorf("netrcPath() = %q, want %q (should ignore _netrc on GOOS=%s)", got, want, runtime.GOOS)
	}
}
