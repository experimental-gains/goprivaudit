package main

import (
	"reflect"
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

func TestGoauthUsesNetrc(t *testing.T) {
	tests := []struct {
		goauth string
		want   bool
	}{
		{"netrc", true},
		{"off", false},
		{"git /home/me/.git-creds", false},
		{"netrc;off", true},
		{"off;netrc", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := goauthUsesNetrc(tt.goauth); got != tt.want {
			t.Errorf("goauthUsesNetrc(%q) = %v, want %v", tt.goauth, got, tt.want)
		}
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
		"-gomod", gomod, "-private", "", "-nosumdb", "", "-goauth", "netrc",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.privatecorp.internal/team/widgets") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunIgnoresNetrcWhenGoauthDoesNotUseIt covers the flip side: if GOAUTH
// has been overridden away from netrc (e.g. "off", or a custom command
// list that dropped the default), `go` never reads ~/.netrc at all, and
// treating its contents as a signal anyway would be a false positive, not
// the real leak this tool exists to catch.
func TestRunIgnoresNetrcWhenGoauthDoesNotUseIt(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".netrc", "machine git.privatecorp.internal\nlogin builder\npassword s3cr3t\n")
	t.Setenv("HOME", home)

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.privatecorp.internal/team/widgets v1.2.3
`)

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod, "-private", "", "-nosumdb", "", "-goauth", "off",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
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
		"-gomod", gomod, "-private", "", "-nosumdb", "", "-goauth", "netrc",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.privatecorp.internal/team/widgets") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}
