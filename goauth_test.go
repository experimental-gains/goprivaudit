package main

import (
	"os"
	"strings"
	"testing"
)

// TestGoAuthConfigError covers goAuthConfigError against the GOAUTH shapes
// confirmed live (2026-10-03) to make real cmd/go's own GOAUTH parsing
// (runGoAuth, cmd/go/internal/auth/auth.go) Fatal outright — entirely
// offline, before the process's first HTTPS request — and the well-formed
// shapes that must NOT trigger a false positive here (a false positive
// would make run() skip a real, otherwise-reportable SUMDB LEAK).
func TestGoAuthConfigError(t *testing.T) {
	absDir := t.TempDir()
	absFile := absDir + "/not-a-dir"
	if err := os.WriteFile(absFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		raw        string
		wantErr    bool
		wantSubstr string
	}{
		{"default netrc", "netrc", false, ""},
		{"off alone", "off", false, ""},
		{"custom command alone", "mycompany-auth-helper --flag", false, ""},
		{"netrc then custom command", "netrc;mycompany-auth-helper", false, ""},
		{"well-formed git with real absolute dir", "git " + absDir, false, ""},
		// Confirmed live: `GOAUTH="off;netrc" GOFLAGS=-mod=mod go build`
		// Fatals in ~3ms, before issuing the request that would otherwise
		// have leaked the module to sum.golang.org.
		{"off combined with netrc", "off;netrc", true, "cannot be combined"},
		{"netrc combined with off", "netrc;off", true, "cannot be combined"},
		// Confirmed live: a stray leading/trailing/doubled semicolon — a
		// natural copy-paste or templating typo — produces this exact Fatal.
		{"trailing semicolon", "netrc;", true, "empty command"},
		{"leading semicolon", ";netrc", true, "empty command"},
		{"doubled semicolon", "netrc;;netrc", true, "empty command"},
		{"whitespace-only entry", "netrc; ;netrc", true, "empty command"},
		{"empty string", "", true, "empty command"},
		{"git with no dir argument", "git", true, "absolute path to the git working directory"},
		{"git with extra argument", "git /abs/dir extra", true, "absolute path to the git working directory"},
		{"git with relative dir", "git relative/dir", true, "dir is not absolute"},
		{"git with nonexistent dir", "git " + absDir + "/does-not-exist", true, "cannot stat"},
		{"git with dir that is a file, not a directory", "git " + absFile, true, "dir is not a directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := goAuthConfigError(c.raw)
			if (err != nil) != c.wantErr {
				t.Fatalf("goAuthConfigError(%q) = %v, want error: %v", c.raw, err, c.wantErr)
			}
			if c.wantErr && !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("goAuthConfigError(%q) = %v, want it to contain %q", c.raw, err, c.wantSubstr)
			}
		})
	}
}
