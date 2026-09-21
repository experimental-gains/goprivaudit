package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// captureRun runs run() with stdout/stderr redirected to temp files and
// returns their contents plus the exit code, so tests don't depend on `go
// env` or the real filesystem's ~/.gitconfig.
func captureRun(t *testing.T, args []string) (stdout, stderr string, code int) {
	t.Helper()
	outFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	code = run(args, outFile, errFile)
	outFile.Close()
	errFile.Close()
	outBytes, _ := os.ReadFile(outFile.Name())
	errBytes, _ := os.ReadFile(errFile.Name())
	return string(outBytes), string(errBytes), code
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunFindsLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	// Isolate from the real environment: HOME points at an empty temp dir
	// with no ~/.gitconfig, so only the repo's .git/config is read.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakViaGitConfigInclude covers a real, common git config
// pattern this tool previously missed entirely: an insteadOf rewrite
// living in a file pulled in via [include] rather than written directly
// in ~/.gitconfig or the repo's .git/config. Verified against real git
// (`git config --get-urlmatch`) that git resolves the rewrite from the
// included file exactly as if it were inline — the pre-fix code only
// ever scanned the two files it already knew about verbatim, so this
// config silently produced "no issues found" for a module that really
// was leaking to sumdb.
func TestRunFindsLeakViaGitConfigInclude(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".gitconfig-private", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, home, ".gitconfig", `[user]
	name = someone
[include]
	path = ~/.gitconfig-private
`)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakViaXDGGitConfig covers the git "global" config tier's
// other file: $XDG_CONFIG_HOME/git/config (or ~/.config/git/config when
// unset), which git reads in addition to ~/.gitconfig, not instead of it
// (git-config(1), "Includes"/"FILES" — verified live: `git config
// --get-regexp insteadof` with a rewrite placed only in this file, and no
// ~/.gitconfig at all, still surfaces it). The pre-fix
// gitConfigCandidates only ever listed ~/.gitconfig and the repo's
// .git/config, so a rewrite kept in the XDG location — the default git
// itself falls back to, and the location XDG-dotfiles-style setups tend
// to use — silently produced "no issues found" for a module that really
// was leaking to sumdb.
func TestRunFindsLeakViaXDGGitConfig(t *testing.T) {
	xdg := t.TempDir()
	writeFile(t, xdg, "git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir()) // no ~/.gitconfig at all
	t.Setenv("XDG_CONFIG_HOME", xdg)

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakViaGitConfigIncludeIf covers the other common form:
// [includeIf "gitdir:..."], used to scope a different rewrite (e.g. a
// work identity) to everything under one directory tree. The condition
// must actually gate the include — a module outside the matching tree
// must stay clean, or the tool would just be treating every includeIf as
// unconditional.
func TestRunFindsLeakViaGitConfigIncludeIf(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".gitconfig-work", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, home, ".gitconfig", `[includeIf "gitdir:~/work/"]
	path = ~/.gitconfig-work
`)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	gomodBody := `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`
	workGomod := writeFile(t, home, "work/app/go.mod", gomodBody)
	personalGomod := writeFile(t, home, "personal/app/go.mod", gomodBody)

	stdout, _, code := captureRun(t, []string{"-gomod", workGomod, "-private", "", "-nosumdb", ""})
	if code != 1 {
		t.Errorf("under matching gitdir: exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("under matching gitdir: stdout missing expected leak finding: %s", stdout)
	}

	stdout, _, code = captureRun(t, []string{"-gomod", personalGomod, "-private", "", "-nosumdb", ""})
	if code != 0 {
		t.Errorf("outside matching gitdir: exit code = %d, want 0 (condition shouldn't apply); stdout=%s", code, stdout)
	}
}

func TestRunClean(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/pkg/errors v0.9.1
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout = %q, want a clean-report message", stdout)
	}
}

func TestRunMissingGoMod(t *testing.T) {
	_, stderr, code := captureRun(t, []string{"-gomod", "/nonexistent/go.mod"})
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "no such file") && !strings.Contains(stderr, "cannot find") {
		t.Errorf("stderr = %q, want a file-not-found message", stderr)
	}
}

func TestRunLocallyReplacedModuleNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-lib v0.0.0-20230101000000-abcdef123456

replace github.com/myorg/internal-lib => ../internal-lib
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0: a locally-replaced module is never fetched over the network, so it can't leak to sumdb regardless of GOPRIVATE; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak for a locally-replaced module, got: %s", stdout)
	}
}

func TestRunForkReplaceChecksReplacementPath(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/upstream/lib v1.0.0

replace github.com/upstream/lib => github.com/myorg/lib-fork v1.0.0-patched
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: the replacement fork is the path actually fetched and is privately hosted; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/lib-fork") {
		t.Errorf("stdout missing expected leak on the replacement path, not the original: %s", stdout)
	}
}

func TestRunPrivateOverrideCoversLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-nosumdb", "github.com/myorg/*",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 once GONOSUMDB covers the module; stdout=%s", code, stdout)
	}
	var buf bytes.Buffer
	buf.WriteString(stdout)
	if strings.Contains(buf.String(), "SUMDB LEAK") {
		t.Errorf("expected no leak once covered, got: %s", stdout)
	}
}

// TestGitConfigCandidates covers the full candidate list directly, both
// with and without XDG_CONFIG_HOME set — the indirect XDG coverage above
// only ever checks that a rewrite in the XDG file is *found*, not that the
// candidate list itself is right, which is what actually distinguishes the
// os.UserHomeDir() err == nil branch on the XDG path from a mutant that
// skips it.
func TestGitConfigCandidates(t *testing.T) {
	home := t.TempDir()
	moduleDir := filepath.Join(home, "app")

	t.Run("XDG_CONFIG_HOME set", func(t *testing.T) {
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
		want := []string{
			filepath.Join(home, "xdg", "git", "config"),
			filepath.Join(home, ".gitconfig"),
			filepath.Join(moduleDir, ".git", "config"),
		}
		if got := gitConfigCandidates(moduleDir); !stringsEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("XDG_CONFIG_HOME unset falls back under HOME", func(t *testing.T) {
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", "")
		want := []string{
			filepath.Join(home, ".config", "git", "config"),
			filepath.Join(home, ".gitconfig"),
			filepath.Join(moduleDir, ".git", "config"),
		}
		if got := gitConfigCandidates(moduleDir); !stringsEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGoEnvCommandNotFound covers goEnv's err != nil fallback: with no `go`
// binary reachable on PATH, exec.Command must fail and goEnv must return ""
// rather than panicking or propagating the error.
func TestGoEnvCommandNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir, no `go` binary in it
	if got := goEnv("GOPROXY"); got != "" {
		t.Errorf("goEnv() with no go binary on PATH = %q, want empty", got)
	}
}

// TestGoEnvSuccess covers goEnv's normal (err == nil) path against the real
// `go` binary — without this, the only other goEnv test forces a failure,
// and since a failed `go env` invocation also yields empty output, a test
// that only ever sees empty results can't tell the success path apart from
// the failure path.
func TestGoEnvSuccess(t *testing.T) {
	want, err := exec.Command("go", "env", "GOPROXY").Output()
	if err != nil {
		t.Skipf("no working `go` binary to compare against: %v", err)
	}
	if got := goEnv("GOPROXY"); got != strings.TrimSpace(string(want)) {
		t.Errorf("goEnv(%q) = %q, want %q", "GOPROXY", got, strings.TrimSpace(string(want)))
	}
}
