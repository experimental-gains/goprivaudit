package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
	_ = outFile.Close()
	_ = errFile.Close()
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

// TestRunGoSumdbOffNoLeak covers a real false-positive this tool had:
// GOSUMDB=off disables the checksum database entirely, for every module,
// per `go help module-auth` — verified live (`GOSUMDB=off go env GOSUMDB`)
// that this holds regardless of what GOPRIVATE/GONOSUMDB say. Before the
// fix, `run` never read GOSUMDB at all, so it still reported a SUMDB LEAK
// for a module with a private-auth signal but no GOPRIVATE/GONOSUMDB
// coverage — an alarm for a checksum-database query that structurally
// cannot happen in this mode.
func TestRunGoSumdbOffNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
		"-sumdb", "off",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean with GOSUMDB=off, got: %s", stdout)
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

// TestRunFindsLeakViaDefaultXDGGitConfigPath covers the other half of
// gitConfigCandidates' XDG branch: with XDG_CONFIG_HOME unset (the common
// case — every other test in this file isolates it to "" specifically so
// it doesn't leak this exact path from the real environment, but none of
// them actually populate $HOME/.config/git/config to confirm the fallback
// default is wired up), git itself still reads $HOME/.config/git/config.
// A mutation-testing pass (gremlins, run #126) found this branch's own
// condition had no test where the outcome differed from simply omitting
// the branch, because no prior test ever put a real config file at this
// path — this closes that gap with the same live-behavior assertion
// TestRunFindsLeakViaXDGGitConfig already makes for the explicit-XDG case.
func TestRunFindsLeakViaDefaultXDGGitConfigPath(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".config/git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", home) // no ~/.gitconfig, only the XDG-default file
	t.Setenv("XDG_CONFIG_HOME", "")

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

// TestGoEnvReturnsRealValue directly unit-tests goEnv's success path
// against a `go env` var guaranteed non-empty on any machine that can run
// `go` at all, rather than only exercising it indirectly through run()
// tests where the box's real GOPRIVATE/GONOSUMDB happen to already be
// empty — which made a mutation (run #126, gremlins) that made goEnv
// return "" on *success* instead of on *failure* survive undetected: the
// wrong-for-the-wrong-reason output was indistinguishable from correct
// output in every existing test's environment.
func TestGoEnvReturnsRealValue(t *testing.T) {
	got := goEnv("GOOS")
	if got == "" {
		t.Fatal("goEnv(\"GOOS\") returned empty; want a real value")
	}
	if got != runtime.GOOS {
		t.Errorf("goEnv(\"GOOS\") = %q, want %q", got, runtime.GOOS)
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

// TestRunFindsLeakViaGoWorkReplace is the direct regression test for the
// gap this fixes: a go.work replace that overrides a go.mod require is
// invisible if the tool only ever reads the single go.mod it was pointed
// at. Verified live against the real toolchain (go list -m all inside a
// workspace resolves the require to the go.work replacement target even
// though the member module's own go.mod shows only the plain, unreplaced
// require) before writing this — the pre-fix tool reported "no issues
// found" for exactly this setup.
func TestRunFindsLeakViaGoWorkReplace(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/foo/bar v1.2.3
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@git.internal.example.com/"]
	insteadOf = https://git.internal.example.com/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "") // isolate from the real environment's XDG git config too

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: the go.work replacement is the path actually fetched and is privately hosted; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.internal.example.com/mirror/bar") {
		t.Errorf("stdout missing expected leak on the go.work replacement path: %s", stdout)
	}
}

// TestRunGoWorkReplaceOverridesGoModReplace covers the documented
// precedence rule (`go help work`): when both go.mod and go.work replace
// the same module, the go.work replacement wins. Without this, a go.mod
// replace pointing at a *safe* (covered or public, non-private) fork could
// mask a go.work replace that actually sends the module to an uncovered
// private host.
func TestRunGoWorkReplaceOverridesGoModReplace(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/foo/bar v1.2.3

replace github.com/foo/bar => github.com/safe-fork/bar v1.2.3
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@git.internal.example.com/"]
	insteadOf = https://git.internal.example.com/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: go.work's replace must take precedence over go.mod's; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "safe-fork") {
		t.Errorf("stdout should not mention the shadowed go.mod replacement target: %s", stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.internal.example.com/mirror/bar") {
		t.Errorf("stdout missing expected leak on the go.work replacement path: %s", stdout)
	}
}

// TestRunGoWorkOffIgnored covers GOWORK=off (workspace mode explicitly
// disabled) and an empty gowork (no workspace at all) both being treated
// as "no go.work replaces to apply", not an error.
func TestRunGoWorkOffIgnored(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", "off",
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: GOWORK=off must not suppress the plain go.mod leak; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak: %s", stdout)
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

// TestRunFindsLeakViaUncoveredToolDirective is the direct regression test
// for the gap this fixes: a Go 1.24+ `tool` directive naming a package
// under a privately-rewritten host, with no `require` entry covering it
// at all (parseRequires alone would never see this dependency), must
// still surface a SUMDB LEAK the same way an equivalent `require` entry
// would.
func TestRunFindsLeakViaUncoveredToolDirective(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

tool github.com/myorg/internal-tool/cmd/gen
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool/cmd/gen") {
		t.Errorf("stdout missing expected leak finding for the uncovered tool path: %s", stdout)
	}
}

// TestRunToolCoveredByRequireNotDoubleReported covers the common,
// go-tooling-produced case: `go get -tool` always pairs a `tool` line
// with a covering `require` entry for the same module, so the tool path
// must not be independently re-checked (already covered via the normal
// require scan) or produce a second, differently-worded SUMDB LEAK line
// for what is really the same dependency.
func TestRunToolCoveredByRequireNotDoubleReported(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

tool github.com/myorg/internal-tool/cmd/gen
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if got := strings.Count(stdout, "SUMDB LEAK"); got != 1 {
		t.Errorf("expected exactly one SUMDB LEAK line for a tool path already covered by require, got %d: %s", got, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunToolDirectiveCleanWhenCovered mirrors TestRunClean but with a
// tool directive present and correctly covered by GONOSUMDB, confirming
// the new code path doesn't introduce a false positive on the clean case.
func TestRunToolDirectiveCleanWhenCovered(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

tool github.com/myorg/internal-tool/cmd/gen
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-nosumdb", "github.com/myorg/*",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 once GONOSUMDB covers the tool's path; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak once covered, got: %s", stdout)
	}
}
