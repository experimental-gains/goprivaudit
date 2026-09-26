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

// TestRunFindsLeakViaCredentialHelper covers the real-world case
// `gh auth setup-git` sets up: no insteadOf rewrite at all, no netrc file
// — just an org-scoped git credential helper for a plain HTTPS URL, which
// `go`'s subprocess `git clone` uses to authenticate. Before this signal
// was recognized, a module authenticated purely this way was invisible to
// the audit, no matter how uncovered by GOPRIVATE/GONOSUMDB it was.
func TestRunFindsLeakViaCredentialHelper(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "https://github.com/myorg"]
	helper = store
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakViaRelativeGitdirIncludeIf covers a real, commonly
// recommended dotfiles pattern this tool missed before expandGitdirPattern
// learned to resolve a "./"-prefixed gitdir pattern relative to the
// directory of the config file the [includeIf] directive itself lives in
// (git-config(1): "the pattern can also be a path relative to the
// directory containing the configuration file... e.g. ... if the
// condition is 'gitdir:./foo/bar', the full pattern would be
// '/home/user/foo/bar'"). Verified live against real git 2.47 before this
// fix (see expandGitdirPattern's doc comment): a real ~/.gitconfig
// containing exactly `[includeIf "gitdir:./work/"] path =
// ~/.gitconfig-work` genuinely applies gitconfig-work's credential helper
// to every repo cloned under ~/work/, per `git config --get-all` — a
// pattern several real "separate work/personal git identity" dotfiles
// guides recommend specifically because it avoids hardcoding an absolute
// $HOME-rooted path on every machine. Before the fix, this tool's
// includeIfMatches never threaded the enclosing config file's own
// directory through to expandGitdirPattern, so "./work/" was glob-matched
// as a literal relative fragment against the audited repo's absolute
// $GIT_DIR and could never match — reporting "no issues found" for a
// require'd module only reachable via that helper.
func TestRunFindsLeakViaRelativeGitdirIncludeIf(t *testing.T) {
	home := t.TempDir()
	repoDir := filepath.Join(home, "work", "myrepo")

	gomod := writeFile(t, repoDir, "go.mod", `module example.com/app

require relative-example.test/pkg v0.0.0-20230101000000-abcdef123456
`)
	// A real repo needs its own .git so resolveGitDir has something to
	// resolve — its content is irrelevant to this test.
	writeFile(t, repoDir, ".git/config", "")

	writeFile(t, home, ".gitconfig", `[includeIf "gitdir:./work/"]
	path = `+filepath.Join(home, ".gitconfig-work")+`
`)
	writeFile(t, home, ".gitconfig-work", `[credential "https://relative-example.test"]
	helper = /path/to/real-helper
`)

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: relative-example.test/pkg") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakCredentialHelperResetAcrossTiers covers a real false
// positive the old per-tier-then-concatenate architecture had: a global
// ~/.gitconfig credential helper (e.g. left over from a one-time `gh auth
// setup-git` run) that a repo's local .git/config deliberately resets with
// an empty `helper =` line, to disable it for that one repo, is not
// actually an active private-auth signal at all — verified live (`git
// credential fill` against a real fake-helper script and the equivalent
// two-tier config) that the reset genuinely stops git from invoking any
// helper. Scanning each tier's own file independently and concatenating
// their prefixes (what run() used to do) can't see a later tier's reset
// canceling an earlier tier's real setting, since the earlier tier's scan
// has no visibility into the later one at all.
func TestRunFindsLeakCredentialHelperResetAcrossTiers(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".gitconfig", `[credential "https://github.com/myorg"]
	helper = store
`)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "https://github.com/myorg"]
	helper =
`)

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (the local tier's reset cancels the global tier's helper); stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout has a false-positive leak finding: %s", stdout)
	}
}

// TestExtraHeaderPrivateHostEndToEnd reproduces, end to end through the
// real built CLI, the exact `[http "<url>"] extraheader = ...` section
// `actions/checkout` (the default way almost every GitHub Actions Go
// workflow checks out code) writes when `github-server-url` points at a
// self-hosted GitHub Enterprise Server instance — verified against its
// real source (git-auth-helper.ts, `GitAuthHelper.configureToken`) and
// reproduced live with the real `git config --file
// http.<url>.extraheader ...` command that code runs, then confirmed
// `git config --get-all http.<url>.extraheader` resolves the value back
// out of exactly this section form before trusting this test.
// (`actions/checkout` itself wires this file in via an
// `includeIf.gitdir:<path>/.git` entry in the repo's own .git/config —
// the include-follows-through-includeIf mechanism is already covered
// generically by TestRunFindsLeakViaGitConfigIncludeIf for another
// signal type, so this test scans the section directly, the same way
// TestRunFindsLeak does for insteadOf, to isolate what's actually new
// here: recognizing the [http] section at all.) Before this fix,
// goprivaudit reported "no issues found" for this exact section (built
// CLI, not just the unit-level parser test) even though the module is
// fetched with real, job-scoped credentials and isn't covered by
// GOPRIVATE/GONOSUMDB.
func TestExtraHeaderPrivateHostEndToEnd(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.mycorp.example/myorg/internal-tool v1.2.3
`)
	writeFile(t, dir, ".git/config", `[http "https://github.mycorp.example/"]
	extraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.mycorp.example/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunExtraHeaderBareHostNoLeak covers actions/checkout's far more
// common default case: a bare, known-public host (plain github.com), the
// same shape `gh auth setup-git`'s bare-host credential helper takes.
// Not flagged, for the same reason: it doesn't name a specific private
// module, and flagging it would mark every public dependency checked out
// in an ordinary GitHub Actions job as a leak.
func TestRunExtraHeaderBareHostNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[http "https://github.com/"]
	extraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX2Zha2V0b2tlbg==
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak finding for a bare-host extraheader, got: %s", stdout)
	}
}

// TestRunGhAuthSetupGitBareHostNoLeak reproduces gh auth setup-git's
// actual default output (host-scoped, not org-scoped) and confirms it's
// correctly excluded as too broad to be a specific module's signal — the
// same reasoning as a bare-host insteadOf rewrite.
func TestRunGhAuthSetupGitBareHostNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "https://github.com"]
	helper =
	helper = !/usr/bin/gh auth git-credential
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak finding for a bare-host credential context, got: %s", stdout)
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

// TestRunGoproxyOffNoLeak covers a real correctness bug: GOPROXY=off
// disables all module-proxy-protocol network access, sumdb lookups
// included — verified live with a local logging HTTP server standing in
// for GOSUMDB's URL: a real `go get` under a normal, reachable GOPROXY
// sent a genuine `/lookup/<module>@<version>` request to it, while the
// identical setup under GOPROXY=off failed immediately with "module
// lookup disabled by GOPROXY=off" and the logging server received no
// request at all. Before this fix, `run` had no notion of GOPROXY at
// all, so it still reported a SUMDB LEAK for a query that structurally
// cannot happen — the same false-positive shape as the GOSUMDB=off and
// vendor-mode cases above, just reached via a config surface this tool
// didn't check yet.
func TestRunGoproxyOffNoLeak(t *testing.T) {
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
		"-sumdb", "",
		"-proxy", "off",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean with GOPROXY=off, got: %s", stdout)
	}
}

// TestRunGoproxyOffChainFirstEntryNoLeak covers the same "off" precedence
// goproxycheck's own localGoproxyOff already relies on: a comma- or
// pipe-separated GOPROXY chain is only structurally blocked when "off" is
// its *first* entry (a later "off" is only reached if every earlier real
// proxy entry fails first, which this test doesn't set up, so it must not
// be treated as blocked).
func TestRunGoproxyOffChainFirstEntryNoLeak(t *testing.T) {
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
		"-sumdb", "",
		"-proxy", "off,https://proxy.golang.org",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean with GOPROXY=off,... (off first), got: %s", stdout)
	}
}

// TestRunGoproxyOffNotFirstStillLeaks is the mirror of the two tests
// above: when "off" is present in the GOPROXY chain but isn't the first
// entry, the real go command still tries the earlier real proxy first, so
// the fetch (and the resulting sumdb query) isn't structurally blocked —
// this must still report the leak.
func TestRunGoproxyOffNotFirstStillLeaks(t *testing.T) {
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
		"-sumdb", "",
		"-proxy", "https://proxy.golang.org,off",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding when 'off' isn't the first GOPROXY entry: %s", stdout)
	}
}

// TestRunCustomSumdbNamesActualDatabase covers a real correctness bug: the
// SUMDB LEAK message used to hardcode "the public checksum database"
// regardless of GOSUMDB's actual value. GOSUMDB's multi-field form
// (`go help environment`: "name[+key] [url]") lets it point at any
// database, including a private, self-hosted one run specifically to keep
// module info off Google's infrastructure — verified live that the URL
// field fully controls the query destination (a real `go get` against a
// dependency with GOSUMDB's URL field pointed at a local HTTP server sent
// the lookup request there, not to sum.golang.org). Calling an arbitrary
// configured destination "the public checksum database" is wrong, not just
// imprecise, so the message must name the actual configured database
// instead.
func TestRunCustomSumdbNamesActualDatabase(t *testing.T) {
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
		"-sumdb", "sum.mycorp.example+abc123 https://sum.mycorp.internal",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
	if !strings.Contains(stdout, "sent to the sum.mycorp.example checksum database") {
		t.Errorf("stdout should name the configured sumdb (sum.mycorp.example), not assume sum.golang.org/\"public\": %s", stdout)
	}
	if strings.Contains(stdout, "public checksum database") {
		t.Errorf("stdout should not call a custom, possibly-private GOSUMDB \"public\": %s", stdout)
	}
}

// TestRunVendorModeNoLeak covers a real go command behavior distinct from
// GOSUMDB=off: when a module ships a committed vendor/ directory and its
// go.mod's `go` directive is 1.14+ (the go command's own auto-vendor
// condition, see `go help modules`), `go build`/`go install` resolve
// dependencies from vendor/ and never consult the module proxy or
// sum.golang.org at all — verified live (see vendorModeActive's doc
// comment): a real `go build` with vendor mode active succeeds even with
// GOPROXY pointed at an unreachable address and GOSUMDB left at its
// default, while flipping to an explicit `-mod=mod` on the identical
// tree immediately fails trying to reach the network. Before this fix,
// `run` had no notion of vendoring at all, so it still reported a SUMDB
// LEAK for a module with a private-auth signal but no GOPRIVATE/GONOSUMDB
// coverage — an alarm for a checksum-database query that cannot happen in
// this mode, the same false-positive shape as the GOSUMDB=off case above.
func TestRunVendorModeNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "vendor/modules.txt", `# github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
## explicit; go 1.20
github.com/myorg/internal-tool
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
		"-sumdb", "", // default (not off): vendor mode alone must be enough to skip
		"-goflags", "", // no explicit -mod= override: rely on the vendor/modules.txt auto-default
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean in vendor mode, got: %s", stdout)
	}
}

// TestRunVendorModeBelowGo114StillLeaks confirms the auto-vendor default's
// go-version gate is honored: a vendor/modules.txt sitting next to a go.mod
// pinned below go 1.14 does NOT make the go command auto-vendor (verified
// live — see vendorModeActive's doc comment), so the audit must still run
// and report the leak normally.
func TestRunVendorModeBelowGo114StillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.13

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "vendor/modules.txt", `# github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
## explicit; go 1.13
github.com/myorg/internal-tool
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
		"-goflags", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding below go 1.14: %s", stdout)
	}
}

// TestRunVendorModeExplicitModModStillLeaks confirms an explicit -mod=mod
// (via GOFLAGS) overrides the vendor/ auto-default, matching real go
// behavior (verified live: GOFLAGS=-mod=mod forces the network-resolving
// path even with a real vendor/modules.txt present) — so the audit must
// still run.
func TestRunVendorModeExplicitModModStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "vendor/modules.txt", `# github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
## explicit; go 1.20
github.com/myorg/internal-tool
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
		"-goflags", "-mod=mod",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding under explicit -mod=mod: %s", stdout)
	}
}

// TestRunVendorModeInsideWorkspaceStillLeaks is the direct regression test
// for the bug found in the 49th real-world-testing pass: the vendor/
// auto-default (see vendorModeActive) must NOT apply inside an active
// go.work workspace, even when every per-module condition (vendor/
// modules.txt present, go.mod's `go` directive >= 1.14) is otherwise met.
// Verified live against the real go toolchain before fixing: a member
// module with a qualifying per-module vendor/ directory built fine offline
// with GOWORK unset, but the identical module — same go.mod, same vendor/ —
// failed trying to reach an unreachable GOPROXY as soon as GOWORK pointed
// at a real workspace file, proving the auto-default never engaged.
// Workspace-wide vendoring is a distinct, opt-in mechanism (`go work
// vendor` + explicit -mod=vendor) that's a different test (the explicit
// override already applies inside a workspace too, per
// TestVendorModeActive). Before this fix, `run` treated the per-module
// vendor/modules.txt as sufficient on its own, so it silently reported "no
// issues found" instead of the real SUMDB LEAK a workspace build actually
// risks sending.
func TestRunVendorModeInsideWorkspaceStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "vendor/modules.txt", `# github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
## explicit; go 1.20
github.com/myorg/internal-tool
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
		"-goflags", "", // no explicit -mod= override: the per-module vendor auto-default must not apply inside a workspace
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: a workspace suppresses the per-module vendor auto-default, so the audit must still run; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding inside an active workspace: %s", stdout)
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

// TestRunFindsLeakViaGitConfigEnvVars covers the GIT_CONFIG_COUNT/
// GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> environment-variable form of git
// config end to end. Before this fix, gitConfigCandidates only ever
// listed files, so a private-auth signal set purely via these variables —
// a real, documented (git-config(1)) way to configure git "when you ...
// cannot depend on a configuration file", e.g. a scripted CI setup that
// deliberately avoids writing credentials to disk — was invisible even
// though a real `go get`'s own git subprocess inherits and honors them
// exactly like it would a config file.
func TestRunFindsLeakViaGitConfigEnvVars(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.gitconfig at all
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", "")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url.git@github.com:myorg/.insteadof")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://github.com/myorg/")

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

// TestRunGitConfigGlobalOverride covers GIT_CONFIG_GLOBAL end to end, in
// both directions git-config(1) documents it changing behavior: it replaces
// the *entire* normal global tier (confirmed live that neither
// $XDG_CONFIG_HOME/git/config nor ~/.gitconfig is read at all once it's
// set), so (a) a real signal kept only in the override file must still be
// found, and (b) a stale signal left in the now-ignored ~/.gitconfig must
// NOT be flagged, since git itself would never act on it for this process.
func TestRunGitConfigGlobalOverride(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".gitconfig", `[url "git@stale.example.com:org/"]
	insteadOf = https://stale.example.com/org/
`)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	override := writeFile(t, t.TempDir(), "override.gitconfig", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("GIT_CONFIG_GLOBAL", override)

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
require stale.example.com/org/other-tool v0.0.0-20230101000000-abcdef123456
`)

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding from the override file: %s", stdout)
	}
	if strings.Contains(stdout, "stale.example.com") {
		t.Errorf("stdout wrongly flagged a signal from the overridden (git-ignored) ~/.gitconfig: %s", stdout)
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
	got := goEnv(".", "GOOS")
	if got == "" {
		t.Fatal("goEnv(\".\", \"GOOS\") returned empty; want a real value")
	}
	if got != runtime.GOOS {
		t.Errorf("goEnv(\".\", \"GOOS\") = %q, want %q", got, runtime.GOOS)
	}
}

// TestGoEnvUsesGivenDir covers the run #348 bug directly at the goEnv
// level: GOWORK's default is directory-dependent (auto-discovered by
// searching upward from wherever `go env GOWORK` is actually run), so
// goEnv must run `go env` with cmd.Dir set to the given dir rather than
// this test process's own working directory. Creates a real go.work in a
// temp dir (a real module nested under it, matching `go help workspaces`
// layout) and confirms goEnv("GOWORK", dir) finds it even though the test
// process's own cwd is unrelated and has no go.work of its own.
func TestGoEnvUsesGivenDir(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "member")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte("module example.com/member\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(root, "go.work")
	if err := os.WriteFile(workPath, []byte("go 1.24\n\nuse ./member\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := goEnv(modDir, "GOWORK")
	if got != workPath {
		t.Errorf("goEnv(%q, \"GOWORK\") = %q, want %q", modDir, got, workPath)
	}

	// Sanity check the negative: a dir with no go.work in its own tree
	// (t.TempDir()'s parent, guaranteed unrelated) resolves to "".
	unrelated := t.TempDir()
	if got := goEnv(unrelated, "GOWORK"); got != "" {
		t.Errorf("goEnv(%q, \"GOWORK\") = %q, want \"\" (no go.work in this tree)", unrelated, got)
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

// TestRunFindsLeakInLinkedWorktree reproduces the exact on-disk shape a
// real `git worktree add` creates (verified live; see resolveGitDir's doc
// comment in gitconfig.go): the worktree's own moduleDir/.git is a *file*,
// not a directory, naming a separate worktree-specific $GIT_DIR under the
// main checkout's .git/worktrees/<name>, which in turn has a "commondir"
// file naming the shared common dir (the main checkout's .git) that git
// actually reads "config" from — worktrees don't get their own config by
// default. Before the resolveGitDir fix, gitConfigCandidates only ever
// looked for moduleDir/.git/config; since moduleDir/.git is a file here,
// that path doesn't exist, so a real insteadOf rewrite in the shared
// config — the exact rewrite `go get` run from this worktree actually
// uses — was silently invisible, reporting "no issues found" instead of
// the real SUMDB LEAK a normal (non-worktree) checkout of the identical
// repository correctly flags.
func TestRunFindsLeakInLinkedWorktree(t *testing.T) {
	mainRepo := t.TempDir()
	writeFile(t, mainRepo, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "wt")
	writeFile(t, worktreeGitDir, "commondir", "../..\n")
	writeFile(t, worktree, ".git", "gitdir: "+worktreeGitDir+"\n")

	gomod := writeFile(t, worktree, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunFindsLeakInWorktreeConfig reproduces git-worktree(1)'s documented
// per-worktree config mechanism: with "extensions.worktreeConfig" enabled
// in the shared config, `git config --worktree ...` writes to a fourth
// config file at the *worktree's own* $GIT_DIR/config.worktree, not the
// shared commonDir/config the plain linked-worktree test above already
// covers — verified live (see gitConfigCandidates' doc comment) that a
// real `git ls-remote` run from this worktree honors an insteadOf rewrite
// kept only there. Before this fix, gitConfigCandidates never looked at
// config.worktree at all, so this exact real, git-documented setup left a
// genuine SUMDB LEAK reported as "no issues found".
func TestRunFindsLeakInWorktreeConfig(t *testing.T) {
	mainRepo := t.TempDir()
	writeFile(t, mainRepo, ".git/config", `[extensions]
	worktreeConfig = true
`)

	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "wt")
	writeFile(t, worktreeGitDir, "commondir", "../..\n")
	writeFile(t, worktreeGitDir, "config.worktree", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, worktree, ".git", "gitdir: "+worktreeGitDir+"\n")

	gomod := writeFile(t, worktree, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunIgnoresConfigWorktreeWhenExtensionDisabled pins the other half of
// the same fix: a config.worktree file left on disk (e.g. from a since-
// disabled extensions.worktreeConfig — git never deletes it automatically)
// must NOT be read when the shared config no longer turns the extension
// on, matching real git's own behavior of ignoring that file entirely in
// that case. Without this guard, unconditionally reading config.worktree
// once discovered would flag a rewrite real git itself no longer applies.
func TestRunIgnoresConfigWorktreeWhenExtensionDisabled(t *testing.T) {
	mainRepo := t.TempDir()
	writeFile(t, mainRepo, ".git/config", "") // extensions.worktreeConfig never set

	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "wt")
	writeFile(t, worktreeGitDir, "commondir", "../..\n")
	writeFile(t, worktreeGitDir, "config.worktree", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, worktree, ".git", "gitdir: "+worktreeGitDir+"\n")

	gomod := writeFile(t, worktree, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (extension off, config.worktree must be ignored); stdout=%s", code, stdout)
	}
}

// TestRunFindsLeakInSubmoduleCheckout covers the sibling real-world shape:
// a real `git submodule add` also gives the submodule's working directory
// a .git *file* rather than a directory (verified live), but unlike a
// linked worktree's, the gitdir it names (relocated under the
// superproject's .git/modules/<name>) has no "commondir" file at all — it
// owns its own config directly. resolveGitDir has to get both shapes
// right from the same commondir-file check; this pins the no-commondir
// branch specifically so a fix aimed only at the worktree case above can't
// silently regress it.
func TestRunFindsLeakInSubmoduleCheckout(t *testing.T) {
	submoduleGitDir := t.TempDir()
	writeFile(t, submoduleGitDir, "config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	submoduleWorkdir := t.TempDir()
	writeFile(t, submoduleWorkdir, ".git", "gitdir: "+submoduleGitDir+"\n")

	gomod := writeFile(t, submoduleWorkdir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
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

// TestRunFindsLeakViaGoWorkAutoDiscovery is the run #348 regression test:
// unlike TestRunFindsLeakViaGoWorkReplace above (which passes an explicit
// -gowork override, bypassing auto-discovery entirely), this test omits
// -gowork so GOWORK is resolved the normal way — via `go env GOWORK`'s own
// auto-discovery, which searches upward from wherever it's run for a
// go.work file (`go help environment`). This test's own process cwd (the
// package directory, unrelated to the TempDir below and containing no
// go.work of its own) stands in for the ordinary case of a wrapper/CI
// script invoking `goprivaudit -gomod /path/to/target/go.mod` from a fixed
// working directory. Before the run #348 fix (goEnv never set cmd.Dir),
// `go env GOWORK` ran from the test binary's own cwd and found nothing,
// so the go.work replace below was silently invisible and the tool
// reported "no issues found" on a real SUMDB LEAK.
func TestRunFindsLeakViaGoWorkAutoDiscovery(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

require github.com/foo/bar v1.2.3
`)
	writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	writeFile(t, dir, "app/.git/config", `[url "ssh://git@git.internal.example.com/"]
	insteadOf = https://git.internal.example.com/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1: GOWORK auto-discovery from the go.mod's own directory should find go.work and its replacement, which is privately hosted; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.internal.example.com/mirror/bar") {
		t.Errorf("stdout missing expected leak found via GOWORK auto-discovery: %s", stdout)
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

// TestRunGoWorkVersionSpecificReplaceLeavesUnrelatedGoModReplaceIntact is
// the direct regression test for the bug found run #288: a go.work replace
// that's specific to a version other than the one actually required must
// not blot out an unrelated go.mod-level replace for the same path.
// Verified live against the real go toolchain before fixing (`go list -m
// all` inside a workspace with this exact shape still resolves through the
// go.mod replace — go.work's version-specific entry never applies, since
// the required version doesn't match it) — the pre-fix tool reported "no
// issues found" here, silently missing a real sumdb leak, because
// mergeReplaces discarded every go.mod entry for a path the moment go.work
// carried *any* entry for it, version-specific or not.
func TestRunGoWorkVersionSpecificReplaceLeavesUnrelatedGoModReplaceIntact(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/foo/bar v1.2.3

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar v9.9.9 => example.com/unrelated-sibling-pin v0.0.0
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
		t.Errorf("exit code = %d, want 1: go.work's v9.9.9-specific replace doesn't apply to the required v1.2.3, so go.mod's replace must still be in effect; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: git.internal.example.com/mirror/bar") {
		t.Errorf("stdout missing expected leak on the go.mod replacement path, which a version-specific go.work entry for a different version must not shadow: %s", stdout)
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

func TestGoproxyEffectivelyOff(t *testing.T) {
	cases := []struct {
		goproxy string
		want    bool
	}{
		{"off", true},
		{" off ", true},
		{"off,https://proxy.golang.org", true},
		{"off|https://proxy.golang.org", true},
		{"https://proxy.golang.org,off", false},
		{"https://proxy.golang.org,direct", false},
		{"direct", false},
		{"", false},
		{"offbeat.example.com", false},
		// Empty entries (stray/leading/trailing separators, e.g. from
		// `GOPROXY="$UNSET_VAR,off"`) don't count as an entry — verified
		// live that real `go` skips them and evaluates the first
		// *non-empty* entry instead of treating the blank as "the first
		// entry, and it's not off".
		{",off", true},
		{",,off", true},
		{" , ,off", true},
		{"|off", true},
		{",direct", false},
		{" ,https://proxy.golang.org,off", false},
	}
	for _, c := range cases {
		if got := goproxyEffectivelyOff(c.goproxy); got != c.want {
			t.Errorf("goproxyEffectivelyOff(%q) = %v, want %v", c.goproxy, got, c.want)
		}
	}
}

// TestRunFindsLeakViaSystemGitConfig covers git's lowest-precedence config
// tier — the system-wide $(prefix)/etc/gitconfig file, relocatable via
// GIT_CONFIG_SYSTEM — which gitConfigCandidates never read at all before
// this fix. A real, common pattern: an org bakes an insteadOf rewrite (or
// credential helper / extraHeader) into a container base image or CI
// runner's system-wide git config so it applies to every job on the
// machine regardless of $HOME. Uses a real `git var GIT_CONFIG_SYSTEM`
// subprocess (same live-behavior-over-guessing approach as
// gitconfig_realgit_test.go) rather than assuming the path, since it's
// platform-dependent (this fix's whole point).
func TestRunFindsLeakViaSystemGitConfig(t *testing.T) {
	sysConfig := writeFile(t, t.TempDir(), "gitconfig", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("GIT_CONFIG_SYSTEM", sysConfig)
	t.Setenv("HOME", t.TempDir()) // no ~/.gitconfig at all
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", "")

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

// TestRunIgnoresSystemGitConfigWhenNoSystemSet covers the flip side of
// TestRunFindsLeakViaSystemGitConfig: GIT_CONFIG_NOSYSTEM (git-config(1))
// makes real git skip the system config tier entirely (confirmed live via
// GIT_TRACE against a real `git ls-remote`: with GIT_CONFIG_NOSYSTEM=1 set,
// an insteadOf rewrite that lives only in the system file never fires, and
// the fetch goes out over the original, unrewritten HTTPS URL instead of
// ssh). So a module whose only private-auth signal is a
// GIT_CONFIG_NOSYSTEM-suppressed system-config rewrite has no real signal
// at all, and should be reported clean — not a false SUMDB LEAK from a
// config file git itself never actually reads in this mode.
func TestRunIgnoresSystemGitConfigWhenNoSystemSet(t *testing.T) {
	sysConfig := writeFile(t, t.TempDir(), "gitconfig", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("GIT_CONFIG_SYSTEM", sysConfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("HOME", t.TempDir()) // no ~/.gitconfig at all
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", "")

	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)

	stdout, _, code := captureRun(t, []string{"-gomod", gomod, "-private", "", "-nosumdb", ""})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (GIT_CONFIG_NOSYSTEM should suppress the system-config signal); stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout has a false leak finding despite GIT_CONFIG_NOSYSTEM: %s", stdout)
	}
}
