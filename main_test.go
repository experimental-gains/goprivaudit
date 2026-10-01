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

// TestCredentialHelperDeprecatedDotSyntaxEndToEnd covers the built CLI's
// end of the same gap TestPrivatePrefixesFromGitConfigCredentialHelperDeprecatedDotSyntax
// exercises at the unit level: git-config(1)'s deprecated, unquoted
// "[section.subsection]" header syntax (case-insensitive subsection, no
// space, no quotes) for a [credential "..."] context — real, live-verified
// git syntax (see parseDotSection's doc comment), just a different header
// shape than every other credential-helper test in this file uses.
func TestCredentialHelperDeprecatedDotSyntaxEndToEnd(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.corp.example.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential.git.corp.example.com]
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
	if !strings.Contains(stdout, "SUMDB LEAK: git.corp.example.com/myorg/internal-tool") {
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

// TestRunGoproxyOffStillLeaks is the regression test for the real bug
// found in the 94th real-world-testing pass: an earlier version of this
// tool treated GOPROXY's effective first chain entry being "off" as an
// unconditional "cannot leak" guarantee, the same as GOSUMDB=off and
// vendor mode. That's wrong. Verified live: with GOPROXY=off, GOSUMDB
// left at its default, and a required module's exact pinned version
// already sitting in the local module cache (an ordinary state — e.g. a
// shared $GOMODCACHE warmed by an earlier online CI stage) but with no
// go.sum entry yet, a real `GOFLAGS=-mod=mod go build` still sent a
// genuine `/lookup/<module>@<version>` request straight to a local HTTP
// server standing in for GOSUMDB's configured URL — bypassing GOPROXY
// entirely, since cmd/go/internal/modfetch/sumdb.go's dbClient falls back
// to a *direct* sumdb connection the instant every proxy in the chain
// reports "off"/"direct". GOPROXY=off only prevents the leak when the
// module isn't in the local cache yet (the narrower case an earlier
// version of this test — using an uncached module and a plain `go get`
// that fails during version resolution before ever reaching sumdb —
// exercised); this tool has no way to know the cache state, so it must
// not assume the safe case and go quiet about a real leak.
func TestRunGoproxyOffStillLeaks(t *testing.T) {
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
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding with GOPROXY=off: %s", stdout)
	}
}

// TestRunGoproxyOffChainStillLeaks is TestRunGoproxyOffStillLeaks's
// counterpart for a comma/pipe-separated GOPROXY chain: whether "off" is
// the first entry or a later one, neither shape is a reliable "cannot
// leak" signal (see TestRunGoproxyOffStillLeaks and this package's own
// doc comment), so both must still report the leak — unlike before this
// fix, when only the "off"-first shape was (wrongly) suppressed.
func TestRunGoproxyOffChainStillLeaks(t *testing.T) {
	for _, proxy := range []string{"off,https://proxy.golang.org", "https://proxy.golang.org,off"} {
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
			"-proxy", proxy,
		})
		if code != 1 {
			t.Errorf("proxy=%q: exit code = %d, want 1; stdout=%s", proxy, code, stdout)
		}
		if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
			t.Errorf("proxy=%q: stdout missing expected leak finding: %s", proxy, stdout)
		}
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

// TestRunMalformedGoflagsNoLeak is the regression test for a real false
// positive found by testing against real go: GOFLAGS="-mod mod" (the
// command-line spacing of `go build -mod mod`, a natural mistake since
// GOFLAGS entries are never re-paired with a following token the way a
// real argv is) makes real go's own $GOFLAGS validation split it into two
// entries, "-mod" and "mod" — the second doesn't start with "-" at all, so
// `go build`/`go list -m all`/`go mod download` all Fatal immediately with
// `go: parsing $GOFLAGS: non-flag "mod"` (verified live), before ever
// resolving a module or querying a checksum database. Pre-fix,
// explicitModFlag didn't recognize either token as a "-mod=" override, so
// vendorModeActive fell through to the auto-default — here, with no
// vendor/ directory present, that default is false, so the audit ran
// normally and reported a SUMDB LEAK for a query that can never actually
// happen, since the real go command dies before getting anywhere near it.
func TestRunMalformedGoflagsNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

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
		"-goflags", "-mod mod",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when GOFLAGS is malformed (go itself would Fatal before any query), got: %s", stdout)
	}
}

// TestRunUnknownGoflagsFlagNameNoLeak is the regression test for a real
// false positive found by testing against real go, one level past
// TestRunMalformedGoflagsNoLeak: GOFLAGS="-notarealflag=vendor" has a
// perfectly valid shape ("-name=value") — goflagsMalformed's static check
// waves it through — but "notarealflag" isn't a real flag on any go
// subcommand at all, a very plausible typo of "-mod=vendor". Verified
// live: cmd/go/internal/base.InitGOFLAGS Fatals with `go: parsing
// $GOFLAGS: unknown flag -notarealflag` for exactly this value, on `go
// build`/`go list -m all`/`go mod download` alike, before resolving a
// single module — so no sumdb query for anything can ever happen. Pre-fix
// (before goflagsRejectedByGo existed), goflagsBad was only
// goflagsMalformed's shape check, which this value passes, so the audit
// ran normally and reported a SUMDB LEAK for a query that can never
// actually happen.
func TestRunUnknownGoflagsFlagNameNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

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
		"-goflags", "-notarealflag=vendor",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when GOFLAGS carries an unknown flag name (go itself would Fatal before any query), got: %s", stdout)
	}
}

// TestRunGoflagsMissingArgNoLeak is the regression test for a real false
// positive found by testing against real go, distinct from both
// TestRunMalformedGoflagsNoLeak (a non-flag-shaped token) and
// TestRunUnknownGoflagsFlagNameNoLeak (an unregistered flag name):
// GOFLAGS="-mod" (bare, missing "=value" entirely) is shaped exactly like
// a valid boolean flag, so InitGOFLAGS's shape check (goflagsMalformed)
// waves it through, and "mod" is a real, registered flag, so InitGOFLAGS's
// registered-flag check (goflagsRejectedByGo's original "parsing $GOFLAGS:"
// substring match) didn't catch it either. But -mod isn't boolean — it
// takes a value — so cmd/go/internal/base.SetFromGOFLAGS Fatals once it
// actually tries to apply the flag, printing "go: flag needs an argument:
// -mod (from $GOFLAGS)" (verified live: `GOFLAGS=-mod go build`/`go list
// -m` both exit 2 immediately with exactly that message, before resolving
// a single module or contacting GOPROXY/GOSUMDB). Pre-fix,
// goflagsRejectedByGo only matched the literal "parsing $GOFLAGS:" prefix
// InitGOFLAGS uses, missed this SetFromGOFLAGS-stage message entirely, and
// so returned false — the audit ran normally and reported a SUMDB LEAK for
// a checksum-database query that can never actually happen, since the real
// go command dies before getting anywhere near it.
func TestRunGoflagsMissingArgNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

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
		"-goflags", "-mod",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when GOFLAGS carries a registered flag missing its required value (go itself would Fatal before any query), got: %s", stdout)
	}
}

// TestRunInvalidModValueGoflagsNoLeak is the regression test for a real
// false positive found by testing against real go, a third distinct
// GOFLAGS "-mod" divergence from TestRunMalformedGoflagsNoLeak (a
// non-flag-shaped token), TestRunUnknownGoflagsFlagNameNoLeak (an
// unregistered flag name), and TestRunGoflagsMissingArgNoLeak (a
// registered flag missing its required value): GOFLAGS="-mod=Vendor"
// (capitalized — a plausible typo of the correct lowercase "vendor") is
// shaped exactly like a valid, registered "-name=value" flag, so neither
// goflagsMalformed's shape check nor goflagsRejectedByGo's
// "$GOFLAGS"/"%GOFLAGS%"-substring probe catches it. But
// cmd/go/internal/work.buildModeInit Fatals once it actually checks the
// value itself, printing "-mod=Vendor not supported (can be ”, 'mod',
// 'readonly', or 'vendor')" — verified live: `GOFLAGS=-mod=Vendor go
// list -m`/`go build` both exit 1 immediately with exactly that message,
// before resolving a single module or contacting GOPROXY/GOSUMDB, for
// every module-aware go subcommand alike (they all funnel through
// work.BuildInit during their own init). Note this message never
// mentions "$GOFLAGS"/"%GOFLAGS%" at all, unlike either of
// goflagsRejectedByGo's cases — hence goflagsInvalidModValue as its own,
// statically-checked function (see vendor.go) rather than a widened
// goflagsRejectedByGo substring match. Pre-fix, goflagsBad was only
// goflagsMalformed || goflagsRejectedByGo, neither of which caught this
// value, so the audit ran normally and reported a SUMDB LEAK for a
// checksum-database query that can never actually happen, since the real
// go command dies before getting anywhere near it.
func TestRunInvalidModValueGoflagsNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

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
		"-goflags", "-mod=Vendor",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when GOFLAGS carries an invalid -mod value (go itself would Fatal before any query), got: %s", stdout)
	}
}

// TestRunBlockCommentGoModNoLeak is the direct regression test for
// goModHasBlockComment (see gomod.go): a go.mod containing a stray "/* ... */"
// line anywhere — unrelated to the require directive itself — makes every
// module-aware go subcommand Fatal parsing go.mod before it resolves a
// single module, so the otherwise-uncovered private-auth signal below can
// never actually leak. Verified live before this fix: `go build` on the
// equivalent file Fatals immediately with "errors parsing go.mod: ... mod
// files must use // comments (not /* */ comments)", while this tool still
// reported "SUMDB LEAK" for the require line it could still see below the
// stray comment.
func TestRunBlockCommentGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

/* a stray block comment some tooling or human mistakenly wrote */
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod itself has a stray block comment (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidGoDirectiveGoModNoLeak is the direct regression test for
// goModHasInvalidGoDirective (see gomod.go): a go.mod whose `go` directive
// argument doesn't match the real go command's strict version-syntax
// validation makes every module-aware go subcommand Fatal parsing go.mod
// before it resolves a single module, so the otherwise-uncovered
// private-auth signal below can never actually leak. Verified live before
// this fix: `go list -m all` on the equivalent file Fatals immediately with
// "errors parsing go.mod: go.mod:3: invalid go version '1.9x': must match
// format 1.23.0", while this tool still reported "SUMDB LEAK" for the
// require line it could still see below the malformed directive.
func TestRunInvalidGoDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.9x

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's go directive is malformed (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidToolchainDirectiveGoModNoLeak is the direct regression test
// for goModHasInvalidToolchainDirective (see gomod.go): a go.mod whose
// `toolchain` directive argument doesn't match the real go command's strict
// toolchain-name syntax validation makes every module-aware go subcommand
// Fatal parsing go.mod before it resolves a single module, so the otherwise-
// uncovered private-auth signal below can never actually leak. Verified live
// before this fix: `go list -m all` on the equivalent file Fatals
// immediately with `go: invalid toolchain "1.24.4" in go.mod` (the
// "toolchain" name is missing its required "go" prefix), while this tool
// still reported "SUMDB LEAK" for the require line it could still see below
// the malformed directive.
func TestRunInvalidToolchainDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

toolchain 1.24.4

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's toolchain directive is malformed (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunRepeatedGoDirectiveGoModNoLeak is the direct regression test for
// goModHasRepeatedSingletonDirective (see gomod.go): a go.mod carrying TWO
// "go" directive lines, each individually well-formed on its own ("go 1.21"
// and "go 1.22", both matching goVersionDirectiveRE), makes every
// module-aware go subcommand Fatal parsing go.mod before it resolves a
// single module, so the otherwise-uncovered private-auth signal below can
// never actually leak. Verified live before this fix: `go list -m all`
// (GOPROXY=off) on the equivalent file Fatals immediately with "go.mod:N:
// repeated go statement" — a different Fatal shape from
// goModHasInvalidGoDirective's own coverage (a single malformed argument),
// since neither "go 1.21" nor "go 1.22" is itself invalid — while this tool
// still reported "SUMDB LEAK" for the require line it could still see below
// both directives.
func TestRunRepeatedGoDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.21

go 1.22

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has two individually well-formed \"go\" directives (go itself would Fatal parsing go.mod with \"repeated go statement\" before any query), got: %s", stdout)
	}
}

// TestRunRepeatedToolchainDirectiveGoModNoLeak is
// TestRunRepeatedGoDirectiveGoModNoLeak's "toolchain" sibling: two
// individually well-formed "toolchain" lines. Verified live before this
// fix: `go list -m all` on the equivalent file Fatals identically with
// "repeated toolchain statement".
func TestRunRepeatedToolchainDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.21

toolchain go1.21.0

toolchain go1.22.0

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has two individually well-formed \"toolchain\" directives (go itself would Fatal parsing go.mod with \"repeated toolchain statement\" before any query), got: %s", stdout)
	}
}

// TestRunRepeatedModuleDirectiveGoModNoLeak is
// TestRunRepeatedGoDirectiveGoModNoLeak's "module" sibling: two separate
// single-line "module" directives. Verified live before this fix: `go list
// -m all` on the equivalent file Fatals identically with "repeated module
// statement".
func TestRunRepeatedModuleDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app
module example.com/other

go 1.21

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has two separate \"module\" directives (go itself would Fatal parsing go.mod with \"repeated module statement\" before any query), got: %s", stdout)
	}
}

// TestRunRepeatedGoDirectiveGoWorkNoLeak is
// TestRunRepeatedGoDirectiveGoModNoLeak's go.work-level sibling, mirroring
// goWorkHasUnparseableDirective's own call to
// goModHasRepeatedSingletonDirective with goWorkSingletonVerbs:
// golang.org/x/mod/modfile's (*WorkFile).add carries the identical "repeated
// go statement" singleton guard as go.mod's own (*File).add. Verified live
// before this fix: `go list -m all` from the member module, with the active
// go.work shown below, Fatals immediately with "errors parsing go.work:
// go.work:3: repeated go statement", before resolving a single one of the
// member's own requires.
func TestRunRepeatedGoDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.21

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.21

go 1.22

use ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work has two individually well-formed \"go\" directives (go itself would Fatal parsing go.work with \"repeated go statement\" before any query), got: %s", stdout)
	}
}

// TestRunUnknownDirectiveGoModNoLeak is the direct regression test for
// goModHasUnknownDirective (see gomod.go): a go.mod containing a top-level
// line whose first token isn't a real go.mod directive keyword — here,
// "requires" instead of "require", a plausible pluralization slip — makes
// every module-aware go subcommand Fatal parsing go.mod before it resolves
// a single module, so the otherwise-uncovered private-auth signal below can
// never actually leak. Verified live before this fix: `go list -m all` on
// the equivalent file Fatals immediately with "errors parsing go.mod:
// go.mod:7: unknown directive: requires", while this tool still reported
// "SUMDB LEAK" for the require line it could still see above the bogus
// line.
func TestRunUnknownDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

requires bogus/directive v1.0.0
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has an unrecognized top-level directive (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidDirectiveArgCountGoModNoLeak is the direct regression test
// for goModHasInvalidDirectiveArgCount (see gomod.go): a go.mod whose
// require directive carries a stray extra argument makes every module-aware
// go subcommand Fatal parsing go.mod before it resolves a single module, so
// the otherwise-uncovered private-auth signal below can never actually
// leak. Verified live before this fix: `go list -m all` on the equivalent
// file Fatals immediately with "errors parsing go.mod: go.mod:5: usage:
// require module/path v1.2.3", while this tool still reported "SUMDB LEAK"
// for the exact same malformed require line, treating "extra" as silently
// ignored trailing text instead of the parse-killing token it actually is.
func TestRunInvalidDirectiveArgCountGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456 extra
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's require directive has a stray extra argument (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidModuleDirectiveArgCountGoModNoLeak is the direct regression
// test for goModHasInvalidDirectiveArgCount's newly-added "module" coverage
// (see gomod.go's goModFixedArgCountVerbs): a go.mod whose `module`
// directive carries a stray extra argument makes every module-aware go
// subcommand Fatal parsing go.mod before it resolves a single module, so the
// otherwise-uncovered private-auth signal below can never actually leak.
// Verified live before this fix: `go list -m all` (GOPROXY=off) on the
// equivalent file Fatals immediately with "errors parsing go.mod: go.mod:1:
// usage: module module/path", while this tool still reported "SUMDB LEAK"
// for the require line it could still see below the malformed directive —
// `module` was the one directive missing from goModFixedArgCountVerbs
// despite sharing `tool`'s exact single-fixed-argument grammar.
func TestRunInvalidModuleDirectiveArgCountGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app extra

go 1.24

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's module directive has a stray extra argument (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidModuleDirectiveZeroArgsGoModNoLeak is
// TestRunInvalidModuleDirectiveArgCountGoModNoLeak's zero-argument sibling:
// a bare "module" line with nothing after it. Verified live before this
// fix: `go list -m all` (GOPROXY=off) on the equivalent file Fatals
// identically with "usage: module module/path".
func TestRunInvalidModuleDirectiveZeroArgsGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module

go 1.24

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
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's module directive has zero arguments (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidIgnoreDirectiveArgCountGoModNoLeak is the direct regression
// test for goModHasInvalidDirectiveArgCount's newly-added "ignore" coverage
// (see gomod.go's goModFixedArgCountVerbs): a go.mod whose `ignore`
// directive carries a stray extra argument makes every module-aware go
// subcommand Fatal parsing go.mod before it resolves a single module, so the
// otherwise-uncovered private-auth signal below can never actually leak.
// `ignore` is a newer go.mod directive, absent from go1.24's own vendored
// golang.org/x/mod (confirmed by diffing that toolchain's vendored rule.go
// against a newer one) but present from go1.26.8 onward, which is what this
// repo's own go.mod `go` directive selects via GOTOOLCHAIN=auto. Verified
// live before this fix, against that real go1.26.8 toolchain: `go list -m
// all` (GOPROXY=off) on the equivalent file Fatals immediately with "errors
// parsing go.mod: go.mod:7: ignore directive expects exactly one argument",
// while this tool still reported "SUMDB LEAK" for the require line it could
// still see above the malformed directive — `ignore` was missing from
// goModFixedArgCountVerbs despite sharing `tool`/`module`'s exact
// single-fixed-argument grammar.
func TestRunInvalidIgnoreDirectiveArgCountGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.26.8

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

ignore testdata extra
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's ignore directive has a stray extra argument (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidIgnoreDirectiveZeroArgsGoModNoLeak is
// TestRunInvalidIgnoreDirectiveArgCountGoModNoLeak's zero-argument sibling:
// a bare "ignore" line with nothing after it. Verified live before this fix
// (real go1.26.8): `go list -m all` (GOPROXY=off) on the equivalent file
// Fatals identically with "ignore directive expects exactly one argument".
func TestRunInvalidIgnoreDirectiveZeroArgsGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.26.8

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

ignore
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's ignore directive has zero arguments (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidRetractDirectiveGoModNoLeak is the direct regression test
// for goModHasInvalidRetractDirective (see gomod.go): a go.mod whose
// `retract` directive carries no argument at all makes every module-aware go
// subcommand Fatal parsing go.mod before it resolves a single module, so the
// otherwise-uncovered private-auth signal below can never actually leak.
// Verified live before this fix: `go list -m all` (GOPROXY=off) on the
// equivalent file Fatals immediately with "errors parsing go.mod: go.mod:7:
// expected '[' or version", while this tool still reported "SUMDB LEAK" for
// the require line it could still see above the bare "retract" line.
func TestRunInvalidRetractDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

retract
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's retract directive has no argument (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidGodebugDirectiveGoModNoLeak is the direct regression test
// for goModHasInvalidGodebugDirective (see gomod.go): a go.mod whose
// `godebug` directive argument has no "=" at all makes every module-aware go
// subcommand Fatal parsing go.mod before it resolves a single module, so the
// otherwise-uncovered private-auth signal below can never actually leak.
// Verified live before this fix: `go list -m all` (GOPROXY=off) on the
// equivalent file Fatals immediately with "errors parsing go.mod: go.mod:7:
// usage: godebug key=value", while this tool still reported "SUMDB LEAK" for
// the require line it could still see above the malformed godebug line.
func TestRunInvalidGodebugDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

godebug nokeyvalue
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's godebug directive has no \"=\" (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunInvalidReplaceDirectiveGoModNoLeak is the direct regression test
// for goModHasInvalidReplaceDirective (see gomod.go): a go.mod whose
// `replace` directive writes its new-side target as "path@version" (a
// plausible habit carried over from an ecosystem that pins dependencies
// that way) instead of real go.mod's space-separated "path version" form
// makes every module-aware go subcommand Fatal parsing go.mod before it
// resolves a single module, so the otherwise-uncovered private-auth signal
// below can never actually leak. Verified live before this fix: `go list -m
// all` (GOPROXY=off) on the equivalent file Fatals immediately with "errors
// parsing go.mod: go.mod:7: replacement module must match format 'path
// version', not 'path@version'", while this tool still reported "SUMDB
// LEAK" for the require line it could still see above the malformed
// replace line.
func TestRunInvalidReplaceDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

replace example.com/foo => example.com/bar@v1.0.0
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod's replace directive uses \"path@version\" instead of \"path version\" (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunMismatchedPathMajorVersionGoModNoLeak is the direct regression test
// for goModHasMismatchedPathMajorVersion (see gomod.go): a go.mod whose
// `require` directive pairs a "/v2"-suffixed module path with a v1.x.x
// version (a plausible real mistake: bumping a dependency to its v2 release
// and forgetting to update the pinned version, or vice versa) makes every
// module-aware go subcommand Fatal parsing go.mod before it resolves a
// single module, so the otherwise-uncovered private-auth signal below can
// never actually leak. Verified live before this fix: `go list -m all`
// (GOPROXY=off) on the equivalent file Fatals immediately with "errors
// parsing go.mod: go.mod:7: require example.com/foo/v2: version "v1.0.0"
// invalid: should be v2, not v1", while this tool still reported "SUMDB
// LEAK" for the require line it could still see above the mismatched one.
func TestRunMismatchedPathMajorVersionGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

require example.com/foo/v2 v1.0.0
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
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has a require directive whose path major-version suffix mismatches its paired version (go itself would Fatal parsing go.mod before any query), got: %s", stdout)
	}
}

// TestRunBlockCommentGoWorkNoLeak is the direct end-to-end regression test
// for goWorkHasUnparseableDirective (see gomod.go): unlike
// TestRunBlockCommentGoModNoLeak above (a stray block comment in the go.mod
// being audited), this puts the stray "/* ... */" line in the ACTIVE go.work
// file instead — the go.mod itself is perfectly well-formed. Verified live
// before this fix: `go list -m all`/`go build` both Fatal immediately with
// "errors parsing go.work: ...: mod files must use // comments (not /* */
// comments)", never resolving a single requirement in app/go.mod, while this
// tool still reported "SUMDB LEAK" for the real, otherwise-uncovered
// private-auth-signaled require it could still see in that go.mod — an
// active wrong claim, since none of the existing go.mod-side parse checks
// ever looked at the go.work file's own bytes at all.
func TestRunBlockCommentGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./app

/* a stray block comment some tooling or human mistakenly wrote */
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work itself has a stray block comment (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunInvalidGoDirectiveGoWorkNoLeak is TestRunBlockCommentGoWorkNoLeak's
// sibling for a malformed `go` directive living in the go.work file instead
// of the go.mod being audited. Verified live before this fix: `go list -m
// all` Fatals immediately with "errors parsing go.work: ...: invalid go
// version '1.9x': must match format 1.23.0", while this tool still reported
// "SUMDB LEAK".
func TestRunInvalidGoDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.9x

use ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's go directive is malformed (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunInvalidToolchainDirectiveGoWorkNoLeak is
// TestRunBlockCommentGoWorkNoLeak's sibling for a malformed `toolchain`
// directive living in the go.work file. Verified live before this fix: `go
// list -m all` Fatals immediately with `go: invalid toolchain "1.24.4" in
// go.work` (missing the required "go" prefix), while this tool still
// reported "SUMDB LEAK".
func TestRunInvalidToolchainDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

toolchain 1.24.4

use ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's toolchain directive is malformed (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunUnknownDirectiveGoWorkNoLeak is TestRunBlockCommentGoWorkNoLeak's
// sibling for a top-level line in the go.work file whose verb isn't one of
// go.work's own four recognized directives — here, "uses" typo'd for "use".
// Verified live before this fix: `go list -m all` Fatals immediately with
// "errors parsing go.work: ...: unknown directive: uses", while this tool
// still reported "SUMDB LEAK".
func TestRunUnknownDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

uses ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work has an unrecognized top-level directive (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunInvalidReplaceDirectiveGoWorkNoLeak is
// TestRunInvalidReplaceDirectiveGoModNoLeak's sibling for a malformed
// `replace` directive living in the ACTIVE go.work file instead of the
// go.mod being audited — the go.mod itself is perfectly well-formed.
// go.work's replace syntax is identical to go.mod's (see goWorkReplaces'
// own doc comment: both are parsed through golang.org/x/mod/modfile's same
// parseReplace grammar), so the same "path@version" mistake (instead of
// go.mod's real space-separated "path version" form) is just as much a
// parse-time Fatal one file up. Verified live before this fix: `go list -m
// all` (GOENV=/dev/null GOPROXY=off) Fatals immediately with "errors parsing
// go.work: ...: replacement module must match format 'path version', not
// 'path@version'", never resolving a single requirement in app/go.mod, while
// this tool still reported "SUMDB LEAK" for the real, otherwise-uncovered
// private-auth-signaled require it could still see in that go.mod —
// goWorkHasUnparseableDirective never called goModHasInvalidReplaceDirective
// on the go.work's own bytes at all before this fix, even though the
// go.mod-side check of the identical shape already existed.
func TestRunInvalidReplaceDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./app

replace example.com/foo => example.com/bar@v1.0.0
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's replace directive uses \"path@version\" instead of \"path version\" (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunConflictingReplaceDirectiveGoModNoLeak is the direct regression
// test for goModHasConflictingReplaceDirective: a go.mod with two
// individually well-formed `replace` directives for the same old module
// path/version naming two different new-side targets makes every
// module-aware go subcommand Fatal immediately with "go: conflicting
// replacements for github.com/myorg/internal-tool:
// \n\texample.com/bar@v1.0.0\n\tgithub.com/privorg/baz@v1.0.0" — verified
// live (go1.26.8, GOPROXY=off; `go list -m all`/`go build`/`go mod
// download` all agree) — before resolving a single module. Before this
// fix, this tool's own best-effort addReplace/resolveEffectiveModules
// machinery silently applied "last replace wins", picking
// github.com/privorg/baz as the effective module to audit — which has its
// own uncovered private-auth signal (a git insteadOf rewrite for
// github.com/privorg/, with no matching GOPRIVATE entry) — and wrongly
// reported "SUMDB LEAK: github.com/privorg/baz ..." even though real go
// never queries anything for it, since the build Fatals on the
// conflicting-replacements error first, every time.
func TestRunConflictingReplaceDirectiveGoModNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

go 1.24

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456

replace github.com/myorg/internal-tool => example.com/bar v1.0.0
replace github.com/myorg/internal-tool => github.com/privorg/baz v1.0.0
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:privorg/"]
	insteadOf = https://github.com/privorg/
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
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when go.mod has two conflicting replace directives for the same old path/version (go itself would Fatal with \"conflicting replacements\" before any query), got: %s", stdout)
	}
}

// TestRunConflictingReplaceDirectiveGoWorkNoLeak is
// TestRunConflictingReplaceDirectiveGoModNoLeak's go.work-side counterpart:
// the identical "go: conflicting replacements for ...:\n\t...\n\t..."
// Fatal applies when the conflicting pair sits in an active go.work file's
// own replace list instead of the go.mod being audited (live-verified,
// go1.26.8, GOPROXY=off, `go list -m all` run from inside a `use`d member
// module) — see goWorkHasConflictingReplaceDirective.
func TestRunConflictingReplaceDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./app

replace github.com/myorg/internal-tool => example.com/bar v1.0.0
replace github.com/myorg/internal-tool => github.com/privorg/baz v1.0.0
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:privorg/"]
	insteadOf = https://github.com/privorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work has two conflicting replace directives for the same old path/version (go itself would Fatal with \"conflicting replacements\" before any query), got: %s", stdout)
	}
}

// TestRunGodebugDirectiveGoWorkStillLeaks is the direct regression test for
// a real-world-testing find: a well-formed `godebug key=value` line in an
// active go.work was, before this fix, misclassified by
// goWorkHasUnknownDirective as an unrecognized top-level verb (godebug was
// missing from goWorkValidTopLevelVerbs, even though golang.org/x/mod/modfile's
// real (*WorkFile).add has its own "godebug" case, byte-identical in shape to
// go.mod's). That false "unknown directive" verdict made
// goWorkHasUnparseableDirective wrongly conclude the go.work would make go
// Fatal before resolving anything, so run() silently skipped the whole
// audit — suppressing a real SUMDB LEAK finding, the mirror image of every
// other goWorkHasUnparseableDirective bug fixed so far (which all
// over-reported a leak that couldn't happen; this one under-reported one
// that could). Verified live before this fix: `go list -m all`
// (GOPROXY=off) against this exact go.work+go.mod reaches "module lookup
// disabled by GOPROXY=off" — i.e. it parses and resolves fine, never
// Fataling on go.work at all — while this tool reported "no issues found"
// instead of the real, otherwise-uncovered private-auth-signaled require's
// leak.
func TestRunGodebugDirectiveGoWorkStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24.4

godebug default=go1.24

use ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
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
		t.Errorf("exit code = %d, want 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout should still report the real leak when the active go.work merely has a well-formed godebug directive (real go parses and resolves this fine, never Fatals), got: %s", stdout)
	}
}

// TestRunInvalidGodebugDirectiveGoWorkNoLeak is
// TestRunInvalidReplaceDirectiveGoWorkNoLeak's sibling for a malformed
// `godebug` directive living in the ACTIVE go.work file instead of the
// go.mod being audited. go.work's godebug syntax is identical to go.mod's
// (see goModHasInvalidGodebugDirective's doc comment and
// goWorkHasUnparseableDirective's updated doc comment: both are parsed
// through golang.org/x/mod/modfile's same "godebug" case shape), so the
// same "no `=` in the argument" mistake is just as much a parse-time Fatal
// one file up. Verified live before this fix: `go list -m all`
// (GOPROXY=off) Fatals immediately with "errors parsing go.work: ...:
// usage: godebug key=value", never resolving a single requirement in
// app/go.mod.
func TestRunInvalidGodebugDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24.4

godebug nokeyvalue

use ./app
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's godebug directive has no \"=\" (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunInvalidUseDirectiveGoWorkNoLeak is the direct regression test for
// run #583's find: a bare "use" line with no directory argument in the
// ACTIVE go.work file. golang.org/x/mod/modfile's real (*WorkFile).add has
// a "use" case — `if len(args) != 1 { errorf("usage: %s local/dir", verb) }`
// — sharing `tool`/`module`/`ignore`'s exact single-fixed-argument grammar
// (see gomod.go's goModFixedArgCountVerbs and
// goWorkHasUnparseableDirective's updated doc comment), but
// goWorkHasUnparseableDirective never checked it before this fix: an earlier
// version of its doc comment wrongly reasoned "use" needed a content-shape
// check like replace/retract/godebug and was deliberately left out of scope,
// when it's actually just an omitted fixed-count check like `module` was
// (technique #86). Verified live before this fix: `go list -m all`
// (GOPROXY=off) Fatals immediately with "errors parsing go.work: ...: usage:
// use local/dir", never resolving a single requirement in app/go.mod, while
// this tool still reported "SUMDB LEAK" for the real, otherwise-uncovered
// private-auth-signaled require sitting in it.
func TestRunInvalidUseDirectiveGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24.4

use
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's \"use\" directive has zero arguments (go itself would Fatal parsing go.work before any query), got: %s", stdout)
	}
}

// TestRunInvalidUseDirectiveExtraArgGoWorkNoLeak is
// TestRunInvalidUseDirectiveGoWorkNoLeak's two-argument sibling: a "use"
// line naming two directories on one line instead of one. Verified live
// before this fix: `go list -m all` (GOPROXY=off) on the equivalent file
// Fatals identically with "usage: use local/dir".
func TestRunInvalidUseDirectiveExtraArgGoWorkNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24.4

use ./app ./other
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when the active go.work's \"use\" directive names two directories on one line (go itself would Fatal parsing go.work before any query), got: %s", stdout)
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
	// go.mod lives under app/, matching go.work's "use ./app" below: per
	// `go help work`, a "use" path names a directory that must actually
	// contain the member's go.mod (verified live: a go.work "use"ing a
	// directory with no go.mod there makes every module-aware command
	// Fatal immediately with "cannot load module app listed in go.work
	// file: open app/go.mod: no such file or directory" — a go.mod
	// sitting one level up, directly at dir, is not itself a member of
	// this workspace at all, and moduleOutsideWorkspace (gomod.go) now
	// correctly refuses to audit it as one).
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "app/vendor/modules.txt", `# github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
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

// TestRunGoflagsModInWorkspaceNoLeak is the direct end-to-end regression
// test for goflagsModRejectedInWorkspace (see vendor.go): GOFLAGS=-mod=mod
// is completely ordinary outside a workspace (see
// TestRunVendorModeExplicitModModStillLeaks), but real go's own
// setDefaultBuildMod restricts -mod to "readonly"/"vendor" once an active
// go.work workspace is in play — "-mod=mod" Fatals immediately with "-mod
// may only be set to readonly or vendor when in workspace mode", before
// resolving a single module. Verified live end-to-end against the actual
// goprivaudit binary before this fix: this exact go.mod/go.work/git-config
// combination was reported "SUMDB LEAK" — an active wrong claim for a
// checksum-database query that structurally cannot happen, since the real
// go command dies parsing its own flags first.
func TestRunGoflagsModInWorkspaceNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.24.4

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)
`)
	writeFile(t, dir, "app/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
		"-goflags", "-mod=mod",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when GOFLAGS=-mod=mod is set inside an active go.work workspace (go itself would Fatal before any query), got: %s", stdout)
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

// TestGoflagsRejectedByGo directly unit-tests goflagsRejectedByGo against
// the real go toolchain, covering all four of its outcomes: an empty
// goflags is never even probed (short-circuited, since it's the common
// case and can't possibly be rejected); a shape-valid but unregistered
// flag name is rejected (the real bug this function exists to catch — see
// TestRunUnknownGoflagsFlagNameNoLeak); a shape-valid, registered flag
// missing its required "=value" is also rejected (a distinct real go
// validation stage, SetFromGOFLAGS rather than InitGOFLAGS — see
// TestRunGoflagsMissingArgNoLeak); and an ordinary, real flag value is not
// rejected at all, confirming the live probe doesn't just always return
// true.
func TestGoflagsRejectedByGo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/probe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := goflagsRejectedByGo(dir, ""); got {
		t.Errorf("goflagsRejectedByGo(%q, \"\") = true, want false (empty GOFLAGS is never rejected)", dir)
	}
	if got := goflagsRejectedByGo(dir, "-notarealflag=vendor"); !got {
		t.Errorf(`goflagsRejectedByGo(%q, "-notarealflag=vendor") = false, want true (real go Fatals with "unknown flag")`, dir)
	}
	if got := goflagsRejectedByGo(dir, "-mod"); !got {
		t.Errorf(`goflagsRejectedByGo(%q, "-mod") = false, want true (real go Fatals with "flag needs an argument")`, dir)
	}
	if got := goflagsRejectedByGo(dir, "-mod=mod"); got {
		t.Errorf(`goflagsRejectedByGo(%q, "-mod=mod") = true, want false (a real, registered flag)`, dir)
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
	// go.mod lives under app/, matching go.work's "use ./app" — see
	// TestRunVendorModeInsideWorkspaceStillLeaks' comment for why a
	// go.mod that doesn't actually sit at a "use"d directory isn't a
	// member of the workspace at all (moduleOutsideWorkspace,
	// gomod.go).
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

require github.com/foo/bar v1.2.3
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	writeFile(t, dir, "app/.git/config", `[url "ssh://git@git.internal.example.com/"]
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
	// go.mod lives under app/, matching go.work's "use ./app" — see
	// TestRunVendorModeInsideWorkspaceStillLeaks' comment.
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

require github.com/foo/bar v1.2.3

replace github.com/foo/bar => github.com/safe-fork/bar v1.2.3
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

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
	// go.mod lives under app/, matching go.work's "use ./app" — see
	// TestRunVendorModeInsideWorkspaceStillLeaks' comment.
	gomod := writeFile(t, dir, "app/go.mod", `module example.com/app

require github.com/foo/bar v1.2.3

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
)

replace github.com/foo/bar v9.9.9 => example.com/unrelated-sibling-pin v0.0.0
`)
	writeFile(t, dir, "app/.git/config", `[url "ssh://git@git.internal.example.com/"]
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

// TestRunModuleOutsideWorkspaceSuppressesLeak is the direct regression test
// for the real-world-testing pass that found this: an active go.work
// workspace whose "use" directives don't list moduleDir at all (and don't
// reach it via any local replace either) makes every standard build
// command Fatal before it ever resolves moduleDir's own requires — see
// moduleOutsideWorkspace's doc comment in gomod.go for the exact,
// live-verified error messages ("current directory is contained in a
// module that is not one of the workspace modules listed in go.work" /
// "pattern ./...: directory prefix . does not contain modules listed in
// go.work or their selected dependencies") and the live confirmation that
// `go mod tidy`/bare `go mod download` both silently resolve zero
// packages in this state. Before this fix, goprivaudit ignored go.work
// membership entirely and reported "SUMDB LEAK" for a checksum-database
// query that structurally cannot happen for this go.mod in this state —
// an active wrong claim, the same failure class every other "cannot leak"
// skip in run() closes. This is a realistic misconfiguration, not a
// contrived one: GOWORK auto-discovery walks upward from moduleDir
// through every parent directory, so any go.work anywhere above it that
// simply hasn't been updated with a `use ./this-module` entry (a new
// module added to a monorepo workspace, or an unrelated go.work leftover
// from a different project in a shared parent directory) puts a module in
// exactly this state.
func TestRunModuleOutsideWorkspaceSuppressesLeak(t *testing.T) {
	dir := t.TempDir()
	// go.mod lives directly at dir, but go.work (also at dir) only "use"s
	// a sibling "./a" — moduleDir (dir) is neither `use`d nor the target
	// of any local replace, so it's excluded from the workspace entirely.
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, "a/go.mod", `module example.com/a

go 1.24
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./a
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-gowork", gowork,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0: moduleDir is excluded from the workspace, so no build can ever resolve its requires; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean when moduleDir is outside the workspace's use list, got: %s", stdout)
	}
}

// TestRunModuleOutsideUseListButReachableViaMemberReplaceStillLeaks checks
// the guard against a false negative in the fix above: moduleDir isn't
// itself `use`d, but a `use`d member's own go.mod replaces a require with
// moduleDir's local directory — the "...or their selected dependencies"
// half of the real go error moduleOutsideWorkspace's doc comment quotes.
// Verified live: `go list -m all` run from moduleDir in exactly this shape
// still resolves moduleDir's own require over the network (a real `git
// ls-remote` attempt), unlike the plain-excluded case above where nothing
// is ever resolved at all. moduleOutsideWorkspace must not treat this
// moduleDir as excluded, or it would suppress a real, reachable leak.
func TestRunModuleOutsideUseListButReachableViaMemberReplaceStillLeaks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/go.mod", `module example.com/a

go 1.24

require example.com/somepublicmod v1.0.0

replace example.com/somepublicmod => ../b
`)
	gomod := writeFile(t, dir, "b/go.mod", `module example.com/b

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./a
`)
	writeFile(t, dir, "b/.git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
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
		t.Errorf("exit code = %d, want 1: b is reachable as a's local replace target, so its own requires can still leak; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak for a module reachable via a workspace member's own replace: %s", stdout)
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

// TestRunToolDirectiveInMainModuleNotFalselyLeaked covers a real, documented
// Go 1.24 pattern (go.dev/ref/mod's `tool` directive doc: a tool directive
// may name "a main package in the main module", not just a dependency's,
// e.g. an in-repo build tool tracked the same go.mod-level way a
// third-party one is) that effectiveToolModules had no notion of at all: no
// function anywhere in this codebase read the go.mod's own `module`
// directive before this fix, so a tool path inside the main module was
// treated exactly like an uncovered external dependency's tool path (see
// TestRunFindsLeakViaUncoveredToolDirective). Live-verified (2026-09)
// against real go1.24.4: a go.mod with only `module github.com/myorg/mymod`
// / `go 1.24.4` / `tool github.com/myorg/mymod/cmd/mytool` (no require at
// all) builds fully offline (`GOPROXY=off go build ./...` succeeds) and `go
// list -m all` resolves only the main module itself — the tool path is
// never looked up as a separate module, so no sumdb query for it can ever
// happen, regardless of what git config says about github.com/myorg.
// Confirmed live end-to-end against the actual pre-fix goprivaudit binary:
// this exact go.mod plus this exact insteadOf rewrite (which would be a
// real, otherwise-uncovered private-auth signal for any *actual* dependency
// under github.com/myorg) was reported "SUMDB LEAK:
// github.com/myorg/mymod/cmd/mytool" pre-fix.
func TestRunToolDirectiveInMainModuleNotFalselyLeaked(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module github.com/myorg/mymod

go 1.24.4

tool github.com/myorg/mymod/cmd/mytool
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/myorg/"]
	insteadOf = https://github.com/myorg/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 for a tool path inside the main module; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak for a main-module-local tool path (never fetched over the network), got: %s", stdout)
	}
}

// TestRunToolDirectiveInMainModuleSiblingStillLeaked confirms the new
// main-module exclusion doesn't over-match: a tool path under a
// similarly-prefixed but genuinely different module
// (github.com/myorg/mymod2, not a subpackage of github.com/myorg/mymod)
// must still be audited as an external dependency's tool.
func TestRunToolDirectiveInMainModuleSiblingStillLeaked(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module github.com/myorg/mymod

go 1.24.4

tool github.com/myorg/mymod2/cmd/mytool
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/myorg/"]
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
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/mymod2/cmd/mytool") {
		t.Errorf("stdout missing expected leak finding for the sibling module's tool path: %s", stdout)
	}
}

// TestRunToolDirectiveInMainModuleBlockFormNotFalselyLeaked is
// TestRunToolDirectiveInMainModuleNotFalselyLeaked's counterpart for a
// go.mod declaring its module path via the parenthesized `module (...)`
// block form instead of the ordinary single-line form. parseModulePath
// used to assume "module" was never a block-form directive (an incorrect
// claim about golang.org/x/mod/modfile's real grammar — rule.go's block-type
// switch accepts "module" exactly like require/exclude/replace/retract/
// tool/ignore/godebug), so it read the opening "module (" line alone and
// returned the garbage token "(" instead of the real path "example.com/foo"
// sitting on the next line inside the block. Live-verified against real
// go1.26.8: `go list -m` on this exact go.mod resolves the main module as
// "example.com/foo", and `GOPROXY=off GOSUMDB=sum.golang.org go build
// -buildvcs=false ./...` succeeds fully offline — no sumdb query for the
// tool path ever happens, exactly like the single-line form. Confirmed live
// end-to-end against the actual pre-fix goprivaudit binary: this exact
// go.mod plus this exact credential-helper signal (which would be a real,
// otherwise-uncovered private-auth signal for any *actual* dependency under
// github.corp.example.com) was reported "SUMDB LEAK:
// github.corp.example.com/myorg/myproject/cmd/lint" pre-fix, while the
// single-line form of the identical go.mod was already correctly silent.
func TestRunToolDirectiveInMainModuleBlockFormNotFalselyLeaked(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module (
	example.com/foo
)

go 1.24.4

tool example.com/foo/cmd/lint
`)
	writeFile(t, dir, ".git/config", `[credential "https://example.com"]
	helper = store
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 for a tool path inside a block-form-declared main module; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("expected no leak for a main-module-local tool path (never fetched over the network), got: %s", stdout)
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

// TestRunPrivateOverridePropagatesToGonosumdbAmbientFallback is the direct
// regression test for a gap in the "-private overrides GOPRIVATE instead of
// reading it from `go env`" flag: when -nosumdb is left unset, run() reads
// the effective GONOSUMDB via `go env GONOSUMDB`, which — per cmd/go's own
// cfg.EnvOrAndChanged("GONOSUMDB", cfg.GOPRIVATE) — already resolves "GOPRIVATE
// is the fallback default for GONOSUMDB" itself, using whatever GOPRIVATE
// that child `go env` process's own environment sees. Before this fix,
// goEnv never passed the already-resolved (possibly -private-overridden)
// value into that child process's environment, so on a machine/CI runner
// with its own real, different ambient GOPRIVATE already set (e.g. a
// corporate `go env -w GOPRIVATE=...` applied machine-wide), a -private
// override meant to audit one project against a different, more specific
// pattern was silently ignored for the GONOSUMDB fallback: `go env
// GONOSUMDB` returned the real ambient GOPRIVATE's value instead, which
// came back non-empty, so the manual `gonosumdb == ""` fallback line never
// even ran. Live-verified pre-fix: with real GOPRIVATE=othercorp.example.com/*
// in the environment, `-private gitlab.corp.example.com/*` against a go.mod
// whose only dependency is privately-rewritten under that exact overridden
// pattern still reported a false SUMDB LEAK.
func TestRunPrivateOverridePropagatesToGonosumdbAmbientFallback(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require gitlab.corp.example.com/team/privaterepo v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@gitlab.corp.example.com/"]
	insteadOf = https://gitlab.corp.example.com/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	// A real, different ambient GOPRIVATE already set machine-wide — the
	// exact condition that silently defeated the -private override pre-fix.
	t.Setenv("GOPRIVATE", "othercorp.example.com/*")
	t.Setenv("GONOSUMDB", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "gitlab.corp.example.com/*",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 once the -private override covers the module; stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout has a false leak finding: the -private override should also cover GONOSUMDB's fallback, got: %s", stdout)
	}
}

// TestRunNosumdbOverrideStillWinsOverPrivateOverride guards against
// over-correcting the fix above: an explicit -nosumdb override must still
// take priority over -private's value, exactly like real go's GONOSUMDB env
// var takes priority over GOPRIVATE whenever it's actually set.
func TestRunNosumdbOverrideStillWinsOverPrivateOverride(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require gitlab.corp.example.com/team/privaterepo v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@gitlab.corp.example.com/"]
	insteadOf = https://gitlab.corp.example.com/
`)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GOPRIVATE", "othercorp.example.com/*")
	t.Setenv("GONOSUMDB", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "gitlab.corp.example.com/*",
		"-nosumdb", "othercorp.example.com/*", // deliberately does NOT cover the module
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; an explicit -nosumdb override that doesn't cover the module should still leak; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: gitlab.corp.example.com/team/privaterepo") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunGoSumCoveredModuleNoLeak is the regression test for the bug
// filterGoSumCovered fixes: a go.mod whose private-auth-signaled require is
// already fully pinned in the committed go.sum (both the content-hash line
// and the "/go.mod" hash line, for the exact required version) cannot
// trigger a new GOSUMDB query for that module on an ordinary subsequent
// `go build`/`go test` — live-verified (go1.24.4): with a real go.sum
// carrying both lines for a module, GOSUMDB pointed at an unreachable host,
// and a completely empty GOMODCACHE, `go build` still succeeds, under both
// the default -mod=readonly and an explicit -mod=mod. Before this fix,
// goprivaudit reported SUMDB LEAK unconditionally for any uncovered
// private-auth signal, regardless of go.sum's own contents — an active
// wrong claim for the extremely common case of a go.mod/go.sum pair already
// committed together.
func TestRunGoSumCoveredModuleNoLeak(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "go.sum", `github.com/myorg/internal-tool v1.2.3 h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdee=
github.com/myorg/internal-tool v1.2.3/go.mod h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdef=
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 once go.sum already covers the module; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no issues found") {
		t.Errorf("stdout should report clean once go.sum covers the module, got: %s", stdout)
	}
}

// TestRunGoSumMissingGoModHashStillLeaks confirms goSumCoversModule's
// "both lines, not just one" requirement end to end: a go.sum carrying only
// the content-hash line (no "/go.mod" line) for the module does NOT
// suppress the finding — live-verified that a real `go build` in this exact
// shape still attempts (and, with GOSUMDB unreachable, fails) a genuine
// GOSUMDB lookup for the missing half.
func TestRunGoSumMissingGoModHashStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "go.sum", `github.com/myorg/internal-tool v1.2.3 h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdee=
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; a go.sum missing the /go.mod hash line should still leak; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunGoSumWrongVersionStillLeaks confirms the go.sum coverage check is
// keyed on the exact required version, not just the module path: a go.sum
// entry for a different version of the same module (e.g. left over from an
// earlier require bump) does not suppress the finding for the version
// go.mod actually requires now, since `go` would still need a fresh
// checksum for that version.
func TestRunGoSumWrongVersionStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "go.sum", `github.com/myorg/internal-tool v1.2.2 h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdee=
github.com/myorg/internal-tool v1.2.2/go.mod h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdef=
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; go.sum pinning a different version should still leak for the required one; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunGoSumCoversReplacedModuleTargetStillLeaks confirms
// filterGoSumCovered's deliberate scoping (see its own doc comment): a
// module-path replace's effective path is never matched against go.sum's
// coverage, even when go.sum happens to carry a complete entry for that
// exact replacement path/version, because this tool's replaceTarget never
// records the replacement's own pinned version independently of the
// original require's — so a coincidental match here must not be trusted.
func TestRunGoSumCoversReplacedModuleTargetStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v1.2.3

replace github.com/myorg/internal-tool => github.com/myorg/internal-tool-fork v1.2.3
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	writeFile(t, dir, "go.sum", `github.com/myorg/internal-tool-fork v1.2.3 h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdee=
github.com/myorg/internal-tool-fork v1.2.3/go.mod h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdef=
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; a replaced module's effective path should not be matched against go.sum coverage; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool-fork") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunGoSumSamePathVersionReplaceStillLeaks covers the sharpest edge of
// filterGoSumCovered's replace scoping: a replace directive that keeps the
// SAME module path but pins a different version (a real, valid go.mod
// shape — e.g. pointing at a privately-patched release of the same import
// path) means the module list's path collides with the original require's
// own path, even though the version `go` actually resolves is the
// replace's, not the plain require's. A go.sum entry left over for the
// pre-replace version must not be mistaken for covering the real one.
func TestRunGoSumSamePathVersionReplaceStillLeaks(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v1.2.3

replace github.com/myorg/internal-tool => github.com/myorg/internal-tool v1.2.3-patched
`)
	writeFile(t, dir, ".git/config", `[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
`)
	// Only the pre-replace version's go.sum entry exists; the replace
	// target's own effective version (v1.2.3-patched) has no entry at all.
	writeFile(t, dir, "go.sum", `github.com/myorg/internal-tool v1.2.3 h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdee=
github.com/myorg/internal-tool v1.2.3/go.mod h1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdef=
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1; a same-path version-bumping replace must not be matched against the pre-replace version's go.sum entry; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "SUMDB LEAK: github.com/myorg/internal-tool") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}
