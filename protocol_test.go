package main

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestSchemeOf(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://github.com/myorg/", "https"},
		{"http://mirror.internal/myorg/", "http"},
		{"ssh://git@github.com/myorg/", "ssh"},
		{"git://127.0.0.1/myorg/", "git"},
		{"ext::sh -c 'git-upload-pack %S /repo'", "ext"},
		{"git@github.com:myorg/", "ssh"}, // go.dev FAQ's documented SCP-like form
		{"user@host.example.com:path/to/repo.git", "ssh"},
		{"/srv/git/mirror.git", "file"},
		{"../local/mirror.git", "file"},
		{"", ""},
	}
	for _, c := range cases {
		if got := schemeOf(c.url); got != c.want {
			t.Errorf("schemeOf(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestInsteadOfSchemes(t *testing.T) {
	src := `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/

[url "http://mirror.internal/"]
	insteadOf = https://example.com/private/
`
	got := insteadOfSchemes([]byte(src))
	want := map[string][]string{
		"github.com/myorg":    {"ssh"},
		"example.com/private": {"http"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestProtocolAllowFromGitConfig(t *testing.T) {
	src := `[protocol]
	allow = never

[protocol "ssh"]
	allow = always

[protocol "ext"]
	allow = never
`
	got := protocolAllowFromGitConfig([]byte(src))
	want := map[string]string{"": "never", "ssh": "always", "ext": "never"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGitProtocolAllowedGitAllowProtocolIsAuthoritative(t *testing.T) {
	getenv := func(k string) string {
		if k == "GIT_ALLOW_PROTOCOL" {
			return "https:ssh"
		}
		return ""
	}
	// ssh is listed: allowed, even with no protocol.ssh.allow entry at all.
	if !gitProtocolAllowed("ssh", nil, getenv) {
		t.Error("ssh should be allowed: listed in GIT_ALLOW_PROTOCOL")
	}
	// git is not listed: blocked, even though git's own built-in default
	// for "git" is "always" and no config says otherwise — per git(1),
	// GIT_ALLOW_PROTOCOL "behave[s] as if protocol.allow is set to never,
	// and each of the listed protocols has protocol.<name>.allow set to
	// always (overriding any existing configuration)".
	if gitProtocolAllowed("git", nil, getenv) {
		t.Error("git should be blocked: not listed in GIT_ALLOW_PROTOCOL")
	}
	// Even an explicit protocol.<name>.allow=always is overridden by a
	// GIT_ALLOW_PROTOCOL list that omits it.
	if gitProtocolAllowed("git", map[string]string{"git": "always"}, getenv) {
		t.Error("GIT_ALLOW_PROTOCOL must override an explicit protocol.git.allow=always")
	}
}

func TestGitProtocolAllowedConfigPrecedence(t *testing.T) {
	noEnv := func(string) string { return "" }
	// protocol.<name>.allow beats the bare protocol.allow default.
	allow := map[string]string{"": "never", "ssh": "always"}
	if !gitProtocolAllowed("ssh", allow, noEnv) {
		t.Error("protocol.ssh.allow=always should win over protocol.allow=never")
	}
	if gitProtocolAllowed("git", allow, noEnv) {
		t.Error("git falls back to protocol.allow=never (no protocol.git.allow entry)")
	}
}

func TestGitProtocolAllowedBuiltinDefaults(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, scheme := range []string{"http", "https", "git", "ssh", "file"} {
		if !gitProtocolAllowed(scheme, nil, noEnv) {
			t.Errorf("%s should be allowed by git's built-in default policy", scheme)
		}
	}
	if gitProtocolAllowed("ext", nil, noEnv) {
		t.Error("ext defaults to \"never\" per git's own built-in policy table")
	}
}

func TestGitProtocolAllowedUnknownSchemeFailsOpen(t *testing.T) {
	// schemeOf returning "" (couldn't confidently classify the URL) must
	// never cause a real signal to be suppressed.
	if !gitProtocolAllowed("", map[string]string{"": "never"}, func(string) string { return "" }) {
		t.Error("an indeterminate scheme must fail open (treated as allowed)")
	}
}

func TestSuppressProtocolBlockedInsteadOfOnlySuppressesTheBlockedOccurrence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".git/config", `[url "ssh://127.0.0.1:1/mirror.git"]
	insteadOf = https://github.com/myorg/leaky

[credential "https://github.com/myorg/leaky"]
	helper = store
`)
	getenv := func(k string) string {
		if k == "GIT_ALLOW_PROTOCOL" {
			return "https" // blocks the ssh insteadOf target
		}
		return ""
	}
	// Simulate what run() assembles: one prefix from the (now-blocked)
	// insteadOf rule, one from the still-valid credential helper.
	prefixes := []string{"github.com/myorg/leaky", "github.com/myorg/leaky"}
	got := suppressProtocolBlockedInsteadOf(prefixes, dir, getenv)
	want := []string{"github.com/myorg/leaky"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (the credential-helper-backed occurrence must survive)", got, want)
	}
}

// TestRunSuppressesLeakWhenGitAllowProtocolBlocksTheInsteadOfTarget is an
// end-to-end test of the false positive this fix closes: an insteadOf
// rewrite to ssh:// (go.dev's own documented private-auth pattern, and
// this tool's primary example) combined with GIT_ALLOW_PROTOCOL=https (a
// real, mainstream hardening pattern — SSH disabled org-wide). Verified
// live (see gitProtocolAllowed's doc comment) that a real `go mod
// download` against this exact combination fails with "fatal: transport
// 'ssh' not allowed" before ever contacting sum.golang.org, so no leak can
// occur — pre-fix, goprivaudit still reported one unconditionally.
func TestRunSuppressesLeakWhenGitAllowProtocolBlocksTheInsteadOfTarget(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_ALLOW_PROTOCOL", "https")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (no leak possible); stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout should not report a leak for a structurally-blocked transport: %s", stdout)
	}
}

// TestRunStillFlagsLeakWhenGitAllowProtocolAllowsTheScheme is the
// regression guard for the fix above: the exact same config, but with
// GIT_ALLOW_PROTOCOL explicitly permitting ssh, must still be flagged.
func TestRunStillFlagsLeakWhenGitAllowProtocolAllowsTheScheme(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_ALLOW_PROTOCOL", "https:ssh")

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

// TestRunSuppressesLeakWhenProtocolAllowConfigBlocksTheInsteadOfTarget
// covers the git-config-file form of the same mechanism (protocol.<name>.allow,
// not just the GIT_ALLOW_PROTOCOL env var) — verified live that
// `git -c protocol.ssh.allow=never ls-remote ssh://...` fails with the
// identical "fatal: transport 'ssh' not allowed" error.
func TestRunSuppressesLeakWhenProtocolAllowConfigBlocksTheInsteadOfTarget(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/

[protocol "ssh"]
	allow = never
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	stdout, _, code := captureRun(t, []string{
		"-gomod", gomod,
		"-private", "",
		"-nosumdb", "",
	})
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (no leak possible); stdout=%s", code, stdout)
	}
	if strings.Contains(stdout, "SUMDB LEAK") {
		t.Errorf("stdout should not report a leak for a structurally-blocked transport: %s", stdout)
	}
}

// TestGitProtocolAllowedAgainstRealGit is an oracle-diff test against the
// real `git` binary: for a representative scheme/policy combination, does
// a real `git ls-remote` actually fail with "fatal: transport '<scheme>'
// not allowed" exactly when gitProtocolAllowed says it should? Targets are
// chosen to fail fast without real network access regardless of whether
// the protocol check itself blocks them (closed local ports, a
// nonexistent local file path) — protocol.allow is checked before any
// connection attempt, so the two failure modes ("not allowed" vs. a
// transport-level error) are easy to distinguish from git's own stderr.
func TestGitProtocolAllowedAgainstRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	cases := []struct {
		name    string
		scheme  string
		url     string
		gitArgs []string // extra `-c` flags to restrict the protocol
	}{
		{"ssh blocked by protocol.ssh.allow", "ssh", "ssh://127.0.0.1:1/x", []string{"-c", "protocol.ssh.allow=never"}},
		{"git blocked by protocol.allow default", "git", "git://127.0.0.1:1/x", []string{"-c", "protocol.allow=never"}},
		{"ssh allowed by default", "ssh", "ssh://127.0.0.1:1/x", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{}, c.gitArgs...), "ls-remote", c.url)
			cmd := exec.Command("git", args...)
			out, _ := cmd.CombinedOutput()
			blockedByGit := strings.Contains(string(out), "not allowed")

			allow := map[string]string{}
			for i := 0; i+1 < len(c.gitArgs); i += 2 {
				if c.gitArgs[i] != "-c" {
					continue
				}
				k, v, ok := strings.Cut(c.gitArgs[i+1], "=")
				if !ok {
					continue
				}
				// protocol.allow / protocol.<name>.allow both have exactly
				// two or three dot-separated components with no
				// URL-shaped subsection, so a plain split (rather than
				// splitConfigKey, built for the URL-subsection case) is
				// enough here.
				parts := strings.SplitN(k, ".", 3)
				switch len(parts) {
				case 2: // protocol.allow
					allow[""] = v
				case 3: // protocol.<name>.allow
					allow[parts[1]] = v
				}
			}
			blockedByModel := !gitProtocolAllowed(c.scheme, allow, func(string) string { return "" })

			if blockedByGit != blockedByModel {
				t.Errorf("real git blocked=%v, gitProtocolAllowed says blocked=%v (git output: %s)", blockedByGit, blockedByModel, out)
			}
		})
	}
}
