package main

import (
	"os"
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
		// SCP-like shorthand with no "user@" at all (e.g. an SSH config Host
		// alias that already carries the username) is still ssh per real
		// git's url_is_local_not_ssh (colon before any slash, no "@" check
		// at all) — verified live against real git in
		// TestSchemeOfScpShorthandWithoutUserAgainstRealGit. This file's
		// pre-fix schemeOf required a leading "user@" and misclassified
		// this as "file".
		{"host.xz:path/to/repo", "ssh"},
		{"internal-git:myorg/private.git", "ssh"},
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

// TestProtocolAllowFromEnv is protocolAllowFromGitConfig's own unit test,
// mirrored for the GIT_CONFIG_COUNT/KEY/VALUE env-var form: both the
// three-part "protocol.<name>.allow" key and the bare two-part
// "protocol.allow" key (no subsection at all, git-config(1)'s spelling for
// the default policy) must resolve into the same map shape
// protocolAllowFromGitConfig itself produces ("" for the bare form).
func TestProtocolAllowFromEnv(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "3",
		"GIT_CONFIG_KEY_0":   "protocol.allow",
		"GIT_CONFIG_VALUE_0": "never",
		"GIT_CONFIG_KEY_1":   "protocol.ssh.allow",
		"GIT_CONFIG_VALUE_1": "always",
		"GIT_CONFIG_KEY_2":   "protocol.ext.allow",
		"GIT_CONFIG_VALUE_2": "never",
	}
	getenv := func(k string) string { return env[k] }
	got := protocolAllowFromEnv(getenv)
	want := map[string]string{"": "never", "ssh": "always", "ext": "never"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestProtocolAllowFromEnvIgnoresUnrelatedKeys checks that only
// protocol.allow/protocol.<name>.allow keys are picked up, not an unrelated
// two- or three-part key that happens to share a segment name.
func TestProtocolAllowFromEnvIgnoresUnrelatedKeys(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT":   "2",
		"GIT_CONFIG_KEY_0":   "protocol.other",
		"GIT_CONFIG_VALUE_0": "never",
		"GIT_CONFIG_KEY_1":   "credential.https://example.com/.helper",
		"GIT_CONFIG_VALUE_1": "",
	}
	getenv := func(k string) string { return env[k] }
	got := protocolAllowFromEnv(getenv)
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// TestRunSuppressesLeakWhenEnvProtocolAllowBlocksTheInsteadOfTarget is the
// GIT_CONFIG_COUNT/KEY/VALUE-env-var counterpart to
// TestRunSuppressesLeakWhenProtocolAllowConfigBlocksTheInsteadOfTarget:
// protocol.ssh.allow=never set purely via the env-var config mechanism
// (git-config(1)'s documented "spawn multiple git commands with a common
// configuration but cannot depend on a configuration file" case), with NO
// file-based protocol.allow entry at all, must suppress the leak exactly
// like the file-based form does — verified live (2026-09) that a real
// `GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=url.ssh://git@github.com/.insteadof
// GIT_CONFIG_VALUE_0=https://github.com/myorg/
// GIT_CONFIG_KEY_1=protocol.ssh.allow GIT_CONFIG_VALUE_1=never git
// ls-remote https://github.com/myorg/internal-tool` fails outright with
// "fatal: transport 'ssh' not allowed", the identical error the file-based
// sibling test already covers. Before this fix, effectiveProtocolAllow
// only ever scanned config FILES for protocol.allow/protocol.<name>.allow,
// so this exact env-only signal was invisible and the leak was wrongly
// reported.
func TestRunSuppressesLeakWhenEnvProtocolAllowBlocksTheInsteadOfTarget(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "url.ssh://git@github.com/.insteadof")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://github.com/myorg/")
	t.Setenv("GIT_CONFIG_KEY_1", "protocol.ssh.allow")
	t.Setenv("GIT_CONFIG_VALUE_1", "never")

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

// TestRunEnvProtocolAllowOverridesFileWhichAllows is the precedence
// regression guard for the fix above: real git lets the env-var config
// mechanism override a config FILE's opposite setting (verified live: a
// real ~/.gitconfig with protocol.ssh.allow=always plus
// GIT_CONFIG_KEY_0=protocol.ssh.allow/GIT_CONFIG_VALUE_0=never still fails
// with "fatal: transport 'ssh' not allowed") — so effectiveProtocolAllow
// must apply the env-var scan AFTER (overriding) the file-based one, not
// merely fall back to it when a file value already exists.
func TestRunEnvProtocolAllowOverridesFileWhichAllows(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/

[protocol "ssh"]
	allow = always
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "protocol.ssh.allow")
	t.Setenv("GIT_CONFIG_VALUE_0", "never")

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

// TestGitProtocolAllowedInvalidPolicyValueBlocks is a regression test for
// policyAllows: a protocol.allow/protocol.<name>.allow value that isn't one
// of git's own three recognized keywords ("always", "never", "user",
// case-insensitive) makes real git die with "unknown value for config" the
// instant it resolves the policy, before any network connection, for every
// fetch using that scheme — the identical "cannot leak" effect "never" has,
// just reached via a config-parse Fatal instead of a deliberate block (see
// policyAllows' own doc comment for the live-verified transcripts, both for
// a plain typo and for the very plausible "true"/"false" boolean-looking
// mistake). Before this fix, policyAllows treated any non-"never" value —
// including "true"/"false"/garbage — as if it were "always", so
// gitProtocolAllowed wrongly reported the transport as permitted.
func TestGitProtocolAllowedInvalidPolicyValueBlocks(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, policy := range []string{"true", "false", "bogus", "", "Always-ish"} {
		if gitProtocolAllowed("ssh", map[string]string{"ssh": policy}, noEnv) {
			t.Errorf("protocol.ssh.allow=%q must be treated as blocked: real git dies with \"unknown value for config\" rather than permitting the fetch", policy)
		}
	}
	for _, policy := range []string{"always", "Always", "ALWAYS", "user", "User"} {
		if !gitProtocolAllowed("ssh", map[string]string{"ssh": policy}, noEnv) {
			t.Errorf("protocol.ssh.allow=%q must be treated as allowed", policy)
		}
	}
	for _, policy := range []string{"never", "Never", "NEVER"} {
		if gitProtocolAllowed("ssh", map[string]string{"ssh": policy}, noEnv) {
			t.Errorf("protocol.ssh.allow=%q must be treated as blocked", policy)
		}
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

// TestRunSuppressesLeakWhenProtocolAllowConfigHasAnInvalidValue is a
// regression test for policyAllows' own fix: a protocol.<name>.allow value
// that isn't "always"/"never"/"user" (here, "true" — the natural mistake of
// treating this boolean-looking knob as an actual boolean) makes real git
// die with "unknown value for config 'protocol.ssh.allow': true" the
// instant it resolves the policy for any ssh fetch, never reaching the
// network — confirmed live (see policyAllows' doc comment) — so the insteadOf
// rewrite below can never actually authenticate anything and no sumdb query
// can happen either. Before this fix, policyAllows treated "true" as if it
// were "always", so this reported a live SUMDB LEAK.
func TestRunSuppressesLeakWhenProtocolAllowConfigHasAnInvalidValue(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[url "ssh://git@github.com/"]
	insteadOf = https://github.com/myorg/

[protocol "ssh"]
	allow = true
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
		t.Errorf("stdout should not report a leak for a structurally-invalid protocol.allow value: %s", stdout)
	}
}

// TestRunStillFlagsLeakForScpShorthandWithoutUserWhenFileProtocolBlocked is a
// regression test for the schemeOf false negative fixed above: an insteadOf
// target written as the SCP-like shorthand with no "user@" prefix (e.g. an
// SSH config Host alias that already carries the username — a real,
// documented git-clone(1) form, not a contrived one) must still be
// classified as ssh, not "file". Before the fix, schemeOf misread this
// exact config as the "file" transport, and a real-world, unrelated
// hardening setting like `protocol.file.allow = never` (a long-recommended
// git security default — see CVE-2017-1000117 and git's own 2.38+ default
// tightening of file/ext protocol.allow) then made
// suppressProtocolBlockedInsteadOf wrongly treat this genuine,
// ssh-authenticated, uncovered-by-GOPRIVATE fetch as blocked, silently
// dropping a real SUMDB LEAK down to "no issues found" — confirmed live
// end-to-end against the actual goprivaudit binary (see this fix's commit
// message for the full transcript). `protocol.file.allow=never` has no
// effect on the real ssh fetch this config performs (verified live: the
// same setting DOES block a genuine bare local-path insteadOf target, see
// TestRunSuppressesLeakWhenProtocolAllowConfigBlocksTheInsteadOfTarget's
// sibling scenario), so the leak must survive.
func TestRunStillFlagsLeakForScpShorthandWithoutUserWhenFileProtocolBlocked(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.corp.example.com/org/private-lib v1.0.0
`)
	writeFile(t, dir, ".git/config", `[url "internal-git:"]
	insteadOf = https://git.corp.example.com/

[protocol "file"]
	allow = never
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
	if !strings.Contains(stdout, "SUMDB LEAK: git.corp.example.com/org/private-lib") {
		t.Errorf("stdout missing expected leak finding: %s", stdout)
	}
}

// TestRunSuppressesLeakWhenGitAllowProtocolBlocksACredentialHelpersOwnScheme
// covers the credential.helper/http.extraHeader counterpart of
// TestRunSuppressesLeakWhenGitAllowProtocolBlocksTheInsteadOfTarget: no
// insteadOf rewrite at all here, just a URL-scoped credential helper for a
// plain https:// context, combined with GIT_ALLOW_PROTOCOL=ssh (SSH-only
// hardening — the mirror image of the https-only hardening the insteadOf
// test uses, equally realistic: an org that moved off long-lived HTTPS PATs
// to SSH keys and forgot to remove an old credential.helper entry).
// Live-verified (see prefixSlot.scheme's doc comment): a real
// `git ls-remote https://...`/`go get` against the identical combination
// fails immediately with "fatal: transport 'https' not allowed", before the
// credential helper is ever consulted and before any hash is computed to
// send to the checksum database — so the module's only private-auth signal
// can never actually authenticate anything, and this finding must not fire.
func TestRunSuppressesLeakWhenGitAllowProtocolBlocksACredentialHelpersOwnScheme(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "https://github.com/myorg"]
	helper = store
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_ALLOW_PROTOCOL", "ssh")

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

// TestRunStillFlagsLeakForCredentialHelperWhenGitAllowProtocolAllowsHttps is
// the regression guard for the fix above: the exact same config, but with
// GIT_ALLOW_PROTOCOL explicitly permitting https, must still be flagged.
func TestRunStillFlagsLeakForCredentialHelperWhenGitAllowProtocolAllowsHttps(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "https://github.com/myorg"]
	helper = store
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

// TestRunSuppressesLeakWhenGitAllowProtocolBlocksAnExtraHeadersOwnScheme is
// the http.extraHeader counterpart of the credential.helper test above —
// same mechanism (prefixSlot.scheme, populated by setSignalSlot for both
// signal types identically), different signal source.
func TestRunSuppressesLeakWhenGitAllowProtocolBlocksAnExtraHeadersOwnScheme(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require github.example.corp/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[http "https://github.example.corp/myorg"]
	extraheader = AUTHORIZATION: basic dGVzdDp0ZXN0
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_ALLOW_PROTOCOL", "ssh")

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

// TestRunStillFlagsLeakForSchemeOmittedCredentialHelperWhenFileProtocolBlocked
// covers a scheme-omitted [credential "..."] section (see
// TestPrivatePrefixesFromGitConfigCredentialHelperSchemeOmitted in
// gitconfig_test.go for the parsing-level half of this bug) combined with
// the protocol-blocked-transport suppression this file adds
// (TestRunSuppressesLeakWhenGitAllowProtocolBlocksACredentialHelpersOwnScheme
// above): a section pattern that never named an explicit scheme applies to
// every protocol (verified live — see
// normalizeSectionURLToModulePrefix's doc comment in gitconfig.go), so it
// must never be treated as scoped to just one guessed scheme the way an
// explicit "https://..."-scoped section is. Before this fix, schemeOf was
// called on the bare section URL unconditionally and (per its own
// documented ssh-vs-local-path heuristic for a colon-less string)
// classified it as "file" — so once GIT_ALLOW_PROTOCOL blocked "file"
// (leaving https, the transport go actually uses, allowed) the credential
// helper's own protocol-scheme filter wrongly suppressed a real, live
// leak signal.
func TestRunStillFlagsLeakForSchemeOmittedCredentialHelperWhenFileProtocolBlocked(t *testing.T) {
	dir := t.TempDir()
	gomod := writeFile(t, dir, "go.mod", `module example.com/app

require git.corp.example.com/myorg/internal-tool v0.0.0-20230101000000-abcdef123456
`)
	writeFile(t, dir, ".git/config", `[credential "git.corp.example.com"]
	helper = store
`)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_ALLOW_PROTOCOL", "https")

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

// TestGitProtocolAllowedAgainstRealGit is an oracle-diff test against the
// real `git` binary: for a representative scheme/policy combination, does
// a real `git ls-remote` actually fail with "fatal: transport '<scheme>'
// not allowed" exactly when gitProtocolAllowed says it should? Targets are
// chosen to fail fast without real network access regardless of whether
// the protocol check itself blocks them (closed local ports, a
// nonexistent local file path) — protocol.allow is checked before any
// connection attempt, so the two failure modes ("not allowed" vs. a
// transport-level error) are easy to distinguish from git's own stderr.
//
// blockedByGit also recognizes git's "unknown value for config" fatal (not
// just "... not allowed"): a protocol.allow/protocol.<name>.allow value
// outside git's own three recognized keywords (always/never/user) makes
// git die with that message the instant it resolves the policy, the
// identical "never reaches the network" effect "not allowed" has (see
// policyAllows' doc comment in gitconfig.go) — this oracle must treat both
// as "blocked", or an invalid-value case would wrongly look unblocked by
// git while gitProtocolAllowed (correctly, post-fix) reports it blocked.
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
		{"ssh blocked by an invalid protocol.ssh.allow value", "ssh", "ssh://127.0.0.1:1/x", []string{"-c", "protocol.ssh.allow=true"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{}, c.gitArgs...), "ls-remote", c.url)
			cmd := exec.Command("git", args...)
			out, _ := cmd.CombinedOutput()
			blockedByGit := strings.Contains(string(out), "not allowed") || strings.Contains(string(out), "unknown value for config")

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

// TestSchemeOfScpShorthandWithoutUserAgainstRealGit is an oracle-diff test
// against real git for schemeOf itself (not just gitProtocolAllowed): does a
// real `git ls-remote` on an SCP-like target with no "user@" prefix actually
// route over ssh, or does it treat the target as a local filesystem path (as
// this file's pre-fix schemeOf assumed)? Distinguishes the two by pointing
// GIT_SSH_COMMAND at a stand-in script that records its own invocation to a
// marker file before failing — if git never launches an ssh child process at
// all (the "file" transport reads straight off disk with no subprocess),
// the marker is never written. Verified live (see this fix's commit
// message) with the real ssh binary and GIT_TRACE too; this test only needs
// GIT_SSH_COMMAND, so it has no dependency on an ssh binary being installed
// or on real network access.
func TestSchemeOfScpShorthandWithoutUserAgainstRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	dir := t.TempDir()
	marker := dir + "/ssh-invoked"
	script := dir + "/fake-ssh.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch \""+marker+"\"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	url := "host.xz:path/to/repo"
	if got := schemeOf(url); got != "ssh" {
		t.Fatalf("schemeOf(%q) = %q, want %q", url, got, "ssh")
	}

	cmd := exec.Command("git", "ls-remote", url)
	cmd.Env = append(cmd.Environ(), "GIT_SSH_COMMAND="+script)
	_ = cmd.Run()

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("real git never invoked the ssh command for %q — it did not route over ssh as schemeOf claims (marker missing: %v)", url, err)
	}
}
