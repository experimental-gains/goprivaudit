package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var urlSectionRe = regexp.MustCompile(`(?i)^\[url\s+"([^"]*)"\]$`)
var credentialSectionRe = regexp.MustCompile(`(?i)^\[credential\s+"([^"]*)"\]$`)
var httpSectionRe = regexp.MustCompile(`(?i)^\[http\s+"([^"]*)"\]$`)
var includeSectionRe = regexp.MustCompile(`(?i)^\[include\]$`)
var includeIfSectionRe = regexp.MustCompile(`(?i)^\[includeif\s+"([^"]*)"\]$`)
var protocolSectionRe = regexp.MustCompile(`(?i)^\[protocol(?:\s+"([^"]*)")?\]$`)

// privatePrefixesFromGitConfig scans a gitconfig file's contents for three
// independent private-auth signals:
//
//	[url "git@github.com:myorg/"]
//		insteadOf = https://github.com/myorg/
//
// the standard way to make `go get`/`go mod download` authenticate to a
// private host over SSH instead of anonymous HTTPS,
//
//	[credential "https://github.com/myorg"]
//		helper = store
//
// a URL-scoped git credential helper (see gitcredentials(7), "CREDENTIAL
// CONTEXTS") — the mechanism `go`'s own subprocess `git clone`/`git
// fetch` uses to authenticate a *plain, unrewritten* HTTPS URL, e.g. the
// config `gh auth setup-git` writes per-host. No insteadOf rewrite is
// needed for this path at all, so a module authenticated purely this way
// was previously invisible to this tool. And:
//
//	[http "https://github.mycorp.example/"]
//		extraheader = AUTHORIZATION: basic <base64 token>
//
// a URL-scoped extra HTTP header (git-config(1): `http.<url>.extraHeader`)
// that embeds the literal credential in the config itself — the mechanism
// `actions/checkout` uses by default to persist a CI job's token. All
// three return the "origin" side of the config, normalized into a
// module-path-style prefix (scheme and trailing .git/ stripped), since
// that's the form that module paths in go.mod are written in and the
// form GOPRIVATE patterns need to cover.
//
// Only "insteadOf" counts as a signal in a [url] section, not
// "pushInsteadOf": git only rewrites fetch/clone URLs for the former
// (verified against real git behavior — a pushInsteadOf-only config leaves
// `git ls-remote`/`git fetch` hitting the original public HTTPS URL
// unchanged). `go get`'s module fetches are a read path, so a
// pushInsteadOf-only rewrite (a common pattern: anonymous HTTPS for
// reads, authenticated SSH only for pushes) never makes the fetch
// private, and treating it as a sumdb-leak signal would flag every
// ordinary public dependency under that prefix.
//
// Only a non-empty "helper" counts as a signal in a [credential] section —
// `gh auth setup-git` itself writes an empty "helper = " line first (to
// clear any inherited default) before the real "helper = !gh auth
// git-credential" line, and an empty value configures no credentials at
// all. A bare top-level [credential] section (no URL context, applying to
// every fetch) is not scanned as a signal either way: `isKnownPublicHost`
// only ever excludes a *bare-host* [url]/[credential]/[http] context (see
// its doc comment) — a completely unscoped [credential] section is
// broader still, applying to hosts that aren't even multi-tenant code
// hosts, and treating it as "every dependency is private" would be an
// even worse false-positive flood than the bare-host case it's modeled
// on.
//
// But an empty "helper" line doesn't just fail to configure anything — per
// gitcredentials(7): "If credential.helper is configured to the empty
// string, this resets the helper list to empty (so you may override a
// helper set by a lower-priority config file...)". That reset applies
// regardless of which side of a non-empty helper line for the *same*
// URL context it appears on: `gh auth setup-git`'s empty-then-real order
// leaves the real helper active (already handled above), but a
// real-then-empty order — e.g. a generated dotfile that later disables a
// helper it had itself just configured for one host — leaves NO helper
// active for that context at all. Verified live: with
// `[credential "https://x"] helper = /path/to/real-helper` followed by a
// second `helper =` line in the same section, `git credential fill`
// never invokes real-helper at all (confirmed via a logging stand-in
// script) and fails outright with "could not read Username ... No such
// device or address" — so a naive "any non-empty helper line for this URL
// is a signal" check (this function's pre-fix behavior) reports a
// SUMDB LEAK for a module that, per real git, has no credential helper
// authenticating it whatsoever: a false positive on a config this tool
// exists to read faithfully, not just glance at. Tracked per URL context
// via credSlots below so the *last* helper line for a given URL wins,
// matching real git's sequential reset-or-append list semantics exactly.
//
// A third, independent signal: a non-empty "extraheader" in a
// URL-scoped [http "..."] section (git-config(1): `http.<url>.extraHeader`
// is a real per-URL config key, section form `[http "https://x/"]
// extraHeader = ...`, verified against real git's own section-header
// normalization). Unlike insteadOf/credential.helper, this one embeds the
// literal credential material in the config value itself rather than
// naming a mechanism — it's exactly how `actions/checkout` (by far the
// most-used GitHub Action, the default way Go CI jobs check out code)
// persists the job's GITHUB_TOKEN by default: it writes
// `http.<serverURL origin>/.extraheader = AUTHORIZATION: basic <token>`
// into a config file wired in via includeIf.gitdir, which
// privatePrefixesFromConfigFile already follows (confirmed against
// actions/checkout's real git-auth-helper.ts source and reproduced live:
// `git config --get-all http.<url>.extraheader` resolves through that
// exact includeIf chain). For github.com/gitlab.com/etc. — the default,
// bare-host case actions/checkout normally produces — this is correctly
// exempted by isKnownPublicHost, same as a blanket insteadOf rewrite,
// since otherwise every public dependency checked out in an ordinary
// GitHub Actions job would falsely look like a sumdb leak. But for a
// self-hosted GitHub/GitLab Enterprise instance (`githubServerUrl` set to
// a private host, an extremely common enterprise Go CI setup), the same
// mechanism authenticates every fetch to that host with a real,
// job-scoped token — a genuine private-auth signal that was completely
// invisible before this fix, since no [http ...] section was parsed at
// all.
//
// git-config(1) documents the exact same reset-on-empty behavior for
// `http.<url>.extraHeader` as for credential.helper above ("an empty
// value will reset the extra headers to the empty list") — confirmed live
// with a local HTTP server standing in for the remote: a real `git
// ls-remote` sent no X-marker header at all once a second, empty
// `extraheader =` line followed a first real one in the same [http "..."]
// section, even though the pre-fix code (which only ever checked
// value != "") would still have reported that host as a sumdb-leak
// signal. Handled the same way, via httpSlots.
// prefixSlot is one candidate private-auth-signal prefix collected while
// scanning a git config source (a file or the GIT_CONFIG_COUNT env-var
// form), tracked as a pointer so a later reset (see setSignalSlot) can
// flip it back off without disturbing the position it was first recorded
// at — matching real git's own file-order-sequential list semantics for
// credential.helper / http.extraHeader (see privatePrefixesFromGitConfig's
// doc comment) while still emitting prefixes in a stable, predictable
// order (first-occurrence position) for everything that stays active.
type prefixSlot struct {
	value  string
	active bool
}

// setSignalSlot records or resets a multi-valued, reset-on-empty git
// config signal (credential.helper or http.extraHeader) for one URL
// context: an empty value resets the existing slot for that URL to
// inactive if one exists (a no-op if none does — resetting a signal that
// was never set is harmless, same as real git resetting an inherited
// helper that happens not to exist), and a non-empty value activates the
// existing slot for that URL if one exists or creates and records a new
// one (appended to *slots, so it's emitted in first-occurrence order) —
// unless the URL normalizes to a known public host, in which case no slot
// is ever created for it at all, same as every other signal source in
// this file.
func setSignalSlot(slots *[]*prefixSlot, bySectionURL map[string]*prefixSlot, sectionURL, value string) {
	if value == "" {
		if s, ok := bySectionURL[sectionURL]; ok {
			s.active = false
		}
		return
	}
	if s, ok := bySectionURL[sectionURL]; ok {
		s.active = true
		return
	}
	p := normalizeToModulePrefix(sectionURL)
	if p == "" || isKnownPublicHost(p) {
		return
	}
	s := &prefixSlot{value: p, active: true}
	*slots = append(*slots, s)
	bySectionURL[sectionURL] = s
}

func privatePrefixesFromGitConfig(data []byte) []string {
	var slots []*prefixSlot
	credSlots := map[string]*prefixSlot{}
	httpSlots := map[string]*prefixSlot{}
	section := "" // "", "url", "credential", "http"
	sectionURL := ""
	for _, raw := range splitLogicalLines(data) {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch {
			case urlSectionRe.MatchString(line):
				section = "url"
			case credentialSectionRe.MatchString(line):
				section = "credential"
				sectionURL = credentialSectionRe.FindStringSubmatch(line)[1]
			case httpSectionRe.MatchString(line):
				section = "http"
				sectionURL = httpSectionRe.FindStringSubmatch(line)[1]
			default:
				section = ""
			}
			continue
		}
		if section == "" {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		switch {
		case section == "url" && key == "insteadof":
			if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
				slots = append(slots, &prefixSlot{value: p, active: true})
			}
		case section == "credential" && key == "helper":
			setSignalSlot(&slots, credSlots, sectionURL, value)
		case section == "http" && key == "extraheader":
			setSignalSlot(&slots, httpSlots, sectionURL, value)
		}
	}

	var prefixes []string
	for _, s := range slots {
		if s.active {
			prefixes = append(prefixes, s.value)
		}
	}
	return prefixes
}

// privatePrefixesFromEnv scans the GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> /
// GIT_CONFIG_VALUE_<n> environment variables (git-config(1)'s documented,
// file-free way to inject config: "useful for cases where you want to spawn
// multiple git commands with a common configuration but cannot depend on a
// configuration file") for the same three private-auth signals
// privatePrefixesFromGitConfig looks for in files: url.<NEW>.insteadof,
// credential.<URL>.helper, and http.<URL>.extraheader. Verified live that
// these variables aren't cosmetic: a real `git ls-remote`/`git fetch`
// honors an insteadOf rewrite set this way exactly like one from a config
// file, and — since they're environment variables, not per-invocation
// flags — they apply to every git subprocess for as long as they're set,
// including the one `go get` itself spawns for a direct VCS fetch. A CI or
// script setup that deliberately avoids ever writing credentials to a file
// (this mechanism's whole documented selling point) leaves a real
// private-auth signal completely invisible to this tool otherwise, since
// privatePrefixesFromGitConfig only ever reads files.
func privatePrefixesFromEnv(getenv func(string) string) []string {
	count, err := strconv.Atoi(getenv("GIT_CONFIG_COUNT"))
	if err != nil || count <= 0 {
		// Per git-config(1): a missing or non-numeric GIT_CONFIG_COUNT is
		// the same as GIT_CONFIG_COUNT=0 (git itself treats a genuinely
		// invalid count as a fatal error rather than "0", but this tool
		// only needs to not misread absent/empty as a signal, not
		// replicate git's own error-exit behavior).
		return nil
	}
	var slots []*prefixSlot
	credSlots := map[string]*prefixSlot{}
	httpSlots := map[string]*prefixSlot{}
	for i := 0; i < count; i++ {
		key := getenv(fmt.Sprintf("GIT_CONFIG_KEY_%d", i))
		value := getenv(fmt.Sprintf("GIT_CONFIG_VALUE_%d", i))
		section, subsection, name, ok := splitConfigKey(key)
		if !ok {
			continue
		}
		section = strings.ToLower(section)
		name = strings.ToLower(name)
		switch {
		case section == "url" && name == "insteadof":
			if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
				slots = append(slots, &prefixSlot{value: p, active: true})
			}
		case section == "credential" && name == "helper":
			// Same real-git reset-on-empty list semantics as the config-file
			// form (see privatePrefixesFromGitConfig's doc comment) — verified
			// live that GIT_CONFIG_COUNT/KEY/VALUE entries are processed with
			// the identical sequential reset-or-append behavior: a
			// credential.<url>.helper set via index 0 and then reset to "" via
			// index 1 leaves `git credential fill` invoking no helper at all,
			// the same as the equivalent two-line config-file form.
			setSignalSlot(&slots, credSlots, subsection, value)
		case section == "http" && name == "extraheader":
			setSignalSlot(&slots, httpSlots, subsection, value)
		}
	}
	var prefixes []string
	for _, s := range slots {
		if s.active {
			prefixes = append(prefixes, s.value)
		}
	}
	return prefixes
}

// splitConfigKey splits a git config key in the flat "section.subsection.name"
// form used by GIT_CONFIG_KEY_<n> into its three parts, per git-config(1):
// the section name is the text up to the first ".", the variable name is the
// text after the last ".", and whatever's between — which may itself contain
// dots, since it's typically a URL — is the subsection. Returns ok=false for
// a key with no subsection (fewer than two dots total), which can't match
// any of the three URL-scoped signals privatePrefixesFromEnv looks for.
func splitConfigKey(key string) (section, subsection, name string, ok bool) {
	i := strings.Index(key, ".")
	if i < 0 {
		return "", "", "", false
	}
	rest := key[i+1:]
	j := strings.LastIndex(rest, ".")
	if j < 0 {
		return "", "", "", false
	}
	return key[:i], rest[:j], rest[j+1:], true
}

// schemeOf extracts the transport scheme git would use for a remote URL
// (the "new" side of a `[url "<new>"] insteadOf = <old>` rewrite), covering
// every form git-config(1)/gitremote-helpers(7) document: an explicit
// "<scheme>://" prefix; the "ext::<command>" form (git treats "ext" as its
// own scheme despite the missing "//" — see protocol.allow's docs); the
// "user@host:path" SCP-like shorthand, which git resolves to the ssh
// transport with no explicit scheme at all and is the *exact* form go.dev's
// own FAQ recommends for insteadOf (`[url "git@github.com:"] insteadOf =
// https://github.com/`, already this file's primary documented example);
// and a bare filesystem path (absolute or relative, no "@"/"://" at all),
// which git treats as the "file" transport. Returns "" when the form can't
// be determined with confidence, so callers fail open (treat the transport
// as allowed, i.e. don't suppress a signal) rather than risk misreading a
// real one as protocol-blocked.
func schemeOf(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if strings.HasPrefix(url, "ext::") {
		return "ext"
	}
	if i := strings.Index(url, "://"); i > 0 {
		scheme := strings.ToLower(url[:i])
		for j := 0; j < len(scheme); j++ {
			c := scheme[j]
			isAlpha := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			switch {
			case j == 0 && !isAlpha:
				return ""
			case j > 0 && !isAlpha && !isDigit && c != '+' && c != '-' && c != '.':
				return ""
			}
		}
		return scheme
	}
	// SCP-like shorthand: [user@]host.xz:path/to/repo (git-clone(1)). Only
	// recognized with a leading "user@" host, matching how git itself
	// disambiguates this from a Windows-style absolute path ("C:\...") or a
	// bare relative path containing a colon.
	if at := strings.Index(url, "@"); at >= 0 {
		rest := url[at+1:]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			if slash := strings.Index(rest, "/"); slash < 0 || colon < slash {
				return "ssh"
			}
		}
	}
	return "file"
}

// insteadOfSchemes scans a gitconfig file's contents for `[url "<new>"]
// insteadOf = <old>` entries the same way privatePrefixesFromGitConfig
// does, but returns a map from the normalized module-path prefix (the
// "old" side, same as privatePrefixesFromGitConfig's return value) to the
// transport scheme(s) of the "new" side — the piece
// privatePrefixesFromGitConfig itself discards, needed to check the
// rewrite against protocol.allow/GIT_ALLOW_PROTOCOL (see
// gitProtocolAllowed). A prefix rewritten by more than one insteadOf rule
// (an unusual but possible config) collects every scheme seen.
func insteadOfSchemes(data []byte) map[string][]string {
	out := map[string][]string{}
	inURL := false
	sectionURL := ""
	for _, raw := range splitLogicalLines(data) {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if urlSectionRe.MatchString(line) {
				inURL = true
				sectionURL = urlSectionRe.FindStringSubmatch(line)[1]
			} else {
				inURL = false
			}
			continue
		}
		if !inURL {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok || key != "insteadof" {
			continue
		}
		if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
			out[p] = append(out[p], schemeOf(sectionURL))
		}
	}
	return out
}

// insteadOfSchemesFromEnv is insteadOfSchemes' counterpart for the
// GIT_CONFIG_COUNT/GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> env-var config
// mechanism privatePrefixesFromEnv already reads the plain insteadOf
// signal from — see its doc comment for why env-set config is a real,
// live-verified signal source, not just a file-parsing nicety.
func insteadOfSchemesFromEnv(getenv func(string) string) map[string][]string {
	count, err := strconv.Atoi(getenv("GIT_CONFIG_COUNT"))
	if err != nil || count <= 0 {
		return nil
	}
	out := map[string][]string{}
	for i := 0; i < count; i++ {
		key := getenv(fmt.Sprintf("GIT_CONFIG_KEY_%d", i))
		value := getenv(fmt.Sprintf("GIT_CONFIG_VALUE_%d", i))
		section, subsection, name, ok := splitConfigKey(key)
		if !ok {
			continue
		}
		section = strings.ToLower(section)
		name = strings.ToLower(name)
		if section == "url" && name == "insteadof" {
			if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
				out[p] = append(out[p], schemeOf(subsection))
			}
		}
	}
	return out
}

// protocolAllowFromGitConfig scans a gitconfig file's contents for
// `[protocol]`/`[protocol "<name>"]` sections' "allow" key — git-config(1)'s
// protocol.allow / protocol.<name>.allow, the config-file counterpart to
// GIT_ALLOW_PROTOCOL (see gitProtocolAllowed). The bare `[protocol]` form
// (no subsection) is returned under the "" key, representing the default
// policy for any protocol without its own protocol.<name>.allow entry.
func protocolAllowFromGitConfig(data []byte) map[string]string {
	out := map[string]string{}
	inProtocol := false
	protoName := ""
	for _, raw := range splitLogicalLines(data) {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if m := protocolSectionRe.FindStringSubmatch(line); m != nil {
				inProtocol = true
				protoName = strings.ToLower(m[1])
			} else {
				inProtocol = false
			}
			continue
		}
		if !inProtocol {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok || key != "allow" {
			continue
		}
		out[protoName] = value
	}
	return out
}

// gitProtocolAllowed reports whether git would permit fetching over the
// given transport scheme, applying the exact precedence git(1)/
// git-config(1) document: GIT_ALLOW_PROTOCOL, if set, is fully
// authoritative — "behave as if protocol.allow is set to never, and each
// of the listed protocols has protocol.<name>.allow set to always
// (overriding any existing configuration)". Verified live (2026-09): with
// GIT_ALLOW_PROTOCOL=https set, `git ls-remote` against an ssh://
// insteadOf target — go.dev's own documented private-auth pattern — fails
// outright with "fatal: transport 'ssh' not allowed", even though ssh's
// own built-in default policy is "always" and no protocol.ssh.allow entry
// exists anywhere. Absent GIT_ALLOW_PROTOCOL, protocol.<scheme>.allow
// (most specific) then the bare protocol.allow default (least specific)
// from the resolved git config apply; absent either, git's own built-in
// policy table applies — confirmed live: "ext" defaults to "never",
// http/https/git/ssh default to "always". Everything else (including
// "file") defaults to "user", which is treated as allowed here since this
// tool only ever reasons about a direct, top-level `go get`/`go build`
// invocation, not the recursive/untrusted-URL context
// (GIT_PROTOCOL_FROM_USER=0) where "user" would actually mean "never".
// scheme=="" (schemeOf couldn't determine the transport with confidence)
// always returns true — fail open, never suppress a real signal on a
// guess.
func gitProtocolAllowed(scheme string, fileAllow map[string]string, getenv func(string) string) bool {
	if scheme == "" {
		return true
	}
	if raw := getenv("GIT_ALLOW_PROTOCOL"); raw != "" {
		for _, p := range strings.Split(raw, ":") {
			if strings.EqualFold(strings.TrimSpace(p), scheme) {
				return true
			}
		}
		return false
	}
	if policy, ok := fileAllow[scheme]; ok {
		return policyAllows(policy)
	}
	if policy, ok := fileAllow[""]; ok {
		return policyAllows(policy)
	}
	return scheme != "ext"
}

func policyAllows(policy string) bool {
	return !strings.EqualFold(strings.TrimSpace(policy), "never")
}

// includeDirective is a raw [include]/[includeIf "..."] path entry found
// while scanning a git config file. cond is empty for an unconditional
// [include]; for [includeIf "kind:pattern"] it holds the "kind:pattern"
// text verbatim.
type includeDirective struct {
	cond string
	path string
}

// parseIncludes scans a gitconfig file's contents for [include] and
// [includeIf "..."] sections and returns their "path" values, in the order
// git itself applies them (top to bottom, interleaved with any [url]
// sections — see privatePrefixesFromConfigFile).
func parseIncludes(data []byte) []includeDirective {
	var out []includeDirective
	section := "" // "" | "include" | "includeif"
	cond := ""
	for _, raw := range splitLogicalLines(data) {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch {
			case includeSectionRe.MatchString(line):
				section, cond = "include", ""
			case includeIfSectionRe.MatchString(line):
				m := includeIfSectionRe.FindStringSubmatch(line)
				section, cond = "includeif", m[1]
			default:
				section = ""
			}
			continue
		}
		if section == "" {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok || key != "path" {
			continue
		}
		out = append(out, includeDirective{cond: cond, path: value})
	}
	return out
}

// resolveIncludePath turns an [include]/[includeIf] "path" value into an
// absolute filesystem path, per git-config(1)'s rules: a leading "~/" is
// the user's home directory, an already-absolute path is used as-is, and
// anything else is relative to the directory containing the config file
// that referenced it.
func resolveIncludePath(value, configFileDir string) string {
	// value arrives already unquoted/unescaped — every caller passes an
	// includeDirective.path sourced from splitKV, which now resolves git's
	// value quoting itself (see unquoteConfigValue). This used to do its
	// own blunt strings.Trim(value, `"`) here, the only quote-handling
	// this file had before unquoteConfigValue existed — redundant now, and
	// actively wrong for the rare case of a real path whose unescaped form
	// itself starts or ends with a literal '"' (Trim would incorrectly eat
	// it a second time).
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, value[2:])
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(configFileDir, value)
}

// resolveGitDir resolves moduleDir's real $GIT_DIR and the "common dir"
// tier that actually owns the shared config file — the same distinction
// git itself makes (gitrepository-layout(5), "Multiple working trees").
//
// For an ordinary repository, moduleDir/.git is a directory and IS its own
// common dir: gitDir == commonDir == moduleDir/.git, matching every
// assumption this file made before this fix.
//
// For a linked worktree (`git worktree add`), moduleDir/.git is instead a
// *file* containing a "gitdir: <path>" line naming the worktree's own,
// separate $GIT_DIR (e.g. "<main-repo>/.git/worktrees/<name>" — verified
// live via `git rev-parse --absolute-git-dir` inside a real linked
// worktree). That directory in turn contains a "commondir" file naming the
// shared common dir (almost always "<main-repo>/.git" itself) that git
// actually reads "config" from — worktrees share one repo-level config by
// default. Treating moduleDir/.git as a plain directory in this case (the
// pre-fix assumption) meant `gitConfigCandidates` looked for a
// "config" file that doesn't exist under a nonexistent moduleDir/.git/
// directory at all, silently finding none of the local insteadOf/
// credential-helper/extraHeader signals `git`/`go` actually apply when run
// from that worktree — a real false negative confirmed live: an insteadOf
// rewrite set in the main checkout's local config was correctly flagged as
// a sumdb leak when audited from the main checkout, but silently missed
// ("no issues found") when the exact same module was audited from a
// linked worktree of that same repository, even though `go get` run from
// that worktree uses the identical shared config and leaks the identical
// module path to the checksum database.
//
// A submodule's .git is also a file with a "gitdir:" line (naming a
// directory relocated under the superproject's .git/modules/<name>), but
// that directory has no "commondir" file — it IS its own common dir,
// unlike a linked worktree's. Verified live for both shapes; the algorithm
// below handles both with the same commondir-file check, defaulting
// commonDir to gitDir itself when no commondir file is present.
func resolveGitDir(moduleDir string) (gitDir, commonDir string, ok bool) {
	p := filepath.Join(moduleDir, ".git")
	info, err := os.Stat(p)
	if err != nil {
		return "", "", false
	}
	if info.IsDir() {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", "", false
		}
		return abs, abs, true
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", "", false
	}
	rest, found := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
	if !found {
		return "", "", false
	}
	rest = strings.TrimSpace(rest)
	if !filepath.IsAbs(rest) {
		rest = filepath.Join(moduleDir, rest)
	}
	gitDir, err = filepath.Abs(rest)
	if err != nil {
		return "", "", false
	}
	commonDir = gitDir
	if cd, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		cdPath := strings.TrimSpace(string(cd))
		if !filepath.IsAbs(cdPath) {
			cdPath = filepath.Join(gitDir, cdPath)
		}
		if abs, err := filepath.Abs(cdPath); err == nil {
			commonDir = abs
		}
	}
	return gitDir, commonDir, true
}

// includeIfMatches reports whether an [includeIf "cond"] condition applies
// when git is run inside moduleDir. "gitdir:"/"gitdir/i:" and
// "onbranch:"/"onbranch/i:" are supported; "hasconfig:" and other forms are
// treated as non-matching rather than guessed at (per git-config(1),
// resolving "hasconfig:remote.*.url:" requires scanning ahead through every
// other config file the audit would otherwise read independently, a
// structurally different, chicken-and-egg-avoiding two-pass algorithm git
// itself implements specially — not a case this tool's single-pass reader
// can approximate safely).
//
// Per git-config(1), a "gitdir:" pattern is matched against the absolute
// path of the repository's *.git directory* ($GIT_DIR), not the working
// tree — matching against moduleDir itself (the pre-fix behavior) happened
// to still work for the common hand-written, wildcard-terminated pattern
// style (e.g. "gitdir:~/work/", which expands to a "**" suffix that
// absorbs a trailing "/.git" difference regardless), but silently never
// matched a pattern that names the .git directory explicitly with no
// trailing wildcard — exactly the literal, non-wildcard
// "gitdir:<absolute-workdir-path>/.git" form `actions/checkout` (the
// default way almost every GitHub Actions Go workflow checks out code)
// generates for its own includeIf entries (verified against its real
// source, git-auth-helper.ts: `gitDir = path.join(workingDirectory,
// '.git')`). A false negative on that exact real, currently-shipping
// config was confirmed live before this fix (see
// TestIncludeIfMatchesActionsCheckoutGitdirPattern). target intentionally
// has no trailing "/" appended (an earlier version of this fix added
// one, matching the old moduleDir-only behavior): a "**"-terminated
// pattern matches with or without it (globMatchSegs returns true the
// moment it reaches a trailing "**" segment, before even looking at what
// remains of target), but an exact non-wildcard pattern — like
// actions/checkout's — needs the segment counts to line up exactly, and
// a stray trailing "/" adds a spurious empty final segment that never
// matches.
func includeIfMatches(cond, moduleDir string) bool {
	kind, pattern, ok := strings.Cut(cond, ":")
	if !ok {
		return false
	}
	switch kind {
	case "gitdir", "gitdir/i":
		return includeIfMatchesGitdir(kind == "gitdir/i", pattern, moduleDir)
	case "onbranch", "onbranch/i":
		return includeIfMatchesOnbranch(kind == "onbranch/i", pattern, moduleDir)
	default:
		return false
	}
}

func includeIfMatchesGitdir(caseInsensitive bool, pattern, moduleDir string) bool {
	gitDir, _, ok2 := resolveGitDir(moduleDir)
	if !ok2 {
		// No resolvable .git at all (e.g. moduleDir isn't a repo yet, or a
		// permission error mid-audit) — fall back to the old plain-directory
		// assumption rather than failing the match outright.
		abs, err := filepath.Abs(moduleDir)
		if err != nil {
			return false
		}
		gitDir = filepath.Join(abs, ".git")
	}
	target := filepath.ToSlash(gitDir)
	pattern = expandGitdirPattern(pattern)
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		target = strings.ToLower(target)
	}
	return matchGitdirGlob(pattern, target)
}

// includeIfMatchesOnbranch implements the "onbranch:"/"onbranch/i:"
// condition: per git-config(1), it matches the name of the branch currently
// checked out in the worktree rooted at moduleDir — unlike gitdir, there's
// no "~/"/"./"-prefix handling and no implicit "**/" prepend for a bare
// pattern. Verified live: a real `git` repo with an
// `[includeIf "onbranch:feature/*"]` entry applies the included file's
// config (a credential.helper, in the reproduction) only while
// "feature/x" is checked out, not on "main" — confirmed by reading
// `git config --get-all` before and after a real `git checkout -b`.
//
// A trailing "/" is a second, subtler asymmetry with gitdir, also verified
// live rather than assumed from the doc wording alone: gitdir's docs say a
// trailing-slash pattern "matches foo and everything inside, recursively"
// (confirmed live — "gitdir:/x/work/" matches the bare directory
// "/x/work" itself, not just things under it), but onbranch's docs instead
// say it "matches all branches that begin with foo/" — no mention of
// matching the bare name. A real `[includeIf "onbranch:feature/"]` entry,
// confirmed live, does NOT apply while a branch literally named "feature"
// (no further path segment) is checked out, only while something like
// "feature/x" is. So unlike expandGitdirPattern's equivalent "append **"
// step, the appended "**" here must consume at least one branch path
// segment, not zero-or-more.
func includeIfMatchesOnbranch(caseInsensitive bool, pattern, moduleDir string) bool {
	gitDir, _, ok := resolveGitDir(moduleDir)
	if !ok {
		return false
	}
	branch, ok := currentBranch(gitDir)
	if !ok {
		// Detached HEAD: per git-config(1) ("if we are in a worktree where
		// the name of the branch that is currently checked out matches"),
		// there is no checked-out branch name for any pattern to match.
		return false
	}
	requireSubBranch := strings.HasSuffix(pattern, "/")
	if requireSubBranch {
		pattern += "**"
	}
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		branch = strings.ToLower(branch)
	}
	pSegs := strings.Split(pattern, "/")
	bSegs := strings.Split(branch, "/")
	if !globMatchSegs(pSegs, bSegs) {
		return false
	}
	if requireSubBranch && len(bSegs) == len(pSegs)-1 {
		// The appended "**" (dropped here via len(pSegs)-1) matched zero
		// segments — exactly the bare-prefix case just above confirms
		// onbranch must reject, unlike gitdir.
		return false
	}
	return true
}

// currentBranch reads gitDir/HEAD directly (no `git` subprocess required,
// consistent with the rest of this file's config-file-only resolution) and
// returns the checked-out branch name, or ok=false if HEAD is detached (a
// raw commit SHA, not a "ref: refs/heads/..." symbolic ref) or unreadable.
func currentBranch(gitDir string) (branch string, ok bool) {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", false
	}
	rest, found := strings.CutPrefix(strings.TrimSpace(string(data)), "ref:")
	if !found {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	name, found := strings.CutPrefix(rest, "refs/heads/")
	if !found {
		return "", false
	}
	return name, true
}

// expandGitdirPattern applies git's documented normalization for gitdir
// patterns (see git-config(1), "Conditional includes"): "~/" becomes the
// home directory, a pattern with no leading "~/", "/", or "./" is treated
// as matching anywhere in the tree (prefixed with "**/"), and a
// trailing "/" gets an implicit "**" so a bare directory prefix still
// matches everything under it.
func expandGitdirPattern(p string) string {
	switch {
	case strings.HasPrefix(p, "~/"):
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.ToSlash(home) + "/" + p[2:]
		}
	case !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "./"):
		p = "**/" + p
	}
	if strings.HasSuffix(p, "/") {
		p += "**"
	}
	return p
}

// matchGitdirGlob matches a "/"-separated pattern (which may contain "**"
// segments matching zero or more path segments, the same as git's gitdir
// glob) against a "/"-separated target path.
func matchGitdirGlob(pattern, target string) bool {
	return globMatchSegs(strings.Split(pattern, "/"), strings.Split(target, "/"))
}

func globMatchSegs(pSegs, tSegs []string) bool {
	for len(pSegs) > 0 {
		if pSegs[0] == "**" {
			if len(pSegs) == 1 {
				return true
			}
			for i := 0; i <= len(tSegs); i++ {
				if globMatchSegs(pSegs[1:], tSegs[i:]) {
					return true
				}
			}
			return false
		}
		if len(tSegs) == 0 {
			return false
		}
		if ok, err := path.Match(pSegs[0], tSegs[0]); err != nil || !ok {
			return false
		}
		pSegs, tSegs = pSegs[1:], tSegs[1:]
	}
	return len(tSegs) == 0
}

// privatePrefixesFromConfigFile reads the git config file at path and
// returns its insteadOf-derived private prefixes, following any
// [include]/[includeIf "gitdir:..."] directives it contains the way git
// itself would when run inside moduleDir. visited guards against include
// cycles and is shared across the whole call tree (including across the
// separate ~/.gitconfig and <module>/.git/config roots) so a file is only
// ever read once.
func privatePrefixesFromConfigFile(configPath, moduleDir string, visited map[string]bool) []string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil
	}
	if visited[abs] {
		return nil
	}
	visited[abs] = true

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	prefixes := privatePrefixesFromGitConfig(data)
	dir := filepath.Dir(configPath)
	for _, inc := range parseIncludes(data) {
		if inc.cond != "" && !includeIfMatches(inc.cond, moduleDir) {
			continue
		}
		if p := resolveIncludePath(inc.path, dir); p != "" {
			prefixes = append(prefixes, privatePrefixesFromConfigFile(p, moduleDir, visited)...)
		}
	}
	return prefixes
}

// insteadOfSchemesFromConfigFile is insteadOfSchemes' counterpart to
// privatePrefixesFromConfigFile: same file-read and [include]/[includeIf]
// following (sharing a visited set with its own call tree, separate from
// privatePrefixesFromConfigFile's, since this is an independent scan of
// the same files for different information — see blockedInsteadOfPrefixCounts).
func insteadOfSchemesFromConfigFile(configPath, moduleDir string, visited map[string]bool) map[string][]string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil
	}
	if visited[abs] {
		return nil
	}
	visited[abs] = true

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	out := insteadOfSchemes(data)
	dir := filepath.Dir(configPath)
	for _, inc := range parseIncludes(data) {
		if inc.cond != "" && !includeIfMatches(inc.cond, moduleDir) {
			continue
		}
		if p := resolveIncludePath(inc.path, dir); p != "" {
			for k, v := range insteadOfSchemesFromConfigFile(p, moduleDir, visited) {
				out[k] = append(out[k], v...)
			}
		}
	}
	return out
}

// protocolAllowFromConfigFile is protocolAllowFromGitConfig's counterpart
// to privatePrefixesFromConfigFile: same file-read and include-following,
// but for single-valued protocol.allow/protocol.<name>.allow keys instead
// of the multi-valued insteadOf signal, so included files' values are
// merged with (and, on conflict, overridden by) this file's own — the
// file that directly names an included one is treated as the more
// specific/authoritative source, the same precedence direction git-config
// itself uses for a value set both before and after an [include] line
// textually (this tool doesn't track that finer textual ordering, so this
// is an approximation, not an exact reimplementation — see
// gitProtocolAllowed's doc comment for why erring toward "not blocked" on
// an ambiguous read is the safe direction anyway).
func protocolAllowFromConfigFile(configPath, moduleDir string, visited map[string]bool) map[string]string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil
	}
	if visited[abs] {
		return nil
	}
	visited[abs] = true

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	out := map[string]string{}
	dir := filepath.Dir(configPath)
	for _, inc := range parseIncludes(data) {
		if inc.cond != "" && !includeIfMatches(inc.cond, moduleDir) {
			continue
		}
		if p := resolveIncludePath(inc.path, dir); p != "" {
			for k, v := range protocolAllowFromConfigFile(p, moduleDir, visited) {
				out[k] = v
			}
		}
	}
	for k, v := range protocolAllowFromGitConfig(data) {
		out[k] = v // this file's own settings take precedence over its includes'
	}
	return out
}

// stripLineComment removes a trailing comment from a raw git config file
// line, mirroring config.c's parse_value/git_parse_source char-by-char
// scan (verified against real git behavior, see gitconfig_test.go): an
// unquoted '#' or ';' starts a comment running to end of line, with no
// whitespace required before it — "insteadOf = https://x/#note" and
// "insteadOf = https://x/;note" both lose everything from the mark
// onward, same as "[url \"x\"] ; note" loses the trailing note but keeps
// the section header intact. A '#'/';' inside a double-quoted value is
// literal, not a comment start, and a backslash escapes the following
// character so an escaped quote doesn't toggle quote state. Without this,
// the very common hand-edited-dotfile pattern of annotating an insteadOf
// rewrite or a section header with an inline comment either garbles the
// parsed prefix or (for a commented section header, since the section
// regexes require the line to end right after "]") makes the whole
// section invisible — a silent false negative on a real private-module
// signal, the failure mode this tool exists to avoid.
// splitLogicalLines splits a git config file's raw contents into logical
// lines, resolving git's own line-continuation rule (config.c's char-by-char
// source reader, verified against real git behavior): a lone unescaped
// backslash immediately followed by a newline joins that physical line with
// the next one, with the backslash and newline both removed and nothing
// inserted in their place — so `insteadOf = https://git\` followed by
// `hub.com/myorg/` on the next physical line is one logical value,
// `https://github.com/myorg/`, not the two-line garbage a naive per-line
// scanner would produce. Continuation is NOT honored once a line has
// entered an unquoted, unescaped '#'/';' comment tail (confirmed live: a
// trailing backslash inside a comment ends the physical line normally and
// git raises a syntax error on whatever the next line contains standing
// alone) — mirrored here by freezing "in comment" state until the next
// newline and skipping continuation checks while it's set. Without this, a
// hand-wrapped insteadOf/path value spanning two lines (a real, git-
// accepted way to keep a long URL readable in a dotfile) silently produces
// a garbled, useless prefix on the first physical line and drops the real
// private-module signal entirely — a false negative, the same failure
// class as the case-sensitivity and bare "."/".." gaps fixed earlier.
// Handles both bare-LF and CRLF line endings (confirmed live: a backslash
// immediately before "\r\n" continues the line exactly like one before a
// bare "\n" does) — CRLF gitconfigs are common on Windows.
func splitLogicalLines(data []byte) []string {
	var lines []string
	var cur strings.Builder
	inQuotes := false
	inComment := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '\n':
			lines = append(lines, strings.TrimSuffix(cur.String(), "\r"))
			cur.Reset()
			inQuotes = false
			inComment = false
		case inComment:
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(data) && data[i+1] == '\n':
			i++ // continuation: drop the backslash and the newline
		case c == '\\' && i+2 < len(data) && data[i+1] == '\r' && data[i+2] == '\n':
			i += 2 // continuation on a CRLF line: drop backslash, CR, and LF
		case c == '\\' && i+1 < len(data):
			cur.WriteByte(c)
			cur.WriteByte(data[i+1])
			i++
		case c == '"':
			inQuotes = !inQuotes
			cur.WriteByte(c)
		case !inQuotes && (c == '#' || c == ';'):
			inComment = true
			cur.WriteByte(c)
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		lines = append(lines, strings.TrimSuffix(cur.String(), "\r"))
	}
	return lines
}

func stripLineComment(line string) string {
	inQuotes := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line):
			i++
		case c == '"':
			inQuotes = !inQuotes
		case !inQuotes && (c == '#' || c == ';'):
			return line[:i]
		}
	}
	return line
}

func splitKV(line string) (key, value string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:i]))
	value = unquoteConfigValue(strings.TrimSpace(line[i+1:]))
	return key, value, true
}

// unquoteConfigValue resolves a git config value's quoting/escaping, per
// git-config(1) ("Syntax"): a value may be entirely or partially wrapped in
// double quotes, an unescaped '"' toggles the quoted region on/off with the
// quote character itself dropped from the result either way, and a
// backslash escapes the character following it — '\"' and '\\' produce a
// literal '"'/'\\', '\n'/'\t'/'\b' produce newline/tab/backspace, and any
// other escaped character (real git treats this as a syntax error and
// refuses to read the file at all — this tool fails open instead, keeping
// the literal unescaped character, matching its existing convention
// elsewhere of not replicating git's own hard-error behavior) is kept as
// its literal, unescaped self. Verified live against real `git config
// --file`: `ab"cd ef"gh` (bare quote-toggling, no escapes) reads back as
// `abcd efgh`, and `"a\"b\\c"` reads back as `a"b\c`.
//
// Before this function existed, splitKV returned every value completely
// raw, quote characters and backslash escapes both intact — resolveIncludePath
// was the only caller that ever stripped anything (a blunt
// strings.Trim(value, `"`), which only handles a value quoted start-to-end
// with no internal escapes). Every other splitKV consumer — insteadOf,
// credential.helper, http.extraHeader, protocol.allow — read the value
// completely unprocessed. That's not just a cosmetic gap: confirmed live
// against a real, widely-forked public dotfiles repo
// (github.com/mathiasbynens/dotfiles, whose .gitconfig writes
// `insteadOf = "gh:"` purely as a stylistic quoting habit, not because the
// value needs escaping) that real git strips the quotes and applies the
// rewrite regardless of whether the quoted content contains anything that
// actually required quoting. Reproduced the exploitable shape directly:
// `[url "git@github.com:myorg/"] insteadOf = "https://github.com/myorg/"`
// — GIT_TRACE confirms a real `git ls-remote`/`go get` against
// https://github.com/myorg/foo genuinely rewrites to the ssh transport
// (a "Host key verification failed" error proves the ssh subprocess really
// launched, not a parse no-op) — while pre-fix goprivaudit reported "no
// issues found" for the identical private-auth signal an unquoted
// `insteadOf = https://github.com/myorg/` line already correctly flagged
// as SUMDB LEAK. A prior pass (run #154) considered quote-handling here
// and concluded a '"' character was structurally unreachable in this
// file's own values because a bare git remote URL can never legally
// contain one — true for the raw URL bytes, but it conflated that with
// whether the *config line* can be written wrapped in quotes, which git
// allows unconditionally regardless of the wrapped content. As a side
// effect, this also fixes setSignalSlot's reset-on-empty detection for a
// value written as an explicit quoted empty string (`helper = ""`, a valid
// alternate spelling of `helper =` per the same quoting rules) — pre-fix,
// `value == ""` compared against the two-character literal `""` and never
// matched, so a real credential.helper/http.extraHeader reset written this
// way was silently ignored.
func unquoteConfigValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			default:
				b.WriteByte(s[i])
			}
		case c == '"':
			// Drop the quote character; a quoted region contributes its
			// characters identically to an unquoted one once escapes are
			// resolved, so no separate "in quotes" state is needed here
			// (unlike stripLineComment/splitLogicalLines, which track it
			// for comment/continuation detection on the surrounding line,
			// not for value extraction).
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// normalizeToModulePrefix converts a git remote URL form (https://,
// ssh://, or the git@host:path shorthand) into a bare "host/path" prefix
// comparable against go.mod module paths.
func normalizeToModulePrefix(url string) string {
	url = strings.TrimSpace(url)
	for _, scheme := range []string{"https://", "http://", "ssh://", "git://"} {
		if strings.HasPrefix(url, scheme) {
			url = strings.TrimPrefix(url, scheme)
			if i := strings.Index(url, "@"); i >= 0 {
				url = url[i+1:] // drop ssh://user@ auth prefix
			}
			return finishPrefix(stripHostPort(url))
		}
	}
	// git@host:path shorthand
	if i := strings.Index(url, "@"); i >= 0 {
		rest := url[i+1:]
		if j := strings.Index(rest, ":"); j >= 0 {
			rest = rest[:j] + "/" + rest[j+1:]
		}
		return finishPrefix(rest)
	}
	return ""
}

// stripHostPort removes a ":<port>" suffix from the host segment (the part
// before the first "/") of a "host[:port][/path]" string, mirroring how a
// real module path is written: golang.org/x/mod/module.CheckPath rejects
// ':' anywhere in a module path, so no go.mod ever declares one with a
// port, regardless of what port the real server behind it needs.
//
// This matters most for setSignalSlot's [credential "..."]/[http "..."]
// section URLs, which name the exact URL git will actually fetch — and
// that real URL legitimately carries a port whenever the module is only
// reachable that way: a self-hosted GHES/GitLab instance fronted by a
// non-default HTTPS port is a real, common enterprise setup, and
// `actions/checkout` (see this function's own doc comment above) writes
// its extraHeader scoped to exactly `github.server_url`, port included
// when the runner's server_url has one. Verified live with real git: a
// `[credential "https://git.internal.corp:8443"] helper = ...` entry only
// answers `git credential fill` for `host=git.internal.corp:8443` — the
// identical query with the port dropped fails outright ("could not read
// Username") — so this credential authenticates a real fetch to that
// exact host:port, while the go.mod module path for it is inevitably the
// port-less "git.internal.corp/org/repo". Before this fix,
// normalizeToModulePrefix left the port embedded (returning
// "git.internal.corp:8443"), a prefix no real module path can ever
// contain a colon to match — silently blinding this tool to exactly the
// self-hosted-behind-a-custom-port setups its credential/extraHeader
// checks exist to catch. (The analogous insteadOf case is already safe
// without this fix: `[url "ssh://host:2222/"] insteadOf = <old-url>`
// derives the prefix from the port-less <old-url> side, never the
// rewritten one — but stripHostPort is a no-op there too, so applying it
// uniformly costs nothing and closes the gap if some future call site
// ever normalizes the rewritten side instead.) A "[" prefix (a bracketed
// IPv6 literal, e.g. "[::1]:2222") is left untouched: not a valid module
// path host either way, and rare enough here that guessing at bracket
// stripping isn't worth the risk of mishandling it.
func stripHostPort(hostAndPath string) string {
	host, rest := hostAndPath, ""
	if i := strings.Index(hostAndPath, "/"); i >= 0 {
		host, rest = hostAndPath[:i], hostAndPath[i:]
	}
	if strings.HasPrefix(host, "[") {
		return hostAndPath
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			host = host[:i]
		}
	}
	return host + rest
}

func finishPrefix(s string) string {
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	if s == "" {
		return ""
	}
	return s
}

// knownPublicGitHosts are multi-tenant code hosts where a bare-host
// insteadOf rewrite (no org/path segment) is Go's own documented pattern
// for blanket SSH auth convenience, not a signal that the whole host is
// private. See the go.dev FAQ ("Why does 'go get' use HTTPS..."), whose
// exact recommended snippet is `[url "ssh://git@github.com/"] insteadOf =
// https://github.com/` — rewriting *all* of github.com, not a private
// org. Treating that as "this module has a private-auth signal" makes
// every public dependency on the host look like a sumdb leak. A bare-host
// rewrite for anything not in this list (e.g. a private GitHub
// Enterprise instance) still counts as private, since there's no public
// multi-tenant use of that host to confuse it with.
var knownPublicGitHosts = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
	"sr.ht":         true,
	"git.sr.ht":     true,
	"gitee.com":     true,
	"codeberg.org":  true,
}

func isKnownPublicHost(prefix string) bool {
	return !strings.Contains(prefix, "/") && knownPublicGitHosts[prefix]
}
