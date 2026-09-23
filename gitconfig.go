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
func privatePrefixesFromGitConfig(data []byte) []string {
	var prefixes []string
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
				prefixes = append(prefixes, p)
			}
		case section == "credential" && key == "helper" && value != "":
			if p := normalizeToModulePrefix(sectionURL); p != "" && !isKnownPublicHost(p) {
				prefixes = append(prefixes, p)
			}
		case section == "http" && key == "extraheader" && value != "":
			if p := normalizeToModulePrefix(sectionURL); p != "" && !isKnownPublicHost(p) {
				prefixes = append(prefixes, p)
			}
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
	var prefixes []string
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
				prefixes = append(prefixes, p)
			}
		case section == "credential" && name == "helper" && value != "":
			if p := normalizeToModulePrefix(subsection); p != "" && !isKnownPublicHost(p) {
				prefixes = append(prefixes, p)
			}
		case section == "http" && name == "extraheader" && value != "":
			if p := normalizeToModulePrefix(subsection); p != "" && !isKnownPublicHost(p) {
				prefixes = append(prefixes, p)
			}
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
	value = strings.Trim(value, `"`)
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

// includeIfMatches reports whether an [includeIf "cond"] condition applies
// when git is run inside moduleDir. Only the "gitdir:"/"gitdir/i:" forms are
// supported (by far the most common use of includeIf — scoping a different
// identity/rewrite to everything under a directory tree, e.g. a work vs.
// personal SSH setup); "onbranch:"/"hasconfig:" and other forms are treated
// as non-matching rather than guessed at.
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
	caseInsensitive := kind == "gitdir/i"
	if kind != "gitdir" && !caseInsensitive {
		return false
	}

	target, err := filepath.Abs(moduleDir)
	if err != nil {
		return false
	}
	target = filepath.ToSlash(filepath.Join(target, ".git"))
	pattern = expandGitdirPattern(pattern)
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		target = strings.ToLower(target)
	}
	return matchGitdirGlob(pattern, target)
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
	value = strings.TrimSpace(line[i+1:])
	return key, value, true
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
			return finishPrefix(url)
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
