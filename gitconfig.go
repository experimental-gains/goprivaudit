package main

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var urlSectionRe = regexp.MustCompile(`(?i)^\[url\s+"([^"]*)"\]$`)
var includeSectionRe = regexp.MustCompile(`(?i)^\[include\]$`)
var includeIfSectionRe = regexp.MustCompile(`(?i)^\[includeif\s+"([^"]*)"\]$`)

// privatePrefixesFromGitConfig scans a gitconfig file's contents for
//
//	[url "git@github.com:myorg/"]
//		insteadOf = https://github.com/myorg/
//
// style rewrites, which is the standard way to make `go get`/`go mod
// download` authenticate to a private host over SSH instead of anonymous
// HTTPS. It returns the "insteadOf" (origin) side of each rewrite,
// normalized into a module-path-style prefix (scheme and trailing .git/
// stripped), since that's the form that module paths in go.mod are written
// in and the form GOPRIVATE patterns need to cover.
//
// Only "insteadOf" counts as a signal here, not "pushInsteadOf": git only
// rewrites fetch/clone URLs for the former (verified against real git
// behavior — a pushInsteadOf-only config leaves `git ls-remote`/`git
// fetch` hitting the original public HTTPS URL unchanged). `go get`'s
// module fetches are a read path, so a pushInsteadOf-only rewrite (a
// common pattern: anonymous HTTPS for reads, authenticated SSH only for
// pushes) never makes the fetch private, and treating it as a sumdb-leak
// signal would flag every ordinary public dependency under that prefix.
func privatePrefixesFromGitConfig(data []byte) []string {
	var prefixes []string
	inURLSection := false
	for _, raw := range splitLogicalLines(data) {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inURLSection = urlSectionRe.MatchString(line)
			continue
		}
		if !inURLSection {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		if key == "insteadof" {
			if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
				prefixes = append(prefixes, p)
			}
		}
	}
	return prefixes
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
	target = filepath.ToSlash(target) + "/"
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
