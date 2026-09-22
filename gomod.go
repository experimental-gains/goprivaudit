package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// parseRequires extracts module paths from require directives in a go.mod
// file's contents. It intentionally does not parse the full go.mod grammar
// (no golang.org/x/mod dependency) — it only needs module paths, not
// versions or other directives, and require blocks have a simple enough
// shape that a line scanner is sufficient.
func parseRequires(data []byte) []string {
	var modules []string
	inBlock := false
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			if m := firstField(trimmed); m != "" {
				modules = append(modules, m)
			}
			continue
		}

		if rest, ok := cutKeyword(trimmed, "require"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			if m := firstField(rest); m != "" {
				modules = append(modules, m)
			}
		}
	}
	return modules
}

// parseTools extracts package import paths from `tool` directives in a
// go.mod file's contents (Go 1.24+; see `go help tool`). A `tool` line
// names a *package* path, not necessarily a module path — e.g. `tool
// golang.org/x/tools/cmd/stringer`, whose owning module is
// `golang.org/x/tools` — and critically isn't guaranteed to be paired
// with a `require` entry: `go get -tool` always adds one, but a
// hand-written or AI-generated go.mod can have a `tool` line with no
// covering `require` at all. Before this function existed, such a line
// was invisible to parseRequires (it matches neither "require" nor
// "replace" at top level), so a private-auth-but-uncovered-by-sumdb tool
// dependency was silently missed entirely. See effectiveToolModules for
// how an uncovered tool path is folded into the checked module list
// without needing to resolve it down to its owning module first.
func parseTools(data []byte) []string {
	var tools []string
	inBlock := false
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			if t := firstField(trimmed); t != "" {
				tools = append(tools, t)
			}
			continue
		}

		if rest, ok := cutKeyword(trimmed, "tool"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			if t := firstField(rest); t != "" {
				tools = append(tools, t)
			}
		}
	}
	return tools
}

// effectiveToolModules returns the tool directive package paths not
// already covered by a require entry (exact match, or the require path
// as a parent package of the tool path), deduplicated. These are meant
// to be appended directly to the module list audit() checks, without
// first resolving each one down to its owning module the way a network-
// capable tool would: matchesPrefixPattern (pattern.go) truncates its
// target to the pattern's own segment count before matching, so a
// pattern like "github.com/myorg/private" already matches a longer tool
// package path like "github.com/myorg/private/cmd/foo" exactly as it
// would match the bare module path — no module-boundary resolution (and
// no network call to find one) is needed for correct GOPRIVATE/GONOSUMDB
// matching, only for questions this tool doesn't ask (e.g. "does this
// module exist"). A tool path covered by a require entry is skipped so
// it isn't checked (and potentially reported) twice under two different
// strings for the same underlying dependency.
func effectiveToolModules(tools []string, requires []string) []string {
	seen := make(map[string]bool, len(tools))
	var out []string
	for _, t := range tools {
		if seen[t] {
			continue
		}
		seen[t] = true

		covered := false
		for _, r := range requires {
			if t == r || strings.HasPrefix(t, r+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, t)
		}
	}
	return out
}

// stripComment removes a trailing "// ..." line comment, e.g. the
// "// indirect" annotation go mod tidy adds. "//" inside a double- or
// backtick-quoted string is left alone rather than treated as a comment
// marker, mirroring golang.org/x/mod/modfile's lexer (readToken): its
// quoted-string scan consumes characters up to the matching close quote
// unconditionally, only looking for "//" again once back outside any
// string. A plain strings.Index(line, "//") truncates mid-string the
// moment a quoted local replace path happens to contain a doubled
// separator — e.g. `replace foo => "../vendor//bar"`, which a real
// go.mod accepts and `go build` resolves correctly (verified live) —
// corrupting the parsed path and, via addReplace's "../" prefix check
// on the now-mangled string, misclassifying a purely local replace as a
// network-fetched module to check against GOPRIVATE instead.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		switch c := line[i]; c {
		case '"':
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				i++
			}
		case '`':
			i++
			for i < len(line) && line[i] != '`' {
				i++
			}
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return line[:i]
			}
		}
	}
	return line
}

// firstField returns the first field of s: for a require-block entry this
// is the module path (the second token is the version); for a replace
// directive's right-hand side it's the replacement path. go.mod's real
// lexer (golang.org/x/mod/modfile) allows any token to be written as a
// double- or backtick-quoted Go string literal instead of a bare word —
// `go mod edit` does this itself for a local replace path containing a
// space (e.g. replace foo => "../my mod"), which `go build` accepts fine.
// A naive whitespace split truncates that at the space and leaves a stray
// quote character, so a quoted token is unquoted first.
func firstField(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s[0] == '"' || s[0] == '`' {
		if tok, ok := leadingQuotedString(s); ok {
			return tok
		}
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// leadingQuotedString parses a double- or backtick-quoted Go string literal
// at the start of s and returns its unquoted value. Double-quoted strings
// honor backslash escapes (e.g. \" \\); backtick-quoted raw strings don't.
func leadingQuotedString(s string) (string, bool) {
	if s[0] == '`' {
		if i := strings.IndexByte(s[1:], '`'); i >= 0 {
			return s[1 : i+1], true
		}
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '"' {
			return b.String(), true
		}
		b.WriteByte(c)
	}
	return "", false
}

// cutKeyword strips a go.mod block keyword (e.g. "require", "replace") from
// the start of s and returns what follows, unparsed. It requires the
// keyword be followed by whitespace or "(" so it doesn't match a module
// path that happens to start with the same letters. go.mod's own lexer
// (golang.org/x/mod/modfile) treats "require(", "require\t(", and
// "require  (" identically to the gofmt-canonical "require (" — there's no
// space requirement — so callers must not rely on an exact-string match
// against "require (".
func cutKeyword(s, kw string) (rest string, ok bool) {
	if !strings.HasPrefix(s, kw) {
		return "", false
	}
	rest = s[len(kw):]
	if rest == "" {
		return "", false
	}
	if c := rest[0]; c != ' ' && c != '\t' && c != '(' {
		return "", false
	}
	return rest, true
}

// replaceTarget is the right-hand side of a go.mod replace directive.
type replaceTarget struct {
	path    string
	isLocal bool // true if the replacement is a filesystem path, not a module
}

// parseReplaces extracts replace directives, keyed by the original module
// path being replaced. A go.mod replace can point at either another module
// (network-fetched, same as any other require) or a local filesystem path
// (per the go.mod spec: a target beginning with "./" or "../", or an
// absolute path — matching golang.org/x/mod/modfile's own IsDirectoryPath,
// which uses filepath.IsAbs rather than a bare "/" prefix so Windows
// absolute paths like "C:\foo" are recognized too — never network-fetched
// at all, since the go tool reads it straight off disk). Both change what,
// if anything, should actually be checked against GOPRIVATE/GONOSUMDB in
// place of the original required path.
func parseReplaces(data []byte) map[string]replaceTarget {
	out := map[string]replaceTarget{}
	inBlock := false
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			addReplace(out, trimmed)
			continue
		}

		if rest, ok := cutKeyword(trimmed, "replace"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			addReplace(out, rest)
		}
	}
	return out
}

func addReplace(out map[string]replaceTarget, entry string) {
	lhs, rhs, ok := strings.Cut(entry, "=>")
	if !ok {
		return
	}
	oldPath := firstField(strings.TrimSpace(lhs))
	newPath := firstField(strings.TrimSpace(rhs))
	if oldPath == "" || newPath == "" {
		return
	}
	out[oldPath] = replaceTarget{path: newPath, isLocal: isDirectoryPath(newPath)}
}

// isDirectoryPath mirrors golang.org/x/mod/modfile.IsDirectoryPath: a
// replacement without a version must be a directory path, and the real
// go tool's own grammar (verified live: `replace foo => ..` builds and
// `go list -m all` resolves it straight off disk, no network call) treats
// the bare "." and ".." forms as directory paths too, not just "./" and
// "../" — a plain HasPrefix("./"/"../")-or-IsAbs check misses exactly
// those two bare forms, misclassifying a purely local replace as a
// network-fetched module path (and, via resolveEffectiveModules, sending
// the literal string "." or ".." to be checked against GOPRIVATE/
// GONOSUMDB in its place) even though `go` never queries anything for it.
// Windows-style forms (".\", "..\", bare "\", a drive letter) are in the
// real x/mod check too, but a go.mod containing one fails to parse at all
// on a non-Windows host (modfile.Parse rejects it explicitly), so this
// tool — which only ever runs on Linux — doesn't need to recognize them.
func isDirectoryPath(path string) bool {
	return path == "." || path == ".." ||
		strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") ||
		filepath.IsAbs(path)
}

// resolveEffectiveModules applies replace directives to a list of required
// module paths, producing the paths actually fetched over the network: a
// locally-replaced module is dropped entirely (go reads it off disk, so it
// can never leak to sum.golang.org regardless of GOPRIVATE), and a
// module-replaced one is swapped for its replacement's path (that's the
// path go actually queries the proxy/sumdb for).
func resolveEffectiveModules(modules []string, replaces map[string]replaceTarget) []string {
	var out []string
	for _, m := range modules {
		if r, ok := replaces[m]; ok {
			if r.isLocal {
				continue
			}
			out = append(out, r.path)
			continue
		}
		out = append(out, m)
	}
	return out
}

// goWorkReplaces reads a go.work file's replace directives, using the same
// grammar and parser as a go.mod's (go.work supports "go", "toolchain",
// "use", and "replace" directives — the replace syntax is identical to
// go.mod's). gowork is the path from `go env GOWORK` (or a test override):
// empty when the module isn't part of a workspace, or "off" when workspace
// mode is explicitly disabled (GOWORK=off) — both cases return nil. A
// go.work that can't be read (e.g. a stale GOWORK pointing at a file that
// no longer exists) is treated the same as "no workspace" rather than an
// error, matching how a missing GOPRIVATE/GONOSUMDB is already tolerated.
//
// This exists because a workspace's go.work can replace a dependency that
// a member module's own go.mod never mentions replacing at all — verified
// live: `go list -m all` inside a workspace module resolves a require to
// its go.work replacement target even though the module's go.mod shows
// only the plain (unreplaced) require. Before this, goprivaudit only ever
// read the single go.mod passed via -gomod, so a go.work replace that
// points a public-looking require at a privately-rewritten host (or vice
// versa) was invisible to it — the same class of silent miss the `tool`
// directive gap was, but for a config surface outside go.mod entirely.
func goWorkReplaces(gowork string) map[string]replaceTarget {
	if gowork == "" || gowork == "off" {
		return nil
	}
	data, err := os.ReadFile(gowork)
	if err != nil {
		return nil
	}
	return parseReplaces(data)
}

// mergeReplaces overlays a workspace's go.work replace directives on top of
// a module's own go.mod replaces. Per `go help work`: "If a module is
// replaced in both the workspace's go.work file and in the workspace
// module's go.mod file, the replacement in the go.work file is used" — so
// on a conflicting key, overlay wins; a go.work-only replace is simply
// added.
func mergeReplaces(base, overlay map[string]replaceTarget) map[string]replaceTarget {
	if len(overlay) == 0 {
		return base
	}
	merged := make(map[string]replaceTarget, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged
}
