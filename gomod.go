package main

import (
	"bufio"
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

// stripComment removes a trailing "// ..." line comment, e.g. the
// "// indirect" annotation go mod tidy adds.
func stripComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
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
// (per the go.mod spec, any target beginning with "./", "../", or "/" —
// never network-fetched at all, since the go tool reads it straight off
// disk). Both change what, if anything, should actually be checked against
// GOPRIVATE/GONOSUMDB in place of the original required path.
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
	local := strings.HasPrefix(newPath, "./") || strings.HasPrefix(newPath, "../") || strings.HasPrefix(newPath, "/")
	out[oldPath] = replaceTarget{path: newPath, isLocal: local}
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
