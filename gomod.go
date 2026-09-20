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

		switch {
		case trimmed == "require (":
			inBlock = true
		case strings.HasPrefix(trimmed, "require "):
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
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

// firstField returns the first whitespace-separated token, which for a
// require-block entry is the module path (the second token is the version).
func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
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

		switch {
		case trimmed == "replace (":
			inBlock = true
		case strings.HasPrefix(trimmed, "replace "):
			addReplace(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "replace")))
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
