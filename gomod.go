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
