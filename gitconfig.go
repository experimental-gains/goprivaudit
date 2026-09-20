package main

import (
	"bufio"
	"regexp"
	"strings"
)

var urlSectionRe = regexp.MustCompile(`^\[url\s+"([^"]*)"\]$`)

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
func privatePrefixesFromGitConfig(data []byte) []string {
	var prefixes []string
	inURLSection := false
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
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
		if key == "insteadof" || key == "pushinsteadof" {
			if p := normalizeToModulePrefix(value); p != "" {
				prefixes = append(prefixes, p)
			}
		}
	}
	return prefixes
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
