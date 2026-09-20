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
			if p := normalizeToModulePrefix(value); p != "" && !isKnownPublicHost(p) {
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
