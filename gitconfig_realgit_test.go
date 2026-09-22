package main

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSplitLogicalLinesAgainstRealGit is an oracle-diff test for
// splitLogicalLines/stripLineComment/splitKV — the hand-rolled char-by-char
// line reader gitconfig.go uses to mirror config.c's continuation/comment
// rules (see splitLogicalLines's doc comment) — against the real `git
// config` binary, rather than the ad hoc single hand-verified case each of
// the last several fixes (case-sensitivity, backslash continuation) relied
// on. The prior fixes were each confirmed against live git by hand for one
// example; this generates many random insteadOf values combining 0-2
// line-continuation breaks (LF and CRLF) with an optional trailing comment
// ('#'/';', with/without a leading space) and checks that this tool's own
// extraction of the "insteadof" value agrees with what `git config --file`
// actually resolves it to.
//
// The generated character set for the value itself is deliberately
// restricted to what a real insteadOf URL can contain (letters, digits, and
// ./-:_~@ — see normalizeToModulePrefix's accepted URL forms): no quotes,
// backslashes, or comment characters. That keeps every generated case a
// valid, unambiguous gitconfig line for real git to parse (a value
// containing those characters needs quoting/escaping, a structurally
// different and separately-scoped question — see the run #154 decision log
// entry on the escaped-quote-in-subsection and literal-backslash gaps,
// both confirmed unreachable for real URLs and deliberately left alone).
func TestSplitLogicalLinesAgainstRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~:/@"
	rng := rand.New(rand.NewSource(42))
	dir := t.TempDir()

	randValue := func() string {
		n := 3 + rng.Intn(40)
		b := make([]byte, n)
		for i := range b {
			b[i] = charset[rng.Intn(len(charset))]
		}
		return string(b)
	}

	for i := 0; i < 5000; i++ {
		v := randValue()

		// Pick 0-2 continuation break points strictly inside v, sorted
		// descending so inserting at each position doesn't shift the
		// indices of the others.
		nBreaks := rng.Intn(3)
		positions := map[int]bool{}
		for len(positions) < nBreaks && len(positions) < len(v)-1 {
			p := 1 + rng.Intn(len(v)-1)
			positions[p] = true
		}
		var sorted []int
		for p := range positions {
			sorted = append(sorted, p)
		}
		for a := 0; a < len(sorted); a++ {
			for b := a + 1; b < len(sorted); b++ {
				if sorted[a] < sorted[b] {
					sorted[a], sorted[b] = sorted[b], sorted[a]
				}
			}
		}
		frag := v
		for _, p := range sorted {
			sep := "\\\n"
			if rng.Intn(2) == 0 {
				sep = "\\\r\n"
			}
			frag = frag[:p] + sep + frag[p:]
		}

		comment := ""
		switch rng.Intn(5) {
		case 0:
			comment = " #trail"
		case 1:
			comment = ";trail"
		case 2:
			comment = "#trail"
		case 3:
			comment = " ;trail"
		}

		content := "[url \"ph\"]\n\tinsteadOf = " + frag + comment + "\n"

		path := filepath.Join(dir, "c.cfg")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		out, err := exec.Command("git", "config", "--file", path, "url.ph.insteadof").Output()
		if err != nil {
			t.Fatalf("real git rejected a generated config it should accept (case %d, content %q): %v", i, content, err)
		}
		want := strings.TrimSuffix(string(out), "\n")

		got, ok := extractRawInsteadOfValue([]byte(content))
		if !ok {
			t.Fatalf("case %d: extractRawInsteadOfValue found no insteadof value for %q (real git: %q)", i, content, want)
		}
		if got != want {
			t.Fatalf("case %d: extractRawInsteadOfValue(%q) = %q, want %q (oracle: real git config --file)", i, content, got, want)
		}
	}
}

// extractRawInsteadOfValue mirrors privatePrefixesFromGitConfig's scan loop
// up to (not including) normalizeToModulePrefix/isKnownPublicHost, so the
// oracle-diff test above compares the raw joined-and-comment-stripped value
// this tool sees, not its further interpretation of that value.
func extractRawInsteadOfValue(data []byte) (string, bool) {
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
			return value, true
		}
	}
	return "", false
}
