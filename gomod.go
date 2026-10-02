package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// requireEntry is one require directive: a module path and the version
// go.mod pins it to. The version is needed to pick the right replace
// directive when a go.mod has both a version-specific and a version-
// agnostic replace for the same module — see selectReplace.
type requireEntry struct {
	path    string
	version string
}

// parseRequires extracts module paths and versions from require directives
// in a go.mod file's contents. It intentionally does not parse the full
// go.mod grammar (no golang.org/x/mod dependency) — require blocks have a
// simple enough shape that a line scanner is sufficient.
func parseRequires(data []byte) []requireEntry {
	return parseModuleVersionDirectives(data, "require")
}

// parseExcludes extracts module paths and versions from exclude directives
// in a go.mod file's contents, using the identical "<path> <version>"
// grammar (single-line or block form) that parseRequires already reads for
// require directives — see filterExcludedRequires for why these are needed
// at all.
func parseExcludes(data []byte) []requireEntry {
	return parseModuleVersionDirectives(data, "exclude")
}

// parseModuleVersionDirectives extracts module paths and versions from
// every single-line or block-form directive in data whose verb is keyword
// (e.g. "require" or "exclude" — both share the exact same "<path>
// <version>" grammar, modulo keyword). It intentionally does not parse the
// full go.mod grammar (no golang.org/x/mod dependency) — these directives
// have a simple enough shape that a line scanner is sufficient.
func parseModuleVersionDirectives(data []byte, keyword string) []requireEntry {
	var modules []requireEntry
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
			if e, ok := parseRequireLine(trimmed); ok {
				modules = append(modules, e)
			}
			continue
		}

		if rest, ok := cutKeyword(trimmed, keyword); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			if e, ok := parseRequireLine(rest); ok {
				modules = append(modules, e)
			}
		}
	}
	return modules
}

// parseRequireLine parses a single require-block entry (or the inline form
// of a single-line require directive): "<path> <version>", version taken
// as the second whitespace-delimited field.
//
// A require path never *needs* quoting in a real go.mod (module paths
// can't contain spaces — module.CheckPath forbids it), but go.mod's real
// lexer (golang.org/x/mod/modfile) still allows one to be written as a
// double- or backtick-quoted Go string literal purely as a styling choice
// — the same optional-quoting allowance firstField already documents and
// handles for a replace target/tool path. A plain strings.Fields (this
// function's pre-fix form) doesn't unquote at all, so a quoted path
// (needlessly quoted or not) was kept with its literal quote characters
// intact — e.g. `require "github.com/org/repo" v1.0.0` parsed to
// requireEntry{path: `"github.com/org/repo"`}, not
// requireEntry{path: "github.com/org/repo"}. Confirmed live: `go mod edit
// -fmt`/`go build` both normalize that exact line straight to the
// unquoted form, resolving the real module — while goprivaudit's mangled,
// quote-still-attached path can never match a real private-auth-signal
// prefix or GOPRIVATE/GONOSUMDB pattern for the module's real host,
// silently dropping a real require entry out of the audit entirely (a
// missed SUMDB LEAK, not just a cosmetic parse difference).
func parseRequireLine(s string) (requireEntry, bool) {
	path, rest := firstFieldAndRest(s)
	if path == "" {
		return requireEntry{}, false
	}
	e := requireEntry{path: path}
	if v := firstField(rest); v != "" {
		e.version = v
	}
	return e, true
}

// parseGoVersion extracts a go.mod's `go` directive version string (e.g.
// "1.24.4" from a line reading "go 1.24.4"), or "" if the file has none. The
// `go` directive is always a single-line directive, never a `go (...)`
// block, so this doesn't need parseRequires/parseReplaces' block tracking.
// Used by vendorModeActive to replicate the go command's own "vendor/
// requires go >= 1.14" auto-detection rule.
func parseGoVersion(data []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if rest, ok := cutKeyword(trimmed, "go"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// parseModulePath extracts a go.mod's own `module` directive path (the
// value of "module <path>"), or "" if the file has no `module` directive at
// all. Used by effectiveToolModules to recognize a `tool` directive whose
// package lives inside the main module itself, rather than in any required
// dependency.
//
// The path is unquoted via firstFieldAndRest the same way parseRequireLine
// already does for a require path — go.mod's own module path can likewise
// be written as a double- or backtick-quoted Go string literal purely as a
// styling choice (modfile's lexer gives every module-path-shaped token the
// same optional-quoting allowance), so a plain whitespace trim (parseGoVersion's
// approach, correct for a `go` directive's version argument, which is never
// quoted) would leave a quoted module path's literal quote characters
// attached.
//
// The `module` directive, unlike `go`/`toolchain`, is NOT always a
// single-line directive: golang.org/x/mod/modfile's real parser (rule.go)
// lists "module" among the verbs its block-type switch accepts for a
// parenthesized `module (...)` form, exactly like require/exclude/replace/
// retract/tool/ignore/godebug — an earlier version of this doc comment
// claimed otherwise ("only require/exclude/replace/retract/tool support a
// parenthesized block form"), which was simply wrong. Live-verified against
// real go1.26.8: `go list -m` on a go.mod whose only module statement is
//
//	module (
//		example.com/foo
//	)
//
// resolves the main module as "example.com/foo", identical to the
// single-line form — not a parse error, not an unknown-block-type
// rejection. Before this fix, parseModulePath read the opening "module ("
// line alone (cutKeyword matches "module" followed by "("), extracted
// firstFieldAndRest's first field of the remaining "(" as the "path", and
// returned the single non-empty, non-module-path string "(" without ever
// looking at the line(s) inside the block — so effectiveToolModules' "does
// this tool directive live in the main module" check
// (`t == modulePath || strings.HasPrefix(t, modulePath+"/")`) could never
// match any real tool path, and a `tool` directive naming a package inside
// a block-form-declared main module was wrongly treated as an external
// dependency needing a GOPRIVATE/GONOSUMDB check — a false SUMDB LEAK for a
// path go never queries the checksum database for at all, confirmed live
// end-to-end against the built binary.
func parseModulePath(data []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	inBlock := false
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
			if path, _ := firstFieldAndRest(trimmed); path != "" {
				return path
			}
			continue
		}
		if rest, ok := cutKeyword(trimmed, "module"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			path, _ := firstFieldAndRest(rest)
			return path
		}
	}
	return ""
}

// goVersionDirectiveRE mirrors golang.org/x/mod/modfile's own GoVersionRE
// (rule.go) exactly: the shape a `go` directive's argument must match for
// the real go command's strict parser (modfile.Parse — what cmd/go actually
// calls to read a go.mod, verified in modload.ReadModFile) to accept it at
// all. Notably: a bare major.minor ("1.14") is valid, a full
// major.minor.patch ("1.24.4") is valid, and a prerelease-style suffix
// directly appended with no separator ("1.21rc1") is valid too — but a
// leading zero on either component, a missing minor, or any other trailing
// garbage is not.
var goVersionDirectiveRE = regexp.MustCompile(`^([1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?([a-z]+[0-9]+)?$`)

// goModHasInvalidGoDirective reports whether data contains a `go` directive
// line the real go command's own strict go.mod parser (modfile.Parse)
// rejects outright — either because its single argument doesn't match
// goVersionDirectiveRE ("invalid go version '<x>': must match format
// 1.23.0"), or because the line doesn't carry exactly one argument at all
// ("go directive expects exactly one argument", e.g. a bare "go" line with
// nothing after it, "go 1.14 extra", or a mistaken "go (...)" block attempt
// — the `go` directive, unlike require/replace/tool, is never a block form,
// confirmed by parseGoVersion's own doc comment).
//
// This matters for the same reason goModHasBlockComment and goflagsMalformed
// already skip the audit: a go.mod real go refuses to parse at all can never
// resolve a single module, so no sumdb query for anything in it can ever
// happen — reporting a SUMDB LEAK/BROAD PATTERN finding for a require line
// that's technically still sitting there in the raw bytes, when the one
// thing that would ever query the checksum database for it never runs, is
// an actively wrong claim, not just a missed check. Confirmed live
// end-to-end against the actual goprivaudit binary: a go.mod with a real,
// otherwise-uncovered private-auth-signaled require plus an invalid `go`
// directive ("go 1.9x") was reported "SUMDB LEAK" pre-fix, while `go list -m
// all`/`go build` on the identical file Fatal immediately with "errors
// parsing go.mod: go.mod:N: invalid go version '1.9x': must match format
// 1.23.0" and never get far enough to query anything. A missing `go`
// directive entirely is NOT one of these cases — verified live, a go.mod
// with no `go` line at all parses and resolves normally — so this only
// triggers when a `go` line is actually present and malformed, matching
// parseGoVersion's own "no `go` directive" convention (empty string, not an
// error).
//
// Deliberately does not reuse cutKeyword here (unlike parseGoVersion):
// cutKeyword requires its keyword be followed by whitespace or "(" — a
// sensible guard against matching a module path that happens to start with
// "go" (e.g. "godebug"), but it also rejects a bare "go" line with nothing
// after it at all (rest == ""), which is exactly one of the two invalid
// shapes this function needs to catch (modfile's real lexer reports that as
// "go directive expects exactly one argument", not "unknown directive").
// Splitting trimmed on whitespace directly and comparing the first field
// against "go" avoids that gap while still correctly leaving "godebug (" (a
// different first field entirely) alone.
func goModHasInvalidGoDirective(data []byte) bool {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if fields[0] != "go" {
			continue
		}
		args := fields[1:]
		if len(args) != 1 || !goVersionDirectiveRE.MatchString(args[0]) {
			return true
		}
	}
	return false
}

// goToolchainDirectiveRE mirrors golang.org/x/mod/modfile's own ToolchainRE
// (rule.go) exactly: the shape a `toolchain` directive's argument must match
// for the real go command's strict parser (modfile.Parse) to accept it at
// all — either the literal "default", or anything starting with "go1"
// followed by end-of-string or a "." (e.g. "go1.24.4", "go1.21rc1"). Unlike
// goVersionDirectiveRE (the bare version string a `go` directive takes),
// this is deliberately loose about what follows "go1" — real go's own
// regex is — because the toolchain name is re-validated more strictly
// elsewhere (gover.IsValid) once resolved; this function only needs to
// match what makes modfile.Parse itself accept or reject the line.
var goToolchainDirectiveRE = regexp.MustCompile(`^default$|^go1($|\.)`)

// goModHasInvalidToolchainDirective reports whether data contains a
// `toolchain` directive line the real go command's own strict go.mod parser
// (modfile.Parse) rejects outright — either because its single argument
// doesn't match goToolchainDirectiveRE ("invalid toolchain version '<x>':
// must match format go1.23.0 or default"), or because the line doesn't
// carry exactly one argument at all ("toolchain directive expects exactly
// one argument", e.g. a bare "toolchain" line with nothing after it, or
// "toolchain go1.24.4 extra") — the exact same argument-shape gap
// goModHasInvalidGoDirective already closes for the sibling `go` directive,
// confirmed to exist here too: golang.org/x/mod/modfile's add() switch
// validates "go" and "toolchain" with the parallel len(args)!=1-then-regex
// structure (see rule.go), so an unrecognized-verb check alone
// (goModHasUnknownDirective, which already accepts "toolchain" as a valid
// verb since it IS one) was never enough to catch a malformed *argument* to
// it, exactly as an unrecognized-verb check alone wasn't enough for `go`
// before goModHasInvalidGoDirective was added.
//
// This matters for the same "cannot leak" reason as every other malformed-
// go.mod skip in this file: a go.mod real go refuses to parse at all can
// never resolve a single module, so no sumdb query for anything in it can
// ever happen. Confirmed live end-to-end against the actual goprivaudit
// binary, pre-fix: a go.mod with a real, otherwise-uncovered
// private-auth-signaled require plus a malformed "toolchain 1.24.4" line
// (missing the "go" prefix a real toolchain name always carries) was
// reported "SUMDB LEAK", while `go list -m all`/`go build` on the identical
// file Fatal immediately ("go: invalid toolchain "1.24.4" in go.mod" for a
// ToolchainRE mismatch, or "errors parsing go.mod: go.mod:N: toolchain
// directive expects exactly one argument" for a bare/extra-argument
// "toolchain" line — both verified live, `go version go1.26.8`) and never
// get far enough to query anything. A missing `toolchain` directive
// entirely is NOT one of these cases — a go.mod with no `toolchain` line at
// all parses and resolves normally — so this only triggers when a
// `toolchain` line is actually present and malformed.
//
// Uses the same fields[0]-comparison shape goModHasInvalidGoDirective uses
// rather than cutKeyword, for the identical reason: cutKeyword requires its
// keyword be followed by whitespace or "(", which would reject a bare
// "toolchain" line with nothing after it at all — exactly one of the two
// invalid shapes this function needs to catch.
func goModHasInvalidToolchainDirective(data []byte) bool {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if fields[0] != "toolchain" {
			continue
		}
		args := fields[1:]
		if len(args) != 1 || !goToolchainDirectiveRE.MatchString(args[0]) {
			return true
		}
	}
	return false
}

// singletonDirectiveVerbs is a set of go.mod/go.work top-level directive
// keywords golang.org/x/mod/modfile's real parser treats as singleton per
// file: reading rule.go's (*File).add and (*WorkFile).add directly, "go"
// and "toolchain" each start with an unconditional `if f.Go != nil
// { errorf("repeated go statement") }`-shaped guard (ditto "toolchain" and,
// go.mod-only, "module") that fires the INSTANT a second occurrence of that
// verb appears anywhere in the file — checked before that second
// occurrence's own argument grammar is validated at all, and regardless of
// whether either occurrence is itself individually well-formed. This is a
// distinct Fatal shape from every other check in this family
// (goModHasInvalidGoDirective/goModHasInvalidToolchainDirective validate a
// single occurrence's own argument; this instead catches two or more
// occurrences that could each individually pass those checks). Every other
// go.mod/go.work directive (require, exclude, replace, retract, tool,
// ignore, godebug, use) is accumulated into a slice instead by the real
// parser and may legally repeat as many times as desired.
//
// goModSingletonVerbs/goWorkSingletonVerbs (immediately below) instantiate
// this per file format: go.work has no "module" directive at all (an
// unrecognized verb there, already caught by goWorkHasUnknownDirective), so
// it isn't included in goWorkSingletonVerbs.
var goModSingletonVerbs = map[string]bool{"go": true, "toolchain": true, "module": true}
var goWorkSingletonVerbs = map[string]bool{"go": true, "toolchain": true}

// goModHasRepeatedSingletonDirective reports whether data contains more
// than one occurrence of a verb in singletonVerbs — a second "go",
// "toolchain", or (go.mod only) "module" statement anywhere in the file —
// which makes the real go command's own strict parser (modfile.Parse /
// modfile.ParseWork) Fatal with "repeated go statement" / "repeated
// toolchain statement" / "repeated module statement" before resolving a
// single module, even when every individual occurrence's own argument is
// perfectly valid on its own (e.g. two individually well-formed "go 1.21"
// and "go 1.22" lines). Live-verified against real go1.26.8, fully offline
// (GOPROXY=off): a go.mod with "go 1.21" followed later by "go 1.22" (both
// matching goVersionDirectiveRE on their own) Fatals immediately with
// "go.mod:N: repeated go statement", and the identical shape reproduces for
// a doubled "toolchain go1.21.0"/"toolchain go1.22.0" pair ("repeated
// toolchain statement") and a doubled "module" directive ("repeated module
// statement") — confirmed end-to-end against the actual goprivaudit binary,
// pre-fix: a go.mod with a real, otherwise-uncovered private-auth-signaled
// require plus a duplicated "go" directive was reported "SUMDB LEAK", while
// `go list -m all`/`go build` on the identical file Fatal immediately and
// never get far enough to query anything. The same Fatal shape was
// independently confirmed for go.work's own "go"/"toolchain" directives
// (`golang.org/x/mod/modfile`'s (*WorkFile).add carries the identical
// `f.Go != nil`/`f.Toolchain != nil` guards), which is why this function
// takes singletonVerbs as a parameter rather than hard-coding go.mod's own
// set — see goWorkHasUnparseableDirective's doc comment for how it's
// reused against a go.work file's own bytes with goWorkSingletonVerbs.
//
// A "module" directive's block form ("module (\n\texample.com/foo\n)")
// counts each non-empty line inside the block as its own occurrence, not
// the block as a whole — matching the real parser, which dispatches every
// block-entry line through the identical (*File).add call as a top-level
// single-line directive of the same verb (see goModHasUnknownDirective's
// own doc comment for the identical block-entry-dispatch convention): two
// module paths inside one `module (...)` block, or one single-line "module"
// directive followed by a separate "module (...)" block (or vice versa),
// both genuinely Fatal with "repeated module statement" too — live-verified
// both shapes independently. "go"/"toolchain" are never valid block-form
// verbs at all (rule.go's own block-type switch doesn't list them), so a
// stray "go (" is simply not counted as an occurrence here — a different,
// already out-of-scope malformed shape ("unknown block type: go"), not a
// hole in this function's own repeated-statement coverage.
func goModHasRepeatedSingletonDirective(data []byte, singletonVerbs map[string]bool) bool {
	counts := map[string]int{}
	inBlock := false
	blockVerb := ""
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
			if singletonVerbs[blockVerb] {
				counts[blockVerb]++
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if singletonVerbs[verb] {
			counts[verb]++
		}
	}
	for _, c := range counts {
		if c > 1 {
			return true
		}
	}
	return false
}

// goModValidTopLevelVerbs is the complete, fixed set of go.mod top-level
// directive keywords golang.org/x/mod/modfile's real parser
// ((*File).add's verb switch, rule.go) recognizes for the main module:
// module, go, toolchain, require, exclude, replace, retract, tool,
// ignore, and godebug — every case in that switch besides its `default`.
// Anything else hits that default case outright: `errorf("unknown
// directive: %s", verb)`. Like goflagsInvalidModValue's accepted -mod
// set, this is small, stable, and fully documented (`go help go.mod`) —
// it hasn't changed shape since `ignore`/`godebug` were added — so it's
// checked directly rather than by shelling out to a live `go` binary the
// way goflagsRejectedByGo's registered-flag-name check does for GOFLAGS
// (whose accepted set isn't otherwise enumerable from outside cmd/go).
var goModValidTopLevelVerbs = map[string]bool{
	"module": true, "go": true, "toolchain": true, "require": true,
	"exclude": true, "replace": true, "retract": true, "tool": true,
	"ignore": true, "godebug": true,
}

// goModHasUnknownDirective reports whether data contains a top-level line
// whose first token isn't one of goModValidTopLevelVerbs — the general
// shape goModHasInvalidGoDirective only ever covers for the "go"
// directive specifically (a recognized "go" line with a malformed
// argument). An entirely unrecognized verb — a plausible pluralization
// slip like "requires" instead of "require" (exactly the kind of mistake
// an LLM's training-data intuition for English grammar produces, the
// same failure class this whole tool exists to catch), a case mismatch
// like "GO" instead of "go" (verb matching is case-sensitive: verified
// live that `GO 1.24` Fatals with "unknown directive: GO", not treated
// as the `go` directive), a misspelling, or outright garbage — makes the
// real go command's strict go.mod parser Fatal with "unknown directive:
// %s" before resolving a single module, before it even gets to whichever
// directive-specific validation goModHasInvalidGoDirective/
// goModHasBlockComment model. Same "cannot leak" reasoning as every
// other malformed-go.mod skip in this file: a query that never happens
// can't leak anything.
//
// Confirmed live end-to-end against the actual goprivaudit binary,
// pre-fix: a go.mod with a real, otherwise-uncovered private-auth-signaled
// require plus an unrelated "requires bogus/directive v1.0.0" line
// elsewhere in the file was reported "SUMDB LEAK", while `go list -m
// all`/`go build` on the identical file Fatal immediately with "errors
// parsing go.mod: go.mod:N: unknown directive: requires" and never get
// far enough to query anything (see
// TestRunUnknownDirectiveGoModNoLeak in main_test.go for the exact
// reproduction).
//
// Lines inside an existing block ("require (\n...\n)") are never
// verb-checked themselves: the real parser dispatches every block entry
// under its own block's opening verb, never re-examines each inner
// line's first token as a directive verb of its own — the same
// convention parseRequires/parseReplaces/parseTools's own dedicated
// block tracking already follows, just generalized here across every
// verb (including ones this file has no dedicated parser for at all,
// like "retract (...)" or "ignore (...)"), not just the handful with
// their own parser. Block-open detection matches cutKeyword's own
// documented rule: the verb may be followed directly by "(" with no
// separating space at all ("require(" is real, accepted go.mod syntax,
// verified live), not just "verb (".
func goModHasUnknownDirective(data []byte) bool {
	return hasUnknownTopLevelDirective(data, goModValidTopLevelVerbs)
}

// goModHasIgnoreDirective reports whether data's go.mod contains a
// top-level `ignore` directive at all (single-line "ignore path" form or
// the parenthesized block form) — just presence, the same scan
// hasUnknownTopLevelDirective already drives for the general
// unknown-verb case, specialized to stop and report true the instant
// "ignore" itself is the verb, rather than checking it against a validity
// set. Used only by goModHasIgnoreDirectiveTooOld, which needs this one
// verb's presence in isolation, not a general-purpose unknown-verb scan.
func goModHasIgnoreDirective(data []byte) bool {
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
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		if verb == "ignore" {
			return true
		}
		if strings.TrimSpace(trimmed[i:]) == "(" {
			inBlock = true
		}
	}
	return false
}

// goModHasIgnoreDirectiveTooOld reports whether data's go.mod contains a
// top-level `ignore` directive (see goModHasIgnoreDirective) that the go
// toolchain actually processing this file cannot recognize at all —
// making every module-aware go subcommand Fatal with "errors parsing
// go.mod: go.mod:N: unknown directive: ignore" before resolving a single
// module. The same "cannot leak" shape goModHasUnknownDirective already
// covers for every verb outside goModValidTopLevelVerbs — except `ignore`
// IS (correctly, for a modern-enough toolchain) in that set, so
// goModHasUnknownDirective alone can't catch this.
//
// `ignore` is a real go.mod directive, but a relatively new one: confirmed
// absent from golang.org/x/mod/modfile as vendored into go1.24.4's own
// cmd/go (no "ignore" case anywhere in its verb switch — only
// module/go/toolchain/require/exclude/replace/retract/tool/godebug) and
// present starting go1.25.14/go1.26.0 (read directly from each
// toolchain's own vendored modfile/rule.go). Whether a given go.mod's
// `ignore` line actually parses depends on which toolchain binary ends up
// running it, governed by GOTOOLCHAIN (default "auto"): the effective
// version is max(the locally installed/selected go version, whatever
// this go.mod's own `go`/`toolchain` directive requires) — go never
// downgrades, and only attempts to download a newer toolchain when the
// file's own stated requirement exceeds what's already installed/selected.
//
// So this only fires when BOTH halves of that max are below 1.25:
//   - the file's own `go` directive requires less than 1.25 (an absent
//     `go` line — parseGoVersion returns "" — counts as unsatisfied too,
//     matching goVersionAtLeast's existing empty-string convention), AND
//   - localGoVersion (the toolchain that's actually installed/selected,
//     meant to be `go env GOVERSION` run in the module's own directory —
//     the same live-ask-go pattern goflagsRejectedByGo already uses for a
//     fact this package can't enumerate any other way) is ALSO below
//     1.25.
//
// If the file's own `go` directive already requires >=1.25,
// GOTOOLCHAIN=auto either runs an already-sufficient local toolchain or
// downloads one — and if that download fails for lack of network, go
// Fatals on ITS OWN toolchain-fetch error instead, a different but
// equally real "cannot leak" case this function deliberately leaves
// alone rather than double-counting. An unresolvable localGoVersion
// (empty, matching goEnv's own failure convention) fails open here too,
// the same convention this package's other goEnv-derived checks already
// use for an environment fact it can't pin down.
//
// Live-verified (2026-10): a from-scratch go.mod reading only `module
// example.com/ignoretest`, `go 1.21`, and `ignore "testdata"` makes
// `go env GOVERSION`/`go list -m all` (run with GOPROXY=off, GOTOOLCHAIN
// left at its default "auto") Fatal instantly with "go.mod:5: unknown
// directive: ignore" under a real go1.24.4 installation, zero network
// access — even though `go mod edit -ignore=testdata` (run moments
// earlier with a real go1.26.8 toolchain) is exactly how that file was
// produced in the first place: `go mod edit -ignore=` does NOT bump the
// file's own `go` line to cover a directive it just added. Before this
// fix, goprivaudit's goModHasUnknownDirective treated `ignore`
// unconditionally as a valid verb and ran its normal SUMDB-leak audit on
// a file like this, misreporting a leak for a query real go, right here,
// never reaches.
func goModHasIgnoreDirectiveTooOld(data []byte, localGoVersion string) bool {
	if !goModHasIgnoreDirective(data) {
		return false
	}
	if goVersionAtLeast(parseGoVersion(data), 1, 25) {
		return false
	}
	local := strings.TrimPrefix(strings.TrimSpace(localGoVersion), "go")
	if local == "" {
		return false
	}
	return !goVersionAtLeast(local, 1, 25)
}

// goWorkValidTopLevelVerbs is the complete, fixed set of go.work top-level
// directive keywords golang.org/x/mod/modfile's real parser
// ((*WorkFile).add's verb switch, rule.go) recognizes: go, toolchain,
// godebug, use, and replace — a DIFFERENT, narrower set than
// goModValidTopLevelVerbs (go.work has no module/require/exclude/retract/
// tool/ignore directives at all; "use" instead is unique to go.work).
// "godebug" is NOT go.mod-only, despite an earlier version of this comment
// claiming it was: (*WorkFile).add has its own "godebug" case (identical
// `len(args) != 1 || strings.ContainsAny(args[0], "\"`',")` shape to the
// go.mod one), and ParseWork's own LineBlock switch accepts a block-form
// "godebug (...)" too, exactly like go.mod's. Live-verified against real
// go1.24.4/go1.26.8, fully offline (GOPROXY=off): a go.work with a
// single-line `godebug default=go1.24` and `use ./app` parses and resolves
// clean (reaches "module lookup disabled by GOPROXY=off" — i.e. it got all
// the way to the fetch attempt, never Fataling parsing go.work at all) —
// pre-fix, this tool's own `goWorkHasUnknownDirective` treated that
// perfectly valid line as an unrecognized verb, so `run()` wrongly
// concluded the go.work "would make go Fatal before resolving anything"
// and silently skipped the entire audit, suppressing a real `SUMDB LEAK`
// finding for an otherwise-uncovered private-auth-signaled require in the
// very same workspace member's go.mod (confirmed end-to-end against the
// actual built binary: identical go.mod+git-insteadOf fixture reports
// "SUMDB LEAK" with no go.work, or with a go.work missing the godebug
// line, and wrongly "no issues found" once the valid godebug line is
// added — see TestRunGodebugDirectiveGoWorkStillLeaks). Verified
// separately that a go.work containing a `require ...` line — perfectly
// valid in a go.mod — still Fatals with "unknown directive: require"
// parsing go.work, confirming the two grammars really are distinct sets,
// not one a subset of the other.
var goWorkValidTopLevelVerbs = map[string]bool{
	"go": true, "toolchain": true, "godebug": true, "use": true, "replace": true,
}

// goWorkHasUnknownDirective is goModHasUnknownDirective's go.work
// counterpart, using go.work's own distinct valid-verb set — see
// goWorkHasUnparseableDirective's doc comment for why go.work needs this
// family of checks at all.
func goWorkHasUnknownDirective(data []byte) bool {
	return hasUnknownTopLevelDirective(data, goWorkValidTopLevelVerbs)
}

// hasUnknownTopLevelDirective is the shared scan goModHasUnknownDirective
// and goWorkHasUnknownDirective both drive off their own distinct
// validVerbs set: golang.org/x/mod/modfile parses go.mod and go.work with
// two separate (*File).add/(*WorkFile).add verb switches that don't
// recognize the same keywords (see goWorkValidTopLevelVerbs), so a single
// shared verb set would either wrongly accept a go.mod-only verb inside a
// go.work file or wrongly reject a go.work-only verb ("use") — either one a
// wrong "cannot leak" verdict in the direction that actually matters here.
func hasUnknownTopLevelDirective(data []byte, validVerbs map[string]bool) bool {
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
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		if !validVerbs[verb] {
			return true
		}
		if strings.TrimSpace(trimmed[i:]) == "(" {
			inBlock = true
		}
	}
	return false
}

// goModFixedArgCountVerbs was originally the subset of goModValidTopLevelVerbs
// whose entire argument-validity rule, per golang.org/x/mod/modfile's real
// parser ((*File).add's verb switch, rule.go), is a single fixed required
// argument count with no further content-shape check beyond that — unlike
// `go`/`toolchain`, whose argument must ALSO match a version/toolchain-name
// regex (already covered by goModHasInvalidGoDirective/
// goModHasInvalidToolchainDirective), or `replace`/`retract`/`godebug`,
// whose usage errors depend on token *content* (an "=>" arrow, a "["/"]"
// version-interval bracket, an embedded quote/comma), not just count, and
// are deliberately left out of scope here — approximating either of those
// risks a wrong verdict in either direction rather than a purely
// conservative one, the same reason `hasconfig:` was ruled out for
// includeIfMatches. Confirmed directly against rule.go's own switch: cases
// "require","exclude" both require len(args)==2 (module path, version);
// "tool" requires len(args)==1 (package path); "module" also requires
// len(args)==1 (the module path) — its `errorf("usage: module module/path")`
// fires purely off the argument count, with the module path's own quoting
// handled generically by parseString exactly like every other verb here, so
// it belongs in this fixed-count family too. `ignore` (added to
// golang.org/x/mod/modfile after go1.24 — absent from go1.24's own vendored
// copy, present from go1.26.8 onward, confirmed by diffing both installed
// toolchains' vendored rule.go directly) shares the exact same
// single-fixed-argument shape: `case "ignore": if len(args) != 1 {
// errorf("ignore directive expects exactly one argument") }`, with its
// argument's own quoting handled generically by parseString exactly like
// module/tool. Confirmed live against real go1.26.8 (this repo's own go.mod
// `go` directive, auto-selected via GOTOOLCHAIN=auto): both a bare `ignore`
// line and `ignore testdata extra` Fatal with "ignore directive expects
// exactly one argument" before resolving a single dependency — `ignore` was
// simply missing from this map (an omission, not a documented exclusion the
// way `replace`/`retract`/`godebug` are), the same drift technique #61's
// family already found once for retract/godebug and technique #86's family
// found again for `module`.
//
// This map now ALSO carries "use" — go.work's own member-directory directive,
// never a valid go.mod verb (absent from goModValidTopLevelVerbs entirely),
// so the "subset of goModValidTopLevelVerbs" framing above is now stale for
// this one entry; it's kept in the same map purely so
// goModHasInvalidDirectiveArgCount can be reused verbatim against a go.work
// file's own bytes, exactly like goModHasInvalidReplaceDirective/
// goModHasInvalidGodebugDirective already are (see
// goWorkHasUnparseableDirective's doc comment). (*WorkFile).add's own "use"
// case (rule.go) is `case "use": if len(args) != 1 { errorf("usage: %s
// local/dir", verb) } ... parseString(&args[0])` — byte-for-byte the same
// single-fixed-argument-with-generic-quoting shape as `tool`/`module`/
// `ignore` above, NOT a content-dependent grammar like `replace`/`retract`/
// `godebug`. A prior version of this file's goWorkHasUnparseableDirective
// doc comment incorrectly lumped "use" in with those three as "left alone"
// because approximating a content-shape rule risks a wrong verdict — but
// "use" was never actually a content-shape rule, just an omitted fixed-count
// one, the same "explicit-looking exclusion that was actually just an
// oversight" trap technique #66/#86 already named for `replace`/`module`.
var goModFixedArgCountVerbs = map[string]int{
	"require": 2,
	"exclude": 2,
	"tool":    1,
	"module":  1,
	"ignore":  1,
	"use":     1,
}

// goModHasInvalidDirectiveArgCount reports whether data contains a
// require/exclude/tool/module/ignore directive line (single-line or
// block-entry form) that the real go command's own strict go.mod parser
// (modfile.Parse) rejects outright for carrying the wrong number of
// arguments: a require line missing its version ("require
// example.com/foo"), one carrying a stray extra token ("require
// example.com/foo v1.0.0 extra" — a plausible leftover from a botched
// merge-conflict resolution or hand-edit), a tool line naming more than one
// package, a module line carrying zero or two-plus arguments ("module"
// alone, or "module example.com/app extra" — the same plausible hand-edit
// slip, just on the one directive every go.mod has), or an ignore line
// carrying zero or two-plus arguments ("ignore" alone, or "ignore testdata
// extra"). Live-verified (2026-09) against the real go toolchain: each of
// those shapes, plus the exclude/block-entry equivalents, Fatals
// immediately with "usage: require module/path v1.2.3" / "usage: exclude
// module/path v1.2.3" / "tool directive expects exactly one argument" /
// "usage: module module/path" / "ignore directive expects exactly one
// argument" — before resolving a single module. Same "cannot leak"
// reasoning as every other malformed-go.mod skip in this file (see
// goModHasInvalidGoDirective's doc comment): a go.mod real go refuses to
// parse at all can never resolve a single module, so no sumdb query for
// anything in it — including an unrelated, otherwise-valid require line
// sitting elsewhere in the same file — can ever happen. Confirmed live
// end-to-end against the actual goprivaudit binary, pre-fix: a go.mod with
// a real, otherwise-uncovered private-auth-signaled netrc-covered require
// plus an unrelated "require example.com/foo v1.0.0 extra" line was
// reported "SUMDB LEAK", while `go list -m all`/`go build` on the identical
// file Fatal immediately and never get far enough to query anything. The
// identical false SUMDB LEAK reproduced (and is fixed by this same check)
// for a malformed `module` line, and again for a malformed `ignore` line —
// see TestRunInvalidModuleDirectiveArgCountGoModNoLeak and
// TestRunInvalidIgnoreDirectiveArgCountGoModNoLeak.
//
// This function also doubles as the argument-count check for go.work's own
// "use" directive when goWorkHasUnparseableDirective calls it against a
// go.work file's bytes instead of a go.mod's — see goModFixedArgCountVerbs'
// doc comment for why "use" belongs in the same map, and
// goWorkHasUnparseableDirective's doc comment for why reusing this function
// verbatim (rather than writing a go.work-specific variant) is safe: none of
// require/exclude/tool/module/ignore are valid go.work verbs, so they can
// never appear in a go.work file without goWorkHasUnknownDirective already
// flagging it first via the same `||` chain.
//
// This is the general-across-verbs sibling of goModHasInvalidGoDirective/
// goModHasInvalidToolchainDirective, extending the same "recognized verb,
// unchecked argument grammar" family one level further: recognizing
// "require"/"exclude"/"tool"/"module"/"ignore" as valid top-level verbs
// (goModHasUnknownDirective already does) is a different claim from
// validating how many arguments follow them. `module` and `ignore` were,
// until fixed, both missing from that family — not because either's
// argument grammar is any different from `tool`'s (all three are a single
// fixed-count argument with no further content-shape check), but by simple
// omission: this function's own doc comment used to claim `module` was
// "out of scope per [goModFixedArgCountVerbs'] doc comment" alongside
// replace/retract/godebug, but that var's doc comment never actually named
// `module` (or `ignore`, added to the language after this function was
// first written) as one of the deliberately-excluded, content-dependent
// verbs — the same "an explicit exclusion reads as more final than an
// ordinary gap" trap technique #66 already named once, just recurring as a
// plain gap each time instead of a documented one.
//
// Block-entry lines (inside "require (\n...\n)" etc.) are checked the same
// way, using the enclosing block's own verb and that line's own tokens as
// its argument list — matching how the real parser dispatches every block
// entry under its own block's opening verb (see goModHasUnknownDirective's
// doc comment for the identical block-tracking convention). A verb outside
// goModFixedArgCountVerbs (go/toolchain, already covered elsewhere;
// replace/retract/godebug, out of scope per that var's doc comment) is not
// checked here at all.
func goModHasInvalidDirectiveArgCount(data []byte) bool {
	inBlock := false
	blockVerb := ""
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
			if n, ok := goModFixedArgCountVerbs[blockVerb]; ok && countDirectiveArgs(trimmed) != n {
				return true
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if n, ok := goModFixedArgCountVerbs[verb]; ok && countDirectiveArgs(rest) != n {
			return true
		}
	}
	return false
}

// countDirectiveArgs counts the arguments in a go.mod directive's argument
// text, honoring two real-lexer quirks a plain strings.Fields split would
// miss:
//
//   - A quoted argument (e.g. a require path written as a Go string
//     literal) counts as a single argument even if it contains embedded
//     spaces — handled via leadingQuotedString, the same helper
//     firstFieldAndRest already uses for this.
//   - "(" and ")" are ALWAYS their own separate one-character tokens to the
//     real lexer, even glued directly onto an adjacent argument with no
//     whitespace at all. Live-verified: `require(example.com/foo v1.0.0)`
//     — a require directive line whose parenthesis is attached with no
//     space, immediately followed by two conceptual arguments and a closing
//     paren all on the SAME line (not a multi-line block: the whole thing,
//     including the closing ")", sits on one line) — Fatals with "usage:
//     require module/path v1.2.3" exactly like a 3-or-more-argument
//     require line does, because the real lexer counts 4 tokens ("(",
//     "example.com/foo", "v1.0.0", ")"), not the 2 a naive split on
//     whitespace-attached-to-parens would suggest. A tokenizer that instead
//     glued a leading/trailing paren onto its neighboring word (as this
//     function's first draft did, matching firstFieldAndRest's own
//     whitespace-only field split) would silently miscount this exact
//     shape as valid — a false negative on a real, live-confirmed
//     unparsable go.mod, the same "active wrong claim" risk this whole
//     function exists to close, just reached through the tokenizer instead
//     of the count comparison.
func countDirectiveArgs(s string) int {
	n := 0
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return n
		}
		switch s[0] {
		case '(', ')':
			s = s[1:]
		case '"', '`':
			if _, consumed, ok := leadingQuotedString(s); ok {
				s = s[consumed:]
			} else {
				s = s[1:]
			}
		default:
			i := 0
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '(' && s[i] != ')' {
				i++
			}
			if i == 0 {
				i = 1
			}
			s = s[i:]
		}
		n++
	}
}

// modulePathVersionSuffix mirrors golang.org/x/mod/module.SplitPathVersion's
// own extraction of a module path's major-version suffix — the "/v2",
// "/v3", ... a module at major version 2+ is required to carry on its own
// path (go.dev/ref/mod, "Major version suffixes") — for every path shape
// except gopkg.in's own distinct ".vN" convention (see
// gopkgInVersionSuffix). Returns major=="" and ok==true for a path with no
// version-shaped suffix at all (the ordinary case: no sumdb-query-blocking
// Fatal is possible on the path's shape alone). Returns ok==false for a
// path whose tail LOOKS like an attempted major-version suffix but isn't a
// well-formed one — a bare "/v1" (invalid: v0/v1 modules never carry an
// explicit suffix at all), a leading-zero "/v02", or a suffix containing a
// stray "." — live-verified (go1.26.8, GOPROXY=off) that each of these
// makes `go build`/`go list -m all` Fatal immediately with `errors parsing
// go.mod: go.mod:N: require <path>: version "<v>" invalid: malformed
// module path "<path>"`, regardless of what version is paired with it.
func modulePathVersionSuffix(path string) (major string, ok bool) {
	if strings.HasPrefix(path, "gopkg.in/") {
		return gopkgInVersionSuffix(path)
	}
	i := len(path)
	dot := false
	for i > 0 && (('0' <= path[i-1] && path[i-1] <= '9') || path[i-1] == '.') {
		if path[i-1] == '.' {
			dot = true
		}
		i--
	}
	if i <= 1 || i == len(path) || path[i-1] != 'v' || path[i-2] != '/' {
		return "", true
	}
	major = path[i-2:]
	if dot || len(major) <= 2 || major[2] == '0' || major == "/v1" {
		return "", false
	}
	return major, true
}

// gopkgInVersionSuffix is modulePathVersionSuffix's counterpart for
// gopkg.in's own distinct major-version convention: a ".vN" suffix (a dot,
// not a slash) immediately before the path's end or its optional
// "-unstable" tag — mirroring golang.org/x/mod/module's own splitGopkgIn
// exactly, including the ".v0" carve-out (gopkg.in, unlike every other
// host, really does allow an explicit v0) and the "-unstable" tag riding
// along inside the returned major string untouched (trimmed back off only
// at comparison time — see requireVersionMajorInvalid, mirroring
// module.CheckPathMajor's own order of operations). Every gopkg.in path
// must end in one of these forms at all per go.dev's own gopkg.in
// documentation; one that doesn't is a different, already-Fatal shape this
// function reports via ok==false, matching modulePathMajor's own "invalid
// module path" error for it.
func gopkgInVersionSuffix(path string) (major string, ok bool) {
	i := len(path)
	if strings.HasSuffix(path, "-unstable") {
		i -= len("-unstable")
	}
	for i > 0 && '0' <= path[i-1] && path[i-1] <= '9' {
		i--
	}
	if i <= 1 || path[i-1] != 'v' || path[i-2] != '.' {
		return "", false
	}
	major = path[i-2:]
	if len(major) <= 2 || (major[2] == '0' && major != ".v0") {
		return "", false
	}
	return major, true
}

// requireVersionCanonicalMajor reports v's major component ("v1", "v2", ...)
// IF AND ONLY IF v is in exactly the one shape real go's own fixVersion
// (cmd/go/internal/modload/init.go, the VersionFixer modload.ReadModFile
// passes when reading the MAIN module's go.mod) short-circuits without any
// network access at all: `module.CanonicalVersion(vers) == vers` — i.e. v
// already specifies a full major.minor.patch triple (not a shorthand like
// "v1" or "v1.0" that fixVersion would need to expand via a proxy Query to
// find the latest matching release), with its build metadata, if any, being
// exactly "+incompatible" (the one build tag module.CanonicalVersion
// preserves verbatim — every other build tag makes CanonicalVersion strip
// it, so the comparison against the untouched original fails and fixVersion
// falls through to its network Query instead). ok=false covers both "v
// isn't valid semver at all" and "v is valid but not already in this exact
// fast-path shape" — in either case this file has no way to know, without a
// network call of its own, whether real go would Fatal offline or just
// query a proxy, so the conservative, fail-open answer is the same either
// way: don't flag it.
//
// Live-verified (go1.26.8, GOPROXY=off), every case against a go.mod
// pairing it with a path whose major suffix it clearly mismatches:
// "v1.0.0" and "v1.0.0-pre" (full triple, with/without prerelease) both
// Fatal immediately with CheckPathMajor's own error text; "v2.0.0+incompatible"
// likewise (parses clean against a no-suffix path, per CheckPathMajor's own
// "+incompatible" carve-out — see requireVersionMajorInvalid); but "v1"
// (bare major), "v1.0" (major.minor, no patch), and "v1.0.0+meta" (a
// generic, non-"+incompatible" build tag) each instead fail with "module
// lookup disabled by GOPROXY=off" — a live network attempt, not an
// immediate parse Fatal — confirming the exact fast-path/network-path
// boundary this function draws. Mirrors golang.org/x/mod/semver's own
// parse/parseInt/parsePrerelease grammar (parseSemverInt/skipSemverPrerelease
// below) closely enough to make this determination without pulling in the
// semver package itself, matching this file's established
// no-golang.org/x/mod-dependency convention for its production (non-test)
// code (see parseRequires' own doc comment).
func requireVersionCanonicalMajor(v string) (major string, ok bool) {
	if len(v) < 2 || v[0] != 'v' {
		return "", false
	}
	s := v[1:]
	var majorDigits string
	majorDigits, s, ok = parseSemverInt(s)
	if !ok || s == "" || s[0] != '.' {
		return "", false
	}
	_, s, ok = parseSemverInt(s[1:])
	if !ok || s == "" || s[0] != '.' {
		return "", false
	}
	_, s, ok = parseSemverInt(s[1:])
	if !ok {
		return "", false
	}
	if s != "" && s[0] == '-' {
		s, ok = skipSemverPrerelease(s)
		if !ok {
			return "", false
		}
	}
	if s != "" && s != "+incompatible" {
		return "", false
	}
	return "v" + majorDigits, true
}

// parseSemverInt mirrors golang.org/x/mod/semver's own parseInt: a run of
// ASCII digits at the start of s with no leading zero (unless the whole
// run is the single digit "0"), the same grammar go.mod's own `go`/
// `toolchain` directive version numbers already follow (see
// goVersionDirectiveRE).
func parseSemverInt(s string) (digits, rest string, ok bool) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return "", s, false
	}
	i := 1
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if s[0] == '0' && i != 1 {
		return "", s, false
	}
	return s[:i], s[i:], true
}

// skipSemverPrerelease mirrors golang.org/x/mod/semver's own
// parsePrerelease: s must start with '-'; what follows, up to the next '+'
// or end of string, must be one or more dot-separated identifiers, each
// using only ASCII alphanumerics and '-', with an all-numeric identifier
// never carrying a leading zero (isBadSemverNum) — per semver's own spec
// ("Numeric identifiers MUST NOT include leading zeroes").
func skipSemverPrerelease(s string) (rest string, ok bool) {
	i := 1
	start := 1
	for i < len(s) && s[i] != '+' {
		c := s[i]
		isIdentChar := ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-'
		if !isIdentChar && c != '.' {
			return s, false
		}
		if c == '.' {
			if start == i || isBadSemverNum(s[start:i]) {
				return s, false
			}
			start = i + 1
		}
		i++
	}
	if start == i || isBadSemverNum(s[start:i]) {
		return s, false
	}
	return s[i:], true
}

func isBadSemverNum(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i == len(s) && i > 1 && s[0] == '0'
}

// requireVersionMajorInvalid reports whether a require/exclude directive's
// (path, version) pair is exactly the shape golang.org/x/mod/modfile's real
// strict parser rejects outright via module.CheckPathMajor — called
// unconditionally on every require/exclude line once its own path and
// version both parse as individually well-formed strings, entirely
// independent of any network access (no proxy/sumdb lookup is involved in
// comparing a path's own major-version suffix against its paired version's
// major component; both are already sitting in the go.mod's raw bytes, and
// requireVersionCanonicalMajor's own gate already excludes any version
// shape that would instead need one). Mirrors module.CheckPathMajor's exact
// logic: a path with no version suffix at all requires a v0 or v1 (or
// "+incompatible"-tagged) version; a path with a "/vN" (or gopkg.in ".vN")
// suffix requires a version whose own major component is exactly "vN"; the
// one documented historical exception (a gopkg.in ".v1" path paired with a
// "v0.0.0-"-prefixed pseudo-version, kept for backward compatibility with
// an old pseudo-version generation bug) is carried over unchanged.
// Live-verified (go1.26.8, GOPROXY=off): `require example.com/foo/v2
// v1.0.0` Fatals with `version "v1.0.0" invalid: should be v2, not v1`;
// `require example.com/bar v2.0.0` (no suffix at all) Fatals with `should
// be v0 or v1, not v2`, while the identical line with "v2.0.0+incompatible"
// parses clean; `require gopkg.in/yaml.v2 v1.0.0` Fatals identically to the
// "/v2" case.
func requireVersionMajorInvalid(path, version string) bool {
	pathMajor, ok := modulePathVersionSuffix(path)
	if !ok {
		return true
	}
	if strings.HasPrefix(pathMajor, ".v") && strings.HasSuffix(pathMajor, "-unstable") {
		pathMajor = strings.TrimSuffix(pathMajor, "-unstable")
	}
	if strings.HasPrefix(version, "v0.0.0-") && pathMajor == ".v1" {
		return false
	}
	m, ok := requireVersionCanonicalMajor(version)
	if !ok {
		return false
	}
	if pathMajor == "" {
		return !(m == "v0" || m == "v1" || strings.HasSuffix(version, "+incompatible"))
	}
	return m != pathMajor[1:]
}

// goModHasMismatchedPathMajorVersion reports whether data contains a
// `require`/`exclude` directive line (single-line or block-entry form, the
// same two verbs goModFixedArgCountVerbs already requires carry exactly two
// arguments) whose path and paired version real go's own strict go.mod
// parser rejects via requireVersionMajorInvalid. Only applies once a line
// already has exactly path+version (two tokens) — a wrong argument count is
// goModHasInvalidDirectiveArgCount's own, already-covered Fatal shape, not
// this one. Same "cannot leak" reasoning as every other malformed-go.mod
// skip in this file: a go.mod real go refuses to parse at all can never
// resolve a single module, so no sumdb query for anything in it — including
// an unrelated, otherwise-valid require line sitting elsewhere in the same
// file — can ever happen. Confirmed live end-to-end against the actual
// goprivaudit binary, pre-fix: a go.mod with a real, otherwise-uncovered
// private-auth-signaled require plus an unrelated "require
// example.com/foo/v2 v1.0.0" line (a plausible mistake: bumping a module to
// v2 and forgetting to update the pinned version, or vice versa) was
// reported "SUMDB LEAK", while `go list -m all`/`go build` on the identical
// file Fatal immediately and never get far enough to query anything — see
// TestRunMismatchedPathMajorVersionGoModNoLeak in main_test.go.
func goModHasMismatchedPathMajorVersion(data []byte) bool {
	inBlock := false
	blockVerb := ""
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
			if (blockVerb == "require" || blockVerb == "exclude") && requireExcludeLineMajorInvalid(trimmed) {
				return true
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if (verb == "require" || verb == "exclude") && requireExcludeLineMajorInvalid(rest) {
			return true
		}
	}
	return false
}

// requireExcludeLineMajorInvalid extracts a require/exclude line's (or
// block entry's) own argument text into a path and version the same way
// parseRequireLine already does, but — unlike parseRequireLine, which
// tolerates a missing or extra token since goModHasInvalidDirectiveArgCount
// handles that shape separately — requires exactly two tokens (path,
// version, nothing more) before calling requireVersionMajorInvalid at all,
// matching the real parser's own `len(args) != 2` gate that runs before
// CheckPathMajor is ever reached.
func requireExcludeLineMajorInvalid(s string) bool {
	path, rest := firstFieldAndRest(s)
	version, rest2 := firstFieldAndRest(rest)
	if path == "" || version == "" {
		return false
	}
	if extra, _ := firstFieldAndRest(rest2); extra != "" {
		return false
	}
	return requireVersionMajorInvalid(path, version)
}

// isValidGodebugArg reports whether s (a `godebug` directive's argument
// text, single-line or block-entry) is the shape golang.org/x/mod/modfile's
// real strict parser accepts: exactly one token, containing no `"`, “ ` “,
// `'`, or `,` byte, and containing at least one "=" — mirroring rule.go's
// "godebug" case exactly (`len(args) != 1 ||
// strings.ContainsAny(args[0], "\"`',")`, then `strings.Cut(args[0], "=")`
// failing when there's no "=" at all).
func isValidGodebugArg(s string) bool {
	fields := strings.Fields(s)
	if len(fields) != 1 {
		return false
	}
	arg := fields[0]
	return !strings.ContainsAny(arg, "\"`',") && strings.Contains(arg, "=")
}

// goModHasInvalidGodebugDirective reports whether data contains a
// `godebug` directive line (single-line or block-entry form — godebug is
// one of the verbs golang.org/x/mod/modfile's LineBlock switch accepts in
// block form, see goModValidTopLevelVerbs' doc comment) the real go
// command's own strict go.mod parser (modfile.Parse) rejects outright: a
// missing/extra argument, an argument with no "=" at all, or one embedding
// a `"`, backtick, `'`, or `,` byte (see isValidGodebugArg). Live-verified
// against real go1.26.8, fully offline (GOPROXY=off): `godebug nokeyvalue`
// (no "=") and `godebug foo=bar,baz` (an embedded comma, one of the
// rejected bytes) both Fatal immediately with "errors parsing go.mod: ...
// usage: godebug key=value", before resolving a single module — the same
// "cannot leak" shape as goModHasInvalidGoDirective/
// goModHasInvalidToolchainDirective, just for the sibling directive that
// also supports the block form. Deliberately does not validate the key
// itself against go's actual recognized godebug settings
// (httplaxcontentlength, etc.) — that's a semantic check real go performs
// later, not a go.mod-parse-time Fatal; a go.mod naming an unrecognized
// godebug key still parses and resolves fine (verified live).
func goModHasInvalidGodebugDirective(data []byte) bool {
	inBlock := false
	blockVerb := ""
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
			if blockVerb == "godebug" && !isValidGodebugArg(trimmed) {
				return true
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if verb == "godebug" && !isValidGodebugArg(rest) {
			return true
		}
	}
	return false
}

// retractDirectiveTokens splits a retract directive's own argument text (or
// a block-entry line's text) into golang.org/x/mod/modfile's real token
// stream for this grammar: "[", "]", and "," are always their own
// single-character tokens, even glued directly onto a version with no
// separating whitespace at all — live-verified: real go accepts
// "retract[v1.0.0,v1.0.1]" with zero spaces anywhere, tokenizing it
// identically to the spaced-out form — exactly the same real-lexer
// convention countDirectiveArgs already documents for "(" and ")".
// Anything else is a bracket/comma/whitespace-delimited word, standing in
// for parseVersionInterval's own "version" token: this only needs the
// token count and shape (see retractArgInvalid), not whether a version
// token is itself a syntactically valid semver string — that's a separate,
// later, network-dependent question (see goModHasInvalidRetractDirective's
// doc comment) out of scope here.
func retractDirectiveTokens(s string) []string {
	var toks []string
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return toks
		}
		switch s[0] {
		case '[', ']', ',':
			toks = append(toks, s[:1])
			s = s[1:]
		default:
			i := 0
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '[' && s[i] != ']' && s[i] != ',' {
				i++
			}
			if i == 0 {
				i = 1
			}
			toks = append(toks, s[:i])
			s = s[i:]
		}
	}
}

// retractArgInvalid reports whether toks (from retractDirectiveTokens)
// violates golang.org/x/mod/modfile's parseVersionInterval grammar
// (rule.go) — the exact structural shape real go's strict go.mod parser
// requires for a retract directive's argument: either one bare version
// token with nothing else, or "[" version "," version "]" with nothing
// left over either way (a real go.mod strict-parses "unexpected token
// after version" when anything trails a complete interval, single-version
// or bracketed). Deliberately does not check whether either version token
// is itself syntactically valid semver: modfile's own retract-specific
// version fixer (dontFixRetract) never validates that at parse time either
// — live-verified that a syntactically nonsensical version
// ("retract bogus-not-a-version") reaches a LATER, network-dependent
// validation step (a proxy lookup to canonicalize it) rather than an
// immediate offline go.mod parse error, unlike every shape this function
// does flag — so treating that shape as invalid here would be a guess this
// tool has no local way to confirm, the same reason GOPROXY=off isn't
// treated as an unconditional "cannot leak" guarantee elsewhere in this
// package.
func retractArgInvalid(toks []string) bool {
	if len(toks) == 0 || toks[0] == "(" {
		return true
	}
	if toks[0] != "[" {
		return len(toks) != 1
	}
	return len(toks) != 5 || toks[2] != "," || toks[4] != "]"
}

// goModHasInvalidRetractDirective reports whether data contains a
// `retract` directive line (single-line or block-entry form) the real go
// command's own strict go.mod parser (modfile.Parse) rejects outright per
// retractArgInvalid's grammar — a bare "retract" with no version at all, a
// stray extra token after a complete version or bracketed interval, or an
// incomplete bracketed interval (missing the comma, the second version, or
// the closing "]"). Live-verified against real go1.26.8, fully offline
// (GOPROXY=off): a bare "retract" line Fatals with "errors parsing go.mod:
// ... expected '[' or version", and "retract v1.2.3 extra" Fatals with
// "... unexpected token after version", both before resolving a single
// module — the same "cannot leak" shape as goModHasInvalidGoDirective/
// goModHasInvalidToolchainDirective/goModHasInvalidGodebugDirective, for
// the sibling directive whose argument grammar hadn't been checked at all
// before this: goModHasUnknownDirective already accepts "retract" as a
// valid top-level verb, and goModFixedArgCountVerbs' own doc comment
// explicitly scoped retract out of the simpler require/exclude/tool
// arg-count check (its argument count varies — 1 token for a bare version,
// 5 for a bracketed interval — so a naive fixed-count check doesn't apply),
// but that never meant no check was possible, just that it needed to
// follow the actual token grammar instead of a bare count, the same way
// goModHasInvalidGoDirective/goModHasInvalidToolchainDirective already do
// for their own directives via a regex instead of a count.
func goModHasInvalidRetractDirective(data []byte) bool {
	inBlock := false
	blockVerb := ""
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
			if blockVerb == "retract" && retractArgInvalid(retractDirectiveTokens(trimmed)) {
				return true
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if verb == "retract" && retractArgInvalid(retractDirectiveTokens(rest)) {
			return true
		}
	}
	return false
}

// replaceDirectiveTokens splits a replace directive's own argument text (or
// a block-entry line's text) into golang.org/x/mod/modfile's real token
// stream for this grammar. Unlike countDirectiveArgs's "(" and ")" tokens
// and retractDirectiveTokens' "[", "]", "," tokens — always their own
// token even glued directly onto a neighboring word with no whitespace at
// all — a replace directive's "=>" arrow is NOT special punctuation to the
// real lexer: confirmed reading golang.org/x/mod/modfile/read.go's isIdent
// directly, only ' ', '(', ')', '[', ']', '{', '}', ',' are excluded from
// the identifier character class, so '=' and '>' are ordinary identifier
// runes exactly like any path character. An arrow glued directly onto an
// adjacent word with no separating whitespace (e.g. "foo=>bar") is lexed
// as ONE token, never recognized as the arrow at all. So this tokenizer,
// unlike the paren/bracket ones, is plain whitespace-and-quote-aware field
// splitting — the same firstFieldAndRest every other token in this
// grammar (require/tool/replace paths) already goes through — with no
// special-casing for "=>" at all.
func replaceDirectiveTokens(s string) []string {
	var toks []string
	for {
		field, rest := firstFieldAndRest(s)
		if field == "" {
			return toks
		}
		toks = append(toks, field)
		s = rest
	}
}

// replaceArgInvalid reports whether toks (from replaceDirectiveTokens)
// violates golang.org/x/mod/modfile's parseReplace grammar (rule.go) in one
// of its purely-structural, offline-checkable ways — matching
// retractArgInvalid's own scope: checks token shape and the new-side path's
// directory-path-ness, not either side's version-string content (see
// goModHasInvalidReplaceDirective's doc comment for why version validity is
// a separate, later, network-dependent question this tool deliberately
// leaves alone, the same carve-out already established for retract).
//
//   - The arrow isn't at position 1 (no old-side version) or position 2 (an
//     old-side version present), or the total token count falls outside
//     [arrow+2, arrow+3] — real go's own "usage: replace module/path
//     [v1.2.3] => other/module v1.4\n\t or ... ../local/directory" check.
//   - No new-side version (arrow+2 tokens total) and the new-side path
//     isn't a directory path (isDirectoryPath) — the new path must either
//     carry its own version or look like a local directory. This also
//     covers the narrower "path@version" shape (a plausible habit carried
//     over from an ecosystem that writes dependency pins that way): real go
//     gives that shape a more specific error message
//     ("replacement module must match format 'path version', not
//     'path@version'"), but it's still just one way for "not a directory
//     path and no separate version token" to be true, so no separate check
//     is needed to also flag it.
//   - A new-side version IS present (arrow+3 tokens) and the new-side path
//     IS a directory path — real go never allows a version pin on a local
//     replacement target.
func replaceArgInvalid(toks []string) bool {
	arrow := 2
	if len(toks) >= 2 && toks[1] == "=>" {
		arrow = 1
	}
	if len(toks) < arrow+2 || len(toks) > arrow+3 || toks[arrow] != "=>" {
		return true
	}
	newPath := toks[arrow+1]
	if len(toks) == arrow+2 {
		return !isDirectoryPath(newPath)
	}
	return isDirectoryPath(newPath)
}

// goModHasInvalidReplaceDirective reports whether data contains a `replace`
// directive line (single-line or block-entry form) the real go command's
// own strict go.mod parser (modfile.Parse) rejects outright per
// replaceArgInvalid's grammar — a missing arrow, a doubled arrow, a
// missing/extra token on either side, a new-side path with neither a
// version nor a directory-path shape (including the common "path@version"
// mistake), or a new-side directory path carrying a version it can't have.
// Live-verified against real go1.24.4, fully offline (GOPROXY=off): a
// go.mod with a real, otherwise-uncovered private-auth-signaled require
// plus an unrelated "replace example.com/foo => example.com/bar@v1.0.0"
// line elsewhere Fatals immediately with "errors parsing go.mod: ...
// replacement module must match format 'path version', not 'path@version'"
// — and the pre-fix goprivaudit binary still reported "SUMDB LEAK" for the
// require line it could still see above the malformed replace, confirmed
// end-to-end against the actual binary (see
// TestRunInvalidReplaceDirectiveGoModNoLeak in main_test.go). Same
// "cannot leak" reasoning as every other malformed-go.mod skip in this
// file (see goModHasInvalidGoDirective's doc comment): a go.mod real go
// refuses to parse at all can never resolve a single module, so no sumdb
// query for anything in it — including an unrelated, otherwise-valid
// require line sitting elsewhere in the same file — can ever happen.
//
// This closes the one verb goModFixedArgCountVerbs' own doc comment named
// as explicitly out of scope for that simpler check and that — unlike its
// two retract/godebug companions, both later given their own dedicated
// grammar check (goModHasInvalidRetractDirective,
// goModHasInvalidGodebugDirective) — had never been revisited since:
// recognizing "replace" as a valid top-level verb (goModHasUnknownDirective)
// is a different claim from validating its own argument grammar, the same
// drift technique #61 already named for retract/godebug themselves.
//
// Deliberately does not validate either side's version-string content
// (e.g. "replace example.com/foo v1.0.0 => example.com/bar not-a-version"):
// live-verified that shape instead makes real go attempt to canonicalize
// the version via its module-fetch machinery ("module lookup disabled by
// GOPROXY=off" with GOPROXY=off, i.e. a real network-dependent path, not an
// immediate offline Fatal) — the same "version content is a separate,
// later question" carve-out goModHasInvalidRetractDirective's own doc
// comment already establishes for retract's version tokens, just
// reconfirmed independently for replace's.
func goModHasInvalidReplaceDirective(data []byte) bool {
	inBlock := false
	blockVerb := ""
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
			if blockVerb == "replace" && replaceArgInvalid(replaceDirectiveTokens(trimmed)) {
				return true
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		verb := trimmed[:i]
		rest := strings.TrimSpace(trimmed[i:])
		if rest == "(" {
			inBlock = true
			blockVerb = verb
			continue
		}
		if verb == "replace" && replaceArgInvalid(replaceDirectiveTokens(rest)) {
			return true
		}
	}
	return false
}

// goModHasConflictingReplaceDirective reports whether data contains two
// (otherwise individually well-formed) `replace` directives — single-line
// or block-entry form, any mix — for the same old module path and old
// version (a bare "replace foo => X", with no version on the old side,
// counts as old version "" — matching every required version of foo, per
// selectReplace's own precedence rule) that name two different new-side
// targets (new path, or new path *and* new version — a module-type
// replacement's own version matters here even though it's otherwise
// irrelevant to the GOPRIVATE/GONOSUMDB path-only check this tool runs,
// since two replacements differing only by new-side version still count as
// "different" to the real parser).
//
// Live-verified (go1.26.8, GOPROXY=off): a go.mod with
//
//	replace example.com/foo v1.0.0 => example.com/bar v1.0.0
//	replace example.com/foo v1.0.0 => example.com/baz v1.0.0
//
// makes `go list -m all`/`go build`/`go mod download` all Fatal immediately
// with "go: conflicting replacements for example.com/foo@v1.0.0:\n\t
// example.com/bar@v1.0.0\n\texample.com/baz@v1.0.0" — before resolving a
// single module, GOPROXY=off or not — while the pre-fix goprivaudit binary
// silently applied "last replace for a given old path/version wins" (see
// addReplace) and audited whichever target happened to be written last.
// Confirmed end-to-end against the actual binary with a go.mod carrying
// exactly this conflicting pair, where the *last* replace's target
// (github.com/privorg/baz) has its own uncovered private-auth signal (a git
// insteadOf rewrite for github.com/privorg/, no matching GOPRIVATE entry):
// the pre-fix binary reported "SUMDB LEAK: github.com/privorg/baz ..." even
// though real go never queries anything for it — the build Fatals on the
// conflicting-replacements error first, every time, regardless of which
// replace is written last. Same "cannot leak" reasoning as every other
// malformed/inconsistent-go.mod skip in this file (see
// goModHasMismatchedPathMajorVersion's doc comment): a build that Fatals
// before resolving a single module can never leak anything to sum.golang.org,
// no matter which of the conflicting targets this tool's own best-effort
// "last one wins" convention happens to pick for its own, unrelated
// resolveEffectiveModules/addReplace machinery.
//
// Does NOT flag two replaces for the same old path/version that happen to
// name the *identical* new-side target (live-verified separately: that
// exact shape makes `go list -m all` proceed past the conflicting-
// replacements check entirely, failing later only for the unrelated reason
// that go.sum has no entry yet) — only a genuine mismatch between the two
// new-side targets triggers the real Fatal this function mirrors.
//
// Deliberately re-scans data from scratch with its own tiny
// oldKey->newTarget map rather than reusing parseReplaces/addReplace's own
// map (which already discards the losing target the moment it sees a
// second entry for the same key, via its own "last one wins" overwrite) —
// recovering that discarded information by threading a parallel "was this
// overwritten with a different value" flag through addReplace would
// complicate the one piece of code every other check in this file already
// depends on for its happy-path resolution, for a single-purpose skip this
// self-contained re-scan gets just as correctly and far more safely.
func goModHasConflictingReplaceDirective(data []byte) bool {
	type target struct {
		path    string
		version string
	}
	seen := map[string]target{}
	inBlock := false
	blockVerb := ""
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var verb, rest string
		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			verb, rest = blockVerb, trimmed
		} else {
			i := 0
			for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
				i++
			}
			verb = trimmed[:i]
			rest = strings.TrimSpace(trimmed[i:])
			if rest == "(" {
				inBlock = true
				blockVerb = verb
				continue
			}
		}
		if verb != "replace" {
			continue
		}
		toks := replaceDirectiveTokens(rest)
		if replaceArgInvalid(toks) {
			// Malformed shape: goModHasInvalidReplaceDirective already
			// Fatals this independently of any conflict, so this function
			// doesn't need to (and, since toks' own shape is unreliable
			// here, safely can't) reason about it further.
			continue
		}
		arrow := 2
		if toks[1] == "=>" {
			arrow = 1
		}
		oldVersion := ""
		if arrow == 2 {
			oldVersion = toks[1]
		}
		key := toks[0] + "\x00" + oldVersion
		newVersion := ""
		if len(toks) == arrow+3 {
			newVersion = toks[arrow+2]
		}
		t := target{path: toks[arrow+1], version: newVersion}
		if prev, ok := seen[key]; ok && prev != t {
			return true
		}
		seen[key] = t
	}
	return false
}

// goWorkHasConflictingReplaceDirective is goModHasConflictingReplaceDirective
// applied to an active go.work file's own replace directives instead of the
// go.mod being audited: go.work's replace grammar is identical to go.mod's
// (see goWorkReplaces' doc comment), and real go applies this exact same
// conflicting-replacements Fatal to a go.work file's own Replace list too —
// live-verified (go1.26.8): a go.work containing the same conflicting pair
// shown in goModHasConflictingReplaceDirective's doc comment, with `use`
// naming the audited module directly, makes `go list -m all` run from
// inside that module Fatal with the identical "conflicting replacements for
// ...\n\t...\n\t..." error, before resolving a single one of its requires.
func goWorkHasConflictingReplaceDirective(gowork string) bool {
	if gowork == "" || gowork == "off" {
		return false
	}
	data, err := os.ReadFile(gowork)
	if err != nil {
		return false
	}
	return goModHasConflictingReplaceDirective(data)
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
//
// A tool path that is the main module itself, or a package inside it (exact
// match against modulePath, or modulePath as a path prefix), is skipped
// entirely rather than audited — go.dev/ref/mod's `tool` directive doc
// explicitly allows naming "a main package in the main module" (not just a
// dependency's), a real, documented, `go mod tidy`-stable pattern for
// tracking an in-repo build tool (e.g. a `cmd/gen` used via `go tool` or
// `go generate`) the same go.mod-level way Go 1.24 tracks a third-party
// one. Live-verified against real go1.24.4: a go.mod with only `module
// example.com/mymod` / `go 1.24.4` / `tool example.com/mymod/cmd/mytool` (no
// require at all) builds fully offline (`GOPROXY=off go build ./...`
// succeeds) and `go list -m all` resolves only the main module itself — the
// tool path is never looked up as a separate module, so no sumdb query for
// it can ever happen. Before this check existed, such a tool path fell
// through to the "not covered by any require" branch exactly like a real
// external dependency's tool would, and got audited as if it were one: with
// a git insteadOf/credential-helper/netrc signal that happened to cover the
// main module's own host (e.g. a private-hosted repo's own module path)
// but wasn't itself listed in GOPRIVATE/GONOSUMDB, goprivaudit reported a
// false "SUMDB LEAK" for a checksum-database query that structurally cannot
// happen — confirmed live end-to-end against the actual goprivaudit binary
// on the go.mod above plus a matching `[url "ssh://git@example.com/"]
// insteadOf = https://example.com/`.
func effectiveToolModules(tools []string, requires []requireEntry, modulePath string) []string {
	seen := make(map[string]bool, len(tools))
	var out []string
	for _, t := range tools {
		if seen[t] {
			continue
		}
		seen[t] = true

		if modulePath != "" && (t == modulePath || strings.HasPrefix(t, modulePath+"/")) {
			continue
		}

		covered := false
		for _, r := range requires {
			if t == r.path || strings.HasPrefix(t, r.path+"/") {
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
// goModHasBlockComment reports whether data contains a "/*" outside any
// quoted string, on some line, before that line's own "//" comment marker
// (if any) — the exact trigger golang.org/x/mod/modfile's real lexer uses to
// Fatal every module-aware go subcommand with "mod files must use // comments
// (not /* */ comments)", verified live: `go build`/`go mod download`/etc. all
// refuse to even parse a go.mod containing a bare `/*` outside a quoted
// string, anywhere in the file — including on a line of its own, unrelated
// to any require/replace directive, e.g. a leftover Go-style block comment a
// human or a generator mistakenly wrote (go.mod's grammar is Go-ish enough to
// invite exactly that mistake, but explicitly disallows it). No matching
// "*/" is required for the Fatal to trigger — the lexer errors the instant it
// sees the two-character "/*" sequence, whatever follows.
//
// This matters here for the same reason goflagsMalformed and vendorModeActive
// do (see main.go's doc comment): a go.mod real go refuses to parse at all
// can never resolve a single module, so no sumdb query for anything in it can
// ever happen — reporting a SUMDB LEAK finding for a require/tool directive
// that's technically still there in the raw bytes, when the one thing that
// would ever query the checksum database for it never runs, is an actively
// wrong claim, not just a missed check. Confirmed live end-to-end against the
// actual goprivaudit binary: a go.mod with a real, otherwise-uncovered
// private-auth-signaled require plus an unrelated stray `/* ... */` line
// elsewhere in the file was reported "SUMDB LEAK" pre-fix, while `go build`
// on the identical file Fatals immediately with "errors parsing go.mod:
// go.mod:N: mod files must use // comments (not /* */ comments)" and never
// gets far enough to query anything.
//
// A "/*" that appears inside a quoted string (e.g. a replace target's local
// path containing a literal "/*", `"../weird/*/dir"`) is not a lexer error —
// verified live, that go.mod parses and builds fine — so, like stripComment,
// quoted and backtick-quoted spans are skipped rather than scanned. go.mod
// strings can never contain a literal newline (the real lexer Fatals on one
// too), so scanning line-by-line, independently per line, matches the real
// lexer's behavior exactly without needing to track quote state across
// lines.
func goModHasBlockComment(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		for i := 0; i < len(line); i++ {
			switch line[i] {
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
				if i+1 >= len(line) {
					continue
				}
				switch line[i+1] {
				case '/':
					i = len(line)
				case '*':
					return true
				}
			}
		}
	}
	return false
}

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
	field, _ := firstFieldAndRest(s)
	return field
}

// firstFieldAndRest is firstField's rest-preserving form: it also returns
// whatever of s came after the first field (with the field's own leading
// whitespace already trimmed off the front of s, but not off the returned
// rest), so a caller that needs a second field — parseRequireLine's
// version, addReplace's old-path version — can keep scanning from exactly
// where the first field ended, whether or not that field was quoted. This
// matters because a quoted field's length in s is not the same as its
// unquoted value's length (an escape like \x2e collapses four source bytes
// into one decoded byte, and even an unescaped quoted token like
// `"foo"` is two bytes longer than its value `foo`) — cutting rest at
// len(field) instead of at the real end-of-token position would silently
// re-scan part of the quoted token itself as if it were the next field.
func firstFieldAndRest(s string) (field, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' || s[0] == '`' {
		if tok, consumed, ok := leadingQuotedString(s); ok {
			return tok, s[consumed:]
		}
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", ""
	}
	return fields[0], s[len(fields[0]):]
}

// leadingQuotedString parses a double- or backtick-quoted Go string literal
// at the start of s and returns its unquoted value plus the number of bytes
// of s it consumed (including both quote characters). Backtick-quoted raw
// strings carry their content verbatim, no escapes at all.
//
// Double-quoted strings go through strconv.Unquote — the same function
// golang.org/x/mod/modfile's own parseString (rule.go) uses for this —
// rather than a hand-rolled "copy the byte after a backslash literally"
// unescaper (this function's pre-fix shape). That naive approach is only
// correct for the two escapes whose decoded byte equals the character
// following the backslash (\\ and \"); every other Go string escape
// decodes to something else entirely — \t is a tab (0x09), not the letter
// 't'; \xHH/\uHHHH/\UHHHHHHHH and octal \NNN decode a hex/unicode/
// octal-coded byte or rune, not a copy of their own digits. Confirmed
// live: a go.mod with `require "github\x2ecom/pkg/errors" v0.9.1` (a
// real, existing dependency, its module path's literal "." hex-escaped
// for no reason other than an AI-generated or hand-written go.mod's
// unusual styling) is accepted by `go build`/`go mod edit -fmt`, both of
// which rewrite it straight to the plain, unquoted `require
// github.com/pkg/errors v0.9.1` — confirming the real go toolchain
// decodes \x2e as "." and resolves the intended, real module, while this
// function's pre-fix byte-literal unescaper turned the same token into
// "githubx2ecom/pkg/errors" (the 'x' kept literally, "2e" copied as plain
// digits) — a path that can never match the module's real private-auth
// signal or GOPRIVATE/GONOSUMDB coverage, silently dropping a real
// require entry out of the audit. The token-boundary scan (skip one byte
// after any backslash, stop at an unescaped quote) already finds the same
// closing-quote position real go's lexer does regardless of which
// multi-byte escape appears, so only the decoded value needed fixing, not
// the boundary search.
func leadingQuotedString(s string) (value string, consumed int, ok bool) {
	if s[0] == '`' {
		if i := strings.IndexByte(s[1:], '`'); i >= 0 {
			return s[1 : i+1], i + 2, true
		}
		return "", 0, false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if c == '"' {
			v, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", 0, false
			}
			return v, i + 1, true
		}
	}
	return "", 0, false
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

// replaceEntry is one replace directive's right-hand side plus the version
// it applies to on the left: oldVersion == "" means the directive has no
// version on its old-path side, so per the go.mod spec it applies to
// every required version of that module ("all versions"), not just one.
// See selectReplace for how a required module's actual version picks
// between two replaceEntry values for the same path.
type replaceEntry struct {
	oldVersion string
	target     replaceTarget
}

// parseReplaces extracts replace directives, keyed by the original module
// path being replaced (a path can have more than one replaceEntry: a
// go.mod may legally carry both a version-specific and a version-agnostic
// replace for the same module — see selectReplace). A go.mod replace can
// point at either another module (network-fetched, same as any other
// require) or a local filesystem path (per the go.mod spec: a target
// beginning with "./" or "../", or an absolute path — matching
// golang.org/x/mod/modfile's own IsDirectoryPath, which uses
// filepath.IsAbs rather than a bare "/" prefix so Windows absolute paths
// like "C:\foo" are recognized too — never network-fetched at all, since
// the go tool reads it straight off disk). Both change what, if anything,
// should actually be checked against GOPRIVATE/GONOSUMDB in place of the
// original required path.
func parseReplaces(data []byte) map[string][]replaceEntry {
	out := map[string][]replaceEntry{}
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

func addReplace(out map[string][]replaceEntry, entry string) {
	lhs, rhs, ok := strings.Cut(entry, "=>")
	if !ok {
		return
	}
	// The LHS's old path can be quoted too — `replace "example.com/foo"
	// v1.0.0 => ../local` is real, `go build`/`go mod edit -fmt`-accepted
	// syntax that normalizes to the unquoted form — so it goes through
	// firstFieldAndRest the same as newPath below, not a raw
	// strings.Fields split (this function's pre-fix form), which kept a
	// quoted oldPath's literal quote characters and made it key this
	// replace under a path resolveEffectiveModules' require-path lookup
	// can never match.
	oldPath, lhsRest := firstFieldAndRest(strings.TrimSpace(lhs))
	oldVersion := firstField(lhsRest)
	newPath := firstField(strings.TrimSpace(rhs))
	if oldPath == "" || newPath == "" {
		return
	}
	e := replaceEntry{
		oldVersion: oldVersion,
		target:     replaceTarget{path: newPath, isLocal: isDirectoryPath(newPath)},
	}
	entries := out[oldPath]
	for i, existing := range entries {
		if existing.oldVersion == oldVersion {
			entries[i] = e
			out[oldPath] = entries
			return
		}
	}
	out[oldPath] = append(entries, e)
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

// filterExcludedRequires drops any require entry whose exact (path,
// version) pair is named by an `exclude` directive elsewhere in the same
// go.mod, matching real go's own build-list behavior: per `go help
// exclude`/the module reference, an excluded version is removed from
// consideration entirely, as if the require naming it didn't exist.
// Verified live (go1.24.4): a go.mod reading
//
//	require example.com/excluded v1.0.0
//	exclude example.com/excluded v1.0.0
//
// makes `go list -m all` print "go: dropping requirement on excluded
// version example.com/excluded v1.0.0" and resolve the build list as if
// that require line were never written at all — confirmed with
// GOPROXY=off and the module's host completely unreachable, so no fetch,
// no proxy query, and no checksum-database lookup is ever attempted for
// it. A `require`/`exclude` pair for the SAME version is exactly what this
// tool needs to recognize, since every other signal it tracks (an
// insteadOf rewrite, a credential helper, go.sum coverage, ...) is keyed
// off the require's own (path, version), and a require that real go drops
// before ever resolving a version can never generate a real sumdb query —
// the identical "cannot leak" reasoning run()'s GOSUMDB=off/vendor-mode/
// malformed-go.mod skips already apply, just scoped to one require entry
// instead of the whole audit.
//
// Also verified live that this holds even when a `replace` directive (both
// a version-specific "replace example.com/excluded v1.0.0 => ../other" and
// a version-agnostic "replace example.com/excluded => ../other") ALSO
// targets the exact same excluded version: `go build` still Fatals with
// "module example.com/excluded provides package ... and is replaced but
// not required" the moment the package is imported — i.e. exclude wins
// outright, dropping the requirement regardless of any replace naming it,
// not just when no replace is present. So this filtering must happen
// before resolveEffectiveModules' own replace resolution (which this
// function's caller, run(), now does), not as a refinement layered on top
// of its output: a require entry excluded this way contributes NEITHER its
// own path NOR its replacement target to the effective module list, since
// real go fetches neither.
//
// Deliberately narrow: only a require whose OWN version is named by an
// exclude for the same path is dropped. A go.mod naming the same module
// path at two different require versions (legal, if unusual, go.mod
// syntax) — where only one of the two happens to match an exclude — only
// has that one entry dropped; the other require line (and whatever
// version it names) is left for the ordinary audit path, since this tool
// doesn't attempt to replicate real go's full minimal-version-selection
// algorithm for picking a next-highest non-excluded version the way
// `cmd/go/internal/modload` does. That can only miss a real suppression
// opportunity for the untouched entry, not introduce a false "no issues
// found".
func filterExcludedRequires(requires []requireEntry, excludes []requireEntry) []requireEntry {
	if len(excludes) == 0 {
		return requires
	}
	excluded := make(map[requireEntry]bool, len(excludes))
	for _, e := range excludes {
		excluded[e] = true
	}
	out := make([]requireEntry, 0, len(requires))
	for _, r := range requires {
		if excluded[r] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// resolveEffectiveModules applies replace directives to a list of required
// modules, producing the paths actually fetched over the network: a
// locally-replaced module is dropped entirely (go reads it off disk, so it
// can never leak to sum.golang.org regardless of GOPRIVATE), and a
// module-replaced one is swapped for its replacement's path (that's the
// path go actually queries the proxy/sumdb for).
func resolveEffectiveModules(modules []requireEntry, replaces map[string][]replaceEntry) []string {
	var out []string
	for _, m := range modules {
		if r, ok := selectReplace(replaces[m.path], m.version); ok {
			if r.isLocal {
				continue
			}
			out = append(out, r.path)
			continue
		}
		out = append(out, m.path)
	}
	return out
}

// selectReplace picks the replaceEntry that applies to a required module at
// the given version, matching the real go toolchain's precedence: a
// version-specific replace (oldVersion equal to the required version) wins
// over a version-agnostic one (oldVersion == "", applying to every version
// of that module) regardless of which is written first in the go.mod —
// verified live against the real go toolchain (`go list -m all` with both
// a specific and a general replace for the same module present: the
// specific one always won, in both file orderings). A go.mod can legally
// carry both at once; a naive map[string]replaceTarget keyed only by path
// (this tool's shape before this function existed) can only ever keep one
// of the two, and — being filled in file order — picked whichever replace
// happened to be written last, not whichever the go tool actually applies.
func selectReplace(entries []replaceEntry, version string) (replaceTarget, bool) {
	var general *replaceTarget
	for i := range entries {
		if entries[i].oldVersion == "" {
			t := entries[i].target
			general = &t
			continue
		}
		if entries[i].oldVersion == version {
			return entries[i].target, true
		}
	}
	if general != nil {
		return *general, true
	}
	return replaceTarget{}, false
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
func goWorkReplaces(gowork string) map[string][]replaceEntry {
	if gowork == "" || gowork == "off" {
		return nil
	}
	data, err := os.ReadFile(gowork)
	if err != nil {
		return nil
	}
	return parseReplaces(data)
}

// goWorkHasUnparseableDirective reports whether an active go.work file
// itself — not the go.mod being audited — contains one of the same
// grammar-level shapes golang.org/x/mod/modfile's real strict parser
// (modfile.ParseWork, what cmd/go actually calls to read a go.work, mirrored
// by modload.ReadWorkFile) Fatals on outright: a stray "/*" block comment, a
// malformed `go`/`toolchain` directive argument, a top-level line whose
// verb isn't one of go.work's own five recognized directives (go, toolchain,
// godebug, use, replace — see goWorkValidTopLevelVerbs), or a malformed
// `replace`/`godebug` directive. Every one of these checks already exists
// for go.mod itself (goModHasBlockComment, goModHasInvalidGoDirective,
// goModHasInvalidToolchainDirective,
// goModHasUnknownDirective/goWorkHasUnknownDirective,
// goModHasInvalidReplaceDirective, goModHasInvalidGodebugDirective) — this
// just re-applies the grammar-generic ones (block comment and the
// go/toolchain directive shape checks don't care which file type they're
// reading) plus the go.work-specific unknown-verb variant, plus replace's
// and godebug's own argument-grammar checks, to gowork's own bytes instead.
//
// The replace and godebug checks are both safe to reuse verbatim, unlike
// goModHasInvalidDirectiveArgCount below: goWorkReplaces' own doc comment
// already established that "go.work supports ... 'replace' directives — the
// replace syntax is identical to go.mod's" (golang.org/x/mod/modfile parses
// both through the exact same parseReplace grammar), so
// goModHasInvalidReplaceDirective's structural checks (arrow position/count,
// new-side directory-path-vs-version shape) apply to a go.work's replace
// lines exactly as written for go.mod's, no go.work-specific variant needed.
// (*WorkFile).add's own "godebug" case in rule.go is byte-for-byte identical
// to (*File).add's — `len(args) != 1 ||
// strings.ContainsAny(args[0], "\"`',")`, then `strings.Cut(args[0], "=")`
// failing when there's no "=" — and ParseWork's own LineBlock switch accepts
// a block-form "godebug (...)" too, exactly like go.mod's, so
// goModHasInvalidGodebugDirective's existing scan (which only ever looks for
// "godebug" lines/blocks in the bytes it's handed, nothing go.mod-specific)
// applies to a go.work's godebug lines unchanged. goModHasInvalidDirectiveArgCount
// is reused the same way for go.work's own "use" directive: (*WorkFile).add's
// "use" case is `if len(args) != 1 { errorf("usage: %s local/dir", verb) }`,
// a single-fixed-argument shape with no content-dependent grammar at all —
// see goModFixedArgCountVerbs' doc comment for why "use" belongs in that same
// map despite never being a valid go.mod verb.
//
// This matters for the identical "cannot leak" reason as every other
// malformed-go.mod skip in main.go's run(): before this fix, none of the
// go.mod-parse-Fatal checks were ever applied to the go.work file itself,
// only to the go.mod being audited — so a go.work with, say, a stray block
// comment (unrelated to any "use"/"replace" directive) left every
// module-aware go subcommand Fataling on go.work before it ever resolved a
// single requirement, while this tool still ran its own audit against the
// go.mod and reported a SUMDB LEAK for a checksum-database query that
// structurally cannot happen. Confirmed live end-to-end against the actual
// goprivaudit binary for all these shapes (block comment, invalid `go`
// directive, an unrecognized verb — e.g. "uses" typo'd for "use" — a
// malformed replace, e.g. "replace example.com/foo => example.com/bar@v1.0.0"
// — and a malformed godebug, e.g. a bare "godebug nokeyvalue" with no "="):
// `go list -m all`/`go build` all Fatal immediately with "errors parsing
// go.work: ...", yet pre-fix goprivaudit still reported "SUMDB LEAK" for a
// real, otherwise-uncovered private-auth-signaled require in the workspace
// member's own go.mod. This is the same "a checklist built for one file
// format doesn't automatically extend to a second file sharing the same
// reference-implementation grammar" gap the block-comment/go/toolchain/
// unknown-verb/replace checks above already closed once each (when they
// were first added to this function) — godebug's own go.mod-side grammar
// check predates this function's own git history, and this function was
// never revisited to pick it up until now, the same drift pattern as
// replace's own addition one run earlier.
//
// Note the mirror-image failure mode this specific fix closes, distinct
// from every other check in this function: adding "godebug" was NOT just
// "another Fatal-shape to recognize" — until goWorkValidTopLevelVerbs itself
// also learned "godebug" is a real, valid go.work verb (a separate, prior
// gap in the SAME verb set this function's unknown-verb check reads), a
// perfectly well-formed `godebug default=go1.24` line in an otherwise-valid
// go.work was itself misclassified as the unknown-verb Fatal shape, making
// this function wrongly report true (unparseable) for a go.work real go
// parses and resolves fine — silently SUPPRESSING a real SUMDB LEAK finding
// rather than producing a false one. Confirmed live end-to-end: the exact
// same go.mod+git-insteadOf fixture reports "SUMDB LEAK" with no go.work (or
// with a go.work missing the godebug line) and wrongly "no issues found"
// once a valid `godebug default=go1.24` line is added, pre-fix — see
// TestRunGodebugDirectiveGoWorkStillLeaks and
// TestRunInvalidGodebugDirectiveGoWorkNoLeak.
//
// gowork == ""/"off" (no active workspace) and an unreadable go.work (e.g.
// stale GOWORK) both report false — the same "missing/unreadable go.work is
// like no workspace" fail-open convention goWorkReplaces/goWorkUseDirs
// already use, since this tool has no better way to tell "not a workspace"
// from "a workspace file some other problem already made irrelevant".
//
// Also calls goModHasInvalidDirectiveArgCount against gowork's own bytes, for
// go.work's "use" directive specifically (run #583's fix) — a bare "use" line
// with no directory argument, or one naming more than one, Fatals real go
// identically to the block-form/malformed-replace/malformed-godebug shapes
// already checked above. An earlier version of this doc comment reasoned
// "use" belonged alongside replace/retract/godebug as a content-shape
// grammar this function deliberately leaves unapproximated — that reasoning
// was simply wrong: (*WorkFile).add's own "use" case
// (`if len(args) != 1 { errorf(...) }`) is byte-for-byte the same
// single-fixed-argument shape as `tool`/`module`/`ignore`, which
// goModHasInvalidDirectiveArgCount already validates exactly this way for
// go.mod. None of require/exclude/tool/module/ignore (the function's other
// fixed-arg-count verbs) are valid go.work verbs, so reusing the function
// verbatim here is safe: a go.work containing any of them would already be
// caught by goWorkHasUnknownDirective above in the same `||` chain, never by
// this call. Live-verified against real go1.24.4, GOPROXY=off: both a bare
// "use" line and a two-argument "use ./a ./b" line Fatal `go list -m all`
// immediately with "usage: use local/dir", while pre-fix goprivaudit kept
// auditing the go.mod being audited and reported a false SUMDB LEAK for an
// otherwise-real, otherwise-uncovered private-auth signal (a git insteadOf
// rewrite) sitting in it — see TestRunInvalidUseDirectiveGoWorkNoLeak.
//
// Also calls goModHasRepeatedSingletonDirective against gowork's own bytes
// with goWorkSingletonVerbs ("go"/"toolchain" — go.work has no "module"
// directive at all): golang.org/x/mod/modfile's (*WorkFile).add carries the
// identical `f.Go != nil`/`f.Toolchain != nil`-shaped singleton guards as
// go.mod's own (*File).add, so a go.work with two individually well-formed
// "go"/"toolchain" lines Fatals with "repeated go statement"/"repeated
// toolchain statement" exactly like its go.mod counterpart — see
// goModHasRepeatedSingletonDirective's own doc comment for the live
// verification (reproduced separately for go.work, not just assumed to
// carry over) and TestRunRepeatedGoDirectiveGoWorkNoLeak for the end-to-end
// regression.
func goWorkHasUnparseableDirective(gowork string) bool {
	if gowork == "" || gowork == "off" {
		return false
	}
	data, err := os.ReadFile(gowork)
	if err != nil {
		return false
	}
	return goModHasBlockComment(data) ||
		goModHasInvalidGoDirective(data) ||
		goModHasInvalidToolchainDirective(data) ||
		goWorkHasUnknownDirective(data) ||
		goModHasInvalidReplaceDirective(data) ||
		goModHasInvalidGodebugDirective(data) ||
		goModHasInvalidDirectiveArgCount(data) ||
		goModHasRepeatedSingletonDirective(data, goWorkSingletonVerbs)
}

// mergeReplaces overlays a workspace's go.work replace directives on top of
// a module's own go.mod replaces. Per `go help work`: "If a module is
// replaced in both the workspace's go.work file and in the workspace
// module's go.mod file, the replacement in the go.work file is used" — but
// that describes selectReplace's existing specific-beats-general, first-
// specific-match-wins precedence *per required version*, not a blanket
// per-path override. Verified live against the real go toolchain: a
// go.work replace that's version-specific for a version other than the one
// actually required leaves an unrelated go.mod-level replace (general or a
// different specific version) fully in effect — `go list -m all` still
// resolves through the go.mod entry. A prior version of this function
// (`merged[k] = v`) discarded every go.mod-level entry for a path the
// moment go.work carried *any* entry for it, which silently dropped a
// go.mod's own replace of a public-looking path to a private host/fork
// whenever go.work also replaced a different version of the same path —
// confirmed live to produce a false "no issues found" on a real
// SUMDB LEAK (the private replace target reverted to the raw, unreplaced
// require path, which no longer matched the private-auth signal). Fixed by
// concatenating go.work's entries before go.mod's for each path: go.work's
// version-specific entries still win their own version (selectReplace
// returns on the first oldVersion match), a go.work general entry still
// overrides outright — a go.mod general entry for the same path is dropped
// (selectReplace's `general` var is last-write-wins, so an undropped
// go.mod general scanned after go.work's would silently win instead), and
// a go.mod entry irrelevant to go.work (a different specific version, or
// any entry for a path go.work doesn't touch at all) survives untouched
// instead of being discarded wholesale.
func mergeReplaces(base, overlay map[string][]replaceEntry) map[string][]replaceEntry {
	if len(overlay) == 0 {
		return base
	}
	generalInOverlay := map[string]bool{}
	for path, entries := range overlay {
		for _, e := range entries {
			if e.oldVersion == "" {
				generalInOverlay[path] = true
			}
		}
	}
	merged := make(map[string][]replaceEntry, len(base)+len(overlay))
	for path, entries := range base {
		if generalInOverlay[path] {
			continue
		}
		merged[path] = entries
	}
	for path, entries := range overlay {
		merged[path] = append(append([]replaceEntry{}, entries...), merged[path]...)
	}
	return merged
}

// goWorkUseDirs parses a go.work file's "use" directives — both the
// single-line "use ./dir" form and the block "use (\n\t./dir\n)" form,
// identical shape/quoting rules to a require/tool directive line, so it
// reuses the same stripComment/cutKeyword/firstField helpers those parsers
// do — and returns each listed member module's directory resolved to an
// absolute, cleaned path. Per `go help work`, a "use" path is "resolved
// relative to the directory containing the go.work file", i.e. relative to
// filepath.Dir(goworkAbs), not to this process's own working directory.
// goworkAbs must already be an absolute path (moduleOutsideWorkspace's
// only caller resolves it before calling in). A go.work that can't be read
// yields no directories, the same "missing/unreadable go.work is like no
// workspace" convention goWorkReplaces already uses.
func goWorkUseDirs(goworkAbs string) []string {
	data, err := os.ReadFile(goworkAbs)
	if err != nil {
		return nil
	}
	workDir := filepath.Dir(goworkAbs)
	var dirs []string
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
			if p := firstField(trimmed); p != "" {
				dirs = append(dirs, resolveLocalPath(workDir, p))
			}
			continue
		}
		if rest, ok := cutKeyword(trimmed, "use"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "(" {
				inBlock = true
				continue
			}
			if p := firstField(rest); p != "" {
				dirs = append(dirs, resolveLocalPath(workDir, p))
			}
		}
	}
	return dirs
}

// resolveLocalPath resolves a go.mod/go.work-relative local path (a
// replace target or a "use" directory, both documented to resolve relative
// to the file that names them, not to this process's cwd) against baseDir,
// returning an absolute, cleaned path. An already-absolute path (a real,
// if unusual, thing to write for either directive) is cleaned as-is,
// mirroring filepath.Join's own documented refusal to prefix an absolute
// second argument with the first.
func resolveLocalPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

// goWorkLocalReplaceTargets collects every local-directory replace target
// reachable from a go.work workspace without following any require chain:
// go.work's own replace directives (resolved relative to its own
// directory) plus each `use`d member module's own go.mod replace
// directives (resolved relative to that member's own directory, per
// go.mod's normal replace-path resolution rule — verified live the same
// way isDirectoryPath's doc comment already did for a go.mod-level
// replace). This is exactly the "...or their selected dependencies" half
// of the real go error moduleOutsideWorkspace's doc comment quotes: a
// directory that isn't itself `use`d can still be part of the workspace's
// build graph if some `use`d member's go.mod replaces a require with it.
//
// Deliberately stops at one hop: it doesn't recurse into a replacement
// target's own go.mod looking for a *second* local replace that reaches
// moduleDir transitively. That chain is real but far rarer than a single
// member replacing a public path with a local sibling (this function's
// main target), and detecting it fully would mean re-implementing a
// chunk of modload's own local-replace-chain resolution — out of scope
// here the same way hasconfig: resolution was ruled out for includeIf
// (see includeIfMatches' doc comment for that precedent). Missing this
// deeper chain can only make moduleOutsideWorkspace over-report exclusion
// for that one narrow shape, not under-report it elsewhere.
func goWorkLocalReplaceTargets(goworkAbs string, useDirs []string) []string {
	var out []string
	collect := func(data []byte, baseDir string) {
		for _, entries := range parseReplaces(data) {
			for _, e := range entries {
				if e.target.isLocal {
					out = append(out, resolveLocalPath(baseDir, e.target.path))
				}
			}
		}
	}
	if data, err := os.ReadFile(goworkAbs); err == nil {
		collect(data, filepath.Dir(goworkAbs))
	}
	for _, d := range useDirs {
		if data, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil {
			collect(data, d)
		}
	}
	return out
}

// moduleOutsideWorkspace reports whether, with an active go.work workspace
// (gowork not "" or "off"), moduleDir would be excluded from every
// standard package-pattern-based build run inside it: `go build`, `go
// build .`, `go run .`, `go list .`/`go list ./...`, `go vet ./...`, and
// `go test ./...` all Fatal immediately with "current directory is
// contained in a module that is not one of the workspace modules listed
// in go.work" (or, for a "./..." pattern specifically, "pattern ./...:
// directory prefix . does not contain modules listed in go.work or their
// selected dependencies") the moment moduleDir is neither `use`d directly
// nor reachable as a local replace target — verified live (2026-09) with a
// go.work listing only a sibling module, none of moduleDir's own
// requires ever resolved (no git/network activity at all): `go mod tidy`
// and bare `go mod download` both silently matched zero packages, and
// every package-pattern command above Fataled before resolving a single
// module. Since every one of these is the ordinary way a private-auth
// signal left uncovered by GOPRIVATE/GONOSUMDB would actually reach
// sum.golang.org, none of them being reachable at all means that query
// structurally cannot happen for moduleDir's own requires in this
// state — the same "cannot leak" reasoning run() already applies to
// GOSUMDB=off, vendor mode, and a goflags-rejecting GOFLAGS, just reached
// because the workspace itself refuses to consider moduleDir's go.mod at
// all rather than because a check downstream of that was disabled.
//
// This is a real, easy-to-hit misconfiguration, not a contrived one: GOWORK
// auto-discovery (see the moduleDir/goEnv comment in main.go) walks
// upward from moduleDir through every parent directory looking for a
// go.work file — a monorepo workspace file that simply hasn't been
// updated with a `use ./newmodule` entry for a newly added module (or,
// more subtly, an unrelated go.work leftover from a different project
// sitting in a shared parent directory) silently puts every module under
// it into exactly this state.
//
// Only ever narrows a false positive, never introduces a false negative:
// a directory this reports true for has been live-confirmed to leak
// nothing via any standard build command, and goWorkLocalReplaceTargets'
// one-hop check (see its own doc comment for the narrow chain it doesn't
// follow) means the one known gap in that confirmation can only make this
// function say "excluded" too often, not too rarely.
func moduleOutsideWorkspace(gowork, moduleDir string) bool {
	if gowork == "" || gowork == "off" {
		return false
	}
	goworkAbs, err := filepath.Abs(gowork)
	if err != nil {
		return false
	}
	useDirs := goWorkUseDirs(goworkAbs)
	if len(useDirs) == 0 {
		// No (parseable) "use" directive at all: this isn't the shape of
		// workspace the live-verified rejection above was confirmed
		// against, so fail open rather than guess, the same convention
		// every other best-effort go.work reader in this file already
		// follows for an unreadable/stale GOWORK.
		return false
	}
	moduleAbs, err := filepath.Abs(moduleDir)
	if err != nil {
		return false
	}
	moduleAbs = filepath.Clean(moduleAbs)
	for _, d := range useDirs {
		if d == moduleAbs {
			return false
		}
	}
	for _, d := range goWorkLocalReplaceTargets(goworkAbs, useDirs) {
		if d == moduleAbs {
			return false
		}
	}
	return true
}
