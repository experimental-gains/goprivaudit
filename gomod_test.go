package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseRequires(t *testing.T) {
	src := `module example.com/foo

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0 // indirect
	example.com/myorg/private v0.0.0-20230101000000-abcdef123456
)

require golang.org/x/sync v0.5.0

require (
)
`
	got := parseRequires([]byte(src))
	want := []requireEntry{
		{path: "github.com/pkg/errors", version: "v0.9.1"},
		{path: "github.com/stretchr/testify", version: "v1.8.0"},
		{path: "example.com/myorg/private", version: "v0.0.0-20230101000000-abcdef123456"},
		{path: "golang.org/x/sync", version: "v0.5.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseRequiresEmpty(t *testing.T) {
	if got := parseRequires([]byte("module example.com/foo\n\ngo 1.21\n")); got != nil {
		t.Errorf("expected nil for a go.mod with no requires, got %v", got)
	}
}

func TestParseRequiresSingleLineOnly(t *testing.T) {
	got := parseRequires([]byte("module example.com/foo\n\nrequire example.com/bar v1.0.0\n"))
	want := []requireEntry{{path: "example.com/bar", version: "v1.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseRequiresBlockNoSpaceBeforeParen(t *testing.T) {
	// go.mod's real lexer (golang.org/x/mod/modfile) doesn't require a
	// space between the "require" keyword and "(" — gofmt just always
	// produces one. Confirmed against `go mod edit -json` on a hand-
	// written go.mod using "require(".
	got := parseRequires([]byte("module example.com/foo\n\nrequire(\n\tgithub.com/pkg/errors v0.9.1\n)\n"))
	want := []requireEntry{{path: "github.com/pkg/errors", version: "v0.9.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseRequiresBlockTabBeforeParen(t *testing.T) {
	got := parseRequires([]byte("module example.com/foo\n\nrequire\t(\n\tgithub.com/pkg/errors v0.9.1\n)\n"))
	want := []requireEntry{{path: "github.com/pkg/errors", version: "v0.9.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseRequiresCommentOnlyLineIgnored covers a require-block line that
// is entirely a "//" comment (e.g. a temporarily commented-out dependency)
// — stripComment must reduce it to "", not leave the "//" marker itself to
// be picked up by firstField as if it were a module path. Deliberately no
// leading whitespace before "//" (unlike gofmt's usual indentation): this
// hand-rolled parser doesn't require gofmt'd input, and stripComment's
// strings.Index(line, "//") boundary is only actually exercised at i==0
// when "//" is the very first thing on the line.
func TestParseRequiresCommentOnlyLineIgnored(t *testing.T) {
	got := parseRequires([]byte("module example.com/foo\n\nrequire (\n// github.com/old/dep v1.0.0\n\tgithub.com/real/dep v1.2.3\n)\n"))
	want := []requireEntry{{path: "github.com/real/dep", version: "v1.2.3"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseRequiresQuotedPath is the regression case for a real bug:
// parseRequireLine used to split a require line with strings.Fields
// directly, never unquoting anything, even though go.mod's real lexer
// (golang.org/x/mod/modfile) allows a require path to be written as a
// double-quoted Go string literal purely as a styling choice — no space
// or other reason to quote it required. Confirmed live: `go build`/`go
// mod edit -fmt` both normalize `require "github.com/org/repo" v1.0.0`
// straight to the unquoted `require github.com/org/repo v1.0.0`,
// resolving the real module. Before this fix, parseRequireLine kept the
// literal quote characters in the path
// (`"github.com/org/repo"`, not `github.com/org/repo`), so it could never
// match that module's real private-auth signal or GOPRIVATE/GONOSUMDB
// coverage — silently dropping a real require entry (and any SUMDB LEAK
// on it) out of the audit entirely.
func TestParseRequiresQuotedPath(t *testing.T) {
	got := parseRequires([]byte("module example.com/foo\n\nrequire \"github.com/org/repo\" v1.0.0\n"))
	want := []requireEntry{{path: "github.com/org/repo", version: "v1.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseRequiresQuotedPathWithHexEscape covers the same gap as
// TestParseRequiresQuotedPath one level deeper: even once a require path
// goes through unquoting at all, it must decode real Go string-literal
// escapes, not just copy the byte after a backslash literally. Confirmed
// live: a go.mod with `require "github\x2ecom/pkg/errors" v0.9.1` (an
// unusual but real, valid quoting of a completely ordinary dependency) is
// accepted by `go build`/`go mod edit -fmt`, both of which normalize it
// to the plain `require github.com/pkg/errors v0.9.1` — real go decodes
// \x2e as the single byte ".". Before this fix, leadingQuotedString's
// byte-literal unescaper decoded the same token to
// "githubx2ecom/pkg/errors" (keeping 'x' and the literal digits "2e"), a
// path that can never match the module's real private-auth signal or
// GOPRIVATE/GONOSUMDB coverage.
func TestParseRequiresQuotedPathWithHexEscape(t *testing.T) {
	got := parseRequires([]byte(`module example.com/foo` + "\n\n" + `require "github\x2ecom/pkg/errors" v0.9.1` + "\n"))
	want := []requireEntry{{path: "github.com/pkg/errors", version: "v0.9.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestLeadingQuotedStringEmptyBacktick covers a degenerate but valid
// backtick-quoted empty string (two backticks in a row) -- the closing
// backtick is the very next byte after the opening one.
func TestLeadingQuotedStringEmptyBacktick(t *testing.T) {
	got, _, ok := leadingQuotedString("``")
	if !ok || got != "" {
		t.Errorf("leadingQuotedString(\"``\") = %q, %v; want \"\", true", got, ok)
	}
}

// TestLeadingQuotedStringUnterminatedDoubleQuote covers a double-quoted
// string with no closing quote at all — must fail cleanly (ok=false), not
// index past the end of the string.
func TestLeadingQuotedStringUnterminatedDoubleQuote(t *testing.T) {
	got, _, ok := leadingQuotedString(`"unterminated`)
	if ok {
		t.Errorf("leadingQuotedString(%q) = %q, true; want ok=false", `"unterminated`, got)
	}
}

// TestLeadingQuotedStringTrailingBackslashUnterminated covers a
// double-quoted string whose last byte is a lone, unescaped backslash (no
// character left to escape) — must not index past the end of the string.
func TestLeadingQuotedStringTrailingBackslashUnterminated(t *testing.T) {
	got, _, ok := leadingQuotedString(`"abc\`)
	if ok {
		t.Errorf("leadingQuotedString(%q) = %q, true; want ok=false", `"abc\`, got)
	}
}

func TestParseReplacesLocalAndModuleSingleLine(t *testing.T) {
	src := `module example.com/foo

require example.com/bar v1.0.0
require example.com/fork-me v1.0.0

replace example.com/bar => ../bar
replace example.com/fork-me => example.com/myorg/fork-me v1.2.3
`
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar":     {{target: replaceTarget{path: "../bar", isLocal: true}}},
		"example.com/fork-me": {{target: replaceTarget{path: "example.com/myorg/fork-me", isLocal: false}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBareDotDot(t *testing.T) {
	// Verified against the real go toolchain: `replace foo => ..` (no
	// trailing slash) is a valid go.mod construct — `go build` accepts it
	// and `go list -m all` resolves it straight off disk, never touching
	// a proxy — but a naive HasPrefix("./"/"../") check misses this bare
	// form (golang.org/x/mod/modfile.IsDirectoryPath treats "." and ".."
	// as directory paths too, not just "./" and "../"), misclassifying a
	// purely local replace as a network-fetched module path.
	src := "module example.com/foo\n\nreplace example.com/bar => ..\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "..", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBareDot(t *testing.T) {
	src := "module example.com/foo\n\nreplace example.com/bar => .\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: ".", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBlock(t *testing.T) {
	src := `module example.com/foo

replace (
	example.com/bar => ./local/bar
	example.com/baz => example.com/myorg/baz v0.1.0
)
`
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "./local/bar", isLocal: true}}},
		"example.com/baz": {{target: replaceTarget{path: "example.com/myorg/baz", isLocal: false}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBlockNoSpaceBeforeParen(t *testing.T) {
	src := "module example.com/foo\n\nreplace(\n\texample.com/bar => ./local/bar\n)\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "./local/bar", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesQuotedLocalPathWithSpace(t *testing.T) {
	// `go mod edit` writes a local replace path this way when it contains
	// a space, and `go build` accepts it — verified against the real go
	// toolchain (module.CheckPath doesn't apply to filesystem replace
	// targets). A naive whitespace split truncates at the space and
	// leaves a stray leading quote, misclassifying the target as a
	// module path instead of a local one.
	src := "module example.com/foo\n\nreplace example.com/bar => \"../my mod\"\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "../my mod", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBacktickQuotedLocalPath(t *testing.T) {
	src := "module example.com/foo\n\nreplace example.com/bar => `../my mod`\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "../my mod", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesQuotedLocalPathWithDoubleSlash(t *testing.T) {
	// A doubled path separator inside a quoted local replace path is
	// unusual but real go.mod syntax `go build` accepts and resolves
	// correctly (verified live against the actual go toolchain). Before
	// stripComment was made quote-aware, its naive strings.Index(line,
	// "//") found the "//" inside the quotes and truncated the line
	// there, leaving a stray leading quote in the parsed path and
	// causing the "../" local-path prefix check to miss — misclassifying
	// a purely local, never-network-fetched replace as a module to check
	// against GOPRIVATE.
	src := "module example.com/foo\n\nreplace example.com/bar => \"../vendor//bar\"\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "../vendor//bar", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesQuotedLocalPathWithEscapedQuoteAndComment(t *testing.T) {
	// A backslash-escaped quote inside a double-quoted local replace path
	// (valid go.mod string-literal syntax, same rules leadingQuotedString
	// already unescapes) followed by a trailing "// ..." comment.
	// Exercises stripComment's backslash-skip branch: it must consume the
	// escaped '"' as string content rather than mistaking it for the
	// close quote, so scanning continues correctly and the real comment
	// marker after the actual close quote is still found and stripped.
	src := "module example.com/foo\n\nreplace example.com/bar => \"../a\\\"b\" // comment\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: `../a"b`, isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseReplacesQuotedOldPath is the regression case for addReplace's
// half of the same quoted-path gap TestParseRequiresQuotedPath covers for
// require: the LHS "old path" of a replace directive can be quoted too —
// confirmed live, `go build`/`go mod edit -fmt` both normalize `replace
// "example.com/foo" v1.0.0 => ../local` straight to the unquoted `replace
// example.com/foo v1.0.0 => ../local`. Before this fix, addReplace's raw
// strings.Fields split on the LHS kept the literal quote characters in
// oldPath (`"example.com/foo"`, not `example.com/foo`), so
// resolveEffectiveModules' require-path lookup into this map could never
// find the replace for the module's real path, silently leaving the
// original (would-be-replaced) path checked against GOPRIVATE/GONOSUMDB
// in its place instead.
func TestParseReplacesQuotedOldPath(t *testing.T) {
	src := "module example.com/foo\n\nreplace \"example.com/foo\" v1.0.0 => ../local\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/foo": {{oldVersion: "v1.0.0", target: replaceTarget{path: "../local", isLocal: true}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestGoModHasBlockComment covers goModHasBlockComment's live-verified
// trigger condition: a bare "/*" outside any quoted string, on any line of
// the file, is exactly what makes golang.org/x/mod/modfile's real lexer
// Fatal every module-aware go subcommand — confirmed against real `go
// build` (see TestRunBlockCommentGoModNoLeak in main_test.go for the
// end-to-end regression). A "/*" appearing inside a double- or
// backtick-quoted string (a legal go.mod string value, e.g. a local replace
// path) is not a lexer error at all — verified live that the equivalent
// go.mod parses and builds fine — so it must not be flagged either.
func TestGoModHasBlockComment(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"no comment at all", "module example.com/foo\n\ngo 1.24\n", false},
		{"ordinary line comment", "module example.com/foo\n\n// just a line comment\n", false},
		{"stray block comment on its own line", "module example.com/foo\n\n/* oops */\n", true},
		{"block comment marker with no closing */", "module example.com/foo\n\n/* oops\n", true},
		{"block comment attached to a directive, no space", "module example.com/foo\n\nrequire/*x*/ example.com/bar v1.0.0\n", true},
		{"slash-star inside a double-quoted replace target", "module example.com/foo\n\nreplace example.com/bar => \"../weird/*/dir\"\n", false},
		{"slash-star inside a backtick-quoted replace target", "module example.com/foo\n\nreplace example.com/bar => `../weird/*/dir`\n", false},
		{"line comment starting before an unrelated slash-star later in the line", "module example.com/foo\n\n// see /* this */ for context\n", false},
	}
	for _, c := range cases {
		if got := goModHasBlockComment([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasBlockComment(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoModHasInvalidGoDirective covers goModHasInvalidGoDirective's
// live-verified trigger condition: a `go` directive line whose argument
// doesn't match golang.org/x/mod/modfile's own strict GoVersionRE, or that
// doesn't carry exactly one argument, is exactly what makes the real go
// command's strict go.mod parser (modfile.Parse, what cmd/go actually calls)
// Fatal every module-aware go subcommand before resolving a single module —
// confirmed against real `go list -m all` (see
// TestRunInvalidGoDirectiveGoModNoLeak in main_test.go for the end-to-end
// regression). A go.mod with no `go` directive at all is NOT one of these
// cases — verified live, real go parses and resolves it normally — matching
// parseGoVersion's own "no directive" convention.
func TestGoModHasInvalidGoDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"no go directive at all", "module example.com/foo\n\nrequire example.com/bar v1.0.0\n", false},
		{"plain major.minor", "module example.com/foo\n\ngo 1.14\n", false},
		{"major.minor.patch", "module example.com/foo\n\ngo 1.24.4\n", false},
		{"prerelease suffix directly appended", "module example.com/foo\n\ngo 1.21rc1\n", false},
		{"trailing non-digit garbage", "module example.com/foo\n\ngo 1.9x\n", true},
		{"single component, no dot", "module example.com/foo\n\ngo 1\n", true},
		{"leading zero in minor", "module example.com/foo\n\ngo 1.05\n", true},
		{"bare go directive, no argument", "module example.com/foo\n\ngo\n\nrequire example.com/bar v1.0.0\n", true},
		{"extra argument after the version", "module example.com/foo\n\ngo 1.14 extra\n", true},
		{"quoted version string", "module example.com/foo\n\ngo \"1.24.4\"\n", true},
		{"mistaken go (...) block attempt", "module example.com/foo\n\ngo (\n\t1.14\n)\n", true},
		{"godebug directive is not mistaken for go", "module example.com/foo\n\ngo 1.24.4\n\ngodebug (\n\ttlsmlkem=0\n)\n", false},
	}
	for _, c := range cases {
		if got := goModHasInvalidGoDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasInvalidGoDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoModHasInvalidToolchainDirective covers
// goModHasInvalidToolchainDirective's live-verified trigger condition: a
// `toolchain` directive line whose argument doesn't match
// golang.org/x/mod/modfile's own strict ToolchainRE, or that doesn't carry
// exactly one argument, is exactly what makes the real go command's strict
// go.mod parser (modfile.Parse) Fatal every module-aware go subcommand
// before resolving a single module — confirmed against real `go list -m
// all` (see TestRunInvalidToolchainDirectiveGoModNoLeak in main_test.go for
// the end-to-end regression). A go.mod with no `toolchain` directive at all
// is NOT one of these cases — verified live, real go parses and resolves it
// normally.
func TestGoModHasInvalidToolchainDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"no toolchain directive at all", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0\n", false},
		{"plain go1.x.y toolchain", "module example.com/foo\n\ngo 1.24\n\ntoolchain go1.24.4\n", false},
		{"go1 with no further version", "module example.com/foo\n\ngo 1.24\n\ntoolchain go1\n", false},
		{"prerelease suffix", "module example.com/foo\n\ngo 1.24\n\ntoolchain go1.21rc1\n", false},
		{"default keyword", "module example.com/foo\n\ngo 1.24\n\ntoolchain default\n", false},
		{"missing go prefix", "module example.com/foo\n\ngo 1.24\n\ntoolchain 1.24.4\n", true},
		{"bare toolchain directive, no argument", "module example.com/foo\n\ngo 1.24\n\ntoolchain\n\nrequire example.com/bar v1.0.0\n", true},
		{"extra argument after the version", "module example.com/foo\n\ngo 1.24\n\ntoolchain go1.24.4 extra\n", true},
		{"quoted toolchain name", "module example.com/foo\n\ngo 1.24\n\ntoolchain \"go1.24.4\"\n", true},
		{"godebug directive is not mistaken for toolchain", "module example.com/foo\n\ngo 1.24.4\n\ngodebug (\n\ttlsmlkem=0\n)\n", false},
	}
	for _, c := range cases {
		if got := goModHasInvalidToolchainDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasInvalidToolchainDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoModHasUnknownDirective covers goModHasUnknownDirective's
// live-verified trigger condition: a top-level line whose first token isn't
// one of the real parser's recognized go.mod directive keywords (module,
// go, toolchain, require, exclude, replace, retract, tool, ignore,
// godebug) is exactly what makes golang.org/x/mod/modfile's real parser
// Fatal every module-aware go subcommand with "unknown directive: %s"
// before resolving a single module — confirmed against real `go list -m
// all` (see TestRunUnknownDirectiveGoModNoLeak in main_test.go for the
// end-to-end regression). Every recognized verb, including ones this file
// has no dedicated parser for at all (retract, ignore, godebug), must NOT
// be flagged — nor may a line legitimately sitting inside an existing
// block, whose own first token can be anything (a module path, a version
// interval) without being a directive verb at all.
func TestGoModHasUnknownDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain valid go.mod", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0\n", false},
		{"pluralized require typo", "module example.com/foo\n\ngo 1.24\n\nrequires example.com/bar v1.0.0\n", true},
		{"uppercase GO instead of go", "module example.com/foo\n\nGO 1.24\n", true},
		{"misspelled replase", "module example.com/foo\n\ngo 1.24\n\nreplase example.com/bar => ../local\n", true},
		{"outright garbage line", "module example.com/foo\n\ngo 1.24\n\nthis is not a directive\n", true},
		{"every real directive keyword accepted", "module example.com/foo\n\ngo 1.24\n\ntoolchain go1.24.4\n\ngodebug tlsmlkem=0\n\nrequire example.com/bar v1.0.0\n\nexclude example.com/bar v0.9.0\n\nreplace example.com/bar => ../local\n\nretract v1.0.0\n\ntool example.com/bar/cmd/x\n\nignore ./testdata\n", false},
		{"require block entries aren't verb-checked", "module example.com/foo\n\ngo 1.24\n\nrequire (\n\texample.com/bar v1.0.0\n\texample.com/baz v2.0.0\n)\n", false},
		{"retract block entries aren't verb-checked", "module example.com/foo\n\ngo 1.24\n\nretract (\n\tv1.0.0\n\t[v1.1.0, v1.2.0]\n)\n", false},
		{"no-space block-open form", "module example.com/foo\n\ngo 1.24\n\nrequire(\n\texample.com/bar v1.0.0\n)\n", false},
		{"unknown verb after a valid block closes", "module example.com/foo\n\ngo 1.24\n\nrequire (\n\texample.com/bar v1.0.0\n)\n\nrequires example.com/baz v1.0.0\n", true},
	}
	for _, c := range cases {
		if got := goModHasUnknownDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasUnknownDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoWorkHasUnknownDirective covers goWorkHasUnknownDirective's own,
// narrower valid-verb set (go, toolchain, use, replace) — distinct from
// goModHasUnknownDirective's go.mod set, confirmed live: a go.work
// containing a `require` line (perfectly valid in a go.mod) Fatals with
// "unknown directive: require" parsing go.work (see
// TestRunUnknownDirectiveGoWorkNoLeak in main_test.go for the end-to-end
// regression), while "use" — invalid in a go.mod — is go.work's own real
// directive.
func TestGoWorkHasUnknownDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain valid go.work", "go 1.24\n\nuse ./app\n", false},
		{"use block form", "go 1.24\n\nuse (\n\t./app\n\t./other\n)\n", false},
		{"replace directive", "go 1.24\n\nuse ./app\n\nreplace example.com/bar => ../local\n", false},
		{"toolchain directive", "go 1.24\n\ntoolchain go1.24.4\n\nuse ./app\n", false},
		{"require is a go.mod-only verb, unknown in go.work", "go 1.24\n\nuse ./app\n\nrequire example.com/bar v1.0.0\n", true},
		{"module is a go.mod-only verb, unknown in go.work", "module example.com/app\n\ngo 1.24\n", true},
		{"typo'd uses instead of use", "go 1.24\n\nuses ./app\n", true},
		{"no-space block-open form", "go 1.24\n\nuse(\n\t./app\n)\n", false},
	}
	for _, c := range cases {
		if got := goWorkHasUnknownDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goWorkHasUnknownDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoWorkHasUnparseableDirective covers goWorkHasUnparseableDirective's
// own gowork-path handling (empty/"off"/unreadable all fail open to false,
// same convention as goWorkReplaces), on top of the shape checks already
// covered individually by TestGoModHasBlockComment/
// TestGoModHasInvalidGoDirective/TestGoModHasInvalidToolchainDirective/
// TestGoWorkHasUnknownDirective above.
func TestGoWorkHasUnparseableDirective(t *testing.T) {
	dir := t.TempDir()
	if got := goWorkHasUnparseableDirective(""); got {
		t.Errorf("empty gowork (no workspace) = %v, want false", got)
	}
	if got := goWorkHasUnparseableDirective("off"); got {
		t.Errorf(`gowork="off" = %v, want false`, got)
	}
	if got := goWorkHasUnparseableDirective(filepath.Join(dir, "does-not-exist.work")); got {
		t.Errorf("unreadable gowork = %v, want false (fail open, matching goWorkReplaces)", got)
	}

	valid := writeFile(t, dir, "valid.work", "go 1.24\n\nuse ./app\n")
	if got := goWorkHasUnparseableDirective(valid); got {
		t.Errorf("valid go.work = %v, want false", got)
	}

	blockComment := writeFile(t, dir, "blockcomment.work", "go 1.24\n\nuse ./app\n\n/* stray */\n")
	if got := goWorkHasUnparseableDirective(blockComment); !got {
		t.Errorf("go.work with a stray block comment = %v, want true", got)
	}

	invalidGo := writeFile(t, dir, "invalidgo.work", "go 1.9x\n\nuse ./app\n")
	if got := goWorkHasUnparseableDirective(invalidGo); !got {
		t.Errorf("go.work with a malformed go directive = %v, want true", got)
	}

	invalidToolchain := writeFile(t, dir, "invalidtoolchain.work", "go 1.24\n\ntoolchain 1.24.4\n\nuse ./app\n")
	if got := goWorkHasUnparseableDirective(invalidToolchain); !got {
		t.Errorf("go.work with a malformed toolchain directive = %v, want true", got)
	}

	unknownVerb := writeFile(t, dir, "unknownverb.work", "go 1.24\n\nuses ./app\n")
	if got := goWorkHasUnparseableDirective(unknownVerb); !got {
		t.Errorf("go.work with an unrecognized verb = %v, want true", got)
	}
}

// TestGoModHasInvalidDirectiveArgCount covers
// goModHasInvalidDirectiveArgCount's live-verified trigger condition: a
// require/exclude/tool directive line (single-line or block-entry form)
// carrying the wrong number of arguments is exactly what makes
// golang.org/x/mod/modfile's real parser Fatal every module-aware go
// subcommand before resolving a single module — confirmed against real `go
// list -m all` (see TestRunInvalidDirectiveArgCountGoModNoLeak in
// main_test.go for the end-to-end regression). A valid go.mod with none of
// these verbs malformed must NOT be flagged, including one using every
// verb this function doesn't check at all (replace/retract/godebug/module).
func TestGoModHasInvalidDirectiveArgCount(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain valid go.mod", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0\n", false},
		{"require missing version", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar\n", true},
		{"bare require, no arguments at all", "module example.com/foo\n\ngo 1.24\n\nrequire\n", true},
		{"require with stray extra token", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0 extra\n", true},
		{"quoted require path with embedded space counts as one argument", "module example.com/foo\n\ngo 1.24\n\nrequire \"example.com/spacey bar\" v1.0.0\n", false},
		{"exclude with stray extra token", "module example.com/foo\n\ngo 1.24\n\nexclude example.com/bar v1.0.0 extra\n", true},
		{"exclude missing version", "module example.com/foo\n\ngo 1.24\n\nexclude example.com/bar\n", true},
		{"tool with extra package", "module example.com/foo\n\ngo 1.24\n\ntool example.com/bar/cmd/x extra\n", true},
		{"bare tool, no argument", "module example.com/foo\n\ngo 1.24\n\ntool\n", true},
		{"valid tool directive", "module example.com/foo\n\ngo 1.24\n\ntool example.com/bar/cmd/x\n", false},
		{"require block entry with stray extra token", "module example.com/foo\n\ngo 1.24\n\nrequire (\n\texample.com/bar v1.0.0 extra\n)\n", true},
		{"require block entry with missing version", "module example.com/foo\n\ngo 1.24\n\nrequire (\n\texample.com/bar\n)\n", true},
		{"valid require block", "module example.com/foo\n\ngo 1.24\n\nrequire (\n\texample.com/bar v1.0.0\n\texample.com/baz v2.0.0\n)\n", false},
		{"no-space block-open form still validated", "module example.com/foo\n\ngo 1.24\n\nrequire(\n\texample.com/bar v1.0.0 extra\n)\n", true},
		{"paren glued directly onto a single-line require", "module example.com/foo\n\ngo 1.24\n\nrequire(example.com/bar v1.0.0)\n", true},
		{"replace/retract/godebug/module are out of scope, even malformed", "module example.com/foo\n\ngo 1.24\n\nreplace example.com/bar\n\nretract\n\ngodebug\n", false},
	}
	for _, c := range cases {
		if got := goModHasInvalidDirectiveArgCount([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasInvalidDirectiveArgCount(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoModHasInvalidGodebugDirective covers
// goModHasInvalidGodebugDirective's live-verified trigger condition: a
// `godebug` directive line (single-line or block-entry form) whose argument
// isn't a single "key=value" token free of `"`/backtick/`'`/`,` is exactly
// what makes the real go command's strict go.mod parser (modfile.Parse)
// Fatal every module-aware go subcommand before resolving a single module —
// confirmed against real `go list -m all` (see
// TestRunInvalidGodebugDirectiveGoModNoLeak in main_test.go for the
// end-to-end regression). A go.mod with no `godebug` directive at all is NOT
// one of these cases.
func TestGoModHasInvalidGodebugDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"no godebug directive at all", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0\n", false},
		{"valid single-line godebug", "module example.com/foo\n\ngo 1.24\n\ngodebug httplaxcontentlength=1\n", false},
		{"no equals sign at all", "module example.com/foo\n\ngo 1.24\n\ngodebug nokeyvalue\n", true},
		{"bare godebug, no argument", "module example.com/foo\n\ngo 1.24\n\ngodebug\n\nrequire example.com/bar v1.0.0\n", true},
		{"embedded comma", "module example.com/foo\n\ngo 1.24\n\ngodebug foo=bar,baz\n", true},
		{"embedded double quote", "module example.com/foo\n\ngo 1.24\n\ngodebug foo=\"bar\"\n", true},
		{"extra argument after key=value", "module example.com/foo\n\ngo 1.24\n\ngodebug foo=bar extra\n", true},
		{"valid godebug block", "module example.com/foo\n\ngo 1.24\n\ngodebug (\n\tfoo=bar\n\tbaz=qux\n)\n", false},
		{"godebug block entry with no equals", "module example.com/foo\n\ngo 1.24\n\ngodebug (\n\tfoo=bar\n\tnokeyvalue\n)\n", true},
	}
	for _, c := range cases {
		if got := goModHasInvalidGodebugDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasInvalidGodebugDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestGoModHasInvalidRetractDirective covers
// goModHasInvalidRetractDirective's live-verified trigger condition: a
// `retract` directive line (single-line or block-entry form) whose argument
// doesn't match golang.org/x/mod/modfile's own parseVersionInterval grammar
// — a bare version with a stray trailing token, an incomplete bracketed
// interval, or a missing argument entirely — is exactly what makes the real
// go command's strict go.mod parser (modfile.Parse) Fatal every
// module-aware go subcommand before resolving a single module, fully
// offline (GOPROXY=off) — confirmed against real `go list -m all` (see
// TestRunInvalidRetractDirectiveGoModNoLeak in main_test.go for the
// end-to-end regression). A version token's own syntax (e.g.
// "bogus-not-a-version") is deliberately NOT checked — live-verified that
// shape instead sends a real go.mod parse down a later, network-dependent
// validation path (a proxy lookup), not an immediate offline Fatal, so it
// must NOT be flagged here.
func TestGoModHasInvalidRetractDirective(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"no retract directive at all", "module example.com/foo\n\ngo 1.24\n\nrequire example.com/bar v1.0.0\n", false},
		{"valid single version", "module example.com/foo\n\ngo 1.24\n\nretract v1.2.3\n", false},
		{"valid bracketed interval", "module example.com/foo\n\ngo 1.24\n\nretract [v1.0.0,v1.9.9]\n", false},
		{"valid bracketed interval, no spaces at all", "module example.com/foo\n\ngo 1.24\n\nretract[v1.0.0,v1.9.9]\n", false},
		{"version with no real semver syntax is not flagged (needs network to judge)", "module example.com/foo\n\ngo 1.24\n\nretract bogus-not-a-version\n", false},
		{"bare retract, no argument", "module example.com/foo\n\ngo 1.24\n\nretract\n\nrequire example.com/bar v1.0.0\n", true},
		{"extra token after a single version", "module example.com/foo\n\ngo 1.24\n\nretract v1.2.3 extra\n", true},
		{"missing comma in bracketed interval", "module example.com/foo\n\ngo 1.24\n\nretract [v1.0.0 v1.9.9]\n", true},
		{"missing closing bracket", "module example.com/foo\n\ngo 1.24\n\nretract [v1.0.0,v1.9.9\n", true},
		{"missing second version after comma", "module example.com/foo\n\ngo 1.24\n\nretract [v1.0.0,]\n", true},
		{"extra token after a complete bracketed interval", "module example.com/foo\n\ngo 1.24\n\nretract [v1.0.0,v1.9.9] extra\n", true},
		{"valid retract block", "module example.com/foo\n\ngo 1.24\n\nretract (\n\tv1.0.0\n\t[v1.2.0,v1.2.9]\n)\n", false},
		{"retract block entry with a stray extra token", "module example.com/foo\n\ngo 1.24\n\nretract (\n\tv1.0.0\n\tv1.2.3 extra\n)\n", true},
	}
	for _, c := range cases {
		if got := goModHasInvalidRetractDirective([]byte(c.src)); got != c.want {
			t.Errorf("%s: goModHasInvalidRetractDirective(%q) = %v, want %v", c.name, c.src, got, c.want)
		}
	}
}

// TestParseReplacesSpecificAndGeneralSameModule covers a go.mod carrying
// both a version-specific and a version-agnostic replace for the same old
// path at once — legal go.mod syntax (verified live: `go list -m all`
// accepts a go.mod with both present). Before replaceEntry existed,
// parseReplaces stored a single replaceTarget per old path in a plain map,
// so the second replace line parsed always clobbered the first regardless
// of specificity — this asserts both survive parsing as two entries, so
// selectReplace has both to choose between at resolution time.
func TestParseReplacesSpecificAndGeneralSameModule(t *testing.T) {
	src := "module example.com/foo\n\nreplace example.com/bar => ./general\nreplace example.com/bar v1.0.0 => ./specific\n"
	got := parseReplaces([]byte(src))
	want := map[string][]replaceEntry{
		"example.com/bar": {
			{oldVersion: "", target: replaceTarget{path: "./general", isLocal: true}},
			{oldVersion: "v1.0.0", target: replaceTarget{path: "./specific", isLocal: true}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesNone(t *testing.T) {
	if got := parseReplaces([]byte("module example.com/foo\n")); len(got) != 0 {
		t.Errorf("expected no replaces, got %v", got)
	}
}

func TestResolveEffectiveModulesDropsLocalReplace(t *testing.T) {
	modules := []requireEntry{
		{path: "example.com/bar", version: "v1.0.0"},
		{path: "example.com/kept", version: "v1.0.0"},
	}
	replaces := map[string][]replaceEntry{
		"example.com/bar": {{target: replaceTarget{path: "../bar", isLocal: true}}},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/kept"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveEffectiveModulesSwapsModuleReplace(t *testing.T) {
	modules := []requireEntry{{path: "example.com/fork-me", version: "v1.0.0"}}
	replaces := map[string][]replaceEntry{
		"example.com/fork-me": {{target: replaceTarget{path: "example.com/myorg/fork-me", isLocal: false}}},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/myorg/fork-me"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveEffectiveModulesNoReplace(t *testing.T) {
	modules := []requireEntry{{path: "example.com/plain", version: "v1.0.0"}}
	got := resolveEffectiveModules(modules, nil)
	want := []string{"example.com/plain"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolveEffectiveModulesVersionSpecificReplaceWinsOverGeneral covers a
// go.mod carrying both a version-specific and a version-agnostic replace
// for the same module — legal go.mod syntax. Verified live against the
// real go toolchain (`go list -m all` with both directives present, in
// both file orderings): the version-specific one always won, regardless of
// which line came first. Before selectReplace existed, parseReplaces kept
// only one replaceTarget per old path in a plain map, so whichever replace
// line was scanned last silently overwrote the other — matching real go
// only by accident of file order, not by the version-match rule real go
// actually uses.
func TestResolveEffectiveModulesVersionSpecificReplaceWinsOverGeneral(t *testing.T) {
	modules := []requireEntry{{path: "example.com/foo", version: "v1.0.0"}}
	replaces := map[string][]replaceEntry{
		"example.com/foo": {
			{oldVersion: "", target: replaceTarget{path: "example.com/foo-general", isLocal: false}},
			{oldVersion: "v1.0.0", target: replaceTarget{path: "example.com/foo-specific", isLocal: false}},
		},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/foo-specific"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestResolveEffectiveModulesGeneralReplaceAppliesWhenNoVersionMatches
// covers the fallback side of the same rule: a version-specific replace
// for a version other than the one actually required must not apply (real
// go leaves it unmatched and falls through to the version-agnostic
// replace) — verified live: a replace at a non-required version alongside
// no matching general replace makes `go list -m all` fail outright trying
// to fetch the untouched module over the network, so a mismatched-version
// replace is not just "lower priority", it's inapplicable.
func TestResolveEffectiveModulesGeneralReplaceAppliesWhenNoVersionMatches(t *testing.T) {
	modules := []requireEntry{{path: "example.com/foo", version: "v2.0.0"}}
	replaces := map[string][]replaceEntry{
		"example.com/foo": {
			{oldVersion: "v1.0.0", target: replaceTarget{path: "example.com/foo-v1-only", isLocal: false}},
			{oldVersion: "", target: replaceTarget{path: "example.com/foo-general", isLocal: false}},
		},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/foo-general"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGoWorkReplacesEmptyGowork(t *testing.T) {
	if got := goWorkReplaces(""); got != nil {
		t.Errorf("expected nil for empty gowork path, got %v", got)
	}
}

func TestGoWorkReplacesOff(t *testing.T) {
	if got := goWorkReplaces("off"); got != nil {
		t.Errorf(`expected nil for gowork = "off", got %v`, got)
	}
}

func TestGoWorkReplacesMissingFile(t *testing.T) {
	if got := goWorkReplaces(filepath.Join(t.TempDir(), "no-such.work")); got != nil {
		t.Errorf("expected nil for an unreadable go.work path, got %v", got)
	}
}

func TestGoWorkReplacesParsesReplaceBlock(t *testing.T) {
	dir := t.TempDir()
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./app
	./fork
)

replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0
`)
	got := goWorkReplaces(gowork)
	want := map[string][]replaceEntry{
		"github.com/foo/bar": {{target: replaceTarget{path: "git.internal.example.com/mirror/bar", isLocal: false}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeReplacesOverlayWinsOnConflict(t *testing.T) {
	base := map[string][]replaceEntry{
		"example.com/shared":     {{target: replaceTarget{path: "example.com/from-gomod", isLocal: false}}},
		"example.com/gomod-only": {{target: replaceTarget{path: "../local", isLocal: true}}},
	}
	overlay := map[string][]replaceEntry{
		"example.com/shared":      {{target: replaceTarget{path: "example.com/from-gowork", isLocal: false}}},
		"example.com/gowork-only": {{target: replaceTarget{path: "example.com/added-by-gowork", isLocal: false}}},
	}
	got := mergeReplaces(base, overlay)
	want := map[string][]replaceEntry{
		"example.com/shared":      {{target: replaceTarget{path: "example.com/from-gowork", isLocal: false}}},
		"example.com/gomod-only":  {{target: replaceTarget{path: "../local", isLocal: true}}},
		"example.com/gowork-only": {{target: replaceTarget{path: "example.com/added-by-gowork", isLocal: false}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeReplacesNilOverlayReturnsBaseUnchanged(t *testing.T) {
	base := map[string][]replaceEntry{
		"example.com/x": {{target: replaceTarget{path: "example.com/y", isLocal: false}}},
	}
	got := mergeReplaces(base, nil)
	if !reflect.DeepEqual(got, base) {
		t.Errorf("got %v, want %v", got, base)
	}
}

// TestMergeReplacesVersionSpecificOverlayLeavesUnrelatedGomodReplaceIntact
// reproduces the false negative found live against the real go toolchain
// (run #288): a go.work replace that's specific to a version other than
// the one actually required must not discard a go.mod-level replace for
// the same path — selectReplace(mergeReplaces(...), requiredVersion) must
// still resolve through the go.mod entry, exactly like `go list -m all`
// does in a real workspace.
func TestMergeReplacesVersionSpecificOverlayLeavesUnrelatedGomodReplaceIntact(t *testing.T) {
	base := map[string][]replaceEntry{
		"example.com/dep": {{target: replaceTarget{path: "github.com/myorg/dep-private", isLocal: false}}},
	}
	overlay := map[string][]replaceEntry{
		"example.com/dep": {{oldVersion: "v1.5.0", target: replaceTarget{path: "example.com/other-fork", isLocal: false}}},
	}
	merged := mergeReplaces(base, overlay)
	got, ok := selectReplace(merged["example.com/dep"], "v1.0.0")
	if !ok || got.path != "github.com/myorg/dep-private" {
		t.Errorf("selectReplace(v1.0.0) = %v, %v; want github.com/myorg/dep-private, true", got, ok)
	}
	got, ok = selectReplace(merged["example.com/dep"], "v1.5.0")
	if !ok || got.path != "example.com/other-fork" {
		t.Errorf("selectReplace(v1.5.0) = %v, %v; want example.com/other-fork, true", got, ok)
	}
}

// TestMergeReplacesGeneralOverlayOverridesGeneralBase reproduces the
// general-vs-general precedence verified live against the real go
// toolchain (run #288): when both go.work and go.mod carry a
// version-agnostic replace for the same path, go.work's wins for every
// version, not just the ones go.work happens to list.
func TestMergeReplacesGeneralOverlayOverridesGeneralBase(t *testing.T) {
	base := map[string][]replaceEntry{
		"example.com/dep": {{target: replaceTarget{path: "bitbucket.org/other/y", isLocal: false}}},
	}
	overlay := map[string][]replaceEntry{
		"example.com/dep": {{target: replaceTarget{path: "github.com/myorg/x", isLocal: false}}},
	}
	merged := mergeReplaces(base, overlay)
	got, ok := selectReplace(merged["example.com/dep"], "v9.9.9")
	if !ok || got.path != "github.com/myorg/x" {
		t.Errorf("selectReplace(v9.9.9) = %v, %v; want github.com/myorg/x, true", got, ok)
	}
}

// TestMergeReplacesExactVersionTieGoesToOverlay reproduces the exact-tie
// precedence verified live against the real go toolchain (run #288): when
// both go.work and go.mod replace the exact same required version,
// go.work's replacement is used, per `go help work`.
func TestMergeReplacesExactVersionTieGoesToOverlay(t *testing.T) {
	base := map[string][]replaceEntry{
		"example.com/dep": {{oldVersion: "v1.0.0", target: replaceTarget{path: "bitbucket.org/other/y", isLocal: false}}},
	}
	overlay := map[string][]replaceEntry{
		"example.com/dep": {{oldVersion: "v1.0.0", target: replaceTarget{path: "github.com/myorg/x", isLocal: false}}},
	}
	merged := mergeReplaces(base, overlay)
	got, ok := selectReplace(merged["example.com/dep"], "v1.0.0")
	if !ok || got.path != "github.com/myorg/x" {
		t.Errorf("selectReplace(v1.0.0) = %v, %v; want github.com/myorg/x, true", got, ok)
	}
}

func TestParseToolsSingleLine(t *testing.T) {
	src := "module example.com/foo\n\ngo 1.24\n\ntool golang.org/x/tools/cmd/stringer\n"
	got := parseTools([]byte(src))
	want := []string{"golang.org/x/tools/cmd/stringer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseToolsBlock(t *testing.T) {
	src := `module example.com/foo

go 1.24

tool (
	golang.org/x/tools/cmd/stringer
	example.com/myorg/private/cmd/thing
)
`
	got := parseTools([]byte(src))
	want := []string{"golang.org/x/tools/cmd/stringer", "example.com/myorg/private/cmd/thing"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseToolsEmpty(t *testing.T) {
	if got := parseTools([]byte("module example.com/foo\n\ngo 1.24\n")); got != nil {
		t.Errorf("expected nil for a go.mod with no tool directives, got %v", got)
	}
}

func TestParseToolsQuotedPath(t *testing.T) {
	src := "module example.com/foo\n\ngo 1.24\n\ntool \"some path with spaces\"\n"
	got := parseTools([]byte(src))
	want := []string{"some path with spaces"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEffectiveToolModulesUncoveredIncluded(t *testing.T) {
	got := effectiveToolModules([]string{"example.com/myorg/private/cmd/thing"}, nil)
	want := []string{"example.com/myorg/private/cmd/thing"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEffectiveToolModulesCoveredByExactRequireExcluded(t *testing.T) {
	got := effectiveToolModules(
		[]string{"example.com/myorg/private"},
		[]requireEntry{{path: "example.com/myorg/private", version: "v1.0.0"}},
	)
	if got != nil {
		t.Errorf("expected a tool path exactly matching a require entry to be excluded, got %v", got)
	}
}

func TestEffectiveToolModulesCoveredByParentRequireExcluded(t *testing.T) {
	got := effectiveToolModules(
		[]string{"example.com/myorg/private/cmd/thing"},
		[]requireEntry{{path: "example.com/myorg/private", version: "v1.0.0"}},
	)
	if got != nil {
		t.Errorf("expected a tool path under a required module's path to be excluded, got %v", got)
	}
}

func TestEffectiveToolModulesSiblingPathNotFalselyCovered(t *testing.T) {
	// "example.com/myorg/private2" must not be treated as covering
	// "example.com/myorg/private" — a naive strings.HasPrefix(t, r) rather
	// than strings.HasPrefix(t, r+"/") would falsely match here.
	got := effectiveToolModules(
		[]string{"example.com/myorg/private"},
		[]requireEntry{{path: "example.com/myorg/private2", version: "v1.0.0"}},
	)
	want := []string{"example.com/myorg/private"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEffectiveToolModulesDeduped(t *testing.T) {
	got := effectiveToolModules(
		[]string{"example.com/myorg/private/cmd/thing", "example.com/myorg/private/cmd/thing"},
		nil,
	)
	want := []string{"example.com/myorg/private/cmd/thing"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGoWorkUseDirsSingleLine(t *testing.T) {
	dir := t.TempDir()
	gowork := writeFile(t, dir, "go.work", `go 1.24

use ./a
`)
	got := goWorkUseDirs(gowork)
	want := []string{filepath.Join(dir, "a")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGoWorkUseDirsBlockForm(t *testing.T) {
	dir := t.TempDir()
	gowork := writeFile(t, dir, "go.work", `go 1.24

use (
	./a
	./b // comment
)
`)
	got := goWorkUseDirs(gowork)
	want := []string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGoWorkUseDirsMissingFile(t *testing.T) {
	if got := goWorkUseDirs(filepath.Join(t.TempDir(), "no-such.work")); got != nil {
		t.Errorf("expected nil for an unreadable go.work path, got %v", got)
	}
}

func TestGoWorkUseDirsNoUseDirective(t *testing.T) {
	dir := t.TempDir()
	gowork := writeFile(t, dir, "go.work", "go 1.24\n")
	if got := goWorkUseDirs(gowork); got != nil {
		t.Errorf("expected nil when go.work has no use directive, got %v", got)
	}
}

func TestResolveLocalPath(t *testing.T) {
	tests := []struct {
		baseDir, path, want string
	}{
		{"/ws", "./a", "/ws/a"},
		{"/ws", "../sibling", "/sibling"},
		{"/ws", "/abs/path", "/abs/path"},
		{"/ws", ".", "/ws"},
	}
	for _, tc := range tests {
		if got := resolveLocalPath(tc.baseDir, tc.path); got != tc.want {
			t.Errorf("resolveLocalPath(%q, %q) = %q, want %q", tc.baseDir, tc.path, got, tc.want)
		}
	}
}

func TestModuleOutsideWorkspaceNoGowork(t *testing.T) {
	if moduleOutsideWorkspace("", "/any/dir") {
		t.Error("expected false when gowork is empty")
	}
	if moduleOutsideWorkspace("off", "/any/dir") {
		t.Error(`expected false when gowork is "off"`)
	}
}

func TestModuleOutsideWorkspaceTrueWhenNotUsed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/go.mod", "module example.com/a\n\ngo 1.24\n")
	moduleDir := writeFile(t, dir, "b/go.mod", "module example.com/b\n\ngo 1.24\n")
	moduleDir = filepath.Dir(moduleDir)
	gowork := writeFile(t, dir, "go.work", "go 1.24\n\nuse ./a\n")
	if !moduleOutsideWorkspace(gowork, moduleDir) {
		t.Error("expected true: moduleDir is not used by the workspace and not reachable via any replace")
	}
}

func TestModuleOutsideWorkspaceFalseWhenUsed(t *testing.T) {
	dir := t.TempDir()
	moduleDir := writeFile(t, dir, "a/go.mod", "module example.com/a\n\ngo 1.24\n")
	moduleDir = filepath.Dir(moduleDir)
	gowork := writeFile(t, dir, "go.work", "go 1.24\n\nuse ./a\n")
	if moduleOutsideWorkspace(gowork, moduleDir) {
		t.Error("expected false: moduleDir is directly used by the workspace")
	}
}

func TestModuleOutsideWorkspaceFalseWhenReachableViaGoWorkReplace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/go.mod", "module example.com/a\n\ngo 1.24\n\nrequire example.com/pub v1.0.0\n")
	moduleDir := writeFile(t, dir, "b/go.mod", "module example.com/b\n\ngo 1.24\n")
	moduleDir = filepath.Dir(moduleDir)
	gowork := writeFile(t, dir, "go.work", "go 1.24\n\nuse ./a\n\nreplace example.com/pub => ./b\n")
	if moduleOutsideWorkspace(gowork, moduleDir) {
		t.Error("expected false: moduleDir is the target of go.work's own replace directive")
	}
}

func TestModuleOutsideWorkspaceFalseWhenReachableViaMemberReplace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/go.mod", "module example.com/a\n\ngo 1.24\n\nrequire example.com/pub v1.0.0\n\nreplace example.com/pub => ../b\n")
	moduleDir := writeFile(t, dir, "b/go.mod", "module example.com/b\n\ngo 1.24\n")
	moduleDir = filepath.Dir(moduleDir)
	gowork := writeFile(t, dir, "go.work", "go 1.24\n\nuse ./a\n")
	if moduleOutsideWorkspace(gowork, moduleDir) {
		t.Error("expected false: moduleDir is the target of a's own go.mod replace directive")
	}
}

func TestModuleOutsideWorkspaceFalseWhenNoUseDirective(t *testing.T) {
	dir := t.TempDir()
	moduleDir := writeFile(t, dir, "b/go.mod", "module example.com/b\n\ngo 1.24\n")
	moduleDir = filepath.Dir(moduleDir)
	gowork := writeFile(t, dir, "go.work", "go 1.24\n")
	if moduleOutsideWorkspace(gowork, moduleDir) {
		t.Error("expected false (fail open) when go.work has no parseable use directive at all")
	}
}
