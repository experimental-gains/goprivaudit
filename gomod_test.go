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
	want := []string{
		"github.com/pkg/errors",
		"github.com/stretchr/testify",
		"example.com/myorg/private",
		"golang.org/x/sync",
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
	want := []string{"example.com/bar"}
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
	want := []string{"github.com/pkg/errors"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseRequiresBlockTabBeforeParen(t *testing.T) {
	got := parseRequires([]byte("module example.com/foo\n\nrequire\t(\n\tgithub.com/pkg/errors v0.9.1\n)\n"))
	want := []string{"github.com/pkg/errors"}
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
	want := []string{"github.com/real/dep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestLeadingQuotedStringEmptyBacktick covers a degenerate but valid
// backtick-quoted empty string (two backticks in a row) -- the closing
// backtick is the very next byte after the opening one.
func TestLeadingQuotedStringEmptyBacktick(t *testing.T) {
	got, ok := leadingQuotedString("``")
	if !ok || got != "" {
		t.Errorf("leadingQuotedString(\"``\") = %q, %v; want \"\", true", got, ok)
	}
}

// TestLeadingQuotedStringUnterminatedDoubleQuote covers a double-quoted
// string with no closing quote at all — must fail cleanly (ok=false), not
// index past the end of the string.
func TestLeadingQuotedStringUnterminatedDoubleQuote(t *testing.T) {
	got, ok := leadingQuotedString(`"unterminated`)
	if ok {
		t.Errorf("leadingQuotedString(%q) = %q, true; want ok=false", `"unterminated`, got)
	}
}

// TestLeadingQuotedStringTrailingBackslashUnterminated covers a
// double-quoted string whose last byte is a lone, unescaped backslash (no
// character left to escape) — must not index past the end of the string.
func TestLeadingQuotedStringTrailingBackslashUnterminated(t *testing.T) {
	got, ok := leadingQuotedString(`"abc\`)
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
	want := map[string]replaceTarget{
		"example.com/bar":     {path: "../bar", isLocal: true},
		"example.com/fork-me": {path: "example.com/myorg/fork-me", isLocal: false},
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
	want := map[string]replaceTarget{
		"example.com/bar": {path: "./local/bar", isLocal: true},
		"example.com/baz": {path: "example.com/myorg/baz", isLocal: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBlockNoSpaceBeforeParen(t *testing.T) {
	src := "module example.com/foo\n\nreplace(\n\texample.com/bar => ./local/bar\n)\n"
	got := parseReplaces([]byte(src))
	want := map[string]replaceTarget{
		"example.com/bar": {path: "./local/bar", isLocal: true},
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
	want := map[string]replaceTarget{
		"example.com/bar": {path: "../my mod", isLocal: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseReplacesBacktickQuotedLocalPath(t *testing.T) {
	src := "module example.com/foo\n\nreplace example.com/bar => `../my mod`\n"
	got := parseReplaces([]byte(src))
	want := map[string]replaceTarget{
		"example.com/bar": {path: "../my mod", isLocal: true},
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
	modules := []string{"example.com/bar", "example.com/kept"}
	replaces := map[string]replaceTarget{
		"example.com/bar": {path: "../bar", isLocal: true},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/kept"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveEffectiveModulesSwapsModuleReplace(t *testing.T) {
	modules := []string{"example.com/fork-me"}
	replaces := map[string]replaceTarget{
		"example.com/fork-me": {path: "example.com/myorg/fork-me", isLocal: false},
	}
	got := resolveEffectiveModules(modules, replaces)
	want := []string{"example.com/myorg/fork-me"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveEffectiveModulesNoReplace(t *testing.T) {
	modules := []string{"example.com/plain"}
	got := resolveEffectiveModules(modules, nil)
	want := []string{"example.com/plain"}
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
	want := map[string]replaceTarget{
		"github.com/foo/bar": {path: "git.internal.example.com/mirror/bar", isLocal: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeReplacesOverlayWinsOnConflict(t *testing.T) {
	base := map[string]replaceTarget{
		"example.com/shared":     {path: "example.com/from-gomod", isLocal: false},
		"example.com/gomod-only": {path: "../local", isLocal: true},
	}
	overlay := map[string]replaceTarget{
		"example.com/shared":      {path: "example.com/from-gowork", isLocal: false},
		"example.com/gowork-only": {path: "example.com/added-by-gowork", isLocal: false},
	}
	got := mergeReplaces(base, overlay)
	want := map[string]replaceTarget{
		"example.com/shared":      {path: "example.com/from-gowork", isLocal: false},
		"example.com/gomod-only":  {path: "../local", isLocal: true},
		"example.com/gowork-only": {path: "example.com/added-by-gowork", isLocal: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergeReplacesNilOverlayReturnsBaseUnchanged(t *testing.T) {
	base := map[string]replaceTarget{"example.com/x": {path: "example.com/y", isLocal: false}}
	got := mergeReplaces(base, nil)
	if !reflect.DeepEqual(got, base) {
		t.Errorf("got %v, want %v", got, base)
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
		[]string{"example.com/myorg/private"},
	)
	if got != nil {
		t.Errorf("expected a tool path exactly matching a require entry to be excluded, got %v", got)
	}
}

func TestEffectiveToolModulesCoveredByParentRequireExcluded(t *testing.T) {
	got := effectiveToolModules(
		[]string{"example.com/myorg/private/cmd/thing"},
		[]string{"example.com/myorg/private"},
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
		[]string{"example.com/myorg/private2"},
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
