package main

import (
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

func TestStripComment(t *testing.T) {
	cases := map[string]string{
		"example.com/foo v1.0.0":             "example.com/foo v1.0.0",
		"example.com/foo v1.0.0 // indirect": "example.com/foo v1.0.0 ",
		// A line that's nothing but a comment (the "//" sits at index 0)
		// isn't exercised by the case above, where "//" is always partway
		// through the line.
		"// standalone comment, no module": "",
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLeadingQuotedString covers `go mod edit`'s quoted-token syntax
// directly — none of the higher-level require/replace parsing tests above
// happen to use a path containing a backslash escape or an empty
// backtick-quoted string, so the escape-handling branch inside the loop
// (and the empty-backtick case) had no coverage at all.
func TestLeadingQuotedString(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`"../my mod"`, "../my mod", true},
		{"`../my mod`", "../my mod", true},
		{"``", "", true},
		{`"esc\"aped"`, `esc"aped`, true},
		{`"back\\slash"`, `back\slash`, true},
		{`"unterminated`, "", false},
		{`"trailing backslash\`, "", false},
	}
	for _, c := range cases {
		got, ok := leadingQuotedString(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("leadingQuotedString(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFirstField(t *testing.T) {
	cases := map[string]string{
		"example.com/foo v1.0.0":  "example.com/foo",
		"  example.com/foo  ":     "example.com/foo",
		"":                        "",
		`"../my mod" // indirect`: "../my mod",
	}
	for in, want := range cases {
		if got := firstField(in); got != want {
			t.Errorf("firstField(%q) = %q, want %q", in, got, want)
		}
	}
}
