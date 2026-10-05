package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoSumKeys(t *testing.T) {
	data := []byte(`github.com/myorg/internal-tool v1.2.3 h1:aaaa=
github.com/myorg/internal-tool v1.2.3/go.mod h1:bbbb=
golang.org/x/mod v0.41.0 h1:cccc=

golang.org/x/mod v0.41.0/go.mod h1:dddd=
`)
	keys := parseGoSumKeys(data)
	want := []string{
		"github.com/myorg/internal-tool v1.2.3",
		"github.com/myorg/internal-tool v1.2.3/go.mod",
		"golang.org/x/mod v0.41.0",
		"golang.org/x/mod v0.41.0/go.mod",
	}
	for _, k := range want {
		if !keys[k] {
			t.Errorf("parseGoSumKeys missing key %q", k)
		}
	}
	if len(keys) != len(want) {
		t.Errorf("parseGoSumKeys returned %d keys, want %d: %v", len(keys), len(want), keys)
	}
}

func TestParseGoSumKeysSkipsMalformedLines(t *testing.T) {
	data := []byte("not-a-valid-line\n\n   \nmodule.example/foo v1.0.0 h1:aaaa=\n")
	keys := parseGoSumKeys(data)
	if len(keys) != 1 || !keys["module.example/foo v1.0.0"] {
		t.Errorf("parseGoSumKeys(%q) = %v, want just the one well-formed entry", data, keys)
	}
}

func TestGoSumCoversModule(t *testing.T) {
	keys := parseGoSumKeys([]byte(`example.com/foo v1.0.0 h1:aaaa=
example.com/foo v1.0.0/go.mod h1:bbbb=
example.com/bar v2.0.0 h1:cccc=
`))

	tests := []struct {
		name, module, version string
		want                  bool
	}{
		{"both lines present", "example.com/foo", "v1.0.0", true},
		{"missing go.mod line", "example.com/bar", "v2.0.0", false},
		{"unknown module", "example.com/baz", "v1.0.0", false},
		{"right module, wrong version", "example.com/foo", "v1.0.1", false},
		{"empty version", "example.com/foo", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goSumCoversModule(keys, tt.module, tt.version); got != tt.want {
				t.Errorf("goSumCoversModule(keys, %q, %q) = %v, want %v", tt.module, tt.version, got, tt.want)
			}
		})
	}
}

func TestFilterGoSumCovered(t *testing.T) {
	requires := []requireEntry{
		{path: "example.com/covered", version: "v1.0.0"},
		{path: "example.com/notcovered", version: "v2.0.0"},
		{path: "example.com/replaced", version: "v3.0.0"},
		{path: "example.com/samepath", version: "v4.0.0"},
	}
	replaces := map[string][]replaceEntry{
		"example.com/replaced": {{oldVersion: "", target: replaceTarget{path: "example.com/replaced-fork", isLocal: false}}},
		// A same-path replace that only bumps the version (a real, valid
		// go.mod shape: `replace example.com/samepath => example.com/samepath
		// v4.0.1-patched`) must not let the ORIGINAL require's version
		// (v4.0.0) be matched against go.sum for the SAME effective path —
		// this tool's replaceTarget never records the replacement's own
		// pinned version (see its doc comment), so a go.sum entry for the
		// pre-replace version must not be trusted as covering the real,
		// different effective version.
		"example.com/samepath": {{oldVersion: "", target: replaceTarget{path: "example.com/samepath", isLocal: false}}},
	}
	modules := []string{"example.com/covered", "example.com/notcovered", "example.com/replaced-fork", "example.com/samepath"}

	dir := t.TempDir()
	writeFile(t, dir, "go.sum", `example.com/covered v1.0.0 h1:aaaa=
example.com/covered v1.0.0/go.mod h1:bbbb=
example.com/replaced-fork v3.0.0 h1:cccc=
example.com/replaced-fork v3.0.0/go.mod h1:dddd=
example.com/samepath v4.0.0 h1:eeee=
example.com/samepath v4.0.0/go.mod h1:ffff=
`)

	got := filterGoSumCovered(modules, requires, replaces, dir, "")
	want := []string{"example.com/notcovered", "example.com/replaced-fork", "example.com/samepath"}
	if len(got) != len(want) {
		t.Fatalf("filterGoSumCovered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("filterGoSumCovered = %v, want %v", got, want)
			break
		}
	}
}

func TestFilterGoSumCoveredNoGoSumFile(t *testing.T) {
	dir := t.TempDir()
	modules := []string{"example.com/foo"}
	got := filterGoSumCovered(modules, nil, nil, dir, "")
	if len(got) != 1 || got[0] != "example.com/foo" {
		t.Errorf("filterGoSumCovered with no go.sum = %v, want unchanged %v", got, modules)
	}
}

// TestFilterGoSumCoveredGoWorkSum covers the gap fixed in this change: a
// real go.work workspace writes a newly-needed dependency's checksums into
// go.work.sum at the WORKSPACE ROOT, not into the member module's own
// go.sum (live-verified, go1.24.4 — see filterGoSumCovered's doc comment).
// A member module whose own go.sum is entirely empty, audited while an
// active go.work names it, must still have its covered require dropped
// once go.work.sum (sitting next to go.work, a sibling directory of
// moduleDir) carries both checksum lines for it.
func TestFilterGoSumCoveredGoWorkSum(t *testing.T) {
	wsRoot := t.TempDir()
	moduleDir := filepath.Join(wsRoot, "member")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	gowork := filepath.Join(wsRoot, "go.work")
	writeFile(t, wsRoot, "go.work", "go 1.24\n\nuse ./member\n")
	writeFile(t, wsRoot, "go.work.sum", `example.com/covered v1.0.0 h1:aaaa=
example.com/covered v1.0.0/go.mod h1:bbbb=
`)
	// moduleDir's own go.sum deliberately does not exist at all, matching
	// the real go.work shape this test reproduces.

	requires := []requireEntry{
		{path: "example.com/covered", version: "v1.0.0"},
		{path: "example.com/notcovered", version: "v2.0.0"},
	}
	modules := []string{"example.com/covered", "example.com/notcovered"}

	got := filterGoSumCovered(modules, requires, nil, moduleDir, gowork)
	want := []string{"example.com/notcovered"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("filterGoSumCovered with go.work.sum coverage = %v, want %v", got, want)
	}

	// gowork == "" (no active workspace) must NOT pick up the sibling
	// go.work.sum at all: the exact same module, audited the same way,
	// stays uncovered when there's no workspace to have written it.
	gotNoWorkspace := filterGoSumCovered(modules, requires, nil, moduleDir, "")
	if len(gotNoWorkspace) != len(modules) {
		t.Errorf("filterGoSumCovered with gowork=\"\" = %v, want unchanged %v (go.work.sum must only apply inside an active workspace)", gotNoWorkspace, modules)
	}

	// gowork == "off" (workspace mode explicitly disabled) must behave
	// identically to "" — same convention goWorkReplaces already uses.
	gotOff := filterGoSumCovered(modules, requires, nil, moduleDir, "off")
	if len(gotOff) != len(modules) {
		t.Errorf("filterGoSumCovered with gowork=\"off\" = %v, want unchanged %v", gotOff, modules)
	}
}
