package main

import "testing"

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

	got := filterGoSumCovered(modules, requires, replaces, dir)
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
	got := filterGoSumCovered(modules, nil, nil, dir)
	if len(got) != 1 || got[0] != "example.com/foo" {
		t.Errorf("filterGoSumCovered with no go.sum = %v, want unchanged %v", got, modules)
	}
}
