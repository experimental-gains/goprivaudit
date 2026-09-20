package main

import (
	"reflect"
	"testing"
)

func TestPrivatePrefixesFromGitConfig(t *testing.T) {
	src := `[user]
	name = someone
	email = someone@example.com

[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/

[url "ssh://git@example.com/"]
	pushInsteadOf = https://example.com/

[core]
	editor = vim
`
	got := privatePrefixesFromGitConfig([]byte(src))
	want := []string{"github.com/myorg", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPrivatePrefixesFromGitConfigNoURLSections(t *testing.T) {
	src := "[user]\n\tname = someone\n"
	if got := privatePrefixesFromGitConfig([]byte(src)); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestNormalizeToModulePrefix(t *testing.T) {
	cases := map[string]string{
		"https://github.com/myorg/":     "github.com/myorg",
		"https://github.com/myorg":      "github.com/myorg",
		"https://github.com/myorg.git":  "github.com/myorg",
		"git@github.com:myorg":          "github.com/myorg",
		"git@github.com:myorg/repo.git": "github.com/myorg/repo",
		"ssh://git@example.com/myorg":   "example.com/myorg",
		"":                              "",
	}
	for in, want := range cases {
		if got := normalizeToModulePrefix(in); got != want {
			t.Errorf("normalizeToModulePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
