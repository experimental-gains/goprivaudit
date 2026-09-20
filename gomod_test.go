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
