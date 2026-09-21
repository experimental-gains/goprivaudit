//go:build windows

package main

import (
	"reflect"
	"testing"
)

// Windows-only: filepath.IsAbs (which addReplace relies on to detect a
// local filesystem replace target) has platform-dependent semantics, so
// this case can only be exercised on a windows GOOS build. See the
// TestParseReplacesLocalAndModuleSingleLine family in gomod_test.go for
// the OS-agnostic cases ("./", "../", "/").
func TestParseReplacesWindowsAbsolutePath(t *testing.T) {
	src := `module example.com/foo

require corp.internal/secret v1.0.0

replace corp.internal/secret => C:\Users\dev\secret
`
	got := parseReplaces([]byte(src))
	want := map[string]replaceTarget{
		"corp.internal/secret": {path: `C:\Users\dev\secret`, isLocal: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
