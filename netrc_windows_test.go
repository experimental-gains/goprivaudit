//go:build windows

package main

import (
	"path/filepath"
	"testing"
)

// Windows-only: netrcPath's _netrc fallback priority is gated on
// runtime.GOOS == "windows", so this case can only be exercised on a
// windows GOOS build. See TestNetrcPathIgnoresLegacyUnderscoreNetrcOnNonWindows
// in netrc_test.go for the non-Windows case.
//
// Real curl's Curl_parsenetrc (lib/netrc.c) tries $HOME/.netrc FIRST and
// only falls back to the legacy $HOME/_netrc if parsenetrc reports the
// primary file missing — the opposite priority from this function's prior,
// wrong version (which mirrored cmd/go/internal/auth.netrcPath instead,
// preferring _netrc over .netrc whenever both existed).
func TestNetrcPathPrefersDotNetrcOverUnderscoreNetrcOnWindows(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".netrc", "machine example.com\nlogin a\npassword b\n")
	writeFile(t, home, "_netrc", "machine example.com\nlogin c\npassword d\n")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	want := filepath.Join(home, ".netrc")
	if got := netrcPath(); got != want {
		t.Errorf("netrcPath() = %q, want %q (.netrc must win over _netrc when both exist)", got, want)
	}
}

// TestNetrcPathFallsBackToUnderscoreNetrcOnWindows covers the other half:
// when $HOME/.netrc doesn't exist at all, netrcPath must still fall back to
// the legacy $HOME/_netrc, matching Curl_parsenetrc's own fallback.
func TestNetrcPathFallsBackToUnderscoreNetrcOnWindows(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, "_netrc", "machine example.com\nlogin c\npassword d\n")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	want := filepath.Join(home, "_netrc")
	if got := netrcPath(); got != want {
		t.Errorf("netrcPath() = %q, want %q (should fall back to _netrc when .netrc is missing)", got, want)
	}
}
