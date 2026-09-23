package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitModFlag(t *testing.T) {
	cases := []struct {
		goflags   string
		wantValue string
		wantOK    bool
	}{
		{"", "", false},
		{"-race", "", false},
		{"-mod=vendor", "vendor", true},
		{"-mod=mod", "mod", true},
		{"-mod=readonly", "readonly", true},
		{"--mod=vendor", "vendor", true},
		{"-race -mod=vendor -v", "vendor", true},
		// Repeated flag: last one wins, matching how GOFLAGS values get
		// prepended to a real argv and re-parsed by the flag package.
		{"-mod=mod -mod=vendor", "vendor", true},
	}
	for _, c := range cases {
		value, ok := explicitModFlag(c.goflags)
		if value != c.wantValue || ok != c.wantOK {
			t.Errorf("explicitModFlag(%q) = (%q, %v), want (%q, %v)", c.goflags, value, ok, c.wantValue, c.wantOK)
		}
	}
}

func TestGoVersionAtLeast(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"1.14", true},
		{"1.14.0", true},
		{"1.24.4", true},
		{"1.26.8", true},
		{"1.13", false},
		{"1.13.9", false},
		{"1.9", false},
		{"", false},
		{"garbage", false},
		{"1", false},
	}
	for _, c := range cases {
		if got := goVersionAtLeast(c.version, 1, 14); got != c.want {
			t.Errorf("goVersionAtLeast(%q, 1, 14) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestParseGoVersion(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"module example.com/app\n\ngo 1.24.4\n", "1.24.4"},
		{"module example.com/app\n\ngo 1.13\n", "1.13"},
		{"module example.com/app\n", ""}, // no go directive at all
		{"module example.com/app\n\ngo 1.21 // some comment\n", "1.21"},
	}
	for _, c := range cases {
		if got := parseGoVersion([]byte(c.content)); got != c.want {
			t.Errorf("parseGoVersion(%q) = %q, want %q", c.content, got, c.want)
		}
	}
}

func TestVendorModeActive(t *testing.T) {
	dir := t.TempDir()
	vendorTxt := filepath.Join(dir, "vendor", "modules.txt")

	// No vendor/modules.txt at all: never active regardless of go version.
	if vendorModeActive("", "1.24.4", vendorTxt) {
		t.Error("vendorModeActive should be false with no vendor/modules.txt present")
	}

	if err := os.MkdirAll(filepath.Dir(vendorTxt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendorTxt, []byte("# example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// vendor/modules.txt present + go >= 1.14: auto-vendor default applies.
	if !vendorModeActive("", "1.24.4", vendorTxt) {
		t.Error("vendorModeActive should be true: vendor/modules.txt present, go 1.24.4, no override")
	}

	// vendor/modules.txt present but go < 1.14: auto-vendor default does
	// NOT apply (verified live against the real go command).
	if vendorModeActive("", "1.13", vendorTxt) {
		t.Error("vendorModeActive should be false: go < 1.14 doesn't auto-vendor even with vendor/modules.txt present")
	}

	// Explicit -mod=mod overrides the auto-default even with vendor/
	// modules.txt present and go >= 1.14.
	if vendorModeActive("-mod=mod", "1.24.4", vendorTxt) {
		t.Error("vendorModeActive should be false: explicit -mod=mod overrides the vendor auto-default")
	}

	// Explicit -mod=vendor is active even without a real vendor/modules.txt
	// (go itself would fail in that case, a separate problem).
	if !vendorModeActive("-mod=vendor", "1.24.4", filepath.Join(dir, "nonexistent", "modules.txt")) {
		t.Error("vendorModeActive should be true: explicit -mod=vendor forces vendor mode")
	}
}
