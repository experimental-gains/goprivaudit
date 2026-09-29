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
		// A whole flag wrapped in quotes (real go's documented way to carry
		// an embedded space, `go help environment`) must still be recognized
		// — see quotedFields' doc comment for the live-verified false
		// "vendor mode active" this produced pre-fix.
		{`"-mod=mod"`, "mod", true},
		{`'-mod=vendor'`, "vendor", true},
		{`"-tags=a b" -mod=vendor`, "vendor", true},
		{`-mod=mod "-tags=a b"`, "mod", true},
		// A bare "-mod=" (explicitly empty value): real go's own
		// explicitStringFlag.Set (cmd/go/internal/base/flag.go) only ever
		// sets cfg.BuildModExplicit when the value being set is non-empty,
		// so this must NOT count as an explicit override — it behaves
		// exactly as if -mod had never been mentioned at all. Verified
		// live: with a real vendor/modules.txt present (go >= 1.14, no
		// workspace) and an unreachable GOPROXY, `GOFLAGS=-mod= go list -m
		// all` fails with "can't compute 'all' using the vendor
		// directory" — proof go auto-vendored, the same as if GOFLAGS were
		// empty — not proof it forced a non-vendor mode.
		{"-mod=", "", false},
		// Compound: an earlier non-empty "-mod=vendor" makes ok sticky
		// true even though the LAST occurrence's value is empty and wins
		// for value itself — mirroring cfg.BuildModExplicit never being
		// reset to false by a later Set(""). Verified live: inside an
		// active go.work workspace, `GOFLAGS="-mod=vendor -mod=" go list
		// -m all` still Fatals with go's workspace "-mod may only be set
		// to readonly or vendor" error (value ""), unlike a bare "-mod="
		// alone, which does not Fatal.
		{"-mod=vendor -mod=", "", true},
	}
	for _, c := range cases {
		value, ok := explicitModFlag(c.goflags)
		if value != c.wantValue || ok != c.wantOK {
			t.Errorf("explicitModFlag(%q) = (%q, %v), want (%q, %v)", c.goflags, value, ok, c.wantValue, c.wantOK)
		}
	}
}

func TestGoflagsMalformed(t *testing.T) {
	cases := []struct {
		goflags string
		want    bool
	}{
		{"", false},
		{"-mod=vendor", false},
		{"-race -mod=vendor -v", false},
		{`"-mod=mod"`, false},
		{`'-mod=vendor'`, false},
		// The exact live-verified divergence: a space-separated "-mod
		// vendor" splits into two GOFLAGS entries, "-mod" and "vendor" —
		// the second doesn't start with "-" at all, which real go's
		// InitGOFLAGS Fatals on immediately for every module-aware
		// subcommand (`go: parsing $GOFLAGS: non-flag "vendor"`), unlike a
		// real argv where "-mod vendor" is a valid two-token flag/value
		// pair. GOFLAGS entries are never re-paired with a following token
		// the way a real command line is.
		{"-mod vendor", true},
		{"-mod mod", true},
		{"-race -mod mod", true},
		// A bare word with no leading dash at all is invalid on its own.
		{"vendor", true},
		// Real go's own carve-outs for a bare/doubled/equals-only dash.
		{"-", true},
		{"--", true},
		{"---mod=vendor", true},
		{"-=vendor", true},
		{"--=vendor", true},
		// A flag with no value at all is still shaped like a flag (no
		// following bare-word token to trip the check).
		{"-mod", false},
		{"-mod=", false},
	}
	for _, c := range cases {
		if got := goflagsMalformed(c.goflags); got != c.want {
			t.Errorf("goflagsMalformed(%q) = %v, want %v", c.goflags, got, c.want)
		}
	}
}

// TestGoflagsInvalidModValue is the regression test for the third
// distinct GOFLAGS "-mod" divergence goflagsMalformed/goflagsRejectedByGo
// don't catch: a syntactically valid "-mod=X" whose X isn't one of the
// four real go accepts. Verified live: `GOFLAGS=-mod=Vendor go list -m`
// (capitalized, a plausible typo of the correct lowercase "vendor")
// exits 1 with "-mod=Vendor not supported (can be ”, 'mod', 'readonly',
// or 'vendor')" — a message that, unlike goflagsRejectedByGo's cases,
// never mentions "$GOFLAGS" at all — before resolving a single module.
func TestGoflagsInvalidModValue(t *testing.T) {
	cases := []struct {
		goflags string
		want    bool
	}{
		{"", false},
		{"-race", false},
		// The four values real go actually accepts.
		{"-mod=", false},
		{"-mod=mod", false},
		{"-mod=readonly", false},
		{"-mod=vendor", false},
		{"--mod=vendor", false},
		{`"-mod=vendor"`, false},
		// Wrong-cased or simply invalid values: real go Fatals with
		// "-mod=X not supported (can be '', 'mod', 'readonly', or
		// 'vendor')" for every one of these, verified live for "Vendor".
		{"-mod=Vendor", true},
		{"-mod=Mod", true},
		{"-mod=readOnly", true},
		{"-mod=bogus", true},
		{"--mod=Vendor", true},
		{`"-mod=Vendor"`, true},
		{"-race -mod=Vendor -v", true},
		// Repeated flag: only the last one (what explicitModFlag itself
		// resolves to) determines the result, same last-wins precedence as
		// explicitModFlag.
		{"-mod=Vendor -mod=vendor", false},
		{"-mod=vendor -mod=Vendor", true},
		// No explicit -mod= entry at all: nothing to reject here (a bare
		// "-mod" with no value is goflagsRejectedByGo's territory, not
		// this function's).
		{"-mod", false},
	}
	for _, c := range cases {
		if got := goflagsInvalidModValue(c.goflags); got != c.want {
			t.Errorf("goflagsInvalidModValue(%q) = %v, want %v", c.goflags, got, c.want)
		}
	}
}

// TestGoflagsModRejectedInWorkspace is the regression test for the bug
// found via real-world-testing pass: cmd/go's setDefaultBuildMod
// (go/src/cmd/go/internal/modload/init.go) restricts -mod to "readonly" or
// "vendor" specifically inside an active go.work workspace — "-mod=mod",
// perfectly valid standalone, Fatals immediately once GOWORK points at a
// real workspace, before resolving a single module. Verified live:
// `GOFLAGS=-mod=mod go list -m all` (and `go build`) both exit 1 with
// "go: -mod may only be set to readonly or vendor when in workspace mode,
// but it is set to \"mod\"" when GOWORK is active, and both exit 0 with the
// identical GOFLAGS when GOWORK=off. Neither goflagsInvalidModValue ("mod"
// is one of the four values it accepts) nor vendorModeActive (only checks
// for "vendor") caught this on their own.
func TestGoflagsModRejectedInWorkspace(t *testing.T) {
	cases := []struct {
		goflags string
		gowork  string
		want    bool
	}{
		// No workspace: "-mod=mod" is completely normal.
		{"-mod=mod", "", false},
		{"-mod=mod", "off", false},
		// Active workspace, "-mod=mod": the live-verified Fatal case.
		{"-mod=mod", "/repo/go.work", true},
		// Active workspace, the two values go itself still accepts there.
		{"-mod=readonly", "/repo/go.work", false},
		{"-mod=vendor", "/repo/go.work", false},
		// Active workspace, no explicit -mod= at all: nothing to reject
		// (the auto-default applies instead, handled elsewhere).
		{"", "/repo/go.work", false},
		{"-race", "/repo/go.work", false},
		// Active workspace, a bare "-mod=" (empty, not explicit per
		// explicitModFlag's sticky-ok semantics): does not Fatal, same as
		// no -mod= at all.
		{"-mod=", "/repo/go.work", false},
		// Active workspace, an already-invalid value: also Fatals, via
		// this same workspace-mode check (verified live: the workspace
		// message fires, not goflagsInvalidModValue's "-mod=bogus not
		// supported" message) — goflagsBad ORs both checks so the overlap
		// is harmless either way.
		{"-mod=bogus", "/repo/go.work", true},
		// Compound: sticky ok (from the earlier non-empty "vendor") but a
		// final empty value — verified live this still Fatals inside a
		// workspace, unlike a bare "-mod=" alone.
		{"-mod=vendor -mod=", "/repo/go.work", true},
	}
	for _, c := range cases {
		if got := goflagsModRejectedInWorkspace(c.goflags, c.gowork); got != c.want {
			t.Errorf("goflagsModRejectedInWorkspace(%q, %q) = %v, want %v", c.goflags, c.gowork, got, c.want)
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
	if vendorModeActive("", "1.24.4", vendorTxt, "") {
		t.Error("vendorModeActive should be false with no vendor/modules.txt present")
	}

	if err := os.MkdirAll(filepath.Dir(vendorTxt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendorTxt, []byte("# example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// vendor/modules.txt present + go >= 1.14: auto-vendor default applies.
	if !vendorModeActive("", "1.24.4", vendorTxt, "") {
		t.Error("vendorModeActive should be true: vendor/modules.txt present, go 1.24.4, no override")
	}

	// vendor/modules.txt present but go < 1.14: auto-vendor default does
	// NOT apply (verified live against the real go command).
	if vendorModeActive("", "1.13", vendorTxt, "") {
		t.Error("vendorModeActive should be false: go < 1.14 doesn't auto-vendor even with vendor/modules.txt present")
	}

	// Explicit -mod=mod overrides the auto-default even with vendor/
	// modules.txt present and go >= 1.14.
	if vendorModeActive("-mod=mod", "1.24.4", vendorTxt, "") {
		t.Error("vendorModeActive should be false: explicit -mod=mod overrides the vendor auto-default")
	}

	// Explicit -mod=vendor is active even without a real vendor/modules.txt
	// (go itself would fail in that case, a separate problem).
	if !vendorModeActive("-mod=vendor", "1.24.4", filepath.Join(dir, "nonexistent", "modules.txt"), "") {
		t.Error("vendorModeActive should be true: explicit -mod=vendor forces vendor mode")
	}

	// An active go.work workspace suppresses the auto-default even though
	// every per-module condition (vendor/modules.txt present, go >= 1.14)
	// is met — verified live against the real go toolchain: a per-module
	// vendor/ directory that would auto-vendor standalone is silently
	// ignored the moment GOWORK points at a real workspace file, and `go
	// build` inside that member module reaches the network exactly as if
	// no vendor/ existed at all. Workspace-wide vendoring is a distinct,
	// opt-in mechanism (`go work vendor` + explicit -mod=vendor) covered by
	// the explicit-override branch above, not this auto-default.
	if vendorModeActive("", "1.24.4", vendorTxt, filepath.Join(dir, "go.work")) {
		t.Error("vendorModeActive should be false: an active workspace suppresses the per-module vendor auto-default")
	}

	// GOWORK=off (workspace mode explicitly disabled) must NOT suppress the
	// auto-default, matching goWorkReplaces' existing "" / "off" convention.
	if !vendorModeActive("", "1.24.4", vendorTxt, "off") {
		t.Error("vendorModeActive should be true: GOWORK=off means no workspace, auto-default still applies")
	}

	// An explicit -mod=vendor override still forces vendor mode inside an
	// active workspace (the override branch is checked before the
	// workspace suppression, matching real go: an explicit flag always
	// wins over any auto-default in either direction).
	if !vendorModeActive("-mod=vendor", "1.24.4", vendorTxt, filepath.Join(dir, "go.work")) {
		t.Error("vendorModeActive should be true: explicit -mod=vendor overrides workspace suppression too")
	}

	// A quoted "-mod=mod" (real go's documented way to write a GOFLAGS
	// entry, and a realistic defensive-quoting habit even without an
	// embedded space) must still override the auto-vendor default, exactly
	// like its unquoted form above. Pre-fix, explicitModFlag's
	// strings.Fields split left the surrounding quotes on the token,
	// so this was never recognized as a "-mod=" flag at all, and
	// vendorModeActive fell through to the auto-default (true, since
	// vendor/modules.txt exists and go >= 1.14) — silently claiming vendor
	// mode was active, and skipping the audit, while the real go command
	// (verified live, see quotedFields' doc comment) actually reaches the
	// network for this exact GOFLAGS value.
	if vendorModeActive(`"-mod=mod"`, "1.24.4", vendorTxt, "") {
		t.Error("vendorModeActive should be false: quoted \"-mod=mod\" overrides the vendor auto-default same as unquoted -mod=mod")
	}
}

// TestVendorModeActiveWorkspaceAutoVendor is the regression test for the
// bug found via real-world-testing pass: `go work vendor` produces a
// workspace-ROOT vendor/modules.txt (annotated "## workspace") that real
// go's setDefaultBuildMod auto-defaults to vendor mode for, even with no
// explicit -mod=vendor override at all — a distinct auto-default from the
// per-module one vendorModeActive already modeled, keyed off go.work's own
// directory and its own `go` directive, not the audited module's. Live-
// verified against real go1.24.4: a two-module workspace vendored via
// `go work vendor`, no -mod= override, unreachable GOPROXY — `go build`
// inside a member module succeeds fully offline. Pre-fix, vendorModeActive
// returned false unconditionally the moment gowork was set to anything
// other than ""/"off", so goprivaudit's own audit ran for a query that
// structurally cannot happen, reporting a false SUMDB LEAK.
func TestVendorModeActiveWorkspaceAutoVendor(t *testing.T) {
	dir := t.TempDir()
	gowork := filepath.Join(dir, "go.work")
	if err := os.WriteFile(gowork, []byte("go 1.24.4\n\nuse ./member\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workspaceVendorTxt := filepath.Join(dir, "vendor", "modules.txt")
	if err := os.MkdirAll(filepath.Dir(workspaceVendorTxt), 0o755); err != nil {
		t.Fatal(err)
	}

	// No workspace-root vendor/modules.txt yet: the workspace auto-default
	// doesn't apply (same as no vendor/ directory at all outside a
	// workspace).
	if vendorModeActive("", "1.24.4", filepath.Join(dir, "member", "vendor", "modules.txt"), gowork) {
		t.Error("vendorModeActive should be false: no workspace-root vendor/modules.txt present yet")
	}

	// A workspace-root vendor/modules.txt that was NOT produced by
	// `go work vendor` (no "## workspace" annotation — e.g. a stray `go mod
	// vendor` output) must not trigger the workspace auto-default either,
	// matching real go's own mismatch check.
	if err := os.WriteFile(workspaceVendorTxt, []byte("# example.com/mainmod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if vendorModeActive("", "1.24.4", filepath.Join(dir, "member", "vendor", "modules.txt"), gowork) {
		t.Error("vendorModeActive should be false: workspace-root vendor/modules.txt isn't annotated for a workspace")
	}

	// A real `go work vendor`-shaped modules.txt (starts "## workspace"):
	// the workspace-level auto-default now applies, live-verified above.
	if err := os.WriteFile(workspaceVendorTxt, []byte("## workspace\n# example.com/mainmod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !vendorModeActive("", "1.24.4", filepath.Join(dir, "member", "vendor", "modules.txt"), gowork) {
		t.Error("vendorModeActive should be true: workspace-root vendor/modules.txt is annotated for a workspace, go.work go directive >= 1.14")
	}

	// An explicit -mod=mod override still suppresses the workspace
	// auto-default too, matching every other override case.
	if vendorModeActive("-mod=mod", "1.24.4", filepath.Join(dir, "member", "vendor", "modules.txt"), gowork) {
		t.Error("vendorModeActive should be false: explicit -mod=mod overrides the workspace auto-default")
	}

	// go.work's own `go` directive below 1.14 suppresses the workspace
	// auto-default, mirroring the per-module go-version gate.
	if err := os.WriteFile(gowork, []byte("go 1.13\n\nuse ./member\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if vendorModeActive("", "1.24.4", filepath.Join(dir, "member", "vendor", "modules.txt"), gowork) {
		t.Error("vendorModeActive should be false: go.work's own go directive is below 1.14")
	}
}

// TestVendorModeActiveMismatchedWorkspaceAnnotation is the non-workspace
// counterpart: a per-module vendor/modules.txt annotated "## workspace" (a
// realistic leftover from a directory that used to be a workspace root, or
// content copied from one) must NOT trigger the per-module auto-default
// outside an active workspace either — live-verified against real go1.24.4:
// copying a genuine `go work vendor` vendor/ tree into a plain module
// directory and running `GOWORK=off go build` with an unreachable GOPROXY
// fails with "missing go.sum entry", proof real go reached the network
// rather than using the mismatched vendor/ directory.
func TestVendorModeActiveMismatchedWorkspaceAnnotation(t *testing.T) {
	dir := t.TempDir()
	vendorTxt := filepath.Join(dir, "vendor", "modules.txt")
	if err := os.MkdirAll(filepath.Dir(vendorTxt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendorTxt, []byte("## workspace\n# example.com/mainmod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if vendorModeActive("", "1.24.4", vendorTxt, "") {
		t.Error("vendorModeActive should be false: vendor/modules.txt is annotated for a workspace but no workspace is active")
	}
	if vendorModeActive("", "1.24.4", vendorTxt, "off") {
		t.Error("vendorModeActive should be false: GOWORK=off, vendor/modules.txt annotated for a workspace, still a mismatch")
	}
}

func TestQuotedFields(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"-mod=vendor", []string{"-mod=vendor"}},
		{"-race -mod=vendor -v", []string{"-race", "-mod=vendor", "-v"}},
		{`"-mod=mod"`, []string{"-mod=mod"}},
		{`'-mod=vendor'`, []string{"-mod=vendor"}},
		{`"-tags=a b" -mod=vendor`, []string{"-tags=a b", "-mod=vendor"}},
		{`"unterminated`, nil}, // real go Fatals here; best-effort empty
	}
	for _, c := range cases {
		got := quotedFields(c.in)
		if len(got) != len(c.want) {
			t.Errorf("quotedFields(%q) = %#v, want %#v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("quotedFields(%q) = %#v, want %#v", c.in, got, c.want)
				break
			}
		}
	}
}
