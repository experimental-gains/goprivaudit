package main

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// TestGomodDirectivesAgainstModfileOracle is an oracle-diff test for
// parseRequires/parseTools/parseReplaces — gomod.go's hand-rolled line
// scanner, chosen over golang.org/x/mod/modfile for the reasons in
// parseRequires' doc comment — against modfile.Parse itself, the real
// go.mod grammar this tool's own doc comments already claim to mirror in
// several places (require/tool block syntax, replace directive shape,
// quoted-string tokens). Every fix so far in this file (comment-in-quote
// handling, no-space-before-paren, bare "." / ".." replace targets, the
// version-specific-vs-general replace precedence bug this run fixed) was
// found and verified by hand, one example at a time; this generalizes
// that verification the way run #155's gitconfig real-git oracle and the
// isDirectoryPath modfile oracle already did for their own files.
//
// Unlike a native `go test -fuzz` byte-mutation target, this builds
// structurally valid go.mod text from a generator (raw byte fuzzing of
// go.mod source was already tried and abandoned per the run #154 decision
// log — most mutated byte strings don't parse at all, so a generator that
// only ever emits valid directives is the only way to exercise this
// parser's actual behavior at scale). Requires/tools/replace old-paths are
// kept unique per generated file and no two replace directives ever share
// both the same old path and old version, since a real go.mod containing
// either is a modfile.Parse error unrelated to what this test targets;
// any go.mod that still fails to parse is skipped rather than asserted
// on, the same escape hatch FuzzMatchesPrefixPattern uses for
// oracle-unreachable inputs.
func TestGomodDirectivesAgainstModfileOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(7))

	hosts := []string{"example.com", "github.com", "golang.org", "corp.internal"}
	randPath := func(segs int) string {
		var b strings.Builder
		b.WriteString(hosts[rng.Intn(len(hosts))])
		for i := 0; i < segs; i++ {
			fmt.Fprintf(&b, "/seg%d", rng.Intn(50))
		}
		return b.String()
	}
	versions := []string{
		"v0.0.0", "v1.0.0", "v1.2.3", "v2.0.0",
		"v0.0.0-20230101000000-abcdef123456",
	}
	randVersion := func() string { return versions[rng.Intn(len(versions))] }

	for iter := 0; iter < 3000; iter++ {
		usedPaths := map[string]bool{}
		uniquePath := func(segs int) string {
			for {
				p := randPath(segs)
				if !usedPaths[p] {
					usedPaths[p] = true
					return p
				}
			}
		}

		type req struct{ path, version string }
		var reqs []req
		nReqs := rng.Intn(5)
		for i := 0; i < nReqs; i++ {
			reqs = append(reqs, req{uniquePath(1 + rng.Intn(2)), randVersion()})
		}

		var tools []string
		nTools := rng.Intn(3)
		for i := 0; i < nTools; i++ {
			tools = append(tools, uniquePath(2+rng.Intn(2)))
		}

		type repl struct {
			oldPath, oldVersion string
			newPath, newVersion string
			local               bool
		}
		var repls []repl
		usedReplaceKey := map[string]bool{}
		nRepls := rng.Intn(4)
		for i := 0; i < nRepls; i++ {
			var oldPath string
			var oldVersion string
			if len(reqs) > 0 && rng.Intn(2) == 0 {
				r := reqs[rng.Intn(len(reqs))]
				oldPath = r.path
				if rng.Intn(2) == 0 {
					oldVersion = r.version // version-specific replace matching the require
				} // else general (applies to all versions)
			} else {
				oldPath = uniquePath(1 + rng.Intn(2))
				if rng.Intn(2) == 0 {
					oldVersion = randVersion()
				}
			}
			key := oldPath + "@" + oldVersion
			if usedReplaceKey[key] {
				continue // avoid a duplicate (oldPath, oldVersion) pair - real go.mod rejects it
			}
			usedReplaceKey[key] = true

			r := repl{oldPath: oldPath, oldVersion: oldVersion}
			if rng.Intn(2) == 0 {
				r.local = true
				dirs := []string{"../local", "./vendor/x", ".", ".."}
				r.newPath = dirs[rng.Intn(len(dirs))]
			} else {
				r.newPath = uniquePath(1 + rng.Intn(2))
				r.newVersion = randVersion()
			}
			repls = append(repls, r)
		}

		var src strings.Builder
		src.WriteString("module scratch\n\ngo 1.22\n\n")
		for _, r := range reqs {
			if rng.Intn(2) == 0 {
				fmt.Fprintf(&src, "require %s %s\n", r.path, r.version)
			} else {
				fmt.Fprintf(&src, "require (\n\t%s %s\n)\n", r.path, r.version)
			}
		}
		for _, tp := range tools {
			if rng.Intn(2) == 0 {
				fmt.Fprintf(&src, "tool %s\n", tp)
			} else {
				fmt.Fprintf(&src, "tool (\n\t%s\n)\n", tp)
			}
		}
		for _, r := range repls {
			lhs := r.oldPath
			if r.oldVersion != "" {
				lhs += " " + r.oldVersion
			}
			rhs := r.newPath
			if r.newVersion != "" {
				rhs += " " + r.newVersion
			}
			if rng.Intn(2) == 0 {
				fmt.Fprintf(&src, "replace %s => %s\n", lhs, rhs)
			} else {
				fmt.Fprintf(&src, "replace (\n\t%s => %s\n)\n", lhs, rhs)
			}
		}
		data := []byte(src.String())

		mf, err := modfile.Parse("go.mod", data, nil)
		if err != nil {
			continue // generator produced something the real parser rejects; not this test's target
		}

		var wantReqs []requireEntry
		for _, r := range mf.Require {
			wantReqs = append(wantReqs, requireEntry{path: r.Mod.Path, version: r.Mod.Version})
		}
		if gotReqs := parseRequires(data); !reflect.DeepEqual(gotReqs, wantReqs) {
			t.Fatalf("iter %d: parseRequires mismatch\nsrc:\n%s\ngot:  %#v\nwant: %#v", iter, data, gotReqs, wantReqs)
		}

		var wantTools []string
		for _, tl := range mf.Tool {
			wantTools = append(wantTools, tl.Path)
		}
		if gotTools := parseTools(data); !reflect.DeepEqual(gotTools, wantTools) {
			t.Fatalf("iter %d: parseTools mismatch\nsrc:\n%s\ngot:  %#v\nwant: %#v", iter, data, gotTools, wantTools)
		}

		wantReplaces := map[string][]replaceEntry{}
		for _, r := range mf.Replace {
			e := replaceEntry{
				oldVersion: r.Old.Version,
				target: replaceTarget{
					path:    r.New.Path,
					isLocal: modfile.IsDirectoryPath(r.New.Path),
				},
			}
			wantReplaces[r.Old.Path] = append(wantReplaces[r.Old.Path], e)
		}
		if gotReplaces := parseReplaces(data); !reflect.DeepEqual(gotReplaces, wantReplaces) {
			t.Fatalf("iter %d: parseReplaces mismatch\nsrc:\n%s\ngot:  %#v\nwant: %#v", iter, data, gotReplaces, wantReplaces)
		}
	}
}
