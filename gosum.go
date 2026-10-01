package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// parseGoSumKeys extracts the "<module> <version>" / "<module>
// <version>/go.mod" key pairs recorded in a go.sum file's lines, ignoring
// the hash values themselves — this tool only needs to know THAT an entry
// is already pinned locally, not what it's pinned to (see
// goSumCoversModule, the only reader of this map). Mirrors
// cmd/go/internal/modfetch's own go.sum line format exactly: "<module
// path> <version>[/go.mod] <h1:hash>", three whitespace-separated fields
// (golang.org/x/mod/sumdb/dirhash's own H1 format never contains
// whitespace), so a plain strings.Fields split is enough. A blank line or
// one with fewer than two fields is skipped rather than erroring — the
// same forgiving convention every other best-effort file reader in this
// tool (netrc.go, gitconfig.go, ...) already uses for a file it doesn't
// control the contents of.
func parseGoSumKeys(data []byte) map[string]bool {
	keys := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		keys[fields[0]+" "+fields[1]] = true
	}
	return keys
}

// goSumCoversModule reports whether goSumKeys (see parseGoSumKeys) already
// contains BOTH checksum lines the real go toolchain tracks independently
// for module@version: the module's own content hash ("<module> <version>
// h1:...") and its go.mod file's hash ("<module> <version>/go.mod
// h1:..."). Both matter, not just one — live-verified (go1.24.4, a fresh
// GOMODCACHE, GOFLAGS=-mod=mod, and GOSUMDB pointed at a deliberately
// unreachable host): dropping just the "/go.mod" line from an otherwise-
// complete go.sum still makes a real `go build` Fatal trying to reach
// GOSUMDB ("verifying go.mod: ... initializing sumdb.Client: ... connect:
// connection refused"), and dropping just the content-hash line Fatals the
// identical way one step earlier ("verifying module: ... connection
// refused"). Only when both lines are already present does `go build`
// verify the downloaded content purely against the existing go.sum, with
// no GOSUMDB query at all — live-verified the same way, succeeding even
// with GOSUMDB unreachable and GOMODCACHE completely empty, both under the
// default -mod=readonly and under an explicit -mod=mod.
func goSumCoversModule(goSumKeys map[string]bool, module, version string) bool {
	if version == "" {
		return false
	}
	return goSumKeys[module+" "+version] && goSumKeys[module+" "+version+"/go.mod"]
}

// filterGoSumCovered drops any module from modules whose go.sum entry (read
// from moduleDir's own go.sum — live-verified to be consulted and
// sufficient on its own even inside an active go.work workspace, with no
// go.work.sum present at all: a two-module workspace built from a member
// directory whose own go.sum already had both lines for its one dependency
// succeeded fully offline, GOSUMDB pointed at an unreachable host) already
// covers (see goSumCoversModule) the exact version `go` would actually
// request for it. Per `go help module-auth`, go.sum is this tool's second
// real, checked-in "cannot leak" source, distinct from (and unlike) the
// local module cache this package's own doc comment already explains
// GOPROXY=off can't reliably stand in for: go.sum is a file sitting right
// next to go.mod in the repository, not transient machine-local state this
// tool has no visibility into, so — unlike GOPROXY=off — treating an
// existing go.sum entry as a real guarantee doesn't require guessing about
// anything this tool can't see.
//
// Before this existed, goprivaudit reported SUMDB LEAK for every uncovered
// private-auth-signaled require regardless of go.sum's own contents — an
// active wrong claim in the extremely common case of a go.mod/go.sum pair
// already committed together (standard practice for any repo that's been
// built/tidied at least once): per goSumCoversModule's own doc comment, a
// real `go build`/`go test` under the default -mod=readonly (or an explicit
// -mod=mod) never queries GOSUMDB for a module@version go.sum already has
// both lines for, so the query this tool's whole purpose is to flag cannot
// actually happen for that module on any ordinary subsequent build.
//
// Deliberately scoped to a require whose own path is NOT touched by any
// replace directive at all: a locally-replaced require is already dropped
// from modules upstream (resolveEffectiveModules), and a module-path-
// replaced one resolves to a different effective path at a version this
// tool's replaceTarget never records (see its own doc comment) — go.sum
// coverage can only be checked against a version this tool actually knows,
// so a replaced require's effective path is left for the ordinary audit
// path rather than guessed at. This can only miss a real suppression
// opportunity (replaced modules keep being audited exactly as before), not
// introduce a false "no issues found".
func filterGoSumCovered(modules []string, requires []requireEntry, replaces map[string][]replaceEntry, moduleDir string) []string {
	data, err := os.ReadFile(filepath.Join(moduleDir, "go.sum"))
	if err != nil {
		return modules
	}
	goSumKeys := parseGoSumKeys(data)
	if len(goSumKeys) == 0 {
		return modules
	}

	versions := make(map[string]string, len(requires))
	for _, r := range requires {
		if _, replaced := selectReplace(replaces[r.path], r.version); replaced {
			continue
		}
		versions[r.path] = r.version
	}

	out := make([]string, 0, len(modules))
	for _, m := range modules {
		if v, ok := versions[m]; ok && goSumCoversModule(goSumKeys, m, v) {
			continue
		}
		out = append(out, m)
	}
	return out
}
