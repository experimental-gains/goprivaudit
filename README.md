# goprivaudit

Audits a Go module's `GOPRIVATE`/`GONOSUMDB` configuration against its
`go.mod` dependencies and git `insteadOf` rewrites, catching two silent
misconfigurations around private Go modules:

1. **Sumdb leaks.** If you've set up a git `insteadOf` rewrite to
   authenticate `go get` to a private host over SSH (the standard way to
   let the `go` tool fetch a private module), but forgot to add that
   module's path to `GOPRIVATE`/`GONOSUMDB`, the `go` command still queries
   the public checksum database (`sum.golang.org`) for it on every build.
   The source fetch is private; the module's existence, path, and version
   are not — they leak to Google's sumdb regardless.
2. **Overly broad patterns.** A bare `GOPRIVATE=*` (or `GONOSUMDB=*`)
   "fixes" the leak above but also disables checksum verification for
   every public dependency in the module, silently removing supply-chain
   protection you almost certainly still want.

It makes no network calls. Everything it checks — `go.mod`, git config,
`go env` output — is local.

## Install

```sh
go install github.com/experimental-gains/goprivaudit@latest
```

Or via Homebrew:

```sh
brew install experimental-gains/tap/goprivaudit
```

## Usage

```sh
cd your-module
goprivaudit
```

```
SUMDB LEAK: github.com/myorg/internal-tool has a private-auth git rewrite but is not covered by GOPRIVATE/GONOSUMDB — its path and version will be sent to the public checksum database
```

Exits `0` with "no issues found" when clean, `1` when it finds something,
`2` on a usage/read error — so it's CI-gateable as-is:

```sh
goprivaudit || exit 1
```

Flags, mainly for testing/CI overrides:

```
-gomod string    path to the go.mod file to audit (default "go.mod")
-private string  override GOPRIVATE instead of reading it from `go env`
-nosumdb string  override GONOSUMDB instead of reading it from `go env`
```

## How it detects "this module should be private"

It looks for git `insteadOf`/`pushInsteadOf` rewrites in `~/.gitconfig`
and the module's `.git/config` — the standard way to point `go get` at an
authenticated SSH remote for a host you don't want to fetch anonymously,
e.g.:

```gitconfig
[url "git@github.com:myorg/"]
	insteadOf = https://github.com/myorg/
```

Any `go.mod` dependency whose path falls under a rewritten prefix is
treated as having a private-auth signal, then checked against
`GOPRIVATE`/`GONOSUMDB` using the same glob-per-path-segment, prefix-match
semantics the `go` command itself uses (see `go help goproxy`).

## What it does not do

- Doesn't modify `GOPRIVATE`, your gitconfig, `.netrc`, or any auth.
- Doesn't make network calls or hit `proxy.golang.org`/`sum.golang.org`.
- Doesn't replace `govulncheck` or general dependency vulnerability
  scanning — this is specifically about the private-module
  configuration gap, not vulnerabilities in the dependencies themselves.

## License

MIT
