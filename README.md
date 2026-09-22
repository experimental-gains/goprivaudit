# goprivaudit

[![Go Reference](https://pkg.go.dev/badge/github.com/experimental-gains/goprivaudit.svg)](https://pkg.go.dev/github.com/experimental-gains/goprivaudit)
[![License: MIT](https://img.shields.io/github/license/experimental-gains/goprivaudit)](LICENSE)
[![Latest release](https://img.shields.io/github/v/tag/experimental-gains/goprivaudit)](https://github.com/experimental-gains/goprivaudit/releases)

Audits a Go module's `GOPRIVATE`/`GONOSUMDB` configuration against its
`go.mod` dependencies and its private-module auth setup — git `insteadOf`
rewrites and netrc credentials — catching two silent misconfigurations
around private Go modules:

1. **Sumdb leaks.** If you've set up a git `insteadOf` rewrite (or netrc
   credentials) to authenticate `go get` to a private host, but forgot to
   add that module's path to `GOPRIVATE`/`GONOSUMDB`, the `go` command
   still queries the public checksum database (`sum.golang.org`) for it
   on every build. The source fetch is private; the module's existence,
   path, and version are not — they leak to Google's sumdb regardless.
2. **Overly broad patterns.** A bare `GOPRIVATE=*` (or `GONOSUMDB=*`)
   "fixes" the leak above but also disables checksum verification for
   every public dependency in the module, silently removing supply-chain
   protection you almost certainly still want.

It makes no network calls. Everything it checks — `go.mod`, git config,
the netrc file, `go env` output — is local.

## If you hit "could not read Username" or "terminal prompts disabled"

That's the real `go get` error that sends most people looking for a
`GOPRIVATE`/git `insteadOf` fix in the first place — the `go` tool tries
the plain HTTPS path to a private module and there's no credential
prompt available to satisfy it. Verified against a real private-looking
module path with no auth configured:

```
go: github.com/experimental-gains-private-test/nonexistent-repo-for-repro@v0.1.0: invalid version: git ls-remote -q origin in /root/go/pkg/mod/cache/vcs/5c411848ac859bfd85ccfed9106f5f8e8633b853e482c574fe6c70398ee55132: exit status 128:
	fatal: could not read Username for 'https://github.com': terminal prompts disabled
Confirm the import path was entered correctly.
If this is a private repository, see https://golang.org/doc/faq#git_https for additional information.
```

The usual fix is a git `insteadOf` rewrite to fetch over SSH instead —
which is exactly the setup `goprivaudit` audits. Getting the fetch
working is only half the job: once `insteadOf` is in place, `go` can
read the source, but it still checks the module's path and version
against the *public* checksum database unless `GOPRIVATE`/`GONOSUMDB`
also covers that path. `goprivaudit` catches the case where someone
fixes the fetch error above and stops there.

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
SUMDB LEAK: github.com/myorg/internal-tool has a private-auth signal (git insteadOf rewrite or netrc credentials) but is not covered by GOPRIVATE/GONOSUMDB — its path and version will be sent to the public checksum database
```

Exits `0` with "no issues found" when clean, `1` when it finds something,
`2` on a usage/read error — so it's CI-gateable as-is:

```sh
goprivaudit || exit 1
```

## Use as a GitHub Action

```yaml
- uses: experimental-gains/goprivaudit@v0.1.19
```

Flags, mainly for testing/CI overrides:

```
-gomod string    path to the go.mod file to audit (default "go.mod")
-private string  override GOPRIVATE instead of reading it from `go env`
-nosumdb string  override GONOSUMDB instead of reading it from `go env`
-gowork string   override the go.work path instead of reading GOWORK from `go env`
-goauth string   override GOAUTH instead of reading it from `go env`
```

## Use with pre-commit

```yaml
repos:
  - repo: https://github.com/experimental-gains/goprivaudit
    rev: v0.1.19
    hooks:
      - id: goprivaudit
```

Runs on any commit that touches `go.mod`, auditing the current
`GOPRIVATE`/`GONOSUMDB`/git config in the working tree (it makes no
network calls). `pre-commit` builds the hook via `go install` the first
time.

## How it detects "this module should be private"

Two independent signals, either one is enough to flag a module.

**Git config.** It looks for git `insteadOf`/`pushInsteadOf` rewrites in the same config
files the real `git config` global tier reads — `$XDG_CONFIG_HOME/git/config`
(or `~/.config/git/config` when that's unset) and `~/.gitconfig`, both of
which apply together, not one-or-the-other — plus the module's
`.git/config`. This is the standard way to point `go get` at an
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

`[include]` and `[includeIf "gitdir:..."]`/`"gitdir/i:..."` directives
(git-config(1)'s "Includes" — the standard way to scope a different
identity or rewrite to everything under one directory tree, e.g. a work
vs. personal setup) are followed the way git itself resolves them, so a
rewrite living in an included file is still caught. Other `includeIf`
condition kinds (`onbranch:`, `hasconfig:`, ...) aren't evaluated.

**Netrc.** It also checks the netrc file (`$NETRC`, or `~/.netrc` — `~/_netrc` on
Windows) for `machine` entries with a login and password, since netrc is
`go`'s **default** `GOAUTH` mechanism (`go help goauth`) for authenticating
HTTPS module fetches — no git config or SSH involved at all. This is easy
to end up relying on by accident: many environments already have a
`~/.netrc` for unrelated tools, and `go` starts consulting it for module
fetches automatically, with nothing module-specific to opt into. A
`machine` entry only counts if the effective `GOAUTH` value actually
includes `netrc` (it does by default; `GOAUTH=off` or a fully custom
command list turns this off, and `goprivaudit` follows suit).

## What it does not do

- Doesn't modify `GOPRIVATE`, your gitconfig, `.netrc`, or any auth.
- Doesn't make network calls or hit `proxy.golang.org`/`sum.golang.org`.
- Doesn't replace `govulncheck` or general dependency vulnerability
  scanning — this is specifically about the private-module
  configuration gap, not vulnerabilities in the dependencies themselves.
- Checks `require` entries and `tool` directives (Go 1.24+), including a
  `tool` line with no covering `require` — but doesn't walk the full
  transitive module graph (what those dependencies themselves require).

If your module is part of a [Go workspace](https://go.dev/ref/mod#workspaces),
the workspace's `go.work` can `replace` a dependency that your module's own
`go.mod` never mentions replacing at all — and per `go help work`, a
`go.work` replace overrides a conflicting `go.mod` replace, not the other
way around. `goprivaudit` reads `go env GOWORK` (or `-gowork`) and applies
those replaces on top of `go.mod`'s own before checking anything, so this
is covered automatically; nothing extra to configure.

## License

MIT
