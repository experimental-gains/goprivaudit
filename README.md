# goprivaudit

[![Go Reference](https://pkg.go.dev/badge/github.com/experimental-gains/goprivaudit.svg)](https://pkg.go.dev/github.com/experimental-gains/goprivaudit)
[![License: MIT](https://img.shields.io/github/license/experimental-gains/goprivaudit)](LICENSE)
[![Latest release](https://img.shields.io/github/v/tag/experimental-gains/goprivaudit)](https://github.com/experimental-gains/goprivaudit/releases)

Audits a Go module's `GOPRIVATE`/`GONOSUMDB` configuration against its
`go.mod` dependencies and its private-module auth setup — git `insteadOf`
rewrites, git credential helpers, URL-scoped extra HTTP headers, and
netrc credentials — catching two silent misconfigurations around private
Go modules:

1. **Sumdb leaks.** If you've set up a git `insteadOf` rewrite, a git
   credential helper, a URL-scoped `http.<url>.extraHeader`, or netrc
   credentials to authenticate `go get` to a
   private host, but forgot to add that module's path to
   `GOPRIVATE`/`GONOSUMDB`, the `go` command
   still queries the public checksum database (`sum.golang.org`) for it
   on every build. The source fetch is private; the module's existence,
   path, and version are not — they leak to Google's sumdb regardless.
2. **Overly broad patterns.** A bare `GOPRIVATE=*` (or `GONOSUMDB=*`)
   "fixes" the leak above but also disables checksum verification for
   every public dependency in the module, silently removing supply-chain
   protection you almost certainly still want.

It makes no network calls. Everything it checks — `go.mod`, git config,
the netrc file, `go env` output — is local.

Both checks are skipped (reported clean) when `GOSUMDB=off`: that setting
disables the checksum database entirely, for every module, so neither
finding can apply — there's no sumdb query happening for anything to leak
from or over-trust.

Both checks are also skipped when the module resolves its dependencies from
a committed `vendor/` directory instead of the network — either because
`vendor/modules.txt` exists next to `go.mod` and the module's `go` directive
is 1.14 or higher (the `go` command's own auto-vendor default; see `go help
modules`), or because `-mod=vendor` is set explicitly via `GOFLAGS`. Verified
live: a vendor-mode build succeeds even with `GOPROXY` unreachable and
`GOSUMDB` left at its default, so there's no sumdb query happening in that
mode either. An explicit `-mod=mod`/`-mod=readonly` in `GOFLAGS` overrides
the vendor auto-default back to the normal network-resolving path, and
`goprivaudit` follows that override too.

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
SUMDB LEAK: github.com/myorg/internal-tool has a private-auth signal (git insteadOf rewrite, git credential helper, extraHeader, or netrc credentials) but is not covered by GOPRIVATE/GONOSUMDB — its path and version will be sent to the public checksum database
```

Exits `0` with "no issues found" when clean, `1` when it finds something,
`2` on a usage/read error — so it's CI-gateable as-is:

```sh
goprivaudit || exit 1
```

## Use as a GitHub Action

```yaml
- uses: experimental-gains/goprivaudit@v0.1.28
```

Flags, mainly for testing/CI overrides:

```
-gomod string    path to the go.mod file to audit (default "go.mod")
-private string  override GOPRIVATE instead of reading it from `go env`
-nosumdb string  override GONOSUMDB instead of reading it from `go env`
-gowork string   override the go.work path instead of reading GOWORK from `go env`
-sumdb string    override GOSUMDB instead of reading it from `go env`
-goflags string  override GOFLAGS instead of reading it from `go env`
```

## Use with pre-commit

```yaml
repos:
  - repo: https://github.com/experimental-gains/goprivaudit
    rev: v0.1.28
    hooks:
      - id: goprivaudit
```

Runs on any commit that touches `go.mod`, auditing the current
`GOPRIVATE`/`GONOSUMDB`/git config in the working tree (it makes no
network calls). `pre-commit` builds the hook via `go install` the first
time.

## How it detects "this module should be private"

Three independent signals, any one is enough to flag a module.

**Git config: insteadOf.** It looks for git `insteadOf`/`pushInsteadOf` rewrites in the same config
files the real `git config` global tier reads — `$XDG_CONFIG_HOME/git/config`
(or `~/.config/git/config` when that's unset) and `~/.gitconfig`, both of
which apply together, not one-or-the-other — plus the module's
`.git/config`. If `GIT_CONFIG_GLOBAL` is set it's honored the way real git
honors it too: that file replaces the whole global tier above, not an
addition to it. It also reads the `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/
`GIT_CONFIG_VALUE_<n>` environment variables (git-config(1)'s file-free way
to inject config — common in scripted/CI setups that deliberately avoid
writing credentials to disk), which a real `git` subprocess — including the
one `go get` spawns — honors identically to a config file. This is the
standard way to point `go get` at an authenticated SSH remote for a host
you don't want to fetch anonymously, e.g.:

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

**Git config: credential helper.** It also looks for a URL-scoped git
credential helper (see `git help gitcredentials`, "CREDENTIAL CONTEXTS")
in the same config files — the mechanism `go`'s own subprocess `git
clone`/`git fetch` uses to authenticate a plain, unrewritten HTTPS URL, no
`insteadOf` rewrite needed at all. This is exactly what `gh auth
setup-git` configures for you:

```gitconfig
[credential "https://github.com/myorg"]
	helper = store
```

A bare-host context (no org/path, e.g. plain `https://github.com` — what
`gh auth setup-git` actually writes by default, since it authenticates a
whole host, not one org) is **not** treated as a signal, the same way a
bare-host `insteadOf` rewrite isn't: it doesn't name a specific private
module, and flagging it would mark every public dependency on that host
as a leak. Only an org- or path-scoped `[credential "..."]` context
counts. An empty `helper = ` value (git's own way to clear an inherited
default before setting a real one — `gh auth setup-git` writes exactly
this pattern) doesn't count either, since it configures no credentials.

**Git config: extraHeader.** It also looks for a URL-scoped
`http.<url>.extraHeader` (git-config(1)) — the mechanism `actions/
checkout` (the default way almost every GitHub Actions Go workflow checks
out code) uses to persist the job's token, by default:

```gitconfig
[http "https://github.example.com/"]
	extraheader = AUTHORIZATION: basic <base64 token>
```

Unlike `insteadOf`/`credential.helper`, this embeds the literal
credential in the config value itself. The same bare-host exemption
applies: `actions/checkout`'s default run against `https://github.com`
(or another known public host) is not flagged, since it isn't
module-specific and would otherwise mark every public dependency checked
out in an ordinary CI job as a leak — but the identical mechanism against
a self-hosted GitHub/GitLab Enterprise instance (a common enterprise
`githubServerUrl` setup) is a genuine per-host private-auth signal.

**Netrc.** It also checks the netrc file (`$NETRC`, or `~/.netrc` — `~/_netrc` on
Windows) for `machine` entries with a login and password. This is easy to
end up relying on by accident: many environments already have a
`~/.netrc` for unrelated tools, and both `go`'s own HTTPS client (via
`GOAUTH`, default `netrc` — `go help goauth`) and a `git` subprocess
fetch (the dominant path for a private, non-proxy-compliant host) consult
it automatically, with nothing module-specific to opt into. Unlike
`go`'s own client, `git` has no notion of `GOAUTH` at all — it always
reads `~/.netrc` for a plain HTTPS remote — so a `machine` entry counts
as a signal unconditionally, regardless of the effective `GOAUTH` value.

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

## Support

This project is free and open source. If it's useful to you, tips are
welcome via [Liberapay](https://liberapay.com/experimental-gains/) or
this ETH address (self-custody, no KYC, no obligation):
`0x87053a1898994043e7476800cB5d4BDB423eADD7`

## License

MIT
