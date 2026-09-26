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

Both checks are also skipped when `GOPROXY`'s effective first chain entry
(comma-separated "try next on not-found", or pipe-separated "try next on
any error" — same precedence `goproxycheck` already applies) is the
literal keyword `off`. That disables all module-proxy-protocol network
access, sumdb lookups included, before a lookup could ever be sent.
Verified live with a local logging HTTP server standing in for `GOSUMDB`'s
URL: with a normal, reachable `GOPROXY`, a real `go get` sent a genuine
`/lookup/<module>@<version>` request to it; with `GOPROXY=off` and the
identical `GOSUMDB` target, `go get` failed immediately with "module
lookup disabled by GOPROXY=off" and the logging server received no
request at all. A later `off` in the chain that isn't the first entry
doesn't count — the real go command only reaches it if every earlier
entry fails first, so a chain like `https://proxy.golang.org,off` is not
treated as blocked.

Both checks are also skipped when the module resolves its dependencies from
a committed `vendor/` directory instead of the network — either because
`vendor/modules.txt` exists next to `go.mod` and the module's `go` directive
is 1.14 or higher (the `go` command's own auto-vendor default; see `go help
modules`), or because `-mod=vendor` is set explicitly via `GOFLAGS`. Verified
live: a vendor-mode build succeeds even with `GOPROXY` unreachable and
`GOSUMDB` left at its default, so there's no sumdb query happening in that
mode either. An explicit `-mod=mod`/`-mod=readonly` in `GOFLAGS` overrides
the vendor auto-default back to the normal network-resolving path, and
`goprivaudit` follows that override too. The auto-default does NOT apply
inside an active [Go workspace](https://go.dev/ref/mod#workspaces) — verified
live, a per-module `vendor/` directory that would auto-vendor on its own is
silently ignored the moment `GOWORK` points at a real workspace file, and
`go build` reaches the network exactly as if no `vendor/` existed. Workspace
vendoring is a separate, opt-in mechanism (`go work vendor`, one `vendor/` at
the workspace root, always paired with an explicit `-mod=vendor`), which
`goprivaudit` still honors as an explicit override either way.

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
- uses: experimental-gains/goprivaudit@v0.1.42
```

Flags, mainly for testing/CI overrides:

```
-gomod string    path to the go.mod file to audit (default "go.mod")
-private string  override GOPRIVATE instead of reading it from `go env`
-nosumdb string  override GONOSUMDB instead of reading it from `go env`
-gowork string   override the go.work path instead of reading GOWORK from `go env`
-sumdb string    override GOSUMDB instead of reading it from `go env`
-goflags string  override GOFLAGS instead of reading it from `go env`
-proxy string    override GOPROXY instead of reading it from `go env`
```

## Use with pre-commit

```yaml
repos:
  - repo: https://github.com/experimental-gains/goprivaudit
    rev: v0.1.42
    hooks:
      - id: goprivaudit
```

Runs on any commit that touches `go.mod`, auditing the current
`GOPRIVATE`/`GONOSUMDB`/git config in the working tree (it makes no
network calls). `pre-commit` builds the hook via `go install` the first
time.

## Use as a Claude Code / Copilot CLI plugin

goprivaudit also ships as a skill in the
[`supplychain-guard`](https://github.com/experimental-gains/claude-plugins)
plugin, so an agent audits `GOPRIVATE`/`go.work` coverage
before committing a `go.mod` change in a repo with private modules:

```
claude plugin marketplace add experimental-gains/claude-plugins
claude plugin install supplychain-guard@experimental-gains-plugins
```

Works the same way with GitHub Copilot CLI (`copilot plugin marketplace add
experimental-gains/claude-plugins`, same install command with `copilot`).

## How it detects "this module should be private"

Three independent signals, any one is enough to flag a module.

**Git config: insteadOf.** It looks for git `insteadOf`/`pushInsteadOf` rewrites in the same config
files the real `git config` global tier reads — `$XDG_CONFIG_HOME/git/config`
(or `~/.config/git/config` when that's unset) and `~/.gitconfig`, both of
which apply together, not one-or-the-other — plus the module's local
config. That local file is resolved the way real git resolves it, not
assumed to always be a plain `.git/config`: inside a `git worktree add`
checkout, `.git` is a file naming a separate per-worktree `$GIT_DIR` that
in turn points at the shared config the main checkout also uses (that's
what a real `go get` run from the worktree actually authenticates with);
inside a submodule checkout, `.git` is also a file, but the `$GIT_DIR` it
names owns its own config directly. Both shapes are followed correctly,
so a rewrite that's only visible through one of them isn't missed. If
`extensions.worktreeConfig` is turned on (`git-worktree(1)`'s own
per-worktree config mechanism, e.g. to isolate a private-registry setup
to one worktree building against a different private branch or fork), the
worktree's own `$GIT_DIR/config.worktree` — a separate file from the
shared config above, only ever consulted by git once the extension is
on — is read too, so a rewrite kept there isn't missed either. If
`GIT_CONFIG_GLOBAL` is set it's honored the way real git honors it too:
that file replaces the whole global tier above, not an addition to it. It also reads the `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/
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

`[include]` and `[includeIf "gitdir:..."]`/`"gitdir/i:..."`/
`"onbranch:..."`/`"onbranch/i:..."` directives (git-config(1)'s
"Includes" — the standard way to scope a different identity or rewrite
to everything under one directory tree, or to one branch/branch
hierarchy, e.g. a work vs. personal setup) are followed the way git
itself resolves them, so a rewrite living in an included file is still
caught. The `hasconfig:` condition kind isn't evaluated (see
`includeIfMatches`'s doc comment for why: resolving it requires a
two-pass scan git itself implements specially).

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

If this caught something useful, a star helps others find it — that's
the main thing. This project is free and open source; if it's useful
to you, tips are also welcome via
[Liberapay](https://liberapay.com/experimental-gains/) or this ETH
address (self-custody, no KYC, no obligation):
`0x87053a1898994043e7476800cB5d4BDB423eADD7`

Build-in-public updates on [Nostr](https://njump.me/npub19ycp547pcykycy9kw3y04fe0wn3uukdukdhcdjdjce5s5ueg4qwq6un59y) (no account needed to read).

## License

MIT
