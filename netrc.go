package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
)

// netrcPath resolves the netrc file `go` itself would read, mirroring
// cmd/go/internal/auth.netrcPath exactly: an explicit NETRC env var wins,
// otherwise it's $HOME/.netrc, except on Windows where $HOME/_netrc is
// preferred if it exists (falling back to $HOME/.netrc otherwise).
func netrcPath() string {
	if env := os.Getenv("NETRC"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		legacy := filepath.Join(home, "_netrc")
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return filepath.Join(home, ".netrc")
}

// privatePrefixesFromNetrc parses netrc-format data for "machine" entries
// that carry a login and/or a password.
//
// Tokenization treats the whole file as one whitespace-separated stream —
// including newlines as ordinary separators between tokens, exactly the
// grammar the inetutils netrc manual documents ("separated by whitespace:
// spaces, tabs, or new-lines") — NOT cmd/go/internal/auth.parseNetrc's own
// tokenizer, which (mirrored here through run #472) re-runs strings.Fields
// independently on each physical line, so a "login"/"password"/"machine"
// keyword with its value written on the following physical line — a real,
// hand-formatted netrc style, one token per line for readability — is
// silently invisible to it: the keyword and its value each end up as a
// lone, unpaired field on their own line and neither is ever recorded.
// Verified live (2026-09) that this is a real go-vs-git divergence, not
// just a go quirk this tool should faithfully reproduce: a `~/.netrc`
// entry with "login"/"password" each on their own line, fed to a real
// `git` subprocess HTTPS fetch (GIT_CURL_VERBOSE=1 against a Basic-Auth
// server), authenticated successfully — "Server auth using Basic with
// user '<login>'", identical Authorization header to the one-line form —
// because libcurl's own netrc reader (CURLOPT_NETRC, what `git`'s HTTP
// backend actually uses) tokenizes the same whitespace-is-whitespace way
// curl's own docs describe, with no per-line pairing at all. Confirmed
// the same way independently with the `curl` CLI directly. A go.mod
// dependency authenticated only through such a netrc entry was a real,
// live-verified sumdb leak that the pre-fix, line-paired tokenizer
// reported "no issues found" for.
//
// A "macdef" section is still skipped without being scanned for
// "machine"/"login"/"password" tokens of its own — a real parser stops
// processing regular tokens once inside one, and a macro body can contain
// arbitrary text (not necessarily valid netrc syntax) that must not be
// misread as real entries. This is modeled by literally walking the same
// token stream nextToken already produces, with an inMacro flag gating
// what the dispatch loop does with each token, rather than a separate
// line-oriented skip pass — porting curl's real lib/netrc.c parsenetrc
// (fetched and read directly, 2026-09; matches the installed curl 8.14.1)
// byte for byte in spirit: entering macdef mode does not itself consume
// anything, it just starts ignoring tokens; the mode clears the instant
// nextToken's scan position lands directly on a raw newline with nothing
// non-blank found first — which normally only happens once, after the
// entire body up to a genuinely blank line has been walked token-by-token
// as ignored input, but happens IMMEDIATELY when a "macdef" line carries
// no macro-name argument at all (just trailing blanks then a newline):
// the "macro name" nextToken call right after "macdef" finds nothing on
// that line, jumps to the next physical line to look for one — and the
// moment it does, this same landed-on-a-newline check fires before it
// even gets there, since jumping to "the next line" and finding THAT
// line's own first byte already blank/newline is exactly the condition
// that ends macro mode. Verified live (2026-09, GIT_CURL_VERBOSE=1 against
// a Basic-Auth test server): a real `~/.netrc` with `macdef ` (trailing
// space, no name) directly followed by a real, well-formed "machine ...
// login ... password ..." line with NO blank line in between still
// authenticated off that line — real curl does NOT treat it as swallowed
// macro body, unlike a naive "macdef always skips through the next blank
// line" implementation (this function's own first, fuzz-caught draft of
// this fix) would.
//
// This does NOT use parseNetrc's own completeness rule either, which
// requires machine, login, AND password all present before using an
// entry. That rule is right for what parseNetrc itself feeds: GOAUTH=netrc,
// `go`'s own HTTP client credential source (`go help goauth`). It is wrong
// for what this function feeds instead — the netrc consultation `git`,
// invoked as a subprocess for a direct VCS fetch, always performs on its
// own via libcurl's CURLOPT_NETRC, per this package's main.go doc comment.
// Verified live with real `git` (and, underneath it, the same libcurl
// netrc reader curl itself uses) against a Basic-Auth-challenging HTTP
// server: a netrc entry with a "login" line but no "password" line at all
// sent "Authorization: Basic <login>:<empty>" on retry after the 401, and
// one with a "password" line but no "login" sent "Basic <empty>:<password>"
// — both real, successful authentications, neither requiring the other
// field. Only a "machine" entry with neither login nor password set at all
// (a bare "machine host" with nothing else) produced no Authorization
// header and made a real `git ls-remote` fail outright ("could not read
// Username"). So the real completeness bar for a git-subprocess-authenticated
// fetch is machine set AND (login set OR password set) — requiring both,
// as parseNetrc does, silently misses a real sumdb-leak signal for the
// common slip of a netrc entry with one of the two fields left unset.
//
// Because "login set OR password set" can't tell a complete entry from an
// incomplete one the moment a single field arrives the way parseNetrc's
// "wait for all three" rule could, this can't commit eagerly inline the way
// parseNetrc itself does — a "login" token might still be followed by its
// own "password" token before the entry is actually done. Instead, the
// pending entry is only finalized (commit) when it's unambiguously done:
// right before a new "machine" token starts the next entry, or at end of
// input/on the "default" stop condition.
func privatePrefixesFromNetrc(data []byte) []string {
	var prefixes []string
	seen := map[string]bool{}
	var machine, login, password string
	haveMachine := false
	inMacro := false

	commit := func() {
		if !haveMachine || (login == "" && password == "") {
			return
		}
		if !isKnownPublicHost(machine) && !seen[machine] {
			seen[machine] = true
			prefixes = append(prefixes, machine)
		}
	}

	i, n := 0, len(data)

	// isBlank reports whether b is an ordinary inter-token separator byte
	// (everything strings.Fields itself also treats as whitespace, in the
	// ASCII range real netrc files live in) OTHER than '\n' — '\n' is
	// handled on its own throughout nextToken below, since it (unlike
	// every other blank byte) also marks a physical line boundary, which
	// matters for macdef/end-of-input. Deliberately not "any byte <=
	// 0x20" (the literal boundary curl's own C `*tok_end > ' '` check
	// uses): a raw embedded NUL or other control byte is content a real
	// netrc file could accidentally contain (e.g. copy-paste corruption)
	// and cmd/go's own Fields-based tokenizer (still this function's
	// fuzz oracle for every shape of the tokenizing logic that IS still
	// shared — see FuzzPrivatePrefixesFromNetrc) treats as ordinary,
	// non-whitespace token content, not a boundary — matching that
	// avoids manufacturing a divergence on a byte value real curl's
	// C-string-based parser would itself likely mishandle in some other,
	// unspecified way, for an input this tool has no real stake in
	// modeling precisely either way.
	isBlank := func(b byte) bool {
		switch b {
		case ' ', '\t', '\r', '\v', '\f':
			return true
		default:
			return false
		}
	}

	// nextToken returns the next whitespace-delimited token in data,
	// mirroring curl's real parsenetrc token scan (lib/netrc.c): a blank
	// run is skipped first, a token is any maximal run of non-blank,
	// non-newline bytes, and exactly one delimiter byte past the token is
	// always consumed before returning — which, the moment that byte is
	// itself the line's own '\n', lands the next scan directly at the
	// start of the following physical line rather than stopping there.
	// That single mechanic is what makes an ordinary "machine"/"login"/
	// "password" keyword and its value keep reading as one continuous
	// token stream across a line break with no special-casing needed
	// (see this function's doc comment for the live verification), while
	// still surfacing a raw '\n' as the current byte — checked by the
	// caller for macdef/end-of-input purposes — the instant a scan
	// position lands on a genuinely blank line (two '\n's with nothing
	// but optional '\r's between them) or end of input.
	//
	// atEOL additionally reports whether the returned token is the last
	// one on its physical line — only blanks (if anything) separate it
	// from the next '\n' or end of input — used solely by the "default"
	// case below to require it be written the conventional way (alone on
	// its own line, trailing blanks allowed), matching the "only an
	// isolated trailing token" shape cmd/go/internal/auth.parseNetrc
	// itself recognizes as the file-ending sentinel (see its own
	// `i < len(f) && f[i] == "default"` check, only ever true for a
	// "default" with nothing else queued after it on that line) rather
	// than stopping the scan on any bare occurrence of the word
	// "default" anywhere, e.g. as JUNK wedged between other tokens on a
	// malformed line.
	nextToken := func() (tok string, atEOL, ok bool) {
		for {
			for i < n && isBlank(data[i]) {
				i++
			}
			if inMacro && i < n && data[i] == '\n' {
				inMacro = false
			}
			if i >= n || data[i] == '\n' {
				nl := bytes.IndexByte(data[i:], '\n')
				if nl < 0 {
					return "", false, false
				}
				i += nl + 1
				continue
			}
			start := i
			for i < n && !isBlank(data[i]) && data[i] != '\n' {
				i++
			}
			tok = string(data[start:i])
			j := i
			for j < n && isBlank(data[j]) {
				j++
			}
			atEOL = j >= n || data[j] == '\n'
			if i < n {
				i++ // consume exactly one delimiter byte
			}
			return tok, atEOL, true
		}
	}

	for {
		tok, atEOL, ok := nextToken()
		if !ok {
			break
		}
		if inMacro {
			continue // token scanned (so its bytes are consumed) but ignored
		}
		switch tok {
		case "machine":
			commit()
			m, _, _ := nextToken()
			machine, login, password = m, "", ""
			haveMachine = m != ""
		case "login":
			// Only a real value-consuming keyword once inside an
			// established machine entry — matching real curl, which
			// only recognizes "login"/"password" as taking a value
			// while in its HOSTVALID state (i.e. after a "machine"
			// token has been read), not while still hunting for the
			// next entry to start. Without this gate, a "login"/
			// "password" appearing as JUNK before any "machine" at
			// all (a real, fuzz-found case: a malformed leading line
			// happens to contain the bare word "password") would
			// unconditionally consume the very next token as its
			// value — which, the moment that next token is itself a
			// real "machine" keyword, silently swallows it, dropping
			// the entry that follows entirely.
			if haveMachine {
				if v, _, ok := nextToken(); ok {
					login = v
				}
			}
		case "password":
			if haveMachine {
				if v, _, ok := nextToken(); ok {
					password = v
				}
			}
		case "macdef":
			inMacro = true
		case "default":
			if atEOL {
				// "There can be only one default token, and it must be
				// after all machine tokens" — go stops processing here
				// too, but (matching parseNetrc's own narrower trigger:
				// an isolated trailing token, nothing queued after it on
				// the same line) only when "default" is genuinely
				// written the conventional way, not merely present
				// somewhere as JUNK on an otherwise-malformed line.
				commit()
				return prefixes
			}
		}
	}
	commit()
	return prefixes
}
