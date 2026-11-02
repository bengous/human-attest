# Human attestation verifier

A static page that tells whether a person approved the text of a GitHub issue,
pull request or comment before it was posted, and shows the evidence.

## What an attestation is

An agent writes issues, comments and pull requests under the account of
Augustin Bengolea (`bengous`). Before such a text leaves for a repository that
is not one of his private ones, a review window shows him the exact text with
its repository, kind and title. When he presses Enter, gpg signs those bytes
with a subkey that lives on a YubiKey, and the key blinks until he touches it.
The subkey was generated on the card with the touch policy `permanent`: no
signature without a finger on the key, and the policy cannot be switched off
without erasing the card's OpenPGP application.

The signature is appended to the body as an HTML comment, invisible on
GitHub's rendered page and returned verbatim by the API.

What a valid attestation proves:

- the holder of the YubiKey touched it while this exact text, for this
  repository, kind and title, was in front of them;
- the text has not changed since, and the block was not moved to another
  repository, posted as another kind, or kept under a changed title.

What it does not prove: that every word was read or agreed with, or who drafted
the text (usually an agent). A text without a block proves nothing either way.

## Format

The raw Markdown body ends with:

```text
<!-- human-attestation v1
repo: owner/name
kind: issue
title: the exact title
-----BEGIN PGP SIGNATURE-----

…
-----END PGP SIGNATURE-----
-->
```

- `repo` is `owner/name`; `kind` is one of `issue`, `pr`, `comment`, `review`;
  `title` is present for an issue or a pull request only.
- The block is the last `\n<!-- human-attestation v1\n` in the body, and only
  whitespace may follow its closing `-->`.
- The signed bytes, UTF-8, are:

  ```text
  human-attestation v1\n
  repo: owner/name\n
  kind: issue\n
  title: the exact title\n      (only when the block has a title)
  \n
  <body>
  ```

  where `<body>` is everything before the block, with CRLF replaced by LF and
  trailing whitespace removed (GitHub's web editor stores CRLF, the API stores
  what it receives). The header is rebuilt in that order whatever order the
  block lists it in. The first line keeps an attestation from passing for a git
  commit or tag signature.
- The signature is an OpenPGP detached signature. Only one subkey counts:
  key id `6e54f320fcca8447`, fingerprint
  `6376 AB0B 9832 7307 7D0A  BFF6 6E54 F320 FCCA 8447`, a subkey of the primary
  key `5499 D366 1B4F 01C9 CE66  3CC6 7C12 2F34 5D40 7A50`. A signature by any
  other subkey of the same primary key is not an attestation: the others are
  software keys.

The format is defined by `attestation.ts` in the `human-attest` tool; `attest.js`
here mirrors it.

## Verify by hand

In a throwaway keyring, so nothing touches yours:

```sh
export GNUPGHOME="$(mktemp -d)"
curl -s https://github.com/bengous.gpg | gpg --import
gpg --list-keys --with-subkey-fingerprints 5499D3661B4F01C9CE663CC67C122F345D407A50
```

The listing must show the subkey `6376AB0B983273077D0ABFF66E54F320FCCA8447`.

Fetch the raw body. For an issue or a pull request, `N` is its number; for a
comment, use `repos/OWNER/REPO/issues/comments/ID` with the number after
`#issuecomment-`:

```sh
gh api repos/OWNER/REPO/issues/N --jq .body > raw.md
```

Without `gh`: `curl -s https://api.github.com/repos/OWNER/REPO/issues/N | jq -j .body > raw.md`.

Rebuild the signed bytes with `split.py`:

```python
import sys

MARK = "<!-- human-attestation v1\n"

text = open(sys.argv[1], encoding="utf-8", newline="").read().replace("\r\n", "\n")
at = text.rindex("\n" + MARK)
block = text[at + 1 + len(MARK):].rstrip()
assert block.endswith("-->"), "the block does not close the body"
inner = block[:-3]
armor = inner.index("-----BEGIN PGP SIGNATURE-----")
fields = dict(line.split(": ", 1) for line in inner[:armor].split("\n") if line)
header = f"repo: {fields['repo']}\nkind: {fields['kind']}\n"
if "title" in fields:
    header += f"title: {fields['title']}\n"
body = text[:at].rstrip()
open("payload", "w", encoding="utf-8", newline="").write("human-attestation v1\n" + header + "\n" + body)
open("payload.asc", "w", encoding="utf-8", newline="").write(inner[armor:].rstrip() + "\n")
print(header, end="")
```

```sh
python3 split.py raw.md
gpg --status-fd 1 --verify payload.asc payload | grep VALIDSIG
```

The attestation holds when all of these are true:

- gpg reports a good signature, and the first fingerprint after `VALIDSIG` is
  `6376AB0B983273077D0ABFF66E54F320FCCA8447`;
- the printed `repo` is the repository the text sits in
  (`gh api repos/OWNER/REPO --jq .full_name`);
- the printed `kind` is `issue`, `pr` (the issue has a `pull_request` field),
  `comment` or `review`;
- for an issue or a pull request, the printed `title` is the current title
  (`gh api repos/OWNER/REPO/issues/N --jq .title`).

`payload` is the exact text the signer was shown; read it.

## Verify with the page

Open `index.html` (served over HTTP; a module script does not load from
`file://`) and either:

- paste a link: `https://github.com/OWNER/REPO/issues/N`, `…/pull/N`, either one
  followed by `#issuecomment-ID`, or a pull request link followed by
  `#pullrequestreview-ID`. The page reads GitHub's public API without signing
  in, 60 requests an hour per network address, public repositories only. A
  link can also be shared as `index.html?url=<link>`, which verifies on load;
- or open "Paste the raw Markdown instead" and paste the body as the API
  returns it. The page then checks the block and the signature, and reports
  the repository, kind and title as not checked, since pasted text has no
  place to compare with.

The verdict lists each check with its reason:

| Check | Fails when |
|---|---|
| Attestation block present | the body does not end with a readable block (a "no attestation" verdict, not an error) |
| Signature valid | the text, the header or the signature changed, or another key signed |
| Signed by the pinned subkey | the signature comes from a subkey other than `6e54f320fcca8447` |
| Repository matches | the block names another repository than the one the API reports (names compare case-insensitively; a rename after the attestation fails too, and the page says it was a rename) |
| Kind matches | the block was made for another kind of text |
| Title matches | the issue or pull request title differs from the attested one; not applicable to comments and reviews |

Below come the signing time, the signing subkey fingerprint, and the exact
signed text in a collapsible block.

The trust anchors are the public key and the pinned subkey id written into
`attest.js`. Cross-check them against <https://github.com/bengous.gpg> and the
profile <https://github.com/bengous> before trusting a copy of this page.

## Files

- `index.html`: the page. It loads OpenPGP.js 6.3.2 from jsDelivr with a
  pinned SHA-384 `integrity` and nothing else from a third party. Its
  Content-Security-Policy allows that one script, `attest.js`, the inline
  script and style by hash, and requests to `api.github.com` only.
- `attest.js`: the verification logic as an ES module, with no DOM and no
  network: block parsing, payload construction, the checks, link parsing, API
  response mapping, HTTP error messages.
- `test/attest.test.js`: Bun tests against the real attested issue and comment
  of `bengous/human-attest` (fixtures in `test/fixtures/`), a tampered copy, a
  rewritten header, a reposted block, CRLF line endings, a body without a
  block. They also check that the page's `integrity` matches the npm copy of
  OpenPGP.js they ran against, and that the CSP hashes match the inline script
  and style.

```sh
bun install
bun test
```

An edit to the inline script or style changes its hash: the CSP test then
fails, and the new value goes into the `Content-Security-Policy` meta tag
(`openssl dgst -sha256 -binary | openssl base64` over the exact text between
the tags).
