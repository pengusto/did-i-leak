# Did I Leak?

**Before you make a repo public, check what Git remembers.**

Your `.env` is gone. Your Git history remembers.

`did-i-leak` is a small, local-first pre-publication check for developers, AI-assisted workflows, and open-source releases. It orchestrates established scanners instead of pretending to replace them, then turns the result into one useful verdict:

- `GO`
- `GO WITH REVIEW`
- `NO-GO`

It never prints full secrets and never changes credentials, Git history, refs, or repository visibility.

## Run it

The fallback inspection needs only Python 3.9+ and Git:

```sh
./bin/did-i-leak
```

Machine-readable output is safe to save or pipe:

```sh
./bin/did-i-leak --json
```

Exit codes are `0` for `GO`, `1` for `GO WITH REVIEW`, `2` for `NO-GO`, and `3` when the repository cannot be inspected.

## Better coverage

Install these tools through your normal package manager or official release process. `did-i-leak` does not install them for you:

- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

Both are invoked against the current tree and reachable Git history. TruffleHog verification is disabled by default so a local check does not send candidate credentials to external services.

Without either scanner, the fallback still checks text in the current tree—including ignored `.env` files outside dependency/build directories—and historical blobs for credential-shaped values, private-key headers, JWTs, credential-bearing database URLs, PII, internal URLs, and absolute local paths. Missing scanners keep a clean result at `GO WITH REVIEW`.

## Agent skill

`SKILL.md` makes the same workflow available to Codex-compatible agents as `$did-i-leak`. The agent should preserve the redaction boundary, add context-aware judgment, and stop at `NO-GO` until blockers are handled.

## Example output

```text
DID I LEAK?

NO-GO

1 blocker

1. BLOCKER — Secret detected by Gitleaks
   File: scripts/test_api.py
   Commit: a83f2c1
   Status: deleted from current tree · Confidence: high
   Detectors: Gitleaks, TruffleHog
   Action: Revoke/rotate the credential before publishing.

Coverage
* Git history: 42 reachable commits · 3 branches · 2 tags
* Current tree: tracked, non-ignored, and ignored files outside dependency/build directories
* Gitleaks: completed
* TruffleHog: completed
```

## Development

```sh
python3 -m unittest discover -s tests -v
./bin/did-i-leak --no-scanners
```

## License

MIT. See [LICENSE](LICENSE).
