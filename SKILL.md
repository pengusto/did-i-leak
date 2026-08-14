---
name: did-i-leak
description: Run a redacted pre-publication safety check over a Git repository's current tree and reachable history, using Gitleaks, TruffleHog, and fallback heuristics. Use when a developer asks whether a repository is safe to publish, open-source, share, or promote, or mentions leaked secrets, deleted credentials, Git history, PII, or internal URLs.
---

# Did I Leak?

Before making a repository public, check what Git remembers.

## Quick start

Run the bundled CLI from the skill directory or repository root:

```sh
python3 scripts/did_i_leak.py --repo .
```

The output is a concise `GO`, `GO WITH REVIEW`, or `NO-GO`. Use `--json` only when structured metadata is needed. Never print raw scanner output or secret values.

## Workflow

1. Inspect the current tree and reachable Git history, including branches, tags, deleted files, and historical blobs.
2. Run Gitleaks and TruffleHog when installed. They run redacted and offline; missing tools are reported, never installed globally.
3. Treat scanner findings and non-placeholder credential-shaped values as blockers. Treat PII, internal URLs, local paths, and unverified/noisy results as review items unless context makes the risk clear.
4. Deduplicate matching scanner hits. Explain current versus historical exposure, file, short commit, confidence, detector coverage, and the safest next action without revealing the value.
5. If a real credential was ever committed or shared: revoke/rotate it first, verify the replacement is absent, then consider history cleanup. Rewriting history does not make the old credential trustworthy.

## Safety boundary

Do not revoke, rotate, rewrite history, force-push, delete refs, change visibility, or alter GitHub security settings without explicit user approval. If a GitHub remote and `gh` are available, guide the user to review Secret Scanning, Push Protection, repository visibility, and workflows that may print secrets; local repositories remain fully supported.
