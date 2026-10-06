---
name: did-i-leak
description: Run a redacted pre-publication safety check over a Git repository's current tree and reachable history, using Gitleaks, TruffleHog, and fallback heuristics. Use when a developer asks whether a repository is safe to publish, open-source, share, or promote, or mentions leaked secrets, deleted credentials, Git history, PII, or internal URLs.
---

# Did I Leak?

Before making a repository public, check what Git remembers.

## Quick start

Resolve the bundled CLI relative to this `SKILL.md`, and pass the target repository explicitly. From the skill directory:

```sh
python3 scripts/did_i_leak.py --repo /path/to/target-repo
```

Replace `/path/to/target-repo` with the repository being reviewed. If calling from another directory, use the resolved path to the bundled script; do not assume the target repository contains it.

Normal runs reuse the repository-local cache at `.git/did-i-leak/` and scan the working tree plus newly reachable history. For a clean audit, use:

```sh
python3 scripts/did_i_leak.py --repo /path/to/target-repo --full
```

If the user asks for a full scan, says to ignore the cache, requests a clean audit, or asks to rescan everything, pass `--full`. When the user intends to make the repository public, open-source it, launch it, publish or release it publicly, or promote it publicly, recommend or automatically select `--full`.

The output is a concise `GO`, `GO WITH REVIEW`, or `NO-GO`. Use `--json` only when structured metadata is needed. Never print raw scanner output or secret values.

## Workflow

1. Inspect the current tree and reachable Git history, including branches, tags, deleted files, and historical blobs. Reuse safe local scan state when coverage is trusted; cache corruption, history rewrites, changed detection/scanner configuration, and uncertain coverage require a full audit.
2. Run Gitleaks and TruffleHog when installed. They run redacted and offline; missing tools are reported, never installed globally.
3. Treat scanner findings and non-placeholder credential-shaped values as blockers. Treat PII, internal URLs, local paths, and unverified/noisy results as review items unless context makes the risk clear.
4. Deduplicate matching scanner hits. Explain current versus historical exposure, file, short commit, confidence, detector coverage, and the safest next action without revealing the value.
5. If a real credential was ever committed or shared: revoke/rotate it first, verify the replacement is absent, then consider history cleanup. Rewriting history does not make the old credential trustworthy.

Gitleaks can receive a native `git --log-opts` commit delta. TruffleHog supports `--since-commit`/`--branch` for one changed local branch; use a conservative full Git scan for mixed refs, new tags, detached history, or ambiguous coverage. Both scanners still inspect the current filesystem, and the cache stores only validated redacted metadata—not scanner payloads or credential values.

## Safety boundary

Do not revoke, rotate, rewrite history, force-push, delete refs, change visibility, or alter GitHub security settings without explicit user approval. If a GitHub remote and `gh` are available, guide the user to review Secret Scanning, Push Protection, repository visibility, and workflows that may print secrets; local repositories remain fully supported.
