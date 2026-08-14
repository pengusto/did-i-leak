#!/usr/bin/env python3
"""A small, redacted pre-publication safety check for Git repositories."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


MAX_TEXT_BYTES = 4 * 1024 * 1024
SCANNER_TIMEOUT_SECONDS = 180

SECRET_ASSIGNMENT = re.compile(
    r"(?ix)\b(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|"
    r"client[_-]?secret|auth[_-]?token|private[_-]?key)\b\s*(?:=|:)\s*"
    r"[\"']?(?P<value>[A-Za-z0-9_./+=:@-]{12,})"
)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
CONNECTION_STRING = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@]+:[^\s@]+@"
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
INTERNAL_URL = re.compile(
    r"(?i)https?://(?:localhost|127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|"
    r"192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|"
    r"[^/\s]+\.(?:internal|intranet|local)(?:[:/\s]|$))"
)
LOCAL_PATH = re.compile(
    r"(?:/Users/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+|"
    r"/home/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+|"
    r"[A-Z]:\\Users\\[^\s\\]+(?:\\[^\s\\]+)+)"
)
PLACEHOLDER = re.compile(
    r"(?i)\b(?:example|sample|fake|dummy|fixture|placeholder|changeme|"
    r"replace[_ -]?me|not[_ -]?a[_ -]?secret|test[_ -]?only)\b"
)


class GitError(RuntimeError):
    pass


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    file: str
    status: str
    confidence: str
    reason: str
    line: int | None = None
    commit: str | None = None
    sources: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str, str, int | None]:
        return self.category, self.file, self.commit or "", self.line


def run_command(command: list[str], cwd: Path, timeout: int = 30, *, text: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=text,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("command timed out") from exc


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    completed = run_command(["git", *args], repo, text=text)
    if completed.returncode != 0:
        raise GitError("Git command failed")
    return completed.stdout


def find_repo(path: Path) -> Path:
    try:
        root = str(git(path.resolve(), "rev-parse", "--show-toplevel")).strip()
    except (GitError, FileNotFoundError):
        raise GitError("not a Git repository")
    return Path(root).resolve()


def short_commit(commit: str | None) -> str | None:
    return commit[:7] if commit else None


def relative_path(repo: Path, value: Any) -> str:
    raw = str(value or "")
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            return str(candidate.resolve().relative_to(repo))
        except ValueError:
            return "outside-repository-path"
    return raw.replace("\\", "/").lstrip("./") or "unknown-file"


def current_paths(repo: Path) -> set[str]:
    tracked_and_unignored = git(repo, "ls-files", "-co", "--exclude-standard", "-z", text=False)
    ignored = git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", text=False)
    names = {
        item.decode("utf-8", "replace")
        for item in bytes(tracked_and_unignored).split(b"\0")
        if item
    }
    skipped_directories = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv"}
    for item in bytes(ignored).split(b"\0"):
        if not item:
            continue
        name = item.decode("utf-8", "replace")
        if not skipped_directories.intersection(Path(name).parts):
            names.add(name)
    return names


def text_from_bytes(data: bytes) -> tuple[str | None, bool]:
    if b"\0" in data[:4096]:
        return None, False
    if len(data) > MAX_TEXT_BYTES:
        # ponytail: cap heuristic reads at 4 MiB; established scanners still cover large files.
        return data[:MAX_TEXT_BYTES].decode("utf-8", "replace"), True
    return data.decode("utf-8", "replace"), False


def finding_status(commit: str | None, file: str, current: set[str]) -> str:
    if not commit:
        return "current tree"
    if file not in current:
        return "deleted from current tree"
    return "historical"


def heuristic_findings(
    text: str,
    file: str,
    *,
    current: set[str],
    commit: str | None = None,
    source: str = "heuristic",
) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    def add(category: str, match: re.Match[str], title: str, severity: str, confidence: str, reason: str) -> None:
        line = text.count("\n", 0, match.start()) + 1
        context = lines[line - 1] if line <= len(lines) else ""
        is_placeholder = bool(PLACEHOLDER.search(context))
        final_severity = "LIKELY FALSE POSITIVE" if is_placeholder else severity
        final_confidence = "low" if is_placeholder else confidence
        findings.append(
            Finding(
                category=category,
                severity=final_severity,
                title=title,
                file=file,
                status=finding_status(commit, file, current),
                confidence=final_confidence,
                reason=("Placeholder-like value in test/example context." if is_placeholder else reason),
                line=line,
                commit=short_commit(commit),
                sources=[source],
            )
        )

    for match in SECRET_ASSIGNMENT.finditer(text):
        add(
            "secret",
            match,
            "Credential-shaped value",
            "BLOCKER",
            "high",
            "Secret-like assignment found in source text.",
        )
    for match in PRIVATE_KEY.finditer(text):
        add("private-key", match, "Private key material", "BLOCKER", "high", "Private-key header found.")
    for match in JWT.finditer(text):
        add("token", match, "JWT-shaped token", "BLOCKER", "medium", "JWT-shaped value found in source text.")
    for match in CONNECTION_STRING.finditer(text):
        add("database-credential", match, "Database credential in connection string", "BLOCKER", "high", "Credential-bearing database URL found.")
    for match in EMAIL.finditer(text):
        add("personal-information", match, "Email address", "REVIEW", "medium", "Email address found in source text.")
    for match in INTERNAL_URL.finditer(text):
        add("internal-url", match, "Internal URL or hostname", "REVIEW", "medium", "Private or internal URL found in source text.")
    for match in LOCAL_PATH.finditer(text):
        add("local-path", match, "Absolute local filesystem path", "REVIEW", "medium", "Machine-specific path found in source text.")
    return findings


def scan_current_tree(repo: Path, current: set[str]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    truncated = 0
    for name in sorted(current):
        path = repo / name
        try:
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
        except (OSError, ValueError):
            continue
        text, was_truncated = text_from_bytes(data)
        if text is None:
            continue
        truncated += int(was_truncated)
        findings.extend(heuristic_findings(text, name, current=current))
    return findings, truncated


def historical_objects(repo: Path) -> list[tuple[str, str]]:
    output = str(git(repo, "rev-list", "--objects", "--all"))
    objects: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        oid, separator, name = line.partition(" ")
        if separator and oid not in seen:
            seen.add(oid)
            objects.append((oid, name))
    return objects


def blob_commit(repo: Path, oid: str, cache: dict[str, str | None]) -> str | None:
    if oid not in cache:
        completed = run_command(["git", "log", "--all", "--format=%H", "--find-object", oid, "-1"], repo)
        cache[oid] = completed.stdout.strip() or None
    return cache[oid]


def scan_historical_blobs(repo: Path, current: set[str]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    truncated = 0
    commit_cache: dict[str, str | None] = {}
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin and process.stdout
    try:
        for oid, name in historical_objects(repo):
            process.stdin.write(f"{oid}\n".encode())
            process.stdin.flush()
            header = process.stdout.readline()
            if not header:
                break
            parts = header.split()
            if len(parts) < 3:
                continue
            size = int(parts[2])
            read_size = min(size, MAX_TEXT_BYTES)
            data = process.stdout.read(read_size)
            remaining = size - read_size
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            process.stdout.read(1)  # batch protocol delimiter
            if parts[1] != b"blob":
                continue
            if size > MAX_TEXT_BYTES:
                truncated += 1
            text, _ = text_from_bytes(data)
            if text is None:
                continue
            blob_findings = heuristic_findings(text, name, current=current, source="history heuristic")
            if blob_findings:
                commit = blob_commit(repo, oid, commit_cache)
                for finding in blob_findings:
                    finding.commit = short_commit(commit)
                    finding.status = finding_status(commit, name, current)
                findings.extend(blob_findings)
    finally:
        process.stdin.close()
        process.stdout.close()
        if process.stderr:
            process.stderr.close()
        process.wait(timeout=30)
    return findings, truncated


def parse_report(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("findings"), list):
        return [item for item in value["findings"] if isinstance(item, dict)]
    return []


def scanner_finding(
    *,
    scanner: str,
    file: str,
    commit: str | None,
    line: int | None,
    current: set[str],
    verified: bool | None = None,
) -> Finding:
    is_blocker = scanner == "Gitleaks" or verified is True
    return Finding(
        category="secret",
        severity="BLOCKER" if is_blocker else "REVIEW",
        title=f"Secret detected by {scanner}",
        file=file,
        status=finding_status(commit, file, current),
        confidence="high" if is_blocker else "medium",
        reason=(
            "Established secret scanner detected a credential-shaped value."
            if is_blocker
            else "TruffleHog found an unverified credential-shaped value."
        ),
        line=line,
        commit=short_commit(commit),
        sources=[scanner],
    )


def run_gitleaks(repo: Path, current: set[str]) -> tuple[list[Finding], str, str | None]:
    binary = shutil.which("gitleaks")
    if not binary:
        return [], "unavailable", "Install Gitleaks; no global installation was attempted."
    findings: list[Finding] = []
    try:
        with tempfile.TemporaryDirectory(prefix="did-i-leak-") as directory:
            for scope in ("git", "dir"):
                report = Path(directory) / f"{scope}.json"
                command = [
                    binary,
                    scope,
                    "--redact",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                    "--exit-code",
                    "0",
                    "--no-banner",
                ]
                if scope == "git":
                    command.extend(["--log-opts=--all", str(repo)])
                else:
                    command.append(str(repo))
                result = run_command(command, repo, SCANNER_TIMEOUT_SECONDS)
                if result.returncode != 0:
                    return findings, "failed", "Gitleaks returned an error; see the command output only after checking its redaction settings."
                for item in parse_report(report):
                    findings.append(
                        scanner_finding(
                            scanner="Gitleaks",
                            file=relative_path(repo, item.get("File")),
                            commit=str(item.get("Commit") or "") or None,
                            line=int(item["StartLine"]) if str(item.get("StartLine", "")).isdigit() else None,
                            current=current,
                        )
                    )
    except (OSError, RuntimeError, ValueError):
        return findings, "failed", "Gitleaks could not complete."
    return findings, "completed", None


def nested_value(value: Any, *names: str) -> Any:
    if not isinstance(value, dict):
        return None
    for name in names:
        if value.get(name) is not None:
            return value[name]
    return None


def truffle_items(output: str) -> Iterable[dict[str, Any]]:
    for line in output.splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


def run_trufflehog(repo: Path, current: set[str]) -> tuple[list[Finding], str, str | None]:
    binary = shutil.which("trufflehog")
    if not binary:
        return [], "unavailable", "Install TruffleHog; no global installation was attempted."
    findings: list[Finding] = []
    try:
        for scope, target in (("git", repo.as_uri()), ("filesystem", str(repo))):
            command = [
                binary,
                scope,
                target,
                "--json",
                "--no-verification",
                "--no-update",
                "--results=unverified,unknown",
            ]
            result = run_command(command, repo, SCANNER_TIMEOUT_SECONDS)
            if result.returncode != 0:
                return findings, "failed", "TruffleHog could not complete."
            for item in truffle_items(result.stdout):
                metadata = item.get("SourceMetadata") or {}
                data = nested_value(metadata, "Data", "data") or {}
                git_data = nested_value(data, "Git", "git") or {}
                file = relative_path(repo, nested_value(git_data, "File", "file"))
                commit = nested_value(git_data, "Commit", "commit")
                line_value = nested_value(git_data, "Line", "line")
                line = int(line_value) if str(line_value).isdigit() else None
                findings.append(
                    scanner_finding(
                        scanner="TruffleHog",
                        file=file,
                        commit=str(commit or "") or None,
                        line=line,
                        current=current,
                        verified=item.get("Verified") is True,
                    )
                )
    except (OSError, RuntimeError, ValueError):
        return findings, "failed", "TruffleHog could not complete."
    return findings, "completed", None


SEVERITY_RANK = {"LIKELY FALSE POSITIVE": 0, "REVIEW": 1, "BLOCKER": 2}


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str, str, int | None], Finding] = {}
    for finding in findings:
        key = finding.key()
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        existing.sources = sorted(set(existing.sources + finding.sources))
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]:
            existing.severity = finding.severity
            existing.confidence = finding.confidence
            existing.reason = finding.reason
    return sorted(
        merged.values(),
        key=lambda item: (-SEVERITY_RANK[item.severity], item.file, item.line or 0, item.title),
    )


def repository_counts(repo: Path) -> dict[str, int]:
    branches = set()
    for prefix in ("refs/heads", "refs/remotes"):
        output = str(git(repo, "for-each-ref", "--format=%(refname)", prefix))
        branches.update(line.strip() for line in output.splitlines() if line.strip())
    tags = str(git(repo, "for-each-ref", "--format=%(refname)", "refs/tags"))
    commits = str(git(repo, "rev-list", "--all", "--count")).strip()
    return {
        "branches": len(branches),
        "tags": len([line for line in tags.splitlines() if line.strip()]),
        "reachable_commits": int(commits or 0),
    }


def scan_repo(repo: Path, *, run_scanners: bool = True) -> dict[str, Any]:
    root = find_repo(repo)
    current = current_paths(root)
    current_findings, current_truncated = scan_current_tree(root, current)
    historical_findings, history_truncated = scan_historical_blobs(root, current)
    findings = current_findings + historical_findings
    coverage: dict[str, Any] = {
        "current_tree": "tracked, non-ignored, and ignored files outside dependency/build directories",
        "git_history": "reachable commits, branches, tags, and historical blobs",
        "counts": repository_counts(root),
        "heuristic_truncated_current_files": current_truncated,
        "heuristic_truncated_historical_blobs": history_truncated,
    }
    scanners: dict[str, dict[str, str | None]] = {}
    if run_scanners:
        for name, runner in (("Gitleaks", run_gitleaks), ("TruffleHog", run_trufflehog)):
            scanner_findings, status, note = runner(root, current)
            findings.extend(scanner_findings)
            scanners[name] = {"status": status, "note": note}
    else:
        scanners = {
            "Gitleaks": {"status": "disabled", "note": "disabled by caller"},
            "TruffleHog": {"status": "disabled", "note": "disabled by caller"},
        }
    coverage["scanners"] = scanners
    result_findings = deduplicate(findings)
    blockers = sum(item.severity == "BLOCKER" for item in result_findings)
    reviews = sum(item.severity == "REVIEW" for item in result_findings)
    false_positives = sum(item.severity == "LIKELY FALSE POSITIVE" for item in result_findings)
    incomplete = any(item["status"] != "completed" for item in scanners.values())
    if blockers:
        verdict = "NO-GO"
    elif reviews or incomplete or current_truncated or history_truncated:
        verdict = "GO WITH REVIEW"
    else:
        verdict = "GO"
    return {
        "verdict": verdict,
        "summary": {"blockers": blockers, "reviews": reviews, "likely_false_positives": false_positives},
        "findings": [asdict(item) for item in result_findings],
        "coverage": coverage,
        "repository": str(root),
    }


def render(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = ["DID I LEAK?", "", result["verdict"], ""]
    if summary["blockers"]:
        lines.append(f"{summary['blockers']} blocker{'s' if summary['blockers'] != 1 else ''}")
    if summary["reviews"]:
        lines.append(f"{summary['reviews']} review item{'s' if summary['reviews'] != 1 else ''}")
    if summary["likely_false_positives"]:
        lines.append(f"{summary['likely_false_positives']} likely false positive{'s' if summary['likely_false_positives'] != 1 else ''}")
    if not any(summary.values()):
        lines.append("No findings")
    lines.append("")
    for number, finding in enumerate(result["findings"], 1):
        lines.append(f"{number}. {finding['severity']} — {finding['title']}")
        lines.append(f"   File: {finding['file']}")
        if finding.get("commit"):
            lines.append(f"   Commit: {finding['commit']}")
        lines.append(f"   Status: {finding['status']} · Confidence: {finding['confidence']}")
        if finding["sources"]:
            lines.append(f"   Detectors: {', '.join(finding['sources'])}")
        lines.append(f"   Reason: {finding['reason']}")
        if finding["severity"] == "BLOCKER":
            lines.append("   Action: Revoke/rotate the credential before publishing.")
        lines.append("")
    lines.append("Coverage")
    counts = result["coverage"]["counts"]
    lines.append(
        f"* Git history: {counts['reachable_commits']} reachable commits · "
        f"{counts['branches']} branches · {counts['tags']} tags"
    )
    lines.append("* Current tree: tracked, non-ignored, and ignored files outside dependency/build directories")
    for name, scanner in result["coverage"]["scanners"].items():
        suffix = f" ({scanner['note']})" if scanner.get("note") else ""
        lines.append(f"* {name}: {scanner['status']}{suffix}")
    if result["coverage"]["heuristic_truncated_current_files"] or result["coverage"]["heuristic_truncated_historical_blobs"]:
        lines.append("* Fallback note: heuristic inspection was capped at 4 MiB per text file/blob.")
    return "\n".join(lines)


def exit_code(verdict: str) -> int:
    return {"GO": 0, "GO WITH REVIEW": 1, "NO-GO": 2}[verdict]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Git repository before publication.")
    parser.add_argument("--repo", default=".", help="repository to inspect (default: current directory)")
    parser.add_argument("--json", action="store_true", help="emit safe machine-readable JSON")
    parser.add_argument("--no-scanners", action="store_true", help="skip external scanners; useful for offline tests")
    args = parser.parse_args(argv)
    try:
        result = scan_repo(Path(args.repo), run_scanners=not args.no_scanners)
    except (GitError, OSError, RuntimeError, ValueError):
        print("did-i-leak: could not inspect a Git repository", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render(result))
    return exit_code(result["verdict"])


if __name__ == "__main__":
    raise SystemExit(main())
