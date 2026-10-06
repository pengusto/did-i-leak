#!/usr/bin/env python3
"""A small, redacted pre-publication safety check for Git repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


TOOL_VERSION = "0.2.0"
CACHE_SCHEMA = 1
CACHE_DIRECTORY = "did-i-leak"
CACHE_STATE = "state.json"
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_CACHE_BYTES = 16 * 1024 * 1024
SCANNER_TIMEOUT_SECONDS = 180
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}$")

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


def git_succeeds(repo: Path, *args: str) -> bool:
    try:
        completed = run_command(["git", *args], repo)
    except RuntimeError:
        return False
    return completed.returncode == 0


def find_repo(path: Path) -> Path:
    try:
        root = str(git(path.resolve(), "rev-parse", "--show-toplevel")).strip()
    except (GitError, FileNotFoundError):
        raise GitError("not a Git repository")
    return Path(root).resolve()


def short_commit(commit: str | None) -> str | None:
    return commit[:7] if commit else None


def git_dir(repo: Path) -> Path:
    raw = str(git(repo, "rev-parse", "--git-dir")).strip()
    path = Path(raw)
    return path if path.is_absolute() else (repo / path).resolve()


def cache_path(repo: Path) -> Path:
    return git_dir(repo) / CACHE_DIRECTORY / CACHE_STATE


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detection_fingerprint() -> str:
    try:
        return sha256_file(Path(__file__).resolve())
    except OSError:
        return ""


CONFIG_FILENAMES = (
    ".gitleaks.toml",
    ".gitleaks.yaml",
    ".gitleaks.yml",
    ".gitleaksignore",
    ".trufflehog.yaml",
    ".trufflehog.yml",
    ".trufflehogignore",
    ".did-i-leak.toml",
    ".did-i-leak.json",
)


def config_fingerprint(repo: Path) -> str:
    digest = hashlib.sha256()
    for name in CONFIG_FILENAMES:
        path = repo / name
        if not path.is_file():
            continue
        digest.update(name.encode("utf-8"))
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return ""
    return digest.hexdigest()


def repository_refs(repo: Path) -> dict[str, str]:
    output = bytes(git(repo, "for-each-ref", "--format=%(refname)%00%(objectname)", text=False))
    refs: dict[str, str] = {}
    for line in output.splitlines():
        name, separator, oid = line.partition(b"\0")
        if separator and OID.fullmatch(oid.decode("ascii", "ignore")):
            refs[name.decode("utf-8", "replace")] = oid.decode("ascii")
    try:
        head = str(git(repo, "rev-parse", "--verify", "HEAD")).strip()
    except GitError:
        head = ""
    if OID.fullmatch(head):
        refs["HEAD"] = head
    return refs


def current_tips(refs: dict[str, str]) -> list[str]:
    return sorted(set(refs.values()))


def is_ancestor(repo: Path, older: str, newer: str) -> bool:
    return git_succeeds(repo, "merge-base", "--is-ancestor", older, newer)


def cached_commit_is_reachable(repo: Path, commit: str, tips: Iterable[str]) -> bool:
    try:
        resolved = str(git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")).strip()
    except GitError:
        return False
    return any(is_ancestor(repo, resolved, tip) for tip in tips)


def scanner_version(name: str) -> dict[str, str | bool]:
    executable = shutil.which(name.lower())
    if not executable:
        return {"available": False, "version": "unavailable"}
    try:
        result = run_command([executable, "version"], Path.cwd(), timeout=10)
        output = (result.stdout or result.stderr).strip()
        version = hashlib.sha256(output.encode("utf-8", "replace")).hexdigest() if output else "available"
    except (OSError, RuntimeError):
        version = "available"
    return {"available": True, "version_fingerprint": version}


def scanner_snapshot(run_scanners: bool) -> dict[str, Any]:
    if not run_scanners:
        return {"mode": "disabled"}
    return {
        "mode": "enabled",
        "Gitleaks": scanner_version("gitleaks"),
        "TruffleHog": scanner_version("trufflehog"),
    }


def safe_finding_dicts(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [asdict(item) for item in findings if item.commit]


def valid_cached_finding(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    expected = {"category", "severity", "title", "file", "status", "confidence", "reason", "line", "commit", "sources"}
    if set(value) != expected:
        return False
    string_fields = ("category", "severity", "title", "file", "status", "confidence", "reason", "commit")
    if any(not isinstance(value.get(name), str) for name in string_fields):
        return False
    if value["severity"] not in SEVERITY_RANK:
        return False
    if not re.fullmatch(r"[0-9a-f]{7}|[0-9a-f]{40}", value["commit"]):
        return False
    if value["line"] is not None and (not isinstance(value["line"], int) or value["line"] < 1):
        return False
    if not isinstance(value["sources"], list) or any(not isinstance(item, str) for item in value["sources"]):
        return False
    return all(len(str(value.get(name, ""))) <= 4096 for name in string_fields)


def load_cache(repo: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = cache_path(repo)
    try:
        if not path.is_file():
            return None, "No trusted scan cache found."
        if path.stat().st_size > MAX_CACHE_BYTES:
            return None, "Scan cache is too large to trust."
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "Scan cache is missing or corrupt; running a full audit."
    if not isinstance(value, dict):
        return None, "Scan cache has an incompatible shape; running a full audit."
    if value.get("schema") != CACHE_SCHEMA or value.get("tool_version") != TOOL_VERSION:
        return None, "Scan cache schema changed; running a full audit."
    if not isinstance(value.get("refs"), dict) or any(
        not isinstance(name, str) or not isinstance(oid, str) or not OID.fullmatch(oid)
        for name, oid in value["refs"].items()
    ):
        return None, "Scan cache refs are invalid; running a full audit."
    for field_name in ("detection_fingerprint", "config_fingerprint"):
        if not isinstance(value.get(field_name), str) or not SHA256.fullmatch(value[field_name]):
            return None, "Scan cache fingerprints are invalid; running a full audit."
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) > 100_000 or not all(valid_cached_finding(item) for item in findings):
        return None, "Scan cache findings are invalid; running a full audit."
    if not isinstance(value.get("scanners"), dict) or not isinstance(value.get("scanner_mode"), str):
        return None, "Scan cache scanner metadata is invalid; running a full audit."
    return value, None


def write_cache(repo: Path, payload: dict[str, Any]) -> None:
    directory = cache_path(repo).parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, prefix=".state-", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, cache_path(repo))
    finally:
        if temporary and temporary.exists():
            temporary.unlink(missing_ok=True)


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


def historical_objects(repo: Path, revisions: Iterable[str] | None = None) -> list[tuple[str, str]]:
    args = ["rev-list", "--objects", "--all"]
    if git_succeeds(repo, "rev-parse", "--verify", "HEAD"):
        args.append("HEAD")
    if revisions is not None:
        args = ["rev-list", "--objects", *revisions]
    output = str(git(repo, *args))
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
        completed = run_command(["git", "log", "--all", "HEAD", "--format=%H", "--find-object", oid, "-1"], repo)
        cache[oid] = completed.stdout.strip() or None
    return cache[oid]


def scan_historical_objects(
    repo: Path, current: set[str], objects: Iterable[tuple[str, str]]
) -> tuple[list[Finding], int]:
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
        for oid, name in objects:
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


def reachable_commit_count(repo: Path, tips: Iterable[str]) -> int:
    tip_list = sorted(set(tips))
    if not tip_list:
        return 0
    try:
        return int(str(git(repo, "rev-list", "--count", *tip_list)).strip() or 0)
    except (GitError, ValueError):
        return 0


def new_history_objects(repo: Path, refs: dict[str, str], previous_refs: dict[str, str]) -> list[tuple[str, str]]:
    new_tips = current_tips(refs)
    old_tips = sorted(set(previous_refs.values()))
    if not new_tips:
        return []
    args = ["rev-list", "--objects", *new_tips]
    if old_tips:
        args.extend(["--not", *old_tips])
    output = str(git(repo, *args))
    objects: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        oid, separator, name = line.partition(" ")
        if separator and oid not in seen:
            seen.add(oid)
            objects.append((oid, name))
    return objects


def new_history_commit_count(repo: Path, refs: dict[str, str], previous_refs: dict[str, str]) -> int:
    new_tips = current_tips(refs)
    old_tips = sorted(set(previous_refs.values()))
    if not new_tips:
        return 0
    args = ["rev-list", "--count", *new_tips]
    if old_tips:
        args.extend(["--not", *old_tips])
    try:
        return int(str(git(repo, *args)).strip() or 0)
    except (GitError, ValueError):
        return 0


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


def run_gitleaks(
    repo: Path, current: set[str], *, history_log_opts: str | None
) -> tuple[list[Finding], str, str | None]:
    binary = shutil.which("gitleaks")
    if not binary:
        return [], "unavailable", "Install Gitleaks; no global installation was attempted."
    findings: list[Finding] = []
    try:
        with tempfile.TemporaryDirectory(prefix="did-i-leak-") as directory:
            scopes = [("dir", None)]
            if history_log_opts:
                scopes.insert(0, ("git", history_log_opts))
            for scope, log_opts in scopes:
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
                    command.extend([f"--log-opts={log_opts}", str(repo)])
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


def run_trufflehog(
    repo: Path, current: set[str], *, history: tuple[str, str] | str | None
) -> tuple[list[Finding], str, str | None]:
    binary = shutil.which("trufflehog")
    if not binary:
        return [], "unavailable", "Install TruffleHog; no global installation was attempted."
    findings: list[Finding] = []
    try:
        scopes: list[tuple[str, list[str]]] = [("filesystem", [str(repo)])]
        if history == "full":
            scopes.insert(0, ("git", [repo.as_uri()]))
        elif isinstance(history, tuple):
            old_commit, branch = history
            scopes.insert(0, ("git", [repo.as_uri(), "--since-commit", old_commit, "--branch", branch]))
        for scope, target_args in scopes:
            command = [
                binary,
                scope,
                *target_args,
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


def repository_counts(repo: Path, cached: dict[str, int] | None = None, *, refresh_history: bool = True) -> dict[str, int]:
    branches = set()
    for prefix in ("refs/heads", "refs/remotes"):
        output = str(git(repo, "for-each-ref", "--format=%(refname)", prefix))
        branches.update(line.strip() for line in output.splitlines() if line.strip())
    tags = str(git(repo, "for-each-ref", "--format=%(refname)", "refs/tags"))
    if not refresh_history and cached and isinstance(cached.get("reachable_commits"), int):
        reachable_commits = cached["reachable_commits"]
    else:
        reachable_commits = reachable_commit_count(repo, repository_refs(repo).values())
    return {
        "branches": len(branches),
        "tags": len([line for line in tags.splitlines() if line.strip()]),
        "reachable_commits": reachable_commits,
    }


def scan_plan(
    repo: Path,
    refs: dict[str, str],
    cached: dict[str, Any] | None,
    cache_note: str | None,
    scanner_state: dict[str, Any],
    *,
    full_requested: bool,
) -> dict[str, Any]:
    full_log_opts = "--all" + (" HEAD" if refs.get("HEAD") else "")
    if full_requested:
        return {
            "full": True,
            "reason": "Explicit full audit requested; cached coverage ignored.",
            "previous_refs": cached.get("refs", {}) if cached else {},
            "new_objects": [],
            "new_commits": 0,
            "changed_refs": [],
            "gitleaks_log_opts": full_log_opts,
            "truffle_history": "full",
        }
    if cached is None:
        return {
            "full": True,
            "reason": cache_note or "No trusted scan cache found; running a full audit.",
            "previous_refs": {},
            "new_objects": [],
            "new_commits": 0,
            "changed_refs": [],
            "gitleaks_log_opts": full_log_opts,
            "truffle_history": "full",
        }
    if cached.get("detection_fingerprint") != detection_fingerprint():
        reason = "Detection logic changed; running a full audit."
    elif cached.get("config_fingerprint") != config_fingerprint(repo):
        reason = "Scanner configuration changed; running a full audit."
    elif cached.get("scanner_mode") != scanner_state.get("mode") or cached.get("scanners") != scanner_state:
        reason = "Scanner version or configuration changed; running a full audit."
    else:
        reason = None
    if reason:
        return {
            "full": True,
            "reason": reason,
            "previous_refs": cached.get("refs", {}),
            "new_objects": [],
            "new_commits": 0,
            "changed_refs": [],
            "gitleaks_log_opts": full_log_opts,
            "truffle_history": "full",
        }

    previous_refs = {str(name): str(oid) for name, oid in cached["refs"].items()}
    tips = current_tips(refs)
    for name, older in previous_refs.items():
        newer = refs.get(name)
        if newer:
            if newer != older and not is_ancestor(repo, older, newer):
                return {
                    "full": True,
                    "reason": "History changed since the previous trusted scan; running a full audit.",
                    "previous_refs": previous_refs,
                    "new_objects": [],
                    "new_commits": 0,
                    "changed_refs": [],
                    "gitleaks_log_opts": full_log_opts,
                    "truffle_history": "full",
                }
        elif tips and not any(is_ancestor(repo, older, tip) for tip in tips):
            return {
                "full": True,
                "reason": "Previously scanned history is no longer reachable; running a full audit.",
                "previous_refs": previous_refs,
                "new_objects": [],
                "new_commits": 0,
                "changed_refs": [],
                "gitleaks_log_opts": full_log_opts,
                "truffle_history": "full",
            }

    cached_commits = {item["commit"] for item in cached.get("findings", [])}
    if any(not cached_commit_is_reachable(repo, commit, tips) for commit in cached_commits):
        return {
            "full": True,
            "reason": "Cached finding coverage is not reachable or valid; running a full audit.",
            "previous_refs": previous_refs,
            "new_objects": [],
            "new_commits": 0,
            "changed_refs": [],
            "gitleaks_log_opts": full_log_opts,
            "truffle_history": "full",
        }

    changed_refs = [
        name for name, oid in refs.items() if name != "HEAD" and previous_refs.get(name) != oid
    ]
    new_objects = new_history_objects(repo, refs, previous_refs) if changed_refs or refs.get("HEAD") != previous_refs.get("HEAD") else []
    new_commits = new_history_commit_count(repo, refs, previous_refs) if new_objects else 0
    old_tips = sorted(set(previous_refs.values()))
    if new_objects:
        gitleaks_log_opts = full_log_opts
        if old_tips:
            gitleaks_log_opts += " --not " + " ".join(old_tips)
        if len(changed_refs) == 1 and changed_refs[0].startswith("refs/heads/"):
            ref = changed_refs[0]
            old_commit = previous_refs.get(ref)
            truffle_history: tuple[str, str] | str = (
                (old_commit, ref.removeprefix("refs/heads/")) if old_commit else "full"
            )
        else:
            # ponytail: TruffleHog has a safe range flag for one branch only; use a full history scan for mixed refs/tags.
            truffle_history = "full"
    else:
        gitleaks_log_opts = None
        truffle_history = None
    return {
        "full": False,
        "reason": "Trusted cache reused; scanning newly reachable history and the working tree.",
        "previous_refs": previous_refs,
        "new_objects": new_objects,
        "new_commits": new_commits,
        "changed_refs": changed_refs,
        "gitleaks_log_opts": gitleaks_log_opts,
        "truffle_history": truffle_history,
    }


def scan_repo(
    repo: Path, *, run_scanners: bool = True, full: bool = False
) -> dict[str, Any]:
    root = find_repo(repo)
    current = current_paths(root)
    refs = repository_refs(root)
    scanner_state = scanner_snapshot(run_scanners)
    cached, cache_note = load_cache(root)
    plan = scan_plan(root, refs, cached, cache_note, scanner_state, full_requested=full)

    current_findings, current_truncated = scan_current_tree(root, current)
    if plan["full"]:
        objects = historical_objects(root)
        historical_findings, history_truncated = scan_historical_objects(root, current, objects)
        cached_historical: list[Finding] = []
    else:
        objects = plan["new_objects"]
        historical_findings, history_truncated = scan_historical_objects(root, current, objects)
        cached_historical = [
            Finding(**item)
            for item in (cached or {}).get("findings", [])
            if item.get("commit")
        ]
        for finding in cached_historical:
            finding.status = finding_status(finding.commit, finding.file, current)

    findings = current_findings + cached_historical + historical_findings
    scanners: dict[str, dict[str, str | None]] = {}
    if run_scanners:
        scanner_findings, status, note = run_gitleaks(
            root, current, history_log_opts=plan["gitleaks_log_opts"]
        )
        findings.extend(scanner_findings)
        scanners["Gitleaks"] = {"status": status, "note": note}
        scanner_findings, status, note = run_trufflehog(
            root, current, history=plan["truffle_history"]
        )
        findings.extend(scanner_findings)
        scanners["TruffleHog"] = {"status": status, "note": note}
    else:
        scanners = {
            "Gitleaks": {"status": "disabled", "note": "disabled by caller"},
            "TruffleHog": {"status": "disabled", "note": "disabled by caller"},
        }
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

    cached_counts = (cached or {}).get("counts")
    counts = repository_counts(
        root,
        cached_counts if isinstance(cached_counts, dict) else None,
        refresh_history=plan["full"] or bool(plan["changed_refs"]),
    )
    history_scanner_mode = "disabled" if not run_scanners else "full"
    if run_scanners and not plan["full"]:
        if plan["gitleaks_log_opts"]:
            history_scanner_mode = "delta"
        else:
            history_scanner_mode = "cached"
    trufflehog_history_mode = "disabled" if not run_scanners else (
        "full" if plan["truffle_history"] == "full" else "delta" if plan["truffle_history"] else "cached"
    )
    coverage: dict[str, Any] = {
        "scan_mode": "full" if plan["full"] else "incremental",
        "cache": {
            "path": ".git/did-i-leak/state.json",
            "status": (
                "ignored"
                if full
                else "initialized"
                if cached is None and cache_note == "No trusted scan cache found."
                else "invalidated"
                if plan["full"]
                else "reused"
            ),
            "reason": plan["reason"],
        },
        "previous_trusted_scan": short_commit(plan["previous_refs"].get("HEAD")),
        "current_head": short_commit(refs.get("HEAD")),
        "new_commits": plan["new_commits"],
        "historical_objects_scanned": len(objects),
        "history_scanner_mode": history_scanner_mode,
        "trufflehog_history_mode": trufflehog_history_mode,
        "current_tree": "tracked, non-ignored, and ignored files outside dependency/build directories",
        "git_history": "reachable commits, branches, tags, and historical blobs",
        "counts": counts,
        "heuristic_truncated_current_files": current_truncated,
        "heuristic_truncated_historical_blobs": history_truncated,
        "scanners": scanners,
    }

    cache_safe_to_write = not history_truncated and not any(item["status"] == "failed" for item in scanners.values())
    cache_write_note: str | None = None
    if cache_safe_to_write:
        payload = {
            "schema": CACHE_SCHEMA,
            "tool_version": TOOL_VERSION,
            "detection_fingerprint": detection_fingerprint(),
            "config_fingerprint": config_fingerprint(root),
            "scanner_mode": scanner_state["mode"],
            "scanners": scanner_state,
            "refs": refs,
            "counts": counts,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "findings": safe_finding_dicts(result_findings),
        }
        try:
            write_cache(root, payload)
        except OSError:
            cache_write_note = "Scan cache could not be written; the next run will audit fully."
    elif history_truncated:
        cache_write_note = "Historical heuristic coverage was truncated; cached coverage was not advanced."
    else:
        cache_write_note = "External scanner failure; cached coverage was not advanced."
    if cache_write_note:
        coverage["cache"]["write_note"] = cache_write_note
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
    coverage = result["coverage"]
    lines.append(f"* Scan mode: {coverage['scan_mode']}")
    if coverage.get("previous_trusted_scan"):
        lines.append(f"* Previous trusted scan: {coverage['previous_trusted_scan']}")
    if coverage.get("current_head"):
        lines.append(f"* Current HEAD: {coverage['current_head']}")
    if coverage["scan_mode"] == "incremental":
        lines.append(f"* History delta: {coverage['new_commits']} new commit(s) + working tree scanned")
    elif coverage["cache"].get("reason"):
        lines.append(f"* {coverage['cache']['reason']}")
    counts = coverage["counts"]
    lines.append(
        f"* Git history: {counts['reachable_commits']} reachable commits · "
        f"{counts['branches']} branches · {counts['tags']} tags"
    )
    lines.append("* Current tree: tracked, non-ignored, and ignored files outside dependency/build directories")
    for name, scanner in result["coverage"]["scanners"].items():
        suffix = f" ({scanner['note']})" if scanner.get("note") else ""
        lines.append(f"* {name}: {scanner['status']}{suffix}")
    lines.append(f"* Gitleaks history: {coverage['history_scanner_mode']}")
    lines.append(f"* TruffleHog history: {coverage['trufflehog_history_mode']}")
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
    parser.add_argument("--full", action="store_true", help="ignore local scan cache and audit all reachable history")
    args = parser.parse_args(argv)
    try:
        result = scan_repo(Path(args.repo), run_scanners=not args.no_scanners, full=args.full)
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
