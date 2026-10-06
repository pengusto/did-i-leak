import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import did_i_leak


class DidILeakTest(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def make_repo(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name)
        self.git(repo, "init", "-b", "main")
        self.git(repo, "config", "user.email", "test@example.invalid")
        self.git(repo, "config", "user.name", "did-i-leak test")
        (repo / "README.md").write_text("safe\n")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-m", "initial")
        return repo

    def commit(self, repo: Path, message: str) -> None:
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-m", message)

    def test_deleted_historical_credential_is_no_go_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-b", "main")
            test_email = "test" + "@" + "example.invalid"
            self.git(repo, "config", "user.email", test_email)
            self.git(repo, "config", "user.name", "did-i-leak test")
            (repo / "README.md").write_text("safe\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "initial")
            historical_value = "live-" + "secret-" + "123456789"
            (repo / "old-config.py").write_text(f"API_KEY = '{historical_value}'\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "add temporary config")
            (repo / "old-config.py").unlink()
            self.git(repo, "add", "-A")
            self.git(repo, "commit", "-m", "remove temporary config")

            result = did_i_leak.scan_repo(repo, run_scanners=False)
            output = did_i_leak.render(result)

            self.assertEqual(result["verdict"], "NO-GO")
            self.assertTrue(any(item["status"] == "deleted from current tree" for item in result["findings"]))
            self.assertNotIn("live" + "-secret-123456789", output)
            self.assertIn("old-config.py", output)

    def test_placeholder_is_not_blocker(self) -> None:
        example_value = "example-" + "key-123456"
        findings = did_i_leak.heuristic_findings(
            f"API_KEY = '{example_value}'\n",
            "example.env",
            current={"example.env"},
        )
        self.assertEqual(findings[0].severity, "LIKELY FALSE POSITIVE")

    def test_missing_scanners_require_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-b", "main")
            test_email = "test" + "@" + "example.invalid"
            self.git(repo, "config", "user.email", test_email)
            self.git(repo, "config", "user.name", "did-i-leak test")
            (repo / "README.md").write_text("safe\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "initial")

            with patch.object(did_i_leak.shutil, "which", return_value=None):
                result = did_i_leak.scan_repo(repo)
            self.assertEqual(result["verdict"], "GO WITH REVIEW")
            self.assertEqual(result["summary"]["blockers"], 0)
            disabled = did_i_leak.scan_repo(repo, run_scanners=False)
            self.assertEqual(disabled["verdict"], "GO WITH REVIEW")

    def test_first_run_is_full_and_unchanged_second_run_reuses_cache(self) -> None:
        repo = self.make_repo()

        first = did_i_leak.scan_repo(repo, run_scanners=False)
        second = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(first["coverage"]["scan_mode"], "full")
        self.assertEqual(second["coverage"]["scan_mode"], "incremental")
        self.assertEqual(second["coverage"]["historical_objects_scanned"], 0)
        self.assertTrue(did_i_leak.cache_path(repo).is_file())

    def test_one_new_commit_uses_history_delta(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)

        (repo / "notes.txt").write_text("one change\n")
        self.commit(repo, "one change")
        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "incremental")
        self.assertEqual(result["coverage"]["new_commits"], 1)
        self.assertGreater(result["coverage"]["historical_objects_scanned"], 0)

    def test_working_tree_secret_is_found_without_history_rescan(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)

        (repo / "working.env").write_text("API_KEY=fake-working-secret-123456789\n")
        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "incremental")
        self.assertEqual(result["coverage"]["historical_objects_scanned"], 0)
        self.assertTrue(any(item["status"] == "current tree" for item in result["findings"]))

    def test_deleted_historical_finding_survives_incremental_run(self) -> None:
        repo = self.make_repo()
        historical_value = "rotated-secret-123456789"
        (repo / "old-config.py").write_text(f"API_KEY = '{historical_value}'\n")
        self.commit(repo, "add temporary config")
        did_i_leak.scan_repo(repo, run_scanners=False)

        (repo / "old-config.py").unlink()
        self.commit(repo, "remove temporary config")
        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertTrue(any(item["status"] == "deleted from current tree" for item in result["findings"]))

    def test_new_branch_scans_previously_unseen_history(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)
        self.git(repo, "switch", "-c", "leak-branch")
        (repo / "branch-config.py").write_text("TOKEN = 'fake-branch-secret-123456789'\n")
        self.commit(repo, "branch with old secret")

        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "incremental")
        self.assertGreater(result["coverage"]["new_commits"], 0)
        self.assertTrue(any(item["file"] == "branch-config.py" for item in result["findings"]))

    def test_history_rewrite_falls_back_to_full(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)
        (repo / "README.md").write_text("rewritten\n")
        self.git(repo, "add", "README.md")
        self.git(repo, "commit", "--amend", "--no-edit")

        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "full")
        self.assertIn("History changed", result["coverage"]["cache"]["reason"])

    def test_config_and_scanner_version_changes_invalidate_cache(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)
        (repo / ".gitleaks.toml").write_text("title = 'test config'\n")
        config_result = did_i_leak.scan_repo(repo, run_scanners=False)
        self.assertEqual(config_result["coverage"]["scan_mode"], "full")

        scanner_a = {
            "mode": "enabled",
            "Gitleaks": {"available": True, "version_fingerprint": "a" * 64},
            "TruffleHog": {"available": False, "version": "unavailable"},
        }
        scanner_b = {
            "mode": "enabled",
            "Gitleaks": {"available": True, "version_fingerprint": "b" * 64},
            "TruffleHog": {"available": False, "version": "unavailable"},
        }
        with patch.object(did_i_leak, "scanner_snapshot", return_value=scanner_a):
            did_i_leak.scan_repo(repo, run_scanners=False)
        with patch.object(did_i_leak, "scanner_snapshot", return_value=scanner_b):
            result = did_i_leak.scan_repo(repo, run_scanners=False)
        self.assertEqual(result["coverage"]["scan_mode"], "full")

    def test_corrupt_cache_falls_back_to_full(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)
        did_i_leak.cache_path(repo).write_text("not json\n")

        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "full")
        self.assertIn("corrupt", result["coverage"]["cache"]["reason"])

    def test_tampered_cache_finding_falls_back_to_full(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)
        cache = did_i_leak.cache_path(repo)
        payload = json.loads(cache.read_text())
        payload["findings"] = [{
            "category": "secret",
            "severity": "BLOCKER",
            "title": "tampered",
            "file": "unknown",
            "status": "historical",
            "confidence": "high",
            "reason": "tampered",
            "line": 1,
            "commit": "deadbee",
            "sources": ["tampered"],
        }]
        cache.write_text(json.dumps(payload))

        result = did_i_leak.scan_repo(repo, run_scanners=False)

        self.assertEqual(result["coverage"]["scan_mode"], "full")
        self.assertIn("not reachable", result["coverage"]["cache"]["reason"])

    def test_truncated_deleted_history_is_not_trusted_on_second_run(self) -> None:
        repo = self.make_repo()
        (repo / "large.txt").write_text("safe text " * 20)
        self.commit(repo, "add large historical file")
        (repo / "large.txt").unlink()
        self.commit(repo, "delete large file")

        with patch.object(did_i_leak, "MAX_TEXT_BYTES", 64):
            for _ in range(2):
                result = did_i_leak.scan_repo(repo, run_scanners=False)
                self.assertEqual(result["verdict"], "GO WITH REVIEW")
                self.assertEqual(result["coverage"]["scan_mode"], "full")
                self.assertGreater(result["coverage"]["heuristic_truncated_historical_blobs"], 0)
                self.assertFalse(did_i_leak.cache_path(repo).exists())

    def test_full_flag_ignores_cache(self) -> None:
        repo = self.make_repo()
        did_i_leak.scan_repo(repo, run_scanners=False)

        result = did_i_leak.scan_repo(repo, run_scanners=False, full=True)

        self.assertEqual(result["coverage"]["scan_mode"], "full")
        self.assertEqual(result["coverage"]["cache"]["status"], "ignored")

    def test_cache_contains_no_fixture_secret(self) -> None:
        repo = self.make_repo()
        historical_value = "fixture-secret-123456789"
        (repo / "old.env").write_text(f"PASSWORD={historical_value}\n")
        self.commit(repo, "fixture secret")
        did_i_leak.scan_repo(repo, run_scanners=False)

        cache_contents = b"".join(path.read_bytes() for path in did_i_leak.cache_path(repo).parent.glob("*") if path.is_file())
        self.assertNotIn(historical_value.encode(), cache_contents)
        self.assertEqual(os.stat(did_i_leak.cache_path(repo)).st_mode & 0o777, 0o600)

    def test_ignored_env_file_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-b", "main")
            test_email = "test" + "@" + "example.invalid"
            self.git(repo, "config", "user.email", test_email)
            self.git(repo, "config", "user.name", "did-i-leak test")
            (repo / ".gitignore").write_text(".env\n")
            env_value = "live-" + "secret-" + "123456789"
            (repo / ".env").write_text(f"API_KEY={env_value}\n")
            self.git(repo, "add", ".gitignore")
            self.git(repo, "commit", "-m", "ignore env files")

            result = did_i_leak.scan_repo(repo, run_scanners=False)
            self.assertEqual(result["verdict"], "NO-GO")
            self.assertTrue(any(item["file"] == ".env" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
