import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import did_i_leak


class DidILeakTest(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

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

            result = did_i_leak.scan_repo(repo)
            self.assertEqual(result["verdict"], "GO WITH REVIEW")
            self.assertEqual(result["summary"]["blockers"], 0)

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
