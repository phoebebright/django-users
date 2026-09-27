"""Release consistency (decision 003, *Versions and pinning*).

Hosts pin a tag, so a tag must say exactly what it contains:
- `pyproject.toml`'s version has a CHANGELOG entry;
- if HEAD is tagged, the tag is `v<version>`.
Run before tagging, and in CI on tags.
"""
import re
import subprocess
from pathlib import Path
from unittest import TestCase

REPO = Path(__file__).resolve().parents[2]


def pyproject_version():
    text = (REPO / "pyproject.toml").read_text()
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)


class ReleaseConsistencyTests(TestCase):
    def test_version_has_a_changelog_entry(self):
        version = pyproject_version()
        changelog = (REPO / "CHANGELOG.md").read_text()
        self.assertRegex(changelog, rf"(?m)^## {re.escape(version)}\b",
                         f"CHANGELOG.md has no '## {version}' entry")

    def test_tag_matches_version(self):
        result = subprocess.run(
            ["git", "-C", str(REPO), "tag", "--points-at", "HEAD", "--list", "v*"],
            capture_output=True, text=True,
        )
        tags = result.stdout.split()
        if result.returncode or not tags:
            self.skipTest("HEAD is not tagged")
        self.assertEqual(tags, [f"v{pyproject_version()}"])
