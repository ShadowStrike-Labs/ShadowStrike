#!/usr/bin/env python3
"""Contract: threat-feed API keys are supplied per installation and never shipped (task 17).

Every wired feed that needs a key is licensed for non-commercial use on its free tier (abuse.ch
ToU 3.1/4, the OTX EULA, the VirusTotal Public API terms, the AbuseIPDB free tier). The product
is compliant because it ships no key: FeedCredentials reads one from the hardened data directory
of each installation. docs/ThreatIntel-Feeds.md records the position; these assertions make it
mechanical, so a key cannot be baked into a build, a package or the repository unnoticed.
"""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CREDENTIALS_HPP = ROOT / "src/PhantomCore/ThreatIntel/FeedCredentials.hpp"
DOC = ROOT / "docs/ThreatIntel-Feeds.md"
README = ROOT / "README.md"
TEXT_SUFFIXES = (".cpp", ".hpp", ".h", ".c", ".ps1", ".psm1", ".py", ".wxs", ".wxi", ".json",
                 ".ini", ".cfg", ".conf", ".txt", ".md", ".xml", ".yml", ".yaml", ".props",
                 ".targets", ".vcxproj", ".bat", ".cmd")


def git_ls_files(*patterns):
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", *patterns],
                         check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def credential_key_names():
    src = CREDENTIALS_HPP.read_text(encoding="utf-8")
    block = re.search(r"namespace FeedCredentialKeys \{(.*?)\n\}", src, re.S)
    return re.findall(r'inline constexpr const char\* \w+ = "([A-Z0-9_]+)";',
                      block.group(1) if block else "")


class FeedKeysUserSuppliedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = credential_key_names()

    def test_the_key_names_are_read_from_the_source(self):
        # Non-vacuity: the value scan below is only as good as this list.
        for name in ("ABUSECH_AUTH_KEY", "OTX_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
            self.assertIn(name, self.keys, "%s is no longer a FeedCredentialKeys name" % name)

    def test_no_credentials_file_is_tracked(self):
        self.assertEqual(git_ls_files("*.credentials"), [],
                         "a credentials file is committed to the repository")

    def test_gitignore_keeps_credentials_out(self):
        lines = [ln.strip() for ln in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()]
        self.assertIn("*.credentials", lines, ".gitignore no longer excludes *.credentials")

    def test_no_installer_source_ships_a_credentials_file(self):
        offenders = []
        for rel in git_ls_files("*.wxs", "*.wxi"):
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"<File\b[^>]*>", text):
                if "credentials" in m.group(0).lower():
                    offenders.append("%s: %s" % (rel, m.group(0)))
        self.assertEqual(offenders, [], "an installer File element ships feed credentials")

    def test_no_tracked_file_assigns_a_key_value(self):
        # A real key is a long token; a placeholder such as <your key> is not matched.
        rx = re.compile(r"\b(%s)\s*[=:]\s*[\"']?[A-Za-z0-9]{20,}" % "|".join(map(re.escape, self.keys)))
        offenders = []
        for rel in git_ls_files():
            if not rel.endswith(TEXT_SUFFIXES):
                continue
            try:
                text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in rx.finditer(text):
                offenders.append("%s: %s=..." % (rel, m.group(1)))
        self.assertEqual(offenders, [], "a feed API key value is committed: %s" % offenders)

    def test_the_position_is_documented_and_linked(self):
        doc = DOC.read_text(encoding="utf-8")
        for name in self.keys:
            self.assertIn(name, doc, "docs/ThreatIntel-Feeds.md does not cover %s" % name)
        self.assertIn("docs/ThreatIntel-Feeds.md", README.read_text(encoding="utf-8"),
                      "README does not link the feed licensing position")


if __name__ == "__main__":
    unittest.main()
