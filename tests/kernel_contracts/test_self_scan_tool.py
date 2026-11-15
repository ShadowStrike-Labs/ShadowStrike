#!/usr/bin/env python3
"""Contract: phantom-sigbuild can scan shipped binaries against the shipped database (task 385 follow-up 1).

The deferred deep scan convicted the service's own binary (a shipped Meterpreter YARA
rule) and tried to quarantine it. The deploy script's token guard pins only that one
rule by its literal strings. This adds a self-scan MODE to phantom-sigbuild that opens
the finished signature database and scans given binaries through the same SignatureStore
the product runs, so a self-match by ANY shipped rule is observable from one command.

Run against the full merged database (11,116 rules) it found that the service and driver
are convicted by several DITEKSHEN rules keyed on FUNCTIONAL detection strings the product
must contain (Defender-disable value names, VM-evasion driver names, download-cradle
command patterns). So this is an audit diagnostic, NOT a blocking gate: a strict
"no shipped binary matches any rule" invariant is unachievable for an AV, which legitimately
carries the indicators its rules detect. The scalable fix for functional self-matches is the
own-binary remediation exemption (task 385 follow-up 3); the tool's job is to surface
INCIDENTAL plain-text indicators (the Meterpreter/Locky class) so they can be encoded.

These assertions pin the tool's safety properties so a later edit cannot make it pass
vacuously (scan nothing, skip a rule class, or treat an un-examined file as clean).
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tools/phantom-sigbuild/SigBuildMain.cpp"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


class SelfScanToolContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = strip_comments(SRC.read_text(encoding="utf-8", errors="surrogateescape"))
        m = re.search(r"int RunSelfScan\(const Options& opt\)\s*\{.*?\n\}", cls.code, re.S)
        cls.body = m.group(0) if m else ""

    def test_source_and_function_found(self):
        self.assertTrue(self.code.strip(), "SigBuildMain.cpp not found or empty")
        self.assertTrue(self.body, "RunSelfScan was not found")

    def test_wmain_dispatches_to_self_scan_mode(self):
        self.assertRegex(
            self.code, r"if \(!opt\.scanDatabase\.empty\(\)\)\s*\{[^}]*return RunSelfScan\(opt\);",
            "wmain does not dispatch to RunSelfScan when --scan-db is given")

    def test_scan_db_requires_a_binary_to_scan(self):
        self.assertIn("--scan-db requires at least one --self-scan", self.code,
                      "scan mode does not require a binary, so it could examine nothing")

    def test_self_scan_covers_all_three_rule_classes(self):
        for member in ("enableHashLookup  = true", "enablePatternScan = true",
                       "enableYaraScan    = true"):
            self.assertIn(member, self.body,
                          "RunSelfScan does not enable %s, so that rule class is not "
                          "checked against our own binaries" % member)

    def test_self_scan_reports_every_match_not_just_the_first(self):
        self.assertIn("stopOnFirstMatch  = false", self.body,
                      "RunSelfScan stops on the first match, hiding further self-matches")

    def test_self_scan_rejects_an_unexamined_file_as_untrusted(self):
        self.assertIn("WasExamined()", self.body,
                      "RunSelfScan does not verify the file was examined, so a scan that "
                      "never ran would read as clean")

    def test_self_scan_inspects_each_match_class(self):
        for vec in ("result.yaraMatches", "result.patternMatches", "result.hashMatches"):
            self.assertIn(vec, self.body, "RunSelfScan does not inspect %s" % vec)

    def test_a_self_match_fails_the_scan(self):
        # convicted binaries must return the dedicated non-zero code, not 0.
        self.assertRegex(self.body, r"(?s)if \(convicted > 0\)\s*\{.*?return 8;",
                         "a self-match does not fail the scan with exit 8")


if __name__ == "__main__":
    unittest.main()
