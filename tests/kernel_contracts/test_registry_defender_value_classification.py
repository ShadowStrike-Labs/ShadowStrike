#!/usr/bin/env python3
"""Contract: a Windows Defender registry write is a disable by its VALUE, not its KEY (task 374).

The 1.0.125 field run reported MsMpEng.exe writing HKLM\\SOFTWARE\\Microsoft\\Windows
Defender\\Signature Updates as a Critical "Registry threat detected". The cause was a
blanket rule: any write to a key containing "Windows Defender" returned DEFENDER_DISABLE.
Defender writes its own operational state to those keys constantly, so the detector fired
on routine activity. The fix classifies by the value written: only a protection-impairing
value, an exclusion, or a deletion is a disable. A signed-writer exemption is explicitly
NOT used, because reg.exe and PowerShell are Microsoft-signed and are how Defender is
switched off.
"""
import re
import unittest
from pathlib import Path


def strip_block_and_line_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


ROOT = Path(__file__).resolve().parents[2]
RM = ROOT / "src/PhantomCore/Core/Registry/RegistryMonitor.cpp"


class RegistryDefenderValueClassificationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = RM.read_text(encoding="utf-8", errors="surrogateescape")
        cls.code = strip_block_and_line_comments(cls.raw)

    def test_a_defender_key_write_is_no_longer_a_blanket_disable(self):
        # With comments stripped, the old shape - key contains "Windows Defender" then an
        # immediate return DEFENDER_DISABLE - must be gone.
        blanket = re.search(
            r'find\(L"Windows Defender"\)\s*!=\s*std::wstring::npos\)\s*\{\s*'
            r'return RegistryThreatType::DEFENDER_DISABLE;',
            self.code, re.S)
        self.assertIsNone(
            blanket,
            "a Defender-key write is still classified as DEFENDER_DISABLE by key alone, so "
            "Defender's own signature update is reported as a Critical registry threat")

    def test_the_defender_branch_classifies_by_the_value_written(self):
        self.assertIn(
            "if (DefenderWriteIsProtectionImpairing(event)) {", self.code,
            "the Defender branch does not consult the value-based classifier")

    def test_the_impairing_set_covers_the_real_disables_removal_and_exclusions(self):
        m = re.search(
            r"DefenderWriteIsProtectionImpairing\(const RegistryEvent& event\)\s*\{.*?\n\}",
            self.code, re.S)
        self.assertIsNotNone(m, "the DefenderWriteIsProtectionImpairing classifier was not found")
        body = m.group(0)
        for value in ("disableantispyware", "disablerealtimemonitoring",
                      "disablebehaviormonitoring", "tamperprotection", "puaprotection"):
            self.assertIn(
                value, body,
                "%s is not treated as a Defender disable - a real evasion would pass" % value)
        self.assertIn(
            r"\\exclusions", body,
            "adding a Defender exclusion is not treated as impairing")
        self.assertIn(
            "RegistryOp::DeleteKey", body,
            "deleting a Defender key (definition/policy removal) is not treated as impairing")
        self.assertIn(
            "RegistryOp::DeleteValue", body,
            "deleting a Defender value (definition removal) is not treated as impairing")


if __name__ == "__main__":
    unittest.main()
