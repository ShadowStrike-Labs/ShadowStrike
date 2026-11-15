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

Remainder (task 374): a routine, non-impairing Defender write is now recorded at Info -
rather than left silent - when it came from Defender's own verified image (an executable
under Defender's platform tree whose Microsoft signature verifies through the offline
ExecutableAnalyzer path). The impairing-value classification is returned first, so this
only labels benign updates and can never silence a disable.
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

    # --- task 374 remainder: routine Defender writes from a verified image at Info ---

    def test_routine_defender_write_from_a_verified_image_is_surfaced_at_info(self):
        self.assertIn(
            "WriterIsVerifiedDefenderPlatformImage(event.processPath)", self.code,
            "the Defender branch does not consult the verified-image helper")
        emitted = re.search(
            r"WriterIsVerifiedDefenderPlatformImage\(event\.processPath\)\)\s*\{\s*"
            r"SS_LOG_INFO",
            self.code, re.S)
        self.assertIsNotNone(
            emitted,
            "a routine Defender write from a verified image is not recorded at Info")

    def test_the_verified_image_helper_requires_the_defender_tree_and_a_signature(self):
        m = re.search(
            r"WriterIsVerifiedDefenderPlatformImage\(const std::wstring& processPath\)\s*\{.*?\n\}",
            self.code, re.S)
        self.assertIsNotNone(m, "the WriterIsVerifiedDefenderPlatformImage helper was not found")
        body = m.group(0)
        self.assertIn(
            r"\\windows defender\\platform\\", body,
            "the helper does not scope to Defender's ACL-protected platform tree")
        self.assertIn(
            "isMicrosoftSigned", body,
            "the helper does not require a verified Microsoft signature")

    def test_the_disable_is_returned_before_the_info_path(self):
        # A signed writer must not silence a disable: the DEFENDER_DISABLE return has to
        # precede the verified-image Info branch.
        disable = self.code.find("return RegistryThreatType::DEFENDER_DISABLE;")
        info = self.code.find("WriterIsVerifiedDefenderPlatformImage(event.processPath)")
        self.assertGreater(disable, 0, "the DEFENDER_DISABLE return was not found")
        self.assertGreater(info, 0, "the verified-image Info branch was not found")
        self.assertLess(
            disable, info,
            "the verified-image Info path precedes the DEFENDER_DISABLE return, so a "
            "Microsoft-signed reg.exe or PowerShell could silence a protection disable")

    def test_the_signature_check_reuses_the_offline_executable_analyzer_path(self):
        # ExecutableAnalyzer::VerifySignature runs WTD_REVOKE_NONE with
        # WTD_CACHE_ONLY_URL_RETRIEVAL, so it does no network I/O on the latency-critical
        # registry thread. The helper must reuse that path, not roll a fresh WinVerifyTrust.
        self.assertIn(
            "ExecutableAnalyzer::Instance().VerifySignature", self.code,
            "the helper does not reuse ExecutableAnalyzer's vetted offline signature path")
        m = re.search(
            r"WriterIsVerifiedDefenderPlatformImage\(const std::wstring& processPath\)\s*\{.*?\n\}",
            self.code, re.S)
        self.assertNotIn(
            "WinVerifyTrust", m.group(0),
            "the helper calls WinVerifyTrust directly instead of the vetted offline path")


if __name__ == "__main__":
    unittest.main()
