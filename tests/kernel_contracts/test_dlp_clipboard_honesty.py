#!/usr/bin/env python3
"""Contract: a DLP clipboard leak is detected, not blocked (task 271).

ClipboardMonitoringThreadFunc's clipboard-clearing call is disabled - emptying a
user's clipboard on a heuristic match is destructive and irreversible, so it needs
an owner ruling on false-positive tolerance (task 271 piece 2). Until then,
sensitive data copied to the clipboard stays available to every process after the
product has logged it. The log and the statistics must say so: the counter is
clipboardLeaksDetected, the clipboard channel is not counted as a block in
operationsBlocked, and the clipboard monitor logs a detection, not a block.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DLP_CPP = ROOT / "src/Products/Community/PhantomHome/Privacy/DataLeakProtection.cpp"


class DlpClipboardHonestyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = DLP_CPP.read_text(encoding="utf-8", errors="surrogateescape")

    def test_the_blocks_counter_name_that_claimed_a_phantom_block_is_gone(self):
        self.assertNotIn(
            "clipboardBlocks", self.src,
            "the clipboardBlocks counter still exists; its name claims a block that "
            "never happens, because the clipboard is never cleared")

    def test_the_clipboard_monitor_does_not_log_a_block_it_did_not_perform(self):
        self.assertNotIn(
            "Blocked sensitive data in clipboard", self.src,
            "the clipboard monitor still logs that it Blocked a leak it did not clear")
        self.assertIn(
            "Detected sensitive data in clipboard", self.src,
            "the clipboard monitor must report a detection, not a block")

    def test_a_clipboard_leak_is_counted_as_a_detection_not_a_block(self):
        m = re.search(
            r"if \(result\.ShouldBlock\(\)\) \{.*?m_stats\.operationsAllowed\+\+;",
            self.src, re.S)
        self.assertIsNotNone(m, "the outbound-data counting block was not found")
        block = m.group(0)
        self.assertIn(
            "m_stats.clipboardLeaksDetected++", block,
            "a would-block clipboard leak is not recorded as a detection")
        clip = block.index("ChannelType::Clipboard")
        blocked = block.index("m_stats.operationsBlocked++")
        self.assertLess(
            clip, blocked,
            "the clipboard channel is still counted inside the operationsBlocked path; "
            "it must be split out, because nothing is blocked on that channel")


if __name__ == "__main__":
    unittest.main()
