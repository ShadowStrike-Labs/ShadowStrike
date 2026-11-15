#!/usr/bin/env python3
"""Contract: ProcessKiller asks the driver only for what the driver implements (task 362).

ProcessKiller's escalation ladder ended in two kernel requests the driver never implemented:
  - level 8 "Nuclear" sent a FilterMessageType_ProcessNotify frame as a kill order, but the driver
    registers no request handler for that type, so the unhandled-message path answered
    STATUS_SUCCESS with no output and nothing was terminated;
  - PPL removal sent an 8-byte {pid, action=0} payload as RegisterProtectedProcess, whose handler
    rejects anything smaller than SHADOWSTRIKE_PROTECTED_PROCESS and can only ADD protection - so
    had it ever been accepted, it would have protected the process being killed.
Both are gone: the ladder stops at level 7 and the two paths say the capability does not exist.

The last test is a deliberate tripwire. If the driver gains a terminate or unprotect handler, it
fails, so whoever adds it also wires ProcessKiller to the real request instead of leaving the
honest-but-unavailable path in place.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KILLER = ROOT / "src/PhantomCore/Core/Process/ProcessKiller.cpp"
MESSAGE_HANDLER = ROOT / "PhantomSensor/PhantomSensor/Communication/MessageHandler.c"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def function_body(src: str, signature: str) -> str:
    start = src.find(signature)
    if start < 0:
        return ""
    end = src.find("\n    }\n", start)
    return src[start:end] if end > start else ""


class ProcessKillerKernelRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = strip_comments(KILLER.read_text(encoding="utf-8", errors="surrogateescape"))
        cls.driver = strip_comments(MESSAGE_HANDLER.read_text(encoding="utf-8", errors="surrogateescape"))

    def test_sources_found(self):
        self.assertIn("KillResult KillKernelDriver(", self.code)
        self.assertIn("bool RemoveProtectionInternal(uint32_t pid) {", self.code)
        self.assertIn("MhRegisterHandler(", self.driver)

    def test_no_frame_the_driver_does_not_handle_is_sent(self):
        for banned in ("FilterMessageType_ProcessNotify", "FilterMessageType_RegisterProtectedProcess",
                       "SendToKernel(", "RequestKernelProtectionRemoval"):
            self.assertFalse(banned in self.code,
                             "ProcessKiller sends %s again; the driver implements no terminate or "
                             "unprotect request for it" % banned)

    def test_the_nuclear_method_reports_failure_without_side_effects(self):
        body = function_body(self.code, "[[nodiscard]] KillResult KillKernelDriver(")
        self.assertTrue(body, "KillKernelDriver not found")
        # Booleans, never the haystack: a failing assertIn would print the whole body.
        self.assertTrue("return KillResult::Failed;" in body, "KillKernelDriver no longer reports Failed")
        self.assertFalse("kernelKills" in body, "a kill that never happened is counted")
        self.assertFalse("KillResult::Success" in body, "KillKernelDriver can report a kill it never made")

    def test_the_ladder_stops_at_level_seven(self):
        self.assertFalse("KillWithMethod(pid, KillMethod::Nuclear" in self.code,
                         "the escalation ladder still escalates to the unimplemented level 8")
        self.assertTrue("kernel-assisted termination " in self.code,
                        "the ladder no longer says kernel-assisted termination is unavailable")

    def test_tripwire_the_driver_still_has_no_terminate_or_unprotect_handler(self):
        registered = re.findall(r"MhRegisterHandler\(\s*(FilterMessageType_\w+)", self.driver)
        self.assertTrue(registered, "no MhRegisterHandler registrations found - the parse is broken")
        self.assertIn("FilterMessageType_RegisterProtectedProcess", registered)
        self.assertNotIn(
            "FilterMessageType_ProcessNotify", registered,
            "the driver now handles ProcessNotify requests: wire ProcessKiller's level 8 to it "
            "and update this contract")
        for name in registered:
            self.assertNotRegex(
                name, r"(?i)terminate|kill|unprotect",
                "the driver now registers %s: wire ProcessKiller to it and update this contract" % name)


if __name__ == "__main__":
    unittest.main()
