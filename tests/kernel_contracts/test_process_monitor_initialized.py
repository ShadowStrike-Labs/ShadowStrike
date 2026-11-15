#!/usr/bin/env python3
"""Contract: the process-creation monitor is initialized and torn down (task 386).

ShadowStrikeRegisterProcessCallbacks arms the PsSetCreateProcessNotifyRoutineEx
callback, but ShadowStrikeProcessNotifyCallback bails at its
'!g_ProcessMonitor.Initialized' gate until ShadowStrikeInitializeProcessMonitoring
sets that flag. For the life of the product that init had NO CALLER anywhere in the
tree, so every process creation no-oped before PnpSendProcessNotification: the
1.0.133 field run saw zero FilterMessageType_ProcessNotify reach user mode across
1.6M messages while the image and registry monitors - which ARE initialized in
DriverEntry - flowed in volume.

This pins the wiring so the defect cannot silently return:
  * DriverEntry calls ShadowStrikeInitializeProcessMonitoring, and it does so after
    FltStartFiltering (the post-init region), keeping the lookaside/timer/engine-
    reference setup off the quiescent boot path rather than merely registering the
    callback and leaving the monitor dark;
  * DriverEntry calls ShadowStrikeCleanupProcessMonitoring on unload, AFTER the
    process callback is unregistered and drained (PsSetCreateProcessNotifyRoutineEx
    Remove blocks until every in-flight callback returns) and BEFORE TmShutdown
    tears down the TimerManager that the cleanup's TmCancel needs.

Comments are stripped before searching so a commented-out call cannot pass this.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVER_ENTRY = ROOT / "PhantomSensor/PhantomSensor/Core/DriverEntry.c"

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')


def _strip_comments_and_strings(src: str) -> str:
    """Remove block and line comments and string literals.

    String literals are blanked too: the init failure path logs a message that
    names the function, and that mention must not be mistaken for a call.
    """
    src = _BLOCK_COMMENT.sub(" ", src)
    src = _LINE_COMMENT.sub(" ", src)
    src = _STRING_LITERAL.sub('""', src)
    return src


class ProcessMonitorInitializedContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = DRIVER_ENTRY.read_text(encoding="utf-8", errors="surrogateescape")
        cls.code = _strip_comments_and_strings(raw)

    def test_source_was_found(self):
        self.assertTrue(self.code.strip(), "DriverEntry.c not found or empty")

    def test_the_comment_stripper_is_not_vacuous(self):
        # If stripping blanked everything, every assertion below would pass for the
        # wrong reason. Prove real code survives and a known comment does not.
        self.assertIn("FltStartFiltering", self.code)
        self.assertNotIn("winlogon grey-screen", self.code)

    def test_process_monitor_is_initialized(self):
        # The defect was the total absence of this call.
        self.assertIn("ShadowStrikeInitializeProcessMonitoring()", self.code,
                      "DriverEntry never calls ShadowStrikeInitializeProcessMonitoring, "
                      "so the process callback stays dormant and no process "
                      "notification ever reaches user mode (task 386)")

    def test_process_monitor_is_cleaned_up_on_unload(self):
        self.assertIn("ShadowStrikeCleanupProcessMonitoring()", self.code,
                      "DriverEntry never calls ShadowStrikeCleanupProcessMonitoring, "
                      "so enabling init would leak the monitor's lookaside lists and "
                      "leave its periodic cleanup timer live across unload")

    def test_init_runs_after_filtering_starts(self):
        flt = self.code.find("FltStartFiltering(g_DriverData.FilterHandle)")
        init = self.code.find("ShadowStrikeInitializeProcessMonitoring()")
        self.assertGreater(flt, 0, "FltStartFiltering call not found")
        self.assertGreater(init, 0, "monitor init call not found")
        self.assertGreater(
            init, flt,
            "monitor init must run in the post-init region, after FltStartFiltering, "
            "to keep lookaside/timer/engine-reference setup off the boot path")

    def test_cleanup_runs_after_callback_unregister_and_before_timer_shutdown(self):
        unreg = self.code.find("ShadowStrikeUnregisterProcessCallbacks(g_CallbackFlags)")
        cleanup = self.code.find("ShadowStrikeCleanupProcessMonitoring()")
        tm = self.code.find("TmShutdown(g_TimerManager)")
        self.assertGreater(unreg, 0, "process-callback unregister not found")
        self.assertGreater(cleanup, 0, "monitor cleanup not found")
        self.assertGreater(tm, 0, "TmShutdown not found")
        self.assertGreater(
            cleanup, unreg,
            "cleanup must run AFTER the process callback is unregistered and drained, "
            "or it frees monitor state a still-running callback would touch")
        self.assertLess(
            cleanup, tm,
            "cleanup must run BEFORE TmShutdown: it cancels its periodic cleanup "
            "timer through the TimerManager, which must still be alive")


if __name__ == "__main__":
    unittest.main()
