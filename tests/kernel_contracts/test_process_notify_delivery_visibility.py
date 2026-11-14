#!/usr/bin/env python3
"""Contract: the periodic capacity line shows where process notifications stop (task 386).

The 1.0.133 VM run counted zero OnKernelProcessNotify calls in 22 minutes of first
boot (procNotifyPreBudgetUs n=0 for both stages) while file scans flowed, so the
whole process-creation handler - encoded-PowerShell and LOLBin-cradle detection,
the revoked-certificate refusal - never ran. Each hop on the way up can lose a
notification without a log line:

  driver   ShadowStrikeSendProcessNotification returns success without sending when
           NotificationsEnabled is off, and buffers into the message queue when no
           client port is acquired; excluded processes are skipped before that;
  service  IPCManager counts every received message per type in byMessageType,
           which nothing printed.

The driver's status reply carries NotificationsEnabled and ConnectedClients, which
this line queries anyway; printing them beside the per-type receive counts says
whether the driver is set to send and has a client, and whether anything arrives.
The struct also declares message-queue and process-exclusion totals, but the
handler that answers the query (CommPort.c ShadowStrikeHandleQueryDriverStatus)
never fills them, so they are deliberately not printed: a structural zero would
read as a measured empty queue.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RTP_CPP = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp"


class ProcessNotifyDeliveryVisibilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = RTP_CPP.read_text(encoding="utf-8", errors="surrogateescape")
        start = src.find('"RealTimeProtection: capacity - ')
        # The capacity report spans from the driver-status query to the format call.
        q = src.rfind("QueryDriverStatus(ds)", 0, start)
        cls.region = src[q:start + 4000] if q >= 0 and start >= 0 else ""

    def test_the_region_was_found(self):
        self.assertTrue(self.region, "capacity report region not found")

    def test_the_driver_side_gates_are_printed(self):
        for field, member in (("enabled=", "ds.NotificationsEnabled"),
                              ("clients=", "ds.ConnectedClients")):
            self.assertIn(field, self.region, f"notifyPath field {field} is not printed")
            self.assertIn(member, self.region, f"{member} is not read into the line")

    def test_fields_the_status_reply_never_fills_are_not_printed(self):
        # CommPort.c ShadowStrikeHandleQueryDriverStatus answers this query; it zeroes
        # the struct and fills neither the message-queue nor the process-exclusion
        # totals, so printing them would show a structural zero as if it were a
        # measured empty queue.
        for member in ("ds.MqTotalEnqueued", "ds.MqTotalDropped", "ds.MqCurrentDepth",
                       "ds.ProcExclTotalLookups", "ds.ProcExclProcessesExcluded"):
            self.assertNotIn(member, self.region,
                             f"{member} is printed but the status reply never fills it")

    def test_user_mode_receive_counts_per_type_are_printed(self):
        self.assertIn("ipcRx: total={} scan={} process={} image={} registry={}", self.region)
        self.assertRegex(self.region, r"rx\(FilterMessageType_ProcessNotify\)",
                         "the ProcessNotify receive count is not read")
        self.assertRegex(self.region, r"kernelPart,\s*ipcRxPart\)",
                         "the receive counts are built but not emitted in the capacity line")

    def test_every_other_received_type_is_listed(self):
        # The 1.0.133 run received ~250,000 messages in 6 minutes, the four named
        # types under 7% of them; the rest must be visible by type number.
        self.assertRegex(self.region,
                         r"for \(size_t type = 0; type < ipc\.byMessageType\.size\(\); \+\+type\)",
                         "the other received types are not enumerated")
        self.assertIn('ipcRxPart += std::format(" other=[{}]", others);', self.region,
                      "the other received types are not appended to the line")


if __name__ == "__main__":
    unittest.main()
