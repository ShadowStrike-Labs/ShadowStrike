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

The driver already reports NotificationsEnabled, ConnectedClients, the message
queue totals and the process-exclusion totals in SHADOWSTRIKE_DRIVER_STATUS, which
this line queries anyway. Printing them beside the per-type receive counts lets one
VM run name the hop, with no driver change.
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
                              ("clients=", "ds.ConnectedClients"),
                              ("mqEnq=", "ds.MqTotalEnqueued"),
                              ("mqDrop=", "ds.MqTotalDropped"),
                              ("procExcluded=", "ds.ProcExclProcessesExcluded")):
            self.assertIn(field, self.region, f"notifyPath field {field} is not printed")
            self.assertIn(member, self.region, f"{member} is not read into the line")

    def test_user_mode_receive_counts_per_type_are_printed(self):
        self.assertIn("ipcRx: total={} scan={} process={} image={} registry={}", self.region)
        self.assertRegex(self.region, r"rx\(FilterMessageType_ProcessNotify\)",
                         "the ProcessNotify receive count is not read")
        self.assertRegex(self.region, r"kernelPart,\s*ipcRxPart\)",
                         "the receive counts are built but not emitted in the capacity line")


if __name__ == "__main__":
    unittest.main()
