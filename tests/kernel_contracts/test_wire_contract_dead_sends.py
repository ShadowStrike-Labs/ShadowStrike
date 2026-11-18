"""Host-safe contract: the wire-contract dead kernel-block sends are removed, and
the REAL user-mode enforcement is preserved (tasks 158 / 361, fix option A).

Many user-mode modules sent the kernel a "block this PID" request as a local
struct whose first field was an invented message type (0x30, 0x31, 0x90, ...)
with NO SHADOWSTRIKE_MESSAGE_HEADER. SendToKernel transmits the buffer unchanged,
and the driver's ShadowStrikeValidateInputBuffer refuses any frame that does not
begin with a valid header - so every one of these sends was dead: silently
refused, yet logged as "kernel block requested". The kernel also has no
on-demand process-block handler at all; malicious code is blocked at scan/create
time (verdicts) and running processes are terminated in USER MODE via
Core::Process::ProcessKiller::TerminateTree.

The fix (option A) removes each dead send and guarantees the real user-mode
termination runs, so detection is never weakened - only the false kernel-block
claim and the dead code go. This test pins, per cleaned module, that (a) the
invented-type dead send is gone and (b) the module's real enforcement remains.
It grows as each module is cleaned; a regression that reintroduces a headerless
0x30-style send, or drops the ProcessKiller enforcement, fails here.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The invented dead-send fingerprints. A bare struct whose first field is set to
# a hardcoded hex message type and shipped straight to SendToKernel. These values
# are >= FilterMessageType_Max (or collide with a kernel->user notify) and never
# carried a SHADOWSTRIKE_MESSAGE_HEADER.
DEAD_SEND_PATTERNS = (
    "messageType = 0x30",
    "msgType; uint32_t pid; } blockReq{0x30",
    "blockReq{0x30",
    "= 0x31;",
    "= 0x35;",
    "= 0x36;",
    "= 0x90;",
    "0x00AD0001",
    "0x00BB0001",
    "0x00BB0002",
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="ignore")


class WireContractDeadSendsContract(unittest.TestCase):
    # Modules cleaned so far. Each entry: the source file, and a token proving the
    # module's REAL user-mode enforcement is still present (so the dead-send
    # removal did not also remove the actual block).
    CLEANED = {
        "src/PhantomCore/RansomwareProtection/RansomwareDetector.cpp":
            "Core::Process::ProcessKiller::TerminateTree",
    }

    def test_cleaned_modules_have_no_invented_dead_send(self) -> None:
        for rel in self.CLEANED:
            src = _read(rel)
            for pat in DEAD_SEND_PATTERNS:
                self.assertNotIn(
                    pat, src,
                    "%s still contains an invented headerless kernel send (%r); the "
                    "driver refuses it and it is logged as a block that never "
                    "happens (task 158/361)" % (rel, pat))

    def test_cleaned_modules_keep_real_enforcement(self) -> None:
        for rel, enforcement in self.CLEANED.items():
            src = _read(rel)
            self.assertIn(
                enforcement, src,
                "%s no longer calls %s - removing the dead kernel send must NOT "
                "remove the real user-mode enforcement (detection integrity)"
                % (rel, enforcement))

    def test_ransomwaredetector_block_method_is_gone(self) -> None:
        # RansomwareDetector::RequestKernelProcessBlock was uncalled dead code
        # wrapping a 0x30 send. It was removed from both the .cpp and the header.
        cpp = _read("src/PhantomCore/RansomwareProtection/RansomwareDetector.cpp")
        hpp = _read("src/PhantomCore/RansomwareProtection/RansomwareDetector.hpp")
        self.assertNotIn("RequestKernelProcessBlock", cpp,
                         "the dead RequestKernelProcessBlock definition must be gone")
        self.assertNotIn("RequestKernelProcessBlock", hpp,
                         "the dead RequestKernelProcessBlock declaration must be gone")

    def test_response_pipeline_still_terminates(self) -> None:
        # The confirmed-ransomware response must still terminate the process tree.
        cpp = _read("src/PhantomCore/RansomwareProtection/RansomwareDetector.cpp")
        self.assertIn("ProcessKiller::TerminateTree(pid)", cpp,
                      "ExecuteResponsePipeline must still terminate the ransomware "
                      "process tree - that is the real block")


if __name__ == "__main__":
    unittest.main(verbosity=2)
