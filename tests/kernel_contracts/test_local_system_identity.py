#!/usr/bin/env python3
"""Contract: LocalSystem is decided by the token user SID (task 387).

A LocalSystem token carries S-1-5-18 as its USER; its TokenGroups do not list it.
GetProcessSecurityInfo used to set isRunningAsSystem only from group membership,
so every SYSTEM process read as not-SYSTEM and QuarantineManager's
CanTerminateProcess - which refuses only isRunningAsSystem processes - treated
SYSTEM services and OS processes as terminable. The 1.0.133 VM run reached
'Failed to terminate process: ShadowStrike Phantom Service (PID 684)' that way.

The classification itself is unit-tested (ProcessUtils_Tests.cpp,
LocalSystemIsDecidedByTheTokenUserNotOnlyByGroups); an unelevated runner cannot
open a real SYSTEM token, so this pins the wiring from the token user to it.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROCESS_UTILS = ROOT / "src/PhantomCore/Utils/ProcessUtils.cpp"


class LocalSystemIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = PROCESS_UTILS.read_text(encoding="utf-8", errors="surrogateescape")

    def _security_info_body(self):
        start = self.src.find("bool GetProcessSecurityInfo(ProcessId pid, ProcessSecurityInfo& sec")
        self.assertGreaterEqual(start, 0, "GetProcessSecurityInfo definition not found")
        end = self.src.find("\nbool ", start + 10)
        return self.src[start:end if end > 0 else len(self.src)]

    def test_the_token_user_sid_decides_local_system(self):
        body = self._security_info_body()
        self.assertRegex(
            body, r"sec\.isRunningAsSystem\s*=\s*TokenIdentityIsLocalSystem\(\s*tu->User\.Sid",
            "isRunningAsSystem is not derived from the token USER SID; a LocalSystem "
            "process would again read as not-SYSTEM and become terminable")

    def test_the_user_decision_precedes_the_group_loop_that_can_only_add_to_it(self):
        body = self._security_info_body()
        user = body.find("TokenIdentityIsLocalSystem(tu->User.Sid")
        groups = body.find("TokenGroups")
        self.assertGreaterEqual(user, 0)
        self.assertGreaterEqual(groups, 0)
        self.assertLess(user, groups,
                        "the user-SID assignment must come before the group loop, or "
                        "it would overwrite a group-derived true with false")


if __name__ == "__main__":
    unittest.main()
