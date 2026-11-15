#!/usr/bin/env python3
"""Contract: the account-name lookup in GetProcessSecurityInfo is requested, never inherited (task 138).

LookupAccountSidW is an LSASS RPC and, for a domain SID, a domain-controller round trip that
blocks until the RPC timeout when the controller is unreachable. The scope parameter used to
default to Full, so every caller that did not think about it paid for that lookup - including
BankingTrojanDetector's per-scan path, which reads only userSid and isElevated, and
QuarantineManager's terminate check, which reads only isRunningAsSystem. That is the defect
class task 48 fixed in CertificateValidator, whose Strict default gave every caller a
synchronous network revocation check.

The default is now LocalOnly. Every function that returns or compares the account name, or
the privilege display names that are resolved only for a Full query, asks for Full itself.
These assertions pin both halves: a flipped-back default fails here, and so does a name
consumer that silently starts inheriting LocalOnly and returns an empty name.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTILS_HPP = ROOT / "src/PhantomCore/Utils/ProcessUtils.hpp"
UTILS_CPP = ROOT / "src/PhantomCore/Utils/ProcessUtils.cpp"
BANKING_CPP = ROOT / "src/Products/Community/PhantomHome/Banking/BankingTrojanDetector.cpp"
QUARANTINE_CPP = ROOT / "src/PhantomCore/Core/Engine/QuarantineManager.cpp"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def read(path: Path) -> str:
    return strip_comments(path.read_text(encoding="utf-8", errors="surrogateescape"))


def function_body(src: str, signature: str) -> str:
    start = src.find(signature)
    if start < 0:
        return ""
    end = src.find("\n}", start)
    return src[start:end] if end > start else ""


def security_info_calls(src: str):
    """Every GetProcessSecurityInfo( call with its full argument list (definitions excluded)."""
    calls = []
    for m in re.finditer(r"GetProcessSecurityInfo\(", src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            depth += {"(": 1, ")": -1}.get(src[i], 0)
            i += 1
        text = src[m.start():i]
        if "ProcessSecurityInfo&" not in text:
            calls.append(" ".join(text.split()))
    return calls


class SecurityInfoScopeCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hpp = read(UTILS_HPP)
        cls.cpp = read(UTILS_CPP)

    def test_the_default_scope_is_local_only(self):
        self.assertRegex(
            self.hpp,
            r"bool GetProcessSecurityInfo\(ProcessId pid, ProcessSecurityInfo& info, "
            r"Error\* err = nullptr,\s*SecurityInfoScope scope = SecurityInfoScope::LocalOnly\)",
            "GetProcessSecurityInfo no longer defaults to LocalOnly, so callers inherit an "
            "account-name lookup that can reach a domain controller")

    def test_every_name_consumer_requests_full_itself(self):
        consumers = {
            "GetProcessOwner(ProcessId pid, Error* err) noexcept {": "returns sec.userName",
            "HasProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, Error* err) noexcept {":
                "compares privilege display names",
            "GetProcessPrivileges(ProcessId pid, std::vector<std::wstring>& privileges, Error* err) noexcept {":
                "returns privilege display names",
            "GetProcessInfo(ProcessId pid, ProcessInfo& info, Error* err) noexcept {":
                "returns an aggregate that includes userName",
            "GetProcessInfoWMI(ProcessId pid, ProcessInfo& info, Error* err) noexcept {":
                "returns an aggregate that includes userName",
        }
        for signature, why in consumers.items():
            body = function_body(self.cpp, signature)
            self.assertTrue(body, "function not found: %s" % signature)
            calls = security_info_calls(body)
            self.assertTrue(calls, "%s no longer queries security info" % signature)
            for call in calls:
                self.assertIn("SecurityInfoScope::Full", call,
                              "%s %s but its query inherits the LocalOnly default: %s"
                              % (signature.split("(")[0], why, call))

    def test_the_user_filter_requests_full(self):
        m = re.search(r"if \(options\.userFilter && !options\.userFilter->empty\(\)\) \{(.*?)\n\s*\}\s*\n",
                      self.cpp, re.S)
        self.assertIsNotNone(m, "the EnumerateProcesses userFilter block was not found")
        calls = security_info_calls(m.group(1))
        self.assertEqual(len(calls), 1, "expected one security query in the userFilter block")
        self.assertIn("SecurityInfoScope::Full", calls[0],
                      "userFilter compares sec.userName but its query inherits LocalOnly, so the "
                      "filter would match nothing")

    def test_token_fact_readers_do_not_request_the_name(self):
        for path in (BANKING_CPP, QUARANTINE_CPP):
            calls = security_info_calls(read(path))
            self.assertEqual(len(calls), 1, "%s: expected exactly one security query" % path.name)
            self.assertIn("SecurityInfoScope::LocalOnly", calls[0],
                          "%s reads only local token facts but does not restrict its query: %s"
                          % (path.name, calls[0]))


if __name__ == "__main__":
    unittest.main()
