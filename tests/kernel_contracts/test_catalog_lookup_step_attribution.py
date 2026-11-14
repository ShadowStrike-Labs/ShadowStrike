#!/usr/bin/env python3
"""Contract: a failed catalog lookup names the call that failed (task 373).

The 1.0.133 VM run logged 158 'Catalog lookup failed (Win32 N)' lines: 11 with 3
(ERROR_PATH_NOT_FOUND, NGEN temp images gone by hash time) and 147 with 1006
(ERROR_FILE_INVALID, Edge installer copies and WindowsApps DLLs). Opening the file,
acquiring the catalog context, hashing it, enumerating catalogs and reading the
catalog info all write the same out-parameter, so the code could not say which of
them refused the file. Each failure branch now records its step and the log line
names it.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DSV_CPP = ROOT / "src/PhantomCore/SelfProtection/DigitalSignatureValidator.cpp"


def function_body(src, signature):
    start = src.find(signature)
    if start < 0:
        return ""
    brace = src.find("{", src.find(") noexcept", start))
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace:i + 1]
    return ""


class CatalogLookupStepAttributionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = DSV_CPP.read_text(encoding="utf-8", errors="surrogateescape")
        cls.hash_fn = function_body(cls.src, "bool computeCatalogMembershipHash(")
        cls.resolve_fn = function_body(cls.src, "CatalogLookup resolveCatalogForFile(")

    def test_both_helpers_were_found(self):
        self.assertTrue(self.hash_fn, "computeCatalogMembershipHash body not found")
        self.assertTrue(self.resolve_fn, "resolveCatalogForFile body not found")

    def test_every_hash_failure_records_its_step(self):
        for step in ("OpenFile", "AcquireContext", "CalcHash"):
            self.assertIn(f"failedAt(CatalogLookupStep::{step})", self.hash_fn,
                          f"the {step} failure in computeCatalogMembershipHash records no step")
        self.assertEqual(self.hash_fn.count("return false;"),
                         self.hash_fn.count("failedAt(CatalogLookupStep::"),
                         "a hash failure branch returns without recording its step")

    def test_every_enumeration_failure_records_its_step(self):
        for step in ("AcquireContext", "CatalogInfo", "EnumCatalog"):
            self.assertIn(f"failedAt(CatalogLookupStep::{step})", self.resolve_fn,
                          f"the {step} failure in resolveCatalogForFile records no step")
        self.assertIn("computeCatalogMembershipHash(filePath, outHash, outError, outStep)",
                      self.resolve_fn, "the hash step is not forwarded to the caller")
        # A miss that classifies as NotMember is an answer, not a failure.
        self.assertRegex(
            self.resolve_fn,
            r"outcome = ClassifyCatalogEnumMiss\(outError\);\s*"
            r"if \(outcome == CatalogLookup::Failed\) \{\s*"
            r"failedAt\(CatalogLookupStep::EnumCatalog\);",
            "an enumeration miss must record a step only when it is a failure")

    def test_the_failure_line_names_the_step(self):
        # assertTrue, not assertIn: a failing assertIn against this ~200 KB source
        # prints all of it.
        self.assertTrue(
            'L"Catalog lookup failed at %hs (Win32 %lu), no verdict: %ls"' in self.src,
            "the catalog failure line does not name the failing step")
        self.assertTrue(
            re.search(r"CatalogLookupStepName\(failedStep\),\s*"
                      r"static_cast<unsigned long>\(lookupError\)", self.src),
            "the step name is not passed in the position the format expects")


if __name__ == "__main__":
    unittest.main()
