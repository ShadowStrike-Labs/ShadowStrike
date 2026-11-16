#!/usr/bin/env python3
"""Contract: the YARA rule loader verifies the database checksum before trusting libyara (task 389).

The service crash-looped on startup with an access violation inside libyara's
yr_rules_load_stream after its own log line 'LoadRulesInternal: Starting rule loading from
mapped database'. libyara's deserializer dereferences the offsets it parses without
revalidating them, so a full-size but internally torn database (a working copy left
half-written by a power loss) crashes it, taking the service down in an SCM restart loop.
ValidateHeader checks the header and section bounds but not the contents.

The fix verifies the whole-database SHA-256 the builder stamped (SignatureFormat
VerifyDatabaseChecksum) in LoadRulesInternal BEFORE calling yr_rules_load_stream, refusing
a corrupt database. These assertions pin that ordering so a later edit cannot drop the
guard or move it after the libyara call, and pin the verifier's safety properties so it
cannot be made to accept anything.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
YARA = ROOT / "src/PhantomCore/SignatureStore/YaraRuleStore.cpp"
FMT = ROOT / "src/PhantomCore/SignatureStore/SignatureFormat.cpp"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


class YaraLoadVerifiesChecksumContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.yara = strip_comments(YARA.read_text(encoding="utf-8", errors="surrogateescape"))
        cls.fmt = strip_comments(FMT.read_text(encoding="utf-8", errors="surrogateescape"))

    def _load_rules_body(self) -> str:
        start = self.yara.find("StoreError YaraRuleStore::LoadRulesInternal()")
        self.assertGreaterEqual(start, 0, "LoadRulesInternal not found")
        nxt = self.yara.find("\nStoreError YaraRuleStore::", start + 10)
        end = nxt if nxt > start else len(self.yara)
        return self.yara[start:end]

    def test_the_verify_is_called_before_libyara_loads(self):
        body = self._load_rules_body()
        verify_at = body.find("Format::VerifyDatabaseChecksum(")
        load_at = body.find("yr_rules_load_stream(")
        self.assertGreaterEqual(verify_at, 0,
                                "LoadRulesInternal no longer verifies the database checksum")
        self.assertGreaterEqual(load_at, 0, "yr_rules_load_stream call not found")
        self.assertLess(verify_at, load_at,
                        "the checksum verification must run BEFORE yr_rules_load_stream, "
                        "or a corrupt database still reaches libyara")

    def test_a_failed_verify_refuses_to_load(self):
        body = self._load_rules_body()
        # The verify sits in a negated guard that returns InvalidFormat on failure.
        self.assertRegex(
            body,
            r"!Format::VerifyDatabaseChecksum\([^;]*\)\s*\)\s*\{[^}]*return\s+StoreError\{\s*"
            r"SignatureStoreError::InvalidFormat",
            "a failed checksum verification must return InvalidFormat without loading rules")

    def test_verifier_compares_against_the_stored_checksum(self):
        # Non-vacuity: the verifier must actually hash and compare, not just return true.
        self.assertIn("bool VerifyDatabaseChecksum(", self.fmt)
        m = re.search(r"bool VerifyDatabaseChecksum\(.*?\n\}", self.fmt, re.S)
        self.assertIsNotNone(m, "VerifyDatabaseChecksum body not found")
        func = m.group(0)
        self.assertIn("sha256Checksum", func, "the verifier never reads the stored checksum")
        self.assertIn("Hasher", func, "the verifier never computes a hash")
        self.assertIn("offsetof(SignatureDatabaseHeader, sha256Checksum)", func,
                      "the verifier must zero the checksum field at its real offset to match "
                      "the builder's domain")

    def test_verifier_skips_only_an_all_zero_checksum(self):
        m = re.search(r"bool VerifyDatabaseChecksum\(.*?\n\}", self.fmt, re.S)
        func = m.group(0)
        # An unfinalized (all-zero) database is allowed through; everything else is compared.
        self.assertIn("storedAllZero", func,
                      "the verifier must treat an all-zero checksum as unfinalized, like the "
                      "whitelist and threat-intel stores")


if __name__ == "__main__":
    unittest.main()
