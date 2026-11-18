"""Host-safe contract: the deferred-deep-scan remediation gate withholds the
destructive action on the product's OWN verified intact binary (task 385 f3).

Field symptom (1.0.128 / 1.0.133 VM runs): the deferred deep scan convicted
ShadowStrikePhantomService.exe via a YARA identification
(SIGNATURE_BASE_HKTL_Meterpreter_Inmemory, and on the full ruleset many DITEKSHEN
/ BINARYALERT / Mimikatz rules) and tried to quarantine the file and terminate
the service - 14 times in 22 minutes. The shipped binaries legitimately carry the
detection strings the shipped rules match, so a deep-scan tier self-matches them,
and encoding every such functional string does not scale.

MayRemediateDetectedFile early-returned "remediate" on any identification, before
the publisher-trust withhold that only inference-class detections reached. The fix
adds a verified-own-binary withhold in the identification branch, scoped by three
independent proofs so a replaced/tampered binary stays fully covered:
  (a) IsOwnInstalledBinary - the path is one of our install-tree binaries;
  (b) EvaluatePublisherTrust(...).firstParty - a VALID signature from our own
      code-signing identity (the single-source trust path that also verifies the
      chain and rejects a stolen-cert signer);
  (c) a TamperProtection baseline that does NOT contradict (a definitive
      Modified/Corrupted/Unauthorized mismatch means the file was replaced since
      install and is NOT exempt).

Detection is never weakened: it is already counted and is still logged; only the
destructive action is withheld. This test does not run the engine; it binds the
source so a future edit cannot drop the withhold, move it out of the
identification branch, loosen the three-proof helper, or widen the first-party
flag so any trusted vendor counts as the product itself.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RTP_C = ROOT / "src" / "PhantomCore" / "RealTime" / "RealTimeProtection.cpp"
RTP_H = ROOT / "src" / "PhantomCore" / "RealTime" / "RealTimeProtection.hpp"
SCANENGINE_C = ROOT / "src" / "PhantomCore" / "Core" / "Engine" / "ScanEngine.cpp"


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


def _slice(source: str, start_anchor: str, end_anchor: str) -> str:
    start = source.index(start_anchor)
    end = source.index(end_anchor, start + len(start_anchor))
    return source[start:end]


class OwnBinaryRemediationWithholdContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rtp = _strip_c_comments(RTP_C.read_text(encoding="utf-8"))
        cls.rtp_h = _strip_c_comments(RTP_H.read_text(encoding="utf-8"))
        cls.scan = _strip_c_comments(SCANENGINE_C.read_text(encoding="utf-8"))

    def _may_remediate(self) -> str:
        return _slice(self.rtp, "bool MayRemediateDetectedFile(",
                      "void HandleDeferredThreat(")

    def _verified_own(self) -> str:
        return _slice(self.rtp, "bool IsVerifiedOwnBinaryIntact(",
                      "bool MayRemediateDetectedFile(")

    def test_withhold_sits_inside_the_identification_branch(self) -> None:
        fn = self._may_remediate()
        i_ident = fn.find("DetectionIdentifiesRatherThanInfers")
        i_verify = fn.find("IsVerifiedOwnBinaryIntact(filePath)")
        i_count = fn.find("ownBinaryIdentificationWithheld")
        self.assertGreaterEqual(i_ident, 0, "the identification check vanished")
        self.assertGreaterEqual(
            i_verify, 0,
            "MayRemediateDetectedFile no longer consults IsVerifiedOwnBinaryIntact; "
            "an identification on our own binary quarantines and terminates the "
            "service again (task 385)")
        self.assertGreaterEqual(i_count, 0, "the withhold is not counted")
        self.assertLess(
            i_ident, i_verify,
            "the own-binary withhold must live INSIDE the identification branch - "
            "it is identifications, not inferences, that early-remediate our binary")
        self.assertLess(
            i_verify, i_count,
            "the counter must be incremented on the withhold, after the check")
        i_false = fn.find("return false", i_count)
        self.assertGreaterEqual(
            i_false, 0,
            "the withhold must return false (do not remediate) for a verified own "
            "binary, after counting the withhold")

    def test_helper_requires_all_three_proofs(self) -> None:
        fn = self._verified_own()
        self.assertIn(
            "IsOwnInstalledBinary", fn,
            "(a) the helper must require the path to be one of our own binaries")
        self.assertIn(
            "EvaluatePublisherTrust", fn,
            "(b) the helper must require a verified publisher-trust evaluation")
        self.assertIn(
            ".firstParty", fn,
            "(b) the helper must require the FIRST-PARTY flag specifically, not "
            "mere third-party vendor trust - only the product's own identity")
        self.assertIn(
            "IsFileProtected", fn,
            "(c) the helper must consult the tamper-protection baseline")
        for status in ("IntegrityStatus::Modified", "IntegrityStatus::Corrupted",
                       "IntegrityStatus::Unauthorized"):
            self.assertIn(
                status, fn,
                "(c) a definitive baseline mismatch (%s) must veto the exemption, "
                "so a replaced binary at our path still remediates" % status)
        self.assertIn(
            "WithholdOwnBinaryIdentificationRemediation", fn,
            "the helper must defer the composition to the pure, unit-tested policy")

    def test_pure_policy_ands_all_three_proofs(self) -> None:
        # The one line of policy. Any drift to an OR, or dropping a term, would let
        # a planted file withhold remediation.
        start = self.rtp_h.index("bool WithholdOwnBinaryIdentificationRemediation(")
        body = self.rtp_h[start:start + 600]
        self.assertIn(
            "isOwnInstalledBinary && firstPartyVerifiedSigner && !baselineContradicts",
            body,
            "the withhold must require own-path AND first-party AND not-contradicted; "
            "any weaker composition shelters a planted or tampered binary")

    def test_first_party_flag_is_set_only_on_a_verified_first_party_signer(self) -> None:
        # firstParty must be a narrow signal: set only in the IsFirstPartySigner
        # branch of the single trust evaluator, reached after the signature, chain
        # and stolen-cert gates. If it were set anywhere a vendor is merely trusted,
        # a third-party signed binary could pose as the product itself.
        i_fp_branch = self.scan.index("IsFirstPartySigner(info.signer)")
        after = self.scan[i_fp_branch:i_fp_branch + 400]
        self.assertIn(
            "decision.firstParty = true;", after,
            "firstParty must be set in the IsFirstPartySigner branch")
        self.assertEqual(
            self.scan.count("firstParty = true"), 1,
            "firstParty must be set in exactly one place - the verified "
            "first-party branch - so nothing else can assert the product's own "
            "identity")


if __name__ == "__main__":
    unittest.main(verbosity=2)
