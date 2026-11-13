"""Host-safe contract: the scan engine trusts its own verified signature safely.

The product must not convict its own first-party-signed installer/uninstaller on
a heuristic score. The field defect (task 322): ShadowStrikePhantom-Home-Setup.exe
scored 68 at Stage 5, the engine returned Suspicious, the driver cached
Verdict_Malicious, and PreAcquireSection enforced it on execute-map, so the bundle
could not run.

EvaluatePublisherTrust suppresses the heuristic SCORE for a first-party signer,
but the suppression must be UNFORGEABLE. It is reached only after the signature
and chain have verified (info.isValid) and after the stolen-certificate gate, and
the publisher identity is hard-coded rather than removable by policy.

This test does not run the scanner. It binds the source so a future edit cannot
(a) drop the first-party suppression, (b) move it ahead of the validity or
stolen-certificate gates where an unsigned or stolen-signed file could reach it,
or (c) make the identity policy-driven. The behavioural half - that a real
first-party signature verifies - belongs on a machine with such a file; this is
the wiring half, which is machine-independent.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_ENGINE_CPP = ROOT / "src" / "PhantomCore" / "Core" / "Engine" / "ScanEngine.cpp"


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


class ScanEngineFirstPartyTrustContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.src = _strip_c_comments(SCAN_ENGINE_CPP.read_text(encoding="utf-8"))

    def _predicate(self) -> str:
        # IsFirstPartySigner is defined immediately before EvaluatePublisherTrust.
        start = self.src.index("IsFirstPartySigner(const Security::SignerInfo")
        end = self.src.index("TrustSuppression EvaluatePublisherTrust", start)
        return self.src[start:end]

    def _evaluate(self) -> str:
        # Anchor on the return type so the slice starts at the definition, not an
        # earlier call site. LogTrustNotEstablished is the next member.
        start = self.src.index("TrustSuppression EvaluatePublisherTrust")
        end = self.src.index("LogTrustNotEstablished", start)
        return self.src[start:end]

    def test_first_party_identity_is_hard_coded_not_policy(self) -> None:
        pred = self._predicate()
        self.assertIn(
            "ShadowStrike-Labs Dev Code Signing", pred,
            "the first-party signer common name must be compiled in")
        self.assertIn(
            "static constexpr", pred,
            "the first-party CN list must be a compiled-in constant so policy "
            "cannot remove the product's trust in its own signature")
        for policy_token in ("m_whitelistStore", "IsPublisherWhitelisted"):
            self.assertNotIn(
                policy_token, pred,
                "first-party identity must not be sourced from the policy "
                "whitelist store (%s)" % policy_token)

    def test_suppression_is_gated_by_validity_then_stolen_cert_then_first_party(self) -> None:
        ev = self._evaluate()
        i_valid = ev.find("!info.isValid")
        i_stolen = ev.find("CheckStolenCertificate")
        i_first = ev.find("IsFirstPartySigner(info.signer)")
        self.assertGreaterEqual(i_valid, 0, "the fail-closed !info.isValid guard is missing")
        self.assertGreaterEqual(i_stolen, 0, "the stolen-certificate gate is missing")
        self.assertGreaterEqual(
            i_first, 0, "EvaluatePublisherTrust no longer consults IsFirstPartySigner")
        self.assertLess(
            i_valid, i_stolen,
            "the stolen-certificate gate must come after the validity guard")
        self.assertLess(
            i_stolen, i_first,
            "the first-party check must come AFTER the stolen-certificate gate, or "
            "a stolen first-party signature would still be trusted")
        self.assertLess(
            i_valid, i_first,
            "the first-party check must come AFTER the signature/chain validity "
            "guard, or an unsigned file could be trusted as first-party")

    def test_first_party_branch_records_its_own_basis(self) -> None:
        ev = self._evaluate()
        self.assertIn(
            "first-party (own publisher)", ev,
            "the first-party branch must record its basis so a field run can tell "
            "this suppression apart from Microsoft / whitelist suppression")


if __name__ == "__main__":
    unittest.main(verbosity=2)
