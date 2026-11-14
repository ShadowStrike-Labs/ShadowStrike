"""Host-safe contract: self-protection permits the product's own uninstall.

The kernel self-protection path ShadowStrikeShouldBlockFileAccess denies
writes/deletes of protected product files by any process that is not a
registered protected process. That is correct against tampering, but it also
denied the product's OWN uninstall: msiexec's RemoveFiles deletes the installed
files and every delete was blocked, so the MSI failed 0x80070005 (task 322).

The fix exempts a Windows Code Integrity signed caller operating inside the
product's own registered install tree - the same gate task 384 applies on the
mass-operation path (PsipIsInstallerTransactionOperation), reached here through
ShadowStrikeIsInstallerServicingOwnTree. The exemption must stay PRECISE: both
the install-tree location and the Windows signer are required, it declines above
PASSIVE_LEVEL, and it only ever allows - so self-protection stays in force for
every unsigned / third-party caller and every path outside the product's folder.

This test does not load the driver. It binds the source so a future edit cannot
drop the consult, move it ahead of the protected-path gate, or widen the signer
allow-set to a non-Windows level.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELF_PROTECT_C = ROOT / "PhantomSensor" / "PhantomSensor" / "SelfProtection" / "SelfProtect.c"
PRE_SET_INFO_C = ROOT / "PhantomSensor" / "PhantomSensor" / "Callbacks" / "FileSystem" / "PreSetInfo.c"

PREDICATE = "ShadowStrikeIsInstallerServicingOwnTree"


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


def _slice(source: str, start_anchor: str, end_anchor: str) -> str:
    start = source.index(start_anchor)
    end = source.index(end_anchor, start + len(start_anchor))
    return source[start:end]


class SelfProtectInstallerExemptionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sp = _strip_c_comments(SELF_PROTECT_C.read_text(encoding="utf-8"))
        cls.psi = _strip_c_comments(PRE_SET_INFO_C.read_text(encoding="utf-8"))

    def _block_fn(self) -> str:
        return _slice(self.sp, "ShadowStrikeShouldBlockFileAccess",
                      "ShadowStrikeShouldBlockRegistryAccess")

    def _predicate_fn(self) -> str:
        # In PreSetInfo.c the predicate name appears only at its definition (no
        # forward declaration, no self-call), so the first hit is the body.
        start = self.psi.index(PREDICATE + "(")
        end = self.psi.index("ShadowStrikeRegisterProductInstallTree", start)
        return self.psi[start:end]

    def test_block_path_consults_the_exemption_after_the_protected_path_gate(self) -> None:
        fn = self._block_fn()
        i_prot = fn.find("ShadowStrikeIsPathProtected")
        i_exempt = fn.find(PREDICATE + "(FilePath, RequestorPid)")
        i_block = fn.find("FileDeleteBlocks")
        self.assertGreaterEqual(i_prot, 0, "the protected-path gate is missing")
        self.assertGreaterEqual(
            i_exempt, 0,
            "ShadowStrikeShouldBlockFileAccess no longer consults the installer "
            "exemption; the product's own uninstall is blocked again (task 322)")
        self.assertGreaterEqual(i_block, 0, "the delete-block site is missing")
        self.assertLess(
            i_prot, i_exempt,
            "the exemption must come AFTER the protected-path gate, so it is only "
            "ever consulted for genuinely protected paths")
        self.assertLess(
            i_exempt, i_block,
            "the exemption must come BEFORE the block, or the delete is denied "
            "before the uninstall can be allowed")

    def test_exemption_requires_install_tree_and_windows_signer(self) -> None:
        fn = self._predicate_fn()
        self.assertIn(
            "PsipPathIsUnderProductInstallTree", fn,
            "the exemption must require the path to be inside the product's own "
            "registered install tree (location half of the gate)")
        self.assertIn(
            "ShadowStrikeValidateProcessSignature", fn,
            "the exemption must require a verified signer (identity half)")

    def test_exemption_declines_above_passive_level(self) -> None:
        fn = self._predicate_fn()
        self.assertIn(
            "KeGetCurrentIrql() != PASSIVE_LEVEL", fn,
            "the exemption must decline above PASSIVE_LEVEL (the signature query "
            "cannot run higher), leaving self-protection in force - fail safe")

    def test_signer_allow_set_is_windows_only(self) -> None:
        fn = self._predicate_fn()
        for allowed in ("ShadowSignerWindows", "ShadowSignerWinTcb", "ShadowSignerWinSystem"):
            self.assertIn(
                allowed, fn,
                "the Windows-signer allow-set must include %s" % allowed)
        # Widening the allow-set to a third-party or unsigned level would let any
        # Authenticode-signed process tamper with the product inside its own dir.
        self.assertNotIn(
            "ShadowSignerAuthenticode", fn,
            "the exemption must NOT accept a third-party Authenticode signer; the "
            "gate is Windows Code Integrity only")

    def _install_tree_match(self) -> str:
        # The per-prefix matcher and the membership test that calls it. The
        # matcher name appears first at its definition (no forward declaration);
        # the slice runs to the next sibling, PsipPathHasVolumeRootConfigMsi.
        start = self.psi.index("PsipPathMatchesInstallTreePrefix")
        end = self.psi.index("PsipPathHasVolumeRootConfigMsi", start)
        return self.psi[start:end]

    def test_install_tree_match_covers_the_root_node(self) -> None:
        # The registered install-tree prefix ends in a backslash (a directory
        # prefix). A delete/rename of the install ROOT directory names it without
        # one, so a descendant-only match left the uninstaller unable to remove
        # the product's own root folder: the self-protect path blocked it with
        # ACCESS_DENIED and an empty orphan survived (task 322, VM-measured 42x
        # error 5 on ...\Phantom\). The membership test must match BOTH a
        # descendant and the exact root node.
        fn = self._install_tree_match()
        self.assertIn(
            "RtlPrefixUnicodeString", fn,
            "the descendant match (any file/subdirectory inside the tree) must "
            "remain")
        self.assertIn(
            "RtlEqualUnicodeString", fn,
            "the install-tree match must ALSO recognize the root directory node "
            "by exact equality; without it the self-protect path blocks the "
            "uninstaller's RemoveDirectory on the install root and leaves an "
            "empty orphan (task 322)")
        self.assertIn(
            "sizeof(WCHAR)", fn,
            "the root node is the registered prefix with its single trailing "
            "separator removed (PrefixLength - sizeof(WCHAR)); exact equality "
            "against that adds only the root, never a sibling path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
