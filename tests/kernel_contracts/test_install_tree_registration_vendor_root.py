"""Host-safe contract: the product registers its VENDOR folder as the install tree.

SyncProductInstallTreeToKernel (SelfDefense.cpp) tells the kernel which directory
is the product's own install tree. The kernel's data-destruction / ransomware gate
then exempts a Windows-signed uninstaller operating inside that tree, so msiexec
can remove the product's files and directories without being scored as a wiper.

The service image lives in ...\ShadowStrike\Phantom\, but the MSI creates and
removes BOTH that Phantom folder AND the vendor folder above it
(ShadowStrikeFolder = ...\ShadowStrike). Registering only ...\Phantom left the
vendor folder outside the exemption: once the Phantom directory itself became
removable (the kernel root-node match, task 322), the gate denied msiexec's
RemoveFolder on C:\Program Files\ShadowStrike\ with error 5 and the empty vendor
folder was orphaned after uninstall (VM-measured, 1.0.132).

The fix resolves the install root two levels up from the service image - the
vendor folder - with a shallow-path guard so the prefix can never degenerate to a
drive or a single top-level folder. This test does not run the service; it binds
the source so a future edit cannot quietly drop back to the Phantom subfolder or
remove the guard.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELF_DEFENSE = ROOT / "src" / "PhantomCore" / "SelfProtection" / "SelfDefense.cpp"


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


class InstallTreeVendorRootContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        text = SELF_DEFENSE.read_text(encoding="utf-8")
        code = _strip_c_comments(text)
        start = code.index("SelfDefenseImpl::SyncProductInstallTreeToKernel")
        end = code.index("SelfDefenseImpl::OnKernelSelfProtectEventInternal", start)
        cls.fn = code[start:end]

    def test_resolves_the_vendor_folder_two_levels_up(self) -> None:
        # The service image path is stripped TWICE: once to the exe directory
        # (...\Phantom), then again to the vendor folder (...\ShadowStrike). A
        # single strip would register the Phantom subfolder and leave the vendor
        # folder undeletable by the signed uninstaller (task 322).
        self.assertIn(
            "exeDir", self.fn,
            "the resolver must name the intermediate exe directory before taking "
            "its parent (the vendor folder)")
        self.assertGreaterEqual(
            self.fn.count("find_last_of"), 2,
            "the install root must be resolved TWO levels up from the service "
            "image (two find_last_of strips): the vendor folder, not the Phantom "
            "subfolder the service sits in (task 322)")
        self.assertIn(
            "exeDir.substr(0, slash2)", self.fn,
            "installDir must be the exe directory's parent (vendor folder), taken "
            "from the second separator")

    def test_has_a_shallow_path_guard(self) -> None:
        # The registered prefix ends in a backslash and prefix-matches everything
        # beneath it, so it must never be a drive root or a single top-level folder
        # (C:\ or C:\Program Files). The guard requires a separator below the drive.
        self.assertIn(
            r"installDir.find(L'\\', 3)", self.fn,
            "the shallow-path guard must reject a root shallower than X:\\dir\\vendor "
            "so a broken layout cannot register a namespace root as the tree")


if __name__ == "__main__":
    unittest.main(verbosity=2)
