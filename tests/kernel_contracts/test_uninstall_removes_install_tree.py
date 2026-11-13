"""Host-safe contract: uninstall removes the whole install-root tree.

MSI RemoveFiles deletes the files this package ships, but the service creates
runtime subdirectories under the install folder (Backup, Backups, Update\\...)
that are not in the MSI directory table. MSI cannot prune a directory it does
not own, so a single non-MSI subfolder keeps the empty Phantom and ShadowStrike
folders behind after an otherwise clean uninstall (VM-confirmed, task 322).

The fix records the install root in a registry value at install and uses
util:RemoveFolderEx to delete that whole tree on uninstall. This binds the WiX
authoring so the removal cannot be dropped: the component, its RemoveFolderEx,
the property/search that feeds it, and the Feature reference that actually
installs the component must all stay present.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS_WXS = ROOT / "packaging" / "installer" / "Components.wxs"
PRODUCT_WXS = ROOT / "packaging" / "installer" / "Product.wxs"

PROP = "REMOVESSINSTALLROOT"


def _strip_xml_comments(source: str) -> str:
    return re.sub(r"<!--.*?-->", "", source, flags=re.DOTALL)


class UninstallRemovesInstallTreeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.comp = _strip_xml_comments(COMPONENTS_WXS.read_text(encoding="utf-8"))
        cls.prod = _strip_xml_comments(PRODUCT_WXS.read_text(encoding="utf-8"))

    def _component(self) -> str:
        start = self.comp.index('Id="CmpRemoveInstallRoot"')
        end = self.comp.index("</Component>", start)
        return self.comp[start:end]

    def test_removal_component_uses_removefolderex_on_uninstall(self) -> None:
        comp = self._component()
        self.assertIn(
            "util:RemoveFolderEx", comp,
            "the install-root removal must use util:RemoveFolderEx (the subdirs are "
            "runtime-created, so a plain RemoveFolder cannot target them)")
        self.assertIn(
            'On="uninstall"', comp,
            "RemoveFolderEx must fire On=uninstall only - never on repair/upgrade")
        self.assertIn(
            'Property="%s"' % PROP, comp,
            "RemoveFolderEx must read the tree path from the %s property" % PROP)

    def test_removal_component_records_the_install_root(self) -> None:
        comp = self._component()
        self.assertIn('Name="InstallRoot"', comp,
                      "the component must record the install root for the search")
        self.assertIn('Value="[ShadowStrikeFolder]"', comp,
                      "the recorded path must be the install root C:\\Program Files\\"
                      "ShadowStrike, so the whole product tree is removed")

    def test_declared_install_folders_are_removed(self) -> None:
        # RemoveFolderEx clears the runtime subtree but not the two empty declared
        # folders themselves; those need explicit RemoveFolder, processed in the
        # RemoveFolders action after files are gone.
        comp = self._component()
        self.assertRegex(
            comp,
            r'<RemoveFolder\b[^>]*Directory="INSTALLFOLDER"[^>]*On="uninstall"',
            "the empty Phantom (INSTALLFOLDER) must be removed on uninstall")
        self.assertRegex(
            comp,
            r'<RemoveFolder\b[^>]*Directory="ShadowStrikeFolder"[^>]*On="uninstall"',
            "the empty parent ShadowStrike folder must be removed on uninstall")

    def test_property_search_reads_the_recorded_root(self) -> None:
        self.assertRegex(
            self.prod,
            r'<Property\s+Id="%s"' % PROP,
            "Product.wxs must declare the %s property" % PROP)
        start = self.prod.index('Id="%s"' % PROP)
        end = self.prod.index("</Property>", start)
        prop = self.prod[start:end]
        self.assertIn('Name="InstallRoot"', prop,
                      "the property must be populated by a RegistrySearch of InstallRoot")

    def test_removal_component_is_actually_installed(self) -> None:
        # A component that is never referenced by a Feature is authored but never
        # installed - and therefore never uninstalled, so the removal would silently
        # not happen.
        self.assertIn(
            '<ComponentRef Id="CmpRemoveInstallRoot"/>', self.prod,
            "CmpRemoveInstallRoot must be referenced by a Feature or it is never "
            "installed, and its uninstall-time removal never runs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
