"""Host-safe contract: the uninstall driver teardown unloads the minifilter.

PhantomSensor is a file-system minifilter. The installer brings it up with the
Filter Manager call FilterLoad (DriverInstaller.cpp, LoadDriver). The uninstall
teardown MUST take it down with the matching Filter Manager call FilterUnload.

The defect this guards (task 322): StopAndDeleteExistingService stopped the
minifilter with the legacy SCM ControlService(SERVICE_CONTROL_STOP), and ignored
that call's result. A file-system minifilter does not honour an SCM stop, so the
driver stayed loaded through the MSI RemoveFiles step. A loaded driver image
cannot be deleted, and the still-live driver's self-protection then denied the
product-file deletions, so the Burn bundle uninstall failed with 0x80070005.
A controlled VM experiment showed that unloading the filter ('fltmc unload
PhantomSensor', the same operation FilterUnload performs) lets the uninstall
complete.

This test does not load the driver. It binds the source so a future edit cannot
revert the teardown to an SCM-stop-only path, and keeps load and unload on the
symmetric Filter Manager calls.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVER_INSTALLER_CPP = (
    ROOT / "src" / "Products" / "Community" / "PhantomHome" / "Installer" /
    "DriverResume" / "DriverInstaller.cpp"
)


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


def _slice(source: str, start_anchor: str, end_anchor: str) -> str:
    start = source.index(start_anchor)
    end = source.index(end_anchor, start + len(start_anchor))
    return source[start:end]


class DriverUninstallTeardownContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.src = _strip_c_comments(
            DRIVER_INSTALLER_CPP.read_text(encoding="utf-8"))

    def _teardown(self) -> str:
        # The definition carries the SC_HANDLE parameter; the call site in
        # UninstallDriver passes (hScm), so this anchor finds the body, not the
        # call. CreateDriverService is the next function in the file.
        return _slice(
            self.src,
            "StopAndDeleteExistingService(SC_HANDLE",
            "CreateDriverService(SC_HANDLE",
        )

    def test_teardown_unloads_the_minifilter_via_filterunload(self) -> None:
        teardown = self._teardown()
        self.assertIn(
            "FilterUnload(kServiceName)", teardown,
            "the uninstall teardown must unload the minifilter with FilterUnload; "
            "an SCM stop does not take a minifilter down, the driver stays loaded, "
            "and the uninstall fails 0x80070005 deleting still-protected files "
            "(task 322)",
        )

    def test_filterunload_is_primary_and_scm_stop_is_only_a_fallback(self) -> None:
        teardown = self._teardown()
        unload_at = teardown.find("FilterUnload(kServiceName)")
        self.assertGreaterEqual(unload_at, 0, "FilterUnload call missing")
        scm_at = teardown.find("SERVICE_CONTROL_STOP")
        if scm_at >= 0:
            self.assertLess(
                unload_at, scm_at,
                "FilterUnload must be attempted before any SERVICE_CONTROL_STOP: "
                "the SCM stop is only the WDM / non-minifilter fallback, mirroring "
                "the FilterLoad -> StartServiceW fallback on the load side",
            )

    def test_load_and_unload_use_the_symmetric_filter_manager_calls(self) -> None:
        # The invariant is a pairing: FilterLoad on the way up, FilterUnload on the
        # way down. If the load side ever stops using FilterLoad this pairing has
        # moved and the teardown assumption has to be re-examined.
        load = _slice(self.src, "LoadDriver(SC_HANDLE", "SetInstallCompleteMarker(")
        self.assertIn(
            "FilterLoad(kServiceName)", load,
            "LoadDriver must bring the minifilter up with FilterLoad, the call "
            "FilterUnload pairs with",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
