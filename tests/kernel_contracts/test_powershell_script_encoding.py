#!/usr/bin/env python3
"""Contract: every tracked PowerShell script decodes the same on every host (task 98).

Windows PowerShell 5.1 reads a script file that has no byte-order mark as the ANSI code
page, not as UTF-8. A BOM-less script holding UTF-8 em-dashes or box-drawing characters is
therefore decoded as CP1252 mojibake on a typical host: the deploy harness once emitted
'[13:29:59] Deployed a?' and lost the bundle hash from the same line. A corrupted or
truncated diagnostic line is how a real failure hides, so a script must behave identically
whatever the host's code page is.

Two encodings are host-independent under 5.1 and PowerShell 7 alike: pure ASCII, or UTF-8
with a BOM. Anything else is refused here, so the class cannot recur in a new script.
"""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UTF8_BOM = b"\xef\xbb\xbf"
SCRIPT_SUFFIXES = (".ps1", ".psm1", ".psd1")


def tracked_scripts():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--", "*.ps1", "*.psm1", "*.psd1"],
        check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p.endswith(SCRIPT_SUFFIXES)]


def first_non_ascii(data: bytes):
    for line_no, line in enumerate(data.split(b"\n"), start=1):
        for byte in line:
            if byte > 0x7F:
                return line_no
    return None


class PowerShellScriptEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scripts = tracked_scripts()

    def test_scripts_are_enumerated(self):
        # Non-vacuity: the check must actually see the harness scripts it protects.
        names = {Path(p).name for p in self.scripts}
        for required in ("Invoke-PhantomDeploy.ps1", "Sign-PhantomHome.ps1",
                         "Invoke-HostGate.ps1", "PhantomVm.psm1"):
            self.assertIn(required, names, "%s is not among the tracked scripts" % required)
        self.assertGreater(len(self.scripts), 20)

    def test_every_script_is_ascii_or_utf8_with_bom(self):
        offenders = []
        for rel in self.scripts:
            data = (ROOT / rel).read_bytes()
            if data.startswith(UTF8_BOM):
                continue
            line = first_non_ascii(data)
            if line is not None:
                offenders.append("%s:%d" % (rel, line))
        self.assertEqual(
            offenders, [],
            "BOM-less script holds non-ASCII bytes, so Windows PowerShell 5.1 decodes it as "
            "the ANSI code page and mangles it: %s. Replace the characters with ASCII or save "
            "the file as UTF-8 with BOM." % ", ".join(offenders))


if __name__ == "__main__":
    unittest.main()
