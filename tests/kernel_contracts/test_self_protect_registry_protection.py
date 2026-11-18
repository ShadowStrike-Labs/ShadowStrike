"""Host-safe contract: kernel self-protection of the product's own registry hive.

Task 394 (split from 360). The registry self-protect gate
ShadowStrikeShouldBlockRegistryAccess was wired (RegistryCallback.c) and enabled
(SelfProtectionEnabled defaults TRUE) but inert: its matcher
ShadowStrikeIsRegistryKeyProtected reads g_ProtectedRegKeys, which had no
producer (ShadowStrikeAddProtectedRegistryKey had zero callers), so it returned
FALSE for every key. The comments claiming the kernel blocks writes to protected
keys were false.

The fix seeds g_ProtectedRegKeys at init with the product's own SOFTWARE hive
(SHADOWSTRIKE_REG_OUR_SOFTWARE = \\REGISTRY\\MACHINE\\SOFTWARE\\ShadowStrike),
whose native path is machine-independent, so no user-mode native-path conversion
or connect-time window is needed. Activating protection would otherwise re-block
the product's OWN uninstall: msiexec removes SOFTWARE\\ShadowStrike and every
delete would be denied (the registry analogue of task 322). So the gate also
gains a Windows-signer servicing exemption, SspIsWindowsSignedServicingCaller,
the registry mirror of the file gate's ShadowStrikeIsInstallerServicingOwnTree.

The exemption must stay PRECISE: it is consulted only AFTER the protected-key
gate (so it is reached only for the product's own keys), only BEFORE the block
(so the delete can be allowed), it declines above PASSIVE_LEVEL, and its signer
allow-set is Windows Code Integrity only. The block itself must stay intact, so a
non-signed caller deleting or rewriting the product's keys is still denied.

The stale driver-service key (SHADOWSTRIKE_REG_OUR_SERVICE names ShadowStrikeFlt,
not the installed PhantomSensor, and carries the control-set-symlink problem) is
deliberately NOT seeded here; that protection is tracked separately.

This test does not load the driver. It binds the source so a future edit cannot
drop the seed, drop or reorder the exemption, widen the signer allow-set, or
neuter the block.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELF_PROTECT_C = ROOT / "PhantomSensor" / "PhantomSensor" / "SelfProtection" / "SelfProtect.c"
REGISTRY_CALLBACK_H = ROOT / "PhantomSensor" / "PhantomSensor" / "Callbacks" / "Registry" / "RegistryCallback.h"

SEED_CALL = "ShadowStrikeAddProtectedRegistryKey"
OUR_SOFTWARE = "SHADOWSTRIKE_REG_OUR_SOFTWARE"
OUR_SERVICE = "SHADOWSTRIKE_REG_OUR_SERVICE"
EXEMPTION = "SspIsWindowsSignedServicingCaller"


def _strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


def _slice(source: str, start_anchor: str, end_anchor: str) -> str:
    start = source.index(start_anchor)
    end = source.index(end_anchor, start + len(start_anchor))
    return source[start:end]


class SelfProtectRegistryProtectionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sp = _strip_c_comments(SELF_PROTECT_C.read_text(encoding="utf-8"))
        cls.reg_h_raw = REGISTRY_CALLBACK_H.read_text(encoding="utf-8")

    def _init_fn(self) -> str:
        return _slice(self.sp, "ShadowStrikeInitializeSelfProtection(",
                      "ShadowStrikeShutdownSelfProtection")

    def _gate_fn(self) -> str:
        return _slice(self.sp, "ShadowStrikeShouldBlockRegistryAccess(",
                      "ShadowStrikeGetSelfProtectStats")

    def _exemption_fn(self) -> str:
        # The helper is defined (first hit) just before the gate; the slice to the
        # gate's name captures only the helper body.
        return _slice(self.sp, EXEMPTION + "(", "ShadowStrikeShouldBlockRegistryAccess")

    # -- the seed -----------------------------------------------------------

    def test_init_seeds_the_product_software_hive(self) -> None:
        fn = self._init_fn()
        i_mark = fn.find("g_SelfProtectInitialized, 1")
        i_seed = fn.find(SEED_CALL + "(")
        self.assertGreaterEqual(
            i_seed, 0,
            "ShadowStrikeInitializeSelfProtection no longer seeds a built-in "
            "protected registry key, so the registry self-protect gate is inert "
            "again (g_ProtectedRegKeys has no other producer) - task 394")
        self.assertIn(
            OUR_SOFTWARE, fn,
            "the seed must register the product's own SOFTWARE hive constant "
            "(%s), not a hand-written path" % OUR_SOFTWARE)
        self.assertGreaterEqual(i_mark, 0, "the initialized-publish is missing")
        self.assertLess(
            i_mark, i_seed,
            "the seed must run AFTER g_SelfProtectInitialized is set, because "
            "ShadowStrikeAddProtectedRegistryKey returns STATUS_DEVICE_NOT_READY "
            "until then")

    def test_init_does_not_seed_the_stale_service_key(self) -> None:
        # SHADOWSTRIKE_REG_OUR_SERVICE names ShadowStrikeFlt (the installed driver
        # service is PhantomSensor) and uses the CurrentControlSet form the
        # callback never reports. Seeding it would be inert at best; its correct
        # protection is a separate, control-set-aware change.
        self.assertNotIn(
            OUR_SERVICE, self._init_fn(),
            "the stale driver-service key must NOT be seeded here; its name and "
            "control-set form are wrong and it needs a dedicated fix")

    def test_software_constant_is_the_software_hive_not_a_service_key(self) -> None:
        m = re.search(
            OUR_SOFTWARE + r'\s*\\\s*\n\s*L"([^"]+)"', self.reg_h_raw)
        self.assertIsNotNone(
            m, "could not resolve %s to a native path literal" % OUR_SOFTWARE)
        value = m.group(1)
        self.assertIn(
            r"\\REGISTRY\\MACHINE\\SOFTWARE\\ShadowStrike", value,
            "the seeded constant must be the product's SOFTWARE hive; a drift "
            "here would protect the wrong key")
        self.assertNotIn(
            "Services", value,
            "the SOFTWARE constant must not point at a Services key")
        self.assertNotIn(
            "ControlSet", value,
            "the SOFTWARE hive has no control-set component")

    # -- the exemption, ordered and precise ---------------------------------

    def test_gate_consults_exemption_after_the_key_gate_and_before_the_block(self) -> None:
        fn = self._gate_fn()
        i_keygate = fn.find("ShadowStrikeIsRegistryKeyProtected")
        i_exempt = fn.find(EXEMPTION + "(RequestorPid)")
        i_block = fn.find("RegistryBlocks")
        self.assertGreaterEqual(i_keygate, 0, "the protected-key gate is missing")
        self.assertGreaterEqual(
            i_exempt, 0,
            "ShadowStrikeShouldBlockRegistryAccess no longer consults the "
            "servicing exemption; the product's own uninstall deleting its keys "
            "is blocked (the registry analogue of task 322)")
        self.assertGreaterEqual(i_block, 0, "the registry block site is missing")
        self.assertLess(
            i_keygate, i_exempt,
            "the exemption must come AFTER the protected-key gate, so it is only "
            "ever consulted for the product's own protected keys")
        self.assertLess(
            i_exempt, i_block,
            "the exemption must come BEFORE the block, or the change is denied "
            "before the uninstall can be allowed")

    def test_exemption_declines_above_passive_level(self) -> None:
        self.assertIn(
            "KeGetCurrentIrql() != PASSIVE_LEVEL", self._exemption_fn(),
            "the exemption must decline above PASSIVE_LEVEL (the signature query "
            "cannot run higher), leaving self-protection in force - fail safe")

    def test_exemption_requires_a_verified_windows_signer(self) -> None:
        fn = self._exemption_fn()
        self.assertIn(
            "ShadowStrikeValidateProcessSignature", fn,
            "the exemption must require a verified signer")
        for allowed in ("ShadowSignerWindows", "ShadowSignerWinTcb", "ShadowSignerWinSystem"):
            self.assertIn(
                allowed, fn,
                "the Windows-signer allow-set must include %s" % allowed)
        self.assertNotIn(
            "ShadowSignerAuthenticode", fn,
            "the exemption must NOT accept a third-party Authenticode signer; a "
            "Windows Code Integrity signer only may service the product's keys")

    # -- the block must stay intact (detection integrity) -------------------

    def test_block_still_denies_the_dangerous_operations(self) -> None:
        fn = self._gate_fn()
        for op in ("RegNtPreDeleteKey", "RegNtPreSetValueKey",
                   "RegNtPreDeleteValueKey", "RegNtPreRenameKey",
                   "RegNtPreSetKeySecurity"):
            self.assertIn(
                op, fn,
                "the gate must still block %s on a protected key; the exemption "
                "must not neuter the block" % op)
        self.assertIn(
            "return TRUE", fn,
            "the gate must still return TRUE (block) for an unexempt caller "
            "modifying a protected key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
