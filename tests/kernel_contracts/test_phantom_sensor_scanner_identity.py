"""Host-safe contracts for PhantomSensor scanner identity and port lifecycle.

These tests intentionally do not load the driver. They bind the production C
implementation to the invariants that prevent recursive scanner IPC and model
the multi-slot/generation lifecycle cases that previously broke scalar or
slot-only identity designs. Snapshot-only runtime validation remains under
vm_shrd/PhantomSensorScannerRecursion.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[2]
PRECREATE_PATH = ROOT / "PhantomSensor/PhantomSensor/Callbacks/FileSystem/PreCreate.c"
SCAN_BRIDGE_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Communication/ScanBridge.c"
SCAN_BRIDGE_H_PATH = ROOT / "PhantomSensor/PhantomSensor/Communication/ScanBridge.h"
COMM_PORT_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Communication/CommPort.c"
COMM_PORT_H_PATH = ROOT / "PhantomSensor/PhantomSensor/Communication/CommPort.h"
DRIVER_ENTRY_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Core/DriverEntry.c"
ERROR_CODES_H_PATH = ROOT / "PhantomSensor/Shared/ErrorCodes.h"
PROCESS_NOTIFY_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Callbacks/Process/ProcessNotify.c"
# The USER-MODE half of the kernel reply contract. It lives here, beside the
# driver half, deliberately: the invariant spans both sides of one exchange, and a
# reader who finds the kernel's "read the verdict only when one arrived" test needs
# to see the "actually send one" test next to it. It also cannot be expressed as a
# C++ unit test - answering a notification needs a loaded driver and a live filter
# port - which is the same reason the driver's own invariants are asserted here
# against source text rather than behaviour.
IPC_MANAGER_CPP_PATH = ROOT / "src/PhantomCore/Communication/IPCManager.cpp"
IPC_MANAGER_HPP_PATH = ROOT / "src/PhantomCore/Communication/IPCManager.hpp"

# THE SCM SERVICE-NAME CONTRACT spans the WiX installer, five C++ modules across three
# separate vcxproj targets, and operator documentation. No C++ test can read a .wxs file,
# and the tray cannot include SelfDefense.hpp to share one constant because that header
# pulls Utils/Logger.hpp, which needs C++23 while the tray project is stdcpp20 (task 96).
# So the only place this invariant can be stated at all is here, cross-language, the same
# way the process fan-out budget spans IPCManager.hpp and ProcessNotify.c.
#
# The installer is the AUTHORITY: whatever ServiceInstall/@Name says is what the SCM
# creates, and every code site is a consumer of that name via OpenServiceW or a
# ...\Services\<name> registry path. A site carrying a different name does not fail
# loudly - OpenServiceW returns ERROR_SERVICE_DOES_NOT_EXIST and the caller reports
# "not found", which is why ServiceManager watched a nonexistent service undetected.
INSTALLER_COMPONENTS_WXS_PATH = ROOT / "packaging/installer/Components.wxs"
SELF_DEFENSE_HPP_PATH = ROOT / "src/PhantomCore/SelfProtection/SelfDefense.hpp"
ANTIVIRUS_SERVICE_HPP_PATH = ROOT / "src/PhantomCore/Service/AntivirusService.hpp"
ANTIVIRUS_SERVICE_CPP_PATH = ROOT / "src/PhantomCore/Service/AntivirusService.cpp"
# The single place the shipped product version is written down. Both the service
# log (task 104) and Invoke-PhantomDeploy.ps1 read it, so the macro name is a
# contract between a C++ source and a PowerShell harness that no compiler checks.
VERSION_INFO_H_PATH = ROOT / "src/VersionInfo.h"
PROGRAM_UPDATER_CPP_PATH = ROOT / "src/PhantomCore/Update/ProgramUpdater.cpp"
ROLLBACK_MANAGER_CPP_PATH = ROOT / "src/PhantomCore/Update/RollbackManager.cpp"
INSTALL_PROBE_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/UI/Tray/InstallProbe.cpp"
)
SERVICE_MANAGER_HPP_PATH = ROOT / "src/PhantomCore/Core/System/ServiceManager.hpp"

# THE REPLY CARRIER spans user-mode C++ (which builds the reply) and driver C (which
# receives it into a fixed-size stack struct and never decrypts it). Neither side can
# see the other's constraint on its own: no C++ test can read the driver's reply-buffer
# declarations, and no C test can read FilterConnection's refusal. So the invariant
# "a kernel reply is bare, plaintext, and no larger than the kernel's own buffer" is
# only expressible here, the same way the process fan-out budget spans IPCManager.hpp
# and ProcessNotify.c.
FILTER_CONNECTION_CPP_PATH = ROOT / "src/PhantomCore/Communication/FilterConnection.cpp"
MESSAGE_PROTOCOL_H_PATH = ROOT / "PhantomSensor/Shared/MessageProtocol.h"
REGISTRY_MONITOR_CPP_PATH = ROOT / "src/PhantomCore/Core/Registry/RegistryMonitor.cpp"
PROCESS_UTILS_CPP_PATH = ROOT / "src/PhantomCore/Utils/ProcessUtils.cpp"
BEHAVIOR_ANALYZER_CPP_PATH = ROOT / "src/PhantomCore/Core/Engine/BehaviorAnalyzer.cpp"
REAL_TIME_PROTECTION_CPP_PATH = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp"
REAL_TIME_PROTECTION_HPP_PATH = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.hpp"
COMMUNICATION_HPP_PATH = ROOT / "src/PhantomCore/Communication/Communication.hpp"
MESSAGE_DISPATCHER_CPP_PATH = ROOT / "src/PhantomCore/Communication/MessageDispatcher.cpp"
FUZZER_VCXPROJ_PATH = ROOT / "Fuzzer/Fuzzer.vcxproj"
FILTER_REGISTRATION_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Core/FilterRegistration.c"
SHARED_DEFS_H_PATH = ROOT / "PhantomSensor/Shared/SharedDefs.h"
BACKUP_PROTECTOR_HPP_PATH = ROOT / "src/PhantomCore/RansomwareProtection/BackupProtector.hpp"
BACKUP_PROTECTOR_CPP_PATH = ROOT / "src/PhantomCore/RansomwareProtection/BackupProtector.cpp"
TAMPER_PROTECTION_HPP_PATH = ROOT / "src/PhantomCore/SelfProtection/TamperProtection.hpp"
TAMPER_PROTECTION_CPP_PATH = ROOT / "src/PhantomCore/SelfProtection/TamperProtection.cpp"

# The exploit tier, split into blockRequested / wasBlocked by 9971ef9e.
ROP_PROTECTION_CPP_PATH = ROOT / "src/PhantomCore/Exploits/ROPProtection.cpp"
STACK_PIVOT_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Exploits/StackPivotDetector.cpp"
JIT_SPRAY_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Exploits/JITSprayDetector.cpp"
JIT_SPRAY_DETECTOR_HPP_PATH = ROOT / "src/PhantomCore/Exploits/JITSprayDetector.hpp"
KERNEL_EXPLOIT_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Exploits/KernelExploitDetector.cpp"
ATOM_BOMBING_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Core/Process/AtomBombingDetector.cpp"
ATOM_BOMBING_DETECTOR_HPP_PATH = ROOT / "src/PhantomCore/Core/Process/AtomBombingDetector.hpp"

# The USB responder, whose accounting was corrected alongside the exploit tier.
BAD_USB_DETECTOR_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/BadUSBDetector.cpp"
)
USB_DEVICE_MONITOR_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/USBDeviceMonitor.cpp"
)
BAD_USB_DETECTOR_HPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/BadUSBDetector.hpp"
)

# The EternalBlue/SMB inspector, whose block claim was corrected in the same sweep.
WANNACRY_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/RansomwareProtection/WannaCryDetector.cpp"
)
WANNACRY_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/RansomwareProtection/WannaCryDetector.hpp"
)

# The VSS destruction analyzer and the ransomware subsystem's kernel event
# aggregator. ShadowCopyProtector::OnKernelProcessNotify had ZERO callers while
# the subsystem called its Initialize and Shutdown, so the module reported
# itself online with no feed and its entire pre-execution analysis - attack-type
# classification, whitelist, decision callback, event history, T1490 telemetry
# and the Critical alert - had never executed. The dispatch is asserted here
# because nothing in a build or a unit test can notice a missing fan-out entry.
SHADOW_COPY_PROTECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/RansomwareProtection/ShadowCopyProtector.cpp"
)
SHADOW_COPY_PROTECTOR_WIRE_PATH = (
    ROOT / "src/PhantomCore/RansomwareProtection/ShadowCopyProtectorWire.cpp"
)
RANSOMWARE_WIRING_CPP_PATH = (
    ROOT / "src/PhantomCore/RansomwareProtection/RansomwareWiring.cpp"
)

# The AMSI provider. It tracked "this process attempted an AMSI bypass" in a
# parallel set AND map - two structures for one fact - whose only eraser was a
# process-exit branch that has no feed, while a deque in the SAME locked block
# was explicitly bounded. So the pair grew without limit under live producers,
# and the two had already drifted: the cross-process detector determined the
# technique, put it in the event it raised, then recorded set membership only,
# so the technique accessor answered Unknown for a bypass it had just named.
AMSI_INTEGRATION_CPP_PATH = ROOT / "src/PhantomCore/Scripts/AMSIIntegration.cpp"
AMSI_INTEGRATION_HPP_PATH = ROOT / "src/PhantomCore/Scripts/AMSIIntegration.hpp"

# The privilege-escalation detector. It recorded kernel-supplied facts about a
# process in TWO parallel maps keyed by the same pid, written on adjacent lines,
# with no erase, no bound, and - unlike their two sibling containers 33 lines
# above, which have a cap AND an erase AND are cleared in both Initialize and
# Shutdown - no presence in either lifecycle clear. Both maps are read by the
# monitoring loop, and one of those reads decides whether to SKIP
# token-manipulation checks for a pid whose recorded path is whitelisted, so a
# record outliving its process is a detection gap and not merely a leak.
#
# The elevation value was also fabricated: the kernel process notification
# carries no elevation bit, and the sole production caller passed a literal
# false, which both disabled the only path that populates the monitored set and
# made the correlation below read a made-up value as kernel evidence.
PRIVESC_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/Exploits/PrivilegeEscalationDetector.cpp"
)
PRIVESC_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/Exploits/PrivilegeEscalationDetector.hpp"
)

# The test binary's entry point. It owns the temporary-file sandbox, and that
# ownership is asserted here because the runtime guard inside it can be deleted
# together with the thing it guards.
TEST_MAIN_PATH = ROOT / "tests/test_main.cpp"

# Two network detectors that reported a CONFIGURED policy as a PERFORMED block.
# Neither module contains any mechanism capable of stopping a connection - no
# WFP filter, no SetTcpEntry, no firewall rule, no process termination - so the
# separation between what policy asked for and what happened is enforced here.
TOR_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Core/Network/TorDetector.cpp"
TOR_DETECTOR_HPP_PATH = ROOT / "src/PhantomCore/Core/Network/TorDetector.hpp"
VPN_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Core/Network/VPNDetector.cpp"
VPN_DETECTOR_HPP_PATH = ROOT / "src/PhantomCore/Core/Network/VPNDetector.hpp"

# IPLeakProtection is the opposite case from Tor/VPN: its kill switch is REAL
# (registered WFP sublayer, netsh via CreateProcessW, iphlpapi), so the defect
# was attribution rather than fabrication. A global "switch is engaged" flag was
# assigned to an individual leak's outcome.
IP_LEAK_PROTECTION_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/Privacy/IPLeakProtection.cpp"
)
IP_LEAK_PROTECTION_HPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/Privacy/IPLeakProtection.hpp"
)

# SelfDefense is the self-protection ORCHESTRATOR - the module an operator reads
# to answer "did we defend ourselves?" - so a counter that overstates a defence
# is more consequential here than anywhere else. Measuring found no fabricated
# block claim, but its periodic code-integrity check incremented
# memoryModificationBlocked for a change it recorded five lines later as
# wasBlocked = false, and since every other writer of that counter sits in
# unreachable code (the access gate has no callers, the kernel SelfProtect
# message has no producer) that was the only way any *Blocked counter in the
# module could ever read non-zero. RegistryProtection is registered alongside it
# because its one remaining claim is a gate DECISION, which is honest only while
# the caller enforces the decision it returns.
SELF_DEFENSE_CPP_PATH = ROOT / "src/PhantomCore/SelfProtection/SelfDefense.cpp"
REGISTRY_PROTECTION_CPP_PATH = (
    ROOT / "src/PhantomCore/SelfProtection/RegistryProtection.cpp"
)

# MessageTypes.h declares the kernel<->user message type enum. Its section
# headings used to advertise hex ranges the enum has never implemented, which is
# the documented reason a set of user-mode enforcement senders invented 0x30 as
# a "block this process" message type. MessageHandler.{c,h} hold the gates that
# actually run: the magic check, the MH_MAX_HANDLERS bound, and the build-time
# C_ASSERT tying that bound to this enum.
MESSAGE_TYPES_PATH = ROOT / "PhantomSensor/Shared/MessageTypes.h"
MESSAGE_HANDLER_C_PATH = (
    ROOT / "PhantomSensor/PhantomSensor/Communication/MessageHandler.c"
)
MESSAGE_HANDLER_H_PATH = (
    ROOT / "PhantomSensor/PhantomSensor/Communication/MessageHandler.h"
)


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _matching_delimiter(source: str, start: int, opening: str, closing: str) -> int:
    """Find a matching C delimiter while ignoring comments and literals."""
    depth = 0
    i = start
    in_string: Optional[str] = None
    in_line_comment = False
    in_block_comment = False
    escaped = False

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_string is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            i += 1
        elif ch in ('"', "'"):
            in_string = ch
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return i
        i += 1

    raise AssertionError(f"Unmatched delimiter {opening!r} at offset {start}")


def extract_c_function(source: str, name: str) -> str:
    """Return a C function definition, excluding calls and declarations."""
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    for match in pattern.finditer(source):
        open_paren = source.find("(", match.start())
        close_paren = _matching_delimiter(source, open_paren, "(", ")")
        cursor = close_paren + 1

        # Skip whitespace, routine-header comments, and any trailing specifier
        # sitting between the parameter list and the body.
        #
        # `noexcept` was a real gap, not a nicety: every function in the
        # ransomware wiring aggregator carries it, and this helper answered
        # "Function definition not found" for definitions that were plainly
        # present. That is the worse of the two possible failures, because the
        # message reads as an ABSENT function - exactly the conclusion these
        # coverage-gap tests exist to draw - when the truth was an unparsed one.
        #
        # Consuming these cannot promote a declaration or a call into a
        # definition: once the specifiers are eaten a declaration still lands on
        # ';' and a call still lands on ')' or ',', and only '{' is accepted
        # below. `&&` is tried before `&` so a reference qualifier is not split.
        trailing_specifiers = ("noexcept", "const", "override", "final", "&&", "&")
        while True:
            while cursor < len(source) and source[cursor].isspace():
                cursor += 1
            if source.startswith("//", cursor):
                newline = source.find("\n", cursor + 2)
                cursor = len(source) if newline < 0 else newline + 1
                continue
            if source.startswith("/*", cursor):
                comment_end = source.find("*/", cursor + 2)
                if comment_end < 0:
                    raise AssertionError(
                        f"Unterminated comment after {name} signature"
                    )
                cursor = comment_end + 2
                continue

            consumed = False
            for specifier in trailing_specifiers:
                if not source.startswith(specifier, cursor):
                    continue
                after = cursor + len(specifier)
                # Whole words only, so an identifier such as `constant` cannot
                # be mistaken for the `const` specifier.
                if specifier[0].isalpha() and after < len(source) and (
                    source[after].isalnum() or source[after] == "_"
                ):
                    continue
                cursor = after
                if specifier == "noexcept":
                    probe = cursor
                    while probe < len(source) and source[probe].isspace():
                        probe += 1
                    if probe < len(source) and source[probe] == "(":
                        cursor = _matching_delimiter(source, probe, "(", ")") + 1
                consumed = True
                break
            if consumed:
                continue
            break

        # A definition has a compound statement after optional routine-header
        # comments. Calls nested in an if-condition have another ')' here;
        # declarations have ';'.
        if cursor >= len(source) or source[cursor] != "{":
            continue

        close_brace = _matching_delimiter(source, cursor, "{", "}")
        return source[match.start() : close_brace + 1]

    raise AssertionError(f"Function definition not found: {name}")


def strip_c_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL)


def enclosing_statement(source: str, position: int) -> str:
    """Return the single C statement containing `position`.

    Used to assert that a delivery decision and its STATUS_TIMEOUT exclusion live
    in the SAME boolean expression. Checking only that both tokens appear
    somewhere near each other would pass for code that tests NT_SUCCESS first and
    mentions STATUS_TIMEOUT in an unreachable `else if` afterwards - which is
    exactly the shape this guard exists to reject.
    """
    start = max(
        source.rfind(";", 0, position),
        source.rfind("{", 0, position),
        source.rfind("}", 0, position),
    )
    candidates = [offset for offset in (source.find(";", position), source.find("{", position)) if offset >= 0]
    if not candidates:
        raise AssertionError(f"Unterminated statement at offset {position}")
    return source[start + 1 : min(candidates)]


class SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.precreate_source = read_source(PRECREATE_PATH)
        cls.scan_bridge_c = read_source(SCAN_BRIDGE_C_PATH)
        cls.scan_bridge_h = read_source(SCAN_BRIDGE_H_PATH)
        cls.comm_port_c = read_source(COMM_PORT_C_PATH)
        cls.comm_port_h = read_source(COMM_PORT_H_PATH)
        cls.driver_entry_c = read_source(DRIVER_ENTRY_C_PATH)
        cls.error_codes_h = read_source(ERROR_CODES_H_PATH)
        cls.process_notify_c = read_source(PROCESS_NOTIFY_C_PATH)
        cls.ipc_manager_cpp = read_source(IPC_MANAGER_CPP_PATH)
        cls.ipc_manager_hpp = read_source(IPC_MANAGER_HPP_PATH)
        cls.installer_components_wxs = read_source(INSTALLER_COMPONENTS_WXS_PATH)
        cls.self_defense_hpp = read_source(SELF_DEFENSE_HPP_PATH)
        cls.antivirus_service_hpp = read_source(ANTIVIRUS_SERVICE_HPP_PATH)
        cls.program_updater_cpp = read_source(PROGRAM_UPDATER_CPP_PATH)
        cls.rollback_manager_cpp = read_source(ROLLBACK_MANAGER_CPP_PATH)
        cls.install_probe_cpp = read_source(INSTALL_PROBE_CPP_PATH)
        cls.service_manager_hpp = read_source(SERVICE_MANAGER_HPP_PATH)
        cls.filter_connection_cpp = read_source(FILTER_CONNECTION_CPP_PATH)
        cls.message_protocol_h = read_source(MESSAGE_PROTOCOL_H_PATH)
        cls.registry_monitor_cpp = read_source(REGISTRY_MONITOR_CPP_PATH)
        cls.process_utils_cpp = read_source(PROCESS_UTILS_CPP_PATH)
        cls.behavior_analyzer_cpp = read_source(BEHAVIOR_ANALYZER_CPP_PATH)
        cls.real_time_protection_cpp = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        cls.communication_hpp = read_source(COMMUNICATION_HPP_PATH)
        cls.message_dispatcher_cpp = read_source(MESSAGE_DISPATCHER_CPP_PATH)
        cls.fuzzer_vcxproj = read_source(FUZZER_VCXPROJ_PATH)
        cls.filter_registration_c = read_source(FILTER_REGISTRATION_C_PATH)
        cls.shared_defs_h = read_source(SHARED_DEFS_H_PATH)
        cls.backup_protector_hpp = read_source(BACKUP_PROTECTOR_HPP_PATH)
        cls.backup_protector_cpp = read_source(BACKUP_PROTECTOR_CPP_PATH)
        cls.tamper_protection_hpp = read_source(TAMPER_PROTECTION_HPP_PATH)
        cls.tamper_protection_cpp = read_source(TAMPER_PROTECTION_CPP_PATH)

    def test_a_decision_hook_never_uses_a_permissive_sentinel(self) -> None:
        """A decision hook must be able to express "permit" distinctly from silence.

        BackupProtector::QueryDecision used to return a bare ProtectionAction and
        answer Allow for all three of "no callback registered", "the callback
        threw" and "the callback deliberately said allow", while its one consumer
        applied the override only when the value was NOT Allow. So a registrant
        could express every verdict except the one it most needed.

        The three sibling decision hooks already return std::optional
        (FileProtection, RegistryProtection, ProcessProtection) and are consumed
        with has_value(); this pins that BackupProtector now agrees, and that its
        no-opinion path answers nullopt rather than a verdict - so a throwing
        callback can never become a bypass of the module's own policy.
        """
        hpp = strip_c_comments(self.backup_protector_hpp)
        cpp = strip_c_comments(self.backup_protector_cpp)

        self.assertEqual(
            hpp.count("std::function<std::optional<ProtectionAction>("),
            1,
            "BackupProtector::DecisionCallback must return std::optional<ProtectionAction>",
        )
        self.assertEqual(
            len(re.findall(r"using\s+DecisionCallback\s*=\s*std::function<ProtectionAction\(", hpp)),
            0,
            "DecisionCallback must not return a bare ProtectionAction - there is no spare "
            "value left to mean 'no opinion'",
        )

        # The no-opinion path must say so explicitly, and must not answer a verdict.
        # Scoped to QueryDecision: "return std::nullopt;" is ordinary elsewhere in
        # this file (AnalyzeProcess and MatchCommandPattern both use it), so a
        # whole-file count would assert nothing about the hook.
        query = extract_c_function(cpp, "BackupProtectorImpl::QueryDecision")
        self.assertGreater(len(query), 200, "failed to slice QueryDecision")
        self.assertEqual(
            query.count("return std::nullopt;"),
            1,
            "QueryDecision's no-callback / callback-threw path must return std::nullopt",
        )
        self.assertEqual(
            query.count("return ProtectionAction::Allow;"),
            0,
            "QueryDecision must not answer a permissive verdict to mean 'no opinion'",
        )
        self.assertEqual(
            query.count("cb = m_decisionCallback;"),
            1,
            "the callback must be copied under the lock and invoked outside it",
        )

        # The consumer must honour ANY engaged value instead of filtering out Allow.
        offenders = [
            line.strip()
            for line in cpp.splitlines()
            if "cbAction" in line and "ProtectionAction::Allow" in line
        ]
        self.assertEqual(
            offenders,
            [],
            "the decision consumer must not compare the override against Allow; that "
            "comparison is what discarded a registrant's permit",
        )

    def test_the_tamper_response_hook_is_consulted_and_reports_only_what_it_did(self) -> None:
        """TamperProtection::SetResponseHandler had zero invocation sites.

        Two things are pinned. First, the handler must be consulted on BOTH event
        paths: HandleTamperEvent (the periodic integrity verifier) and
        RecordAPTEvent (hook / parent-PID / handle-strip detection, which
        hardcoded Alert and was the one path immune to configuration). Wiring only
        one is the same half-fix that let the file-scan length unit diverge.

        Second, neither path may claim a block. Both are post-hoc: one fires when
        a protected file is already gone, the other when its hash already differs.
        The default Protect profile requests Standard (Log|Alert|Block), so taking
        the Block flag as proof of a block reported EVERY detection as prevented
        tampering and inverted the module's headline statistic.
        """
        hpp = strip_c_comments(self.tamper_protection_hpp)
        cpp = strip_c_comments(self.tamper_protection_cpp)

        self.assertEqual(
            hpp.count("std::function<std::optional<TamperResponse>(const TamperEvent&)>"),
            1,
            "TamperResponseHandler must return std::optional<TamperResponse>: TamperResponse "
            "is a flag set whose zero value None is itself meaningful, so it has no spare "
            "value to mean 'no opinion'",
        )

        # Exactly one site reads the handler - the shared resolver - so the two
        # event paths cannot drift apart in how they treat it.
        self.assertEqual(
            cpp.count("handler = m_responseHandler;"),
            1,
            "the response handler must be read in exactly one place (the resolver)",
        )
        self.assertEqual(
            cpp.count("ResolveResponse(event)"),
            2,
            "both event paths (HandleTamperEvent and RecordAPTEvent) must resolve their "
            "response through the handler-aware resolver",
        )
        self.assertEqual(
            cpp.count("return GetEventResponse(event.type);"),
            1,
            "the resolver must fall back to the configured policy, so a handler that "
            "declines or throws cannot suppress it",
        )
        self.assertEqual(
            cpp.count("event.responseTaken = TamperResponse::Alert;"),
            0,
            "RecordAPTEvent must not hardcode its response and ignore the policy",
        )

        # No path in this module may assert a block, and both must say so plainly.
        self.assertEqual(
            cpp.count("wasBlocked = true"),
            0,
            "a post-hoc integrity finding must never be reported as blocked",
        )
        self.assertEqual(
            cpp.count("event.wasBlocked = false;"),
            2,
            "both event paths must state explicitly that nothing was prevented",
        )
        self.assertEqual(
            cpp.count("m_stats.totalTamperingBlocked.fetch_add"),
            0,
            "totalTamperingBlocked counts PREVENTED tampering and has no producer here",
        )

        # The gap between requested and carried out must be measurable, and the
        # new counter must exist at all three sites a counter needs - increment,
        # snapshot and reset - or a reset would leave a stale delta baseline.
        self.assertGreaterEqual(
            cpp.count("m_stats.responsesNotCarriedOut.fetch_add"),
            1,
            "requested-but-unperformed responses must be counted",
        )
        self.assertEqual(
            cpp.count("snap.responsesNotCarriedOut"),
            1,
            "the new counter must be published in the statistics snapshot",
        )
        self.assertEqual(
            cpp.count("m_stats.responsesNotCarriedOut.store(0"),
            1,
            "the new counter must be cleared by ResetStatistics",
        )
        # totalTamperingBlocked is kept, not deleted: it is the right counter for a
        # genuine interception path. It must stay plumbed so its zero is read as
        # accurate rather than as a broken metric.
        self.assertEqual(cpp.count("snap.totalTamperingBlocked"), 1)
        self.assertEqual(cpp.count("m_stats.totalTamperingBlocked.store(0"), 1)

    def test_the_exploit_tier_never_claims_a_block_it_did_not_perform(self) -> None:
        """wasBlocked may only be set where enforcement ran AND reported success.

        9971ef9e split blockRequested (configured INTENT) from wasBlocked
        (enforcement carried out) across five exploit-tier modules, after finding
        seven sites that answered "attack blocked" whenever blocking was merely
        CONFIGURED - and one that discarded TerminateProcess's return value.

        This is a source-text contract because four of the five modules have no
        behavioural test that could catch a regression: reaching their claim
        sites needs a live kernel memory alert or a real stack pivot. The
        residual claim COUNT is therefore the enforceable invariant, and it is
        measured here rather than trusted from a commit message.

        Comments are stripped FIRST. The explanatory comments added by that
        commit necessarily QUOTE the old defect, so a comment-blind count is
        guaranteed to produce false positives - that has now happened five times.
        """
        claim = re.compile(r"\bwasBlocked\s*=\s*true\b")

        # Measured after 9971ef9e. The two permitted sites are the only places in
        # the tier where a process was actually terminated and the call reported
        # success; the three zeros are modules that perform no enforcement at all,
        # because user mode cannot un-queue an APC, un-spray a JIT page or
        # un-execute a ROP chain that has already run.
        expected = (
            ("ROPProtection.cpp", ROP_PROTECTION_CPP_PATH, 1),
            ("StackPivotDetector.cpp", STACK_PIVOT_DETECTOR_CPP_PATH, 1),
            ("JITSprayDetector.cpp", JIT_SPRAY_DETECTOR_CPP_PATH, 0),
            ("KernelExploitDetector.cpp", KERNEL_EXPLOIT_DETECTOR_CPP_PATH, 0),
            ("AtomBombingDetector.cpp", ATOM_BOMBING_DETECTOR_CPP_PATH, 0),
        )

        stripped: dict[str, str] = {}
        offenders: list[str] = []
        for name, path, allowed in expected:
            body = strip_c_comments(read_source(path))
            stripped[name] = body
            found = len(claim.findall(body))
            if found != allowed:
                offenders.append(
                    f"{name}: {found} wasBlocked=true site(s), expected {allowed}"
                )
        # Report only the mismatch, never the haystack.
        self.assertEqual(
            offenders,
            [],
            "an exploit-tier module claims a block it does not perform: "
            + "; ".join(offenders),
        )

        # The count alone would accept MOVING a claim into a blockOn* branch, so
        # each surviving claim must sit downstream of a checked enforcement call.
        rop = stripped["ROPProtection.cpp"]
        rop_claim = claim.search(rop)
        self.assertIsNotNone(rop_claim, "ROPProtection must still be able to block")
        assert rop_claim is not None  # narrow for type checkers
        window = rop[max(0, rop_claim.start() - 800) : rop_claim.start()]
        self.assertIn(
            "::TerminateProcess(",
            window,
            "ROPProtection's only block claim must follow a TerminateProcess call "
            f"whose result was tested (claim at offset {rop_claim.start()})",
        )

        pivot = stripped["StackPivotDetector.cpp"]
        pivot_claim = claim.search(pivot)
        self.assertIsNotNone(pivot_claim, "StackPivotDetector must still be able to block")
        assert pivot_claim is not None
        guard = pivot.find("if (terminated)")
        self.assertNotEqual(
            guard,
            -1,
            "StackPivotDetector must test TerminateProcess's return value; the "
            "defect fixed by 9971ef9e was discarding it",
        )
        self.assertGreater(
            pivot_claim.start(),
            guard,
            "StackPivotDetector's block claim must sit INSIDE the success branch "
            f"(guard at {guard}, claim at {pivot_claim.start()})",
        )

        # The gap counter must survive a copy. JITSprayStatistics and
        # AtomBombingStatistics both carry HAND-WRITTEN copy constructors and
        # assignment operators, so a member added to the declaration alone is
        # silently dropped on every copy - which is exactly how a counter rots
        # into a structural zero (task 102).
        jit_hpp = strip_c_comments(read_source(JIT_SPRAY_DETECTOR_HPP_PATH))
        self.assertGreaterEqual(
            jit_hpp.count("blockRequestedNotPerformed"),
            3,
            "JITSprayDetector.hpp must carry the gap counter in its declaration "
            "AND in both hand-written copy operations",
        )
        atom_hpp = strip_c_comments(read_source(ATOM_BOMBING_DETECTOR_HPP_PATH))
        self.assertGreaterEqual(
            atom_hpp.count("blockRequestedNotPerformed"),
            2,
            "AtomBombingDetector.hpp must carry the gap counter in its "
            "declaration AND in its hand-written copy assignment",
        )

        # Every module must record the INTENT it used to claim as an outcome,
        # otherwise the policy flag becomes unobservable rather than honest.
        missing = [
            name for name, body in stripped.items() if "blockRequested" not in body
        ]
        self.assertEqual(
            missing,
            [],
            "these modules dropped the configured-intent record: " + ", ".join(missing),
        )

    def test_the_badusb_responder_counts_only_enforcement_it_performed(self) -> None:
        """BadUSBDetector claimed a block whenever a response ran, not when it worked.

        Measured before the fix: the response executor DISCARDED the bool from
        both EjectDevice_Locked and BlockDevice_Locked (each declared
        [[nodiscard]] bool), incremented attacksBlocked OUTSIDE the guard that
        decided whether any enforcement ran at all, and BlockDevice_Locked
        incremented that same counter itself - so one successful block counted
        twice while a response that enforced nothing still counted once.

        Underneath all of that, BadUSBAttackEvent::device was never assigned at
        either attack-event construction site, so devicePath was ALWAYS empty,
        every enforcement guard failed, and no response had ever executed.

        Comments are stripped first, and that is load-bearing: the explanatory
        comments necessarily quote the old defect, so a comment-blind count is
        guaranteed to false-positive.
        """
        cpp = strip_c_comments(read_source(BAD_USB_DETECTOR_CPP_PATH))
        hpp = strip_c_comments(read_source(BAD_USB_DETECTOR_HPP_PATH))

        offenders: list[str] = []

        # attacksBlocked is incremented in EXACTLY ONE place. That single number
        # carries two invariants at once: two sites is how the double count
        # returns, and a site outside the accounting helper is how an unenforced
        # response starts claiming a block again.
        increments = len(re.findall(r"\battacksBlocked\+\+", cpp))
        if increments != 1:
            offenders.append(
                f"attacksBlocked incremented at {increments} site(s), expected 1"
            )

        # Slice the executor by its definition. The two CALL sites appear
        # earlier in the file than the definition, so a name-only search would
        # extract a call; "void ExecuteResponse_Locked(" is unique to the
        # definition. Offsets only are reported, never the text.
        start = cpp.find("void ExecuteResponse_Locked(")
        end = cpp.find("void AccountEnforcement_Locked(")
        executor = ""
        if start < 0 or end < 0 or end <= start:
            offenders.append(
                f"could not slice the response executor (start={start}, end={end})"
            )
        else:
            executor = cpp[start:end]

        # Every enforcement call inside the executor must have its return
        # CAPTURED. A bare call statement is a discarded [[nodiscard]] bool,
        # which is precisely how StackPivotDetector reported a failed
        # TerminateProcess as a successful one.
        for name, expected in (("EjectDevice_Locked", 1), ("BlockDevice_Locked", 2)):
            total = len(re.findall(re.escape(name) + r"\s*\(", executor))
            captured = len(
                re.findall(r"haveTarget\s*&&\s*" + re.escape(name) + r"\s*\(", executor)
            )
            if total != expected or captured != expected:
                offenders.append(
                    f"{name}: {total} call(s) in the executor, {captured} with the "
                    f"return captured, expected {expected}/{expected}"
                )

        # The Quarantine arm's escalation must be PERFORMED, not merely logged.
        # Before the fix the arm logged "escalating to USBDeviceMonitor" and no
        # code anywhere called into that module.
        if "EmergencyBlockDevice" not in cpp:
            offenders.append(
                "the Quarantine escalation to USBDeviceMonitor is absent again"
            )

        # ...and it must run with m_mutex RELEASED. USBDeviceMonitor acquires
        # its own lock while its device-arrival path calls back into this module
        # (ProcessNewDevice -> IsKnownBadDevice / AnalyzeDevice), so escalating
        # from inside the locked executor is a lock-order inversion. The queue
        # is the seam: the executor may only push, the drain may only call.
        if executor and "EmergencyBlockDevice" in executor:
            offenders.append(
                "the escalation is called from inside the locked response executor"
            )
        if executor and "m_pendingDeviceEscalations" not in executor:
            offenders.append("the locked executor no longer queues the escalation")

        # event.device must be resolved at BOTH construction sites. Without it
        # devicePath is always empty, every guard fails, and no response can
        # ever run - the silent state this change ended.
        resolved = len(re.findall(r"device = ResolveDeviceDescriptor_Locked", cpp))
        if resolved != 2:
            offenders.append(
                f"device descriptor resolved at {resolved} site(s), expected 2"
            )

        # The intent record must survive: deleting responseRequested would make
        # the policy decision unobservable rather than honest, so losing it
        # fails as loudly as reintroducing the false claim.
        for label, body in (("cpp", cpp), ("hpp", hpp)):
            if "responseRequested" not in body:
                offenders.append(
                    f"the responseRequested intent record was removed from the {label}"
                )

        # The gap counter must stay plumbed through the live struct, the
        # snapshot, Reset() and the JSON. Present in only some of those is task
        # 102's structural zero arrived at by another route.
        gap_cpp = len(re.findall(r"blockRequestedNotPerformed", cpp))
        gap_hpp = len(re.findall(r"blockRequestedNotPerformed", hpp))
        if gap_cpp < 4:
            offenders.append(
                f"blockRequestedNotPerformed appears {gap_cpp} time(s) in the .cpp, "
                "expected at least 4 (increment, snapshot, reset, json)"
            )
        if gap_hpp < 2:
            offenders.append(
                f"blockRequestedNotPerformed appears {gap_hpp} time(s) in the .hpp, "
                "expected at least 2 (live struct, snapshot struct)"
            )

        self.assertEqual(offenders, [], "; ".join(offenders))

    def test_the_smb_inspector_never_claims_a_block_it_cannot_perform(self) -> None:
        """WannaCryDetector::AnalyzeSMBTraffic is a pure inspector.

        It receives a std::span<const uint8_t> and holds no transport, so it can
        neither alter nor drop the frame it is shown. It used to set
        indicator.wasBlocked from config.blockSMBExploit - a policy flag - which
        reported every EternalBlue sighting as a prevented attack.

        This has to be a SOURCE contract rather than a behavioural one: the
        function has ZERO production callers, so no test can reach the claim site
        by running it. The residual claim count is the only enforceable invariant,
        the same technique the exploit tier needed.

        Comments are stripped FIRST and that is load-bearing: the explanatory
        comments added with the fix necessarily quote the defect they describe, so
        a comment-blind count is guaranteed to false-positive.
        """
        cpp = strip_c_comments(read_source(WANNACRY_DETECTOR_CPP_PATH))
        hpp = strip_c_comments(read_source(WANNACRY_DETECTOR_HPP_PATH))
        offenders: list[str] = []

        # A policy flag can never be evidence that an exploit was stopped.
        flag_derived = re.findall(r"wasBlocked\s*=\s*config\.", cpp)
        if flag_derived:
            offenders.append(
                f"WannaCryDetector.cpp derives wasBlocked from a config flag "
                f"{len(flag_derived)} time(s); a policy flag is intent, not an outcome"
            )

        # Nothing in this module prevents an SMB exploit, so nothing may claim one.
        for label, src in (("cpp", cpp), ("hpp", hpp)):
            claims = re.findall(r"wasBlocked\s*=\s*true", src)
            if claims:
                offenders.append(
                    f"WannaCryDetector.{label} claims wasBlocked = true "
                    f"{len(claims)} time(s); no code path here drops an SMB frame"
                )

        # The DEFAULT is the contract, and it is invisible to any grep for an
        # assignment - which is exactly how ShadowCopyProtector's true default hid.
        if not re.search(r"bool\s+wasBlocked\s*=\s*false\s*;", hpp):
            offenders.append(
                "EternalBlueIndicator::wasBlocked must default to false in the header"
            )

        # Deleting the intent record must fail as loudly as reintroducing the claim,
        # or the fix degrades into simply losing what policy asked for.
        if not re.search(r"blockRequested", cpp):
            offenders.append("the blockRequested intent record was removed from the .cpp")
        if not re.search(r"bool\s+blockRequested\s*=\s*false\s*;", hpp):
            offenders.append(
                "EternalBlueIndicator::blockRequested must be declared and default to false"
            )

        # WannaCryStatistics hand-writes BOTH copy operators, so a counter present
        # in the declaration alone is dropped on every copy and becomes a structural
        # zero. Require declaration + both copy operators + snapshot struct.
        detected_hpp = len(re.findall(r"smbExploitsDetected", hpp))
        if detected_hpp < 6:
            offenders.append(
                f"smbExploitsDetected appears {detected_hpp} time(s) in the .hpp, expected "
                "at least 6 (declaration, both hand-written copy operators, snapshot struct)"
            )
        detected_cpp = len(re.findall(r"smbExploitsDetected", cpp))
        if detected_cpp < 6:
            offenders.append(
                f"smbExploitsDetected appears {detected_cpp} time(s) in the .cpp, expected "
                "at least 6 (increment, snapshot fill, Reset, both JSON serializers)"
            )

        # The prevention counter is deliberately kept with no producer so its zero
        # reads as accurate. Removing it would delete the place a real packet-dropping
        # path must report to.
        if not re.search(r"smbExploitsBlocked", hpp):
            offenders.append(
                "smbExploitsBlocked must remain declared as the counter a real "
                "SMB-blocking path reports to"
            )

        self.assertEqual(offenders, [], "; ".join(offenders))

    def test_the_test_binary_owns_and_reclaims_its_temporary_files(self) -> None:
        """One clean run left 14,142 MB of temporary files that nothing deleted.

        MEASURED before the sandbox existed: a single fully passing run of
        phantom-tests.exe (5,016 tests from 518 suites, exit 0, zero skips) left
        136 files and 14,142 MB in the system temporary directory. 133 of them
        were ThreatIntel databases - 131 at 100 MB, one at 1 GB, one at 10 MB -
        and they are not sparse, logical and allocated size both measured at
        104,857,600 bytes. Ten runs is 138 GB of disk nobody reclaims.

        THIS IS A SOURCE CONTRACT BECAUSE NO BEHAVIOURAL TEST CAN COVER IT. What
        is being protected is main()'s ORDERING and its CHOICE OF REMOVAL CALL. A
        test asserting either would have to run inside the process whose exit
        path is the subject, and by the time disposal happens googletest has
        already finished reporting. The binary does carry a runtime guard
        (SandboxEnvironment), and that guard is stronger for what it covers - but
        it can be deleted in the same edit that deletes the sandbox, which is
        exactly the failure this external witness exists to catch.
        """
        src = strip_c_comments(read_source(TEST_MAIN_PATH))

        # ------------------------------------------------------------------
        # The redirect is what makes the sandbox cover PRODUCT code and not
        # merely the test files. GetTempPathW reads the process environment
        # block, so redirecting TMP/TEMP for this process relocates
        # StoreConfig::CreateDefault() - the actual producer of those 133
        # databases, which tests/test_main.cpp has no other way to reach.
        # ------------------------------------------------------------------
        for variable in ('L"TMP"', 'L"TEMP"'):
            self.assertEqual(
                src.count("SetEnvironmentVariableW(" + variable),
                1,
                "tests/test_main.cpp must redirect {} exactly once through "
                "SetEnvironmentVariableW. That call is the entire mechanism: "
                "without it every temporary file the run creates lands in the "
                "real temporary directory and nothing reclaims it.".format(variable),
            )

        # ------------------------------------------------------------------
        # Ordering. Establishing the sandbox after something has already run
        # leaves whatever ran first writing outside it, and disposing before the
        # tests finish deletes the working set out from under them.
        # ------------------------------------------------------------------
        offsets = {
            "sandbox.Establish()": src.find("sandbox.Establish()"),
            "RUN_ALL_TESTS()": src.find("RUN_ALL_TESTS()"),
            "sandbox.Dispose()": src.find("sandbox.Dispose()"),
        }
        for name, offset in offsets.items():
            self.assertNotEqual(
                offset,
                -1,
                "tests/test_main.cpp no longer contains {} - the temporary file "
                "sandbox has been removed or renamed.".format(name),
            )
        self.assertLess(
            offsets["sandbox.Establish()"],
            offsets["RUN_ALL_TESTS()"],
            "The sandbox must be established BEFORE RUN_ALL_TESTS, at offset {} "
            "rather than {}. Anything that runs first writes outside it.".format(
                offsets["sandbox.Establish()"], offsets["RUN_ALL_TESTS()"]
            ),
        )
        self.assertLess(
            offsets["RUN_ALL_TESTS()"],
            offsets["sandbox.Dispose()"],
            "Disposal must happen AFTER RUN_ALL_TESTS, at offset {} rather than "
            "{}.".format(offsets["sandbox.Dispose()"], offsets["RUN_ALL_TESTS()"]),
        )

        # ------------------------------------------------------------------
        # remove_all is banned BY NAME, and this is the assertion that carries
        # the measurement. It treats the whole tree as one operation and stops at
        # its first error, so any entry it cannot delete protects everything it
        # has not yet visited. Measured: a 654-byte forensic buffer that the
        # product deliberately hardens to SYSTEM + BUILTIN\\Administrators - which
        # is CORRECT tamper-resistance, not a defect - aborted the removal of
        # 14,135 MB, because NTFS enumerated ShadowStrike_CoreSystem_UT_* before
        # ShadowStrike_ThreatIntel_*.
        # ------------------------------------------------------------------
        self.assertEqual(
            src.count("remove_all"),
            0,
            "tests/test_main.cpp must not use std::filesystem::remove_all. It "
            "aborts at its first error, so one undeletable entry preserves the "
            "rest of the tree - measured at 654 bytes protecting 14,135 MB. "
            "Delete per entry and continue past failures instead.",
        )
        self.assertGreaterEqual(
            src.count("RemoveTreeRobustly("),
            2,
            "Both the disposal path and the startup orphan sweep must go through "
            "the per-entry removal helper, so neither can be defeated by a single "
            "file it cannot delete.",
        )

        # ------------------------------------------------------------------
        # The startup sweep is the half that survives a crash. Disposing at exit
        # alone still leaks on every run that faults or is killed - and the
        # bounded runner used against this binary calls Kill() on timeout, so
        # that is a routine case, not an exotic one.
        # ------------------------------------------------------------------
        self.assertEqual(
            src.count("SweepOrphans()"),
            2,
            "SweepOrphans must be defined and called exactly once each. Without "
            "the startup sweep, every crashed or killed run leaks its whole "
            "working set permanently, because no exit-time code runs at all.",
        )

        # ------------------------------------------------------------------
        # The runtime guard must actually verify the redirect took effect rather
        # than assume it. Same reasoning as LoggerEnvironment in the same file: a
        # guard that silently stops guarding is worse than no guard.
        # ------------------------------------------------------------------
        env_at = src.find("class SandboxEnvironment")
        self.assertNotEqual(
            env_at, -1, "The SandboxEnvironment runtime guard has been removed."
        )
        env_body = src[env_at : env_at + 2400]
        # Counted with >= rather than == deliberately: the failure messages inside
        # this guard necessarily NAME temp_directory_path, and strip_c_comments
        # removes comments but not string literals, so an equality assertion here
        # would be measuring prose. What matters is that a real call exists and
        # that its result is compared against the sandbox.
        self.assertGreaterEqual(
            env_body.count("temp_directory_path"),
            1,
            "SandboxEnvironment must resolve temp_directory_path() so a redirect "
            "that stops working fails the whole binary loudly instead of quietly "
            "resuming 14 GB per run.",
        )
        self.assertGreaterEqual(
            env_body.count("sandbox.Run()"),
            1,
            "SandboxEnvironment must compare the resolved temporary directory "
            "against the sandbox it established. Resolving it and not comparing "
            "it would assert nothing.",
        )
        self.assertGreaterEqual(
            env_body.count("ASSERT_"),
            3,
            "SandboxEnvironment must assert its own preconditions, not merely "
            "compute them.",
        )
        self.assertEqual(
            src.count("new SandboxEnvironment()"),
            1,
            "SandboxEnvironment must be registered with googletest, or its "
            "assertions never run.",
        )

        # ------------------------------------------------------------------
        # The log deliberately lives OUTSIDE the sandbox, in the location
        # captured before the redirect: a diagnostic deleted along with the run
        # it describes cannot be used to investigate that run. It is bounded
        # separately by rotation (30 MB ceiling, measured at 15.22 MB across a
        # full run), so it is not part of the growth this sandbox addresses.
        # ------------------------------------------------------------------
        self.assertEqual(
            src.count("sandbox.SystemTemp()"),
            1,
            "The logger must be given the real temporary directory captured "
            "before the redirect, so its output survives sandbox disposal.",
        )

    def test_the_network_detectors_never_report_policy_as_enforcement(self) -> None:
        # Comments are stripped FIRST and that is load-bearing: the explanatory
        # comments added with this fix necessarily QUOTE the old defect
        # ("wasBlocked = ShouldBlock", the counter name, the false description
        # string), so a comment-blind count is guaranteed to false-positive.
        tor_cpp = strip_c_comments(read_source(TOR_DETECTOR_CPP_PATH))
        tor_hpp = strip_c_comments(read_source(TOR_DETECTOR_HPP_PATH))
        vpn_cpp = strip_c_comments(read_source(VPN_DETECTOR_CPP_PATH))
        vpn_hpp = strip_c_comments(read_source(VPN_DETECTOR_HPP_PATH))

        # --- TorDetector: the outcome may not be derived from the predicate ---
        self.assertEqual(
            tor_cpp.count("wasBlocked = ShouldBlock("),
            0,
            "TorDetector assigned a pure policy predicate to wasBlocked, so an "
            "alert claimed a block whenever blocking was merely configured. "
            "ShouldBlock() performs no I/O and this module has no mechanism to "
            "drop a connection.",
        )
        self.assertEqual(
            tor_cpp.count("blockRequested = ShouldBlock("),
            1,
            "The policy REQUEST must still be recorded exactly once, so deleting "
            "the intent record fails as loudly as reintroducing the false claim.",
        )
        self.assertEqual(
            tor_cpp.count("wasBlocked = true"),
            0,
            "Nothing in TorDetector performs enforcement, so nothing in it may "
            "claim a performed block.",
        )
        self.assertGreaterEqual(
            tor_cpp.count("alert.wasBlocked = false"),
            1,
            "TorDetector must state the outcome explicitly rather than leaving "
            "it to a default a later edit could change.",
        )

        # --- VPNDetector: ApplyPolicy performs nothing, so it claims nothing ---
        self.assertEqual(
            vpn_cpp.count("m_stats.connectionsBlocked++"),
            0,
            "VPNDetector::ApplyPolicy incremented connectionsBlocked for every "
            "connection the POLICY selected, so the counter measured decisions "
            "rather than blocks and could never read zero under a blocking "
            "policy - which is why the gap was invisible.",
        )
        self.assertEqual(
            vpn_cpp.count('"VPN connection blocked"'),
            0,
            "The alert description asserted a block that never occurred. "
            "A detection whose requested block was not performed must not be "
            "rendered with the same words as a performed block.",
        )
        self.assertEqual(
            vpn_cpp.count("wasBlocked = true"),
            0,
            "Nothing in VPNDetector disables an adapter, installs a WFP filter, "
            "adds a firewall rule or terminates a process.",
        )
        self.assertEqual(
            vpn_cpp.count("alert.wasBlocked = false"),
            1,
            "The VPN alert must record the outcome explicitly, exactly once.",
        )
        self.assertGreaterEqual(
            vpn_cpp.count("alert.blockRequested = blockRequested"),
            1,
            "The policy request must still reach the alert.",
        )

        # --- Both counters must be plumbed, or they become structural zeros ---
        # A counter added to a declaration but never incremented, or never
        # cleared by Reset(), reads as permanently healthy - the same defect
        # class as pool=0/0 (task 102).
        for name, cpp, incr, reset in (
            (
                "TorDetector.cpp",
                tor_cpp,
                "m_statistics.blockRequestedNotPerformed.fetch_add(1",
                "blockRequestedNotPerformed.store(0",
            ),
            (
                "VPNDetector.cpp",
                vpn_cpp,
                "m_stats.blockRequestedNotPerformed++",
                "blockRequestedNotPerformed = 0",
            ),
        ):
            self.assertGreaterEqual(
                cpp.count(incr),
                1,
                f"{name}: the enforcement-gap counter has no producer, so its "
                f"zero would be structural rather than accurate.",
            )
            self.assertGreaterEqual(
                cpp.count(reset),
                1,
                f"{name}: the enforcement-gap counter is not cleared by Reset(), "
                f"so ResetStatistics() would leave a stale value behind.",
            )

        for name, hpp in (("TorDetector.hpp", tor_hpp), ("VPNDetector.hpp", vpn_hpp)):
            self.assertGreaterEqual(
                hpp.count("blockRequested"),
                2,
                f"{name}: the alert must declare the request separately from the "
                f"outcome, and the statistics must name the gap.",
            )
            self.assertGreaterEqual(
                hpp.count("wasBlocked"),
                1,
                f"{name}: the outcome field is kept deliberately - it is the "
                f"correct field for a real enforcement path to set. Removing it "
                f"would delete the only written statement of what such a path "
                f"owes.",
            )

    def test_an_observed_ip_leak_is_never_recorded_as_a_blocked_one(self) -> None:
        cpp = strip_c_comments(read_source(IP_LEAK_PROTECTION_CPP_PATH))
        hpp = strip_c_comments(read_source(IP_LEAK_PROTECTION_HPP_PATH))

        # The exact defect: a global, temporal module flag assigned to one
        # leak's outcome. The leak is detected by observing that an external
        # service saw a non-VPN public IP, so it demonstrably escaped.
        self.assertEqual(
            cpp.count("wasBlocked = m_killSwitchActive"),
            0,
            "IPLeakProtection assigned the global kill-switch state to an "
            "individual leak's outcome, so a leak that provably escaped the "
            "tunnel was recorded as blocked - and which answer you got depended "
            "on ordering, since the monitor engages the switch on a VPN drop and "
            "checks for leaks afterwards.",
        )
        self.assertGreaterEqual(
            cpp.count("killSwitchActiveAtDetection ="),
            1,
            "The kill-switch state is still worth recording - it must be kept as "
            "its own field rather than deleted or overloaded onto the outcome.",
        )
        self.assertGreaterEqual(
            cpp.count("leak.wasBlocked = false"),
            1,
            "An observed leak must state its outcome explicitly.",
        )
        self.assertEqual(
            cpp.count("if (leak.wasBlocked)"),
            0,
            "The statistics counter must not be gated on the outcome field it "
            "used to derive from the same flag.",
        )

        # This module CAN enforce, so the outcome field is not merely reserved -
        # do not let a future edit delete it as unused.
        self.assertGreaterEqual(
            hpp.count("wasBlocked"),
            1,
            "IPLeakProtection's kill switch is real, so wasBlocked is the field "
            "a genuine prevention path sets. It must not be removed.",
        )

        # The escaped-while-engaged counter is a DETECTION signal, not
        # bookkeeping: it means the WFP filters did not cover the leaking path.
        self.assertGreaterEqual(
            cpp.count("leaksEscapedWhileKillSwitchActive.fetch_add("),
            1,
            "The enforcement-gap counter has no producer, so its zero would be "
            "structural rather than accurate.",
        )
        self.assertGreaterEqual(
            cpp.count("leaksEscapedWhileKillSwitchActive.store(0"),
            1,
            "The enforcement-gap counter is not cleared by Reset().",
        )
        # IPLeakStatistics hand-writes BOTH a copy constructor and an assignment
        # operator to load its atomics safely, and GetStatistics() copies. A
        # member added to the declaration alone is silently dropped on every
        # copy and becomes a structural zero - task 102 by another route.
        self.assertEqual(
            cpp.count("other.leaksEscapedWhileKillSwitchActive.load("),
            2,
            "The counter must be carried by BOTH hand-written copy operators "
            "(copy constructor and assignment), or every snapshot drops it.",
        )

    def test_selfdefense_never_counts_an_observed_change_as_a_prevented_one(self) -> None:
        """The self-protection orchestrator's integrity check observes; it cannot prevent.

        VerifyMemoryIntegrity hashes our own code section and compares it against
        a stored digest, so a mismatch means the write has ALREADY landed - and
        the event it records states exactly that with wasBlocked = false. It used
        to increment memoryModificationBlocked on that same path. Because every
        other writer of that counter is unreachable (FilterAccessRequest and
        IsAccessAllowed have zero callers anywhere in the repository, and the
        kernel SelfProtect message it also fires from has no producer in the
        driver), this was the ONLY way any *Blocked counter in SelfDefense could
        ever read non-zero. So the single number an operator would consult to ask
        "did we defend ourselves?" was reporting a modification that was not
        defended against at all.

        This is a source contract because reaching the live path needs our own
        .text section to be modified in a running service.
        """
        raw_cpp = read_source(SELF_DEFENSE_CPP_PATH)
        cpp = strip_c_comments(raw_cpp)
        hpp = strip_c_comments(read_source(SELF_DEFENSE_HPP_PATH))
        registry = strip_c_comments(read_source(REGISTRY_PROTECTION_CPP_PATH))

        body = strip_c_comments(
            extract_c_function(raw_cpp, "SelfDefenseImpl::VerifyMemoryIntegrity")
        )
        self.assertGreater(
            len(body),
            200,
            "VerifyMemoryIntegrity was not sliced, so nothing below is asserted.",
        )

        # The integrity check must not touch ANY prevented-outcome counter. This
        # is written as a pattern rather than a single name so that introducing a
        # different *Blocked counter here fails too.
        offenders = re.findall(r"m_stats\.\w*Blocked\.fetch_add", body)
        self.assertEqual(
            offenders,
            [],
            "VerifyMemoryIntegrity increments a prevented-outcome counter for a "
            "change it can only observe after the fact: "
            + ", ".join(sorted(set(offenders))),
        )
        self.assertEqual(
            body.count("codeIntegrityViolationsDetected.fetch_add"),
            1,
            "The observed code-integrity violation is not counted at all, so a "
            "modification of our own code section would now go unrecorded.",
        )
        self.assertEqual(
            body.count("wasBlocked = false"),
            1,
            "The integrity event must keep stating that nothing was blocked.",
        )

        # The detection counter must be plumbed everywhere the struct is copied
        # or cleared, or it becomes a structural zero that looks like health.
        for needle, where in (
            ("codeIntegrityViolationsDetected", "the public statistics struct"),
        ):
            self.assertGreaterEqual(
                hpp.count(needle),
                1,
                f"The detection counter is missing from {where}.",
            )
        self.assertGreaterEqual(
            cpp.count("codeIntegrityViolationsDetected.store(0"),
            1,
            "The detection counter is not cleared by InternalStats::Reset().",
        )
        self.assertGreaterEqual(
            cpp.count("snap.codeIntegrityViolationsDetected"),
            1,
            "The detection counter never reaches the public snapshot, so no "
            "caller of GetStatistics() can ever see it.",
        )
        self.assertGreaterEqual(
            cpp.count("codeIntegrityViolationsDetected = 0"),
            1,
            "The detection counter is not cleared by SelfDefenseStatistics::Reset().",
        )

        # Residual claim sites, pinned by count. Both surviving sites are gates
        # whose contract is that the CALLER enforces the returned decision, so
        # the claim is correct there and must not be rewritten - but a new one
        # must not appear either. memoryModificationBlocked keeps exactly its two
        # unreachable writers so the reachable one cannot come back.
        self.assertEqual(
            cpp.count("wasBlocked = true"),
            2,
            "SelfDefense gained or lost a block claim. The two expected sites are "
            "IsAccessAllowed (which returns false to deny) and the kernel "
            "SelfProtect handler; both are gates, neither is flag-derived.",
        )
        self.assertEqual(
            cpp.count("memoryModificationBlocked.fetch_add"),
            2,
            "memoryModificationBlocked must keep exactly its two writers inside "
            "the access gate and the kernel handler; a third one means an "
            "observation is being counted as a prevention again.",
        )
        self.assertEqual(
            registry.count("wasBlocked = true"),
            1,
            "RegistryProtection's single claim lives in FireBlockedOperationEvent, "
            "reached only from the FilterOperation gate.",
        )

    def test_the_vss_destruction_analyzer_has_a_production_feed(self) -> None:
        """ShadowCopyProtector's process-creation analyzer must be dispatched.

        Everything this module can do before a VSS destruction command runs -
        classify the attack by type, consult the whitelist and the decision
        callback, record the event, move the per-type counters, attribute
        MITRE T1490, raise the Critical alert - is reachable only through
        OnKernelProcessNotify. That function had ZERO callers while the
        subsystem happily called Initialize and Shutdown, so the module
        reported itself online and was inert.

        The overlap with BackupProtector is exactly why this is pinned rather
        than assumed harmless to lose: BackupProtector IS wired and matches the
        same vssadmin / wmic / PowerShell commands, but its handler writes one
        warning line and stops, so with this feed absent a T1490 attempt was
        visible nowhere an operator or the alert pipeline could see it.

        Comments are stripped first because the explanatory comments added with
        this wiring necessarily NAME the symbols asserted below, so a
        comment-blind check would be satisfied by prose alone.
        """
        wire = strip_c_comments(read_source(SHADOW_COPY_PROTECTOR_WIRE_PATH))
        wiring = strip_c_comments(read_source(RANSOMWARE_WIRING_CPP_PATH))
        protector = strip_c_comments(read_source(SHADOW_COPY_PROTECTOR_CPP_PATH))

        # 1. The shim exists and actually reaches the module.
        self.assertEqual(
            wire.count("void ShadowCopyProtector_OnProcessNotify("),
            1,
            "ShadowCopyProtectorWire.cpp must define the process-notify shim; "
            "a lifecycle-only shim is what left this module without a feed.",
        )
        self.assertEqual(
            wire.count("ShadowCopyProtector::Instance().OnKernelProcessNotify("),
            1,
            "the shim must forward to the module, not merely exist.",
        )
        self.assertEqual(
            wire.count("if (!isCreation) return;"),
            1,
            "termination events must be dropped: the analysis is a "
            "pre-execution command-line check and the module keeps no "
            "per-process state to release.",
        )

        # 2. The aggregator declares it and calls it from the fan-out.
        self.assertEqual(
            wiring.count("void ShadowCopyProtector_OnProcessNotify("),
            1,
            "RansomwareWiring.cpp must forward-declare the shim.",
        )

        dispatch = extract_c_function(wiring, "DispatchProcessNotify")
        self.assertGreater(
            len(dispatch),
            200,
            "DispatchProcessNotify was not sliced, so nothing below is asserted.",
        )
        self.assertEqual(
            dispatch.count(
                "ShadowCopyProtector_OnProcessNotify(pid, parentPid, imagePath, "
                "commandLine, isCreation)"
            ),
            1,
            "the fan-out must call the VSS analyzer with the real parent pid "
            "and the command line, which is what carries the attack intent.",
        )

        # 3. Regression guard: adding one module must not drop another. Each of
        #    these was in the fan-out before this feed was added.
        for sibling in (
            "RansomwareDetector_OnProcessNotify(",
            "LockyDetector_OnProcessNotify(",
            "HoneypotManager_OnProcessNotify(",
            "BackupProtector_OnProcessNotify(",
            "FileBackupManager_OnProcessNotify(",
            "WannaCryDetector_OnProcessCreated(",
        ):
            self.assertEqual(
                dispatch.count(sibling),
                1,
                "process-notify fan-out lost a module: " + sibling,
            )

        # 4. The parent pid is forwarded, not fabricated. It was hardcoded to 0
        #    here, so the telemetry record published a parent that was never
        #    measured - a defaulted value that reads like a fact.
        hook = extract_c_function(
            protector, "ShadowCopyProtector::OnKernelProcessNotify"
        )
        self.assertGreater(
            len(hook),
            80,
            "OnKernelProcessNotify was not sliced, so nothing below is asserted.",
        )
        self.assertEqual(
            hook.count("OnProcessCreation(processId, parentProcessId,"),
            1,
            "the kernel hook must forward the creator pid it was given.",
        )
        self.assertEqual(
            hook.count("OnProcessCreation(processId, 0,"),
            0,
            "the parent pid must not be hardcoded to 0 again.",
        )

    def test_precreate_captures_callback_requestor_once(self) -> None:
        body = extract_c_function(self.precreate_source, "ShadowStrikePreCreate")

        self.assertEqual(body.count("FltGetRequestorProcessIdEx(Data)"), 1)
        self.assertNotIn("RequestorPid = PsGetCurrentProcessId()", body)
        self.assertIn("if (RequestorPid != NULL)", body)
        self.assertRegex(
            body,
            r"SbBuildFileScanRequest\s*\(\s*Data,\s*FltObjects,\s*"
            r"RequestorPid,\s*ScanAccessType,",
        )

    def test_unknown_requestor_never_matches_pid_only_exclusions(self) -> None:
        body = extract_c_function(self.precreate_source, "ShadowStrikePreCreate")

        self.assertRegex(
            body,
            r"RequestorPid != NULL\s*&&\s*"
            r"ShadowStrikeIsProcessExcluded\(RequestorPid, NULL\)",
        )
        self.assertRegex(
            body,
            r"RequestorPid != NULL\s*&&\s*"
            r"ShadowStrikeIsProcessTrusted\(RequestorPid\)",
        )
        self.assertNotRegex(
            body,
            r"FltGetRequestorProcessIdEx\(Data\).*?PsGetCurrentProcessId\(\)",
        )

    def test_scanner_skips_only_recursive_user_mode_phase(self) -> None:
        body = extract_c_function(self.precreate_source, "ShadowStrikePreCreate")
        executable = strip_c_comments(body)
        identity = executable.index(
            "IsScannerRequest = ShadowStrikeIsScannerProcess(RequestorPid);"
        )
        user_gate = executable.index(
            "if (!IsScannerRequest && SHADOWSTRIKE_USER_MODE_CONNECTED())"
        )
        phase_ten = body.index("PHASE 10: APPLY VERDICT")

        # There may be no other executable use: declaration, assignment, and
        # the single negative user-mode gate are the complete contract. This
        # catches an inserted `if (IsScannerRequest) goto CleanupAllow;` even if
        # comments and phase markers remain unchanged.
        self.assertEqual(len(re.findall(r"\bIsScannerRequest\b", executable)), 3)
        self.assertRegex(executable, r"BOOLEAN\s+IsScannerRequest\s*=\s*FALSE\s*;")
        self.assertLess(identity, user_gate)
        self.assertLess(user_gate, phase_ten)
        self.assertNotRegex(
            executable,
            r"if\s*\(\s*IsScannerRequest\s*\).*?goto\s+CleanupAllow",
        )

    def test_scan_bridge_serializes_supplied_requestor(self) -> None:
        wrapper = extract_c_function(self.scan_bridge_c, "SbBuildFileScanRequest")
        extended = extract_c_function(self.scan_bridge_c, "SbBuildFileScanRequestEx")

        self.assertIn("HANDLE RequestorProcessId", self.scan_bridge_h)
        self.assertRegex(
            wrapper,
            r"SbBuildFileScanRequestEx\s*\(\s*Data,\s*FltObjects,\s*"
            r"RequestorProcessId,",
        )
        self.assertIn("HANDLE processId = RequestorProcessId;", extended)
        self.assertIn("scanRequest->ProcessId = HandleToULong(processId);", extended)
        self.assertNotIn("PsGetCurrentProcessId()", extended)
        self.assertRegex(extended, r"if\s*\(processId != NULL\)")

    def test_scan_bridge_requires_ready_primary_and_no_fallback(self) -> None:
        ready = extract_c_function(self.scan_bridge_c, "ShadowStrikeScanBridgeIsReady")
        comm_send = extract_c_function(self.comm_port_c, "ShadowStrikeSendScanRequest")

        self.assertIn("return ShadowStrikeIsPrimaryScannerConnected();", ready)
        self.assertNotIn("ShadowStrikeIsUserModeConnected", ready)
        self.assertRegex(
            comm_send,
            r"ShadowStrikeAcquirePrimaryScannerPort\s*\(\s*&clientRef,\s*FALSE\s*\)",
        )

    def test_scan_bridge_never_sends_to_the_port_itself(self) -> None:
        # This replaces an assertion that SbpSendWithRetry acquired the port with
        # AllowFallback == FALSE.
        #
        # The invariant being protected is that the verdict-blocking scan transport
        # must never route to a non-scanner client, because a non-scanner never
        # replies and FltSendMessage then blocks for the whole timeout budget on
        # every create, which froze boots. That invariant is UNCHANGED and is still
        # asserted, in the test above, against ShadowStrikeSendScanRequest - which is
        # where the scan path actually sends. ScanBridge calls it and supplies only
        # the surrounding retry loop.
        #
        # SbpSendWithRetry was the wrong function to assert it on. Measured: its only
        # callers were four fire-and-forget notification senders, so it carried no
        # scan traffic at all, despite its own comment describing it as "scan
        # transport". It also handed the caller's buffer to FltSendMessage with no
        # encryption and mapped a NULL timeout onto the 30-second SCAN timeout with
        # three retries. It is deleted.
        #
        # What is asserted instead is strictly stronger than what was removed:
        # ScanBridge cannot reach the filter port at all, so it cannot choose the
        # wrong fallback policy and cannot emit unauthenticated bytes - by
        # construction, not by inspection. CommPort is the single chokepoint and
        # every send there either encrypts or refuses.
        executable = strip_c_comments(self.scan_bridge_c)

        self.assertNotIn("FltSendMessage", executable)
        self.assertNotIn("SbpSendWithRetry", executable)
        self.assertNotIn("ShadowStrikeSendMessage", executable)
        self.assertNotIn("ShadowStrikeSendMessage", strip_c_comments(self.scan_bridge_h))

    def test_scan_bridge_notifications_use_the_encrypting_funnel(self) -> None:
        # Every notification ScanBridge emits must go through
        # ShadowStrikeSendNotification, which encrypts under the per-session key,
        # binds the header as AAD, and returns STATUS_ENCRYPTION_FAILED rather than
        # sending plaintext. All four previously used the unencrypted transport, so
        # the receiver had no way to bind these frames to the authenticated session
        # - and these are the frames that drive ProcessInjectionDetector,
        # AtomBombingDetector, RegistryProtection and RealTimeProtection.
        senders = (
            "ShadowStrikeSendProcessEvent",
            "ShadowStrikeSendThreadNotification",
            "ShadowStrikeSendImageNotification",
            "ShadowStrikeSendRegistryNotification",
        )
        for name in senders:
            body = strip_c_comments(extract_c_function(self.scan_bridge_c, name))
            with self.subTest(sender=name):
                self.assertIn("ShadowStrikeSendNotification(header, totalSize)", body)
                self.assertIn("SbpAccountNotificationResult(status,", body)

    def test_notification_accounting_separates_undelivered_from_sent(self) -> None:
        executable = strip_c_comments(
            extract_c_function(self.scan_bridge_c, "SbpAccountNotificationResult")
        )

        # STATUS_TIMEOUT must be tested BEFORE NT_SUCCESS. FltSendMessage documents
        # STATUS_TIMEOUT as a SUCCESS code meaning the message could not be
        # delivered, so NT_SUCCESS(STATUS_TIMEOUT) is true and testing NT_SUCCESS
        # first counts an undelivered notification as a delivered one.
        timeout_at = executable.index("STATUS_TIMEOUT")
        success_at = executable.index("NT_SUCCESS(Status)")
        self.assertLess(timeout_at, success_at)

        # The two counters the deleted transport was the sole writer of must still be
        # written here, or they would read zero forever whatever happened.
        self.assertIn("g_ScanBridge.Stats.ConnectionErrors", executable)
        self.assertIn("g_ScanBridge.Stats.MessageErrors", executable)

    def test_notification_funnel_does_not_count_undelivered_as_sent(self) -> None:
        body = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendNotification")
        )

        self.assertIn("(status != STATUS_TIMEOUT) && NT_SUCCESS(status)", body)
        self.assertIn("SHADOWSTRIKE_INC_STAT(MessagesDropped)", body)
        # The plaintext refusal is absolute and must stay that way.
        self.assertIn("STATUS_ENCRYPTION_FAILED", body)

    def test_no_send_path_transmits_a_payloadless_frame(self) -> None:
        # Every one of these three used to gate its encryption block on
        # `size > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)`, which meant a frame with no
        # payload skipped encryption entirely and went out in cleartext. The
        # notification funnel was actively producing them, from the ETW callback in
        # DriverEntry.c; the other two were latent, which is worse rather than
        # better, because "the callers happen to always supply a payload" is an
        # assumption about future callers and not a property of the function.
        #
        # Refused rather than authenticated because EncEncrypt rejects a zero-length
        # plaintext by documented contract (ENC_MIN_PLAINTEXT_SIZE == 1), so such a
        # frame cannot be authenticated at all without changing the primitive every
        # path shares and the user-mode receive path with it.
        notify = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendNotification")
        )
        scan = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendScanRequest")
        )
        drain = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeDrainMessageQueue")
        )

        self.assertRegex(
            notify, r"Size\s*<=\s*sizeof\(SHADOWSTRIKE_MESSAGE_HEADER\)"
        )
        self.assertRegex(
            scan, r"RequestSize\s*<=\s*sizeof\(SHADOWSTRIKE_MESSAGE_HEADER\)"
        )
        self.assertRegex(
            drain, r"sendSize\s*<=\s*sizeof\(SHADOWSTRIKE_MESSAGE_HEADER\)"
        )

        # In the funnel the refusal must precede EVERY buffering call: a frame that
        # must not be transmitted must not be buffered for later transmission
        # either, or it would be handed straight back to the path that refused it.
        #
        # This used to compare against MqEnqueueMessage directly. The enqueue now
        # sits behind ShadowStrikeBufferUndeliveredNotification, which the funnel
        # calls from three places - no client connected yet, no reader acquired, and
        # a send that did not reach a reader - so the assertion is made against the
        # FIRST of them. That is strictly stronger than the single site it replaces,
        # because it constrains all three rather than one.
        refusal_at = notify.index("Size <= sizeof(SHADOWSTRIKE_MESSAGE_HEADER)")
        self.assertEqual(
            notify.count("ShadowStrikeBufferUndeliveredNotification("),
            3,
            "the funnel must buffer at exactly three points; a new one needs review",
        )
        self.assertLess(
            refusal_at, notify.index("ShadowStrikeBufferUndeliveredNotification(")
        )

        # The enqueue must stay reachable only through that helper, so a later edit
        # cannot reintroduce a queue path that bypasses the refusal above.
        self.assertNotIn("MqEnqueueMessage", notify)

    def test_behavioural_alert_producer_carries_a_payload(self) -> None:
        # The ETW consumer callback is the ONLY producer of
        # FilterMessageType_BehavioralAlert in the driver (RegpSendBehavioralAlert is
        # misnamed and sends FilterMessageType_RegistryNotify). It used to
        # hand-assemble a bare header with DataSize = 0 and the process id stuffed
        # into MessageId, so the user-mode consumer - which parses a pid/ppid pair
        # and can block a process - was gated out by `if (data && size > 0)` and
        # never ran once.
        body = strip_c_comments(
            extract_c_function(self.driver_entry_c, "ShadowStrikeEtwEventCallback")
        )

        self.assertIn("SHADOWSTRIKE_BEHAVIORAL_ALERT", body)
        self.assertIn("ShadowStrikeBatchSendNotification", body)
        self.assertIn("alert.ProcessId", body)

        # It must not go back to hand-building a frame, and in particular must not
        # overload MessageId to carry a process id.
        self.assertNotIn("hdr.DataSize = 0", body)
        self.assertNotIn("MessageId", body)
        self.assertNotIn("ShadowStrikeSendNotification", body)

    def test_batch_flush_delivers_through_the_encrypting_funnel(self) -> None:
        # The producer above relies on this: ShadowStrikeBatchSendNotification queues
        # via BpQueueEvent, and the flush callback is what actually sends. If that
        # ever stopped using ShadowStrikeSendNotification, routing the alert through
        # the batch path would silently move it back onto an unencrypted transport.
        flush = strip_c_comments(
            extract_c_function(self.driver_entry_c, "ShadowStrikeBatchFlushCallback")
        )

        self.assertIn("ShadowStrikeSendNotification(msg, totalSize)", flush)
        self.assertIn("msg->DataSize = (UINT32)evt->DataSize;", flush)
        self.assertNotIn("FltSendMessage", flush)

    def test_per_slot_identity_replaces_scalar_and_rejects_pid_zero(self) -> None:
        scanner_check = extract_c_function(
            self.comm_port_c, "ShadowStrikeIsScannerProcess"
        )

        self.assertNotIn("g_ScannerServiceProcessId", self.comm_port_c)
        self.assertRegex(
            self.comm_port_c,
            r"g_AcceptedPrimaryScannerProcessIds\s*"
            r"\[SHADOWSTRIKE_MAX_CONNECTIONS\]",
        )
        self.assertIn("if (ProcessId == NULL)", scanner_check)
        self.assertIn("InterlockedCompareExchangePointer", scanner_check)
        self.assertIn("i < SHADOWSTRIKE_MAX_CONNECTIONS", scanner_check)

    def test_connection_publishes_only_after_kex_queue_and_ref_transfer(self) -> None:
        connect = extract_c_function(self.comm_port_c, "ShadowStrikeConnectNotify")
        reserve_pos = connect.index("heldReferenceCount = InterlockedIncrement(")
        queue_pos = connect.index("status = FltQueueGenericWorkItem(")
        queue_failure_pos = connect.index("if (!NT_SUCCESS(status))", queue_pos)
        count_pos = connect.index("g_DriverData.ConnectedClients++", queue_failure_pos)
        publish_match = re.search(
            r"InterlockedExchangePointer\s*\(\s*"
            r"&g_AcceptedPrimaryScannerProcessIds\[slotIndex\],\s*"
            r"clientProcessId\s*\)",
            connect,
        )
        self.assertIsNotNone(publish_match)
        assert publish_match is not None

        self.assertLess(reserve_pos, queue_pos)
        self.assertLess(queue_pos, queue_failure_pos)
        self.assertLess(queue_failure_pos, count_pos)
        self.assertLess(count_pos, publish_match.start())
        failure_block = connect[queue_failure_pos:count_pos]
        self.assertIn("remainingReferences = InterlockedDecrement(", failure_block)
        self.assertIn("FltFreeGenericWorkItem(kexWorkItem);", failure_block)
        self.assertIn("FltFreeGenericWorkItem(finalizationWorkItem);", failure_block)
        self.assertIn("ShadowStrikeReleaseSessionCryptoKey", failure_block)
        self.assertIn("return status;", failure_block)

    def test_kex_worker_consumes_held_generation_reference(self) -> None:
        worker = extract_c_function(self.comm_port_c, "ShadowStrikeDeliverKexWorker")

        self.assertIn("clientRef = ctx->HeldClientRef;", worker)
        self.assertIn("ctx->ConnectionGeneration", worker)
        self.assertIn("ctx->ExpectedClientPort", worker)
        self.assertNotIn("ShadowStrikeAcquireClientPortBySlot", worker)
        self.assertIn("ShadowStrikeBeginClientDisconnect(", worker)
        self.assertEqual(worker.count("ShadowStrikeReleaseClientPort(clientRef)"), 1)
        self.assertNotIn("FltCloseClientPort", worker)

    def test_generation_cookie_guards_callbacks_and_slot_acquisition(self) -> None:
        connect = extract_c_function(self.comm_port_c, "ShadowStrikeConnectNotify")
        message = extract_c_function(self.comm_port_c, "ShadowStrikeMessageNotify")
        disconnect = extract_c_function(self.comm_port_c, "ShadowStrikeDisconnectNotify")
        acquire = extract_c_function(
            self.comm_port_c, "ShadowStrikeAcquireClientPortBySlot"
        )

        self.assertIn("ULONG_PTR ConnectionGeneration;", self.comm_port_h)
        self.assertIn("ShadowStrikeEncodeConnectionCookie(", connect)
        self.assertIn("ShadowStrikeDecodeConnectionCookie(", message)
        self.assertIn("ShadowStrikeDecodeConnectionCookie(", disconnect)
        self.assertGreaterEqual(acquire.count("ConnectionGeneration"), 3)
        self.assertIn("ShadowStrikeResetClientSlotPreservingGeneration", self.comm_port_c)
        self.assertNotRegex(
            self.comm_port_c,
            r"(?:slotIndex|SlotIndex)\s*=\s*\(LONG\)\(ULONG_PTR\)"
            r"(?:ConnectionCookie|PortCookie)\s*-\s*1",
        )

    def test_disconnect_owner_retires_only_its_publications_once(self) -> None:
        begin = extract_c_function(self.comm_port_c, "ShadowStrikeBeginClientDisconnect")
        disconnect = extract_c_function(self.comm_port_c, "ShadowStrikeDisconnectNotify")

        self.assertRegex(
            begin,
            r"InterlockedCompareExchange\s*\(\s*"
            r"&clientRef->Disconnecting,\s*1,\s*0\s*\)",
        )
        self.assertEqual(begin.count("InterlockedDecrement("), 2)
        self.assertIn("ScannerPublicationsActive", begin)
        self.assertRegex(
            begin,
            r"InterlockedExchangePointer\s*\(\s*"
            r"&g_AcceptedPrimaryScannerProcessIds\[SlotIndex\],\s*NULL",
        )
        self.assertIn("ShadowStrikeBeginClientDisconnect(", disconnect)
        self.assertNotIn("InterlockedDecrement(", disconnect)

    def test_readiness_is_atomic_and_exactly_paired(self) -> None:
        worker = extract_c_function(self.comm_port_c, "ShadowStrikeDeliverKexWorker")
        begin = extract_c_function(self.comm_port_c, "ShadowStrikeBeginClientDisconnect")

        self.assertIn("volatile LONG EncryptionEstablished;", self.comm_port_h)
        self.assertNotRegex(
            self.comm_port_c,
            r"EncryptionEstablished\s*=\s*(?:TRUE|FALSE|0|1)",
        )
        self.assertRegex(
            worker,
            r"InterlockedCompareExchange\s*\(\s*"
            r"&clientRef->EncryptionEstablished,\s*1,\s*0\s*\)",
        )
        self.assertRegex(
            begin,
            r"InterlockedExchange\s*\(\s*"
            r"&clientRef->EncryptionEstablished,\s*0\s*\)",
        )
        self.assertIn("InterlockedIncrement(&g_DriverData.PrimaryScannersReady)", worker)
        self.assertIn("InterlockedDecrement(", begin)

    def test_finalization_is_single_owner_canonical_and_passive(self) -> None:
        request = extract_c_function(
            self.comm_port_c, "ShadowStrikeRequestClientFinalization"
        )
        finalize = extract_c_function(
            self.comm_port_c, "ShadowStrikeFinalizeClientDisconnect"
        )
        complete = extract_c_function(
            self.comm_port_c, "ShadowStrikeCompleteClientFinalization"
        )
        close = extract_c_function(
            self.comm_port_c, "ShadowStrikeCloseCommunicationPort"
        )
        release = extract_c_function(self.comm_port_c, "ShadowStrikeReleaseClientPort")

        self.assertEqual(self.comm_port_c.count("FltCloseClientPort("), 1)
        self.assertRegex(
            finalize,
            r"FltCloseClientPort\s*\(\s*g_DriverData\.FilterHandle,\s*"
            r"&g_ClientPortRefs\[SlotIndex\]\.ClientPort",
        )
        self.assertIn("currentIrql == PASSIVE_LEVEL", request)
        self.assertIn("ShadowStrikeClientFinalizationWorker", request)
        self.assertIn("FltQueueGenericWorkItem(", request)
        self.assertIn("ShadowStrikeRequestClientFinalization(ClientRef);", release)
        self.assertIn("ShadowStrikeResetClientSlotPreservingGeneration", complete)
        self.assertIn("KeSetEvent(", complete)
        self.assertIn("KeWaitForSingleObject(", close)
        self.assertNotRegex(close, r"waitCount\s*<\s*\d+")
        self.assertIn("_IRQL_requires_max_(APC_LEVEL)", self.comm_port_h)

    def test_primary_selection_skips_pending_lower_slot(self) -> None:
        acquire = extract_c_function(
            self.comm_port_c, "ShadowStrikeAcquirePrimaryScannerPort"
        )
        for required in (
            "IsPrimaryScanner",
            "ShadowStrikeCapScanFiles",
            "ShadowStrikeIsClientEncryptionEstablished",
            "g_ClientSessionEncKeys[i] != NULL",
            "g_AcceptedPrimaryScannerProcessIds[i]",
            "ClientProcessId",
        ):
            self.assertIn(required, acquire)

    def test_queue_drains_only_from_ready_matching_generation(self) -> None:
        connect = extract_c_function(self.comm_port_c, "ShadowStrikeConnectNotify")
        worker = extract_c_function(self.comm_port_c, "ShadowStrikeDeliverKexWorker")
        drain = extract_c_function(self.comm_port_c, "ShadowStrikeDrainMessageQueue")

        self.assertNotIn("ShadowStrikeDrainMessageQueue", connect)
        self.assertIn("ShadowStrikeDrainMessageQueue(", worker)
        self.assertIn("ctx->ConnectionGeneration", worker)
        self.assertIn("ConnectionGeneration", drain)
        self.assertIn("ShadowStrikeAcquireClientPortBySlot(", drain)
        self.assertRegex(drain, r"if\s*\(!canEncrypt\)\s*\{")

    def test_every_send_site_distinguishes_delivery_from_success(self) -> None:
        # THE STRUCTURAL GUARD, and the reason this is expressed over every call
        # site rather than over a list of function names: FltSendMessage documents
        # STATUS_TIMEOUT as "The Timeout interval expired before the message could
        # be delivered ... This is a success code". NT_SUCCESS(STATUS_TIMEOUT) is
        # therefore TRUE, so `if (NT_SUCCESS(status))` after a send does not mean
        # what it reads as, and six sites in this file got it wrong in five
        # different ways - counting undelivered as sent, publishing client
        # readiness, discarding the result entirely, writing back a reply length,
        # and rendering an explicit `else if (status == STATUS_TIMEOUT)` arm
        # unreachable.
        #
        # A new send site added later would reintroduce it, which is why the
        # assertion walks the sites instead of naming the functions.
        executable = strip_c_comments(self.comm_port_c)
        sites = [match.start() for match in re.finditer(r"FltSendMessage\s*\(", executable)]

        # Six today: queue drain, KEX delivery, scan request, notification funnel,
        # and the process notification's reply and fire-and-forget branches.
        self.assertEqual(len(sites), 6, "send-site count changed; review each one")

        for index, start in enumerate(sites):
            window = executable[start : start + 900]
            probe = re.search(r"NT_SUCCESS\s*\(\s*status\s*\)", window)
            with self.subTest(site=index):
                self.assertIsNotNone(
                    probe,
                    "a send whose status is never examined cannot report a failure",
                )
                statement = enclosing_statement(window, probe.start())
                self.assertIn(
                    "STATUS_TIMEOUT",
                    statement,
                    "delivery must be decided in the same expression that excludes "
                    "the documented not-delivered success code",
                )

    def test_kex_readiness_requires_actual_delivery(self) -> None:
        worker = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeDeliverKexWorker")
        )

        # EncryptionEstablished is not a statistic. It is a ROUTING PRECONDITION -
        # ShadowStrikeAcquirePrimaryScannerPort consults it for both primary and
        # fallback selection - and the kernel keeps its own copy of the session key
        # regardless of whether the peer received one. Publishing it for a KEX the
        # peer never collected makes the slot eligible for AES-GCM traffic it cannot
        # decrypt.
        self.assertIn("(status != STATUS_TIMEOUT) && NT_SUCCESS(status)", worker)

        gate_at = worker.index("kexDelivered")
        publish_at = worker.index("&clientRef->EncryptionEstablished")
        self.assertLess(gate_at, publish_at)

        # An undelivered KEX must take the same route as an outright send failure.
        # That response was already written and already correct; nothing about it
        # needed inventing, only reaching.
        self.assertIn("ShadowStrikeBeginClientDisconnect(", worker)
        disconnect_at = worker.index("ShadowStrikeBeginClientDisconnect(")
        self.assertLess(publish_at, disconnect_at)

    def test_queue_drain_counts_a_message_it_could_not_deliver(self) -> None:
        drain = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeDrainMessageQueue")
        )

        # The result used to be discarded with (void) while MqFreeMessage ran
        # unconditionally, so a telemetry message buffered across a reconnect window
        # was lost permanently with nothing counted - next to an encryption-failure
        # path that did count its own drop.
        self.assertNotIn("(void)FltSendMessage", drain)
        self.assertIn("status = FltSendMessage(", drain)

        send_at = drain.index("status = FltSendMessage(")
        free_at = drain.index("MqFreeMessage(", send_at)
        dropped_at = drain.index("SHADOWSTRIKE_INC_STAT(MessagesDropped)", send_at)
        self.assertLess(dropped_at, free_at)

    def test_scan_request_publishes_a_reply_length_only_when_a_reply_arrived(self) -> None:
        body = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendScanRequest")
        )

        self.assertIn("(status != STATUS_TIMEOUT) && NT_SUCCESS(status)", body)

        # *ReplySize is how the caller learns a verdict is present. Writing it back
        # on a timeout told the caller a full-length reply had arrived in a buffer
        # nobody wrote.
        gate_at = body.index("replyReceived")
        publish_at = body.index("*ReplySize = replySize;")
        self.assertLess(gate_at, publish_at)

        # With the success test no longer swallowing it, this arm is reachable and
        # ScanTimeouts can be non-zero for the first time.
        self.assertIn("SHADOWSTRIKE_INC_STAT(ScanTimeouts)", body)
        self.assertIn("RepliesReceived", body)

    def test_scan_bridge_records_a_timeout_as_a_timeout_not_a_success(self) -> None:
        body = strip_c_comments(
            extract_c_function(self.scan_bridge_c, "SbSendScanRequestEx")
        )

        self.assertIn("(status != STATUS_TIMEOUT) && NT_SUCCESS(status)", body)

        # The circuit breaker was fed the INVERSE of what happened: SbpRecordSuccess
        # zeroes ConsecutiveFailures and, half-open, closes the circuit and zeroes
        # RecentTimeouts. SbpRecordTimeout is the only writer that increments
        # RecentTimeouts and it sat in a branch that could never execute, so the
        # windowed "scanner is slow" trip - the defence against taxing every file
        # open with a full scan timeout - could not fire.
        gate_at = body.index("if (replyReceived) {")
        success_at = body.index("SbpRecordSuccess(")
        timeout_at = body.index("SbpRecordTimeout(")
        self.assertLess(gate_at, success_at)
        self.assertLess(success_at, timeout_at)

        # The dedicated verdict for this case exists and must actually be produced.
        self.assertIn("Verdict_Timeout", body)
        self.assertIn("SHADOWSTRIKE_ERROR_SCAN_TIMEOUT", body)

    def test_create_path_never_caches_an_unanswered_scan_as_clean(self) -> None:
        body = strip_c_comments(
            extract_c_function(self.precreate_source, "ShadowStrikePreCreate")
        )

        # ScanCache REFUSES to store Unknown/Error/Timeout, because caching one
        # "would let a hostile file that successfully induced one user-mode scanner
        # failure bypass scanning for the entire TTL window". That guard never saw a
        # transient verdict: on a timeout this path took the allow arm and passed a
        # HARDCODED Verdict_Clean, with ReplyMsg.CacheTTL == 0 meaning the cache's
        # 300 s default rather than the 15 s fail-open window the timeout path uses.
        self.assertIn("(Status != STATUS_TIMEOUT) && NT_SUCCESS(Status)", body)

        gate_at = body.index("ScanAnswered")
        branch_at = body.index("if (ScanAnswered) {")
        clean_at = body.index("Verdict_Clean", branch_at)
        self.assertLess(gate_at, branch_at)
        self.assertLess(branch_at, clean_at)

        # The timeout policy that could not run before: its own counter, the
        # administrator's fail-closed choice, and the deliberately short TTL.
        timeout_at = body.index("Status == STATUS_TIMEOUT", branch_at)
        self.assertLess(clean_at, timeout_at)
        for required in (
            "g_PcState.Stats.ScanTimeouts",
            "FailOpenOnTimeout",
            "PC_FAILOPEN_CACHE_TTL_SEC",
        ):
            self.assertIn(required, body)

    def test_telemetry_fallback_requires_a_declared_reader(self) -> None:
        # The fallback telemetry target must require the peer's OWN declaration that
        # it is the connection which reads kernel messages (ConnectionType == 1,
        # recorded as IsPrimaryScanner). Without that the predicate was "has a
        # session key and is not disconnecting", which describes the TRANSPORT and
        # not whether anyone calls FilterGetMessage.
        #
        # Measured consequence, which is why this is pinned: the service opens three
        # connections - liveness gate, threat-intel push, primary scanner - and only
        # the primary scanner is pumped. Slot allocation is a first-free scan from 0
        # and this loop is a first-match scan from 0, so the gate held slot 0 and was
        # always the slot the fallback chose. Capabilities cannot separate them
        # because ShadowStrikeVerifyClient keys capabilities on the PROCESS, so all
        # three carry an identical mask including ShadowStrikeCapScanFiles.
        body = strip_c_comments(
            extract_c_function(
                self.comm_port_c, "ShadowStrikeAcquirePrimaryScannerPort"
            )
        )

        gate_at = body.index("targetSlot < 0 && AllowFallback")
        fallback = body[gate_at:]

        self.assertIn("g_ClientPortRefs[i].IsPrimaryScanner", fallback)
        # The rest of the predicate must survive too, so this is not "fixed" later
        # by deleting conditions instead of adding one.
        self.assertIn("ShadowStrikeIsClientEncryptionEstablished", fallback)
        self.assertIn("g_ClientSessionEncKeys[i] != NULL", fallback)
        self.assertIn("Disconnecting == 0", fallback)

    def test_an_undelivered_notification_is_buffered_not_destroyed(self) -> None:
        # Both senders already buffered into MessageQueue when NO client was
        # connected, for the stated reason that telemetry must survive agent restart
        # windows. Neither buffered when a client WAS selected and the send then did
        # not deliver: that path incremented MessagesDropped and returned, so a
        # connected-but-unread peer lost telemetry an ABSENT peer would have kept.
        #
        # With a zero timeout STATUS_TIMEOUT is the ordinary report for "nobody was
        # waiting in FilterGetMessage", so for a non-reading peer that was the common
        # path, not a rare one.
        notify = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendNotification")
        )
        proc = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendProcessNotification")
        )

        # The notification funnel's delivery verdict must end in buffering, never in
        # a bare drop. Anchored on the LAST MessagesSent, which is the delivered arm.
        tail = notify[notify.rindex("SHADOWSTRIKE_INC_STAT(MessagesSent)") :]
        self.assertIn("ShadowStrikeBufferUndeliveredNotification(", tail)
        self.assertNotIn("SHADOWSTRIKE_INC_STAT(MessagesDropped)", tail)

        # Same for the process path's fire-and-forget branch, anchored on its zero
        # timeout. The reply branch is deliberately excluded - see the test below.
        ff_tail = proc[proc.rindex("timeout.QuadPart = 0") :]
        self.assertIn("ShadowStrikeBufferUndeliveredProcessNotification(", ff_tail)
        self.assertNotIn("SHADOWSTRIKE_INC_STAT(MessagesDropped)", ff_tail)

        # And the no-client fast paths must buffer rather than discard. This is the
        # window the queue most exists for and the one it never covered.
        for body, helper in (
            (notify, "ShadowStrikeBufferUndeliveredNotification("),
            (proc, "ShadowStrikeBufferUndeliveredProcessNotification("),
        ):
            with self.subTest(path=helper):
                at = body.index("g_DriverData.ConnectedClients == 0")
                self.assertIn(helper, body[at : at + 400])

    def test_buffering_queues_plaintext_and_only_counts_real_loss(self) -> None:
        # Queueing the ENCRYPTED buffer would be encrypted a second time by the
        # drain, and user mode would decrypt once and then parse ciphertext as a
        # structure - silently. That is the same class of failure the removed LZ4
        # path produced on this exact path, so every call site must pass the
        # caller's plaintext parameters rather than sendBuffer/sendSize.
        notify = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendNotification")
        )

        calls = list(
            re.finditer(
                r"ShadowStrikeBufferUndeliveredNotification\s*\(([^;]*?)\)\s*;",
                notify,
                re.S,
            )
        )
        self.assertEqual(len(calls), 3)
        for index, match in enumerate(calls):
            args = " ".join(match.group(1).split())
            with self.subTest(call=index):
                self.assertTrue(
                    args.startswith("Notification, Size,"),
                    f"buffered frame must be the caller's plaintext, got: {args}",
                )

        # MessagesDropped must mean "this message is gone", not "gone or deferred",
        # because it is the counter a field log is read to answer whether telemetry
        # was lost. So the helper returns on a successful enqueue BEFORE reaching it.
        helper = strip_c_comments(
            extract_c_function(
                self.comm_port_c, "ShadowStrikeBufferUndeliveredNotification"
            )
        )
        success_at = helper.index("NT_SUCCESS(mqStatus)")
        drop_at = helper.index("SHADOWSTRIKE_INC_STAT(MessagesDropped)")
        self.assertLess(success_at, drop_at)
        self.assertIn("return;", helper[success_at:drop_at])

    def test_a_reply_required_process_notification_is_never_buffered(self) -> None:
        # REGRESSION GUARD, not a discriminator: this held before the buffering work
        # and must keep holding. Its caller decides a process verdict from the reply
        # buffer, so a copy delivered later is useless to that decision and is also
        # a duplicate event. The reply branch must therefore count the timeout and
        # let the caller fail open, never defer.
        proc = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendProcessNotification")
        )

        start = proc.index("replyBufferSize = *ReplySize")
        end = proc.rindex("timeout.QuadPart = 0")
        reply_branch = proc[start:end]

        self.assertNotIn(
            "ShadowStrikeBufferUndeliveredProcessNotification(", reply_branch
        )
        self.assertIn("SHADOWSTRIKE_INC_STAT(ScanTimeouts)", reply_branch)

    def test_the_scan_path_refuses_fallback_and_never_defers(self) -> None:
        # REGRESSION GUARD for the same reason in the more dangerous direction. The
        # verdict-blocking scan transport must keep AllowFallback == FALSE, and it
        # must never gain buffering: IRP_MJ_CREATE is waiting on the answer, so a
        # queued copy delivered minutes later cannot inform it, while the create
        # would have paid the full timeout to learn nothing.
        scan = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendScanRequest")
        )

        self.assertRegex(
            scan,
            r"ShadowStrikeAcquirePrimaryScannerPort\s*\(\s*&clientRef,\s*FALSE\s*\)",
        )
        self.assertNotIn("ShadowStrikeBufferUndelivered", scan)
        self.assertNotIn("MqEnqueueMessage", scan)

    def test_the_driver_has_exactly_one_error_code_space(self) -> None:
        # ScanBridge.h used to define five error codes underneath its OWN include
        # of ErrorCodes.h. Two (PORT_NOT_CONNECTED, SCAN_TIMEOUT) sat behind
        # #ifndef guards, so the canonical values always won and those fallbacks
        # could never be produced - dead code that read like the definitions in
        # force. The other three were unconditional and live, but numbered
        # 0xE00000xx, i.e. NTSTATUS facility 0x000, while the project's space is
        # facility 0x100. SHADOWSTRIKE_IS_ERROR() tests for exactly
        # SHADOWSTRIKE_ERROR_BASE, so it answered FALSE for three of the driver's
        # own error codes.
        self.assertIn('#include "../../Shared/ErrorCodes.h"', self.scan_bridge_h)
        local_defines = re.findall(
            r"#\s*define\s+SHADOWSTRIKE_ERROR_[A-Z0-9_]+",
            strip_c_comments(self.scan_bridge_h),
        )
        self.assertEqual(
            local_defines,
            [],
            "ScanBridge.h must not define error codes; move these to ErrorCodes.h: "
            f"{local_defines}",
        )

        defines = dict(
            re.findall(
                r"#\s*define\s+(SHADOWSTRIKE_ERROR_[A-Z0-9_]+)[ \t]+([^\r\n]+)",
                strip_c_comments(self.error_codes_h),
            )
        )
        self.assertIn("SHADOWSTRIKE_ERROR_BASE", defines)

        # Every code must be expressed as BASE | <offset>. A bare hex literal is
        # exactly how the second facility appeared, so the shape is the contract,
        # not just the resulting value.
        offsets: dict[int, str] = {}
        for name, body in defines.items():
            if name in ("SHADOWSTRIKE_ERROR_BASE", "SHADOWSTRIKE_ERROR_CODES_H"):
                continue
            match = re.fullmatch(
                r"\(\s*SHADOWSTRIKE_ERROR_BASE\s*\|\s*(0x[0-9A-Fa-f]+)\s*\)",
                body.strip(),
            )
            self.assertIsNotNone(
                match, f"{name} does not derive from SHADOWSTRIKE_ERROR_BASE: {body!r}"
            )
            assert match is not None
            offset = int(match.group(1), 16)
            self.assertNotIn(
                offset,
                offsets,
                f"{name} collides with {offsets.get(offset)} at offset {offset:#05x}",
            )
            offsets[offset] = name

        # The three that moved out of ScanBridge.h must have landed here, and
        # every code ScanBridge.c names must resolve - so deleting a define
        # instead of relocating it is named by this test rather than by a build
        # error that does not explain itself.
        for relocated in (
            "SHADOWSTRIKE_ERROR_CIRCUIT_OPEN",
            "SHADOWSTRIKE_ERROR_MESSAGE_TOO_LARGE",
            "SHADOWSTRIKE_ERROR_INTEGER_OVERFLOW",
        ):
            self.assertIn(relocated, defines)

        used = set(
            re.findall(
                r"\bSHADOWSTRIKE_ERROR_[A-Z0-9_]+\b",
                strip_c_comments(self.scan_bridge_c),
            )
        )
        self.assertTrue(used)
        self.assertEqual(used - set(defines), set())

    def test_a_process_verdict_is_read_only_when_one_actually_arrived(self) -> None:
        # The reply buffer comes from ShadowStrikeAllocateMessageBuffer, which
        # serves small requests from a non-paged LOOKASIDE list and therefore
        # hands back recycled bytes verbatim. The notification buffer beside it
        # was zeroed; the reply buffer was not. And the verdict branch was gated
        # on NT_SUCCESS(Status), which the timeout handler had just made true by
        # converting STATUS_TIMEOUT to STATUS_SUCCESS to express fail-open. So an
        # unanswered request read Verdict out of a recycled block - byte 8, which
        # in the previous occupant of that block is typically the previous
        # process's verdict. Verdict_Malicious is 2, so a genuine block could
        # propagate to the next suspicious creation that timed out.
        send = strip_c_comments(
            extract_c_function(self.process_notify_c, "PnpSendProcessNotification")
        )

        # Defence in depth: the buffer must be zeroed at allocation.
        self.assertRegex(send, r"RtlZeroMemory\s*\(\s*Reply\s*,\s*ReplySize\s*\)")

        # The real fix: arrival is tracked separately from the status, and it must
        # exclude STATUS_TIMEOUT by name rather than relying on NT_SUCCESS.
        self.assertIn("BOOLEAN ReplyReceived", send)
        arrival = send[send.index("BOOLEAN ReplyReceived") :]
        arrival = arrival[: arrival.index(";")]
        for required in ("Status != STATUS_TIMEOUT", "NT_SUCCESS(Status)", "Reply != NULL"):
            self.assertIn(required, arrival)
        # A reply too short to contain the field is not a verdict either.
        self.assertIn("FIELD_OFFSET(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, Verdict)", arrival)

        # The verdict read must be reached only through that flag, and there must
        # be exactly one such read so a future edit cannot add an unguarded one.
        reads = re.findall(r"Reply->Verdict\s*==\s*Verdict_Malicious", send)
        self.assertEqual(len(reads), 1)
        self.assertRegex(
            send,
            r"if\s*\(\s*ReplyReceived\s*\)\s*\{\s*"
            r"if\s*\(\s*Reply->Verdict\s*==\s*Verdict_Malicious\s*\)",
        )
        # The old gate must be gone: NT_SUCCESS is true on timeout by the time the
        # verdict branch runs, because the handler above converts STATUS_TIMEOUT to
        # STATUS_SUCCESS to express fail-open.
        self.assertNotRegex(
            send, r"RequireReply\s*&&\s*NT_SUCCESS\s*\(\s*Status\s*\)\s*&&\s*Reply\s*!=\s*NULL"
        )

    def test_the_process_verdict_wait_is_bounded_by_its_caller(self) -> None:
        # The wait used to be g_DriverData.Config.ScanTimeoutMs: a FILE-scan
        # policy value, 30000 ms by default and accepted up to 300000 ms, applied
        # to a callback that blocks the thread calling CreateProcess. The budget
        # now comes from the caller, which is the only code that knows what its
        # own callback owes the kernel - the same shape the file create path
        # already uses with PC_SCAN_TIMEOUT_{EXECUTE,WRITE,READ}_MS.
        proc = strip_c_comments(
            extract_c_function(self.comm_port_c, "ShadowStrikeSendProcessNotification")
        )

        self.assertNotIn("Config.ScanTimeoutMs", proc)
        self.assertIn("ReplyTimeoutMs", proc)
        # A caller that states no budget is refused, not silently defaulted.
        self.assertRegex(
            proc, r"RequireReply\s*&&\s*ReplyTimeoutMs\s*==\s*0"
        )
        # The chokepoint clamps regardless of what the caller asks for, and the
        # boot-phase tightening survives.
        self.assertIn("SHADOWSTRIKE_PROCESS_REPLY_TIMEOUT_MAX_MS", proc)
        self.assertIn("ShadowFsIsBootPhase()", proc)

        ceiling = re.search(
            r"#define\s+SHADOWSTRIKE_PROCESS_REPLY_TIMEOUT_MAX_MS\s+(\d+)",
            self.comm_port_h,
        )
        self.assertIsNotNone(ceiling)
        assert ceiling is not None
        self.assertLessEqual(int(ceiling.group(1)), 1000)

        # And the caller supplies a budget sized for a process-creation callback,
        # not one borrowed from file scanning.
        budget = re.search(
            r"#define\s+PN_VERDICT_REPLY_TIMEOUT_MS\s+(\d+)", self.process_notify_c
        )
        self.assertIsNotNone(budget)
        assert budget is not None
        self.assertLessEqual(int(budget.group(1)), int(ceiling.group(1)))
        self.assertIn("PN_VERDICT_REPLY_TIMEOUT_MS", self.process_notify_c)

    def test_legacy_builder_uses_operation_requestor(self) -> None:
        legacy = extract_c_function(
            self.comm_port_c, "ShadowStrikeBuildFileScanRequest"
        )
        self.assertIn("FltGetRequestorProcessIdEx(Data)", legacy)
        self.assertIn("FltGetRequestorProcess(Data)", legacy)
        self.assertIn("PsGetThreadId(Data->Thread)", legacy)
        self.assertNotIn("PsGetCurrentProcessId()", legacy)
        self.assertNotIn("PsGetCurrentThreadId()", legacy)

    def test_the_process_fan_out_budget_stays_below_the_driver_wait(self) -> None:
        # A CROSS-LANGUAGE, CROSS-FILE INVARIANT, which is why it lives here and
        # not in the C++ suite: the user-mode fan-out budget is meaningless
        # unless it is smaller than the interval the DRIVER actually waits, and
        # no C++ unit test can see the driver's constant.
        #
        # The process feed is the only fanned-out kernel feed with a waiter.
        # ProcessNotify.c blocks the thread that called CreateProcess for
        # PN_VERDICT_REPLY_TIMEOUT_MS waiting for this verdict. If user mode
        # spends that entire interval walking its subscribers, the driver gives
        # up, fails open, and EVERY subscriber's evidence is discarded while the
        # process launches anyway - strictly worse than answering on time with
        # the evidence gathered.
        driver_wait = re.search(
            r"#define\s+PN_VERDICT_REPLY_TIMEOUT_MS\s+(\d+)", self.process_notify_c
        )
        self.assertIsNotNone(
            driver_wait,
            "PN_VERDICT_REPLY_TIMEOUT_MS is gone from ProcessNotify.c, so the "
            "user-mode fan-out budget has nothing left to be bounded by.",
        )

        fanout_budget = re.search(
            r"kProcessFanOutBudgetMs\s*=\s*(\d+)", self.ipc_manager_hpp
        )
        self.assertIsNotNone(
            fanout_budget,
            "kProcessFanOutBudgetMs is gone from IPCManager.hpp, so the process "
            "fan-out is unbounded again: a second subscriber can push a "
            "suspicious process creation past the driver's reply budget.",
        )

        driver_ms = int(driver_wait.group(1))
        budget_ms = int(fanout_budget.group(1))
        self.assertLess(
            budget_ms,
            driver_ms,
            f"Process fan-out budget {budget_ms} ms is not below the driver's "
            f"{driver_ms} ms wait. The remainder has to cover payload "
            f"validation, verdict serialisation and the ReplyMessage round "
            f"trip; an answer that arrives after the driver gave up is not an "
            f"answer.",
        )

        # AND THE BUDGET MUST ACTUALLY BE READ. This codebase has produced
        # thirteen separate controls that were declared, documented, set by a
        # caller and never consulted by the implementation - the call site looks
        # bounded while nothing enforces anything. A budget nobody reads is that
        # defect with a new name.
        self.assertIn(
            "kProcessFanOutBudgetMs",
            strip_c_comments(self.ipc_manager_cpp),
            "kProcessFanOutBudgetMs is declared but never read in "
            "IPCManager.cpp, so the process fan-out is unbounded in practice.",
        )

    def test_a_reply_bearing_process_notification_is_answered(self) -> None:
        # THE KERNEL HALF OF THIS CONTRACT IS ASSERTED ABOVE, in
        # test_a_process_verdict_is_read_only_when_one_actually_arrived. This is the
        # half that was missing entirely: the driver allocated a reply buffer, asked
        # for a verdict and waited, and nothing in user mode ever answered - so
        # process blocking at creation could never take effect, and the only visible
        # symptom was a timeout that looked like a slow scanner.
        source = strip_c_comments(self.ipc_manager_cpp)

        # Slice the ProcessNotify case from its own label to the next label.
        # Anchoring on THIS case rather than searching the whole function is the
        # point: the flag was already set three times elsewhere in that function,
        # all three inside the ScanRequest case, so a file-wide search for
        # "needsReply = true" passed while this path answered nothing.
        start = source.find("case FilterMessageType_ProcessNotify:")
        self.assertNotEqual(start, -1, "the ProcessNotify dispatch case is gone")
        nxt = source.find("case FilterMessageType_", start + 1)
        self.assertNotEqual(nxt, -1, "expected a further case label after ProcessNotify")
        process_case = source[start:nxt]

        self.assertIn(
            "needsReply = true",
            process_case,
            "the ProcessNotify case must claim a reply; without it the verdict is "
            "computed, assigned and then discarded when the switch falls through",
        )

        # The reply must be built as the PROCESS struct. The scan reply is 26 bytes
        # and ProcessNotify.c allocates 16, so sending the scan struct is refused by
        # Filter Manager and the kernel waits out its entire budget - a failure with
        # no compile error, no wrong field value and a single Debug line.
        self.assertIn("SHADOWSTRIKE_PROCESS_VERDICT_REPLY processReply", source)
        self.assertIn("ReplyToKernel(messageId, processReply)", source)

        # ...and the process struct must be confined to the ProcessNotify branch, so
        # the file-create path keeps the reply shape ITS driver buffer expects.
        branch = re.search(
            r"FilterMessageType_ProcessNotify\s*\)\s*\{(?P<body>.*?)\}\s*else\s*\{",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(
            branch, "the reply site no longer branches on the message type"
        )
        assert branch is not None
        body = branch.group("body")
        self.assertIn("SHADOWSTRIKE_PROCESS_VERDICT_REPLY", body)
        self.assertNotIn(
            "SHADOWSTRIKE_SCAN_VERDICT_REPLY",
            body,
            "the process branch must not build the scan reply - that is the exact "
            "substitution this whole contract exists to prevent",
        )

        # REGRESSION GUARD, not a discriminator, and it says so: replying without
        # consulting the WDK ReplyLength previously produced
        # STATUS_FLT_NO_WAITER_FOR_REPLY storms that pegged the CPU and starved the
        # UI pipe. Setting needsReply unconditionally for this message type is only
        # safe while this gate stands, so the two must be changed together.
        self.assertIn("pWdkHeader->ReplyLength > 0", source)
        self.assertIn("needsReply && kernelAwaitingReply", source)

    def test_an_inference_class_process_block_honours_the_protection_mode(self) -> None:
        # Wiring the reply turned "return Block" from a no-op into real enforcement,
        # and the decision it enables is the OR of five evasion detectors, any one of
        # which sets evasionDetected. The file-scan handler already gates a
        # Suspicious verdict on the configured mode; this handler did not, so a
        # MONITOR_ONLY endpoint would have had process creations blocked by a control
        # it had explicitly turned down.
        rtp = read_source(ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp")
        source = strip_c_comments(rtp)

        gate = re.search(
            r"if\s*\(\s*evasionDetected\s*\)\s*\{(?P<body>.*?)return\s+"
            r"Communication::KernelVerdict::Monitor\s*;",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(
            gate,
            "the evasion decision must be able to end in Monitor; if it can only "
            "return Block then the protection mode is being ignored again",
        )
        assert gate is not None
        body = gate.group("body")

        self.assertIn(
            "ProtectionMode::BLOCK_SUSPICIOUS",
            body,
            "an inference-class process block must consult the configured mode, the "
            "same way the file path does for a Suspicious verdict",
        )
        self.assertIn("processBlocksWithheldByMode", body)

        # The withheld case must NOT be counted as a block. Counting it would
        # recreate the defect this change removes: processesBlocked already read
        # non-zero for blocks that never happened, because the verdict was discarded.
        withheld = body[body.find("processBlocksWithheldByMode") :]
        self.assertNotIn("processesBlocked++", withheld)

        # And the detection itself is never conditional - only the enforcement is.
        self.assertIn("EmitEvasionAlert", body)

    def test_the_repository_declares_exactly_one_product_installer(self) -> None:
        # A SECOND INSTALLER DEFINITION IS NOT A TIDINESS PROBLEM, IT IS AN UPGRADE
        # HAZARD. packaging\wix\ShadowStrikePhantomHome.wxs was a complete, standalone
        # MSI definition that no build referenced, and it declared
        #   UpgradeCode="D8A6D9E2-4E2F-4A8B-9D3E-7F6B0E2C1A11"
        # while the shipping installer declares
        #   UpgradeCode="{C8F5D9A3-7E4B-4D28-9C1F-5A2E6B4D8F01}".
        # The UpgradeCode is the product's permanent identity - the dead file's own
        # README said so - so building the wrong one does NOT upgrade an installed
        # endpoint. MajorUpgrade matches on UpgradeCode, finds nothing, and installs a
        # SECOND copy alongside the first: two ServiceInstall entries, two payload
        # trees, two drivers competing for one altitude. It also declared a different
        # ServiceControl and no install anchor.
        #
        # So the invariant is not "only one file" for neatness. It is: exactly one thing
        # in this repository may claim to be the product MSI.
        wxs_files = []
        for path in ROOT.rglob("*.wxs"):
            parts = path.relative_to(ROOT).parts
            # build\ holds generated authoring (QtHarvest.wxs, emitted per build) and
            # obj\ holds NuGet/MSBuild intermediates. Neither is hand-authored.
            if parts[0] == "build" or "obj" in parts:
                continue
            wxs_files.append(path)

        self.assertTrue(
            wxs_files,
            "no hand-authored .wxs found at all - the glob or the layout changed and "
            "this test is no longer looking at anything",
        )

        stray = [
            str(p.relative_to(ROOT))
            for p in wxs_files
            if p.relative_to(ROOT).parts[:2] != ("packaging", "installer")
        ]
        self.assertEqual(
            stray,
            [],
            "hand-authored installer sources must live only in packaging\\installer, "
            "which is the set tools\\vm-harness\\Invoke-PhantomDeploy.ps1 compiles; "
            "anything else is authoring nothing builds and nobody validates",
        )

        # Exactly one <Package> may carry an UpgradeCode. Bundle.wxs legitimately has
        # its own UpgradeCode on <Bundle> - the burn bundle is a separate installable
        # identity from the MSI - so the count is scoped to Package elements.
        package_upgrade_codes = []
        service_installs = []
        for path in wxs_files:
            text = read_source(path)
            for match in re.finditer(r"<Package\b[^>]*?\bUpgradeCode=\"([^\"]+)\"", text):
                package_upgrade_codes.append((str(path.relative_to(ROOT)), match.group(1)))
            for match in re.finditer(r"<ServiceInstall\b[^>]*?\bName=\"([^\"]+)\"", text):
                service_installs.append((str(path.relative_to(ROOT)), match.group(1)))

        self.assertEqual(
            len(package_upgrade_codes),
            1,
            "exactly one <Package> may declare an UpgradeCode; more than one means two "
            "product identities and an upgrade that installs side by side instead of "
            f"replacing. Found: {package_upgrade_codes}",
        )
        self.assertEqual(
            len(service_installs),
            1,
            "exactly one ServiceInstall may exist across the installer sources; a second "
            "one registers a second service. "
            f"Found: {service_installs}",
        )

    def test_every_site_names_the_service_the_installer_actually_registers(self) -> None:
        # THE INSTALLER IS THE AUTHORITY. packaging/installer/Components.wxs carries the
        # ServiceInstall the deploy harness compiles, so whatever @Name says is the only
        # name the SCM will answer to. Every other site is a CONSUMER of that name -
        # either OpenServiceW or a ...\Services\<name> registry path - and a consumer
        # carrying a different name does not fail loudly: OpenServiceW returns
        # ERROR_SERVICE_DOES_NOT_EXIST and the caller reports "not present". That is how
        # ServiceManagerConfig::mainServiceName sat on L"ShadowStrikeAV" - a name nothing
        # has ever registered - while its watchdog, VerifyServiceIntegrity, recovery
        # configuration and IsOwnServiceKey all reported an absent service, and how
        # RollbackManager tried to stop a driver called L"ShadowStrikeSensor".
        #
        # This test exists because the name CANNOT be reduced to one shared constant
        # today: the tray's InstallProbe.cpp cannot include SelfDefense.hpp (it pulls
        # Utils/Logger.hpp, which needs C++23, and the tray project is stdcpp20 - task 96),
        # and no C++ test can read a .wxs file at all. So the invariant is asserted here
        # instead, and a rename must move every site together or fail right here.
        wxs = self.installer_components_wxs

        install = re.search(r'<ServiceInstall\b[^>]*?\bName="(?P<name>[^"]+)"', wxs)
        self.assertIsNotNone(
            install,
            "packaging/installer/Components.wxs must declare a ServiceInstall with a "
            "Name - it is the authority for the SCM service name",
        )
        assert install is not None
        authoritative = install.group("name")

        # The installer must agree with ITSELF first. ServiceControl decides what gets
        # stopped and removed, util:ServiceConfig decides recovery actions, and the two
        # RegistryValue keys write DelayedAutostart/AutoStartDelay under the service's own
        # key. A rename that misses any of them leaves the new service with no recovery
        # policy, no delayed start, and an old entry nothing removes.
        self.assertEqual(
            re.findall(r'<ServiceControl\b[^>]*?\bName="([^"]+)"', wxs),
            [authoritative],
            "ServiceControl must name the service ServiceInstall creates",
        )
        self.assertEqual(
            re.findall(r'ServiceName="([^"]+)"', wxs),
            [authoritative],
            "util:ServiceConfig must name the service ServiceInstall creates",
        )
        registry_keys = re.findall(
            r'Key="SYSTEM\\CurrentControlSet\\Services\\([^"\\]+)"', wxs
        )
        self.assertTrue(
            registry_keys,
            "the installer writes DelayedAutostart under the service key; if that "
            "lookup found nothing the key path shape changed and this test is blind",
        )
        self.assertEqual(
            set(registry_keys),
            {authoritative},
            "every ...\\Services\\<name> key the installer writes must be the service "
            "it actually creates",
        )

        # THE DEPLOY HARNESS GATES ON THIS NAME AND DIES IF IT DOES NOT MATCH.
        # Invoke-PhantomDeploy.ps1 asserts the ServiceInstall name before building the
        # MSI, so a rename that skips the harness fails the deploy rather than the field -
        # which is the right direction, but only if somebody knows to look here.
        harness = read_source(ROOT / "tools/vm-harness/Invoke-PhantomDeploy.ps1")
        self.assertIn(
            f'Name="{authoritative}"',
            harness,
            "the deploy harness asserts the ServiceInstall name; renaming the service "
            "without updating that assertion stops the deploy",
        )

        driver_match = re.search(
            r'DRIVER_SERVICE_NAME\s*=\s*L"([^"]+)"', self.self_defense_hpp
        )
        self.assertIsNotNone(
            driver_match,
            "SelfDefenseConstants::DRIVER_SERVICE_NAME is the stated single source for "
            "the driver's SCM name (it follows PhantomSensor.inf ServiceName)",
        )
        assert driver_match is not None
        driver_name = driver_match.group(1)

        # Each consumer, extracted by its own declaration rather than by substring, so a
        # failure names the exact site instead of reporting that a string is missing.
        main_name_sites = (
            ("SelfDefense.hpp SERVICE_NAME", self.self_defense_hpp,
             r'\bSERVICE_NAME\s*=\s*L"([^"]+)"'),
            ("AntivirusService.hpp SERVICE_NAME", self.antivirus_service_hpp,
             r'\bSERVICE_NAME\s*=\s*L"([^"]+)"'),
            ("ProgramUpdater.cpp kServiceName", self.program_updater_cpp,
             r'kServiceName\s*=\s*L"([^"]+)"'),
            ("InstallProbe.cpp kServiceName (tray)", self.install_probe_cpp,
             r'kServiceName\s*\[\s*\]\s*=\s*L"([^"]+)"'),
            ("ServiceManager.hpp mainServiceName", self.service_manager_hpp,
             r'mainServiceName\s*\{\s*L"([^"]+)"'),
        )
        for label, source, pattern in main_name_sites:
            found = re.search(pattern, strip_c_comments(source))
            self.assertIsNotNone(
                found, f"{label}: declaration not found - the site or its shape moved"
            )
            assert found is not None
            self.assertEqual(
                found.group(1),
                authoritative,
                f"{label} names a service the installer does not create",
            )

        driver_name_sites = (
            ("ServiceManager.hpp driverServiceName", self.service_manager_hpp,
             r'driverServiceName\s*\{\s*L"([^"]+)"'),
        )
        for label, source, pattern in driver_name_sites:
            found = re.search(pattern, strip_c_comments(source))
            self.assertIsNotNone(found, f"{label}: declaration not found")
            assert found is not None
            self.assertEqual(
                found.group(1),
                driver_name,
                f"{label} must follow DRIVER_SERVICE_NAME, which follows the INF",
            )

        # RollbackManager stops and restarts services around a file restore, so BOTH of
        # its names must be real. PhantomSensor.sys is matched by kCriticalFileExtensions,
        # and a loaded driver image cannot be overwritten, so a wrong driver name here
        # meant driver rollback could not have worked.
        array = re.search(
            r"kServiceNames\s*\[\s*\]\s*=\s*\{(?P<body>[^}]*)\}",
            strip_c_comments(self.rollback_manager_cpp),
        )
        self.assertIsNotNone(
            array, "RollbackManager must still declare kServiceNames as an array"
        )
        assert array is not None
        self.assertEqual(
            re.findall(r'L"([^"]+)"', array.group("body")),
            [authoritative, driver_name],
            "RollbackManager must stop the service and the driver the product actually "
            "registers, in that order",
        )

        # The retired names must not survive as live literals anywhere in these sources.
        # Comments quoting them are the point - they record why the name is what it is -
        # so comments are stripped before this check rather than the names being banned.
        retired = ("ShadowStrikeAV", "ShadowStrikeSensor", "ShadowStrikeDriver")
        for label, source in (
            ("SelfDefense.hpp", self.self_defense_hpp),
            ("AntivirusService.hpp", self.antivirus_service_hpp),
            ("ProgramUpdater.cpp", self.program_updater_cpp),
            ("RollbackManager.cpp", self.rollback_manager_cpp),
            ("InstallProbe.cpp", self.install_probe_cpp),
            ("ServiceManager.hpp", self.service_manager_hpp),
        ):
            stripped = strip_c_comments(source)
            for dead in retired:
                self.assertNotIn(
                    f'L"{dead}"',
                    stripped,
                    f"{label} still uses the retired service name {dead}, which "
                    f"nothing registers",
                )

    def test_a_kernel_reply_is_plaintext_and_bounded_by_the_kernel_buffer(self) -> None:
        """A reply must be a bare, plaintext, fixed-size verdict struct.

        THE RETIRED DEFECT. FilterConnection::ReplyMessage gated encryption on
        `replyBuffer.size() > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)` - an expression
        copied from the SEND paths, where the buffer really is a framed
        [header][payload] message and "> 40" correctly means "there is a payload".
        On the reply path the buffer is a BARE STRUCT, so the comparison tested a
        payload length against the size of a header the reply does not contain. It
        never fired only because both reply structs are under 40 bytes, which made
        the plaintext reply path a coincidence rather than a rule.

        Two facts make an encrypted or oversized reply unusable, and they live on
        opposite sides of the boundary, which is why this test is here:
          - the driver performs NO decryption on the reply path (the sole
            EncDecrypt in CommPort.c is the user->kernel MESSAGE path), so
            ciphertext would be parsed as the verdict struct itself, reading
            Verdict out of an ENC_HEADER byte; and
          - every driver reply buffer is a stack struct sized EXACTLY
            sizeof(struct), so anything longer is refused by Filter Manager, after
            which the kernel waits out its budget and fails open with one Debug
            line as the only evidence.
        """
        source = self.filter_connection_cpp

        marker = "bool ReplyMessage(std::span<const uint8_t> replyBuffer,"
        following = "size_t SendMessage(std::span<const uint8_t> sendBuffer,"
        self.assertEqual(
            source.count(marker), 1, "expected exactly one ReplyMessage body to slice"
        )
        self.assertEqual(
            source.count(following), 1, "the slice end anchor must be unambiguous"
        )

        start = source.index(marker)
        body = source[start : source.index(following, start)]
        stripped = strip_c_comments(body)

        # 1. The reply path cannot encrypt. Asserted on COMMENT-STRIPPED source: the
        #    explanatory comment above the fix necessarily names both the retired
        #    expression and the function it came from, and a comment-blind assertion
        #    would be satisfied - or broken - by prose rather than by code.
        #
        #    Reported per LINE rather than with assertNotIn, which prints the entire
        #    function body on failure and buries the one line that matters.
        for forbidden, why in (
            (
                "EncryptSendMessage",
                "ReplyMessage must not encrypt - the driver never decrypts a reply, "
                "so ciphertext here would be parsed as the verdict struct itself",
            ),
            (
                "sizeof(SHADOWSTRIKE_MESSAGE_HEADER)",
                "the retired frame-header comparison must not survive in live code",
            ),
        ):
            offenders = [
                line.strip() for line in stripped.splitlines() if forbidden in line
            ]
            self.assertEqual([], offenders, f"{why}; offending line(s): {offenders}")

        # 2. It refuses what the kernel cannot receive, and refuses it by returning
        #    false rather than truncating it or sending it anyway.
        self.assertIn("SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE", stripped)
        self.assertRegex(
            stripped,
            r"if\s*\(\s*replyBuffer\.size\(\)\s*>\s*"
            r"SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE\s*\)\s*\{",
        )
        refusal = stripped[stripped.index("SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE") :]
        self.assertIn("return false;", refusal)

        # 3. REGRESSION GUARD, deliberately not a discriminator: the SEND paths must
        #    still encrypt. Removing encryption from the reply carrier must never be
        #    mistaken for permission to remove it from the transport.
        self.assertEqual(
            source.count("EncryptSendMessage(sendBuffer, encryptedBuf)"),
            2,
            "both send paths must continue to encrypt",
        )

        # 4. The driver half of the same contract: exactly one decrypt site, and it
        #    is the message path. A second one means the reply path may now decrypt,
        #    in which case the refusal above has to be revisited in that change.
        self.assertEqual(
            self.comm_port_c.count("EncDecrypt("),
            1,
            "CommPort.c must have exactly one decrypt site (the message path)",
        )

        # 5. Every reply buffer is exactly sizeof(struct). This is what makes the
        #    bound the real ceiling rather than a chosen number.
        self.assertIn(
            "ULONG ReplySize = sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY);",
            self.precreate_source,
        )
        self.assertIn("replySize = sizeof(reply);", self.scan_bridge_c)
        self.assertIn(
            "SIZE_T ReplySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY);",
            self.process_notify_c,
        )

        # 6. The bound is DERIVED from both reply structs, so growing either moves it
        #    automatically; the pinned literal is the review prompt that forces the
        #    same change to visit the user-mode sender and these tests.
        protocol = self.message_protocol_h
        self.assertIn("#define SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE", protocol)
        for struct_name in (
            "SHADOWSTRIKE_SCAN_VERDICT_REPLY",
            "SHADOWSTRIKE_PROCESS_VERDICT_REPLY",
        ):
            self.assertRegex(
                protocol,
                r"C_ASSERT\(\s*sizeof\("
                + struct_name
                + r"\)\s*<=\s*SHADOWSTRIKE_MAX_KERNEL_REPLY_SIZE\s*\);",
                f"{struct_name} must be pinned against the reply-carrier bound",
            )
        self.assertRegex(
            protocol,
            r"C_ASSERT\(\s*FIELD_OFFSET\(SHADOWSTRIKE_SCAN_VERDICT_REPLY,\s*"
            r"Verdict\)\s*==\s*8\s*\);",
        )
        self.assertRegex(
            protocol, r"C_ASSERT\(\s*sizeof\(SHADOWSTRIKE_SCAN_VERDICT_REPLY\)\s*==\s*26\s*\);"
        )


    def test_the_kernel_registry_feed_does_not_block_on_a_name_lookup(self):
        """The kernel registry feed is delivered on IPCManager's worker thread -
        the one it names SS-KernelScanReply - which answers the kernel's scan
        requests while the minifilter holds the originating file operation open.

        Two rules apply to that path. It may make no call that leaves this
        machine, and anything it does is paid by every registry operation on the
        system. Enrichment there previously performed four process-opening
        queries per event, one of which resolved an account name through
        LookupAccountSidW.

        Comments are stripped FIRST. The explanatory comments now in the handler
        necessarily NAME the calls that were removed, so a comment-blind
        assertion would be satisfied - or broken - by prose rather than by code.
        """
        src = self.registry_monitor_cpp

        start_anchor = "SHADOWSTRIKE_SCAN_VERDICT OnKernelRegistryNotification("
        end_anchor = "RegistryVerdict ApplyRulesSnapshot("
        self.assertEqual(
            src.count(start_anchor), 1,
            "expected exactly one kernel registry handler to slice on",
        )
        self.assertEqual(
            src.count(end_anchor), 1,
            "the slice end anchor is no longer unique; re-pick it",
        )
        start = src.index(start_anchor)
        end = src.index(end_anchor)
        self.assertLess(start, end, "slice anchors are in the wrong order")

        body = strip_c_comments(src[start:end])

        banned = (
            (
                "GetProcessSecurityInfo",
                "opens the process token and, at Full scope, resolves an account "
                "name via LookupAccountSidW - an LSASS RPC that becomes a domain "
                "controller round trip for a domain SID",
            ),
            (
                "GetProcessBasicInfo",
                "opens the process with PROCESS_VM_READ and resolves the image "
                "path and process times merely to obtain a session id",
            ),
            (
                "GetProcessName",
                "is GetProcessPath plus a basename, so calling it resolves the "
                "full image path a second time for one string",
            ),
        )
        for symbol, why in banned:
            offenders = [ln.strip() for ln in body.splitlines() if symbol in ln]
            self.assertEqual(
                offenders, [],
                "%s is called on the kernel registry feed path; it %s"
                % (symbol, why),
            )

        # Exactly one image-path resolution. That is the single fact with a
        # genuine per-event consumer: RegistryRule::processPathPattern matches on
        # it, and StartupAnalyzer's subscriber forwards it for every
        # persistence-key write. More than one means the duplicate resolution is
        # back; zero means a rule that filters on process path silently stopped
        # matching, which would be a coverage loss.
        self.assertEqual(
            body.count("GetProcessPath"), 1,
            "the feed path must resolve the process image path exactly once",
        )

    def test_the_account_name_lookup_is_reachable_only_by_explicit_opt_in(self):
        """LookupAccountSidW is the only call in GetProcessSecurityInfo that can
        leave this machine. It must stay behind an explicit scope so a caller
        that owes the kernel an answer cannot reach it by accident, and the two
        projections that never return a name must opt out of it.
        """
        src = strip_c_comments(self.process_utils_cpp)

        sites = [ln.strip() for ln in src.splitlines() if "LookupAccountSidW" in ln]
        self.assertEqual(
            len(sites), 1,
            "expected exactly one account-name lookup site, found: %r" % (sites,),
        )

        # Offsets only, never the haystack: an assertIn against a 5,000-line file
        # prints the entire file on failure and buries the finding.
        gate = "if (scope == SecurityInfoScope::Full)"
        gate_count = src.count(gate)
        self.assertEqual(
            gate_count, 1,
            "expected exactly one Full-scope gate around the account-name lookup, "
            "found %d" % gate_count,
        )
        call_at = src.index("LookupAccountSidW")
        gate_at = src.rfind(gate, 0, call_at)
        self.assertNotEqual(
            gate_at, -1,
            "the account-name lookup at offset %d is not preceded by the Full-scope "
            "gate, so it would run for every caller including those that owe the "
            "kernel an answer" % call_at,
        )
        # Nothing may reopen the guard between the gate and the call.
        between = src[gate_at:call_at]
        reopened = [ln.strip() for ln in between.splitlines()
                    if "SecurityInfoScope::LocalOnly" in ln]
        self.assertEqual(
            reopened, [],
            "the scope is reassigned between the gate and the lookup: %r" % (reopened,),
        )

        # Both projections return a single local fact and must say so. Sliced
        # from the signature to the first closing brace at column zero.
        for fn in ("IsProcessElevated", "GetProcessSID"):
            sig = src.index("%s(ProcessId pid, Error* err) noexcept {" % fn)
            fn_end = src.index("\n}", sig)
            fn_body = src[sig:fn_end]
            self.assertIn(
                "SecurityInfoScope::LocalOnly", fn_body,
                "%s does not restrict its query, so it pays for an account name "
                "it never returns" % fn,
            )


    def test_a_suspend_verdict_is_never_carried_out_as_a_termination(self):
        """A deliberately reversible action must not execute as an irreversible one.

        PerformAction routed RecommendedAction::Suspend to the SAME callback it
        used for Terminate, and that callback received only (pid, reason), so a
        responder could not tell the two apart. Any responder that terminated
        would therefore have killed a process the verdict only asked to suspend,
        and the only available signal was a human-readable prefix inside a log
        string. This pins the action into the signature and pins the statistic.
        """
        src = self.behavior_analyzer_cpp

        start_anchor = (
            "void BehaviorAnalyzer::PerformAction(const BehaviorVerdict& verdict) {"
        )
        self.assertEqual(
            src.count(start_anchor),
            1,
            "PerformAction anchor is not unique, so the slice below would be "
            "measuring the wrong region",
        )
        start = src.index(start_anchor)
        end = src.index("\nvoid BehaviorAnalyzer::", start + len(start_anchor))
        # Strip comments: the explanatory comments in this function necessarily
        # name Suspend and Terminate, so a comment-blind assertion would be
        # satisfied by prose instead of by code.
        body = strip_c_comments(src[start:end])

        self.assertEqual(
            body.count("responder(verdict.processId, verdict.action, verdict.description)"),
            1,
            "PerformAction must hand the decided action to the responder, "
            "otherwise the responder cannot honour it",
        )

        self.assertEqual(
            body.count("terminateCb(verdict.processId, verdict.description)"),
            0,
            "the retired two-argument invocation is back, so Suspend and "
            "Terminate are indistinguishable to a responder again",
        )

        suspend_guard = "verdict.action != RecommendedAction::Suspend"
        self.assertEqual(
            body.count(suspend_guard),
            1,
            "the processesTerminated increment must be guarded by an explicit "
            "Suspend exclusion",
        )
        self.assertEqual(
            body.count("processesTerminated.fetch_add"),
            1,
            "expected exactly one processesTerminated increment in PerformAction",
        )
        self.assertLess(
            body.index(suspend_guard),
            body.index("processesTerminated.fetch_add"),
            "the Suspend exclusion must precede the processesTerminated "
            "increment, or a suspended process is reported as terminated",
        )

        # A response that did not happen must be counted, not dropped in silence.
        self.assertGreaterEqual(
            body.count("responseActionsNotCarriedOut.fetch_add"),
            2,
            "both the no-responder case and the responder-declined case must be "
            "counted; before this they were a log line and total silence",
        )

    def test_a_behavioural_response_is_gated_before_it_can_destroy_anything(self):
        """Every guard must sit BEFORE the call that ends a process.

        A guard placed after the destructive call is not a guard. No behavioural
        termination has ever taken effect in this product, so there is no field
        data on how often these verdicts fire on legitimate software; the
        responder is therefore gated on the protection mode, refuses our own
        binaries, and refuses a Microsoft-signed or not-yet-determined image
        because the evidence is inference-class.
        """
        src = self.real_time_protection_cpp

        start_anchor = "ba.SetTerminationCallback("
        self.assertEqual(
            src.count(start_anchor),
            1,
            "expected exactly one behavioural responder registration",
        )
        start = src.index(start_anchor)
        end_anchor = "// Wire BA into ThreatDetector"
        self.assertEqual(
            src.count(end_anchor), 1, "responder slice end anchor is not unique"
        )
        end = src.index(end_anchor, start)
        self.assertGreater(end, start, "responder slice is inverted")
        body = strip_c_comments(src[start:end])

        first_kill = body.find("ProcessUtils::TerminateProcess(")
        self.assertNotEqual(
            first_kill,
            -1,
            "the responder must actually be able to terminate, otherwise the "
            "engine's response half is still inert",
        )

        # Each guard, and the offset it must precede.
        for label, needle in (
            ("own-process refusal", "::GetCurrentProcessId()"),
            ("own-install-directory refusal", "GetModuleFileNameW"),
            ("protection-mode gate", "ProtectionMode::BLOCK_SUSPICIOUS"),
            ("Microsoft-signed check", "TryGetCachedMicrosoftSigned"),
            ("undetermined-signature withhold", "msTrust.has_value()"),
        ):
            at = body.find(needle)
            self.assertNotEqual(
                at, -1, "the responder is missing its {0}".format(label)
            )
            self.assertLess(
                at,
                first_kill,
                "the {0} appears at offset {1}, after the termination call at "
                "offset {2} - a guard after the destructive step is not a "
                "guard".format(label, at, first_kill),
            )

        # Suspend must be handled by suspending, on its own explicit branch,
        # and that branch must be reached before the termination path.
        suspend_gate = body.find("RecommendedAction::Suspend")
        suspend_call = body.find("SuspendProcess(")
        self.assertNotEqual(
            suspend_call,
            -1,
            "the responder must honour a Suspend by suspending; routing it to "
            "the termination path is what this change exists to prevent",
        )
        self.assertNotEqual(suspend_gate, -1, "no explicit Suspend test found")
        self.assertLess(
            suspend_gate,
            suspend_call,
            "SuspendProcess must be reachable only under an explicit Suspend test",
        )
        self.assertLess(
            suspend_call,
            first_kill,
            "the Suspend branch must precede and return before the termination "
            "path, or a suspend falls through into a kill",
        )

    def test_user_mode_does_not_redeclare_a_kernel_notification_layout(self) -> None:
        """Communication.hpp must not hold a second, untied declaration of a kernel
        wire struct.

        Three of the five wire structs it declared had drifted into layouts the
        driver has never emitted, and nothing could detect that because the header
        included nothing from the kernel. ProcessNotificationData (48B vs a real
        21B payload behind a 40B dead header) and RegistryNotificationData (40B vs
        21B) both rejected every genuine frame on their minimum-size check;
        PolicyUpdateData (48B vs 44B) disagreed on six fields in each direction.
        RegistryMonitor shipped a parser built on the registry one and processed no
        registry event at all until 5fe45d55.
        """
        code = strip_c_comments(self.communication_hpp)

        # Count the include DIRECTIVE, not the bare path: the static_assert failure
        # messages below deliberately name the header too, so a bare-path count is 3.
        self.assertEqual(
            code.count('#include "../../../PhantomSensor/Shared/MessageProtocol.h"'), 1,
            "Communication.hpp must include the kernel wire header exactly once; "
            "without it there is no compile-time relationship between the structs "
            "declared here and the layouts the driver writes",
        )

        # Comments in this header necessarily NAME the removed structs to explain
        # why they were removed, so the check must run on comment-stripped code.
        for fabricated in (
            "ProcessNotificationData",
            "RegistryNotificationData",
            "PolicyUpdateData",
        ):
            self.assertEqual(
                code.count(fabricated), 0,
                f"{fabricated} declared a layout the driver never emitted; "
                f"re-declaring it here reintroduces the defect class that left "
                f"RegistryMonitor unable to read a single registry event",
            )

        # Every surviving mirror of a kernel struct must be pinned to it.
        for user_mode, kernel in (
            ("FileScanRequestData", "FILE_SCAN_REQUEST"),
            ("ScanVerdictReplyData", "SHADOWSTRIKE_SCAN_VERDICT_REPLY"),
        ):
            needle = f"sizeof({user_mode}) == sizeof({kernel})"
            self.assertEqual(
                code.count(needle), 1,
                f"{user_mode} mirrors {kernel} and must static_assert that it stays "
                f"byte-identical to it; expected exactly one '{needle}'",
            )

    def test_the_notification_parsers_read_the_kernel_structs_with_byte_lengths(self) -> None:
        """The two notification parsers must read the kernel structs, and must treat
        the variable-length fields as BYTE counts.

        SHADOWSTRIKE_PROCESS_NOTIFICATION::ImagePathLength and
        SHADOWSTRIKE_REGISTRY_NOTIFICATION::KeyPathLength are byte counts - the
        driver RtlCopyMemory's exactly that many bytes (ProcessNotify.c:3798,
        ScanBridge.c:1491, ScanBridge.c:1952). Multiplying one by sizeof(wchar_t),
        which is what the previous parsers did, walks twice as far as the payload
        extends.
        """
        src = self.message_dispatcher_cpp

        anchors = (
            "static std::optional<ProcessNotification> ParseProcessNotification(",
            "static std::optional<RegistryNotification> ParseRegistryNotification(",
            "static std::vector<uint8_t> SerializeVerdictReply(",
        )
        for anchor in anchors:
            self.assertEqual(
                src.count(anchor), 1,
                f"slice anchor must occur exactly once: {anchor!r}",
            )

        process_body = strip_c_comments(
            src[src.index(anchors[0]):src.index(anchors[1])])
        registry_body = strip_c_comments(
            src[src.index(anchors[1]):src.index(anchors[2])])

        for name, body, kernel_struct, length_fields in (
            ("ParseProcessNotification", process_body,
             "SHADOWSTRIKE_PROCESS_NOTIFICATION",
             ("ImagePathLength", "CommandLineLength")),
            ("ParseRegistryNotification", registry_body,
             "SHADOWSTRIKE_REGISTRY_NOTIFICATION",
             ("KeyPathLength", "ValueNameLength")),
        ):
            self.assertGreaterEqual(
                body.count(kernel_struct), 1,
                f"{name} must parse {kernel_struct} - the layout the driver writes - "
                f"not a user-mode re-declaration of it",
            )

            # A byte count multiplied by sizeof(wchar_t) is the over-read. Report the
            # offending lines only, never the whole body.
            offenders = [
                line.strip()
                for line in body.splitlines()
                for field in length_fields
                if field in line and "sizeof(wchar_t)" in line and "*" in line
            ]
            self.assertEqual(
                offenders, [],
                f"{name} multiplies a BYTE count by sizeof(wchar_t), which reads past "
                f"the payload; it must divide instead",
            )

            self.assertGreaterEqual(
                body.count("/ sizeof(wchar_t)"), 1,
                f"{name} must convert byte counts to character counts by dividing",
            )

            # The bound has to be taken against what was delivered, not against a
            # length the sender declared.
            self.assertGreaterEqual(
                body.count("data.size()"), 2,
                f"{name} must bound the variable region against the delivered payload "
                f"size, both for the fixed part and for the variable part",
            )


    # ------------------------------------------------------------------
    # The fuzz target is built by nothing on a normal day, so anything that
    # rots in its project file stays invisible until somebody builds it. It
    # went four months and eighteen unresolved externals before anyone did.
    # These two pin the invariants that CANNOT be recovered from a link
    # error, because they fail as missing capability rather than as a
    # missing symbol.
    # ------------------------------------------------------------------

    def _fuzzer_listed_name(self, path: Path) -> str:
        """The spelling Fuzzer.vcxproj uses for a repo-relative source."""
        return "..\\" + str(path.relative_to(ROOT)).replace("/", "\\")

    def _product_sources_mentioning(self, macro: str) -> list[Path]:
        found = [
            candidate
            for candidate in sorted((ROOT / "src").rglob("*.cpp"))
            if macro in read_source(candidate)
        ]
        # A guard that silently stops guarding is worse than no guard: if the
        # walk ever stops finding anything, say so instead of passing.
        self.assertNotEqual(
            found, [],
            f"no product source mentions {macro}; this test has stopped "
            f"checking anything and must be repaired or removed",
        )
        return found

    def test_every_fuzzing_only_product_hook_is_compiled_by_the_fuzzer(self):
        project = self.fuzzer_vcxproj

        self.assertIn(
            "SHADOWSTRIKE_FUZZING=1", project,
            "Fuzzer.vcxproj must define SHADOWSTRIKE_FUZZING or every "
            "fuzzing-only hook in the product compiles away",
        )

        # A hook guarded by SHADOWSTRIKE_FUZZING only exists in the binary if
        # the file declaring it is compiled BY THIS PROJECT. Today that is
        # NetworkTrafficFilter::ResetFuzzingState, which TrafficHarness.cpp
        # calls to isolate one iteration from the next. Add the guard to a
        # file the project does not list and the hook silently is not there.
        missing = [
            str(source.relative_to(ROOT))
            for source in self._product_sources_mentioning("SHADOWSTRIKE_FUZZING")
            if self._fuzzer_listed_name(source) not in project
        ]

        self.assertEqual(
            missing, [],
            "these product sources are compiled conditionally on "
            "SHADOWSTRIKE_FUZZING but are not listed in Fuzzer.vcxproj, so "
            "whatever they define under that macro does not exist in the "
            "fuzzer binary: " + ", ".join(missing),
        )

    def test_the_focused_build_macro_is_applied_to_every_listed_file_that_tests_it(self):
        project = self.fuzzer_vcxproj
        macro = "SHADOWSTRIKE_RTP_FOCUSED_BUILD"

        def element_for(listed: str) -> Optional[str]:
            marker = f'<ClCompile Include="{listed}"'
            start = project.find(marker)
            if start < 0:
                return None
            tail = project[start:]
            self_closing = tail.find("/>")
            closing = tail.find("</ClCompile>")
            if closing < 0 or (0 <= self_closing < closing):
                return tail[: self_closing + 2]
            return tail[: closing + len("</ClCompile>")]

        # This macro selects a REDUCED view of the product. It is applied
        # per file, not project wide, so two translation units in one binary
        # can disagree about what the same class provides. Three product
        # sources test it; the project lists one and gives it the macro.
        # Adding a second WITHOUT the macro compiles the full branch beside
        # the reduced one - the divergent-view defect that produced the ODR
        # heap corruption in the test suite, and it would not show up as a
        # link error.
        covered = 0
        offenders = []
        for source in self._product_sources_mentioning(macro):
            listed = self._fuzzer_listed_name(source)
            element = element_for(listed)
            if element is None:
                continue  # not compiled here, so it cannot diverge
            covered += 1
            if macro not in element:
                offenders.append(str(source.relative_to(ROOT)))

        self.assertEqual(
            offenders, [],
            "Fuzzer.vcxproj compiles these sources without "
            f"{macro} while they test it, so this binary would hold both the "
            "reduced and the full view of the same product: "
            + ", ".join(offenders),
        )

        self.assertGreaterEqual(
            covered, 1,
            f"no file testing {macro} is compiled by the fuzzer any more; if "
            "that is deliberate the per-file macro should be removed from "
            "the project as well, so the two cannot drift apart",
        )


    def test_every_file_scan_builder_declares_a_byte_length(self) -> None:
        """Every kernel builder of the file-scan layout must declare BYTE lengths.

        THREE builders fill FILE_SCAN_REQUEST and they did not agree.
        SbBuildFileScanRequestEx (ScanBridge.c) wrote UNICODE_STRING::Length, i.e.
        bytes, on the IRP_MJ_CREATE path. ShadowStrikeBuildFileScanRequest
        (CommPort.c, every rename and delete) and ShadowStrikeQueueRescan
        (FilterRegistration.c, cleanup rescan of modified files) divided by
        sizeof(WCHAR) and wrote characters. All three stamp
        FilterMessageType_ScanRequest and all three route to the primary scanner
        connection, so all three arrive at ONE reader - OnKernelFileScan - which
        divides by sizeof(wchar_t). The create path agreed with it; the other two
        delivered a path the service truncated to half its length.

        That failure mode is why this is a contract test rather than a unit test:
        a halved path raises nothing. It is simply a path that cannot be opened,
        and an unopenable path is an unexamined file.
        """
        builders = {
            "ScanBridge.c": self.scan_bridge_c,
            "CommPort.c": self.comm_port_c,
            "FilterRegistration.c": self.filter_registration_c,
        }

        assignment = re.compile(r"\b(?:PathLength|ProcessNameLength)\s*=")
        offenders: list[str] = []
        sites = 0

        for name, raw in builders.items():
            # COMMENTS STRIPPED FIRST. The explanatory comments added with this
            # change necessarily quote "sizeof(WCHAR)" while describing the
            # division that was removed, so a comment-blind scan would report
            # this file's own documentation as the defect.
            for line in strip_c_comments(raw).splitlines():
                if not assignment.search(line):
                    continue
                # ImagePathLength / KeyPathLength belong to the image-load and
                # registry notifications, which were already byte counts.
                if "ImagePathLength" in line or "KeyPathLength" in line:
                    continue
                sites += 1
                if "sizeof(WCHAR)" in line and "/" in line:
                    offenders.append(f"{name}: {line.strip()}")

        self.assertGreaterEqual(
            sites,
            3,
            "fewer than three file-scan length assignments were found across the "
            "three builders, so this test has stopped inspecting what it exists "
            "to inspect",
        )
        self.assertEqual(
            [],
            offenders,
            "a file-scan builder divides a length by sizeof(WCHAR), i.e. declares "
            "CHARACTERS where every reader expects BYTES:\n  " + "\n  ".join(offenders),
        )

        # The exact surviving expressions, so a revert fails here by name rather
        # than by absence of a pattern. Counted, not assertIn: these haystacks are
        # whole driver sources and assertIn would print them.
        for label, source, expected in (
            ("ScanBridge.c", self.scan_bridge_c,
             "scanRequest->PathLength = (UINT16)filePathLen;"),
            ("CommPort.c", self.comm_port_c,
             "scanRequest->PathLength = (UINT16)nameInfo->Name.Length;"),
            ("FilterRegistration.c", self.filter_registration_c,
             "req->PathLength = copyLen;"),
        ):
            found = strip_c_comments(source).count(expected)
            self.assertEqual(
                found,
                1,
                f"{label} no longer contains the byte-count assignment "
                f"{expected!r} (found {found} occurrences)",
            )

        # The frame-size macro was the third statement of the character contract:
        # it multiplied both arguments by sizeof(WCHAR) while its one caller
        # divided a byte count to compensate.
        defs = self.shared_defs_h
        macro_start = defs.index("#define SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE")
        macro_end = defs.index("#define SHADOWSTRIKE_VALID_MESSAGE_HEADER")
        macro_body = defs[macro_start:macro_end]
        self.assertNotIn(
            "sizeof(WCHAR)",
            macro_body,
            "SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE multiplies by sizeof(WCHAR) again; "
            "its arguments are byte counts taken straight from the wire fields",
        )

        # And the two declarations of the layout are tied together at compile
        # time, which is what makes the duplication safe rather than documented.
        tie = "C_ASSERT(sizeof(FILE_SCAN_REQUEST) == sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST));"
        self.assertEqual(
            self.message_protocol_h.count(tie),
            1,
            "nothing ties FILE_SCAN_REQUEST to its duplicate "
            "SHADOWSTRIKE_FILE_SCAN_REQUEST, so the two can drift into different "
            "wire formats under two names with no build failure anywhere",
        )

    def test_the_scan_request_case_bounds_its_variable_lengths(self) -> None:
        """The scan-request dispatcher must bound its tail and answer every exit.

        Two defects, both in the one switch case the kernel blocks a file
        operation on:

        (1) NO BOUND. The case checked that the FIXED part of the payload fits and
            then handed it to a consumer that builds a wstring of
            PathLength / sizeof(wchar_t) characters from the bytes after the
            struct. PathLength is a uint16, so an over-claiming frame read up to
            ~64 KB past the delivered data, out of a buffer IPCManager documents
            as pooled and NOT zeroed. The three sibling cases in the same switch
            (ProcessNotify, ImageLoad, RegistryNotify) each bound their lengths.

        (2) A NON-DECISION WAS CACHED AS CLEAN. The readiness gate replied
            Verdict_Clean. ScanCache.c refuses to cache transient verdicts and
            says why, but Clean is not transient, so the driver cached it for the
            default 300 seconds - every file touched during warm-up recorded
            clean WITHOUT HAVING BEEN SCANNED. Verdict_Error fails open just the
            same (only Verdict_Malicious blocks) and is refused by the cache.
        """
        src = self.ipc_manager_cpp
        open_anchor = "case FilterMessageType_ScanRequest: {"
        close_anchor = "case FilterMessageType_ProcessNotify: {"

        self.assertEqual(
            src.count(open_anchor), 1, "scan-request case anchor is not unique"
        )
        self.assertEqual(
            src.count(close_anchor), 1, "process-notify case anchor is not unique"
        )

        body = strip_c_comments(src[src.index(open_anchor) : src.index(close_anchor)])
        self.assertGreater(len(body), 200, "sliced scan-request case is implausibly short")

        for needle in (
            "req->PathLength > remaining",
            "req->ProcessNameLength > (remaining - req->PathLength)",
        ):
            # COUNT, never assertIn. assertIn prints the entire haystack on
            # failure, and the haystack here is a whole switch case - so the one
            # line that matters arrives buried under eighty that do not. This is
            # the fourth time that has cost a debugging cycle in this suite.
            self.assertEqual(
                body.count(needle),
                1,
                f"the scan-request case does not bound its variable-length tail: "
                f"expected exactly one occurrence of {needle!r}, found "
                f"{body.count(needle)}. Without it a declared length may exceed "
                f"the delivered payload and the consumer reads past the frame.",
            )

        # The subtraction form matters: summing two uint16 lengths and comparing
        # the total is the version that can wrap.
        self.assertEqual(
            body.count("req->PathLength + req->ProcessNameLength"),
            0,
            "the bound sums the two lengths instead of subtracting from what "
            "remains, which is the form that can wrap",
        )

        clean_replies = body.count("Verdict_Clean")
        self.assertEqual(
            clean_replies,
            0,
            f"the scan-request case replies Verdict_Clean in {clean_replies} place(s). "
            "Clean is not a transient verdict, so ScanCache stores it for the "
            "default 300 s TTL and a file that was never scanned is remembered as "
            "clean. Verdict_Error fails open identically and is refused by the cache.",
        )

        # Every exit that the kernel is waiting on must answer it. Ready gate,
        # truncated payload, over-claimed length, success and the catch block.
        self.assertGreaterEqual(
            body.count("needsReply = true;"),
            5,
            "a refusal path in the scan-request case returns without replying; the "
            "kernel then waits out its full budget for a verdict that never comes",
        )
        self.assertGreaterEqual(
            body.count("Verdict_Error"),
            4,
            "the refusal paths do not all report a non-decision as Verdict_Error",
        )


@dataclass(frozen=True)
class Cookie:
    index: int
    generation: int


@dataclass
class Slot:
    generation: int = 0
    pid: Optional[int] = None
    accepted: bool = False
    primary: bool = False
    encrypted: bool = False
    has_key: bool = False
    can_scan: bool = False


class LifecycleModel:
    """Executable specification for generation-safe multi-slot semantics."""

    def __init__(self, count: int = 4) -> None:
        self.slots = [Slot() for _ in range(count)]

    def accept_primary(
        self, index: int, pid: int, queue_succeeded: bool
    ) -> Optional[Cookie]:
        generation = self.slots[index].generation + 1
        if not queue_succeeded:
            self.slots[index] = Slot(generation=generation)
            return None
        self.slots[index] = Slot(
            generation=generation,
            pid=pid,
            accepted=True,
            primary=True,
            can_scan=True,
        )
        return Cookie(index=index, generation=generation)

    def establish(self, index: int) -> None:
        self.slots[index].encrypted = True
        self.slots[index].has_key = True

    def disconnect(self, cookie: Cookie) -> bool:
        slot = self.slots[cookie.index]
        if not slot.accepted or slot.generation != cookie.generation:
            return False
        self.slots[cookie.index] = Slot(generation=slot.generation)
        return True

    def cookie_is_live(self, cookie: Cookie) -> bool:
        slot = self.slots[cookie.index]
        return slot.accepted and slot.generation == cookie.generation

    def is_scanner(self, pid: Optional[int]) -> bool:
        return pid is not None and any(
            slot.accepted and slot.pid == pid for slot in self.slots
        )

    def selected_primary(self) -> Optional[int]:
        for index, slot in enumerate(self.slots):
            if (
                slot.accepted
                and slot.primary
                and slot.encrypted
                and slot.has_key
                and slot.can_scan
            ):
                return index
        return None


class ReferenceLifecycleModel:
    """Minimal baseline/KEX/finalizer ownership model."""

    def __init__(self) -> None:
        self.references = 1
        self.disconnecting = False
        self.finalization_idle = True
        self.finalized = False

    def reserve_kex(self) -> None:
        self.references += 1

    def begin_disconnect(self) -> None:
        if not self.disconnecting:
            self.disconnecting = True
            self.references -= 1

    def release_kex(self, apc_queue_succeeds: bool = True) -> None:
        self.references -= 1
        if self.references == 0 and self.disconnecting:
            if apc_queue_succeeds:
                self.finalized = True
            else:
                self.finalization_idle = True

    def passive_retry(self) -> None:
        if self.disconnecting and self.references == 0 and self.finalization_idle:
            self.finalized = True


class LifecycleModelTests(unittest.TestCase):
    def test_rejected_primary_never_replaces_live_identity(self) -> None:
        model = LifecycleModel()
        model.accept_primary(0, 100, queue_succeeded=True)
        model.establish(0)
        model.accept_primary(1, 200, queue_succeeded=False)

        self.assertTrue(model.is_scanner(100))
        self.assertFalse(model.is_scanner(200))
        self.assertEqual(model.selected_primary(), 0)

    def test_same_pid_disconnect_keeps_other_slot_accepted(self) -> None:
        model = LifecycleModel()
        first = model.accept_primary(0, 300, queue_succeeded=True)
        model.accept_primary(1, 300, queue_succeeded=True)
        assert first is not None
        model.establish(0)
        model.establish(1)

        self.assertTrue(model.disconnect(first))
        self.assertTrue(model.is_scanner(300))
        self.assertEqual(model.selected_primary(), 1)

    def test_different_pid_overlap_tracks_both(self) -> None:
        model = LifecycleModel()
        model.accept_primary(0, 400, queue_succeeded=True)
        model.accept_primary(1, 500, queue_succeeded=True)

        self.assertTrue(model.is_scanner(400))
        self.assertTrue(model.is_scanner(500))
        self.assertFalse(model.is_scanner(None))

    def test_selection_skips_lower_pending_primary(self) -> None:
        model = LifecycleModel()
        model.accept_primary(0, 600, queue_succeeded=True)
        model.accept_primary(1, 700, queue_succeeded=True)
        model.establish(1)

        self.assertEqual(model.selected_primary(), 1)

    def test_stale_disconnect_cookie_cannot_retire_reused_slot(self) -> None:
        model = LifecycleModel()
        old_cookie = model.accept_primary(0, 800, queue_succeeded=True)
        assert old_cookie is not None
        self.assertTrue(model.disconnect(old_cookie))

        new_cookie = model.accept_primary(0, 900, queue_succeeded=True)
        assert new_cookie is not None
        self.assertNotEqual(old_cookie.generation, new_cookie.generation)
        self.assertFalse(model.disconnect(old_cookie))
        self.assertTrue(model.cookie_is_live(new_cookie))
        self.assertTrue(model.is_scanner(900))

    def test_disconnect_before_kex_worker_finalizes_on_held_release(self) -> None:
        model = ReferenceLifecycleModel()
        model.reserve_kex()
        model.begin_disconnect()
        self.assertEqual(model.references, 1)
        self.assertFalse(model.finalized)

        model.release_kex()
        self.assertEqual(model.references, 0)
        self.assertTrue(model.finalized)

    def test_apc_queue_failure_remains_retryable_at_passive(self) -> None:
        model = ReferenceLifecycleModel()
        model.reserve_kex()
        model.begin_disconnect()
        model.release_kex(apc_queue_succeeds=False)
        self.assertFalse(model.finalized)

        model.passive_retry()
        self.assertTrue(model.finalized)


class MessageTypeNumberingContractTests(unittest.TestCase):
    """Pins how SHADOWSTRIKE_MESSAGE_TYPE assigns its values.

    The enum carries no explicit initialisers, so its values are positional and
    the number travels on the wire. Its section headings nevertheless advertised
    hex ranges it has never implemented - nine of the eleven were arithmetically
    false, and the two that held did so only because the enum starts at zero.
    A set of user-mode enforcement senders consequently stamped a "block this
    process" request with 0x30, the opening value of the range labelled Policy.

    Those frames are refused today for a reason unrelated to the type number:
    they carry no SHADOWSTRIKE_MESSAGE_HEADER at all, so MessageHandler.c reads
    their first four bytes as Magic and rejects them. The type bound in the
    driver is MH_MAX_HANDLERS (64), NOT FilterMessageType_Max, so 48 already
    sits inside the handler table's index space.
    """

    def _enum_entries(self) -> list:
        """Return the enum's entries with any initialiser text removed."""
        source = strip_c_comments(
            read_source(MESSAGE_TYPES_PATH).lstrip("\ufeff")
        )
        match = re.search(
            r"typedef enum _SHADOWSTRIKE_MESSAGE_TYPE\s*\{(.*?)\}\s*"
            r"SHADOWSTRIKE_MESSAGE_TYPE;",
            source,
            re.S,
        )
        self.assertIsNotNone(
            match,
            "The SHADOWSTRIKE_MESSAGE_TYPE enum could not be located in "
            "MessageTypes.h, so its numbering contract cannot be checked. "
            "Suspect this helper before concluding the enum is absent.",
        )
        return [entry.strip() for entry in match.group(1).split(",") if entry.strip()]

    def test_the_message_type_enum_states_its_own_numbering_rule(self) -> None:
        raw = read_source(MESSAGE_TYPES_PATH).lstrip("\ufeff")
        entries = self._enum_entries()

        initialised = [entry for entry in entries if "=" in entry]
        self.assertEqual(
            initialised,
            ["FilterMessageType_None = 0"],
            "SHADOWSTRIKE_MESSAGE_TYPE must carry exactly one initialiser, "
            "None = 0, so every value stays positional. Giving enumerators "
            "explicit values renumbers the wire, and a driver and a service "
            "built either side of that change would disagree about the meaning "
            "of every message type.",
        )

        # This assertion is ABOUT A COMMENT, so it reads the RAW source. Running
        # it against strip_c_comments() output would make it vacuously true.
        start = raw.index("typedef enum _SHADOWSTRIKE_MESSAGE_TYPE")
        end = raw.index("} SHADOWSTRIKE_MESSAGE_TYPE;", start)
        offenders = [
            line.strip()
            for line in raw[start:end].splitlines()
            if re.match(
                r"\s*//.*\(\s*0x[0-9A-Fa-f]{2}\s*-\s*0x[0-9A-Fa-f]{2}\s*\)",
                line,
            )
        ]
        self.assertEqual(
            offenders,
            [],
            "A section heading inside SHADOWSTRIKE_MESSAGE_TYPE advertises a "
            "hex range the enum does not implement. That exact fiction is why "
            "0x30 was invented as a message type by eleven modules. Group "
            "headings are category labels and must carry no numbers.",
        )

        # The knowledge this cost us must stay written down next to the enum.
        preamble = raw[: raw.index("typedef enum _SHADOWSTRIKE_MESSAGE_TYPE")]
        missing = [
            token
            for token in ("APPEND ONLY", "MH_MAX_HANDLERS", "0x30", "0x31", "0x35", "0x36")
            if preamble.count(token) == 0
        ]
        self.assertEqual(
            missing,
            [],
            "MessageTypes.h no longer records the append-only rule, the real "
            "dispatch bound, or the invented constants that are NOT message "
            "types. That documentation is the fix for this defect class; "
            "removing it invites the next module to guess a value again.",
        )

    def test_the_message_type_enum_cannot_reach_the_invented_block_constant(self) -> None:
        entries = self._enum_entries()
        names = [entry.split("=")[0].strip() for entry in entries]
        self.assertEqual(
            names.count("FilterMessageType_Max"),
            1,
            "FilterMessageType_Max must appear exactly once as the final "
            "enumerator - it is the count this contract is derived from.",
        )
        max_value = names.index("FilterMessageType_Max")

        self.assertLessEqual(
            max_value,
            0x30,
            f"FilterMessageType_Max has reached {max_value}. Once it exceeds "
            "0x30 (48) a real, REGISTERED message type occupies slot 48, and 48 "
            "is the 0x30 that user-mode enforcement senders still stamp on an "
            "unframed struct. Today those frames are refused only because they "
            "carry no message header, so the magic check rejects them - not "
            "because 48 is out of range. Replace those constants with a real "
            "message type (task 158) before appending past this point.",
        )

        handler_header = read_source(MESSAGE_HANDLER_H_PATH).lstrip("\ufeff")
        slots_match = re.search(r"#define\s+MH_MAX_HANDLERS\s+(\d+)", handler_header)
        self.assertIsNotNone(
            slots_match,
            "MH_MAX_HANDLERS is no longer a plain integer #define in "
            "MessageHandler.h, so the size of the dispatch table can no longer "
            "be compared against this enum from here.",
        )
        self.assertGreaterEqual(
            int(slots_match.group(1)),
            max_value,
            "The driver's dispatch table is smaller than this enum, so the "
            "highest message types cannot be dispatched at all.",
        )

        handler = strip_c_comments(
            read_source(MESSAGE_HANDLER_C_PATH).lstrip("\ufeff")
        )
        self.assertEqual(
            handler.count("C_ASSERT(MH_MAX_HANDLERS >= FilterMessageType_Max)"),
            1,
            "MessageHandler.c has lost the C_ASSERT tying MH_MAX_HANDLERS to "
            "FilterMessageType_Max. That assert is what turns 'this enum "
            "outgrew the dispatch table' into a build failure instead of "
            "silently undispatchable message types.",
        )
        # Word-boundary matched on purpose: a plain substring count would still
        # be satisfied by a RENAMED, longer constant (SHADOWSTRIKE_MESSAGE_MAGIC_V2),
        # which would leave the gate looking present while comparing against
        # something else.
        self.assertGreaterEqual(
            len(
                re.findall(
                    r"Magic\s*!=\s*SHADOWSTRIKE_MESSAGE_MAGIC\b", handler
                )
            ),
            1,
            "MessageHandler.c no longer refuses an incoming frame whose Magic "
            "is wrong. That check is the ONLY thing currently stopping the "
            "unframed 0x30 enforcement requests from reaching the dispatch "
            "table, where 48 is already a valid index.",
        )

    # ------------------------------------------------------------------
    # The classification macros must describe the enum they sit beside, and
    # the user-mode mirror must not become a second source of truth for it.
    #
    # Both of these are source-text contracts on purpose. Reaching them at
    # runtime needs a loaded driver and a live filter port, and the failure
    # they guard is silent by construction: IS_NOTIFICATION_MESSAGE had
    # drifted to omit thirteen real notification types, and the user-mode
    # mirror had drifted so that 39 of 45 enumerators named a different
    # message class than the one they select on the wire. Nothing in a build
    # or a unit test noticed either.
    # ------------------------------------------------------------------

    @staticmethod
    def _message_type_names():
        """Enumerator suffixes in declaration order, from the enum body only."""
        raw = read_source(MESSAGE_TYPES_PATH).lstrip("\ufeff")
        start = raw.index("typedef enum _SHADOWSTRIKE_MESSAGE_TYPE")
        end = raw.index("} SHADOWSTRIKE_MESSAGE_TYPE;", start)
        body = strip_c_comments(raw[start:end])
        return re.findall(r"\bFilterMessageType_(\w+)\b", body)

    @staticmethod
    def _classifier_members(macro):
        """Types named inside one classification macro's definition."""
        src = strip_c_comments(read_source(MESSAGE_TYPES_PATH).lstrip("\ufeff"))
        marker = "#define " + macro + "(type)"
        start = src.index(marker)
        nxt = src.find("#define ", start + len(marker))
        segment = src[start:] if nxt < 0 else src[start:nxt]
        return re.findall(r"\bFilterMessageType_(\w+)\b", segment)

    def test_every_message_type_is_classified_by_exactly_one_macro(self):
        names = self._message_type_names()
        self.assertGreater(len(names), 40, "enum body did not parse")
        self.assertEqual(names[0], "None")
        self.assertEqual(names[-1], "Max")

        control = self._classifier_members("SHADOWSTRIKE_IS_CONTROL_MESSAGE")
        scan = self._classifier_members("SHADOWSTRIKE_IS_SCAN_MESSAGE")
        policy = self._classifier_members("SHADOWSTRIKE_IS_POLICY_MESSAGE")
        notify = self._classifier_members("SHADOWSTRIKE_IS_NOTIFICATION_MESSAGE")

        # The push macro is RELATIONAL over a contiguous run, so expand it from
        # declaration order rather than from the two endpoints it names. That is
        # also what makes an appended push type visible here: it would land
        # outside this run and therefore outside every category.
        push_bounds = self._classifier_members("SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE")
        self.assertEqual(
            len(push_bounds), 2,
            "SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE is no longer a two-endpoint "
            "range, so this test can no longer expand it.",
        )
        lo, hi = names.index(push_bounds[0]), names.index(push_bounds[1])
        self.assertLess(lo, hi, "data-push range endpoints are inverted")
        push = names[lo:hi + 1]

        real = names[1:-1]  # every type except None and Max

        buckets = {
            "control": control, "scan": scan, "policy": policy,
            "notification": notify, "data push": push,
        }

        seen = {}
        duplicated = []
        for bucket, members in buckets.items():
            for member in members:
                if member in seen:
                    duplicated.append(f"{member} in both {seen[member]} and {bucket}")
                seen[member] = bucket
        self.assertEqual(
            duplicated, [],
            "A message type is classified by more than one macro, so the "
            "categories no longer partition the enum: " + "; ".join(duplicated),
        )

        unclassified = [n for n in real if n not in seen]
        self.assertEqual(
            unclassified, [],
            "These message types are classified by NO macro: "
            + ", ".join(unclassified)
            + ". Appending a type without classifying it is exactly how "
            "IS_NOTIFICATION_MESSAGE came to omit thirteen real notification "
            "types. Add each one to the macro that describes it.",
        )

        stray = [n for n in seen if n not in real]
        self.assertEqual(
            stray, [],
            "These names are classified but are not enumerators of this enum: "
            + ", ".join(stray),
        )

        # Reply semantics are INDEPENDENT of direction, so ProcessNotify is
        # legitimately both a notification and reply-bearing. Pin that overlap
        # deliberately, so nobody "fixes" it by removing one of the two.
        replies = self._classifier_members("SHADOWSTRIKE_REQUIRES_REPLY")
        self.assertIn(
            "ProcessNotify", replies,
            "SHADOWSTRIKE_REQUIRES_REPLY has lost ProcessNotify. The driver "
            "waits PN_VERDICT_REPLY_TIMEOUT_MS for a verdict on a suspicious "
            "process creation, so a reply IS defined for that type.",
        )
        self.assertIn("ProcessNotify", notify)

    def test_the_user_mode_mirror_derives_every_value_from_this_enum(self):
        names = self._message_type_names()
        mirror_src = read_source(COMMUNICATION_HPP_PATH).lstrip("\ufeff")
        start = mirror_src.index("enum class MessageType : uint16_t {")
        end = mirror_src.index("};", start)
        block = mirror_src[start:end]

        restated = re.findall(r"(?m)^\s+(\w+)\s*=\s*\d+\s*,?\s*$", block)
        self.assertEqual(
            restated, [],
            "Communication::MessageType restates numeric wire values for: "
            + ", ".join(restated)
            + ". Every value must be DERIVED from FilterMessageType_*; "
            "restating them is how this mirror came to be low by one from "
            "ScanRequest onward, so ProcessNotify read 7 - which is "
            "ScanVerdict, a type with a registered driver handler.",
        )

        missing = [
            n for n in names
            if not re.search(r"=\s*FilterMessageType_" + n + r"\b", block)
        ]
        self.assertEqual(
            missing, [],
            "Communication::MessageType does not mirror these kernel "
            "enumerators: " + ", ".join(missing)
            + ". An ABSENT enumerator is the one drift deriving the values "
            "cannot prevent, and it is exactly how KeyExchange and "
            "FileOperationEvent went missing.",
        )

        # The review prompt must track the enum, so appending a type fails the
        # build until this mirror is visited.
        prompt = re.search(
            r"static_assert\(\s*static_cast<uint16_t>\(MessageType::Max\)\s*==\s*(\d+)",
            mirror_src,
        )
        self.assertIsNotNone(
            prompt,
            "Communication.hpp has lost the static_assert pinning "
            "MessageType::Max to a literal count. That assert is what forces "
            "whoever appends a kernel message type to visit this mirror.",
        )
        self.assertEqual(
            int(prompt.group(1)), names.index("Max"),
            f"The mirror's review prompt says {prompt.group(1)} but "
            f"FilterMessageType_Max is {names.index('Max')}. Update the count "
            "in the same change that adds the enumerator.",
        )

    def test_the_validity_macro_is_enforced_not_merely_declared(self):
        handler = strip_c_comments(
            read_source(MESSAGE_HANDLER_C_PATH).lstrip("\ufeff")
        )
        uses = handler.count("SHADOWSTRIKE_VALID_MESSAGE_TYPE")
        self.assertGreaterEqual(
            uses, 2,
            f"SHADOWSTRIKE_VALID_MESSAGE_TYPE is used {uses} time(s) in "
            "MessageHandler.c, expected at least 2: once in MhRegisterHandler "
            "so a handler cannot bind outside the enum, and once on the "
            "receive path so an out-of-enum type is refused by name instead of "
            "being lumped in with 'no handler registered'. A classification "
            "macro that gates nothing is the defect this replaced.",
        )
        # The receive path's real name is ShadowStrikeProcessUserMessage. There
        # is no MhDispatchMessage in this driver - earlier notes of mine claimed
        # one, and asserting against the name I expected rather than the name
        # that exists is what this test caught first.
        for fn in ("MhRegisterHandler", "ShadowStrikeProcessUserMessage"):
            body = extract_c_function(handler, fn)
            self.assertIn(
                "SHADOWSTRIKE_VALID_MESSAGE_TYPE", body,
                f"{fn} no longer checks SHADOWSTRIKE_VALID_MESSAGE_TYPE, so "
                "the dispatch table's 64 slots are once again a wider set than "
                "the 45 types this enum defines.",
            )


class AmsiBypassRetentionContractTests(unittest.TestCase):
    """One fact in one structure, and a PID-keyed map that cannot grow forever.

    None of this is reachable behaviourally: putting a record into the map
    requires real AMSI tampering in a real process, and the two public readers
    have no callers yet. So the enforceable invariants are structural, the same
    way the exploit tier's residual block claims are.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp_raw = read_source(AMSI_INTEGRATION_CPP_PATH)
        cls.hpp_raw = read_source(AMSI_INTEGRATION_HPP_PATH)
        # The comments here necessarily NAME every symbol asserted below,
        # because they explain the defect being prevented. A comment-blind
        # count is therefore guaranteed to false-positive. Strip first.
        cls.cpp = strip_c_comments(cls.cpp_raw)
        cls.hpp = strip_c_comments(cls.hpp_raw)

    def test_bypass_state_lives_in_exactly_one_structure(self):
        offenders = [
            name
            for name in ("m_bypassDetectedProcesses", "m_detectedBypassTechniques")
            if name in self.cpp or name in self.hpp
        ]
        self.assertEqual(
            offenders,
            [],
            "AMSI bypass state is tracked in a parallel set/map pair again. Two "
            "structures holding one fact is precisely how the technique "
            "accessor came to answer Unknown for a bypass whose technique the "
            "cross-process detector had already determined and logged.",
        )
        self.assertGreater(
            self.cpp.count("m_bypassDetections"),
            0,
            "The unified bypass-detection record is gone, so this guard can no "
            "longer speak for the invariant it exists to hold.",
        )

    def test_the_bypass_map_has_exactly_one_writer(self):
        inserts = re.findall(
            r"m_bypassDetections\s*\.\s*(?:emplace|insert)\s*\(", self.cpp
        )
        self.assertEqual(
            len(inserts),
            1,
            f"Expected exactly one insertion site for m_bypassDetections, found "
            f"{len(inserts)}. A retention cap can only be enforced where "
            "insertion happens; two inline inserts with no bound between them "
            "is the state this replaced.",
        )
        body = extract_c_function(self.cpp, "void RecordBypassDetection_Locked")
        self.assertEqual(
            body.count("m_bypassDetections.emplace"),
            1,
            "The single insertion site is no longer inside "
            "RecordBypassDetection_Locked, so the cap no longer governs it.",
        )

    def test_the_cap_is_enforced_and_its_losses_are_counted(self):
        body = extract_c_function(self.cpp, "void RecordBypassDetection_Locked")
        governs = re.search(
            r"m_bypassDetections\s*\.\s*size\(\)\s*>=\s*"
            r"AMSIConstants::MAX_BYPASS_DETECTIONS",
            body,
        )
        self.assertTrue(
            bool(governs),
            "The cap constant no longer governs the size comparison in "
            "RecordBypassDetection_Locked. Merely naming it in a log line "
            "would satisfy a weaker check while the comparison used something "
            "else, leaving the map unbounded.",
        )
        self.assertEqual(
            body.count("bypassDetectionsEvicted.fetch_add"),
            1,
            "Eviction at the cap discards a real detection record, so it must "
            "be counted exactly once where it happens. An uncounted eviction "
            "leaves the map looking healthy while evidence disappears.",
        )
        self.assertEqual(
            self.hpp.count("MAX_BYPASS_DETECTIONS"),
            1,
            "The bound must stay one named constant in AMSIConstants rather "
            "than a literal at the use site.",
        )

    def test_the_eviction_counter_cannot_become_a_structural_zero(self):
        self.assertEqual(
            self.hpp.count("bypassDetectionsEvicted"),
            2,
            "bypassDetectionsEvicted must be declared in BOTH AMSIStatistics "
            "and AMSIStatisticsSnapshot. Present in only one means every "
            "public reader sees zero regardless of how much was discarded.",
        )
        required = (
            (
                "bypassDetectionsEvicted.store(0",
                "Reset() would leave a pre-reset value behind",
            ),
            (
                "snapshot.bypassDetectionsEvicted",
                "the snapshot copy would drop it, so it would read zero to "
                "every caller of GetStatistics()",
            ),
            (
                '\\"bypassDetectionsEvicted\\":',
                "it would never reach an operator through ToJson",
            ),
        )
        missing = [needle for needle, _ in required if needle not in self.cpp]
        self.assertEqual(
            missing,
            [],
            "bypassDetectionsEvicted is absent from a required plumbing site; "
            "consequences in order: "
            + "; ".join(why for _, why in required),
        )

    def test_a_known_technique_is_recorded_not_discarded(self):
        self.assertEqual(
            self.cpp.count("RecordBypassDetection_Locked(pid, event.techniques)"),
            1,
            "The cross-process bypass site no longer records the technique it "
            "determined. It sets event.techniques, raises an alert carrying it, "
            "and if it then records bare membership the technique accessor "
            "answers Unknown for a bypass that was fully identified.",
        )

    def test_a_dead_process_loses_its_bypass_record(self):
        paired = re.findall(
            r"m_monitoredProcesses\s*\.\s*erase\(pid\);\s*"
            r"m_bypassDetections\s*\.\s*erase\(pid\);",
            self.cpp,
        )
        self.assertEqual(
            len(paired),
            1,
            "The bypass record is no longer pruned at the site that already "
            "established the process is gone. That is the only live path where "
            "liveness is known for free, so dropping it means a record can "
            "outlive its process and be inherited by a recycled PID.",
        )


class KernelProcessContextRetentionContractTests(unittest.TestCase):
    """The privilege-escalation detector's per-PID kernel context: one home, one
    writer, one bound, and a precise erase when the process dies.

    SOURCE CONTRACTS RATHER THAN BEHAVIOUR, and that is forced rather than
    chosen: reaching the write site needs a live kernel process notification,
    and reaching the read site needs the monitoring thread running against a
    populated monitored set. Nothing a unit test can arrange exercises either.
    The shape is what regressed, so the shape is what is pinned.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp = read_source(PRIVESC_DETECTOR_CPP_PATH)
        cls.hpp = read_source(PRIVESC_DETECTOR_HPP_PATH)
        cls.rtp = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        # COMMENTS STRIPPED FIRST. The change that introduced these guards
        # necessarily describes the defect it prevents, naming the very symbols
        # asserted below, so a comment-blind count is guaranteed to
        # false-positive on the prose rather than on the code.
        cls.cpp_code = strip_c_comments(cls.cpp)
        cls.hpp_code = strip_c_comments(cls.hpp)
        cls.rtp_code = strip_c_comments(cls.rtp)

    def test_the_process_context_lives_in_exactly_one_structure(self):
        for label, body in (("cpp", self.cpp_code), ("hpp", self.hpp_code)):
            for stale in ("m_processCreationPaths", "m_processElevationState"):
                self.assertEqual(
                    body.count(stale),
                    0,
                    "%s: %s is back. Two containers holding one fact about one "
                    "pid is how the image path and the elevation state came to "
                    "be writable independently; they must stay one record."
                    % (label, stale),
                )
        self.assertEqual(
            self.cpp_code.count(
                "std::unordered_map<uint32_t, KernelProcessContext> "
                "m_kernelProcessContexts;"
            ),
            1,
            "The unified per-PID context container is not declared exactly once.",
        )

    def test_the_context_map_has_exactly_one_writer(self):
        # Subscript assignment is how the previous two containers were written,
        # and it bypasses any bound by construction: `map[pid] = v` inserts
        # without ever consulting a cap.
        self.assertEqual(
            self.cpp_code.count("m_kernelProcessContexts["),
            0,
            "A subscript write to the context map is back. Every insertion must "
            "go through the funnel, because a cap checked at some write sites "
            "and not others is not a cap.",
        )
        self.assertEqual(
            self.cpp_code.count("m_kernelProcessContexts.emplace("),
            1,
            "The context map no longer has exactly one insertion site.",
        )
        funnel = strip_c_comments(
            extract_c_function(
                self.cpp,
                "void PrivilegeEscalationDetectorImpl::"
                "RecordKernelProcessContext_Locked",
            )
        )
        self.assertEqual(
            funnel.count("m_kernelProcessContexts.emplace("),
            1,
            "The single insertion no longer lives inside the recording funnel, "
            "so it is no longer covered by the retention bound.",
        )
        self.assertEqual(
            self.cpp_code.count("RecordKernelProcessContext_Locked("),
            3,
            "Expected exactly declaration, definition and one call site for the "
            "recording funnel.",
        )

    def test_the_retention_bound_governs_the_size_comparison(self):
        governs = re.search(
            r"m_kernelProcessContexts\.size\(\)\s*>=\s*"
            r"PrivEscConstants::MAX_TRACKED_PROCESS_CONTEXTS",
            self.cpp_code,
        )
        self.assertTrue(
            bool(governs),
            "The retention bound no longer governs the size comparison. Naming "
            "the constant is not enforcing it - the constant also appears in "
            "the eviction log line, so a containment check would still pass "
            "with the comparison deleted.",
        )
        self.assertEqual(
            self.hpp_code.count("MAX_TRACKED_PROCESS_CONTEXTS"),
            1,
            "The bound must be declared exactly once, as a named constant.",
        )
        self.assertEqual(
            self.cpp_code.count("processContextsEvicted.fetch_add"),
            1,
            "An eviction must be counted exactly once, at the one site that "
            "discards a record.",
        )

    def test_the_eviction_counter_cannot_become_a_structural_zero(self):
        # Declared in the live atomic struct AND the public snapshot. A member
        # added to one only is dropped by the snapshot copy and then reads zero
        # forever - a counter that looks healthy because nothing can write it.
        self.assertEqual(
            self.hpp_code.count("processContextsEvicted"),
            2,
            "The eviction counter must appear in both the atomic statistics "
            "struct and the public snapshot.",
        )
        for label, needle in (
            ("Reset()", "processContextsEvicted = 0;"),
            ("ToJson()", 'j["processContextsEvicted"]'),
            (
                "the snapshot copy",
                "s.processContextsEvicted = processContextsEvicted.load",
            ),
        ):
            self.assertEqual(
                self.cpp_code.count(needle),
                1,
                "The eviction counter is missing from %s, so it would report a "
                "stale or permanently zero value." % label,
            )

    def test_a_dead_process_loses_its_context_record(self):
        impl = strip_c_comments(
            extract_c_function(
                self.cpp,
                "void PrivilegeEscalationDetectorImpl::OnKernelProcessExited",
            )
        )
        self.assertEqual(
            impl.count("m_kernelProcessContexts.erase("),
            1,
            "The exit handler no longer erases the per-PID record. Windows "
            "recycles process ids, and the monitoring loop skips a pid whose "
            "recorded path is whitelisted, so a surviving record hands a dead "
            "process's whitelist decision to whatever inherits its id.",
        )
        # The feed must exist, on the NON-creation branch, unconditionally.
        idx = self.rtp_code.find("ped.OnKernelProcessCreated(")
        self.assertNotEqual(
            idx, -1, "The kernel process-creation feed into the detector is gone."
        )
        window = self.rtp_code[max(0, idx - 200) : idx + 2200]
        i_null = window.find("std::nullopt")
        i_else = window.find("} else {")
        i_exit = window.find("OnKernelProcessExited")
        self.assertTrue(
            i_null != -1 and i_else != -1 and i_exit != -1,
            "The creation branch and its paired exit branch are no longer "
            "adjacent in the process-notify handler (nullopt=%d else=%d "
            "exit=%d)." % (i_null, i_else, i_exit),
        )
        self.assertTrue(
            i_null < i_else < i_exit,
            "The exit notification is no longer the else-branch of the creation "
            "test, so a process exit may not erase its context.",
        )

    def test_the_elevation_state_is_never_fabricated(self):
        idx = self.rtp_code.find("ped.OnKernelProcessCreated(")
        self.assertNotEqual(idx, -1, "The detector feed is gone.")
        call = self.rtp_code[idx : idx + 320]
        self.assertIn(
            "std::nullopt",
            call,
            "The elevation argument is no longer not-determined. The kernel "
            "process notification carries no elevation bit, so any concrete "
            "value passed here is invented.",
        )
        self.assertIsNone(
            re.search(r",\s*false\s*\)\s*;", call),
            "A literal false is being passed as the elevation state again. That "
            "records a fabricated measurement AND disables the only branch that "
            "populates the monitored set, so it hides itself.",
        )
        self.assertEqual(
            self.cpp_code.count("elevated.has_value()"),
            2,
            "Both the auto-monitor gate and the token-theft correlation must "
            "require a measured elevation state. Treating not-determined as "
            "'not elevated' is what made the correlation fire on every "
            "elevation-showing token change while claiming kernel evidence.",
        )

    def test_the_context_map_is_cleared_on_both_lifecycle_transitions(self):
        self.assertEqual(
            self.cpp_code.count("m_kernelProcessContexts.clear()"),
            2,
            "The context map must be cleared on BOTH initialize and shutdown, "
            "as its two sibling containers already are. Surviving either "
            "transition attributes a previous run's processes to current ids.",
        )


class ProcessNotifyReplyHorizonContractTests(unittest.TestCase):
    """The process-creation handler must bound the work whose only product is a
    verdict the driver may already have stopped waiting for - and must NOT bound
    the work that acts on its own.

    Every assertion here is about SOURCE TEXT rather than behaviour, and that is
    forced rather than preferred: reaching this handler needs a loaded kernel
    driver delivering a real process notification over a live filter port, so no
    C++ unit test can exercise it. The invariants are still checkable because
    they are structural, and two of them are cross-language, which is why they
    live in this suite.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # COMMENTS STRIPPED FIRST, before anything is counted. The code guarded
        # here is heavily commented and those comments necessarily NAME every
        # symbol asserted below - including the wording they replaced - so a
        # comment-blind count is guaranteed to match prose and report a guard as
        # satisfied by an explanation of the defect it exists to catch.
        cls.rtp_cpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.rtp_hpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_HPP_PATH))
        cls.ipc_hpp = read_source(IPC_MANAGER_HPP_PATH)
        cls.driver_c = read_source(PROCESS_NOTIFY_C_PATH)
        # The qualified return type is required: this name appears at call and
        # registration sites EARLIER in the file than its definition, and a bare
        # name would extract one of those instead.
        cls.handler = extract_c_function(
            cls.rtp_cpp, "Communication::KernelVerdict OnKernelProcessNotify"
        )

    def test_the_handler_clock_starts_before_the_expensive_pre_budget_stages(self) -> None:
        # THE DEFECT THIS EXISTS FOR was live in the first draft of the very
        # change that added the horizon, so it is not hypothetical. The clock was
        # declared beside the evasion suite, roughly 140 lines into the handler,
        # AFTER two stages that each do real work: AntiDebug's process-notify
        # pass, and CertificateValidator's process-create pass which opens the
        # image and verifies its signature.
        #
        # A deadline measured from after the expensive part reports a handler that
        # has already spent its window as being at zero, so the horizon concludes
        # the driver still has time when it does not. That is the same shape as
        # the four detector timeouts this handler used to declare and never read:
        # a bound that reads correct and enforces nothing.
        clock = self.handler.find("notifyStart = std::chrono::steady_clock::now()")
        self.assertNotEqual(
            clock,
            -1,
            "The handler no longer starts a steady_clock named notifyStart, so "
            "neither the evasion sub-budget nor the reply horizon has anything "
            "to measure elapsed time against.",
        )

        for stage in (
            "AntiDebug::Instance().OnKernelProcessNotify",
            "CertificateValidator::Instance().OnKernelProcessCreate",
        ):
            at = self.handler.find(stage)
            self.assertNotEqual(
                at,
                -1,
                f"{stage} has left OnKernelProcessNotify. If it moved, this "
                f"guard needs updating; if it was deleted, that is a coverage "
                f"change and not a refactor.",
            )
            self.assertLess(
                clock,
                at,
                f"notifyStart is declared at offset {clock} but {stage} runs at "
                f"offset {at}, so that stage's cost is invisible to both "
                f"deadlines. Start the clock before it, or the horizon will let "
                f"the driver time out while believing it had budget left.",
            )

    def test_the_reply_horizon_is_declared_and_actually_governs_the_tail(self) -> None:
        # A CONSTANT THAT IS NAMED BUT DOES NOT GOVERN is this codebase's most
        # repeated defect, so the assertion is on the EXPRESSION, not on the
        # identifier. The identifier also appears in the log line and in the
        # static_assert, either of which would satisfy a containment check while
        # the comparison had been removed.
        declared = re.search(
            r"kProcessNotifyReplyHorizonMs\s*=\s*(\d+)", self.handler
        )
        self.assertIsNotNone(
            declared,
            "kProcessNotifyReplyHorizonMs is gone, so the tail of the "
            "process-creation handler is unbounded again.",
        )

        governs = re.search(
            r"elapsedMs\s*\)\s*<\s*kProcessNotifyReplyHorizonMs", self.handler
        )
        self.assertTrue(
            bool(governs),
            "kProcessNotifyReplyHorizonMs is declared but no longer compared "
            "against elapsed time, so it names a deadline that enforces "
            "nothing.",
        )

        self.assertEqual(
            self.handler.count("m_stats.processNotifyReplyHorizonExceeded++"),
            1,
            "The reply-horizon counter must be incremented exactly once, inside "
            "the latch, or the number either double-counts one skip or stops "
            "recording them.",
        )

    def test_the_horizon_gates_only_reply_dependent_stages(self) -> None:
        # THE LIMIT ON WHAT MAY BE SKIPPED IS THE WHOLE ARGUMENT. Skipping is
        # justified only where the stage's sole product is the verdict, because
        # past the horizon the driver has failed open and the verdict is
        # discarded. Work that acts on its own - terminating a process, raising
        # an alert, erasing per-PID state - survives the driver timing out, so
        # skipping it DROPS capability instead of deferring it.
        gates = re.findall(r'replyHorizonExceeded\("([^"]+)"\)', self.handler)
        self.assertEqual(
            sorted(gates),
            sorted(["external process-create callbacks", "pre-execution image scan"]),
            "The reply horizon must gate exactly the two reply-dependent tail "
            "stages and nothing else. A third gate means something that acts "
            "independently of the verdict is now being skipped under load; a "
            "missing one means an unbounded stage is back on the callback the "
            "driver blocks CreateProcess on.",
        )

        # Both gates must test isCreation in the SAME expression. The driver does
        # not wait for a verdict on process exit, and the exit branch carries the
        # only eraser of the privilege-escalation context map plus the only commit
        # of pending file backups.
        for stage in gates:
            window = self.handler[
                max(0, self.handler.find(f'replyHorizonExceeded("{stage}")') - 200):
                self.handler.find(f'replyHorizonExceeded("{stage}")')
            ]
            self.assertIn(
                "req.isCreation",
                window,
                f'The "{stage}" gate no longer requires req.isCreation, so a '
                f"process EXIT can now be skipped by a latency bound. Exit is "
                f"where this handler does its state maintenance.",
            )

        # REGRESSION GUARDS, and labelled as such rather than presented as
        # discriminators: these two must stay outside every gate.
        # assertTrue over a boolean, never assertIn against the handler slice - a
        # containment failure would dump the whole function into the output and
        # bury the one line that matters.
        self.assertTrue(
            "OnKernelProcessExited(req.processId)" in self.handler,
            "The privilege-escalation exit erase is gone from the handler. It is "
            "the only eraser of that per-PID map; without it the map grows one "
            "entry per process creation for the life of the service.",
        )
        self.assertTrue(
            "Ransomware::Wiring::DispatchProcessNotify(" in self.handler,
            "The ransomware fan-out has left the handler. Two of its seven "
            "targets erase per-PID state on exit and a third commits pending "
            "backups, none of which depends on the kernel verdict.",
        )

    def test_the_deadline_chain_stays_below_the_driver_wait(self) -> None:
        # A THREE-LINK CROSS-LANGUAGE CHAIN, extending the two-link one that
        # already pins the IPC fan-out budget beneath the driver's wait. The
        # handler's own horizon is the new innermost link, and it is restated in
        # RealTimeProtection.cpp rather than referenced because IPCManager keeps
        # kProcessFanOutBudgetMs private - so nothing but this test stops the two
        # numbers drifting apart in separate commits.
        horizon = re.search(
            r"kProcessNotifyReplyHorizonMs\s*=\s*(\d+)", self.handler
        )
        fanout = re.search(r"kProcessFanOutBudgetMs\s*=\s*(\d+)", self.ipc_hpp)
        driver = re.search(
            r"#define\s+PN_VERDICT_REPLY_TIMEOUT_MS\s+(\d+)", self.driver_c
        )
        for name, m in (
            ("kProcessNotifyReplyHorizonMs", horizon),
            ("kProcessFanOutBudgetMs", fanout),
            ("PN_VERDICT_REPLY_TIMEOUT_MS", driver),
        ):
            self.assertIsNotNone(m, f"{name} is gone, so the deadline chain is broken.")

        horizon_ms = int(horizon.group(1))
        fanout_ms = int(fanout.group(1))
        driver_ms = int(driver.group(1))

        self.assertLessEqual(
            horizon_ms,
            fanout_ms,
            f"The handler's reply horizon {horizon_ms} ms exceeds the fan-out "
            f"budget {fanout_ms} ms that its own caller allots to every process "
            f"subscriber, so this handler alone can overrun the window it shares.",
        )
        self.assertLess(
            fanout_ms,
            driver_ms,
            f"Fan-out budget {fanout_ms} ms is not below the driver's "
            f"{driver_ms} ms wait.",
        )

    def test_the_reply_horizon_counter_cannot_become_a_structural_zero(self) -> None:
        # Learned the hard way twice: a counter declared but not plumbed through
        # reset and reporting reads zero forever, and a zero that means "not
        # wired" is indistinguishable from a zero that means "healthy" - which is
        # the more dangerous of the two because it argues against the symptom.
        #
        # Every check below is a boolean over a membership test, never assertIn
        # against a source file. These files are 62 KB and 394 KB; an assertIn
        # failure prints the entire haystack and buries the finding.
        self.assertTrue(
            "std::atomic<uint64_t> processNotifyReplyHorizonExceeded" in self.rtp_hpp,
            "The reply-horizon counter is no longer declared in "
            "RealTimeProtection.hpp.",
        )

        missing = [
            why
            for fragment, why in (
                (
                    "m_stats.processNotifyReplyHorizonExceeded.load",
                    "not read by the periodic capacity report, so the condition "
                    "is invisible in a field log",
                ),
                (
                    "processNotifyReplyHorizonExceeded={}",
                    "not printed in the capacity line, so nothing in the field "
                    "surfaces it",
                ),
                (
                    "processNotifyReplyHorizonExceeded = 0",
                    "not cleared by the statistics reset, so a reset leaves a "
                    "stale value beside counters that restarted at zero",
                ),
            )
            if fragment not in self.rtp_cpp
        ]
        self.assertEqual(
            missing,
            [],
            "The reply-horizon counter is " + "; and is ".join(missing) + ".",
        )

        # The two budget counters must remain DISTINCT. Folding them together
        # would let "the driver is about to fail open" hide inside "the evasion
        # detectors ran long", which are different regimes needing different
        # responses.
        self.assertTrue(
            "std::atomic<uint64_t> processNotifyBudgetExceeded" in self.rtp_hpp,
            "The evasion sub-budget counter has been removed, so the two "
            "conditions can no longer be told apart.",
        )

    def test_the_evasion_sub_budget_is_not_swallowed_by_the_outer_horizon(self) -> None:
        # The two deadlines are nested, and the ordering is load-bearing: if the
        # outer horizon were ever set BELOW the evasion sub-budget it would skip
        # the evasion detectors before their own budget had been spent, quietly
        # reducing detection while both numbers still looked deliberate.
        self.assertTrue(
            "static_assert(kProcessNotifyReplyHorizonMs >= kProcessNotifyBudgetMs"
            in self.handler,
            "The static_assert tying the outer reply horizon to the evasion "
            "sub-budget is gone, so the two can be set into a relationship that "
            "silently disables the evasion suite.",
        )

        budget = re.search(r"kProcessNotifyBudgetMs\s*=\s*(\d+)", self.handler)
        self.assertIsNotNone(
            budget, "The evasion sub-budget constant has been removed."
        )
        self.assertEqual(
            self.handler.count('evasionBudgetExceeded("'),
            4,
            "The evasion sub-budget must still be consulted at exactly its four "
            "detector stages. Fewer means a detector became unbounded; more "
            "means a stage was added without deciding which deadline owns it.",
        )


class ServiceBuildIdentityContractTests(unittest.TestCase):
    """The service must state which build it is, in its own log.

    Task 104. Until this was wired, every field-triage cycle had to infer the
    running version from the MSI or the installer log, because the service never
    named itself. Those are separate artefacts that can disagree with the binary
    actually executing, so a log with no version in it is evidence about an
    unknown build - which is the weakest possible position for diagnosing a
    security product.

    Asserted as source text rather than behaviour on purpose: reaching the line
    needs a started Windows service, and the regression being guarded against is
    somebody deleting or decoupling the version reference during an unrelated
    edit, which is a source-level event.
    """

    @classmethod
    def setUpClass(cls):
        cls.src = strip_c_comments(read_source(ANTIVIRUS_SERVICE_CPP_PATH))
        cls.version_header = strip_c_comments(read_source(VERSION_INFO_H_PATH))

    def test_the_version_macro_still_exists_where_the_service_expects_it(self):
        # Renaming the macro would break the service as a compile error, but it
        # would break Invoke-PhantomDeploy.ps1 SILENTLY, because that harness
        # parses this header as text. Pin the name both sides depend on.
        self.assertIn(
            "define SS_VERSION_STRING",
            self.version_header,
            "VersionInfo.h no longer defines SS_VERSION_STRING. Both the service "
            "log and Invoke-PhantomDeploy.ps1 depend on that name, and only one "
            "of the two would fail loudly.",
        )

    def test_the_service_includes_the_single_version_header(self):
        self.assertIn(
            "VersionInfo.h",
            self.src,
            "AntivirusService.cpp no longer includes VersionInfo.h, so it cannot "
            "name its own build. Do not substitute a local literal: one "
            "definition included everywhere is the fix for this defect class, and "
            "a hand-copied version string is how DRIVER_SERVICE_NAME drifted in "
            "four modules at once.",
        )

    def test_the_service_logs_its_own_version(self):
        # Containment is not enough. An include plus an unreferenced macro would
        # satisfy a naive check while producing no line in the field log, which is
        # the entire defect. Require the macro to sit inside a logging statement.
        idx = self.src.find("SS_VERSION_STRING")
        self.assertGreaterEqual(
            idx,
            0,
            "Nothing in AntivirusService.cpp references SS_VERSION_STRING, so the "
            "service does not state its build in the log.",
        )
        stmt_start = max(self.src.rfind(";", 0, idx), self.src.rfind("{", 0, idx))
        statement = self.src[stmt_start + 1 : idx]
        self.assertIn(
            "SS_LOG_",
            statement,
            "SS_VERSION_STRING is referenced but not from within a logging call, "
            "so the version is compiled in and never emitted.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
