"""Host-safe contracts for PhantomSensor scanner identity and port lifecycle.

These tests intentionally do not load the driver. They bind the production C
implementation to the invariants that prevent recursive scanner IPC and model
the multi-slot/generation lifecycle cases that previously broke scalar or
slot-only identity designs. Snapshot-only runtime validation remains under
vm_shrd/PhantomSensorScannerRecursion.
"""

from __future__ import annotations

import math
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
PRE_WRITE_C_PATH = ROOT / "PhantomSensor" / "PhantomSensor" / "Callbacks" / "FileSystem" / "PreWrite.c"
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
FILE_PROTECTION_HPP_PATH = ROOT / "src" / "PhantomCore" / "SelfProtection" / "FileProtection.hpp"

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
FILE_UTILS_CPP_PATH = ROOT / "src/PhantomCore/Utils/FileUtils.cpp"
FILE_UTILS_HPP_PATH = ROOT / "src/PhantomCore/Utils/FileUtils.hpp"
DATABASE_MANAGER_CPP_PATH = ROOT / "src/PhantomCore/Database/DatabaseManager.cpp"
SCAN_ENGINE_CPP_PATH = ROOT / "src/PhantomCore/Core/Engine/ScanEngine.cpp"
MEMORY_UTILS_HPP_PATH = ROOT / "src/PhantomCore/Utils/MemoryUtils.hpp"
MEMORY_UTILS_CPP_PATH = ROOT / "src/PhantomCore/Utils/MemoryUtils.cpp"
METAMORPHIC_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.cpp"
PACKER_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/AntiEvasion/PackerDetector.cpp"
PE_PARSER_CPP_PATH = ROOT / "src/PhantomCore/PEParser/PEParser.cpp"

# The logging header whose missing <format> include forced an ordering requirement on
# every consumer, and the two projects whose language standards must agree because the
# tray both LINKS PhantomCoreLib.lib and COMPILES its shared headers.
LOGGER_HPP_PATH = ROOT / "src/PhantomCore/Utils/Logger.hpp"
TRAY_VCXPROJ_PATH = ROOT / "ShadowStrikePhantomTray.vcxproj"
PHANTOM_CORE_LIB_VCXPROJ_PATH = ROOT / "PhantomCoreLib.vcxproj"
TRAY_SOURCE_DIR = ROOT / "src/Products/Community/PhantomHome/UI/Tray"
BEHAVIOR_ANALYZER_CPP_PATH = ROOT / "src/PhantomCore/Core/Engine/BehaviorAnalyzer.cpp"
REAL_TIME_PROTECTION_CPP_PATH = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp"
REAL_TIME_PROTECTION_HPP_PATH = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.hpp"
BEHAVIOR_BLOCKER_CPP_PATH = ROOT / "src/PhantomCore/RealTime/BehaviorBlocker.cpp"
BEHAVIOR_BLOCKER_HPP_PATH = ROOT / "src/PhantomCore/RealTime/BehaviorBlocker.hpp"
PROCESS_UTILS_C_PATH = ROOT / "PhantomSensor/PhantomSensor/Utilities/ProcessUtils.c"
PROCESS_UTILS_H_PATH = ROOT / "PhantomSensor/PhantomSensor/Utilities/ProcessUtils.h"
SENSOR_SOURCE_ROOT = ROOT / "PhantomSensor/PhantomSensor"
COMMUNICATION_HPP_PATH = ROOT / "src/PhantomCore/Communication/Communication.hpp"
TELEMETRY_COLLECTOR_HPP_PATH = ROOT / "src/PhantomCore/Communication/TelemetryCollector.hpp"
SANDBOX_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/SandboxEvasionDetector.cpp"
)
SANDBOX_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/SandboxEvasionDetector.hpp"
)
TIME_BASED_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/TimeBasedEvasionDetector.cpp"
)
TIME_BASED_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/TimeBasedEvasionDetector.hpp"
)
VM_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/VMEvasionDetector.hpp"
)
VM_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/VMEvasionDetector.cpp"
)
DEBUGGER_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/DebuggerEvasionDetector.cpp"
)
ENVIRONMENT_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/EnvironmentEvasionDetector.cpp"
)
METAMORPHIC_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.hpp"
)
METAMORPHIC_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.cpp"
)
NETWORK_BASED_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/NetworkBasedEvasionDetector.cpp"
)
ENVIRONMENT_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/EnvironmentEvasionDetector.hpp"
)
NETWORK_BASED_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/NetworkBasedEvasionDetector.hpp"
)
PROCESS_EVASION_DETECTOR_CPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/ProcessEvasionDetector.cpp"
)
PROCESS_EVASION_DETECTOR_HPP_PATH = (
    ROOT / "src/PhantomCore/AntiEvasion/ProcessEvasionDetector.hpp"
)
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
BUFFER_OVERFLOW_PROTECTION_CPP_PATH = (
    ROOT / "src/PhantomCore/Exploits/BufferOverflowProtection.cpp"
)
ATOM_BOMBING_DETECTOR_CPP_PATH = ROOT / "src/PhantomCore/Core/Process/AtomBombingDetector.cpp"
ATOM_BOMBING_DETECTOR_HPP_PATH = ROOT / "src/PhantomCore/Core/Process/AtomBombingDetector.hpp"

# The USB responder, whose accounting was corrected alongside the exploit tier.
BAD_USB_DETECTOR_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/BadUSBDetector.cpp"
)
USB_DEVICE_MONITOR_CPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/USBDeviceMonitor.cpp"
)
USB_DEVICE_MONITOR_HPP_PATH = (
    ROOT / "src/Products/Community/PhantomHome/USB_Protection/USBDeviceMonitor.hpp"
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
HONEYPOT_MANAGER_CPP_PATH = ROOT / "src/PhantomCore/RansomwareProtection/HoneyPotManager.cpp"

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
        # and the decision it enables is the OR of six evasion detectors, any one of
        # which records a finding. The file-scan handler already gates a Suspicious
        # verdict on the configured mode; this handler did not, so a MONITOR_ONLY
        # endpoint would have had process creations blocked by a control it had
        # explicitly turned down.
        #
        # THE CONDITION SPELLING CHANGED AND THE LOCATOR FOLLOWED IT, THE PROPERTY DID
        # NOT MOVE. The handler used to test a bool `evasionDetected`; it now asks
        # whether any finding was recorded, because a single shared description string
        # meant only one detector could ever be named in the alert. Everything this
        # test pins - a reachable Monitor return, the mode being consulted, the
        # withheld case not counting as a block, an unconditional alert - is unchanged.
        rtp = read_source(ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp")
        source = strip_c_comments(rtp)

        gate = re.search(
            r"if\s*\(\s*!\s*evasionFindings\.empty\(\)\s*\)\s*\{(?P<body>.*?)return\s+"
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

        # THE DECISION MUST DRIVE THE BRANCH, NOT MERELY BE COMPUTED. Hoisting the
        # mode comparison into a named value so telemetry can report the real outcome
        # created a failure mode the original form did not have: the value could be
        # computed, satisfying the assertion above, and then ignored by a branch that
        # blocks unconditionally.
        decision = re.search(
            r"const\s+bool\s+(?P<name>\w+)\s*=\s*[^;]*ProtectionMode::BLOCK_SUSPICIOUS[^;]*;",
            body,
            re.DOTALL,
        )
        self.assertIsNotNone(
            decision,
            "the mode comparison must be captured in a named decision so the "
            "enforcement outcome is settled once and reported truthfully",
        )
        assert decision is not None
        # BOUNDED: assertRegex prints the entire string it searched, and this body is
        # thousands of characters. Search first, then assert on a boolean so a failure
        # names the offender instead of reprinting the handler.
        driven = re.search(
            r"if\s*\(\s*" + decision.group("name") + r"\s*\)\s*\{",
            body,
        )
        self.assertTrue(
            driven is not None,
            "the branch that returns Block must be driven by the mode-derived "
            f"decision {decision.group('name')!r}, not by an unconditional test; no "
            f"`if ({decision.group('name')})` appears in the decision block",
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


class UsbEmergencyBlockClaimContractTests(unittest.TestCase):
    """EmergencyBlockDevice must not claim a block it does not perform.

    Task 156. MEASURED, not inferred: the function marks our own in-memory record
    Blocked and performs no PnP operation of any kind, and the mark it writes is
    never COMPARED anywhere in this product - USBDeviceInfo::accessLevel is
    assigned in several places but the only read is the device-arrival path, which
    uses a fresh DeviceControlManager verdict rather than the stored value. So the
    write does not gate a later access decision either.

    Why a wording defect earns a guard: BadUSBDetector's quarantine response
    escalates to this function and logs a successful escalation on the strength of
    the file header's claim that it "actually blocks devices". A false capability
    claim here therefore propagates into another module's outcome reporting - the
    same over-claimed-outcome defect corrected in bb48bf8a, 9c4daf96 and 2beb1f88.

    Source text rather than behaviour for two independent reasons: PhantomTests
    does not compile USBDeviceMonitor.cpp (it is built by PhantomHome,
    ShadowStrike and ShadowStrikePhantomService), and reaching this path needs a
    real removable device.
    """

    @classmethod
    def setUpClass(cls):
        cls.raw = read_source(USB_DEVICE_MONITOR_CPP_PATH)
        cls.src = strip_c_comments(cls.raw)
        # Slice between two anchors rather than trusting a function extractor:
        # the public wrapper USBDeviceMonitor::EmergencyBlockDevice appears later
        # in the file and the declaration appears earlier, so the qualified Impl
        # definition is the only unambiguous starting point.
        start = cls.src.find("void USBDeviceMonitorImpl::EmergencyBlockDevice(")
        assert start >= 0, "EmergencyBlockDevice definition not found"
        end = cls.src.find("USBDeviceMonitorImpl::UnblockDevice(", start + 1)
        assert end > start, "UnblockDevice end anchor not found after the function"
        cls.body = cls.src[start:end]

    def test_the_file_header_no_longer_claims_the_function_blocks_devices(self):
        # RAW source deliberately: the claim lived in a comment, so reading the
        # comment-stripped text would make this assertion pass vacuously - which
        # is the failure mode that let the claim survive in the first place.
        self.assertNotIn(
            "EmergencyBlockDevice actually blocks devices",
            self.raw,
            "The file header again claims EmergencyBlockDevice blocks devices. It "
            "performs no PnP disable and no eject, and BadUSBDetector escalates to "
            "it and reports success on the strength of that claim.",
        )

    def test_the_emergency_block_counter_is_guarded_by_finding_the_device(self):
        self.assertEqual(
            self.body.count("emergencyBlocks.fetch_add"),
            1,
            "There must be exactly one site that counts an emergency block, so "
            "the counter cannot be incremented twice for one request or from an "
            "unguarded path.",
        )
        guard = self.body.find("if (!deviceKnown)")
        counter = self.body.find("emergencyBlocks.fetch_add")
        self.assertGreaterEqual(
            guard,
            0,
            "The not-found guard has been removed, so a request naming a device "
            "we have never seen would report and count a block again.",
        )
        self.assertGreater(
            counter,
            guard,
            "The counter runs before the not-found guard, so it counts blocks for "
            "devices that were never located - the counter-outside-the-guard shape "
            "corrected in bb48bf8a.",
        )

    def test_the_function_still_performs_no_device_level_operation(self):
        # REGRESSION GUARD, NOT A DISCRIMINATOR. It records the measured fact that
        # this path disables nothing, which is what makes the corrected header
        # text true. If real blocking is ever implemented here - an owner's policy
        # decision, because forcibly ejecting a user's device is destructive -
        # this assertion must be REPLACED by one requiring the operation's result
        # to be checked before anything claims success. It must not be deleted.
        for api in ("CM_Disable_DevNode", "SetupDiChangeState", "SafeEjectDeviceById"):
            self.assertNotIn(
                api,
                self.body,
                "%s now appears in EmergencyBlockDevice. The function may finally "
                "perform a real block - if so, update the file header and this "
                "test together, and require the return value to be checked before "
                "the counter or the log claims success." % api,
            )
        self.assertNotIn(
            "EMERGENCY BLOCK triggered",
            self.body,
            "The log line again announces an emergency block without qualifying "
            "that only policy state changed and the device remains usable.",
        )

    def test_the_logged_event_names_the_device_that_was_found(self):
        self.assertNotIn(
            "USBDeviceInfo{}",
            self.body,
            "The event is logged with a default-constructed device record while "
            "the real one was in hand, so it cannot name the vendor, product or "
            "serial it applied to - the same available-value-dropped-on-the-floor "
            "shape as the hardcoded parentPid 0 corrected in 47742cf5.",
        )


class FileUtilsReadErrorContractTests(unittest.TestCase):
    """Every failure of the file read path must describe itself.

    The 1.0.94 field run recorded 53 read failures whose log lines named neither
    the file nor the reason, and they were the only errors that run counted. One
    site - the CreateFileW failure - was corrected in an earlier session, which is
    why the remaining three were easy to believe already fixed: they set a Win32
    code and no message at all, and the public entry point never reset the
    caller's Error, so a stale failure survived a success.

    SOURCE CONTRACTS RATHER THAN BEHAVIOUR, deliberately. Reaching the interesting
    paths needs a mid-read I/O error, a genuine allocation failure, or an
    unhydrated cloud placeholder - none of which a unit test can arrange
    reliably. What IS enforceable is that no failure path in these two functions
    can return without recording a reason.
    """

    @classmethod
    def setUpClass(cls):
        raw = read_source(FILE_UTILS_CPP_PATH)
        start = raw.find("static void RecordFailure")
        end = raw.find("bool ReadAllTextUtf8")
        assert start != -1, "RecordFailure helper missing from FileUtils.cpp"
        assert end != -1, "ReadAllTextUtf8 missing from FileUtils.cpp"
        assert start < end, "RecordFailure must precede ReadAllTextUtf8"
        cls.raw_slice = raw[start:end]
        cls.code = strip_c_comments(cls.raw_slice)
        cls.header_raw = read_source(FILE_UTILS_HPP_PATH)

    def test_every_failure_exit_records_a_reason(self):
        # The invariant, expressed as a relation rather than a fixed number so
        # that ADDING a legitimate failure path stays possible - it just has to
        # bring its own RecordFailure with it.
        exits = len(re.findall(r"return false;", self.code))
        recorded = len(re.findall(r"RecordFailure\(err,", self.code))
        self.assertGreater(exits, 0, "found no failure exits to check")
        self.assertEqual(
            exits,
            recorded,
            "the read path has {} failure exit(s) but records {} reason(s); every "
            "return false must be accompanied by a RecordFailure or a caller gets "
            "a bare false with nothing to log".format(exits, recorded),
        )

    def test_no_failure_path_sets_a_bare_win32_code(self):
        # Comments are stripped FIRST because the explanatory text at these sites
        # necessarily quotes the assignment being banned.
        bare = re.findall(r"err->win32\s*=", self.code)
        self.assertEqual(
            len(bare),
            1,
            "expected exactly one err->win32 assignment in this region (the one "
            "inside RecordFailure); found {}. A second means a failure path is "
            "setting a code directly again, which is how a code without a "
            "description gets shipped.".format(len(bare)),
        )

    def test_a_failure_can_never_report_success(self):
        # Error::hasError() is win32 != 0, so a failure that recorded code 0 would
        # produce an error object claiming success.
        self.assertTrue(
            "ERROR_INVALID_FUNCTION" in self.code,
            "RecordFailure must substitute a non-zero code when the platform "
            "reports none, or hasError() can contradict a returned false",
        )

    def test_the_error_is_reset_on_entry(self):
        self.assertTrue(
            "if (err) err->clear();" in self.code,
            "ReadAllBytes must clear the caller's Error on entry; without it an "
            "object written only on failure keeps a previous call's error across "
            "a success",
        )
        reset_at = self.code.find("if (err) err->clear();")
        first_record = self.code.find("RecordFailure(err,", self.code.find("bool ReadAllBytes("))
        self.assertNotEqual(first_record, -1, "no RecordFailure inside ReadAllBytes")
        self.assertLess(
            reset_at,
            first_record,
            "the reset must precede every failure record, otherwise it erases the "
            "reason it was meant to make trustworthy",
        )

    def test_the_read_implementation_can_name_the_file(self):
        self.assertTrue(
            "ReadAllBytesImpl(HANDLE h, std::wstring_view path" in self.code,
            "the implementation needs the path, or its own failures (too large, "
            "allocation, mid-read I/O) cannot say which file they concern",
        )

    def test_the_header_states_the_contract_without_overclaiming_it(self):
        # Read RAW: the contract is documentation, so a stripped read would pass
        # vacuously. It must ALSO be scoped to this one function, because the
        # other error sites in this module do not honour it yet and a module-wide
        # promise here would be false.
        self.assertTrue(
            "ERROR CONTRACT" in self.header_raw,
            "FileUtils.hpp must state the error contract for ReadAllBytes",
        )
        self.assertTrue(
            "not yet for the rest of this" in self.header_raw,
            "the header must say the contract is specific to ReadAllBytes; the "
            "rest of the module still has failure paths that set a code and no "
            "message, and claiming otherwise would be the defect being fixed",
        )


class DatabaseSecurityInitContractTests(unittest.TestCase):
    """A database security step may not be skipped in silence.

    DatabaseManager::Initialize acquires a connection to apply enableSecurity,
    which sets application_id and the integrity-relevant settings. The acquire
    result was tested, but there was no else branch: a failure left the
    connection null, skipped the entire security block, discarded the error
    Acquire had populated, and returned TRUE. Callers were told the database was
    initialized while it ran without the settings that harden it.
    """

    @classmethod
    def setUpClass(cls):
        raw = read_source(DATABASE_MANAGER_CPP_PATH)
        start = raw.find("bool DatabaseManager::Initialize(const DatabaseConfig& config")
        end = raw.find("m_statementCache = std::make_unique<PreparedStatementCache>", start)
        assert start != -1, "DatabaseManager::Initialize not found"
        assert end != -1, "expected landmark inside Initialize not found"
        cls.code = strip_c_comments(raw[start:end])

    def test_a_failed_acquire_refuses_to_report_success(self):
        gate = self.code.find("if (secConn)")
        self.assertNotEqual(gate, -1, "the enableSecurity acquire gate is gone")
        else_at = self.code.find("else", gate)
        self.assertNotEqual(
            else_at,
            -1,
            "there is no else branch after the enableSecurity acquire gate, so a "
            "failed acquire once again skips the security block and lets "
            "Initialize return true",
        )
        tail = self.code[else_at:]
        self.assertTrue(
            "return false;" in tail,
            "the acquire-failure branch does not fail initialization; a database "
            "whose security settings were never applied must not report success",
        )
        self.assertTrue(
            "Shutdown()" in tail,
            "the acquire-failure branch must tear the pool down, as the sibling "
            "enableSecurity failure directly above it already does",
        )

    def test_the_discarded_acquire_error_is_read(self):
        # THE DISCRIMINATOR. Before the fix secErr was declared, handed to
        # Acquire, and never read again - which is exactly why the skip was
        # invisible. Requiring a READ of it cannot pass against that code.
        self.assertTrue(
            "secErr.HasError()" in self.code,
            "secErr must be consulted, not just declared; Acquire populates it on "
            "both of its null paths and dropping it leaves the caller a bare false",
        )
        self.assertTrue(
            "secErr.sqliteCode" in self.code,
            "the log line must name the acquire failure, or an operator cannot "
            "tell a shut-down pool from an acquisition timeout",
        )

    def test_the_caller_error_is_reset_before_any_success(self):
        reset_at = self.code.find("*err = DatabaseError{}")
        self.assertNotEqual(
            reset_at,
            -1,
            "Initialize must reset the caller's error; every site writes it only "
            "on failure, so an object arriving with anything in it keeps that "
            "across a success and HasError() then contradicts the return value",
        )
        guard_at = self.code.find("m_initialized.load(std::memory_order_acquire)")
        self.assertNotEqual(guard_at, -1, "double-initialization guard not found")
        self.assertLess(
            reset_at,
            guard_at,
            "the reset must precede the double-initialization guard, which returns "
            "TRUE - ConfigurationDB, LogDB and QuarantineDB all initialize this "
            "singleton, so every caller after the first takes that early success "
            "and is the most likely place a stale error was observed",
        )


class ProcessNotifyCallbackSemanticsContractTests(unittest.TestCase):
    """A seam must not appear to offer enforcement it cannot perform.

    RealTimeProtection's process callback is dispatched on creation AND
    termination, but was named for creation only, and its shouldBlock
    out-parameter was honoured on both branches. A block for a terminating
    process cannot be delivered: the driver arms a verdict wait only inside its
    IsCreation branch, so the verdict is discarded and the process is leaving
    anyway. Returning Block there would also have moved processesBlocked for an
    enforcement that never happened.

    Every containment check below is written as a boolean rather than assertIn,
    because the haystacks here run to hundreds of kilobytes and a failure that
    prints one is unreadable.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp_raw = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        cls.hpp_raw = read_source(REAL_TIME_PROTECTION_HPP_PATH)
        cls.cpp = strip_c_comments(cls.cpp_raw)
        cls.hpp = strip_c_comments(cls.hpp_raw)
        anchor = cls.cpp.find("std::vector<RTPProcessNotifyCallback> callbackSnapshot;")
        assert anchor != -1, "process-notify dispatch not found in RealTimeProtection.cpp"
        cls.dispatch = cls.cpp[anchor:anchor + 3000]

    def test_the_api_is_named_for_both_branches_it_carries(self):
        stale_found = []
        for label, text in (
            ("RealTimeProtection.cpp", self.cpp),
            ("RealTimeProtection.hpp", self.hpp),
        ):
            for stale in (
                "RegisterProcessCreateCallback",
                "RTPProcessCreateCallback",
                "m_processCreateCallbacks",
            ):
                if stale in text:
                    stale_found.append("{}: {}".format(label, stale))
        self.assertEqual(
            stale_found,
            [],
            "these names say creation only while the callback is dispatched on "
            "termination too: {}".format(stale_found),
        )
        for needed in ("RTPProcessNotifyCallback", "RegisterProcessNotifyCallback"):
            self.assertTrue(
                needed in self.hpp,
                "RealTimeProtection.hpp must declare {}".format(needed),
            )

    def test_a_block_is_honoured_only_on_creation(self):
        self.assertTrue(
            "shouldBlock && req.isCreation" in self.dispatch,
            "the block decision must be gated on the creation branch; the driver "
            "waits for a verdict only there, so a block for a terminating process "
            "is discarded while still being counted as an enforcement",
        )
        ungated = re.findall(r"if\s*\(\s*shouldBlock\s*\)", self.dispatch)
        self.assertEqual(
            ungated,
            [],
            "found an ungated 'if (shouldBlock)' in the dispatch, which honours a "
            "block request for a terminating process",
        )

    def test_an_undeliverable_exit_block_is_counted_not_dropped(self):
        self.assertTrue(
            "processExitBlockRequestsIgnored" in self.dispatch,
            "a block requested on the exit branch must be counted; discarding it "
            "in silence lets a registrant keep believing it is enforcing something",
        )
        self.assertTrue(
            "std::atomic<uint64_t> processExitBlockRequestsIgnored" in self.hpp,
            "the counter must be declared in the statistics struct",
        )

    def test_the_counter_survives_a_statistics_reset(self):
        # A counter absent from Reset() reports pre-reset values afterwards, which
        # this struct's own comment records as worse than no reset at all.
        sibling = self.cpp.find("processNotifyReplyHorizonExceeded = 0;")
        self.assertNotEqual(sibling, -1, "sibling counter reset not found")
        window = self.cpp[sibling:sibling + 300]
        self.assertTrue(
            "processExitBlockRequestsIgnored = 0;" in window,
            "the new counter is not listed in the statistics reset beside its "
            "sibling, so ResetStatistics would leave it holding a stale value",
        )


class LoggerSelfContainmentContractTests(unittest.TestCase):
    """A header must compile on its own, and one binary must not see two language modes.

    Task 96. Utils/Logger.hpp declares its Fatal/Error/Warn/Info/Debug templates in
    terms of std::format_string<Args...> while never including <format>, so every
    consumer had to include <format> BEFORE it or fail to compile. Six translation
    units in the tray carried exactly that workaround - three of them with no
    explanation at all - and the tray project stayed pinned to stdcpp20 because of it,
    while linking PhantomCoreLib.lib which is built at stdcpp23.
    """

    @staticmethod
    def _language_standards(project_text):
        # Parses the ELEMENT form on purpose. A prose mention of a standard inside an
        # XML comment must not satisfy or break this - the comment-versus-code
        # distinction that has produced false readings repeatedly in this suite.
        found = []
        marker = "<LanguageStandard>"
        idx = project_text.find(marker)
        while idx != -1:
            end = project_text.find("</LanguageStandard>", idx)
            if end == -1:
                break
            found.append(project_text[idx + len(marker):end].strip())
            idx = project_text.find(marker, end)
        return sorted(set(found))

    @classmethod
    def setUpClass(cls):
        cls.logger = strip_c_comments(read_source(LOGGER_HPP_PATH))
        cls.tray_proj = read_source(TRAY_VCXPROJ_PATH)
        cls.core_proj = read_source(PHANTOM_CORE_LIB_VCXPROJ_PATH)

    def test_the_logger_header_includes_the_header_of_the_type_it_names(self):
        self.assertTrue(
            "std::format_string" in self.logger,
            "Logger.hpp no longer names std::format_string. If the logging API genuinely "
            "stopped using it, retire this assertion deliberately rather than leaving a "
            "guard that no longer describes the code.",
        )
        self.assertTrue(
            "#include <format>" in self.logger,
            "Logger.hpp names std::format_string but does not include <format>. That is "
            "not a cosmetic omission: it forces every consumer to include <format> first, "
            "an ordering requirement no caller can discover from the declaration.",
        )

    def test_the_tray_compiles_at_the_same_standard_as_the_library_it_links(self):
        core = self._language_standards(self.core_proj)
        tray = self._language_standards(self.tray_proj)
        self.assertTrue(core, "PhantomCoreLib.vcxproj declares no LanguageStandard element.")
        self.assertTrue(tray, "ShadowStrikePhantomTray.vcxproj declares no LanguageStandard element.")
        # Expressed as a RELATION, not a literal. Hardcoding stdcpp23 here would let the
        # two drift apart again the day the library moves on, while this test kept passing.
        self.assertEqual(
            tray,
            core,
            "The tray links PhantomCoreLib.lib and compiles its shared headers, so two "
            "language modes would see one set of declarations - the divergent-view hazard "
            "behind task 73's ODR heap corruption. tray=%s core=%s" % (tray, core),
        )

    def test_no_tray_source_includes_format_without_using_it(self):
        offenders = []
        sources = sorted(TRAY_SOURCE_DIR.glob("*.cpp")) + sorted(TRAY_SOURCE_DIR.glob("*.hpp"))
        self.assertTrue(sources, "no tray sources found; this guard must not pass vacuously")
        for path in sources:
            body = strip_c_comments(read_source(path))
            if "#include <format>" in body and "std::format" not in body:
                offenders.append(path.name)
        self.assertEqual(
            offenders,
            [],
            "These tray sources include <format> without naming std::format, which is the "
            "Logger.hpp ordering workaround returning: %s" % ", ".join(offenders),
        )


class UsbAutoScanOutcomeContractTests(unittest.TestCase):
    """A refused auto-scan must not be counted or logged as a scan that started.

    Task 194. USBScanner::ScanDriveAsync is [[nodiscard]] bool (USBScanner.hpp:664) and
    USBDeviceMonitor discarded it, then incremented scansTriggered and logged
    "Auto-scan started" unconditionally - so a freshly mounted removable volume that
    nothing would ever examine was reported as a scan in progress, on a primary
    infection vector. USBDeviceMonitor.cpp is compiled by PhantomHome / ShadowStrike /
    the service and NOT by PhantomTests, so no C++ test can reach this site and the
    source contract is the only enforceable guard.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp = strip_c_comments(read_source(USB_DEVICE_MONITOR_CPP_PATH))
        cls.hpp = strip_c_comments(read_source(USB_DEVICE_MONITOR_HPP_PATH))

    def test_the_async_scan_result_is_captured(self):
        total = self.cpp.count("scanner.ScanDriveAsync(")
        self.assertEqual(
            total, 1, "expected exactly one auto-scan submission site, found %d" % total
        )
        captured = self.cpp.count("= scanner.ScanDriveAsync(")
        self.assertEqual(
            captured,
            1,
            "the [[nodiscard]] result of ScanDriveAsync is discarded again, so a refused "
            "submission would once more leave a mounted volume unexamined and unreported",
        )

    def test_only_an_accepted_submission_is_counted_and_logged(self):
        start = self.cpp.find("= scanner.ScanDriveAsync(")
        self.assertGreater(start, -1, "no captured ScanDriveAsync call found")
        triggered = self.cpp.find("m_stats.scansTriggered.fetch_add", start)
        gap = self.cpp.find("m_stats.autoScansNotStarted.fetch_add", start)
        self.assertGreater(
            triggered, start, "scansTriggered is incremented before the result is known"
        )
        self.assertGreater(
            gap, triggered, "the refusal counter must sit in the branch after the success one"
        )
        between = self.cpp[start:triggered]
        self.assertTrue(
            "if (scanStarted)" in between,
            "scansTriggered is no longer gated on the submission actually being accepted",
        )

    def test_the_refusal_counter_cannot_become_a_structural_zero(self):
        # The live atomics and the copyable snapshot are separate declarations here and
        # GetStatistics copies field by field, so a counter added to one and not the
        # other reads zero forever - task 102's defect by another route.
        self.assertGreaterEqual(
            self.hpp.count("autoScansNotStarted"),
            2,
            "autoScansNotStarted must be declared in BOTH the live struct and the snapshot",
        )
        for needed in (
            "autoScansNotStarted.store(0",
            "snap.autoScansNotStarted =",
            "autoScansNotStarted.fetch_add",
        ):
            self.assertTrue(needed in self.cpp, "missing plumbing: %s" % needed)
        # Regression guard: the sibling counter it sits beside must stay plumbed too, so
        # this change cannot be "simplified" by dropping the one that already worked.
        for needed in (
            "scansTriggered.store(0",
            "snap.scansTriggered =",
            "scansTriggered.fetch_add",
        ):
            self.assertTrue(needed in self.cpp, "missing sibling plumbing: %s" % needed)


class ConnectionPoolConfigurationContractTests(unittest.TestCase):
    """A pool must refuse what it cannot serve, and must not relabel why it failed.

    Task 195, and this CORRECTS that task's own filed text. minConnections == 0 is NOT
    the defect: Acquire creates on demand up to maxConnections, so a pool that starts
    empty is lazy rather than broken. The configuration that genuinely cannot work is
    maxConnections == 0 - the growth check in Acquire can then never be true, so every
    caller finds nothing, cannot create anything, and waits out the whole busy timeout
    before failing, which presents as contention rather than as a misconfiguration.
    Separately, Acquire handed the CALLER's error object to createConnection and the
    timeout arm then overwrote it with a generic SQLITE_BUSY, so a disk-full or
    permission fault was reported as contention - and a later successful acquire could
    still carry the stale error, the same uncleared out-parameter shape as task 83.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp = strip_c_comments(read_source(DATABASE_MANAGER_CPP_PATH))

    def test_an_unservable_pool_configuration_is_refused_at_initialize(self):
        body = extract_c_function(self.cpp, "ConnectionPool::Initialize")
        self.assertTrue(
            "m_config.maxConnections == 0" in body,
            "ConnectionPool::Initialize accepts maxConnections == 0, a pool that can never "
            "hand out a connection and instead fails at first use after a full timeout.",
        )
        self.assertTrue(
            "m_config.minConnections > m_config.maxConnections" in body,
            "Initialize accepts minConnections above maxConnections, which pre-warms past "
            "the stated ceiling and leaves Acquire's growth check permanently false.",
        )
        self.assertGreaterEqual(
            body.count("return false"),
            3,
            "each refused configuration must fail closed with its own return",
        )

    def test_a_creation_failure_is_not_relabelled_as_contention(self):
        self.assertEqual(
            self.cpp.count("createConnection(&createErr)"),
            1,
            "Acquire must capture the creation error in a local, not in the caller's object",
        )
        self.assertEqual(
            self.cpp.count("createConnection(err)"),
            1,
            "only ConnectionPool::Initialize may pass the caller's error object to "
            "createConnection; Acquire doing so is what let a later timeout overwrite the "
            "specific cause and what left a stale error on a successful acquire",
        )
        self.assertEqual(
            self.cpp.count("*err = firstCreateFailure;"),
            1,
            "the specific creation failure must be reported instead of the generic timeout",
        )
        self.assertEqual(
            self.cpp.count('err->message = L"Connection acquisition timeout";'),
            1,
            "the generic timeout message must survive for the case where nothing actually "
            "failed to be created - that case is real contention and should say so",
        )


class RegistryDecisionHookLockContractTests(unittest.TestCase):
    """RegistryProtection must never invoke a caller's decision hook while it
    holds m_mutex.

    std::shared_mutex is NOT recursive. A decision callback that calls back into
    RegistryProtection - AddProtectedKey, SetDecisionCallback, IsKeyProtected,
    GetStatistics - acquires m_mutex a second time, and if a writer has queued
    between the two acquisitions the shared re-acquisition waits behind that
    writer while the first acquisition is still held. That is a self-deadlock on
    a thread that may owe the kernel a registry verdict.

    These are source contracts on purpose, and that choice is worth recording.
    Driving the deadlock behaviourally would mean registering a re-entrant
    callback and depending on the timing of a queued writer, and recursive
    lock_shared is undefined behaviour that usually appears to work - so such a
    test would either pass against the defect or hang the entire suite. Neither
    outcome discriminates.
    """

    START_ANCHOR = (
        "RegistryOperationDecisionResult FilterOperation("
        "const RegistryOperationRequest& request) {"
    )
    END_ANCHOR = "void SetDecisionCallback(RegistryOperationDecisionCallback callback) {"

    @classmethod
    def _body(cls) -> str:
        # Comments are stripped FIRST and that is load-bearing here: the fix's own
        # explanatory comment quotes the retired expression m_decisionCallback(
        # and the phrase "safely under lock" verbatim, so a comment-blind
        # assertion would be satisfied - or broken - by prose.
        src = strip_c_comments(read_source(REGISTRY_PROTECTION_CPP_PATH))
        assert src.count(cls.START_ANCHOR) == 1, "FilterOperation start anchor is not unique"
        assert src.count(cls.END_ANCHOR) == 1, "SetDecisionCallback end anchor is not unique"
        start = src.index(cls.START_ANCHOR)
        end = src.index(cls.END_ANCHOR)
        assert end > start, "anchors are out of order"
        return src[start:end]

    def test_the_registry_decision_hook_is_not_invoked_while_the_lock_is_held(self):
        body = self._body()

        self.assertEqual(
            body.count("m_decisionCallback("),
            0,
            "FilterOperation must not call the member m_decisionCallback directly - "
            "the member is only reachable under m_mutex, so calling it there is the "
            "re-entrancy deadlock; snapshot it and call the copy",
        )
        self.assertEqual(
            body.count("callbackCopy = m_decisionCallback;"),
            1,
            "FilterOperation must snapshot the decision hook exactly once",
        )
        self.assertEqual(
            body.count("callbackCopy(request)"),
            1,
            "FilterOperation must invoke the snapshot exactly once",
        )
        self.assertEqual(
            body.count("std::shared_lock"),
            1,
            "FilterOperation should hold m_mutex for exactly one scope - the snapshot; "
            "a second acquisition is the lock cycle this fix removed",
        )

        lock_at = body.index("std::shared_lock")
        snapshot_at = body.index("callbackCopy = m_decisionCallback;")
        invoke_at = body.index("callbackCopy(request)")

        self.assertLess(
            lock_at,
            snapshot_at,
            "the snapshot must be taken INSIDE the lock or it races SetDecisionCallback "
            "(lock at offset %d, snapshot at offset %d)" % (lock_at, snapshot_at),
        )
        self.assertLess(
            lock_at,
            invoke_at,
            "the only lock scope must open before the invocation site so that the "
            "invocation can sit after it closes (lock at offset %d, invoke at offset %d)"
            % (lock_at, invoke_at),
        )
        self.assertEqual(
            body.count("lock.unlock()"),
            0,
            "there is no named lock left to unlock; a reappearing manual unlock means "
            "the callback is being invoked under a lock again",
        )

    def test_the_registry_filter_keeps_the_coverage_it_had_before_the_lock_fix(self):
        # REGRESSION GUARD, not a discriminator: the lock fix restructured this
        # function, so the decisions it used to make must still be reachable.
        body = self._body()

        for needle, why in (
            ("IsProcessWhitelisted(request.processId)", "whitelisted-process early return"),
            ("IsKeyProtectedInternal(request.keyPath)", "protected-key test"),
            (
                r'key.includeSubkeys && normalized.starts_with(path + L"\\")',
                "parent-key walk that gives subkey protection its coverage",
            ),
            ("FireBlockedOperationEvent(request, result)", "blocked-operation event fan-out"),
            ("m_stats.totalBlocked.fetch_add", "blocked counter"),
        ):
            self.assertEqual(
                body.count(needle),
                1,
                "FilterOperation lost its %s" % why,
            )


class BatchScanConcurrencyContractTests(unittest.TestCase):
    """ScanEngine::ScanBatch must bound the work it puts in flight, and a
    stop-on-first-infection request must reach work already dispatched.

    Two measured facts sit behind these guards. (1) ScanBatch is reached from
    ScanDirectory, and ScanDirectory is what CreateScanJob submits to the engine
    thread pool - so ScanBatch itself runs on a pool worker, which is why its
    per-file work must NOT be routed back into that same bounded pool. (2) a
    std::async future's destructor blocks until its task completes, so abandoning
    futures does not cancel anything.
    """

    START_ANCHOR = "BatchScanResult ScanEngine::ScanBatch("
    END_ANCHOR = "std::future<BatchScanResult> ScanEngine::ScanBatchAsync("

    @classmethod
    def _body(cls) -> str:
        src = strip_c_comments(read_source(SCAN_ENGINE_CPP_PATH))
        assert src.count(cls.START_ANCHOR) == 1, "ScanBatch start anchor is not unique"
        assert src.count(cls.END_ANCHOR) == 1, "ScanBatchAsync end anchor is not unique"
        start = src.index(cls.START_ANCHOR)
        end = src.index(cls.END_ANCHOR)
        assert end > start, "anchors are out of order"
        return src[start:end]

    def test_the_batch_scan_bounds_its_in_flight_work(self):
        body = self._body()

        self.assertEqual(
            body.count("m_impl->m_threadPool"),
            0,
            "ScanBatch must not test for the engine thread pool: it is reached from "
            "ScanDirectory, which CreateScanJob submits to that pool, so a gate on the "
            "pool reads as though the pool were used and routing work into it would "
            "deadlock a worker behind its own queued tasks",
        )
        self.assertEqual(
            body.count("futures.size() - awaited >= windowSize"),
            1,
            "ScanBatch must hold at most windowSize scans in flight; without the window "
            "one chore is launched per path and the caller's maxConcurrency is ignored",
        )
        self.assertEqual(
            body.count("std::async(std::launch::async, scanTask, path)"),
            1,
            "the batch should dispatch through exactly one site",
        )
        self.assertEqual(
            body.count("if (scanTask(path) && request.stopOnFirstInfection) {"),
            1,
            "the single-threaded fallback must survive",
        )

    def test_the_batch_scan_stop_request_reaches_work_already_dispatched(self):
        body = self._body()

        self.assertEqual(
            body.count("std::atomic<bool> stopRequested{false};"),
            1,
            "the stop request must be shared state, not a local return value",
        )
        self.assertEqual(
            body.count("stopRequested.store(true, std::memory_order_relaxed)"),
            2,
            "an infection must set the stop request from BOTH the windowed wait and the "
            "drain; setting it in only one leaves the other draining the whole batch",
        )
        self.assertGreaterEqual(
            body.count("stopRequested.load(std::memory_order_relaxed)"),
            2,
            "the stop request must be read by the dispatch loop AND by the task itself",
        )

        scan_call = "auto result = ScanFile(filePath, request.context);"
        self.assertEqual(
            body.count(scan_call),
            1,
            "the per-file scan should have exactly one call site in this function",
        )

        first_load = body.index("stopRequested.load(std::memory_order_relaxed)")
        scan_at = body.index(scan_call)
        self.assertLess(
            first_load,
            scan_at,
            "the task must consult the stop request BEFORE scanning, or a stop only "
            "moves the waiting into the future destructors and every remaining file is "
            "still scanned (load at offset %d, scan at offset %d)" % (first_load, scan_at),
        )


class ShadowCopyFoldOrderContractTests(unittest.TestCase):
    """Task 191: the analysis core's case fold and its keyword comparison.

    NEITHER invariant below can fail on this build host, which is exactly why
    both are pinned as source contracts rather than left to the behavioural
    suite:

      * The fold must run the ASCII pass FIRST and ::CharLowerBuffW SECOND.
        Reversed, ::CharLowerBuffW maps L'I' to the dotless i (U+0131) under a
        Turkish user default locale before the ASCII pass can canonicalise it,
        so "VSSADMIN DELETE SHADOWS" folds to a string matching none of the
        ASCII keywords and every T1490 detection in the module goes dark. On
        this host the two folds AGREE - measured, ACP 1254 but LCID 1033 - so
        no run here would fail. The miss appears only on a Turkish endpoint.

      * Every keyword compared through FoldedContains() must be lowercase
        ASCII. FoldedContains compares EXACTLY by design, so a single uppercase
        character in a needle makes that phase permanently unmatchable while
        raising nothing at all.

    Both failures are silent, which is this codebase's signature failure mode.
    """

    def setUp(self) -> None:
        # The explanatory comments in this region necessarily quote every symbol
        # asserted below, including the retired WideIContains, so strip comments
        # before counting anything or the assertions become self-satisfying.
        self.src = strip_c_comments(read_source(SHADOW_COPY_PROTECTOR_CPP_PATH))

    def test_the_ascii_fold_runs_before_the_locale_dependent_one(self) -> None:
        body = extract_c_function(self.src, "ToLowerInPlace")
        self.assertGreater(
            len(body), 0, "ToLowerInPlace body could not be extracted")

        ascii_at = body.find("AsciiToLower")
        locale_at = body.find("CharLowerBuffW")

        self.assertNotEqual(
            ascii_at, -1,
            "ToLowerInPlace no longer applies the ASCII fold. Without it "
            "::CharLowerBuffW decides the fate of L'I' according to the user "
            "default locale, and every ASCII keyword in this module stops "
            "matching on a Turkish-locale endpoint.")
        self.assertNotEqual(
            locale_at, -1,
            "ToLowerInPlace no longer calls ::CharLowerBuffW. An ASCII-only "
            "fold loses the characters Unicode folds INTO ASCII - U+212A "
            "KELVIN SIGN lowercases to 'k' and \"diskshadow\" contains a 'k' - "
            "so removing this pass narrows detection.")
        self.assertLess(
            ascii_at, locale_at,
            "ToLowerInPlace applies ::CharLowerBuffW at offset {} BEFORE the "
            "ASCII fold at offset {}. The order is the whole point: the ASCII "
            "pass must canonicalise A-Z while it is still ASCII, because once "
            "a Turkish-locale ::CharLowerBuffW has turned L'I' into the "
            "dotless i (U+0131) no later ASCII pass can recover it."
            .format(locale_at, ascii_at))

    def test_the_folded_comparison_never_folds_again(self) -> None:
        body = extract_c_function(self.src, "FoldedContains")
        self.assertIn(
            ".find(", body,
            "FoldedContains is no longer an exact find. It exists to be exact: "
            "its haystack is already folded, so any per-character fold here is "
            "the redundant work task 191 removed (2,837,605 ns -> 235,440 ns "
            "at maximum command-line length).")

        refolds = [needle for needle in ("towlower", "CharLowerBuffW",
                                         "AsciiToLower", "std::search")
                   if needle in body]
        self.assertEqual(
            [], refolds,
            "FoldedContains has regained a per-character fold or comparator "
            "search ({}). That reinstates the cost this guard exists to "
            "prevent, on the callback the kernel blocks CreateProcess on."
            .format(", ".join(refolds)))

        self.assertEqual(
            0, self.src.count("WideIContains"),
            "WideIContains has returned. It was removed because every one of "
            "its 48 call sites ran a towlower comparator over an already-"
            "folded haystack; reintroducing it re-creates the 5.7x budget "
            "violation task 191 closed.")

    def test_every_folded_keyword_is_lowercase_ascii(self) -> None:
        sites = re.findall(
            r'FoldedContains\s*\(\s*\w+\s*,\s*L"([^"]*)"', self.src)
        # Refuse to pass vacuously: if the walk stops finding call sites the
        # guard has silently stopped guarding, which is worse than no guard.
        self.assertGreaterEqual(
            len(sites), 40,
            "only {} FoldedContains literal call sites were found, so this "
            "assertion is no longer inspecting the phases it was written for"
            .format(len(sites)))

        offenders = [lit for lit in sites if any(ch.isupper() for ch in lit)]
        self.assertEqual(
            [], offenders,
            "these FoldedContains keywords contain an uppercase character: {}. "
            "FoldedContains compares exactly against a folded haystack, so an "
            "uppercase needle can never match and the phase using it is dead "
            "without reporting anything."
            .format(offenders))

    def test_the_safe_command_table_is_lowercase_ascii(self) -> None:
        # SAFE_COMMAND_PATTERNS supplies the only two NON-literal needles
        # (keyword1 / keyword2). An uppercase entry there would stop
        # IsSafeCommand recognising a benign "vssadmin list", turning it into a
        # false T1490 conviction - a false positive on an administrative
        # command, which is the opposite failure to the one above and worse for
        # the operator.
        start = self.src.find("SAFE_COMMAND_PATTERNS")
        self.assertNotEqual(
            start, -1, "SAFE_COMMAND_PATTERNS was not found")
        window = self.src[start:start + 2000]
        values = re.findall(r'L"([^"]*)"', window)
        self.assertGreaterEqual(
            len(values), 2,
            "no keyword literals were found near SAFE_COMMAND_PATTERNS, so "
            "this assertion is inspecting nothing")

        offenders = [v for v in values if any(ch.isupper() for ch in v)]
        self.assertEqual(
            [], offenders,
            "these SAFE_COMMAND_PATTERNS keywords contain an uppercase "
            "character: {}. They are matched with FoldedContains against a "
            "folded command line, so an uppercase entry silently stops the "
            "safe-command allowance from ever firing."
            .format(offenders))



class CallbackVocabularyContractTests(unittest.TestCase):
    """Two headers, one namespace: their declared-name intersection must stay empty.

    Communication.hpp and IPCManager.hpp are BOTH ShadowStrike::Communication, and
    each declares a callback vocabulary. IPCManager's takes the packed kernel
    structs and returns SHADOWSTRIKE_SCAN_VERDICT; Communication's takes the
    decoded C++ representations MessageDispatcher's parsers produce and returns the
    rich ScanVerdictReply. Two vocabularies for two layers is correct. What was
    wrong is that two of the NAMES were identical, so the same fully-qualified name
    meant different things depending on include order.

    That was papered over with a one-sided "#ifndef SS_IPC_CALLBACK_TYPES_DEFINED"
    in Communication.hpp, which failed in two ways:

      1. It suppressed only that side, so Communication.hpp first was a hard C2371.
         Three production sources carried the working order by hand.
      2. It suppressed ALL SEVEN aliases in that block whenever IPCManager.hpp won,
         including the five that collided with nothing - so a translation unit
         including IPCManager.hpp first could not name FileNotifyCallback or
         ConnectionStateCallback at all, and got an undeclared-identifier
         diagnostic that named neither the guard nor the conflict.

    Task 117 renamed the decoded side to Parsed*. This test recomputes the
    intersection instead of pinning those two names, because the next collision
    could be on ANY name a future edit adds to either header - a naming prefix
    cannot prevent that, and the resulting compile failure would surface in
    whichever unrelated translation unit happened to include both.
    """

    _WIRE_FORMAT_TESTS = ROOT / "tests/unit/wire_format/WireFormat_Tests.cpp"

    @staticmethod
    def _declared_names(code):
        """Type names declared at the top level of a header, comments already gone."""
        names = set()
        names |= set(re.findall(r"(?m)^\s*(?:struct|class)\s+([A-Za-z_]\w*)\s*(?:final\s*)?[{:]", code))
        names |= set(re.findall(r"(?m)^\s*enum\s+class\s+([A-Za-z_]\w*)", code))
        names |= set(re.findall(r"(?m)^\s*using\s+([A-Za-z_]\w*)\s*=", code))
        return names

    def test_the_two_communication_headers_declare_no_name_in_common(self):
        comm_names = self._declared_names(strip_c_comments(read_source(COMMUNICATION_HPP_PATH)))
        ipc_names = self._declared_names(strip_c_comments(read_source(IPC_MANAGER_HPP_PATH)))

        # ANTI-VACUITY. An empty intersection is exactly what a broken extraction
        # also produces, so require both scans to have found something and to have
        # found the specific anchors this contract is about.
        self.assertGreaterEqual(
            len(comm_names), 15,
            "declaration scan of Communication.hpp collapsed to %d names, so the "
            "intersection below would pass for the wrong reason" % len(comm_names))
        self.assertGreaterEqual(
            len(ipc_names), 15,
            "declaration scan of IPCManager.hpp collapsed to %d names, so the "
            "intersection below would pass for the wrong reason" % len(ipc_names))
        for anchor in ("FileScanCallback", "ProcessNotifyCallback"):
            self.assertTrue(
                anchor in ipc_names,
                "IPCManager.hpp no longer declares %s, so this test is no longer "
                "watching the vocabulary it was written for" % anchor)
        for anchor in ("ParsedFileScanCallback", "ParsedProcessNotifyCallback"):
            self.assertTrue(
                anchor in comm_names,
                "Communication.hpp no longer declares %s, so this test is no longer "
                "watching the vocabulary it was written for" % anchor)

        overlap = sorted(comm_names & ipc_names)
        self.assertEqual(
            overlap, [],
            "Communication.hpp and IPCManager.hpp are both namespace "
            "ShadowStrike::Communication and now declare these names on BOTH "
            "sides: %s. If the types differ, any translation unit including both "
            "fails to compile and the error names whichever unrelated file did so. "
            "Rename one side. Do NOT add an #ifndef guard: the last one suppressed "
            "five unrelated aliases in the same block and made include order "
            "decide whether a file compiled." % ", ".join(overlap))

    def test_the_include_order_guard_is_not_reintroduced(self):
        # Comments are stripped FIRST and that is load-bearing: the explanatory
        # comments left at both sites necessarily NAME the retired macro, so a
        # comment-blind scan reports one hit per header and is guaranteed to
        # false-positive.
        for path, label in ((COMMUNICATION_HPP_PATH, "Communication.hpp"),
                            (IPC_MANAGER_HPP_PATH, "IPCManager.hpp")):
            code = strip_c_comments(read_source(path))
            offenders = [
                "%s:%d" % (label, i + 1)
                for i, line in enumerate(code.splitlines())
                if "SS_IPC_CALLBACK_TYPES_DEFINED" in line
            ]
            self.assertEqual(
                offenders, [],
                "the retired include-order guard is back in code at %s. It cannot "
                "fix a name collision - it hides one in a single include order "
                "while suppressing every other declaration in the same block."
                % ", ".join(offenders))

    def test_the_decoded_vocabulary_is_consumed_under_its_own_names(self):
        code = strip_c_comments(read_source(MESSAGE_DISPATCHER_CPP_PATH))

        # The lookbehind matters: it stops ParsedFileScanCallback from matching
        # FileScanCallback, so this counts genuinely bare uses only.
        for bare in ("FileScanCallback", "ProcessNotifyCallback", "RegistryNotifyCallback",
                     "FileNotifyCallback", "ProcessEventCallback", "RegistryEventCallback"):
            stray = re.findall(r"(?<![A-Za-z0-9_])" + bare + r"\b", code)
            self.assertEqual(
                stray, [],
                "MessageDispatcher.cpp names the bare alias %s %d time(s). It "
                "consumes the DECODED vocabulary, whose names carry the Parsed "
                "prefix; the bare spelling now resolves to IPCManager.hpp's "
                "wire-typed alias over the packed kernel struct, which is a "
                "different contract that happens to be spelled the same way."
                % (bare, len(stray)))

        used = re.findall(r"\bParsed\w+Callback\b", code)
        self.assertGreaterEqual(
            len(used), 20,
            "only %d Parsed* callback uses found in MessageDispatcher.cpp, so the "
            "check above would pass vacuously against a file that stopped "
            "consuming this vocabulary at all" % len(used))

    def test_a_translation_unit_still_proves_the_two_headers_coexist(self):
        """The compile-time half of the fix, pinned so it cannot quietly vanish.

        WireFormat_Tests.cpp includes Communication.hpp and then IPCManager.hpp.
        That order was the fatal one, so the file simply cannot build against the
        pre-fix tree - which makes it the discriminator. Nothing in a passing suite
        would notice if a future edit dropped the second include, so the ordering
        is asserted here rather than left to chance.
        """
        code = strip_c_comments(read_source(self._WIRE_FORMAT_TESTS))
        comm_at = code.find("Communication/Communication.hpp")
        ipc_at = code.find("Communication/IPCManager.hpp")

        self.assertNotEqual(
            comm_at, -1, "WireFormat_Tests.cpp no longer includes Communication.hpp")
        self.assertNotEqual(
            ipc_at, -1,
            "WireFormat_Tests.cpp no longer includes IPCManager.hpp, so the only "
            "translation unit proving the two headers can coexist is gone")
        self.assertLess(
            comm_at, ipc_at,
            "Communication.hpp must be included BEFORE IPCManager.hpp here "
            "(offsets %d and %d). Reversing them is the order that always worked, "
            "so it would prove nothing." % (comm_at, ipc_at))
        self.assertEqual(
            code.count("BothVocabulariesAreNameableInOneTranslationUnit"), 1,
            "the case that spends both callback names is gone or duplicated; "
            "compiling alone would also be satisfied by a guard that left one of "
            "the two contracts unnameable")



class PhantomEdrIncludeResolutionContractTests(unittest.TestCase):
    """The PhantomEDR tree must not reach its dependencies with parent-relative includes.

    THE DEFECT THIS GUARDS, measured rather than inferred. Twelve sources under
    src/Products/Community/PhantomEDR spelled their shared-infrastructure includes
    as "../Utils/<Header>.hpp", and a thirteenth used "../../PhantomCore/Config/..."
    and "../<Store>/...". None of those can resolve:

      * There is NO Utils directory under PhantomEDR. Nor is there one at any other
        point a parent-relative path could land on - repo-root Utils, include/Utils,
        src/Utils, src/Products/Utils and src/Products/Community/Utils were all
        checked and none exists.
      * The projects that compile these files search $(ProjectDir)include,
        $(ProjectDir)include\\YARA and $(ProjectDir)src, so no include directory
        makes a leading "../" resolve either.

    The consequence was a FATAL C1083 - measured directly, not assumed:
    compiling ArtifactExtractor.cpp through ShadowStrike.vcxproj exited 1 with
    "C1083 ... '../Utils/Logger.hpp': No such file or directory" raised from
    ArtifactExtractor.hpp:139. Because C1083 is fatal, every later error in those
    translation units was invisible, which is why this subsystem's real defects went
    unrecorded for so long.

    THE CONTROL IS WHAT MAKES THE FIX PROVABLE. AssetInventory/AssetDatabase.cpp
    sits in the SAME tree, is compiled by the SAME project with the SAME include
    directories and the SAME toolset, and uses the "PhantomCore/Utils/..." form.
    It compiles with exit 0 and zero errors. One spelling resolves and the other
    cannot, with every other variable held constant.

    WHY PhantomCore AND NOT PhantomHome, since several of these header names exist
    under both: TimeUtils.hpp and DatabaseUtils.hpp exist ONLY under
    src/PhantomCore/Utils, PhantomHome's Logger.hpp is a 418-byte stub declaring
    none of the severities these files call, and PhantomEDR is a different product
    from PhantomHome so depending on its Utils would be a cross-product edge. The
    rest of this tree already agrees: 46 files reach PhantomCore this way.

    WHY THIS GUARD IS DELIBERATELY NARROW. It pins the include CONVENTION and the
    resolvability of the PhantomCore form. It does NOT assert that every include in
    the tree resolves, because two files reach for a bare "sqlite3.h" that no search
    path provides while the header actually sits at include/SQLiteCpp/sqlite3.h -
    a separate defect with its own task. Widening this guard before that is fixed
    would make it fail on the tree it ships with, and a guard that cannot pass is
    a guard nobody keeps.
    """

    _EDR_ROOT = ROOT / "src" / "Products" / "Community" / "PhantomEDR"
    _SRC_ROOT = ROOT / "src"
    _SOURCE_SUFFIXES = (".cpp", ".hpp", ".h")

    def _phantomedr_sources(self):
        return sorted(
            path
            for path in self._EDR_ROOT.rglob("*")
            if path.is_file() and path.suffix in self._SOURCE_SUFFIXES
        )

    def _quoted_includes(self, pattern):
        """Yield (relative_path, line_number, include_target) for each match.

        Comments are stripped FIRST. The explanatory comments added by the commit
        that fixed this defect necessarily quote the retired "../Utils/" spelling,
        so a comment-blind scan would report offenders that are prose.
        """
        compiled = re.compile(r'\s*#\s*include\s+"(' + pattern + r')"')
        for path in self._phantomedr_sources():
            code = strip_c_comments(read_source(path).lstrip("\ufeff"))
            relative = path.relative_to(self._EDR_ROOT).as_posix()
            for line_no, line in enumerate(code.splitlines(), start=1):
                match = compiled.match(line)
                if match:
                    yield relative, line_no, match.group(1)

    def test_no_phantomedr_source_reaches_a_dependency_with_a_parent_relative_include(self):
        sources = self._phantomedr_sources()
        self.assertGreaterEqual(
            len(sources),
            100,
            "anti-vacuity: expected at least 100 sources under PhantomEDR, found "
            f"{len(sources)}. A walk that finds nothing would satisfy the offender "
            "assertion below while proving nothing at all.",
        )

        total = 0
        offenders = []
        for relative, line_no, target in self._quoted_includes(r"[^\"]+"):
            total += 1
            if target.startswith("../") or "/../" in target:
                offenders.append(f"{relative}:{line_no} -> {target}")

        self.assertGreaterEqual(
            total,
            150,
            "anti-vacuity: expected at least 150 quoted includes across the "
            f"PhantomEDR tree, found {total}.",
        )
        self.assertEqual(
            [],
            offenders,
            "a parent-relative include cannot resolve from this tree - there is no "
            "Utils directory under PhantomEDR and no include directory makes a "
            "leading '../' resolve, so the compiler stops with a FATAL C1083 and "
            "hides every later error in the translation unit. Use the "
            "PhantomCore/... form, which is what the rest of this tree uses and "
            "what is measured to compile.",
        )

    def test_every_phantomcore_include_in_phantomedr_resolves_to_a_real_header(self):
        checked = 0
        missing = []
        for relative, line_no, target in self._quoted_includes(r"PhantomCore/[^\"]+"):
            checked += 1
            if not (self._SRC_ROOT / target).is_file():
                missing.append(f"{relative}:{line_no} -> {target}")

        self.assertGreaterEqual(
            checked,
            180,
            "anti-vacuity: expected at least 180 PhantomCore/ includes across the "
            f"PhantomEDR tree, found {checked}. The tree carried 154 before the 64 "
            "unresolvable includes were converted, so a count below this floor "
            "means either the conversion was reverted or the walk stopped working.",
        )
        self.assertEqual(
            [],
            missing,
            "a PhantomCore/... include must name a header that exists under src/. "
            "Spelling alone is not the contract - resolvability is, because an "
            "include that looks conventional and resolves to nothing produces the "
            "same fatal C1083 as the parent-relative form it replaced.",
        )



class ProductProjectBuildabilityContractTests(unittest.TestCase):
    """Pins the project-file invariants that decide whether a product can be built at all.

    Every defect guarded here was measured while making PhantomHome compile, and
    every one of them is INVISIBLE to the C++ test suite: a project that cannot be
    evaluated, or that lists a source which does not exist, or that discards the
    macros its own CharacterSet contributes, produces no failing test - it produces
    a build nobody runs.  PhantomHome had all four at once while the suite was green.

    Scoped deliberately:
      * the source-existence rule covers every user-mode project, because a listed
        file that is absent is unambiguously wrong wherever it appears;
      * the object-path rule covers PhantomHome ONLY.  ShadowStrike.vcxproj has NINE
        same-named pairs and no ObjectFileName (task 197), so asserting it tree-wide
        would land a guard that cannot pass, and a guard that cannot pass is a guard
        nobody keeps.  Widen it in the change that fixes 197, not before.

    PhantomEDR and PhantomXDR are deliberately absent from the project list.  Both
    still name an uninstalled toolset so they cannot be evaluated at all (task 202),
    and both carry the same stale source entries this guard rejects.  They join the
    list when they come into scope; excluding them is a scope statement, not an
    oversight.

    NAMING, because two different things shared one word until task 211.  PhantomHome
    is the PRODUCT: its sources live under src/Products/Community/PhantomHome and its
    shipped host is ShadowStrikePhantomService.exe.  PhantomHomeModules.vcxproj is the
    project that compile-verifies that product tree, and it ships nothing.  That
    project was called PhantomHome.vcxproj until the rename, so narrative prose below
    still says "PhantomHome" where it describes what the project did at the time; that
    is deliberate and accurate about the past.  Assertions and the failure messages a
    reader actually sees name the project as it is called now.
    """

    _USER_MODE_PROJECTS = (
        "PhantomHomeModules.vcxproj",
        "ShadowStrike.vcxproj",
        "PhantomCoreLib.vcxproj",
        "PhantomTests.vcxproj",
        "ShadowStrikePhantomService.vcxproj",
        "ShadowStrikePhantomTray.vcxproj",
    )

    # Toolsets present on a machine that can build this tree.  v145 is NOT installed
    # anywhere and a project naming it dies at MSB8020 before one file is compiled,
    # so the failure is invisible to any source-level test.
    _INSTALLED_USER_MODE_TOOLSETS = ("v143",)

    # ---------------------------------------------------------------------------
    # Two project-file defects that are now ABSENT from the in-scope project and
    # still PRESENT in three that are not.  Both are expressed as SHRINK-ONLY
    # ceilings rather than equalities, for a reason worth stating: an equality
    # guard over the whole tree would be red on arrival, and a guard that cannot
    # pass is a guard nobody keeps (the same reasoning that scopes the object-path
    # rule above).  A ceiling pins the out-of-scope debt at its measured value so
    # it is on the record and cannot grow, and it fails the moment the in-scope
    # project regresses.  Lower a number when a project is fixed; never raise one.
    # ---------------------------------------------------------------------------

    # An absolute machine-specific toolchain path baked into a project file.
    #
    # WHY THIS IS A DEFECT AND NOT MERELY UNTIDY, measured rather than assumed:
    # C:\Program Files (x86)\Windows Kits\10\Include contains ZERO files - only the
    # version directories 10.0.26100.0 and wdf - so no #include can resolve through
    # it.  The compiler receives the /I, searches the directory, finds nothing, and
    # moves on.  The Windows SDK reaches the compiler through the toolset's own
    # $(IncludePath); PhantomCoreLib, PhantomTests and ShadowStrikePhantomService
    # name no Windows Kits path at all and compile the same headers successfully.
    # So the entry contributes nothing to a build while hardcoding one developer's
    # SDK layout into projects that CI builds on a machine whose layout we do not
    # control - it can only ever start being wrong, never start being useful.
    _ABSOLUTE_TOOLCHAIN_PATH_CEILING = {
        "PhantomHomeModules.vcxproj": 0,
        "ShadowStrike.vcxproj": 2,
        "PhantomEDR.vcxproj": 2,
        "PhantomXDR.vcxproj": 2,
    }

    # A precompiled-header output name carrying a literal '$'.
    #
    # $(IntDir)$pch.pch is a typo, not a convention: MSBuild substitutes only on
    # $( , so "$p" is literal text and the compiler is told to write a file whose
    # name begins with a dollar sign.  It did - a real 207 MB '$pch.pch' sat in the
    # intermediate directory.  PhantomCoreLib and the Service both write
    # $(IntDir)pch.pch, which is what the author of the other four meant, and that
    # pair is what makes this a measured typo rather than a style judgement.
    _BROKEN_PCH_OUTPUT_NAME_CEILING = {
        "PhantomHomeModules.vcxproj": 0,
        "ShadowStrike.vcxproj": 2,
        "PhantomEDR.vcxproj": 2,
        "PhantomXDR.vcxproj": 2,
    }

    @classmethod
    def _project_text(cls, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8").lstrip("\ufeff")

    @classmethod
    def _compiled_sources(cls, name: str) -> list[str]:
        text = cls._project_text(name)
        return re.findall(r'<ClCompile\s+Include="([^"]+)"', text)

    def test_no_user_mode_project_lists_a_source_that_does_not_exist(self) -> None:
        missing: list[str] = []
        per_project: dict[str, int] = {}
        for project in self._USER_MODE_PROJECTS:
            listed = self._compiled_sources(project)
            per_project[project] = len(listed)
            for rel in listed:
                if not (ROOT / rel.replace("\\", "/")).is_file():
                    missing.append(f"{project} -> {rel}")
        total = sum(per_project.values())

        # Anti-vacuity, PER PROJECT rather than in aggregate.  An aggregate floor
        # cannot distinguish a project that legitimately shrank from one whose parse
        # broke, and it goes stale as soon as a project stops recompiling sources it
        # can borrow: this floor read 1500 while PhantomHome hand-listed 317 sources
        # that PhantomCoreLib already compiles, and reading 1496 after task 205 moved
        # 238 of them behind a library reference was a stale constant, not a defect.
        empty = sorted(name for name, count in per_project.items() if count == 0)
        self.assertEqual(
            [],
            empty,
            msg=(
                "these projects yielded no ClCompile entries at all, so this walk "
                f"proves nothing about them: {empty}"
            ),
        )
        self.assertGreater(
            total,
            1200,
            msg=(
                "expected the six user-mode projects to list >1200 sources, walked "
                f"{total} ({per_project})"
            ),
        )
        self.assertEqual(
            [],
            missing,
            msg=(
                "a project lists a ClCompile source that is absent from the tree; "
                "MSVC reports this as fatal C1083 at build time only. "
                f"offenders: {missing}"
            ),
        )

    def test_phantomhome_names_a_toolset_that_is_installed(self) -> None:
        text = self._project_text("PhantomHomeModules.vcxproj")
        declared = re.findall(r"<PlatformToolset>([^<]+)</PlatformToolset>", text)
        self.assertEqual(
            4,
            len(declared),
            msg=f"expected one PlatformToolset per configuration, found {len(declared)}",
        )
        bad = sorted({t for t in declared if t not in self._INSTALLED_USER_MODE_TOOLSETS})
        self.assertEqual(
            [],
            bad,
            msg=(
                "PhantomHomeModules names a platform toolset that is not installed, so MSBuild "
                "fails at project evaluation (MSB8020) and compiles nothing. "
                f"offending toolsets: {bad}"
            ),
        )

    def test_phantomhome_compiles_against_the_unicode_windows_api(self) -> None:
        text = self._project_text("PhantomHomeModules.vcxproj")

        charsets = re.findall(r"<CharacterSet>([^<]+)</CharacterSet>", text)
        self.assertEqual(
            ["Unicode"] * 4,
            charsets,
            msg=(
                "every configuration must state CharacterSet Unicode; without it TCHAR "
                "resolves to char and every unsuffixed Win32 call binds to its ANSI "
                "variant, which cannot carry a path outside the active code page. "
                f"found: {charsets}"
            ),
        )

        # CharacterSet contributes UNICODE/_UNICODE through inherited item metadata,
        # so a definitions list that omits %(PreprocessorDefinitions) silently
        # discards it.  That is exactly how the C2664 on SE_LOAD_DRIVER_NAME survived
        # the CharacterSet being set correctly.
        blocks = re.findall(
            r"<PreprocessorDefinitions>(.*?)</PreprocessorDefinitions>",
            text,
            re.DOTALL,
        )
        self.assertGreaterEqual(
            len(blocks),
            4,
            msg=f"expected at least one PreprocessorDefinitions per configuration, found {len(blocks)}",
        )
        non_inheriting = [
            b.replace("\n", " ").strip()
            for b in blocks
            if "%(PreprocessorDefinitions)" not in b
        ]
        self.assertEqual(
            [],
            non_inheriting,
            msg=(
                "a PreprocessorDefinitions list replaces the inherited set instead of "
                "extending it, so macros contributed by CharacterSet are dropped. "
                f"offending blocks: {non_inheriting}"
            ),
        )

    def test_phantomhome_gives_every_object_file_a_distinct_path(self) -> None:
        text = self._project_text("PhantomHomeModules.vcxproj")
        sources = self._compiled_sources("PhantomHomeModules.vcxproj")
        # Anti-vacuity floor only.  It is deliberately far below the count: since
        # task 205 PhantomHome borrows the whole shared tree from PhantomCoreLib and
        # compiles only the sources it owns, so 300 - written when the project
        # hand-listed 317 - described the defect rather than the requirement.
        self.assertGreater(
            len(sources),
            50,
            msg=f"expected PhantomHomeModules to compile >50 sources, found {len(sources)}",
        )

        seen: dict[str, list[str]] = {}
        for rel in sources:
            seen.setdefault(rel.split("\\")[-1].lower(), []).append(rel)
        collisions = {k: v for k, v in seen.items() if len(v) > 1}

        if collisions:
            # Same-named sources are permitted ONLY when the object path is derived
            # per source; otherwise one silently overwrites the other's .obj and its
            # symbols go missing at link (MSB8027).
            self.assertIn(
                "<ObjectFileName>$(IntDir)%(RelativeDir)</ObjectFileName>",
                text,
                msg=(
                    "PhantomHomeModules compiles same-named sources without deriving the object "
                    f"path per source, so one overwrites the other: {collisions}"
                ),
            )

        # The intermediate directory must be private to this project.  A shared one
        # lets two projects' objects occupy the same path (MSB8028), which makes a
        # link consume a stale object from an unrelated build.
        shared = re.findall(
            re.escape("<IntDir>$(ProjectDir)build\\$(Configuration)\\</IntDir>"), text
        )
        self.assertEqual(
            [],
            shared,
            msg=(
                "PhantomHomeModules writes intermediates into the shared build\\$(Configuration) "
                "directory; give it a private subdirectory so objects cannot collide "
                "with another project's."
            ),
        )

    def test_no_project_gains_an_absolute_toolchain_include_path(self) -> None:
        measured: dict[str, int] = {}
        include_blocks = 0
        for project in sorted(self._ABSOLUTE_TOOLCHAIN_PATH_CEILING):
            self.assertTrue(
                (ROOT / project).is_file(),
                msg=f"{project} is absent from the tree, so this walk proves nothing about it",
            )
            text = self._project_text(project)
            include_blocks += len(re.findall(r"<AdditionalIncludeDirectories>", text))
            measured[project] = len(re.findall(r"(?i)Windows Kits", text))

        # Anti-vacuity.  Every assertion below is "count is low enough", so a broken
        # parse reports zero everywhere and passes silently.  Requiring that the walk
        # found real include lists is what makes a zero mean "absent" rather than
        # "not looked for".
        self.assertGreater(
            include_blocks,
            4,
            msg=(
                "found only "
                f"{include_blocks} AdditionalIncludeDirectories element(s) across "
                f"{len(measured)} projects; the parse is broken, so the counts below "
                "are meaningless"
            ),
        )

        grown = {
            name: (count, self._ABSOLUTE_TOOLCHAIN_PATH_CEILING[name])
            for name, count in measured.items()
            if count > self._ABSOLUTE_TOOLCHAIN_PATH_CEILING[name]
        }
        self.assertEqual(
            {},
            grown,
            msg=(
                "a project gained an absolute machine-specific SDK include path. "
                "That directory holds no headers, so it cannot help a build, and it "
                "pins one machine's layout into a project CI builds elsewhere. Use "
                "the toolset's own $(IncludePath). offenders "
                f"{{project: (found, ceiling)}}: {grown}"
            ),
        )

        # Removing the path must not be achieved by emptying the list: the entries the
        # project genuinely needs have to survive.  Checked on the in-scope project
        # only, because it is the one this guard requires to be at zero.
        home = self._project_text("PhantomHomeModules.vcxproj")
        for required in (
            "$(ProjectDir)include",
            "$(ProjectDir)include\\YARA",
            "$(ProjectDir)src",
            "%(AdditionalIncludeDirectories)",
        ):
            found = home.count(required)
            self.assertGreaterEqual(
                found,
                2,
                msg=(
                    f"PhantomHomeModules names the include entry {required!r} only "
                    f"{found} time(s); it needs one per configuration, so the list "
                    "was pruned too far rather than having the dead path removed"
                ),
            )

    def test_no_project_gains_a_precompiled_header_name_with_a_literal_dollar(self) -> None:
        measured: dict[str, int] = {}
        declared = 0
        for project in sorted(self._BROKEN_PCH_OUTPUT_NAME_CEILING):
            self.assertTrue(
                (ROOT / project).is_file(),
                msg=f"{project} is absent from the tree, so this walk proves nothing about it",
            )
            text = self._project_text(project)
            declared += len(re.findall(r"<PrecompiledHeaderOutputFile>", text))
            measured[project] = text.count("$(IntDir)$pch.pch")

        # Same anti-vacuity argument as the sibling test above.
        self.assertGreater(
            declared,
            4,
            msg=(
                f"found only {declared} PrecompiledHeaderOutputFile element(s) across "
                f"{len(measured)} projects; the parse is broken, so the counts below "
                "are meaningless"
            ),
        )

        grown = {
            name: (count, self._BROKEN_PCH_OUTPUT_NAME_CEILING[name])
            for name, count in measured.items()
            if count > self._BROKEN_PCH_OUTPUT_NAME_CEILING[name]
        }
        self.assertEqual(
            {},
            grown,
            msg=(
                "a project gained a precompiled-header output name containing a "
                "literal '$'. MSBuild substitutes only on '$(', so '$p' is literal "
                "text and the compiler writes a file actually called '$pch.pch'. "
                "PhantomCoreLib and the Service write $(IntDir)pch.pch. offenders "
                f"{{project: (found, ceiling)}}: {grown}"
            ),
        )

        # And the correct form must be present, so the count cannot reach zero by the
        # element being deleted - which would silently disable the precompiled header
        # and slow every build without failing anything.
        home_correct = self._project_text("PhantomHomeModules.vcxproj").count(
            "<PrecompiledHeaderOutputFile>$(IntDir)pch.pch</PrecompiledHeaderOutputFile>"
        )
        self.assertEqual(
            2,
            home_correct,
            msg=(
                "expected PhantomHomeModules to declare the corrected precompiled-header "
                f"output path once per configuration, found {home_correct}"
            ),
        )


class TestVectorEncodingContractTests(unittest.TestCase):
    """Pins the encoding form of the deliberate Unicode test vectors.

    WHY THE ESCAPE FORM IS REQUIRED, and it is not a style preference.  No product
    project passes /utf-8 and these files carry no BOM, so MSVC decodes the source
    through the active code page (1254 on the machine this was measured on).  For a
    WIDE literal that produces mojibake, and because each of these tests writes a
    value and then reads the same literal back, the comparison agreed with itself and
    passed while carrying corrupted content - a test that cannot fail for the reason
    it exists.  For a u8 literal the mojibake is then re-encoded to UTF-8, so the
    bytes are wrong in a second way.  An escape is decoded by the compiler rather
    than by the code page, so it is correct under either resolution of task 193.

    THE NARROW CASE IS THE OPPOSITE AND MUST NOT BE "FIXED" TO MATCH.  An ordinary
    narrow literal round-trips losslessly (decode via the code page, encode via the
    same code page), so its bytes are already right.  Writing \\uXXXX there asks the
    compiler to represent a codepoint the code page cannot hold: that is warning
    C4566 and a substitution character, i.e. it would BREAK a passing test.  Narrow
    vectors therefore use explicit \\xNN byte escapes, which state the exact bytes and
    remove the raw characters without changing them.  JSONUtils' input is also a RAW
    literal, where escape sequences are not processed at all.

    SCOPE.  This guard covers non-BMP codepoints only.  It deliberately does NOT
    forbid non-ASCII generally: 186 characters in WhiteListPatternIndex_Tests.cpp and
    19 in WhiteListStringPool_Tests.cpp are wide literals belonging to task 193, and
    17 in CacheManager_Tests.cpp are U+2705 glyphs belonging to task 208.  A guard
    that cannot pass is a guard nobody keeps, so those are ratcheted rather than
    banned - the ceilings may fall, never rise.
    """

    _SUFFIXES = (".cpp", ".hpp", ".h", ".c")

    # Files this change made pure ASCII.  Re-introducing any raw non-ASCII character
    # into one of them fails here.
    _MUST_STAY_ASCII = (
        "tests/unit/Database_systems_unit/sig_store/sig_builder_input_methods_tests.cpp",
        "tests/unit/Database_systems_unit/threat_intel/ThreatIntelExporter_Tests.cpp",
        "tests/unit/Database_systems_unit/configuration_db_tests.cpp",
        "tests/unit/utils_unit/JSONUtils_Tests.cpp",
    )

    # Measured non-ASCII population that legitimately remains, with its owning task.
    # These are CEILINGS: tasks 193 and 208 may reduce them without editing this test.
    _NON_ASCII_CEILING = {
        "tests/unit/Database_systems_unit/white_list/WhiteListPatternIndex_Tests.cpp": 186,
        "tests/unit/Database_systems_unit/white_list/WhiteListStringPool_Tests.cpp": 19,
        "tests/unit/utils_unit/CacheManager_Tests.cpp": 17,
    }

    # The value-carrying literals corrected here.  A bare "no astral codepoint" rule
    # would also be satisfied by deleting the test, so each literal is pinned.
    _REQUIRED_VECTORS = (
        (
            "tests/unit/Database_systems_unit/sig_store/sig_builder_input_methods_tests.cpp",
            r'u8"Unicode test: \u4F60\u597D\u4E16\u754C \U0001F512"',
            1,
        ),
        (
            "tests/unit/Database_systems_unit/threat_intel/ThreatIntelExporter_Tests.cpp",
            r'u8"Hello\u2122\u20AC\u4E2D\u6587\U0001F525"',
            1,
        ),
        (
            "tests/unit/Database_systems_unit/white_list/WhiteListPatternIndex_Tests.cpp",
            r'L"C:\\Folder\U0001F4C1\\File\U0001F4C4.txt"',
            2,
        ),
        (
            "tests/unit/Database_systems_unit/configuration_db_tests.cpp",
            r'L"\u6D4B\u8BD5.\u30AD\u30FC"',
            2,
        ),
        (
            "tests/unit/Database_systems_unit/configuration_db_tests.cpp",
            r'L"\u0417\u043D\u0430\u0447\u0435\u043D\u0438\u0435 \u0442\u0435\u0441\u0442 \U0001F389"',
            2,
        ),
        (
            "tests/unit/utils_unit/CacheManager_Tests.cpp",
            r'L"\u952E_\u041A\u043B\u044E\u0447_\u0645\u0641\u062A\u0627\u062D_\U0001F511"',
            1,
        ),
    )

    @classmethod
    def _walk_test_sources(cls):
        for path in sorted((ROOT / "tests").rglob("*")):
            if path.is_file() and path.suffix in cls._SUFFIXES:
                yield path

    @staticmethod
    def _read(rel: str) -> str:
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_no_test_source_contains_a_non_bmp_codepoint(self) -> None:
        offenders: list[str] = []
        walked = 0
        for path in self._walk_test_sources():
            walked += 1
            text = path.read_text(encoding="utf-8")
            astral = sum(1 for ch in text if ord(ch) > 0xFFFF)
            if astral:
                rel = path.relative_to(ROOT).as_posix()
                offenders.append(f"{rel}: {astral}")

        # Anti-vacuity: a walk that finds nothing must not pass silently.
        self.assertGreater(
            walked,
            200,
            msg=f"expected to walk >200 test sources, walked {walked}",
        )
        self.assertEqual(
            [],
            offenders,
            msg=(
                "a test source holds a non-BMP character directly. Write it as a "
                r"\UXXXXXXXX escape in a wide or u8 literal, or as \xNN byte escapes "
                f"in a narrow literal. offenders: {offenders}"
            ),
        )

    def test_the_files_this_change_made_ascii_stay_ascii(self) -> None:
        offenders: list[str] = []
        for rel in self._MUST_STAY_ASCII:
            text = self._read(rel)
            count = sum(1 for ch in text if ord(ch) > 0x7F)
            if count:
                offenders.append(f"{rel}: {count}")
        self.assertEqual(
            [],
            offenders,
            msg=f"these files are required to remain pure ASCII. offenders: {offenders}",
        )

    def test_the_remaining_non_ascii_population_only_shrinks(self) -> None:
        risen: list[str] = []
        for rel, ceiling in self._NON_ASCII_CEILING.items():
            text = self._read(rel)
            count = sum(1 for ch in text if ord(ch) > 0x7F)
            if count > ceiling:
                risen.append(f"{rel}: {count} > ceiling {ceiling}")
        self.assertEqual(
            [],
            risen,
            msg=(
                "the non-ASCII population of a known-affected file has grown. These "
                "ceilings belong to tasks 193 and 208 and may only fall. "
                f"offenders: {risen}"
            ),
        )

    def test_the_corrected_test_vectors_keep_their_escape_form(self) -> None:
        missing: list[str] = []
        for rel, literal, expected in self._REQUIRED_VECTORS:
            found = self._read(rel).count(literal)
            if found != expected:
                missing.append(f"{rel}: found {found} of expected {expected} -> {literal}")
        self.assertEqual(
            [],
            missing,
            msg=(
                "an escaped Unicode test vector was removed or rewritten. Deleting the "
                "vector rather than escaping it would satisfy the non-BMP rule while "
                f"losing the coverage. offenders: {missing}"
            ),
        )

    def test_the_narrow_json_vectors_use_byte_escapes_not_universal_names(self) -> None:
        rel = "tests/unit/utils_unit/JSONUtils_Tests.cpp"
        text = self._read(rel)

        byte_form = r"\xe4\xb8\x96\xe7\x95\x8c \xf0\x9f\x8c\x8d"
        self.assertEqual(
            2,
            text.count(byte_form),
            msg=(
                "both narrow JSON vectors must carry the same explicit UTF-8 bytes; "
                "the parser input and the expected value have to agree byte for byte"
            ),
        )

        # A universal-character-name here is warning C4566 plus a substitution
        # character, so it would break this passing test rather than correct it.
        offenders = [
            line.strip()
            for line in text.splitlines()
            if ("Hello" in line and (r"\u4E16" in line or r"\U0001F30D" in line))
        ]
        self.assertEqual(
            [],
            offenders,
            msg=(
                "a narrow literal must not use a universal-character-name: code page "
                "1254 cannot represent these codepoints, so MSVC warns C4566 and "
                f"substitutes. Use the byte escapes instead. offenders: {offenders}"
            ),
        )


class AssemblyExportUniquenessContractTests(unittest.TestCase):
    """No two assembly files may export the same symbol.

    An object file is the unit of linkage, so a symbol declared PUBLIC and defined
    PROC in two .asm files makes every Application that assembles both fail with
    LNK2005 -- even when nothing calls the symbol, because each object is pulled in
    whole to satisfy its OTHER exports. A StaticLibrary never notices, because
    lib.exe archives both objects without complaint. That is why the duplicate
    DetectSingleStepTiming survived inside PhantomCoreLib and only surfaced once
    PhantomHome got far enough to reach its link step (task 206).

    LNK2005 reports only the FIRST duplicate it meets, so a build error is not a
    reliable enumeration of this defect class. This test enumerates all of them,
    which is what turns a fatal link failure into a two-second test failure.
    """

    _ASM_ROOT = ROOT / "src"
    _ANTIEVASION = ROOT / "src" / "PhantomCore" / "AntiEvasion"
    _MIN_ASM_FILES = 6
    _MIN_PUBLIC_SYMBOLS = 100

    @staticmethod
    def _strip_asm_comments(text):
        """MASM comments run from an unquoted semicolon to end of line."""
        cleaned = []
        for line in text.splitlines():
            index = line.find(";")
            cleaned.append(line if index < 0 else line[:index])
        return cleaned

    @classmethod
    def _inventory(cls):
        """Return (files, public_owners, proc_owners) keyed by symbol name."""
        public_owners = {}
        proc_owners = {}
        files = sorted(cls._ASM_ROOT.rglob("*.asm"))
        for path in files:
            text = read_source(path).lstrip("\ufeff")
            for number, line in enumerate(cls._strip_asm_comments(text), start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped[:7].upper() == "PUBLIC ":
                    for name in stripped[7:].split(","):
                        name = name.strip()
                        if name:
                            public_owners.setdefault(name, []).append((path.name, number))
                match = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_@$?]*)\s+PROC\b", stripped, re.IGNORECASE
                )
                if match:
                    proc_owners.setdefault(match.group(1), []).append((path.name, number))
        return files, public_owners, proc_owners

    def test_no_assembly_symbol_is_exported_by_two_files(self):
        files, public_owners, proc_owners = self._inventory()

        # Anti-vacuity: this test is worthless if the walk found nothing.
        self.assertGreaterEqual(
            len(files),
            self._MIN_ASM_FILES,
            "expected at least %d .asm files under src, walked %d -- the glob is "
            "no longer finding the assembly sources"
            % (self._MIN_ASM_FILES, len(files)),
        )
        self.assertGreaterEqual(
            len(public_owners),
            self._MIN_PUBLIC_SYMBOLS,
            "expected at least %d PUBLIC symbols, parsed %d -- the PUBLIC parser is "
            "no longer matching" % (self._MIN_PUBLIC_SYMBOLS, len(public_owners)),
        )

        offenders = []
        for name, sites in sorted(public_owners.items()):
            owners = sorted({file_name for file_name, _ in sites})
            if len(owners) > 1:
                offenders.append("%s declared PUBLIC in %s" % (name, ", ".join(owners)))
        for name, sites in sorted(proc_owners.items()):
            owners = sorted({file_name for file_name, _ in sites})
            if len(owners) > 1:
                offenders.append("%s defined PROC in %s" % (name, ", ".join(owners)))

        self.assertEqual(
            offenders,
            [],
            "these assembly symbols are exported by more than one file, so every "
            "Application assembling both objects fails with LNK2005: %s"
            % "; ".join(offenders),
        )

    def test_every_public_assembly_symbol_is_defined_in_its_own_file(self):
        """A PUBLIC with no PROC is an unresolved external for every consumer."""
        files, public_owners, proc_owners = self._inventory()
        self.assertGreaterEqual(len(files), self._MIN_ASM_FILES, "walked too few .asm files")

        offenders = []
        for name, sites in sorted(public_owners.items()):
            declaring = sorted({file_name for file_name, _ in sites})
            defining = sorted({file_name for file_name, _ in proc_owners.get(name, [])})
            if not defining:
                offenders.append("%s declared PUBLIC in %s but never defined PROC"
                                 % (name, ", ".join(declaring)))
            elif not set(declaring) & set(defining):
                offenders.append("%s declared PUBLIC in %s but defined only in %s"
                                 % (name, ", ".join(declaring), ", ".join(defining)))

        self.assertEqual(
            offenders,
            [],
            "these PUBLIC symbols have no matching PROC in the file that exports "
            "them: %s" % "; ".join(offenders),
        )

    def test_the_single_step_timing_routines_stay_module_qualified(self):
        """Both routines must survive under module-qualified names.

        A bare no-duplicates rule is ALSO satisfied by deleting one of the two
        routines, which would silently drop an implemented detection primitive.
        This pins that both still exist and that the generic name is gone.
        """
        _, public_owners, proc_owners = self._inventory()

        for symbol, owner in (
            ("DebuggerDetectSingleStepTiming", "DebuggerEvasionDetector_x64.asm"),
            ("SandboxDetectSingleStepTiming", "SandboxEvasionDetector_x64.asm"),
        ):
            self.assertTrue(
                symbol in public_owners,
                "%s is no longer declared PUBLIC by any assembly file" % symbol,
            )
            self.assertTrue(
                symbol in proc_owners,
                "%s is no longer defined PROC by any assembly file -- a routine was "
                "deleted rather than renamed" % symbol,
            )
            declaring = sorted({name for name, _ in public_owners[symbol]})
            defining = sorted({name for name, _ in proc_owners[symbol]})
            self.assertEqual(
                declaring, [owner], "%s should be exported only by %s" % (symbol, owner)
            )
            self.assertEqual(
                defining, [owner], "%s should be defined only in %s" % (symbol, owner)
            )

        self.assertFalse(
            "DetectSingleStepTiming" in public_owners,
            "the unqualified name DetectSingleStepTiming is exported again; two "
            "modules implement different single-step timing algorithms and the "
            "generic name is what made their objects collide",
        )
        self.assertFalse(
            "DetectSingleStepTiming" in proc_owners,
            "the unqualified name DetectSingleStepTiming is defined again",
        )

    def test_the_cplusplus_declarations_track_the_assembly_names(self):
        """The C++ side and the assembly must not drift apart.

        If the assembly is renamed and either the extern "C" declaration or the
        /ALTERNATENAME pragma is left behind, the pragma supplies a fallback for a
        symbol that no longer exists while the real symbol silently has none.
        """
        debugger_cpp = strip_c_comments(
            read_source(self._ANTIEVASION / "DebuggerEvasionDetector.cpp").lstrip("\ufeff")
        )
        sandbox_cpp = strip_c_comments(
            read_source(self._ANTIEVASION / "SandboxEvasionDetector.cpp").lstrip("\ufeff")
        )
        sandbox_hpp = strip_c_comments(
            read_source(self._ANTIEVASION / "SandboxEvasionDetector.hpp").lstrip("\ufeff")
        )

        self.assertEqual(
            debugger_cpp.count("uint64_t DebuggerDetectSingleStepTiming() noexcept;"),
            1,
            "the debugger module must declare its module-qualified symbol exactly once",
        )
        self.assertEqual(
            debugger_cpp.count(
                "/alternatename:DebuggerDetectSingleStepTiming=Fallback_DetectSingleStepTiming"
            ),
            1,
            "the debugger fallback pragma must name the module-qualified symbol",
        )
        self.assertEqual(
            sandbox_hpp.count("uint32_t SandboxDetectSingleStepTiming(void);"),
            1,
            "the sandbox header must declare its module-qualified symbol exactly once",
        )
        self.assertEqual(
            sandbox_cpp.count(
                "/ALTERNATENAME:SandboxDetectSingleStepTiming=Fallback_DetectSingleStepTiming"
            ),
            1,
            "the sandbox fallback pragma must name the module-qualified symbol",
        )

        # The shared C++ fallback keeps its original name and is referenced by both
        # pragmas plus Fallback_DetectICEBPBehavior, so it must still be defined once.
        self.assertEqual(
            debugger_cpp.count(
                'extern "C" uint64_t Fallback_DetectSingleStepTiming() noexcept'
            ),
            1,
            "the shared single-step fallback must be defined exactly once",
        )

        for label, body in (
            ("DebuggerEvasionDetector.cpp", debugger_cpp),
            ("SandboxEvasionDetector.cpp", sandbox_cpp),
            ("SandboxEvasionDetector.hpp", sandbox_hpp),
        ):
            leftovers = re.findall(r"(?<![A-Za-z0-9_])DetectSingleStepTiming", body)
            self.assertEqual(
                leftovers,
                [],
                "%s still names the unqualified symbol in code %d time(s)"
                % (label, len(leftovers)),
            )


class ProductProjectLibraryReuseContractTests(unittest.TestCase):
    """Pins that PhantomHome consumes PhantomCoreLib instead of recompiling it.

    PhantomHome used to hand-maintain a 317-entry source list of which 243 entries
    were files PhantomCoreLib already compiles.  That list is a dependency graph
    maintained by hand, so it rotted: 193 shared sources were missing and the
    executable failed at link with 123 unresolved externals while every source-level
    test stayed green.  The same rot broke the Fuzzer for four months (task 141).

    The invariants below make the rot unrepresentable rather than merely detectable:
    an exe either owns a source or borrows it from the library, never both, and the
    set it owns is DERIVED from a sibling project that provably links.

    Why the derivation and not a literal list: a literal list is the very thing that
    rotted.  ShadowStrikePhantomService is an Application that hosts the same
    PhantomHome product against the same library and links today, so the product
    sources it needs are exactly the product sources PhantomHome needs.  Comparing
    against it is self-maintaining; comparing against a copied list is not.

    NAMING (task 211): PhantomHomeModules.vcxproj is the compile-verification project,
    renamed from PhantomHome.vcxproj because it is not the product and ships nothing.
    Where prose below says "PhantomHome product sources" it means sources under
    src/Products/Community/PhantomHome, which is a source path and is unaffected by
    the project rename.
    """

    _HOME = "PhantomHomeModules.vcxproj"
    _LIB = "PhantomCoreLib.vcxproj"
    _SERVICE = "ShadowStrikePhantomService.vcxproj"
    _UI = "ShadowStrikePhantomUI.vcxproj"

    # The one file that may legitimately appear in both the exe and the library.
    # A precompiled header needs a creating translation unit inside the project that
    # consumes it, so the exe must compile its own pch.cpp; its object defines no
    # product symbol, which is why it cannot collide.
    _SHARED_BY_DESIGN = ("src\\pch.cpp",)

    # Linking the library drags in dependencies the executable never needed while it
    # compiled everything itself.  Each of these was measured as a real unresolved
    # symbol or a documented library requirement, not copied hopefully:
    #   PhantomCoreLib.lib - the library itself
    #   onnxruntime.lib    - the library is built with SHADOWSTRIKE_HAS_ONNXRUNTIME=1
    #   libyara.lib        - the library is built with SHADOWSTRIKE_HAS_YARA
    #   normaliz.lib       - __imp_IdnToUnicode, from PhishingDetector.obj
    _REQUIRED_LIBS = (
        "PhantomCoreLib.lib",
        "onnxruntime.lib",
        "libyara.lib",
        "normaliz.lib",
    )

    _PRODUCT_PREFIX = "src\\products\\community\\phantomhome\\"

    @classmethod
    def _project_text(cls, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8").lstrip("\ufeff")

    @classmethod
    def _sources(cls, name: str) -> list[str]:
        text = cls._project_text(name)
        return [
            item.replace("/", "\\")
            for item in re.findall(r'<ClCompile\s+Include="([^"]+)"', text)
        ]

    @classmethod
    def _source_set(cls, name: str) -> set[str]:
        return {item.lower() for item in cls._sources(name)}

    @classmethod
    def _assembly(cls, name: str) -> list[str]:
        text = cls._project_text(name)
        return re.findall(r'<MASM\s+Include="([^"]+)"', text)

    def test_phantomhome_borrows_the_shared_tree_instead_of_recompiling_it(self) -> None:
        home = self._source_set(self._HOME)
        lib = self._source_set(self._LIB)

        # Anti-vacuity on both sides: an empty parse must not read as compliance.
        self.assertGreater(
            len(lib),
            400,
            msg=f"expected PhantomCoreLib to compile >400 sources, parsed {len(lib)}",
        )
        self.assertGreater(
            len(home),
            50,
            msg=f"expected PhantomHomeModules to compile >50 sources, parsed {len(home)}",
        )

        allowed = {item.lower() for item in self._SHARED_BY_DESIGN}
        duplicated = sorted(home & lib - allowed)
        self.assertEqual(
            [],
            duplicated,
            msg=(
                "PhantomHomeModules compiles sources PhantomCoreLib also compiles.  Every one "
                "is a duplicate object in a link that already archives the library, so "
                "each is a latent LNK2005 the moment the library member is pulled in "
                "for any other symbol it defines (task 206 was exactly that failure). "
                f"offenders: {duplicated}"
            ),
        )

    def test_phantomhome_declares_a_reference_to_the_library_it_links(self) -> None:
        text = self._project_text(self._HOME)
        references = re.findall(r'<ProjectReference\s+Include="([^"]+)"', text)
        self.assertEqual(
            [self._LIB],
            references,
            msg=(
                "PhantomHomeModules must reference PhantomCoreLib so the library is built "
                "before the executable links against it; without the reference a stale "
                f"archive links silently. found: {references}"
            ),
        )

    def test_phantomhome_links_the_dependencies_the_library_brings_with_it(self) -> None:
        text = self._project_text(self._HOME)
        # Both x64 configurations must carry them; fixing only Release leaves Debug
        # unable to link, which is how a half-applied project edit hides.
        for lib_name in self._REQUIRED_LIBS:
            count = len(re.findall(re.escape(lib_name), text))
            self.assertEqual(
                2,
                count,
                msg=(
                    f"{lib_name} must appear in AdditionalDependencies for both x64 "
                    f"configurations, found {count} occurrence(s)"
                ),
            )
        libdir = len(re.findall(re.escape("$(SolutionDir)lib\\$(Configuration)"), text))
        self.assertEqual(
            2,
            libdir,
            msg=(
                "both x64 configurations must search the directory PhantomCoreLib "
                f"publishes its archive to, found {libdir}"
            ),
        )

    def test_the_executable_does_not_reassemble_the_libraries_assembly(self) -> None:
        home_asm = self._assembly(self._HOME)
        lib_asm = self._assembly(self._LIB)
        # Anti-vacuity: the assembly layer must still be built by SOMEBODY.  A guard
        # that passes because the .asm files vanished would be worse than no guard.
        self.assertEqual(
            6,
            len(lib_asm),
            msg=f"expected PhantomCoreLib to assemble 6 .asm files, found {len(lib_asm)}",
        )
        self.assertEqual(
            [],
            home_asm,
            msg=(
                "PhantomHomeModules assembles .asm files the library already archives.  Each "
                "duplicated object exports the same symbols, which is the linkage unit "
                f"collision closed in task 206. offenders: {home_asm}"
            ),
        )

    def test_phantomhome_owns_every_product_source_the_service_owns(self) -> None:
        service = self._sources(self._SERVICE)
        lib = self._source_set(self._LIB)
        home = self._source_set(self._HOME)

        # Product sources the proven sibling links and the library does not supply.
        derived = sorted(
            {
                item.lower()
                for item in service
                if item.lower().startswith(self._PRODUCT_PREFIX)
                and item.lower() not in lib
            }
        )
        # Anti-vacuity: if the derivation yields nothing the comparison proves nothing.
        self.assertGreaterEqual(
            len(derived),
            4,
            msg=(
                "expected the Service to link at least 4 PhantomHome product sources "
                f"absent from the library, derived {len(derived)}"
            ),
        )
        missing = [item for item in derived if item not in home]
        self.assertEqual(
            [],
            missing,
            msg=(
                "ShadowStrikePhantomService links PhantomHome product sources that "
                "PhantomHomeModules does not, and PhantomCoreLib does not supply them either. "
                "Each is an unresolved external at link time and nothing else reports "
                f"it. missing: {missing}"
            ),
        )

    def test_the_two_competing_wiring_anchors_are_never_linked_together(self) -> None:
        # WiringAnchor.cpp and UI\\Client\\WiringStub.cpp both define
        # ShadowStrike::Products::Home::EnsureAllModulesWired.  The anchor performs the
        # real wiring; the stub is a deliberate no-op for the UI process, which has no
        # modules to wire.  A project linking both gets LNK2005; a service-side host
        # linking only the stub silently wires nothing, which is worse than a link
        # error because it looks like it started.
        home = self._source_set(self._HOME)
        anchor = "src\\products\\community\\phantomhome\\wiringanchor.cpp"
        stub = "src\\products\\community\\phantomhome\\ui\\client\\wiringstub.cpp"
        self.assertIn(
            anchor,
            home,
            msg="PhantomHomeModules must link the real wiring anchor",
        )
        self.assertNotIn(
            stub,
            home,
            msg=(
                "PhantomHomeModules links the UI-process wiring stub; it defines the same "
                "symbol as WiringAnchor.cpp, so linking both is LNK2005 and linking "
                "only the stub wires no modules at all"
            ),
        )
        if (ROOT / self._UI).is_file():
            ui = self._source_set(self._UI)
            self.assertNotIn(
                anchor,
                ui,
                msg=(
                    "the UI project links the real wiring anchor; the UI process hosts "
                    "no modules and the stub exists precisely so it does not"
                ),
            )


class EmojiFreeCodebaseContractTests(unittest.TestCase):
    """Task 208. The project owner has forbidden emoji in the codebase, so this guard
    refuses the five emoji-class BMP glyphs that were swept out of 21 of our own files
    (86 sites): U+2713, U+2705, U+2717, U+26A0 and U+274C.

    TWELVE of those 86 sat inside WIDE string literals in files carrying no BOM, and no
    product project passes /utf-8 (task 193), so MSVC decoded them through the ANSI code
    page and the operator-visible text was already mojibake before the sweep. For those
    twelve the removal is a correctness fix, not only hygiene.

    DELIBERATELY OUT OF SCOPE pending the owner's answer: README.md, SECURITY.md,
    CLAUDE.md and .github/copilot-instructions.md carry ten further glyphs. Those are
    presentation documents where GitHub emoji are conventional and removing them changes
    the public face of the project rather than any shipped behaviour, so they sit outside
    the walk roots below rather than being swept silently.

    OUT OF SCOPE BY CONSTRUCTION: PhantomCortex\\.venv_local holds vendored third-party
    Python packages (fontTools, huggingface_hub, onnxscript, rich, torch) whose own emoji
    are not ours to edit, so the walk starts at PhantomCortex\\training.
    """

    _EMOJI_CODEPOINTS = ("\u2713", "\u2705", "\u2717", "\u26A0", "\u274C")

    # Arrows and box-drawing are a SEPARATE class and are deliberately NOT swept: U+2192
    # alone appears well over a thousand times as an ASCII-art relation in comments, and
    # task 193's measured non-ASCII population depends on the rest staying where it is.
    _SPARED_CODEPOINTS = ("\u2190", "\u2192", "\u2193", "\u2194", "\u21C6",
                          "\u21D2", "\u2500")

    _WALK_ROOTS = ("src", "tests", "tools", "PhantomSensor", "Fuzzer",
                   "PhantomCortex/training")
    _EXTENSIONS = (".cpp", ".hpp", ".h", ".c", ".asm", ".py", ".ps1", ".rc", ".inc")
    _SKIP_DIRS = ("build", "bin", "lib", "obj", "node_modules", ".git", "vendor",
                  "include", ".venv", ".venv_local", "__pycache__", "x64")
    _MIN_FILES_WALKED = 800

    def _walk_own_code(self):
        found = []
        for rel in self._WALK_ROOTS:
            base = ROOT / rel
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if path.suffix.lower() not in self._EXTENSIONS:
                    continue
                if any(part.lower() in self._SKIP_DIRS for part in path.parts):
                    continue
                if path.is_file():
                    found.append(path)
        return found

    def test_no_emoji_class_glyph_survives_in_our_own_code(self):
        files = self._walk_own_code()
        self.assertGreater(
            len(files), self._MIN_FILES_WALKED,
            "the walk found only {} source files, so this guard would pass vacuously; "
            "check _WALK_ROOTS and _SKIP_DIRS".format(len(files)),
        )
        offenders = []
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            if not any(glyph in text for glyph in self._EMOJI_CODEPOINTS):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                names = sorted({"U+{:04X}".format(ord(ch))
                                for ch in line if ch in self._EMOJI_CODEPOINTS})
                if names:
                    offenders.append("{}:{} {}".format(
                        path.relative_to(ROOT).as_posix(), lineno, ",".join(names)))
        # Bounded output by construction: report the offenders, never the haystack.
        self.assertEqual(
            offenders[:20], [],
            "{} emoji-class glyph site(s) remain in our own code; the owner has "
            "forbidden emoji in the codebase (task 208). Use [OK] / [FAIL] / [WARN] in "
            "operator-visible text, and delete the glyph outright in a comment. "
            "First 20 shown.".format(len(offenders)),
        )

    def test_the_guard_is_emoji_only_and_never_a_de_unicode_sweep(self):
        self.assertEqual(
            len(self._EMOJI_CODEPOINTS), 5,
            "the emoji set is fixed at five codepoints; widening it would turn a "
            "hygiene guard into a general non-ASCII purge",
        )
        for spared in self._SPARED_CODEPOINTS:
            self.assertNotIn(
                spared, self._EMOJI_CODEPOINTS,
                "U+{:04X} is an arrow or box-drawing character, not an emoji: sweeping "
                "it would destroy task 193's measured non-ASCII population and the "
                "em-dash and box-drawing separators this codebase uses "
                "deliberately".format(ord(spared)),
            )


class ShippedBinaryIdentityContractTests(unittest.TestCase):
    """Pins which executables the installer ships, so a project that ships nothing
    cannot quietly start looking like a product again.

    WHY THIS EXISTS.  Task 211 measured that PhantomHome.vcxproj built a googletest
    runner named after a product tier: it linked zero test cases, so its main() took
    its own "no tests discovered" branch and returned 1, and it appeared in none of the
    six .wxs files.  The name was the whole problem.  FOUR filed tasks had reasoned
    about that project as the product host and were mis-scoped as a result, and one of
    them proposed forcing 22 module anchors into a binary nobody installs.  The project
    is now called PhantomHomeModules to say what it does.  A name alone rots, so the
    invariant behind the rename is asserted here instead of being remembered.

    BOTH DIRECTIONS ARE ASSERTED, because each alone is weak.  Requiring the four
    shipped names catches an installer that silently stops shipping a component -
    which would be a product that no longer installs part of itself.  Forbidding the
    others catches the reverse: an analysis or test harness being added to the MSI.

    SUBSTRING SAFETY was checked rather than assumed.  "PhantomHome.exe" is not a
    substring of "PhantomHomeModules.exe" and "ShadowStrike.exe" is not a substring of
    "ShadowStrikePhantomService.exe" or "ShadowStrikeDriverResume.exe", so a plain
    count() cannot confuse a forbidden name with a permitted one.
    """

    _WXS_DIR = ROOT / "packaging"

    # Measured from build/installer/staging, which holds exactly these four .exe, and
    # corroborated against the installed layout recorded under task 44.
    _SHIPPED = (
        "ShadowStrikePhantomService.exe",
        "ShadowStrikePhantomTray.exe",
        "ShadowStrikePhantomUI.exe",
        "ShadowStrikeDriverResume.exe",
    )

    # Outputs of projects that exist to build, analyse or test the tree.  None is a
    # product and none may appear in installer authoring.  PhantomHome.exe is listed
    # deliberately: the pre-rename name must not come back either.
    _NOT_SHIPPED = (
        "PhantomHomeModules.exe",
        "PhantomHome.exe",
        "ShadowStrike.exe",
        "phantom-tests.exe",
        "PhantomEDR.exe",
        "PhantomXDR.exe",
        "PhantomSigBuild.exe",
    )

    # Anti-vacuity floor.  Six .wxs exist; a walk that finds fewer than four has lost
    # the installer authoring, and every "appears zero times" assertion below would
    # then pass for the wrong reason.
    _MIN_WXS_FILES = 4

    _COVERITY_WORKFLOW = ROOT / ".github/workflows/coverity-scan.yml"

    @classmethod
    def _wxs(cls) -> "list[tuple[str, str]]":
        found = []
        for path in sorted(cls._WXS_DIR.rglob("*.wxs")):
            rel = path.relative_to(ROOT).as_posix()
            found.append((rel, path.read_text(encoding="utf-8", errors="replace")))
        return found

    def test_the_installer_still_ships_every_product_executable(self) -> None:
        files = self._wxs()
        self.assertGreaterEqual(
            len(files),
            self._MIN_WXS_FILES,
            msg=(
                f"found only {len(files)} .wxs files under {self._WXS_DIR.name}, so the "
                "forbidden-name assertions would pass vacuously"
            ),
        )
        blob = "\n".join(text for _, text in files)
        missing = [name for name in self._SHIPPED if name not in blob]
        self.assertEqual(
            [],
            missing,
            msg=(
                "installer authoring no longer names these product executables, so the "
                f"MSI would install a product missing part of itself: {missing}"
            ),
        )

    def test_no_analysis_or_test_harness_is_declared_as_a_product(self) -> None:
        files = self._wxs()
        self.assertGreaterEqual(
            len(files),
            self._MIN_WXS_FILES,
            msg=f"found only {len(files)} .wxs files, so this guard would pass vacuously",
        )
        offenders = []
        for rel, text in files:
            for name in self._NOT_SHIPPED:
                count = text.count(name)
                if count:
                    offenders.append(f"{rel}: {name} x{count}")
        self.assertEqual(
            [],
            offenders,
            msg=(
                "installer authoring names the output of a project that exists only to "
                "build, analyse or test the tree.  Shipping a test or analysis harness "
                "puts code with no product purpose on an endpoint: "
                f"{offenders}"
            ),
        )

    def test_the_compile_verification_project_has_exactly_one_honest_name(self) -> None:
        new = ROOT / "PhantomHomeModules.vcxproj"
        old = ROOT / "PhantomHome.vcxproj"
        self.assertTrue(
            new.is_file(),
            msg="PhantomHomeModules.vcxproj is missing; the product tree has no project that compile-verifies it",
        )
        self.assertFalse(
            old.is_file(),
            msg=(
                "PhantomHome.vcxproj is back.  A project named after the product tier "
                "while shipping nothing is what task 211 removed; two projects for one "
                "role means the next reader cannot tell which is the product"
            ),
        )
        sln = (ROOT / "ShadowStrike.sln").read_text(encoding="utf-8").lstrip("\ufeff")
        # Bounded on purpose: assertIn against a whole file prints the file.
        self.assertTrue(
            "PhantomHomeModules.vcxproj" in sln,
            msg="the solution does not name PhantomHomeModules.vcxproj, so it is not built by a solution build",
        )
        stale = re.findall(re.escape('"PhantomHome.vcxproj"'), sln)
        self.assertEqual(
            [],
            stale,
            msg="the solution still points at PhantomHome.vcxproj, which does not exist; the project would fail to load",
        )

    def test_coverity_still_analyses_the_phantomhome_product_modules(self) -> None:
        # This is the assertion that matters most in this class.  The workflow is the
        # only consumer that builds the compile-verification project, so if it names a
        # project that does not exist, the entire PhantomHome product tree leaves
        # static analysis and nothing in a normal build or test run reports it.
        self.assertTrue(
            self._COVERITY_WORKFLOW.is_file(),
            msg=f"{self._COVERITY_WORKFLOW.name} is missing; static-analysis coverage cannot be checked",
        )
        text = self._COVERITY_WORKFLOW.read_text(encoding="utf-8").lstrip("\ufeff")
        # Bounded on purpose: assertIn against a whole file prints the file.
        self.assertTrue(
            "PhantomHomeModules.vcxproj" in text,
            msg=(
                "the Coverity workflow no longer builds PhantomHomeModules.vcxproj, so "
                "the PhantomHome product modules are silently absent from static "
                "analysis while the scan still reports success"
            ),
        )
        stale = re.findall(r"(?<!Modules)PhantomHome\.vcxproj", text)
        self.assertEqual(
            [],
            stale,
            msg=(
                "the Coverity workflow still names PhantomHome.vcxproj, which does not "
                "exist, so its build phase would fail or be skipped"
            ),
        )


class AssemblyLayerWiringContractTests(unittest.TestCase):
    """Pins the hand-written x64 assembly anti-evasion layer against silent ABI drift.

    Task 209 measured this layer on 2026-08-21: six of our own .asm files export 105
    PROCs, and every one of them has a hand-written extern "C" prototype in a sibling
    C++ file. There is no compiler or linker check tying a prototype to the assembly it
    names - extern "C" suppresses mangling, so a prototype may disagree with the
    implementation about the return width or even the ARGUMENT COUNT and still link.

    That is not hypothetical. VMEvasionDetector.cpp declared MeasureInstructionTiming
    with a second `instructionType` selector that the assembly never reads (it tests
    only ECX), so the selector was passed in EDX and silently discarded on the
    USE_ASM_FUNCTIONS path while the C++ fallback honoured it - the two configurations
    measured different things, which the file's own contract note forbids.

    Comment stripping is mandatory here: the fix left a comment that QUOTES the old
    two-argument signature in order to explain it, so a comment-blind scan is
    guaranteed to report the very defect the comment describes as fixed.
    """

    _ANTIEVASION_DIR = ROOT / "src" / "PhantomCore" / "AntiEvasion"

    # Measured floors, not targets. They exist so a broken walk reports as a failure
    # instead of trivially passing: every other assertion here is "no offenders found",
    # which an empty file list would satisfy vacuously.
    _MIN_ASM_FILES = 6
    _MIN_EXPORTS = 100

    @staticmethod
    def _function_body(code: str, name: str) -> str:
        """Return the brace-matched body of the first definition of *name*."""
        idx = code.index(name)
        brace = code.index("{", idx)
        depth = 0
        for pos in range(brace, len(code)):
            if code[pos] == "{":
                depth += 1
            elif code[pos] == "}":
                depth -= 1
                if depth == 0:
                    return code[brace:pos + 1]
        raise AssertionError("unbalanced braces after " + name)

    def _asm_exports(self):
        """Map every exported assembly PROC to the file that defines it."""
        asm_files = sorted(self._ANTIEVASION_DIR.glob("*_x64.asm"))
        self.assertGreaterEqual(
            len(asm_files),
            self._MIN_ASM_FILES,
            "expected at least {} assembly sources under {}, found {} - the walk is "
            "broken and every other assertion in this class would pass vacuously".format(
                self._MIN_ASM_FILES, self._ANTIEVASION_DIR, len(asm_files)
            ),
        )
        exports = {}
        for path in asm_files:
            # MASM comments run from ';' to end of line.
            stripped = re.sub(r";[^\n]*", "", read_source(path))
            for name in re.findall(
                r"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s+PROC\b", stripped
            ):
                exports[name] = path.name
        self.assertGreaterEqual(
            len(exports),
            self._MIN_EXPORTS,
            "expected at least {} exported assembly routines, found {}".format(
                self._MIN_EXPORTS, len(exports)
            ),
        )
        return exports

    def _cpp_sources(self):
        paths = sorted(self._ANTIEVASION_DIR.glob("*.cpp"))
        paths += sorted(self._ANTIEVASION_DIR.glob("*.hpp"))
        self.assertGreater(
            len(paths), 10, "no C++ sources found beside the assembly layer"
        )
        return {p: strip_c_comments(read_source(p)) for p in paths}

    def test_every_assembly_export_is_declared_beside_the_assembly(self):
        """An export nobody declares cannot be called, and nothing would report that."""
        exports = self._asm_exports()
        bodies = self._cpp_sources()
        combined = re.compile(
            r"(?<![A-Za-z0-9_])("
            + "|".join(re.escape(name) for name in sorted(exports))
            + r")\s*\("
        )
        declared = set()
        for code in bodies.values():
            declared.update(match.group(1) for match in combined.finditer(code))
        undeclared = sorted(
            "{} ({})".format(name, exports[name])
            for name in exports
            if name not in declared
        )
        self.assertEqual(
            [],
            undeclared,
            "every exported assembly routine must be declared in a C++ file beside the "
            "assembly, so the prototype and the implementation stay reviewable "
            "together; these have no prototype at all: " + ", ".join(undeclared),
        )

    def test_the_assembly_instruction_timer_is_never_declared_with_a_selector(self):
        """The assembly reads only ECX, so a second parameter is silently discarded."""
        bodies = self._cpp_sources()
        # The lookbehind rejects Fallback_/Safe_ prefixed names, which legitimately do
        # take a selector because they are C++ implementations, not the assembly symbol.
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])MeasureInstructionTiming\s*\([^;{)]*,[^;{)]*\)\s*"
            r"(noexcept\s*)?;"
        )
        offenders = []
        for path, code in bodies.items():
            for match in pattern.finditer(code):
                offenders.append("{} at offset {}".format(path.name, match.start()))
        self.assertEqual(
            [],
            offenders,
            "MeasureInstructionTiming in EnvironmentEvasionDetector_x64.asm takes ONE "
            "argument - it tests only ECX and times a fixed instruction sequence. A "
            "two-argument prototype links silently because extern \"C\" suppresses "
            "mangling, and the extra argument is then discarded in EDX: "
            + ", ".join(offenders),
        )

    def test_the_typed_instruction_timing_wrapper_is_not_build_switch_dependent(self):
        """Its meaning must not change with USE_ASM_FUNCTIONS, per the file's own note."""
        path = self._ANTIEVASION_DIR / "VMEvasionDetector.cpp"
        code = strip_c_comments(read_source(path))
        wrapper = "Safe_MeasureInstructionTiming"
        self.assertIn(
            wrapper,
            code,
            "{} no longer defines {} - if the typed wrapper was renamed this guard must "
            "follow it rather than being deleted".format(path.name, wrapper),
        )
        body = self._function_body(code, wrapper)
        self.assertNotIn(
            "USE_ASM_FUNCTIONS",
            body,
            "{} must not select an implementation on the build switch: only the C++ "
            "implementation honours the instruction-type selector, so gating here makes "
            "the measured quantity depend on how the product was compiled".format(
                wrapper
            ),
        )
        self.assertEqual(
            1,
            body.count("Fallback_MeasureInstructionTiming"),
            "{} must route to the one implementation that honours the selector, exactly "
            "once".format(wrapper),
        )


class RdtscpFeatureGateContractTests(unittest.TestCase):
    """RDTSCP must never execute without runtime feature detection.

    RDTSCP is not baseline x64. It arrived with Intel Nehalem and AMD Barcelona and is
    reported by CPUID.80000001h:EDX[27]; executing it on a processor without that bit
    raises #UD, which is a hard crash rather than a degraded measurement.

    Before the gate existed there were ZERO queries of CPUID leaf 0x80000000 or
    0x80000001 anywhere in the tree, while 15 call sites across five anti-evasion
    translation units used the __rdtscp intrinsic and 19 assembly routines execute the
    instruction directly. That was LATENT rather than live only because those routines had
    no reachable caller - the assembly layer is largely unwired. Wiring it is exactly the
    outstanding work, so the gate is a prerequisite for that work rather than a fix for a
    crash anyone has seen.

    These tests are deliberately structural. The failure mode cannot be reproduced on
    development hardware, because every machine this is built on implements RDTSCP - so a
    behavioural test would pass on the assembly path whether or not the gate exists. A
    source contract is the only guard that can discriminate here, which is the same reason
    the kernel wire-format contracts are structural.
    """

    _CPU_FEATURES = ROOT / "src" / "PhantomCore" / "Utils" / "CpuFeatures.hpp"
    _ANTIEVASION_DIR = ROOT / "src" / "PhantomCore" / "AntiEvasion"
    _SRC_DIR = ROOT / "src"

    @staticmethod
    def _function_body(code: str, name: str) -> str:
        idx = code.index(name)
        brace = code.index("{", idx)
        depth = 0
        for pos in range(brace, len(code)):
            if code[pos] == "{":
                depth += 1
            elif code[pos] == "}":
                depth -= 1
                if depth == 0:
                    return code[brace:pos + 1]
        raise AssertionError("unbalanced braces after " + name)

    def test_the_feature_probe_header_exists(self):
        self.assertTrue(
            self._CPU_FEATURES.is_file(),
            "{} is missing - it is the single place allowed to execute RDTSCP".format(
                self._CPU_FEATURES
            ),
        )

    def test_only_the_probe_header_uses_the_rdtscp_intrinsic(self):
        """Every other site must route through the substitute-capable helper."""
        offenders = []
        scanned = 0
        for path in sorted(self._SRC_DIR.rglob("*.cpp")) + sorted(self._SRC_DIR.rglob("*.hpp")):
            if ".venv" in str(path):
                continue
            scanned += 1
            if path.resolve() == self._CPU_FEATURES.resolve():
                continue
            code = strip_c_comments(read_source(path))
            count = len(re.findall(r"(?<![A-Za-z0-9_])__rdtscp\s*\(", code))
            if count:
                offenders.append("{}={}".format(path.name, count))
        self.assertGreater(
            scanned, 400, "the source walk found only {} files - it is broken".format(scanned)
        )
        self.assertEqual(
            [],
            sorted(offenders),
            "__rdtscp raises #UD on processors that do not implement it, so it may only be "
            "reached through CpuFeatures::ReadSerializedTsc, which substitutes a "
            "serializing CPUID plus RDTSC. These bypass the gate: "
            + ", ".join(sorted(offenders)),
        )

    def test_the_probe_checks_the_extended_leaf_maximum_before_the_feature_bit(self):
        """Querying 0x80000001 unsupported returns another leaf's data, not zeroes."""
        code = strip_c_comments(read_source(self._CPU_FEATURES))
        self.assertIn("0x80000000", code, "the probe does not query the extended-leaf maximum")
        self.assertIn("0x80000001", code, "the probe does not query the RDTSCP feature leaf")
        self.assertLess(
            code.index("0x80000000"),
            code.index("0x80000001"),
            "the extended-leaf maximum must be tested FIRST: if leaf 0x80000001 is "
            "unsupported CPUID returns the highest supported leaf's data instead of "
            "zeroes, so the feature bit would be sampled from unrelated register content",
        )
        self.assertIn(
            "27",
            code,
            "the probe must test EDX bit 27, the architectural RDTSCP feature bit",
        )
        self.assertIn(
            "regs[3]",
            code,
            "the RDTSCP bit lives in EDX, which is regs[3] for the __cpuid intrinsic - "
            "reading a different register would report an unrelated capability",
        )

    def test_the_substitute_path_still_serializes(self):
        """A substitute that dropped serialization would silently change what is measured."""
        body = self._function_body(
            strip_c_comments(read_source(self._CPU_FEATURES)), "ReadSerializedTsc"
        )
        self.assertIn(
            "__rdtsc()",
            body,
            "the substitute path must still read the timestamp counter",
        )
        # Asserting merely that __cpuid appears would NOT discriminate: this body issues
        # CPUID twice, once to serialize and once to derive the processor id, so deleting
        # the serializing call would leave a passing count. Pin the ordering instead.
        self.assertIn(
            "__cpuid(regs, 0)",
            body,
            "the substitute must issue CPUID leaf 0 to serialize before sampling RDTSC",
        )
        self.assertLess(
            body.index("__cpuid(regs, 0)"),
            body.index("__rdtsc()"),
            "CPUID must be issued BEFORE reading the counter. RDTSC is not a serializing "
            "instruction, so without a preceding barrier the read may be reordered and the "
            "measurement loses the ordering property RDTSCP was chosen for - which would "
            "shift detection thresholds depending on the host processor",
        )

    def test_the_assembly_rdtscp_wrapper_is_gated_on_runtime_support(self):
        """The assembly executes RDTSCP unconditionally, so its caller must check first."""
        path = self._ANTIEVASION_DIR / "VMEvasionDetector.cpp"
        code = strip_c_comments(read_source(path))
        wrapper = "Safe_MeasureRDTSCPTiming"
        self.assertIn(
            wrapper,
            code,
            "{} no longer defines {} - if it was renamed this guard must follow it".format(
                path.name, wrapper
            ),
        )
        body = self._function_body(code, wrapper)
        self.assertIn(
            "HasRDTSCP",
            body,
            "{} is the only wrapper that can reach an RDTSCP assembly routine, so it must "
            "test HasRDTSCP before taking the assembly path. USE_ASM_FUNCTIONS is not a "
            "substitute: it says whether this BUILD has the assembly, not whether this "
            "PROCESSOR has the instruction".format(wrapper),
        )
        self.assertIn(
            "Fallback_MeasureRDTSCPTiming",
            body,
            "the ungated path must fall back to the C++ implementation rather than "
            "returning a sentinel - a fabricated timing value would corrupt the very "
            "measurement the detector reasons about",
        )


class PackerAntiAnalysisWiringContractTests(unittest.TestCase):
    """Pins the anti-analysis opcode scan to its caller and to the assembly's flag bits.

    Task 209: PackerDetector_x64.asm exports 15 routines and, until this wiring, NOT ONE
    had a caller - so neither the assembly nor its /ALTERNATENAME fallback ever executed.
    The binding was already correct (25 uppercase /ALTERNATENAME pragmas); what was missing
    was a call site. ScanForAntiDebugOpcodes is now invoked from PerformHeuristicAnalysis
    on the live file-analysis path.

    The flag bits are declared in TWO artifacts that no compiler cross-checks: the assembly
    sets them with `or r15d, <bit>` and the C++ caller decodes them from a table of
    literals. If either side is renumbered alone, the product silently reports the wrong
    technique - CPUID findings labelled as INT3, for example - while every test that only
    exercises one side keeps passing. That is what this class exists to prevent.
    """

    _ANTIEVASION_DIR = ROOT / "src" / "PhantomCore" / "AntiEvasion"

    def _packer_cpp(self) -> str:
        return strip_c_comments(read_source(self._ANTIEVASION_DIR / "PackerDetector.cpp"))

    def test_the_scanner_is_called_from_the_heuristic_analysis_path(self):
        code = self._packer_cpp()
        calls = re.findall(r"(?<![A-Za-z0-9_])ScanForAntiDebugOpcodes\s*\(", code)
        self.assertGreaterEqual(
            len(calls),
            1,
            "ScanForAntiDebugOpcodes has no caller in PackerDetector.cpp, so the hand-"
            "written assembly is dark again - neither it nor its fallback runs",
        )
        # Anchor on the DEFINITION, not the first mention. PerformHeuristicAnalysis is
        # forward-declared some 400 lines above its body, so a window taken from the first
        # occurrence measures the wrong region entirely and reports a false failure.
        definition = re.search(
            r"(?<![A-Za-z0-9_])PerformHeuristicAnalysis\s*\([^;{]*\)\s*noexcept\s*\{",
            code,
        )
        self.assertIsNotNone(
            definition,
            "the PerformHeuristicAnalysis definition was not found in PackerDetector.cpp",
        )

        brace = code.index("{", definition.end() - 1)
        depth = 0
        end = -1
        for pos in range(brace, len(code)):
            if code[pos] == "{":
                depth += 1
            elif code[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        self.assertGreater(end, brace, "unbalanced braces in PerformHeuristicAnalysis")
        body = code[brace:end + 1]

        self.assertIn(
            "ScanForAntiDebugOpcodes",
            body,
            "the scan must be reached from inside PerformHeuristicAnalysis - that is the "
            "function the live file analysis calls, and a call placed anywhere else would "
            "leave the assembly dark on the scan path",
        )
        self.assertIn(
            "epBytes",
            body,
            "the scan must run over the ENTRY-POINT bytes. Scanning the whole image would "
            "report CPUID and RDTSC on virtually every legitimate binary, because they "
            "occur in ordinary CRT startup code",
        )

        # Every assembly routine wired onto this path must stay wired. Each one that loses
        # its call site goes dark in both forms, because nothing else in the tree calls it.
        #
        # The word-boundary lookbehind is load-bearing, not decoration. A plain substring
        # test passes when the call is rerouted to Fallback_<name>, because the routine name
        # remains present INSIDE the fallback's name - so the guard would accept the exact
        # regression it exists to catch. This was found by mutation: the substring form
        # reported OK when every call was rerouted to the reduced-capability C++ path.
        for routine in (
            "ScanForSMCPatterns",
            "ScanForInt2DOpcode",
            "ScanForRDTSCOpcode",
            "ScanForCPUIDOpcode",
        ):
            direct = re.findall(
                r"(?<![A-Za-z0-9_])" + routine + r"(?![A-Za-z0-9_])", body
            )
            self.assertGreaterEqual(
                len(direct),
                1,
                "{} is no longer called directly from PerformHeuristicAnalysis. Nothing "
                "else in the tree calls it, so losing this call site returns the routine "
                "to being dead weight in the binary - and routing it through Fallback_{} "
                "would silently substitute the reduced-capability C++ implementation for "
                "the hand-written assembly".format(routine, routine),
            )

    def test_the_flag_bits_match_the_assembly_that_sets_them(self):
        asm = re.sub(r";[^\n]*", "", read_source(self._ANTIEVASION_DIR / "PackerDetector_x64.asm"))
        proc = re.search(
            r"(?is)^[ \t]*ScanForAntiDebugOpcodes[ \t]+PROC\b(.*?)^[ \t]*"
            r"ScanForAntiDebugOpcodes[ \t]+ENDP",
            asm,
            re.MULTILINE,
        )
        self.assertIsNotNone(proc, "the ScanForAntiDebugOpcodes PROC body was not found")

        # Every technique the assembly records is an `or r15d, <bit>` into the mask.
        asm_bits = set()
        for raw in re.findall(r"(?i)\bor\s+r15d\s*,\s*([0-9A-Fa-f]+h|\d+)", proc.group(1)):
            token = raw.lower()
            asm_bits.add(int(token[:-1], 16) if token.endswith("h") else int(token))
        self.assertGreaterEqual(
            len(asm_bits),
            5,
            "expected at least 5 technique bits in the assembly, found {} - either the "
            "routine changed or this parse is broken, and a broken parse would let the "
            "comparison below pass vacuously".format(sorted(asm_bits)),
        )

        cpp = self._packer_cpp()
        table = re.search(r"kAntiAnalysisTechniques\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;", cpp, re.DOTALL)
        self.assertIsNotNone(
            table, "the C++ technique table was not found - it decodes the assembly's mask"
        )
        cpp_bits = {int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)u", table.group(1))}

        self.assertEqual(
            asm_bits,
            cpp_bits,
            "the assembly sets bits {} but the C++ table decodes {}. Nothing cross-checks "
            "these two artifacts, so a mismatch mislabels techniques silently - a CPUID "
            "finding reported as an INT3 breakpoint".format(sorted(asm_bits), sorted(cpp_bits)),
        )

    def test_only_the_unambiguous_technique_raises_the_suspicion_flag(self):
        """0xCC is also alignment padding; CPUID and RDTSC occur in legitimate startup."""
        cpp = self._packer_cpp()
        marker = "kInt2DhFlag"
        self.assertIn(
            marker,
            cpp,
            "the INT 2Dh gate is gone. hasSuspiciousCharacteristics is READ by this module, "
            "so raising it for every technique would manufacture false positives on ordinary "
            "binaries: 0xCC doubles as padding and CPUID/RDTSC appear in CRT startup",
        )
        gate = cpp[cpp.index(marker):cpp.index(marker) + 400]
        self.assertIn(
            "hasSuspiciousCharacteristics",
            gate,
            "the INT 2Dh constant must guard the suspicion flag",
        )
        self.assertIn(
            "0x01u",
            gate,
            "INT 2Dh is bit 0 in the assembly; guarding on another bit would raise the flag "
            "for a technique that has benign uses",
        )


class HostContextAccessorUniformityContractTests(unittest.TestCase):
    """ONE rule set for EVERY host-context accessor in the anti-evasion layer.

    This class exists because the assembly wiring must not become a patchwork. Each
    accessor below is the sole consumer of a group of hand-written assembly routines that
    previously had no caller at all, and every one of them obeys the same contract:

      * CONTEXT ONLY. No accessor may contribute to a detection verdict. Host and self
        properties describe the machine or this service, not an analysed file or process,
        so treating them as evidence would misattribute - and reporting virtualisation as
        a threat would fire on the majority of legitimate enterprise endpoints.
      * NO WAITING OR STATE-MUTATING PROBE. Routines that sleep, manipulate the trap flag,
        or have unmeasured duration are excluded, because the first caller to touch an
        innocuous-looking accessor from a latency-sensitive path would stall it.
      * LIFECYCLE MATCHES SUBJECT. Invariant subjects are measured once and cached.
        Volatile subjects are sampled fresh and must NOT be cached, or a cached answer
        becomes a silent false negative the moment the real state changes.

    The two lifecycles are not an inconsistency, they are the consequence of the subjects
    differing: a processor's feature bits cannot change while the process lives, whereas a
    debugger can attach at any moment.
    """

    _ANTIEVASION_DIR = ROOT / "src" / "PhantomCore" / "AntiEvasion"

    # accessor -> (source file, lifecycle, routines it must call)
    _CACHED = "cached"
    _SAMPLED = "sampled"

    _ACCESSORS = (
        (
            "GetHostTimingProfile",
            "TimeBasedEvasionDetector.cpp",
            _CACHED,
            (
                "TimingRDTSCDelta",
                "TimingSerializedRDTSC",
                "TimingCPUIDLatency",
                "TimingCPUIDVariance",
                "TimingMeasureInstructions",
                "TimingMeasureMemory",
                "TimingCheckHypervisorLeaf",
                "TimingCompareRDTSCvRDTSCP",
            ),
        ),
        (
            "GetHostProcessorFacts",
            "EnvironmentEvasionDetector.cpp",
            _CACHED,
            (
                "CheckSSE2Support",
                "GetExtendedCPUIDMaxLeaf",
                "GetCPUIDFeatureFlags",
            ),
        ),
        (
            "SampleSelfDebugState",
            "EnvironmentEvasionDetector.cpp",
            _SAMPLED,
            (
                "CheckBeingDebugged",
                "CheckNtGlobalFlag",
                "GetProcessHeapFlags",
                "CheckDebugRegistersASM",
                "GetDebugRegisters",
            ),
        ),
    )

    # Waits, mutates CPU state, or has unmeasured duration. Forbidden in EVERY accessor.
    _FORBIDDEN = (
        "TimingMeasureSleep",
        "TimingDetectSleepAcceleration",
        "TimingDetectSingleStep",
        "TimingCalibrateTimebase",
        "CheckTrapFlag",
        "DetectSingleStep",
        "DetectHardwareBreakpoints",
        "MeasureExceptionTiming",
        "DetectPopfTiming",
        "MeasureINTTimingDelta",
    )

    def _accessor_body(self, accessor: str, source: str) -> str:
        code = strip_c_comments(read_source(self._ANTIEVASION_DIR / source))
        match = re.search(
            r"(?<![A-Za-z0-9_])" + accessor + r"\s*\(\s*\)\s*noexcept\s*\{", code
        )
        self.assertIsNotNone(
            match,
            "{} is not defined in {} - it is the sole consumer of its assembly routines, "
            "so losing it returns them to being dead weight".format(accessor, source),
        )
        brace = code.index("{", match.end() - 1)
        depth = 0
        for pos in range(brace, len(code)):
            if code[pos] == "{":
                depth += 1
            elif code[pos] == "}":
                depth -= 1
                if depth == 0:
                    return code[brace:pos + 1]
        raise AssertionError("unbalanced braces in " + accessor)

    def test_every_accessor_keeps_its_probes_wired(self):
        missing = []
        for accessor, source, _lifecycle, routines in self._ACCESSORS:
            body = self._accessor_body(accessor, source)
            for routine in routines:
                # Word boundary, not substring: a substring test accepts the call being
                # rerouted to Fallback_<name>, silently substituting the reduced C++
                # implementation for the hand-written assembly.
                if not re.search(
                    r"(?<![A-Za-z0-9_])" + routine + r"(?![A-Za-z0-9_])", body
                ):
                    missing.append("{}::{}".format(accessor, routine))
        self.assertEqual(
            [],
            missing,
            "these probes are no longer called from their only consumer: "
            + ", ".join(missing),
        )

    def test_no_accessor_calls_a_waiting_or_state_mutating_probe(self):
        offenders = []
        for accessor, source, _lifecycle, _routines in self._ACCESSORS:
            body = self._accessor_body(accessor, source)
            for routine in self._FORBIDDEN:
                if re.search(
                    r"(?<![A-Za-z0-9_])" + routine + r"(?![A-Za-z0-9_])", body
                ):
                    offenders.append("{}::{}".format(accessor, routine))
        self.assertEqual(
            [],
            offenders,
            "a host-context accessor must never call a routine that waits, mutates CPU "
            "state, or has unmeasured duration - these sleep, manipulate the trap flag, or "
            "calibrate over an unbounded interval: " + ", ".join(offenders),
        )

    def test_lifecycle_matches_the_subject(self):
        wrong = []
        for accessor, source, lifecycle, _routines in self._ACCESSORS:
            body = self._accessor_body(accessor, source)
            caches = re.search(r"(?<![A-Za-z0-9_])static\s+(?:const\s+)?", body) is not None
            if lifecycle == self._CACHED and not caches:
                wrong.append(
                    accessor + " describes an INVARIANT subject but does not cache, so "
                    "every caller re-issues CPUID"
                )
            if lifecycle == self._SAMPLED and caches:
                wrong.append(
                    accessor + " describes a VOLATILE subject but caches, so it will "
                    "report the first sample forever and turn a state change into a "
                    "silent false negative"
                )
        self.assertEqual([], wrong, "; ".join(wrong))

    def test_the_rdtscp_comparison_is_feature_gated(self):
        body = self._accessor_body("GetHostTimingProfile", "TimeBasedEvasionDetector.cpp")
        self.assertIn(
            "HasRDTSCP",
            body,
            "TimingCompareRDTSCvRDTSCP executes RDTSCP, which raises #UD where the "
            "processor does not implement it, so availability must be tested first",
        )
        self.assertLess(
            body.index("HasRDTSCP"),
            body.index("TimingCompareRDTSCvRDTSCP"),
            "the availability test must precede the RDTSCP call, not follow it",
        )


class NoMachineLifestyleSelfChecksContractTests(unittest.TestCase):
    """A security product must not ask the questions malware asks about its own host.

    Malware fingerprints the machine it lands on - has a human used it, does it hold
    browser history, how large is the screen, has a USB ever been attached - to decide
    whether it is being analysed and should stay dormant. A legitimate endpoint product has
    no use for those answers: it must behave identically on a VMware Workstation box and on
    bare metal. Carrying that code invites a reasonable reviewer to ask why an AV is
    profiling its host the way evasive malware does.

    Four such checks were removed from EnvironmentEvasionDetector: CheckUserActivity,
    CheckBrowserArtifacts, CheckDisplayConfiguration and CheckPeripheralHistory. Each was
    verified first to take no target parameter, to have no caller anywhere, to carry no
    MITRE technique id, and to be referenced by no test.

    DELIBERATELY NOT COVERED HERE, because these are a different thing: the host probes
    that plausibly SUPPRESS false positives - CheckHardwareFingerprint,
    CheckRegistryArtifacts, CheckFileSystemArtifacts, CheckNetworkConfiguration,
    CheckBlacklistedNames, CheckTimingIndicators, CheckAdvancedCPUIDIndicators - and the
    cloud identifiers in VMEvasionDetector, which feed IsLegitimateCloudVMType so that a
    cloud VM is treated as legitimate rather than suspicious. Knowing the host is a VM in
    order NOT to flag it is defensive. Knowing it in order to decide whether to act is not.
    """

    _ENV_CPP = ROOT / "src" / "PhantomCore" / "AntiEvasion" / "EnvironmentEvasionDetector.cpp"
    _ENV_HPP = ROOT / "src" / "PhantomCore" / "AntiEvasion" / "EnvironmentEvasionDetector.hpp"

    _REMOVED = (
        "CheckUserActivity",
        "CheckBrowserArtifacts",
        "CheckDisplayConfiguration",
        "CheckPeripheralHistory",
    )

    def test_the_machine_lifestyle_self_checks_stay_removed(self):
        cpp = strip_c_comments(read_source(self._ENV_CPP))
        hpp = strip_c_comments(read_source(self._ENV_HPP))
        offenders = []
        for name in self._REMOVED:
            pattern = r"(?<![A-Za-z0-9_])" + name + r"(?![A-Za-z0-9_])"
            if re.search(pattern, cpp):
                offenders.append(name + " (.cpp)")
            if re.search(pattern, hpp):
                offenders.append(name + " (.hpp)")
        self.assertEqual(
            [],
            offenders,
            "these host-fingerprinting checks answer the question malware asks about its "
            "own environment and have no defensive use, so they must not return: "
            + ", ".join(offenders),
        )

    def test_the_target_analysis_surface_survived_the_removal(self):
        """Anti-vacuity: prove the removal took the self-checks and not the detection."""
        hpp = strip_c_comments(read_source(self._ENV_HPP))

        # CheckEnvironmentVariables takes a processId and analyses the TARGET process from
        # the live AnalyzeProcess path. It was very nearly removed alongside the self-checks
        # because a signature scan misread it, so it is pinned explicitly here.
        match = re.search(
            r"(?<![A-Za-z0-9_])CheckEnvironmentVariables\s*\(([^)]*)\)", hpp
        )
        self.assertIsNotNone(match, "CheckEnvironmentVariables was removed from the header")
        self.assertIn(
            "processId",
            match.group(1),
            "CheckEnvironmentVariables must keep its processId parameter - it analyses the "
            "TARGET process's environment, which is detection, not host self-assessment",
        )

        for survivor in ("AnalyzeProcess", "AnalyzeSystemEnvironment", "AnalyzeAllProcesses"):
            self.assertRegex(
                hpp,
                r"(?<![A-Za-z0-9_])" + survivor + r"\s*\(",
                "{} is missing - the removal must not have touched target analysis".format(
                    survivor
                ),
            )


class VmTechniqueMitreMappingContractTests(unittest.TestCase):
    """Every anti-VM technique must carry an ATT&CK id, and new ones must not slip through.

    VMEvasionDetector shipped detections with zero MITRE attribution while every sibling
    carried ids - Environment 6, Sandbox 6, ProcessEvasion 11, NetworkBasedEvasion 12. Its
    anti-VM findings were therefore uncorrelatable in a SOC and invisible in the product's
    claimed technique coverage, despite the module having a live production entry point.

    The mapping is a switch over the AntiVMTechnique enum. Nothing in C++ forces a new
    enumerator to be classified - it would silently fall through to the parent T1497 - so
    this test is what reports the omission. It compares the enum against the switch
    directly, which is the only check that can catch an enumerator added without thought.
    """

    _VM_HPP = ROOT / "src" / "PhantomCore" / "AntiEvasion" / "VMEvasionDetector.hpp"

    def test_every_anti_vm_technique_has_an_explicit_mapping(self):
        source = read_source(self._VM_HPP)

        enum_block = re.search(
            r"enum\s+class\s+AntiVMTechnique\s*:\s*uint32_t\s*\{(.*?)\n\s*\};",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(enum_block, "the AntiVMTechnique enum was not found")
        names = re.findall(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", enum_block.group(1))
        self.assertGreaterEqual(
            len(names),
            40,
            "found only {} enumerators - the enum parse is broken and this comparison "
            "would pass vacuously".format(len(names)),
        )

        mapper = re.search(
            r"VMTechniqueToMitreId\s*\(AntiVMTechnique\s+technique\)\s*noexcept\s*\{(.*?)\n\s{8}\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(mapper, "VMTechniqueToMitreId was not found")
        body = mapper.group(1)

        unmapped = [
            n
            for n in names
            if not re.search(r"AntiVMTechnique::" + n + r"(?![A-Za-z0-9_])", body)
        ]
        self.assertEqual(
            [],
            unmapped,
            "these techniques have no explicit ATT&CK mapping and would fall through to the "
            "parent T1497, attributing a detection without saying what was observed: "
            + ", ".join(unmapped),
        )

    def test_the_detection_exposes_a_derived_id(self):
        source = strip_c_comments(read_source(self._VM_HPP))
        struct = re.search(
            r"struct\s+DetectedAntiVMTechnique\s*\{(.*?)\n\s*\};", source, re.DOTALL
        )
        self.assertIsNotNone(struct, "DetectedAntiVMTechnique was not found")
        body = struct.group(1)

        self.assertIn(
            "MitreId",
            body,
            "the detection must expose its ATT&CK id, otherwise a consumer has no way to "
            "attribute it",
        )
        self.assertIn(
            "VMTechniqueToMitreId(technique)",
            body,
            "MitreId must DERIVE the id from `technique`. A stored field could be left "
            "unset at a call site that assigns the technique and forgets it, and an empty "
            "id on a real detection looks attributed while saying nothing",
        )
        self.assertNotRegex(
            body,
            r"std::string\s+mitreId",
            "do not store the id alongside the technique - deriving it is what prevents the "
            "two from disagreeing",
        )


class EvasionFanOutReportingContractTests(unittest.TestCase):
    """The process-creation evasion fan-out must report every detector that fired,
    must not skip a detector because another already fired, and must not claim an
    enforcement outcome before that outcome has been decided.

    These are source contracts rather than behavioural tests because reaching this
    handler needs a loaded kernel driver and a live filter port - the same reason the
    reply-horizon and fan-out-budget contracts beside them are expressed this way.
    """

    _EXPECTED_DETECTORS = (
        "DebuggerEvasionDetector",
        "VMEvasionDetector",
        "ProcessEvasionDetector",
        "TimeBasedEvasionDetector",
        "NetworkBasedEvasionDetector",
        "EnvironmentEvasionDetector",
    )

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST: the change deliberately documents the defects it removed,
        # so the explanatory text names evasionDetected, the hardcoded true and the
        # dead parameters. A comment-blind scan is guaranteed to false-positive.
        cls.rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.telemetry_hpp = strip_c_comments(read_source(TELEMETRY_COLLECTOR_HPP_PATH))

    def _decision_block(self) -> str:
        """Brace-match the evasion decision block.

        Sliced by anchor rather than by extract_c_function because the enclosing
        handler is enormous and the interesting region is a single statement inside
        it.
        """
        anchor = "if (!evasionFindings.empty()) {"
        found = self.rtp.count(anchor)
        self.assertEqual(
            found, 1, f"expected exactly one evasion decision block, found {found}"
        )
        opening = self.rtp.index("{", self.rtp.index(anchor))
        depth = 0
        for index in range(opening, len(self.rtp)):
            if self.rtp[index] == "{":
                depth += 1
            elif self.rtp[index] == "}":
                depth -= 1
                if depth == 0:
                    return self.rtp[opening : index + 1]
        self.fail("could not brace-match the evasion decision block")
        return ""
    def test_the_environment_detector_is_not_gated_on_another_detector_firing(self) -> None:
        """Environment analysis must run whether or not something else already fired.

        It was the only one of the six gated on !evasionDetected, so any process that
        had already tripped the debugger, VM, process, timing or network detector got
        no environment examination at all - losing T1016, T1082, T1497 and its three
        sub-techniques on exactly the samples most worth examining.
        """
        marker = 'evasionBudgetExceeded("EnvironmentEvasionDetector")'
        occurrences = self.rtp.count(marker)
        self.assertEqual(
            occurrences,
            1,
            "expected exactly one environment-detector budget check in the "
            f"process-notify handler, found {occurrences}",
        )
        gate = enclosing_statement(self.rtp, self.rtp.index(marker))

        for forbidden in ("evasionDetected", "evasionFindings.empty()", "evasionFindings.size()"):
            self.assertNotIn(
                forbidden,
                gate,
                "the environment detector's gate must not depend on whether another "
                f"detector already fired, but it names {forbidden!r}. Skipping this "
                "analysis because other evidence exists discards T1016/T1082/T1497 "
                "coverage on the highest-risk processes.",
            )

        # ANTI-WEAKENING: the budget is this path's sanctioned way to shed work under
        # time pressure and must survive. Removing it would be a different defect.
        self.assertIn(
            "evasionBudgetExceeded",
            gate,
            "the environment detector must stay inside the process-notify budget",
        )

        # ANTI-VACUITY: the block must still perform the analysis. Counted rather than
        # asserted with assertIn, which would dump the whole 400 KB source on failure.
        analyses = self.rtp.count("m_environmentDetector->AnalyzeProcess(")
        self.assertGreaterEqual(
            analyses,
            1,
            "the environment analysis call itself must still be present; found "
            f"{analyses} call sites, so this test would pass vacuously",
        )

    def test_every_evasion_detector_records_through_one_mechanism(self) -> None:
        """All six detectors must append a finding, not write a shared string.

        Six blocks previously wrote one std::wstring under three different rules -
        unconditional overwrite, assign-only-if-nothing-fired, and whole-block skip -
        so which detector the SOC alert named depended on block order crossed with
        per-block guard style, and every other finding was dropped from the alert.
        """
        sites = self.rtp.count("noteEvasion(")
        self.assertEqual(
            sites,
            len(self._EXPECTED_DETECTORS),
            f"expected {len(self._EXPECTED_DETECTORS)} noteEvasion call sites, one "
            f"per evasion detector, found {sites}",
        )

        missing = [
            name
            for name in self._EXPECTED_DETECTORS
            if f'noteEvasion("{name}"' not in self.rtp
        ]
        self.assertEqual(
            missing,
            [],
            "every evasion detector must record its finding through noteEvasion so "
            "the alert can name all of them; these do not: " + ", ".join(missing),
        )

        # No block may go back to assigning the shared description directly - that is
        # what made the report depend on ordering.
        direct = re.findall(r"detectionSource\s*=\s*std::format", self.rtp)
        self.assertEqual(
            direct,
            [],
            "a detector block assigned the shared description string directly "
            f"({len(direct)} site(s)); findings must be appended instead so no "
            "detector can overwrite another's evidence",
        )

    def test_the_findings_record_is_append_only(self) -> None:
        """The budget's correctness argument depends on findings never being removed.

        The comment above the budget states that a detector can only ADD evidence, so
        skipping one can never manufacture a wrong Block. That holds only while the
        container is append-only.
        """
        for mutator in (".clear()", ".erase(", ".pop_back(", ".resize("):
            # BOUNDED: assertNotIn prints the entire 394 KB source on failure.
            self.assertFalse(
                ("evasionFindings" + mutator) in self.rtp,
                f"evasionFindings{mutator} would break the append-only property the "
                "budget's safety argument relies on",
            )

    def test_evasion_telemetry_reports_the_outcome_it_actually_had(self) -> None:
        """Telemetry must carry the real enforcement outcome, not an assumed one.

        Six records were emitted inside their detector blocks with blocked hardcoded
        true, about fifty lines before the enforcement decision existed - and that
        decision is gated on a protection mode whose default, BLOCK_KNOWN, is below
        BLOCK_SUSPICIOUS. So on a default endpoint nothing was blocked and every
        record still told the SOC actionTaken="Blocked".
        """
        # SCOPED TO THE FAN-OUT, NOT THE FILE, AND THE DIFFERENCE MATTERS.
        #
        # The defect was SIX emissions inside the detector blocks, roughly fifty
        # lines before the enforcement decision existed. The invariant that removes
        # it is "one emission per finding, after the outcome is decided" WITHIN this
        # decision - not "one emission in the whole translation unit". A file-wide
        # count also forbids unrelated paths from reporting evasion telemetry at all,
        # which is a different and unintended restriction: the deferred deep-scan
        # thread legitimately reports a target sandbox-evasion finding, and there the
        # outcome is decided by construction because nothing can be blocked once the
        # process is already running.
        decision = self._decision_block()
        in_decision = re.findall(
            r"EmitEvasionTelemetry\(([^;]*?)\)\s*;", decision, re.S
        )
        self.assertEqual(
            len(in_decision),
            1,
            f"expected exactly one EmitEvasionTelemetry call inside the evasion "
            f"decision, found {len(in_decision)}. Per-detector emission is what made "
            "the outcome unknowable at the point of reporting.",
        )
        self.assertIn(
            "willBlock",
            in_decision[0],
            "the telemetry call must pass the decided outcome, not a literal: "
            f"arguments were {in_decision[0].strip()!r}",
        )

        # AND FILE-WIDE, NO CALL MAY CLAIM AN OUTCOME THAT WAS NEVER DECIDED. The
        # permitted forms are the fan-out's computed decision and a literal false,
        # which is what a path that cannot block must report.
        calls = re.findall(r"EmitEvasionTelemetry\(([^;]*?)\)\s*;", self.rtp, re.S)
        self.assertGreaterEqual(
            len(calls), 1, "no evasion telemetry is emitted anywhere"
        )
        undecided = [
            " ".join(args.split())
            for args in calls
            if "willBlock" not in args and not re.search(r"(?<![A-Za-z0-9_])false\s*\)?$", args.strip())
        ]
        self.assertEqual(
            undecided,
            [],
            "every evasion telemetry call must report a decided outcome - the "
            "fan-out's computed decision, or false where nothing can be blocked. "
            "These do neither: " + " | ".join(undecided[:2]),
        )

        literal_true = re.findall(r"EmitEvasionTelemetry\([^;]*?,\s*true\s*\)", self.rtp, re.S)
        self.assertEqual(
            literal_true,
            [],
            "EmitEvasionTelemetry must never be handed a literal true for the "
            "outcome - that is the over-claimed-block defect this guard exists for",
        )

        # ORDERING, NOT MERE PRESENCE. A test that only checks willBlock appears
        # cannot tell whether it was computed before the record was emitted.
        decided = self.rtp.index("const bool willBlock")
        emitted = self.rtp.index("EmitEvasionTelemetry(finding")
        self.assertLess(
            decided,
            emitted,
            "the enforcement outcome must be decided BEFORE telemetry reports it "
            f"(willBlock at {decided}, emission at {emitted})",
        )
        self.assertIn(
            "ProtectionMode::BLOCK_SUSPICIOUS",
            enclosing_statement(self.rtp, decided),
            "the outcome must be derived from the configured protection mode",
        )

    def test_evasion_telemetry_does_not_accept_data_it_cannot_record(self) -> None:
        """The function must not promise attribution the telemetry struct cannot hold.

        It used to take processId, imagePath, detectionSource and techniqueCount and
        use none of them, because DetectionEventData has no field for any of them.
        Four dead parameters read as attribution that works.

        THIS TEST IS ALSO THE FORCING FUNCTION FOR THE GAP: if DetectionEventData ever
        gains a process or path field, the second half fails and whoever added it is
        told to wire evasion attribution through rather than leave it unused.
        """
        body = extract_c_function(self.rtp, "EmitEvasionTelemetry")
        signature = body[: body.index("{")]
        for dead in ("processId", "imagePath", "detectionSource", "techniqueCount"):
            self.assertNotIn(
                dead,
                signature,
                f"EmitEvasionTelemetry accepts {dead!r} but DetectionEventData has no "
                "field it can be assigned to, so the parameter is a false promise of "
                "attribution",
            )

        # extract_c_function is for functions; brace-match the struct directly.
        opening = self.telemetry_hpp.index("{", self.telemetry_hpp.index("struct DetectionEventData"))
        depth = 0
        closing = opening
        for index in range(opening, len(self.telemetry_hpp)):
            if self.telemetry_hpp[index] == "{":
                depth += 1
            elif self.telemetry_hpp[index] == "}":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        self.assertGreater(
            closing, opening, "could not brace-match struct DetectionEventData"
        )
        struct = self.telemetry_hpp[opening : closing + 1]
        carriers = [
            field
            for field in ("processId", "ProcessId", "filePath", "imagePath", "processName")
            if re.search(r"(?<![A-Za-z0-9_])" + field + r"(?![A-Za-z0-9_])", struct)
        ]
        self.assertEqual(
            carriers,
            [],
            "DetectionEventData has gained " + ", ".join(carriers) + ", so evasion "
            "telemetry can now identify its subject - wire it through "
            "EmitEvasionTelemetry and update this contract, rather than leaving the "
            "new field unpopulated",
        )


class SandboxHostContextIsNotAVerdictContractTests(unittest.TestCase):
    """A host probe describes the machine we run on. It is never evidence about a sample.

    SandboxEvasionDetector has two independent halves, measured: a HOST half that asks
    whether this machine looks like a sandbox, and a TARGET half that asks whether a
    supplied process contains sandbox-evasion code. The target half calls no host-half
    function. Only the second is detection, and the distinction is what keeps the product
    from flagging every VMware, Hyper-V and cloud endpoint as being under analysis.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST: the fix documents the claim it removed, so the explanatory
        # text quotes the old warning verbatim. A comment-blind scan false-positives.
        cls.rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.sandbox = strip_c_comments(read_source(SANDBOX_EVASION_DETECTOR_CPP_PATH))
        cls.sandbox_hpp = strip_c_comments(
            read_source(SANDBOX_EVASION_DETECTOR_HPP_PATH)
        )

    def _startup_block(self) -> str:
        opening = "SandboxEvasionDetector::Instance();"
        closing = "auto& timeBased"
        for marker in (opening, closing):
            found = self.rtp.count(marker)
            self.assertEqual(
                found, 1, f"expected exactly one {marker!r} in the startup path, found {found}"
            )
        return self.rtp[self.rtp.index(opening) : self.rtp.index(closing)]

    def test_the_startup_host_scan_makes_no_threat_claim(self) -> None:
        """Virtualisation is not evidence and must not be reported as a threat.

        The startup path used to warn that the "endpoint may be under malware analysis"
        whenever the hardware profile looked sandbox-like or the environment score
        reached 50 - a claim about this machine, on a path with no other consumer.
        """
        block = self._startup_block()

        # BOUNDED: assertNotIn against the ~2 KB startup block dumps the whole region on
        # failure. Report only the offending line.
        for claim in (
            "may be under malware analysis",
            "Sandbox environment detected",
            "Sandbox detected",
        ):
            offending = [line.strip() for line in block.splitlines() if claim in line]
            self.assertEqual(
                offending,
                [],
                f"the startup host scan asserts {claim!r}. A legitimate endpoint product "
                "must behave identically on a virtual machine and on bare metal, so "
                "virtualisation cannot be reported as a threat. Offending line: "
                + (offending[0] if offending else ""),
            )

        # CONTEXT ONLY, MADE ENFORCEABLE: the host result may be reported, never branched
        # on. A condition keyed to it is the first step to it reaching a verdict.
        offenders = [
            line.strip()
            for line in block.splitlines()
            if re.search(r"\bif\s*\(", line)
            and re.search(r"isSandboxLike|hostHardware|hostEnvironment", line)
        ]
        self.assertEqual(
            offenders,
            [],
            "the host context must not be tested in a condition; found: "
            + " | ".join(offenders[:3]),
        )

        # THE SEVERITY ASSERTION THAT USED TO SIT HERE IS GONE ON PURPOSE.
        #
        # It required the host report to be raised through Logger::Info rather than Warn,
        # which only makes sense while a host report EXISTS. The owner has since decided
        # that host context may calibrate detection, and that decision removed these two
        # probes outright rather than re-homing them - see the sibling test for the unit
        # argument. There is no host report left to check the severity of, so asserting one
        # would be asserting the presence of the thing this contract now forbids.
    def test_the_startup_path_takes_no_host_sandbox_likeness_measurement(self) -> None:
        """A host "sandbox-likeness" score cannot calibrate anything, so it is not taken.

        SUPERSEDES an earlier contract that REQUIRED these two probes to run. That contract
        was correct while the owner had not yet decided whether host context may calibrate
        detection thresholds: deleting the measurement would have foreclosed the choice, so
        it was kept and only its threat CLAIM was removed.

        The decision has since been taken - host context MAY calibrate detection, because a
        threshold that adapts to the machine yields fewer false positives than a fixed
        constant. That does not rescue these two probes, and the reason is a unit argument:

            a host measurement can calibrate a target measurement only when the two are
            expressed in the SAME UNIT.

        GetHostTimingProfile yields cycles and a target RDTSC delta is cycles, so it is a
        usable baseline. GetHostProcessorFacts yields CPU feature bits, which decide whether
        a target instruction sequence is meaningful at all. AnalyzeHardware and
        AnalyzeEnvironment yielded a suspicion score and an isSandboxLike flag describing
        THIS MACHINE, and nothing in the product is denominated in sandbox likeness, so
        there was nothing for them to calibrate. They answered "am I being analysed?" - a
        question a malware sample asks and a legitimate endpoint product has no use for.
        """
        code = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        for probe in ("AnalyzeHardware", "AnalyzeEnvironment"):
            calls = len(re.findall(r"(?<![A-Za-z0-9_])" + probe + r"\s*\(", code))
            self.assertEqual(
                calls,
                0,
                f"{probe}() is called {calls} time(s) on a product path. It measures this "
                "machine's sandbox likeness, which no target measurement shares a unit "
                "with, so it can calibrate nothing and must not run on an endpoint.",
            )

        # ANTI-VACUITY 1: this must not pass because the startup block was deleted.
        block = self._startup_block()
        inits = block.count("sandbox.Initialize(")
        self.assertEqual(
            inits,
            1,
            "the sandbox detector must still be initialised at startup; its TARGET half is "
            f"live and gated on that, but Initialize appears {inits} time(s)",
        )
        self.assertIn(
            "m_sandboxDetectorInitialized",
            block,
            "the initialisation flag the deferred target analysis is gated on must survive",
        )

        # ANTI-VACUITY 2: the half that DOES reach a verdict must still be wired. Removing
        # host inference must never be satisfiable by removing the detector altogether.
        feeds = len(
            re.findall(
                r"(?<![A-Za-z0-9_])AnalyzeDeferredProcessForSandboxEvasion\s*\(", code
            )
        )
        self.assertGreaterEqual(
            feeds,
            2,
            "the target-analysis feed restored in ad218385 must still be declared and "
            f"called; found {feeds} occurrence(s) of its helper",
        )
    def test_the_host_scan_half_no_longer_exists(self) -> None:
        """SUPERSEDES a guard that required the host notifier to exist but stay unreachable.

        That contract said: do not register a sandbox detection callback, because
        InvokeCallbacks is reachable only from ScanSystem, whose only caller is
        ScanSystemAsync, which nothing calls. It asserted ScanSystemAsync still existed so
        that the reasoning would be revisited if the notifier ever became reachable.

        The notifier is now GONE rather than merely unreachable, which is strictly stronger:
        a callback cannot be registered because there is no registration API and no result
        type to deliver. The whole host half - the half that asked whether THIS MACHINE is a
        sandbox - has been removed. A legitimate endpoint product must behave identically on
        a virtual machine and on bare metal, so that question has no product use.
        """
        removed = (
            "ScanSystem",
            "ScanSystemAsync",
            "QuickScan",
            "AnalyzeHardware",
            "AnalyzeEnvironment",
            "AnalyzeWearAndTear",
            "ScanArtifacts",
            "AnalyzeHumanInteraction",
            "VerifyHumanInteraction",
            "CheckHardwareSpecs",
            "CheckUptime",
            "CheckScreenResolution",
            "CheckNamedObjects",
            "CheckSystemWearAndTear",
            "CheckAPIHooks",
            "CalculateProbability",
            "IdentifySandboxProduct",
            "CalculateMousePathEntropy",
            "AddIndicator",
            "RegisterCallback",
            "UnregisterCallback",
            "InvokeCallbacks",
        )
        for source, label in ((self.sandbox, "cpp"), (self.sandbox_hpp, "hpp")):
            offenders = [
                name
                for name in removed
                if re.search(r"(?<![A-Za-z0-9_])" + name + r"\s*\(", source)
            ]
            self.assertEqual(
                offenders,
                [],
                f"the host scan half is back in the {label}: {offenders}. It answers "
                '"is this machine a sandbox?", which is a question a malware sample asks. '
                "If a genuine need appears, take it to a module whose subject is this host "
                "and give it a consumer that cannot reach a sample verdict.",
            )

        # ANTI-VACUITY 1: the TARGET half must survive. This contract must never be
        # satisfiable by deleting the detector outright - that half is real detection and
        # is the product's only producer of T1012 and T1057.
        for kept in (
            "CheckTargetSandboxImports",
            "CheckTargetSandboxStrings",
            "CheckTargetTimingPatterns",
            "CalculateProcessEvasionScore",
        ):
            # BOUNDED: assertRegex prints the ENTIRE haystack on failure, and this one is
            # the whole 1,700-line module - measured at 55,602 characters in a mutation
            # run. A failure nobody can read is a failure nobody acts on.
            found = re.search(r"(?<![A-Za-z0-9_])" + kept + r"\s*\(", self.sandbox)
            self.assertIsNotNone(
                found,
                f"{kept} is gone; the target half is this module's reason to exist",
            )

        # ANTI-VACUITY 2, AND THE MORE IMPORTANT ONE. The host TIMING routines are kept
        # deliberately and must not be swept away by a later "delete unreferenced code"
        # pass. They measure this host in CYCLES, which is the same unit a target RDTSC
        # delta is measured in, so they are the only legitimate calibration input this
        # module can offer - unlike the sandbox-likeness score that was just removed,
        # which nothing shares a unit with. Deleting them would foreclose the
        # baseline-relative thresholds the owner has decided to build.
        for calibration in (
            "Fallback_MeasureRDTSCOverhead",
            "Fallback_MeasureCPUIDOverhead",
            "Fallback_GetRDTSCFrequency",
            "Fallback_MeasureTimingPrecision",
        ):
            found = re.search(r"(?<![A-Za-z0-9_])" + calibration + r"\s*\(", self.sandbox)
            self.assertIsNotNone(
                found,
                f"{calibration} was removed. It measures the host in cycles and is a "
                "calibration input, not dead code - see the header note where the host "
                "scan used to be declared.",
            )
    def test_the_sandbox_technique_ids_belong_to_target_analysis(self) -> None:
        """T1012 and T1057 are this product's ONLY holders of those techniques.

        Measured: both are pushed in CalculateProcessEvasionScore, which takes a
        ProcessSandboxResult and is fed by CheckTargetSandbox* - functions that take a
        process HANDLE and examine a supplied target. They describe what the SAMPLE did,
        not what this machine looks like. Keeping them there is what makes the attribution
        true; moving either into a host self-check would attribute a property of our own
        endpoint to an analysed process.
        """
        scorer = extract_c_function(
            self.sandbox, "SandboxEvasionDetector::CalculateProcessEvasionScore"
        )
        self.assertIn(
            "ProcessSandboxResult",
            scorer[: scorer.index("{")],
            "the scorer must operate on a target result, not on a host result",
        )

        for technique in ("T1057", "T1012"):
            in_scorer = scorer.count(technique)
            in_file = self.sandbox.count(technique)
            self.assertEqual(
                in_scorer,
                1,
                f"{technique} must be attributed exactly once, inside the target scorer; "
                f"found {in_scorer} occurrences there",
            )
            self.assertEqual(
                in_file,
                in_scorer,
                f"{technique} appears {in_file} times in the module but only {in_scorer} "
                "inside the target scorer, so a host self-check is now claiming a "
                "technique that describes an analysed sample",
            )


class DeferredSandboxTargetAnalysisContractTests(unittest.TestCase):
    """SandboxEvasionDetector's target analysis belongs off the kernel-reply path.

    MEASURED, best-of-5 against a live process: 367 ms at shipped defaults
    (64 MB memory / 4 MB code), 106 ms even when the memory bound is cut to 1 MB,
    and 42 ms for imports alone. The driver waits 500 ms and the evasion suite on
    the process-notify callback is bounded at 250 ms, so no configuration of this
    analysis fits there - the bound caps bytes READ while the address-space walk
    and module enumeration happen regardless.

    These are source contracts because reaching the deferred thread needs a loaded
    driver and a live filter port.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST: the change documents its own measurements and quotes the
        # rejected placement, so a comment-blind scan would false-positive.
        cls.rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.rtp_hpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_HPP_PATH))

    _HELPER = "AnalyzeDeferredProcessForSandboxEvasion"

    def _brace_matched_body(self, source: str, anchor: str) -> str:
        """Slice a function by brace matching from an exact anchor.

        extract_c_function takes the FIRST occurrence of a name, and both functions
        involved here are NAMED EARLIER IN THE FILE THAN THEY ARE DEFINED - the loop
        appears in a std::thread construction hundreds of lines above its body - so
        using it would slice a reference instead of a definition.
        """
        found = source.count(anchor)
        self.assertEqual(
            found, 1, f"expected exactly one {anchor!r}, found {found}"
        )
        opening = source.index("{", source.index(anchor))
        depth = 0
        for index in range(opening, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[opening : index + 1]
        self.fail(f"could not brace-match the body of {anchor!r}")
        return ""

    def test_the_target_analysis_is_invoked_only_from_the_deferred_thread(self) -> None:
        """It must have exactly one caller, and that caller must be the deferred loop.

        Asserting the single call site rather than scanning the process-notify
        handler is what makes this airtight: if the helper is called once and that
        once is inside the deferred loop, it cannot also be on the callback the
        kernel blocks CreateProcess on.
        """
        references = self.rtp.count(self._HELPER + "(")
        self.assertEqual(
            references,
            2,
            "expected exactly two references to the helper - its definition and one "
            f"call - but found {references}. A second call site would put a 367 ms "
            "analysis somewhere it has not been costed.",
        )

        # BOUNDED: assertIn would print the whole loop body on failure.
        loop = self._brace_matched_body(self.rtp, "void DeferredDeepScanLoop() {")
        in_loop = loop.count(self._HELPER + "(")
        self.assertGreaterEqual(
            in_loop,
            1,
            "the target analysis must be driven from the deferred deep-scan loop, "
            "which is off the kernel-reply path and runs below normal priority; the "
            f"loop contains {in_loop} call(s) to it",
        )

        # ANTI-VACUITY: the analysis itself must still be performed.
        analysis_calls = self.rtp.count(".AnalyzeProcess(hProcess")
        self.assertEqual(
            analysis_calls,
            1,
            "expected exactly one handle-based AnalyzeProcess call - the restored "
            f"target analysis - but found {analysis_calls}",
        )

    def test_the_deferred_analysis_verifies_the_process_before_reading_it(self) -> None:
        """The queued pid must be checked against the queued image FIRST.

        The deferred queue carries (path, processId) and the path means different
        things per producer: the accessed FILE from the file-scan handler, the
        process IMAGE from the notify handler. Requiring them to agree selects the
        notify entries and simultaneously supplies pid-recycling safety, per-launch
        deduplication, and the cost bound that follows from it.
        """
        body = self._brace_matched_body(
            self.rtp, "void " + self._HELPER + "(uint32_t processId,"
        )

        # BOUNDED: counted rather than asserted with assertIn, which would print the
        # entire helper body on failure.
        for required in ("QueryFullProcessImageNameW", "_wcsicmp"):
            present = body.count(required)
            self.assertGreaterEqual(
                present,
                1,
                f"the identity check needs {required}; without it a recycled pid "
                "would have another program's memory attributed to this entry "
                f"(found {present} occurrences)",
            )

        # ORDERING, NOT MERE PRESENCE. A check that runs after the read protects
        # nothing, and an assertion that both tokens merely appear cannot tell.
        compared = body.index("_wcsicmp")
        analysed = body.index(".AnalyzeProcess(")
        self.assertLess(
            compared,
            analysed,
            "the image comparison must precede the analysis "
            f"(comparison at {compared}, analysis at {analysed})",
        )

    def test_the_restored_detection_does_not_claim_or_perform_enforcement(self) -> None:
        """This restores detection and telemetry, not blocking, and must say so.

        The process has been running since before the deferred thread saw it, so no
        pre-execution decision remains. Sandbox-evasion capability is also inference
        - what a program is equipped to do, not a named artefact - which is the
        evidence class this file already refuses to let act destructively alone.
        """
        body = self._brace_matched_body(
            self.rtp, "void " + self._HELPER + "(uint32_t processId,"
        )

        for forbidden in (
            "HandleDeferredThreat",
            "TerminateProcess",
            "BlockProcess",
            "QuarantineFile",
            "RequestKernelProcessBlock",
        ):
            offending = [line.strip() for line in body.splitlines() if forbidden in line]
            self.assertEqual(
                offending,
                [],
                f"the deferred sandbox analysis calls {forbidden}, which turns an "
                "inference-class observation about an already-running process into "
                "an action. That is a policy change, not a wiring change. Offending "
                "line: " + (offending[0] if offending else ""),
            )

        telemetry = re.search(r"EmitEvasionTelemetry\(([^;]*?)\)\s*;", body, re.S)
        self.assertIsNotNone(
            telemetry, "the detection must be reported to telemetry"
        )
        assert telemetry is not None
        self.assertIn(
            "false",
            telemetry.group(1),
            "telemetry must record that nothing was blocked; arguments were "
            f"{telemetry.group(1).strip()!r}",
        )

    def test_the_capability_counter_cannot_become_a_structural_zero(self) -> None:
        """A counter that is declared but never reset or reported reads as healthy.

        RTPStatistics::Reset carries an explicit instruction that every counter must
        be listed, because a partial reset looks complete while leaving stale values
        behind for the delta logging to underflow against.
        """
        counter = "sandboxEvasionCapabilityDetected"
        self.assertIn(
            counter,
            self.rtp_hpp,
            f"{counter} must be declared in the statistics struct",
        )
        sites = self.rtp.count(counter)
        self.assertGreaterEqual(
            sites,
            4,
            f"{counter} needs an increment, a load for the periodic report, a use in "
            f"that report's format arguments, and a reset - found {sites} references",
        )
        # BOUNDED: assertIn prints the entire 394 KB source on failure.
        self.assertTrue(
            (counter + " = 0;") in self.rtp,
            f"{counter} is missing from RTPStatistics::Reset, so a reset would leave "
            "it stale while appearing to have cleared everything",
        )
        self.assertTrue(
            (counter + "++") in self.rtp,
            f"{counter} is never incremented, so it can only ever read zero",
        )

class TimingDetectorHonestEvidenceContractTests(unittest.TestCase):
    """A declared control must act, and a stated measurement must have been taken.

    TimeBasedEvasionDetector carried both defects. Its master switch was declared,
    defaulted true and read by nothing, so a policy that disabled the detector got a
    detector that kept running. And two of its findings cited evidence fields that are
    assigned nowhere in the module, so a Critical sleep-acceleration alert reported
    "Acceleration ratio: 0.00" as its supporting detail.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST. The fix DOCUMENTS the fields it stopped citing, naming each one
        # in prose, so a comment-blind scan would report the defect as still present.
        cls.tbe = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))

    def test_the_master_switch_is_honoured_and_reports_not_analysed(self) -> None:
        """A switched-off detector must not be indistinguishable from a clean verdict."""
        reads = len(re.findall(r"(?<![A-Za-z0-9_])config\.enabled(?![A-Za-z0-9_])", self.tbe))
        self.assertEqual(
            reads,
            1,
            f"config.enabled is read {reads} time(s); the master switch must gate the "
            "analysis exactly once",
        )

        idx = self.tbe.index("config.enabled")
        window = self.tbe[idx : idx + 600]
        self.assertIn(
            "analysisComplete = false",
            window,
            "a disabled detector must report NOT ANALYSED. isEvasive defaults to false, so "
            "returning without clearing analysisComplete lets a caller read a detector that "
            "never looked as a clean verdict",
        )
        self.assertIn(
            "errorMessage",
            window,
            "the reason for not analysing must be recorded, not left for a reader to infer",
        )

    def test_no_finding_cites_an_evidence_field_nothing_computes(self) -> None:
        """A field may only be cited once something assigns it.

        NARROWED when AnalyzeObservedDelays landed, exactly as this test's own
        failure message instructed: fragmentedSleepCount and avgFragmentDurationMs
        now have a real producer driven from the emulator's intercepted delay calls,
        so forbidding their citation had become wrong. They moved to the opposite
        assertion below rather than simply being deleted, which is strictly
        stronger - it pins that the producer still exists.
        """
        # STILL no producer anywhere in the module. accelerationRatio describes the
        # ratio of ACTUAL to REQUESTED delay, and measuring an actual delay needs
        # observation of both entry and exit of the call. The emulator reports the
        # requested duration only, so this remains unproduced and uncitable.
        for field in ("accelerationRatio",):
            cites = len(
                re.findall(r"(?<![A-Za-z0-9_])" + field + r"(?![A-Za-z0-9_])", self.tbe)
            )
            self.assertEqual(
                cites,
                0,
                f"{field} is cited in code again. Nothing assigns it, so it is permanently "
                "zero and any alert quoting it fabricates its own supporting evidence. If a "
                "producer has since been written, cite it here and update this contract in "
                "the SAME change.",
            )

        # NOW PRODUCED. Require the assignment to survive, so a future edit cannot
        # silently return these to permanently-zero while the reporting that quotes
        # them stays in place.
        for field in ("fragmentedSleepCount", "avgFragmentDurationMs"):
            assigned = len(
                re.findall(
                    r"(?<![A-Za-z0-9_])" + field + r"\s*=(?!=)", self.tbe
                )
            )
            self.assertGreaterEqual(
                assigned,
                1,
                f"{field} lost its producer. It is populated by AnalyzeObservedDelays "
                "from the emulator's observed delay calls; if that was removed, the "
                "fragmentation reporting that quotes this field must be removed in the "
                "SAME change rather than left quoting a permanent zero.",
            )

        # ANTI-VACUITY: the two detections must survive. This contract must never be
        # satisfiable by deleting the findings that carried the bad evidence.
        for detection in ("accelerationDetected", "fragmentationDetected"):
            present = re.search(
                r"(?<![A-Za-z0-9_])" + detection + r"(?![A-Za-z0-9_])", self.tbe
            )
            self.assertIsNotNone(
                present,
                f"{detection} is gone; sleep-based evasion is a real T1497.003 technique "
                "and the branch is the only written statement of that intent",
            )

        # And the replacement evidence must be drawn from fields that ARE populated.
        for measured in ("sleepAPIsUsed", "sleepCallCount"):
            present = re.search(
                r"(?<![A-Za-z0-9_])" + measured + r"(?![A-Za-z0-9_])", self.tbe
            )
            self.assertIsNotNone(
                present, f"{measured} is the measured evidence the findings now cite"
            )

class TimingUnmeasuredFieldContractTests(unittest.TestCase):
    """A zero that means "not measured" must never be compared as if it were data.

    TimeBasedEvasionDetector declares six detection methods and implements one. Anything
    describing an OBSERVED delta, rate, duration or drift needs a runtime method that does
    not exist, so those fields hold their default of zero permanently. A comparison against
    one of them cannot be true, which makes it worse than absent: it adds the appearance of
    detection and none of the substance. That is the failure mode an unpopulated bloom
    filter and a non-walkable B+tree index both produced in this codebase.
    """

    # Fields with no producer. Each is marked at its declaration in the header.
    UNMEASURED = (
        "avgDeltaNs",
        "minDeltaNs",
        "maxDeltaNs",
        "deltaStdDev",
        "callsPerSecond",
        "maxTickCountDeltaMs",
        "expectedQpcFrequencyHz",
        "qpcFrequencyDeviation",
        "tickCountAnomalyDetected",
        "qpcAnomalyDetected",
    )

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST for the implementation: the fix explains at length WHY these are
        # not computed, naming each one, so a comment-blind scan reports the defect as
        # present. The HEADER is read RAW on purpose - the marker being asserted there IS
        # a comment.
        cls.cpp = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))
        cls.hpp_raw = read_source(TIME_BASED_EVASION_DETECTOR_HPP_PATH)
        cls.hpp = strip_c_comments(cls.hpp_raw)

    def test_the_measured_qpc_frequency_is_stored_under_its_own_name(self) -> None:
        """The live QueryPerformanceFrequency result belonged in qpcFrequencyHz."""
        measured = len(re.findall(r"analysis\.qpcFrequencyHz\s*=", self.cpp))
        self.assertEqual(
            measured,
            1,
            f"qpcFrequencyHz is assigned {measured} time(s); the measured host frequency "
            "must be stored in the field whose name means the measurement",
        )
        misfiled = len(re.findall(r"analysis\.expectedQpcFrequencyHz\s*=", self.cpp))
        self.assertEqual(
            misfiled,
            0,
            "the measured frequency is filed under expectedQpcFrequencyHz again. There is "
            "no defensible expected value: 10 MHz on invariant-TSC hosts, 3,579,545 Hz on "
            "ACPI PM, 14,318,180 Hz on HPET, and other values under hypervisors - all "
            "legitimate. A deviation measures which timer this machine uses, not whether a "
            "sample is evading anything.",
        )

    def test_no_code_compares_against_a_field_that_has_no_producer(self) -> None:
        """The invariant that stops detection being built on a permanent zero."""
        offenders = []
        for field in self.UNMEASURED:
            # a relational or equality test with the field on either side
            pattern = (
                r"(?<![A-Za-z0-9_])" + field + r"\s*(?:[<>]=?|[!=]=)"
                r"|(?:[<>]=?|[!=]=)\s*[A-Za-z_][A-Za-z0-9_\.\->]*" + field + r"(?![A-Za-z0-9_])"
            )
            if re.search(pattern, self.cpp):
                offenders.append(field)
        self.assertEqual(
            offenders,
            [],
            "these fields have no producer, so a comparison against them can never be "
            f"true and manufactures the appearance of detection: {offenders}. Write the "
            "producer in the SAME change as the comparison, and update this contract then.",
        )

    def test_every_unmeasured_field_says_so_at_its_declaration(self) -> None:
        """A reader must not have to grep the module to learn a zero is not a measurement."""
        # LINE-SCOPED, AND THAT IS LOAD-BEARING. A character window measured back from the
        # declaration BLEEDS INTO THE PREVIOUS FIELD'S MARKER, so a field could lose its own
        # warning and still pass on its neighbour's. Proven by mutation: stripping the
        # marker from callsPerSecond left an earlier character-window form PASSING, because
        # deltaStdDev is declared immediately above it and carries its own marker.
        lines = self.hpp_raw.splitlines()
        missing = []
        for field in self.UNMEASURED:
            decl = None
            for i, line in enumerate(lines):
                if re.search(
                    r"(?<![A-Za-z0-9_])" + field + r"(?![A-Za-z0-9_])\s*=", line
                ):
                    decl = i
                    break
            if decl is None:
                missing.append(field + " (declaration absent)")
                continue
            # only the four lines directly above the declaration count; a three-line
            # marker fits, a neighbour's cannot reach
            window = "\n".join(lines[max(0, decl - 4) : decl])
            if "NOT MEASURED" not in window:
                missing.append(field)
        self.assertEqual(
            missing,
            [],
            f"these declarations do not warn that they are unmeasured: {missing}",
        )

        # ANTI-VACUITY: the fields that ARE produced must not be swept into the list.
        for produced in ("rdtscCount", "rdtscCpuidComboCount", "qpcCalls", "sleepCallCount"):
            self.assertNotIn(
                produced,
                self.UNMEASURED,
                f"{produced} is computed by static analysis and must not be marked "
                "unmeasured - doing so would invite deleting a working detection input",
            )
            present = re.search(
                r"(?<![A-Za-z0-9_])" + produced + r"(?![A-Za-z0-9_])", self.cpp
            )
            self.assertIsNotNone(present, f"{produced} is a live measurement and must stay")

class VmEvasionAnalysisDeadlineContractTests(unittest.TestCase):
    """A declared analysis timeout must bound the work, and a bound must not lose coverage.

    ProcessAnalysisConfig::timeoutMs existed with a 10,000 ms default and was read by
    nothing: measured, VMEvasionDetector.cpp contained zero occurrences of timeoutMs and
    zero of steady_clock across 3,906 lines. The scan it should have bounded is a full
    address-space walk that allocates up to 16 MB per executable region and byte-scans up
    to 64 MB, and it runs on the callback the kernel blocks CreateProcess on and abandons
    after PN_VERDICT_REPLY_TIMEOUT_MS = 500.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST: the fix explains the defect at length and names timeoutMs and
        # steady_clock in prose, so a comment-blind scan cannot tell fix from description.
        cls.vme = strip_c_comments(read_source(VM_EVASION_DETECTOR_CPP_PATH))
        cls.rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))

    def test_the_declared_timeout_is_actually_read(self) -> None:
        reads = len(re.findall(r"(?<![A-Za-z0-9_])config\.timeoutMs(?![A-Za-z0-9_])", self.vme))
        self.assertGreaterEqual(
            reads,
            1,
            "ProcessAnalysisConfig::timeoutMs is unread again, so the scan is unbounded on "
            "the process-creation callback",
        )
        clocks = len(re.findall(r"steady_clock", self.vme))
        self.assertGreaterEqual(
            clocks,
            1,
            "no steady_clock in the module, so no deadline can be enforced even in "
            "principle - this is the state task 199 recorded",
        )

    def test_the_deadline_is_checked_inside_the_scan_and_not_only_around_it(self) -> None:
        """One 16 MB region can overrun a budget on its own.

        Task 36 recorded exactly this: a deadline tested only between stages was overrun by
        a single DisassembleBuffer call, so the fix needed an instruction bound as well. The
        equivalent here is that the byte scan inside a region must be interruptible, not
        just the loop over regions.
        """
        checks = len(re.findall(r"vmPastDeadline\s*\(\s*\)", self.vme))
        self.assertGreaterEqual(
            checks,
            2,
            f"the deadline is tested {checks} time(s). It must be tested both at the region "
            "boundary AND inside the per-region byte scan, or one large region overruns the "
            "whole budget while the code looks bounded.",
        )

        # The stride check must not be expressed as a modulus: the loop advances i by 32 on
        # a hit, so a modulus test can be stepped straight over.
        self.assertNotRegex(
            "\n".join(
                line
                for line in self.vme.splitlines()
                if "vmNextDeadlineCheck" in line or "vmPastDeadline" in line
            ),
            r"%\s*\d+|&\s*0x[0-9A-Fa-f]+",
            "the in-region deadline check uses a modulus or mask; the loop can skip past "
            "it because it advances i by 32 on a detection. Use an explicit next-checkpoint.",
        )

    def test_a_truncated_scan_keeps_its_findings_and_requeues_the_remainder(self) -> None:
        """A bound must defer coverage, never drop it."""
        # The function returns result.completed and the caller short-circuits on it, so
        # completed must NOT be cleared by truncation or every finding is discarded.
        self.assertTrue(
            "result.truncated = vmTruncated;" in self.vme,
            "truncation must be reported on its own field. BOUNDED: assertIn would print "
            "the whole 3,900-line module - measured at 290,833 characters in a mutation run.",
        )
        offenders = [
            line.strip()
            for line in self.vme.splitlines()
            if re.search(r"result\.completed\s*=\s*false", line) and "vmTruncated" in line
        ]
        self.assertEqual(
            offenders,
            [],
            "completed is cleared on truncation. This function ends with "
            "'return result.completed' and RealTimeProtection calls it inside a "
            "short-circuit, so that discards every technique already found - losing "
            "detection to gain latency. Offending line: "
            + (offenders[0] if offenders else ""),
        )

        # And the caller must requeue, before testing whether anything was found.
        self.assertTrue(
            "vmResult.truncated" in self.rtp,
            "RealTimeProtection must react to a truncated VM scan",
        )
        idx = self.rtp.index("vmResult.truncated")
        window = self.rtp[idx : idx + 700]
        self.assertIn(
            "QueueDeferredDeepScan",
            window,
            "a truncated VM scan must requeue the image so the unexamined remainder is "
            "analysed off the kernel's thread",
        )
        self.assertIn(
            "vmEvasionAnalysisTruncated",
            window,
            "truncation must be counted, or a bound that fires constantly is invisible",
        )
        # ORDERING: the requeue must precede the hasAntiVMBehavior test, because a truncated
        # scan that found nothing is exactly the case that needs re-examining.
        self.assertLess(
            self.rtp.index("vmResult.truncated"),
            self.rtp.index("vmResult.hasAntiVMBehavior"),
            "the truncation requeue must run before the finding test, or a truncated scan "
            "with no findings is silently dropped",
        )

    def test_the_budget_passed_in_can_never_mean_unlimited(self) -> None:
        """Zero means NO LIMIT in this config family, so a computed zero inverts the fix."""
        self.assertTrue(
            "vmConfig.timeoutMs = static_cast<uint32_t>(std::max<uint64_t>(1ULL" in self.rtp,
            "the derived timeout is not clamped. It is computed from the remaining slice of "
            "kProcessNotifyBudgetMs, and zero means unlimited in this config family, so an "
            "exhausted budget would REMOVE the bound instead of applying the tightest one.",
        )
        self.assertIn(
            "kProcessNotifyBudgetMs",
            self.rtp[
                self.rtp.index("vmConfig.timeoutMs") - 900 : self.rtp.index("vmConfig.timeoutMs")
            ],
            "the timeout must be derived from the budget already being spent, not from a "
            "second constant that can drift out of step with the outer gate",
        )

        # ANTI-VACUITY: the scan itself must survive. This contract must never be
        # satisfiable by deleting the analysis.
        for kept in ("VirtualQueryEx", "ReadProcessMemory"):
            self.assertTrue(
                kept in self.vme,
                f"{kept} is gone; the target memory scan is what this detector is for",
            )

class DebuggerEvasionDeadlineContractTests(unittest.TestCase):
    """The first evasion stage had no bound at any level, and now has one.

    AnalysisConfig::timeoutMs carried a 30,000 ms default and was read by NOTHING - measured,
    zero reads across 5,583 lines. This analysis runs on RealTimeProtection's process-creation
    path, which the kernel blocks CreateProcess on and abandons after 500 ms, and it is the
    FIRST evasion stage there AND the only one with no evasionBudgetExceeded gate in front of
    it. So neither the module nor the caller bounded it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Comments FIRST: the fix names timeoutMs, analysisComplete and the cache rule in
        # prose, so a comment-blind scan cannot tell the fix from its own description.
        cls.ded = strip_c_comments(read_source(DEBUGGER_EVASION_DETECTOR_CPP_PATH))
        cls.rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))

    def test_the_declared_timeout_bounds_every_stage_after_the_first(self) -> None:
        reads = len(re.findall(r"(?<![A-Za-z0-9_])config\.timeoutMs(?![A-Za-z0-9_])", self.ded))
        self.assertGreaterEqual(
            reads, 1, "AnalysisConfig::timeoutMs is unread again, so the analysis is unbounded"
        )
        checks = len(re.findall(r"dbgOutOfTime\s*\(\s*\)", self.ded))
        self.assertGreaterEqual(
            checks,
            9,
            f"the deadline is tested {checks} time(s). AnalyzeProcessInternal has ten "
            "flag-gated stages and every one after the first must be preceded by a check, or "
            "a late stage can overrun the whole reply window.",
        )

    def test_the_first_stage_is_never_skipped(self) -> None:
        """Task 52's rule: the first detector always runs, so a bound cannot return nothing."""
        # ANCHOR ON THE DEFINITION, NOT THE FIRST OCCURRENCE. AnalyzeProcessInternal is
        # CALLED at ~:1955, thousands of lines above its definition at ~:5042, so
        # index("AnalyzeProcessInternal(") lands on the call and the window covers the wrong
        # region entirely. Proven by mutation: an earlier form of this test did not fire when
        # a guard was placed before stage 1.
        definition = self.ded.index(
            "void DebuggerEvasionDetector::AnalyzeProcessInternal("
        )
        first_stage = self.ded.index("AnalyzePEB(", definition)
        head = self.ded[definition:first_stage]
        self.assertNotIn(
            "dbgOutOfTime()",
            head,
            "a deadline check has been placed before the FIRST stage. That lets the analysis "
            "return having done no work at all when the budget is already spent, which is why "
            "task 52 made the first detector unskippable.",
        )

    def test_a_truncated_result_is_never_cached_and_never_claims_completion(self) -> None:
        self.assertTrue(
            "config.enableCaching && !result.analysisTruncated" in self.ded,
            "a truncated result can be cached again. The cache is pid-keyed with a TTL, so "
            "storing a partial answer makes one exhausted budget permanent for that process.",
        )
        self.assertTrue(
            "result.analysisComplete = !result.analysisTruncated" in self.ded,
            "analysisComplete is asserted rather than derived. An unconditional true is the "
            "defect task 36 found in the metamorphic detector: a run that stopped early "
            "reported itself complete. The in-tree precedents are "
            "metamorphic_polymorphicdetector.cpp and PackerDetector.cpp.",
        )
        offenders = [
            line.strip()
            for line in self.ded.splitlines()
            if re.search(r"result\.analysisComplete\s*=\s*true", line)
        ]
        self.assertEqual(
            offenders,
            [],
            "analysisComplete is set unconditionally somewhere: "
            + (offenders[0] if offenders else ""),
        )

    def test_the_caller_bounds_it_from_the_running_budget_and_requeues(self) -> None:
        self.assertTrue(
            "dedConfig.timeoutMs = static_cast<uint32_t>(std::max<uint64_t>(1ULL" in self.rtp,
            "the derived timeout is not clamped, and zero means UNLIMITED in this config "
            "family, so an exhausted budget would remove the bound instead of tightening it",
        )
        idx = self.rtp.index("dedConfig.timeoutMs")
        self.assertIn(
            "kProcessNotifyBudgetMs",
            self.rtp[max(0, idx - 900) : idx],
            "the timeout must come from the budget already being spent, not a new constant",
        )
        tidx = self.rtp.index("result.analysisTruncated")
        window = self.rtp[tidx : tidx + 800]
        self.assertIn(
            "QueueDeferredDeepScan",
            window,
            "a truncated debugger analysis must requeue the image, or the bound trades "
            "detection for latency instead of deferring it",
        )
        self.assertIn(
            "debuggerEvasionAnalysisTruncated",
            window,
            "truncation must be counted or a bound that fires constantly is invisible",
        )
        # ANTI-VACUITY: the analysis must still be invoked at all.
        self.assertIn(
            "m_debuggerDetector->AnalyzeProcess(",
            self.rtp,
            "the debugger analysis call is gone; this contract must never be satisfiable by "
            "removing the detector",
        )

class EnvironmentEvasionDeadlineContractTests(unittest.TestCase):
    """EnvironmentAnalysisConfig::timeoutMs declared 30,000 ms and was read by NOTHING.

    This analysis runs on RealTimeProtection's process-creation path, which the kernel
    blocks CreateProcess on and abandons after PN_VERDICT_REPLY_TIMEOUT_MS = 500 ms.
    Task 199, same class as tasks 36/49/52/54 and the siblings bounded in eca285e9
    (VMEvasion) and dfe6a57e (DebuggerEvasion).
    """

    @staticmethod
    def _internal_body():
        """The body of AnalyzeProcessInternal.

        Sliced between two DEFINITION markers on purpose. extract_c_function grabs the
        FIRST occurrence of a name, and 'AnalyzeProcessInternal(' appears twice as a CALL
        (in both AnalyzeProcess overloads) thousands of lines above its definition, so a
        first-occurrence anchor would measure the wrong region and the test would not fire.
        """
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        start_marker = "void EnvironmentEvasionDetector::AnalyzeProcessInternal("
        end_marker = "void EnvironmentEvasionDetector::AnalyzeSystemInternal("
        start = src.find(start_marker)
        end = src.find(end_marker, start + 1)
        assert start != -1, "AnalyzeProcessInternal definition not found"
        assert end > start, "AnalyzeSystemInternal definition not found after it"
        return src[start:end]

    def test_the_declared_analysis_timeout_is_actually_read(self):
        """A caller setting timeoutMs must not get silence."""
        body = self._internal_body()
        self.assertTrue(
            "config.timeoutMs" in body,
            "EnvironmentAnalysisConfig::timeoutMs is declared with a 30,000 ms default. "
            "AnalyzeProcessInternal must READ it - a declared control that nothing reads "
            "means a caller setting it gets silence.",
        )
        self.assertTrue(
            "steady_clock" in body,
            "The timeout must be enforced with a monotonic clock. system_clock is "
            "wall-clock and steps with NTP, so it cannot bound a latency budget.",
        )
        # 0 must mean unlimited, matching every sibling config in this subsystem.
        self.assertTrue(
            "config.timeoutMs > 0" in body,
            "A zero timeout must mean NO LIMIT, not an instantly-expired deadline. "
            "Every sibling AntiEvasion config uses that convention.",
        )

    def test_the_first_stage_is_never_gated_by_the_deadline(self):
        """Task 52's rule: an analysis must never return having examined nothing.

        This asserts an ABSENCE, deliberately. Adding a deadline check before stage 1
        would let a spent budget produce an analysis that looked at no evidence at all.
        """
        body = self._internal_body()
        # MEASURE FROM THE LAMBDA, NOT FROM THE TOP OF THE FUNCTION. An earlier block in this
        # same function also tests EnvironmentAnalysisFlags::ScanEnvironmentVars, so anchoring
        # stage 1 on that flag found the EARLIER occurrence - which sits above the lambda and
        # therefore above every possible guard, making this assertion vacuous. A mutation that
        # put a deadline check before stage 1 did not fire until this was corrected.
        lam = body.find("const auto envOutOfTime = [&]()")
        self.assertNotEqual(lam, -1, "the deadline lambda has disappeared")
        stage_one = body.find("CheckEnvironmentVariables(processId", lam)
        first_call = body.find("if (envOutOfTime())", lam)
        self.assertNotEqual(stage_one, -1, "stage 1 (CheckEnvironmentVariables) has disappeared")
        self.assertNotEqual(first_call, -1, "no deadline check remains at any stage boundary")
        self.assertLess(
            stage_one,
            first_call,
            "The FIRST stage must run before any deadline check. A check ahead of it lets "
            "the analysis return having examined nothing, which is exactly what task 52 "
            "forbade when it made the first detector unskippable.",
        )

    def test_every_later_stage_is_bounded(self):
        """Five stages follow the first, and each needs a boundary check."""
        body = self._internal_body()
        guards = body.count("if (envOutOfTime()) { result.analysisTruncated = true; }")
        self.assertGreaterEqual(
            guards,
            5,
            "Expected at least 5 stage-boundary deadline checks (stages 2-6) but found "
            f"{guards}. Each stage opens a process handle, parses a PE or scans strings, "
            "so an unguarded stage can overrun the whole budget on its own.",
        )
        # The findings merge must NOT be gated: a bound defers work, it never discards
        # findings already collected.
        self.assertTrue(
            "for (auto& detection : detections) {" in body,
            "The detections merge loop must survive and must stay ungated - truncation "
            "defers the stages that did not run, it does not discard the ones that did.",
        )

    def test_a_truncated_analysis_is_never_reported_complete(self):
        """analysisComplete must be DERIVED, not asserted.

        Extra weight here: AnalyzeSystemInternal skips every result whose analysisComplete
        is false when it aggregates, so an untruthful value silently changes the
        system-wide picture rather than merely mislabelling one process.
        """
        body = self._internal_body()
        self.assertTrue(
            "result.analysisComplete = !result.analysisTruncated" in body,
            "analysisComplete must be derived from the truncation flag. An unconditional "
            "'= true' is the defect task 36 found in the metamorphic detector: a run that "
            "stopped early still reported itself complete.",
        )
        self.assertFalse(
            "result.analysisComplete = true;" in body,
            "An unconditional 'analysisComplete = true' has returned to "
            "AnalyzeProcessInternal. A truncated analysis must never claim completeness.",
        )

    def test_a_truncated_analysis_is_never_cached(self):
        """The cache is pid-keyed with a TTL, so a partial answer would persist."""
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        total = src.count("UpdateCache(processId, result);")
        gated = src.count("config.enableCaching && !result.analysisTruncated")
        self.assertGreaterEqual(total, 2, "the cache write sites have moved or vanished")
        self.assertGreaterEqual(
            gated,
            total,
            f"{total} UpdateCache site(s) but only {gated} guarded by the truncation flag. "
            "The cache is keyed by pid with a TTL, so storing a truncated result makes one "
            "exhausted budget authoritative for the rest of that window.",
        )

    def test_rtp_derives_a_real_budget_and_requeues_what_it_truncates(self):
        """A hardcoded timeout would not be a budget, and dropped coverage is a loss."""
        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        call = rtp.find("m_environmentDetector->AnalyzeProcess(")
        self.assertNotEqual(call, -1, "the environment detector call site has moved")
        window = rtp[max(0, call - 1600):call]
        self.assertTrue(
            "eedConfig.timeoutMs" in window,
            "RealTimeProtection must set eedConfig.timeoutMs before calling. Leaving the "
            "30,000 ms default on a path the kernel abandons after 500 ms is no bound.",
        )
        self.assertTrue(
            "notifyStart" in window and "kProcessNotifyBudgetMs" in window,
            "The timeout must be DERIVED from the clock already running (notifyStart) and "
            "the shared budget, not hardcoded - six detectors share that budget.",
        )
        tail = rtp[call:call + 1800]
        self.assertTrue(
            "environmentEvasionAnalysisTruncated" in tail,
            "A truncation must be counted, otherwise the product cannot tell whether it is "
            "silently skipping analysis in the field.",
        )
        self.assertTrue(
            "QueueDeferredDeepScan" in tail,
            "A truncated analysis must be REQUEUED. Coverage may move in time; it may not "
            "be lost. A truncated scan that found nothing is exactly the case needing "
            "re-examination.",
        )

class NetworkEvasionDeadlineContractTests(unittest.TestCase):
    """NetworkAnalysisConfig declared THREE timeouts and read none of them.

    Only ONE of the three describes work this module performs. Task 199's fourth and
    final module, after eca285e9 (VMEvasion), dfe6a57e (DebuggerEvasion) and 9e27eeaf
    (EnvironmentEvasion).
    """

    @staticmethod
    def _internal_body():
        """The body of AnalyzeProcessInternal, sliced between two DEFINITION markers.

        AnalyzeProcessInternal is CALLED (in AnalyzeProcess) roughly a thousand lines
        above where it is DEFINED, so a first-occurrence anchor measures the wrong
        region. Both markers are namespace-qualified for that reason.
        """
        src = strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))
        start = src.find("void NetworkBasedEvasionDetector::AnalyzeProcessInternal(")
        end = src.find("void NetworkBasedEvasionDetector::DetectNetworkEvasionImports(", start + 1)
        assert start != -1, "AnalyzeProcessInternal definition not found"
        assert end > start, "the following definition was not found after it"
        return src[start:end]

    def test_the_declared_analysis_timeout_is_actually_read(self):
        body = self._internal_body()
        self.assertTrue(
            "config.timeoutMs" in body,
            "NetworkAnalysisConfig::timeoutMs declares a 5,000 ms analysis timeout. "
            "AnalyzeProcessInternal must READ it - a declared control nothing reads means "
            "a caller setting it gets silence.",
        )
        self.assertTrue(
            "steady_clock" in body,
            "The deadline must use a monotonic clock; system_clock steps with NTP.",
        )
        self.assertTrue(
            "config.timeoutMs > 0" in body,
            "Zero must mean NO LIMIT, matching every sibling config in this subsystem.",
        )

    def test_the_first_stage_is_never_gated_by_the_deadline(self):
        """Task 52: an analysis must never return having examined nothing."""
        body = self._internal_body()
        lam = body.find("const auto netOutOfTime = [&]()")
        self.assertNotEqual(lam, -1, "the deadline lambda has disappeared")
        stage_one = body.find("DetectNetworkEvasionImports(processId", lam)
        first_call = body.find("if (netOutOfTime())", lam)
        self.assertNotEqual(stage_one, -1, "stage 1 has disappeared")
        self.assertNotEqual(first_call, -1, "no deadline check remains at any stage boundary")
        self.assertLess(
            stage_one,
            first_call,
            "The FIRST stage must run before any deadline check. A check ahead of it lets "
            "the analysis return having examined nothing, which task 52 forbade.",
        )

    def test_every_later_stage_is_bounded(self):
        body = self._internal_body()
        guards = body.count("if (netOutOfTime()) { result.analysisTruncated = true; }")
        self.assertGreaterEqual(
            guards,
            4,
            f"Expected at least 4 stage-boundary deadline checks but found {guards}. "
            "DNS, traffic-pattern, beaconing and kernel-correlation stages each follow the "
            "first and each needs a boundary check.",
        )

    def test_a_truncated_analysis_is_never_reported_complete(self):
        src = strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))
        self.assertTrue(
            "result.analysisComplete = !result.analysisTruncated" in src,
            "analysisComplete must be DERIVED from the truncation flag. An unconditional "
            "'= true' is the defect task 36 found in the metamorphic detector.",
        )
        self.assertFalse(
            "result.analysisComplete = true;" in src,
            "An unconditional 'analysisComplete = true' has returned. A truncated analysis "
            "must never claim completeness.",
        )

    def test_a_truncated_analysis_is_never_cached(self):
        src = strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))
        writes = src.count("UpdateCache(processId, result);")
        self.assertGreaterEqual(writes, 1, "the cache write site has moved or vanished")
        gated = src.count("!result.analysisTruncated")
        self.assertGreaterEqual(
            gated,
            5,
            "Expected the truncation flag to gate the cache write as well as the later "
            f"stages, but found only {gated} uses. The cache is pid-keyed with a TTL, so a "
            "truncated result would be authoritative for the rest of that window.",
        )
        # PIN THE GATE TEXT ITSELF, not a character window. A window measured back from
        # UpdateCache also sees the neighbouring completion statement, which mentions the
        # same flag, so an ungated cache would still have satisfied it. The '&&' form exists
        # only in the guarded spelling - the cache-READ site a few lines above uses the bare
        # 'EnableCaching)) {' form, so this cannot be satisfied by the wrong site.
        self.assertTrue(
            "NetworkAnalysisFlags::EnableCaching) &&" in src,
            "The UpdateCache call is no longer guarded by the truncation flag. The cache is "
            "pid-keyed with a TTL, so a truncated result would be served as authoritative "
            "for the rest of that window.",
        )

    def test_the_two_io_timeouts_are_not_wired_to_anything(self):
        """dnsTimeoutMs and httpTimeoutMs bound NO operation that exists.

        Measured: DnsQuery_A/W/Ex, InternetOpenA/W and HttpOpenRequestA/W appear in this
        module ONLY as string literals compared against the TARGET process's import
        table - static inspection of what the sample can do, not something this module
        does. The single real Winsock call is a WSAStartup in Impl::Initialize.

        Wiring these would create a timeout attached to nothing: a control that looks
        like a safety bound while providing none. That is the same trap as a threshold
        compared against a field with no producer, and this test exists to stop a future
        reader "finishing the job".
        """
        src = strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))
        for field in ("config.dnsTimeoutMs", "config.httpTimeoutMs"):
            self.assertFalse(
                field in src,
                f"{field} is now read. Before wiring it, a real DNS or HTTP call must "
                "exist for it to bound - otherwise this is a decorative safety control. "
                "If such a call was genuinely added, update this contract deliberately.",
            )
        hpp = read_source(NETWORK_BASED_EVASION_DETECTOR_HPP_PATH)
        self.assertTrue(
            "THIS BOUNDS NOTHING" in hpp,
            "The declarations must say plainly that they bound nothing, so the next reader "
            "does not mistake them for unfinished wiring.",
        )

    def test_rtp_derives_a_real_budget_and_requeues_what_it_truncates(self):
        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        call = rtp.find("m_networkDetector->AnalyzeProcess(")
        self.assertNotEqual(call, -1, "the network detector call site has moved")
        window = rtp[max(0, call - 1600):call]
        self.assertTrue(
            "nbedConfig.timeoutMs" in window,
            "RealTimeProtection must set nbedConfig.timeoutMs before calling.",
        )
        self.assertTrue(
            "notifyStart" in window and "kProcessNotifyBudgetMs" in window,
            "The timeout must be DERIVED from the running clock and the shared budget.",
        )
        tail = rtp[call:call + 1800]
        self.assertTrue(
            "networkEvasionAnalysisTruncated" in tail,
            "A truncation must be counted or the product cannot tell it is skipping work.",
        )
        self.assertTrue(
            "QueueDeferredDeepScan" in tail,
            "A truncated analysis must be REQUEUED. Coverage may move in time, not be lost.",
        )

class SleepEvasionObservationContractTests(unittest.TestCase):
    """The sleep half of TimeBasedEvasionDetector has no runtime producer.

    Three MITRE techniques - SleepBombing, SleepAccelerationDetect and
    SleepFragmentation (T1497.003) - are fully implemented and consume fields that
    are only written from ProcessMonitoringContext, which is filled exclusively by
    RecordTimingEvent. That function has no caller anywhere in src or tests, so
    HasSleepEvasion() returns false for every process and false means NOT OBSERVED
    rather than CLEAN.

    These tests do not require the gap to be closed. They require it to stay
    VISIBLE, and they require nobody to close it by making a static import list
    masquerade as observed behaviour.
    """

    @staticmethod
    def _sleep_struct():
        """The SleepAnalysis struct body, comments PRESERVED.

        Comments are deliberately kept: the whole contract here is about the
        warnings attached to the declarations, so a comment-stripped read would
        assert nothing.
        """
        src = read_source(TIME_BASED_EVASION_DETECTOR_HPP_PATH)
        start = src.find("struct SleepAnalysis {")
        self_end = src.find("struct RDTSCAnalysis", start + 1)
        assert start != -1, "SleepAnalysis struct not found"
        assert self_end > start, "the struct following SleepAnalysis was not found"
        return src[start:self_end]

    def test_every_unobserved_sleep_field_says_so_at_its_declaration(self):
        """A caller reading a zero must be able to tell measured-zero from no-producer."""
        body = self._sleep_struct()
        lines = body.split("\n")
        # fields whose only writer is a default initialiser, measured field by field
        # NARROWED when AnalyzeObservedDelays landed. Six of the original ten now
        # have a real producer driven from the emulator's intercepted delay calls,
        # so their NOT OBSERVED warnings would have become FALSE DOCUMENTATION -
        # which is the defect this whole strand exists to remove. What remains is
        # the set that still genuinely has no producer anywhere.
        #
        # totalActualDurationMs / avgActualDurationMs / accelerationRatio all
        # describe the ACTUAL elapsed delay, which requires observing both entry and
        # exit of the call. The emulator reports the REQUESTED duration only, so
        # these stay unproduced until an observer measures both edges.
        unobserved = [
            "threadId",
            "totalActualDurationMs",
            "avgActualDurationMs",
            "accelerationRatio",
        ]
        missing = []
        for field in unobserved:
            idx = None
            for i, line in enumerate(lines):
                # the DECLARATION line: a type, the name, and an initialiser or ;
                if re.search(r"(?<![A-Za-z0-9_])" + re.escape(field) + r"\s*(=|;)", line):
                    idx = i
                    break
            if idx is None:
                missing.append(field + " (declaration not found)")
                continue
            # SCOPE TO THE CONTIGUOUS DOC-COMMENT BLOCK, not to a fixed span.
            #
            # A fixed window is wrong in BOTH directions and both failures have now
            # happened here. Measured back N characters it reads the PREVIOUS field's
            # warning and passes on it. Measured back N lines it TRUNCATES a long
            # warning and reports a marked field as unmarked - which is exactly how
            # this test first failed, on fragmentationDetected, whose warning runs
            # eleven lines.
            #
            # The comment block is terminated by any non-comment line, and between
            # two field declarations that line is always the previous declaration
            # itself, so walking backwards is exact: it can neither truncate nor
            # bleed.
            block = []
            k = idx - 1
            while k >= 0:
                stripped = lines[k].strip()
                if stripped.startswith("///") or stripped.startswith("*") or stripped == "":
                    block.append(lines[k])
                    k -= 1
                    continue
                break
            window = "\n".join(block)
            if "NOT OBSERVED" not in window:
                missing.append(field)
        self.assertEqual(
            missing,
            [],
            "These SleepAnalysis fields have no producer but their declarations do "
            "not say so, so a reader cannot distinguish a measured zero from an "
            "absent measurement: " + ", ".join(missing),
        )

    def test_the_runtime_dependency_is_structural_not_accidental(self):
        """The bombing predicates must be gated on observation actually happening."""
        src = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))
        flag = "analysis.runtimeObservationAvailable = true;"
        self.assertTrue(
            flag in src,
            "AnalyzeSleep must record that a monitoring context was found. Without "
            "it, 'no sleep evasion' and 'nothing was observed' are the same value.",
        )
        gate = "if (analysis.runtimeObservationAvailable) {"
        self.assertTrue(
            gate in src,
            "The sleep-bombing predicates must be gated on observation. Ungated they "
            "read as though static import evidence alone could raise sleep bombing.",
        )
        # ORDERING: the flag must be set BEFORE the gate tests it.
        self.assertLess(
            src.index(flag),
            src.index(gate),
            "The observation flag is set after the gate that reads it.",
        )

    def test_sleep_evasion_is_never_raised_from_static_imports_alone(self):
        """The one wrong fix this gap invites, refused explicitly.

        Making HasSleepEvasion() true on import evidence would fire on ordinary
        software that imports several wait APIs. The analyzer's own comment says so.
        """
        hpp = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_HPP_PATH))
        self.assertTrue(
            "return sleepBombingDetected || accelerationDetected || fragmentationDetected;" in hpp,
            "HasSleepEvasion()'s disjunction has changed. It must remain the OR of "
            "the three runtime-sourced flags; widening it to static import evidence "
            "converts a false negative into a false positive on normal software.",
        )
        cpp = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))
        # both predicates must still require a runtime term, not imports alone
        self.assertTrue(
            "analysis.sleepCallCount > 50" in cpp,
            "the sleep-bombing predicate lost its runtime call-count term",
        )
        self.assertTrue(
            "analysis.totalRequestedDurationMs > 30000" in cpp,
            "the sleep-bombing predicate lost its runtime duration term",
        )

    def test_the_timing_feed_still_has_no_producer(self):
        """A PIN ON THE GAP ITSELF, so it cannot go stale silently.

        This test FAILS THE DAY SOMEONE WIRES A TIMING FEED. That is the intent: at
        that moment every NOT OBSERVED warning in SleepAnalysis becomes false, the
        three sleep techniques become reachable, and this contract must be revisited
        deliberately rather than left describing a world that no longer exists.

        If you are reading this because the test failed: good. Remove the warnings
        that are no longer true, re-point this test at whatever now bounds the feed,
        and keep the ones that remain accurate.
        """
        roots = [ROOT / "src", ROOT / "tests"]
        callers = []
        for base in roots:
            if not base.exists():
                continue
            for path in base.rglob("*.cpp"):
                text = path.read_text(encoding="utf-8", errors="replace")
                for num, line in enumerate(text.split("\n"), start=1):
                    if "RecordTimingEvent" not in line:
                        continue
                    stripped = line.strip()
                    # a DEFINITION or a DELEGATION inside the module itself is not a feed
                    if path.name == "TimeBasedEvasionDetector.cpp":
                        continue
                    if stripped.startswith("//") or stripped.startswith("*"):
                        continue
                    callers.append(f"{path.name}:{num}: {stripped}")
        self.assertEqual(
            callers,
            [],
            "RecordTimingEvent now has a caller, so the sleep analysis may finally "
            "observe real behaviour. Revisit the NOT OBSERVED warnings in "
            "SleepAnalysis and this contract: " + "; ".join(callers),
        )

class HostContextCalibrationWiringContractTests(unittest.TestCase):
    """The host-context calibration must exist ONCE and run on BOTH analysis paths.

    It previously existed only inside AnalyzeSystemInternal, and the sole entry that
    reaches that function - AnalyzeSystemEnvironment - has zero callers anywhere in
    src or tests. So a correct, complete policy had never once executed, while the
    live per-creation path that RealTimeProtection drives on every process creation
    reported VM-artefact probes at full confidence on VM hosts. That is the opposite
    of the policy's stated purpose, which is false-positive reduction.

    The policy LOGIC is covered behaviourally by HostContextCalibrationTest. What
    cannot be unit-tested is the WIRING: reaching AnalyzeProcessInternal needs a live
    target process. So the call sites are pinned here as source contracts, which is
    the same split used for the kernel reply paths.
    """

    @staticmethod
    def _function_body(start_marker: str, end_marker: str) -> str:
        """Slice between two DEFINITION markers, comments stripped.

        Both markers are namespace-qualified because these functions are CALLED
        earlier in the file than they are DEFINED, so a first-occurrence anchor
        measures the wrong region - a mistake that has produced three vacuous guards
        in this suite already.
        """
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        start = src.find(start_marker)
        assert start != -1, f"definition not found: {start_marker}"
        end = src.find(end_marker, start + 1)
        assert end > start, f"following definition not found: {end_marker}"
        return src[start:end]

    def test_the_calibration_has_exactly_one_implementation(self):
        """Two copies of a policy is how they drift."""
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))

        arithmetic = src.count("detection.confidence *= 0.6")
        self.assertEqual(
            arithmetic,
            1,
            f"the calibration arithmetic appears {arithmetic} time(s); it must exist "
            "exactly once. Task 56 found two YARA metadata builders disagreeing about "
            "severity and task 66 found two producers of one on-disk format where the "
            "broken one was the one that ran - both were duplication with drift.",
        )

        definitions = src.count(
            "void EnvironmentEvasionDetector::CalibrateForHostContext("
        )
        self.assertEqual(definitions, 1, "the calibration must be defined exactly once")

    def test_both_analysis_paths_apply_the_calibration(self):
        """Per-process and system-aggregate must not diverge in what they calibrate."""
        per_process = self._function_body(
            "void EnvironmentEvasionDetector::AnalyzeProcessInternal(",
            "void EnvironmentEvasionDetector::AnalyzeSystemInternal(",
        )
        # BOUNDED, never assertIn against a function body. The unbounded form dumped
        # 4,993 characters on failure, which is the same rule this suite has broken
        # repeatedly: a containment assertion must never print its haystack.
        self.assertTrue(
            "CalibrateForHostContext(" in per_process,
            "the PER-PROCESS path must calibrate. This is the path "
            "RealTimeProtection drives on every process creation, and it is the one "
            "that had no calibration at all while the dark system path had it.",
        )
        self.assertTrue(
            "HostIsVirtualized()" in per_process,
            "the per-process path must read the host fact; calibrating on a "
            "hardcoded value would defeat the point",
        )

        system_path = self._function_body(
            "void EnvironmentEvasionDetector::AnalyzeSystemInternal(",
            "void EnvironmentEvasionDetector::AddDetection(",
        )
        self.assertTrue(
            "CalibrateForHostContext(" in system_path,
            "the system-aggregate path must call the shared implementation rather "
            "than carry its own inline copy",
        )

    def test_the_calibration_input_is_an_exact_host_fact(self):
        """Never a composite sandbox-likeness score."""
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        start = src.find("bool EnvironmentEvasionDetector::HostIsVirtualized()")
        self.assertNotEqual(start, -1, "HostIsVirtualized has been removed")
        body = src[start:start + 700]

        self.assertTrue(
            "hypervisorDetected" in body,
            "the host fact must come from the CPUID hypervisor-present bit, which is "
            "EXACT. 6a1ee4a3 removed a sandbox-likeness score for precisely this "
            "reason: it derived from screen resolution, uptime, RAM and "
            "recent-document counts, all of which read as sandbox-like on ordinary "
            "VDI, cloud and headless endpoints, so calibrating on it would LOWER "
            "confidence exactly where enterprises deploy most.",
        )
        for forbidden in ("isSandboxLike", "sandboxLikeness", "mouseEntropy"):
            self.assertFalse(
                forbidden in body,
                f"{forbidden} is an INFERRED host property and must never calibrate a "
                "detection; only exact facts may.",
            )

    def test_calibration_cannot_suppress_a_finding(self):
        """A reduction must not be able to drop a detection.

        Measured when the calibration was made live: AddDetection does not gate on
        confidence, and minReportableConfidence / minConfidence / confidenceThreshold
        have zero references in the module. This test fails if a confidence gate is
        introduced, because at that moment a reduction COULD suppress a finding and
        the policy would need re-examining rather than silently becoming a filter.
        """
        src = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))

        # A DECLARATION IS HARMLESS; A READ IS THE HAZARD. This distinction was found
        # by this very test: EnvironmentAnalysisConfig DOES declare
        # minConfidenceThreshold = 0.3, which an earlier word-boundary measurement of
        # "minConfidence" and "confidenceThreshold" could not match. The field is
        # declared and never read, so no gate exists and the calibration cannot
        # suppress anything - but three sibling AntiEvasion modules declare the same
        # field and PackerDetector genuinely READS its copy at two sites, so wiring
        # this one is a live possibility rather than a hypothetical.
        for gate in (
            "minReportableConfidence",
            "minConfidenceThreshold",
            "confidenceThreshold",
        ):
            reads = src.count(gate)
            self.assertEqual(
                reads,
                0,
                f"{gate} is now READ in the implementation. Host-context calibration "
                "REDUCES confidence, so a confidence gate makes it capable of "
                "SUPPRESSING a detection rather than merely re-weighting one. That "
                "changes the policy from a re-weighting into a filter, which is a "
                "detection decision. Re-examine the policy and this contract together "
                "before wiring it.",
            )

        # And the only confidence COMPARISON in the module must be the calibration's
        # own floor, which exists so a weak finding is not pushed toward zero.
        comparisons = len(
            re.findall(r"(?<![A-Za-z0-9_])confidence\s*(?:<|>|<=|>=)", src)
        )
        self.assertEqual(
            comparisons,
            1,
            f"{comparisons} confidence comparison(s) in the module; expected exactly "
            "one, the calibration floor. Any other comparison is a potential "
            "suppression point.",
        )

class HostProbeContextOnlyContractTests(unittest.TestCase):
    """EnvironmentEvasionDetector's host-subject probes stay context, never verdicts.

    Every one of these routines inspects THIS machine rather than a caller-supplied
    sample, so under the subject rule the module already follows, none of them may
    produce a verdict. Commit ad535230 removed four siblings outright for asking
    "what does malware ask about the box it landed on"; it KEPT these on the stated
    grounds that knowing the host is a VM in order NOT to flag it is defensive. That
    retention is only true while the findings are marked as context and capped, which
    is exactly what CheckTimingIndicators was missing - it was the single unmarked
    routine of the eight and emitted confidences up to 0.90.
    """

    # Every host-subject probe in the module. The population is asserted below so a
    # newly added host probe cannot skip the marking by simply not being listed here.
    HOST_SUBJECT_PROBES = (
        "CheckBlacklistedNames",
        "CheckHardwareFingerprint",
        "CheckFileSystemArtifacts",
        "CheckRegistryArtifacts",
        "CheckNetworkConfiguration",
        "CheckRunningProcesses",
        "CheckTimingIndicators",
        "CheckAdvancedCPUIDIndicators",
    )

    CONTEXT_MARKER = "NOT a detection source."

    # The context ceiling. CheckRunningProcesses sets the precedent for this module:
    # 0.20 for "VMs are ubiquitous in enterprise", 0.10 for "these are legitimate
    # tools". A host fact that is true of ordinary infrastructure must not be scored
    # above it.
    CONTEXT_CONFIDENCE_CEILING = 0.20

    def test_every_host_subject_probe_is_marked_as_context(self):
        # The markers ARE doc comments, so this one check must read the RAW source.
        hpp = read_source(ENVIRONMENT_EVASION_DETECTOR_HPP_PATH)
        unmarked = []
        for name in self.HOST_SUBJECT_PROBES:
            m = re.search(r"bool\s+" + name + r"\s*\(", hpp)
            self.assertIsNotNone(
                m, name + " is no longer declared in EnvironmentEvasionDetector.hpp. "
                "If it was deliberately removed, drop it from HOST_SUBJECT_PROBES in "
                "the SAME change and say why in the commit message."
            )
            # Locate the doc block that IMMEDIATELY precedes the declaration, anchored
            # on its closing delimiter. A fixed character or line window bleeds into the
            # previous declaration's comment or truncates a long one, and testing "the
            # last semicolon precedes the last /**" is unsound because a doc comment may
            # itself contain a semicolon - that heuristic reported this very function as
            # having no doc block at all. Requiring only whitespace and an optional
            # attribute between */ and the declaration can do neither.
            head = hpp[:m.start()]
            close = head.rfind("*/")
            between = head[close + 2:].strip() if close >= 0 else "x"
            if close < 0 or between not in ("", "[[nodiscard]]"):
                unmarked.append(name + " (no doc-comment block on the declaration)")
                continue
            block_start = head.rfind("/**", 0, close)
            if block_start < 0:
                unmarked.append(name + " (unterminated doc-comment block)")
                continue
            if self.CONTEXT_MARKER not in head[block_start:close]:
                unmarked.append(name)
        self.assertEqual(
            [], unmarked,
            "These host-subject probes do not carry '" + self.CONTEXT_MARKER + "' on "
            "their declaration: " + ", ".join(unmarked) + ". A routine that inspects "
            "THIS machine may contribute context, never a verdict - see ad535230."
        )

    def test_the_host_timing_probe_caps_every_finding_it_collects(self):
        cpp = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        body = extract_c_function(cpp, "EnvironmentEvasionDetector::CheckTimingIndicators")
        self.assertIsNotNone(body, "CheckTimingIndicators definition not found.")

        pushes = len(re.findall(r"outDetections\.push_back", body))
        # The cap MOVED from a per-site assignment into MakeContextIndicator, which
        # forces Low for every indicator it builds. Counting factory calls expresses
        # the same invariant against the mechanism that now enforces it, and a
        # stronger one: a per-site assignment can be forgotten on the next indicator
        # someone adds - which is precisely how seven of the eight host probes came to
        # ship Critical and High - whereas a construction cannot be.
        caps = len(re.findall(r"MakeContextIndicator\s*\(", body))
        # Anti-vacuity: if the routine stops collecting anything this test must fail
        # rather than pass by having nothing left to check.
        self.assertGreaterEqual(
            pushes, 6,
            "CheckTimingIndicators now collects only " + str(pushes) + " indicators. "
            "This guard exists to bound them; if the routine was deliberately reduced, "
            "re-derive the floor in the same change."
        )
        self.assertEqual(
            pushes, caps,
            "CheckTimingIndicators collects " + str(pushes) + " indicators but builds "
            "only " + str(caps) + " through MakeContextIndicator. Every finding about "
            "THIS machine must be capped at Low, and the factory is what caps it - an "
            "uncapped host finding is a verdict about the host. Do NOT satisfy this by "
            "assigning severity at the call site again; that is the pattern that let "
            "seven of the eight probes inherit Critical and High."
        )

    def test_the_host_timing_probe_scores_nothing_above_the_context_ceiling(self):
        cpp = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        body = extract_c_function(cpp, "EnvironmentEvasionDetector::CheckTimingIndicators")
        self.assertIsNotNone(body, "CheckTimingIndicators definition not found.")

        offenders = []
        for m in re.finditer(r"confidence\s*=\s*([0-9]*\.?[0-9]+)", body):
            value = float(m.group(1))
            if value > self.CONTEXT_CONFIDENCE_CEILING + 1e-9:
                offenders.append(m.group(0).strip())
        # Every signal here is true of ordinary corporate infrastructure: short uptime
        # after any reboot, a recent install on any re-imaged endpoint, tick drift on
        # any loaded host, few scheduled tasks on a lean image, System Restore off by
        # default on Server, and a boot mismatch on any resumed snapshot.
        self.assertEqual(
            [], offenders,
            "CheckTimingIndicators scores host facts above the "
            + str(self.CONTEXT_CONFIDENCE_CEILING) + " context ceiling: "
            + ", ".join(offenders) + ". Each of its signals is true of ordinary "
            "infrastructure, so a higher score would fire on the endpoints this "
            "product ships to."
        )

    def test_the_host_timing_probe_is_not_wired_to_a_verdict_path(self):
        cpp = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        # Comment-stripped, so the aggregator comment at AnalyzeProcessInternal that
        # NAMES this routine cannot satisfy or break the count.
        refs = len(re.findall(
            r"(?<![A-Za-z0-9_])CheckTimingIndicators(?![A-Za-z0-9_])", cpp))
        # Exactly two: the definition, and its own error-log string. A third is a call.
        self.assertEqual(
            2, refs,
            "CheckTimingIndicators has " + str(refs) + " comment-stripped references "
            "in EnvironmentEvasionDetector.cpp, expected 2 (its definition and its own "
            "error-log string). A caller has been added. This routine inspects THIS "
            "machine and every signal it collects is true of ordinary infrastructure, "
            "so it must not feed a verdict path. It cannot feed CalibrateForHostContext "
            "either: that policy takes an EXACT host fact and these are all inferred, "
            "which is precisely the composite sandbox-likeness input 6a1ee4a3 removed. "
            "If a genuine context consumer has been written, cite it here and update "
            "this contract in the SAME change."
        )

    def test_the_four_removed_self_checks_have_not_returned(self):
        # ad535230 removed these outright. Re-adding one would re-introduce host
        # fingerprinting with no defensive reading.
        hpp = read_source(ENVIRONMENT_EVASION_DETECTOR_HPP_PATH)
        cpp = read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH)
        returned = []
        for name in ("CheckUserActivity", "CheckBrowserArtifacts",
                     "CheckDisplayConfiguration", "CheckPeripheralHistory"):
            if name in hpp or name in cpp:
                returned.append(name)
        self.assertEqual(
            [], returned,
            "These host-fingerprinting self-checks were deliberately removed by "
            "ad535230 and have returned: " + ", ".join(returned) + "."
        )

    # ------------------------------------------------------------------ the factory
    #
    # THE CAP USED TO BE REMEMBERED AND IS NOW STRUCTURAL. Seven of these eight probes
    # shipped above the cap their own declarations state, and five of the seven never
    # named a severity at all - they inherited one, because
    # EnvironmentDetectedTechnique's converting constructor sets
    # severity(GetDefaultTechniqueSeverity(tech)) and that function is written for
    # VERDICT-BEARING detections: it maps 22 techniques as Critical, High or Medium and
    # reaches Low only through its default case. Severity is then multiplied into the
    # score by CalculateEvasionScore at Low 1.0, Medium 2.5, High 5.0, Critical 10.0, so
    # an inherited Critical gave an observation about OUR OWN MACHINE ten times the
    # weight of an ordinary indicator.
    #
    # Assigning Low at each of the 53 sites would have fixed the eight that exist and
    # been forgotten by whoever adds the 54th. So every indicator is built by a factory
    # that forces the value, and these tests pin that rather than the individual sites.
    CONTEXT_FACTORY = "MakeContextIndicator"

    def test_every_host_probe_builds_its_indicators_through_the_context_factory(self):
        source = read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH)
        code = strip_c_comments(source)
        direct = re.compile(r"EnvironmentDetectedTechnique\s+(\w+)\s*\(\s*"
                            r"EnvironmentEvasionTechnique::\w+\s*\)\s*;")
        assigns = re.compile(r"\w+\.severity\s*=\s*EnvironmentEvasionSeverity::(\w+)")

        offenders = []
        factory_calls_in_probes = 0
        for name in self.HOST_SUBJECT_PROBES:
            body = extract_c_function(code, name)
            self.assertTrue(
                body,
                "host-subject probe %s no longer has a body this guard can read. If it "
                "was removed on purpose, drop it from HOST_SUBJECT_PROBES in the same "
                "change so the population stays honest." % name)
            n_direct = len(direct.findall(body))
            n_assign = assigns.findall(body)
            n_factory = body.count(self.CONTEXT_FACTORY + "(")
            factory_calls_in_probes += n_factory
            if n_direct:
                offenders.append("%s constructs %d indicator(s) directly, which inherits "
                                 "a verdict-grade severity" % (name, n_direct))
            if n_assign:
                offenders.append("%s assigns severity itself (%s); the factory owns that "
                                 "value" % (name, ",".join(sorted(set(n_assign)))))
            if not n_factory:
                offenders.append("%s builds no indicator through %s, so either it stopped "
                                 "collecting context or it found another way to construct "
                                 "one" % (name, self.CONTEXT_FACTORY))
        self.assertEqual(
            [], offenders,
            "a host-context probe can produce a verdict-grade severity again. Severity is "
            "a score multiplier (Low 1.0, Medium 2.5, High 5.0, Critical 10.0) and the "
            "subject of these probes is THIS MACHINE, so Low is the only value a host "
            "observation may carry: " + "; ".join(offenders))

        # The factory must not leak onto a verdict path either: a real detection needs a
        # real severity, so every call site belongs to one of the eight probes.
        total = len(re.findall(re.escape(self.CONTEXT_FACTORY) + r"\s*\(\s*"
                               r"EnvironmentEvasionTechnique::", code))
        self.assertEqual(
            factory_calls_in_probes, total,
            "%s is called %d time(s) but only %d of those are inside the eight "
            "host-context probes. The factory forces Low, so using it on a "
            "verdict-bearing detection would silently cap a real finding - the opposite "
            "defect." % (self.CONTEXT_FACTORY, total, factory_calls_in_probes))

    def test_the_context_factory_forces_the_severity_rather_than_inheriting_it(self):
        code = strip_c_comments(read_source(ENVIRONMENT_EVASION_DETECTOR_CPP_PATH))
        body = extract_c_function(code, "EnvironmentEvasionDetector::" + self.CONTEXT_FACTORY)
        if not body:
            body = extract_c_function(code, self.CONTEXT_FACTORY)
        self.assertTrue(
            body,
            "%s has no definition in EnvironmentEvasionDetector.cpp, so nothing "
            "forces the host-context cap" % self.CONTEXT_FACTORY)
        forced = re.search(r"\w+\.severity\s*=\s*EnvironmentEvasionSeverity::Low\s*;", body)
        self.assertTrue(
            forced,
            "%s no longer forces severity to Low. Without that line it merely forwards "
            "the converting constructor, which inherits Critical, High or Medium for the "
            "22 techniques GetDefaultTechniqueSeverity maps - and the probes no longer "
            "assign severity themselves, so nothing else would catch it."
            % self.CONTEXT_FACTORY)
        raised = re.findall(r"severity\s*=\s*EnvironmentEvasionSeverity::"
                            r"(Medium|High|Critical)", body)
        self.assertEqual(
            [], raised,
            "%s assigns a verdict-grade severity (%s)" % (self.CONTEXT_FACTORY,
                                                          ",".join(raised)))

    def test_the_inheritance_hazard_the_factory_exists_for_is_still_real(self):
        """Anti-vacuity. If GetDefaultTechniqueSeverity ever returned Low for
        everything, the factory would look decorative and a future reader could delete
        it - while every verdict-bearing detection silently lost its severity. So prove
        the hazard the factory guards against still exists."""
        header = read_source(ENVIRONMENT_EVASION_DETECTOR_HPP_PATH)
        code = strip_c_comments(header)
        body = extract_c_function(code, "GetDefaultTechniqueSeverity")
        self.assertTrue(
            body, "GetDefaultTechniqueSeverity has no readable body in the header")
        graded = re.findall(r"return\s+EnvironmentEvasionSeverity::"
                            r"(Medium|High|Critical)\s*;", body)
        self.assertTrue(
            len(graded) >= 3,
            "GetDefaultTechniqueSeverity now returns almost nothing above Low (%d "
            "verdict-grade returns). Either the verdict severities were flattened - "
            "which would weaken every real detection in this module - or this guard is "
            "reading the wrong function. %s is only load-bearing while a direct "
            "construction would inherit a graded severity."
            % (len(graded), self.CONTEXT_FACTORY))



class AssemblyExportCensusContractTests(unittest.TestCase):
    """Pins WHICH assembly routines are reached, and forbids wiring the ones that lie.

    Task 209 was filed as "of 105 exported routines only about 8 have a real caller".
    Measured on 2026-08-23 the live count is 43, and the filed claim that "3 of the 6
    files are referenced by nothing at all" is false - all six are named by four
    project files each.

    IT TOOK THREE ATTEMPTS TO COUNT THIS CORRECTLY, and both wrong answers came from
    testing PUNCTUATION instead of the return type:
      45 - a per-LINE declaration test.  A multi-line prototype
           (`int64_t SIMDScanForPattern(const uint8_t* buffer, size_t bufferSize,`)
           has no semicolon on its own line, so five prototypes read as calls.
      40 - joined statements, but a declaration was defined as "ends in ';' with no
           '='".  A void function called as a bare statement
           (`CheckVMwareBackdoor(rax, rbx, rcx, rdx);`) satisfies that exactly, so
           three real call sites read as prototypes.
      43 - the discriminator that actually works: a declaration carries a RETURN TYPE
           immediately before the name; a call carries nothing, an assignment, a
           control keyword or an enclosing call.
    Anyone re-deriving this census must use _call_sites below rather than a grep.

    What the census actually shows is not 65 missing capabilities.  It shows
    DUPLICATION: EnvironmentEvasionDetector_x64.asm is the layer's shared CPU
    primitive library - VMEvasionDetector.cpp alone calls ten of its exports - so the
    dark routines are overwhelmingly second and third copies of ~10 primitives that
    already have exactly one live implementation.  Two whole modules
    (DebuggerEvasionDetector 18/18, SandboxEvasionDetector 17/17) are entirely dark
    for that reason, and that is 35 of the 65.

    THE POINT OF THIS CLASS IS THE SECOND TEST.  48 of the dark routines convert a
    measurement of THIS MACHINE into a boolean "detected" or a score.  On any VMware,
    Hyper-V or cloud endpoint they read positive, so wiring one to a verdict convicts
    the endpoint we are defending.  TimingDetectVMExit is the clearest: its fallback
    scores rdtscOverhead > 500 as +35, cpuidLatency > 1500 as +40 and the CPUID
    hypervisor bit as +25, which is 100/100 on every virtual machine, every time.
    That is the false-positive engine deleted in 6a1ee4a3 and capped in 73ea88ba, and
    "restoring coverage" by calling these is how it comes back.

    Comment stripping is mandatory: the disposition blocks this change added NAME every
    routine asserted here in order to explain it, so a comment-blind scan is guaranteed
    to report a call site for all 65.
    """

    _ANTIEVASION_DIR = ROOT / "src" / "PhantomCore" / "AntiEvasion"

    # Measured floors so a broken walk fails loudly instead of passing vacuously.
    _MIN_ASM_FILES = 6
    _EXPECTED_EXPORTS = 105

    # Every routine with at least one real call site or function-pointer table entry,
    # measured.  A name LEAVING this set means a reachable routine went dark, which is
    # how coverage is silently lost; a name ENTERING it means review is due.
    _LIVE = {
        # EnvironmentEvasionDetector_x64.asm - the shared CPU primitive library (24)
        "CheckCPUIDHypervisorBit", "MeasureRDTSCTimingDelta", "MeasureRDTSCPTiming",
        "MeasureCPUIDTiming", "GetIDTBase", "GetGDTBase", "GetLDTSelector",
        "GetTRSelector", "CheckSegmentLimits", "GetIDTAndGDTInfo", "GetDebugRegisters",
        "CheckNtGlobalFlag", "GetProcessHeapFlags", "CheckBeingDebugged",
        "CheckCPUIDHypervisorVendor", "GetCPUIDFeatureFlags", "GetExtendedCPUIDMaxLeaf",
        "CheckSSE2Support", "GetProcessorCoreCount", "MeasureRDTSCLatency",
        "CheckDebugRegistersASM", "CheckCPUIDVMXSupport", "GetCPUIDBrandString",
        "GetCPUIDVendorString",
        # PackerDetector_x64.asm - the only TARGET-subject routines in the layer (5)
        "ScanForAntiDebugOpcodes", "ScanForInt2DOpcode", "ScanForRDTSCOpcode",
        "ScanForCPUIDOpcode", "ScanForSMCPatterns",
        # TimeBasedEvasionDetector_x64.asm - the host timing profile, measured once (8)
        "TimingRDTSCDelta", "TimingSerializedRDTSC", "TimingCompareRDTSCvRDTSCP",
        "TimingCPUIDLatency", "TimingCheckHypervisorLeaf", "TimingCPUIDVariance",
        "TimingMeasureInstructions", "TimingMeasureMemory",
        # VMEvasionDetector_x64.asm - the only module with no dark export (6)
        "CheckHyperVBackdoor", "GetExtendedCPUIDInfo", "DetectVMCALL", "DetectVMMCALL",
        "CheckCPUIDLeafRange", "CheckVMwareBackdoor",
    }

    # Dark routines whose SUBJECT is this machine or this process and whose product is a
    # verdict rather than a measurement.  These must never acquire a caller that feeds a
    # sample verdict.  Grouped by owning .asm for reviewability.
    _NEVER_WIRE_AS_VERDICT = {
        # DebuggerEvasionDetector_x64.asm (14).  Read the bodies before the names:
        # DetectInt3Timing executes NO int 3 - it times 32 NOPs against a threshold -
        # and DetectInt2DBehavior executes no int 2Dh; it reads the PEB BeingDebugged
        # byte via gs:[60h] then DISCARDS it and returns a CPUID-timing verdict instead.
        "DebuggerDetectSingleStepTiming", "DetectTrapFlagManipulation",
        "DetectInt2DBehavior", "DetectInt3Timing", "DetectHardwareBreakpointsTiming",
        "MeasureDebugInstructionTiming", "DetectICEBPBehavior", "DetectIDTRelocation",
        "DetectGDTRelocation", "DetectLDTPresence", "CheckDebugRegistersIndirect",
        "MeasureCPUIDRDTSCPair", "DetectPrefetchTiming", "DetectExceptionHandlerTiming",
        # EnvironmentEvasionDetector_x64.asm (8)
        "DetectHardwareBreakpoints", "DetectSingleStep", "CheckTrapFlag",
        "PerformRDTSCPMeasurement", "MeasureInstructionTiming", "MeasureINTTimingDelta",
        "MeasureExceptionTiming", "DetectPopfTiming",
        # PackerDetector_x64.asm (4) - host timing opinions inside a FILE verdict
        "MeasureInstructionSequence", "DetectTimingAnomaly",
        "CheckHardwareBreakpointTraps", "DetectRDTSCAntiDebug",
        # SandboxEvasionDetector_x64.asm (15).  Their own doc comments give them away:
        # "high = likely VM", "deviation percentage", "0 = exact".
        "MeasureRDTSCOverhead", "MeasureCPUIDOverhead", "MeasureSleepAcceleration",
        "CheckCuckooBackdoor", "MeasureTimingPrecision", "SandboxDetectSingleStepTiming",
        "MeasureVMExitOverhead", "CalibrateTimingBaseline", "DetectTimingHook",
        "MeasureMemoryLatency", "CheckHypervisorBit", "MeasureIntOverhead",
        "SandboxRDTSCDifference", "GetRDTSCFrequency", "DetectRDTSCEmulation",
        # TimeBasedEvasionDetector_x64.asm (7)
        "TimingMeasureSleep", "TimingDetectSleepAcceleration", "TimingCalibrateTimebase",
        "TimingDetectSingleStep", "TimingGetTSCFrequency", "TimingDetectVMExit",
        "TimingMeasureHypervisor",
    }


    _DISPOSITION_MARKER = "DISPOSITION"

    _DOCUMENTED_MODULES = (
        "DebuggerEvasionDetector.cpp", "SandboxEvasionDetector.hpp",
        "TimeBasedEvasionDetector.hpp", "PackerDetector.hpp",
        "EnvironmentEvasionDetector.cpp",
    )

    # ---------------------------------------------------------------- helpers

    def _asm_exports(self):
        """Map every exported PROC to its owning .asm file name."""
        asm_files = sorted(self._ANTIEVASION_DIR.glob("*_x64.asm"))
        self.assertGreaterEqual(
            len(asm_files), self._MIN_ASM_FILES,
            "expected at least {} assembly sources under {}, walked {} - the glob is "
            "broken and every assertion here would pass vacuously".format(
                self._MIN_ASM_FILES, self._ANTIEVASION_DIR, len(asm_files)),
        )
        exports = {}
        for path in asm_files:
            stripped = re.sub(r";[^\n]*", "", read_source(path))
            for name in re.findall(
                r"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s+PROC\b", stripped
            ):
                exports[name] = path.name
        return exports

    def _consumer_sources(self):
        """Comment-stripped C/C++ that could reference an assembly export."""
        paths = sorted((ROOT / "src").rglob("*.cpp")) + sorted((ROOT / "src").rglob("*.hpp"))
        paths += sorted((ROOT / "tests").rglob("*.cpp"))
        self.assertGreater(len(paths), 200, "the consumer walk found almost no sources")
        return {p: strip_c_comments(read_source(p)) for p in paths}

    # Control-flow keywords may sit immediately before a name and still be a CALL.
    # Without this list `return Foo();` reads as a declaration, because "return " matches
    # the same character class a return type does.
    _NOT_A_RETURN_TYPE = frozenset(
        ("return", "if", "while", "for", "switch", "else", "do", "case", "goto")
    )

    @classmethod
    def _statement_around(cls, code, position):
        """Return the joined logical statement containing *position*.

        Deliberately NOT enclosing_statement(): that helper stops BEFORE the terminator
        because it exists to compare two tokens inside one boolean expression, so any
        test for a trailing ';' against its output is always false.  Reusing it here
        classified all 65 dark routines as live.
        """
        start = max(code.rfind(";", 0, position), code.rfind("{", 0, position),
                    code.rfind("}", 0, position))
        ends = [off for off in (code.find(";", position), code.find("{", position))
                if off >= 0]
        stop = min(ends) if ends else len(code)
        return " ".join(code[start + 1:stop].split())

    @classmethod
    def _call_sites(cls, code, name):
        """Real call sites of *name*: excludes prototypes, definitions and ALTERNATENAME.

        The discriminator is the text immediately BEFORE the name in its joined
        statement.  A declaration or definition carries a RETURN TYPE there
        (`uint64_t Foo(`); a call carries nothing (`Foo();`), an assignment
        (`x = Foo()`), a control keyword (`return Foo()`) or a nested call
        (`EXPECT_EQ(1u, Foo(`).  Joining the statement first is load-bearing: a
        multi-line prototype has no semicolon on its own line, which is what made a
        per-line test report five call sites that do not exist.

        '&name' counts as live because the packer reaches three routines through a
        function-pointer table rather than by calling them.
        """
        # Preprocessor lines are removed so `#endif` cannot become part of a return
        # type, and so an /ALTERNATENAME pragma can never be read as a call.
        body = re.sub(r"(?m)^\s*#[^\n]*", "", code)
        sites = []
        for match in re.finditer(
            r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(", body
        ):
            flat = cls._statement_around(body, match.start())
            if "ALTERNATENAME" in flat or ("Fallback_" + name) in flat:
                continue
            if name not in flat:
                sites.append(flat[:110])
                continue
            head = flat[:flat.index(name)]
            head = head.replace('extern "C"', "").replace("{", "").replace("}", "").strip()
            words = head.replace("*", " ").replace("&", " ").split()
            is_type = (
                bool(head)
                and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:<>,\*&\s]*", head))
                and not any(w in cls._NOT_A_RETURN_TYPE for w in words)
            )
            if not is_type:
                sites.append(flat[:110])
        for _ in re.finditer(r"&\s*" + re.escape(name) + r"(?![A-Za-z0-9_])", body):
            sites.append("&" + name)
        return sites

    # Three tests need the same census and the walk reads over a thousand sources, so it
    # is computed once per process rather than once per test.
    _census_cache = None

    def _live_names(self):
        if type(self)._census_cache is None:
            exports = self._asm_exports()
            sources = self._consumer_sources()
            live = set()
            for name in exports:
                for code in sources.values():
                    if name not in code:
                        continue
                    if self._call_sites(code, name):
                        live.add(name)
                        break
            type(self)._census_cache = (exports, live)
        return type(self)._census_cache

    # ---------------------------------------------------------------- tests

    def test_the_assembly_export_census_has_not_drifted(self):
        exports, live = self._live_names()
        self.assertEqual(
            self._EXPECTED_EXPORTS, len(exports),
            "the assembly layer exports {} routines, measured {}.  Update this count "
            "together with the _LIVE and _NEVER_WIRE_AS_VERDICT sets - a bare count "
            "bump hides which routine moved.".format(self._EXPECTED_EXPORTS, len(exports)),
        )
        went_dark = sorted(self._LIVE - live)
        self.assertEqual(
            [], went_dark,
            "these routines had a real caller and now have none, so hand-written "
            "assembly that used to run is dead weight in the binary and nothing else "
            "reports it: " + ", ".join(went_dark),
        )
        newly_live = sorted(live - self._LIVE)
        self.assertEqual(
            [], newly_live,
            "these routines acquired a caller.  That may be correct, but it needs a "
            "reviewer: confirm the SUBJECT is the scanned sample and not this machine, "
            "then add the name to _LIVE: " + ", ".join(newly_live),
        )

    def test_no_host_inference_routine_has_acquired_a_caller(self):
        exports, live = self._live_names()
        # Refuse to pass on a stale list: every name here must still be exported.
        missing = sorted(self._NEVER_WIRE_AS_VERDICT - set(exports))
        self.assertEqual(
            [], missing,
            "these names are on the never-wire list but are no longer exported by any "
            ".asm, so this guard is protecting nothing: " + ", ".join(missing),
        )
        wired = sorted(self._NEVER_WIRE_AS_VERDICT & live)
        self.assertEqual(
            [], wired,
            "these routines measure THIS MACHINE and return a verdict, and they now "
            "have a caller: " + ", ".join(wired) + ".  On any VMware, Hyper-V or cloud "
            "endpoint they read positive, so a verdict built from them convicts the "
            "endpoint being defended rather than the sample being scanned.  If a "
            "genuine CONTEXT consumer is intended, cap its severity and confidence the "
            "way 73ea88ba capped CheckTimingIndicators, state at the call site that the "
            "product is context and never a verdict, and only then move the name out of "
            "_NEVER_WIRE_AS_VERDICT.",
        )

    # The three SIMD-named exports of PackerDetector_x64.asm. Two of them do not do what
    # their names say, which is recorded at their declarations in PackerDetector.hpp.
    _SIMD_NAMED_ROUTINES = ("SIMDScanForByte", "SIMDScanForWord", "SIMDScanForPattern")

    # Deliberately NOT a file-wide scan. PackerDetector_x64.asm contains vector
    # instructions, all of them inside the one routine that is honestly named, so a
    # file-wide test would report all three as vectorised.
    _VECTOR_TOKENS = re.compile(
        r"(?i)(?<![A-Za-z0-9_])(?:xmm\d|ymm\d|movdqu|movdqa|pcmpeqb|pmovmskb|vpcmpeqb)"
        r"(?![A-Za-z0-9_])")

    @classmethod
    def _asm_procedure_body(cls, name):
        """The PROC/ENDP body of *name*, with assembly comments removed.

        Stripping ';' comments is load-bearing: these bodies carry prose that NAMES the
        instructions, so a comment-blind scan would read a routine documented as
        "scalar - no pcmpeqb here" as vectorised.
        """
        source = read_source(cls._ANTIEVASION_DIR / "PackerDetector_x64.asm")
        match = re.search(
            r"(?im)^[ \t]*" + name + r"[ \t]+PROC\b(.*?)^[ \t]*" + name + r"[ \t]+ENDP",
            source, re.S)
        if match is None:
            return None
        return re.sub(r";[^\n]*", "", match.group(1))

    def test_a_simd_named_routine_stays_dark_while_its_body_is_scalar(self):
        """A name may promise vectorisation only for as long as nothing relies on it."""
        scalar, vectorised = [], []
        for name in self._SIMD_NAMED_ROUTINES:
            body = self._asm_procedure_body(name)
            self.assertIsNotNone(
                body,
                "%s no longer has a PROC/ENDP pair in PackerDetector_x64.asm, so this "
                "guard can no longer see whether it is vectorised" % name)
            if self._VECTOR_TOKENS.search(body):
                vectorised.append(name)
            else:
                scalar.append(name)

        # ANTI-VACUITY. If the token scan breaks, every routine reads as scalar and the
        # test still passes - while also declaring the one HONEST name dishonest. The
        # scan must keep recognising the routine that genuinely vectorises.
        self.assertIn(
            "SIMDScanForByte", vectorised,
            "the vector-token scan no longer recognises SIMDScanForByte, which is "
            "measured to use movdqu/pcmpeqb/pmovmskb, so it cannot be trusted about the "
            "other two. Fix the scan before believing a green result here.")

        # The two scalar ones must stay dark. This is the rule PackerDetector.hpp states.
        consumers = self._consumer_sources()
        offenders = []
        for name in scalar:
            for path, code in consumers.items():
                if self._call_sites(code, name):
                    offenders.append("%s <- %s" % (name, path.name))

        self.assertEqual(
            [], offenders,
            "%d SIMD-named routine(s) whose assembly body contains NO vector instruction "
            "have acquired a caller: %s. PackerDetector.hpp records the rule at the "
            "declarations: a caller may be added only in the SAME change that either "
            "implements the vectorisation or drops the SIMD prefix. Wiring one as-is "
            "makes the product cite a capability it does not have, and the packer path "
            "scans at most MAX_EP_BYTES = 512 bytes, where vectorising cannot pay for "
            "itself anyway." % (len(offenders), " | ".join(offenders)))

    def test_every_dark_routine_keeps_its_prototype_and_fallback_binding(self):
        exports, live = self._live_names()
        dark = sorted(set(exports) - live)
        self.assertGreaterEqual(
            len(dark), 50,
            "expected the dark set to be large (measured 65); found {} - if the layer "
            "was genuinely wired this guard needs rewriting, not deleting".format(len(dark)),
        )
        sources = self._consumer_sources()
        raw = {p: read_source(p) for p in sources}

        undeclared, unbound = [], []
        for name in dark:
            declared = any(
                re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(", code)
                for code in sources.values()
            )
            if not declared:
                undeclared.append(name)
            bound = any(
                re.search(r"(?i)ALTERNATENAME\s*:\s*" + re.escape(name) + r"\s*=", text)
                for text in raw.values()
            )
            if not bound:
                unbound.append(name)

        self.assertEqual(
            [], sorted(undeclared),
            "a dark routine with no prototype cannot be called even deliberately, so "
            "the capability is unrecoverable rather than merely unused: "
            + ", ".join(sorted(undeclared)),
        )
        self.assertEqual(
            [], sorted(unbound),
            "these dark routines have no /ALTERNATENAME fallback, so a caller added "
            "later links against assembly alone and any configuration that does not "
            "assemble it fails at link time instead of degrading: "
            + ", ".join(sorted(unbound)),
        )


    def test_the_disposition_of_the_dark_layer_is_documented_where_it_is_declared(self):
        """The reasoning must live beside the prototypes, not only in a commit message."""
        missing = []
        for name in self._DOCUMENTED_MODULES:
            # RAW source: the disposition IS a comment, so stripping would delete it.
            text = read_source(self._ANTIEVASION_DIR / name)
            if self._DISPOSITION_MARKER not in text:
                missing.append(name)
        self.assertEqual(
            [], missing,
            "these modules export assembly routines that are deliberately dark and no "
            "longer explain why beside the declarations, so the next reader sees only "
            "unused code and wires it: " + ", ".join(missing),
        )



class AntiEvasionLiteralEncodingContractTests(unittest.TestCase):
    """No string literal in the AntiEvasion layer may hold a non-ASCII character.

    WHY THIS IS A CORRECTNESS GUARD AND NOT HYGIENE (task 193's mechanism):
    no product project passes /utf-8 and these sources carry no BOM, so MSVC decodes
    them with the system code page.  A 3-byte UTF-8 em-dash becomes three separate
    wide characters and a 2-byte umlaut becomes two.  For a log message that is
    mojibake; for a MITRE technique DISPLAY NAME it is a wrong string, and
    MITREMapper.cpp substring-matches display names, so the vocabulary must agree
    across modules or a match silently fails.

    MEASURED WHEN THIS GUARD LANDED: five separate modules render the T1055.013
    display name.  Three already spelled it ASCII, including MITREMapper.c and
    MITREMapper.cpp, which are the authority for technique names in this tree.  Two
    did not.  The ASCII spelling therefore wins because it is the incumbent
    convention, not because ASCII is easier.

    DELIBERATELY NOT ASSERTED: non-ASCII inside COMMENTS.  Box-drawing separators
    and em-dashes in prose are presentation and cannot change a verdict; two headers
    hold hundreds of them on purpose.  Sweeping them would have buried a behavioural
    fix in churn.  Instead the third test records that debt as a shrink-only ceiling
    so it cannot grow while remaining green on arrival - an equality guard there
    would have been red on arrival, and a guard that cannot pass is a guard nobody
    keeps (task 207).
    """

    _ANTIEVASION_DIR = ROOT / "src/PhantomCore/AntiEvasion"
    _SOURCE_SUFFIXES = (".cpp", ".hpp", ".h", ".asm")
    _LITERAL = re.compile(r'(L?)"(?:[^"\\\n]|\\.)*"')
    # IGNORECASE is load-bearing and mutation round 3 proved it: a case-sensitive
    # pattern cannot SEE "Process DoppelGanging", so a case divergence would slip
    # through the disagreement check entirely rather than being caught by it.
    _DOPPEL_LITERAL = re.compile(r'"[^"\n]*Doppelg[^"\n]*"', re.IGNORECASE)
    _MIN_LITERALS = 5700
    _MIN_RENDERERS = 10

    # non-ASCII BYTES per file, measured when this guard landed.  Shrink-only.
    _COMMENT_DEBT_CEILING = {
        "DebuggerEvasionDetector.cpp": 24,
        "DebuggerEvasionDetector.hpp": 3,
        "DebuggerEvasionDetector_x64.asm": 0,
        "EnvironmentEvasionDetector.cpp": 36,
        "EnvironmentEvasionDetector.hpp": 39,
        "EnvironmentEvasionDetector_x64.asm": 0,
        "NetworkBasedEvasionDetector.cpp": 33,
        "NetworkBasedEvasionDetector.hpp": 3,
        "PackerDetector.cpp": 9,
        "PackerDetector.hpp": 0,
        "PackerDetector_x64.asm": 3,
        "ProcessEvasionDetector.cpp": 48,
        "ProcessEvasionDetector.hpp": 2157,
        "SandboxEvasionDetector.cpp": 27,
        "SandboxEvasionDetector.hpp": 24,
        "SandboxEvasionDetector_x64.asm": 6,
        "TimeBasedEvasionDetector.cpp": 27,
        "TimeBasedEvasionDetector.hpp": 1689,
        "TimeBasedEvasionDetector_x64.asm": 9,
        "VMEvasionDetector.cpp": 45,
        "VMEvasionDetector.hpp": 36,
        "VMEvasionDetector_x64.asm": 3,
        "metamorphic_polymorphicdetector.cpp": 24,
        "metamorphic_polymorphicdetector.hpp": 0,
        "nt_undocumented.h": 0,
    }

    @staticmethod
    def _is_comment_line(line):
        stripped = line.lstrip()
        return (stripped.startswith("//")
                or stripped.startswith("*")
                or stripped.startswith("/*"))

    @classmethod
    def _read(cls, path):
        # bytes -> str deliberately: read_text() would translate CRLF and these
        # files are a mix of CRLF-only and LF-only conventions.
        return path.read_bytes().decode("utf-8", errors="replace")

    def test_no_antievasion_string_literal_holds_a_non_ascii_character(self):
        offenders = []
        examined = 0
        for path in sorted(self._ANTIEVASION_DIR.glob("*")):
            if path.suffix.lower() not in self._SOURCE_SUFFIXES:
                continue
            for number, line in enumerate(self._read(path).split("\n"), start=1):
                if self._is_comment_line(line):
                    continue
                for match in self._LITERAL.finditer(line):
                    examined += 1
                    bad = [c for c in match.group(0) if ord(c) > 127]
                    if bad:
                        offenders.append("%s:%d %s" % (
                            path.name, number,
                            " ".join("U+%04X" % ord(c) for c in dict.fromkeys(bad))))
        self.assertGreaterEqual(
            examined, self._MIN_LITERALS,
            "anti-vacuity: only %d literals examined, expected at least %d - the "
            "walk is not reaching the AntiEvasion sources"
            % (examined, self._MIN_LITERALS))
        self.assertEqual(
            [], offenders,
            "a string literal in the AntiEvasion layer holds a non-ASCII character; "
            "with no /utf-8 and no BOM MSVC mis-decodes it, so the string the "
            "product emits is not the string in the source: " + "; ".join(offenders))

    def test_no_renderer_of_the_doppelganging_technique_name_holds_non_ascii(self):
        """Tree-wide, not folder-wide: this technique name is rendered by five
        separate modules and the ASCII spelling is what the MITRE mappers use.

        DELIBERATELY NOT ASSERTED - that every renderer spells it IDENTICALLY.
        That reads like a stronger invariant and is not a sound one: MITREMapper.c
        carries both "Process Doppelganging" (the name) and "Process doppelganging"
        (the description) inside the SAME struct literal, and this codebase has no
        convention separating a title-case name from a sentence-case description.
        Asserting agreement therefore produces false positives on correct code,
        which is how a guard gets deleted.  Non-ASCII is the defect that was real.
        """
        non_ascii = []
        renderers = 0
        for folder in ("src", "tests", "PhantomSensor", "PhantomEmulator"):
            base = ROOT / folder
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                if path.suffix.lower() not in (".cpp", ".hpp", ".h", ".c"):
                    continue
                for number, line in enumerate(self._read(path).split("\n"), start=1):
                    if self._is_comment_line(line):
                        continue
                    for match in self._DOPPEL_LITERAL.finditer(line):
                        renderers += 1
                        literal = match.group(0)
                        bad = [c for c in literal if ord(c) > 127]
                        if bad:
                            non_ascii.append("%s:%d %s" % (
                                path.name, number,
                                " ".join("U+%04X" % ord(c)
                                         for c in dict.fromkeys(bad))))
        self.assertGreaterEqual(
            renderers, self._MIN_RENDERERS,
            "anti-vacuity: found only %d code-site literals mentioning this "
            "technique, expected at least %d" % (renderers, self._MIN_RENDERERS))
        self.assertEqual(
            [], non_ascii,
            "a code site renders the T1055.013 technique name with a non-ASCII "
            "character.  With no /utf-8 and no BOM that string is mis-decoded, so "
            "it cannot match the ASCII spelling MITREMapper.c and MITREMapper.cpp "
            "use - and MITREMapper.cpp substring-matches technique text: "
            + "; ".join(non_ascii))

    def test_the_antievasion_non_ascii_debt_does_not_grow(self):
        grew = []
        missing = []
        for name, ceiling in sorted(self._COMMENT_DEBT_CEILING.items()):
            path = self._ANTIEVASION_DIR / name
            if not path.exists():
                missing.append(name)
                continue
            actual = sum(1 for b in path.read_bytes() if b > 127)
            if actual > ceiling:
                grew.append("%s: %d non-ASCII bytes, ceiling %d"
                            % (name, actual, ceiling))
        self.assertEqual(
            [], missing,
            "a file this ceiling covers has been renamed or removed; update the "
            "ceiling in the same change: " + ", ".join(missing))
        self.assertEqual(
            [], grew,
            "non-ASCII was added to an AntiEvasion source.  This ceiling is "
            "shrink-only: decorative non-ASCII in comments is tolerated at its "
            "measured level but must not increase, and a new non-ASCII byte inside "
            "a string literal is a correctness defect caught by the sibling test: "
            + "; ".join(grew))




class MetamorphicHistogramContractTests(unittest.TestCase):
    """The opcode histogram must cost one pass and must not carry a false threshold.

    TWO PROPERTIES, neither of which any behavioural test can protect.

    ONE PASS.  ComputeOpcodeHistogram builds a 256-bin frequency table over the whole
    buffer.  It used to then call CalculateEntropy(buffer, size), which built an
    IDENTICAL table by walking the same bytes a second time.  On the on-access path
    that buffer is the ENTIRE mapped file - AnalyzeFile hands mappedFile.data() and
    mappedFile.size() straight to AnalyzeFileInternal - and the caller sets timeoutMs
    to 50 ms because a kernel thread is parked in FltSendMessage holding an
    IRP_MJ_CREATE.  A deadline can only be tested BETWEEN stages, so a wasted pass
    pushes later stages past it and into analysisTruncated.  Reintroducing that pass
    would produce the SAME entropy value, so the C++ equivalence test would still
    pass - only this guard can see it.

    A CALIBRATED THRESHOLD.  The 0xCC term was a bare `> 5.0`.  Measuring 0xCC over
    the whole file across 600 Microsoft-signed System32 binaries, which is exactly
    what this histogram measures, gives median 4.92%, p75 6.78%, p90 8.49%, p95
    10.05%, p99 12.27% and maximum 15.94% - so 5% was true for 294 of 600 legitimate
    Windows binaries.  This guard pins the VALUE above that observed maximum, not
    merely the presence of a named constant, because a constant that can be quietly
    moved back to 5.0 protects nothing.
    """

    _CPP = ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.cpp"
    _HPP = ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.hpp"

    # The highest 0xCC ratio observed across the 600-binary sample.
    _OBSERVED_LEGITIMATE_MAXIMUM = 15.94

    @classmethod
    def _read(cls, path):
        # bytes -> str deliberately: read_text() applies universal-newline
        # translation, and these sources are CRLF.
        return path.read_bytes().decode("utf-8", errors="replace")

    @staticmethod
    def _balanced_body(text, start_index):
        """The brace-balanced body beginning at the first '{' at or after start."""
        try:
            open_index = text.index("{", start_index)
        except ValueError:
            return None
        depth = 0
        for offset in range(open_index, len(text)):
            if text[offset] == "{":
                depth += 1
            elif text[offset] == "}":
                depth -= 1
                if depth == 0:
                    return text[open_index:offset + 1]
        return None

    @classmethod
    def _histogram_implementation(cls, code):
        """The Impl body of ComputeOpcodeHistogram - the largest of its definitions.

        There are two: the Impl implementation and a two-line public forwarder.
        Taking the largest cannot accidentally select the forwarder, and the size
        assertion below refuses if the shape ever changes enough to make that
        selection meaningless.
        """
        bodies = []
        for match in re.finditer(r"bool\s+ComputeOpcodeHistogram\s*\(", code):
            body = cls._balanced_body(code, match.end())
            if body:
                bodies.append(body)
        if not bodies:
            return None
        return max(bodies, key=len)

    def test_the_histogram_computes_entropy_without_a_second_pass(self):
        code = strip_c_comments(self._read(self._CPP))
        body = self._histogram_implementation(code)
        self.assertIsNotNone(
            body, "could not locate ComputeOpcodeHistogram; the guard cannot pass "
                  "vacuously, so this is a failure rather than a skip")
        self.assertGreater(
            len(body), 600,
            "the body selected for ComputeOpcodeHistogram is only %d chars, which "
            "means the public forwarder was picked instead of the implementation"
            % len(body))

        self.assertNotIn(
            "CalculateEntropy(", body,
            "ComputeOpcodeHistogram calls CalculateEntropy, which rebuilds the "
            "256-bin frequency table this function has already built - a second "
            "full pass over the whole mapped file inside a 50 ms budget. Use "
            "EntropyFromByteCounts with the counts already in hand.")
        self.assertIn(
            "EntropyFromByteCounts(out.byteCounts", body,
            "ComputeOpcodeHistogram must derive entropy from the byte counts it "
            "already built rather than from a fresh walk over the buffer")

        # exactly one buffer walk in the function
        walks = len(re.findall(r"for\s*\(\s*size_t\s+\w+\s*=\s*0;[^;]*<\s*size;", body))
        self.assertEqual(
            1, walks,
            "ComputeOpcodeHistogram should walk the buffer exactly once (found %d "
            "size-bounded loops); every extra pass is time taken from a stage that "
            "has not run yet" % walks)

    def test_the_module_holds_exactly_one_entropy_implementation(self):
        code = strip_c_comments(self._read(self._CPP))
        sums = len(re.findall(r"entropy\s*-=\s*p\s*\*\s*std::log2\(p\)", code))
        self.assertEqual(
            1, sums,
            "found %d Shannon entropy summations in this module, expected exactly 1. "
            "Two copies of one calculation is how the two YARA metadata builders "
            "(task 56) and the two on-disk trie producers (task 66) drifted apart, "
            "in both cases with the poorer copy being the one that ran." % sums)
        self.assertIn(
            "return EntropyFromByteCounts(freq, size);", code,
            "CalculateEntropy must delegate to the shared summation so the two "
            "entry points cannot diverge")

    def test_the_int3_threshold_stays_above_the_measured_legitimate_maximum(self):
        cpp = strip_c_comments(self._read(self._CPP))
        self.assertNotIn(
            "int3Percentage > 5.0", cpp,
            "the bare 5.0 threshold is back. Measured across 600 Microsoft-signed "
            "System32 binaries, 0xCC over the whole file exceeds 5% in 294 of them, "
            "so this term would be true for half of Windows.")
        self.assertIn(
            "MetamorphicConstants::MIN_SUSPICIOUS_INT3_PERCENTAGE", cpp,
            "the 0xCC threshold must be a named constant, so its calibration can be "
            "read at the declaration instead of guessed at the use site")

        raw_header = self._read(self._HPP)
        match = re.search(
            r"MIN_SUSPICIOUS_INT3_PERCENTAGE\s*=\s*([0-9]+(?:\.[0-9]+)?)", raw_header)
        self.assertIsNotNone(
            match, "MIN_SUSPICIOUS_INT3_PERCENTAGE is not declared with a literal "
                   "value that can be checked")
        value = float(match.group(1))
        self.assertGreaterEqual(
            value, self._OBSERVED_LEGITIMATE_MAXIMUM,
            "MIN_SUSPICIOUS_INT3_PERCENTAGE is %.2f, at or below the %.2f maximum "
            "measured across 600 signed Windows binaries. A threshold inside the "
            "legitimate range is a false-positive source, and naming the constant "
            "does not make the number safe."
            % (value, self._OBSERVED_LEGITIMATE_MAXIMUM))

        # The evidence must survive with the number, or the next reader cannot tell
        # a calibrated threshold from an invented one.
        for token in ("600", "15.94", "294"):
            self.assertIn(
                token, raw_header,
                "the measurement behind MIN_SUSPICIOUS_INT3_PERCENTAGE no longer "
                "records %r. Without the sample size and the observed maximum the "
                "value is indistinguishable from a guess." % token)




class MetamorphicReachabilityContractTests(unittest.TestCase):
    """What the metamorphic layer can actually reach, and what its comments may claim.

    MEASURED: the module emits 40 techniques.  Its only production caller leaves
    flags at MetamorphicAnalysisFlags::Default == StandardScan, and NOTHING anywhere
    sets the deeper flags, so 15 of those 40 cannot fire - the six OBF_* behind
    ScanObfuscation, the four SELF_* behind ScanSelfModifying, the four VM_* behind
    ScanVMProtection, and OBF_ControlFlowFlattening behind EnableCFGAnalysis.

    Two comments in RealTimeProtection asserted the opposite: that "every technique
    still runs", and that the truncation requeue re-examines the file "where the full
    default timeout applies".  The second is false because DeferredDeepScanLoop calls
    ScanEngine::ScanFile and MetamorphicDetector has exactly five production
    references, all in RealTimeProtection.cpp, so no ScanEngine route reaches it.

    THE FIRST TEST IS A DELIBERATE REVIEW PROMPT, not a prohibition.  It passes while
    the deeper flags remain unset and FAILS the moment someone wires them - which is
    the desired change - so that the coverage numbers recorded in two comments cannot
    silently become stale in the same commit that fixes the gap.  Same technique as
    the C_ASSERT review prompt on the kernel reply size.
    """

    _RTP = ROOT / "src/PhantomCore/RealTime/RealTimeProtection.cpp"
    _META_CPP = ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.cpp"
    _META_HPP = ROOT / "src/PhantomCore/AntiEvasion/metamorphic_polymorphicdetector.hpp"

    # Flags whose gated techniques are unreachable because no caller sets them.
    _NEVER_SET = ("ScanObfuscation", "ScanSelfModifying", "ScanVMProtection",
                  "EnableCFGAnalysis", "EnableFuzzyHashing", "ScanSimilarity",
                  "EnableFamilyMatching", "DeepScan", "ComprehensiveScan")

    @classmethod
    def _read(cls, path):
        return path.read_bytes().decode("utf-8", errors="replace")

    @classmethod
    def _enum_body_span(cls, header):
        """Byte span of the MetamorphicAnalysisFlags enum, so its own definitions
        of these names are not mistaken for a caller setting them."""
        start = header.find("enum class MetamorphicAnalysisFlags")
        if start < 0:
            return (0, 0)
        open_i = header.index("{", start)
        depth, i = 0, open_i
        while i < len(header):
            if header[i] == "{":
                depth += 1
            elif header[i] == "}":
                depth -= 1
                if depth == 0:
                    return (start, i)
            i += 1
        return (start, len(header))

    def test_the_deeper_metamorphic_flags_still_have_no_caller(self):
        low, high = self._enum_body_span(self._read(self._META_HPP))
        offenders = []
        for folder in ("src", "tests"):
            base = ROOT / folder
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                if path.suffix.lower() not in (".cpp", ".hpp", ".h"):
                    continue
                code = strip_c_comments(self._read(path))
                is_header = (path == self._META_HPP)
                raw = self._read(path)
                for flag in self._NEVER_SET:
                    needle = "MetamorphicAnalysisFlags::" + flag
                    for offset in range(len(code)):
                        offset = code.find(needle, offset)
                        if offset < 0:
                            break
                        # a HasFlag(...) TEST is a read, not a setter
                        window = code[max(0, offset - 60):offset]
                        if "HasFlag" in window:
                            continue
                        if is_header and low <= offset <= high:
                            continue
                        line = code[:offset].count("\n") + 1
                        offenders.append("%s:%d %s" % (path.name, line, flag))
                        break
        self.assertEqual(
            [], sorted(set(offenders)),
            "a deeper metamorphic flag now has a caller. That is the RIGHT direction - "
            "it restores up to 15 of the module's 40 techniques - but two comments "
            "record the current coverage numbers (RealTimeProtection's on-access block "
            "and the preset block in metamorphic_polymorphicdetector.hpp) and they must "
            "be corrected in the SAME change, or the next reader inherits a stale "
            "measurement. Update both, then update this guard: " + "; ".join(sorted(set(offenders))))

    def test_the_corrected_coverage_claims_are_not_restored(self):
        rtp = strip_c_comments(self._read(self._RTP))
        raw = self._read(self._RTP)
        retired = ("so every technique still runs and simply has",
                   "where the full default timeout applies")
        back = [phrase for phrase in retired if phrase in raw]
        self.assertEqual(
            [], back,
            "a retired coverage claim is back in RealTimeProtection. Measured: flags "
            "default to StandardScan so six analysis groups never run, and the "
            "truncation requeue reaches ScanEngine, not MetamorphicDetector: "
            + "; ".join(back))
        # the corrected text must carry the measurement, or it is just prose
        for token in ("15 of the module's 40 emitted techniques",
                      "metamorphicTruncated is therefore the count"):
            self.assertIn(
                token, raw,
                "the corrected comment no longer records %r, so the claim it replaced "
                "cannot be checked by the next reader" % token)

    def test_the_empty_custom_pattern_loop_is_not_reintroduced(self):
        code = strip_c_comments(self._read(self._META_CPP))
        iterations = code.count("for (const auto& pattern : m_impl->m_customPatterns)")
        self.assertEqual(
            0, iterations,
            "the empty custom-pattern loop is back. m_customPatterns is written only "
            "by AddCustomPattern, which has no caller, so the container is permanently "
            "empty and the loop acquired a lock to iterate nothing.")
        shared = code.count("std::shared_lock lock(m_impl->m_patternMutex)")
        self.assertEqual(
            0, shared,
            "a shared_lock on m_patternMutex is back with no reader behind it; the "
            "only legitimate users of that mutex are AddCustomPattern and "
            "ClearCustomPatterns, which take unique_lock")
        # the API seam must survive - removing it would delete the capability, not the
        # dead code
        for name in ("AddCustomPattern", "ClearCustomPatterns"):
            self.assertEqual(
                1, len(re.findall(r"(?<![A-Za-z0-9_])" + name + r"(?![A-Za-z0-9_])", code)),
                "%s must keep exactly its definition in the .cpp - it is the seam a "
                "caller uses to supply patterns, and deleting it would remove the "
                "capability rather than the dead loop" % name)




class ProcessEvasionDeadlineContractTests(unittest.TestCase):
    """ProcessEvasionAnalysisConfig had no timeout at all, on the kernel's callback.

    THE FIFTH AND LAST MEMBER OF THIS FAMILY. Four of the five evasion detectors on
    RealTimeProtection's process-creation path already took a remaining-budget timeout -
    debugger, VM, network and environment. This one took none, because its config had no
    field for it, and the module contained no deadline machinery whatsoever: timeoutMs,
    deadline, budget, elapsed and analysisTruncated were each zero occurrences.

    WHAT ONE CALL CAN COST, measured: three whole-system CreateToolhelp32Snapshot calls,
    thread enumeration, three EnumProcessModules (two with no gate), six
    ReadProcessMemory, VirtualQueryEx address-space walks, and TWO WinVerifyTrust
    signature verifications that can hit disk. 42 loops, only 5 with a visible cap, and
    six uncapped loops containing ReadProcessMemory. Meanwhile the caller asks for the
    deepest mode explicitly: flags = Default | DeepAnalysis and enableDeepScan = true.

    The outer evasionBudgetExceeded() gate cannot help - it is tested BETWEEN detectors,
    so it declines to start this one when the budget is already spent but cannot
    interrupt it once inside.
    """

    # The expensive stages, in the order the orchestrator runs them. Stage one is
    # deliberately absent: see test_the_first_stage_is_never_gated_by_the_deadline.
    BOUNDED_STAGES = ("CheckMasquerading", "CheckAntiDebug", "CheckMemory")

    @staticmethod
    def _internal_body():
        """AnalyzeProcessInternal's body, sliced between two DEFINITION markers.

        Anchoring on the first occurrence of the name would measure the CALL site in
        AnalyzeProcess, which sits hundreds of lines above the definition - the same trap
        the network sibling documents.
        """
        src = strip_c_comments(read_source(PROCESS_EVASION_DETECTOR_CPP_PATH))
        start = src.find("void ProcessEvasionDetector::AnalyzeProcessInternal(")
        assert start != -1, "AnalyzeProcessInternal definition not found"
        nxt = src.find("void ProcessEvasionDetector::", start + 1)
        end = nxt if nxt > start else len(src)
        return src[start:end]

    def test_the_declared_analysis_timeout_is_actually_read(self):
        body = self._internal_body()
        self.assertTrue(
            "config.timeoutMs" in body,
            "ProcessEvasionAnalysisConfig::timeoutMs must be READ by the orchestrator. A "
            "declared control nothing reads means a caller that sets it gets silence - "
            "which is what checkAllThreads and checkAllModules already do in this same "
            "struct.")
        self.assertTrue(
            "steady_clock" in body,
            "the deadline must use a monotonic clock; system_clock steps with NTP and an "
            "NTP correction would either abort the analysis instantly or disable the bound")

    def test_zero_means_no_limit_and_the_bound_is_an_absolute_point(self):
        """The inversion this family exists to prevent.

        Zero means UNLIMITED across every config in this subsystem. A deadline expressed
        as a remaining-milliseconds counter that each stage recomputes can therefore reach
        zero and silently switch the bound OFF at the exact moment it starts to matter.
        An absolute time point cannot.
        """
        body = self._internal_body()
        self.assertTrue(
            "config.timeoutMs == 0u" in body or "config.timeoutMs > 0" in body,
            "nothing in the orchestrator distinguishes timeoutMs == 0, so either zero no "
            "longer means unlimited - which breaks the convention four sibling configs "
            "share - or the bound now applies a zero-millisecond deadline and every "
            "analysis truncates immediately")
        self.assertTrue(
            "std::nullopt" in body,
            "the no-limit case must be representable as the ABSENCE of a deadline rather "
            "than as a sentinel value that later arithmetic can resurrect")
        # the bound must be computed once, not per stage
        self.assertEqual(
            1, body.count("std::chrono::steady_clock::now() +"),
            "the deadline must be computed EXACTLY ONCE. Recomputing it per stage restarts "
            "the clock and the total is then unbounded no matter how small each slice is.")

    def test_the_first_stage_is_never_gated_by_the_deadline(self):
        """Task 52: an analysis must never return having examined nothing."""
        body = self._internal_body()
        lam = body.find("const auto outOfTime = [&](")
        self.assertNotEqual(lam, -1, "the deadline lambda has disappeared")
        self.assertTrue(
            "!outOfTime(" in body[lam:],
            "no deadline check remains at any stage boundary, so the bound is gone")

        # ORDERING IS THE WRONG INVARIANT HERE and asserting it was a real hole: a gate
        # added on the line AFTER the stage name still leaves the name textually first,
        # so a mutation that gated stage one produced zero failures. What must be true is
        # that the injection stage's GATE EXPRESSION contains no deadline check at all.
        m = re.search(r"HasFlag\(config\.flags,\s*ProcessAnalysisFlags::CheckInjection\)"
                      r"([^{]{0,160})\{", body)
        self.assertIsNotNone(
            m, "the injection stage gate is no longer recognisable, so this guard cannot "
               "tell whether it is bounded")
        self.assertNotIn(
            "outOfTime", m.group(1),
            "the FIRST stage is now behind a deadline check. With an already-spent budget "
            "the analysis would return having examined NOTHING, which task 52 forbade. "
            "The first stage must always run; only later stages may be skipped.")

    def test_every_later_expensive_stage_is_bounded(self):
        body = self._internal_body()
        unbounded = []
        for flag in self.BOUNDED_STAGES:
            m = re.search(r"HasFlag\(config\.flags,\s*ProcessAnalysisFlags::"
                          + flag + r"\)([^{]{0,120})\{", body)
            if not m:
                unbounded.append(flag + " (stage gate not found)")
            elif "outOfTime" not in m.group(1):
                unbounded.append(flag + " (runs without a deadline check)")
        # the deep-analysis stage is gated on two conditions, so match it separately
        deep = re.search(r"config\.enableDeepScan([^{]{0,200})\{", body)
        if not deep:
            unbounded.append("deep analysis (stage gate not found)")
        elif "outOfTime" not in deep.group(1):
            unbounded.append("deep analysis (runs without a deadline check)")
        self.assertEqual(
            [], unbounded,
            "these stages can run after the deadline has passed: " + "; ".join(unbounded)
            + ". Each performs syscalls that scale with the target - snapshots, thread and "
            "module enumeration, cross-process reads, and for deep analysis two "
            "WinVerifyTrust calls that can hit disk.")

    def test_the_cheap_kernel_context_stage_is_not_gated(self):
        """Bounding free work loses detection and buys nothing.

        The kernel-context stage only compares values the caller already supplied, so it
        issues no syscalls. Gating it would drop findings to save no measurable time,
        which is the trade this project refuses. Same reasoning that keeps the ransomware
        fan-out outside the reply horizon.
        """
        body = self._internal_body()
        k = body.find("config.kernelContext.has_value()")
        self.assertNotEqual(k, -1, "the kernel-context stage has disappeared")
        window = body[max(0, k - 260):k]
        self.assertNotIn(
            "outOfTime", window,
            "the kernel-context stage is now behind a deadline check. It performs no "
            "syscalls - it compares data the kernel already handed us - so skipping it "
            "drops detection without saving measurable time.")

    def test_a_truncated_analysis_is_recorded_and_keeps_what_it_found(self):
        body = self._internal_body()
        self.assertTrue(
            "result.analysisTruncated = true;" in body,
            "a bounded analysis must RECORD that it was bounded. Without the flag a "
            "caller cannot tell a clean pass from a partial one, and the absence of a "
            "finding silently becomes evidence of safety.")
        for destructive in ("detectedTechniques.clear()", "result = ProcessEvasionResult"):
            self.assertTrue(
                destructive not in body,
                "the truncation path must not discard findings already collected (%s). A "
                "bound defers coverage; it never deletes it." % destructive)

        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        self.assertTrue(
            "result.analysisTruncated" in rtp,
            "RealTimeProtection must read analysisTruncated. A truncation nobody reports "
            "is how a latency fix becomes an unmeasured detection loss.")
        self.assertTrue(
            "std::max<uint64_t>(1ULL, pedRemainingMs)" in rtp,
            "the caller must clamp its computed budget to at least 1 ms, because zero "
            "means UNLIMITED in this config family - the clamp is what stops a spent "
            "budget from removing the bound entirely. The debugger and VM stages use the "
            "identical clamp.")




class EvasionTruncationHonestyContractTests(unittest.TestCase):
    """What a requeued truncation actually accomplishes, and what it may claim.

    Four evasion stages on the process-creation path count a truncation, requeue the
    image, and used to state that coverage moves in time rather than being lost. MEASURED:
    QueueDeferredDeepScan feeds DeferredDeepScanLoop, which calls ScanEngine::ScanFile,
    and ScanEngine references DebuggerEvasionDetector, VMEvasionDetector,
    ProcessEvasionDetector, NetworkBasedEvasionDetector and EnvironmentEvasionDetector
    ZERO times. So the requeue buys the deferred FILE tiers - signature, YARA, ML, packer,
    heuristics - and cannot finish an evasion analysis.

    The distinction matters because the counter is the only field evidence of coverage
    lost to the deadline. Read as "work successfully deferred" it says the bound is free;
    read correctly it says a process was only partly examined.
    """

    _EVASION_DETECTORS = (
        "DebuggerEvasionDetector",
        "VMEvasionDetector",
        "ProcessEvasionDetector",
        "NetworkBasedEvasionDetector",
        "EnvironmentEvasionDetector",
    )

    # Every truncation counter on this path, with the five sites each must occupy.
    _TRUNCATION_COUNTERS = (
        "metamorphicTruncated",
        "vmEvasionAnalysisTruncated",
        "debuggerEvasionAnalysisTruncated",
        "processEvasionAnalysisTruncated",
        "environmentEvasionAnalysisTruncated",
        "networkEvasionAnalysisTruncated",
    )

    _RETIRED = (
        "COVERAGE MOVES IN TIME, IT IS NOT LOST",
        "COVERAGE MOVES IN TIME RATHER THAN BEING DROPPED",
        "requeued for deferred analysis",
    )

    def test_no_truncation_block_claims_the_evasion_analysis_is_resumed(self):
        raw = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        back = [phrase for phrase in self._RETIRED if phrase in raw]
        self.assertEqual(
            [], back,
            "a retired requeue claim is back in RealTimeProtection. The requeue reaches "
            "ScanEngine, which references none of the evasion detectors, so it cannot "
            "resume an evasion analysis: " + "; ".join(back))
        # and the corrected text must carry the measurement, not just softer wording
        self.assertTrue(
            "COVERAGE MOVES IN TIME ONLY PARTLY" in raw,
            "the authoritative note explaining what the requeue does and does not buy is "
            "gone, so the three short notes that refer to it now point at nothing")
        self.assertEqual(
            3, raw.count("THE REQUEUE BUYS THE DEFERRED FILE TIERS"),
            "expected exactly three short notes referring to the authoritative one; a "
            "changed count means a stage was added or removed without its note")
        self.assertEqual(
            4, raw.count("NOT resumed"),
            "all four requeueing stages must say in their FIELD LOG that this evasion "
            "analysis is not resumed - the log is what an operator actually reads")

    def test_the_deferred_path_still_cannot_reach_these_detectors(self):
        """A REVIEW PROMPT, not a prohibition.

        This passes while no deferred route re-enters the evasion detectors, and fails the
        moment one does - which would be a genuine coverage restoration. It exists so the
        comments asserting unreachability cannot silently outlive the fact.
        """
        scan = strip_c_comments(read_source(SCAN_ENGINE_CPP_PATH))
        reachable = []
        for name in self._EVASION_DETECTORS:
            hits = len(re.findall(r"(?<![A-Za-z0-9_])" + name + r"(?![A-Za-z0-9_])", scan))
            if hits:
                reachable.append("%s (%d reference(s))" % (name, hits))
        self.assertEqual(
            [], reachable,
            "ScanEngine now references an evasion detector: " + "; ".join(reachable) +
            ". If a deferred route really does re-enter it, that is a coverage "
            "RESTORATION and welcome - but the truncation comments in "
            "RealTimeProtection.cpp state that no such route exists, and they must be "
            "corrected in the same change rather than left to mislead.")

    def test_every_evasion_truncation_counter_is_plumbed_through_all_five_sites(self):
        header = read_source(REAL_TIME_PROTECTION_HPP_PATH)
        cpp = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        broken = []
        for name in self._TRUNCATION_COUNTERS:
            declared = ("std::atomic<uint64_t> " + name) in header
            incremented = ("m_stats." + name + "++") in cpp
            loaded = ("m_stats." + name + ".load(") in cpp
            formatted = (name + "={}") in cpp
            reset = bool(re.search(r"(?m)^\s*" + name + r"\s*=\s*0\s*;", cpp))
            missing = [label for label, ok in (("declared", declared),
                                               ("incremented", incremented),
                                               ("loaded", loaded),
                                               ("in the report format", formatted),
                                               ("reset", reset)) if not ok]
            if missing:
                broken.append("%s: missing %s" % (name, ", ".join(missing)))
        self.assertEqual(
            [], broken,
            "a truncation counter is not plumbed through every site it needs. A counter "
            "that is incremented but never reported is invisible in the field, and one "
            "that is never reset accumulates across a Reset() call and misreports the "
            "next interval: " + "; ".join(broken))

    def test_the_capacity_report_format_matches_its_arguments(self):
        """The classic plumbing bug in this file: a placeholder added without an argument,
        or an argument inserted at the wrong position so every later value shifts."""
        cpp = read_source(REAL_TIME_PROTECTION_CPP_PATH)
        m = re.search(r"const auto line = std::format\((.*?)\);", cpp, re.S)
        self.assertIsNotNone(m, "the capacity report's std::format call was not found")
        blob = m.group(1)
        placeholders = blob.count("{}")
        tail = blob[blob.rfind('"') + 1:]
        args = [a.strip() for a in tail.split(",") if a.strip()]
        self.assertEqual(
            placeholders, len(args),
            "the capacity report has %d placeholders and %d arguments. A mismatch either "
            "fails to compile or, worse, silently shifts every value after the insertion "
            "point so the whole line misreports." % (placeholders, len(args)))
        self.assertGreater(
            placeholders, 15,
            "the capacity report has shrunk to %d placeholders; if fields were removed "
            "on purpose, re-derive this floor in the same change" % placeholders)




class NetworkEvasionOutboundTrafficContractTests(unittest.TestCase):
    """NetworkBasedEvasionDetector must not generate outbound traffic.

    This project's stated position is that every network call the product makes is visible
    in its source and that no cloud service is required to reach a verdict. A module named
    for network analysis is the most likely place for that to erode - by adding a DNS
    resolution to characterise a domain, or an HTTP probe to see what a connectivity-check
    URL returns.

    MEASURED TODAY: the module's only network calls are LOCAL QUERIES - one WSAStartup in
    Impl::Initialize, GetAdaptersAddresses, GetExtendedTcpTable in DetectTor, and
    InternetGetConnectedState. No socket connect, no DNS query, no HTTP request, no ICMP.
    That is why DNSQueryInfo and HTTPProbeInfo have no producer: they describe capability
    the module deliberately does not have.

    The analytical point matters as much as the privacy one. A connectivity probe issued by
    US characterises OUR behaviour, not the sample's. Observing a target probing a
    connectivity URL is a real sandbox-detection signal, but it has to be observed on the
    traffic path, not manufactured here.
    """

    # Calls that put a packet on the wire. Names only ever seen as import-table strings in
    # this module are excluded from the source before matching, so a name comparison
    # against the TARGET's imports cannot be mistaken for a call we make.
    _OUTBOUND = (
        "connect", "send", "sendto", "recv", "recvfrom", "WSAConnect", "WSASend",
        "getaddrinfo", "GetAddrInfoW", "gethostbyname", "DnsQuery_A", "DnsQuery_W",
        "DnsQueryEx", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile",
        "HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "IcmpSendEcho", "IcmpSendEcho2",
        "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFile",
    )

    # Local queries the module legitimately makes. These are the anti-vacuity control: if
    # the scanner cannot see these, it cannot see an outbound call either.
    _LOCAL = ("GetAdaptersAddresses", "GetExtendedTcpTable", "InternetGetConnectedState",
              "WSAStartup")

    @staticmethod
    def _code_only(text):
        """Remove comments AND string/char literals, leaving only code.

        Stripping comments alone is not enough here: this module compares import names such
        as "HttpSendRequestW" as WIDE STRING LITERALS, and those would otherwise register
        as calls the module makes.
        """
        out = []
        i, n = 0, len(text)
        while i < n:
            ch = text[i]
            if ch == "/" and i + 1 < n and text[i + 1] == "/":
                j = text.find("\n", i)
                i = n if j == -1 else j
            elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                j = text.find("*/", i + 2)
                i = n if j == -1 else j + 2
            elif ch in ('"', "'"):
                q, j = ch, i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == q or text[j] == "\n":
                        j += 1
                        break
                    j += 1
                out.append(" ")
                i = j
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    def test_the_module_makes_no_outbound_network_call(self):
        code = self._code_only(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))

        # ANTI-VACUITY FIRST. If the local queries are invisible to this scanner then a
        # zero result below would mean nothing at all.
        seen_local = [name for name in self._LOCAL
                      if re.search(r"(?<![A-Za-z0-9_])" + name + r"\s*\(", code)]
        self.assertGreaterEqual(
            len(seen_local), 3,
            "this scanner can only see %d of the local network queries the module is known "
            "to make (%s), so a zero outbound count would prove nothing. Either the module "
            "changed shape or _code_only is over-stripping."
            % (len(seen_local), ", ".join(seen_local) or "none"))

        offenders = []
        for name in self._OUTBOUND:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + name + r"\s*\(", code):
                line = code[:m.start()].count("\n") + 1
                offenders.append("%s (near code line %d)" % (name, line))
        self.assertEqual(
            [], offenders,
            "NetworkBasedEvasionDetector now makes an outbound network call: "
            + "; ".join(offenders) + ". An endpoint security agent generating its own "
            "traffic is a product and privacy decision, not a detail: this project states "
            "that every network call it makes is in the source and that no cloud service "
            "is needed for a verdict. It is also analytically wrong here - a probe we "
            "issue describes OUR behaviour, not the sample's. Observe the target instead.")

    def test_the_unproduced_record_types_stay_documented_as_unproduced(self):
        header = read_source(NETWORK_BASED_EVASION_DETECTOR_HPP_PATH)
        for token, why in (
                ("NO INSTANCE OF THIS TYPE IS EVER PRODUCED, and that is a property",
                 "DNSQueryInfo"),
                ("NO INSTANCE OF THIS TYPE IS EVER PRODUCED. statusCode",
                 "HTTPProbeInfo")):
            self.assertTrue(
                token in header,
                "%s no longer records that it is never produced. If a producer was added, "
                "that is a capability change requiring a decision about outbound traffic, "
                "and this note must be replaced rather than deleted." % why)
        # the containers must keep saying so too
        self.assertEqual(
            2, header.count("NEVER POPULATED"),
            "expected both unpopulated result containers to say so; a changed count means "
            "one was wired or the note was dropped")

    def test_the_host_config_struct_cannot_reach_the_verdict(self):
        """networkConfig describes THIS machine, so it must never score a sample."""
        code = strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))
        body = extract_c_function(code, "NetworkBasedEvasionDetector::CalculateEvasionScore")
        self.assertTrue(body, "CalculateEvasionScore has no readable body")
        self.assertTrue(
            "detectedTechniques" in body,
            "CalculateEvasionScore no longer reads detectedTechniques, so this guard is "
            "measuring the wrong function")
        leaked = [name for name in ("networkConfig", "httpProbes", "dnsQueries",
                                    "beacons", "fastFluxDomains")
                  if name in body]
        self.assertEqual(
            [], leaked,
            "the evasion score now reads %s. networkConfig describes THIS HOST - a VPN or "
            "a public resolver is normal on ordinary corporate infrastructure - so letting "
            "it into evasionScore, maxSeverity or isEvasive scores the machine rather than "
            "the sample. That is the same mistake a composite sandbox-likeness score was "
            "removed from this layer for making." % ", ".join(leaked))




class DisassemblerReadinessContractTests(unittest.TestCase):
    """An uninitialized decoder must never be reported as an initialized one.

    MEASURED. SandboxEvasionDetector::Impl::InitializeDisasm issued three
    Phantom::Disasm Init calls, discarded all three results, set disasmInitialized = true
    unconditionally and logged "PhantomDisassembler initialized".
    TimeBasedEvasionDetector::Impl's CONSTRUCTOR issued the same three calls, discarded
    all three, and kept no readiness state at all - its AnalyzeCodeWithPhantomDisasm then
    decoded through whatever those members happened to contain.

    WHY THIS IS A DETECTION DEFECT AND NOT A COMPILER WARNING: an uninitialized decoder
    does not fail loudly, it decodes nothing. The analysis finds no instructions, reports
    no techniques, and the target is recorded as showing no evasion behaviour - which is
    indistinguishable from a clean target. MetamorphicDetector::Impl::Initialize in the
    same folder already checked all three with Phantom::Disasm::IsFailed; these two had
    drifted from that shape.

    THE FORMATTER EXCLUSION IS DELIBERATE AND IS THE SUBTLE PART. In BOTH modules the
    formatter appears only at its declaration and its Init - it has no consumer. Adding it
    to the readiness condition looks like completeness and would DISABLE WORKING DETECTION
    over a component that cannot affect a result. The third test exists so that
    "tidy-up" fails instead of shipping.
    """

    _MODULES = (
        ("SandboxEvasionDetector.cpp", "SANDBOX"),
        ("TimeBasedEvasionDetector.cpp", "TIMEBASED"),
    )

    @staticmethod
    def _sources():
        return (
            ("SandboxEvasionDetector.cpp",
             strip_c_comments(read_source(SANDBOX_EVASION_DETECTOR_CPP_PATH))),
            ("TimeBasedEvasionDetector.cpp",
             strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))),
        )

    def test_every_disassembler_init_result_is_checked(self):
        offenders = []
        for name, code in self._sources():
            calls = list(re.finditer(r"(\w+)\.Init\s*\(", code))
            self.assertGreaterEqual(
                len(calls), 3,
                "%s makes only %d Init call(s); this guard exists to bound them, so "
                "re-derive the floor if the module deliberately changed shape"
                % (name, len(calls)))
            for m in calls:
                window = code[max(0, m.start() - 140):m.start()]
                if "IsFailed(" not in window:
                    line = code[:m.start()].count("\n") + 1
                    offenders.append("%s:%d %s.Init" % (name, line, m.group(1)))
        self.assertEqual(
            [], offenders,
            "a Phantom::Disasm Init result is discarded again: " + "; ".join(offenders)
            + ". A failed Init leaves a decoder that decodes nothing, so the module "
            "reports no techniques and the target looks clean rather than unexamined.")

    def test_readiness_is_never_asserted_unconditionally(self):
        sandbox = strip_c_comments(read_source(SANDBOX_EVASION_DETECTOR_CPP_PATH))
        # the flag must be set AFTER the readiness values are computed, and a refusal
        # must exist between them
        flag = sandbox.find("disasmInitialized = true;")
        ready = sandbox.find("decoder64Ready")
        self.assertNotEqual(flag, -1, "SandboxEvasionDetector no longer sets its readiness flag")
        self.assertNotEqual(
            ready, -1,
            "SandboxEvasionDetector no longer computes a per-decoder readiness value, so "
            "nothing distinguishes a working disassembler from a failed one")
        self.assertLess(
            ready, flag,
            "disasmInitialized is set before the decoder results are known, which is the "
            "defect this guard exists for: a total initialization failure then presents "
            "as a success and the DEBUG line claims the disassembler is ready")
        # DO NOT assert the literal condition text here. The formatter-exclusion test
        # locates the same statement, so pinning its exact spelling in both places made
        # every edit to that line fail two tests and left neither able to discriminate
        # its own invariant. What matters to THIS test is only that a refusal keyed on
        # the DECODER results exists and precedes the flag.
        gates = re.findall(r"if\s*\(([^)]*decoder64Ready[^)]*)\)", sandbox)
        self.assertTrue(
            gates,
            "no refusal is keyed on the decoder results any more, so nothing keeps "
            "disasmInitialized false when initialization fails")
        refusal = sandbox.find("if (" + gates[0] + ")")
        self.assertTrue(
            -1 < refusal < flag,
            "the decoder refusal no longer precedes the readiness flag, so the flag is "
            "set before the failure can prevent it")

        timebased = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))
        self.assertTrue(
            "bool m_disasmReady{ false };" in timebased,
            "TimeBasedEvasionDetector's readiness flag is gone; without it the constructor "
            "cannot report a failure, because a constructor has no return value")
        self.assertTrue(
            "if (!m_disasmReady) {" in timebased,
            "nothing refuses to decode when TimeBasedEvasionDetector's decoders failed to "
            "initialize, so AnalyzeCodeWithPhantomDisasm walks an uninitialized decoder")

    def test_the_formatter_does_not_gate_decoding_in_either_module(self):
        """DELIBERATE ASYMMETRY, NOT AN OVERSIGHT.

        In both modules the formatter has no consumer - measured, it appears only at its
        declaration and its Init. Including it in the readiness condition would refuse to
        disassemble because a component nobody calls failed, which removes detection to
        satisfy tidiness. That is the one trade this project does not make.
        """
        sandbox = strip_c_comments(read_source(SANDBOX_EVASION_DETECTOR_CPP_PATH))
        timebased = strip_c_comments(read_source(TIME_BASED_EVASION_DETECTOR_CPP_PATH))

        # Collect every expression that GATES readiness. A missing gate is
        # test_readiness_is_never_asserted_unconditionally's failure, not this one - this
        # test must not double-report it, or neither test discriminates its own invariant.
        gating = [("SandboxEvasionDetector.cpp", g)
                  for g in re.findall(r"if\s*\(([^)]*decoder64Ready[^)]*)\)", sandbox)]
        gating += [("TimeBasedEvasionDetector.cpp", g)
                   for g in re.findall(r"m_disasmReady\s*=\s*([^;]+);", timebased)]

        offenders = ["%s: %s" % (name, " ".join(expr.split()))
                     for name, expr in gating if "formatterReady" in expr]
        self.assertEqual(
            [], offenders,
            "the formatter now gates decoding: " + "; ".join(offenders) + ". It has no "
            "consumer in either module, so this refuses to disassemble because a "
            "component nobody calls failed - removing detection to satisfy tidiness.")

        # ANTI-VACUITY: the formatter must still be initialized and its failure reported,
        # or this test would pass on a module that simply deleted it.
        for name, code in self._sources():
            self.assertTrue(
                "formatterReady" in code,
                "%s no longer computes a formatter result at all. Deleting it would satisfy "
                "the assertions above while losing the report that it failed." % name)




class DiscardedAnalysisResultContractTests(unittest.TestCase):
    """An analysis that did not run must not be read as an analysis that found nothing.

    Three [[nodiscard]] returns were discarded and each produced a wrong answer rather
    than merely a compiler warning.

    MEASURED SEMANTICS, because the fix depended on them: Impl::ComputeOpcodeHistogram
    sets outHistogram.valid = true then returns true, with an early return false from its
    entry guard - so the value means SUCCEEDED, not FOUND-SOMETHING. Impl::AnalyzeCFG has
    the identical shape. Both callers discarded the value and then read a field of the
    out-parameter, and those fields default to false, so an analysis that never ran read
    exactly like one that found nothing.

    THE THIRD IS THE SERIOUS ONE. DetectSandboxNetwork discarded CheckNetworkAdapters'
    result and then concluded from `adapterDetails.size() <= 1` that a sandbox network was
    present, appending "Only single network adapter present." and returning true. On a
    failed enumeration that vector is empty, the test holds, and the function returned a
    POSITIVE verdict carrying a claim about the machine that was never measured. An empty
    result is silence, not evidence.
    """

    @staticmethod
    def _meta():
        return strip_c_comments(read_source(METAMORPHIC_DETECTOR_CPP_PATH))

    @staticmethod
    def _net():
        return strip_c_comments(read_source(NETWORK_BASED_EVASION_DETECTOR_CPP_PATH))

    def test_an_unbuilt_histogram_is_not_read_as_a_clean_one(self):
        code = self._meta()
        bare = re.findall(r"(?m)^\s*m_impl->ComputeOpcodeHistogram\s*\(", code)
        self.assertEqual(
            [], bare,
            "the opcode histogram is computed as a bare statement again, so its success "
            "value is discarded and hasExcessiveNops is then read from a histogram that "
            "may never have been built - a default false, indistinguishable from a file "
            "with no NOP padding")
        self.assertTrue(
            "ComputeOpcodeHistogram(buffer, size, result.opcodeHistogram) &&" in code,
            "the histogram result is no longer conjoined with the field it guards; "
            "nothing now distinguishes 'analysed and clean' from 'not analysed'")

    def test_an_unanalysed_cfg_is_not_read_as_unflattened(self):
        code = self._meta()
        bare = re.findall(r"(?m)^\s*m_impl->AnalyzeCFG\s*\(", code)
        self.assertEqual(
            [], bare,
            "AnalyzeCFG is called as a bare statement again, so isFlattened is read from "
            "a CFG that may never have been analysed")
        self.assertTrue(
            "result.cfgAnalysis) &&" in code,
            "the CFG result is no longer conjoined with the isFlattened read it guards")

    def test_a_failed_adapter_enumeration_cannot_produce_a_sandbox_verdict(self):
        code = self._net()
        bare = re.findall(r"(?m)^\s*CheckNetworkAdapters\s*\(", code)
        self.assertEqual(
            [], bare,
            "CheckNetworkAdapters is called as a bare statement again, so a failed "
            "enumeration leaves adapterDetails empty and the count test below turns that "
            "absence into a positive sandbox verdict")
        self.assertTrue(
            "const bool adaptersEnumerated = CheckNetworkAdapters(" in code,
            "the enumeration result is no longer captured")

        # THE GATE IS THE WHOLE POINT: an ungated count test is the defect.
        gated = re.findall(r"if\s*\(\s*adaptersEnumerated\s*&&\s*adapterDetails\.size\(\)\s*<=\s*1\s*\)",
                           code)
        self.assertEqual(
            1, len(gated),
            "the adapter-count inference is not gated on the enumeration having "
            "succeeded (%d matching gate(s) found). size() <= 1 is satisfied by an EMPTY "
            "vector, so without the gate a failure produces 'Only single network adapter "
            "present.' and a true return." % len(gated))

        self.assertNotIn(
            "bool vpnDetected, vmMacDetected;", code,
            "the two adapter flags are uninitialised again while being passed by "
            "reference to a function that may return without writing them")

        # ANTI-VACUITY: the adapter-NAME loop is deliberately NOT gated, because iterating
        # an empty vector finds nothing, which is the correct outcome of being unable to
        # look. If a future edit gates it too, that is a larger change than this guard
        # describes and the reasoning here should be revisited rather than silently kept.
        self.assertTrue(
            "for (const auto& adapter : adapterDetails)" in code,
            "the adapter-name loop is gone; this guard's reasoning about which checks need "
            "gating no longer describes the code")




def enclosing_block_of(text, needle):
    """Return the { ... } block of the statement containing `needle`, or None.

    Anchored on the brace that OPENS after the needle and matched by depth, so it does not
    depend on indentation - the earlier version of this guard assumed a 12-space body and
    silently matched nothing.
    """
    index = text.find(needle)
    if index == -1:
        return None
    open_brace = text.find("{", index)
    if open_brace == -1:
        return None
    depth = 0
    for position in range(open_brace, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:position + 1]
    return None



class DiscardedNodiscardClosureContractTests(unittest.TestCase):
    """Closes the discarded-[[nodiscard]] strand for the AntiEvasion folder.

    Twenty-two sites discarded a [[nodiscard]] result. They were NOT one defect: measuring
    each callee's return semantics split them into five classes, and nine turned out to be
    live defects while thirteen were correct-but-unstated. A blanket (void) sweep would
    have silenced three real ones.

    These tests pin the two invariants that a future edit could plausibly undo, plus the
    two defects the measurement exposed along the way - a fatal check on a component with
    no consumer, and a header comment that contradicted its own implementation.
    """

    MODULES = (
        ("metamorphic_polymorphicdetector.cpp", "metamorphic_polymorphicdetector.hpp"),
        ("VMEvasionDetector.cpp", "VMEvasionDetector.hpp"),
        ("NetworkBasedEvasionDetector.cpp", "NetworkBasedEvasionDetector.hpp"),
        ("SandboxEvasionDetector.cpp", "SandboxEvasionDetector.hpp"),
        ("TimeBasedEvasionDetector.cpp", "TimeBasedEvasionDetector.hpp"),
    )


    @staticmethod
    def _disassembler_nodiscard_names():
        """Names declared [[nodiscard]] by the disassembler this folder calls into."""
        names = set()
        headers = sorted((ROOT / "PhantomDisassembler").rglob("*.h*"))
        for header in headers:
            names |= set(re.findall(
                r"\[\[nodiscard\]\]\s+[\w:<>,\s\*&]*?(\w+)\s*\(",
                strip_c_comments(read_source(header))))
        names.discard("")
        # ANTI-VACUITY: if the tree moves, this silently returns nothing and the union adds
        # no protection at all.
        assert len(names) >= 20, (
            "only %d [[nodiscard]] names found across %d disassembler header(s); the scan "
            "has broken and the external half of this guard is inert"
            % (len(names), len(headers)))
        return names

    def test_no_analysis_result_in_this_folder_is_silently_discarded(self):
        """A bare statement form means a [[nodiscard]] value went nowhere unstated.

        THE SUBJECT SET IS DERIVED, NOT LISTED. Every name declared [[nodiscard]] in the
        module's own header or .cpp becomes a subject, so the guard cannot drift out of date
        as functions are added, and it cannot over-constrain by flagging void-returning
        siblings that merely share a naming prefix - an earlier draft matched bare `Detect`
        and would have done exactly that.

        The receiver chain is optional, so `x->Foo(` and `a.b.Foo(` are caught as well as a
        plain `Foo(`. The earlier draft anchored on the literal call text and would have
        missed a regression at `formatter.FormatInstruction(` entirely.

        KNOWN LIMITATION, stated rather than hidden: a statement start is recognised by the
        previous non-blank line ending in ';', '{' or '}'. A braceless single-line `if (x)
        Foo();` would therefore not be examined. Every conditional in this folder uses
        braces, so the gap is currently empty, but it is a gap.
        """
        folder = METAMORPHIC_DETECTOR_CPP_PATH.parent
        offenders = []
        derived = {}
        for cpp_name, hpp_name in self.MODULES:
            cpp_path, hpp_path = folder / cpp_name, folder / hpp_name
            code = strip_c_comments(read_source(cpp_path))
            declarations = code
            if hpp_path.exists():
                declarations += strip_c_comments(read_source(hpp_path))
            names = set(re.findall(r"\[\[nodiscard\]\]\s+[\w:<>,\s\*&]*?(\w+)\s*\(",
                                   declarations))
            names.discard("")
            # THE EXTERNAL APIS MUST BE IN THE SET TOO. Init and FormatInstruction are
            # declared in PhantomDisassembler, not in these modules, so a set derived only
            # from the module's own files left both unprotected - proven by a mutation that
            # made formatter.FormatInstruction bare and produced ZERO failures. Discarding an
            # Init result is the exact defect fixed in Sandbox and TimeBased, so the external
            # surface this folder calls belongs in scope.
            names |= self._disassembler_nodiscard_names()
            derived[cpp_name] = len(names)
            if not names:
                continue
            alternation = "|".join(sorted(re.escape(n) for n in names))
            bare = re.compile(r"^(?:\w+\s*(?:\.|->)\s*)*(" + alternation + r")\s*\(")
            rows = code.splitlines()
            for number, line in enumerate(rows, start=1):
                stripped = line.strip()
                if not bare.match(stripped):
                    continue
                # A MATCH IS ONLY A DISCARDED RESULT IF IT STARTS A STATEMENT. Without this
                # the check reported continuation lines: `VMTypeToString(x).c_str(), y);`
                # continuing an SS_LOG_INFO argument list, and the second operand of
                # `if (a && m_impl->DisassembleBuffer(...))` - whose value IS consumed.
                previous = ""
                for back in range(number - 2, -1, -1):
                    if rows[back].strip():
                        previous = rows[back].strip()
                        break
                if previous and previous[-1] not in ";{}":
                    continue
                offenders.append("%s stripped-line %d: %s"
                                 % (cpp_name, number, stripped[:64]))

        # ANTI-VACUITY: if the declaration scan breaks, every module yields an empty subject
        # set and this test passes while checking nothing.
        thin = {name: count for name, count in derived.items() if count < 10}
        self.assertEqual(
            {}, thin,
            "the [[nodiscard]] declaration scan found almost nothing for %s, so this test "
            "would pass vacuously - fix the scan before trusting a green result" % thin)

        self.assertEqual(
            [], offenders,
            "%d [[nodiscard]] analysis call(s) appear as a bare statement, discarding the "
            "result with no stated reason. Either consume the value or write (void) with the "
            "reason, as the rest of this folder now does. Line numbers are from the "
            "comment-stripped text: %s" % (len(offenders), " | ".join(offenders[:6])))

    def test_the_formatter_failure_cannot_disable_metamorphic_detection(self):
        """Nothing consumes formatted text, so failing Initialize over it drops everything."""
        code = strip_c_comments(read_source(METAMORPHIC_DETECTOR_CPP_PATH))
        block = enclosing_block_of(code, "m_formatter.Init(")
        self.assertIsNotNone(block, "the formatter Init call is gone entirely")
        self.assertNotIn(
            "return false", block,
            "a formatter Init failure aborts Initialize again. Nothing in this module "
            "consumes formatted instruction text, so this refuses to run EVERY technique "
            "the detector implements in order to report that a reporting facility was "
            "unavailable. Block: %s" % block.strip()[:200])
        self.assertIn(
            "SS_LOG_WARN", block,
            "the formatter failure is now silent; it must still be reported. Block: %s"
            % block.strip()[:200])

        # ANTI-VACUITY: the decoders MUST stay fatal, which also proves this test can tell
        # a fatal block from a warning block rather than passing on anything it reads.
        for decoder in ("m_decoder32.Init(", "m_decoder64.Init("):
            dblock = enclosing_block_of(code, decoder)
            self.assertIsNotNone(dblock, "%s is gone" % decoder)
            self.assertIn(
                "return false", dblock,
                "%s no longer aborts Initialize. Detection genuinely depends on the "
                "decoders - an uninitialised decoder decodes nothing and the module then "
                "reports no techniques, which is indistinguishable from a clean file."
                % decoder)

    def test_the_unread_instruction_text_is_not_formatted_per_instruction(self):
        """Formatting every decoded instruction into a buffer nobody reads is dead work."""
        code = strip_c_comments(read_source(METAMORPHIC_DETECTOR_CPP_PATH))
        readers = [ln for ln in code.splitlines() if ".text" in ln]
        if readers:
            # A READER APPEARED. That is not automatically wrong - it makes the removed
            # formatting meaningful again - but it invalidates the reasoning recorded at the
            # removal site, so it must be a deliberate decision rather than a silent drift.
            self.fail(
                "something now references the instruction text field (%d line(s), e.g. %r). "
                "The formatting call was removed because NOTHING read it and the loop runs "
                "once per decoded instruction up to MAX_INSTRUCTIONS. If a consumer is "
                "genuinely wanted, restore the formatting deliberately and update the note "
                "at the removal site - do not leave a reader of a field that is never "
                "written." % (len(readers), readers[0].strip()[:70]))
        self.assertEqual(
            0, code.count("m_formatter.FormatInstruction"),
            "per-instruction formatting is back while nothing reads the result")
        self.assertTrue(
            "char text[256];" in code,
            "the text field was deleted rather than left as the extension seam it is. "
            "Removing the formatting was a cost fix; removing the field discards a place a "
            "text-matching detector could attach.")

    def test_the_primary_process_scan_reports_when_it_analysed_nothing(self):
        """Zero is a success count of zero, not a clean machine."""
        code = strip_c_comments(read_source(VM_EVASION_DETECTOR_CPP_PATH))
        captured = code.count("const size_t analyzedProcesses = ScanAllProcesses(processResults);")
        reported = code.count("if (analyzedProcesses == 0) {")
        self.assertEqual(
            3, captured,
            "expected all 3 ScanAllProcesses call sites to capture the count, found %d"
            % captured)
        self.assertEqual(
            3, reported,
            "expected all 3 sites to report a zero, found %d. Zero means NOT ONE PROCESS "
            "COULD BE ANALYSED on the phase this file's own comment calls the PRIMARY "
            "detection - silence there is a health signal, not a clean verdict." % reported)

    def test_scan_all_processes_does_not_claim_to_return_a_detection_count(self):
        """The header contradicted its own implementation and its sibling one screen up."""
        header = read_source(VM_EVASION_DETECTOR_HPP_PATH)
        self.assertFalse(
            "@return Number of processes with anti-VM behavior detected" in header,
            "ScanAllProcesses again claims to return a DETECTION count. It forwards "
            "AnalyzeProcessesBatch unchanged, which counts processes for which "
            "AnalyzeProcessAntiVMBehavior returned true, and that is documented 'true if "
            "analysis completed successfully'. The findings are in the out-parameter.")
        self.assertTrue(
            "@return Number of processes successfully analyzed" in header,
            "AnalyzeProcessesBatch's correct wording is gone; it is the reference this "
            "correction was measured against")




class TechniqueAttributionContractTests(unittest.TestCase):
    """A reported technique must name the instruction that was actually found.

    DebuggerEvasionDetector::ScanMemory decodes executable memory and maps each anti-debug
    instruction to an EvasionTechnique. Two mappings named something that was not observed,
    and because the technique drives the MITRE id, the category and the severity, a wrong
    technique is three wrong facts.

    REACHABILITY WAS MEASURED, not assumed: ScanMemory is defined at :2524 and called at
    :5205, and the detector is wired at RealTimeProtection.cpp:4465 with its findings
    reaching the verdict.

    THE FUNCTION NAME HERE WAS WRONG ONCE. It said AnalyzeHandles, because the search walked
    backwards for the nearest preceding signature instead of mapping the switch's offset into
    each definition's byte range. AnalyzeHandles is a separate 61-line function that really
    does analyse handles - SystemHandleInformation, OBJECT_ProcessHandleEnum - and its body
    ends before this switch begins. Attribute by RANGE, never by proximity.
    """

    @staticmethod
    def _mnemonic_switch():
        """The mnemonic switch region only - never the whole 5,700-line file."""
        code = strip_c_comments(read_source(DEBUGGER_EVASION_DETECTOR_CPP_PATH))
        start = code.find("case Phantom::Disasm::Mnemonic::RDTSC:")
        end = code.find("case Phantom::Disasm::Mnemonic::CPUID:")
        if start == -1 or end == -1:
            return None
        tail = code.find("break;", end)
        return code[start:tail + 6 if tail != -1 else end + 400]

    def test_an_interrupt_is_attributed_by_its_number(self):
        region = self._mnemonic_switch()
        self.assertIsNotNone(region, "the mnemonic switch is gone; this guard is stale")

        self.assertTrue(
            "switch (buffer[offset + 1]) {" in region,
            "the INT case no longer inspects the interrupt number. `INT n` encodes as CD n, "
            "so without reading buffer[offset + 1] every interrupt is labelled the same - "
            "and INT 0x29 is __fastfail, emitted by ordinary CFG-hardened Microsoft "
            "binaries, so compiler-generated code gets attributed to the INT 2D anti-debug "
            "trick. Region: %s" % region.strip()[:200])

        for immediate, technique in (("0x2D", "EXCEPTION_INT2D"),
                                     ("0x03", "EXCEPTION_INT3"),
                                     ("0x01", "EXCEPTION_INT1")):
            pattern = re.compile(r"case\s+" + immediate + r"\s*:\s*technique\s*=\s*"
                                 r"EvasionTechnique::" + technique + r"\s*;")
            self.assertTrue(
                bool(pattern.search(region)),
                "interrupt %s is no longer mapped to %s; each anti-debug interrupt must "
                "carry its own technique rather than share one" % (immediate, technique))

        # The unnamed interrupts must be SKIPPED, not recorded under a borrowed label.
        self.assertTrue(
            bool(re.search(r"default\s*:\s*continue\s*;", region)),
            "an unrecognised interrupt number no longer skips the instruction. Recording it "
            "under whichever technique happens to be in scope is the defect this closed.")

    @staticmethod
    def _case_body(code, marker):
        """The case body, delimited by its own `break;`.

        NOT a fixed character window. strip_c_comments turns each comment line into
        whitespace, so a window sized for the original code silently truncated once
        explanatory comments were added above the assignment - which is exactly how this
        guard first failed against correct code.
        """
        index = code.find(marker)
        if index == -1:
            return None
        end = code.find("break;", index)
        return code[index:end + 6] if end != -1 else code[index:]

    def test_a_cpuid_is_not_reported_as_an_rdtsc_timing_check(self):
        code = strip_c_comments(read_source(DEBUGGER_EVASION_DETECTOR_CPP_PATH))
        cpuid_case = self._case_body(code, "case Phantom::Disasm::Mnemonic::CPUID:")
        self.assertIsNotNone(cpuid_case, "the CPUID case is gone; this guard is stale")

        # WORD-BOUNDED: TIMING_RDTSC is a prefix of TIMING_RDTSCP, so a plain substring
        # test cannot tell the two enumerators apart.
        self.assertFalse(
            bool(re.search(r"TIMING_RDTSC(?![A-Za-z0-9_])", cpuid_case)),
            "a CPUID instruction is reported as an RDTSC timing technique again. The "
            "original carried the comment 'Reuse timing category', so the mislabel was "
            "known - and the technique drives the MITRE id, the category and the severity, "
            "making it three wrong facts. Case: %s" % cpuid_case.strip()[:200])
        self.assertTrue(
            "ADVANCED_HypervisorDebug" in cpuid_case,
            "the CPUID case no longer names a hypervisor probe. Case: %s"
            % cpuid_case.strip()[:200])

        # ANTI-VACUITY: the REAL RDTSC case must still use TIMING_RDTSC, which proves this
        # test discriminates between the two cases rather than passing because the string
        # vanished from the file entirely.
        rdtsc_case = self._case_body(code, "case Phantom::Disasm::Mnemonic::RDTSC:")
        self.assertIsNotNone(rdtsc_case, "the RDTSC case is gone")
        self.assertTrue(
            bool(re.search(r"TIMING_RDTSC(?![A-Za-z0-9_])", rdtsc_case)),
            "the genuine RDTSC case no longer reports exactly TIMING_RDTSC, so this test "
            "would pass for the wrong reason. Note TIMING_RDTSCP does NOT satisfy this - "
            "the boundary is deliberate, because an unbounded substring test let a mutation "
            "swap the enumerator undetected. Case: %s" % rdtsc_case.strip()[:200])




class MetamorphicResultVocabularyContractTests(unittest.TestCase):
    """Keeps the metamorphic result vocabulary honest about what it produces.

    Six declared members carry no producer, and one carries eleven producers and no
    consumer. Both states are documented at the declarations; these tests keep the
    documentation and the code from drifting apart in either direction.
    """

    _UNPRODUCED = ("successors", "predecessors", "structuralHash", "variantName",
                   "familyMatches")

    def test_the_unproduced_result_members_say_so_at_their_declarations(self):
        header = read_source(METAMORPHIC_DETECTOR_HPP_PATH)
        missing = [name for name in self._UNPRODUCED
                   if not re.search(r"(?<![A-Za-z0-9_])" + name + r"(?![A-Za-z0-9_])[^;]*;",
                                    header)]
        self.assertEqual([], missing, "declaration(s) vanished: %s" % missing)

        self.assertGreaterEqual(
            header.count("NOT POPULATED") + header.count("NOT PRODUCED"), 6,
            "the unproduced-member notes have been thinned out. A member that reads as a "
            "measurement while having no producer is the defect these notes exist to "
            "prevent - an empty familyMatches vector looks exactly like a file that "
            "matched no family.")

        # The name collision is the specific trap that made an earlier measurement wrong.
        self.assertTrue(
            "DO NOT CONFUSE THIS WITH" in header,
            "the warning that MetamorphicStatistics::familyMatches is a DIFFERENT and "
            "LIVE member is gone. Without it a module-scoped search for the name finds "
            "the counter's producer and reports the inert vector as live.")

    def test_the_error_vector_still_has_producers_and_no_consumer(self):
        """If a consumer appears the recorded gap is closed and the note must change."""
        body = strip_c_comments(read_source(METAMORPHIC_DETECTOR_CPP_PATH))
        producers = re.findall(r"result\.errors\.push_back\s*\(", body)
        self.assertGreaterEqual(
            len(producers), 11,
            "the metamorphic error vector lost producers (%d left, 11 measured). Each one "
            "records a distinct reason an analysis could not run; removing them makes a "
            "failed analysis even less distinguishable from a clean one."
            % len(producers))

        # A READ would be any use that is not one of those appends and not a .clear().
        reads = []
        for line in body.splitlines():
            stripped = line.strip()
            if "errors" not in stripped:
                continue
            if re.search(r"errors\.(?:push_back|clear)\s*\(", stripped):
                continue
            if re.search(r"(?<![A-Za-z0-9_])errors(?![A-Za-z0-9_])", stripped):
                reads.append(stripped[:70])
        if reads:
            self.fail(
                "something now reads the metamorphic error vector (%d site(s), e.g. %r). "
                "That is an IMPROVEMENT - it closes the diagnosability gap recorded at the "
                "declaration - but the note in metamorphic_polymorphicdetector.hpp still "
                "says the vector is never consumed. Update the note in the same change so "
                "the header stops understating what the module reports."
                % (len(reads), reads[0]))




class CloudPlaceholderCoverageContractTests(unittest.TestCase):
    """A file we could not read must say WHY, and must never be reported clean.

    A cloud placeholder whose content is not resident cannot be read by a service at all:
    a session-0 process cannot hydrate one, so the open returns
    ERROR_CLOUD_FILE_ACCESS_DENIED instead of fetching. In the 1.0.94 field run that
    applied to eicar.com and eicar_com.zip sitting on the user's Desktop inside OneDrive -
    a known-malicious file physically present and never examined.

    These tests pin the two properties that make that state honest rather than silent:
    the reason travels with the result, and it is counted apart from genuine faults.
    """

    def test_an_unreadable_file_carries_its_reason_and_is_never_clean(self):
        engine = strip_c_comments(read_source(SCAN_ENGINE_CPP_PATH))

        self.assertTrue(
            "result.errorCode = hashErr.win32;" in engine,
            "the hash failure path no longer records the error code. hashErr was already "
            "being collected and then discarded, which is why 271 field log lines said "
            "only 'Hash computation failed' with no path and no reason.")

        self.assertTrue(
            "IsContentNotLocalError(hashErr.win32)" in engine,
            "the engine no longer distinguishes a cloud placeholder from a genuine I/O "
            "fault, so both are reported at the same severity and a real fault is buried "
            "under routine ones.")

        # THE SAFE DIRECTION IS THE ONE THAT MUST NOT MOVE. Error means not examined; if
        # this ever became Clean, an unexaminable file would be reported safe.
        #
        # The window is anchored on the hash-failure statement itself rather than on an
        # enclosing function name: extract_c_function RAISES on a name it cannot find, so
        # a guessed name gives a test that fails against correct code instead of a
        # fallback.
        opening = engine.find("if (!HashUtils::ComputeFile(HashUtils::Algorithm::SHA256,")
        self.assertNotEqual(
            -1, opening,
            "the hash-failure statement moved or was reworded; this guard is stale and "
            "must be re-anchored rather than deleted")
        closing = engine.find("CheckCache", opening)
        self.assertNotEqual(-1, closing, "the cache lookup that bounds this region is gone")
        window = engine[opening:closing]

        self.assertFalse(
            "ScanVerdict::Clean" in window,
            "the hash-failure region can now yield Clean. A file whose content could not "
            "be read has not been examined and must never be reported clean - that is the "
            "false-negative-by-silence class this whole strand exists to prevent.")
        self.assertTrue(
            "ScanVerdict::Error" in window,
            "the hash-failure region no longer sets Error, so an unreadable file would "
            "fall through carrying whatever verdict was already in the result")

    def test_a_platform_constraint_is_not_counted_as_a_scan_fault(self):
        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))

        self.assertTrue(
            "IsContentNotLocalError(engineResult.errorCode)" in rtp,
            "the on-access Error case no longer separates a non-resident file from a "
            "genuine fault, so scanErrors again mixes a platform constraint with real "
            "faults and neither number can be read.")
        self.assertTrue(
            "m_stats.contentNotLocalNotExamined++;" in rtp,
            "the coverage counter is gone; an unexamined file becomes invisible again")

        # The failure policy must keep deciding the verdict. Special-casing placeholders
        # here would override an owner control silently.
        self.assertTrue(
            "m_config.failurePolicy == FailurePolicy::FAIL_CLOSED" in rtp,
            "the Error case no longer honours failurePolicy. Under FAIL_CLOSED an "
            "unverifiable file is meant to be denied; removing that is a policy change, "
            "not a bug fix.")

    def test_the_coverage_counter_is_plumbed_through_every_statistics_site(self):
        """A counter missing one site is a structural zero that always looks healthy."""
        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        header = strip_c_comments(read_source(REAL_TIME_PROTECTION_HPP_PATH))
        name = "contentNotLocalNotExamined"

        self.assertEqual(
            1, header.count("std::atomic<uint64_t> %s{ 0 };" % name),
            "the counter is not declared exactly once in RTPStatistics")
        for site, needle in (("increment", "m_stats.%s++;" % name),
                             ("report load", "m_stats.%s.load" % name),
                             ("format string", '"%s={} "' % name),
                             ("Reset()", "    %s = 0;" % name)):
            self.assertTrue(
                needle in rtp,
                "the %s site for %s is missing. Every counter in this struct needs all "
                "five: a counter that is incremented but never reset reports pre-reset "
                "values forever, and one that is never printed cannot be read at all."
                % (site, name))




class CloudHydrationRescanContractTests(unittest.TestCase):
    """A cloud file must be examined at the moment its content becomes local.

    A session-0 service cannot hydrate a Cloud Filter placeholder - the open returns
    ERROR_CLOUD_FILE_ACCESS_DENIED instead of fetching - so the access that TRIGGERS
    hydration cannot be examined from user mode. The driver closes that hole at
    IRP_MJ_CLEANUP, by which point whoever read the file has caused the fetch to complete
    and the bytes are resident.

    WHY CLEANUP AND NOT WRITE, measured from the altitudes: we are 385210 (FSFilter
    Activity Monitor) and cldflt is 180451 (FSFilter HSM), so we sit ABOVE the cloud
    filter and the write it performs to populate the file happens BELOW us, invisible to
    our IRP_MJ_WRITE callback.
    """

    @staticmethod
    def _cleanup_body():
        source = strip_c_comments(read_source(FILTER_REGISTRATION_C_PATH))
        return extract_c_function(source, "ShadowStrikePreCleanup")

    def test_the_hydration_rescan_is_not_gated_on_an_unsettable_control(self):
        body = self._cleanup_body()
        self.assertIsNotNone(body, "ShadowStrikePreCleanup is gone")

        call = body.find("ShadowStrikeStreamContentBecameLocal(")
        self.assertNotEqual(
            -1, call,
            "the cleanup callback no longer asks whether a placeholder's content became "
            "local, so a cloud file that was unexaminable at open is never re-examined")

        # The cloud reason must be reachable without Config.ScanOnWrite. That field
        # defaults to FALSE and its only writers are policy messages user mode never
        # sends, so anything behind it has never executed in production.
        # Take the condition of the if-statement that ENCLOSES the call: scan back to
        # the nearest opening if and read forward from there.
        #
        # AN EARLIER DRAFT OF THIS TEST DID NOT WORK. It searched forward FROM the
        # ScanOnWrite token looking for an opening if, which can never match, because
        # the if precedes the token rather than following it. The mutation that puts
        # the hydration rescan behind that gate produced ZERO failures - the single
        # most important invariant in this change was unguarded.
        preceding = body[:call]
        gate_start = preceding.rfind("if (")
        self.assertNotEqual(
            -1, gate_start, "no enclosing if-statement found; this guard is stale")
        condition = preceding[gate_start:]
        self.assertNotIn(
            "Config.ScanOnWrite", condition,
            "the hydration rescan now sits behind a Config.ScanOnWrite test. That "
            "control defaults to FALSE and nothing in the product can set it, so gating "
            "this on it puts a known coverage hole back behind an unsettable switch. "
            "Enclosing condition: %s" % condition.strip()[:160])

        # ANTI-VACUITY: the OTHER reason must still be gated, or this test would pass
        # simply because the gate was deleted wholesale.
        self.assertIn(
            "g_DriverData.Config.ScanOnWrite", body,
            "the modified-or-unscanned rescan reason lost its ScanOnWrite gate. Nothing "
            "sets streamContext->Scanned to TRUE, so an ungated reason 2 would rescan "
            "EVERY file at EVERY close.")

    def test_the_hydration_probe_is_cheap_before_it_is_thorough(self):
        source = strip_c_comments(read_source(FILTER_REGISTRATION_C_PATH))
        helper = extract_c_function(source, "ShadowStrikeStreamContentBecameLocal")
        self.assertIsNotNone(helper, "the hydration probe is gone")

        attr_test = helper.find("StreamContext->FileAttributes")
        query = helper.find("FltQueryInformationFile")
        irql = helper.find("KeGetCurrentIrql")
        for label, offset in (("create-time attribute test", attr_test),
                              ("IRQL guard", irql),
                              ("attribute query", query)):
            self.assertNotEqual(-1, offset, "the %s is missing from the probe" % label)

        self.assertLess(
            attr_test, query,
            "the probe queries the file system before checking the attributes recorded at "
            "create. Almost every file on the machine was never a placeholder, so the "
            "cheap field test must come first or every handle close pays for a query.")
        self.assertLess(
            irql, query,
            "FltQueryInformationFile is a PASSIVE_LEVEL interface and the IRQL test no "
            "longer precedes it. Cleanup can be reached at APC_LEVEL.")

    def test_offline_is_not_treated_as_content_not_being_local(self):
        source = read_source(FILTER_REGISTRATION_C_PATH)
        mask_start = source.find("#define SHADOWSTRIKE_CONTENT_NOT_LOCAL_ATTRIBUTES")
        self.assertNotEqual(-1, mask_start, "the recall mask is gone")
        mask = source[mask_start:mask_start + 260]

        for attribute in ("FILE_ATTRIBUTE_RECALL_ON_OPEN",
                          "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS"):
            self.assertIn(attribute, mask,
                          "%s is no longer treated as content-not-resident" % attribute)

        self.assertNotIn(
            "FILE_ATTRIBUTE_OFFLINE", mask,
            "FILE_ATTRIBUTE_OFFLINE is back in the recall mask. Legacy "
            "hierarchical-storage and some backup products set it on files whose content "
            "IS resident, so including it queues rescans for files that were never "
            "placeholders - and it would disagree with the user-mode locality probe, "
            "which excludes it for the same reason.")

    def test_the_stream_context_is_still_released_exactly_once(self):
        """Opening the outer gate widened how often the context is fetched."""
        body = self._cleanup_body()
        self.assertIsNotNone(body, "ShadowStrikePreCleanup is gone")
        self.assertEqual(
            1, body.count("FltGetStreamContext("),
            "the cleanup callback acquires the stream context more than once")
        self.assertEqual(
            1, body.count("FltReleaseContext(streamContext)"),
            "the stream context is no longer released exactly once. This callback now "
            "fetches a context on EVERY cleanup rather than only when ScanOnWrite is "
            "enabled, so a leaked reference here leaks per handle close.")


class BehaviourChainEscalationContractTests(unittest.TestCase):
    """A behaviour-chain escalation is inference, so it may not terminate by itself.

    WHY THIS IS A SOURCE CONTRACT AND NOT A BEHAVIOURAL TEST: reaching the escalation
    needs a stream of scored kernel behavioural events against a live pid, which needs a
    loaded driver. No unit test can drive it, so the invariant that CAN be enforced is
    the shape of the decision.

    WHAT WENT WRONG, so a future reader does not undo it: this block upgraded ANY action
    to TerminateProcess the instant the decayed composite score reached the threshold,
    with no protection-mode gate and no evidence-class check, and the terminator takes
    the whole process TREE. On the first boot of 1.0.95 it killed 37 processes in 26
    seconds during logon under rule=CHAIN_ESCALATION and the session never reached a
    desktop. The events only began arriving because e5be3e01 gave the kernel behavioural
    alert a real payload, so shipping that fix armed a response nobody had calibrated.
    """

    @staticmethod
    def _slice_body(code, needle):
        """Brace-match the body of the definition introduced by `needle`.

        The needle MUST carry the return-type prefix, not just the name: a call site can
        precede its own definition in the file, and a name-only search would then slice a
        call and the test would assert against the wrong text.
        """
        assert code.count(needle) == 1, (
            "expected exactly one definition matching %r, found %d"
            % (needle, code.count(needle)))
        start = code.index(needle)
        brace = code.index("{", start)
        depth = 0
        for i in range(brace, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[brace:i + 1]
        raise AssertionError("unterminated UpdateBehaviorChain body")

    def test_chain_escalation_cannot_terminate_without_policy_permission(self):
        code = strip_c_comments(read_source(BEHAVIOR_BLOCKER_CPP_PATH))
        body = self._slice_body(code, "BlockAction UpdateBehaviorChain(")

        sets = [m.start() for m in re.finditer(
            r"escalated\s*=\s*BlockAction::TerminateProcess\s*;", body)]
        self.assertEqual(
            1, len(sets),
            "expected exactly ONE place where the escalation promotes the action to "
            "TerminateProcess, found %d. Every such promotion must sit behind the "
            "policy gate, so a second one is either an ungated path or a duplicate."
            % len(sets))

        # Read the condition of the if-statement that ENCLOSES the promotion: scan back
        # to the nearest opening if and forward from there. Do NOT search forward from
        # the promotion for a gate - the gate precedes it, so that can never match and
        # the test would pass while the promotion sat outside any gate at all.
        preceding = body[:sets[0]]
        gate_start = preceding.rfind("if (")
        self.assertNotEqual(
            -1, gate_start,
            "the action promotion is not inside any if-statement; this guard is stale")
        condition = preceding[gate_start:]
        self.assertTrue(
            "allowChainEscalationTermination" in condition,
            "the escalation promotes an action to TerminateProcess without consulting "
            "allowChainEscalationTermination. That makes an inference-class score kill "
            "a process tree with no policy gate, which took a logon session down on "
            "1.0.95. Enclosing condition: %s" % condition.strip()[:200])

    def test_the_escalation_permission_defaults_to_withholding_the_kill(self):
        hpp = strip_c_comments(read_source(BEHAVIOR_BLOCKER_HPP_PATH))
        decls = re.findall(
            r"bool\s+allowChainEscalationTermination\s*\{\s*(\w+)\s*\}", hpp)
        self.assertEqual(
            1, len(decls),
            "expected exactly one declaration of allowChainEscalationTermination, "
            "found %d" % len(decls))
        self.assertEqual(
            "false", decls[0],
            "allowChainEscalationTermination defaults to %r. It MUST default to false: "
            "a default that permits an inference-class termination is the defect this "
            "guard exists to prevent, and a default is invisible to any search for an "
            "assignment." % decls[0])

    def test_the_single_aggressiveness_control_governs_the_escalation(self):
        rtp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        sites = [m for m in re.finditer(
            r"bbConfig\.allowChainEscalationTermination\s*=([^;]*);", rtp, re.S)]
        self.assertEqual(
            1, len(sites),
            "expected exactly one place where RealTimeProtection sets the escalation "
            "permission, found %d" % len(sites))
        expr = sites[0].group(1)
        self.assertTrue(
            "ProtectionMode::BLOCK_SUSPICIOUS" in expr and ">=" in expr,
            "the escalation permission is not derived from the protection mode with a "
            ">= BLOCK_SUSPICIOUS test. The product has ONE aggressiveness control and "
            "inference-class enforcement must honour it, exactly as the file-scan and "
            "process-creation verdict paths already do. Expression: %s"
            % " ".join(expr.split())[:200])

    def test_the_withheld_counter_cannot_become_a_structural_zero(self):
        cpp = strip_c_comments(read_source(BEHAVIOR_BLOCKER_CPP_PATH))
        hpp = strip_c_comments(read_source(BEHAVIOR_BLOCKER_HPP_PATH))
        name = "chainEscalationTerminationsWithheld"
        required = {
            "public stats field (hpp)": ("uint64_t %s" % name) in hpp,
            "atomic declaration": ("std::atomic<uint64_t> %s" % name) in cpp,
            "Reset() store": ("%s.store(" % name) in cpp,
            "snapshot load": ("%s.load(" % name) in cpp,
            "ToJson key": ('j["%s"]' % name) in cpp,
            "increment": ("%s.fetch_add(" % name) in cpp,
        }
        missing = sorted(k for k, v in required.items() if not v)
        self.assertEqual(
            [], missing,
            "the withheld-escalation counter is not plumbed through every site, so it "
            "would read zero regardless of what happened - the same always-healthy "
            "number as pool=0/0 and pendingScanQueue. Missing: %s" % missing)

    def test_a_rule_authored_termination_is_still_reachable(self):
        # ANTI-VACUITY. The fix must withhold the INFERENCE upgrade without disabling
        # enforcement generally: a rule that names TerminateProcess is a deliberate,
        # authored decision and must still be carried out. If this fails, the change
        # went too far and removed capability rather than gating an inference.
        # SCOPED TO THE ENFORCEMENT FUNCTION, and that scoping is the whole point.
        # An earlier version of this test searched the WHOLE FILE for
        # "case BlockAction::TerminateProcess:" and therefore could not discriminate:
        # that literal appears TWICE, once in a helper switch near the top of the file
        # and once in HandleBlockAction. Deleting the enforcement case left the decoy
        # behind and the test still passed, which the mutation proof caught.
        cpp = strip_c_comments(read_source(BEHAVIOR_BLOCKER_CPP_PATH))
        body = self._slice_body(cpp, "bool HandleBlockAction(")
        self.assertTrue(
            "case BlockAction::TerminateProcess:" in body,
            "HandleBlockAction no longer handles TerminateProcess at all - rule-authored "
            "terminations have been removed, which is a loss of enforcement rather than "
            "a policy gate on inference")
        self.assertTrue(
            "TerminateProcessInternal(behavior.processId)" in body,
            "the TerminateProcess case in HandleBlockAction no longer performs a "
            "termination")


class TokenIntegrityQueryContractTests(unittest.TestCase):
    """The integrity-level query must not free a value it does not own.

    THE BUGCHECK THIS PREVENTS, measured from 083026-7031-01.dmp:

        BAD_POOL_CALLER (c2), Arg1=0x99 "free pool with invalid address"
        Arg2=0x0000000000004000                      <- the address being freed
        nt!ExFreePoolWithTag
        PhantomSensor!HppGetProcessIntegrityLevel     <- HandleProtection.c:2476
        PhantomSensor!HppCreateProcessContext
        PhantomSensor!HpRecordDuplication
        PhantomSensor!ShadowStrikeProcessPreCallback
        nt!ObpCallPreOperationCallbacks
        nt!NtDuplicateObject                          <- from csrss.exe

    0x4000 is not a pointer. It is SECURITY_MANDATORY_SYSTEM_RID exactly
    (winnt.h: 0x00004000L), and csrss.exe runs at SYSTEM integrity. So the
    out-parameter of SeQueryInformationToken(..., TokenIntegrityLevel, &p) had
    received the integrity RID as a SCALAR, and the code freed it as a pool
    pointer. Three modules did this; the driver already contained two correct
    implementations using the documented two-call ZwQueryInformationToken path.
    """

    _BROKEN = re.compile(
        r"SeQueryInformationToken\s*\(\s*[^;]*?TokenIntegrityLevel", re.S)

    def test_no_driver_source_queries_the_integrity_level_through_the_pool_returning_api(self):
        # Comments are stripped FIRST and that is load-bearing: the fix's own
        # explanatory comments necessarily quote the defective call, so a
        # comment-blind scan is guaranteed to report offenders that do not exist.
        offenders = []
        for path in sorted(SENSOR_SOURCE_ROOT.rglob("*.c")):
            code = strip_c_comments(read_source(path))
            hits = len(self._BROKEN.findall(code))
            if hits:
                offenders.append("%s x%d" % (path.name, hits))
        self.assertEqual(
            [], offenders,
            "these driver sources query TokenIntegrityLevel through "
            "SeQueryInformationToken. That out-parameter receives the integrity RID as "
            "a scalar, so dereferencing it is an access violation and freeing it is a "
            "BAD_POOL_CALLER bugcheck. Use ShadowStrikeGetTokenIntegrityRid. "
            "Offenders: %s" % offenders)

    def test_the_shared_primitive_owns_the_buffer_it_frees(self):
        # ANTI-VACUITY plus correctness: the replacement is only safe because the
        # driver allocates the buffer itself. If it ever goes back to having the
        # callee hand us a pointer, the whole defect returns.
        code = strip_c_comments(read_source(PROCESS_UTILS_C_PATH))
        needle = "ShadowStrikeGetTokenIntegrityRid("
        self.assertIn(
            needle, code,
            "the shared integrity primitive is gone; the three call sites depend on it")
        # ProcessUtils.c defines the primitive and does not call it, so the single
        # occurrence is the definition. Asserted rather than assumed.
        self.assertEqual(
            1, code.count(needle),
            "expected exactly one occurrence of the primitive in ProcessUtils.c "
            "(its definition), found %d" % code.count(needle))
        start = code.index(needle)
        brace = code.index("{", start)
        depth = 0
        body = None
        for i in range(brace, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    body = code[brace:i + 1]
                    break
        self.assertIsNotNone(body, "could not brace-match the primitive's body")

        required = {
            "opens a token handle": "ObOpenObjectByPointer" in body,
            "two-call size probe": "STATUS_BUFFER_TOO_SMALL" in body,
            "driver-owned allocation": "ShadowStrikeAllocatePagedWithTag" in body,
            "tagged free": "ShadowStrikeFreePoolWithTag" in body,
            "validates the SID": "RtlValidSid" in body,
            "closes the handle": "ZwClose" in body,
        }
        missing = sorted(k for k, v in required.items() if not v)
        self.assertEqual([], missing, "the primitive lost: %s" % missing)

        self.assertNotIn(
            "SeQueryInformationToken", body,
            "the shared primitive itself now uses the API that caused the bugcheck")

    def test_every_converted_site_uses_the_shared_primitive(self):
        # A regression guard, not a discriminator: it fails if a future edit removes
        # the call rather than if the defect returns.
        expected = ("HandleProtection.c", "PrivilegeMonitor.c", "ProcessAnalyzer.c")
        found = {}
        for name in expected:
            matches = list(SENSOR_SOURCE_ROOT.rglob(name))
            self.assertTrue(matches, "%s not found under the driver tree" % name)
            code = strip_c_comments(read_source(matches[0]))
            found[name] = len(re.findall(
                r"ShadowStrikeGetTokenIntegrityRid\s*\(", code))
        absent = sorted(n for n, c in found.items() if c == 0)
        self.assertEqual(
            [], absent,
            "these modules no longer resolve the integrity RID through the shared "
            "primitive: %s (counts: %s)" % (absent, found))

    def test_the_primitive_is_declared_for_its_callers(self):
        header = strip_c_comments(read_source(PROCESS_UTILS_H_PATH))

        # WORD-BOUNDARY MATCH, and it is not pedantry. An earlier version of this test
        # used a bare substring check, and the mutation that renames the declaration to
        # ShadowStrikeGetTokenIntegrityRidRemoved PASSED - because the longer name
        # contains the shorter one. Three of four mutations discriminated and this one
        # did not, which is the only reason the defect was found.
        #
        # assertIn is also avoided deliberately: it dumps the entire header on failure.
        declared = re.search(
            r"(?<![A-Za-z0-9_])ShadowStrikeGetTokenIntegrityRid(?![A-Za-z0-9_])", header)
        self.assertIsNotNone(
            declared,
            "ShadowStrikeGetTokenIntegrityRid is not declared in ProcessUtils.h, so the "
            "three modules that resolve an integrity RID cannot reach it")
        self.assertTrue(
            "PASSIVE_LEVEL" in header,
            "ProcessUtils.h no longer states an IRQL requirement anywhere. The primitive "
            "opens a handle and issues a Zw query, so a caller at raised IRQL would "
            "bugcheck, and the declaration is where that contract is published.")


class BehaviouralAlertStormContractTests(unittest.TestCase):
    """The 1.0.97 field failure: the product generated the events it reacted to.

    The kernel ETW consumer forwarded a behavioural alert for every event with
    Priority <= Normal, including events belonging to the scanner service
    itself. Each alert cost three user-mode WARN lines, and a log write is file
    I/O that re-enters our own minifilter and produces further ETW events, on
    the two threads that owe the kernel a scan verdict. Measured: 51,437 alerts
    and 27.7 MB of log in 4m02s, 19,825 of them naming our own pid.

    Every assertion below is made against COMMENT-STRIPPED source, because the
    comments written for this fix necessarily name every symbol being asserted -
    a comment-blind check would be satisfied by prose alone.
    """

    @staticmethod
    def _slice_definition(code, needle):
        """Brace-match a definition located by a return-type-prefixed needle.

        The needle must carry the return type. UpdateBehaviorChain in
        particular is CALLED earlier in its own file than it is defined, so a
        bare-name search would slice a call site instead.
        """
        start = code.find(needle)
        if start < 0:
            return None
        brace = code.find("{", start)
        if brace < 0:
            return None
        depth = 0
        for i in range(brace, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:i + 1]
        return None

    def test_the_etw_producer_does_not_report_the_scanner_to_itself(self):
        code = strip_c_comments(read_source(DRIVER_ENTRY_C_PATH))
        body = extract_c_function(code, "ShadowStrikeEtwEventCallback")
        self.assertIsNotNone(body, "ShadowStrikeEtwEventCallback not found")

        send = body.find("ShadowStrikeBatchSendNotification")
        self.assertGreater(
            send, -1,
            "the ETW callback no longer forwards a behavioural alert at all; this "
            "guard is about WHICH events it forwards, not about removing the feed")

        guard = body.find("ShadowStrikeIsScannerProcess")
        self.assertGreater(
            guard, -1,
            "ShadowStrikeEtwEventCallback does not consult ShadowStrikeIsScannerProcess, "
            "so the scanner service's own activity is forwarded back to the scanner "
            "service as a behavioural alert. That closes a feedback loop: each alert "
            "produces log writes, each log write is file I/O through our own "
            "minifilter, and each of those produces more ETW events.")
        self.assertLess(
            guard, send,
            "the scanner-process check appears AFTER the forward in "
            "ShadowStrikeEtwEventCallback, so it cannot prevent one")

    def test_the_etw_producer_bounds_the_per_process_rate(self):
        code = strip_c_comments(read_source(DRIVER_ENTRY_C_PATH))
        body = extract_c_function(code, "ShadowStrikeEtwEventCallback")
        self.assertIsNotNone(body, "ShadowStrikeEtwEventCallback not found")

        send = body.find("ShadowStrikeBatchSendNotification")
        check = body.find("RtCheckProcessThrottle")
        self.assertGreater(
            check, -1,
            "the ETW callback does not consult RtCheckProcessThrottle. Without it an "
            "unbounded per-process event rate starves the threads that answer kernel "
            "scan requests, which blinds the scanner without needing an exploit.")
        self.assertLess(
            check, send,
            "the throttle check appears AFTER the forward, so it cannot prevent one")
        self.assertTrue(
            "RtResourceEventQueue" in body,
            "the ETW callback no longer names RtResourceEventQueue. It must not share "
            "RtResourceCallbackRate, which ImageNotify.c already reports image-load "
            "volume into - one producer would exhaust the other's headroom.")
        self.assertTrue(
            "NT_SUCCESS(throttleStatus)" in body,
            "the suppression is no longer conditional on the throttle query having "
            "SUCCEEDED. A fault in a load-shedding mechanism must never be able to "
            "silence a detection feed, so this path fails OPEN by design.")

        self.assertTrue(
            "RtEnableResource(g_ResourceThrottler, RtResourceEventQueue, TRUE)" in code,
            "RtResourceEventQueue is never enabled, so the budget the callback "
            "consults does not exist and the check can never bind")

    def test_the_overflow_module_does_not_consume_a_behavioural_alert(self):
        code = strip_c_comments(read_source(BUFFER_OVERFLOW_PROTECTION_CPP_PATH))
        start = code.find('RegisterGenericHandler("BufferOverflowProtection"')
        self.assertGreater(
            start, -1,
            "BufferOverflowProtection no longer registers a generic handler at all")
        lam = code[start:start + 1500]

        offenders = re.findall(
            r"(?<![A-Za-z0-9_])FilterMessageType_BehavioralAlert(?![A-Za-z0-9_])", lam)
        self.assertEqual(
            offenders, [],
            "BufferOverflowProtection accepts FilterMessageType_BehavioralAlert again. "
            "It has no parser for that payload: HandleKernelMemoryAlert reads "
            "[uint32 pid][uint32 exceptionCode][uint64 addr] while "
            "SHADOWSTRIKE_BEHAVIORAL_ALERT is [ProcessId][ParentProcessId][ThreadId], "
            "so exceptionCode is read out of ParentProcessId - which the driver "
            "hardcodes to 0. Every alert then classifies as OverflowType::Unknown and "
            "logs 'Exploit detected'. 51,437 of those were measured in 4m02s.")

        self.assertTrue(
            "FilterMessageType_MemoryAlert" in lam,
            "BufferOverflowProtection no longer accepts FilterMessageType_MemoryAlert, "
            "which is the only type it can parse. Removing it would delete the "
            "module's kernel feed rather than correct it.")

    def test_an_exception_analysis_refuses_a_zero_exception_code(self):
        code = strip_c_comments(read_source(BUFFER_OVERFLOW_PROTECTION_CPP_PATH))
        body = self._slice_definition(code, "void HandleKernelMemoryAlert(")
        self.assertIsNotNone(body, "HandleKernelMemoryAlert definition not found")

        # The zero must be a COMPLETE token. An earlier version of this
        # assertion used ==\\s*0 with no trailing boundary, and a mutation
        # changing the comparison to == 0xFFFFFFFFul still satisfied it because
        # the pattern matched the leading 0 of the hex literal. The guard was
        # undiscriminating on the one invariant it exists to protect.
        self.assertTrue(
            re.search(r"ctx\.exceptionCode\s*==\s*0(?![A-Za-z0-9_])", body) is not None,
            "HandleKernelMemoryAlert no longer refuses a zero exception code. Zero is "
            "not an NTSTATUS exception value, so the only verdict reachable from it is "
            "OverflowType::Unknown - a fabricated finding rather than an absent one. "
            "This guard is deliberately independent of the message-type filter: the "
            "storm arrived through the wrong type, but it became a DETECTION because "
            "this function was willing to classify a zero code.")

    def test_the_correlation_chain_has_a_count_ceiling(self):
        code = strip_c_comments(read_source(BEHAVIOR_BLOCKER_CPP_PATH))

        m = re.search(r"kMaxChainEvents\s*=\s*(\d+)", code)
        self.assertIsNotNone(
            m,
            "kMaxChainEvents is gone, so a correlation chain is bounded only by time. "
            "At the field event rate that reached ~20,000 entries for one pid, each "
            "holding a std::string, across 156 live pids.")
        ceiling = int(m.group(1))

        body = self._slice_definition(code, "BlockAction UpdateBehaviorChain(")
        self.assertIsNotNone(body, "UpdateBehaviorChain definition not found")
        self.assertTrue(
            "kMaxChainEvents" in body,
            "UpdateBehaviorChain does not apply kMaxChainEvents, so the ceiling is "
            "declared and never enforced")

        # The ceiling must not be able to suppress an escalation that would
        # otherwise fire. Worst case is every retained event at the lowest
        # non-zero risk and aged the full window.
        worst = ceiling * 0.15 * math.exp(-0.01 * 300.0)
        self.assertGreater(
            worst, 0.70,
            "a full chain at the lowest non-zero risk and maximum age now scores "
            "%.3f, which is at or below the 0.70 escalation threshold. The count "
            "ceiling has become a calibration change: it can now suppress an "
            "escalation that would previously have fired." % worst)

    def test_the_escalation_notice_is_rate_limited(self):
        code = strip_c_comments(read_source(BEHAVIOR_BLOCKER_CPP_PATH))
        self.assertTrue(
            "kEscalationLogIntervalMs" in code,
            "kEscalationLogIntervalMs is gone, so the chain-escalation notice is "
            "emitted once per event again. That line was one third of a 27.7 MB log "
            "storm, and our log writes traverse our own minifilter.")

        body = self._slice_definition(code, "BlockAction UpdateBehaviorChain(")
        self.assertIsNotNone(body, "UpdateBehaviorChain definition not found")

        unguarded = []
        for m in re.finditer(r"SS_LOG_WARN", body):
            # Scan BACKWARD: the interval test necessarily precedes the emission.
            if "kEscalationLogIntervalMs" not in body[:m.start()]:
                unguarded.append(body[:m.start()].count("\n") + 1)
        self.assertEqual(
            unguarded, [],
            "SS_LOG_WARN is reached in UpdateBehaviorChain without any preceding "
            "kEscalationLogIntervalMs test, at body line(s) %s" % unguarded)

        self.assertTrue(
            "m_escalationLogsSuppressed" in body,
            "the suppressed-notice count is no longer carried, so occurrences "
            "between emitted lines are silently lost rather than summarised")

    def test_the_per_alert_kernel_line_is_not_a_warning(self):
        code = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        start = code.find("case FilterMessageType_BehavioralAlert:")
        self.assertGreater(
            start, -1, "the BehavioralAlert case is gone from the RTP dispatcher")
        nxt = code.find("case FilterMessageType_", start + 10)
        arm = code[start:nxt if nxt > 0 else start + 2500]

        offenders = [ln.strip()[:90] for ln in arm.split("\n")
                     if "Logger::Warn" in ln and "payload" in ln]
        self.assertEqual(
            offenders, [],
            "the per-alert kernel line is a WARN again: %s. It reports a payload BYTE "
            "COUNT and nothing else - no process, no behaviour, no verdict - and fired "
            "51,169 times in 4m02s as one third of a 27.7 MB log storm. The alert "
            "volume stays observable from the driver's forwarded/suppressed counters "
            "and from chainEscalationTerminationsWithheld." % offenders)


class FilterSendMessageContractTests(unittest.TestCase):
    """lpBytesReturned is _Out_, not _Out_opt_, and fltLib writes through it.

    FilterConnectionImpl::SendMessageNoReply passed nullptr for it, so every
    no-reply kernel send faulted inside FilterpDeviceIoControl with a
    NULL-pointer write and terminated the service. Proven from the 1.0.98 field
    dump:

        mov dword ptr [rcx],eax    rcx = 0x0000000000000000
        fltLib!FilterpDeviceIoControl+0x188
          <- FilterConnectionImpl::SendMessageNoReply+0x15f
          <- IPCManager::SendToKernel+0x34f
          <- PowerShellScanner::Impl::notifyKernelBlock+0xc4

    This guard is deliberately TREE-WIDE rather than pinned to the one site
    that was wrong, because the defect is a misreading of an API contract and
    the next author can make it at any of the other call sites.
    """

    _SRC_ROOT = ROOT / "src"

    @staticmethod
    def _blank_string_literals(code):
        """Replace the contents of string literals with spaces.

        strip_c_comments does not touch strings, and this file logs
        "FilterSendMessage (no reply) failed", so a walk over comment-stripped
        source alone finds a call site inside a log message. Length is preserved
        so reported line numbers stay accurate.
        """
        out = []
        i = 0
        n = len(code)
        while i < n:
            ch = code[i]
            if ch == '"':
                out.append('"')
                i += 1
                while i < n and code[i] != '"':
                    if code[i] == "\\\\" and i + 1 < n:
                        out.append("  ")
                        i += 2
                        continue
                    out.append("\\n" if code[i] == "\\n" else " ")
                    i += 1
                if i < n:
                    out.append('"')
                    i += 1
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    @classmethod
    def _call_sites(cls):
        """Yield (path, line, arglist) for every FilterSendMessage call in src."""
        sites = []
        for path in sorted(cls._SRC_ROOT.rglob("*.cpp")):
            code = cls._blank_string_literals(strip_c_comments(read_source(path)))
            for m in re.finditer(r"(?<![A-Za-z0-9_])FilterSendMessage\s*\(", code):
                depth = 0
                end = None
                for j in range(m.end() - 1, min(m.end() + 2000, len(code))):
                    if code[j] == "(":
                        depth += 1
                    elif code[j] == ")":
                        depth -= 1
                        if depth == 0:
                            end = j
                            break
                if end is None:
                    continue
                inner = code[code.find("(", m.start()) + 1:end]
                args = [a.strip() for a in re.split(r",(?![^(]*\))", inner)]
                sites.append((path.name, code[:m.start()].count("\n") + 1, args))
        return sites

    def test_no_kernel_send_passes_a_null_bytes_returned(self):
        sites = self._call_sites()
        self.assertGreater(
            len(sites), 0,
            "no FilterSendMessage call sites were found at all, so this guard is "
            "vacuous - the walk or the source layout has changed")

        offenders = []
        for name, line, args in sites:
            if len(args) != 6:
                offenders.append("%s:%d takes %d arguments, not 6" % (name, line, len(args)))
                continue
            if args[5] in ("nullptr", "NULL", "0"):
                offenders.append("%s:%d passes %s as lpBytesReturned" % (name, line, args[5]))

        self.assertEqual(
            offenders, [],
            "FilterSendMessage is called with a null lpBytesReturned. That "
            "parameter is _Out_, not _Out_opt_, and fltLib writes the byte count "
            "through it unconditionally, so this terminates the process rather "
            "than failing the call: %s" % offenders)

    def test_the_no_reply_sender_keeps_its_shape(self):
        """Pin SendMessageNoReply's own argument shape.

        An earlier version of this test asserted only that SOME call site passes
        a null output buffer together with a real count. That was circular: the
        very site being fixed satisfies it, so the assertion could never fail
        while the fix was in place and it discriminated nothing. Mutating the two
        FileSystemFilter sites produced zero failures, which is how the tautology
        surfaced.

        What is actually worth pinning is this sender's shape: no output buffer,
        zero output size, real count. That fails if someone "fixes" the crash by
        supplying an output buffer instead - which would silently turn a
        fire-and-forget send into one that waits for a reply the driver does not
        send on this path.
        """
        code = self._blank_string_literals(
            strip_c_comments(read_source(FILTER_CONNECTION_CPP_PATH)))
        start = code.find("bool SendMessageNoReply(")
        self.assertGreater(
            start, -1, "SendMessageNoReply definition not found")

        m = re.search(r"(?<![A-Za-z0-9_])FilterSendMessage\s*\(", code[start:])
        self.assertIsNotNone(
            m, "SendMessageNoReply no longer calls FilterSendMessage")

        abs_open = start + m.end() - 1
        depth = 0
        end = None
        for j in range(abs_open, min(abs_open + 2000, len(code))):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        self.assertIsNotNone(end, "could not brace-match the call")
        args = [a.strip() for a in re.split(r",(?![^(]*\))", code[abs_open + 1:end])]

        self.assertEqual(len(args), 6, "FilterSendMessage arity changed: %s" % args)
        self.assertIn(
            args[3], ("nullptr", "NULL"),
            "the no-reply sender now passes an OUTPUT BUFFER (%s). This path is "
            "fire-and-forget and the driver sends no reply on it, so supplying a "
            "buffer would make the caller wait for something that never "
            "arrives." % args[3])
        self.assertEqual(
            args[4], "0",
            "the no-reply sender declares a non-zero output size (%s) while "
            "passing no buffer" % args[4])
        self.assertNotIn(
            args[5], ("nullptr", "NULL", "0"),
            "lpBytesReturned is null again, which terminates the process")


class KernelConfigPublisherContractTests(unittest.TestCase):
    """Kernel-side configuration must survive a channel that comes up late.

    THE DEFECT. Three modules push configuration the driver needs for the whole
    session - RegistryProtection's protected key list, FileProtection's protected
    path set, SelfDefense's protected process registration. All three push it
    from their own Initialize, on the boot-init thread, which runs before
    IPCManager::Start and therefore before ConnectFilterPort establishes the
    encrypted channel. Every push was refused and lost, so on EVERY BOOT the
    kernel held none of that configuration, silently, for the whole session.

    Measured in the 1.0.99 field log: messageType=23 size=1796 (registry keys),
    messageType=23 size=136 (protected paths) and messageType=26 size=48
    (protected processes), all three stamped on the boot-init thread with
    everConnected=no, and the channel establishing 1.96 s later.

    These tests are source contracts because reaching the defect at runtime needs
    a loaded driver and a live filter port, which no unit test has.
    """

    @classmethod
    def setUpClass(cls):
        cls.ipc_cpp = strip_c_comments(read_source(IPC_MANAGER_CPP_PATH))
        cls.ipc_hpp = strip_c_comments(read_source(IPC_MANAGER_HPP_PATH))
        cls.svc_cpp = strip_c_comments(read_source(ANTIVIRUS_SERVICE_CPP_PATH))

    # -- helpers ------------------------------------------------------------
    def _definition_body(self, code, needle):
        """Slice a function body anchored on its RETURN-TYPE-PREFIXED header.

        Anchoring on the bare name is unsound here: ConnectFilterPort is CALLED
        at four sites, one of which precedes its definition, so a first-occurrence
        match would slice a call.
        """
        self.assertEqual(
            code.count(needle), 1,
            "expected exactly one definition matching %r, found %d"
            % (needle, code.count(needle)))
        start = code.index(needle)
        depth = 0
        i = code.index("{", start)
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:i + 1]
            i += 1
        self.fail("unterminated body for %r" % needle)

    def _call_args(self, code, callee):
        """Every call to `callee`, sliced by parenthesis matching."""
        out = []
        idx = 0
        token = callee + "("
        while True:
            k = code.find(token, idx)
            if k < 0:
                return out
            i = k + len(token)
            depth = 1
            while i < len(code) and depth:
                if code[i] == "(":
                    depth += 1
                elif code[i] == ")":
                    depth -= 1
                i += 1
            out.append(code[k:i])
            idx = i

    # -- the mechanism exists and shares the one subscription implementation --
    def test_the_publisher_registry_exists_and_reuses_the_shared_semantics(self):
        for sym in ("RegisterKernelConfigPublisher",
                    "UnregisterKernelConfigPublisher",
                    "KernelConfigPublisherCount"):
            self.assertTrue(
                sym in self.ipc_hpp,
                "%s is not declared; the publisher API is incomplete" % sym)
            self.assertTrue(
                sym in self.ipc_cpp,
                "%s is not defined" % sym)

        reg = self._definition_body(
            self.ipc_cpp, "void IPCManager::RegisterKernelConfigPublisher(")
        self.assertTrue(
            "UpsertNamedSubscriber(m_kernelConfigPublishers" in reg,
            "registration must route through UpsertNamedSubscriber so the "
            "empty-name refusal and same-name-replaces rules have exactly one "
            "implementation rather than a private copy")

        unreg = self._definition_body(
            self.ipc_cpp, "void IPCManager::UnregisterKernelConfigPublisher(")
        self.assertTrue(
            "EraseNamedSubscriber(m_kernelConfigPublishers" in unreg,
            "removal must route through EraseNamedSubscriber so unregistering "
            "one publisher cannot clear the whole feed")

    # -- the wiring that makes it work ---------------------------------------
    def test_configuration_is_republished_when_the_channel_comes_up(self):
        body = self._definition_body(self.ipc_cpp, "bool IPCManager::ConnectFilterPort(")
        self.assertTrue(
            "PublishKernelConfiguration();" in body,
            "ConnectFilterPort does not republish kernel configuration, so the "
            "configuration refused during Initialize is never restored - and a "
            "reconnect leaves the kernel unconfigured too")

        # It must sit in the branch that ran because the channel IS up. Calling
        # it when the channel is down would send every publisher into the same
        # refusal that caused the defect.
        gate = body.find("if (encryptedChannelUp)")
        call = body.find("PublishKernelConfiguration();")
        self.assertNotEqual(gate, -1, "the encryptedChannelUp gate is gone")
        self.assertGreater(
            call, gate,
            "PublishKernelConfiguration must be inside the encryptedChannelUp "
            "branch; publishing while the channel is down reproduces the defect")
        opened = body.count("{", gate, call)
        closed = body.count("}", gate, call)
        self.assertGreater(
            opened, closed,
            "PublishKernelConfiguration is not nested inside the "
            "encryptedChannelUp branch (brace depth did not increase)")

    def test_the_self_defeating_startup_wait_is_not_reintroduced(self):
        # The wait could never help the senders it was written for: they run on
        # the same thread that later calls Start, so blocking postponed the very
        # connect it waited for. It also stalled one-shot block requests up to
        # 2000 ms against a 400 ms process fan-out budget.
        for banned in ("kStartupChannelWait",
                       "waited for the encrypted channel"):
            self.assertFalse(
                banned in self.ipc_cpp,
                "%r is back in SendToKernel; that wait postpones the connect it "
                "waits for and stalls one-shot responses" % banned)

        send = self._definition_body(self.ipc_cpp, "bool IPCManager::SendToKernel(")
        self.assertFalse(
            "sleep_for" in send,
            "SendToKernel sleeps again; a send that blocks on the kernel channel "
            "delays startup and the process-notify fan-out")

    def test_deferral_is_classified_by_the_enums_own_partition(self):
        send = self._definition_body(self.ipc_cpp, "bool IPCManager::SendToKernel(")
        for macro in ("SHADOWSTRIKE_VALID_MESSAGE_TYPE",
                      "SHADOWSTRIKE_IS_POLICY_MESSAGE",
                      "SHADOWSTRIKE_IS_DATA_PUSH_MESSAGE",
                      "SHADOWSTRIKE_IS_CONTROL_MESSAGE"):
            self.assertTrue(
                macro in send,
                "SendToKernel must classify a deferrable message with %s rather "
                "than a hand-picked list of type numbers; the enum partition is "
                "what keeps every invented 0x30-style constant out" % macro)

        # The two reply-bearing policy members must not be treated as
        # replayable: an answer nobody waits for any more is worthless.
        for query in ("FilterMessageType_QueryDriverStatus",
                      "FilterMessageType_ExclusionQuery"):
            self.assertTrue(
                query in send,
                "%s must be excluded from deferral by name - it is a query, not "
                "configuration" % query)

    # -- every publisher is wired, and none can be silently dropped ----------
    def test_all_three_configuration_owners_register_a_publisher(self):
        calls = self._call_args(self.svc_cpp, "ipc.RegisterKernelConfigPublisher")
        self.assertEqual(
            len(calls), 3,
            "expected exactly 3 kernel configuration publishers in "
            "AntivirusService.cpp, found %d - a module was added or dropped"
            % len(calls))

        expected = {
            "RegistryProtection": "SyncProtectedKeysToKernel",
            "FileProtection": "SyncProtectedPathsToKernel",
            "SelfDefense": "SyncProtectedProcessesToKernel",
        }
        seen = {}
        for call in calls:
            for name, sync in expected.items():
                if '"%s"' % name in call:
                    seen[name] = call

        missing = sorted(set(expected) - set(seen))
        self.assertEqual(
            missing, [],
            "these configuration owners have no publisher, so their kernel-side "
            "protection stays unconfigured: %s" % missing)

        for name, call in seen.items():
            self.assertTrue(
                expected[name] + "(" in call,
                "the '%s' publisher must call %s so it republishes CURRENT state "
                "rather than a stale snapshot" % (name, expected[name]))
            self.assertTrue(
                "IsInitialized()" in call,
                "the '%s' publisher must not ask an uninitialised module to "
                "publish" % name)

    def test_publishers_are_registered_after_the_ipc_manager_is_initialized(self):
        init = self.svc_cpp.find("Communication::IPCManager::Instance().Initialize()")
        first = self.svc_cpp.find("ipc.RegisterKernelConfigPublisher")
        self.assertNotEqual(init, -1, "IPCManager::Initialize call site not found")
        self.assertNotEqual(first, -1, "no publisher registration found")
        self.assertGreater(
            first, init,
            "publishers are registered before IPCManager::Initialize; register "
            "after it so registration cannot depend on construction order")


class ThreatCounterEvidenceClassContractTests(unittest.TestCase):
    """A detection counter must count detections, not message arrivals.

    THE DEFECT. RTPStatistics::threatsDetected was documented "unified across all
    detection methods" and five sites in OnKernelGenericEvent incremented it on
    the mere ARRIVAL of a kernel message - a named-pipe create, a file rollback,
    a kernel alert - with no analysis between the message and the count.

    Measured in the 1.0.99 field log: threats=34933 alongside infected=0
    suspicious=0 blocked=0, and one 5-second interval in which the counter
    advanced by 8,492 while scans advanced by ZERO. A detection counter that
    moves while nothing is scanned is not reporting detections.

    The counter is now three counters by evidence class: what this product
    convicted, what the kernel convicted, and non-detection telemetry.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.hpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_HPP_PATH))

    def _definition_body(self, code, needle):
        self.assertEqual(
            code.count(needle), 1,
            "expected exactly one definition matching %r, found %d"
            % (needle, code.count(needle)))
        start = code.index(needle)
        depth = 0
        i = code.index("{", start)
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:i + 1]
            i += 1
        self.fail("unterminated body for %r" % needle)

    def _case_slice(self, body, label):
        """Slice one switch case, label to next label. A character window would
        bleed into the neighbouring case."""
        start = body.find("case " + label + ":")
        self.assertNotEqual(start, -1, "case %s not found" % label)
        nxt = body.find("case FilterMessageType_", start + 1)
        return body[start:nxt if nxt != -1 else len(body)]

    def test_non_detection_kernel_events_do_not_count_as_threats(self):
        body = self._definition_body(self.cpp, "void OnKernelGenericEvent(")

        # Arrival of a kernel message is not a conviction by this product.
        for label, expected in (
            ("FilterMessageType_NamedPipeEvent", "kernelTelemetryEvents"),
            ("FilterMessageType_FileRollbackEvent", "kernelTelemetryEvents"),
            ("FilterMessageType_RansomwareAlert", "kernelThreatAlerts"),
            ("FilterMessageType_BehavioralAlert", "kernelThreatAlerts"),
            ("FilterMessageType_SelfProtectAlert", "kernelThreatAlerts"),
        ):
            case = self._case_slice(body, label)
            self.assertFalse(
                "m_stats.threatsDetected++" in case,
                "%s increments threatsDetected again; arrival of a kernel "
                "message is not a detection by this product" % label)
            self.assertTrue(
                "m_stats." + expected + "++" in case,
                "%s must be counted in %s, otherwise the event becomes "
                "invisible instead of merely reclassified" % (label, expected))

    def test_the_generic_feed_keeps_exactly_one_real_detection_site(self):
        # The suspicious-IOCTL case IS a detection and must keep counting. Pinning
        # it at exactly one stops an arrival site creeping back in disguised as a
        # detection, while leaving genuine detection sites elsewhere untouched.
        body = self._definition_body(self.cpp, "void OnKernelGenericEvent(")
        n = body.count("m_stats.threatsDetected++")
        self.assertEqual(
            n, 1,
            "OnKernelGenericEvent has %d threatsDetected increments, expected "
            "exactly 1 (the suspicious IOCTL detection)" % n)

    def test_all_three_counters_survive_a_reset(self):
        body = self._definition_body(self.cpp, "void RTPStatistics::Reset()")
        for field in ("threatsDetected", "kernelThreatAlerts",
                      "kernelTelemetryEvents"):
            self.assertTrue(
                field + " = 0;" in body,
                "%s is not reset; a counter absent from Reset() keeps its "
                "pre-reset value and every rate computed afterwards is wrong "
                "in a way nothing reports" % field)
            self.assertTrue(
                "std::atomic<uint64_t> " + field in self.hpp,
                "%s is not declared as an atomic counter" % field)

    def test_the_periodic_report_publishes_every_class(self):
        # The whole point of splitting is that the field log names which class is
        # moving. A counter nobody reports is a counter nobody can act on.
        for token in ("threats={}", "kernelThreatAlerts={}", "kernelTelemetry={}"):
            self.assertTrue(
                token in self.cpp,
                "the on-access pipeline report does not publish %r, so the field "
                "log cannot say which evidence class is moving" % token)

        for arg in ("kThreats", "kTelemetry"):
            self.assertTrue(
                arg in self.cpp,
                "%s is never loaded, so its placeholder would be fed the wrong "
                "argument" % arg)

    def test_the_exported_document_no_longer_mislabels_a_field(self):
        self.assertFalse(
            'stats["threatsDetected"] = m_stats.infectedFiles.load();' in self.cpp,
            "the exported diagnostics publish infectedFiles under the "
            "threatsDetected key again, so the document contradicts both the "
            "field of that name and the periodic report")
        self.assertTrue(
            'stats["threatsDetected"] = m_stats.threatsDetected.load();' in self.cpp,
            "the threatsDetected key must publish threatsDetected")


class SelfActivityNotFlaggedContractTests(unittest.TestCase):
    """The product must not report its own activity as an attack on itself.

    TWO MEASURED INSTANCES in the 1.0.99 field log.

    (1) All EIGHT "Suspicious handle operation" warnings named our own pid as the
        SOURCE, scores 110 and 135, PROCESS_ALL_ACCESS. This service opens such
        handles by design. The alert was also routed to ProcessProtection, which
        filters it against the protected-process set and can raise a blocked-access
        alert, so the product could accuse itself of attacking itself - and feeding
        our own activity into a suspicion score is how 1.0.95 terminated 37 process
        trees.

    (2) "High-risk signature on module in PID 2300: ShadowStrikePhantomTray.exe" -
        our own shipped binary, scored because its signing certificate is not
        trusted by the machine. The same branch BLOCKS at riskScore >= 90, so
        blocking our own tray's module load was latent.

    IsOwnInstalledBinary already existed and was applied on the file-scan path but
    not on image load; ProcessInjectionDetector already guarded the identical
    handle alert with m_selfPid. Both fixes apply a pattern the tree already had.
    """

    @classmethod
    def setUpClass(cls):
        cls.cpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_CPP_PATH))
        cls.hpp = strip_c_comments(read_source(REAL_TIME_PROTECTION_HPP_PATH))

    def _definition_body(self, code, needle):
        self.assertEqual(
            code.count(needle), 1,
            "expected exactly one definition matching %r, found %d"
            % (needle, code.count(needle)))
        start = code.index(needle)
        depth = 0
        i = code.index("{", start)
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:i + 1]
            i += 1
        self.fail("unterminated body for %r" % needle)

    def _brace_block_from(self, code, marker):
        """The braced block that opens at the first '{' at or after marker."""
        k = code.find(marker)
        self.assertNotEqual(k, -1, "marker %r not found" % marker)
        i = code.index("{", k)
        depth = 0
        j = i
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    return code[i:j + 1]
            j += 1
        self.fail("unterminated block after %r" % marker)

    def _handle_alert_case(self):
        body = self._definition_body(self.cpp, "void OnKernelGenericEvent(")
        start = body.find("case FilterMessageType_HandleAlert:")
        self.assertNotEqual(start, -1, "the HandleAlert case is gone")
        nxt = body.find("case FilterMessageType_", start + 1)
        return body[start:nxt if nxt != -1 else len(body)]

    def test_our_own_outbound_handle_work_is_not_reported_as_suspicious(self):
        case = self._handle_alert_case()
        self.assertTrue(
            "alert->SourceProcessId == OwnProcessId()" in case,
            "the HandleAlert case does not exempt alerts sourced from this "
            "process, so our own handle work is reported as suspicious again")
        self.assertTrue(
            "m_stats.ownHandleOperationsNotFlagged++" in case,
            "the exemption must be counted; a self-exemption nobody can see is "
            "how a de-noising guard becomes a blind spot")

    def test_the_exemption_is_source_only_so_self_protection_survives(self):
        # THE ASYMMETRY IS THE WHOLE POINT. An alert whose TARGET is us is another
        # process reaching into this one, which is exactly what ProcessProtection's
        # protected-process filter exists to act on. Exempting that direction would
        # delete self-protection rather than de-noise it.
        case = self._handle_alert_case()
        self.assertFalse(
            "TargetProcessId == OwnProcessId" in case,
            "the HandleAlert case now exempts alerts TARGETING this process; that "
            "removes self-protection instead of removing noise")
        self.assertTrue(
            "OnKernelHandleAlert(" in case,
            "the route to ProcessProtection was deleted; the inbound case must "
            "still reach the access filter")

    def test_our_own_binary_keeps_its_block_withheld_not_its_analysis(self):
        body = self._definition_body(
            self.cpp, "Communication::KernelVerdict OnKernelImageLoad(")
        self.assertTrue(
            "IsOwnInstalledBinary(imagePath)" in body,
            "the image-load path does not consult IsOwnInstalledBinary, so our "
            "own dev-signed binaries can still be blocked at module load")

        withheld = self._brace_block_from(body, "&& ownBinary) {")
        self.assertTrue(
            "m_stats.ownBinaryBlockWithheld++" in withheld,
            "the withheld block is not counted")
        # Withholding a BLOCK must not withhold ANALYSIS. A return here would skip
        # packer detection and the ScanEngine pass below, turning a de-noising
        # guard into a blanket exemption for our own binaries.
        self.assertFalse(
            "return Communication::KernelVerdict::" in withheld,
            "the withhold branch returns a verdict, which skips the remaining "
            "analysis; it must fall through so an identification can still convict")

    def test_the_self_exemption_counters_are_reported_and_reset(self):
        for field in ("ownBinaryBlockWithheld", "ownHandleOperationsNotFlagged"):
            self.assertTrue(
                field + "={}" in self.cpp,
                "%s is never published, so the exemption cannot be seen in the "
                "field" % field)
        reset = self._definition_body(self.cpp, "void RTPStatistics::Reset()")
        self.assertTrue(
            "ownHandleOperationsNotFlagged = 0;" in reset,
            "ownHandleOperationsNotFlagged is not reset, so it keeps its "
            "pre-reset value")
        self.assertTrue(
            "std::atomic<uint64_t> ownHandleOperationsNotFlagged" in self.hpp,
            "ownHandleOperationsNotFlagged is not declared as an atomic counter")


class HoneypotDeploymentContractTests(unittest.TestCase):
    """A decoy must be created with the one operation that is allowed to succeed.

    MEASURED IN THE 1.0.99 FIELD LOG. Eleven ransomware decoys failed to deploy
    into C:\\Users\\Shado\\Downloads and C:\\Users\\Shado\\OneDrive\\Resimler. The chain
    per decoy was identical:

        ReplaceFileAtomic: MoveFileExW failed ... WinError 5 (access denied)
        RemoveFile: DeleteFileW failed        ... WinError 5 (access denied)
        TempFileGuard: Failed to remove       ... WinError 0 (success!)

    So the temp file CREATION succeeded, the rename was denied, and the cleanup
    delete was denied - leaving eleven undeletable .~*.tmp files in folders
    belonging to the user. Running as SYSTEM, so this is not a privilege problem,
    and error 5 rather than 32 means it is not a sharing violation either.

    WriteAllBytesAtomic earns atomicity by writing a temp and renaming over the
    target, which is right for REPLACING content and pointless for a file that
    must not already exist. Creating the decoy in place uses only the operation
    observed to work and strands nothing on failure.
    """

    @classmethod
    def setUpClass(cls):
        cls.fu_cpp = strip_c_comments(read_source(FILE_UTILS_CPP_PATH))
        cls.fu_hpp = strip_c_comments(read_source(FILE_UTILS_HPP_PATH))
        cls.hp_cpp = strip_c_comments(read_source(HONEYPOT_MANAGER_CPP_PATH))

    def _definition_body(self, code, needle):
        self.assertEqual(
            code.count(needle), 1,
            "expected exactly one definition matching %r, found %d"
            % (needle, code.count(needle)))
        start = code.index(needle)
        depth = 0
        i = code.index("{", start)
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return code[start:i + 1]
            i += 1
        self.fail("unterminated body for %r" % needle)

    def test_the_decoy_is_created_in_place_not_renamed_over(self):
        body = self._definition_body(
            self.hp_cpp, "void HoneypotManagerImpl::CreateHoneypotFile(")
        self.assertTrue(
            "FileUtils::WriteNewFileExclusive(" in body,
            "the decoy is not created in place; the temp-and-rename path is the "
            "one the field proved is denied, and it is what strands .~*.tmp files "
            "in the user's folders")
        self.assertFalse(
            "WriteAllBytesAtomic" in body,
            "CreateHoneypotFile still uses the atomic replace primitive, which "
            "performs a rename that buys no atomicity for a file that must not "
            "already exist")

    def _create_file_call_args(self, body):
        """The argument list of the CreateFileW call, by parenthesis matching.

        ASSERTING ON THE WHOLE BODY IS UNSOUND HERE and the mutation proof caught
        it: strip_c_comments does not touch STRING LITERALS, and this function's
        own failure message contains the text "CreateFileW(CREATE_NEW) failed".
        A body-wide search for CREATE_NEW was therefore satisfied by the log
        message, so replacing the real flag with CREATE_ALWAYS produced no
        failure. The flags must be read from the call itself.
        """
        k = body.find("CreateFileW(")
        self.assertNotEqual(k, -1, "the CreateFileW call is gone")
        i = k + len("CreateFileW(")
        depth = 1
        while i < len(body) and depth:
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
            i += 1
        return body[k:i]

    def test_the_new_primitive_keeps_the_properties_that_make_it_safe(self):
        # These two flags are the reason this is a FileUtils primitive rather than
        # a bare CreateFileW at the call site. Losing either turns a decoy write
        # into either an overwrite of a real file or a redirected write.
        body = self._definition_body(
            self.fu_cpp, "bool WriteNewFileExclusive(std::wstring_view path, const std::byte* data, size_t len, Error* err)")
        args = self._create_file_call_args(body)
        self.assertTrue(
            "CREATE_NEW" in args,
            "the CreateFileW call in WriteNewFileExclusive no longer passes "
            "CREATE_NEW, so it can overwrite an existing file the caller does not "
            "own. Disposition passed: %r"
            % (args[-160:] if len(args) > 160 else args))
        self.assertTrue(
            "FILE_FLAG_OPEN_REPARSE_POINT" in args,
            "the CreateFileW call no longer passes FILE_FLAG_OPEN_REPARSE_POINT, "
            "so a pre-planted link can redirect the write to a victim path")
        self.assertTrue(
            "ValidatePath(path)" in body,
            "WriteNewFileExclusive does not validate its path")
        self.assertTrue(
            "RemoveFile(target, &rmErr)" in body,
            "a partially written file is no longer removed, or its removal error "
            "is no longer captured")
        self.assertTrue(
            "WriteNewFileExclusive" in self.fu_hpp,
            "WriteNewFileExclusive is not declared in the header")

    def test_a_failed_removal_reports_the_error_it_actually_got(self):
        # Both guards previously read GetLastError() AFTER RemoveFile had already
        # logged, and that logging resets the thread's last error - which is how a
        # failure came to be reported as "WinError 0: the operation completed
        # successfully". A cause that contradicts the failure is worse than none.
        atomic = self._definition_body(
            self.fu_cpp, "bool WriteAllBytesAtomic(std::wstring_view path, const std::byte* data, size_t len, Error* err)")
        self.assertTrue(
            "RemoveFile(tmp, &rmErr)" in atomic,
            "TempFileGuard calls RemoveFile without capturing its error, so a "
            "failed cleanup will again report whatever last error the logging "
            "left behind")
        self.assertFalse(
            "if (!RemoveFile(tmp))" in atomic,
            "the error-discarding RemoveFile call is back in TempFileGuard")

    def test_the_deployment_failure_reason_is_not_discarded(self):
        body = self._definition_body(
            self.hp_cpp, "void HoneypotManagerImpl::CreateHoneypotFile(")
        self.assertTrue(
            "writeErr.win32" in body,
            "the Win32 cause is captured into writeErr and then discarded again, "
            "so a deployment failure names no reason and diagnosing it requires "
            "correlating separate FileUtils log lines")

    def test_the_cycle_summary_reports_failures_and_not_only_successes(self):
        body = self._definition_body(self.hp_cpp, "bool HoneypotManagerImpl::DeployTraps(")
        self.assertTrue(
            "m_cycleDeployFailures" in body,
            "DeployTraps does not consult the per-cycle failure count, so a cycle "
            "in which decoys failed reads the same as one where none did")
        self.assertTrue(
            "FAILED" in body,
            "the summary does not report failures; a location counts as seeded "
            "when one decoy lands, and per-decoy success is logged at Debug which "
            "production filters, so neither number was visible")
        self.assertTrue(
            "m_cycleDeployFailures.fetch_add" in self.hp_cpp,
            "nothing increments the failure count, so it is a structural zero")


class MappedViewErrorFidelityContractTests(unittest.TestCase):
    """A primitive must not destroy the error it is about to be asked for.

    MEASURED IN THE 1.0.99 FIELD LOG, on two adjacent lines:

        [MemoryUtils]          OpenFileForMap - CreateFileW failed: <path>: WinError 32
        [MetamorphicDetector]  Failed to map file: <path> (error 0)

    Same file, same thread, same millisecond, two different causes - and the
    second one says the operation succeeded. The mechanism: OpenFileForMap logs
    its failure through SS_LOG_LAST_ERROR, whose own work RESETS the thread's
    last-error value, and then returns a bare bool. Eleven call sites across five
    modules then called GetLastError() and got whatever the logging left behind.

    Two of those eleven even carried comments about capturing the value before it
    could be clobbered - PackerDetector's said "SECURITY FIX: Capture
    GetLastError() once", PEParser's said "Capture GetLastError() BEFORE
    err->Set()". Both were guarding against their own later calls, and both were
    already too late, because the callee had destroyed the value before returning.
    That is why the fix belongs in the callee: eleven correct call sites cannot be
    built on a primitive that forgets.

    Same defect class as the TempFileGuard reporting "WinError 0: the operation
    completed successfully" as the reason a delete had failed.
    """

    @classmethod
    def setUpClass(cls):
        cls.mu_hpp = strip_c_comments(read_source(MEMORY_UTILS_HPP_PATH))
        cls.mu_cpp = strip_c_comments(read_source(MEMORY_UTILS_CPP_PATH))
        cls.sc_cpp = strip_c_comments(read_source(SCAN_ENGINE_CPP_PATH))
        cls.consumers = [
            ("metamorphic_polymorphicdetector.cpp", strip_c_comments(read_source(METAMORPHIC_DETECTOR_CPP_PATH))),
            ("PackerDetector.cpp", strip_c_comments(read_source(PACKER_DETECTOR_CPP_PATH))),
            ("PEParser.cpp", strip_c_comments(read_source(PE_PARSER_CPP_PATH))),
        ]

    @staticmethod
    def _block_after(code, start):
        """Slice the braced block that opens at or after `start`."""
        i = code.find("{", start)
        if i < 0:
            return ""
        depth = 0
        j = i
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    return code[i:j + 1]
            j += 1
        return code[i:]

    def _named_body(self, code, needle):
        self.assertEqual(
            code.count(needle), 1,
            "expected exactly one %r, found %d" % (needle, code.count(needle)))
        return self._block_after(code, code.index(needle))

    def test_the_open_captures_the_error_before_it_logs(self):
        # ORDERING IS THE INVARIANT, so the test pins the order rather than mere
        # presence: a capture placed after the logging reads the reset value and
        # would satisfy any test that only checked both lines exist.
        body = self._named_body(self.mu_cpp, "static bool OpenFileForMap(")
        k = body.find("INVALID_HANDLE_VALUE) {")
        self.assertNotEqual(k, -1, "the CreateFileW failure branch is gone")
        branch = self._block_after(body, k)
        cap = branch.find("outErr = ::GetLastError();")
        log = branch.find("SS_LOG_LAST_ERROR")
        self.assertNotEqual(cap, -1,
                            "the open no longer captures the Win32 error, so every "
                            "caller is back to reading a value the logging reset")
        self.assertNotEqual(log, -1, "the failure is no longer logged at all")
        self.assertLess(cap, log,
                        "the error is captured AFTER the logging that resets it, "
                        "which reads back the wrong value - the exact defect the "
                        "field log caught as \"(error 0)\"")

    def test_the_view_exposes_the_error_and_close_does_not_clear_it(self):
        self.assertTrue("lastError()" in self.mu_hpp,
                        "MappedView no longer exposes the error it captured")
        self.assertTrue("m_lastError" in self.mu_hpp,
                        "the preserved-error member is gone")
        # close() runs on mapReadOnly's own failure paths, so clearing there would
        # discard the value the caller is about to ask for.
        close_body = self._named_body(self.mu_cpp, "void MappedView::close() noexcept")
        self.assertFalse(
            "m_lastError" in close_body,
            "close() now touches m_lastError; mapReadOnly calls close() on its "
            "failure paths, so the caller would read a cleared value")
        move_body = self._named_body(self.mu_cpp, "void MappedView::moveFrom(")
        self.assertTrue(
            "m_lastError = other.m_lastError" in move_body,
            "moveFrom does not carry the error, so a moved-from view loses it")

    def test_no_caller_reads_the_thread_error_after_a_failed_map(self):
        # THE POPULATION GUARD. Eleven sites were wrong; this refuses a twelfth,
        # and it is what makes the callee-side fix stick.
        offenders = []
        seen_calls = 0
        for name, code in self.consumers:
            for meth in ("mapReadOnly(", "mapReadWrite("):
                pos = 0
                while True:
                    k = code.find(meth, pos)
                    if k < 0:
                        break
                    pos = k + 1
                    line_start = code.rfind("\n", 0, k) + 1
                    head = code[line_start:k]
                    if "if (!" not in head:
                        continue          # not a failure branch
                    seen_calls += 1
                    branch = self._block_after(code, k)
                    if "GetLastError" in branch:
                        ln = code[:k].count("\n") + 1
                        offenders.append("%s:%d" % (name, ln))
        self.assertGreater(seen_calls, 5,
                           "found only %d guarded map calls; the scan is not "
                           "reaching the code it is meant to police" % seen_calls)
        self.assertEqual(
            offenders, [],
            "these sites read GetLastError() after a failed map, which returns "
            "whatever the map call's own logging left behind: %s" % offenders)

    def test_an_unreadable_file_is_not_reported_as_a_missing_one(self):
        body = self._named_body(self.sc_cpp, "EngineResult ScanEngine::ScanFile(")
        k = body.find("fs::exists(filePath, ec)")
        self.assertNotEqual(k, -1, "the existence check is gone")
        branch = self._block_after(body, k)
        self.assertTrue(
            "if (ec)" in branch,
            "the error_code is captured and never read again, so fs::exists's "
            "'false on any failure' makes a locked or permission-denied file "
            "report as 'File not found'")
        self.assertTrue(
            "NOT scanned" in branch,
            "the inaccessible branch does not say the file went unscanned")

    def test_neither_existence_branch_softens_the_verdict(self):
        # A file we could not examine is an UNSCANNED file. Turning either branch
        # into Clean would quieten the log by lying about coverage.
        body = self._named_body(self.sc_cpp, "EngineResult ScanEngine::ScanFile(")
        k = body.find("fs::exists(filePath, ec)")
        branch = self._block_after(body, k)
        self.assertEqual(
            branch.count("ScanVerdict::Error"), 1,
            "expected exactly one Error verdict covering both branches of the "
            "existence check, found %d" % branch.count("ScanVerdict::Error"))
        self.assertFalse(
            "ScanVerdict::Clean" in branch,
            "an unexaminable file is being reported Clean, which counts an "
            "unscanned file as a scanned one")


class AeadAadIntegrityContractTests(unittest.TestCase):
    """The GCM AAD must equal the header actually transmitted.

    FilterConnection encrypts every user-mode kernel frame with AES-256-GCM and
    passes SHADOWSTRIKE_MESSAGE_HEADER as additional authenticated data. The tag
    therefore binds those exact header bytes, and the driver re-derives the AAD
    from the header it received. Any mutation of the wire header after the tag is
    computed silently invalidates it.

    That defect shipped: SHADOWSTRIKE_MSG_FLAG_HMAC was OR-ed into the wire
    header after encryption, so the kernel's BCryptDecrypt returned
    STATUS_AUTH_TAG_MISMATCH, surfacing as HRESULT 0x80070017 (ERROR_CRC), and
    every encrypted frame on the no-reply path was refused. The measured
    consequence was that no kernel-side protection list was ever populated.

    These tests pin the ORDERING, because presence alone cannot express the
    invariant: the flags must be final BEFORE the encrypt call, and the wire
    header must be written FROM the authenticated value and never touched again.
    """

    @staticmethod
    def _encrypt_send_message_body():
        """Return the comment-stripped body of EncryptSendMessage.

        The definition is located on its RETURN-TYPE PREFIX: the two call sites
        read `EncryptSendMessage(sendBuffer, ...)` with no `bool`, so
        `bool EncryptSendMessage(` identifies the definition uniquely and this
        cannot latch onto a caller.

        Comments are stripped FIRST and that is load-bearing: the fix's own
        comments necessarily name SHADOWSTRIKE_MSG_FLAG_HMAC while describing the
        defect, so a raw-text search would be satisfied by prose.
        """
        source = read_source(FILTER_CONNECTION_CPP_PATH)
        matches = list(re.finditer(r"bool\s+EncryptSendMessage\s*\(", source))
        if len(matches) != 1:
            raise AssertionError(
                "expected exactly 1 definition of EncryptSendMessage keyed on its "
                "return type, found %d" % len(matches))
        start = matches[0].start()
        brace = source.index("{", start)
        depth = 0
        end = None
        for i in range(brace, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            raise AssertionError("unbalanced braces in EncryptSendMessage")
        return strip_c_comments(source[brace:end])

    def test_every_wire_flag_is_set_before_the_gcm_tag_is_computed(self):
        body = self._encrypt_send_message_body()

        encrypt_at = body.find("crypto.Encrypt(")
        self.assertNotEqual(
            encrypt_at, -1,
            "EncryptSendMessage no longer calls crypto.Encrypt; this guard "
            "describes an ordering around that call and must be revisited")

        for flag in ("SHADOWSTRIKE_MSG_FLAG_ENCRYPTED", "SHADOWSTRIKE_MSG_FLAG_HMAC"):
            needle = "aadHeader.Flags |= %s;" % flag
            at = body.find(needle)
            self.assertNotEqual(
                at, -1,
                "%s must be OR-ed into aadHeader so the GCM tag authenticates it; "
                "a flag set on the wire header instead is the ERROR_CRC defect" % flag)
            self.assertLess(
                at, encrypt_at,
                "%s is set at offset %d but crypto.Encrypt is called at offset %d: "
                "the flag is not covered by the tag it must be covered by"
                % (flag, at, encrypt_at))

    def test_the_wire_header_is_never_mutated_after_the_tag(self):
        body = self._encrypt_send_message_body()

        offenders = [
            line.strip()
            for line in body.split("\n")
            if re.search(r"outHeader\s*->\s*Flags\s*(\|=|&=|\^=|=)", line)
        ]
        self.assertEqual(
            offenders, [],
            "the wire header must never be mutated after the GCM tag is computed; "
            "found %d mutation(s): %s" % (len(offenders), offenders))

        # Anti-vacuity: an empty or deleted function would also satisfy the
        # assertion above, so pin the work this function must still do.
        #
        # Bounded deliberately: assertIn would print the whole function body on
        # failure (6,028 characters measured), which buries the finding.
        self.assertTrue(
            "ComputeKernelMessageHMAC" in body,
            "EncryptSendMessage no longer computes the outgoing HMAC (searched "
            "%d chars of comment-stripped body); the no-mutation assertion above "
            "would then be vacuously true" % len(body))

    def test_the_wire_header_is_written_from_the_authenticated_value(self):
        body = self._encrypt_send_message_body()

        self.assertEqual(
            body.count("*outHeader = aadHeader;"), 1,
            "the wire header must be assigned exactly once, from the same value "
            "that was passed to the cipher as AAD")

        assign_at = body.find("*outHeader = aadHeader;")
        encrypt_at = body.find("crypto.Encrypt(")
        self.assertGreater(
            assign_at, encrypt_at,
            "the wire header is written at offset %d, before crypto.Encrypt at "
            "offset %d; it must be written from the value the tag authenticated"
            % (assign_at, encrypt_at))

    def test_a_failed_hmac_refuses_the_send_rather_than_downgrading(self):
        body = self._encrypt_send_message_body()

        guard_at = body.find("hmac.size() != 32")
        self.assertNotEqual(
            guard_at, -1,
            "the outgoing HMAC length must be checked; without it a short tag "
            "would be appended and the frame would be self-inconsistent")

        tail = body[guard_at:guard_at + 900]
        self.assertTrue(
            "return false;" in tail,
            "a failed HMAC must refuse the send: the flag advertising the HMAC is "
            "inside the authenticated AAD, so clearing it to 'send anyway' would "
            "invalidate the GCM tag and reintroduce the ERROR_CRC defect. Searched "
            "the %d chars following the length check." % len(tail))

class ScannerWritePathExemptionContractTests(unittest.TestCase):
    """Our own service must be exempt from write analysis BEFORE any denial.

    PreWrite analyses every write and can complete the I/O with
    STATUS_ACCESS_DENIED from four different places. Our own service writes
    quarantine copies, signature databases, rollback backups and ransomware
    honeypot decoys - bulk, high-entropy writes, some into user document folders
    - which is indistinguishable from ransomware by construction.

    The create path has exempted this process for a long time. The write path had
    no exemption at all, so in 1.0.100 the driver denied 27 of our own honeypot
    decoy writes, leaving four document folders with no decoy and therefore no
    honeypot alert if ransomware encrypted them.

    Ordering is the invariant, not presence: the previous shape had the exclusion
    escape at PreWrite.c:935 sitting DOWNSTREAM of the self-protection denial at
    :890, so an exemption placed there could never save the earlier branch.
    """

    @staticmethod
    def _prewrite_operation_body():
        """Comment-stripped body of the function containing the exemption.

        Comments are stripped FIRST and that is load-bearing here: the fix's own
        comment block quotes STATUS_ACCESS_DENIED while explaining the defect, and
        it sits ABOVE the exemption. Without stripping, that prose would read as a
        denial preceding the exemption and invert the very ordering under test.

        The enclosing function is located by scanning BACKWARD from the exemption
        to the nearest brace alone at column 0, so the test does not depend on the
        callback's name.
        """
        source = strip_c_comments(read_source(PRE_WRITE_C_PATH))

        needle = "ShadowStrikeIsScannerProcess(RequestorPid)"
        at = source.find(needle)
        if at < 0:
            raise AssertionError(
                "the scanner self-exemption is gone from PreWrite.c; the write "
                "path would once again analyse and block our own file I/O")

        start = source.rfind("\n{", 0, at)
        if start < 0:
            raise AssertionError("could not locate the enclosing function brace")
        depth = 0
        end = None
        for i in range(start + 1, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            raise AssertionError("unbalanced braces around the exemption")
        return source[start:end]

    @classmethod
    def _exemption_block(cls):
        """Return the exemption's OWN braced block.

        A fixed character window is wrong here and was measured wrong: moving the
        exemption next to the user-exclusion block put that block's
        SkippedExcluded increment inside a 400-character window, so the test
        reported a conflated counter when nothing was conflated. Brace matching
        scopes the assertion to the statement it is actually about.
        """
        body = cls._prewrite_operation_body()
        at = body.index("ShadowStrikeIsScannerProcess(RequestorPid)")
        open_at = body.index("{", at)
        depth = 0
        for i in range(open_at, len(body)):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                depth -= 1
                if depth == 0:
                    return body[open_at:i + 1]
        raise AssertionError("unbalanced braces in the exemption block")

    def test_the_exemption_precedes_every_access_denial(self):
        body = self._prewrite_operation_body()

        exempt_at = body.index("ShadowStrikeIsScannerProcess(RequestorPid)")
        denials = [m.start() for m in re.finditer(r"STATUS_ACCESS_DENIED", body)]

        # Anti-vacuity: with no denials left the ordering claim is empty, and the
        # measured population of this function is four.
        self.assertGreaterEqual(
            len(denials), 4,
            "expected at least the 4 measured STATUS_ACCESS_DENIED sites in this "
            "callback, found %d; the ordering guarantee below would otherwise be "
            "vacuous" % len(denials))

        early = [d for d in denials if d < exempt_at]
        self.assertEqual(
            early, [],
            "the scanner self-exemption is at offset %d but %d denial(s) precede "
            "it at %s; a denial upstream of the exemption can still refuse our "
            "own writes, which is the defect this guards"
            % (exempt_at, len(early), early))

    def test_the_exemption_precedes_the_file_name_query(self):
        body = self._prewrite_operation_body()

        exempt_at = body.index("ShadowStrikeIsScannerProcess(RequestorPid)")
        name_at = body.find("FltGetFileNameInformation(")
        self.assertNotEqual(
            name_at, -1,
            "FltGetFileNameInformation is gone from this callback; this test "
            "describes an ordering around it and must be revisited")
        self.assertLess(
            exempt_at, name_at,
            "our own bulk I/O must be skipped before paying for a name query and "
            "parse: exemption at %d, name query at %d" % (exempt_at, name_at))

    def test_the_exemption_releases_the_operation_reference(self):
        block = self._exemption_block()
        leave_at = block.find("PwpLeaveOperation();")
        ret_at = block.find("return FLT_PREOP_SUCCESS_NO_CALLBACK;")

        self.assertNotEqual(
            leave_at, -1,
            "the exemption must call PwpLeaveOperation() before returning; "
            "PwpEnterOperation() was already taken, so returning without it leaks "
            "an operation reference and can stall driver unload")
        self.assertNotEqual(ret_at, -1, "the exemption must return from the callback")
        self.assertLess(
            leave_at, ret_at,
            "PwpLeaveOperation() must come before the return, not after it")

    def test_the_exemption_is_counted_under_its_own_reason(self):
        block = self._exemption_block()

        self.assertTrue(
            "SkippedScannerSelf" in block,
            "the exemption must be counted so it can be verified in the field; "
            "searched its own %d-char block" % len(block))
        self.assertFalse(
            "SkippedExcluded" in block,
            "the exemption must NOT reuse SkippedExcluded: a self-exemption and a "
            "user-configured exclusion are different reasons and conflating them "
            "makes both unreadable")

    def test_the_exemption_is_not_gated_on_configuration(self):
        body = self._prewrite_operation_body()

        line = None
        for candidate in body.split("\n"):
            if "ShadowStrikeIsScannerProcess(RequestorPid)" in candidate:
                line = candidate
                break
        self.assertIsNotNone(line, "the exemption line vanished")

        indent = len(line) - len(line.lstrip(" "))
        self.assertEqual(
            indent, 4,
            "the exemption must sit at the callback's top level (indent 4), not "
            "nested inside another block; found indent %d. A configuration in "
            "which the product blocks its own writes must not be selectable."
            % indent)

class KernelConfigDeliveryReportingContractTests(unittest.TestCase):
    """A republish summary must report deliveries, not invocations.

    The kernel-config publisher mechanism exists so that a module whose startup
    push was refused gets it re-pushed when the channel comes up. In 1.0.100 that
    mechanism fired at exactly the right instant and all three sends were still
    refused by the driver - and the log read "Republished kernel configuration
    from 3 publisher(s)" anyway, because the handler returned void so the loop
    could only count itself.

    Three "Failed to sync" warnings sat immediately above that line. A summary
    that contradicts the lines above it is worse than no summary, because it is
    the line a reader trusts.
    """

    @staticmethod
    def _publish_body():
        source = strip_c_comments(read_source(IPC_MANAGER_CPP_PATH))
        m = re.search(r"void\s+IPCManager::PublishKernelConfiguration\s*\(\s*\)", source)
        if m is None:
            raise AssertionError("PublishKernelConfiguration definition not found")
        brace = source.index("{", m.end())
        depth = 0
        for i in range(brace, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    return source[brace:i + 1]
        raise AssertionError("unbalanced braces in PublishKernelConfiguration")

    def test_the_publisher_signature_carries_a_result(self):
        source = strip_c_comments(read_source(IPC_MANAGER_HPP_PATH))

        self.assertTrue(
            "using KernelConfigPublisher = std::function<bool()>;" in source,
            "KernelConfigPublisher must return a result; with std::function<void()> "
            "the aggregator can only count invocations and will report success "
            "even when every push was refused")
        self.assertFalse(
            "using KernelConfigPublisher = std::function<void()>;" in source,
            "the void publisher alias must not come back")

    def test_the_summary_counts_the_handler_result(self):
        body = self._publish_body()

        # Anti-vacuity: the loop must still call the handler at all.
        self.assertTrue(
            "entry.handler()" in body,
            "PublishKernelConfiguration no longer invokes its publishers; every "
            "assertion in this class would then be vacuous")

        offenders = [
            line.strip() for line in body.split("\n")
            if re.search(r"^\s*entry\.handler\(\)\s*;", line)
        ]
        self.assertEqual(
            offenders, [],
            "the handler result must be captured, not discarded as a bare "
            "statement; found %d discarding call(s): %s" % (len(offenders), offenders))

        self.assertTrue(
            re.search(r"=\s*entry\.handler\(\)\s*;", body) is not None,
            "the handler result must be assigned so the summary can count "
            "confirmations rather than loop iterations")

    def test_the_summary_names_what_did_not_confirm(self):
        body = self._publish_body()

        self.assertTrue(
            "NOT CONFIRMED" in body,
            "the failure branch must say which publishers did not confirm; a bare "
            "count cannot tell the reader WHICH kernel-side protection is missing, "
            "and each publisher owns a different one")
        self.assertFalse(
            "Republished kernel configuration from {} publisher(s)" in body,
            "the old invocation-counting message must not come back")

    def test_no_registration_discards_its_sync_result(self):
        source = strip_c_comments(read_source(ANTIVIRUS_SERVICE_CPP_PATH))

        registrations = source.count("RegisterKernelConfigPublisher(")
        self.assertGreaterEqual(
            registrations, 3,
            "expected at least the 3 measured kernel-config registrations, found "
            "%d; the discard assertion below would otherwise be vacuous"
            % registrations)

        offenders = [
            line.strip() for line in source.split("\n")
            if "ToKernel()" in line and re.search(r"\(\s*void\s*\)", line)
        ]
        self.assertEqual(
            offenders, [],
            "no registration may discard its sync result: the answer is what the "
            "summary reports. Found %d discard(s): %s" % (len(offenders), offenders))

    def test_both_kernel_syncs_are_nodiscard(self):
        for label, path, decl in (
            ("FileProtection", FILE_PROTECTION_HPP_PATH,
             "[[nodiscard]] bool SyncProtectedPathsToKernel();"),
            ("SelfDefense", SELF_DEFENSE_HPP_PATH,
             "[[nodiscard]] bool SyncProtectedProcessesToKernel();"),
        ):
            source = strip_c_comments(read_source(path))
            self.assertTrue(
                decl in source,
                "%s's kernel sync must be declared [[nodiscard]] bool so a future "
                "caller cannot silently drop the delivery result, matching "
                "RegistryProtection which has always reported its outcome" % label)

if __name__ == "__main__":
    unittest.main(verbosity=2)
