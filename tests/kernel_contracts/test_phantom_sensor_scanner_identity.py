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
COMMUNICATION_HPP_PATH = ROOT / "src/PhantomCore/Communication/Communication.hpp"
MESSAGE_DISPATCHER_CPP_PATH = ROOT / "src/PhantomCore/Communication/MessageDispatcher.cpp"
FUZZER_VCXPROJ_PATH = ROOT / "Fuzzer/Fuzzer.vcxproj"


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
