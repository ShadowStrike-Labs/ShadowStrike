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
