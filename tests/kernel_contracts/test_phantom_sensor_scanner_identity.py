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


class SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.precreate_source = read_source(PRECREATE_PATH)
        cls.scan_bridge_c = read_source(SCAN_BRIDGE_C_PATH)
        cls.scan_bridge_h = read_source(SCAN_BRIDGE_H_PATH)
        cls.comm_port_c = read_source(COMM_PORT_C_PATH)
        cls.comm_port_h = read_source(COMM_PORT_H_PATH)
        cls.driver_entry_c = read_source(DRIVER_ENTRY_C_PATH)

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

        # In the funnel the refusal must precede the queue fallback: a frame that
        # must not be transmitted must not be buffered for later transmission.
        refusal_at = notify.index("Size <= sizeof(SHADOWSTRIKE_MESSAGE_HEADER)")
        enqueue_at = notify.index("MqEnqueueMessage")
        self.assertLess(refusal_at, enqueue_at)

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
