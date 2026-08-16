#include "ShadowStrike/Fuzzer/Protocol/KernelMessageSchema.hpp"

#include "../../PhantomSensor/Shared/MessageProtocol.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <sstream>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

namespace {

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

[[nodiscard]] KernelFieldSchema MakeField(
    std::string name,
    const std::size_t offset,
    const std::size_t width,
    const KernelFieldEncoding encoding,
    std::string description,
    std::vector<std::string> invariants = {})
{
    return KernelFieldSchema{
        std::move(name),
        offset,
        width,
        encoding,
        std::move(description),
        std::move(invariants)
    };
}

[[nodiscard]] KernelVariableSegmentSchema MakeSegment(
    std::string name,
    std::string lengthField,
    const std::size_t elementWidth,
    std::string encoding,
    std::string description)
{
    return KernelVariableSegmentSchema{
        std::move(name),
        std::move(lengthField),
        elementWidth,
        std::move(encoding),
        std::move(description)
    };
}

[[nodiscard]] std::vector<KernelFieldSchema> BuildCommonHeaderFields() {
    return {
        MakeField("Header.Magic", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Magic), sizeof(UINT32),
            KernelFieldEncoding::UnsignedInteger, "Protocol sentinel for ShadowStrike frames.",
            { "Must equal SHADOWSTRIKE_MESSAGE_MAGIC." }),
        MakeField("Header.Version", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Version), sizeof(UINT16),
            KernelFieldEncoding::UnsignedInteger, "Wire protocol version negotiated between components.",
            { "Must equal SHADOWSTRIKE_PROTOCOL_VERSION until a compatible protocol bump is introduced." }),
        MakeField("Header.MessageType", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageType), sizeof(UINT16),
            KernelFieldEncoding::EnumValue, "Message discriminator used by the kernel/user dispatch layer.",
            { "Must be a valid SHADOWSTRIKE_MESSAGE_TYPE value for the target handler." }),
        MakeField("Header.MessageId", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageId), sizeof(UINT64),
            KernelFieldEncoding::UnsignedInteger, "Correlation identifier used for request/reply matching."),
        MakeField("Header.TotalSize", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, TotalSize), sizeof(UINT32),
            KernelFieldEncoding::ByteCount, "Total frame size, including header and payload.",
            { "Must be greater than or equal to sizeof(SHADOWSTRIKE_MESSAGE_HEADER).",
              "Must not exceed the actual received buffer length." }),
        MakeField("Header.DataSize", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, DataSize), sizeof(UINT32),
            KernelFieldEncoding::ByteCount, "Payload size immediately following the transport header.",
            { "Must satisfy Header.TotalSize == sizeof(Header) + Header.DataSize for canonical frames." }),
        MakeField("Header.Timestamp", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Timestamp), sizeof(UINT64),
            KernelFieldEncoding::UnsignedInteger, "Kernel-side timestamp copied into the frame."),
        MakeField("Header.Flags", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Flags), sizeof(UINT32),
            KernelFieldEncoding::BitFlags, "Transport modifiers such as compression, HMAC, no-ack, and encryption."),
        MakeField("Header.Reserved", offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Reserved), sizeof(UINT32),
            KernelFieldEncoding::UnsignedInteger, "Reserved field that should remain zero on canonical frames.")
    };
}

void AppendFields(std::vector<KernelFieldSchema>& target, std::vector<KernelFieldSchema> fields) {
    const std::size_t baseOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    std::transform(fields.begin(), fields.end(), std::back_inserter(target),
        [baseOffset](KernelFieldSchema field) {
            field.offset += baseOffset;
            return field;
        });
}

void AppendHeaderOnlySchema(std::vector<KernelMessageSchema>& schemas,
    std::string id,
    std::string surfaceId,
    std::string seedId,
    const std::uint16_t messageType,
    std::string messageName,
    std::string description,
    std::vector<std::string> invariants,
    std::vector<std::string> mutationAxes)
{
    schemas.push_back(KernelMessageSchema{
        std::move(id),
        std::move(surfaceId),
        std::move(seedId),
        messageType,
        std::move(messageName),
        "user-to-kernel",
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
        std::move(description),
        std::move(invariants),
        std::move(mutationAxes),
        BuildCommonHeaderFields(),
        {}
    });
}

[[nodiscard]] std::vector<KernelMessageSchema> BuildSchemas() {
    std::vector<KernelMessageSchema> schemas;
    schemas.reserve(9);

    AppendHeaderOnlySchema(schemas,
        "phantomsensor.register-message",
        "phantomsensor.commport.control-plane",
        "register-baseline",
        FilterMessageType_Register,
        "Register",
        "Minimal control-plane registration message for initial user-mode service onboarding.",
        { "Header.DataSize must be zero.",
          "Header.TotalSize must equal sizeof(SHADOWSTRIKE_MESSAGE_HEADER)." },
        { "header-magic", "header-version", "unexpected-flags", "message-reordering" });

    AppendHeaderOnlySchema(schemas,
        "phantomsensor.heartbeat-message",
        "phantomsensor.commport.control-plane",
        "heartbeat-baseline",
        FilterMessageType_Heartbeat,
        "Heartbeat",
        "Lifecycle keep-alive frame used to keep the communication session active.",
        { "Header.DataSize must be zero.",
          "Header.TotalSize must equal sizeof(SHADOWSTRIKE_MESSAGE_HEADER)." },
        { "duplicate-heartbeats", "timing-gaps", "flag-confusion" });

    AppendHeaderOnlySchema(schemas,
        "phantomsensor.query-driver-status-message",
        "phantomsensor.commport.control-plane",
        "query-driver-status-baseline",
        FilterMessageType_QueryDriverStatus,
        "QueryDriverStatus",
        "Request/reply control message used to pull aggregated kernel health and telemetry state.",
        { "Header.DataSize must be zero.",
          "Reply suppression flags should not bypass the expected response path." },
        { "no-ack-flag", "message-id-reuse", "reply-desynchronization" });

    {
        auto fields = BuildCommonHeaderFields();
        AppendFields(fields, {
            MakeField("Policy.ScanOnOpen", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanOnOpen), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enable on-open scan interception."),
            MakeField("Policy.ScanOnExecute", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanOnExecute), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enable execute-time scans."),
            MakeField("Policy.ScanOnWrite", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanOnWrite), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enable write-path scans."),
            MakeField("Policy.EnableNotifications", offsetof(SHADOWSTRIKE_POLICY_UPDATE, EnableNotifications), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enable async telemetry emission to user mode."),
            MakeField("Policy.BlockOnTimeout", offsetof(SHADOWSTRIKE_POLICY_UPDATE, BlockOnTimeout), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Controls fail-closed behavior on user-mode timeout."),
            MakeField("Policy.BlockOnError", offsetof(SHADOWSTRIKE_POLICY_UPDATE, BlockOnError), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Controls fail-closed behavior on processing errors."),
            MakeField("Policy.ScanNetworkFiles", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanNetworkFiles), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enables scanning for remote/network-backed files."),
            MakeField("Policy.ScanRemovableMedia", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanRemovableMedia), sizeof(BOOLEAN),
                KernelFieldEncoding::Boolean, "Enables scanning for removable media volumes."),
            MakeField("Policy.MaxScanFileSize", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MaxScanFileSize), sizeof(UINT64),
                KernelFieldEncoding::UnsignedInteger, "Upper bound on file size eligible for synchronous scanning."),
            MakeField("Policy.ScanTimeoutMs", offsetof(SHADOWSTRIKE_POLICY_UPDATE, ScanTimeoutMs), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Per-request user-mode timeout budget in milliseconds."),
            MakeField("Policy.CacheTTLSeconds", offsetof(SHADOWSTRIKE_POLICY_UPDATE, CacheTTLSeconds), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Cache lifetime for verdict reuse."),
            MakeField("Policy.MaxPendingRequests", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MaxPendingRequests), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Hard limit for queued user-mode scan requests."),
            MakeField("Policy.MqMaxQueueDepth", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MqMaxQueueDepth), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Queue depth tuning knob for the message queue layer.",
                { "Zero means leave the current queue depth unchanged." }),
            MakeField("Policy.MqMaxMessageSize", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MqMaxMessageSize), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Message queue payload cap.",
                { "Zero means leave the current message size limit unchanged." }),
            MakeField("Policy.MqBatchSize", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MqBatchSize), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Batch size limit for queue flush operations.",
                { "Zero means leave the current batch size unchanged." }),
            MakeField("Policy.MqBatchTimeoutMs", offsetof(SHADOWSTRIKE_POLICY_UPDATE, MqBatchTimeoutMs), sizeof(ULONG),
                KernelFieldEncoding::UnsignedInteger, "Maximum batching delay in milliseconds.",
                { "Zero means leave the current batch timeout unchanged." })
        });

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.policy-update-message",
            "phantomsensor.commport.policy-update",
            "policy-update-baseline",
            FilterMessageType_UpdatePolicy,
            "UpdatePolicy",
            "user-to-kernel",
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_POLICY_UPDATE),
            "Policy update payload used to tune scan behavior, queue limits, and timeout policy.",
            { "Header.DataSize must equal sizeof(SHADOWSTRIKE_POLICY_UPDATE).",
              "Queue tuning values must be capped defensively before they influence kernel allocations or latency." },
            { "timeout-boundaries", "queue-depth-overflow", "fail-closed-toggle-combinations" },
            std::move(fields),
            {}
        });
    }

    {
        auto fields = BuildCommonHeaderFields();
        AppendFields(fields, {
            MakeField("ProtectedProcess.ProcessId", offsetof(SHADOWSTRIKE_PROTECTED_PROCESS, ProcessId), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Process identifier to be enrolled in protected-process handling."),
            MakeField("ProtectedProcess.ProtectionFlags", offsetof(SHADOWSTRIKE_PROTECTED_PROCESS, ProtectionFlags), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "Protection policy bits interpreted by the self-protection layer."),
            MakeField("ProtectedProcess.ProcessName", offsetof(SHADOWSTRIKE_PROTECTED_PROCESS, ProcessName),
                sizeof(((SHADOWSTRIKE_PROTECTED_PROCESS*)nullptr)->ProcessName), KernelFieldEncoding::FixedBytes,
                "Fixed-width WCHAR buffer storing the canonical process image name.")
        });

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.protected-process-registration",
            "phantomsensor.commport.policy-update",
            "register-protected-process-baseline",
            FilterMessageType_RegisterProtectedProcess,
            "RegisterProtectedProcess",
            "user-to-kernel",
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PROTECTED_PROCESS),
            "Protected-process registration payload used by the self-protection subsystem.",
            { "Header.DataSize must equal sizeof(SHADOWSTRIKE_PROTECTED_PROCESS).",
              "ProcessName should remain null-terminated within MAX_PROCESS_NAME_LENGTH." },
            { "flag-combinations", "process-id-zero", "unterminated-name-buffer" },
            std::move(fields),
            {}
        });
    }

    {
        auto fields = BuildCommonHeaderFields();
        AppendFields(fields, {
            MakeField("ScanRequest.MessageId", offsetof(FILE_SCAN_REQUEST, MessageId), sizeof(UINT64),
                KernelFieldEncoding::UnsignedInteger, "Payload-level request identifier echoed in scan verdicts."),
            MakeField("ScanRequest.AccessType", offsetof(FILE_SCAN_REQUEST, AccessType), sizeof(UINT8),
                KernelFieldEncoding::EnumValue, "Operation type such as open, write, or execute."),
            MakeField("ScanRequest.Disposition", offsetof(FILE_SCAN_REQUEST, Disposition), sizeof(UINT8),
                KernelFieldEncoding::UnsignedInteger, "Create disposition carried from the file-system event."),
            MakeField("ScanRequest.Priority", offsetof(FILE_SCAN_REQUEST, Priority), sizeof(UINT8),
                KernelFieldEncoding::UnsignedInteger, "Processing urgency used by the broker."),
            MakeField("ScanRequest.RequiresReply", offsetof(FILE_SCAN_REQUEST, RequiresReply), sizeof(UINT8),
                KernelFieldEncoding::Boolean, "Indicates whether the minifilter path is blocked waiting for verdict."),
            MakeField("ScanRequest.ProcessId", offsetof(FILE_SCAN_REQUEST, ProcessId), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Originating process identifier."),
            MakeField("ScanRequest.ThreadId", offsetof(FILE_SCAN_REQUEST, ThreadId), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Originating thread identifier."),
            MakeField("ScanRequest.ParentProcessId", offsetof(FILE_SCAN_REQUEST, ParentProcessId), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Parent process identifier captured at event time."),
            MakeField("ScanRequest.SessionId", offsetof(FILE_SCAN_REQUEST, SessionId), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Interactive session identifier."),
            MakeField("ScanRequest.FileSize", offsetof(FILE_SCAN_REQUEST, FileSize), sizeof(UINT64),
                KernelFieldEncoding::UnsignedInteger, "Observed file size for policy evaluation."),
            MakeField("ScanRequest.FileAttributes", offsetof(FILE_SCAN_REQUEST, FileAttributes), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "Win32 file attribute bitmask."),
            MakeField("ScanRequest.DesiredAccess", offsetof(FILE_SCAN_REQUEST, DesiredAccess), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "Desired access mask requested by the caller."),
            MakeField("ScanRequest.ShareAccess", offsetof(FILE_SCAN_REQUEST, ShareAccess), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "Share access mask."),
            MakeField("ScanRequest.CreateOptions", offsetof(FILE_SCAN_REQUEST, CreateOptions), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "File create/open option mask."),
            MakeField("ScanRequest.VolumeSerial", offsetof(FILE_SCAN_REQUEST, VolumeSerial), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Volume serial number copied from the underlying file object."),
            MakeField("ScanRequest.FileId", offsetof(FILE_SCAN_REQUEST, FileId), sizeof(UINT64),
                KernelFieldEncoding::UnsignedInteger, "Stable file identifier when available."),
            MakeField("ScanRequest.IsDirectory", offsetof(FILE_SCAN_REQUEST, IsDirectory), sizeof(UINT8),
                KernelFieldEncoding::Boolean, "Directory indicator."),
            MakeField("ScanRequest.IsNetworkFile", offsetof(FILE_SCAN_REQUEST, IsNetworkFile), sizeof(UINT8),
                KernelFieldEncoding::Boolean, "Remote/network-backed file indicator."),
            MakeField("ScanRequest.IsRemovableMedia", offsetof(FILE_SCAN_REQUEST, IsRemovableMedia), sizeof(UINT8),
                KernelFieldEncoding::Boolean, "Removable-media indicator."),
            MakeField("ScanRequest.HasADS", offsetof(FILE_SCAN_REQUEST, HasADS), sizeof(UINT8),
                KernelFieldEncoding::Boolean, "Alternate-data-stream indicator."),
            MakeField("ScanRequest.PathLength", offsetof(FILE_SCAN_REQUEST, PathLength), sizeof(UINT16),
                KernelFieldEncoding::ByteCount, "Byte length of the file path tail (not a WCHAR count).",
                { "Must not describe bytes beyond the received payload." }),
            MakeField("ScanRequest.ProcessNameLength", offsetof(FILE_SCAN_REQUEST, ProcessNameLength), sizeof(UINT16),
                KernelFieldEncoding::ByteCount, "Byte length of the process name tail (not a WCHAR count).",
                { "Must not describe bytes beyond the received payload after the file path segment." })
        });

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.scan-request-message",
            "phantomsensor.commport.scan-request",
            "scan-request-baseline",
            FilterMessageType_ScanRequest,
            "ScanRequest",
            "user-to-kernel",
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(FILE_SCAN_REQUEST),
            "Variable-length file scan request carrying path, process, and access metadata from the minifilter path.",
            { "Header.DataSize must be at least sizeof(FILE_SCAN_REQUEST).",
              "PathLength and ProcessNameLength must describe only bytes present in the frame.",
              "If RequiresReply is non-zero, the broker state machine must expect a scan verdict." },
            { "length-overclaim", "tail-truncation", "reply-state-confusion", "path-normalization-boundaries" },
            std::move(fields),
            {
                MakeSegment("FilePath", "ScanRequest.PathLength", sizeof(WCHAR), "utf16-path",
                    "Variable-length file path copied immediately after FILE_SCAN_REQUEST. "
                    "elementWidth describes the UTF-16 content; the governing length field "
                    "ScanRequest.PathLength is a BYTE count, not a count of these elements."),
                MakeSegment("ProcessName", "ScanRequest.ProcessNameLength", sizeof(WCHAR), "utf16-process-name",
                    "Variable-length process image name copied after FilePath. Its length field "
                    "is likewise a BYTE count. Note that one of the three kernel builders writes "
                    "a NUL WCHAR between the two strings and the others do not, so this segment's "
                    "offset is builder-dependent and must be derived from the delivered size.")
            }
        });
    }

    {
        auto fields = BuildCommonHeaderFields();
        AppendFields(fields, {
            MakeField("Batch.EntryCount", offsetof(SHADOWSTRIKE_PUSH_BATCH_HEADER, EntryCount), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Number of IOC entries carried in the batch.",
                { "Must not exceed SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES." }),
            MakeField("Batch.EntrySize", offsetof(SHADOWSTRIKE_PUSH_BATCH_HEADER, EntrySize), sizeof(UINT32),
                KernelFieldEncoding::ByteCount, "Size of each fixed-width entry in bytes."),
            MakeField("Batch.TotalDataSize", offsetof(SHADOWSTRIKE_PUSH_BATCH_HEADER, TotalDataSize), sizeof(UINT32),
                KernelFieldEncoding::ByteCount, "Total entry bytes following the batch header."),
            MakeField("Batch.Flags", offsetof(SHADOWSTRIKE_PUSH_BATCH_HEADER, Flags), sizeof(UINT32),
                KernelFieldEncoding::BitFlags, "Batch-mode control flags such as replace, append, or clear.")
        });

        const std::size_t entryBase = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER);
        fields.push_back(MakeField("HashEntry.HashType", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, HashType), sizeof(UINT8),
            KernelFieldEncoding::EnumValue, "Hash algorithm selector."));
        fields.push_back(MakeField("HashEntry.Verdict", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, Verdict), sizeof(UINT8),
            KernelFieldEncoding::EnumValue, "Threat verdict classification."));
        fields.push_back(MakeField("HashEntry.Severity", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, Severity), sizeof(UINT8),
            KernelFieldEncoding::EnumValue, "IOC severity label."));
        fields.push_back(MakeField("HashEntry.Score", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, Score), sizeof(UINT32),
            KernelFieldEncoding::UnsignedInteger, "Threat score in the 0-100 range."));
        fields.push_back(MakeField("HashEntry.Hash", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, Hash), sizeof(((SHADOWSTRIKE_PUSH_HASH_ENTRY*)nullptr)->Hash),
            KernelFieldEncoding::FixedBytes, "Normalized hash bytes used for the IOC lookup key."));
        fields.push_back(MakeField("HashEntry.ThreatName", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, ThreatName), sizeof(((SHADOWSTRIKE_PUSH_HASH_ENTRY*)nullptr)->ThreatName),
            KernelFieldEncoding::FixedAnsiString, "Threat-name buffer paired with the IOC."));
        fields.push_back(MakeField("HashEntry.Expiry", entryBase + offsetof(SHADOWSTRIKE_PUSH_HASH_ENTRY, Expiry), sizeof(LARGE_INTEGER),
            KernelFieldEncoding::UnsignedInteger, "Expiration time or zero for permanent entries."));

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.push-hash-database-message",
            "phantomsensor.commport.data-push-batches",
            "push-hash-database-baseline",
            FilterMessageType_PushHashDatabase,
            "PushHashDatabase",
            "user-to-kernel",
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PUSH_BATCH_HEADER) + sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY),
            "Fixed-entry IOC push batch used to synchronize file-hash intelligence into the kernel path.",
            { "EntryCount must match the number of serialized entries.",
              "TotalDataSize should equal EntryCount * EntrySize for canonical fixed-size batches.",
              "EntryCount must not exceed SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES." },
            { "batch-count-mismatch", "entry-size-mismatch", "max-batch-overrun", "verdict-range-confusion" },
            std::move(fields),
            {}
        });
    }

    {
        auto fields = BuildCommonHeaderFields();
        AppendFields(fields, {
            MakeField("Exclusion.ExclusionType", offsetof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, ExclusionType), sizeof(UINT8),
                KernelFieldEncoding::EnumValue, "Exclusion namespace selector such as path, extension, or process."),
            MakeField("Exclusion.Operation", offsetof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, Operation), sizeof(UINT8),
                KernelFieldEncoding::EnumValue, "Exclusion operation such as add, remove, or clear."),
            MakeField("Exclusion.Flags", offsetof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, Flags), sizeof(UINT8),
                KernelFieldEncoding::BitFlags, "Operational flags controlling exclusion semantics."),
            MakeField("Exclusion.TTLSeconds", offsetof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, TTLSeconds), sizeof(UINT32),
                KernelFieldEncoding::UnsignedInteger, "Lifetime of the exclusion or zero for permanent entries."),
            MakeField("Exclusion.ValueLength", offsetof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY, ValueLength), sizeof(UINT16),
                KernelFieldEncoding::WideCharCount, "Length of the trailing exclusion value in WCHAR units.",
                { "Must not describe bytes beyond the received payload." })
        });

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.exclusion-update-message",
            "phantomsensor.commport.data-push-batches",
            "exclusion-update-baseline",
            FilterMessageType_ExclusionUpdate,
            "ExclusionUpdate",
            "user-to-kernel",
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY),
            "Variable-length exclusion update used to add, remove, or clear trusted paths or process names.",
            { "Header.DataSize must be at least sizeof(SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY).",
              "ValueLength must fit within the received payload after the fixed entry header." },
            { "value-length-overclaim", "ttl-boundaries", "operation-type-confusion" },
            std::move(fields),
            {
                MakeSegment("Exclusion.Value", "Exclusion.ValueLength", sizeof(WCHAR), "utf16-value",
                    "Variable-length exclusion value following SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY.")
            }
        });
    }

    {
        auto fields = BuildCommonHeaderFields();
        fields.push_back(MakeField("KeyExchange.Salt", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, Salt), sizeof(((SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*)nullptr)->Salt),
            KernelFieldEncoding::FixedBytes, "HKDF salt used to derive the wrapping key."));
        fields.push_back(MakeField("KeyExchange.Nonce", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, Nonce), sizeof(((SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*)nullptr)->Nonce),
            KernelFieldEncoding::FixedBytes, "AES-GCM nonce for the wrapped session key."));
        fields.push_back(MakeField("KeyExchange.WrappedSessionKey", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, WrappedSessionKey), sizeof(((SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*)nullptr)->WrappedSessionKey),
            KernelFieldEncoding::FixedBytes, "Wrapped per-session AES key."));
        fields.push_back(MakeField("KeyExchange.Tag", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, Tag), sizeof(((SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*)nullptr)->Tag),
            KernelFieldEncoding::FixedBytes, "AES-GCM authentication tag for WrappedSessionKey."));
        fields.push_back(MakeField("KeyExchange.SessionNoncePrefix", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, SessionNoncePrefix), sizeof(((SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*)nullptr)->SessionNoncePrefix),
            KernelFieldEncoding::FixedBytes, "Nonce prefix reused by subsequent encrypted messages."));
        fields.push_back(MakeField("KeyExchange.KeyExpirySeconds", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, KeyExpirySeconds), sizeof(UINT32),
            KernelFieldEncoding::UnsignedInteger, "Suggested lifetime of the session key."));
        fields.push_back(MakeField("KeyExchange.ProtocolFlags", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, ProtocolFlags), sizeof(UINT32),
            KernelFieldEncoding::BitFlags, "Protocol negotiation flags, including mandatory encryption."));
        fields.push_back(MakeField("KeyExchange.Reserved", offsetof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE, Reserved), sizeof(UINT32),
            KernelFieldEncoding::UnsignedInteger, "Reserved field that should remain zero."));

        schemas.push_back(KernelMessageSchema{
            "phantomsensor.key-exchange-message",
            "phantomcore.ipc.filter-port-client",
            "key-exchange-inbound-baseline",
            FilterMessageType_KeyExchange,
            "KeyExchange",
            "kernel-to-user",
            sizeof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE),
            "Inbound key-exchange frame sent by the kernel to establish per-session encryption material.",
            { "Header.Flags should include SHADOWSTRIKE_MSG_FLAG_ENCRYPTED for canonical key exchange traffic.",
              "Header.DataSize must equal sizeof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE) - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)." },
            { "auth-tag-corruption", "nonce-reuse", "missing-encryption-flag", "protocol-flag-confusion" },
            std::move(fields),
            {}
        });
    }

    return schemas;
}

void RenderStringArray(std::ostringstream& stream,
    const std::string_view name,
    const std::vector<std::string>& values,
    const std::string_view indent)
{
    stream << indent << '"' << name << "\": [";
    if (!values.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < values.size(); ++index) {
            stream << indent << "  \"" << EscapeJson(values[index]) << '"';
            if (index + 1 != values.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << indent;
    }
    stream << ']';
}

}  // namespace

std::string_view ToString(const KernelFieldEncoding encoding) {
    switch (encoding) {
    case KernelFieldEncoding::UnsignedInteger:
        return "unsigned-integer";
    case KernelFieldEncoding::BitFlags:
        return "bit-flags";
    case KernelFieldEncoding::Boolean:
        return "boolean";
    case KernelFieldEncoding::EnumValue:
        return "enum-value";
    case KernelFieldEncoding::FixedBytes:
        return "fixed-bytes";
    case KernelFieldEncoding::FixedAnsiString:
        return "fixed-ansi-string";
    case KernelFieldEncoding::WideCharCount:
        return "wide-char-count";
    case KernelFieldEncoding::ByteCount:
        return "byte-count";
    }

    return "unknown";
}

const std::vector<KernelMessageSchema>& KernelMessageSchemaCatalog::GetSchemas() {
    static const std::vector<KernelMessageSchema> schemas = BuildSchemas();
    return schemas;
}

const KernelMessageSchema* KernelMessageSchemaCatalog::FindById(const std::string_view id) {
    const auto& schemas = GetSchemas();
    const auto match = std::find_if(schemas.begin(), schemas.end(),
        [&](const KernelMessageSchema& schema) { return schema.id == id; });
    return match == schemas.end() ? nullptr : &(*match);
}

std::string KernelMessageSchemaCatalog::RenderJson(const std::vector<KernelMessageSchema>& schemas) {
    std::ostringstream stream;
    stream << "{\n  \"schemas\": [\n";

    for (std::size_t schemaIndex = 0; schemaIndex < schemas.size(); ++schemaIndex) {
        const auto& schema = schemas[schemaIndex];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(schema.id) << "\",\n"
               << "      \"surfaceId\": \"" << EscapeJson(schema.surfaceId) << "\",\n"
               << "      \"seedId\": \"" << EscapeJson(schema.seedId) << "\",\n"
               << "      \"messageType\": " << schema.messageType << ",\n"
               << "      \"messageName\": \"" << EscapeJson(schema.messageName) << "\",\n"
               << "      \"direction\": \"" << EscapeJson(schema.direction) << "\",\n"
               << "      \"minimumSize\": " << schema.minimumSize << ",\n"
               << "      \"description\": \"" << EscapeJson(schema.description) << "\",\n";

        RenderStringArray(stream, "invariants", schema.invariants, "      ");
        stream << ",\n";
        RenderStringArray(stream, "mutationAxes", schema.mutationAxes, "      ");
        stream << ",\n";

        stream << "      \"fields\": [";
        if (!schema.fields.empty()) {
            stream << '\n';
            for (std::size_t fieldIndex = 0; fieldIndex < schema.fields.size(); ++fieldIndex) {
                const auto& field = schema.fields[fieldIndex];
                stream << "        {\n"
                       << "          \"name\": \"" << EscapeJson(field.name) << "\",\n"
                       << "          \"offset\": " << field.offset << ",\n"
                       << "          \"width\": " << field.width << ",\n"
                       << "          \"encoding\": \"" << ToString(field.encoding) << "\",\n"
                       << "          \"description\": \"" << EscapeJson(field.description) << "\",\n";
                RenderStringArray(stream, "invariants", field.invariants, "          ");
                stream << '\n'
                       << "        }";
                if (fieldIndex + 1 != schema.fields.size()) {
                    stream << ',';
                }
                stream << '\n';
            }
            stream << "      ";
        }
        stream << "],\n";

        stream << "      \"variableSegments\": [";
        if (!schema.variableSegments.empty()) {
            stream << '\n';
            for (std::size_t segmentIndex = 0; segmentIndex < schema.variableSegments.size(); ++segmentIndex) {
                const auto& segment = schema.variableSegments[segmentIndex];
                stream << "        {\n"
                       << "          \"name\": \"" << EscapeJson(segment.name) << "\",\n"
                       << "          \"lengthField\": \"" << EscapeJson(segment.lengthField) << "\",\n"
                       << "          \"elementWidth\": " << segment.elementWidth << ",\n"
                       << "          \"encoding\": \"" << EscapeJson(segment.encoding) << "\",\n"
                       << "          \"description\": \"" << EscapeJson(segment.description) << "\"\n"
                       << "        }";
                if (segmentIndex + 1 != schema.variableSegments.size()) {
                    stream << ',';
                }
                stream << '\n';
            }
            stream << "      ";
        }
        stream << "]\n"
               << "    }";

        if (schemaIndex + 1 != schemas.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer
