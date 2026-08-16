// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageFactory.hpp"

#include <Windows.h>

#include "../../PhantomSensor/Shared/MessageProtocol.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace ShadowStrike::Fuzzer {

namespace {

template <typename T>
void AppendPod(std::vector<std::uint8_t>& bytes, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);

    const auto* raw = reinterpret_cast<const std::uint8_t*>(&value);
    bytes.insert(bytes.end(), raw, raw + sizeof(T));
}

void AppendWideString(std::vector<std::uint8_t>& bytes, const std::wstring& value) {
    const auto* raw = reinterpret_cast<const std::uint8_t*>(value.data());
    bytes.insert(bytes.end(), raw, raw + (value.size() * sizeof(wchar_t)));
}

template <typename T>
[[nodiscard]] T ReadPod(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    static_assert(std::is_trivially_copyable_v<T>);

    if (offset > bytes.size() || (bytes.size() - offset) < sizeof(T)) {
        throw std::out_of_range("ReadPod offset exceeds buffer size");
    }

    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

template <typename T>
void WritePod(std::vector<std::uint8_t>& bytes, const std::size_t offset, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);

    if (offset > bytes.size() || (bytes.size() - offset) < sizeof(T)) {
        throw std::out_of_range("WritePod offset exceeds buffer size");
    }

    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

[[nodiscard]] std::vector<std::uint8_t> WrapMessage(
    const std::uint16_t messageType,
    const std::uint64_t messageId,
    std::vector<std::uint8_t> payload,
    const std::uint32_t flags = 0)
{
    SHADOWSTRIKE_MESSAGE_HEADER header{};
    header.Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    header.Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    header.MessageType = messageType;
    header.MessageId = messageId;
    header.TotalSize = static_cast<UINT32>(sizeof(header) + payload.size());
    header.DataSize = static_cast<UINT32>(payload.size());
    header.Timestamp = 0;
    header.Flags = flags;
    header.Reserved = 0;

    std::vector<std::uint8_t> framed;
    framed.reserve(sizeof(header) + payload.size());
    AppendPod(framed, header);
    framed.insert(framed.end(), payload.begin(), payload.end());
    return framed;
}

[[nodiscard]] BinarySeedArtifact MakeArtifact(
    std::string id,
    std::string surfaceId,
    std::string fileName,
    std::string description,
    std::vector<std::uint8_t> bytes,
    const BinarySeedKind kind,
    std::string schemaId,
    std::string parentId = {})
{
    return BinarySeedArtifact{
        std::move(id),
        std::move(surfaceId),
        std::move(fileName),
        std::move(description),
        std::move(bytes),
        kind,
        std::move(schemaId),
        std::move(parentId)
    };
}

[[nodiscard]] BinarySeedArtifact MakeVariantFromBase(
    const BinarySeedArtifact& base,
    std::string id,
    std::string description,
    std::vector<std::uint8_t> bytes)
{
    const std::string fileName = id + ".bin";
    return MakeArtifact(
        std::move(id),
        base.surfaceId,
        fileName,
        std::move(description),
        std::move(bytes),
        BinarySeedKind::StructuredVariant,
        base.schemaId,
        base.id);
}

[[nodiscard]] std::vector<std::uint8_t> MutateHeader(
    const BinarySeedArtifact& base,
    const auto& mutator)
{
    auto bytes = base.bytes;
    auto header = ReadPod<SHADOWSTRIKE_MESSAGE_HEADER>(bytes, 0);
    mutator(header);
    WritePod(bytes, 0, header);
    return bytes;
}

template <typename T, typename Mutator>
[[nodiscard]] std::vector<std::uint8_t> MutateStructAtOffset(
    const BinarySeedArtifact& base,
    const std::size_t offset,
    Mutator&& mutator)
{
    auto bytes = base.bytes;
    auto value = ReadPod<T>(bytes, offset);
    mutator(value);
    WritePod(bytes, offset, value);
    return bytes;
}

[[nodiscard]] BinarySeedArtifact MakeRegisterSeed() {
    return MakeArtifact(
        "register-baseline",
        "phantomsensor.commport.control-plane",
        "register-baseline.bin",
        "Minimal user-mode service registration frame.",
        WrapMessage(FilterMessageType_Register, 0x1001u, {}),
        BinarySeedKind::Baseline,
        "phantomsensor.register-message");
}

[[nodiscard]] BinarySeedArtifact MakeHeartbeatSeed() {
    return MakeArtifact(
        "heartbeat-baseline",
        "phantomsensor.commport.control-plane",
        "heartbeat-baseline.bin",
        "Heartbeat frame used to exercise lifecycle and keep-alive parsing.",
        WrapMessage(FilterMessageType_Heartbeat, 0x1002u, {}),
        BinarySeedKind::Baseline,
        "phantomsensor.heartbeat-message");
}

[[nodiscard]] BinarySeedArtifact MakeQueryDriverStatusSeed() {
    return MakeArtifact(
        "query-driver-status-baseline",
        "phantomsensor.commport.control-plane",
        "query-driver-status-baseline.bin",
        "Driver status query requiring an explicit reply path.",
        WrapMessage(FilterMessageType_QueryDriverStatus, 0x1003u, {}),
        BinarySeedKind::Baseline,
        "phantomsensor.query-driver-status-message");
}

[[nodiscard]] BinarySeedArtifact MakePolicyUpdateSeed() {
    SHADOWSTRIKE_POLICY_UPDATE policy{};
    policy.ScanOnOpen = TRUE;
    policy.ScanOnExecute = TRUE;
    policy.ScanOnWrite = TRUE;
    policy.EnableNotifications = TRUE;
    policy.BlockOnTimeout = FALSE;
    policy.BlockOnError = TRUE;
    policy.ScanNetworkFiles = TRUE;
    policy.ScanRemovableMedia = TRUE;
    policy.MaxScanFileSize = 64ull * 1024ull * 1024ull;
    policy.ScanTimeoutMs = 15'000u;
    policy.CacheTTLSeconds = 900u;
    policy.MaxPendingRequests = 1024u;
    policy.MqMaxQueueDepth = 2048u;
    policy.MqMaxMessageSize = 64u * 1024u;
    policy.MqBatchSize = 64u;
    policy.MqBatchTimeoutMs = 250u;

    std::vector<std::uint8_t> payload;
    payload.reserve(sizeof(policy));
    AppendPod(payload, policy);

    return MakeArtifact(
        "policy-update-baseline",
        "phantomsensor.commport.policy-update",
        "policy-update-baseline.bin",
        "Well-formed policy update exercising queue and timeout controls.",
        WrapMessage(FilterMessageType_UpdatePolicy, 0x1004u, std::move(payload)),
        BinarySeedKind::Baseline,
        "phantomsensor.policy-update-message");
}

[[nodiscard]] BinarySeedArtifact MakeProtectedProcessSeed() {
    SHADOWSTRIKE_PROTECTED_PROCESS proc{};
    proc.ProcessId = 4242u;
    proc.ProtectionFlags = 0x00000003u;

    constexpr wchar_t kName[] = L"ShadowStrikeService.exe";
    const std::size_t copyCount = std::min<std::size_t>(std::size(kName), std::size(proc.ProcessName));
    std::copy_n(kName, copyCount, proc.ProcessName);

    std::vector<std::uint8_t> payload;
    payload.reserve(sizeof(proc));
    AppendPod(payload, proc);

    return MakeArtifact(
        "register-protected-process-baseline",
        "phantomsensor.commport.policy-update",
        "register-protected-process-baseline.bin",
        "Protected-process registration with a populated process-name buffer.",
        WrapMessage(FilterMessageType_RegisterProtectedProcess, 0x1005u, std::move(payload)),
        BinarySeedKind::Baseline,
        "phantomsensor.protected-process-registration");
}

[[nodiscard]] BinarySeedArtifact MakeScanRequestSeed() {
    const std::wstring filePath = L"\\Device\\HarddiskVolume3\\Users\\Public\\payload.exe";
    const std::wstring processName = L"powershell.exe";

    FILE_SCAN_REQUEST request{};
    request.MessageId = 0x1006u;
    request.AccessType = 2u;
    request.Disposition = 1u;
    request.Priority = 4u;
    request.RequiresReply = 1u;
    request.ProcessId = 31337u;
    request.ThreadId = 808u;
    request.ParentProcessId = 404u;
    request.SessionId = 1u;
    request.FileSize = 98'304u;
    request.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
    request.DesiredAccess = GENERIC_READ | GENERIC_EXECUTE;
    request.ShareAccess = FILE_SHARE_READ;
    request.CreateOptions = 0x00000040u;  // FILE_NON_DIRECTORY_FILE
    request.VolumeSerial = 0x11223344u;
    request.FileId = 0x0102030405060708ull;
    request.IsDirectory = 0u;
    request.IsNetworkFile = 0u;
    request.IsRemovableMedia = 1u;
    request.HasADS = 0u;
    // BYTE counts, matching the wire contract in MessageProtocol.h.
    //
    // These were std::wstring::size(), i.e. CHARACTER counts, so every generated
    // scan-request frame declared exactly half the bytes it actually carried. The
    // seed corpus was therefore self-consistent but described a contract the
    // product does not implement, which means the boundary that matters - a length
    // that runs off the end of the delivered payload - was never actually reached.
    request.PathLength = static_cast<UINT16>(filePath.size() * sizeof(wchar_t));
    request.ProcessNameLength = static_cast<UINT16>(processName.size() * sizeof(wchar_t));

    std::vector<std::uint8_t> payload;
    payload.reserve(sizeof(request) + ((filePath.size() + processName.size()) * sizeof(wchar_t)));
    AppendPod(payload, request);
    AppendWideString(payload, filePath);
    AppendWideString(payload, processName);

    return MakeArtifact(
        "scan-request-baseline",
        "phantomsensor.commport.scan-request",
        "scan-request-baseline.bin",
        "Variable-length scan request with realistic path, process, and access metadata.",
        WrapMessage(FilterMessageType_ScanRequest, 0x1006u, std::move(payload)),
        BinarySeedKind::Baseline,
        "phantomsensor.scan-request-message");
}

[[nodiscard]] BinarySeedArtifact MakePushHashDatabaseSeed() {
    SHADOWSTRIKE_PUSH_BATCH_HEADER batch{};
    batch.EntryCount = 1u;
    batch.EntrySize = sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY);
    batch.TotalDataSize = sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY);
    batch.Flags = SHADOWSTRIKE_PUSH_FLAG_REPLACE;

    SHADOWSTRIKE_PUSH_HASH_ENTRY entry{};
    entry.HashType = 2u;
    entry.Verdict = 2u;
    entry.Severity = 3u;
    entry.Score = 95u;
    std::memcpy(entry.Hash, "0123456789abcdef0123456789abcdef", 32u);
    std::memcpy(entry.ThreatName, "ShadowStrike.Test.Malware", 25u);
    entry.Expiry.QuadPart = 0;

    std::vector<std::uint8_t> payload;
    payload.reserve(sizeof(batch) + sizeof(entry));
    AppendPod(payload, batch);
    AppendPod(payload, entry);

    return MakeArtifact(
        "push-hash-database-baseline",
        "phantomsensor.commport.data-push-batches",
        "push-hash-database-baseline.bin",
        "Single-entry hash database batch for IOC ingestion fuzzing.",
        WrapMessage(FilterMessageType_PushHashDatabase, 0x1007u, std::move(payload)),
        BinarySeedKind::Baseline,
        "phantomsensor.push-hash-database-message");
}

[[nodiscard]] BinarySeedArtifact MakeExclusionUpdateSeed() {
    const std::wstring exclusion = L"\\Device\\HarddiskVolume3\\Temp\\trusted\\";

    SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY entry{};
    entry.ExclusionType = 1u;
    entry.Operation = SHADOWSTRIKE_EXCL_OP_ADD;
    entry.Flags = 0u;
    entry.TTLSeconds = 3600u;
    entry.ValueLength = static_cast<UINT16>(exclusion.size());

    std::vector<std::uint8_t> payload;
    payload.reserve(sizeof(entry) + (exclusion.size() * sizeof(wchar_t)));
    AppendPod(payload, entry);
    AppendWideString(payload, exclusion);

    return MakeArtifact(
        "exclusion-update-baseline",
        "phantomsensor.commport.data-push-batches",
        "exclusion-update-baseline.bin",
        "Exclusion update with a variable-length path payload.",
        WrapMessage(FilterMessageType_ExclusionUpdate, 0x1008u, std::move(payload)),
        BinarySeedKind::Baseline,
        "phantomsensor.exclusion-update-message");
}

[[nodiscard]] BinarySeedArtifact MakeKeyExchangeSeed() {
    SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE message{};
    message.Header.Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    message.Header.Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    message.Header.MessageType = FilterMessageType_KeyExchange;
    message.Header.MessageId = 0x2001u;
    message.Header.TotalSize = static_cast<UINT32>(sizeof(message));
    message.Header.DataSize = static_cast<UINT32>(sizeof(message) - sizeof(message.Header));
    message.Header.Timestamp = 0;
    message.Header.Flags = SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
    message.Header.Reserved = 0;
    message.KeyExpirySeconds = 300u;
    message.ProtocolFlags = SHADOWSTRIKE_KEX_PROTOCOL_FLAG_MANDATORY_ENCRYPTION;

    for (std::size_t i = 0; i < std::size(message.Salt); ++i) {
        message.Salt[i] = static_cast<UCHAR>(i);
    }

    for (std::size_t i = 0; i < std::size(message.Nonce); ++i) {
        message.Nonce[i] = static_cast<UCHAR>(0xA0u + i);
    }

    for (std::size_t i = 0; i < std::size(message.WrappedSessionKey); ++i) {
        message.WrappedSessionKey[i] = static_cast<UCHAR>(0x30u + i);
    }

    for (std::size_t i = 0; i < std::size(message.Tag); ++i) {
        message.Tag[i] = static_cast<UCHAR>(0xD0u + i);
    }

    for (std::size_t i = 0; i < std::size(message.SessionNoncePrefix); ++i) {
        message.SessionNoncePrefix[i] = static_cast<UCHAR>(0xF0u + i);
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(sizeof(message));
    AppendPod(bytes, message);

    return MakeArtifact(
        "key-exchange-inbound-baseline",
        "phantomcore.ipc.filter-port-client",
        "key-exchange-inbound-baseline.bin",
        "Kernel-originated key exchange frame for user-mode filter-port client fuzzing.",
        std::move(bytes),
        BinarySeedKind::Baseline,
        "phantomsensor.key-exchange-message");
}

[[nodiscard]] const std::vector<BinarySeedArtifact>& GetSeedCatalog() {
    static const std::vector<BinarySeedArtifact> seeds = {
        MakeRegisterSeed(),
        MakeHeartbeatSeed(),
        MakeQueryDriverStatusSeed(),
        MakePolicyUpdateSeed(),
        MakeProtectedProcessSeed(),
        MakeScanRequestSeed(),
        MakePushHashDatabaseSeed(),
        MakeExclusionUpdateSeed(),
        MakeKeyExchangeSeed()
    };

    return seeds;
}

[[nodiscard]] const BinarySeedArtifact& GetRequiredSeed(std::string_view id) {
    const auto& seeds = GetSeedCatalog();
    const auto match = std::find_if(seeds.begin(), seeds.end(),
        [&](const BinarySeedArtifact& seed) { return seed.id == id; });

    if (match == seeds.end()) {
        throw std::logic_error("Required baseline seed is missing");
    }

    return *match;
}

[[nodiscard]] BinarySeedArtifact MakeRegisterInvalidMagicVariant() {
    const auto& base = GetRequiredSeed("register-baseline");
    return MakeVariantFromBase(
        base,
        "register-invalid-magic",
        "Registration frame with a corrupted protocol magic value.",
        MutateHeader(base, [](SHADOWSTRIKE_MESSAGE_HEADER& header) { header.Magic = 0x00000000u; }));
}

[[nodiscard]] BinarySeedArtifact MakeRegisterUnsupportedVersionVariant() {
    const auto& base = GetRequiredSeed("register-baseline");
    return MakeVariantFromBase(
        base,
        "register-unsupported-version",
        "Registration frame with an unsupported protocol version.",
        MutateHeader(base, [](SHADOWSTRIKE_MESSAGE_HEADER& header) { header.Version = std::numeric_limits<UINT16>::max(); }));
}

[[nodiscard]] BinarySeedArtifact MakeQueryDriverStatusNoAckVariant() {
    const auto& base = GetRequiredSeed("query-driver-status-baseline");
    return MakeVariantFromBase(
        base,
        "query-driver-status-no-ack",
        "Driver-status query that suppresses acknowledgment semantics with SHADOWSTRIKE_MSG_FLAG_NO_ACK.",
        MutateHeader(base, [](SHADOWSTRIKE_MESSAGE_HEADER& header) { header.Flags = SHADOWSTRIKE_MSG_FLAG_NO_ACK; }));
}

[[nodiscard]] BinarySeedArtifact MakePolicyQueueSaturationVariant() {
    const auto& base = GetRequiredSeed("policy-update-baseline");
    constexpr std::size_t kPayloadOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "policy-update-queue-saturation",
        "Policy update that pushes queue-related knobs to saturation values and zero timeout edge cases.",
        MutateStructAtOffset<SHADOWSTRIKE_POLICY_UPDATE>(base, kPayloadOffset,
            [](SHADOWSTRIKE_POLICY_UPDATE& policy) {
                policy.MaxScanFileSize = std::numeric_limits<UINT64>::max();
                policy.ScanTimeoutMs = 0u;
                policy.CacheTTLSeconds = 0u;
                policy.MaxPendingRequests = std::numeric_limits<ULONG>::max();
                policy.MqMaxQueueDepth = std::numeric_limits<ULONG>::max();
                policy.MqMaxMessageSize = std::numeric_limits<ULONG>::max();
                policy.MqBatchSize = std::numeric_limits<ULONG>::max();
                policy.MqBatchTimeoutMs = 0u;
            }));
}

[[nodiscard]] BinarySeedArtifact MakeScanRequestPathOverclaimVariant() {
    const auto& base = GetRequiredSeed("scan-request-baseline");
    constexpr std::size_t kPayloadOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "scan-request-path-length-overclaim",
        "Scan request whose PathLength exceeds the actual UTF-16 tail carried in the frame.",
        MutateStructAtOffset<FILE_SCAN_REQUEST>(base, kPayloadOffset,
            [](FILE_SCAN_REQUEST& request) {
                request.PathLength = static_cast<UINT16>(request.PathLength + 64u);
            }));
}

[[nodiscard]] BinarySeedArtifact MakeScanRequestProcessNameOverclaimVariant() {
    const auto& base = GetRequiredSeed("scan-request-baseline");
    constexpr std::size_t kPayloadOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "scan-request-process-name-overclaim",
        "Scan request whose ProcessNameLength exceeds the trailing process-name bytes.",
        MutateStructAtOffset<FILE_SCAN_REQUEST>(base, kPayloadOffset,
            [](FILE_SCAN_REQUEST& request) {
                request.ProcessNameLength = static_cast<UINT16>(request.ProcessNameLength + 32u);
            }));
}

[[nodiscard]] BinarySeedArtifact MakeScanRequestTruncatedTailVariant() {
    const auto& base = GetRequiredSeed("scan-request-baseline");
    auto bytes = base.bytes;
    bytes.resize(bytes.size() - sizeof(wchar_t));
    return MakeVariantFromBase(
        base,
        "scan-request-truncated-tail",
        "Scan request with a truncated UTF-16 tail while the transport header still advertises the original payload size.",
        std::move(bytes));
}

[[nodiscard]] BinarySeedArtifact MakePushHashEntryCountMismatchVariant() {
    const auto& base = GetRequiredSeed("push-hash-database-baseline");
    constexpr std::size_t kBatchOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "push-hash-database-entrycount-mismatch",
        "Hash push batch advertising two entries while carrying only one serialized record.",
        MutateStructAtOffset<SHADOWSTRIKE_PUSH_BATCH_HEADER>(base, kBatchOffset,
            [](SHADOWSTRIKE_PUSH_BATCH_HEADER& batch) {
                batch.EntryCount = 2u;
                batch.TotalDataSize = sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY) * 2u;
            }));
}

[[nodiscard]] BinarySeedArtifact MakePushHashBatchLimitPlusOneVariant() {
    const auto& base = GetRequiredSeed("push-hash-database-baseline");
    constexpr std::size_t kBatchOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "push-hash-database-batch-limit-plus-one",
        "Hash push batch that exceeds SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES by one entry.",
        MutateStructAtOffset<SHADOWSTRIKE_PUSH_BATCH_HEADER>(base, kBatchOffset,
            [](SHADOWSTRIKE_PUSH_BATCH_HEADER& batch) {
                batch.EntryCount = SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES + 1u;
                batch.TotalDataSize = batch.EntryCount * static_cast<UINT32>(sizeof(SHADOWSTRIKE_PUSH_HASH_ENTRY));
            }));
}

[[nodiscard]] BinarySeedArtifact MakeExclusionValueLengthOverclaimVariant() {
    const auto& base = GetRequiredSeed("exclusion-update-baseline");
    constexpr std::size_t kEntryOffset = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    return MakeVariantFromBase(
        base,
        "exclusion-update-value-length-overclaim",
        "Exclusion update whose ValueLength exceeds the actual UTF-16 value bytes in the frame.",
        MutateStructAtOffset<SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY>(base, kEntryOffset,
            [](SHADOWSTRIKE_PUSH_EXCLUSION_ENTRY& entry) {
                entry.ValueLength = static_cast<UINT16>(entry.ValueLength + 48u);
            }));
}

[[nodiscard]] BinarySeedArtifact MakeKeyExchangeMissingEncryptedFlagVariant() {
    const auto& base = GetRequiredSeed("key-exchange-inbound-baseline");
    return MakeVariantFromBase(
        base,
        "key-exchange-missing-encrypted-flag",
        "Key-exchange frame whose header omits SHADOWSTRIKE_MSG_FLAG_ENCRYPTED.",
        MutateHeader(base, [](SHADOWSTRIKE_MESSAGE_HEADER& header) { header.Flags = 0u; }));
}

[[nodiscard]] BinarySeedArtifact MakeKeyExchangeZeroTagVariant() {
    const auto& base = GetRequiredSeed("key-exchange-inbound-baseline");
    auto bytes = base.bytes;
    auto message = ReadPod<SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE>(bytes, 0);
    std::fill(std::begin(message.Tag), std::end(message.Tag), static_cast<UCHAR>(0));
    WritePod(bytes, 0, message);
    return MakeVariantFromBase(
        base,
        "key-exchange-zero-tag",
        "Key-exchange frame with an all-zero AES-GCM authentication tag.",
        std::move(bytes));
}

[[nodiscard]] const std::vector<BinarySeedArtifact>& GetVariantCatalog() {
    static const std::vector<BinarySeedArtifact> variants = {
        MakeRegisterInvalidMagicVariant(),
        MakeRegisterUnsupportedVersionVariant(),
        MakeQueryDriverStatusNoAckVariant(),
        MakePolicyQueueSaturationVariant(),
        MakeScanRequestPathOverclaimVariant(),
        MakeScanRequestProcessNameOverclaimVariant(),
        MakeScanRequestTruncatedTailVariant(),
        MakePushHashEntryCountMismatchVariant(),
        MakePushHashBatchLimitPlusOneVariant(),
        MakeExclusionValueLengthOverclaimVariant(),
        MakeKeyExchangeMissingEncryptedFlagVariant(),
        MakeKeyExchangeZeroTagVariant()
    };

    return variants;
}

}  // namespace

std::string_view ToString(const BinarySeedKind kind) {
    switch (kind) {
    case BinarySeedKind::Baseline:
        return "baseline";
    case BinarySeedKind::StructuredVariant:
        return "structured-variant";
    }

    return "unknown";
}

std::vector<BinarySeedArtifact> KernelMessageFactory::BuildBaselineSeedSet() {
    return GetSeedCatalog();
}

std::vector<BinarySeedArtifact> KernelMessageFactory::BuildStructuredVariantSeedSet() {
    return GetVariantCatalog();
}

std::vector<BinarySeedArtifact> KernelMessageFactory::BuildFullSeedSet() {
    std::vector<BinarySeedArtifact> corpus = GetSeedCatalog();
    const auto& variants = GetVariantCatalog();
    corpus.insert(corpus.end(), variants.begin(), variants.end());
    return corpus;
}

std::optional<BinarySeedArtifact> KernelMessageFactory::BuildById(const std::string_view id) {
    const auto corpus = BuildFullSeedSet();
    const auto match = std::find_if(corpus.begin(), corpus.end(),
        [&](const BinarySeedArtifact& seed) { return seed.id == id; });

    if (match == corpus.end()) {
        return std::nullopt;
    }

    return *match;
}

}  // namespace ShadowStrike::Fuzzer
