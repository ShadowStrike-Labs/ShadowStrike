/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - Integration Tests: Communication Pipeline
 * ============================================================================
 *
 * @file CommunicationPipeline_Integration_Tests.cpp
 * @brief Enterprise-grade integration tests for the cross-module communication
 *        pipeline:
 *
 *          AlertSystem       <->  MessageDispatcher
 *          MessageDispatcher <->  TelemetryCollector
 *          AlertSystem       <->  TelemetryCollector
 *
 * COVERAGE SURFACE
 * ================
 *  GROUP  1  Pipeline_Lifecycle              — singleton init/shutdown contracts
 *  GROUP  2  MessageDispatcher_Parse         — wire-format parse edge cases
 *  GROUP  3  MessageDispatcher_Dispatch      — handler registration & routing
 *  GROUP  4  MessageDispatcher_Statistics    — counter accuracy & reset
 *  GROUP  5  AlertSystem_CoreOperations      — raise/ack/resolve/escalate/get
 *  GROUP  6  AlertSystem_RecipientWebhook    — recipient & webhook management
 *  GROUP  7  AlertSystem_Suppression         — suppression rule lifecycle
 *  GROUP  8  AlertSystem_Callbacks           — alert/delivery/escalation events
 *  GROUP  9  AlertSystem_Statistics          — counter accuracy & reset
 *  GROUP 10  TelemetryCollector_Events       — event recording & queue
 *  GROUP 11  TelemetryCollector_Consent      — consent gating & anonymization
 *  GROUP 12  TelemetryCollector_Statistics   — counter accuracy & reset
 *  GROUP 13  CrossPipeline_AlertToTelemetry  — alert callback → telemetry record
 *  GROUP 14  CrossPipeline_DispatchToAlert   — dispatch handler → alert raise
 *  GROUP 15  TypeContracts                   — enum ordinals, struct invariants
 *
 * DESIGN NOTES
 * ============
 * - No mocks. AlertSystem and TelemetryCollector use their real singleton
 *   implementations. All I/O and event queuing is performed against real
 *   in-memory state.
 * - MessageDispatcher is constructed per-test with a disconnected
 *   FilterConnection (no kernel driver required). Parsing and dispatch
 *   routing are fully exercisable without a live kernel port; only reply
 *   delivery silently fails (replyErrors counter is non-zero for ScanRequest
 *   dispatches — this is the expected behaviour and is asserted where relevant).
 * - Both singleton classes are initialised exactly once per process via a
 *   shared helper; subsequent calls to Initialize() when IsInitialized() is
 *   true are no-ops. This satisfies the Meyers' Singleton contract.
 * - Wire-format buffer builders in the anonymous namespace reconstruct the
 *   packed kernel structs (MessageHeader + payload) exactly as the kernel
 *   minifilter would produce them, ensuring parse tests exercise the real
 *   production code paths.
 *
 * BUILD
 * =====
 * cl /nologo /std:c++20 /EHsc /W4 /c /I. /Isrc /Iinclude /Iinclude\YARA ^
 *    tests\integration\communication_pipeline\CommunicationPipeline_Integration_Tests.cpp ^
 *    /FoCommunicationPipeline_Integration_Tests.obj
 *
 * @author  ShadowStrike Security Team
 * @version 1.0.0
 */

// ============================================================================
// WINDOWS / STL PREREQUISITES
// ============================================================================

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// GTEST
// ============================================================================

#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================

#include "src/PhantomCore/Communication/AlertSystem.hpp"
#include "src/PhantomCore/Communication/TelemetryCollector.hpp"
#include "src/PhantomCore/Communication/MessageDispatcher.hpp"
#include "src/PhantomCore/Communication/FilterConnection.hpp"
#include "src/PhantomCore/Communication/Communication.hpp"

// ============================================================================
// NAMESPACE ALIASES
// ============================================================================

namespace Comm = ShadowStrike::Communication;

using Comm::AlertSystem;
using Comm::AlertConfiguration;
using Comm::AlertSeverity;
using Comm::AlertType;
using Comm::AlertStatus;
using Comm::Alert;
using Comm::EscalationLevel;
using Comm::EscalationRule;
using Comm::SuppressionRule;
using Comm::AlertRecipient;
using Comm::WebhookConfiguration;
using Comm::DeliveryChannel;
using Comm::ModuleStatus;

using Comm::TelemetryCollector;
using Comm::TelemetryConfiguration;
using Comm::TelemetryEvent;
using Comm::TelemetryEventType;
using Comm::DetectionEventData;
using Comm::HealthEventData;
using Comm::PerformanceEventData;
using Comm::CrashEventData;
using Comm::ConsentLevel;
using Comm::AnonymizationLevel;
using Comm::TelemetryModuleStatus;

using Comm::MessageDispatcher;
using Comm::FilterConnection;
using Comm::MessageHeader;
using Comm::MessageType;
using Comm::ScanVerdict;
using Comm::FileScanRequest;
using Comm::ProcessNotification;
using Comm::RegistryNotification;
using Comm::ScanVerdictReply;
using Comm::FileScanRequestData;
// ProcessNotificationData / RegistryNotificationData intentionally absent: both
// described layouts the driver never emitted and were deleted from
// Communication.hpp. The payload builders below use the kernel structs from
// PhantomSensor/Shared/MessageProtocol.h, which arrive via Communication.hpp.
using Comm::MESSAGE_MAGIC;
using Comm::PROTOCOL_VERSION;

// ============================================================================
// SUITE-LEVEL SHARED STATE
// ============================================================================

namespace {

// ---------------------------------------------------------------------------
// Idempotent singleton initializers — safe to call from any test fixture's
// SetUpTestSuite(), even when a sibling fixture has already initialised them.
// ---------------------------------------------------------------------------

[[nodiscard]] bool EnsureAlertSystemInit() noexcept {
    auto& as = AlertSystem::Instance();
    if (as.IsInitialized()) return true;

    AlertConfiguration cfg;
    cfg.enabled              = true;
    cfg.enableDeduplication  = false;   // avoid suppressing rapid test alerts
    cfg.rateLimitPerMinute   = 10000;   // effectively no rate limiting in tests
    cfg.retryFailed          = false;
    cfg.defaultChannels      = DeliveryChannel::None; // no real delivery in tests
    return as.Initialize(cfg);
}

// Polls GetAlert() until the alert appears in m_history (i.e. the async worker
// has processed it) or the timeout elapses. Tests must call this after
// RaiseAlert() and before any operation that requires the alert in history
// (GetAlert, AcknowledgeAlert, ResolveAlert, EscalateAlert, GetAlertsByStatus).
[[nodiscard]] bool WaitForAlertInHistory(
    const std::string& alertId,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) noexcept
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (AlertSystem::Instance().GetAlert(alertId).has_value())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

[[nodiscard]] bool EnsureTelemetryCollectorInit() noexcept {
    auto& tc = TelemetryCollector::Instance();
    if (tc.IsInitialized()) return true;

    TelemetryConfiguration cfg;
    cfg.enabled            = true;
    cfg.consentLevel       = ConsentLevel::Full;
    cfg.anonymizationLevel = AnonymizationLevel::None;  // raw data in tests
    cfg.batchSize          = 1000;
    cfg.maxQueueSize       = 10000;
    return tc.Initialize(cfg);
}

// ---------------------------------------------------------------------------
// Wire-format buffer builder: header + arbitrary payload
// Produces a fully-valid MessageBuffer as the kernel minifilter would emit.
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<uint8_t> BuildMessage(
    MessageType     type,
    uint64_t        messageId,
    const void*     payload,
    size_t          payloadSize)
{
    const size_t totalSize = sizeof(MessageHeader) + payloadSize;
    std::vector<uint8_t> buf(totalSize, 0);

    auto* hdr          = reinterpret_cast<MessageHeader*>(buf.data());
    hdr->magic         = MESSAGE_MAGIC;
    hdr->version       = PROTOCOL_VERSION;
    hdr->messageType   = static_cast<uint16_t>(type);
    hdr->messageId     = messageId;
    hdr->totalSize     = static_cast<uint32_t>(totalSize);
    hdr->dataSize      = static_cast<uint32_t>(payloadSize);
    hdr->timestamp     = 0;
    hdr->flags         = 0;
    hdr->reserved      = 0;

    if (payloadSize > 0 && payload != nullptr)
        std::memcpy(buf.data() + sizeof(MessageHeader), payload, payloadSize);

    return buf;
}

// ---------------------------------------------------------------------------
// Build a minimal, valid FileScanRequest payload (no trailing variable data).
// pathLen and procLen specify the character counts; wchar_t zeros are appended.
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<uint8_t> BuildFileScanPayload(
    uint64_t        messageId,
    const wchar_t*  filePath,
    uint16_t        pathLen,
    const wchar_t*  procName,
    uint16_t        procLen,
    uint32_t        pid         = 4,
    uint8_t         requiresReply = 0)
{
    FileScanRequestData fsr{};
    fsr.messageId         = messageId;
    fsr.accessType        = static_cast<uint8_t>(Comm::FileAccessType::Execute);
    fsr.priority          = static_cast<uint8_t>(Comm::ScanPriority::Normal);
    fsr.processId         = pid;
    fsr.fileSize          = 0x10000;
    fsr.requiresReply     = requiresReply;
    // The pathLen / procLen PARAMETERS are CHARACTER counts, because that is what
    // every call site below passes and what the sibling process-notification
    // helper does. The WIRE FIELDS are BYTE counts, because that is what
    // FILE_SCAN_REQUEST declares and what all three kernel builders now write.
    // The conversion happens here, once, so no call site has to know.
    fsr.pathLength        = static_cast<uint16_t>(pathLen * sizeof(wchar_t));
    fsr.processNameLength = static_cast<uint16_t>(procLen * sizeof(wchar_t));

    const size_t pathBytes = static_cast<size_t>(pathLen)  * sizeof(wchar_t);
    const size_t procBytes = static_cast<size_t>(procLen)  * sizeof(wchar_t);
    std::vector<uint8_t> payload(sizeof(FileScanRequestData) + pathBytes + procBytes, 0);

    std::memcpy(payload.data(), &fsr, sizeof(FileScanRequestData));
    if (pathLen > 0)
        std::memcpy(payload.data() + sizeof(FileScanRequestData), filePath, pathBytes);
    if (procLen > 0)
        std::memcpy(payload.data() + sizeof(FileScanRequestData) + pathBytes, procName, procBytes);

    return payload;
}

// ---------------------------------------------------------------------------
// Build a minimal, valid ProcessNotification payload.
// ---------------------------------------------------------------------------

// Builds a real SHADOWSTRIKE_PROCESS_NOTIFICATION payload. The imageLen / cmdLen
// parameters remain CHARACTER counts because that is what every call site below
// passes; they are converted to the BYTE counts the wire actually carries. The
// previous version wrote character counts into the length fields of a fabricated
// 48-byte struct, so the payload it produced could not be parsed by anything that
// reads the driver's real format.
[[nodiscard]] std::vector<uint8_t> BuildProcessNotifyPayload(
    uint64_t        messageId,
    const wchar_t*  imagePath,
    uint16_t        imageLen,
    const wchar_t*  cmdLine,
    uint16_t        cmdLen,
    uint32_t        pid = 1234)
{
    // messageId has no home in this payload: SHADOWSTRIKE_PROCESS_NOTIFICATION does
    // not carry one. Correlation lives in the outer frame header. Accepted and
    // ignored so the call sites need not change.
    (void)messageId;

    const size_t imageBytes = static_cast<size_t>(imageLen) * sizeof(wchar_t);
    const size_t cmdBytes   = static_cast<size_t>(cmdLen)   * sizeof(wchar_t);

    SHADOWSTRIKE_PROCESS_NOTIFICATION pnd{};
    pnd.ProcessId         = pid;
    pnd.Create            = TRUE;
    pnd.ImagePathLength   = static_cast<uint16_t>(imageBytes);
    pnd.CommandLineLength = static_cast<uint16_t>(cmdBytes);

    std::vector<uint8_t> payload(sizeof(pnd) + imageBytes + cmdBytes, 0);

    std::memcpy(payload.data(), &pnd, sizeof(pnd));
    if (imageBytes > 0)
        std::memcpy(payload.data() + sizeof(pnd), imagePath, imageBytes);
    if (cmdBytes > 0)
        std::memcpy(payload.data() + sizeof(pnd) + imageBytes, cmdLine, cmdBytes);

    return payload;
}

// ---------------------------------------------------------------------------
// Build a minimal, valid RegistryNotification payload.
// ---------------------------------------------------------------------------

// Builds a real SHADOWSTRIKE_REGISTRY_NOTIFICATION payload. keyLen / valLen stay
// CHARACTER counts for the call sites and are converted to the BYTE counts the wire
// carries. This is the same wire format RegistryMonitor was corrected to in
// 5fe45d55; the fabricated 40-byte struct this replaced is what made that defect
// possible.
[[nodiscard]] std::vector<uint8_t> BuildRegistryNotifyPayload(
    uint64_t        messageId,
    const wchar_t*  keyPath,
    uint16_t        keyLen,
    const wchar_t*  valueName,
    uint16_t        valLen,
    uint32_t        pid = 1234)
{
    // No messageId on this payload either - correlation is in the outer header.
    (void)messageId;

    const size_t keyBytes = static_cast<size_t>(keyLen) * sizeof(wchar_t);
    const size_t valBytes = static_cast<size_t>(valLen) * sizeof(wchar_t);

    SHADOWSTRIKE_REGISTRY_NOTIFICATION rnd{};
    rnd.ProcessId       = pid;
    rnd.KeyPathLength   = static_cast<uint16_t>(keyBytes);
    rnd.ValueNameLength = static_cast<uint16_t>(valBytes);
    rnd.DataSize        = 0;

    std::vector<uint8_t> payload(sizeof(rnd) + keyBytes + valBytes, 0);

    std::memcpy(payload.data(), &rnd, sizeof(rnd));
    if (keyBytes > 0)
        std::memcpy(payload.data() + sizeof(rnd), keyPath, keyBytes);
    if (valBytes > 0)
        std::memcpy(payload.data() + sizeof(rnd) + keyBytes, valueName, valBytes);

    return payload;
}

// ---------------------------------------------------------------------------
// Fixture helper: create a MessageDispatcher backed by a disconnected port.
// The FilterConnection is constructed with a non-existent port name so that
// any incidental ReplyMessage() call fails gracefully instead of blocking.
// ---------------------------------------------------------------------------

struct DispatcherFixture {
    FilterConnection  connection{ L"\\NonExistentTestPort" };
    MessageDispatcher dispatcher{ connection };

    DispatcherFixture() = default;
    DispatcherFixture(const DispatcherFixture&) = delete;
    DispatcherFixture& operator=(const DispatcherFixture&) = delete;
};

} // anonymous namespace

// ============================================================================
// SKIP MACROS
// ============================================================================

#define SKIP_AS()                                                               \
    do {                                                                        \
        if (!s_asInit) {                                                        \
            GTEST_SKIP() << "AlertSystem::Initialize() returned false — "      \
                            "SMTP/webhook delivery not available in this env."; \
        }                                                                       \
    } while (false)

#define SKIP_TC()                                                               \
    do {                                                                        \
        if (!s_tcInit) {                                                        \
            GTEST_SKIP() << "TelemetryCollector::Initialize() returned false.";\
        }                                                                       \
    } while (false)

// ============================================================================
// GROUP 1 — Pipeline_Lifecycle
// ============================================================================
/**
 * Validates that each component can be initialised, reports correct status,
 * and that the singleton accessor returns a stable reference.
 */
class Pipeline_Lifecycle : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_asInit = EnsureAlertSystemInit();
        s_tcInit = EnsureTelemetryCollectorInit();
    }
    static bool s_asInit;
    static bool s_tcInit;
};
bool Pipeline_Lifecycle::s_asInit = false;
bool Pipeline_Lifecycle::s_tcInit = false;

// 1.1 AlertSystem singleton must initialize on any supported Windows platform.
TEST_F(Pipeline_Lifecycle, AlertSystem_Init_Succeeds) {
    EXPECT_TRUE(s_asInit)
        << "AlertSystem::Initialize() must succeed on a standard Windows environment.";
}

// 1.2 AlertSystem must report Running status after initialization.
TEST_F(Pipeline_Lifecycle, AlertSystem_Status_Running) {
    SKIP_AS();
    EXPECT_EQ(AlertSystem::Instance().GetStatus(), ModuleStatus::Running)
        << "AlertSystem must be in Running state after a successful Initialize().";
}

// 1.3 AlertSystem::HasInstance() must return true post-init.
TEST_F(Pipeline_Lifecycle, AlertSystem_HasInstance_True) {
    SKIP_AS();
    EXPECT_TRUE(AlertSystem::HasInstance());
}

// 1.4 AlertSystem version string must be non-empty.
TEST_F(Pipeline_Lifecycle, AlertSystem_VersionString_NonEmpty) {
    EXPECT_FALSE(AlertSystem::GetVersionString().empty())
        << "GetVersionString() must return a non-empty version identifier.";
}

// 1.5 TelemetryCollector singleton must initialize successfully.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_Init_Succeeds) {
    EXPECT_TRUE(s_tcInit)
        << "TelemetryCollector::Initialize() must succeed.";
}

// 1.6 TelemetryCollector must report Running status after initialization.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_Status_Running) {
    SKIP_TC();
    EXPECT_EQ(TelemetryCollector::Instance().GetStatus(), TelemetryModuleStatus::Running)
        << "TelemetryCollector must be in Running state after Initialize().";
}

// 1.7 TelemetryCollector version string must be non-empty.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_VersionString_NonEmpty) {
    EXPECT_FALSE(TelemetryCollector::GetVersionString().empty());
}

// 1.8 MessageDispatcher must be constructible from a disconnected FilterConnection.
TEST_F(Pipeline_Lifecycle, MessageDispatcher_Constructible_Disconnected) {
    EXPECT_NO_FATAL_FAILURE({
        DispatcherFixture f;
        (void)f;
    }) << "MessageDispatcher must not throw when constructed with a disconnected port.";
}

// 1.9 AlertSystem singleton accessor must return a stable reference address.
TEST_F(Pipeline_Lifecycle, AlertSystem_Instance_StableAddress) {
    SKIP_AS();
    auto* p1 = &AlertSystem::Instance();
    auto* p2 = &AlertSystem::Instance();
    EXPECT_EQ(p1, p2) << "Meyers' singleton must return the same instance every call.";
}

// 1.10 TelemetryCollector singleton accessor must return a stable reference.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_Instance_StableAddress) {
    SKIP_TC();
    auto* p1 = &TelemetryCollector::Instance();
    auto* p2 = &TelemetryCollector::Instance();
    EXPECT_EQ(p1, p2);
}

// ============================================================================
// GROUP 2 — MessageDispatcher_Parse
// ============================================================================
/**
 * Validates the static parse utilities against valid minimal payloads,
 * truncated buffers, zero-length paths, and adversarially crafted inputs
 * that could cause over-reads if bounds checks were absent.
 */
class MessageDispatcher_Parse : public ::testing::Test {};

// 2.1 ParseFileScanRequest with empty span must return nullopt.
TEST_F(MessageDispatcher_Parse, FileScan_Empty_ReturnsNullopt) {
    EXPECT_FALSE(MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>{}).has_value());
}

// 2.2 ParseFileScanRequest with truncated payload (1 byte) must return nullopt.
TEST_F(MessageDispatcher_Parse, FileScan_Truncated_ReturnsNullopt) {
    const uint8_t oneByte = 0xCC;
    EXPECT_FALSE(MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>(&oneByte, 1)).has_value());
}

// 2.3 ParseFileScanRequest with exactly sizeof(FileScanRequestData) bytes
//     and zero-length paths must produce a valid FileScanRequest.
TEST_F(MessageDispatcher_Parse, FileScan_MinimalValidPayload_Succeeds) {
    const auto payload = BuildFileScanPayload(0xABCD1234ULL, nullptr, 0, nullptr, 0, 4);
    const auto result  = MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>(payload));
    ASSERT_TRUE(result.has_value())
        << "A properly-formed FileScanRequestData with no variable data must parse.";
    EXPECT_EQ(result->messageId, 0xABCD1234ULL);
    EXPECT_EQ(result->processId, 4u);
    EXPECT_TRUE(result->filePath.empty());
    EXPECT_TRUE(result->processName.empty());
}

// 2.4 ParseFileScanRequest correctly extracts variable-length file path.
TEST_F(MessageDispatcher_Parse, FileScan_WithPath_Extracted) {
    const wchar_t path[] = L"C:\\Windows\\System32\\calc.exe";
    const wchar_t proc[] = L"explorer.exe";
    const uint16_t pathLen = static_cast<uint16_t>(wcslen(path));
    const uint16_t procLen = static_cast<uint16_t>(wcslen(proc));

    const auto payload = BuildFileScanPayload(
        0x1111ULL, path, pathLen, proc, procLen, 9876);
    const auto result  = MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>(payload));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filePath,    std::wstring(path));
    EXPECT_EQ(result->processName, std::wstring(proc));
    EXPECT_EQ(result->processId, 9876u);
}

// 2.5 ParseFileScanRequest with declared pathLength exceeding buffer must fail.
TEST_F(MessageDispatcher_Parse, FileScan_PathExceedsBuffer_ReturnsNullopt) {
    auto payload = BuildFileScanPayload(0x99ULL, nullptr, 0, nullptr, 0);
    // Corrupt the pathLength to an inflated value that exceeds the buffer.
    auto* fsr = reinterpret_cast<FileScanRequestData*>(payload.data());
    fsr->pathLength = 32767;
    EXPECT_FALSE(MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>(payload)).has_value())
        << "A pathLength overflowing the buffer must yield nullopt (no over-read).";
}

// 2.6 ParseProcessNotification with empty span must return nullopt.
TEST_F(MessageDispatcher_Parse, ProcessNotify_Empty_ReturnsNullopt) {
    EXPECT_FALSE(MessageDispatcher::ParseProcessNotification(
        std::span<const uint8_t>{}).has_value());
}

// 2.7 ParseProcessNotification with minimal valid payload succeeds.
TEST_F(MessageDispatcher_Parse, ProcessNotify_MinimalValidPayload_Succeeds) {
    const auto payload = BuildProcessNotifyPayload(0xBEEF1ULL, nullptr, 0, nullptr, 0, 5555);
    const auto result  = MessageDispatcher::ParseProcessNotification(
        std::span<const uint8_t>(payload));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->processId, 5555u);

    // This case previously required result->messageId == 0xBEEF1. It passed only
    // because both the builder and the parser used a fabricated struct that had a
    // messageId field; SHADOWSTRIKE_PROCESS_NOTIFICATION has none, and correlation
    // is carried in the outer frame header instead. Asserting the absence keeps the
    // contract honest: if a messageId ever appears here it came from somewhere other
    // than this payload, which is exactly the confusion worth failing on.
    EXPECT_EQ(result->messageId, 0ULL)
        << "the process notification payload carries no message id; a non-zero value "
           "means the parser invented one";
}

// 2.8 ParseProcessNotification correctly extracts image path and command line.
TEST_F(MessageDispatcher_Parse, ProcessNotify_WithStrings_Extracted) {
    const wchar_t image[] = L"C:\\malware\\dropper.exe";
    const wchar_t cmd[]   = L"dropper.exe --silent";
    const uint16_t imgLen = static_cast<uint16_t>(wcslen(image));
    const uint16_t cmdLen = static_cast<uint16_t>(wcslen(cmd));

    const auto payload = BuildProcessNotifyPayload(
        0x2222ULL, image, imgLen, cmd, cmdLen, 7777);
    const auto result  = MessageDispatcher::ParseProcessNotification(
        std::span<const uint8_t>(payload));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imagePath,   std::wstring(image));
    EXPECT_EQ(result->commandLine, std::wstring(cmd));
}

// 2.9 ParseRegistryNotification with empty span must return nullopt.
TEST_F(MessageDispatcher_Parse, RegistryNotify_Empty_ReturnsNullopt) {
    EXPECT_FALSE(MessageDispatcher::ParseRegistryNotification(
        std::span<const uint8_t>{}).has_value());
}

// 2.10 ParseRegistryNotification with minimal valid payload succeeds.
TEST_F(MessageDispatcher_Parse, RegistryNotify_MinimalValidPayload_Succeeds) {
    const auto payload = BuildRegistryNotifyPayload(
        0xCAFEULL, nullptr, 0, nullptr, 0, 8888);
    const auto result  = MessageDispatcher::ParseRegistryNotification(
        std::span<const uint8_t>(payload));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->processId, 8888u);
}

// 2.11 ParseRegistryNotification extracts key path and value name.
TEST_F(MessageDispatcher_Parse, RegistryNotify_WithStrings_Extracted) {
    const wchar_t key[] = L"HKLM\\Software\\Malware\\RunKey";
    const wchar_t val[] = L"AutoRun";
    const uint16_t kLen = static_cast<uint16_t>(wcslen(key));
    const uint16_t vLen = static_cast<uint16_t>(wcslen(val));

    const auto payload = BuildRegistryNotifyPayload(0xD00DULL, key, kLen, val, vLen);
    const auto result  = MessageDispatcher::ParseRegistryNotification(
        std::span<const uint8_t>(payload));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->keyPath,   std::wstring(key));
    EXPECT_EQ(result->valueName, std::wstring(val));
}

// 2.12 SerializeVerdictReply produces a non-empty buffer for a default reply.
TEST_F(MessageDispatcher_Parse, SerializeVerdictReply_DefaultReply_NonEmpty) {
    ScanVerdictReply reply;
    reply.messageId     = 0x1234567890ABCDEFULL;
    reply.verdict       = ScanVerdict::Clean;
    reply.threatDetected = false;
    reply.threatScore   = 0;
    reply.shouldCache   = true;
    reply.cacheTTL      = 60;

    const auto buf = MessageDispatcher::SerializeVerdictReply(reply);
    EXPECT_FALSE(buf.empty())
        << "SerializeVerdictReply must produce a non-empty byte buffer.";
    EXPECT_GE(buf.size(), sizeof(Comm::ScanVerdictReplyData));
}

// 2.13 SerializeVerdictReply encodes the verdict field correctly.
TEST_F(MessageDispatcher_Parse, SerializeVerdictReply_VerdictFieldCorrect) {
    ScanVerdictReply reply;
    reply.messageId  = 0xDEADBEEFULL;
    reply.verdict    = ScanVerdict::Malicious;
    reply.threatName = L"EICAR.Test.File";

    const auto buf = MessageDispatcher::SerializeVerdictReply(reply);
    ASSERT_GE(buf.size(), sizeof(Comm::ScanVerdictReplyData));

    const auto* data = reinterpret_cast<const Comm::ScanVerdictReplyData*>(buf.data());
    EXPECT_EQ(data->verdict, static_cast<uint8_t>(ScanVerdict::Malicious));
    EXPECT_EQ(data->messageId, 0xDEADBEEFULL);
    EXPECT_GT(data->threatNameLength, 0u);
}

// 2.14 ParseProcessNotification with ImagePathLength exceeding the buffer must return nullopt.
// Ensures no out-of-bounds read when a kernel-crafted packet is malformed.
TEST_F(MessageDispatcher_Parse, ProcessNotify_PathExceedsBuffer_ReturnsNullopt) {
    auto payload = BuildProcessNotifyPayload(0xFE00ULL, nullptr, 0, nullptr, 0);
    auto* pnd = reinterpret_cast<SHADOWSTRIKE_PROCESS_NOTIFICATION*>(payload.data());
    pnd->ImagePathLength = 32767;  // inflated length far exceeds buffer capacity
    EXPECT_FALSE(MessageDispatcher::ParseProcessNotification(
        std::span<const uint8_t>(payload)).has_value())
        << "An ImagePathLength that overflows the buffer must yield nullopt (no over-read).";
}

// 2.15 ParseRegistryNotification with ValueNameLength exceeding the buffer must return nullopt.
TEST_F(MessageDispatcher_Parse, RegistryNotify_ValueNameExceedsBuffer_ReturnsNullopt) {
    auto payload = BuildRegistryNotifyPayload(0xFE01ULL, nullptr, 0, nullptr, 0);
    auto* rnd = reinterpret_cast<SHADOWSTRIKE_REGISTRY_NOTIFICATION*>(payload.data());
    rnd->ValueNameLength = 32767;  // inflated length far exceeds buffer capacity
    EXPECT_FALSE(MessageDispatcher::ParseRegistryNotification(
        std::span<const uint8_t>(payload)).has_value())
        << "A ValueNameLength that overflows the buffer must yield nullopt (no over-read).";
}

// ============================================================================
// GROUP 3 — MessageDispatcher_Dispatch
// ============================================================================
/**
 * Validates routing from raw wire-format buffers to registered C++ callbacks,
 * including malformed-header rejection, type-to-handler dispatch, unknown
 * message handling, and the heartbeat fast-path.
 */
class MessageDispatcher_Dispatch : public ::testing::Test {
protected:
    DispatcherFixture f;
};

// 3.1 DispatchMessage with empty span must return false (parse error).
TEST_F(MessageDispatcher_Dispatch, Empty_ReturnsFalse) {
    EXPECT_FALSE(f.dispatcher.DispatchMessage(std::span<const uint8_t>{}));
}

// 3.2 DispatchMessage with a buffer smaller than MessageHeader must fail.
TEST_F(MessageDispatcher_Dispatch, TruncatedHeader_ReturnsFalse) {
    const std::array<uint8_t, 4> stub{0x01, 0x02, 0x03, 0x04};
    EXPECT_FALSE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(stub)));
}

// 3.3 DispatchMessage with wrong magic must fail.
TEST_F(MessageDispatcher_Dispatch, BadMagic_ReturnsFalse) {
    auto buf = BuildMessage(MessageType::ProcessNotify, 0x42ULL, nullptr, 0);
    // Corrupt the magic.
    auto* hdr = reinterpret_cast<MessageHeader*>(buf.data());
    hdr->magic = 0xDEADBEEFu;

    EXPECT_FALSE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.4 DispatchMessage with version above PROTOCOL_VERSION must fail.
TEST_F(MessageDispatcher_Dispatch, FutureVersion_ReturnsFalse) {
    auto buf = BuildMessage(MessageType::ProcessNotify, 0x43ULL, nullptr, 0);
    auto* hdr = reinterpret_cast<MessageHeader*>(buf.data());
    hdr->version = PROTOCOL_VERSION + 50u;  // deliberately invalid

    EXPECT_FALSE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.5 DispatchMessage with totalSize larger than buffer must fail.
TEST_F(MessageDispatcher_Dispatch, InflatedTotalSize_ReturnsFalse) {
    auto buf = BuildMessage(MessageType::Heartbeat, 0x44ULL, nullptr, 0);
    auto* hdr = reinterpret_cast<MessageHeader*>(buf.data());
    hdr->totalSize = static_cast<uint32_t>(buf.size()) + 100u;  // claims more bytes

    EXPECT_FALSE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.6 ProcessNotify message with a registered handler fires the handler.
TEST_F(MessageDispatcher_Dispatch, ProcessNotify_RegisteredHandler_Fires) {
    std::atomic<bool> handlerFired{false};

    f.dispatcher.RegisterProcessNotifyHandler(
        [&handlerFired](const ProcessNotification& n) {
            handlerFired.store(true, std::memory_order_release);
            (void)n;
        });

    const wchar_t image[] = L"C:\\Windows\\System32\\cmd.exe";
    const uint16_t imgLen = static_cast<uint16_t>(wcslen(image));
    const auto payload    = BuildProcessNotifyPayload(0x100ULL, image, imgLen, nullptr, 0, 1111);
    const auto msg        = BuildMessage(MessageType::ProcessNotify, 0x100ULL,
                                         payload.data(), payload.size());

    const bool result = f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    EXPECT_TRUE(result)  << "DispatchMessage must return true when a handler is registered.";
    EXPECT_TRUE(handlerFired.load(std::memory_order_acquire));
}

// 3.7 ProcessNotify handler receives the correctly decoded process ID.
TEST_F(MessageDispatcher_Dispatch, ProcessNotify_Handler_ReceivesCorrectPid) {
    uint32_t receivedPid = 0;

    f.dispatcher.RegisterProcessNotifyHandler(
        [&receivedPid](const ProcessNotification& n) {
            receivedPid = n.processId;
        });

    const auto payload = BuildProcessNotifyPayload(0x200ULL, nullptr, 0, nullptr, 0, 3579);
    const auto msg     = BuildMessage(MessageType::ProcessNotify, 0x200ULL,
                                       payload.data(), payload.size());

    ASSERT_TRUE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg)));
    EXPECT_EQ(receivedPid, 3579u);
}

// 3.8 RegistryNotify message with a registered handler fires and delivers key path.
TEST_F(MessageDispatcher_Dispatch, RegistryNotify_RegisteredHandler_Fires) {
    std::wstring receivedKey;

    f.dispatcher.RegisterRegistryNotifyHandler(
        [&receivedKey](const RegistryNotification& n) {
            receivedKey = n.keyPath;
        });

    const wchar_t key[] = L"HKCU\\Software\\TestKey";
    const uint16_t kLen = static_cast<uint16_t>(wcslen(key));
    const auto payload  = BuildRegistryNotifyPayload(0x300ULL, key, kLen, nullptr, 0);
    const auto msg      = BuildMessage(MessageType::RegistryNotify, 0x300ULL,
                                        payload.data(), payload.size());

    ASSERT_TRUE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg)));
    EXPECT_EQ(receivedKey, std::wstring(key));
}

// 3.9 Unknown message type must return false and increment unknownMessages.
TEST_F(MessageDispatcher_Dispatch, UnknownType_ReturnsFalse_IncrementsStat) {
    f.dispatcher.ResetStatistics();

    // MessageType::Max (43) is beyond all defined types.
    auto buf = BuildMessage(MessageType::Max, 0x400ULL, nullptr, 0);
    const bool result = f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf));

    EXPECT_FALSE(result);
    const auto snap = f.dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(snap.unknownMessages, 1u);
}

// 3.10 Alert-type message (HandleAlert) must be handled without crashing.
TEST_F(MessageDispatcher_Dispatch, AlertType_HandleAlert_Handled) {
    auto buf = BuildMessage(MessageType::HandleAlert, 0x500ULL, nullptr, 0);
    // Alert types are silently consumed — true means "handled" (no error).
    EXPECT_TRUE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.11 BehavioralAlert message must be handled (no handler registration needed).
TEST_F(MessageDispatcher_Dispatch, AlertType_BehavioralAlert_Handled) {
    auto buf = BuildMessage(MessageType::BehavioralAlert, 0x501ULL, nullptr, 0);
    EXPECT_TRUE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.12 Heartbeat message must be handled (regardless of reply failure).
TEST_F(MessageDispatcher_Dispatch, Heartbeat_Handled) {
    auto buf = BuildMessage(MessageType::Heartbeat, 0x600ULL, nullptr, 0);
    EXPECT_TRUE(f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf)));
}

// 3.13 SetDefaultVerdict(Malicious) causes ScanRequest to produce a Block reply.
//      We verify indirectly via the FileScanHandler callback return value.
TEST_F(MessageDispatcher_Dispatch, SetDefaultVerdict_Malicious_ReflectedInHandler) {
    f.dispatcher.SetDefaultVerdict(ScanVerdict::Malicious);

    ScanVerdict capturedVerdict = ScanVerdict::Unknown;
    f.dispatcher.RegisterFileScanHandler(
        [&capturedVerdict](const FileScanRequest& req) -> ScanVerdictReply {
            ScanVerdictReply reply;
            reply.messageId = req.messageId;
            reply.verdict   = ScanVerdict::Malicious;  // handler enforces block
            capturedVerdict = reply.verdict;
            return reply;
        });

    const wchar_t path[] = L"C:\\Temp\\payload.exe";
    const uint16_t pLen  = static_cast<uint16_t>(wcslen(path));
    const auto payload   = BuildFileScanPayload(0x700ULL, path, pLen, nullptr, 0, 4);
    const auto msg       = BuildMessage(MessageType::ScanRequest, 0x700ULL,
                                         payload.data(), payload.size());

    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    EXPECT_EQ(capturedVerdict, ScanVerdict::Malicious);
}

// 3.14 SetBlockOnError(false) — dispatch still handles the message even if
//      the handler throws a std::exception.
TEST_F(MessageDispatcher_Dispatch, HandlerException_BlockOnError_False_CleanVerdict) {
    f.dispatcher.SetBlockOnError(false);

    f.dispatcher.RegisterProcessNotifyHandler(
        [](const ProcessNotification&) {
            throw std::runtime_error("simulated handler crash");
        });

    f.dispatcher.ResetStatistics();
    const auto payload = BuildProcessNotifyPayload(0x800ULL, nullptr, 0, nullptr, 0);
    const auto msg     = BuildMessage(MessageType::ProcessNotify, 0x800ULL,
                                       payload.data(), payload.size());

    // DispatchMessage should not propagate the exception.
    EXPECT_NO_THROW((void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg)));

    const auto snap = f.dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_GE(snap.handlerErrors, 1u)
        << "A handler exception must be counted in handlerErrors.";
}

// 3.15 SetBlockOnTimeout(true) must not throw and must be observable without crashing.
TEST_F(MessageDispatcher_Dispatch, SetBlockOnTimeout_DoesNotThrow) {
    EXPECT_NO_FATAL_FAILURE({
        f.dispatcher.SetBlockOnTimeout(true);
        f.dispatcher.SetBlockOnTimeout(false);
    }) << "SetBlockOnTimeout() must not throw or crash on any bool value.";
}

// ============================================================================
// GROUP 4 — MessageDispatcher_Statistics
// ============================================================================
/**
 * Verifies that every dispatch code-path correctly increments the appropriate
 * atomic counter, that TakeSnapshot() produces a coherent POD copy, and that
 * ResetStatistics() atomically zeroes every field.
 */
class MessageDispatcher_Statistics : public ::testing::Test {
protected:
    DispatcherFixture f;
};

// 4.1 All statistics start at zero on a freshly-constructed dispatcher.
TEST_F(MessageDispatcher_Statistics, InitialCounters_AllZero) {
    const auto snap = f.dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(snap.messagesDispatched,     0u);
    EXPECT_EQ(snap.fileScanRequests,       0u);
    EXPECT_EQ(snap.processNotifications,   0u);
    EXPECT_EQ(snap.registryNotifications,  0u);
    EXPECT_EQ(snap.fileNotifications,      0u);
    EXPECT_EQ(snap.unknownMessages,        0u);
    EXPECT_EQ(snap.parseErrors,            0u);
    EXPECT_EQ(snap.handlerErrors,          0u);
    EXPECT_EQ(snap.repliesSent,            0u);
    EXPECT_EQ(snap.replyErrors,            0u);
}

// 4.2 parseErrors increments on every malformed header dispatch.
TEST_F(MessageDispatcher_Statistics, ParseErrors_IncrementOnBadMagic) {
    f.dispatcher.ResetStatistics();

    auto buf = BuildMessage(MessageType::ProcessNotify, 0x01ULL, nullptr, 0);
    reinterpret_cast<MessageHeader*>(buf.data())->magic = 0xBADBADBAu;
    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(buf));

    EXPECT_EQ(f.dispatcher.GetStatistics().TakeSnapshot().parseErrors, 1u);
}

// 4.3 processNotifications increments for each ProcessNotify dispatch.
TEST_F(MessageDispatcher_Statistics, ProcessNotifications_IncrementOnDispatch) {
    f.dispatcher.ResetStatistics();

    for (int i = 0; i < 5; ++i) {
        const auto payload = BuildProcessNotifyPayload(static_cast<uint64_t>(i),
                                                        nullptr, 0, nullptr, 0);
        const auto msg = BuildMessage(MessageType::ProcessNotify,
                                       static_cast<uint64_t>(i),
                                       payload.data(), payload.size());
        (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    }

    EXPECT_EQ(f.dispatcher.GetStatistics().TakeSnapshot().processNotifications, 5u);
}

// 4.4 registryNotifications increments for each RegistryNotify dispatch.
TEST_F(MessageDispatcher_Statistics, RegistryNotifications_IncrementOnDispatch) {
    f.dispatcher.ResetStatistics();

    for (int i = 0; i < 3; ++i) {
        const auto payload = BuildRegistryNotifyPayload(static_cast<uint64_t>(i),
                                                         nullptr, 0, nullptr, 0);
        const auto msg = BuildMessage(MessageType::RegistryNotify,
                                       static_cast<uint64_t>(i),
                                       payload.data(), payload.size());
        (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    }

    EXPECT_EQ(f.dispatcher.GetStatistics().TakeSnapshot().registryNotifications, 3u);
}

// 4.5 ResetStatistics() atomically zeroes all counters.
TEST_F(MessageDispatcher_Statistics, Reset_ZeroesAllCounters) {
    // Produce non-zero state first.
    const auto payload = BuildProcessNotifyPayload(0xABCULL, nullptr, 0, nullptr, 0);
    const auto msg     = BuildMessage(MessageType::ProcessNotify, 0xABCULL,
                                       payload.data(), payload.size());
    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));

    f.dispatcher.ResetStatistics();
    const auto snap = f.dispatcher.GetStatistics().TakeSnapshot();

    EXPECT_EQ(snap.messagesDispatched, 0u);
    EXPECT_EQ(snap.processNotifications, 0u);
    EXPECT_EQ(snap.parseErrors, 0u);
    EXPECT_EQ(snap.handlerErrors, 0u);
}

// 4.6 TakeSnapshot() produces a coherent, copyable POD copy.
TEST_F(MessageDispatcher_Statistics, TakeSnapshot_IsCoherent) {
    const auto snap1 = f.dispatcher.GetStatistics().TakeSnapshot();
    const auto snap2 = snap1; // POD copy
    EXPECT_EQ(snap1.messagesDispatched,   snap2.messagesDispatched);
    EXPECT_EQ(snap1.processNotifications, snap2.processNotifications);
    EXPECT_EQ(snap1.parseErrors,          snap2.parseErrors);
}

// 4.7 ToJson() returns a non-empty string.
TEST_F(MessageDispatcher_Statistics, ToJson_NonEmpty) {
    EXPECT_FALSE(f.dispatcher.ToJson().empty());
}

// 4.8 fileScanRequests counter increments once per ScanRequest dispatch.
TEST_F(MessageDispatcher_Statistics, FileScanRequests_IncrementOnDispatch) {
    f.dispatcher.ResetStatistics();

    f.dispatcher.RegisterFileScanHandler(
        [](const FileScanRequest& req) -> ScanVerdictReply {
            ScanVerdictReply reply;
            reply.messageId = req.messageId;
            reply.verdict   = ScanVerdict::Clean;
            return reply;
        });

    for (int i = 0; i < 4; ++i) {
        const auto payload = BuildFileScanPayload(
            static_cast<uint64_t>(0xC00 + i), nullptr, 0, nullptr, 0, 4);
        const auto msg = BuildMessage(MessageType::ScanRequest,
                                       static_cast<uint64_t>(0xC00 + i),
                                       payload.data(), payload.size());
        (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    }

    EXPECT_EQ(f.dispatcher.GetStatistics().TakeSnapshot().fileScanRequests, 4u)
        << "fileScanRequests must increment exactly once per ScanRequest dispatch.";
}

// 4.9 replyErrors increments when a ScanRequest with requiresReply=1 is dispatched
//     on a disconnected port (reply serialization succeeds; FilterConnection send fails).
TEST_F(MessageDispatcher_Statistics, ReplyErrors_IncrementOnDisconnectedReply) {
    f.dispatcher.ResetStatistics();

    f.dispatcher.RegisterFileScanHandler(
        [](const FileScanRequest& req) -> ScanVerdictReply {
            ScanVerdictReply reply;
            reply.messageId = req.messageId;
            reply.verdict   = ScanVerdict::Clean;
            return reply;
        });

    const wchar_t path[] = L"C:\\Temp\\test_reply.exe";
    const uint16_t pLen  = static_cast<uint16_t>(wcslen(path));
    // requiresReply=1: dispatcher must attempt to send the verdict reply.
    const auto payload   = BuildFileScanPayload(0xC10ULL, path, pLen, nullptr, 0, 4, 1);
    const auto msg       = BuildMessage(MessageType::ScanRequest, 0xC10ULL,
                                         payload.data(), payload.size());
    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));

    const auto snap = f.dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_GE(snap.fileScanRequests, 1u)
        << "fileScanRequests must increment even when the reply send fails.";
    EXPECT_GE(snap.replyErrors, 1u)
        << "replyErrors must increment when ReplyMessage() fails on a disconnected port.";
}

// ============================================================================
// GROUP 5 — AlertSystem_CoreOperations
// ============================================================================
/**
 * Validates the alert raise / lifecycle state machine including deduplication,
 * lookup, and the convenience / struct overloads of RaiseAlert().
 */
class AlertSystem_CoreOperations : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_asInit = EnsureAlertSystemInit();
    }
    static bool s_asInit;
};
bool AlertSystem_CoreOperations::s_asInit = false;

// 5.1 RaiseAlert(severity, type, subject, details) returns a non-empty alert ID.
TEST_F(AlertSystem_CoreOperations, RaiseAlert_Convenience_ReturnsNonEmptyId) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High,
        AlertType::ThreatDetection,
        "Integration Test — Suspicious PE",
        "Integration test raising a High-severity threat detection alert.",
        "CommunicationPipeline_Tests");

    EXPECT_FALSE(id.empty())
        << "RaiseAlert() must return a non-empty GUID-style alert ID.";
}

// 5.2 GetAlert() by the returned ID must find the alert.
TEST_F(AlertSystem_CoreOperations, GetAlert_ByKnownId_Found) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Medium,
        AlertType::PolicyViolation,
        "Policy Violation — Test",
        "Integration test alert for GetAlert lookup.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());

    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must appear in history within timeout after RaiseAlert().";
    const auto found = AlertSystem::Instance().GetAlert(id);
    ASSERT_TRUE(found.has_value())
        << "GetAlert() must find an alert by the ID returned from RaiseAlert().";
    EXPECT_EQ(found->alertId, id);
}

// 5.3 A freshly raised alert must have severity matching the requested level.
TEST_F(AlertSystem_CoreOperations, RaisedAlert_SeverityPreserved) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Critical,
        AlertType::Security,
        "Critical Security Alert — Test",
        "Severity preservation check.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must appear in history within timeout after RaiseAlert().";
    const auto found = AlertSystem::Instance().GetAlert(id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->severity, AlertSeverity::Critical);
}

// 5.4 GetAlert() with an unknown ID must return nullopt.
TEST_F(AlertSystem_CoreOperations, GetAlert_UnknownId_ReturnsNullopt) {
    SKIP_AS();
    const auto found = AlertSystem::Instance().GetAlert(
        "00000000-0000-0000-0000-000000000000");
    EXPECT_FALSE(found.has_value());
}

// 5.5 AcknowledgeAlert() transitions the status to Acknowledged.
TEST_F(AlertSystem_CoreOperations, AcknowledgeAlert_TransitionsStatus) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High,
        AlertType::ThreatDetection,
        "Ack Test Alert",
        "Alert to be acknowledged.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must reach history before AcknowledgeAlert() can act on it.";
    const bool acked = AlertSystem::Instance().AcknowledgeAlert(id, "soc-analyst-01");
    EXPECT_TRUE(acked) << "AcknowledgeAlert() must return true for a known alert.";

    const auto found = AlertSystem::Instance().GetAlert(id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, AlertStatus::Acknowledged);
    EXPECT_EQ(found->acknowledgedBy, "soc-analyst-01");
}

// 5.6 AcknowledgeAlert() on an unknown ID must return false.
TEST_F(AlertSystem_CoreOperations, AcknowledgeAlert_UnknownId_ReturnsFalse) {
    SKIP_AS();
    EXPECT_FALSE(AlertSystem::Instance().AcknowledgeAlert(
        "nonexistent-id-abcdef", "analyst"));
}

// 5.7 ResolveAlert() transitions a previously-acknowledged alert to Resolved.
TEST_F(AlertSystem_CoreOperations, ResolveAlert_TransitionsStatus) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Low,
        AlertType::Operational,
        "Resolve Test Alert",
        "Alert to be resolved.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must reach history before lifecycle transitions.";
    (void)AlertSystem::Instance().AcknowledgeAlert(id, "analyst");
    const bool resolved = AlertSystem::Instance().ResolveAlert(
        id, "analyst", "False positive — whitelisted binary");

    EXPECT_TRUE(resolved);
    const auto found = AlertSystem::Instance().GetAlert(id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->status, AlertStatus::Resolved);
}

// 5.8 EscalateAlert() transitions a known alert to Escalated status.
TEST_F(AlertSystem_CoreOperations, EscalateAlert_TransitionsStatus) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High,
        AlertType::ThreatDetection,
        "Escalation Test Alert",
        "Alert for escalation path test.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must reach history before EscalateAlert() can act on it.";
    const bool escalated = AlertSystem::Instance().EscalateAlert(
        id, "Auto-escalated: no acknowledgment within SLA.");

    EXPECT_TRUE(escalated)
        << "EscalateAlert() must succeed for a known, unacknowledged alert.";
}

// 5.9 RaiseAlert(Alert struct) overload returns a non-empty ID.
TEST_F(AlertSystem_CoreOperations, RaiseAlert_StructOverload_ReturnsId) {
    SKIP_AS();
    Alert a;
    a.severity = AlertSeverity::Medium;
    a.type     = AlertType::AuditEvent;
    a.subject  = "Struct Overload Test Alert";
    a.details  = "Testing the Alert struct overload of RaiseAlert().";
    a.source   = "CommunicationPipeline_Tests";

    const std::string id = AlertSystem::Instance().RaiseAlert(a);
    EXPECT_FALSE(id.empty());
}

// 5.10 GetRecentAlerts(limit) must not return more entries than the limit.
TEST_F(AlertSystem_CoreOperations, GetRecentAlerts_RespectsLimit) {
    SKIP_AS();
    // Raise several alerts to ensure there is history.
    for (int i = 0; i < 5; ++i) {
        (void)AlertSystem::Instance().RaiseAlert(
            AlertSeverity::Info,
            AlertType::Operational,
            "Limit Test " + std::to_string(i),
            "Limit test body.",
            "CommunicationPipeline_Tests");
    }

    const auto recent = AlertSystem::Instance().GetRecentAlerts(3);
    EXPECT_LE(recent.size(), 3u)
        << "GetRecentAlerts(3) must not return more than 3 alerts.";
}

// 5.11 GetAlertsByStatus(Acknowledged) returns at least one previously-acked alert.
TEST_F(AlertSystem_CoreOperations, GetAlertsByStatus_ReturnsMatchingAlerts) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Low,
        AlertType::Operational,
        "Status Filter Test",
        "Alert for status filter.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must reach history before AcknowledgeAlert() can act on it.";
    (void)AlertSystem::Instance().AcknowledgeAlert(id, "filter-tester");

    const auto acked = AlertSystem::Instance().GetAlertsByStatus(AlertStatus::Acknowledged);
    const bool found = std::any_of(acked.begin(), acked.end(),
        [&id](const Alert& a) { return a.alertId == id; });

    EXPECT_TRUE(found)
        << "GetAlertsByStatus(Acknowledged) must include the recently acked alert.";
}

// 5.12 GetConfiguration() returns a configuration with enabled == true.
TEST_F(AlertSystem_CoreOperations, GetConfiguration_ReflectsInitConfig) {
    SKIP_AS();
    const auto cfg = AlertSystem::Instance().GetConfiguration();
    EXPECT_TRUE(cfg.enabled);
}

// ============================================================================
// GROUP 6 — AlertSystem_RecipientWebhook
// ============================================================================
/**
 * Validates the recipient and webhook management surfaces including CRUD
 * operations and input-validation contracts.
 */
class AlertSystem_RecipientWebhook : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_asInit = EnsureAlertSystemInit(); }
    static bool s_asInit;
};
bool AlertSystem_RecipientWebhook::s_asInit = false;

// 6.1 AddRecipient() stores a valid recipient.
TEST_F(AlertSystem_RecipientWebhook, AddRecipient_Valid_Stored) {
    SKIP_AS();
    AlertRecipient r;
    r.recipientId = "tier8-test-recipient-1";
    r.name        = "Test SOC Analyst";
    r.email       = "analyst@corp.internal";
    r.level       = EscalationLevel::Level1;
    r.channels    = DeliveryChannel::Email;
    r.enabled     = true;

    const bool added = AlertSystem::Instance().AddRecipient(r);
    EXPECT_TRUE(added);

    const auto recipients = AlertSystem::Instance().GetRecipients();
    const bool found = std::any_of(recipients.begin(), recipients.end(),
        [](const AlertRecipient& rec) {
            return rec.recipientId == "tier8-test-recipient-1";
        });
    EXPECT_TRUE(found) << "AddRecipient() must persist the recipient in GetRecipients().";
    EXPECT_TRUE(AlertSystem::Instance().RemoveRecipient("tier8-test-recipient-1"))
        << "Recipient-creation tests must clean up singleton state for later suites.";
}

// 6.2 RemoveRecipient() by ID removes the previously-added recipient.
TEST_F(AlertSystem_RecipientWebhook, RemoveRecipient_ByKnownId_Removed) {
    SKIP_AS();
    AlertRecipient r;
    r.recipientId = "tier8-test-recipient-2";
    r.name        = "Temp Recipient";
    r.email       = "temp@corp.internal";
    (void)AlertSystem::Instance().AddRecipient(r);

    EXPECT_TRUE(AlertSystem::Instance().RemoveRecipient("tier8-test-recipient-2"));

    const auto recipients = AlertSystem::Instance().GetRecipients();
    const bool stillPresent = std::any_of(recipients.begin(), recipients.end(),
        [](const AlertRecipient& rec) {
            return rec.recipientId == "tier8-test-recipient-2";
        });
    EXPECT_FALSE(stillPresent);
}

// 6.3 RemoveRecipient() with unknown ID must return false.
TEST_F(AlertSystem_RecipientWebhook, RemoveRecipient_UnknownId_ReturnsFalse) {
    SKIP_AS();
    EXPECT_FALSE(AlertSystem::Instance().RemoveRecipient("does-not-exist-xyz"));
}

// 6.4 AddWebhook() with a valid configuration stores the webhook.
TEST_F(AlertSystem_RecipientWebhook, AddWebhook_Valid_Stored) {
    SKIP_AS();
    WebhookConfiguration wh;
    wh.webhookId     = "tier8-test-webhook-1";
    wh.name          = "Test Slack Integration";
    wh.url           = "https://hooks.example.slack.com/services/test";
    wh.channelType   = DeliveryChannel::Slack;
    wh.method        = "POST";
    wh.enabled       = true;

    const bool added = AlertSystem::Instance().AddWebhook(wh);
    EXPECT_TRUE(added);

    const auto hooks = AlertSystem::Instance().GetWebhooks();
    const bool found = std::any_of(hooks.begin(), hooks.end(),
        [](const WebhookConfiguration& w) {
            return w.webhookId == "tier8-test-webhook-1";
        });
    EXPECT_TRUE(found);
    EXPECT_TRUE(AlertSystem::Instance().RemoveWebhook("tier8-test-webhook-1"))
        << "Webhook-creation tests must clean up singleton state for later suites.";
}

// 6.5 RemoveWebhook() by ID removes the webhook.
TEST_F(AlertSystem_RecipientWebhook, RemoveWebhook_ByKnownId_Removed) {
    SKIP_AS();
    WebhookConfiguration wh;
    wh.webhookId = "tier8-test-webhook-remove";
    wh.name      = "Temp Webhook";
    wh.url       = "https://example.com/hook";
    wh.enabled   = true;
    (void)AlertSystem::Instance().AddWebhook(wh);

    EXPECT_TRUE(AlertSystem::Instance().RemoveWebhook("tier8-test-webhook-remove"));

    const auto hooks = AlertSystem::Instance().GetWebhooks();
    const bool stillPresent = std::any_of(hooks.begin(), hooks.end(),
        [](const WebhookConfiguration& w) {
            return w.webhookId == "tier8-test-webhook-remove";
        });
    EXPECT_FALSE(stillPresent);
}

// 6.6 WebhookConfiguration::IsValid() returns false for a missing URL.
TEST_F(AlertSystem_RecipientWebhook, WebhookIsValid_EmptyUrl_ReturnsFalse) {
    WebhookConfiguration wh;
    wh.webhookId = "no-url-webhook";
    wh.name      = "No URL";
    // url intentionally empty
    EXPECT_FALSE(wh.IsValid());
}

// ============================================================================
// GROUP 7 — AlertSystem_Suppression
// ============================================================================
/**
 * Validates suppression rule lifecycle and the IsAlertSuppressed() predicate.
 */
class AlertSystem_Suppression : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_asInit = EnsureAlertSystemInit(); }
    static bool s_asInit;
};
bool AlertSystem_Suppression::s_asInit = false;

// 7.1 AddSuppressionRule() stores a rule accessible via GetSuppressionRules().
TEST_F(AlertSystem_Suppression, AddRule_Stored_InGetRules) {
    SKIP_AS();
    SuppressionRule rule;
    rule.ruleId       = "tier8-suppress-1";
    rule.name         = "Test Suppression Rule";
    rule.criteria["source"] = "CommunicationPipeline_Tests";
    rule.reason       = "Integration test rule";
    rule.createdBy    = "tier8-test";
    rule.active       = true;

    EXPECT_TRUE(AlertSystem::Instance().AddSuppressionRule(rule));

    const auto rules = AlertSystem::Instance().GetSuppressionRules();
    const bool found = std::any_of(rules.begin(), rules.end(),
        [](const SuppressionRule& r) { return r.ruleId == "tier8-suppress-1"; });
    EXPECT_TRUE(found);

    // Remove immediately: source="CommunicationPipeline_Tests" would suppress
    // every subsequent test alert, breaking callbacks and lifecycle tests.
    (void)AlertSystem::Instance().RemoveSuppressionRule("tier8-suppress-1");
}
TEST_F(AlertSystem_Suppression, RemoveRule_ByKnownId_Removed) {
    SKIP_AS();
    SuppressionRule rule;
    rule.ruleId   = "tier8-suppress-remove";
    rule.name     = "Temp Suppression";
    rule.criteria["source"] = "TempSource";
    rule.active   = true;
    (void)AlertSystem::Instance().AddSuppressionRule(rule);

    EXPECT_TRUE(AlertSystem::Instance().RemoveSuppressionRule("tier8-suppress-remove"));

    const auto rules = AlertSystem::Instance().GetSuppressionRules();
    const bool stillPresent = std::any_of(rules.begin(), rules.end(),
        [](const SuppressionRule& r) {
            return r.ruleId == "tier8-suppress-remove";
        });
    EXPECT_FALSE(stillPresent);
}

// 7.3 RemoveSuppressionRule() with unknown ID returns false.
TEST_F(AlertSystem_Suppression, RemoveRule_UnknownId_ReturnsFalse) {
    SKIP_AS();
    EXPECT_FALSE(AlertSystem::Instance().RemoveSuppressionRule("not-present-rule"));
}

// 7.4 IsAlertSuppressed() respects suppression rules with matching criteria.
TEST_F(AlertSystem_Suppression, IsAlertSuppressed_MatchingCriteria_ReturnsTrue) {
    SKIP_AS();
    SuppressionRule rule;
    rule.ruleId   = "tier8-suppress-match";
    rule.name     = "Match Test Rule";
    rule.criteria["source"] = "SuppressedTestSource";
    rule.active   = true;
    (void)AlertSystem::Instance().AddSuppressionRule(rule);

    Alert a;
    a.severity = AlertSeverity::High;
    a.type     = AlertType::ThreatDetection;
    a.subject  = "Suppressed Alert Test";
    a.source   = "SuppressedTestSource";  // matches criteria

    EXPECT_TRUE(AlertSystem::Instance().IsAlertSuppressed(a))
        << "IsAlertSuppressed() must return true when source matches a suppression rule.";

    // Clean up
    (void)AlertSystem::Instance().RemoveSuppressionRule("tier8-suppress-match");
}

// 7.5 IsAlertSuppressed() returns false when no criteria match.
TEST_F(AlertSystem_Suppression, IsAlertSuppressed_NoMatch_ReturnsFalse) {
    SKIP_AS();
    Alert a;
    a.severity = AlertSeverity::Medium;
    a.type     = AlertType::Operational;
    a.subject  = "Non-suppressed Alert";
    a.source   = "ZZZ_UnmatchedSource_ZZZ";

    EXPECT_FALSE(AlertSystem::Instance().IsAlertSuppressed(a));
}

// ============================================================================
// GROUP 8 — AlertSystem_Callbacks
// ============================================================================
/**
 * Verifies that alert, delivery, and escalation callbacks fire with the
 * correct payload, and that UnregisterCallbacks() prevents further delivery.
 */
class AlertSystem_Callbacks : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_asInit = EnsureAlertSystemInit(); }
    static bool s_asInit;
};
bool AlertSystem_Callbacks::s_asInit = false;

// 8.1 RegisterAlertCallback fires when a new alert is raised.
TEST_F(AlertSystem_Callbacks, AlertCallback_Fires_OnRaiseAlert) {
    SKIP_AS();
    std::atomic<bool>    callbackFired{false};
    std::string          capturedId;
    std::mutex           captureMutex;

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            std::lock_guard<std::mutex> lg(captureMutex);
            callbackFired.store(true, std::memory_order_release);
            capturedId = a.alertId;
        });

    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High,
        AlertType::ThreatDetection,
        "Callback Test Alert",
        "Verifying alert callback delivery.",
        "CommunicationPipeline_Tests");

    // Give the (potentially async) delivery a moment to execute.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!callbackFired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(callbackFired.load())
        << "AlertCallback must fire within 2 seconds of RaiseAlert().";
    EXPECT_EQ(capturedId, id);

    AlertSystem::Instance().UnregisterCallbacks();
}

// 8.2 AlertCallback receives the correct severity.
TEST_F(AlertSystem_Callbacks, AlertCallback_SeverityMatchesRaisedAlert) {
    SKIP_AS();
    AlertSeverity capturedSeverity = AlertSeverity::Info;
    std::atomic<bool> fired{false};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            capturedSeverity = a.severity;
            fired.store(true, std::memory_order_release);
        });

    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Emergency,
        AlertType::Security,
        "Severity Callback Test",
        "Emergency severity check.",
        "CommunicationPipeline_Tests");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!fired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_EQ(capturedSeverity, AlertSeverity::Emergency);
    AlertSystem::Instance().UnregisterCallbacks();
}

// 8.3 RaiseEmergency() must not throw and must complete without crashing.
TEST_F(AlertSystem_Callbacks, RaiseEmergency_DoesNotThrow) {
    SKIP_AS();
    EXPECT_NO_FATAL_FAILURE({
        AlertSystem::Instance().RaiseEmergency(
            "Emergency Integration Test",
            "Testing SS_ALERT_EMERGENCY code path — no real incident.");
    });
}

// 8.4 UnregisterCallbacks() prevents the callback from firing on subsequent alerts.
TEST_F(AlertSystem_Callbacks, UnregisterCallbacks_PreventsSubsequentFiring) {
    SKIP_AS();
    std::atomic<uint32_t> fireCount{0};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert&) {
            fireCount.fetch_add(1, std::memory_order_relaxed);
        });

    // Fire once to confirm registration works.
    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Low, AlertType::Operational,
        "Pre-Unregister Test", "Before unregister.", "CommunicationPipeline_Tests");

    // Spin-wait until at least one callback fires to avoid a race between the
    // async delivery thread and UnregisterCallbacks().
    {
        const auto spinDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (fireCount.load(std::memory_order_acquire) == 0 &&
               std::chrono::steady_clock::now() < spinDeadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    AlertSystem::Instance().UnregisterCallbacks();

    const uint32_t countAfterUnregister = fireCount.load();

    // Subsequent alerts must NOT increment the counter.
    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Low, AlertType::Operational,
        "Post-Unregister Test", "After unregister.", "CommunicationPipeline_Tests");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(fireCount.load(), countAfterUnregister)
        << "UnregisterCallbacks() must prevent future callback invocations.";
}

// ============================================================================
// GROUP 9 — AlertSystem_Statistics
// ============================================================================
/**
 * Validates counter accuracy, TakeSnapshot() coherence, and Reset() behaviour.
 */
class AlertSystem_Statistics : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_asInit = EnsureAlertSystemInit(); }
    static bool s_asInit;
};
bool AlertSystem_Statistics::s_asInit = false;

// 9.1 totalAlerts increments on each RaiseAlert() call.
TEST_F(AlertSystem_Statistics, TotalAlerts_IncrementOnRaise) {
    SKIP_AS();
    AlertSystem::Instance().ResetStatistics();

    const uint64_t before = AlertSystem::Instance().GetStatistics().totalAlerts;
    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Medium, AlertType::Operational,
        "Stats Test 1", "Counter test.", "CommunicationPipeline_Tests");
    const uint64_t after = AlertSystem::Instance().GetStatistics().totalAlerts;

    EXPECT_GT(after, before)
        << "totalAlerts must be incremented for each RaiseAlert() call.";
}

// 9.2 alertsAcknowledged increments after AcknowledgeAlert().
TEST_F(AlertSystem_Statistics, AlertsAcknowledged_IncrementOnAck) {
    SKIP_AS();
    AlertSystem::Instance().ResetStatistics();

    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High, AlertType::Security,
        "Stats Ack Test", "Ack counter test.", "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must be in history before AcknowledgeAlert() can increment the counter.";
    const uint64_t before = AlertSystem::Instance().GetStatistics().alertsAcknowledged;
    (void)AlertSystem::Instance().AcknowledgeAlert(id, "stats-tester");
    const uint64_t after = AlertSystem::Instance().GetStatistics().alertsAcknowledged;

    EXPECT_GT(after, before);
}

// 9.3 ResetStatistics() zeroes all counters.
TEST_F(AlertSystem_Statistics, Reset_ZeroesAllCounters) {
    SKIP_AS();
    // Produce non-zero state.
    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Low, AlertType::Operational,
        "Pre-Reset Test", "Counter.", "CommunicationPipeline_Tests");

    AlertSystem::Instance().ResetStatistics();
    const auto snap = AlertSystem::Instance().GetStatistics();
    EXPECT_EQ(snap.totalAlerts, 0u);
    EXPECT_EQ(snap.alertsSent, 0u);
    EXPECT_EQ(snap.alertsAcknowledged, 0u);
    EXPECT_EQ(snap.alertsSuppressed, 0u);
    EXPECT_EQ(snap.alertsEscalated, 0u);
}

// 9.4 GetStatistics() returns a snapshot (AlertStatisticsSnapshot POD struct).
TEST_F(AlertSystem_Statistics, GetStatistics_Copyable) {
    SKIP_AS();
    const auto snap1 = AlertSystem::Instance().GetStatistics();
    const auto snap2 = snap1;  // POD copy
    EXPECT_EQ(snap1.totalAlerts, snap2.totalAlerts);
}

// 9.5 SelfTest() must complete without throwing.
TEST_F(AlertSystem_Statistics, SelfTest_Completes) {
    SKIP_AS();
    EXPECT_NO_FATAL_FAILURE({
        (void)AlertSystem::Instance().SelfTest();
    });
}

// 9.6 alertsEscalated increments after a successful EscalateAlert() call.
TEST_F(AlertSystem_Statistics, AlertsEscalated_IncrementOnEscalate) {
    SKIP_AS();
    AlertSystem::Instance().ResetStatistics();

    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High, AlertType::ThreatDetection,
        "Escalation Stats Test",
        "Verifying that alertsEscalated increments on escalation.",
        "CommunicationPipeline_Tests");
    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must be in history before EscalateAlert() can act on it.";

    const uint64_t before = AlertSystem::Instance().GetStatistics().alertsEscalated;
    const bool escalated  = AlertSystem::Instance().EscalateAlert(
        id, "SLA breach — no analyst response within threshold.");

    EXPECT_TRUE(escalated);
    EXPECT_GT(AlertSystem::Instance().GetStatistics().alertsEscalated, before)
        << "alertsEscalated must increment after a successful EscalateAlert() call.";
}

// ============================================================================
// GROUP 10 — TelemetryCollector_Events
// ============================================================================
/**
 * Validates the event recording pipeline: queue growth, per-type routing,
 * typed convenience recorders, and ClearQueue() semantics.
 */
class TelemetryCollector_Events : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_tcInit = EnsureTelemetryCollectorInit();
    }
    static bool s_tcInit;
};
bool TelemetryCollector_Events::s_tcInit = false;

// 10.1 RecordEvent(type, data) increments the queue size.
TEST_F(TelemetryCollector_Events, RecordEvent_StringOverload_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();
    TelemetryCollector::Instance().ResetStatistics();

    TelemetryCollector::Instance().RecordEvent("Detection", "{\"threat\":\"EICAR\"}");

    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.2 RecordDetection() queues a detection event.
TEST_F(TelemetryCollector_Events, RecordDetection_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    DetectionEventData det;
    det.threatName       = "Trojan.GenericKD.EICAR";
    det.threatType       = "Trojan";
    det.fileHash         = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    det.fileSize         = 68;
    det.detectionMethod  = "Signature";
    det.actionTaken      = "Quarantine";
    det.fpProbability    = 0.001;

    TelemetryCollector::Instance().RecordDetection(det);
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.3 RecordHealth() queues a health event.
TEST_F(TelemetryCollector_Events, RecordHealth_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    HealthEventData health;
    health.cpuUsage      = 12.5;
    health.memoryUsageMB = 256;
    health.uptimeSeconds = 3600;
    health.scanQueueSize = 0;
    health.activeScans   = 1;
    health.errorCount    = 0;

    TelemetryCollector::Instance().RecordHealth(health);
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.4 RecordPerformance() queues a performance event.
TEST_F(TelemetryCollector_Events, RecordPerformance_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    PerformanceEventData perf;
    perf.metricName  = "scan_latency_ms";
    perf.value       = 4.7;
    perf.unit        = "ms";
    perf.durationMs  = 5;

    TelemetryCollector::Instance().RecordPerformance(perf);
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.5 RecordCrash() queues a crash event.
TEST_F(TelemetryCollector_Events, RecordCrash_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    CrashEventData crash;
    crash.exceptionType    = "AccessViolation";
    crash.exceptionMessage = "Read from null pointer at 0x0000";
    crash.moduleName       = "PhantomSensor.sys";
    crash.functionName     = "ScanCallback";
    crash.threadId         = 1234;
    crash.isCritical       = true;

    TelemetryCollector::Instance().RecordCrash(crash);
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.6 RecordCustom() queues a custom event with the specified subtype.
TEST_F(TelemetryCollector_Events, RecordCustom_GrowsQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    const std::map<std::string, std::string> data{
        {"component", "CommunicationPipeline"},
        {"test_id",   "10.6"},
        {"status",    "pass"}
    };

    TelemetryCollector::Instance().RecordCustom("integration_test_result", data);
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.7 ClearQueue() empties the pending queue.
TEST_F(TelemetryCollector_Events, ClearQueue_EmptiesQueue) {
    SKIP_TC();
    TelemetryCollector::Instance().RecordEvent("Custom", "{}");
    TelemetryCollector::Instance().ClearQueue();
    EXPECT_EQ(TelemetryCollector::Instance().GetQueueSize(), 0u);
}

// 10.8 GetPendingEvents(limit) does not return more than the requested limit.
TEST_F(TelemetryCollector_Events, GetPendingEvents_RespectsLimit) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    for (int i = 0; i < 10; ++i)
        TelemetryCollector::Instance().RecordEvent("Detection", "{}");

    const auto events = TelemetryCollector::Instance().GetPendingEvents(5);
    EXPECT_LE(events.size(), 5u);
}

// 10.9 RecordEvent typed overload (TelemetryEvent struct) populates eventId.
TEST_F(TelemetryCollector_Events, RecordEvent_StructOverload_Accepted) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();

    TelemetryEvent ev;
    ev.eventType    = TelemetryEventType::Configuration;
    ev.subtype      = "policy_update";
    ev.payloadJson  = R"({"policy_version":42})";
    ev.timestamp    = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());

    EXPECT_NO_FATAL_FAILURE(TelemetryCollector::Instance().RecordEvent(ev));
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(), 1u);
}

// 10.10 Flush() must not throw even with an empty queue.
TEST_F(TelemetryCollector_Events, Flush_EmptyQueue_DoesNotThrow) {
    SKIP_TC();
    TelemetryCollector::Instance().ClearQueue();
    EXPECT_NO_FATAL_FAILURE(TelemetryCollector::Instance().Flush());
}

// ============================================================================
// GROUP 11 — TelemetryCollector_Consent
// ============================================================================
/**
 * Validates consent gating (events must be dropped when consent is None),
 * anonymization utilities, and the anonymous machine ID contract.
 */
class TelemetryCollector_Consent : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_tcInit = EnsureTelemetryCollectorInit(); }
    static bool s_tcInit;

    void TearDown() override {
        // Restore Full consent after any test that changes it.
        TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::Full);
    }
};
bool TelemetryCollector_Consent::s_tcInit = false;

// 11.1 GetConsentLevel() reflects the level set during initialization.
TEST_F(TelemetryCollector_Consent, GetConsentLevel_ReflectsInitValue) {
    SKIP_TC();
    EXPECT_EQ(TelemetryCollector::Instance().GetConsentLevel(), ConsentLevel::Full);
}

// 11.2 SetConsentLevel(None) causes IsConsented() to return false.
TEST_F(TelemetryCollector_Consent, SetConsentNone_IsConsented_False) {
    SKIP_TC();
    TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::None);
    EXPECT_FALSE(TelemetryCollector::Instance().IsConsented());
}

// 11.3 SetConsentLevel(Full) causes IsConsented() to return true.
TEST_F(TelemetryCollector_Consent, SetConsentFull_IsConsented_True) {
    SKIP_TC();
    TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::Full);
    EXPECT_TRUE(TelemetryCollector::Instance().IsConsented());
}

// 11.4 SetConsentLevel(Required) causes IsConsented() to return true.
TEST_F(TelemetryCollector_Consent, SetConsentRequired_IsConsented_True) {
    SKIP_TC();
    TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::Required);
    EXPECT_TRUE(TelemetryCollector::Instance().IsConsented());
}

// 11.5 Anonymize() with Standard level returns a non-empty string.
TEST_F(TelemetryCollector_Consent, Anonymize_Standard_NonEmpty) {
    SKIP_TC();
    const std::string raw   = R"({"user":"john.doe@corp.com","host":"DESKTOP-ABC123"})";
    const std::string anon  = TelemetryCollector::Instance().Anonymize(
        raw, AnonymizationLevel::Standard);

    EXPECT_FALSE(anon.empty())
        << "Anonymize() must return a non-empty string.";
}

// 11.6 AnonymizePath() returns a non-empty string for a valid path.
TEST_F(TelemetryCollector_Consent, AnonymizePath_ValidPath_NonEmpty) {
    SKIP_TC();
    const std::filesystem::path p{L"C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\dropper.exe"};
    const std::string result = TelemetryCollector::Instance().AnonymizePath(p);
    EXPECT_FALSE(result.empty());
}

// 11.7 GetAnonymousMachineId() returns a stable non-empty identifier.
TEST_F(TelemetryCollector_Consent, GetAnonymousMachineId_Stable) {
    SKIP_TC();
    const std::string id1 = TelemetryCollector::Instance().GetAnonymousMachineId();
    const std::string id2 = TelemetryCollector::Instance().GetAnonymousMachineId();

    EXPECT_FALSE(id1.empty())
        << "GetAnonymousMachineId() must return a non-empty identifier.";
    EXPECT_EQ(id1, id2)
        << "GetAnonymousMachineId() must return the same value on repeated calls.";
}

// 11.8 Free-function ScrubPII() removes email addresses from a string.
TEST_F(TelemetryCollector_Consent, ScrubPII_RemovesEmailPattern) {
    const std::string input  = "Logged on as user@example.com from host";
    const std::string output = Comm::ScrubPII(input);
    EXPECT_EQ(output.find("user@example.com"), std::string::npos)
        << "ScrubPII() must remove email addresses from the input string.";
}

// 11.9 Free-function HashSensitiveData() returns a non-empty hex string.
TEST_F(TelemetryCollector_Consent, HashSensitiveData_NonEmpty) {
    const std::string result = Comm::HashSensitiveData("sensitive-data-payload");
    EXPECT_FALSE(result.empty())
        << "HashSensitiveData() must return a non-empty hash string.";
}

// 11.10 UpdateConfiguration() with a valid config must succeed.
TEST_F(TelemetryCollector_Consent, UpdateConfiguration_ValidConfig_Succeeds) {
    SKIP_TC();
    TelemetryConfiguration newCfg;
    newCfg.enabled         = true;
    newCfg.consentLevel    = ConsentLevel::Basic;
    newCfg.batchSize       = 50;
    newCfg.maxQueueSize    = 5000;

    EXPECT_TRUE(TelemetryCollector::Instance().UpdateConfiguration(newCfg));

    // Restore full config
    TelemetryConfiguration restore;
    restore.enabled         = true;
    restore.consentLevel    = ConsentLevel::Full;
    (void)TelemetryCollector::Instance().UpdateConfiguration(restore);
}

// 11.11 Anonymize() with AnonymizationLevel::Strict returns a non-empty string.
//       Strict mode must apply the strongest available anonymization without discarding the payload.
TEST_F(TelemetryCollector_Consent, Anonymize_Strict_NonEmpty) {
    SKIP_TC();
    const std::string raw  = R"({"user":"john.doe@corp.com","host":"DESKTOP-ABC123","ip":"192.168.1.100"})";
    const std::string anon = TelemetryCollector::Instance().Anonymize(
        raw, AnonymizationLevel::Strict);
    EXPECT_FALSE(anon.empty())
        << "Anonymize() with Strict level must return a non-empty result — "
           "the payload may not be silently discarded.";
}

// 11.12 RecordEvent() with ConsentLevel::None must not enqueue the event.
//       Privacy contract: zero telemetry when the user has revoked consent.
TEST_F(TelemetryCollector_Consent, ConsentNone_EventDropped_QueueUnchanged) {
    SKIP_TC();
    TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::None);
    TelemetryCollector::Instance().ClearQueue();
    TelemetryCollector::Instance().ResetStatistics();

    TelemetryCollector::Instance().RecordEvent("Detection", R"({"threat":"TestDropEvent"})");

    EXPECT_EQ(TelemetryCollector::Instance().GetQueueSize(), 0u)
        << "Events must be silently dropped when ConsentLevel is None — "
           "no telemetry may leave the endpoint without user consent.";
    // TearDown() restores ConsentLevel::Full.
}

// ============================================================================
// GROUP 12 — TelemetryCollector_Statistics
// ============================================================================
/**
 * Validates counter accuracy, TakeSnapshot() coherence, and Reset().
 */
class TelemetryCollector_Statistics : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_tcInit = EnsureTelemetryCollectorInit(); }
    static bool s_tcInit;
};
bool TelemetryCollector_Statistics::s_tcInit = false;

// 12.1 eventsRecorded increments for each RecordEvent() call.
TEST_F(TelemetryCollector_Statistics, EventsRecorded_IncrementOnRecord) {
    SKIP_TC();
    TelemetryCollector::Instance().ResetStatistics();

    const uint64_t before = TelemetryCollector::Instance().GetStatistics().eventsRecorded;
    TelemetryCollector::Instance().RecordEvent("Health", "{}");
    const uint64_t after  = TelemetryCollector::Instance().GetStatistics().eventsRecorded;

    EXPECT_GT(after, before);
}

// 12.2 ResetStatistics() zeroes all counters.
TEST_F(TelemetryCollector_Statistics, Reset_ZeroesAllCounters) {
    SKIP_TC();
    TelemetryCollector::Instance().RecordEvent("Detection", "{}");
    TelemetryCollector::Instance().ResetStatistics();

    const auto snap = TelemetryCollector::Instance().GetStatistics();
    EXPECT_EQ(snap.eventsRecorded,  0u);
    EXPECT_EQ(snap.eventsSubmitted, 0u);
    EXPECT_EQ(snap.eventsFailed,    0u);
    EXPECT_EQ(snap.eventsDropped,   0u);
}

// 12.3 TakeSnapshot() returns a copyable POD struct.
TEST_F(TelemetryCollector_Statistics, TakeSnapshot_Copyable) {
    SKIP_TC();
    const auto snap1 = TelemetryCollector::Instance().GetStatistics();
    const auto snap2 = snap1;
    EXPECT_EQ(snap1.eventsRecorded, snap2.eventsRecorded);
}

// 12.4 SelfTest() must complete without throwing.
TEST_F(TelemetryCollector_Statistics, SelfTest_Completes) {
    SKIP_TC();
    EXPECT_NO_FATAL_FAILURE({
        (void)TelemetryCollector::Instance().SelfTest();
    });
}

// ============================================================================
// GROUP 13 — CrossPipeline_AlertToTelemetry
// ============================================================================
/**
 * Validates the AlertSystem → TelemetryCollector integration path:
 * an AlertCallback is wired to call TelemetryCollector.RecordDetection(),
 * confirming that a single RaiseAlert() call produces a telemetry event.
 */
class CrossPipeline_AlertToTelemetry : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_asInit = EnsureAlertSystemInit();
        s_tcInit = EnsureTelemetryCollectorInit();
    }
    void TearDown() override {
        AlertSystem::Instance().UnregisterCallbacks();
        TelemetryCollector::Instance().ClearQueue();
        TelemetryCollector::Instance().ResetStatistics();
    }
    static bool s_asInit;
    static bool s_tcInit;
};
bool CrossPipeline_AlertToTelemetry::s_asInit = false;
bool CrossPipeline_AlertToTelemetry::s_tcInit = false;

// 13.1 RaiseAlert() → AlertCallback → RecordDetection() produces a telemetry event.
TEST_F(CrossPipeline_AlertToTelemetry, AlertToTelemetry_End2End_EventQueued) {
    if (!s_asInit || !s_tcInit) GTEST_SKIP() << "Both singletons must be initialized.";

    TelemetryCollector::Instance().ClearQueue();
    TelemetryCollector::Instance().ResetStatistics();

    // Wire the alert callback to push a detection event into TelemetryCollector.
    AlertSystem::Instance().RegisterAlertCallback(
        [](const Alert& a) {
            DetectionEventData det;
            det.threatName      = a.subject;
            det.detectionMethod = "AlertSystemCallback";
            det.actionTaken     = "Alert";
            TelemetryCollector::Instance().RecordDetection(det);
        });

    const size_t queueBefore = TelemetryCollector::Instance().GetQueueSize();

    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Critical,
        AlertType::ThreatDetection,
        "Ransomware Detected: WannaCry Variant",
        "File encryption pattern detected across C:\\Users.",
        "CommunicationPipeline_Tests");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (TelemetryCollector::Instance().GetQueueSize() == queueBefore &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_GT(TelemetryCollector::Instance().GetQueueSize(), queueBefore)
        << "An alert raised via AlertSystem must trigger a TelemetryCollector event "
           "through the registered AlertCallback.";
}

// 13.2 Emergency alert → callback → TelemetryCollector records a crash event.
TEST_F(CrossPipeline_AlertToTelemetry, EmergencyAlert_TriggersCrashEvent) {
    if (!s_asInit || !s_tcInit) GTEST_SKIP() << "Both singletons must be initialized.";

    TelemetryCollector::Instance().ClearQueue();
    std::atomic<bool> eventRecorded{false};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            if (a.severity == AlertSeverity::Emergency ||
                a.severity == AlertSeverity::Critical) {
                CrashEventData crash;
                crash.exceptionType    = "EmergencyAlert";
                crash.exceptionMessage = a.subject;
                crash.isCritical       = true;
                TelemetryCollector::Instance().RecordCrash(crash);
                eventRecorded.store(true, std::memory_order_release);
            }
        });

    AlertSystem::Instance().RaiseEmergency(
        "Kernel Exploit Detected",
        "Ring-0 escalation attempt intercepted by PhantomSensor ELAM.");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!eventRecorded.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(eventRecorded.load())
        << "RaiseEmergency() must trigger the AlertCallback, which records a crash event.";
}

// 13.3 Multiple alerts → multiple telemetry events (counter accuracy).
TEST_F(CrossPipeline_AlertToTelemetry, MultipleAlerts_EachProducesTelemetryEvent) {
    if (!s_asInit || !s_tcInit) GTEST_SKIP() << "Both singletons must be initialized.";

    TelemetryCollector::Instance().ClearQueue();
    TelemetryCollector::Instance().ResetStatistics();

    constexpr int kCount = 5;
    std::atomic<int> callbackCount{0};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            DetectionEventData det;
            det.threatName = a.subject;
            TelemetryCollector::Instance().RecordDetection(det);
            callbackCount.fetch_add(1, std::memory_order_relaxed);
        });

    for (int i = 0; i < kCount; ++i) {
        (void)AlertSystem::Instance().RaiseAlert(
            AlertSeverity::High,
            AlertType::ThreatDetection,
            "Batch Alert " + std::to_string(i),
            "Batch telemetry wiring test.",
            "CommunicationPipeline_Tests");
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (callbackCount.load(std::memory_order_relaxed) < kCount &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_EQ(callbackCount.load(), kCount)
        << "Each RaiseAlert() must invoke the callback exactly once.";
    EXPECT_GE(TelemetryCollector::Instance().GetQueueSize(),
              static_cast<size_t>(kCount))
        << "Each callback invocation must produce at least one telemetry event.";
}

// 13.4 Alert severity is preserved through the callback to the telemetry payload.
TEST_F(CrossPipeline_AlertToTelemetry, AlertSeverity_PreservedInTelemetryPayload) {
    if (!s_asInit || !s_tcInit) GTEST_SKIP() << "Both singletons must be initialized.";

    TelemetryCollector::Instance().ClearQueue();
    AlertSeverity capturedSeverity = AlertSeverity::Info;
    std::atomic<bool> fired{false};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            capturedSeverity = a.severity;
            TelemetryEvent ev;
            ev.eventType   = TelemetryEventType::Detection;
            ev.subtype     = std::string(Comm::GetAlertSeverityName(a.severity));
            ev.payloadJson = R"({"severity_test":true})";
            TelemetryCollector::Instance().RecordEvent(ev);
            fired.store(true, std::memory_order_release);
        });

    (void)AlertSystem::Instance().RaiseAlert(
        AlertSeverity::Emergency,
        AlertType::Security,
        "Severity Preservation Test",
        "Checking severity flows from AlertSystem to TelemetryCollector.",
        "CommunicationPipeline_Tests");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!fired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_EQ(capturedSeverity, AlertSeverity::Emergency);
}

// ============================================================================
// GROUP 14 — CrossPipeline_DispatchToAlert
// ============================================================================
/**
 * Validates the MessageDispatcher → AlertSystem integration path:
 * a FileScanHandler or ProcessNotifyHandler raises an alert when the
 * scan verdict is Malicious.
 */
class CrossPipeline_DispatchToAlert : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_asInit = EnsureAlertSystemInit();
        s_tcInit = EnsureTelemetryCollectorInit();
    }
    void TearDown() override {
        AlertSystem::Instance().UnregisterCallbacks();
    }
    static bool s_asInit;
    static bool s_tcInit;
};
bool CrossPipeline_DispatchToAlert::s_asInit = false;
bool CrossPipeline_DispatchToAlert::s_tcInit = false;

// 14.1 FileScan handler raises a High alert when the scan returns Malicious.
TEST_F(CrossPipeline_DispatchToAlert, FileScan_Malicious_RaisesAlert) {
    if (!s_asInit) GTEST_SKIP() << "AlertSystem must be initialized.";

    DispatcherFixture f;
    std::atomic<bool>  alertRaised{false};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            if (a.type == AlertType::ThreatDetection &&
                a.severity == AlertSeverity::High) {
                alertRaised.store(true, std::memory_order_release);
            }
        });

    f.dispatcher.RegisterFileScanHandler(
        [](const FileScanRequest& req) -> ScanVerdictReply {
            // Simulated detection: raise a high alert for any execute request.
            if (req.accessType == Comm::FileAccessType::Execute) {
                (void)AlertSystem::Instance().RaiseAlert(
                    AlertSeverity::High,
                    AlertType::ThreatDetection,
                    "Malicious Executable Detected",
                    "File scan handler detected a suspicious executable.",
                    "MessageDispatcher");
            }
            ScanVerdictReply reply;
            reply.messageId     = req.messageId;
            reply.verdict       = ScanVerdict::Malicious;
            reply.threatDetected = true;
            reply.threatScore   = 95;
            return reply;
        });

    const wchar_t path[] = L"C:\\ProgramData\\dropper.exe";
    const uint16_t pLen  = static_cast<uint16_t>(wcslen(path));
    const auto payload   = BuildFileScanPayload(0xF001ULL, path, pLen, nullptr, 0, 4);
    const auto msg       = BuildMessage(MessageType::ScanRequest, 0xF001ULL,
                                         payload.data(), payload.size());

    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!alertRaised.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(alertRaised.load())
        << "A FileScanHandler detecting malicious activity must be able to raise "
           "a High-severity ThreatDetection alert via AlertSystem.";
}

// 14.2 ProcessNotify handler raises alert + records telemetry for privilege escalation.
TEST_F(CrossPipeline_DispatchToAlert, ProcessNotify_ElevatedProcess_RaisesAlertAndTelemetry) {
    if (!s_asInit || !s_tcInit)
        GTEST_SKIP() << "Both singletons must be initialized.";

    DispatcherFixture f;
    TelemetryCollector::Instance().ClearQueue();
    const size_t qBefore = TelemetryCollector::Instance().GetQueueSize();

    std::atomic<bool> alertFired{false};
    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            if (a.type == AlertType::Security) {
                DetectionEventData det;
                det.threatName = "PrivilegeEscalation";
                det.threatType = "Process";
                TelemetryCollector::Instance().RecordDetection(det);
            }
            alertFired.store(true, std::memory_order_release);
        });

    // WAS: this handler branched on n.isElevated and the payload below set an
    // isElevated byte. SHADOWSTRIKE_PROCESS_NOTIFICATION CARRIES NO ELEVATION BIT -
    // the field existed only in a fabricated user-mode struct - so the capability
    // this asserted could never have worked against a real kernel notification.
    // Re-expressed on Create, which the payload does carry, because what this
    // integration case is actually for is the dispatch -> alert -> telemetry chain,
    // not the elevation policy. Deciding elevation requires querying the pid in user
    // mode, and that query must not happen on a thread owing the kernel a verdict.
    f.dispatcher.RegisterProcessNotifyHandler(
        [](const ProcessNotification& n) {
            if (n.isCreation) {
                (void)AlertSystem::Instance().RaiseAlert(
                    AlertSeverity::High,
                    AlertType::Security,
                    "Process Created",
                    "A new process creation was reported by the kernel.",
                    "MessageDispatcher");
            }
        });

    // Build a real process-creation notification.
    SHADOWSTRIKE_PROCESS_NOTIFICATION pnd{};
    pnd.ProcessId = 999;
    pnd.Create    = TRUE;
    std::vector<uint8_t> pPayload(sizeof(pnd), 0);
    std::memcpy(pPayload.data(), &pnd, sizeof(pnd));
    const auto msg = BuildMessage(MessageType::ProcessNotify, 0xF002ULL,
                                   pPayload.data(), pPayload.size());

    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!alertFired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(alertFired.load())
        << "ProcessNotifyHandler must raise an alert for a reported process creation.";

    const auto deadline2 = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (TelemetryCollector::Instance().GetQueueSize() <= qBefore &&
           std::chrono::steady_clock::now() < deadline2) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_GT(TelemetryCollector::Instance().GetQueueSize(), qBefore)
        << "The alert callback must forward the detection to TelemetryCollector.";
}

// 14.3 RegistryNotify handler raises a PolicyViolation alert for a Run key write.
TEST_F(CrossPipeline_DispatchToAlert, RegistryNotify_RunKey_RaisesPolicyAlert) {
    if (!s_asInit) GTEST_SKIP() << "AlertSystem must be initialized.";

    DispatcherFixture f;
    std::atomic<bool> alertRaised{false};

    AlertSystem::Instance().RegisterAlertCallback(
        [&](const Alert& a) {
            if (a.type == AlertType::PolicyViolation)
                alertRaised.store(true, std::memory_order_release);
        });

    f.dispatcher.RegisterRegistryNotifyHandler(
        [](const RegistryNotification& n) {
            // Detect writes to the autorun registry key.
            if (n.keyPath.find(L"Run") != std::wstring::npos) {
                (void)AlertSystem::Instance().RaiseAlert(
                    AlertSeverity::Medium,
                    AlertType::PolicyViolation,
                    "Registry Autorun Key Modified",
                    "A process modified an autorun registry key.",
                    "MessageDispatcher");
            }
        });

    const wchar_t key[] = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t val[] = L"MalwarePersistence";
    const uint16_t kLen = static_cast<uint16_t>(wcslen(key));
    const uint16_t vLen = static_cast<uint16_t>(wcslen(val));
    const auto payload  = BuildRegistryNotifyPayload(0xF003ULL, key, kLen, val, vLen);
    const auto msg      = BuildMessage(MessageType::RegistryNotify, 0xF003ULL,
                                        payload.data(), payload.size());

    (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!alertRaised.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(alertRaised.load());
}

// 14.4 Dispatch statistics and AlertSystem statistics are both consistent
//      after a cross-pipeline dispatch-to-alert sequence.
TEST_F(CrossPipeline_DispatchToAlert, Statistics_Consistent_AfterCrossPipelineDispatch) {
    if (!s_asInit) GTEST_SKIP() << "AlertSystem must be initialized.";

    DispatcherFixture f;
    f.dispatcher.ResetStatistics();
    AlertSystem::Instance().ResetStatistics();

    f.dispatcher.RegisterProcessNotifyHandler(
        [](const ProcessNotification&) {
            (void)AlertSystem::Instance().RaiseAlert(
                AlertSeverity::Low,
                AlertType::Operational,
                "Process Notify Stats Test",
                "Pipeline statistics consistency check.",
                "MessageDispatcher");
        });

    for (int i = 0; i < 3; ++i) {
        const auto payload = BuildProcessNotifyPayload(
            static_cast<uint64_t>(0xF010 + i), nullptr, 0, nullptr, 0);
        const auto msg = BuildMessage(MessageType::ProcessNotify,
                                       static_cast<uint64_t>(0xF010 + i),
                                       payload.data(), payload.size());
        (void)f.dispatcher.DispatchMessage(std::span<const uint8_t>(msg));
    }

    const auto dispSnap = f.dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(dispSnap.processNotifications, 3u)
        << "Dispatcher must count 3 ProcessNotify messages.";

    const auto alertSnap = AlertSystem::Instance().GetStatistics();
    EXPECT_GE(alertSnap.totalAlerts, 3u)
        << "AlertSystem must record at least 3 alerts raised by the handler.";
}

// ============================================================================
// GROUP 15 — TypeContracts
// ============================================================================
/**
 * Validates enum ordinal values (which cross the kernel wire boundary),
 * struct layout invariants, and the name-lookup free functions.
 */
class TypeContracts : public ::testing::Test {};

// 15.1 AlertSeverity ordinals match the documented wire values.
TEST_F(TypeContracts, AlertSeverity_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::Info),      0u);
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::Low),       1u);
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::Medium),    2u);
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::High),      3u);
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::Critical),  4u);
    EXPECT_EQ(static_cast<uint8_t>(AlertSeverity::Emergency), 5u);
}

// 15.2 AlertType ordinals are stable.
TEST_F(TypeContracts, AlertType_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(AlertType::ThreatDetection), 0u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::SystemHealth),    1u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::PolicyViolation), 2u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::ComplianceAlert), 3u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::AuditEvent),      4u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::Operational),     5u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::Security),        6u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::Performance),     7u);
    EXPECT_EQ(static_cast<uint8_t>(AlertType::Custom),          8u);
}

// 15.3 AlertStatus ordinals are stable.
TEST_F(TypeContracts, AlertStatus_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::New),           0u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Pending),       1u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Sent),          2u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Acknowledged),  3u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Escalated),     4u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Resolved),      5u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Suppressed),    6u);
    EXPECT_EQ(static_cast<uint8_t>(AlertStatus::Failed),        7u);
}

// 15.4 TelemetryEventType ordinals are stable.
TEST_F(TypeContracts, TelemetryEventType_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Detection),     0u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Scan),          1u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Update),        2u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Crash),         3u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Error),         4u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Health),        5u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Performance),   6u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Configuration), 7u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::License),       8u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Feedback),      9u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Sample),        10u);
    EXPECT_EQ(static_cast<uint8_t>(TelemetryEventType::Custom),        11u);
}

// 15.5 ConsentLevel ordinals are stable.
TEST_F(TypeContracts, ConsentLevel_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(ConsentLevel::None),     0u);
    EXPECT_EQ(static_cast<uint8_t>(ConsentLevel::Required), 1u);
    EXPECT_EQ(static_cast<uint8_t>(ConsentLevel::Basic),    2u);
    EXPECT_EQ(static_cast<uint8_t>(ConsentLevel::Full),     3u);
}

// 15.6 MessageType kernel wire ordinals must not drift from the protocol contract.
TEST_F(TypeContracts, MessageType_KernelWireOrdinals) {
    EXPECT_EQ(static_cast<uint16_t>(MessageType::None),           0u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::ScanRequest),    5u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::ScanVerdictReply), 6u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::ProcessNotify),  7u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::RegistryNotify), 10u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::HandleAlert),    26u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::BehavioralAlert), 36u);
    EXPECT_EQ(static_cast<uint16_t>(MessageType::Max),            43u);
}

// 15.7 ScanVerdict wire ordinals must not drift.
TEST_F(TypeContracts, ScanVerdict_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Unknown),    0u);
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Clean),      1u);
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Malicious),  2u);
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Suspicious), 3u);
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Error),      4u);
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Timeout),    5u);
    // Aliases
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Allow), static_cast<uint8_t>(ScanVerdict::Clean));
    EXPECT_EQ(static_cast<uint8_t>(ScanVerdict::Block), static_cast<uint8_t>(ScanVerdict::Malicious));
}

// 15.8 MessageHeader must be exactly 40 bytes (static_assert already enforces this,
//      but the runtime test documents the contract for cross-version checks).
TEST_F(TypeContracts, MessageHeader_Size_40Bytes) {
    EXPECT_EQ(sizeof(MessageHeader), 40u);
}

// 15.9 GetAlertSeverityName() returns a non-empty string for every enum value.
TEST_F(TypeContracts, GetAlertSeverityName_AllValues_NonEmpty) {
    const AlertSeverity values[] = {
        AlertSeverity::Info, AlertSeverity::Low, AlertSeverity::Medium,
        AlertSeverity::High, AlertSeverity::Critical, AlertSeverity::Emergency
    };
    for (auto v : values) {
        EXPECT_FALSE(Comm::GetAlertSeverityName(v).empty())
            << "GetAlertSeverityName() must return non-empty for every severity.";
    }
}

// 15.10 GetAlertTypeName() returns non-empty for every AlertType value.
TEST_F(TypeContracts, GetAlertTypeName_AllValues_NonEmpty) {
    const AlertType values[] = {
        AlertType::ThreatDetection, AlertType::SystemHealth, AlertType::PolicyViolation,
        AlertType::ComplianceAlert, AlertType::AuditEvent,   AlertType::Operational,
        AlertType::Security,        AlertType::Performance,  AlertType::Custom
    };
    for (auto v : values) {
        EXPECT_FALSE(Comm::GetAlertTypeName(v).empty());
    }
}

// 15.11 GetEventTypeName() returns non-empty for every TelemetryEventType value.
TEST_F(TypeContracts, GetEventTypeName_AllValues_NonEmpty) {
    const TelemetryEventType values[] = {
        TelemetryEventType::Detection, TelemetryEventType::Scan,
        TelemetryEventType::Update,    TelemetryEventType::Crash,
        TelemetryEventType::Error,     TelemetryEventType::Health,
        TelemetryEventType::Performance, TelemetryEventType::Configuration,
        TelemetryEventType::License,   TelemetryEventType::Feedback,
        TelemetryEventType::Sample,    TelemetryEventType::Custom
    };
    for (auto v : values) {
        EXPECT_FALSE(Comm::GetEventTypeName(v).empty());
    }
}

// 15.12 Alert default construction initialises fields to documented defaults.
TEST_F(TypeContracts, Alert_DefaultConstruction_CorrectDefaults) {
    Alert a;
    EXPECT_EQ(a.severity,       AlertSeverity::Medium);
    EXPECT_EQ(a.type,           AlertType::ThreatDetection);
    EXPECT_EQ(a.status,         AlertStatus::New);
    EXPECT_EQ(a.escalationLevel, EscalationLevel::Level1);
    EXPECT_EQ(a.retryCount,     0u);
    EXPECT_TRUE(a.alertId.empty());
    EXPECT_TRUE(a.subject.empty());
}

// 15.13 TelemetryEvent default construction initialises fields correctly.
TEST_F(TypeContracts, TelemetryEvent_DefaultConstruction_CorrectDefaults) {
    TelemetryEvent ev;
    EXPECT_EQ(ev.eventType,         TelemetryEventType::Detection);
    EXPECT_EQ(ev.status,            Comm::SubmissionStatus::Pending);
    EXPECT_EQ(ev.retryCount,        0u);
    EXPECT_EQ(ev.timestamp,         0u);
    EXPECT_FALSE(ev.isAnonymized);
    EXPECT_EQ(ev.anonymizationLevel, AnonymizationLevel::Standard);
    EXPECT_TRUE(ev.eventId.empty());
}

// 15.14 EscalationLevel ordinals are stable.
TEST_F(TypeContracts, EscalationLevel_Ordinals) {
    EXPECT_EQ(static_cast<uint8_t>(EscalationLevel::Level1), 0u);
    EXPECT_EQ(static_cast<uint8_t>(EscalationLevel::Level2), 1u);
    EXPECT_EQ(static_cast<uint8_t>(EscalationLevel::Level3), 2u);
    EXPECT_EQ(static_cast<uint8_t>(EscalationLevel::Level4), 3u);
    EXPECT_EQ(static_cast<uint8_t>(EscalationLevel::Level5), 4u);
}

// 15.15 GetDeliveryChannelName() returns a non-empty string for all named channels.
TEST_F(TypeContracts, GetDeliveryChannelName_AllValues_NonEmpty) {
    const DeliveryChannel channels[] = {
        DeliveryChannel::Email,   DeliveryChannel::Slack,
        DeliveryChannel::Teams,   DeliveryChannel::SMS,
        DeliveryChannel::SIEM,    DeliveryChannel::Webhook,
        DeliveryChannel::Syslog
    };
    for (auto ch : channels) {
        EXPECT_FALSE(Comm::GetDeliveryChannelName(ch).empty())
            << "GetDeliveryChannelName() must return non-empty for every named channel.";
    }
}

// 15.16 GetAlertStatusName() returns a non-empty string for all AlertStatus values.
TEST_F(TypeContracts, GetAlertStatusName_AllValues_NonEmpty) {
    const AlertStatus statuses[] = {
        AlertStatus::New,          AlertStatus::Pending,
        AlertStatus::Sent,         AlertStatus::Acknowledged,
        AlertStatus::Escalated,    AlertStatus::Resolved,
        AlertStatus::Suppressed,   AlertStatus::Failed
    };
    for (auto s : statuses) {
        EXPECT_FALSE(Comm::GetAlertStatusName(s).empty())
            << "GetAlertStatusName() must return non-empty for every AlertStatus value.";
    }
}

// 15.17 GetEscalationLevelName() returns a non-empty string for all levels.
TEST_F(TypeContracts, GetEscalationLevelName_AllValues_NonEmpty) {
    const EscalationLevel levels[] = {
        EscalationLevel::Level1, EscalationLevel::Level2,
        EscalationLevel::Level3, EscalationLevel::Level4,
        EscalationLevel::Level5
    };
    for (auto l : levels) {
        EXPECT_FALSE(Comm::GetEscalationLevelName(l).empty())
            << "GetEscalationLevelName() must return non-empty for every EscalationLevel.";
    }
}

// ============================================================================
// GROUP 1 ADDITIONS — extended lifecycle contracts
// ============================================================================

// 1.11 AlertSystem version string must contain at least one dot (semantic version format).
TEST_F(Pipeline_Lifecycle, AlertSystem_VersionString_HasDotSeparator) {
    const std::string ver = AlertSystem::GetVersionString();
    EXPECT_NE(ver.find('.'), std::string::npos)
        << "AlertSystem::GetVersionString() must embed a semantic version (x.y.z) "
           "with at least one dot separator.";
}

// 1.12 TelemetryCollector version string must contain at least one dot separator.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_VersionString_HasDotSeparator) {
    const std::string ver = TelemetryCollector::GetVersionString();
    EXPECT_NE(ver.find('.'), std::string::npos)
        << "TelemetryCollector::GetVersionString() must embed a semantic version (x.y.z).";
}

// 1.13 A second AlertSystem::Initialize() call must not overwrite the first configuration.
//      Meyers' singleton contract: whichever caller wins the first init owns the config.
TEST_F(Pipeline_Lifecycle, AlertSystem_RepeatedInitialize_PreservesFirstConfig) {
    SKIP_AS();
    AlertConfiguration intruderCfg;
    intruderCfg.enabled           = false;   // deliberately contrary to first init
    intruderCfg.rateLimitPerMinute = 1;

    (void)AlertSystem::Instance().Initialize(intruderCfg);

    // The original enabled=true must be intact.
    const auto cfg = AlertSystem::Instance().GetConfiguration();
    EXPECT_TRUE(cfg.enabled)
        << "A second Initialize() call must not overwrite the configuration "
           "established by the first caller.";
}

// 1.14 A second TelemetryCollector::Initialize() call must not overwrite the first config.
TEST_F(Pipeline_Lifecycle, TelemetryCollector_RepeatedInitialize_PreservesFirstConfig) {
    SKIP_TC();
    TelemetryConfiguration intruderCfg;
    intruderCfg.enabled      = false;
    intruderCfg.consentLevel = ConsentLevel::None;

    (void)TelemetryCollector::Instance().Initialize(intruderCfg);

    const auto cfg = TelemetryCollector::Instance().GetConfiguration();
    EXPECT_TRUE(cfg.enabled)
        << "A second Initialize() must not change enabled=true set at first init.";
    EXPECT_NE(cfg.consentLevel, ConsentLevel::None)
        << "A second Initialize() must not change the consent level set at first init.";
}

// ============================================================================
// GROUP 2 ADDITIONS — additional parse adversarial edge cases
// ============================================================================

// 2.16 ParseFileScanRequest: processNameLength alone overflowing the buffer yields nullopt.
//      Validates that bounds checking covers both variable-length fields independently.
TEST_F(MessageDispatcher_Parse, FileScan_ProcNameExceedsBuffer_ReturnsNullopt) {
    auto payload = BuildFileScanPayload(0xFE02ULL, nullptr, 0, nullptr, 0);
    auto* fsr    = reinterpret_cast<FileScanRequestData*>(payload.data());
    fsr->pathLength        = 0;
    fsr->processNameLength = 32767;  // inflated — no actual data appended
    EXPECT_FALSE(MessageDispatcher::ParseFileScanRequest(
        std::span<const uint8_t>(payload)).has_value())
        << "A processNameLength that overflows the buffer must yield nullopt.";
}

// 2.17 ParseProcessNotification: CommandLineLength overflow must return nullopt.
//      Tests that both variable-length fields in the packed struct are bounds-checked.
TEST_F(MessageDispatcher_Parse, ProcessNotify_CmdLineExceedsBuffer_ReturnsNullopt) {
    auto payload = BuildProcessNotifyPayload(0xFE03ULL, nullptr, 0, nullptr, 0);
    auto* pnd    = reinterpret_cast<SHADOWSTRIKE_PROCESS_NOTIFICATION*>(payload.data());
    pnd->ImagePathLength   = 0;
    pnd->CommandLineLength = 32767;  // inflated - no actual data appended
    EXPECT_FALSE(MessageDispatcher::ParseProcessNotification(
        std::span<const uint8_t>(payload)).has_value())
        << "A CommandLineLength overflowing the buffer must yield nullopt (no over-read).";
}

// ============================================================================
// GROUP 5 ADDITIONS — additional AlertSystem core-operation edge cases
// ============================================================================

// 5.13 After raising an alert the singleton history must contain at least one
//      entry with the returned ID — GetRecentAlerts() is used here because the
//      test environment uses DeliveryChannel::None which causes the worker to
//      mark alerts as Failed (not Pending/Sent). GetPendingAlerts() semantics
//      are separately verified in the unit-level AlertSystem tests.
TEST_F(AlertSystem_CoreOperations, GetRecentAlerts_AfterRaise_ContainsNewAlert) {
    SKIP_AS();
    const std::string id = AlertSystem::Instance().RaiseAlert(
        AlertSeverity::High,
        AlertType::ThreatDetection,
        "Recent Alerts Contract Test",
        "Verifying that GetRecentAlerts() reflects a just-raised alert.",
        "CommunicationPipeline_Tests");

    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(WaitForAlertInHistory(id))
        << "Alert must appear in history within timeout after RaiseAlert().";

    const auto recent = AlertSystem::Instance().GetRecentAlerts(10);
    EXPECT_FALSE(recent.empty())
        << "GetRecentAlerts() must return at least the newly raised alert.";
    const bool found = std::any_of(recent.begin(), recent.end(),
        [&id](const Alert& a) { return a.alertId == id; });
    EXPECT_TRUE(found) << "GetRecentAlerts() must include the just-raised alert ID.";
}

// 5.14 Alert::ToJson() on a fully populated alert must return a non-empty JSON payload.
TEST_F(AlertSystem_CoreOperations, Alert_ToJson_ReturnsNonEmpty) {
    Alert a;
    a.alertId  = "toJson-test-id";
    a.severity = AlertSeverity::Critical;
    a.type     = AlertType::Security;
    a.subject  = "JSON Serialization Contract Test";
    a.details  = "Alert::ToJson() must produce a valid, non-empty JSON string.";
    a.source   = "CommunicationPipeline_Tests";
    a.status   = AlertStatus::New;

    const std::string json = a.ToJson();
    EXPECT_FALSE(json.empty())
        << "Alert::ToJson() must return a non-empty JSON payload for any populated alert.";
}

// 5.15 RaiseAlert() with an empty subject must not crash (adversarial robustness).
//      The system must handle empty/degenerate inputs without undefined behaviour.
TEST_F(AlertSystem_CoreOperations, RaiseAlert_EmptySubject_DoesNotCrash) {
    SKIP_AS();
    EXPECT_NO_FATAL_FAILURE({
        (void)AlertSystem::Instance().RaiseAlert(
            AlertSeverity::Low,
            AlertType::Operational,
            "",  // empty subject — adversarial input
            "Empty-subject adversarial robustness test.",
            "CommunicationPipeline_Tests");
    }) << "RaiseAlert() must not crash or assert on an empty subject string.";
}

// ============================================================================
// GROUP 6 ADDITIONS — WebhookConfiguration IsValid positive case
// ============================================================================

// 6.7 WebhookConfiguration::IsValid() returns true for a fully-populated config.
TEST_F(AlertSystem_RecipientWebhook, WebhookIsValid_FullyPopulated_ReturnsTrue) {
    WebhookConfiguration wh;
    wh.webhookId   = "valid-webhook-positive-test";
    wh.name        = "Valid Webhook";
    wh.url         = "https://hooks.example.com/valid";
    wh.channelType = DeliveryChannel::Webhook;
    wh.enabled     = true;
    EXPECT_TRUE(wh.IsValid())
        << "WebhookConfiguration::IsValid() must return true for a fully-populated, "
           "enabled webhook with a non-empty URL.";
}

// ============================================================================
// GROUP 11 ADDITION — eventsDropped privacy counter
// ============================================================================

// 11.13 eventsDropped increments when an event is attempted with ConsentLevel::None.
//       Privacy accounting contract: dropped events must be explicitly counted,
//       not silently discarded with no observable side-effect.
TEST_F(TelemetryCollector_Consent, ConsentNone_EventDropped_IncrementsDroppedCounter) {
    SKIP_TC();
    TelemetryCollector::Instance().SetConsentLevel(ConsentLevel::None);
    TelemetryCollector::Instance().ResetStatistics();
    TelemetryCollector::Instance().ClearQueue();

    TelemetryCollector::Instance().RecordEvent("Detection", R"({"threat":"DropCounterTest"})");

    const auto snap = TelemetryCollector::Instance().GetStatistics();
    EXPECT_GE(snap.eventsDropped, 1u)
        << "eventsDropped must increment when an event is rejected due to ConsentLevel::None. "
           "Silent discard without counter update violates the privacy accounting contract.";
    // TearDown() restores ConsentLevel::Full.
}

// ============================================================================
// GROUP 16 — Hardening: EscalationRule CRUD / FilterConnection / DispatchAsync
// ============================================================================
/**
 * Supplementary hardening tests covering API surfaces not exercised in
 * Groups 1–15: escalation rule management, FilterConnection state contracts,
 * and async dispatch lifecycle.
 */

class Hardening_EscalationRules : public ::testing::Test {
public:
    static void SetUpTestSuite() { s_asInit = EnsureAlertSystemInit(); }
    static bool s_asInit;
};
bool Hardening_EscalationRules::s_asInit = false;

// 16.1 AddEscalationRule() persists a rule retrievable via GetEscalationRules().
TEST_F(Hardening_EscalationRules, AddEscalationRule_Persists) {
    SKIP_AS();
    EscalationRule rule;
    rule.ruleId         = "hardening-escalation-persist";
    rule.name           = "Hardening Escalation Persist Test";
    rule.minSeverity    = AlertSeverity::High;
    rule.alertTypes     = { AlertType::ThreatDetection, AlertType::Security };
    rule.timeoutMinutes = 15;
    rule.enabled        = true;

    EXPECT_TRUE(AlertSystem::Instance().AddEscalationRule(rule))
        << "AddEscalationRule() must return true for a valid, uniquely-IDed rule.";

    const auto rules = AlertSystem::Instance().GetEscalationRules();
    const bool found = std::any_of(rules.begin(), rules.end(),
        [](const EscalationRule& r) {
            return r.ruleId == "hardening-escalation-persist";
        });
    EXPECT_TRUE(found)
        << "AddEscalationRule() must make the rule visible via GetEscalationRules().";
}

// 16.2 RemoveEscalationRule() by known ID removes the previously-added rule.
TEST_F(Hardening_EscalationRules, RemoveEscalationRule_ByKnownId_Removed) {
    SKIP_AS();
    EscalationRule rule;
    rule.ruleId  = "hardening-escalation-remove";
    rule.name    = "Temp Escalation Rule for Removal Test";
    rule.enabled = true;
    (void)AlertSystem::Instance().AddEscalationRule(rule);

    EXPECT_TRUE(AlertSystem::Instance().RemoveEscalationRule("hardening-escalation-remove"))
        << "RemoveEscalationRule() must return true for a known rule ID.";

    const auto rules = AlertSystem::Instance().GetEscalationRules();
    const bool stillPresent = std::any_of(rules.begin(), rules.end(),
        [](const EscalationRule& r) {
            return r.ruleId == "hardening-escalation-remove";
        });
    EXPECT_FALSE(stillPresent)
        << "RemoveEscalationRule() must remove the rule from GetEscalationRules().";
}

// 16.3 RemoveEscalationRule() with an unknown ID must return false without crashing.
TEST_F(Hardening_EscalationRules, RemoveEscalationRule_UnknownId_ReturnsFalse) {
    SKIP_AS();
    EXPECT_FALSE(
        AlertSystem::Instance().RemoveEscalationRule("no-such-escalation-rule-xyz-9999"))
        << "RemoveEscalationRule() must return false for an unknown rule ID.";
}

// ============================================================================

class Hardening_FilterConnection : public ::testing::Test {};

// 16.4 FilterConnection constructed with a non-existent port must report IsConnected()==false.
//      This is the fundamental state contract used throughout the test suite.
TEST_F(Hardening_FilterConnection, DisconnectedPort_IsConnected_False) {
    FilterConnection fc{ L"\\PhantomSensorHardeningTestPort_NeverExists" };
    EXPECT_FALSE(fc.IsConnected())
        << "A FilterConnection to a non-existent port must report IsConnected()==false.";
}

// 16.5 GetHandle() on a disconnected FilterConnection must return nullptr.
TEST_F(Hardening_FilterConnection, DisconnectedPort_GetHandle_Nullptr) {
    FilterConnection fc{ L"\\PhantomSensorHardeningTestPort_NeverExists2" };
    EXPECT_EQ(fc.GetHandle(), nullptr)
        << "GetHandle() must return nullptr for a FilterConnection that is not connected.";
}

// 16.6 GetLastErrorMessage() on a disconnected port must return a non-empty string.
//      The error must be surfaced as an actionable message, not silently eaten.
TEST_F(Hardening_FilterConnection, DisconnectedPort_GetLastErrorMessage_NonEmpty) {
    FilterConnection fc{ L"\\PhantomSensorHardeningTestPort_NeverExists3" };
    // Attempt a connect — will fail; error state must be populated.
    (void)fc.Connect();
    EXPECT_FALSE(fc.GetLastErrorMessage().empty())
        << "GetLastErrorMessage() must be non-empty after a failed Connect() attempt.";
}

// ============================================================================

class Hardening_AsyncDispatch : public ::testing::Test {
protected:
    DispatcherFixture f;
};

// 16.7 DispatchMessageAsync returns a valid future; bad magic resolves to false.
TEST_F(Hardening_AsyncDispatch, BadMagic_AsyncDispatch_FutureResolvesToFalse) {
    auto buf   = BuildMessage(MessageType::ProcessNotify, 0xA010ULL, nullptr, 0);
    auto* hdr  = reinterpret_cast<MessageHeader*>(buf.data());
    hdr->magic = 0xDEADC0DEu;   // corrupt magic

    auto fut = f.dispatcher.DispatchMessageAsync(std::span<const uint8_t>(buf));
    ASSERT_TRUE(fut.valid())
        << "DispatchMessageAsync must always return a valid std::future.";
    EXPECT_FALSE(fut.get())
        << "A message with a corrupt magic must resolve the async future to false.";
}

// 16.8 DispatchMessageAsync with a valid ProcessNotify fires the handler asynchronously
//      and resolves the future to true.
TEST_F(Hardening_AsyncDispatch, ValidProcessNotify_AsyncDispatch_FutureResolvesToTrue) {
    std::atomic<bool> handlerFired{ false };
    f.dispatcher.RegisterProcessNotifyHandler(
        [&handlerFired](const ProcessNotification&) {
            handlerFired.store(true, std::memory_order_release);
        });

    const auto payload = BuildProcessNotifyPayload(0xA011ULL, nullptr, 0, nullptr, 0, 9901);
    const auto msg     = BuildMessage(MessageType::ProcessNotify, 0xA011ULL,
                                      payload.data(), payload.size());

    auto fut = f.dispatcher.DispatchMessageAsync(std::span<const uint8_t>(msg));
    ASSERT_TRUE(fut.valid());
    const bool result = fut.get();
    EXPECT_TRUE(result)
        << "DispatchMessageAsync must resolve to true for a valid, handleable message.";
    EXPECT_TRUE(handlerFired.load(std::memory_order_acquire))
        << "DispatchMessageAsync must invoke the registered ProcessNotify handler "
           "before the future resolves.";
}
