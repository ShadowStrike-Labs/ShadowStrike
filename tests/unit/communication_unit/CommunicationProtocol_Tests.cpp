#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Communication/Communication.hpp"
#include "../../../src/PhantomCore/Communication/FilterConnection.hpp"
#include "../../../src/PhantomCore/Communication/MessageDispatcher.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace Comm = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;

template <typename T>
void AppendPod(std::vector<uint8_t>& buffer, const T& value) {
    const size_t offset = buffer.size();
    buffer.resize(offset + sizeof(T));
    std::memcpy(buffer.data() + offset, &value, sizeof(T));
}

void AppendWideString(std::vector<uint8_t>& buffer, std::wstring_view value) {
    if (value.empty()) {
        return;
    }

    const size_t byteCount = value.size() * sizeof(wchar_t);
    const size_t offset = buffer.size();
    buffer.resize(offset + byteCount);
    std::memcpy(buffer.data() + offset, value.data(), byteCount);
}

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

std::vector<uint8_t> BuildMessageBuffer(
    Comm::MessageType type,
    std::span<const uint8_t> payload = {},
    uint64_t messageId = 0x1234ULL) {

    Comm::MessageHeader header{};
    header.magic = Comm::MESSAGE_MAGIC;
    header.version = Comm::PROTOCOL_VERSION;
    header.messageType = static_cast<uint16_t>(type);
    header.messageId = messageId;
    header.totalSize = static_cast<uint32_t>(sizeof(Comm::MessageHeader) + payload.size());
    header.dataSize = static_cast<uint32_t>(payload.size());

    std::vector<uint8_t> buffer;
    AppendPod(buffer, header);
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    return buffer;
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike Communication Protocol - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Kernel/user-mode wire contract validation
 * - Static parsing and serialization in MessageDispatcher.cpp
 * - JSON/status surfaces that higher-level components consume
 * - Statistics reset/snapshot behavior used by diagnostics paths
 *
 * These tests intentionally stay on pure, deterministic unit-test surfaces and
 * avoid live Filter Manager / kernel communication side effects.
 *
 * ============================================================================
 */

TEST(CommunicationProtocolTest, MessageHeaderValidationAcceptsOnlyWireCompatibleHeaders) {
    Comm::MessageHeader header{};
    header.magic = Comm::MESSAGE_MAGIC;
    header.version = Comm::PROTOCOL_VERSION;
    header.totalSize = sizeof(Comm::MessageHeader);
    header.dataSize = 0;

    EXPECT_TRUE(header.IsValid());

    header.magic = 0;
    EXPECT_FALSE(header.IsValid());

    header.magic = Comm::MESSAGE_MAGIC;
    header.version = Comm::PROTOCOL_VERSION + 1;
    EXPECT_FALSE(header.IsValid());

    header.version = Comm::PROTOCOL_VERSION;
    header.totalSize = sizeof(Comm::MessageHeader) - 1;
    EXPECT_FALSE(header.IsValid());

    header.totalSize = Comm::MAX_MESSAGE_SIZE + 1;
    EXPECT_FALSE(header.IsValid());

    header.totalSize = sizeof(Comm::MessageHeader);
    header.version = Comm::PROTOCOL_VERSION - 1;
    EXPECT_TRUE(header.IsValid());
}

TEST(CommunicationProtocolTest, ParseFileScanRequestParsesFixedAndVariableFields) {
    const std::wstring filePath = LR"(C:\Temp\specimen.exe)";
    const std::wstring processName = LR"(scanner.exe)";

    Comm::FileScanRequestData raw{};
    raw.messageId = 0x1122334455667788ULL;
    raw.accessType = static_cast<uint8_t>(Comm::FileAccessType::Execute);
    raw.priority = static_cast<uint8_t>(Comm::ScanPriority::Critical);
    raw.requiresReply = 1;
    raw.processId = 4242;
    raw.threadId = 3131;
    raw.parentProcessId = 1111;
    raw.sessionId = 9;
    raw.fileSize = 65'535;
    raw.fileAttributes = 0x20;
    raw.desiredAccess = 0x00120089;
    raw.shareAccess = 0x00000003;
    raw.createOptions = 0x200000;
    raw.volumeSerial = 0xAABBCCDD;
    raw.fileId = 0x8877665544332211ULL;
    raw.isDirectory = 0;
    raw.isNetworkFile = 1;
    raw.isRemovableMedia = 0;
    raw.hasADS = 1;
    raw.pathLength = static_cast<uint16_t>(filePath.size());
    raw.processNameLength = static_cast<uint16_t>(processName.size());

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);
    AppendWideString(buffer, filePath);
    AppendWideString(buffer, processName);

    const auto request = Comm::MessageDispatcher::ParseFileScanRequest(buffer);
    ASSERT_TRUE(request.has_value());

    EXPECT_EQ(request->messageId, raw.messageId);
    EXPECT_EQ(request->filePath, filePath);
    EXPECT_EQ(request->processName, processName);
    EXPECT_EQ(request->accessType, Comm::FileAccessType::Execute);
    EXPECT_EQ(request->priority, Comm::ScanPriority::Critical);
    EXPECT_EQ(request->processId, raw.processId);
    EXPECT_EQ(request->threadId, raw.threadId);
    EXPECT_EQ(request->parentProcessId, raw.parentProcessId);
    EXPECT_EQ(request->sessionId, raw.sessionId);
    EXPECT_EQ(request->fileSize, raw.fileSize);
    EXPECT_EQ(request->volumeSerial, raw.volumeSerial);
    EXPECT_TRUE(request->isNetworkFile);
    EXPECT_TRUE(request->hasADS);
    EXPECT_TRUE(request->requiresReply);
}

TEST(CommunicationProtocolTest, ParseFileScanRequestRejectsTruncatedVariableData) {
    Comm::FileScanRequestData raw{};
    raw.pathLength = 10;
    raw.processNameLength = 6;

    std::vector<uint8_t> buffer(sizeof(raw));
    std::memcpy(buffer.data(), &raw, sizeof(raw));

    EXPECT_FALSE(Comm::MessageDispatcher::ParseFileScanRequest(buffer).has_value());
}

TEST(CommunicationProtocolTest, ParseFileScanRequestAcceptsHeaderOnlyBuffersWhenStringsAreEmpty) {
    Comm::FileScanRequestData raw{};
    raw.messageId = 15;
    raw.accessType = static_cast<uint8_t>(Comm::FileAccessType::Read);
    raw.priority = static_cast<uint8_t>(Comm::ScanPriority::Low);
    raw.processId = 91;
    raw.requiresReply = 0;

    std::vector<uint8_t> buffer(sizeof(raw));
    std::memcpy(buffer.data(), &raw, sizeof(raw));

    const auto request = Comm::MessageDispatcher::ParseFileScanRequest(buffer);
    ASSERT_TRUE(request.has_value());
    EXPECT_TRUE(request->filePath.empty());
    EXPECT_TRUE(request->processName.empty());
    EXPECT_EQ(request->processId, 91u);
    EXPECT_FALSE(request->requiresReply);
    EXPECT_EQ(request->priority, Comm::ScanPriority::Low);
}

// ============================================================================
// Process / registry notification parsing.
//
// THESE TESTS WERE REWRITTEN AND THE REASON MATTERS MORE THAN THE TESTS.
// They previously built their payloads from Communication::ProcessNotificationData
// and Communication::RegistryNotificationData - structs that described a layout the
// driver has never emitted - and then parsed them back with a parser built on the
// same structs. Serializing and deserializing through one wrong definition agrees
// with itself perfectly, so all six cases passed while proving nothing whatsoever
// about the wire. That is why the fabrication survived long enough for
// RegistryMonitor to ship a parser that never processed a single registry event
// (fixed in 5fe45d55).
//
// Every case below now builds the payload from the KERNEL struct in
// PhantomSensor/Shared/MessageProtocol.h - the same declaration the driver writes
// through - so a divergence on either side fails here instead of being ratified.
// MessageProtocol.h arrives transitively via Communication.hpp, which includes it
// precisely so this comparison is possible.
// ============================================================================

TEST(CommunicationProtocolTest, ParseProcessNotificationReadsTheLayoutTheDriverWrites) {
    const std::wstring imagePath = LR"(C:\Windows\System32\cmd.exe)";
    const std::wstring commandLine = LR"("C:\Windows\System32\cmd.exe" /c whoami)";

    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    raw.ProcessId = 9001;
    raw.ParentProcessId = 1337;
    raw.CreatingProcessId = 100;
    raw.CreatingThreadId = 101;
    raw.Create = TRUE;
    // BYTE counts, exactly as ProcessNotify.c:3798 and ScanBridge.c:1491 write them.
    raw.ImagePathLength = static_cast<uint16_t>(imagePath.size() * sizeof(wchar_t));
    raw.CommandLineLength = static_cast<uint16_t>(commandLine.size() * sizeof(wchar_t));

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);
    AppendWideString(buffer, imagePath);
    AppendWideString(buffer, commandLine);

    const auto notification = Comm::MessageDispatcher::ParseProcessNotification(buffer);
    ASSERT_TRUE(notification.has_value())
        << "the parser must accept a payload built from the kernel's own struct";

    EXPECT_EQ(notification->processId, 9001u);
    EXPECT_EQ(notification->parentProcessId, 1337u);
    EXPECT_EQ(notification->creatingProcessId, 100u);
    EXPECT_EQ(notification->creatingThreadId, 101u);
    EXPECT_EQ(notification->imagePath, imagePath);
    EXPECT_EQ(notification->commandLine, commandLine);
    EXPECT_TRUE(notification->isCreation);
}

// The kernel struct opens with a 40-byte SS_MESSAGE_HEADER that the driver zeroes
// and never fills. It is redundant with the outer frame header, which is exactly
// what makes it easy to "optimise" away - and every field offset depends on it.
// Fill it with a recognisable pattern: a parser that reads ProcessId from offset 0
// instead of offset 40 recovers 0xEEEEEEEE and this test names it.
TEST(CommunicationProtocolTest, ParseProcessNotificationAccountsForTheDeadInnerHeader) {
    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    std::memset(&raw.Header, 0xEE, sizeof(raw.Header));
    raw.ProcessId = 4242;
    raw.ParentProcessId = 24;
    raw.Create = TRUE;
    raw.ImagePathLength = 0;
    raw.CommandLineLength = 0;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    const auto notification = Comm::MessageDispatcher::ParseProcessNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_EQ(notification->processId, 4242u)
        << "processId must be read from offset 40, past the dead inner header";
    EXPECT_NE(notification->processId, 0xEEEEEEEEu)
        << "the parser is reading the inner header as if it were the payload fields";
    EXPECT_EQ(notification->parentProcessId, 24u);
}

// The unit of the length fields is not visible from their names, and getting it
// wrong is not a cosmetic error: reading a byte count as a character count walks
// twice as far as the payload extends. Give the parser a path whose byte length is
// unambiguous and require the exact string back - a character-count reading returns
// double the characters, a halving returns half the path.
TEST(CommunicationProtocolTest, ParseProcessNotificationTreatsLengthsAsBytesNotCharacters) {
    const std::wstring imagePath = L"C:\\a\\b.exe";   // 10 chars, 20 bytes
    ASSERT_EQ(imagePath.size(), 10u);

    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    raw.ProcessId = 7;
    raw.Create = TRUE;
    raw.ImagePathLength = 20;   // BYTES
    raw.CommandLineLength = 0;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);
    AppendWideString(buffer, imagePath);

    const auto notification = Comm::MessageDispatcher::ParseProcessNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_EQ(notification->imagePath.size(), 10u)
        << "20 wire bytes is 10 wide characters; a character-count reading would "
           "produce 20 and run past the payload";
    EXPECT_EQ(notification->imagePath, imagePath);
}

// Create versus exit is the single most consequential bit in this payload, and the
// parsed type had no field for it at all while the fabricated struct was in use.
TEST(CommunicationProtocolTest, ParseProcessNotificationDistinguishesCreationFromExit) {
    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    raw.ProcessId = 31337;
    raw.Create = FALSE;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    const auto notification = Comm::MessageDispatcher::ParseProcessNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_FALSE(notification->isCreation)
        << "a process exit must not be reported as a creation";
}

TEST(CommunicationProtocolTest, ParseProcessNotificationRejectsShortBuffer) {
    std::vector<uint8_t> buffer(sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) - 1, 0xAB);
    EXPECT_FALSE(Comm::MessageDispatcher::ParseProcessNotification(buffer).has_value());
}

TEST(CommunicationProtocolTest, ParseProcessNotificationRejectsOverlongVariableLengths) {
    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    raw.ProcessId = 1;
    raw.ImagePathLength = 64;      // claims 64 bytes that are not present
    raw.CommandLineLength = 0;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);        // fixed part only

    EXPECT_FALSE(Comm::MessageDispatcher::ParseProcessNotification(buffer).has_value())
        << "a declared length beyond the delivered payload must be refused, not read";
}

TEST(CommunicationProtocolTest, ParseProcessNotificationAcceptsFixedPartWhenStringsAreEmpty) {
    SHADOWSTRIKE_PROCESS_NOTIFICATION raw{};
    raw.ProcessId = 500;
    raw.ParentProcessId = 400;
    raw.Create = TRUE;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    const auto notification = Comm::MessageDispatcher::ParseProcessNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_TRUE(notification->imagePath.empty());
    EXPECT_TRUE(notification->commandLine.empty());
    EXPECT_EQ(notification->processId, 500u);
    EXPECT_EQ(notification->parentProcessId, 400u);
}

TEST(CommunicationProtocolTest, ParseRegistryNotificationReadsTheLayoutTheDriverWrites) {
    const std::wstring keyPath = LR"(HKCU\Software\ShadowStrike)";
    const std::wstring valueName = LR"(PolicyState)";
    const std::array<uint8_t, 4> valueData{0x10, 0x20, 0x30, 0x40};

    SHADOWSTRIKE_REGISTRY_NOTIFICATION raw{};
    raw.ProcessId = 777;
    raw.ThreadId = 778;
    raw.Operation = 2;
    raw.DataType = 4;
    // BYTE counts, exactly as ScanBridge.c:1952 writes them.
    raw.KeyPathLength = static_cast<uint16_t>(keyPath.size() * sizeof(wchar_t));
    raw.ValueNameLength = static_cast<uint16_t>(valueName.size() * sizeof(wchar_t));
    raw.DataSize = static_cast<uint32_t>(valueData.size());

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);
    AppendWideString(buffer, keyPath);
    AppendWideString(buffer, valueName);
    buffer.insert(buffer.end(), valueData.begin(), valueData.end());

    const auto notification = Comm::MessageDispatcher::ParseRegistryNotification(buffer);
    ASSERT_TRUE(notification.has_value())
        << "the parser must accept a payload built from the kernel's own struct";

    EXPECT_EQ(notification->processId, 777u);
    EXPECT_EQ(notification->threadId, 778u);
    EXPECT_EQ(notification->operationType, 2u);
    EXPECT_EQ(notification->valueType, 4u);
    EXPECT_EQ(notification->keyPath, keyPath);
    EXPECT_EQ(notification->valueName, valueName);
    ASSERT_EQ(notification->valueData.size(), valueData.size());
    EXPECT_EQ(notification->valueData[0], valueData[0]);
    EXPECT_EQ(notification->valueData[3], valueData[3]);
}

TEST(CommunicationProtocolTest, ParseRegistryNotificationTreatsLengthsAsBytesNotCharacters) {
    const std::wstring keyPath = L"HKCU\\Zz";   // 7 chars, 14 bytes
    ASSERT_EQ(keyPath.size(), 7u);

    SHADOWSTRIKE_REGISTRY_NOTIFICATION raw{};
    raw.ProcessId = 5;
    raw.KeyPathLength = 14;   // BYTES
    raw.ValueNameLength = 0;
    raw.DataSize = 0;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);
    AppendWideString(buffer, keyPath);

    const auto notification = Comm::MessageDispatcher::ParseRegistryNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_EQ(notification->keyPath.size(), 7u)
        << "14 wire bytes is 7 wide characters";
    EXPECT_EQ(notification->keyPath, keyPath);
}

TEST(CommunicationProtocolTest, ParseRegistryNotificationRejectsTruncatedValueData) {
    SHADOWSTRIKE_REGISTRY_NOTIFICATION raw{};
    raw.KeyPathLength = 4;
    raw.ValueNameLength = 4;
    raw.DataSize = 16;   // not present in the buffer

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    EXPECT_FALSE(Comm::MessageDispatcher::ParseRegistryNotification(buffer).has_value());
}

// The overflow cap is the reason DataSize is checked on its own before being summed
// with the two name lengths: it is a UINT32 straight off the wire.
TEST(CommunicationProtocolTest, ParseRegistryNotificationRejectsAbsurdDataSizeBeforeSumming) {
    SHADOWSTRIKE_REGISTRY_NOTIFICATION raw{};
    raw.KeyPathLength = 0;
    raw.ValueNameLength = 0;
    raw.DataSize = 0xFFFFFFFFu;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    EXPECT_FALSE(Comm::MessageDispatcher::ParseRegistryNotification(buffer).has_value())
        << "a length that could wrap the bounds arithmetic must be refused up front";
}

TEST(CommunicationProtocolTest, ParseRegistryNotificationAcceptsFixedPartWhenPayloadIsEmpty) {
    SHADOWSTRIKE_REGISTRY_NOTIFICATION raw{};
    raw.ProcessId = 701;
    raw.ThreadId = 702;
    raw.Operation = 5;
    raw.DataType = 1;

    std::vector<uint8_t> buffer;
    AppendPod(buffer, raw);

    const auto notification = Comm::MessageDispatcher::ParseRegistryNotification(buffer);
    ASSERT_TRUE(notification.has_value());
    EXPECT_TRUE(notification->keyPath.empty());
    EXPECT_TRUE(notification->valueName.empty());
    EXPECT_TRUE(notification->valueData.empty());
    EXPECT_EQ(notification->operationType, 5u);
}

// Both parsers are declared to read the kernel's layout, so the sizes they bound
// against are part of the contract. If either fires, a struct moved on one side of
// the boundary only.
TEST(CommunicationProtocolTest, TheParsedWireStructsAreTheSizesTheDriverWrites) {
    EXPECT_EQ(sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION), 61u)
        << "40-byte dead header + 4 ids + Create + two 2-byte lengths";
    EXPECT_EQ(sizeof(SHADOWSTRIKE_REGISTRY_NOTIFICATION), 21u)
        << "two ids + Operation + two 2-byte lengths + DataSize + DataType";
}

TEST(CommunicationProtocolTest, SerializeVerdictReplyProducesWireCompatibleLayout) {
    Comm::ScanVerdictReply reply{};
    reply.messageId = 0xCAFEBABEULL;
    reply.verdict = Comm::ScanVerdict::Malicious;
    reply.resultCode = 7;
    reply.threatDetected = true;
    reply.threatScore = 93;
    reply.shouldCache = true;
    reply.cacheTTL = 300;
    reply.threatName = L"Trojan.Test";

    const std::vector<uint8_t> buffer = Comm::MessageDispatcher::SerializeVerdictReply(reply);
    ASSERT_EQ(buffer.size(),
              sizeof(Comm::ScanVerdictReplyData) + reply.threatName.size() * sizeof(wchar_t));

    const auto* raw = reinterpret_cast<const Comm::ScanVerdictReplyData*>(buffer.data());
    EXPECT_EQ(raw->messageId, reply.messageId);
    EXPECT_EQ(raw->verdict, static_cast<uint8_t>(reply.verdict));
    EXPECT_EQ(raw->resultCode, reply.resultCode);
    EXPECT_EQ(raw->threatDetected, 1u);
    EXPECT_EQ(raw->threatScore, reply.threatScore);
    EXPECT_EQ(raw->cacheResult, 1u);
    EXPECT_EQ(raw->cacheTTL, reply.cacheTTL);
    EXPECT_EQ(raw->threatNameLength, reply.threatName.size());

    const auto* threatNamePtr = reinterpret_cast<const wchar_t*>(
        buffer.data() + sizeof(Comm::ScanVerdictReplyData));
    const std::wstring decoded(threatNamePtr, raw->threatNameLength);
    EXPECT_EQ(decoded, reply.threatName);
}

TEST(CommunicationProtocolTest, SerializeVerdictReplyOmitsVariablePayloadForEmptyThreatName) {
    Comm::ScanVerdictReply reply{};
    reply.messageId = 0xAA55;
    reply.verdict = Comm::ScanVerdict::Clean;
    reply.resultCode = 0;
    reply.threatDetected = false;

    const std::vector<uint8_t> buffer = Comm::MessageDispatcher::SerializeVerdictReply(reply);
    ASSERT_EQ(buffer.size(), sizeof(Comm::ScanVerdictReplyData));

    const auto* raw = reinterpret_cast<const Comm::ScanVerdictReplyData*>(buffer.data());
    EXPECT_EQ(raw->threatNameLength, 0u);
    EXPECT_EQ(raw->cacheResult, 0u);
    EXPECT_EQ(raw->threatDetected, 0u);
}

TEST(CommunicationProtocolTest, UserModeStructuresSerializeToJsonWithEscapedContent) {
    Comm::FileScanRequest fileRequest{};
    fileRequest.messageId = 10;
    fileRequest.filePath = LR"(C:\Temp\alpha"sample.exe)";
    fileRequest.processName = LR"(proc"name.exe)";
    fileRequest.processId = 42;
    fileRequest.fileSize = 1234;
    fileRequest.isDirectory = false;
    fileRequest.isNetworkFile = true;
    fileRequest.requiresReply = true;

    const std::string fileJson = fileRequest.ToJson();
    EXPECT_NE(fileJson.find("\"messageId\":10"), std::string::npos);
    EXPECT_NE(fileJson.find("alpha\\\"sample.exe"), std::string::npos);
    EXPECT_NE(fileJson.find("proc\\\"name.exe"), std::string::npos);
    EXPECT_NE(fileJson.find("\"isNetworkFile\":true"), std::string::npos);

    Comm::ProcessNotification processNotification{};
    processNotification.messageId = 11;
    processNotification.processId = 99;
    processNotification.parentProcessId = 12;
    processNotification.imagePath = LR"(C:\Windows\app.exe)";
    processNotification.commandLine = LR"("C:\Windows\app.exe" --flag)";
    processNotification.isWow64 = true;
    processNotification.isElevated = false;
    processNotification.requiresReply = true;

    const std::string processJson = processNotification.ToJson();
    EXPECT_NE(processJson.find("\"processId\":99"), std::string::npos);
    EXPECT_NE(processJson.find("\"requiresReply\":true"), std::string::npos);

    Comm::RegistryNotification registryNotification{};
    registryNotification.messageId = 12;
    registryNotification.processId = 88;
    registryNotification.keyPath = LR"(HKLM\Software\ShadowStrike)";
    registryNotification.valueName = LR"(Setting)";
    registryNotification.operationType = 3;
    registryNotification.valueType = 1;
    registryNotification.requiresReply = false;

    const std::string registryJson = registryNotification.ToJson();
    EXPECT_NE(registryJson.find("\"keyPath\":\"HKLM\\\\Software\\\\ShadowStrike\""), std::string::npos);
    EXPECT_NE(registryJson.find("\"requiresReply\":false"), std::string::npos);

    Comm::ScanVerdictReply verdictReply{};
    verdictReply.messageId = 13;
    verdictReply.verdict = Comm::ScanVerdict::Suspicious;
    verdictReply.resultCode = 9;
    verdictReply.threatDetected = true;
    verdictReply.threatScore = 51;
    verdictReply.shouldCache = false;
    verdictReply.cacheTTL = 0;
    verdictReply.threatName = LR"(Suspicious"Artifact)";

    const std::string verdictJson = verdictReply.ToJson();
    EXPECT_NE(verdictJson.find("\"verdict\":3"), std::string::npos);
    EXPECT_NE(verdictJson.find("Suspicious\\\"Artifact"), std::string::npos);
}

TEST(CommunicationProtocolTest, CommunicationConfigSerializesAndEmptyJsonFallsBackToDefaults) {
    Comm::CommunicationConfig config{};
    config.portName = LR"(\CustomShadowStrikePort)";
    config.replyTimeoutMs = 15'000;
    config.reconnectIntervalMs = 9'000;
    config.maxReconnectAttempts = 4;
    config.messageQueueSize = 2048;
    config.workerThreadCount = 6;
    config.autoReconnect = false;
    config.blockOnTimeout = true;
    config.enableStatistics = false;

    const std::string json = config.ToJson();
    EXPECT_NE(json.find("\"portName\":\"\\\\CustomShadowStrikePort\""), std::string::npos);
    EXPECT_NE(json.find("\"replyTimeoutMs\":15000"), std::string::npos);
    EXPECT_NE(json.find("\"enableStatistics\":false"), std::string::npos);

    const Comm::CommunicationConfig parsed = Comm::CommunicationConfig::FromJson({});
    EXPECT_EQ(parsed.portName, Comm::SS_COMM_PORT_NAME);
    EXPECT_EQ(parsed.replyTimeoutMs, Comm::DEFAULT_REPLY_TIMEOUT_MS);
    EXPECT_TRUE(parsed.autoReconnect);
    EXPECT_TRUE(parsed.enableStatistics);

    const Comm::CommunicationConfig malformed =
        Comm::CommunicationConfig::FromJson("{\"portName\":\"\\\\ignored\", this is not json");
    EXPECT_EQ(malformed.portName, Comm::SS_COMM_PORT_NAME);
    EXPECT_EQ(malformed.replyTimeoutMs, Comm::DEFAULT_REPLY_TIMEOUT_MS);
    EXPECT_EQ(malformed.workerThreadCount, 4u);

    // WELL-FORMED input is honoured, which is what makes ToJson above worth having.
    // This block used to feed FromJson valid JSON, call it "malformed", and assert
    // that portName and replyTimeoutMs were IGNORED - which contradicted the first
    // half of this same test, where ToJson is checked for emitting exactly those two
    // fields. A round trip would have been impossible.
    //
    // Range checking is the consumer's job and is already done there:
    // IPCManager rejects replyTimeoutMs == 0 or > 300000 before using it, with its
    // own tests. FromJson has no production callers at all today.
    const Comm::CommunicationConfig roundTripped = Comm::CommunicationConfig::FromJson(json);
    EXPECT_EQ(roundTripped.portName, config.portName);
    EXPECT_EQ(roundTripped.replyTimeoutMs, config.replyTimeoutMs);
    EXPECT_EQ(roundTripped.reconnectIntervalMs, config.reconnectIntervalMs);
    EXPECT_EQ(roundTripped.maxReconnectAttempts, config.maxReconnectAttempts);
    EXPECT_EQ(roundTripped.messageQueueSize, config.messageQueueSize);
    EXPECT_EQ(roundTripped.workerThreadCount, config.workerThreadCount);
    EXPECT_EQ(roundTripped.autoReconnect, config.autoReconnect);
    EXPECT_EQ(roundTripped.blockOnTimeout, config.blockOnTimeout);
    EXPECT_EQ(roundTripped.enableStatistics, config.enableStatistics);
}

TEST(CommunicationProtocolTest, MovedFromFilterConnectionRemainsSafelyInert) {
    Comm::FilterConnection source(L"\\ShadowStrikeUnitTestPort");
    Comm::FilterConnection moved(std::move(source));

    EXPECT_FALSE(source.Connect());
    EXPECT_FALSE(source.IsConnected());
    EXPECT_EQ(source.ToJson(), "{}");

    Comm::FilterConnection assigned(L"\\ShadowStrikeUnitTestPort2");
    assigned = std::move(moved);
    EXPECT_FALSE(moved.Connect());
    EXPECT_FALSE(moved.IsConnected());
    EXPECT_EQ(moved.ToJson(), "{}");
    EXPECT_FALSE(assigned.IsConnected());
}

TEST(CommunicationProtocolTest, DispatchMessageRejectsEmptyAndTruncatedBuffersBeforeRouting) {
    Comm::FilterConnection connection(L"\\ShadowStrikeDispatchTestPort");
    Comm::MessageDispatcher dispatcher(connection);

    EXPECT_FALSE(dispatcher.DispatchMessage({}));
    EXPECT_EQ(dispatcher.GetStatistics().TakeSnapshot().parseErrors, 1u);

    std::vector<uint8_t> truncated = BuildMessageBuffer(Comm::MessageType::Heartbeat);
    auto* header = reinterpret_cast<Comm::MessageHeader*>(truncated.data());
    header->totalSize += 4;

    EXPECT_FALSE(dispatcher.DispatchMessage(truncated));

    const Comm::DispatchStatisticsSnapshot snapshot = dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(snapshot.messagesDispatched, 0u);
    EXPECT_EQ(snapshot.parseErrors, 2u);
}

TEST(CommunicationProtocolTest, DispatchMessageTracksUnknownAndNotificationOnlyMessageTypes) {
    Comm::FilterConnection connection(L"\\ShadowStrikeDispatchTestPort");
    Comm::MessageDispatcher dispatcher(connection);

    std::vector<uint8_t> unknown = BuildMessageBuffer(Comm::MessageType::None);
    reinterpret_cast<Comm::MessageHeader*>(unknown.data())->messageType = 0xFFFF;
    EXPECT_FALSE(dispatcher.DispatchMessage(unknown));

    const std::vector<uint8_t> alert = BuildMessageBuffer(Comm::MessageType::BehavioralAlert);
    EXPECT_TRUE(dispatcher.DispatchMessage(alert));

    const Comm::DispatchStatisticsSnapshot snapshot = dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(snapshot.messagesDispatched, 2u);
    EXPECT_EQ(snapshot.unknownMessages, 1u);
    EXPECT_EQ(snapshot.fileNotifications, 1u);
    EXPECT_EQ(snapshot.parseErrors, 0u);
}

TEST(CommunicationProtocolTest, DispatchHeartbeatOnDisconnectedConnectionRecordsReplyFailure) {
    Comm::FilterConnection connection(L"\\ShadowStrikeDispatchTestPort");
    Comm::MessageDispatcher dispatcher(connection);

    const std::vector<uint8_t> heartbeat = BuildMessageBuffer(Comm::MessageType::Heartbeat, {}, 0x99ULL);
    EXPECT_TRUE(dispatcher.DispatchMessage(heartbeat));

    const Comm::DispatchStatisticsSnapshot snapshot = dispatcher.GetStatistics().TakeSnapshot();
    EXPECT_EQ(snapshot.messagesDispatched, 1u);
    EXPECT_EQ(snapshot.repliesSent, 0u);
    EXPECT_EQ(snapshot.replyErrors, 1u);
    EXPECT_EQ(snapshot.parseErrors, 0u);
}

TEST(CommunicationProtocolTest, CommunicationStatisticsResetProducesCleanSnapshotAndJson) {
    Comm::CommunicationStatistics stats{};
    stats.Reset();
    stats.messagesReceived.store(12, std::memory_order_relaxed);
    stats.messagesSent.store(7, std::memory_order_relaxed);
    stats.fileScanRequests.store(3, std::memory_order_relaxed);
    stats.processNotifications.store(2, std::memory_order_relaxed);
    stats.registryNotifications.store(1, std::memory_order_relaxed);
    stats.repliesSent.store(5, std::memory_order_relaxed);
    stats.timeouts.store(1, std::memory_order_relaxed);
    stats.errors.store(2, std::memory_order_relaxed);
    stats.reconnections.store(4, std::memory_order_relaxed);
    stats.bytesReceived.store(2048, std::memory_order_relaxed);
    stats.bytesSent.store(1024, std::memory_order_relaxed);

    Comm::CommunicationStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.messagesReceived, 12u);
    EXPECT_EQ(snapshot.messagesSent, 7u);
    EXPECT_EQ(snapshot.bytesReceived, 2048u);
    EXPECT_GE(snapshot.uptimeSeconds, 0);
    EXPECT_NE(snapshot.ToJson().find("\"bytesSent\":1024"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.messagesReceived, 0u);
    EXPECT_EQ(snapshot.messagesSent, 0u);
    EXPECT_EQ(snapshot.errors, 0u);
}

TEST(CommunicationProtocolTest, DispatchStatisticsSnapshotComputesAverageAndResetClearsCounters) {
    Comm::MessageDispatcher::DispatchStatistics stats{};
    stats.messagesDispatched.store(4, std::memory_order_relaxed);
    stats.fileScanRequests.store(2, std::memory_order_relaxed);
    stats.processScanRequests.store(1, std::memory_order_relaxed);
    stats.registryScanRequests.store(1, std::memory_order_relaxed);
    stats.fileNotifications.store(3, std::memory_order_relaxed);
    stats.processNotifications.store(5, std::memory_order_relaxed);
    stats.registryNotifications.store(6, std::memory_order_relaxed);
    stats.unknownMessages.store(7, std::memory_order_relaxed);
    stats.parseErrors.store(8, std::memory_order_relaxed);
    stats.handlerErrors.store(9, std::memory_order_relaxed);
    stats.repliesSent.store(10, std::memory_order_relaxed);
    stats.replyErrors.store(11, std::memory_order_relaxed);
    stats.totalProcessingTimeUs.store(200, std::memory_order_relaxed);

    const Comm::DispatchStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.messagesDispatched, 4u);
    EXPECT_DOUBLE_EQ(snapshot.avgProcessingTimeUs, 50.0);
    EXPECT_NE(snapshot.ToJson().find("\"avgProcessingTimeUs\":50"), std::string::npos);

    stats.Reset();
    const Comm::DispatchStatisticsSnapshot cleared = stats.TakeSnapshot();
    EXPECT_EQ(cleared.messagesDispatched, 0u);
    EXPECT_EQ(cleared.replyErrors, 0u);
    EXPECT_DOUBLE_EQ(cleared.avgProcessingTimeUs, 0.0);
}
