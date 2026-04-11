#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Communication/IPCManager.hpp"

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace IPC = ShadowStrike::Communication;

namespace {

template <typename T>
std::vector<uint8_t> BufferWithPod(const T& value, size_t extraBytes = 0) {
    std::vector<uint8_t> buffer(sizeof(T) + extraBytes);
    std::memcpy(buffer.data(), &value, sizeof(T));
    return buffer;
}

void CopyBytes(std::vector<uint8_t>& buffer, size_t offset, const void* data, size_t size) {
    std::memcpy(buffer.data() + offset, data, size);
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike IPC Manager - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Validation logic for deterministic configuration/state surfaces
 * - Snapshot and JSON reporting helpers consumed by diagnostics
 * - Packed wire-structure accessors that read variable-length payloads
 *
 * ============================================================================
 */

TEST(IPCManagerTest, IPCConfigurationEnforcesProductionSafetyBounds) {
    IPC::IPCConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.workerThreadCount = 64;
    config.maxQueueDepth = 1'000'000;
    config.replyTimeoutMs = 300'000;
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.filterPortName.clear();
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.workerThreadCount = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.workerThreadCount = 65;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxQueueDepth = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxQueueDepth = 1'000'001;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.replyTimeoutMs = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.replyTimeoutMs = 300'001;
    EXPECT_FALSE(config.IsValid());
}

TEST(IPCManagerTest, IPCStatisticsResetAndSnapshotRemainConsistent) {
    IPC::IPCStatistics stats{};
    stats.messagesReceived.store(100, std::memory_order_relaxed);
    stats.messagesSent.store(90, std::memory_order_relaxed);
    stats.messagesDropped.store(7, std::memory_order_relaxed);
    stats.bytesReceived.store(2048, std::memory_order_relaxed);
    stats.bytesSent.store(1024, std::memory_order_relaxed);
    stats.timeouts.store(3, std::memory_order_relaxed);
    stats.errors.store(2, std::memory_order_relaxed);
    stats.reconnects.store(4, std::memory_order_relaxed);
    stats.avgLatencyUs.store(55, std::memory_order_relaxed);
    stats.maxLatencyUs.store(120, std::memory_order_relaxed);
    stats.byMessageType[3].store(11, std::memory_order_relaxed);
    stats.byVerdict[2].store(5, std::memory_order_relaxed);

    IPC::IPCStatisticsSnapshot snapshot = IPC::TakeSnapshot(stats);
    EXPECT_EQ(snapshot.messagesReceived, 100u);
    EXPECT_EQ(snapshot.messagesDropped, 7u);
    EXPECT_EQ(snapshot.byMessageType[3], 11u);
    EXPECT_EQ(snapshot.byVerdict[2], 5u);
    EXPECT_NE(snapshot.ToJson().find("\"avgLatencyUs\":55"), std::string::npos);

    stats.Reset();
    snapshot = IPC::TakeSnapshot(stats);
    EXPECT_EQ(snapshot.messagesReceived, 0u);
    EXPECT_EQ(snapshot.messagesSent, 0u);
    EXPECT_EQ(snapshot.byMessageType[3], 0u);
    EXPECT_EQ(snapshot.byVerdict[2], 0u);
}

TEST(IPCManagerTest, ConnectionInfoToJsonIncludesConnectionMetadata) {
    IPC::ConnectionInfo info{};
    info.channelType = IPC::ChannelType::FilterPort;
    info.status = IPC::ConnectionStatus::Ready;
    info.endpoint = LR"(\\.\ShadowStrike\Control)";
    info.messagesReceived = 321;
    info.messagesSent = 123;
    info.bytesReceived = 4096;
    info.bytesSent = 1024;
    info.reconnectCount = 2;

    const std::string json = info.ToJson();
    EXPECT_NE(json.find("\"channelType\":\"FilterPort\""), std::string::npos);
    EXPECT_NE(json.find("\"status\":\"Ready\""), std::string::npos);
    EXPECT_NE(json.find("\"messagesReceived\":321"), std::string::npos);
    EXPECT_NE(json.find("\"reconnectCount\":2"), std::string::npos);
}

TEST(IPCManagerTest, ProcessNotifyRequestAccessorsHonorEmbeddedLengths) {
    const std::wstring imagePath = LR"(C:\Windows\System32\svchost.exe)";
    const std::wstring commandLine = LR"(svchost.exe -k netsvcs)";

    IPC::ProcessNotifyRequest request{};
    request.processId = 111;
    request.parentProcessId = 10;
    request.creatingProcessId = 20;
    request.creatingThreadId = 30;
    request.isCreation = 1;
    request.imagePathLength = static_cast<uint16_t>(imagePath.size() * sizeof(wchar_t));
    request.commandLineLength = static_cast<uint16_t>(commandLine.size() * sizeof(wchar_t));

    std::vector<uint8_t> buffer = BufferWithPod(
        request,
        request.imagePathLength + request.commandLineLength);

    CopyBytes(buffer, sizeof(IPC::ProcessNotifyRequest), imagePath.data(), request.imagePathLength);
    CopyBytes(buffer,
              sizeof(IPC::ProcessNotifyRequest) + request.imagePathLength,
              commandLine.data(),
              request.commandLineLength);

    const auto* parsed = reinterpret_cast<const IPC::ProcessNotifyRequest*>(buffer.data());
    EXPECT_EQ(parsed->imagePathCharLen(), imagePath.size());
    EXPECT_EQ(parsed->commandLineCharLen(), commandLine.size());
    EXPECT_EQ(std::wstring(parsed->imagePathData(), parsed->imagePathCharLen()), imagePath);
    EXPECT_EQ(std::wstring(parsed->commandLineData(), parsed->commandLineCharLen()), commandLine);
}

TEST(IPCManagerTest, ImageLoadRequestAccessorsExposeVariablePathPayload) {
    const std::wstring imagePath = LR"(C:\Program Files\ShadowStrike\agent.dll)";

    IPC::ImageLoadRequest request{};
    request.processId = 501;
    request.imageBase = 0x140000000ULL;
    request.imageSize = 0x2000ULL;
    request.signatureLevel = 8;
    request.signatureType = 2;
    request.isSystemModule = 0;
    request.imagePathLength = static_cast<uint16_t>(imagePath.size() * sizeof(wchar_t));

    std::vector<uint8_t> buffer = BufferWithPod(request, request.imagePathLength);
    CopyBytes(buffer, sizeof(IPC::ImageLoadRequest), imagePath.data(), request.imagePathLength);

    const auto* parsed = reinterpret_cast<const IPC::ImageLoadRequest*>(buffer.data());
    EXPECT_EQ(parsed->imagePathCharLen(), imagePath.size());
    EXPECT_EQ(std::wstring(parsed->imagePathData(), parsed->imagePathCharLen()), imagePath);
}

TEST(IPCManagerTest, RegistryOpRequestAccessorsPreserveKeyValueAndBinaryData) {
    const std::wstring keyPath = LR"(HKLM\Software\ShadowStrike)";
    const std::wstring valueName = LR"(Enabled)";
    const std::vector<uint8_t> data{0xDE, 0xAD, 0xBE, 0xEF};

    IPC::RegistryOpRequest request{};
    request.processId = 901;
    request.threadId = 902;
    request.operation = 2;
    request.keyPathLength = static_cast<uint16_t>(keyPath.size() * sizeof(wchar_t));
    request.valueNameLength = static_cast<uint16_t>(valueName.size() * sizeof(wchar_t));
    request.dataSize = static_cast<uint32_t>(data.size());
    request.dataType = 4;

    std::vector<uint8_t> buffer = BufferWithPod(
        request,
        request.keyPathLength + request.valueNameLength + request.dataSize);

    size_t offset = sizeof(IPC::RegistryOpRequest);
    CopyBytes(buffer, offset, keyPath.data(), request.keyPathLength);
    offset += request.keyPathLength;
    CopyBytes(buffer, offset, valueName.data(), request.valueNameLength);
    offset += request.valueNameLength;
    CopyBytes(buffer, offset, data.data(), data.size());

    const auto* parsed = reinterpret_cast<const IPC::RegistryOpRequest*>(buffer.data());
    EXPECT_EQ(parsed->keyPathCharLen(), keyPath.size());
    EXPECT_EQ(parsed->valueNameCharLen(), valueName.size());
    EXPECT_EQ(std::wstring(parsed->keyPathData(), parsed->keyPathCharLen()), keyPath);
    EXPECT_EQ(std::wstring(parsed->valueNameData(), parsed->valueNameCharLen()), valueName);
    EXPECT_EQ(std::vector<uint8_t>(parsed->registryData(), parsed->registryData() + data.size()), data);
}
