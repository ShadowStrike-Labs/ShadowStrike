/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Network\TrafficAnalyzer deterministic contracts.
 *
 * Focus:
 *   - configuration/statistics contracts and protocol-name stability
 *   - protocol identification and payload analysis without live capture
 *   - JA3, callback, stream, and diagnostics behavior that remains in-process
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/Core/Network/TrafficAnalyzer.hpp"
#include "CoreNetwork_TestUtils.hpp"

namespace ShadowStrike::Core::Network::Test {

namespace {

std::vector<uint8_t> Bytes(std::string_view text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> ByteRamp() {
    std::vector<uint8_t> bytes(256);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(i);
    }
    return bytes;
}

}  // namespace

class TrafficAnalyzerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_TrafficAnalyzerTests_"};
    TrafficAnalyzer& analyzer = TrafficAnalyzer::Instance();

    void SetUp() override {
        analyzer.Shutdown();
        ASSERT_TRUE(analyzer.Initialize(TrafficAnalyzerConfig::CreateDefault()));
        analyzer.ResetStatistics();
        analyzer.ClearAllStreams();
    }

    void TearDown() override {
        analyzer.Shutdown();
    }
};

TEST_F(TrafficAnalyzerTest, ConfigFactoriesAndStatisticsResetReflectExpectedProfiles) {
    const auto defaults = TrafficAnalyzerConfig::CreateDefault();
    const auto highSecurity = TrafficAnalyzerConfig::CreateHighSecurity();
    const auto performance = TrafficAnalyzerConfig::CreatePerformance();
    const auto forensic = TrafficAnalyzerConfig::CreateForensic();

    EXPECT_TRUE(defaults.enableProtocolDetection);
    EXPECT_TRUE(defaults.enableTLSInspection);
    EXPECT_TRUE(defaults.enableSignatureScanning);

    EXPECT_TRUE(highSecurity.logThreatsOnly);
    EXPECT_TRUE(highSecurity.logTLSInfo);
    EXPECT_TRUE(highSecurity.enableShellcodeDetection);

    EXPECT_FALSE(performance.enableTLSInspection);
    EXPECT_FALSE(performance.enableAnomalyDetection);
    EXPECT_FALSE(performance.enableSignatureScanning);
    EXPECT_EQ(performance.workerThreads, 8u);

    EXPECT_TRUE(forensic.logAllStreams);
    EXPECT_FALSE(forensic.logThreatsOnly);
    EXPECT_EQ(forensic.streamTimeoutMs, 600000u);

    TrafficAnalyzerStatistics stats;
    stats.totalPackets.store(7, std::memory_order_relaxed);
    stats.activeStreams.store(2, std::memory_order_relaxed);
    stats.threatsDetected.store(3, std::memory_order_relaxed);
    stats.maliciousJA3.store(1, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.totalPackets.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.activeStreams.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threatsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.maliciousJA3.load(std::memory_order_relaxed), 0u);
}

TEST_F(TrafficAnalyzerTest, ProtocolIdentificationAndNameHelpersRemainStable) {
    const auto httpPayload = Bytes("GET / HTTP/1.1\r\nHost: example\r\n\r\n");
    const auto sshPayload = Bytes("SSH-2.0-OpenSSH_8.9\r\n");
    const auto tlsPayload = std::vector<uint8_t>{
        0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00,
        0x0C, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    EXPECT_EQ(analyzer.IdentifyProtocol(httpPayload, 80, 53123), Protocol::HTTP);
    EXPECT_EQ(analyzer.IdentifyProtocol(httpPayload, 4444, 5555), Protocol::HTTP);
    EXPECT_EQ(analyzer.IdentifyProtocol(httpPayload, 443, 51515), Protocol::HTTP);
    EXPECT_EQ(analyzer.IdentifyProtocol(sshPayload, 22, 51515), Protocol::SSH);
    EXPECT_EQ(analyzer.IdentifyProtocol(tlsPayload, 443, 51515), Protocol::HTTPS);
    EXPECT_EQ(analyzer.IdentifyProtocol(tlsPayload, 636, 51515), Protocol::LDAPS);
    EXPECT_EQ(analyzer.IdentifyProtocol(tlsPayload, 9999, 51515), Protocol::TLS_UNKNOWN);
    EXPECT_EQ(analyzer.IdentifyProtocol({}, 80, 80), Protocol::UNKNOWN);

    EXPECT_EQ(TrafficAnalyzer::GetProtocolName(Protocol::HTTP), "HTTP");
    EXPECT_EQ(TrafficAnalyzer::GetProtocolName(Protocol::TLS_UNKNOWN), "TLS (Unknown App)");
    EXPECT_EQ(TrafficAnalyzer::GetProtocolName(static_cast<Protocol>(65535)), "Unknown");
}

TEST_F(TrafficAnalyzerTest, PayloadAnalysisDifferentiatesTextBase64AndHighEntropyContent) {
    const auto textPayload = Bytes("Hello ShadowStrike\n");
    const auto base64Payload = Bytes("QUJDREVGRw==");
    const auto entropyPayload = ByteRamp();
    const auto binaryPayload = std::vector<uint8_t>{0x4D, 0x01, 0x5A, 0x02, 0x03};

    const PayloadAnalysis empty = analyzer.AnalyzePayload({});
    EXPECT_EQ(empty.type, PayloadType::UNKNOWN);
    EXPECT_EQ(empty.size, 0u);

    const PayloadAnalysis text = analyzer.AnalyzePayload(textPayload);
    EXPECT_EQ(text.type, PayloadType::TEXT);
    EXPECT_EQ(text.size, textPayload.size());
    EXPECT_FALSE(text.isBase64);

    const PayloadAnalysis base64 = analyzer.AnalyzePayload(base64Payload);
    EXPECT_EQ(base64.type, PayloadType::ENCODED_BASE64);
    EXPECT_TRUE(base64.isBase64);

    const PayloadAnalysis highEntropy = analyzer.AnalyzePayload(entropyPayload);
    EXPECT_EQ(highEntropy.type, PayloadType::ENCRYPTED);
    EXPECT_TRUE(highEntropy.isHighEntropy);
    EXPECT_GT(highEntropy.entropy, 7.5);

    const PayloadAnalysis binary = analyzer.AnalyzePayload(binaryPayload);
    EXPECT_EQ(binary.type, PayloadType::BINARY);
}

TEST_F(TrafficAnalyzerTest, ShellcodeFileTypeAndJa3HelpersReturnDeterministicSignals) {
    const auto benignPayload = Bytes("regular-text-payload");
    const auto shortPayload = std::vector<uint8_t>{0x4D, 0x5A, 0x90};
    const auto shortHello = std::vector<uint8_t>{0x16, 0x03, 0x03};
    const auto tooShortForShellcode = std::vector<uint8_t>(
        TrafficAnalyzerConstants::SHELLCODE_MIN_SIZE - 1, 0x90);

    const auto [isShellcode, score] = analyzer.DetectShellcode(benignPayload);
    EXPECT_FALSE(isShellcode);
    EXPECT_GE(score, 0.0);

    const auto [shortShellcode, shortScore] = analyzer.DetectShellcode(tooShortForShellcode);
    EXPECT_FALSE(shortShellcode);
    EXPECT_DOUBLE_EQ(shortScore, 0.0);

    EXPECT_EQ(analyzer.DetectFileType(shortPayload), "application/octet-stream");
    EXPECT_TRUE(analyzer.IsJA3Malicious("72a589da586844d7f0818ce684948eea"));
    EXPECT_FALSE(analyzer.IsJA3Malicious("00000000000000000000000000000000"));

    const auto ja3 = analyzer.CalculateJA3(shortHello);
    EXPECT_TRUE(ja3.hash.empty());
    EXPECT_TRUE(ja3.rawString.empty());
    EXPECT_EQ(ja3.version, TrafficAnalyzerTLSVersion::UNKNOWN);
}

TEST_F(TrafficAnalyzerTest, CallbackStreamAndDiagnosticsContractsRemainHealthy) {
    const uint64_t packetCallbackId = analyzer.RegisterPacketCallback([](const AnalysisResult&) {});
    const uint64_t streamCallbackId = analyzer.RegisterStreamCallback([](const StreamInfo&, bool) {});
    const uint64_t protocolCallbackId = analyzer.RegisterProtocolCallback(
        [](uint64_t, Protocol, const StreamInfo&) {});
    const uint64_t threatCallbackId = analyzer.RegisterThreatCallback(
        [](uint64_t, TrafficThreatIndicator, const AnalysisResult&) {});
    const uint64_t tlsCallbackId = analyzer.RegisterTLSCallback(
        [](uint64_t, const TrafficAnalyzerTLSInfo&) {});

    EXPECT_TRUE(packetCallbackId < streamCallbackId);
    EXPECT_TRUE(streamCallbackId < protocolCallbackId);
    EXPECT_TRUE(protocolCallbackId < threatCallbackId);
    EXPECT_TRUE(threatCallbackId < tlsCallbackId);
    EXPECT_TRUE(analyzer.UnregisterCallback(protocolCallbackId));
    EXPECT_FALSE(analyzer.UnregisterCallback(protocolCallbackId));

    EXPECT_TRUE(analyzer.GetActiveStreams().empty());
    EXPECT_FALSE(analyzer.GetStream(1).has_value());
    analyzer.ClearAllStreams();
    EXPECT_TRUE(analyzer.GetActiveStreams().empty());

    EXPECT_TRUE(analyzer.PerformDiagnostics());
    EXPECT_FALSE(analyzer.ExportDiagnostics(L""));

    const auto diagnosticsPath = tempDir.File(L"traffic-diagnostics.txt");
    ASSERT_TRUE(analyzer.ExportDiagnostics(diagnosticsPath.wstring()));
    const std::string report = ReadTextFile(diagnosticsPath);
    EXPECT_NE(report.find("TrafficAnalyzer Diagnostics"), std::string::npos);
    EXPECT_NE(report.find("Packet Statistics"), std::string::npos);
}

}  // namespace ShadowStrike::Core::Network::Test
