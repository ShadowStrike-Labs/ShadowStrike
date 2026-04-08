/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic PowerShellScanner contracts.
 *
 * Focus:
 *   - blocking and statistics JSON semantics
 *   - configuration and singleton health behavior
 *   - public memory/command-line heuristics with no live dependencies
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Scripts/PowerShellScanner.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;

std::string EncodePowerShellCommand(std::string_view command) {
    std::string utf16le;
    utf16le.reserve(command.size() * 2);
    for (unsigned char ch : command) {
        utf16le.push_back(static_cast<char>(ch));
        utf16le.push_back('\0');
    }

    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    encoded.reserve(((utf16le.size() + 2) / 3) * 4);

    for (size_t index = 0; index < utf16le.size(); index += 3) {
        const uint32_t b0 = static_cast<unsigned char>(utf16le[index]);
        const uint32_t b1 =
            (index + 1 < utf16le.size()) ? static_cast<unsigned char>(utf16le[index + 1]) : 0u;
        const uint32_t b2 =
            (index + 2 < utf16le.size()) ? static_cast<unsigned char>(utf16le[index + 2]) : 0u;
        const uint32_t triplet = (b0 << 16) | (b1 << 8) | b2;

        encoded.push_back(kAlphabet[(triplet >> 18) & 0x3F]);
        encoded.push_back(kAlphabet[(triplet >> 12) & 0x3F]);
        encoded.push_back((index + 1 < utf16le.size()) ? kAlphabet[(triplet >> 6) & 0x3F] : '=');
        encoded.push_back((index + 2 < utf16le.size()) ? kAlphabet[triplet & 0x3F] : '=');
    }

    return encoded;
}

}  // namespace

TEST(PowerShellScannerTest, ScanResultBlockingAndStatisticsSerializationRemainStable) {
    ScanResult benign;
    benign.status = ScanStatus::SUSPICIOUS;
    benign.riskScore = Constants::Heuristics::THRESHOLD_SUSPICIOUS;
    EXPECT_FALSE(benign.isBlocking());

    ScanResult blocking;
    blocking.status = ScanStatus::SUSPICIOUS;
    blocking.riskScore = Constants::Heuristics::THRESHOLD_BLOCK;
    EXPECT_TRUE(blocking.isBlocking());

    blocking.status = ScanStatus::MALICIOUS;
    EXPECT_TRUE(blocking.isBlocking());

    PSStatisticsSnapshot snapshot;
    snapshot.totalScans = 5;
    snapshot.maliciousDetected = 2;
    snapshot.amsiBypassesBlocked = 1;
    snapshot.averageScanTimeUs = 333;
    snapshot.cacheHits = 4;
    snapshot.cacheMisses = 6;

    const json statsJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(statsJson.at("totalScans"), 5);
    EXPECT_EQ(statsJson.at("maliciousDetected"), 2);
    EXPECT_EQ(statsJson.at("cacheMisses"), 6);
}

TEST(PowerShellScannerTest, ConfigUpdatesPersistAndHealthCheckStaysHealthy) {
    auto& scanner = PowerShellScanner::getInstance();
    scanner.resetStats();

    PowerShellScanConfig config = scanner.getConfig();
    config.blockObfuscatedScripts = true;
    config.maxDeobfuscationDepth = 3;
    config.blacklistedCmdlets.push_back("Invoke-Test");
    scanner.updateConfig(config);

    const auto updated = scanner.getConfig();
    EXPECT_TRUE(updated.blockObfuscatedScripts);
    EXPECT_EQ(updated.maxDeobfuscationDepth, 3u);
    EXPECT_NE(std::find(updated.blacklistedCmdlets.begin(),
                        updated.blacklistedCmdlets.end(),
                        "Invoke-Test"),
              updated.blacklistedCmdlets.end());

    EXPECT_TRUE(scanner.healthCheck());
}

TEST(PowerShellScannerTest, EmptyMemoryAndNonPowerShellCommandLineFailClosed) {
    auto& scanner = PowerShellScanner::getInstance();
    scanner.resetStats();

    const std::string empty;
    const auto emptyResult = scanner.scanMemory(
        std::span<const char>(empty.data(), empty.size()),
        "empty",
        42);
    EXPECT_EQ(emptyResult.status, ScanStatus::CLEAN);
    EXPECT_EQ(emptyResult.mode, ExecutionMode::MEMORY_ONLY);

    const auto nonPowerShell = scanner.scanCommandLine("cmd.exe /c whoami", 42);
    EXPECT_EQ(nonPowerShell.status, ScanStatus::CLEAN);
    EXPECT_EQ(nonPowerShell.description, "Not a PowerShell command");
    EXPECT_EQ(nonPowerShell.mode, ExecutionMode::ENCODED_COMMAND_LINE);
}

TEST(PowerShellScannerTest, SuspiciousCommandLinesAndKnownMaliciousMemoryAreFlagged) {
    auto& scanner = PowerShellScanner::getInstance();
    scanner.resetStats();

    const auto downgrade = scanner.scanCommandLine(
        "powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass",
        99);
    EXPECT_TRUE(downgrade.isBlocking());
    EXPECT_EQ(downgrade.category, ThreatCategory::V2_DOWNGRADE);
    EXPECT_GE(downgrade.riskScore, Constants::Heuristics::THRESHOLD_BLOCK);

    const std::string payload = "Invoke-Mimikatz -DumpCreds";
    const auto memoryResult = scanner.scanMemory(
        std::span<const char>(payload.data(), payload.size()),
        "memory",
        1337);
    EXPECT_TRUE(memoryResult.isBlocking());
    EXPECT_EQ(memoryResult.status, ScanStatus::MALICIOUS);
    EXPECT_FALSE(memoryResult.sha256.empty());

    const auto stats = scanner.getStats();
    EXPECT_GE(stats.totalScans, 2u);
    EXPECT_GE(stats.maliciousDetected, 1u);
}

TEST(PowerShellScannerTest, SizeLimitsAndQuotedEncodedCommandsRemainDeterministic) {
    auto& scanner = PowerShellScanner::getInstance();
    scanner.resetStats();

    const PowerShellScanConfig originalConfig = scanner.getConfig();

    const std::string benignPayload = "Write-Host 'ok'";
    PowerShellScanConfig sizedConfig = originalConfig;
    sizedConfig.maxScriptSize = static_cast<uint32_t>(benignPayload.size());
    scanner.updateConfig(sizedConfig);

    const auto exactLimit = scanner.scanMemory(
        std::span<const char>(benignPayload.data(), benignPayload.size()),
        "exact-limit",
        7);
    EXPECT_NE(exactLimit.status, ScanStatus::SKIPPED_SIZE_LIMIT);

    sizedConfig.maxScriptSize = static_cast<uint32_t>(benignPayload.size() - 1);
    scanner.updateConfig(sizedConfig);

    const auto overLimit = scanner.scanMemory(
        std::span<const char>(benignPayload.data(), benignPayload.size()),
        "over-limit",
        8);
    EXPECT_EQ(overLimit.status, ScanStatus::SKIPPED_SIZE_LIMIT);
    EXPECT_EQ(overLimit.description, "Content exceeds size limit");

    scanner.updateConfig(originalConfig);

    const std::string encodedPayload = EncodePowerShellCommand("Invoke-Mimikatz -DumpCreds");
    const auto unquoted = scanner.scanCommandLine("powershell.exe -enc " + encodedPayload, 100);
    const auto quoted =
        scanner.scanCommandLine("powershell.exe -enc \"" + encodedPayload + "\"", 101);

    EXPECT_TRUE(unquoted.isBlocking());
    EXPECT_TRUE(quoted.isBlocking());
    EXPECT_EQ(quoted.status, unquoted.status);
    EXPECT_EQ(quoted.category, unquoted.category);
}

}  // namespace ShadowStrike::Scripts::Test
