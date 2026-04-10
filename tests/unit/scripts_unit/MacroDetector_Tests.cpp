/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic MacroDetector behavior.
 *
 * Focus:
 *   - helper names and VBA predicate contracts
 *   - DTO/config/statistics serialization
 *   - public format/VBA/IOC/deobfuscation helpers
 *   - lifecycle and self-test behavior that should remain stable
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Scripts/MacroDetector.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;
namespace fs = std::filesystem;

class MacroDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        MacroDetector::Instance().Shutdown();
    }

    void TearDown() override {
        MacroDetector::Instance().Shutdown();
    }
};

bool ContainsString(const std::vector<std::string>& values, std::string_view needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

fs::path WriteTempBinaryFile(std::string_view extension, std::span<const uint8_t> bytes) {
    static std::atomic_uint64_t counter{0};

    const fs::path path = fs::temp_directory_path() /
        ("shadowstrike_macro_test_" + std::to_string(++counter) + std::string(extension));

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    return path;
}

}  // namespace

TEST_F(MacroDetectorTest, HelperNamesAndPredicatesRemainStable) {
    EXPECT_EQ(GetMacroTypeName(MacroType::TemplateInjection), "Remote Template Injection");
    EXPECT_EQ(GetDocumentFormatName(DocumentFormat::DOCM), ".docm (Word Macro-Enabled)");
    EXPECT_EQ(GetVBAModuleTypeName(VBAModuleType::Workbook), "Workbook Module");
    EXPECT_EQ(GetMacroThreatCategoryName(MacroThreatCategory::InfoStealer),
              "Information Stealer");
    EXPECT_EQ(GetMacroObfuscationTypeName(MacroObfuscationType::VBAStomping), "VBA Stomping");

    EXPECT_TRUE(IsAutoExecFunction("document_open"));
    EXPECT_TRUE(IsAutoExecFunction("Workbook_Open"));
    EXPECT_FALSE(IsAutoExecFunction("RegularFunction"));

    EXPECT_TRUE(IsSuspiciousVBAAPI("CreateObject"));
    EXPECT_TRUE(IsSuspiciousVBAAPI("URLDownloadToFileA"));
    EXPECT_FALSE(IsSuspiciousVBAAPI("MsgBox"));

    const std::string version = MacroDetector::GetVersionString();
    EXPECT_FALSE(version.empty());
    EXPECT_EQ(std::count(version.begin(), version.end(), '.'), 2);
}

TEST_F(MacroDetectorTest, SerializationAndBlockingContractsRemainActionable) {
    VBAModuleInfo module;
    module.moduleName = "ThisDocument";
    module.type = VBAModuleType::Document;
    module.sourceSize = 128;
    module.lineCount = 6;
    module.hasAutoExec = true;
    module.autoExecFunctions = {"Document_Open"};
    module.suspiciousAPIs = {"CreateObject"};
    module.isObfuscated = true;
    module.obfuscationType = MacroObfuscationType::CharManipulation;
    module.containsShell = true;

    const json moduleJson = json::parse(module.ToJson());
    EXPECT_EQ(moduleJson.at("moduleName"), "ThisDocument");
    EXPECT_TRUE(moduleJson.at("hasAutoExec").get<bool>());
    EXPECT_EQ(moduleJson.at("obfuscationType"), "Character Manipulation");

    VBAProjectInfo project;
    project.projectName = "Project";
    project.moduleCount = 1;
    project.totalSourceSize = 128;
    project.modules = {module};
    project.references = {"VBA"};

    XLMMacroInfo xlm;
    xlm.sheetName = "Macro1";
    xlm.hasAutoOpen = true;
    xlm.execCalls = {"EXEC(\"cmd.exe\")"};

    TemplateInjectionInfo injection;
    injection.templateUrl = "https://evil.example/template.dotm";
    injection.xmlElement = "attachedTemplate";
    injection.relationshipType = "external";

    XLLInfo xll;
    xll.isPEFile = true;
    xll.hasXlAutoOpen = true;
    xll.exportNames = {"xlAutoOpen"};

    MacroScanResult result;
    result.status = MacroScanStatus::Suspicious;
    result.hasMacros = true;
    result.category = MacroThreatCategory::Downloader;
    result.riskScore = 81;
    result.format = DocumentFormat::DOCM;
    result.macroTypes = {MacroType::VBAModern};
    result.vbaProject = project;
    result.xlmMacros = {xlm};
    result.templateInjections = {injection};
    result.xllInfo = xll;
    result.triggerFunctions = {"Document_Open"};
    result.suspiciousAPIs = {"CreateObject"};
    result.extractedIOCs = {"https://evil.example/payload.exe"};

    EXPECT_TRUE(result.ShouldBlock());

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("hasMacros").get<bool>());
    EXPECT_EQ(resultJson.at("category"), "Downloader");
    EXPECT_EQ(resultJson.at("format"), ".docm (Word Macro-Enabled)");
    EXPECT_EQ(resultJson.at("macroTypes")[0], "VBA Modern (OpenXML)");
    EXPECT_EQ(resultJson.at("vbaProject").at("modules").size(), 1u);
    EXPECT_EQ(resultJson.at("templateInjections").size(), 1u);
    EXPECT_EQ(resultJson.at("xllInfo").at("exportNames")[0], "xlAutoOpen");
}

TEST_F(MacroDetectorTest, AnalysisHelpersDetectFormatsRiskyVbaAndIocs) {
    auto& detector = MacroDetector::Instance();
    ASSERT_TRUE(detector.Initialize());

    const std::array<uint8_t, 8> oleHeader = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    const std::array<uint8_t, 4> zipHeader = {0x50, 0x4B, 0x03, 0x04};
    const std::array<uint8_t, 5> rtfHeader = {'{', '\\', 'r', 't', 'f'};

    EXPECT_EQ(detector.DetectFormat(std::span<const uint8_t>(oleHeader)), DocumentFormat::DOC);
    EXPECT_EQ(detector.DetectFormat(std::span<const uint8_t>(zipHeader)), DocumentFormat::DOCX);
    EXPECT_EQ(detector.DetectFormat(std::span<const uint8_t>(rtfHeader)), DocumentFormat::RTF);

    const std::string vbaCode =
        "Sub AutoOpen()\n"
        "  Shell \"powershell.exe -nop -w hidden\"\n"
        "  CreateObject(\"WScript.Shell\").Run \"cmd.exe /c calc.exe\"\n"
        "  x = \"http://evil.example/payload.exe\"\n"
        "End Sub\n";

    const auto analysis = detector.AnalyzeVBA(vbaCode);
    EXPECT_TRUE(analysis.hasMacros);
    EXPECT_TRUE(ContainsString(analysis.triggerFunctions, "AutoOpen"));
    EXPECT_TRUE(ContainsString(analysis.suspiciousAPIs, "CreateObject"));
    EXPECT_TRUE(ContainsString(analysis.extractedIOCs, "http://evil.example/payload.exe"));
    EXPECT_GE(analysis.riskScore, 50);

    const auto iocs = detector.ExtractIOCs(
        "url = \"https://evil.example/dropper.exe\"\n"
        "ip = \"10.20.30.40\"\n"
        "bad = \"999.20.30.40\"\n"
        "path = \"C:\\temp\\payload.exe\"\n"
        "reg = \"HKCU\\Software\\Run\"\n");
    EXPECT_EQ(iocs.size(), 4u);
    EXPECT_FALSE(ContainsString(iocs, "999.20.30.40"));

    EXPECT_EQ(detector.Deobfuscate("Chr(72)"), "H");

    const auto deobfuscated = detector.Deobfuscate("\"Hel\" & \"lo\"");
    EXPECT_NE(deobfuscated.find("\"Hello\""), std::string::npos);
}

TEST_F(MacroDetectorTest, ConfigurationStatisticsAndSelfTestStayPredictable) {
    MacroDetectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxDocumentSize = 0;
    EXPECT_FALSE(config.IsValid());

    auto& detector = MacroDetector::Instance();
    MacroDetectorConfiguration invalid;
    invalid.maxDocumentSize = 0;
    EXPECT_FALSE(detector.Initialize(invalid));

    ASSERT_TRUE(detector.Initialize());
    const auto baselineConfig = detector.GetConfiguration();
    EXPECT_FALSE(detector.UpdateConfiguration(invalid));
    EXPECT_EQ(detector.GetConfiguration().maxDocumentSize, baselineConfig.maxDocumentSize);
    EXPECT_TRUE(detector.SelfTest());

    const std::array<uint8_t, 4> zipHeader = {0x50, 0x4B, 0x03, 0x04};
    const std::array<uint8_t, 4> mzHeader = {'M', 'Z', 0x00, 0x00};
    const std::array<uint8_t, 3> shortHeader = {0x01, 0x02, 0x03};

    const auto docmPath = WriteTempBinaryFile(".docm", std::span<const uint8_t>(zipHeader));
    const auto xllPath = WriteTempBinaryFile(".xll", std::span<const uint8_t>(mzHeader));
    const auto shortPath = WriteTempBinaryFile(".bin", std::span<const uint8_t>(shortHeader));

    EXPECT_EQ(detector.DetectFormat(docmPath), DocumentFormat::DOCM);
    EXPECT_EQ(detector.DetectFormat(xllPath), DocumentFormat::XLL);
    EXPECT_EQ(detector.DetectFormat(shortPath), DocumentFormat::Unknown);

    fs::remove(docmPath);
    fs::remove(xllPath);
    fs::remove(shortPath);

    detector.ResetStatistics();
    const auto stats = detector.GetStatistics();
    EXPECT_EQ(stats.totalScans, 0u);
    EXPECT_EQ(stats.parseErrors, 0u);

    MacroStatisticsSnapshot snapshot;
    snapshot.totalScans = 5;
    snapshot.documentsWithMacros = 3;
    snapshot.passwordProtected = 1;
    snapshot.startTime = Clock::now() - std::chrono::milliseconds(10);

    const json statsJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(statsJson.at("documentsWithMacros"), 3);
    EXPECT_GE(statsJson.at("uptimeMs").get<int64_t>(), 0);
}

}  // namespace ShadowStrike::Scripts::Test
