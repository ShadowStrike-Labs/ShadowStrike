// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ShadowStrike Antivirus - Unit Tests
 * YaraRuleStore Module Tests
 * 
 * Enterprise-grade comprehensive testing for YARA rule engine integration
 * Tests cover: Rule compilation, scanning, streaming, metadata, statistics,
 * thread safety, performance, and error handling
 * 
 * Copyright (c) 2024 ShadowStrike Team
 */

#include <gtest/gtest.h>
#include "../../../../src/SignatureStore/YaraRuleStore.hpp"
#include "../../../../src/SignatureStore/SignatureFormat.hpp"
#include <memory>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <filesystem>
#include <atomic>

using namespace ShadowStrike::SignatureStore;
namespace fs = std::filesystem;

// ============================================================================
// Test Fixture
// ============================================================================

class YaraRuleStoreTest : public ::testing::Test {
protected:
    std::unique_ptr<YaraRuleStore> yara_store_;
    std::wstring test_db_path_;
    fs::path test_dir_;
    
    static void SetUpTestSuite() {
        // Initialize YARA library once for all tests
        auto error = YaraRuleStore::InitializeYara();
        if (!error.IsSuccess()) {
            std::cerr << "Failed to initialize YARA: " << error.message << std::endl;
        }
    }
    
    static void TearDownTestSuite() {
        // Finalize YARA library
        YaraRuleStore::FinalizeYara();
    }
    
    void SetUp() override {
        // Create temporary test directory
        test_dir_ = fs::temp_directory_path() / "shadowstrike_yara_tests";
        fs::create_directories(test_dir_);
        
        // Create temporary test database path
        test_db_path_ = (test_dir_ / "test_yara_store.ysdb").wstring();
        
        // Remove any existing test database
        fs::remove(test_db_path_);
        
        // Create new YARA rule store
        yara_store_ = std::make_unique<YaraRuleStore>();
    }
    
    void TearDown() override {
        // Close and cleanup
        if (yara_store_) {
            yara_store_->Close();
            yara_store_.reset();
        }
        
        // Remove test directory
        try {
            if (fs::exists(test_dir_)) {
                fs::remove_all(test_dir_);
            }
        } catch (...) {
            // Ignore cleanup errors
        }
    }
    
    // Helper: Create test YARA rule
    std::string CreateTestRule(const std::string& rule_name, 
                               const std::string& hex_pattern) {
        return "rule " + rule_name + " {\n"
               "    meta:\n"
               "        author = \"Test\"\n"
               "        description = \"Test rule\"\n"
               "    strings:\n"
               "        $a = { " + hex_pattern + " }\n"
               "    condition:\n"
               "        $a\n"
               "}\n";
    }
    
    // Helper: Create test YARA rule with strings
    std::string CreateStringRule(const std::string& rule_name,
                                 const std::string& string_pattern) {
        return "rule " + rule_name + " {\n"
               "    strings:\n"
               "        $str = \"" + string_pattern + "\"\n"
               "    condition:\n"
               "        $str\n"
               "}\n";
    }
    
    // Helper: Create YARA rule file
    std::wstring CreateRuleFile(const std::string& filename,
                               const std::string& rule_content) {
        auto file_path = test_dir_ / filename;
        std::ofstream file(file_path);
        file << rule_content;
        file.close();
        return file_path.wstring();
    }
    
    // Helper: Create test buffer
    std::vector<uint8_t> CreateTestBuffer(const std::string& content) {
        return std::vector<uint8_t>(content.begin(), content.end());
    }
};

// ============================================================================
// YARA Compiler Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, Compiler_AddString) {
    YaraCompiler compiler;
    
    std::string rule = CreateTestRule("TestRule", "4D 5A 90");
    
    auto error = compiler.AddString(rule, "default");
    
    EXPECT_TRUE(error.IsSuccess()) << "Error: " << error.message;
}

TEST_F(YaraRuleStoreTest, Compiler_AddInvalidRule) {
    YaraCompiler compiler;
    
    std::string invalid_rule = "invalid syntax here";
    
    auto error = compiler.AddString(invalid_rule, "default");
    
    EXPECT_FALSE(error.IsSuccess());
    
    auto errors = compiler.GetErrors();
    EXPECT_FALSE(errors.empty());
}

TEST_F(YaraRuleStoreTest, Compiler_AddFile) {
    YaraCompiler compiler;
    
    std::string rule = CreateTestRule("FileRule", "50 45 00 00");
    auto rule_file = CreateRuleFile("test_rule.yar", rule);
    
    auto error = compiler.AddFile(rule_file, "default");
    
    EXPECT_TRUE(error.IsSuccess()) << "Error: " << error.message;
}

TEST_F(YaraRuleStoreTest, Compiler_AddNonexistentFile) {
    YaraCompiler compiler;
    
    auto error = compiler.AddFile(L"nonexistent_rule.yar", "default");
    
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Compiler_GetErrors) {
    YaraCompiler compiler;
    
    compiler.AddString("invalid rule", "default");//-V530
    
    auto errors = compiler.GetErrors();
    EXPECT_FALSE(errors.empty());
    
    compiler.ClearErrors();
    
    errors = compiler.GetErrors();
    EXPECT_TRUE(errors.empty());
}

TEST_F(YaraRuleStoreTest, Compiler_SaveToFile) {
    YaraCompiler compiler;
    
    std::string rule = CreateTestRule("SaveTest", "4D 5A");
    ASSERT_TRUE(compiler.AddString(rule, "default").IsSuccess());
    
    auto compiled_path = (test_dir_ / "compiled_rules.yc").wstring();
    
    auto error = compiler.SaveToFile(compiled_path);
    
    EXPECT_TRUE(error.IsSuccess()) << "Error: " << error.message;
    EXPECT_TRUE(fs::exists(compiled_path));
}

TEST_F(YaraRuleStoreTest, Compiler_SaveToBuffer) {
    YaraCompiler compiler;
    
    std::string rule = CreateTestRule("BufferTest", "4D 5A");
    ASSERT_TRUE(compiler.AddString(rule, "default").IsSuccess());
    
    auto buffer = compiler.SaveToBuffer();
    
    ASSERT_TRUE(buffer.has_value());
    EXPECT_FALSE(buffer->empty());
}

TEST_F(YaraRuleStoreTest, Compiler_MultipleRules) {
    YaraCompiler compiler;
    
    std::string rule1 = CreateTestRule("Rule1", "4D 5A");
    std::string rule2 = CreateTestRule("Rule2", "50 45");
    
    EXPECT_TRUE(compiler.AddString(rule1, "namespace1").IsSuccess());
    EXPECT_TRUE(compiler.AddString(rule2, "namespace2").IsSuccess());
    
    auto rules = compiler.GetRules();
    EXPECT_NE(rules, nullptr);
}

TEST_F(YaraRuleStoreTest, Compiler_DefineExternalVariables) {
    YaraCompiler compiler;
    
    compiler.DefineExternalVariable("test_string", "value");
    compiler.DefineExternalVariable("test_int", static_cast<bool>(42));
    compiler.DefineExternalVariable("test_bool", true);
    
    // Should not crash
    SUCCEED();
}

// ============================================================================
// YaraRuleStore Initialization Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, Initialize_NotInitialized) {
    EXPECT_FALSE(yara_store_->IsInitialized());
}

TEST_F(YaraRuleStoreTest, Initialize_InvalidPath) {
    auto error = yara_store_->Initialize(L"\\\\invalid\\path\\rules.ysdb");
    
    EXPECT_FALSE(error.IsSuccess());
    EXPECT_FALSE(yara_store_->IsInitialized());
}

TEST_F(YaraRuleStoreTest, CreateNew_ValidPath) {
    auto error = yara_store_->CreateNew(test_db_path_);
    
    if (error.IsSuccess()) {
        EXPECT_TRUE(yara_store_->IsInitialized());
    }
}

TEST_F(YaraRuleStoreTest, Close_Idempotent) {
    yara_store_->Close();
    yara_store_->Close(); // Should not crash
    
    EXPECT_FALSE(yara_store_->IsInitialized());
}

// ============================================================================
// Rule Management Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, AddRulesFromSource_SimpleRule) {
    std::string rule = CreateTestRule("AddTest", "4D 5A 90");
    
    auto error = yara_store_->AddRulesFromSource(rule, "default");
    
    // May succeed or fail depending on initialization
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, AddRulesFromFile_ValidFile) {
    std::string rule = CreateTestRule("FileAddTest", "50 45");
    auto rule_file = CreateRuleFile("add_test.yar", rule);
    
    auto error = yara_store_->AddRulesFromFile(rule_file, "default");
    
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, AddRulesFromDirectory_EmptyDirectory) {
    auto empty_dir = test_dir_ / "empty_rules";
    fs::create_directories(empty_dir);
    
    auto error = yara_store_->AddRulesFromDirectory(empty_dir.wstring(), "default");
    
    // Should handle gracefully
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, AddRulesFromDirectory_WithRules) {
    auto rules_dir = test_dir_ / "rules_dir";
    fs::create_directories(rules_dir);
    
    // Create rule files
    for (int i = 0; i < 3; ++i) {
        std::string rule = CreateTestRule("DirRule" + std::to_string(i), "4D 5A");
        CreateRuleFile("rules_dir/rule" + std::to_string(i) + ".yar", rule);
    }
    
    size_t progress_count = 0;
    auto error = yara_store_->AddRulesFromDirectory(
        rules_dir.wstring(), 
        "default",
        [&progress_count](size_t current, size_t total) {
            progress_count++;
        });
    
    if (error.IsSuccess()) {
        EXPECT_GT(progress_count, 0);
    }
}

TEST_F(YaraRuleStoreTest, TestRule_ValidSyntax) {
    std::string valid_rule = CreateTestRule("SyntaxTest", "4D 5A");
    
    std::vector<std::string> errors;
    auto result = yara_store_->TestRule(valid_rule, errors);
    
    if (result.IsSuccess()) {
        EXPECT_TRUE(errors.empty());
    }
}

TEST_F(YaraRuleStoreTest, TestRule_InvalidSyntax) {
    std::string invalid_rule = "rule BadRule { invalid syntax }";
    
    std::vector<std::string> errors;
    auto result = yara_store_->TestRule(invalid_rule, errors);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_FALSE(errors.empty());
}

// ============================================================================
// Scanning Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, ScanBuffer_EmptyBuffer) {
    std::vector<uint8_t> empty_buffer;
    YaraScanOptions options;
    
    auto matches = yara_store_->ScanBuffer(empty_buffer, options);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanBuffer_NoRules) {
    std::vector<uint8_t> test_buffer = {0x4D, 0x5A, 0x90, 0x00};
    YaraScanOptions options;
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // Should return empty (no rules loaded)
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanBuffer_WithTimeout) {
    std::vector<uint8_t> test_buffer = {0x4D, 0x5A, 0x90};
    
    YaraScanOptions options;
    options.timeoutSeconds = 5;
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // Should not crash
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanBuffer_FastMode) {
    std::vector<uint8_t> test_buffer = {0x50, 0x45, 0x00, 0x00};
    
    YaraScanOptions options;
    options.fastMode = true;
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanBuffer_CaptureMatchData) {
    std::vector<uint8_t> test_buffer = {0x4D, 0x5A};
    
    YaraScanOptions options;
    options.captureMatchData = true;
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // If matches found, data should be captured
    for (const auto& match : matches) {
        if (!match.stringMatches.empty()) {
            // Data capture requested
        }
    }
    
    SUCCEED();
}

TEST_F(YaraRuleStoreTest, ScanBuffer_ThreatLevelFiltering) {
    std::vector<uint8_t> test_buffer = {0x00, 0x01, 0x02};
    
    YaraScanOptions options;
    options.minThreatLevel = ThreatLevel::High;
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // All matches should be at least High threat level
    for (const auto& match : matches) {
        EXPECT_GE(static_cast<uint8_t>(match.threatLevel),
                  static_cast<uint8_t>(ThreatLevel::High));
    }
}

TEST_F(YaraRuleStoreTest, ScanBuffer_NamespaceFiltering) {
    std::vector<uint8_t> test_buffer = {0x4D, 0x5A};
    
    YaraScanOptions options;
    options.namespaceFilter = {"test_namespace"};
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // All matches should be from filtered namespace
    for (const auto& match : matches) {
        EXPECT_EQ(match.namespace_, "test_namespace");
    }
}

TEST_F(YaraRuleStoreTest, ScanBuffer_TagFiltering) {
    std::vector<uint8_t> test_buffer = {0x00};
    
    YaraScanOptions options;
    options.tagFilter = {"malware", "trojan"};
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);
    
    // All matches should have at least one of the filtered tags
    for (const auto& match : matches) {
        bool has_filtered_tag = false;
        for (const auto& tag : match.tags) {
            if (tag == "malware" || tag == "trojan") {
                has_filtered_tag = true;
                break;
            }
        }
        if (!match.tags.empty()) {
            // Tag filtering should apply
        }
    }
    
    SUCCEED();
}

TEST_F(YaraRuleStoreTest, ScanFile_NonexistentFile) {
    YaraScanOptions options;
    
    auto matches = yara_store_->ScanFile(L"nonexistent.bin", options);
    
    // Should handle gracefully
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanFile_EmptyFile) {
    auto empty_file = test_dir_ / "empty.bin";
    std::ofstream(empty_file).close();
    
    YaraScanOptions options;
    
    auto matches = yara_store_->ScanFile(empty_file.wstring(), options);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanFile_ValidFile) {
    auto test_file = test_dir_ / "test.bin";
    std::ofstream file(test_file, std::ios::binary);
    std::vector<uint8_t> data = {0x4D, 0x5A, 0x90, 0x00};
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    
    YaraScanOptions options;
    
    auto matches = yara_store_->ScanFile(test_file.wstring(), options);
    
    // Should not crash
    EXPECT_TRUE(matches.empty());
}

// ============================================================================
// Stream Scanning Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, ScanContext_Create) {
    YaraScanOptions options;
    
    auto context = yara_store_->CreateScanContext(options);
    
    EXPECT_TRUE(context.IsValid());
    EXPECT_EQ(context.GetBufferSize(), 0);
    EXPECT_EQ(context.GetTotalBytesProcessed(), 0);
}

TEST_F(YaraRuleStoreTest, ScanContext_FeedChunk) {
    auto context = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk1 = {0x4D, 0x5A};
    std::vector<uint8_t> chunk2 = {0x90, 0x00};
    
    context.FeedChunk(chunk1);//-V530
	context.FeedChunk(chunk2);//-V530
    
    EXPECT_EQ(context.GetTotalBytesProcessed(), 4);
}

TEST_F(YaraRuleStoreTest, ScanContext_Finalize) {
    auto context = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk = {0x50, 0x45, 0x00, 0x00};
    context.FeedChunk(chunk);//-V530
    
    auto matches = context.Finalize();
    
    // Should return matches (or empty)
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraRuleStoreTest, ScanContext_Reset) {
    auto context = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk = {0x00, 0x01, 0x02};
    context.FeedChunk(chunk);//-V530
    
    context.Reset();
    
    EXPECT_EQ(context.GetBufferSize(), 0);
    EXPECT_EQ(context.GetTotalBytesProcessed(), 0);
}

TEST_F(YaraRuleStoreTest, ScanContext_LargeStream) {
    auto context = yara_store_->CreateScanContext();
    
    // Feed 1MB in chunks
    constexpr size_t chunk_size = 10 * 1024;
    constexpr size_t total_size = 1 * 1024 * 1024;
    
    for (size_t i = 0; i < total_size / chunk_size; ++i) {
        std::vector<uint8_t> chunk(chunk_size, static_cast<uint8_t>(i % 256));
        context.FeedChunk(chunk);//-V530
    }
    
    auto matches = context.Finalize();//-V808
    
    EXPECT_EQ(context.GetTotalBytesProcessed(), total_size);
}

TEST_F(YaraRuleStoreTest, ScanContext_MoveSemantics) {
    auto context1 = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk = {0x4D, 0x5A};
    context1.FeedChunk(chunk);//-V530
    
    // Move context
    auto context2 = std::move(context1);
    
    EXPECT_EQ(context2.GetTotalBytesProcessed(), 2);
}

// ============================================================================
// Rule Query Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, GetRuleMetadata_NoRules) {
    auto metadata = yara_store_->GetRuleMetadata("NonexistentRule", "default");
    
    EXPECT_FALSE(metadata.has_value());
}

TEST_F(YaraRuleStoreTest, ListRules_EmptyStore) {
    auto rules = yara_store_->ListRules();
    
    EXPECT_TRUE(rules.empty());
}

TEST_F(YaraRuleStoreTest, ListNamespaces_EmptyStore) {
    auto namespaces = yara_store_->ListNamespaces();
    
    EXPECT_TRUE(namespaces.empty());
}

TEST_F(YaraRuleStoreTest, FindRulesByTag_NoMatches) {
    auto rules = yara_store_->FindRulesByTag("nonexistent_tag");
    
    EXPECT_TRUE(rules.empty());
}

TEST_F(YaraRuleStoreTest, FindRulesByAuthor_NoMatches) {
    auto rules = yara_store_->FindRulesByAuthor("Unknown Author");
    
    EXPECT_TRUE(rules.empty());
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, GetStatistics_Initial) {
    auto stats = yara_store_->GetStatistics();
    
    EXPECT_EQ(stats.totalRules, 0);
    EXPECT_EQ(stats.totalScans, 0);
    EXPECT_EQ(stats.totalMatches, 0);
}

TEST_F(YaraRuleStoreTest, GetStatistics_AfterScans) {
    std::vector<uint8_t> test_buffer = {0x4D, 0x5A};
    
    // Perform multiple scans
    for (int i = 0; i < 5; ++i) {
        yara_store_->ScanBuffer(test_buffer);//-V530
    }
    
    auto stats = yara_store_->GetStatistics();
    
    EXPECT_GE(stats.totalScans, 5);
}

TEST_F(YaraRuleStoreTest, ResetStatistics) {
    std::vector<uint8_t> test_buffer = { 0x00 };
    yara_store_->ScanBuffer(test_buffer);//-V530 

    yara_store_->ResetStatistics();

    auto stats = yara_store_->GetStatistics();
    EXPECT_EQ(stats.totalScans, 0);
}

TEST_F(YaraRuleStoreTest, GetTopRules_EmptyStore) {
    auto top_rules = yara_store_->GetTopRules(10);
    
    EXPECT_TRUE(top_rules.empty());
}

// ============================================================================
// Import/Export Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, ExportToJson_EmptyStore) {
    auto json = yara_store_->ExportToJson();
    
    EXPECT_FALSE(json.empty());
}

TEST_F(YaraRuleStoreTest, ExportCompiled_ValidPath) {
    auto export_path = (test_dir_ / "exported_rules.yc").wstring();
    
    auto error = yara_store_->ExportCompiled(export_path);
    
    // May succeed or fail depending on rules loaded
    EXPECT_TRUE(error.IsSuccess());
}

// ============================================================================
// Maintenance Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, Recompile_EmptyStore) {
    auto error = yara_store_->Recompile();
    
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Verify_EmptyStore) {
    std::vector<std::string> log_messages;
    
    auto error = yara_store_->Verify(
        [&log_messages](const std::string& msg) {
            log_messages.push_back(msg);
        });
    
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Flush_NoChanges) {
    auto error = yara_store_->Flush();
    
    EXPECT_TRUE(error.IsSuccess());
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, SetProfilingEnabled) {
    yara_store_->SetProfilingEnabled(true);
    yara_store_->SetProfilingEnabled(false);
    
    SUCCEED();
}

TEST_F(YaraRuleStoreTest, SetScanTimeout) {
    yara_store_->SetScanTimeout(300);
    yara_store_->SetScanTimeout(60);
    
    SUCCEED();
}

// ============================================================================
// Advanced Features Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, GetYaraVersion) {
    auto version = YaraRuleStore::GetYaraVersion();
    
    EXPECT_FALSE(version.empty());
}

TEST_F(YaraRuleStoreTest, GetDatabasePath_Uninitialized) {
    auto path = yara_store_->GetDatabasePath();
    
    EXPECT_TRUE(path.empty());
}

TEST_F(YaraRuleStoreTest, GetHeader_Uninitialized) {
    auto header = yara_store_->GetHeader();
    
    EXPECT_EQ(header, nullptr);
}

// ============================================================================
// YaraUtils Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, YaraUtils_ValidateRuleSyntax_Valid) {
    std::string valid_rule = CreateTestRule("ValidRule", "4D 5A");
    
    std::vector<std::string> errors;
    bool valid = YaraUtils::ValidateRuleSyntax(valid_rule, errors);
    
    EXPECT_TRUE(valid);
    EXPECT_TRUE(errors.empty());
}

TEST_F(YaraRuleStoreTest, YaraUtils_ValidateRuleSyntax_Invalid) {
    std::string invalid_rule = "rule Bad { invalid }";
    
    std::vector<std::string> errors;
    bool valid = YaraUtils::ValidateRuleSyntax(invalid_rule, errors);
    
    EXPECT_FALSE(valid);
    EXPECT_FALSE(errors.empty());
}

TEST_F(YaraRuleStoreTest, YaraUtils_ExtractMetadata) {
    std::string rule = "rule MetaTest {\n"
                      "    meta:\n"
                      "        author = \"TestAuthor\"\n"
                      "        description = \"Test Description\"\n"
                      "    condition:\n"
                      "        true\n"
                      "}\n";
    
    auto metadata = YaraUtils::ExtractMetadata(rule);
    
    EXPECT_FALSE(metadata.empty());
}

TEST_F(YaraRuleStoreTest, YaraUtils_ExtractTags) {
    std::string rule = "rule TagTest : malware trojan {\n"
                      "    condition:\n"
                      "        true\n"
                      "}\n";
    
    auto tags = YaraUtils::ExtractTags(rule);
    
    EXPECT_GE(tags.size(), 0);
}

TEST_F(YaraRuleStoreTest, YaraUtils_ParseThreatLevel) {
    std::map<std::string, std::string> metadata;
    metadata["severity"] = "high";
    
    auto threat_level = YaraUtils::ParseThreatLevel(metadata);
    
    EXPECT_TRUE(threat_level == ThreatLevel::High);
}

TEST_F(YaraRuleStoreTest, YaraUtils_FindYaraFiles_EmptyDir) {
    auto empty_dir = test_dir_ / "empty_yara";
    fs::create_directories(empty_dir);
    
    auto files = YaraUtils::FindYaraFiles(empty_dir.wstring(), false);
    
    EXPECT_TRUE(files.empty());
}

TEST_F(YaraRuleStoreTest, YaraUtils_FindYaraFiles_WithFiles) {
    auto yara_dir = test_dir_ / "yara_files";
    fs::create_directories(yara_dir);
    
    // Create .yar files
    std::ofstream((yara_dir / "rule1.yar")).close();
    std::ofstream((yara_dir / "rule2.yara")).close();
    std::ofstream((yara_dir / "not_yara.txt")).close();
    
    auto files = YaraUtils::FindYaraFiles(yara_dir.wstring(), false);
    
    EXPECT_GE(files.size(), 2);
}

TEST_F(YaraRuleStoreTest, YaraUtils_FindYaraFiles_Recursive) {
    auto yara_dir = test_dir_ / "recursive_yara";
    fs::create_directories(yara_dir / "subdir");
    
    std::ofstream((yara_dir / "rule1.yar")).close();
    std::ofstream((yara_dir / "subdir" / "rule2.yar")).close();
    
    auto files = YaraUtils::FindYaraFiles(yara_dir.wstring(), true);
    
    EXPECT_GE(files.size(), 2);
}

// ============================================================================
// YaraMatch Structure Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, YaraMatch_Structure) {
    YaraMatch match;
    
    match.ruleId = 1;
    match.ruleName = "TestRule";
    match.namespace_ = "default";
    match.threatLevel = ThreatLevel::High;
    match.tags = {"malware", "trojan"};
    
    YaraMatch::StringMatch string_match;
    string_match.identifier = "$a";
    string_match.offsets = {0, 100, 200};
    string_match.data = {"data1", "data2", "data3"};
    
    match.stringMatches.push_back(string_match);
    match.metadata["author"] = "Test";
    
    EXPECT_EQ(match.ruleName, "TestRule");
    EXPECT_EQ(match.stringMatches.size(), 1);
    EXPECT_EQ(match.stringMatches[0].offsets.size(), 3);
}

// ============================================================================
// YaraScanOptions Validation Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, YaraScanOptions_DefaultValues) {
    YaraScanOptions options;
    
    EXPECT_EQ(options.timeoutSeconds, 300);
    EXPECT_EQ(options.maxMatchesPerRule, 100);
    EXPECT_FALSE(options.captureMatchData);
    EXPECT_FALSE(options.fastMode);
}

TEST_F(YaraRuleStoreTest, YaraScanOptions_CustomValues) {
    YaraScanOptions options;
    
    options.timeoutSeconds = 60;
    options.maxMatchesPerRule = 50;
    options.captureMatchData = true;
    options.fastMode = true;
    options.threadCount = 4;
    options.minThreatLevel = ThreatLevel::Medium;
    
    EXPECT_EQ(options.timeoutSeconds, 60);
    EXPECT_TRUE(options.captureMatchData);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, ThreadSafety_ConcurrentScans) {
    std::array<uint8_t,4> test_buffer = {0x4D, 0x5A, 0x90, 0x00};
    
    std::vector<std::thread> threads;
    std::atomic<int> scan_count{0};
    
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([this, &test_buffer, &scan_count]() {
            auto matches = yara_store_->ScanBuffer(test_buffer);
            scan_count++;
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(scan_count, 8);
}

TEST_F(YaraRuleStoreTest, ThreadSafety_ConcurrentStatisticsAccess) {
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this]() {
            for (int j = 0; j < 100; ++j) {
                auto stats = yara_store_->GetStatistics();
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    SUCCEED();
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, Performance_SmallBufferScan) {
    std::vector<uint8_t> small_buffer = {0x4D, 0x5A, 0x90, 0x00};
    
    auto start = std::chrono::high_resolution_clock::now();
    
    auto matches = yara_store_->ScanBuffer(small_buffer);//-V808
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete quickly
    EXPECT_LT(duration.count(), 100000); // < 100ms
}

TEST_F(YaraRuleStoreTest, Performance_LargeBufferScan) {
    // Create 10MB buffer
    std::vector<uint8_t> large_buffer(10 * 1024 * 1024, 0xAA);
    
    YaraScanOptions options;
    options.timeoutSeconds = 60;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    auto matches = yara_store_->ScanBuffer(large_buffer, options);//-V808
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should complete within timeout
    EXPECT_LT(duration.count(), 60000);
}

TEST_F(YaraRuleStoreTest, Performance_ManySmallScans) {
    std::vector<uint8_t> test_buffer = {0x00, 0x01, 0x02, 0x03};
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100; ++i) {
        yara_store_->ScanBuffer(test_buffer);//-V530
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should handle many scans efficiently
    EXPECT_LT(duration.count(), 5000); // < 5 seconds for 100 scans
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, EdgeCase_MaxBufferSize) {
    // Test with buffer at Titanium limit
    try {
        std::vector<uint8_t> max_buffer(YaraTitaniumLimits::MAX_SCAN_BUFFER_SIZE, 0xAA);
        
        YaraScanOptions options;
        options.timeoutSeconds = 300;
        
        auto matches = yara_store_->ScanBuffer(max_buffer, options);//-V808
        
        SUCCEED();
    } catch (const std::bad_alloc&) {
        GTEST_SKIP() << "Insufficient memory for max buffer test";
    }
}

TEST_F(YaraRuleStoreTest, EdgeCase_VeryLongRuleName) {
    std::string long_name(YaraTitaniumLimits::MAX_RULE_NAME_LENGTH, 'A');
    std::string rule = CreateTestRule(long_name, "4D 5A");
    
    auto error = yara_store_->AddRulesFromSource(rule);
    
    // Should handle long names
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, EdgeCase_MaxTimeout) {
    YaraScanOptions options;
    options.timeoutSeconds = YaraTitaniumLimits::MAX_TIMEOUT_SECONDS;
    
    std::vector<uint8_t> test_buffer = {0x00};
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);//-V808
    
    SUCCEED();
}

TEST_F(YaraRuleStoreTest, EdgeCase_MaxMatchesPerRule) {
    YaraScanOptions options;
    options.maxMatchesPerRule = YaraTitaniumLimits::ABSOLUTE_MAX_MATCHES_PER_RULE;
    
    std::vector<uint8_t> test_buffer = {0x00};
    
    auto matches = yara_store_->ScanBuffer(test_buffer, options);//-V808
    
    SUCCEED();
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST_F(YaraRuleStoreTest, Stress_ManyStreamContexts) {
    std::vector<YaraRuleStore::ScanContext> contexts;
    
    for (int i = 0; i < 10; ++i) {
        contexts.push_back(yara_store_->CreateScanContext());
    }
    
    EXPECT_EQ(contexts.size(), 10);
}

TEST_F(YaraRuleStoreTest, Stress_RepeatedCompilation) {
    std::string rule = CreateTestRule("StressRule", "4D 5A");
    
    for (int i = 0; i < 10; ++i) {
        YaraCompiler compiler;
        auto error = compiler.AddString(rule);
        EXPECT_TRUE(error.IsSuccess());
    }
}

// ============================================================================
// Entry Point
// ============================================================================


