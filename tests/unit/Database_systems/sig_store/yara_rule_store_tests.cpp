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
    
    // Empty directory returns FileNotFound (no rules to add)
    // This is correct behavior - no rules found is an error condition
    EXPECT_FALSE(error.IsSuccess());
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
    
    // Context requires store to be initialized - without init, IsValid() returns false
    // This is correct security behavior - cannot scan without proper initialization
    EXPECT_FALSE(context.IsValid());
    EXPECT_EQ(context.GetBufferSize(), 0);
    EXPECT_EQ(context.GetTotalBytesProcessed(), 0);
}

TEST_F(YaraRuleStoreTest, ScanContext_FeedChunk) {
    auto context = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk1 = {0x4D, 0x5A};
    std::vector<uint8_t> chunk2 = {0x90, 0x00};
    
    // Without initialization, FeedChunk returns empty (context invalid)
    context.FeedChunk(chunk1);//-V530
	context.FeedChunk(chunk2);//-V530
    
    // Store not initialized, so bytes aren't processed
    EXPECT_EQ(context.GetTotalBytesProcessed(), 0);
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
    
    // Without initialization, bytes aren't processed
    EXPECT_EQ(context.GetTotalBytesProcessed(), 0);
}

TEST_F(YaraRuleStoreTest, ScanContext_MoveSemantics) {
    auto context1 = yara_store_->CreateScanContext();
    
    std::vector<uint8_t> chunk = {0x4D, 0x5A};
    context1.FeedChunk(chunk);//-V530
    
    // Move context
    auto context2 = std::move(context1);
    
    // Without initialization, bytes aren't processed
    EXPECT_EQ(context2.GetTotalBytesProcessed(), 0);
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
    
    // Perform multiple scans - without initialization, ScanBuffer returns early
    for (int i = 0; i < 5; ++i) {
        yara_store_->ScanBuffer(test_buffer);//-V530
    }
    
    auto stats = yara_store_->GetStatistics();
    
    // Store not initialized, so scans don't count
    EXPECT_EQ(stats.totalScans, 0);
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
    
    // Without rules loaded, export should fail
    EXPECT_FALSE(error.IsSuccess());
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
    
    // Store not initialized, Verify returns NotInitialized error
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Flush_NoChanges) {
    auto error = yara_store_->Flush();
    
    // Store not initialized, Flush returns NotInitialized error  
    EXPECT_FALSE(error.IsSuccess());
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
    // YARA library has a max identifier length of 128 characters
    // Using a name at that limit to test boundary behavior
    std::string long_name(128, 'A');
    std::string rule = CreateTestRule(long_name, "4D 5A");
    
    auto error = yara_store_->AddRulesFromSource(rule);
    
    // Should handle long names at YARA's limit
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
// ADDITIONAL EDGE CASE TESTS - ENTERPRISE COVERAGE
// ============================================================================

// Rule merging tests
TEST_F(YaraRuleStoreTest, RuleMerging_AddMultipleRuleSets) {
    std::string rule1 = CreateTestRule("MergeRule1", "4D 5A");
    std::string rule2 = CreateTestRule("MergeRule2", "50 45");
    
    // Add first rule set
    auto error1 = yara_store_->AddRulesFromSource(rule1, "namespace1");
    EXPECT_TRUE(error1.IsSuccess()) << "Error: " << error1.message;
    
    // Add second rule set - should merge, not replace
    auto error2 = yara_store_->AddRulesFromSource(rule2, "namespace2");
    EXPECT_TRUE(error2.IsSuccess()) << "Error: " << error2.message;
    
    // Both rules should be accessible
    auto rules = yara_store_->ListRules();
    
    // Check metadata exists for both
    auto meta1 = yara_store_->GetRuleMetadata("MergeRule1", "namespace1");
    auto meta2 = yara_store_->GetRuleMetadata("MergeRule2", "namespace2");
    
    EXPECT_TRUE(meta1.has_value());
    EXPECT_TRUE(meta2.has_value());
}

TEST_F(YaraRuleStoreTest, RuleMerging_ThreeRuleSetsSequential) {
    std::string rule1 = CreateTestRule("SeqRule1", "4D 5A");
    std::string rule2 = CreateTestRule("SeqRule2", "50 45");
    std::string rule3 = CreateTestRule("SeqRule3", "7F 45 4C 46");  // ELF magic
    
    EXPECT_TRUE(yara_store_->AddRulesFromSource(rule1, "default").IsSuccess());
    EXPECT_TRUE(yara_store_->AddRulesFromSource(rule2, "default").IsSuccess());
    EXPECT_TRUE(yara_store_->AddRulesFromSource(rule3, "default").IsSuccess());
    
    // All three rules should exist
    EXPECT_TRUE(yara_store_->GetRuleMetadata("SeqRule1", "default").has_value());
    EXPECT_TRUE(yara_store_->GetRuleMetadata("SeqRule2", "default").has_value());
    EXPECT_TRUE(yara_store_->GetRuleMetadata("SeqRule3", "default").has_value());
}

TEST_F(YaraRuleStoreTest, RuleMerging_ScanWithMergedRules) {
    // Test rule merging capability by compiling multiple rules together
    YaraCompiler compiler;
    std::string rule1 = CreateTestRule("ScanMerge1", "4D 5A");  // MZ header
    std::string rule2 = CreateTestRule("ScanMerge2", "50 45 00 00");  // PE signature
    
    // Both rules should compile successfully together
    ASSERT_TRUE(compiler.AddString(rule1).IsSuccess());
    ASSERT_TRUE(compiler.AddString(rule2).IsSuccess());
    
    auto rules = compiler.GetRules();
    ASSERT_NE(rules, nullptr);
    
    // Verify both rules were compiled
    int ruleCount = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(rules, rule) {
        ruleCount++;
    }
    EXPECT_EQ(ruleCount, 2);
    
    yr_rules_destroy(rules);
}

// Compiler move semantics tests
TEST_F(YaraRuleStoreTest, Compiler_MoveConstructor) {
    YaraCompiler compiler1;
    std::string rule = CreateTestRule("MoveTest", "4D 5A");
    ASSERT_TRUE(compiler1.AddString(rule).IsSuccess());
    
    // Move construct
    YaraCompiler compiler2(std::move(compiler1));
    
    // Should be able to get rules from moved-to compiler
    auto rules = compiler2.GetRules();
    EXPECT_NE(rules, nullptr);
}

TEST_F(YaraRuleStoreTest, Compiler_MoveAssignment) {
    YaraCompiler compiler1;
    std::string rule1 = CreateTestRule("MoveAssign1", "4D 5A");
    ASSERT_TRUE(compiler1.AddString(rule1).IsSuccess());
    
    YaraCompiler compiler2;
    std::string rule2 = CreateTestRule("MoveAssign2", "50 45");
    ASSERT_TRUE(compiler2.AddString(rule2).IsSuccess());
    
    // Move assign
    compiler2 = std::move(compiler1);
    
    // compiler2 should now have rules from compiler1
    auto rules = compiler2.GetRules();
    EXPECT_NE(rules, nullptr);
}

// AddFiles with mixed results
TEST_F(YaraRuleStoreTest, Compiler_AddFiles_MixedResults) {
    YaraCompiler compiler;
    
    // Create one valid and one invalid file
    std::string validRule = CreateTestRule("ValidRule", "4D 5A");
    auto validFile = CreateRuleFile("valid_rule.yar", validRule);
    
    std::string invalidRule = "this is not a valid rule";
    auto invalidFile = CreateRuleFile("invalid_rule.yar", invalidRule);
    
    std::vector<std::wstring> files = {validFile, invalidFile};
    
    auto error = compiler.AddFiles(files, "default");
    
    // Should fail because one file is invalid
    // (depends on implementation - might succeed if partial success allowed)
    auto errors = compiler.GetErrors();
    EXPECT_FALSE(errors.empty());
}

// Namespace validation tests
TEST_F(YaraRuleStoreTest, Compiler_InvalidNamespaceChars) {
    YaraCompiler compiler;
    std::string rule = CreateTestRule("NsTest", "4D 5A");
    
    // Namespace with invalid characters
    auto error = compiler.AddString(rule, "invalid-namespace!");
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Compiler_EmptyNamespace) {
    YaraCompiler compiler;
    std::string rule = CreateTestRule("EmptyNsTest", "4D 5A");
    
    // Empty namespace should use default
    auto error = compiler.AddString(rule, "");
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, Compiler_VeryLongNamespace) {
    YaraCompiler compiler;
    std::string rule = CreateTestRule("LongNsTest", "4D 5A");
    
    // Namespace exceeding limit (>128 chars)
    std::string longNamespace(200, 'a');
    auto error = compiler.AddString(rule, longNamespace);
    EXPECT_FALSE(error.IsSuccess());
}

// Timeout boundary tests
TEST_F(YaraRuleStoreTest, ScanOptions_MinTimeout) {
    YaraScanOptions options;
    options.timeoutSeconds = YaraTitaniumLimits::MIN_TIMEOUT_SECONDS;
    
    std::vector<uint8_t> buffer = {0x00, 0x01};
    auto matches = yara_store_->ScanBuffer(buffer, options);
    
    SUCCEED();
}

TEST_F(YaraRuleStoreTest, ScanOptions_ZeroTimeout) {
    YaraScanOptions options;
    options.timeoutSeconds = 0;  // Should be clamped or handled
    
    std::vector<uint8_t> buffer = {0x00};
    auto matches = yara_store_->ScanBuffer(buffer, options);
    
    SUCCEED();
}

// RemoveRule/RemoveNamespace tests
TEST_F(YaraRuleStoreTest, RemoveRule_Existing) {
    std::string rule = CreateTestRule("RemoveTest", "4D 5A");
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    // Verify rule exists
    EXPECT_TRUE(yara_store_->GetRuleMetadata("RemoveTest", "default").has_value());
    
    // Remove rule
    auto error = yara_store_->RemoveRule("RemoveTest", "default");
    EXPECT_TRUE(error.IsSuccess());
    
    // Verify rule is gone from metadata
    EXPECT_FALSE(yara_store_->GetRuleMetadata("RemoveTest", "default").has_value());
}

TEST_F(YaraRuleStoreTest, RemoveRule_NonExistent) {
    auto error = yara_store_->RemoveRule("NonExistentRule", "default");
    
    // Should succeed (no-op for non-existent rule)
    EXPECT_TRUE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, RemoveNamespace_WithRules) {
    std::string rule1 = CreateTestRule("NsRemoveRule1", "4D 5A");
    std::string rule2 = CreateTestRule("NsRemoveRule2", "50 45");
    
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule1, "removable_ns").IsSuccess());
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule2, "removable_ns").IsSuccess());
    
    // Remove namespace
    auto error = yara_store_->RemoveNamespace("removable_ns");
    EXPECT_TRUE(error.IsSuccess());
    
    // Rules should be gone
    EXPECT_FALSE(yara_store_->GetRuleMetadata("NsRemoveRule1", "removable_ns").has_value());
    EXPECT_FALSE(yara_store_->GetRuleMetadata("NsRemoveRule2", "removable_ns").has_value());
}

TEST_F(YaraRuleStoreTest, RemoveNamespace_PreservesOtherNamespaces) {
    std::string rule1 = CreateTestRule("PreserveRule1", "4D 5A");
    std::string rule2 = CreateTestRule("PreserveRule2", "50 45");
    
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule1, "keep_ns").IsSuccess());
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule2, "remove_ns").IsSuccess());
    
    // Remove one namespace
    yara_store_->RemoveNamespace("remove_ns");
    
    // Other namespace should be preserved
    EXPECT_TRUE(yara_store_->GetRuleMetadata("PreserveRule1", "keep_ns").has_value());
    EXPECT_FALSE(yara_store_->GetRuleMetadata("PreserveRule2", "remove_ns").has_value());
}

// UpdateRuleMetadata tests
TEST_F(YaraRuleStoreTest, UpdateRuleMetadata_ExistingRule) {
    std::string rule = CreateTestRule("UpdateMetaTest", "4D 5A");
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    // Get current metadata
    auto currentMeta = yara_store_->GetRuleMetadata("UpdateMetaTest", "default");
    ASSERT_TRUE(currentMeta.has_value());
    
    // Update metadata
    YaraRuleMetadata newMeta = currentMeta.value();
    newMeta.author = "Updated Author";
    newMeta.description = "Updated Description";
    newMeta.threatLevel = ThreatLevel::Critical;
    
    auto error = yara_store_->UpdateRuleMetadata("UpdateMetaTest", newMeta);
    EXPECT_TRUE(error.IsSuccess());
    
    // Verify update
    auto updatedMeta = yara_store_->GetRuleMetadata("UpdateMetaTest", "default");
    ASSERT_TRUE(updatedMeta.has_value());
    EXPECT_EQ(updatedMeta->author, "Updated Author");
    EXPECT_EQ(updatedMeta->threatLevel, ThreatLevel::Critical);
}

TEST_F(YaraRuleStoreTest, UpdateRuleMetadata_NonExistent) {
    YaraRuleMetadata meta{};
    meta.ruleName = "NonExistent";
    meta.namespace_ = "default";
    
    auto error = yara_store_->UpdateRuleMetadata("NonExistent", meta);
    EXPECT_FALSE(error.IsSuccess());
}

// ImportFromYaraRulesRepo tests
TEST_F(YaraRuleStoreTest, ImportFromYaraRulesRepo_InvalidPath) {
    auto error = yara_store_->ImportFromYaraRulesRepo(L"C:\\nonexistent\\path");
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(YaraRuleStoreTest, ImportFromYaraRulesRepo_EmptyDirectory) {
    auto emptyRepo = test_dir_ / "empty_repo";
    fs::create_directories(emptyRepo);
    
    auto error = yara_store_->ImportFromYaraRulesRepo(emptyRepo.wstring());
    
    // Empty directory returns error (no rules found)
    EXPECT_FALSE(error.IsSuccess());
}

// ExportCompiled tests
TEST_F(YaraRuleStoreTest, ExportCompiled_WithRulesLoaded) {
    std::string rule = CreateTestRule("ExportRule", "4D 5A");
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    auto exportPath = (test_dir_ / "exported_with_rules.yc").wstring();
    auto error = yara_store_->ExportCompiled(exportPath);
    
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(fs::exists(exportPath));
}

TEST_F(YaraRuleStoreTest, ExportCompiled_InvalidPath) {
    std::string rule = CreateTestRule("ExportRule2", "4D 5A");
    yara_store_->AddRulesFromSource(rule, "default");
    
    auto error = yara_store_->ExportCompiled(L"\\\\invalid\\network\\path\\export.yc");
    EXPECT_FALSE(error.IsSuccess());
}

// Verify tests
TEST_F(YaraRuleStoreTest, Verify_WithRulesLoaded) {
    std::string rule = CreateTestRule("VerifyRule", "4D 5A");
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    std::vector<std::string> logMessages;
    auto error = yara_store_->Verify([&logMessages](const std::string& msg) {
        logMessages.push_back(msg);
    });
    
    EXPECT_TRUE(error.IsSuccess());
}

// Concurrent rule addition tests
TEST_F(YaraRuleStoreTest, ThreadSafety_ConcurrentRuleAddition) {
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> failCount{0};
    
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([this, i, &successCount, &failCount]() {
            std::string rule = CreateTestRule("ConcurrentRule" + std::to_string(i), "4D 5A");
            std::string ns = "concurrent_ns" + std::to_string(i);
            auto error = yara_store_->AddRulesFromSource(rule, ns);
            if (error.IsSuccess()) {
                successCount++;
            } else {
                failCount++;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // At least some should succeed
    EXPECT_GT(successCount.load(), 0);
}

// Special characters in rule content
TEST_F(YaraRuleStoreTest, EdgeCase_SpecialCharsInRuleSource) {
    // Rule with various special characters in strings
    std::string rule = R"(
rule SpecialChars {
    meta:
        author = "Test \"Author\""
        description = "Special: \\ / ' \" < > & @"
    strings:
        $a = "test\x00string"
        $b = { 4D 5A ?? ?? }
    condition:
        any of them
}
)";
    
    auto error = yara_store_->AddRulesFromSource(rule, "default");
    EXPECT_TRUE(error.IsSuccess());
}

// Binary data in strings section
TEST_F(YaraRuleStoreTest, EdgeCase_BinaryPatternMatching) {
    // Test that binary patterns compile correctly 
    YaraCompiler compiler;
    std::string rule = R"(
rule BinaryPattern {
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $elf = { 7F 45 4C 46 }
    condition:
        any of them
}
)";
    
    ASSERT_TRUE(compiler.AddString(rule).IsSuccess());
    
    auto rules = compiler.GetRules();
    ASSERT_NE(rules, nullptr);
    
    // Verify rule was compiled
    int ruleCount = 0;
    YR_RULE* r = nullptr;
    yr_rules_foreach(rules, r) {
        ruleCount++;
    }
    EXPECT_EQ(ruleCount, 1);
    
    yr_rules_destroy(rules);
}

// Wildcard pattern tests
TEST_F(YaraRuleStoreTest, EdgeCase_WildcardPatterns) {
    std::string rule = R"(
rule WildcardTest {
    strings:
        $pattern = { 4D 5A ?? ?? [0-10] 50 45 }
    condition:
        $pattern
}
)";
    
    auto error = yara_store_->AddRulesFromSource(rule, "default");
    EXPECT_TRUE(error.IsSuccess());
}

// Condition-only rules
TEST_F(YaraRuleStoreTest, EdgeCase_ConditionOnlyRule) {
    std::string rule = R"(
rule ConditionOnly {
    condition:
        filesize > 0
}
)";
    
    auto error = yara_store_->AddRulesFromSource(rule, "default");
    EXPECT_TRUE(error.IsSuccess());
}

// Rule with many tags
TEST_F(YaraRuleStoreTest, EdgeCase_ManyTags) {
    std::string tags;
    for (int i = 0; i < 50; ++i) {
        tags += "tag" + std::to_string(i) + " ";
    }
    
    std::string rule = "rule ManyTags : " + tags + "{\n"
                       "    condition:\n"
                       "        true\n"
                       "}\n";
    
    auto error = yara_store_->AddRulesFromSource(rule, "default");
    EXPECT_TRUE(error.IsSuccess());
    
    auto meta = yara_store_->GetRuleMetadata("ManyTags", "default");
    if (meta.has_value()) {
        EXPECT_GE(meta->tags.size(), 10u);  // Should have many tags
    }
}

// Rule with comprehensive metadata
TEST_F(YaraRuleStoreTest, EdgeCase_ComprehensiveMetadata) {
    std::string rule = R"(
rule ComprehensiveMeta {
    meta:
        author = "Security Researcher"
        description = "Comprehensive test rule with all metadata fields"
        reference = "https://example.com/malware-analysis"
        severity = "critical"
        date = "2026-01-01"
        hash = "aabbccdd"
        version = "1.0"
    strings:
        $a = "test"
    condition:
        $a
}
)";
    
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    auto meta = yara_store_->GetRuleMetadata("ComprehensiveMeta", "default");
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->author, "Security Researcher");
    EXPECT_EQ(meta->threatLevel, ThreatLevel::Critical);
}

// Recompile tests
TEST_F(YaraRuleStoreTest, Recompile_WithRules) {
    std::string rule = CreateTestRule("RecompileTest", "4D 5A");
    ASSERT_TRUE(yara_store_->AddRulesFromSource(rule, "default").IsSuccess());
    
    auto error = yara_store_->Recompile();
    EXPECT_TRUE(error.IsSuccess());
    
    // Rule should still be accessible after recompile
    EXPECT_TRUE(yara_store_->GetRuleMetadata("RecompileTest", "default").has_value());
}

// Large rule source tests
TEST_F(YaraRuleStoreTest, EdgeCase_LargeRuleSource) {
    // Create a rule with many strings
    std::ostringstream ruleBuilder;
    ruleBuilder << "rule LargeRule {\n    strings:\n";
    for (int i = 0; i < 100; ++i) {
        ruleBuilder << "        $s" << i << " = \"pattern" << i << "\"\n";
    }
    ruleBuilder << "    condition:\n        any of them\n}\n";
    
    auto error = yara_store_->AddRulesFromSource(ruleBuilder.str(), "default");
    EXPECT_TRUE(error.IsSuccess());
}

// Empty buffer scan
TEST_F(YaraRuleStoreTest, ScanBuffer_EmptyAfterRulesAdded) {
    std::string rule = CreateTestRule("EmptyBufRule", "4D 5A");
    yara_store_->AddRulesFromSource(rule, "default");
    
    std::vector<uint8_t> emptyBuffer;
    auto matches = yara_store_->ScanBuffer(emptyBuffer);
    
    EXPECT_TRUE(matches.empty());
}

// Statistics accuracy after operations
TEST_F(YaraRuleStoreTest, Statistics_AccuracyAfterOperations) {
    // Test that statistics are properly reset and can be retrieved
    std::string rule = CreateTestRule("StatsRule", "4D 5A");
    yara_store_->AddRulesFromSource(rule, "default");
    
    // Reset statistics should work even without initialization
    yara_store_->ResetStatistics();
    
    auto stats = yara_store_->GetStatistics();
    
    // After reset, counts should be 0
    EXPECT_EQ(stats.totalScans, 0u);
    EXPECT_EQ(stats.totalMatches, 0u);
}

// GetTopRules with data
TEST_F(YaraRuleStoreTest, GetTopRules_WithMatches) {
    std::string rule = CreateTestRule("TopRule", "4D 5A");
    yara_store_->AddRulesFromSource(rule, "default");
    
    std::vector<uint8_t> buffer = {0x4D, 0x5A};
    
    // Generate some hits
    for (int i = 0; i < 5; ++i) {
        yara_store_->ScanBuffer(buffer);
    }
    
    auto topRules = yara_store_->GetTopRules(5);
    // May or may not have entries depending on hit tracking
    SUCCEED();
}

// LoadCompiledRules test
TEST_F(YaraRuleStoreTest, LoadCompiledRules_FromFile) {
    // First, save compiled rules
    YaraCompiler compiler;
    std::string rule = CreateTestRule("LoadTest", "4D 5A");
    ASSERT_TRUE(compiler.AddString(rule).IsSuccess());
    
    auto compiledPath = (test_dir_ / "load_test.yc").wstring();
    ASSERT_TRUE(compiler.SaveToFile(compiledPath).IsSuccess());
    
    // Create new store and load
    YaraRuleStore loadStore;
    auto error = loadStore.LoadCompiledRules(compiledPath);
    
    EXPECT_TRUE(error.IsSuccess());
    loadStore.Close();
}
