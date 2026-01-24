// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include <gtest/gtest.h>
#include "../../../src/Database/ConfigurationDB.hpp"
#include "../../../src/Utils/StringUtils.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>
#include <fstream>

using namespace ShadowStrike::Database;
using namespace std::chrono_literals;

namespace fs = std::filesystem;

// ============================================================================
// Test Utilities & Helpers
// ============================================================================

namespace {
    // Generate unique test paths
    std::wstring GenerateTestBasePath() {
        static std::atomic<int> counter{ 0 };
        auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        auto id = counter.fetch_add(1, std::memory_order_relaxed);

        std::wstring path = L"C:\\Temp\\ConfigDBTest_";
        path += std::to_wstring(timestamp);
        path += L"_";
        path += std::to_wstring(id);

        return path;
    }

    // Clean up test directory
    void CleanupTestDirectory(const std::wstring& path) {
        try {
            if (fs::exists(path)) {
                fs::remove_all(path);
            }
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }

    // Create test configuration
    ConfigurationDB::Config CreateTestConfig(const std::wstring& basePath) {
        ConfigurationDB::Config config;
        config.dbPath = basePath + L"\\config_test.db";

        // Generate random 256-bit key for testing
        config.masterKey.resize(32);
        for (size_t i = 0; i < 32; ++i) {
            config.masterKey[i] = static_cast<uint8_t>(rand() % 256);
        }

        config.enableEncryption = true;
        config.requireStrongKeys = true;
        config.enableAuditLog = true;
        config.trackAllChanges = true;
        config.maxAuditRecords = 10000;
        config.enableVersioning = true;
        config.maxVersionsPerKey = 5;
        config.enforceValidation = false;  // Disable for flexible testing
        config.allowUnknownKeys = true;
        config.enableCaching = true;
        config.maxCacheEntries = 1000;
        config.cacheRefreshInterval = std::chrono::minutes(5);
        config.enableHotReload = false;  // Disable for deterministic tests

        return config;
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

class ConfigurationDBTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Shutdown any existing instances
        ConfigurationDB::Instance().Shutdown();
        DatabaseManager::Instance().Shutdown();

        std::this_thread::sleep_for(100ms);

        // Generate unique test paths
        m_basePath = GenerateTestBasePath();

        // Create directories
        fs::create_directories(m_basePath);

        // Create config
        m_config = CreateTestConfig(m_basePath);
    }

    void TearDown() override {
        // Explicit cleanup
        ConfigurationDB::Instance().Shutdown();
        DatabaseManager::Instance().Shutdown();

        std::this_thread::sleep_for(100ms);

        CleanupTestDirectory(m_basePath);
    }

    // Helper: Initialize ConfigDB
    bool InitializeConfigDB() {
        DatabaseError err;
        bool success = ConfigurationDB::Instance().Initialize(m_config, &err);
        if (!success) {
            ADD_FAILURE() << "ConfigDB initialization failed: "
                << ShadowStrike::Utils::StringUtils::ToNarrow(err.message);
        }
        return success;
    }

    std::wstring m_basePath;
    ConfigurationDB::Config m_config;
};

// ============================================================================
// Initialization & Lifecycle Tests
// ============================================================================

TEST_F(ConfigurationDBTest, InitializeSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());
    EXPECT_TRUE(ConfigurationDB::Instance().IsInitialized());
}

TEST_F(ConfigurationDBTest, InitializeCreatesDatabase) {
    EXPECT_TRUE(InitializeConfigDB());
    EXPECT_TRUE(fs::exists(m_config.dbPath));
}

TEST_F(ConfigurationDBTest, InitializeWithInvalidPathFails) {
    m_config.dbPath = L"Z:\\invalid\\path\\config.db";

    DatabaseError err;
    EXPECT_FALSE(ConfigurationDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(err.HasError());
}

TEST_F(ConfigurationDBTest, InitializeWithShortKeyFails) {
    m_config.masterKey.resize(16);  // Too short (128-bit instead of 256-bit)
    m_config.requireStrongKeys = true;

    DatabaseError err;
    EXPECT_FALSE(ConfigurationDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(err.HasError());
}

TEST_F(ConfigurationDBTest, DoubleInitializeSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(ConfigurationDB::Instance().IsInitialized());
}

TEST_F(ConfigurationDBTest, ShutdownClearsInitializedFlag) {
    EXPECT_TRUE(InitializeConfigDB());
    EXPECT_TRUE(ConfigurationDB::Instance().IsInitialized());

    ConfigurationDB::Instance().Shutdown();

    EXPECT_FALSE(ConfigurationDB::Instance().IsInitialized());
}

// ============================================================================
// Basic Set/Get Operations Tests
// ============================================================================

TEST_F(ConfigurationDBTest, SetAndGetStringSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetString(L"test.string", L"Hello World",
        ConfigurationDB::ConfigScope::Global, L"TestUser", &err));

    auto value = ConfigurationDB::Instance().GetString(L"test.string", L"", &err);
    EXPECT_EQ(value, L"Hello World");
}

TEST_F(ConfigurationDBTest, SetAndGetIntegerSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetInt(L"test.int", 42,
        ConfigurationDB::ConfigScope::Global, L"TestUser", &err));

    auto value = ConfigurationDB::Instance().GetInt(L"test.int", 0, &err);
    EXPECT_EQ(value, 42);
}

TEST_F(ConfigurationDBTest, SetAndGetDoubleSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetDouble(L"test.double", 3.14159,
        ConfigurationDB::ConfigScope::Global, L"TestUser", &err));

    auto value = ConfigurationDB::Instance().GetDouble(L"test.double", 0.0, &err);
    EXPECT_NEAR(value, 3.14159, 0.00001);
}

TEST_F(ConfigurationDBTest, SetAndGetBooleanSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetBool(L"test.bool", true,
        ConfigurationDB::ConfigScope::Global, L"TestUser", &err));

    auto value = ConfigurationDB::Instance().GetBool(L"test.bool", false, &err);
    EXPECT_TRUE(value);
}

TEST_F(ConfigurationDBTest, SetAndGetJsonSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    ShadowStrike::Utils::JSON::Json jsonValue;
    jsonValue["name"] = "Test";
    jsonValue["value"] = 123;
    jsonValue["enabled"] = true;

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetJson(L"test.json", jsonValue,
        ConfigurationDB::ConfigScope::Global, L"TestUser", &err));

    auto retrieved = ConfigurationDB::Instance().GetJson(L"test.json", {}, &err);
    EXPECT_EQ(retrieved["name"].get<std::string>(), "Test");
    EXPECT_EQ(retrieved["value"].get<int64_t>(), 123);
    EXPECT_TRUE(retrieved["enabled"].is_boolean());
    EXPECT_TRUE(retrieved["enabled"]); 
}

TEST_F(ConfigurationDBTest, GetNonExistentKeyReturnsDefault) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    auto value = ConfigurationDB::Instance().GetString(L"nonexistent.key", L"default", &err);
    EXPECT_EQ(value, L"default");
}

TEST_F(ConfigurationDBTest, ContainsReturnsTrueForExistingKey) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"exists.key", L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    EXPECT_TRUE(ConfigurationDB::Instance().Contains(L"exists.key"));
    EXPECT_FALSE(ConfigurationDB::Instance().Contains(L"nonexistent.key"));
}

// ============================================================================
// Hierarchical Keys Tests
// ============================================================================

TEST_F(ConfigurationDBTest, HierarchicalKeysWork) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"network.proxy.host", L"proxy.example.com",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetInt(L"network.proxy.port", 8080,
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetBool(L"network.proxy.enabled", true,
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"network.proxy.host"), L"proxy.example.com");
    EXPECT_EQ(ConfigurationDB::Instance().GetInt(L"network.proxy.port"), 8080);
    EXPECT_TRUE(ConfigurationDB::Instance().GetBool(L"network.proxy.enabled"));
}

TEST_F(ConfigurationDBTest, GetKeysByPrefixWorks) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"app.feature1.enabled", L"true",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"app.feature2.enabled", L"false",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"app.version", L"1.0",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"network.timeout", L"30",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    auto keys = ConfigurationDB::Instance().GetKeysByPrefix(L"app.", std::nullopt, 100, &err);

    EXPECT_GE(keys.size(), 3);
    for (const auto& key : keys) {
        EXPECT_EQ(key.substr(0, 4), L"app.");
    }
}

// ============================================================================
// Scope Tests
// ============================================================================

TEST_F(ConfigurationDBTest, DifferentScopesWork) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"test", L"system",
        ConfigurationDB::ConfigScope::System, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"test2", L"global",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"test3", L"agent",
        ConfigurationDB::ConfigScope::Agent, L"Test", &err);

    auto allKeys = ConfigurationDB::Instance().GetAllKeys(std::nullopt, &err);
    EXPECT_GE(allKeys.size(), 3);

    auto systemKeys = ConfigurationDB::Instance().GetAllKeys(ConfigurationDB::ConfigScope::System, &err);
    EXPECT_GE(systemKeys.size(), 1);
}

// ============================================================================
// Update/Remove Operations Tests
// ============================================================================

TEST_F(ConfigurationDBTest, UpdateExistingKeySucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"update.test", L"original",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"update.test"), L"original");

    ConfigurationDB::Instance().SetString(L"update.test", L"updated",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"update.test"), L"updated");
}

TEST_F(ConfigurationDBTest, RemoveKeySucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"remove.test", L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    EXPECT_TRUE(ConfigurationDB::Instance().Contains(L"remove.test"));

    EXPECT_TRUE(ConfigurationDB::Instance().Remove(L"remove.test", L"Test", L"Testing remove", &err));

    EXPECT_FALSE(ConfigurationDB::Instance().Contains(L"remove.test"));
}

TEST_F(ConfigurationDBTest, RemoveNonExistentKeyFails) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_FALSE(ConfigurationDB::Instance().Remove(L"nonexistent", L"Test", L"", &err));
}

// ============================================================================
// Encryption Tests
// ============================================================================

TEST_F(ConfigurationDBTest, EncryptAndDecryptSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"secret.password", L"SuperSecretPassword123!",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    // Encrypt
    EXPECT_TRUE(ConfigurationDB::Instance().Encrypt(L"secret.password", L"Test", &err));
    EXPECT_TRUE(ConfigurationDB::Instance().IsEncrypted(L"secret.password"));

    // Decrypt
    EXPECT_TRUE(ConfigurationDB::Instance().Decrypt(L"secret.password", L"Test", &err));
    EXPECT_FALSE(ConfigurationDB::Instance().IsEncrypted(L"secret.password"));

    // Value should be intact
    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"secret.password"), L"SuperSecretPassword123!");
}

TEST_F(ConfigurationDBTest, EncryptValueDirectlySucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    std::wstring plaintext = L"Sensitive Data";

    auto encrypted = ConfigurationDB::Instance().EncryptValue(plaintext, &err);
    EXPECT_FALSE(encrypted.empty());
    EXPECT_FALSE(err.HasError());

    auto decrypted = ConfigurationDB::Instance().DecryptValue(encrypted, &err);
    EXPECT_EQ(decrypted, plaintext);
}

// ============================================================================
// Batch Operations Tests
// ============================================================================

TEST_F(ConfigurationDBTest, SetBatchSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    std::vector<std::pair<std::wstring, ConfigurationDB::ConfigValue>> batch; //-V827
    batch.emplace_back(L"batch.key1", std::wstring(L"value1"));
    batch.emplace_back(L"batch.key2", int64_t(42));
    batch.emplace_back(L"batch.key3", true);

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetBatch(batch,
        ConfigurationDB::ConfigScope::Global, L"Test", &err));

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"batch.key1"), L"value1");
    EXPECT_EQ(ConfigurationDB::Instance().GetInt(L"batch.key2"), 42);
    EXPECT_TRUE(ConfigurationDB::Instance().GetBool(L"batch.key3"));
}

TEST_F(ConfigurationDBTest, GetBatchSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"get1", L"value1",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetInt(L"get2", 123,
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    std::vector<std::wstring> keys = { L"get1", L"get2", L"nonexistent" };
    auto results = ConfigurationDB::Instance().GetBatch(keys, &err);

    EXPECT_EQ(results.size(), 2);  // nonexistent not in results
    EXPECT_TRUE(results.find(L"get1") != results.end());
    EXPECT_TRUE(results.find(L"get2") != results.end());
}

TEST_F(ConfigurationDBTest, RemoveBatchSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"del1", L"value1",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"del2", L"value2",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    std::vector<std::wstring> keys = { L"del1", L"del2" };
    EXPECT_TRUE(ConfigurationDB::Instance().RemoveBatch(keys, L"Test", &err));

    EXPECT_FALSE(ConfigurationDB::Instance().Contains(L"del1"));
    EXPECT_FALSE(ConfigurationDB::Instance().Contains(L"del2"));
}

// ============================================================================
// Versioning & History Tests
// ============================================================================

TEST_F(ConfigurationDBTest, VersioningTracksChanges) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"version.test", L"v1",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"version.test", L"v2",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"version.test", L"v3",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    auto history = ConfigurationDB::Instance().GetHistory(L"version.test", 10, &err);

    EXPECT_GE(history.size(), 2);  // At least 2 versions in history
}

TEST_F(ConfigurationDBTest, RollbackRestoresPreviousVersion) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"rollback.test", L"original",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    auto entry1 = ConfigurationDB::Instance().GetEntry(L"rollback.test", &err);
    ASSERT_TRUE(entry1.has_value());
    int version1 = entry1->version;

    ConfigurationDB::Instance().SetString(L"rollback.test", L"modified",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    // Rollback to version 1
    EXPECT_TRUE(ConfigurationDB::Instance().Rollback(L"rollback.test", version1, L"Test", &err));

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"rollback.test"), L"original");
}

TEST_F(ConfigurationDBTest, GetChangeHistoryWorks) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"change.test", L"v1",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetString(L"change.test", L"v2",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().Remove(L"change.test", L"Test", L"Cleanup", &err);

    auto changes = ConfigurationDB::Instance().GetChangeHistory(
        L"change.test", std::nullopt, 100, &err);

    EXPECT_GE(changes.size(), 2);  // At least modify + delete
}

// ============================================================================
// Validation Tests
// ============================================================================

TEST_F(ConfigurationDBTest, ValidationRuleEnforcesType) {
    EXPECT_TRUE(InitializeConfigDB());

    
    ConfigurationDB::Instance().SetEnforceValidation(true);

    // REGISTER RULE
    ConfigurationDB::ValidationRule rule;
    rule.key = L"validated.int";
    rule.expectedType = ConfigurationDB::ValueType::Integer;
    rule.required = true;

    EXPECT_TRUE(ConfigurationDB::Instance().RegisterValidationRule(rule));

    DatabaseError err;
    // This should NOW fail validation!
    EXPECT_FALSE(ConfigurationDB::Instance().SetString(L"validated.int", L"not_an_int",
        ConfigurationDB::ConfigScope::Global, L"Test", &err));
}

TEST_F(ConfigurationDBTest, ValidationRuleEnforcesRange) {
    EXPECT_TRUE(InitializeConfigDB());

    ConfigurationDB::ValidationRule rule;
    rule.key = L"validated.range";
    rule.expectedType = ConfigurationDB::ValueType::Integer;
    rule.minInt = 0;
    rule.maxInt = 100;

    EXPECT_TRUE(ConfigurationDB::Instance().RegisterValidationRule(rule));

    std::wstring errorMsg;
    ConfigurationDB::ConfigValue validValue = int64_t(50);
    EXPECT_TRUE(ConfigurationDB::Instance().Validate(L"validated.range", validValue, errorMsg));

    ConfigurationDB::ConfigValue invalidValue = int64_t(150);
    EXPECT_FALSE(ConfigurationDB::Instance().Validate(L"validated.range", invalidValue, errorMsg));
    EXPECT_FALSE(errorMsg.empty());
}

// ============================================================================
// Cache Tests
// ============================================================================

TEST_F(ConfigurationDBTest, CacheImprovesPerformance) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"cache.test", L"cached_value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    // First read (cache miss)
    auto stats1 = ConfigurationDB::Instance().GetStatistics();
    auto value1 = ConfigurationDB::Instance().GetString(L"cache.test");

    // Second read (cache hit)
    auto value2 = ConfigurationDB::Instance().GetString(L"cache.test");
    auto stats2 = ConfigurationDB::Instance().GetStatistics();

    EXPECT_EQ(value1, value2);
    EXPECT_GT(stats2.cacheHits, stats1.cacheHits);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(ConfigurationDBTest, StatisticsTrackOperations) {
    EXPECT_TRUE(InitializeConfigDB());

    auto stats1 = ConfigurationDB::Instance().GetStatistics();

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"stats.test", L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().GetString(L"stats.test");
    ConfigurationDB::Instance().Remove(L"stats.test", L"Test", L"", &err);

    auto stats2 = ConfigurationDB::Instance().GetStatistics();

    EXPECT_GT(stats2.totalWrites, stats1.totalWrites);
    EXPECT_GT(stats2.totalReads, stats1.totalReads);
    EXPECT_GT(stats2.totalDeletes, stats1.totalDeletes);
}

TEST_F(ConfigurationDBTest, ResetStatisticsWorks) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"test", L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    ConfigurationDB::Instance().ResetStatistics();

    auto stats = ConfigurationDB::Instance().GetStatistics();
    EXPECT_EQ(stats.totalWrites, 0);
    EXPECT_EQ(stats.totalReads, 0);
}

// ============================================================================
// Export/Import Tests
// ============================================================================

TEST_F(ConfigurationDBTest, ExportToJsonSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"export.test1", L"value1",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);
    ConfigurationDB::Instance().SetInt(L"export.test2", 42,
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    std::filesystem::path exportPath = m_basePath + L"\\export.json";
    EXPECT_TRUE(ConfigurationDB::Instance().ExportToJson(exportPath, std::nullopt, false, &err));

    EXPECT_TRUE(fs::exists(exportPath));
    EXPECT_GT(fs::file_size(exportPath), 0);
}

TEST_F(ConfigurationDBTest, ImportFromJsonSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    // Export first
    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"import.test", L"original",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    std::filesystem::path exportPath = m_basePath + L"\\import.json";
    EXPECT_TRUE(ConfigurationDB::Instance().ExportToJson(exportPath, std::nullopt, false, &err));

    // Clear and import
    ConfigurationDB::Instance().Remove(L"import.test", L"Test", L"", &err);
    EXPECT_FALSE(ConfigurationDB::Instance().Contains(L"import.test"));

    EXPECT_TRUE(ConfigurationDB::Instance().ImportFromJson(exportPath, true, L"Test", &err));
    EXPECT_TRUE(ConfigurationDB::Instance().Contains(L"import.test"));
    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"import.test"), L"original");
}

// ============================================================================
// Maintenance Tests
// ============================================================================

TEST_F(ConfigurationDBTest, VacuumSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().Vacuum(&err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(ConfigurationDBTest, CheckIntegritySucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().CheckIntegrity(&err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(ConfigurationDBTest, OptimizeSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().Optimize(&err));
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Edge Cases & Error Handling Tests
// ============================================================================

TEST_F(ConfigurationDBTest, EmptyKeyFails) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_FALSE(ConfigurationDB::Instance().SetString(L"", L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err));
    EXPECT_TRUE(err.HasError());
}

TEST_F(ConfigurationDBTest, VeryLongKeySucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    std::wstring longKey(1000, L'A');

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetString(longKey, L"value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err));

    EXPECT_EQ(ConfigurationDB::Instance().GetString(longKey), L"value");
}

TEST_F(ConfigurationDBTest, VeryLongValueSucceeds) {
    EXPECT_TRUE(InitializeConfigDB());

    std::wstring longValue(10000, L'X');

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetString(L"long.value", longValue,
        ConfigurationDB::ConfigScope::Global, L"Test", &err));

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"long.value"), longValue);
}

TEST_F(ConfigurationDBTest, UnicodeKeysAndValuesWork) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    EXPECT_TRUE(ConfigurationDB::Instance().SetString(L"测试.キー", L"Значение тест 🎉",
        ConfigurationDB::ConfigScope::Global, L"Test", &err));

    EXPECT_EQ(ConfigurationDB::Instance().GetString(L"测试.キー"), L"Значение тест 🎉");
}

// ============================================================================
// Concurrency Tests (Basic)
// ============================================================================

TEST_F(ConfigurationDBTest, ConcurrentWritesSucceed) {
    EXPECT_TRUE(InitializeConfigDB());

    std::atomic<int> successCount{ 0 };
    std::vector<std::thread> threads;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([i, &successCount]() {
            DatabaseError err;
            std::wstring key = L"concurrent." + std::to_wstring(i);
            if (ConfigurationDB::Instance().SetInt(key, i,
                ConfigurationDB::ConfigScope::Global, L"Test", &err)) {
                successCount++;
            }
            });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), 10);
}

TEST_F(ConfigurationDBTest, ConcurrentReadsSucceed) {
    EXPECT_TRUE(InitializeConfigDB());

    DatabaseError err;
    ConfigurationDB::Instance().SetString(L"concurrent.read", L"shared_value",
        ConfigurationDB::ConfigScope::Global, L"Test", &err);

    std::atomic<int> successCount{ 0 };
    std::vector<std::thread> threads;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&successCount]() {
            auto value = ConfigurationDB::Instance().GetString(L"concurrent.read");
            if (value == L"shared_value") {
                successCount++;
            }
            });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), 10);
}

// ============================================================================
// Performance Tests (Basic)
// ============================================================================

TEST_F(ConfigurationDBTest, BulkWritePerformance) {
    EXPECT_TRUE(InitializeConfigDB());

    auto start = std::chrono::steady_clock::now();

    DatabaseError err;
    for (int i = 0; i < 100; ++i) {
        std::wstring key = L"perf.key" + std::to_wstring(i);
        ConfigurationDB::Instance().SetString(key, L"value",
            ConfigurationDB::ConfigScope::Global, L"Test", &err);
    }

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time
    EXPECT_LT(duration.count(), 5000);  // < 5 seconds for 100 writes
}
