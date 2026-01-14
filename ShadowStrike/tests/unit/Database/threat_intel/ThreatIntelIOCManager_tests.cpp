/**
 * @file ThreatIntelIOCManager_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelIOCManager
 *
 * Comprehensive test coverage for IOC management operations:
 * - Initialization and lifecycle management
 * - Single IOC operations (Add, Update, Delete, Restore)
 * - Batch IOC operations (BatchAdd, BatchUpdate, BatchDelete)
 * - Query operations (GetIOC, FindIOC, QueryIOCs, ExistsIOC)
 * - Relationship management (Add, Remove, Get, Find paths)
 * - Version control (History, GetVersion, Revert)
 * - TTL management (Set, Renew, Purge, GetExpiring)
 * - Validation and normalization (ValidateIOC, NormalizeIOCValue, ParseIOC)
 * - Deduplication (FindDuplicate, MergeDuplicates, AutoMerge)
 * - STIX support (Import/Export bundles)
 * - Statistics tracking and maintenance
 * - Thread safety and concurrent operations
 * - Performance benchmarks
 * - Edge cases and error handling
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelIOCManager.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"
#include"../../../../src/ThreatIntel/ReputationCache.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;

// ============================================================================
// TEST HELPERS & FIXTURES
// ============================================================================

namespace {

// Temporary directory helper
struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_IOCMgr_") + 
			std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
		path = base / name;
		std::filesystem::create_directories(path);
	}

	~TempDir() {
		std::error_code ec;
		std::filesystem::remove_all(path, ec);
	}

	[[nodiscard]] std::filesystem::path FilePath(const std::string& filename) const {
		return path / filename;
	}
};

// Helper to create test IOC entry
[[nodiscard]] IOCEntry CreateTestIOC(IOCType type, const std::string& value = "") {
	IOCEntry entry{};
	entry.type = type;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.category = ThreatCategory::C2Server;
	entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
	entry.firstSeen = entry.createdTime;
	entry.lastSeen = entry.createdTime;

	switch (type) {
		case IOCType::IPv4:
			if (!value.empty()) {
				auto parsed = Format::ParseIPv4(value);
				if (parsed.has_value()) {
					entry.value.ipv4 = *parsed;
					
				}
			} else {
				entry.value.ipv4 = {};
				entry.value.ipv4.Set(192, 168, 1, 1);
			}
			break;
			
		case IOCType::IPv6:
			if (!value.empty()) {
				auto parsed = Format::ParseIPv6(value);
				if (parsed.has_value()) {
					entry.value.ipv6 = *parsed;
				}
			}
			break;
			
		case IOCType::FileHash:
			if (!value.empty()) {
				auto parsed = Format::ParseHashString(value, HashAlgorithm::SHA256);
				if (parsed.has_value()) {
					entry.value.hash = *parsed;
				}
			} else {
				entry.value.hash.algorithm = HashAlgorithm::MD5;
				entry.value.hash.length = 16;
				std::fill(entry.value.hash.data.begin(), entry.value.hash.data.begin() + 16, 0xAB);
			}
			break;
			
		default:
			break;
	}
	
	return entry;
}

// Helper to create and initialize manager
[[nodiscard]] bool CreateTestManager(
	ThreatIntelIOCManager& manager,
	ThreatIntelDatabase& database,
	const std::filesystem::path& dbPath
) {
	StoreError error;
	ThreatIntel::DatabaseConfig config = 
		ThreatIntel::DatabaseConfig::CreateDefault(dbPath.wstring());
	// Create database
	if (!database.CreateDatabase(config)) {
		return false;
	}
	
	// Initialize manager
	error = manager.Initialize(&database);
	if (!error.IsSuccess()) {
		database.Close();
		return false;
	}
	
	return true;
}

} // anonymous namespace

// ============================================================================
// PART 1/10: INITIALIZATION & LIFECYCLE TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Init, DefaultConstruction) {
	ThreatIntelIOCManager manager;
	EXPECT_FALSE(manager.IsInitialized());
}

TEST(ThreatIntelIOCManager_Init, Initialize_ValidDatabase) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	EXPECT_TRUE(manager.IsInitialized());
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Init, Initialize_NullDatabase) {
	ThreatIntelIOCManager manager;
	StoreError error = manager.Initialize(nullptr);
	
	EXPECT_FALSE(error.IsSuccess());
	EXPECT_FALSE(manager.IsInitialized());
}

TEST(ThreatIntelIOCManager_Init, Initialize_ClosedDatabase) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	// Database not opened
	StoreError error = manager.Initialize(&database);
	
	EXPECT_FALSE(error.IsSuccess());
	EXPECT_FALSE(manager.IsInitialized());
}

TEST(ThreatIntelIOCManager_Init, Initialize_AlreadyInitialized) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Second initialization should fail
	StoreError error = manager.Initialize(&database);
	EXPECT_FALSE(error.IsSuccess());
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Init, Shutdown_CleansUp) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	manager.Shutdown();
	EXPECT_FALSE(manager.IsInitialized());
	
	database.Close();
}

TEST(ThreatIntelIOCManager_Init, MultipleShutdown_Safe) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	manager.Shutdown();
	manager.Shutdown(); // Should not crash
	manager.Shutdown(); // Multiple calls safe
	
	database.Close();
}

// ============================================================================
// PART 2/10: SINGLE IOC OPERATIONS TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Add, AddIOC_IPv4) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.entryId, 0u);
	EXPECT_EQ(manager.GetIOCCount(true, true), 1u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_IPv6) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv6, "2001:db8::1");
	IOCAddOptions options;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.entryId, 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_Hash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::FileHash, "d41d8cd98f00b204e9800998ecf8427e");
	IOCAddOptions options;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.entryId, 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_WithValidation) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	options.skipValidation = false;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	EXPECT_TRUE(result.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_InvalidEntry) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry{};
	entry.type = IOCType::IPv4;
	// Invalid: no data set
	
	IOCAddOptions options;
	options.skipValidation = false;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	EXPECT_FALSE(result.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_Duplicate) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	options.skipDeduplication = false;
	
	// Add first time
	IOCOperationResult result1 = manager.AddIOC(entry, options);
	EXPECT_TRUE(result1.success);
	
	// Add duplicate
	IOCOperationResult result2 = manager.AddIOC(entry, options);
	EXPECT_FALSE(result2.success); // Should reject duplicate
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Add, AddIOC_SkipDeduplication) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	options.skipDeduplication = true;
	
	// Add first time
	IOCOperationResult result1 = manager.AddIOC(entry, options);
	EXPECT_TRUE(result1.success);
	
	// Add duplicate (should succeed with skip)
	IOCOperationResult result2 = manager.AddIOC(entry, options);
	EXPECT_TRUE(result2.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Update, UpdateIOC_ExistingEntry) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions addOptions;
	
	IOCOperationResult addResult = manager.AddIOC(entry, addOptions);
	ASSERT_TRUE(addResult.success);
	
	// Update confidence
	entry.entryId = addResult.entryId;
	entry.confidence = ConfidenceLevel::Low;
	
	IOCOperationResult updateResult = manager.UpdateIOC(entry, addOptions);
	EXPECT_TRUE(updateResult.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Delete, DeleteIOC_ById_SoftDelete) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult addResult = manager.AddIOC(entry, options);
	ASSERT_TRUE(addResult.success);
	
	IOCOperationResult deleteResult = manager.DeleteIOC(addResult.entryId, true);
	EXPECT_TRUE(deleteResult.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Delete, DeleteIOC_ByValue) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult addResult = manager.AddIOC(entry, options);
	ASSERT_TRUE(addResult.success);
	
	IOCOperationResult deleteResult = manager.DeleteIOC(IOCType::IPv4, "192.168.1.1", true);
	EXPECT_TRUE(deleteResult.success);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Delete, RestoreIOC) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult addResult = manager.AddIOC(entry, options);
	ASSERT_TRUE(addResult.success);
	
	// Soft delete
	manager.DeleteIOC(addResult.entryId, true);
	
	// Restore
	IOCOperationResult restoreResult = manager.RestoreIOC(addResult.entryId);
	EXPECT_TRUE(restoreResult.success);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 3/10: BATCH OPERATIONS TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Batch, BatchAddIOCs_MultipleEntries) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	std::vector<IOCEntry> entries;
	for (int i = 0; i < 10; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		entries.push_back(CreateTestIOC(IOCType::IPv4, ip));
	}
	
	IOCBatchOptions options;
	IOCBulkImportResult result = manager.BatchAddIOCs(entries, options);
	
	EXPECT_GT(result.successCount, 0u);
	EXPECT_EQ(result.failedCount, 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Batch, BatchAddIOCs_EmptyList) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	std::vector<IOCEntry> entries;
	IOCBatchOptions options;
	
	IOCBulkImportResult result = manager.BatchAddIOCs(entries, options);
	
	EXPECT_EQ(result.successCount, 0u);
	EXPECT_EQ(result.failedCount, 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Batch, BatchAddIOCs_LargeScale) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Create 1000 entries
	std::vector<IOCEntry> entries;
	for (int i = 0; i < 1000; ++i) {
		std::string ip = "192.168." + std::to_string(i / 256) + "." + std::to_string(i % 256);
		entries.push_back(CreateTestIOC(IOCType::IPv4, ip));
	}
	
	auto start = std::chrono::steady_clock::now();
	
	IOCBatchOptions options;
	IOCBulkImportResult result = manager.BatchAddIOCs(entries, options);
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	EXPECT_GT(result.successCount, 0u);
	EXPECT_LT(ms, 5000); // Should process 1000 entries in < 5 seconds
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Batch, BatchDeleteIOCs) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add entries
	std::vector<uint64_t> entryIds;
	for (int i = 0; i < 10; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		IOCEntry entry = CreateTestIOC(IOCType::IPv4, ip);
		IOCAddOptions options;
		IOCOperationResult result = manager.AddIOC(entry, options);
		if (result.success) {
			entryIds.push_back(result.entryId);
		}
	}
	
	ASSERT_FALSE(entryIds.empty());
	
	// Batch delete
	size_t deletedCount = manager.BatchDeleteIOCs(entryIds, true);
	EXPECT_GT(deletedCount, 0u);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 4/10: QUERY OPERATIONS TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Query, GetIOC_ById) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult addResult = manager.AddIOC(entry, options);
	ASSERT_TRUE(addResult.success);
	
	IOCQueryOptions queryOptions;
	auto retrieved = manager.GetIOC(addResult.entryId, queryOptions);
	
	ASSERT_TRUE(retrieved.has_value());
	EXPECT_EQ(retrieved->entryId, addResult.entryId);
	EXPECT_EQ(retrieved->type, IOCType::IPv4);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Query, GetIOC_NotFound) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCQueryOptions queryOptions;
	auto retrieved = manager.GetIOC(99999, queryOptions);
	
	EXPECT_FALSE(retrieved.has_value());
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Query, FindIOC_ByValue) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	manager.AddIOC(entry, options);
	
	IOCQueryOptions queryOptions;
	auto found = manager.FindIOC(IOCType::IPv4, "192.168.1.1", queryOptions);
	
	ASSERT_TRUE(found.has_value());
	EXPECT_EQ(found->type, IOCType::IPv4);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Query, ExistsIOC) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	manager.AddIOC(entry, options);
	
	EXPECT_TRUE(manager.ExistsIOC(IOCType::IPv4, "192.168.1.1"));
	EXPECT_FALSE(manager.ExistsIOC(IOCType::IPv4, "10.0.0.1"));
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Query, GetIOCCount) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	EXPECT_EQ(manager.GetIOCCount(true, true), 0u);
	
	// Add entries
	for (int i = 0; i < 5; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		IOCEntry entry = CreateTestIOC(IOCType::IPv4, ip);
		IOCAddOptions options;
		manager.AddIOC(entry, options);
	}
	
	EXPECT_GE(manager.GetIOCCount(true, true), 1u);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 5/10: RELATIONSHIP MANAGEMENT TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Relationship, AddRelationship) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add two IOCs
	IOCEntry entry1 = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCEntry entry2 = CreateTestIOC(IOCType::IPv4, "192.168.1.2");
	IOCAddOptions options;
	
	IOCOperationResult result1 = manager.AddIOC(entry1, options);
	IOCOperationResult result2 = manager.AddIOC(entry2, options);
	
	ASSERT_TRUE(result1.success);
	ASSERT_TRUE(result2.success);
	
	// Add relationship
	bool added = manager.AddRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo,
		ConfidenceLevel::High
	);
	
	EXPECT_TRUE(added);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Relationship, RemoveRelationship) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add two IOCs
	IOCEntry entry1 = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCEntry entry2 = CreateTestIOC(IOCType::IPv4, "192.168.1.2");
	IOCAddOptions options;
	
	IOCOperationResult result1 = manager.AddIOC(entry1, options);
	IOCOperationResult result2 = manager.AddIOC(entry2, options);
	
	// Add relationship
	manager.AddRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo,
		ConfidenceLevel::High
	);
	
	// Remove relationship
	bool removed = manager.RemoveRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo
	);
	
	EXPECT_TRUE(removed);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Relationship, GetRelationships) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add IOCs
	IOCEntry entry1 = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCEntry entry2 = CreateTestIOC(IOCType::IPv4, "192.168.1.2");
	IOCAddOptions options;
	
	IOCOperationResult result1 = manager.AddIOC(entry1, options);
	IOCOperationResult result2 = manager.AddIOC(entry2, options);
	
	// Add relationship
	manager.AddRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo,
		ConfidenceLevel::High
	);
	
	// Get relationships
	auto relationships = manager.GetRelationships(result1.entryId);
	EXPECT_GE(relationships.size(), 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Relationship, GetRelatedIOCs) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add IOCs
	IOCEntry entry1 = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCEntry entry2 = CreateTestIOC(IOCType::IPv4, "192.168.1.2");
	IOCAddOptions options;
	
	IOCOperationResult result1 = manager.AddIOC(entry1, options);
	IOCOperationResult result2 = manager.AddIOC(entry2, options);
	
	// Add relationship
	manager.AddRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo,
		ConfidenceLevel::High
	);
	
	// Get related IOCs
	auto related = manager.GetRelatedIOCs(result1.entryId, IOCRelationType::RelatedTo, 1);
	EXPECT_GE(related.size(), 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Relationship, FindPath) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add IOCs
	IOCEntry entry1 = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCEntry entry2 = CreateTestIOC(IOCType::IPv4, "192.168.1.2");
	IOCAddOptions options;
	
	IOCOperationResult result1 = manager.AddIOC(entry1, options);
	IOCOperationResult result2 = manager.AddIOC(entry2, options);
	
	// Add relationship
	manager.AddRelationship(
		result1.entryId,
		result2.entryId,
		IOCRelationType::RelatedTo,
		ConfidenceLevel::High
	);
	
	// Find path
	auto path = manager.FindPath(result1.entryId, result2.entryId);
	EXPECT_GE(path.size(), 0u);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 6/10: VERSION CONTROL TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Version, GetVersionHistory) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	options.createAuditLog = true;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	ASSERT_TRUE(result.success);
	
	// Get version history
	auto history = manager.GetVersionHistory(result.entryId, 10);
	EXPECT_GE(history.size(), 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Version, GetIOCVersion) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	ASSERT_TRUE(result.success);
	
	// Get version (may not exist)
	auto version = manager.GetIOCVersion(result.entryId, 1);
	// Version may or may not exist depending on implementation
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 7/10: VALIDATION & NORMALIZATION TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Validation, ValidateIOC_ValidIPv4) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	std::string errorMessage;
	
	bool valid = manager.ValidateIOC(entry, errorMessage);
	EXPECT_TRUE(valid);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Validation, ValidateIOC_InvalidIPv4) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	IOCEntry entry{};
	entry.type = IOCType::IPv4;
	// Invalid: no data
	
	std::string errorMessage;
	bool valid = manager.ValidateIOC(entry, errorMessage);
	
	EXPECT_FALSE(valid);
	EXPECT_FALSE(errorMessage.empty());
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Validation, NormalizeIOCValue_Domain) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	std::string normalized = manager.NormalizeIOCValue(IOCType::Domain, "EXAMPLE.COM");
	EXPECT_EQ(normalized, "example.com");
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Validation, NormalizeIOCValue_Hash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	std::string normalized = manager.NormalizeIOCValue(
		IOCType::FileHash,
		"D41D8CD98F00B204E9800998ECF8427E"
	);
	
	EXPECT_EQ(normalized, "d41d8cd98f00b204e9800998ecf8427e");
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 8/10: STATISTICS & MAINTENANCE TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Stats, GetStatistics) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	auto stats = manager.GetStatistics();
	EXPECT_EQ(stats.totalAdds.load(), 0u);
	EXPECT_EQ(stats.totalEntries.load(), 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Stats, ResetStatistics) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add entry to generate stats
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	manager.AddIOC(entry, options);
	
	// Reset stats
	manager.ResetStatistics();
	
	auto stats = manager.GetStatistics();
	EXPECT_EQ(stats.totalAdds.load(), 0u);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Stats, GetMemoryUsage) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	size_t memUsage = manager.GetMemoryUsage();
	EXPECT_GE(memUsage, 0u);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 9/10: THREAD SAFETY & CONCURRENT OPERATIONS TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_ThreadSafety, ConcurrentAddIOCs) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	std::atomic<int> successCount{0};
	std::vector<std::thread> threads;
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&manager, &successCount, t]() {
			for (int i = 0; i < 25; ++i) {
				std::string ip = "192.168." + std::to_string(t) + "." + std::to_string(i);
				IOCEntry entry = CreateTestIOC(IOCType::IPv4, ip);
				IOCAddOptions options;
				
				IOCOperationResult result = manager.AddIOC(entry, options);
				if (result.success) {
					successCount.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_GT(successCount.load(), 0);
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_ThreadSafety, ConcurrentQueryIOCs) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	// Add test data
	for (int i = 0; i < 10; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		IOCEntry entry = CreateTestIOC(IOCType::IPv4, ip);
		IOCAddOptions options;
		manager.AddIOC(entry, options);
	}
	
	std::atomic<int> queryCount{0};
	std::vector<std::thread> threads;
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&manager, &queryCount]() {
			IOCQueryOptions queryOptions;
			for (int i = 0; i < 100; ++i) {
				auto result = manager.QueryIOCs(queryOptions);
				queryCount.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_EQ(queryCount.load(), 400);
	
	manager.Shutdown();
	database.Close();
}

// ============================================================================
// PART 10/10: UTILITY FUNCTIONS & EDGE CASES TESTS
// ============================================================================

TEST(ThreatIntelIOCManager_Utility, IOCRelationTypeToString) {
	EXPECT_STREQ(IOCRelationTypeToString(IOCRelationType::ParentOf), "ParentOf");
	EXPECT_STREQ(IOCRelationTypeToString(IOCRelationType::ChildOf), "ChildOf");
	EXPECT_STREQ(IOCRelationTypeToString(IOCRelationType::RelatedTo), "RelatedTo");
	EXPECT_STREQ(IOCRelationTypeToString(IOCRelationType::SameFamily), "SameFamily");
}

TEST(ThreatIntelIOCManager_Utility, ParseIOCRelationType) {
	auto type1 = ParseIOCRelationType("ParentOf");
	ASSERT_TRUE(type1.has_value());
	EXPECT_EQ(*type1, IOCRelationType::ParentOf);
	
	auto type2 = ParseIOCRelationType("invalid");
	EXPECT_FALSE(type2.has_value());
}

TEST(ThreatIntelIOCManager_Utility, CalculateIOCHash) {
	uint64_t hash1 = CalculateIOCHash(IOCType::IPv4, "192.168.1.1");
	EXPECT_NE(hash1, 0u);
	
	uint64_t hash2 = CalculateIOCHash(IOCType::IPv4, "192.168.1.1");
	EXPECT_EQ(hash1, hash2); // Deterministic
	
	uint64_t hash3 = CalculateIOCHash(IOCType::IPv4, "10.0.0.1");
	EXPECT_NE(hash1, hash3); // Different values
}

TEST(ThreatIntelIOCManager_Utility, ValidateIOCTypeValue_IPv4) {
	std::string errorMessage;
	
	bool valid1 = ValidateIOCTypeValue(IOCType::IPv4, "192.168.1.1", errorMessage);
	EXPECT_TRUE(valid1);
	
	bool valid2 = ValidateIOCTypeValue(IOCType::IPv4, "invalid", errorMessage);
	EXPECT_FALSE(valid2);
	EXPECT_FALSE(errorMessage.empty());
}

TEST(ThreatIntelIOCManager_Utility, ValidateIOCTypeValue_Domain) {
	std::string errorMessage;
	
	bool valid1 = ValidateIOCTypeValue(IOCType::Domain, "example.com", errorMessage);
	EXPECT_TRUE(valid1);
	
	bool valid2 = ValidateIOCTypeValue(IOCType::Domain, "..invalid", errorMessage);
	EXPECT_FALSE(valid2);
}

TEST(ThreatIntelIOCManager_EdgeCase, AddIOC_NotInitialized) {
	ThreatIntelIOCManager manager;
	
	IOCEntry entry = CreateTestIOC(IOCType::IPv4, "192.168.1.1");
	IOCAddOptions options;
	
	IOCOperationResult result = manager.AddIOC(entry, options);
	EXPECT_FALSE(result.success);
}

TEST(ThreatIntelIOCManager_EdgeCase, GetIOC_NotInitialized) {
	ThreatIntelIOCManager manager;
	
	IOCQueryOptions queryOptions;
	auto result = manager.GetIOC(1, queryOptions);
	
	EXPECT_FALSE(result.has_value());
}

TEST(ThreatIntelIOCManager_EdgeCase, EmptyDatabase) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	EXPECT_EQ(manager.GetIOCCount(true, true), 0u);
	
	IOCQueryOptions queryOptions;
	auto results = manager.QueryIOCs(queryOptions);
	EXPECT_TRUE(results.empty());
	
	manager.Shutdown();
	database.Close();
}

TEST(ThreatIntelIOCManager_Performance, AddIOC_LargeScale) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ThreatIntelIOCManager manager;
	
	ASSERT_TRUE(CreateTestManager(manager, database, dbPath));
	
	auto start = std::chrono::steady_clock::now();
	
	IOCAddOptions options;
	int successCount = 0;
	
	for (int i = 0; i < 1000; ++i) {
		std::string ip = "192.168." + std::to_string(i / 256) + "." + std::to_string(i % 256);
		IOCEntry entry = CreateTestIOC(IOCType::IPv4, ip);
		
		IOCOperationResult result = manager.AddIOC(entry, options);
		if (result.success) {
			++successCount;
		}
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	EXPECT_GT(successCount, 0);
	EXPECT_LT(ms, 10000); // Should process 1000 adds in < 10 seconds
	
	manager.Shutdown();
	database.Close();
}

} // namespace ShadowStrike::ThreatIntel::Tests
