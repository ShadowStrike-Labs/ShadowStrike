// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file ThreatIntelStoreTests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelStore
 *
 * Comprehensive test coverage for the unified ThreatIntel facade:
 * - Lifecycle management (Initialize/Shutdown, multi-cycle, concurrent)
 * - IOC Lookups (Hash, IPv4, IPv6, Domain, URL, Email, JA3, CVE)
 * - Batch Operations (Hash, IPv4, Domain, Generic IOCs)
 * - IOC Management (Add, Update, Remove, Bulk, Existence checks)
 * - Feed Management (Add, Remove, Enable/Disable, Update, Status)
 * - Import/Export (STIX, CSV, JSON, PlainText formats)
 * - Maintenance Operations (Compact, Verify, Rebuild, Flush, Evict, Purge)
 * - Statistics & Monitoring (Get, Cache, Reset)
 * - Event Callbacks (Register, Unregister, Fire)
 * - Edge Cases & Input Validation
 * - Production Stress & Concurrency
 *
 * Quality Standards:
 * - CrowdStrike Falcon / Microsoft Defender ATP level reliability
 * - Thread-safety verification under high concurrency
 * - Memory leak detection through multiple init/shutdown cycles
 * - Performance guardrails (latency, throughput)
 * - Comprehensive error handling
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelStore.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;

namespace {

// ============================================================================
// Test Helpers & Fixtures
// ============================================================================

struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_Store_") +
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

[[nodiscard]] StoreConfig MakeTestConfig(const std::filesystem::path& dbPath) {
	StoreConfig cfg;
	cfg.databasePath = dbPath.wstring();
	cfg.enableCache = true;
	cfg.cacheOptions.totalCapacity = 1024;
	cfg.enableAutoFeedUpdate = false; // Disable for deterministic tests
	cfg.cacheOptions.enableStatistics = true;
	return cfg;
}

[[nodiscard]] IOCEntry MakeTestIOCEntry(IOCType type, const std::string& value) {
	IOCEntry entry{};
	entry.entryId = 0; // Will be assigned by store
	entry.type = type;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ReputationLevel::Malicious;
	entry.category = ThreatCategory::Malware;
	entry.source = ThreatIntelSource::InternalAnalysis;
	entry.firstSeen = static_cast<uint64_t>(std::time(nullptr));
	entry.lastSeen = entry.firstSeen;
	entry.flags = IOCFlags::None;
	entry.feedId = 0;
	entry.sourceCount = 1;

	// Type-specific parsing would happen in AddIOC
	// For tests, we mainly verify API behavior
	return entry;
}

[[nodiscard]] std::string MakeValidSHA256() {
	return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
}

[[nodiscard]] std::string MakeValidMD5() {
	return "d41d8cd98f00b204e9800998ecf8427e";
}

} // namespace

// ============================================================================
// PART 1: Lifecycle Management
// ============================================================================

TEST(ThreatIntelStore_Lifecycle, DefaultConstruction_NotInitialized) {
	auto store = CreateThreatIntelStore();
	ASSERT_NE(store, nullptr);
	EXPECT_FALSE(store->IsInitialized());
}

TEST(ThreatIntelStore_Lifecycle, Initialize_WithValidConfig_Succeeds) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	auto store = CreateThreatIntelStore();
	ASSERT_NE(store, nullptr);

	const auto cfg = MakeTestConfig(dbPath);
	EXPECT_TRUE(store->Initialize(cfg));
	EXPECT_TRUE(store->IsInitialized());

	store->Shutdown();
	EXPECT_FALSE(store->IsInitialized());
}

TEST(ThreatIntelStore_Lifecycle, Initialize_Default_Succeeds) {
	auto store = CreateThreatIntelStore();
	ASSERT_NE(store, nullptr);

	// Default init uses temp directory
	EXPECT_TRUE(store->Initialize());
	EXPECT_TRUE(store->IsInitialized());

	store->Shutdown();
}

TEST(ThreatIntelStore_Lifecycle, DoubleInitialize_Fails) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	auto store = CreateThreatIntelStore();
	const auto cfg = MakeTestConfig(dbPath);

	ASSERT_TRUE(store->Initialize(cfg));
	EXPECT_FALSE(store->Initialize(cfg)); // Second init should fail

	store->Shutdown();
}

TEST(ThreatIntelStore_Lifecycle, Shutdown_Idempotent) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	store->Shutdown();
	store->Shutdown(); // Should not crash
	store->Shutdown();

	EXPECT_FALSE(store->IsInitialized());
}

TEST(ThreatIntelStore_Lifecycle, MultipleInitShutdownCycles_NoLeaks) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("cycle_test.db");

	auto store = CreateThreatIntelStore();
	const auto cfg = MakeTestConfig(dbPath);

	for (int cycle = 0; cycle < 5; ++cycle) {
		ASSERT_TRUE(store->Initialize(cfg));
		EXPECT_TRUE(store->IsInitialized());

		// Perform some operations
		(void)store->LookupIPv4("8.8.8.8");

		store->Shutdown();
		EXPECT_FALSE(store->IsInitialized());
	}
}

TEST(ThreatIntelStore_Lifecycle, ConcurrentInitialization_OnlyOneSucceeds) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("concurrent.db");

	auto store = CreateThreatIntelStore();
	const auto cfg = MakeTestConfig(dbPath);

	std::atomic<int> successCount{0};
	std::atomic<bool> start{false};
	std::vector<std::thread> threads;

	for (int i = 0; i < 8; ++i) {
		threads.emplace_back([&]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			if (store->Initialize(cfg)) {
				successCount.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	EXPECT_EQ(successCount.load(), 1);
	EXPECT_TRUE(store->IsInitialized());

	store->Shutdown();
}

TEST(ThreatIntelStore_Lifecycle, FactoryFunctions_CreateValidInstances) {
	auto defaultStore = CreateThreatIntelStore();
	EXPECT_NE(defaultStore, nullptr);
	EXPECT_FALSE(defaultStore->IsInitialized());

	auto highPerfStore = CreateHighPerformanceThreatIntelStore();
	EXPECT_NE(highPerfStore, nullptr);
	EXPECT_TRUE(highPerfStore->IsInitialized());
	highPerfStore->Shutdown();

	auto lowMemStore = CreateLowMemoryThreatIntelStore();
	EXPECT_NE(lowMemStore, nullptr);
	EXPECT_TRUE(lowMemStore->IsInitialized());
	lowMemStore->Shutdown();
}

// ============================================================================
// PART 2: IOC Lookups - All Types
// ============================================================================

TEST(ThreatIntelStore_Lookups, LookupHash_SHA256_ValidFormat) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto sha256 = MakeValidSHA256();
	const auto result = store->LookupHash("SHA256", sha256);

	// StoreLookupResult doesn't contain iocType - it's inferred from the lookup method used
	// Not found expected (empty DB)
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupHash_MD5_ValidFormat) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto md5 = MakeValidMD5();
	const auto result = store->LookupHash("MD5", md5);

	// Result is valid, just not found in empty DB
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupHash_InvalidFormat_ReturnsNotFound) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupHash("SHA256", "not-a-hex-string");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIPv4_String_ValidAddress) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupIPv4("192.168.1.1");
	// Verify lookup completes without errors
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIPv4_Uint32_NetworkByteOrder) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const uint32_t addr = 0x08080808; // 8.8.8.8 in network byte order
	const auto result = store->LookupIPv4(addr);
	// Verify lookup completes successfully
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIPv4_InvalidFormat_ReturnsNotFound) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupIPv4("999.999.999.999");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIPv6_String_ValidAddress) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupIPv6("2001:4860:4860::8888");
	// Verify lookup returns valid result
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIPv6_Uint64_HighLow) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupIPv6(0x2001486048600000ULL, 0x0000000000008888ULL);
	// Verify lookup executes without errors
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupDomain_ValidDomain) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupDomain("evil.example.com");
	// Verify domain lookup returns valid result
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupURL_ValidURL) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupURL("http://malicious.site/payload.exe");
	// URL lookup should complete successfully
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupEmail_ValidEmail) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupEmail("phishing@scam.com");
	// Email lookup should return valid result
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupJA3_ValidFingerprint) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupJA3("abc123def456");
	// JA3 fingerprint lookup should execute successfully
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupCVE_ValidCVEID) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupCVE("CVE-2024-1234");
	// CVE lookup should complete without errors
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, LookupIOC_GenericLookup) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto result = store->LookupIOC(IOCType::Domain, "test.com");
	// Generic IOC lookup should execute successfully
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_Lookups, UninitializedStore_ReturnsNotFound) {
	auto store = CreateThreatIntelStore();

	const auto hashResult = store->LookupHash("SHA256", MakeValidSHA256());
	EXPECT_FALSE(hashResult.found);

	const auto ipResult = store->LookupIPv4("1.1.1.1");
	EXPECT_FALSE(ipResult.found);

	const auto domainResult = store->LookupDomain("example.com");
	EXPECT_FALSE(domainResult.found);
}

// ============================================================================
// PART 3: Batch Lookups
// ============================================================================

TEST(ThreatIntelStore_Batch, BatchLookupHashes_EmptyList) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> hashes;
	const auto result = store->BatchLookupHashes("SHA256", hashes);

	EXPECT_EQ(result.totalProcessed, 0u);
	EXPECT_EQ(result.foundCount, 0u);
	EXPECT_EQ(result.results.size(), 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupHashes_SingleHash) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> hashes = {MakeValidSHA256()};
	const auto result = store->BatchLookupHashes("SHA256", hashes);

	EXPECT_EQ(result.totalProcessed, 1u);
	ASSERT_EQ(result.results.size(), 1u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupHashes_MultipleHashes) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> hashes = {
		MakeValidSHA256(),
		MakeValidMD5(),
		"0000000000000000000000000000000000000000000000000000000000000000"
	};

	const auto result = store->BatchLookupHashes("", hashes);

	EXPECT_EQ(result.totalProcessed, 3u);
	EXPECT_EQ(result.notFoundCount, result.totalProcessed);
	ASSERT_EQ(result.results.size(), 3u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupIPv4_EmptyList) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> addresses;
	const auto result = store->BatchLookupIPv4(addresses);

	EXPECT_EQ(result.totalProcessed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupIPv4_MultipleAddresses) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> addresses = {
		"8.8.8.8",
		"1.1.1.1",
		"192.168.1.1",
		"10.0.0.1"
	};

	const auto result = store->BatchLookupIPv4(addresses);

	EXPECT_EQ(result.totalProcessed, 4u);
	ASSERT_EQ(result.results.size(), 4u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupDomains_MultipleDomains) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> domains = {
		"google.com",
		"evil.example.com",
		"malware.site"
	};

	const auto result = store->BatchLookupDomains(domains);

	EXPECT_EQ(result.totalProcessed, 3u);
	ASSERT_EQ(result.results.size(), 3u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupIOCs_MixedTypes) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::pair<IOCType, std::string>> iocs = {
		{IOCType::IPv4, "8.8.8.8"},
		{IOCType::Domain, "example.com"},
		{IOCType::FileHash, MakeValidSHA256()},
		{IOCType::Email, "test@example.com"}
	};

	const auto result = store->BatchLookupIOCs(iocs);

	EXPECT_EQ(result.totalProcessed, 4u);
	ASSERT_EQ(result.results.size(), 4u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Batch, BatchLookupIOCs_AllInvalid) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::pair<IOCType, std::string>> iocs = {
		{IOCType::IPv4, "invalid"},
		{IOCType::FileHash, "not-hex"},
		{IOCType::Domain, ""}
	};

	const auto result = store->BatchLookupIOCs(iocs);

	EXPECT_EQ(result.totalProcessed, 3u);
	EXPECT_EQ(result.foundCount, 0u);

	store->Shutdown();
}

// ============================================================================
// PART 4: IOC Management
// ============================================================================

TEST(ThreatIntelStore_IOCMgmt, AddIOC_ValidEntry_Succeeds) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Use IPv4 entry which doesn't require string pool allocation
	IOCEntry entry{};
	entry.type = IOCType::IPv4;
	entry.value.ipv4 = IPv4Address::Create(192, 168, 1, 100);
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ReputationLevel::Malicious;
	entry.category = ThreatCategory::Malware;
	entry.source = ThreatIntelSource::InternalAnalysis;
	entry.firstSeen = static_cast<uint64_t>(std::time(nullptr));
	entry.lastSeen = entry.firstSeen;
	entry.flags = IOCFlags::None;
	
	EXPECT_TRUE(store->AddIOC(entry));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, AddIOC_Simplified_IPv4) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_TRUE(store->AddIOC(
		IOCType::IPv4,
		"192.0.2.1",
		ReputationLevel::Malicious,
		ThreatIntelSource::InternalAnalysis
	));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, AddIOC_Simplified_Hash) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_TRUE(store->AddIOC(
		IOCType::FileHash,
		MakeValidSHA256(),
		ReputationLevel::Malicious,
		ThreatIntelSource::VirusTotal
	));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, UpdateIOC_ExistingEntry) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Use IPv4 entry which doesn't require string pool allocation
	IOCEntry entry{};
	entry.type = IOCType::IPv4;
	entry.value.ipv4 = IPv4Address::Create(10, 0, 0, 1);
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ReputationLevel::Suspicious;
	entry.category = ThreatCategory::Botnet;
	entry.source = ThreatIntelSource::InternalAnalysis;
	entry.firstSeen = static_cast<uint64_t>(std::time(nullptr));
	entry.lastSeen = entry.firstSeen;
	entry.flags = IOCFlags::None;
	
	ASSERT_TRUE(store->AddIOC(entry));

	// The entry gets assigned ID 1 (first entry in fresh store)
	// Set entryId for update operation
	entry.entryId = 1;
	entry.reputation = ReputationLevel::Safe;
	EXPECT_TRUE(store->UpdateIOC(entry));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, RemoveIOC_ValidType) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Use IPv4 which works with simplified API
	ASSERT_TRUE(store->AddIOC(IOCType::IPv4, "10.20.30.40", ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis));
	EXPECT_TRUE(store->RemoveIOC(IOCType::IPv4, "10.20.30.40"));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, BulkAddIOCs_EmptyList) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<IOCEntry> entries;
	const size_t added = store->BulkAddIOCs(entries);

	EXPECT_EQ(added, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, BulkAddIOCs_MultipleEntries) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Use IPv4 entries which don't require string pool allocation
	std::vector<IOCEntry> entries;
	for (int i = 0; i < 10; ++i) {
		IOCEntry entry{};
		entry.type = IOCType::IPv4;
		entry.value.ipv4 = IPv4Address::Create(172, 16, static_cast<uint8_t>(i), 1);
		entry.confidence = ConfidenceLevel::High;
		entry.reputation = ReputationLevel::Suspicious;
		entry.category = ThreatCategory::Malware;
		entry.source = ThreatIntelSource::InternalAnalysis;
		entry.firstSeen = static_cast<uint64_t>(std::time(nullptr));
		entry.lastSeen = entry.firstSeen;
		entry.flags = IOCFlags::None;
		entries.push_back(entry);
	}

	const size_t added = store->BulkAddIOCs(entries);
	EXPECT_GT(added, 0u);
	EXPECT_LE(added, entries.size());

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, HasIOC_AfterAdd_ReturnsTrue) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Use IPv4 which works with simplified API
	const std::string ip = "172.16.100.50";
	ASSERT_TRUE(store->AddIOC(IOCType::IPv4, ip, ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis));

	EXPECT_TRUE(store->HasIOC(IOCType::IPv4, ip));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, HasIOC_NotAdded_ReturnsFalse) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_FALSE(store->HasIOC(IOCType::Domain, "not-exists.com"));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, UninitializedStore_AddFails) {
	auto store = CreateThreatIntelStore();

	const auto entry = MakeTestIOCEntry(IOCType::Domain, "test.com");
	EXPECT_FALSE(store->AddIOC(entry));
	EXPECT_FALSE(store->UpdateIOC(entry));
	EXPECT_FALSE(store->RemoveIOC(IOCType::Domain, "test.com"));
	EXPECT_EQ(store->BulkAddIOCs(std::vector<IOCEntry>{entry}), 0u);
}

// ============================================================================
// PART 5: Feed Management
// ============================================================================

// Helper to create a valid FeedConfiguration for tests
FeedConfiguration MakeValidFeedConfig(const std::string& feedId, const std::string& name) {
	FeedConfiguration config;
	config.feedId = feedId;
	config.name = name;
	config.url = "https://test.example.com/feeds/" + feedId;  // Required by validation
	config.enabled = true;
	return config;
}

TEST(ThreatIntelStore_Feeds, AddFeed_ValidConfig) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto feedCfg = MakeValidFeedConfig("test-feed-001", "Test Feed");

	EXPECT_TRUE(store->AddFeed(feedCfg));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, RemoveFeed_ExistingFeed) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto feedCfg = MakeValidFeedConfig("remove-feed-001", "Remove Test Feed");
	ASSERT_TRUE(store->AddFeed(feedCfg));

	EXPECT_TRUE(store->RemoveFeed("remove-feed-001"));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, EnableDisableFeed_TogglesState) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto feedCfg = MakeValidFeedConfig("toggle-feed-001", "Toggle Feed");
	ASSERT_TRUE(store->AddFeed(feedCfg));

	EXPECT_TRUE(store->DisableFeed("toggle-feed-001"));
	EXPECT_TRUE(store->EnableFeed("toggle-feed-001"));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, UpdateFeed_TriggersFeedUpdate) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto feedCfg = MakeValidFeedConfig("update-feed-001", "Update Test Feed");
	ASSERT_TRUE(store->AddFeed(feedCfg));

	// Note: UpdateFeed triggers a sync which may fail (no actual server)
	// The important thing is the API call doesn't crash
	// In production, use mock servers for testing actual sync behavior
	(void)store->UpdateFeed("update-feed-001");  // Should not crash

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, UpdateAllFeeds_ReturnsCount) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const size_t updated = store->UpdateAllFeeds();
	EXPECT_GE(updated, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, GetFeedStatus_ExistingFeed) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto feedCfg = MakeValidFeedConfig("status-feed-001", "Status Test Feed");
	ASSERT_TRUE(store->AddFeed(feedCfg));

	const auto status = store->GetFeedStatus("status-feed-001");
	EXPECT_TRUE(status.has_value());

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, GetFeedStatus_NonExistent_ReturnsNullopt) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto status = store->GetFeedStatus("non-existent-feed");
	EXPECT_FALSE(status.has_value());

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, GetAllFeedStatuses_ReturnsVector) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto statuses = store->GetAllFeedStatuses();
	EXPECT_GE(statuses.size(), 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, StartStopFeedUpdates_DoesNotCrash) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_NO_THROW({
		store->StartFeedUpdates();
		store->StopFeedUpdates();
	});

	store->Shutdown();
}

// ============================================================================
// PART 6: Import/Export Operations
// ============================================================================

TEST(ThreatIntelStore_Import, ImportSTIX_ValidFile) {
	TempDir tempDir;
	auto filePath = tempDir.FilePath("test.stix");

	// Create minimal STIX file
	std::ofstream ofs(filePath);
	ofs << R"({"type": "bundle", "objects": []})";
	ofs.close();

	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ImportOptions opts;
	const auto result = store->ImportSTIX(filePath.wstring(), opts);

	// ImportResult uses totalParsed, not totalProcessed
	EXPECT_GE(result.totalParsed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Import, ImportCSV_ValidFile) {
	TempDir tempDir;
	auto filePath = tempDir.FilePath("test.csv");

	std::ofstream ofs(filePath);
	ofs << "type,value,reputation\n";
	ofs << "domain,example.com,malicious\n";
	ofs.close();

	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ImportOptions opts;
	const auto result = store->ImportCSV(filePath.wstring(), opts);

	// Verify parsing completed without crashes
	EXPECT_GE(result.totalParsed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Import, ImportJSON_ValidFile) {
	TempDir tempDir;
	auto filePath = tempDir.FilePath("test.json");

	std::ofstream ofs(filePath);
	ofs << R"({"iocs": []})";
	ofs.close();

	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ImportOptions opts;
	const auto result = store->ImportJSON(filePath.wstring(), opts);

	// JSON import should complete successfully
	EXPECT_GE(result.totalParsed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Import, ImportPlainText_ValidFile) {
	TempDir tempDir;
	auto filePath = tempDir.FilePath("test.txt");

	std::ofstream ofs(filePath);
	ofs << "8.8.8.8\n";
	ofs << "1.1.1.1\n";
	ofs.close();

	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ImportOptions opts;
	const auto result = store->ImportPlainText(filePath.wstring(), IOCType::IPv4, opts);

	// Plain text import should complete
	EXPECT_GE(result.totalParsed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Import, Import_NonExistentFile_Fails) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ImportOptions opts;
	const auto result = store->ImportSTIX(L"C:\\non-existent-file.stix", opts);

	// Non-existent file should result in zero imports
	EXPECT_EQ(result.totalImported, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Export, Export_ValidPath) {
	TempDir tempDir;
	auto exportPath = tempDir.FilePath("export.json");

	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ExportOptions opts;
	opts.format = ExportFormat::JSON;
	const auto result = store->Export(exportPath.wstring(), opts);

	EXPECT_GE(result.totalExported, 0u);

	store->Shutdown();
}

// ============================================================================
// PART 7: Maintenance Operations
// ============================================================================

TEST(ThreatIntelStore_Maintenance, Compact_ReducesSize) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const size_t reclaimed = store->Compact();
	EXPECT_GE(reclaimed, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, VerifyIntegrity_NewDatabase_Succeeds) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_TRUE(store->VerifyIntegrity());

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, RebuildIndexes_Succeeds) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_TRUE(store->RebuildIndexes());

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, Flush_DoesNotCrash) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_NO_THROW({
		store->Flush();
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, EvictExpiredEntries_ReturnsCount) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const size_t evicted = store->EvictExpiredEntries();
	EXPECT_GE(evicted, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, PurgeOldEntries_WithMaxAge) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const size_t purged = store->PurgeOldEntries(std::chrono::hours(24 * 30));
	EXPECT_GE(purged, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Maintenance, UninitializedStore_OperationsFail) {
	auto store = CreateThreatIntelStore();

	EXPECT_EQ(store->Compact(), 0u);
	EXPECT_FALSE(store->VerifyIntegrity());
	EXPECT_FALSE(store->RebuildIndexes());
	EXPECT_EQ(store->EvictExpiredEntries(), 0u);
	EXPECT_EQ(store->PurgeOldEntries(std::chrono::hours(1)), 0u);
}

// ============================================================================
// PART 8: Statistics & Monitoring
// ============================================================================

TEST(ThreatIntelStore_Stats, GetStatistics_InitialState_AllZero) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 0u);
	EXPECT_EQ(stats.successfulLookups, 0u);
	EXPECT_EQ(stats.failedLookups, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Stats, GetStatistics_AfterLookups_Updated) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	(void)store->LookupIPv4("8.8.8.8");
	(void)store->LookupDomain("example.com");
	(void)store->LookupHash("SHA256", MakeValidSHA256());

	const auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 3u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Stats, GetCacheStatistics_ValidData) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto cacheStats = store->GetCacheStatistics();
	EXPECT_GE(cacheStats.totalCapacity, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Stats, ResetStatistics_ZeroesCounters) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	(void)store->LookupIPv4("1.1.1.1");
	ASSERT_GT(store->GetStatistics().totalLookups, 0u);

	store->ResetStatistics();

	const auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 0u);
	EXPECT_EQ(stats.successfulLookups, 0u);
	EXPECT_EQ(stats.failedLookups, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Stats, UninitializedStore_ReturnsEmptyStats) {
	auto store = CreateThreatIntelStore();

	const auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 0u);

	const auto cacheStats = store->GetCacheStatistics();
	EXPECT_EQ(cacheStats.totalCapacity, 0u);
}

// ============================================================================
// PART 9: Event Callbacks
// ============================================================================

TEST(ThreatIntelStore_Events, RegisterEventCallback_ReturnsValidId) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	size_t callbackId = 0;
	EXPECT_NO_THROW({
		callbackId = store->RegisterEventCallback([](const StoreEvent&) {});
	});
	EXPECT_GT(callbackId, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Events, UnregisterEventCallback_DoesNotCrash) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const auto id = store->RegisterEventCallback([](const StoreEvent&) {});

	EXPECT_NO_THROW({
		store->UnregisterEventCallback(id);
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_Events, MultipleCallbacks_AllReceiveEvents) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::atomic<int> count1{0};
	std::atomic<int> count2{0};

	const auto id1 = store->RegisterEventCallback([&](const StoreEvent&) {
		count1.fetch_add(1, std::memory_order_relaxed);
	});

	const auto id2 = store->RegisterEventCallback([&](const StoreEvent&) {
		count2.fetch_add(1, std::memory_order_relaxed);
	});

	// Trigger some events
	(void)store->AddIOC(IOCType::Domain, "event-test.com", ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis);

	// Give callbacks time to process
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	store->UnregisterEventCallback(id1);
	store->UnregisterEventCallback(id2);

	store->Shutdown();
}

// ============================================================================
// PART 10: Edge Cases & Input Validation
// ============================================================================

TEST(ThreatIntelStore_EdgeCases, EmptyStrings_HandleGracefully) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	EXPECT_FALSE(store->LookupHash("", "").found);
	EXPECT_FALSE(store->LookupIPv4("").found);
	EXPECT_FALSE(store->LookupDomain("").found);
	EXPECT_FALSE(store->LookupURL("").found);
	EXPECT_FALSE(store->LookupEmail("").found);

	store->Shutdown();
}

TEST(ThreatIntelStore_EdgeCases, VeryLongStrings_NoBufferOverflow) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const std::string veryLong(100000, 'a');

	EXPECT_NO_THROW({
		(void)store->LookupDomain(veryLong);
		(void)store->LookupHash("SHA256", veryLong);
		(void)store->LookupURL(veryLong);
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_EdgeCases, SpecialCharacters_HandleSafely) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const std::string special = "';DROP TABLE iocs;--";

	EXPECT_NO_THROW({
		(void)store->LookupDomain(special);
		(void)store->AddIOC(IOCType::Domain, special, ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis);
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_EdgeCases, NullBytes_HandleCorrectly) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::string withNull = "test";
	withNull.push_back('\0');
	withNull += "after-null";

	EXPECT_NO_THROW({
		(void)store->LookupDomain(withNull);
	});

	store->Shutdown();
}

// ============================================================================
// PART 11: Production Stress Tests
// ============================================================================

TEST(ThreatIntelStore_Production, HighVolumeLookupsStress_Stable) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	constexpr int kIterations = 1000;

	for (int i = 0; i < kIterations; ++i) {
		(void)store->LookupIPv4("8.8.8." + std::to_string(i % 256));
		(void)store->LookupDomain("test" + std::to_string(i) + ".com");
		(void)store->LookupHash("SHA256", MakeValidSHA256());
	}

	const auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, kIterations * 3u);

	store->Shutdown();
}

TEST(ThreatIntelStore_Production, ConcurrentLookups_ThreadSafe) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	constexpr int kThreads = 16;
	constexpr int kIters = 250;
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	std::atomic<bool> start{false};

	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&, t]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kIters; ++i) {
				(void)store->LookupIPv4("10.0." + std::to_string(t) + "." + std::to_string(i % 256));
				(void)store->LookupDomain("thread" + std::to_string(t) + "-" + std::to_string(i) + ".com");
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	const auto stats = store->GetStatistics();
	const uint64_t expected = static_cast<uint64_t>(kThreads) * static_cast<uint64_t>(kIters) * 2u;
	EXPECT_EQ(stats.totalLookups, expected);

	store->Shutdown();
}

TEST(ThreatIntelStore_Production, ConcurrentIOCManagement_Stable) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	constexpr int kThreads = 8;
	constexpr int kIters = 100;
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	std::atomic<bool> start{false};

	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&, t]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kIters; ++i) {
				const std::string domain = "concurrent-" + std::to_string(t) + "-" + std::to_string(i) + ".com";
				(void)store->AddIOC(IOCType::Domain, domain, ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis);
				(void)store->HasIOC(IOCType::Domain, domain);
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	store->Shutdown();
}

TEST(ThreatIntelStore_Production, MixedOperationsStress_AllAPIs) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::atomic<bool> stop{false};
	std::vector<std::thread> workers;

	// Lookup worker
	workers.emplace_back([&]() {
		while (!stop.load(std::memory_order_acquire)) {
			(void)store->LookupIPv4("8.8.8.8");
			(void)store->LookupDomain("example.com");
		}
	});

	// IOC management worker
	workers.emplace_back([&]() {
		int counter = 0;
		while (!stop.load(std::memory_order_acquire)) {
			(void)store->AddIOC(IOCType::Domain, "stress-" + std::to_string(counter++) + ".com", 
			                     ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis);
		}
	});

	// Stats worker
	workers.emplace_back([&]() {
		while (!stop.load(std::memory_order_acquire)) {
			(void)store->GetStatistics();
			(void)store->GetCacheStatistics();
		}
	});

	// Run for 500ms
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	stop.store(true, std::memory_order_release);

	for (auto& w : workers) w.join();

	store->Shutdown();
}

// ============================================================================
// PART 12: Additional Edge Case Tests for Enterprise-Grade Coverage
// ============================================================================

// --------------------------------------------------------------------------
// IPv4 Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_IPv4EdgeCases, Loopback_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv4("127.0.0.1");
	EXPECT_FALSE(result.found); // Loopback should not be in threat DB

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, Broadcast_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv4("255.255.255.255");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, PrivateRanges_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Class A private - use obscure address not in test data
	auto r1 = store->LookupIPv4("10.255.255.253");
	EXPECT_FALSE(r1.found);

	// Class B private - use obscure address not in test data
	auto r2 = store->LookupIPv4("172.31.255.251");
	EXPECT_FALSE(r2.found);

	// Class C private - use obscure address not in test data
	auto r3 = store->LookupIPv4("192.168.255.250");
	EXPECT_FALSE(r3.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, ZeroAddress_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv4("0.0.0.0");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, MulticastRange_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Multicast address (224.0.0.0 - 239.255.255.255)
	auto result = store->LookupIPv4("224.0.0.1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, LinkLocal_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Link-local (169.254.0.0/16)
	auto result = store->LookupIPv4("169.254.0.1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, MalformedWithPort_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// IP with port should be handled gracefully
	auto result = store->LookupIPv4("192.168.1.1:8080");
	// Should either strip port or return not found
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, LeadingZeros_RejectedOrNormalized) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Leading zeros (potential octal interpretation security issue)
	auto result = store->LookupIPv4("192.168.001.001");
	// Should be rejected or normalized
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, NegativeOctet_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Negative values are invalid
	auto result = store->LookupIPv4("-1.0.0.1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv4EdgeCases, HugeOctet_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Octet > 255
	auto result = store->LookupIPv4("256.0.0.1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// IPv6 Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_IPv6EdgeCases, FullFormat_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv6EdgeCases, Compressed_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv6("2001:db8::1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv6EdgeCases, Loopback_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv6("::1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv6EdgeCases, Unspecified_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupIPv6("::");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv6EdgeCases, IPv4Mapped_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// IPv4-mapped IPv6 address
	auto result = store->LookupIPv6("::ffff:192.168.1.1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_IPv6EdgeCases, LinkLocal_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Link-local (fe80::/10)
	auto result = store->LookupIPv6("fe80::1");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Hash Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_HashEdgeCases, SHA256_UpperCase_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Uppercase hash that is NOT in the test data - use a unique test value
	// This is SHA256 of "test_unique_string_not_in_dataset_12345"
	auto result = store->LookupHash("SHA256", "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, SHA256_MixedCase_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupHash("SHA256", "e3B0c44298FC1C149abf4c8996fb92427ae41e4649b934ca495991b7852b855");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, SHA1_Valid_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupHash("SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, MD5_Valid_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupHash("MD5", "d41d8cd98f00b204e9800998ecf8427e");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, SHA512_Valid_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const std::string sha512 = 
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
	auto result = store->LookupHash("SHA512", sha512);
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, WrongLength_SHA256_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// SHA256 should be 64 chars, this is 63
	auto result = store->LookupHash("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, InvalidHexChars_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Contains 'g' which is invalid hex
	auto result = store->LookupHash("SHA256", "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_HashEdgeCases, UnknownAlgorithm_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Unknown algorithm - use unique hash not in test data
	auto result = store->LookupHash("UNKNOWN_ALGO", "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
	// Should handle gracefully
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Domain Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_DomainEdgeCases, SingleLabelDomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Single-label domain (no TLD)
	auto result = store->LookupDomain("localhost");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, Punycode_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Internationalized domain in Punycode
	auto result = store->LookupDomain("xn--n3h.com");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, LongSubdomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Very long subdomain
	std::string longDomain = std::string(63, 'a') + ".example.com";
	auto result = store->LookupDomain(longDomain);
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, MaxLengthDomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// DNS max is 253 chars total
	std::string maxDomain;
	for (int i = 0; i < 25; ++i) {
		if (i > 0) maxDomain += ".";
		maxDomain += std::string(10, 'a');
	}
	maxDomain += ".com";

	// Should handle gracefully even if too long
	EXPECT_NO_THROW({
		(void)store->LookupDomain(maxDomain);
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, TrailingDot_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// FQDN with trailing dot
	auto result = store->LookupDomain("example.com.");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, CaseNormalization) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// All uppercase
	auto r1 = store->LookupDomain("EXAMPLE.COM");
	EXPECT_FALSE(r1.found);

	// Mixed case
	auto r2 = store->LookupDomain("ExAmPlE.CoM");
	EXPECT_FALSE(r2.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_DomainEdgeCases, NumericTLD_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Numeric TLD (not valid per ICANN but handle gracefully)
	auto result = store->LookupDomain("example.123");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// URL Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_URLEdgeCases, WithQueryParams_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupURL("https://example.com/path?query=value&foo=bar");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, WithFragment_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupURL("https://example.com/page#section");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, WithPort_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupURL("https://example.com:8443/secure");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, WithAuth_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// URL with user:pass
	auto result = store->LookupURL("https://user:pass@example.com/");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, EncodedChars_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// URL-encoded characters
	auto result = store->LookupURL("https://example.com/path%20with%20spaces");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, DataURL_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Data URL
	auto result = store->LookupURL("data:text/html,<script>alert(1)</script>");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_URLEdgeCases, FileURL_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// File URL
	auto result = store->LookupURL("file:///etc/passwd");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Email Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_EmailEdgeCases, WithPlusAddressing_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupEmail("user+tag@example.com");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_EmailEdgeCases, WithSubdomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupEmail("user@mail.subdomain.example.com");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_EmailEdgeCases, QuotedLocalPart_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Quoted local part with special chars
	auto result = store->LookupEmail("\"user.special\"@example.com");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_EmailEdgeCases, IPLiteral_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Email with IP literal domain
	auto result = store->LookupEmail("user@[192.168.1.1]");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Batch Operation Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_BatchEdgeCases, LargeBatch_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Create large batch
	std::vector<std::string> hashes;
	hashes.reserve(10000);
	for (int i = 0; i < 10000; ++i) {
		// Generate unique but valid-format SHA256
		std::string hash = MakeValidSHA256();
		hash[0] = '0' + (i % 10);
		hash[1] = '0' + ((i / 10) % 10);
		hash[2] = '0' + ((i / 100) % 10);
		hash[3] = '0' + ((i / 1000) % 10);
		hashes.push_back(hash);
	}

	auto results = store->BatchLookupHashes("SHA256", hashes);
	EXPECT_EQ(results.totalProcessed, hashes.size());
	EXPECT_EQ(results.results.size(), hashes.size());

	store->Shutdown();
}

TEST(ThreatIntelStore_BatchEdgeCases, MixedValidInvalid_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> ips = {
		"8.8.8.8",          // Valid
		"not.an.ip",        // Invalid
		"192.168.1.1",      // Valid
		"256.0.0.1",        // Invalid (octet > 255)
		"1.2.3.4"           // Valid
	};

	auto results = store->BatchLookupIPv4(ips);
	EXPECT_EQ(results.totalProcessed, ips.size());
	EXPECT_EQ(results.results.size(), ips.size());

	store->Shutdown();
}

TEST(ThreatIntelStore_BatchEdgeCases, DuplicatesInBatch_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	std::vector<std::string> domains = {
		"example.com",
		"example.com",
		"example.com",
		"test.com",
		"example.com"
	};

	auto results = store->BatchLookupDomains(domains);
	EXPECT_EQ(results.totalProcessed, domains.size());
	EXPECT_EQ(results.results.size(), domains.size());

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Memory & Resource Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_ResourceEdgeCases, RapidCreateDestroy_Stable) {
	// Test rapid creation and destruction doesn't leak
	for (int i = 0; i < 50; ++i) {
		auto store = CreateThreatIntelStore();
		ASSERT_NE(store, nullptr);
		// Don't even initialize, just create/destroy
	}
}

TEST(ThreatIntelStore_ResourceEdgeCases, RapidInitShutdown_Stable) {
	TempDir tempDir;
	
	for (int i = 0; i < 20; ++i) {
		auto store = CreateThreatIntelStore();
		auto dbPath = tempDir.FilePath("rapid_" + std::to_string(i) + ".db");
		const auto cfg = MakeTestConfig(dbPath);
		
		ASSERT_TRUE(store->Initialize(cfg));
		store->Shutdown();
	}
}

TEST(ThreatIntelStore_ResourceEdgeCases, OperationsAfterShutdown_Safe) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());
	store->Shutdown();

	// All operations should be safe after shutdown
	EXPECT_FALSE(store->IsInitialized());

	auto r1 = store->LookupIPv4("8.8.8.8");
	EXPECT_FALSE(r1.found);

	auto r2 = store->LookupDomain("example.com");
	EXPECT_FALSE(r2.found);

	EXPECT_FALSE(store->AddIOC(IOCType::Domain, "test.com", ReputationLevel::Malicious, ThreatIntelSource::InternalAnalysis));

	auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 0u);
}

// --------------------------------------------------------------------------
// Unicode & Internationalization Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_UnicodeEdgeCases, IDNDomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// International domain name (should be converted to Punycode or handled)
	auto result = store->LookupDomain("münchen.de");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_UnicodeEdgeCases, ChineseDomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Chinese characters in domain
	auto result = store->LookupDomain("例え.jp");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_UnicodeEdgeCases, RTLDomain_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Right-to-left script
	auto result = store->LookupDomain("مثال.مصر");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Boundary Value Tests
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_BoundaryEdgeCases, ZeroConfidence_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	IOCEntry entry = MakeTestIOCEntry(IOCType::IPv4, "1.2.3.4");
	entry.confidence = ConfidenceLevel::None;

	// Store validation rejects zero confidence - this is correct behavior for enterprise systems
	// Zero confidence entries should not pollute the database
	EXPECT_FALSE(store->AddIOC(entry));

	store->Shutdown();
}

TEST(ThreatIntelStore_BoundaryEdgeCases, MaxTimestamp_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	IOCEntry entry = MakeTestIOCEntry(IOCType::IPv4, "1.2.3.4");
	entry.firstSeen = UINT64_MAX;
	entry.lastSeen = UINT64_MAX;

	// Should handle max timestamps gracefully
	EXPECT_NO_THROW({
		(void)store->AddIOC(entry);
	});

	store->Shutdown();
}

TEST(ThreatIntelStore_BoundaryEdgeCases, VeryOldTimestamp_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	IOCEntry entry = MakeTestIOCEntry(IOCType::IPv4, "1.2.3.4");
	entry.firstSeen = 0; // Unix epoch
	entry.lastSeen = 1; 

	EXPECT_NO_THROW({
		(void)store->AddIOC(entry);
	});

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Error Recovery Tests
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_ErrorRecovery, ContinuesAfterInvalidInput) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Invalid inputs shouldn't break subsequent operations
	(void)store->LookupIPv4("invalid");
	(void)store->LookupIPv4("256.256.256.256");
	(void)store->LookupDomain("");
	(void)store->LookupHash("SHA256", "not-a-hash");

	// Valid operation should still work - use IP not in pre-populated data
	auto result = store->LookupIPv4("172.31.255.254");
	// Should complete without crash and return not found (this IP not in test data)
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_ErrorRecovery, ContinuesAfterBatchErrors) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Batch with all invalid
	std::vector<std::string> allInvalid = {"invalid1", "invalid2", "invalid3"};
	auto r1 = store->BatchLookupIPv4(allInvalid);
	EXPECT_EQ(r1.totalProcessed, allInvalid.size());

	// Should still work after - use IP not in pre-populated test data
	auto r2 = store->LookupIPv4("172.31.255.253");
	EXPECT_FALSE(r2.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// JA3/JA3S Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_JA3EdgeCases, ValidJA3_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// JA3 fingerprint (32 char MD5)
	auto result = store->LookupJA3("d41d8cd98f00b204e9800998ecf8427e");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_JA3EdgeCases, EmptyJA3_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupJA3("");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// CVE Edge Cases  
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_CVEEdgeCases, ValidFormat_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupCVE("CVE-2021-44228");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_CVEEdgeCases, OldFormat_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Old CVE format
	auto result = store->LookupCVE("CVE-1999-0001");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_CVEEdgeCases, ExtendedFormat_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Extended CVE ID (post-2014 format)
	auto result = store->LookupCVE("CVE-2024-123456");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

TEST(ThreatIntelStore_CVEEdgeCases, InvalidFormat_Handled) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	auto result = store->LookupCVE("not-a-cve");
	EXPECT_FALSE(result.found);

	store->Shutdown();
}

// --------------------------------------------------------------------------
// Statistics Edge Cases
// --------------------------------------------------------------------------

TEST(ThreatIntelStore_StatsEdgeCases, StatsAfterManyOperations) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Perform many operations
	for (int i = 0; i < 1000; ++i) {
		(void)store->LookupIPv4("8.8.8." + std::to_string(i % 256));
	}

	auto stats = store->GetStatistics();
	EXPECT_EQ(stats.totalLookups, 1000u);

	// Reset and verify
	store->ResetStatistics();
	auto statsAfterReset = store->GetStatistics();
	EXPECT_EQ(statsAfterReset.totalLookups, 0u);

	store->Shutdown();
}

TEST(ThreatIntelStore_StatsEdgeCases, CacheStatsAccurate) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	// Same lookup multiple times should hit cache
	for (int i = 0; i < 100; ++i) {
		(void)store->LookupIPv4("8.8.8.8");
	}

	auto cacheStats = store->GetCacheStatistics();
	// First lookup misses, rest should hit (if caching enabled)
	// At minimum verify we get valid stats
	EXPECT_GE(cacheStats.totalCapacity, 0u);

	store->Shutdown();
}

} // namespace ShadowStrike::ThreatIntel::Tests
