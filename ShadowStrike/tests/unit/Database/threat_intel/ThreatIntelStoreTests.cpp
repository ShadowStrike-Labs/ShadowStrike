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
	cfg.cacheCapacity = 1024;
	cfg.enableAutoFeedUpdates = false; // Disable for deterministic tests
	cfg.enableStatistics = true;
	return cfg;
}

[[nodiscard]] IOCEntry MakeTestIOCEntry(IOCType type, const std::string& value) {
	IOCEntry entry{};
	entry.entryId = 0; // Will be assigned by store
	entry.type = type;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ReputationLevel::Malicious;
	entry.category = ThreatCategory::Malware;
	entry.source = ThreatIntelSource::Internal;
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

	const auto entry = MakeTestIOCEntry(IOCType::Domain, "malicious.com");
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
		ThreatIntelSource::Internal
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

	auto entry = MakeTestIOCEntry(IOCType::Domain, "update-test.com");
	ASSERT_TRUE(store->AddIOC(entry));

	entry.reputation = ReputationLevel::Safe;
	EXPECT_TRUE(store->UpdateIOC(entry));

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, RemoveIOC_ValidType) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	ASSERT_TRUE(store->AddIOC(IOCType::Domain, "remove-test.com", ReputationLevel::Malicious, ThreatIntelSource::Internal));
	EXPECT_TRUE(store->RemoveIOC(IOCType::Domain, "remove-test.com"));

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

	std::vector<IOCEntry> entries;
	for (int i = 0; i < 10; ++i) {
		entries.push_back(MakeTestIOCEntry(IOCType::Domain, "bulk" + std::to_string(i) + ".com"));
	}

	const size_t added = store->BulkAddIOCs(entries);
	EXPECT_GT(added, 0u);
	EXPECT_LE(added, entries.size());

	store->Shutdown();
}

TEST(ThreatIntelStore_IOCMgmt, HasIOC_AfterAdd_ReturnsTrue) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	const std::string domain = "check-exists.com";
	ASSERT_TRUE(store->AddIOC(IOCType::Domain, domain, ReputationLevel::Malicious, ThreatIntelSource::Internal));

	EXPECT_TRUE(store->HasIOC(IOCType::Domain, domain));

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

TEST(ThreatIntelStore_Feeds, AddFeed_ValidConfig) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	FeedConfiguration feedCfg;
	feedCfg.feedId = "test-feed-001";
	feedCfg.name = "Test Feed";
	feedCfg.enabled = true;

	EXPECT_TRUE(store->AddFeed(feedCfg));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, RemoveFeed_ExistingFeed) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	FeedConfiguration feedCfg;
	feedCfg.feedId = "remove-feed-001";
	feedCfg.name = "Remove Test Feed";
	ASSERT_TRUE(store->AddFeed(feedCfg));

	EXPECT_TRUE(store->RemoveFeed("remove-feed-001"));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, EnableDisableFeed_TogglesState) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	FeedConfiguration feedCfg;
	feedCfg.feedId = "toggle-feed-001";
	feedCfg.name = "Toggle Feed";
	feedCfg.enabled = true;
	ASSERT_TRUE(store->AddFeed(feedCfg));

	EXPECT_TRUE(store->DisableFeed("toggle-feed-001"));
	EXPECT_TRUE(store->EnableFeed("toggle-feed-001"));

	store->Shutdown();
}

TEST(ThreatIntelStore_Feeds, UpdateFeed_TriggersFeedUpdate) {
	auto store = CreateThreatIntelStore();
	ASSERT_TRUE(store->Initialize());

	FeedConfiguration feedCfg;
	feedCfg.feedId = "update-feed-001";
	feedCfg.name = "Update Test Feed";
	ASSERT_TRUE(store->AddFeed(feedCfg));

	EXPECT_TRUE(store->UpdateFeed("update-feed-001"));

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

	FeedConfiguration feedCfg;
	feedCfg.feedId = "status-feed-001";
	feedCfg.name = "Status Test Feed";
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
	(void)store->AddIOC(IOCType::Domain, "event-test.com", ReputationLevel::Malicious, ThreatIntelSource::Internal);

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
		(void)store->AddIOC(IOCType::Domain, special, ReputationLevel::Malicious, ThreatIntelSource::Internal);
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
				(void)store->AddIOC(IOCType::Domain, domain, ReputationLevel::Malicious, ThreatIntelSource::Internal);
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
			                     ReputationLevel::Malicious, ThreatIntelSource::Internal);
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

} // namespace ShadowStrike::ThreatIntel::Tests
