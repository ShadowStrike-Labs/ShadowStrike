
/**
 * @file ThreatIntelLookup_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelLookup
 *
 * Focus:
 * - Lifecycle correctness (Initialize/Shutdown, idempotency)
 * - Safe behavior when uninitialized
 * - Correct tier routing for currently-implemented tiers:
 *   - Thread-local cache
 *   - Index lookup via ThreatIntelIndex
 * - Batch lookup aggregation and ordering
 * - Statistics tracking/reset behavior
 * - Concurrency smoke and counter correctness
 *
 * Notes on current implementation realities:
 * - Shared cache and database/store tiers are present but currently stubbed/TODO.
 * - Index tier requires options.maxLookupTiers >= 3 (Tier 1 TL cache, Tier 2 shared cache,
 *   Tier 3 index). Tests explicitly set maxLookupTiers=3 to exercise the index tier.
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelLookup.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelIndex.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;


// ============================================================================
// MINIMUM DATABASE SIZE CONSTANT
// ============================================================================

/// @brief Minimum size for a valid threat intel database
/// @details Must accommodate header (4KB) + minimal data sections
constexpr size_t MIN_DATABASE_SIZE = 10 * 1024 * 1024;  // 10 MB minimum

namespace {

// Temporary directory helper (mirrors ThreatIntelIndex_tests.cpp style)
struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_Lookup_") +
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

[[nodiscard]] bool CreateTestDatabase(const std::filesystem::path& dbPath, MemoryMappedView& view) {
	StoreError error;

	// Create database
	bool result = MemoryMapping::CreateDatabase(dbPath.wstring(), MIN_DATABASE_SIZE, view, error);
	if (!result) {
		return false;
	}

	// Initialize header
	auto* header = const_cast<ThreatIntelDatabaseHeader*>(view.GetAt<ThreatIntelDatabaseHeader>(0));
	if (!header) {
		MemoryMapping::CloseView(view);
		return false;
	}

	// Set basic header fields
	header->magic = THREATINTEL_DB_MAGIC;
	header->versionMajor = THREATINTEL_DB_VERSION_MAJOR;
	header->versionMinor = THREATINTEL_DB_VERSION_MINOR;
	header->creationTime = static_cast<uint64_t>(std::time(nullptr));
	header->lastUpdateTime = header->creationTime;
	header->totalFileSize = view.fileSize;

	return true;
}

[[nodiscard]] IOCEntry CreateTestEntry(IOCType type, const std::string& value) {
	IOCEntry entry{};
	entry.type = type;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.category = ThreatCategory::C2Server;

	switch (type) {
		case IOCType::IPv4: {
			auto parsed = Format::ParseIPv4(value);
			if (parsed.has_value()) {
				entry.value.ipv4 = *parsed;
			}
			break;
		}
		case IOCType::IPv6: {
			auto parsed = Format::ParseIPv6(value);
			if (parsed.has_value()) {
				entry.value.ipv6 = *parsed;
			}
			break;
		}
		case IOCType::FileHash: {
			auto parsed = Format::ParseHashString(value, HashAlgorithm::SHA256);
			if (parsed.has_value()) {
				entry.value.hash = *parsed;
			}
			break;
		}
		default:
			break;
	}

	return entry;
}

[[nodiscard]] UnifiedLookupOptions MakeIndexEnabledOptions() {
	auto opts = UnifiedLookupOptions::FastestLookup();
	// Current engine tier gating: TL=1, Shared=2, Index=3, Database=4, External=5.
	// Force index usage in tests even when Shared cache is not configured.
	opts.maxLookupTiers = 3;
	opts.cacheResult = true;
	opts.includeMetadata = false;
	opts.includeSourceAttribution = false;
	opts.queryExternalAPI = false;
	return opts;
}

} // namespace

// ============================================================================
// Lifecycle & Safety Tests
// ============================================================================

TEST(ThreatIntelLookup_Lifecycle, DefaultConstruction_NotInitialized) {
	ThreatIntelLookup lookup;
	EXPECT_FALSE(lookup.IsInitialized());
}

TEST(ThreatIntelLookup_Lifecycle, UninitializedLookup_ReturnsNotFoundAndNoCrash) {
	ThreatIntelLookup lookup;
	const auto res = lookup.LookupIPv4("1.2.3.4");
	EXPECT_FALSE(res.found);
	EXPECT_EQ(res.source, ThreatLookupResult::Source::None);
}

TEST(ThreatIntelLookup_Lifecycle, Initialize_Shutdown_IdempotentAndSafe) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	ASSERT_NE(header, nullptr);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 256;

	ASSERT_TRUE(lookup.Initialize(cfg, /*store*/nullptr, &index, /*iocManager*/nullptr, /*cache*/nullptr));
	EXPECT_TRUE(lookup.IsInitialized());

	// Second initialize should fail (already initialized)
	EXPECT_FALSE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	lookup.Shutdown();
	EXPECT_FALSE(lookup.IsInitialized());
	lookup.Shutdown();
	lookup.Shutdown();

	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Index Tier Routing & Thread-Local Cache
// ============================================================================

TEST(ThreatIntelLookup_Routing, IPv4_IndexHit_SetsFoundAndSource) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	ASSERT_TRUE(index.Insert(entry, 1000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 256;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("192.168.1.1", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv4);
	EXPECT_EQ(res.source, ThreatLookupResult::Source::Index);
	EXPECT_GT(res.latencyNs, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Routing, SameThread_SecondLookup_HitsThreadLocalCache) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "10.1.2.3");
	ASSERT_TRUE(index.Insert(entry, 4242).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 128;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto first = lookup.LookupIPv4("10.1.2.3", opts);
	ASSERT_TRUE(first.found);
	EXPECT_EQ(first.source, ThreatLookupResult::Source::Index);

	const auto second = lookup.LookupIPv4("10.1.2.3", opts);
	ASSERT_TRUE(second.found);
	EXPECT_EQ(second.source, ThreatLookupResult::Source::ThreadLocalCache);

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(stats.successfulLookups.load(std::memory_order_relaxed), 2u);
	EXPECT_EQ(stats.indexHits.load(std::memory_order_relaxed), 1u);
	EXPECT_EQ(stats.threadLocalCacheHits.load(std::memory_order_relaxed), 1u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Routing, InvalidInputs_DoNotCrash_AndReturnNotFound) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 64;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	EXPECT_FALSE(lookup.LookupIPv4("999.999.999.999", opts).found);
	EXPECT_FALSE(lookup.LookupIPv6("this-is-not-an-ipv6", opts).found);
	EXPECT_FALSE(lookup.LookupSHA256("not-hex", opts).found);
	EXPECT_FALSE(lookup.LookupHash("", opts).found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Batch Lookups
// ============================================================================

TEST(ThreatIntelLookup_Batch, BatchLookupIPv4_AggregatesCountsAndPreservesOrder) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert only two known hits
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "8.8.8.8"), 111).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "1.1.1.1"), 222).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	// Disable thread-local cache to make tier counts deterministic for batch tests.
	cfg.enableThreadLocalCache = false;
	cfg.enableSIMD = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	std::vector<std::string> values = {"8.8.8.8", "9.9.9.9", "1.1.1.1", "7.7.7.7"};
	std::vector<std::string_view> views;
	views.reserve(values.size());
	for (const auto& s : values) views.emplace_back(s);

	auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.totalProcessed, values.size());
	EXPECT_EQ(batch.foundCount, 2u);
	EXPECT_EQ(batch.notFoundCount, 2u);
	EXPECT_EQ(batch.indexHits, 2u);
	EXPECT_EQ(batch.threadLocalCacheHits, 0u);
	EXPECT_EQ(batch.sharedCacheHits, 0u);
	EXPECT_EQ(batch.databaseHits, 0u);
	EXPECT_EQ(batch.externalAPIHits, 0u);
	ASSERT_EQ(batch.results.size(), values.size());

	// Order preserved: results align with inputs
	EXPECT_TRUE(batch.results[0].found);
	EXPECT_FALSE(batch.results[1].found);
	EXPECT_TRUE(batch.results[2].found);
	EXPECT_FALSE(batch.results[3].found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Batch, LargeBatch_ParallelPath_NoCrash_AndStableAggregation) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Prepare 128 IPv4 values; insert the first 64 as hits
	std::vector<std::string> values;
	values.reserve(128);
	for (int i = 0; i < 128; ++i) {
		values.emplace_back("10.10.0." + std::to_string(i + 1));
	}
	for (int i = 0; i < 64; ++i) {
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, values[static_cast<size_t>(i)]), 1000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	cfg.enableSIMD = true;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	std::vector<std::string_view> views;
	views.reserve(values.size());
	for (const auto& s : values) views.emplace_back(s);

	auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.totalProcessed, values.size());
	EXPECT_EQ(batch.foundCount, 64u);
	EXPECT_EQ(batch.notFoundCount, 64u);
	EXPECT_EQ(batch.indexHits, 64u);
	ASSERT_EQ(batch.results.size(), values.size());

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Statistics & Concurrency
// ============================================================================

TEST(ThreatIntelLookup_Stats, ResetStatistics_ZeroesCounters) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "4.4.4.4"), 44).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 64;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	(void)lookup.LookupIPv4("4.4.4.4", opts);
	(void)lookup.LookupIPv4("4.4.4.4", opts);

	{
		const auto s = lookup.GetStatistics();
		EXPECT_EQ(s.totalLookups.load(std::memory_order_relaxed), 2u);
		EXPECT_EQ(s.successfulLookups.load(std::memory_order_relaxed), 2u);
	}

	lookup.ResetStatistics();
	{
		const auto s = lookup.GetStatistics();
		EXPECT_EQ(s.totalLookups.load(std::memory_order_relaxed), 0u);
		EXPECT_EQ(s.successfulLookups.load(std::memory_order_relaxed), 0u);
		EXPECT_EQ(s.indexHits.load(std::memory_order_relaxed), 0u);
		EXPECT_EQ(s.threadLocalCacheHits.load(std::memory_order_relaxed), 0u);
	}

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Concurrency, ConcurrentLookups_CountersMatchAndNoCrash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "123.45.67.89"), 1234).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 64;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	constexpr int kThreads = 8;
	constexpr int kIters = 200;
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	std::atomic<bool> start{false};
	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kIters; ++i) {
				const auto r = lookup.LookupIPv4("123.45.67.89", opts);
				if (!r.found) {
					// Fail-fast in thread; use EXPECT in main thread after join.
					return;
				}
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	const auto stats = lookup.GetStatistics();
	const uint64_t expected = static_cast<uint64_t>(kThreads) * static_cast<uint64_t>(kIters);
	EXPECT_EQ(stats.totalLookups.load(std::memory_order_relaxed), expected);
	EXPECT_EQ(stats.successfulLookups.load(std::memory_order_relaxed), expected);
	EXPECT_EQ(stats.indexHits.load(std::memory_order_relaxed), static_cast<uint64_t>(kThreads));
	EXPECT_EQ(stats.threadLocalCacheHits.load(std::memory_order_relaxed), expected - static_cast<uint64_t>(kThreads));

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Additional IOC Type Coverage (IPv6, Domain, URL, Hash, Email)
// ============================================================================

TEST(ThreatIntelLookup_IOCTypes, IPv6Lookup_ValidAddress_IndexHit) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv6, "2001:4860:4860::8888");
	ASSERT_TRUE(index.Insert(entry, 2000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv6("2001:4860:4860::8888", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv6);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IOCTypes, DomainLookup_MaliciousDomain_IndexHit) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry{};
	entry.type = IOCType::Domain;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	ASSERT_TRUE(index.Insert(entry, 3000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupDomain("evil.example.com", opts);

	EXPECT_EQ(res.type, IOCType::Domain);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IOCTypes, HashLookup_SHA256_ValidFormat) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	const std::string validSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, validSHA256);
	ASSERT_TRUE(index.Insert(entry, 4000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupSHA256(validSHA256, opts);

	EXPECT_EQ(res.type, IOCType::FileHash);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IOCTypes, EmailLookup_ValidEmail) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupEmail("phishing@malicious.com", opts);

	EXPECT_EQ(res.type, IOCType::Email);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Edge Cases & Input Validation
// ============================================================================

TEST(ThreatIntelLookup_EdgeCases, EmptyInputStrings_ReturnNotFound) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	EXPECT_FALSE(lookup.LookupIPv4("", opts).found);
	EXPECT_FALSE(lookup.LookupDomain("", opts).found);
	EXPECT_FALSE(lookup.LookupURL("", opts).found);
	EXPECT_FALSE(lookup.LookupHash("", opts).found);
	EXPECT_FALSE(lookup.LookupEmail("", opts).found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_EdgeCases, VeryLongInputs_HandleGracefully) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const std::string veryLongDomain(10000, 'a');
	const std::string veryLongHash(10000, 'f');

	const auto opts = MakeIndexEnabledOptions();
	EXPECT_NO_THROW({
		(void)lookup.LookupDomain(veryLongDomain, opts);
		(void)lookup.LookupHash(veryLongHash, opts);
	});

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_EdgeCases, ConcurrentInitialization_OnlyOneSucceeds) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();

	std::atomic<int> successCount{0};
	std::atomic<bool> start{false};
	std::vector<std::thread> threads;

	for (int i = 0; i < 4; ++i) {
		threads.emplace_back([&]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			if (lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr)) {
				successCount.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	EXPECT_EQ(successCount.load(), 1);
	EXPECT_TRUE(lookup.IsInitialized());

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Configuration & Options Tests
// ============================================================================

TEST(ThreatIntelLookup_Config, LookupOptions_FastestVsDetailed) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "203.0.113.1");
	ASSERT_TRUE(index.Insert(entry, 5555).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto fastOpts = UnifiedLookupOptions::FastestLookup();
	fastOpts.maxLookupTiers = 3;
	const auto fastRes = lookup.LookupIPv4("203.0.113.1", fastOpts);

	auto detailedOpts = UnifiedLookupOptions::DetailedLookup();
	detailedOpts.maxLookupTiers = 3;
	const auto detailedRes = lookup.LookupIPv4("203.0.113.1", detailedOpts);

	EXPECT_TRUE(fastRes.found);
	EXPECT_TRUE(detailedRes.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Config, ThreadLocalCacheDisabled_NoTLCacheHits) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "198.51.100.42");
	ASSERT_TRUE(index.Insert(entry, 6666).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	(void)lookup.LookupIPv4("198.51.100.42", opts);
	(void)lookup.LookupIPv4("198.51.100.42", opts);

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.threadLocalCacheHits.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(stats.indexHits.load(std::memory_order_relaxed), 2u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Config, GetAndUpdateConfiguration_Succeeds) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.threadLocalCacheSize = 512;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto& retrievedCfg = lookup.GetConfiguration();
	EXPECT_EQ(retrievedCfg.threadLocalCacheSize, 512u);

	LookupConfig newCfg = cfg;
	newCfg.threadLocalCacheSize = 1024;
	lookup.UpdateConfiguration(newCfg);

	const auto& updatedCfg = lookup.GetConfiguration();
	EXPECT_EQ(updatedCfg.threadLocalCacheSize, 1024u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Batch Operation Edge Cases
// ============================================================================

TEST(ThreatIntelLookup_BatchEdge, EmptyBatch_ReturnsZeroCounts) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	std::vector<std::string_view> empty;
	const auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(empty), opts);

	EXPECT_EQ(batch.totalProcessed, 0u);
	EXPECT_EQ(batch.foundCount, 0u);
	EXPECT_EQ(batch.results.size(), 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchEdge, SingleItemBatch_WorksCorrectly) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.0.2.1");
	ASSERT_TRUE(index.Insert(entry, 7777).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	std::vector<std::string> values = {"192.0.2.1"};
	std::vector<std::string_view> views;
	for (const auto& s : values) views.emplace_back(s);

	const auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.totalProcessed, 1u);
	EXPECT_EQ(batch.foundCount, 1u);
	ASSERT_EQ(batch.results.size(), 1u);
	EXPECT_TRUE(batch.results[0].found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchEdge, AllInvalidInputsBatch_AllNotFound) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	std::vector<std::string> values = {"invalid", "999.999.999.999", "", "not-an-ip"};
	std::vector<std::string_view> views;
	for (const auto& s : values) views.emplace_back(s);

	const auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.totalProcessed, values.size());
	EXPECT_EQ(batch.foundCount, 0u);
	EXPECT_EQ(batch.notFoundCount, values.size());

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Statistics & Diagnostics
// ============================================================================

TEST(ThreatIntelLookup_Stats, StatisticsBeforeLookups_AllZero) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(stats.successfulLookups.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(stats.failedLookups.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(stats.indexHits.load(std::memory_order_relaxed), 0u);
	EXPECT_EQ(stats.GetCacheHitRate(), 0.0);
	EXPECT_EQ(stats.GetAverageLatencyNs(), 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Stats, GetCacheStatistics_ValidData) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "10.20.30.40");
	ASSERT_TRUE(index.Insert(entry, 8888).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 128;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	(void)lookup.LookupIPv4("10.20.30.40", opts);
	(void)lookup.LookupIPv4("10.20.30.40", opts);

	const auto cacheStats = lookup.GetCacheStatistics();
	EXPECT_GT(cacheStats.totalLookups, 0u);
	EXPECT_GT(cacheStats.cacheHits, 0u);
	EXPECT_GE(cacheStats.utilization, 0.0);
	EXPECT_LE(cacheStats.utilization, 1.0);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Stats, GetMemoryUsage_NonZero) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.threadLocalCacheSize = 1024;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const size_t memUsage = lookup.GetMemoryUsage();
	EXPECT_GT(memUsage, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Stats, GetThroughput_Computes) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "172.16.0.1");
	ASSERT_TRUE(index.Insert(entry, 9999).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	for (int i = 0; i < 10; ++i) {
		(void)lookup.LookupIPv4("172.16.0.1", opts);
	}

	const double throughput = lookup.GetThroughput();
	EXPECT_GE(throughput, 0.0);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Cache Management API
// ============================================================================

TEST(ThreatIntelLookup_CacheMgmt, WarmCache_DoesNotCrash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	EXPECT_NO_THROW({
		const size_t warmed = lookup.WarmCache(100);
		(void)warmed;
	});

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_CacheMgmt, InvalidateCacheEntry_DoesNotCrash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	EXPECT_NO_THROW({
		lookup.InvalidateCacheEntry(IOCType::IPv4, "1.2.3.4");
	});

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_CacheMgmt, ClearAllCaches_DoesNotCrash) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	EXPECT_NO_THROW({
		lookup.ClearAllCaches();
	});

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// Production Stress & Leak Tests
// ============================================================================

TEST(ThreatIntelLookup_Production, MultipleInitShutdownCycles_NoLeaks) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.threadLocalCacheSize = 64;

	for (int cycle = 0; cycle < 5; ++cycle) {
		ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));
		EXPECT_TRUE(lookup.IsInitialized());

		const auto opts = MakeIndexEnabledOptions();
		(void)lookup.LookupIPv4("127.0.0.1", opts);

		lookup.Shutdown();
		EXPECT_FALSE(lookup.IsInitialized());
	}

	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Production, HighConcurrencyStress_Stable) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	for (int i = 0; i < 32; ++i) {
		const std::string ip = "10.0.0." + std::to_string(i + 1);
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 10000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 128;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();

	constexpr int kThreads = 16;
	constexpr int kIters = 500;
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	std::atomic<bool> start{false};
	std::atomic<uint64_t> errorCount{0};

	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&, t]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kIters; ++i) {
				const std::string ip = "10.0.0." + std::to_string((t % 32) + 1);
				const auto r = lookup.LookupIPv4(ip, opts);
				if (!r.found) {
					errorCount.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	EXPECT_EQ(errorCount.load(), 0u);

	const auto stats = lookup.GetStatistics();
	const uint64_t expected = static_cast<uint64_t>(kThreads) * static_cast<uint64_t>(kIters);
	EXPECT_EQ(stats.totalLookups.load(std::memory_order_relaxed), expected);
	EXPECT_EQ(stats.successfulLookups.load(std::memory_order_relaxed), expected);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

} // namespace ShadowStrike::ThreatIntel::Tests

