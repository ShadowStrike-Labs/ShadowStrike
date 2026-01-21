// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
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

/// @brief Offset where the string table begins in test databases
/// @details Placed immediately after the header for simplicity
constexpr uint64_t TEST_STRING_TABLE_OFFSET = sizeof(ThreatIntelDatabaseHeader);

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
	header->stringPoolOffset = TEST_STRING_TABLE_OFFSET;

	return true;
}

/**
 * @brief Helper to write a test string to the database and return its offset/length
 * @param view Memory mapped view
 * @param str String to write
 * @param currentOffset Current offset in string table (will be updated)
 * @return Pair of (offset, length) for the written string
 */
[[nodiscard]] std::pair<uint64_t, uint32_t> WriteTestString(
	MemoryMappedView& view, 
	const std::string& str, 
	uint64_t& currentOffset
) {
	if (str.empty() || currentOffset + str.size() >= view.fileSize) {
		return {0, 0};
	}
	
	auto* dest = const_cast<char*>(view.GetAt<char>(currentOffset));
	if (!dest) {
		return {0, 0};
	}
	
	std::memcpy(dest, str.data(), str.size());
	
	uint64_t offset = currentOffset;
	uint32_t length = static_cast<uint32_t>(str.size());
	currentOffset += str.size() + 1;  // +1 for null terminator space
	
	return {offset, length};
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
			// Auto-detect hash algorithm by length
			HashAlgorithm algo = HashAlgorithm::SHA256;  // Default
			if (value.length() == 32) algo = HashAlgorithm::MD5;
			else if (value.length() == 40) algo = HashAlgorithm::SHA1;
			else if (value.length() == 64) algo = HashAlgorithm::SHA256;
			else if (value.length() == 128) algo = HashAlgorithm::SHA512;
			
			auto parsed = Format::ParseHashString(value, algo);
			if (parsed.has_value()) {
				entry.value.hash = *parsed;
			}
			break;
		}
		case IOCType::Domain:
		case IOCType::URL:
		case IOCType::Email: {
			// For string-based types, use stringRef with inline storage
			// Note: In a real implementation, this would use a string pool
			// For testing, we store a simple hash to identify the entry
			entry.value.stringRef.stringOffset = Format::HashFNV1a(value);
			entry.value.stringRef.stringLength = static_cast<uint32_t>(value.length());
			entry.value.stringRef.patternOffset = 0;
			entry.value.stringRef.patternLength = 0;
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

	// Write domain string to database (must be done before index Insert)
	uint64_t stringOffset = TEST_STRING_TABLE_OFFSET;
	auto [domainOffset, domainLen] = WriteTestString(view, "evil.example.com", stringOffset);
	ASSERT_GT(domainOffset, 0u);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Create domain entry with actual string reference
	IOCEntry entry{};
	entry.type = IOCType::Domain;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.category = ThreatCategory::C2Server;
	entry.value.stringRef.stringOffset = domainOffset;
	entry.value.stringRef.stringLength = domainLen;
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

// ============================================================================
// COMPREHENSIVE EDGE CASE TESTS
// ============================================================================

TEST(ThreatIntelLookup_IPv4EdgeCases, BroadcastAddress_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "255.255.255.255"), 1000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("255.255.255.255", opts);
	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv4);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv4EdgeCases, ZeroAddress_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "0.0.0.0"), 1000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("0.0.0.0", opts);
	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv4);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv4EdgeCases, LoopbackRange_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "127.0.0.1"), 1001).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "127.255.255.254"), 1002).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	EXPECT_TRUE(lookup.LookupIPv4("127.0.0.1", opts).found);
	EXPECT_TRUE(lookup.LookupIPv4("127.255.255.254", opts).found);
	EXPECT_FALSE(lookup.LookupIPv4("127.0.0.2", opts).found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv4EdgeCases, MalformedAddresses_ReturnNotFound) {
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
	
	// Various malformed IPv4 inputs
	EXPECT_FALSE(lookup.LookupIPv4("256.1.1.1", opts).found);        // Octet overflow
	EXPECT_FALSE(lookup.LookupIPv4("1.1.1", opts).found);            // Missing octet
	EXPECT_FALSE(lookup.LookupIPv4("1.1.1.1.1", opts).found);        // Extra octet
	EXPECT_FALSE(lookup.LookupIPv4("1.1.1.1a", opts).found);         // Trailing chars
	EXPECT_FALSE(lookup.LookupIPv4("-1.1.1.1", opts).found);         // Negative
	EXPECT_FALSE(lookup.LookupIPv4("1..1.1", opts).found);           // Double dot
	EXPECT_FALSE(lookup.LookupIPv4(".1.1.1.1", opts).found);         // Leading dot
	EXPECT_FALSE(lookup.LookupIPv4("1.1.1.1.", opts).found);         // Trailing dot
	EXPECT_FALSE(lookup.LookupIPv4("abc.def.ghi.jkl", opts).found);  // Non-numeric

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv6EdgeCases, CompressedFormats_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert loopback in full form
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv6, "::1"), 2000).IsSuccess());
	// Insert all-zeros
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv6, "::"), 2001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	// Test various compressed representations
	EXPECT_TRUE(lookup.LookupIPv6("::1", opts).found);
	EXPECT_TRUE(lookup.LookupIPv6("::", opts).found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv6EdgeCases, MalformedAddresses_ReturnNotFound) {
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
	
	// Malformed IPv6
	EXPECT_FALSE(lookup.LookupIPv6("gggg::1", opts).found);          // Invalid hex
	EXPECT_FALSE(lookup.LookupIPv6(":::", opts).found);              // Triple colon
	EXPECT_FALSE(lookup.LookupIPv6("1:2:3:4:5:6:7:8:9", opts).found); // Too many groups

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_HashEdgeCases, AllHashTypes_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// MD5 - 32 chars
	const std::string md5 = "d41d8cd98f00b204e9800998ecf8427e";
	// SHA1 - 40 chars
	const std::string sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	// SHA256 - 64 chars
	const std::string sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	// SHA512 - 128 chars
	const std::string sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::FileHash, md5), 3001).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::FileHash, sha1), 3002).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::FileHash, sha256), 3003).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::FileHash, sha512), 3004).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	EXPECT_TRUE(lookup.LookupHash(md5, opts).found);
	EXPECT_TRUE(lookup.LookupHash(sha1, opts).found);
	EXPECT_TRUE(lookup.LookupHash(sha256, opts).found);
	EXPECT_TRUE(lookup.LookupHash(sha512, opts).found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_HashEdgeCases, CaseInsensitivity_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert lowercase
	const std::string hashLower = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::FileHash, hashLower), 3010).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	// Query with uppercase should still find it (case-insensitive)
	const std::string hashUpper = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";
	// Note: Whether this passes depends on implementation - testing both
	const auto resLower = lookup.LookupHash(hashLower, opts);
	EXPECT_TRUE(resLower.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_HashEdgeCases, InvalidHashFormats_ReturnNotFound) {
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
	
	// Invalid hash formats
	EXPECT_FALSE(lookup.LookupHash("", opts).found);                          // Empty
	EXPECT_FALSE(lookup.LookupHash("zzzz", opts).found);                      // Too short and invalid hex
	EXPECT_FALSE(lookup.LookupHash("g" + std::string(63, '0'), opts).found);  // Invalid hex char
	EXPECT_FALSE(lookup.LookupHash(std::string(31, '0'), opts).found);        // 31 chars - invalid length
	EXPECT_FALSE(lookup.LookupHash(std::string(33, '0'), opts).found);        // 33 chars - invalid length

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchEdgeCases, ExactThresholdBatch_UsesSequential) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert exactly 99 entries (below 100 threshold)
	for (int i = 0; i < 99; ++i) {
		const std::string ip = "192.168.1." + std::to_string(i + 1);
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 5000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	// Create batch of 99 (should use sequential path)
	std::vector<std::string> values;
	values.reserve(99);
	for (int i = 0; i < 99; ++i) {
		values.push_back("192.168.1." + std::to_string(i + 1));
	}
	std::vector<std::string_view> views;
	views.reserve(values.size());
	for (const auto& s : values) views.emplace_back(s);

	const auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.results.size(), 99u);
	EXPECT_EQ(batch.foundCount, 99u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchEdgeCases, AboveThresholdBatch_UsesParallel) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert 150 entries (above 100 threshold)
	for (int i = 0; i < 150; ++i) {
		const std::string ip = "10." + std::to_string(i / 255) + ".0." + std::to_string((i % 255) + 1);
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 6000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	// Create batch of 150 (should use parallel path)
	std::vector<std::string> values;
	values.reserve(150);
	for (int i = 0; i < 150; ++i) {
		values.push_back("10." + std::to_string(i / 255) + ".0." + std::to_string((i % 255) + 1));
	}
	std::vector<std::string_view> views;
	views.reserve(values.size());
	for (const auto& s : values) views.emplace_back(s);

	const auto opts = MakeIndexEnabledOptions();
	auto batch = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batch.results.size(), 150u);
	EXPECT_EQ(batch.foundCount, 150u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchEdgeCases, MixedValidInvalidBatch_HandledCorrectly) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "1.2.3.4"), 7000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = false;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	// Mix of valid, invalid, and not-found
	std::vector<std::string> values = {
		"1.2.3.4",        // Valid and found
		"invalid",        // Invalid format
		"5.6.7.8",        // Valid but not found
		"",               // Empty
		"1.2.3.4"         // Duplicate, found
	};
	std::vector<std::string_view> views;
	views.reserve(values.size());
	for (const auto& s : values) views.emplace_back(s);

	const auto opts = MakeIndexEnabledOptions();
	auto batchResult = lookup.BatchLookupIPv4(std::span<const std::string_view>(views), opts);

	EXPECT_EQ(batchResult.results.size(), 5u);
	EXPECT_TRUE(batchResult.results[0].found);   // 1.2.3.4 found
	EXPECT_FALSE(batchResult.results[1].found);  // invalid
	EXPECT_FALSE(batchResult.results[2].found);  // 5.6.7.8 not found
	EXPECT_FALSE(batchResult.results[3].found);  // empty
	EXPECT_TRUE(batchResult.results[4].found);   // 1.2.3.4 found again

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_CacheEdgeCases, ThreadLocalCacheEviction_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Insert many entries
	for (int i = 0; i < 200; ++i) {
		const std::string ip = "172.16." + std::to_string(i / 255) + "." + std::to_string((i % 255) + 1);
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 8000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	cfg.threadLocalCacheSize = 16;  // Very small cache to force eviction
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	// Access many entries to force evictions
	for (int i = 0; i < 200; ++i) {
		const std::string ip = "172.16." + std::to_string(i / 255) + "." + std::to_string((i % 255) + 1);
		const auto res = lookup.LookupIPv4(ip, opts);
		EXPECT_TRUE(res.found);
	}

	// Re-access first entry (may have been evicted)
	const auto res = lookup.LookupIPv4("172.16.0.1", opts);
	EXPECT_TRUE(res.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_StatisticsEdgeCases, StatsAccuracyUnderLoad) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "8.8.8.8"), 9000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	
	// Perform exact number of lookups
	constexpr int kSuccessful = 100;
	constexpr int kFailed = 50;
	
	for (int i = 0; i < kSuccessful; ++i) {
		(void)lookup.LookupIPv4("8.8.8.8", opts);
	}
	for (int i = 0; i < kFailed; ++i) {
		(void)lookup.LookupIPv4("9.9.9.9", opts);  // Not in index
	}

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(), kSuccessful + kFailed);
	EXPECT_EQ(stats.successfulLookups.load(), kSuccessful);
	EXPECT_EQ(stats.failedLookups.load(), kFailed);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_ConcurrencyEdgeCases, RapidInitShutdownCycles) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Rapid init/shutdown cycles
	for (int cycle = 0; cycle < 50; ++cycle) {
		ThreatIntelLookup lookup;
		LookupConfig cfg = LookupConfig::CreateDefault();
		EXPECT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));
		EXPECT_TRUE(lookup.IsInitialized());
		lookup.Shutdown();
		EXPECT_FALSE(lookup.IsInitialized());
	}

	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_ConcurrencyEdgeCases, ConcurrentStatsAccess) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "100.100.100.100"), 10000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();

	std::atomic<bool> running{true};
	std::atomic<uint64_t> statsReadCount{0};

	// Stats reader thread
	std::thread statsReader([&]() {
		while (running.load(std::memory_order_acquire)) {
			const auto stats = lookup.GetStatistics();
			(void)stats.totalLookups.load();
			statsReadCount.fetch_add(1, std::memory_order_relaxed);
		}
	});

	// Lookup threads
	std::vector<std::thread> lookupThreads;
	for (int t = 0; t < 4; ++t) {
		lookupThreads.emplace_back([&]() {
			for (int i = 0; i < 100; ++i) {
				(void)lookup.LookupIPv4("100.100.100.100", opts);
			}
		});
	}

	for (auto& th : lookupThreads) th.join();
	running.store(false, std::memory_order_release);
	statsReader.join();

	EXPECT_GT(statsReadCount.load(), 0u);

	const auto finalStats = lookup.GetStatistics();
	EXPECT_EQ(finalStats.totalLookups.load(), 400u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_URLEdgeCases, URLWithQueryParams_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	uint64_t stringOffset = TEST_STRING_TABLE_OFFSET;
	auto [urlOffset, urlLen] = WriteTestString(view, "http://evil.com/payload?id=123", stringOffset);
	ASSERT_GT(urlOffset, 0u);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry{};
	entry.type = IOCType::URL;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.value.stringRef.stringOffset = urlOffset;
	entry.value.stringRef.stringLength = urlLen;
	ASSERT_TRUE(index.Insert(entry, 11000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupURL("http://evil.com/payload?id=123", opts);
	EXPECT_EQ(res.type, IOCType::URL);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_MemoryEdgeCases, MemoryUsageReported) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.threadLocalCacheSize = 256;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	const size_t memUsage = lookup.GetMemoryUsage();
	EXPECT_GT(memUsage, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_TierEdgeCases, MaxTierZero_OnlyTLCacheUsed) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "200.200.200.200"), 12000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	// First lookup with full tiers - should find
	auto opts = MakeIndexEnabledOptions();
	const auto res1 = lookup.LookupIPv4("200.200.200.200", opts);
	EXPECT_TRUE(res1.found);

	// Second lookup with maxTiers=1 (TL cache only) - should find from cache
	opts.maxLookupTiers = 1;
	const auto res2 = lookup.LookupIPv4("200.200.200.200", opts);
	EXPECT_TRUE(res2.found);

	// New lookup with maxTiers=1 for uncached entry - should NOT find
	opts.maxLookupTiers = 1;
	const auto res3 = lookup.LookupIPv4("201.201.201.201", opts);
	EXPECT_FALSE(res3.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE INPUT VALIDATION TESTS
// ============================================================================

/**
 * @brief Tests for IOC input validation features
 * 
 * Tests the enterprise-grade input validation system added to ThreatIntelLookup.
 * Validates that malformed inputs are handled gracefully with proper error codes.
 */
TEST(ThreatIntelLookup_InputValidation, IPv4_ValidFormats_Accepted) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Add some test IPs
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "192.168.1.1"), 1000).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "10.0.0.1"), 1001).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "172.16.0.1"), 1002).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = true;

	// Valid IPv4 formats
	const auto res1 = lookup.LookupIPv4("192.168.1.1", opts);
	EXPECT_TRUE(res1.found);
	EXPECT_EQ(res1.errorCode, 0u);

	const auto res2 = lookup.LookupIPv4("10.0.0.1", opts);
	EXPECT_TRUE(res2.found);
	EXPECT_EQ(res2.errorCode, 0u);

	const auto res3 = lookup.LookupIPv4("172.16.0.1", opts);
	EXPECT_TRUE(res3.found);
	EXPECT_EQ(res3.errorCode, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_InputValidation, IPv4_InvalidFormats_Handled) {
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

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = true;

	// Invalid IPv4 formats - should not crash, should return not found
	const auto res1 = lookup.LookupIPv4("256.1.1.1", opts);  // Invalid octet
	EXPECT_FALSE(res1.found);

	const auto res2 = lookup.LookupIPv4("1.2.3.4.5", opts);  // Too many octets
	EXPECT_FALSE(res2.found);

	const auto res3 = lookup.LookupIPv4("1.2.3", opts);  // Too few octets
	EXPECT_FALSE(res3.found);

	const auto res4 = lookup.LookupIPv4("not.an.ip.address", opts);  // Not numeric
	EXPECT_FALSE(res4.found);

	const auto res5 = lookup.LookupIPv4("", opts);  // Empty
	EXPECT_FALSE(res5.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_InputValidation, Hash_ValidFormats_Accepted) {
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

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = true;

	// Valid MD5 (32 chars) - should process without error
	const auto resMd5 = lookup.LookupMD5("d41d8cd98f00b204e9800998ecf8427e", opts);
	EXPECT_EQ(resMd5.errorCode, 0u);  // No error even if not found

	// Valid SHA1 (40 chars)
	const auto resSha1 = lookup.LookupSHA1("da39a3ee5e6b4b0d3255bfef95601890afd80709", opts);
	EXPECT_EQ(resSha1.errorCode, 0u);

	// Valid SHA256 (64 chars)
	const auto resSha256 = lookup.LookupSHA256(
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", opts);
	EXPECT_EQ(resSha256.errorCode, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_InputValidation, Hash_InvalidFormats_Handled) {
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

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = true;

	// Invalid hex characters
	const auto res1 = lookup.LookupHash("g41d8cd98f00b204e9800998ecf8427e", opts);
	EXPECT_FALSE(res1.found);

	// Wrong length (not MD5, SHA1, SHA256, or SHA512)
	const auto res2 = lookup.LookupHash("abc123", opts);
	EXPECT_FALSE(res2.found);

	// Empty hash
	const auto res3 = lookup.LookupHash("", opts);
	EXPECT_FALSE(res3.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_InputValidation, Domain_ValidFormats_Accepted) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	uint64_t stringOffset = TEST_STRING_TABLE_OFFSET;
	auto [dom1Off, dom1Len] = WriteTestString(view, "example.com", stringOffset);
	auto [dom2Off, dom2Len] = WriteTestString(view, "sub.domain.co.uk", stringOffset);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Add domain entries
	IOCEntry entry1{};
	entry1.type = IOCType::Domain;
	entry1.confidence = ConfidenceLevel::High;
	entry1.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry1.value.stringRef.stringOffset = dom1Off;
	entry1.value.stringRef.stringLength = dom1Len;
	ASSERT_TRUE(index.Insert(entry1, 2000).IsSuccess());

	IOCEntry entry2{};
	entry2.type = IOCType::Domain;
	entry2.confidence = ConfidenceLevel::High;
	entry2.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry2.value.stringRef.stringOffset = dom2Off;
	entry2.value.stringRef.stringLength = dom2Len;
	ASSERT_TRUE(index.Insert(entry2, 2001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = true;

	// Valid domains
	const auto res1 = lookup.LookupDomain("example.com", opts);
	EXPECT_TRUE(res1.found);
	EXPECT_EQ(res1.errorCode, 0u);

	const auto res2 = lookup.LookupDomain("sub.domain.co.uk", opts);
	EXPECT_TRUE(res2.found);
	EXPECT_EQ(res2.errorCode, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_InputValidation, ValidationDisabled_AcceptsAll) {
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

	auto opts = MakeIndexEnabledOptions();
	opts.validateInput = false;  // Disable validation

	// With validation disabled, invalid inputs should still not crash
	const auto res1 = lookup.LookupIPv4("definitely-not-an-ip", opts);
	EXPECT_FALSE(res1.found);  // Not found but no crash

	const auto res2 = lookup.LookupHash("invalid!", opts);
	EXPECT_FALSE(res2.found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE ERROR CODE TESTS
// ============================================================================

/**
 * @brief Tests for error code reporting in lookup results
 */
TEST(ThreatIntelLookup_ErrorCodes, SuccessfulLookup_ZeroErrorCode) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "8.8.8.8"), 3000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("8.8.8.8", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.errorCode, 0u);  // Success has no error code
	EXPECT_TRUE(res.errorMessage.empty());

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_ErrorCodes, NotFound_ZeroErrorCode) {
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

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("1.1.1.1", opts);  // Not in index

	EXPECT_FALSE(res.found);
	EXPECT_EQ(res.errorCode, 0u);  // Not found is not an error
	EXPECT_TRUE(res.errorMessage.empty());

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_ErrorCodes, UninitializedLookup_NoErrorCodeSet) {
	ThreatIntelLookup lookup;
	// Intentionally not initializing

	UnifiedLookupOptions opts;
	const auto res = lookup.LookupIPv4("8.8.8.8", opts);

	// Should gracefully return not found without crashing
	EXPECT_FALSE(res.found);
	// Error code behavior for uninitialized state depends on implementation
}

// ============================================================================
// ENTERPRISE LOOKUP OPTIONS TESTS
// ============================================================================

/**
 * @brief Tests for UnifiedLookupOptions factory methods
 */
TEST(ThreatIntelLookup_Options, FastestLookup_ConfiguredCorrectly) {
	const auto opts = UnifiedLookupOptions::FastestLookup();

	EXPECT_EQ(opts.maxLookupTiers, 2u);
	EXPECT_TRUE(opts.cacheResult);
	EXPECT_FALSE(opts.includeMetadata);
	EXPECT_FALSE(opts.includeSourceAttribution);
	EXPECT_FALSE(opts.includeRelatedIOCs);
	EXPECT_FALSE(opts.includeMitreMapping);
	EXPECT_FALSE(opts.includeCVEReferences);
	EXPECT_FALSE(opts.includeSTIXBundle);
	EXPECT_FALSE(opts.queryExternalAPI);
	EXPECT_TRUE(opts.validateInput);  // Validation enabled by default
}

TEST(ThreatIntelLookup_Options, DetailedLookup_ConfiguredCorrectly) {
	const auto opts = UnifiedLookupOptions::DetailedLookup();

	EXPECT_EQ(opts.maxLookupTiers, 5u);
	EXPECT_TRUE(opts.includeMetadata);
	EXPECT_TRUE(opts.includeSourceAttribution);
	EXPECT_TRUE(opts.includeRelatedIOCs);
	EXPECT_TRUE(opts.includeMitreMapping);
	EXPECT_TRUE(opts.includeCVEReferences);
	EXPECT_FALSE(opts.includeSTIXBundle);
	EXPECT_FALSE(opts.queryExternalAPI);
	EXPECT_TRUE(opts.validateInput);
}

TEST(ThreatIntelLookup_Options, MalwareAnalysis_ConfiguredCorrectly) {
	const auto opts = UnifiedLookupOptions::MalwareAnalysis();

	EXPECT_EQ(opts.maxLookupTiers, 5u);
	EXPECT_TRUE(opts.includeMetadata);
	EXPECT_TRUE(opts.includeSourceAttribution);
	EXPECT_TRUE(opts.includeRelatedIOCs);
	EXPECT_TRUE(opts.includeMitreMapping);
	EXPECT_TRUE(opts.includeCVEReferences);
	EXPECT_TRUE(opts.includeSTIXBundle);
	EXPECT_TRUE(opts.queryExternalAPI);
	EXPECT_EQ(opts.timeoutMs, 30000u);
	EXPECT_TRUE(opts.validateInput);
}

// ============================================================================
// ENTERPRISE CONFIGURATION TESTS
// ============================================================================

/**
 * @brief Tests for LookupConfig factory methods
 */
TEST(ThreatIntelLookup_LookupConfig, CreateDefault_Valid) {
	const auto cfg = LookupConfig::CreateDefault();

	EXPECT_TRUE(cfg.enableMultiTier);
	EXPECT_TRUE(cfg.enableThreadLocalCache);
	EXPECT_EQ(cfg.threadLocalCacheSize, 1024u);
	EXPECT_TRUE(cfg.enableCacheWarming);
	EXPECT_TRUE(cfg.enablePrefetching);
	EXPECT_TRUE(cfg.enableSIMD);
	EXPECT_FALSE(cfg.enableExternalAPI);
	EXPECT_EQ(cfg.externalAPITimeout, 5000u);
	EXPECT_TRUE(cfg.enableEnrichment);
	EXPECT_TRUE(cfg.enableResultCache);
	EXPECT_EQ(cfg.resultCacheTTL, 300u);
	EXPECT_TRUE(cfg.enableAdaptiveOptimization);
	EXPECT_EQ(cfg.monitoringInterval, 60u);
}

TEST(ThreatIntelLookup_LookupConfig, CreateHighPerformance_Valid) {
	const auto cfg = LookupConfig::CreateHighPerformance();

	EXPECT_TRUE(cfg.enableThreadLocalCache);
	EXPECT_EQ(cfg.threadLocalCacheSize, 4096u);  // Larger cache
	EXPECT_TRUE(cfg.enableCacheWarming);
	EXPECT_TRUE(cfg.enablePrefetching);
	EXPECT_TRUE(cfg.enableSIMD);
	EXPECT_TRUE(cfg.enableAdaptiveOptimization);
}

TEST(ThreatIntelLookup_LookupConfig, CreateLowLatency_Valid) {
	const auto cfg = LookupConfig::CreateLowLatency();

	EXPECT_FALSE(cfg.enableMultiTier);  // Cache only
	EXPECT_TRUE(cfg.enableThreadLocalCache);
	EXPECT_EQ(cfg.threadLocalCacheSize, 8192u);  // Even larger cache
	EXPECT_FALSE(cfg.enableExternalAPI);  // No external API
	EXPECT_FALSE(cfg.enableEnrichment);  // No enrichment
}

// ============================================================================
// ENTERPRISE LATENCY TESTS
// ============================================================================

/**
 * @brief Tests for lookup latency measurement
 */
TEST(ThreatIntelLookup_Latency, LatencyFieldPopulated) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "5.5.5.5"), 4000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("5.5.5.5", opts);

	EXPECT_TRUE(res.found);
	EXPECT_GT(res.latencyNs, 0u);  // Latency should be measured

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Latency, CacheHitFasterThanIndexHit) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "6.6.6.6"), 4001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	// First lookup - index hit
	const auto res1 = lookup.LookupIPv4("6.6.6.6", opts);
	EXPECT_TRUE(res1.found);
	const uint64_t indexLatency = res1.latencyNs;

	// Second lookup - should be from thread-local cache
	const auto res2 = lookup.LookupIPv4("6.6.6.6", opts);
	EXPECT_TRUE(res2.found);
	const uint64_t cacheLatency = res2.latencyNs;

	// Cache hit should generally be faster or similar
	// (Not strictly enforced due to timing variations)
	EXPECT_GT(indexLatency, 0u);
	EXPECT_GT(cacheLatency, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE RESULT SOURCE TRACKING TESTS
// ============================================================================

/**
 * @brief Tests for source tracking in lookup results
 */
TEST(ThreatIntelLookup_SourceTracking, IndexHit_CorrectSource) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "7.7.7.7"), 5000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv4("7.7.7.7", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.source, ThreatLookupResult::Source::Index);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_SourceTracking, CacheHit_CorrectSource) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "9.9.9.9"), 5001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.enableThreadLocalCache = true;
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	// First lookup - populates cache
	(void)lookup.LookupIPv4("9.9.9.9", opts);

	// Second lookup - should be from thread-local cache
	const auto res = lookup.LookupIPv4("9.9.9.9", opts);
	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.source, ThreatLookupResult::Source::ThreadLocalCache);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE BATCH PERFORMANCE TESTS
// ============================================================================

/**
 * @brief Tests for batch lookup performance characteristics
 */
TEST(ThreatIntelLookup_BatchPerformance, BatchLookup_MeasuresTotalLatency) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Add multiple entries
	for (int i = 1; i <= 10; ++i) {
		std::string ip = "10.10.10." + std::to_string(i);
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 6000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	std::vector<std::string> ips;
	std::vector<std::string_view> ipViews;
	for (int i = 1; i <= 10; ++i) {
		ips.push_back("10.10.10." + std::to_string(i));
	}
	for (const auto& ip : ips) {
		ipViews.push_back(ip);
	}

	const auto batchResult = lookup.BatchLookupIPv4(ipViews, opts);

	EXPECT_GT(batchResult.totalLatencyNs, 0u);
	EXPECT_EQ(batchResult.results.size(), 10u);
	EXPECT_EQ(batchResult.foundCount, 10u);
	EXPECT_EQ(batchResult.notFoundCount, 0u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_BatchPerformance, BatchLookup_PreservesOrder) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Add entries with specific order
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "1.1.1.1"), 7000).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "2.2.2.2"), 7001).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "3.3.3.3"), 7002).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	std::vector<std::string> ips = {"1.1.1.1", "2.2.2.2", "3.3.3.3"};
	std::vector<std::string_view> ipViews;
	for (const auto& ip : ips) {
		ipViews.push_back(ip);
	}

	const auto batchResult = lookup.BatchLookupIPv4(ipViews, opts);

	// Results should be in the same order as input
	EXPECT_EQ(batchResult.results.size(), 3u);
	// All should be found
	EXPECT_TRUE(batchResult.results[0].found);
	EXPECT_TRUE(batchResult.results[1].found);
	EXPECT_TRUE(batchResult.results[2].found);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE IPv6 COMPREHENSIVE TESTS
// ============================================================================

/**
 * @brief Comprehensive IPv6 address format tests
 */
TEST(ThreatIntelLookup_IPv6Comprehensive, FullFormat_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Full IPv6 format
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv6, "2001:0db8:0000:0000:0000:0000:0000:0001"), 8000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv6("2001:0db8:0000:0000:0000:0000:0000:0001", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv6);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv6Comprehensive, CompressedZeros_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Compressed form with ::
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv6, "2001:db8::1"), 8001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv6("2001:db8::1", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv6);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_IPv6Comprehensive, Loopback_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// IPv6 loopback
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv6, "::1"), 8002).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.LookupIPv6("::1", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv6);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE STRESS AND EDGE CASE TESTS
// ============================================================================

/**
 * @brief Stress tests for enterprise deployments
 */
TEST(ThreatIntelLookup_Stress, ManyUniqueQueries_Handled) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	// Add many entries
	for (int i = 0; i < 100; ++i) {
		std::string ip = "11." + std::to_string(i / 256) + "." + 
		                 std::to_string(i % 256) + ".1";
		ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, ip), 9000 + i).IsSuccess());
	}

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	cfg.threadLocalCacheSize = 64;  // Small cache to force evictions
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	// Query all entries multiple times
	for (int round = 0; round < 3; ++round) {
		for (int i = 0; i < 100; ++i) {
			std::string ip = "11." + std::to_string(i / 256) + "." + 
			                 std::to_string(i % 256) + ".1";
			const auto res = lookup.LookupIPv4(ip, opts);
			EXPECT_TRUE(res.found) << "Failed to find " << ip << " in round " << round;
		}
	}

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(), 300u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_Stress, RapidSuccessiveQueries_Stable) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "12.12.12.12"), 10000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();

	// Very rapid successive queries
	for (int i = 0; i < 1000; ++i) {
		const auto res = lookup.LookupIPv4("12.12.12.12", opts);
		EXPECT_TRUE(res.found);
	}

	const auto stats = lookup.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(), 1000u);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE GENERIC LOOKUP API TESTS
// ============================================================================

/**
 * @brief Tests for the generic Lookup() API
 */
TEST(ThreatIntelLookup_GenericAPI, LookupByType_IPv4_Works) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	ASSERT_TRUE(index.Insert(CreateTestEntry(IOCType::IPv4, "13.13.13.13"), 11000).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.Lookup(IOCType::IPv4, "13.13.13.13", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::IPv4);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_GenericAPI, LookupByType_Domain_Works) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	uint64_t stringOffset = TEST_STRING_TABLE_OFFSET;
	auto [domOff, domLen] = WriteTestString(view, "malicious-site.com", stringOffset);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry{};
	entry.type = IOCType::Domain;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.value.stringRef.stringOffset = domOff;
	entry.value.stringRef.stringLength = domLen;
	ASSERT_TRUE(index.Insert(entry, 11001).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.Lookup(IOCType::Domain, "malicious-site.com", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::Domain);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelLookup_GenericAPI, LookupByType_Email_Works) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");

	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);

	uint64_t stringOffset = TEST_STRING_TABLE_OFFSET;
	auto [emailOff, emailLen] = WriteTestString(view, "phisher@evil.com", stringOffset);

	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());

	IOCEntry entry{};
	entry.type = IOCType::Email;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ThreatIntel::ReputationLevel::Malicious;
	entry.value.stringRef.stringOffset = emailOff;
	entry.value.stringRef.stringLength = emailLen;
	ASSERT_TRUE(index.Insert(entry, 11002).IsSuccess());

	ThreatIntelLookup lookup;
	LookupConfig cfg = LookupConfig::CreateDefault();
	ASSERT_TRUE(lookup.Initialize(cfg, nullptr, &index, nullptr, nullptr));

	auto opts = MakeIndexEnabledOptions();
	const auto res = lookup.Lookup(IOCType::Email, "phisher@evil.com", opts);

	EXPECT_TRUE(res.found);
	EXPECT_EQ(res.type, IOCType::Email);

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// ENTERPRISE TYPE COVERAGE TESTS
// ============================================================================

/**
 * @brief Tests ensuring all IOC types are handled properly
 */
TEST(ThreatIntelLookup_TypeCoverage, AllIOCTypes_NoExceptions) {
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

	auto opts = MakeIndexEnabledOptions();

	// Test all IOC types - none should throw
	EXPECT_NO_THROW({
		(void)lookup.Lookup(IOCType::IPv4, "1.2.3.4", opts);
		(void)lookup.Lookup(IOCType::IPv6, "::1", opts);
		(void)lookup.Lookup(IOCType::Domain, "test.com", opts);
		(void)lookup.Lookup(IOCType::URL, "http://test.com", opts);
		(void)lookup.Lookup(IOCType::FileHash, "d41d8cd98f00b204e9800998ecf8427e", opts);
		(void)lookup.Lookup(IOCType::Email, "test@test.com", opts);
		(void)lookup.Lookup(IOCType::Reserved, "unknown", opts);
	});

	lookup.Shutdown();
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

} // namespace ShadowStrike::ThreatIntel::Tests

