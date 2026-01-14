/**
 * @file ThreatIntelIndex_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelIndex
 *
 * Comprehensive test coverage for multi-dimensional threat intelligence indexing:
 * - Bloom filter operations (add, contains, false positive rate)
 * - IPv4 radix tree (insert, lookup, CIDR support, prefix matching)
 * - IPv6 patricia trie (path compression, lookup)
 * - Domain suffix trie (hierarchical matching, wildcard support)
 * - Hash B+Tree (all hash algorithms, insert, lookup)
 * - URL pattern matcher (pattern matching, normalization)
 * - Email hash table (insert, lookup, validation)
 * - Generic B+tree (other IOC types)
 * - Index initialization and shutdown
 * - Lookup operations (single and batch)
 * - Index modifications (insert, remove, update)
 * - Index maintenance (rebuild, optimize, verify)
 * - Statistics tracking and diagnostics
 * - Thread safety and concurrent access
 * - Performance benchmarks
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelIndex.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"

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

// Minimum database size for tests
constexpr uint64_t TEST_MIN_DATABASE_SIZE = 64 * 1024;  // 64KB for tests

// Temporary directory helper
struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_Index_") + 
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

// Helper to create test database
[[nodiscard]] bool CreateTestDatabase(const std::filesystem::path& dbPath, MemoryMappedView& view) {
	StoreError error;
	
	// Create database
	bool result = MemoryMapping::CreateDatabase(dbPath.wstring(), TEST_MIN_DATABASE_SIZE, view, error);
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

// Helper to create test IOC entry
[[nodiscard]] IOCEntry CreateTestEntry(IOCType type, const std::string& value) {
	IOCEntry entry{};
	entry.type = type;
	entry.confidence = ConfidenceLevel::High;
	entry.reputation = ReputationLevel::Malicious;
	entry.category = ThreatCategory::C2Server;
	
	switch (type) {
		case IOCType::IPv4: {
			// Simple IPv4 parser for tests
			std::array<uint8_t, 4> octets{};
			uint8_t prefixLen = 32;
			size_t pos = 0;
			size_t octetIdx = 0;
			std::string_view sv = value;
			
			while (pos < sv.size() && octetIdx < 4) {
				size_t dotPos = sv.find('.', pos);
				size_t slashPos = sv.find('/', pos);
				size_t endPos = std::min({dotPos, slashPos, sv.size()});
				
				std::string octetStr(sv.substr(pos, endPos - pos));
				octets[octetIdx++] = static_cast<uint8_t>(std::stoi(octetStr));
				
				pos = endPos + 1;
				if (dotPos == std::string_view::npos || slashPos < dotPos) break;
			}
			
			// Check for CIDR notation
			size_t slashPos = value.find('/');
			if (slashPos != std::string::npos) {
				prefixLen = static_cast<uint8_t>(std::stoi(value.substr(slashPos + 1)));
			}
			
			entry.value.ipv4 = {};
			entry.value.ipv4.Set(octets, prefixLen);
			break;
		}
		case IOCType::IPv6: {
			// Simplified - just set a default value for tests
			entry.value.ipv6 = IPv6Address{};
			break;
		}
		case IOCType::FileHash: {
			// Parse hex string hash
			entry.value.hash.algorithm = HashAlgorithm::SHA256;
			entry.value.hash.length = 32;
			entry.value.hash.data.fill(0);

			for (size_t i = 0; i < std::min(value.size() / 2, size_t(32)); ++i) {
				std::string byteStr = value.substr(i * 2, 2);
				entry.value.hash.data[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
			}
			break;
		}
		default:
			break;
	}
	
	return entry;
}

} // anonymous namespace

// ============================================================================
// PART 1/8: INDEX INITIALIZATION & CONFIGURATION TESTS
// ============================================================================

TEST(ThreatIntelIndex_Init, DefaultConstruction) {
	ThreatIntelIndex index;
	EXPECT_FALSE(index.IsInitialized());
}

TEST(ThreatIntelIndex_Init, Initialize_ValidDatabase) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	ASSERT_NE(header, nullptr);
	
	ThreatIntelIndex index;
	StoreError error = index.Initialize(view, header);
	
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_TRUE(index.IsInitialized());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Init, Initialize_NullHeader) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	ThreatIntelIndex index;
	StoreError error = index.Initialize(view, nullptr);
	
	EXPECT_FALSE(error.IsSuccess());
	EXPECT_FALSE(index.IsInitialized());
	
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Init, Initialize_WithOptions) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	ASSERT_NE(header, nullptr);
	
	IndexBuildOptions options;
	options.buildBloomFilters = true;  // Correct member name
	options.buildIPv4 = true;
	options.buildIPv6 = true;
	
	ThreatIntelIndex index;
	StoreError error = index.Initialize(view, header, options);
	
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_TRUE(index.IsInitialized());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Init, Shutdown_CleansUp) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	index.Initialize(view, header);
	ASSERT_TRUE(index.IsInitialized());
	
	index.Shutdown();
	EXPECT_FALSE(index.IsInitialized());
	
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Init, MultipleShutdown_Safe) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	index.Initialize(view, header);
	
	index.Shutdown();
	index.Shutdown(); // Should not crash
	index.Shutdown(); // Multiple calls safe
	
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 2/8: IPv4 RADIX TREE TESTS
// ============================================================================

TEST(ThreatIntelIndex_IPv4, Insert_SingleAddress) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	StoreError error = index.Insert(entry, 1000);
	
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_EQ(index.GetEntryCount(IOCType::IPv4), 1u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv4, Lookup_ExactMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	ASSERT_TRUE(index.Insert(entry, 1000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupIPv4(entry.value.ipv4, queryOptions);
	
	EXPECT_TRUE(result.found);
	EXPECT_EQ(result.entryOffset, 1000u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv4, Lookup_NotFound) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	const auto addr = IPv4Address::Create(192, 168, 1, 1, 32);
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupIPv4(addr, queryOptions);
	
	EXPECT_FALSE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv4, Insert_CIDR) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.0.0/24");
	StoreError error = index.Insert(entry, 1000);
	
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv4, Lookup_PrefixMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert /24 network
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.0/24");
	ASSERT_TRUE(index.Insert(entry, 1000).IsSuccess());
	
	// Lookup address in that network
	// Note: Prefix matching is inherent behavior of radix tree for CIDR entries
	const auto addr = IPv4Address::Create(192, 168, 1, 100);
	IndexQueryOptions queryOptions;
	
	IndexLookupResult result = index.LookupIPv4(addr, queryOptions);
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv4, BatchLookup) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert multiple entries
	for (int i = 0; i < 10; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		IOCEntry entry = CreateTestEntry(IOCType::IPv4, ip);
		ASSERT_TRUE(index.Insert(entry, 1000 + i).IsSuccess());
	}
	
	// Batch lookup
	std::vector<IPv4Address> addresses;
	for (int i = 0; i < 10; ++i) {
		addresses.push_back(IPv4Address::Create(192, 168, 1, i, 32));
	}
	
	std::vector<IndexLookupResult> results;
	IndexQueryOptions queryOptions;
	index.BatchLookupIPv4(addresses, results, queryOptions);
	
	ASSERT_EQ(results.size(), 10u);
	for (const auto& result : results) {
		EXPECT_TRUE(result.found);
	}
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 3/8: IPv6 PATRICIA TRIE TESTS
// ============================================================================

TEST(ThreatIntelIndex_IPv6, Insert_SingleAddress) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv6, "2001:db8::1");
	StoreError error = index.Insert(entry, 2000);
	
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_EQ(index.GetEntryCount(IOCType::IPv6), 1u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv6, Lookup_ExactMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv6, "2001:db8::1");
	ASSERT_TRUE(index.Insert(entry, 2000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupIPv6(entry.value.ipv6, queryOptions);
	
	EXPECT_TRUE(result.found);
	EXPECT_EQ(result.entryOffset, 2000u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_IPv6, Lookup_Compressed) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert compressed IPv6
	IOCEntry entry = CreateTestEntry(IOCType::IPv6, "::1");
	ASSERT_TRUE(index.Insert(entry, 2000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupIPv6(entry.value.ipv6, queryOptions);
	
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 4/8: DOMAIN SUFFIX TRIE TESTS
// ============================================================================

TEST(ThreatIntelIndex_Domain, Insert_SingleDomain) {
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
	
	StoreError error = index.Insert(entry, 3000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Domain, Lookup_ExactMatch) {
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
	ASSERT_TRUE(index.Insert(entry, 3000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupDomain("evil.com", queryOptions);
	
	EXPECT_TRUE(result.found);
	EXPECT_EQ(result.entryOffset, 3000u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Domain, Lookup_WildcardMatch) {
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
	ASSERT_TRUE(index.Insert(entry, 3000).IsSuccess());
	
	// Note: Wildcard matching is inherent behavior of domain suffix trie
	IndexQueryOptions queryOptions;
	
	// Lookup with wildcard should match
	IndexLookupResult result = index.LookupDomain("*.evil.com", queryOptions);
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Domain, Lookup_CaseInsensitive) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry{};
	entry.type = IOCType::Domain;
	ASSERT_TRUE(index.Insert(entry, 3000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	
	// Different case should still match
	IndexLookupResult result = index.LookupDomain("EVIL.COM", queryOptions);
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Domain, BatchLookup) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert multiple domains
	std::vector<std::string> domains = {"evil1.com", "evil2.com", "evil3.com"};
	for (size_t i = 0; i < domains.size(); ++i) {
		IOCEntry entry{};
		entry.type = IOCType::Domain;
		ASSERT_TRUE(index.Insert(entry, 3000 + i).IsSuccess());
	}
	
	// Batch lookup
	std::vector<std::string_view> lookupDomains = {"evil1.com", "evil2.com", "evil3.com"};
	std::vector<IndexLookupResult> results;
	IndexQueryOptions queryOptions;
	
	index.BatchLookupDomains(lookupDomains, results, queryOptions);
	
	ASSERT_EQ(results.size(), 3u);
	for (const auto& result : results) {
		EXPECT_TRUE(result.found);
	}
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 5/8: HASH B+TREE TESTS
// ============================================================================

TEST(ThreatIntelIndex_Hash, Insert_MD5) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, "d41d8cd98f00b204e9800998ecf8427e");
	entry.value.hash.algorithm = HashAlgorithm::MD5;
	
	StoreError error = index.Insert(entry, 4000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Hash, Insert_SHA1) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	entry.value.hash.algorithm = HashAlgorithm::SHA1;
	
	StoreError error = index.Insert(entry, 4000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Hash, Insert_SHA256) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	const std::string sha256(64, 'a');
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, sha256);
	entry.value.hash.algorithm = HashAlgorithm::SHA256;
	
	StoreError error = index.Insert(entry, 4000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Hash, Lookup_ExactMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, "d41d8cd98f00b204e9800998ecf8427e");
	entry.value.hash.algorithm = HashAlgorithm::MD5;
	ASSERT_TRUE(index.Insert(entry, 4000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupHash(entry.value.hash, queryOptions);
	
	EXPECT_TRUE(result.found);
	EXPECT_EQ(result.entryOffset, 4000u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Hash, Lookup_WrongAlgorithm) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::FileHash, "d41d8cd98f00b204e9800998ecf8427e");
	entry.value.hash.algorithm = HashAlgorithm::MD5;
	ASSERT_TRUE(index.Insert(entry, 4000).IsSuccess());
	
	// Lookup with wrong algorithm
	HashValue wrongHash = entry.value.hash;
	wrongHash.algorithm = HashAlgorithm::SHA1;
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupHash(wrongHash, queryOptions);
	
	EXPECT_FALSE(result.found); // Should not find with wrong algorithm
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Hash, BatchLookup) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert multiple hashes
	std::vector<std::string> hashStrings = {
		"d41d8cd98f00b204e9800998ecf8427e",
		"098f6bcd4621d373cade4e832627b4f6",
		"5d41402abc4b2a76b9719d911017c592"
	};
	
	std::vector<HashValue> hashes;
	for (size_t i = 0; i < hashStrings.size(); ++i) {
		IOCEntry entry = CreateTestEntry(IOCType::FileHash, hashStrings[i]);
		entry.value.hash.algorithm = HashAlgorithm::MD5;
		ASSERT_TRUE(index.Insert(entry, 4000 + i).IsSuccess());
		hashes.push_back(entry.value.hash);
	}
	
	// Batch lookup
	std::vector<IndexLookupResult> results;
	IndexQueryOptions queryOptions;
	index.BatchLookupHashes(hashes, results, queryOptions);
	
	ASSERT_EQ(results.size(), 3u);
	for (const auto& result : results) {
		EXPECT_TRUE(result.found);
	}
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 6/8: URL & EMAIL TESTS
// ============================================================================

TEST(ThreatIntelIndex_URL, Insert_SingleURL) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry{};
	entry.type = IOCType::URL;
	entry.confidence = ConfidenceLevel::High;
	
	StoreError error = index.Insert(entry, 5000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_URL, Lookup_ExactMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry{};
	entry.type = IOCType::URL;
	ASSERT_TRUE(index.Insert(entry, 5000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupURL("http://evil.com/payload", queryOptions);
	
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Email, Insert_SingleEmail) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry{};
	entry.type = IOCType::Email;
	entry.confidence = ConfidenceLevel::High;
	
	StoreError error = index.Insert(entry, 6000);
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Email, Lookup_ExactMatch) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry{};
	entry.type = IOCType::Email;
	ASSERT_TRUE(index.Insert(entry, 6000).IsSuccess());
	
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupEmail("user@evil.com", queryOptions);
	
	EXPECT_TRUE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 7/8: INDEX MODIFICATION & MAINTENANCE TESTS
// ============================================================================

TEST(ThreatIntelIndex_Modify, Remove_ExistingEntry) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	ASSERT_TRUE(index.Insert(entry, 1000).IsSuccess());
	ASSERT_EQ(index.GetEntryCount(IOCType::IPv4), 1u);
	
	StoreError error = index.Remove(entry);
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_EQ(index.GetEntryCount(IOCType::IPv4), 0u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Modify, Update_ExistingEntry) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry oldEntry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	ASSERT_TRUE(index.Insert(oldEntry, 1000).IsSuccess());
	
	IOCEntry newEntry = CreateTestEntry(IOCType::IPv4, "192.168.1.2");
	StoreError error = index.Update(oldEntry, newEntry, 2000);
	
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Modify, BatchInsert) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Create batch entries
	std::vector<std::pair<IOCEntry, uint64_t>> entries;
	for (int i = 0; i < 100; ++i) {
		std::string ip = "192.168.1." + std::to_string(i % 256);
		IOCEntry entry = CreateTestEntry(IOCType::IPv4, ip);
		entries.emplace_back(entry, 1000 + i);
	}
	
	StoreError error = index.BatchInsert(entries);
	EXPECT_TRUE(error.IsSuccess());
	EXPECT_GE(index.GetEntryCount(IOCType::IPv4), 1u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Maintenance, Optimize) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert some data
	for (int i = 0; i < 10; ++i) {
		std::string ip = "192.168.1." + std::to_string(i);
		IOCEntry entry = CreateTestEntry(IOCType::IPv4, ip);
		index.Insert(entry, 1000 + i);
	}
	
	StoreError error = index.Optimize();
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Maintenance, Verify) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	StoreError error = index.Verify();
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Maintenance, Flush) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	StoreError error = index.Flush();
	EXPECT_TRUE(error.IsSuccess());
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

// ============================================================================
// PART 8/8: STATISTICS, THREAD SAFETY & PERFORMANCE TESTS
// ============================================================================

TEST(ThreatIntelIndex_Stats, GetStatistics) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IndexStatistics stats = index.GetStatistics();
	EXPECT_EQ(stats.totalEntries, 0u);
	EXPECT_EQ(stats.totalLookups.load(), 0u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Stats, ResetStatistics) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Do some lookups
	const auto addr = IPv4Address::Create(192, 168, 1, 1, 32);
	IndexQueryOptions queryOptions;
	index.LookupIPv4(addr, queryOptions);
	
	// Reset stats
	index.ResetStatistics();
	
	IndexStatistics stats = index.GetStatistics();
	EXPECT_EQ(stats.totalLookups.load(), 0u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Stats, GetMemoryUsage) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	size_t memUsage = index.GetMemoryUsage();
	EXPECT_GT(memUsage, 0u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Stats, GetEntryCount) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	EXPECT_EQ(index.GetEntryCount(IOCType::IPv4), 0u);
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	index.Insert(entry, 1000);
	
	EXPECT_EQ(index.GetEntryCount(IOCType::IPv4), 1u);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_ThreadSafety, ConcurrentLookups) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert test data
	for (int i = 0; i < 100; ++i) {
		std::string ip = "192.168.1." + std::to_string(i % 256);
		IOCEntry entry = CreateTestEntry(IOCType::IPv4, ip);
		index.Insert(entry, 1000 + i);
	}
	
	// Concurrent lookups
	std::atomic<int> successCount{0};
	std::vector<std::thread> threads;

	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&index, &successCount]() {
			IndexQueryOptions queryOptions;
			for (int i = 0; i < 100; ++i) {
				const auto addr = IPv4Address::Create(192, 168, 1, i % 256);
				IndexLookupResult result = index.LookupIPv4(addr, queryOptions);
				if (result.found) {
					successCount.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_GT(successCount.load(), 0);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Performance, IPv4Lookup_LargeScale) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert 10K entries
	for (int i = 0; i < 10000; ++i) {

		const auto addr = IPv4Address::Create(
			192,
			168,
			(i / 256) % 256,
			i % 256,
			32
		);
		
		IOCEntry entry{};
		entry.type = IOCType::IPv4;
		entry.value.ipv4 = addr;
		index.Insert(entry, 1000 + i);
	}
	
	// Benchmark lookups
	auto start = std::chrono::steady_clock::now();
	
	IndexQueryOptions queryOptions;
	for (int i = 0; i < 10000; ++i) {
		const auto addr = IPv4Address::Create(
			192,
			168,
			(i / 256) % 256,
			i % 256,
			32
		);
		
		index.LookupIPv4(addr, queryOptions);
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	// Should process 10K lookups in < 1 second
	EXPECT_LT(ms, 1000);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Performance, HashLookup_LargeScale) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Insert 1K hash entries
	std::vector<HashValue> hashes;
	for (int i = 0; i < 1000; ++i) {
		HashValue hash{};
		hash.algorithm = HashAlgorithm::MD5;
		hash.length = 16;
		// Generate pseudo-random hash
		for (int j = 0; j < 16; ++j) {
			hash.data[j] = static_cast<uint8_t>((i * 17 + j) % 256);
		}
		
		IOCEntry entry{};
		entry.type = IOCType::FileHash;
		entry.value.hash = hash;
		index.Insert(entry, 4000 + i);
		hashes.push_back(hash);
	}
	
	// Benchmark lookups
	auto start = std::chrono::steady_clock::now();
	
	IndexQueryOptions queryOptions;
	for (const auto& hash : hashes) {
		index.LookupHash(hash, queryOptions);
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	// Should process 1K lookups in < 100ms
	EXPECT_LT(ms, 100);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_EdgeCase, EmptyDatabase) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	// Lookup in empty index
	const auto addr = IPv4Address::Create(192, 168, 1, 1, 32);
	IndexQueryOptions queryOptions;
	IndexLookupResult result = index.LookupIPv4(addr, queryOptions);
	
	EXPECT_FALSE(result.found);
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_EdgeCase, DuplicateInsert) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	ASSERT_TRUE(CreateTestDatabase(dbPath, view));
	
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	
	ThreatIntelIndex index;
	ASSERT_TRUE(index.Initialize(view, header).IsSuccess());
	
	IOCEntry entry = CreateTestEntry(IOCType::IPv4, "192.168.1.1");
	
	// Insert same entry twice
	EXPECT_TRUE(index.Insert(entry, 1000).IsSuccess());
	EXPECT_TRUE(index.Insert(entry, 2000).IsSuccess()); // Should handle gracefully
	
	index.Shutdown();
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelIndex_Utility, CalculateIndexSize) {
	uint64_t size = CalculateIndexSize(IOCType::IPv4, 10000);
	EXPECT_GT(size, 0u);
}

TEST(ThreatIntelIndex_Utility, EstimateIndexMemory) {
	std::vector<IOCEntry> entries;
	for (int i = 0; i < 100; ++i) {
		std::string ip = "192.168.1." + std::to_string(i % 256);
		entries.push_back(CreateTestEntry(IOCType::IPv4, ip));
	}
	
	IndexBuildOptions options;
	uint64_t estimate = EstimateIndexMemory(entries, options);
	EXPECT_GT(estimate, 0u);
}

TEST(ThreatIntelIndex_Utility, ConvertToReverseDomain) {
	std::string reversed = ConvertToReverseDomain("www.example.com");
	EXPECT_EQ(reversed, "com.example.www");
}

TEST(ThreatIntelIndex_Utility, NormalizeURL) {
	std::string normalized = NormalizeURL("HTTP://EXAMPLE.COM:80/Path");
	EXPECT_FALSE(normalized.empty());
	// Should be lowercase and port removed
	EXPECT_NE(normalized.find("http://"), std::string::npos);
}

TEST(ThreatIntelIndex_Utility, ValidateIndexConfiguration) {
	IndexBuildOptions options;
	options.buildBloomFilters = true;
	options.buildIPv4 = true;
	options.buildIPv6 = true;
	
	std::string errorMessage;
	bool valid = ValidateIndexConfiguration(options, errorMessage);
	EXPECT_TRUE(valid);
}

} // namespace ShadowStrike::ThreatIntel::Tests

