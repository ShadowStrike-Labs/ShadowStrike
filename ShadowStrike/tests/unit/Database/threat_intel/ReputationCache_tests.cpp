
/**
 * @file ReputationCache_tests.cpp
 * @brief Comprehensive Enterprise-Grade Unit Tests for ThreatIntel ReputationCache
 *
 * Coverage goals (unit-level, no external IO):
 * - BloomFilter: parameter clamping, Add/MightContain/Clear, fill-rate sanity, concurrency
 * - CacheShard: invalid inputs, CRUD, TTL expiration, EvictExpired, LRU eviction behavior
 * - ReputationCache: lifecycle (Initialize/Shutdown), invalid options, insert/lookup per IOC type,
 *   negative caching, TTL clamp via setters, bloom fast-path behavior, Clear/EvictExpired,
 *   BatchLookup contract, PreWarm (values + callback), statistics sanity, concurrency smoke
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ReputationCache.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include<span>
#include <limits>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace ShadowStrike::ThreatIntel;

namespace {

[[nodiscard]] uint32_t NowUnixSeconds() noexcept {
	using namespace std::chrono;
	return static_cast<uint32_t>(
		duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

[[nodiscard]] CacheOptions MakeSmallOptions(bool bloomEnabled = true) {
	CacheOptions opt{};
	opt.shardCount = 8;                 // power of 2
	opt.totalCapacity = 256;            // >= shardCount
	opt.positiveTTL = CacheConfig::MIN_TTL_SECONDS;
	opt.negativeTTL = CacheConfig::MIN_TTL_SECONDS;
	opt.enableBloomFilter = bloomEnabled;
	opt.bloomExpectedElements = 512;
	opt.bloomFalsePositiveRate = 0.01;
	opt.enableStatistics = true;
	opt.enableAutoEviction = false;
	opt.autoEvictionIntervalSeconds = 60;
	return opt;
}

[[nodiscard]] LookupResult MakeFoundResult(
	IOCType type,
	ReputationLevel rep = ReputationLevel::Malicious,
	ConfidenceLevel conf = ConfidenceLevel::High,
	ThreatCategory cat = ThreatCategory::Malware,
	ThreatIntelSource src = ThreatIntelSource::CrowdStrike,
	bool shouldBlock = true,
	bool shouldAlert = true) {
	LookupResult r{};
	r.found = true;
	r.entryId = 42;
	r.type = type;
	r.reputation = rep;
	r.confidence = conf;
	r.category = cat;
	r.source = src;
	r.shouldBlock = shouldBlock;
	r.shouldAlert = shouldAlert;
	r.lookupTimeNs = 123;
	return r;
}

[[nodiscard]] CacheValue MakePositiveValue(uint32_t ttlSeconds) {
	return CacheValue(MakeFoundResult(IOCType::Domain), ttlSeconds);
}

[[nodiscard]] HashValue MakeHash(HashAlgorithm algo, uint8_t fillByte = 0xAB) {
	const uint8_t len = GetHashLength(algo);
	std::array<uint8_t, 72> buf{};
	buf.fill(0);
	for (size_t i = 0; i < len && i < buf.size(); ++i) {
		buf[i] = static_cast<uint8_t>(fillByte + static_cast<uint8_t>(i));
	}
	HashValue result{};
	result.Set(algo, buf.data(), len);
	return result;
}

} // namespace

// ============================================================================
// BloomFilter Unit Tests
// ============================================================================

TEST(BloomFilterTests, Construction_ClampsInvalidParameters) {
	BloomFilter bfZero(0, -1.0);
	EXPECT_GE(bfZero.GetBitCount(), 64u);
	EXPECT_GT(bfZero.GetByteCount(), 0u);
	EXPECT_EQ(bfZero.GetHashFunctions(), CacheConfig::BLOOM_HASH_FUNCTIONS);

	BloomFilter bfHuge(std::numeric_limits<size_t>::max(), 2.0);
	EXPECT_GE(bfHuge.GetBitCount(), 64u);
	EXPECT_GT(bfHuge.GetByteCount(), 0u);
}

TEST(BloomFilterTests, Add_InvalidKey_NoEffect) {
	BloomFilter bf(64, 0.01);
	const size_t before = bf.GetElementCount();
	bf.Add(CacheKey{});
	EXPECT_EQ(bf.GetElementCount(), before);
}

TEST(BloomFilterTests, MightContain_InvalidKey_False) {
	BloomFilter bf(64, 0.01);
	EXPECT_FALSE(bf.MightContain(CacheKey{}));
}

TEST(BloomFilterTests, AddAndMightContain_BasicBehavior) {
	BloomFilter bf(128, 0.01);
	CacheKey k1(IOCType::Domain, "example.com");
	CacheKey k2(IOCType::Domain, "example.org");

	EXPECT_FALSE(bf.MightContain(k1));
	bf.Add(k1);
	EXPECT_TRUE(bf.MightContain(k1));

	// Not guaranteed false (bloom), but very likely with empty->single insertion.
	// We only assert it doesn't spuriously become true after Clear.
	bf.Clear();
	EXPECT_EQ(bf.GetElementCount(), 0u);
	EXPECT_FALSE(bf.MightContain(k1));
	EXPECT_FALSE(bf.MightContain(k2));
}

TEST(BloomFilterTests, EstimateRates_SaneRanges) {
	BloomFilter bf(256, 0.01);
	EXPECT_GE(bf.EstimateFillRate(), 0.0);
	EXPECT_LE(bf.EstimateFillRate(), 1.0);
	EXPECT_GE(bf.EstimateFalsePositiveRate(), 0.0);
	EXPECT_LE(bf.EstimateFalsePositiveRate(), 1.0);

	CacheKey k(IOCType::URL, "https://example.com/path");
	for (int i = 0; i < 100; ++i) {
		bf.Add(k);
		// Mutate key slightly to avoid pure duplicates
		k.data[0] = static_cast<uint8_t>(k.data[0] + 1);
		k.ComputeHash();
	}
	const double fill = bf.EstimateFillRate();
	const double fpr = bf.EstimateFalsePositiveRate();
	EXPECT_GE(fill, 0.0);
	EXPECT_LE(fill, 1.0);
	EXPECT_GE(fpr, 0.0);
	EXPECT_LE(fpr, 1.0);
}

TEST(BloomFilterTests, Concurrency_ConcurrentAddsAndReads_NoCrash) {
	BloomFilter bf(4096, 0.01);
	constexpr int kThreads = 4;
	constexpr int kIters = 2000;
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	std::atomic<bool> start{false};
	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kIters; ++i) {
				CacheKey key(IOCType::Domain, "t" + std::to_string(t) + "-" + std::to_string(i));
				bf.Add(key);
				(void)bf.MightContain(key);
			}
		});
	}
	start.store(true, std::memory_order_release);
	for (auto& th : threads) {
		th.join();
	}
	EXPECT_GT(bf.GetElementCount(), 0u);
}

// ============================================================================
// CacheShard Unit Tests
// ============================================================================

TEST(CacheShardTests, Construction_ClampsMinimumCapacity) {
	CacheShard shard(0);
	EXPECT_GE(shard.GetCapacity(), 1u);
	EXPECT_EQ(shard.GetEntryCount(), 0u);
}

TEST(CacheShardTests, InvalidKey_OperationsReturnFalse) {
	CacheShard shard(8);
	CacheValue out{};
	EXPECT_FALSE(shard.Lookup(CacheKey{}, out));
	EXPECT_FALSE(shard.Contains(CacheKey{}));
	EXPECT_FALSE(shard.Insert(CacheKey{}, CacheValue::NegativeResult(CacheConfig::MIN_TTL_SECONDS)));
	EXPECT_FALSE(shard.Remove(CacheKey{}));
}

TEST(CacheShardTests, InsertLookupRemove_BasicCRUD) {
	CacheShard shard(8);
	CacheKey key(IOCType::Domain, "example.com");
	CacheValue in = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);
	ASSERT_TRUE(shard.Insert(key, in));
	EXPECT_TRUE(shard.Contains(key));

	CacheValue out{};
	ASSERT_TRUE(shard.Lookup(key, out));
	EXPECT_EQ(out.reputation, in.reputation);
	EXPECT_EQ(out.confidence, in.confidence);
	EXPECT_EQ(out.category, in.category);
	EXPECT_EQ(out.source, in.source);
	EXPECT_EQ(out.shouldBlock, in.shouldBlock);
	EXPECT_EQ(out.shouldAlert, in.shouldAlert);
	EXPECT_TRUE(out.isPositive);

	EXPECT_TRUE(shard.Remove(key));
	EXPECT_FALSE(shard.Contains(key));
	EXPECT_FALSE(shard.Lookup(key, out));
}

TEST(CacheShardTests, Expiration_LookupRemovesExpiredEntry) {
	CacheShard shard(8);
	CacheKey key(IOCType::URL, "https://expired.example/path");
	CacheValue v = CacheValue::NegativeResult(CacheConfig::MIN_TTL_SECONDS);
	const uint32_t now = NowUnixSeconds();
	v.insertionTime = now - 120;
	v.expirationTime = now - 1;

	ASSERT_TRUE(shard.Insert(key, v));
	CacheValue out{};
	EXPECT_FALSE(shard.Lookup(key, out));
	EXPECT_FALSE(shard.Contains(key));
}

TEST(CacheShardTests, EvictExpired_RemovesExpiredEntries) {
	CacheShard shard(16);
	const uint32_t now = NowUnixSeconds();
	for (int i = 0; i < 10; ++i) {
		CacheKey key(IOCType::Domain, "e" + std::to_string(i) + ".example");
		CacheValue v = CacheValue::NegativeResult(CacheConfig::MIN_TTL_SECONDS);
		v.insertionTime = now - 100;
		v.expirationTime = now - 1;
		ASSERT_TRUE(shard.Insert(key, v));
	}
	const size_t evicted = shard.EvictExpired();
	EXPECT_GE(evicted, 1u);
	EXPECT_EQ(shard.GetEntryCount(), 0u);
}

TEST(CacheShardTests, LRU_EvictionPrefersLeastRecentlyUsed) {
	CacheShard shard(2);
	CacheKey a(IOCType::Domain, "a.example");
	CacheKey b(IOCType::Domain, "b.example");
	CacheKey c(IOCType::Domain, "c.example");
	CacheValue v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);

	ASSERT_TRUE(shard.Insert(a, v));
	ASSERT_TRUE(shard.Insert(b, v));

	// Touch A -> B becomes LRU
	CacheValue out{};
	ASSERT_TRUE(shard.Lookup(a, out));

	ASSERT_TRUE(shard.Insert(c, v));

	EXPECT_TRUE(shard.Contains(a));
	EXPECT_TRUE(shard.Contains(c));
	EXPECT_FALSE(shard.Contains(b));
}

TEST(CacheShardTests, Clear_ResetsState) {
	CacheShard shard(8);
	CacheValue v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);
	ASSERT_TRUE(shard.Insert(CacheKey(IOCType::Domain, "x.example"), v));
	ASSERT_TRUE(shard.Insert(CacheKey(IOCType::Domain, "y.example"), v));
	EXPECT_GT(shard.GetEntryCount(), 0u);
	shard.Clear();
	EXPECT_EQ(shard.GetEntryCount(), 0u);
}

// ============================================================================
// ReputationCache Unit Tests
// ============================================================================

class ReputationCacheTestFixture : public ::testing::Test {
protected:
	void TearDown() override {
		// Ensure shutdown is always safe/idempotent
		cache.Shutdown();
	}

	ReputationCache cache;
};

TEST_F(ReputationCacheTestFixture, Lifecycle_ShutdownBeforeInitialize_NoCrash) {
	EXPECT_FALSE(cache.IsInitialized());
	cache.Shutdown();
	EXPECT_FALSE(cache.IsInitialized());
}

TEST_F(ReputationCacheTestFixture, Initialize_DefaultOptions_Succeeds) {
	StoreError err = cache.Initialize();
	ASSERT_TRUE(err.IsSuccess()) << err.GetFullMessage();
	EXPECT_TRUE(cache.IsInitialized());
}

TEST(ReputationCacheTests, Initialize_InvalidOptions_FailsValidation) {
	CacheOptions opt = MakeSmallOptions(true);
	opt.shardCount = 3; // not power-of-two

	ReputationCache c(opt);
	StoreError err = c.Initialize();
	EXPECT_FALSE(err.IsSuccess());
	EXPECT_EQ(err.code, ThreatIntelError::InvalidEntry);
	EXPECT_FALSE(c.IsInitialized());
}

TEST(ReputationCacheTests, Initialize_DoubleInitialize_IsIdempotent) {
	ReputationCache c(MakeSmallOptions(true));
	ASSERT_TRUE(c.Initialize().IsSuccess());
	ASSERT_TRUE(c.IsInitialized());
	EXPECT_TRUE(c.Initialize().IsSuccess());
	EXPECT_TRUE(c.IsInitialized());
}

TEST(ReputationCacheTests, Lookup_Uninitialized_ReturnsFalseAndDoesNotClobberOutput) {
	ReputationCache c(MakeSmallOptions(true));
	CacheValue sentinel{};
	sentinel.entryId = 0xDEADBEEF;
	sentinel.reputation = ReputationLevel::Critical;
	const CacheKey key(IOCType::Domain, "example.com");
	EXPECT_FALSE(c.Lookup(key, sentinel));
	EXPECT_EQ(sentinel.entryId, 0xDEADBEEF);
	EXPECT_EQ(sentinel.reputation, ReputationLevel::Critical);
}

TEST(ReputationCacheTests, InsertLookup_AllSupportedKeyTypes) {
	ReputationCache c(MakeSmallOptions(true));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	const uint32_t ttl = CacheConfig::MIN_TTL_SECONDS;
	const CacheValue v = CacheValue(MakeFoundResult(IOCType::Domain), ttl);

	// IPv4
	const auto addr_4 = IPv4Address::Create(8, 8, 8, 8);
	c.Insert(addr_4, v);
	CacheValue out{};
	EXPECT_TRUE(c.Lookup(addr_4, out));
	EXPECT_EQ(out.reputation, v.reputation);
	EXPECT_TRUE(out.isPositive);

	// IPv6
	const auto addr_6 = IPv6Address::Create(0x20010DB800000000ULL, 0x0000000000000001ULL);
	c.Insert(addr_6, v);
	EXPECT_TRUE(c.Lookup(addr_6, out));

	// Hash
	HashValue hv = MakeHash(HashAlgorithm::SHA256, 0x11);
	c.Insert(hv, v);
	EXPECT_TRUE(c.Lookup(hv, out));

	// Domain
	c.InsertDomain("evil.example", v);
	EXPECT_TRUE(c.LookupDomain("evil.example", out));

	// URL
	c.InsertURL("https://evil.example/path", v);
	EXPECT_TRUE(c.LookupURL("https://evil.example/path", out));

	// Email
	c.InsertEmail("attacker@evil.example", v);
	EXPECT_TRUE(c.LookupEmail("attacker@evil.example", out));
}

TEST(ReputationCacheTests, StringKeys_EmptyString_IsRejected) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());
	const CacheValue v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);

	c.InsertDomain("", v);
	c.InsertURL("", v);
	c.InsertEmail("", v);
	EXPECT_EQ(c.GetEntryCount(), 0u);

	CacheValue out{};
	EXPECT_FALSE(c.LookupDomain("", out));
	EXPECT_FALSE(c.LookupURL("", out));
	EXPECT_FALSE(c.LookupEmail("", out));
}

TEST(ReputationCacheTests, StringKeys_LongString_IsTruncatedConsistently) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	std::string longDomain(200, 'a');
	longDomain.replace(0, 12, "example-long");
	const CacheValue v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);

	c.InsertDomain(longDomain, v);
	CacheValue out{};
	EXPECT_TRUE(c.LookupDomain(longDomain, out));
}

TEST(ReputationCacheTests, InsertNegative_RespectsNegativeTTL_AndLookupReturnsNegativeValue) {
	CacheOptions opt = MakeSmallOptions(false);
	ReputationCache c(opt);
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheKey key(IOCType::Domain, "notfound.example");
	c.SetNegativeTTL(CacheConfig::MIN_TTL_SECONDS);
	c.InsertNegative(key);

	CacheValue out{};
	ASSERT_TRUE(c.Lookup(key, out));
	EXPECT_FALSE(out.isPositive);
	EXPECT_EQ(out.reputation, ReputationLevel::Unknown);
	EXPECT_EQ(out.expirationTime - out.insertionTime, CacheConfig::MIN_TTL_SECONDS);
}

TEST(ReputationCacheTests, TTL_SettersClampToConfigRange_AffectsNewInsertionsOnly) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheKey k1(IOCType::Domain, "k1.example");
	LookupResult r1 = MakeFoundResult(IOCType::Domain);

	// Clamp below min
	c.SetPositiveTTL(1);
	c.Insert(k1, r1);
	CacheValue v1{};
	ASSERT_TRUE(c.Lookup(k1, v1));
	EXPECT_TRUE(v1.isPositive);
	EXPECT_EQ(v1.expirationTime - v1.insertionTime, CacheConfig::MIN_TTL_SECONDS);

	// Existing entry should remain with original TTL even after setter change.
	c.SetPositiveTTL(CacheConfig::MAX_TTL_SECONDS);
	CacheValue v1Again{};
	ASSERT_TRUE(c.Lookup(k1, v1Again));
	EXPECT_EQ(v1Again.expirationTime - v1Again.insertionTime, CacheConfig::MIN_TTL_SECONDS);

	CacheKey k2(IOCType::Domain, "k2.example");
	LookupResult r2 = MakeFoundResult(IOCType::Domain);
	c.Insert(k2, r2);
	CacheValue v2{};
	ASSERT_TRUE(c.Lookup(k2, v2));
	EXPECT_EQ(v2.expirationTime - v2.insertionTime, CacheConfig::MAX_TTL_SECONDS);
}

TEST(ReputationCacheTests, BloomFilter_MightContainAndLookupFastPath) {
	ReputationCache c(MakeSmallOptions(true));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheKey key(IOCType::Domain, "bloom.example");
	CacheValue out{};

	// Empty bloom => definitely not contained
	EXPECT_FALSE(c.MightContain(key));
	EXPECT_FALSE(c.Lookup(key, out));

	// Invalid key => MightContain returns true (by contract)
	EXPECT_TRUE(c.MightContain(CacheKey{}));

	// After insert => bloom must accept, and lookup must succeed
	const CacheValue v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);
	c.Insert(key, v);
	EXPECT_TRUE(c.MightContain(key));
	EXPECT_TRUE(c.Lookup(key, out));
}

TEST(ReputationCacheTests, Clear_ResetsEntriesAndBloomAndCounters) {
	ReputationCache c(MakeSmallOptions(true));
	ASSERT_TRUE(c.Initialize().IsSuccess());
	const CacheKey key(IOCType::Domain, "clear.example");
	c.Insert(key, MakePositiveValue(CacheConfig::MIN_TTL_SECONDS));
	EXPECT_EQ(c.GetEntryCount(), 1u);

	CacheStatistics before = c.GetStatistics();
	EXPECT_GE(before.totalCapacity, 1u);

	c.Clear();
	EXPECT_EQ(c.GetEntryCount(), 0u);
	CacheValue out{};
	EXPECT_FALSE(c.Lookup(key, out));
	EXPECT_FALSE(c.MightContain(key));

	CacheStatistics after = c.GetStatistics();
	EXPECT_EQ(after.totalEntries, 0u);
	EXPECT_EQ(after.bloomRejects, 0u);
}

TEST(ReputationCacheTests, EvictExpired_RemovesExpiredAcrossShards) {
	CacheOptions opt = MakeSmallOptions(false);
	opt.shardCount = 1;
	opt.totalCapacity = 16;
	ReputationCache c(opt);
	ASSERT_TRUE(c.Initialize().IsSuccess());

	const uint32_t now = NowUnixSeconds();
	for (int i = 0; i < 10; ++i) {
		CacheKey k(IOCType::Domain, "expired-" + std::to_string(i));
		CacheValue v = CacheValue::NegativeResult(CacheConfig::MIN_TTL_SECONDS);
		v.insertionTime = now - 100;
		v.expirationTime = now - 1;
		c.Insert(k, v);
	}
	EXPECT_EQ(c.GetEntryCount(), 10u);
	const size_t evicted = c.EvictExpired();
	EXPECT_GE(evicted, 1u);
	EXPECT_EQ(c.GetEntryCount(), 0u);
}
TEST(ReputationCacheTests, BatchLookup_SizeMismatch_IsNoOp) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	std::vector<CacheKey> keys;
	keys.emplace_back(IOCType::Domain, "a");
	keys.emplace_back(IOCType::Domain, "b");
	std::vector<CacheValue> values(1);

	auto buffer = std::make_unique<bool[]>(1);
	buffer[0] = true;
	std::span<bool> found(buffer.get(), 1);

	c.BatchLookup(keys, values, found);
	EXPECT_TRUE(found[0]);
}

TEST(ReputationCacheTests, BatchLookup_FindsInsertedEntries) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheKey a(IOCType::Domain, "a.example");
	CacheKey b(IOCType::Domain, "b.example");
	CacheKey cKey(IOCType::Domain, "c.example");
	c.Insert(a, MakePositiveValue(CacheConfig::MIN_TTL_SECONDS));
	c.Insert(cKey, MakePositiveValue(CacheConfig::MIN_TTL_SECONDS));

	std::vector<CacheKey> keys{ a, b, cKey };
	std::vector<CacheValue> values(keys.size());

	auto buffer = std::make_unique<bool[]>(keys.size());
	std::fill_n(buffer.get(), keys.size(), false);
	std::span<bool> found(buffer.get(), keys.size());

	c.BatchLookup(keys, values, found);

	EXPECT_TRUE(found[0]);
	EXPECT_FALSE(found[1]);
	EXPECT_TRUE(found[2]);
}



TEST(ReputationCacheTests, PreWarm_WithValues_InsertsMinCount) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheKey a(IOCType::Domain, "a.example");
	CacheKey b(IOCType::Domain, "b.example");
	CacheKey cKey(IOCType::Domain, "c.example");

	std::vector<CacheKey> keys{a, b, cKey};
	std::vector<CacheValue> values{MakePositiveValue(CacheConfig::MIN_TTL_SECONDS),
								   MakePositiveValue(CacheConfig::MIN_TTL_SECONDS)};
	c.PreWarm(keys, values);

	CacheValue out{};
	EXPECT_TRUE(c.Lookup(a, out));
	EXPECT_TRUE(c.Lookup(b, out));
	EXPECT_FALSE(c.Lookup(cKey, out));
}

TEST(ReputationCacheTests, PreWarm_Callback_NullOrSelectiveInsert) {
	ReputationCache c(MakeSmallOptions(false));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	std::vector<CacheKey> keys;
	keys.emplace_back(IOCType::Domain, "a.example");
	keys.emplace_back(IOCType::Domain, "b.example");

	// Null callback -> no-op
	c.PreWarm(keys, ReputationCache::PreWarmCallback{});
	EXPECT_EQ(c.GetEntryCount(), 0u);

	// Selectively insert only one
	c.PreWarm(keys, [&](const CacheKey& k, CacheValue& v) {
		if (k == keys[0]) {
			v = MakePositiveValue(CacheConfig::MIN_TTL_SECONDS);
			return true;
		}
		return false;
	});

	CacheValue out{};
	EXPECT_TRUE(c.Lookup(keys[0], out));
	EXPECT_FALSE(c.Lookup(keys[1], out));
}

TEST(ReputationCacheTests, Statistics_SanityAfterOperations) {
	ReputationCache c(MakeSmallOptions(true));
	ASSERT_TRUE(c.Initialize().IsSuccess());

	CacheStatistics s0 = c.GetStatistics();
	EXPECT_EQ(s0.totalEntries, 0u);
	EXPECT_GE(s0.totalCapacity, 1u);
	EXPECT_GE(s0.utilization, 0.0);
	EXPECT_LE(s0.utilization, 1.0);
	EXPECT_GE(s0.hitRate, 0.0);
	EXPECT_LE(s0.hitRate, 1.0);
	EXPECT_GT(s0.memoryUsageBytes, 0u);
	EXPECT_GT(s0.bloomFilterBytes, 0u);

	CacheKey k(IOCType::Domain, "stats.example");
	c.Insert(k, MakePositiveValue(CacheConfig::MIN_TTL_SECONDS));
	CacheValue out{};
	EXPECT_TRUE(c.Lookup(k, out));

	CacheStatistics s1 = c.GetStatistics();
	EXPECT_EQ(s1.totalEntries, 1u);
	EXPECT_GE(s1.cacheHits, 1u);
	EXPECT_GE(s1.totalLookups, 1u);
}

TEST(ReputationCacheTests, Concurrency_MultiThreadedInsertAndLookup_Smoke) {
	CacheOptions opt = MakeSmallOptions(false);
	opt.shardCount = 16;
	opt.totalCapacity = 8192;
	ReputationCache c(opt);
	ASSERT_TRUE(c.Initialize().IsSuccess());

	constexpr int kThreads = 6;
	constexpr int kKeysPerThread = 300;

	std::atomic<bool> start{false};
	std::vector<std::thread> threads;
	threads.reserve(kThreads);

	for (int t = 0; t < kThreads; ++t) {
		threads.emplace_back([&, t]() {
			while (!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			for (int i = 0; i < kKeysPerThread; ++i) {
				CacheKey key(IOCType::Domain, "t" + std::to_string(t) + "-" + std::to_string(i) + ".example");
				c.Insert(key, MakePositiveValue(CacheConfig::MIN_TTL_SECONDS));
				CacheValue out{};
				(void)c.Lookup(key, out);
			}
		});
	}

	start.store(true, std::memory_order_release);
	for (auto& th : threads) {
		th.join();
	}

	// Not all inserts are guaranteed to remain if evictions happened, but we should have many.
	EXPECT_GT(c.GetEntryCount(), 0u);
	CacheStatistics s = c.GetStatistics();
	EXPECT_GE(s.totalLookups, 1u);
}

