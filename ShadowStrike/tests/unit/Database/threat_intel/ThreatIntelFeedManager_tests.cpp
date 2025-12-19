/**
 * @file ThreatIntelFeedManager_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelFeedManager
 *
 * Comprehensive test coverage for feed management, parsing, synchronization,
 * and all edge cases with production-grade validation.
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelFeedManager.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelStore.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;
using namespace std::chrono_literals;

// ============================================================================
// TEST HELPERS & FIXTURES
// ============================================================================

namespace {

// Temporary directory helper
struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_FeedMgr_") + 
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

// Helper to create test JSON data
[[nodiscard]] std::string CreateTestJsonFeed(int numEntries) {
	std::ostringstream oss;
	oss << R"({"data":[)";
	for (int i = 0; i < numEntries; ++i) {
		if (i > 0) oss << ",";
		oss << R"({"ip":"192.168.)" << (i % 256) << "." << ((i / 256) % 256) 
			<< R"(","type":"malware","confidence":85})";
	}
	oss << R"(]})";
	return oss.str();
}

// Helper to create test CSV data
[[nodiscard]] std::string CreateTestCsvFeed(int numEntries, bool withHeader = true) {
	std::ostringstream oss;
	if (withHeader) {
		oss << "indicator,type,confidence\n";
	}
	for (int i = 0; i < numEntries; ++i) {
		oss << "192.168." << (i % 256) << "." << ((i / 256) % 256) 
			<< ",malware,85\n";
	}
	return oss.str();
}

} // anonymous namespace

// ============================================================================
// PART 1/5: UTILITY FUNCTIONS TESTS
// ============================================================================

// ----------------------------------------------------------------------------
// ParseDurationString Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_Seconds) {
	EXPECT_EQ(ParseDurationString("123"), 123u);
	EXPECT_EQ(ParseDurationString("0"), 0u);
	EXPECT_EQ(ParseDurationString("1"), 1u);
	EXPECT_EQ(ParseDurationString("999999"), 999999u);
	EXPECT_EQ(ParseDurationString("123s"), 123u);
	EXPECT_EQ(ParseDurationString("456sec"), 456u);
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_Minutes) {
	EXPECT_EQ(ParseDurationString("5m"), 300u);        // 5 * 60
	EXPECT_EQ(ParseDurationString("1m"), 60u);
	EXPECT_EQ(ParseDurationString("10min"), 600u);
	EXPECT_EQ(ParseDurationString("0m"), 0u);
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_Hours) {
	EXPECT_EQ(ParseDurationString("1h"), 3600u);       // 1 * 3600
	EXPECT_EQ(ParseDurationString("2h"), 7200u);
	EXPECT_EQ(ParseDurationString("24h"), 86400u);
	EXPECT_EQ(ParseDurationString("1hr"), 3600u);
	EXPECT_EQ(ParseDurationString("3hour"), 10800u);
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_Days) {
	EXPECT_EQ(ParseDurationString("1d"), 86400u);      // 1 * 86400
	EXPECT_EQ(ParseDurationString("7d"), 604800u);
	EXPECT_EQ(ParseDurationString("1day"), 86400u);
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_Weeks) {
	EXPECT_EQ(ParseDurationString("1w"), 604800u);     // 1 * 604800
	EXPECT_EQ(ParseDurationString("2w"), 1209600u);
	EXPECT_EQ(ParseDurationString("1week"), 604800u);
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_EdgeCases) {
	// Empty string
	EXPECT_EQ(ParseDurationString(""), std::nullopt);
	
	// Too long
	EXPECT_EQ(ParseDurationString(std::string(100, '1')), std::nullopt);
	
	// Invalid format
	EXPECT_EQ(ParseDurationString("abc"), std::nullopt);
	EXPECT_EQ(ParseDurationString("m5"), std::nullopt);
	EXPECT_EQ(ParseDurationString("--5"), std::nullopt);
	
	// Unknown unit
	EXPECT_EQ(ParseDurationString("5x"), std::nullopt);
	EXPECT_EQ(ParseDurationString("5years"), std::nullopt);
	
	// Overflow protection (UINT32_MAX is 4294967295)
	EXPECT_EQ(ParseDurationString("5000000000"), std::nullopt); // > UINT32_MAX
	EXPECT_EQ(ParseDurationString("100000000h"), std::nullopt); // Would overflow with multiplier
	EXPECT_EQ(ParseDurationString("1000000d"), std::nullopt);   // Would overflow
}

TEST(ThreatIntelFeedManager_Utilities, ParseDurationString_BoundaryValues) {
	// Maximum safe values
	EXPECT_EQ(ParseDurationString("4294967295"), 4294967295u); // UINT32_MAX
	EXPECT_EQ(ParseDurationString("71582788m"), 4294967280u);  // Just under overflow
	EXPECT_EQ(ParseDurationString("1193046h"), 4294965600u);   // Just under overflow
	EXPECT_EQ(ParseDurationString("49710d"), 4294464000u);     // Just under overflow
}

// ----------------------------------------------------------------------------
// FormatDuration Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Utilities, FormatDuration_Seconds) {
	EXPECT_EQ(FormatDuration(0), "0s");
	EXPECT_EQ(FormatDuration(1), "1s");
	EXPECT_EQ(FormatDuration(59), "59s");
}

TEST(ThreatIntelFeedManager_Utilities, FormatDuration_Minutes) {
	EXPECT_EQ(FormatDuration(60), "1m");
	EXPECT_EQ(FormatDuration(120), "2m");
	EXPECT_EQ(FormatDuration(3599), "59m 59s");
}

TEST(ThreatIntelFeedManager_Utilities, FormatDuration_Hours) {
	EXPECT_EQ(FormatDuration(3600), "1h");
	EXPECT_EQ(FormatDuration(7200), "2h");
	EXPECT_EQ(FormatDuration(3661), "1h 1m 1s");
}

TEST(ThreatIntelFeedManager_Utilities, FormatDuration_Days) {
	EXPECT_EQ(FormatDuration(86400), "1d");
	EXPECT_EQ(FormatDuration(172800), "2d");
	EXPECT_EQ(FormatDuration(90061), "1d 1h 1m 1s");
}

TEST(ThreatIntelFeedManager_Utilities, FormatDuration_LargeValues) {
	// Large values
	EXPECT_EQ(FormatDuration(604800), "7d");           // 1 week
	EXPECT_EQ(FormatDuration(31536000), "365d");       // 1 year
	EXPECT_EQ(FormatDuration(UINT64_MAX), "");         // Should handle gracefully
}

// ----------------------------------------------------------------------------
// IsValidUrl Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Utilities, IsValidUrl_ValidUrls) {
	EXPECT_TRUE(IsValidUrl("http://example.com"));
	EXPECT_TRUE(IsValidUrl("https://example.com"));
	EXPECT_TRUE(IsValidUrl("https://example.com/path"));
	EXPECT_TRUE(IsValidUrl("https://example.com:8080/path?query=value"));
	EXPECT_TRUE(IsValidUrl("ftp://ftp.example.com"));
	EXPECT_TRUE(IsValidUrl("ftps://secure.example.com"));
}

TEST(ThreatIntelFeedManager_Utilities, IsValidUrl_InvalidUrls) {
	EXPECT_FALSE(IsValidUrl(""));
	EXPECT_FALSE(IsValidUrl("example.com"));
	EXPECT_FALSE(IsValidUrl("www.example.com"));
	EXPECT_FALSE(IsValidUrl("htp://example.com"));    // Typo
	EXPECT_FALSE(IsValidUrl("file:///path"));
	EXPECT_FALSE(IsValidUrl("javascript:alert(1)"));
}

// ----------------------------------------------------------------------------
// DetectIOCType Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_IPv4) {
	EXPECT_EQ(DetectIOCType("192.168.1.1"), IOCType::IPv4);
	EXPECT_EQ(DetectIOCType("10.0.0.1"), IOCType::IPv4);
	EXPECT_EQ(DetectIOCType("8.8.8.8"), IOCType::IPv4);
	EXPECT_EQ(DetectIOCType("255.255.255.255"), IOCType::IPv4);
	EXPECT_EQ(DetectIOCType("0.0.0.0"), IOCType::IPv4);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_IPv6) {
	EXPECT_EQ(DetectIOCType("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), IOCType::IPv6);
	EXPECT_EQ(DetectIOCType("2001:db8::1"), IOCType::IPv6);
	EXPECT_EQ(DetectIOCType("::1"), IOCType::IPv6);
	EXPECT_EQ(DetectIOCType("fe80::"), IOCType::IPv6);
	EXPECT_EQ(DetectIOCType("::ffff:192.168.1.1"), IOCType::IPv6);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_Domain) {
	EXPECT_EQ(DetectIOCType("example.com"), IOCType::Domain);
	EXPECT_EQ(DetectIOCType("sub.example.com"), IOCType::Domain);
	EXPECT_EQ(DetectIOCType("malware.evil-site.org"), IOCType::Domain);
	EXPECT_EQ(DetectIOCType("test-site.co.uk"), IOCType::Domain);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_URL) {
	EXPECT_EQ(DetectIOCType("http://example.com"), IOCType::URL);
	EXPECT_EQ(DetectIOCType("https://malware.com/payload"), IOCType::URL);
	EXPECT_EQ(DetectIOCType("ftp://files.example.com"), IOCType::URL);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_Email) {
	EXPECT_EQ(DetectIOCType("user@example.com"), IOCType::Email);
	EXPECT_EQ(DetectIOCType("admin@malware.net"), IOCType::Email);
	EXPECT_EQ(DetectIOCType("test.user+tag@domain.co.uk"), IOCType::Email);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_Hashes) {
	// MD5 (32 hex chars)
	EXPECT_EQ(DetectIOCType("d41d8cd98f00b204e9800998ecf8427e"), IOCType::FileHash);
	
	// SHA-1 (40 hex chars)
	EXPECT_EQ(DetectIOCType("da39a3ee5e6b4b0d3255bfef95601890afd80709"), IOCType::FileHash);
	
	// SHA-256 (64 hex chars)
	EXPECT_EQ(DetectIOCType("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), IOCType::FileHash);
	
	// SHA-512 (128 hex chars)
	EXPECT_EQ(DetectIOCType(std::string(128, 'a')), IOCType::FileHash);
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_Invalid) {
	EXPECT_EQ(DetectIOCType(""), std::nullopt);
	EXPECT_EQ(DetectIOCType("not-an-ioc"), std::nullopt);
	EXPECT_EQ(DetectIOCType("999.999.999.999"), std::nullopt); // Invalid IPv4
	EXPECT_EQ(DetectIOCType("12345"), std::nullopt);           // Just a number
}

TEST(ThreatIntelFeedManager_Utilities, DetectIOCType_EdgeCases) {
	// IPv4 edge cases
	EXPECT_EQ(DetectIOCType("256.1.1.1"), std::nullopt);       // Octet > 255
	EXPECT_EQ(DetectIOCType("1.1.1"), std::nullopt);           // Too few octets
	EXPECT_EQ(DetectIOCType("1.1.1.1.1"), std::nullopt);       // Too many octets
	
	// Hash edge cases
	EXPECT_EQ(DetectIOCType(std::string(31, 'a')), std::nullopt); // Too short for MD5
	EXPECT_EQ(DetectIOCType(std::string(33, 'a')), std::nullopt); // Between MD5 and SHA-1
	EXPECT_EQ(DetectIOCType("not_hex_12345678901234567890123456789012"), std::nullopt); // Non-hex
	
	// Domain edge cases
	EXPECT_EQ(DetectIOCType("a"), std::nullopt);               // Too short
	EXPECT_EQ(DetectIOCType(".com"), std::nullopt);            // Starts with dot
	EXPECT_EQ(DetectIOCType("example..com"), std::nullopt);    // Double dot
	EXPECT_EQ(DetectIOCType("-example.com"), std::nullopt);    // Starts with hyphen
}

// ============================================================================
// PART 1/5: RETRY CONFIG TESTS
// ============================================================================

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_ExponentialBackoff) {
	RetryConfig config;
	config.maxAttempts = 5;
	config.initialDelayMs = 1000;
	config.maxDelayMs = 60000;
	config.backoffMultiplier = 2.0;
	config.jitterFactor = 0.0; // Disable jitter for predictable testing

	// Attempt 0 (first try): initial delay
	uint32_t delay0 = config.CalculateDelay(0);
	EXPECT_EQ(delay0, 1000u);

	// Attempt 1: initial * 2^1 = 2000
	uint32_t delay1 = config.CalculateDelay(1);
	EXPECT_EQ(delay1, 2000u);

	// Attempt 2: initial * 2^2 = 4000
	uint32_t delay2 = config.CalculateDelay(2);
	EXPECT_EQ(delay2, 4000u);

	// Attempt 3: initial * 2^3 = 8000
	uint32_t delay3 = config.CalculateDelay(3);
	EXPECT_EQ(delay3, 8000u);

	// Attempt 4: initial * 2^4 = 16000
	uint32_t delay4 = config.CalculateDelay(4);
	EXPECT_EQ(delay4, 16000u);
}

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_MaxDelayCap) {
	RetryConfig config;
	config.initialDelayMs = 1000;
	config.maxDelayMs = 5000;
	config.backoffMultiplier = 2.0;
	config.jitterFactor = 0.0;

	// Should cap at maxDelayMs
	EXPECT_EQ(config.CalculateDelay(10), 5000u); // 1000 * 2^10 = 1024000, capped to 5000
	EXPECT_EQ(config.CalculateDelay(20), 5000u); // Would be huge, capped to 5000
}

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_Jitter) {
	RetryConfig config;
	config.initialDelayMs = 1000;
	config.maxDelayMs = 60000;
	config.backoffMultiplier = 2.0;
	config.jitterFactor = 0.25; // +/- 25%

	// With jitter, delays should vary within range
	std::unordered_set<uint32_t> delays;
	for (int i = 0; i < 100; ++i) {
		uint32_t delay = config.CalculateDelay(1); // Base 2000ms
		delays.insert(delay);
		// Should be within 2000 +/- 25% = [1500, 2500]
		EXPECT_GE(delay, 1500u);
		EXPECT_LE(delay, 2500u);
	}
	
	// With jitter, we should see variation (not all same value)
	EXPECT_GT(delays.size(), 1u);
}

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_ZeroAttempt) {
	RetryConfig config;
	config.initialDelayMs = 5000;
	config.jitterFactor = 0.0;

	EXPECT_EQ(config.CalculateDelay(0), 5000u);
}

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_OverflowProtection) {
	RetryConfig config;
	config.initialDelayMs = 1000;
	config.maxDelayMs = UINT32_MAX;
	config.backoffMultiplier = 2.0;
	config.jitterFactor = 0.0;

	// Very large attempt number shouldn't overflow
	uint32_t delay = config.CalculateDelay(100);
	EXPECT_LE(delay, UINT32_MAX);
	EXPECT_GT(delay, 0u);
}

TEST(ThreatIntelFeedManager_RetryConfig, CalculateDelay_DifferentMultipliers) {
	RetryConfig config;
	config.initialDelayMs = 1000;
	config.maxDelayMs = 60000;
	config.jitterFactor = 0.0;

	// Multiplier 1.5
	config.backoffMultiplier = 1.5;
	EXPECT_EQ(config.CalculateDelay(1), 1500u);  // 1000 * 1.5
	EXPECT_EQ(config.CalculateDelay(2), 2250u);  // 1000 * 1.5^2

	// Multiplier 3.0
	config.backoffMultiplier = 3.0;
	EXPECT_EQ(config.CalculateDelay(1), 3000u);  // 1000 * 3
	EXPECT_EQ(config.CalculateDelay(2), 9000u);  // 1000 * 3^2
}

// ============================================================================
// PART 1/5: AUTH CREDENTIALS TESTS
// ============================================================================

TEST(ThreatIntelFeedManager_AuthCredentials, IsConfigured_None) {
	AuthCredentials auth;
	auth.method = AuthMethod::None;
	EXPECT_FALSE(auth.IsConfigured());
}

TEST(ThreatIntelFeedManager_AuthCredentials, IsConfigured_ApiKey) {
	AuthCredentials auth;
	auth.method = AuthMethod::ApiKey;
	
	auth.apiKey = "";
	EXPECT_FALSE(auth.IsConfigured());
	
	auth.apiKey = "test-key-123";
	EXPECT_TRUE(auth.IsConfigured());
}

TEST(ThreatIntelFeedManager_AuthCredentials, IsConfigured_BasicAuth) {
	AuthCredentials auth;
	auth.method = AuthMethod::BasicAuth;
	
	auth.username = "";
	auth.password = "";
	EXPECT_FALSE(auth.IsConfigured());
	
	auth.username = "user";
	auth.password = "";
	EXPECT_FALSE(auth.IsConfigured());
	
	auth.username = "";
	auth.password = "pass";
	EXPECT_FALSE(auth.IsConfigured());
	
	auth.username = "user";
	auth.password = "pass";
	EXPECT_TRUE(auth.IsConfigured());
}

TEST(ThreatIntelFeedManager_AuthCredentials, IsConfigured_BearerToken) {
	AuthCredentials auth;
	auth.method = AuthMethod::BearerToken;
	
	auth.bearerToken = "";
	EXPECT_FALSE(auth.IsConfigured());
	
	auth.bearerToken = "token-abc-123";
	EXPECT_TRUE(auth.IsConfigured());
}

TEST(ThreatIntelFeedManager_AuthCredentials, NeedsTokenRefresh_NoExpiration) {
	AuthCredentials auth;
	auth.method = AuthMethod::OAuth2;
	auth.bearerToken = "valid-token";
	auth.tokenExpiresAt = 0; // No expiration
	
	EXPECT_FALSE(auth.NeedsTokenRefresh());
}

TEST(ThreatIntelFeedManager_AuthCredentials, NeedsTokenRefresh_FutureExpiration) {
	AuthCredentials auth;
	auth.method = AuthMethod::OAuth2;
	auth.bearerToken = "valid-token";
	
	const auto now = std::chrono::system_clock::now();
	const auto future = now + std::chrono::hours(1);
	auth.tokenExpiresAt = std::chrono::system_clock::to_time_t(future);
	
	EXPECT_FALSE(auth.NeedsTokenRefresh());
}

TEST(ThreatIntelFeedManager_AuthCredentials, NeedsTokenRefresh_PastExpiration) {
	AuthCredentials auth;
	auth.method = AuthMethod::OAuth2;
	auth.bearerToken = "expired-token";
	
	const auto now = std::chrono::system_clock::now();
	const auto past = now - std::chrono::hours(1);
	auth.tokenExpiresAt = std::chrono::system_clock::to_time_t(past);
	
	EXPECT_TRUE(auth.NeedsTokenRefresh());
}

TEST(ThreatIntelFeedManager_AuthCredentials, Clear_RemovesAllData) {
	AuthCredentials auth;
	auth.method = AuthMethod::ApiKey;
	auth.apiKey = "secret-key";
	auth.headerName = "X-API-Key";
	auth.username = "user";
	auth.password = "pass";
	auth.bearerToken = "token";
	auth.clientId = "client";
	auth.clientSecret = "secret";
	auth.tokenExpiresAt = 12345;

	auth.Clear();

	EXPECT_EQ(auth.method, AuthMethod::None);
	EXPECT_TRUE(auth.apiKey.empty());
	EXPECT_TRUE(auth.headerName.empty());
	EXPECT_TRUE(auth.username.empty());
	EXPECT_TRUE(auth.password.empty());
	EXPECT_TRUE(auth.bearerToken.empty());
	EXPECT_TRUE(auth.clientId.empty());
	EXPECT_TRUE(auth.clientSecret.empty());
	EXPECT_EQ(auth.tokenExpiresAt, 0u);
}

// ============================================================================
// PART 2/5: FEEDENDPOINT, THREATFEEDCONFIG & FEEDSTATS TESTS
// ============================================================================

// ----------------------------------------------------------------------------
// FeedEndpoint Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_FeedEndpoint, GetFullUrl_BasicUrl) {
	FeedEndpoint endpoint;
	endpoint.baseUrl = "https://api.example.com";
	endpoint.path = "/v1/indicators";

	EXPECT_EQ(endpoint.GetFullUrl(), "https://api.example.com/v1/indicators");
}

TEST(ThreatIntelFeedManager_FeedEndpoint, GetFullUrl_WithQueryParams) {
	FeedEndpoint endpoint;
	endpoint.baseUrl = "https://api.example.com";
	endpoint.path = "/v1/indicators";
	endpoint.queryParams = {
		{"limit", "100"},
		{"type", "malware"}
	};

	const std::string url = endpoint.GetFullUrl();
	EXPECT_NE(url.find("https://api.example.com/v1/indicators?"), std::string::npos);
	EXPECT_NE(url.find("limit=100"), std::string::npos);
	EXPECT_NE(url.find("type=malware"), std::string::npos);
}

TEST(ThreatIntelFeedManager_FeedEndpoint, GetFullUrl_TrailingSlashHandling) {
	FeedEndpoint endpoint1;
	endpoint1.baseUrl = "https://api.example.com/";
	endpoint1.path = "/v1/indicators";

	FeedEndpoint endpoint2;
	endpoint2.baseUrl = "https://api.example.com";
	endpoint2.path = "v1/indicators";

	// Both should produce same result
	EXPECT_EQ(endpoint1.GetFullUrl(), "https://api.example.com/v1/indicators");
	EXPECT_EQ(endpoint2.GetFullUrl(), "https://api.example.com/v1/indicators");
}

TEST(ThreatIntelFeedManager_FeedEndpoint, GetPaginatedUrl_OffsetLimit) {
	FeedEndpoint endpoint;
	endpoint.baseUrl = "https://api.example.com";
	endpoint.path = "/v1/indicators";
	endpoint.paginationStyle = PaginationStyle::OffsetLimit;
	endpoint.offsetParam = "offset";
	endpoint.limitParam = "limit";

	const std::string url = endpoint.GetPaginatedUrl(100, 50);
	EXPECT_NE(url.find("offset=100"), std::string::npos);
	EXPECT_NE(url.find("limit=50"), std::string::npos);
}

TEST(ThreatIntelFeedManager_FeedEndpoint, GetPaginatedUrl_PageBased) {
	FeedEndpoint endpoint;
	endpoint.baseUrl = "https://api.example.com";
	endpoint.path = "/v1/indicators";
	endpoint.paginationStyle = PaginationStyle::PageBased;
	endpoint.pageParam = "page";
	endpoint.limitParam = "per_page";

	// Offset 100 with limit 50 = page 3 (100/50 + 1)
	const std::string url = endpoint.GetPaginatedUrl(100, 50);
	EXPECT_NE(url.find("page=3"), std::string::npos);
	EXPECT_NE(url.find("per_page=50"), std::string::npos);
}

// ----------------------------------------------------------------------------
// ThreatFeedConfig Validation Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_ThreatFeedConfig, Validate_ValidConfig) {
	ThreatFeedConfig config;
	config.feedId = "test-feed-1";
	config.name = "Test Feed";
	config.source = ThreatIntelSource::VirusTotal;
	config.protocol = FeedProtocol::JSON;
	config.enabled = true;
	config.endpoint.baseUrl = "https://api.virustotal.com";
	config.endpoint.path = "/v3/feeds/domains";
	config.updateInterval = 3600;

	std::string error;
	EXPECT_TRUE(config.Validate(&error));
	EXPECT_TRUE(error.empty());
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, Validate_EmptyFeedId) {
	ThreatFeedConfig config;
	config.feedId = "";
	config.name = "Test Feed";
	config.endpoint.baseUrl = "https://api.example.com";

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
	EXPECT_NE(error.find("feedId"), std::string::npos);
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, Validate_EmptyName) {
	ThreatFeedConfig config;
	config.feedId = "test-1";
	config.name = "";
	config.endpoint.baseUrl = "https://api.example.com";

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
	EXPECT_NE(error.find("name"), std::string::npos);
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, Validate_InvalidUrl) {
	ThreatFeedConfig config;
	config.feedId = "test-1";
	config.name = "Test Feed";
	config.endpoint.baseUrl = "not-a-url";

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
	EXPECT_NE(error.find("baseUrl"), std::string::npos);
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, Validate_ZeroUpdateInterval) {
	ThreatFeedConfig config;
	config.feedId = "test-1";
	config.name = "Test Feed";
	config.endpoint.baseUrl = "https://api.example.com";
	config.updateInterval = 0;

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
	EXPECT_NE(error.find("updateInterval"), std::string::npos);
}

// ----------------------------------------------------------------------------
// ThreatFeedConfig Factory Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateVirusTotal_ValidConfig) {
	const std::string apiKey = "test-vt-key-123";
	ThreatFeedConfig config = ThreatFeedConfig::CreateVirusTotal(apiKey);

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.source, ThreatIntelSource::VirusTotal);
	EXPECT_EQ(config.protocol, FeedProtocol::JSON);
	EXPECT_EQ(config.auth.method, AuthMethod::ApiKey);
	EXPECT_EQ(config.auth.apiKey, apiKey);
	EXPECT_NE(config.endpoint.baseUrl.find("virustotal.com"), std::string::npos);
	EXPECT_TRUE(config.enabled);
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateAlienVaultOTX_ValidConfig) {
	const std::string apiKey = "test-otx-key-456";
	ThreatFeedConfig config = ThreatFeedConfig::CreateAlienVaultOTX(apiKey);

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.source, ThreatIntelSource::AlienVaultOTX);
	EXPECT_EQ(config.protocol, FeedProtocol::JSON);
	EXPECT_EQ(config.auth.method, AuthMethod::ApiKey);
	EXPECT_EQ(config.auth.apiKey, apiKey);
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateAbuseIPDB_ValidConfig) {
	const std::string apiKey = "test-abuse-key-789";
	ThreatFeedConfig config = ThreatFeedConfig::CreateAbuseIPDB(apiKey);

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.source, ThreatIntelSource::AbuseIPDB);
	EXPECT_EQ(config.protocol, FeedProtocol::JSON);
	EXPECT_EQ(config.auth.method, AuthMethod::ApiKey);
	EXPECT_EQ(config.auth.apiKey, apiKey);
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateURLhaus_NoAuthRequired) {
	ThreatFeedConfig config = ThreatFeedConfig::CreateURLhaus();

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.source, ThreatIntelSource::URLhaus);
	EXPECT_EQ(config.protocol, FeedProtocol::CSV);
	EXPECT_EQ(config.auth.method, AuthMethod::None); // URLhaus is public
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateMISP_CustomUrl) {
	const std::string baseUrl = "https://misp.example.com";
	const std::string apiKey = "misp-key-abc";
	ThreatFeedConfig config = ThreatFeedConfig::CreateMISP(baseUrl, apiKey);

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.source, ThreatIntelSource::MISP);
	EXPECT_EQ(config.protocol, FeedProtocol::JSON);
	EXPECT_EQ(config.auth.method, AuthMethod::ApiKey);
	EXPECT_EQ(config.auth.apiKey, apiKey);
	EXPECT_NE(config.endpoint.baseUrl.find(baseUrl), std::string::npos);
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

TEST(ThreatIntelFeedManager_ThreatFeedConfig, CreateCSVFeed_CustomColumn) {
	const std::string url = "https://feeds.example.com/iocs.csv";
	ThreatFeedConfig config = ThreatFeedConfig::CreateCSVFeed(url, 2, IOCType::IPv4);

	EXPECT_FALSE(config.feedId.empty());
	EXPECT_EQ(config.protocol, FeedProtocol::CSV);
	EXPECT_EQ(config.parserConfig.csvValueColumn, 2);
	EXPECT_NE(config.endpoint.baseUrl.find(url), std::string::npos);
	
	std::string error;
	EXPECT_TRUE(config.Validate(&error));
}

// ----------------------------------------------------------------------------
// FeedStats Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_FeedStats, GetSuccessRate_NoAttempts) {
	FeedStats stats{};
	stats.totalSyncs = 0;
	stats.successfulSyncs = 0;

	EXPECT_EQ(stats.GetSuccessRate(), 0.0);
}

TEST(ThreatIntelFeedManager_FeedStats, GetSuccessRate_AllSuccess) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 100;

	EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 100.0);
}

TEST(ThreatIntelFeedManager_FeedStats, GetSuccessRate_PartialSuccess) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 75;

	EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 75.0);
}

TEST(ThreatIntelFeedManager_FeedStats, GetSuccessRate_NoSuccess) {
	FeedStats stats{};
	stats.totalSyncs = 50;
	stats.successfulSyncs = 0;

	EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 0.0);
}

TEST(ThreatIntelFeedManager_FeedStats, IsHealthy_HighSuccessRate) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 95; // 95% success rate
	stats.consecutiveFailures = 0;

	EXPECT_TRUE(stats.IsHealthy());
}

TEST(ThreatIntelFeedManager_FeedStats, IsHealthy_LowSuccessRate) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 40; // 40% success rate (< 50% threshold)
	stats.consecutiveFailures = 0;

	EXPECT_FALSE(stats.IsHealthy());
}

TEST(ThreatIntelFeedManager_FeedStats, IsHealthy_ConsecutiveFailures) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 90; // Good success rate
	stats.consecutiveFailures = 10; // But many consecutive failures

	EXPECT_FALSE(stats.IsHealthy());
}

TEST(ThreatIntelFeedManager_FeedStats, Reset_ClearsAllCounters) {
	FeedStats stats{};
	stats.totalSyncs = 100;
	stats.successfulSyncs = 75;
	stats.failedSyncs = 25;
	stats.totalIOCsReceived = 50000;
	stats.totalIOCsStored = 48000;
	stats.totalBytesDownloaded = 1024000;
	stats.consecutiveFailures = 5;
	stats.SetLastError("Test error");

	stats.Reset();

	EXPECT_EQ(stats.totalSyncs, 0u);
	EXPECT_EQ(stats.successfulSyncs, 0u);
	EXPECT_EQ(stats.failedSyncs, 0u);
	EXPECT_EQ(stats.totalIOCsReceived, 0u);
	EXPECT_EQ(stats.totalIOCsStored, 0u);
	EXPECT_EQ(stats.totalBytesDownloaded, 0u);
	EXPECT_EQ(stats.consecutiveFailures, 0u);
	EXPECT_TRUE(stats.GetLastError().empty());
}

TEST(ThreatIntelFeedManager_FeedStats, ThreadSafety_LastError) {
	FeedStats stats{};

	std::vector<std::thread> threads;
	for (int i = 0; i < 10; ++i) {
		threads.emplace_back([&stats, i]() {
			for (int j = 0; j < 100; ++j) {
				stats.SetLastError("Error " + std::to_string(i * 100 + j));
				std::string error = stats.GetLastError();
				EXPECT_FALSE(error.empty());
			}
		});
	}

	for (auto& t : threads) {
		t.join();
	}

	// Should have one of the error messages
	EXPECT_FALSE(stats.GetLastError().empty());
}

// ============================================================================
// PART 3/5: SYNC RESULT & HTTP TYPES TESTS
// ============================================================================

TEST(ThreatIntelFeedManager_SyncResult, GetIOCsPerSecond_ZeroDuration) {
	SyncResult result;
	result.newIOCs = 1000;
	result.durationMs = 0;

	EXPECT_EQ(result.GetIOCsPerSecond(), 0.0);
}

TEST(ThreatIntelFeedManager_SyncResult, GetIOCsPerSecond_ValidCalculation) {
	SyncResult result;
	result.newIOCs = 5000;
	result.durationMs = 2000; // 2 seconds

	EXPECT_DOUBLE_EQ(result.GetIOCsPerSecond(), 2500.0); // 5000 / 2
}

TEST(ThreatIntelFeedManager_SyncResult, GetIOCsPerSecond_SubSecond) {
	SyncResult result;
	result.newIOCs = 100;
	result.durationMs = 500; // 0.5 seconds

	EXPECT_DOUBLE_EQ(result.GetIOCsPerSecond(), 200.0); // 100 / 0.5
}

TEST(ThreatIntelFeedManager_FeedEvent, Create_PopulatesFields) {
	const std::string feedId = "test-feed-1";
	const std::string message = "Sync completed";
	
	FeedEvent event = FeedEvent::Create(FeedEventType::SyncCompleted, feedId, message);

	EXPECT_EQ(event.type, FeedEventType::SyncCompleted);
	EXPECT_EQ(event.feedId, feedId);
	EXPECT_EQ(event.message, message);
	EXPECT_GT(event.timestamp, 0u);
}

TEST(ThreatIntelFeedManager_HttpRequest, Get_CreatesGetRequest) {
	const std::string url = "https://api.example.com/data";
	HttpRequest req = HttpRequest::Get(url);

	EXPECT_EQ(req.method, HttpMethod::GET);
	EXPECT_EQ(req.url, url);
	EXPECT_TRUE(req.body.empty());
}

TEST(ThreatIntelFeedManager_HttpRequest, Post_CreatesPostRequest) {
	const std::string url = "https://api.example.com/submit";
	const std::string body = R"({"data":"value"})";
	HttpRequest req = HttpRequest::Post(url, body);

	EXPECT_EQ(req.method, HttpMethod::POST);
	EXPECT_EQ(req.url, url);
	EXPECT_EQ(req.body, body);
}

TEST(ThreatIntelFeedManager_HttpResponse, GetRetryAfter_NoHeader) {
	HttpResponse response;
	response.statusCode = 200;

	EXPECT_EQ(response.GetRetryAfter(), std::nullopt);
}

TEST(ThreatIntelFeedManager_HttpResponse, GetRetryAfter_NumericSeconds) {
	HttpResponse response;
	response.statusCode = 429;
	response.headers["Retry-After"] = "120";

	auto retryAfter = response.GetRetryAfter();
	ASSERT_TRUE(retryAfter.has_value());
	EXPECT_EQ(*retryAfter, 120u);
}

TEST(ThreatIntelFeedManager_HttpResponse, GetRetryAfter_HttpDate) {
	HttpResponse response;
	response.statusCode = 429;
	response.headers["Retry-After"] = "Wed, 21 Oct 2015 07:28:00 GMT";

	// Should parse HTTP date and return delta
	auto retryAfter = response.GetRetryAfter();
	// Result depends on current time, just verify it's set
	EXPECT_TRUE(retryAfter.has_value());
}

TEST(ThreatIntelFeedManager_HttpResponse, GetRetryAfter_InvalidValue) {
	HttpResponse response;
	response.statusCode = 429;
	response.headers["Retry-After"] = "invalid";

	EXPECT_EQ(response.GetRetryAfter(), std::nullopt);
}

// ============================================================================
// PART 4/5: PARSER TESTS (JSON, CSV, STIX)
// ============================================================================

// ----------------------------------------------------------------------------
// JSON Parser Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_JsonParser, Parse_EmptyData) {
	JsonFeedParser parser;
	ParserConfig config;
	std::vector<IOCEntry> entries;

	const std::string jsonStr = "{}";
	const auto data = std::as_bytes(std::span(jsonStr.data(), jsonStr.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_TRUE(entries.empty());
}

TEST(ThreatIntelFeedManager_JsonParser, Parse_SimpleArray) {
	JsonFeedParser parser;
	ParserConfig config;
	config.jsonArrayPath = "data";
	config.jsonValueField = "ip";
	std::vector<IOCEntry> entries;

	const std::string json = CreateTestJsonFeed(5);
	const auto data = std::as_bytes(std::span(json.data(), json.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_EQ(entries.size(), 5u);
}

TEST(ThreatIntelFeedManager_JsonParser, Parse_LargeDataset) {
	JsonFeedParser parser;
	ParserConfig config;
	config.jsonArrayPath = "data";
	config.jsonValueField = "ip";
	std::vector<IOCEntry> entries;

	const std::string json = CreateTestJsonFeed(1000);
	const auto data = std::as_bytes(std::span(json.data(), json.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_EQ(entries.size(), 1000u);
}

TEST(ThreatIntelFeedManager_JsonParser, Parse_InvalidJson) {
	JsonFeedParser parser;
	ParserConfig config;
	std::vector<IOCEntry> entries;

	const std::string invalidJson = "{invalid json}";
	const auto data = std::as_bytes(std::span(invalidJson.data(), invalidJson.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_FALSE(result);
}

TEST(ThreatIntelFeedManager_JsonParser, GetNextPageToken_TokenPresent) {
	JsonFeedParser parser;
	ParserConfig config;
	config.jsonNextPageField = "next_page";

	const std::string json = R"({"next_page":"token-abc-123","data":[]})";
	const auto data = std::as_bytes(std::span(json.data(), json.size()));

	auto token = parser.GetNextPageToken(data, config);
	ASSERT_TRUE(token.has_value());
	EXPECT_EQ(*token, "token-abc-123");
}

TEST(ThreatIntelFeedManager_JsonParser, GetNextPageToken_NoToken) {
	JsonFeedParser parser;
	ParserConfig config;
	config.jsonNextPageField = "next_page";

	const std::string json = R"({"data":[]})";
	const auto data = std::as_bytes(std::span(json.data(), json.size()));

	auto token = parser.GetNextPageToken(data, config);
	EXPECT_FALSE(token.has_value());
}

TEST(ThreatIntelFeedManager_JsonParser, GetTotalCount_CountPresent) {
	JsonFeedParser parser;
	ParserConfig config;
	config.jsonTotalCountField = "total";

	const std::string json = R"({"total":12345,"data":[]})";
	const auto data = std::as_bytes(std::span(json.data(), json.size()));

	auto count = parser.GetTotalCount(data, config);
	ASSERT_TRUE(count.has_value());
	EXPECT_EQ(*count, 12345u);
}

// ----------------------------------------------------------------------------
// CSV Parser Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_CsvParser, Parse_WithHeader) {
	CsvFeedParser parser;
	ParserConfig config;
	config.csvHasHeader = true;
	config.csvValueColumn = 0;
	std::vector<IOCEntry> entries;

	const std::string csv = CreateTestCsvFeed(10, true);
	const auto data = std::as_bytes(std::span(csv.data(), csv.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_EQ(entries.size(), 10u); // Should skip header
}

TEST(ThreatIntelFeedManager_CsvParser, Parse_WithoutHeader) {
	CsvFeedParser parser;
	ParserConfig config;
	config.csvHasHeader = false;
	config.csvValueColumn = 0;
	std::vector<IOCEntry> entries;

	const std::string csv = CreateTestCsvFeed(10, false);
	const auto data = std::as_bytes(std::span(csv.data(), csv.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_EQ(entries.size(), 10u);
}

TEST(ThreatIntelFeedManager_CsvParser, Parse_EmptyLines) {
	CsvFeedParser parser;
	ParserConfig config;
	config.csvHasHeader = false;
	config.csvValueColumn = 0;
	std::vector<IOCEntry> entries;

	const std::string csv = "192.168.1.1,malware,85\n\n\n192.168.1.2,malware,90\n";
	const auto data = std::as_bytes(std::span(csv.data(), csv.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_EQ(entries.size(), 2u); // Should skip empty lines
}

TEST(ThreatIntelFeedManager_CsvParser, ParseLine_SimpleFields) {
	CsvFeedParser parser;
	const std::string line = "field1,field2,field3";

	auto fields = parser.ParseLine(line, ',', '"');
	ASSERT_EQ(fields.size(), 3u);
	EXPECT_EQ(fields[0], "field1");
	EXPECT_EQ(fields[1], "field2");
	EXPECT_EQ(fields[2], "field3");
}

TEST(ThreatIntelFeedManager_CsvParser, ParseLine_QuotedFields) {
	CsvFeedParser parser;
	const std::string line = R"("field,1","field""2","field3")";

	auto fields = parser.ParseLine(line, ',', '"');
	ASSERT_EQ(fields.size(), 3u);
	EXPECT_EQ(fields[0], "field,1");     // Comma inside quotes
	EXPECT_EQ(fields[1], "field\"2");    // Escaped quote
	EXPECT_EQ(fields[2], "field3");
}

TEST(ThreatIntelFeedManager_CsvParser, ParseLine_EmptyFields) {
	CsvFeedParser parser;
	const std::string line = "field1,,field3,";

	auto fields = parser.ParseLine(line, ',', '"');
	ASSERT_EQ(fields.size(), 4u);
	EXPECT_EQ(fields[0], "field1");
	EXPECT_TRUE(fields[1].empty());
	EXPECT_EQ(fields[2], "field3");
	EXPECT_TRUE(fields[3].empty());
}

TEST(ThreatIntelFeedManager_CsvParser, ParseLine_AlternativeDelimiter) {
	CsvFeedParser parser;
	const std::string line = "field1;field2;field3";

	auto fields = parser.ParseLine(line, ';', '"');
	ASSERT_EQ(fields.size(), 3u);
	EXPECT_EQ(fields[0], "field1");
	EXPECT_EQ(fields[1], "field2");
	EXPECT_EQ(fields[2], "field3");
}

TEST(ThreatIntelFeedManager_CsvParser, GetTotalCount_LineCount) {
	CsvFeedParser parser;
	ParserConfig config;
	config.csvHasHeader = true;

	const std::string csv = CreateTestCsvFeed(100, true);
	const auto data = std::as_bytes(std::span(csv.data(), csv.size()));

	auto count = parser.GetTotalCount(data, config);
	ASSERT_TRUE(count.has_value());
	EXPECT_EQ(*count, 100u); // Excluding header
}

// ----------------------------------------------------------------------------
// STIX Parser Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_StixParser, Parse_EmptyBundle) {
	StixFeedParser parser;
	ParserConfig config;
	std::vector<IOCEntry> entries;

	const std::string stix = R"({"type":"bundle","objects":[]})";
	const auto data = std::as_bytes(std::span(stix.data(), stix.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_TRUE(entries.empty());
}

TEST(ThreatIntelFeedManager_StixParser, Parse_IPv4Indicator) {
	StixFeedParser parser;
	ParserConfig config;
	std::vector<IOCEntry> entries;

	const std::string stix = R"({
		"type":"bundle",
		"objects":[{
			"type":"indicator",
			"pattern":"[ipv4-addr:value = '192.168.1.1']"
		}]
	})";
	const auto data = std::as_bytes(std::span(stix.data(), stix.size()));

	bool result = parser.Parse(data, entries, config);
	EXPECT_TRUE(result);
	EXPECT_GE(entries.size(), 1u);
}

TEST(ThreatIntelFeedManager_StixParser, MapSTIXTypeToIOCType_ValidMappings) {
	StixFeedParser parser;

	EXPECT_EQ(parser.MapSTIXTypeToIOCType("ipv4-addr"), IOCType::IPv4);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType("ipv6-addr"), IOCType::IPv6);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType("domain-name"), IOCType::Domain);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType("url"), IOCType::URL);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType("email-addr"), IOCType::Email);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType("file"), IOCType::FileHash);
}

TEST(ThreatIntelFeedManager_StixParser, MapSTIXTypeToIOCType_InvalidType) {
	StixFeedParser parser;

	EXPECT_EQ(parser.MapSTIXTypeToIOCType("unknown-type"), std::nullopt);
	EXPECT_EQ(parser.MapSTIXTypeToIOCType(""), std::nullopt);
}

// ============================================================================
// PART 5/5: FEEDMANAGER INTEGRATION & ADVANCED TESTS
// ============================================================================

// ----------------------------------------------------------------------------
// FeedManager Config Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Config, Validate_ValidConfig) {
	ThreatIntelFeedManager::Config config;
	config.maxConcurrentSyncs = 4;
	config.workerThreads = 2;
	config.healthCheckInterval = 60;
	config.maxFeedsPerSource = 10;

	std::string error;
	EXPECT_TRUE(config.Validate(&error));
	EXPECT_TRUE(error.empty());
}

TEST(ThreatIntelFeedManager_Config, Validate_ZeroThreads) {
	ThreatIntelFeedManager::Config config;
	config.workerThreads = 0;

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
}

TEST(ThreatIntelFeedManager_Config, Validate_ExcessiveThreads) {
	ThreatIntelFeedManager::Config config;
	config.workerThreads = 1000;

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
}

TEST(ThreatIntelFeedManager_Config, Validate_ZeroConcurrentSyncs) {
	ThreatIntelFeedManager::Config config;
	config.maxConcurrentSyncs = 0;

	std::string error;
	EXPECT_FALSE(config.Validate(&error));
	EXPECT_FALSE(error.empty());
}

// ----------------------------------------------------------------------------
// Persistence Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Persistence, SaveConfigs_CreatesFile) {
	TempDir tempDir;
	ThreatIntelFeedManager manager;

	ThreatFeedConfig feed1 = ThreatFeedConfig::CreateURLhaus();
	feed1.feedId = "urlhaus-test";

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));
	ASSERT_TRUE(manager.AddFeed(feed1));

	const auto savePath = tempDir.FilePath("feeds.json");
	EXPECT_TRUE(manager.SaveConfigs(savePath));
	EXPECT_TRUE(std::filesystem::exists(savePath));
}

TEST(ThreatIntelFeedManager_Persistence, LoadConfigs_RestoresFeeds) {
	TempDir tempDir;
	
	// Save configs
	{
		ThreatIntelFeedManager manager;
		ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
		feed.feedId = "test-feed-load";
		feed.name = "Test Load Feed";

		ThreatIntelFeedManager::Config config;
		config.workerThreads = 2;
		ASSERT_TRUE(manager.Initialize(config));
		ASSERT_TRUE(manager.AddFeed(feed));

		const auto savePath = tempDir.FilePath("feeds_load.json");
		ASSERT_TRUE(manager.SaveConfigs(savePath));
	}

	// Load configs
	{
		ThreatIntelFeedManager manager;
		ThreatIntelFeedManager::Config config;
		config.workerThreads = 2;
		ASSERT_TRUE(manager.Initialize(config));

		const auto loadPath = tempDir.FilePath("feeds_load.json");
		EXPECT_TRUE(manager.LoadConfigs(loadPath));
		
		auto feedIds = manager.GetFeedIds();
		EXPECT_EQ(feedIds.size(), 1u);
		EXPECT_NE(std::find(feedIds.begin(), feedIds.end(), "test-feed-load"), feedIds.end());
	}
}

TEST(ThreatIntelFeedManager_Persistence, SaveState_PreservesStats) {
	TempDir tempDir;
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "state-test";
	ASSERT_TRUE(manager.AddFeed(feed));

	const auto statePath = tempDir.FilePath("state.json");
	EXPECT_TRUE(manager.SaveState(statePath));
	EXPECT_TRUE(std::filesystem::exists(statePath));
}

TEST(ThreatIntelFeedManager_Persistence, ExportImportJson_RoundTrip) {
	ThreatIntelFeedManager manager;

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "export-test";
	feed.name = "Export Test Feed";

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));
	ASSERT_TRUE(manager.AddFeed(feed));

	// Export
	std::string json = manager.ExportConfigsToJson();
	EXPECT_FALSE(json.empty());

	// Import into new manager
	ThreatIntelFeedManager manager2;
	ASSERT_TRUE(manager2.Initialize(config));
	EXPECT_TRUE(manager2.ImportConfigsFromJson(json));

	auto feedIds = manager2.GetFeedIds();
	EXPECT_EQ(feedIds.size(), 1u);
}

// ----------------------------------------------------------------------------
// Error Handling & Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_ErrorHandling, AddFeed_DuplicateId) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed1 = ThreatFeedConfig::CreateURLhaus();
	feed1.feedId = "duplicate-test";

	ThreatFeedConfig feed2 = ThreatFeedConfig::CreateMalwareBazaar();
	feed2.feedId = "duplicate-test"; // Same ID

	EXPECT_TRUE(manager.AddFeed(feed1));
	EXPECT_FALSE(manager.AddFeed(feed2)); // Should fail
}

TEST(ThreatIntelFeedManager_ErrorHandling, RemoveFeed_NonExistent) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	EXPECT_FALSE(manager.RemoveFeed("non-existent-feed"));
}

TEST(ThreatIntelFeedManager_ErrorHandling, UpdateFeed_NonExistent) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig newConfig = ThreatFeedConfig::CreateURLhaus();
	EXPECT_FALSE(manager.UpdateFeed("non-existent", newConfig));
}

TEST(ThreatIntelFeedManager_ErrorHandling, GetFeedConfig_NonExistent) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	auto feedConfig = manager.GetFeedConfig("non-existent");
	EXPECT_FALSE(feedConfig.has_value());
}

// ----------------------------------------------------------------------------
// Feed Management Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Management, AddFeed_Success) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "mgmt-test-1";

	EXPECT_TRUE(manager.AddFeed(feed));
	EXPECT_TRUE(manager.HasFeed("mgmt-test-1"));
}

TEST(ThreatIntelFeedManager_Management, RemoveFeed_Success) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "remove-test";
	ASSERT_TRUE(manager.AddFeed(feed));

	EXPECT_TRUE(manager.RemoveFeed("remove-test"));
	EXPECT_FALSE(manager.HasFeed("remove-test"));
}

TEST(ThreatIntelFeedManager_Management, EnableDisableFeed) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "toggle-test";
	feed.enabled = true;
	ASSERT_TRUE(manager.AddFeed(feed));

	EXPECT_TRUE(manager.IsFeedEnabled("toggle-test"));

	EXPECT_TRUE(manager.DisableFeed("toggle-test"));
	EXPECT_FALSE(manager.IsFeedEnabled("toggle-test"));

	EXPECT_TRUE(manager.EnableFeed("toggle-test"));
	EXPECT_TRUE(manager.IsFeedEnabled("toggle-test"));
}

TEST(ThreatIntelFeedManager_Management, GetAllFeedConfigs) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed1 = ThreatFeedConfig::CreateURLhaus();
	feed1.feedId = "all-test-1";
	ThreatFeedConfig feed2 = ThreatFeedConfig::CreateMalwareBazaar();
	feed2.feedId = "all-test-2";

	ASSERT_TRUE(manager.AddFeed(feed1));
	ASSERT_TRUE(manager.AddFeed(feed2));

	auto configs = manager.GetAllFeedConfigs();
	EXPECT_EQ(configs.size(), 2u);
}

TEST(ThreatIntelFeedManager_Management, GetFeedIds) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	ThreatFeedConfig feed1 = ThreatFeedConfig::CreateURLhaus();
	feed1.feedId = "ids-test-1";
	ThreatFeedConfig feed2 = ThreatFeedConfig::CreateMalwareBazaar();
	feed2.feedId = "ids-test-2";

	ASSERT_TRUE(manager.AddFeed(feed1));
	ASSERT_TRUE(manager.AddFeed(feed2));

	auto ids = manager.GetFeedIds();
	EXPECT_EQ(ids.size(), 2u);
	EXPECT_NE(std::find(ids.begin(), ids.end(), "ids-test-1"), ids.end());
	EXPECT_NE(std::find(ids.begin(), ids.end(), "ids-test-2"), ids.end());
}

TEST(ThreatIntelFeedManager_Management, AddFeeds_Batch) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	std::vector<ThreatFeedConfig> feeds;
	for (int i = 0; i < 5; ++i) {
		ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
		feed.feedId = "batch-" + std::to_string(i);
		feeds.push_back(feed);
	}

	uint32_t added = manager.AddFeeds(feeds);
	EXPECT_EQ(added, 5u);
}

// ----------------------------------------------------------------------------
// Lifecycle Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFeedManager_Lifecycle, Initialize_Success) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	config.maxConcurrentSyncs = 4;

	EXPECT_TRUE(manager.Initialize(config));
}

TEST(ThreatIntelFeedManager_Lifecycle, Initialize_InvalidConfig) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 0; // Invalid

	EXPECT_FALSE(manager.Initialize(config));
}

TEST(ThreatIntelFeedManager_Lifecycle, StartStop) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));

	EXPECT_TRUE(manager.Start());
	EXPECT_TRUE(manager.IsRunning());

	EXPECT_TRUE(manager.Stop(5000));
	EXPECT_FALSE(manager.IsRunning());
}

TEST(ThreatIntelFeedManager_Lifecycle, Shutdown_GracefulTermination) {
	ThreatIntelFeedManager manager;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager.Initialize(config));
	ASSERT_TRUE(manager.Start());

	manager.Shutdown();
	EXPECT_FALSE(manager.IsRunning());
}

TEST(ThreatIntelFeedManager_Lifecycle, MoveConstructor) {
	ThreatIntelFeedManager manager1;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager1.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "move-test";
	ASSERT_TRUE(manager1.AddFeed(feed));

	ThreatIntelFeedManager manager2(std::move(manager1));
	EXPECT_TRUE(manager2.HasFeed("move-test"));
}

TEST(ThreatIntelFeedManager_Lifecycle, MoveAssignment) {
	ThreatIntelFeedManager manager1;
	ThreatIntelFeedManager manager2;

	ThreatIntelFeedManager::Config config;
	config.workerThreads = 2;
	ASSERT_TRUE(manager1.Initialize(config));

	ThreatFeedConfig feed = ThreatFeedConfig::CreateURLhaus();
	feed.feedId = "assign-test";
	ASSERT_TRUE(manager1.AddFeed(feed));

	manager2 = std::move(manager1);
	EXPECT_TRUE(manager2.HasFeed("assign-test"));
}

} // namespace ShadowStrike::ThreatIntel::Tests
