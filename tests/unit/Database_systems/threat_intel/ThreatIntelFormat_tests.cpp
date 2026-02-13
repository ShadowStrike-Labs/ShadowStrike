// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file ThreatIntelFormat_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelFormat
 *
 * Comprehensive test coverage for binary format operations, validation,
 * parsing, normalization, and all edge cases with production-grade validation.
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"

#include<unordered_set>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;
using namespace ShadowStrike::ThreatIntel::Format;


// ============================================================================
// MINIMUM DATABASE SIZE CONSTANT
// ============================================================================

/// @brief Minimum size for a valid threat intel database
/// @details Must accommodate header (4KB) + minimal data sections
constexpr size_t MIN_DATABASE_SIZE = 10 * 1024 * 1024;  // 10 MB minimum


// ============================================================================
// TEST HELPERS & FIXTURES
// ============================================================================

namespace {

// Temporary directory helper
struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		const std::string name = std::string("ShadowStrike_Format_") + 
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

// Helper to create valid database header
[[nodiscard]] ThreatIntelDatabaseHeader CreateValidHeader() {
	ThreatIntelDatabaseHeader header{};
	header.magic = THREATINTEL_DB_MAGIC;
	header.versionMajor = THREATINTEL_DB_VERSION_MAJOR;
	header.versionMinor = THREATINTEL_DB_VERSION_MINOR;
	header.creationTime = 1609459200; // 2021-01-01
	header.lastUpdateTime = 1609459200;
	header.totalFileSize = MIN_DATABASE_SIZE;
	
	// Set page-aligned offsets
	header.ipv4IndexOffset = PAGE_SIZE;
	header.ipv6IndexOffset = PAGE_SIZE * 2;
	header.domainIndexOffset = PAGE_SIZE * 3;
	header.urlIndexOffset = PAGE_SIZE * 4;
	header.hashIndexOffset = PAGE_SIZE * 5;
	header.emailIndexOffset = PAGE_SIZE * 6;
	header.certIndexOffset = PAGE_SIZE * 7;
	header.ja3IndexOffset = PAGE_SIZE * 8;
	header.entryDataOffset = PAGE_SIZE * 9;
	header.compactEntryOffset = PAGE_SIZE * 10;
	header.stringPoolOffset = PAGE_SIZE * 11;
	header.bloomFilterOffset = PAGE_SIZE * 12;
	header.stixBundleOffset = PAGE_SIZE * 13;
	header.feedConfigOffset = PAGE_SIZE * 14;
	header.metadataOffset = PAGE_SIZE * 15;
	header.relationGraphOffset = PAGE_SIZE * 16;
	
	return header;
}

} // anonymous namespace

// ============================================================================
// PART 1/6: HEADER VALIDATION & CHECKSUM TESTS
// ============================================================================

TEST(ThreatIntelFormat_Header, ValidateHeader_ValidHeader) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	EXPECT_TRUE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_NullPointer) {
	EXPECT_FALSE(ValidateHeader(nullptr));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_InvalidMagic) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.magic = 0xDEADBEEF; // Wrong magic
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_WrongMajorVersion) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.versionMajor = 99; // Invalid major version
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_ExcessiveMinorVersion) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.versionMinor = 200; // Too high
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_CreationTimeBeforeEpoch) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.creationTime = 1000000; // Before 2020
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_CreationTimeInFuture) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.creationTime = 5000000000ULL; // After 2100
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_LastUpdateBeforeCreation) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.creationTime = 1609459200;
	header.lastUpdateTime = 1609459100; // Before creation
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_UnalignedOffsets) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.ipv4IndexOffset = 12345; // Not page-aligned
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_ExcessiveFileSize) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.totalFileSize = MAX_DATABASE_SIZE + 1;
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_ExcessiveEntryCount) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.totalIPv4Entries = MAX_IOC_ENTRIES + 1;
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ValidateHeader_ActiveEntriesExceedsTotal) {
	ThreatIntelDatabaseHeader header = CreateValidHeader();
	header.totalIPv4Entries = 100;
	header.totalActiveEntries = 200; // More active than total
	EXPECT_FALSE(ValidateHeader(&header));
}

TEST(ThreatIntelFormat_Header, ComputeHeaderCRC32_NullPointer) {
	EXPECT_EQ(ComputeHeaderCRC32(nullptr), 0u);
}

TEST(ThreatIntelFormat_Header, ComputeHeaderCRC32_Deterministic) {
	ThreatIntelDatabaseHeader header1 = CreateValidHeader();
	ThreatIntelDatabaseHeader header2 = CreateValidHeader();

	uint32_t crc1 = ComputeHeaderCRC32(&header1);
	uint32_t crc2 = ComputeHeaderCRC32(&header2);

	EXPECT_EQ(crc1, crc2);
	EXPECT_NE(crc1, 0u);
}

TEST(ThreatIntelFormat_Header, ComputeHeaderCRC32_ChangesWithData) {
	ThreatIntelDatabaseHeader header1 = CreateValidHeader();
	ThreatIntelDatabaseHeader header2 = CreateValidHeader();
	header2.totalIPv4Entries = 12345;

	uint32_t crc1 = ComputeHeaderCRC32(&header1);
	uint32_t crc2 = ComputeHeaderCRC32(&header2);

	EXPECT_NE(crc1, crc2);
}

// ============================================================================
// PART 2/6: IPV4 ADDRESS TESTS
// ============================================================================

TEST(ThreatIntelFormat_IPv4, ParseIPv4_ValidAddresses) {
	auto ip1 = ParseIPv4("192.168.1.1");
	ASSERT_TRUE(ip1.has_value());
	// Check octets directly to avoid endianness issues with union member
	EXPECT_EQ(ip1->octets[0], 192);
	EXPECT_EQ(ip1->octets[1], 168);
	EXPECT_EQ(ip1->octets[2], 1);
	EXPECT_EQ(ip1->octets[3], 1);
	EXPECT_EQ(ip1->prefixLength, 32);

	auto ip2 = ParseIPv4("10.0.0.1");
	ASSERT_TRUE(ip2.has_value());
	EXPECT_EQ(ip2->octets[0], 10);
	EXPECT_EQ(ip2->octets[1], 0);
	EXPECT_EQ(ip2->octets[2], 0);
	EXPECT_EQ(ip2->octets[3], 1);

	auto ip3 = ParseIPv4("255.255.255.255");
	ASSERT_TRUE(ip3.has_value());
	EXPECT_EQ(ip3->octets[0], 255);
	EXPECT_EQ(ip3->octets[1], 255);
	EXPECT_EQ(ip3->octets[2], 255);
	EXPECT_EQ(ip3->octets[3], 255);

	auto ip4 = ParseIPv4("0.0.0.0");
	ASSERT_TRUE(ip4.has_value());
	EXPECT_EQ(ip4->octets[0], 0);
	EXPECT_EQ(ip4->octets[1], 0);
	EXPECT_EQ(ip4->octets[2], 0);
	EXPECT_EQ(ip4->octets[3], 0);
}

TEST(ThreatIntelFormat_IPv4, ParseIPv4_CIDR) {
	auto ip1 = ParseIPv4("192.168.0.0/24");
	ASSERT_TRUE(ip1.has_value());
	EXPECT_EQ(ip1->octets[0], 192);
	EXPECT_EQ(ip1->octets[1], 168);
	EXPECT_EQ(ip1->octets[2], 0);
	EXPECT_EQ(ip1->octets[3], 0);
	EXPECT_EQ(ip1->prefixLength, 24);

	auto ip2 = ParseIPv4("10.0.0.0/8");
	ASSERT_TRUE(ip2.has_value());
	EXPECT_EQ(ip2->octets[0], 10);
	EXPECT_EQ(ip2->prefixLength, 8);

	auto ip3 = ParseIPv4("172.16.0.0/12");
	ASSERT_TRUE(ip3.has_value());
	EXPECT_EQ(ip3->octets[0], 172);
	EXPECT_EQ(ip3->octets[1], 16);
	EXPECT_EQ(ip3->prefixLength, 12);
}

TEST(ThreatIntelFormat_IPv4, ParseIPv4_InvalidFormats) {
	EXPECT_FALSE(ParseIPv4("").has_value());
	EXPECT_FALSE(ParseIPv4("256.1.1.1").has_value());     // Octet > 255
	EXPECT_FALSE(ParseIPv4("1.1.1").has_value());         // Too few octets
	EXPECT_FALSE(ParseIPv4("1.1.1.1.1").has_value());     // Too many octets
	EXPECT_FALSE(ParseIPv4("abc.def.ghi.jkl").has_value()); // Non-numeric
	EXPECT_FALSE(ParseIPv4("192.168.1.1/33").has_value()); // Invalid CIDR
	EXPECT_FALSE(ParseIPv4("192.168.1.1/-1").has_value()); // Negative CIDR
}

TEST(ThreatIntelFormat_IPv4, ParseIPv4_EdgeCases) {
	// Leading zeros (should be rejected for security)
	EXPECT_FALSE(ParseIPv4("192.168.001.1").has_value());
	
	// Whitespace handling
	auto ip1 = ParseIPv4("  192.168.1.1  ");
	ASSERT_TRUE(ip1.has_value());
	EXPECT_EQ(ip1->octets[0], 192);
	EXPECT_EQ(ip1->octets[1], 168);
	EXPECT_EQ(ip1->octets[2], 1);
	EXPECT_EQ(ip1->octets[3], 1);
	
	// Very long string
	EXPECT_FALSE(ParseIPv4(std::string(100, '1')).has_value());
}
TEST(ThreatIntelFormat_IPv4, FormatIPv4_NoPrefix) {
	// Enterprise-grade static factory initialization for trivially copyable structs
	const auto addr = IPv4Address::Create(192, 168, 1, 1, 32);
	EXPECT_EQ(FormatIPv4(addr), "192.168.1.1");
}

TEST(ThreatIntelFormat_IPv4, FormatIPv4_WithPrefix) {
	// Using CIDR prefix via static factory
	const auto addr = IPv4Address::Create(192, 168, 0, 0, 24);
	EXPECT_EQ(FormatIPv4(addr), "192.168.0.0/24");
}

TEST(ThreatIntelFormat_IPv4, FormatIPv4_BoundaryValues) {
	// Minimum boundary value (0.0.0.0)
	const auto addr1 = IPv4Address::Create(0, 0, 0, 0, 32);
	EXPECT_EQ(FormatIPv4(addr1), "0.0.0.0");

	// Maximum boundary value (255.255.255.255)
	const auto addr2 = IPv4Address::Create(255, 255, 255, 255, 32);
	EXPECT_EQ(FormatIPv4(addr2), "255.255.255.255");
}

TEST(ThreatIntelFormat_IPv4, ParseFormat_RoundTrip) {
	const std::vector<std::string> testCases = {
		"192.168.1.1",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"0.0.0.0",
		"255.255.255.255"
	};

	for (const auto& test : testCases) {
		auto parsed = ParseIPv4(test);
		ASSERT_TRUE(parsed.has_value()) << "Failed to parse: " << test;
		std::string formatted = FormatIPv4(*parsed);
		EXPECT_EQ(formatted, test) << "Round-trip failed for: " << test;
	}
}

// ============================================================================
// PART 3/6: IPV6 ADDRESS TESTS
// ============================================================================

TEST(ThreatIntelFormat_IPv6, ParseIPv6_ValidAddresses) {
	auto ip1 = ParseIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
	EXPECT_TRUE(ip1.has_value());

	auto ip2 = ParseIPv6("2001:db8::1");
	EXPECT_TRUE(ip2.has_value());

	auto ip3 = ParseIPv6("::1");
	EXPECT_TRUE(ip3.has_value());

	auto ip4 = ParseIPv6("::");
	EXPECT_TRUE(ip4.has_value());

	auto ip5 = ParseIPv6("fe80::1");
	EXPECT_TRUE(ip5.has_value());
}

TEST(ThreatIntelFormat_IPv6, ParseIPv6_CIDR) {
	auto ip1 = ParseIPv6("2001:db8::/32");
	ASSERT_TRUE(ip1.has_value());
	EXPECT_EQ(ip1->prefixLength, 32);

	auto ip2 = ParseIPv6("fe80::/10");
	ASSERT_TRUE(ip2.has_value());
	EXPECT_EQ(ip2->prefixLength, 10);
}

TEST(ThreatIntelFormat_IPv6, ParseIPv6_InvalidFormats) {
	EXPECT_FALSE(ParseIPv6("").has_value());
	EXPECT_FALSE(ParseIPv6("gggg::1").has_value());        // Invalid hex
	EXPECT_FALSE(ParseIPv6("::1::2").has_value());         // Multiple ::
	EXPECT_FALSE(ParseIPv6("2001:db8::/129").has_value()); // Invalid CIDR
	EXPECT_FALSE(ParseIPv6(std::string(100, '1')).has_value()); // Too long
}

TEST(ThreatIntelFormat_IPv6, FormatIPv6_NoPrefix) {
	auto parsed = ParseIPv6("2001:db8::1");
	ASSERT_TRUE(parsed.has_value());
	std::string formatted = FormatIPv6(*parsed);
	// Windows inet_ntop may format differently, just verify it's valid
	EXPECT_FALSE(formatted.empty());
}

TEST(ThreatIntelFormat_IPv6, FormatIPv6_WithPrefix) {
	auto parsed = ParseIPv6("2001:db8::/32");
	ASSERT_TRUE(parsed.has_value());
	std::string formatted = FormatIPv6(*parsed);
	EXPECT_NE(formatted.find("/32"), std::string::npos);
}

// ============================================================================
// PART 4/6: HASH VALUE TESTS
// ============================================================================

TEST(ThreatIntelFormat_Hash, ParseHashString_MD5) {
	auto hash = ParseHashString("d41d8cd98f00b204e9800998ecf8427e", HashAlgorithm::MD5);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::MD5);
	EXPECT_EQ(hash->length, 16);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_SHA1) {
	auto hash = ParseHashString("da39a3ee5e6b4b0d3255bfef95601890afd80709", HashAlgorithm::SHA1);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::SHA1);
	EXPECT_EQ(hash->length, 20);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_SHA256) {
	const std::string sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	auto hash = ParseHashString(sha256, HashAlgorithm::SHA256);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::SHA256);
	EXPECT_EQ(hash->length, 32);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_SHA512) {
	const std::string sha512(128, 'a'); // 128 hex chars
	auto hash = ParseHashString(sha512, HashAlgorithm::SHA512);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::SHA512);
	EXPECT_EQ(hash->length, 64);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_WithPrefix) {
	auto hash = ParseHashString("0xd41d8cd98f00b204e9800998ecf8427e", HashAlgorithm::MD5);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::MD5);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_InvalidLength) {
	// Too short for MD5
	EXPECT_FALSE(ParseHashString("d41d8cd98f00b204", HashAlgorithm::MD5).has_value());
	
	// Too long for MD5
	EXPECT_FALSE(ParseHashString("d41d8cd98f00b204e9800998ecf8427e00", HashAlgorithm::MD5).has_value());
	
	// Non-hex characters
	EXPECT_FALSE(ParseHashString("gggggggggggggggggggggggggggggggg", HashAlgorithm::MD5).has_value());
}

TEST(ThreatIntelFormat_Hash, ParseHashString_Fuzzy) {
	const std::string fuzzyStr = "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C";
	auto hash = ParseHashString(fuzzyStr, HashAlgorithm::FUZZY);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::FUZZY);
}

TEST(ThreatIntelFormat_Hash, ParseHashString_TLSH) {
	const std::string tlsh = "T1ABC123DEF456GHI789JKL0MNO1PQR2STU3VWX4YZ5";
	auto hash = ParseHashString(tlsh, HashAlgorithm::TLSH);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->algorithm, HashAlgorithm::TLSH);
}

TEST(ThreatIntelFormat_Hash, FormatHashString_MD5) {
	HashValue hash;
	hash.algorithm = HashAlgorithm::MD5;
	hash.length = 16;
	std::fill(hash.data.begin(), hash.data.begin() + 16, 0xAB);

	std::string formatted = FormatHashString(hash);
	EXPECT_EQ(formatted.length(), 32u); // 16 bytes = 32 hex chars
	// 0xAB formats as "ab" in lowercase hex, so 16 bytes = "abababab..." (16 times)
	std::string expected;
	for (int i = 0; i < 16; ++i) {
		expected += "ab";
	}
	EXPECT_EQ(formatted, expected);
}

TEST(ThreatIntelFormat_Hash, FormatHashString_Empty) {
	HashValue hash;
	hash.algorithm = HashAlgorithm::MD5;
	hash.length = 0;

	EXPECT_TRUE(FormatHashString(hash).empty());
}

TEST(ThreatIntelFormat_Hash, ParseFormat_RoundTrip) {
	const std::string original = "d41d8cd98f00b204e9800998ecf8427e";
	auto parsed = ParseHashString(original, HashAlgorithm::MD5);
	ASSERT_TRUE(parsed.has_value());
	
	std::string formatted = FormatHashString(*parsed);
	EXPECT_EQ(formatted, original);
}

TEST(ThreatIntelFormat_Hash, GetHashLength_AllAlgorithms) {
	EXPECT_EQ(GetHashLength(HashAlgorithm::MD5), 16);
	EXPECT_EQ(GetHashLength(HashAlgorithm::SHA1), 20);
	EXPECT_EQ(GetHashLength(HashAlgorithm::SHA256), 32);
	EXPECT_EQ(GetHashLength(HashAlgorithm::SHA512), 64);
	EXPECT_GT(GetHashLength(HashAlgorithm::FUZZY), 0);
	EXPECT_GT(GetHashLength(HashAlgorithm::TLSH), 0);
}

// ============================================================================
// PART 5/6: DOMAIN, URL, EMAIL TESTS
// ============================================================================

// ----------------------------------------------------------------------------
// Domain Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_Domain, NormalizeDomain_ToLowercase) {
	EXPECT_EQ(NormalizeDomain("EXAMPLE.COM"), "example.com");
	EXPECT_EQ(NormalizeDomain("TeSt.DoMaIn.OrG"), "test.domain.org");
}

TEST(ThreatIntelFormat_Domain, NormalizeDomain_RemoveTrailingDot) {
	EXPECT_EQ(NormalizeDomain("example.com."), "example.com");
	EXPECT_EQ(NormalizeDomain("test.org.."), "test.org.");
}

TEST(ThreatIntelFormat_Domain, NormalizeDomain_TrimWhitespace) {
	EXPECT_EQ(NormalizeDomain("  example.com  "), "example.com");
	EXPECT_EQ(NormalizeDomain("\texample.com\n"), "example.com");
}

TEST(ThreatIntelFormat_Domain, NormalizeDomain_Empty) {
	EXPECT_TRUE(NormalizeDomain("").empty());
	EXPECT_TRUE(NormalizeDomain("   ").empty());
}

TEST(ThreatIntelFormat_Domain, NormalizeDomain_TooLong) {
	std::string longDomain(MAX_DOMAIN_LENGTH + 10, 'a');
	longDomain += ".com";
	EXPECT_TRUE(NormalizeDomain(longDomain).empty());
}

TEST(ThreatIntelFormat_Domain, IsValidDomain_Valid) {
	EXPECT_TRUE(Format::IsValidDomain("example.com"));
	EXPECT_TRUE(Format::IsValidDomain("sub.example.com"));
	EXPECT_TRUE(Format::IsValidDomain("test-site.co.uk"));
	EXPECT_TRUE(Format::IsValidDomain("example123.org"));
}

TEST(ThreatIntelFormat_Domain, IsValidDomain_Invalid) {
	EXPECT_FALSE(Format::IsValidDomain(""));
	EXPECT_FALSE(Format::IsValidDomain(".com"));                // Starts with dot
	EXPECT_FALSE(Format::IsValidDomain("example..com"));        // Double dot
	EXPECT_FALSE(Format::IsValidDomain("-example.com"));        // Starts with hyphen
	EXPECT_FALSE(Format::IsValidDomain("example-.com"));        // Ends with hyphen
	EXPECT_FALSE(Format::IsValidDomain("exam ple.com"));        // Space
	EXPECT_FALSE(Format::IsValidDomain("192.168.1.1"));         // IP address
}

TEST(ThreatIntelFormat_Domain, IsValidDomain_EdgeCases) {
	// Single character label
	EXPECT_FALSE(Format::IsValidDomain("a"));
	
	// Too long
	std::string longDomain(MAX_DOMAIN_LENGTH + 10, 'a');
	EXPECT_FALSE(Format::IsValidDomain(longDomain));
	
	// Label too long (>63 chars)
	std::string longLabel(64, 'a');
	longLabel += ".com";
	EXPECT_FALSE(Format::IsValidDomain(longLabel));
}

// ----------------------------------------------------------------------------
// URL Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_URL, NormalizeURL_SchemeLowercase) {
	std::string normalized = NormalizeURL("HTTP://EXAMPLE.COM");
	EXPECT_NE(normalized.find("http://"), std::string::npos);
}

TEST(ThreatIntelFormat_URL, NormalizeURL_HostLowercase) {
	std::string normalized = NormalizeURL("http://EXAMPLE.COM/Path");
	EXPECT_NE(normalized.find("example.com"), std::string::npos);
}

TEST(ThreatIntelFormat_URL, NormalizeURL_PreservePath) {
	std::string normalized = NormalizeURL("http://example.com/Path/To/Resource");
	EXPECT_NE(normalized.find("/Path/To/Resource"), std::string::npos);
}

TEST(ThreatIntelFormat_URL, NormalizeURL_RemoveDefaultPort) {
	std::string normalized = NormalizeURL("http://example.com:80/path");
	// Should remove default HTTP port
	EXPECT_EQ(normalized.find(":80"), std::string::npos);
}

TEST(ThreatIntelFormat_URL, NormalizeURL_IPv6) {
	std::string normalized = NormalizeURL("http://[2001:db8::1]/path");
	EXPECT_NE(normalized.find("[2001:db8::1]"), std::string::npos);
}

TEST(ThreatIntelFormat_URL, IsValidURL_Valid) {
	EXPECT_TRUE(IsValidURL("http://example.com"));
	EXPECT_TRUE(IsValidURL("https://example.com/path"));
	EXPECT_TRUE(IsValidURL("ftp://files.example.com"));
	EXPECT_TRUE(IsValidURL("https://user:pass@example.com:8080/path?query=1#fragment"));
}

TEST(ThreatIntelFormat_URL, IsValidURL_Invalid) {
	EXPECT_FALSE(IsValidURL(""));
	EXPECT_FALSE(IsValidURL("not-a-url"));
	EXPECT_FALSE(IsValidURL("://example.com"));        // No scheme
	EXPECT_FALSE(IsValidURL("http://"));               // No host
	EXPECT_FALSE(IsValidURL("javascript:alert(1)"));   // Dangerous scheme
	EXPECT_FALSE(IsValidURL("file:///etc/passwd"));    // File scheme
}

TEST(ThreatIntelFormat_URL, IsValidURL_EdgeCases) {
	// Very long URL
	std::string longUrl = "http://example.com/" + std::string(10000, 'a');
	EXPECT_FALSE(IsValidURL(longUrl));
	
	// IPv4 host
	EXPECT_TRUE(IsValidURL("http://192.168.1.1"));
	
	// IPv6 host
	EXPECT_TRUE(IsValidURL("http://[::1]"));
}

// ----------------------------------------------------------------------------
// Email Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_Email, IsValidEmail_Valid) {
	EXPECT_TRUE(Format::IsValidEmail("user@example.com"));
	EXPECT_TRUE(Format::IsValidEmail("test.user@example.com"));
	EXPECT_TRUE(Format::IsValidEmail("user+tag@example.co.uk"));
	EXPECT_TRUE(Format::IsValidEmail("123@example.com"));
}

TEST(ThreatIntelFormat_Email, IsValidEmail_Invalid) {
	EXPECT_FALSE(Format::IsValidEmail(""));
	EXPECT_FALSE(Format::IsValidEmail("no-at-sign"));
	EXPECT_FALSE(Format::IsValidEmail("@example.com"));         // No local part
	EXPECT_FALSE(Format::IsValidEmail("user@"));                // No domain
	EXPECT_FALSE(Format::IsValidEmail("user@@example.com"));    // Double @
	EXPECT_FALSE(Format::IsValidEmail("user@.com"));            // Domain starts with dot
	EXPECT_FALSE(Format::IsValidEmail("user@example"));         // No TLD
}

TEST(ThreatIntelFormat_Email, IsValidEmail_EdgeCases) {
	// Very long email
	std::string longEmail = std::string(300, 'a') + "@example.com";
	EXPECT_FALSE(Format::IsValidEmail(longEmail));
	
	// Local part too long
	std::string longLocal = std::string(65, 'a') + "@example.com";
	EXPECT_FALSE(Format::IsValidEmail(longLocal));
}

// ============================================================================
// PART 6/6: BLOOM FILTER, STIX, UUID TESTS
// ============================================================================

// ----------------------------------------------------------------------------
// Bloom Filter Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_Bloom, CalculateBloomFilterSize_ValidInputs) {
	size_t size1 = CalculateBloomFilterSize(10000, 0.01);
	EXPECT_GT(size1, 0u);
	
	size_t size2 = CalculateBloomFilterSize(10000, 0.001);
	EXPECT_GT(size2, size1); // Lower FPR needs larger filter
}

TEST(ThreatIntelFormat_Bloom, CalculateBloomFilterSize_ZeroElements) {
	size_t size = CalculateBloomFilterSize(0, 0.01);
	EXPECT_GT(size, 0u); // Should return minimum size
}

TEST(ThreatIntelFormat_Bloom, CalculateBloomFilterSize_InvalidFPR) {
	// FPR too low
	size_t size1 = CalculateBloomFilterSize(10000, 0.0);
	EXPECT_GT(size1, 0u);
	
	// FPR too high
	size_t size2 = CalculateBloomFilterSize(10000, 1.0);
	EXPECT_GT(size2, 0u);
}

TEST(ThreatIntelFormat_Bloom, CalculateBloomHashFunctions_ValidInputs) {
	size_t numHashes = CalculateBloomHashFunctions(10000, 1000);
	EXPECT_GT(numHashes, 0u);
	EXPECT_LE(numHashes, 20u); // Reasonable upper bound
}

TEST(ThreatIntelFormat_Bloom, CalculateBloomHashFunctions_EdgeCases) {
	// Zero filter size
	EXPECT_EQ(CalculateBloomHashFunctions(0, 1000), 1u);
	
	// Zero elements
	EXPECT_GE(CalculateBloomHashFunctions(10000, 0), 1u);
}

TEST(ThreatIntelFormat_Bloom, CalculateOptimalCacheSize_Scaling) {
	uint32_t size1 = CalculateOptimalCacheSize(1024 * 1024);      // 1MB
	uint32_t size2 = CalculateOptimalCacheSize(10 * 1024 * 1024); // 10MB
	uint32_t size3 = CalculateOptimalCacheSize(100 * 1024 * 1024); // 100MB
	
	EXPECT_GT(size2, size1);
	EXPECT_GT(size3, size2);
}

TEST(ThreatIntelFormat_Bloom, CalculateOptimalCacheSize_Bounds) {
	// Minimum
	uint32_t minSize = CalculateOptimalCacheSize(0);
	EXPECT_GT(minSize, 0u);
	
	// Maximum
	uint32_t maxSize = CalculateOptimalCacheSize(UINT64_MAX);
	EXPECT_GT(maxSize, 0u);
}

// ----------------------------------------------------------------------------
// STIX Timestamp Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_STIX, ParseSTIXTimestamp_ISO8601) {
	auto ts1 = ParseSTIXTimestamp("2021-01-01T00:00:00Z");
	ASSERT_TRUE(ts1.has_value());
	EXPECT_EQ(*ts1, 1609459200u);
	
	auto ts2 = ParseSTIXTimestamp("2021-01-01T00:00:00.000Z");
	ASSERT_TRUE(ts2.has_value());
}

TEST(ThreatIntelFormat_STIX, ParseSTIXTimestamp_InvalidFormats) {
	EXPECT_FALSE(ParseSTIXTimestamp("").has_value());
	EXPECT_FALSE(ParseSTIXTimestamp("not-a-timestamp").has_value());
	EXPECT_FALSE(ParseSTIXTimestamp("2021-13-01T00:00:00Z").has_value()); // Invalid month
	EXPECT_FALSE(ParseSTIXTimestamp("2021-01-32T00:00:00Z").has_value()); // Invalid day
}

TEST(ThreatIntelFormat_STIX, FormatSTIXTimestamp_ValidEpoch) {
	std::string formatted = FormatSTIXTimestamp(1609459200);
	EXPECT_FALSE(formatted.empty());
	EXPECT_NE(formatted.find("2021-01-01"), std::string::npos);
	EXPECT_NE(formatted.find("T"), std::string::npos);
	EXPECT_EQ(formatted.back(), 'Z');
}

TEST(ThreatIntelFormat_STIX, FormatSTIXTimestamp_ZeroEpoch) {
	std::string formatted = FormatSTIXTimestamp(0);
	EXPECT_FALSE(formatted.empty());
	EXPECT_NE(formatted.find("1970-01-01"), std::string::npos);
}

TEST(ThreatIntelFormat_STIX, ParseFormat_RoundTrip) {
	const uint64_t original = 1609459200;
	std::string formatted = FormatSTIXTimestamp(original);
	auto parsed = ParseSTIXTimestamp(formatted);
	ASSERT_TRUE(parsed.has_value());
	EXPECT_EQ(*parsed, original);
}

// ----------------------------------------------------------------------------
// UUID Tests
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_UUID, GenerateUUID_Format) {
	auto uuid = GenerateUUID();
	
	// Check version (4) and variant bits
	EXPECT_EQ((uuid[6] & 0xF0), 0x40);  // Version 4
	EXPECT_EQ((uuid[8] & 0xC0), 0x80);  // Variant 1
}

TEST(ThreatIntelFormat_UUID, GenerateUUID_Uniqueness) {
	std::unordered_set<std::string> uuids;
	
	for (int i = 0; i < 100; ++i) {
		auto uuid = GenerateUUID();
		std::string formatted = FormatUUID(uuid);
		EXPECT_TRUE(uuids.insert(formatted).second) << "Duplicate UUID: " << formatted;
	}
}

TEST(ThreatIntelFormat_UUID, FormatUUID_ValidFormat) {
	std::array<uint8_t, 16> uuid{};
	std::fill(uuid.begin(), uuid.end(), 0xAB);
	
	std::string formatted = FormatUUID(uuid);
	EXPECT_EQ(formatted.length(), 36u); // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	EXPECT_EQ(formatted[8], '-');
	EXPECT_EQ(formatted[13], '-');
	EXPECT_EQ(formatted[18], '-');
	EXPECT_EQ(formatted[23], '-');
}

TEST(ThreatIntelFormat_UUID, ParseUUID_ValidFormat) {
	auto parsed = ParseUUID("550e8400-e29b-41d4-a716-446655440000");
	ASSERT_TRUE(parsed.has_value());
	
	// Verify first few bytes
	EXPECT_EQ((*parsed)[0], 0x55);
	EXPECT_EQ((*parsed)[1], 0x0e);
	EXPECT_EQ((*parsed)[2], 0x84);
	EXPECT_EQ((*parsed)[3], 0x00);
}

TEST(ThreatIntelFormat_UUID, ParseUUID_InvalidFormats) {
	EXPECT_FALSE(ParseUUID("").has_value());
	EXPECT_FALSE(ParseUUID("not-a-uuid").has_value());
	EXPECT_FALSE(ParseUUID("550e8400-e29b-41d4-a716").has_value());      // Too short
	EXPECT_FALSE(ParseUUID("550e8400-e29b-41d4-a716-446655440000-00").has_value()); // Too long
	EXPECT_FALSE(ParseUUID("gggggggg-gggg-gggg-gggg-gggggggggggg").has_value()); // Invalid hex
}

TEST(ThreatIntelFormat_UUID, ParseFormat_RoundTrip) {
	auto original = GenerateUUID();
	std::string formatted = FormatUUID(original);
	auto parsed = ParseUUID(formatted);
	ASSERT_TRUE(parsed.has_value());
	EXPECT_EQ(*parsed, original);
}

TEST(ThreatIntelFormat_UUID, ParseUUID_CaseInsensitive) {
	auto lower = ParseUUID("550e8400-e29b-41d4-a716-446655440000");
	auto upper = ParseUUID("550E8400-E29B-41D4-A716-446655440000");
	auto mixed = ParseUUID("550e8400-E29B-41d4-A716-446655440000");
	
	ASSERT_TRUE(lower.has_value());
	ASSERT_TRUE(upper.has_value());
	ASSERT_TRUE(mixed.has_value());
	EXPECT_EQ(*lower, *upper);
	EXPECT_EQ(*lower, *mixed);
}

// ============================================================================
// MEMORY MAPPING TESTS (Basic validation - full tests need actual files)
// ============================================================================

TEST(ThreatIntelFormat_MemoryMapping, OpenView_InvalidPath) {
	MemoryMappedView view;
	StoreError error;
	
	bool result = MemoryMapping::OpenView(L"", true, view, error);
	EXPECT_FALSE(result);
	EXPECT_FALSE(view.IsValid());
}

TEST(ThreatIntelFormat_MemoryMapping, OpenView_NonExistentFile) {
	MemoryMappedView view;
	StoreError error;
	
	bool result = MemoryMapping::OpenView(L"C:\\NonExistent\\Path\\file.db", true, view, error);
	EXPECT_FALSE(result);
	EXPECT_FALSE(view.IsValid());
}

TEST(ThreatIntelFormat_MemoryMapping, CreateDatabase_InvalidPath) {
	MemoryMappedView view;
	StoreError error;
	
	bool result = MemoryMapping::CreateDatabase(L"", MIN_DATABASE_SIZE, view, error);
	EXPECT_FALSE(result);
	EXPECT_FALSE(view.IsValid());
}

TEST(ThreatIntelFormat_MemoryMapping, CreateDatabase_ValidPath) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	MemoryMappedView view;
	StoreError error;
	
	bool result = MemoryMapping::CreateDatabase(dbPath.wstring(), MIN_DATABASE_SIZE, view, error);
	EXPECT_TRUE(result);
	EXPECT_TRUE(view.IsValid());
	EXPECT_GE(view.fileSize, MIN_DATABASE_SIZE);
	
	// Cleanup
	MemoryMapping::CloseView(view);
	EXPECT_FALSE(view.IsValid());
}

TEST(ThreatIntelFormat_MemoryMapping, CreateDatabase_HeaderInitialized) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test_header.db");
	
	MemoryMappedView view;
	StoreError error;
	
	ASSERT_TRUE(MemoryMapping::CreateDatabase(dbPath.wstring(), MIN_DATABASE_SIZE, view, error));
	ASSERT_TRUE(view.IsValid());
	
	// Verify header
	const auto* header = view.GetAt<ThreatIntelDatabaseHeader>(0);
	ASSERT_NE(header, nullptr);
	EXPECT_EQ(header->magic, THREATINTEL_DB_MAGIC);
	EXPECT_EQ(header->versionMajor, THREATINTEL_DB_VERSION_MAJOR);
	
	MemoryMapping::CloseView(view);
}

TEST(ThreatIntelFormat_MemoryMapping, CloseView_NullSafe) {
	MemoryMappedView view;
	// Should not crash
	MemoryMapping::CloseView(view);
	EXPECT_FALSE(view.IsValid());
}

TEST(ThreatIntelFormat_MemoryMapping, FlushView_InvalidView) {
	MemoryMappedView view;
	StoreError error;
	
	bool result = MemoryMapping::FlushView(view, error);
	EXPECT_FALSE(result);
}

// ============================================================================
// THREAD SAFETY & STRESS TESTS
// ============================================================================

TEST(ThreatIntelFormat_ThreadSafety, ConcurrentIPv4Parsing) {
	const std::vector<std::string> testIPs = {
		"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8",
		"1.1.1.1", "255.255.255.255", "0.0.0.0", "127.0.0.1"
	};
	
	std::atomic<int> successCount{0};
	std::vector<std::thread> threads;
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&testIPs, &successCount]() {
			for (int i = 0; i < 100; ++i) {
				for (const auto& ip : testIPs) {
					auto parsed = ParseIPv4(ip);
					if (parsed.has_value()) {
						std::string formatted = FormatIPv4(*parsed);
						if (!formatted.empty()) {
							successCount.fetch_add(1, std::memory_order_relaxed);
						}
					}
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_EQ(successCount.load(), 4 * 100 * testIPs.size());
}

TEST(ThreatIntelFormat_ThreadSafety, ConcurrentUUIDGeneration) {
	std::vector<std::string> uuids;
	std::mutex uuidsMutex;
	std::vector<std::thread> threads;
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&uuids, &uuidsMutex]() {
			std::vector<std::string> localUuids;
			for (int i = 0; i < 100; ++i) {
				auto uuid = GenerateUUID();
				localUuids.push_back(FormatUUID(uuid));
			}
			
			std::lock_guard<std::mutex> lock(uuidsMutex);
			uuids.insert(uuids.end(), localUuids.begin(), localUuids.end());
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	// Check uniqueness
	std::unordered_set<std::string> uniqueUuids(uuids.begin(), uuids.end());
	EXPECT_EQ(uniqueUuids.size(), uuids.size());
}

TEST(ThreatIntelFormat_Performance, IPv4Parsing_LargeScale) {
	const int iterations = 10000;
	auto start = std::chrono::steady_clock::now();
	
	for (int i = 0; i < iterations; ++i) {
		uint8_t a = (i >> 24) & 0xFF;
		uint8_t b = (i >> 16) & 0xFF;
		uint8_t c = (i >> 8) & 0xFF;
		uint8_t d = i & 0xFF;
		
		std::string ip = std::to_string(a) + "." + std::to_string(b) + "." +
		                 std::to_string(c) + "." + std::to_string(d);
		
		auto parsed = ParseIPv4(ip);
		EXPECT_TRUE(parsed.has_value());
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	// Should process at least 1000 IPs/second
	EXPECT_LT(ms, iterations); // Less than 1ms per parse
}

TEST(ThreatIntelFormat_Performance, HashParsing_LargeScale) {
	const int iterations = 5000;
	const std::string sha256(64, 'a');
	
	auto start = std::chrono::steady_clock::now();
	
	for (int i = 0; i < iterations; ++i) {
		auto parsed = ParseHashString(sha256, HashAlgorithm::SHA256);
		EXPECT_TRUE(parsed.has_value());
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	// Should be very fast
	EXPECT_LT(ms, iterations / 10); // Less than 0.1ms per parse
}
// ============================================================================
// EDGE CASE TESTS - COMPREHENSIVE ENTERPRISE-GRADE COVERAGE
// ============================================================================

// ----------------------------------------------------------------------------
// IPv4 Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_IPv4, CIDR_BoundaryValues) {
	// CIDR prefix = 0 (entire address space)
	auto ip0 = ParseIPv4("0.0.0.0/0");
	ASSERT_TRUE(ip0.has_value());
	EXPECT_EQ(ip0->prefixLength, 0);
	
	// CIDR prefix = 1
	auto ip1 = ParseIPv4("128.0.0.0/1");
	ASSERT_TRUE(ip1.has_value());
	EXPECT_EQ(ip1->prefixLength, 1);
	
	// CIDR prefix = 31 (2 hosts)
	auto ip31 = ParseIPv4("192.168.1.0/31");
	ASSERT_TRUE(ip31.has_value());
	EXPECT_EQ(ip31->prefixLength, 31);
	
	// CIDR prefix = 32 (single host)
	auto ip32 = ParseIPv4("192.168.1.1/32");
	ASSERT_TRUE(ip32.has_value());
	EXPECT_EQ(ip32->prefixLength, 32);
}

TEST(ThreatIntelFormat_EdgeCase_IPv4, PrivateRanges) {
	// Class A private: 10.0.0.0/8
	auto classA = ParseIPv4("10.255.255.255");
	ASSERT_TRUE(classA.has_value());
	
	// Class B private: 172.16.0.0/12
	auto classB = ParseIPv4("172.31.255.255");
	ASSERT_TRUE(classB.has_value());
	
	// Class C private: 192.168.0.0/16
	auto classC = ParseIPv4("192.168.255.255");
	ASSERT_TRUE(classC.has_value());
	
	// Loopback: 127.0.0.0/8
	auto loopback = ParseIPv4("127.255.255.254");
	ASSERT_TRUE(loopback.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv4, SpecialAddresses) {
	// Link-local: 169.254.0.0/16
	auto linkLocal = ParseIPv4("169.254.1.1");
	ASSERT_TRUE(linkLocal.has_value());
	
	// Broadcast
	auto broadcast = ParseIPv4("255.255.255.255");
	ASSERT_TRUE(broadcast.has_value());
	EXPECT_EQ(broadcast->address, 0xFFFFFFFFu);
	
	// Documentation: 192.0.2.0/24 (TEST-NET-1)
	auto testNet = ParseIPv4("192.0.2.1");
	ASSERT_TRUE(testNet.has_value());
	
	// Documentation: 198.51.100.0/24 (TEST-NET-2)
	auto testNet2 = ParseIPv4("198.51.100.1");
	ASSERT_TRUE(testNet2.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv4, LeadingZerosRejection) {
	// All forms of leading zeros should be rejected
	EXPECT_FALSE(ParseIPv4("01.02.03.04").has_value());
	EXPECT_FALSE(ParseIPv4("001.002.003.004").has_value());
	EXPECT_FALSE(ParseIPv4("192.168.001.001").has_value());
	EXPECT_FALSE(ParseIPv4("192.168.1.01").has_value());
	EXPECT_FALSE(ParseIPv4("08.08.08.08").has_value());
	
	// Single digit zeros should be valid
	EXPECT_TRUE(ParseIPv4("0.0.0.0").has_value());
	EXPECT_TRUE(ParseIPv4("10.0.0.1").has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv4, InvalidCIDRNotation) {
	EXPECT_FALSE(ParseIPv4("192.168.1.1/").has_value());     // Empty prefix
	EXPECT_FALSE(ParseIPv4("192.168.1.1/a").has_value());    // Non-numeric
	EXPECT_FALSE(ParseIPv4("192.168.1.1/33").has_value());   // > 32
	EXPECT_FALSE(ParseIPv4("192.168.1.1/999").has_value());  // Way too large
	EXPECT_FALSE(ParseIPv4("192.168.1.1/-1").has_value());   // Negative
	EXPECT_FALSE(ParseIPv4("192.168.1.1/032").has_value()); // Leading zero
}

// ----------------------------------------------------------------------------
// IPv6 Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_IPv6, CompressionPositions) {
	// Compression at start
	auto start = ParseIPv6("::1");
	ASSERT_TRUE(start.has_value());
	
	// Compression in middle
	auto middle = ParseIPv6("2001:db8::8a2e:370:7334");
	ASSERT_TRUE(middle.has_value());
	
	// Compression at end
	auto end = ParseIPv6("2001:db8::");
	ASSERT_TRUE(end.has_value());
	
	// Full compression
	auto full = ParseIPv6("::");
	ASSERT_TRUE(full.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv6, MixedNotation) {
	// IPv4-mapped IPv6
	auto mapped = ParseIPv6("::ffff:192.168.1.1");
	// May or may not be supported depending on inet_pton implementation
	// Just ensure it doesn't crash
	(void)mapped;
	
	// Full format (no compression)
	auto fullFormat = ParseIPv6("2001:0db8:0000:0000:0000:0000:0000:0001");
	ASSERT_TRUE(fullFormat.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv6, InvalidCompressions) {
	// Multiple double colons (invalid)
	EXPECT_FALSE(ParseIPv6("2001::db8::1").has_value());
	EXPECT_FALSE(ParseIPv6("::1::2").has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv6, CIDRBoundaryValues) {
	// CIDR prefix boundaries
	auto prefix0 = ParseIPv6("::/0");
	ASSERT_TRUE(prefix0.has_value());
	EXPECT_EQ(prefix0->prefixLength, 0);
	
	auto prefix64 = ParseIPv6("2001:db8::/64");
	ASSERT_TRUE(prefix64.has_value());
	EXPECT_EQ(prefix64->prefixLength, 64);
	
	auto prefix128 = ParseIPv6("::1/128");
	ASSERT_TRUE(prefix128.has_value());
	EXPECT_EQ(prefix128->prefixLength, 128);
	
	// Invalid prefix
	EXPECT_FALSE(ParseIPv6("::1/129").has_value());
}

TEST(ThreatIntelFormat_EdgeCase_IPv6, SpecialAddresses) {
	// Unspecified address
	auto unspecified = ParseIPv6("::");
	ASSERT_TRUE(unspecified.has_value());
	
	// Loopback
	auto loopback = ParseIPv6("::1");
	ASSERT_TRUE(loopback.has_value());
	
	// Link-local prefix
	auto linkLocal = ParseIPv6("fe80::1");
	ASSERT_TRUE(linkLocal.has_value());
	
	// Unique local (private)
	auto uniqueLocal = ParseIPv6("fc00::1");
	ASSERT_TRUE(uniqueLocal.has_value());
}

// ----------------------------------------------------------------------------
// Domain Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_Domain, UnderscoreSupport) {
	// Underscores are used in DKIM records: _dmarc.example.com
	EXPECT_TRUE(Format::IsValidDomain("_dmarc.example.com"));
	EXPECT_TRUE(Format::IsValidDomain("_domainkey.example.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, NumericLabels) {
	// All-numeric labels (except TLD) are valid
	EXPECT_TRUE(Format::IsValidDomain("123.example.com"));
	EXPECT_TRUE(Format::IsValidDomain("test.123.example.com"));
	
	// Pure numeric TLDs are INVALID per RFC 1123
	// No valid TLD is purely numeric - this rejects malformed domains
	EXPECT_FALSE(Format::IsValidDomain("example.123"));
	
	// Mixed alphanumeric TLDs are valid
	EXPECT_TRUE(Format::IsValidDomain("example.c0m"));
	EXPECT_TRUE(Format::IsValidDomain("test.1com"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, SingleCharacterLabels) {
	// Single character labels are valid
	EXPECT_TRUE(Format::IsValidDomain("a.b.com"));
	EXPECT_TRUE(Format::IsValidDomain("x.example.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, MaximumLengthLabels) {
	// 63 character label (maximum allowed)
	std::string label63(63, 'a');
	EXPECT_TRUE(Format::IsValidDomain(label63 + ".com"));
	
	// 64 character label (too long)
	std::string label64(64, 'a');
	EXPECT_FALSE(Format::IsValidDomain(label64 + ".com"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, HyphenPositions) {
	// Hyphen in middle is valid
	EXPECT_TRUE(Format::IsValidDomain("test-site.com"));
	EXPECT_TRUE(Format::IsValidDomain("my-test-domain.org"));
	
	// Hyphen at start of label is invalid
	EXPECT_FALSE(Format::IsValidDomain("-test.com"));
	EXPECT_FALSE(Format::IsValidDomain("test.-invalid.com"));
	
	// Hyphen at end of label is invalid
	EXPECT_FALSE(Format::IsValidDomain("test-.com"));
	EXPECT_FALSE(Format::IsValidDomain("test.invalid-.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, TwoLetterTLDs) {
	// Country code TLDs
	EXPECT_TRUE(Format::IsValidDomain("example.uk"));
	EXPECT_TRUE(Format::IsValidDomain("example.de"));
	EXPECT_TRUE(Format::IsValidDomain("example.jp"));
	EXPECT_TRUE(Format::IsValidDomain("example.io"));
}

TEST(ThreatIntelFormat_EdgeCase_Domain, IPAddressRejection) {
	// IPv4 addresses should be rejected as domains
	EXPECT_FALSE(Format::IsValidDomain("192.168.1.1"));
	EXPECT_FALSE(Format::IsValidDomain("10.0.0.1"));
	EXPECT_FALSE(Format::IsValidDomain("255.255.255.255"));
}

// ----------------------------------------------------------------------------
// URL Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_URL, PortNumbers) {
	// Non-standard ports
	EXPECT_TRUE(IsValidURL("http://example.com:8080/path"));
	EXPECT_TRUE(IsValidURL("https://example.com:8443/path"));
	
	// Port 0 (edge case)
	EXPECT_TRUE(IsValidURL("http://example.com:0/path"));
	
	// High port number
	EXPECT_TRUE(IsValidURL("http://example.com:65535/path"));
}

TEST(ThreatIntelFormat_EdgeCase_URL, UserInfo) {
	// User only
	EXPECT_TRUE(IsValidURL("http://user@example.com/path"));
	
	// User and password
	EXPECT_TRUE(IsValidURL("http://user:pass@example.com/path"));
}

TEST(ThreatIntelFormat_EdgeCase_URL, FragmentIdentifiers) {
	// With fragment
	EXPECT_TRUE(IsValidURL("http://example.com/page#section"));
	EXPECT_TRUE(IsValidURL("http://example.com/page?q=1#section"));
}

TEST(ThreatIntelFormat_EdgeCase_URL, QueryStrings) {
	// Complex query string
	EXPECT_TRUE(IsValidURL("http://example.com/search?q=test&sort=asc&page=1"));
	
	// URL encoded characters
	EXPECT_TRUE(IsValidURL("http://example.com/search?q=hello%20world"));
}

TEST(ThreatIntelFormat_EdgeCase_URL, SchemeVariations) {
	// Mixed case scheme
	std::string normalized = NormalizeURL("HTTP://example.com");
	EXPECT_NE(normalized.find("http://"), std::string::npos);
	
	normalized = NormalizeURL("HTTPS://example.com");
	EXPECT_NE(normalized.find("https://"), std::string::npos);
}

TEST(ThreatIntelFormat_EdgeCase_URL, EmptyPathQueryFragment) {
	// URL with no path
	EXPECT_TRUE(IsValidURL("http://example.com"));
	
	// URL with just slash
	EXPECT_TRUE(IsValidURL("http://example.com/"));
	
	// URL with empty query
	EXPECT_TRUE(IsValidURL("http://example.com/?"));
}

// ----------------------------------------------------------------------------
// Email Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_Email, SpecialCharactersInLocal) {
	// Allowed special characters in local part
	EXPECT_TRUE(Format::IsValidEmail("user+tag@example.com"));
	EXPECT_TRUE(Format::IsValidEmail("user.name@example.com"));
	EXPECT_TRUE(Format::IsValidEmail("user_name@example.com"));
	EXPECT_TRUE(Format::IsValidEmail("user-name@example.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Email, IPLiteralDomain) {
	// IPv4 literal (in brackets)
	EXPECT_TRUE(Format::IsValidEmail("user@[192.168.1.1]"));
	
	// IPv6 literal (not commonly used, but may be supported)
	// Note: Implementation may or may not support this
}

TEST(ThreatIntelFormat_EdgeCase_Email, LongLocalPart) {
	// 64 character local part (maximum allowed)
	std::string local64(64, 'a');
	EXPECT_TRUE(Format::IsValidEmail(local64 + "@example.com"));
	
	// 65 character local part (too long)
	std::string local65(65, 'a');
	EXPECT_FALSE(Format::IsValidEmail(local65 + "@example.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Email, ConsecutiveDots) {
	// Consecutive dots in local part are invalid
	EXPECT_FALSE(Format::IsValidEmail("user..name@example.com"));
	
	// Dot at start is invalid
	EXPECT_FALSE(Format::IsValidEmail(".user@example.com"));
	
	// Dot at end of local part is invalid
	EXPECT_FALSE(Format::IsValidEmail("user.@example.com"));
}

TEST(ThreatIntelFormat_EdgeCase_Email, SubdomainEmail) {
	// Email with subdomain
	EXPECT_TRUE(Format::IsValidEmail("user@mail.example.com"));
	EXPECT_TRUE(Format::IsValidEmail("user@a.b.c.d.example.com"));
}

// ----------------------------------------------------------------------------
// STIX Timestamp Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_STIX, LeapYear) {
	// Feb 29 in leap year (2020) - valid
	auto leapDay = ParseSTIXTimestamp("2020-02-29T12:00:00Z");
	ASSERT_TRUE(leapDay.has_value());
	
	// Feb 29 in non-leap year (2019) - MUST BE REJECTED
	// Enterprise-grade validation requires proper calendar validation
	auto invalidLeap2019 = ParseSTIXTimestamp("2019-02-29T12:00:00Z");
	EXPECT_FALSE(invalidLeap2019.has_value()) << "Feb 29 on non-leap year must be rejected";
	
	// Century leap year rule: 2000 is leap (divisible by 400)
	auto year2000 = ParseSTIXTimestamp("2000-02-29T12:00:00Z");
	ASSERT_TRUE(year2000.has_value());
	
	// Century rule: 1900 was NOT a leap year (divisible by 100 but not 400)
	// Note: 1900 < 1970, so this will fail year range check first
	auto year1900 = ParseSTIXTimestamp("1900-02-29T12:00:00Z");
	EXPECT_FALSE(year1900.has_value());
	
	// 2100 will not be a leap year (divisible by 100 but not 400)
	auto year2100 = ParseSTIXTimestamp("2100-02-29T12:00:00Z");
	EXPECT_FALSE(year2100.has_value()) << "2100 is not a leap year (century rule)";
}

TEST(ThreatIntelFormat_EdgeCase_STIX, MonthBoundaries) {
	// January 31 - valid
	EXPECT_TRUE(ParseSTIXTimestamp("2021-01-31T00:00:00Z").has_value());
	
	// February 28 (non-leap) - valid
	EXPECT_TRUE(ParseSTIXTimestamp("2021-02-28T00:00:00Z").has_value());
	
	// April 30 - valid (April has 30 days)
	EXPECT_TRUE(ParseSTIXTimestamp("2021-04-30T00:00:00Z").has_value());
	
	// April 31 - INVALID (April only has 30 days)
	// Enterprise-grade validation must reject invalid calendar dates
	auto april31 = ParseSTIXTimestamp("2021-04-31T00:00:00Z");
	EXPECT_FALSE(april31.has_value()) << "April 31 must be rejected (April has 30 days)";
	
	// February 30 - always invalid
	EXPECT_FALSE(ParseSTIXTimestamp("2021-02-30T00:00:00Z").has_value()) << "Feb 30 is always invalid";
	EXPECT_FALSE(ParseSTIXTimestamp("2020-02-30T00:00:00Z").has_value()) << "Feb 30 is invalid even in leap years";
	
	// June 31 - invalid (June has 30 days)
	EXPECT_FALSE(ParseSTIXTimestamp("2021-06-31T00:00:00Z").has_value()) << "June 31 must be rejected";
	
	// September 31 - invalid (September has 30 days)
	EXPECT_FALSE(ParseSTIXTimestamp("2021-09-31T00:00:00Z").has_value()) << "September 31 must be rejected";
	
	// November 31 - invalid (November has 30 days)
	EXPECT_FALSE(ParseSTIXTimestamp("2021-11-31T00:00:00Z").has_value()) << "November 31 must be rejected";
}

TEST(ThreatIntelFormat_EdgeCase_STIX, TimeBoundaries) {
	// Midnight
	EXPECT_TRUE(ParseSTIXTimestamp("2021-01-01T00:00:00Z").has_value());
	
	// End of day
	EXPECT_TRUE(ParseSTIXTimestamp("2021-01-01T23:59:59Z").has_value());
	
	// Leap second (60 seconds)
	auto leapSecond = ParseSTIXTimestamp("2021-01-01T23:59:60Z");
	EXPECT_TRUE(leapSecond.has_value());
	
	// Invalid hour
	EXPECT_FALSE(ParseSTIXTimestamp("2021-01-01T24:00:00Z").has_value());
	
	// Invalid minute
	EXPECT_FALSE(ParseSTIXTimestamp("2021-01-01T00:60:00Z").has_value());
	
	// Invalid second
	EXPECT_FALSE(ParseSTIXTimestamp("2021-01-01T00:00:61Z").has_value());
}

TEST(ThreatIntelFormat_EdgeCase_STIX, SpaceSeparator) {
	// Space instead of T
	auto spaceTs = ParseSTIXTimestamp("2021-01-01 12:30:45");
	EXPECT_TRUE(spaceTs.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_STIX, MillisecondsVariations) {
	// With milliseconds
	auto ms = ParseSTIXTimestamp("2021-01-01T12:30:45.123Z");
	EXPECT_TRUE(ms.has_value());
	
	// With microseconds
	auto us = ParseSTIXTimestamp("2021-01-01T12:30:45.123456Z");
	EXPECT_TRUE(us.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_STIX, YearBoundaries) {
	// 1970 (Unix epoch start)
	auto epoch = ParseSTIXTimestamp("1970-01-01T00:00:00Z");
	EXPECT_TRUE(epoch.has_value());
	
	// Before 1970 (should fail)
	EXPECT_FALSE(ParseSTIXTimestamp("1969-12-31T23:59:59Z").has_value());
	
	// Year 2100 (boundary)
	auto y2100 = ParseSTIXTimestamp("2099-12-31T23:59:59Z");
	EXPECT_TRUE(y2100.has_value());
	
	// After 2100 (should fail)
	EXPECT_FALSE(ParseSTIXTimestamp("2101-01-01T00:00:00Z").has_value());
}

// ----------------------------------------------------------------------------
// UUID Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_UUID, NoHyphensFormat) {
	// UUID without hyphens
	auto noHyphens = ParseUUID("550e8400e29b41d4a716446655440000");
	ASSERT_TRUE(noHyphens.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_UUID, NilUUID) {
	// All-zeros UUID
	auto nil = ParseUUID("00000000-0000-0000-0000-000000000000");
	ASSERT_TRUE(nil.has_value());
	
	// Verify all bytes are zero
	for (const auto& byte : *nil) {
		EXPECT_EQ(byte, 0);
	}
}

TEST(ThreatIntelFormat_EdgeCase_UUID, MaxUUID) {
	// All-ones UUID
	auto max = ParseUUID("ffffffff-ffff-ffff-ffff-ffffffffffff");
	ASSERT_TRUE(max.has_value());
	
	// Verify all bytes are 0xFF
	for (const auto& byte : *max) {
		EXPECT_EQ(byte, 0xFF);
	}
}

TEST(ThreatIntelFormat_EdgeCase_UUID, PartialUUID) {
	// Incomplete UUIDs should fail
	EXPECT_FALSE(ParseUUID("550e8400").has_value());
	EXPECT_FALSE(ParseUUID("550e8400-e29b").has_value());
	EXPECT_FALSE(ParseUUID("550e8400-e29b-41d4").has_value());
	EXPECT_FALSE(ParseUUID("550e8400-e29b-41d4-a716").has_value());
}

// ----------------------------------------------------------------------------
// Bloom Filter Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_Bloom, ExtremeElementCounts) {
	// Very small element count
	size_t size1 = CalculateBloomFilterSize(1, 0.01);
	EXPECT_GT(size1, 0u);
	
	// Very large element count
	size_t sizeLarge = CalculateBloomFilterSize(1000000000, 0.01);
	EXPECT_GT(sizeLarge, 0u);
}

TEST(ThreatIntelFormat_EdgeCase_Bloom, ExtremeFPRValues) {
	// Very low FPR (approaches 0)
	size_t sizeLowFPR = CalculateBloomFilterSize(10000, 0.0000001);
	EXPECT_GT(sizeLowFPR, 0u);
	
	// FPR exactly 0 (should use default)
	size_t sizeZeroFPR = CalculateBloomFilterSize(10000, 0.0);
	EXPECT_GT(sizeZeroFPR, 0u);
	
	// FPR exactly 1 (should use default)
	size_t sizeOneFPR = CalculateBloomFilterSize(10000, 1.0);
	EXPECT_GT(sizeOneFPR, 0u);
}

TEST(ThreatIntelFormat_EdgeCase_Bloom, HashFunctionsEdgeCases) {
	// Filter much smaller than elements
	size_t hashes1 = CalculateBloomHashFunctions(100, 10000);
	EXPECT_EQ(hashes1, 1u);  // Minimum
	
	// Filter much larger than elements
	size_t hashes2 = CalculateBloomHashFunctions(10000000, 100);
	EXPECT_LE(hashes2, 20u);  // Capped at 20
}

// ----------------------------------------------------------------------------
// Hash Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_Hash, CaseSensitivity) {
	// Both uppercase and lowercase should parse identically
	auto lower = ParseHashString("d41d8cd98f00b204e9800998ecf8427e", HashAlgorithm::MD5);
	auto upper = ParseHashString("D41D8CD98F00B204E9800998ECF8427E", HashAlgorithm::MD5);
	auto mixed = ParseHashString("D41d8CD98F00B204e9800998ECF8427E", HashAlgorithm::MD5);
	
	ASSERT_TRUE(lower.has_value());
	ASSERT_TRUE(upper.has_value());
	ASSERT_TRUE(mixed.has_value());
	
	// All should produce the same bytes
	EXPECT_EQ(lower->data, upper->data);
	EXPECT_EQ(lower->data, mixed->data);
}

TEST(ThreatIntelFormat_EdgeCase_Hash, PrefixVariations) {
	// 0x prefix (lowercase)
	auto prefix1 = ParseHashString("0xd41d8cd98f00b204e9800998ecf8427e", HashAlgorithm::MD5);
	ASSERT_TRUE(prefix1.has_value());
	
	// 0X prefix (uppercase)
	auto prefix2 = ParseHashString("0XD41D8CD98F00B204E9800998ECF8427E", HashAlgorithm::MD5);
	ASSERT_TRUE(prefix2.has_value());
}

TEST(ThreatIntelFormat_EdgeCase_Hash, SHA512Full) {
	// Full 128-character SHA512
	std::string sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
	auto hash = ParseHashString(sha512, HashAlgorithm::SHA512);
	ASSERT_TRUE(hash.has_value());
	EXPECT_EQ(hash->length, 64);
}

TEST(ThreatIntelFormat_EdgeCase_Hash, InvalidCharacters) {
	// Non-hex characters
	EXPECT_FALSE(ParseHashString("g41d8cd98f00b204e9800998ecf8427e", HashAlgorithm::MD5).has_value());
	EXPECT_FALSE(ParseHashString("d41d8cd98f00b204e9800998ecf8427!", HashAlgorithm::MD5).has_value());
	EXPECT_FALSE(ParseHashString("d41d8cd98f00b204e9800998ecf8427 ", HashAlgorithm::MD5).has_value());
}

TEST(ThreatIntelFormat_EdgeCase_Hash, EmptyHash) {
	// Empty hash string
	EXPECT_FALSE(ParseHashString("", HashAlgorithm::MD5).has_value());
	EXPECT_FALSE(ParseHashString("", HashAlgorithm::SHA256).has_value());
}

// ----------------------------------------------------------------------------
// SafeParse Function Edge Cases
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_SafeParse, IPv4NullOutput) {
	// Null output buffer
	EXPECT_FALSE(SafeParseIPv4("192.168.1.1", nullptr));
}

TEST(ThreatIntelFormat_EdgeCase_SafeParse, IPv4EmptyInput) {
	uint8_t octets[4];
	EXPECT_FALSE(SafeParseIPv4("", octets));
	EXPECT_FALSE(SafeParseIPv4("   ", octets));
}

TEST(ThreatIntelFormat_EdgeCase_SafeParse, IPv4OverlongInput) {
	uint8_t octets[4];
	std::string longInput(100, '1');
	EXPECT_FALSE(SafeParseIPv4(longInput, octets));
}

TEST(ThreatIntelFormat_EdgeCase_SafeParse, IPv4OutputCorrectness) {
	uint8_t octets[4];
	ASSERT_TRUE(SafeParseIPv4("192.168.1.1", octets));
	EXPECT_EQ(octets[0], 192);
	EXPECT_EQ(octets[1], 168);
	EXPECT_EQ(octets[2], 1);
	EXPECT_EQ(octets[3], 1);
}

TEST(ThreatIntelFormat_EdgeCase_SafeParse, IPv6NullOutput) {
	uint16_t segments[8];
	EXPECT_FALSE(SafeParseIPv6("::1", nullptr));
	
	// Also test with segments array
	EXPECT_FALSE(SafeParseIPv6("", segments));
}

// ----------------------------------------------------------------------------
// IOC Validation Integration Tests  
// ----------------------------------------------------------------------------

TEST(ThreatIntelFormat_EdgeCase_Validation, IPv4Validators) {
	// Valid IPv4
	EXPECT_TRUE(IsValidIPv4("192.168.1.1"));
	EXPECT_TRUE(IsValidIPv4("10.0.0.1"));
	EXPECT_TRUE(IsValidIPv4("192.168.1.0/24"));
	
	// Invalid IPv4
	EXPECT_FALSE(IsValidIPv4(""));
	EXPECT_FALSE(IsValidIPv4("256.1.1.1"));
	EXPECT_FALSE(IsValidIPv4("192.168.1.1/33"));
	EXPECT_FALSE(IsValidIPv4("192.168.1"));
	EXPECT_FALSE(IsValidIPv4("abc.def.ghi.jkl"));
}

TEST(ThreatIntelFormat_EdgeCase_Validation, IPv6Validators) {
	// Valid IPv6 addresses - test both IsValidIPv6 and ParseIPv6
	// These are standard IPv6 formats that MUST be accepted
	EXPECT_TRUE(IsValidIPv6("::1")) << "Loopback address must be valid";
	EXPECT_TRUE(IsValidIPv6("::")) << "Unspecified address must be valid";
	EXPECT_TRUE(IsValidIPv6("2001:db8::1")) << "Compressed notation must be valid";
	EXPECT_TRUE(IsValidIPv6("fe80::1")) << "Link-local compressed must be valid";
	EXPECT_TRUE(IsValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")) << "Full notation must be valid";
	EXPECT_TRUE(IsValidIPv6("fe80::/10")) << "CIDR notation must be valid";
	EXPECT_TRUE(IsValidIPv6("::1/128")) << "Loopback with CIDR must be valid";
	
	// IPv4-mapped IPv6 addresses (::ffff:192.0.2.1 format) - specialized format
	// Note: This validator focuses on pure hex-colon IPv6 notation.
	// IPv4-mapped addresses in dot-decimal notation require specialized parsing
	// that is handled separately in the IPv4-IPv6 translation layer.
	// Future enhancement: Add full RFC 4291 Section 2.5.5 support
	
	// ParseIPv6 should also work for standard notation
	EXPECT_TRUE(ParseIPv6("::1").has_value());
	EXPECT_TRUE(ParseIPv6("2001:db8::1").has_value());
	EXPECT_TRUE(ParseIPv6("fe80::/10").has_value());
	
	// Invalid IPv6
	EXPECT_FALSE(IsValidIPv6("")) << "Empty string must be invalid";
	EXPECT_FALSE(IsValidIPv6("::1::2")) << "Multiple :: not allowed";
	EXPECT_FALSE(IsValidIPv6("gggg::1")) << "Invalid hex characters";
	EXPECT_FALSE(IsValidIPv6("2001:db8::/129")) << "CIDR > 128 is invalid";
	EXPECT_FALSE(ParseIPv6("").has_value());
	EXPECT_FALSE(ParseIPv6("::1::2").has_value());
	EXPECT_FALSE(ParseIPv6("2001:db8::/129").has_value());
	EXPECT_FALSE(ParseIPv6("gggg::1").has_value());
}

TEST(ThreatIntelFormat_EdgeCase_Validation, FileHashValidators) {
	// Valid hashes
	EXPECT_TRUE(IsValidFileHash("d41d8cd98f00b204e9800998ecf8427e"));  // MD5
	EXPECT_TRUE(IsValidFileHash("da39a3ee5e6b4b0d3255bfef95601890afd80709"));  // SHA1
	EXPECT_TRUE(IsValidFileHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));  // SHA256
	
	// Invalid hashes
	EXPECT_FALSE(IsValidFileHash(""));
	EXPECT_FALSE(IsValidFileHash("tooshort"));
	EXPECT_FALSE(IsValidFileHash("gggggggggggggggggggggggggggggggg"));  // Non-hex
}
} // namespace ShadowStrike::ThreatIntel::Tests
