/**
 * @file ThreatIntelImporter_tests.cpp
 * @brief Enterprise-Grade Unit Tests for ThreatIntelImporter
 *
 * Comprehensive test coverage for threat intelligence import operations:
 * - Format utilities (extensions, names, parsing)
 * - Defang/Refang IOC operations
 * - Timestamp parsing (ISO8601, Unix)
 * - CSV import (header detection, field parsing, IOC type detection)
 * - JSON import (document parsing, JSONL support)
 * - STIX 2.1 import (bundle parsing, pattern parsing, type mapping)
 * - MISP import (event/attribute parsing, category mapping)
 * - Plain text import (line parsing, type detection)
 * - OpenIOC import (XML parsing, indicator extraction)
 * - Main importer (file/stream import, validation, normalization)
 * - Thread safety and performance tests
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelImporter.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
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
		const std::string name = std::string("ShadowStrike_Importer_") + 
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

// Mock string pool writer for testing
class MockStringPool : public IStringPoolWriter {
public:
	std::pair<uint64_t, uint32_t> AddString(std::string_view str) override {
		const uint64_t offset = m_strings.size();
		m_strings.emplace_back(str);
		const uint32_t length = static_cast<uint32_t>(str.length());
		return {offset, length};
	}
	
	[[nodiscard]] std::optional<std::pair<uint64_t, uint32_t>> FindString(std::string_view str) const override {
		for (size_t i = 0; i < m_strings.size(); ++i) {
			if (m_strings[i] == str) {
				return std::make_pair(static_cast<uint64_t>(i), static_cast<uint32_t>(str.length()));
			}
		}
		return std::nullopt;
	}
	
	[[nodiscard]] uint64_t GetPoolSize() const noexcept override {
		uint64_t totalSize = 0;
		for (const auto& s : m_strings) {
			totalSize += s.length();
		}
		return totalSize;
	}

	[[nodiscard]] const std::vector<std::string>& GetStrings() const noexcept {
		return m_strings;
	}

private:
	std::vector<std::string> m_strings;
};

// Helper to create test CSV data
[[nodiscard]] std::string CreateTestCSV(bool withHeader = true) {
	std::ostringstream oss;
	if (withHeader) {
		oss << "indicator,type,confidence,reputation,category\n";
	}
	oss << "192.168.1.1,IPv4,High,Malicious,C2\n";
	oss << "evil.com,Domain,Medium,Suspicious,Phishing\n";
	oss << "d41d8cd98f00b204e9800998ecf8427e,MD5,Low,Unknown,Malware\n";
	return oss.str();
}

// Helper to create test JSON data
[[nodiscard]] std::string CreateTestJSON() {
	return R"({
		"indicators": [
			{
				"value": "192.168.1.1",
				"type": "ipv4",
				"confidence": "high",
				"reputation": "malicious",
				"category": "c2"
			},
			{
				"value": "evil.com",
				"type": "domain",
				"confidence": "medium",
				"reputation": "suspicious"
			}
		]
	})";
}

// Helper to create test JSONL data
[[nodiscard]] std::string CreateTestJSONL() {
	return R"({"value":"192.168.1.1","type":"ipv4","reputation":"malicious"}
{"value":"evil.com","type":"domain","reputation":"suspicious"}
{"value":"badsite.org","type":"domain","reputation":"malicious"}
)";
}

// Helper to create test STIX 2.1 bundle
[[nodiscard]] std::string CreateTestSTIXBundle() {
	return R"({
		"type": "bundle",
		"id": "bundle--550e8400-e29b-41d4-a716-446655440000",
		"objects": [
			{
				"type": "indicator",
				"id": "indicator--550e8400-e29b-41d4-a716-446655440001",
				"created": "2021-01-01T00:00:00.000Z",
				"modified": "2021-01-01T00:00:00.000Z",
				"pattern": "[ipv4-addr:value = '192.168.1.1']",
				"pattern_type": "stix",
				"valid_from": "2021-01-01T00:00:00.000Z"
			},
			{
				"type": "indicator",
				"id": "indicator--550e8400-e29b-41d4-a716-446655440002",
				"created": "2021-01-01T00:00:00.000Z",
				"modified": "2021-01-01T00:00:00.000Z",
				"pattern": "[domain-name:value = 'evil.com']",
				"pattern_type": "stix",
				"valid_from": "2021-01-01T00:00:00.000Z"
			}
		]
	})";
}

// Helper to create test MISP event
[[nodiscard]] std::string CreateTestMISPEvent() {
	return R"({
		"Event": {
			"id": "1",
			"uuid": "550e8400-e29b-41d4-a716-446655440000",
			"info": "Test Event",
			"Attribute": [
				{
					"type": "ip-dst",
					"value": "192.168.1.1",
					"category": "Network activity",
					"to_ids": true,
					"comment": "C2 server"
				},
				{
					"type": "domain",
					"value": "evil.com",
					"category": "Network activity",
					"to_ids": true
				}
			]
		}
	})";
}

// Helper to create test OpenIOC document
[[nodiscard]] std::string CreateTestOpenIOC() {
	return R"(<?xml version="1.0" encoding="UTF-8"?>
<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
     id="550e8400-e29b-41d4-a716-446655440000"
     last-modified="2021-01-01T00:00:00">
  <short_description>Test IOC</short_description>
  <definition>
    <Indicator operator="OR">
      <IndicatorItem condition="is">
        <Context document="NetworkItem" search="NetworkItem/IP" type="IP"/>
        <Content type="IP">192.168.1.1</Content>
      </IndicatorItem>
      <IndicatorItem condition="is">
        <Context document="DnsItem" search="DnsItem/Host" type="string"/>
        <Content type="string">evil.com</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>
)";
}

// Helper to create test plain text file
[[nodiscard]] std::string CreateTestPlainText() {
	return R"(# Test IOC list
192.168.1.1
evil.com
badsite.org
d41d8cd98f00b204e9800998ecf8427e
https://malicious.site/payload
user@phishing.com
)";
}

} // anonymous namespace

// ============================================================================
// PART 1/7: FORMAT UTILITY TESTS
// ============================================================================

TEST(ThreatIntelImporter_Format, GetImportFormatExtension_AllFormats) {
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::CSV), ".csv");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::JSON), ".json");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::JSONL), ".jsonl");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::STIX21), ".json");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::MISP), ".json");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::OpenIOC), ".ioc");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::TAXII21), ".json");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::PlainText), ".txt");
	EXPECT_STREQ(GetImportFormatExtension(ImportFormat::Binary), ".bin");
}

TEST(ThreatIntelImporter_Format, GetImportFormatName_AllFormats) {
	EXPECT_STREQ(GetImportFormatName(ImportFormat::Auto), "Auto-Detect");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::CSV), "CSV");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::JSON), "JSON");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::JSONL), "JSON Lines");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::STIX21), "STIX 2.1");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::MISP), "MISP");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::OpenIOC), "OpenIOC");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::PlainText), "Plain Text");
	EXPECT_STREQ(GetImportFormatName(ImportFormat::CrowdStrike), "CrowdStrike");
}

TEST(ThreatIntelImporter_Format, ParseImportFormat_Valid) {
	EXPECT_EQ(ParseImportFormat("csv"), ImportFormat::CSV);
	EXPECT_EQ(ParseImportFormat("CSV"), ImportFormat::CSV);
	EXPECT_EQ(ParseImportFormat("json"), ImportFormat::JSON);
	EXPECT_EQ(ParseImportFormat("jsonl"), ImportFormat::JSONL);
	EXPECT_EQ(ParseImportFormat("stix"), ImportFormat::STIX21);
	EXPECT_EQ(ParseImportFormat("stix2"), ImportFormat::STIX21);
	EXPECT_EQ(ParseImportFormat("stix21"), ImportFormat::STIX21);
	EXPECT_EQ(ParseImportFormat("misp"), ImportFormat::MISP);
	EXPECT_EQ(ParseImportFormat("txt"), ImportFormat::PlainText);
	EXPECT_EQ(ParseImportFormat("text"), ImportFormat::PlainText);
}

TEST(ThreatIntelImporter_Format, ParseImportFormat_Invalid) {
	EXPECT_FALSE(ParseImportFormat("").has_value());
	EXPECT_FALSE(ParseImportFormat("invalid").has_value());
	EXPECT_FALSE(ParseImportFormat("unknown").has_value());
}

// ============================================================================
// PART 2/7: DEFANG/REFANG & TIMESTAMP TESTS
// ============================================================================

TEST(ThreatIntelImporter_Defang, DefangIOC_Domain) {
	EXPECT_EQ(DefangIOC("evil.com", IOCType::Domain), "evil[.]com");
	EXPECT_EQ(DefangIOC("malware.evil.com", IOCType::Domain), "malware[.]evil[.]com");
}

TEST(ThreatIntelImporter_Defang, DefangIOC_URL) {
	EXPECT_EQ(DefangIOC("http://evil.com", IOCType::URL), "hxxp://evil[.]com");
	EXPECT_EQ(DefangIOC("https://evil.com/payload", IOCType::URL), "hxxps://evil[.]com/payload");
	EXPECT_EQ(DefangIOC("ftp://files.evil.com", IOCType::URL), "fxp://files[.]evil[.]com");
}

TEST(ThreatIntelImporter_Defang, DefangIOC_Email) {
	EXPECT_EQ(DefangIOC("user@evil.com", IOCType::Email), "user[@]evil[.]com");
	EXPECT_EQ(DefangIOC("admin@phishing.org", IOCType::Email), "admin[@]phishing[.]org");
}

TEST(ThreatIntelImporter_Defang, DefangIOC_IPv4) {
	EXPECT_EQ(DefangIOC("192.168.1.1", IOCType::IPv4), "192[.]168[.]1[.]1");
	EXPECT_EQ(DefangIOC("10.0.0.1", IOCType::IPv4), "10[.]0[.]0[.]1");
}

TEST(ThreatIntelImporter_Defang, DefangIOC_EmptyInput) {
	EXPECT_TRUE(DefangIOC("", IOCType::Domain).empty());
}

TEST(ThreatIntelImporter_Defang, DefangIOC_TooLong) {
	std::string longValue(100000, 'a');
	EXPECT_TRUE(DefangIOC(longValue, IOCType::Domain).empty());
}

TEST(ThreatIntelImporter_Refang, RefangIOC_Domain) {
	EXPECT_EQ(RefangIOC("evil[.]com", IOCType::Domain), "evil.com");
	EXPECT_EQ(RefangIOC("malware[.]evil[.]com", IOCType::Domain), "malware.evil.com");
}

TEST(ThreatIntelImporter_Refang, RefangIOC_URL) {
	EXPECT_EQ(RefangIOC("hxxp://evil[.]com", IOCType::URL), "http://evil.com");
	EXPECT_EQ(RefangIOC("hxxps://evil[.]com/payload", IOCType::URL), "https://evil.com/payload");
}

TEST(ThreatIntelImporter_Refang, RefangIOC_Email) {
	EXPECT_EQ(RefangIOC("user[@]evil[.]com", IOCType::Email), "user@evil.com");
}

TEST(ThreatIntelImporter_Refang, RefangIOC_IPv4) {
	EXPECT_EQ(RefangIOC("192[.]168[.]1[.]1", IOCType::IPv4), "192.168.1.1");
}

TEST(ThreatIntelImporter_Refang, DefangRefang_RoundTrip) {
	const std::vector<std::pair<std::string, IOCType>> testCases = {
		{"evil.com", IOCType::Domain},
		{"http://evil.com", IOCType::URL},
		{"user@evil.com", IOCType::Email},
		{"192.168.1.1", IOCType::IPv4}
	};

	for (const auto& [value, type] : testCases) {
		std::string defanged = DefangIOC(value, type);
		std::string refanged = RefangIOC(defanged, type);
		EXPECT_EQ(refanged, value) << "Round-trip failed for: " << value;
	}
}

TEST(ThreatIntelImporter_Timestamp, ParseISO8601Timestamp_Valid) {
	// Standard format
	EXPECT_EQ(ParseISO8601Timestamp("2021-01-01T00:00:00Z"), 1609459200u);
	
	// With milliseconds
	EXPECT_EQ(ParseISO8601Timestamp("2021-01-01T00:00:00.000Z"), 1609459200u);
	
	// Space separator
	EXPECT_EQ(ParseISO8601Timestamp("2021-01-01 00:00:00"), 1609459200u);
}

TEST(ThreatIntelImporter_Timestamp, ParseISO8601Timestamp_Invalid) {
	EXPECT_EQ(ParseISO8601Timestamp(""), 0u);
	EXPECT_EQ(ParseISO8601Timestamp("not-a-timestamp"), 0u);
	EXPECT_EQ(ParseISO8601Timestamp("2021-13-01T00:00:00Z"), 0u); // Invalid month
	EXPECT_EQ(ParseISO8601Timestamp("2021-01-32T00:00:00Z"), 0u); // Invalid day
	EXPECT_EQ(ParseISO8601Timestamp("2021-01-01T25:00:00Z"), 0u); // Invalid hour
}

TEST(ThreatIntelImporter_Timestamp, ParseISO8601Timestamp_EdgeCases) {
	// Leap year February 29
	EXPECT_GT(ParseISO8601Timestamp("2020-02-29T00:00:00Z"), 0u);
	
	// Non-leap year February 29 (invalid)
	EXPECT_EQ(ParseISO8601Timestamp("2021-02-29T00:00:00Z"), 0u);
	
	// Year boundaries
	EXPECT_GT(ParseISO8601Timestamp("1970-01-01T00:00:00Z"), 0u);
	EXPECT_GT(ParseISO8601Timestamp("2099-12-31T23:59:59Z"), 0u);
	
	// Out of range year
	EXPECT_EQ(ParseISO8601Timestamp("1969-12-31T23:59:59Z"), 0u); // Before epoch
	EXPECT_EQ(ParseISO8601Timestamp("2101-01-01T00:00:00Z"), 0u); // After 2100
}

TEST(ThreatIntelImporter_Timestamp, ParseTimestamp_UnixEpoch) {
	EXPECT_EQ(ParseTimestamp("1609459200"), 1609459200u);
	EXPECT_EQ(ParseTimestamp("0"), 0u);
	EXPECT_EQ(ParseTimestamp("2147483647"), 2147483647u); // Max 32-bit
}

TEST(ThreatIntelImporter_Timestamp, ParseTimestamp_ISO8601) {
	EXPECT_EQ(ParseTimestamp("2021-01-01T00:00:00Z"), 1609459200u);
}

TEST(ThreatIntelImporter_Timestamp, ParseTimestamp_Invalid) {
	EXPECT_EQ(ParseTimestamp(""), 0u);
	EXPECT_EQ(ParseTimestamp("abc"), 0u);
	EXPECT_EQ(ParseTimestamp(std::string(100, '1')), 0u); // Too long
}

TEST(ThreatIntelImporter_Checksum, CalculateImportChecksum_ValidData) {
	const std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
	uint32_t crc1 = CalculateImportChecksum(data);
	EXPECT_NE(crc1, 0u);

	// Same data should produce same checksum
	uint32_t crc2 = CalculateImportChecksum(data);
	EXPECT_EQ(crc1, crc2);
}

TEST(ThreatIntelImporter_Checksum, CalculateImportChecksum_DifferentData) {
	const std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
	const std::vector<uint8_t> data2 = {0x04, 0x05, 0x06};
	
	uint32_t crc1 = CalculateImportChecksum(data1);
	uint32_t crc2 = CalculateImportChecksum(data2);
	EXPECT_NE(crc1, crc2);
}

TEST(ThreatIntelImporter_Checksum, CalculateImportChecksum_EmptyData) {
	const std::vector<uint8_t> empty;
	EXPECT_EQ(CalculateImportChecksum(empty), 0u);
}

// ============================================================================
// PART 3/7: CSV IMPORT READER TESTS
// ============================================================================

TEST(ThreatIntelImporter_CSV, Initialize_WithHeader) {
	std::istringstream input(CreateTestCSV(true));
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_CSV, Initialize_WithoutHeader) {
	std::istringstream input(CreateTestCSV(false));
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = false;
	
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_CSV, ReadNextEntry_ValidData) {
	std::istringstream input(CreateTestCSV(true));
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first entry (192.168.1.1)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Read second entry (evil.com)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
	
	// Read third entry (MD5 hash)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::FileHash);
}

TEST(ThreatIntelImporter_CSV, ReadNextEntry_NoMoreEntries) {
	std::istringstream input("indicator,type\n192.168.1.1,IPv4\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_FALSE(reader.ReadNextEntry(entry, &stringPool)); // No more entries
}

TEST(ThreatIntelImporter_CSV, ParseField_QuotedFields) {
	// Test CSV with quoted fields containing special characters
	std::istringstream input("indicator,type,description\n\"192.168.1.1\",\"IPv4\",\"Test, with comma\"\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Should successfully parse quoted field with comma
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
}

TEST(ThreatIntelImporter_CSV, ParseField_EmptyFields) {
	// Test CSV handling of empty fields
	std::istringstream input("indicator,type,confidence\n192.168.1.1,,\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Should handle empty fields gracefully
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
}

TEST(ThreatIntelImporter_CSV, DetectIOCType_AllTypes) {
	// Test IOC type detection through CSV parsing
	std::istringstream input("indicator\n192.168.1.1\nevil.com\nhttp://test.com\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// IPv4
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Domain
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
	
	// URL
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::URL);
}

TEST(ThreatIntelImporter_CSV, HasMoreEntries) {
	std::istringstream input("192.168.1.1\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = false;
	ASSERT_TRUE(reader.Initialize(options));
	
	EXPECT_TRUE(reader.HasMoreEntries());
	
	IOCEntry entry;
	MockStringPool stringPool;
	reader.ReadNextEntry(entry, &stringPool);
	
	EXPECT_FALSE(reader.HasMoreEntries());
}

TEST(ThreatIntelImporter_CSV, Reset) {
	std::istringstream input("192.168.1.1\n10.0.0.1\n");
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = false;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first entry
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	
	// Reset
	EXPECT_TRUE(reader.Reset());
	
	// Should be able to read again
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
}

// ============================================================================
// PART 4/7: JSON & JSONL IMPORT READER TESTS
// ============================================================================

TEST(ThreatIntelImporter_JSON, Initialize_ValidJSON) {
	std::istringstream input(CreateTestJSON());
	JSONImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_JSON, Initialize_InvalidJSON) {
	std::istringstream input("{invalid json");
	JSONImportReader reader(input);
	
	ImportOptions options;
	EXPECT_FALSE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_JSON, ReadNextEntry_ValidData) {
	std::istringstream input(CreateTestJSON());
	JSONImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first entry
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Read second entry
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
}

TEST(ThreatIntelImporter_JSON, ReadNextEntry_JSONL) {
	std::istringstream input(CreateTestJSONL());
	JSONImportReader reader(input);
	
	ImportOptions options;
	options.format = ImportFormat::JSONL;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	int count = 0;
	while (reader.ReadNextEntry(entry, &stringPool)) {
		++count;
	}
	
	EXPECT_EQ(count, 3); // Three entries in JSONL
}

TEST(ThreatIntelImporter_JSON, ReadNextEntry_EmptyArray) {
	std::istringstream input(R"({"indicators": []})");
	JSONImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	EXPECT_FALSE(reader.ReadNextEntry(entry, &stringPool));
}

TEST(ThreatIntelImporter_JSON, HasMoreEntries) {
	std::istringstream input(CreateTestJSON());
	JSONImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	EXPECT_TRUE(reader.HasMoreEntries());
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read all entries
	while (reader.ReadNextEntry(entry, &stringPool)) {}
	
	EXPECT_FALSE(reader.HasMoreEntries());
}

TEST(ThreatIntelImporter_JSON, ParseEntryFromJSON_AllFields) {
	// Test JSON parsing with all fields via public ReadNextEntry
	const std::string jsonStr = R"({"indicators": [{
		"value": "192.168.1.1",
		"type": "ipv4",
		"confidence": "high",
		"reputation": "malicious",
		"category": "c2"
	}]})";
	
	std::istringstream input(jsonStr);
	JSONImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	EXPECT_EQ(entry.confidence, ConfidenceLevel::High);
	EXPECT_EQ(entry.reputation, ReputationLevel::Malicious);
}

// ============================================================================
// PART 5/7: STIX 2.1 & MISP IMPORT READER TESTS
// ============================================================================

TEST(ThreatIntelImporter_STIX, Initialize_ValidBundle) {
	std::istringstream input(CreateTestSTIXBundle());
	STIX21ImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_STIX, Initialize_InvalidBundle) {
	std::istringstream input(R"({"type": "invalid"})");
	STIX21ImportReader reader(input);
	
	ImportOptions options;
	EXPECT_FALSE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_STIX, ReadNextEntry_ValidIndicators) {
	std::istringstream input(CreateTestSTIXBundle());
	STIX21ImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first indicator (IPv4)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Read second indicator (Domain)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
}

// STIX pattern parsing tested through ReadNextEntry which uses internal methods
// No direct testing of private ParseSTIXPattern needed - covered by integration tests

TEST(ThreatIntelImporter_MISP, Initialize_ValidEvent) {
	std::istringstream input(CreateTestMISPEvent());
	MISPImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_MISP, ReadNextEntry_ValidAttributes) {
	std::istringstream input(CreateTestMISPEvent());
	MISPImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first attribute (IPv4)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Read second attribute (Domain)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
}

// MISP type mapping tested through ReadNextEntry - no need for private method tests

// ============================================================================
// PART 6/7: PLAINTEXT & OPENIOC IMPORT READER TESTS
// ============================================================================

TEST(ThreatIntelImporter_PlainText, Initialize) {
	std::istringstream input(CreateTestPlainText());
	PlainTextImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_PlainText, ReadNextEntry_MixedTypes) {
	std::istringstream input(CreateTestPlainText());
	PlainTextImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	std::vector<IOCType> detectedTypes;
	while (reader.ReadNextEntry(entry, &stringPool)) {
		detectedTypes.push_back(entry.type);
	}
	
	// Should detect: IPv4, Domain, Domain, Hash, URL, Email
	EXPECT_GE(detectedTypes.size(), 5u);
	
	// Check for variety of types
	bool hasIPv4 = false;
	bool hasDomain = false;
	bool hasHash = false;
	bool hasURL = false;
	
	for (const auto type : detectedTypes) {
		if (type == IOCType::IPv4) hasIPv4 = true;
		if (type == IOCType::Domain) hasDomain = true;
		if (type == IOCType::FileHash) hasHash = true;
		if (type == IOCType::URL) hasURL = true;
	}
	
	EXPECT_TRUE(hasIPv4);
	EXPECT_TRUE(hasDomain);
	EXPECT_TRUE(hasHash);
	EXPECT_TRUE(hasURL);
}

TEST(ThreatIntelImporter_PlainText, ParseLine_SkipComments) {
	std::istringstream input("# Comment\n192.168.1.1\n");
	PlainTextImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
}

// PlainText IOC detection tested through ReadNextEntry - integration test sufficient

TEST(ThreatIntelImporter_OpenIOC, Initialize_ValidDocument) {
	std::istringstream input(CreateTestOpenIOC());
	OpenIOCImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_OpenIOC, Initialize_InvalidXML) {
	std::istringstream input("<invalid xml");
	OpenIOCImportReader reader(input);
	
	ImportOptions options;
	EXPECT_FALSE(reader.Initialize(options));
}

TEST(ThreatIntelImporter_OpenIOC, ReadNextEntry_ValidIndicators) {
	std::istringstream input(CreateTestOpenIOC());
	OpenIOCImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Read first indicator (IPv4)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::IPv4);
	
	// Read second indicator (Domain)
	EXPECT_TRUE(reader.ReadNextEntry(entry, &stringPool));
	EXPECT_EQ(entry.type, IOCType::Domain);
}

// ============================================================================
// PART 7/7: MAIN IMPORTER & INTEGRATION TESTS
// ============================================================================

// CreateReader is private - tested implicitly through ImportFromFile/ImportFromStream

TEST(ThreatIntelImporter_Main, DetectFormatFromExtension_AllFormats) {
	ThreatIntelImporter importer;
	
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.csv"), ImportFormat::CSV);
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.json"), ImportFormat::JSON);
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.jsonl"), ImportFormat::JSONL);
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.txt"), ImportFormat::PlainText);
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.ioc"), ImportFormat::OpenIOC);
}

TEST(ThreatIntelImporter_Main, DetectFormatFromExtension_CaseInsensitive) {
	ThreatIntelImporter importer;
	
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.CSV"), ImportFormat::CSV);
	EXPECT_EQ(importer.DetectFormatFromExtension(L"test.JSON"), ImportFormat::JSON);
}

TEST(ThreatIntelImporter_Main, DetectFormatFromContent_CSV) {
	ThreatIntelImporter importer;
	std::istringstream input("indicator,type,confidence\n192.168.1.1,IPv4,High\n");
	
	ImportFormat detected = importer.DetectFormatFromContent(input, 1024);
	EXPECT_EQ(detected, ImportFormat::CSV);
}

TEST(ThreatIntelImporter_Main, DetectFormatFromContent_JSON) {
	ThreatIntelImporter importer;
	std::istringstream input(CreateTestJSON());
	
	ImportFormat detected = importer.DetectFormatFromContent(input, 1024);
	EXPECT_EQ(detected, ImportFormat::JSON);
}

TEST(ThreatIntelImporter_Main, DetectFormatFromContent_STIX) {
	ThreatIntelImporter importer;
	std::istringstream input(CreateTestSTIXBundle());
	
	ImportFormat detected = importer.DetectFormatFromContent(input, 2048);
	EXPECT_EQ(detected, ImportFormat::STIX21);
}

TEST(ThreatIntelImporter_Main, DetectIOCType_AllTypes) {
	ThreatIntelImporter importer;
	
	EXPECT_EQ(importer.DetectIOCType("192.168.1.1"), IOCType::IPv4);
	EXPECT_EQ(importer.DetectIOCType("2001:db8::1"), IOCType::IPv6);
	EXPECT_EQ(importer.DetectIOCType("evil.com"), IOCType::Domain);
	EXPECT_EQ(importer.DetectIOCType("http://evil.com"), IOCType::URL);
	EXPECT_EQ(importer.DetectIOCType("user@evil.com"), IOCType::Email);
	EXPECT_EQ(importer.DetectIOCType("d41d8cd98f00b204e9800998ecf8427e"), IOCType::FileHash);
}

TEST(ThreatIntelImporter_Main, ImportFromFile_CSVFormat) {
	TempDir tempDir;
	auto csvPath = tempDir.FilePath("test.csv");
	
	// Create test CSV file
	{
		std::ofstream out(csvPath);
		out << CreateTestCSV(true);
	}
	
	// Create temporary database
	auto dbPath = tempDir.FilePath("test.db");
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	// Import
	ThreatIntelImporter importer;
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	
	ImportResult result = importer.ImportFromFile(database, csvPath.wstring(), options, nullptr);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.totalParsed, 0u);
	EXPECT_EQ(result.totalParseErrors, 0u);
	
	database.Close();
}

TEST(ThreatIntelImporter_Main, ImportFromFile_NonExistent) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	ThreatIntelImporter importer;
	ImportOptions options;
	
	ImportResult result = importer.ImportFromFile(database, L"C:\\NonExistent\\file.csv", options, nullptr);
	
	EXPECT_FALSE(result.success);
	
	database.Close();
}

TEST(ThreatIntelImporter_Main, ImportFromStream_CSV) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	std::istringstream input(CreateTestCSV(true));
	
	ThreatIntelImporter importer;
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	options.format = ImportFormat::CSV;
	
	ImportResult result = importer.ImportFromStream(database, input, options, nullptr);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.totalParsed, 0u);
	
	database.Close();
}

TEST(ThreatIntelImporter_Main, ImportFromStream_JSON) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	std::istringstream input(CreateTestJSON());
	
	ThreatIntelImporter importer;
	ImportOptions options;
	options.format = ImportFormat::JSON;
	
	ImportResult result = importer.ImportFromStream(database, input, options, nullptr);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(result.totalParsed, 0u);
	
	database.Close();
}

TEST(ThreatIntelImporter_Main, ImportProgress_Callback) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	std::istringstream input(CreateTestCSV(true));
	
	int callbackCount = 0;
	ImportProgressCallback progressCallback = [&callbackCount](const ImportProgress& progress) {
		++callbackCount;
		EXPECT_GE(progress.percentComplete, 0.0);
		EXPECT_LE(progress.percentComplete, 100.0);
		return true; // Continue
	};
	
	ThreatIntelImporter importer;
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	options.format = ImportFormat::CSV;
	
	ImportResult result = importer.ImportFromStream(database, input, options, progressCallback);
	
	EXPECT_TRUE(result.success);
	EXPECT_GT(callbackCount, 0); // Callback was invoked
	
	database.Close();
}

TEST(ThreatIntelImporter_Main, ImportProgress_Cancellation) {
	TempDir tempDir;
	auto dbPath = tempDir.FilePath("test.db");
	
	ThreatIntelDatabase database;
	ASSERT_TRUE(database.Open(dbPath.wstring()));
	
	// Create large CSV
	std::ostringstream oss;
	oss << "indicator,type\n";
	for (int i = 0; i < 100; ++i) {
		oss << "192.168." << (i / 256) << "." << (i % 256) << ",IPv4\n";
	}
	std::istringstream input(oss.str());
	
	int callbackCount = 0;
	ImportProgressCallback progressCallback = [&callbackCount](const ImportProgress&) {
		++callbackCount;
		return callbackCount < 2; // Cancel after second callback
	};
	
	ThreatIntelImporter importer;
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	options.format = ImportFormat::CSV;
	
	ImportResult result = importer.ImportFromStream(database, input, options, progressCallback);
	
	EXPECT_FALSE(result.success); // Should be cancelled
	EXPECT_LT(result.totalParsed, 100u); // Not all entries processed
	
	database.Close();
}

// ============================================================================
// THREAD SAFETY & PERFORMANCE TESTS
// ============================================================================

TEST(ThreatIntelImporter_ThreadSafety, ConcurrentDefangOperations) {
	std::vector<std::thread> threads;
	std::atomic<int> successCount{0};
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&successCount]() {
			for (int i = 0; i < 100; ++i) {
				std::string defanged = DefangIOC("evil.com", IOCType::Domain);
				if (defanged == "evil[.]com") {
					successCount.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_EQ(successCount.load(), 400);
}

TEST(ThreatIntelImporter_ThreadSafety, ConcurrentTimestampParsing) {
	std::vector<std::thread> threads;
	std::atomic<int> successCount{0};
	
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&successCount]() {
			for (int i = 0; i < 100; ++i) {
				uint64_t ts = ParseISO8601Timestamp("2021-01-01T00:00:00Z");
				if (ts == 1609459200u) {
					successCount.fetch_add(1, std::memory_order_relaxed);
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_EQ(successCount.load(), 400);
}

TEST(ThreatIntelImporter_Performance, CSVParsing_LargeScale) {
	// Create large CSV (10K entries)
	std::ostringstream oss;
	oss << "indicator,type,confidence\n";
	for (int i = 0; i < 10000; ++i) {
		oss << "192.168." << (i / 256) << "." << (i % 256) << ",IPv4,High\n";
	}
	
	std::istringstream input(oss.str());
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	auto start = std::chrono::steady_clock::now();
	
	IOCEntry entry;
	MockStringPool stringPool;
	int count = 0;
	
	while (reader.ReadNextEntry(entry, &stringPool)) {
		++count;
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	EXPECT_EQ(count, 10000);
	EXPECT_LT(ms, 5000); // Should process 10K entries in < 5 seconds
}

TEST(ThreatIntelImporter_Performance, JSONParsing_LargeScale) {
	// Create large JSON (1000 entries)
	std::ostringstream oss;
	oss << R"({"indicators": [)";
	for (int i = 0; i < 1000; ++i) {
		if (i > 0) oss << ",";
		oss << R"({"value":"192.168.)" << (i / 256) << "." << (i % 256) 
		    << R"(","type":"ipv4","reputation":"malicious"})";
	}
	oss << "]}";
	
	std::istringstream input(oss.str());
	JSONImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	auto start = std::chrono::steady_clock::now();
	
	IOCEntry entry;
	MockStringPool stringPool;
	int count = 0;
	
	while (reader.ReadNextEntry(entry, &stringPool)) {
		++count;
	}
	
	auto elapsed = std::chrono::steady_clock::now() - start;
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
	
	EXPECT_EQ(count, 1000);
	EXPECT_LT(ms, 2000); // Should process 1K entries in < 2 seconds
}

TEST(ThreatIntelImporter_EdgeCase, EmptyInput) {
	std::istringstream input("");
	CSVImportReader reader(input);
	
	ImportOptions options;
	EXPECT_TRUE(reader.Initialize(options)); // Should handle empty input gracefully
}

TEST(ThreatIntelImporter_EdgeCase, VeryLongLine) {
	// Create CSV with very long field
	std::ostringstream oss;
	oss << "indicator,type\n";
	oss << std::string(100000, 'a') << ",Domain\n"; // 100KB field
	
	std::istringstream input(oss.str());
	CSVImportReader reader(input);
	
	ImportOptions options;
	options.csvConfig.hasHeader = true;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Should handle gracefully (may skip or truncate)
	bool result = reader.ReadNextEntry(entry, &stringPool);
	// Don't assert - implementation may choose to skip or reject
}

TEST(ThreatIntelImporter_EdgeCase, MalformedJSON) {
	std::istringstream input(R"({"indicators": [{"value": "test", "type": )"); // Incomplete JSON
	JSONImportReader reader(input);
	
	ImportOptions options;
	EXPECT_FALSE(reader.Initialize(options)); // Should detect malformed JSON
}

TEST(ThreatIntelImporter_EdgeCase, InvalidXML) {
	std::istringstream input("<ioc><unclosed>");
	OpenIOCImportReader reader(input);
	
	ImportOptions options;
	EXPECT_FALSE(reader.Initialize(options)); // Should detect invalid XML
}

TEST(ThreatIntelImporter_EdgeCase, NullCharactersInInput) {
	std::string data = "192.168.1.1\0evil.com\n";
	data[11] = '\0'; // Embedded null
	std::istringstream input(data);
	
	PlainTextImportReader reader(input);
	
	ImportOptions options;
	ASSERT_TRUE(reader.Initialize(options));
	
	IOCEntry entry;
	MockStringPool stringPool;
	
	// Should handle gracefully
	reader.ReadNextEntry(entry, &stringPool);
}

} // namespace ShadowStrike::ThreatIntel::Tests
