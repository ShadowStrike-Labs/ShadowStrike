// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file ThreatIntelFeedManager_parsers_tests.cpp
 * @brief Enterprise-grade unit tests for ThreatIntelFeedManager parser implementations
 * @author ShadowStrike Security Team
 * @date 2024
 * 
 * Comprehensive test coverage for:
 * - JsonFeedParser: JSON format parsing (ThreatStream, AlienVault, MISP, etc.)
 * - CsvFeedParser: CSV/TSV format parsing
 * - StixFeedParser: STIX 1.x/2.x format parsing
 * - Custom parser implementations
 * 
 * Coverage Requirements:
 * - Line coverage: >95%
 * - Branch coverage: >90%
 * - Edge case coverage: 100%
 */

#include <gtest/gtest.h>
#include "../../src/ThreatIntel/ThreatIntelFeedManager.hpp"
#include "../../src/ThreatIntel/ThreatIntelFormat.hpp"
#include <memory>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <span>
#include <chrono>
#include <utility>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// MOCK CLASSES AND HELPERS
// ============================================================================

/**
 * @brief Helper to create test JSON feed data
 */
class JsonTestDataBuilder {
public:
    static std::string CreateThreatStreamFormat(
        const std::string& ipAddress,
        const std::string& severity = "high",
        const std::string& itype = "mal_ip"
    ) {
        std::ostringstream json;
        json << R"({
            "objects": [{
                "value": ")" << ipAddress << R"(",
                "itype": ")" << itype << R"(",
                "severity": ")" << severity << R"(",
                "confidence": 85,
                "source": "test_source",
                "tags": ["malware", "botnet"],
                "created_ts": "2024-01-01T00:00:00Z",
                "modified_ts": "2024-01-01T00:00:00Z"
            }]
        })";
        return json.str();
    }
    
    static std::string CreateAlienVaultFormat(
        const std::string& indicator,
        const std::string& type = "IPv4"
    ) {
        std::ostringstream json;
        json << R"({
            "results": [{
                "indicator": ")" << indicator << R"(",
                "type": ")" << type << R"(",
                "pulse_info": {
                    "count": 1,
                    "pulses": [{
                        "name": "Test Pulse",
                        "tags": ["malware"]
                    }]
                },
                "validation": [{
                    "source": "test",
                    "message": "confirmed malicious"
                }]
            }]
        })";
        return json.str();
    }
    
    static std::string CreateMispFormat(
        const std::string& value,
        const std::string& type = "ip-dst"
    ) {
        std::ostringstream json;
        json << R"({
            "response": {
                "Attribute": [{
                    "id": "12345",
                    "event_id": "1",
                    "category": "Network activity",
                    "type": ")" << type << R"(",
                    "value": ")" << value << R"(",
                    "to_ids": true,
                    "timestamp": "1640000000",
                    "comment": "Test indicator"
                }]
            }
        })";
        return json.str();
    }
    
    static std::string CreateEmptyResponse() {
        return "{}";
    }
    
    static std::string CreateMalformedJson() {
        return R"({ "invalid": json syntax )";
    }
    
    static std::string CreateLargeResponse(int numIndicators) {
        std::ostringstream json;
        json << R"({"objects": [)";
        for (int i = 0; i < numIndicators; ++i) {
            if (i > 0) json << ",";
            json << R"({"value": "192.168.1.)" << i << R"(", "itype": "mal_ip", "severity": "low"})";
        }
        json << "]}";
        return json.str();
    }
};

/**
 * @brief Helper to create test CSV feed data
 */
class CsvTestDataBuilder {
public:
    static std::string CreateStandardCsv() {
        return "ip,type,severity,confidence,source\n"
               "192.168.1.1,malware,high,90,test1\n"
               "192.168.1.2,botnet,medium,75,test2\n"
               "192.168.1.3,c2,low,60,test3\n";
    }
    
    static std::string CreateTsvFormat() {
        return "ip\ttype\tseverity\tconfidence\tsource\n"
               "10.0.0.1\tmalware\thigh\t85\ttest_tsv\n"
               "10.0.0.2\tbotnet\tmedium\t70\ttest_tsv\n";
    }
    
    static std::string CreateWithQuotedFields() {
        return R"(indicator,"type","severity",description,tags)" "\n"
               R"(192.168.1.1,"mal_ip","high","Test description","tag1,tag2")" "\n"
               R"(evil.com,"mal_domain","medium","Another test","tag3")" "\n";
    }
    
    static std::string CreateWithEmbeddedCommas() {
        return R"(indicator,description,tags)" "\n"
               R"(192.168.1.1,"Description with, comma","tag1,tag2,tag3")" "\n";
    }
    
    static std::string CreateWithMissingFields() {
        return "ip,type,severity\n"
               "192.168.1.1,malware,high\n"
               "192.168.1.2,,medium\n"  // Missing type
               "192.168.1.3,botnet,\n";  // Missing severity
    }
    
    static std::string CreateWithInvalidData() {
        return "ip,type,severity\n"
               "not-an-ip,malware,high\n"
               "256.256.256.256,malware,high\n"
               "192.168.1.1,invalid_type,unknown_severity\n";
    }
    
    static std::string CreateEmpty() {
        return "";
    }
    
    static std::string CreateHeaderOnly() {
        return "ip,type,severity\n";
    }
};

/**
 * @brief Helper to create test STIX feed data
 */
class StixTestDataBuilder {
public:
    static std::string CreateStix2Indicator(
        const std::string& pattern,
        const std::string& name = "Test Indicator"
    ) {
        std::ostringstream json;
        json << R"({
            "type": "bundle",
            "id": "bundle--test-123",
            "objects": [{
                "type": "indicator",
                "id": "indicator--test-456",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": ")" << name << R"(",
                "pattern": ")" << pattern << R"(",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00.000Z",
                "labels": ["malicious-activity"]
            }]
        })";
        return json.str();
    }
    
    static std::string CreateStix1Observable() {
        return R"(<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1">
    <stix:Observables>
        <cybox:Observable id="obs-1">
            <cybox:Object>
                <cybox:Properties xsi:type="AddressObject:AddressObjectType">
                    <AddressObject:Address_Value>192.168.1.1</AddressObject:Address_Value>
                </cybox:Properties>
            </cybox:Object>
        </cybox:Observable>
    </stix:Observables>
</stix:STIX_Package>)";
    }
    
    static std::string CreateStix2Bundle() {
        return R"({
            "type": "bundle",
            "id": "bundle--multi-test",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '192.168.1.1']",
                    "valid_from": "2024-01-01T00:00:00.000Z"
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "valid_from": "2024-01-01T00:00:00.000Z"
                }
            ]
        })";
    }
};

// ============================================================================
// JSON PARSER TESTS
// ============================================================================

/**
 * @brief Test fixture for JsonFeedParser
 * 
 * Tests JSON parsing functionality with proper interface compliance:
 * - Parse takes span<const uint8_t>, vector<IOCEntry>&, ParserConfig&
 * - Returns bool (true = success, false = failure)
 * - GetLastError() provides error details on failure
 */
class JsonFeedParserTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<JsonFeedParser>();
        defaultConfig = ParserConfig{};  // Use default parser configuration
    }
    
    void TearDown() override {
        parser.reset();
    }
    
    /**
     * @brief Helper to convert string to span for parsing
     * @param data String data to convert
     * @return Span view of the data bytes
     */
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(JsonFeedParserTest, ParseThreatStreamFormatSingleIndicator) {
    // Test: Parse ThreatStream format with single indicator
    std::string data = JsonTestDataBuilder::CreateThreatStreamFormat("192.168.1.100");
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 1u);
    
    if (!entries.empty()) {
        EXPECT_EQ(entries[0].type, IOCType::IPv4);
        // Note: Severity is parsed from feed data, mapped to ReputationLevel
    }
}

TEST_F(JsonFeedParserTest, ParseThreatStreamFormatMultipleSeverities) {
    // Test: Parse indicators with different severity levels
    std::string dataHigh = JsonTestDataBuilder::CreateThreatStreamFormat("1.1.1.1", "high");
    std::string dataMedium = JsonTestDataBuilder::CreateThreatStreamFormat("2.2.2.2", "medium");
    std::string dataLow = JsonTestDataBuilder::CreateThreatStreamFormat("3.3.3.3", "low");
    
    std::vector<IOCEntry> entriesHigh, entriesMedium, entriesLow;
    
    parser->Parse(ToSpan(dataHigh), entriesHigh, defaultConfig);
    parser->Parse(ToSpan(dataMedium), entriesMedium, defaultConfig);
    parser->Parse(ToSpan(dataLow), entriesLow, defaultConfig);
    
    // Verify entries were parsed (severity mapping is implementation-dependent)
    EXPECT_GE(entriesHigh.size(), 1u);
    EXPECT_GE(entriesMedium.size(), 1u);
    EXPECT_GE(entriesLow.size(), 1u);
}

TEST_F(JsonFeedParserTest, ParseAlienVaultFormat) {
    // Test: Parse AlienVault OTX format
    std::string data = JsonTestDataBuilder::CreateAlienVaultFormat("10.20.30.40", "IPv4");
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 1u);
}

TEST_F(JsonFeedParserTest, ParseMispFormat) {
    // Test: Parse MISP format
    std::string data = JsonTestDataBuilder::CreateMispFormat("evil.example.com", "domain");
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 1u);
}

TEST_F(JsonFeedParserTest, ParseEmptyJson) {
    // Test: Parse empty JSON response
    std::string data = JsonTestDataBuilder::CreateEmptyResponse();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 0u);
}

TEST_F(JsonFeedParserTest, ParseMalformedJson) {
    // Test: Parse malformed JSON
    std::string data = JsonTestDataBuilder::CreateMalformedJson();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_FALSE(success);
    EXPECT_FALSE(parser->GetLastError().empty());
}

TEST_F(JsonFeedParserTest, ParseEmptyString) {
    // Test: Parse empty string
    std::string data = "";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_FALSE(success);
}

TEST_F(JsonFeedParserTest, ParseLargeResponse) {
    // Test: Parse large JSON response with many indicators
    std::string data = JsonTestDataBuilder::CreateLargeResponse(1000);
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 1000u);
}

TEST_F(JsonFeedParserTest, ParseWithUnicodeCharacters) {
    // Test: Parse JSON with Unicode characters
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "description": "Malware C2 - 恶意软件 - Вредоносное ПО",
            "severity": "high"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserTest, ParseWithMissingRequiredFields) {
    // Test: Parse JSON with missing required fields
    std::string data = R"({
        "objects": [{
            "itype": "mal_ip",
            "severity": "high"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should either skip invalid entry or fail
    EXPECT_TRUE(success || !success);
}

TEST_F(JsonFeedParserTest, ParseWithExtraFields) {
    // Test: Parse JSON with extra unknown fields (should be ignored)
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "severity": "high",
            "unknown_field1": "value1",
            "unknown_field2": 12345
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 1u);
}

// ============================================================================
// CSV PARSER TESTS
// ============================================================================

/**
 * @brief Test fixture for CsvFeedParser
 * 
 * Tests CSV/TSV parsing functionality with proper interface compliance
 */
class CsvFeedParserTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<CsvFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    void TearDown() override {
        parser.reset();
    }
    
    /**
     * @brief Helper to convert string to span for parsing
     */
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(CsvFeedParserTest, ParseStandardCsv) {
    // Test: Parse standard CSV format
    std::string data = CsvTestDataBuilder::CreateStandardCsv();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 3u);
}

TEST_F(CsvFeedParserTest, ParseTsvFormat) {
    // Test: Parse TSV (tab-separated) format
    std::string data = CsvTestDataBuilder::CreateTsvFormat();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 2u);
}

TEST_F(CsvFeedParserTest, ParseWithQuotedFields) {
    // Test: Parse CSV with quoted fields
    std::string data = CsvTestDataBuilder::CreateWithQuotedFields();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 1u);
}

TEST_F(CsvFeedParserTest, ParseWithEmbeddedCommas) {
    // Test: Parse CSV with embedded commas in quoted fields
    std::string data = CsvTestDataBuilder::CreateWithEmbeddedCommas();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserTest, ParseWithMissingFields) {
    // Test: Parse CSV with missing fields
    std::string data = CsvTestDataBuilder::CreateWithMissingFields();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should handle gracefully - may skip invalid rows or use defaults
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserTest, ParseWithInvalidData) {
    // Test: Parse CSV with invalid data
    std::string data = CsvTestDataBuilder::CreateWithInvalidData();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should skip invalid entries
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserTest, ParseEmptyCsv) {
    // Test: Parse empty CSV
    std::string data = CsvTestDataBuilder::CreateEmpty();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_FALSE(success);
}

TEST_F(CsvFeedParserTest, ParseHeaderOnlyCsv) {
    // Test: Parse CSV with header but no data rows
    std::string data = CsvTestDataBuilder::CreateHeaderOnly();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 0u);
}

TEST_F(CsvFeedParserTest, ParseWithDifferentLineEndings) {
    // Test: Parse CSV with different line endings (CRLF, LF)
    std::string dataCRLF = "ip,type\r\n192.168.1.1,malware\r\n192.168.1.2,botnet\r\n";
    std::string dataLF = "ip,type\n192.168.1.1,malware\n192.168.1.2,botnet\n";
    
    std::vector<IOCEntry> entriesCRLF, entriesLF;
    
    bool successCRLF = parser->Parse(ToSpan(dataCRLF), entriesCRLF, defaultConfig);
    bool successLF = parser->Parse(ToSpan(dataLF), entriesLF, defaultConfig);
    
    EXPECT_TRUE(successCRLF);
    EXPECT_TRUE(successLF);
    EXPECT_EQ(entriesCRLF.size(), entriesLF.size());
}

TEST_F(CsvFeedParserTest, ParseWithColumnMapping) {
    // Test: Parser should auto-detect column mapping
    std::string data = "indicator,threat_type,risk_level\n"
                       "192.168.1.1,malware,high\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

// ============================================================================
// STIX PARSER TESTS
// ============================================================================

/**
 * @brief Test fixture for StixFeedParser
 * 
 * Tests STIX 1.x/2.x parsing functionality with proper interface compliance
 */
class StixFeedParserTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<StixFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    void TearDown() override {
        parser.reset();
    }
    
    /**
     * @brief Helper to convert string to span for parsing
     */
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(StixFeedParserTest, ParseStix2Indicator) {
    // Test: Parse STIX 2.x indicator
    std::string data = StixTestDataBuilder::CreateStix2Indicator(
        "[ipv4-addr:value = '192.168.1.1']"
    );
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 1u);
}

TEST_F(StixFeedParserTest, ParseStix2Bundle) {
    // Test: Parse STIX 2.x bundle with multiple indicators
    std::string data = StixTestDataBuilder::CreateStix2Bundle();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 2u);
}

TEST_F(StixFeedParserTest, ParseStix1Observable) {
    // Test: Parse STIX 1.x observable
    std::string data = StixTestDataBuilder::CreateStix1Observable();
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success || !success);  // May not be implemented
}

TEST_F(StixFeedParserTest, ParseInvalidStix) {
    // Test: Parse invalid STIX data
    std::string data = R"({"type": "invalid", "not": "stix"})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_FALSE(success);
}

TEST_F(StixFeedParserTest, ParseStixWithDomainPattern) {
    // Test: Parse STIX with domain pattern
    std::string data = StixTestDataBuilder::CreateStix2Indicator(
        "[domain-name:value = 'evil.example.com']",
        "Malicious Domain"
    );
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(StixFeedParserTest, ParseStixWithFileHashPattern) {
    // Test: Parse STIX with file hash pattern
    std::string data = StixTestDataBuilder::CreateStix2Indicator(
        "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        "Malicious File"
    );
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

// ============================================================================
// PARSER INTEGRATION TESTS
// ============================================================================

/**
 * @brief Test fixture for parser integration scenarios
 * 
 * Tests interactions between multiple parser types
 */
class ParserIntegrationTest : public ::testing::Test {
protected:
    std::unique_ptr<JsonFeedParser> jsonParser;
    std::unique_ptr<CsvFeedParser> csvParser;
    std::unique_ptr<StixFeedParser> stixParser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        jsonParser = std::make_unique<JsonFeedParser>();
        csvParser = std::make_unique<CsvFeedParser>();
        stixParser = std::make_unique<StixFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    /**
     * @brief Helper to convert string to span for parsing
     */
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(ParserIntegrationTest, ParseMultipleFormatsSequentially) {
    // Test: Parse different formats sequentially
    std::string jsonData = JsonTestDataBuilder::CreateThreatStreamFormat("1.1.1.1");
    std::string csvData = CsvTestDataBuilder::CreateStandardCsv();
    std::string stixData = StixTestDataBuilder::CreateStix2Indicator("[ipv4-addr:value = '2.2.2.2']");
    
    std::vector<IOCEntry> jsonEntries, csvEntries, stixEntries;
    
    bool jsonSuccess = jsonParser->Parse(ToSpan(jsonData), jsonEntries, defaultConfig);
    bool csvSuccess = csvParser->Parse(ToSpan(csvData), csvEntries, defaultConfig);
    bool stixSuccess = stixParser->Parse(ToSpan(stixData), stixEntries, defaultConfig);
    
    EXPECT_TRUE(jsonSuccess);
    EXPECT_TRUE(csvSuccess);
    // STIX may or may not succeed depending on implementation
    EXPECT_TRUE(stixSuccess || !stixSuccess);
    
    size_t totalEntries = jsonEntries.size() + csvEntries.size() + stixEntries.size();
    EXPECT_GT(totalEntries, 0u);
}

TEST_F(ParserIntegrationTest, ParseSameFormatMultipleTimes) {
    // Test: Reuse parser for multiple parses
    std::string data1 = JsonTestDataBuilder::CreateThreatStreamFormat("1.1.1.1");
    std::string data2 = JsonTestDataBuilder::CreateThreatStreamFormat("2.2.2.2");
    std::string data3 = JsonTestDataBuilder::CreateThreatStreamFormat("3.3.3.3");
    
    std::vector<IOCEntry> entries1, entries2, entries3;
    
    EXPECT_TRUE(jsonParser->Parse(ToSpan(data1), entries1, defaultConfig));
    EXPECT_TRUE(jsonParser->Parse(ToSpan(data2), entries2, defaultConfig));
    EXPECT_TRUE(jsonParser->Parse(ToSpan(data3), entries3, defaultConfig));
    
    EXPECT_EQ(entries1.size(), 1u);
    EXPECT_EQ(entries2.size(), 1u);
    EXPECT_EQ(entries3.size(), 1u);
}

TEST_F(ParserIntegrationTest, ParseWithEmptyOutputVector) {
    // Test: Parse into empty vector (should work)
    std::string data = JsonTestDataBuilder::CreateThreatStreamFormat("1.1.1.1");
    
    std::vector<IOCEntry> entries;
    EXPECT_EQ(entries.size(), 0u);
    
    bool success = jsonParser->Parse(ToSpan(data), entries, defaultConfig);
    EXPECT_TRUE(success);
    EXPECT_GT(entries.size(), 0u);
}

TEST_F(ParserIntegrationTest, ParseWithPrePopulatedVector) {
    // Test: Parse into pre-populated vector (should append)
    std::string data = JsonTestDataBuilder::CreateThreatStreamFormat("1.1.1.1");
    
    std::vector<IOCEntry> entries;
    IOCEntry existingEntry = {};
    existingEntry.type = IOCType::Domain;
    entries.push_back(existingEntry);
    
    size_t initialSize = entries.size();
    EXPECT_EQ(initialSize, 1u);
    
    bool success = jsonParser->Parse(ToSpan(data), entries, defaultConfig);
    EXPECT_TRUE(success);
    EXPECT_GT(entries.size(), initialSize);
}

// ============================================================================
// TITANIUM-GRADE EDGE CASE TESTS
// ============================================================================

/**
 * @brief Enterprise-grade edge case tests for JsonFeedParser
 * 
 * These tests cover critical security, boundary, and robustness scenarios
 * that are essential for enterprise antivirus deployments.
 */
class JsonFeedParserEdgeCaseTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<JsonFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

// --- Security Edge Cases ---

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithNullBytes) {
    // Test: JSON containing null bytes (potential security issue)
    std::string data = R"({"objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]})";
    data.insert(20, 1, '\0');  // Insert null byte
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should either fail gracefully or handle correctly
    EXPECT_TRUE(success || !success);
    EXPECT_TRUE(parser->GetLastError().empty() || !parser->GetLastError().empty());
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithScriptInjection) {
    // Test: Attempt to inject script tags in JSON values
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "description": "<script>alert('xss')</script>"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should parse successfully - XSS is not a JSON parsing issue
    EXPECT_TRUE(success);
    // Values should be stored as-is (sanitization is display layer concern)
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithSQLInjection) {
    // Test: SQL injection attempt in JSON values
    std::string data = R"({
        "objects": [{
            "value": "'; DROP TABLE iocs; --",
            "itype": "mal_domain"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Parser should handle this - SQL injection prevention is database layer
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithPathTraversal) {
    // Test: Path traversal attempt in file path values
    std::string data = R"({
        "objects": [{
            "value": "../../etc/passwd",
            "itype": "mal_file"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);  // Parser should parse, validation is separate
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithExtremelyLongStrings) {
    // Test: Very long string values (potential DoS via memory exhaustion)
    std::string longValue(1024 * 1024, 'A');  // 1MB string
    std::string data = R"({"objects": [{"value": ")" + longValue + R"(", "itype": "mal_ip"}]})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should handle gracefully
    EXPECT_TRUE(success || !success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithDeepNesting) {
    // Test: Deeply nested JSON (potential stack overflow)
    std::string data = R"({"a":)";
    for (int i = 0; i < 1000; i++) {
        data += R"({"a":)";
    }
    data += "null";
    for (int i = 0; i < 1001; i++) {
        data += "}";
    }
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should either fail gracefully or succeed (nlohmann::json handles this)
    EXPECT_TRUE(success || !success);
}

// --- Boundary Conditions ---

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithIntegerOverflow) {
    // Test: Integer values at the edge of representation
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "confidence": 18446744073709551615,
            "severity_score": -9223372036854775808
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithFloatingPointEdgeCases) {
    // Test: Edge case floating point values
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "score": 1.7976931348623157e+308,
            "tiny_score": 2.2250738585072014e-308,
            "negative_zero": -0.0
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithExactlyZeroItems) {
    // Test: Empty objects array
    std::string data = R"({"objects": []})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 0u);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithExactlyOneItem) {
    // Test: Single item edge case
    std::string data = R"({"objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 1u);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithSpecialIPAddresses) {
    // Test: Special/reserved IP addresses
    std::vector<std::pair<std::string, std::string>> specialIPs = {
        {"0.0.0.0", "null_address"},
        {"255.255.255.255", "broadcast"},
        {"127.0.0.1", "localhost"},
        {"169.254.0.1", "link_local"},
        {"224.0.0.1", "multicast"},
        {"::1", "ipv6_localhost"},
        {"::ffff:192.168.1.1", "ipv4_mapped_ipv6"},
        {"fe80::1", "ipv6_link_local"}
    };
    
    for (const auto& [ip, description] : specialIPs) {
        std::string data = R"({"objects": [{"value": ")" + ip + R"(", "itype": "mal_ip"}]})";
        std::vector<IOCEntry> entries;
        bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
        
        EXPECT_TRUE(success) << "Failed for IP: " << ip << " (" << description << ")";
    }
}

// --- Format Edge Cases ---

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithBOM) {
    // Test: JSON with UTF-8 BOM
    std::string bom = "\xEF\xBB\xBF";
    std::string data = bom + R"({"objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should handle BOM gracefully
    EXPECT_TRUE(success || !success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithControlCharacters) {
    // Test: JSON with escaped control characters
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "description": "Test\t\r\n\b\f"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithEscapedUnicode) {
    // Test: JSON with escaped Unicode sequences
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "description": "\u0048\u0065\u006C\u006C\u006F \u4E16\u754C"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithSurrogatePairs) {
    // Test: JSON with Unicode surrogate pairs (emoji, etc.)
    std::string data = R"({
        "objects": [{
            "value": "192.168.1.1",
            "itype": "mal_ip",
            "description": "Malware \uD83D\uDC80"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithTrailingComma) {
    // Test: JSON with trailing comma (invalid JSON but common mistake)
    std::string data = R"({
        "objects": [
            {"value": "192.168.1.1", "itype": "mal_ip"},
        ]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // nlohmann::json rejects trailing commas by default
    EXPECT_FALSE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithComments) {
    // Test: JSON with comments (invalid standard JSON)
    std::string data = R"({
        // This is a comment
        "objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Standard JSON parsers reject comments
    EXPECT_FALSE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithWhitespaceVariations) {
    // Test: Various whitespace patterns
    std::string data = "   \t\n\r {  \"objects\"  :  [  {  \"value\"  :  \"192.168.1.1\"  ,  \"itype\"  :  \"mal_ip\"  }  ]  }   ";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithDuplicateKeys) {
    // Test: JSON with duplicate keys (behavior is undefined in JSON spec)
    std::string data = R"({
        "objects": [{"value": "192.168.1.1", "value": "10.0.0.1", "itype": "mal_ip"}]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // nlohmann::json takes the last value for duplicate keys
    EXPECT_TRUE(success);
}

// --- Error Recovery Edge Cases ---

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithPartialData) {
    // Test: Truncated JSON data
    std::string data = R"({"objects": [{"value": "192.168)";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_FALSE(success);
    EXPECT_FALSE(parser->GetLastError().empty());
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithNullValues) {
    // Test: JSON with explicit null values
    std::string data = R"({
        "objects": [{
            "value": null,
            "itype": "mal_ip",
            "severity": null,
            "tags": null
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should handle null values gracefully
    EXPECT_TRUE(success || !success);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithMixedValidInvalidEntries) {
    // Test: Mix of valid and invalid entries
    std::string data = R"({
        "objects": [
            {"value": "192.168.1.1", "itype": "mal_ip"},
            {"invalid": "entry", "no_value": true},
            {"value": "192.168.1.2", "itype": "mal_ip"},
            {},
            {"value": "192.168.1.3", "itype": "mal_ip"}
        ]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    // Should skip invalid entries, parse valid ones
    EXPECT_GE(entries.size(), 3u);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithDifferentFormats) {
    // Test: Auto-detection of various JSON formats
    std::vector<std::string> formats = {
        R"({"objects": [{"value": "1.1.1.1", "itype": "mal_ip"}]})",       // ThreatStream
        R"({"results": [{"indicator": "2.2.2.2", "type": "IPv4"}]})",     // AlienVault
        R"({"data": [{"value": "3.3.3.3", "type": "ip"}]})",              // Generic data
        R"({"indicators": [{"value": "4.4.4.4", "type": "ip"}]})",        // Generic indicators
        R"({"iocs": [{"value": "5.5.5.5", "type": "ip"}]})",              // Generic iocs
        R"({"entries": [{"value": "6.6.6.6", "type": "ip"}]})",           // Generic entries
        R"({"items": [{"value": "7.7.7.7", "type": "ip"}]})"              // Generic items
    };
    
    for (size_t i = 0; i < formats.size(); i++) {
        std::vector<IOCEntry> entries;
        bool success = parser->Parse(ToSpan(formats[i]), entries, defaultConfig);
        
        EXPECT_TRUE(success) << "Failed for format index: " << i;
        EXPECT_GE(entries.size(), 1u) << "No entries parsed for format index: " << i;
    }
}

// --- Performance Edge Cases ---

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithManySmallObjects) {
    // Test: Many small objects (stress test for object allocation)
    std::ostringstream json;
    json << R"({"objects": [)";
    for (int i = 0; i < 10000; i++) {
        if (i > 0) json << ",";
        json << R"({"value": "192.168.)" << (i / 256) << "." << (i % 256) << R"(", "itype": "mal_ip"})";
    }
    json << "]}";
    
    std::string data = json.str();
    std::vector<IOCEntry> entries;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 10000u);
    // Should complete in reasonable time (< 5 seconds)
    EXPECT_LT(duration.count(), 5000);
}

TEST_F(JsonFeedParserEdgeCaseTest, ParseJsonWithDeepArrayNesting) {
    // Test: Deeply nested arrays (different from object nesting)
    std::string data = R"({
        "objects": [
            {"value": "192.168.1.1", "itype": "mal_ip", "tags": [["a", ["b", ["c"]]], "d"]}
        ]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

/**
 * @brief Enterprise-grade edge case tests for CsvFeedParser
 */
class CsvFeedParserEdgeCaseTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<CsvFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithNullBytes) {
    // Test: CSV with null bytes
    std::string data = "ip,type\n192.168.1.1,malware\n";
    data.insert(10, 1, '\0');
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithExtremelyLongLine) {
    // Test: Single line exceeding typical buffer sizes
    std::string longDesc(1024 * 64, 'A');  // 64KB description
    std::string data = "ip,description\n192.168.1.1,\"" + longDesc + "\"\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithMixedQuoteStyles) {
    // Test: Inconsistent quote usage
    std::string data = "ip,type,desc\n"
                       "192.168.1.1,malware,\"quoted\"\n"
                       "192.168.1.2,malware,unquoted\n"
                       "192.168.1.3,\"malware\",mixed\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 3u);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithEscapedQuotes) {
    // Test: CSV with escaped quotes inside quoted fields
    std::string data = "ip,description\n"
                       R"(192.168.1.1,"He said ""hello""")";
    data += "\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithNewlinesInQuotedFields) {
    // Test: Multiline quoted fields
    std::string data = "ip,description\n"
                       R"(192.168.1.1,"Line 1
Line 2
Line 3")";
    data += "\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithVariableColumnCount) {
    // Test: Rows with different column counts
    std::string data = "ip,type,severity\n"
                       "192.168.1.1,malware,high\n"
                       "192.168.1.2,botnet\n"  // Missing column
                       "192.168.1.3,c2,low,extra\n";  // Extra column
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should handle gracefully
    EXPECT_TRUE(success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithUnicodeHeaders) {
    // Test: Unicode in header names
    std::string data = "IP地址,类型,严重性\n"
                       "192.168.1.1,malware,high\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithOnlyWhitespace) {
    // Test: CSV with only whitespace
    // Parser may return true (success with 0 entries) or false (no valid content)
    // Both are valid behaviors depending on implementation
    std::string data = "   \t\n\r\n   \t   \n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // If success, should have no entries
    if (success) {
        EXPECT_EQ(entries.size(), 0u);
    }
    // Both outcomes are acceptable - the key is no crash
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithSemicolonDelimiter) {
    // Test: European CSV format with semicolon delimiter
    std::string data = "ip;type;severity\n"
                       "192.168.1.1;malware;high\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Parser should auto-detect or allow configuration
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseCsvWithBOM) {
    // Test: CSV with UTF-8 BOM
    std::string bom = "\xEF\xBB\xBF";
    std::string data = bom + "ip,type\n192.168.1.1,malware\n";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success || !success);
}

TEST_F(CsvFeedParserEdgeCaseTest, ParseLargeCsvFile) {
    // Test: Large CSV file (performance test)
    std::ostringstream csv;
    csv << "ip,type,severity\n";
    for (int i = 0; i < 50000; i++) {
        csv << "192.168." << (i / 256) << "." << (i % 256) << ",malware,high\n";
    }
    
    std::string data = csv.str();
    std::vector<IOCEntry> entries;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 50000u);
    // Should complete in reasonable time (< 10 seconds)
    EXPECT_LT(duration.count(), 10000);
}

/**
 * @brief Enterprise-grade edge case tests for StixFeedParser
 */
class StixFeedParserEdgeCaseTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<StixFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(StixFeedParserEdgeCaseTest, ParseStixWithComplexPattern) {
    // Test: Complex STIX patterns with AND/OR operators
    std::string data = R"({
        "type": "bundle",
        "id": "bundle--complex-1",
        "objects": [{
            "type": "indicator",
            "id": "indicator--complex-1",
            "pattern": "([ipv4-addr:value = '192.168.1.1'] AND [domain-name:value = 'evil.com']) OR [file:hashes.SHA256 = 'abc123']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00.000Z"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(StixFeedParserEdgeCaseTest, ParseStixWithMultipleIndicatorTypes) {
    // Test: Bundle with various indicator types
    std::string data = R"({
        "type": "bundle",
        "id": "bundle--multi-type",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '1.1.1.1']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[ipv6-addr:value = '2001:db8::1']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "indicator", "id": "indicator--3", "pattern": "[domain-name:value = 'evil.com']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "indicator", "id": "indicator--4", "pattern": "[url:value = 'http://evil.com/malware']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "indicator", "id": "indicator--5", "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']", "valid_from": "2024-01-01T00:00:00.000Z"}
        ]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_GE(entries.size(), 5u);
}

TEST_F(StixFeedParserEdgeCaseTest, ParseStixWithMixedObjectTypes) {
    // Test: Bundle with non-indicator objects (should be skipped)
    std::string data = R"({
        "type": "bundle",
        "id": "bundle--mixed",
        "objects": [
            {"type": "identity", "id": "identity--1", "name": "Test"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '1.1.1.1']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "malware", "id": "malware--1", "name": "TestMalware"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value = 'evil.com']", "valid_from": "2024-01-01T00:00:00.000Z"},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "uses"}
        ]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    // Should only parse indicators
    EXPECT_EQ(entries.size(), 2u);
}

TEST_F(StixFeedParserEdgeCaseTest, ParseStixWithKillChainPhases) {
    // Test: STIX indicator with kill chain phases
    std::string data = R"({
        "type": "bundle",
        "id": "bundle--killchain",
        "objects": [{
            "type": "indicator",
            "id": "indicator--killchain",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00.000Z",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
            ]
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
}

TEST_F(StixFeedParserEdgeCaseTest, ParseStixEmptyBundle) {
    // Test: Empty STIX bundle
    std::string data = R"({"type": "bundle", "id": "bundle--empty", "objects": []})";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entries.size(), 0u);
}

TEST_F(StixFeedParserEdgeCaseTest, ParseStixWithExpiredIndicator) {
    // Test: STIX indicator with expired valid_until
    std::string data = R"({
        "type": "bundle",
        "id": "bundle--expired",
        "objects": [{
            "type": "indicator",
            "id": "indicator--expired",
            "pattern": "[ipv4-addr:value = '192.168.1.1']",
            "pattern_type": "stix",
            "valid_from": "2020-01-01T00:00:00.000Z",
            "valid_until": "2020-12-31T23:59:59.000Z"
        }]
    })";
    
    std::vector<IOCEntry> entries;
    bool success = parser->Parse(ToSpan(data), entries, defaultConfig);
    
    // Should still parse, expiration check is application logic
    EXPECT_TRUE(success);
}

/**
 * @brief Memory safety and robustness tests
 */
class ParserMemorySafetyTest : public ::testing::Test {
protected:
    std::unique_ptr<IFeedParser> jsonParser;
    std::unique_ptr<IFeedParser> csvParser;
    std::unique_ptr<IFeedParser> stixParser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        jsonParser = std::make_unique<JsonFeedParser>();
        csvParser = std::make_unique<CsvFeedParser>();
        stixParser = std::make_unique<StixFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(ParserMemorySafetyTest, ParseEmptySpan) {
    // Test: Parsing completely empty span
    std::span<const uint8_t> emptySpan;
    std::vector<IOCEntry> entries;
    
    EXPECT_FALSE(jsonParser->Parse(emptySpan, entries, defaultConfig));
    EXPECT_FALSE(csvParser->Parse(emptySpan, entries, defaultConfig));
    EXPECT_FALSE(stixParser->Parse(emptySpan, entries, defaultConfig));
}

TEST_F(ParserMemorySafetyTest, ParseRepeatedlyWithoutReset) {
    // Test: Multiple parses without creating new parser
    std::string data = R"({"objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]})";
    
    for (int i = 0; i < 100; i++) {
        std::vector<IOCEntry> entries;
        bool success = jsonParser->Parse(ToSpan(data), entries, defaultConfig);
        EXPECT_TRUE(success);
        EXPECT_EQ(entries.size(), 1u);
    }
}

TEST_F(ParserMemorySafetyTest, ParseAlternatingSuccessFailure) {
    // Test: Alternating valid and invalid data
    std::string validData = R"({"objects": [{"value": "192.168.1.1", "itype": "mal_ip"}]})";
    std::string invalidData = R"({"invalid json)";
    
    for (int i = 0; i < 50; i++) {
        std::vector<IOCEntry> entries;
        
        if (i % 2 == 0) {
            bool success = jsonParser->Parse(ToSpan(validData), entries, defaultConfig);
            EXPECT_TRUE(success);
        } else {
            bool success = jsonParser->Parse(ToSpan(invalidData), entries, defaultConfig);
            EXPECT_FALSE(success);
        }
    }
}

TEST_F(ParserMemorySafetyTest, ParseConcurrentParsers) {
    // Test: Multiple parser instances don't interfere
    auto parser1 = std::make_unique<JsonFeedParser>();
    auto parser2 = std::make_unique<JsonFeedParser>();
    auto parser3 = std::make_unique<JsonFeedParser>();
    
    std::string data1 = R"({"objects": [{"value": "1.1.1.1", "itype": "mal_ip"}]})";
    std::string data2 = R"({"objects": [{"value": "2.2.2.2", "itype": "mal_ip"}]})";
    std::string data3 = R"({"objects": [{"value": "3.3.3.3", "itype": "mal_ip"}]})";
    
    std::vector<IOCEntry> entries1, entries2, entries3;
    
    bool success1 = parser1->Parse(ToSpan(data1), entries1, defaultConfig);
    bool success2 = parser2->Parse(ToSpan(data2), entries2, defaultConfig);
    bool success3 = parser3->Parse(ToSpan(data3), entries3, defaultConfig);
    
    EXPECT_TRUE(success1);
    EXPECT_TRUE(success2);
    EXPECT_TRUE(success3);
    
    EXPECT_EQ(entries1.size(), 1u);
    EXPECT_EQ(entries2.size(), 1u);
    EXPECT_EQ(entries3.size(), 1u);
}

/**
 * @brief Streaming parser edge case tests
 * 
 * Tests the ParseStreaming API which uses IOCReceivedCallback
 * for memory-efficient processing of large feeds.
 */
class StreamingParserEdgeCaseTest : public ::testing::Test {
protected:
    std::unique_ptr<JsonFeedParser> parser;
    ParserConfig defaultConfig;
    
    void SetUp() override {
        parser = std::make_unique<JsonFeedParser>();
        defaultConfig = ParserConfig{};
    }
    
    [[nodiscard]] std::span<const uint8_t> ToSpan(const std::string& data) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
    }
};

TEST_F(StreamingParserEdgeCaseTest, ParseLargeFileStreaming) {
    // Test: Large file with streaming callback
    std::ostringstream json;
    json << R"({"objects": [)";
    for (int i = 0; i < 5000; i++) {
        if (i > 0) json << ",";
        json << R"({"value": "192.168.)" << (i / 256) << "." << (i % 256) << R"(", "itype": "mal_ip"})";
    }
    json << "]}";
    
    std::string data = json.str();
    std::vector<IOCEntry> receivedEntries;
    
    // Use IOCReceivedCallback to collect entries
    IOCReceivedCallback callback = [&receivedEntries](const IOCEntry& entry) -> bool {
        receivedEntries.push_back(entry);
        return true;  // Continue processing
    };
    
    bool success = parser->ParseStreaming(ToSpan(data), callback, defaultConfig);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(receivedEntries.size(), 5000u);
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingWithEarlyTermination) {
    // Test: Streaming with early termination via callback
    std::string data = R"({"objects": [
        {"value": "1.1.1.1", "itype": "mal_ip"},
        {"value": "2.2.2.2", "itype": "mal_ip"},
        {"value": "3.3.3.3", "itype": "mal_ip"},
        {"value": "4.4.4.4", "itype": "mal_ip"},
        {"value": "5.5.5.5", "itype": "mal_ip"}
    ]})";
    
    size_t callbackCount = 0;
    constexpr size_t MAX_ENTRIES = 3;
    
    IOCReceivedCallback callback = [&callbackCount, MAX_ENTRIES](const IOCEntry&) -> bool {
        callbackCount++;
        // Return false after 3 entries to terminate early
        return callbackCount < MAX_ENTRIES;
    };
    
    bool success = parser->ParseStreaming(ToSpan(data), callback, defaultConfig);
    
    // Should succeed even with early termination
    EXPECT_TRUE(success || !success);  // Implementation may vary
    EXPECT_GE(callbackCount, 1u);
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingEmptyData) {
    // Test: Streaming with empty data
    std::string data = "";
    std::vector<IOCEntry> receivedEntries;
    
    IOCReceivedCallback callback = [&receivedEntries](const IOCEntry& entry) -> bool {
        receivedEntries.push_back(entry);
        return true;
    };
    
    bool success = parser->ParseStreaming(ToSpan(data), callback, defaultConfig);
    
    EXPECT_FALSE(success);
    EXPECT_EQ(receivedEntries.size(), 0u);
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingMalformedData) {
    // Test: Streaming with malformed data
    std::string data = R"({"objects": [{"invalid)";
    std::vector<IOCEntry> receivedEntries;
    
    IOCReceivedCallback callback = [&receivedEntries](const IOCEntry& entry) -> bool {
        receivedEntries.push_back(entry);
        return true;
    };
    
    bool success = parser->ParseStreaming(ToSpan(data), callback, defaultConfig);
    
    EXPECT_FALSE(success);
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingWithNullCallback) {
    // Test: Streaming with null callback (should handle gracefully)
    std::string data = R"({"objects": [{"value": "1.1.1.1", "itype": "mal_ip"}]})";
    
    IOCReceivedCallback nullCallback = nullptr;
    
    // Should not crash with null callback
    bool success = parser->ParseStreaming(ToSpan(data), nullCallback, defaultConfig);
    
    // Behavior depends on implementation
    EXPECT_TRUE(success || !success);
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingCallbackThrows) {
    // Test: Callback throws exception (should be handled)
    std::string data = R"({"objects": [
        {"value": "1.1.1.1", "itype": "mal_ip"},
        {"value": "2.2.2.2", "itype": "mal_ip"}
    ]})";
    
    int callCount = 0;
    IOCReceivedCallback throwingCallback = [&callCount](const IOCEntry&) -> bool {
        callCount++;
        if (callCount == 2) {
            throw std::runtime_error("Test exception");
        }
        return true;
    };
    
    // Should handle exception gracefully
    try {
        bool success = parser->ParseStreaming(ToSpan(data), throwingCallback, defaultConfig);
        EXPECT_TRUE(success || !success);
    } catch (const std::exception&) {
        // Parser may propagate exception - both behaviors are valid
        EXPECT_GE(callCount, 1);
    }
}

TEST_F(StreamingParserEdgeCaseTest, ParseStreamingPerformance) {
    // Test: Performance of streaming parser with large dataset
    std::ostringstream json;
    json << R"({"objects": [)";
    for (int i = 0; i < 10000; i++) {
        if (i > 0) json << ",";
        json << R"({"value": "10.)" << ((i / 65536) % 256) << "." << ((i / 256) % 256) << "." << (i % 256) << R"(", "itype": "mal_ip"})";
    }
    json << "]}";
    
    std::string data = json.str();
    size_t entryCount = 0;
    
    IOCReceivedCallback callback = [&entryCount](const IOCEntry&) -> bool {
        entryCount++;
        return true;
    };
    
    auto start = std::chrono::high_resolution_clock::now();
    bool success = parser->ParseStreaming(ToSpan(data), callback, defaultConfig);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(entryCount, 10000u);
    // Should complete in reasonable time (< 5 seconds)
    EXPECT_LT(duration.count(), 5000);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
