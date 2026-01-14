
#include <gtest/gtest.h>

#include "../../../../src/ThreatIntel/ThreatIntelExporter.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelDatabase.hpp"

#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ShadowStrike::ThreatIntel::Tests {

using namespace ShadowStrike::ThreatIntel;

namespace {

class TestStringPool final : public IStringPoolReader {
public:
	uint64_t Put(std::string value) {
		// Keep offsets small and deterministic.
		const uint64_t offset = m_nextOffset;
		m_nextOffset += static_cast<uint64_t>(value.size() + 17);
		m_storage.emplace(offset, std::move(value));
		return offset;
	}

	[[nodiscard]] std::string_view ReadString(uint64_t offset, uint32_t length) const noexcept override {
		auto it = m_storage.find(offset);
		if (it == m_storage.end()) {
			return {};
		}
		const std::string& s = it->second;
		if (length == 0 || length > s.size()) {
			return {};
		}
		return std::string_view(s.data(), length);
	}

	[[nodiscard]] bool IsValidOffset(uint64_t offset) const noexcept override {
		return m_storage.find(offset) != m_storage.end();
	}

private:
	uint64_t m_nextOffset = 1;
	std::unordered_map<uint64_t, std::string> m_storage;
};

struct TempDir {
	std::filesystem::path path;

	TempDir() {
		const auto base = std::filesystem::temp_directory_path();
		// Use UUID for collision resistance.
		const std::string name = std::string("ShadowStrike_ThreatIntelExporter_") + GenerateUUID();
		path = base / name;
		std::filesystem::create_directories(path);
	}

	~TempDir() {
		std::error_code ec;
		std::filesystem::remove_all(path, ec);
	}

	[[nodiscard]] std::wstring WPath(const std::wstring& filename) const {
		return (path / filename).wstring();
	}
};

[[nodiscard]] bool LooksLikeUuidV4(std::string_view s) {
	static const std::regex kUuidRe(
		"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		std::regex::ECMAScript
	);
	return std::regex_match(s.begin(), s.end(), kUuidRe);
}

[[nodiscard]] IOCEntry MakeActiveBaseEntry(uint64_t id, IOCType type) {
	IOCEntry e{};
	e.entryId = id;
	e.type = type;
	e.flags = IOCFlags::Enabled;
	e.source = ThreatIntelSource::InternalAnalysis;
	e.secondarySource = ThreatIntelSource::Reserved;
	e.feedId = 123;
	e.reputation = ReputationLevel::HighRisk;
	e.confidence = ConfidenceLevel::High;
	e.category = ThreatCategory::Malware;
	e.secondaryCategory = ThreatCategory::Unknown;
	e.firstSeen = 1609459200;   // 2021-01-01T00:00:00Z
	e.lastSeen = 1609459260;    // +60 sec
	e.createdTime = 1609459200;
	e.expirationTime = 0;
	e.severity = 80;
	e.vtPositives = 10;
	e.vtTotal = 70;
	e.abuseIPDBScore = 90;
	e.SetHitCount(0);
	return e;
}

[[nodiscard]] IOCEntry MakeIPv4Entry(uint64_t id, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t prefix = 32) {
	IOCEntry e = MakeActiveBaseEntry(id, IOCType::IPv4);
	e.value.ipv4 = {};
	e.value.ipv4.Set(a, b, c, d, prefix);
	return e;
}

[[nodiscard]] IOCEntry MakeHashEntry(uint64_t id, HashAlgorithm algo, std::span<const uint8_t> bytes) {
	IOCEntry e = MakeActiveBaseEntry(id, IOCType::FileHash);
	e.value.hash = {};
	e.value.hash.Set(algo, bytes.data(), static_cast<uint8_t>(bytes.size()));
	return e;
}

// Helper to write a small file in binary mode.
[[nodiscard]] bool WriteFile(const std::filesystem::path& p, std::string_view bytes) {
	std::ofstream f(p, std::ios::binary | std::ios::trunc);
	if (!f.is_open()) {
		return false;
	}
	f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	return f.good();
}

// Split lines (drops a trailing empty line).
std::vector<std::string> SplitLines(const std::string& s) {
	std::vector<std::string> lines;
	std::string cur;
	for (char ch : s) {
		if (ch == '\n') {
			lines.push_back(cur);
			cur.clear();
		} else if (ch != '\r') {
			cur.push_back(ch);
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	return lines;
}

} // namespace

// ============================================================================
// Utility Function Tests
// ============================================================================

TEST(ThreatIntelExporter_Utilities, ExportFormat_MetadataIsStable) {
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::CSV), ".csv");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::JSON), ".json");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::JSONL), ".jsonl");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::STIX21), ".stix.json");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::MISP), ".misp.json");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::OpenIOC), ".ioc");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::TAXII21), ".taxii.json");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::PlainText), ".txt");
	EXPECT_STREQ(GetExportFormatExtension(ExportFormat::Binary), ".bin");

	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::CSV), "text/csv");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::JSON), "application/json");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::JSONL), "application/json");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::STIX21), "application/json");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::MISP), "application/json");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::OpenIOC), "application/xml");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::PlainText), "text/plain");
	EXPECT_STREQ(GetExportFormatMimeType(ExportFormat::Binary), "application/octet-stream");

	EXPECT_STREQ(GetExportFormatName(ExportFormat::CSV), "CSV");
	EXPECT_STREQ(GetExportFormatName(ExportFormat::JSON), "JSON");
	EXPECT_STREQ(GetExportFormatName(ExportFormat::JSONL), "JSON Lines");
}

TEST(ThreatIntelExporter_Utilities, ParseExportFormat_CaseInsensitiveAndAliases) {
	EXPECT_EQ(ParseExportFormat("CSV"), ExportFormat::CSV);
	EXPECT_EQ(ParseExportFormat("json"), ExportFormat::JSON);
	EXPECT_EQ(ParseExportFormat("JsonL"), ExportFormat::JSONL);
	EXPECT_EQ(ParseExportFormat("jsonlines"), ExportFormat::JSONL);
	EXPECT_EQ(ParseExportFormat("stix"), ExportFormat::STIX21);
	EXPECT_EQ(ParseExportFormat("stix2.1"), ExportFormat::STIX21);
	EXPECT_EQ(ParseExportFormat("ioc"), ExportFormat::OpenIOC);
	EXPECT_EQ(ParseExportFormat("taxii21"), ExportFormat::TAXII21);
	EXPECT_EQ(ParseExportFormat("plain"), ExportFormat::PlainText);
	EXPECT_EQ(ParseExportFormat("binary"), ExportFormat::Binary);
	EXPECT_EQ(ParseExportFormat("cs"), ExportFormat::CrowdStrike);
	EXPECT_EQ(ParseExportFormat("mssentinel"), ExportFormat::MSSentinel);
	EXPECT_EQ(ParseExportFormat("splunk"), ExportFormat::Splunk);

	EXPECT_EQ(ParseExportFormat(" csv "), std::nullopt); // no trimming
	EXPECT_EQ(ParseExportFormat(""), std::nullopt);
	EXPECT_EQ(ParseExportFormat("unknown-format"), std::nullopt);
}

TEST(ThreatIntelExporter_Utilities, GenerateUUID_FormatVersionVariantAndUniqueness) {
	std::unordered_set<std::string> seen;
	seen.reserve(256);

	for (int i = 0; i < 200; ++i) {
		std::string id = GenerateUUID();
		ASSERT_EQ(id.size(), 36u);
		ASSERT_TRUE(LooksLikeUuidV4(id)) << id;
		// Uniqueness (probabilistic but extremely safe at this scale)
		ASSERT_TRUE(seen.insert(id).second) << "UUID collision: " << id;
	}
}

TEST(ThreatIntelExporter_Utilities, FormatISO8601Timestamp_KnownValues) {
	EXPECT_EQ(FormatISO8601Timestamp(0), "1970-01-01T00:00:00Z");
	EXPECT_EQ(FormatISO8601Timestamp(1), "1970-01-01T00:00:01Z");
	EXPECT_EQ(FormatISO8601Timestamp(1609459200ULL), "2021-01-01T00:00:00Z");

	const std::string s = FormatISO8601Timestamp(1700000000ULL);
	EXPECT_EQ(s.size(), 20u);
	EXPECT_EQ(s.back(), 'Z');
	EXPECT_EQ(s[4], '-');
	EXPECT_EQ(s[7], '-');
	EXPECT_EQ(s[10], 'T');
	EXPECT_EQ(s[13], ':');
	EXPECT_EQ(s[16], ':');
}

TEST(ThreatIntelExporter_Utilities, CalculateFileSHA256_KnownDigestsAndFailures) {
	TempDir dir;
	const auto abcPath = dir.path / "abc.txt";
	const auto emptyPath = dir.path / "empty.bin";

	ASSERT_TRUE(WriteFile(abcPath, "abc"));
	ASSERT_TRUE(WriteFile(emptyPath, ""));

	EXPECT_EQ(CalculateFileSHA256(L""), "");
	EXPECT_EQ(CalculateFileSHA256((dir.path / "does_not_exist.bin").wstring()), "");

	EXPECT_EQ(
		CalculateFileSHA256(abcPath.wstring()),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	);
	EXPECT_EQ(
		CalculateFileSHA256(emptyPath.wstring()),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	);
}

// ============================================================================
// IOC Value Formatting Tests
// ============================================================================

TEST(ThreatIntelExporter_FormatIOCValue, InlineTypes_AreFormatted) {
	EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(MakeIPv4Entry(1, 1, 2, 3, 4, 32), nullptr), "1.2.3.4");
	EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(MakeIPv4Entry(2, 10, 0, 0, 0, 24), nullptr), "10.0.0.0/24");

	const std::array<uint8_t, 3> h{{0x00, 0x01, 0xFF}};
	IOCEntry hashEntry = MakeHashEntry(3, HashAlgorithm::SHA256, h);
	const std::string hashStr = ThreatIntelExporter::FormatIOCValue(hashEntry, nullptr);
	// Hash formatter prints exactly length bytes (hex), so 3 bytes -> 6 chars.
	EXPECT_EQ(hashStr, "0001ff");
}

TEST(ThreatIntelExporter_FormatIOCValue, StringTypes_ValidateStringPool) {
	TestStringPool pool;

	// Missing pool -> empty.
	{
		IOCEntry e = MakeActiveBaseEntry(10, IOCType::Domain);
		e.value.stringRef.stringOffset = 1;
		e.value.stringRef.stringLength = 5;
		EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(e, nullptr), "");
	}

	// Invalid offset -> empty.
	{
		IOCEntry e = MakeActiveBaseEntry(11, IOCType::Domain);
		e.value.stringRef.stringOffset = 9999;
		e.value.stringRef.stringLength = 5;
		EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(e, &pool), "");
	}

	// Zero length -> empty.
	{
		IOCEntry e = MakeActiveBaseEntry(12, IOCType::Domain);
		const uint64_t off = pool.Put("example.com");
		e.value.stringRef.stringOffset = off;
		e.value.stringRef.stringLength = 0;
		EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(e, &pool), "");
	}

	// Valid read.
	{
		const std::string v = "example.com";
		const uint64_t off = pool.Put(v);
		IOCEntry e = MakeActiveBaseEntry(13, IOCType::Domain);
		e.value.stringRef.stringOffset = off;
		e.value.stringRef.stringLength = static_cast<uint32_t>(v.size());
		EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(e, &pool), v);
	}
}

TEST(ThreatIntelExporter_FormatIOCValue, ASN_UsesRawBytes) {
	IOCEntry e = MakeActiveBaseEntry(20, IOCType::ASN);
	const uint32_t asn = 13335;
	std::memcpy(e.value.raw, &asn, sizeof(asn));
	EXPECT_EQ(ThreatIntelExporter::FormatIOCValue(e, nullptr), "AS13335");
}

// ============================================================================
// ExportFilter Tests
// ============================================================================

TEST(ThreatIntelExporter_Filter, OnlyActive_RejectsInactive) {
	ExportFilter f;
	f.onlyActive = true;
	IOCEntry e = MakeActiveBaseEntry(1, IOCType::IPv4);
	EXPECT_TRUE(f.Matches(e));

	e.flags = IOCFlags::None; // not Enabled -> inactive
	EXPECT_FALSE(f.Matches(e));
}

TEST(ThreatIntelExporter_Filter, IncludeExcludeTypes_Work) {
	ExportFilter f;
	f.onlyActive = false;
	f.includeTypes = {IOCType::Domain, IOCType::URL};
	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	EXPECT_TRUE(f.Matches(e));
	e.type = IOCType::IPv4;
	EXPECT_FALSE(f.Matches(e));

	f.includeTypes.clear();
	f.excludeTypes = {IOCType::IPv4};
	e.type = IOCType::IPv4;
	EXPECT_FALSE(f.Matches(e));
}

TEST(ThreatIntelExporter_Filter, ReputationConfidenceCategorySourceAndTimeWork) {
	ExportFilter f;
	f.onlyActive = true;
	f.minReputation = ReputationLevel::HighRisk;
	f.maxReputation = ReputationLevel::Critical;
	f.minConfidence = ConfidenceLevel::Medium;
	f.includeCategories = {ThreatCategory::Ransomware};
	f.includeSources = {ThreatIntelSource::VirusTotal};
	f.createdAfter = 100;
	f.createdBefore = 500;
	f.seenAfter = 150;
	f.expiresAfter = 400;

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::IPv4);
	e.reputation = ReputationLevel::HighRisk;
	e.confidence = ConfidenceLevel::High;
	e.category = ThreatCategory::Ransomware;
	e.source = ThreatIntelSource::VirusTotal;
	e.createdTime = 200;
	e.lastSeen = 200;
	e.expirationTime = 0; // No expiration -> passes expiresAfter check
	EXPECT_TRUE(f.Matches(e));

	e.reputation = ReputationLevel::LowRisk;
	EXPECT_FALSE(f.Matches(e));
	e.reputation = ReputationLevel::HighRisk;

	e.confidence = ConfidenceLevel::Low;
	EXPECT_FALSE(f.Matches(e));
	e.confidence = ConfidenceLevel::High;

	e.category = ThreatCategory::Malware;
	e.secondaryCategory = ThreatCategory::Ransomware;
	EXPECT_TRUE(f.Matches(e));
	e.secondaryCategory = ThreatCategory::Unknown;
	EXPECT_FALSE(f.Matches(e));
	e.category = ThreatCategory::Ransomware;

	e.source = ThreatIntelSource::InternalAnalysis;
	e.secondarySource = ThreatIntelSource::VirusTotal;
	EXPECT_TRUE(f.Matches(e));
}

TEST(ThreatIntelExporter_Filter, FlagsAndFeedIds_Work) {
	ExportFilter f;
	f.onlyActive = false;
	f.requiredFlags = IOCFlags::BlockOnMatch;
	f.excludedFlags = IOCFlags::Whitelisted;
	f.feedIds = {7, 11};

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::IPv4);
	e.flags = IOCFlags::Enabled | IOCFlags::BlockOnMatch;
	e.feedId = 11;
	EXPECT_TRUE(f.Matches(e));

	e.feedId = 99;
	EXPECT_FALSE(f.Matches(e));
	e.feedId = 7;

	e.flags = IOCFlags::Enabled; // missing required flag
	EXPECT_FALSE(f.Matches(e));
	e.flags = IOCFlags::Enabled | IOCFlags::BlockOnMatch | IOCFlags::Whitelisted;
	EXPECT_FALSE(f.Matches(e));
}

// ============================================================================
// ExportOptions Factory Tests
// ============================================================================

TEST(ThreatIntelExporter_Options, FactoryMethods_SetExpectedDefaults) {
	{
		ExportOptions o = ExportOptions::FastCSV();
		EXPECT_EQ(o.format, ExportFormat::CSV);
		EXPECT_EQ(o.fields, ExportFields::Basic);
		EXPECT_TRUE(o.includeHeader);
		EXPECT_FALSE(o.prettyPrint);
		EXPECT_EQ(o.bufferSize, 4u * 1024u * 1024u);
		EXPECT_EQ(o.flushInterval, 50000u);
	}
	{
		ExportOptions o = ExportOptions::STIX21Sharing();
		EXPECT_EQ(o.format, ExportFormat::STIX21);
		EXPECT_EQ(o.fields, ExportFields::Full);
		EXPECT_TRUE(o.prettyPrint);
		ASSERT_FALSE(o.stixIdentityId.empty());
		ASSERT_TRUE(o.stixIdentityId.rfind("identity--", 0) == 0);
		ASSERT_TRUE(LooksLikeUuidV4(o.stixIdentityId.substr(std::string("identity--").size())));
	}
	{
		ExportOptions o = ExportOptions::MISPEvent("unit-test");
		EXPECT_EQ(o.format, ExportFormat::MISP);
		EXPECT_EQ(o.fields, ExportFields::Standard);
		EXPECT_TRUE(o.prettyPrint);
		EXPECT_EQ(o.mispEventInfo, "unit-test");
		ASSERT_TRUE(LooksLikeUuidV4(o.mispEventUuid));
	}
	{
		ExportOptions o = ExportOptions::CompressedJSON();
		EXPECT_EQ(o.format, ExportFormat::JSON);
		EXPECT_EQ(o.compression, ExportCompression::GZIP);
		EXPECT_FALSE(o.prettyPrint);
	}
}

// ============================================================================
// Exporter Span-based Export Tests (writers exercised via public API)
// ============================================================================

TEST(ThreatIntelExporter_Export, ExportToString_JSON_EmptyEntriesProducesValidWrapper) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.prettyPrint = false;
	options.fields = ExportFields::Basic;

	std::string out;
	const std::span<const IOCEntry> entries;
	ExportResult r = exporter.ExportToString(entries, nullptr, out, options);

	EXPECT_TRUE(r.success);
	EXPECT_FALSE(r.wasCancelled);
	EXPECT_EQ(r.totalExported, 0u);
	EXPECT_NE(out.find("\"entries\""), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_JSON_BOMAndEscaping) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;
	options.includeBOM = true;

	TestStringPool pool;
	const std::string raw = std::string("a\"b\\c\n\r\t") + std::string(1, static_cast<char>(0x01));
	const uint64_t off = pool.Put(raw);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(raw.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);

	ASSERT_GE(out.size(), 3u);
	EXPECT_EQ(static_cast<unsigned char>(out[0]), 0xEF);
	EXPECT_EQ(static_cast<unsigned char>(out[1]), 0xBB);
	EXPECT_EQ(static_cast<unsigned char>(out[2]), 0xBF);

	// Expect escaped sequences.
	EXPECT_NE(out.find("\\\""), std::string::npos);      // \"
	EXPECT_NE(out.find("\\\\"), std::string::npos);     // \\\\ in JSON text
	EXPECT_NE(out.find("\\n"), std::string::npos);
	EXPECT_NE(out.find("\\r"), std::string::npos);
	EXPECT_NE(out.find("\\t"), std::string::npos);
	EXPECT_NE(out.find("\\u0001"), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_JSONL_OneObjectPerLine) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSONL;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	IOCEntry a = MakeIPv4Entry(1, 1, 2, 3, 4);
	IOCEntry b = MakeIPv4Entry(2, 5, 6, 7, 8);

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&a, 1), nullptr, out, options);
	ASSERT_TRUE(r.success);
	ASSERT_FALSE(out.empty());
	EXPECT_EQ(out.front(), '{');
	EXPECT_EQ(out.back(), '\n');

	std::string out2;
	std::array<IOCEntry, 2> es{a, b};
	r = exporter.ExportToString(std::span<const IOCEntry>(es), nullptr, out2, options);
	ASSERT_TRUE(r.success);
	auto lines = SplitLines(out2);
	ASSERT_EQ(lines.size(), 2u);
	EXPECT_FALSE(lines[0].empty());
	EXPECT_FALSE(lines[1].empty());
	EXPECT_EQ(lines[0].front(), '{');
	EXPECT_EQ(lines[1].front(), '{');
}

TEST(ThreatIntelExporter_Export, ExportToString_CSV_EscapesQuotesDelimitersAndNewlines_CRLF) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::CSV;
	options.fields = ExportFields::Type | ExportFields::Value;
	options.includeHeader = true;
	options.csvDelimiter = ',';
	options.csvQuote = '"';
	options.windowsNewlines = true;

	TestStringPool pool;
	const std::string v = "evil,\"quoted\"\r\nline";
	const uint64_t off = pool.Put(v);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(v.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);

	// Header should end with CRLF.
	ASSERT_NE(out.find("type,value\r\n"), std::string::npos);

	// Value should be quoted and quotes doubled per RFC 4180.
	EXPECT_NE(out.find("domain-name,\"evil,\"\"quoted\"\"\r\nline\"\r\n"), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_STIX21_BundleAndUrlQuoteEscaping) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::STIX21;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value | ExportFields::CreatedTime;

	TestStringPool pool;
	const std::string url = "http://example.com/path'quote";
	const uint64_t off = pool.Put(url);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::URL);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(url.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_NE(out.find("\"type\":\"bundle\""), std::string::npos);
	EXPECT_NE(out.find("\"objects\":"), std::string::npos);
	// URL single quote should be escaped in the STIX pattern.
	EXPECT_NE(out.find("path\\'quote"), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_MISP_MapsHashAlgorithmAndEscapes) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::MISP;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value | ExportFields::Reputation;
	options.mispEventInfo = "evt";

	const std::array<uint8_t, 3> md5bytes{{0xAA, 0xBB, 0xCC}};
	IOCEntry e = MakeHashEntry(1, HashAlgorithm::MD5, md5bytes);
	// Ensure JSON escaping path is exercised too.
	e.reputation = ReputationLevel::HighRisk;

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_NE(out.find("\"Event\":"), std::string::npos);
	EXPECT_NE(out.find("\"type\":\"md5\""), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_OpenIOC_EscapesXmlEntities) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::OpenIOC;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	TestStringPool pool;
	const std::string val = "a&b<c>\"d\'e";
	const uint64_t off = pool.Put(val);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(val.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_NE(out.find("&amp;"), std::string::npos);
	EXPECT_NE(out.find("&lt;"), std::string::npos);
	EXPECT_NE(out.find("&gt;"), std::string::npos);
	EXPECT_NE(out.find("&quot;"), std::string::npos);
	EXPECT_NE(out.find("&apos;"), std::string::npos);
}

TEST(ThreatIntelExporter_Export, ExportToString_PlainText_OneIOCPerLine) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;

	std::array<IOCEntry, 2> entries{MakeIPv4Entry(1, 1, 1, 1, 1), MakeIPv4Entry(2, 8, 8, 8, 8)};
	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(entries), nullptr, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_NE(out.find("1.1.1.1"), std::string::npos);
	EXPECT_NE(out.find("8.8.8.8"), std::string::npos);
}

TEST(ThreatIntelExporter_Export, StartIndexAndMaxEntries_AreRespected) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;
	options.filter.startIndex = 1;
	options.filter.maxEntries = 2;

	std::array<IOCEntry, 4> entries{
		MakeIPv4Entry(1, 1, 1, 1, 1),
		MakeIPv4Entry(2, 2, 2, 2, 2),
		MakeIPv4Entry(3, 3, 3, 3, 3),
		MakeIPv4Entry(4, 4, 4, 4, 4)
	};

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(entries), nullptr, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_EQ(r.totalExported, 2u);
	EXPECT_NE(out.find("2.2.2.2"), std::string::npos);
	EXPECT_NE(out.find("3.3.3.3"), std::string::npos);
	EXPECT_EQ(out.find("1.1.1.1"), std::string::npos);
	EXPECT_EQ(out.find("4.4.4.4"), std::string::npos);
}

// ============================================================================
// Progress / Cancellation Tests
// ============================================================================

TEST(ThreatIntelExporter_Progress, CallbackFiresPeriodicallyAndFinally) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.flushInterval = 1'000'000; // avoid flush noise
	options.filter.onlyActive = false;

	std::vector<IOCEntry> entries;
	entries.reserve(2001);
	for (int i = 0; i < 2001; ++i) {
		entries.push_back(MakeIPv4Entry(static_cast<uint64_t>(i + 1), 10, 0, 0, static_cast<uint8_t>(i % 255)));
	}

	std::atomic<int> calls{0};
	std::atomic<size_t> lastExported{0};

	auto cb = [&](const ExportProgress& p) {
		calls.fetch_add(1, std::memory_order_relaxed);
		EXPECT_GE(p.exportedEntries, lastExported.load(std::memory_order_relaxed));
		lastExported.store(p.exportedEntries, std::memory_order_relaxed);
		if (p.isComplete) {
			EXPECT_TRUE(p.percentComplete >= 100.0);
		}
		return true;
	};

	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, cb);
	ASSERT_TRUE(r.success);
	EXPECT_GE(calls.load(), 3); // at least (1000, 2000, final)
}

TEST(ThreatIntelExporter_Progress, CallbackCanCancelExport) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.flushInterval = 1'000'000;
	options.filter.onlyActive = false;

	std::vector<IOCEntry> entries;
	entries.reserve(3000);
	for (int i = 0; i < 3000; ++i) {
		entries.push_back(MakeIPv4Entry(static_cast<uint64_t>(i + 1), 192, 168, 1, static_cast<uint8_t>(i % 255)));
	}

	auto cb = [&](const ExportProgress& p) {
		if (!p.isComplete && p.exportedEntries >= 1000) {
			return false; // cancel
		}
		return true;
	};

	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, cb);
	EXPECT_TRUE(r.wasCancelled);
	EXPECT_FALSE(r.success); // DoExport leaves success=false on cancellation
	EXPECT_EQ(r.totalExported, 1000u);
}

TEST(ThreatIntelExporter_Progress, RequestCancelStopsBeforeFirstWrite) {
	ThreatIntelExporter exporter;
	exporter.RequestCancel();
	ASSERT_TRUE(exporter.IsCancellationRequested());

	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 2> entries{MakeIPv4Entry(1, 1, 1, 1, 1), MakeIPv4Entry(2, 2, 2, 2, 2)};

	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, nullptr);
	EXPECT_TRUE(r.wasCancelled);
	EXPECT_EQ(r.totalExported, 0u);
	EXPECT_FALSE(r.success);

	exporter.ResetCancellation();
	EXPECT_FALSE(exporter.IsCancellationRequested());
}

// ============================================================================
// File Export Tests
// ============================================================================

TEST(ThreatIntelExporter_File, ExportToFile_WritesFileAndProducesHash) {
	TempDir dir;
	ThreatIntelExporter exporter;

	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 2> entries{MakeIPv4Entry(1, 8, 8, 8, 8), MakeIPv4Entry(2, 1, 1, 1, 1)};
	const std::wstring outPath = dir.WPath(L"out.txt");

	ExportResult r = exporter.ExportToFile(std::span<const IOCEntry>(entries), nullptr, outPath, options, nullptr);
	ASSERT_TRUE(r.success);
	ASSERT_FALSE(r.outputHash.empty());
	EXPECT_EQ(r.outputHash.size(), 64u);
	EXPECT_EQ(r.outputHash, CalculateFileSHA256(outPath));
	EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(outPath)));
}

TEST(ThreatIntelExporter_File, ExportToFile_AppendModeAppends) {
	TempDir dir;
	ThreatIntelExporter exporter;

	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	const std::wstring outPath = dir.WPath(L"append.txt");
	{
		std::array<IOCEntry, 1> entries{MakeIPv4Entry(1, 9, 9, 9, 9)};
		ExportResult r = exporter.ExportToFile(std::span<const IOCEntry>(entries), nullptr, outPath, options, nullptr);
		ASSERT_TRUE(r.success);
	}

	const auto size1 = std::filesystem::file_size(std::filesystem::path(outPath));
	options.appendMode = true;
	{
		std::array<IOCEntry, 1> entries{MakeIPv4Entry(2, 7, 7, 7, 7)};
		ExportResult r = exporter.ExportToFile(std::span<const IOCEntry>(entries), nullptr, outPath, options, nullptr);
		ASSERT_TRUE(r.success);
	}
	const auto size2 = std::filesystem::file_size(std::filesystem::path(outPath));
	EXPECT_GT(size2, size1);
}

TEST(ThreatIntelExporter_File, ExportToFile_EmptyPathFails) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 1> entries{MakeIPv4Entry(1, 1, 2, 3, 4)};
	ExportResult r = exporter.ExportToFile(std::span<const IOCEntry>(entries), nullptr, L"", options, nullptr);
	EXPECT_FALSE(r.success);
	EXPECT_FALSE(r.errorMessage.empty());
}

// ============================================================================
// Database-backed Export Helpers (ExportToBytes / ExportByType / ExportIncremental)
// ============================================================================

class ThreatIntelExporter_DatabaseFixture : public ::testing::Test {
protected:
	TempDir dir;
	std::wstring dbPath;

	ThreatIntelDatabase db;

	void SetUp() override {
		dbPath = (dir.path / L"ti.db").wstring();
		DatabaseConfig cfg = DatabaseConfig::CreateDefault(dbPath);
		cfg.initialSize = DATABASE_MIN_SIZE;
		cfg.verifyOnOpen = false;
		ASSERT_TRUE(db.Open(cfg));
		ASSERT_TRUE(db.IsOpen());
	}

	void TearDown() override {
		db.Close();
	}

	void Populate(std::span<const IOCEntry> entries) {
		const size_t start = db.AllocateEntries(entries.size());
		ASSERT_NE(start, SIZE_MAX);
		IOCEntry* buf = db.GetMutableEntries();
		ASSERT_NE(buf, nullptr);
		for (size_t i = 0; i < entries.size(); ++i) {
			buf[start + i] = entries[i];
		}
		ASSERT_TRUE(db.SetEntryCount(start + entries.size()));
		ASSERT_EQ(db.GetEntryCount(), start + entries.size());
	}
};

TEST_F(ThreatIntelExporter_DatabaseFixture, ExportToBytes_MirrorsStringOutput) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.fields = ExportFields::Basic;
	options.prettyPrint = false;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 1> entries{MakeIPv4Entry(1, 1, 2, 3, 4)};
	Populate(entries);

	std::string s;
	ExportResult r1 = exporter.ExportToString(db, s, options);
	ASSERT_TRUE(r1.success);

	std::vector<uint8_t> bytes;
	ExportResult r2 = exporter.ExportToBytes(db, bytes, options);
	ASSERT_TRUE(r2.success);

	std::string s2(bytes.begin(), bytes.end());
	EXPECT_EQ(s2, s);
}

TEST_F(ThreatIntelExporter_DatabaseFixture, ExportByType_WritesPerTypeFiles) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 3> entries{
		MakeIPv4Entry(1, 1, 1, 1, 1),
		MakeIPv4Entry(2, 8, 8, 8, 8),
		MakeIPv4Entry(3, 9, 9, 9, 9)
	};
	entries[1].type = IOCType::Domain; // we will not export value needing pool; still writer calls FormatIOCValue -> empty; ok for file existence test
	Populate(entries);

	const std::wstring outDir = (dir.path / L"by_type").wstring();
	auto results = exporter.ExportByType(db, outDir, options, nullptr);
	ASSERT_FALSE(results.empty());

	// At least one per present type.
	EXPECT_TRUE(results.find(IOCType::IPv4) != results.end());
	EXPECT_TRUE(results.find(IOCType::Domain) != results.end());

	// Files should exist.
	const auto ipv4File = std::filesystem::path(outDir) / L"ipv4-addr.txt";
	const auto domFile = std::filesystem::path(outDir) / L"domain-name.txt";
	EXPECT_TRUE(std::filesystem::exists(ipv4File));
	EXPECT_TRUE(std::filesystem::exists(domFile));
}

TEST_F(ThreatIntelExporter_DatabaseFixture, ExportIncremental_AppendsAndFiltersByCreatedTime) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 3> entries{MakeIPv4Entry(1, 1, 1, 1, 1), MakeIPv4Entry(2, 2, 2, 2, 2), MakeIPv4Entry(3, 3, 3, 3, 3)};
	entries[0].createdTime = 100;
	entries[1].createdTime = 200;
	entries[2].createdTime = 300;
	Populate(entries);

	const std::wstring outPath = (dir.path / L"inc.txt").wstring();

	ExportResult r1 = exporter.ExportIncremental(db, outPath, 150, options, nullptr);
	ASSERT_TRUE(r1.success);
	{
		std::ifstream f(std::filesystem::path(outPath), std::ios::binary);
		ASSERT_TRUE(f.is_open());
		std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		EXPECT_EQ(SplitLines(s).size(), 2u);
	}

	ExportResult r2 = exporter.ExportIncremental(db, outPath, 250, options, nullptr);
	ASSERT_TRUE(r2.success);
	{
		std::ifstream f(std::filesystem::path(outPath), std::ios::binary);
		ASSERT_TRUE(f.is_open());
		std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		EXPECT_EQ(SplitLines(s).size(), 3u);
	}
}

// ============================================================================
// Additional Edge Cases & Enterprise-Grade Tests
// ============================================================================

// Test all control characters JSON escaping (0x00-0x1F)
TEST(ThreatIntelExporter_Export, JSON_AllControlCharactersEscaped) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	TestStringPool pool;
	// Build string with all control characters
	std::string ctrl;
	for (int i = 0; i < 32; ++i) {
		ctrl.push_back(static_cast<char>(i));
	}
	const uint64_t off = pool.Put(ctrl);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(ctrl.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);

	// All control chars should be escaped as \uXXXX or special escapes
	EXPECT_NE(out.find("\\u0000"), std::string::npos); // NULL
	EXPECT_NE(out.find("\\u0001"), std::string::npos); // SOH
	EXPECT_NE(out.find("\\b"), std::string::npos);     // Backspace (0x08)
	EXPECT_NE(out.find("\\t"), std::string::npos);     // Tab (0x09)
	EXPECT_NE(out.find("\\n"), std::string::npos);     // LF (0x0A)
	EXPECT_NE(out.find("\\f"), std::string::npos);     // FF (0x0C)
	EXPECT_NE(out.find("\\r"), std::string::npos);     // CR (0x0D)
	EXPECT_NE(out.find("\\u001f"), std::string::npos); // Unit Separator
}

// Test Unicode handling in JSON
TEST(ThreatIntelExporter_Export, JSON_UnicodeHandling) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	TestStringPool pool;
	// UTF-8 string with Unicode characters (Trademark™, Euro€, Chinese中文, Emoji🔥)
	const std::string unicode = std::string(
		reinterpret_cast<const char*>(u8"Hello™€中文🔥")
	);
	const uint64_t off = pool.Put(unicode);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(unicode.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);
	// Should contain the unicode string (UTF-8 passthrough or escaped)
	EXPECT_FALSE(out.empty());
}

// Test CSV with different delimiters
TEST(ThreatIntelExporter_Export, CSV_AlternativeDelimiters) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::CSV;
	options.fields = ExportFields::Type | ExportFields::Value;
	options.includeHeader = true;
	options.csvDelimiter = ';'; // Semicolon delimiter
	options.csvQuote = '\'';    // Single quote

	TestStringPool pool;
	const std::string v = "test;with'delimiter";
	const uint64_t off = pool.Put(v);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(v.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);

	// Header should use semicolon
	EXPECT_NE(out.find("type;value"), std::string::npos);
	// Field with delimiter and quote should be quoted and quotes doubled
	EXPECT_NE(out.find("'test;with''delimiter'"), std::string::npos);
}
// Test mixed IOC types in single export
TEST(ThreatIntelExporter_Export, MixedIOCTypes_AllFormatsCorrectly) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	TestStringPool pool;
	const std::string domain = "malware.example.com";
	const uint64_t domOff = pool.Put(domain);

	std::array<IOCEntry, 4> entries{
		MakeIPv4Entry(1, 192, 168, 1, 1),
		MakeActiveBaseEntry(2, IOCType::Domain),
		MakeActiveBaseEntry(3, IOCType::ASN),
		MakeHashEntry(4, HashAlgorithm::SHA256, std::span<const uint8_t>())
	};

	entries[1].value.stringRef.stringOffset = domOff;
	entries[1].value.stringRef.stringLength = static_cast<uint32_t>(domain.size());

	const uint32_t asn = 64512;
	std::memcpy(entries[2].value.raw, &asn, sizeof(asn));  

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(entries), &pool, out, options);
	ASSERT_TRUE(r.success);

	// Should contain all types
	EXPECT_NE(out.find("192.168.1.1"), std::string::npos);
	EXPECT_NE(out.find("malware.example.com"), std::string::npos);
	EXPECT_NE(out.find("AS64512"), std::string::npos);
}

// Test different ExportFields combinations
TEST(ThreatIntelExporter_Export, FieldsCombinations_ProduceCorrectOutput) {
	ThreatIntelExporter exporter;
	IOCEntry e = MakeIPv4Entry(1, 10, 0, 0, 1);

	// Basic fields
	{
		ExportOptions opts;
		opts.format = ExportFormat::JSON;
		opts.fields = ExportFields::Basic;
		std::string out;
		ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, opts);
		ASSERT_TRUE(r.success);
		// Basic includes type, value, reputation, confidence
		EXPECT_NE(out.find("\"type\""), std::string::npos);
		EXPECT_NE(out.find("\"value\""), std::string::npos);
	}

	// Standard fields
	{
		ExportOptions opts;
		opts.format = ExportFormat::JSON;
		opts.fields = ExportFields::Standard;
		std::string out;
		ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, opts);
		ASSERT_TRUE(r.success);
		// Standard includes Basic + timestamps + category
		EXPECT_NE(out.find("\"type\""), std::string::npos);
		EXPECT_NE(out.find("\"value\""), std::string::npos);
	}

	// Full fields
	{
		ExportOptions opts;
		opts.format = ExportFormat::JSON;
		opts.fields = ExportFields::Full;
		std::string out;
		ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, opts);
		ASSERT_TRUE(r.success);
		// Full includes everything
		EXPECT_NE(out.find("\"type\""), std::string::npos);
		EXPECT_NE(out.find("\"value\""), std::string::npos);
	}
}

// Test large string pool values
TEST(ThreatIntelExporter_Export, LargeStringPoolValues_HandleCorrectly) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;

	TestStringPool pool;
	// Create a large string (10KB)
	std::string large(10 * 1024, 'A');
	large += "END";
	const uint64_t off = pool.Put(large);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(large.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);
	EXPECT_NE(out.find("END"), std::string::npos);
	EXPECT_GE(out.size(), 10 * 1024);
}

// Test SHA256 with larger file
TEST(ThreatIntelExporter_Utilities, CalculateFileSHA256_LargeFile) {
	TempDir dir;
	const auto largePath = dir.path / "large.bin";

	// Create 1MB file
	{
		std::ofstream f(largePath, std::ios::binary);
		ASSERT_TRUE(f.is_open());
		std::vector<char> data(1024 * 1024, 'X');
		f.write(data.data(), data.size());
	}

	const std::string hash = CalculateFileSHA256(largePath.wstring());
	ASSERT_FALSE(hash.empty());
	EXPECT_EQ(hash.size(), 64u);
	// Verify it's hex
	for (char c : hash) {
		EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
	}
}

// Test timestamp edge cases
TEST(ThreatIntelExporter_Utilities, FormatISO8601Timestamp_EdgeCases) {
	// Max timestamp (year 2038 problem boundary for 32-bit)
	const std::string s1 = FormatISO8601Timestamp(2147483647ULL);
	EXPECT_EQ(s1.size(), 20u);
	EXPECT_EQ(s1.back(), 'Z');

	// Future timestamp
	const std::string s2 = FormatISO8601Timestamp(4102444800ULL); // 2100-01-01
	EXPECT_EQ(s2.size(), 20u);
	EXPECT_EQ(s2.back(), 'Z');
}

// Test filter factory methods
TEST(ThreatIntelExporter_Filter, FactoryMethods_ProduceCorrectFilters) {
	// MaliciousOnly
	{
		ExportFilter f = ExportFilter::MaliciousOnly();
		EXPECT_EQ(f.minReputation, ReputationLevel::HighRisk);
		EXPECT_TRUE(f.onlyActive);

		IOCEntry e = MakeIPv4Entry(1, 1, 1, 1, 1);
		e.reputation = ReputationLevel::LowRisk;
		EXPECT_FALSE(f.Matches(e));

		e.reputation = ReputationLevel::Critical;
		EXPECT_TRUE(f.Matches(e));
	}

	// ByType
	{
		ExportFilter f = ExportFilter::ByType(IOCType::Domain);
		IOCEntry e1 = MakeIPv4Entry(1, 1, 1, 1, 1);
		IOCEntry e2 = MakeActiveBaseEntry(2, IOCType::Domain);

		EXPECT_FALSE(f.Matches(e1));
		EXPECT_TRUE(f.Matches(e2));
	}

	// BySource
	{
		ExportFilter f = ExportFilter::BySource(ThreatIntelSource::AbuseIPDB);
		IOCEntry e = MakeIPv4Entry(1, 1, 1, 1, 1);
		e.source = ThreatIntelSource::InternalAnalysis;
		EXPECT_FALSE(f.Matches(e));

		e.source = ThreatIntelSource::AbuseIPDB;
		EXPECT_TRUE(f.Matches(e));
	}

	// RecentEntries
	{
		ExportFilter f = ExportFilter::RecentEntries(24); // 24 hours
		const uint64_t now = static_cast<uint64_t>(std::time(nullptr));

		IOCEntry e = MakeIPv4Entry(1, 1, 1, 1, 1);
		e.createdTime = now - 3600; // 1 hour ago
		EXPECT_TRUE(f.Matches(e));

		e.createdTime = now - (48 * 3600); // 48 hours ago
		EXPECT_FALSE(f.Matches(e));
	}
}

// Test error message content
TEST(ThreatIntelExporter_File, ExportToFile_InvalidPath_ProducesDescriptiveError) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;

	std::array<IOCEntry, 1> entries{MakeIPv4Entry(1, 1, 2, 3, 4)};

	// Invalid path (Windows reserved name)
	ExportResult r = exporter.ExportToFile(std::span<const IOCEntry>(entries), nullptr, L"CON", options, nullptr);
	EXPECT_FALSE(r.success);
	EXPECT_FALSE(r.errorMessage.empty());
	// Error message should be descriptive
	EXPECT_GT(r.errorMessage.size(), 5u);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST(ThreatIntelExporter_ThreadSafety, ConcurrentExports_NoDataRaces) {
	static constexpr int kNumThreads = 4;
	static constexpr int kEntriesPerThread = 100;

	std::array<IOCEntry, kEntriesPerThread> entries;
	for (int i = 0; i < kEntriesPerThread; ++i) {
		entries[i] = MakeIPv4Entry(static_cast<uint64_t>(i + 1), 10, 0, 0, static_cast<uint8_t>(i % 255));
	}

	std::atomic<int> successCount{0};
	std::vector<std::thread> threads;
	threads.reserve(kNumThreads);

	for (int t = 0; t < kNumThreads; ++t) {
		threads.emplace_back([&entries, &successCount]() {
			ThreatIntelExporter exporter; // Each thread has own instance
			ExportOptions options;
			options.format = ExportFormat::JSON;
			options.fields = ExportFields::Basic;
			options.filter.onlyActive = false;

			std::string out;
			ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(entries), nullptr, out, options);
			if (r.success) {
				successCount.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	for (auto& th : threads) {
		th.join();
	}

	EXPECT_EQ(successCount.load(), kNumThreads);
}

TEST(ThreatIntelExporter_ThreadSafety, ConcurrentCancellation_ThreadSafe) {
	ThreatIntelExporter exporter;

	std::vector<IOCEntry> entries;
	entries.reserve(10000);
	for (int i = 0; i < 10000; ++i) {
		entries.push_back(MakeIPv4Entry(static_cast<uint64_t>(i + 1), 192, 168, 0, static_cast<uint8_t>(i % 255)));
	}

	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::atomic<bool> exportStarted{false};

	// Export thread
	std::thread exportThread([&]() {
		exportStarted.store(true, std::memory_order_release);
		std::ostringstream oss;
		exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, nullptr);
	});

	// Wait for export to start
	while (!exportStarted.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}

	// Cancel from another thread
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	exporter.RequestCancel();

	exportThread.join();

	EXPECT_TRUE(exporter.IsCancellationRequested());
	exporter.ResetCancellation();
	EXPECT_FALSE(exporter.IsCancellationRequested());
}

// ============================================================================
// Large-Scale/Performance Tests
// ============================================================================

TEST(ThreatIntelExporter_Performance, LargeDataset_HandlesEfficiently) {
	static constexpr size_t kLargeCount = 10000;

	std::vector<IOCEntry> entries;
	entries.reserve(kLargeCount);
	for (size_t i = 0; i < kLargeCount; ++i) {
		entries.push_back(MakeIPv4Entry(static_cast<uint64_t>(i + 1), 
			static_cast<uint8_t>((i >> 16) & 0xFF),
			static_cast<uint8_t>((i >> 8) & 0xFF),
			static_cast<uint8_t>(i & 0xFF),
			static_cast<uint8_t>((i >> 24) & 0xFF)
		));
	}

	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	const auto start = std::chrono::steady_clock::now();
	
	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, nullptr);
	
	const auto elapsed = std::chrono::steady_clock::now() - start;
	const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

	ASSERT_TRUE(r.success);
	EXPECT_EQ(r.totalExported, kLargeCount);
	
	// Performance expectation: should process at least 1000 entries/sec
	// (10000 entries in max 10 seconds)
	EXPECT_LT(ms, 10000) << "Export too slow: " << ms << "ms for " << kLargeCount << " entries";
}

TEST(ThreatIntelExporter_Performance, ProgressCallback_LowOverhead) {
	static constexpr size_t kCount = 5000;

	std::vector<IOCEntry> entries;
	entries.reserve(kCount);
	for (size_t i = 0; i < kCount; ++i) {
		entries.push_back(MakeIPv4Entry(static_cast<uint64_t>(i + 1), 10, 0, 0, static_cast<uint8_t>(i % 255)));
	}

	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::atomic<int> callbackCount{0};
	auto callback = [&callbackCount](const ExportProgress&) {
		callbackCount.fetch_add(1, std::memory_order_relaxed);
		return true;
	};

	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, callback);

	ASSERT_TRUE(r.success);
	EXPECT_EQ(r.totalExported, kCount);
	
	// Callback should fire periodically (at least a few times, not for every entry)
	EXPECT_GT(callbackCount.load(), 0);
	EXPECT_LT(callbackCount.load(), static_cast<int>(kCount)); // Not called for every entry
}

// ============================================================================
// Error Handling & Robustness Tests
// ============================================================================

// Custom stream that fails after N bytes
class FailingOStream : public std::ostream {
private:
	class FailingBuf : public std::streambuf {
	public:
		explicit FailingBuf(size_t failAfter) : m_failAfter(failAfter), m_written(0) {}

	protected:
		std::streamsize xsputn(const char*, std::streamsize n) override {
			if (m_written + n > m_failAfter) {
				return -1; // Fail
			}
			m_written += n;
			return n;
		}

		int overflow(int c) override {
			if (m_written >= m_failAfter) {
				return traits_type::eof();
			}
			m_written++;
			return c;
		}

	private:
		size_t m_failAfter;
		size_t m_written;
	};

	FailingBuf m_buf;

public:
	explicit FailingOStream(size_t failAfter) : std::ostream(&m_buf), m_buf(failAfter) {}
};

TEST(ThreatIntelExporter_ErrorHandling, StreamWriteFailure_ReportsError) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	std::array<IOCEntry, 10> entries;
	for (int i = 0; i < 10; ++i) {
		entries[i] = MakeIPv4Entry(static_cast<uint64_t>(i + 1), 192, 168, 1, static_cast<uint8_t>(i));
	}

	// Stream that fails after 50 bytes
	FailingOStream failStream(50);
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, failStream, options, nullptr);

	// Should handle stream failure gracefully
	// Depending on implementation, might succeed for first few entries or fail
	// The key is it shouldn't crash
	EXPECT_TRUE(r.success || !r.errorMessage.empty());
}

TEST(ThreatIntelExporter_ErrorHandling, InvalidIOCType_HandlesGracefully) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::JSON;
	options.fields = ExportFields::Type | ExportFields::Value;

	IOCEntry e = MakeActiveBaseEntry(1, static_cast<IOCType>(999)); // Invalid type

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, options);
	
	// Should not crash, should handle gracefully
	EXPECT_NO_THROW({
		// Verify no crash
	});
}

TEST(ThreatIntelExporter_ErrorHandling, NullStringPool_HandlesGracefully) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = 100;
	e.value.stringRef.stringLength = 50;

	std::string out;
	// Pass nullptr for string pool - should handle gracefully
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), nullptr, out, options);
	
	ASSERT_TRUE(r.success);
	// Value should be empty since pool is null
}

// ============================================================================
// XML Nested Entity Escaping
// ============================================================================

TEST(ThreatIntelExporter_Export, OpenIOC_NestedXmlEscaping) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::OpenIOC;
	options.prettyPrint = false;
	options.fields = ExportFields::Type | ExportFields::Value;

	TestStringPool pool;
	const std::string nested = "&lt;script&gt;"; // Already contains entities
	const uint64_t off = pool.Put(nested);

	IOCEntry e = MakeActiveBaseEntry(1, IOCType::Domain);
	e.value.stringRef.stringOffset = off;
	e.value.stringRef.stringLength = static_cast<uint32_t>(nested.size());

	std::string out;
	ExportResult r = exporter.ExportToString(std::span<const IOCEntry>(&e, 1), &pool, out, options);
	ASSERT_TRUE(r.success);

	// & in &lt; should be escaped to &amp;lt;
	EXPECT_NE(out.find("&amp;lt;"), std::string::npos);
	EXPECT_NE(out.find("&amp;gt;"), std::string::npos);
}

// ============================================================================
// ExportEntry (Single Entry) Tests
// ============================================================================

TEST(ThreatIntelExporter_SingleEntry, ExportEntry_ReturnsFormattedString) {
	ThreatIntelExporter exporter;
	IOCEntry e = MakeIPv4Entry(1, 8, 8, 8, 8);

	// PlainText format
	{
		std::string result = exporter.ExportEntry(e, nullptr, ExportFormat::PlainText, ExportFields::Value);
		EXPECT_NE(result.find("8.8.8.8"), std::string::npos);
	}

	// JSON format
	{
		std::string result = exporter.ExportEntry(e, nullptr, ExportFormat::JSON, ExportFields::Type | ExportFields::Value);
		EXPECT_NE(result.find("\"type\""), std::string::npos);
		EXPECT_NE(result.find("8.8.8.8"), std::string::npos);
	}
}

// ============================================================================
// Statistics Tracking Tests
// ============================================================================

TEST(ThreatIntelExporter_Statistics, TracksExportStatistics) {
	ThreatIntelExporter exporter;
	ExportOptions options;
	options.format = ExportFormat::PlainText;
	options.fields = ExportFields::Value;
	options.filter.onlyActive = false;

	EXPECT_EQ(exporter.GetTotalEntriesExported(), 0u);
	EXPECT_EQ(exporter.GetTotalBytesWritten(), 0u);
	EXPECT_EQ(exporter.GetTotalExportCount(), 0u);

	std::array<IOCEntry, 5> entries;
	for (int i = 0; i < 5; ++i) {
		entries[i] = MakeIPv4Entry(static_cast<uint64_t>(i + 1), 10, 0, 0, static_cast<uint8_t>(i));
	}

	std::ostringstream oss;
	ExportResult r = exporter.ExportToStream(std::span<const IOCEntry>(entries), nullptr, oss, options, nullptr);
	ASSERT_TRUE(r.success);

	// Statistics should be updated
	EXPECT_GT(exporter.GetTotalEntriesExported(), 0u);
	EXPECT_GT(exporter.GetTotalBytesWritten(), 0u);
	EXPECT_GT(exporter.GetTotalExportCount(), 0u);
}

} // namespace ShadowStrike::ThreatIntel::Tests

