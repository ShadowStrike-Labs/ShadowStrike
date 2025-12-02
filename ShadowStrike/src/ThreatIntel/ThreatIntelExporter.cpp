/**
 * @file ThreatIntelExporter.cpp
 * @brief Enterprise-grade Threat Intelligence Export Implementation
 *
 * High-performance export implementation supporting multiple industry-standard
 * formats with streaming capabilities and progress tracking.
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#include "ThreatIntelExporter.hpp"
#include "ThreatIntelDatabase.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include <filesystem>
#include <algorithm>
#include <charconv>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Utility Function Implementations
// ============================================================================

const char* GetExportFormatExtension(ExportFormat format) noexcept {
    switch (format) {
        case ExportFormat::CSV:         return ".csv";
        case ExportFormat::JSON:        return ".json";
        case ExportFormat::JSONL:       return ".jsonl";
        case ExportFormat::STIX21:      return ".stix.json";
        case ExportFormat::MISP:        return ".misp.json";
        case ExportFormat::OpenIOC:     return ".ioc";
        case ExportFormat::TAXII21:     return ".taxii.json";
        case ExportFormat::PlainText:   return ".txt";
        case ExportFormat::Binary:      return ".bin";
        case ExportFormat::CrowdStrike: return ".cs.json";
        case ExportFormat::MSSentinel:  return ".sentinel.json";
        case ExportFormat::Splunk:      return ".splunk.json";
        default:                        return ".dat";
    }
}

const char* GetExportFormatMimeType(ExportFormat format) noexcept {
    switch (format) {
        case ExportFormat::CSV:         return "text/csv";
        case ExportFormat::JSON:        
        case ExportFormat::JSONL:       
        case ExportFormat::STIX21:      
        case ExportFormat::MISP:        
        case ExportFormat::TAXII21:     return "application/json";
        case ExportFormat::OpenIOC:     return "application/xml";
        case ExportFormat::PlainText:   return "text/plain";
        case ExportFormat::Binary:      return "application/octet-stream";
        default:                        return "application/octet-stream";
    }
}

const char* GetExportFormatName(ExportFormat format) noexcept {
    switch (format) {
        case ExportFormat::CSV:         return "CSV";
        case ExportFormat::JSON:        return "JSON";
        case ExportFormat::JSONL:       return "JSON Lines";
        case ExportFormat::STIX21:      return "STIX 2.1";
        case ExportFormat::MISP:        return "MISP";
        case ExportFormat::OpenIOC:     return "OpenIOC";
        case ExportFormat::TAXII21:     return "TAXII 2.1";
        case ExportFormat::PlainText:   return "Plain Text";
        case ExportFormat::Binary:      return "Binary";
        case ExportFormat::CrowdStrike: return "CrowdStrike";
        case ExportFormat::MSSentinel:  return "Microsoft Sentinel";
        case ExportFormat::Splunk:      return "Splunk";
        default:                        return "Unknown";
    }
}

std::optional<ExportFormat> ParseExportFormat(std::string_view str) noexcept {
    // Convert to lowercase for comparison
    std::string lower;
    lower.reserve(str.size());
    for (char c : str) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    
    if (lower == "csv") return ExportFormat::CSV;
    if (lower == "json") return ExportFormat::JSON;
    if (lower == "jsonl" || lower == "jsonlines") return ExportFormat::JSONL;
    if (lower == "stix" || lower == "stix21" || lower == "stix2.1") return ExportFormat::STIX21;
    if (lower == "misp") return ExportFormat::MISP;
    if (lower == "openioc" || lower == "ioc") return ExportFormat::OpenIOC;
    if (lower == "taxii" || lower == "taxii21") return ExportFormat::TAXII21;
    if (lower == "txt" || lower == "text" || lower == "plain") return ExportFormat::PlainText;
    if (lower == "bin" || lower == "binary") return ExportFormat::Binary;
    if (lower == "crowdstrike" || lower == "cs") return ExportFormat::CrowdStrike;
    if (lower == "sentinel" || lower == "mssentinel") return ExportFormat::MSSentinel;
    if (lower == "splunk") return ExportFormat::Splunk;
    
    return std::nullopt;
}

std::string GenerateUUID() {
    // Use Windows crypto API for secure random UUID generation
    std::array<uint8_t, 16> bytes{};
    
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) == 0) {
        BCryptGenRandom(hAlg, bytes.data(), static_cast<ULONG>(bytes.size()), 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    } else {
        // Fallback to std::random_device
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        
        uint64_t* ptr = reinterpret_cast<uint64_t*>(bytes.data());
        ptr[0] = dis(gen);
        ptr[1] = dis(gen);
    }
    
    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  // Variant 1
    
    // Format as UUID string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            oss << '-';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return oss.str();
}

std::string FormatISO8601Timestamp(uint64_t timestamp) {
    if (timestamp == 0) {
        return "1970-01-01T00:00:00Z";
    }
    
    time_t time = static_cast<time_t>(timestamp);
    struct tm tm_utc;
    
#ifdef _WIN32
    gmtime_s(&tm_utc, &time);
#else
    gmtime_r(&time, &tm_utc);
#endif
    
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << (tm_utc.tm_year + 1900) << '-'
        << std::setw(2) << (tm_utc.tm_mon + 1) << '-'
        << std::setw(2) << tm_utc.tm_mday << 'T'
        << std::setw(2) << tm_utc.tm_hour << ':'
        << std::setw(2) << tm_utc.tm_min << ':'
        << std::setw(2) << tm_utc.tm_sec << 'Z';
    
    return oss.str();
}

std::string CalculateFileSHA256(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        DWORD hashObjectSize = 0;
        DWORD dataSize = 0;
        
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, 
                          reinterpret_cast<PUCHAR>(&hashObjectSize), 
                          sizeof(DWORD), &dataSize, 0);
        
        std::vector<uint8_t> hashObject(hashObjectSize);
        
        if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, 
                             nullptr, 0, 0) == 0) {
            
            std::array<uint8_t, 65536> buffer;
            DWORD bytesRead = 0;
            
            while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), 
                           &bytesRead, nullptr) && bytesRead > 0) {
                BCryptHashData(hHash, buffer.data(), bytesRead, 0);
            }
            
            std::array<uint8_t, 32> hash;
            if (BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0) == 0) {
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (uint8_t b : hash) {
                    oss << std::setw(2) << static_cast<int>(b);
                }
                result = oss.str();
            }
            
            BCryptDestroyHash(hHash);
        }
        
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    CloseHandle(hFile);
    return result;
}

// ============================================================================
// ExportFilter Implementation
// ============================================================================

bool ExportFilter::Matches(const IOCEntry& entry) const noexcept {
    // Check if only active entries
    if (onlyActive && !entry.IsActive()) {
        return false;
    }
    
    // Check IOC type inclusion
    if (!includeTypes.empty()) {
        bool found = false;
        for (IOCType t : includeTypes) {
            if (entry.type == t) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    // Check IOC type exclusion
    for (IOCType t : excludeTypes) {
        if (entry.type == t) {
            return false;
        }
    }
    
    // Check reputation range
    if (minReputation.has_value()) {
        if (static_cast<uint8_t>(entry.reputation) < static_cast<uint8_t>(*minReputation)) {
            return false;
        }
    }
    
    if (maxReputation.has_value()) {
        if (static_cast<uint8_t>(entry.reputation) > static_cast<uint8_t>(*maxReputation)) {
            return false;
        }
    }
    
    // Check confidence
    if (minConfidence.has_value()) {
        if (static_cast<uint8_t>(entry.confidence) < static_cast<uint8_t>(*minConfidence)) {
            return false;
        }
    }
    
    // Check categories
    if (!includeCategories.empty()) {
        bool found = false;
        for (ThreatCategory cat : includeCategories) {
            if (entry.category == cat || entry.secondaryCategory == cat) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    // Check sources
    if (!includeSources.empty()) {
        bool found = false;
        for (ThreatIntelSource src : includeSources) {
            if (entry.source == src || entry.secondarySource == src) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    // Check timestamps
    if (createdAfter.has_value() && entry.createdTime < *createdAfter) {
        return false;
    }
    
    if (createdBefore.has_value() && entry.createdTime > *createdBefore) {
        return false;
    }
    
    if (seenAfter.has_value() && entry.lastSeen < *seenAfter) {
        return false;
    }
    
    if (expiresAfter.has_value()) {
        if (entry.expirationTime > 0 && entry.expirationTime < *expiresAfter) {
            return false;
        }
    }
    
    // Check required flags
    if (requiredFlags != IOCFlags::None) {
        if (!HasFlag(entry.flags, requiredFlags)) {
            return false;
        }
    }
    
    // Check excluded flags
    if (excludedFlags != IOCFlags::None) {
        if (HasFlag(entry.flags, excludedFlags)) {
            return false;
        }
    }
    
    // Check feed IDs
    if (!feedIds.empty()) {
        bool found = false;
        for (uint32_t fid : feedIds) {
            if (entry.feedId == fid) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    return true;
}

ExportFilter ExportFilter::MaliciousOnly() {
    ExportFilter filter;
    filter.minReputation = ReputationLevel::HighRisk;
    filter.minConfidence = ConfidenceLevel::Medium;
    filter.onlyActive = true;
    return filter;
}

ExportFilter ExportFilter::ByType(IOCType type) {
    ExportFilter filter;
    filter.includeTypes.push_back(type);
    return filter;
}

ExportFilter ExportFilter::BySource(ThreatIntelSource source) {
    ExportFilter filter;
    filter.includeSources.push_back(source);
    return filter;
}

ExportFilter ExportFilter::RecentEntries(uint32_t maxAgeHours) {
    ExportFilter filter;
    
    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    
    filter.createdAfter = now - (static_cast<uint64_t>(maxAgeHours) * 3600);
    return filter;
}

// ============================================================================
// ExportOptions Factory Methods
// ============================================================================

ExportOptions ExportOptions::FastCSV() {
    ExportOptions opts;
    opts.format = ExportFormat::CSV;
    opts.fields = ExportFields::Basic;
    opts.prettyPrint = false;
    opts.includeHeader = true;
    opts.bufferSize = 4 * 1024 * 1024; // 4 MB buffer for speed
    opts.flushInterval = 50000;
    return opts;
}

ExportOptions ExportOptions::STIX21Sharing() {
    ExportOptions opts;
    opts.format = ExportFormat::STIX21;
    opts.fields = ExportFields::Full;
    opts.prettyPrint = true;
    opts.stixIdentityId = "identity--" + GenerateUUID();
    opts.includeStatistics = true;
    return opts;
}

ExportOptions ExportOptions::MISPEvent(const std::string& eventInfo) {
    ExportOptions opts;
    opts.format = ExportFormat::MISP;
    opts.fields = ExportFields::Standard;
    opts.prettyPrint = true;
    opts.mispEventInfo = eventInfo;
    opts.mispEventUuid = GenerateUUID();
    return opts;
}

ExportOptions ExportOptions::CompressedJSON() {
    ExportOptions opts;
    opts.format = ExportFormat::JSON;
    opts.compression = ExportCompression::GZIP;
    opts.fields = ExportFields::Standard;
    opts.prettyPrint = false;
    return opts;
}

// ============================================================================
// Helper: Format IOC Value to String
// ============================================================================

namespace {

/**
 * @brief Format IPv4 address to string
 */
std::string FormatIPv4(const IPv4Address& addr) {
    uint32_t ip = addr.address;
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    
    if (addr.prefixLength < 32) {
        oss << '/' << static_cast<int>(addr.prefixLength);
    }
    
    return oss.str();
}

/**
 * @brief Format IPv6 address to string
 */
std::string FormatIPv6(const IPv6Address& addr) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (int i = 0; i < 8; ++i) {
        if (i > 0) oss << ':';
        uint16_t segment = (static_cast<uint16_t>(addr.address[i * 2]) << 8) |
                           static_cast<uint16_t>(addr.address[i * 2 + 1]);
        oss << std::setw(4) << segment;
    }
    
    if (addr.prefixLength < 128) {
        oss << '/' << std::dec << static_cast<int>(addr.prefixLength);
    }
    
    return oss.str();
}

/**
 * @brief Format hash value to hex string
 */
std::string FormatHash(const HashValue& hash) {
    uint8_t len = GetHashLength(hash.algorithm);
    if (len == 0 || len > hash.data.size()) {
        return "";
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(hash.data[i]);
    }
    
    return oss.str();
}

} // anonymous namespace

std::string ThreatIntelExporter::FormatIOCValue(
    const IOCEntry& entry,
    const IStringPoolReader* stringPool
) {
    switch (entry.type) {
        case IOCType::IPv4:
        case IOCType::CIDRv4:
            return FormatIPv4(entry.value.ipv4);
            
        case IOCType::IPv6:
        case IOCType::CIDRv6:
            return FormatIPv6(entry.value.ipv6);
            
        case IOCType::FileHash:
            return FormatHash(entry.value.hash);
            
        case IOCType::Domain:
        case IOCType::URL:
        case IOCType::Email:
        case IOCType::CertFingerprint:
        case IOCType::JA3:
        case IOCType::JA3S:
        case IOCType::RegistryKey:
        case IOCType::ProcessName:
        case IOCType::MutexName:
        case IOCType::NamedPipe:
        case IOCType::UserAgent:
        case IOCType::YaraRule:
        case IOCType::SigmaRule:
        case IOCType::MitreAttack:
        case IOCType::CVE:
        case IOCType::STIXPattern:
            // String reference - read from string pool
            if (stringPool && stringPool->IsValidOffset(entry.value.stringRef.stringOffset)) {
                auto sv = stringPool->ReadString(
                    entry.value.stringRef.stringOffset,
                    entry.value.stringRef.stringLength
                );
                return std::string(sv);
            }
            return "";
            
        case IOCType::ASN:
            // ASN stored as uint32 in raw bytes
            if (entry.value.raw.size() >= 4) {
                uint32_t asn = *reinterpret_cast<const uint32_t*>(entry.value.raw.data());
                return "AS" + std::to_string(asn);
            }
            return "";
            
        default:
            return "";
    }
}

// ============================================================================
// CSVExportWriter Implementation
// ============================================================================

CSVExportWriter::CSVExportWriter(std::ostream& output)
    : m_output(output) {
    m_buffer.reserve(65536); // 64KB initial buffer
}

CSVExportWriter::~CSVExportWriter() = default;

bool CSVExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    m_buffer.clear();
    
    // Write BOM if requested
    if (options.includeBOM) {
        m_output.write("\xEF\xBB\xBF", 3);
        m_bytesWritten += 3;
    }
    
    // Write header
    if (options.includeHeader) {
        WriteHeader();
    }
    
    return m_output.good();
}

void CSVExportWriter::WriteHeader() {
    m_buffer.clear();
    bool first = true;
    
    auto addField = [&](const char* name) {
        if (!first) m_buffer += m_options.csvDelimiter;
        first = false;
        m_buffer += name;
    };
    
    ExportFields fields = m_options.fields;
    
    if (HasExportField(fields, ExportFields::EntryId)) addField("entry_id");
    if (HasExportField(fields, ExportFields::Type)) addField("type");
    if (HasExportField(fields, ExportFields::Value)) addField("value");
    if (HasExportField(fields, ExportFields::Reputation)) addField("reputation");
    if (HasExportField(fields, ExportFields::Confidence)) addField("confidence");
    if (HasExportField(fields, ExportFields::Category)) addField("category");
    if (HasExportField(fields, ExportFields::Source)) addField("source");
    if (HasExportField(fields, ExportFields::FirstSeen)) addField("first_seen");
    if (HasExportField(fields, ExportFields::LastSeen)) addField("last_seen");
    if (HasExportField(fields, ExportFields::CreatedTime)) addField("created_time");
    if (HasExportField(fields, ExportFields::ExpirationTime)) addField("expiration_time");
    if (HasExportField(fields, ExportFields::Severity)) addField("severity");
    if (HasExportField(fields, ExportFields::HitCount)) addField("hit_count");
    if (HasExportField(fields, ExportFields::Flags)) addField("flags");
    if (HasExportField(fields, ExportFields::Description)) addField("description");
    if (HasExportField(fields, ExportFields::Tags)) addField("tags");
    
    m_buffer += m_options.windowsNewlines ? "\r\n" : "\n";
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
}

void CSVExportWriter::WriteEscapedField(std::string_view field) {
    // Check if escaping is needed
    bool needsQuotes = false;
    for (char c : field) {
        if (c == m_options.csvDelimiter || c == m_options.csvQuote || 
            c == '\n' || c == '\r') {
            needsQuotes = true;
            break;
        }
    }
    
    if (!needsQuotes) {
        m_buffer += field;
        return;
    }
    
    // Escape with quotes
    m_buffer += m_options.csvQuote;
    for (char c : field) {
        if (c == m_options.csvQuote) {
            m_buffer += m_options.csvQuote; // Double the quote
        }
        m_buffer += c;
    }
    m_buffer += m_options.csvQuote;
}

std::string CSVExportWriter::FormatIOCValue(
    const IOCEntry& entry,
    const IStringPoolReader* stringPool
) const {
    return ThreatIntelExporter::FormatIOCValue(entry, stringPool);
}

bool CSVExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    m_buffer.clear();
    bool first = true;
    
    auto addField = [&](std::string_view value) {
        if (!first) m_buffer += m_options.csvDelimiter;
        first = false;
        WriteEscapedField(value);
    };
    
    auto addNumericField = [&](auto value) {
        if (!first) m_buffer += m_options.csvDelimiter;
        first = false;
        m_buffer += std::to_string(value);
    };
    
    ExportFields fields = m_options.fields;
    
    if (HasExportField(fields, ExportFields::EntryId)) {
        addNumericField(entry.entryId);
    }
    
    if (HasExportField(fields, ExportFields::Type)) {
        addField(IOCTypeToString(entry.type));
    }
    
    if (HasExportField(fields, ExportFields::Value)) {
        addField(FormatIOCValue(entry, stringPool));
    }
    
    if (HasExportField(fields, ExportFields::Reputation)) {
        addNumericField(static_cast<int>(entry.reputation));
    }
    
    if (HasExportField(fields, ExportFields::Confidence)) {
        addNumericField(static_cast<int>(entry.confidence));
    }
    
    if (HasExportField(fields, ExportFields::Category)) {
        addField(ThreatCategoryToString(entry.category));
    }
    
    if (HasExportField(fields, ExportFields::Source)) {
        addField(ThreatIntelSourceToString(entry.source));
    }
    
    if (HasExportField(fields, ExportFields::FirstSeen)) {
        addField(FormatISO8601Timestamp(entry.firstSeen));
    }
    
    if (HasExportField(fields, ExportFields::LastSeen)) {
        addField(FormatISO8601Timestamp(entry.lastSeen));
    }
    
    if (HasExportField(fields, ExportFields::CreatedTime)) {
        addField(FormatISO8601Timestamp(entry.createdTime));
    }
    
    if (HasExportField(fields, ExportFields::ExpirationTime)) {
        if (entry.expirationTime > 0) {
            addField(FormatISO8601Timestamp(entry.expirationTime));
        } else {
            addField("");
        }
    }
    
    if (HasExportField(fields, ExportFields::Severity)) {
        addNumericField(static_cast<int>(entry.severity));
    }
    
    if (HasExportField(fields, ExportFields::HitCount)) {
        addNumericField(entry.hitCount.load(std::memory_order_relaxed));
    }
    
    if (HasExportField(fields, ExportFields::Flags)) {
        addNumericField(static_cast<uint32_t>(entry.flags));
    }
    
    if (HasExportField(fields, ExportFields::Description)) {
        if (stringPool && entry.descriptionLength > 0) {
            auto desc = stringPool->ReadString(entry.descriptionOffset, entry.descriptionLength);
            addField(desc);
        } else {
            addField("");
        }
    }
    
    if (HasExportField(fields, ExportFields::Tags)) {
        // Tags would need to be read from string pool - simplified here
        addField("");
    }
    
    m_buffer += m_options.windowsNewlines ? "\r\n" : "\n";
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
    
    return m_output.good();
}

bool CSVExportWriter::End() {
    Flush();
    return m_output.good();
}

void CSVExportWriter::Flush() {
    m_output.flush();
}

uint64_t CSVExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string CSVExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// JSONExportWriter Implementation
// ============================================================================

JSONExportWriter::JSONExportWriter(std::ostream& output)
    : m_output(output) {
    m_buffer.reserve(65536);
}

JSONExportWriter::~JSONExportWriter() = default;

bool JSONExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    m_entryCount = 0;
    m_buffer.clear();
    m_isJsonLines = (options.format == ExportFormat::JSONL);
    
    // Write BOM if requested
    if (options.includeBOM) {
        m_output.write("\xEF\xBB\xBF", 3);
        m_bytesWritten += 3;
    }
    
    if (!m_isJsonLines) {
        // Start JSON object/array
        if (options.prettyPrint) {
            m_output << "{\n  \"entries\": [\n";
        } else {
            m_output << "{\"entries\":[";
        }
        m_bytesWritten += m_options.prettyPrint ? 18 : 12;
    }
    
    return m_output.good();
}

void JSONExportWriter::WriteIndent(int level) {
    if (!m_options.prettyPrint) return;
    for (int i = 0; i < level; ++i) {
        m_buffer += "  ";
    }
}

void JSONExportWriter::WriteEscapedString(std::string_view str) {
    m_buffer += '"';
    for (char c : str) {
        switch (c) {
            case '"':  m_buffer += "\\\""; break;
            case '\\': m_buffer += "\\\\"; break;
            case '\b': m_buffer += "\\b"; break;
            case '\f': m_buffer += "\\f"; break;
            case '\n': m_buffer += "\\n"; break;
            case '\r': m_buffer += "\\r"; break;
            case '\t': m_buffer += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // Control character - encode as \u00XX
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    m_buffer += buf;
                } else {
                    m_buffer += c;
                }
                break;
        }
    }
    m_buffer += '"';
}

void JSONExportWriter::WriteEntryJSON(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    m_buffer.clear();
    
    int baseIndent = m_isJsonLines ? 0 : 2;
    bool pp = m_options.prettyPrint;
    ExportFields fields = m_options.fields;
    
    WriteIndent(baseIndent);
    m_buffer += '{';
    if (pp) m_buffer += '\n';
    
    bool firstField = true;
    
    auto writeField = [&](const char* name, auto writeValue) {
        if (!firstField) {
            m_buffer += ',';
            if (pp) m_buffer += '\n';
        }
        firstField = false;
        WriteIndent(baseIndent + 1);
        m_buffer += '"';
        m_buffer += name;
        m_buffer += "\":";
        if (pp) m_buffer += ' ';
        writeValue();
    };
    
    if (HasExportField(fields, ExportFields::EntryId)) {
        writeField("entry_id", [&]() {
            m_buffer += std::to_string(entry.entryId);
        });
    }
    
    if (HasExportField(fields, ExportFields::Type)) {
        writeField("type", [&]() {
            WriteEscapedString(IOCTypeToString(entry.type));
        });
    }
    
    if (HasExportField(fields, ExportFields::Value)) {
        writeField("value", [&]() {
            WriteEscapedString(ThreatIntelExporter::FormatIOCValue(entry, stringPool));
        });
    }
    
    if (HasExportField(fields, ExportFields::Reputation)) {
        writeField("reputation", [&]() {
            m_buffer += std::to_string(static_cast<int>(entry.reputation));
        });
    }
    
    if (HasExportField(fields, ExportFields::Confidence)) {
        writeField("confidence", [&]() {
            m_buffer += std::to_string(static_cast<int>(entry.confidence));
        });
    }
    
    if (HasExportField(fields, ExportFields::Category)) {
        writeField("category", [&]() {
            WriteEscapedString(ThreatCategoryToString(entry.category));
        });
    }
    
    if (HasExportField(fields, ExportFields::Source)) {
        writeField("source", [&]() {
            WriteEscapedString(ThreatIntelSourceToString(entry.source));
        });
    }
    
    if (HasExportField(fields, ExportFields::FirstSeen)) {
        writeField("first_seen", [&]() {
            WriteEscapedString(FormatISO8601Timestamp(entry.firstSeen));
        });
    }
    
    if (HasExportField(fields, ExportFields::LastSeen)) {
        writeField("last_seen", [&]() {
            WriteEscapedString(FormatISO8601Timestamp(entry.lastSeen));
        });
    }
    
    if (HasExportField(fields, ExportFields::CreatedTime)) {
        writeField("created_time", [&]() {
            WriteEscapedString(FormatISO8601Timestamp(entry.createdTime));
        });
    }
    
    if (HasExportField(fields, ExportFields::ExpirationTime)) {
        writeField("expiration_time", [&]() {
            if (entry.expirationTime > 0) {
                WriteEscapedString(FormatISO8601Timestamp(entry.expirationTime));
            } else {
                m_buffer += "null";
            }
        });
    }
    
    if (HasExportField(fields, ExportFields::Severity)) {
        writeField("severity", [&]() {
            m_buffer += std::to_string(static_cast<int>(entry.severity));
        });
    }
    
    if (HasExportField(fields, ExportFields::HitCount)) {
        writeField("hit_count", [&]() {
            m_buffer += std::to_string(entry.hitCount.load(std::memory_order_relaxed));
        });
    }
    
    if (HasExportField(fields, ExportFields::Flags)) {
        writeField("flags", [&]() {
            m_buffer += std::to_string(static_cast<uint32_t>(entry.flags));
        });
    }
    
    if (HasExportField(fields, ExportFields::VTData)) {
        writeField("virustotal", [&]() {
            m_buffer += '{';
            if (pp) m_buffer += '\n';
            WriteIndent(baseIndent + 2);
            m_buffer += "\"positives\":";
            if (pp) m_buffer += ' ';
            m_buffer += std::to_string(entry.vtPositives);
            m_buffer += ',';
            if (pp) m_buffer += '\n';
            WriteIndent(baseIndent + 2);
            m_buffer += "\"total\":";
            if (pp) m_buffer += ' ';
            m_buffer += std::to_string(entry.vtTotal);
            if (pp) m_buffer += '\n';
            WriteIndent(baseIndent + 1);
            m_buffer += '}';
        });
    }
    
    if (HasExportField(fields, ExportFields::AbuseIPDBData)) {
        writeField("abuseipdb_score", [&]() {
            m_buffer += std::to_string(entry.abuseIPDBScore);
        });
    }
    
    if (pp) m_buffer += '\n';
    WriteIndent(baseIndent);
    m_buffer += '}';
}

bool JSONExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    // Add comma before entry (except first)
    if (m_entryCount > 0 && !m_isJsonLines) {
        m_output << ',';
        if (m_options.prettyPrint) m_output << '\n';
        m_bytesWritten += m_options.prettyPrint ? 2 : 1;
    }
    
    WriteEntryJSON(entry, stringPool);
    
    if (m_isJsonLines) {
        m_buffer += '\n';
    }
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
    m_entryCount++;
    
    return m_output.good();
}

bool JSONExportWriter::End() {
    if (!m_isJsonLines) {
        if (m_options.prettyPrint) {
            m_output << "\n  ]\n}";
            m_bytesWritten += 6;
        } else {
            m_output << "]}";
            m_bytesWritten += 2;
        }
    }
    
    Flush();
    return m_output.good();
}

void JSONExportWriter::Flush() {
    m_output.flush();
}

uint64_t JSONExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string JSONExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// STIX21ExportWriter Implementation
// ============================================================================

STIX21ExportWriter::STIX21ExportWriter(std::ostream& output)
    : m_output(output) {
    m_buffer.reserve(65536);
}

STIX21ExportWriter::~STIX21ExportWriter() = default;

bool STIX21ExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    m_objectCount = 0;
    m_buffer.clear();
    
    // Generate bundle ID if not provided
    m_bundleId = options.stixBundleId.empty() 
        ? "bundle--" + GenerateUUID() 
        : options.stixBundleId;
    
    // Write STIX bundle header
    bool pp = options.prettyPrint;
    
    m_output << "{";
    if (pp) m_output << "\n  ";
    m_output << "\"type\":\"bundle\",";
    if (pp) m_output << "\n  ";
    m_output << "\"id\":\"" << m_bundleId << "\",";
    if (pp) m_output << "\n  ";
    m_output << "\"objects\":[";
    if (pp) m_output << "\n";
    
    m_bytesWritten = static_cast<uint64_t>(m_output.tellp());
    
    return m_output.good();
}

std::string STIX21ExportWriter::GenerateSTIXId(const IOCEntry& entry) const {
    std::string typePrefix = MapIOCTypeToSTIXType(entry.type);
    return typePrefix + "--" + GenerateUUID();
}

std::string STIX21ExportWriter::MapIOCTypeToSTIXType(IOCType type) const {
    switch (type) {
        case IOCType::IPv4:
        case IOCType::IPv6:
        case IOCType::CIDRv4:
        case IOCType::CIDRv6:
        case IOCType::Domain:
        case IOCType::URL:
        case IOCType::Email:
        case IOCType::FileHash:
            return "indicator";
        case IOCType::MitreAttack:
            return "attack-pattern";
        case IOCType::CVE:
            return "vulnerability";
        default:
            return "indicator";
    }
}

void STIX21ExportWriter::WriteSTIXPattern(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    std::string value = ThreatIntelExporter::FormatIOCValue(entry, stringPool);
    
    m_buffer += "\"pattern\":\"";
    
    switch (entry.type) {
        case IOCType::IPv4:
        case IOCType::CIDRv4:
            m_buffer += "[ipv4-addr:value = '";
            m_buffer += value;
            m_buffer += "']";
            break;
            
        case IOCType::IPv6:
        case IOCType::CIDRv6:
            m_buffer += "[ipv6-addr:value = '";
            m_buffer += value;
            m_buffer += "']";
            break;
            
        case IOCType::Domain:
            m_buffer += "[domain-name:value = '";
            m_buffer += value;
            m_buffer += "']";
            break;
            
        case IOCType::URL:
            m_buffer += "[url:value = '";
            // Escape single quotes in URL
            for (char c : value) {
                if (c == '\'') m_buffer += "\\'";
                else m_buffer += c;
            }
            m_buffer += "']";
            break;
            
        case IOCType::Email:
            m_buffer += "[email-addr:value = '";
            m_buffer += value;
            m_buffer += "']";
            break;
            
        case IOCType::FileHash:
            m_buffer += "[file:hashes.'";
            m_buffer += HashAlgorithmToString(entry.value.hash.algorithm);
            m_buffer += "' = '";
            m_buffer += value;
            m_buffer += "']";
            break;
            
        default:
            m_buffer += "[x-shadowstrike:value = '";
            m_buffer += value;
            m_buffer += "']";
            break;
    }
    
    m_buffer += "\"";
}

void STIX21ExportWriter::WriteIndicatorObject(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    m_buffer.clear();
    bool pp = m_options.prettyPrint;
    int indent = pp ? 4 : 0;
    
    auto writeIndent = [&]() {
        if (pp) {
            for (int i = 0; i < indent; ++i) m_buffer += ' ';
        }
    };
    
    auto nl = [&]() {
        if (pp) m_buffer += '\n';
    };
    
    writeIndent();
    m_buffer += "{";
    nl();
    
    indent += 2;
    
    // Type
    writeIndent();
    m_buffer += "\"type\":\"indicator\",";
    nl();
    
    // Spec version
    writeIndent();
    m_buffer += "\"spec_version\":\"2.1\",";
    nl();
    
    // ID
    writeIndent();
    m_buffer += "\"id\":\"";
    m_buffer += GenerateSTIXId(entry);
    m_buffer += "\",";
    nl();
    
    // Created
    writeIndent();
    m_buffer += "\"created\":\"";
    m_buffer += FormatISO8601Timestamp(entry.createdTime);
    m_buffer += "\",";
    nl();
    
    // Modified
    writeIndent();
    m_buffer += "\"modified\":\"";
    m_buffer += FormatISO8601Timestamp(entry.lastSeen > 0 ? entry.lastSeen : entry.createdTime);
    m_buffer += "\",";
    nl();
    
    // Name
    writeIndent();
    m_buffer += "\"name\":\"";
    m_buffer += IOCTypeToString(entry.type);
    m_buffer += " indicator\",";
    nl();
    
    // Pattern
    writeIndent();
    WriteSTIXPattern(entry, stringPool);
    m_buffer += ",";
    nl();
    
    // Pattern type
    writeIndent();
    m_buffer += "\"pattern_type\":\"stix\",";
    nl();
    
    // Valid from
    writeIndent();
    m_buffer += "\"valid_from\":\"";
    m_buffer += FormatISO8601Timestamp(entry.firstSeen > 0 ? entry.firstSeen : entry.createdTime);
    m_buffer += "\"";
    
    // Valid until (if has expiration)
    if (entry.expirationTime > 0) {
        m_buffer += ",";
        nl();
        writeIndent();
        m_buffer += "\"valid_until\":\"";
        m_buffer += FormatISO8601Timestamp(entry.expirationTime);
        m_buffer += "\"";
    }
    
    // Confidence (scaled 0-100)
    m_buffer += ",";
    nl();
    writeIndent();
    m_buffer += "\"confidence\":";
    m_buffer += std::to_string(static_cast<int>(entry.confidence));
    
    // Labels based on category
    m_buffer += ",";
    nl();
    writeIndent();
    m_buffer += "\"labels\":[\"";
    m_buffer += ThreatCategoryToString(entry.category);
    m_buffer += "\"]";
    
    // External references
    m_buffer += ",";
    nl();
    writeIndent();
    m_buffer += "\"external_references\":[{";
    if (pp) {
        nl();
        writeIndent();
        m_buffer += "  ";
    }
    m_buffer += "\"source_name\":\"";
    m_buffer += ThreatIntelSourceToString(entry.source);
    m_buffer += "\"";
    if (pp) {
        nl();
        writeIndent();
    }
    m_buffer += "}]";
    
    nl();
    indent -= 2;
    writeIndent();
    m_buffer += "}";
}

bool STIX21ExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    // Add comma before entry (except first)
    if (m_objectCount > 0) {
        m_output << ',';
        if (m_options.prettyPrint) m_output << '\n';
    }
    
    WriteIndicatorObject(entry, stringPool);
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
    m_objectCount++;
    
    return m_output.good();
}

bool STIX21ExportWriter::End() {
    if (m_options.prettyPrint) {
        m_output << "\n  ]\n}";
    } else {
        m_output << "]}";
    }
    
    Flush();
    return m_output.good();
}

void STIX21ExportWriter::Flush() {
    m_output.flush();
}

uint64_t STIX21ExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string STIX21ExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// MISPExportWriter Implementation
// ============================================================================

MISPExportWriter::MISPExportWriter(std::ostream& output)
    : m_output(output) {
    m_buffer.reserve(65536);
}

MISPExportWriter::~MISPExportWriter() = default;

bool MISPExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    m_attributeCount = 0;
    m_buffer.clear();
    
    m_eventUuid = options.mispEventUuid.empty() 
        ? GenerateUUID() 
        : options.mispEventUuid;
    
    bool pp = options.prettyPrint;
    
    // Write MISP event header
    m_output << "{";
    if (pp) m_output << "\n  ";
    m_output << "\"Event\":{";
    if (pp) m_output << "\n    ";
    m_output << "\"uuid\":\"" << m_eventUuid << "\",";
    if (pp) m_output << "\n    ";
    m_output << "\"info\":\"" << options.mispEventInfo << "\",";
    if (pp) m_output << "\n    ";
    m_output << "\"threat_level_id\":\"2\",";
    if (pp) m_output << "\n    ";
    m_output << "\"analysis\":\"2\",";
    if (pp) m_output << "\n    ";
    m_output << "\"date\":\"" << FormatISO8601Timestamp(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    ).substr(0, 10) << "\",";
    if (pp) m_output << "\n    ";
    m_output << "\"Attribute\":[";
    if (pp) m_output << "\n";
    
    m_bytesWritten = static_cast<uint64_t>(m_output.tellp());
    
    return m_output.good();
}

std::string MISPExportWriter::MapIOCTypeToMISPType(IOCType type) const {
    switch (type) {
        case IOCType::IPv4:
        case IOCType::CIDRv4:     return "ip-dst";
        case IOCType::IPv6:
        case IOCType::CIDRv6:     return "ip-dst";
        case IOCType::Domain:     return "domain";
        case IOCType::URL:        return "url";
        case IOCType::Email:      return "email-src";
        case IOCType::FileHash:   return "sha256"; // Will be adjusted based on algorithm
        case IOCType::CertFingerprint: return "x509-fingerprint-sha256";
        case IOCType::JA3:        return "ja3-fingerprint-md5";
        case IOCType::JA3S:       return "ja3-fingerprint-md5";
        case IOCType::RegistryKey: return "regkey";
        case IOCType::ProcessName: return "filename";
        case IOCType::MutexName:  return "mutex";
        case IOCType::UserAgent:  return "user-agent";
        case IOCType::CVE:        return "vulnerability";
        default:                  return "text";
    }
}

std::string MISPExportWriter::MapIOCTypeToMISPCategory(IOCType type) const {
    switch (type) {
        case IOCType::IPv4:
        case IOCType::IPv6:
        case IOCType::CIDRv4:
        case IOCType::CIDRv6:
        case IOCType::Domain:
        case IOCType::URL:        return "Network activity";
        case IOCType::Email:      return "Payload delivery";
        case IOCType::FileHash:   return "Payload delivery";
        case IOCType::CertFingerprint:
        case IOCType::JA3:
        case IOCType::JA3S:       return "Network activity";
        case IOCType::RegistryKey:
        case IOCType::ProcessName:
        case IOCType::MutexName:  return "Artifacts dropped";
        case IOCType::CVE:        return "External analysis";
        default:                  return "Other";
    }
}

void MISPExportWriter::WriteAttribute(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    m_buffer.clear();
    bool pp = m_options.prettyPrint;
    
    std::string value = ThreatIntelExporter::FormatIOCValue(entry, stringPool);
    std::string type = MapIOCTypeToMISPType(entry.type);
    std::string category = MapIOCTypeToMISPCategory(entry.type);
    
    // Adjust hash type based on algorithm
    if (entry.type == IOCType::FileHash) {
        switch (entry.value.hash.algorithm) {
            case HashAlgorithm::MD5:    type = "md5"; break;
            case HashAlgorithm::SHA1:   type = "sha1"; break;
            case HashAlgorithm::SHA256: type = "sha256"; break;
            case HashAlgorithm::SHA512: type = "sha512"; break;
            default: break;
        }
    }
    
    if (pp) m_buffer += "      ";
    m_buffer += "{";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"uuid\":\"";
    m_buffer += GenerateUUID();
    m_buffer += "\",";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"type\":\"";
    m_buffer += type;
    m_buffer += "\",";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"category\":\"";
    m_buffer += category;
    m_buffer += "\",";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"value\":\"";
    // Escape JSON string
    for (char c : value) {
        switch (c) {
            case '"':  m_buffer += "\\\""; break;
            case '\\': m_buffer += "\\\\"; break;
            case '\n': m_buffer += "\\n"; break;
            case '\r': m_buffer += "\\r"; break;
            case '\t': m_buffer += "\\t"; break;
            default: m_buffer += c; break;
        }
    }
    m_buffer += "\",";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"to_ids\":";
    m_buffer += (static_cast<int>(entry.reputation) >= 50) ? "true" : "false";
    m_buffer += ",";
    if (pp) m_buffer += "\n        ";
    
    m_buffer += "\"timestamp\":\"";
    m_buffer += std::to_string(entry.createdTime);
    m_buffer += "\"";
    if (pp) m_buffer += "\n      ";
    
    m_buffer += "}";
}

bool MISPExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    if (m_attributeCount > 0) {
        m_output << ',';
        if (m_options.prettyPrint) m_output << '\n';
    }
    
    WriteAttribute(entry, stringPool);
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
    m_attributeCount++;
    
    return m_output.good();
}

bool MISPExportWriter::End() {
    if (m_options.prettyPrint) {
        m_output << "\n    ]\n  }\n}";
    } else {
        m_output << "]}}";
    }
    
    Flush();
    return m_output.good();
}

void MISPExportWriter::Flush() {
    m_output.flush();
}

uint64_t MISPExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string MISPExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// OpenIOCExportWriter Implementation
// ============================================================================

OpenIOCExportWriter::OpenIOCExportWriter(std::ostream& output)
    : m_output(output) {
    m_buffer.reserve(65536);
}

OpenIOCExportWriter::~OpenIOCExportWriter() = default;

bool OpenIOCExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    m_buffer.clear();
    
    // Write XML header and OpenIOC root
    m_output << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    m_output << "<ioc xmlns=\"http://schemas.mandiant.com/2010/ioc\" "
             << "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
             << "id=\"" << GenerateUUID() << "\" "
             << "last-modified=\"" << FormatISO8601Timestamp(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count()
                ) << "\">\n";
    m_output << "  <short_description>ShadowStrike Threat Intelligence Export</short_description>\n";
    m_output << "  <authored_by>" << options.openIocAuthor << "</authored_by>\n";
    m_output << "  <authored_date>" << FormatISO8601Timestamp(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count()
                ) << "</authored_date>\n";
    m_output << "  <definition>\n";
    m_output << "    <Indicator operator=\"OR\" id=\"" << GenerateUUID() << "\">\n";
    
    m_bytesWritten = static_cast<uint64_t>(m_output.tellp());
    
    return m_output.good();
}

void OpenIOCExportWriter::WriteXMLEscaped(std::string_view str) {
    for (char c : str) {
        switch (c) {
            case '&':  m_buffer += "&amp;"; break;
            case '<':  m_buffer += "&lt;"; break;
            case '>':  m_buffer += "&gt;"; break;
            case '"':  m_buffer += "&quot;"; break;
            case '\'': m_buffer += "&apos;"; break;
            default:   m_buffer += c; break;
        }
    }
}

std::string OpenIOCExportWriter::MapIOCTypeToOpenIOCSearch(IOCType type) const {
    switch (type) {
        case IOCType::IPv4:
        case IOCType::IPv6:
        case IOCType::CIDRv4:
        case IOCType::CIDRv6:     return "Network/DNS";
        case IOCType::Domain:     return "Network/DNS";
        case IOCType::URL:        return "Network/URI";
        case IOCType::Email:      return "Email/From";
        case IOCType::FileHash:   return "FileItem/Md5sum"; // Adjusted by algorithm
        case IOCType::RegistryKey: return "RegistryItem/Path";
        case IOCType::ProcessName: return "ProcessItem/name";
        case IOCType::MutexName:  return "SystemInfoItem/Mutex";
        default:                  return "Custom/String";
    }
}

void OpenIOCExportWriter::WriteIndicatorItem(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    m_buffer.clear();
    
    std::string value = ThreatIntelExporter::FormatIOCValue(entry, stringPool);
    std::string search = MapIOCTypeToOpenIOCSearch(entry.type);
    
    // Adjust search term for hash type
    if (entry.type == IOCType::FileHash) {
        switch (entry.value.hash.algorithm) {
            case HashAlgorithm::MD5:    search = "FileItem/Md5sum"; break;
            case HashAlgorithm::SHA1:   search = "FileItem/Sha1sum"; break;
            case HashAlgorithm::SHA256: search = "FileItem/Sha256sum"; break;
            default: break;
        }
    }
    
    m_buffer += "      <IndicatorItem id=\"";
    m_buffer += GenerateUUID();
    m_buffer += "\" condition=\"is\">\n";
    m_buffer += "        <Context document=\"";
    
    // Extract document from search path
    size_t slashPos = search.find('/');
    if (slashPos != std::string::npos) {
        m_buffer += search.substr(0, slashPos);
        m_buffer += "\" search=\"";
        m_buffer += search;
    } else {
        m_buffer += "Custom\" search=\"";
        m_buffer += search;
    }
    
    m_buffer += "\" type=\"mir\"/>\n";
    m_buffer += "        <Content type=\"string\">";
    WriteXMLEscaped(value);
    m_buffer += "</Content>\n";
    m_buffer += "      </IndicatorItem>\n";
}

bool OpenIOCExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    WriteIndicatorItem(entry, stringPool);
    
    m_output.write(m_buffer.data(), static_cast<std::streamsize>(m_buffer.size()));
    m_bytesWritten += m_buffer.size();
    
    return m_output.good();
}

bool OpenIOCExportWriter::End() {
    m_output << "    </Indicator>\n";
    m_output << "  </definition>\n";
    m_output << "</ioc>\n";
    
    Flush();
    return m_output.good();
}

void OpenIOCExportWriter::Flush() {
    m_output.flush();
}

uint64_t OpenIOCExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string OpenIOCExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// PlainTextExportWriter Implementation
// ============================================================================

PlainTextExportWriter::PlainTextExportWriter(std::ostream& output)
    : m_output(output) {
}

PlainTextExportWriter::~PlainTextExportWriter() = default;

bool PlainTextExportWriter::Begin(const ExportOptions& options) {
    m_options = options;
    m_bytesWritten = 0;
    
    if (options.includeBOM) {
        m_output.write("\xEF\xBB\xBF", 3);
        m_bytesWritten += 3;
    }
    
    return m_output.good();
}

std::string PlainTextExportWriter::FormatIOCValue(
    const IOCEntry& entry,
    const IStringPoolReader* stringPool
) const {
    return ThreatIntelExporter::FormatIOCValue(entry, stringPool);
}

bool PlainTextExportWriter::WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) {
    std::string value = FormatIOCValue(entry, stringPool);
    
    m_output << value;
    if (m_options.windowsNewlines) {
        m_output << "\r\n";
        m_bytesWritten += value.size() + 2;
    } else {
        m_output << '\n';
        m_bytesWritten += value.size() + 1;
    }
    
    return m_output.good();
}

bool PlainTextExportWriter::End() {
    Flush();
    return m_output.good();
}

void PlainTextExportWriter::Flush() {
    m_output.flush();
}

uint64_t PlainTextExportWriter::GetBytesWritten() const noexcept {
    return m_bytesWritten;
}

std::string PlainTextExportWriter::GetLastError() const {
    return m_lastError;
}

// ============================================================================
// ThreatIntelExporter Implementation
// ============================================================================

ThreatIntelExporter::ThreatIntelExporter() = default;
ThreatIntelExporter::~ThreatIntelExporter() = default;

ThreatIntelExporter::ThreatIntelExporter(ThreatIntelExporter&&) noexcept = default;
ThreatIntelExporter& ThreatIntelExporter::operator=(ThreatIntelExporter&&) noexcept = default;

std::unique_ptr<IExportWriter> ThreatIntelExporter::CreateWriter(
    std::ostream& output,
    ExportFormat format
) {
    switch (format) {
        case ExportFormat::CSV:
            return std::make_unique<CSVExportWriter>(output);
        case ExportFormat::JSON:
        case ExportFormat::JSONL:
            return std::make_unique<JSONExportWriter>(output);
        case ExportFormat::STIX21:
        case ExportFormat::TAXII21:
            return std::make_unique<STIX21ExportWriter>(output);
        case ExportFormat::MISP:
            return std::make_unique<MISPExportWriter>(output);
        case ExportFormat::OpenIOC:
            return std::make_unique<OpenIOCExportWriter>(output);
        case ExportFormat::PlainText:
            return std::make_unique<PlainTextExportWriter>(output);
        default:
            return std::make_unique<JSONExportWriter>(output);
    }
}

void ThreatIntelExporter::UpdateProgress(
    ExportProgress& progress,
    size_t currentEntry,
    size_t totalEntries,
    uint64_t bytesWritten,
    const std::chrono::steady_clock::time_point& startTime
) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime);
    
    progress.exportedEntries = currentEntry;
    progress.bytesWritten = bytesWritten;
    progress.elapsedMs = static_cast<uint64_t>(elapsed.count());
    
    if (elapsed.count() > 0) {
        progress.entriesPerSecond = static_cast<double>(currentEntry) * 1000.0 / elapsed.count();
        progress.bytesPerSecond = static_cast<double>(bytesWritten) * 1000.0 / elapsed.count();
    }
    
    if (totalEntries > 0) {
        progress.percentComplete = static_cast<double>(currentEntry) * 100.0 / totalEntries;
        
        if (progress.entriesPerSecond > 0) {
            size_t remaining = totalEntries - currentEntry;
            progress.estimatedRemainingMs = static_cast<uint64_t>(
                remaining * 1000.0 / progress.entriesPerSecond
            );
        }
    }
}

ExportResult ThreatIntelExporter::DoExport(
    std::span<const IOCEntry> entries,
    const IStringPoolReader* stringPool,
    IExportWriter& writer,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    ExportResult result;
    result.format = options.format;
    result.compression = options.compression;
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Initialize writer
    if (!writer.Begin(options)) {
        result.success = false;
        result.errorMessage = writer.GetLastError();
        return result;
    }
    
    ExportProgress progress;
    progress.totalEntries = entries.size();
    progress.currentPhase = "Exporting entries";
    
    size_t exportedCount = 0;
    size_t skippedCount = 0;
    size_t processedCount = 0;
    
    // Apply start index from filter
    size_t startIdx = options.filter.startIndex;
    size_t maxEntries = options.filter.maxEntries > 0 
        ? options.filter.maxEntries 
        : SIZE_MAX;
    
    for (size_t i = startIdx; i < entries.size() && exportedCount < maxEntries; ++i) {
        // Check cancellation
        if (m_cancellationRequested.load(std::memory_order_relaxed)) {
            result.wasCancelled = true;
            break;
        }
        
        const IOCEntry& entry = entries[i];
        
        // Apply filter
        if (!options.filter.Matches(entry)) {
            skippedCount++;
            continue;
        }
        
        // Write entry
        if (!writer.WriteEntry(entry, stringPool)) {
            result.success = false;
            result.errorMessage = writer.GetLastError();
            break;
        }
        
        exportedCount++;
        processedCount++;
        
        // Progress callback
        if (progressCallback && (processedCount % 1000 == 0)) {
            UpdateProgress(progress, exportedCount, entries.size() - startIdx,
                          writer.GetBytesWritten(), startTime);
            progress.skippedEntries = skippedCount;
            
            if (!progressCallback(progress)) {
                result.wasCancelled = true;
                break;
            }
        }
        
        // Periodic flush
        if (exportedCount % options.flushInterval == 0) {
            writer.Flush();
        }
    }
    
    // Finalize writer
    if (!result.wasCancelled && result.errorMessage.empty()) {
        if (!writer.End()) {
            result.success = false;
            result.errorMessage = writer.GetLastError();
        } else {
            result.success = true;
        }
    }
    
    // Calculate final statistics
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    result.totalExported = exportedCount;
    result.totalSkipped = skippedCount;
    result.bytesWritten = writer.GetBytesWritten();
    result.durationMs = static_cast<uint64_t>(duration.count());
    
    if (duration.count() > 0) {
        result.entriesPerSecond = static_cast<double>(exportedCount) * 1000.0 / duration.count();
    }
    
    // Update global statistics
    m_totalEntriesExported.fetch_add(exportedCount, std::memory_order_relaxed);
    m_totalBytesWritten.fetch_add(result.bytesWritten, std::memory_order_relaxed);
    m_totalExportCount.fetch_add(1, std::memory_order_relaxed);
    
    // Final progress callback
    if (progressCallback) {
        progress.isComplete = true;
        progress.exportedEntries = exportedCount;
        progress.skippedEntries = skippedCount;
        progress.bytesWritten = result.bytesWritten;
        progress.percentComplete = 100.0;
        progressCallback(progress);
    }
    
    return result;
}

ExportResult ThreatIntelExporter::ExportToFile(
    const ThreatIntelDatabase& database,
    const std::wstring& outputPath,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    // Get entries from database
    const IOCEntry* entries = database.GetEntries();
    size_t entryCount = database.GetEntryCount();
    
    if (!entries || entryCount == 0) {
        ExportResult result;
        result.success = true;
        result.totalExported = 0;
        result.outputPath = outputPath;
        return result;
    }
    
    return ExportToFile(
        std::span<const IOCEntry>(entries, entryCount),
        nullptr, // No string pool access in this simplified version
        outputPath,
        options,
        progressCallback
    );
}

ExportResult ThreatIntelExporter::ExportToFile(
    std::span<const IOCEntry> entries,
    const IStringPoolReader* stringPool,
    const std::wstring& outputPath,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    ExportResult result;
    result.outputPath = outputPath;
    result.format = options.format;
    result.compression = options.compression;
    
    // Create output directory if needed
    try {
        std::filesystem::path path(outputPath);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = "Failed to create directory: ";
        result.errorMessage += e.what();
        return result;
    }
    
    // Open file
    std::ios_base::openmode mode = std::ios::out | std::ios::binary;
    if (options.appendMode) {
        mode |= std::ios::app;
    } else {
        mode |= std::ios::trunc;
    }
    
    std::ofstream file(outputPath, mode);
    if (!file.is_open()) {
        result.success = false;
        result.errorMessage = "Failed to open output file";
        return result;
    }
    
    // Export to stream
    result = ExportToStream(entries, stringPool, file, options, progressCallback);
    result.outputPath = outputPath;
    
    file.close();
    
    // Calculate file hash if successful
    if (result.success && !result.wasCancelled) {
        result.outputHash = CalculateFileSHA256(outputPath);
    }
    
    return result;
}

ExportResult ThreatIntelExporter::ExportToStream(
    const ThreatIntelDatabase& database,
    std::ostream& output,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    const IOCEntry* entries = database.GetEntries();
    size_t entryCount = database.GetEntryCount();
    
    if (!entries || entryCount == 0) {
        ExportResult result;
        result.success = true;
        result.totalExported = 0;
        return result;
    }
    
    return ExportToStream(
        std::span<const IOCEntry>(entries, entryCount),
        nullptr,
        output,
        options,
        progressCallback
    );
}

ExportResult ThreatIntelExporter::ExportToStream(
    std::span<const IOCEntry> entries,
    const IStringPoolReader* stringPool,
    std::ostream& output,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    auto writer = CreateWriter(output, options.format);
    if (!writer) {
        ExportResult result;
        result.success = false;
        result.errorMessage = "Failed to create writer for format";
        return result;
    }
    
    return DoExport(entries, stringPool, *writer, options, progressCallback);
}

ExportResult ThreatIntelExporter::ExportToString(
    const ThreatIntelDatabase& database,
    std::string& output,
    const ExportOptions& options
) {
    std::ostringstream oss;
    ExportResult result = ExportToStream(database, oss, options, nullptr);
    
    if (result.success) {
        output = oss.str();
    }
    
    return result;
}

ExportResult ThreatIntelExporter::ExportToString(
    std::span<const IOCEntry> entries,
    const IStringPoolReader* stringPool,
    std::string& output,
    const ExportOptions& options
) {
    std::ostringstream oss;
    ExportResult result = ExportToStream(entries, stringPool, oss, options, nullptr);
    
    if (result.success) {
        output = oss.str();
    }
    
    return result;
}

ExportResult ThreatIntelExporter::ExportToBytes(
    const ThreatIntelDatabase& database,
    std::vector<uint8_t>& output,
    const ExportOptions& options
) {
    std::string str;
    ExportResult result = ExportToString(database, str, options);
    
    if (result.success) {
        output.assign(str.begin(), str.end());
    }
    
    return result;
}

std::string ThreatIntelExporter::ExportEntry(
    const IOCEntry& entry,
    const IStringPoolReader* stringPool,
    ExportFormat format,
    ExportFields fields
) {
    ExportOptions options;
    options.format = format;
    options.fields = fields;
    options.prettyPrint = true;
    
    std::ostringstream oss;
    auto writer = CreateWriter(oss, format);
    
    if (writer) {
        writer->Begin(options);
        writer->WriteEntry(entry, stringPool);
        writer->End();
    }
    
    return oss.str();
}

std::unordered_map<IOCType, ExportResult> ThreatIntelExporter::ExportByType(
    const ThreatIntelDatabase& database,
    const std::wstring& outputDir,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    std::unordered_map<IOCType, ExportResult> results;
    
    // Get all IOC types present in database
    const IOCEntry* entries = database.GetEntries();
    size_t entryCount = database.GetEntryCount();
    
    if (!entries || entryCount == 0) {
        return results;
    }
    
    // Group entries by type
    std::unordered_map<IOCType, std::vector<const IOCEntry*>> entriesByType;
    
    for (size_t i = 0; i < entryCount; ++i) {
        entriesByType[entries[i].type].push_back(&entries[i]);
    }
    
    // Export each type
    for (const auto& [type, typeEntries] : entriesByType) {
        std::wstring filename = outputDir + L"/" + 
            std::wstring(IOCTypeToString(type), IOCTypeToString(type) + strlen(IOCTypeToString(type))) +
            std::wstring(GetExportFormatExtension(options.format), 
                         GetExportFormatExtension(options.format) + strlen(GetExportFormatExtension(options.format)));
        
        // Create vector from pointers
        std::vector<IOCEntry> entriesVec;
        entriesVec.reserve(typeEntries.size());
        for (const IOCEntry* e : typeEntries) {
            entriesVec.push_back(*e);
        }
        
        results[type] = ExportToFile(
            std::span<const IOCEntry>(entriesVec),
            nullptr,
            filename,
            options,
            progressCallback
        );
    }
    
    return results;
}

ExportResult ThreatIntelExporter::ExportIncremental(
    const ThreatIntelDatabase& database,
    const std::wstring& outputPath,
    uint64_t lastExportTimestamp,
    const ExportOptions& options,
    ExportProgressCallback progressCallback
) {
    // Create filter for incremental export
    ExportOptions incrementalOptions = options;
    incrementalOptions.filter.createdAfter = lastExportTimestamp;
    incrementalOptions.appendMode = true;
    
    return ExportToFile(database, outputPath, incrementalOptions, progressCallback);
}

void ThreatIntelExporter::RequestCancel() noexcept {
    m_cancellationRequested.store(true, std::memory_order_release);
}

bool ThreatIntelExporter::IsCancellationRequested() const noexcept {
    return m_cancellationRequested.load(std::memory_order_acquire);
}

void ThreatIntelExporter::ResetCancellation() noexcept {
    m_cancellationRequested.store(false, std::memory_order_release);
}

uint64_t ThreatIntelExporter::GetTotalEntriesExported() const noexcept {
    return m_totalEntriesExported.load(std::memory_order_relaxed);
}

uint64_t ThreatIntelExporter::GetTotalBytesWritten() const noexcept {
    return m_totalBytesWritten.load(std::memory_order_relaxed);
}

uint32_t ThreatIntelExporter::GetTotalExportCount() const noexcept {
    return m_totalExportCount.load(std::memory_order_relaxed);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
