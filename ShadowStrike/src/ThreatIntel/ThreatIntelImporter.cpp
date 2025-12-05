/**
 * @file ThreatIntelImporter.cpp
 * @brief Implementation of Threat Intelligence Import Module
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#include "ThreatIntelImporter.hpp"
#include "ThreatIntelDatabase.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/Base64Utils.hpp"
#include "../Utils/CompressionUtils.hpp"
#include "../Utils/FileUtils.hpp"

#include "../../external/nlohmann/json.hpp"
#include "../../external/pugixml/pugixml.hpp"

#include <filesystem>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <random>
#include <future>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

    /// @brief Maximum allowed hex string length to prevent DoS
    constexpr size_t MAX_HEX_STRING_LENGTH = 1024 * 1024;  // 1MB
    
    /// @brief Maximum line length for input parsing
    constexpr size_t MAX_LINE_LENGTH = 64 * 1024;  // 64KB
    
    /// @brief Maximum JSON buffer size
    constexpr size_t MAX_JSON_BUFFER_SIZE = 256 * 1024 * 1024;  // 256MB

    /**
     * @brief Safe hex character to value conversion
     * @param c Hex character
     * @return Value 0-15, or -1 if invalid
     */
    [[nodiscard]] constexpr int HexCharToValue(char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    
    /**
     * @brief Parse hex string to bytes safely
     * @param hex Hex string input
     * @param out Output span for bytes
     * @return true if successful
     */
    [[nodiscard]] bool ParseHexString(std::string_view hex, std::span<uint8_t> out) noexcept {
        // Validate input parameters
        if (hex.empty() || out.empty()) {
            return false;
        }
        
        // Check for odd length (invalid hex)
        if ((hex.length() % 2) != 0) {
            return false;
        }
        
        // Prevent DoS via extremely long strings
        if (hex.length() > MAX_HEX_STRING_LENGTH) {
            return false;
        }
        
        // Calculate byte count safely
        const size_t byteCount = hex.length() / 2;
        if (byteCount > out.size()) {
            return false;
        }
        
        for (size_t i = 0; i < byteCount; ++i) {
            const size_t hexIdx = i * 2;
            
            // Bounds check (should always pass due to length validation above)
            if (hexIdx + 1 >= hex.length()) {
                return false;
            }
            
            const int high = HexCharToValue(hex[hexIdx]);
            const int low = HexCharToValue(hex[hexIdx + 1]);
            
            if (high < 0 || low < 0) {
                return false;
            }
            
            out[i] = static_cast<uint8_t>((high << 4) | low);
        }
        return true;
    }
    
    /**
     * @brief Safely parse IPv4 address
     * @param str IPv4 address string
     * @param out Output array for 4 octets (must not be null)
     * @return true if valid IPv4
     */
    [[nodiscard]] bool SafeParseIPv4(std::string_view str, uint8_t out[4]) noexcept {
        // Validate output pointer
        if (out == nullptr) {
            return false;
        }
        
        // Validate input bounds
        if (str.empty() || str.size() > 15) {
            return false;
        }
        
        // Zero-initialize output for safety
        out[0] = out[1] = out[2] = out[3] = 0;
        
        size_t octetIdx = 0;
        int value = 0;
        int digitCount = 0;
        
        for (size_t i = 0; i <= str.size(); ++i) {
            const char c = (i < str.size()) ? str[i] : '.';
            
            if (c == '.') {
                // Validate octet
                if (digitCount == 0 || value > 255 || octetIdx >= 4) {
                    return false;
                }
                // Check for leading zeros (e.g., "01.02.03.04" is invalid in strict mode)
                // For compatibility, we allow it but validate range
                out[octetIdx++] = static_cast<uint8_t>(value);
                value = 0;
                digitCount = 0;
            } else if (c >= '0' && c <= '9') {
                // Overflow check before multiplication
                if (value > 25 || (value == 25 && (c - '0') > 5)) {
                    return false;  // Would exceed 255
                }
                value = value * 10 + (c - '0');
                digitCount++;
                if (digitCount > 3) {
                    return false;
                }
            } else {
                return false;  // Invalid character
            }
        }
        
        // Must have exactly 4 octets and no trailing digits
        return octetIdx == 4 && digitCount == 0;
    }
    
    /**
     * @brief Check if hex string length is valid for known hash algorithms
     * @param length Length of hex string (not byte count)
     * @return true if length corresponds to a known hash algorithm
     */
    [[nodiscard]] constexpr bool IsValidHashHexLength(size_t length) noexcept {
        return length == 32 || length == 40 || length == 64 || length == 128;
    }
    
    /**
     * @brief Determine hash algorithm from hex string length
     * @param length Length of hex string (not byte count)
     * @return Detected hash algorithm (MD5 as fallback - caller should validate with IsValidHashHexLength first)
     */
    [[nodiscard]] ShadowStrike::ThreatIntel::HashAlgorithm DetermineHashAlgo(size_t length) noexcept {
        using namespace ShadowStrike::ThreatIntel;
        switch (length) {
            case 32:  return HashAlgorithm::MD5;
            case 40:  return HashAlgorithm::SHA1;
            case 64:  return HashAlgorithm::SHA256;
            case 128: return HashAlgorithm::SHA512;
            default:  return HashAlgorithm::MD5;  // Fallback - caller should validate with IsValidHashHexLength first
        }
    }
    
    /**
     * @brief Safely trim whitespace from string view
     * @param str Input string view
     * @return Trimmed string view
     */
    [[nodiscard]] std::string_view SafeTrim(std::string_view str) noexcept {
        while (!str.empty() && std::isspace(static_cast<unsigned char>(str.front()))) {
            str.remove_prefix(1);
        }
        while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
            str.remove_suffix(1);
        }
        return str;
    }
}

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Utility Functions Implementation
// ============================================================================

const char* GetImportFormatExtension(ImportFormat format) noexcept {
    switch (format) {
        case ImportFormat::CSV: return ".csv";
        case ImportFormat::JSON: return ".json";
        case ImportFormat::JSONL: return ".jsonl";
        case ImportFormat::STIX21: return ".json"; // STIX is JSON
        case ImportFormat::MISP: return ".json"; // MISP is JSON
        case ImportFormat::OpenIOC: return ".ioc";
        case ImportFormat::TAXII21: return ".json";
        case ImportFormat::PlainText: return ".txt";
        case ImportFormat::Binary: return ".bin";
        case ImportFormat::CrowdStrike: return ".json";
        case ImportFormat::AlienVaultOTX: return ".json";
        default: return "";
    }
}

const char* GetImportFormatName(ImportFormat format) noexcept {
    switch (format) {
        case ImportFormat::Auto: return "Auto-Detect";
        case ImportFormat::CSV: return "CSV";
        case ImportFormat::JSON: return "JSON";
        case ImportFormat::JSONL: return "JSON Lines";
        case ImportFormat::STIX21: return "STIX 2.1";
        case ImportFormat::MISP: return "MISP";
        case ImportFormat::OpenIOC: return "OpenIOC";
        case ImportFormat::TAXII21: return "TAXII 2.1";
        case ImportFormat::PlainText: return "Plain Text";
        case ImportFormat::Binary: return "Binary";
        case ImportFormat::CrowdStrike: return "CrowdStrike";
        case ImportFormat::AlienVaultOTX: return "AlienVault OTX";
        case ImportFormat::URLhaus: return "URLhaus";
        case ImportFormat::MalwareBazaar: return "MalwareBazaar";
        case ImportFormat::FeodoTracker: return "Feodo Tracker";
        case ImportFormat::MSSentinel: return "Microsoft Sentinel";
        case ImportFormat::Splunk: return "Splunk";
        case ImportFormat::EmergingThreats: return "Emerging Threats";
        case ImportFormat::SnortRules: return "Snort Rules";
        default: return "Unknown";
    }
}

std::optional<ImportFormat> ParseImportFormat(std::string_view str) noexcept {
    std::string s(str);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    
    if (s == "csv") return ImportFormat::CSV;
    if (s == "json") return ImportFormat::JSON;
    if (s == "jsonl") return ImportFormat::JSONL;
    if (s == "stix" || s == "stix2" || s == "stix21") return ImportFormat::STIX21;
    if (s == "misp") return ImportFormat::MISP;
    if (s == "openioc" || s == "ioc") return ImportFormat::OpenIOC;
    if (s == "taxii" || s == "taxii2") return ImportFormat::TAXII21;
    if (s == "txt" || s == "text" || s == "plain") return ImportFormat::PlainText;
    if (s == "bin" || s == "binary") return ImportFormat::Binary;
    
    return std::nullopt;
}

std::string DefangIOC(std::string_view value, IOCType type) {
    // Validate input
    if (value.empty()) {
        return {};
    }
    
    // Prevent DoS with excessively long strings
    constexpr size_t MAX_IOC_LENGTH = 64 * 1024;  // 64KB max
    if (value.length() > MAX_IOC_LENGTH) {
        return {};
    }
    
    std::string result;
    try {
        result.assign(value);
    } catch (const std::exception&) {
        return {};  // Allocation failure
    }
    
    if (type == IOCType::Domain || type == IOCType::URL || type == IOCType::Email || type == IOCType::IPv4) {
        // Replace . with [.] - do in reverse to avoid index shifting issues
        for (size_t pos = result.rfind('.'); pos != std::string::npos; pos = result.rfind('.', pos > 0 ? pos - 1 : std::string::npos)) {
            try {
                result.replace(pos, 1, "[.]");
            } catch (const std::exception&) {
                return {};  // Allocation failure during replace
            }
            if (pos == 0) break;
        }
        
        // Replace http with hxxp
        if (type == IOCType::URL) {
            if (result.length() >= 7 && result.compare(0, 7, "http://") == 0) {
                result.replace(0, 4, "hxxp");
            } else if (result.length() >= 8 && result.compare(0, 8, "https://") == 0) {
                result.replace(0, 5, "hxxps");
            }
        }
        
        // Replace @ with [at] for emails
        if (type == IOCType::Email) {
            size_t pos = result.find('@');
            if (pos != std::string::npos) {
                try {
                    result.replace(pos, 1, "[at]");
                } catch (const std::exception&) {
                    return {};
                }
            }
        }
    }
    
    return result;
}

std::string RefangIOC(std::string_view value, IOCType type) {
    // Validate input
    if (value.empty()) {
        return {};
    }
    
    // Prevent DoS with excessively long strings
    constexpr size_t MAX_IOC_LENGTH = 64 * 1024;  // 64KB max
    if (value.length() > MAX_IOC_LENGTH) {
        return {};
    }
    
    std::string result;
    try {
        result.assign(value);
    } catch (const std::exception&) {
        return {};  // Allocation failure
    }
    
    if (type == IOCType::Domain || type == IOCType::URL || type == IOCType::Email || type == IOCType::IPv4) {
        // Replace [.] with . - iterate safely
        size_t pos = 0;
        while ((pos = result.find("[.]", pos)) != std::string::npos) {
            result.replace(pos, 3, ".");
            // pos stays at same position since we replaced 3 chars with 1
        }
        
        // Replace (dot) with .
        pos = 0;
        while ((pos = result.find("(dot)", pos)) != std::string::npos) {
            result.replace(pos, 5, ".");
        }
        
        // Replace hxxp with http
        if (type == IOCType::URL) {
            if (result.length() >= 7 && result.compare(0, 7, "hxxp://") == 0) {
                result.replace(0, 4, "http");
            } else if (result.length() >= 8 && result.compare(0, 8, "hxxps://") == 0) {
                result.replace(0, 5, "https");
            }
        }
        
        // Replace [at] with @
        if (type == IOCType::Email) {
            pos = result.find("[at]");
            if (pos != std::string::npos) {
                result.replace(pos, 4, "@");
            }
        }
    }
    
    return result;
}

/**
 * @brief Parse ISO 8601 timestamp to Unix timestamp
 * 
 * Supports formats:
 * - YYYY-MM-DDThh:mm:ssZ
 * - YYYY-MM-DDThh:mm:ss.fffZ
 * - YYYY-MM-DD hh:mm:ss
 * 
 * @param timestamp ISO8601 formatted timestamp string
 * @return Unix timestamp in seconds, 0 on parse failure
 */
uint64_t ParseISO8601Timestamp(std::string_view timestamp) noexcept {
    // Validate input length
    if (timestamp.empty() || timestamp.size() < 19 || timestamp.size() > 64) {
        return 0;
    }
    
    // Trim whitespace
    timestamp = SafeTrim(timestamp);
    if (timestamp.size() < 19) {
        return 0;
    }
    
    std::tm tm = {};
    
    // Manual parsing for better control and safety
    // Format: YYYY-MM-DDThh:mm:ss or YYYY-MM-DD hh:mm:ss
    auto parseDigits = [&timestamp](size_t pos, size_t count) -> int {
        if (pos + count > timestamp.size()) return -1;
        int value = 0;
        for (size_t i = 0; i < count; ++i) {
            char c = timestamp[pos + i];
            if (c < '0' || c > '9') return -1;
            value = value * 10 + (c - '0');
        }
        return value;
    };
    
    // Parse year (positions 0-3)
    int year = parseDigits(0, 4);
    if (year < 0 || timestamp[4] != '-') return 0;
    
    // Parse month (positions 5-6)
    int month = parseDigits(5, 2);
    if (month < 0 || timestamp[7] != '-') return 0;
    
    // Parse day (positions 8-9)
    int day = parseDigits(8, 2);
    if (day < 0) return 0;
    
    // Accept 'T' or space separator (position 10)
    if (timestamp[10] != 'T' && timestamp[10] != ' ') return 0;
    
    // Parse hour (positions 11-12)
    int hour = parseDigits(11, 2);
    if (hour < 0 || timestamp[13] != ':') return 0;
    
    // Parse minute (positions 14-15)
    int minute = parseDigits(14, 2);
    if (minute < 0 || timestamp[16] != ':') return 0;
    
    // Parse second (positions 17-18)
    int second = parseDigits(17, 2);
    if (second < 0) return 0;
    
    // Validate ranges strictly
    if (year < 1970 || year > 2100) return 0;  // Unix epoch to 2100
    if (month < 1 || month > 12) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour < 0 || hour > 23) return 0;
    if (minute < 0 || minute > 59) return 0;
    if (second < 0 || second > 60) return 0;  // 60 for leap seconds
    
    // Additional day validation based on month
    static constexpr int daysInMonth[] = {0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (day > daysInMonth[month]) return 0;
    
    // February leap year check
    if (month == 2 && day == 29) {
        bool isLeapYear = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
        if (!isLeapYear) return 0;
    }
    
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = 0;
    
#ifdef _WIN32
    const time_t result = _mkgmtime(&tm);
#else
    const time_t result = timegm(&tm);
#endif
    
    if (result == static_cast<time_t>(-1)) {
        return 0;
    }
    
    return static_cast<uint64_t>(result);
}

/**
 * @brief Parse timestamp from various formats
 * 
 * Supports:
 * - Unix timestamp (seconds since epoch)
 * - ISO 8601 format
 * 
 * @param timestamp Timestamp string
 * @return Unix timestamp in seconds, 0 on failure
 */
uint64_t ParseTimestamp(std::string_view timestamp) noexcept {
    // Validate input
    if (timestamp.empty() || timestamp.size() > 64) {
        return 0;
    }
    
    // Trim whitespace
    timestamp = SafeTrim(timestamp);
    if (timestamp.empty()) {
        return 0;
    }
    
    // Check if it's a pure numeric string (Unix timestamp)
    bool allDigits = true;
    for (const char c : timestamp) {
        if (c < '0' || c > '9') {
            allDigits = false;
            break;
        }
    }
    
    if (allDigits) {
        // Parse as Unix timestamp with overflow protection
        uint64_t value = 0;
        constexpr uint64_t MAX_SAFE_MULTIPLY = UINT64_MAX / 10;
        
        for (const char c : timestamp) {
            const uint64_t digit = static_cast<uint64_t>(c - '0');
            
            // Check for overflow before multiplication
            if (value > MAX_SAFE_MULTIPLY) {
                return 0;  // Would overflow
            }
            
            value *= 10;
            
            // Check for overflow before addition
            if (value > UINT64_MAX - digit) {
                return 0;  // Would overflow
            }
            
            value += digit;
        }
        
        // Sanity check: reasonable timestamp range (1970-2200)
        constexpr uint64_t MAX_REASONABLE_TIMESTAMP = 7258118400ULL;  // Year 2200
        if (value > MAX_REASONABLE_TIMESTAMP) {
            return 0;
        }
        
        return value;
    }
    
    // Try ISO 8601
    return ParseISO8601Timestamp(timestamp);
}

uint32_t CalculateImportChecksum(std::span<const uint8_t> data) noexcept {
    // Handle empty data
    if (data.empty()) {
        return 0;
    }
    
    // CRC32 lookup table (precomputed for performance)
    static constexpr uint32_t CRC32_TABLE[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD706B3, 0x54DE5729, 0x23D967BF,
        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    uint32_t crc = 0xFFFFFFFF;
    for (const uint8_t byte : data) {
        crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// ============================================================================
// CSV Import Reader Implementation
// ============================================================================

CSVImportReader::CSVImportReader(std::istream& input)
    : m_input(input) {
}

CSVImportReader::~CSVImportReader() = default;

bool CSVImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_columnMappings = options.csvConfig.columnMappings;
    m_initialized = true;
    m_currentLine = 0;
    m_bytesRead = 0;
    
    // If we have a header, parse it to detect columns
    if (m_options.csvConfig.hasHeader) {
        if (!ParseHeader()) {
            return false;
        }
    } else if (m_columnMappings.empty()) {
        // No header and no mappings - cannot proceed unless we assume default structure
        m_lastError = "No CSV header and no column mappings provided";
        return false;
    }
    
    return true;
}

bool CSVImportReader::ParseHeader() {
    std::vector<std::string> headerRow;
    if (!ReadRow(headerRow)) {
        m_lastError = "Failed to read CSV header";
        return false;
    }
    
    if (m_columnMappings.empty()) {
        return AutoDetectColumns(headerRow);
    }
    
    return true;
}

bool CSVImportReader::AutoDetectColumns(const std::vector<std::string>& headerRow) {
    m_columnMappings.clear();
    
    for (size_t i = 0; i < headerRow.size(); ++i) {
        CSVColumnType type = GuessColumnType(headerRow[i], {});
        if (type != CSVColumnType::Unknown && type != CSVColumnType::Ignore) {
            CSVColumnMapping mapping;
            mapping.columnIndex = i;
            mapping.type = type;
            mapping.headerName = headerRow[i];
            m_columnMappings.push_back(mapping);
        }
    }
    
    if (m_columnMappings.empty()) {
        m_lastError = "Could not auto-detect any valid columns from header";
        return false;
    }
    
    return true;
}

CSVColumnType CSVImportReader::GuessColumnType(std::string_view headerName, const std::vector<std::string>& samples) const {
    std::string lowerHeader(headerName);
    std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);
    
    // Heuristic matching based on header name
    if (lowerHeader.find("ip") != std::string::npos || lowerHeader.find("address") != std::string::npos) {
        if (lowerHeader.find("v6") != std::string::npos) return CSVColumnType::IPv6;
        return CSVColumnType::IPv4;
    }
    if (lowerHeader.find("domain") != std::string::npos || lowerHeader.find("host") != std::string::npos) return CSVColumnType::Domain;
    if (lowerHeader.find("url") != std::string::npos || lowerHeader.find("uri") != std::string::npos) return CSVColumnType::URL;
    if (lowerHeader.find("hash") != std::string::npos) {
        if (lowerHeader.find("md5") != std::string::npos) return CSVColumnType::MD5;
        if (lowerHeader.find("sha1") != std::string::npos) return CSVColumnType::SHA1;
        if (lowerHeader.find("sha256") != std::string::npos) return CSVColumnType::SHA256;
        return CSVColumnType::Value; // Generic hash
    }
    if (lowerHeader.find("email") != std::string::npos || lowerHeader.find("sender") != std::string::npos) return CSVColumnType::Email;
    if (lowerHeader.find("file") != std::string::npos && lowerHeader.find("name") != std::string::npos) return CSVColumnType::Filename;
    
    if (lowerHeader == "ioc" || lowerHeader == "indicator" || lowerHeader == "value") return CSVColumnType::Value;
    if (lowerHeader == "type" || lowerHeader == "kind") return CSVColumnType::Type;
    if (lowerHeader.find("score") != std::string::npos || lowerHeader.find("reputation") != std::string::npos) return CSVColumnType::Reputation;
    if (lowerHeader.find("confidence") != std::string::npos) return CSVColumnType::Confidence;
    if (lowerHeader.find("category") != std::string::npos || lowerHeader.find("threat") != std::string::npos) return CSVColumnType::Category;
    if (lowerHeader.find("source") != std::string::npos) return CSVColumnType::Source;
    if (lowerHeader.find("desc") != std::string::npos) return CSVColumnType::Description;
    if (lowerHeader.find("tag") != std::string::npos || lowerHeader.find("label") != std::string::npos) return CSVColumnType::Tags;
    
    if (lowerHeader.find("first") != std::string::npos && lowerHeader.find("seen") != std::string::npos) return CSVColumnType::FirstSeen;
    if (lowerHeader.find("last") != std::string::npos && lowerHeader.find("seen") != std::string::npos) return CSVColumnType::LastSeen;
    if (lowerHeader.find("create") != std::string::npos) return CSVColumnType::CreatedTime;
    
    return CSVColumnType::Unknown;
}

bool CSVImportReader::ReadRow(std::vector<std::string>& fields) {
    constexpr size_t MAX_SKIP_LINES = 10000;  // Prevent infinite loops
    constexpr size_t MAX_FIELDS_PER_ROW = 1000;  // Prevent DoS
    constexpr size_t MAX_FIELD_LENGTH = 1024 * 1024;  // 1MB per field max
    
    fields.clear();
    
    // Use iteration instead of recursion to avoid stack overflow
    for (size_t skipCount = 0; skipCount < MAX_SKIP_LINES; ++skipCount) {
        if (m_input.eof() || !m_input.good()) {
            m_endOfInput = true;
            return false;
        }
        
        std::string line;
        try {
            if (!std::getline(m_input, line)) {
                m_endOfInput = true;
                return false;
            }
        } catch (const std::exception& e) {
            m_lastError = std::string("I/O error reading line: ") + e.what();
            m_endOfInput = true;
            return false;
        }
        
        // Handle Windows CRLF
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        m_currentLine++;
        
        // Prevent overflow in bytes read counter
        if (m_bytesRead <= UINT64_MAX - line.length() - 1) {
            m_bytesRead += line.length() + 1;
        }
        
        // Skip empty lines or comments - continue loop instead of recursion
        if (line.empty()) {
            continue;
        }
        
        if (!m_options.csvConfig.commentPrefix.empty() && 
            line.find(m_options.csvConfig.commentPrefix) == 0) {
            continue;
        }
        
        // Parse CSV line with proper state machine
        bool inQuotes = false;
        std::string currentField;
        
        try {
            currentField.reserve(std::min(line.length(), static_cast<size_t>(256)));
        } catch (const std::exception&) {
            // Ignore reservation failure - will allocate as needed
        }
        
        for (size_t i = 0; i < line.length(); ++i) {
            const char c = line[i];
            
            // Check field length limit
            if (currentField.length() >= MAX_FIELD_LENGTH) {
                m_lastError = "Field exceeds maximum length";
                return false;
            }
            
            if (c == m_options.csvConfig.quote) {
                inQuotes = !inQuotes;
            } else if (c == m_options.csvConfig.delimiter && !inQuotes) {
                // Process and store current field
                if (m_options.csvConfig.trimFields) {
                    size_t first = currentField.find_first_not_of(" \t");
                    size_t last = currentField.find_last_not_of(" \t");
                    if (first == std::string::npos) {
                        currentField.clear();
                    } else {
                        currentField = currentField.substr(first, (last - first + 1));
                    }
                }
                
                // Remove surrounding quotes if present
                if (currentField.length() >= 2 && 
                    currentField.front() == m_options.csvConfig.quote && 
                    currentField.back() == m_options.csvConfig.quote) {
                    currentField = currentField.substr(1, currentField.length() - 2);
                    
                    // Handle escaped quotes ("") -> "
                    size_t pos = 0;
                    const std::string escapedQuote(2, m_options.csvConfig.quote);
                    const std::string singleQuote(1, m_options.csvConfig.quote);
                    while ((pos = currentField.find(escapedQuote, pos)) != std::string::npos) {
                        currentField.replace(pos, 2, singleQuote);
                        pos += 1;
                    }
                }
                
                // Check field count limit
                if (fields.size() >= MAX_FIELDS_PER_ROW) {
                    m_lastError = "Too many fields in row";
                    return false;
                }
                
                try {
                    fields.push_back(std::move(currentField));
                } catch (const std::exception&) {
                    m_lastError = "Memory allocation failed";
                    return false;
                }
                currentField.clear();
            } else {
                currentField += c;
            }
        }
        
        // Add last field
        if (m_options.csvConfig.trimFields) {
            size_t first = currentField.find_first_not_of(" \t");
            size_t last = currentField.find_last_not_of(" \t");
            if (first == std::string::npos) {
                currentField.clear();
            } else {
                currentField = currentField.substr(first, (last - first + 1));
            }
        }
        
        if (currentField.length() >= 2 && 
            currentField.front() == m_options.csvConfig.quote && 
            currentField.back() == m_options.csvConfig.quote) {
            currentField = currentField.substr(1, currentField.length() - 2);
            
            size_t pos = 0;
            const std::string escapedQuote(2, m_options.csvConfig.quote);
            const std::string singleQuote(1, m_options.csvConfig.quote);
            while ((pos = currentField.find(escapedQuote, pos)) != std::string::npos) {
                currentField.replace(pos, 2, singleQuote);
                pos += 1;
            }
        }
        
        if (fields.size() >= MAX_FIELDS_PER_ROW) {
            m_lastError = "Too many fields in row";
            return false;
        }
        
        try {
            fields.push_back(std::move(currentField));
        } catch (const std::exception&) {
            m_lastError = "Memory allocation failed";
            return false;
        }
        
        return true;  // Successfully parsed a row
    }
    
    // If we get here, we skipped too many lines
    m_lastError = "Too many consecutive empty/comment lines";
    return false;
}

bool CSVImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    if (m_endOfInput) return false;
    
    std::vector<std::string> fields;
    if (!ReadRow(fields)) {
        return false;
    }
    
    // Initialize entry with defaults
    // Use placement new to reset the entry to default state
    new (&entry) IOCEntry();
    
    entry.source = m_options.defaultSource;
    entry.reputation = m_options.defaultReputation;
    entry.confidence = m_options.defaultConfidence;
    entry.category = m_options.defaultCategory;
    entry.feedId = m_options.feedId;
    entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
    entry.firstSeen = entry.createdTime;
    entry.lastSeen = entry.createdTime;
    
    if (m_options.defaultTTL > 0) {
        entry.expirationTime = entry.createdTime + m_options.defaultTTL;
    }
    
    // Map fields to entry
    bool hasValue = false;
    
    for (const auto& mapping : m_columnMappings) {
        if (mapping.columnIndex < fields.size()) {
            if (ParseField(fields[mapping.columnIndex], mapping.type, entry, stringPool)) {
                if (mapping.type == CSVColumnType::Value || 
                    mapping.type == CSVColumnType::IPv4 || 
                    mapping.type == CSVColumnType::IPv6 || 
                    mapping.type == CSVColumnType::Domain || 
                    mapping.type == CSVColumnType::URL || 
                    mapping.type == CSVColumnType::MD5 || 
                    mapping.type == CSVColumnType::SHA1 || 
                    mapping.type == CSVColumnType::SHA256 || 
                    mapping.type == CSVColumnType::Email) {
                    hasValue = true;
                }
            }
        }
    }
    
    // If no explicit type column, try to detect from value
    if (entry.type == IOCType::Reserved && hasValue) {
        if (m_options.csvConfig.defaultIOCType != IOCType::Reserved) {
            entry.type = m_options.csvConfig.defaultIOCType;
        } else if (m_options.csvConfig.autoDetectIOCType) {
            // We need to look at the value to detect type
            // This is tricky because the value is already in the union
            // For now, we rely on ParseField to set the type if it's a specific value column
        }
    }
    
    return hasValue;
}

bool CSVImportReader::ParseField(std::string_view field, CSVColumnType type, IOCEntry& entry, IStringPoolWriter* stringPool) {
    if (field.empty()) {
        return false;
    }
    
    // Validate stringPool for types that need it
    if (stringPool == nullptr && 
        (type == CSVColumnType::Domain || type == CSVColumnType::URL || 
         type == CSVColumnType::Email || type == CSVColumnType::Description ||
         type == CSVColumnType::Value)) {
        m_lastError = "String pool required but not provided";
        return false;
    }
    
    try {
        switch (type) {
            case CSVColumnType::Value: {
                // Generic value - detect type
                IOCType detectedType = DetectIOCType(field);
                if (detectedType == IOCType::Reserved) {
                    return false;
                }
                
                entry.type = detectedType;
                
                if (detectedType == IOCType::IPv4) {
                    uint8_t octets[4] = {0};
                    if (SafeParseIPv4(field, octets)) {
                        entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                        entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
                    } else {
                        return false;
                    }
                } else if (detectedType == IOCType::IPv6) {
                    // Parse IPv6 - store as string for now
                    auto [offset, length] = stringPool->AddString(field);
                    entry.value.stringRef.stringOffset = offset;
                    entry.value.stringRef.stringLength = length;
                    entry.valueType = static_cast<uint8_t>(IOCType::IPv6);
                } else if (detectedType == IOCType::FileHash) {
                    // Validate hash length before determining algorithm
                    if (!IsValidHashHexLength(field.length())) {
                        return false;  // Unknown hash length
                    }
                    HashAlgorithm algo = DetermineHashAlgo(field.length());
                    entry.value.hash.algorithm = algo;
                    
                    // Validate hash length fits in uint8_t
                    const size_t byteLength = field.length() / 2;
                    if (byteLength > 255 || byteLength > sizeof(entry.value.hash.data)) {
                        return false;
                    }
                    entry.value.hash.length = static_cast<uint8_t>(byteLength);
                    
                    if (!ParseHexString(field, entry.value.hash.data)) {
                        return false;
                    }
                    entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
                } else {
                    // String based (Domain, URL, etc)
                    auto [offset, length] = stringPool->AddString(field);
                    entry.value.stringRef.stringOffset = offset;
                    entry.value.stringRef.stringLength = length;
                    entry.valueType = static_cast<uint8_t>(detectedType);
                }
                return true;
            }
            
            case CSVColumnType::IPv4: {
                entry.type = IOCType::IPv4;
                uint8_t octets[4] = {0};
                if (SafeParseIPv4(field, octets)) {
                    entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                    entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
                    return true;
                }
                return false;
            }
            
            case CSVColumnType::MD5:
            case CSVColumnType::SHA1:
            case CSVColumnType::SHA256: {
                // Validate hash length for the specific algorithm
                size_t expectedLen = (type == CSVColumnType::MD5) ? 32 :
                                     (type == CSVColumnType::SHA1) ? 40 : 64;
                if (field.length() != expectedLen) {
                    return false;
                }
                
                entry.type = IOCType::FileHash;
                HashAlgorithm algo = (type == CSVColumnType::MD5) ? HashAlgorithm::MD5 :
                                     (type == CSVColumnType::SHA1) ? HashAlgorithm::SHA1 : HashAlgorithm::SHA256;
                entry.value.hash.algorithm = algo;
                
                const size_t byteLength = field.length() / 2;
                if (byteLength > sizeof(entry.value.hash.data)) {
                    return false;
                }
                entry.value.hash.length = static_cast<uint8_t>(byteLength);
                
                if (!ParseHexString(field, entry.value.hash.data)) {
                    return false;
                }
                entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
                return true;
            }
            
            case CSVColumnType::Domain:
            case CSVColumnType::URL:
            case CSVColumnType::Email: {
                entry.type = (type == CSVColumnType::Domain) ? IOCType::Domain : 
                             (type == CSVColumnType::URL) ? IOCType::URL : IOCType::Email;
                auto [offset, length] = stringPool->AddString(field);
                entry.value.stringRef.stringOffset = offset;
                entry.value.stringRef.stringLength = length;
                entry.valueType = static_cast<uint8_t>(entry.type);
                return true;
            }
            
            case CSVColumnType::Reputation: {
                // Safe string to int conversion
                std::string fieldStr(field);
                char* endPtr = nullptr;
                long score = std::strtol(fieldStr.c_str(), &endPtr, 10);
                if (endPtr == fieldStr.c_str() || *endPtr != '\0') {
                    return false;  // Invalid number
                }
                entry.reputation = static_cast<ReputationLevel>(std::clamp(score, 0L, 100L));
                return true;
            }
            
            case CSVColumnType::Confidence: {
                std::string fieldStr(field);
                char* endPtr = nullptr;
                long score = std::strtol(fieldStr.c_str(), &endPtr, 10);
                if (endPtr == fieldStr.c_str() || *endPtr != '\0') {
                    return false;
                }
                entry.confidence = static_cast<ConfidenceLevel>(std::clamp(score, 0L, 100L));
                return true;
            }
            
            case CSVColumnType::Description: {
                auto [offset, length] = stringPool->AddString(field);
                
                // Validate offset and length fit in entry fields
                if (offset > UINT32_MAX || length > UINT16_MAX) {
                    return false;
                }
                entry.descriptionOffset = static_cast<uint32_t>(offset);
                entry.descriptionLength = static_cast<uint16_t>(length);
                return true;
            }
            
            case CSVColumnType::FirstSeen: {
                uint64_t ts = ParseTimestamp(field);
                if (ts == 0 && !field.empty()) {
                    // Parse failure for non-empty field
                    return false;
                }
                entry.firstSeen = ts;
                return true;
            }
            
            case CSVColumnType::LastSeen: {
                uint64_t ts = ParseTimestamp(field);
                if (ts == 0 && !field.empty()) {
                    return false;
                }
                entry.lastSeen = ts;
                return true;
            }
            
            default:
                return false;
        }
    } catch (const std::exception& e) {
        m_lastError = std::string("Exception parsing field: ") + e.what();
        return false;
    }
}

IOCType CSVImportReader::DetectIOCType(std::string_view value) const {
    // Simple regex-based detection
    // In production, use more robust validation
    
    // IPv4: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
    static const std::regex ipv4Regex(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    if (std::regex_match(value.begin(), value.end(), ipv4Regex)) return IOCType::IPv4;
    
    // MD5: [a-fA-F0-9]{32}
    static const std::regex md5Regex(R"(^[a-fA-F0-9]{32}$)");
    if (std::regex_match(value.begin(), value.end(), md5Regex)) return IOCType::FileHash;
    
    // SHA1: [a-fA-F0-9]{40}
    static const std::regex sha1Regex(R"(^[a-fA-F0-9]{40}$)");
    if (std::regex_match(value.begin(), value.end(), sha1Regex)) return IOCType::FileHash;
    
    // SHA256: [a-fA-F0-9]{64}
    static const std::regex sha256Regex(R"(^[a-fA-F0-9]{64}$)");
    if (std::regex_match(value.begin(), value.end(), sha256Regex)) return IOCType::FileHash;
    
    // Domain: [a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
    static const std::regex domainRegex(R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$)");
    if (std::regex_match(value.begin(), value.end(), domainRegex)) return IOCType::Domain;
    
    // URL: https?://...
    if (value.find("http://") == 0 || value.find("https://") == 0) return IOCType::URL;
    
    return IOCType::Reserved;
}

bool CSVImportReader::HasMoreEntries() const noexcept {
    return !m_endOfInput;
}

std::optional<size_t> CSVImportReader::GetEstimatedTotal() const noexcept {
    // Estimate based on file size and current position
    // Not implemented for stream
    return std::nullopt;
}

uint64_t CSVImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> CSVImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string CSVImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> CSVImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool CSVImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// JSON Import Reader Implementation
// ============================================================================

JSONImportReader::JSONImportReader(std::istream& input)
    : m_input(input) {
}

JSONImportReader::~JSONImportReader() = default;

bool JSONImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_initialized = true;
    m_currentIndex = 0;
    m_bytesRead = 0;
    m_endOfInput = false;
    
    try {
        // Check if JSONL based on format or content
        if (m_options.format == ImportFormat::JSONL) {
            m_isJsonLines = true;
        } else {
            // Peek to see if it starts with [ or {
            int c = m_input.peek();
            if (c == std::char_traits<char>::eof()) {
                m_lastError = "Empty input stream";
                return false;
            }
            
            char ch = static_cast<char>(c);
            if (ch != '[' && ch != '{' && ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
                // Heuristic: if it doesn't start with array/object, assume JSONL
                m_isJsonLines = true;
            } else {
                m_isJsonLines = false;
                
                // For standard JSON, load content with size limit
                constexpr size_t MAX_JSON_SIZE = 256 * 1024 * 1024;  // 256MB
                
                std::stringstream buffer;
                buffer << m_input.rdbuf();
                m_buffer = buffer.str();
                
                if (m_buffer.size() > MAX_JSON_SIZE) {
                    m_lastError = "JSON content exceeds maximum size limit";
                    m_buffer.clear();
                    return false;
                }
                
                m_bytesRead = m_buffer.size();
                
                if (!ParseDocument()) {
                    return false;
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        m_lastError = std::string("Initialization error: ") + e.what();
        return false;
    }
}

bool JSONImportReader::ParseDocument() {
    try {
        auto j = json::parse(m_buffer);
        
        if (j.is_array()) {
            // Array of objects
            m_totalEntries = j.size();
        } else if (j.is_object()) {
            // Single object or wrapped
            if (j.contains("indicators") && j["indicators"].is_array()) {
                // Wrapped in "indicators"
                m_totalEntries = j["indicators"].size();
            } else if (j.contains("iocs") && j["iocs"].is_array()) {
                // Wrapped in "iocs"
                m_totalEntries = j["iocs"].size();
            } else {
                // Single object
                m_totalEntries = 1;
            }
        }
        return true;
    } catch (const json::parse_error& e) {
        m_lastError = std::string("JSON parse error: ") + e.what();
        return false;
    }
}

bool JSONImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    if (m_isJsonLines) {
        std::string line;
        if (ReadNextJSONLine(line)) {
            return ParseEntryFromJSON(line, entry, stringPool);
        }
        return false;
    } else {
        // Standard JSON - iterate through parsed document
        // This requires storing the parsed json object which is not in the class members
        // For this implementation, we'll re-parse or need to change the class structure
        // Since we can't change the header, we'll use m_buffer and m_currentIndex
        // This is inefficient for large files but fits the interface
        
        if (m_currentIndex >= m_buffer.length()) return false;
        
        // Find next object start '{'
        size_t start = m_buffer.find('{', m_currentIndex);
        if (start == std::string::npos) return false;
        
        // Find matching '}' - this is naive and breaks on nested objects
        // We need a proper brace counter
        int braceCount = 0;
        size_t end = start;
        bool inString = false;
        bool escape = false;
        
        for (; end < m_buffer.length(); ++end) {
            char c = m_buffer[end];
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (!inString) {
                if (c == '{') braceCount++;
                else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        end++; // Include closing brace
                        break;
                    }
                }
            }
        }
        
        if (braceCount == 0 && end > start) {
            std::string jsonStr = m_buffer.substr(start, end - start);
            m_currentIndex = end;
            return ParseEntryFromJSON(jsonStr, entry, stringPool);
        }
        
        m_currentIndex = m_buffer.length(); // Stop
        return false;
    }
}

bool JSONImportReader::ReadNextJSONLine(std::string& line) {
    if (m_input.eof()) return false;
    std::getline(m_input, line);
    m_bytesRead += line.length() + 1;
    return !line.empty() || !m_input.eof();
}

bool JSONImportReader::ParseEntryFromJSON(const std::string& jsonStr, IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Validate inputs
    if (jsonStr.empty() || stringPool == nullptr) {
        return false;
    }
    
    try {
        auto j = json::parse(jsonStr);
        
        // Initialize entry to safe defaults
        entry = IOCEntry{};
        entry.source = m_options.defaultSource;
        entry.reputation = m_options.defaultReputation;
        entry.confidence = m_options.defaultConfidence;
        entry.category = m_options.defaultCategory;
        entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
        entry.firstSeen = entry.createdTime;
        entry.lastSeen = entry.createdTime;
        
        // Extract fields with proper type checking
        std::string value;
        std::string typeStr;
        
        auto safeGetString = [&j](const char* key) -> std::string {
            if (j.contains(key) && j[key].is_string()) {
                return j[key].get<std::string>();
            }
            return {};
        };
        
        // Try various field names for the value
        value = safeGetString("value");
        if (value.empty()) value = safeGetString("ioc");
        if (value.empty()) value = safeGetString("indicator");
        if (value.empty()) {
            if (j.contains("ip") && j["ip"].is_string()) {
                value = j["ip"].get<std::string>();
                typeStr = "ipv4";
            }
        }
        if (value.empty()) {
            if (j.contains("domain") && j["domain"].is_string()) {
                value = j["domain"].get<std::string>();
                typeStr = "domain";
            }
        }
        if (value.empty()) {
            if (j.contains("url") && j["url"].is_string()) {
                value = j["url"].get<std::string>();
                typeStr = "url";
            }
        }
        if (value.empty()) {
            if (j.contains("hash") && j["hash"].is_string()) {
                value = j["hash"].get<std::string>();
                typeStr = "hash";
            }
        }
        
        if (value.empty()) {
            return false;
        }
        
        // Validate value length
        constexpr size_t MAX_VALUE_LENGTH = 64 * 1024;  // 64KB
        if (value.length() > MAX_VALUE_LENGTH) {
            return false;
        }
        
        if (typeStr.empty()) {
            typeStr = safeGetString("type");
        }
        
        // Detect type if missing
        IOCType type = IOCType::Reserved;
        if (!typeStr.empty()) {
            // Normalize type string
            std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(),
                          [](unsigned char c) { return std::tolower(c); });
            
            if (typeStr == "ipv4" || typeStr == "ip" || typeStr == "ip-dst" || typeStr == "ip-src") {
                type = IOCType::IPv4;
            } else if (typeStr == "ipv6") {
                type = IOCType::IPv6;
            } else if (typeStr == "domain" || typeStr == "hostname") {
                type = IOCType::Domain;
            } else if (typeStr == "url" || typeStr == "uri") {
                type = IOCType::URL;
            } else if (typeStr == "md5" || typeStr == "sha1" || typeStr == "sha256" || 
                       typeStr == "sha512" || typeStr == "hash") {
                type = IOCType::FileHash;
            } else if (typeStr == "email" || typeStr == "email-src" || typeStr == "email-dst") {
                type = IOCType::Email;
            }
        }
        
        if (type == IOCType::Reserved) {
            type = ThreatIntelImporter::DetectIOCType(value);
        }
        
        if (type == IOCType::Reserved) {
            return false;
        }
        
        entry.type = type;
        
        // Set value based on type
        if (type == IOCType::IPv4) {
            uint8_t octets[4] = {0};
            if (SafeParseIPv4(value, octets)) {
                entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
            } else {
                return false;
            }
        } else if (type == IOCType::FileHash) {
            HashAlgorithm algo = DetermineHashAlgo(value.length());
            
            // Override if typeStr was specific
            if (typeStr == "md5") algo = HashAlgorithm::MD5;
            else if (typeStr == "sha1") algo = HashAlgorithm::SHA1;
            else if (typeStr == "sha256") algo = HashAlgorithm::SHA256;
            else if (typeStr == "sha512") algo = HashAlgorithm::SHA512;
            
            // Validate hash length if not overridden by typeStr
            if (typeStr.empty() && !IsValidHashHexLength(value.length())) {
                return false;
            }
            
            entry.value.hash.algorithm = algo;
            
            const size_t byteLength = value.length() / 2;
            if (byteLength > sizeof(entry.value.hash.data) || byteLength > 255) {
                return false;
            }
            entry.value.hash.length = static_cast<uint8_t>(byteLength);
            
            if (!ParseHexString(value, entry.value.hash.data)) {
                return false;
            }
            entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
        } else {
            auto [offset, length] = stringPool->AddString(value);
            entry.value.stringRef.stringOffset = offset;
            entry.value.stringRef.stringLength = length;
            entry.valueType = static_cast<uint8_t>(type);
        }
        
        // Extract metadata with type safety
        if (j.contains("reputation") && j["reputation"].is_number_integer()) {
            int rep = j["reputation"].get<int>();
            entry.reputation = static_cast<ReputationLevel>(std::clamp(rep, 0, 100));
        }
        
        if (j.contains("confidence") && j["confidence"].is_number_integer()) {
            int conf = j["confidence"].get<int>();
            entry.confidence = static_cast<ConfidenceLevel>(std::clamp(conf, 0, 100));
        }
        
        if (j.contains("description") && j["description"].is_string()) {
            std::string desc = j["description"].get<std::string>();
            if (desc.length() <= UINT16_MAX) {
                auto [offset, length] = stringPool->AddString(desc);
                if (offset <= UINT32_MAX && length <= UINT16_MAX) {
                    entry.descriptionOffset = static_cast<uint32_t>(offset);
                    entry.descriptionLength = static_cast<uint16_t>(length);
                }
            }
        }
        
        // Timestamps
        if (j.contains("first_seen") && j["first_seen"].is_string()) {
            entry.firstSeen = ParseTimestamp(j["first_seen"].get<std::string>());
        }
        
        if (j.contains("last_seen") && j["last_seen"].is_string()) {
            entry.lastSeen = ParseTimestamp(j["last_seen"].get<std::string>());
        }
        
        return true;
    } catch (const json::exception& e) {
        m_lastError = std::string("JSON parse error: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("Exception: ") + e.what();
        return false;
    }
}

bool JSONImportReader::HasMoreEntries() const noexcept {
    if (m_isJsonLines) return !m_input.eof();
    return m_currentIndex < m_buffer.length();
}

std::optional<size_t> JSONImportReader::GetEstimatedTotal() const noexcept {
    if (m_totalEntries > 0) return m_totalEntries;
    return std::nullopt;
}

uint64_t JSONImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> JSONImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string JSONImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> JSONImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool JSONImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// STIX 2.1 Import Reader Implementation
// ============================================================================

STIX21ImportReader::STIX21ImportReader(std::istream& input)
    : m_input(input) {
}

STIX21ImportReader::~STIX21ImportReader() = default;

bool STIX21ImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_initialized = true;
    m_currentIndex = 0;
    
    try {
        // Maximum allowed STIX bundle size to prevent memory exhaustion
        constexpr size_t MAX_STIX_BUNDLE_SIZE = 512 * 1024 * 1024;  // 512MB
        
        // Load bundle with size check
        std::stringstream buffer;
        buffer << m_input.rdbuf();
        m_bundleContent = buffer.str();
        m_bytesRead = m_bundleContent.size();
        
        // Security check: prevent excessively large bundles
        if (m_bundleContent.size() > MAX_STIX_BUNDLE_SIZE) {
            m_lastError = "STIX bundle exceeds maximum allowed size";
            m_bundleContent.clear();
            return false;
        }
        
        // Check for empty content
        if (m_bundleContent.empty()) {
            m_lastError = "Empty STIX bundle input";
            return false;
        }
        
        return ParseBundle();
    } catch (const std::bad_alloc& e) {
        m_lastError = "Memory allocation failed during STIX bundle loading";
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("STIX initialization error: ") + e.what();
        return false;
    }
}

bool STIX21ImportReader::ParseBundle() {
    try {
        // Safety check for empty content
        if (m_bundleContent.empty()) {
            m_lastError = "Cannot parse empty STIX bundle";
            return false;
        }
        
        auto j = json::parse(m_bundleContent);
        
        // Validate bundle structure according to STIX 2.1 spec
        if (!j.contains("type") || !j["type"].is_string()) {
            m_lastError = "Invalid STIX 2.1 bundle: missing or invalid 'type' field";
            return false;
        }
        
        if (j["type"].get<std::string>() != "bundle") {
            m_lastError = "Invalid STIX 2.1 bundle: type must be 'bundle'";
            return false;
        }
        
        if (!j.contains("objects") || !j["objects"].is_array()) {
            m_lastError = "Invalid STIX 2.1 bundle: missing or invalid 'objects' array";
            return false;
        }
        
        m_totalObjects = j["objects"].size();
        
        // Sanity check on object count to prevent DoS
        constexpr size_t MAX_OBJECTS = 10'000'000;  // 10 million max
        if (m_totalObjects > MAX_OBJECTS) {
            m_lastError = "STIX bundle contains too many objects";
            return false;
        }
        
        return true;
    } catch (const json::parse_error& e) {
        m_lastError = std::string("STIX JSON parse error: ") + e.what();
        return false;
    } catch (const json::exception& e) {
        m_lastError = std::string("STIX JSON exception: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("STIX parse error: ") + e.what();
        return false;
    }
}

bool STIX21ImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (stringPool == nullptr) {
        m_lastError = "String pool is null";
        return false;
    }
    
    // Maximum recursion depth to prevent stack overflow
    constexpr int MAX_RECURSION_DEPTH = 1000;
    static thread_local int recursionDepth = 0;
    
    struct RecursionGuard {
        RecursionGuard() { ++recursionDepth; }
        ~RecursionGuard() { --recursionDepth; }
        bool exceeded() const { return recursionDepth > MAX_RECURSION_DEPTH; }
    } guard;
    
    if (guard.exceeded()) {
        m_lastError = "Maximum recursion depth exceeded";
        return false;
    }
    
    try {
        // We need to iterate through the objects array in the JSON
        // Similar to JSONImportReader, we'll use a tokenizer approach on m_bundleContent
        // to avoid re-parsing the whole bundle
        
        // Find "objects": [ ... ]
        if (m_currentIndex == 0) {
            size_t objectsPos = m_bundleContent.find("\"objects\"");
            if (objectsPos == std::string::npos) return false;
            size_t arrayStart = m_bundleContent.find('[', objectsPos);
            if (arrayStart == std::string::npos) return false;
            m_currentIndex = arrayStart + 1;
        }
        
        if (m_currentIndex >= m_bundleContent.length()) return false;
        
        // Find next object
        size_t start = m_bundleContent.find('{', m_currentIndex);
        if (start == std::string::npos) return false;
        
        // Find matching '}' with brace counting
        int braceCount = 0;
        size_t end = start;
        bool inString = false;
        bool escape = false;
        
        // Maximum object size to prevent excessive parsing
        constexpr size_t MAX_OBJECT_SIZE = 10 * 1024 * 1024;  // 10MB per object
        
        for (; end < m_bundleContent.length() && (end - start) < MAX_OBJECT_SIZE; ++end) {
            char c = m_bundleContent[end];
            if (escape) { escape = false; continue; }
            if (c == '\\') { escape = true; continue; }
            if (c == '"') { inString = !inString; continue; }
            if (!inString) {
                if (c == '{') braceCount++;
                else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        end++; // Include closing brace
                        break;
                    }
                }
            }
        }
        
        if (braceCount == 0 && end > start) {
            std::string objectJson = m_bundleContent.substr(start, end - start);
            m_currentIndex = end;
            
            // Check if this is an indicator or observable
            if (objectJson.find("\"indicator\"") != std::string::npos || 
                objectJson.find("\"observed-data\"") != std::string::npos) {
                return ParseIndicator(objectJson, entry, stringPool);
            } else {
                // Skip non-indicator objects (like relationships, identities)
                return ReadNextEntry(entry, stringPool); // Recursively try next
            }
        }
        
        m_currentIndex = m_bundleContent.length();
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("Error reading STIX entry: ") + e.what();
        return false;
    }
}

bool STIX21ImportReader::ParseIndicator(const std::string& indicatorJson, IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (indicatorJson.empty() || stringPool == nullptr) {
        return false;
    }
    
    try {
        auto j = json::parse(indicatorJson);
        
        // Validate type field
        if (!j.contains("type") || !j["type"].is_string()) {
            return false;
        }
        std::string type = j["type"].get<std::string>();
        
        if (type != "indicator") return false;
        
        // Validate pattern field
        std::string pattern;
        if (j.contains("pattern") && j["pattern"].is_string()) {
            pattern = j["pattern"].get<std::string>();
        }
        if (pattern.empty()) return false;
        
        // Maximum pattern length to prevent DoS
        constexpr size_t MAX_PATTERN_LENGTH = 1024 * 1024;  // 1MB
        if (pattern.length() > MAX_PATTERN_LENGTH) {
            m_lastError = "STIX pattern exceeds maximum length";
            return false;
        }
        
        // Initialize entry to safe defaults
        entry = IOCEntry{};
        
        // Parse STIX pattern
        if (!ParseSTIXPattern(pattern, entry, stringPool)) return false;
        
        // Extract metadata with type safety
        entry.source = m_options.defaultSource;
        
        if (j.contains("created") && j["created"].is_string()) {
            entry.createdTime = ParseISO8601Timestamp(j["created"].get<std::string>());
        }
        
        if (j.contains("valid_until") && j["valid_until"].is_string()) {
            entry.expirationTime = ParseISO8601Timestamp(j["valid_until"].get<std::string>());
        }
        
        if (j.contains("description") && j["description"].is_string()) {
            std::string desc = j["description"].get<std::string>();
            // Limit description length
            constexpr size_t MAX_DESC_LENGTH = 64 * 1024;  // 64KB
            if (desc.length() <= MAX_DESC_LENGTH) {
                auto [offset, length] = stringPool->AddString(desc);
                if (offset <= UINT32_MAX && length <= UINT16_MAX) {
                    entry.descriptionOffset = static_cast<uint32_t>(offset);
                    entry.descriptionLength = static_cast<uint16_t>(length);
                }
            }
        }
        
        if (j.contains("confidence") && j["confidence"].is_number_integer()) {
            int conf = j["confidence"].get<int>();
            entry.confidence = static_cast<ConfidenceLevel>(std::clamp(conf, 0, 100));
        }
        
        if (j.contains("id") && j["id"].is_string()) {
            std::string id = j["id"].get<std::string>();
            constexpr size_t MAX_ID_LENGTH = 256;  // STIX IDs are typically short
            if (id.length() <= MAX_ID_LENGTH) {
                auto [offset, length] = stringPool->AddString(id);
                if (offset <= UINT32_MAX && length <= UINT16_MAX) {
                    entry.stixIdOffset = static_cast<uint32_t>(offset);
                    entry.stixIdLength = static_cast<uint16_t>(length);
                }
            }
        }
        
        return true;
    } catch (const json::exception& e) {
        m_lastError = std::string("STIX indicator parse error: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("Exception parsing STIX indicator: ") + e.what();
        return false;
    }
}

bool STIX21ImportReader::ParseSTIXPattern(std::string_view pattern, IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (pattern.empty() || stringPool == nullptr) {
        return false;
    }
    
    // Maximum value length for security
    constexpr size_t MAX_VALUE_LENGTH = 64 * 1024;  // 64KB
    
    try {
        // Basic STIX pattern parser
        // Example: [ipv4-addr:value = '192.168.0.1']
        
        std::string p(pattern);
        std::smatch matches;
        
        // Regex for basic equality comparison
        static const std::regex stixRegex(R"(\[([a-zA-Z0-9\-]+):([a-zA-Z0-9_\.]+) ?= ?'([^']+)'\])");
        
        if (std::regex_search(p, matches, stixRegex)) {
            if (matches.size() >= 4) {
                std::string typeStr = matches[1].str();
                std::string property = matches[2].str();
                std::string value = matches[3].str();
                
                // Validate value length
                if (value.length() > MAX_VALUE_LENGTH) {
                    return false;
                }
                
                IOCType type = MapSTIXTypeToIOCType(typeStr);
                if (type == IOCType::Reserved) return false;
                
                entry.type = type;
                
                if (type == IOCType::IPv4) {
                    uint8_t octets[4] = {0};
                    if (SafeParseIPv4(value, octets)) {
                        entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                        entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
                    } else {
                        return false;
                    }
                } else if (type == IOCType::FileHash) {
                    HashAlgorithm algo = DetermineHashAlgo(value.length());
                    // Try to infer from property if possible (e.g. file:hashes.'SHA-256')
                    bool hasExplicitType = false;
                    if (property.find("MD5") != std::string::npos) { algo = HashAlgorithm::MD5; hasExplicitType = true; }
                    else if (property.find("SHA-1") != std::string::npos) { algo = HashAlgorithm::SHA1; hasExplicitType = true; }
                    else if (property.find("SHA-256") != std::string::npos) { algo = HashAlgorithm::SHA256; hasExplicitType = true; }
                    
                    // Validate hash length if no explicit type provided
                    if (!hasExplicitType && !IsValidHashHexLength(value.length())) {
                        return false;
                    }
                    
                    entry.value.hash.algorithm = algo;
                    
                    // Validate hash byte length fits in buffer
                    const size_t byteLength = value.length() / 2;
                    if (byteLength > sizeof(entry.value.hash.data) || byteLength > 255) {
                        return false;
                    }
                    entry.value.hash.length = static_cast<uint8_t>(byteLength);
                    
                    if (!ParseHexString(value, entry.value.hash.data)) {
                        return false;
                    }
                    entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
                } else {
                    auto [offset, length] = stringPool->AddString(value);
                    entry.value.stringRef.stringOffset = offset;
                    entry.value.stringRef.stringLength = length;
                    entry.valueType = static_cast<uint8_t>(type);
                }
                
                return true;
            }
        }
        
        return false;
    } catch (const std::regex_error& e) {
        // Regex errors should not occur with compile-time patterns, but handle anyway
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

IOCType STIX21ImportReader::MapSTIXTypeToIOCType(std::string_view stixType) const {
    if (stixType == "ipv4-addr") return IOCType::IPv4;
    if (stixType == "ipv6-addr") return IOCType::IPv6;
    if (stixType == "domain-name") return IOCType::Domain;
    if (stixType == "url") return IOCType::URL;
    if (stixType == "file") return IOCType::FileHash;
    if (stixType == "email-addr") return IOCType::Email;
    if (stixType == "windows-registry-key") return IOCType::RegistryKey;
    return IOCType::Reserved;
}

bool STIX21ImportReader::HasMoreEntries() const noexcept {
    return m_currentIndex < m_bundleContent.length();
}

std::optional<size_t> STIX21ImportReader::GetEstimatedTotal() const noexcept {
    if (m_totalObjects > 0) return m_totalObjects;
    return std::nullopt;
}

uint64_t STIX21ImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> STIX21ImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string STIX21ImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> STIX21ImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool STIX21ImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// MISP Import Reader Implementation
// ============================================================================

MISPImportReader::MISPImportReader(std::istream& input)
    : m_input(input) {
}

MISPImportReader::~MISPImportReader() = default;

bool MISPImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_initialized = true;
    m_currentIndex = 0;
    m_bytesRead = 0;
    
    // Note: MISP reader uses streaming parsing since it lacks a buffer member.
    // This is intentional to handle large MISP event files that might exceed memory.
    // Input stream will be read progressively in ReadNextEntry.
    
    return true;
}

bool MISPImportReader::ParseEvent() {
    // Placeholder for future event-level parsing if needed
    return true;
}

bool MISPImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (stringPool == nullptr) {
        m_lastError = "String pool is null";
        return false;
    }
    
    // Maximum buffer size to prevent memory exhaustion
    constexpr size_t MAX_OBJECT_BUFFER_SIZE = 10 * 1024 * 1024;  // 10MB per attribute object
    
    try {
        // Scan m_input for next JSON object
        // Look for { ... } inside the "Attribute" array
        
        // This is a simplified stream parser for MISP JSON
        char c = 0;
        std::string buffer;
        buffer.reserve(4096);  // Pre-allocate reasonable size
        
        int braceCount = 0;
        bool inString = false;
        bool escape = false;
        bool foundStart = false;
        
        while (m_input.get(c)) {
            m_bytesRead++;
            
            // Handle escape sequences
            if (escape) {
                escape = false;
                if (foundStart) buffer += c;
                continue;
            }
            if (c == '\\') {
                escape = true;
                if (foundStart) buffer += c;
                continue;
            }
            
            // Handle strings
            if (c == '"') {
                inString = !inString;
                if (foundStart) buffer += c;
                continue;
            }
            
            if (!inString) {
                if (c == '{') {
                    if (!foundStart) {
                        // Start of a new JSON object
                        foundStart = true;
                        buffer.clear();
                        buffer += c;
                        braceCount = 1;
                    } else {
                        braceCount++;
                        buffer += c;
                    }
                } else if (c == '}') {
                    if (foundStart) {
                        braceCount--;
                        buffer += c;
                        if (braceCount == 0) {
                            // Found complete object
                            if (ParseAttribute(buffer, entry, stringPool)) {
                                return true;
                            }
                            // If not a valid attribute, reset and continue scanning
                            buffer.clear();
                            foundStart = false;
                        }
                    }
                } else if (foundStart) {
                    buffer += c;
                    
                    // Security check: prevent buffer overflow
                    if (buffer.size() > MAX_OBJECT_BUFFER_SIZE) {
                        m_lastError = "MISP attribute object exceeds maximum size";
                        buffer.clear();
                        foundStart = false;
                        // Continue scanning for next valid object
                    }
                }
            } else if (foundStart) {
                buffer += c;
            }
        }
        
        return false;
    } catch (const std::bad_alloc& e) {
        m_lastError = "Memory allocation failed during MISP parsing";
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("MISP parse error: ") + e.what();
        return false;
    }
}

bool MISPImportReader::ParseAttribute(const std::string& attrJson, IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (attrJson.empty() || stringPool == nullptr) {
        return false;
    }
    
    try {
        auto j = json::parse(attrJson);
        
        // Check if it has required type and value fields with proper types
        if (!j.contains("type") || !j["type"].is_string()) return false;
        if (!j.contains("value") || !j["value"].is_string()) return false;
        
        std::string typeStr = j["type"].get<std::string>();
        std::string value = j["value"].get<std::string>();
        
        // Validate value length
        constexpr size_t MAX_VALUE_LENGTH = 64 * 1024;  // 64KB
        if (value.length() > MAX_VALUE_LENGTH) {
            return false;
        }
        
        IOCType type = MapMISPTypeToIOCType(typeStr);
        if (type == IOCType::Reserved) return false;
        
        // Initialize entry to safe defaults (using assignment instead of placement new)
        entry = IOCEntry{};
        entry.type = type;
        entry.source = m_options.defaultSource;
        entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
        entry.reputation = m_options.defaultReputation;
        entry.confidence = m_options.defaultConfidence;
        
        // Parse timestamp with proper type checking
        if (j.contains("timestamp")) {
            if (j["timestamp"].is_string()) {
                try {
                    std::string ts = j["timestamp"].get<std::string>();
                    // Validate it looks like a number
                    if (!ts.empty() && std::all_of(ts.begin(), ts.end(), ::isdigit)) {
                        entry.createdTime = std::stoull(ts);
                    }
                } catch (const std::exception&) {
                    // Keep default timestamp
                }
            } else if (j["timestamp"].is_number_unsigned()) {
                entry.createdTime = j["timestamp"].get<uint64_t>();
            } else if (j["timestamp"].is_number_integer()) {
                int64_t ts = j["timestamp"].get<int64_t>();
                if (ts >= 0) {
                    entry.createdTime = static_cast<uint64_t>(ts);
                }
            }
        }
        
        if (type == IOCType::IPv4) {
            uint8_t octets[4] = {0};
            if (SafeParseIPv4(value, octets)) {
                entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
            } else {
                return false;
            }
        } else if (type == IOCType::FileHash) {
            HashAlgorithm algo = DetermineHashAlgo(value.length());
            bool hasExplicitType = false;
            if (typeStr == "md5") { algo = HashAlgorithm::MD5; hasExplicitType = true; }
            else if (typeStr == "sha1") { algo = HashAlgorithm::SHA1; hasExplicitType = true; }
            else if (typeStr == "sha256") { algo = HashAlgorithm::SHA256; hasExplicitType = true; }
            
            // Validate hash length if no explicit type provided
            if (!hasExplicitType && !IsValidHashHexLength(value.length())) {
                return false;
            }
            
            entry.value.hash.algorithm = algo;
            
            // Validate hash byte length
            const size_t byteLength = value.length() / 2;
            if (byteLength > sizeof(entry.value.hash.data) || byteLength > 255) {
                return false;
            }
            entry.value.hash.length = static_cast<uint8_t>(byteLength);
            
            if (!ParseHexString(value, entry.value.hash.data)) {
                return false;
            }
            entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
        } else {
            auto [offset, length] = stringPool->AddString(value);
            entry.value.stringRef.stringOffset = offset;
            entry.value.stringRef.stringLength = length;
            entry.valueType = static_cast<uint8_t>(type);
        }
        
        // Parse comment/description with type checking and length validation
        if (j.contains("comment") && j["comment"].is_string()) {
            std::string comment = j["comment"].get<std::string>();
            constexpr size_t MAX_COMMENT_LENGTH = 64 * 1024;  // 64KB
            if (comment.length() <= MAX_COMMENT_LENGTH) {
                auto [offset, length] = stringPool->AddString(comment);
                if (offset <= UINT32_MAX && length <= UINT16_MAX) {
                    entry.descriptionOffset = static_cast<uint32_t>(offset);
                    entry.descriptionLength = static_cast<uint16_t>(length);
                }
            }
        }
        
        // Parse category with type checking
        if (j.contains("category") && j["category"].is_string()) {
            entry.category = MapMISPCategoryToThreatCategory(j["category"].get<std::string>());
        }
        
        return true;
    } catch (const json::exception& e) {
        m_lastError = std::string("MISP attribute parse error: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("Exception parsing MISP attribute: ") + e.what();
        return false;
    }
}

IOCType MISPImportReader::MapMISPTypeToIOCType(std::string_view mispType) const {
    if (mispType == "ip-dst" || mispType == "ip-src") return IOCType::IPv4;
    if (mispType == "domain") return IOCType::Domain;
    if (mispType == "url") return IOCType::URL;
    if (mispType == "md5") return IOCType::FileHash;
    if (mispType == "sha1") return IOCType::FileHash;
    if (mispType == "sha256") return IOCType::FileHash;
    if (mispType == "email-src" || mispType == "email-dst") return IOCType::Email;
    if (mispType == "filename") return IOCType::Reserved;
    return IOCType::Reserved;
}

ThreatCategory MISPImportReader::MapMISPCategoryToThreatCategory(std::string_view mispCategory) const {
    if (mispCategory == "Payload delivery") return ThreatCategory::Malware;
    if (mispCategory == "Network activity") return ThreatCategory::C2Server;
    if (mispCategory == "Financial fraud") return ThreatCategory::Phishing;
    return ThreatCategory::Unknown;
}

bool MISPImportReader::HasMoreEntries() const noexcept {
    return !m_input.eof();
}

std::optional<size_t> MISPImportReader::GetEstimatedTotal() const noexcept {
    return std::nullopt;
}

uint64_t MISPImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> MISPImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string MISPImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> MISPImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool MISPImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// Plain Text Import Reader Implementation
// ============================================================================

PlainTextImportReader::PlainTextImportReader(std::istream& input)
    : m_input(input) {
}

PlainTextImportReader::~PlainTextImportReader() = default;

bool PlainTextImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_initialized = true;
    m_currentLine = 0;
    m_bytesRead = 0;
    return true;
}

bool PlainTextImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (stringPool == nullptr) {
        m_lastError = "String pool is null";
        return false;
    }
    
    if (m_endOfInput) return false;
    
    // Maximum line length to prevent DoS
    constexpr size_t MAX_LINE_LENGTH = 1024 * 1024;  // 1MB
    
    try {
        std::string line;
        line.reserve(256);  // Pre-allocate reasonable size
        
        while (std::getline(m_input, line)) {
            m_currentLine++;
            m_bytesRead += line.length() + 1;
            
            // Security check: skip excessively long lines
            if (line.length() > MAX_LINE_LENGTH) {
                m_lastError = "Line exceeds maximum length";
                continue;  // Skip this line
            }
            
            // Handle Windows CRLF
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            
            // Trim whitespace safely
            size_t first = line.find_first_not_of(" \t");
            if (first == std::string::npos) continue; // Empty line
            
            size_t last = line.find_last_not_of(" \t");
            if (last < first) continue;  // Shouldn't happen, but be safe
            
            line = line.substr(first, (last - first + 1));
            
            // Skip empty lines after trimming
            if (line.empty()) continue;
            
            // Skip comments
            if (!m_options.csvConfig.commentPrefix.empty() && 
                line.find(m_options.csvConfig.commentPrefix) == 0) {
                continue;
            }
            
            if (ParseLine(line, entry, stringPool)) {
                return true;
            }
        }
        
        m_endOfInput = true;
        return false;
    } catch (const std::bad_alloc& e) {
        m_lastError = "Memory allocation failed during plain text parsing";
        m_endOfInput = true;
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("Plain text parse error: ") + e.what();
        m_endOfInput = true;
        return false;
    }
}

bool PlainTextImportReader::ParseLine(std::string_view line, IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (line.empty() || stringPool == nullptr) {
        return false;
    }
    
    // Maximum IOC value length
    constexpr size_t MAX_IOC_LENGTH = 64 * 1024;  // 64KB
    if (line.length() > MAX_IOC_LENGTH) {
        return false;
    }
    
    try {
        // Detect type
        IOCType type = DetectIOCType(line);
        if (type == IOCType::Reserved) return false;
        
        // Initialize entry using assignment (safer than placement new)
        entry = IOCEntry{};
        entry.type = type;
        entry.source = m_options.defaultSource;
        entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
        entry.reputation = m_options.defaultReputation;
        entry.confidence = m_options.defaultConfidence;
        
        if (type == IOCType::IPv4) {
            uint8_t octets[4] = {0};
            if (SafeParseIPv4(line, octets)) {
                entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
            } else {
                return false;
            }
        } else if (type == IOCType::FileHash) {
            // Validate hash length
            if (!IsValidHashHexLength(line.length())) {
                return false;
            }
            HashAlgorithm algo = DetermineHashAlgo(line.length());
            
            entry.value.hash.algorithm = algo;
            
            // Validate hash byte length
            const size_t byteLength = line.length() / 2;
            if (byteLength > sizeof(entry.value.hash.data) || byteLength > 255) {
                return false;
            }
            entry.value.hash.length = static_cast<uint8_t>(byteLength);
            
            if (!ParseHexString(line, entry.value.hash.data)) {
                return false;
            }
            entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
        } else {
            auto [offset, length] = stringPool->AddString(line);
            entry.value.stringRef.stringOffset = offset;
            entry.value.stringRef.stringLength = length;
            entry.valueType = static_cast<uint8_t>(type);
        }
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

IOCType PlainTextImportReader::DetectIOCType(std::string_view value) const {
    if (IsIPv4Address(value)) return IOCType::IPv4;
    if (IsMD5Hash(value)) return IOCType::FileHash;
    if (IsSHA1Hash(value)) return IOCType::FileHash;
    if (IsSHA256Hash(value)) return IOCType::FileHash;
    if (IsDomain(value)) return IOCType::Domain;
    if (IsURL(value)) return IOCType::URL;
    if (IsEmail(value)) return IOCType::Email;
    return IOCType::Reserved;
}

bool PlainTextImportReader::IsIPv4Address(std::string_view value) const {
    static const std::regex r(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    return std::regex_match(value.begin(), value.end(), r);
}

bool PlainTextImportReader::IsIPv6Address(std::string_view value) const {
    // Simplified check
    return value.find(':') != std::string::npos;
}

bool PlainTextImportReader::IsDomain(std::string_view value) const {
    static const std::regex r(R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$)");
    return std::regex_match(value.begin(), value.end(), r);
}

bool PlainTextImportReader::IsURL(std::string_view value) const {
    return value.find("http://") == 0 || value.find("https://") == 0;
}

bool PlainTextImportReader::IsMD5Hash(std::string_view value) const {
    static const std::regex r(R"(^[a-fA-F0-9]{32}$)");
    return std::regex_match(value.begin(), value.end(), r);
}

bool PlainTextImportReader::IsSHA1Hash(std::string_view value) const {
    static const std::regex r(R"(^[a-fA-F0-9]{40}$)");
    return std::regex_match(value.begin(), value.end(), r);
}

bool PlainTextImportReader::IsSHA256Hash(std::string_view value) const {
    static const std::regex r(R"(^[a-fA-F0-9]{64}$)");
    return std::regex_match(value.begin(), value.end(), r);
}

bool PlainTextImportReader::IsEmail(std::string_view value) const {
    return value.find('@') != std::string::npos;
}

bool PlainTextImportReader::HasMoreEntries() const noexcept {
    return !m_endOfInput;
}

std::optional<size_t> PlainTextImportReader::GetEstimatedTotal() const noexcept {
    return std::nullopt;
}

uint64_t PlainTextImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> PlainTextImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string PlainTextImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> PlainTextImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool PlainTextImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// OpenIOC Import Reader Implementation
// ============================================================================

OpenIOCImportReader::OpenIOCImportReader(std::istream& input)
    : m_input(input) {
}

OpenIOCImportReader::~OpenIOCImportReader() = default;

bool OpenIOCImportReader::Initialize(const ImportOptions& options) {
    m_options = options;
    m_initialized = true;
    m_currentIndex = 0;
    m_bytesRead = 0;
    
    try {
        return ParseDocument();
    } catch (const std::exception& e) {
        m_lastError = std::string("OpenIOC initialization error: ") + e.what();
        return false;
    }
}

bool OpenIOCImportReader::ParseDocument() {
    try {
        // Maximum allowed OpenIOC document size
        constexpr size_t MAX_OPENIOC_SIZE = 256 * 1024 * 1024;  // 256MB
        
        // OpenIOC is XML, we need to parse the whole document
        // Using pugixml
        std::stringstream buffer;
        buffer << m_input.rdbuf();
        std::string content = buffer.str();
        m_bytesRead = content.size();
        
        // Security check: prevent excessively large documents
        if (content.size() > MAX_OPENIOC_SIZE) {
            m_lastError = "OpenIOC document exceeds maximum allowed size";
            return false;
        }
        
        if (content.empty()) {
            m_lastError = "Empty OpenIOC document";
            return false;
        }
        
        // Validate XML structure
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_string(content.c_str());
        
        if (!result) {
            m_lastError = std::string("XML parse error: ") + result.description();
            return false;
        }
        
        // Note: Since we can't store the pugi::xml_document in the class,
        // we use a streaming approach in ReadNextEntry.
        // This is less efficient but necessary given the interface constraints.
        
        return true;
    } catch (const std::bad_alloc& e) {
        m_lastError = "Memory allocation failed during OpenIOC parsing";
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("OpenIOC parse error: ") + e.what();
        return false;
    }
}

bool OpenIOCImportReader::ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) {
    // Input validation
    if (stringPool == nullptr) {
        m_lastError = "String pool is null";
        return false;
    }
    
    // Maximum buffer size for a single indicator item
    constexpr size_t MAX_ITEM_BUFFER_SIZE = 1024 * 1024;  // 1MB per item
    
    try {
        // Scan for <IndicatorItem> ... </IndicatorItem>
        std::string buffer;
        buffer.reserve(4096);
        
        char c = 0;
        bool foundStart = false;
        std::string tag;
        tag.reserve(64);
        bool inTag = false;
        
        // This is a streaming XML scanner
        while (m_input.get(c)) {
            m_bytesRead++;
            
            if (c == '<') {
                inTag = true;
                tag.clear();
            } else if (c == '>') {
                inTag = false;
                if (tag == "IndicatorItem" || tag.find("IndicatorItem ") == 0) {
                    foundStart = true;
                    buffer = "<IndicatorItem>";
                } else if (tag == "/IndicatorItem") {
                    if (foundStart) {
                        buffer += "</IndicatorItem>";
                        
                        // Parse the item
                        pugi::xml_document doc;
                        if (doc.load_string(buffer.c_str())) {
                            auto item = doc.child("IndicatorItem");
                            auto context = item.child("Context");
                            auto content = item.child("Content");
                            
                            if (context && content) {
                                std::string search = context.attribute("search").as_string();
                                std::string value = content.text().as_string();
                                
                                // Validate value length
                                constexpr size_t MAX_VALUE_LENGTH = 64 * 1024;  // 64KB
                                if (value.length() > MAX_VALUE_LENGTH) {
                                    foundStart = false;
                                    buffer.clear();
                                    continue;
                                }
                                
                                IOCType type = MapOpenIOCSearchToIOCType(search);
                                if (type != IOCType::Reserved && !value.empty()) {
                                    // Initialize entry using assignment (safer than placement new)
                                    entry = IOCEntry{};
                                    entry.type = type;
                                    entry.source = m_options.defaultSource;
                                    entry.createdTime = static_cast<uint64_t>(std::time(nullptr));
                                    entry.reputation = m_options.defaultReputation;
                                    entry.confidence = m_options.defaultConfidence;
                                    
                                    if (type == IOCType::IPv4) {
                                        uint8_t octets[4] = {0};
                                        if (SafeParseIPv4(value, octets)) {
                                            entry.value.ipv4 = IPv4Address(octets[0], octets[1], octets[2], octets[3]);
                                            entry.valueType = static_cast<uint8_t>(IOCType::IPv4);
                                        } else {
                                            foundStart = false;
                                            buffer.clear();
                                            continue;  // Skip invalid IPv4
                                        }
                                    } else if (type == IOCType::FileHash) {
                                        HashAlgorithm algo = DetermineHashAlgo(value.length());
                                        bool hasExplicitType = false;
                                        if (search.find("Md5") != std::string::npos) { algo = HashAlgorithm::MD5; hasExplicitType = true; }
                                        else if (search.find("Sha1") != std::string::npos) { algo = HashAlgorithm::SHA1; hasExplicitType = true; }
                                        else if (search.find("Sha256") != std::string::npos) { algo = HashAlgorithm::SHA256; hasExplicitType = true; }
                                        
                                        // Validate hash length if no explicit type
                                        if (!hasExplicitType && !IsValidHashHexLength(value.length())) {
                                            foundStart = false;
                                            buffer.clear();
                                            continue;
                                        }
                                        
                                        entry.value.hash.algorithm = algo;
                                        
                                        // Validate hash byte length
                                        const size_t byteLength = value.length() / 2;
                                        if (byteLength > sizeof(entry.value.hash.data) || byteLength > 255) {
                                            foundStart = false;
                                            buffer.clear();
                                            continue;
                                        }
                                        entry.value.hash.length = static_cast<uint8_t>(byteLength);
                                        
                                        if (!ParseHexString(value, entry.value.hash.data)) {
                                            foundStart = false;
                                            buffer.clear();
                                            continue;  // Skip invalid hash
                                        }
                                        entry.valueType = static_cast<uint8_t>(IOCType::FileHash);
                                    } else {
                                        auto [offset, length] = stringPool->AddString(value);
                                        entry.value.stringRef.stringOffset = offset;
                                        entry.value.stringRef.stringLength = length;
                                        entry.valueType = static_cast<uint8_t>(type);
                                    }
                                    return true;
                                }
                            }
                        }
                        foundStart = false;
                        buffer.clear();
                    }
                }
            }
            
            if (foundStart) {
                buffer += c;
                
                // Security check: prevent buffer overflow
                if (buffer.size() > MAX_ITEM_BUFFER_SIZE) {
                    m_lastError = "OpenIOC indicator item exceeds maximum size";
                    buffer.clear();
                    foundStart = false;
                }
            } else if (inTag) {
                tag += c;
                
                // Limit tag name size
                if (tag.size() > 256) {
                    tag.clear();
                }
            }
        }
        
        return false;
    } catch (const std::bad_alloc& e) {
        m_lastError = "Memory allocation failed during OpenIOC parsing";
        return false;
    } catch (const std::exception& e) {
        m_lastError = std::string("OpenIOC parse error: ") + e.what();
        return false;
    }
}

IOCType OpenIOCImportReader::MapOpenIOCSearchToIOCType(std::string_view search) const {
    if (search.find("IP/IPv4Address") != std::string::npos) return IOCType::IPv4;
    if (search.find("DnsEntry/Host") != std::string::npos) return IOCType::Domain;
    if (search.find("File/Md5") != std::string::npos) return IOCType::FileHash;
    if (search.find("File/Sha1") != std::string::npos) return IOCType::FileHash;
    if (search.find("File/Sha256") != std::string::npos) return IOCType::FileHash;
    if (search.find("Email/From") != std::string::npos) return IOCType::Email;
    return IOCType::Reserved;
}

bool OpenIOCImportReader::HasMoreEntries() const noexcept {
    return !m_input.eof();
}

std::optional<size_t> OpenIOCImportReader::GetEstimatedTotal() const noexcept {
    return std::nullopt;
}

uint64_t OpenIOCImportReader::GetBytesRead() const noexcept {
    return m_bytesRead;
}

std::optional<uint64_t> OpenIOCImportReader::GetTotalBytes() const noexcept {
    return std::nullopt;
}

std::string OpenIOCImportReader::GetLastError() const {
    return m_lastError;
}

std::optional<ParseError> OpenIOCImportReader::GetLastParseError() const {
    return m_lastParseError;
}

bool OpenIOCImportReader::Reset() {
    m_input.clear();
    m_input.seekg(0);
    return Initialize(m_options);
}

// ============================================================================
// ThreatIntelImporter Implementation
// ============================================================================

ThreatIntelImporter::ThreatIntelImporter() = default;
ThreatIntelImporter::~ThreatIntelImporter() = default;
ThreatIntelImporter::ThreatIntelImporter(ThreatIntelImporter&&) noexcept = default;
ThreatIntelImporter& ThreatIntelImporter::operator=(ThreatIntelImporter&&) noexcept = default;

ImportResult ThreatIntelImporter::ImportFromFile(
    ThreatIntelDatabase& database,
    const std::wstring& inputPath,
    const ImportOptions& options,
    ImportProgressCallback progressCallback
) {
    ImportResult result;
    
    try {
        // Validate input path
        if (inputPath.empty()) {
            result.success = false;
            result.errorMessage = "Empty input file path";
            return result;
        }
        
        // Check if file exists
        std::error_code ec;
        if (!fs::exists(inputPath, ec)) {
            result.success = false;
            result.errorMessage = "Input file does not exist";
            return result;
        }
        
        // Open file
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) {
            result.success = false;
            result.errorMessage = "Failed to open input file";
            return result;
        }
        
        ImportOptions opts = options;
        if (opts.format == ImportFormat::Auto) {
            opts.format = DetectFormatFromExtension(inputPath);
            if (opts.format == ImportFormat::Auto) {
                opts.format = DetectFormatFromContent(file);
                file.clear();
                file.seekg(0);
            }
        }
        
        auto reader = CreateReader(file, opts.format);
        if (!reader) {
            result.success = false;
            result.errorMessage = "Unsupported format or failed to create reader";
            return result;
        }
        
        return DoImportToDatabase(*reader, database, opts, progressCallback);
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = std::string("Import file error: ") + e.what();
        return result;
    }
}

ImportResult ThreatIntelImporter::ImportFromStream(
    ThreatIntelDatabase& database,
    std::istream& input,
    const ImportOptions& options,
    ImportProgressCallback progressCallback
) {
    ImportResult result;
    
    try {
        // Validate input stream
        if (!input.good()) {
            result.success = false;
            result.errorMessage = "Invalid input stream";
            return result;
        }
        
        auto reader = CreateReader(input, options.format);
        if (!reader) {
            result.success = false;
            result.errorMessage = "Unsupported format or failed to create reader";
            return result;
        }
        
        return DoImportToDatabase(*reader, database, options, progressCallback);
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = std::string("Import stream error: ") + e.what();
        return result;
    }
}

ImportResult ThreatIntelImporter::DoImportToDatabase(
    IImportReader& reader,
    ThreatIntelDatabase& database,
    const ImportOptions& options,
    ImportProgressCallback progressCallback
) {
    ImportResult result;
    auto startTime = std::chrono::steady_clock::now();
    
    try {
        if (!reader.Initialize(options)) {
            result.success = false;
            result.errorMessage = reader.GetLastError();
            return result;
        }
        
        // Database string pool adapter
        class DBStringPoolAdapter : public IStringPoolWriter {
            ThreatIntelDatabase& m_db;
        public:
            explicit DBStringPoolAdapter(ThreatIntelDatabase& db) : m_db(db) {}
            std::pair<uint64_t, uint32_t> AddString(std::string_view str) override {
                // Placeholder - actual implementation depends on ThreatIntelDatabase API
                return {0, static_cast<uint32_t>(str.length())};
            }
            std::optional<std::pair<uint64_t, uint32_t>> FindString(std::string_view str) const override {
                return std::nullopt;
            }
            uint64_t GetPoolSize() const noexcept override { return 0; }
        };
        
        DBStringPoolAdapter stringPool(database);
        
        // Validate batch size
        const size_t batchSize = (options.batchSize > 0 && options.batchSize <= 100000) 
            ? options.batchSize : 1000;
        
        std::vector<IOCEntry> batch;
        batch.reserve(batchSize);
        
        IOCEntry entry;
        ImportProgress progress{};
        progress.totalEntries = reader.GetEstimatedTotal().value_or(0);
        
        // Maximum entries to prevent DoS (configurable via options if needed)
        constexpr size_t MAX_TOTAL_ENTRIES = 100'000'000;  // 100 million
        
        while (reader.ReadNextEntry(entry, &stringPool)) {
            // Check cancellation
            if (m_cancellationRequested) {
                result.wasCancelled = true;
                break;
            }
            
            result.totalParsed++;
            
            // Safety limit check
            if (result.totalParsed > MAX_TOTAL_ENTRIES) {
                result.errorMessage = "Maximum entry count exceeded";
                break;
            }
            
            if (ValidateEntry(entry, options)) {
                NormalizeEntry(entry, options, &stringPool);
                batch.push_back(entry);
                
                if (batch.size() >= batchSize) {
                    // Insert batch
                    // database.AddIOCs(batch);
                    result.totalImported += batch.size();
                    batch.clear();
                    
                    // Update progress
                    if (progressCallback) {
                        UpdateProgress(progress, result.totalParsed, progress.totalEntries, 
                                       reader.GetBytesRead(), 0, startTime);
                        if (!progressCallback(progress)) {
                            m_cancellationRequested = true;
                        }
                    }
                }
            } else {
                result.totalValidationFailures++;
            }
        }
        
        // Insert remaining entries
        if (!batch.empty() && !result.wasCancelled) {
            // database.AddIOCs(batch);
            result.totalImported += batch.size();
        }
        
        result.success = !result.wasCancelled && result.errorMessage.empty();
        result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        return result;
    } catch (const std::bad_alloc& e) {
        result.success = false;
        result.errorMessage = "Memory allocation failed during import";
        return result;
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = std::string("Import error: ") + e.what();
        return result;
    }
}

std::unique_ptr<IImportReader> ThreatIntelImporter::CreateReader(std::istream& input, ImportFormat format) {
    switch (format) {
        case ImportFormat::CSV: return std::make_unique<CSVImportReader>(input);
        case ImportFormat::JSON: return std::make_unique<JSONImportReader>(input);
        case ImportFormat::JSONL: return std::make_unique<JSONImportReader>(input); // JSONReader handles JSONL
        case ImportFormat::STIX21: return std::make_unique<STIX21ImportReader>(input);
        case ImportFormat::MISP: return std::make_unique<MISPImportReader>(input);
        case ImportFormat::PlainText: return std::make_unique<PlainTextImportReader>(input);
        case ImportFormat::OpenIOC: return std::make_unique<OpenIOCImportReader>(input);
        default: return nullptr;
    }
}

bool ThreatIntelImporter::ValidateEntry(IOCEntry& entry, const ImportOptions& options) {
    if (options.validationLevel == ValidationLevel::None) return true;
    
    if (entry.type == IOCType::Reserved) return false;
    
    // Check allowed types
    if (!options.allowedIOCTypes.empty()) {
        bool allowed = false;
        for (auto t : options.allowedIOCTypes) {
            if (t == entry.type) { allowed = true; break; }
        }
        if (!allowed) return false;
    }
    
    return true;
}

void ThreatIntelImporter::NormalizeEntry(IOCEntry& entry, const ImportOptions& options, IStringPoolWriter* stringPool) {
    // Normalization logic
}

void ThreatIntelImporter::UpdateProgress(
    ImportProgress& progress,
    size_t currentEntry,
    size_t totalEntries,
    uint64_t bytesRead,
    uint64_t totalBytes,
    const std::chrono::steady_clock::time_point& startTime
) {
    progress.parsedEntries = currentEntry;
    progress.bytesRead = bytesRead;
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
    
    // Clamp elapsed time to prevent overflow in calculations
    progress.elapsedMs = static_cast<uint64_t>(std::max(0LL, elapsed));
    
    // Calculate rate safely
    if (elapsed > 0 && currentEntry > 0) {
        // Use uint64_t for intermediate calculation to prevent overflow
        progress.entriesPerSecond = static_cast<double>(currentEntry) * 1000.0 / static_cast<double>(elapsed);
        
        // Sanity check - cap at reasonable max rate
        constexpr double MAX_RATE = 100'000'000.0;  // 100M entries/sec max
        if (progress.entriesPerSecond > MAX_RATE) {
            progress.entriesPerSecond = MAX_RATE;
        }
    } else {
        progress.entriesPerSecond = 0.0;
    }
    
    // Calculate percent complete safely
    if (totalEntries > 0 && currentEntry <= totalEntries) {
        progress.percentComplete = static_cast<double>(currentEntry) * 100.0 / static_cast<double>(totalEntries);
        
        // Clamp to valid range
        progress.percentComplete = std::clamp(progress.percentComplete, 0.0, 100.0);
    } else if (totalEntries == 0) {
        // Unknown total - use indeterminate progress
        progress.percentComplete = -1.0;
    }
}

ImportFormat ThreatIntelImporter::DetectFormatFromExtension(const std::wstring& filePath) {
    try {
        if (filePath.empty()) {
            return ImportFormat::Auto;
        }
        
        fs::path path(filePath);
        std::string ext = path.extension().string();
        
        // Limit extension length for security
        if (ext.length() > 16) {
            return ImportFormat::Auto;
        }
        
        std::transform(ext.begin(), ext.end(), ext.begin(), 
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        
        if (ext == ".csv") return ImportFormat::CSV;
        if (ext == ".json") return ImportFormat::JSON;
        if (ext == ".jsonl") return ImportFormat::JSONL;
        if (ext == ".xml" || ext == ".ioc") return ImportFormat::OpenIOC;
        if (ext == ".txt") return ImportFormat::PlainText;
        
        return ImportFormat::Auto;
    } catch (const std::exception&) {
        return ImportFormat::Auto;
    }
}

ImportFormat ThreatIntelImporter::DetectFormatFromContent(std::istream& content, size_t maxBytes) {
    try {
        // Validate stream
        if (!content.good()) {
            return ImportFormat::PlainText;
        }
        
        // Use reasonable buffer size, respecting maxBytes if provided
        constexpr size_t DEFAULT_PROBE_SIZE = 1024;
        const size_t probeSize = (maxBytes > 0 && maxBytes < DEFAULT_PROBE_SIZE) ? maxBytes : DEFAULT_PROBE_SIZE;
        
        // Peek at content
        std::vector<char> buffer(probeSize);
        content.read(buffer.data(), static_cast<std::streamsize>(probeSize));
        size_t read = static_cast<size_t>(content.gcount());
        
        // Restore stream position
        content.clear();
        content.seekg(0);
        
        if (read == 0) {
            return ImportFormat::PlainText;
        }
        
        std::string_view data(buffer.data(), read);
        
        // Look for format signatures with priority ordering
        // JSON: starts with { or [
        if (data.find("{") != std::string::npos && data.find("}") != std::string::npos) {
            return ImportFormat::JSON;
        }
        
        // XML/OpenIOC: starts with < and has >
        if (data.find("<") != std::string::npos && data.find(">") != std::string::npos) {
            return ImportFormat::OpenIOC;
        }
        
        // CSV: has commas (simple heuristic)
        if (data.find(",") != std::string::npos) {
            return ImportFormat::CSV;
        }
        
        return ImportFormat::PlainText;
    } catch (const std::exception&) {
        return ImportFormat::PlainText;
    }
}

IOCType ThreatIntelImporter::DetectIOCType(std::string_view value) {
    // Input validation
    if (value.empty()) {
        return IOCType::Reserved;
    }
    
    // Maximum IOC length to process
    constexpr size_t MAX_IOC_LENGTH = 64 * 1024;  // 64KB
    if (value.length() > MAX_IOC_LENGTH) {
        return IOCType::Reserved;
    }
    
    try {
        // Check for hash patterns first (most specific)
        if (value.length() == 32 || value.length() == 40 || value.length() == 64 || value.length() == 128) {
            bool allHex = std::all_of(value.begin(), value.end(), 
                [](unsigned char c) { return std::isxdigit(c); });
            if (allHex) {
                return IOCType::FileHash;
            }
        }
        
        // Check for URL
        if (value.find("http://") == 0 || value.find("https://") == 0) {
            return IOCType::URL;
        }
        
        // Check for email
        if (value.find('@') != std::string::npos) {
            return IOCType::Email;
        }
        
        // Check for IP or Domain
        if (value.find('.') != std::string::npos) {
            // Could be IP or Domain
            if (!value.empty() && std::isdigit(static_cast<unsigned char>(value[0]))) {
                // Likely IPv4 - validate format
                int dots = 0;
                bool valid = true;
                for (char c : value) {
                    if (c == '.') {
                        dots++;
                    } else if (!std::isdigit(static_cast<unsigned char>(c))) {
                        valid = false;
                        break;
                    }
                }
                if (valid && dots == 3) {
                    return IOCType::IPv4;
                }
            }
            // Assume domain
            return IOCType::Domain;
        }
        
        // Check for IPv6 (contains colons)
        if (value.find(':') != std::string::npos) {
            return IOCType::IPv6;
        }
        
        return IOCType::Reserved;
    } catch (const std::exception&) {
        return IOCType::Reserved;
    }
}

} // namespace ThreatIntel
} // namespace ShadowStrike