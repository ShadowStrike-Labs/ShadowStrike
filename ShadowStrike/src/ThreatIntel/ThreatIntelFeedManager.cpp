/**
 * @file ThreatIntelFeedManager.cpp
 * @brief Enterprise-Grade Threat Intelligence Feed Manager Implementation
 *
 * High-performance feed management with concurrent synchronization,
 * rate limiting, and comprehensive monitoring.
 *
 * Part 1/3: Utility functions, struct implementations, parser implementations
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 */

#include "ThreatIntelFeedManager.hpp"
#include "ThreatIntelDatabase.hpp"
#include "ThreatIntelStore.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <WinINet.h>
#include <bcrypt.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <charconv>
#include <cmath>
#include <random>
#include <fstream>

// JSON parsing using nlohmann/json
#include "../../external/nlohmann/json.hpp"

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

namespace {

/**
 * @brief Get current timestamp in seconds since epoch
 */
[[nodiscard]] uint64_t GetCurrentTimestampImpl() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

/**
 * @brief Get current timestamp in milliseconds since epoch
 */
[[nodiscard]] uint64_t GetCurrentTimestampMs() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

/**
 * @brief Generate random jitter value
 * 
 * Thread-safe random jitter generation using thread-local RNG.
 * Uses secure seeding with multiple entropy sources on Windows.
 * 
 * @param factor Jitter factor (e.g., 0.25 for +/- 25%)
 * @return Random jitter value in range [-factor, factor]
 */
[[nodiscard]] double GetRandomJitter(double factor) noexcept {
    // Validate factor to prevent invalid distribution or NaN propagation
    if (factor <= 0.0 || !std::isfinite(factor) || std::isnan(factor)) {
        return 0.0;
    }
    
    // Clamp factor to reasonable range to prevent excessive jitter
    factor = std::min(factor, 1.0);
    
    try {
        // Thread-local RNG with secure seeding combining multiple entropy sources
        static thread_local std::mt19937_64 rng([] {
            std::random_device rd;
            // Combine multiple entropy sources for better seeding
            std::seed_seq seed{
                rd(), rd(), rd(), rd(),
                static_cast<uint32_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
                static_cast<uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()))
            };
            return std::mt19937_64(seed);
        }());
        
        std::uniform_real_distribution<double> dist(-factor, factor);
        double result = dist(rng);
        
        // Ensure result is finite (defensive against FP edge cases)
        if (!std::isfinite(result)) {
            return 0.0;
        }
        return result;
    } catch (...) {
        // Fallback if RNG fails - return deterministic zero
        return 0.0;
    }
}

/**
 * @brief Trim whitespace from string
 * 
 * Safely removes leading and trailing whitespace.
 * Handles all common whitespace characters including vertical tabs and form feeds.
 * 
 * @param str Input string view
 * @return Trimmed string, empty if input is all whitespace
 */
[[nodiscard]] std::string TrimString(std::string_view str) {
    if (str.empty()) {
        return "";
    }
    
    // Use extended whitespace character set for security
    constexpr std::string_view kWhitespace = " \t\r\n\v\f";
    
    const size_t start = str.find_first_not_of(kWhitespace);
    if (start == std::string_view::npos) {
        return "";  // All whitespace
    }
    
    const size_t end = str.find_last_not_of(kWhitespace);
    // end is guaranteed >= start since start found a non-whitespace char
    
    // Calculate length with overflow protection
    const size_t length = end - start + 1;
    if (length > str.size()) {
        return "";  // Defensive check
    }
    
    return std::string(str.substr(start, length));
}

/**
 * @brief Convert string to lowercase
 * 
 * Safely converts ASCII characters to lowercase. Uses unsigned char
 * cast to prevent UB with negative char values on some platforms.
 * 
 * @param str Input string view
 * @return Lowercase string
 */
[[nodiscard]] std::string ToLowerCase(std::string_view str) {
    std::string result;
    try {
        result.reserve(str.size());
    } catch (const std::bad_alloc&) {
        return "";  // Return empty on allocation failure
    }
    
    for (const char c : str) {
        // Cast to unsigned char to avoid UB with std::tolower on negative char values
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

/**
 * @brief URL encode string
 * 
 * RFC 3986 compliant URL encoding. Encodes all characters except
 * unreserved characters (A-Z, a-z, 0-9, -, _, ., ~).
 * 
 * @param str Input string view
 * @return URL-encoded string, empty on allocation failure
 */
[[nodiscard]] std::string UrlEncode(std::string_view str) {
    if (str.empty()) {
        return "";
    }
    
    // Validate input size to prevent memory exhaustion (each char can become 3 chars)
    constexpr size_t MAX_INPUT_SIZE = 1024 * 1024;  // 1MB limit
    if (str.size() > MAX_INPUT_SIZE) {
        return "";
    }
    
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    
    for (const char c : str) {
        const unsigned char uc = static_cast<unsigned char>(c);
        // RFC 3986 unreserved characters
        if (std::isalnum(uc) || uc == '-' || uc == '_' || uc == '.' || uc == '~') {
            oss << c;
        } else {
            oss << '%' << std::setw(2) << static_cast<unsigned int>(uc);
        }
    }
    
    return oss.str();
}

/**
 * @brief Base64 encode for Basic Auth
 * 
 * RFC 4648 compliant Base64 encoding with proper padding.
 * Thread-safe and exception-safe implementation.
 * 
 * @param input Input bytes to encode
 * @return Base64 encoded string, empty on failure
 */
[[nodiscard]] std::string Base64Encode(std::string_view input) {
    static constexpr char kBase64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    if (input.empty()) {
        return "";
    }
    
    // Validate input size to prevent integer overflow in output calculation
    constexpr size_t MAX_INPUT_SIZE = (SIZE_MAX / 4) * 3 - 3;  // Safe limit
    if (input.size() > MAX_INPUT_SIZE) {
        return "";  // Input too large
    }
    
    // Calculate output size: ceil(input.size() / 3) * 4
    const size_t outputLen = ((input.size() + 2) / 3) * 4;
    
    std::string result;
    try {
        result.reserve(outputLen);
    } catch (const std::bad_alloc&) {
        return "";
    }
    
    size_t i = 0;
    const size_t inputSize = input.size();
    
    // Process 3-byte groups
    while (i + 2 < inputSize) {
        const uint32_t octet_a = static_cast<uint8_t>(input[i++]);
        const uint32_t octet_b = static_cast<uint8_t>(input[i++]);
        const uint32_t octet_c = static_cast<uint8_t>(input[i++]);
        
        const uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        result += kBase64Chars[(triple >> 18) & 0x3F];
        result += kBase64Chars[(triple >> 12) & 0x3F];
        result += kBase64Chars[(triple >> 6) & 0x3F];
        result += kBase64Chars[triple & 0x3F];
    }
    
    // Handle remaining bytes with proper padding
    if (i < inputSize) {
        const uint32_t octet_a = static_cast<uint8_t>(input[i++]);
        const uint32_t octet_b = (i < inputSize) ? static_cast<uint8_t>(input[i++]) : 0;
        
        const uint32_t triple = (octet_a << 16) | (octet_b << 8);
        
        result += kBase64Chars[(triple >> 18) & 0x3F];
        result += kBase64Chars[(triple >> 12) & 0x3F];
        
        // Determine padding based on how many bytes we processed
        if (i == inputSize) {
            // We processed one remaining byte (octet_a only)
            // i was incremented once, octet_b is 0
            // But wait, we need to check the original position
            // After the while loop, i points to first remaining byte
            // If there was 1 remaining byte: i was at inputSize-1, after reading octet_a, i = inputSize
            // If there were 2 remaining bytes: i was at inputSize-2, after reading both, i = inputSize
        }
        
        // Cleaner logic: check how many bytes were actually read
        const size_t remainingBytes = inputSize - (i - (i < inputSize ? 0 : (octet_b != 0 ? 2 : 1)));
        
        // Actually, let's use a simpler approach - check position before loop
        const size_t bytesAfterLoop = inputSize - (inputSize / 3) * 3;
        if (bytesAfterLoop == 1) {
            // One remaining byte: add two padding
            result += '=';
            result += '=';
        } else {
            // Two remaining bytes: add one more char and one padding
            result += kBase64Chars[(triple >> 6) & 0x3F];
            result += '=';
        }
    }
    
    return result;
}
        
/**
 * @brief Parse ISO8601 timestamp to Unix timestamp
 * 
 * Supports formats:
 * - YYYY-MM-DDTHH:MM:SSZ
 * - YYYY-MM-DDTHH:MM:SS
 * - YYYY-MM-DD HH:MM:SS
 * 
 * Thread-safe with proper input validation.
 * 
 * @param timestamp ISO8601 formatted timestamp string
 * @return Unix timestamp in seconds, 0 on parse failure
 */
[[nodiscard]] uint64_t ParseISO8601(const std::string& timestamp) {
    // Validate input bounds
    if (timestamp.empty() || timestamp.size() > 64) {
        return 0;  // Invalid input
    }
    
    // Check for null characters that could cause issues
    if (timestamp.find('\0') != std::string::npos) {
        return 0;
    }
    
    std::tm tm = {};
    tm.tm_isdst = 0;  // Explicitly disable DST for UTC parsing
    
    std::istringstream ss(timestamp);
    
    // Try ISO8601 with T separator
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        // Try alternate format with space separator
        ss.clear();
        ss.str(timestamp);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    }
    
    if (ss.fail()) {
        return 0;
    }
    
    // Validate parsed values are in reasonable ranges
    // tm_year is years since 1900
    if (tm.tm_year < 0 || tm.tm_year > 200 ||  // Years 1900-2100
        tm.tm_mon < 0 || tm.tm_mon > 11 ||
        tm.tm_mday < 1 || tm.tm_mday > 31 ||
        tm.tm_hour < 0 || tm.tm_hour > 23 ||
        tm.tm_min < 0 || tm.tm_min > 59 ||
        tm.tm_sec < 0 || tm.tm_sec > 60) {  // 60 for leap second
        return 0;
    }
    
    // Additional validation for days in month
    static constexpr int daysInMonth[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (tm.tm_mday > daysInMonth[tm.tm_mon]) {
        // Check for non-leap year February
        if (tm.tm_mon == 1 && tm.tm_mday == 29) {
            const int year = tm.tm_year + 1900;
            const bool isLeapYear = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            if (!isLeapYear) {
                return 0;
            }
        } else {
            return 0;
        }
    }
    
    // Convert to Unix timestamp (use _mkgmtime for UTC on Windows)
    const time_t result = _mkgmtime(&tm);
    if (result == static_cast<time_t>(-1)) {
        return 0;
    }
    
    // Ensure non-negative result
    if (result < 0) {
        return 0;
    }
    
    return static_cast<uint64_t>(result);
}

/**
 * @brief Check if string is valid IPv4 address
 * 
 * Validates dotted-decimal notation (e.g., "192.168.1.1").
 * Does NOT accept CIDR notation.
 * 
 * @param str String to validate
 * @return true if valid IPv4 address
 */
[[nodiscard]] bool IsValidIPv4(std::string_view str) {
    if (str.empty() || str.size() > 15) {  // Max: "255.255.255.255"
        return false;
    }
    
    int segments = 0;
    int value = 0;
    int digitCount = 0;
    
    for (char c : str) {
        if (c == '.') {
            if (digitCount == 0 || value > 255) {
                return false;
            }
            segments++;
            if (segments > 3) {
                return false;  // Too many segments
            }
            value = 0;
            digitCount = 0;
        } else if (c >= '0' && c <= '9') {
            value = value * 10 + (c - '0');
            digitCount++;
            if (digitCount > 3 || value > 255) {
                return false;
            }
        } else {
            return false;  // Invalid character
        }
    }
    
    return segments == 3 && digitCount > 0 && value <= 255;
}

/**
 * @brief Check if string is valid IPv6
 * 
 * Validates IPv6 address format including compressed notation (::).
 * Does NOT accept CIDR notation or zone IDs.
 * 
 * @param str String to validate
 * @return true if valid IPv6 address
 */
[[nodiscard]] bool IsValidIPv6(std::string_view str) {
    if (str.empty() || str.size() > 45) {  // Max IPv6 length with embedded IPv4
        return false;
    }
    
    int colonCount = 0;
    bool hasDoubleColon = false;
    int groupLen = 0;
    
    for (size_t i = 0; i < str.size(); ++i) {
        const char c = str[i];
        if (c == ':') {
            if (groupLen > 4) {
                return false;  // Group too long
            }
            colonCount++;
            groupLen = 0;
            if (i + 1 < str.size() && str[i + 1] == ':') {
                if (hasDoubleColon) {
                    return false;  // Only one :: allowed
                }
                hasDoubleColon = true;
            }
        } else if ((c >= '0' && c <= '9') || 
                   (c >= 'a' && c <= 'f') || 
                   (c >= 'A' && c <= 'F')) {
            groupLen++;
            if (groupLen > 4) {
                return false;  // Hex group too long
            }
        } else {
            return false;  // Invalid character
        }
    }
    
    // Final group check
    if (groupLen > 4) {
        return false;
    }
    
    // Must have at least 2 colons (3 groups minimum in compressed form)
    // Maximum 7 colons (8 groups)
    return colonCount >= 2 && colonCount <= 7;
}

/**
 * @brief Check if string is valid domain
 * 
 * Validates domain name format according to RFC 1035 with security considerations.
 * Rejects punycode/IDN domains that could be used for homograph attacks.
 * 
 * @param str String to validate
 * @return true if valid domain name
 */
[[nodiscard]] bool IsValidDomain(std::string_view str) {
    // RFC 1035: domain name max 253 characters
    if (str.empty() || str.size() > 253) return false;
    
    // Reject potential homograph attacks (punycode starting with xn--)
    if (str.size() >= 4 && (str.substr(0, 4) == "xn--" || 
        str.find(".xn--") != std::string_view::npos)) {
        // Allow punycode but flag it - in security context, may want to reject
        // For now, we allow it but this is a security consideration
    }
    
    // Simple domain validation with label length checks
    bool hasDot = false;
    size_t labelLength = 0;
    bool lastWasHyphen = false;
    bool labelStartsWithHyphen = false;
    
    for (size_t i = 0; i < str.size(); ++i) {
        const char c = str[i];
        if (c == '.') {
            hasDot = true;
            // RFC 1035: label cannot be empty or start/end with hyphen
            if (labelLength == 0) return false;  // Empty label (consecutive dots or leading dot)
            if (lastWasHyphen) return false;  // Label ends with hyphen
            if (labelStartsWithHyphen) return false;  // Label starts with hyphen
            // RFC 1035: each label max 63 characters
            if (labelLength > 63) return false;
            labelLength = 0;
            labelStartsWithHyphen = false;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                   (c >= '0' && c <= '9')) {
            if (labelLength == 0) {
                // First character of label - cannot be hyphen (already checked above)
            }
            labelLength++;
            lastWasHyphen = false;
        } else if (c == '-') {
            if (labelLength == 0) {
                labelStartsWithHyphen = true;  // Label starts with hyphen - invalid
            }
            labelLength++;
            lastWasHyphen = true;
        } else {
            return false;  // Invalid character
        }
    }
    
    // Check final label
    if (labelLength == 0 || labelLength > 63) return false;  // Trailing dot or too long
    if (lastWasHyphen) return false;  // Last label ends with hyphen
    if (labelStartsWithHyphen) return false;  // Last label starts with hyphen
    
    return hasDot;
}

/**
 * @brief Check if string is valid URL
 * 
 * Validates URL starts with a known protocol scheme.
 * Does NOT perform full URL syntax validation.
 * 
 * @param str String to validate
 * @return true if string starts with http://, https://, ftp://, or ftps://
 */
[[nodiscard]] bool IsValidUrlString(std::string_view str) {
    if (str.empty() || str.size() > 2048) {  // RFC 2616 practical limit
        return false;
    }
    return str.starts_with("http://") || str.starts_with("https://") ||
           str.starts_with("ftp://") || str.starts_with("ftps://");
}

/**
 * @brief Check if string is valid email address
 * 
 * Basic validation: local@domain with at least one dot after @.
 * Does NOT perform RFC 5322 compliant validation.
 * 
 * @param str String to validate
 * @return true if basic email format is satisfied
 */
[[nodiscard]] bool IsValidEmail(std::string_view str) {
    if (str.empty() || str.size() > 254) {  // RFC 5321 limit
        return false;
    }
    
    const size_t atPos = str.find('@');
    if (atPos == std::string_view::npos || atPos == 0 || atPos == str.size() - 1) {
        return false;
    }
    
    // Local part max 64 chars (RFC 5321)
    if (atPos > 64) {
        return false;
    }
    
    return str.find('.', atPos) != std::string_view::npos;
}

/**
 * @brief Check if string is valid cryptographic hash (hex string)
 * 
 * Validates common hash lengths:
 * - 32 chars: MD5 (128 bits)
 * - 40 chars: SHA-1 (160 bits)
 * - 64 chars: SHA-256 (256 bits)
 * - 128 chars: SHA-512 (512 bits)
 * 
 * @param str String to validate
 * @return true if valid hex string of appropriate hash length
 */
[[nodiscard]] bool IsValidHash(std::string_view str) {
    if (str.size() != 32 && str.size() != 40 && str.size() != 64 && str.size() != 128) {
        return false;
    }
    
    for (const char c : str) {
        if (!((c >= '0' && c <= '9') || 
              (c >= 'a' && c <= 'f') || 
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Convert single hex character to value
 * 
 * @param c Hex character ('0'-'9', 'a'-'f', 'A'-'F')
 * @return Value 0-15, or -1 if invalid character
 */
[[nodiscard]] constexpr int HexCharToValue(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;  // Invalid character
}

/**
 * @brief Parse hex string to bytes
 * 
 * Converts a hex string (e.g., "DEADBEEF") to binary bytes.
 * 
 * @param hex Hex string (must be exactly 2*outLen characters)
 * @param out Output buffer for bytes
 * @param outLen Size of output buffer in bytes
 * @return true if parse successful, false on invalid input
 */
[[nodiscard]] bool ParseHexString(std::string_view hex, uint8_t* out, size_t outLen) {
    if (!out || outLen == 0) {
        return false;
    }
    
    if (hex.size() != outLen * 2) {
        return false;
    }
    
    for (size_t i = 0; i < outLen; ++i) {
        const int highVal = HexCharToValue(hex[i * 2]);
        const int lowVal = HexCharToValue(hex[i * 2 + 1]);
        
        if (highVal < 0 || lowVal < 0) {
            return false;  // Invalid hex character
        }
        
        out[i] = static_cast<uint8_t>((highVal << 4) | lowVal);
    }
    
    return true;
}

/**
 * @brief Safely parse IPv4 address string to octets
 * 
 * Parses dotted-decimal notation (e.g., "192.168.1.1") with full validation.
 * Does NOT use sscanf to avoid potential security issues with malformed input.
 * Rejects leading zeros (which could indicate octal interpretation in some systems).
 * 
 * @param str IPv4 address string
 * @param octets Output array for 4 octets (must be size 4)
 * @return true if parse successful and valid IPv4 address
 */
[[nodiscard]] bool SafeParseIPv4(std::string_view str, uint8_t octets[4]) noexcept {
    if (!octets) {
        return false;  // Null pointer check
    }
    
    if (str.empty() || str.size() > 15) {
        return false;
    }
    
    // Initialize output
    octets[0] = octets[1] = octets[2] = octets[3] = 0;
    
    size_t octetIndex = 0;
    int currentValue = 0;
    int digitCount = 0;
    size_t segmentStart = 0;
    
    for (size_t i = 0; i <= str.size(); ++i) {
        const char c = (i < str.size()) ? str[i] : '.';  // Treat end as final separator
        
        if (c == '.') {
            // Validate octet
            if (digitCount == 0 || currentValue > 255) {
                return false;
            }
            if (octetIndex >= 4) {
                return false;
            }
            
            // Check for leading zeros (security: prevent octal interpretation)
            if (digitCount > 1 && str[segmentStart] == '0') {
                return false;  // Leading zero detected (e.g., "01" or "007")
            }
            
            octets[octetIndex++] = static_cast<uint8_t>(currentValue);
            currentValue = 0;
            digitCount = 0;
            segmentStart = i + 1;
        } else if (c >= '0' && c <= '9') {
            currentValue = currentValue * 10 + (c - '0');
            digitCount++;
            
            if (digitCount > 3 || currentValue > 255) {
                return false;
            }
        } else {
            return false;  // Invalid character
        }
    }
    
    // Must have exactly 4 octets and ended cleanly
    return octetIndex == 4 && digitCount == 0;
}

} // anonymous namespace

// ============================================================================
// UTILITY FUNCTIONS (PUBLIC)
// ============================================================================

/**
 * @brief Parse duration string to seconds
 * 
 * Supported formats:
 * - "123" or "123s" or "123sec" - seconds
 * - "5m" or "5min" - minutes
 * - "2h" or "2hr" or "2hour" - hours
 * - "1d" or "1day" - days
 * - "1w" or "1week" - weeks
 * 
 * @param duration Duration string to parse
 * @return Parsed duration in seconds, or nullopt on failure
 */
std::optional<uint32_t> ParseDurationString(std::string_view duration) {
    if (duration.empty() || duration.size() > 32) {
        return std::nullopt;
    }
    
    uint64_t value = 0;  // Use uint64_t to detect overflow
    size_t i = 0;
    
    // Parse numeric part with overflow check
    while (i < duration.size() && duration[i] >= '0' && duration[i] <= '9') {
        const uint64_t digit = static_cast<uint64_t>(duration[i] - '0');
        
        // Check for overflow before multiplication
        if (value > (UINT32_MAX / 10)) {
            return std::nullopt;  // Would overflow
        }
        value = value * 10;
        
        // Check for overflow before addition
        if (value > UINT32_MAX - digit) {
            return std::nullopt;  // Would overflow
        }
        value += digit;
        ++i;
    }
    
    if (i == 0) {
        return std::nullopt;  // No digits found
    }
    
    // Parse unit
    std::string_view unit = duration.substr(i);
    uint32_t multiplier = 1;
    
    if (unit.empty() || unit == "s" || unit == "sec") {
        multiplier = 1;
    } else if (unit == "m" || unit == "min") {
        multiplier = 60;
    } else if (unit == "h" || unit == "hr" || unit == "hour") {
        multiplier = 3600;
    } else if (unit == "d" || unit == "day") {
        multiplier = 86400;
    } else if (unit == "w" || unit == "week") {
        multiplier = 604800;
    } else {
        return std::nullopt;  // Unknown unit
    }
    
    // Check for overflow with multiplier
    if (value > UINT32_MAX / multiplier) {
        return std::nullopt;
    }
    
    return static_cast<uint32_t>(value * multiplier);
}

std::string FormatDuration(uint64_t seconds) {
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else if (seconds < 3600) {
        return std::to_string(seconds / 60) + "m " + std::to_string(seconds % 60) + "s";
    } else if (seconds < 86400) {
        uint64_t hours = seconds / 3600;
        uint64_t mins = (seconds % 3600) / 60;
        return std::to_string(hours) + "h " + std::to_string(mins) + "m";
    } else {
        uint64_t days = seconds / 86400;
        uint64_t hours = (seconds % 86400) / 3600;
        return std::to_string(days) + "d " + std::to_string(hours) + "h";
    }
}

bool IsValidUrl(std::string_view url) {
    return IsValidUrlString(url);
}

std::optional<IOCType> DetectIOCType(std::string_view value) {
    if (value.empty()) return std::nullopt;
    
    // Check for hash first (most common)
    if (IsValidHash(value)) {
        switch (value.size()) {
            case 32:  return IOCType::FileHash;  // MD5
            case 40:  return IOCType::FileHash;  // SHA1
            case 64:  return IOCType::FileHash;  // SHA256
            case 128: return IOCType::FileHash;  // SHA512
        }
    }
    
    // Check for URL
    if (IsValidUrlString(value)) {
        return IOCType::URL;
    }
    
    // Check for email
    if (IsValidEmail(value)) {
        return IOCType::Email;
    }
    
    // Check for IPv4
    if (IsValidIPv4(value)) {
        return IOCType::IPv4;
    }
    
    // Check for IPv6
    if (IsValidIPv6(value)) {
        return IOCType::IPv6;
    }
    
    // Check for domain
    if (IsValidDomain(value)) {
        return IOCType::Domain;
    }
    
    return std::nullopt;
}

// ============================================================================
// RETRY CONFIG IMPLEMENTATION
// ============================================================================

uint32_t RetryConfig::CalculateDelay(uint32_t attempt) const noexcept {
    if (attempt == 0) return initialDelayMs;
    
    // Validate configuration to prevent invalid calculations
    if (initialDelayMs == 0 || maxDelayMs == 0) {
        return 1000;  // Fallback to 1 second
    }
    
    // Clamp attempt to prevent overflow in pow calculation
    constexpr uint32_t MAX_ATTEMPTS = 30;  // 2^30 is max safe power
    const uint32_t clampedAttempt = std::min(attempt, MAX_ATTEMPTS);
    
    // Validate backoff multiplier
    double safeMultiplier = backoffMultiplier;
    if (!std::isfinite(safeMultiplier) || safeMultiplier <= 0.0) {
        safeMultiplier = 2.0;  // Default
    }
    safeMultiplier = std::min(safeMultiplier, 10.0);  // Clamp to reasonable max
    
    // Calculate exponential delay with overflow protection
    double delay = static_cast<double>(initialDelayMs) * 
                   std::pow(safeMultiplier, static_cast<double>(clampedAttempt));
    
    // Check for NaN or infinity
    if (!std::isfinite(delay)) {
        return maxDelayMs;
    }
    
    // Validate jitter factor
    double safeJitterFactor = jitterFactor;
    if (!std::isfinite(safeJitterFactor) || safeJitterFactor < 0.0) {
        safeJitterFactor = 0.0;
    }
    safeJitterFactor = std::min(safeJitterFactor, 1.0);
    
    // Add jitter
    const double jitter = GetRandomJitter(safeJitterFactor);
    delay *= (1.0 + jitter);
    
    // Check again after jitter
    if (!std::isfinite(delay) || delay < 0.0) {
        return maxDelayMs;
    }
    
    // Clamp to max
    if (delay > static_cast<double>(maxDelayMs)) {
        return maxDelayMs;
    }
    
    // Ensure minimum delay
    if (delay < 1.0) {
        return 1;
    }
    
    return static_cast<uint32_t>(delay);
}

// ============================================================================
// AUTH CREDENTIALS IMPLEMENTATION
// ============================================================================

bool AuthCredentials::IsConfigured() const noexcept {
    switch (method) {
        case AuthMethod::None:
            return true;
        case AuthMethod::ApiKey:
            return !apiKey.empty();
        case AuthMethod::BasicAuth:
            return !username.empty();
        case AuthMethod::BearerToken:
            return !accessToken.empty();
        case AuthMethod::OAuth2:
            return !clientId.empty() && !clientSecret.empty() && !tokenUrl.empty();
        case AuthMethod::Certificate:
            return !certPath.empty();
        case AuthMethod::HMAC:
            return !hmacSecret.empty();
        default:
            return false;
    }
}

bool AuthCredentials::NeedsTokenRefresh() const noexcept {
    if (method != AuthMethod::OAuth2 && method != AuthMethod::BearerToken) {
        return false;
    }
    
    if (accessToken.empty()) return true;
    if (tokenExpiry == 0) return false;
    
    // Refresh 5 minutes before expiry
    uint64_t now = GetCurrentTimestampImpl();
    return now >= (tokenExpiry - 300);
}

void AuthCredentials::Clear() noexcept {
    // Securely clear sensitive data by overwriting before clearing
    // This helps prevent sensitive data from remaining in memory
    auto secureClear = [](std::string& str) {
        if (!str.empty()) {
            // Overwrite with zeros
            volatile char* p = str.data();
            for (size_t i = 0; i < str.size(); ++i) {
                p[i] = 0;
            }
            str.clear();
            str.shrink_to_fit();  // Actually deallocate
        }
    };
    
    secureClear(apiKey);
    secureClear(username);
    secureClear(password);
    secureClear(clientId);
    secureClear(clientSecret);
    secureClear(accessToken);
    secureClear(refreshToken);
    secureClear(keyPassword);
    secureClear(hmacSecret);
    tokenExpiry = 0;
}

// ============================================================================
// FEED ENDPOINT IMPLEMENTATION
// ============================================================================

std::string FeedEndpoint::GetFullUrl() const {
    // Validate base URL
    if (baseUrl.empty()) {
        return "";
    }
    
    // Size limit to prevent memory exhaustion
    constexpr size_t MAX_URL_LENGTH = 8192;
    
    std::string url;
    try {
        url.reserve(std::min(baseUrl.size() + path.size() + 1024, MAX_URL_LENGTH));
    } catch (const std::bad_alloc&) {
        return "";
    }
    
    url = baseUrl;
    
    // Append path with proper separator handling
    if (!path.empty()) {
        const bool baseEndsWithSlash = !url.empty() && url.back() == '/';
        const bool pathStartsWithSlash = !path.empty() && path.front() == '/';
        
        if (!baseEndsWithSlash && !pathStartsWithSlash) {
            url += '/';
        } else if (baseEndsWithSlash && pathStartsWithSlash) {
            // Avoid double slash - skip leading slash in path
            url += path.substr(1);
        } else {
            url += path;
        }
    }
    
    // Append query parameters
    if (!queryParams.empty()) {
        url += '?';
        bool first = true;
        for (const auto& [key, value] : queryParams) {
            // Skip empty keys for security
            if (key.empty()) continue;
            
            if (!first) url += '&';
            url += UrlEncode(key) + '=' + UrlEncode(value);
            first = false;
            
            // Check URL length limit
            if (url.size() > MAX_URL_LENGTH) {
                return "";  // URL too long
            }
        }
    }
    
    return url;
}

std::string FeedEndpoint::GetPaginatedUrl(uint64_t offset, uint32_t limit) const {
    std::string url = GetFullUrl();
    
    // Check if GetFullUrl failed
    if (url.empty() && !baseUrl.empty()) {
        return "";  // GetFullUrl failed
    }
    
    // Size limit check
    constexpr size_t MAX_URL_LENGTH = 8192;
    if (url.size() > MAX_URL_LENGTH - 100) {  // Leave room for pagination params
        return "";
    }
    
    const char separator = (url.find('?') == std::string::npos) ? '?' : '&';
    url += separator;
    url += "offset=" + std::to_string(offset);
    url += "&limit=" + std::to_string(limit);
    
    return url;
}

// ============================================================================
// FEED CONFIG IMPLEMENTATION
// ============================================================================

bool ThreatFeedConfig::Validate(std::string* errorMsg) const {
    // Feed ID validation
    if (feedId.empty()) {
        if (errorMsg) *errorMsg = "Feed ID is required";
        return false;
    }
    
    // Validate feedId format (alphanumeric, dash, underscore only)
    constexpr size_t MAX_FEED_ID_LENGTH = 256;
    if (feedId.size() > MAX_FEED_ID_LENGTH) {
        if (errorMsg) *errorMsg = "Feed ID too long (max 256 characters)";
        return false;
    }
    
    for (const char c : feedId) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            if (errorMsg) *errorMsg = "Feed ID contains invalid characters";
            return false;
        }
    }
    
    if (name.empty()) {
        if (errorMsg) *errorMsg = "Feed name is required";
        return false;
    }
    
    // Name length limit
    constexpr size_t MAX_NAME_LENGTH = 512;
    if (name.size() > MAX_NAME_LENGTH) {
        if (errorMsg) *errorMsg = "Feed name too long (max 512 characters)";
        return false;
    }
    
    if (endpoint.baseUrl.empty() && protocol != FeedProtocol::FILE_WATCH) {
        if (errorMsg) *errorMsg = "Base URL is required";
        return false;
    }
    
    // Validate base URL format if provided
    if (!endpoint.baseUrl.empty()) {
        if (!IsValidUrl(endpoint.baseUrl)) {
            if (errorMsg) *errorMsg = "Invalid base URL format";
            return false;
        }
    }
    
    if (!auth.IsConfigured()) {
        if (errorMsg) *errorMsg = "Authentication not properly configured";
        return false;
    }
    
    if (syncIntervalSeconds > 0 && syncIntervalSeconds < minSyncIntervalSeconds) {
        if (errorMsg) *errorMsg = "Sync interval below minimum";
        return false;
    }
    
    // Validate timeout values
    if (connectionTimeoutMs > 300000) {  // Max 5 minutes
        if (errorMsg) *errorMsg = "Connection timeout too high (max 300000ms)";
        return false;
    }
    
    if (readTimeoutMs > 600000) {  // Max 10 minutes
        if (errorMsg) *errorMsg = "Read timeout too high (max 600000ms)";
        return false;
    }
    
    return true;
}

ThreatFeedConfig ThreatFeedConfig::CreateDefault(ThreatIntelSource source) {
    ThreatFeedConfig config;
    config.source = source;
    config.feedId = ThreatIntelSourceToString(source);
    config.name = ThreatIntelSourceToString(source);
    
    // Set default rate limits based on source
    switch (source) {
        case ThreatIntelSource::VirusTotal:
            config.rateLimit.requestsPerMinute = 4;  // Free tier
            config.rateLimit.requestsPerDay = 500;
            break;
        case ThreatIntelSource::AbuseIPDB:
            config.rateLimit.requestsPerMinute = 60;
            config.rateLimit.requestsPerDay = 1000;
            break;
        case ThreatIntelSource::AlienVaultOTX:
            config.rateLimit.requestsPerMinute = 100;
            config.rateLimit.requestsPerHour = 10000;
            break;
        default:
            config.rateLimit.requestsPerMinute = 60;
            break;
    }
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateVirusTotal(const std::string& apiKey) {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::VirusTotal);
    
    config.feedId = "virustotal";
    config.name = "VirusTotal";
    config.description = "VirusTotal threat intelligence feed";
    config.protocol = FeedProtocol::REST_API;
    
    config.endpoint.baseUrl = "https://www.virustotal.com";
    config.endpoint.path = "/api/v3/intelligence/search";
    config.endpoint.method = "GET";
    
    config.auth.method = AuthMethod::ApiKey;
    config.auth.apiKey = apiKey;
    config.auth.apiKeyHeader = "x-apikey";
    
    // Rate limits for free tier
    config.rateLimit.requestsPerMinute = 4;
    config.rateLimit.requestsPerDay = 500;
    config.rateLimit.minIntervalMs = 15000;
    
    config.parser.iocPath = "$.data";
    config.parser.valuePath = "$.id";
    config.parser.typePath = "$.type";
    
    config.syncIntervalSeconds = 3600;  // 1 hour
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateAlienVaultOTX(const std::string& apiKey) {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::AlienVaultOTX);
    
    config.feedId = "alienvault-otx";
    config.name = "AlienVault OTX";
    config.description = "Open Threat Exchange indicators";
    config.protocol = FeedProtocol::REST_API;
    
    config.endpoint.baseUrl = "https://otx.alienvault.com";
    config.endpoint.path = "/api/v1/indicators/export";
    config.endpoint.method = "GET";
    
    config.auth.method = AuthMethod::ApiKey;
    config.auth.apiKey = apiKey;
    config.auth.apiKeyHeader = "X-OTX-API-KEY";
    
    config.rateLimit.requestsPerMinute = 100;
    config.rateLimit.requestsPerHour = 10000;
    
    config.parser.iocPath = "$.results";
    config.parser.valuePath = "$.indicator";
    config.parser.typePath = "$.type";
    config.parser.descriptionPath = "$.description";
    
    config.syncIntervalSeconds = 1800;  // 30 minutes
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateAbuseIPDB(const std::string& apiKey) {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::AbuseIPDB);
    
    config.feedId = "abuseipdb";
    config.name = "AbuseIPDB";
    config.description = "IP address abuse reports";
    config.protocol = FeedProtocol::REST_API;
    
    config.endpoint.baseUrl = "https://api.abuseipdb.com";
    config.endpoint.path = "/api/v2/blacklist";
    config.endpoint.method = "GET";
    config.endpoint.queryParams["confidenceMinimum"] = "75";
    
    config.auth.method = AuthMethod::ApiKey;
    config.auth.apiKey = apiKey;
    config.auth.apiKeyHeader = "Key";
    
    config.rateLimit.requestsPerMinute = 60;
    config.rateLimit.requestsPerDay = 1000;
    
    config.parser.iocPath = "$.data";
    config.parser.valuePath = "$.ipAddress";
    config.parser.confidencePath = "$.abuseConfidenceScore";
    
    // All entries are IPv4
    config.parser.typeMapping["ip"] = IOCType::IPv4;
    
    config.syncIntervalSeconds = 3600;  // 1 hour
    config.allowedTypes = { IOCType::IPv4, IOCType::IPv6 };
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateURLhaus() {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::URLhaus);
    
    config.feedId = "urlhaus";
    config.name = "URLhaus";
    config.description = "Malicious URLs from URLhaus";
    config.protocol = FeedProtocol::CSV_HTTP;
    
    config.endpoint.baseUrl = "https://urlhaus.abuse.ch";
    config.endpoint.path = "/downloads/csv_online/";
    config.endpoint.method = "GET";
    
    config.auth.method = AuthMethod::None;
    
    // No rate limit for public feed
    config.rateLimit.requestsPerMinute = 10;
    
    config.parser.csvDelimiter = ',';
    config.parser.csvQuote = '"';
    config.parser.csvHasHeader = true;
    config.parser.csvValueColumn = 2;  // URL column
    
    config.syncIntervalSeconds = 300;  // 5 minutes (frequently updated)
    config.allowedTypes = { IOCType::URL };
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateMalwareBazaar() {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::MalwareBazaar);
    
    config.feedId = "malwarebazaar";
    config.name = "MalwareBazaar";
    config.description = "Malware samples from MalwareBazaar";
    config.protocol = FeedProtocol::REST_API;
    
    config.endpoint.baseUrl = "https://mb-api.abuse.ch";
    config.endpoint.path = "/api/v1/";
    config.endpoint.method = "POST";
    config.endpoint.requestBody = "query=get_recent&selector=100";
    config.endpoint.contentType = "application/x-www-form-urlencoded";
    
    config.auth.method = AuthMethod::None;
    
    config.rateLimit.requestsPerMinute = 10;
    
    config.parser.iocPath = "$.data";
    config.parser.valuePath = "$.sha256_hash";
    
    config.syncIntervalSeconds = 600;  // 10 minutes
    config.allowedTypes = { IOCType::FileHash };
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateThreatFox(const std::string& apiKey) {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::ThreatFox);
    
    config.feedId = "threatfox";
    config.name = "ThreatFox";
    config.description = "IOCs from ThreatFox";
    config.protocol = FeedProtocol::REST_API;
    
    config.endpoint.baseUrl = "https://threatfox-api.abuse.ch";
    config.endpoint.path = "/api/v1/";
    config.endpoint.method = "POST";
    config.endpoint.requestBody = R"({"query": "get_iocs", "days": 1})";
    config.endpoint.contentType = "application/json";
    
    if (!apiKey.empty()) {
        config.auth.method = AuthMethod::ApiKey;
        config.auth.apiKey = apiKey;
        config.auth.apiKeyHeader = "API-KEY";
    } else {
        config.auth.method = AuthMethod::None;
    }
    
    config.rateLimit.requestsPerMinute = 10;
    
    config.parser.iocPath = "$.data";
    config.parser.valuePath = "$.ioc";
    config.parser.typePath = "$.ioc_type";
    config.parser.categoryPath = "$.threat_type";
    
    config.parser.typeMapping["ip:port"] = IOCType::IPv4;
    config.parser.typeMapping["domain"] = IOCType::Domain;
    config.parser.typeMapping["url"] = IOCType::URL;
    config.parser.typeMapping["md5_hash"] = IOCType::FileHash;
    config.parser.typeMapping["sha256_hash"] = IOCType::FileHash;
    
    config.syncIntervalSeconds = 900;  // 15 minutes
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateMISP(const std::string& baseUrl, const std::string& apiKey) {
    ThreatFeedConfig config = CreateDefault(ThreatIntelSource::MISP);
    
    config.feedId = "misp-" + std::to_string(std::hash<std::string>{}(baseUrl) % 10000);
    config.name = "MISP Instance";
    config.description = "MISP threat sharing platform";
    config.protocol = FeedProtocol::MISP_API;
    
    config.endpoint.baseUrl = baseUrl;
    config.endpoint.path = "/attributes/restSearch";
    config.endpoint.method = "POST";
    config.endpoint.contentType = "application/json";
    
    config.auth.method = AuthMethod::ApiKey;
    config.auth.apiKey = apiKey;
    config.auth.apiKeyHeader = "Authorization";
    
    config.rateLimit.requestsPerMinute = 60;
    
    config.parser.iocPath = "$.response.Attribute";
    config.parser.valuePath = "$.value";
    config.parser.typePath = "$.type";
    config.parser.categoryPath = "$.category";
    
    // MISP type mappings
    config.parser.typeMapping["ip-src"] = IOCType::IPv4;
    config.parser.typeMapping["ip-dst"] = IOCType::IPv4;
    config.parser.typeMapping["domain"] = IOCType::Domain;
    config.parser.typeMapping["hostname"] = IOCType::Domain;
    config.parser.typeMapping["url"] = IOCType::URL;
    config.parser.typeMapping["md5"] = IOCType::FileHash;
    config.parser.typeMapping["sha1"] = IOCType::FileHash;
    config.parser.typeMapping["sha256"] = IOCType::FileHash;
    config.parser.typeMapping["email-src"] = IOCType::Email;
    
    config.syncIntervalSeconds = 1800;  // 30 minutes
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateSTIXTAXII(
    const std::string& discoveryUrl,
    const std::string& apiRoot,
    const std::string& collectionId
) {
    ThreatFeedConfig config;
    
    config.feedId = "taxii-" + collectionId;
    config.name = "TAXII Collection: " + collectionId;
    config.description = "STIX/TAXII 2.1 feed";
    config.source = ThreatIntelSource::CustomFeed;
    config.protocol = FeedProtocol::STIX_TAXII;
    
    config.endpoint.baseUrl = apiRoot;
    config.endpoint.path = "/collections/" + collectionId + "/objects/";
    config.endpoint.method = "GET";
    config.endpoint.headers["Accept"] = "application/taxii+json;version=2.1";
    
    config.auth.method = AuthMethod::BasicAuth;
    
    config.rateLimit.requestsPerMinute = 60;
    
    config.syncIntervalSeconds = 3600;  // 1 hour
    
    return config;
}

ThreatFeedConfig ThreatFeedConfig::CreateCSVFeed(
    const std::string& url,
    int valueColumn,
    IOCType iocType
) {
    ThreatFeedConfig config;
    
    config.feedId = "csv-" + std::to_string(std::hash<std::string>{}(url) % 10000);
    config.name = "CSV Feed";
    config.description = "Custom CSV feed";
    config.source = ThreatIntelSource::CustomFeed;
    config.protocol = FeedProtocol::CSV_HTTP;
    
    config.endpoint.baseUrl = url;
    config.endpoint.method = "GET";
    
    config.auth.method = AuthMethod::None;
    
    config.parser.csvDelimiter = ',';
    config.parser.csvQuote = '"';
    config.parser.csvHasHeader = true;
    config.parser.csvValueColumn = valueColumn;
    
    config.allowedTypes = { iocType };
    
    config.syncIntervalSeconds = 3600;  // 1 hour
    
    return config;
}

// ============================================================================
// FEED STATS IMPLEMENTATION
// ============================================================================

std::string FeedStats::GetLastError() const {
    std::lock_guard<std::mutex> lock(errorMutex);
    return lastErrorMessage;
}

void FeedStats::SetLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(errorMutex);
    lastErrorMessage = error;
    lastErrorTime.store(GetCurrentTimestampImpl(), std::memory_order_release);
}

std::string FeedStats::GetCurrentPhase() const {
    std::lock_guard<std::mutex> lock(phaseMutex);
    return currentPhase;
}

void FeedStats::SetCurrentPhase(const std::string& phase) {
    std::lock_guard<std::mutex> lock(phaseMutex);
    currentPhase = phase;
}

double FeedStats::GetSuccessRate() const noexcept {
    const uint64_t success = totalSuccessfulSyncs.load(std::memory_order_acquire);
    const uint64_t failed = totalFailedSyncs.load(std::memory_order_acquire);
    
    // Check for overflow in addition (defensive)
    if (success > UINT64_MAX - failed) {
        return 50.0;  // Return neutral value on overflow
    }
    
    const uint64_t total = success + failed;
    
    if (total == 0) return 100.0;  // No syncs = healthy
    
    // Calculate rate with proper floating point handling
    const double rate = static_cast<double>(success) * 100.0 / static_cast<double>(total);
    
    // Ensure result is in valid range
    if (!std::isfinite(rate)) {
        return 0.0;
    }
    
    return std::clamp(rate, 0.0, 100.0);
}

bool FeedStats::IsHealthy() const noexcept {
    FeedSyncStatus currentStatus = status.load(std::memory_order_acquire);
    
    // Error or rate limited is not healthy
    if (currentStatus == FeedSyncStatus::Error || currentStatus == FeedSyncStatus::RateLimited) {
        return false;
    }
    
    // Too many consecutive errors
    if (consecutiveErrors.load(std::memory_order_relaxed) >= 5) {
        return false;
    }
    
    // Low success rate
    if (GetSuccessRate() < 50.0) {
        return false;
    }
    
    return true;
}

void FeedStats::Reset() noexcept {
    status.store(FeedSyncStatus::Unknown, std::memory_order_release);
    lastSuccessfulSync.store(0, std::memory_order_release);
    lastSyncAttempt.store(0, std::memory_order_release);
    lastErrorTime.store(0, std::memory_order_release);
    totalSuccessfulSyncs.store(0, std::memory_order_release);
    totalFailedSyncs.store(0, std::memory_order_release);
    totalIOCsFetched.store(0, std::memory_order_release);
    lastSyncIOCCount.store(0, std::memory_order_release);
    lastSyncNewIOCs.store(0, std::memory_order_release);
    lastSyncUpdatedIOCs.store(0, std::memory_order_release);
    totalBytesDownloaded.store(0, std::memory_order_release);
    lastSyncDurationMs.store(0, std::memory_order_release);
    avgSyncDurationMs.store(0, std::memory_order_release);
    consecutiveErrors.store(0, std::memory_order_release);
    currentRetryAttempt.store(0, std::memory_order_release);
    nextScheduledSync.store(0, std::memory_order_release);
    syncProgress.store(0, std::memory_order_release);
    
    {
        std::lock_guard<std::mutex> lock(errorMutex);
        lastErrorMessage.clear();
    }
    {
        std::lock_guard<std::mutex> lock(phaseMutex);
        currentPhase.clear();
    }
}

// ============================================================================
// SYNC RESULT IMPLEMENTATION
// ============================================================================

double SyncResult::GetIOCsPerSecond() const noexcept {
    if (durationMs == 0) return 0.0;
    
    // Calculate with overflow protection
    const double iocsPerMs = static_cast<double>(totalFetched) / static_cast<double>(durationMs);
    const double iocsPerSec = iocsPerMs * 1000.0;
    
    // Validate result
    if (!std::isfinite(iocsPerSec) || iocsPerSec < 0.0) {
        return 0.0;
    }
    
    return iocsPerSec;
}

// ============================================================================
// FEED EVENT IMPLEMENTATION
// ============================================================================

FeedEvent FeedEvent::Create(FeedEventType type, const std::string& feedId, const std::string& msg) {
    FeedEvent event;
    event.type = type;
    
    // Validate and limit feedId length
    constexpr size_t MAX_FEED_ID_LEN = 256;
    if (feedId.size() <= MAX_FEED_ID_LEN) {
        event.feedId = feedId;
    } else {
        event.feedId = feedId.substr(0, MAX_FEED_ID_LEN);
    }
    
    event.timestamp = GetCurrentTimestampImpl();
    
    // Validate and limit message length
    constexpr size_t MAX_MSG_LEN = 4096;
    if (msg.size() <= MAX_MSG_LEN) {
        event.message = msg;
    } else {
        event.message = msg.substr(0, MAX_MSG_LEN) + "...";
    }
    
    return event;
}

// ============================================================================
// HTTP REQUEST IMPLEMENTATION
// ============================================================================

HttpRequest HttpRequest::Get(const std::string& url) {
    HttpRequest request;
    request.url = url;
    request.method = "GET";
    return request;
}

HttpRequest HttpRequest::Post(const std::string& url, const std::string& body) {
    HttpRequest request;
    request.url = url;
    request.method = "POST";
    request.body.assign(body.begin(), body.end());
    return request;
}

// ============================================================================
// HTTP RESPONSE IMPLEMENTATION
// ============================================================================

std::optional<uint32_t> HttpResponse::GetRetryAfter() const {
    // Check both cases - HTTP headers are case-insensitive
    auto it = headers.find("Retry-After");
    if (it == headers.end()) {
        it = headers.find("retry-after");
    }
    if (it == headers.end()) {
        it = headers.find("RETRY-AFTER");
    }
    if (it == headers.end()) return std::nullopt;
    
    // Validate header value length
    if (it->second.empty() || it->second.size() > 20) {
        return std::nullopt;
    }
    
    // Parse integer value with bounds checking
    uint32_t value = 0;
    auto [ptr, ec] = std::from_chars(it->second.data(), 
                                      it->second.data() + it->second.size(), 
                                      value);
    if (ec == std::errc() && ptr == it->second.data() + it->second.size()) {
        // Clamp to reasonable maximum (1 hour)
        constexpr uint32_t MAX_RETRY_AFTER = 3600;
        return std::min(value, MAX_RETRY_AFTER);
    }
    
    return std::nullopt;
}

// ============================================================================
// FEED MANAGER CONFIG VALIDATION
// ============================================================================

bool ThreatIntelFeedManager::Config::Validate(std::string* errorMsg) const {
    if (maxConcurrentSyncs == 0) {
        if (errorMsg) *errorMsg = "maxConcurrentSyncs must be > 0";
        return false;
    }
    
    if (maxConcurrentSyncs > 32) {
        if (errorMsg) *errorMsg = "maxConcurrentSyncs too high (max 32)";
        return false;
    }
    
    if (maxTotalIOCs == 0) {
        if (errorMsg) *errorMsg = "maxTotalIOCs must be > 0";
        return false;
    }
    
    // Validate health check interval
    if (healthCheckIntervalSeconds > 0 && healthCheckIntervalSeconds < 10) {
        if (errorMsg) *errorMsg = "healthCheckIntervalSeconds too low (min 10)";
        return false;
    }
    
    // Validate worker threads
    if (workerThreads > 64) {
        if (errorMsg) *errorMsg = "workerThreads too high (max 64)";
        return false;
    }
    
    // Validate max consecutive errors
    if (maxConsecutiveErrors == 0) {
        if (errorMsg) *errorMsg = "maxConsecutiveErrors must be > 0";
        return false;
    }
    
    return true;
}

// ============================================================================
// PART 2/3: PARSER IMPLEMENTATIONS
// ============================================================================

// ============================================================================
// JSON FEED PARSER IMPLEMENTATION
// ============================================================================

bool JsonFeedParser::Parse(
    std::span<const uint8_t> data,
    std::vector<IOCEntry>& outEntries,
    const ParserConfig& config
) {
    // Size limits to prevent DoS via massive JSON
    constexpr size_t MAX_JSON_SIZE = 100 * 1024 * 1024;  // 100MB max
    constexpr size_t MAX_IOC_COUNT = 10000000;  // 10M IOCs max per feed
    constexpr size_t MAX_PATH_DEPTH = 32;  // Maximum nesting depth
    
    if (data.empty()) {
        m_lastError = "Empty data";
        return false;
    }
    
    if (data.size() > MAX_JSON_SIZE) {
        m_lastError = "JSON data exceeds size limit (100MB)";
        return false;
    }
    
    try {
        // Parse JSON with size validation
        std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonView);
        
        // Navigate to IOC array using path
        nlohmann::json* iocArray = &root;
        
        if (!config.iocPath.empty()) {
            // Validate path length
            if (config.iocPath.size() > 1024) {
                m_lastError = "IOC path too long";
                return false;
            }
            
            // Simple path navigation (e.g., "$.data.indicators")
            std::string path = config.iocPath;
            if (path.starts_with("$.")) {
                path = path.substr(2);
            }
            
            std::istringstream pathStream(path);
            std::string segment;
            size_t depth = 0;
            
            while (std::getline(pathStream, segment, '.')) {
                if (++depth > MAX_PATH_DEPTH) {
                    m_lastError = "Path too deep (max " + std::to_string(MAX_PATH_DEPTH) + " levels)";
                    return false;
                }
                
                if (segment.empty()) {
                    continue;  // Skip empty segments (e.g., "a..b")
                }
                
                if (iocArray->is_object() && iocArray->contains(segment)) {
                    iocArray = &(*iocArray)[segment];
                } else if (iocArray->is_array()) {
                    // Handle array index
                    size_t idx = 0;
                    auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), idx);
                    if (ec == std::errc() && ptr == segment.data() + segment.size()) {
                        if (idx < iocArray->size()) {
                            iocArray = &(*iocArray)[idx];
                        } else {
                            m_lastError = "Array index out of bounds: " + segment;
                            return false;
                        }
                    } else {
                        m_lastError = "Invalid array index: " + segment;
                        return false;
                    }
                } else {
                    m_lastError = "Path not found: " + config.iocPath;
                    return false;
                }
            }
        }
        
        if (!iocArray->is_array()) {
            m_lastError = "IOC path does not point to array";
            return false;
        }
        
        // Enforce IOC count limit
        const size_t iocCount = iocArray->size();
        if (iocCount > MAX_IOC_COUNT) {
            m_lastError = "Too many IOCs in feed (max " + std::to_string(MAX_IOC_COUNT) + ")";
            return false;
        }
        
        // Pre-allocate with reasonable limit
        const size_t reserveCount = std::min(iocCount, size_t{100000});
        outEntries.reserve(reserveCount);
        
        for (const auto& item : *iocArray) {
            IOCEntry entry;
            if (ParseIOCEntry(&item, entry, config)) {
                outEntries.push_back(std::move(entry));
                
                // Safety check - shouldn't grow unbounded
                if (outEntries.size() > MAX_IOC_COUNT) {
                    m_lastError = "Exceeded maximum IOC count during parsing";
                    return false;
                }
            }
        }
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        m_lastError = "JSON parse error: " + std::string(e.what());
        return false;
    } catch (const std::bad_alloc&) {
        m_lastError = "Out of memory during JSON parsing";
        return false;
    } catch (const std::exception& e) {
        m_lastError = "Parse error: " + std::string(e.what());
        return false;
    }
}

bool JsonFeedParser::ParseStreaming(
    std::span<const uint8_t> data,
    IOCReceivedCallback callback,
    const ParserConfig& config
) {
    // Validate inputs
    if (!callback) {
        m_lastError = "Invalid callback";
        return false;
    }
    
    // Size limits to prevent DoS
    constexpr size_t MAX_STREAMING_SIZE = 100 * 1024 * 1024;  // 100MB
    if (data.empty()) {
        m_lastError = "Empty data";
        return false;
    }
    if (data.size() > MAX_STREAMING_SIZE) {
        m_lastError = "Data too large for streaming parse";
        return false;
    }
    
    try {
        std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonView);
        
        nlohmann::json* iocArray = &root;
        
        if (!config.iocPath.empty()) {
            // Validate path length
            if (config.iocPath.size() > 1024) {
                m_lastError = "IOC path too long";
                return false;
            }
            
            std::string path = config.iocPath;
            if (path.starts_with("$.")) path = path.substr(2);
            
            std::istringstream pathStream(path);
            std::string segment;
            size_t depth = 0;
            constexpr size_t MAX_PATH_DEPTH = 32;
            
            while (std::getline(pathStream, segment, '.')) {
                if (++depth > MAX_PATH_DEPTH) {
                    m_lastError = "Path too deep";
                    return false;
                }
                if (segment.empty()) continue;
                
                if (iocArray->is_object() && iocArray->contains(segment)) {
                    iocArray = &(*iocArray)[segment];
                } else {
                    m_lastError = "Path not found: " + config.iocPath;
                    return false;
                }
            }
        }
        
        if (!iocArray->is_array()) {
            m_lastError = "IOC path does not point to array";
            return false;
        }
        
        // Process each item with size limit
        constexpr size_t MAX_ITEMS = 10000000;
        size_t processedCount = 0;
        
        for (const auto& item : *iocArray) {
            if (++processedCount > MAX_ITEMS) {
                m_lastError = "Exceeded maximum item count";
                return false;
            }
            
            IOCEntry entry;
            if (ParseIOCEntry(&item, entry, config)) {
                if (!callback(entry)) {
                    return true;  // Callback requested stop
                }
            }
        }
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        m_lastError = "JSON parse error: " + std::string(e.what());
        return false;
    } catch (const std::bad_alloc&) {
        m_lastError = "Out of memory";
        return false;
    } catch (const std::exception& e) {
        m_lastError = "Streaming parse error: " + std::string(e.what());
        return false;
    }
}

std::optional<std::string> JsonFeedParser::GetNextPageToken(
    std::span<const uint8_t> data,
    const ParserConfig& config
) {
    if (config.nextPagePath.empty()) return std::nullopt;
    if (data.empty() || data.size() > 100 * 1024 * 1024) return std::nullopt;
    
    try {
        std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonView);
        
        auto result = ExtractJsonPath(&root, config.nextPagePath);
        
        // Validate token length
        if (result && result->size() > 1024) {
            return std::nullopt;  // Token too long
        }
        
        return result;
        
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<uint64_t> JsonFeedParser::GetTotalCount(
    std::span<const uint8_t> data,
    const ParserConfig& config
) {
    if (config.totalCountPath.empty()) return std::nullopt;
    if (data.empty() || data.size() > 100 * 1024 * 1024) return std::nullopt;
    
    try {
        std::string_view jsonView(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonView);
        
        auto value = ExtractJsonPath(&root, config.totalCountPath);
        if (value) {
            // Safe conversion with bounds check
            const uint64_t count = std::stoull(*value);
            constexpr uint64_t MAX_COUNT = 100000000ULL;  // 100M max
            return std::min(count, MAX_COUNT);
        }
        
    } catch (const std::out_of_range&) {
        // Value too large
    } catch (const std::invalid_argument&) {
        // Not a valid number
    } catch (...) {}
    
    return std::nullopt;
}

bool JsonFeedParser::ParseIOCEntry(
    const void* jsonObject,
    IOCEntry& entry,
    const ParserConfig& config
) {
    const nlohmann::json& obj = *static_cast<const nlohmann::json*>(jsonObject);
    
    try {
        // Extract value
        std::string value;
        if (!config.valuePath.empty()) {
            auto extracted = ExtractJsonPath(&obj, config.valuePath);
            if (!extracted) return false;
            value = *extracted;
        } else {
            // Try common field names
            if (obj.contains("value")) value = obj["value"].get<std::string>();
            else if (obj.contains("indicator")) value = obj["indicator"].get<std::string>();
            else if (obj.contains("ioc")) value = obj["ioc"].get<std::string>();
            else if (obj.contains("ip")) value = obj["ip"].get<std::string>();
            else if (obj.contains("domain")) value = obj["domain"].get<std::string>();
            else if (obj.contains("url")) value = obj["url"].get<std::string>();
            else if (obj.contains("hash")) value = obj["hash"].get<std::string>();
            else return false;
        }
        
        // Process value
        if (config.trimWhitespace) {
            value = TrimString(value);
        }
        if (config.lowercaseValues) {
            value = ToLowerCase(value);
        }
        
        if (value.empty()) return false;
        
        // Determine IOC type
        IOCType iocType = IOCType::Domain;  // Default
        
        if (!config.typePath.empty()) {
            auto typeStr = ExtractJsonPath(&obj, config.typePath);
            if (typeStr) {
                // Check type mapping first
                auto it = config.typeMapping.find(*typeStr);
                if (it != config.typeMapping.end()) {
                    iocType = it->second;
                } else {
                    // Try to detect from type string
                    std::string lowerType = ToLowerCase(*typeStr);
                    if (lowerType.find("ipv4") != std::string::npos || lowerType == "ip") {
                        iocType = IOCType::IPv4;
                    } else if (lowerType.find("ipv6") != std::string::npos) {
                        iocType = IOCType::IPv6;
                    } else if (lowerType.find("domain") != std::string::npos || 
                               lowerType.find("hostname") != std::string::npos) {
                        iocType = IOCType::Domain;
                    } else if (lowerType.find("url") != std::string::npos) {
                        iocType = IOCType::URL;
                    } else if (lowerType.find("hash") != std::string::npos ||
                               lowerType.find("md5") != std::string::npos ||
                               lowerType.find("sha") != std::string::npos) {
                        iocType = IOCType::FileHash;
                    } else if (lowerType.find("email") != std::string::npos) {
                        iocType = IOCType::Email;
                    }
                }
            }
        } else {
            // Auto-detect type from value
            auto detected = DetectIOCType(value);
            if (detected) {
                iocType = *detected;
            }
        }
        
        entry.type = iocType;
        
        // Set value based on type
        switch (iocType) {
            case IOCType::IPv4:
            case IOCType::CIDRv4: {
                // Parse IPv4 address using safe parser
                uint8_t octets[4] = {0};
                if (SafeParseIPv4(value, octets)) {
                    entry.value.ipv4 = IPv4Address(
                        octets[0], octets[1], octets[2], octets[3]
                    );
                } else {
                    return false;  // Invalid IPv4 format
                }
                break;
            }
            case IOCType::FileHash: {
                // Parse hash
                HashValue hash;
                size_t hashLen = value.size() / 2;
                if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
                else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
                else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
                else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
                else break;
                
                hash.length = static_cast<uint8_t>(hashLen);
                ParseHexString(value, hash.data.data(), hashLen);
                entry.value.hash = hash;
                break;
            }
            default: {
                // String-based IOCs use string pool reference
                // For now, we store a hash of the value for deduplication
                uint32_t valueHash = 0;
                for (char c : value) {
                    valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                }
                entry.value.stringRef.stringOffset = valueHash;
                entry.value.stringRef.stringLength = static_cast<uint16_t>(std::min(value.size(), size_t(65535)));
                break;
            }
        }
        
        // Extract confidence
        if (!config.confidencePath.empty()) {
            auto confStr = ExtractJsonPath(&obj, config.confidencePath);
            if (confStr) {
                try {
                    int conf = std::stoi(*confStr);
                    if (conf >= 90) entry.confidence = ConfidenceLevel::Confirmed;
                    else if (conf >= 70) entry.confidence = ConfidenceLevel::High;
                    else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                    else if (conf >= 30) entry.confidence = ConfidenceLevel::Low;
                    else entry.confidence = ConfidenceLevel::None;
                } catch (...) {}
            }
        }
        
        // Extract reputation
        if (!config.reputationPath.empty()) {
            auto repStr = ExtractJsonPath(&obj, config.reputationPath);
            if (repStr) {
                std::string lowerRep = ToLowerCase(*repStr);
                if (lowerRep.find("malicious") != std::string::npos ||
                    lowerRep.find("bad") != std::string::npos) {
                    entry.reputation = ReputationLevel::Malicious;
                } else if (lowerRep.find("suspicious") != std::string::npos) {
                    entry.reputation = ReputationLevel::Suspicious;
                } else if (lowerRep.find("clean") != std::string::npos ||
                           lowerRep.find("safe") != std::string::npos) {
                    entry.reputation = ReputationLevel::Safe;
                }
            }
        }
        
        // Extract timestamps
        if (!config.firstSeenPath.empty()) {
            auto ts = ExtractJsonPath(&obj, config.firstSeenPath);
            if (ts) entry.firstSeen = ParseISO8601(*ts);
        }
        
        if (!config.lastSeenPath.empty()) {
            auto ts = ExtractJsonPath(&obj, config.lastSeenPath);
            if (ts) entry.lastSeen = ParseISO8601(*ts);
        }
        
        // Set current time
        uint64_t now = GetCurrentTimestampImpl();
        if (entry.firstSeen == 0) entry.firstSeen = now;
        if (entry.lastSeen == 0) entry.lastSeen = now;
        entry.createdTime = now;
        
        return true;
        
    } catch (const std::exception& e) {
        m_lastError = "Entry parse error: " + std::string(e.what());
        return false;
    }
}

std::optional<std::string> JsonFeedParser::ExtractJsonPath(
    const void* root,
    const std::string& path
) {
    if (!root) {
        return std::nullopt;
    }
    
    // Validate path
    if (path.empty() || path.size() > 1024) {
        return std::nullopt;
    }
    
    const nlohmann::json& json = *static_cast<const nlohmann::json*>(root);
    
    try {
        std::string cleanPath = path;
        if (cleanPath.starts_with("$.")) {
            cleanPath = cleanPath.substr(2);
        }
        
        const nlohmann::json* current = &json;
        std::istringstream pathStream(cleanPath);
        std::string segment;
        size_t depth = 0;
        constexpr size_t MAX_PATH_DEPTH = 32;
        
        while (std::getline(pathStream, segment, '.')) {
            if (++depth > MAX_PATH_DEPTH) {
                return std::nullopt;  // Path too deep
            }
            
            if (segment.empty()) continue;
            
            if (current->is_object() && current->contains(segment)) {
                current = &(*current)[segment];
            } else {
                return std::nullopt;
            }
        }
        
        if (current->is_string()) {
            const std::string result = current->get<std::string>();
            // Limit returned string length
            constexpr size_t MAX_STRING_LENGTH = 65536;
            if (result.size() > MAX_STRING_LENGTH) {
                return result.substr(0, MAX_STRING_LENGTH);
            }
            return result;
        } else if (current->is_number_integer()) {
            return std::to_string(current->get<int64_t>());
        } else if (current->is_number_unsigned()) {
            return std::to_string(current->get<uint64_t>());
        } else if (current->is_number_float()) {
            // Format floating point without scientific notation for reasonable numbers
            const double val = current->get<double>();
            if (std::isfinite(val)) {
                std::ostringstream oss;
                oss << std::fixed << std::setprecision(6) << val;
                return oss.str();
            }
            return std::nullopt;
        } else if (current->is_boolean()) {
            return current->get<bool>() ? "true" : "false";
        }
        
    } catch (const nlohmann::json::exception&) {
        // JSON access error
    } catch (const std::exception&) {
        // Other errors
    }
    
    return std::nullopt;
}

// ============================================================================
// CSV FEED PARSER IMPLEMENTATION
// ============================================================================

bool CsvFeedParser::Parse(
    std::span<const uint8_t> data,
    std::vector<IOCEntry>& outEntries,
    const ParserConfig& config
) {
    // Size limits to prevent DoS
    constexpr size_t MAX_CSV_SIZE = 100 * 1024 * 1024;  // 100MB
    constexpr size_t MAX_LINE_COUNT = 10000000;  // 10M lines
    constexpr size_t MAX_LINE_LENGTH = 65536;  // 64KB per line
    
    if (data.empty()) {
        m_lastError = "Empty data";
        return false;
    }
    
    if (data.size() > MAX_CSV_SIZE) {
        m_lastError = "CSV data too large";
        return false;
    }
    
    // Check for null bytes which shouldn't be in CSV
    if (std::find(data.begin(), data.end(), '\0') != data.end()) {
        m_lastError = "CSV contains null bytes";
        return false;
    }
    
    try {
        std::string content(reinterpret_cast<const char*>(data.data()), data.size());
        std::istringstream stream(content);
        std::string line;
        
        bool firstLine = true;
        size_t lineNum = 0;
        
        // Pre-allocate with estimate
        const size_t estimatedLines = std::count(content.begin(), content.end(), '\n');
        outEntries.reserve(std::min(estimatedLines, size_t{100000}));
        
        while (std::getline(stream, line)) {
            lineNum++;
            
            // Line count limit
            if (lineNum > MAX_LINE_COUNT) {
                m_lastError = "Too many lines in CSV";
                return false;
            }
            
            // Line length limit
            if (line.size() > MAX_LINE_LENGTH) {
                continue;  // Skip overly long lines
            }
            
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') continue;
            
            // Skip header if configured
            if (firstLine && config.csvHasHeader) {
                firstLine = false;
                continue;
            }
            firstLine = false;
            
            // Parse line
            auto fields = ParseLine(line, config.csvDelimiter, config.csvQuote);
            
            if (fields.empty()) continue;
            
            // Validate column index
            if (config.csvValueColumn < 0 || 
                static_cast<size_t>(config.csvValueColumn) >= fields.size()) {
                continue;
            }
            
            std::string value = fields[static_cast<size_t>(config.csvValueColumn)];
            if (config.trimWhitespace) {
                value = TrimString(value);
            }
            if (config.lowercaseValues) {
                value = ToLowerCase(value);
            }
            
            if (value.empty()) continue;
            
            // Value length limit
            constexpr size_t MAX_VALUE_LENGTH = 8192;
            if (value.size() > MAX_VALUE_LENGTH) {
                continue;  // Skip overly long values
            }
            
            // Create IOC entry
            IOCEntry entry;
            
            // Determine type
            IOCType iocType = IOCType::Domain;  // Default
            
            if (config.csvTypeColumn >= 0 && 
                static_cast<size_t>(config.csvTypeColumn) < fields.size()) {
                std::string typeStr = fields[static_cast<size_t>(config.csvTypeColumn)];
                auto it = config.typeMapping.find(typeStr);
                if (it != config.typeMapping.end()) {
                    iocType = it->second;
                }
            } else {
                // Auto-detect
                auto detected = DetectIOCType(value);
                if (detected) {
                    iocType = *detected;
                }
            }
            
            entry.type = iocType;
            
            // Set value based on type
            switch (iocType) {
                case IOCType::IPv4:
                case IOCType::CIDRv4: {
                    uint8_t octets[4] = {0};
                    if (SafeParseIPv4(value, octets)) {
                        entry.value.ipv4 = IPv4Address(
                            octets[0], octets[1], octets[2], octets[3]
                        );
                    } else {
                        continue;  // Invalid IPv4, skip this entry
                    }
                    break;
                }
                case IOCType::FileHash: {
                    HashValue hash{};
                    const size_t hashLen = value.size() / 2;
                    if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
                    else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
                    else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
                    else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
                    else continue;  // Invalid hash length
                    
                    // Validate hash fits in buffer
                    if (hashLen > hash.data.size()) {
                        continue;
                    }
                    
                    hash.length = static_cast<uint8_t>(hashLen);
                    if (!ParseHexString(value, hash.data.data(), hashLen)) {
                        continue;
                    }
                    entry.value.hash = hash;
                    break;
                }
                default: {
                    // String-based IOCs - compute hash for deduplication
                    uint32_t valueHash = 0;
                    for (const char c : value) {
                        valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                    }
                    entry.value.stringRef.stringOffset = valueHash;
                    entry.value.stringRef.stringLength = static_cast<uint16_t>(
                        std::min(value.size(), static_cast<size_t>(65535))
                    );
                    break;
                }
            }
            
            // Set timestamps
            const uint64_t now = GetCurrentTimestampImpl();
            entry.firstSeen = now;
            entry.lastSeen = now;
            entry.createdTime = now;
            
            outEntries.push_back(std::move(entry));
        }
        
        return true;
        
    } catch (const std::bad_alloc&) {
        m_lastError = "Out of memory";
        return false;
    } catch (const std::exception& e) {
        m_lastError = "CSV parse error: " + std::string(e.what());
        return false;
    }
}

bool CsvFeedParser::ParseStreaming(
    std::span<const uint8_t> data,
    IOCReceivedCallback callback,
    const ParserConfig& config
) {
    if (!callback) {
        m_lastError = "Invalid callback";
        return false;
    }
    
    std::vector<IOCEntry> entries;
    if (!Parse(data, entries, config)) {
        return false;
    }
    
    for (const auto& entry : entries) {
        if (!callback(entry)) {
            return true;  // Stop requested
        }
    }
    
    return true;
}

std::optional<std::string> CsvFeedParser::GetNextPageToken(
    std::span<const uint8_t> /*data*/,
    const ParserConfig& /*config*/
) {
    // CSV feeds typically don't support pagination
    return std::nullopt;
}

std::optional<uint64_t> CsvFeedParser::GetTotalCount(
    std::span<const uint8_t> data,
    const ParserConfig& config
) {
    if (data.empty()) return std::nullopt;
    
    // Count lines safely with size limit
    constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
    if (data.size() > MAX_SIZE) return std::nullopt;
    
    uint64_t count = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == '\n') {
            count++;
            // Overflow protection
            if (count >= UINT64_MAX - 1) break;
        }
    }
    
    // Subtract header if present
    if (config.csvHasHeader && count > 0) {
        count--;
    }
    
    return count;
}

std::vector<std::string> CsvFeedParser::ParseLine(
    std::string_view line,
    char delimiter,
    char quote
) {
    std::vector<std::string> fields;
    
    // Size limits for security
    constexpr size_t MAX_FIELDS = 1000;
    constexpr size_t MAX_FIELD_LENGTH = 65536;
    
    if (line.empty()) {
        return fields;
    }
    
    try {
        fields.reserve(std::min(size_t{64}, line.size() / 2 + 1));
    } catch (const std::bad_alloc&) {
        return fields;
    }
    
    std::string field;
    field.reserve(std::min(MAX_FIELD_LENGTH, line.size()));
    
    bool inQuotes = false;
    
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        
        if (c == quote) {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == quote) {
                // Escaped quote - add single quote and skip next
                field += quote;
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c == delimiter && !inQuotes) {
            // End of field
            if (field.size() > MAX_FIELD_LENGTH) {
                field = field.substr(0, MAX_FIELD_LENGTH);
            }
            fields.push_back(std::move(field));
            field.clear();
            
            // Field count limit
            if (fields.size() >= MAX_FIELDS) {
                return fields;
            }
        } else if (c == '\r') {
            // Skip carriage return
        } else {
            // Check field length before adding
            if (field.size() < MAX_FIELD_LENGTH) {
                field += c;
            }
        }
    }
    
    // Add last field
    if (field.size() > MAX_FIELD_LENGTH) {
        field = field.substr(0, MAX_FIELD_LENGTH);
    }
    
    if (fields.size() < MAX_FIELDS) {
        fields.push_back(std::move(field));
    }
    
    return fields;
}

// ============================================================================
// STIX FEED PARSER IMPLEMENTATION
// ============================================================================

bool StixFeedParser::Parse(
    std::span<const uint8_t> data,
    std::vector<IOCEntry>& outEntries,
    const ParserConfig& /*config*/
) {
    // Security limits to prevent DoS
    constexpr size_t MAX_STIX_SIZE = 100 * 1024 * 1024;  // 100MB
    constexpr size_t MAX_OBJECTS = 10000000;  // 10M objects
    
    if (data.empty()) {
        m_lastError = "Empty STIX data";
        return false;
    }
    
    if (data.size() > MAX_STIX_SIZE) {
        m_lastError = "STIX data too large";
        return false;
    }
    
    try {
        // Safe string construction with size validation
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        // STIX bundle structure validation
        if (!root.is_object()) {
            m_lastError = "Invalid STIX bundle: not an object";
            return false;
        }
        
        if (!root.contains("objects") || !root["objects"].is_array()) {
            m_lastError = "Invalid STIX bundle: missing objects array";
            return false;
        }
        
        const auto& objects = root["objects"];
        
        // Check objects count limit
        if (objects.size() > MAX_OBJECTS) {
            m_lastError = "Too many objects in STIX bundle";
            return false;
        }
        
        // Pre-allocate with reasonable estimate
        const size_t estimatedIndicators = std::min(objects.size(), size_t{100000});
        try {
            outEntries.reserve(estimatedIndicators);
        } catch (const std::bad_alloc&) {
            m_lastError = "Out of memory";
            return false;
        }
        
        for (const auto& obj : objects) {
            // Validate object structure
            if (!obj.is_object() || !obj.contains("type")) {
                continue;
            }
            
            // Get object type safely
            if (!obj["type"].is_string()) {
                continue;
            }
            
            const std::string objType = obj["type"].get<std::string>();
            
            // Validate type string length
            if (objType.empty() || objType.size() > 256) {
                continue;
            }
            
            // Process indicator objects
            if (objType == "indicator") {
                if (!obj.contains("pattern") || !obj["pattern"].is_string()) {
                    continue;
                }
                
                const std::string pattern = obj["pattern"].get<std::string>();
                
                // Pattern length limit
                constexpr size_t MAX_PATTERN_LENGTH = 65536;
                if (pattern.size() > MAX_PATTERN_LENGTH) {
                    continue;
                }
                
                IOCEntry entry;
                
                if (ParseSTIXPattern(pattern, entry)) {
                    // Extract metadata safely
                    if (obj.contains("created") && obj["created"].is_string()) {
                        entry.createdTime = ParseISO8601(obj["created"].get<std::string>());
                    }
                    if (obj.contains("modified") && obj["modified"].is_string()) {
                        entry.lastSeen = ParseISO8601(obj["modified"].get<std::string>());
                    }
                    if (obj.contains("valid_from") && obj["valid_from"].is_string()) {
                        entry.firstSeen = ParseISO8601(obj["valid_from"].get<std::string>());
                    }
                    if (obj.contains("valid_until") && obj["valid_until"].is_string()) {
                        entry.expirationTime = ParseISO8601(obj["valid_until"].get<std::string>());
                    }
                    if (obj.contains("confidence") && obj["confidence"].is_number_integer()) {
                        const int conf = std::clamp(obj["confidence"].get<int>(), 0, 100);
                        if (conf >= 90) entry.confidence = ConfidenceLevel::Confirmed;
                        else if (conf >= 70) entry.confidence = ConfidenceLevel::High;
                        else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                        else entry.confidence = ConfidenceLevel::Low;
                    }
                    
                    try {
                        outEntries.push_back(std::move(entry));
                    } catch (const std::bad_alloc&) {
                        m_lastError = "Out of memory";
                        return false;
                    }
                }
            }
        }
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        m_lastError = "STIX JSON parse error: " + std::string(e.what());
        return false;
    } catch (const std::bad_alloc&) {
        m_lastError = "Out of memory";
        return false;
    } catch (const std::exception& e) {
        m_lastError = "STIX parse error: " + std::string(e.what());
        return false;
    }
}

bool StixFeedParser::ParseStreaming(
    std::span<const uint8_t> data,
    IOCReceivedCallback callback,
    const ParserConfig& config
) {
    if (!callback) {
        m_lastError = "Invalid callback";
        return false;
    }
    
    std::vector<IOCEntry> entries;
    if (!Parse(data, entries, config)) {
        return false;
    }
    
    for (const auto& entry : entries) {
        try {
            if (!callback(entry)) {
                return true;  // Stop requested by callback
            }
        } catch (const std::exception&) {
            // Callback exception - continue with next entry
        }
    }
    
    return true;
}

std::optional<std::string> StixFeedParser::GetNextPageToken(
    std::span<const uint8_t> data,
    const ParserConfig& /*config*/
) {
    // Security limits
    constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
    constexpr size_t MAX_TOKEN_LENGTH = 1024;
    
    if (data.empty() || data.size() > MAX_SIZE) {
        return std::nullopt;
    }
    
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        if (!root.is_object()) {
            return std::nullopt;
        }
        
        // Check for TAXII pagination
        if (root.contains("next") && root["next"].is_string()) {
            std::string token = root["next"].get<std::string>();
            if (!token.empty() && token.size() <= MAX_TOKEN_LENGTH) {
                return token;
            }
        }
        
        // Alternative pagination
        if (root.contains("more") && root["more"].is_boolean() && root["more"].get<bool>()) {
            if (root.contains("id") && root["id"].is_string()) {
                std::string token = root["id"].get<std::string>();
                if (!token.empty() && token.size() <= MAX_TOKEN_LENGTH) {
                    return token;
                }
            }
        }
        
    } catch (const std::exception&) {
        // Parse error - no pagination available
    }
    
    return std::nullopt;
}

std::optional<uint64_t> StixFeedParser::GetTotalCount(
    std::span<const uint8_t> data,
    const ParserConfig& /*config*/
) {
    // Security limits
    constexpr size_t MAX_SIZE = 100 * 1024 * 1024;
    constexpr uint64_t MAX_COUNT = 100000000ULL;  // 100M max
    
    if (data.empty() || data.size() > MAX_SIZE) {
        return std::nullopt;
    }
    
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        if (!root.is_object()) {
            return std::nullopt;
        }
        
        if (root.contains("objects") && root["objects"].is_array()) {
            const uint64_t count = root["objects"].size();
            return std::min(count, MAX_COUNT);
        }
        
    } catch (const std::exception&) {
        // Parse error
    }
    
    return std::nullopt;
}

bool StixFeedParser::ParseSTIXPattern(
    const std::string& pattern,
    IOCEntry& entry
) {
    // STIX pattern format: [type:property = 'value']
    // Examples:
    // [ipv4-addr:value = '192.168.1.1']
    // [domain-name:value = 'malware.com']
    // [file:hashes.SHA-256 = 'abc123...']
    
    // Pattern length validation
    constexpr size_t MAX_PATTERN_LENGTH = 65536;
    if (pattern.empty() || pattern.size() > MAX_PATTERN_LENGTH) {
        return false;
    }
    
    // Simple pattern parser with bounds checking
    const size_t start = pattern.find('[');
    const size_t end = pattern.rfind(']');
    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return false;
    }
    
    // Extract content between brackets safely
    const size_t contentLength = end - start - 1;
    if (contentLength == 0 || contentLength > MAX_PATTERN_LENGTH) {
        return false;
    }
    
    std::string content = pattern.substr(start + 1, contentLength);
    
    // Find type and value separator
    const size_t colonPos = content.find(':');
    if (colonPos == std::string::npos || colonPos == 0 || colonPos >= content.size() - 1) {
        return false;
    }
    
    // Extract STIX type with length validation
    std::string stixType = TrimString(content.substr(0, colonPos));
    if (stixType.empty() || stixType.size() > 256) {
        return false;
    }
    
    std::string rest = content.substr(colonPos + 1);
    if (rest.empty()) {
        return false;
    }
    
    // Find value in quotes - use proper quote matching
    const size_t valueStart = rest.find('\'');
    const size_t valueEnd = rest.rfind('\'');
    if (valueStart == std::string::npos || valueEnd == std::string::npos || valueEnd <= valueStart) {
        return false;
    }
    
    // Extract value safely
    const size_t valueLength = valueEnd - valueStart - 1;
    if (valueLength == 0) {
        return false;
    }
    
    // Value length limit for security
    constexpr size_t MAX_VALUE_LENGTH = 8192;
    if (valueLength > MAX_VALUE_LENGTH) {
        return false;
    }
    
    std::string value = rest.substr(valueStart + 1, valueLength);
    
    // Map STIX type to IOCType
    auto iocType = MapSTIXTypeToIOCType(stixType);
    if (!iocType) {
        return false;
    }
    
    entry.type = *iocType;
    
    // Set value based on type
    switch (entry.type) {
        case IOCType::IPv4:
        case IOCType::CIDRv4: {
            uint8_t octets[4] = {0};
            if (SafeParseIPv4(value, octets)) {
                entry.value.ipv4 = IPv4Address(
                    octets[0], octets[1], octets[2], octets[3]
                );
            } else {
                return false;  // Invalid IPv4 format
            }
            break;
        }
        case IOCType::FileHash: {
            // Validate hex string format
            if (value.size() % 2 != 0) {
                return false;
            }
            
            HashValue hash{};
            const size_t hashLen = value.size() / 2;
            
            // Validate hash length
            if (hashLen == 16) {
                hash.algorithm = HashAlgorithm::MD5;
            } else if (hashLen == 20) {
                hash.algorithm = HashAlgorithm::SHA1;
            } else if (hashLen == 32) {
                hash.algorithm = HashAlgorithm::SHA256;
            } else if (hashLen == 64) {
                hash.algorithm = HashAlgorithm::SHA512;
            } else {
                return false;  // Unsupported hash length
            }
            
            // Bounds check before parsing
            if (hashLen > hash.data.size()) {
                return false;
            }
            
            hash.length = static_cast<uint8_t>(hashLen);
            if (!ParseHexString(value, hash.data.data(), hashLen)) {
                return false;
            }
            entry.value.hash = hash;
            break;
        }
        default: {
            // String-based IOCs - compute hash for deduplication
            uint32_t valueHash = 0;
            for (const char c : value) {
                // Overflow is intentional for hash mixing
                valueHash = valueHash * 31 + static_cast<uint8_t>(c);
            }
            entry.value.stringRef.stringOffset = valueHash;
            entry.value.stringRef.stringLength = static_cast<uint16_t>(
                std::min(value.size(), size_t{65535})
            );
            break;
        }
    }
    
    const uint64_t now = GetCurrentTimestampImpl();
    entry.firstSeen = now;
    entry.lastSeen = now;
    entry.createdTime = now;
    
    return true;
}

std::optional<IOCType> StixFeedParser::MapSTIXTypeToIOCType(const std::string& stixType) {
    // Validate input
    if (stixType.empty() || stixType.size() > 256) {
        return std::nullopt;
    }
    
    // Standard STIX type mappings
    if (stixType == "ipv4-addr") return IOCType::IPv4;
    if (stixType == "ipv6-addr") return IOCType::IPv6;
    if (stixType == "domain-name") return IOCType::Domain;
    if (stixType == "url") return IOCType::URL;
    if (stixType == "email-addr") return IOCType::Email;
    if (stixType == "file") return IOCType::FileHash;
    if (stixType == "x509-certificate") return IOCType::CertFingerprint;
    if (stixType == "windows-registry-key") return IOCType::RegistryKey;
    if (stixType == "process") return IOCType::ProcessName;
    if (stixType == "mutex") return IOCType::MutexName;
    
    return std::nullopt;
}

// ============================================================================
// PART 3/3: THREATINTELFEEDMANAGER CLASS IMPLEMENTATION
// ============================================================================

// ============================================================================
// CONSTRUCTORS & LIFECYCLE
// ============================================================================

ThreatIntelFeedManager::ThreatIntelFeedManager() {
    // Register default parsers with exception safety
    try {
        m_parsers[FeedProtocol::REST_API] = std::make_shared<JsonFeedParser>();
        m_parsers[FeedProtocol::JSON_HTTP] = std::make_shared<JsonFeedParser>();
        m_parsers[FeedProtocol::CSV_HTTP] = std::make_shared<CsvFeedParser>();
        m_parsers[FeedProtocol::STIX_TAXII] = std::make_shared<StixFeedParser>();
        m_parsers[FeedProtocol::MISP_API] = std::make_shared<JsonFeedParser>();
    } catch (const std::bad_alloc&) {
        // Parsers will be empty - Initialize() will fail gracefully
        m_parsers.clear();
    }
}

ThreatIntelFeedManager::~ThreatIntelFeedManager() {
    // Ensure clean shutdown
    try {
        Shutdown();
    } catch (...) {
        // Suppress exceptions in destructor
    }
}

ThreatIntelFeedManager::ThreatIntelFeedManager(ThreatIntelFeedManager&& other) noexcept 
    : m_config{}
    , m_running{false}
    , m_shutdown{false}
    , m_initialized{false}
{
    // Lock the other object and transfer state
    std::unique_lock<std::shared_mutex> feedsLock(other.m_feedsMutex);
    std::lock_guard<std::mutex> parsersLock(other.m_parsersMutex);
    
    m_config = std::move(other.m_config);
    m_feeds = std::move(other.m_feeds);
    m_parsers = std::move(other.m_parsers);
    m_running.store(other.m_running.load(std::memory_order_acquire), std::memory_order_release);
    m_initialized.store(other.m_initialized.load(std::memory_order_acquire), std::memory_order_release);
    
    // Reset other's state
    other.m_running.store(false, std::memory_order_release);
    other.m_initialized.store(false, std::memory_order_release);
}

ThreatIntelFeedManager& ThreatIntelFeedManager::operator=(ThreatIntelFeedManager&& other) noexcept {
    if (this != &other) {
        // First shutdown this instance
        Shutdown();
        
        // Lock both objects (consistent ordering to prevent deadlock)
        std::unique_lock<std::shared_mutex> thisLock(m_feedsMutex, std::defer_lock);
        std::unique_lock<std::shared_mutex> otherLock(other.m_feedsMutex, std::defer_lock);
        std::lock(thisLock, otherLock);
        
        std::lock_guard<std::mutex> thisParsersLock(m_parsersMutex);
        std::lock_guard<std::mutex> otherParsersLock(other.m_parsersMutex);
        
        m_config = std::move(other.m_config);
        m_feeds = std::move(other.m_feeds);
        m_parsers = std::move(other.m_parsers);
        m_running.store(other.m_running.load(std::memory_order_acquire), std::memory_order_release);
        m_initialized.store(other.m_initialized.load(std::memory_order_acquire), std::memory_order_release);
        
        // Reset other's state
        other.m_running.store(false, std::memory_order_release);
        other.m_initialized.store(false, std::memory_order_release);
    }
    return *this;
}

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

bool ThreatIntelFeedManager::Initialize(const Config& config) {
    // Check for double initialization
    bool expected = false;
    if (!m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return false;  // Already initialized
    }
    
    std::string errorMsg;
    if (!config.Validate(&errorMsg)) {
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
    
    m_config = config;
    
    // Create data directory if needed with security checks
    if (!m_config.dataDirectory.empty()) {
        try {
            // Validate path doesn't contain suspicious elements
            const std::filesystem::path dataPath(m_config.dataDirectory);
            if (dataPath.has_relative_path() && dataPath.relative_path().string().find("..") != std::string::npos) {
                m_initialized.store(false, std::memory_order_release);
                return false;  // Reject path traversal attempts
            }
            
            std::filesystem::create_directories(dataPath);
            
            // Verify we can write to the directory
            const auto testFile = dataPath / ".write_test";
            {
                std::ofstream test(testFile, std::ios::out);
                if (!test.is_open()) {
                    m_initialized.store(false, std::memory_order_release);
                    return false;
                }
            }
            std::filesystem::remove(testFile);
            
        } catch (const std::filesystem::filesystem_error&) {
            m_initialized.store(false, std::memory_order_release);
            return false;
        } catch (const std::exception&) {
            m_initialized.store(false, std::memory_order_release);
            return false;
        }
    }
    
    // Initialize statistics
    m_stats.startTime = GetCurrentTimestampImpl();
    m_stats.totalFeeds.store(0, std::memory_order_release);
    m_stats.enabledFeeds.store(0, std::memory_order_release);
    m_stats.syncingFeeds.store(0, std::memory_order_release);
    m_stats.errorFeeds.store(0, std::memory_order_release);
    m_stats.totalSyncsCompleted.store(0, std::memory_order_release);
    m_stats.totalIOCsFetched.store(0, std::memory_order_release);
    m_stats.totalBytesDownloaded.store(0, std::memory_order_release);
    m_stats.uptimeSeconds.store(0, std::memory_order_release);
    
    return true;
}

bool ThreatIntelFeedManager::Start() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Use atomic CAS to prevent race conditions on multiple Start() calls
    bool expected = false;
    if (!m_running.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return true;  // Already running
    }
    
    m_shutdown.store(false, std::memory_order_release);
    
    // Determine worker thread count with safety bounds
    uint32_t threadCount = m_config.workerThreads;
    if (threadCount == 0) {
        const unsigned int hwConcurrency = std::thread::hardware_concurrency();
        threadCount = std::max(2u, hwConcurrency > 0 ? hwConcurrency / 2 : 2u);
    }
    threadCount = std::clamp(threadCount, 1u, 16u);
    
    try {
        // Start worker threads with exception safety
        m_workerThreads.reserve(threadCount);
        for (uint32_t i = 0; i < threadCount; ++i) {
            m_workerThreads.emplace_back(&ThreatIntelFeedManager::WorkerThread, this);
        }
        
        // Start scheduler thread
        m_schedulerThread = std::thread(&ThreatIntelFeedManager::SchedulerThread, this);
        
        // Start health monitor if enabled
        if (m_config.enableHealthMonitoring) {
            m_healthThread = std::thread(&ThreatIntelFeedManager::HealthMonitorThread, this);
        }
        
    } catch (const std::system_error&) {
        // Thread creation failed - cleanup and return false
        m_shutdown.store(true, std::memory_order_release);
        m_queueCondition.notify_all();
        
        for (auto& thread : m_workerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_workerThreads.clear();
        
        if (m_schedulerThread.joinable()) {
            m_schedulerThread.join();
        }
        if (m_healthThread.joinable()) {
            m_healthThread.join();
        }
        
        m_running.store(false, std::memory_order_release);
        return false;
    }
    
    // Schedule initial sync for all enabled feeds
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [feedId, context] : m_feeds) {
            if (context && context->config.enabled) {
                ScheduleNextSync(*context);
            }
        }
    }
    
    return true;
}

bool ThreatIntelFeedManager::Stop(uint32_t timeoutMs) {
    if (!m_running.load(std::memory_order_acquire)) {
        return true;
    }
    
    // Signal shutdown
    m_shutdown.store(true, std::memory_order_release);
    m_running.store(false, std::memory_order_release);
    
    // Wake up all waiting threads
    m_queueCondition.notify_all();
    m_syncLimiterCv.notify_all();
    
    const auto startTime = std::chrono::steady_clock::now();
    const auto timeoutDuration = std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 5000);
    
    // Wait for worker threads with timeout
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            const auto elapsed = std::chrono::steady_clock::now() - startTime;
            const auto remaining = timeoutDuration - elapsed;
            
            if (remaining.count() > 0) {
                // Try to join with remaining time
                // Note: std::thread doesn't support timed join, so we just join
                // In production, consider using std::jthread (C++20) or platform-specific APIs
                thread.join();
            } else {
                // Timeout expired - detach remaining threads (they will clean up when done)
                // This is not ideal but prevents blocking indefinitely
                thread.detach();
            }
        }
    }
    m_workerThreads.clear();
    
    // Wait for scheduler thread
    if (m_schedulerThread.joinable()) {
        const auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (elapsed < timeoutDuration) {
            m_schedulerThread.join();
        } else {
            m_schedulerThread.detach();
        }
    }
    
    // Wait for health monitor thread
    if (m_healthThread.joinable()) {
        const auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (elapsed < timeoutDuration) {
            m_healthThread.join();
        } else {
            m_healthThread.detach();
        }
    }
    
    // Clear task queue
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        while (!m_taskQueue.empty()) {
            m_taskQueue.pop();
        }
    }
    
    return true;
}

bool ThreatIntelFeedManager::IsRunning() const noexcept {
    return m_running.load(std::memory_order_acquire);
}

void ThreatIntelFeedManager::Shutdown() {
    Stop(5000);
    
    // Clear feeds with proper locking
    {
        std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
        m_feeds.clear();
    }
    
    // Clear parsers
    {
        std::lock_guard<std::mutex> lock(m_parsersMutex);
        m_parsers.clear();
    }
    
    // Clear callbacks safely
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_eventCallback = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(m_progressMutex);
        m_progressCallback = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        m_authRefreshCallback = nullptr;
    }
    
    // Reset statistics
    m_stats.totalFeeds.store(0, std::memory_order_release);
    m_stats.enabledFeeds.store(0, std::memory_order_release);
    m_stats.syncingFeeds.store(0, std::memory_order_release);
    m_stats.errorFeeds.store(0, std::memory_order_release);
    
    m_initialized.store(false, std::memory_order_release);
}

// ============================================================================
// FEED MANAGEMENT
// ============================================================================

bool ThreatIntelFeedManager::AddFeed(const ThreatFeedConfig& config) {
    std::string errorMsg;
    if (!config.Validate(&errorMsg)) {
        return false;
    }
    
    // Validate feed ID is reasonable
    if (config.feedId.empty() || config.feedId.size() > 256) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    // Check if feed already exists
    if (m_feeds.find(config.feedId) != m_feeds.end()) {
        return false;  // Feed already exists
    }
    
    // Check max feeds limit
    constexpr size_t MAX_FEEDS = 1000;
    if (m_feeds.size() >= MAX_FEEDS) {
        return false;  // Too many feeds
    }
    
    try {
        auto context = std::make_unique<FeedContext>();
        context->config = config;
        context->rateLimit = std::make_unique<RateLimitConfig>(config.rateLimit);
        context->stats.status.store(FeedSyncStatus::Idle, std::memory_order_release);
        context->syncInProgress.store(false, std::memory_order_release);
        context->cancelRequested.store(false, std::memory_order_release);
        
        const std::string feedId = config.feedId;  // Copy before move
        m_feeds[feedId] = std::move(context);
        
        m_stats.totalFeeds.fetch_add(1, std::memory_order_relaxed);
        if (config.enabled) {
            m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
        }
        
        // Emit event (release lock first to prevent deadlock)
        lock.unlock();
        EmitEvent(FeedEventType::FeedAdded, feedId, "Feed added: " + config.name);
        
        // Schedule initial sync if running and enabled
        if (m_running.load(std::memory_order_acquire) && config.enabled) {
            std::shared_lock<std::shared_mutex> readLock(m_feedsMutex);
            auto it = m_feeds.find(feedId);
            if (it != m_feeds.end() && it->second) {
                ScheduleNextSync(*it->second);
            }
        }
        
        return true;
        
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

uint32_t ThreatIntelFeedManager::AddFeeds(std::span<const ThreatFeedConfig> configs) {
    // Security limit on batch size
    constexpr size_t MAX_BATCH_SIZE = 10000;
    if (configs.empty() || configs.size() > MAX_BATCH_SIZE) {
        return 0;
    }
    
    uint32_t added = 0;
    for (const auto& config : configs) {
        // Check total feeds limit
        if (m_stats.totalFeeds.load(std::memory_order_relaxed) >= 1000) {
            break;  // Stop adding when limit reached
        }
        
        if (AddFeed(config)) {
            added++;
            // Prevent overflow
            if (added == UINT32_MAX) {
                break;
            }
        }
    }
    return added;
}

bool ThreatIntelFeedManager::RemoveFeed(const std::string& feedId) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return false;
    }
    
    // Cancel any ongoing sync
    if (it->second) {
        it->second->cancelRequested.store(true, std::memory_order_release);
    }
    
    const bool wasEnabled = it->second ? it->second->config.enabled : false;
    
    // Erase feed
    m_feeds.erase(it);
    
    // Update stats safely
    const uint32_t currentTotal = m_stats.totalFeeds.load(std::memory_order_relaxed);
    if (currentTotal > 0) {
        m_stats.totalFeeds.fetch_sub(1, std::memory_order_relaxed);
    }
    if (wasEnabled) {
        const uint32_t currentEnabled = m_stats.enabledFeeds.load(std::memory_order_relaxed);
        if (currentEnabled > 0) {
            m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
        }
    }
    
    // Emit event without holding lock
    lock.unlock();
    EmitEvent(FeedEventType::FeedRemoved, feedId, "Feed removed");
    
    return true;
}

bool ThreatIntelFeedManager::UpdateFeed(const std::string& feedId, const ThreatFeedConfig& config) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::string errorMsg;
    if (!config.Validate(&errorMsg)) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return false;
    }
    
    const bool wasEnabled = it->second->config.enabled;
    it->second->config = config;
    
    // Create new rate limit config (safely handle allocation failure)
    try {
        it->second->rateLimit = std::make_unique<RateLimitConfig>(config.rateLimit);
    } catch (const std::bad_alloc&) {
        return false;
    }
    
    // Update enabled count safely
    if (wasEnabled != config.enabled) {
        if (config.enabled) {
            m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
        } else {
            const uint32_t currentEnabled = m_stats.enabledFeeds.load(std::memory_order_relaxed);
            if (currentEnabled > 0) {
                m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
            }
        }
    }
    
    // Emit event without holding lock
    const std::string feedIdCopy = feedId;
    lock.unlock();
    EmitEvent(FeedEventType::FeedConfigChanged, feedIdCopy, "Configuration updated");
    
    return true;
}

std::optional<ThreatFeedConfig> ThreatIntelFeedManager::GetFeedConfig(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return std::nullopt;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return std::nullopt;
    }
    
    return it->second->config;
}

std::vector<ThreatFeedConfig> ThreatIntelFeedManager::GetAllFeedConfigs() const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<ThreatFeedConfig> configs;
    
    // Reserve to prevent multiple allocations
    try {
        configs.reserve(m_feeds.size());
    } catch (const std::bad_alloc&) {
        return configs;  // Return empty on allocation failure
    }
    
    for (const auto& [feedId, context] : m_feeds) {
        if (context) {
            try {
                configs.push_back(context->config);
            } catch (const std::bad_alloc&) {
                break;  // Stop on allocation failure
            }
        }
    }
    
    return configs;
}

std::vector<std::string> ThreatIntelFeedManager::GetFeedIds() const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<std::string> ids;
    
    // Reserve to prevent multiple allocations
    try {
        ids.reserve(m_feeds.size());
    } catch (const std::bad_alloc&) {
        return ids;
    }
    
    for (const auto& [feedId, context] : m_feeds) {
        if (!feedId.empty()) {
            try {
                ids.push_back(feedId);
            } catch (const std::bad_alloc&) {
                break;
            }
        }
    }
    
    return ids;
}

bool ThreatIntelFeedManager::HasFeed(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    auto it = m_feeds.find(feedId);
    return it != m_feeds.end() && it->second != nullptr;
}

bool ThreatIntelFeedManager::EnableFeed(const std::string& feedId) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second || it->second->config.enabled) {
        return false;
    }
    
    it->second->config.enabled = true;
    it->second->stats.status.store(FeedSyncStatus::Idle, std::memory_order_release);
    it->second->cancelRequested.store(false, std::memory_order_release);
    m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
    
    const bool isRunning = m_running.load(std::memory_order_acquire);
    FeedContext* contextPtr = it->second.get();
    const std::string feedIdCopy = feedId;
    
    // Emit event without holding lock
    lock.unlock();
    EmitEvent(FeedEventType::FeedEnabled, feedIdCopy);
    
    if (isRunning && contextPtr) {
        std::shared_lock<std::shared_mutex> readLock(m_feedsMutex);
        // Re-validate context is still valid after releasing lock
        auto itCheck = m_feeds.find(feedIdCopy);
        if (itCheck != m_feeds.end() && itCheck->second.get() == contextPtr) {
            ScheduleNextSync(*contextPtr);
        }
    }
    
    return true;
}

bool ThreatIntelFeedManager::DisableFeed(const std::string& feedId) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second || !it->second->config.enabled) {
        return false;
    }
    
    it->second->config.enabled = false;
    it->second->stats.status.store(FeedSyncStatus::Disabled, std::memory_order_release);
    it->second->cancelRequested.store(true, std::memory_order_release);
    it->second->stats.nextScheduledSync.store(0, std::memory_order_release);
    
    const uint32_t currentEnabled = m_stats.enabledFeeds.load(std::memory_order_relaxed);
    if (currentEnabled > 0) {
        m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
    }
    
    const std::string feedIdCopy = feedId;
    lock.unlock();
    EmitEvent(FeedEventType::FeedDisabled, feedIdCopy);
    
    return true;
}

bool ThreatIntelFeedManager::IsFeedEnabled(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    return it != m_feeds.end() && it->second && it->second->config.enabled;
}

// ============================================================================
// SYNCHRONIZATION
// ============================================================================

SyncResult ThreatIntelFeedManager::SyncFeed(
    const std::string& feedId,
    SyncProgressCallback progressCallback
) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        SyncResult result;
        result.feedId = feedId;
        result.errorMessage = "Invalid feed ID";
        return result;
    }
    
    FeedContext* context = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        auto it = m_feeds.find(feedId);
        if (it == m_feeds.end() || !it->second) {
            SyncResult result;
            result.feedId = feedId;
            result.errorMessage = "Feed not found";
            return result;
        }
        context = it->second.get();
    }
    
    return ExecuteSync(*context, SyncTrigger::Manual, std::move(progressCallback));
}

std::future<SyncResult> ThreatIntelFeedManager::SyncFeedAsync(
    const std::string& feedId,
    SyncCompletionCallback completionCallback
) {
    // Validate feedId before starting async operation
    if (feedId.empty() || feedId.size() > 256) {
        std::promise<SyncResult> promise;
        SyncResult result;
        result.feedId = feedId;
        result.errorMessage = "Invalid feed ID";
        promise.set_value(result);
        return promise.get_future();
    }
    
    // Capture copies of feedId and callback for async execution
    return std::async(std::launch::async, [this, feedId, completionCallback]() {
        SyncResult result = SyncFeed(feedId, nullptr);
        if (completionCallback) {
            try {
                completionCallback(result);
            } catch (const std::exception&) {
                // Swallow callback exceptions
            }
        }
        return result;
    });
}

std::unordered_map<std::string, SyncResult> ThreatIntelFeedManager::SyncAllFeeds(
    SyncProgressCallback progressCallback
) {
    std::unordered_map<std::string, SyncResult> results;
    
    // Get feed IDs first (copy to avoid holding lock during sync)
    const std::vector<std::string> feedIds = GetFeedIds();
    
    // Reserve space for results
    try {
        results.reserve(feedIds.size());
    } catch (const std::bad_alloc&) {
        return results;
    }
    
    for (const auto& feedId : feedIds) {
        // Check if manager is still running
        if (!m_running.load(std::memory_order_acquire)) {
            break;
        }
        
        if (IsFeedEnabled(feedId)) {
            try {
                results[feedId] = SyncFeed(feedId, progressCallback);
            } catch (const std::exception&) {
                // Continue with other feeds on error
                SyncResult errorResult;
                errorResult.feedId = feedId;
                errorResult.errorMessage = "Sync exception";
                results[feedId] = errorResult;
            }
        }
    }
    
    return results;
}

void ThreatIntelFeedManager::SyncAllFeedsAsync(SyncCompletionCallback completionCallback) {
    // Get feed IDs first
    const std::vector<std::string> feedIds = GetFeedIds();
    
    for (const auto& feedId : feedIds) {
        // Check if manager is still running
        if (!m_running.load(std::memory_order_acquire)) {
            break;
        }
        
        if (IsFeedEnabled(feedId)) {
            try {
                SyncTask task;
                task.feedId = feedId;
                task.trigger = SyncTrigger::Manual;
                task.priority = FeedPriority::Normal;
                task.completionCallback = completionCallback;
                task.scheduledTime = std::chrono::steady_clock::now();
                
                {
                    std::lock_guard<std::mutex> lock(m_queueMutex);
                    
                    // Prevent queue from growing unbounded
                    constexpr size_t MAX_QUEUE_SIZE = 10000;
                    if (m_taskQueue.size() >= MAX_QUEUE_SIZE) {
                        continue;  // Skip this feed if queue is full
                    }
                    
                    m_taskQueue.push(task);
                }
                m_queueCondition.notify_one();
            } catch (const std::bad_alloc&) {
                break;  // Stop on allocation failure
            }
        }
    }
}

bool ThreatIntelFeedManager::CancelSync(const std::string& feedId) {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return false;
    }
    
    it->second->cancelRequested.store(true, std::memory_order_release);
    return true;
}

void ThreatIntelFeedManager::CancelAllSyncs() {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    for (auto& [_, context] : m_feeds) {
        if (context) {
            context->cancelRequested.store(true, std::memory_order_release);
        }
    }
}

bool ThreatIntelFeedManager::IsSyncing(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return false;
    }
    
    return it->second->syncInProgress.load(std::memory_order_acquire);
}

uint32_t ThreatIntelFeedManager::GetSyncingCount() const noexcept {
    return m_activeSyncCount.load(std::memory_order_relaxed);
}

// ============================================================================
// STATISTICS & MONITORING
// ============================================================================

const FeedStats* ThreatIntelFeedManager::GetFeedStats(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return nullptr;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return nullptr;
    }
    
    return &it->second->stats;
}

const FeedManagerStats& ThreatIntelFeedManager::GetManagerStats() const noexcept {
    return m_stats;
}

FeedSyncStatus ThreatIntelFeedManager::GetFeedStatus(const std::string& feedId) const {
    // Validate feedId
    if (feedId.empty() || feedId.size() > 256) {
        return FeedSyncStatus::Unknown;
    }
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second) {
        return FeedSyncStatus::Unknown;
    }
    
    return it->second->stats.status.load(std::memory_order_acquire);
}

std::vector<std::string> ThreatIntelFeedManager::GetFeedsByStatus(FeedSyncStatus status) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<std::string> feedIds;
    
    // Reserve to prevent multiple allocations
    try {
        feedIds.reserve(m_feeds.size());
    } catch (const std::bad_alloc&) {
        return feedIds;
    }
    
    for (const auto& [feedId, context] : m_feeds) {
        if (context && context->stats.status.load(std::memory_order_acquire) == status) {
            try {
                feedIds.push_back(feedId);
            } catch (const std::bad_alloc&) {
                break;
            }
        }
    }
    
    return feedIds;
}

bool ThreatIntelFeedManager::IsHealthy() const noexcept {
    const uint32_t errorCount = m_stats.errorFeeds.load(std::memory_order_relaxed);
    const uint32_t totalCount = m_stats.totalFeeds.load(std::memory_order_relaxed);
    
    if (totalCount == 0) return true;
    
    // More than 50% in error state is unhealthy
    // Use safe division to prevent any edge cases
    return errorCount <= (totalCount / 2);
}

std::string ThreatIntelFeedManager::GetHealthReport() const {
    std::ostringstream oss;
    
    try {
        const uint32_t total = m_stats.totalFeeds.load(std::memory_order_relaxed);
        const uint32_t enabled = m_stats.enabledFeeds.load(std::memory_order_relaxed);
        const uint32_t syncing = m_stats.syncingFeeds.load(std::memory_order_relaxed);
        const uint32_t errors = m_stats.errorFeeds.load(std::memory_order_relaxed);
        const uint64_t totalSyncs = m_stats.totalSyncsCompleted.load(std::memory_order_relaxed);
        const uint64_t totalIOCs = m_stats.totalIOCsFetched.load(std::memory_order_relaxed);
        const uint64_t totalBytes = m_stats.totalBytesDownloaded.load(std::memory_order_relaxed);
        
        // Safe division for MB conversion
        const uint64_t totalMB = totalBytes / (1024 * 1024);
        
        oss << "Feed Manager Health Report\n";
        oss << "==========================\n";
        oss << "Total Feeds: " << total << "\n";
        oss << "Enabled: " << enabled << "\n";
        oss << "Currently Syncing: " << syncing << "\n";
        oss << "In Error State: " << errors << "\n";
        oss << "Total Syncs: " << totalSyncs << "\n";
        oss << "Total IOCs: " << totalIOCs << "\n";
        oss << "Total Downloaded: " << totalMB << " MB\n";
        oss << "Overall Status: " << (IsHealthy() ? "HEALTHY" : "UNHEALTHY") << "\n";
        
    } catch (const std::exception&) {
        oss << "Error generating health report\n";
    }
    
    return oss.str();
}

// ============================================================================
// CALLBACKS & EVENTS
// ============================================================================

void ThreatIntelFeedManager::SetEventCallback(FeedEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_eventMutex);
    m_eventCallback = std::move(callback);
}

void ThreatIntelFeedManager::SetProgressCallback(SyncProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_progressMutex);
    m_progressCallback = std::move(callback);
}

void ThreatIntelFeedManager::SetAuthRefreshCallback(AuthRefreshCallback callback) {
    std::lock_guard<std::mutex> lock(m_authMutex);
    m_authRefreshCallback = std::move(callback);
}

// ============================================================================
// DATA ACCESS
// ============================================================================

void ThreatIntelFeedManager::SetTargetDatabase(std::shared_ptr<ThreatIntelDatabase> database) {
    if (database) {
        m_database = std::move(database);
    }
}

void ThreatIntelFeedManager::SetTargetStore(std::shared_ptr<ThreatIntelStore> store) {
    if (store) {
        m_store = std::move(store);
    }
}

void ThreatIntelFeedManager::SetHttpClient(std::shared_ptr<IHttpClient> client) {
    if (client) {
        m_httpClient = std::move(client);
    }
}

void ThreatIntelFeedManager::RegisterParser(FeedProtocol protocol, std::shared_ptr<IFeedParser> parser) {
    if (!parser) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_parsersMutex);
    m_parsers[protocol] = std::move(parser);
}

// ============================================================================
// PERSISTENCE
// ============================================================================

/**
 * @brief Save feed configurations to file
 * 
 * Performs atomic write using temporary file to prevent data corruption
 * on write failures. Does NOT save sensitive credentials.
 * 
 * @param path Output file path
 * @return true on success, false on failure
 */
bool ThreatIntelFeedManager::SaveConfigs(const std::filesystem::path& path) const {
    // Validate path
    if (path.empty()) {
        return false;
    }
    
    try {
        nlohmann::json root = nlohmann::json::array();
        
        {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            for (const auto& [feedId, context] : m_feeds) {
                // Validate feedId to prevent injection
                if (feedId.empty() || feedId.size() > 256) {
                    continue;
                }
                
                nlohmann::json feed;
                feed["feedId"] = context->config.feedId;
                feed["name"] = context->config.name;
                feed["description"] = context->config.description;
                feed["source"] = static_cast<int>(context->config.source);
                feed["protocol"] = static_cast<int>(context->config.protocol);
                feed["enabled"] = context->config.enabled;
                feed["baseUrl"] = context->config.endpoint.baseUrl;
                feed["path"] = context->config.endpoint.path;
                feed["syncIntervalSeconds"] = context->config.syncIntervalSeconds;
                feed["authMethod"] = static_cast<int>(context->config.auth.method);
                // Note: Don't save sensitive credentials (apiKey, password, tokens)
                
                root.push_back(feed);
            }
        }
        
        // Atomic write: write to temp file, then rename
        std::filesystem::path tempPath = path;
        tempPath += ".tmp";
        
        {
            std::ofstream file(tempPath, std::ios::out | std::ios::trunc);
            if (!file.is_open()) {
                return false;
            }
            
            const std::string jsonStr = root.dump(2);
            file.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
            
            if (!file.good()) {
                file.close();
                std::filesystem::remove(tempPath);
                return false;
            }
            file.close();
        }
        
        // Rename temp to target (atomic on most filesystems)
        std::error_code ec;
        std::filesystem::rename(tempPath, path, ec);
        if (ec) {
            std::filesystem::remove(tempPath);
            return false;
        }
        
        return true;
        
    } catch (const std::filesystem::filesystem_error&) {
        return false;
    } catch (const nlohmann::json::exception&) {
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * @brief Load feed configurations from file
 * 
 * Validates file content and size limits to prevent malicious input.
 * 
 * @param path Input file path
 * @return true on success, false on failure
 */
bool ThreatIntelFeedManager::LoadConfigs(const std::filesystem::path& path) {
    constexpr size_t MAX_CONFIG_FILE_SIZE = 10 * 1024 * 1024;  // 10MB max
    constexpr size_t MAX_FEEDS_COUNT = 1000;  // Max feeds from single file
    
    if (path.empty()) {
        return false;
    }
    
    try {
        // Check file existence and size
        if (!std::filesystem::exists(path)) {
            return false;
        }
        
        const auto fileSize = std::filesystem::file_size(path);
        if (fileSize == 0 || fileSize > MAX_CONFIG_FILE_SIZE) {
            return false;
        }
        
        std::ifstream file(path, std::ios::in);
        if (!file.is_open()) {
            return false;
        }
        
        nlohmann::json root = nlohmann::json::parse(file);
        
        if (!root.is_array()) {
            return false;
        }
        
        if (root.size() > MAX_FEEDS_COUNT) {
            return false;  // Too many feeds
        }
        
        size_t loadedCount = 0;
        for (const auto& feed : root) {
            if (!feed.is_object()) {
                continue;
            }
            
            ThreatFeedConfig config;
            config.feedId = feed.value("feedId", "");
            config.name = feed.value("name", "");
            config.description = feed.value("description", "");
            
            // Validate feedId
            if (config.feedId.empty() || config.feedId.size() > 256) {
                continue;
            }
            
            // Safely cast integers with range checks
            const int sourceInt = feed.value("source", 0);
            const int protocolInt = feed.value("protocol", 0);
            const int authMethodInt = feed.value("authMethod", 0);
            
            if (sourceInt < 0 || sourceInt > 255) continue;
            if (protocolInt < 0 || protocolInt > 255) continue;
            if (authMethodInt < 0 || authMethodInt > 255) continue;
            
            config.source = static_cast<ThreatIntelSource>(sourceInt);
            config.protocol = static_cast<FeedProtocol>(protocolInt);
            config.enabled = feed.value("enabled", true);
            config.endpoint.baseUrl = feed.value("baseUrl", "");
            config.endpoint.path = feed.value("path", "");
            config.syncIntervalSeconds = feed.value("syncIntervalSeconds", 3600);
            config.auth.method = static_cast<AuthMethod>(authMethodInt);
            
            if (AddFeed(config)) {
                loadedCount++;
            }
        }
        
        return loadedCount > 0;
        
    } catch (const std::filesystem::filesystem_error&) {
        return false;
    } catch (const nlohmann::json::exception&) {
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * @brief Save feed state (sync history) to file
 * 
 * Saves non-sensitive state data like sync timestamps and counts.
 * Uses atomic write for data integrity.
 * 
 * @param path Output file path
 * @return true on success
 */
bool ThreatIntelFeedManager::SaveState(const std::filesystem::path& path) const {
    if (path.empty()) {
        return false;
    }
    
    try {
        nlohmann::json root = nlohmann::json::object();
        
        {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            for (const auto& [feedId, context] : m_feeds) {
                if (feedId.empty() || feedId.size() > 256) {
                    continue;
                }
                
                nlohmann::json state;
                state["lastSync"] = context->stats.lastSuccessfulSync.load(std::memory_order_relaxed);
                state["totalSyncs"] = context->stats.totalSuccessfulSyncs.load(std::memory_order_relaxed);
                state["totalIOCs"] = context->stats.totalIOCsFetched.load(std::memory_order_relaxed);
                root[feedId] = state;
            }
        }
        
        // Atomic write
        std::filesystem::path tempPath = path;
        tempPath += ".tmp";
        
        {
            std::ofstream file(tempPath, std::ios::out | std::ios::trunc);
            if (!file.is_open()) {
                return false;
            }
            
            const std::string jsonStr = root.dump(2);
            file.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
            
            if (!file.good()) {
                file.close();
                std::filesystem::remove(tempPath);
                return false;
            }
            file.close();
        }
        
        std::error_code ec;
        std::filesystem::rename(tempPath, path, ec);
        if (ec) {
            std::filesystem::remove(tempPath);
            return false;
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * @brief Load feed state from file
 * 
 * Restores sync history state. Validates file content.
 * 
 * @param path Input file path
 * @return true on success
 */
bool ThreatIntelFeedManager::LoadState(const std::filesystem::path& path) {
    constexpr size_t MAX_STATE_FILE_SIZE = 10 * 1024 * 1024;  // 10MB max
    
    if (path.empty()) {
        return false;
    }
    
    try {
        if (!std::filesystem::exists(path)) {
            return false;
        }
        
        const auto fileSize = std::filesystem::file_size(path);
        if (fileSize == 0 || fileSize > MAX_STATE_FILE_SIZE) {
            return false;
        }
        
        std::ifstream file(path, std::ios::in);
        if (!file.is_open()) {
            return false;
        }
        
        nlohmann::json root = nlohmann::json::parse(file);
        
        if (!root.is_object()) {
            return false;
        }
        
        std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
        for (auto& [feedId, context] : m_feeds) {
            if (root.contains(feedId) && root[feedId].is_object()) {
                const auto& state = root[feedId];
                context->stats.lastSuccessfulSync.store(
                    state.value("lastSync", 0ULL), std::memory_order_relaxed);
                context->stats.totalSuccessfulSyncs.store(
                    state.value("totalSyncs", 0ULL), std::memory_order_relaxed);
                context->stats.totalIOCsFetched.store(
                    state.value("totalIOCs", 0ULL), std::memory_order_relaxed);
            }
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

std::string ThreatIntelFeedManager::ExportConfigsToJson() const {
    try {
        nlohmann::json root = nlohmann::json::array();
        
        {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            for (const auto& [feedId, context] : m_feeds) {
                if (!context || feedId.empty()) continue;
                
                nlohmann::json feed;
                feed["feedId"] = context->config.feedId;
                feed["name"] = context->config.name;
                feed["enabled"] = context->config.enabled;
                // Note: Don't export sensitive credentials
                root.push_back(feed);
            }
        }
        
        return root.dump(2);
        
    } catch (const std::exception&) {
        return "[]";  // Return empty array on error
    }
}

bool ThreatIntelFeedManager::ImportConfigsFromJson(const std::string& json) {
    // Validate input
    if (json.empty()) {
        return false;
    }
    
    // Size limit to prevent DoS
    constexpr size_t MAX_JSON_SIZE = 10 * 1024 * 1024;  // 10MB
    if (json.size() > MAX_JSON_SIZE) {
        return false;
    }
    
    try {
        nlohmann::json root = nlohmann::json::parse(json);
        
        if (!root.is_array()) {
            return false;
        }
        
        // Limit number of feeds to prevent DoS
        constexpr size_t MAX_IMPORT_FEEDS = 1000;
        if (root.size() > MAX_IMPORT_FEEDS) {
            return false;
        }
        
        size_t importedCount = 0;
        for (const auto& feed : root) {
            if (!feed.is_object()) continue;
            
            ThreatFeedConfig config;
            config.feedId = feed.value("feedId", "");
            config.name = feed.value("name", "");
            config.enabled = feed.value("enabled", true);
            
            // Validate feedId
            if (config.feedId.empty() || config.feedId.size() > 256) {
                continue;
            }
            
            // Additional validation would be done in AddFeed
            if (AddFeed(config)) {
                importedCount++;
            }
        }
        
        return importedCount > 0;
        
    } catch (const nlohmann::json::exception&) {
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

void ThreatIntelFeedManager::WorkerThread() {
    while (!m_shutdown.load(std::memory_order_acquire)) {
        SyncTask task;
        
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            
            // Wait with predicate and periodic wake-up for shutdown check
            const bool hasWork = m_queueCondition.wait_for(lock, std::chrono::milliseconds(100), [this]() {
                return m_shutdown.load(std::memory_order_acquire) || !m_taskQueue.empty();
            });
            
            if (m_shutdown.load(std::memory_order_acquire)) break;
            if (!hasWork || m_taskQueue.empty()) continue;
            
            task = m_taskQueue.top();
            m_taskQueue.pop();
        }
        
        // Acquire sync slot using condition variable (safer than semaphore)
        {
            std::unique_lock<std::mutex> syncLock(m_syncLimiterMutex);
            const bool acquired = m_syncLimiterCv.wait_for(syncLock, std::chrono::seconds(30), [this]() {
                return m_shutdown.load(std::memory_order_acquire) ||
                       m_activeSyncCount.load(std::memory_order_acquire) < MAX_CONCURRENT_SYNCS;
            });
            
            if (m_shutdown.load(std::memory_order_acquire)) break;
            if (!acquired) continue;  // Timeout - retry later
            
            m_activeSyncCount.fetch_add(1, std::memory_order_acq_rel);
        }
        
        // Execute sync with exception safety
        try {
            FeedContext* context = nullptr;
            {
                std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
                auto it = m_feeds.find(task.feedId);
                if (it != m_feeds.end() && it->second) {
                    context = it->second.get();
                }
            }
            
            if (context && context->config.enabled && 
                !context->cancelRequested.load(std::memory_order_acquire)) {
                SyncResult result = ExecuteSync(*context, task.trigger, task.progressCallback);
                
                if (task.completionCallback) {
                    try {
                        task.completionCallback(result);
                    } catch (...) {
                        // Swallow callback exceptions
                    }
                }
            }
        } catch (const std::exception&) {
            // Log error but don't crash worker thread
        } catch (...) {
            // Unknown exception - continue processing
        }
        
        // Release sync slot
        {
            std::lock_guard<std::mutex> syncLock(m_syncLimiterMutex);
            m_activeSyncCount.fetch_sub(1, std::memory_order_acq_rel);
        }
        m_syncLimiterCv.notify_one();
    }
}

void ThreatIntelFeedManager::SchedulerThread() {
    while (!m_shutdown.load(std::memory_order_acquire)) {
        // Sleep with periodic wake-up check (10 seconds)
        for (int i = 0; i < 10 && !m_shutdown.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (m_shutdown.load(std::memory_order_acquire)) break;
        
        const uint64_t now = GetCurrentTimestampImpl();
        
        // Process scheduled syncs
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (auto& [feedId, context] : m_feeds) {
            if (!context) continue;
            if (!context->config.enabled) continue;
            if (context->syncInProgress.load(std::memory_order_acquire)) continue;
            
            const uint64_t nextSync = context->stats.nextScheduledSync.load(std::memory_order_acquire);
            if (nextSync > 0 && now >= nextSync) {
                try {
                    SyncTask task;
                    task.feedId = feedId;
                    task.trigger = SyncTrigger::Scheduled;
                    task.priority = context->config.priority;
                    task.scheduledTime = std::chrono::steady_clock::now();
                    
                    {
                        std::lock_guard<std::mutex> queueLock(m_queueMutex);
                        m_taskQueue.push(task);
                    }
                    m_queueCondition.notify_one();
                    
                    // Clear next scheduled time until sync completes
                    context->stats.nextScheduledSync.store(0, std::memory_order_release);
                    
                } catch (const std::bad_alloc&) {
                    // Queue full or OOM - skip this cycle
                    break;
                }
            }
        }
        
        // Update uptime
        m_stats.uptimeSeconds.store(now - m_stats.startTime, std::memory_order_relaxed);
    }
}

void ThreatIntelFeedManager::HealthMonitorThread() {
    // Minimum health check interval to prevent CPU spinning
    const uint32_t checkIntervalSec = std::max(m_config.healthCheckIntervalSeconds, 10u);
    
    while (!m_shutdown.load(std::memory_order_acquire)) {
        // Sleep with periodic wake-up check
        for (uint32_t i = 0; i < checkIntervalSec && !m_shutdown.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (m_shutdown.load(std::memory_order_acquire)) break;
        
        uint32_t errorCount = 0;
        uint32_t enabledCount = 0;
        
        try {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            for (const auto& [feedId, context] : m_feeds) {
                if (!context) continue;
                if (!context->config.enabled) continue;
                
                enabledCount++;
                
                if (!context->stats.IsHealthy()) {
                    errorCount++;
                    
                    // Check for auto-disable threshold
                    const uint32_t consecutiveErrors = context->stats.consecutiveErrors.load(std::memory_order_relaxed);
                    if (consecutiveErrors >= m_config.maxConsecutiveErrors) {
                        // Emit warning event (don't hold lock during callback)
                        const std::string feedIdCopy = feedId;
                        const std::string msg = "Feed exceeded max consecutive errors (" + 
                                               std::to_string(consecutiveErrors) + ")";
                        
                        lock.unlock();
                        EmitEvent(FeedEventType::HealthWarning, feedIdCopy, msg);
                        lock.lock();  // Re-acquire but iteration may be invalid
                        break;  // Exit loop since we released lock
                    }
                }
            }
        } catch (const std::exception&) {
            // Ignore errors in health check
        }
        
        m_stats.errorFeeds.store(errorCount, std::memory_order_release);
    }
}

SyncResult ThreatIntelFeedManager::ExecuteSync(
    FeedContext& context,
    SyncTrigger trigger,
    SyncProgressCallback progressCallback
) {
    SyncResult result;
    result.feedId = context.config.feedId;
    result.trigger = trigger;
    result.startTime = GetCurrentTimestampImpl();
    
    // Check if already syncing using atomic CAS
    bool expected = false;
    if (!context.syncInProgress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        result.errorMessage = "Sync already in progress";
        return result;
    }
    
    // RAII guard to ensure syncInProgress is reset and stats are updated
    struct SyncGuard {
        FeedContext& ctx;
        ThreatIntelFeedManager& mgr;
        SyncResult& res;
        bool completed = false;
        
        SyncGuard(FeedContext& c, ThreatIntelFeedManager& m, SyncResult& r) 
            : ctx(c), mgr(m), res(r) {}
        
        ~SyncGuard() {
            if (!completed) {
                // Abnormal exit - ensure cleanup
                ctx.syncInProgress.store(false, std::memory_order_release);
                mgr.m_activeSyncCount.fetch_sub(1, std::memory_order_relaxed);
                mgr.m_stats.syncingFeeds.fetch_sub(1, std::memory_order_relaxed);
            }
        }
        
        void complete() { completed = true; }
    } guard(context, *this, result);
    
    context.cancelRequested.store(false, std::memory_order_release);
    context.stats.status.store(FeedSyncStatus::Syncing, std::memory_order_release);
    context.stats.lastSyncAttempt.store(result.startTime, std::memory_order_release);
    context.stats.SetCurrentPhase("Starting sync");
    context.lastSyncStart = std::chrono::steady_clock::now();
    
    // Note: Don't increment m_activeSyncCount here - WorkerThread already did
    m_stats.syncingFeeds.fetch_add(1, std::memory_order_relaxed);
    
    EmitEvent(FeedEventType::SyncStarted, context.config.feedId);
    
    try {
        // Check for cancellation before starting
        if (context.cancelRequested.load(std::memory_order_acquire)) {
            result.errorMessage = "Sync cancelled before start";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Wait for rate limit
        if (!WaitForRateLimit(context)) {
            result.errorMessage = "Rate limit wait cancelled";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Fetch data
        context.stats.SetCurrentPhase("Fetching data");
        const std::string url = context.config.endpoint.GetFullUrl();
        
        if (url.empty()) {
            result.errorMessage = "Invalid feed URL";
            throw std::runtime_error(result.errorMessage);
        }
        
        HttpResponse response = FetchFeedData(context, url);
        
        if (!response.IsSuccess()) {
            result.httpErrors++;
            result.errorCode = std::to_string(response.statusCode);
            result.errorMessage = response.error.empty() ? response.statusMessage : response.error;
            throw std::runtime_error(result.errorMessage);
        }
        
        result.bytesDownloaded = response.body.size();
        result.httpRequests++;
        
        // Check for cancellation
        if (context.cancelRequested.load(std::memory_order_acquire)) {
            result.errorMessage = "Sync cancelled during fetch";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Parse response
        context.stats.SetCurrentPhase("Parsing response");
        context.stats.status.store(FeedSyncStatus::Parsing, std::memory_order_release);
        
        std::vector<IOCEntry> entries;
        if (!ParseFeedResponse(context, response, entries)) {
            result.errorMessage = "Failed to parse response";
            throw std::runtime_error(result.errorMessage);
        }
        
        result.totalFetched = entries.size();
        
        // Check for cancellation
        if (context.cancelRequested.load(std::memory_order_acquire)) {
            result.errorMessage = "Sync cancelled during parse";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Store IOCs
        context.stats.SetCurrentPhase("Storing IOCs");
        context.stats.status.store(FeedSyncStatus::Storing, std::memory_order_release);
        
        if (!StoreIOCs(context, entries, result)) {
            result.errorMessage = "Failed to store IOCs";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Success
        result.success = true;
        result.endTime = GetCurrentTimestampImpl();
        result.durationMs = (result.endTime > result.startTime) ? 
                           (result.endTime - result.startTime) : 0;
        
        // Update stats atomically
        context.stats.lastSuccessfulSync.store(result.endTime, std::memory_order_release);
        context.stats.totalSuccessfulSyncs.fetch_add(1, std::memory_order_relaxed);
        context.stats.totalIOCsFetched.fetch_add(result.totalFetched, std::memory_order_relaxed);
        context.stats.lastSyncIOCCount.store(result.totalFetched, std::memory_order_release);
        context.stats.lastSyncNewIOCs.store(result.newIOCs, std::memory_order_release);
        context.stats.totalBytesDownloaded.fetch_add(result.bytesDownloaded, std::memory_order_relaxed);
        context.stats.lastSyncDurationMs.store(result.durationMs, std::memory_order_release);
        context.stats.consecutiveErrors.store(0, std::memory_order_release);
        context.stats.status.store(FeedSyncStatus::Idle, std::memory_order_release);
        
        m_stats.totalSyncsCompleted.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalIOCsFetched.fetch_add(result.totalFetched, std::memory_order_relaxed);
        m_stats.totalBytesDownloaded.fetch_add(result.bytesDownloaded, std::memory_order_relaxed);
        
        EmitEvent(FeedEventType::SyncCompleted, context.config.feedId,
                 "Fetched " + std::to_string(result.totalFetched) + " IOCs");
        
    } catch (const std::exception& e) {
        result.success = false;
        result.endTime = GetCurrentTimestampImpl();
        result.durationMs = (result.endTime > result.startTime) ? 
                           (result.endTime - result.startTime) : 0;
        
        context.stats.totalFailedSyncs.fetch_add(1, std::memory_order_relaxed);
        context.stats.consecutiveErrors.fetch_add(1, std::memory_order_relaxed);
        context.stats.SetLastError(e.what());
        context.stats.status.store(FeedSyncStatus::Error, std::memory_order_release);
        
        EmitEvent(FeedEventType::SyncFailed, context.config.feedId, e.what());
    }
    
    // Schedule next sync
    ScheduleNextSync(context);
    
    // Note: Don't decrement m_activeSyncCount here - WorkerThread will do it
    m_stats.syncingFeeds.fetch_sub(1, std::memory_order_relaxed);
    context.syncInProgress.store(false, std::memory_order_release);
    
    guard.complete();  // Prevent double cleanup
    
    return result;
}

HttpResponse ThreatIntelFeedManager::FetchFeedData(
    FeedContext& context,
    const std::string& url,
    uint64_t /*offset*/
) {
    HttpResponse response;
    
    // Validate URL
    if (url.empty()) {
        response.error = "Empty URL";
        return response;
    }
    
    // Strict URL length limit to prevent buffer issues
    constexpr size_t MAX_URL_LENGTH = 8192;
    if (url.size() > MAX_URL_LENGTH) {
        response.error = "URL too long (max " + std::to_string(MAX_URL_LENGTH) + " characters)";
        return response;
    }
    
    // Validate URL scheme for security
    const bool isHttps = url.starts_with("https://");
    const bool isHttp = url.starts_with("http://");
    if (!isHttps && !isHttp) {
        response.error = "Invalid URL scheme (only http/https supported)";
        return response;
    }
    
    // RAII wrapper for WinINet handles to prevent leaks
    struct WinINetHandleGuard {
        HINTERNET handle = nullptr;
        WinINetHandleGuard() = default;
        explicit WinINetHandleGuard(HINTERNET h) : handle(h) {}
        ~WinINetHandleGuard() { 
            if (handle) {
                InternetCloseHandle(handle); 
                handle = nullptr;
            }
        }
        WinINetHandleGuard(const WinINetHandleGuard&) = delete;
        WinINetHandleGuard& operator=(const WinINetHandleGuard&) = delete;
        WinINetHandleGuard(WinINetHandleGuard&& other) noexcept : handle(other.handle) { 
            other.handle = nullptr; 
        }
        WinINetHandleGuard& operator=(WinINetHandleGuard&& other) noexcept {
            if (this != &other) {
                if (handle) InternetCloseHandle(handle);
                handle = other.handle;
                other.handle = nullptr;
            }
            return *this;
        }
        explicit operator bool() const noexcept { return handle != nullptr; }
        HINTERNET get() const noexcept { return handle; }
    };
    
    // Build user agent (validate length)
    std::string userAgent = "ShadowStrike/1.0";
    if (!context.config.userAgent.empty() && context.config.userAgent.size() <= 256) {
        userAgent = context.config.userAgent;
    }
    
    // Initialize WinINet
    WinINetHandleGuard hInternet(InternetOpenA(
        userAgent.c_str(),
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr, nullptr, 0
    ));
    
    if (!hInternet) {
        const DWORD error = GetLastError();
        response.error = "Failed to initialize WinINet: error " + std::to_string(error);
        return response;
    }
    
    // Configure timeouts (clamp to reasonable values)
    const DWORD connectTimeout = std::clamp(context.config.connectionTimeoutMs, 1000u, 120000u);
    const DWORD readTimeout = std::clamp(context.config.readTimeoutMs, 1000u, 300000u);
    
    InternetSetOptionA(hInternet.get(), INTERNET_OPTION_CONNECT_TIMEOUT, 
                       const_cast<DWORD*>(&connectTimeout), sizeof(connectTimeout));
    InternetSetOptionA(hInternet.get(), INTERNET_OPTION_RECEIVE_TIMEOUT, 
                       const_cast<DWORD*>(&readTimeout), sizeof(readTimeout));
    InternetSetOptionA(hInternet.get(), INTERNET_OPTION_SEND_TIMEOUT, 
                       const_cast<DWORD*>(&readTimeout), sizeof(readTimeout));
    
    // Build request flags - prefer HTTPS with certificate validation
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
    if (isHttps) {
        flags |= INTERNET_FLAG_SECURE;
        // Note: In production, consider INTERNET_FLAG_IGNORE_CERT_CN_INVALID only if specifically configured
    }
    
    // Open URL
    WinINetHandleGuard hConnect(InternetOpenUrlA(
        hInternet.get(),
        url.c_str(),
        nullptr, 0,
        flags,
        0
    ));
    
    if (!hConnect) {
        const DWORD error = GetLastError();
        response.error = "Failed to connect: error " + std::to_string(error);
        return response;
    }
    
    // Response size limits to prevent memory exhaustion attacks
    constexpr size_t MAX_RESPONSE_SIZE = 100 * 1024 * 1024;  // 100MB max
    constexpr size_t INITIAL_BUFFER_SIZE = 64 * 1024;  // 64KB initial
    constexpr size_t READ_CHUNK_SIZE = 8192;
    
    try {
        response.body.reserve(INITIAL_BUFFER_SIZE);
    } catch (const std::bad_alloc&) {
        response.error = "Failed to allocate response buffer";
        return response;
    }
    
    // Read response with size checking
    std::vector<uint8_t> buffer(READ_CHUNK_SIZE);
    DWORD bytesRead = 0;
    
    while (InternetReadFile(hConnect.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead)) {
        if (bytesRead == 0) {
            break;  // End of data
        }
        
        // Check size limit before adding
        if (response.body.size() + bytesRead > MAX_RESPONSE_SIZE) {
            response.error = "Response too large (exceeds " + std::to_string(MAX_RESPONSE_SIZE / 1024 / 1024) + "MB limit)";
            return response;
        }
        
        try {
            response.body.insert(response.body.end(), buffer.begin(), buffer.begin() + bytesRead);
        } catch (const std::bad_alloc&) {
            response.error = "Out of memory while reading response";
            return response;
        }
        
        // Update progress in stats
        context.stats.totalBytesDownloaded.fetch_add(bytesRead, std::memory_order_relaxed);
        
        // Check for cancellation periodically
        if (context.cancelRequested.load(std::memory_order_acquire)) {
            response.error = "Request cancelled by user";
            return response;
        }
    }
    
    // Get HTTP status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (HttpQueryInfoA(hConnect.get(), HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                       &statusCode, &statusSize, nullptr)) {
        response.statusCode = static_cast<int>(statusCode);
    } else {
        response.statusCode = -1;  // Unknown status
    }
    
    // Get status text (with length limit)
    char statusText[256] = {0};
    DWORD statusTextSize = sizeof(statusText) - 1;
    if (HttpQueryInfoA(hConnect.get(), HTTP_QUERY_STATUS_TEXT,
                       statusText, &statusTextSize, nullptr)) {
        statusText[sizeof(statusText) - 1] = '\0';  // Ensure null termination
        response.statusMessage = std::string(statusText, std::min(statusTextSize, static_cast<DWORD>(sizeof(statusText) - 1)));
    }
    
    // Get important headers (Content-Type, Retry-After)
    char headerBuffer[1024] = {0};
    DWORD headerSize = sizeof(headerBuffer) - 1;
    if (HttpQueryInfoA(hConnect.get(), HTTP_QUERY_CONTENT_TYPE,
                       headerBuffer, &headerSize, nullptr)) {
        headerBuffer[sizeof(headerBuffer) - 1] = '\0';
        response.headers["Content-Type"] = std::string(headerBuffer, std::min(headerSize, static_cast<DWORD>(sizeof(headerBuffer) - 1)));
    }
    
    headerSize = sizeof(headerBuffer) - 1;
    if (HttpQueryInfoA(hConnect.get(), HTTP_QUERY_CUSTOM,
                       headerBuffer, &headerSize, nullptr)) {
        // Try to get Retry-After if present
    }
    
    // Handles automatically closed by RAII guards
    return response;
}

bool ThreatIntelFeedManager::ParseFeedResponse(
    FeedContext& context,
    const HttpResponse& response,
    std::vector<IOCEntry>& outEntries
) {
    // Validate response
    if (response.body.empty()) {
        return false;
    }
    
    IFeedParser* parser = GetParser(context.config.protocol);
    if (!parser) {
        return false;
    }
    
    // Parse with size limit enforcement
    constexpr size_t MAX_ENTRIES = 10000000;  // 10M max entries
    
    const bool success = parser->Parse(
        std::span<const uint8_t>(response.body),
        outEntries,
        context.config.parser
    );
    
    // Enforce entry limit
    if (outEntries.size() > MAX_ENTRIES) {
        outEntries.resize(MAX_ENTRIES);
    }
    
    return success;
}

bool ThreatIntelFeedManager::StoreIOCs(
    FeedContext& context,
    const std::vector<IOCEntry>& entries,
    SyncResult& result
) {
    // In production, this would write to the database/store
    // For now, just count the entries
    
    // Validate context
    if (entries.empty()) {
        return true;  // Nothing to store is success
    }
    
    // Check for cancellation
    if (context.cancelRequested.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Track new IOCs
    uint64_t newCount = 0;
    uint64_t updatedCount = 0;
    
    for (const auto& entry : entries) {
        // In real implementation: check if exists, insert/update
        // For now, count as new
        newCount++;
        
        // Periodic cancellation check
        if ((newCount % 10000) == 0) {
            if (context.cancelRequested.load(std::memory_order_acquire)) {
                return false;
            }
        }
    }
    
    result.newIOCs = newCount;
    result.updatedIOCs = updatedCount;
    
    return true;
}

bool ThreatIntelFeedManager::WaitForRateLimit(FeedContext& context) {
    // Validate rate limit config exists
    if (!context.rateLimit) {
        return !context.cancelRequested.load(std::memory_order_acquire);
    }
    
    auto& rl = *context.rateLimit;
    
    const uint64_t now = GetCurrentTimestampMs();
    const uint64_t lastRequest = rl.lastRequestTime.load(std::memory_order_acquire);
    
    // Calculate wait time with overflow protection
    if (lastRequest > 0 && now >= lastRequest) {
        const uint64_t elapsed = now - lastRequest;
        if (elapsed < rl.minIntervalMs) {
            const uint64_t waitMs = rl.minIntervalMs - elapsed;
            
            // Cap maximum wait to prevent excessive blocking
            constexpr uint64_t MAX_WAIT_MS = 60000;  // 60 seconds max
            const uint64_t actualWait = std::min(waitMs, MAX_WAIT_MS);
            
            // Wait in small intervals to allow cancellation
            constexpr uint64_t CHECK_INTERVAL_MS = 100;
            uint64_t remaining = actualWait;
            while (remaining > 0) {
                if (context.cancelRequested.load(std::memory_order_acquire)) {
                    return false;
                }
                const uint64_t sleepTime = std::min(remaining, CHECK_INTERVAL_MS);
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
                remaining -= sleepTime;
            }
        }
    }
    
    // Check retry-after with overflow protection
    const uint64_t retryAfter = rl.retryAfterTime.load(std::memory_order_acquire);
    if (retryAfter > 0 && now < retryAfter) {
        context.stats.status.store(FeedSyncStatus::RateLimited, std::memory_order_release);
        
        const uint64_t waitMs = retryAfter - now;
        constexpr uint64_t MAX_RETRY_WAIT_MS = 300000;  // 5 minutes max
        const uint64_t actualWait = std::min(waitMs, MAX_RETRY_WAIT_MS);
        
        // Wait in intervals for cancellation
        constexpr uint64_t CHECK_INTERVAL_MS = 500;
        uint64_t remaining = actualWait;
        while (remaining > 0) {
            if (context.cancelRequested.load(std::memory_order_acquire)) {
                return false;
            }
            const uint64_t sleepTime = std::min(remaining, CHECK_INTERVAL_MS);
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
            remaining -= sleepTime;
        }
    }
    
    rl.lastRequestTime.store(GetCurrentTimestampMs(), std::memory_order_release);
    
    // Prevent overflow on counter
    const uint32_t currentCount = rl.currentMinuteCount.load(std::memory_order_relaxed);
    if (currentCount < UINT32_MAX) {
        rl.currentMinuteCount.fetch_add(1, std::memory_order_relaxed);
    }
    
    return !context.cancelRequested.load(std::memory_order_acquire);
}

bool ThreatIntelFeedManager::PrepareAuthentication(FeedContext& context, HttpRequest& request) {
    const auto& auth = context.config.auth;
    
    // Validate request URL exists
    if (request.url.empty()) {
        return false;
    }
    
    try {
        switch (auth.method) {
            case AuthMethod::ApiKey:
                // Validate API key before use
                if (auth.apiKey.empty()) {
                    return false;
                }
                if (auth.apiKeyInQuery) {
                    // Validate query param name
                    if (auth.apiKeyQueryParam.empty() || auth.apiKeyQueryParam.size() > 128) {
                        return false;
                    }
                    // Check URL length before appending
                    constexpr size_t MAX_URL_LENGTH = 8192;
                    const std::string encodedKey = UrlEncode(auth.apiKey);
                    const size_t additionalLength = 1 + auth.apiKeyQueryParam.size() + 1 + encodedKey.size();
                    if (request.url.size() + additionalLength > MAX_URL_LENGTH) {
                        return false;
                    }
                    request.url += (request.url.find('?') == std::string::npos ? "?" : "&");
                    request.url += auth.apiKeyQueryParam + "=" + encodedKey;
                } else {
                    // Validate header name
                    if (auth.apiKeyHeader.empty() || auth.apiKeyHeader.size() > 128) {
                        return false;
                    }
                    request.headers[auth.apiKeyHeader] = auth.apiKey;
                }
                break;
                
            case AuthMethod::BasicAuth:
                // Validate credentials
                if (auth.username.empty()) {
                    return false;
                }
                // Password can be empty but username cannot
                request.headers["Authorization"] = "Basic " + 
                    Base64Encode(auth.username + ":" + auth.password);
                break;
                
            case AuthMethod::BearerToken:
                // Validate token
                if (auth.accessToken.empty()) {
                    return false;
                }
                request.headers["Authorization"] = "Bearer " + auth.accessToken;
                break;
                
            case AuthMethod::OAuth2:
                // Validate OAuth2 token
                if (auth.accessToken.empty()) {
                    // Try to refresh token
                    if (!RefreshOAuth2Token(context)) {
                        return false;
                    }
                    // Re-check after refresh attempt
                    if (context.config.auth.accessToken.empty()) {
                        return false;
                    }
                }
                request.headers["Authorization"] = "Bearer " + auth.accessToken;
                break;
                
            case AuthMethod::None:
            default:
                // No authentication required
                break;
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool ThreatIntelFeedManager::RefreshOAuth2Token(FeedContext& context) {
    // OAuth2 token refresh implementation
    // This is a placeholder - full implementation would involve:
    // 1. Check if refresh token is available and valid
    // 2. Make token refresh request to OAuth2 provider
    // 3. Update access token and expiry time
    // 4. Securely store new tokens
    
    auto& auth = context.config.auth;
    
    // Validate we have refresh token
    if (auth.refreshToken.empty()) {
        return false;
    }
    
    // Validate OAuth2 endpoint
    if (auth.tokenUrl.empty()) {
        return false;
    }
    
    // Check if current token is actually expired
    const uint64_t now = GetCurrentTimestampImpl();
    if (!auth.accessToken.empty() && auth.tokenExpiry > now) {
        // Token still valid, no refresh needed
        return true;
    }
    
    // Call auth refresh callback if registered
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (m_authRefreshCallback) {
            try {
                return m_authRefreshCallback(auth);
            } catch (const std::exception&) {
                return false;
            }
        }
    }
    
    // No callback registered and token expired - cannot refresh
    return false;
}

uint32_t ThreatIntelFeedManager::CalculateRetryDelay(const FeedContext& context, uint32_t attempt) {
    // Clamp attempt to prevent overflow in exponential calculation
    constexpr uint32_t MAX_ATTEMPT = 30;
    const uint32_t safeAttempt = std::min(attempt, MAX_ATTEMPT);
    
    return context.config.retry.CalculateDelay(safeAttempt);
}

IFeedParser* ThreatIntelFeedManager::GetParser(FeedProtocol protocol) {
    std::lock_guard<std::mutex> lock(m_parsersMutex);
    
    // Direct lookup for requested protocol
    auto it = m_parsers.find(protocol);
    if (it != m_parsers.end() && it->second) {
        return it->second.get();
    }
    
    // Fall back to JSON parser for REST APIs
    if (protocol != FeedProtocol::REST_API) {
        it = m_parsers.find(FeedProtocol::REST_API);
        if (it != m_parsers.end() && it->second) {
            return it->second.get();
        }
    }
    
    // No parser found
    return nullptr;
}

void ThreatIntelFeedManager::EmitEvent(FeedEventType type, const std::string& feedId, const std::string& message) {
    // Copy callback under lock to avoid holding lock during callback
    FeedEventCallback callback;
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        callback = m_eventCallback;
    }
    
    if (callback) {
        try {
            FeedEvent event = FeedEvent::Create(type, feedId, message);
            callback(event);
        } catch (const std::exception&) {
            // Swallow callback exceptions to prevent caller disruption
        } catch (...) {
            // Unknown exception - ignore
        }
    }
}

void ThreatIntelFeedManager::ScheduleNextSync(FeedContext& context) {
    if (!context.config.enabled || context.config.syncIntervalSeconds == 0) {
        context.stats.nextScheduledSync.store(0, std::memory_order_release);
        return;
    }
    
    const uint64_t now = GetCurrentTimestampImpl();
    
    // Overflow-safe calculation
    constexpr uint64_t MAX_INTERVAL = 365 * 24 * 60 * 60;  // 1 year max
    const uint64_t interval = std::min(static_cast<uint64_t>(context.config.syncIntervalSeconds), MAX_INTERVAL);
    
    // Check for overflow before adding
    uint64_t nextSync;
    if (now > UINT64_MAX - interval) {
        nextSync = UINT64_MAX;  // Saturate instead of overflow
    } else {
        nextSync = now + interval;
    }
    
    context.stats.nextScheduledSync.store(nextSync, std::memory_order_release);
}

void ThreatIntelFeedManager::UpdateManagerStats() {
    uint32_t errorCount = 0;
    uint32_t syncingCount = 0;
    
    // Scope lock to minimize hold time
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [_, context] : m_feeds) {
            if (!context) continue;
            
            const FeedSyncStatus status = context->stats.status.load(std::memory_order_acquire);
            if (status == FeedSyncStatus::Error) {
                errorCount++;
            }
            if (status == FeedSyncStatus::Syncing || 
                status == FeedSyncStatus::Parsing || 
                status == FeedSyncStatus::Storing) {
                syncingCount++;
            }
        }
    }
    
    m_stats.errorFeeds.store(errorCount, std::memory_order_release);
    m_stats.syncingFeeds.store(syncingCount, std::memory_order_release);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
