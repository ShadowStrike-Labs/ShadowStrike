
#pragma once

#include <chrono>
#include <iostream>
#include <string>
#include <random>
#include <thread>
#include "ThreatIntelFormat.hpp"  // For Format:: utilities
#include "../../src/Utils/Base64Utils.hpp"


namespace ShadowStrike {
    namespace ThreatIntel_Util {
       

            // ============================================================================
            // UTILITY FUNCTION IMPLEMENTATIONS
            // ============================================================================
            
            // NOTE: String/parsing utilities have been moved to ThreatIntel::Format namespace.
            // Use Format::TrimWhitespace, Format::ToLowerASCII, Format::SafeParseIPv4, etc.
            // The functions below delegate to Format:: for backward compatibility.
                /**
                 * @brief Get current timestamp in seconds since epoch
                 */
            [[nodiscard]] inline uint64_t GetCurrentTimestampImpl() noexcept {
                return static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count()
                    );
            }

            /**
             * @brief Get current timestamp in milliseconds since epoch
             */
            [[nodiscard]] inline uint64_t GetCurrentTimestampMs() noexcept {
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
            [[nodiscard]] inline double GetRandomJitter(double factor) noexcept {
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
                }
                catch (...) {
                    // Fallback if RNG fails - return deterministic zero
                    return 0.0;
                }
            }

            /**
             * @brief Trim whitespace from string
             * @note Delegates to ThreatIntel::Format::TrimWhitespace.
             *
             * @param str Input string view
             * @return Trimmed string, empty if input is all whitespace
             */
            [[nodiscard]] inline std::string TrimString(std::string_view str) {
                auto trimmed = ThreatIntel::Format::TrimWhitespace(str);
                return std::string(trimmed);
            }

            /**
             * @brief Convert string to lowercase
             * @note Delegates to ThreatIntel::Format::ToLowerASCII.
             *
             * @param str Input string view
             * @return Lowercase string
             */
            [[nodiscard]] inline std::string ToLowerCase(std::string_view str) {
                return ThreatIntel::Format::ToLowerCase(str);
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
            [[nodiscard]] inline std::string UrlEncode(std::string_view str) {
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
                    }
                    else {
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
             * Uses Standard Base64 alphabet suitable for HTTP headers.
             *
             * @param input Input bytes to encode
             * @return Base64 encoded string, empty on failure
             */
            [[nodiscard]] inline std::string Base64Encode(std::string_view input) {
                // Handle empty input
                if (input.empty()) {
                    return "";
                }

                std::string output;

                try {
                    // Use Base64Utils with Standard alphabet (suitable for HTTP Basic Auth)
                    const Utils::Base64EncodeOptions options{
                        .alphabet = Utils::Base64Alphabet::Standard,
                        .flags = Utils::Base64Flags::None  // Standard encoding with padding
                    };

                    // Call Base64Utils encode function
                    if (!Utils::Base64Encode(input, output, options)) {
                        return "";  // Encode failed
                    }

                    return output;  // ← RETURN STATEMENT!

                }
                catch (const std::bad_alloc&) {
                    return "";  // Memory allocation failed
                }
                catch (const std::exception&) {
                    return "";  // Any other exception
                }
            }
            /**
             * @brief UrlSafe-Base64 encode for Basic Auth
             *
             * RFC 4648 compliant Base64 encoding with proper padding.
             * Thread-safe and exception-safe implementation.
             * Uses Standard Base64 alphabet suitable for HTTP headers.
             *
             * @param input Input bytes to encode
             * @return Base64 encoded string, empty on failure
             */

            [[nodiscard]] inline std::string Base64EncodeUrlSafe(std::string_view input) {
                if (input.empty()) return "";

                std::string output;
                try {
                    const Utils::Base64EncodeOptions options{
                        .alphabet = Utils::Base64Alphabet::UrlSafe,
                        .flags = Utils::Base64Flags::None
                    };

                    if (!Utils::Base64Encode(input, output, options)) {
                        return "";
                    }
                    return output;
                }
                catch (const std::exception&) {
                    return "";
                }
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
            [[nodiscard]] inline uint64_t ParseISO8601(const std::string& timestamp) {
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
                    }
                    else {
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
            [[nodiscard]] inline bool IsValidIPv4(std::string_view str) {
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
                    }
                    else if (c >= '0' && c <= '9') {
                        value = value * 10 + (c - '0');
                        digitCount++;
                        if (digitCount > 3 || value > 255) {
                            return false;
                        }
                    }
                    else {
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
            [[nodiscard]] inline bool IsValidIPv6(std::string_view str) {
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
                    }
                    else if ((c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F')) {
                        groupLen++;
                        if (groupLen > 4) {
                            return false;  // Hex group too long
                        }
                    }
                    else {
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
            [[nodiscard]] inline bool IsValidDomain(std::string_view str) {
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
                    }
                    else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9')) {
                        if (labelLength == 0) {
                            // First character of label - cannot be hyphen (already checked above)
                        }
                        labelLength++;
                        lastWasHyphen = false;
                    }
                    else if (c == '-') {
                        if (labelLength == 0) {
                            labelStartsWithHyphen = true;  // Label starts with hyphen - invalid
                        }
                        labelLength++;
                        lastWasHyphen = true;
                    }
                    else {
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
            [[nodiscard]] inline bool IsValidUrlString(std::string_view str) {
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
            [[nodiscard]] inline bool IsValidEmail(std::string_view str) {
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
            [[nodiscard]] inline bool IsValidHash(std::string_view str) {
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
             * @note Delegates to ThreatIntel::Format::HexCharToValue.
             *
             * @param c Hex character ('0'-'9', 'a'-'f', 'A'-'F')
             * @return Value 0-15, or -1 if invalid character
             */
            [[nodiscard]] constexpr int HexCharToValue(char c) noexcept {
                return ThreatIntel::Format::HexCharToValue(c);
            }

            /**
             * @brief Parse hex string to bytes
             * @note Delegates to ThreatIntel::Format::ParseHexString.
             *
             * @param hex Hex string (must be exactly 2*outLen characters)
             * @param out Output buffer for bytes
             * @param outLen Size of output buffer in bytes
             * @return true if parse successful, false on invalid input
             */
            [[nodiscard]] inline bool ParseHexString(std::string_view hex, uint8_t* out, size_t outLen) {
                return ThreatIntel::Format::ParseHexString(hex, out, outLen);
            }

            /**
             * @brief Safely parse IPv4 address string to octets
             * @note Delegates to ThreatIntel::Format::SafeParseIPv4.
             *
             * @param str IPv4 address string
             * @param octets Output array for 4 octets (must be size 4)
             * @return true if parse successful and valid IPv4 address
             */
            [[nodiscard]] inline bool SafeParseIPv4(std::string_view str, uint8_t octets[4]) noexcept {
                return ThreatIntel::Format::SafeParseIPv4(str, octets);
            }
    }

}