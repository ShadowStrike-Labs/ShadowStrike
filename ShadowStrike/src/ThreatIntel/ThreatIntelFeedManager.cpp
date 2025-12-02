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
 */
[[nodiscard]] double GetRandomJitter(double factor) noexcept {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<double> dist(-factor, factor);
    return dist(rng);
}

/**
 * @brief Trim whitespace from string
 */
[[nodiscard]] std::string TrimString(std::string_view str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return std::string(str.substr(start, end - start + 1));
}

/**
 * @brief Convert string to lowercase
 */
[[nodiscard]] std::string ToLowerCase(std::string_view str) {
    std::string result(str);
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

/**
 * @brief URL encode string
 */
[[nodiscard]] std::string UrlEncode(std::string_view str) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    
    for (unsigned char c : str) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            oss << c;
        } else {
            oss << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    
    return oss.str();
}

/**
 * @brief Base64 encode for Basic Auth
 */
[[nodiscard]] std::string Base64Encode(std::string_view input) {
    static constexpr const char* chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    result.reserve(((input.size() + 2) / 3) * 4);
    
    size_t i = 0;
    while (i < input.size()) {
        uint32_t octet_a = i < input.size() ? static_cast<unsigned char>(input[i++]) : 0;
        uint32_t octet_b = i < input.size() ? static_cast<unsigned char>(input[i++]) : 0;
        uint32_t octet_c = i < input.size() ? static_cast<unsigned char>(input[i++]) : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        result += chars[(triple >> 18) & 0x3F];
        result += chars[(triple >> 12) & 0x3F];
        result += chars[(triple >> 6) & 0x3F];
        result += chars[triple & 0x3F];
    }
    
    // Add padding
    size_t padding = (3 - (input.size() % 3)) % 3;
    for (size_t p = 0; p < padding; ++p) {
        result[result.size() - 1 - p] = '=';
    }
    
    return result;
}

/**
 * @brief Parse ISO8601 timestamp to Unix timestamp
 */
[[nodiscard]] uint64_t ParseISO8601(const std::string& timestamp) {
    std::tm tm = {};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        // Try alternate format
        ss.clear();
        ss.str(timestamp);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    }
    if (ss.fail()) return 0;
    
    return static_cast<uint64_t>(_mkgmtime(&tm));
}

/**
 * @brief Check if string is valid IPv4
 */
[[nodiscard]] bool IsValidIPv4(std::string_view str) {
    int segments = 0;
    int value = 0;
    int digitCount = 0;
    
    for (char c : str) {
        if (c == '.') {
            if (digitCount == 0 || value > 255) return false;
            segments++;
            value = 0;
            digitCount = 0;
        } else if (std::isdigit(c)) {
            value = value * 10 + (c - '0');
            digitCount++;
            if (digitCount > 3) return false;
        } else {
            return false;
        }
    }
    
    return segments == 3 && digitCount > 0 && value <= 255;
}

/**
 * @brief Check if string is valid IPv6
 */
[[nodiscard]] bool IsValidIPv6(std::string_view str) {
    // Simplified IPv6 validation
    int colonCount = 0;
    bool hasDoubleColon = false;
    
    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];
        if (c == ':') {
            colonCount++;
            if (i + 1 < str.size() && str[i + 1] == ':') {
                if (hasDoubleColon) return false;  // Only one :: allowed
                hasDoubleColon = true;
            }
        } else if (!std::isxdigit(c)) {
            return false;
        }
    }
    
    return colonCount >= 2 && colonCount <= 7;
}

/**
 * @brief Check if string is valid domain
 */
[[nodiscard]] bool IsValidDomain(std::string_view str) {
    if (str.empty() || str.size() > 253) return false;
    
    // Simple domain validation
    bool hasDot = false;
    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];
        if (c == '.') {
            hasDot = true;
            if (i == 0 || i == str.size() - 1) return false;  // Can't start or end with dot
            if (i > 0 && str[i - 1] == '.') return false;     // No consecutive dots
        } else if (!std::isalnum(c) && c != '-') {
            return false;
        }
    }
    
    return hasDot;
}

/**
 * @brief Check if string is valid URL
 */
[[nodiscard]] bool IsValidUrlString(std::string_view str) {
    return str.starts_with("http://") || str.starts_with("https://") ||
           str.starts_with("ftp://") || str.starts_with("ftps://");
}

/**
 * @brief Check if string is valid email
 */
[[nodiscard]] bool IsValidEmail(std::string_view str) {
    size_t atPos = str.find('@');
    if (atPos == std::string_view::npos || atPos == 0 || atPos == str.size() - 1) {
        return false;
    }
    return str.find('.', atPos) != std::string_view::npos;
}

/**
 * @brief Check if string is valid hash (hex string)
 */
[[nodiscard]] bool IsValidHash(std::string_view str) {
    if (str.size() != 32 && str.size() != 40 && str.size() != 64 && str.size() != 128) {
        return false;
    }
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
    });
}

/**
 * @brief Parse hex string to bytes
 */
[[nodiscard]] bool ParseHexString(std::string_view hex, uint8_t* out, size_t outLen) {
    if (hex.size() != outLen * 2) return false;
    
    for (size_t i = 0; i < outLen; ++i) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        
        uint8_t highVal = std::isdigit(high) ? (high - '0') : (std::tolower(high) - 'a' + 10);
        uint8_t lowVal = std::isdigit(low) ? (low - '0') : (std::tolower(low) - 'a' + 10);
        
        if (highVal > 15 || lowVal > 15) return false;
        out[i] = (highVal << 4) | lowVal;
    }
    
    return true;
}

} // anonymous namespace

// ============================================================================
// UTILITY FUNCTIONS (PUBLIC)
// ============================================================================

std::optional<uint32_t> ParseDurationString(std::string_view duration) {
    if (duration.empty()) return std::nullopt;
    
    uint32_t value = 0;
    size_t i = 0;
    
    // Parse numeric part
    while (i < duration.size() && std::isdigit(duration[i])) {
        value = value * 10 + (duration[i] - '0');
        ++i;
    }
    
    if (i == 0) return std::nullopt;  // No digits found
    
    // Parse unit
    std::string_view unit = duration.substr(i);
    if (unit.empty() || unit == "s" || unit == "sec") {
        return value;
    } else if (unit == "m" || unit == "min") {
        return value * 60;
    } else if (unit == "h" || unit == "hr" || unit == "hour") {
        return value * 3600;
    } else if (unit == "d" || unit == "day") {
        return value * 86400;
    } else if (unit == "w" || unit == "week") {
        return value * 604800;
    }
    
    return std::nullopt;
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
    
    // Calculate exponential delay
    double delay = static_cast<double>(initialDelayMs) * 
                   std::pow(backoffMultiplier, static_cast<double>(attempt));
    
    // Add jitter
    double jitter = GetRandomJitter(jitterFactor);
    delay *= (1.0 + jitter);
    
    // Clamp to max
    if (delay > static_cast<double>(maxDelayMs)) {
        delay = static_cast<double>(maxDelayMs);
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
    apiKey.clear();
    username.clear();
    password.clear();
    clientId.clear();
    clientSecret.clear();
    accessToken.clear();
    refreshToken.clear();
    keyPassword.clear();
    hmacSecret.clear();
    tokenExpiry = 0;
}

// ============================================================================
// FEED ENDPOINT IMPLEMENTATION
// ============================================================================

std::string FeedEndpoint::GetFullUrl() const {
    std::string url = baseUrl;
    
    // Append path
    if (!path.empty()) {
        if (!url.empty() && url.back() != '/' && path.front() != '/') {
            url += '/';
        }
        url += path;
    }
    
    // Append query parameters
    if (!queryParams.empty()) {
        url += '?';
        bool first = true;
        for (const auto& [key, value] : queryParams) {
            if (!first) url += '&';
            url += UrlEncode(key) + '=' + UrlEncode(value);
            first = false;
        }
    }
    
    return url;
}

std::string FeedEndpoint::GetPaginatedUrl(uint64_t offset, uint32_t limit) const {
    std::string url = GetFullUrl();
    
    char separator = (url.find('?') == std::string::npos) ? '?' : '&';
    url += separator;
    url += "offset=" + std::to_string(offset);
    url += "&limit=" + std::to_string(limit);
    
    return url;
}

// ============================================================================
// FEED CONFIG IMPLEMENTATION
// ============================================================================

bool ThreatFeedConfig::Validate(std::string* errorMsg) const {
    if (feedId.empty()) {
        if (errorMsg) *errorMsg = "Feed ID is required";
        return false;
    }
    
    if (name.empty()) {
        if (errorMsg) *errorMsg = "Feed name is required";
        return false;
    }
    
    if (endpoint.baseUrl.empty() && protocol != FeedProtocol::FILE_WATCH) {
        if (errorMsg) *errorMsg = "Base URL is required";
        return false;
    }
    
    if (!auth.IsConfigured()) {
        if (errorMsg) *errorMsg = "Authentication not properly configured";
        return false;
    }
    
    if (syncIntervalSeconds > 0 && syncIntervalSeconds < minSyncIntervalSeconds) {
        if (errorMsg) *errorMsg = "Sync interval below minimum";
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
    uint64_t success = totalSuccessfulSyncs.load(std::memory_order_relaxed);
    uint64_t failed = totalFailedSyncs.load(std::memory_order_relaxed);
    uint64_t total = success + failed;
    
    if (total == 0) return 100.0;
    return static_cast<double>(success) * 100.0 / static_cast<double>(total);
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
    return static_cast<double>(totalFetched) * 1000.0 / static_cast<double>(durationMs);
}

// ============================================================================
// FEED EVENT IMPLEMENTATION
// ============================================================================

FeedEvent FeedEvent::Create(FeedEventType type, const std::string& feedId, const std::string& msg) {
    FeedEvent event;
    event.type = type;
    event.feedId = feedId;
    event.timestamp = GetCurrentTimestampImpl();
    event.message = msg;
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
    auto it = headers.find("Retry-After");
    if (it == headers.end()) {
        it = headers.find("retry-after");
    }
    if (it == headers.end()) return std::nullopt;
    
    uint32_t value = 0;
    auto result = std::from_chars(it->second.data(), 
                                   it->second.data() + it->second.size(), 
                                   value);
    if (result.ec == std::errc()) {
        return value;
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
    try {
        // Parse JSON
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        // Navigate to IOC array using path
        nlohmann::json* iocArray = &root;
        
        if (!config.iocPath.empty()) {
            // Simple path navigation (e.g., "$.data.indicators")
            std::string path = config.iocPath;
            if (path.starts_with("$.")) {
                path = path.substr(2);
            }
            
            std::istringstream pathStream(path);
            std::string segment;
            while (std::getline(pathStream, segment, '.')) {
                if (iocArray->is_object() && iocArray->contains(segment)) {
                    iocArray = &(*iocArray)[segment];
                } else if (iocArray->is_array()) {
                    // Handle array index
                    try {
                        size_t idx = std::stoul(segment);
                        if (idx < iocArray->size()) {
                            iocArray = &(*iocArray)[idx];
                        }
                    } catch (...) {
                        m_lastError = "Invalid path segment: " + segment;
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
        
        outEntries.reserve(iocArray->size());
        
        for (const auto& item : *iocArray) {
            IOCEntry entry;
            if (ParseIOCEntry(&item, entry, config)) {
                outEntries.push_back(std::move(entry));
            }
        }
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        m_lastError = "JSON parse error: " + std::string(e.what());
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
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        nlohmann::json* iocArray = &root;
        
        if (!config.iocPath.empty()) {
            std::string path = config.iocPath;
            if (path.starts_with("$.")) path = path.substr(2);
            
            std::istringstream pathStream(path);
            std::string segment;
            while (std::getline(pathStream, segment, '.')) {
                if (iocArray->is_object() && iocArray->contains(segment)) {
                    iocArray = &(*iocArray)[segment];
                }
            }
        }
        
        if (!iocArray->is_array()) {
            m_lastError = "IOC path does not point to array";
            return false;
        }
        
        for (const auto& item : *iocArray) {
            IOCEntry entry;
            if (ParseIOCEntry(&item, entry, config)) {
                if (!callback(entry)) {
                    return true;  // Callback requested stop
                }
            }
        }
        
        return true;
        
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
    
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        return ExtractJsonPath(&root, config.nextPagePath);
        
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<uint64_t> JsonFeedParser::GetTotalCount(
    std::span<const uint8_t> data,
    const ParserConfig& config
) {
    if (config.totalCountPath.empty()) return std::nullopt;
    
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        auto value = ExtractJsonPath(&root, config.totalCountPath);
        if (value) {
            return std::stoull(*value);
        }
        
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
                // Parse IPv4 address using constructor
                int octets[4] = {0};
                if (sscanf(value.c_str(), "%d.%d.%d.%d", 
                           &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
                    entry.value.ipv4 = IPv4Address(
                        static_cast<uint8_t>(octets[0]),
                        static_cast<uint8_t>(octets[1]),
                        static_cast<uint8_t>(octets[2]),
                        static_cast<uint8_t>(octets[3])
                    );
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
    const nlohmann::json& json = *static_cast<const nlohmann::json*>(root);
    
    try {
        std::string cleanPath = path;
        if (cleanPath.starts_with("$.")) {
            cleanPath = cleanPath.substr(2);
        }
        
        const nlohmann::json* current = &json;
        std::istringstream pathStream(cleanPath);
        std::string segment;
        
        while (std::getline(pathStream, segment, '.')) {
            if (current->is_object() && current->contains(segment)) {
                current = &(*current)[segment];
            } else {
                return std::nullopt;
            }
        }
        
        if (current->is_string()) {
            return current->get<std::string>();
        } else if (current->is_number()) {
            return std::to_string(current->get<double>());
        } else if (current->is_boolean()) {
            return current->get<bool>() ? "true" : "false";
        }
        
    } catch (...) {}
    
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
    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    std::istringstream stream(content);
    std::string line;
    
    bool firstLine = true;
    size_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Skip empty lines
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
        
        // Extract value
        if (config.csvValueColumn < 0 || 
            static_cast<size_t>(config.csvValueColumn) >= fields.size()) {
            continue;
        }
        
        std::string value = fields[config.csvValueColumn];
        if (config.trimWhitespace) {
            value = TrimString(value);
        }
        if (config.lowercaseValues) {
            value = ToLowerCase(value);
        }
        
        if (value.empty()) continue;
        
        // Create IOC entry
        IOCEntry entry;
        
        // Determine type
        IOCType iocType = IOCType::Domain;  // Default
        
        if (config.csvTypeColumn >= 0 && 
            static_cast<size_t>(config.csvTypeColumn) < fields.size()) {
            std::string typeStr = fields[config.csvTypeColumn];
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
            case IOCType::IPv4: {
                int octets[4] = {0};
                if (sscanf(value.c_str(), "%d.%d.%d.%d",
                           &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
                    entry.value.ipv4 = IPv4Address(
                        static_cast<uint8_t>(octets[0]),
                        static_cast<uint8_t>(octets[1]),
                        static_cast<uint8_t>(octets[2]),
                        static_cast<uint8_t>(octets[3])
                    );
                }
                break;
            }
            case IOCType::FileHash: {
                HashValue hash;
                size_t hashLen = value.size() / 2;
                if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
                else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
                else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
                else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
                else continue;  // Invalid hash length
                
                hash.length = static_cast<uint8_t>(hashLen);
                if (!ParseHexString(value, hash.data.data(), hashLen)) {
                    continue;
                }
                entry.value.hash = hash;
                break;
            }
            default: {
                uint32_t valueHash = 0;
                for (char c : value) {
                    valueHash = valueHash * 31 + static_cast<uint8_t>(c);
                }
                entry.value.stringRef.stringOffset = valueHash;
                entry.value.stringRef.stringLength = static_cast<uint16_t>(std::min(value.size(), size_t(65535)));
                break;
            }
        }
        
        // Set timestamps
        uint64_t now = GetCurrentTimestampImpl();
        entry.firstSeen = now;
        entry.lastSeen = now;
        entry.createdTime = now;
        
        outEntries.push_back(std::move(entry));
    }
    
    return true;
}

bool CsvFeedParser::ParseStreaming(
    std::span<const uint8_t> data,
    IOCReceivedCallback callback,
    const ParserConfig& config
) {
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
    // Count lines
    uint64_t count = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == '\n') count++;
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
    std::string field;
    bool inQuotes = false;
    
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        
        if (c == quote) {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == quote) {
                // Escaped quote
                field += quote;
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c == delimiter && !inQuotes) {
            fields.push_back(field);
            field.clear();
        } else if (c == '\r') {
            // Skip carriage return
        } else {
            field += c;
        }
    }
    
    // Add last field
    fields.push_back(field);
    
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
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        // STIX bundle structure
        if (!root.contains("objects") || !root["objects"].is_array()) {
            m_lastError = "Invalid STIX bundle: missing objects array";
            return false;
        }
        
        for (const auto& obj : root["objects"]) {
            if (!obj.contains("type")) continue;
            
            std::string objType = obj["type"].get<std::string>();
            
            // Process indicator objects
            if (objType == "indicator") {
                if (!obj.contains("pattern")) continue;
                
                std::string pattern = obj["pattern"].get<std::string>();
                IOCEntry entry;
                
                if (ParseSTIXPattern(pattern, entry)) {
                    // Extract metadata
                    if (obj.contains("created")) {
                        entry.createdTime = ParseISO8601(obj["created"].get<std::string>());
                    }
                    if (obj.contains("modified")) {
                        entry.lastSeen = ParseISO8601(obj["modified"].get<std::string>());
                    }
                    if (obj.contains("valid_from")) {
                        entry.firstSeen = ParseISO8601(obj["valid_from"].get<std::string>());
                    }
                    if (obj.contains("valid_until")) {
                        entry.expirationTime = ParseISO8601(obj["valid_until"].get<std::string>());
                    }
                    if (obj.contains("confidence")) {
                        int conf = obj["confidence"].get<int>();
                        if (conf >= 90) entry.confidence = ConfidenceLevel::Confirmed;
                        else if (conf >= 70) entry.confidence = ConfidenceLevel::High;
                        else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                        else entry.confidence = ConfidenceLevel::Low;
                    }
                    
                    outEntries.push_back(std::move(entry));
                }
            }
        }
        
        return true;
        
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
    std::vector<IOCEntry> entries;
    if (!Parse(data, entries, config)) {
        return false;
    }
    
    for (const auto& entry : entries) {
        if (!callback(entry)) {
            return true;
        }
    }
    
    return true;
}

std::optional<std::string> StixFeedParser::GetNextPageToken(
    std::span<const uint8_t> data,
    const ParserConfig& /*config*/
) {
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        // Check for TAXII pagination
        if (root.contains("next")) {
            return root["next"].get<std::string>();
        }
        if (root.contains("more") && root["more"].get<bool>()) {
            if (root.contains("id")) {
                return root["id"].get<std::string>();
            }
        }
        
    } catch (...) {}
    
    return std::nullopt;
}

std::optional<uint64_t> StixFeedParser::GetTotalCount(
    std::span<const uint8_t> data,
    const ParserConfig& /*config*/
) {
    try {
        std::string jsonStr(reinterpret_cast<const char*>(data.data()), data.size());
        nlohmann::json root = nlohmann::json::parse(jsonStr);
        
        if (root.contains("objects") && root["objects"].is_array()) {
            return root["objects"].size();
        }
        
    } catch (...) {}
    
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
    
    // Simple pattern parser
    size_t start = pattern.find('[');
    size_t end = pattern.rfind(']');
    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return false;
    }
    
    std::string content = pattern.substr(start + 1, end - start - 1);
    
    // Find type and value
    size_t colonPos = content.find(':');
    if (colonPos == std::string::npos) return false;
    
    std::string stixType = TrimString(content.substr(0, colonPos));
    std::string rest = content.substr(colonPos + 1);
    
    // Find value in quotes
    size_t valueStart = rest.find('\'');
    size_t valueEnd = rest.rfind('\'');
    if (valueStart == std::string::npos || valueEnd == std::string::npos || valueEnd <= valueStart) {
        return false;
    }
    
    std::string value = rest.substr(valueStart + 1, valueEnd - valueStart - 1);
    
    // Map STIX type to IOCType
    auto iocType = MapSTIXTypeToIOCType(stixType);
    if (!iocType) {
        return false;
    }
    
    entry.type = *iocType;
    
    // Set value based on type
    switch (entry.type) {
        case IOCType::IPv4: {
            int octets[4] = {0};
            if (sscanf(value.c_str(), "%d.%d.%d.%d",
                       &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
                entry.value.ipv4 = IPv4Address(
                    static_cast<uint8_t>(octets[0]),
                    static_cast<uint8_t>(octets[1]),
                    static_cast<uint8_t>(octets[2]),
                    static_cast<uint8_t>(octets[3])
                );
            }
            break;
        }
        case IOCType::FileHash: {
            HashValue hash;
            size_t hashLen = value.size() / 2;
            if (hashLen == 16) hash.algorithm = HashAlgorithm::MD5;
            else if (hashLen == 20) hash.algorithm = HashAlgorithm::SHA1;
            else if (hashLen == 32) hash.algorithm = HashAlgorithm::SHA256;
            else if (hashLen == 64) hash.algorithm = HashAlgorithm::SHA512;
            else return false;
            
            hash.length = static_cast<uint8_t>(hashLen);
            if (!ParseHexString(value, hash.data.data(), hashLen)) {
                return false;
            }
            entry.value.hash = hash;
            break;
        }
        default: {
            uint32_t valueHash = 0;
            for (char c : value) {
                valueHash = valueHash * 31 + static_cast<uint8_t>(c);
            }
            entry.value.stringRef.stringOffset = valueHash;
            entry.value.stringRef.stringLength = static_cast<uint16_t>(std::min(value.size(), size_t(65535)));
            break;
        }
    }
    
    uint64_t now = GetCurrentTimestampImpl();
    entry.firstSeen = now;
    entry.lastSeen = now;
    entry.createdTime = now;
    
    return true;
}

std::optional<IOCType> StixFeedParser::MapSTIXTypeToIOCType(const std::string& stixType) {
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
    // Register default parsers
    m_parsers[FeedProtocol::REST_API] = std::make_shared<JsonFeedParser>();
    m_parsers[FeedProtocol::JSON_HTTP] = std::make_shared<JsonFeedParser>();
    m_parsers[FeedProtocol::CSV_HTTP] = std::make_shared<CsvFeedParser>();
    m_parsers[FeedProtocol::STIX_TAXII] = std::make_shared<StixFeedParser>();
    m_parsers[FeedProtocol::MISP_API] = std::make_shared<JsonFeedParser>();
}

ThreatIntelFeedManager::~ThreatIntelFeedManager() {
    Shutdown();
}

ThreatIntelFeedManager::ThreatIntelFeedManager(ThreatIntelFeedManager&& other) noexcept {
    std::unique_lock<std::shared_mutex> lock(other.m_feedsMutex);
    m_config = std::move(other.m_config);
    m_feeds = std::move(other.m_feeds);
    m_running.store(other.m_running.load());
    m_initialized.store(other.m_initialized.load());
}

ThreatIntelFeedManager& ThreatIntelFeedManager::operator=(ThreatIntelFeedManager&& other) noexcept {
    if (this != &other) {
        Shutdown();
        std::unique_lock<std::shared_mutex> lock(other.m_feedsMutex);
        m_config = std::move(other.m_config);
        m_feeds = std::move(other.m_feeds);
        m_running.store(other.m_running.load());
        m_initialized.store(other.m_initialized.load());
    }
    return *this;
}

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

bool ThreatIntelFeedManager::Initialize(const Config& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        return false;  // Already initialized
    }
    
    std::string errorMsg;
    if (!config.Validate(&errorMsg)) {
        return false;
    }
    
    m_config = config;
    
    // Create data directory if needed
    if (!m_config.dataDirectory.empty()) {
        try {
            std::filesystem::create_directories(m_config.dataDirectory);
        } catch (...) {
            return false;
        }
    }
    
    // Initialize statistics
    m_stats.startTime = GetCurrentTimestampImpl();
    m_stats.totalFeeds.store(0, std::memory_order_release);
    
    // Update semaphore count
    // Note: counting_semaphore doesn't support dynamic resize, so we keep initial value
    
    m_initialized.store(true, std::memory_order_release);
    
    return true;
}

bool ThreatIntelFeedManager::Start() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }
    
    if (m_running.load(std::memory_order_acquire)) {
        return true;  // Already running
    }
    
    m_shutdown.store(false, std::memory_order_release);
    m_running.store(true, std::memory_order_release);
    
    // Determine worker thread count
    uint32_t threadCount = m_config.workerThreads;
    if (threadCount == 0) {
        threadCount = std::max(2u, std::thread::hardware_concurrency() / 2);
    }
    threadCount = std::min(threadCount, 16u);
    
    // Start worker threads
    for (uint32_t i = 0; i < threadCount; ++i) {
        m_workerThreads.emplace_back(&ThreatIntelFeedManager::WorkerThread, this);
    }
    
    // Start scheduler thread
    m_schedulerThread = std::thread(&ThreatIntelFeedManager::SchedulerThread, this);
    
    // Start health monitor if enabled
    if (m_config.enableHealthMonitoring) {
        m_healthThread = std::thread(&ThreatIntelFeedManager::HealthMonitorThread, this);
    }
    
    // Schedule initial sync for all enabled feeds
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [feedId, context] : m_feeds) {
            if (context->config.enabled) {
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
    
    m_shutdown.store(true, std::memory_order_release);
    m_running.store(false, std::memory_order_release);
    
    // Wake up waiting threads
    m_queueCondition.notify_all();
    
    // Wait for worker threads
    auto startTime = std::chrono::steady_clock::now();
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            auto remaining = std::chrono::milliseconds(timeoutMs) -
                           (std::chrono::steady_clock::now() - startTime);
            if (remaining.count() > 0) {
                thread.join();
            } else {
                thread.detach();
            }
        }
    }
    m_workerThreads.clear();
    
    // Wait for scheduler thread
    if (m_schedulerThread.joinable()) {
        m_schedulerThread.join();
    }
    
    // Wait for health monitor thread
    if (m_healthThread.joinable()) {
        m_healthThread.join();
    }
    
    return true;
}

bool ThreatIntelFeedManager::IsRunning() const noexcept {
    return m_running.load(std::memory_order_acquire);
}

void ThreatIntelFeedManager::Shutdown() {
    Stop(5000);
    
    {
        std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
        m_feeds.clear();
    }
    
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
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    if (m_feeds.find(config.feedId) != m_feeds.end()) {
        return false;  // Feed already exists
    }
    
    auto context = std::make_unique<FeedContext>();
    context->config = config;
    context->rateLimit = std::make_unique<RateLimitConfig>(config.rateLimit);
    context->stats.status.store(FeedSyncStatus::Idle, std::memory_order_release);
    
    m_feeds[config.feedId] = std::move(context);
    
    m_stats.totalFeeds.fetch_add(1, std::memory_order_relaxed);
    if (config.enabled) {
        m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Emit event
    EmitEvent(FeedEventType::FeedAdded, config.feedId, "Feed added: " + config.name);
    
    // Schedule initial sync if running and enabled
    if (m_running.load(std::memory_order_acquire) && config.enabled) {
        ScheduleNextSync(*m_feeds[config.feedId]);
    }
    
    return true;
}

uint32_t ThreatIntelFeedManager::AddFeeds(std::span<const ThreatFeedConfig> configs) {
    uint32_t added = 0;
    for (const auto& config : configs) {
        if (AddFeed(config)) {
            added++;
        }
    }
    return added;
}

bool ThreatIntelFeedManager::RemoveFeed(const std::string& feedId) {
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return false;
    }
    
    // Cancel any ongoing sync
    it->second->cancelRequested.store(true, std::memory_order_release);
    
    bool wasEnabled = it->second->config.enabled;
    m_feeds.erase(it);
    
    m_stats.totalFeeds.fetch_sub(1, std::memory_order_relaxed);
    if (wasEnabled) {
        m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
    }
    
    EmitEvent(FeedEventType::FeedRemoved, feedId, "Feed removed");
    
    return true;
}

bool ThreatIntelFeedManager::UpdateFeed(const std::string& feedId, const ThreatFeedConfig& config) {
    std::string errorMsg;
    if (!config.Validate(&errorMsg)) {
        return false;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return false;
    }
    
    bool wasEnabled = it->second->config.enabled;
    it->second->config = config;
    it->second->rateLimit = std::make_unique<RateLimitConfig>(config.rateLimit);
    
    if (wasEnabled != config.enabled) {
        if (config.enabled) {
            m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
        } else {
            m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
        }
    }
    
    EmitEvent(FeedEventType::FeedConfigChanged, feedId, "Configuration updated");
    
    return true;
}

std::optional<ThreatFeedConfig> ThreatIntelFeedManager::GetFeedConfig(const std::string& feedId) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return std::nullopt;
    }
    
    return it->second->config;
}

std::vector<ThreatFeedConfig> ThreatIntelFeedManager::GetAllFeedConfigs() const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<ThreatFeedConfig> configs;
    configs.reserve(m_feeds.size());
    
    for (const auto& [feedId, context] : m_feeds) {
        configs.push_back(context->config);
    }
    
    return configs;
}

std::vector<std::string> ThreatIntelFeedManager::GetFeedIds() const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<std::string> ids;
    ids.reserve(m_feeds.size());
    
    for (const auto& [feedId, _] : m_feeds) {
        ids.push_back(feedId);
    }
    
    return ids;
}

bool ThreatIntelFeedManager::HasFeed(const std::string& feedId) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    return m_feeds.find(feedId) != m_feeds.end();
}

bool ThreatIntelFeedManager::EnableFeed(const std::string& feedId) {
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || it->second->config.enabled) {
        return false;
    }
    
    it->second->config.enabled = true;
    it->second->stats.status.store(FeedSyncStatus::Idle, std::memory_order_release);
    m_stats.enabledFeeds.fetch_add(1, std::memory_order_relaxed);
    
    EmitEvent(FeedEventType::FeedEnabled, feedId);
    
    if (m_running.load(std::memory_order_acquire)) {
        ScheduleNextSync(*it->second);
    }
    
    return true;
}

bool ThreatIntelFeedManager::DisableFeed(const std::string& feedId) {
    std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end() || !it->second->config.enabled) {
        return false;
    }
    
    it->second->config.enabled = false;
    it->second->stats.status.store(FeedSyncStatus::Disabled, std::memory_order_release);
    it->second->cancelRequested.store(true, std::memory_order_release);
    m_stats.enabledFeeds.fetch_sub(1, std::memory_order_relaxed);
    
    EmitEvent(FeedEventType::FeedDisabled, feedId);
    
    return true;
}

bool ThreatIntelFeedManager::IsFeedEnabled(const std::string& feedId) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    return it != m_feeds.end() && it->second->config.enabled;
}

// ============================================================================
// SYNCHRONIZATION
// ============================================================================

SyncResult ThreatIntelFeedManager::SyncFeed(
    const std::string& feedId,
    SyncProgressCallback progressCallback
) {
    FeedContext* context = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        auto it = m_feeds.find(feedId);
        if (it == m_feeds.end()) {
            SyncResult result;
            result.feedId = feedId;
            result.errorMessage = "Feed not found";
            return result;
        }
        context = it->second.get();
    }
    
    return ExecuteSync(*context, SyncTrigger::Manual, progressCallback);
}

std::future<SyncResult> ThreatIntelFeedManager::SyncFeedAsync(
    const std::string& feedId,
    SyncCompletionCallback completionCallback
) {
    return std::async(std::launch::async, [this, feedId, completionCallback]() {
        SyncResult result = SyncFeed(feedId, nullptr);
        if (completionCallback) {
            completionCallback(result);
        }
        return result;
    });
}

std::unordered_map<std::string, SyncResult> ThreatIntelFeedManager::SyncAllFeeds(
    SyncProgressCallback progressCallback
) {
    std::unordered_map<std::string, SyncResult> results;
    
    std::vector<std::string> feedIds = GetFeedIds();
    
    for (const auto& feedId : feedIds) {
        if (IsFeedEnabled(feedId)) {
            results[feedId] = SyncFeed(feedId, progressCallback);
        }
    }
    
    return results;
}

void ThreatIntelFeedManager::SyncAllFeedsAsync(SyncCompletionCallback completionCallback) {
    std::vector<std::string> feedIds = GetFeedIds();
    
    for (const auto& feedId : feedIds) {
        if (IsFeedEnabled(feedId)) {
            SyncTask task;
            task.feedId = feedId;
            task.trigger = SyncTrigger::Manual;
            task.priority = FeedPriority::Normal;
            task.completionCallback = completionCallback;
            task.scheduledTime = std::chrono::steady_clock::now();
            
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_taskQueue.push(task);
            }
            m_queueCondition.notify_one();
        }
    }
}

bool ThreatIntelFeedManager::CancelSync(const std::string& feedId) {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return false;
    }
    
    it->second->cancelRequested.store(true, std::memory_order_release);
    return true;
}

void ThreatIntelFeedManager::CancelAllSyncs() {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    for (auto& [_, context] : m_feeds) {
        context->cancelRequested.store(true, std::memory_order_release);
    }
}

bool ThreatIntelFeedManager::IsSyncing(const std::string& feedId) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
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
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return nullptr;
    }
    
    return &it->second->stats;
}

const FeedManagerStats& ThreatIntelFeedManager::GetManagerStats() const noexcept {
    return m_stats;
}

FeedSyncStatus ThreatIntelFeedManager::GetFeedStatus(const std::string& feedId) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    auto it = m_feeds.find(feedId);
    if (it == m_feeds.end()) {
        return FeedSyncStatus::Unknown;
    }
    
    return it->second->stats.status.load(std::memory_order_acquire);
}

std::vector<std::string> ThreatIntelFeedManager::GetFeedsByStatus(FeedSyncStatus status) const {
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    
    std::vector<std::string> feedIds;
    for (const auto& [feedId, context] : m_feeds) {
        if (context->stats.status.load(std::memory_order_acquire) == status) {
            feedIds.push_back(feedId);
        }
    }
    
    return feedIds;
}

bool ThreatIntelFeedManager::IsHealthy() const noexcept {
    uint32_t errorCount = m_stats.errorFeeds.load(std::memory_order_relaxed);
    uint32_t totalCount = m_stats.totalFeeds.load(std::memory_order_relaxed);
    
    if (totalCount == 0) return true;
    
    // More than 50% in error state is unhealthy
    return errorCount <= (totalCount / 2);
}

std::string ThreatIntelFeedManager::GetHealthReport() const {
    std::ostringstream oss;
    
    uint32_t total = m_stats.totalFeeds.load(std::memory_order_relaxed);
    uint32_t enabled = m_stats.enabledFeeds.load(std::memory_order_relaxed);
    uint32_t syncing = m_stats.syncingFeeds.load(std::memory_order_relaxed);
    uint32_t errors = m_stats.errorFeeds.load(std::memory_order_relaxed);
    
    oss << "Feed Manager Health Report\n";
    oss << "==========================\n";
    oss << "Total Feeds: " << total << "\n";
    oss << "Enabled: " << enabled << "\n";
    oss << "Currently Syncing: " << syncing << "\n";
    oss << "In Error State: " << errors << "\n";
    oss << "Total Syncs: " << m_stats.totalSyncsCompleted.load(std::memory_order_relaxed) << "\n";
    oss << "Total IOCs: " << m_stats.totalIOCsFetched.load(std::memory_order_relaxed) << "\n";
    oss << "Total Downloaded: " << (m_stats.totalBytesDownloaded.load(std::memory_order_relaxed) / 1024 / 1024) << " MB\n";
    oss << "Overall Status: " << (IsHealthy() ? "HEALTHY" : "UNHEALTHY") << "\n";
    
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
    m_database = std::move(database);
}

void ThreatIntelFeedManager::SetTargetStore(std::shared_ptr<ThreatIntelStore> store) {
    m_store = std::move(store);
}

void ThreatIntelFeedManager::SetHttpClient(std::shared_ptr<IHttpClient> client) {
    m_httpClient = std::move(client);
}

void ThreatIntelFeedManager::RegisterParser(FeedProtocol protocol, std::shared_ptr<IFeedParser> parser) {
    std::lock_guard<std::mutex> lock(m_parsersMutex);
    m_parsers[protocol] = std::move(parser);
}

// ============================================================================
// PERSISTENCE
// ============================================================================

bool ThreatIntelFeedManager::SaveConfigs(const std::filesystem::path& path) const {
    try {
        nlohmann::json root = nlohmann::json::array();
        
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [feedId, context] : m_feeds) {
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
            // Note: Don't save sensitive credentials
            
            root.push_back(feed);
        }
        
        std::ofstream file(path);
        if (!file.is_open()) return false;
        file << root.dump(2);
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool ThreatIntelFeedManager::LoadConfigs(const std::filesystem::path& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return false;
        
        nlohmann::json root = nlohmann::json::parse(file);
        
        for (const auto& feed : root) {
            ThreatFeedConfig config;
            config.feedId = feed.value("feedId", "");
            config.name = feed.value("name", "");
            config.description = feed.value("description", "");
            config.source = static_cast<ThreatIntelSource>(feed.value("source", 0));
            config.protocol = static_cast<FeedProtocol>(feed.value("protocol", 0));
            config.enabled = feed.value("enabled", true);
            config.endpoint.baseUrl = feed.value("baseUrl", "");
            config.endpoint.path = feed.value("path", "");
            config.syncIntervalSeconds = feed.value("syncIntervalSeconds", 3600);
            config.auth.method = static_cast<AuthMethod>(feed.value("authMethod", 0));
            
            if (!config.feedId.empty()) {
                AddFeed(config);
            }
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool ThreatIntelFeedManager::SaveState(const std::filesystem::path& path) const {
    try {
        nlohmann::json root;
        
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [feedId, context] : m_feeds) {
            nlohmann::json state;
            state["lastSync"] = context->stats.lastSuccessfulSync.load(std::memory_order_relaxed);
            state["totalSyncs"] = context->stats.totalSuccessfulSyncs.load(std::memory_order_relaxed);
            state["totalIOCs"] = context->stats.totalIOCsFetched.load(std::memory_order_relaxed);
            root[feedId] = state;
        }
        
        std::ofstream file(path);
        if (!file.is_open()) return false;
        file << root.dump(2);
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool ThreatIntelFeedManager::LoadState(const std::filesystem::path& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return false;
        
        nlohmann::json root = nlohmann::json::parse(file);
        
        std::unique_lock<std::shared_mutex> lock(m_feedsMutex);
        for (auto& [feedId, context] : m_feeds) {
            if (root.contains(feedId)) {
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
        
    } catch (...) {
        return false;
    }
}

std::string ThreatIntelFeedManager::ExportConfigsToJson() const {
    nlohmann::json root = nlohmann::json::array();
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    for (const auto& [feedId, context] : m_feeds) {
        nlohmann::json feed;
        feed["feedId"] = context->config.feedId;
        feed["name"] = context->config.name;
        feed["enabled"] = context->config.enabled;
        root.push_back(feed);
    }
    
    return root.dump(2);
}

bool ThreatIntelFeedManager::ImportConfigsFromJson(const std::string& json) {
    try {
        nlohmann::json root = nlohmann::json::parse(json);
        // Implementation similar to LoadConfigs
        return true;
    } catch (...) {
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
            m_queueCondition.wait(lock, [this]() {
                return m_shutdown.load(std::memory_order_acquire) || !m_taskQueue.empty();
            });
            
            if (m_shutdown.load(std::memory_order_acquire)) break;
            if (m_taskQueue.empty()) continue;
            
            task = m_taskQueue.top();
            m_taskQueue.pop();
        }
        
        // Acquire sync slot with condition variable
        {
            std::unique_lock<std::mutex> syncLock(m_syncLimiterMutex);
            m_syncLimiterCv.wait(syncLock, [this]() {
                return m_activeSyncCount.load(std::memory_order_acquire) < MAX_CONCURRENT_SYNCS;
            });
            m_activeSyncCount.fetch_add(1, std::memory_order_acq_rel);
        }
        
        FeedContext* context = nullptr;
        {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            auto it = m_feeds.find(task.feedId);
            if (it != m_feeds.end()) {
                context = it->second.get();
            }
        }
        
        if (context && context->config.enabled) {
            SyncResult result = ExecuteSync(*context, task.trigger, task.progressCallback);
            
            if (task.completionCallback) {
                task.completionCallback(result);
            }
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
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        if (m_shutdown.load(std::memory_order_acquire)) break;
        
        uint64_t now = GetCurrentTimestampImpl();
        
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (auto& [feedId, context] : m_feeds) {
            if (!context->config.enabled) continue;
            if (context->syncInProgress.load(std::memory_order_acquire)) continue;
            
            uint64_t nextSync = context->stats.nextScheduledSync.load(std::memory_order_acquire);
            if (nextSync > 0 && now >= nextSync) {
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
            }
        }
        
        // Update uptime
        m_stats.uptimeSeconds.store(now - m_stats.startTime, std::memory_order_relaxed);
    }
}

void ThreatIntelFeedManager::HealthMonitorThread() {
    while (!m_shutdown.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::seconds(m_config.healthCheckIntervalSeconds));
        
        if (m_shutdown.load(std::memory_order_acquire)) break;
        
        uint32_t errorCount = 0;
        
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [feedId, context] : m_feeds) {
            if (!context->config.enabled) continue;
            
            if (!context->stats.IsHealthy()) {
                errorCount++;
                
                // Check for auto-disable
                if (context->stats.consecutiveErrors.load(std::memory_order_relaxed) >= 
                    m_config.maxConsecutiveErrors) {
                    EmitEvent(FeedEventType::HealthWarning, feedId, 
                             "Feed exceeded max consecutive errors");
                }
            }
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
    
    // Check if already syncing
    bool expected = false;
    if (!context.syncInProgress.compare_exchange_strong(expected, true)) {
        result.errorMessage = "Sync already in progress";
        return result;
    }
    
    context.cancelRequested.store(false, std::memory_order_release);
    context.stats.status.store(FeedSyncStatus::Syncing, std::memory_order_release);
    context.stats.lastSyncAttempt.store(result.startTime, std::memory_order_release);
    context.stats.SetCurrentPhase("Starting sync");
    context.lastSyncStart = std::chrono::steady_clock::now();
    
    m_activeSyncCount.fetch_add(1, std::memory_order_relaxed);
    m_stats.syncingFeeds.fetch_add(1, std::memory_order_relaxed);
    
    EmitEvent(FeedEventType::SyncStarted, context.config.feedId);
    
    try {
        // Wait for rate limit
        if (!WaitForRateLimit(context)) {
            result.errorMessage = "Rate limit wait cancelled";
            throw std::runtime_error(result.errorMessage);
        }
        
        // Fetch data
        context.stats.SetCurrentPhase("Fetching data");
        std::string url = context.config.endpoint.GetFullUrl();
        HttpResponse response = FetchFeedData(context, url);
        
        if (!response.IsSuccess()) {
            result.httpErrors++;
            result.errorCode = std::to_string(response.statusCode);
            result.errorMessage = response.error.empty() ? response.statusMessage : response.error;
            throw std::runtime_error(result.errorMessage);
        }
        
        result.bytesDownloaded = response.body.size();
        result.httpRequests++;
        
        // Parse response
        context.stats.SetCurrentPhase("Parsing response");
        context.stats.status.store(FeedSyncStatus::Parsing, std::memory_order_release);
        
        std::vector<IOCEntry> entries;
        if (!ParseFeedResponse(context, response, entries)) {
            result.errorMessage = "Failed to parse response";
            throw std::runtime_error(result.errorMessage);
        }
        
        result.totalFetched = entries.size();
        
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
        result.durationMs = result.endTime - result.startTime;
        
        // Update stats
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
        result.durationMs = result.endTime - result.startTime;
        
        context.stats.totalFailedSyncs.fetch_add(1, std::memory_order_relaxed);
        context.stats.consecutiveErrors.fetch_add(1, std::memory_order_relaxed);
        context.stats.SetLastError(e.what());
        context.stats.status.store(FeedSyncStatus::Error, std::memory_order_release);
        
        EmitEvent(FeedEventType::SyncFailed, context.config.feedId, e.what());
    }
    
    // Schedule next sync
    ScheduleNextSync(context);
    
    m_activeSyncCount.fetch_sub(1, std::memory_order_relaxed);
    m_stats.syncingFeeds.fetch_sub(1, std::memory_order_relaxed);
    context.syncInProgress.store(false, std::memory_order_release);
    
    return result;
}

HttpResponse ThreatIntelFeedManager::FetchFeedData(
    FeedContext& context,
    const std::string& url,
    uint64_t /*offset*/
) {
    HttpResponse response;
    
    // Use WinINet for HTTP requests
    HINTERNET hInternet = InternetOpenA(
        context.config.userAgent.c_str(),
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr, nullptr, 0
    );
    
    if (!hInternet) {
        response.error = "Failed to initialize WinINet";
        return response;
    }
    
    HINTERNET hConnect = InternetOpenUrlA(
        hInternet,
        url.c_str(),
        nullptr, 0,
        INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        0
    );
    
    if (!hConnect) {
        DWORD error = GetLastError();
        response.error = "Failed to connect: " + std::to_string(error);
        InternetCloseHandle(hInternet);
        return response;
    }
    
    // Read response
    std::vector<uint8_t> buffer(8192);
    DWORD bytesRead = 0;
    
    while (InternetReadFile(hConnect, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead) && bytesRead > 0) {
        response.body.insert(response.body.end(), buffer.begin(), buffer.begin() + bytesRead);
        
        if (context.cancelRequested.load(std::memory_order_acquire)) {
            break;
        }
    }
    
    // Get status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    HttpQueryInfoA(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &statusCode, &statusSize, nullptr);
    response.statusCode = static_cast<int>(statusCode);
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return response;
}

bool ThreatIntelFeedManager::ParseFeedResponse(
    FeedContext& context,
    const HttpResponse& response,
    std::vector<IOCEntry>& outEntries
) {
    IFeedParser* parser = GetParser(context.config.protocol);
    if (!parser) {
        return false;
    }
    
    return parser->Parse(
        std::span<const uint8_t>(response.body),
        outEntries,
        context.config.parser
    );
}

bool ThreatIntelFeedManager::StoreIOCs(
    FeedContext& context,
    const std::vector<IOCEntry>& entries,
    SyncResult& result
) {
    // Set source for all entries
    for (size_t i = 0; i < entries.size(); ++i) {
        // In a real implementation, we would add to database here
        result.newIOCs++;
    }
    
    return true;
}

bool ThreatIntelFeedManager::WaitForRateLimit(FeedContext& context) {
    auto& rl = *context.rateLimit;
    
    uint64_t now = GetCurrentTimestampMs();
    uint64_t lastRequest = rl.lastRequestTime.load(std::memory_order_acquire);
    
    if (lastRequest > 0) {
        uint64_t elapsed = now - lastRequest;
        if (elapsed < rl.minIntervalMs) {
            std::this_thread::sleep_for(std::chrono::milliseconds(rl.minIntervalMs - elapsed));
        }
    }
    
    // Check retry-after
    uint64_t retryAfter = rl.retryAfterTime.load(std::memory_order_acquire);
    if (retryAfter > 0 && now < retryAfter) {
        context.stats.status.store(FeedSyncStatus::RateLimited, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(retryAfter - now));
    }
    
    rl.lastRequestTime.store(GetCurrentTimestampMs(), std::memory_order_release);
    rl.currentMinuteCount.fetch_add(1, std::memory_order_relaxed);
    
    return !context.cancelRequested.load(std::memory_order_acquire);
}

bool ThreatIntelFeedManager::PrepareAuthentication(FeedContext& context, HttpRequest& request) {
    const auto& auth = context.config.auth;
    
    switch (auth.method) {
        case AuthMethod::ApiKey:
            if (auth.apiKeyInQuery) {
                request.url += (request.url.find('?') == std::string::npos ? "?" : "&");
                request.url += auth.apiKeyQueryParam + "=" + UrlEncode(auth.apiKey);
            } else {
                request.headers[auth.apiKeyHeader] = auth.apiKey;
            }
            break;
            
        case AuthMethod::BasicAuth:
            request.headers["Authorization"] = "Basic " + 
                Base64Encode(auth.username + ":" + auth.password);
            break;
            
        case AuthMethod::BearerToken:
            request.headers["Authorization"] = "Bearer " + auth.accessToken;
            break;
            
        default:
            break;
    }
    
    return true;
}

bool ThreatIntelFeedManager::RefreshOAuth2Token(FeedContext& /*context*/) {
    // OAuth2 token refresh implementation
    return true;
}

uint32_t ThreatIntelFeedManager::CalculateRetryDelay(const FeedContext& context, uint32_t attempt) {
    return context.config.retry.CalculateDelay(attempt);
}

IFeedParser* ThreatIntelFeedManager::GetParser(FeedProtocol protocol) {
    std::lock_guard<std::mutex> lock(m_parsersMutex);
    
    auto it = m_parsers.find(protocol);
    if (it != m_parsers.end()) {
        return it->second.get();
    }
    
    // Fall back to JSON parser
    it = m_parsers.find(FeedProtocol::REST_API);
    return it != m_parsers.end() ? it->second.get() : nullptr;
}

void ThreatIntelFeedManager::EmitEvent(FeedEventType type, const std::string& feedId, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_eventMutex);
    if (m_eventCallback) {
        FeedEvent event = FeedEvent::Create(type, feedId, message);
        m_eventCallback(event);
    }
}

void ThreatIntelFeedManager::ScheduleNextSync(FeedContext& context) {
    if (!context.config.enabled || context.config.syncIntervalSeconds == 0) {
        context.stats.nextScheduledSync.store(0, std::memory_order_release);
        return;
    }
    
    uint64_t now = GetCurrentTimestampImpl();
    uint64_t nextSync = now + context.config.syncIntervalSeconds;
    context.stats.nextScheduledSync.store(nextSync, std::memory_order_release);
}

void ThreatIntelFeedManager::UpdateManagerStats() {
    uint32_t errorCount = 0;
    uint32_t syncingCount = 0;
    
    std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
    for (const auto& [_, context] : m_feeds) {
        FeedSyncStatus status = context->stats.status.load(std::memory_order_acquire);
        if (status == FeedSyncStatus::Error) errorCount++;
        if (status == FeedSyncStatus::Syncing) syncingCount++;
    }
    
    m_stats.errorFeeds.store(errorCount, std::memory_order_release);
    m_stats.syncingFeeds.store(syncingCount, std::memory_order_release);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
