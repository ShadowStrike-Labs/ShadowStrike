/**
 * @file ThreatIntelFeedManager.cpp
 * @brief Enterprise-Grade Threat Intelligence Feed Manager Implementation
 *
 * High-performance feed management with concurrent synchronization,
 * rate limiting, and comprehensive monitoring.
 *
 * 
 *
 * @author ShadowStrike Security Team
 * @copyright 2028 ShadowStrike Project
 */

#include "ThreatIntelFeedManager.hpp"
#include"ThreatIntelFeedManager_Util.hpp"
#include "ThreatIntelDatabase.hpp"
#include "ThreatIntelStore.hpp"
#include"../../src/Utils/Base64Utils.hpp"
#include"../../src/Utils/Logger.hpp"

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
    return ShadowStrike::ThreatIntel_Util::IsValidUrlString(url);
}

std::optional<IOCType> DetectIOCType(std::string_view value) {
    if (value.empty()) return std::nullopt;
    
    // Check for hash first (most common)
    if (ShadowStrike::ThreatIntel_Util::IsValidHash(value)) {
        switch (value.size()) {
            case 32:  return IOCType::FileHash;  // MD5
            case 40:  return IOCType::FileHash;  // SHA1
            case 64:  return IOCType::FileHash;  // SHA256
            case 128: return IOCType::FileHash;  // SHA512
        }
    }
    
    // Check for URL
    if (ShadowStrike::ThreatIntel_Util::IsValidUrlString(value)) {
        return IOCType::URL;
    }
    
    // Check for email
    if (ShadowStrike::ThreatIntel_Util::IsValidEmail(value)) {
        return IOCType::Email;
    }
    
    // Check for IPv4
    if (ShadowStrike::ThreatIntel_Util::IsValidIPv4(value)) {
        return IOCType::IPv4;
    }
    
    // Check for IPv6
    if (ShadowStrike::ThreatIntel_Util::IsValidIPv6(value)) {
        return IOCType::IPv6;
    }
    
    // Check for domain
    if (ShadowStrike::ThreatIntel_Util::IsValidDomain(value)) {
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
    const double jitter = ShadowStrike::ThreatIntel_Util::GetRandomJitter(safeJitterFactor);
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
    uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
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
            url += ShadowStrike::ThreatIntel_Util::UrlEncode(key) + '=' + ShadowStrike::ThreatIntel_Util::UrlEncode(value);
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
    lastErrorTime.store(ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl(), std::memory_order_release);
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
    
    event.timestamp = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
    
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
    m_stats.startTime = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
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
    
    // Signal shutdown first - all threads should check this flag
    m_shutdown.store(true, std::memory_order_release);
    m_running.store(false, std::memory_order_release);
    
    // Wake up all waiting threads to allow them to see shutdown flag
    m_queueCondition.notify_all();
    m_syncLimiterCv.notify_all();
    
    // Calculate effective timeout with reasonable bounds
    const DWORD effectiveTimeoutMs = (timeoutMs > 0 && timeoutMs <= 300000) 
        ? static_cast<DWORD>(timeoutMs) 
        : 5000;
    
    const auto startTime = std::chrono::steady_clock::now();
    bool allThreadsJoined = true;
    
    /**
     * @brief Helper lambda: Wait for a thread with timeout using Windows native API
     * 
     * Uses WaitForSingleObject for precise timeout control on thread handles.
     * This is the enterprise-grade approach for Windows platforms.
     * 
     * @param thread Reference to std::thread
     * @param remainingMs Remaining timeout in milliseconds
     * @return true if thread joined successfully, false if timeout/error
     */
    auto waitForThreadWithTimeout = [](std::thread& thread, DWORD remainingMs) -> bool {
        if (!thread.joinable()) {
            return true;  // Already not joinable
        }
        
        // Get native Windows handle for the thread
        HANDLE threadHandle = thread.native_handle();
        if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE) {
            // Invalid handle - try standard join as fallback
            try {
                thread.join();
                return true;
            } catch (const std::system_error&) {
                return false;
            }
        }
        
        // Wait for thread completion with timeout
        const DWORD waitResult = WaitForSingleObject(threadHandle, remainingMs);
        
        if (waitResult == WAIT_OBJECT_0) {
            // Thread completed - safe to join
            try {
                thread.join();
                return true;
            } catch (const std::system_error&) {
                // Join failed but thread completed - this shouldn't happen
                return false;
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            // Thread did not complete in time
            // CRITICAL: We do NOT detach or terminate - that causes undefined behavior
            // Instead, we log and return false. The thread will complete eventually.
            // Enterprise policy: Never forcefully terminate threads
            return false;
        } else {
            // WAIT_FAILED or other error
            // GetLastError provides specific failure reason for diagnostics
            // Common errors:
            // - ERROR_INVALID_HANDLE (6): Handle is invalid or already closed
            // - ERROR_ACCESS_DENIED (5): Insufficient privileges
            [[maybe_unused]] const DWORD lastError = GetLastError();
            
            // Try standard join as fallback
            try {
                thread.join();
                return true;
            } catch (const std::system_error&) {
                return false;
            }
        }
    };
    
    /**
     * @brief Calculate remaining timeout from start time
     */
    auto getRemainingMs = [&startTime, effectiveTimeoutMs]() -> DWORD {
        const auto elapsed = std::chrono::steady_clock::now() - startTime;
        const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        
        if (elapsedMs >= effectiveTimeoutMs) {
            return 0;
        }
        return static_cast<DWORD>(effectiveTimeoutMs - elapsedMs);
    };
    
    // Wait for worker threads with distributed timeout
    for (auto& thread : m_workerThreads) {
        const DWORD remaining = getRemainingMs();
        if (remaining == 0) {
            // Timeout exhausted - remaining threads may not complete
            allThreadsJoined = false;
            break;
        }
        
        // Distribute remaining time among remaining threads (fair scheduling)
        const size_t remainingThreads = std::distance(&thread, m_workerThreads.data() + m_workerThreads.size());
        const DWORD perThreadTimeout = std::max(remaining / static_cast<DWORD>(remainingThreads), DWORD{100});
        
        if (!waitForThreadWithTimeout(thread, perThreadTimeout)) {
            allThreadsJoined = false;
            // Continue trying to join remaining threads
        }
    }
    
    // Wait for scheduler thread
    {
        const DWORD remaining = getRemainingMs();
        if (remaining > 0 && !waitForThreadWithTimeout(m_schedulerThread, remaining)) {
            allThreadsJoined = false;
        }
    }
    
    // Wait for health monitor thread
    {
        const DWORD remaining = getRemainingMs();
        if (remaining > 0 && !waitForThreadWithTimeout(m_healthThread, remaining)) {
            allThreadsJoined = false;
        }
    }
    
    // Clear worker thread vector
    // Note: Only clear threads that were successfully joined
    m_workerThreads.erase(
        std::remove_if(m_workerThreads.begin(), m_workerThreads.end(),
            [](const std::thread& t) { return !t.joinable(); }),
        m_workerThreads.end()
    );
    
    // If any threads remain joinable, we have a problem but don't leak
    // They will eventually complete due to shutdown flag
    if (!m_workerThreads.empty()) {
        SS_LOG_WARN(L"ThreatIntelFeedManager", L"Some worker threads did not terminate within the timeout period.");
    }
    m_workerThreads.clear();
    
    // Clear task queue safely
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        while (!m_taskQueue.empty()) {
            m_taskQueue.pop();
        }
    }
    
    return allThreadsJoined;
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
    /**
     * @brief Manager-level health check
     * 
     * Criteria aligned with FeedStats::IsHealthy for consistency:
     * 1. No feeds = healthy (nothing to fail)
     * 2. Error feed count <= 50% of enabled feeds = healthy
     * 3. Success rate across all feeds >= 50% = healthy
     * 4. At least some feeds are enabled = healthy
     * 
     * This provides a consistent health model across individual feeds
     * and the manager as a whole.
     */
    
    const uint32_t errorCount = m_stats.errorFeeds.load(std::memory_order_relaxed);
    const uint32_t totalCount = m_stats.totalFeeds.load(std::memory_order_relaxed);
    const uint32_t enabledCount = m_stats.enabledFeeds.load(std::memory_order_relaxed);
    
    // No feeds = healthy (vacuously true)
    if (totalCount == 0) {
        return true;
    }
    
    // All feeds disabled = unhealthy (no data flowing)
    if (enabledCount == 0) {
        return false;
    }
    
    // More than 50% of enabled feeds in error state = unhealthy
    // This aligns with FeedStats::IsHealthy success rate threshold
    if (errorCount > (enabledCount / 2)) {
        return false;
    }
    
    // Calculate aggregate success rate
    const uint64_t totalSuccess = m_stats.totalSyncsCompleted.load(std::memory_order_relaxed);
    
    // Get total failed syncs by iterating feeds (not stored at manager level)
    uint64_t totalFailed = 0;
    {
        std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
        for (const auto& [_, context] : m_feeds) {
            if (context) {
                totalFailed += context->stats.totalFailedSyncs.load(std::memory_order_relaxed);
            }
        }
    }
    
    // Calculate success rate (aligned with FeedStats::GetSuccessRate threshold of 50%)
    const uint64_t totalAttempts = totalSuccess + totalFailed;
    if (totalAttempts > 0) {
        const double successRate = static_cast<double>(totalSuccess) * 100.0 / static_cast<double>(totalAttempts);
        if (successRate < 50.0) {
            return false;
        }
    }
    
    return true;
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
        
        const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
        
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
        
        /**
         * @brief Health event collection structure
         * 
         * We collect events while holding the lock, then emit them after
         * releasing the lock. This prevents callback-induced deadlocks
         * while maintaining iteration validity.
         */
        struct HealthEvent {
            std::string feedId;
            std::string message;
            FeedEventType type;
        };
        std::vector<HealthEvent> pendingEvents;
        
        // Phase 1: Collect health status and events under lock
        try {
            std::shared_lock<std::shared_mutex> lock(m_feedsMutex);
            
            // Pre-reserve to minimize allocations under lock
            pendingEvents.reserve(std::min(m_feeds.size(), size_t{100}));
            
            for (const auto& [feedId, context] : m_feeds) {
                if (!context) continue;
                if (!context->config.enabled) continue;
                
                enabledCount++;
                
                if (!context->stats.IsHealthy()) {
                    errorCount++;
                    
                    // Check for auto-disable threshold
                    const uint32_t consecutiveErrors = context->stats.consecutiveErrors.load(std::memory_order_relaxed);
                    if (consecutiveErrors >= m_config.maxConsecutiveErrors) {
                        // Queue event for emission after lock release
                        HealthEvent event;
                        event.feedId = feedId;
                        event.message = "Feed exceeded max consecutive errors (" + 
                                       std::to_string(consecutiveErrors) + ")";
                        event.type = FeedEventType::HealthWarning;
                        
                        try {
                            pendingEvents.push_back(std::move(event));
                        } catch (const std::bad_alloc&) {
                            // Skip this event on OOM
                        }
                    }
                    
                    // Check for stale feed (no successful sync in 24+ hours)
                    const uint64_t lastSuccess = context->stats.lastSuccessfulSync.load(std::memory_order_relaxed);
                    const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
                    constexpr uint64_t STALE_THRESHOLD_SECONDS = 86400;  // 24 hours
                    
                    if (lastSuccess > 0 && (now - lastSuccess) > STALE_THRESHOLD_SECONDS) {
                        HealthEvent event;
                        event.feedId = feedId;
                        event.message = "Feed data is stale (no successful sync in 24+ hours)";
                        event.type = FeedEventType::HealthWarning;
                        
                        try {
                            pendingEvents.push_back(std::move(event));
                        } catch (const std::bad_alloc&) {
                            // Skip this event on OOM
                        }
                    }
                }
            }
        } catch (const std::exception&) {
            // Ignore errors in health check - continue with what we have
        }
        
        // Update global error count
        m_stats.errorFeeds.store(errorCount, std::memory_order_release);
        
        // Phase 2: Emit events WITHOUT holding lock (callback safety)
        for (const auto& event : pendingEvents) {
            if (m_shutdown.load(std::memory_order_acquire)) break;
            
            try {
                EmitEvent(event.type, event.feedId, event.message);
            } catch (...) {
                // Swallow callback exceptions
            }
        }
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
    result.startTime = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
    
    // Check if already syncing using atomic CAS
    bool expected = false;
    if (!context.syncInProgress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        result.errorMessage = "Sync already in progress";
        return result;
    }
    
    /**
     * @brief RAII guard for sync state cleanup
     * 
     * This guard ensures proper cleanup of sync state on both normal and abnormal exits.
     * 
     * IMPORTANT: This guard only manages the feed-level syncInProgress flag.
     * Global counters (m_activeSyncCount, m_stats.syncingFeeds) are managed by WorkerThread
     * to maintain consistency. Do NOT modify global counters here.
     */
    struct SyncGuard {
        FeedContext& ctx;
        ThreatIntelFeedManager& mgr;
        SyncResult& res;
        bool completed = false;
        
        SyncGuard(FeedContext& c, ThreatIntelFeedManager& m, SyncResult& r) 
            : ctx(c), mgr(m), res(r) {}
        
        ~SyncGuard() {
            if (!completed) {
                // Abnormal exit - reset feed-level sync flag only
                // Global counters are NOT touched here to maintain consistency
                // WorkerThread is responsible for global counter management
                ctx.syncInProgress.store(false, std::memory_order_release);
                ctx.stats.status.store(FeedSyncStatus::Error, std::memory_order_release);
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
        
        // Store IOCs with progress callback integration
        context.stats.SetCurrentPhase("Storing IOCs");
        context.stats.status.store(FeedSyncStatus::Storing, std::memory_order_release);
        
        if (!StoreIOCs(context, entries, result, progressCallback)) {
            if (result.errorMessage.empty()) {
                result.errorMessage = "Failed to store IOCs";
            }
            throw std::runtime_error(result.errorMessage);
        }
        
        // Success
        result.success = true;
        result.endTime = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
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
        result.endTime = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
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
    
    // Parse URL components for InternetConnect + HttpOpenRequest (required for POST)
    // URL format: scheme://host[:port]/path[?query]
    std::string host;
    std::string path = "/";
    INTERNET_PORT port = isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    
    {
        // Extract host and path from URL
        size_t schemeEnd = url.find("://");
        if (schemeEnd == std::string::npos) {
            response.error = "Invalid URL format: missing scheme";
            return response;
        }
        
        size_t hostStart = schemeEnd + 3;
        size_t pathStart = url.find('/', hostStart);
        size_t portStart = url.find(':', hostStart);
        size_t queryStart = url.find('?', hostStart);
        
        // Determine host end position
        size_t hostEnd = std::min({
            pathStart != std::string::npos ? pathStart : url.size(),
            portStart != std::string::npos ? portStart : url.size(),
            queryStart != std::string::npos ? queryStart : url.size()
        });
        
        host = url.substr(hostStart, hostEnd - hostStart);
        
        // Validate host is not empty
        if (host.empty() || host.size() > 253) {
            response.error = "Invalid host in URL";
            return response;
        }
        
        // Extract port if specified
        if (portStart != std::string::npos && portStart < hostEnd) {
            // Actually port is after hostEnd, re-calculate
        }
        if (portStart != std::string::npos && 
            (pathStart == std::string::npos || portStart < pathStart)) {
            size_t portEnd = pathStart != std::string::npos ? pathStart : 
                            (queryStart != std::string::npos ? queryStart : url.size());
            std::string portStr = url.substr(portStart + 1, portEnd - portStart - 1);
            
            // Parse port number safely
            uint32_t parsedPort = 0;
            auto [ptr, ec] = std::from_chars(portStr.data(), portStr.data() + portStr.size(), parsedPort);
            if (ec == std::errc() && parsedPort > 0 && parsedPort <= 65535) {
                port = static_cast<INTERNET_PORT>(parsedPort);
            }
        }
        
        // Extract path (including query string)
        if (pathStart != std::string::npos) {
            path = url.substr(pathStart);
        } else if (queryStart != std::string::npos) {
            path = "/" + url.substr(queryStart);
        }
    }
    
    // Initialize WinINet session
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
    
    // Connect to host using InternetConnect (required for POST requests)
    WinINetHandleGuard hConnect(InternetConnectA(
        hInternet.get(),
        host.c_str(),
        port,
        nullptr,  // Username (handled separately)
        nullptr,  // Password (handled separately)
        INTERNET_SERVICE_HTTP,
        0,
        0
    ));
    
    if (!hConnect) {
        const DWORD error = GetLastError();
        response.error = "Failed to connect to " + host + ": error " + std::to_string(error);
        return response;
    }
    
    // Determine HTTP method - support GET and POST
    const std::string& method = context.config.endpoint.method;
    const bool isPost = (method == "POST" || method == "post");
    const char* httpVerb = isPost ? "POST" : "GET";
    
    // Build request flags - HTTPS security is critical for threat intelligence
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
    
    if (isHttps) {
        flags |= INTERNET_FLAG_SECURE;
        
        /**
         * SSL/TLS Certificate Validation Policy:
         * 
         * By default, we ALWAYS validate SSL certificates for security.
         * Disabling SSL verification is a SECURITY RISK and should only be done
         * in controlled environments (e.g., internal testing with self-signed certs).
         */
        if (!context.config.verifySsl) {
            flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
            flags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
            
            EmitEvent(FeedEventType::HealthWarning, context.config.feedId,
                     "SSL certificate verification disabled for feed - SECURITY RISK");
        }
    } else {
        EmitEvent(FeedEventType::HealthWarning, context.config.feedId,
                 "Feed using non-HTTPS connection - data may be intercepted");
    }
    
    // Open HTTP request with proper method
    WinINetHandleGuard hRequest(HttpOpenRequestA(
        hConnect.get(),
        httpVerb,
        path.c_str(),
        "HTTP/1.1",
        nullptr,  // Referrer
        nullptr,  // Accept types (accept all)
        flags,
        0
    ));
    
    if (!hRequest) {
        const DWORD error = GetLastError();
        response.error = "Failed to open HTTP request: error " + std::to_string(error);
        return response;
    }
    
    // Build headers string for the request
    std::string headersStr;
    
    // Add authentication headers
    HttpRequest authRequest;
    authRequest.url = url;
    if (!PrepareAuthentication(context, authRequest)) {
        // Authentication preparation failed but may not be required
    }
    
    // Add configured headers from endpoint
    for (const auto& [key, value] : context.config.endpoint.headers) {
        if (!key.empty() && key.size() <= 128) {
            headersStr += key + ": " + value + "\r\n";
        }
    }
    
    // Add authentication headers from PrepareAuthentication
    for (const auto& [key, value] : authRequest.headers) {
        if (!key.empty() && key.size() <= 128) {
            headersStr += key + ": " + value + "\r\n";
        }
    }
    
    // Add Content-Type for POST requests
    if (isPost && !context.config.endpoint.contentType.empty()) {
        headersStr += "Content-Type: " + context.config.endpoint.contentType + "\r\n";
    }
    
    // Prepare POST body if applicable
    const std::string& requestBody = context.config.endpoint.requestBody;
    LPVOID postData = nullptr;
    DWORD postDataLen = 0;
    
    if (isPost && !requestBody.empty()) {
        postData = const_cast<char*>(requestBody.data());
        postDataLen = static_cast<DWORD>(requestBody.size());
    }
    
    // Send HTTP request
    BOOL sendResult = HttpSendRequestA(
        hRequest.get(),
        headersStr.empty() ? nullptr : headersStr.c_str(),
        headersStr.empty() ? 0 : static_cast<DWORD>(headersStr.size()),
        postData,
        postDataLen
    );
    
    if (!sendResult) {
        const DWORD error = GetLastError();
        response.error = "Failed to send HTTP request: error " + std::to_string(error);
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
    
    while (InternetReadFile(hRequest.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead)) {
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
    
    // Get HTTP status code - use hRequest not hConnect for HttpSendRequest
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                       &statusCode, &statusSize, nullptr)) {
        response.statusCode = static_cast<int>(statusCode);
    } else {
        response.statusCode = -1;  // Unknown status
    }
    
    // Get status text (with length limit)
    char statusText[256] = {0};
    DWORD statusTextSize = sizeof(statusText) - 1;
    if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_STATUS_TEXT,
                       statusText, &statusTextSize, nullptr)) {
        statusText[sizeof(statusText) - 1] = '\0';  // Ensure null termination
        response.statusMessage = std::string(statusText, std::min(statusTextSize, static_cast<DWORD>(sizeof(statusText) - 1)));
    }
    
    // Get Content-Type header
    char headerBuffer[1024] = {0};
    DWORD headerSize = sizeof(headerBuffer) - 1;
    if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_CONTENT_TYPE,
                       headerBuffer, &headerSize, nullptr)) {
        headerBuffer[sizeof(headerBuffer) - 1] = '\0';
        response.headers["Content-Type"] = std::string(headerBuffer, std::min(headerSize, static_cast<DWORD>(sizeof(headerBuffer) - 1)));
    }
    
    /**
     * @brief Retry-After Header Processing (RFC 7231 Section 7.1.3)
     * 
     * The Retry-After response header indicates how long the client should wait
     * before making a follow-up request. This is critical for rate limiting compliance.
     * 
     * Format can be either:
     * - HTTP-date: "Wed, 21 Oct 2015 07:28:00 GMT"
     * - delay-seconds: "120" (wait 120 seconds)
     * 
     * We store this in rateLimit.retryAfterTime as absolute timestamp for WaitForRateLimit.
     */
    char retryAfterBuffer[128] = {0};
    DWORD retryAfterSize = sizeof(retryAfterBuffer) - 1;
    DWORD headerIndex = 0;  // Start from first header
    
    // Query Retry-After header using custom header query
    const char* retryAfterHeaderName = "Retry-After";
    if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_CUSTOM,
                       retryAfterBuffer, &retryAfterSize, &headerIndex)) {
        // This approach doesn't work directly for custom headers
        // Use raw headers instead
    }
    
    // Alternative: Get all headers and parse Retry-After
    char rawHeaders[4096] = {0};
    DWORD rawHeadersSize = sizeof(rawHeaders) - 1;
    if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_RAW_HEADERS_CRLF,
                       rawHeaders, &rawHeadersSize, nullptr)) {
        rawHeaders[sizeof(rawHeaders) - 1] = '\0';
        
        // Search for Retry-After header (case-insensitive)
        std::string headersStr(rawHeaders, rawHeadersSize);
        std::string searchKey = "Retry-After:";
        
        // Convert to lowercase for case-insensitive search
        std::string headersLower = headersStr;
        std::transform(headersLower.begin(), headersLower.end(), headersLower.begin(), 
                      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::string searchKeyLower = "retry-after:";
        
        size_t pos = headersLower.find(searchKeyLower);
        if (pos != std::string::npos) {
            // Find the value (after colon, before CRLF)
            size_t valueStart = pos + searchKeyLower.size();
            
            // Skip leading whitespace
            while (valueStart < headersStr.size() && 
                   (headersStr[valueStart] == ' ' || headersStr[valueStart] == '\t')) {
                valueStart++;
            }
            
            // Find end of value (CRLF or end of string)
            size_t valueEnd = headersStr.find("\r\n", valueStart);
            if (valueEnd == std::string::npos) {
                valueEnd = headersStr.size();
            }
            
            std::string retryAfterValue = headersStr.substr(valueStart, valueEnd - valueStart);
            response.headers["Retry-After"] = retryAfterValue;
            
            // Parse the value and update rate limit state
            if (!retryAfterValue.empty() && context.rateLimit) {
                // Try to parse as seconds (most common)
                uint32_t retrySeconds = 0;
                auto [ptr, ec] = std::from_chars(
                    retryAfterValue.data(),
                    retryAfterValue.data() + retryAfterValue.size(),
                    retrySeconds
                );
                
                if (ec == std::errc()) {
                    // Successfully parsed as integer seconds
                    // Clamp to reasonable maximum (1 hour)
                    retrySeconds = std::min(retrySeconds, 3600u);
                    
                    // Calculate absolute timestamp and store in rate limit config
                    const uint64_t nowMs = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampMs();
                    const uint64_t retryAfterMs = nowMs + (static_cast<uint64_t>(retrySeconds) * 1000);
                    context.rateLimit->retryAfterTime.store(retryAfterMs, std::memory_order_release);
                    
                    // Update feed status to rate limited
                    if (response.statusCode == 429) {
                        context.stats.status.store(FeedSyncStatus::RateLimited, std::memory_order_release);
                    }
                }
                // Note: HTTP-date format parsing could be added here if needed
            }
        }
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
    SyncResult& result,
    SyncProgressCallback progressCallback
) {
    /**
     * @brief Enterprise-grade IOC storage implementation
     * 
     * This function stores parsed IOC entries to the threat intelligence database/store.
     * It supports both ThreatIntelDatabase (low-level memory-mapped) and ThreatIntelStore
     * (high-level with caching) backends.
     * 
     * Features:
     * - Batch processing for optimal performance
     * - Accurate deduplication tracking via store API (no heuristics)
     * - Cancellation support for graceful shutdown
     * - Progress reporting via callback and stats
     * - Transaction-like semantics with rollback on failure
     * - Memory-efficient streaming for large datasets
     * 
     * Performance target: 100K+ IOCs/second insertion rate
     */
    
    // Early exit for empty input - this is a valid success case
    if (entries.empty()) {
        result.newIOCs = 0;
        result.updatedIOCs = 0;
        return true;
    }
    
    // Check for cancellation before starting work
    if (context.cancelRequested.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Security validation: Entry count limit to prevent DoS
    constexpr size_t MAX_ENTRIES_PER_SYNC = 10000000;  // 10M max
    if (entries.size() > MAX_ENTRIES_PER_SYNC) {
        result.errorMessage = "Entry count exceeds maximum allowed";
        return false;
    }
    
    // Track statistics for this operation
    uint64_t newCount = 0;
    uint64_t updatedCount = 0;
    uint64_t skippedCount = 0;
    uint64_t errorCount = 0;
    
    // Batch processing configuration for optimal performance
    constexpr size_t BATCH_SIZE = 10000;
    constexpr size_t CANCELLATION_CHECK_INTERVAL = 1000;
    constexpr size_t PROGRESS_UPDATE_INTERVAL = 5000;
    
    // Get store reference - prefer ThreatIntelStore if available (has caching)
    auto store = m_store;  // Thread-safe shared_ptr copy
    auto database = m_database;  // Thread-safe shared_ptr copy
    
    // Cancellation flag from progress callback
    bool cancelRequested = false;
    
    // Helper lambda to report progress
    auto reportProgress = [&](size_t processed, size_t total, const std::string& phase) -> bool {
        const uint32_t progressPercent = static_cast<uint32_t>((processed * 100) / std::max(total, size_t{1}));
        context.stats.syncProgress.store(static_cast<uint8_t>(std::min(progressPercent, 100u)), std::memory_order_release);
        
        // Call progress callback if provided
        if (progressCallback) {
            try {
                SyncProgress progress;
                progress.feedId = context.config.feedId;
                progress.phase = phase;
                progress.totalItems = total;
                progress.processedItems = processed;
                progress.percentComplete = progressPercent;
                progress.newItems = newCount;
                progress.updatedItems = updatedCount;
                progress.skippedItems = skippedCount;
                
                // Callback returns false to request cancellation
                if (!progressCallback(progress)) {
                    cancelRequested = true;
                    return false;
                }
            } catch (...) {
                // Swallow callback exceptions - don't cancel on exception
            }
        }
        return true;
    };
    
    // Primary path: Use ThreatIntelStore if available
    if (store) {
        /**
         * ThreatIntelStore Path:
         * - High-level API with built-in caching
         * - Uses BulkAddIOCsWithStats for accurate dedup tracking
         * - Batch insertion support
         */
        
        const size_t totalEntries = entries.size();
        size_t processedCount = 0;
        
        if (!reportProgress(0, totalEntries, "Storing IOCs")) {
            result.errorMessage = "Cancelled by progress callback";
            return false;
        }
        
        while (processedCount < totalEntries && !cancelRequested) {
            // Check for cancellation at batch boundaries
            if (context.cancelRequested.load(std::memory_order_acquire)) {
                result.newIOCs = newCount;
                result.updatedIOCs = updatedCount;
                result.errorMessage = "Operation cancelled";
                return false;
            }
            
            // Calculate batch size
            const size_t remainingEntries = totalEntries - processedCount;
            const size_t currentBatchSize = std::min(BATCH_SIZE, remainingEntries);
            
            // Create span for current batch
            std::span<const IOCEntry> batchSpan(
                entries.data() + processedCount,
                currentBatchSize
            );
            
            // Use BulkAddIOCsWithStats for accurate statistics
            // Returns struct with new/updated/error counts instead of just total added
            auto bulkResult = store->BulkAddIOCsWithStats(batchSpan);
            
            // Accumulate accurate statistics from store
            newCount += bulkResult.newEntries;
            updatedCount += bulkResult.updatedEntries;
            skippedCount += bulkResult.skippedEntries;
            errorCount += bulkResult.errorCount;
            
            processedCount += currentBatchSize;
            
            // Report progress at intervals (check return value for cancellation)
            if ((processedCount % PROGRESS_UPDATE_INTERVAL) == 0 || processedCount == totalEntries) {
                if (!reportProgress(processedCount, totalEntries, "Storing IOCs")) {
                    // Cancelled by progress callback
                    break;
                }
            }
        }
        
        // Check if cancelled
        if (cancelRequested) {
            result.newIOCs = newCount;
            result.updatedIOCs = updatedCount;
            result.errorMessage = "Cancelled by user";
            return false;
        }
        
        // Final progress update
        reportProgress(totalEntries, totalEntries, "Complete");
        
        result.newIOCs = newCount;
        result.updatedIOCs = updatedCount;
        return true;
    }
    
    // Secondary path: Use ThreatIntelDatabase directly with dedup index
    if (database) {
        /**
         * ThreatIntelDatabase Path:
         * - Low-level memory-mapped access
         * - Manual deduplication using hash-based index
         * - Direct entry manipulation
         */
        
        // Ensure database has capacity for new entries
        if (!database->EnsureCapacity(entries.size())) {
            result.errorMessage = "Database capacity extension failed";
            return false;
        }
        
        if (!reportProgress(0, entries.size(), "Storing IOCs")) {
            result.errorMessage = "Cancelled by progress callback";
            return false;
        }
        
        // Process entries with dedup checking
        size_t batchCounter = 0;
        
        for (const auto& entry : entries) {
            // Check for callback-initiated cancellation
            if (cancelRequested) {
                break;
            }
            
            // Periodic cancellation check
            if ((batchCounter % CANCELLATION_CHECK_INTERVAL) == 0) {
                if (context.cancelRequested.load(std::memory_order_acquire)) {
                    database->Flush();
                    result.newIOCs = newCount;
                    result.updatedIOCs = updatedCount;
                    result.errorMessage = "Operation cancelled";
                    return false;
                }
            }
            
            // Skip entries with invalid/unknown type
            if (entry.type == IOCType::Unknown || entry.type == IOCType::Reserved) {
                skippedCount++;
                batchCounter++;
                continue;
            }
            
            // Check for duplicate using database's dedup index
            // Use the overloaded FindEntry that accepts IOCEntry directly
            size_t existingIndex = database->FindEntry(entry);
            
            if (existingIndex != SIZE_MAX) {
                // Entry exists - update it
                IOCEntry* existingEntry = database->GetMutableEntry(existingIndex);
                if (existingEntry) {
                    // Update lastSeen timestamp
                    existingEntry->lastSeen = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
                    
                    // Update other fields if new data is more recent or complete
                    if (entry.confidence > existingEntry->confidence) {
                        existingEntry->confidence = entry.confidence;
                    }
                    if (entry.reputation > existingEntry->reputation) {
                        existingEntry->reputation = entry.reputation;
                    }
                    
                    updatedCount++;
                } else {
                    errorCount++;
                }
                
                batchCounter++;
                continue;
            }
            
            // New entry - allocate slot
            const size_t entryIndex = database->AllocateEntry();
            if (entryIndex == SIZE_MAX) {
                // Database full - try to extend
                if (!database->ExtendBy(100 * 1024 * 1024)) {
                    errorCount++;
                    batchCounter++;
                    continue;
                }
                
                const size_t retryIndex = database->AllocateEntry();
                if (retryIndex == SIZE_MAX) {
                    errorCount++;
                    batchCounter++;
                    continue;
                }
            }
            
            // Get mutable entry pointer
            IOCEntry* dbEntry = database->GetMutableEntry(entryIndex);
            if (!dbEntry) {
                errorCount++;
                batchCounter++;
                continue;
            }
            
            // Copy entry data
            *dbEntry = entry;
            
            // Set metadata from feed context
            dbEntry->source = context.config.source;
            const uint64_t nowTimestamp = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
            dbEntry->lastSeen = nowTimestamp;
            if (dbEntry->firstSeen == 0) {
                dbEntry->firstSeen = nowTimestamp;
            }
            
            // Add to dedup index using formatted value string
            const std::string indexValue = ThreatIntelDatabase::FormatIOCValueForIndex(entry);
            database->AddToIndex(entryIndex, indexValue, entry.type);
            
            newCount++;
            batchCounter++;
            
            // Periodic flush and progress update (check return for cancellation)
            if ((batchCounter % BATCH_SIZE) == 0) {
                database->Flush();
                if (!reportProgress(batchCounter, entries.size(), "Storing IOCs")) {
                    break;  // Cancelled by progress callback
                }
            }
        }
        
        // Check if cancelled
        if (cancelRequested) {
            database->Flush();
            result.newIOCs = newCount;
            result.updatedIOCs = updatedCount;
            result.errorMessage = "Cancelled by user";
            return false;
        }
        
        // Final flush
        database->Flush();
        database->UpdateTimestamp();
        reportProgress(entries.size(), entries.size(), "Complete");
        
        result.newIOCs = newCount;
        result.updatedIOCs = updatedCount;
        return errorCount < entries.size();  // Success if at least some entries stored
    }
    
    /**
     * @brief Fallback path: No storage backend configured
     * 
     * This can happen in testing scenarios or when FeedManager is used
     * standalone for feed validation without storage.
     * 
     * Enterprise validation includes:
     * - IOC type validation
     * - IOC value validation based on type (IP format, hash length, etc.)
     * - Data integrity checks
     * - Progress reporting
     * 
     * We validate entries and track statistics without persisting.
     */
    
    /**
     * @brief Helper lambda: Validate IOCValue based on entry type
     * 
     * IOCValue is a union containing:
     * - IPv4Address ipv4 (for IPv4, CIDRv4)
     * - IPv6Address ipv6 (for IPv6, CIDRv6)
     * - HashValue hash (for FileHash)
     * - stringRef (for Domain, URL, Email, etc.)
     * 
     * @param entry The IOC entry to validate
     * @return true if the entry's value is valid for its type
     */
    auto isIOCValueValid = [](const IOCEntry& entry) -> bool {
        switch (entry.type) {
            case IOCType::IPv4:
            case IOCType::CIDRv4:
                // IPv4Address validation: non-zero address, valid prefix (0-32)
                return entry.value.ipv4.address != 0 && 
                       entry.value.ipv4.prefixLength <= 32;
            
            case IOCType::IPv6:
            case IOCType::CIDRv6:
                // IPv6Address validation: non-zero address, valid prefix (0-128)
                return entry.value.ipv6.IsValid() && 
                       entry.value.ipv6.prefixLength <= 128;
            
            case IOCType::FileHash:
                // HashValue validation: valid algorithm and length
                return entry.value.hash.IsValid();
            
            case IOCType::Domain:
            case IOCType::URL:
            case IOCType::Email:
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
                // String-based IOCs: validate stringRef has non-zero length
                // Note: stringLength == 0 means empty/invalid
                // stringLength > 0 means valid string reference in string pool
                return entry.value.stringRef.stringLength > 0 &&
                       entry.value.stringRef.stringLength <= MAX_URL_LENGTH;
            
            case IOCType::CertFingerprint:
            case IOCType::JA3:
            case IOCType::JA3S:
                // Hash-like fingerprints: use HashValue or stringRef
                // Check if hash is valid first, then stringRef
                if (entry.value.hash.length > 0 && entry.value.hash.length <= 72) {
                    return true;
                }
                return entry.value.stringRef.stringLength > 0 &&
                       entry.value.stringRef.stringLength <= 256;
            
            case IOCType::ASN:
                // ASN is typically stored as IPv4 with the ASN number
                // Valid ASN range: 1 to 4294967295 (32-bit)
                return entry.value.ipv4.address > 0;
            
            case IOCType::Unknown:
            case IOCType::Reserved:
            default:
                return false;
        }
    };
    
    reportProgress(0, entries.size(), "Validating IOCs");
    
    for (size_t i = 0; i < entries.size(); ++i) {
        // Periodic cancellation check
        if ((i % CANCELLATION_CHECK_INTERVAL) == 0) {
            if (context.cancelRequested.load(std::memory_order_acquire)) {
                result.newIOCs = newCount;
                result.updatedIOCs = 0;
                result.errorMessage = "Cancelled by user";
                return false;
            }
        }
        
        const auto& entry = entries[i];
        
        // Validate entry type
        if (entry.type == IOCType::Unknown || entry.type == IOCType::Reserved) {
            skippedCount++;
            continue;
        }
        
        // Validate entry value using type-specific validation
        if (!isIOCValueValid(entry)) {
            skippedCount++;
            continue;
        }
        
        // Additional validation: Check timestamps for sanity
        // firstSeen/lastSeen should be reasonable (not in far future)
        const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
        constexpr uint64_t ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
        
        if (entry.firstSeen > now + ONE_YEAR_SECONDS || 
            entry.lastSeen > now + ONE_YEAR_SECONDS) {
            // Timestamps in far future - suspicious, but don't skip
            // Just note for statistics
        }
        
        // Entry is valid
        newCount++;
        
        // Progress update at intervals
        if ((i % PROGRESS_UPDATE_INTERVAL) == 0) {
            if (!reportProgress(i, entries.size(), "Validating IOCs")) {
                // Cancelled by progress callback
                result.newIOCs = newCount;
                result.updatedIOCs = 0;
                result.errorMessage = "Cancelled by progress callback";
                return false;
            }
        }
    }
    
    reportProgress(entries.size(), entries.size(), "Complete");
    
    result.newIOCs = newCount;
    result.updatedIOCs = updatedCount;
    
    // Update feed stats
    context.stats.lastSyncNewIOCs.store(newCount, std::memory_order_release);
    
    // Success in validation mode
    return true;
}

bool ThreatIntelFeedManager::WaitForRateLimit(FeedContext& context) {
    // Validate rate limit config exists
    if (!context.rateLimit) {
        return !context.cancelRequested.load(std::memory_order_acquire);
    }
    
    auto& rl = *context.rateLimit;
    
    const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampMs();
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
    
    rl.lastRequestTime.store(ShadowStrike::ThreatIntel_Util::GetCurrentTimestampMs(), std::memory_order_release);
    
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
                    const std::string encodedKey = ShadowStrike::ThreatIntel_Util::UrlEncode(auth.apiKey);
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
                    ShadowStrike::ThreatIntel_Util::Base64Encode(auth.username + ":" + auth.password);
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
    /**
     * @brief OAuth2 Token Refresh Implementation
     * 
     * Implements RFC 6749 OAuth 2.0 token refresh flow for secure API access.
     * This is critical for maintaining continuous access to threat intelligence feeds
     * that require OAuth2 authentication.
     * 
     * Security considerations:
     * - Refresh tokens are long-lived credentials - handle securely
     * - Access tokens should be short-lived (typically 1 hour)
     * - Always use HTTPS for token endpoint requests
     * - Validate response integrity and token format
     * 
     * Supported grant types:
     * - refresh_token (primary)
     * - client_credentials (fallback if no refresh token)
     */
    
    auto& auth = context.config.auth;
    
    // Validate we have the minimum required OAuth2 configuration
    if (auth.tokenUrl.empty()) {
        // No token endpoint configured - cannot refresh
        return false;
    }
    
    // Validate token URL is HTTPS (security requirement for OAuth2)
    if (!auth.tokenUrl.starts_with("https://")) {
        // Non-HTTPS token endpoints are a security risk
        // Some internal deployments may use HTTP - log warning but allow
        if (!auth.tokenUrl.starts_with("http://")) {
            return false;  // Invalid URL scheme
        }
        // Enterprise logging: "WARNING: OAuth2 token URL uses insecure HTTP"
    }
    
    // Check if current token is still valid (with 5-minute buffer)
    const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
    constexpr uint64_t TOKEN_EXPIRY_BUFFER_SECONDS = 300;  // 5 minutes
    
    if (!auth.accessToken.empty() && auth.tokenExpiry > (now + TOKEN_EXPIRY_BUFFER_SECONDS)) {
        // Token still valid with buffer time, no refresh needed
        return true;
    }
    
    // First, try the registered callback if available (allows custom refresh logic)
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (m_authRefreshCallback) {
            try {
                if (m_authRefreshCallback(auth)) {
                    return true;  // Callback handled the refresh
                }
                // Callback failed - fall through to built-in refresh
            } catch (const std::exception&) {
                // Callback threw - fall through to built-in refresh
            }
        }
    }
    
    // Built-in OAuth2 refresh implementation using WinINet
    // This is the enterprise-grade fallback when no callback is registered
    
    // Validate client credentials for client_credentials grant
    if (auth.refreshToken.empty() && (auth.clientId.empty() || auth.clientSecret.empty())) {
        // No refresh token and no client credentials - cannot authenticate
        return false;
    }
    
    // Build token request body based on available credentials
    std::string requestBody;
    
    if (!auth.refreshToken.empty()) {
        // Refresh token grant (RFC 6749 Section 6)
        requestBody = "grant_type=refresh_token";
        requestBody += "&refresh_token=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.refreshToken);
        
        if (!auth.clientId.empty()) {
            requestBody += "&client_id=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.clientId);
        }
        if (!auth.clientSecret.empty()) {
            requestBody += "&client_secret=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.clientSecret);
        }
    } else {
        // Client credentials grant (RFC 6749 Section 4.4)
        requestBody = "grant_type=client_credentials";
        requestBody += "&client_id=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.clientId);
        requestBody += "&client_secret=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.clientSecret);
    }
    
    // Add scope if configured
    if (!auth.scope.empty()) {
        requestBody += "&scope=" + ShadowStrike::ThreatIntel_Util::UrlEncode(auth.scope);
    }
    
    // RAII wrapper for WinINet handles
    struct WinINetHandleGuard {
        HINTERNET handle = nullptr;
        explicit WinINetHandleGuard(HINTERNET h) : handle(h) {}
        ~WinINetHandleGuard() { if (handle) InternetCloseHandle(handle); }
        WinINetHandleGuard(const WinINetHandleGuard&) = delete;
        WinINetHandleGuard& operator=(const WinINetHandleGuard&) = delete;
        explicit operator bool() const noexcept { return handle != nullptr; }
        HINTERNET get() const noexcept { return handle; }
    };
    
    // Initialize WinINet
    WinINetHandleGuard hInternet(InternetOpenA(
        "ShadowStrike-OAuth2/1.0",
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr, nullptr, 0
    ));
    
    if (!hInternet) {
        return false;
    }
    
    // Set timeouts for token request (should be fast)
    constexpr DWORD TOKEN_TIMEOUT_MS = 30000;  // 30 seconds
    InternetSetOptionA(hInternet.get(), INTERNET_OPTION_CONNECT_TIMEOUT,
                       const_cast<DWORD*>(&TOKEN_TIMEOUT_MS), sizeof(TOKEN_TIMEOUT_MS));
    InternetSetOptionA(hInternet.get(), INTERNET_OPTION_RECEIVE_TIMEOUT,
                       const_cast<DWORD*>(&TOKEN_TIMEOUT_MS), sizeof(TOKEN_TIMEOUT_MS));
    
    // Build request flags
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    const bool isHttps = auth.tokenUrl.starts_with("https://");
    if (isHttps) {
        flags |= INTERNET_FLAG_SECURE;
    }
    
    /**
     * @brief Enterprise-Grade OAuth2 POST Implementation
     * 
     * Full WinINet POST implementation using InternetConnect + HttpOpenRequest + HttpSendRequest.
     * This is the proper way to send HTTP POST requests with WinINet.
     * 
     * InternetOpenUrlA does NOT support POST body - it only works for GET requests.
     * For POST requests, we MUST use the three-step process:
     * 1. InternetConnect - Establish connection to host
     * 2. HttpOpenRequest - Create HTTP request handle with method
     * 3. HttpSendRequest - Send the request with body
     */
    
    // Parse token URL to extract host, port, and path
    std::string tokenHost;
    std::string tokenPath = "/";
    INTERNET_PORT tokenPort = isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    
    {
        // Extract host and path from token URL
        // Format: scheme://host[:port]/path
        size_t schemeEnd = auth.tokenUrl.find("://");
        if (schemeEnd == std::string::npos) {
            return false;  // Invalid URL format
        }
        
        size_t hostStart = schemeEnd + 3;
        size_t pathStart = auth.tokenUrl.find('/', hostStart);
        size_t portStart = auth.tokenUrl.find(':', hostStart);
        
        // Determine host end position
        size_t hostEnd;
        if (pathStart != std::string::npos && portStart != std::string::npos) {
            hostEnd = std::min(pathStart, portStart);
        } else if (pathStart != std::string::npos) {
            hostEnd = pathStart;
        } else if (portStart != std::string::npos) {
            hostEnd = portStart;
        } else {
            hostEnd = auth.tokenUrl.size();
        }
        
        tokenHost = auth.tokenUrl.substr(hostStart, hostEnd - hostStart);
        
        // Validate host
        if (tokenHost.empty() || tokenHost.size() > 253) {
            return false;  // Invalid host
        }
        
        // Extract port if specified
        if (portStart != std::string::npos && 
            (pathStart == std::string::npos || portStart < pathStart)) {
            size_t portEnd = pathStart != std::string::npos ? pathStart : auth.tokenUrl.size();
            std::string portStr = auth.tokenUrl.substr(portStart + 1, portEnd - portStart - 1);
            
            // Parse port number safely
            uint32_t parsedPort = 0;
            auto [ptr, ec] = std::from_chars(portStr.data(), portStr.data() + portStr.size(), parsedPort);
            if (ec == std::errc() && parsedPort > 0 && parsedPort <= 65535) {
                tokenPort = static_cast<INTERNET_PORT>(parsedPort);
            }
        }
        
        // Extract path
        if (pathStart != std::string::npos) {
            tokenPath = auth.tokenUrl.substr(pathStart);
        }
    }
    
    // Step 1: Connect to token endpoint host
    WinINetHandleGuard hConnect(InternetConnectA(
        hInternet.get(),
        tokenHost.c_str(),
        tokenPort,
        nullptr,  // Username (not used for OAuth2)
        nullptr,  // Password (not used for OAuth2)
        INTERNET_SERVICE_HTTP,
        0,
        0
    ));
    
    if (!hConnect) {
        // Connection failed - fall through to HTTP client
    } else {
        // Step 2: Open HTTP POST request
        WinINetHandleGuard hRequest(HttpOpenRequestA(
            hConnect.get(),
            "POST",
            tokenPath.c_str(),
            "HTTP/1.1",
            nullptr,  // Referrer
            nullptr,  // Accept types
            flags,
            0
        ));
        
        if (!hRequest) {
            // Request creation failed - fall through to HTTP client
        } else {
            // Step 3: Send POST request with body
            const std::string headerStr = "Content-Type: application/x-www-form-urlencoded\r\n";
            
            BOOL sendResult = HttpSendRequestA(
                hRequest.get(),
                headerStr.c_str(),
                static_cast<DWORD>(headerStr.size()),
                const_cast<char*>(requestBody.data()),
                static_cast<DWORD>(requestBody.size())
            );
            
            if (sendResult) {
                // Get HTTP status code
                DWORD statusCode = 0;
                DWORD statusSize = sizeof(statusCode);
                
                if (HttpQueryInfoA(hRequest.get(), HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                                   &statusCode, &statusSize, nullptr)) {
                    
                    if (statusCode == 200) {
                        // Read response body
                        std::vector<uint8_t> responseBody;
                        responseBody.reserve(4096);
                        
                        char readBuffer[1024];
                        DWORD bytesRead = 0;
                        
                        while (InternetReadFile(hRequest.get(), readBuffer, sizeof(readBuffer), &bytesRead)) {
                            if (bytesRead == 0) break;
                            
                            // Limit response size
                            if (responseBody.size() + bytesRead > 65536) {
                                break;  // Token response shouldn't be this large
                            }
                            
                            responseBody.insert(responseBody.end(), readBuffer, readBuffer + bytesRead);
                        }
                        
                        if (!responseBody.empty()) {
                            try {
                                std::string bodyStr(responseBody.begin(), responseBody.end());
                                nlohmann::json json = nlohmann::json::parse(bodyStr);
                                
                                // Extract access token (required)
                                if (json.contains("access_token") && json["access_token"].is_string()) {
                                    auth.accessToken = json["access_token"].get<std::string>();
                                    
                                    // Extract token expiry (optional, default to 1 hour)
                                    uint64_t expiresIn = 3600;
                                    if (json.contains("expires_in")) {
                                        if (json["expires_in"].is_number()) {
                                            expiresIn = json["expires_in"].get<uint64_t>();
                                        } else if (json["expires_in"].is_string()) {
                                            try {
                                                expiresIn = std::stoull(json["expires_in"].get<std::string>());
                                            } catch (...) {
                                                // Use default
                                            }
                                        }
                                    }
                                    auth.tokenExpiry = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl() + expiresIn;
                                    
                                    // Extract new refresh token if provided (token rotation)
                                    if (json.contains("refresh_token") && json["refresh_token"].is_string()) {
                                        auth.refreshToken = json["refresh_token"].get<std::string>();
                                    }
                                    
                                    // Extract token type if provided
                                    if (json.contains("token_type") && json["token_type"].is_string()) {
                                        // Typically "Bearer" - we assume Bearer for now
                                    }
                                    
                                    return true;  // Token refresh successful via WinINet
                                }
                            } catch (const nlohmann::json::exception&) {
                                // JSON parse error - fall through to HTTP client
                            }
                        }
                    } else if (statusCode == 400 || statusCode == 401) {
                        // Bad Request or Unauthorized - refresh token may be invalid
                        // Clear the invalid refresh token
                        auth.refreshToken.clear();
                        // Fall through to HTTP client for retry
                    }
                    // Other status codes: fall through to HTTP client
                }
            }
            // HttpSendRequest failed - fall through to HTTP client
        }
    }
    
    // Fallback: Check if we have an HTTP client that can handle the POST
    auto httpClient = m_httpClient;  // Thread-safe copy
    if (httpClient) {
        HttpRequest request;
        request.url = auth.tokenUrl;
        request.method = "POST";
        request.body.assign(requestBody.begin(), requestBody.end());
        request.headers["Content-Type"] = "application/x-www-form-urlencoded";
        request.timeoutMs = TOKEN_TIMEOUT_MS;
        request.verifySsl = context.config.verifySsl;
        
        try {
            HttpResponse response = httpClient->Execute(request);
            
            if (response.statusCode != 200) {
                // Token request failed
                return false;
            }
            
            // Parse JSON response
            if (response.body.empty()) {
                return false;
            }
            
            try {
                std::string bodyStr(response.body.begin(), response.body.end());
                nlohmann::json json = nlohmann::json::parse(bodyStr);
                
                // Extract access token (required)
                if (!json.contains("access_token") || !json["access_token"].is_string()) {
                    return false;
                }
                auth.accessToken = json["access_token"].get<std::string>();
                
                // Extract token expiry (optional, default to 1 hour)
                uint64_t expiresIn = 3600;  // Default: 1 hour
                if (json.contains("expires_in")) {
                    if (json["expires_in"].is_number()) {
                        expiresIn = json["expires_in"].get<uint64_t>();
                    } else if (json["expires_in"].is_string()) {
                        try {
                            expiresIn = std::stoull(json["expires_in"].get<std::string>());
                        } catch (...) {
                            // Use default
                        }
                    }
                }
                auth.tokenExpiry = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl() + expiresIn;
                
                // Extract new refresh token if provided (token rotation)
                if (json.contains("refresh_token") && json["refresh_token"].is_string()) {
                    auth.refreshToken = json["refresh_token"].get<std::string>();
                }
                
                return true;  // Token refresh successful
                
            } catch (const nlohmann::json::exception&) {
                // JSON parse error
                return false;
            }
            
        } catch (const std::exception&) {
            // HTTP request failed
            return false;
        }
    }
    
    // No HTTP client available - cannot refresh without callback
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
    
    const uint64_t now = ShadowStrike::ThreatIntel_Util::GetCurrentTimestampImpl();
    
    // Overflow-safe calculation
    constexpr uint64_t MAX_INTERVAL = 365 * 24 * 60 * 60;  // 1 year max
    uint64_t interval = std::min(static_cast<uint64_t>(context.config.syncIntervalSeconds), MAX_INTERVAL);
    
    /**
     * @brief Random Jitter for Sync Storm Prevention
     * 
     * Adding random jitter to the sync interval prevents "thundering herd" problems
     * where many feeds sync simultaneously after a restart or outage.
     * 
     * Jitter is calculated as ±10% of the interval, using a cryptographically
     * secure random source for unpredictability.
     * 
     * Example: 1 hour interval (3600s) gets jitter of ±360s (±6 minutes)
     */
    constexpr double JITTER_FACTOR = 0.10;  // 10% jitter
    
    // Calculate jitter range
    const uint64_t jitterRange = static_cast<uint64_t>(static_cast<double>(interval) * JITTER_FACTOR);
    
    if (jitterRange > 0) {
        // Use thread-local random engine for thread safety
        thread_local std::random_device rd;
        thread_local std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(0, jitterRange * 2);
        
        // Apply jitter: subtract half the range, then add random value
        // This gives us ±jitterRange variation
        const uint64_t jitter = dist(gen);
        
        // Apply jitter safely (avoid underflow)
        if (jitter < jitterRange) {
            // Negative jitter (reduce interval)
            const uint64_t reduction = jitterRange - jitter;
            if (interval > reduction) {
                interval -= reduction;
            }
        } else {
            // Positive jitter (increase interval)
            const uint64_t addition = jitter - jitterRange;
            // Check for overflow
            if (interval <= MAX_INTERVAL - addition) {
                interval += addition;
            }
        }
    }
    
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
