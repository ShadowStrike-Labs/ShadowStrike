/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * IOCExtractor.cpp — Indicator of Compromise extraction from emulation sessions
 *
 * Extracts and classifies all IOCs observed during emulation:
 *   - Domains (with DGA detection via entropy + consonant-ratio heuristics)
 *   - IPv4 / IPv6 addresses (with private/reserved classification)
 *   - URLs (full component extraction)
 *   - File paths and hashes
 *   - Registry keys and values (with persistence flagging)
 *   - Mutexes, services, named pipes
 *   - User agents, email addresses, command lines
 *
 * In-memory string scanning identifies embedded IOCs in guest memory,
 * including Base64-encoded values that are decoded and re-checked.
 *
 * All containers are capped to prevent memory exhaustion from adversarial
 * input flooding.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "IOCExtractor.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <cmath>
#include <cstring>
#include <shared_mutex>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Limits
// ============================================================================

static constexpr uint32_t kMaxIOCEntries         = 16384;
static constexpr uint32_t kMaxDomainsTracked     = 4096;
static constexpr uint32_t kMaxIPsTracked         = 4096;
static constexpr uint32_t kMaxURLsTracked        = 4096;
static constexpr uint32_t kMaxFilesTracked       = 4096;
static constexpr uint32_t kMaxRegistryTracked    = 4096;
static constexpr uint32_t kMaxMutexesTracked     = 1024;
static constexpr uint32_t kMaxServicesTracked    = 512;
static constexpr uint32_t kMaxPipesTracked       = 512;
static constexpr uint32_t kMaxUserAgentsTracked  = 128;
static constexpr uint32_t kMaxCmdLinesTracked    = 512;
static constexpr uint32_t kMaxStringLength       = 4096;
static constexpr uint32_t kMinASCIIStringLen     = 4;
static constexpr uint32_t kMinUTF16StringLen     = 4;
static constexpr size_t   kMaxMemoryScanSize     = 16 * 1024 * 1024;  // 16 MB per scan
static constexpr size_t   kMaxBase64DecodeLen    = 8192;

// DGA detection thresholds
static constexpr float    kDGAEntropyThreshold   = 3.5f;
static constexpr float    kDGAConsonantRatio     = 4.0f;
static constexpr float    kDGADigitRatio         = 0.5f;
static constexpr size_t   kDGAMinLabelLen        = 5;

// ============================================================================
// Common TLDs for domain validation
// ============================================================================

static const std::unordered_set<std::string>& GetCommonTLDs() noexcept {
    static const std::unordered_set<std::string> tlds = {
        "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "ru",
        "cn", "jp", "br", "in", "au", "ca", "it", "es", "nl", "se",
        "no", "fi", "dk", "pl", "cz", "kr", "tw", "sg", "hk", "nz",
        "za", "mx", "ar", "cl", "pe", "ve", "co", "ec", "th", "vn",
        "ph", "id", "my", "pk", "bd", "eg", "ng", "ke", "gh", "tz",
        "info", "biz", "xyz", "top", "site", "online", "club", "live",
        "tech", "store", "app", "dev", "cloud", "pro", "name", "mobi",
        "asia", "tel", "travel", "museum", "aero", "coop", "int",
        "gov", "edu", "mil", "cat", "jobs", "post",
        "cc", "tv", "ws", "me", "ly", "tk", "cf", "ga", "ml", "gq",
        "pw", "sx", "su", "to", "vu", "nu", "la", "be", "at", "ch",
        "li", "lu", "ie", "pt", "gr", "ro", "bg", "hr", "hu", "sk",
        "si", "lt", "lv", "ee", "is", "ua", "by", "md", "ge", "am",
        "az", "kz", "uz", "tm", "kg", "tj", "mn", "ir", "iq", "sa",
        "ae", "il", "tr", "cy",
    };
    return tlds;
}

// ============================================================================
// Known suspicious TLDs (heavily abused by malware)
// ============================================================================

static const std::unordered_set<std::string>& GetSuspiciousTLDs() noexcept {
    static const std::unordered_set<std::string> tlds = {
        "tk", "cf", "ga", "ml", "gq", "pw", "sx", "su", "cc",
        "top", "xyz", "club", "icu", "buzz", "cam", "monster",
        "rest", "fit", "beauty", "hair", "quest",
    };
    return tlds;
}

// ============================================================================
// Persistence-related registry key patterns
// ============================================================================

static bool IsPersistenceRegistryKey(const std::wstring& key) noexcept {
    // Case-insensitive check for persistence-related paths
    std::wstring lower;
    lower.reserve(key.size());
    for (wchar_t c : key) {
        lower.push_back(static_cast<wchar_t>(std::towlower(c)));
    }

    static const std::wstring_view kPersistencePatterns[] = {
        L"\\software\\microsoft\\windows\\currentversion\\run",
        L"\\software\\microsoft\\windows\\currentversion\\runonce",
        L"\\software\\microsoft\\windows\\currentversion\\runonceex",
        L"\\software\\microsoft\\windows\\currentversion\\runservices",
        L"\\software\\microsoft\\windows\\currentversion\\runservicesonce",
        L"\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
        L"\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
        L"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
        L"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
        L"\\software\\microsoft\\windows nt\\currentversion\\windows",
        L"\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
        L"\\software\\microsoft\\active setup\\installed components",
        L"\\system\\currentcontrolset\\services",
        L"\\system\\currentcontrolset\\control\\session manager",
        L"\\system\\currentcontrolset\\control\\lsa",
        L"\\software\\classes\\clsid",
        L"\\software\\classes\\directory\\shellex",
        L"\\software\\classes\\folder\\shellex",
        L"\\software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects",
        L"\\software\\microsoft\\internet explorer\\toolbar",
        L"\\software\\microsoft\\office",
        L"\\environment",
    };

    for (const auto& pattern : kPersistencePatterns) {
        if (lower.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Helper: convert wstring to UTF-8 string (basic)
// ============================================================================

static std::string WideToNarrow(const std::wstring& wide) noexcept {
    std::string result;
    result.reserve(wide.size());
    for (wchar_t c : wide) {
        if (c < 0x80) {
            result.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (c >> 6)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (c >> 12)));
            result.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return result;
}

// ============================================================================
// Helper: extract filename from path
// ============================================================================

static std::string ExtractFileName(const std::wstring& path) noexcept {
    auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return WideToNarrow(path);
    if (pos + 1 >= path.size()) return {};
    return WideToNarrow(path.substr(pos + 1));
}

// ============================================================================
// Helper: defang domain for display
// ============================================================================

static std::string DefangDomain(const std::string& domain) noexcept {
    std::string result;
    result.reserve(domain.size() + 4);
    for (size_t i = 0; i < domain.size(); ++i) {
        if (domain[i] == '.') {
            result += "[.]";
        } else {
            result.push_back(domain[i]);
        }
    }
    return result;
}

// ============================================================================
// Helper: defang URL for display
// ============================================================================

static std::string DefangURL(const std::string& url) noexcept {
    std::string result = url;
    // Replace http:// with hxxp://
    if (result.size() >= 7) {
        if (result.substr(0, 7) == "http://") {
            result = "hxxp://" + result.substr(7);
        } else if (result.size() >= 8 && result.substr(0, 8) == "https://") {
            result = "hxxps://" + result.substr(8);
        }
    }
    // Also defang the dots in the host portion
    size_t hostStart = result.find("://");
    if (hostStart != std::string::npos) {
        hostStart += 3;
        size_t hostEnd = result.find('/', hostStart);
        if (hostEnd == std::string::npos) hostEnd = result.size();
        std::string host = result.substr(hostStart, hostEnd - hostStart);
        std::string defangedHost = DefangDomain(host);
        result = result.substr(0, hostStart) + defangedHost + result.substr(hostEnd);
    }
    return result;
}

// ============================================================================
// Helper: defang IP for display
// ============================================================================

static std::string DefangIP(const std::string& ip) noexcept {
    return DefangDomain(ip); // Same dot-replacement logic
}

// ============================================================================
// IPv4 Parsing and Validation
// ============================================================================

struct IPv4Parts {
    uint8_t octets[4] = {};
};

[[nodiscard]] static bool ParseIPv4(const std::string& str, IPv4Parts& parts) noexcept {
    if (str.size() < 7 || str.size() > 15) return false; // "1.1.1.1" to "255.255.255.255"

    int octetIdx = 0;
    int currentVal = 0;
    int digitCount = 0;

    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];
        if (c >= '0' && c <= '9') {
            currentVal = currentVal * 10 + (c - '0');
            digitCount++;
            if (currentVal > 255 || digitCount > 3) return false;
        } else if (c == '.') {
            if (digitCount == 0 || octetIdx >= 3) return false;
            parts.octets[octetIdx++] = static_cast<uint8_t>(currentVal);
            currentVal = 0;
            digitCount = 0;
        } else {
            return false; // invalid character
        }
    }

    if (digitCount == 0 || octetIdx != 3) return false;
    parts.octets[3] = static_cast<uint8_t>(currentVal);

    return true;
}

[[nodiscard]] static bool IsValidIPv4(const std::string& ip) noexcept {
    IPv4Parts parts;
    if (!ParseIPv4(ip, parts)) return false;

    // Filter out special addresses
    if (parts.octets[0] == 0 && parts.octets[1] == 0 &&
        parts.octets[2] == 0 && parts.octets[3] == 0) return false; // 0.0.0.0
    if (parts.octets[0] == 255 && parts.octets[1] == 255 &&
        parts.octets[2] == 255 && parts.octets[3] == 255) return false; // broadcast

    return true;
}

[[nodiscard]] static bool IsPrivateIPv4(const IPv4Parts& parts) noexcept {
    // 10.0.0.0/8
    if (parts.octets[0] == 10) return true;
    // 172.16.0.0/12
    if (parts.octets[0] == 172 && parts.octets[1] >= 16 && parts.octets[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts.octets[0] == 192 && parts.octets[1] == 168) return true;
    return false;
}

[[nodiscard]] static bool IsReservedIPv4(const IPv4Parts& parts) noexcept {
    // Loopback 127.0.0.0/8
    if (parts.octets[0] == 127) return true;
    // Link-local 169.254.0.0/16
    if (parts.octets[0] == 169 && parts.octets[1] == 254) return true;
    // Documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (parts.octets[0] == 192 && parts.octets[1] == 0 && parts.octets[2] == 2) return true;
    if (parts.octets[0] == 198 && parts.octets[1] == 51 && parts.octets[2] == 100) return true;
    if (parts.octets[0] == 203 && parts.octets[1] == 0 && parts.octets[2] == 113) return true;
    // Multicast 224.0.0.0/4
    if (parts.octets[0] >= 224 && parts.octets[0] <= 239) return true;
    // Reserved 240.0.0.0/4
    if (parts.octets[0] >= 240) return true;
    // Private ranges are also "reserved" in a general sense
    if (IsPrivateIPv4(parts)) return true;
    return false;
}

// ============================================================================
// IPv6 Parsing (basic validation — checks format, not full RFC compliance)
// ============================================================================

[[nodiscard]] static bool LooksLikeIPv6(const std::string& str) noexcept {
    if (str.size() < 2 || str.size() > 45) return false;

    int colonCount = 0;
    int groupCount = 0;
    int hexDigits = 0;
    bool hasDoubleColon = false;

    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            hexDigits++;
            if (hexDigits > 4) return false;
        } else if (c == ':') {
            if (hexDigits > 0) groupCount++;
            hexDigits = 0;
            colonCount++;
            if (i + 1 < str.size() && str[i + 1] == ':') {
                if (hasDoubleColon) return false; // only one :: allowed
                hasDoubleColon = true;
            }
        } else {
            return false;
        }
    }

    if (hexDigits > 0) groupCount++;

    // Valid IPv6: up to 8 groups, or fewer with ::
    if (hasDoubleColon) {
        return groupCount <= 8 && colonCount >= 2;
    }
    return groupCount == 8 && colonCount == 7;
}

// ============================================================================
// Domain Validation
// ============================================================================

[[nodiscard]] static bool IsValidDomainChar(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.';
}

[[nodiscard]] static bool IsValidDomain(const std::string& domain) noexcept {
    if (domain.empty() || domain.size() > 253) return false;

    // Must contain at least one dot
    if (domain.find('.') == std::string::npos) return false;

    // Must not start or end with dot or hyphen
    if (domain.front() == '.' || domain.back() == '.' ||
        domain.front() == '-' || domain.back() == '-') return false;

    // Validate characters
    for (char c : domain) {
        if (!IsValidDomainChar(c)) return false;
    }

    // No consecutive dots
    if (domain.find("..") != std::string::npos) return false;

    // Extract TLD
    auto lastDot = domain.rfind('.');
    if (lastDot == std::string::npos || lastDot + 1 >= domain.size()) return false;

    std::string tld = domain.substr(lastDot + 1);
    // Convert to lowercase
    for (auto& ch : tld) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

    // TLD must be alphabetic
    for (char c : tld) {
        if (c < 'a' || c > 'z') return false;
    }

    // TLD length: 2–24 characters
    if (tld.size() < 2 || tld.size() > 24) return false;

    return true;
}

// ============================================================================
// URL Extraction from string
// ============================================================================

struct ParsedURL {
    std::string scheme;
    std::string host;
    uint16_t    port = 0;
    std::string path;
    std::string query;
};

[[nodiscard]] static bool ParseURL(const std::string& url, ParsedURL& parsed) noexcept {
    if (url.size() < 10 || url.size() > kMaxStringLength) return false;

    size_t pos = 0;

    // Scheme
    if (url.substr(0, 8) == "https://") {
        parsed.scheme = "https";
        parsed.port = 443;
        pos = 8;
    } else if (url.substr(0, 7) == "http://") {
        parsed.scheme = "http";
        parsed.port = 80;
        pos = 7;
    } else if (url.substr(0, 6) == "ftp://") {
        parsed.scheme = "ftp";
        parsed.port = 21;
        pos = 6;
    } else {
        return false;
    }

    // Host (up to ':', '/', '?', or end)
    size_t hostStart = pos;
    while (pos < url.size() && url[pos] != ':' && url[pos] != '/' && url[pos] != '?') {
        pos++;
    }
    parsed.host = url.substr(hostStart, pos - hostStart);
    if (parsed.host.empty()) return false;

    // Optional port
    if (pos < url.size() && url[pos] == ':') {
        pos++;
        size_t portStart = pos;
        while (pos < url.size() && url[pos] >= '0' && url[pos] <= '9') {
            pos++;
        }
        if (pos > portStart) {
            int portVal = 0;
            for (size_t i = portStart; i < pos; ++i) {
                portVal = portVal * 10 + (url[i] - '0');
                if (portVal > 65535) return false;
            }
            parsed.port = static_cast<uint16_t>(portVal);
        }
    }

    // Path
    if (pos < url.size() && url[pos] == '/') {
        size_t pathStart = pos;
        while (pos < url.size() && url[pos] != '?' && url[pos] != ' ' &&
               url[pos] != '\t' && url[pos] != '\n' && url[pos] != '\r') {
            pos++;
        }
        parsed.path = url.substr(pathStart, pos - pathStart);
    }

    // Query
    if (pos < url.size() && url[pos] == '?') {
        pos++;
        size_t queryStart = pos;
        while (pos < url.size() && url[pos] != ' ' &&
               url[pos] != '\t' && url[pos] != '\n') {
            pos++;
        }
        parsed.query = url.substr(queryStart, pos - queryStart);
    }

    return true;
}

// ============================================================================
// Base64 Detection and Decoding
// ============================================================================

static constexpr uint8_t kBase64Invalid = 0xFF;

static constexpr uint8_t kBase64DecodeTable[256] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 62 ,0xFF,0xFF,0xFF, 63 ,
      52,  53,  54,  55,  56,  57,  58,  59,  60,  61,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
      15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
      41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

[[nodiscard]] static bool IsBase64Char(char c) noexcept {
    return kBase64DecodeTable[static_cast<uint8_t>(c)] != kBase64Invalid || c == '=';
}

[[nodiscard]] static bool LooksLikeBase64(const std::string& str) noexcept {
    if (str.size() < 8) return false;
    if (str.size() % 4 != 0) return false;

    size_t padCount = 0;
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '=') {
            padCount++;
            if (padCount > 2) return false;
            // Padding must only appear at end
            for (size_t j = i + 1; j < str.size(); ++j) {
                if (str[j] != '=') return false;
            }
            break;
        }
        if (!IsBase64Char(str[i])) return false;
    }

    return true;
}

[[nodiscard]] static std::string DecodeBase64(const std::string& input) noexcept {
    if (input.empty() || input.size() % 4 != 0) return {};
    if (input.size() > kMaxBase64DecodeLen) return {};

    std::string output;
    output.reserve((input.size() / 4) * 3);

    for (size_t i = 0; i < input.size(); i += 4) {
        uint8_t a = kBase64DecodeTable[static_cast<uint8_t>(input[i])];
        uint8_t b = kBase64DecodeTable[static_cast<uint8_t>(input[i + 1])];
        uint8_t c = (input[i + 2] != '=') ?
                    kBase64DecodeTable[static_cast<uint8_t>(input[i + 2])] : 0;
        uint8_t d = (input[i + 3] != '=') ?
                    kBase64DecodeTable[static_cast<uint8_t>(input[i + 3])] : 0;

        if (a == kBase64Invalid || b == kBase64Invalid) break;

        output.push_back(static_cast<char>((a << 2) | (b >> 4)));
        if (input[i + 2] != '=') {
            if (c == kBase64Invalid) break;
            output.push_back(static_cast<char>(((b & 0x0F) << 4) | (c >> 2)));
        }
        if (input[i + 3] != '=') {
            if (d == kBase64Invalid) break;
            output.push_back(static_cast<char>(((c & 0x03) << 6) | d));
        }
    }

    return output;
}

// ============================================================================
// Shannon Entropy Calculation
// ============================================================================

[[nodiscard]] static float CalculateEntropy(const std::string& str) noexcept {
    if (str.empty()) return 0.0f;

    std::array<uint32_t, 256> freq{};
    for (char c : str) {
        freq[static_cast<uint8_t>(c)]++;
    }

    float entropy = 0.0f;
    float len = static_cast<float>(str.size());

    for (uint32_t f : freq) {
        if (f > 0) {
            float p = static_cast<float>(f) / len;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

// ============================================================================
// System path filtering — filter benign system paths
// ============================================================================

static bool IsCommonSystemPath(const std::wstring& path) noexcept {
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) {
        lower.push_back(static_cast<wchar_t>(std::towlower(c)));
    }

    // Allow-listed system directories (reads from these are normal)
    static const std::wstring_view kBenignPrefixes[] = {
        L"c:\\windows\\system32\\",
        L"c:\\windows\\syswow64\\",
        L"c:\\windows\\winsxs\\",
        L"c:\\windows\\assembly\\",
        L"c:\\windows\\microsoft.net\\",
        L"c:\\windows\\fonts\\",
        L"c:\\windows\\globalization\\",
        L"c:\\windows\\inf\\",
        L"c:\\windows\\help\\",
    };

    // Only filter reads of system DLLs — writing to system paths is suspicious
    for (const auto& prefix : kBenignPrefixes) {
        if (lower.starts_with(prefix)) {
            // Check if it's a common DLL
            if (lower.ends_with(L".dll") || lower.ends_with(L".sys") ||
                lower.ends_with(L".drv") || lower.ends_with(L".mui") ||
                lower.ends_with(L".nls")) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// IOCExtractor::Impl
// ============================================================================

struct IOCExtractor::Impl {
    const EmulationConfig& config;
    mutable std::shared_mutex mutex;

    std::vector<IOCEntry> iocs;

    // Deduplication maps (value → index in iocs vector)
    std::unordered_map<std::string, size_t> domainIndex;
    std::unordered_map<std::string, size_t> ipIndex;
    std::unordered_map<std::string, size_t> urlIndex;
    std::unordered_map<std::string, size_t> filePathIndex;
    std::unordered_map<std::string, size_t> registryKeyIndex;
    std::unordered_map<std::string, size_t> mutexIndex;
    std::unordered_map<std::string, size_t> serviceIndex;
    std::unordered_map<std::string, size_t> pipeIndex;
    std::unordered_map<std::string, size_t> uaIndex;
    std::unordered_map<std::string, size_t> cmdLineIndex;

    uint32_t callIndex = 0;  // monotonic counter for firstSeen/lastSeen

    explicit Impl(const EmulationConfig& cfg) noexcept
        : config(cfg)
    {
        iocs.reserve(512);
        domainIndex.reserve(256);
        ipIndex.reserve(256);
        urlIndex.reserve(256);
        filePathIndex.reserve(256);
        registryKeyIndex.reserve(128);
        mutexIndex.reserve(64);
    }

    // Add or update an IOC entry with deduplication
    void AddIOC(IOCType type, const std::string& value,
                const std::string& context, float confidence,
                std::unordered_map<std::string, size_t>& index,
                uint32_t maxTracked) noexcept
    {
        if (value.empty() || value.size() > kMaxStringLength) return;
        if (iocs.size() >= kMaxIOCEntries) return;

        auto it = index.find(value);
        if (it != index.end()) {
            // Update existing entry
            auto& entry = iocs[it->second];
            entry.occurrences++;
            entry.lastSeen = callIndex;
            if (confidence > entry.confidence) {
                entry.confidence = confidence;
            }
            return;
        }

        if (index.size() >= maxTracked) return;

        IOCEntry entry;
        entry.type        = type;
        entry.value       = value;
        entry.context     = context;
        entry.confidence  = std::clamp(confidence, 0.0f, 1.0f);
        entry.firstSeen   = callIndex;
        entry.lastSeen    = callIndex;
        entry.occurrences = 1;
        entry.isDefanged  = false;

        size_t idx = iocs.size();
        iocs.push_back(std::move(entry));
        index[value] = idx;
    }

    void AddDomain(const std::string& domain, const std::string& context,
                   float confidence) noexcept {
        std::string lower;
        lower.reserve(domain.size());
        for (char c : domain) {
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (!IsValidDomain(lower)) return;
        AddIOC(IOCType::Domain, lower, context, confidence,
               domainIndex, kMaxDomainsTracked);
    }

    void AddIPv4(const std::string& ip, const std::string& context,
                 float confidence) noexcept {
        if (!IsValidIPv4(ip)) return;
        AddIOC(IOCType::IPv4, ip, context, confidence,
               ipIndex, kMaxIPsTracked);
    }

    void AddIPv6(const std::string& ip, const std::string& context,
                 float confidence) noexcept {
        if (!LooksLikeIPv6(ip)) return;
        AddIOC(IOCType::IPv6, ip, context, confidence,
               ipIndex, kMaxIPsTracked);
    }

    void AddURL(const std::string& url, const std::string& context,
                float confidence) noexcept {
        ParsedURL parsed;
        if (!ParseURL(url, parsed)) return;
        AddIOC(IOCType::URL, url, context, confidence,
               urlIndex, kMaxURLsTracked);
        // Also extract domain from URL
        AddDomain(parsed.host, "Extracted from URL: " + url, confidence * 0.9f);
    }

    void AddFilePath(const std::string& path, const std::string& context,
                     float confidence) noexcept {
        AddIOC(IOCType::FilePath, path, context, confidence,
               filePathIndex, kMaxFilesTracked);
    }

    void AddFileName(const std::string& name, const std::string& context,
                     float confidence) noexcept {
        if (name.empty()) return;
        // Reuse filePathIndex for dedup (file names are tracked alongside paths)
        AddIOC(IOCType::FileName, name, context, confidence,
               filePathIndex, kMaxFilesTracked);
    }

    void AddRegistryKey(const std::string& key, const std::string& context,
                        float confidence) noexcept {
        AddIOC(IOCType::RegistryKey, key, context, confidence,
               registryKeyIndex, kMaxRegistryTracked);
    }

    void AddRegistryValue(const std::string& value, const std::string& context,
                          float confidence) noexcept {
        AddIOC(IOCType::RegistryValue, value, context, confidence,
               registryKeyIndex, kMaxRegistryTracked);
    }

    void AddMutex(const std::string& name, const std::string& context,
                  float confidence) noexcept {
        AddIOC(IOCType::MutexName, name, context, confidence,
               mutexIndex, kMaxMutexesTracked);
    }

    void AddService(const std::string& name, const std::string& context,
                    float confidence) noexcept {
        AddIOC(IOCType::ServiceName, name, context, confidence,
               serviceIndex, kMaxServicesTracked);
    }

    void AddPipe(const std::string& name, const std::string& context,
                 float confidence) noexcept {
        AddIOC(IOCType::PipeName, name, context, confidence,
               pipeIndex, kMaxPipesTracked);
    }

    void AddUserAgent(const std::string& ua, const std::string& context,
                      float confidence) noexcept {
        AddIOC(IOCType::UserAgent, ua, context, confidence,
               uaIndex, kMaxUserAgentsTracked);
    }

    void AddCommandLine(const std::string& cmdline, const std::string& context,
                        float confidence) noexcept {
        AddIOC(IOCType::CommandLine, cmdline, context, confidence,
               cmdLineIndex, kMaxCmdLinesTracked);
    }

    // Extract IOCs from a raw string found in memory or arguments
    void ExtractFromString(const std::string& str, const std::string& context) noexcept {
        if (str.size() < 4 || str.size() > kMaxStringLength) return;

        // Check for URLs
        for (size_t i = 0; i + 10 < str.size(); ++i) {
            if ((str.substr(i, 7) == "http://" || str.substr(i, 8) == "https://") ||
                str.substr(i, 6) == "ftp://") {
                // Find URL end (whitespace or null)
                size_t end = i;
                while (end < str.size() && str[end] != ' ' && str[end] != '\t' &&
                       str[end] != '\n' && str[end] != '\r' && str[end] != '\0' &&
                       str[end] != '"' && str[end] != '\'' && str[end] != '>') {
                    end++;
                }
                if (end > i + 8) {
                    AddURL(str.substr(i, end - i), context, 0.7f);
                }
                i = end;
            }
        }

        // Check for IPv4 addresses
        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] >= '0' && str[i] <= '9') {
                // Try to parse IPv4 starting here
                size_t end = i;
                while (end < str.size() && (str[end] == '.' ||
                       (str[end] >= '0' && str[end] <= '9'))) {
                    end++;
                }
                if (end - i >= 7 && end - i <= 15) {
                    std::string candidate = str.substr(i, end - i);
                    IPv4Parts parts;
                    if (ParseIPv4(candidate, parts) && IsValidIPv4(candidate)) {
                        AddIPv4(candidate, context, 0.6f);
                    }
                }
                i = end;
            }
        }

        // Check for domain-like strings
        if (IsValidDomain(str)) {
            AddDomain(str, context, 0.5f);
        }

        // Check for email addresses (simple pattern: xxx@domain.tld)
        auto atPos = str.find('@');
        if (atPos != std::string::npos && atPos > 0 && atPos + 3 < str.size()) {
            std::string afterAt = str.substr(atPos + 1);
            if (IsValidDomain(afterAt)) {
                // Validate local part (basic: alphanumeric + . _ -)
                bool validLocal = true;
                for (size_t i = 0; i < atPos; ++i) {
                    char c = str[i];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
                        validLocal = false;
                        break;
                    }
                }
                if (validLocal) {
                    AddIOC(IOCType::EmailAddress, str, context, 0.6f,
                           domainIndex, kMaxDomainsTracked);
                }
            }
        }

        // Check for Base64-encoded content
        if (LooksLikeBase64(str) && str.size() >= 16) {
            std::string decoded = DecodeBase64(str);
            if (!decoded.empty() && decoded.size() >= 4) {
                // Re-check decoded content for IOCs
                bool hasPrintable = true;
                for (char c : decoded) {
                    if (static_cast<unsigned char>(c) < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                        hasPrintable = false;
                        break;
                    }
                }
                if (hasPrintable) {
                    ExtractFromString(decoded, "Base64-decoded from: " + context);
                }
            }
        }
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

IOCExtractor::IOCExtractor(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(config))
{
}

IOCExtractor::~IOCExtractor() noexcept = default;

// ============================================================================
// OnAPICall — extract IOCs from API call arguments
// ============================================================================

void IOCExtractor::OnAPICall(const APICallDetail& call) noexcept {
    if (!call.funcName) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string_view func(call.funcName);

    // === Network APIs — extract hosts/IPs ===
    if (func == "InternetConnectA" || func == "InternetConnectW" ||
        func == "WinHttpConnect") {
        // arg[1] = server name
        if (call.args[1] != 0) {
            // We can't read the string directly here (no memory access),
            // but the caller should use OnNetworkConnect/OnDnsQuery for actual string extraction.
            // This method tracks the API call pattern.
        }
    }

    if (func == "InternetOpenUrlA" || func == "InternetOpenUrlW") {
        // arg[1] = URL — tracked via specific event methods
    }

    if (func == "URLDownloadToFileA" || func == "URLDownloadToFileW") {
        // arg[1] = URL, arg[2] = local file path
    }

    // === File APIs ===
    if (func == "CreateFileA" || func == "CreateFileW" ||
        func == "DeleteFileA" || func == "DeleteFileW" ||
        func == "MoveFileA" || func == "MoveFileW" ||
        func == "CopyFileA" || func == "CopyFileW") {
        // File path extraction is handled via OnFileAccess
    }

    // === Registry APIs ===
    if (func == "RegOpenKeyExA" || func == "RegOpenKeyExW" ||
        func == "RegCreateKeyExA" || func == "RegCreateKeyExW" ||
        func == "RegSetValueExA" || func == "RegSetValueExW" ||
        func == "RegDeleteKeyA" || func == "RegDeleteKeyW") {
        // Registry extraction is handled via OnRegistryAccess
    }

    // === Mutex APIs ===
    if (func == "CreateMutexA" || func == "CreateMutexW" ||
        func == "OpenMutexA" || func == "OpenMutexW") {
        // Mutex extraction handled via OnMutexCreate
    }

    // === Service APIs ===
    if (func == "CreateServiceA" || func == "CreateServiceW") {
        // Service extraction handled via OnServiceCreate
    }

    // === Process APIs ===
    if (func == "CreateProcessA" || func == "CreateProcessW" ||
        func == "WinExec" || func == "ShellExecuteA" || func == "ShellExecuteW") {
        // Command line extraction handled via OnProcessCreate
    }

    // === DNS APIs ===
    if (func == "DnsQuery_A" || func == "DnsQuery_W" ||
        func == "getaddrinfo" || func == "GetAddrInfoW") {
        // DNS extraction handled via OnDnsQuery
    }
}

// ============================================================================
// OnMemoryScan — scan raw memory for embedded IOCs
// ============================================================================

void IOCExtractor::OnMemoryScan(const uint8_t* data, size_t size,
                                GuestAddress base) noexcept {
    if (!data || size == 0) return;
    if (!m_impl->config.enableIOCExtraction) return;

    // Cap scan size to prevent excessive processing
    size_t scanSize = std::min(size, kMaxMemoryScanSize);

    std::unique_lock lock(m_impl->mutex);

    std::string context = "Memory scan at 0x" +
        ([base]() -> std::string {
            char buf[20];
            std::snprintf(buf, sizeof(buf), "%016llX",
                          static_cast<unsigned long long>(base));
            return std::string(buf);
        })();

    // Extract ASCII strings
    std::string currentStr;
    currentStr.reserve(256);

    for (size_t i = 0; i < scanSize; ++i) {
        uint8_t byte = data[i];
        if (byte >= 0x20 && byte < 0x7F) {
            currentStr.push_back(static_cast<char>(byte));
            if (currentStr.size() > kMaxStringLength) {
                currentStr.clear(); // Too long, not a real string
            }
        } else {
            if (currentStr.size() >= kMinASCIIStringLen) {
                m_impl->ExtractFromString(currentStr, context);
            }
            currentStr.clear();
        }
    }
    if (currentStr.size() >= kMinASCIIStringLen) {
        m_impl->ExtractFromString(currentStr, context);
    }

    // Extract UTF-16LE strings
    std::string utf16Str;
    utf16Str.reserve(256);

    for (size_t i = 0; i + 1 < scanSize; i += 2) {
        uint16_t wchar = static_cast<uint16_t>(data[i]) |
                         (static_cast<uint16_t>(data[i + 1]) << 8);
        if (wchar >= 0x20 && wchar < 0x7F) {
            utf16Str.push_back(static_cast<char>(wchar));
            if (utf16Str.size() > kMaxStringLength) {
                utf16Str.clear();
            }
        } else {
            if (utf16Str.size() >= kMinUTF16StringLen) {
                m_impl->ExtractFromString(utf16Str,
                    "UTF-16 string from " + context);
            }
            utf16Str.clear();
        }
    }
    if (utf16Str.size() >= kMinUTF16StringLen) {
        m_impl->ExtractFromString(utf16Str, "UTF-16 string from " + context);
    }
}

// ============================================================================
// OnStringFound — process a string already extracted from memory
// ============================================================================

void IOCExtractor::OnStringFound(const std::string& str, GuestAddress addr) noexcept {
    if (str.empty() || str.size() > kMaxStringLength) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string context = "String at 0x" +
        ([addr]() -> std::string {
            char buf[20];
            std::snprintf(buf, sizeof(buf), "%016llX",
                          static_cast<unsigned long long>(addr));
            return std::string(buf);
        })();

    m_impl->ExtractFromString(str, context);
}

// ============================================================================
// OnNetworkConnect
// ============================================================================

void IOCExtractor::OnNetworkConnect(const std::string& addr, uint16_t port) noexcept {
    if (addr.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string context = "Network connection to port " + std::to_string(port);

    // Check if it's an IP address
    IPv4Parts parts;
    if (ParseIPv4(addr, parts)) {
        if (IsValidIPv4(addr)) {
            m_impl->AddIPv4(addr, context, 0.85f);
        }
    } else if (LooksLikeIPv6(addr)) {
        m_impl->AddIPv6(addr, context, 0.85f);
    } else {
        // Assume domain
        m_impl->AddDomain(addr, context, 0.85f);
    }
}

// ============================================================================
// OnDnsQuery
// ============================================================================

void IOCExtractor::OnDnsQuery(const std::string& domain) noexcept {
    if (domain.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    m_impl->AddDomain(domain, "DNS query", 0.90f);
}

// ============================================================================
// OnFileAccess
// ============================================================================

void IOCExtractor::OnFileAccess(const std::wstring& path, bool isCreate) noexcept {
    if (path.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    // Filter benign system path reads (but always track creates/writes)
    if (!isCreate && IsCommonSystemPath(path)) return;

    std::string narrowPath = WideToNarrow(path);
    float confidence = isCreate ? 0.80f : 0.50f;
    std::string context = isCreate ? "File created" : "File accessed";

    m_impl->AddFilePath(narrowPath, context, confidence);

    // Extract file name
    std::string fileName = ExtractFileName(path);
    if (!fileName.empty()) {
        m_impl->AddFileName(fileName, context, confidence * 0.8f);
    }
}

// ============================================================================
// OnRegistryAccess
// ============================================================================

void IOCExtractor::OnRegistryAccess(const std::wstring& key,
                                    const std::wstring& value) noexcept {
    if (key.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    bool isPersistence = IsPersistenceRegistryKey(key);
    float confidence = isPersistence ? 0.85f : 0.50f;
    std::string context = isPersistence ? "Persistence-related registry key" : "Registry access";

    std::string narrowKey = WideToNarrow(key);
    m_impl->AddRegistryKey(narrowKey, context, confidence);

    if (!value.empty()) {
        std::string narrowValue = WideToNarrow(value);
        m_impl->AddRegistryValue(narrowValue,
            "Registry value in " + narrowKey, confidence * 0.9f);
    }
}

// ============================================================================
// OnMutexCreate
// ============================================================================

void IOCExtractor::OnMutexCreate(const std::wstring& name) noexcept {
    if (name.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string narrowName = WideToNarrow(name);

    // Assess suspiciousness of mutex name
    float confidence = 0.60f;

    // GUID-like pattern: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    if (narrowName.size() == 38 && narrowName.front() == '{' && narrowName.back() == '}') {
        confidence = 0.70f;
    }

    // Long hex string (common in malware)
    bool allHex = true;
    if (narrowName.size() >= 16) {
        for (char c : narrowName) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) {
                allHex = false;
                break;
            }
        }
        if (allHex) confidence = 0.75f;
    }

    // High entropy name (randomized)
    float entropy = CalculateEntropy(narrowName);
    if (entropy > 4.0f && narrowName.size() > 8) {
        confidence = std::max(confidence, 0.75f);
    }

    m_impl->AddMutex(narrowName, "CreateMutex", confidence);
}

// ============================================================================
// OnServiceCreate
// ============================================================================

void IOCExtractor::OnServiceCreate(const std::wstring& name) noexcept {
    if (name.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string narrowName = WideToNarrow(name);
    m_impl->AddService(narrowName, "CreateService", 0.80f);
}

// ============================================================================
// OnProcessCreate
// ============================================================================

void IOCExtractor::OnProcessCreate(const std::wstring& cmdline) noexcept {
    if (cmdline.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    std::string narrow = WideToNarrow(cmdline);

    // Track the full command line
    m_impl->AddCommandLine(narrow, "CreateProcess", 0.80f);

    // Extract IOCs from command line content
    m_impl->ExtractFromString(narrow, "Process command line");
}

// ============================================================================
// OnPipeCreate
// ============================================================================

void IOCExtractor::OnPipeCreate(const std::string& name) noexcept {
    if (name.empty()) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    m_impl->AddPipe(name, "Named pipe created", 0.70f);
}

// ============================================================================
// OnUserAgent
// ============================================================================

void IOCExtractor::OnUserAgent(const std::string& ua) noexcept {
    if (ua.empty() || ua.size() > kMaxStringLength) return;
    if (!m_impl->config.enableIOCExtraction) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->callIndex++;

    m_impl->AddUserAgent(ua, "HTTP User-Agent header", 0.75f);
}

// ============================================================================
// GenerateReport
// ============================================================================

IOCReport IOCExtractor::GenerateReport() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    IOCReport report;

    // Create defanged copies
    report.indicators.reserve(m_impl->iocs.size());
    for (const auto& ioc : m_impl->iocs) {
        IOCEntry entry = ioc;

        // Defang display values
        switch (entry.type) {
            case IOCType::Domain:
                entry.value = DefangDomain(ioc.value);
                entry.isDefanged = true;
                break;
            case IOCType::IPv4:
            case IOCType::IPv6:
                entry.value = DefangIP(ioc.value);
                entry.isDefanged = true;
                break;
            case IOCType::URL:
                entry.value = DefangURL(ioc.value);
                entry.isDefanged = true;
                break;
            default:
                break;
        }

        report.indicators.push_back(std::move(entry));
    }

    // Count by type
    for (const auto& ioc : m_impl->iocs) {
        switch (ioc.type) {
            case IOCType::Domain:
            case IOCType::EmailAddress:
                report.totalDomains++;
                break;
            case IOCType::IPv4:
            case IOCType::IPv6:
                report.totalIPs++;
                break;
            case IOCType::URL:
                report.totalURLs++;
                break;
            case IOCType::FilePath:
            case IOCType::FileName:
            case IOCType::FileHashMD5:
            case IOCType::FileHashSHA1:
            case IOCType::FileHashSHA256:
                report.totalFiles++;
                break;
            case IOCType::RegistryKey:
            case IOCType::RegistryValue:
                report.totalRegistry++;
                break;
            case IOCType::MutexName:
                report.totalMutexes++;
                break;
            default:
                break;
        }
    }

    // Build summary
    std::ostringstream ss;
    ss << "IOC Report: " << m_impl->iocs.size() << " indicator(s) extracted. ";
    if (report.totalDomains > 0)
        ss << report.totalDomains << " domain(s), ";
    if (report.totalIPs > 0)
        ss << report.totalIPs << " IP address(es), ";
    if (report.totalURLs > 0)
        ss << report.totalURLs << " URL(s), ";
    if (report.totalFiles > 0)
        ss << report.totalFiles << " file indicator(s), ";
    if (report.totalRegistry > 0)
        ss << report.totalRegistry << " registry indicator(s), ";
    if (report.totalMutexes > 0)
        ss << report.totalMutexes << " mutex(es)";

    report.summary = ss.str();
    // Remove trailing comma-space if present
    if (report.summary.size() >= 2 &&
        report.summary.back() == ' ' &&
        report.summary[report.summary.size() - 2] == ',') {
        report.summary.pop_back();
        report.summary.pop_back();
    }

    return report;
}

// ============================================================================
// GetAllIOCs
// ============================================================================

const std::vector<IOCEntry>& IOCExtractor::GetAllIOCs() const noexcept {
    return m_impl->iocs;
}

// ============================================================================
// GetByType
// ============================================================================

std::vector<const IOCEntry*> IOCExtractor::GetByType(IOCType type) const noexcept {
    std::shared_lock lock(m_impl->mutex);

    std::vector<const IOCEntry*> result;
    for (const auto& ioc : m_impl->iocs) {
        if (ioc.type == type) {
            result.push_back(&ioc);
        }
    }
    return result;
}

// ============================================================================
// GetTotalIOCCount
// ============================================================================

uint32_t IOCExtractor::GetTotalIOCCount() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->iocs.size());
}

// ============================================================================
// IsSuspiciousDomain
// ============================================================================

bool IOCExtractor::IsSuspiciousDomain(const std::string& domain) const noexcept {
    if (!IsValidDomain(domain)) return false;

    // Check for DGA characteristics
    if (IsDGA(domain)) return true;

    // Check for suspicious TLD
    auto lastDot = domain.rfind('.');
    if (lastDot != std::string::npos && lastDot + 1 < domain.size()) {
        std::string tld = domain.substr(lastDot + 1);
        for (auto& c : tld) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (GetSuspiciousTLDs().count(tld) > 0) return true;
    }

    // Check for IP-like subdomains
    auto firstDot = domain.find('.');
    if (firstDot != std::string::npos) {
        std::string firstLabel = domain.substr(0, firstDot);
        bool allDigitsOrDots = true;
        for (char c : firstLabel) {
            if (c < '0' || c > '9') {
                allDigitsOrDots = false;
                break;
            }
        }
        if (allDigitsOrDots && firstLabel.size() >= 3) return true;
    }

    // Very long subdomain labels are suspicious
    size_t maxLabelLen = 0;
    size_t currentLabelLen = 0;
    for (char c : domain) {
        if (c == '.') {
            maxLabelLen = std::max(maxLabelLen, currentLabelLen);
            currentLabelLen = 0;
        } else {
            currentLabelLen++;
        }
    }
    maxLabelLen = std::max(maxLabelLen, currentLabelLen);
    if (maxLabelLen > 30) return true;

    // Many subdomains (> 4 levels) are suspicious
    uint32_t dotCount = 0;
    for (char c : domain) {
        if (c == '.') dotCount++;
    }
    if (dotCount > 4) return true;

    return false;
}

// ============================================================================
// CalculateDomainEntropy
// ============================================================================

float IOCExtractor::CalculateDomainEntropy(const std::string& domain) const noexcept {
    if (domain.empty()) return 0.0f;

    // Calculate entropy of the main label (excluding TLD)
    auto lastDot = domain.rfind('.');
    if (lastDot == std::string::npos) return CalculateEntropy(domain);

    std::string label = domain.substr(0, lastDot);

    // If there are subdomains, use the second-level label
    auto secondDot = label.rfind('.');
    if (secondDot != std::string::npos) {
        label = label.substr(secondDot + 1);
    }

    return CalculateEntropy(label);
}

// ============================================================================
// IsDGA — Domain Generation Algorithm detection
// ============================================================================

bool IOCExtractor::IsDGA(const std::string& domain) const noexcept {
    if (!IsValidDomain(domain)) return false;

    // Extract the registrable domain label (second-level domain)
    auto lastDot = domain.rfind('.');
    if (lastDot == std::string::npos) return false;

    std::string label = domain.substr(0, lastDot);
    auto secondDot = label.rfind('.');
    if (secondDot != std::string::npos) {
        label = label.substr(secondDot + 1);
    }

    // Convert to lowercase for analysis
    for (auto& c : label) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Too short to be DGA
    if (label.size() < kDGAMinLabelLen) return false;

    // === Entropy check ===
    float entropy = CalculateEntropy(label);
    if (entropy > kDGAEntropyThreshold) return true;

    // === Consonant-to-vowel ratio check ===
    uint32_t consonants = 0;
    uint32_t vowels = 0;
    uint32_t digits = 0;
    uint32_t hyphens = 0;

    for (char c : label) {
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowels++;
        } else if (c >= 'a' && c <= 'z') {
            consonants++;
        } else if (c >= '0' && c <= '9') {
            digits++;
        } else if (c == '-') {
            hyphens++;
        }
    }

    // Very high consonant-to-vowel ratio
    if (vowels > 0 && static_cast<float>(consonants) / static_cast<float>(vowels) > kDGAConsonantRatio) {
        return true;
    }
    // No vowels and significant consonants
    if (vowels == 0 && consonants > 4) return true;

    // === Digit density check ===
    if (label.size() > kDGAMinLabelLen &&
        static_cast<float>(digits) / static_cast<float>(label.size()) > kDGADigitRatio) {
        return true;
    }

    // === Consecutive consonants check ===
    uint32_t maxConsecConsonants = 0;
    uint32_t currentConsec = 0;
    for (char c : label) {
        if (c >= 'a' && c <= 'z' &&
            c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u') {
            currentConsec++;
            maxConsecConsonants = std::max(maxConsecConsonants, currentConsec);
        } else {
            currentConsec = 0;
        }
    }
    if (maxConsecConsonants >= 5) return true;

    // === Bigram analysis — check for rare letter combinations ===
    uint32_t rareBigrams = 0;
    static const std::unordered_set<std::string>& commonBigrams = []() -> const std::unordered_set<std::string>& {
        static const std::unordered_set<std::string> bigrams = {
            "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
            "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
            "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
            "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
            "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
            "ca", "el", "ta", "la", "ns", "ge", "ly", "ei", "ow", "ad",
            "di", "lo", "us", "pe", "ec", "no", "ol", "tr", "oo", "ct",
            "ss", "pr", "un", "wa", "so", "em", "wi", "op", "su", "ie",
        };
        return bigrams;
    }();

    if (label.size() >= 4) {
        uint32_t bigramTotal = 0;
        for (size_t i = 0; i + 1 < label.size(); ++i) {
            if (label[i] >= 'a' && label[i] <= 'z' &&
                label[i + 1] >= 'a' && label[i + 1] <= 'z') {
                bigramTotal++;
                std::string bg = label.substr(i, 2);
                if (commonBigrams.find(bg) == commonBigrams.end()) {
                    rareBigrams++;
                }
            }
        }

        if (bigramTotal > 0 &&
            static_cast<float>(rareBigrams) / static_cast<float>(bigramTotal) > 0.6f) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// IsPrivateIP
// ============================================================================

bool IOCExtractor::IsPrivateIP(const std::string& ip) const noexcept {
    IPv4Parts parts;
    if (!ParseIPv4(ip, parts)) return false;
    return IsPrivateIPv4(parts);
}

// ============================================================================
// IsReservedIP
// ============================================================================

bool IOCExtractor::IsReservedIP(const std::string& ip) const noexcept {
    IPv4Parts parts;
    if (!ParseIPv4(ip, parts)) return false;
    return IsReservedIPv4(parts);
}

// ============================================================================
// ScanForIOCsInBuffer — public API for on-demand string scanning
// ============================================================================

void IOCExtractor::ScanForIOCsInBuffer(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) return;
    if (!m_impl->config.enableIOCExtraction) return;

    OnMemoryScan(data, size, 0);
}

// ============================================================================
// Reset
// ============================================================================

void IOCExtractor::Reset() noexcept {
    std::unique_lock lock(m_impl->mutex);

    m_impl->iocs.clear();
    m_impl->domainIndex.clear();
    m_impl->ipIndex.clear();
    m_impl->urlIndex.clear();
    m_impl->filePathIndex.clear();
    m_impl->registryKeyIndex.clear();
    m_impl->mutexIndex.clear();
    m_impl->serviceIndex.clear();
    m_impl->pipeIndex.clear();
    m_impl->uaIndex.clear();
    m_impl->cmdLineIndex.clear();
    m_impl->callIndex = 0;
}

} // namespace Phantom
