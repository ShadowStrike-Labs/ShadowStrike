/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "NetworkBehaviorAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <numeric>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxConnections          = 10'000;
static constexpr uint32_t kMaxAlerts               = 1'000;
static constexpr uint32_t kMaxDnsQueries           = 50'000;
static constexpr uint32_t kMaxDgaDomains           = 10'000;
static constexpr uint32_t kMaxHttpRequests         = 50'000;
static constexpr uint32_t kMaxConnectionTimestamps = 256;
static constexpr uint32_t kMaxSubdomainTrack       = 10'000;
static constexpr uint32_t kMaxRecentConnections    = 2'048;
static constexpr uint32_t kMaxC2Signatures         = 64;
static constexpr uint32_t kMaxJA3Entries           = 128;
static constexpr uint32_t kMaxPeerConnections      = 4'096;
static constexpr uint32_t kMaxTLSCertRecords       = 1'024;
static constexpr uint32_t kMaxDnsQueryRecords      = 50'000;

// P2P detection thresholds
static constexpr uint32_t kP2PPersistentConnThreshold   = 10;
static constexpr uint32_t kP2PPeerDiscoveryMinPeers     = 3;
static constexpr float    kP2PHighScore                 = 0.8f;

// DNS advanced thresholds
static constexpr uint32_t kDnsTxtQueryThreshold         = 5;
static constexpr uint32_t kDnsCnameDepthThreshold       = 3;
static constexpr uint32_t kDnsQueryVolPerDomainThreshold = 50;
static constexpr uint32_t kDnsSubdomainEnumThreshold    = 20;

// HTTP header analysis thresholds
static constexpr uint32_t kMaxUserAgentLen               = 512;
static constexpr uint32_t kMinExpectedHeaders            = 3;

// Exfiltration thresholds
static constexpr uint64_t kExfilBytesThreshold     = 102'400;       // 100 KB per connection
static constexpr uint64_t kExfilRatioThreshold     = 10;            // send:recv ratio
static constexpr uint64_t kGlobalExfilBytes        = 1'048'576;     // 1 MB total
static constexpr uint64_t kGlobalExfilRatio        = 5;             // global send:recv

// Beaconing thresholds
static constexpr uint32_t kMinBeaconConnections    = 3;
static constexpr float    kBeaconJitterThreshold   = 0.3f;

// DGA thresholds
static constexpr float    kDgaScoreThreshold       = 0.6f;
static constexpr float    kDgaEntropyThreshold     = 3.5f;
static constexpr float    kDgaConsonantThreshold   = 0.7f;
static constexpr float    kDgaBigramThreshold      = 0.7f;
static constexpr uint32_t kDgaLengthMedium         = 15;
static constexpr uint32_t kDgaLengthLong           = 20;
static constexpr float    kDgaNumberRatioThreshold = 0.3f;

// DNS tunneling thresholds
static constexpr float    kDnsTunnelEntropy        = 4.0f;
static constexpr uint32_t kDnsTunnelLabelLen       = 30;
static constexpr uint32_t kDnsTunnelSubdomainCount = 10;

// Connection pattern thresholds
static constexpr uint32_t kRapidConnUniqueIPs      = 10;
static constexpr uint64_t kRapidConnWindow         = 1'000;

// ============================================================================
// Internal Helpers
// ============================================================================

namespace {

// ---------- String utilities (no regex, character-by-character) -------------

[[nodiscard]] std::string MakeConnectionKey(const std::string& addr,
                                            uint16_t port) noexcept
{
    // addr + ":" + to_string(port)
    std::string key;
    key.reserve(addr.size() + 6);
    key += addr;
    key += ':';

    // Fast uint16 to string
    char buf[6];
    int pos = 0;
    uint16_t v = port;
    if (v == 0) {
        buf[pos++] = '0';
    } else {
        char tmp[5];
        int tpos = 0;
        while (v > 0) {
            tmp[tpos++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (int i = tpos - 1; i >= 0; --i) {
            buf[pos++] = tmp[i];
        }
    }
    key.append(buf, static_cast<size_t>(pos));
    return key;
}

[[nodiscard]] char ToLowerChar(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return static_cast<char>(c + ('a' - 'A'));
    return c;
}

[[nodiscard]] std::string ToLower(const std::string& s) noexcept {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        result += ToLowerChar(c);
    }
    return result;
}

[[nodiscard]] bool IsAlpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] bool IsDigit(char c) noexcept {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool IsConsonant(char c) noexcept {
    char lower = ToLowerChar(c);
    if (!IsAlpha(lower)) return false;
    switch (lower) {
        case 'a': case 'e': case 'i': case 'o': case 'u':
            return false;
        default:
            return true;
    }
}

// ---------- Domain parsing (character-by-character) -------------------------

struct DomainParts {
    std::string label;    // Main domain label (e.g., "example" in example.com)
    std::string tld;      // Top-level domain (e.g., "com")
    std::string baseDomain; // label + "." + tld
    std::string subdomain;  // Everything before baseDomain
    bool valid = false;
};

[[nodiscard]] DomainParts ParseDomain(const std::string& domain) noexcept {
    DomainParts parts;

    if (domain.empty() || domain.size() > 253) {
        return parts;
    }

    // Split by dots
    std::vector<std::string> labels;
    labels.reserve(8);
    std::string current;
    current.reserve(64);

    for (char c : domain) {
        if (c == '.') {
            if (!current.empty()) {
                labels.push_back(std::move(current));
                current.clear();
                current.reserve(64);
            }
        } else {
            if (current.size() < 63) {
                current += ToLowerChar(c);
            }
        }
    }
    if (!current.empty()) {
        labels.push_back(std::move(current));
    }

    if (labels.size() < 2) {
        // Single label like "localhost" — use as-is
        if (labels.size() == 1) {
            parts.label = labels[0];
            parts.tld.clear();
            parts.baseDomain = labels[0];
            parts.valid = true;
        }
        return parts;
    }

    parts.tld = labels.back();
    parts.label = labels[labels.size() - 2];
    parts.baseDomain = parts.label + "." + parts.tld;

    // Subdomain is everything before baseDomain
    if (labels.size() > 2) {
        for (size_t i = 0; i < labels.size() - 2; ++i) {
            if (i > 0) parts.subdomain += '.';
            parts.subdomain += labels[i];
        }
    }

    parts.valid = true;
    return parts;
}

// ---------- Shannon Entropy ------------------------------------------------

[[nodiscard]] float ComputeShannonEntropy(const std::string& s) noexcept {
    if (s.empty()) return 0.0f;

    std::array<uint32_t, 256> freq{};
    for (unsigned char c : s) {
        freq[c]++;
    }

    float entropy = 0.0f;
    float len = static_cast<float>(s.size());
    for (uint32_t f : freq) {
        if (f == 0) continue;
        float p = static_cast<float>(f) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ---------- Consonant Ratio ------------------------------------------------

[[nodiscard]] float ComputeConsonantRatio(const std::string& s) noexcept {
    uint32_t alphaCount = 0;
    uint32_t consonantCount = 0;
    for (char c : s) {
        if (IsAlpha(c)) {
            ++alphaCount;
            if (IsConsonant(c)) {
                ++consonantCount;
            }
        }
    }
    if (alphaCount == 0) return 0.0f;
    return static_cast<float>(consonantCount) / static_cast<float>(alphaCount);
}

// ---------- Common English Bigrams -----------------------------------------

// ~40 most common English bigrams for DGA detection
static constexpr const char* kCommonBigrams[] = {
    "th", "he", "in", "er", "an", "re", "on", "at",
    "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co",
    "me", "de", "hi", "ri", "ro", "ic"
};

static constexpr size_t kNumCommonBigrams =
    sizeof(kCommonBigrams) / sizeof(kCommonBigrams[0]);

[[nodiscard]] float ComputeBigramScore(const std::string& s) noexcept {
    if (s.size() < 2) return 1.0f;

    std::string lower = ToLower(s);
    uint32_t totalPairs = 0;
    uint32_t commonCount = 0;

    for (size_t i = 0; i + 1 < lower.size(); ++i) {
        if (!IsAlpha(lower[i]) || !IsAlpha(lower[i + 1])) continue;

        ++totalPairs;
        char pair[3] = { lower[i], lower[i + 1], '\0' };

        for (size_t b = 0; b < kNumCommonBigrams; ++b) {
            if (pair[0] == kCommonBigrams[b][0] &&
                pair[1] == kCommonBigrams[b][1]) {
                ++commonCount;
                break;
            }
        }
    }

    if (totalPairs == 0) return 1.0f;
    return 1.0f - (static_cast<float>(commonCount) / static_cast<float>(totalPairs));
}

// ---------- Number Ratio ---------------------------------------------------

[[nodiscard]] float ComputeNumberRatio(const std::string& s) noexcept {
    if (s.empty()) return 0.0f;
    uint32_t digitCount = 0;
    for (char c : s) {
        if (IsDigit(c)) ++digitCount;
    }
    return static_cast<float>(digitCount) / static_cast<float>(s.size());
}

// ---------- Small Embedded Dictionary (~200 common English words) ----------

static constexpr const char* kDictionaryWords[] = {
    "the", "be", "to", "of", "and", "a", "in", "that",
    "have", "it", "for", "not", "on", "with", "he", "as",
    "you", "do", "at", "this", "but", "his", "by", "from",
    "they", "we", "her", "she", "or", "an", "will", "my",
    "one", "all", "would", "there", "their", "what", "so", "up",
    "out", "if", "about", "who", "get", "which", "go", "me",
    "when", "make", "can", "like", "time", "no", "just", "him",
    "know", "take", "people", "into", "year", "your", "good", "some",
    "could", "them", "see", "other", "than", "then", "now", "look",
    "only", "come", "its", "over", "think", "also", "back", "after",
    "use", "two", "how", "our", "work", "first", "well", "way",
    "even", "new", "want", "because", "any", "these", "give", "day",
    "most", "us",
    "file", "open", "close", "read", "write", "data", "system", "user",
    "name", "code", "test", "http", "error", "start", "end", "server",
    "client", "host", "port", "send", "recv", "connect",
    "able", "above", "across", "add", "age", "ago", "air",
    "again", "against", "along", "always", "animal", "another",
    "area", "around", "ask", "away",
    "bad", "ball", "base", "been", "before", "began", "begin",
    "being", "below", "best", "better", "between", "big", "bit",
    "black", "blue", "body", "book", "both", "box", "boy",
    "bring", "build", "bus",
    "call", "came", "car", "care", "case", "change", "check",
    "child", "city", "class", "clear", "color", "common",
    "company", "control", "copy", "cost", "country", "course",
    "cover", "cut",
    "dark", "dead", "deep", "did", "door", "down", "draw",
    "drive", "drop", "dry", "during",
    "each", "early", "earth", "east", "eat", "else", "enough",
    "every", "example", "eye",
    "face", "fact", "fall", "family", "far", "fast", "father",
    "feel", "few", "field", "final", "find", "fire", "fish",
    "five", "food", "foot", "form", "found", "four", "free",
    "friend", "front", "full", "game", "gave",
    "great", "green", "ground", "group", "grow",
    "had", "half", "hand", "hard", "has", "head", "hear",
    "help", "here", "high", "hold", "home", "hot", "house",
    "hundred", "idea"
};

static constexpr size_t kDictionarySize =
    sizeof(kDictionaryWords) / sizeof(kDictionaryWords[0]);

[[nodiscard]] bool ContainsDictionaryWord(const std::string& s) noexcept {
    if (s.size() < 3) return false;

    std::string lower = ToLower(s);

    for (size_t w = 0; w < kDictionarySize; ++w) {
        const char* word = kDictionaryWords[w];
        size_t wlen = 0;
        while (word[wlen] != '\0') ++wlen;

        if (wlen < 3) continue;
        if (wlen > lower.size()) continue;

        // Search for word as substring
        for (size_t i = 0; i + wlen <= lower.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < wlen; ++j) {
                if (lower[i + j] != word[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

// ---------- Unusual TLDs ---------------------------------------------------

static constexpr const char* kUnusualTLDs[] = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw",
    "cc", "ws", "biz", "club", "work", "date", "racing",
    "win", "bid", "stream", "download", "xin", "gdn",
    "loan", "men", "click", "link", "trade"
};

static constexpr size_t kNumUnusualTLDs =
    sizeof(kUnusualTLDs) / sizeof(kUnusualTLDs[0]);

[[nodiscard]] bool IsUnusualTLD(const std::string& tld) noexcept {
    std::string lower = ToLower(tld);
    for (size_t i = 0; i < kNumUnusualTLDs; ++i) {
        const char* t = kUnusualTLDs[i];
        size_t tlen = 0;
        while (t[tlen] != '\0') ++tlen;
        if (lower.size() != tlen) continue;
        bool match = true;
        for (size_t j = 0; j < tlen; ++j) {
            if (lower[j] != t[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

// ---------- DGA Score Computation ------------------------------------------

[[nodiscard]] float ComputeDgaScore(const std::string& label,
                                    const std::string& tld) noexcept
{
    if (label.empty()) return 0.0f;

    float score = 0.0f;

    // (a) Shannon Entropy
    float entropy = ComputeShannonEntropy(label);
    if (entropy > kDgaEntropyThreshold) {
        score += 0.2f;
    }

    // (b) Consonant Ratio
    float consonantRatio = ComputeConsonantRatio(label);
    if (consonantRatio > kDgaConsonantThreshold) {
        score += 0.15f;
    }

    // (c) Bigram Frequency
    float bigramScore = ComputeBigramScore(label);
    if (bigramScore > kDgaBigramThreshold) {
        score += 0.15f;
    }

    // (d) Length
    if (label.size() > kDgaLengthLong) {
        score += 0.2f;
    } else if (label.size() > kDgaLengthMedium) {
        score += 0.1f;
    }

    // (e) No Dictionary Words
    if (!ContainsDictionaryWord(label)) {
        score += 0.15f;
    }

    // (f) Number Ratio
    float numberRatio = ComputeNumberRatio(label);
    if (numberRatio > kDgaNumberRatioThreshold) {
        score += 0.1f;
    }

    // (g) TLD Check
    if (IsUnusualTLD(tld)) {
        score += 0.05f;
    }

    return score;
}

// ---------- Protocol Inference from Port -----------------------------------

[[nodiscard]] std::string InferProtocol(uint16_t port) noexcept {
    switch (port) {
        case 80:   return "http";
        case 443:  return "https";
        case 53:   return "dns";
        case 8080: return "http";
        case 8443: return "https";
        default:   return "tcp";
    }
}

// ---------- Suspicious Ports -----------------------------------------------

static constexpr uint16_t kSuspiciousPorts[] = {
    4444,  5555,  6666,  7777,  8888,  9999,
    1234,  31337, 12345, 54321,
    1337,  3127,  3128,  4321,  5000,  5001,
    6667,  6668,  6669,        // IRC (common C2 channel)
    1080,  9050,  9150,        // SOCKS proxies / Tor
    3389,                      // RDP (suspicious for outbound)
    2222,                      // Alternate SSH
    4443,                      // Alt HTTPS (cobalt strike default)
    8081,  8082,  8888,
    10000, 20000, 25565,
    41337, 65535,
    13337, 27015,
    23,                        // Telnet
    1900,                      // SSDP (reflection attacks)
    11211,                     // Memcached (reflection)
};

static constexpr size_t kNumSuspiciousPorts =
    sizeof(kSuspiciousPorts) / sizeof(kSuspiciousPorts[0]);

[[nodiscard]] bool IsSuspiciousPort(uint16_t port) noexcept {
    for (size_t i = 0; i < kNumSuspiciousPorts; ++i) {
        if (kSuspiciousPorts[i] == port) return true;
    }
    return false;
}

// ---------- Known Malicious / Suspicious User-Agent Patterns ---------------

struct UAPattern {
    const char* pattern;
    bool        exactMatch;   // true = full string, false = substring
    bool        caseSensitive;
};

// ~30 known suspicious / malicious user-agent patterns
static constexpr UAPattern kSuspiciousUserAgents[] = {
    // Empty or very short
    { "",                          true,  false },

    // Known malware families and frameworks
    { "Mozilla/4.0",               false, false },
    { "MSIE 6.0",                  false, false },
    { "CobaltStrike",              false, false },
    { "Meterpreter",               false, false },
    { "Empire",                    false, true  },
    { "Covenant",                  false, true  },
    { "PoshC2",                    false, false },
    { "Mythic",                    false, true  },
    { "Havoc",                     false, true  },
    { "Sliver",                    false, true  },

    // Automated tools (suspicious in malware context)
    { "Wget",                      false, false },
    { "curl/",                     false, false },
    { "python-requests",           false, false },
    { "python-urllib",             false, false },
    { "Go-http-client",            false, false },
    { "Java/",                     false, false },
    { "libwww-perl",               false, false },
    { "lwp-trivial",               false, false },
    { "PHP/",                      false, false },
    { "Powershell",                false, false },
    { "WinHttp",                   false, false },
    { "XMLHTTP",                   false, false },

    // Suspicious impersonation keywords
    { "bot",                       false, false },
    { "crawler",                   false, false },
    { "spider",                    false, false },
    { "scanner",                   false, false },

    // Known IoT/botnet signatures
    { "Mirai",                     false, false },
    { "Hajime",                    false, false },
    { "Bashlite",                  false, false },
};

static constexpr size_t kNumSuspiciousUA =
    sizeof(kSuspiciousUserAgents) / sizeof(kSuspiciousUserAgents[0]);

[[nodiscard]] bool StringContainsCaseInsensitive(const std::string& haystack,
                                                 const char* needle) noexcept
{
    size_t nlen = 0;
    while (needle[nlen] != '\0') ++nlen;
    if (nlen == 0) return true;
    if (nlen > haystack.size()) return false;

    for (size_t i = 0; i + nlen <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            if (ToLowerChar(haystack[i + j]) != ToLowerChar(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

[[nodiscard]] bool StringContainsCaseSensitive(const std::string& haystack,
                                               const char* needle) noexcept
{
    size_t nlen = 0;
    while (needle[nlen] != '\0') ++nlen;
    if (nlen == 0) return true;
    if (nlen > haystack.size()) return false;

    for (size_t i = 0; i + nlen <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            if (haystack[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

[[nodiscard]] bool IsUserAgentSuspicious(const std::string& ua) noexcept {
    // Very short user-agents are suspicious
    if (ua.size() < 10 && !ua.empty()) {
        return true;
    }

    for (size_t i = 0; i < kNumSuspiciousUA; ++i) {
        const auto& pat = kSuspiciousUserAgents[i];

        if (pat.exactMatch) {
            // Exact match (primarily for empty UA)
            size_t plen = 0;
            while (pat.pattern[plen] != '\0') ++plen;
            if (ua.size() == plen) {
                bool match = true;
                for (size_t j = 0; j < plen; ++j) {
                    if (pat.caseSensitive) {
                        if (ua[j] != pat.pattern[j]) { match = false; break; }
                    } else {
                        if (ToLowerChar(ua[j]) != ToLowerChar(pat.pattern[j])) {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) return true;
            }
        } else {
            // Substring match
            bool found = pat.caseSensitive
                ? StringContainsCaseSensitive(ua, pat.pattern)
                : StringContainsCaseInsensitive(ua, pat.pattern);
            if (found) return true;
        }
    }

    return false;
}

// ---------- Statistics Helpers ----------------------------------------------

[[nodiscard]] float ComputeMean(const std::vector<uint64_t>& intervals) noexcept {
    if (intervals.empty()) return 0.0f;
    uint64_t sum = 0;
    for (uint64_t v : intervals) {
        // Guard overflow: clamp accumulation
        if (sum > UINT64_MAX - v) {
            sum = UINT64_MAX;
            break;
        }
        sum += v;
    }
    return static_cast<float>(sum) / static_cast<float>(intervals.size());
}

[[nodiscard]] float ComputeStdDev(const std::vector<uint64_t>& intervals,
                                  float mean) noexcept
{
    if (intervals.size() < 2) return 0.0f;
    float sumSqDiff = 0.0f;
    for (uint64_t v : intervals) {
        float diff = static_cast<float>(v) - mean;
        sumSqDiff += diff * diff;
    }
    return std::sqrt(sumSqDiff / static_cast<float>(intervals.size()));
}

// ============================================================================
// C2 Signature Database — static pattern definitions
// ============================================================================

struct C2SignatureEntry {
    const char* frameworkName;
    const char* patternType;      // "http", "dns", "pipe", "tls"
    const char* matchField;       // which field to match: "path", "cookie", "pipe", "port", "content_type", "dns_pattern"
    const char* pattern;          // substring pattern to check
    float       confidence;
};

static constexpr C2SignatureEntry kC2Signatures[] = {
    // Cobalt Strike HTTP
    { "CobaltStrike", "http", "cookie",       "SESSIONID=",                0.7f },
    { "CobaltStrike", "http", "path",         "/submit.php",              0.7f },
    { "CobaltStrike", "http", "content_type", "application/octet-stream", 0.5f },
    { "CobaltStrike", "http", "path",         "/pixel.gif",               0.6f },
    { "CobaltStrike", "http", "path",         "/__utm.gif",               0.6f },
    { "CobaltStrike", "http", "path",         "/ca",                      0.4f },
    { "CobaltStrike", "http", "path",         "/dpixel",                  0.6f },
    { "CobaltStrike", "http", "path",         "/ptj",                     0.5f },
    { "CobaltStrike", "http", "path",         "/j.ad",                    0.5f },

    // Cobalt Strike named pipes
    { "CobaltStrike", "pipe", "pipe", "\\\\\\\\.\\\\.pipe\\\\msagent_",   0.9f },
    { "CobaltStrike", "pipe", "pipe", "\\\\\\\\.\\\\pipe\\\\postex_",     0.9f },
    { "CobaltStrike", "pipe", "pipe", "\\\\.\\.pipe\\\\status_",          0.7f },
    { "CobaltStrike", "pipe", "pipe", "\\\\.\\.pipe\\\\msagent_",         0.9f },
    { "CobaltStrike", "pipe", "pipe", "\\\\.\\.pipe\\\\postex_",          0.9f },
    { "CobaltStrike", "pipe", "pipe", "msagent_",                         0.8f },
    { "CobaltStrike", "pipe", "pipe", "postex_",                          0.8f },

    // Cobalt Strike DNS
    { "CobaltStrike", "dns", "dns_pattern", ".stage.",                    0.8f },
    { "CobaltStrike", "dns", "dns_pattern", "aaa.stage.",                 0.9f },
    { "CobaltStrike", "dns", "dns_pattern", ".post.",                     0.6f },

    // Cobalt Strike port
    { "CobaltStrike", "tls", "port", "4443",                             0.5f },
    { "CobaltStrike", "tls", "port", "50050",                            0.7f },

    // Sliver C2
    { "Sliver", "tls",  "port", "8888",                                  0.5f },
    { "Sliver", "tls",  "port", "31337",                                 0.6f },
    { "Sliver", "http", "path", "/login",                                0.3f },
    { "Sliver", "http", "path", "/settings",                             0.3f },
    { "Sliver", "http", "path", "/api/version",                          0.5f },
    { "Sliver", "http", "path", "/.well-known/acme-challenge",           0.4f },
    { "Sliver", "dns",  "dns_pattern", "_domainkey.",                    0.4f },

    // Brute Ratel C4
    { "BruteRatel", "dns",  "dns_pattern", "dns.google",                 0.3f },
    { "BruteRatel", "http", "path", "/content",                          0.3f },
    { "BruteRatel", "http", "path", "/auth",                             0.3f },
    { "BruteRatel", "pipe", "pipe", "badger_",                           0.8f },
    { "BruteRatel", "tls",  "port", "8443",                              0.3f },

    // Empire / PowerShell Empire
    { "Empire", "http", "path", "/login/process.php",                    0.7f },
    { "Empire", "http", "path", "/admin/get.php",                        0.7f },
    { "Empire", "http", "path", "/news.php",                             0.5f },
    { "Empire", "http", "path", "/download/process.php",                 0.6f },
    { "Empire", "http", "cookie", "session=",                            0.3f },
};

static constexpr size_t kNumC2Signatures =
    sizeof(kC2Signatures) / sizeof(kC2Signatures[0]);

// ============================================================================
// JA3 Known Malicious Hash Database
// ============================================================================

struct JA3DatabaseEntry {
    const char* hash;
    const char* malwareFamily;
    float       confidence;
};

static constexpr JA3DatabaseEntry kJA3Database[] = {
    { "72a589da586844d7f0818ce684948eea", "Trickbot",        0.9f },
    { "a0e9f5d64349fb13191bc781f81f42e1", "AsyncRAT",        0.9f },
    { "e7d705a3286e19ea42f587b344ee6865", "Metasploit",      0.9f },
    { "51c64c77e60f3980eea90869b68c58a8", "CobaltStrike",    0.9f },
    { "b742b407517bac9536a77a7b0fee28e9", "CobaltStrike4x",  0.9f },
    { "3b5074b1b5d032e5620f69f9f700ff0e", "Empire",          0.9f },
    { "6734f37431670b3ab4292b8f60f29984", "Sliver",          0.9f },
    { "36f7277af969a6947a61ae0b815907a1", "BruteRatel",      0.9f },
    { "3b5074b1b5d032e5620f69f9f700ff0e", "IcedID",          0.85f },
    { "bd0bf25947d4a37404f0424571a32b96", "Emotet",          0.85f },
    { "8672281a1e9f5c4dc1f0e9b2b1f4be84", "Dridex",         0.85f },
    { "4d7a28d6f2263ed61de88ca66eb011e3", "QakBot",          0.85f },
    { "c12f54a3f91dc7bafd92b15381c47c1a", "BazarLoader",     0.85f },
    { "e35df3e00ca4ef31d42b34bebaa2f86e", "BumbleBee",       0.85f },
};

static constexpr size_t kNumJA3Entries =
    sizeof(kJA3Database) / sizeof(kJA3Database[0]);

// ============================================================================
// Known C2 TLS Issuers (staging / self-signed / commonly abused)
// ============================================================================

static constexpr const char* kKnownC2Issuers[] = {
    "cobaltstrike",
    "major cobalt strike",
    "default",
    "test",
    "localhost",
    "server",
    "self",
};

static constexpr size_t kNumKnownC2Issuers =
    sizeof(kKnownC2Issuers) / sizeof(kKnownC2Issuers[0]);

[[nodiscard]] bool IsKnownC2Issuer(const std::string& issuer) noexcept {
    std::string lower = ToLower(issuer);
    for (size_t i = 0; i < kNumKnownC2Issuers; ++i) {
        if (StringContainsCaseInsensitive(lower, kKnownC2Issuers[i])) {
            return true;
        }
    }
    return false;
}

// ---------- C2-specific HTTP header patterns --------------------------------

struct C2HeaderPattern {
    const char* headerName;
    const char* frameworkName;
    float       confidence;
};

static constexpr C2HeaderPattern kC2HeaderPatterns[] = {
    { "X-Session",     "Generic C2",     0.5f },
    { "X-UUID",        "Generic C2",     0.5f },
    { "X-Req-ID",      "Generic C2",     0.4f },
    { "X-Request-ID",  "CobaltStrike",   0.4f },
    { "X-Forwarded",   "Generic C2",     0.2f },
    { "X-C2",          "Generic C2",     0.9f },
    { "X-Bot-ID",      "Botnet",         0.8f },
    { "X-Malware",     "Generic C2",     0.9f },
};

static constexpr size_t kNumC2HeaderPatterns =
    sizeof(kC2HeaderPatterns) / sizeof(kC2HeaderPatterns[0]);

// ---------- Standard expected HTTP headers ----------------------------------

static constexpr const char* kExpectedHeaders[] = {
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
};

static constexpr size_t kNumExpectedHeaders =
    sizeof(kExpectedHeaders) / sizeof(kExpectedHeaders[0]);

// ---------- Port number to string (reusable helper) -------------------------

[[nodiscard]] bool PortMatchesPattern(uint16_t port, const char* pattern) noexcept {
    char buf[6];
    int pos = 0;
    uint16_t v = port;
    if (v == 0) {
        buf[pos++] = '0';
    } else {
        char tmp[5];
        int tpos = 0;
        while (v > 0) {
            tmp[tpos++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (int i = tpos - 1; i >= 0; --i) {
            buf[pos++] = tmp[i];
        }
    }
    buf[pos] = '\0';

    size_t plen = 0;
    while (pattern[plen] != '\0') ++plen;
    if (static_cast<size_t>(pos) != plen) return false;
    for (int i = 0; i < pos; ++i) {
        if (buf[i] != pattern[i]) return false;
    }
    return true;
}

// ---------- Check if string looks like base64 data -------------------------

[[nodiscard]] bool LooksLikeBase64(const std::string& data) noexcept {
    if (data.size() < 16) return false;

    uint32_t b64Chars = 0;
    for (char c : data) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            ++b64Chars;
        }
    }

    float ratio = static_cast<float>(b64Chars) / static_cast<float>(data.size());
    return ratio > 0.9f;
}

// ---------- Check if data appears to be high-entropy (encrypted) -----------

[[nodiscard]] bool LooksLikeEncryptedBlob(const std::string& data) noexcept {
    if (data.size() < 32) return false;
    float entropy = ComputeShannonEntropy(data);
    return entropy > 5.5f;
}

// ---------- Check for sequential/incremental subdomain patterns ------------

[[nodiscard]] bool AreSubdomainsSequential(
    const std::unordered_set<std::string>& subdomains) noexcept
{
    if (subdomains.size() < 5) return false;

    // Extract numeric suffixes from subdomains
    std::vector<int64_t> numbers;
    numbers.reserve(subdomains.size());

    for (const auto& sub : subdomains) {
        // Try to extract trailing numeric portion
        size_t numStart = sub.size();
        while (numStart > 0 && IsDigit(sub[numStart - 1])) {
            --numStart;
        }
        if (numStart < sub.size() && (sub.size() - numStart) <= 10) {
            int64_t val = 0;
            bool overflow = false;
            for (size_t i = numStart; i < sub.size(); ++i) {
                int64_t digit = sub[i] - '0';
                if (val > (INT64_MAX - digit) / 10) {
                    overflow = true;
                    break;
                }
                val = val * 10 + digit;
            }
            if (!overflow) {
                numbers.push_back(val);
            }
        }
    }

    if (numbers.size() < 5) return false;

    // Sort and check for sequential runs
    std::sort(numbers.begin(), numbers.end());
    uint32_t sequentialCount = 0;
    for (size_t i = 1; i < numbers.size(); ++i) {
        if (numbers[i] == numbers[i - 1] + 1) {
            ++sequentialCount;
        }
    }

    // If >50% of pairs are sequential, it's enumeration
    float seqRatio = static_cast<float>(sequentialCount) /
                     static_cast<float>(numbers.size() - 1);
    return seqRatio > 0.5f;
}

} // anonymous namespace

// ============================================================================
// HTTP Request Record (internal tracking)
// ============================================================================

struct HttpRequestRecord {
    std::string method;
    std::string url;
    std::string userAgent;
    uint64_t    timestamp = 0;
};

// ============================================================================
// Recent Connection Entry (for rapid-connection detection)
// ============================================================================

struct RecentConnectionEntry {
    std::string addr;
    uint64_t    timestamp = 0;
};

// ============================================================================
// P2P Peer Connection Entry (per-process connection graph tracking)
// ============================================================================

struct PeerConnectionEntry {
    uint32_t    processId     = 0;
    std::string srcAddr;
    std::string dstAddr;
    uint16_t    dstPort       = 0;
    uint64_t    firstSeen     = 0;
    uint64_t    lastSeen      = 0;
    uint32_t    bytesSent     = 0;
    uint32_t    bytesRecv     = 0;
    bool        isPersistent  = false;
};

// ============================================================================
// P2P Peer Discovery Record
// ============================================================================

struct PeerDiscoveryRecord {
    uint32_t                 processId = 0;
    std::string              sourceAddr;
    std::vector<std::string> discoveredAddrs;
    uint64_t                 timestamp = 0;
};

// ============================================================================
// TLS Certificate Observation Record
// ============================================================================

struct TLSCertRecord {
    std::string  addr;
    uint16_t     port   = 0;
    TLSCertInfo  cert;
    TLSAnomalyResult anomalyResult;
    uint64_t     timestamp = 0;
};

// ============================================================================
// DNS Advanced Tracking Entry
// ============================================================================

struct DnsAdvancedEntry {
    std::string domain;
    uint16_t    queryType   = 1;
    uint64_t    timestamp   = 0;
    uint32_t    cnameDepth  = 0;
};

// ============================================================================
// PIMPL — Implementation
// ============================================================================

struct NetworkBehaviorAnalyzer::Impl {
    // ---- Core data ----
    std::vector<NetworkConnection> connections;
    std::vector<NetworkAlert>      alerts;
    std::vector<std::string>       dnsQueries;
    std::vector<std::string>       dgaDomains;
    std::vector<HttpRequestRecord> httpRequests;

    // ---- Connection key → index mapping ----
    std::unordered_map<std::string, size_t> connectionIndex;

    // ---- Beaconing detection: per-connection timestamps ----
    // Key: connection key, Value: vector of instruction-count timestamps
    std::unordered_map<std::string, std::vector<uint64_t>> connectionTimestamps;

    // ---- DNS tunneling: base domain → set of subdomains ----
    std::unordered_map<std::string, std::unordered_set<std::string>> subdomainTracker;

    // ---- Rapid connection tracking ----
    std::vector<RecentConnectionEntry> recentConnections;

    // ---- P2P tracking ----
    // processId → set of unique destination addresses
    std::unordered_map<uint32_t, std::unordered_set<std::string>> processConnGraph;
    std::vector<PeerConnectionEntry>  peerConnections;
    std::vector<PeerDiscoveryRecord>  peerDiscoveries;

    // ---- TLS certificate observations ----
    std::vector<TLSCertRecord> tlsCertRecords;

    // ---- JA3 observation tracking ----
    std::vector<JA3Fingerprint> observedJA3;

    // ---- DNS advanced tracking ----
    std::vector<DnsAdvancedEntry> dnsAdvancedRecords;
    // baseDomain → query count (for volume analysis)
    std::unordered_map<std::string, uint32_t> dnsQueryVolume;
    // baseDomain → TXT query count
    std::unordered_map<std::string, uint32_t> dnsTxtQueryCount;

    // ---- Byte counters ----
    uint64_t totalBytesSent     = 0;
    uint64_t totalBytesReceived = 0;

    // ---- Instruction counter (monotonic, incremented per event) ----
    uint64_t instructionCounter = 0;

    // ---- Configuration reference ----
    const EmulationConfig* config = nullptr;

    // ---- Flags for quick indicator checks ----
    bool hasBeaconingDetected    = false;
    bool hasDgaDetected          = false;
    bool hasSuspiciousUA         = false;
    bool hasExfiltrationDetected = false;
    bool hasDnsTunnelingDetected = false;
    bool hasC2SignatureDetected  = false;
    bool hasTLSAnomalyDetected  = false;
    bool hasJA3MatchDetected     = false;
    bool hasP2PDetected          = false;

    // ========================================================================
    // Impl Constructor
    // ========================================================================

    explicit Impl(const EmulationConfig& cfg) noexcept
        : config(&cfg)
    {
        connections.reserve(256);
        alerts.reserve(64);
        dnsQueries.reserve(256);
        dgaDomains.reserve(64);
        httpRequests.reserve(64);
        recentConnections.reserve(256);
        peerConnections.reserve(64);
        peerDiscoveries.reserve(32);
        tlsCertRecords.reserve(32);
        observedJA3.reserve(32);
        dnsAdvancedRecords.reserve(256);
    }

    // ========================================================================
    // Advance the internal instruction counter
    // ========================================================================

    [[nodiscard]] uint64_t Tick() noexcept {
        return ++instructionCounter;
    }

    // ========================================================================
    // Add an alert (with cap enforcement)
    // ========================================================================

    void AddAlert(const std::string& type,
                  const std::string& description,
                  float severity,
                  const std::string& evidence) noexcept
    {
        if (alerts.size() >= kMaxAlerts) return;

        // Clamp severity to [0, 1]
        float sev = severity;
        if (sev < 0.0f) sev = 0.0f;
        if (sev > 1.0f) sev = 1.0f;

        NetworkAlert alert;
        alert.type        = type;
        alert.description = description;
        alert.severity    = sev;
        alert.evidence    = evidence;
        alerts.push_back(std::move(alert));
    }

    // ========================================================================
    // Get or create a connection entry for addr:port
    // ========================================================================

    [[nodiscard]] NetworkConnection* GetOrCreateConnection(
        const std::string& addr,
        uint16_t port,
        const std::string& protocol) noexcept
    {
        std::string key = MakeConnectionKey(addr, port);

        auto it = connectionIndex.find(key);
        if (it != connectionIndex.end()) {
            if (it->second < connections.size()) {
                return &connections[it->second];
            }
        }

        // Cap check
        if (connections.size() >= kMaxConnections) {
            return nullptr;
        }

        // Create new connection
        NetworkConnection conn;
        conn.remoteAddr = addr;
        conn.remotePort = port;
        conn.protocol   = protocol.empty() ? InferProtocol(port) : protocol;

        size_t idx = connections.size();
        connections.push_back(std::move(conn));
        connectionIndex[key] = idx;
        return &connections[idx];
    }

    // ========================================================================
    // Score suspicious port
    // ========================================================================

    void ScoreSuspiciousPort(NetworkConnection& conn) noexcept {
        if (IsSuspiciousPort(conn.remotePort)) {
            conn.suspiciousness += 0.3f;
            if (conn.suspiciousness > 1.0f) conn.suspiciousness = 1.0f;

            // Generate alert on first detection (when suspiciousness first
            // crossed threshold from port alone)
            if (conn.connectionCount == 1) {
                std::string evidence = "port=" +
                    std::to_string(conn.remotePort) +
                    " addr=" + conn.remoteAddr;

                AddAlert("suspicious_port",
                         "Connection to commonly-abused port " +
                             std::to_string(conn.remotePort),
                         0.4f,
                         evidence);
            }
        }
    }

    // ========================================================================
    // Beaconing Detection
    // ========================================================================

    void CheckBeaconing(const std::string& key,
                        NetworkConnection& conn,
                        uint64_t timestamp) noexcept
    {
        auto& timestamps = connectionTimestamps[key];

        // Cap timestamps per connection
        if (timestamps.size() >= kMaxConnectionTimestamps) {
            // Slide window: remove the oldest quarter
            size_t removeCount = kMaxConnectionTimestamps / 4;
            timestamps.erase(timestamps.begin(),
                             timestamps.begin() +
                                 static_cast<ptrdiff_t>(removeCount));
        }
        timestamps.push_back(timestamp);

        if (timestamps.size() < kMinBeaconConnections) return;

        // Compute intervals
        std::vector<uint64_t> intervals;
        intervals.reserve(timestamps.size() - 1);
        for (size_t i = 1; i < timestamps.size(); ++i) {
            if (timestamps[i] > timestamps[i - 1]) {
                intervals.push_back(timestamps[i] - timestamps[i - 1]);
            } else {
                intervals.push_back(0);
            }
        }

        if (intervals.empty()) return;

        float mean   = ComputeMean(intervals);
        float stddev = ComputeStdDev(intervals, mean);

        // Avoid division by zero
        if (mean < 1.0f) return;

        float jitter = stddev / mean;

        if (jitter < kBeaconJitterThreshold) {
            conn.isBeaconing = true;
            hasBeaconingDetected = true;

            // Severity scales with count and consistency
            float severity = 0.5f;
            if (conn.connectionCount >= 10)  severity += 0.15f;
            if (conn.connectionCount >= 20)  severity += 0.15f;
            if (jitter < 0.1f)               severity += 0.1f;
            if (severity > 1.0f) severity = 1.0f;

            conn.suspiciousness += 0.4f;
            if (conn.suspiciousness > 1.0f) conn.suspiciousness = 1.0f;

            std::string evidence =
                "addr=" + conn.remoteAddr +
                ":" + std::to_string(conn.remotePort) +
                " count=" + std::to_string(conn.connectionCount) +
                " mean_interval=" + std::to_string(static_cast<uint64_t>(mean)) +
                " jitter=" + std::to_string(jitter);

            AddAlert("c2_beaconing",
                     "Regular beaconing detected to " + conn.remoteAddr +
                         ":" + std::to_string(conn.remotePort) +
                         " (jitter=" + std::to_string(jitter) + ")",
                     severity,
                     evidence);
        }
    }

    // ========================================================================
    // Exfiltration Detection (per-connection)
    // ========================================================================

    void CheckExfiltration(NetworkConnection& conn) noexcept {
        // Per-connection threshold
        if (conn.bytesSent > kExfilBytesThreshold) {
            uint64_t recvGuard = (conn.bytesReceived > 0)
                                     ? conn.bytesReceived
                                     : 1;
            if (conn.bytesSent > recvGuard * kExfilRatioThreshold) {
                conn.suspiciousness += 0.5f;
                if (conn.suspiciousness > 1.0f) conn.suspiciousness = 1.0f;

                hasExfiltrationDetected = true;

                std::string evidence =
                    "addr=" + conn.remoteAddr +
                    ":" + std::to_string(conn.remotePort) +
                    " sent=" + std::to_string(conn.bytesSent) +
                    " recv=" + std::to_string(conn.bytesReceived) +
                    " ratio=" + std::to_string(
                        conn.bytesSent / recvGuard);

                AddAlert("exfiltration",
                         "Potential data exfiltration to " +
                             conn.remoteAddr + ":" +
                             std::to_string(conn.remotePort) +
                             " (" + std::to_string(conn.bytesSent) +
                             " bytes sent, " +
                             std::to_string(conn.bytesSent / recvGuard) +
                             ":1 send/recv ratio)",
                         0.7f,
                         evidence);
            }
        }
    }

    // ========================================================================
    // Global Exfiltration Detection
    // ========================================================================

    void CheckGlobalExfiltration() noexcept {
        if (totalBytesSent > kGlobalExfilBytes) {
            uint64_t recvGuard = (totalBytesReceived > 0)
                                     ? totalBytesReceived
                                     : 1;
            if (totalBytesSent > recvGuard * kGlobalExfilRatio) {
                hasExfiltrationDetected = true;

                std::string evidence =
                    "total_sent=" + std::to_string(totalBytesSent) +
                    " total_recv=" + std::to_string(totalBytesReceived) +
                    " ratio=" + std::to_string(totalBytesSent / recvGuard);

                AddAlert("exfiltration_global",
                         "High aggregate outbound data volume: " +
                             std::to_string(totalBytesSent) +
                             " bytes sent across all connections (" +
                             std::to_string(totalBytesSent / recvGuard) +
                             ":1 send/recv ratio)",
                         0.8f,
                         evidence);
            }
        }
    }

    // ========================================================================
    // Encrypted Channel Detection
    // ========================================================================

    void CheckEncryptedChannel(NetworkConnection& conn) noexcept {
        // Heuristic: large sends to HTTPS ports suggest encrypted exfil
        bool isEncryptedPort = (conn.remotePort == 443  ||
                                conn.remotePort == 8443 ||
                                conn.remotePort == 4443);
        if (!isEncryptedPort) return;

        // Only flag if significant data volume
        if (conn.bytesSent > kExfilBytesThreshold) {
            conn.suspiciousness += 0.1f;
            if (conn.suspiciousness > 1.0f) conn.suspiciousness = 1.0f;

            std::string evidence =
                "addr=" + conn.remoteAddr +
                ":" + std::to_string(conn.remotePort) +
                " sent=" + std::to_string(conn.bytesSent) +
                " encrypted_port=true";

            AddAlert("encrypted_channel",
                     "Significant data sent over encrypted channel to " +
                         conn.remoteAddr + ":" +
                         std::to_string(conn.remotePort),
                     0.4f,
                     evidence);
        }
    }

    // ========================================================================
    // DGA Detection
    // ========================================================================

    void AnalyzeDgaDomain(const std::string& domain) noexcept {
        DomainParts parts = ParseDomain(domain);
        if (!parts.valid) return;
        if (parts.label.empty()) return;

        float score = ComputeDgaScore(parts.label, parts.tld);

        if (score > kDgaScoreThreshold) {
            hasDgaDetected = true;

            if (dgaDomains.size() < kMaxDgaDomains) {
                dgaDomains.push_back(domain);
            }

            std::string evidence =
                "domain=" + domain +
                " label=" + parts.label +
                " score=" + std::to_string(score) +
                " entropy=" + std::to_string(
                    ComputeShannonEntropy(parts.label));

            AddAlert("dga",
                     "Algorithmically generated domain detected: " + domain +
                         " (score=" + std::to_string(score) + ")",
                     0.6f + (score - kDgaScoreThreshold) * 0.5f,
                     evidence);
        }
    }

    // ========================================================================
    // DNS Tunneling Detection
    // ========================================================================

    void CheckDnsTunneling(const std::string& domain) noexcept {
        DomainParts parts = ParseDomain(domain);
        if (!parts.valid) return;

        // Check 1: High-entropy, long subdomain label → encoded data
        if (!parts.subdomain.empty()) {
            // Analyze the full subdomain string (everything before base domain)
            float subEntropy = ComputeShannonEntropy(parts.subdomain);
            if (subEntropy > kDnsTunnelEntropy &&
                parts.subdomain.size() > kDnsTunnelLabelLen) {

                hasDnsTunnelingDetected = true;

                std::string evidence =
                    "domain=" + domain +
                    " subdomain=" + parts.subdomain +
                    " entropy=" + std::to_string(subEntropy) +
                    " length=" + std::to_string(parts.subdomain.size());

                AddAlert("dns_tunneling",
                         "DNS tunneling suspected: high-entropy subdomain in " +
                             domain + " (entropy=" +
                             std::to_string(subEntropy) + ", len=" +
                             std::to_string(parts.subdomain.size()) + ")",
                         0.7f,
                         evidence);
            }
        }

        // Check 2: Many unique subdomains under same base domain
        if (!parts.baseDomain.empty() && !parts.subdomain.empty()) {
            if (subdomainTracker.size() < kMaxSubdomainTrack) {
                auto& subSet = subdomainTracker[parts.baseDomain];
                if (subSet.size() < kMaxSubdomainTrack) {
                    subSet.insert(parts.subdomain);
                }

                if (subSet.size() > kDnsTunnelSubdomainCount) {
                    hasDnsTunnelingDetected = true;

                    std::string evidence =
                        "base_domain=" + parts.baseDomain +
                        " unique_subdomains=" +
                            std::to_string(subSet.size());

                    AddAlert("dns_tunneling",
                             "Many unique subdomains under " +
                                 parts.baseDomain + " (" +
                                 std::to_string(subSet.size()) +
                                 " unique subdomains — DNS tunneling indicator)",
                             0.75f,
                             evidence);
                }
            }
        }

        // Check 3: High entropy in the label itself with long length
        float labelEntropy = ComputeShannonEntropy(parts.label);
        if (labelEntropy > kDnsTunnelEntropy &&
            parts.label.size() > kDnsTunnelLabelLen) {

            hasDnsTunnelingDetected = true;

            std::string evidence =
                "domain=" + domain +
                " label=" + parts.label +
                " entropy=" + std::to_string(labelEntropy) +
                " length=" + std::to_string(parts.label.size());

            AddAlert("dns_tunneling",
                     "DNS tunneling suspected: encoded-looking domain label " +
                         parts.label + " (entropy=" +
                         std::to_string(labelEntropy) + ")",
                     0.65f,
                     evidence);
        }
    }

    // ========================================================================
    // Rapid Connection Pattern Detection
    // ========================================================================

    void CheckRapidConnections(const std::string& addr,
                               uint64_t timestamp) noexcept
    {
        // Record this connection
        if (recentConnections.size() >= kMaxRecentConnections) {
            // Evict oldest quarter
            size_t removeCount = kMaxRecentConnections / 4;
            recentConnections.erase(
                recentConnections.begin(),
                recentConnections.begin() +
                    static_cast<ptrdiff_t>(removeCount));
        }

        RecentConnectionEntry entry;
        entry.addr      = addr;
        entry.timestamp = timestamp;
        recentConnections.push_back(std::move(entry));

        // Count unique IPs within the recent window
        uint64_t windowStart = 0;
        if (timestamp > kRapidConnWindow) {
            windowStart = timestamp - kRapidConnWindow;
        }

        std::unordered_set<std::string> uniqueAddrs;
        for (auto it = recentConnections.rbegin();
             it != recentConnections.rend(); ++it) {
            if (it->timestamp < windowStart) break;
            uniqueAddrs.insert(it->addr);
        }

        if (uniqueAddrs.size() > kRapidConnUniqueIPs) {
            std::string evidence =
                "unique_ips=" + std::to_string(uniqueAddrs.size()) +
                " window=" + std::to_string(kRapidConnWindow) +
                " instructions";

            AddAlert("rapid_connections",
                     "Rapid connections to " +
                         std::to_string(uniqueAddrs.size()) +
                         " unique addresses within " +
                         std::to_string(kRapidConnWindow) +
                         " instructions — possible port scanning or C2 failover",
                     0.6f,
                     evidence);
        }
    }

    // ========================================================================
    // User-Agent Analysis
    // ========================================================================

    void AnalyzeUserAgent(const std::string& userAgent,
                          const std::string& method,
                          const std::string& url) noexcept
    {
        if (IsUserAgentSuspicious(userAgent)) {
            hasSuspiciousUA = true;

            std::string truncatedUA = userAgent;
            if (truncatedUA.size() > 200) {
                truncatedUA.resize(200);
                truncatedUA += "...";
            }

            std::string evidence =
                "user_agent=\"" + truncatedUA + "\"" +
                " method=" + method +
                " url=" + url;

            float severity = 0.4f;
            if (userAgent.empty()) severity = 0.6f;
            if (userAgent.size() < 10 && !userAgent.empty()) severity = 0.5f;

            AddAlert("suspicious_user_agent",
                     "Suspicious User-Agent detected: \"" + truncatedUA + "\"",
                     severity,
                     evidence);
        }
    }

    // ========================================================================
    // Reset
    // ========================================================================

    void ResetAll() noexcept {
        connections.clear();
        alerts.clear();
        dnsQueries.clear();
        dgaDomains.clear();
        httpRequests.clear();
        connectionIndex.clear();
        connectionTimestamps.clear();
        subdomainTracker.clear();
        recentConnections.clear();
        processConnGraph.clear();
        peerConnections.clear();
        peerDiscoveries.clear();
        tlsCertRecords.clear();
        observedJA3.clear();
        dnsAdvancedRecords.clear();
        dnsQueryVolume.clear();
        dnsTxtQueryCount.clear();

        totalBytesSent       = 0;
        totalBytesReceived   = 0;
        instructionCounter   = 0;

        hasBeaconingDetected    = false;
        hasDgaDetected          = false;
        hasSuspiciousUA         = false;
        hasExfiltrationDetected = false;
        hasDnsTunnelingDetected = false;
        hasC2SignatureDetected  = false;
        hasTLSAnomalyDetected  = false;
        hasJA3MatchDetected     = false;
        hasP2PDetected          = false;
    }
};

// ============================================================================
// NetworkBehaviorAnalyzer — Public Interface
// ============================================================================

// ---------- Constructor / Destructor / Move --------------------------------

NetworkBehaviorAnalyzer::NetworkBehaviorAnalyzer(
    const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(config))
{
}

NetworkBehaviorAnalyzer::~NetworkBehaviorAnalyzer() noexcept = default;

NetworkBehaviorAnalyzer::NetworkBehaviorAnalyzer(
    NetworkBehaviorAnalyzer&&) noexcept = default;

NetworkBehaviorAnalyzer& NetworkBehaviorAnalyzer::operator=(
    NetworkBehaviorAnalyzer&&) noexcept = default;

// ---------- OnConnect ------------------------------------------------------

void NetworkBehaviorAnalyzer::OnConnect(const std::string& addr,
                                        uint16_t port,
                                        const std::string& protocol) noexcept
{
    if (!m_impl) return;
    if (addr.empty()) return;

    uint64_t ts = m_impl->Tick();

    // Resolve protocol
    std::string resolvedProtocol = protocol.empty()
        ? InferProtocol(port)
        : protocol;

    NetworkConnection* conn =
        m_impl->GetOrCreateConnection(addr, port, resolvedProtocol);
    if (!conn) return;

    conn->connectionCount++;

    if (conn->firstSeen == 0) {
        conn->firstSeen = ts;
    }
    conn->lastSeen = ts;

    // Score suspicious port
    m_impl->ScoreSuspiciousPort(*conn);

    // Beaconing detection
    std::string key = MakeConnectionKey(addr, port);
    m_impl->CheckBeaconing(key, *conn, ts);

    // Rapid connection pattern detection
    m_impl->CheckRapidConnections(addr, ts);
}

// ---------- OnSend ---------------------------------------------------------

void NetworkBehaviorAnalyzer::OnSend(const std::string& addr,
                                     uint16_t port,
                                     uint32_t bytes) noexcept
{
    if (!m_impl) return;
    if (addr.empty() || bytes == 0) return;

    m_impl->Tick();

    NetworkConnection* conn =
        m_impl->GetOrCreateConnection(addr, port, "");
    if (!conn) return;

    // Accumulate bytes with overflow protection
    uint64_t newSent = conn->bytesSent;
    if (newSent <= UINT64_MAX - bytes) {
        newSent += bytes;
    } else {
        newSent = UINT64_MAX;
    }
    conn->bytesSent = newSent;

    // Update global total
    if (m_impl->totalBytesSent <= UINT64_MAX - bytes) {
        m_impl->totalBytesSent += bytes;
    } else {
        m_impl->totalBytesSent = UINT64_MAX;
    }

    // Per-connection exfiltration check
    m_impl->CheckExfiltration(*conn);

    // Global exfiltration check
    m_impl->CheckGlobalExfiltration();

    // Encrypted channel detection
    m_impl->CheckEncryptedChannel(*conn);
}

// ---------- OnReceive ------------------------------------------------------

void NetworkBehaviorAnalyzer::OnReceive(const std::string& addr,
                                        uint16_t port,
                                        uint32_t bytes) noexcept
{
    if (!m_impl) return;
    if (addr.empty() || bytes == 0) return;

    m_impl->Tick();

    NetworkConnection* conn =
        m_impl->GetOrCreateConnection(addr, port, "");
    if (!conn) return;

    // Accumulate bytes with overflow protection
    uint64_t newRecv = conn->bytesReceived;
    if (newRecv <= UINT64_MAX - bytes) {
        newRecv += bytes;
    } else {
        newRecv = UINT64_MAX;
    }
    conn->bytesReceived = newRecv;

    // Update global total
    if (m_impl->totalBytesReceived <= UINT64_MAX - bytes) {
        m_impl->totalBytesReceived += bytes;
    } else {
        m_impl->totalBytesReceived = UINT64_MAX;
    }
}

// ---------- OnDnsQuery -----------------------------------------------------

void NetworkBehaviorAnalyzer::OnDnsQuery(const std::string& domain) noexcept
{
    if (!m_impl) return;
    if (domain.empty()) return;

    m_impl->Tick();

    // Store query (capped)
    if (m_impl->dnsQueries.size() < kMaxDnsQueries) {
        m_impl->dnsQueries.push_back(domain);
    }

    // DGA analysis
    m_impl->AnalyzeDgaDomain(domain);

    // DNS tunneling analysis
    m_impl->CheckDnsTunneling(domain);
}

// ---------- OnHttpRequest --------------------------------------------------

void NetworkBehaviorAnalyzer::OnHttpRequest(const std::string& method,
                                            const std::string& url,
                                            const std::string& userAgent) noexcept
{
    if (!m_impl) return;

    uint64_t ts = m_impl->Tick();

    // Store request (capped)
    if (m_impl->httpRequests.size() < kMaxHttpRequests) {
        HttpRequestRecord rec;
        rec.method    = method;
        rec.url       = url;
        rec.userAgent = userAgent;
        rec.timestamp = ts;
        m_impl->httpRequests.push_back(std::move(rec));
    }

    // User-Agent analysis
    m_impl->AnalyzeUserAgent(userAgent, method, url);
}

// ---------- GetConnections -------------------------------------------------

const std::vector<NetworkConnection>&
NetworkBehaviorAnalyzer::GetConnections() const noexcept
{
    static const std::vector<NetworkConnection> kEmpty;
    if (!m_impl) return kEmpty;
    return m_impl->connections;
}

// ---------- GetAlerts ------------------------------------------------------

const std::vector<NetworkAlert>&
NetworkBehaviorAnalyzer::GetAlerts() const noexcept
{
    static const std::vector<NetworkAlert> kEmpty;
    if (!m_impl) return kEmpty;
    return m_impl->alerts;
}

// ---------- GetTotalBytesSent ----------------------------------------------

uint64_t NetworkBehaviorAnalyzer::GetTotalBytesSent() const noexcept
{
    if (!m_impl) return 0;
    return m_impl->totalBytesSent;
}

// ---------- GetTotalBytesReceived ------------------------------------------

uint64_t NetworkBehaviorAnalyzer::GetTotalBytesReceived() const noexcept
{
    if (!m_impl) return 0;
    return m_impl->totalBytesReceived;
}

// ---------- HasC2Indicators ------------------------------------------------

bool NetworkBehaviorAnalyzer::HasC2Indicators() const noexcept
{
    if (!m_impl) return false;

    // Any beaconing detected
    if (m_impl->hasBeaconingDetected) return true;

    // Any DGA domains detected
    if (m_impl->hasDgaDetected) return true;

    // Any suspicious user-agents
    if (m_impl->hasSuspiciousUA) return true;

    // C2 protocol signature match
    if (m_impl->hasC2SignatureDetected) return true;

    // TLS anomaly indicative of C2
    if (m_impl->hasTLSAnomalyDetected) return true;

    // Known malicious JA3 fingerprint
    if (m_impl->hasJA3MatchDetected) return true;

    // P2P botnet behaviour
    if (m_impl->hasP2PDetected) return true;

    // Check individual connections for beaconing flag
    for (const auto& conn : m_impl->connections) {
        if (conn.isBeaconing) return true;
    }

    return false;
}

// ---------- HasExfiltrationIndicators --------------------------------------

bool NetworkBehaviorAnalyzer::HasExfiltrationIndicators() const noexcept
{
    if (!m_impl) return false;

    // Exfiltration flag
    if (m_impl->hasExfiltrationDetected) return true;

    // DNS tunneling detected
    if (m_impl->hasDnsTunnelingDetected) return true;

    // Scan alerts for exfiltration types
    for (const auto& alert : m_impl->alerts) {
        if (alert.type == "exfiltration" ||
            alert.type == "exfiltration_global" ||
            alert.type == "dns_tunneling") {
            return true;
        }
    }

    return false;
}

// ---------- GetDGADomains --------------------------------------------------

std::vector<std::string>
NetworkBehaviorAnalyzer::GetDGADomains() const noexcept
{
    if (!m_impl) return {};
    return m_impl->dgaDomains;
}

// ---------- Reset ----------------------------------------------------------

void NetworkBehaviorAnalyzer::Reset() noexcept
{
    if (!m_impl) return;
    m_impl->ResetAll();
}

// ============================================================================
// Extended Feed Events
// ============================================================================

// ---------- OnTLSCertObserved ---------------------------------------------

void NetworkBehaviorAnalyzer::OnTLSCertObserved(
    const std::string& addr, uint16_t port,
    const TLSCertInfo& cert) noexcept
{
    if (!m_impl) return;
    if (addr.empty()) return;

    uint64_t ts = m_impl->Tick();

    if (m_impl->tlsCertRecords.size() >= kMaxTLSCertRecords) return;

    TLSAnomalyResult anomaly = AnalyzeTLSCert(cert);

    TLSCertRecord record;
    record.addr          = addr;
    record.port          = port;
    record.cert          = cert;
    record.anomalyResult = anomaly;
    record.timestamp     = ts;
    m_impl->tlsCertRecords.push_back(std::move(record));

    if (anomaly.anomalyScore > 0.5f) {
        m_impl->hasTLSAnomalyDetected = true;

        std::string evidence =
            "addr=" + addr + ":" + std::to_string(port) +
            " cn=" + cert.commonName +
            " issuer=" + cert.issuer +
            " self_signed=" + (cert.selfSigned ? "true" : "false") +
            " score=" + std::to_string(anomaly.anomalyScore);

        m_impl->AddAlert("tls_anomaly",
                         "Suspicious TLS certificate from " + addr + ":" +
                             std::to_string(port) + " (CN=" + cert.commonName +
                             ", score=" + std::to_string(anomaly.anomalyScore) + ")",
                         anomaly.anomalyScore,
                         evidence);
    }
}

// ---------- OnJA3Observed -------------------------------------------------

void NetworkBehaviorAnalyzer::OnJA3Observed(
    const std::string& addr, uint16_t port,
    const JA3Fingerprint& fingerprint) noexcept
{
    if (!m_impl) return;

    m_impl->Tick();

    if (m_impl->observedJA3.size() < kMaxJA3Entries) {
        m_impl->observedJA3.push_back(fingerprint);
    }

    // Check client hash against database
    if (!fingerprint.clientHash.empty()) {
        JA3MatchResult result = CheckJA3(fingerprint.clientHash);
        if (result.matched) {
            m_impl->hasJA3MatchDetected = true;

            std::string evidence =
                "addr=" + addr + ":" + std::to_string(port) +
                " ja3=" + fingerprint.clientHash +
                " family=" + result.malwareFamily +
                " confidence=" + std::to_string(result.confidence);

            m_impl->AddAlert("ja3_malicious",
                             "Known malicious JA3 fingerprint: " +
                                 result.malwareFamily + " (hash=" +
                                 fingerprint.clientHash + ")",
                             result.confidence,
                             evidence);
        }
    }

    // Also check server hash
    if (!fingerprint.serverHash.empty()) {
        JA3MatchResult sResult = CheckJA3(fingerprint.serverHash);
        if (sResult.matched) {
            m_impl->hasJA3MatchDetected = true;

            std::string evidence =
                "addr=" + addr + ":" + std::to_string(port) +
                " ja3s=" + fingerprint.serverHash +
                " family=" + sResult.malwareFamily;

            m_impl->AddAlert("ja3s_malicious",
                             "Known malicious JA3S fingerprint: " +
                                 sResult.malwareFamily + " (hash=" +
                                 fingerprint.serverHash + ")",
                             sResult.confidence * 0.9f,
                             evidence);
        }
    }
}

// ---------- OnNetworkEvent ------------------------------------------------

void NetworkBehaviorAnalyzer::OnNetworkEvent(const NetworkEvent& event) noexcept
{
    if (!m_impl) return;

    m_impl->Tick();

    // Run C2 signature analysis on the event
    C2DetectionResult c2Result = AnalyzeForC2(event);
    if (c2Result.detected) {
        m_impl->hasC2SignatureDetected = true;

        m_impl->AddAlert("c2_signature",
                         "C2 framework signature matched: " +
                             c2Result.frameworkName + " via " +
                             c2Result.matchType + " (confidence=" +
                             std::to_string(c2Result.confidence) + ")",
                         c2Result.confidence,
                         c2Result.evidence);
    }

    // Track P2P connection graph for process
    if (event.processId != 0 && !event.remoteAddr.empty()) {
        auto& procConns = m_impl->processConnGraph[event.processId];
        if (procConns.size() < kMaxPeerConnections) {
            procConns.insert(event.remoteAddr);
        }
    }
}

// ---------- OnDnsQueryEx --------------------------------------------------

void NetworkBehaviorAnalyzer::OnDnsQueryEx(const DNSQueryRecord& record) noexcept
{
    if (!m_impl) return;

    m_impl->Tick();

    // Store advanced record (capped)
    if (m_impl->dnsAdvancedRecords.size() < kMaxDnsQueryRecords) {
        DnsAdvancedEntry entry;
        entry.domain    = record.domain;
        entry.queryType = record.queryType;
        entry.timestamp = record.timestamp;
        entry.cnameDepth = record.cnameDepth;
        m_impl->dnsAdvancedRecords.push_back(std::move(entry));
    }

    // Also feed into existing DNS analysis pipeline
    OnDnsQuery(record.domain);

    // --- TXT record frequency analysis ---
    if (record.queryType == 16) {  // TXT record
        DomainParts parts = ParseDomain(record.domain);
        if (parts.valid && !parts.baseDomain.empty()) {
            auto& txtCount = m_impl->dnsTxtQueryCount[parts.baseDomain];
            if (txtCount < UINT32_MAX) ++txtCount;

            if (txtCount >= kDnsTxtQueryThreshold) {
                std::string evidence =
                    "domain=" + parts.baseDomain +
                    " txt_queries=" + std::to_string(txtCount);

                m_impl->AddAlert("dns_txt_anomaly",
                                 "Excessive TXT queries to " + parts.baseDomain +
                                     " (" + std::to_string(txtCount) +
                                     " queries — potential DNS tunneling via TXT records)",
                                 0.65f,
                                 evidence);

                m_impl->hasDnsTunnelingDetected = true;
            }
        }
    }

    // --- CNAME chain depth analysis ---
    if (record.cnameDepth > kDnsCnameDepthThreshold) {
        std::string evidence =
            "domain=" + record.domain +
            " cname_depth=" + std::to_string(record.cnameDepth);

        m_impl->AddAlert("dns_cname_depth",
                         "Deep CNAME chain for " + record.domain +
                             " (depth=" + std::to_string(record.cnameDepth) +
                             " — possible domain fronting or evasion)",
                         0.5f + 0.1f * static_cast<float>(
                             record.cnameDepth - kDnsCnameDepthThreshold),
                         evidence);
    }

    // --- Query volume per unique domain ---
    {
        DomainParts parts = ParseDomain(record.domain);
        if (parts.valid && !parts.baseDomain.empty()) {
            auto& vol = m_impl->dnsQueryVolume[parts.baseDomain];
            if (vol < UINT32_MAX) ++vol;

            if (vol == kDnsQueryVolPerDomainThreshold) {
                std::string evidence =
                    "domain=" + parts.baseDomain +
                    " query_count=" + std::to_string(vol);

                m_impl->AddAlert("dns_high_volume",
                                 "High DNS query volume to " + parts.baseDomain +
                                     " (" + std::to_string(vol) +
                                     " queries — possible DNS-based C2 or tunneling)",
                                 0.6f,
                                 evidence);
            }
        }
    }

    // --- Subdomain enumeration detection ---
    {
        DomainParts parts = ParseDomain(record.domain);
        if (parts.valid && !parts.subdomain.empty() && !parts.baseDomain.empty()) {
            auto& subSet = m_impl->subdomainTracker[parts.baseDomain];
            if (subSet.size() >= kDnsSubdomainEnumThreshold) {
                if (AreSubdomainsSequential(subSet)) {
                    std::string evidence =
                        "base_domain=" + parts.baseDomain +
                        " subdomain_count=" + std::to_string(subSet.size()) +
                        " pattern=sequential";

                    m_impl->AddAlert("dns_subdomain_enum",
                                     "Sequential subdomain enumeration detected under " +
                                         parts.baseDomain + " (" +
                                         std::to_string(subSet.size()) +
                                         " subdomains with sequential pattern)",
                                     0.7f,
                                     evidence);
                }
            }
        }
    }
}

// ---------- OnHttpRequestEx -----------------------------------------------

void NetworkBehaviorAnalyzer::OnHttpRequestEx(const HTTPRequest& request) noexcept
{
    if (!m_impl) return;

    m_impl->Tick();

    // Feed into existing HTTP analysis
    OnHttpRequest(request.method, request.url, request.userAgent);

    // Run HTTP header analysis
    float headerScore = AnalyzeHTTPHeaders(request);
    if (headerScore > 0.5f) {
        std::string truncatedUA = request.userAgent;
        if (truncatedUA.size() > 200) {
            truncatedUA.resize(200);
            truncatedUA += "...";
        }

        std::string evidence =
            "method=" + request.method +
            " url=" + request.url +
            " user_agent=\"" + truncatedUA + "\"" +
            " header_score=" + std::to_string(headerScore);

        m_impl->AddAlert("http_header_anomaly",
                         "Anomalous HTTP headers in " + request.method + " " +
                             request.url + " (score=" +
                             std::to_string(headerScore) + ")",
                         headerScore,
                         evidence);
    }
}

// ---------- OnPeerDiscovery -----------------------------------------------

void NetworkBehaviorAnalyzer::OnPeerDiscovery(
    uint32_t processId,
    const std::string& sourceAddr,
    const std::vector<std::string>& discoveredAddrs) noexcept
{
    if (!m_impl) return;
    if (processId == 0 || sourceAddr.empty()) return;

    uint64_t ts = m_impl->Tick();

    if (m_impl->peerDiscoveries.size() < kMaxPeerConnections) {
        PeerDiscoveryRecord rec;
        rec.processId      = processId;
        rec.sourceAddr     = sourceAddr;
        rec.timestamp      = ts;

        // Cap the number of discovered addresses stored per record
        size_t count = discoveredAddrs.size();
        if (count > 256) count = 256;
        rec.discoveredAddrs.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            rec.discoveredAddrs.push_back(discoveredAddrs[i]);
        }

        m_impl->peerDiscoveries.push_back(std::move(rec));
    }

    // Track in connection graph
    auto& procConns = m_impl->processConnGraph[processId];
    for (const auto& addr : discoveredAddrs) {
        if (procConns.size() >= kMaxPeerConnections) break;
        procConns.insert(addr);
    }

    // Check for P2P peer discovery pattern:
    // process connects to A, then response from A reveals B,C,D → process connects to B,C,D
    if (discoveredAddrs.size() >= kP2PPeerDiscoveryMinPeers) {
        m_impl->hasP2PDetected = true;

        std::string evidence =
            "process=" + std::to_string(processId) +
            " source=" + sourceAddr +
            " discovered_peers=" + std::to_string(discoveredAddrs.size());

        m_impl->AddAlert("p2p_peer_discovery",
                         "P2P peer discovery pattern: process " +
                             std::to_string(processId) +
                             " obtained " + std::to_string(discoveredAddrs.size()) +
                             " new peer addresses from " + sourceAddr,
                         0.7f,
                         evidence);
    }
}

// ============================================================================
// Advanced Analysis Methods
// ============================================================================

// ---------- AnalyzeForC2 --------------------------------------------------

C2DetectionResult NetworkBehaviorAnalyzer::AnalyzeForC2(
    const NetworkEvent& event) noexcept
{
    C2DetectionResult result;
    if (!m_impl) return result;

    float bestConfidence = 0.0f;
    const char* bestFramework = nullptr;
    const char* bestType = nullptr;
    std::string bestEvidence;

    for (size_t i = 0; i < kNumC2Signatures; ++i) {
        const auto& sig = kC2Signatures[i];
        bool matched = false;
        std::string matchDetail;

        if (std::strcmp(sig.matchField, "path") == 0) {
            // Match against HTTP path
            if (!event.httpPath.empty()) {
                if (StringContainsCaseInsensitive(event.httpPath, sig.pattern)) {
                    matched = true;
                    matchDetail = "path=" + event.httpPath;
                }
            }
        } else if (std::strcmp(sig.matchField, "cookie") == 0) {
            // Match against HTTP cookie header
            if (!event.httpCookie.empty()) {
                if (StringContainsCaseInsensitive(event.httpCookie, sig.pattern)) {
                    matched = true;
                    matchDetail = "cookie_match";
                }
            }
            // Also check headers
            for (const auto& [hdrName, hdrVal] : event.httpHeaders) {
                if (StringContainsCaseInsensitive(hdrName, "cookie") &&
                    StringContainsCaseInsensitive(hdrVal, sig.pattern)) {
                    matched = true;
                    matchDetail = "cookie_header_match";
                    break;
                }
            }
        } else if (std::strcmp(sig.matchField, "content_type") == 0) {
            if (!event.httpContentType.empty()) {
                if (StringContainsCaseInsensitive(event.httpContentType, sig.pattern)) {
                    matched = true;
                    matchDetail = "content_type=" + event.httpContentType;
                }
            }
        } else if (std::strcmp(sig.matchField, "pipe") == 0) {
            if (!event.namedPipePath.empty()) {
                if (StringContainsCaseInsensitive(event.namedPipePath, sig.pattern)) {
                    matched = true;
                    matchDetail = "pipe=" + event.namedPipePath;
                }
            }
        } else if (std::strcmp(sig.matchField, "dns_pattern") == 0) {
            if (!event.dnsQueryDomain.empty()) {
                if (StringContainsCaseInsensitive(event.dnsQueryDomain, sig.pattern)) {
                    matched = true;
                    matchDetail = "dns=" + event.dnsQueryDomain;
                }
            }
        } else if (std::strcmp(sig.matchField, "port") == 0) {
            if (PortMatchesPattern(event.remotePort, sig.pattern)) {
                matched = true;
                matchDetail = "port=" + std::to_string(event.remotePort);
            }
        }

        if (matched && sig.confidence > bestConfidence) {
            bestConfidence = sig.confidence;
            bestFramework = sig.frameworkName;
            bestType = sig.patternType;
            bestEvidence = "framework=" + std::string(sig.frameworkName) +
                           " type=" + std::string(sig.patternType) +
                           " " + matchDetail;
        }
    }

    if (bestConfidence > 0.3f && bestFramework != nullptr && bestType != nullptr) {
        result.detected      = true;
        result.frameworkName  = bestFramework;
        result.matchType      = bestType;
        result.confidence     = bestConfidence;
        result.evidence       = bestEvidence;
    }

    return result;
}

// ---------- AnalyzeTLSCert ------------------------------------------------

TLSAnomalyResult NetworkBehaviorAnalyzer::AnalyzeTLSCert(
    const TLSCertInfo& cert) noexcept
{
    TLSAnomalyResult result;

    float score = 0.0f;

    // Self-signed certificate: strong anomaly signal
    if (cert.selfSigned) {
        score += 0.4f;
        result.selfSignedCert = true;
    }

    // Very short validity period (<30 days): staging/throwaway cert
    if (cert.shortValidity && cert.validityDays < 30) {
        score += 0.3f;
        result.tooShortValidity = true;
    } else if (cert.shortValidity) {
        // 30-90 day validity is mildly suspicious
        score += 0.15f;
        result.tooShortValidity = true;
    }

    // IP address in CN: almost never legitimate for real services
    if (cert.ipAddressCN) {
        score += 0.2f;
        result.suspiciousCN = true;
    }

    // Recently created certificate (<30 days old)
    if (cert.recentlyCreated) {
        score += 0.2f;
        result.certAgeTooNew = true;
    }

    // Known C2 issuer patterns
    if (IsKnownC2Issuer(cert.issuer) || IsKnownC2Issuer(cert.commonName)) {
        score += 0.3f;
        result.knownC2Issuer = true;
    }

    // Empty or placeholder CN
    if (cert.commonName.empty() || cert.commonName == "localhost" ||
        cert.commonName == "server" || cert.commonName == "test") {
        score += 0.15f;
        result.suspiciousCN = true;
    }

    // Clamp to [0.0, 1.0]
    if (score > 1.0f) score = 1.0f;
    result.anomalyScore = score;

    return result;
}

// ---------- CheckJA3 ------------------------------------------------------

JA3MatchResult NetworkBehaviorAnalyzer::CheckJA3(
    const std::string& hash) noexcept
{
    JA3MatchResult result;
    if (hash.empty() || hash.size() != 32) return result;

    for (size_t i = 0; i < kNumJA3Entries; ++i) {
        const auto& entry = kJA3Database[i];

        // Compare 32-character MD5 hex strings
        bool match = true;
        for (size_t j = 0; j < 32; ++j) {
            if (ToLowerChar(hash[j]) != entry.hash[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            result.matched       = true;
            result.hash          = hash;
            result.malwareFamily = entry.malwareFamily;
            result.confidence    = entry.confidence;
            return result;
        }
    }

    return result;
}

// ---------- AnalyzePeerBehavior -------------------------------------------

float NetworkBehaviorAnalyzer::AnalyzePeerBehavior(uint32_t processId) noexcept
{
    if (!m_impl) return 0.0f;
    if (processId == 0) return 0.0f;

    float score = 0.0f;

    // Check 1: Number of unique persistent connections from this process
    auto graphIt = m_impl->processConnGraph.find(processId);
    if (graphIt != m_impl->processConnGraph.end()) {
        uint32_t uniquePeers = static_cast<uint32_t>(graphIt->second.size());

        if (uniquePeers > kP2PPersistentConnThreshold) {
            // Score scales with number of peers
            float peerFactor = static_cast<float>(uniquePeers) /
                               static_cast<float>(kP2PPersistentConnThreshold);
            if (peerFactor > 5.0f) peerFactor = 5.0f;
            score += 0.2f * peerFactor;
        }
    }

    // Check 2: Peer discovery patterns — did this process discover peers
    // through responses from other peers?
    uint32_t discoveryCount = 0;
    uint32_t totalDiscoveredPeers = 0;
    for (const auto& disc : m_impl->peerDiscoveries) {
        if (disc.processId == processId) {
            ++discoveryCount;
            totalDiscoveredPeers += static_cast<uint32_t>(disc.discoveredAddrs.size());
        }
    }

    if (discoveryCount > 0) {
        score += 0.3f;

        if (totalDiscoveredPeers > 10) {
            score += 0.2f;
        }
    }

    // Check 3: Does the process connect to discovered addresses?
    // (Cross-reference discovery records with connection graph)
    if (graphIt != m_impl->processConnGraph.end() && discoveryCount > 0) {
        uint32_t connectBackCount = 0;
        for (const auto& disc : m_impl->peerDiscoveries) {
            if (disc.processId != processId) continue;
            for (const auto& discoveredAddr : disc.discoveredAddrs) {
                if (graphIt->second.count(discoveredAddr) > 0) {
                    ++connectBackCount;
                }
            }
        }

        if (connectBackCount >= kP2PPeerDiscoveryMinPeers) {
            score += 0.3f;  // Strong P2P indicator: connecting to discovered peers
        }
    }

    // Clamp
    if (score > 1.0f) score = 1.0f;

    // If score crosses threshold, set the detection flag and alert
    if (score >= kP2PHighScore && !m_impl->hasP2PDetected) {
        m_impl->hasP2PDetected = true;

        uint32_t peerCount = 0;
        if (graphIt != m_impl->processConnGraph.end()) {
            peerCount = static_cast<uint32_t>(graphIt->second.size());
        }

        std::string evidence =
            "process=" + std::to_string(processId) +
            " unique_peers=" + std::to_string(peerCount) +
            " discovery_events=" + std::to_string(discoveryCount) +
            " discovered_total=" + std::to_string(totalDiscoveredPeers) +
            " score=" + std::to_string(score);

        m_impl->AddAlert("p2p_botnet",
                         "P2P botnet communication pattern detected for process " +
                             std::to_string(processId) + " (" +
                             std::to_string(peerCount) + " unique peers, score=" +
                             std::to_string(score) + ")",
                         score,
                         evidence);
    }

    return score;
}

// ---------- AnalyzeHTTPHeaders --------------------------------------------

float NetworkBehaviorAnalyzer::AnalyzeHTTPHeaders(
    const HTTPRequest& request) noexcept
{
    if (!m_impl) return 0.0f;

    float score = 0.0f;

    // --- User-Agent analysis ---

    // Empty User-Agent
    if (request.userAgent.empty()) {
        score += 0.3f;
    }
    // Very short UA (single word or abbreviated)
    else if (request.userAgent.size() < 10) {
        score += 0.2f;
    }
    // Known suspicious "Mozilla/4.0" only (no extended info)
    else if (request.userAgent.size() < 30 &&
             StringContainsCaseInsensitive(request.userAgent, "Mozilla/4.0")) {
        score += 0.15f;
    }
    // Excessively long User-Agent (may be used to exfil data)
    else if (request.userAgent.size() > kMaxUserAgentLen) {
        score += 0.2f;
    }

    // --- Missing standard headers ---
    uint32_t missingStandard = 0;
    for (size_t i = 0; i < kNumExpectedHeaders; ++i) {
        bool found = false;
        for (const auto& [hdrName, hdrVal] : request.headers) {
            if (StringContainsCaseInsensitive(hdrName, kExpectedHeaders[i])) {
                found = true;
                break;
            }
        }
        if (!found) {
            ++missingStandard;
        }
    }

    if (missingStandard >= kMinExpectedHeaders) {
        score += 0.2f;
    } else if (missingStandard >= 2) {
        score += 0.1f;
    }

    // --- Known C2 custom headers ---
    for (const auto& [hdrName, hdrVal] : request.headers) {
        for (size_t i = 0; i < kNumC2HeaderPatterns; ++i) {
            if (StringContainsCaseInsensitive(hdrName, kC2HeaderPatterns[i].headerName)) {
                score += kC2HeaderPatterns[i].confidence * 0.5f;
                break;
            }
        }
    }

    // --- POST body analysis ---
    if (!request.body.empty() &&
        (request.method == "POST" || request.method == "PUT")) {

        // Base64-encoded body
        if (LooksLikeBase64(request.body)) {
            score += 0.2f;
        }

        // High-entropy body (encrypted data)
        if (LooksLikeEncryptedBlob(request.body)) {
            score += 0.25f;
        }
    }

    // Clamp to [0.0, 1.0]
    if (score > 1.0f) score = 1.0f;

    return score;
}

} // namespace Phantom
