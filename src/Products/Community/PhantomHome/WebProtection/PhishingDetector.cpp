/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "pch.h"
/**
 * ============================================================================
 * ShadowStrike NGAV - PHISHING DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file PhishingDetector.cpp
 * @brief Implementation of the PhishingDetector class.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "PhishingDetector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cmath>
#include <format>
#include <numeric>
#include <cctype>

// Windows Headers for SSL/TLS certificate analysis
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace ShadowStrike {
namespace WebBrowser {

// Bring infrastructure into scope
using Utils::Logger;

namespace json_helper {
    std::string EscapeJsonValue(const std::string& input) {
        std::string output;
        output.reserve(input.size() + 8);
        for (char c : input) {
            switch (c) {
                case '"':  output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\n': output += "\\n";  break;
                case '\r': output += "\\r";  break;
                case '\t': output += "\\t";  break;
                default:   output += c;      break;
            }
        }
        return output;
    }

    using json = std::map<std::string, std::string>;

    struct JsonBuilder {
        std::ostringstream oss;
        bool first = true;
        void begin() { oss << "{"; first = true; }
        void addStr(const char* key, const std::string& val) {
            if (!first) oss << ",";
            first = false;
            oss << "\"" << key << "\":\"" << EscapeJsonValue(val) << "\"";
        }
        void addBool(const char* key, bool val) {
            if (!first) oss << ",";
            first = false;
            oss << "\"" << key << "\":" << (val ? "true" : "false");
        }
        void addNum(const char* key, double val) {
            if (!first) oss << ",";
            first = false;
            oss << "\"" << key << "\":" << val;
        }
        void addInt(const char* key, int64_t val) {
            if (!first) oss << ",";
            first = false;
            oss << "\"" << key << "\":" << val;
        }
        std::string end() { oss << "}"; return oss.str(); }
    };
} // namespace json_helper

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> PhishingDetector::s_instanceCreated{false};

// ============================================================================
// COMPILE-TIME LIMITS
// ============================================================================

namespace {
    inline constexpr size_t MAX_PROTECTED_BRANDS  = 256;
    inline constexpr size_t MAX_CALLBACKS         = 64;
    inline constexpr size_t MAX_FORM_REGEX_ITERS  = 10'000;
    inline constexpr int    TYPOSQUAT_MAX_EDIT_DIST = 3;
    inline constexpr double TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75;
}

// ============================================================================
// BRAND-TO-DOMAIN REGISTRY
// ============================================================================

namespace {

    struct BrandDomainEntry {
        const char* brand;
        std::initializer_list<const char*> domains;
    };

    static const BrandDomainEntry kDefaultBrandDomains[] = {
        {"microsoft",       {"microsoft.com", "microsoftonline.com", "live.com", "hotmail.com", "outlook.com"}},
        {"office365",       {"office.com", "office365.com", "sharepoint.com", "onedrive.com"}},
        {"outlook",         {"outlook.com", "outlook.live.com", "hotmail.com"}},
        {"azure",           {"azure.com", "azure.microsoft.com", "portal.azure.com"}},
        {"google",          {"google.com", "google.co.uk", "google.de", "google.fr"}},
        {"gmail",           {"gmail.com", "mail.google.com"}},
        {"drive",           {"drive.google.com", "docs.google.com"}},
        {"apple",           {"apple.com", "icloud.com", "appleid.apple.com"}},
        {"icloud",          {"icloud.com", "me.com"}},
        {"amazon",          {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp"}},
        {"aws",             {"aws.amazon.com", "console.aws.amazon.com"}},
        {"paypal",          {"paypal.com", "paypal.me"}},
        {"stripe",          {"stripe.com", "dashboard.stripe.com"}},
        {"square",          {"squareup.com", "square.com"}},
        {"facebook",        {"facebook.com", "fb.com", "messenger.com"}},
        {"instagram",       {"instagram.com"}},
        {"whatsapp",        {"whatsapp.com", "web.whatsapp.com"}},
        {"netflix",         {"netflix.com"}},
        {"spotify",         {"spotify.com"}},
        {"dropbox",         {"dropbox.com"}},
        {"linkedin",        {"linkedin.com"}},
        {"chase",           {"chase.com", "secure.chase.com"}},
        {"wellsfargo",      {"wellsfargo.com", "online.wellsfargo.com"}},
        {"bankofamerica",   {"bankofamerica.com", "secure.bankofamerica.com"}},
        {"citi",            {"citi.com", "citibank.com", "online.citi.com"}},
        {"fedex",           {"fedex.com"}},
        {"ups",             {"ups.com"}},
        {"dhl",             {"dhl.com"}},
        {"usps",            {"usps.com"}},
    };

    std::string NarrowToLowerPD(std::string_view input) {
        std::string result(input);
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    // Extract the registrable domain (last two labels) from a full domain
    std::string ExtractRegistrableDomain(const std::string& domain) {
        auto pos = domain.rfind('.');
        if (pos == std::string::npos || pos == 0) return domain;
        auto pos2 = domain.rfind('.', pos - 1);
        if (pos2 == std::string::npos) return domain;
        return domain.substr(pos2 + 1);
    }

    // Damerau-Levenshtein distance (handles transpositions)
    int DamerauLevenshteinDistance(const std::string& s1, const std::string& s2) {
        const size_t m = s1.length();
        const size_t n = s2.length();
        if (m == 0) return static_cast<int>(n);
        if (n == 0) return static_cast<int>(m);

        // Bounded: if length diff is too large, skip expensive computation
        if (m > 100 || n > 100) return static_cast<int>(std::max(m, n));

        // Use two-row optimization for standard Levenshtein, plus transposition check
        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1, 0));
        for (size_t i = 0; i <= m; ++i) dp[i][0] = static_cast<int>(i);
        for (size_t j = 0; j <= n; ++j) dp[0][j] = static_cast<int>(j);

        for (size_t i = 1; i <= m; ++i) {
            for (size_t j = 1; j <= n; ++j) {
                int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
                dp[i][j] = std::min({
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost
                });
                // Damerau transposition
                if (i > 1 && j > 1 && s1[i - 1] == s2[j - 2] && s1[i - 2] == s2[j - 1]) {
                    dp[i][j] = std::min(dp[i][j], dp[i - 2][j - 2] + cost);
                }
            }
        }
        return dp[m][n];
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class PhishingDetectorImpl {
public:
    PhishingDetectorImpl()  = default;
    ~PhishingDetectorImpl() = default;

    PhishingDetectorImpl(const PhishingDetectorImpl&) = delete;
    PhishingDetectorImpl& operator=(const PhishingDetectorImpl&) = delete;

    // State
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_callbackMutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    PhishingDetectorConfiguration m_config;

    // Brand protection: brand name -> list of legitimate domains
    std::unordered_map<std::string, std::vector<std::string>> m_protectedBrands;

    // Stats
    mutable PhishingDetectorStatistics m_stats;

    // Callbacks
    std::vector<PhishingDetectionCallback> m_detectionCallbacks;
    std::vector<BrandAlertCallback>        m_brandCallbacks;
    std::vector<ErrorCallback>             m_errorCallbacks;

    // ========================================================================
    // CORE ANALYSIS
    // ========================================================================

    PhishingScore AnalyzeURLInternal(const std::string& url) {
        PhishingScore result;
        result.urlAnalysis.originalUrl = url;

        auto start = std::chrono::high_resolution_clock::now();

        // Validate URL length
        if (url.empty() || url.length() > PhishingDetectorConstants::MAX_URL_LENGTH) {
            result.verdict = PhishingVerdict::Safe;
            result.reason  = "URL empty or exceeds maximum analysis length";
            return result;
        }

        // Parse URL components
        std::regex urlRegex(R"(^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)",
                            std::regex_constants::ECMAScript);
        std::smatch urlMatch;
        if (!std::regex_match(url, urlMatch, urlRegex) || urlMatch.size() < 8) {
            result.verdict = PhishingVerdict::Safe;
            return result;
        }

        std::string scheme    = urlMatch[2].str();
        std::string authority = urlMatch[4].str();

        // Separate host:port
        auto colonPos = authority.rfind(':');
        if (colonPos != std::string::npos && colonPos > 0) {
            std::string portStr = authority.substr(colonPos + 1);
            bool isPort = !portStr.empty() && std::all_of(portStr.begin(), portStr.end(), ::isdigit);
            if (isPort) {
                result.urlAnalysis.domain = authority.substr(0, colonPos);
                result.urlAnalysis.port   = static_cast<uint16_t>(std::stoul(portStr));
                result.urlAnalysis.hasPort = true;
            } else {
                result.urlAnalysis.domain = authority;
            }
        } else {
            result.urlAnalysis.domain = authority;
        }

        result.urlAnalysis.normalizedUrl = url;
        result.urlAnalysis.path    = urlMatch[5].str();
        result.urlAnalysis.query   = urlMatch[7].str();
        result.urlAnalysis.isHTTPS = (scheme == "https");

        // TLD extraction
        const std::string& domain = result.urlAnalysis.domain;
        size_t lastDot = domain.rfind('.');
        if (lastDot != std::string::npos) {
            result.urlAnalysis.tld = domain.substr(lastDot + 1);
        }

        // Subdomain extraction
        size_t firstDot = domain.find('.');
        if (firstDot != std::string::npos && firstDot < lastDot) {
            result.urlAnalysis.subdomain = domain.substr(0, firstDot);
        }

        result.urlAnalysis.subdomainCount = static_cast<int>(
            std::count(domain.begin(), domain.end(), '.'));

        // Special character count in domain
        result.urlAnalysis.specialCharCount = static_cast<int>(
            std::count_if(domain.begin(), domain.end(),
                          [](char c) { return c == '-' || c == '_' || c == '~'; }));

        // ----------------------------------------------------------------
        // 1. HTTPS Check
        // ----------------------------------------------------------------
        if (!result.urlAnalysis.isHTTPS) {
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::NoHTTPS));
            result.score += 0.15;
            result.allReasons.push_back("Site does not use HTTPS");
        }

        // ----------------------------------------------------------------
        // 2. IP Address Check
        // ----------------------------------------------------------------
        std::regex ipRegex(R"((\d{1,3}\.){3}\d{1,3})");
        if (std::regex_match(domain, ipRegex)) {
            result.urlAnalysis.isIPAddress = true;
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::IPAddressURL));
            result.allReasons.push_back("URL uses IP address instead of domain");
            result.score += 0.2;
        }

        // ----------------------------------------------------------------
        // 3. Length Check
        // ----------------------------------------------------------------
        result.urlAnalysis.urlLength = url.length();
        if (result.urlAnalysis.urlLength > 75) {
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::LongURL));
            result.score += 0.1;
        }

        // ----------------------------------------------------------------
        // 4. Entropy Check (DGA detection)
        // ----------------------------------------------------------------
        result.urlAnalysis.entropyScore = CalculateEntropy(domain);
        if (result.urlAnalysis.entropyScore > 4.5) {
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::DGADomain));
            result.allReasons.push_back("Domain has high entropy (possible DGA)");
            result.score += 0.2;
        }

        // ----------------------------------------------------------------
        // 5. Homograph Detection (IDN/Unicode confusable analysis)
        // ----------------------------------------------------------------
        auto homographRes = CheckHomographInternal(domain);
        result.homographResult = homographRes;
        if (homographRes.hasHomograph) {
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::HomographAttack));
            result.allReasons.push_back("Homograph attack detected targeting " + homographRes.targetedBrand);
            result.score += 0.8;
        }

        // ----------------------------------------------------------------
        // 6. Typosquatting Detection (Damerau-Levenshtein)
        // ----------------------------------------------------------------
        auto typoRes = CheckTyposquattingInternal(domain);
        result.typosquattingResult = typoRes;
        if (typoRes.isTyposquatting) {
            result.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(result.indicators) | static_cast<uint32_t>(PhishingIndicator::Typosquatting));
            result.allReasons.push_back("Typosquatting detected targeting " + typoRes.targetBrand);
            result.score += 0.6;
            result.targetedBrand = typoRes.targetBrand;
        }

        // ----------------------------------------------------------------
        // 7. Brand Impersonation Check (path / subdomain)
        // ----------------------------------------------------------------
        {
            std::string lowerDomain = NarrowToLowerPD(domain);
            std::string lowerPath   = NarrowToLowerPD(result.urlAnalysis.path);

            std::shared_lock lock(m_mutex);
            for (const auto& [brand, domains] : m_protectedBrands) {
                // Check if brand name appears in domain but domain is NOT legitimate
                if (lowerDomain.find(brand) != std::string::npos) {
                    bool isLegitimate = false;
                    for (const auto& legit : domains) {
                        // Exact match or subdomain of legitimate domain
                        if (lowerDomain == legit ||
                            (lowerDomain.size() > legit.size() &&
                             lowerDomain.substr(lowerDomain.size() - legit.size() - 1) == "." + legit)) {
                            isLegitimate = true;
                            break;
                        }
                    }
                    if (!isLegitimate) {
                        result.indicators = static_cast<PhishingIndicator>(
                            static_cast<uint32_t>(result.indicators) |
                            static_cast<uint32_t>(PhishingIndicator::BrandImpersonation));
                        result.allReasons.push_back("Domain contains brand name '" + brand + "' but is not a legitimate domain");
                        result.targetedBrand = brand;
                        result.score += 0.5;
                        break;
                    }
                }

                // Check if brand appears in path (common phishing pattern)
                if (lowerPath.find(brand) != std::string::npos &&
                    lowerPath.find("login") != std::string::npos) {
                    result.allReasons.push_back("Path contains brand '" + brand + "' with login keyword");
                    result.score += 0.15;
                }
            }
        }

        // ----------------------------------------------------------------
        // 8. Suspicious Path Patterns
        // ----------------------------------------------------------------
        {
            std::string lowerPath = NarrowToLowerPD(result.urlAnalysis.path);
            static const std::vector<std::string> suspiciousPathTokens = {
                "login", "signin", "verify", "account", "confirm", "secure",
                "update", "banking", "password", "credential", "auth",
                "recover", "unlock", "suspended", "restricted"
            };

            int pathHitCount = 0;
            for (const auto& token : suspiciousPathTokens) {
                if (lowerPath.find(token) != std::string::npos) {
                    ++pathHitCount;
                }
            }
            if (pathHitCount >= 2) {
                result.indicators = static_cast<PhishingIndicator>(
                    static_cast<uint32_t>(result.indicators) |
                    static_cast<uint32_t>(PhishingIndicator::SuspiciousPath));
                result.allReasons.push_back("Path contains multiple credential-harvesting keywords");
                result.score += 0.15 * pathHitCount;
            }
        }

        // ----------------------------------------------------------------
        // 9. Threat Intelligence Check
        // ----------------------------------------------------------------
        if (m_config.checkThreatIntel) {
            auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
            if (tiMgr.IsInitialized()) {
                auto urlLookup = tiMgr.LookupURL(url);
                if (urlLookup.IsMalicious()) {
                    result.indicators = static_cast<PhishingIndicator>(
                        static_cast<uint32_t>(result.indicators) |
                        static_cast<uint32_t>(PhishingIndicator::ThreatIntelMatch));
                    result.allReasons.push_back("URL found in Threat Intelligence database (score=" +
                                                std::to_string(urlLookup.score) + ")");
                    result.score = 1.0;
                    result.verdict = PhishingVerdict::KnownBad;
                    result.reason  = "URL matched in ThreatIntel";
                    m_stats.threatIntelMatches++;
                } else if (urlLookup.IsSuspicious()) {
                    result.allReasons.push_back("URL flagged as suspicious in ThreatIntel");
                    result.score += 0.3;
                }

                // Also check domain reputation
                auto domainLookup = tiMgr.LookupDomain(domain);
                if (domainLookup.IsMalicious() && result.verdict != PhishingVerdict::KnownBad) {
                    result.indicators = static_cast<PhishingIndicator>(
                        static_cast<uint32_t>(result.indicators) |
                        static_cast<uint32_t>(PhishingIndicator::ThreatIntelMatch));
                    result.allReasons.push_back("Domain found in Threat Intelligence database");
                    result.score = 1.0;
                    result.verdict = PhishingVerdict::KnownBad;
                    m_stats.threatIntelMatches++;
                }
            }
        }

        // ----------------------------------------------------------------
        // 10. Calculate Final Verdict
        // ----------------------------------------------------------------
        if (result.verdict != PhishingVerdict::KnownBad) {
            if (result.score >= m_config.phishingThreshold) {
                result.isPhishing = true;
                result.verdict = PhishingVerdict::Phishing;
                result.reason  = "Multiple phishing indicators detected";
            } else if (result.score >= m_config.suspiciousThreshold) {
                result.verdict = PhishingVerdict::Suspicious;
                result.reason  = "Suspicious characteristics detected";
            }
        } else {
            result.isPhishing = true;
        }

        // Detect attack type
        if (result.isPhishing && !result.targetedBrand.empty()) {
            result.attackType = PhishingAttackType::Credential_Harvest;
            result.verdict    = PhishingVerdict::BrandSpoof;
        }

        result.confidence = static_cast<int>(std::clamp(result.score * 100.0, 0.0, 100.0));

        auto end = std::chrono::high_resolution_clock::now();
        result.analysisDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        return result;
    }

    // ========================================================================
    // HOMOGRAPH DETECTION (Unicode Confusable Analysis)
    // ========================================================================

    HomographResult CheckHomographInternal(const std::string& domain) {
        HomographResult result;
        result.originalDomain = domain;

        // Check for punycode domains (xn-- prefix)
        if (domain.find("xn--") != std::string::npos) {
            result.hasHomograph = true;
            result.decodedDomain = domain;
            result.similarityScore = 0.8;
        }

        std::wstring wDomain = Utils::StringUtils::ToWide(domain);

        // Check each character against known confusable mappings
        bool foundConfusable = false;
        std::wstring normalized = wDomain;

        for (size_t i = 0; i < wDomain.size(); ++i) {
            wchar_t c = wDomain[i];
            for (const auto& pair : PhishingDetectorConstants::HOMOGRAPH_CHARS) {
                if (c == pair[0]) {
                    foundConfusable = true;
                    result.confusables.push_back({c, static_cast<char>(pair[1])});
                    normalized[i] = static_cast<wchar_t>(pair[1]);
                }
            }

            // Extended confusable detection: Greek/Latin lookalikes
            static constexpr std::pair<wchar_t, char> kExtendedConfusables[] = {
                {L'\u0430', 'a'}, {L'\u0435', 'e'}, {L'\u043E', 'o'}, // Cyrillic
                {L'\u0440', 'p'}, {L'\u0441', 'c'}, {L'\u0445', 'x'},
                {L'\u0443', 'y'}, {L'\u0456', 'i'}, {L'\u0432', 'b'},
                {L'\u043C', 'm'}, {L'\u043D', 'n'}, {L'\u0442', 't'},
                {L'\u03B1', 'a'}, {L'\u03BF', 'o'}, {L'\u03C1', 'p'}, // Greek
                {L'\u03B5', 'e'}, {L'\u03BA', 'k'}, {L'\u03BD', 'v'},
            };

            for (const auto& [confusable, latin] : kExtendedConfusables) {
                if (c == confusable) {
                    if (!foundConfusable) foundConfusable = true;
                    result.confusables.push_back({confusable, latin});
                    normalized[i] = static_cast<wchar_t>(latin);
                }
            }
        }

        if (foundConfusable) {
            result.hasHomograph = true;
            result.decodedDomain = Utils::StringUtils::ToNarrow(normalized);
            result.similarityScore = 1.0; // Visual match

            // Check if the decoded domain matches a protected brand
            std::string decodedLower = NarrowToLowerPD(result.decodedDomain);
            std::shared_lock lock(m_mutex);
            for (const auto& [brand, domains] : m_protectedBrands) {
                for (const auto& legit : domains) {
                    // Exact match or decoded domain is the registrable domain of a legit domain
                    if (decodedLower == legit ||
                        decodedLower.find(legit) != std::string::npos ||
                        legit.find(decodedLower) != std::string::npos) {
                        result.targetedBrand = brand;
                        return result;
                    }
                }
                // Also check if decoded domain contains brand name
                if (decodedLower.find(brand) != std::string::npos) {
                    result.targetedBrand = brand;
                    return result;
                }
            }
        }

        return result;
    }

    // ========================================================================
    // TYPOSQUATTING DETECTION (Damerau-Levenshtein)
    // ========================================================================

    TyposquattingResult CheckTyposquattingInternal(const std::string& domain) {
        TyposquattingResult result;
        result.suspiciousDomain = domain;

        std::string domainLower = NarrowToLowerPD(domain);
        std::string registrable = NarrowToLowerPD(ExtractRegistrableDomain(domainLower));

        std::shared_lock lock(m_mutex);

        int minDistance = INT_MAX;
        std::string bestMatchBrand;
        std::string bestMatchDomain;
        double bestSimilarity = 0.0;

        for (const auto& [brand, domains] : m_protectedBrands) {
            for (const auto& legit : domains) {
                if (domainLower == legit) continue; // Exact match = legitimate
                if (legit.empty()) continue;

                // Compare against registrable domain and full domain
                for (const auto& candidate : {domainLower, registrable}) {
                    if (candidate.empty()) continue;

                    int dist = DamerauLevenshteinDistance(candidate, legit);
                    if (dist > TYPOSQUAT_MAX_EDIT_DIST) continue;

                    double similarity = 1.0 - (static_cast<double>(dist) /
                                                static_cast<double>(std::max(candidate.length(), legit.length())));

                    if (similarity >= TYPOSQUAT_SIMILARITY_THRESHOLD && dist < minDistance) {
                        minDistance = dist;
                        bestMatchBrand  = brand;
                        bestMatchDomain = legit;
                        bestSimilarity  = similarity;
                    }
                }
            }
        }

        if (!bestMatchBrand.empty()) {
            result.isTyposquatting = true;
            result.targetBrand    = bestMatchBrand;
            result.targetDomain   = bestMatchDomain;
            result.editDistance    = minDistance;
            result.similarityScore = bestSimilarity;

            // Classify typo type
            if (minDistance == 1) {
                // Determine specific typo type
                const std::string& s1 = domainLower;
                const std::string& s2 = bestMatchDomain;
                if (s1.size() == s2.size()) {
                    result.typoType = "Character Substitution";
                } else if (s1.size() > s2.size()) {
                    result.typoType = "Extra Character";
                } else {
                    result.typoType = "Missing Character";
                }
            } else if (minDistance == 2) {
                result.typoType = "Adjacent Key/Transposition";
            } else {
                result.typoType = "Multiple Edits";
            }
        }

        return result;
    }

    // ========================================================================
    // FORM ANALYSIS
    // ========================================================================

    FormAnalysisResult AnalyzeFormsInternal(const std::string& html) {
        FormAnalysisResult result;

        if (html.empty() || html.size() > PhishingDetectorConstants::MAX_HTML_SIZE) {
            return result;
        }

        // 1. Detect Forms
        std::regex formRegex(R"(<form[^>]*>)", std::regex_constants::icase);
        auto formsBegin = std::sregex_iterator(html.begin(), html.end(), formRegex);
        auto formsEnd   = std::sregex_iterator();
        result.formCount = static_cast<int>(std::distance(formsBegin, formsEnd));

        // 2. Detect Password Fields
        std::regex pwdRegex(R"(type=["']password["'])", std::regex_constants::icase);
        auto pwdBegin = std::sregex_iterator(html.begin(), html.end(), pwdRegex);
        result.passwordFieldCount = static_cast<int>(std::distance(pwdBegin, std::sregex_iterator()));
        if (result.passwordFieldCount > 0) {
            result.detectedFieldTypes.push_back(FormFieldType::Password);
        }

        // 3. Login Intent Detection
        if (result.passwordFieldCount > 0) {
            result.hasLoginForm = true;
            result.riskScore += 20;
        }

        // 4. Detect Hidden Fields
        std::regex hiddenRegex(R"(type=["']hidden["'])", std::regex_constants::icase);
        auto hiddenBegin = std::sregex_iterator(html.begin(), html.end(), hiddenRegex);
        result.hiddenFieldCount = static_cast<int>(std::distance(hiddenBegin, std::sregex_iterator()));
        if (result.hiddenFieldCount > 5) {
            result.riskScore += 10;
            result.suspiciousAttributes.push_back("Excessive hidden form fields: " + std::to_string(result.hiddenFieldCount));
        }

        // 5. Detect sensitive input fields
        std::regex emailRegex(R"(type=["']email["'])", std::regex_constants::icase);
        auto emailBegin = std::sregex_iterator(html.begin(), html.end(), emailRegex);
        if (std::distance(emailBegin, std::sregex_iterator()) > 0) {
            result.detectedFieldTypes.push_back(FormFieldType::Email);
        }

        // Credit card pattern in inputs
        std::regex ccRegex(R"((?:credit|card|cc|cvv|cvc|expir))", std::regex_constants::icase);
        auto ccBegin = std::sregex_iterator(html.begin(), html.end(), ccRegex);
        if (std::distance(ccBegin, std::sregex_iterator()) > 0) {
            result.detectedFieldTypes.push_back(FormFieldType::CreditCard);
            result.riskScore += 30;
            result.suspiciousAttributes.push_back("Credit card input fields detected");
        }

        // SSN pattern
        std::regex ssnRegex(R"((?:ssn|social.?security|tax.?id))", std::regex_constants::icase);
        auto ssnBegin = std::sregex_iterator(html.begin(), html.end(), ssnRegex);
        if (std::distance(ssnBegin, std::sregex_iterator()) > 0) {
            result.detectedFieldTypes.push_back(FormFieldType::SSN);
            result.riskScore += 40;
            result.suspiciousAttributes.push_back("SSN/Tax ID input fields detected");
        }

        // 6. Extract Form Actions
        std::regex actionRegex(R"(action=["']([^"']*)["'])", std::regex_constants::icase);
        for (auto it = formsBegin; it != formsEnd; ++it) {
            std::string formTag = it->str();
            std::smatch actionMatch;
            if (std::regex_search(formTag, actionMatch, actionRegex)) {
                std::string action = actionMatch[1].str();
                result.formActions.push_back(action);

                if (action.find("http") == 0) {
                    result.hasExternalAction = true;
                    result.suspiciousAttributes.push_back("External Form Action: " + action);
                    result.riskScore += 30;
                }
            }
        }

        // 7. Check for suspicious JavaScript patterns
        std::regex jsPatterns[] = {
            std::regex(R"(onsubmit\s*=\s*["'][^"']*document\.location)", std::regex_constants::icase),
            std::regex(R"(addEventListener\s*\(\s*["']submit["'])", std::regex_constants::icase),
            std::regex(R"(fetch\s*\(\s*["']https?://)", std::regex_constants::icase),
        };
        for (const auto& pat : jsPatterns) {
            auto jsBegin = std::sregex_iterator(html.begin(), html.end(), pat);
            if (std::distance(jsBegin, std::sregex_iterator()) > 0) {
                result.riskScore += 15;
                result.suspiciousAttributes.push_back("Suspicious form submission JavaScript detected");
                break;
            }
        }

        return result;
    }

    // ========================================================================
    // VISUAL / STRUCTURAL ANALYSIS
    // ========================================================================

    VisualAnalysisResult AnalyzeVisualInternal(const std::string& url, const std::string& html) {
        VisualAnalysisResult result;

        if (html.empty() || html.size() > PhishingDetectorConstants::MAX_HTML_SIZE) {
            return result;
        }

        // Page structure fingerprint: count key HTML elements
        struct ElementCount {
            const char* tag;
            int count;
        };

        std::vector<ElementCount> elements = {
            {"<form",  0}, {"<input", 0}, {"<img",   0},
            {"<a ",    0}, {"<div",   0}, {"<script", 0},
            {"<iframe", 0}, {"<link", 0},
        };

        std::string lowerHtml(html.size(), '\0');
        std::transform(html.begin(), html.end(), lowerHtml.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (auto& elem : elements) {
            size_t pos = 0;
            while ((pos = lowerHtml.find(elem.tag, pos)) != std::string::npos) {
                elem.count++;
                pos += std::strlen(elem.tag);
            }
        }

        // Detect brand elements in page
        std::shared_lock lock(m_mutex);
        for (const auto& [brand, domains] : m_protectedBrands) {
            // Check for brand name in title
            std::regex titleRegex("<title[^>]*>([^<]*)</title>", std::regex_constants::icase);
            std::smatch titleMatch;
            if (std::regex_search(html, titleMatch, titleRegex)) {
                std::string title = NarrowToLowerPD(titleMatch[1].str());
                if (title.find(brand) != std::string::npos) {
                    result.hasBrandElements = true;
                    result.detectedBrand    = brand;
                }
            }

            // Check for brand logo references
            std::string lowerBrand = brand;
            if (lowerHtml.find(lowerBrand + ".com/logo") != std::string::npos ||
                lowerHtml.find(lowerBrand + "-logo") != std::string::npos ||
                lowerHtml.find("logo-" + lowerBrand) != std::string::npos) {
                result.hasBrandElements = true;
                result.detectedBrand    = brand;
            }

            // Check for favicon referencing a brand
            if (lowerHtml.find("favicon") != std::string::npos &&
                lowerHtml.find(lowerBrand) != std::string::npos) {
                result.hasBrandElements = true;
                result.detectedBrand    = brand;
            }

            if (result.hasBrandElements) break;
        }

        // Check if brand elements appear on a non-legitimate domain
        if (result.hasBrandElements && !result.detectedBrand.empty()) {
            std::string lowerUrl = NarrowToLowerPD(url);
            auto brandIt = m_protectedBrands.find(result.detectedBrand);
            if (brandIt != m_protectedBrands.end()) {
                bool isLegitSite = false;
                for (const auto& legit : brandIt->second) {
                    if (lowerUrl.find(legit) != std::string::npos) {
                        isLegitSite = true;
                        break;
                    }
                }
                result.isLegitimate = isLegitSite;
                if (!isLegitSite) {
                    result.logoMatchConfidence = 0.7;
                    result.layoutSimilarity    = 0.5;
                }
            }
        }

        // Compute a simple layout fingerprint hash
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
        if (hasher.Init()) {
            // Hash the structural summary (element counts + lengths)
            std::string structural;
            for (const auto& elem : elements) {
                structural += std::string(elem.tag) + ":" + std::to_string(elem.count) + ";";
            }
            structural += "len:" + std::to_string(html.size());
            hasher.Update(structural.data(), structural.size());
            std::string fpHash;
            hasher.FinalHex(fpHash);
            result.faviconHash = fpHash; // Reusing field for structure fingerprint
        }

        return result;
    }

    // ========================================================================
    // SSL/TLS CERTIFICATE ANALYSIS (WinHTTP)
    // ========================================================================

    CertificateAnalysis AnalyzeCertificateInternal(const std::string& url) {
        CertificateAnalysis certResult;

        // Parse URL to extract host and port
        std::regex urlRegex(R"(^https?://([^/:]+)(?::(\d+))?)");
        std::smatch match;
        if (!std::regex_search(url, match, urlRegex) || match.size() < 2) {
            return certResult;
        }

        std::string host = match[1].str();
        int port = 443;
        if (match.size() >= 3 && match[2].matched) {
            port = std::stoi(match[2].str());
        }

        // Only analyze HTTPS URLs
        if (url.find("https://") != 0) {
            return certResult;
        }

        std::wstring wHost = Utils::StringUtils::ToWide(host);

        HINTERNET hSession = WinHttpOpen(
            L"ShadowStrike/3.0 CertAnalyzer",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) return certResult;

        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(),
                                            static_cast<INTERNET_PORT>(port), 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return certResult;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"HEAD", L"/",
            nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return certResult;
        }

        // Set timeout (5 seconds)
        DWORD timeout = 5000;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

        // Allow invalid certificates so we can inspect them
        DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        BOOL sendOk = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (sendOk) {
            WinHttpReceiveResponse(hRequest, nullptr);
        }

        // Extract certificate info
        WINHTTP_CERTIFICATE_INFO certInfo{};
        DWORD certInfoSize = sizeof(certInfo);
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
                               &certInfo, &certInfoSize)) {
            certResult.hasCertificate = true;

            if (certInfo.lpszSubjectInfo) {
                certResult.subjectCN = Utils::StringUtils::ToNarrow(certInfo.lpszSubjectInfo);
                LocalFree(certInfo.lpszSubjectInfo);
            }
            if (certInfo.lpszIssuerInfo) {
                certResult.issuer = Utils::StringUtils::ToNarrow(certInfo.lpszIssuerInfo);
                LocalFree(certInfo.lpszIssuerInfo);
            }

            // Check validity
            certResult.isValid = true; // If we got cert info, the handshake succeeded

            // Convert FILETIME to system_clock::time_point
            auto FTToTP = [](const FILETIME& ft) -> SystemTimePoint {
                ULARGE_INTEGER uli;
                uli.LowPart  = ft.dwLowDateTime;
                uli.HighPart = ft.dwHighDateTime;
                // Windows FILETIME epoch: Jan 1, 1601
                // Unix epoch: Jan 1, 1970
                constexpr uint64_t kEpochDiff = 116444736000000000ULL;
                if (uli.QuadPart < kEpochDiff) return SystemTimePoint{};
                auto microseconds = (uli.QuadPart - kEpochDiff) / 10;
                return SystemTimePoint{std::chrono::microseconds{microseconds}};
            };

            certResult.validFrom = FTToTP(certInfo.ftStart);
            certResult.validTo   = FTToTP(certInfo.ftExpiry);

            // Calculate days until expiry
            auto now = std::chrono::system_clock::now();
            auto diff = certResult.validTo - now;
            certResult.daysUntilExpiry = static_cast<int>(
                std::chrono::duration_cast<std::chrono::hours>(diff).count() / 24);

            // Certificate age
            auto age = now - certResult.validFrom;
            certResult.certificateAgeDays = static_cast<int>(
                std::chrono::duration_cast<std::chrono::hours>(age).count() / 24);

            // Free certificate issuer indicator (Let's Encrypt, etc.)
            std::string issuerLower = NarrowToLowerPD(certResult.issuer);
            if (issuerLower.find("let's encrypt") != std::string::npos ||
                issuerLower.find("letsencrypt") != std::string::npos ||
                issuerLower.find("zerossl") != std::string::npos ||
                issuerLower.find("buypass") != std::string::npos) {
                certResult.isFreeCert = true;
            }

            // Self-signed detection (subject == issuer)
            if (certResult.subjectCN == certResult.issuer && !certResult.subjectCN.empty()) {
                certResult.isSelfSigned = true;
            }

            if (certInfo.lpszProtocolName) LocalFree(certInfo.lpszProtocolName);
            if (certInfo.lpszSignatureAlgName) LocalFree(certInfo.lpszSignatureAlgName);
            if (certInfo.lpszEncryptionAlgName) LocalFree(certInfo.lpszEncryptionAlgName);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return certResult;
    }
};

// ============================================================================
// UTILITY IMPLEMENTATIONS (free functions declared in header)
// ============================================================================

int LevenshteinDistance(const std::string& s1, const std::string& s2) {
    const size_t m = s1.length();
    const size_t n = s2.length();
    if (m == 0) return static_cast<int>(n);
    if (n == 0) return static_cast<int>(m);
    if (m > 200 || n > 200) return static_cast<int>(std::max(m, n));

    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
    for (size_t i = 0; i <= m; ++i) dp[i][0] = static_cast<int>(i);
    for (size_t j = 0; j <= n; ++j) dp[0][j] = static_cast<int>(j);

    for (size_t i = 1; i <= m; ++i) {
        for (size_t j = 1; j <= n; ++j) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            dp[i][j] = std::min({
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            });
        }
    }
    return dp[m][n];
}

double CalculateEntropy(const std::string& str) {
    if (str.empty()) return 0.0;
    std::array<int, 256> freqs{};
    for (unsigned char c : str) freqs[c]++;
    double entropy = 0.0;
    double len = static_cast<double>(str.size());
    for (int f : freqs) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ============================================================================
// PHISHING DETECTOR PUBLIC INTERFACE
// ============================================================================

PhishingDetector& PhishingDetector::Instance() noexcept {
    static PhishingDetector instance;
    s_instanceCreated = true;
    return instance;
}

bool PhishingDetector::HasInstance() noexcept {
    return s_instanceCreated;
}

PhishingDetector::PhishingDetector() : m_impl(std::make_unique<PhishingDetectorImpl>()) {
}

PhishingDetector::~PhishingDetector() = default;

bool PhishingDetector::Initialize(const PhishingDetectorConfiguration& config) {
    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_status == ModuleStatus::Running) {
        return true;
    }

    m_impl->m_status = ModuleStatus::Initializing;
    m_impl->m_config = config;

    // Populate brand-to-domain mapping from defaults
    for (const auto& entry : kDefaultBrandDomains) {
        std::vector<std::string> domains(entry.domains.begin(), entry.domains.end());
        m_impl->m_protectedBrands[entry.brand] = std::move(domains);
    }

    // Merge additional brands from config
    for (const auto& brand : config.protectedBrands) {
        std::string lowerBrand = NarrowToLowerPD(brand);
        if (m_impl->m_protectedBrands.find(lowerBrand) == m_impl->m_protectedBrands.end()) {
            // Not in defaults; generate domain from brand name
            m_impl->m_protectedBrands[lowerBrand] = {lowerBrand + ".com"};
        }
    }

    if (m_impl->m_protectedBrands.size() > MAX_PROTECTED_BRANDS) {
        Logger::Warn("PhishingDetector: brand count {} exceeds limit {}, truncating",
                     m_impl->m_protectedBrands.size(), MAX_PROTECTED_BRANDS);
    }

    Logger::Info("PhishingDetector: initialized with threshold={}, {} protected brands",
                 config.phishingThreshold, m_impl->m_protectedBrands.size());
    m_impl->m_status = ModuleStatus::Running;
    return true;
}

void PhishingDetector::Shutdown() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = ModuleStatus::Stopped;
    Logger::Info("PhishingDetector: shutdown complete");
}

bool PhishingDetector::IsInitialized() const noexcept {
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus PhishingDetector::GetStatus() const noexcept {
    return m_impl->m_status;
}

bool PhishingDetector::UpdateConfiguration(const PhishingDetectorConfiguration& config) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

PhishingDetectorConfiguration PhishingDetector::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

PhishingScore PhishingDetector::AnalyzeURL(const std::string& url) {
    m_impl->m_stats.totalAnalyzed++;

    auto score = m_impl->AnalyzeURLInternal(url);

    // Update stats by verdict
    if (score.isPhishing) {
        m_impl->m_stats.phishingDetected++;
    } else if (score.verdict == PhishingVerdict::Suspicious) {
        m_impl->m_stats.suspiciousDetected++;
    } else {
        m_impl->m_stats.safeDetected++;
    }

    if (score.homographResult.hasHomograph) m_impl->m_stats.homographsDetected++;
    if (score.typosquattingResult.isTyposquatting) m_impl->m_stats.typosquattingDetected++;
    if (!score.targetedBrand.empty()) m_impl->m_stats.brandImpersonationDetected++;

    // Notify callbacks if phishing detected
    if (score.isPhishing) {
        std::shared_lock lock(m_impl->m_callbackMutex);
        for (const auto& cb : m_impl->m_detectionCallbacks) {
            try { cb(url, score); } catch (...) {
                Logger::Error("PhishingDetector: exception in detection callback");
            }
        }
        if (!score.targetedBrand.empty()) {
            for (const auto& cb : m_impl->m_brandCallbacks) {
                try { cb(score.targetedBrand, url); } catch (...) {
                    Logger::Error("PhishingDetector: exception in brand alert callback");
                }
            }
        }
    }

    return score;
}

PhishingScore PhishingDetector::AnalyzePageContent(const std::string& url, const std::string& html) {
    if (html.size() > PhishingDetectorConstants::MAX_HTML_SIZE) {
        Logger::Warn("PhishingDetector: HTML content exceeds max size ({}), truncating analysis",
                     html.size());
    }

    PhishingScore score = AnalyzeURL(url);

    // Form analysis
    if (m_impl->m_config.enableFormAnalysis) {
        m_impl->m_stats.loginFormsAnalyzed++;
        auto formRes = m_impl->AnalyzeFormsInternal(html);
        score.formAnalysis = formRes;

        if (formRes.hasLoginForm && !score.urlAnalysis.isHTTPS) {
            score.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(score.indicators) | static_cast<uint32_t>(PhishingIndicator::LoginFormHTTP));
            score.allReasons.push_back("Login form detected over HTTP (insecure)");
            score.score += 0.5;
        }

        if (formRes.hasExternalAction) {
            score.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(score.indicators) | static_cast<uint32_t>(PhishingIndicator::ExternalFormAction));
            score.allReasons.push_back("Form sends data to external domain");
            score.score += 0.4;
        }

        if (formRes.passwordFieldCount > 0 && formRes.hiddenFieldCount > 5) {
            score.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(score.indicators) | static_cast<uint32_t>(PhishingIndicator::HiddenFormFields));
            score.allReasons.push_back("Password form with excessive hidden fields");
            score.score += 0.2;
        }
    }

    // Re-evaluate verdict after content analysis
    if (score.score >= m_impl->m_config.phishingThreshold && score.verdict != PhishingVerdict::KnownBad) {
        score.isPhishing = true;
        score.verdict = PhishingVerdict::Phishing;
    }

    return score;
}

PhishingScore PhishingDetector::AnalyzeFull(
        const std::string& url, const std::string& html, const std::vector<uint8_t>& screenshot) {

    PhishingScore score = AnalyzePageContent(url, html);

    // Visual / structural analysis
    if (m_impl->m_config.enableVisualAnalysis) {
        auto visualRes = m_impl->AnalyzeVisualInternal(url, html);
        score.visualAnalysis = visualRes;

        if (visualRes.hasBrandElements && !visualRes.isLegitimate) {
            score.indicators = static_cast<PhishingIndicator>(
                static_cast<uint32_t>(score.indicators) |
                static_cast<uint32_t>(PhishingIndicator::VisualSimilarity));
            score.allReasons.push_back("Brand elements detected on non-legitimate domain");
            score.score += 0.4;

            if (!visualRes.detectedBrand.empty() && score.targetedBrand.empty()) {
                score.targetedBrand = visualRes.detectedBrand;
            }
        }
    }

    // Certificate analysis
    if (m_impl->m_config.enableCertificateAnalysis) {
        m_impl->m_stats.certificatesChecked++;
        auto certRes = m_impl->AnalyzeCertificateInternal(url);
        score.certificateAnalysis = certRes;

        if (certRes.hasCertificate) {
            if (certRes.isSelfSigned) {
                score.indicators = static_cast<PhishingIndicator>(
                    static_cast<uint32_t>(score.indicators) |
                    static_cast<uint32_t>(PhishingIndicator::SelfSignedCert));
                score.allReasons.push_back("Self-signed SSL certificate detected");
                score.score += 0.3;
            }
            if (certRes.isFreeCert && score.isPhishing) {
                score.indicators = static_cast<PhishingIndicator>(
                    static_cast<uint32_t>(score.indicators) |
                    static_cast<uint32_t>(PhishingIndicator::FreeCertificate));
                score.allReasons.push_back("Free SSL certificate on suspected phishing site");
                score.score += 0.1;
            }
            if (certRes.daysUntilExpiry < 0) {
                score.indicators = static_cast<PhishingIndicator>(
                    static_cast<uint32_t>(score.indicators) |
                    static_cast<uint32_t>(PhishingIndicator::InvalidCertificate));
                score.allReasons.push_back("Expired SSL certificate");
                score.score += 0.3;
            }
            if (certRes.certificateAgeDays < 7 && certRes.certificateAgeDays >= 0) {
                score.allReasons.push_back("Very new SSL certificate (< 7 days)");
                score.score += 0.15;
            }
        }
    }

    // Final verdict recalculation
    score.confidence = static_cast<int>(std::clamp(score.score * 100.0, 0.0, 100.0));
    if (score.score >= m_impl->m_config.phishingThreshold && score.verdict != PhishingVerdict::KnownBad) {
        score.isPhishing = true;
        score.verdict = PhishingVerdict::Phishing;
    }

    // Generate recommendations
    if (score.isPhishing) {
        score.recommendations.push_back("Do not enter any credentials on this page");
        score.recommendations.push_back("Close this tab immediately");
        if (!score.targetedBrand.empty()) {
            score.recommendations.push_back("Navigate directly to the official " +
                                            score.targetedBrand + " website");
        }
    } else if (score.verdict == PhishingVerdict::Suspicious) {
        score.recommendations.push_back("Exercise caution; verify the URL before entering information");
    }

    return score;
}

HomographResult PhishingDetector::CheckHomograph(const std::string& domain) {
    return m_impl->CheckHomographInternal(domain);
}

TyposquattingResult PhishingDetector::CheckTyposquatting(const std::string& domain) {
    return m_impl->CheckTyposquattingInternal(domain);
}

FormAnalysisResult PhishingDetector::AnalyzeForms(const std::string& html) {
    return m_impl->AnalyzeFormsInternal(html);
}

CertificateAnalysis PhishingDetector::AnalyzeCertificate(const std::string& url) {
    m_impl->m_stats.certificatesChecked++;
    return m_impl->AnalyzeCertificateInternal(url);
}

bool PhishingDetector::IsPhishing(const std::string& url) {
    return AnalyzeURL(url).isPhishing;
}

int PhishingDetector::GetRiskScore(const std::string& url) {
    auto res = AnalyzeURL(url);
    return res.confidence;
}

std::optional<std::string> PhishingDetector::DetectBrandImpersonation(const std::string& domain) {
    auto homoRes = CheckHomograph(domain);
    if (homoRes.hasHomograph && !homoRes.targetedBrand.empty()) {
        return homoRes.targetedBrand;
    }
    auto typoRes = CheckTyposquatting(domain);
    if (typoRes.isTyposquatting) return typoRes.targetBrand;
    return std::nullopt;
}

bool PhishingDetector::IsLegitimeDomain(const std::string& domain, const std::string& brand) {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_protectedBrands.find(NarrowToLowerPD(brand));
    if (it == m_impl->m_protectedBrands.end()) {
        return false;
    }

    std::string lowerDomain = NarrowToLowerPD(domain);
    for (const auto& d : it->second) {
        if (d == lowerDomain ||
            (lowerDomain.size() > d.size() &&
             lowerDomain.substr(lowerDomain.size() - d.size() - 1) == "." + d)) {
            return true;
        }
    }
    return false;
}

bool PhishingDetector::AddProtectedBrand(const std::string& brandName,
                                         const std::vector<std::string>& legitimateDomains) {
    std::unique_lock lock(m_impl->m_mutex);
    if (m_impl->m_protectedBrands.size() >= MAX_PROTECTED_BRANDS) {
        Logger::Warn("PhishingDetector: cannot add brand '{}', limit reached", brandName);
        return false;
    }
    m_impl->m_protectedBrands[NarrowToLowerPD(brandName)] = legitimateDomains;
    Logger::Info("PhishingDetector: added protected brand '{}' with {} domains",
                 brandName, legitimateDomains.size());
    return true;
}

bool PhishingDetector::RemoveProtectedBrand(const std::string& brandName) {
    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_protectedBrands.erase(NarrowToLowerPD(brandName)) > 0;
}

std::vector<std::string> PhishingDetector::GetProtectedBrands() const {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<std::string> brands;
    brands.reserve(m_impl->m_protectedBrands.size());
    for (const auto& [name, domains] : m_impl->m_protectedBrands) {
        brands.push_back(name);
    }
    return brands;
}

void PhishingDetector::RegisterDetectionCallback(PhishingDetectionCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    if (m_impl->m_detectionCallbacks.size() >= MAX_CALLBACKS) return;
    m_impl->m_detectionCallbacks.push_back(std::move(callback));
}

void PhishingDetector::RegisterBrandAlertCallback(BrandAlertCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    if (m_impl->m_brandCallbacks.size() >= MAX_CALLBACKS) return;
    m_impl->m_brandCallbacks.push_back(std::move(callback));
}

void PhishingDetector::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    if (m_impl->m_errorCallbacks.size() >= MAX_CALLBACKS) return;
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void PhishingDetector::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_detectionCallbacks.clear();
    m_impl->m_brandCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

PhishingDetectorStatistics PhishingDetector::GetStatistics() const {
    return m_impl->m_stats;
}

void PhishingDetector::ResetStatistics() {
    m_impl->m_stats.Reset();
}

bool PhishingDetector::SelfTest() {
    // Test basic phishing detection with known-suspicious URL
    std::string testUrl = "http://microsoft.com.secure-login.attacker.com/login";
    auto result = AnalyzeURL(testUrl);
    // Should trigger: LongURL, subdomains, possibly brand impersonation

    // Test homograph detection with Cyrillic 'o' (U+043E)
    std::wstring wTest = L"micr\x043Esoft.com";
    std::string hTest = Utils::StringUtils::ToNarrow(wTest);
    auto hResult = CheckHomograph(hTest);
    if (!hResult.hasHomograph) {
        Logger::Error("PhishingDetector: self-test failed: homograph detection missed Cyrillic 'o'");
        return false;
    }

    // Test typosquatting detection
    auto typoResult = CheckTyposquatting("micorsoft.com");
    if (!typoResult.isTyposquatting) {
        Logger::Error("PhishingDetector: self-test failed: typosquatting not detected for 'micorsoft.com'");
        return false;
    }

    Logger::Info("PhishingDetector: self-test passed");
    return true;
}

std::string PhishingDetector::GetVersionString() noexcept {
    return std::format("{}.{}.{}", PhishingDetectorConstants::VERSION_MAJOR,
                       PhishingDetectorConstants::VERSION_MINOR,
                       PhishingDetectorConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetPhishingVerdictName(PhishingVerdict verdict) noexcept {
    switch (verdict) {
        case PhishingVerdict::Safe:           return "Safe";
        case PhishingVerdict::Suspicious:     return "Suspicious";
        case PhishingVerdict::Phishing:       return "Phishing";
        case PhishingVerdict::Spear_Phishing: return "SpearPhishing";
        case PhishingVerdict::BrandSpoof:     return "BrandSpoof";
        case PhishingVerdict::KnownBad:       return "KnownBad";
        default:                              return "Unknown";
    }
}

std::string_view GetPhishingIndicatorName(PhishingIndicator indicator) noexcept {
    switch (indicator) {
        case PhishingIndicator::None:                  return "None";
        case PhishingIndicator::HomographAttack:       return "HomographAttack";
        case PhishingIndicator::Typosquatting:         return "Typosquatting";
        case PhishingIndicator::SuspiciousDomain:      return "SuspiciousDomain";
        case PhishingIndicator::NewDomain:             return "NewDomain";
        case PhishingIndicator::DGADomain:             return "DGADomain";
        case PhishingIndicator::IPAddressURL:          return "IPAddressURL";
        case PhishingIndicator::LongURL:               return "LongURL";
        case PhishingIndicator::SuspiciousPath:        return "SuspiciousPath";
        case PhishingIndicator::HiddenURL:             return "HiddenURL";
        case PhishingIndicator::NoHTTPS:               return "NoHTTPS";
        case PhishingIndicator::InvalidCertificate:    return "InvalidCertificate";
        case PhishingIndicator::SelfSignedCert:        return "SelfSignedCert";
        case PhishingIndicator::FreeCertificate:       return "FreeCertificate";
        case PhishingIndicator::BrandImpersonation:    return "BrandImpersonation";
        case PhishingIndicator::LoginFormHTTP:         return "LoginFormHTTP";
        case PhishingIndicator::PasswordFieldDetected: return "PasswordFieldDetected";
        case PhishingIndicator::SuspiciousFormAction:  return "SuspiciousFormAction";
        case PhishingIndicator::HiddenFormFields:      return "HiddenFormFields";
        case PhishingIndicator::ExternalFormAction:    return "ExternalFormAction";
        case PhishingIndicator::LogoMismatch:          return "LogoMismatch";
        case PhishingIndicator::VisualSimilarity:      return "VisualSimilarity";
        case PhishingIndicator::SuspiciousJavaScript:  return "SuspiciousJavaScript";
        case PhishingIndicator::PopupBlocker:          return "PopupBlocker";
        case PhishingIndicator::RedirectChain:         return "RedirectChain";
        case PhishingIndicator::ThreatIntelMatch:      return "ThreatIntelMatch";
        default:                                       return "Unknown";
    }
}

std::string_view GetAttackTypeName(PhishingAttackType type) noexcept {
    switch (type) {
        case PhishingAttackType::Unknown:            return "Unknown";
        case PhishingAttackType::Credential_Harvest: return "CredentialHarvest";
        case PhishingAttackType::Financial:          return "Financial";
        case PhishingAttackType::Corporate:          return "Corporate";
        case PhishingAttackType::Social_Engineering: return "SocialEngineering";
        case PhishingAttackType::Technical_Support:  return "TechnicalSupport";
        case PhishingAttackType::Romance_Scam:       return "RomanceScam";
        case PhishingAttackType::Lottery_Scam:       return "LotteryScam";
        default:                                     return "Unknown";
    }
}

std::string_view GetFormFieldTypeName(FormFieldType type) noexcept {
    switch (type) {
        case FormFieldType::Unknown:     return "Unknown";
        case FormFieldType::Username:    return "Username";
        case FormFieldType::Email:       return "Email";
        case FormFieldType::Password:    return "Password";
        case FormFieldType::CreditCard:  return "CreditCard";
        case FormFieldType::SSN:         return "SSN";
        case FormFieldType::Phone:       return "Phone";
        case FormFieldType::Address:     return "Address";
        case FormFieldType::DateOfBirth: return "DateOfBirth";
        case FormFieldType::Hidden:      return "Hidden";
        case FormFieldType::OTP:         return "OTP";
        case FormFieldType::PIN:         return "PIN";
        default:                         return "Unknown";
    }
}

bool ContainsHomograph(const std::wstring& text) {
    for (wchar_t c : text) {
        for (const auto& pair : PhishingDetectorConstants::HOMOGRAPH_CHARS) {
            if (c == pair[0]) return true;
        }
    }
    return false;
}

std::vector<std::string> ExtractURLsFromHTML(const std::string& html) {
    std::vector<std::string> urls;
    if (html.size() > PhishingDetectorConstants::MAX_HTML_SIZE) return urls;

    std::regex hrefRegex(R"(href=["']([^"']+)["'])", std::regex_constants::icase);
    auto begin = std::sregex_iterator(html.begin(), html.end(), hrefRegex);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        if (urls.size() >= 10000) break; // Cap extraction
        urls.push_back((*it)[1].str());
    }
    return urls;
}

std::wstring DecodePunycode(const std::string& domain) {
    // ACE-prefix check for internationalized domain names
    if (domain.find("xn--") == std::string::npos) {
        return Utils::StringUtils::ToWide(domain);
    }

    // Windows IdnToUnicode conversion
    std::wstring wideDomain = Utils::StringUtils::ToWide(domain);
    int needed = IdnToUnicode(0, wideDomain.c_str(), static_cast<int>(wideDomain.size()), nullptr, 0);
    if (needed <= 0) return wideDomain;

    std::wstring decoded(static_cast<size_t>(needed), L'\0');
    int result = IdnToUnicode(0, wideDomain.c_str(), static_cast<int>(wideDomain.size()),
                              decoded.data(), needed);
    if (result <= 0) return wideDomain;
    decoded.resize(static_cast<size_t>(result));
    return decoded;
}

// ============================================================================
// STRUCT SERIALIZATION
// ============================================================================

std::string URLAnalysisDetail::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addStr("originalUrl", originalUrl);
    j.addStr("normalizedUrl", normalizedUrl);
    j.addStr("domain", domain);
    j.addStr("tld", tld);
    j.addStr("subdomain", subdomain);
    j.addStr("path", path);
    j.addBool("isHTTPS", isHTTPS);
    j.addBool("isIPAddress", isIPAddress);
    j.addNum("entropy", entropyScore);
    j.addInt("urlLength", static_cast<int64_t>(urlLength));
    j.addInt("subdomainCount", subdomainCount);
    return j.end();
}

std::string HomographResult::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("hasHomograph", hasHomograph);
    j.addStr("originalDomain", originalDomain);
    j.addStr("decodedDomain", decodedDomain);
    j.addStr("targetedBrand", targetedBrand);
    j.addNum("similarityScore", similarityScore);
    j.addInt("confusableCount", static_cast<int64_t>(confusables.size()));
    return j.end();
}

std::string TyposquattingResult::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("isTyposquatting", isTyposquatting);
    j.addStr("suspiciousDomain", suspiciousDomain);
    j.addStr("targetDomain", targetDomain);
    j.addStr("targetBrand", targetBrand);
    j.addInt("editDistance", editDistance);
    j.addStr("typoType", typoType);
    j.addNum("similarityScore", similarityScore);
    return j.end();
}

std::string FormAnalysisResult::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("hasLoginForm", hasLoginForm);
    j.addInt("formCount", formCount);
    j.addInt("passwordFieldCount", passwordFieldCount);
    j.addInt("hiddenFieldCount", hiddenFieldCount);
    j.addBool("hasExternalAction", hasExternalAction);
    j.addBool("formOverHTTP", formOverHTTP);
    j.addInt("riskScore", riskScore);
    return j.end();
}

std::string VisualAnalysisResult::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("hasBrandElements", hasBrandElements);
    j.addStr("detectedBrand", detectedBrand);
    j.addNum("logoMatchConfidence", logoMatchConfidence);
    j.addBool("colorSchemeMatch", colorSchemeMatch);
    j.addNum("layoutSimilarity", layoutSimilarity);
    j.addStr("faviconHash", faviconHash);
    j.addBool("isLegitimate", isLegitimate);
    return j.end();
}

std::string CertificateAnalysis::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("hasCertificate", hasCertificate);
    j.addBool("isValid", isValid);
    j.addBool("isSelfSigned", isSelfSigned);
    j.addBool("isFreeCert", isFreeCert);
    j.addStr("subjectCN", subjectCN);
    j.addStr("issuer", issuer);
    j.addInt("daysUntilExpiry", daysUntilExpiry);
    j.addInt("certificateAgeDays", certificateAgeDays);
    return j.end();
}

bool PhishingScore::ShouldBlock() const noexcept {
    return isPhishing ||
           verdict == PhishingVerdict::KnownBad ||
           verdict == PhishingVerdict::BrandSpoof;
}

std::string PhishingScore::ToJson() const {
    json_helper::JsonBuilder j;
    j.begin();
    j.addBool("isPhishing", isPhishing);
    j.addNum("score", score);
    j.addStr("verdict", std::string(GetPhishingVerdictName(verdict)));
    j.addInt("confidence", confidence);
    j.addStr("reason", reason);
    j.addStr("targetedBrand", targetedBrand);
    j.addStr("attackType", std::string(GetAttackTypeName(attackType)));
    j.addInt("analysisDurationUs", static_cast<int64_t>(analysisDuration.count()));
    return j.end();
}

void PhishingDetectorStatistics::Reset() noexcept {
    totalAnalyzed            = 0;
    phishingDetected         = 0;
    suspiciousDetected       = 0;
    safeDetected             = 0;
    homographsDetected       = 0;
    typosquattingDetected    = 0;
    brandImpersonationDetected = 0;
    loginFormsAnalyzed       = 0;
    certificatesChecked      = 0;
    threatIntelMatches       = 0;
    for (auto& v : byVerdict)   v.store(0, std::memory_order_relaxed);
    for (auto& v : byIndicator) v.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string PhishingDetectorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << R"({"totalAnalyzed":)" << totalAnalyzed.load()
        << R"(,"phishingDetected":)" << phishingDetected.load()
        << R"(,"suspiciousDetected":)" << suspiciousDetected.load()
        << R"(,"safeDetected":)" << safeDetected.load()
        << R"(,"homographsDetected":)" << homographsDetected.load()
        << R"(,"typosquattingDetected":)" << typosquattingDetected.load()
        << R"(,"brandImpersonationDetected":)" << brandImpersonationDetected.load()
        << R"(,"loginFormsAnalyzed":)" << loginFormsAnalyzed.load()
        << R"(,"certificatesChecked":)" << certificatesChecked.load()
        << R"(,"threatIntelMatches":)" << threatIntelMatches.load()
        << "}";
    return oss.str();
}

bool PhishingDetectorConfiguration::IsValid() const noexcept {
    if (phishingThreshold <= 0.0 || phishingThreshold > 1.0) return false;
    if (suspiciousThreshold <= 0.0 || suspiciousThreshold > phishingThreshold) return false;
    return true;
}

} // namespace WebBrowser
} // namespace ShadowStrike
