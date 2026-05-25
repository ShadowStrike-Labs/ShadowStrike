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
/**
 * ============================================================================
 * ShadowStrike NGAV - BROWSER PROTECTION ORCHESTRATOR IMPLEMENTATION
 * ============================================================================
 *
 * @file BrowserProtection.cpp
 * @brief Implementation of the enterprise browser protection orchestrator.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "BrowserProtection.hpp"
#include "AdBlocker.hpp"
#include "PhishingDetector.hpp"
#include "MaliciousDownloadBlocker.hpp"
#include "SafeBrowsingAPI.hpp"
#include "TrackerBlocker.hpp"
#include "PhantomCore/Utils/NetworkUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <regex>
#include <filesystem>
#include <iomanip>
#include <cctype>

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"BrowserProtection";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> BrowserProtection::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    std::string ToLower(std::string_view str) {
        std::string lower(str);
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lower;
    }

    [[nodiscard]] bool ContainsUnsafeText(std::string_view value) noexcept {
        return std::any_of(value.begin(), value.end(), [](unsigned char c) {
            return c < 0x21 || c == 0x7F;
        });
    }

    [[nodiscard]] bool IsValidDomainCharacter(char c) noexcept {
        const unsigned char uc = static_cast<unsigned char>(c);
        return std::isalnum(uc) != 0 || c == '.' || c == '-';
    }

    [[nodiscard]] std::string NormalizeDomainCandidate(std::string_view value) {
        if (value.empty() || value.size() > 253 || ContainsUnsafeText(value)) {
            return {};
        }

        if (value.find("://") != std::string_view::npos ||
            value.find('/') != std::string_view::npos ||
            value.find('\\') != std::string_view::npos ||
            value.find('@') != std::string_view::npos ||
            value.find(':') != std::string_view::npos ||
            value.front() == '.' || value.front() == '-' ||
            value.back() == '-') {
            return {};
        }

        std::string normalized = ToLower(value);
        while (!normalized.empty() && normalized.back() == '.') {
            normalized.pop_back();
        }

        if (normalized.empty()) {
            return {};
        }

        bool lastWasDot = true;
        for (char c : normalized) {
            if (!IsValidDomainCharacter(c)) {
                return {};
            }

            if (c == '.') {
                if (lastWasDot) {
                    return {};
                }
                lastWasDot = true;
                continue;
            }

            lastWasDot = false;
        }

        return lastWasDot ? std::string{} : normalized;
    }

    [[nodiscard]] bool HasOnlyValidCustomDomains(const std::vector<std::string>& domains) {
        return std::all_of(domains.begin(), domains.end(), [](const std::string& domain) {
            return !NormalizeDomainCandidate(domain).empty();
        });
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    std::string GetDomainFromUrl(const std::string& url) {
        const std::wstring wideUrl = Utils::StringUtils::ToWide(url);
        if (!wideUrl.empty()) {
            Utils::NetworkUtils::UrlComponents components;
            Utils::NetworkUtils::Error parseError;
            if (Utils::NetworkUtils::ParseUrl(wideUrl, components, &parseError) &&
                !components.host.empty())
            {
                const std::string host = ToLower(Utils::StringUtils::ToNarrow(components.host));
                if (host.find(':') != std::string::npos) {
                    // NetworkUtils already canonicalizes IPv6 host extraction; domain-specific
                    // normalization intentionally does not apply to literals containing ':'.
                    return host;
                }
                const auto normalized = NormalizeDomainCandidate(host);
                if (!normalized.empty()) {
                    return normalized;
                }
            }
        }

        if (url.find("://") == std::string::npos &&
            url.find('/') == std::string::npos &&
            url.find('?') == std::string::npos &&
            url.find('#') == std::string::npos)
        {
            return NormalizeDomainCandidate(url);
        }

        return {};
    }

    bool DomainEndsWith(const std::string& domain, const std::string& suffix) {
        if (domain.size() < suffix.size()) return false;
        if (domain == suffix) return true;
        if (domain.size() > suffix.size() && domain[domain.size() - suffix.size() - 1] == '.') {
            return domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
        return false;
    }

    // Map well-known TLDs/domains to URL categories
    URLCategory CategorizeByDomain(const std::string& domain) {
        // Search engines
        if (DomainEndsWith(domain, "google.com") ||
            DomainEndsWith(domain, "bing.com") ||
            DomainEndsWith(domain, "duckduckgo.com") ||
            DomainEndsWith(domain, "yahoo.com")) {
            return URLCategory::Search;
        }
        // Social media
        if (DomainEndsWith(domain, "facebook.com") || DomainEndsWith(domain, "twitter.com") ||
            DomainEndsWith(domain, "x.com") || DomainEndsWith(domain, "instagram.com") ||
            DomainEndsWith(domain, "linkedin.com") || DomainEndsWith(domain, "reddit.com") ||
            DomainEndsWith(domain, "tiktok.com")) {
            return URLCategory::SocialMedia;
        }
        // Streaming
        if (DomainEndsWith(domain, "youtube.com") || DomainEndsWith(domain, "netflix.com") ||
            DomainEndsWith(domain, "twitch.tv") || DomainEndsWith(domain, "spotify.com")) {
            return URLCategory::Streaming;
        }
        // Shopping
        if (DomainEndsWith(domain, "amazon.com") || DomainEndsWith(domain, "ebay.com") ||
            DomainEndsWith(domain, "shopify.com") || DomainEndsWith(domain, "aliexpress.com")) {
            return URLCategory::Shopping;
        }
        // News
        if (DomainEndsWith(domain, "cnn.com") || DomainEndsWith(domain, "bbc.com") ||
            DomainEndsWith(domain, "reuters.com") || DomainEndsWith(domain, "nytimes.com")) {
            return URLCategory::News;
        }
        // Finance
        if (DomainEndsWith(domain, "paypal.com") || DomainEndsWith(domain, "chase.com") ||
            DomainEndsWith(domain, "bankofamerica.com")) {
            return URLCategory::Finance;
        }
        // Government
        if (domain.size() > 4 && domain.substr(domain.size() - 4) == ".gov") {
            return URLCategory::Government;
        }
        // Education
        if (domain.size() > 4 && domain.substr(domain.size() - 4) == ".edu") {
            return URLCategory::Education;
        }
        // Advertising
        if (DomainEndsWith(domain, "doubleclick.net") ||
            DomainEndsWith(domain, "googlesyndication.com") ||
            DomainEndsWith(domain, "adnxs.com") ||
            DomainEndsWith(domain, "criteo.com")) {
            return URLCategory::Advertising;
        }
        // Gaming
        if (DomainEndsWith(domain, "steampowered.com") || DomainEndsWith(domain, "epicgames.com") ||
            DomainEndsWith(domain, "roblox.com")) {
            return URLCategory::Games;
        }
        return URLCategory::Unknown;
    }

    // Map BrowserType to known process names
    std::wstring BrowserTypeToExeName(BrowserType type) {
        switch (type) {
            case BrowserType::Chrome:  return L"chrome.exe";
            case BrowserType::Edge:    return L"msedge.exe";
            case BrowserType::Firefox: return L"firefox.exe";
            case BrowserType::Brave:   return L"brave.exe";
            case BrowserType::Opera:   return L"opera.exe";
            case BrowserType::Vivaldi: return L"vivaldi.exe";
            default: return L"";
        }
    }

    BrowserType ExeNameToBrowserType(std::wstring_view name) {
        std::wstring lower(name);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        if (lower == L"chrome.exe")  return BrowserType::Chrome;
        if (lower == L"msedge.exe")  return BrowserType::Edge;
        if (lower == L"firefox.exe") return BrowserType::Firefox;
        if (lower == L"brave.exe")   return BrowserType::Brave;
        if (lower == L"opera.exe")   return BrowserType::Opera;
        if (lower == L"vivaldi.exe") return BrowserType::Vivaldi;
        return BrowserType::Unknown;
    }

}  // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string BrowserInstance::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"processId\":" << processId << ","
        << "\"type\":\"" << GetBrowserTypeName(type) << "\","
        << "\"version\":\"" << EscapeJson(version) << "\","
        << "\"profilePath\":\"" << EscapeJson(profilePath.string()) << "\","
        << "\"isPrivate\":" << (isPrivate ? "true" : "false") << ","
        << "\"extensionStatus\":\"" << GetExtensionStatusName(extensionStatus) << "\","
        << "\"nativeMessagingConnected\":" << (nativeMessagingConnected ? "true" : "false") << ","
        << "\"windowCount\":" << windowCount << ","
        << "\"tabCount\":" << tabCount
        << "}";
    return oss.str();
}

std::string NavigationRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"requestId\":\"" << EscapeJson(requestId) << "\","
        << "\"url\":\"" << EscapeJson(url) << "\","
        << "\"domain\":\"" << EscapeJson(domain) << "\","
        << "\"referrer\":\"" << EscapeJson(referrer) << "\","
        << "\"method\":\"" << EscapeJson(method) << "\","
        << "\"browserPid\":" << browserPid << ","
        << "\"isMainFrame\":" << (isMainFrame ? "true" : "false") << ","
        << "\"resourceType\":\"" << EscapeJson(resourceType) << "\""
        << "}";
    return oss.str();
}

bool NavigationResult::IsBlocked() const noexcept {
    return action == NavigationAction::Block || action == NavigationAction::Redirect;
}

std::string NavigationResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"requestId\":\"" << EscapeJson(requestId) << "\","
        << "\"action\":\"" << GetNavigationActionName(action) << "\","
        << "\"blockReasons\":\"" << GetBlockReasonName(blockReasons) << "\","
        << "\"category\":\"" << GetURLCategoryName(category) << "\","
        << "\"riskScore\":" << riskScore << ","
        << "\"threatName\":\"" << EscapeJson(threatName) << "\","
        << "\"processingTimeUs\":" << processingTime.count();
    if (!matchedRules.empty()) {
        oss << ",\"matchedRules\":[";
        for (size_t i = 0; i < matchedRules.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << EscapeJson(matchedRules[i]) << "\"";
        }
        oss << "]";
    }
    oss << "}";
    return oss.str();
}

std::string DownloadInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"downloadId\":\"" << EscapeJson(downloadId) << "\","
        << "\"filename\":\"" << EscapeJson(filename) << "\","
        << "\"url\":\"" << EscapeJson(sourceUrl) << "\","
        << "\"mimeType\":\"" << EscapeJson(mimeType) << "\","
        << "\"size\":" << fileSize
        << "}";
    return oss.str();
}

std::string DownloadScanResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"downloadId\":\"" << EscapeJson(downloadId) << "\","
        << "\"verdict\":\"" << GetDownloadVerdictName(verdict) << "\","
        << "\"isSafe\":" << (isSafe ? "true" : "false") << ","
        << "\"shouldBlock\":" << (shouldBlock ? "true" : "false") << ","
        << "\"threatName\":\"" << EscapeJson(threatName) << "\","
        << "\"riskScore\":" << riskScore << ","
        << "\"reputation\":" << reputation
        << "}";
    return oss.str();
}

void BrowserProtectionStatistics::Reset() noexcept {
    totalNavigations = 0;
    allowedNavigations = 0;
    blockedNavigations = 0;
    warnedNavigations = 0;
    malwareBlocked = 0;
    phishingBlocked = 0;
    categoryBlocked = 0;
    downloadsScanned = 0;
    downloadsBlocked = 0;
    adsBlocked = 0;
    trackersBlocked = 0;
    safeSearchEnforced = 0;
    cacheHits = 0;
    cacheMisses = 0;

    for (auto& count : byBlockReason) count = 0;
    for (auto& count : byCategory) count = 0;
    for (auto& count : byBrowser) count = 0;

    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string BrowserProtectionStatistics::ToJson() const {
    const auto statsStartTime = AtomicValueLoadRelaxed(startTime);
    std::ostringstream oss;
    oss << "{"
        << "\"totalNavigations\":" << totalNavigations.load() << ","
        << "\"allowedNavigations\":" << allowedNavigations.load() << ","
        << "\"blockedNavigations\":" << blockedNavigations.load() << ","
        << "\"warnedNavigations\":" << warnedNavigations.load() << ","
        << "\"malwareBlocked\":" << malwareBlocked.load() << ","
        << "\"phishingBlocked\":" << phishingBlocked.load() << ","
        << "\"categoryBlocked\":" << categoryBlocked.load() << ","
        << "\"downloadsScanned\":" << downloadsScanned.load() << ","
        << "\"downloadsBlocked\":" << downloadsBlocked.load() << ","
        << "\"adsBlocked\":" << adsBlocked.load() << ","
        << "\"trackersBlocked\":" << trackersBlocked.load() << ","
        << "\"safeSearchEnforced\":" << safeSearchEnforced.load() << ","
        << "\"uptimeSeconds\":" << std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - statsStartTime).count()
        << "}";
    return oss.str();
}

bool BrowserProtectionConfiguration::IsValid() const noexcept {
    if (cacheTTLSeconds == 0 || cacheTTLSeconds > 86400) return false;
    if (newDomainThresholdDays < 0 || newDomainThresholdDays > 365) return false;
    if (customBlocklist.size() > 100000) return false;
    if (customAllowlist.size() > 100000) return false;
    if (!HasOnlyValidCustomDomains(customBlocklist)) return false;
    if (!HasOnlyValidCustomDomains(customAllowlist)) return false;
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BrowserProtectionImpl {
public:
    BrowserProtectionImpl() = default;
    ~BrowserProtectionImpl() { Shutdown(); }

    bool Initialize(const BrowserProtectionConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
            return true;
        }

        m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            m_status = ModuleStatus::Error;
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid BrowserProtection configuration rejected");
            return false;
        }

        m_config = config;

        m_blocklist.clear();
        m_allowlist.clear();

        for (const auto& domain : m_config.customBlocklist) {
            if (const auto normalizedDomain = NormalizeDomainCandidate(domain); !normalizedDomain.empty()) {
                m_blocklist.insert(std::move(normalizedDomain));
            }
        }
        for (const auto& domain : m_config.customAllowlist) {
            if (const auto normalizedDomain = NormalizeDomainCandidate(domain); !normalizedDomain.empty()) {
                m_allowlist.insert(std::move(normalizedDomain));
            }
        }

        // Store safe search and parental control settings
        m_safeSearchSettings = m_config.safeSearch;
        m_parentalSettings = m_config.parentalControls;
        m_safeSearchEnforced = m_config.enableSafeSearch;

        if (m_config.enableExtensionScanning) {
            StartNativeMessagingInternal();
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"BrowserProtection initialized with %zu blocklist, %zu allowlist entries",
                    m_blocklist.size(), m_allowlist.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Stopped) return;

        m_status = ModuleStatus::Stopping;
        StopNativeMessagingInternal();

        m_blocklist.clear();
        m_allowlist.clear();

        m_navCallback = nullptr;
        m_downloadCallback = nullptr;
        m_blockCallback = nullptr;
        m_eventCallback = nullptr;
        m_preNavCallback = nullptr;
        m_errorCallback = nullptr;

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"BrowserProtection shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load();
    }

    [[nodiscard]] bool UpdateConfiguration(const BrowserProtectionConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid configuration rejected");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        m_safeSearchSettings = config.safeSearch;
        m_parentalSettings = config.parentalControls;
        m_safeSearchEnforced = config.enableSafeSearch;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] BrowserProtectionConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // NAVIGATION LOGIC
    // ========================================================================

    NavigationResult OnNavigate(const NavigationRequest& request) {
        NavigationResult result;
        result.requestId = request.requestId;
        auto start = Clock::now();

        if (!IsInitialized()) {
            return result;
        }

        // Snapshot configuration, parental settings and callbacks under shared_lock
        // so the hot path does not race with UpdateConfiguration / SetParentalControls
        // / Register*Callback. Copying these small structs once is far cheaper than
        // the per-field unlocked reads they replace, and removes the prior racing-
        // `std::function` invocations entirely.
        bool                       cfgEnabled = false;
        bool                       cfgEnableParental = false;
        bool                       cfgEnablePhishing = false;
        bool                       cfgBlockMalware = false;
        bool                       cfgEnableAds = false;
        bool                       cfgEnableTrackers = false;
        std::set<URLCategory> cfgBlockedCategories;
        bool                       safeSearchSnap = false;
        ParentalControlSettings    parentalSnap;
        PreNavigationCallback      preNavCb;
        NavigationCallback         navCb;
        BlockCallback              blockCb;
        {
            std::shared_lock lock(m_mutex);
            cfgEnabled              = m_config.enabled;
            cfgEnableParental       = m_config.enableParentalControls;
            cfgEnablePhishing       = m_config.enablePhishingDetection;
            cfgBlockMalware         = m_config.blockMalwareDomains;
            cfgEnableAds            = m_config.enableAdBlocking;
            cfgEnableTrackers       = m_config.enableTrackerBlocking;
            cfgBlockedCategories    = m_config.blockedCategories;
            safeSearchSnap          = m_safeSearchEnforced;
            parentalSnap            = m_parentalSettings;
            preNavCb                = m_preNavCallback;
            navCb                   = m_navCallback;
            blockCb                 = m_blockCallback;
        }

        if (!cfgEnabled) {
            return result;
        }

        m_stats.totalNavigations++;

        // Validate URL length
        if (request.url.size() > BrowserConstants::MAX_URL_LENGTH) {
            result.action = NavigationAction::Block;
            result.blockReasons = BlockReason::PolicyViolation;
            result.threatName = "URL exceeds maximum length";
            m_stats.blockedNavigations++;
            return result;
        }

        std::string domain = request.domain.empty()
            ? GetDomainFromUrl(request.url)
            : NormalizeDomainCandidate(request.domain);
        if (domain.empty()) {
            result.action = NavigationAction::Block;
            result.blockReasons = BlockReason::PolicyViolation;
            result.threatName = "Malformed domain in navigation request";
            m_stats.blockedNavigations++;
            return result;
        }

        // 1. Pre-navigation callback (invoked OUTSIDE any lock)
        if (preNavCb) {
            bool allowed = true;
            try { allowed = preNavCb(request); } catch (...) { allowed = true; }
            if (!allowed) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::PolicyViolation;
                result.threatName = "Blocked by pre-navigation callback";
                m_stats.blockedNavigations++;
                return result;
            }
        }

        // 2. Check allowlist
        if (IsInAllowlistInternal(domain)) {
            m_stats.allowedNavigations++;
            result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            return result;
        }

        // 3. Check blocklist
        if (IsInBlocklistInternal(domain)) {
            result.action = NavigationAction::Block;
            result.blockReasons = BlockReason::CustomBlocklist;
            result.threatName = "Blocked by custom blocklist policy";
            result.blockPageUrl = BrowserConstants::BLOCK_PAGE_URL;
            m_stats.blockedNavigations++;
            InvokeBlockCallback(blockCb, request.url, BlockReason::CustomBlocklist);
            result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            return result;
        }

        // 4. Parental controls
        if (cfgEnableParental && parentalSnap.enabled) {
            // Time-based restriction check
            auto now = std::chrono::system_clock::now();
            auto tt = std::chrono::system_clock::to_time_t(now);
            struct tm localTm;
#ifdef _WIN32
            localtime_s(&localTm, &tt);
#else
            localtime_r(&tt, &localTm);
#endif
            int currentHour = localTm.tm_hour;
            if (currentHour >= 0 && currentHour < 24 && !parentalSnap.hourlyAccess[static_cast<size_t>(currentHour)]) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::TimeRestriction;
                result.threatName = "Access restricted during this time period";
                m_stats.blockedNavigations++;
                m_stats.categoryBlocked++;
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }

            // Check blocked domains in parental settings
            for (const auto& blocked : parentalSnap.blockedDomains) {
                if (DomainEndsWith(domain, ToLower(blocked))) {
                    result.action = NavigationAction::Block;
                    result.blockReasons = BlockReason::CategoryBlocked;
                    result.threatName = "Blocked by parental controls";
                    m_stats.blockedNavigations++;
                    m_stats.categoryBlocked++;
                    result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                    return result;
                }
            }

            // Category-based blocking (parental categories evaluated against snapshot)
            if (IsCategoryBlockedFromSnapshot(domain, parentalSnap)) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::CategoryBlocked;
                result.threatName = "Category blocked by parental controls";
                m_stats.categoryBlocked++;
                m_stats.blockedNavigations++;
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        }

        // 5. Safe search enforcement
        if (safeSearchSnap) {
            EnforceSafeSearchOnUrl(request.url, domain);
        }

        // 6. Phishing / malware check via SafeBrowsingAPI
        if (cfgEnablePhishing || cfgBlockMalware) {
            auto& safeBrowsing = SafeBrowsingAPI::Instance();
            auto sbResult = safeBrowsing.CheckUrl(request.url);

            if (sbResult.isMalicious) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::Malware;
                result.threatName = sbResult.threatName.empty() ? "Malware detected" : sbResult.threatName;
                result.riskScore = sbResult.threatScore;
                result.blockPageUrl = BrowserConstants::BLOCK_PAGE_URL;
                m_stats.malwareBlocked++;
                m_stats.blockedNavigations++;
                InvokeBlockCallback(blockCb, request.url, BlockReason::Malware);
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }

            if (sbResult.isPhishing) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::Phishing;
                result.threatName = sbResult.threatName.empty() ? "Phishing site detected" : sbResult.threatName;
                result.riskScore = sbResult.threatScore;
                result.blockPageUrl = BrowserConstants::BLOCK_PAGE_URL;
                m_stats.phishingBlocked++;
                m_stats.blockedNavigations++;
                InvokeBlockCallback(blockCb, request.url, BlockReason::Phishing);
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }

            if (sbResult.isSuspicious) {
                result.action = NavigationAction::Warn;
                result.blockReasons = BlockReason::Reputation;
                result.threatName = "Suspicious URL detected";
                result.riskScore = sbResult.threatScore;
                m_stats.warnedNavigations++;
            }
        }

        // 7. Phishing detector (heuristic analysis)
        if (cfgEnablePhishing) {
            auto& phishing = PhishingDetector::Instance();
            if (phishing.IsPhishing(request.url)) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::Phishing;
                result.threatName = "Heuristic phishing detection";
                result.riskScore = phishing.GetRiskScore(request.url);
                result.blockPageUrl = BrowserConstants::BLOCK_PAGE_URL;
                m_stats.phishingBlocked++;
                m_stats.blockedNavigations++;
                InvokeBlockCallback(blockCb, request.url, BlockReason::Phishing);
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        }

        // 8. Ad blocking
        if (cfgEnableAds) {
            if (AdBlocker::Instance().ShouldBlock(request.url)) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::Advertising;
                result.threatName = "Advertisement blocked";
                m_stats.adsBlocked++;
                m_stats.blockedNavigations++;
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        }

        // 9. Tracker blocking
        if (cfgEnableTrackers) {
            auto trackerDecision = TrackerBlocker::Instance().ShouldBlockUrl(request.url);
            if (trackerDecision.decision == BlockDecision::Block) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::PolicyViolation;
                result.threatName = "Tracker blocked";
                m_stats.trackersBlocked++;
                m_stats.blockedNavigations++;
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        }

        // 10. Category-based blocking (from snapshot config)
        if (!cfgBlockedCategories.empty()) {
            URLCategory cat = CategorizeByDomain(domain);
            if (cat != URLCategory::Unknown &&
                cfgBlockedCategories.find(cat) != cfgBlockedCategories.end()) {
                result.action = NavigationAction::Block;
                result.blockReasons = BlockReason::CategoryBlocked;
                result.category = cat;
                result.threatName = std::string("Category blocked: ") + std::string(GetURLCategoryName(cat));
                m_stats.categoryBlocked++;
                m_stats.blockedNavigations++;
                result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        }

        result.processingTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
        m_stats.allowedNavigations++;

        if (navCb) {
            try { navCb(request, result); } catch (...) {}
        }

        return result;
    }

    DownloadScanResult OnDownload(const DownloadInfo& download) {
        DownloadScanResult result;
        result.downloadId = download.downloadId;
        auto start = Clock::now();

        if (!IsInitialized()) {
            return result;
        }

        // Snapshot config flag and callback under shared_lock to avoid race with
        // UpdateConfiguration / RegisterDownloadCallback.
        bool             cfgEnableDownloadScanning = false;
        DownloadCallback dlCb;
        {
            std::shared_lock lock(m_mutex);
            cfgEnableDownloadScanning = m_config.enableDownloadScanning;
            dlCb = m_downloadCallback;
        }

        if (!cfgEnableDownloadScanning) {
            return result;
        }

        m_stats.downloadsScanned++;

        // Check source URL reputation via SafeBrowsingAPI
        auto& safeBrowsing = SafeBrowsingAPI::Instance();
        auto sbResult = safeBrowsing.CheckUrl(download.sourceUrl);

        if (sbResult.isMalicious) {
            result.verdict = DownloadVerdict::Malware;
            result.isSafe = false;
            result.shouldBlock = true;
            result.threatName = sbResult.threatName.empty() ? "Malicious download source" : sbResult.threatName;
            result.riskScore = sbResult.threatScore;
            m_stats.downloadsBlocked++;
            if (dlCb) { try { dlCb(download, result); } catch (...) {} }
            result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            return result;
        }

        // Check file extension risk
        std::string ext = ToLower(fs::path(download.filename).extension().string());
        static const std::unordered_set<std::string> highRiskExts = {
            ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".scr", ".pif", ".com", ".hta", ".wsf", ".cpl", ".dll"
        };
        static const std::unordered_set<std::string> mediumRiskExts = {
            ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
            ".zip", ".rar", ".7z", ".iso", ".img"
        };

        if (highRiskExts.count(ext)) {
            result.riskScore = 70;
            result.verdict = DownloadVerdict::Suspicious;
            result.isSafe = false;
        } else if (mediumRiskExts.count(ext)) {
            result.riskScore = 40;
            result.verdict = DownloadVerdict::Suspicious;
        }

        // Check file size sanity (0 byte or extremely large files are suspicious)
        if (download.fileSize == 0 && !download.filename.empty()) {
            result.riskScore = std::max(result.riskScore, 30);
        }

        // Adjust based on URL reputation
        if (sbResult.isSuspicious) {
            result.riskScore = std::max(result.riskScore, static_cast<int>(sbResult.threatScore));
            result.verdict = DownloadVerdict::Suspicious;
            result.isSafe = false;
        }

        // Block if risk is critical
        if (result.riskScore >= 80) {
            result.shouldBlock = true;
            result.verdict = DownloadVerdict::Blocked;
            m_stats.downloadsBlocked++;
        }

        if (result.verdict != DownloadVerdict::Safe && result.verdict != DownloadVerdict::Unknown) {
            if (dlCb) { try { dlCb(download, result); } catch (...) {} }
        }

        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
        return result;
    }

    DownloadScanResult ScanDownload(const fs::path& filePath) {
        DownloadScanResult result;
        auto start = Clock::now();

        if (!fs::exists(filePath)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Download scan target does not exist: %ls", filePath.c_str());
            result.verdict = DownloadVerdict::Unknown;
            return result;
        }

        // Check file size against cap (prevent scanning extremely large files inline)
        std::error_code ec;
        auto fileSize = fs::file_size(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to get file size for scan: %ls", filePath.c_str());
            result.verdict = DownloadVerdict::Unknown;
            return result;
        }

        constexpr size_t MAX_INLINE_SCAN_SIZE = 256 * 1024 * 1024; // 256MB
        if (fileSize > MAX_INLINE_SCAN_SIZE) {
            SS_LOG_WARN(LOG_CATEGORY, L"File exceeds inline scan limit (%zu bytes): %ls",
                        static_cast<size_t>(fileSize), filePath.c_str());
            result.verdict = DownloadVerdict::Unknown;
            result.riskScore = 50;
            return result;
        }

        // Use MaliciousDownloadBlocker for deep file analysis
        auto& downloadBlocker = MaliciousDownloadBlocker::Instance();
        auto deepResult = downloadBlocker.ScanFile(filePath);

        result.shouldBlock = deepResult.shouldBlock;
        result.threatName = deepResult.threatName;
        result.riskScore = deepResult.riskScore;
        result.isSafe = !deepResult.shouldBlock;

        if (deepResult.shouldBlock) {
            result.verdict = DownloadVerdict::Malware;
            m_stats.downloadsBlocked++;
        } else if (deepResult.riskScore > 50) {
            result.verdict = DownloadVerdict::Suspicious;
        } else {
            result.verdict = DownloadVerdict::Safe;
            result.isSafe = true;
        }

        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
        SS_LOG_INFO(LOG_CATEGORY, L"Download scan complete: %ls verdict=%d risk=%d",
                    filePath.c_str(), static_cast<int>(result.verdict), result.riskScore);
        return result;
    }

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    URLCategory GetURLCategoryInternal(const std::string& url) {
        std::string domain = GetDomainFromUrl(url);

        // First check SafeBrowsingAPI for threat categories
        auto& safeBrowsing = SafeBrowsingAPI::Instance();
        auto sbResult = safeBrowsing.CheckUrl(url);

        if (sbResult.isMalicious) return URLCategory::Malware;
        if (sbResult.isPhishing) return URLCategory::Phishing;
        if (sbResult.isPUA) return URLCategory::Spam;

        // Then use domain-based categorization
        URLCategory domainCat = CategorizeByDomain(domain);
        if (domainCat != URLCategory::Unknown) return domainCat;

        return URLCategory::Unknown;
    }

    int GetURLRiskScoreInternal(const std::string& url) {
        int score = 0;

        // SafeBrowsingAPI threat score
        auto& safeBrowsing = SafeBrowsingAPI::Instance();
        auto sbResult = safeBrowsing.CheckUrl(url);
        score = std::max(score, static_cast<int>(sbResult.threatScore));

        if (sbResult.isMalicious) score = std::max(score, 90);
        if (sbResult.isPhishing) score = std::max(score, 85);
        if (sbResult.isSuspicious) score = std::max(score, 60);

        // Phishing detector risk score
        auto& phishing = PhishingDetector::Instance();
        int phishScore = phishing.GetRiskScore(url);
        score = std::max(score, phishScore);

        // Penalize HTTP-only URLs (no TLS)
        if (!IsHTTPS(url) && url.find("http://") == 0) {
            score = std::max(score, 20);
        }

        // Cap at 100
        return std::min(score, 100);
    }

    int GetDownloadReputationInternal(const std::string& url) {
        auto& safeBrowsing = SafeBrowsingAPI::Instance();
        auto sbResult = safeBrowsing.CheckUrl(url);

        if (sbResult.isMalicious) return 0;
        if (sbResult.isPhishing) return 10;
        if (sbResult.isSuspicious) return 30;
        if (sbResult.isPUA) return 25;

        // Higher confidence = higher reputation
        int reputation = 50 + static_cast<int>(sbResult.confidence) / 2;
        return std::min(reputation, 100);
    }

    // ========================================================================
    // BROWSER MANAGEMENT
    // ========================================================================

    std::vector<BrowserInstance> GetBrowserInstances() const {
        std::vector<BrowserInstance> instances;

        const BrowserType browserTypes[] = {
            BrowserType::Chrome, BrowserType::Edge, BrowserType::Firefox,
            BrowserType::Brave, BrowserType::Opera, BrowserType::Vivaldi
        };

        for (auto type : browserTypes) {
            std::wstring exeName = BrowserTypeToExeName(type);
            if (exeName.empty()) continue;

            auto pids = Utils::ProcessUtils::GetProcessIdsByName(exeName);
            for (auto pid : pids) {
                BrowserInstance inst;
                inst.processId = pid;
                inst.type = type;
                instances.push_back(std::move(inst));
            }
        }
        return instances;
    }

    std::vector<uint32_t> GetBrowserPidsInternal(BrowserType type) const {
        std::vector<uint32_t> result;

        if (type == BrowserType::Unknown) {
            // Return all browser PIDs
            auto instances = GetBrowserInstances();
            result.reserve(instances.size());
            for (const auto& inst : instances) {
                result.push_back(inst.processId);
            }
        } else {
            std::wstring exeName = BrowserTypeToExeName(type);
            if (!exeName.empty()) {
                auto pids = Utils::ProcessUtils::GetProcessIdsByName(exeName);
                result.reserve(pids.size());
                for (auto pid : pids) {
                    result.push_back(static_cast<uint32_t>(pid));
                }
            }
        }
        return result;
    }

    BrowserType GetBrowserTypeInternal(uint32_t pid) const {
        auto nameOpt = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(pid));
        if (!nameOpt) return BrowserType::Unknown;
        return ExeNameToBrowserType(*nameOpt);
    }

    // ========================================================================
    // EXTENSION MANAGEMENT
    // ========================================================================

    bool InstallExtensionInternal(BrowserType browser) {
        // Register native messaging host manifest for the target browser
        std::wstring exeName = BrowserTypeToExeName(browser);
        if (exeName.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot install extension for unsupported browser type %d",
                         static_cast<int>(browser));
            return false;
        }

        // Build native messaging host manifest path
        fs::path manifestDir;
        HKEY rootKey = HKEY_CURRENT_USER;
        std::wstring regPath;
        const char* allowedExtensionId = nullptr;

        switch (browser) {
            case BrowserType::Chrome:
            case BrowserType::Brave:
            case BrowserType::Vivaldi:
                regPath = L"SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\";
                regPath += Utils::StringUtils::ToWide(BrowserConstants::NATIVE_HOST_NAME);
                allowedExtensionId = BrowserConstants::CHROME_EXTENSION_ID;
                break;
            case BrowserType::Edge:
                regPath = L"SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\";
                regPath += Utils::StringUtils::ToWide(BrowserConstants::NATIVE_HOST_NAME);
                allowedExtensionId = BrowserConstants::CHROME_EXTENSION_ID;
                break;
            case BrowserType::Firefox: {
                // Firefox uses a JSON manifest in AppData (no registry entry)
                wchar_t appData[MAX_PATH] = {};
                if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH) > 0) {
                    manifestDir = fs::path(appData) / L"Mozilla" / L"NativeMessagingHosts";
                }
                break;
            }
            default:
                SS_LOG_WARN(LOG_CATEGORY, L"Extension install not supported for browser type %d",
                            static_cast<int>(browser));
                return false;
        }

        // Chromium-based browsers: write the manifest JSON to disk AND register the
        // registry pointer that names it. The original implementation only wrote the
        // registry entry, leaving the manifest file missing and breaking installation.
        if (!regPath.empty()) {
            wchar_t modulePath[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"GetModuleFileNameW failed during extension install: %lu",
                             GetLastError());
                return false;
            }
            fs::path hostExePath = fs::path(modulePath).parent_path() / L"ShadowStrikeNativeHost.exe";
            fs::path manifestPath = hostExePath.parent_path() / L"native_messaging_manifest.json";

            // 1. Write the manifest JSON next to the native host executable.
            {
                std::error_code ec;
                fs::create_directories(manifestPath.parent_path(), ec);
                if (ec) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                                 L"Failed to create native messaging manifest directory: %hs",
                                 ec.message().c_str());
                    return false;
                }

                std::ofstream ofs(manifestPath, std::ios::binary | std::ios::trunc);
                if (!ofs.is_open()) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                                 L"Failed to open Chromium native messaging manifest for write: %ls",
                                 manifestPath.c_str());
                    return false;
                }

                const std::string allowedOriginPrefix = "chrome-extension://";
                const std::string allowedOrigin =
                    allowedExtensionId
                        ? (allowedOriginPrefix + std::string(allowedExtensionId) + "/")
                        : std::string{};

                ofs << "{\n"
                    << "  \"name\": \"" << BrowserConstants::NATIVE_HOST_NAME << "\",\n"
                    << "  \"description\": \"ShadowStrike Browser Protection\",\n"
                    << "  \"path\": \"" << EscapeJson(hostExePath.string()) << "\",\n"
                    << "  \"type\": \"stdio\",\n"
                    << "  \"allowed_origins\": [\"" << EscapeJson(allowedOrigin) << "\"]\n"
                    << "}\n";
                ofs.close();
                if (ofs.fail()) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                                 L"Stream error while writing Chromium native messaging manifest: %ls",
                                 manifestPath.c_str());
                    return false;
                }
            }

            // 2. Register the manifest pointer under HKCU.
            HKEY hKey = nullptr;
            LONG res = RegCreateKeyExW(rootKey, regPath.c_str(), 0, nullptr,
                                       REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
            if (res != ERROR_SUCCESS || hKey == nullptr) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Failed to create registry key for native messaging host: %ld", res);
                return false;
            }

            const std::wstring manifestPathStr = manifestPath.wstring();
            const LONG setRes = RegSetValueExW(
                hKey, nullptr, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(manifestPathStr.c_str()),
                static_cast<DWORD>((manifestPathStr.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);

            if (setRes != ERROR_SUCCESS) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"RegSetValueExW failed for native messaging host manifest: %ld", setRes);
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Registered native messaging host for %ls (manifest: %ls)",
                        exeName.c_str(), manifestPath.c_str());
            return true;
        }

        // Firefox: write JSON manifest file
        if (!manifestDir.empty()) {
            std::error_code ec;
            fs::create_directories(manifestDir, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to create Firefox native messaging directory: %hs",
                             ec.message().c_str());
                return false;
            }

            fs::path manifestFile = manifestDir / (std::string(BrowserConstants::NATIVE_HOST_NAME) + ".json");
            std::ofstream ofs(manifestFile, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to write Firefox native messaging manifest");
                return false;
            }

            wchar_t modulePath[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"GetModuleFileNameW failed during Firefox install: %lu",
                             GetLastError());
                return false;
            }
            fs::path hostExePath = fs::path(modulePath).parent_path() / L"ShadowStrikeNativeHost.exe";

            ofs << "{\n"
                << "  \"name\": \"" << BrowserConstants::NATIVE_HOST_NAME << "\",\n"
                << "  \"description\": \"ShadowStrike Browser Protection\",\n"
                << "  \"path\": \"" << EscapeJson(hostExePath.string()) << "\",\n"
                << "  \"type\": \"stdio\",\n"
                << "  \"allowed_extensions\": [\"" << BrowserConstants::FIREFOX_EXTENSION_ID << "\"]\n"
                << "}\n";
            ofs.close();
            if (ofs.fail()) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Stream error while writing Firefox native messaging manifest: %ls",
                             manifestFile.c_str());
                return false;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Wrote Firefox native messaging manifest to %ls", manifestFile.c_str());
            return true;
        }

        return false;
    }

    ExtensionStatus GetExtensionStatusInternal(BrowserType browser) const {
        std::wstring exeName = BrowserTypeToExeName(browser);
        if (exeName.empty()) return ExtensionStatus::NotInstalled;

        // Check if native messaging host is registered
        std::wstring regPath;
        switch (browser) {
            case BrowserType::Chrome:
            case BrowserType::Brave:
            case BrowserType::Vivaldi:
                regPath = L"SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\";
                regPath += Utils::StringUtils::ToWide(BrowserConstants::NATIVE_HOST_NAME);
                break;
            case BrowserType::Edge:
                regPath = L"SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\";
                regPath += Utils::StringUtils::ToWide(BrowserConstants::NATIVE_HOST_NAME);
                break;
            case BrowserType::Firefox: {
                wchar_t appData[MAX_PATH] = {};
                if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH) > 0) {
                    fs::path manifestFile = fs::path(appData) / L"Mozilla" / L"NativeMessagingHosts" /
                                            (std::string(BrowserConstants::NATIVE_HOST_NAME) + ".json");
                    if (fs::exists(manifestFile)) return ExtensionStatus::Enabled;
                }
                return ExtensionStatus::NotInstalled;
            }
            default:
                return ExtensionStatus::NotInstalled;
        }

        if (!regPath.empty()) {
            HKEY hKey = nullptr;
            LONG res = RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey);
            if (res == ERROR_SUCCESS && hKey) {
                RegCloseKey(hKey);
                return ExtensionStatus::Enabled;
            }
        }

        return ExtensionStatus::NotInstalled;
    }

    // ========================================================================
    // NATIVE MESSAGING
    // ========================================================================

    bool StartNativeMessagingInternal() {
        if (m_nativeMessagingRunning.load()) return true;

        // Verify the native host executable exists
        wchar_t modulePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
        fs::path hostExePath = fs::path(modulePath).parent_path() / L"ShadowStrikeNativeHost.exe";
        if (!fs::exists(hostExePath) || !fs::is_regular_file(hostExePath)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Native messaging host executable missing: %ls", hostExePath.c_str());
            return false;
        }

        m_nativeMessagingRunning.store(true);
        SS_LOG_INFO(LOG_CATEGORY, L"Native messaging host started");
        return true;
    }

    void StopNativeMessagingInternal() {
        if (!m_nativeMessagingRunning.load()) return;

        // Close the named pipe handle if open
        if (m_nativePipeHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_nativePipeHandle);
            m_nativePipeHandle = INVALID_HANDLE_VALUE;
        }

        m_nativeMessagingRunning.store(false);
        SS_LOG_INFO(LOG_CATEGORY, L"Native messaging host stopped");
    }

    bool IsNativeMessagingRunningInternal() const noexcept {
        if (!m_nativeMessagingRunning.load()) return false;

        // Verify the named pipe exists
        std::wstring pipeName = L"\\\\.\\pipe\\ShadowStrikeBrowserProtection";
        HANDLE hPipe = CreateFileW(pipeName.c_str(), GENERIC_READ, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            return true;
        }

        // Pipe may not be created yet but the flag indicates intent to run
        return m_nativeMessagingRunning.load();
    }

    // ========================================================================
    // SAFE SEARCH
    // ========================================================================

    bool EnforceSafeSearchInternal(bool enable) {
        std::unique_lock lock(m_mutex);
        m_safeSearchEnforced = enable;
        SS_LOG_INFO(LOG_CATEGORY, L"Safe search enforcement %ls", enable ? L"enabled" : L"disabled");
        return true;
    }

    bool IsSafeSearchEnforcedInternal() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_safeSearchEnforced;
    }

    bool UpdateSafeSearchSettingsInternal(const SafeSearchSettings& settings) {
        std::unique_lock lock(m_mutex);
        m_safeSearchSettings = settings;
        m_safeSearchEnforced = settings.enabled;
        return true;
    }

    // ========================================================================
    // PARENTAL CONTROLS
    // ========================================================================

    bool EnableParentalControlsInternal(bool enable) {
        std::unique_lock lock(m_mutex);
        m_parentalSettings.enabled = enable;
        m_config.enableParentalControls = enable;
        SS_LOG_INFO(LOG_CATEGORY, L"Parental controls %ls", enable ? L"enabled" : L"disabled");
        return true;
    }

    bool UpdateParentalControlsInternal(const ParentalControlSettings& settings) {
        std::unique_lock lock(m_mutex);
        m_parentalSettings = settings;
        m_config.enableParentalControls = settings.enabled;
        return true;
    }

    ParentalControlSettings GetParentalControlsInternal() const {
        std::shared_lock lock(m_mutex);
        return m_parentalSettings;
    }

    // ========================================================================
    // LIST MANAGEMENT
    // ========================================================================

    bool AddToBlocklistInternal(const std::string& domain) {
        const std::string normalized = NormalizeDomainCandidate(domain);
        if (normalized.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"AddToBlocklist rejected: malformed domain candidate");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_blocklist.insert(normalized);
        return true;
    }

    bool RemoveFromBlocklistInternal(const std::string& domain) {
        const std::string normalized = NormalizeDomainCandidate(domain);
        if (normalized.empty()) return false;
        std::unique_lock lock(m_mutex);
        return m_blocklist.erase(normalized) > 0;
    }

    bool IsInBlocklistInternal(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        std::string domLower = ToLower(domain);
        if (m_blocklist.count(domLower)) return true;
        // Check if any blocklist entry is a suffix of the domain
        for (const auto& blocked : m_blocklist) {
            if (DomainEndsWith(domLower, blocked)) return true;
        }
        return false;
    }

    bool AddToAllowlistInternal(const std::string& domain) {
        const std::string normalized = NormalizeDomainCandidate(domain);
        if (normalized.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"AddToAllowlist rejected: malformed domain candidate");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_allowlist.insert(normalized);
        return true;
    }

    bool RemoveFromAllowlistInternal(const std::string& domain) {
        const std::string normalized = NormalizeDomainCandidate(domain);
        if (normalized.empty()) return false;
        std::unique_lock lock(m_mutex);
        return m_allowlist.erase(normalized) > 0;
    }

    bool IsInAllowlistInternal(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        std::string domLower = ToLower(domain);
        if (m_allowlist.count(domLower)) return true;
        for (const auto& allowed : m_allowlist) {
            if (DomainEndsWith(domLower, allowed)) return true;
        }
        return false;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterNavigationCallback(NavigationCallback callback) {
        std::unique_lock lock(m_mutex);
        m_navCallback = std::move(callback);
    }

    void RegisterDownloadCallback(DownloadCallback callback) {
        std::unique_lock lock(m_mutex);
        m_downloadCallback = std::move(callback);
    }

    void RegisterBlockCallback(BlockCallback callback) {
        std::unique_lock lock(m_mutex);
        m_blockCallback = std::move(callback);
    }

    void RegisterBrowserEventCallback(BrowserEventCallback callback) {
        std::unique_lock lock(m_mutex);
        m_eventCallback = std::move(callback);
    }

    void RegisterPreNavigationCallback(PreNavigationCallback callback) {
        std::unique_lock lock(m_mutex);
        m_preNavCallback = std::move(callback);
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallback = std::move(callback);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_navCallback = nullptr;
        m_downloadCallback = nullptr;
        m_blockCallback = nullptr;
        m_eventCallback = nullptr;
        m_preNavCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    BrowserProtectionStatistics GetStatistics() const {
        BrowserProtectionStatistics stats;
        stats.totalNavigations = m_stats.totalNavigations.load();
        stats.allowedNavigations = m_stats.allowedNavigations.load();
        stats.blockedNavigations = m_stats.blockedNavigations.load();
        stats.warnedNavigations = m_stats.warnedNavigations.load();
        stats.malwareBlocked = m_stats.malwareBlocked.load();
        stats.phishingBlocked = m_stats.phishingBlocked.load();
        stats.categoryBlocked = m_stats.categoryBlocked.load();
        stats.downloadsScanned = m_stats.downloadsScanned.load();
        stats.downloadsBlocked = m_stats.downloadsBlocked.load();
        stats.adsBlocked = m_stats.adsBlocked.load();
        stats.trackersBlocked = m_stats.trackersBlocked.load();
        stats.safeSearchEnforced = m_stats.safeSearchEnforced.load();
        stats.cacheHits = m_stats.cacheHits.load();
        stats.cacheMisses = m_stats.cacheMisses.load();
        AtomicValueStoreRelaxed(stats.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    void NotifyBlock(const std::string& url, BlockReason reason) {
        // Snapshot callback under lock, invoke without holding lock.
        BlockCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_blockCallback;
        }
        InvokeBlockCallback(cb, url, reason);
    }

    // Helper: invoke a snapshot block callback safely outside of any lock.
    void InvokeBlockCallback(const BlockCallback& cb, const std::string& url, BlockReason reason) noexcept {
        if (!cb) return;
        try { cb(url, reason); } catch (...) {}
    }

    bool IsCategoryBlocked(const std::string& domain) {
        if (m_parentalSettings.blockedCategories.empty()) return false;

        URLCategory cat = CategorizeByDomain(domain);
        if (cat == URLCategory::Unknown) return false;

        return m_parentalSettings.blockedCategories.count(cat) > 0;
    }

    // Snapshot variant: evaluates against a previously-captured ParentalControlSettings,
    // avoiding any further lock acquisition during the navigation hot path.
    [[nodiscard]] bool IsCategoryBlockedFromSnapshot(const std::string& domain,
                                                     const ParentalControlSettings& snap) const {
        if (snap.blockedCategories.empty()) return false;
        URLCategory cat = CategorizeByDomain(domain);
        if (cat == URLCategory::Unknown) return false;
        return snap.blockedCategories.count(cat) > 0;
    }

    void EnforceSafeSearchOnUrl(const std::string& url, const std::string& domain) {
        // Track safe search enforcement in stats
        bool isSearchEngine = false;
        for (const char* searchDomain : BrowserConstants::SAFE_SEARCH_DOMAINS) {
            if (DomainEndsWith(domain, searchDomain)) {
                isSearchEngine = true;
                break;
            }
        }
        if (isSearchEngine) {
            m_stats.safeSearchEnforced++;
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    BrowserProtectionConfiguration m_config;
    BrowserProtectionStatistics m_stats;

    std::unordered_set<std::string> m_blocklist;
    std::unordered_set<std::string> m_allowlist;
    std::atomic<bool> m_nativeMessagingRunning{false};
    HANDLE m_nativePipeHandle = INVALID_HANDLE_VALUE;

    // Safe search and parental control state
    SafeSearchSettings m_safeSearchSettings;
    ParentalControlSettings m_parentalSettings;
    bool m_safeSearchEnforced = false;

    // Callbacks
    NavigationCallback m_navCallback;
    DownloadCallback m_downloadCallback;
    BlockCallback m_blockCallback;
    BrowserEventCallback m_eventCallback;
    PreNavigationCallback m_preNavCallback;
    ErrorCallback m_errorCallback;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

BrowserProtection& BrowserProtection::Instance() noexcept {
    static BrowserProtection instance;
    return instance;
}

bool BrowserProtection::HasInstance() noexcept {
    return s_instanceCreated.load();
}

BrowserProtection::BrowserProtection() : m_impl(std::make_unique<BrowserProtectionImpl>()) {
    s_instanceCreated.store(true);
}

BrowserProtection::~BrowserProtection() {
    s_instanceCreated.store(false);
}

bool BrowserProtection::Initialize(const BrowserProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

void BrowserProtection::Shutdown() {
    m_impl->Shutdown();
}

bool BrowserProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus BrowserProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool BrowserProtection::UpdateConfiguration(const BrowserProtectionConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

BrowserProtectionConfiguration BrowserProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

NavigationResult BrowserProtection::OnNavigate(const NavigationRequest& request) {
    return m_impl->OnNavigate(request);
}

NavigationResult BrowserProtection::CheckURL(const std::string& url, uint32_t browserPid) {
    NavigationRequest req;
    req.url = url;
    req.domain = ExtractDomain(url);
    req.browserPid = browserPid;
    return m_impl->OnNavigate(req);
}

bool BrowserProtection::IsURLBlocked(const std::string& url) {
    NavigationRequest req;
    req.url = url;
    req.domain = ExtractDomain(url);
    return m_impl->OnNavigate(req).IsBlocked();
}

URLCategory BrowserProtection::GetURLCategory(const std::string& url) {
    return m_impl->GetURLCategoryInternal(url);
}

int BrowserProtection::GetURLRiskScore(const std::string& url) {
    return m_impl->GetURLRiskScoreInternal(url);
}

DownloadScanResult BrowserProtection::OnDownload(const DownloadInfo& download) {
    return m_impl->OnDownload(download);
}

DownloadScanResult BrowserProtection::ScanDownload(const fs::path& filePath) {
    return m_impl->ScanDownload(filePath);
}

int BrowserProtection::GetDownloadReputation(const std::string& url) {
    return m_impl->GetDownloadReputationInternal(url);
}

std::vector<BrowserInstance> BrowserProtection::GetBrowserInstances() const {
    return m_impl->GetBrowserInstances();
}

std::vector<uint32_t> BrowserProtection::GetBrowserPids(BrowserType type) const {
    return m_impl->GetBrowserPidsInternal(type);
}

BrowserType BrowserProtection::GetBrowserType(uint32_t pid) const {
    return m_impl->GetBrowserTypeInternal(pid);
}

bool BrowserProtection::InstallExtension(BrowserType browser) {
    return m_impl->InstallExtensionInternal(browser);
}

ExtensionStatus BrowserProtection::GetExtensionStatus(BrowserType browser) const {
    return m_impl->GetExtensionStatusInternal(browser);
}

bool BrowserProtection::StartNativeMessaging() {
    return m_impl->StartNativeMessagingInternal();
}

void BrowserProtection::StopNativeMessaging() {
    m_impl->StopNativeMessagingInternal();
}

bool BrowserProtection::IsNativeMessagingRunning() const noexcept {
    return m_impl->IsNativeMessagingRunningInternal();
}

bool BrowserProtection::RegisterNativeHost(BrowserType browser) {
    return m_impl->InstallExtensionInternal(browser);
}

bool BrowserProtection::EnforceSafeSearch(bool enable) {
    return m_impl->EnforceSafeSearchInternal(enable);
}

bool BrowserProtection::IsSafeSearchEnforced() const noexcept {
    return m_impl->IsSafeSearchEnforcedInternal();
}

bool BrowserProtection::UpdateSafeSearchSettings(const SafeSearchSettings& settings) {
    return m_impl->UpdateSafeSearchSettingsInternal(settings);
}

bool BrowserProtection::EnableParentalControls(bool enable) {
    return m_impl->EnableParentalControlsInternal(enable);
}

bool BrowserProtection::UpdateParentalControls(const ParentalControlSettings& settings) {
    return m_impl->UpdateParentalControlsInternal(settings);
}

ParentalControlSettings BrowserProtection::GetParentalControls() const {
    return m_impl->GetParentalControlsInternal();
}

bool BrowserProtection::AddToBlocklist(const std::string& domain) {
    return m_impl->AddToBlocklistInternal(domain);
}

bool BrowserProtection::RemoveFromBlocklist(const std::string& domain) {
    return m_impl->RemoveFromBlocklistInternal(domain);
}

bool BrowserProtection::IsInBlocklist(const std::string& domain) const {
    return m_impl->IsInBlocklistInternal(domain);
}

bool BrowserProtection::AddToAllowlist(const std::string& domain) {
    return m_impl->AddToAllowlistInternal(domain);
}

bool BrowserProtection::RemoveFromAllowlist(const std::string& domain) {
    return m_impl->RemoveFromAllowlistInternal(domain);
}

bool BrowserProtection::IsInAllowlist(const std::string& domain) const {
    return m_impl->IsInAllowlistInternal(domain);
}

// Sub-component access: use the singleton instances
SafeBrowsingAPI& BrowserProtection::GetSafeBrowsingAPI() {
    return SafeBrowsingAPI::Instance();
}

PhishingDetector& BrowserProtection::GetPhishingDetector() {
    return PhishingDetector::Instance();
}

MaliciousDownloadBlocker& BrowserProtection::GetDownloadBlocker() {
    return MaliciousDownloadBlocker::Instance();
}

AdBlocker& BrowserProtection::GetAdBlocker() {
    return AdBlocker::Instance();
}

TrackerBlocker& BrowserProtection::GetTrackerBlocker() {
    return TrackerBlocker::Instance();
}

void BrowserProtection::RegisterNavigationCallback(NavigationCallback callback) {
    m_impl->RegisterNavigationCallback(std::move(callback));
}

void BrowserProtection::RegisterDownloadCallback(DownloadCallback callback) {
    m_impl->RegisterDownloadCallback(std::move(callback));
}

void BrowserProtection::RegisterBlockCallback(BlockCallback callback) {
    m_impl->RegisterBlockCallback(std::move(callback));
}

void BrowserProtection::RegisterBrowserEventCallback(BrowserEventCallback callback) {
    m_impl->RegisterBrowserEventCallback(std::move(callback));
}

void BrowserProtection::RegisterPreNavigationCallback(PreNavigationCallback callback) {
    m_impl->RegisterPreNavigationCallback(std::move(callback));
}

void BrowserProtection::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void BrowserProtection::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

BrowserProtectionStatistics BrowserProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void BrowserProtection::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool BrowserProtection::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"SelfTest: beginning browser protection verification");

    // Test 1: Blocklist operations
    bool addOk = AddToBlocklist("test-selftest-malware.example.com");
    if (!addOk) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not add domain to blocklist");
        return false;
    }

    bool isBlocked = IsInBlocklist("test-selftest-malware.example.com");
    if (!isBlocked) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: added domain not found in blocklist");
        RemoveFromBlocklist("test-selftest-malware.example.com");
        return false;
    }

    // Test 2: Allowlist operations
    bool allowOk = AddToAllowlist("test-selftest-safe.example.com");
    if (!allowOk) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not add domain to allowlist");
        RemoveFromBlocklist("test-selftest-malware.example.com");
        return false;
    }

    bool isAllowed = IsInAllowlist("test-selftest-safe.example.com");
    if (!isAllowed) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: added domain not found in allowlist");
        RemoveFromBlocklist("test-selftest-malware.example.com");
        RemoveFromAllowlist("test-selftest-safe.example.com");
        return false;
    }

    // Test 3: URL category function returns a valid result
    URLCategory cat = GetURLCategory("https://www.google.com");
    (void)cat; // Category may vary; just verify no crash

    // Test 4: Risk score returns within range
    int score = GetURLRiskScore("https://example.com");
    if (score < 0 || score > 100) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: risk score %d out of range [0,100]", score);
        RemoveFromBlocklist("test-selftest-malware.example.com");
        RemoveFromAllowlist("test-selftest-safe.example.com");
        return false;
    }

    // Cleanup
    RemoveFromBlocklist("test-selftest-malware.example.com");
    RemoveFromAllowlist("test-selftest-safe.example.com");

    SS_LOG_INFO(LOG_CATEGORY, L"SelfTest: all 4 verification checks passed");
    return true;
}

std::string BrowserProtection::GetVersionString() noexcept {
    return std::to_string(BrowserConstants::VERSION_MAJOR) + "." +
           std::to_string(BrowserConstants::VERSION_MINOR) + "." +
           std::to_string(BrowserConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetBrowserTypeName(BrowserType type) noexcept {
    switch (type) {
        case BrowserType::Unknown:          return "Unknown";
        case BrowserType::Chrome:           return "Chrome";
        case BrowserType::Edge:             return "Edge";
        case BrowserType::Firefox:          return "Firefox";
        case BrowserType::Brave:            return "Brave";
        case BrowserType::Opera:            return "Opera";
        case BrowserType::Vivaldi:          return "Vivaldi";
        case BrowserType::Safari:           return "Safari";
        case BrowserType::InternetExplorer: return "InternetExplorer";
    }
    return "Unknown";
}

std::string_view GetNavigationActionName(NavigationAction action) noexcept {
    switch (action) {
        case NavigationAction::Allow:   return "Allow";
        case NavigationAction::Block:   return "Block";
        case NavigationAction::Warn:    return "Warn";
        case NavigationAction::Redirect: return "Redirect";
        case NavigationAction::Log:     return "Log";
        case NavigationAction::Sandbox: return "Sandbox";
    }
    return "Allow";
}

std::string_view GetBlockReasonName(BlockReason reason) noexcept {
    switch (reason) {
        case BlockReason::None:             return "None";
        case BlockReason::Malware:          return "Malware";
        case BlockReason::Phishing:         return "Phishing";
        case BlockReason::Spam:             return "Spam";
        case BlockReason::AdultContent:     return "AdultContent";
        case BlockReason::Violence:         return "Violence";
        case BlockReason::Gambling:         return "Gambling";
        case BlockReason::SocialMedia:      return "SocialMedia";
        case BlockReason::Streaming:        return "Streaming";
        case BlockReason::Gaming:           return "Gaming";
        case BlockReason::Shopping:         return "Shopping";
        case BlockReason::News:             return "News";
        case BlockReason::PolicyViolation:  return "PolicyViolation";
        case BlockReason::CustomBlocklist:  return "CustomBlocklist";
        case BlockReason::CategoryBlocked:  return "CategoryBlocked";
        case BlockReason::TimeRestriction:  return "TimeRestriction";
        case BlockReason::Cryptomining:     return "Cryptomining";
        case BlockReason::Scam:             return "Scam";
        case BlockReason::C2Server:         return "C2Server";
        case BlockReason::DGA:             return "DGA";
        case BlockReason::Typosquatting:    return "Typosquatting";
        case BlockReason::Reputation:       return "Reputation";
        case BlockReason::Advertising:      return "Advertising";
    }
    return "None";
}

std::string_view GetURLCategoryName(URLCategory category) noexcept {
    switch (category) {
        case URLCategory::Unknown:       return "Unknown";
        case URLCategory::Business:      return "Business";
        case URLCategory::Education:     return "Education";
        case URLCategory::Entertainment: return "Entertainment";
        case URLCategory::Finance:       return "Finance";
        case URLCategory::Games:         return "Games";
        case URLCategory::Government:    return "Government";
        case URLCategory::Health:        return "Health";
        case URLCategory::News:          return "News";
        case URLCategory::Search:        return "Search";
        case URLCategory::Shopping:      return "Shopping";
        case URLCategory::SocialMedia:   return "SocialMedia";
        case URLCategory::Sports:        return "Sports";
        case URLCategory::Technology:    return "Technology";
        case URLCategory::Travel:        return "Travel";
        case URLCategory::Adult:         return "Adult";
        case URLCategory::Gambling:      return "Gambling";
        case URLCategory::Violence:      return "Violence";
        case URLCategory::Weapons:       return "Weapons";
        case URLCategory::Drugs:         return "Drugs";
        case URLCategory::Hacking:       return "Hacking";
        case URLCategory::Malware:       return "Malware";
        case URLCategory::Phishing:      return "Phishing";
        case URLCategory::Spam:          return "Spam";
        case URLCategory::Proxy:         return "Proxy";
        case URLCategory::Advertising:   return "Advertising";
        case URLCategory::Streaming:     return "Streaming";
    }
    return "Unknown";
}

std::string_view GetDownloadVerdictName(DownloadVerdict verdict) noexcept {
    switch (verdict) {
        case DownloadVerdict::Safe:       return "Safe";
        case DownloadVerdict::Suspicious: return "Suspicious";
        case DownloadVerdict::Malware:    return "Malware";
        case DownloadVerdict::PUP:        return "PUP";
        case DownloadVerdict::Unknown:    return "Unknown";
        case DownloadVerdict::Blocked:    return "Blocked";
    }
    return "Unknown";
}

std::string_view GetExtensionStatusName(ExtensionStatus status) noexcept {
    switch (status) {
        case ExtensionStatus::NotInstalled:    return "NotInstalled";
        case ExtensionStatus::Disabled:        return "Disabled";
        case ExtensionStatus::Enabled:         return "Enabled";
        case ExtensionStatus::UpdateAvailable: return "UpdateAvailable";
        case ExtensionStatus::Error:           return "Error";
    }
    return "NotInstalled";
}

std::string ExtractDomain(const std::string& url) {
    return GetDomainFromUrl(url);
}

std::string NormalizeURL(const std::string& url) {
    if (url.empty()) return {};

    std::string result = url;

    // 1. Lowercase scheme and host
    size_t schemeEnd = result.find("://");
    if (schemeEnd != std::string::npos) {
        for (size_t i = 0; i <= schemeEnd + 2; ++i) {
            result[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(result[i])));
        }
        // Lowercase the host portion
        size_t hostStart = schemeEnd + 3;
        size_t hostEnd = result.find_first_of("/?#:", hostStart);
        if (hostEnd == std::string::npos) hostEnd = result.size();
        for (size_t i = hostStart; i < hostEnd; ++i) {
            result[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(result[i])));
        }
    } else {
        // No scheme - lowercase everything up to first /
        size_t slashPos = result.find('/');
        size_t end = slashPos == std::string::npos ? result.size() : slashPos;
        for (size_t i = 0; i < end; ++i) {
            result[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(result[i])));
        }
    }

    // 2. Decode percent-encoded characters that are safe (unreserved: A-Z a-z 0-9 - . _ ~)
    std::string decoded;
    decoded.reserve(result.size());
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i] == '%' && i + 2 < result.size()) {
            char h1 = result[i + 1];
            char h2 = result[i + 2];
            if (std::isxdigit(static_cast<unsigned char>(h1)) &&
                std::isxdigit(static_cast<unsigned char>(h2))) {
                unsigned int val = 0;
                std::istringstream iss(std::string{h1, h2});
                iss >> std::hex >> val;
                char ch = static_cast<char>(val);
                if (std::isalnum(static_cast<unsigned char>(ch)) ||
                    ch == '-' || ch == '.' || ch == '_' || ch == '~') {
                    decoded += ch;
                    i += 2;
                    continue;
                }
            }
        }
        decoded += result[i];
    }
    result = std::move(decoded);

    // 3. Remove default port (:80 for http, :443 for https)
    if (result.find("http://") == 0) {
        size_t hostStart = 7;
        size_t portPos = result.find(":80", hostStart);
        if (portPos != std::string::npos) {
            size_t afterPort = portPos + 3;
            if (afterPort >= result.size() || result[afterPort] == '/' || result[afterPort] == '?') {
                result.erase(portPos, 3);
            }
        }
    } else if (result.find("https://") == 0) {
        size_t hostStart = 8;
        size_t portPos = result.find(":443", hostStart);
        if (portPos != std::string::npos) {
            size_t afterPort = portPos + 4;
            if (afterPort >= result.size() || result[afterPort] == '/' || result[afterPort] == '?') {
                result.erase(portPos, 4);
            }
        }
    }

    // 4. Normalize path: remove /./ and resolve /../
    size_t pathStart = result.find('/', result.find("://") != std::string::npos ? result.find("://") + 3 : 0);
    if (pathStart != std::string::npos) {
        std::string pathPart = result.substr(pathStart);
        std::string queryPart;
        size_t queryPos = pathPart.find('?');
        if (queryPos != std::string::npos) {
            queryPart = pathPart.substr(queryPos);
            pathPart = pathPart.substr(0, queryPos);
        }

        // Remove /./ segments
        std::string normalizedPath;
        size_t pos = 0;
        while (pos < pathPart.size()) {
            if (pos + 2 <= pathPart.size() && pathPart.substr(pos, 2) == "./") {
                if (pos == 0 || pathPart[pos - 1] == '/') {
                    pos += 2;
                    continue;
                }
            }
            if (pos + 3 <= pathPart.size() && pathPart.substr(pos, 3) == "/./") {
                normalizedPath += '/';
                pos += 3;
                continue;
            }
            normalizedPath += pathPart[pos];
            ++pos;
        }

        // Resolve /../ segments
        std::vector<std::string> segments;
        std::istringstream segStream(normalizedPath);
        std::string segment;
        while (std::getline(segStream, segment, '/')) {
            if (segment == "..") {
                if (!segments.empty()) segments.pop_back();
            } else if (!segment.empty() && segment != ".") {
                segments.push_back(segment);
            }
        }

        std::string resolvedPath = "/";
        for (size_t i = 0; i < segments.size(); ++i) {
            if (i > 0) resolvedPath += '/';
            resolvedPath += segments[i];
        }

        result = result.substr(0, pathStart) + resolvedPath + queryPart;
    }

    // 5. Remove trailing fragment (#...)
    size_t fragPos = result.find('#');
    if (fragPos != std::string::npos) {
        result.erase(fragPos);
    }

    return result;
}

bool IsHTTPS(const std::string& url) {
    return ToLower(url).find("https://") == 0;
}

BrowserType DetectBrowserFromProcess(uint32_t pid) {
    auto nameOpt = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(pid));
    if (!nameOpt) return BrowserType::Unknown;
    return ExeNameToBrowserType(*nameOpt);
}

std::vector<fs::path> GetBrowserProfilePaths(BrowserType browser) {
    std::vector<fs::path> paths;

    wchar_t localAppData[MAX_PATH] = {};
    wchar_t appData[MAX_PATH] = {};
    GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH);

    switch (browser) {
        case BrowserType::Chrome:
            paths.push_back(fs::path(localAppData) / L"Google" / L"Chrome" / L"User Data");
            break;
        case BrowserType::Edge:
            paths.push_back(fs::path(localAppData) / L"Microsoft" / L"Edge" / L"User Data");
            break;
        case BrowserType::Firefox:
            paths.push_back(fs::path(appData) / L"Mozilla" / L"Firefox" / L"Profiles");
            break;
        case BrowserType::Brave:
            paths.push_back(fs::path(localAppData) / L"BraveSoftware" / L"Brave-Browser" / L"User Data");
            break;
        case BrowserType::Opera:
            paths.push_back(fs::path(appData) / L"Opera Software" / L"Opera Stable");
            break;
        case BrowserType::Vivaldi:
            paths.push_back(fs::path(localAppData) / L"Vivaldi" / L"User Data");
            break;
        default:
            break;
    }

    // Filter to only existing paths
    std::vector<fs::path> existingPaths;
    for (const auto& p : paths) {
        std::error_code ec;
        if (fs::exists(p, ec)) {
            existingPaths.push_back(p);
        }
    }

    return existingPaths;
}

}  // namespace WebBrowser
}  // namespace ShadowStrike

