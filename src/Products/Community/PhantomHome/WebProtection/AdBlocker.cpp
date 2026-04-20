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
 * ShadowStrike NGAV - AD BLOCKER MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file AdBlocker.cpp
 * @brief Implementation of the enterprise ad blocking engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "AdBlocker.hpp"
#include "PhantomCore/Utils/NetworkUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <future>
#include <filesystem>
#include <iomanip>
#include <cctype>

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"AdBlocker";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> AdBlocker::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
namespace {
    inline constexpr uintmax_t MAX_FILTER_LIST_FILE_SIZE = 64ULL * 1024ULL * 1024ULL;
    inline constexpr size_t MAX_FILTER_RULE_LENGTH = 8192;
    inline constexpr size_t MAX_REGEX_RULE_LENGTH = 1024;

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    bool StartsWith(std::string_view str, std::string_view prefix) noexcept {
        return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
    }

    bool EndsWith(std::string_view str, std::string_view suffix) noexcept {
        return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
    }

    std::string ToLowerStr(std::string_view sv) {
        std::string result(sv);
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    std::string GetDomainFromUrl(const std::string& url) {
        const std::wstring wideUrl = Utils::StringUtils::ToWide(url);
        if (!wideUrl.empty()) {
            Utils::NetworkUtils::UrlComponents components;
            Utils::NetworkUtils::Error parseError;
            if (Utils::NetworkUtils::ParseUrl(wideUrl, components, &parseError) &&
                !components.host.empty())
            {
                return ToLowerStr(Utils::StringUtils::ToNarrow(components.host));
            }
        }

        if (url.find("://") == std::string::npos &&
            url.find('/') == std::string::npos &&
            url.find('?') == std::string::npos &&
            url.find('#') == std::string::npos)
        {
            return ToLowerStr(url);
        }

        return {};
    }

    [[nodiscard]] bool IsStrictUtf8(std::string_view value) noexcept {
        if (value.empty()) {
            return true;
        }

        const int required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0);
        return required > 0;
    }

    [[nodiscard]] bool ContainsEmbeddedLineBreak(std::string_view value) noexcept {
        return value.find('\r') != std::string_view::npos ||
               value.find('\n') != std::string_view::npos ||
               value.find('\0') != std::string_view::npos;
    }

    std::string GetBaseDomain(const std::string& domain) {
        auto parts = std::string_view(domain);
        size_t dotCount = 0;
        for (auto c : parts) {
            if (c == '.') ++dotCount;
        }
        if (dotCount <= 1) return domain;
        size_t pos = parts.find('.');
        if (pos != std::string_view::npos) {
            return std::string(parts.substr(pos + 1));
        }
        return domain;
    }

    bool IsSeparator(char c) noexcept {
        return c == '/' || c == ':' || c == '?' || c == '=' || c == '&' ||
               c == '#' || c == '^' || c == ' ' || c == '\t' || c == '\r' ||
               c == '\n' || c == '!' || c == '%';
    }

    bool IsDomainBoundary(std::string_view url, size_t pos) noexcept {
        if (pos == 0) return true;
        char prev = url[pos - 1];
        return prev == '.' || prev == '/' || prev == ':' || prev == '@';
    }

    bool MatchABPPattern(std::string_view url, std::string_view pattern) {
        if (pattern.empty()) return true;
        if (url.empty()) return false;

        std::string_view effectivePattern = pattern;
        bool domainAnchor = false;
        bool leftAnchor = false;
        bool rightAnchor = false;

        if (StartsWith(effectivePattern, "||")) {
            domainAnchor = true;
            effectivePattern = effectivePattern.substr(2);
        } else if (StartsWith(effectivePattern, "|")) {
            leftAnchor = true;
            effectivePattern = effectivePattern.substr(1);
        }

        if (!effectivePattern.empty() && effectivePattern.back() == '|') {
            rightAnchor = true;
            effectivePattern = effectivePattern.substr(0, effectivePattern.size() - 1);
        }

        // Recursive pattern match with separator ^ and wildcard * support
        std::function<bool(size_t, size_t)> doMatch;
        doMatch = [&](size_t ui, size_t pi) -> bool {
            while (pi < effectivePattern.size() && ui <= url.size()) {
                char pc = effectivePattern[pi];

                if (pc == '*') {
                    ++pi;
                    if (pi >= effectivePattern.size()) return true;
                    for (size_t k = ui; k <= url.size(); ++k) {
                        if (doMatch(k, pi)) return true;
                    }
                    return false;
                }

                if (ui >= url.size()) return false;

                if (pc == '^') {
                    if (ui < url.size() && IsSeparator(url[ui])) {
                        ++ui; ++pi;
                        continue;
                    }
                    if (ui == url.size()) {
                        ++pi;
                        continue;
                    }
                    return false;
                }

                if (static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(pc))) !=
                    static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(url[ui])))) {
                    return false;
                }
                ++ui; ++pi;
            }

            while (pi < effectivePattern.size() && effectivePattern[pi] == '*') ++pi;
            if (pi < effectivePattern.size() && effectivePattern[pi] == '^' && ui == url.size()) ++pi;

            return pi >= effectivePattern.size() && (ui >= url.size() || !rightAnchor);
        };

        if (domainAnchor) {
            std::string urlDomain = GetDomainFromUrl(std::string(url));
            std::string schemeStripped(url);
            size_t schemeEnd = 0;
            if (StartsWith(url, "http://")) schemeEnd = 7;
            else if (StartsWith(url, "https://")) schemeEnd = 8;
            else if (StartsWith(url, "//")) schemeEnd = 2;

            for (size_t start = schemeEnd; start < url.size(); ++start) {
                if (IsDomainBoundary(url, start)) {
                    if (doMatch(start, 0)) {
                        if (!rightAnchor || start + effectivePattern.size() >= url.size()) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        if (leftAnchor) {
            return doMatch(0, 0);
        }

        // Substring search: try matching at every position
        for (size_t i = 0; i <= url.size(); ++i) {
            if (doMatch(i, 0)) {
                if (rightAnchor && i + effectivePattern.size() < url.size()) {
                    continue;
                }
                return true;
            }
        }
        return false;
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
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

    std::vector<std::string> SplitString(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        size_t start = 0;
        size_t end = str.find(delimiter);
        while (end != std::string::npos) {
            auto token = str.substr(start, end - start);
            if (!token.empty()) tokens.push_back(std::move(token));
            start = end + 1;
            end = str.find(delimiter, start);
        }
        auto last = str.substr(start);
        if (!last.empty()) tokens.push_back(std::move(last));
        return tokens;
    }

    std::string TrimWhitespace(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return {};
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    RequestType ParseRequestTypeOption(std::string_view opt) {
        if (opt == "script") return RequestType::Script;
        if (opt == "image") return RequestType::Image;
        if (opt == "stylesheet") return RequestType::Stylesheet;
        if (opt == "object") return RequestType::Object;
        if (opt == "xmlhttprequest") return RequestType::XMLHTTPRequest;
        if (opt == "subdocument" || opt == "sub_frame") return RequestType::SubDocument;
        if (opt == "document") return RequestType::Document;
        if (opt == "font") return RequestType::Font;
        if (opt == "media") return RequestType::Media;
        if (opt == "websocket") return RequestType::WebSocket;
        if (opt == "ping" || opt == "beacon") return RequestType::Ping;
        if (opt == "popup") return RequestType::Popup;
        if (opt == "webrtc") return RequestType::WebRTC;
        if (opt == "other") return RequestType::Other;
        return RequestType::None;
    }

    bool IsCrossOrigin(const std::string& requestUrl, const std::string& pageUrl) {
        std::string reqDomain = GetBaseDomain(GetDomainFromUrl(requestUrl));
        std::string pageDomain = GetBaseDomain(GetDomainFromUrl(pageUrl));
        return reqDomain != pageDomain;
    }

}  // anonymous namespace

// ============================================================================
// FORWARD DECLARATIONS (file-scope)
// ============================================================================

std::optional<NetworkFilterRule> ParseNetworkRule(const std::string& rule);
std::optional<CosmeticFilterRule> ParseCosmeticRule(const std::string& rule);

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

std::string NetworkFilterRule::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"ruleId\":" << ruleId << ","
        << "\"pattern\":\"" << EscapeJson(pattern) << "\","
        << "\"action\":" << static_cast<int>(action) << ","
        << "\"isException\":" << (isException ? "true" : "false") << ","
        << "\"thirdPartyOnly\":" << (thirdPartyOnly ? "true" : "false") << ","
        << "\"firstPartyOnly\":" << (firstPartyOnly ? "true" : "false") << ","
        << "\"isImportant\":" << (isImportant ? "true" : "false")
        << "}";
    return oss.str();
}

std::string CosmeticFilterRule::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"ruleId\":" << ruleId << ","
        << "\"selector\":\"" << EscapeJson(selector) << "\","
        << "\"action\":\"" << EscapeJson(action) << "\","
        << "\"isException\":" << (isException ? "true" : "false") << ","
        << "\"isProcedural\":" << (isProcedural ? "true" : "false")
        << "}";
    return oss.str();
}

std::string FilterListInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"listId\":\"" << EscapeJson(listId) << "\","
        << "\"name\":\"" << EscapeJson(name) << "\","
        << "\"url\":\"" << EscapeJson(url) << "\","
        << "\"status\":" << static_cast<int>(status) << ","
        << "\"ruleCount\":" << ruleCount << ","
        << "\"networkRules\":" << networkRules << ","
        << "\"cosmeticRules\":" << cosmeticRules << ","
        << "\"enabled\":" << (enabled ? "true" : "false") << ","
        << "\"isBuiltIn\":" << (isBuiltIn ? "true" : "false")
        << "}";
    return oss.str();
}

std::string FilterMatchResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"url\":\"" << EscapeJson(url) << "\","
        << "\"blocked\":" << (blocked ? "true" : "false") << ","
        << "\"action\":" << static_cast<int>(action) << ","
        << "\"matchTimeUs\":" << matchTime.count();
    if (matchedRule) {
        oss << ",\"matchedRule\":" << matchedRule->ToJson();
    }
    if (exceptionRule) {
        oss << ",\"exceptionRule\":" << exceptionRule->ToJson();
    }
    oss << "}";
    return oss.str();
}

void AdBlockerStatistics::Reset() noexcept {
    totalRequests = 0;
    blockedRequests = 0;
    allowedRequests = 0;
    hiddenElements = 0;
    redirectedRequests = 0;
    exceptionsApplied = 0;
    popupsBlocked = 0;
    cryptominersBlocked = 0;
    malvertisementBlocked = 0;
    cacheHits = 0;
    cacheMisses = 0;
    bytesBlocked = 0;
    for (auto& count : byRequestType) count = 0;
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string AdBlockerStatistics::ToJson() const {
    const auto statsStartTime = AtomicValueLoadRelaxed(startTime);
    std::ostringstream oss;
    oss << "{"
        << "\"totalRequests\":" << totalRequests.load() << ","
        << "\"blockedRequests\":" << blockedRequests.load() << ","
        << "\"allowedRequests\":" << allowedRequests.load() << ","
        << "\"hiddenElements\":" << hiddenElements.load() << ","
        << "\"redirectedRequests\":" << redirectedRequests.load() << ","
        << "\"exceptionsApplied\":" << exceptionsApplied.load() << ","
        << "\"popupsBlocked\":" << popupsBlocked.load() << ","
        << "\"cryptominersBlocked\":" << cryptominersBlocked.load() << ","
        << "\"malvertisementBlocked\":" << malvertisementBlocked.load() << ","
        << "\"cacheHits\":" << cacheHits.load() << ","
        << "\"cacheMisses\":" << cacheMisses.load() << ","
        << "\"bytesBlocked\":" << bytesBlocked.load() << ","
        << "\"uptimeSeconds\":" << std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - statsStartTime).count()
        << "}";
    return oss.str();
}

bool AdBlockerConfiguration::IsValid() const noexcept {
    if (updateIntervalHours == 0 || updateIntervalHours > 720) return false;
    if (filterListUrls.size() > 100) return false;
    if (customRules.size() > AdBlockerConstants::MAX_RULES) return false;
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class AdBlockerImpl {
public:
    AdBlockerImpl() = default;
    ~AdBlockerImpl() { Shutdown(); }

    bool Initialize(const AdBlockerConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
            return true;
        }

        m_status = ModuleStatus::Initializing;
        if (!config.IsValid()) {
            m_status = ModuleStatus::Error;
            return false;
        }
        m_config = config;

        m_networkRules.clear();
        m_cosmeticRules.clear();
        m_domainToNetworkRuleIndices.clear();
        m_globalNetworkRuleIndices.clear();
        m_customRuleTexts.clear();
        m_filterLists.clear();
        m_whitelist.clear();
        m_nextRuleId = 1;

        for (const auto& rule : m_config.customRules) {
            AddCustomRuleInternal(rule);
        }

        for (const auto& domain : m_config.whitelistedDomains) {
            m_whitelist.insert(ToLowerStr(domain));
        }

        // Register built-in filter list entries (actual download deferred)
        for (const char* builtInUrl : AdBlockerConstants::BUILTIN_FILTER_LISTS) {
            FilterListInfo info;
            info.listId = builtInUrl;
            info.name = builtInUrl;
            info.url = builtInUrl;
            info.isBuiltIn = true;
            info.status = FilterListStatus::NotLoaded;
            info.enabled = true;
            m_filterLists.push_back(std::move(info));
        }

        // Register configured filter list URLs
        for (const auto& listUrl : m_config.filterListUrls) {
            bool alreadyRegistered = false;
            for (const auto& existing : m_filterLists) {
                if (existing.url == listUrl) { alreadyRegistered = true; break; }
            }
            if (!alreadyRegistered) {
                FilterListInfo info;
                info.listId = listUrl;
                info.name = listUrl;
                info.url = listUrl;
                info.isBuiltIn = false;
                info.status = FilterListStatus::NotLoaded;
                info.enabled = true;
                m_filterLists.push_back(std::move(info));
            }
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"AdBlocker initialized with %zu network rules, %zu cosmetic rules",
                    m_networkRules.size(), m_cosmeticRules.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Stopped) return;

        m_status = ModuleStatus::Stopping;
        m_networkRules.clear();
        m_cosmeticRules.clear();
        m_domainToNetworkRuleIndices.clear();
        m_globalNetworkRuleIndices.clear();
        m_customRuleTexts.clear();
        m_whitelist.clear();
        m_filterLists.clear();

        m_blockCallback = nullptr;
        m_updateCallback = nullptr;
        m_errorCallback = nullptr;

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"AdBlocker shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load();
    }

    [[nodiscard]] bool UpdateConfiguration(const AdBlockerConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid configuration rejected");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] AdBlockerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // FILTERING LOGIC
    // ========================================================================

    [[nodiscard]] FilterMatchResult CheckURL(const std::string& url, const std::string& pageUrl, RequestType requestType) {
        FilterMatchResult result;
        result.url = url;
        auto start = Clock::now();

        if (!IsInitialized() || !m_config.enabled) {
            result.action = FilterAction::Allow;
            return result;
        }

        m_stats.totalRequests++;

        // Validate URL length to prevent abuse
        if (url.size() > 8192) {
            SS_LOG_WARN(LOG_CATEGORY, L"URL exceeds maximum length, blocking as precaution");
            result.blocked = true;
            result.action = FilterAction::Block;
            m_stats.blockedRequests++;
            return result;
        }

        std::string urlLower = ToLowerStr(url);
        std::string pageDomain = GetDomainFromUrl(pageUrl.empty() ? url : pageUrl);
        std::string urlDomain = GetDomainFromUrl(url);
        bool isThirdPartyReq = !pageUrl.empty() && IsCrossOrigin(url, pageUrl);

        // 1. Check whitelist (page domain)
        if (IsWhitelistedInternal(pageDomain)) {
            result.action = FilterAction::Allow;
            m_stats.allowedRequests++;
            result.matchTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            return result;
        }

        // 2. Check common ad domains for fast-path blocking
        for (const char* adDomain : AdBlockerConstants::COMMON_AD_DOMAINS) {
            if (urlDomain == adDomain || EndsWith(urlDomain, std::string(".") + adDomain)) {
                result.blocked = true;
                result.action = FilterAction::Block;
                m_stats.blockedRequests++;
                m_stats.malvertisementBlocked++;
                result.matchTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                if (m_blockCallback) m_blockCallback(url, result);
                return result;
            }
        }

        // 3. Check network rules using domain index + global rules
        if (m_config.enableNetworkFiltering) {
            std::shared_lock lock(m_mutex);
            bool blocked = false;
            std::optional<NetworkFilterRule> matchingRule;
            std::optional<NetworkFilterRule> matchingException;

            auto checkRuleSet = [&](const std::vector<size_t>& indices) {
                for (size_t idx : indices) {
                    if (idx >= m_networkRules.size()) continue;
                    const auto& rule = m_networkRules[idx];

                    // Check request type applicability
                    if (rule.requestTypes != RequestType::All) {
                        if ((static_cast<uint32_t>(rule.requestTypes) & static_cast<uint32_t>(requestType)) == 0) {
                            continue;
                        }
                    }

                    // Check third-party constraint
                    if (rule.thirdPartyOnly && !isThirdPartyReq) continue;
                    if (rule.firstPartyOnly && isThirdPartyReq) continue;

                    // Check domain constraints
                    if (!rule.domains.empty()) {
                        bool domainMatch = false;
                        for (const auto& d : rule.domains) {
                            if (d == pageDomain || EndsWith(pageDomain, std::string(".") + d)) {
                                domainMatch = true;
                                break;
                            }
                        }
                        if (!domainMatch) continue;
                    }

                    // Check exclude-domain constraints
                    if (!rule.excludeDomains.empty()) {
                        bool excluded = false;
                        for (const auto& d : rule.excludeDomains) {
                            if (d == pageDomain || EndsWith(pageDomain, std::string(".") + d)) {
                                excluded = true;
                                break;
                            }
                        }
                        if (excluded) continue;
                    }

                    // Check pattern match
                    bool patternMatches = false;
                    if (rule.compiledRegex) {
                        std::smatch m;
                        try {
                            patternMatches = std::regex_search(url, m, *rule.compiledRegex);
                        } catch (...) {
                            patternMatches = false;
                        }
                    } else {
                        patternMatches = MatchABPPattern(urlLower, rule.pattern);
                    }

                    if (!patternMatches) continue;

                    if (rule.isException) {
                        matchingException = rule;
                        m_stats.exceptionsApplied++;
                        break;
                    }

                    if (rule.isImportant) {
                        blocked = true;
                        matchingRule = rule;
                        break;
                    }

                    if (!blocked) {
                        blocked = true;
                        matchingRule = rule;
                    }
                }
            };

            // Check domain-specific rules
            auto it = m_domainToNetworkRuleIndices.find(urlDomain);
            if (it != m_domainToNetworkRuleIndices.end()) {
                checkRuleSet(it->second);
            }

            // Also check base domain
            std::string baseDomain = GetBaseDomain(urlDomain);
            if (baseDomain != urlDomain) {
                auto baseIt = m_domainToNetworkRuleIndices.find(baseDomain);
                if (baseIt != m_domainToNetworkRuleIndices.end()) {
                    checkRuleSet(baseIt->second);
                }
            }

            // Check global rules (domain-agnostic)
            if (!matchingException) {
                checkRuleSet(m_globalNetworkRuleIndices);
            }

            // Apply result: exception overrides block unless rule is important
            if (blocked && !matchingException) {
                result.blocked = true;
                result.action = FilterAction::Block;
                result.matchedRule = matchingRule;
                m_stats.blockedRequests++;

                if (m_blockCallback) {
                    m_blockCallback(url, result);
                }

                result.matchTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }

            if (matchingException) {
                result.exceptionRule = matchingException;
            }
        }

        result.matchTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
        m_stats.allowedRequests++;
        return result;
    }

    [[nodiscard]] bool ShouldBlock(const std::string& url) {
        return CheckURL(url, std::string{}, RequestType::Other).blocked;
    }

    [[nodiscard]] std::vector<CosmeticFilterRule> GetCosmeticFilters(const std::string& domain) {
        std::shared_lock lock(m_mutex);
        std::vector<CosmeticFilterRule> rules;
        if (!m_config.enableCosmeticFiltering) return rules;

        std::string domainLower = ToLowerStr(domain);

        for (const auto& rule : m_cosmeticRules) {
            if (rule.isException) continue;

            if (rule.domains.empty()) {
                // Global cosmetic rule applies to all domains
                rules.push_back(rule);
            } else {
                bool domainMatch = false;
                for (const auto& d : rule.domains) {
                    if (d == domainLower || EndsWith(domainLower, std::string(".") + d)) {
                        domainMatch = true;
                        break;
                    }
                }
                if (domainMatch) {
                    // Verify not excluded
                    bool excluded = false;
                    for (const auto& d : rule.excludeDomains) {
                        if (d == domainLower || EndsWith(domainLower, std::string(".") + d)) {
                            excluded = true;
                            break;
                        }
                    }
                    if (!excluded) {
                        rules.push_back(rule);
                    }
                }
            }
        }
        return rules;
    }

    [[nodiscard]] std::vector<std::string> GetScriptFilters(const std::string& domain) {
        std::shared_lock lock(m_mutex);
        std::vector<std::string> scripts;
        if (!m_config.enableCosmeticFiltering) return scripts;

        std::string domainLower = ToLowerStr(domain);

        for (const auto& rule : m_cosmeticRules) {
            if (!rule.isProcedural) continue;
            if (rule.isException) continue;

            bool applies = rule.domains.empty();
            if (!applies) {
                for (const auto& d : rule.domains) {
                    if (d == domainLower || EndsWith(domainLower, std::string(".") + d)) {
                        applies = true;
                        break;
                    }
                }
            }

            if (applies) {
                bool excluded = false;
                for (const auto& d : rule.excludeDomains) {
                    if (d == domainLower || EndsWith(domainLower, std::string(".") + d)) {
                        excluded = true;
                        break;
                    }
                }
                if (!excluded) {
                    scripts.push_back(rule.selector);
                }
            }
        }
        return scripts;
    }

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    bool AddCustomRuleInternal(const std::string& ruleText) {
        auto netRule = ParseNetworkRule(ruleText);
        if (netRule) {
            netRule->ruleId = m_nextRuleId++;
            size_t idx = m_networkRules.size();
            m_networkRules.push_back(*netRule);
            IndexNetworkRule(idx, *netRule);
            m_customRuleTexts.push_back(ruleText);
            return true;
        }

        auto cosmeticRule = ParseCosmeticRule(ruleText);
        if (cosmeticRule) {
            cosmeticRule->ruleId = m_nextRuleId++;
            m_cosmeticRules.push_back(*cosmeticRule);
            m_customRuleTexts.push_back(ruleText);
            return true;
        }

        SS_LOG_WARN(LOG_CATEGORY, L"Failed to parse rule: %hs", ruleText.c_str());
        return false;
    }

    bool RemoveCustomRuleInternal(const std::string& ruleText) {
        auto it = std::find(m_customRuleTexts.begin(), m_customRuleTexts.end(), ruleText);
        if (it == m_customRuleTexts.end()) return false;
        m_customRuleTexts.erase(it);

        // Remove matching network rule
        for (auto nit = m_networkRules.begin(); nit != m_networkRules.end(); ++nit) {
            if (nit->originalRule == ruleText) {
                m_networkRules.erase(nit);
                RebuildDomainIndex();
                return true;
            }
        }

        // Remove matching cosmetic rule
        for (auto cit = m_cosmeticRules.begin(); cit != m_cosmeticRules.end(); ++cit) {
            if (cit->originalRule == ruleText) {
                m_cosmeticRules.erase(cit);
                return true;
            }
        }

        return false;
    }

    std::vector<std::string> GetCustomRulesInternal() const {
        return m_customRuleTexts;
    }

    void ClearCustomRulesInternal() {
        // Remove all rules that originated from custom rule texts
        for (const auto& ruleText : m_customRuleTexts) {
            for (auto nit = m_networkRules.begin(); nit != m_networkRules.end();) {
                if (nit->originalRule == ruleText) {
                    nit = m_networkRules.erase(nit);
                } else {
                    ++nit;
                }
            }
            for (auto cit = m_cosmeticRules.begin(); cit != m_cosmeticRules.end();) {
                if (cit->originalRule == ruleText) {
                    cit = m_cosmeticRules.erase(cit);
                } else {
                    ++cit;
                }
            }
        }
        m_customRuleTexts.clear();
        RebuildDomainIndex();
    }

    bool IsWhitelistedInternal(const std::string& domain) const {
        std::string domLower = ToLowerStr(domain);
        if (m_whitelist.find(domLower) != m_whitelist.end()) return true;
        std::string baseDom = GetBaseDomain(domLower);
        if (baseDom != domLower && m_whitelist.find(baseDom) != m_whitelist.end()) return true;
        return false;
    }

    // ========================================================================
    // FILTER LIST MANAGEMENT
    // ========================================================================

    bool LoadFilterListFromUrl(const std::string& url) {
        std::unique_lock lock(m_mutex);
        // Find or create list entry
        FilterListInfo* listInfo = nullptr;
        for (auto& info : m_filterLists) {
            if (info.url == url) {
                listInfo = &info;
                break;
            }
        }
        if (!listInfo) {
            m_filterLists.emplace_back();
            listInfo = &m_filterLists.back();
            listInfo->listId = url;
            listInfo->name = url;
            listInfo->url = url;
            listInfo->isBuiltIn = false;
            listInfo->enabled = true;
        }

        listInfo->status = FilterListStatus::Loading;
        SS_LOG_INFO(LOG_CATEGORY, L"Filter list registered for URL: %hs", url.c_str());

        // Attempt to load from local cache path if available
        if (!listInfo->localPath.empty()) {
            lock.unlock();
            bool loaded = LoadFilterListFromFileInternal(listInfo->localPath, listInfo->listId);
            lock.lock();
            if (loaded) {
                listInfo->status = FilterListStatus::Loaded;
                listInfo->lastUpdate = std::chrono::system_clock::now();
                listInfo->nextUpdate = listInfo->lastUpdate +
                    std::chrono::hours(m_config.updateIntervalHours);
                return true;
            }
        }

        // Mark as not-loaded (external fetch would be handled by platform layer)
        listInfo->status = FilterListStatus::NotLoaded;
        SS_LOG_WARN(LOG_CATEGORY, L"Filter list URL registered but local file unavailable: %hs", url.c_str());
        return false;
    }

    bool LoadFilterListFromFileInternal(const std::string& filePath, const std::string& listId = {}) {
        std::error_code sizeError;
        const auto fileSize = fs::file_size(filePath, sizeError);
        if (!sizeError && fileSize > MAX_FILTER_LIST_FILE_SIZE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Filter list exceeds maximum size: %hs", filePath.c_str());
            return false;
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open filter list file: %hs", filePath.c_str());
            return false;
        }

        std::string effectiveListId = listId.empty() ? filePath : listId;
        size_t networkLoaded = 0;
        size_t cosmeticLoaded = 0;
        std::string line;

        std::unique_lock lock(m_mutex);

        // Find or create list entry
        FilterListInfo* listInfo = nullptr;
        for (auto& info : m_filterLists) {
            if (info.listId == effectiveListId || info.localPath == filePath) {
                listInfo = &info;
                break;
            }
        }
        if (!listInfo) {
            m_filterLists.emplace_back();
            listInfo = &m_filterLists.back();
            listInfo->listId = effectiveListId;
            listInfo->name = effectiveListId;
            listInfo->isBuiltIn = false;
            listInfo->enabled = true;
        }
        listInfo->localPath = filePath;
        listInfo->status = FilterListStatus::Loading;

        while (std::getline(file, line)) {
            if (line.size() > MAX_FILTER_RULE_LENGTH) {
                SS_LOG_WARN(LOG_CATEGORY, L"Skipping overlong filter rule in %hs", filePath.c_str());
                continue;
            }
            if (ContainsEmbeddedLineBreak(line) || !IsStrictUtf8(line)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Skipping invalid UTF-8 or smuggled filter rule in %hs", filePath.c_str());
                continue;
            }
            line = TrimWhitespace(line);
            if (line.empty() || line[0] == '!' || line[0] == '[') continue;

            // Enforce maximum rule count
            if (m_networkRules.size() + m_cosmeticRules.size() >= AdBlockerConstants::MAX_RULES) {
                SS_LOG_WARN(LOG_CATEGORY, L"Maximum rule count (%zu) reached, stopping load",
                            AdBlockerConstants::MAX_RULES);
                break;
            }

            if (line.find("##") != std::string::npos || line.find("#@#") != std::string::npos ||
                line.find("#?#") != std::string::npos) {
                auto rule = ParseCosmeticRule(line);
                if (rule) {
                    rule->ruleId = m_nextRuleId++;
                    m_cosmeticRules.push_back(*rule);
                    cosmeticLoaded++;
                }
            } else {
                auto rule = ParseNetworkRule(line);
                if (rule) {
                    rule->ruleId = m_nextRuleId++;
                    size_t idx = m_networkRules.size();
                    m_networkRules.push_back(*rule);
                    IndexNetworkRule(idx, *rule);
                    networkLoaded++;
                }
            }
        }

        listInfo->status = FilterListStatus::Loaded;
        listInfo->networkRules = networkLoaded;
        listInfo->cosmeticRules = cosmeticLoaded;
        listInfo->ruleCount = networkLoaded + cosmeticLoaded;
        listInfo->lastUpdate = std::chrono::system_clock::now();
        listInfo->nextUpdate = listInfo->lastUpdate +
            std::chrono::hours(m_config.updateIntervalHours);

        SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu network + %zu cosmetic rules from %hs",
                    networkLoaded, cosmeticLoaded, filePath.c_str());
        return true;
    }

    bool UnloadFilterListInternal(const std::string& listId) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_filterLists.begin(), m_filterLists.end(),
                               [&](const FilterListInfo& info) { return info.listId == listId; });
        if (it == m_filterLists.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Filter list not found for unload: %hs", listId.c_str());
            return false;
        }

        it->status = FilterListStatus::NotLoaded;
        it->ruleCount = 0;
        it->networkRules = 0;
        it->cosmeticRules = 0;
        SS_LOG_INFO(LOG_CATEGORY, L"Filter list unloaded: %hs", listId.c_str());
        return true;
    }

    bool UpdateFilterListInternal(const std::string& listId) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_filterLists.begin(), m_filterLists.end(),
                               [&](const FilterListInfo& info) { return info.listId == listId; });
        if (it == m_filterLists.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Filter list not found for update: %hs", listId.c_str());
            return false;
        }
        if (!it->enabled) return false;

        it->status = FilterListStatus::Updating;
        // Reload from local path if available
        if (!it->localPath.empty()) {
            lock.unlock();
            bool reloaded = LoadFilterListFromFileInternal(it->localPath, it->listId);
            return reloaded;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Filter list update requested: %hs", listId.c_str());
        return true;
    }

    bool UpdateAllFilterListsInternal() {
        std::vector<std::string> listIds;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& info : m_filterLists) {
                if (info.enabled) {
                    listIds.push_back(info.listId);
                }
            }
        }

        bool allOk = true;
        for (const auto& id : listIds) {
            if (!UpdateFilterListInternal(id)) {
                allOk = false;
            }
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Updated %zu filter lists", listIds.size());
        return allOk;
    }

    std::vector<FilterListInfo> GetFilterListsInternal() const {
        std::shared_lock lock(m_mutex);
        return m_filterLists;
    }

    bool SetFilterListEnabledInternal(const std::string& listId, bool enabled) {
        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_filterLists.begin(), m_filterLists.end(),
                               [&](const FilterListInfo& info) { return info.listId == listId; });
        if (it == m_filterLists.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Filter list not found: %hs", listId.c_str());
            return false;
        }
        it->enabled = enabled;
        if (!enabled) {
            it->status = FilterListStatus::Disabled;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Filter list '%hs' %ls",
                    listId.c_str(), enabled ? L"enabled" : L"disabled");
        return true;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterBlockCallback(AdBlockCallback callback) {
        std::unique_lock lock(m_mutex);
        m_blockCallback = std::move(callback);
    }

    void RegisterUpdateCallback(UpdateCallback callback) {
        std::unique_lock lock(m_mutex);
        m_updateCallback = std::move(callback);
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallback = std::move(callback);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_blockCallback = nullptr;
        m_updateCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // DATA ACCESS
    // ========================================================================

    AdBlockerStatistics GetStatistics() const {
        AdBlockerStatistics stats;
        stats.totalRequests = m_stats.totalRequests.load();
        stats.blockedRequests = m_stats.blockedRequests.load();
        stats.allowedRequests = m_stats.allowedRequests.load();
        stats.hiddenElements = m_stats.hiddenElements.load();
        stats.redirectedRequests = m_stats.redirectedRequests.load();
        stats.exceptionsApplied = m_stats.exceptionsApplied.load();
        stats.popupsBlocked = m_stats.popupsBlocked.load();
        stats.cryptominersBlocked = m_stats.cryptominersBlocked.load();
        stats.malvertisementBlocked = m_stats.malvertisementBlocked.load();
        stats.cacheHits = m_stats.cacheHits.load();
        stats.cacheMisses = m_stats.cacheMisses.load();
        stats.bytesBlocked = m_stats.bytesBlocked.load();
        AtomicValueStoreRelaxed(stats.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    size_t GetTotalRuleCount() const {
        std::shared_lock lock(m_mutex);
        return m_networkRules.size() + m_cosmeticRules.size();
    }

    std::vector<std::string> GetWhitelistedDomains() const {
        std::shared_lock lock(m_mutex);
        return std::vector<std::string>(m_whitelist.begin(), m_whitelist.end());
    }

    bool AddToWhitelist(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        m_whitelist.insert(ToLowerStr(domain));
        return true;
    }

    bool RemoveFromWhitelist(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        return m_whitelist.erase(ToLowerStr(domain)) > 0;
    }

    // ========================================================================
    // LOCKED PUBLIC WRAPPERS (for AdBlocker facade to call safely)
    // ========================================================================

    bool AddCustomRuleLocked(const std::string& rule) {
        std::unique_lock lock(m_mutex);
        return AddCustomRuleInternal(rule);
    }

    bool RemoveCustomRuleLocked(const std::string& rule) {
        std::unique_lock lock(m_mutex);
        return RemoveCustomRuleInternal(rule);
    }

    std::vector<std::string> GetCustomRulesLocked() const {
        std::shared_lock lock(m_mutex);
        return GetCustomRulesInternal();
    }

    void ClearCustomRulesLocked() {
        std::unique_lock lock(m_mutex);
        ClearCustomRulesInternal();
    }

    bool IsWhitelistedLocked(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        return IsWhitelistedInternal(domain);
    }

private:
    void IndexNetworkRule(size_t index, const NetworkFilterRule& rule) {
        // Extract domain hint from pattern for indexing
        std::string_view pattern = rule.pattern;
        if (StartsWith(pattern, "||")) {
            pattern = pattern.substr(2);
            // Extract domain portion (up to first ^ / * or end)
            size_t endPos = 0;
            while (endPos < pattern.size() && pattern[endPos] != '^' &&
                   pattern[endPos] != '/' && pattern[endPos] != '*') {
                ++endPos;
            }
            std::string domainHint = ToLowerStr(pattern.substr(0, endPos));
            if (!domainHint.empty()) {
                m_domainToNetworkRuleIndices[domainHint].push_back(index);
                return;
            }
        }
        // If no domain can be extracted, add to global rules
        m_globalNetworkRuleIndices.push_back(index);
    }

    void RebuildDomainIndex() {
        m_domainToNetworkRuleIndices.clear();
        m_globalNetworkRuleIndices.clear();
        for (size_t i = 0; i < m_networkRules.size(); ++i) {
            IndexNetworkRule(i, m_networkRules[i]);
        }
    }

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    AdBlockerConfiguration m_config;
    AdBlockerStatistics m_stats;

    std::vector<NetworkFilterRule> m_networkRules;
    std::vector<CosmeticFilterRule> m_cosmeticRules;
    std::unordered_set<std::string> m_whitelist;
    std::vector<FilterListInfo> m_filterLists;

    // Domain-indexed lookup for O(1) domain check + scan of per-domain rules
    std::unordered_map<std::string, std::vector<size_t>> m_domainToNetworkRuleIndices;
    std::vector<size_t> m_globalNetworkRuleIndices;

    // Custom rule tracking
    std::vector<std::string> m_customRuleTexts;
    uint32_t m_nextRuleId = 1;

    // Callbacks
    AdBlockCallback m_blockCallback;
    UpdateCallback m_updateCallback;
    ErrorCallback m_errorCallback;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

AdBlocker& AdBlocker::Instance() noexcept {
    static AdBlocker instance;
    return instance;
}

bool AdBlocker::HasInstance() noexcept {
    return s_instanceCreated.load();
}

AdBlocker::AdBlocker() : m_impl(std::make_unique<AdBlockerImpl>()) {
    s_instanceCreated.store(true);
}

AdBlocker::~AdBlocker() {
    s_instanceCreated.store(false);
}

bool AdBlocker::Initialize(const AdBlockerConfiguration& config) {
    return m_impl->Initialize(config);
}

void AdBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool AdBlocker::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus AdBlocker::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool AdBlocker::UpdateConfiguration(const AdBlockerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

AdBlockerConfiguration AdBlocker::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

bool AdBlocker::ShouldBlock(const std::string& url) {
    return m_impl->ShouldBlock(url);
}

FilterMatchResult AdBlocker::CheckURL(const std::string& url, const std::string& pageUrl, RequestType requestType) {
    return m_impl->CheckURL(url, pageUrl, requestType);
}

std::vector<CosmeticFilterRule> AdBlocker::GetCosmeticFilters(const std::string& domain) {
    return m_impl->GetCosmeticFilters(domain);
}

std::vector<std::string> AdBlocker::GetScriptFilters(const std::string& domain) {
    return m_impl->GetScriptFilters(domain);
}

bool AdBlocker::LoadFilterList(const std::string& url) {
    return m_impl->LoadFilterListFromUrl(url);
}

bool AdBlocker::LoadFilterListFromFile(const std::string& filePath) {
    return m_impl->LoadFilterListFromFileInternal(filePath);
}

bool AdBlocker::UnloadFilterList(const std::string& listId) {
    return m_impl->UnloadFilterListInternal(listId);
}

bool AdBlocker::UpdateAllFilterLists() {
    return m_impl->UpdateAllFilterListsInternal();
}

bool AdBlocker::UpdateFilterList(const std::string& listId) {
    return m_impl->UpdateFilterListInternal(listId);
}

std::vector<FilterListInfo> AdBlocker::GetFilterLists() const {
    return m_impl->GetFilterListsInternal();
}

bool AdBlocker::SetFilterListEnabled(const std::string& listId, bool enabled) {
    return m_impl->SetFilterListEnabledInternal(listId, enabled);
}

bool AdBlocker::AddCustomRule(const std::string& rule) {
    return m_impl->AddCustomRuleLocked(rule);
}

bool AdBlocker::RemoveCustomRule(const std::string& rule) {
    return m_impl->RemoveCustomRuleLocked(rule);
}

std::vector<std::string> AdBlocker::GetCustomRules() const {
    return m_impl->GetCustomRulesLocked();
}

void AdBlocker::ClearCustomRules() {
    m_impl->ClearCustomRulesLocked();
}

bool AdBlocker::AddToWhitelist(const std::string& domain) {
    return m_impl->AddToWhitelist(domain);
}

bool AdBlocker::RemoveFromWhitelist(const std::string& domain) {
    return m_impl->RemoveFromWhitelist(domain);
}

bool AdBlocker::IsWhitelisted(const std::string& domain) const {
    return m_impl->IsWhitelistedLocked(domain);
}

std::vector<std::string> AdBlocker::GetWhitelistedDomains() const {
    return m_impl->GetWhitelistedDomains();
}

void AdBlocker::RegisterBlockCallback(AdBlockCallback callback) {
    m_impl->RegisterBlockCallback(std::move(callback));
}

void AdBlocker::RegisterUpdateCallback(UpdateCallback callback) {
    m_impl->RegisterUpdateCallback(std::move(callback));
}

void AdBlocker::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void AdBlocker::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

AdBlockerStatistics AdBlocker::GetStatistics() const {
    return m_impl->GetStatistics();
}

void AdBlocker::ResetStatistics() {
    m_impl->ResetStatistics();
}

size_t AdBlocker::GetTotalRuleCount() const {
    return m_impl->GetTotalRuleCount();
}

bool AdBlocker::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"SelfTest: beginning ad blocker verification");

    // Create a temporary configuration and test rule parsing + matching
    AdBlockerConfiguration testConfig;
    testConfig.enabled = true;
    testConfig.enableNetworkFiltering = true;
    testConfig.enableCosmeticFiltering = true;

    // Test 1: Parse a basic ABP network rule
    auto netRule = ParseNetworkRule("||doubleclick.net^");
    if (!netRule) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not parse basic network rule '||doubleclick.net^'");
        return false;
    }
    if (netRule->pattern != "||doubleclick.net^") {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: parsed pattern mismatch");
        return false;
    }

    // Test 2: Parse an exception rule
    auto exRule = ParseNetworkRule("@@||example.com^$document");
    if (!exRule || !exRule->isException) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not parse exception rule");
        return false;
    }

    // Test 3: Parse a cosmetic rule
    auto cosRule = ParseCosmeticRule("example.com##.ad-banner");
    if (!cosRule || cosRule->selector != ".ad-banner") {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not parse cosmetic rule");
        return false;
    }

    // Test 4: ABP pattern matching
    bool matchResult = MatchABPPattern("https://ad.doubleclick.net/tracking/pixel", "||doubleclick.net^");
    if (!matchResult) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: ABP pattern did not match known ad URL");
        return false;
    }

    // Test 5: Non-matching URL
    bool noMatch = MatchABPPattern("https://example.com/page", "||doubleclick.net^");
    if (noMatch) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: ABP pattern incorrectly matched non-ad URL");
        return false;
    }

    // Test 6: Parse rule with $options
    auto optRule = ParseNetworkRule("||tracker.com^$third-party,script,domain=example.com|test.org");
    if (!optRule || !optRule->thirdPartyOnly) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: could not parse rule with $options");
        return false;
    }
    if (optRule->domains.size() != 2) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: domain= parsing produced %zu domains, expected 2",
                     optRule->domains.size());
        return false;
    }

    SS_LOG_INFO(LOG_CATEGORY, L"SelfTest: all 6 verification checks passed");
    return true;
}

std::string AdBlocker::GetVersionString() noexcept {
    return std::to_string(AdBlockerConstants::VERSION_MAJOR) + "." +
           std::to_string(AdBlockerConstants::VERSION_MINOR) + "." +
           std::to_string(AdBlockerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetFilterActionName(FilterAction action) noexcept {
    switch (action) {
        case FilterAction::Allow:    return "Allow";
        case FilterAction::Block:    return "Block";
        case FilterAction::Hide:     return "Hide";
        case FilterAction::Redirect: return "Redirect";
        case FilterAction::Modify:   return "Modify";
    }
    return "Block";
}

std::string_view GetFilterTypeName(FilterType type) noexcept {
    switch (type) {
        case FilterType::Network:    return "Network";
        case FilterType::Cosmetic:   return "Cosmetic";
        case FilterType::Script:     return "Script";
        case FilterType::CSP:        return "CSP";
        case FilterType::Redirect:   return "Redirect";
        case FilterType::Exception:  return "Exception";
    }
    return "Network";
}

std::string_view GetRequestTypeName(RequestType type) noexcept {
    switch (type) {
        case RequestType::Document:       return "Document";
        case RequestType::SubDocument:    return "SubDocument";
        case RequestType::Stylesheet:     return "Stylesheet";
        case RequestType::Script:         return "Script";
        case RequestType::Image:          return "Image";
        case RequestType::Font:           return "Font";
        case RequestType::Object:         return "Object";
        case RequestType::XMLHTTPRequest: return "XMLHTTPRequest";
        case RequestType::Ping:           return "Ping";
        case RequestType::Media:          return "Media";
        case RequestType::WebSocket:      return "WebSocket";
        case RequestType::Popup:          return "Popup";
        case RequestType::WebRTC:         return "WebRTC";
        case RequestType::Other:          return "Other";
        case RequestType::All:            return "All";
        case RequestType::None:           return "None";
    }
    return "Other";
}

std::string_view GetFilterListStatusName(FilterListStatus status) noexcept {
    switch (status) {
        case FilterListStatus::NotLoaded: return "NotLoaded";
        case FilterListStatus::Loading:   return "Loading";
        case FilterListStatus::Loaded:    return "Loaded";
        case FilterListStatus::Updating:  return "Updating";
        case FilterListStatus::Error:     return "Error";
        case FilterListStatus::Disabled:  return "Disabled";
    }
    return "NotLoaded";
}

// ============================================================================
// RULE PARSING
// ============================================================================

std::optional<NetworkFilterRule> ParseNetworkRule(const std::string& rule) {
    if (rule.empty() || rule[0] == '!' || rule[0] == '[') return std::nullopt;
    if (rule.find("##") != std::string::npos || rule.find("#@#") != std::string::npos ||
        rule.find("#?#") != std::string::npos) {
        return std::nullopt;
    }

    NetworkFilterRule r;
    r.originalRule = rule;
    r.action = FilterAction::Block;

    std::string_view p = rule;

    // Handle exception prefix @@
    if (StartsWith(p, "@@")) {
        r.isException = true;
        r.action = FilterAction::Allow;
        p = p.substr(2);
    }

    // Split on $ for options
    size_t optPos = std::string::npos;
    {
        // Find the last $ that is not inside a regex
        bool inRegex = (p.size() >= 2 && p.front() == '/' && p.back() == '/');
        if (!inRegex) {
            optPos = p.rfind('$');
        }
    }

    std::string patternStr;
    std::string optionsStr;

    if (optPos != std::string::npos && optPos > 0) {
        patternStr = std::string(p.substr(0, optPos));
        optionsStr = std::string(p.substr(optPos + 1));
    } else {
        patternStr = std::string(p);
    }

    // Parse options
    if (!optionsStr.empty()) {
        auto options = SplitString(optionsStr, ',');
        bool hasTypeFilter = false;
        uint32_t typeMask = 0;

        for (const auto& opt : options) {
            std::string optLower = ToLowerStr(opt);

            if (optLower == "third-party" || optLower == "3p") {
                r.thirdPartyOnly = true;
            } else if (optLower == "~third-party" || optLower == "1p" || optLower == "first-party") {
                r.firstPartyOnly = true;
            } else if (optLower == "important") {
                r.isImportant = true;
            } else if (StartsWith(optLower, "domain=")) {
                std::string domainList = opt.substr(7);
                auto domains = SplitString(domainList, '|');
                for (const auto& d : domains) {
                    if (!d.empty() && d[0] == '~') {
                        r.excludeDomains.push_back(ToLowerStr(d.substr(1)));
                    } else {
                        r.domains.push_back(ToLowerStr(d));
                    }
                }
            } else if (StartsWith(optLower, "redirect=")) {
                r.action = FilterAction::Redirect;
                r.redirectTarget = opt.substr(9);
            } else if (StartsWith(optLower, "csp=")) {
                // CSP injection rule - store the directive in redirectTarget field
                r.redirectTarget = opt.substr(4);
            } else {
                // Check if it's a negated type option
                bool negated = false;
                std::string typeOpt = optLower;
                if (!typeOpt.empty() && typeOpt[0] == '~') {
                    negated = true;
                    typeOpt = typeOpt.substr(1);
                }

                RequestType parsed = ParseRequestTypeOption(typeOpt);
                if (parsed != RequestType::None) {
                    hasTypeFilter = true;
                    if (!negated) {
                        typeMask |= static_cast<uint32_t>(parsed);
                    }
                }
            }
        }

        if (hasTypeFilter && typeMask != 0) {
            r.requestTypes = static_cast<RequestType>(typeMask);
        }
    }

    // Handle regex pattern (enclosed in /.../)
    if (patternStr.size() >= 2 && patternStr.front() == '/' && patternStr.back() == '/') {
        std::string regexStr = patternStr.substr(1, patternStr.size() - 2);
        if (regexStr.size() > MAX_REGEX_RULE_LENGTH) {
            SS_LOG_WARN(LOG_CATEGORY, L"Rejecting oversized regex rule");
            return std::nullopt;
        }
        try {
            r.compiledRegex = std::regex(regexStr, std::regex_constants::ECMAScript |
                                                    std::regex_constants::icase |
                                                    std::regex_constants::optimize);
        } catch (const std::regex_error& e) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid regex in rule '%hs': %hs", rule.c_str(), e.what());
            return std::nullopt;
        }
    }

    r.pattern = std::move(patternStr);
    return r;
}

std::optional<CosmeticFilterRule> ParseCosmeticRule(const std::string& rule) {
    // Detect separator: ## (inject), #@# (exception), #?# (procedural)
    bool isException = false;
    bool isProcedural = false;
    size_t sepPos = std::string::npos;
    size_t sepLen = 2;

    size_t exPos = rule.find("#@#");
    size_t procPos = rule.find("#?#");
    size_t stdPos = rule.find("##");

    if (exPos != std::string::npos) {
        sepPos = exPos;
        sepLen = 3;
        isException = true;
    } else if (procPos != std::string::npos) {
        sepPos = procPos;
        sepLen = 3;
        isProcedural = true;
    } else if (stdPos != std::string::npos) {
        sepPos = stdPos;
        sepLen = 2;
    }

    if (sepPos == std::string::npos) return std::nullopt;

    CosmeticFilterRule r;
    r.originalRule = rule;
    r.isException = isException;
    r.isProcedural = isProcedural;
    r.selector = rule.substr(sepPos + sepLen);
    r.action = "hide";

    if (r.selector.empty()) return std::nullopt;

    // Parse domain list (comma-separated, before the ## separator)
    std::string domainPart = rule.substr(0, sepPos);
    if (!domainPart.empty()) {
        auto domainTokens = SplitString(domainPart, ',');
        for (const auto& d : domainTokens) {
            std::string trimmed = TrimWhitespace(d);
            if (trimmed.empty()) continue;
            if (trimmed[0] == '~') {
                r.excludeDomains.push_back(ToLowerStr(trimmed.substr(1)));
            } else {
                r.domains.push_back(ToLowerStr(trimmed));
            }
        }
    }

    // Parse procedural operators (e.g., :has(), :has-text(), :matches-css())
    if (isProcedural) {
        size_t pos = 0;
        while (pos < r.selector.size()) {
            size_t colonPos = r.selector.find(':', pos);
            if (colonPos == std::string::npos) break;
            size_t parenOpen = r.selector.find('(', colonPos);
            if (parenOpen != std::string::npos) {
                r.proceduralOps.push_back(r.selector.substr(colonPos, parenOpen - colonPos));
            }
            pos = colonPos + 1;
        }
    }

    return r;
}

}  // namespace WebBrowser
}  // namespace ShadowStrike
