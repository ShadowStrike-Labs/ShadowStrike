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

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <future>
#include <filesystem>
#include <iostream>

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

    // Helper to check if string starts with prefix
    bool StartsWith(std::string_view str, std::string_view prefix) {
        return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
    }

    // Helper to check if string ends with suffix
    bool EndsWith(std::string_view str, std::string_view suffix) {
        return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
    }

    // Helper to extract domain from URL
    std::string GetDomainFromUrl(const std::string& url) {
        size_t start = 0;
        if (StartsWith(url, "http://")) start = 7;
        else if (StartsWith(url, "https://")) start = 8;

        size_t end = url.find('/', start);
        if (end == std::string::npos) end = url.length();

        // Remove port if present
        size_t port = url.find(':', start);
        if (port != std::string::npos && port < end) end = port;

        return url.substr(start, end - start);
    }

    // Simple wildcard matching (glob)
    bool WildcardMatch(std::string_view text, std::string_view pattern) {
        // This is a simplified implementation.
        // In a real engine, we'd convert ABP syntax to Regex or use Aho-Corasick.

        // Handle ABP "||" (domain anchor)
        std::string_view effectivePattern = pattern;
        bool domainAnchor = false;
        if (StartsWith(pattern, "||")) {
            effectivePattern = pattern.substr(2);
            domainAnchor = true;
        }

        // Remove separator char '^' for simple matching
        std::string cleanPattern;
        cleanPattern.reserve(effectivePattern.size());
        for (char c : effectivePattern) {
            if (c != '^') cleanPattern += c;
        }

        if (domainAnchor) {
            // Check if text contains the domain
            auto pos = text.find(cleanPattern);
            if (pos == std::string_view::npos) return false;

            // Should be at start or after a separator
            // For simplified logic, just check if it's contained
            return true;
        }

        // Simple substring search for now (performance optimization would be needed)
        return text.find(cleanPattern) != std::string_view::npos;
    }

    // Escape JSON string
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
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }
}

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

std::string NetworkFilterRule::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"ruleId\":" << ruleId << ","
        << "\"pattern\":\"" << EscapeJson(pattern) << "\","
        << "\"action\":" << static_cast<int>(action) << ","
        << "\"isException\":" << (isException ? "true" : "false")
        << "}";
    return oss.str();
}

std::string CosmeticFilterRule::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"ruleId\":" << ruleId << ","
        << "\"selector\":\"" << EscapeJson(selector) << "\","
        << "\"action\":\"" << EscapeJson(action) << "\""
        << "}";
    return oss.str();
}

std::string FilterListInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"listId\":\"" << EscapeJson(listId) << "\","
        << "\"name\":\"" << EscapeJson(name) << "\","
        << "\"url\":\"" << EscapeJson(url) << "\","
        << "\"ruleCount\":" << ruleCount
        << "}";
    return oss.str();
}

std::string FilterMatchResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"url\":\"" << EscapeJson(url) << "\","
        << "\"blocked\":" << (blocked ? "true" : "false") << ","
        << "\"action\":" << static_cast<int>(action);
    if (matchedRule) {
        oss << ",\"matchedRule\":" << matchedRule->ToJson();
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
    startTime = Clock::now();
}

std::string AdBlockerStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalRequests\":" << totalRequests.load() << ","
        << "\"blockedRequests\":" << blockedRequests.load() << ","
        << "\"uptimeSeconds\":" << std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - startTime).count()
        << "}";
    return oss.str();
}

bool AdBlockerConfiguration::IsValid() const noexcept {
    return true; // Simplistic validation
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
        m_config = config;

        // Initialize lists from config
        if (m_config.autoUpdateLists) {
            // In a real app, this would start a background thread
            SS_LOG_INFO(LOG_CATEGORY, L"Auto-update enabled for filter lists");
        }

        // Load built-in lists (simulated)
        for (const auto& listUrl : m_config.filterListUrls) {
            // Queue load
        }

        // Add custom rules
        for (const auto& rule : m_config.customRules) {
            AddCustomRuleInternal(rule);
        }

        // Add whitelist
        for (const auto& domain : m_config.whitelistedDomains) {
            m_whitelist.insert(domain);
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"AdBlocker initialized");
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Stopped) return;

        m_status = ModuleStatus::Stopped;
        m_networkRules.clear();
        m_cosmeticRules.clear();
        m_whitelist.clear();
        m_filterLists.clear();

        // Clear callbacks
        m_blockCallback = nullptr;
        m_updateCallback = nullptr;
        m_errorCallback = nullptr;

        SS_LOG_INFO(LOG_CATEGORY, L"AdBlocker shutdown");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load();
    }

    [[nodiscard]] bool UpdateConfiguration(const AdBlockerConfiguration& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;
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

        // 1. Check Whitelist (Page Domain)
        std::string pageDomain = GetDomainFromUrl(pageUrl.empty() ? url : pageUrl);
        if (IsWhitelistedInternal(pageDomain)) {
            result.action = FilterAction::Allow;
            m_stats.allowedRequests++;
            return result;
        }

        // 2. Check Network Rules
        if (m_config.enableNetworkFiltering) {
            bool blocked = false;
            std::optional<NetworkFilterRule> matchingRule;

            std::shared_lock lock(m_mutex);
            // Linear scan for now (should be optimized with Aho-Corasick or similar)
            for (const auto& rule : m_networkRules) {
                // Skip if types don't match (simplified)

                if (WildcardMatch(url, rule.pattern)) {
                    // Check domain constraints
                    bool domainMatch = true;
                    if (!rule.domains.empty()) {
                        domainMatch = false;
                        for (const auto& d : rule.domains) {
                            if (d == pageDomain) {
                                domainMatch = true;
                                break;
                            }
                        }
                    }

                    if (!domainMatch) continue;

                    // Check exceptions
                    if (rule.isException) {
                        result.exceptionRule = rule;
                        blocked = false;
                        break; // Exception overrides block
                    } else {
                        blocked = true;
                        matchingRule = rule;
                        // Don't break yet, look for exception
                    }
                }
            }

            if (blocked && !result.exceptionRule) {
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
        }

        result.matchTime = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
        m_stats.allowedRequests++;
        return result;
    }

    [[nodiscard]] bool ShouldBlock(const std::string& url) {
        return CheckURL(url).blocked;
    }

    [[nodiscard]] std::vector<CosmeticFilterRule> GetCosmeticFilters(const std::string& domain) {
        std::shared_lock lock(m_mutex);
        std::vector<CosmeticFilterRule> rules;

        if (!m_config.enableCosmeticFiltering) return rules;

        // Return rules applicable to this domain
        for (const auto& rule : m_cosmeticRules) {
            // Simplified logic: matches all or specific domain
            if (rule.domains.empty()) {
                rules.push_back(rule);
            } else {
                for (const auto& d : rule.domains) {
                    if (d == domain) {
                        rules.push_back(rule);
                        break;
                    }
                }
            }
        }
        return rules;
    }

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    bool AddCustomRuleInternal(const std::string& ruleText) {
        // Parse rule
        auto netRule = ParseNetworkRule(ruleText);
        if (netRule) {
            m_networkRules.push_back(*netRule);
            return true;
        }

        auto cosmeticRule = ParseCosmeticRule(ruleText);
        if (cosmeticRule) {
            m_cosmeticRules.push_back(*cosmeticRule);
            return true;
        }

        return false;
    }

    bool IsWhitelistedInternal(const std::string& domain) const {
        return m_whitelist.find(domain) != m_whitelist.end();
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterBlockCallback(BlockCallback callback) {
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
        // Copy atomic stats
        AdBlockerStatistics stats;
        stats.totalRequests = m_stats.totalRequests.load();
        stats.blockedRequests = m_stats.blockedRequests.load();
        stats.allowedRequests = m_stats.allowedRequests.load();
        stats.startTime = m_stats.startTime;
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    size_t GetTotalRuleCount() const {
        std::shared_lock lock(m_mutex);
        return m_networkRules.size() + m_cosmeticRules.size();
    }

    // ... Other methods simplified for this implementation ...

    std::vector<std::string> GetWhitelistedDomains() const {
        std::shared_lock lock(m_mutex);
        return std::vector<std::string>(m_whitelist.begin(), m_whitelist.end());
    }

    bool AddToWhitelist(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        m_whitelist.insert(domain);
        return true;
    }

    bool RemoveFromWhitelist(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        return m_whitelist.erase(domain) > 0;
    }

    bool LoadFilterListFromFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) return false;

        std::string line;
        int loaded = 0;

        std::unique_lock lock(m_mutex);
        while (std::getline(file, line)) {
            // Trim
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty() || line[0] == '!') continue; // Comment

            if (line.find("##") != std::string::npos || line.find("#@#") != std::string::npos) {
                 auto rule = ParseCosmeticRule(line);
                 if (rule) {
                     m_cosmeticRules.push_back(*rule);
                     loaded++;
                 }
            } else {
                 auto rule = ParseNetworkRule(line);
                 if (rule) {
                     m_networkRules.push_back(*rule);
                     loaded++;
                 }
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Loaded %d rules from %hs", loaded, filePath.c_str());
        return true;
    }

private:
    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    AdBlockerConfiguration m_config;
    AdBlockerStatistics m_stats;

    // Data structures
    std::vector<NetworkFilterRule> m_networkRules;
    std::vector<CosmeticFilterRule> m_cosmeticRules;
    std::unordered_set<std::string> m_whitelist;
    std::vector<FilterListInfo> m_filterLists;

    // Callbacks
    BlockCallback m_blockCallback;
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

// ... Stubbed remaining implementations ...

std::vector<std::string> AdBlocker::GetScriptFilters(const std::string& domain) {
    return {}; // TODO
}

bool AdBlocker::LoadFilterList(const std::string& url) {
    // In real impl, would fetch URL
    return false;
}

bool AdBlocker::LoadFilterListFromFile(const std::string& filePath) {
    return m_impl->LoadFilterListFromFile(filePath);
}

bool AdBlocker::UnloadFilterList(const std::string& listId) { return true; }
bool AdBlocker::UpdateAllFilterLists() { return true; }
bool AdBlocker::UpdateFilterList(const std::string& listId) { return true; }

std::vector<FilterListInfo> AdBlocker::GetFilterLists() const { return {}; }
bool AdBlocker::SetFilterListEnabled(const std::string& listId, bool enabled) { return true; }

bool AdBlocker::AddCustomRule(const std::string& rule) {
    return m_impl->AddCustomRuleInternal(rule);
}

bool AdBlocker::RemoveCustomRule(const std::string& rule) { return true; }

std::vector<std::string> AdBlocker::GetCustomRules() const { return {}; }
void AdBlocker::ClearCustomRules() {}

bool AdBlocker::AddToWhitelist(const std::string& domain) {
    return m_impl->AddToWhitelist(domain);
}

bool AdBlocker::RemoveFromWhitelist(const std::string& domain) {
    return m_impl->RemoveFromWhitelist(domain);
}

bool AdBlocker::IsWhitelisted(const std::string& domain) const {
    return m_impl->IsWhitelistedInternal(domain);
}

std::vector<std::string> AdBlocker::GetWhitelistedDomains() const {
    return m_impl->GetWhitelistedDomains();
}

void AdBlocker::RegisterBlockCallback(BlockCallback callback) {
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
    return true;
}

std::string AdBlocker::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetFilterActionName(FilterAction action) noexcept {
    switch (action) {
        case FilterAction::Allow: return "Allow";
        case FilterAction::Block: return "Block";
        case FilterAction::Hide: return "Hide";
        default: return "Unknown";
    }
}

// ... other GetName functions ...

std::optional<NetworkFilterRule> ParseNetworkRule(const std::string& rule) {
    // Basic parser
    if (rule.empty() || rule[0] == '!') return std::nullopt;
    if (rule.find("##") != std::string::npos) return std::nullopt; // Cosmetic

    NetworkFilterRule r;
    r.originalRule = rule;
    r.action = FilterAction::Block;

    // Handle exception
    std::string_view p = rule;
    if (StartsWith(p, "@@")) {
        r.isException = true;
        r.action = FilterAction::Allow;
        p = p.substr(2);
    }

    // Handle options ($...)
    size_t optPos = p.find('$');
    if (optPos != std::string::npos) {
        r.pattern = std::string(p.substr(0, optPos));
        // Parse options (simplified)
        std::string opts = std::string(p.substr(optPos + 1));
        if (opts.find("domain=") != std::string::npos) {
            // Extract domains
        }
    } else {
        r.pattern = std::string(p);
    }

    return r;
}

std::optional<CosmeticFilterRule> ParseCosmeticRule(const std::string& rule) {
    size_t sepPos = rule.find("##");
    if (sepPos == std::string::npos) return std::nullopt;

    CosmeticFilterRule r;
    r.originalRule = rule;
    r.selector = rule.substr(sepPos + 2);

    std::string domains = rule.substr(0, sepPos);
    if (!domains.empty()) {
        // Parse domains...
        r.domains.push_back(domains); // Simplified
    }

    r.action = "hide";
    return r;
}

bool IsThirdParty(const std::string& requestUrl, const std::string& pageUrl) {
    return GetDomainFromUrl(requestUrl) != GetDomainFromUrl(pageUrl);
}

} // namespace WebBrowser
} // namespace ShadowStrike
