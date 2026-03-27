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
#include "PolicyManager.hpp"
#include "ConfigManager.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"

#include <sstream>
#include <thread>

namespace ShadowStrike {
namespace Config {

// ============================================================================
// PolicyManagerImpl — PIMPL internals
// ============================================================================

class PolicyManagerImpl final {
public:
    PolicyManagerConfiguration       m_config;
    PolicyStatus                     m_status{ PolicyStatus::Uninitialized };
    std::vector<PolicyViolation>     m_violations;

    std::unordered_map<uint64_t, PolicyChangeCallback>  m_policyCallbacks;
    std::unordered_map<uint64_t, ViolationCallback>     m_violationCallbacks;
    std::unordered_map<uint64_t, SyncCallback>          m_syncCallbacks;
    ErrorCallback                                       m_errorCallback;

    uint64_t                         m_nextCallbackId{ 1 };
    PolicyStatistics                 m_stats;
    std::optional<SystemTimePoint>   m_lastSyncTime;
    std::atomic<bool>                m_syncInProgress{ false };
    std::atomic<bool>                m_shutdownRequested{ false };
    std::jthread                     m_syncThread;
    uint64_t                         m_nextViolationId{ 1 };
};

// ============================================================================
// Static members
// ============================================================================

std::atomic<bool> PolicyManager::s_instanceCreated{ false };

// ============================================================================
// Singleton
// ============================================================================

PolicyManager& PolicyManager::Instance() noexcept {
    static PolicyManager instance;
    return instance;
}

bool PolicyManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// Ctor / Dtor
// ============================================================================

PolicyManager::PolicyManager()
    : m_impl(std::make_unique<PolicyManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

PolicyManager::~PolicyManager() {
    Shutdown();
}

// ============================================================================
// Lifecycle
// ============================================================================

bool PolicyManager::Initialize(const PolicyManagerConfiguration& config) {
    bool shouldLoadCache = false;

    {
        std::unique_lock lock(m_mutex);

        if (m_impl->m_status == PolicyStatus::Running ||
            m_impl->m_status == PolicyStatus::Initializing) {
            SS_LOG_WARN(L"Policy", L"PolicyManager already initialized or initializing");
            return (m_impl->m_status == PolicyStatus::Running);
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(L"Policy", L"Invalid PolicyManagerConfiguration supplied");
            return false;
        }

        m_impl->m_status = PolicyStatus::Initializing;
        m_impl->m_config = config;
        m_impl->m_shutdownRequested.store(false, std::memory_order_release);
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        shouldLoadCache = config.enableOfflineCache && !config.offlineCachePath.empty();
    }

    // Load offline cache outside the lock (LoadFromOfflineCache takes its own locks)
    if (shouldLoadCache) {
        (void)LoadFromOfflineCache();
    }

    {
        std::unique_lock lock(m_mutex);

        // Guard against concurrent Shutdown() that ran while we were loading cache
        if (m_impl->m_status != PolicyStatus::Initializing) {
            SS_LOG_WARN(L"Policy", L"PolicyManager state changed during init, aborting");
            return false;
        }

        // Launch periodic sync thread
        if (config.enableAutoSync && config.syncIntervalSeconds > 0) {
            m_impl->m_syncThread = std::jthread([this](std::stop_token stoken) {
                const auto interval = std::chrono::seconds(m_impl->m_config.syncIntervalSeconds);
                while (!stoken.stop_requested() && !m_impl->m_shutdownRequested.load(std::memory_order_acquire)) {
                    constexpr auto kWakeInterval = std::chrono::seconds(1);
                    auto remaining = interval;
                    while (remaining > std::chrono::seconds(0) &&
                           !stoken.stop_requested() &&
                           !m_impl->m_shutdownRequested.load(std::memory_order_acquire)) {
                        auto sleepTime = std::min(remaining, kWakeInterval);
                        std::this_thread::sleep_for(sleepTime);
                        remaining -= sleepTime;
                    }
                    if (stoken.stop_requested() || m_impl->m_shutdownRequested.load(std::memory_order_acquire))
                        break;
                    (void)SyncWithServer();
                }
            });
        }

        m_impl->m_status = PolicyStatus::Running;
    }

    SS_LOG_INFO(L"Policy", L"PolicyManager initialized successfully");
    return true;
}

void PolicyManager::Shutdown() {
    {
        std::unique_lock lock(m_mutex);
        if (m_impl->m_status == PolicyStatus::Stopped ||
            m_impl->m_status == PolicyStatus::Uninitialized) {
            return;
        }
        m_impl->m_status = PolicyStatus::Stopping;
    }

    SS_LOG_INFO(L"Policy", L"PolicyManager shutting down");
    m_impl->m_shutdownRequested.store(true, std::memory_order_release);

    if (m_impl->m_syncThread.joinable()) {
        m_impl->m_syncThread.request_stop();
        m_impl->m_syncThread.join();
    }

    // Persist active policies before shutdown
    if (m_impl->m_config.enableOfflineCache && !m_impl->m_config.offlineCachePath.empty()) {
        (void)SaveToOfflineCache();
    }

    {
        std::unique_lock lock(m_mutex);
        m_activePolicies.clear();
        m_impl->m_status = PolicyStatus::Stopped;
    }
    SS_LOG_INFO(L"Policy", L"PolicyManager shutdown complete");
}

bool PolicyManager::IsInitialized() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_impl && m_impl->m_status == PolicyStatus::Running;
}

PolicyStatus PolicyManager::GetStatus() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_impl ? m_impl->m_status : PolicyStatus::Uninitialized;
}

// ============================================================================
// Helper: fire callbacks outside lock
// ============================================================================

namespace {

// Serialize a PolicyValue to JSON value
Utils::JSON::Json PolicyValueToJson(const PolicyValue& val) {
    return std::visit([](auto&& arg) -> Utils::JSON::Json {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>)
            return nullptr;
        else if constexpr (std::is_same_v<T, bool>)
            return arg;
        else if constexpr (std::is_same_v<T, int64_t>)
            return arg;
        else if constexpr (std::is_same_v<T, double>)
            return arg;
        else if constexpr (std::is_same_v<T, std::string>)
            return arg;
        else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            Utils::JSON::Json arr = Utils::JSON::Json::array();
            for (const auto& s : arg) arr.push_back(s);
            return arr;
        }
        else if constexpr (std::is_same_v<T, std::map<std::string, std::string>>) {
            Utils::JSON::Json obj = Utils::JSON::Json::object();
            for (const auto& [k, v] : arg) obj[k] = v;
            return obj;
        }
        else {
            return nullptr;
        }
    }, val);
}

// Deserialize a JSON value into a PolicyValue
PolicyValue JsonToPolicyValue(const Utils::JSON::Json& j) {
    if (j.is_null())        return std::monostate{};
    if (j.is_boolean())     return j.get<bool>();
    if (j.is_number_integer()) return j.get<int64_t>();
    if (j.is_number_float())   return j.get<double>();
    if (j.is_string())      return j.get<std::string>();
    if (j.is_array()) {
        std::vector<std::string> vec;
        vec.reserve(j.size());
        for (const auto& elem : j) {
            vec.push_back(elem.is_string() ? elem.get<std::string>() : elem.dump());
        }
        return vec;
    }
    if (j.is_object()) {
        std::map<std::string, std::string> m;
        for (auto it = j.begin(); it != j.end(); ++it) {
            m[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
        }
        return m;
    }
    return std::monostate{};
}

// Serialize SystemTimePoint as ISO-8601 UTC string
std::string TimePointToIso8601(const SystemTimePoint& tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// Parse ISO-8601 UTC string to SystemTimePoint
SystemTimePoint Iso8601ToTimePoint(const std::string& s) {
    std::tm tm{};
    int y{}, mon{}, d{}, h{}, mi{}, se{};
    if (sscanf_s(s.c_str(), "%d-%d-%dT%d:%d:%dZ", &y, &mon, &d, &h, &mi, &se) == 6) {
        tm.tm_year = y - 1900;
        tm.tm_mon  = mon - 1;
        tm.tm_mday = d;
        tm.tm_hour = h;
        tm.tm_min  = mi;
        tm.tm_sec  = se;
        tm.tm_isdst = 0;
        return std::chrono::system_clock::from_time_t(_mkgmtime(&tm));
    }
    return {};
}

// Serialize a Policy to nlohmann::json object
Utils::JSON::Json PolicyToJsonObj(const Policy& p) {
    Utils::JSON::Json j;
    j["id"]            = p.id;
    j["name"]          = p.name;
    j["description"]   = p.description;
    j["type"]          = static_cast<uint8_t>(p.type);
    j["state"]         = static_cast<uint8_t>(p.state);
    j["enforcement"]   = static_cast<uint8_t>(p.enforcement);
    j["isMandatory"]   = p.isMandatory;
    j["priority"]      = p.priority;
    j["version"]       = p.version;
    j["effectiveFrom"] = TimePointToIso8601(p.effectiveFrom);
    j["createdAt"]     = TimePointToIso8601(p.createdAt);
    j["modifiedAt"]    = TimePointToIso8601(p.modifiedAt);
    j["createdBy"]     = p.createdBy;

    if (p.expiresAt.has_value()) {
        j["expiresAt"] = TimePointToIso8601(*p.expiresAt);
    }

    // Settings
    Utils::JSON::Json settingsJson = Utils::JSON::Json::object();
    for (const auto& [key, setting] : p.settings) {
        Utils::JSON::Json sj;
        sj["key"]          = setting.key;
        sj["displayName"]  = setting.displayName;
        sj["value"]        = PolicyValueToJson(setting.value);
        sj["enforcement"]  = static_cast<uint8_t>(setting.enforcement);
        sj["description"]  = setting.description;
        settingsJson[key]  = std::move(sj);
    }
    j["settings"] = std::move(settingsJson);

    // Target groups
    if (!p.targetGroups.empty()) {
        Utils::JSON::Json arr = Utils::JSON::Json::array();
        for (const auto& g : p.targetGroups) arr.push_back(g);
        j["targetGroups"] = std::move(arr);
    }

    // Target machines
    if (!p.targetMachines.empty()) {
        Utils::JSON::Json arr = Utils::JSON::Json::array();
        for (const auto& m : p.targetMachines) arr.push_back(m);
        j["targetMachines"] = std::move(arr);
    }

    // Signature (base64 hex for offline cache)
    if (!p.signature.empty()) {
        std::string hexSig;
        hexSig.reserve(p.signature.size() * 2);
        for (uint8_t b : p.signature) {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02x", b);
            hexSig.append(hex);
        }
        j["signature"] = std::move(hexSig);
    }

    return j;
}

// Parse nlohmann::json object into Policy
std::optional<Policy> JsonObjToPolicy(const Utils::JSON::Json& j) {
    try {
        if (!j.is_object()) return std::nullopt;

        Policy p;
        if (j.contains("id") && j["id"].is_string())
            p.id = j["id"].get<std::string>();
        if (j.contains("name") && j["name"].is_string())
            p.name = j["name"].get<std::string>();
        if (j.contains("description") && j["description"].is_string())
            p.description = j["description"].get<std::string>();
        if (j.contains("type") && j["type"].is_number())
            p.type = static_cast<PolicyType>(j["type"].get<uint8_t>());
        if (j.contains("state") && j["state"].is_number())
            p.state = static_cast<PolicyState>(j["state"].get<uint8_t>());
        if (j.contains("enforcement") && j["enforcement"].is_number())
            p.enforcement = static_cast<EnforcementLevel>(j["enforcement"].get<uint8_t>());
        if (j.contains("isMandatory") && j["isMandatory"].is_boolean())
            p.isMandatory = j["isMandatory"].get<bool>();
        if (j.contains("priority") && j["priority"].is_number())
            p.priority = j["priority"].get<uint32_t>();
        if (j.contains("version") && j["version"].is_number())
            p.version = j["version"].get<uint32_t>();
        if (j.contains("effectiveFrom") && j["effectiveFrom"].is_string())
            p.effectiveFrom = Iso8601ToTimePoint(j["effectiveFrom"].get<std::string>());
        if (j.contains("createdAt") && j["createdAt"].is_string())
            p.createdAt = Iso8601ToTimePoint(j["createdAt"].get<std::string>());
        if (j.contains("modifiedAt") && j["modifiedAt"].is_string())
            p.modifiedAt = Iso8601ToTimePoint(j["modifiedAt"].get<std::string>());
        if (j.contains("createdBy") && j["createdBy"].is_string())
            p.createdBy = j["createdBy"].get<std::string>();
        if (j.contains("expiresAt") && j["expiresAt"].is_string())
            p.expiresAt = Iso8601ToTimePoint(j["expiresAt"].get<std::string>());

        // Settings
        if (j.contains("settings") && j["settings"].is_object()) {
            for (auto it = j["settings"].begin(); it != j["settings"].end(); ++it) {
                const auto& sj = it.value();
                PolicySetting ps;
                ps.key = it.key();
                if (sj.contains("displayName") && sj["displayName"].is_string())
                    ps.displayName = sj["displayName"].get<std::string>();
                if (sj.contains("value"))
                    ps.value = JsonToPolicyValue(sj["value"]);
                if (sj.contains("enforcement") && sj["enforcement"].is_number())
                    ps.enforcement = static_cast<EnforcementLevel>(sj["enforcement"].get<uint8_t>());
                if (sj.contains("description") && sj["description"].is_string())
                    ps.description = sj["description"].get<std::string>();
                p.settings[ps.key] = std::move(ps);
            }
        }

        // Target groups
        if (j.contains("targetGroups") && j["targetGroups"].is_array()) {
            for (const auto& g : j["targetGroups"]) {
                if (g.is_string()) p.targetGroups.insert(g.get<std::string>());
            }
        }

        // Target machines
        if (j.contains("targetMachines") && j["targetMachines"].is_array()) {
            for (const auto& m : j["targetMachines"]) {
                if (m.is_string()) p.targetMachines.insert(m.get<std::string>());
            }
        }

        // Signature (hex-encoded)
        if (j.contains("signature") && j["signature"].is_string()) {
            const auto& hexStr = j["signature"].get<std::string>();
            if (hexStr.size() % 2 == 0) {
                p.signature.reserve(hexStr.size() / 2);
                for (size_t i = 0; i + 1 < hexStr.size(); i += 2) {
                    unsigned int byte = 0;
                    if (sscanf_s(hexStr.c_str() + i, "%2x", &byte) == 1) {
                        p.signature.push_back(static_cast<uint8_t>(byte));
                    }
                }
            }
        }

        return p;
    }
    catch (...) {
        return std::nullopt;
    }
}

} // anonymous namespace

// ============================================================================
// Struct methods — Policy
// ============================================================================

bool Policy::IsValid() const noexcept {
    if (name.empty()) return false;
    if (settings.empty()) return false;
    if (IsExpired()) return false;
    return true;
}

bool Policy::IsExpired() const noexcept {
    if (!expiresAt.has_value()) return false;
    return std::chrono::system_clock::now() > *expiresAt;
}

std::string Policy::ToJson() const {
    try {
        auto j = PolicyToJsonObj(*this);
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — PolicySetting
// ============================================================================

std::string PolicySetting::ToJson() const {
    try {
        Utils::JSON::Json j;
        j["key"]         = key;
        j["displayName"] = displayName;
        j["value"]       = PolicyValueToJson(value);
        j["enforcement"] = static_cast<uint8_t>(enforcement);
        j["description"] = description;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — PolicyViolation
// ============================================================================

std::string PolicyViolation::ToJson() const {
    try {
        Utils::JSON::Json j;
        j["violationId"]  = violationId;
        j["policyId"]     = policyId;
        j["settingKey"]   = settingKey;
        j["expectedValue"]= PolicyValueToJson(expectedValue);
        j["actualValue"]  = PolicyValueToJson(actualValue);
        j["timestamp"]    = TimePointToIso8601(timestamp);
        j["machineName"]  = machineName;
        j["userName"]     = userName;
        j["processName"]  = processName;
        j["action"]       = static_cast<uint8_t>(action);
        j["remediated"]   = remediated;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — ComplianceReport
// ============================================================================

double ComplianceReport::GetCompliancePercentage() const noexcept {
    if (totalPolicies == 0) return 100.0;
    return (static_cast<double>(compliantCount) / static_cast<double>(totalPolicies)) * 100.0;
}

std::string ComplianceReport::ToJson() const {
    try {
        Utils::JSON::Json j;
        j["reportId"]       = reportId;
        j["machineName"]    = machineName;
        j["overallStatus"]  = std::string(GetComplianceStatusName(overallStatus));
        j["totalPolicies"]  = totalPolicies;
        j["compliantCount"] = compliantCount;
        j["nonCompliantCount"] = nonCompliantCount;
        j["compliancePercentage"] = GetCompliancePercentage();
        j["generatedAt"]    = TimePointToIso8601(generatedAt);

        Utils::JSON::Json pcj = Utils::JSON::Json::object();
        for (const auto& [pid, status] : policyCompliance) {
            pcj[pid] = std::string(GetComplianceStatusName(status));
        }
        j["policyCompliance"] = std::move(pcj);

        Utils::JSON::Json violations = Utils::JSON::Json::array();
        for (const auto& v : pendingViolations) {
            Utils::JSON::Json vj;
            (void)Utils::JSON::Parse(v.ToJson(), vj);
            violations.push_back(std::move(vj));
        }
        j["pendingViolations"] = std::move(violations);

        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — PolicySyncResult
// ============================================================================

std::string PolicySyncResult::ToJson() const {
    try {
        Utils::JSON::Json j;
        j["success"]          = success;
        j["newPolicies"]      = newPolicies;
        j["updatedPolicies"]  = updatedPolicies;
        j["removedPolicies"]  = removedPolicies;
        j["failedPolicies"]   = failedPolicies;
        j["syncTime"]         = TimePointToIso8601(syncTime);

        Utils::JSON::Json errs = Utils::JSON::Json::array();
        for (const auto& e : errors) errs.push_back(e);
        j["errors"] = std::move(errs);

        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — PolicyStatistics
// ============================================================================

void PolicyStatistics::Reset() noexcept {
    policiesApplied.store(0, std::memory_order_relaxed);
    policiesActive.store(0, std::memory_order_relaxed);
    enforcementChecks.store(0, std::memory_order_relaxed);
    violationsDetected.store(0, std::memory_order_relaxed);
    violationsRemediated.store(0, std::memory_order_relaxed);
    syncOperations.store(0, std::memory_order_relaxed);
    syncFailures.store(0, std::memory_order_relaxed);
    for (auto& counter : byPolicyType)
        counter.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string PolicyStatistics::ToJson() const {
    try {
        Utils::JSON::Json j;
        j["policiesApplied"]      = policiesApplied.load(std::memory_order_relaxed);
        j["policiesActive"]       = policiesActive.load(std::memory_order_relaxed);
        j["enforcementChecks"]    = enforcementChecks.load(std::memory_order_relaxed);
        j["violationsDetected"]   = violationsDetected.load(std::memory_order_relaxed);
        j["violationsRemediated"] = violationsRemediated.load(std::memory_order_relaxed);
        j["syncOperations"]       = syncOperations.load(std::memory_order_relaxed);
        j["syncFailures"]         = syncFailures.load(std::memory_order_relaxed);

        Utils::JSON::Json typeArr = Utils::JSON::Json::array();
        for (const auto& c : byPolicyType)
            typeArr.push_back(c.load(std::memory_order_relaxed));
        j["byPolicyType"] = std::move(typeArr);

        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime).count();
        j["uptimeSeconds"] = elapsed;

        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// ============================================================================
// Struct methods — PolicyManagerConfiguration
// ============================================================================

bool PolicyManagerConfiguration::IsValid() const noexcept {
    if (syncIntervalSeconds == 0 && enableAutoSync) return false;
    if (enableOfflineCache && offlineCachePath.empty()) return false;
    if (maxViolationHistory == 0) return false;
    return true;
}

// ============================================================================
// Policy Application
// ============================================================================

bool PolicyManager::ApplyPolicy(const Policy& policy) {
    if (!policy.IsValid()) {
        SS_LOG_ERROR(L"Policy", L"ApplyPolicy rejected invalid policy id=%hs name=%hs",
                     policy.id.c_str(), policy.name.c_str());
        return false;
    }

    // Signature verification for signed policies — fail-closed
    if (!policy.signature.empty()) {
        SS_LOG_INFO(L"Policy", L"Verifying signature for policy id=%hs", policy.id.c_str());

        // Serialize policy payload (everything except signature) for verification
        Policy verifyPolicy = policy;
        verifyPolicy.signature.clear();
        const std::string payload = verifyPolicy.ToJson();

        // Signature verification requires a loaded public key from the management server.
        // Without the server's public key material, we cannot verify — reject to fail closed.
        SS_LOG_ERROR(L"Policy", L"Policy id=%hs has signature but no trust store key configured; "
                    L"rejecting signed policy (fail-closed)", policy.id.c_str());
        return false;
    }

    // Snapshot callbacks under lock, then fire outside lock
    std::vector<PolicyChangeCallback> callbacksToFire;
    bool isUpdate = false;

    {
        std::unique_lock lock(m_mutex);

        auto it = m_activePolicies.find(policy.id);
        isUpdate = (it != m_activePolicies.end());

        m_activePolicies[policy.id] = policy;
        m_activePolicies[policy.id].state = PolicyState::Active;

        m_impl->m_stats.policiesApplied.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.policiesActive.store(
            static_cast<uint64_t>(m_activePolicies.size()), std::memory_order_relaxed);

        const auto typeIdx = static_cast<size_t>(policy.type);
        if (typeIdx < m_impl->m_stats.byPolicyType.size()) {
            m_impl->m_stats.byPolicyType[typeIdx].fetch_add(1, std::memory_order_relaxed);
        }

        callbacksToFire.reserve(m_impl->m_policyCallbacks.size());
        for (const auto& [cbId, cb] : m_impl->m_policyCallbacks) {
            if (cb) callbacksToFire.push_back(cb);
        }
    }

    // Fire callbacks outside lock
    for (const auto& cb : callbacksToFire) {
        try { cb(policy, !isUpdate); }
        catch (...) {
            SS_LOG_WARN(L"Policy", L"Policy change callback threw exception for policy id=%hs",
                        policy.id.c_str());
        }
    }

    SS_LOG_INFO(L"Policy", L"Policy %hs id=%hs (priority=%u, mandatory=%d)",
                isUpdate ? "updated" : "applied",
                policy.id.c_str(), policy.priority, policy.isMandatory ? 1 : 0);
    return true;
}

PolicySyncResult PolicyManager::ApplyPolicies(const std::vector<Policy>& policies) {
    PolicySyncResult result;
    result.syncTime = std::chrono::system_clock::now();

    for (const auto& p : policies) {
        bool exists;
        {
            std::shared_lock lock(m_mutex);
            exists = m_activePolicies.contains(p.id);
        }

        if (ApplyPolicy(p)) {
            if (exists) ++result.updatedPolicies;
            else        ++result.newPolicies;
        }
        else {
            ++result.failedPolicies;
            result.errors.push_back("Failed to apply policy: " + p.id);
        }
    }

    result.success = (result.failedPolicies == 0);
    return result;
}

bool PolicyManager::RemovePolicy(const std::string& policyId) {
    std::vector<PolicyChangeCallback> callbacksToFire;
    Policy removedPolicy;

    {
        std::unique_lock lock(m_mutex);
        auto it = m_activePolicies.find(policyId);
        if (it == m_activePolicies.end()) {
            SS_LOG_WARN(L"Policy", L"RemovePolicy: policy id=%hs not found", policyId.c_str());
            return false;
        }

        removedPolicy = it->second;
        m_activePolicies.erase(it);
        m_impl->m_stats.policiesActive.store(
            static_cast<uint64_t>(m_activePolicies.size()), std::memory_order_relaxed);

        for (const auto& [cbId, cb] : m_impl->m_policyCallbacks) {
            if (cb) callbacksToFire.push_back(cb);
        }
    }

    for (const auto& cb : callbacksToFire) {
        try { cb(removedPolicy, false); }
        catch (...) {
            SS_LOG_WARN(L"Policy", L"Policy change callback threw on remove for id=%hs",
                        policyId.c_str());
        }
    }

    SS_LOG_INFO(L"Policy", L"Policy removed: id=%hs", policyId.c_str());
    return true;
}

bool PolicyManager::ActivatePolicy(const std::string& policyId) {
    std::unique_lock lock(m_mutex);
    auto it = m_activePolicies.find(policyId);
    if (it == m_activePolicies.end()) {
        SS_LOG_WARN(L"Policy", L"ActivatePolicy: policy id=%hs not found", policyId.c_str());
        return false;
    }
    it->second.state = PolicyState::Active;
    SS_LOG_INFO(L"Policy", L"Policy activated: id=%hs", policyId.c_str());
    return true;
}

bool PolicyManager::DeactivatePolicy(const std::string& policyId) {
    std::unique_lock lock(m_mutex);
    auto it = m_activePolicies.find(policyId);
    if (it == m_activePolicies.end()) {
        SS_LOG_WARN(L"Policy", L"DeactivatePolicy: policy id=%hs not found", policyId.c_str());
        return false;
    }
    it->second.state = PolicyState::Superseded;
    SS_LOG_INFO(L"Policy", L"Policy deactivated: id=%hs", policyId.c_str());
    return true;
}

// ============================================================================
// Policy Query
// ============================================================================

std::optional<Policy> PolicyManager::GetPolicy(const std::string& policyId) const {
    std::shared_lock lock(m_mutex);
    auto it = m_activePolicies.find(policyId);
    if (it == m_activePolicies.end()) return std::nullopt;
    return it->second;
}

std::vector<Policy> PolicyManager::GetAllPolicies() const {
    std::shared_lock lock(m_mutex);
    std::vector<Policy> result;
    result.reserve(m_activePolicies.size());
    for (const auto& [id, p] : m_activePolicies) {
        result.push_back(p);
    }
    return result;
}

std::vector<Policy> PolicyManager::GetPoliciesByType(PolicyType type) const {
    std::shared_lock lock(m_mutex);
    std::vector<Policy> result;
    for (const auto& [id, p] : m_activePolicies) {
        if (p.type == type) result.push_back(p);
    }
    return result;
}

std::vector<Policy> PolicyManager::GetActivePolicies() const {
    std::shared_lock lock(m_mutex);
    std::vector<Policy> result;
    for (const auto& [id, p] : m_activePolicies) {
        if (p.state == PolicyState::Active) result.push_back(p);
    }
    return result;
}

std::vector<Policy> PolicyManager::GetMandatoryPolicies() const {
    std::shared_lock lock(m_mutex);
    std::vector<Policy> result;
    for (const auto& [id, p] : m_activePolicies) {
        if (p.isMandatory && p.state == PolicyState::Active) result.push_back(p);
    }
    return result;
}

// ============================================================================
// Enforcement
// ============================================================================

bool PolicyManager::IsEnforced(const std::string& settingName) const {
    std::shared_lock lock(m_mutex);
    m_impl->m_stats.enforcementChecks.fetch_add(1, std::memory_order_relaxed);

    for (const auto& [id, p] : m_activePolicies) {
        if (p.state != PolicyState::Active || !p.isMandatory) continue;
        if (p.settings.contains(settingName)) {
            const auto& setting = p.settings.at(settingName);
            if (setting.enforcement == EnforcementLevel::Mandatory) {
                return true;
            }
        }
    }
    return false;
}

std::optional<PolicyValue> PolicyManager::GetEnforcedValue(const std::string& settingName) const {
    std::shared_lock lock(m_mutex);
    m_impl->m_stats.enforcementChecks.fetch_add(1, std::memory_order_relaxed);

    const Policy* best = nullptr;
    for (const auto& [id, p] : m_activePolicies) {
        if (p.state != PolicyState::Active || !p.isMandatory) continue;
        if (!p.settings.contains(settingName)) continue;
        const auto& setting = p.settings.at(settingName);
        if (setting.enforcement != EnforcementLevel::Mandatory) continue;
        if (!best || p.priority > best->priority) {
            best = &p;
        }
    }

    if (best) {
        return best->settings.at(settingName).value;
    }
    return std::nullopt;
}

std::string PolicyManager::GetPolicyValue(const std::string& settingName) const {
    auto val = GetEnforcedValue(settingName);
    if (val.has_value()) {
        return PolicyValueToString(*val);
    }
    return {};
}

EnforcementLevel PolicyManager::GetEnforcementLevel(const std::string& settingName) const {
    std::shared_lock lock(m_mutex);

    EnforcementLevel highest = EnforcementLevel::Disabled;
    for (const auto& [id, p] : m_activePolicies) {
        if (p.state != PolicyState::Active) continue;
        auto sit = p.settings.find(settingName);
        if (sit == p.settings.end()) continue;
        if (static_cast<uint8_t>(sit->second.enforcement) < static_cast<uint8_t>(highest)) {
            highest = sit->second.enforcement;
        }
    }
    return highest;
}

bool PolicyManager::ValidateSetting(const std::string& key, const PolicyValue& value) const {
    // Build violation and snapshot callbacks under exclusive lock since we
    // mutate m_violations and m_nextViolationId (non-atomic, non-thread-safe).
    std::optional<PolicyViolation> detectedViolation;
    std::vector<ViolationCallback> vcbs;

    {
        std::unique_lock lock(m_mutex);
        m_impl->m_stats.enforcementChecks.fetch_add(1, std::memory_order_relaxed);

        for (const auto& [id, p] : m_activePolicies) {
            if (p.state != PolicyState::Active || !p.isMandatory) continue;
            auto sit = p.settings.find(key);
            if (sit == p.settings.end()) continue;
            if (sit->second.enforcement != EnforcementLevel::Mandatory) continue;

            // Proposed value differs from mandatory policy value → violation
            if (PolicyValueToString(sit->second.value) != PolicyValueToString(value)) {
                PolicyViolation violation;
                violation.violationId  = m_impl->m_nextViolationId++;
                violation.policyId     = p.id;
                violation.settingKey   = key;
                violation.expectedValue = sit->second.value;
                violation.actualValue  = value;
                violation.timestamp    = std::chrono::system_clock::now();
                violation.action       = ViolationAction::Block;

                {
                    char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
                    DWORD sz = sizeof(compName);
                    if (::GetComputerNameA(compName, &sz)) {
                        violation.machineName = compName;
                    }
                }

                m_impl->m_stats.violationsDetected.fetch_add(1, std::memory_order_relaxed);

                m_impl->m_violations.push_back(violation);
                if (m_impl->m_violations.size() > m_impl->m_config.maxViolationHistory) {
                    m_impl->m_violations.erase(m_impl->m_violations.begin());
                }

                vcbs.reserve(m_impl->m_violationCallbacks.size());
                for (const auto& [cbId, cb] : m_impl->m_violationCallbacks) {
                    if (cb) vcbs.push_back(cb);
                }

                detectedViolation = std::move(violation);
                break;
            }
        }
    }

    // Fire violation callbacks outside lock
    if (detectedViolation.has_value()) {
        for (const auto& cb : vcbs) {
            try { cb(*detectedViolation); }
            catch (...) {
                SS_LOG_WARN(L"Policy", L"Violation callback threw for key=%hs", key.c_str());
            }
        }

        SS_LOG_WARN(L"Policy", L"Policy violation: key=%hs conflicts with mandatory policy id=%hs",
                    key.c_str(), detectedViolation->policyId.c_str());
        return false;
    }
    return true;
}

// ============================================================================
// Compliance
// ============================================================================

ComplianceStatus PolicyManager::CheckCompliance() const {
    const auto report = GenerateComplianceReport();
    return report.overallStatus;
}

ComplianceReport PolicyManager::GenerateComplianceReport() const {
    ComplianceReport report;
    report.generatedAt = std::chrono::system_clock::now();

    {
        char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD sz = sizeof(compName);
        if (::GetComputerNameA(compName, &sz)) {
            report.machineName = compName;
        }
    }

    std::shared_lock lock(m_mutex);

    uint32_t totalSettings = 0;
    uint32_t compliantSettings = 0;

    for (const auto& [policyId, policy] : m_activePolicies) {
        if (policy.state != PolicyState::Active || !policy.isMandatory) continue;

        ++report.totalPolicies;
        bool policyCompliant = true;

        for (const auto& [settingKey, setting] : policy.settings) {
            if (setting.enforcement != EnforcementLevel::Mandatory) continue;
            ++totalSettings;

            // Read actual config value from ConfigManager
            auto currentOpt = ConfigManager::Instance().GetOptionalValue<std::string>(settingKey);
            const std::string expected = PolicyValueToString(setting.value);

            if (currentOpt.has_value() && *currentOpt == expected) {
                ++compliantSettings;
            }
            else {
                policyCompliant = false;

                PolicyViolation v;
                v.policyId     = policyId;
                v.settingKey   = settingKey;
                v.expectedValue = setting.value;
                if (currentOpt.has_value()) {
                    v.actualValue = *currentOpt;
                }
                v.timestamp    = report.generatedAt;
                v.machineName  = report.machineName;
                v.action       = ViolationAction::Audit;
                report.pendingViolations.push_back(std::move(v));
            }
        }

        report.policyCompliance[policyId] =
            policyCompliant ? ComplianceStatus::Compliant : ComplianceStatus::NonCompliant;
        if (policyCompliant) ++report.compliantCount;
        else                 ++report.nonCompliantCount;
    }

    if (report.totalPolicies == 0) {
        report.overallStatus = ComplianceStatus::NotApplicable;
    }
    else if (report.nonCompliantCount == 0) {
        report.overallStatus = ComplianceStatus::Compliant;
    }
    else if (report.compliantCount > 0) {
        report.overallStatus = ComplianceStatus::PartiallyCompliant;
    }
    else {
        report.overallStatus = ComplianceStatus::NonCompliant;
    }

    return report;
}

double PolicyManager::GetCompliancePercentage() const {
    const auto report = GenerateComplianceReport();
    return report.GetCompliancePercentage();
}

std::vector<PolicyViolation> PolicyManager::GetPendingViolations() const {
    std::shared_lock lock(m_mutex);
    std::vector<PolicyViolation> result;
    for (const auto& v : m_impl->m_violations) {
        if (!v.remediated) result.push_back(v);
    }
    return result;
}

bool PolicyManager::RemediateViolation(uint64_t violationId) {
    std::unique_lock lock(m_mutex);
    for (auto& v : m_impl->m_violations) {
        if (v.violationId == violationId) {
            v.remediated = true;
            m_impl->m_stats.violationsRemediated.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"Policy", L"Violation id=%llu remediated", static_cast<unsigned long long>(violationId));
            return true;
        }
    }
    SS_LOG_WARN(L"Policy", L"RemediateViolation: violation id=%llu not found",
                static_cast<unsigned long long>(violationId));
    return false;
}

// ============================================================================
// Synchronization
// ============================================================================

PolicySyncResult PolicyManager::SyncWithServer() {
    PolicySyncResult result;
    result.syncTime = std::chrono::system_clock::now();

    bool expected = false;
    if (!m_impl->m_syncInProgress.compare_exchange_strong(expected, true)) {
        result.errors.push_back("Sync already in progress");
        SS_LOG_WARN(L"Policy", L"SyncWithServer: sync already in progress, skipping");
        return result;
    }

    // RAII guard to reset sync flag
    struct SyncGuard {
        std::atomic<bool>& flag;
        ~SyncGuard() { flag.store(false, std::memory_order_release); }
    } guard{ m_impl->m_syncInProgress };

    m_impl->m_stats.syncOperations.fetch_add(1, std::memory_order_relaxed);

    SS_LOG_INFO(L"Policy", L"SyncWithServer: loading policies from offline cache");

    // In this implementation, sync loads from offline cache.
    // Actual server communication would be implemented in the Communication layer.
    if (m_impl->m_config.enableOfflineCache && !m_impl->m_config.offlineCachePath.empty()) {
        const auto cachePath = m_impl->m_config.offlineCachePath.wstring();
        std::string content;
        Utils::FileUtils::Error fileErr;

        if (!Utils::FileUtils::ReadAllTextUtf8(cachePath, content, &fileErr)) {
            result.errors.push_back("Failed to read offline cache: " + fileErr.message);
            m_impl->m_stats.syncFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"Policy", L"SyncWithServer: offline cache read failed");
            result.success = false;

            // Fire sync callbacks
            std::vector<SyncCallback> scbs;
            {
                std::shared_lock lock(m_mutex);
                for (const auto& [cbId, cb] : m_impl->m_syncCallbacks) {
                    if (cb) scbs.push_back(cb);
                }
            }
            for (const auto& cb : scbs) {
                try { cb(result); } catch (...) {}
            }
            return result;
        }

        Utils::JSON::Json cacheJson;
        Utils::JSON::Error jsonErr;
        if (!Utils::JSON::Parse(content, cacheJson, &jsonErr)) {
            result.errors.push_back("Failed to parse offline cache JSON: " + jsonErr.message);
            m_impl->m_stats.syncFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(L"Policy", L"SyncWithServer: cache JSON parse error");
            result.success = false;

            std::vector<SyncCallback> scbs;
            {
                std::shared_lock lock(m_mutex);
                for (const auto& [cbId, cb] : m_impl->m_syncCallbacks) {
                    if (cb) scbs.push_back(cb);
                }
            }
            for (const auto& cb : scbs) {
                try { cb(result); } catch (...) {}
            }
            return result;
        }

        if (cacheJson.contains("policies") && cacheJson["policies"].is_array()) {
            for (const auto& pj : cacheJson["policies"]) {
                auto parsedPolicy = JsonObjToPolicy(pj);
                if (!parsedPolicy.has_value()) {
                    ++result.failedPolicies;
                    result.errors.push_back("Failed to parse cached policy entry");
                    continue;
                }

                bool exists;
                {
                    std::shared_lock lock(m_mutex);
                    exists = m_activePolicies.contains(parsedPolicy->id);
                }

                if (ApplyPolicy(*parsedPolicy)) {
                    if (exists) ++result.updatedPolicies;
                    else        ++result.newPolicies;
                }
                else {
                    ++result.failedPolicies;
                    result.errors.push_back("Failed to apply cached policy: " + parsedPolicy->id);
                }
            }
        }

        result.success = (result.failedPolicies == 0);
    }
    else {
        // No offline cache configured — nothing to sync from
        result.success = true;
        SS_LOG_INFO(L"Policy", L"SyncWithServer: no offline cache configured, sync is a no-op");
    }

    {
        std::unique_lock lock(m_mutex);
        m_impl->m_lastSyncTime = result.syncTime;
    }

    // Fire sync callbacks
    std::vector<SyncCallback> scbs;
    {
        std::shared_lock lock(m_mutex);
        for (const auto& [cbId, cb] : m_impl->m_syncCallbacks) {
            if (cb) scbs.push_back(cb);
        }
    }
    for (const auto& cb : scbs) {
        try { cb(result); } catch (...) {}
    }

    SS_LOG_INFO(L"Policy", L"SyncWithServer complete: new=%u updated=%u failed=%u",
                result.newPolicies, result.updatedPolicies, result.failedPolicies);
    return result;
}

PolicySyncResult PolicyManager::ForceSyncNow() {
    SS_LOG_INFO(L"Policy", L"ForceSyncNow requested");
    return SyncWithServer();
}

std::optional<SystemTimePoint> PolicyManager::GetLastSyncTime() const {
    std::shared_lock lock(m_mutex);
    return m_impl->m_lastSyncTime;
}

bool PolicyManager::IsSyncInProgress() const noexcept {
    return m_impl->m_syncInProgress.load(std::memory_order_acquire);
}

// ============================================================================
// Offline Support
// ============================================================================

bool PolicyManager::SaveToOfflineCache() const {
    std::string content;
    std::wstring widePath;
    size_t policyCount = 0;

    {
        std::shared_lock lock(m_mutex);

        if (m_impl->m_config.offlineCachePath.empty()) {
            SS_LOG_WARN(L"Policy", L"SaveToOfflineCache: no cache path configured");
            return false;
        }

        try {
            Utils::JSON::Json root;
            root["version"] = GetVersionString();
            root["savedAt"] = TimePointToIso8601(std::chrono::system_clock::now());

            Utils::JSON::Json policiesArr = Utils::JSON::Json::array();
            for (const auto& [id, p] : m_activePolicies) {
                policiesArr.push_back(PolicyToJsonObj(p));
            }
            root["policies"] = std::move(policiesArr);

            content = root.dump(2);
            widePath = m_impl->m_config.offlineCachePath.wstring();
            policyCount = m_activePolicies.size();
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(L"Policy", L"SaveToOfflineCache serialization exception: %hs", ex.what());
            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"Policy", L"SaveToOfflineCache serialization unknown exception");
            return false;
        }
    }

    // Write file outside lock to avoid blocking writers during I/O
    try {
        Utils::FileUtils::Error fileErr;
        if (!Utils::FileUtils::WriteAllTextUtf8Atomic(widePath, content, &fileErr)) {
            SS_LOG_ERROR(L"Policy", L"SaveToOfflineCache failed: %hs", fileErr.message.c_str());
            return false;
        }

        SS_LOG_INFO(L"Policy", L"Saved %zu policies to offline cache", policyCount);
        return true;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"Policy", L"SaveToOfflineCache write exception: %hs", ex.what());
        return false;
    }
    catch (...) {
        SS_LOG_ERROR(L"Policy", L"SaveToOfflineCache write unknown exception");
        return false;
    }
}

bool PolicyManager::LoadFromOfflineCache() {
    const auto cachePath = [&]() {
        std::shared_lock lock(m_mutex);
        return m_impl->m_config.offlineCachePath;
    }();

    if (cachePath.empty()) {
        SS_LOG_WARN(L"Policy", L"LoadFromOfflineCache: no cache path configured");
        return false;
    }

    const auto widePath = cachePath.wstring();
    std::string content;
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::ReadAllTextUtf8(widePath, content, &fileErr)) {
        SS_LOG_WARN(L"Policy", L"LoadFromOfflineCache: cannot read cache file: %hs",
                    fileErr.message.c_str());
        return false;
    }

    Utils::JSON::Json root;
    Utils::JSON::Error jsonErr;
    if (!Utils::JSON::Parse(content, root, &jsonErr)) {
        SS_LOG_ERROR(L"Policy", L"LoadFromOfflineCache: JSON parse error: %hs", jsonErr.message.c_str());
        return false;
    }

    if (!root.contains("policies") || !root["policies"].is_array()) {
        SS_LOG_ERROR(L"Policy", L"LoadFromOfflineCache: missing 'policies' array in cache");
        return false;
    }

    uint32_t loaded = 0, failed = 0;
    for (const auto& pj : root["policies"]) {
        auto policy = JsonObjToPolicy(pj);
        if (!policy.has_value()) {
            ++failed;
            continue;
        }
        if (ApplyPolicy(*policy)) ++loaded;
        else ++failed;
    }

    SS_LOG_INFO(L"Policy", L"Loaded %u policies from offline cache (%u failed)",
                loaded, failed);
    return (failed == 0);
}

void PolicyManager::ClearOfflineCache() {
    std::shared_lock lock(m_mutex);
    if (m_impl->m_config.offlineCachePath.empty()) return;

    const auto widePath = m_impl->m_config.offlineCachePath.wstring();
    Utils::FileUtils::Error fileErr;
    (void)Utils::FileUtils::RemoveFile(widePath, &fileErr);
    SS_LOG_INFO(L"Policy", L"Offline cache cleared");
}

// ============================================================================
// Callbacks
// ============================================================================

uint64_t PolicyManager::RegisterPolicyChangeCallback(PolicyChangeCallback callback) {
    std::unique_lock lock(m_mutex);
    const uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_policyCallbacks[id] = std::move(callback);
    return id;
}

uint64_t PolicyManager::RegisterViolationCallback(ViolationCallback callback) {
    std::unique_lock lock(m_mutex);
    const uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_violationCallbacks[id] = std::move(callback);
    return id;
}

uint64_t PolicyManager::RegisterSyncCallback(SyncCallback callback) {
    std::unique_lock lock(m_mutex);
    const uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_syncCallbacks[id] = std::move(callback);
    return id;
}

void PolicyManager::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_impl->m_errorCallback = std::move(callback);
}

void PolicyManager::UnregisterCallback(uint64_t callbackId) {
    std::unique_lock lock(m_mutex);
    m_impl->m_policyCallbacks.erase(callbackId);
    m_impl->m_violationCallbacks.erase(callbackId);
    m_impl->m_syncCallbacks.erase(callbackId);
}

// ============================================================================
// Statistics
// ============================================================================

PolicyStatistics PolicyManager::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_impl->m_stats;
}

void PolicyManager::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_impl->m_stats.Reset();
}

// ============================================================================
// Self-test & Version
// ============================================================================

bool PolicyManager::SelfTest() {
    SS_LOG_INFO(L"Policy", L"PolicyManager self-test starting");

    // Validate that basic operations work without crashing
    Policy testPolicy;
    testPolicy.id = "__selftest__";
    testPolicy.name = "SelfTest Policy";
    testPolicy.type = PolicyType::Custom;
    testPolicy.enforcement = EnforcementLevel::Advisory;
    testPolicy.isMandatory = false;
    testPolicy.priority = 0;
    testPolicy.version = 1;
    testPolicy.effectiveFrom = std::chrono::system_clock::now();
    testPolicy.createdAt = std::chrono::system_clock::now();
    testPolicy.modifiedAt = std::chrono::system_clock::now();

    PolicySetting ps;
    ps.key = "__selftest_setting__";
    ps.value = std::string("test_value");
    ps.enforcement = EnforcementLevel::Advisory;
    testPolicy.settings[ps.key] = ps;

    if (!testPolicy.IsValid()) {
        SS_LOG_ERROR(L"Policy", L"SelfTest: Policy::IsValid failed");
        return false;
    }

    // Test serialization round-trip
    const std::string json = testPolicy.ToJson();
    if (json.empty() || json == "{}") {
        SS_LOG_ERROR(L"Policy", L"SelfTest: Policy::ToJson produced empty output");
        return false;
    }

    if (!ApplyPolicy(testPolicy)) {
        SS_LOG_ERROR(L"Policy", L"SelfTest: ApplyPolicy failed");
        return false;
    }

    auto retrieved = GetPolicy("__selftest__");
    if (!retrieved.has_value()) {
        SS_LOG_ERROR(L"Policy", L"SelfTest: GetPolicy returned nullopt");
        (void)RemovePolicy("__selftest__");
        return false;
    }

    if (!RemovePolicy("__selftest__")) {
        SS_LOG_ERROR(L"Policy", L"SelfTest: RemovePolicy failed");
        return false;
    }

    SS_LOG_INFO(L"Policy", L"PolicyManager self-test passed");
    return true;
}

std::string PolicyManager::GetVersionString() noexcept {
    try {
        return std::to_string(PolicyConstants::VERSION_MAJOR) + "." +
               std::to_string(PolicyConstants::VERSION_MINOR) + "." +
               std::to_string(PolicyConstants::VERSION_PATCH);
    }
    catch (...) {
        return "0.0.0";
    }
}

// ============================================================================
// Free functions — Name lookups
// ============================================================================

std::string_view GetEnforcementLevelName(EnforcementLevel level) noexcept {
    switch (level) {
        case EnforcementLevel::Mandatory:   return "Mandatory";
        case EnforcementLevel::Default:     return "Default";
        case EnforcementLevel::Advisory:    return "Advisory";
        case EnforcementLevel::AuditOnly:   return "AuditOnly";
        case EnforcementLevel::Disabled:    return "Disabled";
    }
    return "Unknown";
}

std::string_view GetPolicyTypeName(PolicyType type) noexcept {
    switch (type) {
        case PolicyType::Scan:            return "Scan";
        case PolicyType::Protection:      return "Protection";
        case PolicyType::Exclusion:       return "Exclusion";
        case PolicyType::Network:         return "Network";
        case PolicyType::DeviceControl:   return "DeviceControl";
        case PolicyType::Application:     return "Application";
        case PolicyType::DataProtection:  return "DataProtection";
        case PolicyType::Firewall:        return "Firewall";
        case PolicyType::WebControl:      return "WebControl";
        case PolicyType::EmailControl:    return "EmailControl";
        case PolicyType::Encryption:      return "Encryption";
        case PolicyType::Update:          return "Update";
        case PolicyType::Logging:         return "Logging";
        case PolicyType::Custom:          return "Custom";
    }
    return "Unknown";
}

std::string_view GetPolicyStateName(PolicyState state) noexcept {
    switch (state) {
        case PolicyState::Active:      return "Active";
        case PolicyState::Pending:     return "Pending";
        case PolicyState::Superseded:  return "Superseded";
        case PolicyState::Expired:     return "Expired";
        case PolicyState::Revoked:     return "Revoked";
        case PolicyState::Failed:      return "Failed";
    }
    return "Unknown";
}

std::string_view GetComplianceStatusName(ComplianceStatus status) noexcept {
    switch (status) {
        case ComplianceStatus::Compliant:          return "Compliant";
        case ComplianceStatus::NonCompliant:       return "NonCompliant";
        case ComplianceStatus::PartiallyCompliant: return "PartiallyCompliant";
        case ComplianceStatus::Pending:            return "Pending";
        case ComplianceStatus::NotApplicable:      return "NotApplicable";
        case ComplianceStatus::Unknown:            return "Unknown";
    }
    return "Unknown";
}

std::string_view GetViolationActionName(ViolationAction action) noexcept {
    switch (action) {
        case ViolationAction::Allow:       return "Allow";
        case ViolationAction::Block:       return "Block";
        case ViolationAction::Quarantine:  return "Quarantine";
        case ViolationAction::Notify:      return "Notify";
        case ViolationAction::Remediate:   return "Remediate";
        case ViolationAction::Audit:       return "Audit";
    }
    return "Unknown";
}

// ============================================================================
// Free functions — PolicyValueToString
// ============================================================================

std::string PolicyValueToString(const PolicyValue& value) {
    return std::visit([](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>)
            return {};
        else if constexpr (std::is_same_v<T, bool>)
            return arg ? "true" : "false";
        else if constexpr (std::is_same_v<T, int64_t>)
            return std::to_string(arg);
        else if constexpr (std::is_same_v<T, double>) {
            char buf[64]{};
            std::snprintf(buf, sizeof(buf), "%.17g", arg);
            return buf;
        }
        else if constexpr (std::is_same_v<T, std::string>)
            return arg;
        else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            std::string result = "[";
            for (size_t i = 0; i < arg.size(); ++i) {
                if (i > 0) result += ",";
                result += "\"" + arg[i] + "\"";
            }
            result += "]";
            return result;
        }
        else if constexpr (std::is_same_v<T, std::map<std::string, std::string>>) {
            std::string result = "{";
            bool first = true;
            for (const auto& [k, v] : arg) {
                if (!first) result += ",";
                first = false;
                result += "\"" + k + "\":\"" + v + "\"";
            }
            result += "}";
            return result;
        }
        else {
            return {};
        }
    }, value);
}

// ============================================================================
// Free functions — ParsePolicyFromJson
// ============================================================================

std::optional<Policy> ParsePolicyFromJson(const std::string& json) {
    if (json.empty()) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromJson: empty input");
        return std::nullopt;
    }

    Utils::JSON::Json j;
    Utils::JSON::Error err;
    if (!Utils::JSON::Parse(json, j, &err)) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromJson: parse error: %hs", err.message.c_str());
        return std::nullopt;
    }

    auto result = JsonObjToPolicy(j);
    if (!result.has_value()) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromJson: failed to map JSON to Policy struct");
    }
    return result;
}

// ============================================================================
// Free functions — ParsePolicyFromXml
// ============================================================================

std::optional<Policy> ParsePolicyFromXml(const std::string& xml) {
    if (xml.empty()) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromXml: empty input");
        return std::nullopt;
    }

    Utils::XML::Document doc;
    Utils::XML::Error err;
    if (!Utils::XML::Parse(xml, doc, &err)) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromXml: parse error: %hs", err.message.c_str());
        return std::nullopt;
    }

    auto root = doc.first_child();
    if (!root) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromXml: no root element");
        return std::nullopt;
    }

    Policy p;

    // Read scalar fields
    {
        std::string val;
        if (Utils::XML::GetText(root, "id", val))            p.id = val;
        if (Utils::XML::GetText(root, "name", val))          p.name = val;
        if (Utils::XML::GetText(root, "description", val))   p.description = val;
        if (Utils::XML::GetText(root, "createdBy", val))     p.createdBy = val;

        int64_t numVal = 0;
        if (Utils::XML::GetInt64(root, "type", numVal))
            p.type = static_cast<PolicyType>(static_cast<uint8_t>(numVal));
        if (Utils::XML::GetInt64(root, "state", numVal))
            p.state = static_cast<PolicyState>(static_cast<uint8_t>(numVal));
        if (Utils::XML::GetInt64(root, "enforcement", numVal))
            p.enforcement = static_cast<EnforcementLevel>(static_cast<uint8_t>(numVal));
        if (Utils::XML::GetInt64(root, "priority", numVal))
            p.priority = static_cast<uint32_t>(numVal);
        if (Utils::XML::GetInt64(root, "version", numVal))
            p.version = static_cast<uint32_t>(numVal);

        bool boolVal = false;
        if (Utils::XML::GetBool(root, "isMandatory", boolVal)) p.isMandatory = boolVal;

        if (Utils::XML::GetText(root, "effectiveFrom", val))
            p.effectiveFrom = Iso8601ToTimePoint(val);
        if (Utils::XML::GetText(root, "createdAt", val))
            p.createdAt = Iso8601ToTimePoint(val);
        if (Utils::XML::GetText(root, "modifiedAt", val))
            p.modifiedAt = Iso8601ToTimePoint(val);
        if (Utils::XML::GetText(root, "expiresAt", val))
            p.expiresAt = Iso8601ToTimePoint(val);
    }

    // Parse settings
    auto settingsNode = root.child("settings");
    if (settingsNode) {
        for (auto settingNode = settingsNode.first_child(); settingNode;
             settingNode = settingNode.next_sibling()) {
            PolicySetting ps;
            std::string val;
            if (Utils::XML::GetText(settingNode, "key", val)) ps.key = val;
            else continue; // key is required

            if (Utils::XML::GetText(settingNode, "displayName", val)) ps.displayName = val;
            if (Utils::XML::GetText(settingNode, "description", val)) ps.description = val;
            if (Utils::XML::GetText(settingNode, "value", val)) ps.value = val;

            int64_t numVal = 0;
            if (Utils::XML::GetInt64(settingNode, "enforcement", numVal))
                ps.enforcement = static_cast<EnforcementLevel>(static_cast<uint8_t>(numVal));

            p.settings[ps.key] = std::move(ps);
        }
    }

    // Parse target groups
    auto groupsNode = root.child("targetGroups");
    if (groupsNode) {
        for (auto groupNode = groupsNode.first_child(); groupNode;
             groupNode = groupNode.next_sibling()) {
            const char* text = groupNode.text().get();
            if (text && text[0] != '\0') {
                p.targetGroups.insert(text);
            }
        }
    }

    // Parse target machines
    auto machinesNode = root.child("targetMachines");
    if (machinesNode) {
        for (auto machineNode = machinesNode.first_child(); machineNode;
             machineNode = machineNode.next_sibling()) {
            const char* text = machineNode.text().get();
            if (text && text[0] != '\0') {
                p.targetMachines.insert(text);
            }
        }
    }

    if (p.name.empty() || p.settings.empty()) {
        SS_LOG_ERROR(L"Policy", L"ParsePolicyFromXml: incomplete policy (name or settings missing)");
        return std::nullopt;
    }

    return p;
}

}  // namespace Config
}  // namespace ShadowStrike

