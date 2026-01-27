#include "BehaviorBlocker.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <regex>
#include <chrono>
#include <atomic>
#include <nlohmann/json.hpp>

namespace ShadowStrike::RealTime {

using json = nlohmann::json;

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

std::string ProcessBehavior::ToJson() const {
    try {
        return json{
            {"pid", processId},
            {"path", processPath},
            {"cmd", commandLine},
            {"type", static_cast<int>(type)},
            {"target", target},
            {"risk", static_cast<int>(risk)}
        }.dump();
    } catch (...) {
        return "{}";
    }
}

std::string BlockEvent::ToJson() const {
    try {
        return json{
            {"ts", timestamp},
            {"pid", processId},
            {"path", processPath},
            {"type", static_cast<int>(behaviorType)},
            {"action", static_cast<int>(actionTaken)},
            {"rule", ruleId},
            {"details", details}
        }.dump();
    } catch (...) {
        return "{}";
    }
}

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

// Unique identifier for a process instance: PID + Creation Time
struct ProcessKey {
    uint32_t pid;
    uint64_t creationTime;

    bool operator==(const ProcessKey& other) const {
        return pid == other.pid && creationTime == other.creationTime;
    }
};

struct ProcessKeyHash {
    std::size_t operator()(const ProcessKey& k) const {
        return std::hash<uint32_t>{}(k.pid) ^ (std::hash<uint64_t>{}(k.creationTime) << 1);
    }
};

struct CompiledRule {
    BehaviorRule rule;
    std::unique_ptr<std::regex> targetRegex;
    bool valid = false;
};

struct CompiledExclusion {
    BehaviorExclusion exclusion;
    std::unique_ptr<std::regex> pathRegex;
    bool valid = false;
};

struct BehaviorBlockerStats {
    std::atomic<uint64_t> behaviorsAnalyzed{0};
    std::atomic<uint64_t> threatsBlocked{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> processesSuspended{0};
    std::atomic<uint64_t> rulesEvaluated{0};
    std::atomic<uint64_t> analysisFailures{0};
    std::atomic<uint64_t> exclusionsMatched{0};
    std::atomic<uint64_t> totalAnalysisTimeUs{0};

    [[nodiscard]] std::string ToJson() const {
        return json{
            {"analyzed", behaviorsAnalyzed.load()},
            {"blocked", threatsBlocked.load()},
            {"terminated", processesTerminated.load()},
            {"suspended", processesSuspended.load()},
            {"rules_eval", rulesEvaluated.load()},
            {"failures", analysisFailures.load()},
            {"exclusions", exclusionsMatched.load()},
            {"total_time_us", totalAnalysisTimeUs.load()}
        }.dump();
    }
};

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class BehaviorBlockerImpl {
public:
    BehaviorBlockerImpl() {
        LoadDefaultRules();
    }

    ~BehaviorBlockerImpl() = default;

    BlockAction AnalyzeBehavior(const ProcessBehavior& behavior) {
        auto start = std::chrono::high_resolution_clock::now();
        m_stats.behaviorsAnalyzed++;

        // 1. Validation
        if (behavior.processId == 0) return BlockAction::Allow;

        // 2. Identify Process (Handle PID Reuse)
        ProcessKey pKey = GetProcessKey(behavior.processId);

        // 3. Check Manual Blocks (Fast Path)
        {
            std::shared_lock lock(m_blockedMutex);
            if (m_blockedPids.contains(pKey)) {
                return BlockAction::BlockOperation; // Already blocked, deny everything
            }
        }

        // 4. Check Exclusions
        if (IsExcluded(behavior)) {
            m_stats.exclusionsMatched++;
            return BlockAction::Allow;
        }

        BlockAction resultAction = BlockAction::Allow;
        std::string matchingRuleId;
        std::string matchDetails;

        // 5. Rule Evaluation (Read Lock)
        {
            std::shared_lock lock(m_ruleMutex);

            for (const auto& compiled : m_rules) {
                if (!compiled.valid) continue;

                const auto& rule = compiled.rule;
                m_stats.rulesEvaluated++;

                // A. Type mismatch check
                if (rule.targetType != behavior.type) continue;

                // B. Risk threshold check
                if (behavior.risk < rule.minRiskLevel) continue;

                // C. Pattern match (Target)
                bool matched = false;
                try {
                    if (compiled.targetRegex && std::regex_search(behavior.target, *compiled.targetRegex)) {
                        matched = true;
                    }
                } catch (const std::exception& e) {
                    Utils::Logger::Error("Rule {} regex failure: {}", rule.ruleId, e.what());
                    m_stats.analysisFailures++;
                    continue;
                }

                if (matched) {
                    // We have a match. Determine if this is the strongest action.
                    // Priority: Terminate > Suspend > Block > Quarantine > Log > Allow
                    if (rule.action > resultAction) {
                        resultAction = rule.action;
                        matchingRuleId = rule.ruleId;
                        matchDetails = "Matched pattern: " + rule.targetPattern;
                    }

                    // If we reached Terminate, we can stop searching (highest priority)
                    if (resultAction == BlockAction::TerminateProcess) {
                        break;
                    }
                }
            }
        }

        // 6. Apply Action
        if (resultAction != BlockAction::Allow) {
            HandleBlockAction(behavior, resultAction, matchingRuleId, matchDetails);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        m_stats.totalAnalysisTimeUs += duration;

        return resultAction;
    }

    bool BlockProcess(uint32_t pid, const std::string& reason) {
        if (pid == 0) return false;

        Utils::Logger::Info("Manual block requested for PID {}: {}", pid, reason);

        ProcessKey key = GetProcessKey(pid);

        {
            std::unique_lock lock(m_blockedMutex);
            m_blockedPids.insert(key);
        }

        // Default manual block action is usually Terminate for safety
        return TerminateProcess(pid);
    }

    bool TerminateProcess(uint32_t pid) {
        if (pid == 0) return false;

        // SAFETIES: Do not terminate critical system processes or ourselves
        if (IsCriticalProcess(pid)) {
            Utils::Logger::Error("Refusing to terminate critical system process PID {}", pid);
            return false;
        }

        try {
            // Attempt to terminate using ProcessUtils
            if (Utils::ProcessUtils::TerminateProcess(pid)) {
                Utils::Logger::Info("Successfully terminated PID {}", pid);
                m_stats.processesTerminated++;

                // Record in blocked list to prevent respawn confusion or further alerts
                ProcessKey key = GetProcessKey(pid);
                std::unique_lock lock(m_blockedMutex);
                m_blockedPids.insert(key);
                return true;
            } else {
                Utils::Logger::Error("Failed to terminate PID {}", pid);
                return false;
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("Exception terminating PID {}: {}", pid, e.what());
            return false;
        }
    }

    bool IsBlocked(uint32_t pid) const {
        // Warning: This simple check might be susceptible to PID reuse if the caller doesn't have timing info
        // But for internal consistency we do best-effort lookups
        ProcessKey key = const_cast<BehaviorBlockerImpl*>(this)->GetProcessKey(pid); // Logical constness
        std::shared_lock lock(m_blockedMutex);
        return m_blockedPids.contains(key);
    }

    bool AddRule(const BehaviorRule& rule) {
        std::unique_lock lock(m_ruleMutex);

        // Check for duplicates
        for (const auto& r : m_rules) {
            if (r.rule.ruleId == rule.ruleId) return false;
        }

        CompiledRule compiled;
        compiled.rule = rule;

        try {
            compiled.targetRegex = std::make_unique<std::regex>(
                rule.targetPattern,
                std::regex::icase | std::regex::optimize
            );
            compiled.valid = true;
        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to compile regex for rule {}: {}", rule.ruleId, e.what());
            return false;
        }

        m_rules.push_back(std::move(compiled));
        Utils::Logger::Info("Added behavior rule: {}", rule.ruleId);
        return true;
    }

    bool RemoveRule(const std::string& ruleId) {
        std::unique_lock lock(m_ruleMutex);
        auto it = std::remove_if(m_rules.begin(), m_rules.end(),
            [&](const CompiledRule& r) { return r.rule.ruleId == ruleId; });

        if (it != m_rules.end()) {
            m_rules.erase(it, m_rules.end());
            Utils::Logger::Info("Removed behavior rule: {}", ruleId);
            return true;
        }
        return false;
    }

    void ClearRules() {
        std::unique_lock lock(m_ruleMutex);
        m_rules.clear();
    }

    void LoadDefaultRules() {
        std::unique_lock lock(m_ruleMutex);
        m_rules.clear();

        auto addRuleInternal = [&](const BehaviorRule& r) {
            CompiledRule c;
            c.rule = r;
            try {
                c.targetRegex = std::make_unique<std::regex>(r.targetPattern, std::regex::icase | std::regex::optimize);
                c.valid = true;
                m_rules.push_back(std::move(c));
            } catch (...) {}
        };

        // 1. Ransomware - Encrypted Extension
        addRuleInternal({
            "RANSOM_EXT_001",
            "Known ransomware file extension write",
            BehaviorType::FileModification,
            ".*\\.(lock|crypt|enc|ryuk|wannacry)$",
            RiskLevel::High,
            BlockAction::TerminateProcess
        });

        // 2. LSASS Access
        addRuleInternal({
            "CRED_THEFT_001",
            "Access to LSASS memory",
            BehaviorType::ProcessInjection,
            ".*lsass\\.exe$",
            RiskLevel::Critical,
            BlockAction::TerminateProcess
        });

        // 3. Shadow Copy Deletion
        addRuleInternal({
            "RECOVERY_DEL_001",
            "Shadow copy deletion attempt",
            BehaviorType::ShadowCopyDeletion,
            ".*", // Any shadow copy deletion behavior
            RiskLevel::High,
            BlockAction::TerminateProcess
        });

        // 4. Persistence - Run Keys
        addRuleInternal({
            "PERSIST_REG_001",
            "Registry run key modification",
            BehaviorType::RegistryModification,
            ".*\\\\CurrentVersion\\\\Run\\\\.*",
            RiskLevel::Medium,
            BlockAction::LogOnly // Just log for now
        });

        // 5. Driver Loading (often used by rootkits)
        addRuleInternal({
            "DRIVER_LOAD_001",
            "Kernel driver load attempt",
            BehaviorType::DriverLoading,
            ".*\\.sys$",
            RiskLevel::High,
            BlockAction::BlockOperation // Prevent load but don't necessarily kill caller (might be system)
        });
    }

    bool AddExclusion(const BehaviorExclusion& exclusion) {
        std::unique_lock lock(m_exclusionMutex);

        CompiledExclusion compiled;
        compiled.exclusion = exclusion;

        try {
            if (!exclusion.processPathPattern.empty()) {
                compiled.pathRegex = std::make_unique<std::regex>(
                    exclusion.processPathPattern,
                    std::regex::icase | std::regex::optimize
                );
            }
            compiled.valid = true;
        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to compile regex for exclusion {}: {}", exclusion.exclusionId, e.what());
            return false;
        }

        m_exclusions.push_back(std::move(compiled));
        Utils::Logger::Info("Added exclusion: {}", exclusion.exclusionId);
        return true;
    }

    bool RemoveExclusion(const std::string& exclusionId) {
        std::unique_lock lock(m_exclusionMutex);
        auto it = std::remove_if(m_exclusions.begin(), m_exclusions.end(),
            [&](const CompiledExclusion& e) { return e.exclusion.exclusionId == exclusionId; });

        if (it != m_exclusions.end()) {
            m_exclusions.erase(it, m_exclusions.end());
            return true;
        }
        return false;
    }

    std::vector<BlockEvent> GetRecentEvents(size_t limit) const {
        std::shared_lock lock(m_historyMutex);
        std::vector<BlockEvent> result;
        result.reserve(std::min(limit, m_history.size()));

        // Return reverse order (newest first)
        for (auto it = m_history.rbegin(); it != m_history.rend() && result.size() < limit; ++it) {
            result.push_back(*it);
        }
        return result;
    }

    std::string GetStatistics() const {
        return m_stats.ToJson();
    }

    bool SelfTest() {
        // Create a dummy rule and test matching
        std::string testId = "SELFTEST_RULE";
        BehaviorRule rule{
            testId, "Test Rule", BehaviorType::FileModification, ".*test_malware\\.exe$", RiskLevel::Low, BlockAction::BlockOperation
        };

        if (!AddRule(rule)) return false;

        ProcessBehavior behavior{
            1234, "C:\\Temp\\malware.exe", "cmd.exe /c run", BehaviorType::FileModification, "C:\\Windows\\test_malware.exe", RiskLevel::Low
        };

        BlockAction action = AnalyzeBehavior(behavior);

        RemoveRule(testId);

        bool passed = (action == BlockAction::BlockOperation);
        if (!passed) {
             Utils::Logger::Error("BehaviorBlocker SelfTest failed: Rule matching not working");
        } else {
             Utils::Logger::Info("BehaviorBlocker SelfTest passed");
        }
        return passed;
    }

private:
    // Helper to get robust process key (PID + StartTime)
    ProcessKey GetProcessKey(uint32_t pid) {
        ProcessKey key{pid, 0};

        // Try to get process creation time
        // Note: ProcessUtils might fail if process is already dead or protected
        Utils::ProcessUtils::ProcessBasicInfo info;
        Utils::ProcessUtils::Error err;
        if (Utils::ProcessUtils::GetProcessBasicInfo(pid, info, &err)) {
            // Convert FILETIME to uint64_t
            ULARGE_INTEGER ull;
            ull.LowPart = info.creationTime.dwLowDateTime;
            ull.HighPart = info.creationTime.dwHighDateTime;
            key.creationTime = ull.QuadPart;
        }

        return key;
    }

    bool IsCriticalProcess(uint32_t pid) {
        // Check if process is critical (BSOD if killed)
        // 1. Check via API
        if (Utils::ProcessUtils::IsProcessCritical(pid)) return true;

        // 2. Check name allowlist for absolute safety
        auto nameOpt = Utils::ProcessUtils::GetProcessName(pid);
        if (nameOpt) {
            std::wstring name = *nameOpt;
            // Normalize case
            std::transform(name.begin(), name.end(), name.begin(), ::towlower);

            static const std::unordered_set<std::wstring> criticalNames = {
                L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
                L"lsass.exe", L"svchost.exe", L"winlogon.exe", L"dwm.exe"
            };

            if (criticalNames.count(name)) return true;
        }

        return false;
    }

    bool IsExcluded(const ProcessBehavior& behavior) {
        std::shared_lock lock(m_exclusionMutex);

        for (const auto& compiled : m_exclusions) {
            if (!compiled.valid) continue;

            const auto& exc = compiled.exclusion;

            // Type check
            if (exc.behaviorType.has_value() && *exc.behaviorType != behavior.type) {
                continue;
            }

            // Path Regex check
            if (compiled.pathRegex) {
                if (std::regex_search(behavior.processPath, *compiled.pathRegex)) {
                    return true;
                }
            }
        }

        return false;
    }

    void HandleBlockAction(const ProcessBehavior& behavior, BlockAction action, const std::string& ruleId, const std::string& details) {
        m_stats.threatsBlocked++;

        bool actionSuccess = true;

        // Execute Action
        if (action == BlockAction::TerminateProcess) {
            if (!TerminateProcess(behavior.processId)) {
                actionSuccess = false;
            }
        } else if (action == BlockAction::SuspendProcess) {
             try {
                 Utils::ProcessUtils::Error err;
                 if (Utils::ProcessUtils::SuspendProcess(behavior.processId, &err)) {
                     m_stats.processesSuspended++;
                 } else {
                     Utils::Logger::Error("Failed to suspend process {}: {}", behavior.processId, Utils::StringUtils::WideToUtf8(err.message));
                     actionSuccess = false;
                 }
             } catch(...) {
                 actionSuccess = false;
             }
        }

        // Log Event to History
        BlockEvent event{
            std::chrono::system_clock::now().time_since_epoch().count(),
            behavior.processId,
            behavior.processPath,
            behavior.type,
            action,
            ruleId,
            details + (actionSuccess ? "" : " (Action Failed)")
        };

        {
            std::unique_lock lock(m_historyMutex);
            m_history.push_back(event);
            if (m_history.size() > 1000) {
                m_history.pop_front(); // Keep size bounded
            }
        }

        Utils::Logger::Critical("BLOCKED behavior from PID {}: {} [Rule: {}]", behavior.processId, details, ruleId);
    }

    // Rules
    mutable std::shared_mutex m_ruleMutex;
    std::vector<CompiledRule> m_rules;

    // Exclusions
    mutable std::shared_mutex m_exclusionMutex;
    std::vector<CompiledExclusion> m_exclusions;

    // History
    mutable std::shared_mutex m_historyMutex;
    std::deque<BlockEvent> m_history;

    // Blocked Processes (PID Tracking)
    mutable std::shared_mutex m_blockedMutex;
    std::unordered_set<ProcessKey, ProcessKeyHash> m_blockedPids;

    // Stats
    BehaviorBlockerStats m_stats;
};

// ============================================================================
// SINGLETON WRAPPER IMPLEMENTATION
// ============================================================================

BehaviorBlocker& BehaviorBlocker::Instance() noexcept {
    static BehaviorBlocker instance;
    return instance;
}

BehaviorBlocker::BehaviorBlocker() : m_impl(std::make_unique<BehaviorBlockerImpl>()) {
    Utils::Logger::Info("BehaviorBlocker initialized");
}

BehaviorBlocker::~BehaviorBlocker() {
    Utils::Logger::Info("BehaviorBlocker shutting down");
}

BlockAction BehaviorBlocker::AnalyzeBehavior(const ProcessBehavior& behavior) {
    return m_impl->AnalyzeBehavior(behavior);
}

bool BehaviorBlocker::BlockProcess(uint32_t pid, const std::string& reason) {
    return m_impl->BlockProcess(pid, reason);
}

bool BehaviorBlocker::TerminateProcess(uint32_t pid) {
    return m_impl->TerminateProcess(pid);
}

bool BehaviorBlocker::IsBlocked(uint32_t pid) const {
    return m_impl->IsBlocked(pid);
}

bool BehaviorBlocker::AddRule(const BehaviorRule& rule) {
    return m_impl->AddRule(rule);
}

bool BehaviorBlocker::RemoveRule(const std::string& ruleId) {
    return m_impl->RemoveRule(ruleId);
}

void BehaviorBlocker::ClearRules() {
    m_impl->ClearRules();
}

void BehaviorBlocker::LoadDefaultRules() {
    m_impl->LoadDefaultRules();
}

bool BehaviorBlocker::AddExclusion(const BehaviorExclusion& exclusion) {
    return m_impl->AddExclusion(exclusion);
}

bool BehaviorBlocker::RemoveExclusion(const std::string& exclusionId) {
    return m_impl->RemoveExclusion(exclusionId);
}

std::vector<BlockEvent> BehaviorBlocker::GetRecentEvents(size_t limit) const {
    return m_impl->GetRecentEvents(limit);
}

std::string BehaviorBlocker::GetStatistics() const {
    return m_impl->GetStatistics();
}

bool BehaviorBlocker::SelfTest() {
    return m_impl->SelfTest();
}

} // namespace ShadowStrike::RealTime
