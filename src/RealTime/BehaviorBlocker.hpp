#pragma once

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <span>
#include <cstdint>
#include <filesystem>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike::RealTime {

/**
 * @brief Categorization of observed system behaviors
 */
enum class BehaviorType {
    Unknown,
    FileModification,       // Rename, Delete, Write
    NetworkConnection,      // Connect, Listen
    ProcessInjection,       // Remote thread, APC injection
    RegistryModification,   // ASEP changes
    DriverLoading,          // Loading kernel drivers
    ShadowCopyDeletion,     // vssadmin usage
    RansomwareActivity,     // High entropy writes, known extensions
    PrivilegeEscalation,    // Token manipulation
    DefenseEvasion          // Disabling AV, killing logs
};

/**
 * @brief Risk assessment level
 */
enum class RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical
};

/**
 * @brief Action to take upon matching a rule
 */
enum class BlockAction {
    Allow,              // Allow execution
    LogOnly,            // Allow but log
    BlockOperation,     // Deny specific operation (e.g., prevent file write)
    SuspendProcess,     // Suspend process threads
    TerminateProcess,   // Kill process tree
    QuarantineFile      // Move executable to quarantine
};

/**
 * @brief Input: Context about the observed behavior
 */
struct ProcessBehavior {
    uint32_t processId;
    std::string processPath;
    std::string commandLine;
    BehaviorType type;
    std::string target; // File path, IP, Registry key, Process Name
    RiskLevel risk;

    // Serialization for logging
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Output: Record of an action taken
 */
struct BlockEvent {
    int64_t timestamp;
    uint32_t processId;
    std::string processPath;
    BehaviorType behaviorType;
    BlockAction actionTaken;
    std::string ruleId;
    std::string details;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration: Rule for matching behaviors
 */
struct BehaviorRule {
    std::string ruleId;
    std::string description;
    BehaviorType targetType;
    std::string targetPattern; // Regex
    RiskLevel minRiskLevel;
    BlockAction action;
};

class BehaviorBlockerImpl;

/**
 * @brief Real-time Behavior Blocking Engine
 *
 * Analyzes process behaviors against a set of rules and enforces blocking actions.
 * Implemented as a thread-safe Singleton with PIMPL idiom.
 */
class BehaviorBlocker final {
public:
    /**
     * @brief Singleton access
     * @return Reference to the single instance
     */
    [[nodiscard]] static BehaviorBlocker& Instance() noexcept;

    // Delete copy/move semantics
    BehaviorBlocker(const BehaviorBlocker&) = delete;
    BehaviorBlocker& operator=(const BehaviorBlocker&) = delete;
    BehaviorBlocker(BehaviorBlocker&&) = delete;
    BehaviorBlocker& operator=(BehaviorBlocker&&) = delete;

    /**
     * @brief Analyzes a specific behavior and determines the action.
     * This is the hot path called by sensors.
     *
     * @param behavior Context of the event
     * @return Action to be enforced by the sensor
     */
    [[nodiscard]] BlockAction AnalyzeBehavior(const ProcessBehavior& behavior);

    /**
     * @brief Manually blocks a process (e.g. from UI or other module)
     */
    [[nodiscard]] bool BlockProcess(uint32_t pid, const std::string& reason);

    /**
     * @brief Terminates a process immediately
     */
    [[nodiscard]] bool TerminateProcess(uint32_t pid);

    /**
     * @brief Checks if a process is currently in the blocked list
     */
    [[nodiscard]] bool IsBlocked(uint32_t pid) const;

    // -- Configuration --

    [[nodiscard]] bool AddRule(const BehaviorRule& rule);
    [[nodiscard]] bool RemoveRule(const std::string& ruleId);
    void ClearRules();
    void LoadDefaultRules();

    // -- Monitoring & Stats --

    /**
     * @brief Retrieve recent block events (thread-safe copy)
     */
    [[nodiscard]] std::vector<BlockEvent> GetRecentEvents(size_t limit = 100) const;

    /**
     * @brief Get internal statistics as JSON
     */
    [[nodiscard]] std::string GetStatistics() const;

    /**
     * @brief Verify module integrity
     */
    [[nodiscard]] bool SelfTest();

private:
    BehaviorBlocker();
    ~BehaviorBlocker();

    std::unique_ptr<BehaviorBlockerImpl> m_impl;
};

} // namespace ShadowStrike::RealTime
