/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

using Clock = std::chrono::system_clock;

// ============================================================================
// ENUMERATIONS
// ============================================================================

enum class SandboxVerdict : uint8_t {
    Clean       = 0,
    Suspicious  = 1,
    Malicious   = 2,
    Evasive     = 3,
    Error       = 4,
    Timeout     = 5,
    Pending     = 6
};

enum class DetonationStatus : uint8_t {
    Queued      = 0,
    Running     = 1,
    Completed   = 2,
    Failed      = 3,
    TimedOut    = 4,
    Cancelled   = 5
};

enum class SubmitTrigger : uint8_t {
    Manual      = 0,
    AutoPolicy  = 1,
    ScanEngine  = 2,
    Playbook    = 3
};

enum class BehaviorTag : uint8_t {
    None                = 0,
    DropsExecutable     = 1,
    ModifiesRegistry    = 2,
    ContactsC2          = 3,
    InjectsProcess      = 4,
    CreatesService      = 5,
    EscalatesPrivilege  = 6,
    DeletesSelf         = 7,
    EncryptsFiles       = 8,
    ExfiltratesData     = 9,
    DisablesSecurity    = 10,
    EvadesSandbox       = 11,
    SpawnsCmdShell      = 12,
    ModifiesBootRecord  = 13,
    UsesReflection      = 14,
    StealsCredentials   = 15
};

enum class SubmitRuleCriteria : uint8_t {
    FileExtension       = 0,
    MimeType            = 1,
    DetectionConfidence = 2,
    ReputationScore     = 3,
    FileSize            = 4,
    HashUnknown         = 5
};

// ============================================================================
// TOSTRING HELPERS
// ============================================================================

[[nodiscard]] constexpr std::string_view ToString(SandboxVerdict v) noexcept {
    switch (v) {
        case SandboxVerdict::Clean:      return "Clean";
        case SandboxVerdict::Suspicious: return "Suspicious";
        case SandboxVerdict::Malicious:  return "Malicious";
        case SandboxVerdict::Evasive:    return "Evasive";
        case SandboxVerdict::Error:      return "Error";
        case SandboxVerdict::Timeout:    return "Timeout";
        case SandboxVerdict::Pending:    return "Pending";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(DetonationStatus s) noexcept {
    switch (s) {
        case DetonationStatus::Queued:    return "Queued";
        case DetonationStatus::Running:   return "Running";
        case DetonationStatus::Completed: return "Completed";
        case DetonationStatus::Failed:    return "Failed";
        case DetonationStatus::TimedOut:  return "TimedOut";
        case DetonationStatus::Cancelled: return "Cancelled";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(BehaviorTag t) noexcept {
    switch (t) {
        case BehaviorTag::None:               return "None";
        case BehaviorTag::DropsExecutable:    return "DropsExecutable";
        case BehaviorTag::ModifiesRegistry:   return "ModifiesRegistry";
        case BehaviorTag::ContactsC2:         return "ContactsC2";
        case BehaviorTag::InjectsProcess:     return "InjectsProcess";
        case BehaviorTag::CreatesService:     return "CreatesService";
        case BehaviorTag::EscalatesPrivilege: return "EscalatesPrivilege";
        case BehaviorTag::DeletesSelf:        return "DeletesSelf";
        case BehaviorTag::EncryptsFiles:      return "EncryptsFiles";
        case BehaviorTag::ExfiltratesData:    return "ExfiltratesData";
        case BehaviorTag::DisablesSecurity:   return "DisablesSecurity";
        case BehaviorTag::EvadesSandbox:      return "EvadesSandbox";
        case BehaviorTag::SpawnsCmdShell:     return "SpawnsCmdShell";
        case BehaviorTag::ModifiesBootRecord: return "ModifiesBootRecord";
        case BehaviorTag::UsesReflection:     return "UsesReflection";
        case BehaviorTag::StealsCredentials:  return "StealsCredentials";
    }
    return "Unknown";
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct DroppedFile {
    std::string path;
    std::string sha256;
    uint64_t    size = 0;
    bool        isExecutable = false;
};

struct NetworkIOC {
    std::string ip;
    uint16_t    port = 0;
    std::string domain;
    std::string protocol;
    std::string url;
    bool        isDNS = false;
    bool        isC2 = false;
};

struct RegistryChange {
    std::string hive;
    std::string key;
    std::string value;
    std::string data;
    std::string operation;   // "Create", "Set", "Delete"
};

struct ProcessActivity {
    uint32_t    pid = 0;
    uint32_t    parentPid = 0;
    std::string imagePath;
    std::string commandLine;
    bool        isInjected = false;
    bool        isElevated = false;
};

struct DetonationResult {
    std::string                 submissionId;
    std::string                 filePath;
    std::string                 sha256;
    uint64_t                    fileSize = 0;
    SandboxVerdict              verdict = SandboxVerdict::Pending;
    DetonationStatus            status = DetonationStatus::Queued;
    SubmitTrigger               trigger = SubmitTrigger::Manual;
    uint32_t                    threatScore = 0;    // 0-100
    Clock::time_point           submittedAt;
    Clock::time_point           completedAt;
    uint32_t                    durationMs = 0;

    std::vector<BehaviorTag>    behaviorTags;
    std::vector<DroppedFile>    droppedFiles;
    std::vector<NetworkIOC>     networkIOCs;
    std::vector<RegistryChange> registryChanges;
    std::vector<ProcessActivity> processActivity;
    std::vector<std::string>    mitreAttackIds;

    std::string                 errorDetail;
};

struct SubmitRule {
    std::string         ruleId;
    std::string         description;
    SubmitRuleCriteria  criteria = SubmitRuleCriteria::FileExtension;
    std::string         value;          // e.g. ".exe", ">=70", "unknown"
    std::string         comparisonOp;   // "==", ">=", "<=", "contains"
    bool                enabled = true;
    int32_t             priority = 0;   // lower = higher priority
};

struct SandboxSubmission {
    std::string         filePath;
    std::string         sha256;
    uint64_t            fileSize = 0;
    SubmitTrigger       trigger = SubmitTrigger::Manual;
    uint32_t            timeoutSeconds = 120;
    std::string         matchedRuleId;
};

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
