/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Sandboxing/SandboxAnalyzer.hpp"

#include <algorithm>
#include <format>
#include <ranges>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[SandboxAnalyzer]";

// ============================================================================
// BEHAVIOR TAG DETECTION RULES
// ============================================================================

struct BehaviorRule {
    BehaviorTag tag;
    uint32_t    scoreWeight;
    std::string mitreTechnique;
};

// Static mapping of behavior tags to scores and MITRE techniques
[[nodiscard]] const std::vector<BehaviorRule>& GetBehaviorRules() {
    static const std::vector<BehaviorRule> rules = {
        { BehaviorTag::DropsExecutable,    20, "T1105" },  // Ingress Tool Transfer
        { BehaviorTag::ModifiesRegistry,   10, "T1112" },  // Modify Registry
        { BehaviorTag::ContactsC2,         40, "T1071" },  // Application Layer Protocol
        { BehaviorTag::InjectsProcess,     35, "T1055" },  // Process Injection
        { BehaviorTag::CreatesService,     15, "T1543.003" }, // Windows Service
        { BehaviorTag::EscalatesPrivilege, 30, "T1548" },  // Abuse Elevation Control
        { BehaviorTag::DeletesSelf,        10, "T1070.004" }, // File Deletion
        { BehaviorTag::EncryptsFiles,      45, "T1486" },  // Data Encrypted for Impact
        { BehaviorTag::ExfiltratesData,    35, "T1041" },  // Exfiltration Over C2
        { BehaviorTag::DisablesSecurity,   30, "T1562.001" }, // Disable or Modify Tools
        { BehaviorTag::EvadesSandbox,      25, "T1497" },  // Virtualization/Sandbox Evasion
        { BehaviorTag::SpawnsCmdShell,     15, "T1059.003" }, // Windows Command Shell
        { BehaviorTag::ModifiesBootRecord, 50, "T1542" },  // Pre-OS Boot
        { BehaviorTag::UsesReflection,     20, "T1620" },  // Reflective Code Loading
        { BehaviorTag::StealsCredentials,  40, "T1003" },  // OS Credential Dumping
    };
    return rules;
}

// ============================================================================
// EVASION DETECTION PATTERNS
// ============================================================================

[[nodiscard]] bool DetectSandboxEvasion(const DetonationResult& raw) {
    // Short execution duration with no activity = likely evasion
    if (raw.durationMs < 2000 &&
        raw.droppedFiles.empty() &&
        raw.networkIOCs.empty() &&
        raw.registryChanges.empty() &&
        raw.processActivity.size() <= 1) {
        return true;
    }

    // Check for known evasion patterns in process activity
    for (const auto& proc : raw.processActivity) {
        auto cmdLower = proc.commandLine;
        std::ranges::transform(cmdLower, cmdLower.begin(), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });

        // Common sandbox detection commands
        if (cmdLower.find("systeminfo") != std::string::npos ||
            cmdLower.find("wmic") != std::string::npos ||
            cmdLower.find("vboxservice") != std::string::npos ||
            cmdLower.find("vmtoolsd") != std::string::npos ||
            cmdLower.find("sbiedll") != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// PROCESS TREE ANALYSIS
// ============================================================================

[[nodiscard]] std::vector<BehaviorTag> AnalyzeProcessTree(const DetonationResult& raw) {
    std::vector<BehaviorTag> tags;
    std::unordered_set<uint8_t> seen;

    auto addTag = [&](BehaviorTag t) {
        auto val = static_cast<uint8_t>(t);
        if (!seen.contains(val)) {
            seen.insert(val);
            tags.push_back(t);
        }
    };

    for (const auto& proc : raw.processActivity) {
        if (proc.isInjected) addTag(BehaviorTag::InjectsProcess);
        if (proc.isElevated) addTag(BehaviorTag::EscalatesPrivilege);

        auto cmdLower = proc.commandLine;
        std::ranges::transform(cmdLower, cmdLower.begin(), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });

        if (cmdLower.find("cmd.exe") != std::string::npos ||
            cmdLower.find("powershell") != std::string::npos) {
            addTag(BehaviorTag::SpawnsCmdShell);
        }

        if (cmdLower.find("sc create") != std::string::npos ||
            cmdLower.find("sc config") != std::string::npos) {
            addTag(BehaviorTag::CreatesService);
        }

        if (cmdLower.find("reg add") != std::string::npos ||
            cmdLower.find("reg delete") != std::string::npos) {
            addTag(BehaviorTag::ModifiesRegistry);
        }

        if (cmdLower.find("lsass") != std::string::npos ||
            cmdLower.find("mimikatz") != std::string::npos ||
            cmdLower.find("sekurlsa") != std::string::npos) {
            addTag(BehaviorTag::StealsCredentials);
        }

        // Check for self-deletion patterns
        if (cmdLower.find("del /f") != std::string::npos &&
            cmdLower.find(proc.imagePath) != std::string::npos) {
            addTag(BehaviorTag::DeletesSelf);
        }
    }

    return tags;
}

// ============================================================================
// NETWORK IOC ANALYSIS
// ============================================================================

[[nodiscard]] std::vector<BehaviorTag> AnalyzeNetworkActivity(const DetonationResult& raw) {
    std::vector<BehaviorTag> tags;

    for (const auto& ioc : raw.networkIOCs) {
        if (ioc.isC2) {
            tags.push_back(BehaviorTag::ContactsC2);
            break;
        }
    }

    // Check for data exfiltration patterns: many outbound connections or large payload hints
    uint32_t outboundCount = 0;
    for (const auto& ioc : raw.networkIOCs) {
        if (!ioc.isDNS && ioc.port != 0) ++outboundCount;
    }
    if (outboundCount >= 10) {
        tags.push_back(BehaviorTag::ExfiltratesData);
    }

    return tags;
}

// ============================================================================
// REGISTRY ANALYSIS
// ============================================================================

[[nodiscard]] std::vector<BehaviorTag> AnalyzeRegistryChanges(const DetonationResult& raw) {
    std::vector<BehaviorTag> tags;

    for (const auto& change : raw.registryChanges) {
        auto keyLower = change.key;
        std::ranges::transform(keyLower, keyLower.begin(), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });

        tags.push_back(BehaviorTag::ModifiesRegistry);

        // Persistence mechanisms
        if (keyLower.find("run") != std::string::npos &&
            keyLower.find("currentversion") != std::string::npos) {
            tags.push_back(BehaviorTag::ModifiesRegistry);
        }

        // Security tool disabling
        if (keyLower.find("disableantispy") != std::string::npos ||
            keyLower.find("disablerealtimemonitoring") != std::string::npos ||
            keyLower.find("disablebehaviormonitoring") != std::string::npos) {
            tags.push_back(BehaviorTag::DisablesSecurity);
        }

        break; // One registry tag is enough
    }

    return tags;
}

// ============================================================================
// FILESYSTEM ANALYSIS
// ============================================================================

[[nodiscard]] std::vector<BehaviorTag> AnalyzeDroppedFiles(const DetonationResult& raw) {
    std::vector<BehaviorTag> tags;

    bool hasExecutable = false;
    for (const auto& df : raw.droppedFiles) {
        if (df.isExecutable) {
            hasExecutable = true;
            break;
        }
    }
    if (hasExecutable) {
        tags.push_back(BehaviorTag::DropsExecutable);
    }

    return tags;
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class SandboxAnalyzerImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;

        if (!CreateSchema()) return false;

        m_initialized = true;
        Logger::Info("{} Initialized", kLogPrefix);
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] DetonationResult Analyze(DetonationResult raw) const {
        // Merge behavior tags from all analysis phases
        std::unordered_set<uint8_t> seenTags;
        auto mergeTags = [&](const std::vector<BehaviorTag>& newTags) {
            for (auto t : newTags) {
                auto val = static_cast<uint8_t>(t);
                if (!seenTags.contains(val)) {
                    seenTags.insert(val);
                    raw.behaviorTags.push_back(t);
                }
            }
        };

        // Also preserve any existing tags from the detonation engine
        for (auto t : raw.behaviorTags) {
            seenTags.insert(static_cast<uint8_t>(t));
        }

        // Run analysis pipelines
        mergeTags(AnalyzeProcessTree(raw));
        mergeTags(AnalyzeNetworkActivity(raw));
        mergeTags(AnalyzeRegistryChanges(raw));
        mergeTags(AnalyzeDroppedFiles(raw));

        // Check for sandbox evasion
        if (DetectSandboxEvasion(raw)) {
            auto val = static_cast<uint8_t>(BehaviorTag::EvadesSandbox);
            if (!seenTags.contains(val)) {
                raw.behaviorTags.push_back(BehaviorTag::EvadesSandbox);
            }
        }

        // Score calculation
        uint32_t score = 0;
        const auto& rules = GetBehaviorRules();
        std::vector<std::string> mitreIds;

        for (auto tag : raw.behaviorTags) {
            for (const auto& rule : rules) {
                if (rule.tag == tag) {
                    score += rule.scoreWeight;
                    mitreIds.push_back(rule.mitreTechnique);
                    break;
                }
            }
        }

        raw.threatScore = std::min(score, 100u);
        raw.mitreAttackIds = std::move(mitreIds);

        // Final verdict
        if (raw.status == DetonationStatus::TimedOut) {
            raw.verdict = SandboxVerdict::Timeout;
        } else if (raw.status == DetonationStatus::Failed) {
            raw.verdict = SandboxVerdict::Error;
        } else if (raw.threatScore >= 70) {
            raw.verdict = SandboxVerdict::Malicious;
        } else if (raw.threatScore >= 40) {
            raw.verdict = SandboxVerdict::Suspicious;
        } else if (raw.threatScore >= 15) {
            raw.verdict = SandboxVerdict::Evasive;
        } else {
            raw.verdict = SandboxVerdict::Clean;
        }

        // Persist
        PersistAnalysis(raw);

        // Cache
        {
            std::unique_lock lk(m_mtx);
            m_cache[raw.submissionId] = raw;
        }

        Logger::Info("{} Analysis complete: {} verdict={} score={} tags={} mitre={}",
                     kLogPrefix, raw.submissionId, ToString(raw.verdict),
                     raw.threatScore, raw.behaviorTags.size(), raw.mitreAttackIds.size());
        return raw;
    }

    [[nodiscard]] std::optional<DetonationResult> GetAnalysis(std::string_view submissionId) const {
        std::shared_lock lk(m_mtx);
        auto it = m_cache.find(std::string(submissionId));
        if (it != m_cache.end()) return it->second;
        return LoadFromDb(submissionId);
    }

    [[nodiscard]] std::vector<DetonationResult> GetAnalysesByHash(std::string_view sha256) const {
        std::shared_lock lk(m_mtx);
        std::vector<DetonationResult> results;
        for (const auto& [_, r] : m_cache) {
            if (r.sha256 == sha256) results.push_back(r);
        }
        return results;
    }

    [[nodiscard]] std::vector<DetonationResult> GetRecentAnalyses(uint32_t maxResults) const {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        auto rows = db.QueryWithParams(
            "SELECT submission_id, file_path, sha256, verdict, threat_score, submitted_at"
            " FROM sandbox_analyses ORDER BY submitted_at DESC LIMIT ?;",
            &dbErr, static_cast<int64_t>(maxResults));

        std::vector<DetonationResult> results;
        while (rows.Next()) {
            DetonationResult r;
            r.submissionId = rows.GetString(0);
            r.filePath = rows.GetString(1);
            r.sha256 = rows.GetString(2);
            r.verdict = static_cast<SandboxVerdict>(rows.GetInt(3));
            r.threatScore = static_cast<uint32_t>(rows.GetInt(4));
            r.submittedAt = Clock::time_point(std::chrono::duration_cast<Clock::duration>(
                std::chrono::milliseconds(rows.GetInt64(5))));
            results.push_back(std::move(r));
        }
        return results;
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;
    mutable std::unordered_map<std::string, DetonationResult> m_cache;

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        return db.Execute(
            "CREATE TABLE IF NOT EXISTS sandbox_analyses ("
            "  submission_id TEXT PRIMARY KEY,"
            "  file_path TEXT NOT NULL,"
            "  sha256 TEXT,"
            "  verdict INTEGER,"
            "  threat_score INTEGER,"
            "  behavior_tags TEXT,"
            "  mitre_ids TEXT,"
            "  submitted_at INTEGER NOT NULL,"
            "  analyzed_at INTEGER NOT NULL"
            ");", &dbErr);
    }

    void PersistAnalysis(const DetonationResult& r) const {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;

        std::string tags;
        for (size_t i = 0; i < r.behaviorTags.size(); ++i) {
            if (i > 0) tags += ',';
            tags += ToString(r.behaviorTags[i]);
        }
        std::string mitreIds;
        for (size_t i = 0; i < r.mitreAttackIds.size(); ++i) {
            if (i > 0) mitreIds += ',';
            mitreIds += r.mitreAttackIds[i];
        }

        auto submittedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            r.submittedAt.time_since_epoch()).count();
        auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count();

        db.ExecuteWithParams(
            "INSERT OR REPLACE INTO sandbox_analyses"
            " (submission_id, file_path, sha256, verdict, threat_score,"
            "  behavior_tags, mitre_ids, submitted_at, analyzed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?);",
            &dbErr,
            r.submissionId, r.filePath, r.sha256,
            static_cast<int>(r.verdict), static_cast<int>(r.threatScore),
            tags, mitreIds, submittedMs, nowMs);
    }

    [[nodiscard]] std::optional<DetonationResult> LoadFromDb(std::string_view submissionId) const {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        auto rows = db.QueryWithParams(
            "SELECT submission_id, file_path, sha256, verdict, threat_score, submitted_at"
            " FROM sandbox_analyses WHERE submission_id = ?;",
            &dbErr, std::string(submissionId));

        if (!rows.Next()) return std::nullopt;

        DetonationResult r;
        r.submissionId = rows.GetString(0);
        r.filePath = rows.GetString(1);
        r.sha256 = rows.GetString(2);
        r.verdict = static_cast<SandboxVerdict>(rows.GetInt(3));
        r.threatScore = static_cast<uint32_t>(rows.GetInt(4));
        r.submittedAt = Clock::time_point(std::chrono::duration_cast<Clock::duration>(
            std::chrono::milliseconds(rows.GetInt64(5))));
        return r;
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

SandboxAnalyzer::SandboxAnalyzer() : m_impl(std::make_unique<SandboxAnalyzerImpl>()) {}
SandboxAnalyzer::~SandboxAnalyzer() = default;

SandboxAnalyzer& SandboxAnalyzer::Instance() {
    static SandboxAnalyzer instance;
    return instance;
}

bool SandboxAnalyzer::Initialize() { return m_impl->Initialize(); }
void SandboxAnalyzer::Shutdown() { m_impl->Shutdown(); }
bool SandboxAnalyzer::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
DetonationResult SandboxAnalyzer::Analyze(DetonationResult raw) const { return m_impl->Analyze(std::move(raw)); }
std::optional<DetonationResult> SandboxAnalyzer::GetAnalysis(std::string_view id) const { return m_impl->GetAnalysis(id); }
std::vector<DetonationResult> SandboxAnalyzer::GetAnalysesByHash(std::string_view sha256) const { return m_impl->GetAnalysesByHash(sha256); }
std::vector<DetonationResult> SandboxAnalyzer::GetRecentAnalyses(uint32_t max) const { return m_impl->GetRecentAnalyses(max); }

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
