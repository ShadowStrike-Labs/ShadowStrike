/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Sandboxing/SandboxPolicy.hpp"

#include <algorithm>
#include <filesystem>
#include <format>
#include <ranges>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[SandboxPolicy]";

[[nodiscard]] std::string ToLower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return out;
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class SandboxPolicyImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;

        if (!CreateSchema()) return false;

        LoadBuiltinRules();
        LoadCustomRulesFromDb();

        m_initialized = true;
        Logger::Info("{} Initialized with {} rules", kLogPrefix, m_rules.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        m_rules.clear();
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] bool ShouldSubmit(std::string_view filePath, std::string_view sha256,
                                    uint64_t fileSize, uint32_t detectionConfidence,
                                    int32_t reputationScore) const {
        std::shared_lock lk(m_mtx);

        // Collect and sort by priority
        std::vector<const SubmitRule*> sorted;
        sorted.reserve(m_rules.size());
        for (const auto& [_, rule] : m_rules) {
            if (rule.enabled) sorted.push_back(&rule);
        }
        std::ranges::sort(sorted, [](const auto* a, const auto* b) {
            return a->priority < b->priority;
        });

        for (const auto* rule : sorted) {
            bool matched = EvaluateRule(*rule, filePath, sha256, fileSize,
                                       detectionConfidence, reputationScore);
            if (matched) {
                m_lastMatchedRuleId = rule->ruleId;
                return true;
            }
        }

        m_lastMatchedRuleId.clear();
        return false;
    }

    [[nodiscard]] std::optional<SubmitRule> GetLastMatchedRule() const {
        std::shared_lock lk(m_mtx);
        if (m_lastMatchedRuleId.empty()) return std::nullopt;
        auto it = m_rules.find(m_lastMatchedRuleId);
        if (it == m_rules.end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] bool AddRule(const SubmitRule& rule) {
        if (rule.ruleId.empty()) return false;

        {
            std::unique_lock lk(m_mtx);
            m_rules[rule.ruleId] = rule;
        }

        PersistRule(rule);
        Logger::Info("{} Added rule '{}': {} {} {}",
                     kLogPrefix, rule.ruleId, rule.description,
                     rule.comparisonOp, rule.value);
        return true;
    }

    [[nodiscard]] bool RemoveRule(std::string_view ruleId) {
        {
            std::unique_lock lk(m_mtx);
            auto it = m_rules.find(std::string(ruleId));
            if (it == m_rules.end()) return false;
            m_rules.erase(it);
        }

        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        db.ExecuteWithParams("DELETE FROM sandbox_submit_rules WHERE rule_id = ?;",
                             &dbErr, std::string(ruleId));
        Logger::Info("{} Removed rule '{}'", kLogPrefix, ruleId);
        return true;
    }

    [[nodiscard]] bool SetRuleEnabled(std::string_view ruleId, bool enabled) {
        std::unique_lock lk(m_mtx);
        auto it = m_rules.find(std::string(ruleId));
        if (it == m_rules.end()) return false;
        it->second.enabled = enabled;

        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        db.ExecuteWithParams("UPDATE sandbox_submit_rules SET enabled = ? WHERE rule_id = ?;",
                             &dbErr, enabled ? 1 : 0, std::string(ruleId));
        return true;
    }

    [[nodiscard]] std::optional<SubmitRule> GetRule(std::string_view ruleId) const {
        std::shared_lock lk(m_mtx);
        auto it = m_rules.find(std::string(ruleId));
        if (it == m_rules.end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] std::vector<SubmitRule> GetAllRules() const {
        std::shared_lock lk(m_mtx);
        std::vector<SubmitRule> result;
        result.reserve(m_rules.size());
        for (const auto& [_, r] : m_rules) result.push_back(r);
        return result;
    }

    [[nodiscard]] uint32_t GetRuleCount() const {
        std::shared_lock lk(m_mtx);
        return static_cast<uint32_t>(m_rules.size());
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;
    std::unordered_map<std::string, SubmitRule> m_rules;
    mutable std::string m_lastMatchedRuleId;  // thread_local would be better; per-instance for simplicity

    // ========================================================================
    // RULE EVALUATION
    // ========================================================================

    [[nodiscard]] bool EvaluateRule(const SubmitRule& rule, std::string_view filePath,
                                    std::string_view /*sha256*/, uint64_t fileSize,
                                    uint32_t detectionConfidence, int32_t reputationScore) const {
        switch (rule.criteria) {
            case SubmitRuleCriteria::FileExtension: {
                auto ext = std::filesystem::path(filePath).extension().string();
                auto extLower = ToLower(ext);
                auto ruleValLower = ToLower(rule.value);

                if (rule.comparisonOp == "==" || rule.comparisonOp == "equals") {
                    return extLower == ruleValLower;
                }
                if (rule.comparisonOp == "contains" || rule.comparisonOp == "in") {
                    // value can be comma-separated: ".exe,.dll,.scr"
                    auto pos = ruleValLower.find(extLower);
                    return pos != std::string::npos;
                }
                return false;
            }

            case SubmitRuleCriteria::MimeType:
                // MIME-based matching requires content inspection;
                // for Community we do extension-based heuristic
                return false;

            case SubmitRuleCriteria::DetectionConfidence:
                return CompareNumeric(static_cast<int64_t>(detectionConfidence),
                                      rule.comparisonOp, rule.value);

            case SubmitRuleCriteria::ReputationScore:
                return CompareNumeric(static_cast<int64_t>(reputationScore),
                                      rule.comparisonOp, rule.value);

            case SubmitRuleCriteria::FileSize:
                return CompareNumeric(static_cast<int64_t>(fileSize),
                                      rule.comparisonOp, rule.value);

            case SubmitRuleCriteria::HashUnknown:
                // value == "true" means submit if hash is unknown (reputation < 0)
                if (rule.value == "true") {
                    return reputationScore < 0;
                }
                return false;
        }
        return false;
    }

    [[nodiscard]] static bool CompareNumeric(int64_t actual, std::string_view op,
                                             std::string_view threshold) {
        int64_t thr = 0;
        try { thr = std::stoll(std::string(threshold)); }
        catch (...) { return false; }

        if (op == ">=") return actual >= thr;
        if (op == "<=") return actual <= thr;
        if (op == "==") return actual == thr;
        if (op == ">")  return actual > thr;
        if (op == "<")  return actual < thr;
        if (op == "!=") return actual != thr;
        return false;
    }

    // ========================================================================
    // BUILTIN RULES
    // ========================================================================

    void LoadBuiltinRules() {
        // Rule 1: Auto-submit executables with high detection confidence
        {
            SubmitRule r;
            r.ruleId = "builtin-high-confidence-exe";
            r.description = "Submit executables with detection confidence >= 70";
            r.criteria = SubmitRuleCriteria::DetectionConfidence;
            r.comparisonOp = ">=";
            r.value = "70";
            r.priority = 10;
            r.enabled = true;
            m_rules[r.ruleId] = std::move(r);
        }

        // Rule 2: Auto-submit unknown-reputation files
        {
            SubmitRule r;
            r.ruleId = "builtin-unknown-reputation";
            r.description = "Submit files with unknown reputation (score < 0)";
            r.criteria = SubmitRuleCriteria::HashUnknown;
            r.comparisonOp = "==";
            r.value = "true";
            r.priority = 20;
            r.enabled = true;
            m_rules[r.ruleId] = std::move(r);
        }

        // Rule 3: Auto-submit suspicious file types
        {
            SubmitRule r;
            r.ruleId = "builtin-suspicious-extensions";
            r.description = "Submit files with suspicious extensions (.scr, .pif, .hta, .vbs)";
            r.criteria = SubmitRuleCriteria::FileExtension;
            r.comparisonOp = "in";
            r.value = ".scr,.pif,.hta,.vbs,.vbe,.wsf,.wsh,.ps1,.bat,.cmd";
            r.priority = 30;
            r.enabled = true;
            m_rules[r.ruleId] = std::move(r);
        }

        // Rule 4: Skip very large files (> 100MB) — they slow down sandboxing
        {
            SubmitRule r;
            r.ruleId = "builtin-skip-large-files";
            r.description = "Skip files larger than 100MB";
            r.criteria = SubmitRuleCriteria::FileSize;
            r.comparisonOp = ">";
            r.value = "104857600";
            r.priority = 1;  // Highest priority — evaluated first
            r.enabled = false; // This is a "deny" rule; callers should check negative
            m_rules[r.ruleId] = std::move(r);
        }

        // Rule 5: Auto-submit files with low reputation score
        {
            SubmitRule r;
            r.ruleId = "builtin-low-reputation";
            r.description = "Submit files with reputation score <= 30";
            r.criteria = SubmitRuleCriteria::ReputationScore;
            r.comparisonOp = "<=";
            r.value = "30";
            r.priority = 15;
            r.enabled = true;
            m_rules[r.ruleId] = std::move(r);
        }
    }

    // ========================================================================
    // DATABASE
    // ========================================================================

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        return db.Execute(
            "CREATE TABLE IF NOT EXISTS sandbox_submit_rules ("
            "  rule_id TEXT PRIMARY KEY,"
            "  description TEXT,"
            "  criteria INTEGER NOT NULL,"
            "  comparison_op TEXT NOT NULL,"
            "  value TEXT NOT NULL,"
            "  priority INTEGER DEFAULT 0,"
            "  enabled INTEGER DEFAULT 1"
            ");", &dbErr);
    }

    void LoadCustomRulesFromDb() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        auto rows = db.Query(
            "SELECT rule_id, description, criteria, comparison_op, value, priority, enabled"
            " FROM sandbox_submit_rules;", &dbErr);

        while (rows.Next()) {
            SubmitRule r;
            r.ruleId = rows.GetString(0);
            r.description = rows.GetString(1);
            r.criteria = static_cast<SubmitRuleCriteria>(rows.GetInt(2));
            r.comparisonOp = rows.GetString(3);
            r.value = rows.GetString(4);
            r.priority = rows.GetInt(5);
            r.enabled = rows.GetInt(6) != 0;
            m_rules[r.ruleId] = std::move(r);
        }
    }

    void PersistRule(const SubmitRule& r) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        db.ExecuteWithParams(
            "INSERT OR REPLACE INTO sandbox_submit_rules"
            " (rule_id, description, criteria, comparison_op, value, priority, enabled)"
            " VALUES (?,?,?,?,?,?,?);",
            &dbErr,
            r.ruleId, r.description, static_cast<int>(r.criteria),
            r.comparisonOp, r.value, r.priority, r.enabled ? 1 : 0);
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

SandboxPolicy::SandboxPolicy() : m_impl(std::make_unique<SandboxPolicyImpl>()) {}
SandboxPolicy::~SandboxPolicy() = default;

SandboxPolicy& SandboxPolicy::Instance() {
    static SandboxPolicy instance;
    return instance;
}

bool SandboxPolicy::Initialize() { return m_impl->Initialize(); }
void SandboxPolicy::Shutdown() { m_impl->Shutdown(); }
bool SandboxPolicy::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
bool SandboxPolicy::ShouldSubmit(std::string_view fp, std::string_view sha, uint64_t sz,
                                  uint32_t conf, int32_t rep) const {
    return m_impl->ShouldSubmit(fp, sha, sz, conf, rep);
}
std::optional<SubmitRule> SandboxPolicy::GetLastMatchedRule() const { return m_impl->GetLastMatchedRule(); }
bool SandboxPolicy::AddRule(const SubmitRule& r) { return m_impl->AddRule(r); }
bool SandboxPolicy::RemoveRule(std::string_view id) { return m_impl->RemoveRule(id); }
bool SandboxPolicy::SetRuleEnabled(std::string_view id, bool en) { return m_impl->SetRuleEnabled(id, en); }
std::optional<SubmitRule> SandboxPolicy::GetRule(std::string_view id) const { return m_impl->GetRule(id); }
std::vector<SubmitRule> SandboxPolicy::GetAllRules() const { return m_impl->GetAllRules(); }
uint32_t SandboxPolicy::GetRuleCount() const { return m_impl->GetRuleCount(); }

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
