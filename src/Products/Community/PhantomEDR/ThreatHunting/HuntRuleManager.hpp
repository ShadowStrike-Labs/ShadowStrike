#pragma once

#include "Products/Community/PhantomEDR/ThreatHunting/ThreatHuntingTypes.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class HuntRuleManagerImpl;

class HuntRuleManager final {
public:
    [[nodiscard]] static HuntRuleManager& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool AddRule(HuntRule&& rule);
    [[nodiscard]] bool RemoveRule(const std::string& ruleId);
    [[nodiscard]] bool UpdateRuleStatus(const std::string& ruleId, RuleStatus status);
    [[nodiscard]] std::optional<HuntRule> GetRule(const std::string& ruleId);
    [[nodiscard]] std::vector<HuntRule> QueryRules(const RuleQueryParams& params);
    [[nodiscard]] uint64_t GetRuleCount();
    [[nodiscard]] bool ImportSigmaRules(const std::filesystem::path& dirOrFile);
    [[nodiscard]] bool ImportYaraRules(const std::filesystem::path& dirOrFile);
    [[nodiscard]] HuntResult EvaluateRule(const std::string& ruleId);
    [[nodiscard]] std::vector<HuntResult> EvaluateAllActive();

private:
    HuntRuleManager();
    ~HuntRuleManager();

    HuntRuleManager(const HuntRuleManager&) = delete;
    HuntRuleManager& operator=(const HuntRuleManager&) = delete;
    HuntRuleManager(HuntRuleManager&&) = delete;
    HuntRuleManager& operator=(HuntRuleManager&&) = delete;

    std::unique_ptr<HuntRuleManagerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
