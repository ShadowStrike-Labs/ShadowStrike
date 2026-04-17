/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Products/Community/PhantomEDR/Playbooks/PlaybookTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

class PlaybookEngineImpl;

class PlaybookEngine final {
public:
    [[nodiscard]] static PlaybookEngine& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] bool LoadPlaybookFromJson(std::string_view playbookJson, std::string* registeredId = nullptr);
    [[nodiscard]] bool LoadPlaybookFromFile(std::wstring_view path, std::string* registeredId = nullptr);
    [[nodiscard]] bool RegisterPlaybook(const PlaybookDefinition& playbook, bool builtIn = false);
    [[nodiscard]] std::optional<PlaybookDefinition> GetPlaybook(std::string_view playbookId) const;
    [[nodiscard]] std::vector<PlaybookDefinition> ListPlaybooks() const;
    [[nodiscard]] std::optional<PlaybookRunRecord> ExecutePlaybook(
        std::string_view playbookId,
        const Json& context = Json::object(),
        PlaybookTriggerType trigger = PlaybookTriggerType::OnDemand,
        std::string_view triggerReference = {});
    [[nodiscard]] std::optional<PlaybookRunRecord> GetRun(std::string_view runId) const;
    [[nodiscard]] std::vector<PlaybookRunRecord> GetRunHistory(
        std::string_view playbookId,
        uint32_t maxRecords = 50) const;

private:
    PlaybookEngine();
    ~PlaybookEngine();
    PlaybookEngine(const PlaybookEngine&) = delete;
    PlaybookEngine& operator=(const PlaybookEngine&) = delete;
    PlaybookEngine(PlaybookEngine&&) = delete;
    PlaybookEngine& operator=(PlaybookEngine&&) = delete;

    std::unique_ptr<PlaybookEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
