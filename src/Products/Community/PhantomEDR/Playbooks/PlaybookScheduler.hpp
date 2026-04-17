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
#include <string_view>
#include <vector>

#include "Products/Community/PhantomEDR/Playbooks/PlaybookTypes.hpp"

namespace ShadowStrike::Communication {
struct Alert;
}

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

class PlaybookSchedulerImpl;

class PlaybookScheduler final {
public:
    [[nodiscard]] static PlaybookScheduler& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] bool Start();
    void Stop();
    [[nodiscard]] bool RegisterJob(const PlaybookJobRecord& job);
    [[nodiscard]] bool RemoveJob(std::string_view jobId);
    [[nodiscard]] bool SetJobEnabled(std::string_view jobId, bool enabled);
    [[nodiscard]] std::optional<PlaybookJobRecord> GetJob(std::string_view jobId) const;
    [[nodiscard]] std::vector<PlaybookJobRecord> GetJobs() const;
    [[nodiscard]] std::optional<PlaybookRunRecord> RunPlaybookNow(
        std::string_view playbookId,
        const Json& context = Json::object());
    void OnAlert(const ShadowStrike::Communication::Alert& alert);
    [[nodiscard]] std::vector<PlaybookRunRecord> GetJobHistory(
        std::string_view playbookId,
        uint32_t maxRecords = 50) const;

private:
    PlaybookScheduler();
    ~PlaybookScheduler();
    PlaybookScheduler(const PlaybookScheduler&) = delete;
    PlaybookScheduler& operator=(const PlaybookScheduler&) = delete;
    PlaybookScheduler(PlaybookScheduler&&) = delete;
    PlaybookScheduler& operator=(PlaybookScheduler&&) = delete;

    std::unique_ptr<PlaybookSchedulerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
