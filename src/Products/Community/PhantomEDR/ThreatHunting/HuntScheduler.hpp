#pragma once

#include "Products/Community/PhantomEDR/ThreatHunting/ThreatHuntingTypes.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class HuntSchedulerImpl;

class HuntScheduler final {
public:
    [[nodiscard]] static HuntScheduler& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool ScheduleHunt(ScheduledHunt&& schedule);
    [[nodiscard]] bool CancelSchedule(const std::string& scheduleId);
    [[nodiscard]] bool PauseSchedule(const std::string& scheduleId);
    [[nodiscard]] bool ResumeSchedule(const std::string& scheduleId);
    [[nodiscard]] std::optional<ScheduledHunt> GetSchedule(const std::string& scheduleId);
    [[nodiscard]] std::vector<ScheduledHunt> GetAllSchedules();
    [[nodiscard]] std::vector<HuntJobRecord> GetJobHistory(const std::string& scheduleId, uint32_t maxRecords = 50);
    [[nodiscard]] std::optional<HuntJobRecord> GetLatestJob(const std::string& scheduleId);
    void Start();
    void Stop();

private:
    HuntScheduler();
    ~HuntScheduler();

    HuntScheduler(const HuntScheduler&) = delete;
    HuntScheduler& operator=(const HuntScheduler&) = delete;
    HuntScheduler(HuntScheduler&&) = delete;
    HuntScheduler& operator=(HuntScheduler&&) = delete;

    std::unique_ptr<HuntSchedulerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
