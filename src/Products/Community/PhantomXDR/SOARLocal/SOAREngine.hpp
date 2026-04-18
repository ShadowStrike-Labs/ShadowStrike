/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file SOAREngine.hpp
/// @brief Local SOAR execution engine for XDR-triggered response playbooks.

#include "Products/Community/PhantomXDR/SOARLocal/SOARTypes.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/XDRTypes.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOARPlaybooks.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::SOARLocal {

struct SOARStatistics {
    uint64_t totalExecuted{0};
    uint64_t totalSucceeded{0};
    uint64_t totalFailed{0};
};

class SOAREngineImpl;

class SOAREngine final {
public:
    [[nodiscard]] static SOAREngine& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::vector<std::string> HandleCorrelationMatch(
        const ShadowStrike::Products::PhantomXDR::XDRCorrelation::CorrelationMatch& match,
        const std::vector<ShadowStrike::Products::PhantomXDR::XDRCorrelation::XDREvent>& events);

    [[nodiscard]] std::optional<std::string> ExecutePlaybook(
        std::string_view playbookId,
        std::string_view triggerId);

    [[nodiscard]] std::vector<PlaybookExecution> GetExecutionHistory(uint32_t limit) const;
    [[nodiscard]] std::optional<PlaybookExecution> GetExecutionById(std::string_view executionId) const;
    [[nodiscard]] SOARStatistics GetStatistics() const;

private:
    SOAREngine();
    ~SOAREngine();
    SOAREngine(const SOAREngine&) = delete;
    SOAREngine& operator=(const SOAREngine&) = delete;

    std::unique_ptr<SOAREngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::SOARLocal
