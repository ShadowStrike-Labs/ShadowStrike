/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

#include "Products/Community/PhantomXDR/AIAssistant/AssistantTypes.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

class SOCAssistantImpl;

class SOCAssistant final {
public:
    [[nodiscard]] static SOCAssistant& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] AssistantResponse      Ask(const AssistantContext& ctx, std::string_view question);
    [[nodiscard]] std::string            GetThreatBrief() const;
    [[nodiscard]] std::vector<std::string> GetRecommendations(std::string_view storylineId) const;
    [[nodiscard]] std::string            StartSession();
    void                                 EndSession(std::string_view sessionId);

private:
    SOCAssistant();
    ~SOCAssistant();
    SOCAssistant(const SOCAssistant&) = delete;
    SOCAssistant& operator=(const SOCAssistant&) = delete;

    std::unique_ptr<SOCAssistantImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant
