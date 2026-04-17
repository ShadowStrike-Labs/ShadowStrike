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

#include "Products/Community/PhantomEDR/Playbooks/PlaybookTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

class PlaybookActionImpl;

class PlaybookAction final {
public:
    [[nodiscard]] static PlaybookAction& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] ActionResult ExecuteAction(
        PlaybookActionType action,
        const Json& parameters,
        Json& context,
        std::string_view runId = {});

private:
    PlaybookAction();
    ~PlaybookAction();
    PlaybookAction(const PlaybookAction&) = delete;
    PlaybookAction& operator=(const PlaybookAction&) = delete;
    PlaybookAction(PlaybookAction&&) = delete;
    PlaybookAction& operator=(PlaybookAction&&) = delete;

    std::unique_ptr<PlaybookActionImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
