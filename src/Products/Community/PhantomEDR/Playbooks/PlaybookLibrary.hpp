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
#include <vector>

#include "Products/Community/PhantomEDR/Playbooks/PlaybookTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

class PlaybookLibraryImpl;

class PlaybookLibrary final {
public:
    [[nodiscard]] static PlaybookLibrary& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] std::vector<std::string> GetPlaybookIds() const;
    [[nodiscard]] std::optional<Json> GetPlaybookDocument(std::string_view playbookId) const;
    [[nodiscard]] std::vector<Json> GetPlaybookDocuments() const;

private:
    PlaybookLibrary();
    ~PlaybookLibrary();
    PlaybookLibrary(const PlaybookLibrary&) = delete;
    PlaybookLibrary& operator=(const PlaybookLibrary&) = delete;
    PlaybookLibrary(PlaybookLibrary&&) = delete;
    PlaybookLibrary& operator=(PlaybookLibrary&&) = delete;

    std::unique_ptr<PlaybookLibraryImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
