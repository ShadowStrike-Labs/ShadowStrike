/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file SOARPlaybooks.hpp
/// @brief Thread-safe playbook manager for local SOAR automation.

#include "Products/Community/PhantomXDR/SOARLocal/SOARTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::SOARLocal {

class SOARPlaybooksImpl;

class SOARPlaybooks final {
public:
    [[nodiscard]] static SOARPlaybooks& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool                     AddPlaybook(const Playbook& playbook);
    [[nodiscard]] bool                     RemovePlaybook(std::string_view playbookId);
    [[nodiscard]] bool                     UpdatePlaybook(const Playbook& playbook);
    [[nodiscard]] std::optional<Playbook>  GetPlaybook(std::string_view playbookId) const;
    [[nodiscard]] std::vector<Playbook>    GetActivePlaybooks() const;
    [[nodiscard]] std::vector<Playbook>    GetAllPlaybooks() const;
    [[nodiscard]] uint32_t                 GetPlaybookCount() const;
    [[nodiscard]] bool                     InstallDefaultPlaybooks();

private:
    SOARPlaybooks();
    ~SOARPlaybooks();
    SOARPlaybooks(const SOARPlaybooks&) = delete;
    SOARPlaybooks& operator=(const SOARPlaybooks&) = delete;

    std::unique_ptr<SOARPlaybooksImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::SOARLocal
