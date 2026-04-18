/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once

#include "Products/Community/PhantomXDR/IdentityProtection/IdentityTypes.hpp"

#include <memory>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

class CredentialProtectionImpl;

class CredentialProtection final {
public:
    [[nodiscard]] static CredentialProtection& Instance();

    [[nodiscard]] bool Initialize(const std::wstring& databasePath = L"", bool deployHoneypot = true);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::vector<IdentityAlert> MonitorLSASS();
    [[nodiscard]] std::vector<IdentityAlert> DetectCredentialAccess();
    [[nodiscard]] std::vector<IdentityAlert> GetCredentialAlerts(size_t limit = 100) const;
    [[nodiscard]] bool IsLSASSProtected() const;
    [[nodiscard]] CredentialProtectionStatistics GetStatistics() const;

private:
    CredentialProtection();
    ~CredentialProtection();

    CredentialProtection(const CredentialProtection&) = delete;
    CredentialProtection& operator=(const CredentialProtection&) = delete;
    CredentialProtection(CredentialProtection&&) = delete;
    CredentialProtection& operator=(CredentialProtection&&) = delete;

    std::unique_ptr<CredentialProtectionImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
