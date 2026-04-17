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

#include "Products/Community/PhantomEDR/ThreatHunting/ThreatHuntingTypes.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class IOCScannerImpl;

class IOCScanner final {
public:
    [[nodiscard]] static IOCScanner& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] IOCScanSummary ScanIOCs(const std::vector<IOCEntry>& iocs);
    [[nodiscard]] IOCScanSummary ScanIOCs(
        const std::vector<IOCEntry>& iocs,
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime);

    [[nodiscard]] bool AddWatchList(const std::vector<IOCEntry>& iocs);
    [[nodiscard]] bool RemoveFromWatchList(const std::string& iocValue);
    [[nodiscard]] std::vector<IOCEntry> GetWatchList();
    [[nodiscard]] IOCScanSummary ScanWatchList();

private:
    IOCScanner();
    ~IOCScanner();

    IOCScanner(const IOCScanner&) = delete;
    IOCScanner& operator=(const IOCScanner&) = delete;

    std::unique_ptr<IOCScannerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
