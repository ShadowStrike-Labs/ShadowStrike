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

#include "Products/Community/PhantomEDR/LiveResponse/LiveResponseTypes.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class ProcessInspectorImpl;

class ProcessInspector final {
public:
    [[nodiscard]] static ProcessInspector& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    struct ProcessTreeNode {
        ProcessSnapshot process;
        uint32_t depth = 0;
        std::vector<uint32_t> childPids;
    };

    [[nodiscard]] std::vector<ProcessTreeNode> GetProcessTree();
    [[nodiscard]] std::optional<ProcessSnapshot> InspectProcess(uint32_t pid);

    struct SuspiciousProcessInfo {
        ProcessSnapshot process;
        std::vector<std::string> reasons;
        uint32_t riskScore = 0;
    };

    [[nodiscard]] std::vector<SuspiciousProcessInfo> GetSuspiciousProcesses();
    [[nodiscard]] std::vector<ProcessSnapshot> TakeSnapshot();

    struct ProcessDiff {
        std::vector<uint32_t> newProcesses;
        std::vector<uint32_t> terminatedProcesses;
        std::vector<uint32_t> modifiedProcesses;
    };

    [[nodiscard]] ProcessDiff CompareSnapshots(
        const std::vector<ProcessSnapshot>& before,
        const std::vector<ProcessSnapshot>& after);

private:
    ProcessInspector();
    ~ProcessInspector();

    ProcessInspector(const ProcessInspector&) = delete;
    ProcessInspector& operator=(const ProcessInspector&) = delete;

    std::unique_ptr<ProcessInspectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
