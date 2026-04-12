// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
/**
 * @file EmulatorExecutionHarness.hpp
 * @brief Fuzz harness for PhantomEmulator CPU::Execute().
 *
 * Exercises the PhantomEmulator CPU execution engine with hostile shellcode
 * bytes in both 64-bit and 32-bit shellcode configurations, validates basic
 * execution invariants, and wraps execution in Windows SEH to survive in-
 * process hardware faults during fuzzing.
 */

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace ShadowStrike::Fuzzer {

class EmulatorExecutionHarness {
public:
    [[nodiscard]] static HarnessResult Run(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] static HarnessFunction GetHarnessFunction() noexcept;
    [[nodiscard]] static std::string_view GetName() noexcept;
    [[nodiscard]] static std::string_view GetDescription() noexcept;
    [[nodiscard]] static std::string ExceptionCodeToString(unsigned long code) noexcept;

private:
    [[nodiscard]] static bool ExecutionImpl(
        const uint8_t* data,
        size_t size,
        HarnessResult& result);

    [[nodiscard]] static unsigned long SEHCallExecution(
        const uint8_t* data,
        size_t size,
        HarnessResult* pResult) noexcept;
};

/// Convenience entry point for CLI --fuzz-emu-execution command.
[[nodiscard]] int RunEmulatorExecutionFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept;

}  // namespace ShadowStrike::Fuzzer
