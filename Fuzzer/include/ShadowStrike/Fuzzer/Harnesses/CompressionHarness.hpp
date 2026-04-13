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
 * @file CompressionHarness.hpp
 * @brief Fuzz harness for ShadowStrike CompressionUtils entry points.
 *
 * Exercises one-shot and persistent compression/decompression flows across all
 * Windows Compression API algorithms, validates round-trip invariants, and
 * hardens execution with Windows SEH for in-process fuzzing.
 */

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace ShadowStrike::Fuzzer {

class CompressionHarness {
public:
    [[nodiscard]] static HarnessResult Run(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] static HarnessFunction GetHarnessFunction() noexcept;
    [[nodiscard]] static std::string_view GetName() noexcept;
    [[nodiscard]] static std::string_view GetDescription() noexcept;
    [[nodiscard]] static std::string ExceptionCodeToString(unsigned long code);

private:
    [[nodiscard]] static unsigned long SEHCallCompression(
        const uint8_t* data,
        size_t size,
        HarnessResult* pResult) noexcept;

    [[nodiscard]] static bool ExerciseCompressionImpl(
        const uint8_t* data,
        size_t size,
        HarnessResult& result);
};

[[nodiscard]] int RunCompressionFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept;

}  // namespace ShadowStrike::Fuzzer
