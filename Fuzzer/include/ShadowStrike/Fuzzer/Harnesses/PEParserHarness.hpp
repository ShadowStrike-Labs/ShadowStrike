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
 * @file PEParserHarness.hpp
 * @brief Fuzz harness for the ShadowStrike PE parser.
 *
 * This harness exercises all PE parsing functionality including:
 * - Main ParseBuffer entry point
 * - All lazy-loaded parsers (imports, exports, TLS, resources, etc.)
 * - Validation functions
 * - Standalone validation helpers
 * - Address translation functions
 *
 * Uses Windows SEH for crash detection to catch access violations,
 * stack overflows, and other hardware exceptions.
 *
 * @copyright ShadowStrike Security Suite
 */

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include <cstdint>
#include <cstddef>
#include <span>
#include <string>

namespace ShadowStrike::Fuzzer {

/**
 * @brief PE parser fuzz harness.
 *
 * This class provides a comprehensive harness for fuzzing the ShadowStrike
 * PE parser. It exercises all parsing and validation functionality while
 * catching both C++ exceptions and Windows SEH exceptions.
 *
 * Usage:
 * @code
 *   std::vector<uint8_t> input = GetFuzzInput();
 *   HarnessResult result = PEParserHarness::Run(input);
 *   
 *   if (result.crashed) {
 *       SaveCrash(input, result);
 *   }
 * @endcode
 *
 * Thread safety: The harness is stateless and thread-safe.
 */
class PEParserHarness {
public:
    /**
     * @brief Execute the PE parser harness on input data.
     *
     * This is the main entry point for fuzzing. It:
     * 1. Feeds input to PEParser::ParseBuffer()
     * 2. If successful, calls all lazy-loaded parsers
     * 3. Calls ValidatePE and VerifyChecksum
     * 4. Tests RvaToOffset with various RVAs
     * 5. Calls standalone validation functions
     *
     * All operations are wrapped in SEH __try/__except blocks
     * to catch access violations, stack overflows, etc.
     *
     * @param input Input buffer to parse.
     * @return Harness result with crash/parse information.
     */
    [[nodiscard]] static HarnessResult Run(std::span<const uint8_t> input) noexcept;

    /**
     * @brief Get the harness function pointer.
     *
     * Returns a function suitable for use with FuzzLoop.
     *
     * @return Harness function.
     */
    [[nodiscard]] static HarnessFunction GetHarnessFunction() noexcept;

    /**
     * @brief Get the harness name.
     * @return Harness identifier string.
     */
    [[nodiscard]] static std::string_view GetName() noexcept;

    /**
     * @brief Get harness description.
     * @return Human-readable description.
     */
    [[nodiscard]] static std::string_view GetDescription() noexcept;

private:
    // Internal implementation separated for SEH compatibility
    [[nodiscard]] static HarnessResult RunInternal(std::span<const uint8_t> input) noexcept;

    // SEH-wrapped parsing steps
    [[nodiscard]] static bool TryParseBuffer(
        const uint8_t* data,
        size_t size,
        HarnessResult& result) noexcept;

    [[nodiscard]] static bool TryParseLazyLoaded(HarnessResult& result) noexcept;
    [[nodiscard]] static bool TryValidate(HarnessResult& result) noexcept;
    [[nodiscard]] static bool TryStandaloneValidation(
        const uint8_t* data,
        size_t size,
        HarnessResult& result) noexcept;

    // Convert SEH exception code to string
    [[nodiscard]] static std::string ExceptionCodeToString(unsigned int code) noexcept;
};

/**
 * @brief Run the PE parser fuzz loop.
 *
 * Convenience function that sets up and runs a complete fuzzing session
 * for the PE parser.
 *
 * @param workspaceDir Workspace directory (contains corpora/ and crashes/).
 * @param config Fuzzing configuration.
 * @return 0 on success, non-zero on error.
 */
[[nodiscard]] int RunPEParserFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept;

}  // namespace ShadowStrike::Fuzzer
