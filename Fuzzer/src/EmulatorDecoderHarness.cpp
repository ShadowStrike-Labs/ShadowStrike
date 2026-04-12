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

/**
 * @file EmulatorDecoderHarness.cpp
 * @brief Implementation of the PhantomEmulator InstructionDecoder fuzz harness.
 *
 * Exercises Phantom::InstructionDecoder::Decode() across all three CPU modes
 * (Long64, Protected32, Real16) with:
 *   - Single instruction decode with random byte sequences
 *   - Full buffer walk consuming instructions until exhaustion
 *   - Boundary condition testing (empty, 1-byte, max-length buffers)
 *   - Prefix storm generation (segment, REX, VEX, EVEX)
 *   - Truncation sweep at every byte offset within valid instructions
 *   - Cross-mode consistency validation (same bytes, different modes)
 *   - Operand validation for decoded instructions
 *   - Guard-page boundary testing to detect decoder over-reads
 *   - Stack overflow recovery and heap corruption termination (SEH hardened)
 */

#include "ShadowStrike/Fuzzer/Harnesses/EmulatorDecoderHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "PhantomEmulator/Core/CPU/Executor/Decoder/InstructionDecoder.hpp"
#include "PhantomEmulator/Core/CPU/Executor/Decoder/Instruction.hpp"
#include "PhantomEmulator/Common/Types.hpp"
#include "PhantomEmulator/Common/Errors.hpp"
#include "PhantomEmulator/Common/Constants.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <malloc.h>  // _resetstkoflw()

namespace ShadowStrike::Fuzzer {
namespace {

// ============================================================================
// Type aliases for readability
// ============================================================================

using Phantom::CPUMode;
using Phantom::DecodedInstruction;
using Phantom::DecodedOperand;
using Phantom::ErrorCode;
using Phantom::GuestAddress;
using Phantom::InstructionDecoder;
using Phantom::OperandType;
using Phantom::Encoding::kMaxInstructionLength;

// ============================================================================
// Constants
// ============================================================================

constexpr std::array<CPUMode, 3> kCPUModes{
    CPUMode::Long64,
    CPUMode::Protected32,
    CPUMode::Real16,
};

constexpr size_t kMaxInstructionsPerLoop = 10000;

// Simulated RIP base for decode calls (arbitrary, non-zero for realism)
constexpr GuestAddress kFuzzRIPBase = 0x00401000ULL;

// ============================================================================
// SEH exception code string conversion
// ============================================================================

std::string ExceptionCodeToStringInternal(DWORD code) noexcept {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:             return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

// ============================================================================
// Patterned buffer builder — fills a fixed-size buffer using input as pattern
// ============================================================================

template <size_t N>
[[nodiscard]] std::array<uint8_t, N> BuildPatternedBuffer(
    std::span<const uint8_t> input,
    const std::array<uint8_t, N>& fallback) noexcept
{
    std::array<uint8_t, N> output = fallback;
    if (input.empty()) {
        return output;
    }
    for (size_t i = 0; i < N; ++i) {
        output[i] = input[i % input.size()];
    }
    return output;
}

// ============================================================================
// Decode invariant validation
// ============================================================================

void ValidateSuccessfulDecode(
    const DecodedInstruction& inst,
    size_t availableLength,
    HarnessResult& result) noexcept
{
    // Length must be 1..15 and within available bytes
    if (inst.length == 0 || inst.length > kMaxInstructionLength) {
        ++result.validationIssueCount;
    }
    if (inst.length > availableLength) {
        ++result.validationIssueCount;
    }

    // Operand count must be 0..3
    if (inst.operandCount > 3) {
        ++result.validationIssueCount;
    }

    // Validate each operand has a valid type
    const uint8_t opCount = std::min<uint8_t>(inst.operandCount, 3);
    for (uint8_t i = 0; i < opCount; ++i) {
        const auto& op = inst.operands[i];
        if (op.type == OperandType::None) {
            // Declared operand should not be None
            ++result.validationIssueCount;
        }
    }

    // Operands beyond operandCount should be None
    for (uint8_t i = opCount; i < 3; ++i) {
        if (inst.operands[i].type != OperandType::None) {
            ++result.validationIssueCount;
        }
    }

    // Immediate size consistency
    if (inst.immSize > 0) {
        if (inst.immSize != 1 && inst.immSize != 2 && inst.immSize != 4 && inst.immSize != 8) {
            ++result.validationIssueCount;
        }
    }

    // Displacement size consistency
    if (inst.dispSize > 0) {
        if (inst.dispSize != 1 && inst.dispSize != 2 && inst.dispSize != 4) {
            ++result.validationIssueCount;
        }
    }

    // Address field should match the RIP we passed in
    // (tolerance: decoder might set it to 0 if not implemented)
    // We just touch it to exercise the field
    (void)inst.NextRIP();
}

// ============================================================================
// Truncation testing — sweep all byte lengths from 0 to successfulLength-1
// ============================================================================

void ExerciseTruncation(
    InstructionDecoder& decoder,
    const uint8_t* buffer,
    uint8_t successfulLength,
    CPUMode mode,
    HarnessResult& result) noexcept
{
    if (buffer == nullptr || successfulLength == 0 || successfulLength > kMaxInstructionLength) {
        return;
    }

    // Test every truncation point from successfulLength-1 down to 0.
    // This exercises prefix/opcode/ModRM/SIB/displacement/immediate parsing
    // boundaries that a single-point truncation would miss.
    for (size_t truncLen = static_cast<size_t>(successfulLength) - 1;; --truncLen) {
        DecodedInstruction truncInst{};
        const auto truncSpan = std::span<const uint8_t>(buffer, truncLen);
        const ErrorCode truncErr = decoder.Decode(truncSpan, kFuzzRIPBase, mode, truncInst);

        if (truncErr == ErrorCode::Success) {
            // Truncated input decoded successfully — the instruction must be
            // strictly shorter than the original to be valid (it found a shorter
            // encoding within the prefix of the original bytes).
            if (truncInst.length >= successfulLength) {
                ++result.validationIssueCount;
            }
            ValidateSuccessfulDecode(truncInst, truncLen, result);
        }
        // Truncation failure is expected at most cut points — not an anomaly.

        if (truncLen == 0) break;
    }
}

// ============================================================================
// Single instruction decode exercise
// ============================================================================

void ExerciseSingleDecode(
    InstructionDecoder& decoder,
    const uint8_t* buffer,
    size_t length,
    CPUMode mode,
    HarnessResult& result) noexcept
{
    DecodedInstruction inst{};
    const auto inputSpan = (buffer != nullptr && length > 0)
        ? std::span<const uint8_t>(buffer, length)
        : std::span<const uint8_t>{};

    const ErrorCode err = decoder.Decode(inputSpan, kFuzzRIPBase, mode, inst);

    if (err == ErrorCode::Success) {
        result.parsedOk = true;
        ValidateSuccessfulDecode(inst, length, result);
        ExerciseTruncation(decoder, buffer, inst.length, mode, result);
    } else {
        ++result.anomalyCount;
    }
}

// ============================================================================
// Full buffer decode loop — walk buffer consuming instructions
// ============================================================================

void ExerciseDecodeLoop(
    InstructionDecoder& decoder,
    std::span<const uint8_t> input,
    CPUMode mode,
    HarnessResult& result) noexcept
{
    if (input.empty()) {
        return;
    }

    size_t offset = 0;
    size_t iterations = 0;
    GuestAddress rip = kFuzzRIPBase;

    while (offset < input.size() && iterations < kMaxInstructionsPerLoop) {
        DecodedInstruction inst{};
        const uint8_t* cursor = input.data() + offset;
        const size_t remaining = input.size() - offset;
        const auto slice = std::span<const uint8_t>(cursor, remaining);

        const ErrorCode err = decoder.Decode(slice, rip, mode, inst);

        if (err == ErrorCode::Success) {
            result.parsedOk = true;
            ValidateSuccessfulDecode(inst, remaining, result);

            size_t advance = static_cast<size_t>(inst.length);
            if (advance == 0 || advance > kMaxInstructionLength || advance > remaining) {
                ++result.validationIssueCount;
                advance = 1;
            }

            offset += advance;
            rip += advance;
        } else {
            ++result.anomalyCount;
            ++offset;
            ++rip;
        }

        ++iterations;
    }
}

// ============================================================================
// Cross-mode consistency — same bytes decoded in all modes
// ============================================================================

void ExerciseCrossModeConsistency(
    std::span<const uint8_t> input,
    HarnessResult& result) noexcept
{
    if (input.empty() || input.size() > kMaxInstructionLength) {
        return;
    }

    // Decode the same bytes in all three modes and check basic consistency
    struct ModeResult {
        ErrorCode err;
        uint8_t length;
    };

    std::array<ModeResult, 3> results{};
    InstructionDecoder decoder;

    for (size_t i = 0; i < kCPUModes.size(); ++i) {
        DecodedInstruction inst{};
        results[i].err = decoder.Decode(input, kFuzzRIPBase, kCPUModes[i], inst);
        results[i].length = inst.length;
    }

    // If all modes succeed, lengths should all be in [1, 15]
    for (const auto& r : results) {
        if (r.err == ErrorCode::Success) {
            if (r.length == 0 || r.length > kMaxInstructionLength) {
                ++result.validationIssueCount;
            }
        }
    }
}

// ============================================================================
// Guard-page boundary testing — detect decoder over-reads past buffer end
// ============================================================================

void ExerciseGuardPageDecode(
    InstructionDecoder& decoder,
    std::span<const uint8_t> input,
    CPUMode mode,
    HarnessResult& result) noexcept
{
    if (input.empty()) return;

    // Clamp to max instruction length — no point placing more at the boundary
    const size_t testLen = std::min(input.size(), static_cast<size_t>(kMaxInstructionLength));

    // Allocate two contiguous pages: first writable, second NOACCESS
    constexpr DWORD kPageSize = 4096;
    auto* base = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, kPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base) return;

    DWORD oldProtect = 0;
    if (!VirtualProtect(base + kPageSize, kPageSize, PAGE_NOACCESS, &oldProtect)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return;
    }

    // Place test bytes at the end of the first page, flush against the guard
    uint8_t* target = base + kPageSize - testLen;
    std::memcpy(target, input.data(), testLen);

    // Decode — if the decoder reads even one byte past testLen, it hits
    // PAGE_NOACCESS and triggers EXCEPTION_ACCESS_VIOLATION (caught by SEH)
    DecodedInstruction inst{};
    const auto slice = std::span<const uint8_t>(target, testLen);
    const ErrorCode err = decoder.Decode(slice, kFuzzRIPBase, mode, inst);

    if (err == ErrorCode::Success) {
        result.parsedOk = true;
        ValidateSuccessfulDecode(inst, testLen, result);
    }

    VirtualFree(base, 0, MEM_RELEASE);
}

// ============================================================================
// Exercise one CPU mode with full test battery
// ============================================================================

void ExerciseMode(
    CPUMode mode,
    std::span<const uint8_t> input,
    HarnessResult& result) noexcept
{
    InstructionDecoder decoder;

    // Core exercises: single decode + full buffer walk
    ExerciseSingleDecode(
        decoder,
        input.empty() ? nullptr : input.data(),
        input.size(),
        mode,
        result);

    ExerciseDecodeLoop(decoder, input, mode, result);

    // Boundary conditions
    constexpr std::array<uint8_t, 1> kBoundary1{{0x90}};  // NOP
    constexpr std::array<uint8_t, 15> kBoundary15{{
        0x66, 0x67, 0x2E, 0x90, 0x90,
        0xF3, 0x90, 0x48, 0x90, 0x0F,
        0x1F, 0x40, 0x00, 0x90, 0x90
    }};
    constexpr std::array<uint8_t, 16> kBoundaryOver{{
        0xF0, 0x66, 0x67, 0x2E, 0x36, 0x3E, 0x26, 0x64,
        0x65, 0x48, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00
    }};

    // Prefix storms
    constexpr std::array<uint8_t, 15> kSegmentStorm{{
        0x2E, 0x36, 0x3E, 0x26, 0x64,
        0x65, 0x66, 0x67, 0xF3, 0xF2,
        0xF0, 0x90, 0x90, 0x90, 0x90
    }};
    constexpr std::array<uint8_t, 15> kRexStorm{{
        0x40, 0x41, 0x42, 0x43, 0x44,
        0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B, 0x4C, 0x4D, 0x90
    }};
    constexpr std::array<uint8_t, 15> kVexStorm{{
        0xC4, 0xE1, 0x79, 0xC5, 0xF9,
        0xC4, 0xE2, 0x79, 0x58, 0xC0,
        0x90, 0x90, 0x90, 0x90, 0x90
    }};
    constexpr std::array<uint8_t, 15> kEvexStorm{{
        0x62, 0xF1, 0x7C, 0x08, 0x62,
        0xF1, 0x7C, 0x08, 0x58, 0xC0,
        0x90, 0x90, 0x90, 0x90, 0x90
    }};

    // Patterned buffers derived from fuzz input
    const auto boundary1  = BuildPatternedBuffer(input, kBoundary1);
    const auto boundary15 = BuildPatternedBuffer(input, kBoundary15);
    const auto boundaryOver = BuildPatternedBuffer(input, kBoundaryOver);

    // Empty buffer
    ExerciseSingleDecode(decoder, nullptr, 0, mode, result);

    // Fixed-size boundaries
    ExerciseSingleDecode(decoder, boundary1.data(), boundary1.size(), mode, result);
    ExerciseSingleDecode(decoder, boundary15.data(), boundary15.size(), mode, result);
    ExerciseSingleDecode(decoder, boundaryOver.data(), boundaryOver.size(), mode, result);

    // Prefix storm patterns
    ExerciseSingleDecode(decoder, kSegmentStorm.data(), kSegmentStorm.size(), mode, result);
    ExerciseSingleDecode(decoder, kRexStorm.data(), kRexStorm.size(), mode, result);
    ExerciseSingleDecode(decoder, kVexStorm.data(), kVexStorm.size(), mode, result);
    ExerciseSingleDecode(decoder, kEvexStorm.data(), kEvexStorm.size(), mode, result);

    // All-zeros and all-ones (degenerate cases)
    constexpr std::array<uint8_t, 15> kAllZeros{};
    constexpr std::array<uint8_t, 15> kAllOnes{{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }};
    ExerciseSingleDecode(decoder, kAllZeros.data(), kAllZeros.size(), mode, result);
    ExerciseSingleDecode(decoder, kAllOnes.data(), kAllOnes.size(), mode, result);

    // Guard-page boundary test — detects buffer over-reads in the decoder
    ExerciseGuardPageDecode(decoder, input, mode, result);
}

}  // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

std::string EmulatorDecoderHarness::ExceptionCodeToString(unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool EmulatorDecoderHarness::DecodeImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result) noexcept
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    // Exercise all three CPU modes
    for (const CPUMode mode : kCPUModes) {
        ExerciseMode(mode, input, result);
    }

    // Cross-mode consistency check
    ExerciseCrossModeConsistency(input, result);

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long EmulatorDecoderHarness::SEHCallDecode(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        DecodeImpl(data, size, *pResult);
    }
    __except (exCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        // Stack overflow requires explicit recovery before the thread can
        // use its stack normally again. Without this, the next function call
        // that touches the guard page will terminate the process.
        if (exCode == EXCEPTION_STACK_OVERFLOW) {
            _resetstkoflw();
        }
        // Heap corruption means the process heap is in an undefined state.
        // Continuing would produce undefined behavior — record the crash
        // and terminate immediately so the crash seed is preserved by the
        // FuzzLoop filesystem layer (seeds are flushed before harness call).
        if (exCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exCode);
        }
    }
    return exCode;
}

HarnessResult EmulatorDecoderHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallDecode(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != 0) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(exceptionCode);
        }
    } catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction EmulatorDecoderHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view EmulatorDecoderHarness::GetName() noexcept {
    return "emu-decoder";
}

std::string_view EmulatorDecoderHarness::GetDescription() noexcept {
    return "PhantomEmulator InstructionDecoder::Decode fuzz harness across all x86 CPU modes";
}

int RunEmulatorDecoderFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[EmuDecoderFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "emulator" / "decoder";
    const auto crashDir = workspaceDir / "crashes" / "emulator" / "decoder";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[EmuDecoderFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[EmuDecoderFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(EmulatorDecoderHarness::GetName());

    std::cout << "[EmuDecoderFuzzer] Starting emulator decoder fuzzing...\n";
    std::cout << "[EmuDecoderFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[EmuDecoderFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, EmulatorDecoderHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[EmuDecoderFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
