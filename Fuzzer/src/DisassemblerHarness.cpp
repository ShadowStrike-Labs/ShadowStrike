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
 * @file DisassemblerHarness.cpp
 * @brief Implementation of the PhantomDisassembler fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/DisassemblerHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "PhantomDisassembler/Decoder.hpp"

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
#include <exception>
#include <iomanip>
#include <iostream>
#include <system_error>

namespace ShadowStrike::Fuzzer {
namespace {

using Phantom::Disasm::DecodedInstruction;
using Phantom::Disasm::DecodedOperand;
using Phantom::Disasm::Decoder;
using Phantom::Disasm::IsFailed;
using Phantom::Disasm::IsSuccess;
using Phantom::Disasm::MachineMode;
using Phantom::Disasm::MAX_INSTRUCTION_LENGTH;
using Phantom::Disasm::MAX_OPERANDS;
using Phantom::Disasm::Register;
using Phantom::Disasm::Status;

constexpr std::array<MachineMode, 4> kMachineModes{
    MachineMode::Long64,
    MachineMode::LongCompat32,
    MachineMode::Legacy32,
    MachineMode::Real16,
};

constexpr size_t kMaxInstructionsPerLoop = 10000;

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
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

template <size_t N>
[[nodiscard]] std::array<uint8_t, N> BuildPatternedBuffer(
    std::span<const uint8_t> input,
    const std::array<uint8_t, N>& fallback) noexcept
{
    std::array<uint8_t, N> output = fallback;
    if (input.empty()) {
        return output;
    }

    for (size_t index = 0; index < N; ++index) {
        output[index] = input[index % input.size()];
    }

    return output;
}

void RecordFailure(HarnessResult& result) noexcept {
    ++result.anomalyCount;
}

void ValidateSuccessfulDecode(
    const DecodedInstruction& instruction,
    const std::array<DecodedOperand, MAX_OPERANDS>& operands,
    size_t availableLength,
    HarnessResult& result) noexcept
{
    if (instruction.length == 0 || instruction.length > MAX_INSTRUCTION_LENGTH) {
        ++result.validationIssueCount;
    }

    if (instruction.length > availableLength) {
        ++result.validationIssueCount;
    }

    if (instruction.operand_count > MAX_OPERANDS) {
        ++result.validationIssueCount;
    }

    const auto operandCount = static_cast<size_t>(
        std::min<uint8_t>(instruction.operand_count, MAX_OPERANDS));
    for (size_t index = 0; index < operandCount; ++index) {
        if (operands[index].IsRegister() && operands[index].reg.value == Register::NONE) {
            ++result.validationIssueCount;
        }
    }
}

void ExerciseTruncation(
    const Decoder& decoder,
    const uint8_t* buffer,
    uint8_t successfulLength,
    HarnessResult& result) noexcept
{
    if (buffer == nullptr || successfulLength > MAX_INSTRUCTION_LENGTH) {
        ++result.validationIssueCount;
        return;
    }

    DecodedInstruction truncatedInstruction{};
    std::array<DecodedOperand, MAX_OPERANDS> truncatedOperands{};

    const size_t truncatedLength =
        successfulLength == 0 ? 0U : static_cast<size_t>(successfulLength - 1U);
    const Status truncatedStatus = decoder.DecodeFull(
        buffer,
        truncatedLength,
        truncatedInstruction,
        truncatedOperands.data());

    if (IsSuccess(truncatedStatus)) {
        ++result.validationIssueCount;
        return;
    }

    RecordFailure(result);
}

void ExerciseSingleDecode(
    const Decoder& decoder,
    const uint8_t* buffer,
    size_t length,
    HarnessResult& result,
    Status expectedFailure = Status::Success) noexcept
{
    DecodedInstruction instruction{};
    std::array<DecodedOperand, MAX_OPERANDS> operands{};

    const Status status = decoder.DecodeFull(buffer, length, instruction, operands.data());
    if (IsSuccess(status)) {
        result.parsedOk = true;
        ValidateSuccessfulDecode(instruction, operands, length, result);
        ExerciseTruncation(decoder, buffer, instruction.length, result);
        return;
    }

    RecordFailure(result);
    if (expectedFailure != Status::Success && status != expectedFailure) {
        ++result.validationIssueCount;
    }
}

void ExerciseDecodeLoop(
    const Decoder& decoder,
    std::span<const uint8_t> input,
    HarnessResult& result) noexcept
{
    if (input.empty()) {
        return;
    }

    size_t offset = 0;
    size_t iterations = 0;

    while (offset < input.size() && iterations < kMaxInstructionsPerLoop) {
        DecodedInstruction instruction{};
        std::array<DecodedOperand, MAX_OPERANDS> operands{};
        const uint8_t* cursor = input.data() + offset;
        const size_t remaining = input.size() - offset;

        const Status status = decoder.DecodeFull(cursor, remaining, instruction, operands.data());
        if (IsSuccess(status)) {
            result.parsedOk = true;
            ValidateSuccessfulDecode(instruction, operands, remaining, result);
            ExerciseTruncation(decoder, cursor, instruction.length, result);

            size_t advance = static_cast<size_t>(instruction.length);
            if (advance == 0 || advance > MAX_INSTRUCTION_LENGTH || advance > remaining) {
                ++result.validationIssueCount;
                advance = 1;
            }

            offset += advance;
        } else {
            RecordFailure(result);
            ++offset;
        }

        ++iterations;
    }
}

void ExerciseMode(
    MachineMode mode,
    std::span<const uint8_t> input,
    HarnessResult& result) noexcept
{
    Decoder decoder;
    const Status initStatus = decoder.Init(mode);
    if (IsFailed(initStatus) || !decoder.IsInitialized() || decoder.GetMode() != mode) {
        ++result.validationIssueCount;
        return;
    }

    ExerciseSingleDecode(
        decoder,
        input.empty() ? nullptr : input.data(),
        input.size(),
        result,
        input.empty() ? Status::InvalidInput : Status::Success);

    ExerciseDecodeLoop(decoder, input, result);

    constexpr std::array<uint8_t, 1> kBoundary1{{0x90}};
    constexpr std::array<uint8_t, 15> kBoundary15{{
        0x66, 0x67, 0x2E, 0x90, 0x90,
        0xF3, 0x90, 0x48, 0x90, 0x0F,
        0x1F, 0x40, 0x00, 0x90, 0x90
    }};
    constexpr std::array<uint8_t, 16> kBoundary16{{
        0xF0, 0x66, 0x67, 0x2E, 0x36, 0x3E, 0x26, 0x64,
        0x65, 0x48, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00
    }};
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

    const auto boundary1 = BuildPatternedBuffer(input, kBoundary1);
    const auto boundary15 = BuildPatternedBuffer(input, kBoundary15);
    const auto boundary16 = BuildPatternedBuffer(input, kBoundary16);

    ExerciseSingleDecode(decoder, nullptr, 0, result, Status::InvalidInput);
    ExerciseSingleDecode(decoder, boundary1.data(), boundary1.size(), result);
    ExerciseSingleDecode(decoder, boundary15.data(), boundary15.size(), result);
    ExerciseSingleDecode(decoder, boundary16.data(), boundary16.size(), result);

    ExerciseSingleDecode(decoder, kSegmentStorm.data(), kSegmentStorm.size(), result);
    ExerciseSingleDecode(decoder, kRexStorm.data(), kRexStorm.size(), result);
    ExerciseSingleDecode(decoder, kVexStorm.data(), kVexStorm.size(), result);
    ExerciseSingleDecode(decoder, kEvexStorm.data(), kEvexStorm.size(), result);
}

}  // namespace

std::string DisassemblerHarness::ExceptionCodeToString(unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool DisassemblerHarness::DecodeImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result) noexcept
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    for (const MachineMode mode : kMachineModes) {
        ExerciseMode(mode, input, result);
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long DisassemblerHarness::SEHCallDecode(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        DecodeImpl(data, size, *pResult);
    }
    __except (exCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        // Hardware exception caught — process survives.
    }
    return exCode;
}

HarnessResult DisassemblerHarness::Run(std::span<const uint8_t> input) noexcept {
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

HarnessFunction DisassemblerHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view DisassemblerHarness::GetName() noexcept {
    return "disassembler";
}

std::string_view DisassemblerHarness::GetDescription() noexcept {
    return "PhantomDisassembler Decoder::DecodeFull fuzz harness across all x86 machine modes";
}

int RunDisassemblerFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[DisassemblerFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "parser" / "disassembler";
    const auto crashDir = workspaceDir / "crashes" / "disassembler";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[DisassemblerFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[DisassemblerFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(DisassemblerHarness::GetName());

    std::cout << "[DisassemblerFuzzer] Starting disassembler fuzzing...\n";
    std::cout << "[DisassemblerFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[DisassemblerFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, DisassemblerHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[DisassemblerFuzzer] Final Results:\n";
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
