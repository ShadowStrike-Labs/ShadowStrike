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
 * @file CompressionHarness.cpp
 * @brief Implementation of the CompressionUtils fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/CompressionHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "Utils/CompressionUtils.hpp"

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
#include <malloc.h>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSCompression = ShadowStrike::Utils::CompressionUtils;
using SSCompression::Algorithm;
using SSCompression::CompressBuffer;
using SSCompression::Compressor;
using SSCompression::DecompressBuffer;
using SSCompression::Decompressor;

constexpr std::array<Algorithm, 4> kAlgorithms{
    Algorithm::Mszip,
    Algorithm::Xpress,
    Algorithm::XpressHuff,
    Algorithm::Lzms,
};

constexpr size_t kMaxHarnessExpectedSize = 64ULL * 1024;

std::string ExceptionCodeToStringInternal(DWORD code) {
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

void CaptureFirstIssue(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

[[nodiscard]] const void* InputPointer(std::span<const uint8_t> input) noexcept {
    return input.empty() ? nullptr : input.data();
}

[[nodiscard]] size_t DeriveExpectedSize(std::span<const uint8_t> input) noexcept {
    if (input.empty()) {
        return 0;
    }

    uint64_t value = 0;
    const size_t copySize = std::min(input.size(), sizeof(value));
    std::memcpy(&value, input.data(), copySize);

    const size_t dynamicLimit = std::min<size_t>(
        kMaxHarnessExpectedSize,
        std::max<size_t>(4096, input.size() * 8));
    const uint64_t limit = static_cast<uint64_t>(dynamicLimit);
    return static_cast<size_t>(value % (limit + 1ULL));
}

void ValidateRoundTrip(
    std::span<const uint8_t> original,
    const std::vector<uint8_t>& roundTrip,
    std::string_view stage,
    HarnessResult& result)
{
    if (roundTrip.size() != original.size()) {
        std::string message(stage);
        message += " produced a decompressed size mismatch.";
        RecordValidationIssue(result, message);
        return;
    }

    if (!std::equal(roundTrip.begin(), roundTrip.end(), original.begin(), original.end())) {
        std::string message(stage);
        message += " changed payload bytes across a compression round-trip.";
        RecordAnomaly(result, message);
    }
}

void ExerciseHostileDecompression(
    Algorithm algorithm,
    std::span<const uint8_t> input,
    HarnessResult& result)
{
    std::vector<uint8_t> output;
    if (DecompressBuffer(algorithm, InputPointer(input), input.size(), output, 0)) {
        result.parsedOk = true;
        if (output.size() > SSCompression::MAX_DECOMPRESSED_SIZE) {
            RecordAnomaly(result, "DecompressBuffer returned data above MAX_DECOMPRESSED_SIZE.");
        }
    }

    const size_t derivedExpectedSize = DeriveExpectedSize(input);
    if (derivedExpectedSize != 0 &&
        DecompressBuffer(algorithm, InputPointer(input), input.size(), output, derivedExpectedSize)) {
        result.parsedOk = true;
        if (output.size() != derivedExpectedSize) {
            RecordValidationIssue(result, "DecompressBuffer ignored the supplied expected size.");
        }
    }

    Decompressor decompressor;
    if (!decompressor.open(algorithm)) {
        if (SSCompression::IsAlgorithmSupported(algorithm)) {
            RecordValidationIssue(result, "Decompressor::open failed for a supported algorithm.");
        }
        return;
    }

    if (decompressor.decompress(InputPointer(input), input.size(), output, 0)) {
        result.parsedOk = true;
        if (output.size() > SSCompression::MAX_DECOMPRESSED_SIZE) {
            RecordAnomaly(result, "Persistent decompressor returned data above MAX_DECOMPRESSED_SIZE.");
        }
    }

    if (derivedExpectedSize != 0 &&
        decompressor.decompress(InputPointer(input), input.size(), output, derivedExpectedSize) &&
        output.size() != derivedExpectedSize) {
        RecordValidationIssue(result, "Persistent decompressor ignored the supplied expected size.");
    }
}

void ExerciseRoundTrip(
    Algorithm algorithm,
    std::span<const uint8_t> input,
    HarnessResult& result)
{
    std::vector<uint8_t> compressedOneShot;
    if (!CompressBuffer(algorithm, InputPointer(input), input.size(), compressedOneShot)) {
        return;
    }

    result.parsedOk = true;

    std::vector<uint8_t> decompressedOneShot;
    if (!DecompressBuffer(
            algorithm,
            compressedOneShot.empty() ? nullptr : compressedOneShot.data(),
            compressedOneShot.size(),
            decompressedOneShot,
            input.size())) {
        RecordValidationIssue(result, "One-shot compression succeeded but one-shot decompression failed.");
    } else {
        ValidateRoundTrip(input, decompressedOneShot, "One-shot compression", result);
    }

    if (!input.empty()) {
        std::vector<uint8_t> rejectedOutput;
        if (DecompressBuffer(
                algorithm,
                compressedOneShot.empty() ? nullptr : compressedOneShot.data(),
                compressedOneShot.size(),
                rejectedOutput,
                input.size() + 1)) {
            RecordValidationIssue(result, "DecompressBuffer accepted an incorrect expected output size.");
        }
    }

    Compressor compressor;
    if (!compressor.open(algorithm)) {
        RecordValidationIssue(result, "Compressor::open failed after one-shot compression succeeded.");
        return;
    }

    std::vector<uint8_t> compressedPersistent;
    if (!compressor.compress(InputPointer(input), input.size(), compressedPersistent)) {
        RecordValidationIssue(result, "Persistent compressor failed after one-shot compression succeeded.");
        return;
    }

    Decompressor decompressor;
    if (!decompressor.open(algorithm)) {
        RecordValidationIssue(result, "Decompressor::open failed during persistent round-trip.");
        return;
    }

    std::vector<uint8_t> decompressedPersistent;
    if (!decompressor.decompress(
            compressedPersistent.empty() ? nullptr : compressedPersistent.data(),
            compressedPersistent.size(),
            decompressedPersistent,
            input.size())) {
        RecordValidationIssue(result, "Persistent compression succeeded but persistent decompression failed.");
        return;
    }

    ValidateRoundTrip(input, decompressedPersistent, "Persistent compression", result);
}

}  // namespace

std::string CompressionHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool CompressionHarness::ExerciseCompressionImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    if (!SSCompression::IsCompressionApiAvailable()) {
        RecordValidationIssue(result, "Windows Compression API is unavailable.");
    } else {
        for (const Algorithm algorithm : kAlgorithms) {
            if (!SSCompression::IsAlgorithmSupported(algorithm)) {
                continue;
            }

            ExerciseHostileDecompression(algorithm, input, result);
            ExerciseRoundTrip(algorithm, input, result);
        }
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long CompressionHarness::SEHCallCompression(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExerciseCompressionImpl(data, size, *pResult);
    }
    __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exceptionCode == EXCEPTION_STACK_OVERFLOW) {
            if (_resetstkoflw() == 0) {
                TerminateProcess(GetCurrentProcess(), exceptionCode);
            }
        }

        if (exceptionCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exceptionCode);
        }
    }

    return exceptionCode;
}

HarnessResult CompressionHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallCompression(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != 0) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(exceptionCode);
        }
    }
    catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    }
    catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction CompressionHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view CompressionHarness::GetName() noexcept {
    return "compression";
}

std::string_view CompressionHarness::GetDescription() noexcept {
    return "CompressionUtils compression/decompression fuzz harness";
}

int RunCompressionFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[CompressionFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "compression";
    const auto crashDir = workspaceDir / "crashes" / "compression";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[CompressionFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[CompressionFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(CompressionHarness::GetName());

    std::cout << "[CompressionFuzzer] Starting compression fuzzing...\n";
    std::cout << "[CompressionFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[CompressionFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, CompressionHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[CompressionFuzzer] Final Results:\n";
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
