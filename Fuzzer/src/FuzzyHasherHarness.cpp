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
 * @file FuzzyHasherHarness.cpp
 * @brief Implementation of the ShadowStrike fuzzy hasher fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/FuzzyHasherHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#if __has_include("FuzzyHasher/FuzzyHasher.hpp")
#include "FuzzyHasher/FuzzyHasher.hpp"
#else
#include "PhantomCore/FuzzyHasher/FuzzyHasher.hpp"
#endif

#if __has_include("FuzzyHasher/DigestComparer.hpp")
#include "FuzzyHasher/DigestComparer.hpp"
#else
#include "PhantomCore/FuzzyHasher/DigestComparer.hpp"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <malloc.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <string>

namespace ShadowStrike::Fuzzer {
namespace {

namespace FH = ShadowStrike::FuzzyHasher;

[[nodiscard]] std::string ExceptionCodeToStringInternal(DWORD code) {
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
    case EXCEPTION_INVALID_HANDLE:           return "EXCEPTION_INVALID_HANDLE";
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

[[nodiscard]] std::span<const uint8_t> Payload(std::span<const uint8_t> input) noexcept {
    return input.size() > 1 ? input.subspan(1) : std::span<const uint8_t>{};
}

[[nodiscard]] std::string MakeByteString(std::span<const uint8_t> bytes) {
    return std::string(
        reinterpret_cast<const char*>(bytes.data()),
        reinterpret_cast<const char*>(bytes.data()) + bytes.size());
}

[[nodiscard]] std::string MakeCString(std::span<const uint8_t> bytes) {
    std::string value = MakeByteString(bytes);
    value.push_back('\0');
    return value;
}

}  // namespace

std::string FuzzyHasherHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool FuzzyHasherHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();

    const std::span<const uint8_t> input(data, size);
    if (input.empty()) {
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.parseTimeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
        return true;
    }

    const uint8_t mode = input.front() % 4u;
    const std::span<const uint8_t> payload = Payload(input);

    switch (mode) {
    case 0: {
        const auto digest = FH::HashBuffer(payload);
        result.parsedOk = true;
        if (digest.has_value() && FH::IsSuspiciousDigest(*digest)) {
            ++result.anomalyCount;
        }
        break;
    }
    case 1: {
        const size_t midpoint = payload.size() / 2;
        const std::string digest1 = MakeCString(payload.first(midpoint));
        const std::string digest2 = MakeCString(payload.subspan(midpoint));

        const int compareScore = FH::Compare(digest1.c_str(), digest2.c_str());
        const int comparerScore = FH::CompareDigests(digest1.c_str(), digest2.c_str());

        result.parsedOk = true;
        if (compareScore >= 0 && comparerScore >= 0 && compareScore != comparerScore) {
            ++result.validationIssueCount;
            if (result.errorMessage.empty()) {
                result.errorMessage = "FuzzyHasher::Compare and CompareDigests disagree";
            }
        }
        if (compareScore == 100 || comparerScore == 100) {
            ++result.anomalyCount;
        }
        break;
    }
    case 2: {
        const std::string digest = MakeByteString(payload);
        result.parsedOk = true;
        if (FH::IsSuspiciousDigest(digest)) {
            ++result.anomalyCount;
        }
        break;
    }
    case 3: {
        const size_t midpoint = payload.size() / 2;
        const auto confirm = FH::CompareWithCryptoConfirmation(
            payload.first(midpoint),
            payload.subspan(midpoint));

        result.parsedOk = true;
        if (confirm.fuzzyScore >= FH::kCryptoConfirmThreshold) {
            ++result.anomalyCount;
        }
        if (confirm.cryptoRan && confirm.exactMatch) {
            ++result.anomalyCount;
        }
        break;
    }
    default:
        break;
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long FuzzyHasherHarness::SEHCallExercise(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        (void)ExerciseImpl(data, size, *pResult);
    }
    __except (exCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exCode == EXCEPTION_STACK_OVERFLOW) {
            if (_resetstkoflw() == 0) {
                TerminateProcess(GetCurrentProcess(), exCode);
            }
        }
        if (exCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exCode);
        }
    }
    return exCode;
}

HarnessResult FuzzyHasherHarness::Run(std::span<const uint8_t> input) {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallExercise(
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

HarnessFunction FuzzyHasherHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view FuzzyHasherHarness::GetName() noexcept {
    return "fuzzy-hasher";
}

std::string_view FuzzyHasherHarness::GetDescription() noexcept {
    return "Fuzzy hashing fuzz harness for ShadowStrike NGAV";
}

int RunFuzzyHasherFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[FuzzyHasherFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "fuzzy_hasher";
    const auto crashDir = workspaceDir / "crashes" / "fuzzy_hasher";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[FuzzyHasherFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[FuzzyHasherFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(FuzzyHasherHarness::GetName());

    std::cout << "[FuzzyHasherFuzzer] Starting fuzzy hasher fuzzing...\n";
    std::cout << "[FuzzyHasherFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[FuzzyHasherFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, FuzzyHasherHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[FuzzyHasherFuzzer] Final Results:\n";
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
