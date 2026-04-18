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
 * @file RansomwareAnalysisHarness.cpp
 * @brief Implementation of the ransomware analysis fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/RansomwareAnalysisHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "RansomwareProtection/RansomwareDetector.hpp"
#include "RansomwareProtection/WannaCryDetector.hpp"
// LockyDetector.hpp reuses the same enum identifier as WannaCryDetector.hpp.
#define DetectionConfidence LockyDetectionConfidence
#include "RansomwareProtection/LockyDetector.hpp"
#undef DetectionConfidence

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
#include <exception>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <system_error>
#include <utility>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSRansomware = ShadowStrike::Ransomware;

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

void SetFirstError(HarnessResult& result, std::string message) {
    if (result.errorMessage.empty()) {
        result.errorMessage = std::move(message);
    }
}

void RecordValidation(HarnessResult& result, std::string message) {
    ++result.validationIssueCount;
    SetFirstError(result, std::move(message));
}

[[nodiscard]] bool EnsureRansomwareDetectorReady(HarnessResult& result) {
    static std::once_flag initFlag;
    static bool initialized = false;

    std::call_once(initFlag, [] {
        initialized = SSRansomware::RansomwareDetector::Instance().Initialize({});
    });

    if (!initialized) {
        RecordValidation(result, "RansomwareDetector initialization failed");
    }

    return initialized;
}

[[nodiscard]] bool EnsureWannaCryReady(HarnessResult& result) {
    static std::once_flag initFlag;
    static bool initialized = false;

    std::call_once(initFlag, [] {
        initialized = SSRansomware::WannaCryDetector::Instance().Initialize();
    });

    if (!initialized) {
        RecordValidation(result, "WannaCryDetector initialization failed");
    }

    return initialized;
}

[[nodiscard]] bool EnsureLockyReady(HarnessResult& result) {
    static std::once_flag initFlag;
    static bool initialized = false;

    std::call_once(initFlag, [] {
        initialized = SSRansomware::LockyDetector::Instance().Initialize();
    });

    if (!initialized) {
        RecordValidation(result, "LockyDetector initialization failed");
    }

    return initialized;
}

[[nodiscard]] std::string BuildNarrowString(const uint8_t* data, size_t count) {
    if (data == nullptr || count == 0) {
        return {};
    }

    return std::string(reinterpret_cast<const char*>(data), count);
}

[[nodiscard]] std::wstring BuildWideString(const uint8_t* data, size_t count) {
    if (data == nullptr || count < sizeof(wchar_t)) {
        return {};
    }

    return std::wstring(reinterpret_cast<const wchar_t*>(data), count / sizeof(wchar_t));
}

void ExerciseEntropy(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureRansomwareDetectorReady(result)) {
        return;
    }

    auto& detector = SSRansomware::RansomwareDetector::Instance();
    const auto entropyResult = detector.AnalyzeEntropy(input);
    const bool isEncrypted = detector.IsEncrypted(input);
    const double entropy = detector.CalculateEntropy(input);

    result.parsedOk = true;

    if (entropy < 0.0 || entropy > 8.0) {
        RecordValidation(result, "RansomwareDetector::CalculateEntropy returned a value outside the Shannon range");
    }

    if (entropyResult.shannonEntropy < 0.0 || entropyResult.shannonEntropy > 8.0) {
        RecordValidation(result, "RansomwareDetector::AnalyzeEntropy returned a Shannon entropy outside the valid range");
    }

    if (entropyResult.isEncrypted != isEncrypted) {
        ++result.validationIssueCount;
    }

    if (entropyResult.isEncrypted) {
        ++result.anomalyCount;
    }
    if (isEncrypted) {
        ++result.anomalyCount;
    }
    if (entropyResult.confidence >= 0.90) {
        ++result.anomalyCount;
    }
}

void ExerciseWannaCryStrings(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureWannaCryReady(result)) {
        return;
    }

    const std::string str = BuildNarrowString(input.data(), input.size());
    const std::wstring wstr = BuildWideString(input.data(), input.size());

    auto& detector = SSRansomware::WannaCryDetector::Instance();
    const bool isKillSwitchDomain = detector.IsKillSwitchDomain(str);
    const bool isArtifact = detector.IsWannaCryArtifact(wstr);

    result.parsedOk = true;

    if (isKillSwitchDomain) {
        ++result.anomalyCount;
    }
    if (isArtifact) {
        ++result.anomalyCount;
    }
}

void ExerciseLockyStrings(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureLockyReady(result)) {
        return;
    }

    const std::string str = BuildNarrowString(input.data(), input.size());
    const std::wstring wstr = BuildWideString(input.data(), input.size());

    auto& detector = SSRansomware::LockyDetector::Instance();
    const bool isExtension = detector.IsLockyExtension(wstr);
    const bool isRansomNote = detector.IsLockyRansomNote(wstr);
    const bool isC2Domain = detector.IsLockyC2Domain(str);

    result.parsedOk = true;

    if (isExtension) {
        ++result.anomalyCount;
    }
    if (isRansomNote) {
        ++result.anomalyCount;
    }
    if (isC2Domain) {
        ++result.anomalyCount;
    }
}

}  // namespace

std::string RansomwareAnalysisHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool RansomwareAnalysisHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};
    const std::span<const uint8_t> payload =
        input.size() > 1 ? input.subspan(1) : std::span<const uint8_t>{};
    const std::span<const uint8_t> stringInput = payload.empty() ? input : payload;

    const uint8_t mode = input.empty() ? 0U : static_cast<uint8_t>(input.front() % 4U);

    switch (mode) {
    case 0:
        ExerciseEntropy(input, result);
        break;
    case 1:
        ExerciseWannaCryStrings(stringInput, result);
        break;
    case 2:
        ExerciseLockyStrings(stringInput, result);
        break;
    case 3:
        ExerciseEntropy(input, result);
        ExerciseWannaCryStrings(stringInput, result);
        ExerciseLockyStrings(stringInput, result);
        break;
    default:
        RecordValidation(result, "Ransomware analysis mode selector was outside the expected range");
        break;
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long RansomwareAnalysisHarness::SEHCallExercise(
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

HarnessResult RansomwareAnalysisHarness::Run(std::span<const uint8_t> input) {
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

HarnessFunction RansomwareAnalysisHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view RansomwareAnalysisHarness::GetName() noexcept {
    return "ransomware-analysis";
}

std::string_view RansomwareAnalysisHarness::GetDescription() noexcept {
    return "Ransomware analysis fuzz harness for ShadowStrike entropy, WannaCry, and Locky detectors";
}

int RunRansomwareAnalysisFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[RansomwareAnalysisFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "ransomware-analysis";
    const auto crashDir = workspaceDir / "crashes" / "ransomware-analysis";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[RansomwareAnalysisFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[RansomwareAnalysisFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(RansomwareAnalysisHarness::GetName());

    std::cout << "[RansomwareAnalysisFuzzer] Starting ransomware analysis fuzzing...\n";
    std::cout << "[RansomwareAnalysisFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[RansomwareAnalysisFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(
        corpusDir,
        crashDir,
        RansomwareAnalysisHarness::GetHarnessFunction(),
        loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[RansomwareAnalysisFuzzer] Final Results:\n";
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
