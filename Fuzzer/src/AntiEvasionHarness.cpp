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
 * @file AntiEvasionHarness.cpp
 * @brief Implementation of the anti-evasion detector fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/AntiEvasionHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#if __has_include("AntiEvasion/PackerDetector.hpp")
#include "AntiEvasion/PackerDetector.hpp"
#include "AntiEvasion/VMEvasionDetector.hpp"
#else
#include "PhantomCore/AntiEvasion/PackerDetector.hpp"
#include "PhantomCore/AntiEvasion/VMEvasionDetector.hpp"
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
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSAntiEvasion = ShadowStrike::AntiEvasion;

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

void CaptureFirstIssue(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

[[nodiscard]] std::string NarrowWide(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);
    if (written <= 0) {
        return {};
    }

    return result;
}

[[nodiscard]] std::span<const uint8_t> GetPayloadSpan(const uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return {};
    }

    return std::span<const uint8_t>(data, size).subspan(1);
}

[[nodiscard]] SSAntiEvasion::PackerDetector& GetPackerDetector() {
    static SSAntiEvasion::PackerDetector detector;
    return detector;
}

[[nodiscard]] bool EnsurePackerDetectorInitialized(HarnessResult& result) {
    static std::once_flag initOnce;
    static bool initialized = false;
    static std::string initError;

    std::call_once(initOnce, [] {
        SSAntiEvasion::PackerError error{};
        auto& detector = GetPackerDetector();
        initialized = detector.IsInitialized() || detector.Initialize(&error);
        if (!initialized) {
            initError = NarrowWide(error.context);
            if (!error.message.empty()) {
                if (!initError.empty()) {
                    initError += ": ";
                }
                initError += NarrowWide(error.message);
            }
            if (initError.empty()) {
                initError = "PackerDetector initialization failed.";
            }
        }
    });

    if (!initialized) {
        RecordValidationIssue(result, initError);
    }
    return initialized;
}

[[nodiscard]] SSAntiEvasion::VMEvasionDetector& GetVMEvasionDetector() {
    static std::once_flag initOnce;
    static std::unique_ptr<SSAntiEvasion::VMEvasionDetector> detector;

    std::call_once(initOnce, [] {
        detector = std::make_unique<SSAntiEvasion::VMEvasionDetector>();
    });

    return *detector;
}

}  // namespace

std::string AntiEvasionHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool AntiEvasionHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const uint8_t modeSelector = (data != nullptr && size != 0) ? data[0] : 0;
    const std::span<const uint8_t> payload = GetPayloadSpan(data, size);

    switch (modeSelector % 2U) {
    case 0: {
        if (!EnsurePackerDetectorInitialized(result)) {
            break;
        }

        SSAntiEvasion::PackerAnalysisConfig config{};
        SSAntiEvasion::PackerError error{};
        const auto packingInfo = GetPackerDetector().AnalyzeBuffer(
            payload.empty() ? nullptr : payload.data(),
            payload.size(),
            config,
            &error);

        result.parsedOk = !error.HasError();
        if (error.HasError()) {
            std::string message = NarrowWide(error.context);
            if (!error.message.empty()) {
                if (!message.empty()) {
                    message += ": ";
                }
                message += NarrowWide(error.message);
            }
            if (message.empty()) {
                message = "PackerDetector::AnalyzeBuffer reported an error.";
            }
            RecordValidationIssue(result, message);
        } else if (packingInfo.isPacked || packingInfo.packingConfidence > 0.0) {
            ++result.anomalyCount;
        }
        break;
    }
    case 1:
    default: {
        SSAntiEvasion::CodeAnalysisResult analysis{};
        SSAntiEvasion::ExtendedAnalysisConfig config{};
        result.parsedOk = GetVMEvasionDetector().AnalyzeCodeBuffer(
            payload,
            0x400000ULL,
            true,
            analysis,
            config);
        if (!result.parsedOk) {
            RecordValidationIssue(result, "VMEvasionDetector::AnalyzeCodeBuffer rejected the payload.");
        } else if (analysis.evasionScore > 0.0f || !analysis.antiVMInstructions.empty()) {
            ++result.anomalyCount;
        }
        break;
    }
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long AntiEvasionHarness::SEHCallExercise(
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

HarnessResult AntiEvasionHarness::Run(std::span<const uint8_t> input) {
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

HarnessFunction AntiEvasionHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view AntiEvasionHarness::GetName() noexcept {
    return "anti-evasion";
}

std::string_view AntiEvasionHarness::GetDescription() noexcept {
    return "Anti-evasion detector fuzz harness for ShadowStrike NGAV";
}

int RunAntiEvasionFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[AntiEvasionFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "anti-evasion";
    const auto crashDir = workspaceDir / "crashes" / "anti-evasion";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[AntiEvasionFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[AntiEvasionFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(AntiEvasionHarness::GetName());

    std::cout << "[AntiEvasionFuzzer] Starting anti-evasion fuzzing...\n";
    std::cout << "[AntiEvasionFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[AntiEvasionFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, AntiEvasionHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[AntiEvasionFuzzer] Final Results:\n";
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
