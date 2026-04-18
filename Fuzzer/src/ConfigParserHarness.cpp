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
 * @file ConfigParserHarness.cpp
 * @brief Implementation of the configuration and policy parser fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ConfigParserHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#if __has_include("Config/ConfigManager.hpp")
#include "Config/ConfigManager.hpp"
#include "Config/PolicyManager.hpp"
#else
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Config/PolicyManager.hpp"
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
#include <mutex>
#include <string>
#include <string_view>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSConfig = ShadowStrike::Config;

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

[[nodiscard]] std::span<const uint8_t> GetPayloadSpan(const uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return {};
    }

    return std::span<const uint8_t>(data, size).subspan(1);
}

[[nodiscard]] std::string BuildPayloadString(std::span<const uint8_t> payload) {
    if (payload.empty()) {
        return {};
    }

    return std::string(
        reinterpret_cast<const char*>(payload.data()),
        payload.size());
}

[[nodiscard]] bool EnsureConfigManagersInitialized(HarnessResult& result) {
    static std::once_flag configInitOnce;
    static std::once_flag policyInitOnce;
    static bool configReady = false;
    static bool policyReady = false;

    std::call_once(configInitOnce, [] {
        auto& manager = SSConfig::ConfigManager::Instance();
        SSConfig::ConfigManagerConfiguration config{};
        configReady = manager.IsInitialized() || manager.Initialize(config);
    });
    if (!configReady) {
        RecordValidationIssue(result, "ConfigManager initialization failed.");
        return false;
    }

    std::call_once(policyInitOnce, [] {
        auto& manager = SSConfig::PolicyManager::Instance();
        SSConfig::PolicyManagerConfiguration config{};
        config.enableAutoSync = false;
        config.enableOfflineCache = false;
        policyReady = manager.IsInitialized() || manager.Initialize(config);
    });
    if (!policyReady) {
        RecordValidationIssue(result, "PolicyManager initialization failed.");
        return false;
    }

    return true;
}

}  // namespace

std::string ConfigParserHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool ConfigParserHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const uint8_t modeSelector = (data != nullptr && size != 0) ? data[0] : 0;
    const std::span<const uint8_t> payload = GetPayloadSpan(data, size);
    const std::string payloadText = BuildPayloadString(payload);

    if (!EnsureConfigManagersInitialized(result)) {
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.parseTimeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
        return false;
    }

    switch (modeSelector % 3U) {
    case 0: {
        auto& manager = SSConfig::ConfigManager::Instance();
        manager.ResetToDefaults(SSConfig::ConfigLayer::Session);
        result.parsedOk = manager.ImportFromJson(payloadText, SSConfig::ConfigLayer::Session);
        if (!result.parsedOk) {
            RecordValidationIssue(result, "ConfigManager::ImportFromJson rejected the payload.");
        }
        break;
    }
    case 1: {
        const auto policy = SSConfig::ParsePolicyFromJson(payloadText);
        result.parsedOk = policy.has_value();
        if (policy.has_value() && !policy->settings.empty()) {
            ++result.anomalyCount;
        } else if (!result.parsedOk) {
            RecordValidationIssue(result, "ParsePolicyFromJson rejected the payload.");
        }
        break;
    }
    case 2:
    default: {
        const auto policy = SSConfig::ParsePolicyFromXml(payloadText);
        result.parsedOk = policy.has_value();
        if (policy.has_value() && !policy->settings.empty()) {
            ++result.anomalyCount;
        } else if (!result.parsedOk) {
            RecordValidationIssue(result, "ParsePolicyFromXml rejected the payload.");
        }
        break;
    }
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long ConfigParserHarness::SEHCallExercise(
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

HarnessResult ConfigParserHarness::Run(std::span<const uint8_t> input) {
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

HarnessFunction ConfigParserHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view ConfigParserHarness::GetName() noexcept {
    return "config-parser";
}

std::string_view ConfigParserHarness::GetDescription() noexcept {
    return "Configuration and policy parser fuzz harness for ShadowStrike NGAV";
}

int RunConfigParserFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ConfigParserFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "config-parser";
    const auto crashDir = workspaceDir / "crashes" / "config-parser";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ConfigParserFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ConfigParserFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ConfigParserHarness::GetName());

    std::cout << "[ConfigParserFuzzer] Starting configuration/policy fuzzing...\n";
    std::cout << "[ConfigParserFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ConfigParserFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ConfigParserHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ConfigParserFuzzer] Final Results:\n";
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
