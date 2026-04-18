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
 * @file AIFeatureHarness.cpp
 * @brief Implementation of the AI feature extraction fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/AIFeatureHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#if __has_include("AI/FeatureExtractor.hpp")
#include "AI/FeatureExtractor.hpp"
#else
#include "PhantomCore/AI/FeatureExtractor.hpp"
#endif

#if __has_include("AI/CortexTypes.hpp")
#include "AI/CortexTypes.hpp"
#else
#include "PhantomCore/AI/CortexTypes.hpp"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <malloc.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSAI = ShadowStrike::AI;

constexpr unsigned long kSehSuccess = 0UL;
constexpr unsigned long kSehInvalidParameter = 0xC000000DUL;
constexpr size_t kBehaviorRecordSize = 16;
constexpr size_t kMemoryHeaderSize = sizeof(uint64_t) + sizeof(uint32_t);
constexpr size_t kEmulationEventSize = 6;

SRWLOCK& HarnessLock() noexcept {
    static SRWLOCK lock = SRWLOCK_INIT;
    return lock;
}

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

void SetFirstError(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidation(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    SetFirstError(result, message);
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    SetFirstError(result, message);
}

template <typename T>
[[nodiscard]] T CopyValue(std::span<const uint8_t> input, size_t offset) noexcept {
    T value{};
    if (offset >= input.size()) {
        return value;
    }

    const size_t copySize = std::min(sizeof(T), input.size() - offset);
    std::memcpy(&value, input.data() + offset, copySize);
    return value;
}

[[nodiscard]] bool EnsureFeatureExtractorInitialized(HarnessResult& result) {
    static std::once_flag initOnce;
    static bool initialized = false;

    std::call_once(initOnce, []() {
        initialized = SSAI::FeatureExtractor::Instance().Initialize();
    });

    if (!initialized) {
        RecordValidation(result, "FeatureExtractor::Initialize failed");
    }

    return initialized;
}

[[nodiscard]] std::vector<SSAI::APICallRecord> BuildBehavioralRecords(std::span<const uint8_t> input) {
    const size_t recordCount = std::min(
        input.size() / kBehaviorRecordSize,
        static_cast<size_t>(SSAI::CortexConstants::MAX_API_SEQUENCE_LENGTH));

    std::vector<SSAI::APICallRecord> records;
    records.reserve(recordCount);

    for (size_t index = 0; index < recordCount; ++index) {
        const size_t offset = index * kBehaviorRecordSize;
        SSAI::APICallRecord record{};
        std::memcpy(&record.apiNameHash, input.data() + offset + 0, sizeof(record.apiNameHash));
        std::memcpy(&record.argSummaryHash, input.data() + offset + 4, sizeof(record.argSummaryHash));
        std::memcpy(&record.returnValue, input.data() + offset + 8, sizeof(record.returnValue));
        std::memcpy(&record.timestampDeltaMs, input.data() + offset + 12, sizeof(record.timestampDeltaMs));
        records.push_back(record);
    }

    return records;
}

[[nodiscard]] SSAI::MemoryRegionInfo BuildMemoryRegion(std::span<const uint8_t> input) noexcept {
    const std::span<const uint8_t> regionData =
        input.size() > kMemoryHeaderSize ? input.subspan(kMemoryHeaderSize) : std::span<const uint8_t>{};

    SSAI::MemoryRegionInfo region{};
    region.baseAddress = static_cast<uintptr_t>(CopyValue<uint64_t>(input, 0));
    region.protection = CopyValue<uint32_t>(input, sizeof(uint64_t));
    region.data = regionData;
    region.size = regionData.size();
    return region;
}

[[nodiscard]] SSAI::NetworkFlowInfo BuildNetworkFlow(std::span<const uint8_t> input) noexcept {
    SSAI::NetworkFlowInfo flow{};
    if (!input.empty()) {
        const size_t copySize = std::min(sizeof(flow), input.size());
        std::memcpy(&flow, input.data(), copySize);
    }
    return flow;
}

[[nodiscard]] std::vector<SSAI::EmulationEvent> BuildEmulationEvents(std::span<const uint8_t> input) {
    const size_t eventCount = std::min(
        input.size() / kEmulationEventSize,
        static_cast<size_t>(SSAI::CortexConstants::EMULATION_SEQ_LENGTH));

    std::vector<SSAI::EmulationEvent> events;
    events.reserve(eventCount);

    for (size_t index = 0; index < eventCount; ++index) {
        const size_t offset = index * kEmulationEventSize;
        SSAI::EmulationEvent event{};
        std::memcpy(&event.opcodeCategory, input.data() + offset + 0, sizeof(event.opcodeCategory));
        std::memcpy(&event.memoryAccessType, input.data() + offset + 2, sizeof(event.memoryAccessType));
        std::memcpy(&event.apiCallId, input.data() + offset + 3, sizeof(event.apiCallId));
        std::memcpy(&event.eflagsChange, input.data() + offset + 5, sizeof(event.eflagsChange));
        events.push_back(event);
    }

    return events;
}

template <typename ResultT>
void ValidateExtractionResult(
    std::string_view name,
    const std::optional<ResultT>& extractionResult,
    size_t expectedSize,
    HarnessResult& result,
    bool& anySucceeded)
{
    if (!extractionResult.has_value()) {
        RecordAnomaly(result, std::string(name) + " returned std::nullopt");
        return;
    }

    anySucceeded = true;
    if (extractionResult->size() != expectedSize) {
        std::ostringstream stream;
        stream << name << " returned " << extractionResult->size()
               << " features; expected " << expectedSize;
        RecordValidation(result, stream.str());
    }
}

void ExercisePEFeatures(std::span<const uint8_t> input, HarnessResult& result, bool& anySucceeded) {
    auto peFeatures = SSAI::FeatureExtractor::Instance().ExtractPEFeatures(input);
    ValidateExtractionResult(
        "ExtractPEFeatures",
        peFeatures,
        SSAI::CortexConstants::STATIC_FEATURE_COUNT,
        result,
        anySucceeded);
}

void ExerciseBehavioralFeatures(std::span<const uint8_t> input, HarnessResult& result, bool& anySucceeded) {
    const auto apiCalls = BuildBehavioralRecords(input);
    auto behavioralFeatures = SSAI::FeatureExtractor::Instance().ExtractBehavioralFeatures(apiCalls);
    ValidateExtractionResult(
        "ExtractBehavioralFeatures",
        behavioralFeatures,
        SSAI::CortexConstants::BEHAVIORAL_FEATURE_COUNT,
        result,
        anySucceeded);
}

void ExerciseMemoryFeatures(std::span<const uint8_t> input, HarnessResult& result, bool& anySucceeded) {
    const SSAI::MemoryRegionInfo region = BuildMemoryRegion(input);
    auto memoryFeatures = SSAI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    ValidateExtractionResult(
        "ExtractMemoryFeatures",
        memoryFeatures,
        SSAI::CortexConstants::MEMORY_FEATURE_COUNT,
        result,
        anySucceeded);
}

void ExerciseNetworkFeatures(std::span<const uint8_t> input, HarnessResult& result, bool& anySucceeded) {
    const SSAI::NetworkFlowInfo flow = BuildNetworkFlow(input);
    auto networkFeatures = SSAI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    ValidateExtractionResult(
        "ExtractNetworkFeatures",
        networkFeatures,
        SSAI::CortexConstants::NETWORK_FEATURE_COUNT,
        result,
        anySucceeded);
}

void ExerciseEmulationFeatures(std::span<const uint8_t> input, HarnessResult& result, bool& anySucceeded) {
    const auto events = BuildEmulationEvents(input);
    auto emulationFeatures = SSAI::FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    ValidateExtractionResult(
        "ExtractEmulationFeatures",
        emulationFeatures,
        SSAI::CortexConstants::EMULATION_FEATURE_COUNT,
        result,
        anySucceeded);
}

}  // namespace

std::string AIFeatureHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool AIFeatureHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input(data, size);

    if (!EnsureFeatureExtractorInitialized(result)) {
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.parseTimeNs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
        return false;
    }

    bool anySucceeded = false;
    const uint8_t selector = input.empty() ? 0u : static_cast<uint8_t>(input[0] % 5u);

    for (size_t lane = 0; lane < 5; ++lane) {
        switch ((selector + lane) % 5u) {
        case 0u:
            ExercisePEFeatures(input, result, anySucceeded);
            break;
        case 1u:
            ExerciseBehavioralFeatures(input, result, anySucceeded);
            break;
        case 2u:
            ExerciseMemoryFeatures(input, result, anySucceeded);
            break;
        case 3u:
            ExerciseNetworkFeatures(input, result, anySucceeded);
            break;
        default:
            ExerciseEmulationFeatures(input, result, anySucceeded);
            break;
        }
    }

    result.parsedOk = anySucceeded;

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long AIFeatureHarness::SEHCallExercise(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    if (pResult == nullptr) {
        return kSehInvalidParameter;
    }

    bool lockHeld = false;
    AcquireSRWLockExclusive(&HarnessLock());
    lockHeld = true;

    __try {
        __try {
            (void)ExerciseImpl(data, size, *pResult);
            return kSehSuccess;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return static_cast<unsigned long>(GetExceptionCode());
        }
    }
    __finally {
        if (lockHeld) {
            ReleaseSRWLockExclusive(&HarnessLock());
        }
    }
}

HarnessResult AIFeatureHarness::Run(std::span<const uint8_t> input) {
    HarnessResult result{};

    try {
        const unsigned long exceptionCode = SEHCallExercise(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != kSehSuccess) {
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

HarnessFunction AIFeatureHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view AIFeatureHarness::GetName() noexcept {
    return "ai-feature";
}

std::string_view AIFeatureHarness::GetDescription() noexcept {
    return "AI feature extraction fuzz harness for ShadowStrike NGAV";
}

int RunAIFeatureFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[AIFeatureFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "ai-feature";
    const auto crashDir = workspaceDir / "crashes" / "ai-feature";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[AIFeatureFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[AIFeatureFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(AIFeatureHarness::GetName());

    std::cout << "[AIFeatureFuzzer] Starting AI feature extraction fuzzing...\n";
    std::cout << "[AIFeatureFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[AIFeatureFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, AIFeatureHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[AIFeatureFuzzer] Final Results:\n";
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
