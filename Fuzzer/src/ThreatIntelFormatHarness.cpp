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
 * @file ThreatIntelFormatHarness.cpp
 * @brief Implementation of the ThreatIntel format parser fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ThreatIntelFormatHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "ThreatIntel/ThreatIntelFormat.hpp"

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

namespace SSFormat = ShadowStrike::ThreatIntel::Format;
using ShadowStrike::ThreatIntel::HashAlgorithm;
using ShadowStrike::ThreatIntel::HashValue;
using ShadowStrike::ThreatIntel::IPv4Address;
using ShadowStrike::ThreatIntel::IPv6Address;
using ShadowStrike::ThreatIntel::MemoryMappedView;
using ShadowStrike::ThreatIntel::StoreError;
using ShadowStrike::ThreatIntel::THREATINTEL_DB_MAGIC;
using ShadowStrike::ThreatIntel::THREATINTEL_DB_VERSION_MAJOR;
using ShadowStrike::ThreatIntel::THREATINTEL_DB_VERSION_MINOR;
using ShadowStrike::ThreatIntel::ThreatIntelDatabaseHeader;

constexpr std::array<HashAlgorithm, 11> kHashAlgorithms{
    HashAlgorithm::MD5,
    HashAlgorithm::SHA1,
    HashAlgorithm::SHA256,
    HashAlgorithm::SHA512,
    HashAlgorithm::SHA3_256,
    HashAlgorithm::SHA3_512,
    HashAlgorithm::FUZZY,
    HashAlgorithm::TLSH,
    HashAlgorithm::ImpHash,
    HashAlgorithm::TypeHash,
    HashAlgorithm::Authentihash,
};

[[nodiscard]] bool IsHexEncodedHashAlgorithm(HashAlgorithm algorithm) noexcept {
    switch (algorithm) {
    case HashAlgorithm::MD5:
    case HashAlgorithm::SHA1:
    case HashAlgorithm::SHA256:
    case HashAlgorithm::SHA512:
    case HashAlgorithm::SHA3_256:
    case HashAlgorithm::SHA3_512:
    case HashAlgorithm::ImpHash:
    case HashAlgorithm::TypeHash:
    case HashAlgorithm::Authentihash:
        return true;
    case HashAlgorithm::FUZZY:
    case HashAlgorithm::TLSH:
        return false;
    }

    return false;
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

void AppendDetail(HarnessResult& result, std::string_view prefix, std::string_view detail) {
    if (!result.errorMessage.empty()) {
        return;
    }

    result.errorMessage.assign(prefix.data(), prefix.size());
    if (!detail.empty()) {
        result.errorMessage += ": ";
        result.errorMessage.append(detail.data(), detail.size());
    }
}

template <typename Fn>
void ExecuteSafely(
    HarnessResult& result,
    std::string_view stage,
    Fn&& fn)
{
    try {
        fn();
    }
    catch (const std::exception& ex) {
        std::string message(stage);
        message += " threw C++ exception: ";
        message += ex.what();
        RecordValidationIssue(result, message);
    }
    catch (...) {
        std::string message(stage);
        message += " threw a non-standard C++ exception.";
        RecordValidationIssue(result, message);
    }
}

void AddCandidate(
    std::vector<std::string_view>& candidates,
    std::string_view candidate)
{
    if (candidate.empty()) {
        return;
    }

    for (const std::string_view existing : candidates) {
        if (existing == candidate) {
            return;
        }
    }

    candidates.push_back(candidate);
}

[[nodiscard]] std::vector<std::string_view> BuildCandidates(std::string_view inputText) {
    std::vector<std::string_view> candidates;
    candidates.reserve(8);

    AddCandidate(candidates, inputText);

    if (inputText.size() > 18) {
        AddCandidate(candidates, inputText.substr(0, 18));
    }
    if (inputText.size() > 43) {
        AddCandidate(candidates, inputText.substr(0, 43));
    }
    if (inputText.size() > 64) {
        AddCandidate(candidates, inputText.substr(0, 64));
    }
    if (inputText.size() > 128) {
        AddCandidate(candidates, inputText.substr(0, 128));
    }

    const size_t firstSeparator = inputText.find_first_of(" \t\r\n");
    if (firstSeparator != std::string_view::npos && firstSeparator != 0) {
        AddCandidate(candidates, inputText.substr(0, firstSeparator));
    }

    if (inputText.size() > 32) {
        const size_t middle = inputText.size() / 2;
        const size_t remaining = inputText.size() - middle;
        AddCandidate(candidates, inputText.substr(middle, std::min<size_t>(remaining, 64)));
    }

    return candidates;
}

void ExerciseIPv4Parsing(std::string_view candidate, HarnessResult& result) {
    const auto parsed = SSFormat::ParseIPv4(candidate);
    const bool valid = SSFormat::IsValidIPv4(candidate);

    uint8_t octets[4]{};
    const bool safeParsed = SSFormat::SafeParseIPv4(candidate, octets);

    if (parsed.has_value()) {
        result.parsedOk = true;

        const std::string formatted = SSFormat::FormatIPv4(*parsed);
        if (formatted.empty()) {
            RecordValidationIssue(result, "FormatIPv4 returned an empty string after a successful ParseIPv4.");
        } else {
            const auto reparsed = SSFormat::ParseIPv4(formatted);
            if (!reparsed.has_value() || *reparsed != *parsed) {
                RecordValidationIssue(result, "ParseIPv4 and FormatIPv4 did not round-trip consistently.");
            }
        }

        if (!valid) {
            RecordValidationIssue(result, "ParseIPv4 succeeded while IsValidIPv4 rejected the same candidate.");
        }

        if (candidate.find('/') == std::string_view::npos && !safeParsed) {
            RecordValidationIssue(result, "ParseIPv4 accepted a host address that SafeParseIPv4 rejected.");
        }
    } else if (valid) {
        RecordValidationIssue(result, "IsValidIPv4 accepted a candidate that ParseIPv4 rejected.");
    }
}

void ExerciseIPv6Parsing(std::string_view candidate, HarnessResult& result) {
    const auto parsed = SSFormat::ParseIPv6(candidate);
    const bool valid = SSFormat::IsValidIPv6(candidate);

    uint16_t segments[8]{};
    const bool safeParsed = SSFormat::SafeParseIPv6(candidate, segments);

    if (parsed.has_value()) {
        result.parsedOk = true;

        const std::string formatted = SSFormat::FormatIPv6(*parsed);
        if (formatted.empty()) {
            RecordValidationIssue(result, "FormatIPv6 returned an empty string after a successful ParseIPv6.");
        } else {
            const auto reparsed = SSFormat::ParseIPv6(formatted);
            if (!reparsed.has_value()) {
                RecordValidationIssue(result, "ParseIPv6 rejected the output of FormatIPv6.");
            }
        }

        if (!valid) {
            RecordValidationIssue(result, "ParseIPv6 succeeded while IsValidIPv6 rejected the same candidate.");
        }

        if (candidate.find('/') == std::string_view::npos && !safeParsed) {
            RecordValidationIssue(result, "ParseIPv6 accepted an address that SafeParseIPv6 rejected.");
        }
    } else if (valid) {
        RecordValidationIssue(result, "IsValidIPv6 accepted a candidate that ParseIPv6 rejected.");
    }
}

void ExerciseHashParsing(std::string_view candidate, HarnessResult& result) {
    for (const HashAlgorithm algorithm : kHashAlgorithms) {
        const auto parsed = SSFormat::ParseHashString(candidate, algorithm);
        if (!parsed.has_value()) {
            continue;
        }

        result.parsedOk = true;

        if (!parsed->IsValid()) {
            RecordValidationIssue(result, "ParseHashString returned a HashValue that failed HashValue::IsValid.");
        }

        const std::string formatted = SSFormat::FormatHashString(*parsed);
        if (formatted.empty()) {
            RecordValidationIssue(result, "FormatHashString returned an empty string after a successful ParseHashString.");
            continue;
        }

        if (IsHexEncodedHashAlgorithm(algorithm) && !SSFormat::IsValidFileHash(formatted)) {
            RecordValidationIssue(result, "FormatHashString produced a string that IsValidFileHash rejected.");
        }

        const auto reparsed = SSFormat::ParseHashString(formatted, algorithm);
        if (!reparsed.has_value() || *reparsed != *parsed) {
            RecordValidationIssue(result, "ParseHashString and FormatHashString did not round-trip consistently.");
        }
    }
}

void ExerciseStringValidators(std::string_view candidate, HarnessResult& result) {
    const std::string normalizedDomain = SSFormat::NormalizeDomain(candidate);
    const std::string normalizedDomainName = SSFormat::NormalizeDomainName(candidate);
    if (normalizedDomain != normalizedDomainName) {
        RecordValidationIssue(result, "NormalizeDomain and NormalizeDomainName diverged.");
    }

    const auto labels = SSFormat::SplitDomainLabels(candidate);
    const auto labelViews = SSFormat::SplitDomainLabelsView(candidate);
    if (labels.size() != labelViews.size()) {
        RecordValidationIssue(result, "SplitDomainLabels and SplitDomainLabelsView returned different label counts.");
    }

    const bool validDomain = SSFormat::IsValidDomain(candidate);
    if (validDomain) {
        result.parsedOk = true;
        if (normalizedDomain.empty()) {
            RecordValidationIssue(result, "NormalizeDomain returned an empty string for a valid domain.");
        } else if (!SSFormat::IsValidDomain(normalizedDomain)) {
            RecordValidationIssue(result, "NormalizeDomain produced a domain that failed validation.");
        }
    }

    const std::string normalizedUrl = SSFormat::NormalizeURL(candidate);
    const bool validUrl = SSFormat::IsValidURL(candidate);
    if (validUrl) {
        result.parsedOk = true;
        if (normalizedUrl.empty()) {
            RecordValidationIssue(result, "NormalizeURL returned an empty string for a valid URL.");
        } else if (!SSFormat::IsValidURL(normalizedUrl)) {
            RecordValidationIssue(result, "NormalizeURL produced a URL that failed validation.");
        }
    }

    if (SSFormat::IsValidEmail(candidate)) {
        result.parsedOk = true;
    }

    if (SSFormat::IsValidFileHash(candidate)) {
        result.parsedOk = true;
    }
}

void ExerciseTimestampAndUuid(std::string_view candidate, HarnessResult& result) {
    const auto parsedTimestamp = SSFormat::ParseSTIXTimestamp(candidate);
    if (parsedTimestamp.has_value()) {
        result.parsedOk = true;

        const std::string formatted = SSFormat::FormatSTIXTimestamp(*parsedTimestamp);
        if (formatted.empty()) {
            RecordValidationIssue(result, "FormatSTIXTimestamp returned an empty string after a successful ParseSTIXTimestamp.");
        } else {
            const auto reparsed = SSFormat::ParseSTIXTimestamp(formatted);
            if (!reparsed.has_value() || *reparsed != *parsedTimestamp) {
                RecordValidationIssue(result, "ParseSTIXTimestamp and FormatSTIXTimestamp did not round-trip consistently.");
            }
        }
    }

    const auto parsedUuid = SSFormat::ParseUUID(candidate);
    if (parsedUuid.has_value()) {
        result.parsedOk = true;

        const std::string formatted = SSFormat::FormatUUID(*parsedUuid);
        const auto reparsed = SSFormat::ParseUUID(formatted);
        if (!reparsed.has_value() || *reparsed != *parsedUuid) {
            RecordValidationIssue(result, "ParseUUID and FormatUUID did not round-trip consistently.");
        }
    }

    const std::array<uint8_t, 16> generatedUuid = SSFormat::GenerateUUID();
    const std::string generatedUuidText = SSFormat::FormatUUID(generatedUuid);
    const auto reparsedGeneratedUuid = SSFormat::ParseUUID(generatedUuidText);
    if (!reparsedGeneratedUuid.has_value() || *reparsedGeneratedUuid != generatedUuid) {
        RecordValidationIssue(result, "GenerateUUID produced a value that failed a format/parse round-trip.");
    }
}

[[nodiscard]] ThreatIntelDatabaseHeader BuildBaselineHeader(uint64_t fileSize) {
    ThreatIntelDatabaseHeader header{};
    header.magic = THREATINTEL_DB_MAGIC;
    header.versionMajor = THREATINTEL_DB_VERSION_MAJOR;
    header.versionMinor = THREATINTEL_DB_VERSION_MINOR;
    header.databaseUuid = SSFormat::GenerateUUID();
    header.creationTime = 1735689600ULL;
    header.lastUpdateTime = header.creationTime;
    header.buildNumber = 1;
    header.recommendedCacheSize = 64;
    header.totalFileSize = fileSize;
    header.headerCrc32 = SSFormat::ComputeHeaderCRC32(&header);
    return header;
}

[[nodiscard]] MemoryMappedView MakeSyntheticView(std::vector<uint8_t>& storage) noexcept {
    MemoryMappedView view{};
    view.fileHandle = reinterpret_cast<HANDLE>(static_cast<intptr_t>(1));
    view.mappingHandle = reinterpret_cast<HANDLE>(static_cast<intptr_t>(1));
    view.baseAddress = storage.empty() ? nullptr : storage.data();
    view.fileSize = storage.size();
    view.readOnly = true;
    return view;
}

void ExerciseHeaderValidation(HarnessResult& result) {
    std::vector<uint8_t> validStorage(sizeof(ThreatIntelDatabaseHeader));
    ThreatIntelDatabaseHeader baselineHeader = BuildBaselineHeader(validStorage.size());
    std::memcpy(validStorage.data(), &baselineHeader, sizeof(baselineHeader));

    const auto* validHeader = reinterpret_cast<const ThreatIntelDatabaseHeader*>(validStorage.data());
    if (!SSFormat::ValidateHeader(validHeader)) {
        RecordValidationIssue(result, "ValidateHeader rejected a baseline header that satisfies declared invariants.");
    }

    MemoryMappedView validView = MakeSyntheticView(validStorage);
    if (validView.GetAt<ThreatIntelDatabaseHeader>(0) == nullptr) {
        RecordValidationIssue(result, "MemoryMappedView::GetAt failed on a valid baseline header.");
    }
    if (validView.GetSpan(0, sizeof(ThreatIntelDatabaseHeader)).size() != sizeof(ThreatIntelDatabaseHeader)) {
        RecordValidationIssue(result, "MemoryMappedView::GetSpan returned an unexpected span size.");
    }

    std::array<uint8_t, 32> computedChecksum{};
    if (!SSFormat::ComputeDatabaseChecksum(validView, computedChecksum)) {
        RecordValidationIssue(result, "ComputeDatabaseChecksum failed on a valid synthetic database buffer.");
    }

    StoreError verifyError = StoreError::Success();
    if (!SSFormat::VerifyIntegrity(validView, verifyError)) {
        RecordValidationIssue(result, "VerifyIntegrity rejected a valid synthetic database buffer.");
        AppendDetail(result, "VerifyIntegrity", verifyError.GetFullMessage());
    } else {
        result.parsedOk = true;
    }

    {
        std::vector<uint8_t> invalidStorage = validStorage;
        auto* invalidHeader = reinterpret_cast<ThreatIntelDatabaseHeader*>(invalidStorage.data());
        invalidHeader->magic ^= 0xFFFFFFFFu;

        StoreError invalidError = StoreError::Success();
        if (SSFormat::VerifyIntegrity(MakeSyntheticView(invalidStorage), invalidError)) {
            RecordAnomaly(result, "VerifyIntegrity accepted a header with an invalid magic number.");
        }
    }

    {
        std::vector<uint8_t> invalidStorage = validStorage;
        auto* invalidHeader = reinterpret_cast<ThreatIntelDatabaseHeader*>(invalidStorage.data());
        invalidHeader->ipv4IndexOffset = 1;
        invalidHeader->headerCrc32 = SSFormat::ComputeHeaderCRC32(invalidHeader);

        if (SSFormat::ValidateHeader(invalidHeader)) {
            RecordAnomaly(result, "ValidateHeader accepted a header with an unaligned section offset.");
        }
    }

    {
        std::vector<uint8_t> invalidStorage = validStorage;
        auto* invalidHeader = reinterpret_cast<ThreatIntelDatabaseHeader*>(invalidStorage.data());
        invalidHeader->totalFileSize = invalidStorage.size() + 1;
        invalidHeader->headerCrc32 = SSFormat::ComputeHeaderCRC32(invalidHeader);

        StoreError invalidError = StoreError::Success();
        if (SSFormat::VerifyIntegrity(MakeSyntheticView(invalidStorage), invalidError)) {
            RecordAnomaly(result, "VerifyIntegrity accepted a header with a mismatched totalFileSize.");
        }
    }

    {
        std::vector<uint8_t> invalidStorage = validStorage;
        auto* invalidHeader = reinterpret_cast<ThreatIntelDatabaseHeader*>(invalidStorage.data());
        invalidHeader->headerCrc32 ^= 0xFFFFFFFFu;

        StoreError invalidError = StoreError::Success();
        if (SSFormat::VerifyIntegrity(MakeSyntheticView(invalidStorage), invalidError)) {
            RecordAnomaly(result, "VerifyIntegrity accepted a header with a corrupted CRC32 value.");
        }
    }
}

}  // namespace

std::string ThreatIntelFormatHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool ThreatIntelFormatHarness::ExerciseFormatImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::string_view inputText = (data != nullptr && size != 0)
        ? std::string_view(reinterpret_cast<const char*>(data), size)
        : std::string_view{};

    const std::vector<std::string_view> candidates = BuildCandidates(inputText);
    for (const std::string_view candidate : candidates) {
        ExecuteSafely(result, "ExerciseIPv4Parsing", [&]() { ExerciseIPv4Parsing(candidate, result); });
        ExecuteSafely(result, "ExerciseIPv6Parsing", [&]() { ExerciseIPv6Parsing(candidate, result); });
        ExecuteSafely(result, "ExerciseHashParsing", [&]() { ExerciseHashParsing(candidate, result); });
        ExecuteSafely(result, "ExerciseStringValidators", [&]() { ExerciseStringValidators(candidate, result); });
        ExecuteSafely(result, "ExerciseTimestampAndUuid", [&]() { ExerciseTimestampAndUuid(candidate, result); });
    }

    ExecuteSafely(result, "ExerciseHeaderValidation", [&]() { ExerciseHeaderValidation(result); });

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long ThreatIntelFormatHarness::SEHCallFormat(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExerciseFormatImpl(data, size, *pResult);
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

HarnessResult ThreatIntelFormatHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallFormat(
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

HarnessFunction ThreatIntelFormatHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view ThreatIntelFormatHarness::GetName() noexcept {
    return "threatintel-format";
}

std::string_view ThreatIntelFormatHarness::GetDescription() noexcept {
    return "ThreatIntel format parser and integrity fuzz harness";
}

int RunThreatIntelFormatFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ThreatIntelFormatFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "threatintel-format";
    const auto crashDir = workspaceDir / "crashes" / "threatintel-format";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ThreatIntelFormatFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ThreatIntelFormatFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ThreatIntelFormatHarness::GetName());

    std::cout << "[ThreatIntelFormatFuzzer] Starting ThreatIntel format fuzzing...\n";
    std::cout << "[ThreatIntelFormatFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ThreatIntelFormatFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(
        corpusDir,
        crashDir,
        ThreatIntelFormatHarness::GetHarnessFunction(),
        loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ThreatIntelFormatFuzzer] Final Results:\n";
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
