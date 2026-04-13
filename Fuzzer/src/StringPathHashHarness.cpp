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
 * @file StringPathHashHarness.cpp
 * @brief Implementation of the StringUtils/FileUtils/HashUtils fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/StringPathHashHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "Utils/FileUtils.hpp"
#include "Utils/HashUtils.hpp"
#include "Utils/StringUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSFileUtils = ShadowStrike::Utils::FileUtils;
namespace SSHashUtils = ShadowStrike::Utils::HashUtils;
namespace SSStringUtils = ShadowStrike::Utils::StringUtils;

using SSHashUtils::Algorithm;

constexpr std::array<Algorithm, 6> kAlgorithms{
    Algorithm::SHA1,
    Algorithm::SHA256,
    Algorithm::SHA384,
    Algorithm::SHA512,
    Algorithm::MD5,
    Algorithm::SHA3_256,
};

std::atomic<uint64_t> g_filesystemExerciseCounter{0};

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

template <typename Fn>
void ExecuteSafely(HarnessResult& result, std::string_view stage, Fn&& fn) {
    try {
        fn();
    } catch (const std::exception& ex) {
        std::string message(stage);
        message += " threw C++ exception: ";
        message += ex.what();
        RecordValidationIssue(result, message);
    } catch (...) {
        std::string message(stage);
        message += " threw a non-standard C++ exception.";
        RecordValidationIssue(result, message);
    }
}

[[nodiscard]] std::filesystem::path MakeIterationRoot(std::span<const uint8_t> input, uint64_t sequence) {
    const uint64_t hash = SSHashUtils::Fnv1a64(input.data(), input.size());
    std::ostringstream stream;
    stream << "shadowstrike_string_path_hash_" << GetCurrentProcessId() << '_' << sequence << '_'
           << std::hex << hash;
    return std::filesystem::temp_directory_path() / stream.str();
}

[[nodiscard]] std::optional<uint64_t> AcquireFilesystemSequence() noexcept {
    const uint64_t sequence = g_filesystemExerciseCounter.fetch_add(1, std::memory_order_relaxed);
    if ((sequence % 8ULL) != 0ULL) {
        return std::nullopt;
    }

    return sequence;
}

[[nodiscard]] std::vector<std::byte> ToByteVector(std::span<const uint8_t> input) {
    std::vector<std::byte> bytes;
    bytes.reserve(std::max<size_t>(input.size(), 1));
    if (input.empty()) {
        bytes.push_back(std::byte{0x00});
        return bytes;
    }

    for (const uint8_t byte : input) {
        bytes.push_back(static_cast<std::byte>(byte));
    }

    return bytes;
}

[[nodiscard]] std::wstring MakeReasonableWideCandidate(std::string_view inputText) {
    std::wstring wide = SSStringUtils::ToWide(inputText);
    if (!wide.empty() || inputText.empty()) {
        return wide;
    }

    static constexpr wchar_t kFallback[] = L"shadowstrike";
    return std::wstring(kFallback);
}

void ExerciseStringUtilities(std::string_view inputText, HarnessResult& result) {
    const std::wstring wide = SSStringUtils::ToWide(inputText);
    if (inputText.empty()) {
        if (!wide.empty()) {
            RecordValidationIssue(result, "ToWide returned non-empty output for empty input.");
        }
    } else if (!wide.empty()) {
        result.parsedOk = true;
        const std::string narrowRoundTrip = SSStringUtils::ToNarrow(wide);
        if (narrowRoundTrip != inputText) {
            RecordValidationIssue(result, "ToWide and ToNarrow failed to round-trip valid UTF-8.");
        }
    }

    const std::string nullTerminatedInput(inputText);
    const std::wstring legacyWide = SSStringUtils::utf8_to_wstring(nullTerminatedInput.c_str());
    if (!legacyWide.empty()) {
        result.parsedOk = true;
    }

    std::wstring working = MakeReasonableWideCandidate(inputText);
    SSStringUtils::Trim(working);
    const std::wstring joined = SSStringUtils::Join(SSStringUtils::Split(working, L":"), L":");
    if (working.find(L':') == std::wstring::npos && joined != working) {
        RecordValidationIssue(result, "Split and Join changed a delimiter-free string.");
    }

    std::wstring replacement = working;
    SSStringUtils::ReplaceAll(replacement, L"a", L"aa");
    if (replacement.empty() && !working.empty()) {
        RecordValidationIssue(result, "ReplaceAll unexpectedly cleared a non-empty string.");
    }

    const std::wstring formatted = SSStringUtils::Format(L"%ls|%zu", working.c_str(), working.size());
    if (formatted.empty()) {
        RecordValidationIssue(result, "StringUtils::Format returned an empty string for a valid format request.");
    }

    const std::string escaped = SSStringUtils::EscapeJson(inputText);
    if (escaped.empty() && !inputText.empty()) {
        RecordValidationIssue(result, "EscapeJson returned an empty string for non-empty input.");
    }
}

void ExerciseHashUtilities(std::span<const uint8_t> input, HarnessResult& result) {
    const void* dataPointer = input.empty() ? nullptr : input.data();
    const size_t dataSize = input.size();

    if (SSHashUtils::Fnv1a32(dataPointer, dataSize) == 0 && !input.empty()) {
        RecordAnomaly(result, "Fnv1a32 returned zero for non-empty input.");
    }
    if (SSHashUtils::Fnv1a64(dataPointer, dataSize) == 0 && !input.empty()) {
        RecordAnomaly(result, "Fnv1a64 returned zero for non-empty input.");
    }

    for (const Algorithm algorithm : kAlgorithms) {
        SSHashUtils::Error error{};
        std::vector<uint8_t> digest;
        if (!SSHashUtils::Compute(algorithm, dataPointer, dataSize, digest, &error)) {
            continue;
        }

        result.parsedOk = true;

        if (digest.size() != SSHashUtils::DigestSize(algorithm)) {
            RecordValidationIssue(result, "Compute returned an unexpected digest size.");
        }

        const std::string lowerHex = SSHashUtils::ToHexLower(digest);
        const std::string upperHex = SSHashUtils::ToHexUpper(digest);
        if (lowerHex.empty() || upperHex.empty()) {
            RecordValidationIssue(result, "Hex conversion failed for a computed digest.");
        }

        std::vector<uint8_t> reparsed;
        if (!SSHashUtils::FromHex(lowerHex, reparsed) || reparsed != digest) {
            RecordValidationIssue(result, "FromHex failed to round-trip a lowercase digest.");
        }

        SSHashUtils::Hasher hasher(algorithm);
        if (!hasher.Init(&error)) {
            RecordValidationIssue(result, "Hasher::Init failed after one-shot Compute succeeded.");
            continue;
        }

        if (!hasher.Update(dataPointer, dataSize, &error)) {
            RecordValidationIssue(result, "Hasher::Update failed after successful initialization.");
            continue;
        }

        std::string streamedHex;
        if (!hasher.FinalHex(streamedHex, false, &error) || streamedHex != lowerHex) {
            RecordValidationIssue(result, "Hasher::FinalHex disagreed with one-shot Compute + ToHexLower.");
        }
    }

    std::vector<uint8_t> oddHex;
    if (SSHashUtils::FromHex("abc", oddHex)) {
        RecordAnomaly(result, "FromHex accepted an odd-length hexadecimal string.");
    }

    static constexpr std::array<uint8_t, 16> kHmacKey{
        0x53, 0x68, 0x61, 0x64, 0x6F, 0x77, 0x53, 0x74,
        0x72, 0x69, 0x6B, 0x65, 0x4B, 0x65, 0x79, 0x21
    };

    SSHashUtils::Error error{};
    std::vector<uint8_t> oneShotMac;
    if (SSHashUtils::ComputeHmac(
            Algorithm::SHA256,
            kHmacKey.data(),
            kHmacKey.size(),
            dataPointer,
            dataSize,
            oneShotMac,
            &error)) {
        result.parsedOk = true;

        SSHashUtils::Hmac hmac(Algorithm::SHA256);
        if (!hmac.Init(kHmacKey.data(), kHmacKey.size(), &error) ||
            !hmac.Update(dataPointer, dataSize, &error)) {
            RecordValidationIssue(result, "Streaming HMAC failed after one-shot HMAC succeeded.");
        } else {
            std::vector<uint8_t> streamedMac;
            if (!hmac.Final(streamedMac, &error) || streamedMac != oneShotMac) {
                RecordValidationIssue(result, "Streaming HMAC disagreed with one-shot HMAC.");
            }
        }
    }
}

void ExerciseFilesystemUtilities(
    std::span<const uint8_t> input,
    uint64_t sequence,
    std::string_view inputText,
    HarnessResult& result) {
    const std::filesystem::path root = MakeIterationRoot(input, sequence);
    const std::filesystem::path payloadPath = root / "payload.bin";
    const std::filesystem::path textPath = root / "payload.txt";
    const std::vector<std::byte> payload = ToByteVector(input);

    SSFileUtils::Error fileError{};
    if (!SSFileUtils::CreateDirectories(root.wstring(), &fileError)) {
        RecordValidationIssue(result, "CreateDirectories failed for the temporary filesystem workspace.");
        return;
    }

    if (!SSFileUtils::WriteAllBytesAtomic(payloadPath.wstring(), payload, &fileError)) {
        RecordValidationIssue(result, "WriteAllBytesAtomic failed for the payload file.");
        SSFileUtils::RemoveDirectoryRecursive(root.wstring(), nullptr);
        return;
    }

    if (!SSFileUtils::WriteAllTextUtf8Atomic(textPath.wstring(), std::string(inputText), &fileError)) {
        RecordValidationIssue(result, "WriteAllTextUtf8Atomic failed for the payload text file.");
    }

    std::vector<std::byte> readBack;
    if (!SSFileUtils::ReadAllBytes(payloadPath.wstring(), readBack, &fileError) || readBack != payload) {
        RecordValidationIssue(result, "ReadAllBytes failed to round-trip the payload file.");
    } else {
        result.parsedOk = true;
    }

    std::string textRoundTrip;
    if (!SSFileUtils::ReadAllTextUtf8(textPath.wstring(), textRoundTrip, &fileError)) {
        RecordValidationIssue(result, "ReadAllTextUtf8 failed for the payload text file.");
    }

    std::wstring normalizedPayload = SSFileUtils::NormalizePath(payloadPath.wstring(), true, &fileError);
    if (normalizedPayload.empty()) {
        RecordValidationIssue(result, "NormalizePath failed for an existing file.");
    }

    if (!SSFileUtils::IsPathUnderRoot(payloadPath.wstring(), root.wstring(), true, &fileError)) {
        RecordValidationIssue(result, "IsPathUnderRoot rejected a file created inside the root workspace.");
    }

    const std::wstring traversalCandidate = (root / L"..\\outside.bin").wstring();
    if (SSFileUtils::IsPathUnderRoot(traversalCandidate, root.wstring(), true, &fileError)) {
        RecordAnomaly(result, "IsPathUnderRoot accepted an escaping traversal candidate.");
    }

    const std::wstring prefixedPath = SSFileUtils::AddLongPathPrefix(payloadPath.wstring());
    if (prefixedPath.empty() || prefixedPath.find(SSFileUtils::LONG_PATH_PREFIX) != 0) {
        RecordValidationIssue(result, "AddLongPathPrefix failed for a normal payload path.");
    }

    SSFileUtils::FileStat stat{};
    if (!SSFileUtils::Stat(payloadPath.wstring(), stat, &fileError) || !stat.exists || stat.isDirectory) {
        RecordValidationIssue(result, "Stat returned unexpected metadata for the payload file.");
    }

    std::vector<uint8_t> inMemoryDigest;
    SSHashUtils::Error hashError{};
    if (SSHashUtils::Compute(Algorithm::SHA256, payload.data(), payload.size(), inMemoryDigest, &hashError)) {
        std::vector<uint8_t> fileDigest;
        if (!SSHashUtils::ComputeFile(Algorithm::SHA256, payloadPath.wstring(), fileDigest, &hashError) ||
            fileDigest != inMemoryDigest) {
            RecordValidationIssue(result, "ComputeFile disagreed with in-memory SHA-256 hashing.");
        }
    }

    if (!SSFileUtils::RemoveFile(payloadPath.wstring(), &fileError)) {
        RecordValidationIssue(result, "RemoveFile failed for the payload file.");
    }

    SSFileUtils::RemoveDirectoryRecursive(root.wstring(), nullptr);
}

}  // namespace

std::string StringPathHashHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool StringPathHashHarness::ExerciseStringPathHashImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};
    const std::string inputText =
        (data != nullptr && size != 0)
            ? std::string(reinterpret_cast<const char*>(data), size)
            : std::string{};

    ExecuteSafely(result, "ExerciseStringUtilities", [&]() { ExerciseStringUtilities(inputText, result); });
    ExecuteSafely(result, "ExerciseHashUtilities", [&]() { ExerciseHashUtilities(input, result); });

    if (const auto filesystemSequence = AcquireFilesystemSequence(); filesystemSequence.has_value()) {
        ExecuteSafely(result, "ExerciseFilesystemUtilities", [&]() {
            ExerciseFilesystemUtilities(input, *filesystemSequence, inputText, result);
        });
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long StringPathHashHarness::SEHCallStringPathHash(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExerciseStringPathHashImpl(data, size, *pResult);
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

HarnessResult StringPathHashHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallStringPathHash(
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

HarnessFunction StringPathHashHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view StringPathHashHarness::GetName() noexcept {
    return "string-path-hash";
}

std::string_view StringPathHashHarness::GetDescription() noexcept {
    return "StringUtils, FileUtils, and HashUtils fuzz harness";
}

int RunStringPathHashFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[StringPathHashFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "string-path-hash";
    const auto crashDir = workspaceDir / "crashes" / "string-path-hash";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[StringPathHashFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[StringPathHashFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(StringPathHashHarness::GetName());

    std::cout << "[StringPathHashFuzzer] Starting string/path/hash fuzzing...\n";
    std::cout << "[StringPathHashFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[StringPathHashFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, StringPathHashHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[StringPathHashFuzzer] Final Results:\n";
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
