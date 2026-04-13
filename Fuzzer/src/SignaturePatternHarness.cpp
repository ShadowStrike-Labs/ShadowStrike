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
 * @file SignaturePatternHarness.cpp
 * @brief Implementation of the SignatureStore/PatternStore fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/SignaturePatternHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "PatternStore/PatternStore.hpp"
#include "SignatureStore/SignatureFormat.hpp"
#include "Utils/FileUtils.hpp"
#include "Utils/HashUtils.hpp"

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
#include <cmath>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSFormat = ShadowStrike::SignatureStore::Format;
namespace SSPattern = ShadowStrike::PatternStore;
namespace SSMemoryMapping = ShadowStrike::SignatureStore::MemoryMapping;
namespace SSFileUtils = ShadowStrike::Utils::FileUtils;
namespace SSHashUtils = ShadowStrike::Utils::HashUtils;

using ShadowStrike::SignatureStore::HashType;
using ShadowStrike::SignatureStore::MemoryMappedView;
using ShadowStrike::SignatureStore::QueryOptions;
using ShadowStrike::SignatureStore::SIGNATURE_DB_MAGIC;
using ShadowStrike::SignatureStore::SIGNATURE_DB_VERSION_MAJOR;
using ShadowStrike::SignatureStore::SIGNATURE_DB_VERSION_MINOR;
using ShadowStrike::SignatureStore::SignatureDatabaseHeader;
using ShadowStrike::SignatureStore::StoreError;
using ShadowStrike::SignatureStore::ThreatLevel;
using ShadowStrike::SignatureStore::PAGE_SIZE;

constexpr std::array<HashType, 7> kHashTypes{
    HashType::MD5,
    HashType::SHA1,
    HashType::SHA256,
    HashType::SHA512,
    HashType::IMPHASH,
    HashType::FUZZY,
    HashType::TLSH,
};

std::atomic<uint64_t> g_persistentExerciseCounter{0};

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

[[nodiscard]] bool IsHexEncodedHashType(HashType type) noexcept {
    switch (type) {
    case HashType::MD5:
    case HashType::SHA1:
    case HashType::SHA256:
    case HashType::SHA512:
    case HashType::IMPHASH:
        return true;
    case HashType::FUZZY:
    case HashType::TLSH:
    case HashType::All:
        return false;
    }

    return false;
}

[[nodiscard]] std::string ByteToHex(uint8_t value) {
    char buffer[3]{};
    std::snprintf(buffer, sizeof(buffer), "%02X", static_cast<unsigned int>(value));
    return std::string(buffer);
}

[[nodiscard]] std::string BuildExactPattern(std::span<const uint8_t> input) {
    const size_t count = std::min<size_t>(input.size(), 8);
    if (count == 0) {
        return "4D 5A";
    }

    std::string pattern;
    pattern.reserve(count * 3);
    for (size_t index = 0; index < count; ++index) {
        if (!pattern.empty()) {
            pattern.push_back(' ');
        }
        pattern += ByteToHex(input[index]);
    }

    return pattern;
}

[[nodiscard]] std::string BuildWildcardPattern(std::span<const uint8_t> input) {
    const size_t count = std::min<size_t>(input.size(), 8);
    if (count < 3) {
        return "90 ?? C3";
    }

    std::string pattern;
    pattern.reserve(count * 3);
    for (size_t index = 0; index < count; ++index) {
        if (!pattern.empty()) {
            pattern.push_back(' ');
        }

        if ((index % 3U) == 1U) {
            pattern += "??";
        } else {
            pattern += ByteToHex(input[index]);
        }
    }

    return pattern;
}

[[nodiscard]] std::string BuildRangePattern(std::span<const uint8_t> input) {
    if (input.size() < 3) {
        return "41 [42-44] 45";
    }

    const uint8_t low = std::min(input[1], input[2]);
    const uint8_t high = std::max(input[1], input[2]);

    std::string pattern;
    pattern.reserve(16);
    pattern += ByteToHex(input[0]);
    pattern += " [";
    pattern += ByteToHex(low);
    pattern += '-';
    pattern += ByteToHex(high);
    pattern += "] ";
    pattern += ByteToHex(input.back());
    return pattern;
}

[[nodiscard]] std::string BuildGapPattern(std::span<const uint8_t> input) {
    if (input.size() < 2) {
        return "4D {0-4} 5A";
    }

    const unsigned int gap = static_cast<unsigned int>(input[0] & 0x0F);
    std::string pattern;
    pattern.reserve(24);
    pattern += ByteToHex(input[0]);
    pattern += " {0-";
    pattern += std::to_string(gap);
    pattern += "} ";
    pattern += ByteToHex(input[input.size() / 2]);
    return pattern;
}

[[nodiscard]] std::vector<std::string> BuildPatternCandidates(std::span<const uint8_t> input) {
    std::vector<std::string> candidates;
    candidates.reserve(4);
    candidates.push_back(BuildExactPattern(input));
    candidates.push_back(BuildWildcardPattern(input));
    candidates.push_back(BuildRangePattern(input));
    candidates.push_back(BuildGapPattern(input));
    return candidates;
}

[[nodiscard]] SignatureDatabaseHeader BuildSignatureHeader(uint64_t fileSize) {
    SignatureDatabaseHeader header{};
    header.magic = SIGNATURE_DB_MAGIC;
    header.versionMajor = SIGNATURE_DB_VERSION_MAJOR;
    header.versionMinor = SIGNATURE_DB_VERSION_MINOR;
    header.creationTime = 1735689600ULL;
    header.lastUpdateTime = header.creationTime;
    header.buildNumber = 1;
    header.recommendedCacheSize = 64;
    std::fill(header.databaseUuid.begin(), header.databaseUuid.end(), 0x5A);
    std::fill(header.sha256Checksum.begin(), header.sha256Checksum.end(), 0);
    header.reserved[0] = static_cast<uint8_t>(fileSize & 0xFFU);
    return header;
}

[[nodiscard]] std::filesystem::path MakeIterationRoot(std::span<const uint8_t> input, uint64_t sequence) {
    const uint64_t hash = SSHashUtils::Fnv1a64(input.data(), input.size());
    std::ostringstream stream;
    stream << "shadowstrike_sig_pattern_" << GetCurrentProcessId() << '_' << sequence << '_'
           << std::hex << hash;
    return std::filesystem::temp_directory_path() / stream.str();
}

[[nodiscard]] std::optional<uint64_t> AcquirePersistentStoreSequence() noexcept {
    const uint64_t sequence = g_persistentExerciseCounter.fetch_add(1, std::memory_order_relaxed);
    if ((sequence % 8ULL) != 0ULL) {
        return std::nullopt;
    }

    return sequence;
}

void ExerciseSignatureHashes(std::string_view candidate, HarnessResult& result) {
    for (const HashType type : kHashTypes) {
        const auto parsed = SSFormat::ParseHashString(std::string(candidate), type);
        if (!parsed.has_value()) {
            continue;
        }

        result.parsedOk = true;

        if (parsed->length != ShadowStrike::SignatureStore::GetHashLengthForType(type)) {
            RecordValidationIssue(result, "ParseHashString returned an unexpected hash length.");
        }

        const std::string formatted = SSFormat::FormatHashString(*parsed);
        if (formatted.empty()) {
            RecordValidationIssue(result, "FormatHashString returned an empty string after a successful parse.");
            continue;
        }

        if (IsHexEncodedHashType(type) && formatted.size() != parsed->length * 2ULL) {
            RecordValidationIssue(result, "FormatHashString produced an unexpected hex length.");
        }

        const auto reparsed = SSFormat::ParseHashString(formatted, type);
        if (!reparsed.has_value() || !(*reparsed == *parsed)) {
            RecordValidationIssue(result, "ParseHashString and FormatHashString failed to round-trip.");
        }

        if (reparsed.has_value() && reparsed->FastHash() != parsed->FastHash()) {
            RecordValidationIssue(result, "HashValue::FastHash changed across a parse/format round-trip.");
        }
    }
}

void ExerciseSignatureHeaderValidation(HarnessResult& result) {
    std::vector<uint8_t> storage(sizeof(SignatureDatabaseHeader));
    SignatureDatabaseHeader header = BuildSignatureHeader(storage.size());
    std::memcpy(storage.data(), &header, sizeof(header));

    const auto* validHeader = reinterpret_cast<const SignatureDatabaseHeader*>(storage.data());
    if (!SSFormat::ValidateHeader(validHeader, storage.size())) {
        RecordValidationIssue(result, "ValidateHeader rejected a baseline signature database header.");
    } else {
        result.parsedOk = true;
    }

    {
        std::vector<uint8_t> invalid = storage;
        auto* invalidHeader = reinterpret_cast<SignatureDatabaseHeader*>(invalid.data());
        invalidHeader->magic ^= 0xFFFFFFFFu;
        if (SSFormat::ValidateHeader(invalidHeader, invalid.size())) {
            RecordAnomaly(result, "ValidateHeader accepted an invalid magic value.");
        }
    }

    {
        std::vector<uint8_t> invalid = storage;
        auto* invalidHeader = reinterpret_cast<SignatureDatabaseHeader*>(invalid.data());
        invalidHeader->patternIndexOffset = 1;
        invalidHeader->patternIndexSize = PAGE_SIZE;
        if (SSFormat::ValidateHeader(invalidHeader, invalid.size())) {
            RecordAnomaly(result, "ValidateHeader accepted an unaligned section offset.");
        }
    }

    {
        std::vector<uint8_t> invalid = storage;
        auto* invalidHeader = reinterpret_cast<SignatureDatabaseHeader*>(invalid.data());
        invalidHeader->hashIndexOffset = PAGE_SIZE;
        invalidHeader->hashIndexSize = PAGE_SIZE;
        invalidHeader->patternIndexOffset = PAGE_SIZE;
        invalidHeader->patternIndexSize = PAGE_SIZE;
        if (SSFormat::ValidateHeader(invalidHeader, invalid.size() + PAGE_SIZE * 2ULL)) {
            RecordAnomaly(result, "ValidateHeader accepted overlapping signature sections.");
        }
    }

    {
        std::vector<uint8_t> invalid = storage;
        auto* invalidHeader = reinterpret_cast<SignatureDatabaseHeader*>(invalid.data());
        invalidHeader->stringPoolOffset = PAGE_SIZE;
        invalidHeader->stringPoolSize = PAGE_SIZE;
        if (SSFormat::ValidateHeader(invalidHeader, invalid.size())) {
            RecordAnomaly(result, "ValidateHeader accepted a section that extends beyond the file.");
        }
    }
}

void ExercisePathValidation(HarnessResult& result) {
    std::wstring canonicalPath;
    std::string errorMessage;
    if (SSFormat::ValidateAndCanonicalizePath(L"..\\..\\shadowstrike.sigdb", canonicalPath, errorMessage)) {
        RecordAnomaly(result, "ValidateAndCanonicalizePath accepted a relative traversal path.");
    }

    canonicalPath.clear();
    errorMessage.clear();
    if (SSFormat::ValidateAndCanonicalizePath(L"CON", canonicalPath, errorMessage)) {
        RecordAnomaly(result, "ValidateAndCanonicalizePath accepted a reserved device path.");
    }
}

void ExercisePatternCompiler(std::span<const uint8_t> input, HarnessResult& result) {
    const std::vector<std::string> candidates = BuildPatternCandidates(input);
    for (const std::string& candidate : candidates) {
        std::string validationError;
        const bool validSyntax = SSPattern::PatternCompiler::ValidatePattern(candidate, validationError);

        ShadowStrike::SignatureStore::PatternMode mode{};
        std::vector<uint8_t> mask;
        const auto compiled = SSPattern::PatternCompiler::CompilePattern(candidate, mode, mask);
        if (compiled.has_value()) {
            result.parsedOk = true;

            if (!validSyntax) {
                RecordValidationIssue(result, "CompilePattern succeeded while ValidatePattern rejected the same string.");
            }

            const float entropy = SSPattern::PatternCompiler::ComputeEntropy(*compiled);
            if (!std::isfinite(entropy) || entropy < 0.0F || entropy > 8.01F) {
                RecordValidationIssue(result, "ComputeEntropy returned an out-of-range value.");
            }

            if (compiled->empty()) {
                RecordValidationIssue(result, "CompilePattern returned an empty compiled pattern.");
            }

            if (mask.size() != compiled->size()) {
                RecordValidationIssue(result, "CompilePattern returned a mask size that does not match the pattern size.");
            }
        }
    }

    std::string invalidError;
    if (SSPattern::PatternCompiler::ValidatePattern("{5-2}", invalidError)) {
        RecordAnomaly(result, "ValidatePattern accepted a reversed variable-gap range.");
    }
}

void ExerciseExactMatchers(HarnessResult& result) {
    const std::array<uint8_t, 2> mz{0x4D, 0x5A};
    const std::array<uint8_t, 3> abc{0x41, 0x42, 0x43};
    const std::array<uint8_t, 12> buffer{
        0x00, 0x4D, 0x5A, 0x10, 0x41, 0x42, 0x43, 0x90, 0x4D, 0x5A, 0x41, 0x42
    };

    SSPattern::AhoCorasickAutomaton automaton;
    if (!automaton.AddPattern(mz, 1001) || !automaton.AddPattern(abc, 1002) || !automaton.Compile()) {
        RecordValidationIssue(result, "AhoCorasickAutomaton failed to compile baseline patterns.");
        return;
    }

    size_t callbackMatches = 0;
    automaton.Search(buffer, [&](uint64_t patternId, size_t offset) {
        ++callbackMatches;
        if (patternId != 1001 && patternId != 1002) {
            RecordAnomaly(result, "AhoCorasickAutomaton returned an unexpected pattern identifier.");
        }
        if (offset >= buffer.size()) {
            RecordAnomaly(result, "AhoCorasickAutomaton reported an out-of-range match offset.");
        }
    });

    const size_t countedMatches = automaton.CountMatches(buffer);
    if (callbackMatches == 0 || countedMatches == 0) {
        RecordValidationIssue(result, "AhoCorasickAutomaton failed to report baseline matches.");
    } else if (callbackMatches != countedMatches) {
        RecordValidationIssue(result, "AhoCorasickAutomaton search and count paths diverged.");
    } else {
        result.parsedOk = true;
    }

    SSPattern::BoyerMooreMatcher matcher(abc);
    const auto offsets = matcher.Search(buffer);
    const auto first = matcher.FindFirst(buffer);
    if (offsets.empty() || !first.has_value()) {
        RecordValidationIssue(result, "BoyerMooreMatcher failed to match a present pattern.");
    } else if (*first != offsets.front()) {
        RecordValidationIssue(result, "BoyerMooreMatcher FindFirst disagreed with Search.");
    }

    if (SSPattern::SIMDMatcher::IsAVX2Available()) {
        const auto simdOffsets = SSPattern::SIMDMatcher::SearchAVX2(buffer, abc);
        if (simdOffsets.empty()) {
            RecordValidationIssue(result, "SIMDMatcher::SearchAVX2 failed to match a present exact pattern.");
        }
    }
}

void ExercisePersistentPatternStore(std::span<const uint8_t> input, uint64_t sequence, HarnessResult& result) {
    const std::filesystem::path root = MakeIterationRoot(input, sequence);
    const std::filesystem::path dbPath = root / "patterns.sdb";
    const std::filesystem::path samplePath = root / "sample.bin";

    SSFileUtils::Error fileError{};
    if (!SSFileUtils::CreateDirectories(root.wstring(), &fileError)) {
        RecordValidationIssue(result, "CreateDirectories failed for the temporary pattern-store workspace.");
        return;
    }

    SSPattern::PatternStore store;
    StoreError storeError = store.CreateNew(dbPath.wstring(), 2ULL * 1024ULL * 1024ULL);
    if (!storeError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::CreateNew failed for the fuzz workspace.");
        SSFileUtils::RemoveDirectoryRecursive(root.wstring(), nullptr);
        return;
    }

    auto addError = store.AddPattern("4D 5A", "mz-header", ThreatLevel::Medium, "DOS stub marker");
    if (!addError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::AddPattern failed for baseline exact pattern.");
    }

    addError = store.AddPattern("41 42 43", "abc-sequence", ThreatLevel::Low, "ASCII sentinel");
    if (!addError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::AddPattern failed for ASCII sentinel pattern.");
    }

    addError = store.AddPattern("90 ?? C3", "wildcard-stub", ThreatLevel::High, "Wildcard opcode sentinel");
    if (!addError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::AddPattern failed for wildcard sentinel pattern.");
    }

    auto stats = store.GetStatistics();
    if (stats.totalPatterns < 3) {
        RecordValidationIssue(result, "PatternStore statistics did not reflect added baseline patterns.");
    }

    std::vector<uint8_t> scanBuffer(input.begin(), input.end());
    scanBuffer.insert(scanBuffer.end(), {0x4D, 0x5A, 0x41, 0x42, 0x43, 0x90, 0x11, 0xC3});

    const QueryOptions options{};
    const auto scanResults = store.Scan(scanBuffer, options);
    if (scanResults.empty()) {
        RecordValidationIssue(result, "PatternStore::Scan failed to detect baseline patterns.");
    } else {
        result.parsedOk = true;
    }

    auto scanContext = store.CreateScanContext(options);
    std::vector<ShadowStrike::SignatureStore::DetectionResult> incrementalResults;
    const size_t split = std::max<size_t>(1, scanBuffer.size() / 2);
    auto firstChunk = scanContext.FeedChunk(std::span<const uint8_t>(scanBuffer.data(), split));
    auto secondChunk = scanContext.FeedChunk(std::span<const uint8_t>(scanBuffer.data() + split, scanBuffer.size() - split));
    auto finalChunk = scanContext.Finalize();
    incrementalResults.insert(incrementalResults.end(), firstChunk.begin(), firstChunk.end());
    incrementalResults.insert(incrementalResults.end(), secondChunk.begin(), secondChunk.end());
    incrementalResults.insert(incrementalResults.end(), finalChunk.begin(), finalChunk.end());
    if (incrementalResults.empty()) {
        RecordValidationIssue(result, "PatternStore::ScanContext failed to report baseline matches.");
    }

    std::vector<std::byte> scanBytes;
    scanBytes.reserve(scanBuffer.size());
    for (const uint8_t byte : scanBuffer) {
        scanBytes.push_back(static_cast<std::byte>(byte));
    }

    if (!SSFileUtils::WriteAllBytesAtomic(samplePath.wstring(), scanBytes, &fileError)) {
        RecordValidationIssue(result, "WriteAllBytesAtomic failed for the pattern-scan sample.");
    } else {
        const auto fileScanResults = store.ScanFile(samplePath.wstring(), options);
        if (fileScanResults.empty()) {
            RecordValidationIssue(result, "PatternStore::ScanFile failed to detect baseline patterns.");
        }
    }

    const std::string exportedJson = store.ExportToJson(16);
    if (exportedJson.empty() || exportedJson.find("mz-header") == std::string::npos) {
        RecordValidationIssue(result, "PatternStore::ExportToJson did not contain the baseline pattern metadata.");
    }

    const StoreError verifyError = store.Verify();
    if (!verifyError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::Verify rejected the freshly built temporary database.");
    }

    const StoreError flushError = store.Flush();
    if (!flushError.IsSuccess()) {
        RecordValidationIssue(result, "PatternStore::Flush failed after baseline updates.");
    }

    MemoryMappedView view{};
    StoreError mappingError = StoreError::Success();
    if (!SSMemoryMapping::OpenView(dbPath.wstring(), true, view, mappingError)) {
        RecordValidationIssue(result, "SignatureStore::MemoryMapping::OpenView failed on the PatternStore database.");
    } else {
        const auto* mappedHeader = view.GetAt<SignatureDatabaseHeader>(0);
        if (mappedHeader == nullptr || !SSFormat::ValidateHeader(mappedHeader, view.fileSize)) {
            RecordValidationIssue(result, "Memory-mapped PatternStore database did not expose a valid signature header.");
        }
        SSMemoryMapping::CloseView(view);
    }

    store.Close();
    SSFileUtils::RemoveDirectoryRecursive(root.wstring(), nullptr);
}

}  // namespace

std::string SignaturePatternHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool SignaturePatternHarness::ExerciseSignaturePatternImpl(
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

    ExecuteSafely(result, "ExerciseSignatureHashes", [&]() { ExerciseSignatureHashes(inputText, result); });
    ExecuteSafely(result, "ExerciseSignatureHeaderValidation", [&]() { ExerciseSignatureHeaderValidation(result); });
    ExecuteSafely(result, "ExercisePathValidation", [&]() { ExercisePathValidation(result); });
    ExecuteSafely(result, "ExercisePatternCompiler", [&]() { ExercisePatternCompiler(input, result); });
    ExecuteSafely(result, "ExerciseExactMatchers", [&]() { ExerciseExactMatchers(result); });

    if (const auto persistentSequence = AcquirePersistentStoreSequence(); persistentSequence.has_value()) {
        ExecuteSafely(result, "ExercisePersistentPatternStore", [&]() {
            ExercisePersistentPatternStore(input, *persistentSequence, result);
        });
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long SignaturePatternHarness::SEHCallSignaturePattern(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExerciseSignaturePatternImpl(data, size, *pResult);
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

HarnessResult SignaturePatternHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallSignaturePattern(
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

HarnessFunction SignaturePatternHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view SignaturePatternHarness::GetName() noexcept {
    return "signature-pattern";
}

std::string_view SignaturePatternHarness::GetDescription() noexcept {
    return "SignatureStore format and PatternStore fuzz harness";
}

int RunSignaturePatternFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[SignaturePatternFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "signature-pattern";
    const auto crashDir = workspaceDir / "crashes" / "signature-pattern";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[SignaturePatternFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[SignaturePatternFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(SignaturePatternHarness::GetName());

    std::cout << "[SignaturePatternFuzzer] Starting signature and pattern fuzzing...\n";
    std::cout << "[SignaturePatternFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[SignaturePatternFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, SignaturePatternHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[SignaturePatternFuzzer] Final Results:\n";
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
