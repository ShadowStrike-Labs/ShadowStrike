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
 * @file ParserUtilsHarness.cpp
 * @brief Implementation of the ShadowStrike parser utility fuzz harness.
 *
 * Exercises JSON, XML, and Base64 utility entry points against identical hostile
 * input, validates error-reporting contracts, checks transform round-trips, and
 * hardens execution with Windows SEH for in-process fuzzing.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ParserUtilsHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "Utils/JSONUtils.hpp"
#include "Utils/XMLUtils.hpp"
#include "Utils/Base64Utils.hpp"

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
#include <cctype>
#include <exception>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSJson = ShadowStrike::Utils::JSON;
namespace SSXml = ShadowStrike::Utils::XML;
using ShadowStrike::Utils::Base64Alphabet;
using ShadowStrike::Utils::Base64Decode;
using ShadowStrike::Utils::Base64DecodeError;
using ShadowStrike::Utils::Base64DecodeErrorToString;
using ShadowStrike::Utils::Base64DecodeOptions;
using ShadowStrike::Utils::Base64Encode;
using ShadowStrike::Utils::Base64EncodeOptions;

constexpr int kPrettyIndentSpaces = 2;
constexpr std::array<Base64Alphabet, 2> kBase64Alphabets{
    Base64Alphabet::Standard,
    Base64Alphabet::UrlSafe,
};

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

[[nodiscard]] bool HasXmlError(const SSXml::Error& err) noexcept {
    return !err.message.empty();
}

[[nodiscard]] bool IsSafeXPathToken(std::string_view token) noexcept {
    if (token.empty()) {
        return false;
    }

    for (const unsigned char ch : token) {
        if (std::isalnum(ch) != 0 || ch == '_' || ch == '-' || ch == '.') {
            continue;
        }
        return false;
    }

    return true;
}

void ValidateJsonErrorState(
    bool success,
    const SSJson::Error& err,
    std::string_view operation,
    size_t inputSize,
    HarnessResult& result)
{
    if (success) {
        if (err.hasError()) {
            std::string message(operation);
            message += " reported an unexpected JSON error on success.";
            RecordValidationIssue(result, message);
        }
        return;
    }

    if (!err.hasError() || err.message.empty()) {
        std::string message(operation);
        message += " did not populate JSON error details on failure.";
        RecordValidationIssue(result, message);
    }

    if (err.byteOffset > inputSize) {
        std::string message(operation);
        message += " reported a JSON byte offset past the input buffer.";
        RecordValidationIssue(result, message);
    }
}

void ValidateXmlErrorState(
    bool success,
    const SSXml::Error& err,
    std::string_view operation,
    size_t inputSize,
    HarnessResult& result)
{
    if (success) {
        if (HasXmlError(err)) {
            std::string message(operation);
            message += " reported an unexpected XML error on success.";
            RecordValidationIssue(result, message);
        }
        return;
    }

    if (!HasXmlError(err)) {
        std::string message(operation);
        message += " did not populate XML error details on failure.";
        RecordValidationIssue(result, message);
    }

    if (err.byteOffset > inputSize) {
        std::string message(operation);
        message += " reported an XML byte offset past the input buffer.";
        RecordValidationIssue(result, message);
    }
}

void ValidateBase64ErrorState(
    bool success,
    Base64DecodeError err,
    std::string_view operation,
    HarnessResult& result)
{
    if (success) {
        if (err != Base64DecodeError::None) {
            std::string message(operation);
            message += " returned a Base64 error despite success.";
            RecordValidationIssue(result, message);
        }
        return;
    }

    if (err == Base64DecodeError::None) {
        std::string message(operation);
        message += " failed without reporting a Base64 error.";
        RecordValidationIssue(result, message);
    }
}

void ExerciseJsonUtilities(std::string_view inputText, HarnessResult& result) {
    SSJson::ParseOptions parseOptions{};

    SSJson::Json parsedJson;
    SSJson::Error parseErr{};
    const bool parseOk = SSJson::Parse(inputText, parsedJson, &parseErr, parseOptions);
    ValidateJsonErrorState(parseOk, parseErr, "JSON::Parse", inputText.size(), result);
    if (!parseOk && !parsedJson.is_null()) {
        RecordValidationIssue(result, "JSON::Parse left non-null output after failure.");
    }

    std::string minifiedJson;
    SSJson::Error minifyErr{};
    const bool minifyOk = SSJson::Minify(inputText, minifiedJson, &minifyErr, parseOptions);
    ValidateJsonErrorState(minifyOk, minifyErr, "JSON::Minify", inputText.size(), result);
    if (!minifyOk && !minifiedJson.empty()) {
        RecordValidationIssue(result, "JSON::Minify left output text after failure.");
    }

    std::string prettyJson;
    SSJson::Error prettifyErr{};
    const bool prettifyOk = SSJson::Prettify(
        inputText,
        prettyJson,
        kPrettyIndentSpaces,
        &prettifyErr,
        parseOptions);
    ValidateJsonErrorState(prettifyOk, prettifyErr, "JSON::Prettify", inputText.size(), result);
    if (!prettifyOk && !prettyJson.empty()) {
        RecordValidationIssue(result, "JSON::Prettify left output text after failure.");
    }

    if (parseOk || minifyOk || prettifyOk) {
        result.parsedOk = true;
    }

    if (!parseOk && minifyOk) {
        RecordAnomaly(result, "JSON::Minify succeeded after JSON::Parse failed.");
    }
    if (!parseOk && prettifyOk) {
        RecordAnomaly(result, "JSON::Prettify succeeded after JSON::Parse failed.");
    }

    if (!parseOk) {
        return;
    }

    if (!minifyOk) {
        RecordAnomaly(result, "JSON::Minify failed on successfully parsed JSON input.");
    } else {
        SSJson::Json reparsedMinified;
        SSJson::Error reparseErr{};
        const bool reparseOk = SSJson::Parse(minifiedJson, reparsedMinified, &reparseErr, parseOptions);
        ValidateJsonErrorState(reparseOk, reparseErr, "JSON::Parse(minified)", minifiedJson.size(), result);
        if (!reparseOk) {
            RecordAnomaly(result, "JSON minified output did not parse successfully.");
        } else if (reparsedMinified != parsedJson) {
            RecordValidationIssue(result, "JSON::Minify changed parsed document semantics.");
        }
    }

    if (!prettifyOk) {
        RecordAnomaly(result, "JSON::Prettify failed on successfully parsed JSON input.");
    } else {
        SSJson::Json reparsedPretty;
        SSJson::Error reparseErr{};
        const bool reparseOk = SSJson::Parse(prettyJson, reparsedPretty, &reparseErr, parseOptions);
        ValidateJsonErrorState(reparseOk, reparseErr, "JSON::Parse(pretty)", prettyJson.size(), result);
        if (!reparseOk) {
            RecordAnomaly(result, "JSON prettified output did not parse successfully.");
        } else if (reparsedPretty != parsedJson) {
            RecordValidationIssue(result, "JSON::Prettify changed parsed document semantics.");
        }
    }

    SSJson::Json patchJson;
    SSJson::Error patchErr{};
    const bool patchOk = SSJson::Parse(inputText, patchJson, &patchErr, parseOptions);
    ValidateJsonErrorState(patchOk, patchErr, "JSON::Parse(patch)", inputText.size(), result);
    if (!patchOk) {
        RecordAnomaly(result, "JSON patch parse failed after an identical successful parse.");
        return;
    }

    SSJson::Json mergeTarget = parsedJson;
    SSJson::Error mergeErr{};
    const bool mergeOk = SSJson::MergePatch(mergeTarget, patchJson, &mergeErr);
    ValidateJsonErrorState(mergeOk, mergeErr, "JSON::MergePatch", inputText.size(), result);
    if (!mergeOk) {
        RecordAnomaly(result, "JSON::MergePatch failed on successfully parsed inputs.");
    }
}

void ExerciseXmlGetters(const SSXml::Document& document) {
    std::string textValue;
    int64_t intValue = 0;

    (void)SSXml::GetText(document, "", textValue);
    (void)SSXml::GetInt64(document, "", intValue);

    const auto root = document.document_element();
    if (!root) {
        return;
    }

    const std::string_view rootName(root.name());
    if (!IsSafeXPathToken(rootName)) {
        return;
    }

    std::string rootPath;
    rootPath.reserve(rootName.size() + 1);
    rootPath.push_back('/');
    rootPath.append(rootName);

    (void)SSXml::GetText(document, rootPath, textValue);
    (void)SSXml::GetInt64(document, rootPath, intValue);

    const auto firstAttribute = root.first_attribute();
    if (firstAttribute) {
        const std::string_view attributeName(firstAttribute.name());
        if (IsSafeXPathToken(attributeName)) {
            std::string attributePath(rootPath);
            attributePath += "/@";
            attributePath.append(attributeName);
            (void)SSXml::GetText(document, attributePath, textValue);
            (void)SSXml::GetInt64(document, attributePath, intValue);
        }
    }

    for (auto child = root.first_child(); child; child = child.next_sibling()) {
        if (child.type() != pugi::node_element) {
            continue;
        }

        const std::string_view childName(child.name());
        if (!IsSafeXPathToken(childName)) {
            continue;
        }

        std::string childPath(rootPath);
        childPath.push_back('/');
        childPath.append(childName);
        (void)SSXml::GetText(document, childPath, textValue);
        (void)SSXml::GetInt64(document, childPath, intValue);
        break;
    }
}

void ExerciseXmlUtilities(std::string_view inputText, HarnessResult& result) {
    SSXml::ParseOptions parseOptions{};

    SSXml::Document parsedXml;
    SSXml::Error parseErr{};
    const bool parseOk = SSXml::Parse(inputText, parsedXml, &parseErr, parseOptions);
    ValidateXmlErrorState(parseOk, parseErr, "XML::Parse", inputText.size(), result);

    std::string minifiedXml;
    SSXml::Error minifyErr{};
    const bool minifyOk = SSXml::Minify(inputText, minifiedXml, &minifyErr, parseOptions);
    ValidateXmlErrorState(minifyOk, minifyErr, "XML::Minify", inputText.size(), result);
    if (!minifyOk && !minifiedXml.empty()) {
        RecordValidationIssue(result, "XML::Minify left output text after failure.");
    }

    std::string prettyXml;
    SSXml::Error prettifyErr{};
    const bool prettifyOk = SSXml::Prettify(
        inputText,
        prettyXml,
        kPrettyIndentSpaces,
        &prettifyErr,
        parseOptions);
    ValidateXmlErrorState(prettifyOk, prettifyErr, "XML::Prettify", inputText.size(), result);
    if (!prettifyOk && !prettyXml.empty()) {
        RecordValidationIssue(result, "XML::Prettify left output text after failure.");
    }

    if (parseOk || minifyOk || prettifyOk) {
        result.parsedOk = true;
    }

    if (!parseOk && minifyOk) {
        RecordAnomaly(result, "XML::Minify succeeded after XML::Parse failed.");
    }
    if (!parseOk && prettifyOk) {
        RecordAnomaly(result, "XML::Prettify succeeded after XML::Parse failed.");
    }

    if (!parseOk) {
        return;
    }

    if (!minifyOk) {
        RecordAnomaly(result, "XML::Minify failed on successfully parsed XML input.");
    } else {
        SSXml::Document reparsedMinified;
        SSXml::Error reparseErr{};
        const bool reparseOk = SSXml::Parse(minifiedXml, reparsedMinified, &reparseErr, parseOptions);
        ValidateXmlErrorState(reparseOk, reparseErr, "XML::Parse(minified)", minifiedXml.size(), result);
        if (!reparseOk) {
            RecordAnomaly(result, "XML minified output did not parse successfully.");
        }
    }

    if (!prettifyOk) {
        RecordAnomaly(result, "XML::Prettify failed on successfully parsed XML input.");
    } else {
        SSXml::Document reparsedPretty;
        SSXml::Error reparseErr{};
        const bool reparseOk = SSXml::Parse(prettyXml, reparsedPretty, &reparseErr, parseOptions);
        ValidateXmlErrorState(reparseOk, reparseErr, "XML::Parse(pretty)", prettyXml.size(), result);
        if (!reparseOk) {
            RecordAnomaly(result, "XML prettified output did not parse successfully.");
        }
    }

    ExerciseXmlGetters(parsedXml);
}

std::string DescribeBase64Alphabet(Base64Alphabet alphabet) {
    return (alphabet == Base64Alphabet::Standard) ? "Standard" : "UrlSafe";
}

void ExerciseBase64DirectDecoding(
    std::string_view inputText,
    Base64Alphabet alphabet,
    HarnessResult& result)
{
    Base64DecodeOptions decodeOptions{};
    decodeOptions.alphabet = alphabet;

    std::vector<uint8_t> decodedWithErr;
    Base64DecodeError decodeErr = Base64DecodeError::None;
    const bool decodeWithErrOk = Base64Decode(inputText, decodedWithErr, decodeErr, decodeOptions);
    ValidateBase64ErrorState(decodeWithErrOk, decodeErr, "Base64Decode(with error)", result);
    if (!decodeWithErrOk && !decodedWithErr.empty()) {
        RecordValidationIssue(result, "Base64Decode(with error) left bytes after failure.");
    }

    std::vector<uint8_t> decodedWithoutErr;
    const bool decodeWithoutErrOk = Base64Decode(inputText, decodedWithoutErr, decodeOptions);
    if (!decodeWithoutErrOk && !decodedWithoutErr.empty()) {
        RecordValidationIssue(result, "Base64Decode(without error) left bytes after failure.");
    }

    if (decodeWithErrOk || decodeWithoutErrOk) {
        result.parsedOk = true;
    }

    if (decodeWithErrOk != decodeWithoutErrOk) {
        std::string message = "Base64Decode overload disagreement for ";
        message += DescribeBase64Alphabet(alphabet);
        message += " alphabet.";
        RecordAnomaly(result, message);
    }

    if (decodeWithErrOk && decodedWithErr != decodedWithoutErr) {
        std::string message = "Base64Decode overloads produced mismatched outputs for ";
        message += DescribeBase64Alphabet(alphabet);
        message += " alphabet.";
        RecordValidationIssue(result, message);
    }

    if (!decodeWithErrOk && decodeErr == Base64DecodeError::None) {
        std::string message = "Base64Decode did not report an error for ";
        message += DescribeBase64Alphabet(alphabet);
        message += " alphabet.";
        RecordValidationIssue(result, message);
    }
}

void ExerciseBase64RoundTrip(
    std::span<const uint8_t> input,
    Base64Alphabet alphabet,
    HarnessResult& result)
{
    Base64EncodeOptions encodeOptions{};
    encodeOptions.alphabet = alphabet;

    std::string encodedText;
    const bool encodeOk = Base64Encode(
        input.empty() ? nullptr : input.data(),
        input.size(),
        encodedText,
        encodeOptions);
    if (!encodeOk) {
        std::string message = "Base64Encode failed during ";
        message += DescribeBase64Alphabet(alphabet);
        message += " round-trip.";
        RecordValidationIssue(result, message);
        return;
    }

    Base64DecodeOptions decodeOptions{};
    decodeOptions.alphabet = alphabet;
    decodeOptions.acceptMissingPadding = false;

    std::vector<uint8_t> decodedBytes;
    Base64DecodeError decodeErr = Base64DecodeError::None;
    const bool decodeOk = Base64Decode(encodedText, decodedBytes, decodeErr, decodeOptions);
    ValidateBase64ErrorState(decodeOk, decodeErr, "Base64Decode(round-trip)", result);
    if (!decodeOk) {
        std::string message = "Base64 round-trip decode failed for ";
        message += DescribeBase64Alphabet(alphabet);
        message += " alphabet: ";
        message += Base64DecodeErrorToString(decodeErr);
        RecordAnomaly(result, message);
        return;
    }

    if (decodedBytes.size() != input.size() ||
        !std::equal(decodedBytes.begin(), decodedBytes.end(), input.begin(), input.end())) {
        std::string message = "Base64 round-trip mismatch for ";
        message += DescribeBase64Alphabet(alphabet);
        message += " alphabet.";
        RecordValidationIssue(result, message);
    } else {
        result.parsedOk = true;
    }
}

void ExerciseBase64Utilities(std::span<const uint8_t> input, HarnessResult& result) {
    const std::string_view inputText = (input.data() != nullptr && !input.empty())
        ? std::string_view(reinterpret_cast<const char*>(input.data()), input.size())
        : std::string_view{};

    for (const Base64Alphabet alphabet : kBase64Alphabets) {
        ExerciseBase64DirectDecoding(inputText, alphabet, result);
        ExerciseBase64RoundTrip(input, alphabet, result);
    }
}

}  // anonymous namespace

std::string ParserUtilsHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool ParserUtilsHarness::ExerciseParsersImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();

    const std::string_view inputText = (data != nullptr && size != 0)
        ? std::string_view(reinterpret_cast<const char*>(data), size)
        : std::string_view{};
    const auto inputBytes = (data != nullptr && size != 0)
        ? std::span<const uint8_t>(data, size)
        : std::span<const uint8_t>{};

    ExerciseJsonUtilities(inputText, result);
    ExerciseXmlUtilities(inputText, result);
    ExerciseBase64Utilities(inputBytes, result);

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long ParserUtilsHarness::SEHCallParsers(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        ExerciseParsersImpl(data, size, *pResult);
    }
    __except (exCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exCode == EXCEPTION_STACK_OVERFLOW) {
            if (!_resetstkoflw()) {
                TerminateProcess(GetCurrentProcess(), exCode);
            }
        }
        if (exCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exCode);
        }
    }
    return exCode;
}

HarnessResult ParserUtilsHarness::Run(std::span<const uint8_t> input) {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallParsers(
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

HarnessFunction ParserUtilsHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view ParserUtilsHarness::GetName() noexcept {
    return "parser-utils";
}

std::string_view ParserUtilsHarness::GetDescription() noexcept {
    return "JSON/XML/Base64 parser utility fuzz harness";
}

int RunParserUtilsFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ParserUtilsFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "parsers";
    const auto crashDir = workspaceDir / "crashes" / "parsers";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ParserUtilsFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ParserUtilsFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ParserUtilsHarness::GetName());

    std::cout << "[ParserUtilsFuzzer] Starting parser utility fuzzing...\n";
    std::cout << "[ParserUtilsFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ParserUtilsFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ParserUtilsHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ParserUtilsFuzzer] Final Results:\n";
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
