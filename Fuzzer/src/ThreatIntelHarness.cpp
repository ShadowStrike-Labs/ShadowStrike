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
 * @file ThreatIntelHarness.cpp
 * @brief Implementation of the ThreatIntel feed parser fuzz harness.
 *
 * Executes JsonFeedParser, CsvFeedParser, and StixFeedParser against the same
 * input using multiple ParserConfig variants, validates parsed IOC types, and
 * hardens execution with Windows SEH for in-process fuzzing.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ThreatIntelHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "ThreatIntel/ThreatIntelFeedManager.hpp"
#include "ThreatIntel/ThreatIntelFormat.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

using ShadowStrike::ThreatIntel::ConfidenceLevel;
using ShadowStrike::ThreatIntel::CsvFeedParser;
using ShadowStrike::ThreatIntel::IFeedParser;
using ShadowStrike::ThreatIntel::IOCEntry;
using ShadowStrike::ThreatIntel::IOCType;
using ShadowStrike::ThreatIntel::JsonFeedParser;
using ShadowStrike::ThreatIntel::ParserConfig;
using ShadowStrike::ThreatIntel::ReputationLevel;
using ShadowStrike::ThreatIntel::StixFeedParser;

struct ParserVariant final {
    std::string_view name;
    ParserConfig config;
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

[[nodiscard]] bool IsValidIOCType(const IOCType type) noexcept {
    switch (type) {
    case IOCType::IPv4:
    case IOCType::IPv6:
    case IOCType::Domain:
    case IOCType::URL:
    case IOCType::FileHash:
    case IOCType::Email:
    case IOCType::CertFingerprint:
    case IOCType::JA3:
    case IOCType::JA3S:
    case IOCType::RegistryKey:
    case IOCType::ProcessName:
    case IOCType::MutexName:
    case IOCType::NamedPipe:
    case IOCType::UserAgent:
    case IOCType::ASN:
    case IOCType::CIDRv4:
    case IOCType::CIDRv6:
    case IOCType::YaraRule:
    case IOCType::SigmaRule:
    case IOCType::MitreAttack:
    case IOCType::CVE:
    case IOCType::STIXPattern:
    case IOCType::Unknown:
    case IOCType::Reserved:
        return true;
    }

    return false;
}

void AppendErrorMessage(
    HarnessResult& result,
    std::string_view parserName,
    std::string_view variantName,
    const std::string& errorMessage)
{
    if (errorMessage.empty()) {
        return;
    }

    constexpr size_t kMaxErrorMessageLength = 2048;
    if (!result.errorMessage.empty()) {
        if (result.errorMessage.size() >= kMaxErrorMessageLength) {
            return;
        }
        result.errorMessage += " | ";
    }

    std::string fragment;
    fragment.reserve(parserName.size() + variantName.size() + errorMessage.size() + 8);
    fragment += parserName;
    fragment += '[';
    fragment += variantName;
    fragment += "]: ";
    fragment += errorMessage;

    const size_t remaining = kMaxErrorMessageLength - result.errorMessage.size();
    if (fragment.size() > remaining) {
        fragment.resize(remaining);
    }

    result.errorMessage += fragment;
}

void PopulateCommonTypeMapping(ParserConfig& config) {
    config.typeMapping.emplace("ip", IOCType::IPv4);
    config.typeMapping.emplace("ipv4", IOCType::IPv4);
    config.typeMapping.emplace("ipv4-addr", IOCType::IPv4);
    config.typeMapping.emplace("ipv6", IOCType::IPv6);
    config.typeMapping.emplace("ipv6-addr", IOCType::IPv6);
    config.typeMapping.emplace("domain", IOCType::Domain);
    config.typeMapping.emplace("domain-name", IOCType::Domain);
    config.typeMapping.emplace("hostname", IOCType::Domain);
    config.typeMapping.emplace("url", IOCType::URL);
    config.typeMapping.emplace("uri", IOCType::URL);
    config.typeMapping.emplace("hash", IOCType::FileHash);
    config.typeMapping.emplace("sha1", IOCType::FileHash);
    config.typeMapping.emplace("sha256", IOCType::FileHash);
    config.typeMapping.emplace("sha512", IOCType::FileHash);
    config.typeMapping.emplace("md5", IOCType::FileHash);
    config.typeMapping.emplace("email", IOCType::Email);
    config.typeMapping.emplace("email-addr", IOCType::Email);
    config.typeMapping.emplace("indicator", IOCType::Domain);
    config.typeMapping.emplace("pattern", IOCType::STIXPattern);
}

[[nodiscard]] ParserConfig BuildDefaultConfig() {
    ParserConfig config{};
    PopulateCommonTypeMapping(config);
    return config;
}

[[nodiscard]] std::vector<ParserVariant> BuildParserVariants() {
    std::vector<ParserVariant> variants;
    variants.reserve(14);

    {
        ParserConfig config = BuildDefaultConfig();
        variants.push_back({ "default", std::move(config) });
    }

    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$.data";
        config.valuePath = "value";
        config.typePath = "type";
        config.confidencePath = "confidence";
        config.reputationPath = "reputation";
        variants.push_back({ "json-data", std::move(config) });
    }

    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$.objects";
        config.valuePath = "indicator";
        config.typePath = "kind";
        config.confidencePath = "score";
        config.reputationPath = "severity";
        config.lowercaseValues = true;
        config.typeMapping["indicator"] = IOCType::URL;
        config.typeMapping["unknown"] = IOCType::Domain;
        variants.push_back({ "json-objects", std::move(config) });
    }

    {
        ParserConfig config = BuildDefaultConfig();
        config.csvHasHeader = false;
        config.csvDelimiter = ',';
        config.csvQuote = '"';
        config.csvValueColumn = 0;
        config.csvTypeColumn = 1;
        variants.push_back({ "csv-comma", std::move(config) });
    }

    {
        ParserConfig config = BuildDefaultConfig();
        config.csvHasHeader = false;
        config.csvDelimiter = ';';
        config.csvQuote = '"';
        config.csvValueColumn = 0;
        config.csvTypeColumn = 1;
        config.lowercaseValues = true;
        config.typeMapping["indicator"] = IOCType::Email;
        variants.push_back({ "csv-semicolon", std::move(config) });
    }

    {
        ParserConfig config = BuildDefaultConfig();
        config.csvHasHeader = false;
        config.csvDelimiter = '\t';
        config.csvQuote = '\'';
        config.csvValueColumn = 0;
        config.csvTypeColumn = -1;
        config.trimWhitespace = true;
        config.lowercaseValues = true;
        variants.push_back({ "csv-tab-autodetect", std::move(config) });
    }

    // ---- Feed-specific configs: exercise the exact parser paths used by real feeds ----

    // URLhaus CSV config (comma-delimited, header row, URL in column 2)
    {
        ParserConfig config = BuildDefaultConfig();
        config.csvDelimiter = ',';
        config.csvQuote = '"';
        config.csvHasHeader = true;
        config.csvValueColumn = 2;
        config.trimWhitespace = true;
        config.skipInvalid = true;
        variants.push_back({ "urlhaus-csv", std::move(config) });
    }

    // MalwareBazaar JSON config
    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$.data";
        config.valuePath = "$.sha256_hash";
        config.firstSeenPath = "$.first_seen";
        config.lastSeenPath = "$.last_seen";
        config.categoryPath = "$.file_type";
        config.tagsPath = "$.tags";
        variants.push_back({ "malwarebazaar-json", std::move(config) });
    }

    // ThreatFox JSON config (multi-type IOC, type mapping)
    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$.data";
        config.valuePath = "$.ioc";
        config.typePath = "$.ioc_type";
        config.categoryPath = "$.threat_type";
        config.confidencePath = "$.confidence_level";
        config.firstSeenPath = "$.first_seen_utc";
        config.lastSeenPath = "$.last_seen_utc";
        config.tagsPath = "$.tags";
        config.typeMapping["ip:port"] = IOCType::IPv4;
        config.typeMapping["domain"] = IOCType::Domain;
        config.typeMapping["url"] = IOCType::URL;
        config.typeMapping["md5_hash"] = IOCType::FileHash;
        config.typeMapping["sha256_hash"] = IOCType::FileHash;
        config.typeMapping["sha1_hash"] = IOCType::FileHash;
        variants.push_back({ "threatfox-json", std::move(config) });
    }

    // Feodo/ET Open/Botvrij: newline-delimited single-column (IP or hash per line)
    {
        ParserConfig config = BuildDefaultConfig();
        config.csvDelimiter = '\n';
        config.csvHasHeader = false;
        config.csvValueColumn = 0;
        config.trimWhitespace = true;
        config.skipInvalid = true;
        variants.push_back({ "line-per-ioc", std::move(config) });
    }

    // PhishTank JSON config (root-level array of objects)
    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$";
        config.valuePath = "$.url";
        config.categoryPath = "$.target";
        config.firstSeenPath = "$.verification_time";
        variants.push_back({ "phishtank-json", std::move(config) });
    }

    // MISP JSON config
    {
        ParserConfig config = BuildDefaultConfig();
        config.iocPath = "$.response.Attribute";
        config.valuePath = "$.value";
        config.typePath = "$.type";
        config.categoryPath = "$.category";
        config.typeMapping["ip-src"] = IOCType::IPv4;
        config.typeMapping["ip-dst"] = IOCType::IPv4;
        config.typeMapping["domain"] = IOCType::Domain;
        config.typeMapping["hostname"] = IOCType::Domain;
        config.typeMapping["url"] = IOCType::URL;
        config.typeMapping["md5"] = IOCType::FileHash;
        config.typeMapping["sha1"] = IOCType::FileHash;
        config.typeMapping["sha256"] = IOCType::FileHash;
        config.typeMapping["email-src"] = IOCType::Email;
        variants.push_back({ "misp-json", std::move(config) });
    }

    // Empty/minimal config (edge case)
    {
        ParserConfig config{};
        variants.push_back({ "empty-config", std::move(config) });
    }

    return variants;
}

void ValidateEntries(
    std::string_view parserName,
    std::string_view variantName,
    const std::vector<IOCEntry>& entries,
    HarnessResult& result)
{
    for (size_t index = 0; index < entries.size(); ++index) {
        const IOCType type = entries[index].type;
        if (!IsValidIOCType(type)) {
            ++result.anomalyCount;
            ++result.validationIssueCount;
            AppendErrorMessage(
                result,
                parserName,
                variantName,
                "Parsed entry contains an invalid IOCType value");
        }
    }
}

void ExerciseParser(
    std::string_view parserName,
    IFeedParser& parser,
    std::span<const uint8_t> input,
    const std::vector<ParserVariant>& variants,
    HarnessResult& result)
{
    for (const auto& variant : variants) {
        std::vector<IOCEntry> entries;
        const bool parsed = parser.Parse(input, entries, variant.config);
        if (parsed) {
            result.parsedOk = true;
            ValidateEntries(parserName, variant.name, entries, result);
            continue;
        }

        AppendErrorMessage(result, parserName, variant.name, parser.GetLastError());
    }
}

}  // namespace

bool ThreatIntelHarness::ParseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    const std::vector<ParserVariant> variants = BuildParserVariants();

    JsonFeedParser jsonParser;
    CsvFeedParser csvParser;
    StixFeedParser stixParser;

    ExerciseParser("json", jsonParser, input, variants, result);
    ExerciseParser("csv", csvParser, input, variants, result);
    ExerciseParser("stix", stixParser, input, variants, result);

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return result.parsedOk;
}

unsigned long ThreatIntelHarness::SEHCallParse(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ParseImpl(data, size, *pResult);
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

HarnessResult ThreatIntelHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallParse(
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

HarnessFunction ThreatIntelHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view ThreatIntelHarness::GetName() noexcept {
    return "threatintel";
}

std::string_view ThreatIntelHarness::GetDescription() noexcept {
    return "ThreatIntel JSON/CSV/STIX feed parser fuzz harness";
}

std::string ThreatIntelHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

int RunThreatIntelFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ThreatIntelFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "threatintel";
    const auto crashDir = workspaceDir / "crashes" / "threatintel";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ThreatIntelFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ThreatIntelFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ThreatIntelHarness::GetName());

    std::cout << "[ThreatIntelFuzzer] Starting ThreatIntel parser fuzzing...\n";
    std::cout << "[ThreatIntelFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ThreatIntelFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ThreatIntelHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ThreatIntelFuzzer] Final Results:\n";
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
