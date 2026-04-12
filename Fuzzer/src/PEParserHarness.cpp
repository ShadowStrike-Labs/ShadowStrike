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
 * @file PEParserHarness.cpp
 * @brief Implementation of the PE parser fuzz harness.
 *
 * Uses Windows Vectored Exception Handling (VEH) to catch hardware exceptions
 * (access violations, stack overflows, etc.) in addition to C++ exceptions.
 * 
 * Note: The PE parser API is designed to be noexcept-safe and handle all
 * bounds checking internally. This harness wraps it with additional exception
 * handling for defense in depth during fuzzing.
 */

#include "ShadowStrike/Fuzzer/Harnesses/PEParserHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "ShadowStrike/Fuzzer/Core/MutationEngine.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

// Suppress warnings from PE parser headers
#pragma warning(push)
#pragma warning(disable: 4201)  // nameless struct/union

// Include PE parser headers
#include "src/PhantomCore/PEParser/PEParser.hpp"
#include "src/PhantomCore/PEParser/PEValidation.hpp"
#include "src/PhantomCore/PEParser/SafeReader.hpp"

#pragma warning(pop)

#include <chrono>
#include <iomanip>
#include <iostream>

namespace ShadowStrike::Fuzzer {

// ============================================================================
// Thread-local state for VEH crash detection
// ============================================================================

namespace {

// Thread-local crash state for VEH
thread_local bool g_inHarness = false;
thread_local bool g_crashDetected = false;
thread_local DWORD g_exceptionCode = 0;

// Vectored Exception Handler
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS exceptionInfo) {
    if (!g_inHarness) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    const DWORD code = exceptionInfo->ExceptionRecord->ExceptionCode;
    
    // Check for fatal exceptions
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_GUARD_PAGE:
    case STATUS_HEAP_CORRUPTION:
        g_crashDetected = true;
        g_exceptionCode = code;
        // Note: We cannot safely longjmp out of here in C++
        // Just record the crash and let it propagate
        return EXCEPTION_CONTINUE_SEARCH;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

// VEH registration
class VEHGuard {
public:
    VEHGuard() noexcept {
        m_handler = AddVectoredExceptionHandler(1, VectoredHandler);
    }
    
    ~VEHGuard() {
        if (m_handler) {
            RemoveVectoredExceptionHandler(m_handler);
        }
    }
    
    VEHGuard(const VEHGuard&) = delete;
    VEHGuard& operator=(const VEHGuard&) = delete;
    
private:
    PVOID m_handler = nullptr;
};

// Global VEH guard - installs handler on startup
VEHGuard g_vehGuard;

// Convert Windows exception code to string
std::string ExceptionCodeToStringInternal(DWORD code) noexcept {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
        return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:
        return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:
        return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:
        return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:
        return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:
        return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:
        return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:
        return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:
        return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:
        return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:
        return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_INVALID_HANDLE:
        return "EXCEPTION_INVALID_HANDLE";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:
        return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:
        return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:
        return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:
        return "STATUS_HEAP_CORRUPTION";
    default:
        char buf[32];
        snprintf(buf, sizeof(buf), "EXCEPTION_0x%08lX", code);
        return buf;
    }
}

// RAII guard for harness execution
class HarnessGuard {
public:
    HarnessGuard() noexcept {
        g_inHarness = true;
        g_crashDetected = false;
        g_exceptionCode = 0;
    }
    
    ~HarnessGuard() {
        g_inHarness = false;
    }
    
    [[nodiscard]] bool WasCrashDetected() const noexcept {
        return g_crashDetected;
    }
    
    [[nodiscard]] DWORD GetExceptionCode() const noexcept {
        return g_exceptionCode;
    }
    
    HarnessGuard(const HarnessGuard&) = delete;
    HarnessGuard& operator=(const HarnessGuard&) = delete;
};

}  // namespace

// ============================================================================
// PEParserHarness Implementation
// ============================================================================

std::string PEParserHarness::ExceptionCodeToString(unsigned int code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool PEParserHarness::TryParseBuffer(
    const uint8_t* data,
    size_t size,
    HarnessResult& result) noexcept
{
    PEParser::PEParser parser;
    PEParser::PEInfo info;
    PEParser::PEError error;
    
    const auto startTime = std::chrono::high_resolution_clock::now();
    
    result.parsedOk = parser.ParseBuffer(data, size, info, &error);
    
    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - startTime).count());
    
    result.anomalyCount = static_cast<uint32_t>(info.anomalies.size());
    
    if (result.parsedOk) {
        // Exercise lazy-loaded parsers
        {
            std::vector<PEParser::ImportInfo> imports;
            (void)parser.ParseImports(imports, &error);
        }
        {
            PEParser::ExportDirectoryInfo exports;
            (void)parser.ParseExports(exports, &error);
        }
        {
            PEParser::TLSInfo tls;
            (void)parser.ParseTLS(tls, &error);
        }
        {
            std::vector<PEParser::ResourceEntry> resources;
            (void)parser.ParseResources(resources, 16, &error);
        }
        {
            std::vector<PEParser::RelocationBlock> relocs;
            (void)parser.ParseRelocations(relocs, &error);
        }
        {
            std::vector<PEParser::DebugInfo> debugInfo;
            (void)parser.ParseDebugInfo(debugInfo, &error);
        }
        {
            PEParser::RichHeaderInfo richHeader;
            (void)parser.ParseRichHeader(richHeader, &error);
        }
        {
            std::vector<PEParser::DelayImportInfo> delayImports;
            (void)parser.ParseDelayImports(delayImports, &error);
        }
        {
            PEParser::LoadConfigInfo loadConfig;
            (void)parser.ParseLoadConfig(loadConfig, &error);
        }
        {
            std::vector<PEParser::ExceptionEntry> exceptions;
            (void)parser.ParseExceptionDirectory(exceptions, &error);
        }
        
        // Validation
        {
            std::vector<PEParser::ValidationResult> issues;
            (void)parser.ValidatePE(issues);
            result.validationIssueCount = static_cast<uint32_t>(issues.size());
        }
        
        // Checksum
        (void)parser.VerifyChecksum();
        
        // Test RvaToOffset with various RVAs
        constexpr uint32_t testRvas[] = {
            0x0000, 0x0001, 0x0040, 0x0100,
            0x1000, 0x2000, 0x3000, 0x4000,
            0x10000, 0x100000, 0x1000000,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
        };
        for (uint32_t rva : testRvas) {
            (void)parser.RvaToOffset(rva);
        }
    }
    
    return true;
}

bool PEParserHarness::TryParseLazyLoaded(HarnessResult& /* result */) noexcept {
    // Lazy-loaded parsing is done inside TryParseBuffer
    return true;
}

bool PEParserHarness::TryValidate(HarnessResult& /* result */) noexcept {
    // Validation is done inside TryParseBuffer
    return true;
}

bool PEParserHarness::TryStandaloneValidation(
    const uint8_t* data,
    size_t size,
    HarnessResult& result) noexcept
{
    PEParser::SafeReader reader(data, size);
    PEParser::PEError error;
    
    int32_t lfanew = 0;
    const auto dosResult = PEParser::ValidateDosHeader(reader, lfanew, &error);
    
    if (dosResult != PEParser::ValidationResult::Valid) {
        ++result.validationIssueCount;
    }
    
    if (dosResult == PEParser::ValidationResult::Valid && lfanew > 0) {
        const auto ntOffset = static_cast<size_t>(lfanew);
        
        bool is64Bit = false;
        PEParser::FileHeader fileHeader{};
        const auto ntResult = PEParser::ValidateNtHeaders(
            reader, ntOffset, is64Bit, fileHeader, &error);
        
        if (ntResult != PEParser::ValidationResult::Valid) {
            ++result.validationIssueCount;
        }
        
        if (ntResult == PEParser::ValidationResult::Valid) {
            const size_t optionalOffset = ntOffset + 4 + sizeof(PEParser::FileHeader);
            
            if (is64Bit) {
                PEParser::OptionalHeader64 optional{};
                const auto optResult = PEParser::ValidateOptionalHeader64(
                    reader, optionalOffset, fileHeader.SizeOfOptionalHeader,
                    optional, &error);
                if (optResult != PEParser::ValidationResult::Valid) {
                    ++result.validationIssueCount;
                }
            } else {
                PEParser::OptionalHeader32 optional{};
                const auto optResult = PEParser::ValidateOptionalHeader32(
                    reader, optionalOffset, fileHeader.SizeOfOptionalHeader,
                    optional, &error);
                if (optResult != PEParser::ValidationResult::Valid) {
                    ++result.validationIssueCount;
                }
            }
        }
    }
    
    return true;
}

HarnessResult PEParserHarness::RunInternal(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};
    
    if (input.empty()) {
        result.parsedOk = false;
        return result;
    }
    
    // Enable crash detection
    HarnessGuard guard;
    
    // Phase 1: Parse buffer through main API
    (void)TryParseBuffer(input.data(), input.size(), result);
    
    // Check if VEH detected a crash
    if (guard.WasCrashDetected()) {
        result.crashed = true;
        result.crashSignal = ExceptionCodeToStringInternal(guard.GetExceptionCode());
        return result;
    }
    
    // Phase 2: Standalone validation functions
    (void)TryStandaloneValidation(input.data(), input.size(), result);
    
    // Check if VEH detected a crash
    if (guard.WasCrashDetected()) {
        result.crashed = true;
        result.crashSignal = ExceptionCodeToStringInternal(guard.GetExceptionCode());
    }
    
    return result;
}

HarnessResult PEParserHarness::Run(std::span<const uint8_t> input) noexcept {
    // Outer try-catch for any C++ exceptions that escape
    try {
        return RunInternal(input);
    } catch (const std::exception& e) {
        HarnessResult result{};
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = e.what();
        return result;
    } catch (...) {
        HarnessResult result{};
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
        return result;
    }
}

HarnessFunction PEParserHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view PEParserHarness::GetName() noexcept {
    return "pe-parser";
}

std::string_view PEParserHarness::GetDescription() noexcept {
    return "PE (Portable Executable) parser fuzz harness for ShadowStrike NGAV";
}

// ============================================================================
// Convenience Function
// ============================================================================

int RunPEParserFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    // Install Ctrl+C handler
    if (!InstallCtrlCHandler()) {
        std::cerr << "[PEParserFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }
    
    // Setup paths
    const auto corpusDir = workspaceDir / "corpora" / "parser" / "pe";
    const auto crashDir = workspaceDir / "crashes" / "pe";
    
    // Create directories
    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[PEParserFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }
    
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[PEParserFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }
    
    // Create config with target name
    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(PEParserHarness::GetName());
    
    // Create and run fuzz loop
    std::cout << "[PEParserFuzzer] Starting PE parser fuzzing...\n";
    std::cout << "[PEParserFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[PEParserFuzzer] Crashes: " << crashDir << '\n';
    
    FuzzLoop loop(corpusDir, crashDir, PEParserHarness::GetHarnessFunction(), loopConfig);
    
    const bool success = loop.Run();
    
    const auto& stats = loop.GetStatistics();
    
    std::cout << "\n[PEParserFuzzer] Final Results:\n";
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
