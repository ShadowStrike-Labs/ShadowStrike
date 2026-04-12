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
 * @file EmulatorExecutionHarness.cpp
 * @brief Implementation of the PhantomEmulator CPU::Execute fuzz harness.
 *
 * Executes hostile shellcode bytes through Phantom::CPU::Execute() in both
 * Long64 and Protected32 modes with a tightly constrained emulation config,
 * isolated guest memory, invariant validation, and SEH hardening for in-
 * process fuzzing.
 */

#include "ShadowStrike/Fuzzer/Harnesses/EmulatorExecutionHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "PhantomEmulator/Core/CPU/CPU.hpp"
#include "PhantomEmulator/Core/Memory/VirtualMemory.hpp"
#include "PhantomEmulator/Core/Memory/MemoryTracker.hpp"
#include "PhantomEmulator/Common/Config.hpp"
#include "PhantomEmulator/Common/Types.hpp"
#include "PhantomEmulator/Common/Errors.hpp"

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
#include <memory>

namespace ShadowStrike::Fuzzer {
namespace {

using Phantom::CPU;
using Phantom::CPUMode;
using Phantom::CPUState;
using Phantom::EmulationConfig;
using Phantom::EmulationTarget;
using Phantom::ErrorCode;
using Phantom::ExecutionResult;
using Phantom::GPR;
using Phantom::GuestAddress;
using Phantom::GuestSize;
using Phantom::MemProt;
using Phantom::MemoryTracker;
using Phantom::StopReason;
using Phantom::VirtualMemory;

constexpr GuestAddress kCodeBase = 0x00401000ULL;
constexpr GuestSize kCodeSize = 0x1000ULL;
constexpr GuestAddress kStackBase = 0x10000000ULL;   // Away from PEB/TEB at 0x7FFE0000
constexpr GuestSize kStackGuardSize = 0x1000ULL;      // 4KB guard page at bottom
constexpr GuestSize kStackSize = 64ULL * 1024ULL;
constexpr GuestSize kHeapSize = 256ULL * 1024ULL;
constexpr GuestSize kMaxGuestMemory = 16ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxInstructions = 10'000ULL;
constexpr uint64_t kMaxAPICalls = 100ULL;
constexpr GuestAddress kSentinelReturn64 = 0xDEADC0DEDEADC0DEULL;
constexpr uint32_t kSentinelReturn32 = 0xDEADC0DEUL;

std::string ExceptionCodeToStringInternal(DWORD code) noexcept {
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

[[nodiscard]] EmulationConfig BuildFuzzExecutionConfig(CPUMode mode) noexcept {
    EmulationConfig config{};
    config.maxInstructions = kMaxInstructions;
    config.maxAPIcalls = kMaxAPICalls;
    config.maxWallTime = std::chrono::milliseconds{ 500 };
    config.maxGuestMemory = kMaxGuestMemory;
    config.maxThreads = 1;
    config.maxUnpackLayers = 0;
    config.maxStackDepth = 256;
    config.cpuMode = mode;
    config.target = (mode == CPUMode::Long64)
        ? EmulationTarget::Shellcode64
        : EmulationTarget::Shellcode32;
    config.stackSize = kStackSize;
    config.heapSize = kHeapSize;
    config.enableDEP = true;
    config.trackMemoryAccess = false;

    config.enableFileSystem = false;
    config.enableADSTracking = false;
    config.enableRegistry = false;
    config.enableNetwork = false;
    config.enableCOM = false;
    config.enableETW = false;
    config.enableAMSI = false;
    config.enableVSS = false;
    config.enableWMI = false;
    config.enableDotNetAnalysis = false;
    config.blockExternalCalls = false;

    config.enableTimingAcceleration = false;
    config.enableAntiDebugBypass = false;
    config.enableAntiVMBypass = false;
    config.enableAntiSandboxBypass = false;

    config.enableUnpacking = false;
    config.captureUnpackLayers = false;
    config.minOEPInstructions = 0;

    config.enableBehaviorMonitor = false;
    config.enableAPISequenceAnalysis = false;
    config.enableMemoryForensics = false;
    config.enableMITREMapping = false;
    config.enableIOCExtraction = false;
    config.enableTaintAnalysis = false;
    config.enableMLClassifier = false;
    config.yaraScansPerSession = 0;

    config.enableJIT = false;
    config.enableHardwareAccel = false;
    config.enableSIMDScanning = false;
    config.enableCryptoAcceleration = false;
    config.enableMemoryScanAccel = false;
    config.enableJITOptimizer = false;

    config.enableCET = false;
    config.cetEnforceShadowStack = false;
    config.cetEnforceIBT = false;

    config.enableKernelEmulation = false;
    config.enableDKOMDetection = false;
    config.enableSSDTIntegrity = false;
    config.enableIDTIntegrity = false;
    config.enableMSRMonitoring = false;
    config.enableRingTransitionCheck = false;
    config.enableDriverLoading = false;
    config.enableKernelAPITracking = false;
    config.maxKernelDrivers = 0;

    config.enableMultiProcess = false;
    config.maxChildProcesses = 0;
    config.maxInjectedPayloadCapture = 0;

    config.enableWoW64 = false;
    config.detectHeavensGate = false;
    config.enableFsRedirection = false;
    config.enableRegistryRedirection = false;

    config.enableInstructionTrace = false;
    config.enableAPITrace = false;
    config.enableMemoryTrace = false;
    return config;
}

[[nodiscard]] bool IsValidStopReason(StopReason reason) noexcept {
    switch (reason) {
    case StopReason::None:
    case StopReason::InstructionLimit:
    case StopReason::TimeLimit:
    case StopReason::MemoryLimit:
    case StopReason::InvalidInstruction:
    case StopReason::AccessViolation:
    case StopReason::DivideByZero:
    case StopReason::StackOverflow:
    case StopReason::Breakpoint:
    case StopReason::Syscall:
    case StopReason::APICallTrap:
    case StopReason::ExitProcess:
    case StopReason::UnpackComplete:
    case StopReason::Crashed:
    case StopReason::UserAborted:
        return true;
    }

    return false;
}

[[nodiscard]] std::unique_ptr<VirtualMemory> CreateExecutionMemory(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    auto memory = std::make_unique<VirtualMemory>(kMaxGuestMemory);

    std::array<uint8_t, static_cast<size_t>(kCodeSize)> codePage{};
    if (data != nullptr && size != 0) {
        const size_t clampedSize = std::min<size_t>(size, codePage.size());
        std::memcpy(codePage.data(), data, clampedSize);
    }

    const ErrorCode mapErr = memory->MapRegion(
        kCodeBase,
        codePage.data(),
        static_cast<uint32_t>(codePage.size()),
        kCodeSize,
        MemProt::RX);
    if (mapErr != ErrorCode::Success) {
        ++result.anomalyCount;
        if (result.errorMessage.empty()) {
            result.errorMessage = "Failed to map emulator fuzz code page.";
        }
        return nullptr;
    }

    // Allocate stack with guard page at the bottom for stack overflow detection
    const auto guardBase = memory->Allocate(kStackBase, kStackGuardSize, MemProt::None);
    if (!guardBase.has_value() || *guardBase != kStackBase) {
        ++result.anomalyCount;
        if (result.errorMessage.empty()) {
            result.errorMessage = "Failed to allocate emulator fuzz stack guard page.";
        }
        return nullptr;
    }

    const GuestAddress usableStackBase = kStackBase + kStackGuardSize;
    const GuestSize usableStackSize = kStackSize - kStackGuardSize;
    const auto stackBase = memory->Allocate(usableStackBase, usableStackSize, MemProt::RW);
    if (!stackBase.has_value() || *stackBase != usableStackBase) {
        ++result.anomalyCount;
        if (result.errorMessage.empty()) {
            result.errorMessage = "Failed to allocate emulator fuzz stack region.";
        }
        return nullptr;
    }

    return memory;
}

bool StopOnSyscall(CPUState&, VirtualMemory&) noexcept {
    return false;
}

bool StopOnInterrupt(CPUState&, VirtualMemory&, uint8_t) noexcept {
    return false;
}

bool StopOnAPICall(CPUState&, VirtualMemory&, GuestAddress) noexcept {
    return false;
}

void ValidateExecutionResult(
    const ExecutionResult& execResult,
    const EmulationConfig& config,
    HarnessResult& result) noexcept
{
    if (!IsValidStopReason(execResult.reason)) {
        ++result.validationIssueCount;
    }

    if (execResult.instructionsExecuted > config.maxInstructions) {
        ++result.validationIssueCount;
    }

    if (execResult.apiCallCount > config.maxAPIcalls) {
        ++result.validationIssueCount;
    }

    if (execResult.reason == StopReason::InstructionLimit) {
        const uint64_t lowerBound = (config.maxInstructions > 0)
            ? (config.maxInstructions - 1)
            : 0;
        if (execResult.instructionsExecuted < lowerBound) {
            ++result.validationIssueCount;
        }
    }

    if (execResult.reason != StopReason::None
        && execResult.instructionsExecuted > 0
        && execResult.lastRIP == 0) {
        ++result.validationIssueCount;
    }

    if (execResult.reason == StopReason::Crashed || execResult.reason == StopReason::None) {
        ++result.anomalyCount;
    }
}

[[nodiscard]] bool ExecuteMode(
    CPUMode mode,
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    auto memory = CreateExecutionMemory(data, size, result);
    if (!memory) {
        return false;
    }

    MemoryTracker tracker;
    tracker.Reset();

    CPU cpu;
    cpu.SetSyscallCallback(StopOnSyscall);
    cpu.SetInterruptCallback(StopOnInterrupt);
    cpu.SetAPICallCallback(StopOnAPICall);
    cpu.SetAPIHookRange(0, 0);

    auto& state = cpu.State();
    if (mode == CPUMode::Long64) {
        cpu.Reset64();
        const GuestAddress rsp = Phantom::AlignDown(kStackBase + kStackSize, 16) - 8;
        if (memory->WriteU64(rsp, kSentinelReturn64) != ErrorCode::Success) {
            ++result.anomalyCount;
            if (result.errorMessage.empty()) {
                result.errorMessage = "Failed to initialize 64-bit emulator fuzz stack.";
            }
            return false;
        }
        state.SetRIP(kCodeBase);
        state.SetReg64(GPR::RSP, rsp);
    } else {
        cpu.Reset32();
        const GuestAddress esp = Phantom::AlignDown(kStackBase + kStackSize, 4) - 4;
        if (memory->WriteU32(esp, kSentinelReturn32) != ErrorCode::Success) {
            ++result.anomalyCount;
            if (result.errorMessage.empty()) {
                result.errorMessage = "Failed to initialize 32-bit emulator fuzz stack.";
            }
            return false;
        }
        state.SetRIP(kCodeBase);
        state.SetReg32(GPR::RSP, static_cast<uint32_t>(esp));
    }

    const EmulationConfig config = BuildFuzzExecutionConfig(mode);
    const ExecutionResult execResult = cpu.Execute(*memory, &tracker, config);
    ValidateExecutionResult(execResult, config, result);
    return true;
}

}  // anonymous namespace

std::string EmulatorExecutionHarness::ExceptionCodeToString(unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool EmulatorExecutionHarness::ExecutionImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();

    bool executedAny = false;
    executedAny |= ExecuteMode(CPUMode::Long64, data, size, result);
    executedAny |= ExecuteMode(CPUMode::Protected32, data, size, result);
    result.parsedOk = executedAny;

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return executedAny;
}

unsigned long EmulatorExecutionHarness::SEHCallExecution(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        ExecutionImpl(data, size, *pResult);
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

HarnessResult EmulatorExecutionHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallExecution(
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

HarnessFunction EmulatorExecutionHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view EmulatorExecutionHarness::GetName() noexcept {
    return "emu-execution";
}

std::string_view EmulatorExecutionHarness::GetDescription() noexcept {
    return "PhantomEmulator CPU::Execute fuzz harness for 64-bit and 32-bit shellcode execution";
}

int RunEmulatorExecutionFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[EmuExecutionFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "emulator" / "execution";
    const auto crashDir = workspaceDir / "crashes" / "emulator" / "execution";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[EmuExecutionFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[EmuExecutionFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(EmulatorExecutionHarness::GetName());

    std::cout << "[EmuExecutionFuzzer] Starting emulator execution fuzzing...\n";
    std::cout << "[EmuExecutionFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[EmuExecutionFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, EmulatorExecutionHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[EmuExecutionFuzzer] Final Results:\n";
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
