/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "Types.hpp"
#include "../Core/JIT/JITCompiler.hpp"
#include <cstdint>
#include <string>
#include <chrono>

namespace Phantom {

// ============================================================================
// Emulation Configuration
// ============================================================================

struct EmulationConfig {
    // === Execution limits ===
    uint64_t maxInstructions     = 50'000'000;     // 50M instructions default
    uint64_t maxAPIcalls         = 100'000;         // Bail if this many API calls
    std::chrono::milliseconds    maxWallTime{ 30'000 }; // 30 seconds wall clock
    GuestSize maxGuestMemory     = 256ULL * 1024 * 1024;  // 256 MB default
    uint32_t  maxThreads         = 8;              // Max emulated threads
    uint32_t  maxUnpackLayers    = 16;             // Max packing layers before bail
    uint32_t  maxStackDepth      = 4096;           // Max call stack depth

    // === CPU mode ===
    CPUMode   cpuMode            = CPUMode::Long64;
    EmulationTarget target       = EmulationTarget::PE64;

    // === Memory ===
    GuestSize stackSize          = 1024 * 1024;    // 1 MB per thread
    GuestSize heapSize           = 4 * 1024 * 1024; // 4 MB initial heap
    bool      enableDEP          = true;            // Enforce W^X
    bool      trackMemoryAccess  = true;            // Log all memory ops (slower but needed for analysis)

    // === API emulation behavior ===
    bool      enableFileSystem   = true;            // Virtual filesystem
    bool      enableRegistry     = true;            // Virtual registry
    bool      enableNetwork      = false;           // Virtual network (disabled: security)
    bool      enableCOM          = false;           // COM object emulation
    bool      blockExternalCalls = true;            // Block unrecognized API calls

    // === Anti-evasion ===
    bool      enableTimingAcceleration = true;      // Accelerate Sleep/GetTickCount
    bool      enableAntiDebugBypass    = true;      // Fake IsDebuggerPresent etc
    bool      enableAntiVMBypass       = true;      // Hide emulation artifacts
    bool      enableAntiSandboxBypass  = true;      // Fake environment info
    uint64_t  fakeTickCount            = 0;         // Starting tick count (0 = randomize)
    uint64_t  fakeTSCFrequency         = 3'800'000'000ULL; // 3.8 GHz TSC

    // === Unpacking ===
    bool      enableUnpacking    = true;            // Track W→X transitions
    bool      captureUnpackLayers = true;           // Dump each unpack layer
    double    entropyThreshold   = 7.0;             // Shannon entropy threshold for "packed"
    uint32_t  minOEPInstructions = 50;              // Min instructions at suspected OEP

    // === Analysis ===
    bool      enableBehaviorMonitor   = true;
    bool      enableAPISequenceAnalysis = true;
    bool      enableMemoryForensics   = true;
    bool      enableMITREMapping      = true;
    bool      enableIOCExtraction     = true;
    uint32_t  yaraScansPerSession     = 4;          // Periodic YARA scans during emulation

    // === JIT compilation ===
    bool        enableJIT          = false;              // Disabled by default (opt-in)
    JITStrategy jitStrategy        = JITStrategy::BasicBlock;
    uint32_t    jitCodeCacheSize   = 4 * 1024 * 1024;   // 4 MB
    uint32_t    jitHotThreshold    = 64;                 // Interpret N times before compiling

    // === Multi-process emulation ===
    bool      enableMultiProcess        = true;
    uint32_t  maxChildProcesses         = 8;           // Max child processes per session
    GuestSize maxInjectedPayloadCapture = 64 * 1024;   // 64 KB capture per injection

    // === Performance tuning ===
    uint32_t  instructionCacheSize = 4096;          // Decoded instruction cache entries
    bool      enableInstructionTrace = false;       // Full trace (very slow, debug only)
    bool      enableAPITrace     = true;            // Log all API calls
    bool      enableMemoryTrace  = false;           // Log all memory accesses (very slow)

    // === Environment faking ===
    std::wstring computerName     = L"DESKTOP-A7B3CF9";
    std::wstring userName         = L"JSmith";
    std::wstring domainName       = L"CORP";
    std::wstring windowsVersion   = L"10.0.19045";  // Win10 22H2
    uint32_t     osBuildNumber    = 19045;
    uint32_t     processorCount   = 8;
    uint64_t     totalPhysicalMem = 16ULL * 1024 * 1024 * 1024; // 16 GB
};

// ============================================================================
// Quick Presets
// ============================================================================

[[nodiscard]] inline EmulationConfig FastScanConfig() noexcept {
    EmulationConfig cfg;
    cfg.maxInstructions = 5'000'000;
    cfg.maxWallTime = std::chrono::milliseconds{ 5'000 };
    cfg.maxGuestMemory = 64ULL * 1024 * 1024;
    cfg.trackMemoryAccess = false;
    cfg.enableInstructionTrace = false;
    cfg.enableMemoryTrace = false;
    cfg.enableBehaviorMonitor = false;
    cfg.enableAPISequenceAnalysis = false;
    cfg.yaraScansPerSession = 1;
    return cfg;
}

[[nodiscard]] inline EmulationConfig DeepAnalysisConfig() noexcept {
    EmulationConfig cfg;
    cfg.maxInstructions = 200'000'000;
    cfg.maxWallTime = std::chrono::milliseconds{ 120'000 };
    cfg.maxGuestMemory = 512ULL * 1024 * 1024;
    cfg.trackMemoryAccess = true;
    cfg.enableInstructionTrace = true;
    cfg.enableAPITrace = true;
    cfg.enableNetwork = true;
    cfg.yaraScansPerSession = 8;
    return cfg;
}

[[nodiscard]] inline EmulationConfig UnpackOnlyConfig() noexcept {
    EmulationConfig cfg;
    cfg.maxInstructions = 100'000'000;
    cfg.maxWallTime = std::chrono::milliseconds{ 60'000 };
    cfg.enableUnpacking = true;
    cfg.captureUnpackLayers = true;
    cfg.enableBehaviorMonitor = false;
    cfg.enableAPISequenceAnalysis = false;
    cfg.enableMITREMapping = false;
    cfg.enableIOCExtraction = false;
    cfg.yaraScansPerSession = 2;
    return cfg;
}

} // namespace Phantom
