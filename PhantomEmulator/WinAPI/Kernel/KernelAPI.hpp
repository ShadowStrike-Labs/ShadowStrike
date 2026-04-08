/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelAPI.hpp — Kernel API emulation handlers for rootkit/driver analysis
 *
 * Replaces the simple RET stubs pre-registered by DriverLoader with
 * behavioral tracking handlers that:
 *   1. Log every kernel API call the loaded driver makes
 *   2. Update kernel structures (process creation, driver registration, etc.)
 *   3. Detect suspicious API usage patterns (SSDT manipulation, process
 *      hiding, APC injection, MMIO mapping)
 *   4. Report MITRE ATT&CK techniques
 *
 * Covers ntoskrnl.exe exports: memory management, process/thread ops,
 * object manager, registry (Zw*), file system (Zw*), device I/O,
 * callback registration, and rootkit-relevant primitives.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel {

// ============================================================================
// Kernel API Call Record — per-call telemetry for the analysis engine
// ============================================================================

struct KernelAPICallRecord {
    std::string apiName;
    std::string moduleName;         // ntoskrnl.exe, hal.dll, etc.
    uint64_t    arg1            = 0;
    uint64_t    arg2            = 0;
    uint64_t    arg3            = 0;
    uint64_t    arg4            = 0;
    uint64_t    returnValue     = 0;
    uint64_t    timestamp       = 0;
    bool        isSuspicious    = false;
    std::string suspiciousReason;
};

// ============================================================================
// Kernel API Report — aggregated session-level analysis output
// ============================================================================

struct KernelAPIReport {
    std::vector<KernelAPICallRecord> calls;
    uint32_t totalCalls             = 0;
    uint32_t suspiciousCalls        = 0;

    // Category counters
    uint32_t memoryAllocations      = 0;
    uint32_t processManipulations   = 0;
    uint32_t registryOperations     = 0;
    uint32_t fileOperations         = 0;
    uint32_t callbackRegistrations  = 0;
    uint32_t hookingAttempts        = 0;

    // Suspicious-activity flags
    bool usesDirectSSDTAccess           = false;
    bool usesProcessAttach              = false;
    bool usesMmMapIoSpace               = false;
    bool usesDynamicImportResolution    = false;
    bool usesAPCInjection               = false;
    bool registersSecurityCallbacks     = false;

    std::vector<std::string> mitreTechniques;
};

// ============================================================================
// KernelAPITracker — Thread-safe, session-scoped telemetry aggregator
// ============================================================================
// Meyers' singleton — one tracker per emulation session.
// PIMPL hides all mutable state behind the firewall.

class KernelAPITracker {
public:
    static KernelAPITracker& Instance();
    void Reset();

    void RecordCall(const KernelAPICallRecord& record);

    // Category / flag / MITRE mutation — called by handlers
    void IncrementMemoryAllocations();
    void IncrementProcessManipulations();
    void IncrementRegistryOperations();
    void IncrementFileOperations();
    void IncrementCallbackRegistrations();
    void IncrementHookingAttempts();

    void FlagDirectSSDTAccess();
    void FlagProcessAttach();
    void FlagMmMapIoSpace();
    void FlagDynamicImportResolution();
    void FlagAPCInjection();
    void FlagSecurityCallbacks();

    void AddMitreTechnique(const std::string& technique);

    [[nodiscard]] KernelAPIReport GenerateReport() const;
    [[nodiscard]] uint32_t        GetCallCount() const;
    [[nodiscard]] bool             HasSuspiciousActivity() const;

private:
    KernelAPITracker();
    ~KernelAPITracker();

    KernelAPITracker(const KernelAPITracker&) = delete;
    KernelAPITracker& operator=(const KernelAPITracker&) = delete;
    KernelAPITracker(KernelAPITracker&&) = delete;
    KernelAPITracker& operator=(KernelAPITracker&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Registration entry point (follows WinAPI module pattern)
// ============================================================================

void RegisterKernelAPIs(APIDispatcher& dispatcher) noexcept;

} // namespace WinAPI::Kernel
} // namespace Phantom
