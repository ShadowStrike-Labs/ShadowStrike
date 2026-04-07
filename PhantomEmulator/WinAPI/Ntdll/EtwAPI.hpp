/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EtwAPI.hpp — ETW event tracing API emulation handlers
 *
 * Emulates the ntdll.dll ETW API surface that advanced malware targets for
 * defense evasion. Modern threat actors (Cobalt Strike, Brute Ratel, APT29,
 * Seatbelt) disable ETW telemetry by:
 *
 *   1. Patching EtwEventWrite with a RET instruction to blind EDR sensors
 *   2. Calling NtProtectVirtualMemory on ETW function addresses (W→X)
 *   3. Unregistering security-sensitive ETW providers (TI, AMSI, .NET)
 *   4. Checking provider registration state for sandbox detection
 *
 * This module captures all ETW interaction for behavioral analysis and flags
 * patching/blinding attempts as DefenseEvasion + AntiAnalysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// ============================================================================
// Forensic Extraction Types
// ============================================================================

/// A 128-bit GUID stored in unpacked form for easy comparison.
struct EtwGuid {
    uint32_t data1    = 0;
    uint16_t data2    = 0;
    uint16_t data3    = 0;
    uint8_t  data4[8] = {};

    [[nodiscard]] bool operator==(const EtwGuid& o) const noexcept;
    [[nodiscard]] bool operator!=(const EtwGuid& o) const noexcept { return !(*this == o); }

    /// Human-readable "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" form.
    [[nodiscard]] std::string ToString() const noexcept;
};

/// Recorded provider registration.
struct EtwProviderInfo {
    uint64_t    regHandle  = 0;       // Emulated REGHANDLE
    EtwGuid     providerId;           // Provider GUID
    std::string guidString;           // Cached "{...}" string
    bool        isSensitive = false;  // True if TI, AMSI, .NET, Kernel-Audit
    uint32_t    eventWriteCount = 0;  // Events emitted through this provider
};

/// Captured ETW patching / blinding attempt.
struct EtwBlindingEvent {
    enum class Kind : uint8_t {
        FunctionPatched  = 0,   // RET written over EtwEventWrite or similar
        ProtectionChange = 1,   // VirtualProtect on ETW function page
        ProviderTampering = 2,  // Unregister of sensitive provider
    };

    Kind         kind        = Kind::FunctionPatched;
    GuestAddress patchAddr   = 0;   // Guest virtual address targeted
    std::string  targetFunc;        // "EtwEventWrite", etc.
    std::string  detail;            // Additional context
};

// ============================================================================
// EtwState — Module-level singleton for ETW emulation state
// ============================================================================
// Meyers' singleton holding all emulated provider registrations, event write
// counts, and blinding event forensics. Thread-safe via internal mutex.

class EtwState {
public:
    [[nodiscard]] static EtwState& Instance() noexcept;

    // --- Forensic extraction ---------------------------------------------------

    /// Snapshot of all currently registered providers.
    [[nodiscard]] std::vector<EtwProviderInfo> GetRegisteredProviders() const noexcept;

    /// All detected ETW blinding/patching events.
    [[nodiscard]] std::vector<EtwBlindingEvent> GetBlindingEvents() const noexcept;

    /// Total number of EtwEventWrite / NtTraceEvent calls observed.
    [[nodiscard]] uint32_t GetEventWriteCount() const noexcept;

    /// True if any blinding event has been recorded.
    [[nodiscard]] bool WasEtwPatched() const noexcept;

    // --- Internal mutation (called from handlers) ------------------------------

    void RegisterProvider(uint64_t regHandle, const EtwGuid& guid,
                          bool sensitive) noexcept;
    void UnregisterProvider(uint64_t regHandle) noexcept;
    void IncrementEventWriteCount(uint64_t regHandle) noexcept;
    void RecordBlindingEvent(EtwBlindingEvent evt) noexcept;

    /// Check if a given REGHANDLE is known-sensitive.
    [[nodiscard]] bool IsHandleSensitive(uint64_t regHandle) const noexcept;

    // --- Session lifecycle -----------------------------------------------------

    void Reset() noexcept;

    EtwState(const EtwState&)            = delete;
    EtwState& operator=(const EtwState&) = delete;

private:
    EtwState() noexcept = default;
};

// ============================================================================
// Registration
// ============================================================================

void RegisterEtwAPI(APIDispatcher& dispatcher) noexcept;

// ============================================================================
// Individual API Handlers
// ============================================================================
// Each returns true → continue emulation, false → halt.

bool HandleEtwEventRegister(APIContext& ctx);
bool HandleEtwEventUnregister(APIContext& ctx);
bool HandleEtwEventWrite(APIContext& ctx);
bool HandleEtwEventWriteFull(APIContext& ctx);
bool HandleNtTraceEvent(APIContext& ctx);
bool HandleNtTraceControl(APIContext& ctx);
bool HandleEtwEventEnabled(APIContext& ctx);
bool HandleEtwGetTraceLoggerHandle(APIContext& ctx);
bool HandleEtwGetTraceEnableFlags(APIContext& ctx);
bool HandleEtwGetTraceEnableLevel(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
