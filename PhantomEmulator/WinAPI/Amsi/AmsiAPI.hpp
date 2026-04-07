/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AmsiAPI.hpp — AMSI antimalware scan interface emulation
 *
 * Emulates the Windows AMSI (Antimalware Scan Interface) surface used
 * by PowerShell, VBScript, JScript, and .NET to submit content for
 * scanning. Modern malware universally patches or bypasses AMSI before
 * executing payloads — detecting that bypass IS the detection.
 *
 * This module:
 *   1. Captures every buffer/string submitted via AmsiScanBuffer/String
 *      for forensic payload extraction (the actual malicious script)
 *   2. Returns AMSI_RESULT_DETECTED to simulate a security product
 *      blocking malicious content (forces malware to reveal bypass code)
 *   3. Detects AMSI bypass techniques: memory patching, VirtualProtect
 *      on AMSI regions, amsiInitFailed manipulation, DLL hijacking
 *   4. Tracks AMSI consumer identity (powershell.exe, wscript.exe, etc.)
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

namespace WinAPI::Amsi {

// ============================================================================
// AMSI Result Constants (Windows SDK parity)
// ============================================================================

static constexpr uint32_t AMSI_RESULT_CLEAN                    = 0;
static constexpr uint32_t AMSI_RESULT_NOT_DETECTED             = 1;
static constexpr uint32_t AMSI_RESULT_BLOCKED_BY_ADMIN_START   = 0x4000;
static constexpr uint32_t AMSI_RESULT_BLOCKED_BY_ADMIN_END     = 0x4FFF;
static constexpr uint32_t AMSI_RESULT_DETECTED                 = 32768;

// HRESULT codes used by AMSI
static constexpr int32_t S_OK            = 0;
static constexpr int32_t E_INVALIDARG    = static_cast<int32_t>(0x80070057);
static constexpr int32_t E_OUTOFMEMORY   = static_cast<int32_t>(0x8007000E);
static constexpr int32_t E_NOT_VALID_STATE = static_cast<int32_t>(0x8007139F);

// ============================================================================
// Resource Caps (defense against hostile allocation abuse)
// ============================================================================

static constexpr uint32_t kMaxAmsiContexts        = 16;
static constexpr uint32_t kMaxSessionsPerContext   = 64;
static constexpr uint32_t kMaxScanContentCapture   = 64 * 1024;  // 64 KB per scan
static constexpr uint32_t kMaxCapturedScans        = 256;
static constexpr uint32_t kMaxBypassEvents         = 128;
static constexpr uint32_t kMaxContentNameLen       = 1024;
static constexpr uint32_t kMaxAppNameLen           = 512;

// ============================================================================
// Forensic Extraction Types
// ============================================================================

struct CapturedAmsiScan {
    std::string              appName;        // Consumer app (e.g. "PowerShell_C:\...")
    std::string              contentName;    // Content identifier provided by caller
    std::vector<uint8_t>     content;        // Raw scan content (up to kMaxScanContentCapture)
    uint32_t                 originalSize;   // Untruncated buffer size
    uint32_t                 result;         // AMSI result we returned
    uint64_t                 instructionNum; // Instruction count at capture time
};

struct AmsiBypassEvent {
    enum class Type : uint8_t {
        PatchDetected,          // AmsiScanBuffer bytes overwritten
        VirtualProtectOnAmsi,   // VirtualProtect on AMSI code region
        InitFailedSet,          // amsiInitFailed flag manipulation
        DllHijackAttempt,       // Manual amsi.dll loading via LoadLibrary
    };

    Type          type;
    GuestAddress  address;          // Guest address involved
    uint64_t      instructionNum;   // Instruction count at event
};

// ============================================================================
// AmsiState — Module-level state (Meyers' singleton)
// ============================================================================
// Holds all emulated AMSI contexts, sessions, captured scan content,
// and bypass detection events. Thread-safe via internal mutex.

class AmsiState {
public:
    [[nodiscard]] static AmsiState& Instance() noexcept;

    // --- Forensic accessors (all return copies under lock) ---
    [[nodiscard]] std::vector<CapturedAmsiScan> GetCapturedScans() const noexcept;
    [[nodiscard]] std::vector<AmsiBypassEvent>  GetBypassEvents() const noexcept;
    [[nodiscard]] uint32_t GetScanCount() const noexcept;
    [[nodiscard]] bool     WasAmsiPatched() const noexcept;

    // --- Bypass event recording (called from external detectors) ---
    void RecordBypassEvent(AmsiBypassEvent::Type type, GuestAddress addr,
                           uint64_t instrNum) noexcept;

    // --- Session cleanup ---
    void Reset() noexcept;

    AmsiState(const AmsiState&) = delete;
    AmsiState& operator=(const AmsiState&) = delete;

private:
    AmsiState() noexcept = default;
};

// ============================================================================
// Registration
// ============================================================================

void RegisterAmsiAPI(APIDispatcher& dispatcher) noexcept;

// ============================================================================
// Individual API Handlers
// ============================================================================
// Each returns true to continue emulation, false to halt.

bool HandleAmsiInitialize(APIContext& ctx);
bool HandleAmsiOpenSession(APIContext& ctx);
bool HandleAmsiCloseSession(APIContext& ctx);
bool HandleAmsiUninitialize(APIContext& ctx);
bool HandleAmsiScanBuffer(APIContext& ctx);
bool HandleAmsiScanString(APIContext& ctx);
bool HandleAmsiResultIsMalware(APIContext& ctx);
bool HandleAmsiNotifyOperation(APIContext& ctx);

} // namespace WinAPI::Amsi
} // namespace Phantom
