/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VssAPI.hpp — VSS shadow copy deletion detection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Vss {

// ============================================================================
// VSS deletion method taxonomy — every known ransomware technique
// ============================================================================

enum class VssDeleteMethod : uint8_t {
    VssAdmin,           // vssadmin delete shadows
    VssAdminResize,     // vssadmin resize shadowstorage
    WmicShadowCopy,     // wmic shadowcopy delete
    PowerShellWmi,      // powershell/pwsh with shadowcopy delete
    DirectCom,          // CoCreateInstance on IVssBackupComponents
    BcdeditRecovery,    // bcdedit /set recoveryenabled No
    BcdeditBootPolicy,  // bcdedit /set bootstatuspolicy ignoreallfailures
    WbadminCatalog,     // wbadmin delete catalog
    CipherWipe,         // cipher /w: overwrite free space
    DiskShadow,         // diskshadow /s script-based deletion
    RegistryDisable,    // DisableSR or DisableSystemBackup via registry
    UnknownMethod,
};

// ============================================================================
// Event record captured for each detection
// ============================================================================

struct VssDeleteEvent {
    VssDeleteMethod method;
    std::string     commandLine;
    std::string     details;
    uint64_t        instructionNum = 0;
};

// ============================================================================
// VssDetector — Meyers' singleton for VSS behavior tracking
// ============================================================================
//
// Cross-cutting detection engine invoked by:
//   - CreateProcess/WinExec/ShellExecute handlers (command line analysis)
//   - CoCreateInstance handler (COM CLSID matching)
//   - RegSetValue handlers (registry disable patterns)
//
// Thread-safe: all public methods are guarded by m_mutex.

class VssDetector {
public:
    [[nodiscard]] static VssDetector& Instance() noexcept;

    VssDetector(const VssDetector&) = delete;
    VssDetector& operator=(const VssDetector&) = delete;

    // Command line analysis — called by process creation handlers.
    // Returns true if the command line contains VSS deletion behavior.
    [[nodiscard]] bool AnalyzeCommandLine(std::string_view cmdLine,
                                          uint64_t instrNum) noexcept;
    [[nodiscard]] bool AnalyzeCommandLineW(std::wstring_view cmdLine,
                                           uint64_t instrNum) noexcept;

    // COM CLSID analysis — called by CoCreateInstance handler.
    // Returns true if the CLSID is VSS-related.
    [[nodiscard]] bool AnalyzeComCreation(uint64_t clsidAddr,
                                          const uint8_t* clsidBytes,
                                          uint64_t instrNum) noexcept;

    // Registry analysis — called by RegSetValue handlers.
    // Returns true if the write disables system restore or backup.
    [[nodiscard]] bool AnalyzeRegistryWrite(std::wstring_view keyPath,
                                            std::wstring_view valueName,
                                            uint32_t data,
                                            uint64_t instrNum) noexcept;

    // Forensic extraction
    [[nodiscard]] std::vector<VssDeleteEvent> GetEvents() const noexcept;
    [[nodiscard]] uint32_t GetDeleteAttemptCount() const noexcept;
    [[nodiscard]] bool     HasRansomwareBehavior() const noexcept;
    [[nodiscard]] float    GetRansomwareScore() const noexcept;

    void Reset() noexcept;

private:
    VssDetector() = default;

    mutable std::mutex          m_mutex;
    std::vector<VssDeleteEvent> m_events;
    uint32_t                    m_uniqueMethodMask = 0;
};

// ============================================================================
// Registration and handlers
// ============================================================================

// Register vssapi.dll handlers with the dispatcher.
void RegisterVssAPI(APIDispatcher& dispatcher) noexcept;

// Direct handler: CreateVssBackupComponentsInternal (vssapi.dll)
bool HandleCreateVssBackupComponents(APIContext& ctx);

} // namespace WinAPI::Vss
} // namespace Phantom
