/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VssAPI.cpp — VSS shadow copy deletion detection
 *
 * Detects every known ransomware VSS deletion technique across three
 * independent API surfaces:
 *
 *   1. Command-line analysis (CreateProcess/WinExec/ShellExecute)
 *      - vssadmin delete shadows / resize shadowstorage
 *      - wmic shadowcopy delete
 *      - bcdedit /set recoveryenabled No / bootstatuspolicy ignoreallfailures
 *      - wbadmin delete catalog
 *      - cipher /w:
 *      - powershell/pwsh with shadowcopy delete
 *      - diskshadow /s
 *
 *   2. COM CLSID monitoring (CoCreateInstance)
 *      - IVssBackupComponents {E579AB5F-1CC4-44b4-BED9-DE0991FF0623}
 *      - IVssAsync            {507C37B4-CF5B-4e95-B0AF-14EB9767467E}
 *
 *   3. Registry monitoring (RegSetValue)
 *      - DisableSR = 1 under SystemRestore
 *      - DisableSystemBackup = 1 under Backup\Client
 *
 * Every detection is a STRONG ransomware signal.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VssAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <cctype>
#include <bit>

// DESIGN: Guest writebacks and the AnalyzeComCreation probe both return
// [[nodiscard]] bools we intentionally ignore. Guest writeback failure is
// a guest-side fault; the probe's return is surfaced via the detector
// singleton instead of the call site.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Vss {

// ============================================================================
// COM HRESULT constants
// ============================================================================

static constexpr int32_t kE_NOTIMPL = static_cast<int32_t>(0x80004001);

// ============================================================================
// GUID size (Data1[4] + Data2[2] + Data3[2] + Data4[8])
// ============================================================================

static constexpr uint32_t kGuidSize = 16;

// ============================================================================
// Resource caps and scoring constants
// ============================================================================

static constexpr uint32_t kMaxEvents        = 1024;
static constexpr uint32_t kMaxCommandLineLen = 32 * 1024;
static constexpr float    kScorePerMethod    = 0.15f;
static constexpr float    kMaxScore          = 1.0f;

// ============================================================================
// String lowering utilities — operates in-place, ASCII-only
// ============================================================================

static void ToLowerInPlace(std::string& s) noexcept {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
    }
}

[[nodiscard]] static std::string NarrowFromWide(std::wstring_view wide,
                                                uint32_t maxLen) noexcept {
    const uint32_t len = static_cast<uint32_t>(
        std::min(wide.size(), static_cast<size_t>(maxLen)));
    std::string result;
    result.reserve(len);
    for (uint32_t i = 0; i < len; ++i) {
        const wchar_t wc = wide[i];
        result += (wc < 128) ? static_cast<char>(wc) : '?';
    }
    return result;
}

static void ToLowerInPlaceW(std::wstring& s) noexcept {
    for (auto& c : s) {
        if (c >= L'A' && c <= L'Z') {
            c = static_cast<wchar_t>(c + (L'a' - L'A'));
        }
    }
}

// ============================================================================
// Substring search on pre-lowered strings
// ============================================================================

[[nodiscard]] static bool Contains(const std::string& haystack,
                                   const char* needle) noexcept {
    return haystack.find(needle) != std::string::npos;
}

[[nodiscard]] static bool ContainsW(const std::wstring& haystack,
                                    const wchar_t* needle) noexcept {
    return haystack.find(needle) != std::wstring::npos;
}

// ============================================================================
// Command-line pattern table
// ============================================================================
// Each entry describes one ransomware technique detectable via command line.
// All patterns are lowercase — input must be lowered before comparison.

struct CmdLinePattern {
    const char*     primary;        // Required substring
    const char*     secondary;      // Optional additional substring (both must match)
    VssDeleteMethod method;
};

static constexpr CmdLinePattern kPatterns[] = {
    // vssadmin delete shadows (most common ransomware technique)
    { "vssadmin",   "delete",          VssDeleteMethod::VssAdmin },
    // vssadmin resize shadowstorage (shrink to zero to destroy copies)
    { "vssadmin",   "resize",          VssDeleteMethod::VssAdminResize },
    // wmic shadowcopy delete (WMI-based deletion)
    { "wmic",       "shadowcopy",      VssDeleteMethod::WmicShadowCopy },
    // bcdedit /set {default} recoveryenabled No
    { "bcdedit",    "recoveryenabled", VssDeleteMethod::BcdeditRecovery },
    // bcdedit /set {default} bootstatuspolicy ignoreallfailures
    { "bcdedit",    "bootstatuspolicy", VssDeleteMethod::BcdeditBootPolicy },
    // wbadmin delete catalog
    { "wbadmin",    "delete",          VssDeleteMethod::WbadminCatalog },
    // cipher /w: (wipe free space to destroy recoverable data)
    { "cipher",     "/w:",             VssDeleteMethod::CipherWipe },
    // diskshadow /s (script-based shadow copy manipulation)
    { "diskshadow", "/s",              VssDeleteMethod::DiskShadow },
};

static constexpr uint32_t kPatternCount =
    static_cast<uint32_t>(sizeof(kPatterns) / sizeof(kPatterns[0]));

// PowerShell patterns require special handling because the executable name
// can be "powershell", "powershell.exe", "pwsh", or "pwsh.exe".
struct PowerShellPattern {
    const char* keyword1;
    const char* keyword2;
};

static constexpr PowerShellPattern kPowerShellPatterns[] = {
    { "shadowcopy", "delete" },
    { "win32_shadowcopy", nullptr },
};

static constexpr uint32_t kPSPatternCount =
    static_cast<uint32_t>(sizeof(kPowerShellPatterns) / sizeof(kPowerShellPatterns[0]));

// ============================================================================
// VSS-related COM CLSIDs (binary, little-endian Data1/2/3, big-endian Data4)
// ============================================================================

struct VssCLSID {
    uint8_t     bytes[kGuidSize];
    const char* description;
};

// {E579AB5F-1CC4-44b4-BED9-DE0991FF0623} — IVssBackupComponents
// Data1 = 0xE579AB5F (LE: 5F AB 79 E5)
// Data2 = 0x1CC4     (LE: C4 1C)
// Data3 = 0x44b4     (LE: b4 44)
// Data4 = BE D9 DE 09 91 FF 06 23
static constexpr VssCLSID kVssCLSIDs[] = {
    { { 0x5F, 0xAB, 0x79, 0xE5, 0xC4, 0x1C, 0xB4, 0x44,
        0xBE, 0xD9, 0xDE, 0x09, 0x91, 0xFF, 0x06, 0x23 },
      "IVssBackupComponents" },

    // {507C37B4-CF5B-4e95-B0AF-14EB9767467E} — IVssAsync
    // Data1 = 0x507C37B4 (LE: B4 37 7C 50)
    // Data2 = 0xCF5B     (LE: 5B CF)
    // Data3 = 0x4e95     (LE: 95 4E)
    // Data4 = B0 AF 14 EB 97 67 46 7E
    { { 0xB4, 0x37, 0x7C, 0x50, 0x5B, 0xCF, 0x95, 0x4E,
        0xB0, 0xAF, 0x14, 0xEB, 0x97, 0x67, 0x46, 0x7E },
      "IVssAsync" },
};

static constexpr uint32_t kVssCLSIDCount =
    static_cast<uint32_t>(sizeof(kVssCLSIDs) / sizeof(kVssCLSIDs[0]));

// ============================================================================
// VssDetector — Meyers' singleton implementation
// ============================================================================

VssDetector& VssDetector::Instance() noexcept {
    static VssDetector instance;
    return instance;
}

// ============================================================================
// RecordEvent — internal helper, must be called with m_mutex held
// ============================================================================

static void RecordEvent(std::vector<VssDeleteEvent>& events,
                        uint32_t& methodMask,
                        VssDeleteMethod method,
                        std::string cmdLine,
                        std::string details,
                        uint64_t instrNum) noexcept {
    if (events.size() >= kMaxEvents) {
        return;
    }

    methodMask |= (1u << static_cast<uint8_t>(method));

    VssDeleteEvent evt;
    evt.method         = method;
    evt.commandLine    = std::move(cmdLine);
    evt.details        = std::move(details);
    evt.instructionNum = instrNum;
    events.push_back(std::move(evt));
}

// ============================================================================
// AnalyzeCommandLine — narrow string variant
// ============================================================================

bool VssDetector::AnalyzeCommandLine(std::string_view cmdLine,
                                     uint64_t instrNum) noexcept {
    if (cmdLine.empty()) {
        return false;
    }

    const uint32_t safeLen = static_cast<uint32_t>(
        std::min(cmdLine.size(), static_cast<size_t>(kMaxCommandLineLen)));
    std::string lower(cmdLine.substr(0, safeLen));
    ToLowerInPlace(lower);

    bool detected = false;
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check standard patterns
    for (uint32_t i = 0; i < kPatternCount; ++i) {
        const auto& pat = kPatterns[i];
        if (!Contains(lower, pat.primary)) {
            continue;
        }
        if (pat.secondary != nullptr && !Contains(lower, pat.secondary)) {
            continue;
        }

        RecordEvent(m_events, m_uniqueMethodMask, pat.method,
                    std::string(cmdLine.substr(0, safeLen)),
                    std::string("Matched command-line pattern: ") + pat.primary,
                    instrNum);
        detected = true;
    }

    // Check PowerShell patterns: executable must be powershell or pwsh
    const bool isPowerShell = Contains(lower, "powershell") ||
                              Contains(lower, "pwsh");
    if (isPowerShell) {
        for (uint32_t i = 0; i < kPSPatternCount; ++i) {
            const auto& ps = kPowerShellPatterns[i];
            if (!Contains(lower, ps.keyword1)) {
                continue;
            }
            if (ps.keyword2 != nullptr && !Contains(lower, ps.keyword2)) {
                continue;
            }

            RecordEvent(m_events, m_uniqueMethodMask,
                        VssDeleteMethod::PowerShellWmi,
                        std::string(cmdLine.substr(0, safeLen)),
                        std::string("PowerShell VSS deletion via: ") + ps.keyword1,
                        instrNum);
            detected = true;
        }
    }

    return detected;
}

// ============================================================================
// AnalyzeCommandLineW — wide string variant (converts to narrow, then analyzes)
// ============================================================================

bool VssDetector::AnalyzeCommandLineW(std::wstring_view cmdLine,
                                      uint64_t instrNum) noexcept {
    if (cmdLine.empty()) {
        return false;
    }

    const std::string narrow = NarrowFromWide(cmdLine, kMaxCommandLineLen);
    return AnalyzeCommandLine(narrow, instrNum);
}

// ============================================================================
// AnalyzeComCreation — match CLSID bytes against VSS COM interfaces
// ============================================================================

bool VssDetector::AnalyzeComCreation(uint64_t clsidAddr,
                                     const uint8_t* clsidBytes,
                                     uint64_t instrNum) noexcept {
    if (clsidBytes == nullptr) {
        return false;
    }

    for (uint32_t i = 0; i < kVssCLSIDCount; ++i) {
        if (std::memcmp(clsidBytes, kVssCLSIDs[i].bytes, kGuidSize) != 0) {
            continue;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        RecordEvent(m_events, m_uniqueMethodMask,
                    VssDeleteMethod::DirectCom,
                    std::string("CoCreateInstance at guest addr 0x") +
                        [](uint64_t addr) {
                            static constexpr char hex[] = "0123456789abcdef";
                            std::string s(16, '0');
                            for (int j = 15; j >= 0; --j) {
                                s[static_cast<size_t>(j)] = hex[addr & 0xF];
                                addr >>= 4;
                            }
                            return s;
                        }(clsidAddr),
                    std::string("VSS COM interface: ") + kVssCLSIDs[i].description,
                    instrNum);
        return true;
    }

    return false;
}

// ============================================================================
// AnalyzeRegistryWrite — detect DisableSR and DisableSystemBackup
// ============================================================================

bool VssDetector::AnalyzeRegistryWrite(std::wstring_view keyPath,
                                       std::wstring_view valueName,
                                       uint32_t data,
                                       uint64_t instrNum) noexcept {
    if (data == 0) {
        return false;
    }

    std::wstring lowerPath(keyPath);
    std::wstring lowerValue(valueName);
    ToLowerInPlaceW(lowerPath);
    ToLowerInPlaceW(lowerValue);

    bool match = false;
    std::string detail;

    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR = 1
    if (ContainsW(lowerPath, L"systemrestore") &&
        ContainsW(lowerValue, L"disablesr")) {
        match  = true;
        detail = "Registry: DisableSR set to non-zero (System Restore disabled)";
    }

    // HKLM\SOFTWARE\Policies\Microsoft\Windows\Backup\Client\DisableSystemBackup = 1
    if (ContainsW(lowerPath, L"backup") &&
        ContainsW(lowerValue, L"disablesystembackup")) {
        match  = true;
        detail = "Registry: DisableSystemBackup set to non-zero (Windows Backup disabled)";
    }

    if (!match) {
        return false;
    }

    std::string narrowPath  = NarrowFromWide(keyPath, 1024);
    std::string narrowValue = NarrowFromWide(valueName, 256);

    std::lock_guard<std::mutex> lock(m_mutex);
    RecordEvent(m_events, m_uniqueMethodMask,
                VssDeleteMethod::RegistryDisable,
                narrowPath + "\\" + narrowValue + " = " + std::to_string(data),
                std::move(detail),
                instrNum);
    return true;
}

// ============================================================================
// Forensic extraction
// ============================================================================

std::vector<VssDeleteEvent> VssDetector::GetEvents() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events;
}

uint32_t VssDetector::GetDeleteAttemptCount() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(m_events.size());
}

bool VssDetector::HasRansomwareBehavior() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_events.empty();
}

float VssDetector::GetRansomwareScore() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_uniqueMethodMask == 0) {
        return 0.0f;
    }

    // Count distinct methods via popcount on the bitmask
    const uint32_t uniqueCount = static_cast<uint32_t>(
        std::popcount(m_uniqueMethodMask));

    const float raw = static_cast<float>(uniqueCount) * kScorePerMethod;
    return (raw > kMaxScore) ? kMaxScore : raw;
}

void VssDetector::Reset() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
    m_uniqueMethodMask = 0;
}

// ============================================================================
// IVssBackupComponents CLSID bytes for direct handler recording
// ============================================================================
// {E579AB5F-1CC4-44b4-BED9-DE0991FF0623} — same as kVssCLSIDs[0]

static constexpr uint8_t kIVssBackupComponentsCLSID[kGuidSize] = {
    0x5F, 0xAB, 0x79, 0xE5, 0xC4, 0x1C, 0xB4, 0x44,
    0xBE, 0xD9, 0xDE, 0x09, 0x91, 0xFF, 0x06, 0x23
};

// ============================================================================
// HandleCreateVssBackupComponents — vssapi.dll direct entry point
// ============================================================================
// HRESULT CreateVssBackupComponentsInternal(IVssBackupComponents** ppBackup)
//
// Rare: some ransomware families load vssapi.dll directly and call this
// function to obtain IVssBackupComponents for DeleteSnapshots().
// We return E_NOTIMPL and flag the attempt.

bool HandleCreateVssBackupComponents(APIContext& ctx) {
    const auto ppBackup = ctx.GetArgPtr(0);

    // Write NULL to output pointer — no COM object will be created
    if (ppBackup != 0) {
        if (ctx.Is64Bit()) {
            ctx.Memory().WriteU64(ppBackup, 0);
        } else {
            ctx.Memory().WriteU32(ppBackup, 0);
        }
    }

    // T1490 Inhibit System Recovery — dropping the T1490 MITRE flag
    // equivalents we have: SuspiciousAPI always, DefenseEvasion because
    // shadow-copy destruction is the canonical forensic-erasure primitive.
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

    // Record this as a direct COM VSS access via the known CLSID.
    // Pass the real IVssBackupComponents CLSID bytes so AnalyzeComCreation
    // matches it against the VSS CLSID table and records the event properly.
    VssDetector::Instance().AnalyzeComCreation(
        0, kIVssBackupComponentsCLSID, ctx.CPU().instructionCount);

    ctx.SetReturn32(static_cast<uint32_t>(kE_NOTIMPL));
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterVssAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "vssapi.dll", "CreateVssBackupComponentsInternal",
          HandleCreateVssBackupComponents, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Vss

#pragma warning(pop)

