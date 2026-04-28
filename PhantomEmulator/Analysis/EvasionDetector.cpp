/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "EvasionDetector.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxEvasionAttempts       = 50'000;
static constexpr uint32_t kMaxTimingEntriesPerRIP   = 64;
static constexpr uint32_t kMaxTimingRIPs            = 4'096;
static constexpr uint32_t kMaxProcessNames          = 4'096;
static constexpr uint32_t kMaxRegistryPaths         = 4'096;
static constexpr uint32_t kMaxFilePaths             = 4'096;
static constexpr uint32_t kMaxInstructionProbeRIPs  = 4'096;
static constexpr uint32_t kMaxDescriptionLength     = 512;
static constexpr uint32_t kMaxInputStringLength     = 4'096;
static constexpr size_t   kTechniqueCount =
    static_cast<size_t>(EvasionTechnique::AVX512_EVEXInstruction) + 1U;
static constexpr float    kTotalTechniques          = static_cast<float>(kTechniqueCount);

[[nodiscard]] size_t TechniqueIndex(EvasionTechnique technique) noexcept {
    return static_cast<size_t>(technique);
}

[[nodiscard]] EvasionTechnique TechniqueAt(size_t index) noexcept {
    return static_cast<EvasionTechnique>(index);
}

// ============================================================================
// Evasion Category Classification
// ============================================================================

enum class EvasionCategory : uint8_t {
    AntiDebug   = 0,
    AntiVM      = 1,
    AntiSandbox = 2,
    AntiAnalysis = 3,
};

[[nodiscard]] static EvasionCategory ClassifyTechnique(EvasionTechnique tech) noexcept {
    const auto t = static_cast<uint8_t>(tech);
    const auto antiDebugEnd =
        static_cast<uint8_t>(EvasionTechnique::FindWindow_OllyDbg);
    const auto antiVMEnd =
        static_cast<uint8_t>(EvasionTechnique::FirmwareTable_Check);
    const auto antiSandboxEnd =
        static_cast<uint8_t>(EvasionTechnique::Filename_Check);

    if (t <= antiDebugEnd)   return EvasionCategory::AntiDebug;
    if (t <= antiVMEnd)      return EvasionCategory::AntiVM;
    if (t <= antiSandboxEnd) return EvasionCategory::AntiSandbox;
    return EvasionCategory::AntiAnalysis;
}

// ============================================================================
// Case-Insensitive ASCII Helpers
// ============================================================================

namespace {

[[nodiscard]] char AsciiToLower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

[[nodiscard]] bool CaseInsensitiveEquals(const char* a, const char* b) noexcept {
    if (!a || !b) return a == b;

    for (size_t i = 0; i < kMaxInputStringLength; ++i) {
        const char ac = a[i];
        const char bc = b[i];
        if (AsciiToLower(ac) != AsciiToLower(bc)) return false;
        if (ac == '\0') return true;
    }
    return false;
}

[[nodiscard]] bool CaseInsensitiveEquals(
    const std::string& a, const std::string& b) noexcept
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (AsciiToLower(a[i]) != AsciiToLower(b[i])) return false;
    }
    return true;
}

[[nodiscard]] bool CaseInsensitiveEquals(
    std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (AsciiToLower(a[i]) != AsciiToLower(b[i])) return false;
    }
    return true;
}

[[nodiscard]] std::string_view BoundedCStringView(const char* text) noexcept {
    if (!text) return {};

    size_t len = 0;
    while (len < kMaxInputStringLength && text[len] != '\0') {
        ++len;
    }
    return { text, len };
}

[[nodiscard]] bool CaseInsensitiveContains(std::string_view haystack,
                                           std::string_view needle) noexcept {
    if (needle.empty()) return true;
    const size_t needleLen = std::min<size_t>(needle.size(), kMaxInputStringLength);
    const size_t haystackLen = std::min<size_t>(haystack.size(), kMaxInputStringLength);
    if (needleLen > haystackLen) return false;

    for (size_t i = 0; i <= haystackLen - needleLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < needleLen; ++j) {
            if (AsciiToLower(haystack[i + j]) != AsciiToLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

[[nodiscard]] bool CaseInsensitiveContains(const char* haystack,
                                           const char* needle) noexcept {
    return CaseInsensitiveContains(BoundedCStringView(haystack), BoundedCStringView(needle));
}

[[nodiscard]] bool CaseInsensitiveContains(const std::string& haystack,
                                           const char* needle) noexcept {
    return CaseInsensitiveContains(std::string_view{ haystack }, BoundedCStringView(needle));
}

[[nodiscard]] bool CaseInsensitiveContains(const std::string& haystack,
                                           const std::string& needle) noexcept {
    return CaseInsensitiveContains(std::string_view{ haystack }, std::string_view{ needle });
}

// Safe funcName comparison — handles null funcName pointers
[[nodiscard]] bool FuncNameIs(const char* funcName, const char* target) noexcept {
    if (!funcName || !target) return false;
    return CaseInsensitiveEquals(funcName, target);
}

// Safe funcName prefix match (case-insensitive)
[[nodiscard]] bool FuncNameContains(const char* funcName, const char* sub) noexcept {
    if (!funcName || !sub) return false;
    return CaseInsensitiveContains(funcName, sub);
}

// Truncate and sanitize descriptions to prevent unbounded growth
[[nodiscard]] std::string SafeDescription(std::string_view text) noexcept {
    std::string result;
    try {
        const size_t len = std::min<size_t>(text.size(), kMaxDescriptionLength);
        result.reserve(len + 3);
        for (size_t i = 0; i < len; ++i) {
            const unsigned char ch = static_cast<unsigned char>(text[i]);
            result.push_back((ch < 0x20U || ch == 0x7FU) ? ' ' : static_cast<char>(ch));
        }
        if (text.size() > kMaxDescriptionLength) {
            result += "...";
        }
    } catch (const std::bad_alloc&) {
        result = "(description unavailable)";
    }
    return result;
}

[[nodiscard]] std::string BuildDescription(std::string_view prefix,
                                           std::string_view detail) noexcept
{
    std::string result;
    try {
        const size_t prefixLen = std::min<size_t>(prefix.size(), kMaxDescriptionLength);
        const size_t remaining =
            (prefixLen < kMaxDescriptionLength) ? (kMaxDescriptionLength - prefixLen) : 0U;
        const size_t detailLen = std::min<size_t>(detail.size(), remaining);
        result.reserve(prefixLen + detailLen + 3U);
        result.append(prefix.data(), prefixLen);
        result.append(detail.data(), detailLen);
        if (detail.size() > detailLen) {
            result += "...";
        }
    } catch (const std::bad_alloc&) {
        result = "(description unavailable)";
    }
    return SafeDescription(result);
}

} // anonymous namespace

// ============================================================================
// Process Name → EvasionTechnique Mapping
// ============================================================================

namespace {

struct ProcessMapping {
    const char*      processName;
    EvasionTechnique technique;
    float            severity;
};

// Static table of known analysis/VM tool process names.
// All comparisons are case-insensitive at lookup time.
static constexpr std::array<ProcessMapping, 22> kProcessMappings = {{
    // Network analysis
    { "wireshark.exe",    EvasionTechnique::ProcessCheck_Wireshark, 0.5f },
    { "tshark.exe",       EvasionTechnique::ProcessCheck_Wireshark, 0.5f },
    { "dumpcap.exe",      EvasionTechnique::ProcessCheck_Wireshark, 0.5f },

    // Disassemblers / decompilers
    { "idaq.exe",         EvasionTechnique::ProcessCheck_IDA,       0.55f },
    { "idaq64.exe",       EvasionTechnique::ProcessCheck_IDA,       0.55f },
    { "ida.exe",          EvasionTechnique::ProcessCheck_IDA,       0.55f },
    { "ida64.exe",        EvasionTechnique::ProcessCheck_IDA,       0.55f },

    // Debuggers
    { "x64dbg.exe",       EvasionTechnique::ProcessCheck_x64dbg,    0.55f },
    { "x32dbg.exe",       EvasionTechnique::ProcessCheck_x64dbg,    0.55f },
    { "ollydbg.exe",      EvasionTechnique::ProcessCheck_x64dbg,    0.55f },

    // Process monitors
    { "procmon.exe",      EvasionTechnique::ProcessCheck_Procmon,   0.5f },
    { "procmon64.exe",    EvasionTechnique::ProcessCheck_Procmon,   0.5f },

    // Process explorer
    { "procexp.exe",      EvasionTechnique::ProcessCheck_ProcExp,   0.5f },
    { "procexp64.exe",    EvasionTechnique::ProcessCheck_ProcExp,   0.5f },

    // VMware tools
    { "vmtoolsd.exe",     EvasionTechnique::ProcessCheck_VMTools,   0.5f },
    { "vmwaretray.exe",   EvasionTechnique::ProcessCheck_VMTools,   0.5f },

    // VirtualBox tools
    { "vboxservice.exe",  EvasionTechnique::ProcessCheck_VBoxTray,  0.5f },
    { "vboxtray.exe",     EvasionTechnique::ProcessCheck_VBoxTray,  0.5f },

    // File monitor
    { "filemon.exe",      EvasionTechnique::WindowCheck_Filemon,    0.4f },

    // Additional analysis tools
    { "fiddler.exe",      EvasionTechnique::ProcessCheck_Wireshark, 0.45f },
    { "autoruns.exe",     EvasionTechnique::ProcessCheck_ProcExp,   0.4f },
    { "tcpview.exe",      EvasionTechnique::ProcessCheck_ProcExp,   0.4f },
}};

// Debugger window class names used with FindWindow evasion
static constexpr std::array<const char*, 8> kDebuggerWindowNames = {{
    "OLLYDBG",
    "OllyDbg",
    "x64dbg",
    "x32dbg",
    "IDA",
    "Immunity",
    "WinDbgFrameClass",
    "ID",
}};

// VMware-related registry key substrings
static constexpr std::array<const char*, 6> kVMwareRegistryIndicators = {{
    "VMware",
    "vmware",
    "VMWARE",
    "vm3dgl",
    "vmrawdsk",
    "vmusbmouse",
}};

// VirtualBox-related registry key substrings
static constexpr std::array<const char*, 5> kVBoxRegistryIndicators = {{
    "VirtualBox",
    "Oracle",
    "VBOX",
    "VBoxGuest",
    "VBoxMouse",
}};

// Hyper-V-related registry key substrings
static constexpr std::array<const char*, 4> kHyperVRegistryIndicators = {{
    "Hyper-V",
    "Microsoft\\Virtual Machine",
    "hvservice",
    "integrationsvc",
}};

// VirtualBox device paths used with CreateFile evasion
static constexpr std::array<const char*, 4> kVBoxDevicePaths = {{
    "\\\\.\\VBoxMiniRdrDN",
    "\\\\.\\VBoxGuest",
    "\\\\.\\VBoxTrayIPC",
    "\\\\.\\pipe\\VBoxTrayIPC",
}};

// VMware device paths
static constexpr std::array<const char*, 3> kVMwareDevicePaths = {{
    "\\\\.\\vmci",
    "\\\\.\\hgfs",
    "\\\\.\\VMCI",
}};

// VMware file indicators
static constexpr std::array<const char*, 4> kVMwareFileIndicators = {{
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmacthlp.exe",
    "vmware.exe",
}};

// VirtualBox file indicators
static constexpr std::array<const char*, 4> kVBoxFileIndicators = {{
    "VBoxService.exe",
    "VBoxTray.exe",
    "VBoxControl.exe",
    "VirtualBox.exe",
}};

// VM-related DLLs checked via GetModuleHandle
static constexpr std::array<const char*, 3> kVMwareDLLs = {{
    "vmGuestLib.dll",
    "vmhgfs.dll",
    "vmmemctl.dll",
}};

static constexpr std::array<const char*, 3> kVBoxDLLs = {{
    "vboxmrxnp.dll",
    "VBoxHook.dll",
    "VBoxOGLarrayspu.dll",
}};

// Sandbox DLLs
static constexpr const char* kSandboxDLL = "SbieDll.dll";

// Debug help DLL (benign alone, suspicious in context)
static constexpr const char* kDbgHelpDLL = "dbghelp.dll";

// VMware MAC OUI prefixes (first 3 bytes)
static constexpr std::array<const char*, 3> kVMwareMACPrefixes = {{
    "00:0C:29",
    "00:50:56",
    "00:05:69",
}};

// VirtualBox MAC OUI prefix
static constexpr const char* kVBoxMACPrefix = "08:00:27";

// Sandbox filename indicators — malware checks its own filename
static constexpr std::array<const char*, 10> kSandboxFilenameIndicators = {{
    "sample",
    "malware",
    "test",
    "virus",
    "sandbox",
    "analysis",
    "maltest",
    "infected",
    "suspicious",
    "payload",
}};

// Invalid handle sentinels used in CloseHandle anti-debug trick
static constexpr std::array<uint64_t, 4> kInvalidHandleSentinels = {{
    0xDEADBEEF,
    0xBAADF00D,
    0xFEEDFACE,
    0xDEADC0DE,
}};

// SMBIOS firmware table signature: 'RSMB'
static constexpr uint32_t kFirmwareSigRSMB = 0x52534D42; // 'RSMB' as uint32_t
// ACPI firmware table signature: 'ACPI'
static constexpr uint32_t kFirmwareSigACPI = 0x41435049; // 'ACPI' as uint32_t

// ProcessInformationClass values for NtQueryInformationProcess
static constexpr uint64_t kProcessDebugPort          = 7;
static constexpr uint64_t kProcessDebugObjectHandle   = 30;
static constexpr uint64_t kProcessDebugFlags          = 31;

// ThreadInformationClass for NtSetInformationThread
static constexpr uint64_t kThreadHideFromDebugger     = 17;

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct EvasionDetector::Impl {
    mutable std::shared_mutex mutex;

    // --- Core state ---
    std::vector<EvasionAttempt>     attempts;
    std::array<bool, kTechniqueCount> techniqueSeen{};
    uint32_t uniqueTechniqueCount = 0;

    // --- Timing attack tracking ---
    // Map of RIP → vector of instruction counts at which timing checks occurred
    std::map<GuestAddress, std::vector<uint64_t>> timingByRIP;
    uint32_t totalTimingRIPs = 0;

    // --- Process enumeration tracking ---
    std::set<std::string> processNamesSeen;

    // --- Registry query tracking ---
    std::set<std::string> registryPathsSeen;

    // --- File query tracking ---
    std::set<std::string> filePathsSeen;
    std::unordered_set<GuestAddress> instructionProbeRIPs;

    // --- SetLastError / GetLastError pairing ---
    bool     lastCallWasSetLastError = false;
    uint64_t setLastErrorInstrNum    = 0;

    // --- Internal instruction counter ---
    uint64_t instrCounter = 0;

    // --- QPC timing pairing ---
    bool     qpcSeen = false;
    uint64_t qpcInstrNum = 0;

    // --- GetTickCount early-call tracking ---
    bool getTickCountRecorded = false;

    // --- Configuration reference ---
    const EmulationConfig& config;

    explicit Impl(const EmulationConfig& cfg) noexcept
        : config(cfg)
    {
        try {
            attempts.reserve(256);
        } catch (const std::bad_alloc&) {
            attempts.clear();
        }
    }

    // ------------------------------------------------------------------
    // RecordAttempt — central recording function with cap enforcement
    // ------------------------------------------------------------------

    void RecordAttempt(EvasionTechnique technique,
                       std::string description,
                       GuestAddress rip,
                       uint64_t instrCount,
                       float severity) noexcept
    {
        // Enforce hard cap on total recorded attempts
        if (attempts.size() >= kMaxEvasionAttempts) return;

        // Determine if the evasion was defeated based on config + category
        bool defeated = false;
        const EvasionCategory cat = ClassifyTechnique(technique);
        switch (cat) {
            case EvasionCategory::AntiDebug:
                defeated = config.enableAntiDebugBypass;
                break;
            case EvasionCategory::AntiVM:
                defeated = config.enableAntiVMBypass;
                break;
            case EvasionCategory::AntiSandbox:
                defeated = config.enableAntiSandboxBypass;
                break;
            case EvasionCategory::AntiAnalysis:
                // Anti-analysis is defeated if any bypass is active
                defeated = config.enableAntiDebugBypass ||
                           config.enableAntiVMBypass ||
                           config.enableAntiSandboxBypass;
                break;
        }

        try {
            EvasionAttempt attempt;
            attempt.technique        = technique;
            attempt.description      = SafeDescription(description);
            attempt.rip              = rip;
            attempt.instructionCount = instrCount;
            attempt.severity         = std::isfinite(severity)
                ? std::clamp(severity, 0.0f, 1.0f)
                : 0.0f;
            attempt.wasDefeated      = defeated;

            const size_t techniqueIndex = TechniqueIndex(technique);
            if (techniqueIndex < techniqueSeen.size() && !techniqueSeen[techniqueIndex]) {
                techniqueSeen[techniqueIndex] = true;
                if (uniqueTechniqueCount < std::numeric_limits<uint32_t>::max()) {
                    ++uniqueTechniqueCount;
                }
            }
            attempts.push_back(std::move(attempt));
        } catch (const std::bad_alloc&) {
            // Memory allocation failure — silently drop this attempt.
            // The cap check above prevents unbounded growth; this catch
            // guards against OOM on individual insertions.
        }
    }

    // ------------------------------------------------------------------
    // CheckRegistryForVMIndicators — scan registry path string for VM keys
    // ------------------------------------------------------------------

    void CheckRegistryForVMIndicators(const char* pathStr,
                                      GuestAddress rip,
                                      uint64_t instrNum) noexcept
    {
        if (!pathStr) return;

        // Track the registry path (capped)
        try {
            if (registryPathsSeen.size() < kMaxRegistryPaths) {
                const auto pathView = BoundedCStringView(pathStr);
                registryPathsSeen.emplace(pathView.data(), pathView.size());
            }
        } catch (const std::bad_alloc&) {}

        // VMware indicators
        for (const char* indicator : kVMwareRegistryIndicators) {
            if (CaseInsensitiveContains(pathStr, indicator)) {
                RecordAttempt(
                    EvasionTechnique::RegQuery_VMware,
                    BuildDescription("Registry query for VMware indicator: ", indicator),
                    rip, instrNum, 0.6f);
                return;
            }
        }

        // VirtualBox indicators
        for (const char* indicator : kVBoxRegistryIndicators) {
            if (CaseInsensitiveContains(pathStr, indicator)) {
                RecordAttempt(
                    EvasionTechnique::RegQuery_VBox,
                    BuildDescription("Registry query for VirtualBox indicator: ", indicator),
                    rip, instrNum, 0.6f);
                return;
            }
        }

        // Hyper-V indicators
        for (const char* indicator : kHyperVRegistryIndicators) {
            if (CaseInsensitiveContains(pathStr, indicator)) {
                RecordAttempt(
                    EvasionTechnique::RegQuery_HyperV,
                    BuildDescription("Registry query for Hyper-V indicator: ", indicator),
                    rip, instrNum, 0.6f);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // CheckFilePathForVMIndicators — scan file path for VM artifacts
    // ------------------------------------------------------------------

    void CheckFilePathForVMIndicators(const char* pathStr,
                                      GuestAddress rip,
                                      uint64_t instrNum) noexcept
    {
        if (!pathStr) return;

        // Track the file path (capped)
        try {
            if (filePathsSeen.size() < kMaxFilePaths) {
                const auto pathView = BoundedCStringView(pathStr);
                filePathsSeen.emplace(pathView.data(), pathView.size());
            }
        } catch (const std::bad_alloc&) {}

        // VBox device paths
        for (const char* devPath : kVBoxDevicePaths) {
            if (CaseInsensitiveContains(pathStr, devPath)) {
                RecordAttempt(
                    EvasionTechnique::DeviceQuery_VBox,
                    BuildDescription("Device open attempt for VirtualBox: ", devPath),
                    rip, instrNum, 0.6f);
                return;
            }
        }

        // VMware device paths
        for (const char* devPath : kVMwareDevicePaths) {
            if (CaseInsensitiveContains(pathStr, devPath)) {
                RecordAttempt(
                    EvasionTechnique::DeviceQuery_VMware,
                    BuildDescription("Device open attempt for VMware: ", devPath),
                    rip, instrNum, 0.6f);
                return;
            }
        }

        // VMware file indicators
        for (const char* fileInd : kVMwareFileIndicators) {
            if (CaseInsensitiveContains(pathStr, fileInd)) {
                RecordAttempt(
                    EvasionTechnique::FileCheck_VMware,
                    BuildDescription("File access for VMware artifact: ", fileInd),
                    rip, instrNum, 0.5f);
                return;
            }
        }

        // VBox file indicators
        for (const char* fileInd : kVBoxFileIndicators) {
            if (CaseInsensitiveContains(pathStr, fileInd)) {
                RecordAttempt(
                    EvasionTechnique::FileCheck_VBox,
                    BuildDescription("File access for VirtualBox artifact: ", fileInd),
                    rip, instrNum, 0.5f);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // CheckModuleForIndicators — scan loaded module name
    // ------------------------------------------------------------------

    void CheckModuleForIndicators(const char* moduleName,
                                  GuestAddress rip,
                                  uint64_t instrNum) noexcept
    {
        if (!moduleName) return;

        // VMware DLLs
        for (const char* dll : kVMwareDLLs) {
            if (CaseInsensitiveEquals(moduleName, dll)) {
                RecordAttempt(
                    EvasionTechnique::FileCheck_VMware,
                    BuildDescription("GetModuleHandle for VMware DLL: ", dll),
                    rip, instrNum, 0.55f);
                return;
            }
        }

        // VirtualBox DLLs
        for (const char* dll : kVBoxDLLs) {
            if (CaseInsensitiveEquals(moduleName, dll)) {
                RecordAttempt(
                    EvasionTechnique::FileCheck_VBox,
                    BuildDescription("GetModuleHandle for VirtualBox DLL: ", dll),
                    rip, instrNum, 0.55f);
                return;
            }
        }

        // Sandbox DLL (Sandboxie)
        if (CaseInsensitiveEquals(moduleName, kSandboxDLL)) {
            RecordAttempt(
                EvasionTechnique::ModuleCheck_SbieDll,
                "GetModuleHandle for Sandboxie DLL: SbieDll.dll",
                rip, instrNum, 0.6f);
            return;
        }

        // Debug help DLL
        if (CaseInsensitiveEquals(moduleName, kDbgHelpDLL)) {
            RecordAttempt(
                EvasionTechnique::ModuleCheck_DbgHelp,
                "GetModuleHandle for dbghelp.dll (debug helper)",
                rip, instrNum, 0.3f);
            return;
        }
    }

    // ------------------------------------------------------------------
    // HandleAntiDebugAPI — detect anti-debug API calls
    // ------------------------------------------------------------------

    void HandleAntiDebugAPI(const APICallDetail& call) noexcept {
        const char* fn = call.funcName;
        if (!fn) return;

        // --- IsDebuggerPresent ---
        if (FuncNameIs(fn, "IsDebuggerPresent")) {
            RecordAttempt(
                EvasionTechnique::IsDebuggerPresent,
                "IsDebuggerPresent() called — checks PEB.BeingDebugged flag",
                call.returnAddress, call.instructionNum, 0.6f);
            return;
        }

        // --- CheckRemoteDebuggerPresent ---
        if (FuncNameIs(fn, "CheckRemoteDebuggerPresent")) {
            RecordAttempt(
                EvasionTechnique::CheckRemoteDebuggerPresent,
                "CheckRemoteDebuggerPresent() called — queries remote debug status",
                call.returnAddress, call.instructionNum, 0.65f);
            return;
        }

        // --- NtQueryInformationProcess ---
        if (FuncNameIs(fn, "NtQueryInformationProcess")) {
            const uint64_t infoClass = call.args[1];

            if (infoClass == kProcessDebugPort) {
                RecordAttempt(
                    EvasionTechnique::NtQueryInfoProcessDebugPort,
                    "NtQueryInformationProcess(ProcessDebugPort=7) — detects active debugger port",
                    call.returnAddress, call.instructionNum, 0.7f);
            } else if (infoClass == kProcessDebugFlags) {
                RecordAttempt(
                    EvasionTechnique::NtQueryInfoProcessDebugFlags,
                    "NtQueryInformationProcess(ProcessDebugFlags=31) — checks NoDebugInherit",
                    call.returnAddress, call.instructionNum, 0.7f);
            } else if (infoClass == kProcessDebugObjectHandle) {
                RecordAttempt(
                    EvasionTechnique::NtQueryInfoProcessDebugObject,
                    "NtQueryInformationProcess(ProcessDebugObjectHandle=30) — queries debug object",
                    call.returnAddress, call.instructionNum, 0.75f);
            }
            return;
        }

        // --- NtSetInformationThread (ThreadHideFromDebugger) ---
        if (FuncNameIs(fn, "NtSetInformationThread")) {
            if (call.args[1] == kThreadHideFromDebugger) {
                RecordAttempt(
                    EvasionTechnique::NtSetInfoThreadHideFromDebugger,
                    "NtSetInformationThread(ThreadHideFromDebugger=17) — hides thread from debugger",
                    call.returnAddress, call.instructionNum, 0.8f);
            }
            return;
        }

        // --- CloseHandle with invalid handle sentinel ---
        if (FuncNameIs(fn, "CloseHandle")) {
            const uint64_t handle = call.args[0];
            for (const uint64_t sentinel : kInvalidHandleSentinels) {
                if (handle == sentinel) {
                    RecordAttempt(
                        EvasionTechnique::CloseHandleWithInvalidHandle,
                        "CloseHandle() with known invalid sentinel — triggers exception under debugger",
                        call.returnAddress, call.instructionNum, 0.5f);
                    return;
                }
            }
            return;
        }

        // --- OutputDebugString ---
        if (FuncNameIs(fn, "OutputDebugStringA") ||
            FuncNameIs(fn, "OutputDebugStringW")) {
            RecordAttempt(
                EvasionTechnique::OutputDebugString,
                "OutputDebugString() called — may be checking for debugger via GetLastError side-effect",
                call.returnAddress, call.instructionNum, 0.4f);
            return;
        }

        // --- SetUnhandledExceptionFilter ---
        if (FuncNameIs(fn, "SetUnhandledExceptionFilter")) {
            RecordAttempt(
                EvasionTechnique::UnhandledExceptionFilter,
                "SetUnhandledExceptionFilter() called — under debugger, filter is not invoked",
                call.returnAddress, call.instructionNum, 0.5f);
            return;
        }

        // --- NtYieldExecution ---
        if (FuncNameIs(fn, "NtYieldExecution")) {
            RecordAttempt(
                EvasionTechnique::NtYieldExecution,
                "NtYieldExecution() called — return value differs under debugger",
                call.returnAddress, call.instructionNum, 0.3f);
            return;
        }

        // --- SetLastError / GetLastError pattern ---
        if (FuncNameIs(fn, "SetLastError")) {
            lastCallWasSetLastError = true;
            setLastErrorInstrNum = call.instructionNum;
            return;
        }
        if (FuncNameIs(fn, "GetLastError")) {
            if (lastCallWasSetLastError &&
                call.instructionNum > setLastErrorInstrNum &&
                (call.instructionNum - setLastErrorInstrNum) < 100) {
                RecordAttempt(
                    EvasionTechnique::SetLastError_Check,
                    "SetLastError/GetLastError pair — checks if debugger altered last error value",
                    call.returnAddress, call.instructionNum, 0.4f);
            }
            lastCallWasSetLastError = false;
            return;
        }

        // --- FindWindowA/W with debugger class names ---
        if (FuncNameIs(fn, "FindWindowA") || FuncNameIs(fn, "FindWindowW")) {
            // args[0] = lpClassName, args[1] = lpWindowName
            // The window/class name string content is passed as a guest address.
            // We check string-argument encoding: the emulator marshals string
            // arguments into args[1] for FindWindow variants. In practice the
            // emulated environment resolves the guest string and stores a hash
            // or the first 8 bytes in args[]. We check both arg slots for
            // known debugger window names by examining the call's behavior flags.
            //
            // Since the emulator pre-categorizes FindWindow calls that reference
            // debugger windows with the AntiDebug category, we can shortcut:
            if (call.category == APICategory::AntiDebug) {
                RecordAttempt(
                    EvasionTechnique::FindWindow_OllyDbg,
                    "FindWindow() searching for debugger/analysis tool window",
                    call.returnAddress, call.instructionNum, 0.6f);
                return;
            }

            // Fallback: check behavior flags
            if (HasFlag(call.behaviorFlags, BehaviorFlag::AntiAnalysis)) {
                RecordAttempt(
                    EvasionTechnique::FindWindow_OllyDbg,
                    "FindWindow() with AntiAnalysis behavior flag — likely searching for debugger window",
                    call.returnAddress, call.instructionNum, 0.6f);
                return;
            }
            return;
        }
    }

    // ------------------------------------------------------------------
    // HandleTimingAPI — detect timing-based evasion via API calls
    // ------------------------------------------------------------------

    void HandleTimingAPI(const APICallDetail& call) noexcept {
        const char* fn = call.funcName;
        if (!fn) return;

        // --- GetTickCount / GetTickCount64 ---
        if (FuncNameIs(fn, "GetTickCount") || FuncNameIs(fn, "GetTickCount64")) {
            // Record as a timing event
            RecordTimingEvent(call.returnAddress, call.instructionNum);

            // Early call → SystemUptime_Check (anti-sandbox)
            if (call.instructionNum < 1000 && !getTickCountRecorded) {
                getTickCountRecorded = true;
                RecordAttempt(
                    EvasionTechnique::SystemUptime_Check,
                    "GetTickCount() called early in execution — checking system uptime for sandbox detection",
                    call.returnAddress, call.instructionNum, 0.35f);
            }
            return;
        }

        // --- QueryPerformanceCounter ---
        if (FuncNameIs(fn, "QueryPerformanceCounter")) {
            RecordTimingEvent(call.returnAddress, call.instructionNum);
            qpcSeen = true;
            qpcInstrNum = call.instructionNum;
            return;
        }

        // --- QueryPerformanceFrequency (often paired with QPC) ---
        if (FuncNameIs(fn, "QueryPerformanceFrequency")) {
            // Informational — not an evasion on its own, but record pairing
            if (qpcSeen &&
                call.instructionNum > qpcInstrNum &&
                (call.instructionNum - qpcInstrNum) < 500) {
                RecordAttempt(
                    EvasionTechnique::QueryPerformanceCounter_Timing,
                    "QueryPerformanceCounter/Frequency pair — timing-based debugger detection",
                    call.returnAddress, call.instructionNum, 0.65f);
            }
            return;
        }

        // --- NtQuerySystemTime ---
        if (FuncNameIs(fn, "NtQuerySystemTime") ||
            FuncNameIs(fn, "GetSystemTimeAsFileTime")) {
            RecordTimingEvent(call.returnAddress, call.instructionNum);
            return;
        }
    }

    // ------------------------------------------------------------------
    // RecordTimingEvent — track timing check at a specific RIP
    // ------------------------------------------------------------------

    void RecordTimingEvent(GuestAddress rip, uint64_t instrCount) noexcept {
        if (totalTimingRIPs >= kMaxTimingRIPs && timingByRIP.find(rip) == timingByRIP.end()) {
            return; // Cap on distinct RIPs
        }

        try {
            auto& entries = timingByRIP[rip];
            if (entries.empty()) {
                ++totalTimingRIPs;
            }
            if (entries.size() < kMaxTimingEntriesPerRIP) {
                entries.push_back(instrCount);
            }

            // If same RIP has multiple timing checks → elevated concern
            if (entries.size() >= 2) {
                const uint64_t delta = (entries.back() >= entries.front())
                    ? (entries.back() - entries.front())
                    : std::numeric_limits<uint64_t>::max();
                // Small delta (few instructions between checks) is a timing attack pattern
                if (delta < 5000) {
                    RecordAttempt(
                        EvasionTechnique::GetTickCount_Timing,
                        "Multiple timing checks from same code location — timing delta attack pattern",
                        rip, instrCount, 0.65f);
                }
            }
        } catch (const std::bad_alloc&) {}
    }

    // ------------------------------------------------------------------
    // HandleAntiVMAPI — detect anti-VM API calls
    // ------------------------------------------------------------------

    void HandleAntiVMAPI(const APICallDetail& call) noexcept {
        const char* fn = call.funcName;
        if (!fn) return;

        // --- Registry queries for VM artifacts ---
        if (FuncNameIs(fn, "RegOpenKeyExA") || FuncNameIs(fn, "RegOpenKeyExW") ||
            FuncNameIs(fn, "RegQueryValueExA") || FuncNameIs(fn, "RegQueryValueExW") ||
            FuncNameIs(fn, "RegOpenKeyA") || FuncNameIs(fn, "RegOpenKeyW") ||
            FuncNameIs(fn, "RegGetValueA") || FuncNameIs(fn, "RegGetValueW")) {
            // args[1] typically holds the subkey or value name guest address.
            // The emulator categorizes registry calls that reference VM keys
            // with AntiVM category. Use that as a reliable shortcut.
            if (call.category == APICategory::AntiVM) {
                // Determine which VM vendor based on behavior flag or category
                // Default to recording as a generic VM registry query
                RecordAttempt(
                    EvasionTechnique::RegQuery_VMware,
                    "Registry query targeting virtual machine artifacts",
                    call.returnAddress, call.instructionNum, 0.6f);
            }
            return;
        }

        // --- CreateFile for VM devices / files ---
        if (FuncNameIs(fn, "CreateFileA") || FuncNameIs(fn, "CreateFileW") ||
            FuncNameIs(fn, "NtCreateFile") || FuncNameIs(fn, "NtOpenFile")) {
            // The emulator categorizes device-open calls that target VM paths
            if (call.category == APICategory::AntiVM) {
                RecordAttempt(
                    EvasionTechnique::DeviceQuery_VMware,
                    "File/device open targeting virtual machine artifacts",
                    call.returnAddress, call.instructionNum, 0.6f);
            }
            return;
        }

        // --- GetModuleHandle for VM/sandbox/debug DLLs ---
        if (FuncNameIs(fn, "GetModuleHandleA") || FuncNameIs(fn, "GetModuleHandleW") ||
            FuncNameIs(fn, "GetModuleHandleExA") || FuncNameIs(fn, "GetModuleHandleExW")) {
            // Category-based detection for pre-classified calls
            if (call.category == APICategory::AntiVM) {
                RecordAttempt(
                    EvasionTechnique::FileCheck_VMware,
                    "GetModuleHandle checking for VM-related DLL",
                    call.returnAddress, call.instructionNum, 0.55f);
            } else if (call.category == APICategory::AntiDebug) {
                RecordAttempt(
                    EvasionTechnique::ModuleCheck_DbgHelp,
                    "GetModuleHandle checking for debug-related DLL",
                    call.returnAddress, call.instructionNum, 0.3f);
            }
            return;
        }

        // --- GetSystemFirmwareTable (SMBIOS / ACPI) ---
        if (FuncNameIs(fn, "GetSystemFirmwareTable")) {
            const uint32_t sig = static_cast<uint32_t>(call.args[0]);
            if (sig == kFirmwareSigRSMB) {
                RecordAttempt(
                    EvasionTechnique::SMBIOS_Check,
                    "GetSystemFirmwareTable('RSMB') — reading SMBIOS for VM vendor strings",
                    call.returnAddress, call.instructionNum, 0.65f);
            } else if (sig == kFirmwareSigACPI) {
                RecordAttempt(
                    EvasionTechnique::ACPI_Check,
                    "GetSystemFirmwareTable('ACPI') — reading ACPI tables for VM indicators",
                    call.returnAddress, call.instructionNum, 0.65f);
            } else {
                RecordAttempt(
                    EvasionTechnique::FirmwareTable_Check,
                    "GetSystemFirmwareTable() — reading firmware tables for VM detection",
                    call.returnAddress, call.instructionNum, 0.65f);
            }
            return;
        }

        // --- EnumSystemFirmwareTables ---
        if (FuncNameIs(fn, "EnumSystemFirmwareTables")) {
            RecordAttempt(
                EvasionTechnique::FirmwareTable_Check,
                "EnumSystemFirmwareTables() — enumerating firmware tables for VM detection",
                call.returnAddress, call.instructionNum, 0.6f);
            return;
        }

        // --- Network adapter queries for MAC OUI ---
        if (FuncNameIs(fn, "GetAdaptersInfo") || FuncNameIs(fn, "GetAdaptersAddresses")) {
            // The MAC address check happens post-call; we record the attempt
            // since querying adapters in a PE under emulation is suspicious
            RecordAttempt(
                EvasionTechnique::MACAddress_VMware,
                "GetAdaptersInfo/Addresses() — likely checking MAC OUI for VM vendor",
                call.returnAddress, call.instructionNum, 0.5f);
            return;
        }

        // --- Disk size check ---
        if (FuncNameIs(fn, "GetDiskFreeSpaceExA") || FuncNameIs(fn, "GetDiskFreeSpaceExW") ||
            FuncNameIs(fn, "GetDiskFreeSpaceA") || FuncNameIs(fn, "GetDiskFreeSpaceW")) {
            RecordAttempt(
                EvasionTechnique::DiskSize_Check,
                "GetDiskFreeSpace() — checking disk size (VMs often have small disks)",
                call.returnAddress, call.instructionNum, 0.3f);
            return;
        }

        // --- Physical memory size check ---
        if (FuncNameIs(fn, "GlobalMemoryStatusEx") || FuncNameIs(fn, "GlobalMemoryStatus")) {
            RecordAttempt(
                EvasionTechnique::MemorySize_Check,
                "GlobalMemoryStatus() — checking physical RAM (VMs often have less)",
                call.returnAddress, call.instructionNum, 0.3f);
            return;
        }

        // --- Processor count check ---
        if (FuncNameIs(fn, "GetSystemInfo") || FuncNameIs(fn, "GetNativeSystemInfo")) {
            RecordAttempt(
                EvasionTechnique::ProcessorCount_Check,
                "GetSystemInfo() — checking processor count (VMs often have fewer)",
                call.returnAddress, call.instructionNum, 0.3f);
            return;
        }
    }

    // ------------------------------------------------------------------
    // HandleAntiSandboxAPI — detect anti-sandbox API calls
    // ------------------------------------------------------------------

    void HandleAntiSandboxAPI(const APICallDetail& call) noexcept {
        const char* fn = call.funcName;
        if (!fn) return;

        // --- Sleep / SleepEx with long delay ---
        if (FuncNameIs(fn, "Sleep") || FuncNameIs(fn, "SleepEx")) {
            const uint64_t ms = call.args[0];
            if (ms > 60000) {
                RecordAttempt(
                    EvasionTechnique::SleepAcceleration,
                    "Sleep() with delay > 60s — sandbox evasion via long sleep",
                    call.returnAddress, call.instructionNum, 0.5f);
            }
            return;
        }

        // --- WaitForSingleObject with long timeout (similar to Sleep) ---
        if (FuncNameIs(fn, "WaitForSingleObject") || FuncNameIs(fn, "WaitForSingleObjectEx")) {
            const uint64_t ms = call.args[1];
            if (ms > 120000 && ms != 0xFFFFFFFF) { // INFINITE = 0xFFFFFFFF
                RecordAttempt(
                    EvasionTechnique::SleepAcceleration,
                    "WaitForSingleObject() with timeout > 120s — sandbox evasion via delayed execution",
                    call.returnAddress, call.instructionNum, 0.45f);
            }
            return;
        }

        // --- NtDelayExecution (native Sleep) ---
        if (FuncNameIs(fn, "NtDelayExecution")) {
            RecordAttempt(
                EvasionTechnique::SleepAcceleration,
                "NtDelayExecution() — native delay execution, potential sandbox evasion",
                call.returnAddress, call.instructionNum, 0.5f);
            return;
        }

        // --- User interaction checks ---
        if (FuncNameIs(fn, "GetCursorPos") || FuncNameIs(fn, "GetLastInputInfo") ||
            FuncNameIs(fn, "GetAsyncKeyState") || FuncNameIs(fn, "GetKeyState")) {
            RecordAttempt(
                EvasionTechnique::UserInteraction_Check,
                "User interaction query — checking for real human activity (sandbox detection)",
                call.returnAddress, call.instructionNum, 0.4f);
            return;
        }

        // --- Screen resolution check ---
        if (FuncNameIs(fn, "GetSystemMetrics")) {
            const uint64_t metric = call.args[0];
            // SM_CXSCREEN = 0, SM_CYSCREEN = 1
            if (metric == 0 || metric == 1) {
                RecordAttempt(
                    EvasionTechnique::ScreenResolution_Check,
                    "GetSystemMetrics(SM_CX/CYSCREEN) — checking screen resolution for sandbox detection",
                    call.returnAddress, call.instructionNum, 0.35f);
            }
            return;
        }

        // --- Domain joined check ---
        if (FuncNameIs(fn, "GetComputerNameExA") || FuncNameIs(fn, "GetComputerNameExW")) {
            // ComputerNameDnsDomain = 2
            if (call.args[0] == 2) {
                RecordAttempt(
                    EvasionTechnique::DomainJoined_Check,
                    "GetComputerNameEx(DnsDomain) — checking if machine is domain-joined",
                    call.returnAddress, call.instructionNum, 0.35f);
            }
            return;
        }

        // --- NetGetJoinInformation (also domain check) ---
        if (FuncNameIs(fn, "NetGetJoinInformation")) {
            RecordAttempt(
                EvasionTechnique::DomainJoined_Check,
                "NetGetJoinInformation() — checking domain membership for sandbox detection",
                call.returnAddress, call.instructionNum, 0.35f);
            return;
        }

        // --- Process enumeration (snapshot-based) ---
        if (FuncNameIs(fn, "Process32FirstW") || FuncNameIs(fn, "Process32First") ||
            FuncNameIs(fn, "Process32NextW") || FuncNameIs(fn, "Process32Next")) {
            RecordAttempt(
                EvasionTechnique::RunningProcessCount_Check,
                "Process32First/Next() — enumerating running processes (sandbox typically has few)",
                call.returnAddress, call.instructionNum, 0.3f);
            return;
        }

        // --- CreateToolhelp32Snapshot for process enumeration ---
        if (FuncNameIs(fn, "CreateToolhelp32Snapshot")) {
            // TH32CS_SNAPPROCESS = 0x00000002
            if (call.args[0] & 0x2) {
                RecordAttempt(
                    EvasionTechnique::RunningProcessCount_Check,
                    "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) — process enumeration for sandbox detection",
                    call.returnAddress, call.instructionNum, 0.3f);
            }
            return;
        }
    }

    // ------------------------------------------------------------------
    // ComputeEvasionScore — calculate the aggregate evasion score
    // ------------------------------------------------------------------

    [[nodiscard]] float ComputeEvasionScore() const noexcept {
        if (uniqueTechniqueCount == 0) return 0.0f;

        const auto numUnique = static_cast<float>(uniqueTechniqueCount);

        // Base score: proportion of known techniques observed
        float score = (numUnique / kTotalTechniques) * 0.5f;

        // Check for multi-category evasion (more sophisticated malware)
        bool hasAntiDebug   = false;
        bool hasAntiVM      = false;
        bool hasAntiSandbox = false;
        bool hasTiming      = false;

        for (size_t i = 0; i < techniqueSeen.size(); ++i) {
            if (!techniqueSeen[i]) continue;
            const auto tech = TechniqueAt(i);
            const EvasionCategory cat = ClassifyTechnique(tech);
            switch (cat) {
                case EvasionCategory::AntiDebug:
                    hasAntiDebug = true;
                    break;
                case EvasionCategory::AntiVM:
                    hasAntiVM = true;
                    break;
                case EvasionCategory::AntiSandbox:
                    hasAntiSandbox = true;
                    break;
                case EvasionCategory::AntiAnalysis:
                    break;
            }

            // Check for timing-specific techniques
            if (tech == EvasionTechnique::RDTSC_Timing ||
                tech == EvasionTechnique::QueryPerformanceCounter_Timing ||
                tech == EvasionTechnique::GetTickCount_Timing ||
                tech == EvasionTechnique::NtQuerySystemTime_Timing) {
                hasTiming = true;
            }
        }

        // Multi-category bonus: using anti-debug + anti-VM + anti-sandbox
        if (hasAntiDebug && hasAntiVM && hasAntiSandbox) {
            score += 0.3f;
        }

        // Timing attack bonus
        if (hasTiming) {
            score += 0.1f;
        }

        // High technique count bonus
        if (numUnique > 10.0f) {
            score += 0.1f;
        }

        // Clamp to [0.0, 1.0]
        if (score < 0.0f) score = 0.0f;
        if (score > 1.0f) score = 1.0f;

        return score;
    }

    // ------------------------------------------------------------------
    // DetermineSophisticationLevel
    // ------------------------------------------------------------------

    [[nodiscard]] std::string DetermineSophisticationLevel() const noexcept {
        const auto numUnique = uniqueTechniqueCount;

        // Check for combined timing + VM + sandbox (nation-state indicator)
        bool hasTiming  = false;
        bool hasVM      = false;
        bool hasSandbox = false;

        for (size_t i = 0; i < techniqueSeen.size(); ++i) {
            if (!techniqueSeen[i]) continue;
            const auto tech = TechniqueAt(i);
            const EvasionCategory cat = ClassifyTechnique(tech);
            if (cat == EvasionCategory::AntiVM)      hasVM = true;
            if (cat == EvasionCategory::AntiSandbox)  hasSandbox = true;

            if (tech == EvasionTechnique::RDTSC_Timing ||
                tech == EvasionTechnique::QueryPerformanceCounter_Timing ||
                tech == EvasionTechnique::GetTickCount_Timing ||
                tech == EvasionTechnique::NtQuerySystemTime_Timing) {
                hasTiming = true;
            }
        }

        // Nation-state: 11+ techniques OR (timing + VM + sandbox combined)
        if (numUnique >= 11 || (hasTiming && hasVM && hasSandbox)) {
            return "Nation-State";
        }
        if (numUnique >= 6) return "Advanced";
        if (numUnique >= 3) return "Intermediate";
        return "Basic";
    }
};

// ============================================================================
// EvasionDetector Public Interface
// ============================================================================

EvasionDetector::EvasionDetector(const EmulationConfig& config) noexcept
    : m_impl(nullptr)
{
    try {
        m_impl = std::make_unique<Impl>(config);
    } catch (const std::bad_alloc&) {
        // If allocation fails, m_impl remains null.
        // All public methods check for null and return safe defaults.
    }
}

EvasionDetector::~EvasionDetector() noexcept = default;

EvasionDetector::EvasionDetector(EvasionDetector&&) noexcept = default;
EvasionDetector& EvasionDetector::operator=(EvasionDetector&&) noexcept = default;

// ============================================================================
// OnAPICall — Main event handler for intercepted API calls
// ============================================================================

void EvasionDetector::OnAPICall(const APICallDetail& call) noexcept {
    if (!m_impl) return;
    if (!call.funcName) return;
    std::unique_lock lock(m_impl->mutex);

    // Update internal instruction counter
    if (call.instructionNum > m_impl->instrCounter) {
        m_impl->instrCounter = call.instructionNum;
    }

    // Reset SetLastError tracking if the current call is not GetLastError
    // and not SetLastError (the handler sets it itself)
    if (!FuncNameIs(call.funcName, "SetLastError") &&
        !FuncNameIs(call.funcName, "GetLastError")) {
        m_impl->lastCallWasSetLastError = false;
    }

    // ---- Anti-Debug APIs ----

    // IsDebuggerPresent
    if (FuncNameIs(call.funcName, "IsDebuggerPresent")) {
        m_impl->RecordAttempt(
            EvasionTechnique::IsDebuggerPresent,
            "IsDebuggerPresent() called — checks PEB.BeingDebugged flag",
            call.returnAddress, call.instructionNum, 0.6f);
        return;
    }

    // CheckRemoteDebuggerPresent
    if (FuncNameIs(call.funcName, "CheckRemoteDebuggerPresent")) {
        m_impl->RecordAttempt(
            EvasionTechnique::CheckRemoteDebuggerPresent,
            "CheckRemoteDebuggerPresent() called — queries remote debug status",
            call.returnAddress, call.instructionNum, 0.65f);
        return;
    }

    // NtQueryInformationProcess — debug port / flags / object handle
    if (FuncNameIs(call.funcName, "NtQueryInformationProcess")) {
        const uint64_t infoClass = call.args[1];
        if (infoClass == kProcessDebugPort) {
            m_impl->RecordAttempt(
                EvasionTechnique::NtQueryInfoProcessDebugPort,
                "NtQueryInformationProcess(ProcessDebugPort=7) — detects active debugger port",
                call.returnAddress, call.instructionNum, 0.7f);
        } else if (infoClass == kProcessDebugFlags) {
            m_impl->RecordAttempt(
                EvasionTechnique::NtQueryInfoProcessDebugFlags,
                "NtQueryInformationProcess(ProcessDebugFlags=31) — checks NoDebugInherit",
                call.returnAddress, call.instructionNum, 0.7f);
        } else if (infoClass == kProcessDebugObjectHandle) {
            m_impl->RecordAttempt(
                EvasionTechnique::NtQueryInfoProcessDebugObject,
                "NtQueryInformationProcess(ProcessDebugObjectHandle=30) — queries debug object",
                call.returnAddress, call.instructionNum, 0.75f);
        }
        return;
    }

    // NtSetInformationThread — ThreadHideFromDebugger
    if (FuncNameIs(call.funcName, "NtSetInformationThread")) {
        if (call.args[1] == kThreadHideFromDebugger) {
            m_impl->RecordAttempt(
                EvasionTechnique::NtSetInfoThreadHideFromDebugger,
                "NtSetInformationThread(ThreadHideFromDebugger=17) — hides thread from debugger",
                call.returnAddress, call.instructionNum, 0.8f);
        }
        return;
    }

    // CloseHandle with invalid sentinel
    if (FuncNameIs(call.funcName, "CloseHandle") ||
        FuncNameIs(call.funcName, "NtClose")) {
        const uint64_t handle = call.args[0];
        for (const uint64_t sentinel : kInvalidHandleSentinels) {
            if (handle == sentinel) {
                m_impl->RecordAttempt(
                    EvasionTechnique::CloseHandleWithInvalidHandle,
                    "CloseHandle() with known invalid sentinel — triggers exception under debugger",
                    call.returnAddress, call.instructionNum, 0.5f);
                return;
            }
        }
        return;
    }

    // OutputDebugString
    if (FuncNameIs(call.funcName, "OutputDebugStringA") ||
        FuncNameIs(call.funcName, "OutputDebugStringW")) {
        m_impl->RecordAttempt(
            EvasionTechnique::OutputDebugString,
            "OutputDebugString() called — may check debugger via GetLastError side-effect",
            call.returnAddress, call.instructionNum, 0.4f);
        return;
    }

    // SetUnhandledExceptionFilter
    if (FuncNameIs(call.funcName, "SetUnhandledExceptionFilter")) {
        m_impl->RecordAttempt(
            EvasionTechnique::UnhandledExceptionFilter,
            "SetUnhandledExceptionFilter() called — under debugger, filter is not invoked",
            call.returnAddress, call.instructionNum, 0.5f);
        return;
    }

    // NtYieldExecution
    if (FuncNameIs(call.funcName, "NtYieldExecution")) {
        m_impl->RecordAttempt(
            EvasionTechnique::NtYieldExecution,
            "NtYieldExecution() called — return value differs under debugger",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // SetLastError / GetLastError anti-debug pattern
    if (FuncNameIs(call.funcName, "SetLastError")) {
        m_impl->lastCallWasSetLastError = true;
        m_impl->setLastErrorInstrNum = call.instructionNum;
        return;
    }
    if (FuncNameIs(call.funcName, "GetLastError")) {
        if (m_impl->lastCallWasSetLastError &&
            call.instructionNum > m_impl->setLastErrorInstrNum &&
            (call.instructionNum - m_impl->setLastErrorInstrNum) < 100) {
            m_impl->RecordAttempt(
                EvasionTechnique::SetLastError_Check,
                "SetLastError/GetLastError pair — checks if debugger altered last error value",
                call.returnAddress, call.instructionNum, 0.4f);
        }
        m_impl->lastCallWasSetLastError = false;
        return;
    }

    // FindWindowA/W — looking for debugger/analysis windows
    if (FuncNameIs(call.funcName, "FindWindowA") ||
        FuncNameIs(call.funcName, "FindWindowW") ||
        FuncNameIs(call.funcName, "FindWindowExA") ||
        FuncNameIs(call.funcName, "FindWindowExW")) {
        if (call.category == APICategory::AntiDebug ||
            HasFlag(call.behaviorFlags, BehaviorFlag::AntiAnalysis)) {
            m_impl->RecordAttempt(
                EvasionTechnique::FindWindow_OllyDbg,
                "FindWindow() searching for debugger/analysis tool window",
                call.returnAddress, call.instructionNum, 0.6f);
        }
        return;
    }

    // ---- Timing APIs (also anti-debug) ----

    // GetTickCount / GetTickCount64
    if (FuncNameIs(call.funcName, "GetTickCount") ||
        FuncNameIs(call.funcName, "GetTickCount64")) {
        m_impl->RecordTimingEvent(call.returnAddress, call.instructionNum);
        if (call.instructionNum < 1000 && !m_impl->getTickCountRecorded) {
            m_impl->getTickCountRecorded = true;
            m_impl->RecordAttempt(
                EvasionTechnique::SystemUptime_Check,
                "GetTickCount() called early in execution — checking system uptime for sandbox detection",
                call.returnAddress, call.instructionNum, 0.35f);
        }
        return;
    }

    // QueryPerformanceCounter
    if (FuncNameIs(call.funcName, "QueryPerformanceCounter")) {
        m_impl->RecordTimingEvent(call.returnAddress, call.instructionNum);
        m_impl->qpcSeen = true;
        m_impl->qpcInstrNum = call.instructionNum;
        return;
    }

    // QueryPerformanceFrequency — often paired with QPC for timing attacks
    if (FuncNameIs(call.funcName, "QueryPerformanceFrequency")) {
        if (m_impl->qpcSeen &&
            call.instructionNum > m_impl->qpcInstrNum &&
            (call.instructionNum - m_impl->qpcInstrNum) < 500) {
            m_impl->RecordAttempt(
                EvasionTechnique::QueryPerformanceCounter_Timing,
                "QueryPerformanceCounter/Frequency pair — timing-based debugger detection",
                call.returnAddress, call.instructionNum, 0.65f);
        }
        return;
    }

    // NtQuerySystemTime / GetSystemTimeAsFileTime
    if (FuncNameIs(call.funcName, "NtQuerySystemTime") ||
        FuncNameIs(call.funcName, "GetSystemTimeAsFileTime")) {
        m_impl->RecordTimingEvent(call.returnAddress, call.instructionNum);
        return;
    }

    // ---- Anti-VM APIs ----

    // Registry queries for VM artifacts
    if (FuncNameIs(call.funcName, "RegOpenKeyExA") ||
        FuncNameIs(call.funcName, "RegOpenKeyExW") ||
        FuncNameIs(call.funcName, "RegQueryValueExA") ||
        FuncNameIs(call.funcName, "RegQueryValueExW") ||
        FuncNameIs(call.funcName, "RegOpenKeyA") ||
        FuncNameIs(call.funcName, "RegOpenKeyW") ||
        FuncNameIs(call.funcName, "RegGetValueA") ||
        FuncNameIs(call.funcName, "RegGetValueW")) {
        if (call.category == APICategory::AntiVM) {
            m_impl->RecordAttempt(
                EvasionTechnique::RegQuery_VMware,
                "Registry query targeting virtual machine artifacts",
                call.returnAddress, call.instructionNum, 0.6f);
        }
        return;
    }

    // CreateFile for VM devices
    if (FuncNameIs(call.funcName, "CreateFileA") ||
        FuncNameIs(call.funcName, "CreateFileW") ||
        FuncNameIs(call.funcName, "NtCreateFile") ||
        FuncNameIs(call.funcName, "NtOpenFile")) {
        if (call.category == APICategory::AntiVM) {
            m_impl->RecordAttempt(
                EvasionTechnique::DeviceQuery_VMware,
                "File/device open targeting virtual machine artifacts",
                call.returnAddress, call.instructionNum, 0.6f);
        }
        return;
    }

    // GetModuleHandle for VM/sandbox/debug DLLs
    if (FuncNameIs(call.funcName, "GetModuleHandleA") ||
        FuncNameIs(call.funcName, "GetModuleHandleW") ||
        FuncNameIs(call.funcName, "GetModuleHandleExA") ||
        FuncNameIs(call.funcName, "GetModuleHandleExW")) {
        if (call.category == APICategory::AntiVM) {
            m_impl->RecordAttempt(
                EvasionTechnique::FileCheck_VMware,
                "GetModuleHandle checking for VM-related DLL",
                call.returnAddress, call.instructionNum, 0.55f);
        } else if (call.category == APICategory::AntiDebug) {
            m_impl->RecordAttempt(
                EvasionTechnique::ModuleCheck_DbgHelp,
                "GetModuleHandle checking for debug-related DLL",
                call.returnAddress, call.instructionNum, 0.3f);
        }
        return;
    }

    // GetSystemFirmwareTable (SMBIOS / ACPI)
    if (FuncNameIs(call.funcName, "GetSystemFirmwareTable")) {
        const uint32_t sig = static_cast<uint32_t>(call.args[0]);
        if (sig == kFirmwareSigRSMB) {
            m_impl->RecordAttempt(
                EvasionTechnique::SMBIOS_Check,
                "GetSystemFirmwareTable('RSMB') — reading SMBIOS for VM vendor strings",
                call.returnAddress, call.instructionNum, 0.65f);
        } else if (sig == kFirmwareSigACPI) {
            m_impl->RecordAttempt(
                EvasionTechnique::ACPI_Check,
                "GetSystemFirmwareTable('ACPI') — reading ACPI tables for VM indicators",
                call.returnAddress, call.instructionNum, 0.65f);
        } else {
            m_impl->RecordAttempt(
                EvasionTechnique::FirmwareTable_Check,
                "GetSystemFirmwareTable() — reading firmware tables for VM detection",
                call.returnAddress, call.instructionNum, 0.65f);
        }
        return;
    }

    // EnumSystemFirmwareTables
    if (FuncNameIs(call.funcName, "EnumSystemFirmwareTables")) {
        m_impl->RecordAttempt(
            EvasionTechnique::FirmwareTable_Check,
            "EnumSystemFirmwareTables() — enumerating firmware tables for VM detection",
            call.returnAddress, call.instructionNum, 0.6f);
        return;
    }

    // Network adapter queries (MAC OUI)
    if (FuncNameIs(call.funcName, "GetAdaptersInfo") ||
        FuncNameIs(call.funcName, "GetAdaptersAddresses")) {
        m_impl->RecordAttempt(
            EvasionTechnique::MACAddress_VMware,
            "GetAdaptersInfo/Addresses() — likely checking MAC OUI for VM vendor",
            call.returnAddress, call.instructionNum, 0.5f);
        return;
    }

    // Disk size check
    if (FuncNameIs(call.funcName, "GetDiskFreeSpaceExA") ||
        FuncNameIs(call.funcName, "GetDiskFreeSpaceExW") ||
        FuncNameIs(call.funcName, "GetDiskFreeSpaceA") ||
        FuncNameIs(call.funcName, "GetDiskFreeSpaceW")) {
        m_impl->RecordAttempt(
            EvasionTechnique::DiskSize_Check,
            "GetDiskFreeSpace() — checking disk size (VMs often have small disks)",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // Physical memory size check
    if (FuncNameIs(call.funcName, "GlobalMemoryStatusEx") ||
        FuncNameIs(call.funcName, "GlobalMemoryStatus")) {
        m_impl->RecordAttempt(
            EvasionTechnique::MemorySize_Check,
            "GlobalMemoryStatus() — checking physical RAM (VMs often have less)",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // Processor count check
    if (FuncNameIs(call.funcName, "GetSystemInfo") ||
        FuncNameIs(call.funcName, "GetNativeSystemInfo")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessorCount_Check,
            "GetSystemInfo() — checking processor count (VMs often have fewer)",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // ---- Anti-Sandbox APIs ----

    // Sleep / SleepEx with long delay
    if (FuncNameIs(call.funcName, "Sleep") || FuncNameIs(call.funcName, "SleepEx")) {
        const uint64_t ms = call.args[0];
        if (ms > 60000) {
            m_impl->RecordAttempt(
                EvasionTechnique::SleepAcceleration,
                "Sleep() with delay > 60s — sandbox evasion via long sleep",
                call.returnAddress, call.instructionNum, 0.5f);
        }
        return;
    }

    // WaitForSingleObject with long timeout
    if (FuncNameIs(call.funcName, "WaitForSingleObject") ||
        FuncNameIs(call.funcName, "WaitForSingleObjectEx")) {
        const uint64_t ms = call.args[1];
        // INFINITE = 0xFFFFFFFF; ignore infinite waits (common in benign code)
        if (ms > 120000 && ms != 0xFFFFFFFF && ms != 0xFFFFFFFFFFFFFFFF) {
            m_impl->RecordAttempt(
                EvasionTechnique::SleepAcceleration,
                "WaitForSingleObject() with long timeout — sandbox evasion via delayed execution",
                call.returnAddress, call.instructionNum, 0.45f);
        }
        return;
    }

    // NtDelayExecution (native Sleep)
    if (FuncNameIs(call.funcName, "NtDelayExecution")) {
        m_impl->RecordAttempt(
            EvasionTechnique::SleepAcceleration,
            "NtDelayExecution() — native delay execution, potential sandbox evasion",
            call.returnAddress, call.instructionNum, 0.5f);
        return;
    }

    // User interaction checks
    if (FuncNameIs(call.funcName, "GetCursorPos") ||
        FuncNameIs(call.funcName, "GetLastInputInfo") ||
        FuncNameIs(call.funcName, "GetAsyncKeyState") ||
        FuncNameIs(call.funcName, "GetKeyState")) {
        m_impl->RecordAttempt(
            EvasionTechnique::UserInteraction_Check,
            "User interaction query — checking for real human activity (sandbox detection)",
            call.returnAddress, call.instructionNum, 0.4f);
        return;
    }

    // Screen resolution check
    if (FuncNameIs(call.funcName, "GetSystemMetrics")) {
        const uint64_t metric = call.args[0];
        if (metric == 0 || metric == 1) { // SM_CXSCREEN, SM_CYSCREEN
            m_impl->RecordAttempt(
                EvasionTechnique::ScreenResolution_Check,
                "GetSystemMetrics(SM_CX/CYSCREEN) — checking screen resolution for sandbox detection",
                call.returnAddress, call.instructionNum, 0.35f);
        }
        return;
    }

    // Domain joined check
    if (FuncNameIs(call.funcName, "GetComputerNameExA") ||
        FuncNameIs(call.funcName, "GetComputerNameExW")) {
        if (call.args[0] == 2) { // ComputerNameDnsDomain
            m_impl->RecordAttempt(
                EvasionTechnique::DomainJoined_Check,
                "GetComputerNameEx(DnsDomain) — checking if machine is domain-joined",
                call.returnAddress, call.instructionNum, 0.35f);
        }
        return;
    }

    // NetGetJoinInformation (domain check)
    if (FuncNameIs(call.funcName, "NetGetJoinInformation")) {
        m_impl->RecordAttempt(
            EvasionTechnique::DomainJoined_Check,
            "NetGetJoinInformation() — checking domain membership for sandbox detection",
            call.returnAddress, call.instructionNum, 0.35f);
        return;
    }

    // Process enumeration
    if (FuncNameIs(call.funcName, "Process32FirstW") ||
        FuncNameIs(call.funcName, "Process32First") ||
        FuncNameIs(call.funcName, "Process32NextW") ||
        FuncNameIs(call.funcName, "Process32Next")) {
        m_impl->RecordAttempt(
            EvasionTechnique::RunningProcessCount_Check,
            "Process32First/Next() — enumerating running processes (sandbox typically has few)",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // CreateToolhelp32Snapshot for processes
    if (FuncNameIs(call.funcName, "CreateToolhelp32Snapshot")) {
        if (call.args[0] & 0x2) { // TH32CS_SNAPPROCESS
            m_impl->RecordAttempt(
                EvasionTechnique::RunningProcessCount_Check,
                "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) — process enumeration for sandbox detection",
                call.returnAddress, call.instructionNum, 0.3f);
        }
        return;
    }

    // EnumProcesses (PSAPI)
    if (FuncNameIs(call.funcName, "EnumProcesses") ||
        FuncNameIs(call.funcName, "K32EnumProcesses")) {
        m_impl->RecordAttempt(
            EvasionTechnique::RunningProcessCount_Check,
            "EnumProcesses() — process enumeration for sandbox detection",
            call.returnAddress, call.instructionNum, 0.3f);
        return;
    }

    // NtQuerySystemInformation (process list)
    if (FuncNameIs(call.funcName, "NtQuerySystemInformation")) {
        // SystemProcessInformation = 5
        if (call.args[0] == 5) {
            m_impl->RecordAttempt(
                EvasionTechnique::RunningProcessCount_Check,
                "NtQuerySystemInformation(SystemProcessInformation) — native process enumeration",
                call.returnAddress, call.instructionNum, 0.35f);
        }
        return;
    }

    // GetForegroundWindow — user interaction / sandbox check
    if (FuncNameIs(call.funcName, "GetForegroundWindow")) {
        m_impl->RecordAttempt(
            EvasionTechnique::UserInteraction_Check,
            "GetForegroundWindow() — checking for active user interaction",
            call.returnAddress, call.instructionNum, 0.35f);
        return;
    }

    // Mouse movement check via SetWindowsHookEx
    if (FuncNameIs(call.funcName, "SetWindowsHookExA") ||
        FuncNameIs(call.funcName, "SetWindowsHookExW")) {
        // WH_MOUSE_LL = 14
        if (call.args[0] == 14) {
            m_impl->RecordAttempt(
                EvasionTechnique::MouseMovement_Check,
                "SetWindowsHookEx(WH_MOUSE_LL) — monitoring mouse movement for sandbox detection",
                call.returnAddress, call.instructionNum, 0.4f);
        }
        return;
    }

    // GetModuleFileName — checking own filename for sandbox indicators
    if (FuncNameIs(call.funcName, "GetModuleFileNameA") ||
        FuncNameIs(call.funcName, "GetModuleFileNameW") ||
        FuncNameIs(call.funcName, "GetModuleFileNameExA") ||
        FuncNameIs(call.funcName, "GetModuleFileNameExW")) {
        // If the handle is null (checking own filename), this is suspicious
        if (call.args[0] == 0) {
            m_impl->RecordAttempt(
                EvasionTechnique::Filename_Check,
                "GetModuleFileName(NULL) — checking own filename for sandbox indicators",
                call.returnAddress, call.instructionNum, 0.45f);
        }
        return;
    }

    // GetCommandLine — also used to check execution context
    if (FuncNameIs(call.funcName, "GetCommandLineA") ||
        FuncNameIs(call.funcName, "GetCommandLineW")) {
        m_impl->RecordAttempt(
            EvasionTechnique::Filename_Check,
            "GetCommandLine() — checking command line for sandbox indicators",
            call.returnAddress, call.instructionNum, 0.35f);
        return;
    }

    // SHGetSpecialFolderPath / SHGetFolderPath — recent files check
    if (FuncNameIs(call.funcName, "SHGetSpecialFolderPathA") ||
        FuncNameIs(call.funcName, "SHGetSpecialFolderPathW") ||
        FuncNameIs(call.funcName, "SHGetFolderPathA") ||
        FuncNameIs(call.funcName, "SHGetFolderPathW")) {
        // CSIDL_RECENT = 0x0008
        if (call.args[1] == 0x0008) {
            m_impl->RecordAttempt(
                EvasionTechnique::RecentFiles_Check,
                "SHGetSpecialFolderPath(CSIDL_RECENT) — checking recent files for sandbox detection",
                call.returnAddress, call.instructionNum, 0.35f);
        }
        return;
    }

    // SetupDi* — USB history check
    if (FuncNameIs(call.funcName, "SetupDiGetClassDevsA") ||
        FuncNameIs(call.funcName, "SetupDiGetClassDevsW") ||
        FuncNameIs(call.funcName, "SetupDiEnumDeviceInfo") ||
        FuncNameIs(call.funcName, "SetupDiGetDeviceRegistryPropertyA") ||
        FuncNameIs(call.funcName, "SetupDiGetDeviceRegistryPropertyW")) {
        m_impl->RecordAttempt(
            EvasionTechnique::USBHistory_Check,
            "SetupDi*() — enumerating device history (USB artifacts indicate real machine)",
            call.returnAddress, call.instructionNum, 0.4f);
        return;
    }

    // MsiEnumProducts / MsiGetProductInfo — installed software check
    if (FuncNameIs(call.funcName, "MsiEnumProductsA") ||
        FuncNameIs(call.funcName, "MsiEnumProductsW") ||
        FuncNameIs(call.funcName, "MsiGetProductInfoA") ||
        FuncNameIs(call.funcName, "MsiGetProductInfoW") ||
        FuncNameIs(call.funcName, "MsiEnumProductsExA") ||
        FuncNameIs(call.funcName, "MsiEnumProductsExW")) {
        m_impl->RecordAttempt(
            EvasionTechnique::InstalledSoftware_Check,
            "Msi*() — enumerating installed software (sandbox detection heuristic)",
            call.returnAddress, call.instructionNum, 0.35f);
        return;
    }

    // ---- Parent process check ----
    if (FuncNameIs(call.funcName, "NtQueryInformationProcess")) {
        // ProcessBasicInformation = 0
        if (call.args[1] == 0) {
            m_impl->RecordAttempt(
                EvasionTechnique::ParentProcess_Check,
                "NtQueryInformationProcess(ProcessBasicInformation) — may check parent PID for analysis tools",
                call.returnAddress, call.instructionNum, 0.5f);
        }
        return;
    }

    // __cpuid-based checks that arrive as API calls (some emulators hook these)
    if (FuncNameIs(call.funcName, "__cpuid") || FuncNameIs(call.funcName, "cpuid")) {
        const uint64_t leaf = call.args[0];
        if (leaf == 1) {
            // EAX=1 → ECX bit 31 is hypervisor present bit
            m_impl->RecordAttempt(
                EvasionTechnique::CPUID_Hypervisor,
                "CPUID(EAX=1) — checking hypervisor present bit in ECX[31]",
                call.returnAddress, call.instructionNum, 0.65f);
        } else if (leaf == 0x40000000) {
            // Hypervisor vendor leaf
            m_impl->RecordAttempt(
                EvasionTechnique::CPUID_Vendor,
                "CPUID(EAX=0x40000000) — reading hypervisor vendor string",
                call.returnAddress, call.instructionNum, 0.5f);
        } else if (leaf == 0) {
            // Processor vendor string — may check for known VM vendors
            m_impl->RecordAttempt(
                EvasionTechnique::CPUID_Vendor,
                "CPUID(EAX=0) — reading processor vendor string for VM detection",
                call.returnAddress, call.instructionNum, 0.5f);
        }
        return;
    }
}

// ============================================================================
// OnTimingCheck — Called for timing-related instruction events (RDTSC, etc.)
// ============================================================================

void EvasionDetector::OnTimingCheck(GuestAddress rip, uint64_t instrCount) noexcept {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->mutex);

    // Track this timing event by RIP
    if (m_impl->totalTimingRIPs >= kMaxTimingRIPs &&
        m_impl->timingByRIP.find(rip) == m_impl->timingByRIP.end()) {
        return;
    }

    try {
        auto& entries = m_impl->timingByRIP[rip];
        if (entries.empty()) {
            ++m_impl->totalTimingRIPs;
        }
        if (entries.size() >= kMaxTimingEntriesPerRIP) {
            return;
        }
        entries.push_back(instrCount);

        // First occurrence at this RIP → record basic RDTSC timing attempt
        if (entries.size() == 1) {
            float severity = 0.7f;

            // If QPC was seen recently, this is a compound timing check
            if (m_impl->qpcSeen &&
                instrCount > m_impl->qpcInstrNum &&
                (instrCount - m_impl->qpcInstrNum) < 2000) {
                severity = 0.75f;
            }

            m_impl->RecordAttempt(
                EvasionTechnique::RDTSC_Timing,
                "RDTSC instruction executed — hardware timestamp counter read for timing-based evasion",
                rip, instrCount, severity);
        }

        // Second+ occurrence at same RIP → timing delta attack pattern
        if (entries.size() == 2) {
            const uint64_t delta = (entries[1] >= entries[0])
                ? (entries[1] - entries[0])
                : std::numeric_limits<uint64_t>::max();

            float severity = 0.7f;
            if (delta < 1000) {
                // Very tight loop → highly likely timing attack
                severity = 0.85f;
            } else if (delta < 5000) {
                severity = 0.75f;
            }

            // If QPC was also used → compound timing evasion
            if (m_impl->qpcSeen) {
                severity = std::min(severity + 0.1f, 1.0f);
            }

            m_impl->RecordAttempt(
                EvasionTechnique::RDTSC_Timing,
                "Repeated RDTSC from same code location — timing delta attack pattern detected",
                rip, instrCount, severity);
        }

        // Third+ occurrence → high-confidence compound timing
        if (entries.size() >= 3 && entries.size() <= 5) {
            m_impl->RecordAttempt(
                EvasionTechnique::RDTSC_Timing,
                "Multiple RDTSC reads from same function — advanced timing-based evasion",
                rip, instrCount, 0.85f);
        }
    } catch (const std::bad_alloc&) {
        // OOM — silently drop
    }
}

// ============================================================================
// OnEnvironmentQuery — Called for environment-related evasion checks
// ============================================================================

void EvasionDetector::OnEnvironmentQuery(const std::string& queryType,
                                         const std::string& detail) noexcept {
    if (!m_impl) return;
    if (queryType.empty()) return;
    std::unique_lock lock(m_impl->mutex);

    // CPUID-based checks
    if (CaseInsensitiveEquals(queryType, std::string_view("cpuid"))) {
        if (CaseInsensitiveEquals(detail, std::string_view("hypervisor"))) {
            m_impl->RecordAttempt(
                EvasionTechnique::CPUID_Hypervisor,
                "CPUID hypervisor bit check — detecting virtualization",
                0, m_impl->instrCounter, 0.65f);
        } else if (CaseInsensitiveEquals(detail, std::string_view("vendor"))) {
            m_impl->RecordAttempt(
                EvasionTechnique::CPUID_Vendor,
                "CPUID vendor string check — detecting VM-specific CPU vendor",
                0, m_impl->instrCounter, 0.5f);
        }
        return;
    }

    // Registry-based environment queries
    if (CaseInsensitiveEquals(queryType, std::string_view("registry"))) {
        m_impl->CheckRegistryForVMIndicators(
            detail.c_str(), 0, m_impl->instrCounter);
        return;
    }

    // Firmware table queries
    if (CaseInsensitiveEquals(queryType, std::string_view("firmware"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::FirmwareTable_Check,
            BuildDescription("Firmware table query - ", detail),
            0, m_impl->instrCounter, 0.65f);
        return;
    }

    // Filename self-check (sandbox detection)
    if (CaseInsensitiveEquals(queryType, std::string_view("filename"))) {
        // Check if the detail contains sandbox-indicative filename patterns
        bool foundIndicator = false;
        for (const char* indicator : kSandboxFilenameIndicators) {
            if (CaseInsensitiveContains(detail, indicator)) {
                foundIndicator = true;
                break;
            }
        }
        m_impl->RecordAttempt(
            EvasionTechnique::Filename_Check,
            foundIndicator
                ? BuildDescription("Filename check matched sandbox indicator in: ", detail)
                : BuildDescription("Filename self-check: ", detail),
            0, m_impl->instrCounter,
            foundIndicator ? 0.55f : 0.45f);
        return;
    }

    // USB history check
    if (CaseInsensitiveEquals(queryType, std::string_view("usb"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::USBHistory_Check,
            BuildDescription("USB device history query - ", detail),
            0, m_impl->instrCounter, 0.4f);
        return;
    }

    // Installed software check
    if (CaseInsensitiveEquals(queryType, std::string_view("software"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::InstalledSoftware_Check,
            BuildDescription("Installed software enumeration - ", detail),
            0, m_impl->instrCounter, 0.35f);
        return;
    }

    // Mouse movement check
    if (CaseInsensitiveEquals(queryType, std::string_view("mouse"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::MouseMovement_Check,
            BuildDescription("Mouse movement analysis - ", detail),
            0, m_impl->instrCounter, 0.4f);
        return;
    }

    // Recent files check
    if (CaseInsensitiveEquals(queryType, std::string_view("recentfiles"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::RecentFiles_Check,
            BuildDescription("Recent files enumeration - ", detail),
            0, m_impl->instrCounter, 0.35f);
        return;
    }

    // Parent process check
    if (CaseInsensitiveEquals(queryType, std::string_view("parent"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::ParentProcess_Check,
            BuildDescription("Parent process analysis - ", detail),
            0, m_impl->instrCounter, 0.5f);
        return;
    }

    // Screen resolution query
    if (CaseInsensitiveEquals(queryType, std::string_view("screen"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::ScreenResolution_Check,
            BuildDescription("Screen resolution query - ", detail),
            0, m_impl->instrCounter, 0.35f);
        return;
    }

    // Domain / network environment query
    if (CaseInsensitiveEquals(queryType, std::string_view("domain"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::DomainJoined_Check,
            BuildDescription("Domain membership query - ", detail),
            0, m_impl->instrCounter, 0.35f);
        return;
    }

    // System uptime query
    if (CaseInsensitiveEquals(queryType, std::string_view("uptime"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::SystemUptime_Check,
            BuildDescription("System uptime query - ", detail),
            0, m_impl->instrCounter, 0.35f);
        return;
    }

    // User interaction query
    if (CaseInsensitiveEquals(queryType, std::string_view("interaction"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::UserInteraction_Check,
            BuildDescription("User interaction query - ", detail),
            0, m_impl->instrCounter, 0.4f);
        return;
    }

    // MAC address query
    if (CaseInsensitiveEquals(queryType, std::string_view("mac"))) {
        // Check for VMware/VBox MAC prefixes
        bool isVMware = false;
        bool isVBox = false;
        for (const char* prefix : kVMwareMACPrefixes) {
            if (CaseInsensitiveContains(detail, prefix)) {
                isVMware = true;
                break;
            }
        }
        if (!isVMware && CaseInsensitiveContains(detail, kVBoxMACPrefix)) {
            isVBox = true;
        }

        if (isVMware) {
            m_impl->RecordAttempt(
                EvasionTechnique::MACAddress_VMware,
                BuildDescription("MAC address matched VMware OUI: ", detail),
                0, m_impl->instrCounter, 0.5f);
        } else if (isVBox) {
            m_impl->RecordAttempt(
                EvasionTechnique::MACAddress_VBox,
                BuildDescription("MAC address matched VirtualBox OUI: ", detail),
                0, m_impl->instrCounter, 0.5f);
        } else {
            m_impl->RecordAttempt(
                EvasionTechnique::MACAddress_VMware,
                BuildDescription("MAC address query for VM detection: ", detail),
                0, m_impl->instrCounter, 0.4f);
        }
        return;
    }

    // Disk size query
    if (CaseInsensitiveEquals(queryType, std::string_view("disk"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::DiskSize_Check,
            BuildDescription("Disk size query - ", detail),
            0, m_impl->instrCounter, 0.3f);
        return;
    }

    // Memory size query
    if (CaseInsensitiveEquals(queryType, std::string_view("memory"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::MemorySize_Check,
            BuildDescription("Memory size query - ", detail),
            0, m_impl->instrCounter, 0.3f);
        return;
    }

    // Processor count query
    if (CaseInsensitiveEquals(queryType, std::string_view("processor"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessorCount_Check,
            BuildDescription("Processor count query - ", detail),
            0, m_impl->instrCounter, 0.3f);
        return;
    }

    // Sleep acceleration / delay detection
    if (CaseInsensitiveEquals(queryType, std::string_view("sleep"))) {
        m_impl->RecordAttempt(
            EvasionTechnique::SleepAcceleration,
            BuildDescription("Sleep acceleration detection - ", detail),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
}

// ============================================================================
// OnProcessEnumeration — Called when the sample enumerates a process
// ============================================================================

void EvasionDetector::OnProcessEnumeration(const std::string& processName) noexcept {
    if (!m_impl) return;
    if (processName.empty()) return;
    std::unique_lock lock(m_impl->mutex);
    const std::string_view processView{ processName.data(),
        std::min<size_t>(processName.size(), kMaxInputStringLength) };

    // Track the process name (capped)
    try {
        if (m_impl->processNamesSeen.size() >= kMaxProcessNames) return;

        // Normalize to lowercase for dedup
        std::string normalized;
        normalized.reserve(processView.size());
        for (char c : processView) {
            normalized.push_back(AsciiToLower(c));
        }

        // Already seen this process name?
        if (m_impl->processNamesSeen.count(normalized) > 0) return;
        m_impl->processNamesSeen.insert(normalized);
    } catch (const std::bad_alloc&) {
        return;
    }

    // Check against known analysis/VM tool process names
    for (const auto& mapping : kProcessMappings) {
        if (CaseInsensitiveEquals(processName.c_str(), mapping.processName)) {
            m_impl->RecordAttempt(
                mapping.technique,
                BuildDescription("Process enumeration found analysis tool: ", mapping.processName),
                0, m_impl->instrCounter, mapping.severity);
            return;
        }
    }

    // Additional partial-match checks for process names that may have
    // version suffixes or path prefixes
    if (CaseInsensitiveContains(processName, "wireshark")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_Wireshark,
            BuildDescription("Process name contains 'wireshark': ", processName),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
    if (CaseInsensitiveContains(processName, "ida")) {
        // Avoid false positives on common names containing "ida"
        if (CaseInsensitiveContains(processName, "idaq") ||
            CaseInsensitiveContains(processName, "ida64") ||
            CaseInsensitiveContains(processName, "ida.exe") ||
            CaseInsensitiveContains(processName, "idapro")) {
            m_impl->RecordAttempt(
                EvasionTechnique::ProcessCheck_IDA,
                BuildDescription("Process name matches IDA pattern: ", processName),
                0, m_impl->instrCounter, 0.55f);
            return;
        }
    }
    if (CaseInsensitiveContains(processName, "x64dbg") ||
        CaseInsensitiveContains(processName, "x32dbg") ||
        CaseInsensitiveContains(processName, "ollydbg") ||
        CaseInsensitiveContains(processName, "windbg") ||
        CaseInsensitiveContains(processName, "immunitydebugger")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_x64dbg,
            BuildDescription("Process name matches debugger pattern: ", processName),
            0, m_impl->instrCounter, 0.55f);
        return;
    }
    if (CaseInsensitiveContains(processName, "procmon")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_Procmon,
            BuildDescription("Process name contains 'procmon': ", processName),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
    if (CaseInsensitiveContains(processName, "procexp")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_ProcExp,
            BuildDescription("Process name contains 'procexp': ", processName),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
    if (CaseInsensitiveContains(processName, "vmtoolsd") ||
        CaseInsensitiveContains(processName, "vmwaretray") ||
        CaseInsensitiveContains(processName, "vmwareuser") ||
        CaseInsensitiveContains(processName, "vmacthlp")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_VMTools,
            BuildDescription("Process name matches VMware tool pattern: ", processName),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
    if (CaseInsensitiveContains(processName, "vboxservice") ||
        CaseInsensitiveContains(processName, "vboxtray") ||
        CaseInsensitiveContains(processName, "vboxcontrol")) {
        m_impl->RecordAttempt(
            EvasionTechnique::ProcessCheck_VBoxTray,
            BuildDescription("Process name matches VirtualBox tool pattern: ", processName),
            0, m_impl->instrCounter, 0.5f);
        return;
    }
    if (CaseInsensitiveContains(processName, "filemon")) {
        m_impl->RecordAttempt(
            EvasionTechnique::WindowCheck_Filemon,
            BuildDescription("Process name contains 'filemon': ", processName),
            0, m_impl->instrCounter, 0.4f);
        return;
    }
}

// ============================================================================
// OnInstructionProbe — Called for suspicious decoded instruction patterns
// ============================================================================

void EvasionDetector::OnInstructionProbe(
    GuestAddress rip, uint64_t instrCount, const char* detail) noexcept
{
    if (!m_impl) return;
    if (!detail || *detail == '\0') return;
    std::unique_lock lock(m_impl->mutex);

    if (instrCount > m_impl->instrCounter) {
        m_impl->instrCounter = instrCount;
    }

    const bool isEVEXProbe =
        CaseInsensitiveContains(detail, "evex") ||
        CaseInsensitiveContains(detail, "avx-512") ||
        CaseInsensitiveContains(detail, "avx512") ||
        CaseInsensitiveContains(detail, "zmm");
    if (!isEVEXProbe) {
        return;
    }

    if (m_impl->instructionProbeRIPs.size() >= kMaxInstructionProbeRIPs &&
        m_impl->instructionProbeRIPs.find(rip) == m_impl->instructionProbeRIPs.end()) {
        return;
    }

    try {
        if (!m_impl->instructionProbeRIPs.insert(rip).second) {
            return;
        }
    } catch (const std::bad_alloc&) {
        return;
    }

    m_impl->RecordAttempt(
        EvasionTechnique::AVX512_EVEXInstruction,
        "EVEX / AVX-512 instruction executed — potential emulator or analyst capability probe",
        rip, instrCount, 0.55f);
}

// ============================================================================
// Results — Read-only accessors
// ============================================================================

const std::vector<EvasionAttempt>& EvasionDetector::GetAttempts() const noexcept {
    static const std::vector<EvasionAttempt> kEmpty;
    static thread_local std::vector<EvasionAttempt> snapshot;
    if (!m_impl) return kEmpty;

    try {
        std::shared_lock lock(m_impl->mutex);
        snapshot = m_impl->attempts;
        return snapshot;
    } catch (const std::bad_alloc&) {
        snapshot.clear();
        return kEmpty;
    }
}

EvasionSummary EvasionDetector::GetSummary() const noexcept {
    EvasionSummary summary;
    if (!m_impl) return summary;
    std::shared_lock lock(m_impl->mutex);

    summary.totalAttempts    = static_cast<uint32_t>(m_impl->attempts.size());
    summary.uniqueTechniques = m_impl->uniqueTechniqueCount;

    // Count attempts by category
    for (const auto& attempt : m_impl->attempts) {
        switch (ClassifyTechnique(attempt.technique)) {
            case EvasionCategory::AntiDebug:
                ++summary.antiDebugCount;
                break;
            case EvasionCategory::AntiVM:
                ++summary.antiVMCount;
                break;
            case EvasionCategory::AntiSandbox:
                ++summary.antiSandboxCount;
                break;
            case EvasionCategory::AntiAnalysis:
                ++summary.antiAnalysisCount;
                break;
        }
    }

    summary.evasionScore       = m_impl->ComputeEvasionScore();
    summary.isHighlyEvasive    = summary.evasionScore > 0.7f;
    summary.sophisticationLevel = m_impl->DetermineSophisticationLevel();

    return summary;
}

uint32_t EvasionDetector::GetAttemptCount() const noexcept {
    if (!m_impl) return 0;
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->attempts.size());
}

std::vector<const EvasionAttempt*> EvasionDetector::GetByTechnique(
    EvasionTechnique tech) const noexcept
{
    std::vector<const EvasionAttempt*> results;
    if (!m_impl) return results;

    try {
        static thread_local std::vector<EvasionAttempt> snapshot;
        snapshot.clear();
        {
            std::shared_lock lock(m_impl->mutex);
            snapshot = m_impl->attempts;
        }
        results.reserve(16);
        for (const auto& attempt : snapshot) {
            if (attempt.technique == tech) {
                results.push_back(&attempt);
            }
        }
    } catch (const std::bad_alloc&) {
        // OOM on reserve — return what we have
    }
    return results;
}

bool EvasionDetector::HasTechnique(EvasionTechnique tech) const noexcept {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->mutex);
    const size_t techniqueIndex = TechniqueIndex(tech);
    return techniqueIndex < m_impl->techniqueSeen.size() &&
           m_impl->techniqueSeen[techniqueIndex];
}

float EvasionDetector::GetEvasionScore() const noexcept {
    if (!m_impl) return 0.0f;
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ComputeEvasionScore();
}

// ============================================================================
// Reset — Clear all accumulated state
// ============================================================================

void EvasionDetector::Reset() noexcept {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->mutex);

    m_impl->attempts.clear();
    m_impl->techniqueSeen.fill(false);
    m_impl->uniqueTechniqueCount = 0;
    m_impl->timingByRIP.clear();
    m_impl->totalTimingRIPs          = 0;
    m_impl->processNamesSeen.clear();
    m_impl->registryPathsSeen.clear();
    m_impl->filePathsSeen.clear();
    m_impl->instructionProbeRIPs.clear();
    m_impl->lastCallWasSetLastError  = false;
    m_impl->setLastErrorInstrNum     = 0;
    m_impl->instrCounter             = 0;
    m_impl->qpcSeen                  = false;
    m_impl->qpcInstrNum              = 0;
    m_impl->getTickCountRecorded     = false;
}

} // namespace Phantom
