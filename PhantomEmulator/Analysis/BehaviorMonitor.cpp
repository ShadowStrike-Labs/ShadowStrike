/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BehaviorMonitor.cpp — Behavioral analysis engine implementation
 *
 * Implements 50 behavioral detection rules as state machines, covering:
 *   - Process injection (classic, APC, NtMap, atom bombing, early bird, hijack)
 *   - Process hollowing (classic, transacted, doppelganging)
 *   - DLL injection (LoadLibrary, manual map, reflective)
 *   - Shellcode execution (RWX, staged, egg hunter, stack-based)
 *   - Persistence, credential access, ransomware, defense evasion
 *   - C2 communication, downloaders, discovery, keyloggers
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "BehaviorMonitor.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_map>
#include <utility>

namespace Phantom {

// ============================================================================
// Anonymous namespace — Constants and helpers
// ============================================================================

namespace {

// Win32 constants for argument-level checks (no windows.h dependency)
constexpr uint32_t kCreateSuspended        = 0x00000004;
constexpr uint32_t kPageExecuteReadWrite   = 0x40;
constexpr uint32_t kPageExecuteRead        = 0x20;
constexpr uint32_t kPageExecute            = 0x10;
constexpr uint32_t kPageReadWrite          = 0x04;
constexpr uint32_t kProcessVMWrite         = 0x0020;
constexpr uint32_t kProcessVMOperation     = 0x0008;
constexpr uint32_t kProcessCreateThread    = 0x0002;
constexpr uint32_t kProcessAllAccess       = 0x001FFFFF;
constexpr uint32_t kGenericWrite           = 0x40000000;
constexpr uint32_t kWHKeyboard             = 2;
constexpr uint32_t kWHKeyboardLL           = 13;

// Capacity caps to prevent resource exhaustion
constexpr uint32_t kMaxAlerts              = 1024;
constexpr uint32_t kMaxStateMachines       = 512;
constexpr uint32_t kMaxRWXTracked          = 256;
constexpr uint32_t kMaxResourceEntries     = 4096;
constexpr uint8_t  kMaxEvidencePerMachine  = 16;
constexpr uint32_t kMaxEvidencePerAlert    = 32;

// Total number of rules
constexpr uint32_t kRuleCount              = 50;

// ----------------------------------------------------------------------------
// Case-insensitive string comparison (no locale, ASCII only)
// ----------------------------------------------------------------------------

[[nodiscard]] bool StrEqCI(const char* a, const char* b) noexcept {
    if (!a || !b) return false;
    for (;; ++a, ++b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        if (ca == '\0') return true;
    }
}

[[nodiscard]] bool FuncIs(const APICallDetail& call, const char* name) noexcept {
    return StrEqCI(call.funcName, name);
}

[[nodiscard]] bool FuncIsAny(const APICallDetail& call,
                             const char* a, const char* b) noexcept {
    return FuncIs(call, a) || FuncIs(call, b);
}

[[nodiscard]] bool FuncIsAny3(const APICallDetail& call,
                              const char* a, const char* b, const char* c) noexcept {
    return FuncIs(call, a) || FuncIs(call, b) || FuncIs(call, c);
}

[[nodiscard]] bool FuncIsAny4(const APICallDetail& call,
                              const char* a, const char* b,
                              const char* c, const char* d) noexcept {
    return FuncIs(call, a) || FuncIs(call, b) || FuncIs(call, c) || FuncIs(call, d);
}

[[nodiscard]] bool ContainsCI(const char* haystack, const char* needle) noexcept {
    if (!haystack || !needle) return false;
    size_t nLen = 0;
    while (needle[nLen]) ++nLen;
    if (nLen == 0) return true;
    for (size_t i = 0; haystack[i]; ++i) {
        bool match = true;
        for (size_t j = 0; j < nLen; ++j) {
            char ha = haystack[i + j];
            if (ha == '\0') { match = false; break; }
            char ne = needle[j];
            if (ha >= 'A' && ha <= 'Z') ha += 32;
            if (ne >= 'A' && ne <= 'Z') ne += 32;
            if (ha != ne) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

// Check if a Win32 protection value includes execute
[[nodiscard]] bool ProtHasExec(uint32_t prot) noexcept {
    uint32_t base = prot & 0xFF;
    return base == kPageExecute || base == kPageExecuteRead ||
           base == kPageExecuteReadWrite || base == 0x80; // PAGE_EXECUTE_WRITECOPY
}

// Check if a Win32 protection is RWX
[[nodiscard]] bool ProtIsRWX(uint32_t prot) noexcept {
    uint32_t base = prot & 0xFF;
    return base == kPageExecuteReadWrite || base == 0x80;
}

// Check if a Win32 protection is RW (no execute)
[[nodiscard]] bool ProtIsRW(uint32_t prot) noexcept {
    uint32_t base = prot & 0xFF;
    return base == kPageReadWrite || base == 0x08; // PAGE_WRITECOPY
}

// Check if OpenProcess access mask implies injection capability
[[nodiscard]] bool IsInjectionAccess(uint32_t access) noexcept {
    if (access == kProcessAllAccess) return true;
    return (access & kProcessVMWrite) && (access & kProcessVMOperation);
}

// Combine BehaviorFlag values
[[nodiscard]] constexpr BehaviorFlag CombineFlags(BehaviorFlag a, BehaviorFlag b) noexcept {
    return static_cast<BehaviorFlag>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

// ----------------------------------------------------------------------------
// Rule Metadata Table
// ----------------------------------------------------------------------------

struct RuleInfo {
    BehaviorCategory category;
    AlertSeverity    severity;
    float            confidence;
    const char*      description;
    const char*      mitreId;
    uint8_t          totalSteps;  // 0 = inline/counter-based (no state machine)
    uint32_t         windowSize;  // Max instruction window
    bool             crossThread;
};

// Indexed by ruleId - 1. All 50 rules.
static const RuleInfo kRuleTable[kRuleCount] = {
    // --- Process Injection (Rules 1-6) ---
    /*  1 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.95f,
               "Classic process injection: OpenProcess->VirtualAllocEx->WriteProcessMemory->CreateRemoteThread",
               "T1055.001", 4, 500'000, true },
    /*  2 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.95f,
               "APC injection: OpenProcess->VirtualAllocEx->WriteProcessMemory->QueueUserAPC",
               "T1055.004", 4, 500'000, true },
    /*  3 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.90f,
               "NtMapViewOfSection injection: NtCreateSection->NtMapViewOfSection (remote)",
               "T1055.012", 2, 300'000, true },
    /*  4 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.85f,
               "Atom bombing: GlobalAddAtom->QueueUserAPC with GlobalGetAtomName",
               "T1055", 2, 400'000, true },
    /*  5 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.95f,
               "Early bird injection: CreateProcess(SUSPENDED)->VirtualAllocEx->WriteProcessMemory->QueueUserAPC->ResumeThread",
               "T1055.004", 5, 600'000, true },
    /*  6 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.90f,
               "Thread hijacking: OpenThread->SuspendThread->SetThreadContext->ResumeThread",
               "T1055.003", 4, 400'000, false },
    // --- Process Hollowing (Rules 7-9) ---
    /*  7 */ { BehaviorCategory::ProcessHollowing, AlertSeverity::Critical, 0.95f,
               "Classic process hollowing: CreateProcess(SUSPENDED)->NtUnmapViewOfSection->VirtualAllocEx->WriteProcessMemory->SetThreadContext->ResumeThread",
               "T1055.012", 6, 800'000, false },
    /*  8 */ { BehaviorCategory::ProcessHollowing, AlertSeverity::Critical, 0.90f,
               "Transacted hollowing: CreateTransaction->CreateFileTransacted->NtCreateSection->NtCreateProcessEx",
               "T1055.013", 4, 500'000, false },
    /*  9 */ { BehaviorCategory::ProcessHollowing, AlertSeverity::Critical, 0.95f,
               "Process doppelganging: CreateTransaction->CreateFileTransacted->WriteFile->NtCreateSection->NtCreateProcessEx->RollbackTransaction",
               "T1055.013", 6, 600'000, false },
    // --- DLL Injection (Rules 10-12) ---
    /* 10 */ { BehaviorCategory::DLLInjection, AlertSeverity::Critical, 0.90f,
               "LoadLibrary injection: OpenProcess->VirtualAllocEx->WriteProcessMemory(DLL path)->CreateRemoteThread(LoadLibrary)",
               "T1055.001", 4, 500'000, false },
    /* 11 */ { BehaviorCategory::DLLInjection, AlertSeverity::Critical, 0.90f,
               "Manual DLL mapping: OpenProcess->VirtualAllocEx(RWX)->WriteProcessMemory(PE)->CreateRemoteThread",
               "T1055.001", 4, 500'000, false },
    /* 12 */ { BehaviorCategory::ReflectiveDLLLoad, AlertSeverity::Critical, 0.85f,
               "Reflective DLL loading: VirtualAlloc(RWX)->write PE->execute in-memory",
               "T1620.001", 0, 1'000'000, false },
    // --- Shellcode Detection (Rules 13-16) ---
    /* 13 */ { BehaviorCategory::ShellcodeExecution, AlertSeverity::High, 0.85f,
               "Classic shellcode: VirtualAlloc(RWX)->write->execute",
               "T1059.007", 0, 1'000'000, false },
    /* 14 */ { BehaviorCategory::ShellcodeExecution, AlertSeverity::High, 0.90f,
               "Staged shellcode: VirtualAlloc(RW)->VirtualProtect(RX)->execute",
               "T1059.007", 2, 1'000'000, false },
    /* 15 */ { BehaviorCategory::ShellcodeExecution, AlertSeverity::Medium, 0.70f,
               "Egg hunter: small code scanning memory for larger payload marker",
               "T1059.007", 0, 0, false },
    /* 16 */ { BehaviorCategory::ShellcodeExecution, AlertSeverity::High, 0.80f,
               "Stack-based shellcode: write to stack followed by execution from stack",
               "T1059.007", 0, 0, false },
    // --- Persistence (Rules 17-21) ---
    /* 17 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.90f,
               "Registry Run key persistence: RegOpenKey(Run/RunOnce)->RegSetValue",
               "T1547.001", 2, 200'000, false },
    /* 18 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.85f,
               "Scheduled task creation via schtasks.exe",
               "T1053.005", 0, 0, false },
    /* 19 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.90f,
               "Service installation: OpenSCManager->CreateService->StartService",
               "T1543.003", 3, 400'000, false },
    /* 20 */ { BehaviorCategory::Persistence, AlertSeverity::Medium, 0.70f,
               "DLL search order hijacking: CreateFile with DLL in system path",
               "T1574.001", 0, 0, false },
    /* 21 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.80f,
               "WMI event subscription via CoCreateInstance(IWbemServices)",
               "T1546.003", 0, 0, false },
    // --- Credential Access (Rules 22-24) ---
    /* 22 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Critical, 0.90f,
               "LSASS process access with high privileges",
               "T1003.001", 0, 0, false },
    /* 23 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.85f,
               "SAM registry hive access attempt",
               "T1003.002", 0, 0, false },
    /* 24 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::High, 0.90f,
               "Token theft: OpenProcessToken->DuplicateTokenEx->ImpersonateLoggedOnUser",
               "T1134.001", 3, 300'000, false },
    // --- Ransomware (Rules 25-29) ---
    /* 25 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.90f,
               "Ransomware behavior: file enumeration + crypto API + write pattern",
               "T1486", 0, 2'000'000, false },
    /* 26 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.95f,
               "Shadow copy deletion via vssadmin or wmic",
               "T1490", 0, 0, false },
    /* 27 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.90f,
               "Direct volume/physical drive access for encryption",
               "T1561.002", 0, 0, false },
    /* 28 */ { BehaviorCategory::Ransomware, AlertSeverity::High, 0.80f,
               "Ransom note file creation (common ransom note filenames)",
               "T1486", 0, 0, false },
    /* 29 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.85f,
               "Mass file rename with crypto-like extensions",
               "T1486", 0, 500'000, false },
    // --- Defense Evasion (Rules 30-34) ---
    /* 30 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.80f,
               "Anti-debug technique: IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess(DebugPort)",
               "T1497.001", 0, 0, false },
    /* 31 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.75f,
               "Anti-VM detection: CPUID / VM registry checks / VM process enumeration",
               "T1497.001", 0, 0, false },
    /* 32 */ { BehaviorCategory::AntiForensics, AlertSeverity::High, 0.85f,
               "Timestomping: SetFileTime with dates far in the past",
               "T1070.006", 0, 0, false },
    /* 33 */ { BehaviorCategory::AntiForensics, AlertSeverity::High, 0.90f,
               "Event log tampering: OpenEventLog->ClearEventLog",
               "T1070.001", 2, 200'000, false },
    /* 34 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Critical, 0.90f,
               "AMSI bypass: LoadLibrary(amsi.dll)->GetProcAddress(AmsiScanBuffer)->VirtualProtect->patch",
               "T1562.001", 3, 300'000, false },
    // --- Network C2 (Rules 35-37) ---
    /* 35 */ { BehaviorCategory::CommandAndControl, AlertSeverity::High, 0.80f,
               "HTTP C2 channel: InternetOpen->InternetConnect->HttpOpenRequest->HttpSendRequest",
               "T1071.001", 4, 500'000, false },
    /* 36 */ { BehaviorCategory::CommandAndControl, AlertSeverity::High, 0.75f,
               "DNS tunneling: repeated DnsQuery with encoded subdomains",
               "T1071.004", 0, 300'000, false },
    /* 37 */ { BehaviorCategory::CommandAndControl, AlertSeverity::High, 0.80f,
               "Raw socket C2: WSASocket->connect->send/recv loop",
               "T1095", 3, 400'000, false },
    // --- Downloader (Rules 38-40) ---
    /* 38 */ { BehaviorCategory::Downloader, AlertSeverity::High, 0.85f,
               "URL download and execute: URLDownloadToFile->CreateProcess/ShellExecute",
               "T1105", 2, 500'000, false },
    /* 39 */ { BehaviorCategory::Downloader, AlertSeverity::High, 0.80f,
               "WinHTTP download chain: WinHttpOpen->Connect->OpenRequest->Send->ReceiveResponse",
               "T1105", 5, 500'000, false },
    /* 40 */ { BehaviorCategory::Downloader, AlertSeverity::High, 0.80f,
               "COM-based download via XMLHTTP",
               "T1105", 2, 400'000, false },
    // --- Discovery (Rules 41-44) ---
    /* 41 */ { BehaviorCategory::Discovery, AlertSeverity::Low, 0.70f,
               "Process enumeration via CreateToolhelp32Snapshot + Process32First/Next",
               "T1057", 2, 200'000, false },
    /* 42 */ { BehaviorCategory::Discovery, AlertSeverity::Low, 0.65f,
               "System information gathering: multiple sysinfo API calls in sequence",
               "T1082", 0, 200'000, false },
    /* 43 */ { BehaviorCategory::Discovery, AlertSeverity::Low, 0.65f,
               "Network configuration enumeration: GetAdaptersInfo / GetIpForwardTable / NetShareEnum",
               "T1016", 0, 300'000, false },
    /* 44 */ { BehaviorCategory::Discovery, AlertSeverity::Low, 0.60f,
               "File system reconnaissance: GetDriveType + GetDiskFreeSpace on multiple drives",
               "T1083", 0, 300'000, false },
    // --- Additional (Rules 45-50) ---
    /* 45 */ { BehaviorCategory::Keylogger, AlertSeverity::High, 0.85f,
               "Keylogger: SetWindowsHookEx(WH_KEYBOARD/WH_KEYBOARD_LL) or GetAsyncKeyState loop",
               "T1056.001", 0, 0, false },
    /* 46 */ { BehaviorCategory::ScreenCapture, AlertSeverity::Medium, 0.80f,
               "Screen capture: GetDC(0)->CreateCompatibleDC->BitBlt",
               "T1113", 3, 200'000, false },
    /* 47 */ { BehaviorCategory::Discovery, AlertSeverity::Medium, 0.75f,
               "Clipboard data theft: OpenClipboard->GetClipboardData",
               "T1115", 2, 100'000, false },
    /* 48 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.95f,
               "MBR/VBR overwrite: CreateFile(\\\\.\\PhysicalDrive0, GENERIC_WRITE)",
               "T1561.002", 0, 0, false },
    /* 49 */ { BehaviorCategory::CommandAndControl, AlertSeverity::Medium, 0.75f,
               "Named pipe C2: CreateNamedPipe->ConnectNamedPipe->ReadFile/WriteFile",
               "T1090", 3, 400'000, false },
    /* 50 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.85f,
               "PowerShell cradle: CreateProcess with powershell.exe -enc / IEX / DownloadString",
               "T1059.001", 0, 0, false },
};

[[nodiscard]] const RuleInfo& GetRule(uint32_t ruleId) noexcept {
    return kRuleTable[ruleId - 1];
}

// ----------------------------------------------------------------------------
// State Machine Instance
// ----------------------------------------------------------------------------

struct StateMachine {
    uint32_t ruleId        = 0;
    uint8_t  currentState  = 0; // Steps completed (1 after first match)
    uint64_t firstInstr    = 0;
    uint64_t lastInstr     = 0;
    uint16_t originThread  = 0;

    // Captured context passed between steps
    uint64_t capturedHandle   = 0;
    uint64_t capturedAddress  = 0;
    uint64_t capturedHandle2  = 0;

    // Evidence (call indices that triggered transitions)
    uint32_t evidence[kMaxEvidencePerMachine] = {};
    uint8_t  evidenceCount = 0;

    void AddEvidence(uint32_t idx) noexcept {
        if (evidenceCount < kMaxEvidencePerMachine)
            evidence[evidenceCount++] = idx;
    }
};

// ----------------------------------------------------------------------------
// Counter accumulator for frequency-based rules
// ----------------------------------------------------------------------------

struct CountAccum {
    uint32_t count      = 0;
    uint64_t firstInstr = 0;
    uint64_t lastInstr  = 0;
    uint32_t evidence[kMaxEvidencePerAlert] = {};
    uint8_t  evidenceCount = 0;
    bool     fired      = false;

    void Record(uint32_t callIndex, uint64_t instrCount) noexcept {
        if (count == 0) firstInstr = instrCount;
        lastInstr = instrCount;
        ++count;
        if (evidenceCount < kMaxEvidencePerAlert)
            evidence[evidenceCount++] = callIndex;
    }

    void Reset() noexcept {
        count = 0; firstInstr = 0; lastInstr = 0;
        evidenceCount = 0; fired = false;
    }

    [[nodiscard]] std::vector<uint32_t> GetEvidence() const {
        return { evidence, evidence + evidenceCount };
    }
};

// ----------------------------------------------------------------------------
// Tracked RWX / RW allocation for shellcode detection
// ----------------------------------------------------------------------------

struct TrackedAlloc {
    GuestAddress base        = 0;
    GuestSize    size        = 0;
    uint64_t     instrCount  = 0;
    uint16_t     threadId    = 0;
    uint32_t     callIndex   = 0;
    bool         isRWX       = false;  // true=RWX, false=RW
    bool         protChanged = false;  // RW→RX/RWX change observed
    bool         wasWritten  = false;
    bool         executed    = false;
};

} // anonymous namespace

// ============================================================================
// Impl — PIMPL body
// ============================================================================

struct BehaviorMonitor::Impl {
    bool enabled = false;

    // --- Alert storage ---
    std::vector<BehaviorAlert> alerts;
    BehaviorAlertCallback alertCallback;
    AlertSeverity maxSeverity = AlertSeverity::Info;
    BehaviorFlag accumulatedFlags = BehaviorFlag::None;

    // --- Active state machines ---
    std::vector<StateMachine> machines;

    // --- Cross-thread resource tracker ---
    struct ResourceOrigin {
        uint16_t threadId     = 0;
        uint64_t instrCount   = 0;
    };
    std::unordered_map<uint64_t, ResourceOrigin> handleOrigins;
    std::unordered_map<uint64_t, ResourceOrigin> allocOrigins;

    // --- Counter-based detection ---
    CountAccum findFileCount;
    CountAccum cryptoAPICount;
    CountAccum readWriteFileCount;
    CountAccum fileRenameCount;
    CountAccum dnsQueryCount;
    CountAccum keyStateCount;
    CountAccum driveEnumCount;
    CountAccum netEnumCount;

    // System info individual flags (for Rule 42)
    struct SysInfoFlags {
        bool computerName = false;
        bool userName     = false;
        bool versionEx    = false;
        bool systemInfo   = false;
        uint32_t count    = 0;
        uint64_t firstInstr = 0;
        uint64_t lastInstr  = 0;
        std::vector<uint32_t> evidence;
        bool fired        = false;

        void Set(const char* which, uint32_t callIndex, uint64_t instr) {
            if (StrEqCI(which, "computerName") && !computerName)
                { computerName = true; ++count; }
            else if (StrEqCI(which, "userName") && !userName)
                { userName = true; ++count; }
            else if (StrEqCI(which, "versionEx") && !versionEx)
                { versionEx = true; ++count; }
            else if (StrEqCI(which, "systemInfo") && !systemInfo)
                { systemInfo = true; ++count; }
            else return;

            if (count == 1) firstInstr = instr;
            lastInstr = instr;
            if (evidence.size() < kMaxEvidencePerAlert)
                evidence.push_back(callIndex);
        }

        void Reset() {
            computerName = userName = versionEx = systemInfo = false;
            count = 0; firstInstr = lastInstr = 0;
            evidence.clear(); fired = false;
        }
    } sysInfo;

    // Anti-debug/anti-VM call tracking
    bool antiDebugFired = false;
    bool antiVMFired    = false;

    // --- Shellcode / W→X tracking ---
    std::vector<TrackedAlloc> trackedAllocs;

    // Egg hunter tracking: source RIP seen doing many small reads
    struct EggHunterState {
        GuestAddress codeBase       = 0;
        uint32_t     scanCount      = 0;
        uint64_t     firstInstr     = 0;
        uint64_t     lastInstr      = 0;
        uint32_t     uniquePageCount = 0;
        std::unordered_map<GuestAddress, bool> scannedPages;
        bool         fired          = false;
    } eggHunter;

    // Stack execution tracking
    GuestAddress stackBase = 0;
    GuestSize    stackSize = 0;

    // -----------------------------------------------------------------------
    // Methods
    // -----------------------------------------------------------------------

    void ProcessAPICall(const APICallDetail& call, uint32_t callIndex) noexcept;
    void StartNewMachines(const APICallDetail& call, uint32_t callIndex) noexcept;
    void AdvanceStateMachines(const APICallDetail& call, uint32_t callIndex) noexcept;
    bool TryTransition(StateMachine& sm, const APICallDetail& call) noexcept;
    void ExpireMachines(uint64_t instrCount) noexcept;
    void CompleteMachine(const StateMachine& sm) noexcept;

    void CheckInlineRules(const APICallDetail& call, uint32_t callIndex) noexcept;
    void UpdateCounters(const APICallDetail& call, uint32_t callIndex) noexcept;
    void CheckCounterThresholds(uint64_t instrCount) noexcept;
    void TrackAllocations(const APICallDetail& call, uint32_t callIndex) noexcept;
    void TrackResources(const APICallDetail& call) noexcept;

    void EmitAlert(uint32_t ruleId,
                   const std::vector<uint32_t>& evidence,
                   uint64_t instrCount, uint16_t threadId) noexcept;

    void EmitAlertDirect(BehaviorCategory cat, AlertSeverity sev, float conf,
                         const char* desc, const char* mitre,
                         const std::vector<uint32_t>& evidence,
                         uint64_t instrCount, uint16_t threadId) noexcept;

    void StartMachine(uint32_t ruleId, const APICallDetail& call,
                      uint32_t callIndex, uint64_t handle = 0,
                      uint64_t address = 0) noexcept;
};

// ============================================================================
// Impl — Alert Emission
// ============================================================================

void BehaviorMonitor::Impl::EmitAlert(
    uint32_t ruleId, const std::vector<uint32_t>& evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    if (alerts.size() >= kMaxAlerts) return;
    if (ruleId < 1 || ruleId > kRuleCount) return;

    const auto& rule = GetRule(ruleId);
    EmitAlertDirect(rule.category, rule.severity, rule.confidence,
                    rule.description, rule.mitreId,
                    evidence, instrCount, threadId);
}

void BehaviorMonitor::Impl::EmitAlertDirect(
    BehaviorCategory cat, AlertSeverity sev, float conf,
    const char* desc, const char* mitre,
    const std::vector<uint32_t>& evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    if (alerts.size() >= kMaxAlerts) return;
    try {
        BehaviorAlert alert;
        alert.category           = cat;
        alert.severity           = sev;
        alert.confidence         = conf;
        alert.description        = desc ? desc : "";
        alert.mitreId            = mitre ? mitre : "";
        alert.evidenceCallIndices = evidence;
        alert.instructionCount   = instrCount;
        alert.threadId           = threadId;

        if (static_cast<uint8_t>(sev) > static_cast<uint8_t>(maxSeverity))
            maxSeverity = sev;

        if (alertCallback) {
            alertCallback(alert);
        }

        alerts.push_back(std::move(alert));
    } catch (...) {
        // Allocation failure — silently drop. Non-critical path.
    }
}

// ============================================================================
// Impl — State Machine Lifecycle
// ============================================================================

void BehaviorMonitor::Impl::StartMachine(
    uint32_t ruleId, const APICallDetail& call, uint32_t callIndex,
    uint64_t handle, uint64_t address) noexcept
{
    if (machines.size() >= kMaxStateMachines) return;

    StateMachine sm;
    sm.ruleId        = ruleId;
    sm.currentState  = 1;
    sm.firstInstr    = static_cast<uint64_t>(call.instructionNum);
    sm.lastInstr     = sm.firstInstr;
    sm.originThread  = call.threadId;
    sm.capturedHandle  = handle;
    sm.capturedAddress = address;
    sm.AddEvidence(callIndex);
    machines.push_back(sm);
}

void BehaviorMonitor::Impl::CompleteMachine(const StateMachine& sm) noexcept {
    std::vector<uint32_t> ev(sm.evidence, sm.evidence + sm.evidenceCount);
    EmitAlert(sm.ruleId, ev, sm.lastInstr, sm.originThread);
}

void BehaviorMonitor::Impl::ExpireMachines(uint64_t instrCount) noexcept {
    machines.erase(
        std::remove_if(machines.begin(), machines.end(),
            [instrCount](const StateMachine& sm) {
                const auto& info = GetRule(sm.ruleId);
                return (instrCount - sm.firstInstr) > info.windowSize;
            }),
        machines.end());
}

// ============================================================================
// Impl — StartNewMachines: Match first step of all state-machine rules
// ============================================================================

void BehaviorMonitor::Impl::StartNewMachines(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    if (machines.size() >= kMaxStateMachines) return;
    if (!call.funcName || !call.succeeded) return;

    const uint64_t retVal = call.returnValue;
    const auto instrN = static_cast<uint64_t>(call.instructionNum);

    // ---- Rules 1, 2, 10, 11: Start with OpenProcess (injection) ----
    if (FuncIs(call, "OpenProcess")) {
        uint32_t access = static_cast<uint32_t>(call.args[0]);
        uint32_t pid    = static_cast<uint32_t>(call.args[2]);
        if (IsInjectionAccess(access) && pid != 0 && retVal != 0) {
            StartMachine(1,  call, callIndex, retVal);
            StartMachine(2,  call, callIndex, retVal);
            StartMachine(10, call, callIndex, retVal);
            StartMachine(11, call, callIndex, retVal);
        }
    }

    // ---- Rule 3: NtCreateSection ----
    if (FuncIsAny(call, "NtCreateSection", "ZwCreateSection")) {
        if (retVal != 0) {
            StartMachine(3, call, callIndex, retVal);
        }
    }

    // ---- Rule 4: GlobalAddAtom (atom bombing) ----
    if (FuncIsAny3(call, "GlobalAddAtomA", "GlobalAddAtomW", "GlobalAddAtom")) {
        StartMachine(4, call, callIndex, retVal);
    }

    // ---- Rules 5, 7: CreateProcess(SUSPENDED) ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        uint32_t flags = static_cast<uint32_t>(call.args[5]);
        if (flags & kCreateSuspended) {
            StartMachine(5, call, callIndex, retVal);
            StartMachine(7, call, callIndex, retVal);
        }
    }

    // ---- Rule 6: OpenThread (thread hijacking) ----
    if (FuncIsAny(call, "OpenThread", "NtOpenThread")) {
        if (retVal != 0) {
            StartMachine(6, call, callIndex, retVal);
        }
    }

    // ---- Rules 8, 9: CreateTransaction ----
    if (FuncIsAny(call, "CreateTransaction", "NtCreateTransaction")) {
        if (retVal != 0) {
            StartMachine(8, call, callIndex, retVal);
            StartMachine(9, call, callIndex, retVal);
        }
    }

    // ---- Rule 14: VirtualAlloc(RW) for staged shellcode ----
    if (FuncIsAny(call, "VirtualAlloc", "NtAllocateVirtualMemory")) {
        uint32_t prot = static_cast<uint32_t>(call.args[3]);
        if (ProtIsRW(prot) && !ProtHasExec(prot) && retVal != 0) {
            StartMachine(14, call, callIndex, 0, retVal);
        }
    }

    // ---- Rule 17: RegOpenKey on Run/RunOnce ----
    if (FuncIsAny4(call, "RegOpenKeyExA", "RegOpenKeyExW",
                   "RegCreateKeyExA", "RegCreateKeyExW")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::RegistryPersistence)) {
            StartMachine(17, call, callIndex, retVal);
        }
    }

    // ---- Rule 19: OpenSCManager (service installation) ----
    if (FuncIsAny(call, "OpenSCManagerA", "OpenSCManagerW")) {
        if (retVal != 0) {
            StartMachine(19, call, callIndex, retVal);
        }
    }

    // ---- Rule 24: OpenProcessToken (token stealing) ----
    if (FuncIsAny(call, "OpenProcessToken", "NtOpenProcessToken")) {
        if (retVal != 0 || call.succeeded) {
            StartMachine(24, call, callIndex, call.args[2]);
        }
    }

    // ---- Rule 33: OpenEventLog (log tampering) ----
    if (FuncIsAny(call, "OpenEventLogA", "OpenEventLogW")) {
        if (retVal != 0) {
            StartMachine(33, call, callIndex, retVal);
        }
    }

    // ---- Rule 34: LoadLibrary(amsi.dll) — AMSI bypass ----
    if (FuncIsAny3(call, "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion) ||
            call.category == APICategory::ModuleLoading) {
            // We flag this as potential AMSI bypass start; the transition
            // logic verifies the GetProcAddress->VirtualProtect chain.
            StartMachine(34, call, callIndex, retVal);
        }
    }

    // ---- Rule 35: InternetOpen (HTTP C2) ----
    if (FuncIsAny(call, "InternetOpenA", "InternetOpenW")) {
        if (retVal != 0) {
            StartMachine(35, call, callIndex, retVal);
        }
    }

    // ---- Rule 37: WSASocket/socket (raw socket C2) ----
    if (FuncIsAny3(call, "WSASocketA", "WSASocketW", "socket")) {
        if (retVal != 0 && retVal != static_cast<uint64_t>(-1)) {
            StartMachine(37, call, callIndex, retVal);
        }
    }

    // ---- Rule 38: URLDownloadToFile (download+exec) ----
    if (FuncIsAny(call, "URLDownloadToFileA", "URLDownloadToFileW")) {
        StartMachine(38, call, callIndex);
    }

    // ---- Rule 39: WinHttpOpen ----
    if (FuncIs(call, "WinHttpOpen")) {
        if (retVal != 0) {
            StartMachine(39, call, callIndex, retVal);
        }
    }

    // ---- Rule 40: CoCreateInstance (COM download) ----
    if (FuncIs(call, "CoCreateInstance")) {
        if (call.category == APICategory::COM || call.category == APICategory::Network) {
            StartMachine(40, call, callIndex, retVal);
        }
    }

    // ---- Rule 41: CreateToolhelp32Snapshot (process enumeration) ----
    if (FuncIs(call, "CreateToolhelp32Snapshot")) {
        if (retVal != 0) {
            StartMachine(41, call, callIndex, retVal);
        }
    }

    // ---- Rule 46: GetDC(0) (screen capture) ----
    if (FuncIsAny(call, "GetDC", "GetWindowDC")) {
        if (call.args[0] == 0 && retVal != 0) {
            StartMachine(46, call, callIndex, retVal);
        }
    }

    // ---- Rule 47: OpenClipboard (clipboard theft) ----
    if (FuncIs(call, "OpenClipboard")) {
        StartMachine(47, call, callIndex);
    }

    // ---- Rule 49: CreateNamedPipe (named pipe C2) ----
    if (FuncIsAny(call, "CreateNamedPipeA", "CreateNamedPipeW")) {
        if (retVal != 0) {
            StartMachine(49, call, callIndex, retVal);
        }
    }
}

// ============================================================================
// Impl — TryTransition: Per-rule state advancement logic
// ============================================================================

bool BehaviorMonitor::Impl::TryTransition(
    StateMachine& sm, const APICallDetail& call) noexcept
{
    if (!call.funcName) return false;

    const auto& info = GetRule(sm.ruleId);

    // Thread check: for cross-thread rules, verify shared resource correlation.
    // For non-cross-thread rules, require same thread.
    if (!info.crossThread && sm.originThread != call.threadId) return false;

    // For cross-thread rules, the transition is valid if:
    // (a) same thread, OR
    // (b) the call references a resource (handle/address) that was
    //     created by the state machine's originating thread.
    if (info.crossThread && sm.originThread != call.threadId) {
        bool sharedResource = false;
        // Check if this call uses a handle created by the origin thread
        if (sm.capturedHandle != 0) {
            for (uint32_t argIdx = 0; argIdx < call.argCount && argIdx < 8; ++argIdx) {
                if (call.args[argIdx] == sm.capturedHandle) {
                    sharedResource = true;
                    break;
                }
            }
        }
        // Check if this call targets an address allocated by the origin thread
        if (!sharedResource && sm.capturedAddress != 0) {
            for (uint32_t argIdx = 0; argIdx < call.argCount && argIdx < 8; ++argIdx) {
                if (call.args[argIdx] == sm.capturedAddress) {
                    sharedResource = true;
                    break;
                }
            }
        }
        // Check the cross-thread resource tracker
        if (!sharedResource) {
            auto hit = handleOrigins.find(sm.capturedHandle);
            if (hit != handleOrigins.end() && hit->second.threadId == sm.originThread)
                sharedResource = true;
        }
        if (!sharedResource) return false;
    }

    // Window check
    uint64_t instr = static_cast<uint64_t>(call.instructionNum);
    if (info.windowSize > 0 && (instr - sm.firstInstr) > info.windowSize)
        return false;

    bool matched = false;

    switch (sm.ruleId) {

    // ======================================================================
    // Rule 1: Classic injection
    //   OpenProcess(done) → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
    // ======================================================================
    case 1:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    sm.capturedAddress = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 3: if (FuncIs(call, "CreateRemoteThread") && call.succeeded)
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 2: APC injection
    //   OpenProcess(done) → VirtualAllocEx → WriteProcessMemory → QueueUserAPC
    // ======================================================================
    case 2:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    sm.capturedAddress = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "QueueUserAPC", "NtQueueApcThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 3: NtMapViewOfSection injection
    //   NtCreateSection(done) → NtMapViewOfSection (remote)
    // ======================================================================
    case 3:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "NtMapViewOfSection", "ZwMapViewOfSection")) {
                // args[1] = process handle — if not current process, it's remote
                if (call.args[1] != 0 && call.args[1] != static_cast<uint64_t>(-1))
                    matched = true;
            }
        } break;

    // ======================================================================
    // Rule 4: Atom bombing
    //   GlobalAddAtom(done) → QueueUserAPC/NtQueueApcThread
    // ======================================================================
    case 4:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "QueueUserAPC", "NtQueueApcThread"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 5: Early bird injection
    //   CreateProcess(SUSP)(done) → VirtualAllocEx → WriteProcessMemory →
    //   QueueUserAPC → ResumeThread
    // ======================================================================
    case 5:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    sm.capturedAddress = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "QueueUserAPC", "NtQueueApcThread"))
                    matched = true;
                break;
        case 4: if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 6: Thread hijacking
    //   OpenThread(done) → SuspendThread → SetThreadContext → ResumeThread
    // ======================================================================
    case 6:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "SuspendThread", "NtSuspendThread"))
                    matched = true;
                break;
        case 2: if (FuncIsAny3(call, "SetThreadContext", "Wow64SetThreadContext",
                               "NtSetContextThread"))
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 7: Classic process hollowing
    //   CreateProcess(SUSP)(done) → NtUnmapViewOfSection → VirtualAllocEx →
    //   WriteProcessMemory → SetThreadContext → ResumeThread
    // ======================================================================
    case 7:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "NtUnmapViewOfSection", "ZwUnmapViewOfSection"))
                    matched = true;
                break;
        case 2: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    sm.capturedAddress = call.returnValue;
                    matched = true;
                } break;
        case 3: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 4: if (FuncIsAny3(call, "SetThreadContext", "Wow64SetThreadContext",
                               "NtSetContextThread"))
                    matched = true;
                break;
        case 5: if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 8: Transacted hollowing
    //   CreateTransaction(done) → CreateFileTransacted → NtCreateSection →
    //   NtCreateProcessEx
    // ======================================================================
    case 8:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateFileTransactedA", "CreateFileTransactedW"))
                    { sm.capturedHandle2 = call.returnValue; matched = true; }
                break;
        case 2: if (FuncIsAny(call, "NtCreateSection", "ZwCreateSection"))
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "NtCreateProcessEx", "RtlCreateProcessParametersEx"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 9: Process doppelganging
    //   CreateTransaction(done) → CreateFileTransacted → WriteFile →
    //   NtCreateSection → NtCreateProcessEx → RollbackTransaction
    // ======================================================================
    case 9:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateFileTransactedA", "CreateFileTransactedW"))
                    { sm.capturedHandle2 = call.returnValue; matched = true; }
                break;
        case 2: if (FuncIs(call, "WriteFile") && call.succeeded)
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "NtCreateSection", "ZwCreateSection"))
                    matched = true;
                break;
        case 4: if (FuncIsAny(call, "NtCreateProcessEx", "RtlCreateProcessParametersEx"))
                    matched = true;
                break;
        case 5: if (FuncIsAny(call, "RollbackTransaction", "NtRollbackTransaction"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 10: LoadLibrary injection
    //   OpenProcess(done) → VirtualAllocEx → WriteProcessMemory(DLL) →
    //   CreateRemoteThread(LoadLibrary)
    // ======================================================================
    case 10:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    sm.capturedAddress = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIs(call, "WriteProcessMemory") && call.succeeded) {
                    // DLL injection: typical write size is a path string (<520 bytes)
                    if (call.args[3] > 0 && call.args[3] < 1024)
                        matched = true;
                } break;
        case 3: if (FuncIs(call, "CreateRemoteThread") && call.succeeded)
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 11: Manual DLL mapping
    //   OpenProcess(done) → VirtualAllocEx(RWX) → WriteProcessMemory(PE) →
    //   CreateRemoteThread
    // ======================================================================
    case 11:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "VirtualAllocEx") && call.succeeded) {
                    uint32_t prot = static_cast<uint32_t>(call.args[4]);
                    if (ProtIsRWX(prot) || ProtHasExec(prot)) {
                        sm.capturedAddress = call.returnValue;
                        matched = true;
                    }
                } break;
        case 2: if (FuncIs(call, "WriteProcessMemory") && call.succeeded) {
                    // Manual mapping: typical write size >= one page (PE sections)
                    if (call.args[3] >= 0x200)
                        matched = true;
                } break;
        case 3: if (FuncIs(call, "CreateRemoteThread") && call.succeeded)
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 14: Staged shellcode
    //   VirtualAlloc(RW)(done) → VirtualProtect(RX/RWX)
    //   (Execution is detected via OnWXTransition, completing the chain)
    // ======================================================================
    case 14:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory")) {
                uint32_t newProt = static_cast<uint32_t>(call.args[2]);
                if (ProtHasExec(newProt)) {
                    sm.capturedHandle = call.args[0]; // address being protected
                    matched = true;
                }
            }
        } break;

    // ======================================================================
    // Rule 17: Registry Run key
    //   RegOpenKey/RegCreateKey(Run/RunOnce)(done) → RegSetValue
    // ======================================================================
    case 17:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "RegSetValueExA", "RegSetValueExW",
                           "RegSetValueA", "RegSetValueW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 19: Service installation
    //   OpenSCManager(done) → CreateService → StartService
    // ======================================================================
    case 19:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateServiceA", "CreateServiceW")) {
                    sm.capturedHandle2 = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIsAny(call, "StartServiceA", "StartServiceW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 24: Token stealing
    //   OpenProcessToken(done) → DuplicateTokenEx → ImpersonateLoggedOnUser
    // ======================================================================
    case 24:
        switch (sm.currentState) {
        case 1: if (FuncIsAny3(call, "DuplicateTokenEx", "DuplicateToken",
                               "NtDuplicateToken")) {
                    sm.capturedHandle2 = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIsAny3(call, "ImpersonateLoggedOnUser", "SetThreadToken",
                               "NtSetInformationThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 33: Log tampering
    //   OpenEventLog(done) → ClearEventLog
    // ======================================================================
    case 33:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "ClearEventLogA", "ClearEventLogW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 34: AMSI bypass
    //   LoadLibrary(amsi)(done) → GetProcAddress → VirtualProtect
    // ======================================================================
    case 34:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "GetProcAddress", "LdrGetProcedureAddress"))
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 35: HTTP C2
    //   InternetOpen(done) → InternetConnect → HttpOpenRequest → HttpSendRequest
    // ======================================================================
    case 35:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "InternetConnectA", "InternetConnectW")) {
                    sm.capturedHandle2 = call.returnValue;
                    matched = true;
                } break;
        case 2: if (FuncIsAny(call, "HttpOpenRequestA", "HttpOpenRequestW"))
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "HttpSendRequestA", "HttpSendRequestW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 37: Raw socket C2
    //   WSASocket/socket(done) → connect → send/WSASend
    // ======================================================================
    case 37:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "connect", "WSAConnect"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "send", "WSASend", "sendto", "WSASendTo"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 38: URL download + exec
    //   URLDownloadToFile(done) → CreateProcess/ShellExecute
    // ======================================================================
    case 38:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                           "ShellExecuteA", "ShellExecuteW") ||
                FuncIsAny(call, "ShellExecuteExA", "ShellExecuteExW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 39: WinHTTP download chain
    //   WinHttpOpen(done) → WinHttpConnect → WinHttpOpenRequest →
    //   WinHttpSendRequest → WinHttpReceiveResponse
    // ======================================================================
    case 39:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WinHttpConnect"))
                    { sm.capturedHandle2 = call.returnValue; matched = true; }
                break;
        case 2: if (FuncIs(call, "WinHttpOpenRequest"))
                    matched = true;
                break;
        case 3: if (FuncIs(call, "WinHttpSendRequest"))
                    matched = true;
                break;
        case 4: if (FuncIs(call, "WinHttpReceiveResponse"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 40: COM-based download
    //   CoCreateInstance(done) → network send/receive or ExecMethod
    // ======================================================================
    case 40:
        if (sm.currentState == 1) {
            if (call.category == APICategory::Network ||
                FuncIsAny(call, "HttpSendRequestA", "HttpSendRequestW") ||
                FuncIsAny(call, "InternetReadFile", "URLDownloadToFileA"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 41: Process enumeration
    //   CreateToolhelp32Snapshot(done) → Process32First/Next
    // ======================================================================
    case 41:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "Process32FirstW", "Process32First",
                           "Process32NextW", "Process32Next"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 46: Screen capture
    //   GetDC(0)(done) → CreateCompatibleDC → BitBlt
    // ======================================================================
    case 46:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "CreateCompatibleDC"))
                    matched = true;
                break;
        case 2: if (FuncIsAny3(call, "BitBlt", "StretchBlt",
                               "CreateCompatibleBitmap"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 47: Clipboard theft
    //   OpenClipboard(done) → GetClipboardData
    // ======================================================================
    case 47:
        if (sm.currentState == 1) {
            if (FuncIs(call, "GetClipboardData"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 49: Named pipe C2
    //   CreateNamedPipe(done) → ConnectNamedPipe → ReadFile/WriteFile
    // ======================================================================
    case 49:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "ConnectNamedPipe"))
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "ReadFile", "WriteFile"))
                    matched = true;
                break;
        } break;

    default:
        break;
    }

    return matched;
}

// ============================================================================
// Impl — AdvanceStateMachines
// ============================================================================

void BehaviorMonitor::Impl::AdvanceStateMachines(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    for (size_t i = 0; i < machines.size(); ) {
        auto& sm = machines[i];

        if (TryTransition(sm, call)) {
            sm.AddEvidence(callIndex);
            sm.currentState++;
            sm.lastInstr = static_cast<uint64_t>(call.instructionNum);

            const auto& info = GetRule(sm.ruleId);
            if (sm.currentState >= info.totalSteps) {
                CompleteMachine(sm);
                // Remove completed machine (swap with last for O(1))
                machines[i] = machines.back();
                machines.pop_back();
                continue;
            }
        }
        ++i;
    }
}

// ============================================================================
// Impl — Inline Rules (single-call and flag-based detections)
// ============================================================================

void BehaviorMonitor::Impl::CheckInlineRules(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    if (!call.funcName) return;

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);
    const auto tid = call.threadId;

    // ========================================================================
    // CreateProcess-based rules: check once for all process-creation patterns
    // ========================================================================
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        // ---- Rule 18: Scheduled task via schtasks ----
        // The dispatcher tags schtasks-related CreateProcess with
        // ServiceManipulation (service/task creation behavior).
        if (HasFlag(call.behaviorFlags, BehaviorFlag::ServiceManipulation)) {
            EmitAlert(18, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::ServiceManipulation);
        }

        // ---- Rule 26: Shadow copy delete via vssadmin / wmic ----
        // The dispatcher flags vssadmin/wmic shadow-delete commands with
        // SuspiciousAPI. We combine with FileDropped to reduce false positives.
        if (HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            // Strong signal: SuspiciousAPI + a file-manipulation indicator
            if (HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped) ||
                HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion)) {
                EmitAlert(26, { callIndex }, instrN, tid);
            }
        }

        // ---- Rule 50: PowerShell cradle ----
        // The dispatcher flags powershell.exe -enc / -e / IEX / DownloadString
        // with PowershellExecution.
        if (HasFlag(call.behaviorFlags, BehaviorFlag::PowershellExecution)) {
            EmitAlert(50, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::PowershellExecution);
        }
    }

    // ========================================================================
    // CreateFile-based rules: check once for all file-creation patterns
    // ========================================================================
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        uint32_t access = static_cast<uint32_t>(call.args[1]);

        // ---- Rule 20: DLL search order hijacking ----
        // Creating a DLL file flagged as potential injection vector
        if (HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped) &&
            HasFlag(call.behaviorFlags, BehaviorFlag::DLLInjection)) {
            EmitAlert(20, { callIndex }, instrN, tid);
        }

        // ---- Rule 27: Direct volume / physical drive access ----
        // Writing to \\.\PhysicalDrive or \\.\C: — the dispatcher flags
        // these low-level device paths with SuspiciousAPI.
        if ((access & kGenericWrite) &&
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            EmitAlert(27, { callIndex }, instrN, tid);
        }

        // ---- Rule 28: Ransom note drop ----
        // FileDropped + SuspiciousAPI on common ransom note patterns
        // (README.txt, DECRYPT_*.txt, HOW_TO_*.txt, etc.)
        if (HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped) &&
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            // Only fire if not already covered by rule 27 (device access)
            if (!(access & kGenericWrite)) {
                EmitAlert(28, { callIndex }, instrN, tid);
            }
        }

        // ---- Rule 48: MBR/VBR overwrite ----
        // Direct physical drive write access — critical severity.
        // Differentiated from rule 27 by the GENERIC_WRITE requirement
        // and the specific MBR/VBR context from the dispatcher.
        if ((access & kGenericWrite) &&
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            // If the access also indicates a physical device (not just a volume),
            // the dispatcher sets both SuspiciousAPI and MemoryManipulation.
            if (HasFlag(call.behaviorFlags, BehaviorFlag::MemoryManipulation)) {
                EmitAlert(48, { callIndex }, instrN, tid);
                accumulatedFlags = CombineFlags(accumulatedFlags,
                    BehaviorFlag::SuspiciousAPI);
            }
        }
    }

    // ========================================================================
    // COM-based rules
    // ========================================================================
    if (FuncIs(call, "CoCreateInstance")) {
        // ---- Rule 21: WMI event subscription ----
        if (HasFlag(call.behaviorFlags, BehaviorFlag::WMIExecution)) {
            EmitAlert(21, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::WMIExecution);
        }
    }

    // ========================================================================
    // Process handle rules
    // ========================================================================
    if (FuncIs(call, "OpenProcess")) {
        // ---- Rule 22: LSASS process access ----
        // The dispatcher flags lsass-targeting OpenProcess with CredentialAccess.
        if (HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess)) {
            uint32_t access = static_cast<uint32_t>(call.args[0]);
            // Any access that enables memory reading: VM_READ, VM_OPERATION,
            // QUERY_INFORMATION, or ALL_ACCESS
            if (access == kProcessAllAccess ||
                (access & (kProcessVMOperation | 0x0410))) {
                EmitAlert(22, { callIndex }, instrN, tid);
                accumulatedFlags = CombineFlags(accumulatedFlags,
                    BehaviorFlag::CredentialAccess);
            }
        }
    }

    // ========================================================================
    // Registry-based rules
    // ========================================================================
    if (FuncIsAny4(call, "RegOpenKeyExA", "RegOpenKeyExW",
                   "NtOpenKey", "NtCreateFile")) {
        // ---- Rule 23: SAM hive access ----
        if (HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess)) {
            EmitAlert(23, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::CredentialAccess);
        }
    }

    // ========================================================================
    // Anti-analysis rules
    // ========================================================================

    // ---- Rule 30: Anti-debug ----
    if (!antiDebugFired) {
        bool isAntiDebug = false;
        if (FuncIsAny3(call, "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                       "NtQueryInformationProcess")) {
            // NtQueryInformationProcess: check if querying ProcessDebugPort (class 7)
            // or ProcessDebugFlags (class 31) or ProcessDebugObjectHandle (class 30)
            if (FuncIs(call, "NtQueryInformationProcess")) {
                uint32_t infoClass = static_cast<uint32_t>(call.args[1]);
                isAntiDebug = (infoClass == 7 || infoClass == 30 || infoClass == 31);
            } else {
                isAntiDebug = true;
            }
        }
        if (call.category == APICategory::AntiDebug) {
            isAntiDebug = true;
        }
        if (isAntiDebug) {
            antiDebugFired = true;
            EmitAlert(30, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::AntiAnalysis);
        }
    }

    // ---- Rule 31: Anti-VM ----
    if (!antiVMFired && call.category == APICategory::AntiVM) {
        antiVMFired = true;
        EmitAlert(31, { callIndex }, instrN, tid);
        accumulatedFlags = CombineFlags(accumulatedFlags,
            BehaviorFlag::AntiAnalysis);
    }

    // ---- Rule 32: Timestomping ----
    if (FuncIsAny(call, "SetFileTime", "NtSetInformationFile")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion)) {
            EmitAlert(32, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::DefenseEvasion);
        }
    }

    // ========================================================================
    // Keylogger hook detection
    // ========================================================================

    // ---- Rule 45: Keylogger (hook-based detection) ----
    if (FuncIsAny(call, "SetWindowsHookExA", "SetWindowsHookExW")) {
        uint32_t hookId = static_cast<uint32_t>(call.args[0]);
        if (hookId == kWHKeyboard || hookId == kWHKeyboardLL) {
            EmitAlert(45, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::Keylogging);
        }
    }
}

// ============================================================================
// Impl — Counter-based Detection
// ============================================================================

void BehaviorMonitor::Impl::UpdateCounters(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    if (!call.funcName) return;

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);

    // ---- Ransomware counters (Rule 25) ----
    if (FuncIsAny4(call, "FindFirstFileA", "FindFirstFileW",
                   "FindNextFileA", "FindNextFileW") ||
        FuncIsAny(call, "FindFirstFileExA", "FindFirstFileExW")) {
        findFileCount.Record(callIndex, instrN);
    }

    if (FuncIsAny4(call, "CryptEncrypt", "BCryptEncrypt",
                   "CryptHashData", "BCryptFinishHash")) {
        cryptoAPICount.Record(callIndex, instrN);
    }

    if (FuncIsAny(call, "ReadFile", "WriteFile")) {
        readWriteFileCount.Record(callIndex, instrN);
    }

    // ---- Mass file rename (Rule 29) ----
    if (FuncIsAny4(call, "MoveFileA", "MoveFileW",
                   "MoveFileExA", "MoveFileExW") ||
        FuncIsAny(call, "NtSetInformationFile", "SetFileInformationByHandle")) {
        // For NtSetInformationFile, we'd need to check the info class
        // is FileRenameInformation. The behaviorFlags help here.
        if (call.funcName[0] == 'M' || call.funcName[0] == 'm' ||
            HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped)) {
            fileRenameCount.Record(callIndex, instrN);
        }
    }

    // ---- DNS tunneling (Rule 36) ----
    if (FuncIsAny4(call, "DnsQuery_A", "DnsQuery_W",
                   "DnsQueryEx", "getaddrinfo")) {
        dnsQueryCount.Record(callIndex, instrN);
    }

    // ---- Keylogger GetAsyncKeyState loop (Rule 45 variant) ----
    if (FuncIs(call, "GetAsyncKeyState") || FuncIs(call, "GetKeyState")) {
        keyStateCount.Record(callIndex, instrN);
    }

    // ---- System info gathering (Rule 42) ----
    if (FuncIsAny(call, "GetComputerNameA", "GetComputerNameW") ||
        FuncIs(call, "GetComputerNameExW")) {
        try { sysInfo.Set("computerName", callIndex, instrN); } catch (...) {}
    }
    if (FuncIsAny3(call, "GetUserNameA", "GetUserNameW", "GetUserNameExW")) {
        try { sysInfo.Set("userName", callIndex, instrN); } catch (...) {}
    }
    if (FuncIsAny3(call, "GetVersionExA", "GetVersionExW", "RtlGetVersion")) {
        try { sysInfo.Set("versionEx", callIndex, instrN); } catch (...) {}
    }
    if (FuncIsAny3(call, "GetSystemInfo", "GetNativeSystemInfo",
                   "NtQuerySystemInformation")) {
        try { sysInfo.Set("systemInfo", callIndex, instrN); } catch (...) {}
    }

    // ---- Network enumeration (Rule 43) ----
    if (FuncIsAny4(call, "GetAdaptersInfo", "GetAdaptersAddresses",
                   "GetIpForwardTable", "NetShareEnum") ||
        FuncIsAny(call, "GetIpAddrTable", "NetServerEnum")) {
        netEnumCount.Record(callIndex, instrN);
    }

    // ---- File system recon (Rule 44) ----
    if (FuncIsAny4(call, "GetDriveTypeA", "GetDriveTypeW",
                   "GetDiskFreeSpaceA", "GetDiskFreeSpaceW") ||
        FuncIsAny(call, "GetDiskFreeSpaceExA", "GetDiskFreeSpaceExW") ||
        FuncIsAny(call, "GetLogicalDrives", "GetLogicalDriveStringsW")) {
        driveEnumCount.Record(callIndex, instrN);
    }
}

void BehaviorMonitor::Impl::CheckCounterThresholds(uint64_t instrCount) noexcept {
    // ---- Rule 25: Ransomware composite threshold ----
    if (!findFileCount.fired) {
        bool fileEnumHigh   = findFileCount.count >= 20;
        bool cryptoHigh     = cryptoAPICount.count >= 5;
        bool rwHigh         = readWriteFileCount.count >= 10;
        bool inWindow       = true;

        if (findFileCount.count > 0 && readWriteFileCount.count > 0) {
            uint64_t span = readWriteFileCount.lastInstr - findFileCount.firstInstr;
            inWindow = span <= 2'000'000;
        }

        if (fileEnumHigh && cryptoHigh && rwHigh && inWindow) {
            findFileCount.fired = true;
            auto ev = findFileCount.GetEvidence();
            auto cryptoEv = cryptoAPICount.GetEvidence();
            ev.insert(ev.end(), cryptoEv.begin(), cryptoEv.end());
            if (ev.size() > kMaxEvidencePerAlert)
                ev.resize(kMaxEvidencePerAlert);
            EmitAlert(25, ev, instrCount, 0);
        }
    }

    // ---- Rule 29: Mass file rename ----
    if (!fileRenameCount.fired && fileRenameCount.count >= 10) {
        uint64_t span = fileRenameCount.lastInstr - fileRenameCount.firstInstr;
        if (span <= 500'000) {
            fileRenameCount.fired = true;
            EmitAlert(29, fileRenameCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 36: DNS tunneling ----
    if (!dnsQueryCount.fired && dnsQueryCount.count >= 15) {
        uint64_t span = dnsQueryCount.lastInstr - dnsQueryCount.firstInstr;
        if (span <= 300'000) {
            dnsQueryCount.fired = true;
            EmitAlert(36, dnsQueryCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 42: System info gathering ----
    if (!sysInfo.fired && sysInfo.count >= 3) {
        uint64_t span = sysInfo.lastInstr - sysInfo.firstInstr;
        if (span <= 200'000) {
            sysInfo.fired = true;
            EmitAlert(42, sysInfo.evidence, instrCount, 0);
        }
    }

    // ---- Rule 43: Network enumeration ----
    if (!netEnumCount.fired && netEnumCount.count >= 2) {
        uint64_t span = netEnumCount.lastInstr - netEnumCount.firstInstr;
        if (span <= 300'000) {
            netEnumCount.fired = true;
            EmitAlert(43, netEnumCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 44: File system recon ----
    if (!driveEnumCount.fired && driveEnumCount.count >= 3) {
        uint64_t span = driveEnumCount.lastInstr - driveEnumCount.firstInstr;
        if (span <= 300'000) {
            driveEnumCount.fired = true;
            EmitAlert(44, driveEnumCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 45 variant: GetAsyncKeyState loop ----
    if (!keyStateCount.fired && keyStateCount.count >= 50) {
        uint64_t span = keyStateCount.lastInstr - keyStateCount.firstInstr;
        if (span <= 500'000) {
            keyStateCount.fired = true;
            EmitAlert(45, keyStateCount.GetEvidence(), instrCount, 0);
            accumulatedFlags = CombineFlags(accumulatedFlags, BehaviorFlag::Keylogging);
        }
    }
}

// ============================================================================
// Impl — Allocation Tracking (for shellcode rules 12-16)
// ============================================================================

void BehaviorMonitor::Impl::TrackAllocations(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    if (!call.funcName || !call.succeeded) return;

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);

    // Track VirtualAlloc / NtAllocateVirtualMemory for shellcode detection
    if (FuncIsAny(call, "VirtualAlloc", "NtAllocateVirtualMemory")) {
        uint32_t prot = static_cast<uint32_t>(call.args[3]);
        GuestAddress base = call.returnValue;
        GuestSize size = static_cast<GuestSize>(call.args[1]);

        if (base != 0 && trackedAllocs.size() < kMaxRWXTracked) {
            TrackedAlloc ta;
            ta.base       = base;
            ta.size       = size;
            ta.instrCount = instrN;
            ta.threadId   = call.threadId;
            ta.callIndex  = callIndex;
            ta.isRWX      = ProtIsRWX(prot);

            if (ta.isRWX) {
                // Rule 12: Reflective DLL — large RWX alloc (>= 4KB = PE-sized)
                // Rule 13: Classic shellcode — any RWX alloc
                trackedAllocs.push_back(ta);
            } else if (ProtIsRW(prot)) {
                // Rule 14: Staged shellcode — RW alloc (execute comes later)
                ta.isRWX = false;
                trackedAllocs.push_back(ta);
            }
        }
    }

    // Track VirtualAllocEx for remote allocation (injection rules handle this
    // via state machines, but we still record for cross-thread tracking)
    if (FuncIs(call, "VirtualAllocEx") && call.returnValue != 0) {
        try {
            allocOrigins[call.returnValue] = { call.threadId, instrN };
        } catch (...) {}
    }
}

// ============================================================================
// Impl — Cross-Thread Resource Tracking
// ============================================================================

void BehaviorMonitor::Impl::TrackResources(const APICallDetail& call) noexcept {
    if (!call.funcName || !call.succeeded) return;
    if (handleOrigins.size() >= kMaxResourceEntries) return;

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);

    try {
        // Track handle-producing API calls
        if (FuncIsAny(call, "OpenProcess", "OpenThread") ||
            FuncIsAny(call, "CreateFileA", "CreateFileW") ||
            FuncIsAny(call, "NtCreateSection", "NtOpenSection") ||
            FuncIsAny(call, "OpenSCManagerA", "OpenSCManagerW") ||
            FuncIsAny(call, "CreateNamedPipeA", "CreateNamedPipeW")) {
            if (call.returnValue != 0 && call.returnValue != static_cast<uint64_t>(-1)) {
                handleOrigins[call.returnValue] = { call.threadId, instrN };
            }
        }

        // Track memory allocations
        if (FuncIsAny(call, "VirtualAlloc", "VirtualAllocEx") ||
            FuncIs(call, "NtAllocateVirtualMemory")) {
            if (call.returnValue != 0) {
                allocOrigins[call.returnValue] = { call.threadId, instrN };
            }
        }
    } catch (...) {
        // Allocation failure in map — silently ignore
    }
}

// ============================================================================
// Impl — Central API Call Processing
// ============================================================================

void BehaviorMonitor::Impl::ProcessAPICall(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    // Accumulate behavior flags from each call
    accumulatedFlags = CombineFlags(accumulatedFlags, call.behaviorFlags);

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);

    // 1. Track resources for cross-thread correlation
    TrackResources(call);

    // 2. Track allocations for shellcode detection
    TrackAllocations(call, callIndex);

    // 3. Advance existing state machines
    AdvanceStateMachines(call, callIndex);

    // 4. Start new state machines if this call matches any rule's first step
    StartNewMachines(call, callIndex);

    // 5. Check inline (single-call) detection rules
    CheckInlineRules(call, callIndex);

    // 6. Update counter-based accumulators
    UpdateCounters(call, callIndex);

    // 7. Check counter thresholds
    CheckCounterThresholds(instrN);

    // 8. Expire old state machines
    ExpireMachines(instrN);
}

// ============================================================================
// Impl — Memory Event Handling
// ============================================================================
//
// OnMemoryEvent is called for tracked memory accesses. It feeds:
//   - Egg hunter detection (Rule 15)
//   - Shellcode write tracking for RWX/RW allocations
//   - Stack write tracking for stack-based shellcode (Rule 16)

// ============================================================================
// Public Interface — Constructor / Destructor
// ============================================================================

BehaviorMonitor::BehaviorMonitor(const EmulationConfig& config) noexcept {
    try {
        m_impl = std::make_unique<Impl>();
        m_impl->enabled = config.enableBehaviorMonitor;
        m_impl->stackBase = 0x0000000080000000ULL;  // From WinConst::kStackBase64
        m_impl->stackSize = config.stackSize;
        m_impl->alerts.reserve(256);
        m_impl->machines.reserve(128);
        m_impl->trackedAllocs.reserve(64);
    } catch (...) {
        // If allocation fails, m_impl stays null; all methods become no-ops
    }
}

BehaviorMonitor::~BehaviorMonitor() noexcept = default;
BehaviorMonitor::BehaviorMonitor(BehaviorMonitor&&) noexcept = default;
BehaviorMonitor& BehaviorMonitor::operator=(BehaviorMonitor&&) noexcept = default;

// ============================================================================
// Public Interface — Event Feeds
// ============================================================================

void BehaviorMonitor::OnAPICall(
    const APICallDetail& call, uint32_t callIndex) noexcept
{
    if (!m_impl || !m_impl->enabled) return;
    m_impl->ProcessAPICall(call, callIndex);
}

void BehaviorMonitor::OnMemoryEvent(const MemoryAccessRecord& record) noexcept {
    if (!m_impl || !m_impl->enabled) return;

    auto& impl = *m_impl;

    // ---- Rule 15: Egg hunter detection ----
    // A small code region performing many reads across different pages
    // is characteristic of an egg hunter scanning for a payload marker.
    if (record.type == MemoryAccessRecord::Type::Read) {
        GuestAddress srcPage = PageBase(record.rip);
        GuestAddress dstPage = PageBase(record.address);

        if (impl.eggHunter.codeBase == 0) {
            impl.eggHunter.codeBase    = srcPage;
            impl.eggHunter.firstInstr  = record.instructionCount;
        }

        // If reads come from same small code region but target many pages
        if (srcPage == impl.eggHunter.codeBase ||
            (srcPage >= impl.eggHunter.codeBase &&
             srcPage < impl.eggHunter.codeBase + 2 * kPageSize)) {
            impl.eggHunter.lastInstr = record.instructionCount;
            try {
                auto [it, inserted] = impl.eggHunter.scannedPages.emplace(dstPage, true);
                if (inserted) {
                    impl.eggHunter.uniquePageCount++;
                    impl.eggHunter.scanCount++;
                }
            } catch (...) {}

            // Fire if scanning many distinct pages from a small code region
            if (!impl.eggHunter.fired && impl.eggHunter.uniquePageCount >= 32) {
                uint64_t span = impl.eggHunter.lastInstr - impl.eggHunter.firstInstr;
                if (span <= 500'000) {
                    impl.eggHunter.fired = true;
                    impl.EmitAlert(15, {}, record.instructionCount, 0);
                }
            }
        } else {
            // Different code region — reset tracker
            impl.eggHunter.codeBase       = srcPage;
            impl.eggHunter.firstInstr     = record.instructionCount;
            impl.eggHunter.scanCount      = 0;
            impl.eggHunter.uniquePageCount = 0;
            impl.eggHunter.scannedPages.clear();
        }
    }

    // Track writes to allocated regions (for shellcode detection)
    if (record.type == MemoryAccessRecord::Type::Write) {
        for (auto& ta : impl.trackedAllocs) {
            if (record.address >= ta.base &&
                record.address < ta.base + ta.size) {
                ta.wasWritten = true;
                break;
            }
        }
    }

    // ---- Rule 16: Stack-based shellcode (write tracking) ----
    // Execution from stack is detected in OnWXTransition
}

void BehaviorMonitor::OnWXTransition(
    GuestAddress page, uint64_t instrCount) noexcept
{
    if (!m_impl || !m_impl->enabled) return;

    auto& impl = *m_impl;

    // ---- Rule 16: Stack-based shellcode ----
    // If execution occurs from the stack region, it's stack-based shellcode
    if (page >= impl.stackBase &&
        page < impl.stackBase + impl.stackSize) {
        const auto& r = GetRule(16);
        impl.EmitAlertDirect(r.category, r.severity, r.confidence,
                             r.description, r.mitreId,
                             {}, instrCount, 0);
        impl.accumulatedFlags = CombineFlags(
            impl.accumulatedFlags, BehaviorFlag::CodeInjection);
        return;
    }

    // Check tracked allocations for W→X transitions
    for (auto& ta : impl.trackedAllocs) {
        if (page >= ta.base && page < ta.base + ta.size) {
            ta.executed = true;

            if (ta.isRWX && ta.wasWritten) {
                // ---- Rule 13: Classic shellcode (RWX alloc + write + execute) ----
                impl.EmitAlert(13, { ta.callIndex }, instrCount, ta.threadId);
                impl.accumulatedFlags = CombineFlags(
                    impl.accumulatedFlags, BehaviorFlag::CodeInjection);

                // ---- Rule 12: Reflective DLL (large RWX alloc) ----
                if (ta.size >= 0x1000) {
                    impl.EmitAlert(12, { ta.callIndex }, instrCount, ta.threadId);
                    impl.accumulatedFlags = CombineFlags(
                        impl.accumulatedFlags, BehaviorFlag::DLLInjection);
                }
            }

            if (!ta.isRWX && ta.protChanged) {
                // ---- Rule 14: Staged shellcode (RW → RX → execute) ----
                // The state machine for rule 14 tracks VirtualAlloc(RW) →
                // VirtualProtect(RX). The W→X transition completes it.
                impl.EmitAlert(14, { ta.callIndex }, instrCount, ta.threadId);
                impl.accumulatedFlags = CombineFlags(
                    impl.accumulatedFlags, BehaviorFlag::CodeInjection);
            }
            break;
        }
    }
}

void BehaviorMonitor::OnProtectionChange(
    GuestAddress base, GuestSize size,
    MemProt oldProt, MemProt newProt) noexcept
{
    if (!m_impl || !m_impl->enabled) return;

    auto& impl = *m_impl;

    // Update tracked allocations: mark RW→RX transition
    bool oldHasExec = HasProt(oldProt, MemProt::Execute);
    bool newHasExec = HasProt(newProt, MemProt::Execute);
    bool oldHasWrite = HasProt(oldProt, MemProt::Write);

    if (!oldHasExec && newHasExec && oldHasWrite) {
        // RW → RX/RWX transition — mark relevant allocations
        for (auto& ta : impl.trackedAllocs) {
            if (base >= ta.base && base < ta.base + ta.size) {
                ta.protChanged = true;
                break;
            }
        }
    }

    // Generic flag: any RW→X transition is suspicious
    if (!oldHasExec && newHasExec) {
        impl.accumulatedFlags = CombineFlags(
            impl.accumulatedFlags, BehaviorFlag::MemoryManipulation);
    }
}

// ============================================================================
// Public Interface — Alert Management
// ============================================================================

void BehaviorMonitor::SetAlertCallback(BehaviorAlertCallback cb) noexcept {
    if (!m_impl) return;
    try {
        m_impl->alertCallback = std::move(cb);
    } catch (...) {}
}

const std::vector<BehaviorAlert>&
BehaviorMonitor::GetAlerts() const noexcept {
    static const std::vector<BehaviorAlert> kEmpty;
    if (!m_impl) return kEmpty;
    return m_impl->alerts;
}

uint32_t BehaviorMonitor::GetAlertCount() const noexcept {
    if (!m_impl) return 0;
    return static_cast<uint32_t>(m_impl->alerts.size());
}

AlertSeverity BehaviorMonitor::GetMaxSeverity() const noexcept {
    if (!m_impl) return AlertSeverity::Info;
    return m_impl->maxSeverity;
}

std::vector<const BehaviorAlert*>
BehaviorMonitor::GetAlertsByCategory(BehaviorCategory cat) const noexcept {
    std::vector<const BehaviorAlert*> result;
    if (!m_impl) return result;
    try {
        for (const auto& alert : m_impl->alerts) {
            if (alert.category == cat)
                result.push_back(&alert);
        }
    } catch (...) {}
    return result;
}

// ============================================================================
// Public Interface — Behavior Flags & State
// ============================================================================

BehaviorFlag BehaviorMonitor::GetAccumulatedFlags() const noexcept {
    if (!m_impl) return BehaviorFlag::None;
    return m_impl->accumulatedFlags;
}

uint32_t BehaviorMonitor::GetActiveStateMachineCount() const noexcept {
    if (!m_impl) return 0;
    return static_cast<uint32_t>(m_impl->machines.size());
}

// ============================================================================
// Public Interface — Reset
// ============================================================================

void BehaviorMonitor::Reset() noexcept {
    if (!m_impl) return;

    auto& impl = *m_impl;

    impl.alerts.clear();
    impl.maxSeverity = AlertSeverity::Info;
    impl.accumulatedFlags = BehaviorFlag::None;
    impl.machines.clear();
    impl.handleOrigins.clear();
    impl.allocOrigins.clear();
    impl.trackedAllocs.clear();

    impl.findFileCount.Reset();
    impl.cryptoAPICount.Reset();
    impl.readWriteFileCount.Reset();
    impl.fileRenameCount.Reset();
    impl.dnsQueryCount.Reset();
    impl.keyStateCount.Reset();
    impl.driveEnumCount.Reset();
    impl.netEnumCount.Reset();
    impl.sysInfo.Reset();

    impl.antiDebugFired = false;
    impl.antiVMFired    = false;

    impl.eggHunter = {};

    // Callback is preserved across reset (intentional)
}

} // namespace Phantom
