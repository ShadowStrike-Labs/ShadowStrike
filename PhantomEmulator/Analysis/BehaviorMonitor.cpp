/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BehaviorMonitor.cpp — Behavioral analysis engine implementation
 *
 * Implements 150 behavioral detection rules as state machines, covering:
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
#include <initializer_list>
#include <limits>
#include <new>
#include <span>
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
constexpr uint32_t kRuleCount              = 150;

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

void IncrementSaturating(uint32_t& value) noexcept {
    if (value < (std::numeric_limits<uint32_t>::max)()) {
        ++value;
    }
}

[[nodiscard]] bool AddGuestSize(GuestAddress base, GuestSize size, GuestAddress& end) noexcept {
    if (size > (std::numeric_limits<GuestAddress>::max)() - base) {
        return false;
    }
    end = base + size;
    return true;
}

[[nodiscard]] bool RangesOverlap(
    GuestAddress firstBase,
    GuestSize firstSize,
    GuestAddress secondBase,
    GuestSize secondSize) noexcept {
    if (firstSize == 0 || secondSize == 0) return false;
    GuestAddress firstEnd = 0;
    GuestAddress secondEnd = 0;
    if (!AddGuestSize(firstBase, firstSize, firstEnd) ||
        !AddGuestSize(secondBase, secondSize, secondEnd)) {
        return false;
    }
    return firstBase < secondEnd && secondBase < firstEnd;
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

// Indexed by ruleId - 1. All 150 rules.
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
    // --- Fileless Attacks (Rules 51-65) ---
    /* 51 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.90f,
               "PowerShell encoded command: CreateProcess with powershell -enc/-encodedcommand",
               "T1059.001", 0, 0, false },
    /* 52 */ { BehaviorCategory::Execution, AlertSeverity::Critical, 0.92f,
               "PowerShell download cradle: IEX + DownloadString execution",
               "T1059.001", 0, 0, false },
    /* 53 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.88f,
               "PowerShell reflective Assembly::Load execution",
               "T1620", 0, 0, false },
    /* 54 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.82f,
               "Script host network activity: WScript/CScript followed by connect/send",
               "T1059.005", 2, 300'000, false },
    /* 55 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.86f,
               "MSHTA inline script execution via javascript:/vbscript:",
               "T1218.005", 0, 0, false },
    /* 56 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Critical, 0.90f,
               "Regsvr32 Squiblydoo: regsvr32 scrobj.dll proxy execution",
               "T1218.010", 0, 0, false },
    /* 57 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.82f,
               "Rundll32 unusual DLL entry execution",
               "T1218.011", 0, 0, false },
    /* 58 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.86f,
               "WMIC process call create execution",
               "T1047", 0, 0, false },
    /* 59 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.84f,
               "WMIC XSL script execution via /format",
               "T1220", 0, 0, false },
    /* 60 */ { BehaviorCategory::Downloader, AlertSeverity::High, 0.82f,
               "BitsAdmin transfer download",
               "T1197", 0, 0, false },
    /* 61 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.84f,
               "Certutil download/decode via urlcache or -decode",
               "T1140", 0, 0, false },
    /* 62 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.82f,
               "InstallUtil proxy execution bypass",
               "T1218.004", 0, 0, false },
    /* 63 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.84f,
               "MSBuild inline task execution",
               "T1127.001", 0, 0, false },
    /* 64 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::High, 0.82f,
               "CMSTP proxy execution and UAC bypass",
               "T1218.003", 0, 0, false },
    /* 65 */ { BehaviorCategory::Execution, AlertSeverity::Medium, 0.76f,
               "Forfiles command execution proxy",
               "T1202", 0, 0, false },
    // --- Living-off-the-Land (Rules 66-80) ---
    /* 66 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.86f,
               "Schtasks persistent payload creation",
               "T1053.005", 0, 0, false },
    /* 67 */ { BehaviorCategory::Persistence, AlertSeverity::Medium, 0.76f,
               "At.exe job creation",
               "T1053.002", 0, 0, false },
    /* 68 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.88f,
               "Service creation via sc.exe binPath",
               "T1543.003", 0, 0, false },
    /* 69 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.86f,
               "Netsh firewall configuration modification",
               "T1562.004", 0, 0, false },
    /* 70 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.82f,
               "Netsh helper DLL registration",
               "T1546.007", 0, 0, false },
    /* 71 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.90f,
               "Reg.exe Run key persistence",
               "T1547.001", 0, 0, false },
    /* 72 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.90f,
               "Event log clearing via wevtutil",
               "T1070.001", 0, 0, false },
    /* 73 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.90f,
               "Bcdedit disable recovery / boot failover",
               "T1490", 0, 0, false },
    /* 74 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.95f,
               "Vssadmin delete shadows",
               "T1490", 0, 0, false },
    /* 75 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.72f,
               "Icacls permission grant / ACL weakening",
               "T1222.001", 0, 0, false },
    /* 76 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.72f,
               "Takeown ownership acquisition",
               "T1222.001", 0, 0, false },
    /* 77 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.78f,
               "Diskshadow script execution",
               "T1218", 0, 0, false },
    /* 78 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.82f,
               "Msiexec remote package installation",
               "T1218.007", 0, 0, false },
    /* 79 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.86f,
               "Mavinject DLL injection",
               "T1218.013", 0, 0, false },
    /* 80 */ { BehaviorCategory::Execution, AlertSeverity::Medium, 0.76f,
               "Pcalua proxy execution",
               "T1202", 0, 0, false },
    // --- WMI & Lateral Movement (Rules 81-95) ---
    /* 81 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.90f,
               "WMI event subscription chain: WbemLocator->ConnectServer->ExecMethod",
               "T1546.003", 3, 400'000, false },
    /* 82 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.86f,
               "WMI process creation via Win32_Process.Create",
               "T1047", 2, 300'000, false },
    /* 83 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.84f,
               "Remote WMI over DCOM",
               "T1021.003", 2, 300'000, false },
    /* 84 */ { BehaviorCategory::Persistence, AlertSeverity::High, 0.86f,
               "COM object hijack: CLSID registry change followed by activation",
               "T1546.015", 2, 500'000, false },
    /* 85 */ { BehaviorCategory::Execution, AlertSeverity::High, 0.82f,
               "COM script engine instantiation",
               "T1059.007", 0, 0, false },
    /* 86 */ { BehaviorCategory::LateralMovement, AlertSeverity::Critical, 0.92f,
               "PsExec-style remote service execution",
               "T1021.002", 3, 400'000, false },
    /* 87 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.84f,
               "WinRM remote execution chain",
               "T1021.006", 2, 300'000, false },
    /* 88 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.82f,
               "DCOM lateral movement via MMC20 activation",
               "T1021.003", 2, 300'000, false },
    /* 89 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.82f,
               "SMB named pipe lateral movement",
               "T1021.002", 2, 300'000, false },
    /* 90 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.82f,
               "Pass-the-hash authentication replay",
               "T1550.002", 2, 300'000, false },
    /* 91 */ { BehaviorCategory::LateralMovement, AlertSeverity::High, 0.82f,
               "Pass-the-ticket Kerberos replay",
               "T1550.003", 2, 300'000, false },
    /* 92 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.82f,
               "Kerberoasting request and ticket extraction",
               "T1558.003", 2, 300'000, false },
    /* 93 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.82f,
               "AS-REP roasting without preauthentication",
               "T1558.004", 2, 300'000, false },
    /* 94 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::Critical, 0.95f,
               "Golden ticket creation and use",
               "T1558.001", 3, 500'000, false },
    /* 95 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Critical, 0.90f,
               "DCSync replication request",
               "T1003.006", 2, 300'000, false },
    // --- Advanced Injection (Rules 96-110) ---
    /* 96 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.90f,
               "KernelCallbackTable hijack: OpenProcess->WriteProcessMemory->SetWindowLong",
               "T1574", 3, 400'000, true },
    /* 97 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.86f,
               "PROPagate injection via SetProp callback chain",
               "T1055", 3, 400'000, false },
    /* 98 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.90f,
               "Ghostwriting remote injection",
               "T1055", 3, 400'000, true },
    /* 99 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.86f,
               "Ctrl-Inject via NtQueueApcThread control handler",
               "T1055.004", 2, 300'000, true },
    /* 100 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.90f,
                "Mockingjay RWX section abuse",
                "T1055", 3, 400'000, false },
    /* 101 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.95f,
                "Process ghosting: file write->section->delete->process create",
                "T1055", 5, 700'000, false },
    /* 102 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.95f,
                "Process herpaderping: file write->section->modify->process create",
                "T1055", 5, 700'000, false },
    /* 103 */ { BehaviorCategory::DLLInjection, AlertSeverity::Critical, 0.90f,
                "Phantom DLL hollowing sequence",
                "T1574.002", 3, 500'000, false },
    /* 104 */ { BehaviorCategory::ProcessInjection, AlertSeverity::Critical, 0.86f,
                "Module stomping: LoadLibrary->VirtualProtect->shellcode copy",
                "T1055.001", 3, 400'000, false },
    /* 105 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.82f,
                "Thread pool work injection",
                "T1055", 3, 300'000, false },
    /* 106 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.82f,
                "Fiber-based execution chain",
                "T1055", 3, 300'000, false },
    /* 107 */ { BehaviorCategory::ProcessInjection, AlertSeverity::High, 0.82f,
                "Callback injection via EnumWindows",
                "T1055", 2, 300'000, true },
    /* 108 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.86f,
                "ETW patching via EtwEventWrite overwrite",
                "T1562.006", 2, 300'000, false },
    /* 109 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.76f,
                "Heaven's Gate 32-bit to 64-bit transition",
                "T1106", 0, 0, false },
    /* 110 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.82f,
                "Direct syscall stub construction / SysWhispers / HellsGate",
                "T1106", 0, 0, false },
    // --- Credential Access (Rules 111-125) ---
    /* 111 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Critical, 0.95f,
                "LSASS credential scraping: OpenProcess->ReadProcessMemory->credential dump",
                "T1003.001", 3, 400'000, false },
    /* 112 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.86f,
                "Credential API enumeration and read",
                "T1555", 2, 200'000, false },
    /* 113 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.82f,
                "Browser credential database access",
                "T1555.003", 0, 0, false },
    /* 114 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.84f,
                "Windows Credential Manager access",
                "T1555", 2, 250'000, false },
    /* 115 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.82f,
                "DPAPI master key extraction",
                "T1555", 2, 300'000, false },
    /* 116 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.90f,
                "SAM hive export via reg save",
                "T1003.002", 0, 0, false },
    /* 117 */ { BehaviorCategory::CredentialAccess, AlertSeverity::High, 0.90f,
                "SECURITY hive export via reg save",
                "T1003.004", 0, 0, false },
    /* 118 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Critical, 0.95f,
                "NTDS.dit extraction via shadow copy",
                "T1003.003", 3, 700'000, false },
    /* 119 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Medium, 0.76f,
                "Certificate store access",
                "T1552.004", 2, 250'000, false },
    /* 120 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::High, 0.86f,
                "Token impersonation chain",
                "T1134.001", 3, 300'000, false },
    /* 121 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::High, 0.86f,
                "Named pipe client impersonation",
                "T1134.001", 3, 300'000, false },
    /* 122 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Medium, 0.72f,
                "Clipboard monitoring loop",
                "T1115", 0, 0, false },
    /* 123 */ { BehaviorCategory::Persistence, AlertSeverity::Medium, 0.74f,
                "Browser extension installation",
                "T1176", 2, 400'000, false },
    /* 124 */ { BehaviorCategory::CredentialAccess, AlertSeverity::Medium, 0.78f,
                "Email collection via MAPI harvest",
                "T1114.001", 2, 300'000, false },
    /* 125 */ { BehaviorCategory::Discovery, AlertSeverity::Low, 0.68f,
                "Network share enumeration",
                "T1135", 0, 0, false },
    // --- Evasion (Rules 126-140) ---
    /* 126 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Critical, 0.95f,
                "AMSI patch: GetProcAddress(AmsiScanBuffer)->WriteMemory(RET)",
                "T1562.001", 2, 250'000, false },
    /* 127 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Critical, 0.92f,
                "ETW blind: patch EtwEventWrite",
                "T1562.006", 2, 250'000, false },
    /* 128 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Critical, 0.90f,
                "ntdll unhooking from disk",
                "T1562.001", 3, 500'000, false },
    /* 129 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.82f,
                "Manual syscall stub construction in writable memory",
                "T1106", 0, 0, false },
    /* 130 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.82f,
                "CFG bypass preparation",
                "T1562", 2, 300'000, false },
    /* 131 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.76f,
                "PEB BeingDebugged anti-debug check",
                "T1497.001", 0, 0, false },
    /* 132 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.76f,
                "Heap flag anti-debug check",
                "T1497.001", 0, 0, false },
    /* 133 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.82f,
                "Hardware breakpoint detection via debug registers",
                "T1497.001", 0, 0, false },
    /* 134 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.82f,
                "TLS callback anti-debug chain",
                "T1622", 2, 300'000, false },
    /* 135 */ { BehaviorCategory::PrivilegeEscalation, AlertSeverity::High, 0.86f,
                "Parent PID spoofing via process attributes",
                "T1134.004", 2, 300'000, false },
    /* 136 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.86f,
                "Argument spoofing via suspended process PEB rewrite",
                "T1564.010", 4, 500'000, false },
    /* 137 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::High, 0.86f,
                "PE header stomping",
                "T1027.002", 2, 250'000, false },
    /* 138 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.72f,
                "Entropy reduction / junk encoding behavior",
                "T1027", 0, 0, false },
    /* 139 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.76f,
                "Execution guardrails based on host identity",
                "T1480.001", 2, 250'000, false },
    /* 140 */ { BehaviorCategory::DefenseEvasion, AlertSeverity::Medium, 0.76f,
                "Time-based evasion before malicious action",
                "T1497.003", 0, 0, false },
    // --- Ransomware & Destructive (Rules 141-150) ---
    /* 141 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.95f,
                "File encryption cascade: enumerate->read->encrypt->write/rename",
                "T1486", 4, 1'500'000, false },
    /* 142 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.90f,
                "Recursive directory encryption",
                "T1486", 3, 1'000'000, false },
    /* 143 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.90f,
                "Recovery partition deletion via diskpart",
                "T1561", 0, 0, false },
    /* 144 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.90f,
                "Boot configuration tampering via bcdedit",
                "T1490", 0, 0, false },
    /* 145 */ { BehaviorCategory::Ransomware, AlertSeverity::High, 0.86f,
                "Backup process termination",
                "T1489", 0, 0, false },
    /* 146 */ { BehaviorCategory::Ransomware, AlertSeverity::High, 0.86f,
                "Database process termination prior to encryption",
                "T1489", 0, 0, false },
    /* 147 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.95f,
                "Network share encryption",
                "T1486", 3, 1'500'000, false },
    /* 148 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.90f,
                "Wiper-style sequential overwrite",
                "T1485", 2, 800'000, false },
    /* 149 */ { BehaviorCategory::FileManipulation, AlertSeverity::Critical, 0.95f,
                "MBR ransomware overwrite",
                "T1561.002", 2, 200'000, false },
    /* 150 */ { BehaviorCategory::Ransomware, AlertSeverity::Critical, 0.95f,
                "Double extortion: encryption activity combined with data exfiltration",
                "T1486/T1041", 0, 0, false },
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
        IncrementSaturating(count);
        if (evidenceCount < kMaxEvidencePerAlert)
            evidence[evidenceCount++] = callIndex;
    }

    void Reset() noexcept {
        count = 0; firstInstr = 0; lastInstr = 0;
        evidenceCount = 0; fired = false;
    }

    [[nodiscard]] std::vector<uint32_t> GetEvidence() const noexcept {
        try {
            return { evidence, evidence + evidenceCount };
        } catch (const std::bad_alloc&) {
            return {};
        }
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
    uint32_t droppedEvents = 0;

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
        std::array<uint32_t, kMaxEvidencePerAlert> evidence{};
        uint8_t evidenceCount = 0;
        bool fired        = false;

        void Set(const char* which, uint32_t callIndex, uint64_t instr) noexcept {
            if (StrEqCI(which, "computerName") && !computerName)
                { computerName = true; IncrementSaturating(count); }
            else if (StrEqCI(which, "userName") && !userName)
                { userName = true; IncrementSaturating(count); }
            else if (StrEqCI(which, "versionEx") && !versionEx)
                { versionEx = true; IncrementSaturating(count); }
            else if (StrEqCI(which, "systemInfo") && !systemInfo)
                { systemInfo = true; IncrementSaturating(count); }
            else return;

            if (count == 1) firstInstr = instr;
            lastInstr = instr;
            if (evidenceCount < kMaxEvidencePerAlert)
                evidence[evidenceCount++] = callIndex;
        }

        void Reset() noexcept {
            computerName = userName = versionEx = systemInfo = false;
            count = 0; firstInstr = lastInstr = 0;
            evidenceCount = 0; fired = false;
        }

        [[nodiscard]] std::vector<uint32_t> GetEvidence() const noexcept {
            try {
                return { evidence.data(), evidence.data() + evidenceCount };
            } catch (const std::bad_alloc&) {
                return {};
            }
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
    void EmitAlert(uint32_t ruleId,
                   std::initializer_list<uint32_t> evidence,
                   uint64_t instrCount, uint16_t threadId) noexcept;
    void EmitAlert(uint32_t ruleId,
                   std::span<const uint32_t> evidence,
                   uint64_t instrCount, uint16_t threadId) noexcept;

    void EmitAlertDirect(BehaviorCategory cat, AlertSeverity sev, float conf,
                         const char* desc, const char* mitre,
                         const std::vector<uint32_t>& evidence,
                         uint64_t instrCount, uint16_t threadId) noexcept;
    void EmitAlertDirect(BehaviorCategory cat, AlertSeverity sev, float conf,
                         const char* desc, const char* mitre,
                         std::initializer_list<uint32_t> evidence,
                         uint64_t instrCount, uint16_t threadId) noexcept;
    void EmitAlertDirect(BehaviorCategory cat, AlertSeverity sev, float conf,
                         const char* desc, const char* mitre,
                         std::span<const uint32_t> evidence,
                         uint64_t instrCount, uint16_t threadId) noexcept;

    void StartMachine(uint32_t ruleId, const APICallDetail& call,
                      uint32_t callIndex, uint64_t handle = 0,
                      uint64_t address = 0) noexcept;

    void RecordDrop() noexcept {
        IncrementSaturating(droppedEvents);
    }
};

// ============================================================================
// Impl — Alert Emission
// ============================================================================

void BehaviorMonitor::Impl::EmitAlert(
    uint32_t ruleId, const std::vector<uint32_t>& evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    EmitAlert(ruleId, std::span<const uint32_t>(evidence.data(), evidence.size()),
              instrCount, threadId);
}

void BehaviorMonitor::Impl::EmitAlert(
    uint32_t ruleId, std::initializer_list<uint32_t> evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    EmitAlert(ruleId, std::span<const uint32_t>(evidence.begin(), evidence.size()),
              instrCount, threadId);
}

void BehaviorMonitor::Impl::EmitAlert(
    uint32_t ruleId, std::span<const uint32_t> evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    if (alerts.size() >= kMaxAlerts) {
        RecordDrop();
        return;
    }
    if (ruleId < 1 || ruleId > kRuleCount) {
        RecordDrop();
        return;
    }

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
    EmitAlertDirect(cat, sev, conf, desc, mitre,
                    std::span<const uint32_t>(evidence.data(), evidence.size()),
                    instrCount, threadId);
}

void BehaviorMonitor::Impl::EmitAlertDirect(
    BehaviorCategory cat, AlertSeverity sev, float conf,
    const char* desc, const char* mitre,
    std::initializer_list<uint32_t> evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    EmitAlertDirect(cat, sev, conf, desc, mitre,
                    std::span<const uint32_t>(evidence.begin(), evidence.size()),
                    instrCount, threadId);
}

void BehaviorMonitor::Impl::EmitAlertDirect(
    BehaviorCategory cat, AlertSeverity sev, float conf,
    const char* desc, const char* mitre,
    std::span<const uint32_t> evidence,
    uint64_t instrCount, uint16_t threadId) noexcept
{
    if (alerts.size() >= kMaxAlerts) {
        RecordDrop();
        return;
    }
    try {
        BehaviorAlert alert{};
        alert.category           = cat;
        alert.severity           = sev;
        alert.confidence         = conf;
        alert.description        = desc ? desc : "";
        alert.mitreId            = mitre ? mitre : "";
        alert.evidenceCallIndices.assign(evidence.begin(), evidence.end());
        alert.instructionCount   = instrCount;
        alert.threadId           = threadId;

        if (static_cast<uint8_t>(sev) > static_cast<uint8_t>(maxSeverity))
            maxSeverity = sev;

        alerts.push_back(std::move(alert));

        if (alertCallback) {
            try {
                alertCallback(alerts.back());
            } catch (...) {
                RecordDrop();
            }
        }
    } catch (const std::bad_alloc&) {
        RecordDrop();
    }
}

// ============================================================================
// Impl — State Machine Lifecycle
// ============================================================================

void BehaviorMonitor::Impl::StartMachine(
    uint32_t ruleId, const APICallDetail& call, uint32_t callIndex,
    uint64_t handle, uint64_t address) noexcept
{
    if (machines.size() >= kMaxStateMachines) {
        RecordDrop();
        return;
    }

    StateMachine sm{};
    sm.ruleId        = ruleId;
    sm.currentState  = 1;
    sm.firstInstr    = static_cast<uint64_t>(call.instructionNum);
    sm.lastInstr     = sm.firstInstr;
    sm.originThread  = call.threadId;
    sm.capturedHandle  = handle;
    sm.capturedAddress = address;
    sm.AddEvidence(callIndex);
    try {
        machines.push_back(sm);
    } catch (const std::bad_alloc&) {
        RecordDrop();
    }
}

void BehaviorMonitor::Impl::CompleteMachine(const StateMachine& sm) noexcept {
    EmitAlert(sm.ruleId, std::span<const uint32_t>(sm.evidence, sm.evidenceCount),
              sm.lastInstr, sm.originThread);
}

void BehaviorMonitor::Impl::ExpireMachines(uint64_t instrCount) noexcept {
    machines.erase(
        std::remove_if(machines.begin(), machines.end(),
            [instrCount](const StateMachine& sm) {
                const auto& info = GetRule(sm.ruleId);
                return instrCount >= sm.firstInstr &&
                       (instrCount - sm.firstInstr) > info.windowSize;
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

    // ---- Rule 54: Script host network activity ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI) ||
            call.category == APICategory::Process) {
            StartMachine(54, call, callIndex, retVal);
        }
    }

    // ---- Rules 81, 83, 88: WMI / DCOM via COM activation ----
    if (FuncIs(call, "CoCreateInstance")) {
        if (call.category == APICategory::COM ||
            HasFlag(call.behaviorFlags, BehaviorFlag::WMIExecution) ||
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(81, call, callIndex, retVal);
            StartMachine(83, call, callIndex, retVal);
            StartMachine(88, call, callIndex, retVal);
        }
    }

    // ---- Rule 82: WMI process creation ----
    if (ContainsCI(call.funcName, "ConnectServer")) {
        StartMachine(82, call, callIndex, retVal);
    }

    // ---- Rule 84: COM object hijack ----
    if (FuncIsAny4(call, "RegSetValueExA", "RegSetValueExW",
                   "RegSetValueA", "RegSetValueW")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::RegistryPersistence) ||
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(84, call, callIndex, call.args[0]);
        }
    }

    // ---- Rule 86: PsExec-style remote service execution ----
    if (FuncIsAny(call, "OpenSCManagerA", "OpenSCManagerW")) {
        if (retVal != 0) {
            StartMachine(86, call, callIndex, retVal);
        }
    }

    // ---- Rule 87: WinRM remote execution ----
    if (ContainsCI(call.funcName, "WSManCreateSession") ||
        FuncIs(call, "WinHttpOpen")) {
        if (retVal != 0 || FuncIs(call, "WinHttpOpen")) {
            StartMachine(87, call, callIndex, retVal);
        }
    }

    // ---- Rule 89: SMB named pipe lateral movement ----
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        if (retVal != 0 && HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(89, call, callIndex, retVal);
        }
    }

    // ---- Rules 90-94: Authentication / Kerberos abuse ----
    if (FuncIsAny(call, "AcquireCredentialsHandleA", "AcquireCredentialsHandleW") ||
        FuncIsAny3(call, "LogonUserA", "LogonUserW", "LogonUserExExW") ||
        FuncIs(call, "LsaCallAuthenticationPackage")) {
        StartMachine(90, call, callIndex, retVal);
        StartMachine(91, call, callIndex, retVal);
        StartMachine(92, call, callIndex, retVal);
        StartMachine(93, call, callIndex, retVal);
        StartMachine(94, call, callIndex, retVal);
    }

    // ---- Rule 95: DCSync / replication abuse ----
    if (ContainsCI(call.funcName, "DRSBind") || ContainsCI(call.funcName, "DsBind")) {
        StartMachine(95, call, callIndex, retVal);
    }

    // ---- Rules 96, 98: OpenProcess for advanced injection ----
    if (FuncIs(call, "OpenProcess")) {
        uint32_t access = static_cast<uint32_t>(call.args[0]);
        uint32_t pid    = static_cast<uint32_t>(call.args[2]);
        if (IsInjectionAccess(access) && pid != 0 && retVal != 0) {
            StartMachine(96, call, callIndex, retVal);
            StartMachine(98, call, callIndex, retVal);
        }
    }

    // ---- Rule 97: PROPagate ----
    if (FuncIsAny3(call, "SetPropA", "SetPropW", "SetProp")) {
        StartMachine(97, call, callIndex, call.args[0], call.args[2]);
    }

    // ---- Rule 99: Ctrl-Inject ----
    if (FuncIsAny(call, "OpenThread", "NtOpenThread")) {
        if (retVal != 0) {
            StartMachine(99, call, callIndex, retVal);
        }
    }

    // ---- Rule 100: Mockingjay ----
    if (FuncIsAny3(call, "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA")) {
        if (retVal != 0) {
            StartMachine(100, call, callIndex, retVal);
        }
    }

    // ---- Rules 101, 102, 148, 149: File-backed destructive execution ----
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        if (retVal != 0 && retVal != static_cast<uint64_t>(-1)) {
            StartMachine(101, call, callIndex, retVal);
            StartMachine(102, call, callIndex, retVal);
            StartMachine(148, call, callIndex, retVal);
            if (HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI) &&
                (static_cast<uint32_t>(call.args[1]) & kGenericWrite)) {
                StartMachine(149, call, callIndex, retVal);
            }
        }
    }

    // ---- Rule 103: Phantom DLL hollowing ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        uint32_t flags = static_cast<uint32_t>(call.args[5]);
        if (flags & kCreateSuspended) {
            StartMachine(103, call, callIndex, retVal);
        }
    }

    // ---- Rule 104: Module stomping ----
    if (FuncIsAny3(call, "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA")) {
        if (retVal != 0) {
            StartMachine(104, call, callIndex, retVal);
        }
    }

    // ---- Rule 105: Thread pool injection ----
    if (ContainsCI(call.funcName, "TpAllocWork")) {
        StartMachine(105, call, callIndex, retVal);
    }

    // ---- Rule 106: Fiber-based execution ----
    if (FuncIsAny(call, "ConvertThreadToFiber", "ConvertThreadToFiberEx")) {
        if (retVal != 0) {
            StartMachine(106, call, callIndex, retVal);
        }
    }

    // ---- Rule 107: Callback injection via EnumWindows ----
    if (FuncIs(call, "VirtualAllocEx") && call.returnValue != 0) {
        StartMachine(107, call, callIndex, call.args[0], call.returnValue);
    }

    // ---- Rule 108: ETW patching ----
    if (FuncIsAny(call, "GetProcAddress", "LdrGetProcedureAddress")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(108, call, callIndex, call.args[0], retVal);
        }
    }

    // ---- Rule 111: LSASS credential scraping ----
    if (FuncIs(call, "OpenProcess")) {
        uint32_t access = static_cast<uint32_t>(call.args[0]);
        if ((access == kProcessAllAccess || (access & kProcessVMOperation)) &&
            HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess)) {
            StartMachine(111, call, callIndex, retVal);
        }
    }

    // ---- Rule 112: CredEnumerate -> CredRead ----
    if (FuncIsAny(call, "CredEnumerateA", "CredEnumerateW")) {
        StartMachine(112, call, callIndex, retVal);
    }

    // ---- Rule 114: Windows Credential Manager ----
    if (FuncIsAny(call, "CredReadA", "CredReadW")) {
        StartMachine(114, call, callIndex, retVal);
    }

    // ---- Rule 115: DPAPI master key extraction ----
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess)) {
            StartMachine(115, call, callIndex, retVal);
        }
    }

    // ---- Rule 118: NTDS.dit extraction ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(118, call, callIndex, retVal);
        }
    }

    // ---- Rule 119: Certificate store access ----
    if (FuncIsAny(call, "CertOpenStore", "PFXImportCertStore")) {
        StartMachine(119, call, callIndex, retVal);
    }

    // ---- Rule 120: Token impersonation chain ----
    if (FuncIsAny3(call, "LogonUserA", "LogonUserW", "LogonUserExExW")) {
        StartMachine(120, call, callIndex, retVal);
    }

    // ---- Rule 121: Named pipe impersonation ----
    if (FuncIsAny(call, "CreateNamedPipeA", "CreateNamedPipeW")) {
        if (retVal != 0) {
            StartMachine(121, call, callIndex, retVal);
        }
    }

    // ---- Rule 123: Browser extension install ----
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped)) {
            StartMachine(123, call, callIndex, retVal);
        }
    }

    // ---- Rule 124: Email MAPI harvest ----
    if (ContainsCI(call.funcName, "MAPILogon") || ContainsCI(call.funcName, "MAPIInitialize")) {
        StartMachine(124, call, callIndex, retVal);
    }

    // ---- Rules 126, 127: AMSI / ETW patch ----
    if (FuncIsAny(call, "GetProcAddress", "LdrGetProcedureAddress")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI)) {
            StartMachine(126, call, callIndex, call.args[0], retVal);
            StartMachine(127, call, callIndex, call.args[0], retVal);
        }
    }

    // ---- Rule 128: ntdll unhooking ----
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        if (retVal != 0) {
            StartMachine(128, call, callIndex, retVal);
        }
    }

    // ---- Rule 130: CFG bypass ----
    if (ContainsCI(call.funcName, "SetProcessValidCallTargets") ||
        ContainsCI(call.funcName, "NtSetInformationVirtualMemory")) {
        StartMachine(130, call, callIndex, retVal);
    }

    // ---- Rule 134: TLS callback anti-debug ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        uint32_t flags = static_cast<uint32_t>(call.args[5]);
        if (flags & kCreateSuspended) {
            StartMachine(134, call, callIndex, retVal);
        }
    }

    // ---- Rule 135: Parent PID spoofing ----
    if (ContainsCI(call.funcName, "InitializeProcThreadAttributeList")) {
        StartMachine(135, call, callIndex, retVal);
    }

    // ---- Rule 136: Argument spoofing ----
    if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                   "CreateProcessInternalW", "NtCreateUserProcess")) {
        uint32_t flags = static_cast<uint32_t>(call.args[5]);
        if (flags & kCreateSuspended) {
            StartMachine(136, call, callIndex, retVal);
        }
    }

    // ---- Rule 137: PE header stomping ----
    if (FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory")) {
        if (call.succeeded) {
            StartMachine(137, call, callIndex, call.args[0], call.args[0]);
        }
    }

    // ---- Rule 139: Execution guardrails ----
    if (FuncIsAny(call, "GetComputerNameA", "GetComputerNameW") ||
        FuncIsAny3(call, "GetUserNameA", "GetUserNameW", "GetUserNameExW")) {
        StartMachine(139, call, callIndex, retVal);
    }

    // ---- Rules 141, 142: Ransomware encryption chains ----
    if (FuncIsAny4(call, "FindFirstFileA", "FindFirstFileW",
                   "FindFirstFileExA", "FindFirstFileExW")) {
        StartMachine(141, call, callIndex, retVal);
        StartMachine(142, call, callIndex, retVal);
    }

    // ---- Rule 147: Network share encryption ----
    if (FuncIsAny(call, "NetShareEnum", "WNetEnumResourceW") ||
        FuncIs(call, "WNetEnumResourceA")) {
        StartMachine(147, call, callIndex, retVal);
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
    if (info.windowSize > 0 &&
        instr >= sm.firstInstr &&
        (instr - sm.firstInstr) > info.windowSize)
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

    // ======================================================================
    // Rule 54: Script host network activity
    //   CreateProcess(done) → connect/send
    // ======================================================================
    case 54:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "connect", "WSAConnect", "send", "WSASend") ||
                FuncIsAny(call, "sendto", "WSASendTo"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 81: WMI event subscription chain
    //   CoCreateInstance(done) → ConnectServer → ExecMethod
    // ======================================================================
    case 81:
        switch (sm.currentState) {
        case 1: if (ContainsCI(call.funcName, "ConnectServer"))
                    matched = true;
                break;
        case 2: if (ContainsCI(call.funcName, "ExecMethod") ||
                    ContainsCI(call.funcName, "PutInstance"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 82: WMI process create
    //   ConnectServer(done) → ExecMethod
    // ======================================================================
    case 82:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "ExecMethod"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 83: Remote WMI via DCOM
    //   CoCreateInstance(done) → ConnectServer / CoSetProxyBlanket
    // ======================================================================
    case 83:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "ConnectServer") ||
                ContainsCI(call.funcName, "CoSetProxyBlanket"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 84: COM object hijack
    //   RegSetValue(done) → CoCreateInstance
    // ======================================================================
    case 84:
        if (sm.currentState == 1) {
            if (FuncIs(call, "CoCreateInstance"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 86: PsExec-style remote service execution
    //   OpenSCManager(done) → CreateService → StartService
    // ======================================================================
    case 86:
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
    // Rule 87: WinRM remote execution
    //   WSManCreateSession/WinHttpOpen(done) → send/request
    // ======================================================================
    case 87:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "WSMan") ||
                FuncIsAny3(call, "WinHttpConnect", "WinHttpSendRequest",
                           "WinHttpReceiveResponse"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 88: DCOM lateral movement
    //   CoCreateInstance(done) → CreateProcess / ShellExecute
    // ======================================================================
    case 88:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                           "ShellExecuteA", "ShellExecuteW") ||
                FuncIsAny(call, "ShellExecuteExA", "ShellExecuteExW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 89: SMB named pipe lateral movement
    //   CreateFile(done) → WriteFile
    // ======================================================================
    case 89:
        if (sm.currentState == 1) {
            if (FuncIs(call, "WriteFile") && call.succeeded)
                matched = true;
        } break;

    // ======================================================================
    // Rule 90: Pass-the-hash
    //   AcquireCredentials/LogonUser(done) → Impersonate / CreateProcessWithLogon
    // ======================================================================
    case 90:
        if (sm.currentState == 1) {
            if (FuncIsAny3(call, "ImpersonateLoggedOnUser", "SetThreadToken",
                           "CreateProcessWithLogonW") ||
                FuncIsAny(call, "CreateProcessWithTokenW", "CreateProcessAsUserW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 91: Pass-the-ticket
    //   Kerberos auth setup(done) → Impersonate / CreateProcessWithTokenW
    // ======================================================================
    case 91:
        if (sm.currentState == 1) {
            if (FuncIsAny3(call, "CreateProcessWithTokenW", "SetThreadToken",
                           "ImpersonateLoggedOnUser"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 92: Kerberoasting
    //   Kerberos auth setup(done) → ticket read/write
    // ======================================================================
    case 92:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "ReadFile", "WriteFile", "InternetReadFile",
                           "HttpSendRequestA") ||
                FuncIs(call, "HttpSendRequestW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 93: AS-REP roasting
    //   Kerberos auth setup(done) → write/receive response
    // ======================================================================
    case 93:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "WriteFile", "ReadFile", "recv", "WSARecv") ||
                FuncIsAny(call, "InternetReadFile", "WinHttpReceiveResponse"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 94: Golden ticket
    //   Kerberos auth setup(done) → impersonate → process spawn
    // ======================================================================
    case 94:
        switch (sm.currentState) {
        case 1: if (FuncIsAny3(call, "ImpersonateLoggedOnUser", "SetThreadToken",
                               "DuplicateTokenEx"))
                    matched = true;
                break;
        case 2: if (FuncIsAny3(call, "CreateProcessAsUserA", "CreateProcessAsUserW",
                               "CreateProcessWithTokenW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 95: DCSync
    //   DRSBind(done) → DRSGetNCChanges
    // ======================================================================
    case 95:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "DRSGetNCChanges"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 96: KernelCallbackTable hijack
    //   OpenProcess(done) → WriteProcessMemory → SetWindowLong
    // ======================================================================
    case 96:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "SetWindowLongA", "SetWindowLongW",
                               "SetWindowLongPtrA", "SetWindowLongPtrW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 97: PROPagate injection
    //   SetProp(done) → Get/dispatch message → SetWindowLong/CallWindowProc
    // ======================================================================
    case 97:
        switch (sm.currentState) {
        case 1: if (FuncIsAny4(call, "GetMessageA", "GetMessageW",
                               "PeekMessageA", "PeekMessageW") ||
                    FuncIs(call, "DispatchMessageW"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "SetWindowLongA", "SetWindowLongW",
                               "CallWindowProcA", "CallWindowProcW") ||
                    FuncIsAny(call, "DispatchMessageA", "DispatchMessageW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 98: Ghostwriting
    //   OpenProcess(done) → WriteProcessMemory → SendMessage/PostMessage
    // ======================================================================
    case 98:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "SendMessageA", "SendMessageW",
                               "PostMessageA", "PostMessageW") ||
                    FuncIsAny(call, "SendNotifyMessageA", "SendNotifyMessageW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 99: Ctrl-Inject
    //   OpenThread(done) → NtQueueApcThread / QueueUserAPC
    // ======================================================================
    case 99:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "NtQueueApcThread", "QueueUserAPC"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 100: Mockingjay
    //   LoadLibrary(done) → VirtualProtect(exec) → memory copy
    // ======================================================================
    case 100:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory")) {
                    uint32_t newProt = static_cast<uint32_t>(call.args[2]);
                    if (ProtHasExec(newProt))
                        matched = true;
                } break;
        case 2: if (FuncIsAny4(call, "WriteProcessMemory", "RtlMoveMemory",
                               "RtlCopyMemory", "CopyMemory") ||
                    FuncIs(call, "memcpy"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 101: Process ghosting
    //   CreateFile(done) → WriteFile → NtCreateSection → DeleteFile → CreateProcess
    // ======================================================================
    case 101:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WriteFile") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "NtCreateSection", "ZwCreateSection"))
                    matched = true;
                break;
        case 3: if (FuncIsAny4(call, "DeleteFileA", "DeleteFileW",
                               "NtSetInformationFile", "SetFileInformationByHandle"))
                    matched = true;
                break;
        case 4: if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                               "CreateProcessInternalW", "NtCreateUserProcess"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 102: Process herpaderping
    //   CreateFile(done) → WriteFile → NtCreateSection → modify file → CreateProcess
    // ======================================================================
    case 102:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WriteFile") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "NtCreateSection", "ZwCreateSection"))
                    matched = true;
                break;
        case 3: if (FuncIsAny4(call, "WriteFile", "SetEndOfFile",
                               "FlushFileBuffers", "NtSetInformationFile"))
                    matched = true;
                break;
        case 4: if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                               "CreateProcessInternalW", "NtCreateUserProcess"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 103: Phantom DLL hollowing
    //   CreateProcess(SUSPENDED)(done) → WriteProcessMemory → ResumeThread
    // ======================================================================
    case 103:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "WriteProcessMemory") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 104: Module stomping
    //   LoadLibrary(done) → VirtualProtect(exec) → memory copy
    // ======================================================================
    case 104:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory")) {
                    uint32_t newProt = static_cast<uint32_t>(call.args[2]);
                    if (ProtHasExec(newProt))
                        matched = true;
                } break;
        case 2: if (FuncIsAny4(call, "WriteProcessMemory", "RtlMoveMemory",
                               "RtlCopyMemory", "CopyMemory") ||
                    FuncIs(call, "memcpy"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 105: Thread pool injection
    //   TpAllocWork(done) → TpPostWork → TpReleaseWork
    // ======================================================================
    case 105:
        switch (sm.currentState) {
        case 1: if (ContainsCI(call.funcName, "TpPostWork"))
                    matched = true;
                break;
        case 2: if (ContainsCI(call.funcName, "TpReleaseWork"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 106: Fiber-based execution
    //   ConvertThreadToFiber(done) → CreateFiber → SwitchToFiber
    // ======================================================================
    case 106:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateFiber", "CreateFiberEx"))
                    matched = true;
                break;
        case 2: if (FuncIs(call, "SwitchToFiber"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 107: Callback injection via EnumWindows
    //   VirtualAllocEx(done) → EnumWindows/EnumChildWindows
    // ======================================================================
    case 107:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "EnumWindows", "EnumChildWindows",
                           "EnumThreadWindows", "EnumDesktopWindows"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 108: ETW patching
    //   GetProcAddress(done) → WriteProcessMemory / VirtualProtect
    // ======================================================================
    case 108:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "WriteProcessMemory", "VirtualProtect",
                           "NtProtectVirtualMemory", "RtlMoveMemory"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 111: LSASS credential scraping
    //   OpenProcess(done) → ReadProcessMemory → dump/write
    // ======================================================================
    case 111:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "ReadProcessMemory", "NtReadVirtualMemory"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "MiniDumpWriteDump", "WriteFile",
                               "CreateFileA", "CreateFileW") ||
                    FuncIsAny(call, "CryptUnprotectData", "BCryptDecrypt"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 112: Credential API enumeration and read
    //   CredEnumerate(done) → CredRead
    // ======================================================================
    case 112:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "CredReadA", "CredReadW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 114: Windows Credential Manager
    //   CredRead(done) → CryptUnprotectData / CredEnumerate
    // ======================================================================
    case 114:
        if (sm.currentState == 1) {
            if (FuncIsAny3(call, "CryptUnprotectData", "CredEnumerateA",
                           "CredEnumerateW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 115: DPAPI master key extraction
    //   CreateFile(done) → CryptUnprotectData
    // ======================================================================
    case 115:
        if (sm.currentState == 1) {
            if (FuncIs(call, "CryptUnprotectData"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 118: NTDS.dit extraction
    //   CreateProcess(done) → CreateFile → ReadFile
    // ======================================================================
    case 118:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateFileA", "CreateFileW"))
                    matched = true;
                break;
        case 2: if (FuncIs(call, "ReadFile") && call.succeeded)
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 119: Certificate store access
    //   CertOpenStore(done) → CertEnumCertificatesInStore / CertFindCertificate
    // ======================================================================
    case 119:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "CertEnumCertificatesInStore", "CertFindCertificateInStore"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 120: Token impersonation chain
    //   LogonUser(done) → ImpersonateLoggedOnUser → action
    // ======================================================================
    case 120:
        switch (sm.currentState) {
        case 1: if (FuncIsAny3(call, "ImpersonateLoggedOnUser", "SetThreadToken",
                               "NtSetInformationThread"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                               "CreateFileA", "CreateFileW") ||
                    FuncIsAny(call, "RegOpenKeyExA", "RegOpenKeyExW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 121: Named pipe client impersonation
    //   CreateNamedPipe(done) → ConnectNamedPipe → ImpersonateNamedPipeClient
    // ======================================================================
    case 121:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "ConnectNamedPipe"))
                    matched = true;
                break;
        case 2: if (FuncIs(call, "ImpersonateNamedPipeClient"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 123: Browser extension install
    //   CreateFile(done) → WriteFile / RegSetValue
    // ======================================================================
    case 123:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "WriteFile", "CopyFileA", "CopyFileW",
                           "RegSetValueExA") ||
                FuncIs(call, "RegSetValueExW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 124: Email MAPI harvest
    //   MAPI logon(done) → OpenEntry / QueryRows
    // ======================================================================
    case 124:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "OpenEntry") ||
                ContainsCI(call.funcName, "QueryRows") ||
                ContainsCI(call.funcName, "ReadMail"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 126: AMSI patch
    //   GetProcAddress(done) → patch write
    // ======================================================================
    case 126:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "WriteProcessMemory", "VirtualProtect",
                           "NtProtectVirtualMemory", "RtlMoveMemory"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 127: ETW blind
    //   GetProcAddress(done) → patch write
    // ======================================================================
    case 127:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "WriteProcessMemory", "VirtualProtect",
                           "NtProtectVirtualMemory", "RtlMoveMemory"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 128: ntdll unhooking from disk
    //   CreateFile(done) → ReadFile → WriteProcessMemory
    // ======================================================================
    case 128:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "ReadFile") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "WriteProcessMemory", "NtWriteVirtualMemory",
                               "RtlMoveMemory", "CopyMemory"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 130: CFG bypass
    //   SetProcessValidCallTargets(done) → thread execution
    // ======================================================================
    case 130:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "CreateRemoteThread", "NtCreateThreadEx",
                           "SetThreadContext", "NtContinue") ||
                FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 134: TLS callback anti-debug
    //   CreateProcess(SUSPENDED)(done) → ResumeThread
    // ======================================================================
    case 134:
        if (sm.currentState == 1) {
            if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 135: Parent PID spoofing
    //   InitializeProcThreadAttributeList(done) → UpdateProcThreadAttribute
    // ======================================================================
    case 135:
        if (sm.currentState == 1) {
            if (ContainsCI(call.funcName, "UpdateProcThreadAttribute"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 136: Argument spoofing
    //   CreateProcess(SUSPENDED)(done) → ReadProcessMemory → WriteProcessMemory → ResumeThread
    // ======================================================================
    case 136:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "ReadProcessMemory", "NtReadVirtualMemory"))
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "WriteProcessMemory", "NtWriteVirtualMemory"))
                    matched = true;
                break;
        case 3: if (FuncIsAny(call, "ResumeThread", "NtResumeThread"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 137: PE header stomping
    //   VirtualProtect(done) → ZeroMemory / memset / RtlZeroMemory
    // ======================================================================
    case 137:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "ZeroMemory", "RtlZeroMemory", "memset",
                           "WriteProcessMemory") ||
                FuncIs(call, "NtWriteVirtualMemory"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 139: Execution guardrails
    //   GetComputerName/GetUserName(done) → sensitive action
    // ======================================================================
    case 139:
        if (sm.currentState == 1) {
            if (FuncIsAny4(call, "CreateProcessA", "CreateProcessW",
                           "ShellExecuteA", "ShellExecuteW") ||
                FuncIsAny(call, "WinExec", "RegSetValueExW"))
                matched = true;
        } break;

    // ======================================================================
    // Rule 141: File encryption cascade
    //   FindFirstFile(done) → ReadFile → CryptEncrypt → WriteFile/rename
    // ======================================================================
    case 141:
        switch (sm.currentState) {
        case 1: if (FuncIs(call, "ReadFile") && call.succeeded)
                    matched = true;
                break;
        case 2: if (FuncIsAny(call, "CryptEncrypt", "BCryptEncrypt"))
                    matched = true;
                break;
        case 3: if (FuncIsAny4(call, "WriteFile", "MoveFileA",
                               "MoveFileW", "MoveFileExA") ||
                    FuncIsAny(call, "MoveFileExW", "SetFileInformationByHandle"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 142: Recursive directory encryption
    //   FindFirstFile(done) → CryptEncrypt → WriteFile/rename
    // ======================================================================
    case 142:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CryptEncrypt", "BCryptEncrypt"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "WriteFile", "MoveFileA",
                               "MoveFileW", "MoveFileExA") ||
                    FuncIs(call, "MoveFileExW"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 147: Network share encryption
    //   NetShareEnum(done) → CreateFile → CryptEncrypt/WriteFile
    // ======================================================================
    case 147:
        switch (sm.currentState) {
        case 1: if (FuncIsAny(call, "CreateFileA", "CreateFileW"))
                    matched = true;
                break;
        case 2: if (FuncIsAny4(call, "CryptEncrypt", "BCryptEncrypt",
                               "WriteFile", "MoveFileExW") ||
                    FuncIsAny(call, "MoveFileExA", "SetFileInformationByHandle"))
                    matched = true;
                break;
        } break;

    // ======================================================================
    // Rule 148: Wiper sequential overwrite
    //   CreateFile(done) → WriteFile
    // ======================================================================
    case 148:
        if (sm.currentState == 1) {
            if (FuncIs(call, "WriteFile") && call.succeeded)
                matched = true;
        } break;

    // ======================================================================
    // Rule 149: MBR ransomware overwrite
    //   CreateFile(done) → WriteFile
    // ======================================================================
    case 149:
        if (sm.currentState == 1) {
            if (FuncIs(call, "WriteFile") && call.succeeded)
                matched = true;
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
            if (sm.currentState < (std::numeric_limits<uint8_t>::max)()) {
                ++sm.currentState;
            }
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
        const bool hasSuspicious = HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI);
        const bool hasDefense    = HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion);
        const bool hasService    = HasFlag(call.behaviorFlags, BehaviorFlag::ServiceManipulation);
        const bool hasRegistry   = HasFlag(call.behaviorFlags, BehaviorFlag::RegistryPersistence);
        const bool hasPowerShell = HasFlag(call.behaviorFlags, BehaviorFlag::PowershellExecution);
        const bool hasFileDrop   = HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped) ||
                                   HasFlag(accumulatedFlags, BehaviorFlag::FileDropped);
        const bool sawNetwork    = HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2);
        const bool sawInjection  = HasFlag(accumulatedFlags, BehaviorFlag::CodeInjection) ||
                                   HasFlag(accumulatedFlags, BehaviorFlag::DLLInjection) ||
                                   HasFlag(accumulatedFlags, BehaviorFlag::ProcessInjection);
        const bool sawPrivEsc    = HasFlag(accumulatedFlags, BehaviorFlag::PrivilegeEscalation);

        // ---- Rule 18: Scheduled task via schtasks ----
        // The dispatcher tags schtasks-related CreateProcess with
        // ServiceManipulation (service/task creation behavior).
        if (hasService) {
            EmitAlert(18, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::ServiceManipulation);
        }

        // ---- Rule 26: Shadow copy delete via vssadmin / wmic ----
        // The dispatcher flags vssadmin/wmic shadow-delete commands with
        // SuspiciousAPI. We combine with FileDropped to reduce false positives.
        if (hasSuspicious) {
            // Strong signal: SuspiciousAPI + a file-manipulation indicator
            if (HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped) ||
                hasDefense) {
                EmitAlert(26, { callIndex }, instrN, tid);
            }
        }

        // ---- Rule 50: PowerShell cradle ----
        // The dispatcher flags powershell.exe -enc / -e / IEX / DownloadString
        // with PowershellExecution.
        if (hasPowerShell) {
            EmitAlert(50, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::PowershellExecution);
        }

        // ---- Rules 51-53: PowerShell fileless execution variants ----
        if (hasPowerShell) {
            EmitAlert(51, { callIndex }, instrN, tid);
            if (sawNetwork || hasSuspicious) {
                EmitAlert(52, { callIndex }, instrN, tid);
            }
            if (sawInjection || HasFlag(accumulatedFlags, BehaviorFlag::MemoryManipulation)) {
                EmitAlert(53, { callIndex }, instrN, tid);
            }
        }

        // ---- Rules 55-65: LOLBin / proxy execution ----
        if (hasSuspicious && !hasPowerShell) {
            EmitAlert(55, { callIndex }, instrN, tid);
            if (sawInjection || HasFlag(accumulatedFlags, BehaviorFlag::DLLInjection)) {
                EmitAlert(56, { callIndex }, instrN, tid);
                EmitAlert(57, { callIndex }, instrN, tid);
                EmitAlert(62, { callIndex }, instrN, tid);
                EmitAlert(63, { callIndex }, instrN, tid);
                EmitAlert(79, { callIndex }, instrN, tid);
            }
            if (HasFlag(call.behaviorFlags, BehaviorFlag::WMIExecution) || sawNetwork) {
                EmitAlert(58, { callIndex }, instrN, tid);
                EmitAlert(59, { callIndex }, instrN, tid);
            }
            if (sawNetwork && hasFileDrop) {
                EmitAlert(60, { callIndex }, instrN, tid);
                EmitAlert(78, { callIndex }, instrN, tid);
            }
            if (hasFileDrop || hasDefense) {
                EmitAlert(61, { callIndex }, instrN, tid);
                EmitAlert(77, { callIndex }, instrN, tid);
            }
            if (sawPrivEsc || hasDefense) {
                EmitAlert(64, { callIndex }, instrN, tid);
                EmitAlert(80, { callIndex }, instrN, tid);
            }
            EmitAlert(65, { callIndex }, instrN, tid);
        }

        // ---- Rules 66-80: Living-off-the-land binaries ----
        if (hasService) {
            EmitAlert(66, { callIndex }, instrN, tid);
            if (hasSuspicious) {
                EmitAlert(67, { callIndex }, instrN, tid);
                EmitAlert(68, { callIndex }, instrN, tid);
            }
        }
        if (hasDefense && hasSuspicious) {
            EmitAlert(69, { callIndex }, instrN, tid);
            EmitAlert(72, { callIndex }, instrN, tid);
            EmitAlert(73, { callIndex }, instrN, tid);
            EmitAlert(74, { callIndex }, instrN, tid);
            EmitAlert(75, { callIndex }, instrN, tid);
            EmitAlert(76, { callIndex }, instrN, tid);
            EmitAlert(144, { callIndex }, instrN, tid);
        }
        if (hasRegistry) {
            EmitAlert(71, { callIndex }, instrN, tid);
        }
        if (HasFlag(accumulatedFlags, BehaviorFlag::DLLInjection) && hasDefense) {
            EmitAlert(70, { callIndex }, instrN, tid);
        }
        if (hasSuspicious && HasFlag(accumulatedFlags, BehaviorFlag::MemoryManipulation)) {
            EmitAlert(143, { callIndex }, instrN, tid);
        }
    }

    // ========================================================================
    // CreateFile-based rules: check once for all file-creation patterns
    // ========================================================================
    if (FuncIsAny(call, "CreateFileA", "CreateFileW")) {
        uint32_t access = static_cast<uint32_t>(call.args[1]);
        const bool hasSuspicious = HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI);
        const bool hasCreds      = HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess);
        const bool hasFileDrop   = HasFlag(call.behaviorFlags, BehaviorFlag::FileDropped);

        // ---- Rule 20: DLL search order hijacking ----
        // Creating a DLL file flagged as potential injection vector
        if (hasFileDrop &&
            HasFlag(call.behaviorFlags, BehaviorFlag::DLLInjection)) {
            EmitAlert(20, { callIndex }, instrN, tid);
        }

        // ---- Rule 27: Direct volume / physical drive access ----
        // Writing to \\.\PhysicalDrive or \\.\C: — the dispatcher flags
        // these low-level device paths with SuspiciousAPI.
        if ((access & kGenericWrite) && hasSuspicious) {
            EmitAlert(27, { callIndex }, instrN, tid);
        }

        // ---- Rule 28: Ransom note drop ----
        // FileDropped + SuspiciousAPI on common ransom note patterns
        // (README.txt, DECRYPT_*.txt, HOW_TO_*.txt, etc.)
        if (hasFileDrop && hasSuspicious) {
            // Only fire if not already covered by rule 27 (device access)
            if (!(access & kGenericWrite)) {
                EmitAlert(28, { callIndex }, instrN, tid);
            }
        }

        // ---- Rule 48: MBR/VBR overwrite ----
        // Direct physical drive write access — critical severity.
        // Differentiated from rule 27 by the GENERIC_WRITE requirement
        // and the specific MBR/VBR context from the dispatcher.
        if ((access & kGenericWrite) && hasSuspicious) {
            // If the access also indicates a physical device (not just a volume),
            // the dispatcher sets both SuspiciousAPI and MemoryManipulation.
            if (HasFlag(call.behaviorFlags, BehaviorFlag::MemoryManipulation)) {
                EmitAlert(48, { callIndex }, instrN, tid);
                accumulatedFlags = CombineFlags(accumulatedFlags,
                    BehaviorFlag::SuspiciousAPI);
            }
        }

        // ---- Rule 113: Browser credential database access ----
        if (hasCreds || (hasFileDrop && HasFlag(accumulatedFlags, BehaviorFlag::CredentialAccess))) {
            EmitAlert(113, { callIndex }, instrN, tid);
        }

        // ---- Rule 115: DPAPI master key access path ----
        if (hasCreds && !(access & kGenericWrite)) {
            EmitAlert(115, { callIndex }, instrN, tid);
        }

        // ---- Rule 143: Recovery partition deletion staging ----
        if ((access & kGenericWrite) && hasSuspicious &&
            HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion)) {
            EmitAlert(143, { callIndex }, instrN, tid);
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

        // ---- Rule 85: COM script engine ----
        if (HasFlag(call.behaviorFlags, BehaviorFlag::SuspiciousAPI) ||
            HasFlag(accumulatedFlags, BehaviorFlag::PowershellExecution)) {
            EmitAlert(85, { callIndex }, instrN, tid);
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

    if (FuncIsAny4(call, "RegSaveKeyA", "RegSaveKeyW",
                   "RegSaveKeyExA", "RegSaveKeyExW")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::CredentialAccess) ||
            HasFlag(accumulatedFlags, BehaviorFlag::CredentialAccess)) {
            EmitAlert(116, { callIndex }, instrN, tid);
            EmitAlert(117, { callIndex }, instrN, tid);
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

    // ---- Rule 109: Heaven's Gate heuristic ----
    if (FuncIsAny3(call, "Wow64GetThreadContext", "Wow64SetThreadContext",
                   "NtContinue")) {
        EmitAlert(109, { callIndex }, instrN, tid);
    }

    // ---- Rule 110: Direct syscall / HellsGate heuristic ----
    if (call.dllName && StrEqCI(call.dllName, "ntdll.dll") &&
        call.funcName[0] == 'N' && call.funcName[1] == 't') {
        if (HasFlag(accumulatedFlags, BehaviorFlag::SuspiciousAPI) ||
            HasFlag(accumulatedFlags, BehaviorFlag::CodeInjection)) {
            EmitAlert(110, { callIndex }, instrN, tid);
        }
    }

    // ---- Rule 32: Timestomping ----
    if (FuncIsAny(call, "SetFileTime", "NtSetInformationFile")) {
        if (HasFlag(call.behaviorFlags, BehaviorFlag::DefenseEvasion)) {
            EmitAlert(32, { callIndex }, instrN, tid);
            accumulatedFlags = CombineFlags(accumulatedFlags,
                BehaviorFlag::DefenseEvasion);
        }
    }

    // ---- Rule 131: PEB BeingDebugged anti-debug ----
    if (FuncIs(call, "NtQueryInformationProcess")) {
        uint32_t infoClass = static_cast<uint32_t>(call.args[1]);
        if (infoClass == 7 || infoClass == 30 || infoClass == 31) {
            EmitAlert(131, { callIndex }, instrN, tid);
        }
    }

    // ---- Rule 132: Heap flag anti-debug ----
    if (FuncIsAny3(call, "HeapWalk", "HeapQueryInformation",
                   "RtlQueryProcessHeapInformation")) {
        EmitAlert(132, { callIndex }, instrN, tid);
    }

    // ---- Rule 133: Hardware breakpoint detection ----
    if (FuncIsAny3(call, "GetThreadContext", "Wow64GetThreadContext",
                   "NtGetContextThread")) {
        EmitAlert(133, { callIndex }, instrN, tid);
    }

    // ---- Rule 138: Entropy reduction encoding heuristic ----
    if (FuncIsAny(call, "CryptEncrypt", "BCryptEncrypt")) {
        if (HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(accumulatedFlags, BehaviorFlag::SuspiciousAPI)) {
            EmitAlert(138, { callIndex }, instrN, tid);
        }
    }

    // ---- Rule 140: Time-based evasion ----
    if (FuncIsAny4(call, "GetTickCount", "GetTickCount64",
                   "QueryPerformanceCounter", "GetSystemTimeAsFileTime")) {
        if (HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(accumulatedFlags, BehaviorFlag::SuspiciousAPI)) {
            EmitAlert(140, { callIndex }, instrN, tid);
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

    // ========================================================================
    // Generic credential, discovery, evasion, and destructive inline rules
    // ========================================================================

    // ---- Rule 122: Clipboard monitoring ----
    if (FuncIs(call, "GetClipboardData")) {
        EmitAlert(122, { callIndex }, instrN, tid);
    }

    // ---- Rule 125: Network share enumeration ----
    if (FuncIsAny4(call, "NetShareEnum", "WNetEnumResourceA",
                   "WNetEnumResourceW", "NetServerEnum")) {
        EmitAlert(125, { callIndex }, instrN, tid);
    }

    // ---- Rule 129: Manual syscall stub construction heuristic ----
    if (FuncIsAny(call, "VirtualAlloc", "NtAllocateVirtualMemory") ||
        FuncIsAny(call, "VirtualProtect", "NtProtectVirtualMemory")) {
        if (HasFlag(accumulatedFlags, BehaviorFlag::MemoryManipulation) &&
            HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion)) {
            EmitAlert(129, { callIndex }, instrN, tid);
        }
    }

    // ---- Rules 145-146: Pre-encryption process kill sets ----
    if (FuncIsAny(call, "TerminateProcess", "NtTerminateProcess")) {
        if (HasFlag(accumulatedFlags, BehaviorFlag::DefenseEvasion) ||
            HasFlag(accumulatedFlags, BehaviorFlag::SuspiciousAPI)) {
            EmitAlert(145, { callIndex }, instrN, tid);
            EmitAlert(146, { callIndex }, instrN, tid);
        }
    }

    // ---- Rule 150: Double extortion heuristic ----
    if (FuncIsAny4(call, "CryptEncrypt", "BCryptEncrypt", "HttpSendRequestA",
                   "HttpSendRequestW") ||
        FuncIsAny4(call, "WinHttpSendRequest", "send", "WSASend", "InternetWriteFile")) {
        if (HasFlag(accumulatedFlags, BehaviorFlag::NetworkC2) &&
            (HasFlag(accumulatedFlags, BehaviorFlag::FileDropped) ||
             HasFlag(accumulatedFlags, BehaviorFlag::CredentialAccess))) {
            EmitAlert(150, { callIndex }, instrN, tid);
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
        sysInfo.Set("computerName", callIndex, instrN);
    }
    if (FuncIsAny3(call, "GetUserNameA", "GetUserNameW", "GetUserNameExW")) {
        sysInfo.Set("userName", callIndex, instrN);
    }
    if (FuncIsAny3(call, "GetVersionExA", "GetVersionExW", "RtlGetVersion")) {
        sysInfo.Set("versionEx", callIndex, instrN);
    }
    if (FuncIsAny3(call, "GetSystemInfo", "GetNativeSystemInfo",
                   "NtQuerySystemInformation")) {
        sysInfo.Set("systemInfo", callIndex, instrN);
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
            uint64_t span = (readWriteFileCount.lastInstr >= findFileCount.firstInstr)
                ? (readWriteFileCount.lastInstr - findFileCount.firstInstr)
                : 0;
            inWindow = span <= 2'000'000;
        }

        if (fileEnumHigh && cryptoHigh && rwHigh && inWindow) {
            findFileCount.fired = true;
            auto ev = findFileCount.GetEvidence();
            auto cryptoEv = cryptoAPICount.GetEvidence();
            try {
                const size_t remaining =
                    ev.size() < kMaxEvidencePerAlert
                        ? (kMaxEvidencePerAlert - ev.size())
                        : 0;
                ev.insert(ev.end(),
                          cryptoEv.begin(),
                          cryptoEv.begin() +
                              static_cast<std::ptrdiff_t>(
                                  std::min(remaining, cryptoEv.size())));
            } catch (const std::bad_alloc&) {
                RecordDrop();
            }
            EmitAlert(25, ev, instrCount, 0);
        }
    }

    // ---- Rule 29: Mass file rename ----
    if (!fileRenameCount.fired && fileRenameCount.count >= 10) {
        uint64_t span = (fileRenameCount.lastInstr >= fileRenameCount.firstInstr)
            ? (fileRenameCount.lastInstr - fileRenameCount.firstInstr)
            : 0;
        if (span <= 500'000) {
            fileRenameCount.fired = true;
            EmitAlert(29, fileRenameCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 36: DNS tunneling ----
    if (!dnsQueryCount.fired && dnsQueryCount.count >= 15) {
        uint64_t span = (dnsQueryCount.lastInstr >= dnsQueryCount.firstInstr)
            ? (dnsQueryCount.lastInstr - dnsQueryCount.firstInstr)
            : 0;
        if (span <= 300'000) {
            dnsQueryCount.fired = true;
            EmitAlert(36, dnsQueryCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 42: System info gathering ----
    if (!sysInfo.fired && sysInfo.count >= 3) {
        uint64_t span = (sysInfo.lastInstr >= sysInfo.firstInstr)
            ? (sysInfo.lastInstr - sysInfo.firstInstr)
            : 0;
        if (span <= 200'000) {
            sysInfo.fired = true;
            EmitAlert(42, sysInfo.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 43: Network enumeration ----
    if (!netEnumCount.fired && netEnumCount.count >= 2) {
        uint64_t span = (netEnumCount.lastInstr >= netEnumCount.firstInstr)
            ? (netEnumCount.lastInstr - netEnumCount.firstInstr)
            : 0;
        if (span <= 300'000) {
            netEnumCount.fired = true;
            EmitAlert(43, netEnumCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 44: File system recon ----
    if (!driveEnumCount.fired && driveEnumCount.count >= 3) {
        uint64_t span = (driveEnumCount.lastInstr >= driveEnumCount.firstInstr)
            ? (driveEnumCount.lastInstr - driveEnumCount.firstInstr)
            : 0;
        if (span <= 300'000) {
            driveEnumCount.fired = true;
            EmitAlert(44, driveEnumCount.GetEvidence(), instrCount, 0);
        }
    }

    // ---- Rule 45 variant: GetAsyncKeyState loop ----
    if (!keyStateCount.fired && keyStateCount.count >= 50) {
        uint64_t span = (keyStateCount.lastInstr >= keyStateCount.firstInstr)
            ? (keyStateCount.lastInstr - keyStateCount.firstInstr)
            : 0;
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
                try {
                    trackedAllocs.push_back(ta);
                } catch (const std::bad_alloc&) {
                    RecordDrop();
                }
            } else if (ProtIsRW(prot)) {
                // Rule 14: Staged shellcode — RW alloc (execute comes later)
                ta.isRWX = false;
                try {
                    trackedAllocs.push_back(ta);
                } catch (const std::bad_alloc&) {
                    RecordDrop();
                }
            }
        }
    }

    // Track VirtualAllocEx for remote allocation (injection rules handle this
    // via state machines, but we still record for cross-thread tracking)
    if (FuncIs(call, "VirtualAllocEx") && call.returnValue != 0) {
        try {
            if (allocOrigins.size() < kMaxResourceEntries ||
                allocOrigins.find(call.returnValue) != allocOrigins.end()) {
                allocOrigins[call.returnValue] = { call.threadId, instrN };
            } else {
                RecordDrop();
            }
        } catch (const std::bad_alloc&) {
            RecordDrop();
        }
    }
}

// ============================================================================
// Impl — Cross-Thread Resource Tracking
// ============================================================================

void BehaviorMonitor::Impl::TrackResources(const APICallDetail& call) noexcept {
    if (!call.funcName || !call.succeeded) return;

    const uint64_t instrN = static_cast<uint64_t>(call.instructionNum);

    try {
        // Track handle-producing API calls
        if (FuncIsAny(call, "OpenProcess", "OpenThread") ||
            FuncIsAny(call, "CreateFileA", "CreateFileW") ||
            FuncIsAny(call, "NtCreateSection", "NtOpenSection") ||
            FuncIsAny(call, "OpenSCManagerA", "OpenSCManagerW") ||
            FuncIsAny(call, "CreateNamedPipeA", "CreateNamedPipeW")) {
            if (call.returnValue != 0 && call.returnValue != static_cast<uint64_t>(-1)) {
                if (handleOrigins.size() < kMaxResourceEntries ||
                    handleOrigins.find(call.returnValue) != handleOrigins.end()) {
                    handleOrigins[call.returnValue] = { call.threadId, instrN };
                } else {
                    RecordDrop();
                }
            }
        }

        // Track memory allocations
        if (FuncIsAny(call, "VirtualAlloc", "VirtualAllocEx") ||
            FuncIs(call, "NtAllocateVirtualMemory")) {
            if (call.returnValue != 0) {
                if (allocOrigins.size() < kMaxResourceEntries ||
                    allocOrigins.find(call.returnValue) != allocOrigins.end()) {
                    allocOrigins[call.returnValue] = { call.threadId, instrN };
                } else {
                    RecordDrop();
                }
            }
        }
    } catch (const std::bad_alloc&) {
        RecordDrop();
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
        auto impl = std::make_unique<Impl>();
        impl->enabled = config.enableBehaviorMonitor;
        impl->stackBase = 0x0000000080000000ULL;  // From WinConst::kStackBase64
        impl->stackSize = config.stackSize;
        impl->alerts.reserve(256);
        impl->machines.reserve(128);
        impl->trackedAllocs.reserve(64);
        impl->eggHunter.scannedPages.reserve(64);
        m_impl = std::move(impl);
    } catch (const std::bad_alloc&) {
        m_impl.reset();
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
        GuestAddress codeWindowEnd = 0;
        const bool inCodeWindow =
            srcPage == impl.eggHunter.codeBase ||
            (AddGuestSize(impl.eggHunter.codeBase, 2ULL * kPageSize, codeWindowEnd) &&
             srcPage >= impl.eggHunter.codeBase &&
             srcPage < codeWindowEnd);
        if (inCodeWindow) {
            impl.eggHunter.lastInstr = record.instructionCount;
            try {
                if (impl.eggHunter.scannedPages.size() < 512 ||
                    impl.eggHunter.scannedPages.find(dstPage) != impl.eggHunter.scannedPages.end()) {
                    auto [it, inserted] = impl.eggHunter.scannedPages.emplace(dstPage, true);
                    (void)it;
                    if (inserted) {
                        IncrementSaturating(impl.eggHunter.uniquePageCount);
                        IncrementSaturating(impl.eggHunter.scanCount);
                    }
                } else {
                    impl.RecordDrop();
                }
            } catch (const std::bad_alloc&) {
                impl.RecordDrop();
            }

            // Fire if scanning many distinct pages from a small code region
            if (!impl.eggHunter.fired && impl.eggHunter.uniquePageCount >= 32) {
                uint64_t span = (impl.eggHunter.lastInstr >= impl.eggHunter.firstInstr)
                    ? (impl.eggHunter.lastInstr - impl.eggHunter.firstInstr)
                    : 0;
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
            if (RangesOverlap(record.address, 1, ta.base, ta.size)) {
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
    if (RangesOverlap(page, 1, impl.stackBase, impl.stackSize)) {
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
        if (RangesOverlap(page, 1, ta.base, ta.size)) {
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
            if (RangesOverlap(base, size, ta.base, ta.size)) {
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
    m_impl->alertCallback = std::move(cb);
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
        result.reserve(m_impl->alerts.size());
        for (const auto& alert : m_impl->alerts) {
            if (alert.category == cat)
                result.push_back(&alert);
        }
    } catch (const std::bad_alloc&) {
        result.clear();
    }
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

    impl.eggHunter.codeBase = 0;
    impl.eggHunter.scanCount = 0;
    impl.eggHunter.firstInstr = 0;
    impl.eggHunter.lastInstr = 0;
    impl.eggHunter.uniquePageCount = 0;
    impl.eggHunter.scannedPages.clear();
    impl.eggHunter.fired = false;

    // Callback is preserved across reset (intentional)
}

} // namespace Phantom
