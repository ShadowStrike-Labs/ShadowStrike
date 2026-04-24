/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ProcessAPI.cpp — Kernel32 process management API implementations
 *
 * Every handler reads arguments via APIContext, creates/manipulates
 * handles in the HandleTable, and flags suspicious behavioral patterns.
 * No host OS calls are made.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ProcessAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <atomic>

// DESIGN: PROCESS_INFORMATION writeback, guest exit-code writeback, and
// handle-table cleanup on rollback paths are [[nodiscard]] because a failed
// guest write is an access-violation condition the guest must handle itself.
// Those are scoped disables; all dangerous error surfaces (Read of
// user-controlled path strings, Allocate, Protect) are still checked.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kOurPid          = 4444;
static constexpr uint32_t kMaxPathChars    = 1024;

// CreateProcess dwCreationFlags
static constexpr uint32_t CREATE_SUSPENDED     = 0x00000004;
static constexpr uint32_t CREATE_NEW_CONSOLE   = 0x00000010;
static constexpr uint32_t CREATE_NO_WINDOW     = 0x08000000;

// PROCESS_INFORMATION structure layout (x64):
//   +0x00 HANDLE hProcess  (8 bytes)
//   +0x08 HANDLE hThread   (8 bytes)
//   +0x10 DWORD  dwProcessId (4 bytes)
//   +0x14 DWORD  dwThreadId  (4 bytes)
static constexpr uint32_t kProcessInfoSize = 24;

// Monotonic counters for unique PIDs/TIDs
static std::atomic<uint32_t> s_nextPid{5000};
static std::atomic<uint32_t> s_nextTid{6000};

// ============================================================================
// Helpers
// ============================================================================

static std::wstring AnsiToWide(const std::string& ansi) noexcept {
    std::wstring result;
    result.reserve(ansi.size());
    for (char c : ansi) {
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return result;
}

// DESIGN: per-file LOLBin (Living-Off-the-Land Binary) lineage classifier.
// The CreateProcess IOCs are the single richest behavioural surface in any
// emulator — 90%+ of post-exploitation activity in real incidents is modelled
// as "Office/IE/Acrobat/unknown.exe spawning powershell.exe with -enc ..."
// The list below is deliberately conservative (no false-positives on benign
// MSI custom actions) and covers the mitre ATT&CK T1059 / T1218 / T1105
// techniques most frequently abused by commodity loaders, red-team kits
// (Cobalt Strike, Sliver, Mythic, Brute Ratel) and APT tooling.
struct LolbinClassification {
    BehaviorFlag primary;
    BehaviorFlag secondary;
    std::string_view name;
};

// Returns {primary, secondary, name} where BehaviorFlag::None in either slot
// means "no additional flag". `lowerLeaf` is the lower-cased image file name
// (no path, no quoting). Returns nullopt when the leaf is not on the list.
[[nodiscard]] static std::optional<LolbinClassification>
ClassifyLolbin(std::wstring_view lowerLeaf) noexcept {
    // PowerShell family — T1059.001.
    if (lowerLeaf == L"powershell.exe" || lowerLeaf == L"powershell" ||
        lowerLeaf == L"pwsh.exe"       || lowerLeaf == L"pwsh") {
        return LolbinClassification{BehaviorFlag::PowershellExecution,
                                    BehaviorFlag::SuspiciousAPI, "powershell"};
    }
    // Classic script hosts — T1059.005 / T1059.007 / T1059.003.
    if (lowerLeaf == L"wscript.exe" || lowerLeaf == L"cscript.exe") {
        return LolbinClassification{BehaviorFlag::SuspiciousAPI,
                                    BehaviorFlag::DefenseEvasion, "wscript"};
    }
    if (lowerLeaf == L"cmd.exe") {
        return LolbinClassification{BehaviorFlag::SuspiciousAPI,
                                    BehaviorFlag::None, "cmd"};
    }
    // T1218 signed-binary proxy execution family.
    if (lowerLeaf == L"rundll32.exe"  || lowerLeaf == L"regsvr32.exe" ||
        lowerLeaf == L"mshta.exe"     || lowerLeaf == L"msiexec.exe"  ||
        lowerLeaf == L"installutil.exe"|| lowerLeaf == L"regasm.exe"  ||
        lowerLeaf == L"regsvcs.exe") {
        return LolbinClassification{BehaviorFlag::DefenseEvasion,
                                    BehaviorFlag::SuspiciousAPI, "signed-proxy"};
    }
    // T1105 download+stage LOLBins — extremely high-signal IOCs.
    if (lowerLeaf == L"certutil.exe"  || lowerLeaf == L"bitsadmin.exe" ||
        lowerLeaf == L"curl.exe"      || lowerLeaf == L"wget.exe") {
        return LolbinClassification{BehaviorFlag::DefenseEvasion,
                                    BehaviorFlag::SuspiciousAPI, "stager"};
    }
    if (lowerLeaf == L"wmic.exe") {
        return LolbinClassification{BehaviorFlag::WMIExecution,
                                    BehaviorFlag::DefenseEvasion, "wmic"};
    }
    // Credential / recon / shadow-copy destruction utilities.
    if (lowerLeaf == L"vssadmin.exe"  || lowerLeaf == L"wbadmin.exe" ||
        lowerLeaf == L"bcdedit.exe") {
        return LolbinClassification{BehaviorFlag::DefenseEvasion,
                                    BehaviorFlag::SuspiciousAPI, "anti-recovery"};
    }
    return std::nullopt;
}

// Extract the case-folded leaf filename from either an applicationName or a
// commandLine first token. Caller passes whichever was supplied. Empty input
// → empty output. No allocations beyond the returned string.
[[nodiscard]] static std::wstring ExtractLowerLeaf(std::wstring_view input) noexcept {
    // Strip leading whitespace and optional quote.
    size_t start = 0;
    while (start < input.size() && (input[start] == L' ' || input[start] == L'\t')) ++start;
    if (start < input.size() && input[start] == L'"') {
        ++start;
        const size_t endQuote = input.find(L'"', start);
        const size_t tokenEnd = (endQuote == std::wstring_view::npos) ? input.size() : endQuote;
        input = input.substr(start, tokenEnd - start);
    } else {
        const size_t space = input.find_first_of(L" \t", start);
        input = input.substr(start, (space == std::wstring_view::npos) ? input.size() - start : space - start);
    }

    // Strip directory component.
    const size_t lastSep = input.find_last_of(L"\\/");
    if (lastSep != std::wstring_view::npos) {
        input = input.substr(lastSep + 1);
    }

    std::wstring leaf(input);
    for (auto& ch : leaf) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch + (L'a' - L'A'));
        }
    }
    return leaf;
}

// Case-insensitive substring search for a narrow ASCII needle inside a
// wide-string haystack. Used to scan command lines for PowerShell encoded-
// command flags and similar evasion markers.
[[nodiscard]] static bool ContainsInsensitive(std::wstring_view hay,
                                              std::string_view needle) noexcept {
    if (needle.empty() || needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            wchar_t hc = hay[i + j];
            if (hc >= L'A' && hc <= L'Z') hc = static_cast<wchar_t>(hc + (L'a' - L'A'));
            char nc = needle[j];
            if (nc >= 'A' && nc <= 'Z') nc = static_cast<char>(nc + ('a' - 'A'));
            if (hc != static_cast<wchar_t>(static_cast<unsigned char>(nc))) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// Internal: CreateProcess core logic (shared by A and W variants)
// ============================================================================

static bool CreateProcessCore(APIContext& ctx,
                              const std::wstring& applicationName,
                              const std::wstring& commandLine,
                              uint32_t dwCreationFlags,
                              GuestAddress lpProcessInfo) {
    if (lpProcessInfo == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // ------------------------------------------------------------------
    // IOC derivation — MUST happen before we short-circuit so a malformed
    // PROCESS_INFORMATION pointer still leaves the behavioural fingerprint.
    //   * CREATE_SUSPENDED on a child is the canonical pre-write step of
    //     T1055.012 Process Hollowing / T1055.004 Thread Hijacking.
    //   * LOLBin child → T1059 / T1218 / T1105 depending on family.
    //   * PowerShell with an encoded-command flag → DefenseEvasion.
    // ------------------------------------------------------------------
    const std::wstring_view leafSource =
        !applicationName.empty() ? std::wstring_view{applicationName}
                                 : std::wstring_view{commandLine};
    const std::wstring leaf = ExtractLowerLeaf(leafSource);

    if (!leaf.empty()) {
        if (auto cls = ClassifyLolbin(leaf); cls.has_value()) {
            ctx.AddBehaviorFlag(cls->primary);
            if (cls->secondary != BehaviorFlag::None) {
                ctx.AddBehaviorFlag(cls->secondary);
            }
            // PowerShell encoded command — T1059.001 + T1027. Single
            // highest-signal commodity-malware IOC in the industry.
            if (leaf == L"powershell.exe" || leaf == L"powershell" ||
                leaf == L"pwsh.exe"       || leaf == L"pwsh") {
                if (ContainsInsensitive(commandLine, "-enc") ||
                    ContainsInsensitive(commandLine, "-encodedcommand") ||
                    ContainsInsensitive(commandLine, "-e ")) {
                    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
                }
                // Remote payload fetch via PowerShell — T1105.
                if (ContainsInsensitive(commandLine, "downloadstring") ||
                    ContainsInsensitive(commandLine, "iwr ") ||
                    ContainsInsensitive(commandLine, "invoke-webrequest") ||
                    ContainsInsensitive(commandLine, "net.webclient")) {
                    ctx.AddBehaviorFlag(BehaviorFlag::NetworkC2);
                }
            }
            // certutil/bitsadmin with a URL argument → T1105 stager.
            if (leaf == L"certutil.exe" || leaf == L"bitsadmin.exe") {
                if (ContainsInsensitive(commandLine, "http://") ||
                    ContainsInsensitive(commandLine, "https://") ||
                    ContainsInsensitive(commandLine, "ftp://")) {
                    ctx.AddBehaviorFlag(BehaviorFlag::NetworkC2);
                }
            }
            // vssadmin delete shadows / wbadmin delete catalog — the
            // defining T1490 (Inhibit System Recovery) ransomware IOC.
            // No dedicated BehaviorFlag::RansomwareBehavior exists today;
            // the baseline LOLBin classification already emits
            // DefenseEvasion + SuspiciousAPI above, and the recovery-
            // inhibition argument pattern additionally reinforces the
            // PrivilegeEscalation posture (these commands require admin).
            if (leaf == L"vssadmin.exe" || leaf == L"wbadmin.exe" ||
                leaf == L"bcdedit.exe") {
                if (ContainsInsensitive(commandLine, "delete shadows") ||
                    ContainsInsensitive(commandLine, "delete catalog") ||
                    ContainsInsensitive(commandLine, "recoveryenabled no") ||
                    ContainsInsensitive(commandLine, "bootstatuspolicy ignoreallfailures")) {
                    ctx.AddBehaviorFlag(BehaviorFlag::PrivilegeEscalation);
                }
            }
        }
    }

    // CREATE_SUSPENDED on any child is a T1055.012 process-hollowing
    // precursor — the parent will next unmap the child's main image and
    // write a replacement with WriteProcessMemory before ResumeThread.
    if ((dwCreationFlags & CREATE_SUSPENDED) != 0) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessHollowing);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    // Assign unique PIDs for the child
    const uint32_t childPid = s_nextPid.fetch_add(1, std::memory_order_relaxed);
    const uint32_t childTid = s_nextTid.fetch_add(1, std::memory_order_relaxed);

    // Create a process handle
    ProcessHandleData phd;
    phd.pid        = childPid;
    phd.accessMask = NT::PROCESS_ALL_ACCESS;
    phd.isSelf     = false;

    auto& handles = ctx.Handles();
    GuestHandle hProcess = handles.Create(HandleType::Process, phd);
    if (hProcess == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Create a thread handle for the primary thread
    ThreadHandleData thd;
    thd.tid        = childTid;
    thd.ownerPid   = childPid;
    thd.accessMask = NT::THREAD_ALL_ACCESS;
    thd.suspended  = (dwCreationFlags & CREATE_SUSPENDED) != 0;

    GuestHandle hThread = handles.Create(HandleType::Thread, thd);
    if (hThread == kNullHandle) {
        handles.Close(hProcess);
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Fill PROCESS_INFORMATION structure in guest memory
    auto& mem = ctx.Memory();
    uint8_t pi[kProcessInfoSize] = {};

    std::memcpy(pi + 0x00, &hProcess, 8);
    std::memcpy(pi + 0x08, &hThread, 8);
    std::memcpy(pi + 0x10, &childPid, 4);
    std::memcpy(pi + 0x14, &childTid, 4);

    if (mem.Write(lpProcessInfo, pi, kProcessInfoSize) != ErrorCode::Success) {
        handles.Close(hProcess);
        handles.Close(hThread);
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CreateProcessA — lpApplicationName(0), lpCommandLine(1),
//                  lpProcessAttributes(2), lpThreadAttributes(3),
//                  bInheritHandles(4), dwCreationFlags(5),
//                  lpEnvironment(6), lpCurrentDirectory(7),
//                  lpStartupInfo(8), lpProcessInformation(9)
// ============================================================================

bool HandleCreateProcessA(APIContext& ctx) {
    const auto lpAppName       = ctx.GetArgPtr(0);
    const auto lpCmdLine       = ctx.GetArgPtr(1);
    // args 2-4 ignored in emulation
    const auto dwCreationFlags = ctx.GetArg32(5);
    // args 6-8 ignored
    const auto lpProcessInfo   = ctx.GetArgPtr(9);

    std::wstring appName;
    std::wstring cmdLine;

    if (lpAppName != 0) {
        std::string ansi = ctx.ReadAnsiString(lpAppName, kMaxPathChars);
        appName = AnsiToWide(ansi);
    }
    if (lpCmdLine != 0) {
        std::string ansi = ctx.ReadAnsiString(lpCmdLine, kMaxPathChars);
        cmdLine = AnsiToWide(ansi);
    }

    if (appName.empty() && cmdLine.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    return CreateProcessCore(ctx, appName, cmdLine, dwCreationFlags, lpProcessInfo);
}

// ============================================================================
// CreateProcessW — same layout, wide strings
// ============================================================================

bool HandleCreateProcessW(APIContext& ctx) {
    const auto lpAppName       = ctx.GetArgPtr(0);
    const auto lpCmdLine       = ctx.GetArgPtr(1);
    const auto dwCreationFlags = ctx.GetArg32(5);
    const auto lpProcessInfo   = ctx.GetArgPtr(9);

    std::wstring appName;
    std::wstring cmdLine;

    if (lpAppName != 0) {
        appName = ctx.ReadWideString(lpAppName, kMaxPathChars);
    }
    if (lpCmdLine != 0) {
        cmdLine = ctx.ReadWideString(lpCmdLine, kMaxPathChars);
    }

    if (appName.empty() && cmdLine.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    return CreateProcessCore(ctx, appName, cmdLine, dwCreationFlags, lpProcessInfo);
}

// ============================================================================
// OpenProcess — dwDesiredAccess(0), bInheritHandle(1), dwProcessId(2)
// ============================================================================

bool HandleOpenProcess(APIContext& ctx) {
    const auto dwAccess   = ctx.GetArg32(0);
    // arg1 = bInheritHandle (not enforced)
    const auto dwPid      = ctx.GetArg32(2);

    const bool isSelf = (dwPid == kOurPid);

    // IOC: requesting injection-grade access on another process is the
    // reconnaissance/setup step of T1055 Process Injection. PROCESS_VM_WRITE
    // plus PROCESS_VM_OPERATION is the exact mask used by every remote
    // shellcode loader (the follow-up calls are VirtualAllocEx →
    // WriteProcessMemory → CreateRemoteThread). PROCESS_QUERY_INFORMATION
    // alone on a remote PID is noisier and intentionally not flagged.
    if (!isSelf) {
        constexpr uint32_t kInjMask = NT::PROCESS_VM_WRITE |
                                      NT::PROCESS_VM_OPERATION |
                                      NT::PROCESS_CREATE_THREAD;
        if ((dwAccess & kInjMask) != 0 ||
            (dwAccess & NT::PROCESS_ALL_ACCESS) == NT::PROCESS_ALL_ACCESS) {
            ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
        // Credential-access reconnaissance on a remote process: VM_READ
        // on something like LSASS is the canonical T1003.001 LSASS
        // dumping precursor.
        if ((dwAccess & NT::PROCESS_VM_READ) != 0) {
            ctx.AddBehaviorFlag(BehaviorFlag::CredentialAccess);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    ProcessHandleData phd;
    phd.pid        = dwPid;
    phd.accessMask = dwAccess;
    phd.isSelf     = isSelf;

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(HandleType::Process, phd);
    if (gh == kNullHandle) {
        ctx.FailWithInvalidHandle(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(gh);
    return true;
}

// ============================================================================
// TerminateProcess — hProcess(0), uExitCode(1)
// ============================================================================

bool HandleTerminateProcess(APIContext& ctx) {
    const auto hProcess  = ctx.GetArg(0);

    // Check if this is self-termination
    if (hProcess == kCurrentProcess || hProcess == kNullHandle) {
        // Self-termination stops emulation
        return false;
    }

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hProcess, HandleType::Process);
    if (entry.has_value()) {
        auto* pd = std::get_if<ProcessHandleData>(&entry->data);
        if (pd && pd->isSelf) {
            return false;
        }
    }

    // Remote process termination — succeed silently
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// ExitProcess — uExitCode(0)
// ============================================================================

bool HandleExitProcess(APIContext& ctx) {
    (void)ctx;
    // Returning false stops the emulation with StopReason::ExitProcess
    return false;
}

// ============================================================================
// GetCurrentProcessId — no arguments
// ============================================================================

bool HandleGetCurrentProcessId(APIContext& ctx) {
    ctx.SetReturn32(kOurPid);
    return true;
}

// ============================================================================
// GetCurrentProcess — no arguments
// ============================================================================

bool HandleGetCurrentProcess(APIContext& ctx) {
    ctx.SetReturnHandle(kCurrentProcess);
    return true;
}

// ============================================================================
// GetExitCodeProcess — hProcess(0), lpExitCode(1)
// ============================================================================

bool HandleGetExitCodeProcess(APIContext& ctx) {
    const auto hProcess   = ctx.GetArg(0);
    const auto lpExitCode = ctx.GetArgPtr(1);

    if (lpExitCode == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // If the handle is valid (even remote), report STILL_ACTIVE
    auto& handles = ctx.Handles();
    bool validHandle = (hProcess == kCurrentProcess) ||
                       handles.IsValid(hProcess);

    if (!validHandle) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Memory().WriteU32(lpExitCode, Win32::STILL_ACTIVE);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// IsWow64Process — hProcess(0), Wow64Process(1)
// ============================================================================

bool HandleIsWow64Process(APIContext& ctx) {
    const auto hProcess     = ctx.GetArg(0);
    const auto lpWow64Flag  = ctx.GetArgPtr(1);
    (void)hProcess; // DESIGN: emulator is single-persona, hProcess is accepted
                    // for API compatibility but the answer is always derived
                    // from the emulated CPU bitness.

    if (lpWow64Flag == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // If 64-bit emulation → WoW64 = FALSE; 32-bit → WoW64 = TRUE
    const GuestBool isWow64 = ctx.CPU().Is64Bit() ? 0 : 1;
    ctx.Memory().WriteU32(lpWow64Flag, static_cast<uint32_t>(isWow64));

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterProcessAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "CreateProcessA",
          HandleCreateProcessA, 10, true },
        { "kernel32.dll", "CreateProcessW",
          HandleCreateProcessW, 10, true },
        { "kernel32.dll", "OpenProcess",
          HandleOpenProcess, 3, true },
        { "kernel32.dll", "TerminateProcess",
          HandleTerminateProcess, 2, false },
        { "kernel32.dll", "ExitProcess",
          HandleExitProcess, 1, true },
        { "kernel32.dll", "GetCurrentProcessId",
          HandleGetCurrentProcessId, 0, true },
        { "kernel32.dll", "GetCurrentProcess",
          HandleGetCurrentProcess, 0, true },
        { "kernel32.dll", "GetExitCodeProcess",
          HandleGetExitCodeProcess, 2, false },
        { "kernel32.dll", "IsWow64Process",
          HandleIsWow64Process, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
