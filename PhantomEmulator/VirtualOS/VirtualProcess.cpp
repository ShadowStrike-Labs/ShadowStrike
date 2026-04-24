/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualProcess.cpp — Centralized fake process / thread table
 *
 * Pre-populates ~60 realistic Windows 10 22H2 Pro processes so that
 * NtQuerySystemInformation(SystemProcessInformation) returns data
 * indistinguishable from a real endpoint.
 *
 * CRITICAL ANTI-EVASION RULES:
 *   1. No analysis tools (OllyDbg, x64dbg, Wireshark, ProcMon, etc.)
 *      may ever appear in the process list.
 *   2. PIDs, thread counts, working-set sizes, and parent relationships
 *      must match a plausible Win10 boot.
 *   3. PID 4444 is the emulated malware process; its name comes from
 *      the sample filename.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VirtualProcess.hpp"
#include "../Common/Constants.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <limits>
#include <new>
#include <string>

namespace Phantom::VirtualOS {

namespace {

static constexpr size_t kMaxProcessTextChars = 4096;
static constexpr size_t kMaxProcessIOCChars = 8192;

[[nodiscard]] bool IsReasonableWideText(std::wstring_view text, size_t maxLen) noexcept {
    if (text.size() > maxLen) return false;
    for (const wchar_t ch : text) {
        if (ch == L'\0') return false;
    }
    return true;
}

[[nodiscard]] std::wstring SanitizedUserName(std::wstring_view userName) {
    if (userName.empty()) return L"JSmith";
    const size_t len = std::min<size_t>(userName.size(), 64);
    std::wstring result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        const wchar_t ch = userName[i];
        result.push_back((ch >= L' ' && ch != L'\\' && ch != L'/' && ch != L':' &&
                          ch != L'*' && ch != L'?' && ch != L'"' && ch != L'<' &&
                          ch != L'>' && ch != L'|')
                             ? ch
                             : L'_');
    }
    return result.empty() ? std::wstring(L"JSmith") : result;
}

[[nodiscard]] int32_t ClampThreadPriority(int32_t priority) noexcept {
    if (priority == 0) return 8;
    if (priority < -15) return -15;
    if (priority > 15) return 15;
    return priority;
}

} // namespace

// ============================================================================
// Meyers' Singleton
// ============================================================================

VirtualProcess& VirtualProcess::Instance() noexcept {
    static VirtualProcess instance;
    return instance;
}

// ============================================================================
// Initialization / Reset
// ============================================================================

void VirtualProcess::Initialize(const EmulationConfig& config) noexcept {
    try {
    std::unique_lock lock(m_mutex);
    if (m_initialized) return;

    m_processList.clear();
    m_threads.clear();
    m_modules.clear();
    m_createIOCs.clear();
    m_nextTID = kEmulatedPID + 1; // TIDs start above the emulated PID

    PopulateProcessList(config);
    PopulateModuleList();

    // Locate the emulated process entry we just inserted
    for (const auto& p : m_processList) {
        if (p.pid == kEmulatedPID) {
            m_currentProcess = p;
            break;
        }
    }

    // Create the main thread for the emulated process
    if (m_currentProcess.pid != kEmulatedPID) {
        m_processList.clear();
        m_threads.clear();
        m_modules.clear();
        m_createIOCs.clear();
        m_currentProcess = {};
        m_nextTID = 1;
        m_initialized = false;
        return;
    }

    ThreadInfo mainThread{};
    mainThread.tid          = m_nextTID++;
    mainThread.ownerPid     = kEmulatedPID;
    mainThread.startAddress = 0; // Will be set later by the loader
    mainThread.priority     = 8; // THREAD_PRIORITY_NORMAL
    mainThread.state        = 5; // KTHREAD_STATE: Waiting
    mainThread.createTime   = m_currentProcess.createTime;
    mainThread.kernelTime   = 0;
    mainThread.userTime     = 0;
    mainThread.waitReason   = 6; // WrUserRequest
    mainThread.isSuspended  = false;
    m_threads.push_back(mainThread);

    m_initialized = true;
    } catch (const std::bad_alloc&) {
        Reset();
    } catch (const std::length_error&) {
        Reset();
    }
}

void VirtualProcess::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_processList.clear();
    m_threads.clear();
    m_modules.clear();
    m_createIOCs.clear();
    m_currentProcess = {};
    m_nextTID     = 0;
    m_initialized = false;
}

// ============================================================================
// Process Table — Public Queries
// ============================================================================

std::vector<ProcessInfo> VirtualProcess::GetProcessList() const noexcept {
    try {
        std::shared_lock lock(m_mutex);
        return m_processList;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

std::optional<ProcessInfo> VirtualProcess::GetProcessByPID(uint32_t pid) const noexcept {
    try {
    std::shared_lock lock(m_mutex);
    for (const auto& p : m_processList) {
        if (p.pid == pid) return p;
    }
    return std::nullopt;
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    } catch (const std::length_error&) {
        return std::nullopt;
    }
}

std::optional<ProcessInfo> VirtualProcess::GetProcessByName(std::wstring_view name) const noexcept {
    if (!IsReasonableWideText(name, kMaxProcessTextChars)) return std::nullopt;
    try {
    std::shared_lock lock(m_mutex);
    for (const auto& p : m_processList) {
        if (p.name.size() != name.size()) continue;
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i) {
            if (std::towlower(static_cast<wint_t>(p.name[i])) !=
                std::towlower(static_cast<wint_t>(name[i]))) {
                match = false;
                break;
            }
        }
        if (match) return p;
    }
    return std::nullopt;
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    } catch (const std::length_error&) {
        return std::nullopt;
    }
}

ProcessInfo VirtualProcess::GetCurrentProcess() const noexcept {
    try {
        std::shared_lock lock(m_mutex);
        return m_currentProcess;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

uint32_t VirtualProcess::GetCurrentPID() const noexcept {
    return kEmulatedPID;
}

uint32_t VirtualProcess::GetParentPID() const noexcept {
    return kEmulatedParentPID;
}

// ============================================================================
// Thread Management
// ============================================================================

uint32_t VirtualProcess::CreateThread(GuestAddress startAddress, int32_t priority) noexcept {
    try {
    std::unique_lock lock(m_mutex);
    if (m_threads.size() >= kMaxThreads) return 0;
    if (m_nextTID == 0 || m_nextTID == std::numeric_limits<uint32_t>::max()) return 0;

    ThreadInfo ti{};
    ti.tid          = m_nextTID++;
    ti.ownerPid     = kEmulatedPID;
    ti.startAddress = startAddress;
    ti.priority     = ClampThreadPriority(priority);
    ti.state        = 0; // KTHREAD_STATE: Initialized
    ti.createTime   = m_currentProcess.createTime + static_cast<uint64_t>(m_threads.size()) * 100'000;
    ti.kernelTime   = 0;
    ti.userTime     = 0;
    ti.waitReason   = 0;
    ti.isSuspended  = false;
    m_threads.push_back(ti);
    return ti.tid;
    } catch (const std::bad_alloc&) {
        return 0;
    } catch (const std::length_error&) {
        return 0;
    }
}

std::vector<ThreadInfo> VirtualProcess::GetThreadList(uint32_t pid) const noexcept {
    try {
    std::shared_lock lock(m_mutex);
    std::vector<ThreadInfo> result;
    result.reserve(std::min(m_threads.size(), static_cast<size_t>(kMaxThreads)));
    for (const auto& t : m_threads) {
        if (t.ownerPid == pid) result.push_back(t);
    }
    return result;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

std::optional<ThreadInfo> VirtualProcess::GetThreadByTID(uint32_t tid) const noexcept {
    std::shared_lock lock(m_mutex);
    for (const auto& t : m_threads) {
        if (t.tid == tid) return t;
    }
    return std::nullopt;
}

uint32_t VirtualProcess::GetCurrentTID() const noexcept {
    std::shared_lock lock(m_mutex);
    if (m_threads.empty()) return 0;
    return m_threads.front().tid; // First thread is the main thread
}

bool VirtualProcess::SuspendThread(uint32_t tid) noexcept {
    std::unique_lock lock(m_mutex);
    for (auto& t : m_threads) {
        if (t.tid == tid) {
            t.isSuspended = true;
            t.state       = 5; // Waiting
            t.waitReason  = 7; // WrSuspended
            return true;
        }
    }
    return false;
}

bool VirtualProcess::ResumeThread(uint32_t tid) noexcept {
    std::unique_lock lock(m_mutex);
    for (auto& t : m_threads) {
        if (t.tid == tid) {
            t.isSuspended = false;
            t.state       = 2; // Running
            t.waitReason  = 0;
            return true;
        }
    }
    return false;
}

bool VirtualProcess::TerminateThread(uint32_t tid) noexcept {
    std::unique_lock lock(m_mutex);
    if (!m_threads.empty() && m_threads.front().tid == tid) return false;
    auto it = std::find_if(m_threads.begin(), m_threads.end(),
                           [tid](const ThreadInfo& t) { return t.tid == tid; });
    if (it == m_threads.end()) return false;
    m_threads.erase(it);
    return true;
}

// ============================================================================
// Module List
// ============================================================================

std::vector<ModuleInfo> VirtualProcess::GetModuleList() const noexcept {
    try {
        std::shared_lock lock(m_mutex);
        return m_modules;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

std::optional<ModuleInfo> VirtualProcess::GetModuleByName(std::wstring_view name) const noexcept {
    if (!IsReasonableWideText(name, kMaxProcessTextChars)) return std::nullopt;
    try {
    std::shared_lock lock(m_mutex);
    for (const auto& m : m_modules) {
        if (m.name.size() != name.size()) continue;
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i) {
            if (std::towlower(static_cast<wint_t>(m.name[i])) !=
                std::towlower(static_cast<wint_t>(name[i]))) {
                match = false;
                break;
            }
        }
        if (match) return m;
    }
    return std::nullopt;
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    } catch (const std::length_error&) {
        return std::nullopt;
    }
}

std::optional<ModuleInfo> VirtualProcess::GetModuleByAddress(GuestAddress addr) const noexcept {
    try {
    std::shared_lock lock(m_mutex);
    for (const auto& m : m_modules) {
        if (addr >= m.baseAddress && (addr - m.baseAddress) < m.imageSize) {
            return m;
        }
    }
    return std::nullopt;
    } catch (const std::bad_alloc&) {
        return std::nullopt;
    } catch (const std::length_error&) {
        return std::nullopt;
    }
}

// ============================================================================
// Anti-Evasion — Analysis Tool Detection
// ============================================================================
// Static blocklist of process names associated with analysis / debugging /
// sandboxing tools.  These must NEVER appear in the process list and any
// query for them must return negative.

namespace {

// Case-insensitive wide-string compare helper
[[nodiscard]] bool WideICmp(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(static_cast<wint_t>(a[i])) !=
            std::towlower(static_cast<wint_t>(b[i])))
            return false;
    }
    return true;
}

// Debuggers
static constexpr const wchar_t* kDebuggerTools[] = {
    L"ollydbg.exe",
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"windbg.exe",
    L"ida.exe",
    L"ida64.exe",
    L"idaq.exe",
    L"idaq64.exe",
    L"radare2.exe",
    L"ghidra.exe",
    L"binaryninja.exe",
    L"immunitydebugger.exe",
    L"devenv.exe",
};

// Network analysis / interception
static constexpr const wchar_t* kNetworkTools[] = {
    L"wireshark.exe",
    L"tshark.exe",
    L"tcpdump.exe",
    L"fiddler.exe",
    L"burpsuite.exe",
    L"charles.exe",
    L"mitmproxy.exe",
    L"rawcap.exe",
};

// System monitoring / forensics
static constexpr const wchar_t* kMonitoringTools[] = {
    L"procmon.exe",
    L"procexp.exe",
    L"procexp64.exe",
    L"processhacker.exe",
    L"autoruns.exe",
    L"regmon.exe",
    L"filemon.exe",
    L"pestudio.exe",
    L"pe-bear.exe",
    L"pe-sieve.exe",
    L"hollowshunter.exe",
    L"apimonitor.exe",
    L"rohitab.exe",
};

// Reverse engineering / analysis
static constexpr const wchar_t* kRETools[] = {
    L"dnspy.exe",
    L"dotpeek.exe",
    L"die.exe",
    L"hxd.exe",
    L"peid.exe",
    L"lordpe.exe",
    L"resourcehacker.exe",
    L"cff explorer.exe",
    L"bytecodeviewer.exe",
};

// Sandbox / VM indicators
static constexpr const wchar_t* kSandboxTools[] = {
    L"cuckoo.exe",
    L"sandbox.exe",
    L"sample.exe",
    L"malware.exe",
    L"vboxservice.exe",
    L"vboxtray.exe",
    L"vmtoolsd.exe",
    L"vmwaretray.exe",
    L"vmwareuser.exe",
    L"vmacthlp.exe",
    L"xenservice.exe",
    L"qemu-ga.exe",
    L"joeboxserver.exe",
    L"joeboxcontrol.exe",
    L"prl_tools.exe",
};

[[nodiscard]] bool IsInBlocklist(std::wstring_view name,
                                 const wchar_t* const* list,
                                 size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        if (WideICmp(name, list[i])) return true;
    }
    return false;
}

} // anonymous namespace

bool VirtualProcess::IsAnalysisTool(std::wstring_view processName) const noexcept {
    if (!IsReasonableWideText(processName, kMaxProcessTextChars)) return false;
    return IsInBlocklist(processName, kDebuggerTools,    std::size(kDebuggerTools))
        || IsInBlocklist(processName, kNetworkTools,     std::size(kNetworkTools))
        || IsInBlocklist(processName, kMonitoringTools,  std::size(kMonitoringTools))
        || IsInBlocklist(processName, kRETools,          std::size(kRETools))
        || IsInBlocklist(processName, kSandboxTools,     std::size(kSandboxTools));
}

bool VirtualProcess::IsDebuggerProcess(std::wstring_view processName) const noexcept {
    if (!IsReasonableWideText(processName, kMaxProcessTextChars)) return false;
    return IsInBlocklist(processName, kDebuggerTools, std::size(kDebuggerTools));
}

// ============================================================================
// IOC Tracking — Child Process Creation
// ============================================================================

void VirtualProcess::RecordProcessCreation(const ProcessCreateIOC& ioc) noexcept {
    if (!IsReasonableWideText(ioc.commandLine, kMaxProcessIOCChars) ||
        !IsReasonableWideText(ioc.imagePath, kMaxProcessTextChars)) {
        return;
    }
    try {
    std::unique_lock lock(m_mutex);
    if (m_createIOCs.size() < kMaxIOCs) {
        ProcessCreateIOC sanitized = ioc;
        sanitized.isSuspended = (ioc.creationFlags & 0x00000004UL) != 0; // CREATE_SUSPENDED
        sanitized.isHidden = (ioc.creationFlags & 0x08000000UL) != 0;    // CREATE_NO_WINDOW
        m_createIOCs.push_back(std::move(sanitized));
    }
    } catch (const std::bad_alloc&) {
        return;
    } catch (const std::length_error&) {
        return;
    }
}

std::vector<ProcessCreateIOC> VirtualProcess::GetProcessCreationIOCs() const noexcept {
    try {
    std::shared_lock lock(m_mutex);
    return m_createIOCs;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// PEB / TEB / Heap Addresses
// ============================================================================

GuestAddress VirtualProcess::GetPEBAddress() const noexcept {
    return WinConst::kPEBAddress64;
}

GuestAddress VirtualProcess::GetTEBAddress() const noexcept {
    return WinConst::kTEBAddress64;
}

GuestAddress VirtualProcess::GetProcessHeapAddress() const noexcept {
    return WinConst::kProcessHeapBase64;
}

// ============================================================================
// PopulateProcessList — ~60 Realistic Win10 22H2 Processes
// ============================================================================
// FILETIME base: 2025-01-15 09:00:00 UTC ≈ 133_507_800_000_000_000
// Each subsequent process is created a few seconds after boot.

void VirtualProcess::PopulateProcessList(const EmulationConfig& config) {
    m_processList.clear();
    m_processList.reserve(64);

    // FILETIME base offset (boot time)
    constexpr uint64_t kBootTime = 133'507'800'000'000'000ULL;
    uint64_t t = kBootTime;

    auto add = [&](uint32_t pid, uint32_t ppid, const wchar_t* name,
                   const wchar_t* path, uint32_t threads, uint32_t handles,
                   uint64_t wsMB, uint64_t vsMB, int32_t prio,
                   uint32_t session, bool sys) {
        ProcessInfo pi{};
        pi.pid            = pid;
        pi.parentPid      = ppid;
        pi.name           = name;
        pi.imagePath      = path;
        pi.threadCount    = threads;
        pi.handleCount    = handles;
        pi.workingSetSize = wsMB;
        pi.virtualSize    = vsMB;
        pi.createTime     = t;
        pi.basePriority   = prio;
        pi.sessionId      = session;
        pi.isSystem       = sys;
        m_processList.push_back(std::move(pi));
        t += 500'000'000ULL; // 50 ms between each "boot" entry
    };

    // Helper: KB/MB constants for readability
    constexpr uint64_t KB = 1024ULL;
    constexpr uint64_t MB = 1024ULL * 1024ULL;
    const std::wstring userName = SanitizedUserName(config.userName);
    const std::wstring emulatedImagePath = L"C:\\Users\\" + userName + L"\\Downloads\\sample.exe";

    // ----- Session 0 — Kernel / System -----
    add(0,    0,   L"[System Idle Process]", L"",
        8,   0,   8  * KB,    64 * KB,  0, 0, true);
    add(4,    0,   L"System",               L"",
        180, 3200, 200 * KB,  4 * MB,  8, 0, true);
    add(104,  4,   L"Registry",             L"",
        4,   0,   60 * MB,   128 * MB, 8, 0, true);
    add(448,  4,   L"smss.exe",
        L"C:\\Windows\\System32\\smss.exe",
        2,   53,  1500 * KB,  2 * MB,  11, 0, true);

    // First CSRSS + wininit
    add(556,  448, L"csrss.exe",
        L"C:\\Windows\\System32\\csrss.exe",
        14,  570, 5 * MB,  2 * MB, 13, 0, true);
    add(612,  448, L"wininit.exe",
        L"C:\\Windows\\System32\\wininit.exe",
        1,   78,  2 * MB,  2 * MB, 13, 0, true);

    // Second CSRSS (session 1) + winlogon
    add(620,  612, L"csrss.exe",
        L"C:\\Windows\\System32\\csrss.exe",
        14,  538, 5 * MB,  2 * MB, 13, 1, false);
    add(680,  612, L"winlogon.exe",
        L"C:\\Windows\\System32\\winlogon.exe",
        5,   145, 10 * MB, 2 * MB, 13, 1, false);

    // Services + LSASS
    add(728,  612, L"services.exe",
        L"C:\\Windows\\System32\\services.exe",
        9,   340, 8 * MB,  2 * MB, 9, 0, true);
    add(748,  612, L"lsass.exe",
        L"C:\\Windows\\System32\\lsass.exe",
        10,  980, 25 * MB, 2 * MB, 9, 0, true);

    // ----- SVCHOSTs (all children of services.exe, PID 728) -----
    add(852,  728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        21,  720, 20 * MB, 2 * MB, 8, 0, true);   // DcomLaunch
    add(980,  728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        15,  490, 12 * MB, 2 * MB, 8, 0, true);   // RPCSS
    add(360,  728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        44, 1350, 30 * MB, 2 * MB, 8, 0, true);   // netsvcs
    add(424,  728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        19,  560, 15 * MB, 2 * MB, 8, 0, true);   // LocalServiceNetworkRestricted
    add(1032, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        6,   210, 8 * MB,  2 * MB, 8, 0, true);   // TermService
    add(1076, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        8,   350, 10 * MB, 2 * MB, 8, 0, true);   // LocalSystem
    add(1128, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        12,  380, 14 * MB, 2 * MB, 8, 0, true);   // LocalServiceNoNetwork
    add(1228, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        3,   120, 5 * MB,  2 * MB, 8, 0, true);   // AppXSvc
    add(1296, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        4,   160, 6 * MB,  2 * MB, 8, 0, true);   // CryptSvc
    add(1416, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        7,   280, 12 * MB, 2 * MB, 8, 0, true);   // Winmgmt
    add(1524, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        11,  440, 18 * MB, 2 * MB, 8, 0, true);   // Schedule
    add(1640, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        5,   190, 7 * MB,  2 * MB, 8, 0, true);   // ProfSvc
    add(1752, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        4,   220, 9 * MB,  2 * MB, 8, 0, true);   // EventLog
    add(1820, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        6,   260, 8 * MB,  2 * MB, 8, 0, true);   // Themes
    add(1904, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        3,   110, 5 * MB,  2 * MB, 8, 0, true);   // SessionEnv

    // Font driver host
    add(888,  680, L"fontdrvhost.exe",
        L"C:\\Windows\\System32\\fontdrvhost.exe",
        5,   35,  3 * MB,  2 * MB, 8, 1, false);

    // Spooler
    add(2024, 728, L"spoolsv.exe",
        L"C:\\Windows\\System32\\spoolsv.exe",
        12,  330, 12 * MB, 2 * MB, 8, 0, true);

    // More svchosts
    add(2088, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        8,   290, 10 * MB, 2 * MB, 8, 0, true);   // SENS

    // Windows Defender
    add(2148, 728, L"MsMpEng.exe",
        L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24120.9\\MsMpEng.exe",
        28, 1100, 300 * MB, 2 * MB, 8, 0, true);

    // WinHTTP proxy
    add(2216, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        6,   180, 7 * MB,  2 * MB, 8, 0, true);   // WinHttpAutoProxySvc

    // Search indexer
    add(2392, 728, L"SearchIndexer.exe",
        L"C:\\Windows\\System32\\SearchIndexer.exe",
        15,  760, 40 * MB, 2 * MB, 8, 0, true);

    // Security Health
    add(2520, 728, L"SecurityHealthService.exe",
        L"C:\\Windows\\System32\\SecurityHealthService.exe",
        8,   260, 15 * MB, 2 * MB, 8, 0, true);

    // COM Surrogate
    add(2648, 852, L"dllhost.exe",
        L"C:\\Windows\\System32\\dllhost.exe",
        10,  310, 14 * MB, 2 * MB, 8, 0, true);

    // ----- Session 1 — User Desktop -----
    add(2840, 852, L"sihost.exe",
        L"C:\\Windows\\System32\\sihost.exe",
        8,   430, 18 * MB, 2 * MB, 8, 1, false);
    add(2900, 852, L"taskhostw.exe",
        L"C:\\Windows\\System32\\taskhostw.exe",
        6,   210, 10 * MB, 2 * MB, 8, 1, false);

    // Explorer — the shell
    add(3000, 2840, L"explorer.exe",
        L"C:\\Windows\\explorer.exe",
        52, 2100, 150 * MB, 2 * MB, 8, 1, false);

    // Modern app hosts
    add(3244, 852, L"StartMenuExperienceHost.exe",
        L"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
        14,  480, 45 * MB, 2 * MB, 8, 1, false);
    add(3352, 852, L"RuntimeBroker.exe",
        L"C:\\Windows\\System32\\RuntimeBroker.exe",
        5,   180, 15 * MB, 2 * MB, 8, 1, false);
    add(3480, 852, L"SearchHost.exe",
        L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe",
        22,  680, 70 * MB, 2 * MB, 8, 1, false);
    add(3600, 852, L"TextInputHost.exe",
        L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe",
        8,   240, 22 * MB, 2 * MB, 8, 1, false);

    // Edge browser
    add(3748, 3000, L"msedge.exe",
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        32, 1200, 200 * MB, 2 * MB, 8, 1, false);
    add(3900, 3748, L"msedge.exe",
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        8,   340, 300 * MB, 2 * MB, 8, 1, false);  // GPU
    add(4044, 3748, L"msedge.exe",
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        12,  480, 150 * MB, 2 * MB, 8, 1, false);  // renderer
    add(4200, 3748, L"msedge.exe",
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        6,   160, 50 * MB,  2 * MB, 8, 1, false);  // utility

    // *** THE EMULATED PROCESS (PID 4444) ***
    add(kEmulatedPID, kEmulatedParentPID, L"sample.exe",
        emulatedImagePath.c_str(),
        1,   42,  8 * MB,   2 * MB, 8, 1, false);

    // Conhost for the emulated process
    add(4604, kEmulatedPID, L"conhost.exe",
        L"C:\\Windows\\System32\\conhost.exe",
        4,   85,  12 * MB, 2 * MB, 8, 1, false);

    // NisSrv (Defender network inspection)
    add(4728, 728, L"NisSrv.exe",
        L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24120.9\\NisSrv.exe",
        6,   180, 10 * MB, 2 * MB, 8, 0, true);

    // Remaining svchosts
    add(4856, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        4,   140, 6 * MB,  2 * MB, 8, 0, true);   // WdiSystemHost
    add(5432, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        3,   130, 5 * MB,  2 * MB, 8, 0, true);   // LanmanServer
    add(5600, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        4,   150, 6 * MB,  2 * MB, 8, 0, true);   // DeviceAssociationService
    add(5888, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        3,   110, 5 * MB,  2 * MB, 8, 0, true);   // CDPSvc
    add(6000, 728, L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        3,   100, 5 * MB,  2 * MB, 8, 0, true);   // WpnService

    // WMI provider
    add(5012, 852, L"WmiPrvSE.exe",
        L"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        8,   290, 18 * MB, 2 * MB, 8, 0, true);

    // CTF monitor
    add(5148, 852, L"ctfmon.exe",
        L"C:\\Windows\\System32\\ctfmon.exe",
        4,   120, 8 * MB,  2 * MB, 8, 1, false);

    // Audio device graph
    add(5300, 1076, L"audiodg.exe",
        L"C:\\Windows\\System32\\audiodg.exe",
        6,   180, 16 * MB, 2 * MB, 8, 0, true);

    // Office Click-to-Run
    add(5744, 728, L"OfficeClickToRun.exe",
        L"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe",
        20,  640, 55 * MB, 2 * MB, 8, 0, true);
}

// ============================================================================
// PopulateModuleList — Known DLLs for the emulated process
// ============================================================================
// Base addresses MUST match LibraryAPI.cpp kKnownDLLs for cross-module
// consistency.  Diverging bases will trip anti-sandbox checks.

void VirtualProcess::PopulateModuleList() {
    m_modules.clear();
    m_modules.reserve(16);

    struct ModuleDef {
        const wchar_t* name;
        const wchar_t* path;
        GuestAddress   base;
        uint32_t       size;
    };

    static constexpr ModuleDef kModules[] = {
        { L"ntdll.dll",      L"C:\\Windows\\System32\\ntdll.dll",
          0x7FF800000000ULL,  2'202'624 },                          // ~2.1 MB
        { L"kernel32.dll",   L"C:\\Windows\\System32\\kernel32.dll",
          0x7FF801000000ULL,  819'200 },                            // ~800 KB
        { L"kernelbase.dll", L"C:\\Windows\\System32\\KernelBase.dll",
          0x7FF802000000ULL,  3'358'720 },                          // ~3.2 MB
        { L"advapi32.dll",   L"C:\\Windows\\System32\\advapi32.dll",
          0x7FF803000000ULL,  716'800 },                            // ~700 KB
        { L"ws2_32.dll",     L"C:\\Windows\\System32\\ws2_32.dll",
          0x7FF804000000ULL,  92'160 },                             // ~90 KB
        { L"wininet.dll",    L"C:\\Windows\\System32\\wininet.dll",
          0x7FF805000000ULL,  1'258'496 },                          // ~1.2 MB
        { L"winhttp.dll",    L"C:\\Windows\\System32\\winhttp.dll",
          0x7FF806000000ULL,  614'400 },                            // ~600 KB
        { L"user32.dll",     L"C:\\Windows\\System32\\user32.dll",
          0x7FF807000000ULL,  1'785'856 },                          // ~1.7 MB
        { L"shell32.dll",    L"C:\\Windows\\System32\\shell32.dll",
          0x7FF808000000ULL,  23'068'672 },                         // ~22 MB
        { L"ole32.dll",      L"C:\\Windows\\System32\\ole32.dll",
          0x7FF809000000ULL,  1'572'864 },                          // ~1.5 MB
        { L"urlmon.dll",     L"C:\\Windows\\System32\\urlmon.dll",
          0x7FF80A000000ULL,  1'468'416 },                          // ~1.4 MB
        { L"msvcrt.dll",     L"C:\\Windows\\System32\\msvcrt.dll",
          0x7FF80B000000ULL,  819'200 },                            // ~800 KB
    };

    uint16_t loadOrder = 0;
    uint16_t initOrder = 0;
    for (const auto& def : kModules) {
        ModuleInfo mi{};
        mi.name           = def.name;
        mi.fullPath       = def.path;
        mi.baseAddress    = def.base;
        mi.imageSize      = def.size;
        mi.flags          = 0x00084004; // LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED
        mi.loadOrderIndex = loadOrder++;
        mi.initOrderIndex = initOrder++;
        m_modules.push_back(std::move(mi));
    }
}

} // namespace Phantom::VirtualOS
