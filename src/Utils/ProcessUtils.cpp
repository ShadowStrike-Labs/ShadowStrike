// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include "ProcessUtils.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef OBJ_PROTECT_CLOSE
#define OBJ_PROTECT_CLOSE 0x00000002UL
#endif

#include <comdef.h>
#include <Wbemidl.h>
#include <evntrace.h>
#include <evntcons.h>
#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <system_error>
#include <iomanip>
#include <OleAuto.h>
#include <processthreadsapi.h>
#include <tchar.h>
#include <powrprof.h>
#include <DbgHelp.h>
#include <sddl.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace ShadowStrike {
    namespace Utils {
        namespace ProcessUtils {

            // ==========================================================
            // Internal helpers
            // ==========================================================

            namespace {

                // ============================================================================
                // RAII Handle Wrapper for Windows HANDLE objects
                // ============================================================================
                
                using unique_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&::CloseHandle)>;

                /**
                 * @brief Creates a unique_ptr-based RAII wrapper for Windows HANDLE.
                 * @param h The handle to wrap. May be nullptr or INVALID_HANDLE_VALUE.
                 * @return A unique_handle that will automatically call CloseHandle on destruction.
                 * @note If h is nullptr or INVALID_HANDLE_VALUE, the wrapper is still valid but empty.
                 */
                [[nodiscard]] inline unique_handle make_unique_handle(HANDLE h) noexcept {
                    // Normalize invalid handles to nullptr for consistent behavior
                    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
                        return unique_handle(nullptr, &::CloseHandle);
                    }
                    return unique_handle(h, &::CloseHandle);
                }

                // Maximum buffer sizes to prevent DoS via oversized allocations
                static constexpr DWORD kMaxTokenInfoSize = 64 * 1024;        // 64KB max for token info
                static constexpr DWORD kMaxPathLength = 32768;               // MAX_PATH extended
                static constexpr DWORD kMaxProcessCount = 65536;             // Max reasonable process count
                static constexpr DWORD kMaxModuleCount = 16384;              // Max modules per process
                static constexpr DWORD kMaxThreadCount = 65536;              // Max threads per process
                static constexpr DWORD kMaxHandleCount = 16 * 1024 * 1024;   // 16M handles max

                /**
                 * @brief Sets Win32 error information in the Error struct.
                 * @param err Pointer to Error struct (may be nullptr).
                 * @param ctx Context string describing where the error occurred.
                 * @param code Win32 error code (defaults to GetLastError()).
                 * @param customMsg Optional custom message to override system message.
                 */
                void SetWin32Error(Error* err, std::wstring_view ctx, DWORD code = ::GetLastError(), std::wstring_view customMsg = L"") noexcept {
                    if (!err) return;
                    
                    err->Clear();
                    err->win32 = code;
                    
                    // Safely copy context - truncate if necessary
                    try {
                        err->context.assign(ctx.data(), std::min(ctx.size(), static_cast<size_t>(1024)));
                    } catch (...) {
                        err->context.clear();
                    }
                    
                    if (!customMsg.empty()) {
                        try {
                            err->message.assign(customMsg.data(), std::min(customMsg.size(), static_cast<size_t>(2048)));
                        } catch (...) {
                            err->message.clear();
                        }
                        return;
                    }

                    LPWSTR buf = nullptr;
                    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
                    const DWORD result = FormatMessageW(flags, nullptr, code, 
                                                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                                                        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
                    if (result > 0 && buf) {
                        try {
                            // Remove trailing newlines from system messages
                            size_t len = result;
                            while (len > 0 && (buf[len - 1] == L'\r' || buf[len - 1] == L'\n')) {
                                --len;
                            }
                            err->message.assign(buf, len);
                        } catch (...) {
                            err->message.clear();
                        }
                        LocalFree(buf);
                    }
                    else {
                        try {
                            std::wostringstream os;
                            os << L"Win32 error 0x" << std::hex << std::uppercase << code;
                            err->message = os.str();
                        } catch (...) {
                            err->message.clear();
                        }
                    }
                }

                /**
                 * @brief Sets NTSTATUS error information in the Error struct.
                 * @param err Pointer to Error struct (may be nullptr).
                 * @param ctx Context string describing where the error occurred.
                 * @param status NTSTATUS code from NT API call.
                 * @param customMsg Optional custom message.
                 */
                void SetNtError(Error* err, std::wstring_view ctx, LONG status, std::wstring_view customMsg = L"") noexcept {
                    if (!err) return;
                    
                    err->Clear();
                    err->ntstatus = status;
                    
                    try {
                        err->context.assign(ctx.data(), std::min(ctx.size(), static_cast<size_t>(1024)));
                    } catch (...) {
                        err->context.clear();
                    }
                    
                    if (!customMsg.empty()) {
                        try {
                            err->message.assign(customMsg.data(), std::min(customMsg.size(), static_cast<size_t>(2048)));
                        } catch (...) {
                            err->message.clear();
                        }
                    }
                    else {
                        try {
                            std::wostringstream os;
                            os << L"NTSTATUS 0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
                            err->message = os.str();
                        } catch (...) {
                            err->message.clear();
                        }
                    }
                }

                /**
                 * @brief Converts a wide string to lowercase (locale-independent).
                 * @param s Input string (by value for move semantics).
                 * @return Lowercase version of the string.
                 */
                [[nodiscard]] std::wstring ToLower(std::wstring s) noexcept {
                    try {
                        std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) noexcept {
                            // Use towlower for proper Unicode handling
                            return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c)));
                        });
                    } catch (...) {
                        // If transform fails, return original
                    }
                    return s;
                }

                /**
                 * @brief Extracts the filename from a full path.
                 * @param p Full path string.
                 * @return The filename portion (after last \\ or /).
                 */
                [[nodiscard]] std::wstring BaseName(const std::wstring& p) noexcept {
                    if (p.empty()) return std::wstring{};
                    
                    const size_t pos = p.find_last_of(L"\\/");
                    if (pos == std::wstring::npos) return p;
                    if (pos + 1 >= p.size()) return std::wstring{};
                    
                    try {
                        return p.substr(pos + 1);
                    } catch (...) {
                        return std::wstring{};
                    }
                }

                /**
                 * @brief Performs case-insensitive wildcard matching.
                 * @param pattern Pattern with * (any chars) and ? (single char) wildcards.
                 * @param text Text to match against the pattern.
                 * @return true if text matches pattern.
                 * @note Uses standard wildcard semantics: * = zero or more, ? = exactly one.
                 */
                [[nodiscard]] bool WildcardMatchInsensitive(std::wstring_view pattern, std::wstring_view text) noexcept {
                    if (pattern.empty()) return text.empty();
                    
                    try {
                        const auto p = ToLower(std::wstring(pattern));
                        const auto t = ToLower(std::wstring(text));

                        size_t pi = 0, ti = 0;
                        size_t star = std::wstring::npos;
                        size_t mark = 0;
                        
                        while (ti < t.size()) {
                            if (pi < p.size() && (p[pi] == L'?' || p[pi] == t[ti])) {
                                ++pi; ++ti;
                            }
                            else if (pi < p.size() && p[pi] == L'*') {
                                star = pi++;
                                mark = ti;
                            }
                            else if (star != std::wstring::npos) {
                                pi = star + 1;
                                ti = ++mark;
                            }
                            else {
                                return false;
                            }
                        }
                        
                        // Skip trailing wildcards
                        while (pi < p.size() && p[pi] == L'*') ++pi;
                        return pi == p.size();
                    } catch (...) {
                        return false;
                    }
                }

                /**
                 * @brief Enumerates top-level windows belonging to a specific process.
                 * @tparam F Callable type accepting HWND parameter.
                 * @param pid Process ID to filter by.
                 * @param f Callback function invoked for each matching window.
                 */
                template <typename F>
                void EnumerateTopLevelWindowsForPid(DWORD pid, F&& f) noexcept {
                    struct Ctx { 
                        DWORD pid; 
                        F* func;
                        bool hadError;
                    };
                    Ctx ctx{ pid, &f, false };
                    
                    auto cb = [](HWND h, LPARAM lparam) -> BOOL {
                        if (!h) return TRUE; // Continue enumeration
                        
                        auto* c = reinterpret_cast<Ctx*>(lparam);
                        if (!c || !c->func) return TRUE;
                        
                        DWORD wpid = 0;
                        GetWindowThreadProcessId(h, &wpid);
                        if (wpid == c->pid) {
                            try {
                                (*c->func)(h);
                            } catch (...) {
                                c->hadError = true;
                            }
                        }
                        return TRUE; // Continue enumeration
                    };
                    
                    EnumWindows(cb, reinterpret_cast<LPARAM>(&ctx));
                }

                /**
                 * @brief Gets the main window title for a process.
                 * @param pid Process ID.
                 * @param titleOut Output string for the window title.
                 * @return true if a window title was found.
                 * @note Selects the longest visible window title as the "main" title.
                 */
                [[nodiscard]] bool GetMainWindowTitleForPid(DWORD pid, std::wstring& titleOut) noexcept {
                    titleOut.clear();
                    std::wstring best;
                    
                    EnumerateTopLevelWindowsForPid(pid, [&best](HWND h) noexcept {
                        if (!h || !IsWindowVisible(h)) return;
                        
                        wchar_t buf[1024] = {};
                        const int len = GetWindowTextW(h, buf, static_cast<int>(std::size(buf)));
                        if (len > 0 && len < static_cast<int>(std::size(buf))) {
                            try {
                                std::wstring t(buf, static_cast<size_t>(len));
                                if (t.size() > best.size()) {
                                    best = std::move(t);
                                }
                            } catch (...) {
                                // Ignore allocation failures
                            }
                        }
                    });
                    
                    if (!best.empty()) {
                        titleOut = std::move(best);
                        return true;
                    }
                    return false;
                }

                /**
                 * @brief Queries the full image path for a process handle.
                 * @param hProcess Process handle with PROCESS_QUERY_LIMITED_INFORMATION.
                 * @param path Output string for the full path.
                 * @return true if the path was retrieved successfully.
                 */
                [[nodiscard]] bool QueryFullImagePath(HANDLE hProcess, std::wstring& path) noexcept {
                    path.clear();
                    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;
                    
                    try {
                        DWORD len = MAX_PATH;
                        std::wstring tmp(len, L'\0');
                        
                        if (!QueryFullProcessImageNameW(hProcess, 0, tmp.data(), &len)) {
                            const DWORD lastErr = GetLastError();
                            if (lastErr == ERROR_INSUFFICIENT_BUFFER && len > 0 && len < kMaxPathLength) {
                                tmp.resize(static_cast<size_t>(len) + 1);
                                len = static_cast<DWORD>(tmp.size());
                                if (!QueryFullProcessImageNameW(hProcess, 0, tmp.data(), &len)) {
                                    return false;
                                }
                            }
                            else {
                                return false;
                            }
                        }
                        
                        if (len > 0 && len < tmp.size()) {
                            tmp.resize(len);
                            path = std::move(tmp);
                            return true;
                        }
                        return false;
                    } catch (...) {
                        return false;
                    }
                }

                /**
                 * @brief Checks if a process is running under WOW64 (32-bit on 64-bit OS).
                 * @param hProcess Process handle.
                 * @param isWow64 Output flag indicating WOW64 status.
                 * @return true if the check succeeded.
                 * @note Uses IsWow64Process2 if available (Windows 10+), falls back to IsWow64Process.
                 */
                [[nodiscard]] bool IsProcessWow64Cached(HANDLE hProcess, bool& isWow64) noexcept {
                    isWow64 = false;
                    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;
                    
                    // Try IsWow64Process2 first (Windows 10 1511+)
                    typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
                    static const IsWow64Process2_t pIsWow64Process2 = 
                        reinterpret_cast<IsWow64Process2_t>(
                            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));

                    if (pIsWow64Process2) {
                        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                        if (!pIsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
                            return false;
                        }
                        // Process is WOW64 if it has a machine type and it differs from native
                        isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) && 
                                  (processMachine != nativeMachine);
                        return true;
                    }
                    
                    // Fallback to IsWow64Process
                    BOOL wow = FALSE;
                    if (!IsWow64Process(hProcess, &wow)) {
                        return false;
                    }
                    isWow64 = (wow == TRUE);
                    return true;
                }

                /**
                 * @brief Checks if the current OS is 64-bit.
                 * @return true if running on 64-bit Windows.
                 */
                [[nodiscard]] bool IsCurrentOS64Bit() noexcept {
#if defined(_WIN64)
                    return true;
#else
                    BOOL wow = FALSE;
                    if (IsWow64Process(GetCurrentProcess(), &wow)) {
                        return wow == TRUE;
                    }
                    return false;
#endif
                }

                /**
                 * @brief Gets process CPU times in milliseconds.
                 * @param hProcess Process handle.
                 * @param kernelMs Output kernel mode time in milliseconds.
                 * @param userMs Output user mode time in milliseconds.
                 * @return true if times were retrieved successfully.
                 */
                [[nodiscard]] bool GetProcessTimesMs(HANDLE hProcess, uint64_t& kernelMs, uint64_t& userMs) noexcept {
                    kernelMs = 0;
                    userMs = 0;
                    
                    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;
                    
                    FILETIME ct{}, et{}, kt{}, ut{};
                    if (!GetProcessTimes(hProcess, &ct, &et, &kt, &ut)) {
                        return false;
                    }
                    
                    // Convert FILETIME to milliseconds (100ns units to ms)
                    auto ftToMs = [](const FILETIME& ft) noexcept -> uint64_t {
                        ULARGE_INTEGER u{};
                        u.LowPart = ft.dwLowDateTime;
                        u.HighPart = ft.dwHighDateTime;
                        return u.QuadPart / 10000ULL; // 100ns to ms
                    };
                    
                    kernelMs = ftToMs(kt);
                    userMs = ftToMs(ut);
                    return true;
                }

                /**
                 * @brief CPU usage sample for delta calculations.
                 */
                struct CpuSample {
                    uint64_t kernelMs = 0;
                    uint64_t userMs = 0;
                    uint64_t timestampMs = 0;
                    DWORD affinity = 0;
                    int priority = NORMAL_PRIORITY_CLASS;
                };
                
                // Global CPU sample cache (protected by mutex)
                std::mutex g_cpuMutex;
                std::unordered_map<DWORD, CpuSample> g_cpuPrev;

                /**
                 * @brief Gets current tick count in milliseconds.
                 * @return Current tick count (wraps every ~49 days on 32-bit).
                 */
                [[nodiscard]] inline uint64_t GetTickCount64Ms() noexcept {
                    return GetTickCount64();
                }

                /**
                 * @brief Safely retrieves module information.
                 * @tparam T Module info structure type (MODULEINFO or compatible).
                 * @param hProcess Process handle.
                 * @param mod Module handle.
                 * @param mi Output module info structure.
                 * @return true if info was retrieved successfully.
                 */
                template<typename T>
                [[nodiscard]] bool SafeGetModuleInfo(HANDLE hProcess, HMODULE mod, T& mi) noexcept {
                    static_assert(sizeof(T) >= sizeof(MODULEINFO), "T must be at least MODULEINFO size");
                    std::memset(&mi, 0, sizeof(T));
                    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || !mod) return false;
                    return GetModuleInformation(hProcess, mod, reinterpret_cast<MODULEINFO*>(&mi), sizeof(T)) == TRUE;
                }

                // NT API function pointer types
                using NtSuspendProcess_t = LONG(NTAPI*)(HANDLE);
                using NtResumeProcess_t = LONG(NTAPI*)(HANDLE);

                /**
                 * @brief Gets pointer to NtSuspendProcess from ntdll.dll.
                 * @return Function pointer or nullptr if not available.
                 */
                [[nodiscard]] NtSuspendProcess_t GetNtSuspendProcess() noexcept {
                    static const auto fn = reinterpret_cast<NtSuspendProcess_t>(
                        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess"));
                    return fn;
                }
                
                /**
                 * @brief Gets pointer to NtResumeProcess from ntdll.dll.
                 * @return Function pointer or nullptr if not available.
                 */
                [[nodiscard]] NtResumeProcess_t GetNtResumeProcess() noexcept {
                    static const auto fn = reinterpret_cast<NtResumeProcess_t>(
                        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"));
                    return fn;
                }

            } // anon namespace

            // ==========================================================
            // ProcessHandle RAII Implementation
            // ==========================================================

            ProcessHandle::ProcessHandle(ProcessId pid, DWORD desiredAccess, Error* err) noexcept {
                static_cast<void>(Open(pid, desiredAccess, err));
            }

            bool ProcessHandle::Open(ProcessId pid, DWORD desiredAccess, Error* err) noexcept {
                Close();
                
                // Validate PID - 0 is System Idle Process, cannot be opened
                if (pid == 0) {
                    SetWin32Error(err, L"OpenProcess", ERROR_INVALID_PARAMETER, 
                                  L"Cannot open System Idle Process (PID 0)");
                    return false;
                }
                
                m_handle = ::OpenProcess(desiredAccess, FALSE, pid);
                if (!m_handle) {
                    SetWin32Error(err, L"OpenProcess");
                    return false;
                }
                return true;
            }

            void ProcessHandle::Close() noexcept {
                if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(m_handle);
                    m_handle = nullptr;
                }
            }

            // ==========================================================
            // Basic Process Utilities
            // ==========================================================

            ProcessId GetCurrentProcessId() noexcept {
                return ::GetCurrentProcessId();
            }

            // ==========================================================
            // Process Enumeration
            // ==========================================================

            bool EnumerateProcesses(std::vector<ProcessId>& pids, Error* err) noexcept {
                pids.clear();
                
                const HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == INVALID_HANDLE_VALUE) {
                    SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
                    return false;
                }
                
                // RAII guard for snapshot handle
                const auto snapGuard = make_unique_handle(hSnap);
                
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                
                if (!Process32FirstW(hSnap, &pe)) {
                    const DWORD lastErr = GetLastError();
                    if (lastErr != ERROR_NO_MORE_FILES) {
                        SetWin32Error(err, L"Process32FirstW", lastErr);
                        return false;
                    }
                    return true; // Empty list is valid
                }
                
                try {
                    pids.reserve(256); // Pre-allocate for typical system
                    do {
                        if (pids.size() >= kMaxProcessCount) {
                            // Safety limit reached
                            break;
                        }
                        pids.push_back(pe.th32ProcessID);
                    } while (Process32NextW(hSnap, &pe));
                } catch (const std::bad_alloc&) {
                    pids.clear();
                    SetWin32Error(err, L"EnumerateProcesses", ERROR_OUTOFMEMORY, 
                                  L"Memory allocation failed");
                    return false;
                }
                
                return true;
            }

            bool GetProcessBasicInfo(ProcessId pid, ProcessBasicInfo& info, Error* err) noexcept {
                info = {};
                info.pid = pid;

                // Get process entry from snapshot
                const HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    const auto snapGuard = make_unique_handle(hSnap);
                    
                    PROCESSENTRY32W pe{};
                    pe.dwSize = sizeof(pe);
                    if (Process32FirstW(hSnap, &pe)) {
                        do {
                            if (pe.th32ProcessID == pid) {
                                info.parentPid = pe.th32ParentProcessID;
                                info.basePriority = pe.pcPriClassBase;
                                info.threadCount = pe.cntThreads;
                                try {
                                    // Ensure null-termination safety
                                    pe.szExeFile[MAX_PATH - 1] = L'\0';
                                    info.name = pe.szExeFile;
                                } catch (...) {
                                    info.name.clear();
                                }
                                break;
                            }
                        } while (Process32NextW(hSnap, &pe));
                    }
                }

                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, nullptr)) {
                    if (err) {
                        SetWin32Error(err, L"OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)");
                    }
                    info.isSystemProcess = (pid == 4 || pid == 0);
                    return err == nullptr;
                }

                std::wstring fullPath;
                if (QueryFullImagePath(ph.Get(), fullPath)) {
                    try {
                        info.executablePath = std::move(fullPath);
                        if (info.name.empty()) {
                            info.name = BaseName(info.executablePath);
                        }
                    } catch (...) {
                        // Ignore allocation failures
                    }
                }

                FILETIME ct{}, et{}, kt{}, ut{};
                if (GetProcessTimes(ph.Get(), &ct, &et, &kt, &ut)) {
                    info.creationTime = ct;
                    info.exitTime = et;
                    info.kernelTime = kt;
                    info.userTime = ut;
                }

                DWORD sid = 0;
                if (ProcessIdToSessionId(pid, &sid)) {
                    info.sessionId = sid;
                }

                DWORD handleCount = 0;
                if (GetProcessHandleCount(ph.Get(), &handleCount)) {
                    info.handleCount = handleCount;
                }

                const DWORD priorityClass = GetPriorityClass(ph.Get());
                info.priorityClass = static_cast<int64_t>(priorityClass);

                bool wow = false;
                if (IsProcessWow64Cached(ph.Get(), wow)) {
                    info.isWow64 = wow;
                    info.is64Bit = IsCurrentOS64Bit() && !wow;
                }

                std::wstring title;
                if (GetMainWindowTitleForPid(pid, title)) {
                    try {
                        info.windowTitle = std::move(title);
                        info.hasGUI = true;
                    } catch (...) {
                        info.hasGUI = false;
                    }
                }

                info.isSystemProcess = (pid == 4 || pid == 0);

                return true;
            }

            bool EnumerateProcesses(std::vector<ProcessBasicInfo>& processes,
                const EnumerationOptions& options,
                Error* err) noexcept {
                processes.clear();
                
                std::vector<ProcessId> pids;
                if (!EnumerateProcesses(pids, err)) return false;

                const ProcessId currentPid = ::GetCurrentProcessId();
                
                try {
                    processes.reserve(std::min(pids.size(), static_cast<size_t>(1024)));
                } catch (...) {
                    // Continue without reservation
                }

                for (const auto pid : pids) {
                    // Apply filters
                    if (!options.includeIdleProcess && pid == 0) continue;
                    if (!options.includeCurrentProcess && pid == currentPid) continue;

                    ProcessBasicInfo bi{};
                    if (!GetProcessBasicInfo(pid, bi, nullptr)) continue;

                    if (!options.includeSystemProcesses && bi.isSystemProcess) continue;

                    if (options.nameFilter && !options.nameFilter->empty()) {
                        if (!WildcardMatchInsensitive(*options.nameFilter, bi.name)) continue;
                    }
                    
                    if (options.sessionFilter) {
                        DWORD sid = 0;
                        if (!ProcessIdToSessionId(pid, &sid) || sid != *options.sessionFilter) continue;
                    }
                    
                    if (options.userFilter && !options.userFilter->empty()) {
                        ProcessSecurityInfo sec{};
                        if (GetProcessSecurityInfo(pid, sec, nullptr)) {
                            if (ToLower(sec.userName) != ToLower(*options.userFilter)) continue;
                        }
                        else {
                            continue;
                        }
                    }

                    try {
                        processes.push_back(std::move(bi));
                    } catch (const std::bad_alloc&) {
                        SetWin32Error(err, L"EnumerateProcesses", ERROR_OUTOFMEMORY,
                                      L"Memory allocation failed");
                        return false;
                    }
                }

                // Apply sorting (use stable_sort for deterministic ordering)
                try {
                    if (options.sortByName) {
                        std::stable_sort(processes.begin(), processes.end(), 
                            [](const ProcessBasicInfo& a, const ProcessBasicInfo& b) noexcept {
                                return ToLower(a.name) < ToLower(b.name);
                            });
                    }
                    else if (options.sortByPid) {
                        std::stable_sort(processes.begin(), processes.end(), 
                            [](const ProcessBasicInfo& a, const ProcessBasicInfo& b) noexcept {
                                return a.pid < b.pid;
                            });
                    }
                    else if (options.sortByMemoryUsage) {
                        // Collect memory info for sorting
                        for (auto& p : processes) {
                            ProcessMemoryInfo mi{};
                            if (GetProcessMemoryInfo(p.pid, mi, nullptr)) {
                                // Store working set in handleCount temporarily (uint64_t truncated to DWORD)
                                p.handleCount = static_cast<DWORD>(std::min(mi.workingSetSize, 
                                                static_cast<SIZE_T>(MAXDWORD)));
                            }
                        }
                        std::stable_sort(processes.begin(), processes.end(), 
                            [](const ProcessBasicInfo& a, const ProcessBasicInfo& b) noexcept {
                                return a.handleCount > b.handleCount;
                            });
                    }
                    else if (options.sortByCpuUsage) {
                        // Collect CPU info for sorting
                        for (auto& p : processes) {
                            ProcessCpuInfo ci{};
                            GetProcessCpuInfo(p.pid, ci, nullptr);
                            // Store scaled CPU percentage in basePriority temporarily
                            p.basePriority = static_cast<int64_t>(std::clamp(ci.cpuUsagePercent, 0.0, 100.0) * 1000.0);
                        }
                        std::stable_sort(processes.begin(), processes.end(), 
                            [](const ProcessBasicInfo& a, const ProcessBasicInfo& b) noexcept {
                                return a.basePriority > b.basePriority;
                            });
                    }
                } catch (...) {
                    // Sorting failed, return unsorted results
                }

                return true;
            }

            // ==========================================================
            // Process Information Retrieval
            // ==========================================================

            bool GetProcessMemoryInfo(ProcessId pid, ProcessMemoryInfo& info, Error* err) noexcept {
                info = {};
                
                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, err)) {
                    return false;
                }

                PROCESS_MEMORY_COUNTERS_EX pmc{};
                pmc.cb = sizeof(pmc);
                
                if (!::GetProcessMemoryInfo(ph.Get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                    SetWin32Error(err, L"GetProcessMemoryInfo");
                    return false;
                }
                
                info.workingSetSize = pmc.WorkingSetSize;
                info.peakWorkingSetSize = pmc.PeakWorkingSetSize;
                info.privateMemorySize = pmc.PrivateUsage;
                info.pageFaultCount = pmc.PageFaultCount;
                info.pagedPoolUsage = pmc.QuotaPagedPoolUsage;
                info.nonPagedPoolUsage = pmc.QuotaNonPagedPoolUsage;
                
                return true;
            }

            bool GetProcessIOCounters(ProcessId pid, ProcessIOCounters& io, Error* err) noexcept {
                io = {};
                
                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
                    return false;
                }

                IO_COUNTERS ioc{};
                if (!::GetProcessIoCounters(ph.Get(), &ioc)) {
                    SetWin32Error(err, L"GetProcessIoCounters");
                    return false;
                }
                
                io.readOperationCount = ioc.ReadOperationCount;
                io.writeOperationCount = ioc.WriteOperationCount;
                io.otherOperationCount = ioc.OtherOperationCount;
                io.readTransferCount = ioc.ReadTransferCount;
                io.writeTransferCount = ioc.WriteTransferCount;
                io.otherTransferCount = ioc.OtherTransferCount;
                
                return true;
            }

            bool GetProcessCpuInfo(ProcessId pid, ProcessCpuInfo& info, Error* err) noexcept {
                info = {};
                info.priorityClass = NORMAL_PRIORITY_CLASS;

                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
                    return false;
                }

                DWORD_PTR affinity = 0, sysAffinity = 0;
                if (GetProcessAffinityMask(ph.Get(), &affinity, &sysAffinity)) {
                    info.affinityMask = static_cast<DWORD>(affinity);
                }
                
                const DWORD priorityClass = GetPriorityClass(ph.Get());
                info.priorityClass = (priorityClass != 0) ? static_cast<int>(priorityClass) : NORMAL_PRIORITY_CLASS;

                uint64_t kMs = 0, uMs = 0;
                if (!GetProcessTimesMs(ph.Get(), kMs, uMs)) {
                    SetWin32Error(err, L"GetProcessTimes");
                    return false;
                }

                const uint64_t now = GetTickCount64Ms();

                // Thread-safe access to CPU sample cache
                std::lock_guard<std::mutex> lock(g_cpuMutex);
                
                auto it = g_cpuPrev.find(pid);
                if (it != g_cpuPrev.end()) {
                    const auto& prev = it->second;
                    
                    // Calculate delta time (handle wrap-around)
                    const uint64_t dt = (now >= prev.timestampMs) ? (now - prev.timestampMs) : 0;
                    
                    // Calculate delta CPU time (handle counter reset)
                    const uint64_t currentTotal = kMs + uMs;
                    const uint64_t prevTotal = prev.kernelMs + prev.userMs;
                    const uint64_t dtotal = (currentTotal >= prevTotal) ? (currentTotal - prevTotal) : currentTotal;

                    if (dt > 0) {
                        // Get processor count for CPU percentage calculation
                        SYSTEM_INFO si{};
                        GetSystemInfo(&si);
                        const DWORD numProcessors = std::max<DWORD>(1, si.dwNumberOfProcessors);
                        
                        // Avoid overflow: dt * numProcessors
                        const uint64_t denom = dt * static_cast<uint64_t>(numProcessors);
                        
                        double usage = 0.0;
                        if (denom > 0) {
                            usage = (static_cast<double>(dtotal) / static_cast<double>(denom)) * 100.0;
                        }
                        
                        info.totalCpuTimeMs = currentTotal;
                        info.kernelCpuTimeMs = kMs;
                        info.userCpuTimeMs = uMs;
                        info.cpuUsagePercent = std::clamp(usage, 0.0, 100.0);
                        
                        if (dtotal > 0) {
                            const uint64_t dKernel = (kMs >= prev.kernelMs) ? (kMs - prev.kernelMs) : 0;
                            const double kpart = static_cast<double>(dKernel) / static_cast<double>(dtotal);
                            info.kernelTimePercent = std::clamp(kpart * info.cpuUsagePercent, 0.0, 100.0);
                            info.userTimePercent = std::clamp(info.cpuUsagePercent - info.kernelTimePercent, 0.0, 100.0);
                        }
                    }
                    
                    // Update sample
                    it->second = CpuSample{ kMs, uMs, now, static_cast<DWORD>(affinity), info.priorityClass };
                }
                else {
                    // First sample - can only report totals, not percentage
                    try {
                        g_cpuPrev.emplace(pid, CpuSample{ kMs, uMs, now, static_cast<DWORD>(affinity), info.priorityClass });
                    } catch (...) {
                        // Ignore allocation failure for cache
                    }
                    info.totalCpuTimeMs = kMs + uMs;
                    info.kernelCpuTimeMs = kMs;
                    info.userCpuTimeMs = uMs;
                    info.cpuUsagePercent = 0.0;
                }

                return true;
            }

#else // !_WIN32

namespace ShadowStrike {
    namespace Utils {
        namespace ProcessUtils {
            // Stub implementations for non-Windows
        }
    }
}

#endif


// ==========================================================
// Process Security Information
// ==========================================================

bool GetProcessSecurityInfo(ProcessId pid, ProcessSecurityInfo& sec, Error* err) noexcept {
    sec = {};
    
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(ph.Get(), TOKEN_QUERY, &hToken)) {
        SetWin32Error(err, L"OpenProcessToken");
        return false;
    }
    auto token = make_unique_handle(hToken);

    // User information with buffer size validation
    DWORD len = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &len);
    
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0 || len > kMaxTokenInfoSize) {
        SetWin32Error(err, L"GetTokenInformation(TokenUser) size query");
        return false;
    }
    
    std::vector<BYTE> buf;
    try {
        buf.resize(len);
    } catch (const std::bad_alloc&) {
        SetWin32Error(err, L"GetProcessSecurityInfo", ERROR_OUTOFMEMORY, L"Memory allocation failed");
        return false;
    }
    
    if (!GetTokenInformation(token.get(), TokenUser, buf.data(), static_cast<DWORD>(buf.size()), &len)) {
        SetWin32Error(err, L"GetTokenInformation(TokenUser)");
        return false;
    }
    
    auto tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    if (tu && tu->User.Sid) {
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &sidStr) && sidStr) {
            try {
                sec.userSid = sidStr;
            } catch (...) {
                sec.userSid.clear();
            }
            LocalFree(sidStr);
        }

        WCHAR name[256] = {}, domain[256] = {};
        DWORD cchName = static_cast<DWORD>(std::size(name));
        DWORD cchDomain = static_cast<DWORD>(std::size(domain));
        SID_NAME_USE use = SidTypeUnknown;
        
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &cchName, domain, &cchDomain, &use)) {
            try {
                sec.userName = std::wstring(domain) + L"\\" + std::wstring(name);
            } catch (...) {
                sec.userName.clear();
            }
        }
    }

    // Integrity level with proper validation
    len = 0;
    GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &len);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > 0 && len <= kMaxTokenInfoSize) {
        std::vector<BYTE> il;
        try {
            il.resize(len);
        } catch (...) {
            // Continue without integrity level
            il.clear();
        }
        
        if (!il.empty() && GetTokenInformation(token.get(), TokenIntegrityLevel, 
                                               il.data(), static_cast<DWORD>(il.size()), &len)) {
            auto til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(il.data());
            if (til && til->Label.Sid) {
                PUCHAR subAuthCountPtr = GetSidSubAuthorityCount(til->Label.Sid);
                if (subAuthCountPtr && *subAuthCountPtr > 0) {
                    PDWORD ridPtr = GetSidSubAuthority(til->Label.Sid, *subAuthCountPtr - 1);
                    if (ridPtr) {
                        const DWORD rid = *ridPtr;
                        if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
                            sec.integrityLevel = L"Low";
                        } else if (rid < SECURITY_MANDATORY_HIGH_RID) {
                            sec.integrityLevel = L"Medium";
                        } else if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
                            sec.integrityLevel = L"High";
                        } else {
                            sec.integrityLevel = L"System";
                        }
                    }
                }
            }
        }
    }

    // Elevation
    TOKEN_ELEVATION elev{};
    len = sizeof(elev);
    if (GetTokenInformation(token.get(), TokenElevation, &elev, sizeof(elev), &len)) {
        sec.isElevated = (elev.TokenIsElevated != 0);
    }

    // Group membership: SYSTEM / SERVICE with RAII for SIDs
    len = 0;
    GetTokenInformation(token.get(), TokenGroups, nullptr, 0, &len);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > 0 && len <= kMaxTokenInfoSize) {
        std::vector<BYTE> gr;
        try {
            gr.resize(len);
        } catch (...) {
            gr.clear();
        }
        
        if (!gr.empty() && GetTokenInformation(token.get(), TokenGroups, 
                                               gr.data(), static_cast<DWORD>(gr.size()), &len)) {
            auto tg = reinterpret_cast<TOKEN_GROUPS*>(gr.data());
            
            // RAII wrapper for SIDs
            struct SidGuard {
                PSID sid = nullptr;
                ~SidGuard() { if (sid) FreeSid(sid); }
            };
            
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            SidGuard sidSystemGuard, sidServiceGuard;
            
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 
                                     0, 0, 0, 0, 0, 0, 0, &sidSystemGuard.sid);
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_SERVICE_RID, 
                                     0, 0, 0, 0, 0, 0, 0, &sidServiceGuard.sid);
            
            if (tg) {
                for (DWORD i = 0; i < tg->GroupCount; i++) {
                    if (tg->Groups[i].Sid) {
                        if (sidSystemGuard.sid && EqualSid(tg->Groups[i].Sid, sidSystemGuard.sid)) {
                            sec.isRunningAsSystem = true;
                        }
                        if (sidServiceGuard.sid && EqualSid(tg->Groups[i].Sid, sidServiceGuard.sid)) {
                            sec.isRunningAsService = true;
                        }
                    }
                }
            }
        }
    }

    // Privileges with bounds checking
    len = 0;
    GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &len);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > 0 && len <= kMaxTokenInfoSize) {
        std::vector<BYTE> pv;
        try {
            pv.resize(len);
        } catch (...) {
            pv.clear();
        }
        
        if (!pv.empty() && GetTokenInformation(token.get(), TokenPrivileges, 
                                               pv.data(), static_cast<DWORD>(pv.size()), &len)) {
            auto tp = reinterpret_cast<TOKEN_PRIVILEGES*>(pv.data());
            if (tp) {
                try {
                    sec.enabledPrivileges.reserve(std::min(static_cast<DWORD>(64), tp->PrivilegeCount));
                } catch (...) {
                    // Continue without reservation
                }
                
                for (DWORD i = 0; i < tp->PrivilegeCount && i < 256; i++) {
                    WCHAR privName[256] = {};
                    DWORD cch = static_cast<DWORD>(std::size(privName));
                    
                    if (LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, privName, &cch)) {
                        try {
                            sec.enabledPrivileges.emplace_back(privName);
                        } catch (...) {
                            // Ignore allocation failure for individual privilege
                        }
                        
                        if (_wcsicmp(privName, L"SeDebugPrivilege") == 0) {
                            const bool enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                            sec.hasSeDebugPrivilege = enabled;
                            if (enabled) {
                                sec.hasDebugPrivilege = true;
                            }
                        }
                    }
                }
            }
        }
    }

    return true;
}

bool GetProcessInfo(ProcessId pid, ProcessInfo& info, Error* err) noexcept {
    info = {};
    if (!GetProcessBasicInfo(pid, info.basic, err)) return false;
    GetProcessMemoryInfo(pid, info.memory, nullptr);
    GetProcessIOCounters(pid, info.io, nullptr);
    GetProcessCpuInfo(pid, info.cpu, nullptr);
    GetProcessSecurityInfo(pid, info.security, nullptr);
    EnumerateProcessModules(pid, info.modules, nullptr);
    EnumerateProcessThreads(pid, info.threads, nullptr);
    return true;
}

// ==========================================================
// Process Path & Identity
// ==========================================================

std::optional<std::wstring> GetProcessPath(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return std::nullopt;
    std::wstring p;
    if (!QueryFullImagePath(ph.Get(), p)) {
        SetWin32Error(err, L"QueryFullProcessImageNameW");
        return std::nullopt;
    }
    return p;
}

std::optional<std::wstring> GetProcessCommandLine(ProcessId pid, Error* err) noexcept {
    // NtQueryInformationProcess API for PEB access
    typedef LONG(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    if (!NtQueryInformationProcess) {
        SetWin32Error(err, L"GetProcessCommandLine", ERROR_CALL_NOT_IMPLEMENTED,
            L"Failed to resolve NtQueryInformationProcess from ntdll.dll.");
        return std::nullopt;
    }

    // Open process with VM_READ to access PEB
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, err)) {
        return std::nullopt;
    }

    // Query Process Basic Information to get PEB address
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retLen = 0;
    LONG status = NtQueryInformationProcess(ph.Get(), ProcessBasicInformation,
        &pbi, sizeof(pbi), &retLen);

    if (status != 0) {
        SetNtError(err, L"NtQueryInformationProcess(ProcessBasicInformation)", status);
        return std::nullopt;
    }

    if (!pbi.PebBaseAddress) {
        SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_ADDRESS,
            L"PEB base address is invalid.");
        return std::nullopt;
    }

    // Determine if target process is WOW64
    bool isTargetWow64 = false;
    if (!IsProcessWow64Cached(ph.Get(), isTargetWow64)) {
        SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_FUNCTION,
            L"Failed to determine WOW64 status of target process.");
        return std::nullopt;
    }

    SIZE_T read = 0;
#ifdef _WIN64
    if (isTargetWow64) {
        // Reading WOW64 process from x64 process
        struct PEB32 {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            ULONG Reserved3[2];
            ULONG Ldr;
            ULONG ProcessParameters;
            // RTL_USER_PROCESS_PARAMETERS*
        };


        struct UNICODE_STRING32 {
            USHORT Length;
            USHORT MaximumLength;
            ULONG Buffer;
        };

        struct RTL_USER_PROCESS_PARAMETERS32 {
            BYTE Reserved1[16];
            ULONG Reserved2[10];
            UNICODE_STRING32 ImagePathName;
            UNICODE_STRING32 CommandLine;
        };

        PEB32 peb32{};
        SIZE_T read = 0;
        if (!::ReadProcessMemory(ph.Get(), pbi.PebBaseAddress, &peb32, sizeof(peb32), &read)) {
            SetWin32Error(err, L"ReadProcessMemory(PEB32)");
            return std::nullopt;
        }

        if (!peb32.ProcessParameters) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_ADDRESS,
                L"ProcessParameters address is invalid.");
            return std::nullopt;
        }

        RTL_USER_PROCESS_PARAMETERS32 params32{};
        if (!::ReadProcessMemory(ph.Get(),
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(peb32.ProcessParameters)),
            &params32, sizeof(params32), &read)) {
            SetWin32Error(err, L"ReadProcessMemory(RTL_USER_PROCESS_PARAMETERS32)");
            return std::nullopt;
        }

        if (!params32.CommandLine.Buffer || params32.CommandLine.Length == 0) {
            return std::wstring{};
        }

        if(params32.CommandLine.Length > 32768 || params32.CommandLine.Length % sizeof(wchar_t) != 0) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_DATA,
                L"Invalid Command Line Length.");
            return std::nullopt;
		}

        std::wstring cmdLine(params32.CommandLine.Length / sizeof(wchar_t), L'\0');
        if (!::ReadProcessMemory(ph.Get(),
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(params32.CommandLine.Buffer)),
            cmdLine.data(), params32.CommandLine.Length, &read)) {
            SetWin32Error(err, L"ReadProcessMemory(CommandLine32)");
            return std::nullopt;
        }

        if (read != params32.CommandLine.Length) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_PARTIAL_COPY,
                L"Incomplete read of command line.");
            return std::nullopt;
        }
        cmdLine.resize(params32.CommandLine.Length / sizeof(wchar_t));
        return cmdLine;
    }
    else

    {
        // Native pointer size (x64 reading x64, or x86 reading x86)
        struct PEB_INTERNAL {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PVOID Ldr;
            PVOID ProcessParameters;
            // RTL_USER_PROCESS_PARAMETERS*
        };

        struct RTL_USER_PROCESS_PARAMETERS_INTERNAL {
            BYTE Reserved1[16];
            PVOID Reserved2[10];
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
        };

        PEB_INTERNAL peb{};
        
        if (!::ReadProcessMemory(ph.Get(), pbi.PebBaseAddress, &peb, sizeof(peb), &read)) {
            SetWin32Error(err, L"ReadProcessMemory(PEB)");
            return std::nullopt;
        }

        if (!peb.ProcessParameters) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_ADDRESS,
                L"ProcessParameters value is invalid");
            return std::nullopt;
        }

        RTL_USER_PROCESS_PARAMETERS_INTERNAL params{};
        if (!::ReadProcessMemory(ph.Get(), peb.ProcessParameters, &params, sizeof(params), &read)) {
            SetWin32Error(err, L"ReadProcessMemory(RTL_USER_PROCESS_PARAMETERS)");
            return std::nullopt;
        }

        if (!params.CommandLine.Buffer || params.CommandLine.Length == 0) {
            return std::wstring{};
        }

        // Validate command line length (security check)
        if (params.CommandLine.Length > 32768 || params.CommandLine.Length % sizeof(wchar_t) != 0) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_DATA,
                L"Command line length is invalid");
            return std::nullopt;
        }
        if (!params.CommandLine.Buffer) {
            return std::wstring{};
        }

        //Probe read access before allocating memory
        MEMORY_BASIC_INFORMATION mbi{};
        if (!::VirtualQueryEx(ph.Get(), params.CommandLine.Buffer, &mbi, sizeof(mbi))) {
            SetWin32Error(err, L"VirtualQueryEx(CommandLine)");
            return std::nullopt;
        }

        //Check if memory region is readable
        if (!(mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_ADDRESS,
                L"Command line buffer is not readable");
            return std::nullopt;
        }

        // Check if the entire buffer is within the valid region
        if (params.CommandLine.Length > mbi.RegionSize -
            (reinterpret_cast<uintptr_t>(params.CommandLine.Buffer) -
                reinterpret_cast<uintptr_t>(mbi.BaseAddress))) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_INVALID_DATA,
                L"Command line buffer exceeds memory region");
            return std::nullopt;
        }


        std::wstring cmdLine;
        try {
            cmdLine.resize(params.CommandLine.Length / sizeof(wchar_t), L'\0');
        }
        catch (const std::bad_alloc&) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_NOT_ENOUGH_MEMORY,
                L"Memory allocation failed");
            return std::nullopt;
        }

        //SIZE_T read = 0;
        if (!::ReadProcessMemory(ph.Get(), params.CommandLine.Buffer,
            cmdLine.data(), params.CommandLine.Length, &read)) {
            SetWin32Error(err, L"ReadProcessMemory(CommandLine)");
            return std::nullopt;
        }

        // Validate actual bytes read
        if (read != params.CommandLine.Length) {
            SetWin32Error(err, L"GetProcessCommandLine", ERROR_PARTIAL_COPY,
                L"Incomplete read of command line");
            return std::nullopt;
        }

        cmdLine.resize(params.CommandLine.Length / sizeof(wchar_t));

        // Sanitize: Remove any embedded nulls and validate UTF-16
        for (size_t i = 0; i < cmdLine.size(); ++i) {
            if (cmdLine[i] == L'\0') {
                cmdLine.resize(i);
                break;
            }
        }

        return cmdLine;
#endif
    }
}

std::optional<std::wstring> GetProcessName(ProcessId pid, Error* err) noexcept {
    auto p = GetProcessPath(pid, err);
    if (!p) return std::nullopt;
    return BaseName(*p);
}

std::optional<std::wstring> GetProcessWindowTitle(ProcessId pid, Error* /*err*/) noexcept {
    std::wstring t;
    if (GetMainWindowTitleForPid(pid, t)) return t;
    return std::nullopt;
}

// ==========================================================
// Process Tree & Relationships
// ==========================================================

/**
 * @brief Gets the parent process ID for a given process.
 * 
 * @param pid Process ID to query.
 * @param err Optional error output.
 * @return Parent process ID if found, std::nullopt otherwise.
 */
[[nodiscard]]
std::optional<ProcessId> GetParentProcessId(ProcessId pid, Error* err) noexcept {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return std::nullopt;
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot
    
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapGuard.get(), &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                return pe.th32ParentProcessID;
            }
        } while (Process32NextW(snapGuard.get(), &pe));
    }
    return std::nullopt;
}

/**
 * @brief Gets all direct child processes of a parent process.
 * 
 * @param parentPid Parent process ID.
 * @param children Output vector of child process IDs.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool GetChildProcesses(ProcessId parentPid, std::vector<ProcessId>& children, Error* err) noexcept {
    children.clear();
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return false;
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot
    
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapGuard.get(), &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid) {
                try {
                    children.push_back(pe.th32ProcessID);
                } catch (const std::bad_alloc&) {
                    SetWin32Error(err, L"GetChildProcesses", ERROR_NOT_ENOUGH_MEMORY,
                        L"Failed to allocate memory for child process list.");
                    return false;
                }
            }
        } while (Process32NextW(snapGuard.get(), &pe));
    }
    return true;
}

bool BuildProcessTree(ProcessDependencyGraph& graph, Error* err) noexcept {
    graph.childProcesses.clear();
    graph.processInfo.clear();
    graph.orphanedProcesses.clear();

    std::vector<ProcessBasicInfo> plist;
    if (!EnumerateProcesses(plist, EnumerationOptions{}, err)) return false;

    std::unordered_map<ProcessId, ProcessId> parent;
    for (const auto& p : plist) {
        parent[p.pid] = p.parentPid;
        graph.processInfo[p.pid] = p;
    }
    for (const auto& p : plist) {
        if (p.pid == 0) continue;
        graph.childProcesses[p.parentPid].push_back(p.pid);
    }
    for (const auto& p : plist) {
        if (p.pid == 0) continue;
        if (parent.find(p.parentPid) == parent.end()) {
            graph.orphanedProcesses.insert(p.pid);
        }
    }
    return true;
}

// ==========================================================
// Process Existence & State
// ==========================================================

/**
 * @brief Checks if a process is currently running by PID.
 * 
 * @param pid Process ID to check.
 * @return true if process exists and is running, false otherwise.
 */
[[nodiscard]]
bool IsProcessRunning(ProcessId pid) noexcept {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h) {
        return false;
    }
    auto guard = make_unique_handle(h);  // RAII for process handle
    
    DWORD code = 0;
    if (!GetExitCodeProcess(guard.get(), &code)) {
        return false;
    }
    return (code == STILL_ACTIVE);
}

bool IsProcessRunning(std::wstring_view processName) noexcept {
    std::vector<ProcessId> pids;
    if (!EnumerateProcesses(pids, nullptr)) return false;
    std::wstring target = ToLower(std::wstring(processName));
    for (auto pid : pids) {
        auto name = GetProcessName(pid, nullptr);
        if (name && ToLower(*name) == target) return true;
    }
    return false;
}

bool IsProcess64Bit(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    bool wow = false;
    if (!IsProcessWow64Cached(ph.Get(), wow)) {
        SetWin32Error(err, L"IsWow64Process/2");
        return false;
    }
    return IsCurrentOS64Bit() && !wow;
}

bool IsProcessElevated(ProcessId pid, Error* err) noexcept {
    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) return false;
    return sec.isElevated;
}

bool IsProcessCritical(ProcessId pid, Error* err) noexcept {
    typedef LONG(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    if (!NtQueryInformationProcess) {
        SetWin32Error(err, L"NtQueryInformationProcess", ERROR_CALL_NOT_IMPLEMENTED, 
            L"Failed to resolve NtQueryInformationProcess from ntdll.dll.");
        return false;
    }

    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

    ULONG breakOnTerm = 0;
    ULONG retLen = 0;
    LONG status = NtQueryInformationProcess(ph.Get(), ProcessBreakOnTermination, &breakOnTerm, sizeof(breakOnTerm), &retLen);
    if (status != 0) {
        SetNtError(err, L"NtQueryInformationProcess(ProcessBreakOnTermination)", status);
        return false;
    }
    return breakOnTerm != 0;
}

bool IsProcessProtected(ProcessId pid, Error* err) noexcept {
    typedef BOOL(WINAPI* GetProcessInformation_t)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
    static auto GetProcessInformationDyn = reinterpret_cast<GetProcessInformation_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessInformation"));
    if (!GetProcessInformationDyn) {
        SetWin32Error(err, L"GetProcessInformation", ERROR_CALL_NOT_IMPLEMENTED, 
            L"ProcessProtectionLevel query is not supported on this Windows version.");
        return false;
    }
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

    PROCESS_PROTECTION_LEVEL_INFORMATION ppl{};
    if (!GetProcessInformationDyn(ph.Get(), ProcessProtectionLevelInfo, &ppl, sizeof(ppl))) {
        SetWin32Error(err, L"GetProcessInformation(ProcessProtectionLevelInfo)");
        return false;
    }
    return ppl.ProtectionLevel != PROTECTION_LEVEL_NONE;
}

/**
 * @brief Checks if a process is fully suspended (all threads suspended).
 * 
 * @param pid Process ID to check.
 * @param err Unused but kept for API consistency.
 * @return true if all threads are suspended, false otherwise.
 * 
 * @warning This function temporarily suspends threads to check their state.
 */
[[nodiscard]]
bool IsProcessSuspended(ProcessId pid, Error* /*err*/) noexcept {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool anyThread = false;
    bool anyRunning = false;
    
    if (Thread32First(snapGuard.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                anyThread = true;
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    auto threadGuard = make_unique_handle(hThread);  // RAII for thread handle
                    
                    // Suspend to get previous suspend count
                    DWORD prev = ::SuspendThread(threadGuard.get());
                    if (prev == static_cast<DWORD>(-1)) {
                        anyRunning = true;
                    }
                    else {
                        // If previous count was 0, thread was running
                        if (prev == 0) {
                            anyRunning = true;
                        }
                        // Resume to restore original state
                        ::ResumeThread(threadGuard.get());
                    }
                }
                else {
                    // Can't open thread - assume running
                    anyRunning = true;
                }
            }
        } while (Thread32Next(snapGuard.get(), &te));
    }
    
    return anyThread && !anyRunning;
}

// ==========================================================
// Process Control & Manipulation
// ==========================================================

bool SuspendProcess(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, nullptr)) {
        if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    }
    
    // Try native API first (atomic operation)
    if (auto fn = GetNtSuspendProcess()) {
        LONG st = fn(ph.Get());
        if (st != 0) { 
            SetNtError(err, L"NtSuspendProcess", st); 
            return false; 
        }
        return true;
    }
    
    // Fallback: suspend each thread individually
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { 
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)"); 
        return false; 
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snapGuard.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { 
                    auto threadGuard = make_unique_handle(hThread);
                    ::SuspendThread(threadGuard.get());
                }
            }
        } while (Thread32Next(snapGuard.get(), &te));
    }
    return true;
}

/**
 * @brief Resumes a suspended process.
 * 
 * Uses NtResumeProcess if available, otherwise resumes all threads individually.
 * 
 * @param pid Process ID to resume.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool ResumeProcess(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, nullptr)) {
        if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    }
    
    // Try native API first (atomic operation)
    if (auto fn = GetNtResumeProcess()) {
        LONG st = fn(ph.Get());
        if (st != 0) { 
            SetNtError(err, L"NtResumeProcess", st); 
            return false; 
        }
        return true;
    }
    
    // Fallback: resume each thread individually
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { 
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)"); 
        return false; 
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snapGuard.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { 
                    auto threadGuard = make_unique_handle(hThread);
                    // Resume until suspend count is 0
                    while (::ResumeThread(threadGuard.get()) > 0) {
                        // Continue resuming
                    }
                }
            }
        } while (Thread32Next(snapGuard.get(), &te));
    }
    return true;
}

bool SetProcessPriority(ProcessId pid, DWORD priorityClass, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    if (!::SetPriorityClass(ph.Get(), priorityClass)) {
        SetWin32Error(err, L"SetPriorityClass");
        return false;
    }
    return true;
}

bool SetProcessAffinity(ProcessId pid, DWORD_PTR affinityMask, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    if (!::SetProcessAffinityMask(ph.Get(), affinityMask)) {
        SetWin32Error(err, L"SetProcessAffinityMask");
        return false;
    }
    return true;
}

bool SetProcessWorkingSetSize(ProcessId pid, SIZE_T minSize, SIZE_T maxSize, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    if (!::SetProcessWorkingSetSizeEx(ph.Get(), minSize, maxSize, QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_ENABLE)) {
        SetWin32Error(err, L"SetProcessWorkingSetSizeEx");
        return false;
    }
    return true;
}

// ==========================================================
// Module Operations
// ==========================================================

bool EnumerateProcessModules(ProcessId pid, std::vector<ProcessModuleInfo>& modules, Error* err) noexcept {
    modules.clear();
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err)) return false;

    DWORD needed = 0;
    if (!EnumProcessModulesEx(ph.Get(), nullptr, 0, &needed, LIST_MODULES_ALL)) {
        SetWin32Error(err, L"EnumProcessModulesEx(size)");
        return false;
    }
    std::vector<HMODULE> mods(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(ph.Get(), mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)) {
        SetWin32Error(err, L"EnumProcessModulesEx(data)");
        return false;
    }

    wchar_t path[MAX_PATH];
    for (HMODULE m : mods) {
        ProcessModuleInfo mi{};
        MODULEINFO kmi{};
        if (SafeGetModuleInfo(ph.Get(), m, kmi)) {
            mi.baseAddress = kmi.lpBaseOfDll;
            mi.size = kmi.SizeOfImage;
            mi.entryPoint = kmi.EntryPoint;
        }

        if (GetModuleFileNameExW(ph.Get(), m, path, MAX_PATH)) {
            mi.path = path;
            mi.name = BaseName(mi.path);
        }
        wchar_t winDir[MAX_PATH]{};
        GetWindowsDirectoryW(winDir, MAX_PATH);
        if (wcslen(winDir) > 0) {
            std::wstring winPath = std::wstring(winDir) + L"\\";
            mi.isSystemModule = ToLower(mi.path).find(ToLower(winPath)) == 0;
        }
        modules.push_back(std::move(mi));
    }

    return true;
}

std::optional<ProcessModuleInfo> GetModuleInfo(ProcessId pid, std::wstring_view moduleName, Error* err) noexcept {
    std::vector<ProcessModuleInfo> modules;
    if (!EnumerateProcessModules(pid, modules, err)) return std::nullopt;
    std::wstring target = ToLower(std::wstring(moduleName));
    for (auto& m : modules) {
        if (ToLower(m.name) == target) return m;
    }
    return std::nullopt;
}

std::optional<void*> GetModuleBaseAddress(ProcessId pid, std::wstring_view moduleName, Error* err) noexcept {
    auto mi = GetModuleInfo(pid, moduleName, err);
    if (!mi) return std::nullopt;
    return mi->baseAddress;
}

std::optional<void*> GetModuleExportAddress(ProcessId pid, std::wstring_view moduleName, std::string_view exportName, Error* err) noexcept {
    if (pid == ::GetCurrentProcessId()) {
        HMODULE hMod = GetModuleHandleW(std::wstring(moduleName).c_str());
        if (!hMod) {
            SetWin32Error(err, L"GetModuleHandleW");
            return std::nullopt;
        }
        FARPROC p = GetProcAddress(hMod, exportName.data());
        if (!p) {
            SetWin32Error(err, L"GetProcAddress");
            return std::nullopt;
        }
        return reinterpret_cast<void*>(p);
    }
    SetWin32Error(err, L"GetModuleExportAddress", ERROR_NOT_SUPPORTED, L"Getting module export address is not supported");
    return std::nullopt;
}

bool InjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err) noexcept {
    // Validate DLL path exists and is accessible
    if (dllPath.empty()) {
        SetWin32Error(err, L"InjectDLL", ERROR_INVALID_PARAMETER, L"DLL path cant be empty.");
        return false;
    }

    DWORD attrs = GetFileAttributesW(std::wstring(dllPath).c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        SetWin32Error(err, L"InjectDLL", ERROR_FILE_NOT_FOUND, L"failed to find the DLL file.");
        return false;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        SetWin32Error(err, L"InjectDLL", ERROR_DIRECTORY, L"The specified path is a directory.");
        return false;
    }

    // Open target process WITH SYNCHRONIZE for locking
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        SYNCHRONIZE, err)) { // ✅ SYNCHRONIZE eklendi
        return false;
    }

    // Architecture compatibility check
    bool isTargetWow64 = false;
    if (!IsProcessWow64Cached(ph.Get(), isTargetWow64)) {
        SetWin32Error(err, L"InjectDLL", ERROR_INVALID_FUNCTION,
            L"Target process architecture failed to find.");
        return false;
    }

#ifdef _WIN64
    bool isCurrentWow64 = false;
#else
    bool isCurrentWow64 = true;
#endif

    if (isCurrentWow64 != isTargetWow64) {
        SetWin32Error(err, L"InjectDLL", ERROR_BAD_EXE_FORMAT,
            L"Architectures are incompatible.");
        return false;
    }

    // Get full path to DLL
    wchar_t fullPath[MAX_PATH * 2] = {};
    DWORD len = GetFullPathNameW(std::wstring(dllPath).c_str(), MAX_PATH * 2, fullPath, nullptr);
    if (len == 0 || len >= MAX_PATH * 2) {
        SetWin32Error(err, L"GetFullPathNameW");
        return false;
    }

    // CREATE A NAMED MUTEX FOR INJECTION SYNCHRONIZATION
    // This prevents multiple injectors from racing
    std::wstring mutexName = L"Global\\ShadowStrike_Inject_" + std::to_wstring(pid);
    HANDLE hMutex = ::CreateMutexW(nullptr, FALSE, mutexName.c_str());
    if (!hMutex) {
        SetWin32Error(err, L"CreateMutexW");
        return false;
    }

    auto mutexGuard = make_unique_handle(hMutex);

    // Wait for mutex with timeout (prevent deadlock)
    DWORD mutexWait = ::WaitForSingleObject(hMutex, 5000); // 5 second timeout
    if (mutexWait != WAIT_OBJECT_0) {
        SetWin32Error(err, L"InjectDLL", ERROR_TIMEOUT,
            L"Failed to acquire injection mutex (another injection in progress?)");
        return false;
    }

    //  RAII mutex releaser
    struct MutexReleaser {
        HANDLE mutex;
        ~MutexReleaser() { if (mutex) ::ReleaseMutex(mutex); }
    } mutexReleaser{ hMutex };

    //  NOW WE HAVE EXCLUSIVE ACCESS - CHECK AGAIN
    std::vector<ProcessModuleInfo> modules;
    std::wstring targetDllName = BaseName(fullPath);

    if (EnumerateProcessModules(pid, modules, nullptr)) {
        for (const auto& mod : modules) {
            if (ToLower(mod.name) == ToLower(targetDllName)) {
                SetWin32Error(err, L"InjectDLL", ERROR_ALREADY_EXISTS,
                    L"DLL is already loaded in the target process.");
                return false;
            }
        }
    }

    //  ALLOCATE MEMORY (now under mutex protection)
    size_t pathSize = (wcslen(fullPath) + 1) * sizeof(wchar_t);
    void* remoteMemory = ::VirtualAllocEx(ph.Get(), nullptr, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMemory) {
        SetWin32Error(err, L"VirtualAllocEx");
        return false;
    }

    //  IMPROVED RAII wrapper with proper cleanup
    struct MemoryGuard {
        HANDLE process;
        void* memory;
        ~MemoryGuard() {
            if (memory && process) {
                ::VirtualFreeEx(process, memory, 0, MEM_RELEASE);
            }
        }
    } memGuard{ ph.Get(), remoteMemory };

    // Write DLL path to remote process
    SIZE_T written = 0;
    if (!::WriteProcessMemory(ph.Get(), remoteMemory, fullPath, pathSize, &written) ||
        written != pathSize) {
        SetWin32Error(err, L"WriteProcessMemory");
        return false;
    }

    // Get address of LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        SetWin32Error(err, L"GetModuleHandleW(kernel32.dll)");
        return false;
    }

    FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        SetWin32Error(err, L"GetProcAddress(LoadLibraryW)");
        return false;
    }

    // Create remote thread
    HANDLE hThread = ::CreateRemoteThread(
        ph.Get(),
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
        remoteMemory,
        0,
        nullptr
    );

    if (!hThread) {
        SetWin32Error(err, L"CreateRemoteThread");
        return false;
    }

    auto threadGuard = make_unique_handle(hThread);

    // Wait for thread completion
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult != WAIT_OBJECT_0) {
        if (waitResult == WAIT_TIMEOUT) {
            //  TRY TO TERMINATE HUNG THREAD
            ::TerminateThread(hThread, ERROR_TIMEOUT);
            SetWin32Error(err, L"InjectDLL", ERROR_TIMEOUT,
                L"DLL loading process timed out.");
        }
        else {
            SetWin32Error(err, L"WaitForSingleObject");
        }
        return false;
    }

    // Get thread exit code
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        SetWin32Error(err, L"GetExitCodeThread");
        return false;
    }

    // Check if LoadLibrary succeeded
    if (exitCode == 0) {
        SetWin32Error(err, L"InjectDLL", ERROR_MOD_NOT_FOUND,
            L"LoadLibraryW failed in target process. DLL dependencies might be missing.");
        return false;
    }

    //  FINAL VERIFICATION (still under mutex)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    bool verified = false;
    if (EnumerateProcessModules(pid, modules, nullptr)) {
        for (const auto& mod : modules) {
            if (ToLower(mod.name) == ToLower(targetDllName)) {
                // ADDITIONAL CHECK: Verify base address matches HMODULE returned
                if (reinterpret_cast<uintptr_t>(mod.baseAddress) ==
                    static_cast<uintptr_t>(exitCode)) {
                    verified = true;
                    break;
                }
            }
        }
    }

    if (!verified) {
        SetWin32Error(err, L"InjectDLL", ERROR_MOD_NOT_FOUND,
            L"DLL loaded but verification failed (possible race condition detected)");
        return false;
    }

    //  SUCCESS - Mutex will be released by RAII
    return true;
}

bool EjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err) noexcept {
    if (dllPath.empty()) {
        SetWin32Error(err, L"EjectDLL", ERROR_INVALID_PARAMETER, L"DLL path cant be empty.");
        return false;
    }

    // Open target process
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_READ, err)) {
        return false;
    }

    // Get module list and find target DLL
    std::vector<ProcessModuleInfo> modules;
    if (!EnumerateProcessModules(pid, modules, err)) {
        return false;
    }

    std::wstring targetDllName = BaseName(std::wstring(dllPath));
    void* moduleBase = nullptr;

    for (const auto& mod : modules) {
        if (ToLower(mod.name) == ToLower(targetDllName)) {
            moduleBase = mod.baseAddress;
            break;
        }
    }

    if (!moduleBase) {
        SetWin32Error(err, L"EjectDLL", ERROR_MOD_NOT_FOUND,
            L"failed to find the DLL in the target process.");
        return false;
    }

    // Prevent ejection of critical system modules
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring winDirLower = ToLower(std::wstring(winDir));

    for (const auto& mod : modules) {
        if (ToLower(mod.name) == ToLower(targetDllName)) {
            std::wstring modPathLower = ToLower(mod.path);
            if (modPathLower.find(winDirLower) == 0) {
                SetWin32Error(err, L"EjectDLL", ERROR_ACCESS_DENIED,
                    L"We are not allowing to export the system Dlls.");
                return false;
            }
            break;
        }
    }

    // Get address of FreeLibrary in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        SetWin32Error(err, L"GetModuleHandleW(kernel32.dll)");
        return false;
    }

    FARPROC freeLibraryAddr = GetProcAddress(hKernel32, "FreeLibrary");
    if (!freeLibraryAddr) {
        SetWin32Error(err, L"GetProcAddress(FreeLibrary)");
        return false;
    }

    // Create remote thread to execute FreeLibrary
    HANDLE hThread = ::CreateRemoteThread(
        ph.Get(),
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibraryAddr),
        moduleBase,
        0,
        nullptr
    );

    if (!hThread) {
        SetWin32Error(err, L"CreateRemoteThread");
        return false;
    }

    auto threadGuard = make_unique_handle(hThread);

    // Wait for the thread to complete
    DWORD waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
    if (waitResult != WAIT_OBJECT_0) {
        if (waitResult == WAIT_TIMEOUT) {
            SetWin32Error(err, L"EjectDLL", ERROR_TIMEOUT,
                L"DLL ejecting process is timed out.");
        }
        else {
            SetWin32Error(err, L"WaitForSingleObject");
        }
        return false;
    }

    // Get thread exit code (non-zero indicates success for FreeLibrary)
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        SetWin32Error(err, L"GetExitCodeThread");
        return false;
    }

    if (exitCode == 0) {
        SetWin32Error(err, L"EjectDLL", ERROR_GEN_FAILURE,
            L"FreeLibrary is failed at the target process.");
        return false;
    }

    // Verify DLL is now unloaded
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (EnumerateProcessModules(pid, modules, nullptr)) {
        for (const auto& mod : modules) {
            if (ToLower(mod.name) == ToLower(targetDllName)) {
                // DLL still loaded, might have multiple instances
                SetWin32Error(err, L"EjectDLL", ERROR_SUCCESS,
                    L"DLL is still loaded, might have multiple instances");
                return true; // Technically succeeded in calling FreeLibrary
            }
        }
    }

    return true; // Successfully ejected
}

// ==========================================================
// Thread Operations
// ==========================================================

bool EnumerateProcessThreads(ProcessId pid, std::vector<ProcessThreadInfo>& threads, Error* err) noexcept {
    threads.clear();
    
    const HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)");
        return false;
    }
    
    // RAII guard for snapshot handle
    const auto snapGuard = make_unique_handle(hSnap);
    
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    
    if (!Thread32First(hSnap, &te)) {
        const DWORD lastErr = GetLastError();
        if (lastErr != ERROR_NO_MORE_FILES) {
            SetWin32Error(err, L"Thread32First", lastErr);
            return false;
        }
        return true; // Empty is valid
    }
    
    try {
        threads.reserve(64); // Reasonable initial reservation
    } catch (...) {
        // Continue without reservation
    }
    
    do {
        if (te.th32OwnerProcessID == pid) {
            if (threads.size() >= kMaxThreadCount) {
                break; // Safety limit
            }
            
            ProcessThreadInfo ti{};
            ti.tid = te.th32ThreadID;
            ti.ownerPid = te.th32OwnerProcessID;
            ti.basePriority = te.tpBasePri;

            // Open thread for additional info
            HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread) {
                auto threadGuard = make_unique_handle(hThread);
                
                FILETIME ct{}, et{}, kt{}, ut{};
                if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
                    ti.creationTime = ct;
                    ti.exitTime = et;
                    ti.kernelTime = kt;
                    ti.userTime = ut;
                }
                
                // Check if suspended (only if not current thread)
                const ThreadId currentTid = ::GetCurrentThreadId();
                if (te.th32ThreadID != currentTid) {
                    const DWORD prev = ::SuspendThread(hThread);
                    if (prev != static_cast<DWORD>(-1)) {
                        ti.isSuspended = (prev > 0);
                        ::ResumeThread(hThread);
                    }
                }
            }
            
            try {
                threads.push_back(std::move(ti));
            } catch (const std::bad_alloc&) {
                SetWin32Error(err, L"EnumerateProcessThreads", ERROR_OUTOFMEMORY, 
                              L"Memory allocation failed");
                return false;
            }
        }
    } while (Thread32Next(hSnap, &te));
    
    return true;
}

std::optional<ProcessThreadInfo> GetThreadInfo(ThreadId tid, Error* err) noexcept {
    ProcessThreadInfo ti{};
    ti.tid = tid;

    HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) {
        SetWin32Error(err, L"OpenThread");
        return std::nullopt;
    }
    
    auto threadGuard = make_unique_handle(hThread);
    
    FILETIME ct{}, et{}, kt{}, ut{};
    if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
        ti.creationTime = ct;
        ti.exitTime = et;
        ti.kernelTime = kt;
        ti.userTime = ut;
    }
    
    // Check suspended state (avoid suspending current thread)
    const ThreadId currentTid = ::GetCurrentThreadId();
    if (tid != currentTid) {
        const DWORD prev = ::SuspendThread(hThread);
        if (prev != static_cast<DWORD>(-1)) {
            ti.isSuspended = (prev > 0);
            ::ResumeThread(hThread);
        }
    }
    else {
        ti.isSuspended = false;
    }
    
    return ti;
}

bool SuspendThread(ThreadId tid, Error* err) noexcept {
    // Prevent suspending current thread
    if (tid == ::GetCurrentThreadId()) {
        SetWin32Error(err, L"SuspendThread", ERROR_INVALID_PARAMETER, 
                      L"Cannot suspend current thread");
        return false;
    }
    
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) {
        SetWin32Error(err, L"OpenThread");
        return false;
    }
    
    auto threadGuard = make_unique_handle(h);
    
    const DWORD r = ::SuspendThread(h);
    if (r == static_cast<DWORD>(-1)) {
        SetWin32Error(err, L"SuspendThread");
        return false;
    }
    
    return true;
}

bool ResumeThread(ThreadId tid, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) {
        SetWin32Error(err, L"OpenThread");
        return false;
    }
    
    auto threadGuard = make_unique_handle(h);
    
    const DWORD r = ::ResumeThread(h);
    if (r == static_cast<DWORD>(-1)) {
        SetWin32Error(err, L"ResumeThread");
        return false;
    }
    
    return true;
}

bool TerminateThread(ThreadId tid, DWORD exitCode, Error* err) noexcept {
    // Prevent terminating current thread
    if (tid == ::GetCurrentThreadId()) {
        SetWin32Error(err, L"TerminateThread", ERROR_INVALID_PARAMETER, 
                      L"Cannot terminate current thread");
        return false;
    }
    
    HANDLE h = OpenThread(THREAD_TERMINATE, FALSE, tid);
    if (!h) {
        SetWin32Error(err, L"OpenThread");
        return false;
    }
    
    auto threadGuard = make_unique_handle(h);
    
    if (!::TerminateThread(h, exitCode)) {
        SetWin32Error(err, L"TerminateThread");
        return false;
    }
    
    return true;
}

bool SetThreadPriority(ThreadId tid, int priority, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
    if (!h) {
        SetWin32Error(err, L"OpenThread");
        return false;
    }
    
    auto threadGuard = make_unique_handle(h);
    
    if (!::SetThreadPriority(h, priority)) {
        SetWin32Error(err, L"SetThreadPriority");
        return false;
    }
    
    return true;
}

bool SetThreadAffinity(ThreadId tid, DWORD_PTR affinityMask, Error* err) noexcept {
    // Validate affinity mask is not empty
    if (affinityMask == 0) {
        SetWin32Error(err, L"SetThreadAffinity", ERROR_INVALID_PARAMETER,
                      L"Affinity mask cannot be zero");
        return false;
    }
    
    HANDLE h = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) {
        SetWin32Error(err, L"OpenThread");
        return false;
    }
    
    auto threadGuard = make_unique_handle(h);
    
    const auto prev = ::SetThreadAffinityMask(h, affinityMask);
    if (!prev) {
        SetWin32Error(err, L"SetThreadAffinityMask");
        return false;
    }
    
    return true;
}


// ==========================================================
// Memory Operations
// ==========================================================

bool ReadProcessMemory(ProcessId pid, void* address, void* buffer, SIZE_T size,
    SIZE_T* bytesRead, Error* err) noexcept {
    
    // Validate parameters
    if (!address) {
        SetWin32Error(err, L"ReadProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Source address is null");
        return false;
    }
    if (!buffer) {
        SetWin32Error(err, L"ReadProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Destination buffer is null");
        return false;
    }
    if (size == 0) {
        if (bytesRead) *bytesRead = 0;
        return true; // Reading 0 bytes always succeeds
    }
    
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    
    SIZE_T br = 0;
    if (!::ReadProcessMemory(ph.Get(), address, buffer, size, &br)) {
        SetWin32Error(err, L"ReadProcessMemory");
        return false;
    }
    
    if (bytesRead) *bytesRead = br;
    return true;
}

bool WriteProcessMemory(ProcessId pid, void* address, const void* buffer, SIZE_T size,
    SIZE_T* bytesWritten, Error* err) noexcept {
    
    // Validate parameters
    if (!address) {
        SetWin32Error(err, L"WriteProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Destination address is null");
        return false;
    }
    if (!buffer) {
        SetWin32Error(err, L"WriteProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Source buffer is null");
        return false;
    }
    if (size == 0) {
        if (bytesWritten) *bytesWritten = 0;
        return true; // Writing 0 bytes always succeeds
    }
    
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    
    SIZE_T bw = 0;
    if (!::WriteProcessMemory(ph.Get(), address, buffer, size, &bw)) {
        SetWin32Error(err, L"WriteProcessMemory");
        return false;
    }
    
    if (bytesWritten) *bytesWritten = bw;
    return true;
}

bool AllocateProcessMemory(ProcessId pid, SIZE_T size, void** outAddress,
    DWORD allocationType, DWORD protection, Error* err) noexcept {
    
    // Validate parameters
    if (!outAddress) {
        SetWin32Error(err, L"AllocateProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"outAddress is null");
        return false;
    }
    *outAddress = nullptr;
    
    if (size == 0) {
        SetWin32Error(err, L"AllocateProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Allocation size cannot be zero");
        return false;
    }
    
    // Sanity check on allocation size (prevent excessive allocations)
    static constexpr SIZE_T kMaxAllocationSize = 1ULL * 1024 * 1024 * 1024; // 1GB
    if (size > kMaxAllocationSize) {
        SetWin32Error(err, L"AllocateProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Allocation size exceeds maximum allowed");
        return false;
    }
    
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    
    void* p = ::VirtualAllocEx(ph.Get(), nullptr, size, allocationType, protection);
    if (!p) {
        SetWin32Error(err, L"VirtualAllocEx");
        return false;
    }
    
    *outAddress = p;
    return true;
}

bool FreeProcessMemory(ProcessId pid, void* address, SIZE_T size, DWORD freeType, Error* err) noexcept {
    // Validate address
    if (!address) {
        SetWin32Error(err, L"FreeProcessMemory", ERROR_INVALID_PARAMETER, 
                      L"Address is null");
        return false;
    }
    
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    
    // For MEM_RELEASE, size must be 0 per Windows API spec
    const SIZE_T effectiveSize = (freeType == MEM_RELEASE) ? 0 : size;
    
    if (!::VirtualFreeEx(ph.Get(), address, effectiveSize, freeType)) {
        SetWin32Error(err, L"VirtualFreeEx");
        return false;
    }
    
    return true;
}

bool ProtectProcessMemory(ProcessId pid, void* address, SIZE_T size,
    DWORD newProtection, DWORD* oldProtection, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    DWORD oldProt = 0;
    if (!::VirtualProtectEx(ph.Get(), address, size, newProtection, &oldProt)) {
        SetWin32Error(err, L"VirtualProtectEx");
        return false;
    }
    if (oldProtection) *oldProtection = oldProt;
    return true;
}

bool QueryProcessMemoryRegion(ProcessId pid, void* address,
    MEMORY_BASIC_INFORMATION& mbi, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err)) return false;
    SIZE_T r = ::VirtualQueryEx(ph.Get(), address, &mbi, sizeof(mbi));
    if (r == 0) {
        SetWin32Error(err, L"VirtualQueryEx");
        return false;
    }
    return true;
}

// ==========================================================
// Handle Operations
// ==========================================================

/**
 * @brief Enumerates all handles owned by a specific process.
 * 
 * Uses NtQuerySystemInformation to retrieve system-wide handle information,
 * then filters handles belonging to the target process. Handle type names
 * and object names are retrieved when possible via handle duplication.
 * 
 * @param pid Target process ID to enumerate handles for.
 * @param handles Output vector of handle information structures.
 * @param err Optional error output.
 * @return true on success, false on failure.
 * 
 * @note Requires SeDebugPrivilege for handles from protected processes.
 * @warning Some handle types (File, Key) may hang during name query - they are skipped.
 */
bool EnumerateProcessHandles(ProcessId pid, std::vector<ProcessHandleInfo>& handles, Error* err) noexcept {
    handles.clear();

    // NtQuerySystemInformation for handle enumeration - resolve once and cache
    typedef LONG(NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation) {
        SetWin32Error(err, L"EnumerateProcessHandles", ERROR_CALL_NOT_IMPLEMENTED,
            L"Failed to resolve NtQuerySystemInformation from ntdll.dll.");
        return false;
    }

    // SystemExtendedHandleInformation (0x40) provides more info than SystemHandleInformation (0x10)
    constexpr SYSTEM_INFORMATION_CLASS SystemExtendedHandleInformation = 
        static_cast<SYSTEM_INFORMATION_CLASS>(0x40);

    // Maximum buffer size to prevent runaway allocation (256MB limit)
    constexpr ULONG kMaxHandleBufferSize = 256 * 1024 * 1024;
    
    // Dynamically allocate buffer for handle information, start with 64KB
    ULONG bufferSize = 0x10000;
    std::vector<BYTE> buffer;
    LONG status = 0;

    // Query with increasing buffer size, up to kMaxHandleBufferSize
    for (int attempts = 0; attempts < 10; ++attempts) {
        try {
            buffer.resize(bufferSize);
        } catch (const std::bad_alloc&) {
            SetWin32Error(err, L"EnumerateProcessHandles", ERROR_NOT_ENOUGH_MEMORY,
                L"Failed to allocate buffer for handle enumeration.");
            return false;
        }

        ULONG returnLength = 0;
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer.data(),
            bufferSize,
            &returnLength
        );

        if (status == 0) {
            break; // Success
        }
        else if (status == static_cast<LONG>(0xC0000004)) { // STATUS_INFO_LENGTH_MISMATCH
            // Calculate new buffer size with 4KB margin, check for overflow
            const ULONG newSize = returnLength + 0x1000;
            if (newSize < returnLength || newSize > kMaxHandleBufferSize) {
                SetWin32Error(err, L"EnumerateProcessHandles", ERROR_NOT_ENOUGH_MEMORY,
                    L"Handle information buffer size exceeded maximum limit.");
                return false;
            }
            bufferSize = newSize;
            continue;
        }
        else {
            SetNtError(err, L"NtQuerySystemInformation(SystemExtendedHandleInformation)", status);
            return false;
        }
    }

    if (status != 0) {
        SetNtError(err, L"EnumerateProcessHandles", status,
            L"Handle information query failed after maximum retry attempts.");
        return false;
    }

    // Parse SYSTEM_HANDLE_INFORMATION_EX structure (Windows internal structure)
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    struct SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    };

    // Validate buffer size before accessing structure
    if (buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_EX)) {
        SetWin32Error(err, L"EnumerateProcessHandles", ERROR_INVALID_DATA,
            L"Returned buffer is too small for handle information.");
        return false;
    }

    auto* handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    
    // Validate handle count against buffer capacity
    const SIZE_T maxHandles = (buffer.size() - offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles)) / 
                              sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
    if (handleInfo->NumberOfHandles > maxHandles) {
        SetWin32Error(err, L"EnumerateProcessHandles", ERROR_INVALID_DATA,
            L"Handle count exceeds buffer capacity.");
        return false;
    }

    // Pre-reserve space for efficiency (estimate 1% of handles belong to target process)
    try {
        handles.reserve(std::min<SIZE_T>(handleInfo->NumberOfHandles / 100 + 10, 10000));
    } catch (...) {
        // Non-fatal - continue without pre-allocation
    }

    // Open target process for handle duplication (to get object names)
    ProcessHandle ph;
    bool canDuplicate = ph.Open(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, nullptr);

    // Filter and collect handles for target process
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; ++i) {
        const auto& entry = handleInfo->Handles[i];

        if (entry.UniqueProcessId != pid) {
            continue; // Not our target process
        }

        ProcessHandleInfo hi{};
        hi.handle = reinterpret_cast<HANDLE>(entry.HandleValue);
        hi.uniqueId = static_cast<HandleId>(entry.HandleValue);
        hi.type = entry.ObjectTypeIndex;
        hi.accessMask = entry.GrantedAccess;
        hi.attributes = entry.HandleAttributes;
        hi.isInheritable = (entry.HandleAttributes & OBJ_INHERIT) != 0;
        hi.isProtected = (entry.HandleAttributes & OBJ_PROTECT_CLOSE) != 0;

        // Attempt to get object type name and object name
        if (canDuplicate) {
            HANDLE dupHandle = nullptr;

            // Duplicate handle to query information
            if (::DuplicateHandle(
                ph.Get(),
                hi.handle,
                GetCurrentProcess(),
                &dupHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
            {
                auto dupGuard = make_unique_handle(dupHandle);

                // Query object type information
                typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {
                    UNICODE_STRING TypeName;
                    ULONG Reserved[22];
                } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

                typedef enum _OBJECT_INFORMATION_CLASS {
                    ObjectBasicInformation = 0,
                    ObjectTypeInformation = 2,
                } OBJECT_INFORMATION_CLASS;

                typedef LONG(NTAPI* NtQueryObject_t)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
                static auto NtQueryObject = reinterpret_cast<NtQueryObject_t>(
                    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));

                if (NtQueryObject) {
                    // Get object type
                    BYTE typeBuffer[1024] = {};
                    ULONG typeReturnLength = 0;

                    if (NtQueryObject(dupHandle, ObjectTypeInformation,
                        typeBuffer, sizeof(typeBuffer), &typeReturnLength) == 0) {
                        auto* typeInfo = reinterpret_cast<PUBLIC_OBJECT_TYPE_INFORMATION*>(typeBuffer);
                        if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
                            hi.typeName.assign(typeInfo->TypeName.Buffer,
                                typeInfo->TypeName.Length / sizeof(wchar_t));
                        }
                    }

                    // Get object name (with timeout protection for hung handles)
                    // Some handles (like named pipes) can hang indefinitely
                    // We skip name query for potentially problematic handle types
                    bool skipNameQuery = (hi.typeName == L"File") ||
                        (hi.typeName == L"Key") ||
                        (hi.type >= 30); // Potentially problematic types

                    if (!skipNameQuery) {
                        BYTE nameBuffer[4096] = {};
                        ULONG nameReturnLength = 0;

                        // ObjectNameInformation = 1
                        if (NtQueryObject(dupHandle, static_cast<OBJECT_INFORMATION_CLASS>(1),
                            nameBuffer, sizeof(nameBuffer), &nameReturnLength) == 0) {
                            auto* nameInfo = reinterpret_cast<UNICODE_STRING*>(nameBuffer);
                            if (nameInfo->Buffer && nameInfo->Length > 0) {
                                hi.name.assign(nameInfo->Buffer, nameInfo->Length / sizeof(wchar_t));
                            }
                        }
                    }
                }
            }
        }

        // Map common object type indices to names (fallback)
        if (hi.typeName.empty()) {
            switch (hi.type) {
            case 2:  hi.typeName = L"Type"; break;
            case 3:  hi.typeName = L"Directory"; break;
            case 4:  hi.typeName = L"SymbolicLink"; break;
            case 5:  hi.typeName = L"Token"; break;
            case 6:  hi.typeName = L"Job"; break;
            case 7:  hi.typeName = L"Process"; break;
            case 8:  hi.typeName = L"Thread"; break;
            case 9:  hi.typeName = L"UserApcReserve"; break;
            case 10: hi.typeName = L"IoCompletionReserve"; break;
            case 11: hi.typeName = L"DebugObject"; break;
            case 12: hi.typeName = L"Event"; break;
            case 13: hi.typeName = L"EventPair"; break;
            case 14: hi.typeName = L"Mutant"; break;
            case 15: hi.typeName = L"Callback"; break;
            case 16: hi.typeName = L"Semaphore"; break;
            case 17: hi.typeName = L"Timer"; break;
            case 18: hi.typeName = L"IRTimer"; break;
            case 19: hi.typeName = L"Profile"; break;
            case 20: hi.typeName = L"KeyedEvent"; break;
            case 21: hi.typeName = L"WindowStation"; break;
            case 22: hi.typeName = L"Desktop"; break;
            case 23: hi.typeName = L"TpWorkerFactory"; break;
            case 24: hi.typeName = L"Adapter"; break;
            case 25: hi.typeName = L"Controller"; break;
            case 26: hi.typeName = L"Device"; break;
            case 27: hi.typeName = L"Driver"; break;
            case 28: hi.typeName = L"IoCompletion"; break;
            case 29: hi.typeName = L"File"; break;
            case 30: hi.typeName = L"TmTm"; break;
            case 31: hi.typeName = L"TmTx"; break;
            case 32: hi.typeName = L"TmRm"; break;
            case 33: hi.typeName = L"TmEn"; break;
            case 34: hi.typeName = L"Section"; break;
            case 35: hi.typeName = L"Session"; break;
            case 36: hi.typeName = L"Key"; break;
            case 37: hi.typeName = L"ALPC Port"; break;
            case 38: hi.typeName = L"PowerRequest"; break;
            case 39: hi.typeName = L"WmiGuid"; break;
            case 40: hi.typeName = L"EtwRegistration"; break;
            case 41: hi.typeName = L"EtwConsumer"; break;
            case 42: hi.typeName = L"DmaAdapter"; break;
            case 43: hi.typeName = L"DmaDomain"; break;
            case 44: hi.typeName = L"PcwObject"; break;
            case 45: hi.typeName = L"FilterConnectionPort"; break;
            case 46: hi.typeName = L"FilterCommunicationPort"; break;
            case 47: hi.typeName = L"NetworkNamespace"; break;
            default: hi.typeName = L"Unknown"; break;
            }
        }

        handles.push_back(std::move(hi));
    }

    return true;
}

/**
 * @brief Closes a handle in a remote process.
 * 
 * Validates the handle exists and performs safety checks to prevent
 * closing critical system handles that could destabilize the system.
 * 
 * @param pid Target process ID that owns the handle.
 * @param handle The handle value to close in the target process.
 * @param err Optional error output.
 * @return true if handle was successfully closed, false on failure.
 * 
 * @warning Closing handles in another process is dangerous and can cause
 *          crashes or undefined behavior in the target process.
 * @note Protected handles (Process, Thread to system/current process) are blocked.
 */
bool CloseProcessHandle(ProcessId pid, HANDLE handle, Error* err) noexcept {
    // Validate handle parameter
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CloseProcessHandle", ERROR_INVALID_HANDLE,
            L"Invalid handle specified.");
        return false;
    }

    // Security check: Prevent closing handles in the current process via this API
    if (pid == ::GetCurrentProcessId()) {
        SetWin32Error(err, L"CloseProcessHandle", ERROR_ACCESS_DENIED,
            L"Cannot close handles in current process via remote API.");
        return false;
    }

    // Open target process with handle duplication rights
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }

    // Duplicate the handle to our process for validation and type checking
    HANDLE testHandle = nullptr;
    if (!::DuplicateHandle(
        ph.Get(),
        handle,
        GetCurrentProcess(),
        &testHandle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS))
    {
        SetWin32Error(err, L"CloseProcessHandle", GetLastError(),
            L"Failed to validate handle - handle may not exist or access denied.");
        return false;
    }

    // RAII guard for the duplicated test handle
    auto testGuard = make_unique_handle(testHandle);

    // Resolve NtQueryObject for handle type checking
    typedef LONG(NTAPI* NtQueryObject_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    static auto NtQueryObject = reinterpret_cast<NtQueryObject_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));

    // Get handle type for safety checks using the duplicated handle
    if (NtQueryObject) {
        BYTE typeBuffer[1024] = {};
        ULONG returnLength = 0;

        struct PUBLIC_OBJECT_TYPE_INFORMATION {
            UNICODE_STRING TypeName;
            ULONG Reserved[22];
        };

        // Query object type information (ObjectTypeInformation = 2)
        if (NtQueryObject(testGuard.get(), 2, typeBuffer, sizeof(typeBuffer), &returnLength) == 0) {
            auto* typeInfo = reinterpret_cast<PUBLIC_OBJECT_TYPE_INFORMATION*>(typeBuffer);
            if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
                // Safely construct string with bounds checking
                const SIZE_T charCount = typeInfo->TypeName.Length / sizeof(wchar_t);
                std::wstring typeName(typeInfo->TypeName.Buffer, charCount);

                // Prevent closing critical handle types (Process or Thread handles)
                if (typeName == L"Process" || typeName == L"Thread") {
                    // Additional check: Don't close handles to system or current process
                    typedef LONG(NTAPI* NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
                    static auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
                        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

                    if (NtQueryInformationProcess) {
                        struct PROCESS_BASIC_INFORMATION {
                            PVOID Reserved1;
                            PVOID PebBaseAddress;
                            PVOID Reserved2[2];
                            ULONG_PTR UniqueProcessId;
                            PVOID Reserved3;
                        };

                        PROCESS_BASIC_INFORMATION pbi{};
                        // ProcessBasicInformation = 0
                        if (NtQueryInformationProcess(testGuard.get(), 0, &pbi, sizeof(pbi), nullptr) == 0) {
                            const DWORD handlePid = static_cast<DWORD>(pbi.UniqueProcessId);

                            // Block closing handles to System (PID 4) or current process
                            if (handlePid == ::GetCurrentProcessId() || handlePid == 4) {
                                SetWin32Error(err, L"CloseProcessHandle", ERROR_ACCESS_DENIED,
                                    L"Cannot close handle to System process or current process.");
                                return false;
                            }
                        }
                    }
                }
            }
        }
    }

    // Close the handle in the remote process using DuplicateHandle with DUPLICATE_CLOSE_SOURCE
    // This atomically closes the handle in the source process
    if (!::DuplicateHandle(
        ph.Get(),
        handle,
        nullptr,  // No target process - just close source
        nullptr,  // No target handle needed
        0,
        FALSE,
        DUPLICATE_CLOSE_SOURCE))  // This flag closes the source handle
    {
        SetWin32Error(err, L"DuplicateHandle(DUPLICATE_CLOSE_SOURCE)");
        return false;
    }

    return true;
}

/**
 * @brief Duplicates a handle from one process to another.
 * 
 * @param sourcePid Process ID that owns the source handle.
 * @param sourceHandle Handle value to duplicate from source process.
 * @param targetPid Process ID to receive the duplicated handle.
 * @param targetHandle Output: receives the new handle value in target process.
 * @param desiredAccess Access rights for the duplicated handle.
 * @param inheritHandle Whether the duplicated handle is inheritable.
 * @param options Duplication options (DUPLICATE_SAME_ACCESS, etc.).
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool DuplicateProcessHandle(ProcessId sourcePid, HANDLE sourceHandle,
    ProcessId targetPid, HANDLE* targetHandle,
    DWORD desiredAccess, bool inheritHandle,
    DWORD options, Error* err) noexcept {
    // Validate output parameter
    if (!targetHandle) {
        SetWin32Error(err, L"DuplicateProcessHandle", ERROR_INVALID_PARAMETER, 
            L"targetHandle output parameter is null.");
        return false;
    }
    *targetHandle = nullptr;  // Initialize output

    // Validate source handle
    if (!sourceHandle || sourceHandle == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"DuplicateProcessHandle", ERROR_INVALID_HANDLE,
            L"Invalid source handle specified.");
        return false;
    }

    // Open source and target processes with duplication rights
    ProcessHandle src, dst;
    if (!src.Open(sourcePid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    if (!dst.Open(targetPid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }

    HANDLE dup = nullptr;
    if (!::DuplicateHandle(src.Get(), sourceHandle, dst.Get(), &dup, 
                           desiredAccess, inheritHandle ? TRUE : FALSE, options)) {
        SetWin32Error(err, L"DuplicateHandle");
        return false;
    }
    
    *targetHandle = dup;
    return true;
}

// ==========================================================
// Process Security & Privileges
// ==========================================================

/**
 * @brief Enables or disables a privilege on a process token.
 * 
 * @param pid Target process ID.
 * @param privilegeName Name of the privilege (e.g., SE_DEBUG_NAME, SE_BACKUP_NAME).
 * @param enable true to enable, false to disable.
 * @param err Optional error output.
 * @return true on success, false on failure.
 * 
 * @note The privilege must already exist in the token; this function cannot add new privileges.
 */
bool EnableProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, bool enable, Error* err) noexcept {
    // Validate privilege name
    if (privilegeName.empty()) {
        SetWin32Error(err, L"EnableProcessPrivilege", ERROR_INVALID_PARAMETER,
            L"Privilege name cannot be empty.");
        return false;
    }

    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }

    // Open the process token with required access rights
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(ph.Get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        SetWin32Error(err, L"OpenProcessToken");
        return false;
    }
    auto token = make_unique_handle(hToken);

    // Look up the LUID for the privilege name
    LUID luid{};
    // Create null-terminated string for API call
    std::wstring privNameStr(privilegeName);
    if (!LookupPrivilegeValueW(nullptr, privNameStr.c_str(), &luid)) {
        SetWin32Error(err, L"LookupPrivilegeValueW");
        return false;
    }

    // Set up the privilege structure
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    // Adjust the token privileges
    if (!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        SetWin32Error(err, L"AdjustTokenPrivileges");
        return false;
    }

    // Check if the privilege was actually adjusted
    // AdjustTokenPrivileges succeeds even if not all privileges were adjusted
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        SetWin32Error(err, L"AdjustTokenPrivileges", ERROR_NOT_ALL_ASSIGNED, 
            L"Requested privilege does not exist in the process token.");
        return false;
    }

    return true;
}

/**
 * @brief Checks if a process has a specific privilege enabled.
 * 
 * @param pid Target process ID.
 * @param privilegeName Name of the privilege to check.
 * @param err Optional error output.
 * @return true if privilege is enabled, false otherwise (or on error).
 */
[[nodiscard]]
bool HasProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, Error* err) noexcept {
    if (privilegeName.empty()) {
        return false;
    }

    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) {
        return false;
    }

    const std::wstring target = ToLower(std::wstring(privilegeName));
    for (const auto& p : sec.enabledPrivileges) {
        if (ToLower(p) == target) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Retrieves all enabled privileges for a process.
 * 
 * @param pid Target process ID.
 * @param privileges Output vector of enabled privilege names.
 * @param err Optional error output.
 * @return true on success, false on failure.
 */
bool GetProcessPrivileges(ProcessId pid, std::vector<std::wstring>& privileges, Error* err) noexcept {
    privileges.clear();

    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) {
        return false;
    }

    try {
        privileges = sec.enabledPrivileges;
    } catch (const std::bad_alloc&) {
        SetWin32Error(err, L"GetProcessPrivileges", ERROR_NOT_ENOUGH_MEMORY,
            L"Failed to allocate memory for privilege list.");
        return false;
    }

    return true;
}

/**
 * @brief Impersonates the security context of another process.
 * 
 * The calling thread will assume the security context of the target process.
 * Call RevertToSelf() when done to restore the original security context.
 * 
 * @param pid Target process ID to impersonate.
 * @param err Optional error output.
 * @return true on success, false on failure.
 * 
 * @warning Impersonation affects the current thread only. Always call RevertToSelf().
 */
bool ImpersonateProcess(ProcessId pid, Error* err) noexcept {
    // Prevent impersonating the current process (no-op but may indicate logic error)
    if (pid == ::GetCurrentProcessId()) {
        SetWin32Error(err, L"ImpersonateProcess", ERROR_INVALID_PARAMETER,
            L"Cannot impersonate the current process.");
        return false;
    }

    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(ph.Get(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        SetWin32Error(err, L"OpenProcessToken");
        return false;
    }
    auto token = make_unique_handle(hToken);

    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(token.get(), MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &hDup)) {
        SetWin32Error(err, L"DuplicateTokenEx");
        return false;
    }
    auto dup = make_unique_handle(hDup);

    if (!ImpersonateLoggedOnUser(dup.get())) {
        SetWin32Error(err, L"ImpersonateLoggedOnUser");
        return false;
    }
    return true;
}

bool RevertToSelf(Error* err) noexcept {
    if (!::RevertToSelf()) {
        SetWin32Error(err, L"RevertToSelf");
        return false;
    }
    return true;
}

// ==========================================================
// Process Creation & Termination
// ==========================================================

namespace {
    void FillStartupInfo(const ProcessStartupInfo& in, STARTUPINFOW& si) {
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.lpDesktop = in.desktopName.empty() ? nullptr : const_cast<LPWSTR>(in.desktopName.c_str());
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = static_cast<WORD>(in.windowShowState);
        if (in.redirectStdInput || in.redirectStdOutput || in.redirectStdError) {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput = in.hStdInput;
            si.hStdOutput = in.hStdOutput;
            si.hStdError = in.hStdError;
        }
    }
}

bool CreateProcess(std::wstring_view executablePath,
    std::wstring_view arguments,
    ProcessCreationResult& result,
    const ProcessStartupInfo& startupInfo,
    ProcessCreationFlags flags,
    Error* err) noexcept {
    result = {};

    std::wstring cmd;
    cmd.reserve(executablePath.size() + 1 + arguments.size() + 2);
    cmd.append(L"\"").append(executablePath).append(L"\"");
    if (!arguments.empty()) {
        cmd.push_back(L' ');
        cmd.append(arguments);
    }

    STARTUPINFOW si{};
    FillStartupInfo(startupInfo, si);

    PROCESS_INFORMATION pi{};
    DWORD createFlags = static_cast<DWORD>(flags) | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = ::CreateProcessW(executablePath.data(),
        cmd.data(),
        nullptr, nullptr,
        (startupInfo.redirectStdInput || startupInfo.redirectStdOutput || startupInfo.redirectStdError),
        createFlags,
        nullptr,
        startupInfo.workingDirectory.empty() ? nullptr : startupInfo.workingDirectory.c_str(),
        &si, &pi);
    if (!ok) {
        SetWin32Error(err, L"CreateProcessW");
        result.succeeded = false;
        return false;
    }

    result.hProcess = pi.hProcess;
    result.hThread = pi.hThread;
    result.pid = pi.dwProcessId;
    result.mainThreadId = pi.dwThreadId;
    result.succeeded = true;
    return true;
}

bool CreateProcessAsUser(std::wstring_view executablePath,
    std::wstring_view arguments,
    HANDLE hUserToken,
    ProcessCreationResult& result,
    const ProcessStartupInfo& startupInfo,
    ProcessCreationFlags flags,
    Error* err) noexcept {
    result = {};

    std::wstring cmd;
    cmd.reserve(executablePath.size() + 1 + arguments.size() + 2);
    cmd.append(L"\"").append(executablePath).append(L"\"");
    if (!arguments.empty()) {
        cmd.push_back(L' ');
        cmd.append(arguments);
    }

    STARTUPINFOW si{};
    FillStartupInfo(startupInfo, si);

    PROCESS_INFORMATION pi{};
    DWORD createFlags = static_cast<DWORD>(flags) | CREATE_UNICODE_ENVIRONMENT;

    BOOL ok = ::CreateProcessAsUserW(hUserToken,
        executablePath.data(),
        cmd.data(),
        nullptr, nullptr,
        (startupInfo.redirectStdInput || startupInfo.redirectStdOutput || startupInfo.redirectStdError),
        createFlags,
        nullptr,
        startupInfo.workingDirectory.empty() ? nullptr : startupInfo.workingDirectory.c_str(),
        &si, &pi);
    if (!ok) {
        SetWin32Error(err, L"CreateProcessAsUserW");
        result.succeeded = false;
        return false;
    }

    result.hProcess = pi.hProcess;
    result.hThread = pi.hThread;
    result.pid = pi.dwProcessId;
    result.mainThreadId = pi.dwThreadId;
    result.succeeded = true;
    return true;
}

bool CreateProcessWithToken(std::wstring_view executablePath,
    std::wstring_view arguments,
    HANDLE hToken,
    ProcessCreationResult& result,
    Error* err) noexcept {
    result = {};
    std::wstring cmd;
    cmd.reserve(executablePath.size() + 1 + arguments.size() + 2);
    cmd.append(L"\"").append(executablePath).append(L"\"");
    if (!arguments.empty()) {
        cmd.push_back(L' ');
        cmd.append(arguments);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    BOOL ok = ::CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE,
        executablePath.data(),
        cmd.data(),
        CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &si, &pi);
    if (!ok) {
        SetWin32Error(err, L"CreateProcessWithTokenW");
        return false;
    }
    result.hProcess = pi.hProcess;
    result.hThread = pi.hThread;
    result.pid = pi.dwProcessId;
    result.mainThreadId = pi.dwThreadId;
    result.succeeded = true;
    return true;
}

/**
 * @brief Terminates a process by PID.
 * 
 * @param pid Process ID to terminate.
 * @param exitCode Exit code for the terminated process.
 * @param err Optional error output.
 * @return true on success, false on failure.
 * 
 * @warning Process termination is abrupt and may cause data loss.
 */
bool TerminateProcess(ProcessId pid, DWORD exitCode, Error* err) noexcept {
    // Prevent terminating System process or current process
    if (pid == 0 || pid == 4) {
        SetWin32Error(err, L"TerminateProcess", ERROR_ACCESS_DENIED,
            L"Cannot terminate System process.");
        return false;
    }
    if (pid == ::GetCurrentProcessId()) {
        SetWin32Error(err, L"TerminateProcess", ERROR_ACCESS_DENIED,
            L"Cannot terminate current process via this API.");
        return false;
    }

    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_TERMINATE, err)) {
        return false;
    }
    
    if (!::TerminateProcess(ph.Get(), exitCode)) {
        SetWin32Error(err, L"TerminateProcess");
        return false;
    }
    return true;
}

/**
 * @brief Terminates a process by handle.
 * 
 * @param hProcess Handle to the process to terminate.
 * @param exitCode Exit code for the terminated process.
 * @param err Optional error output.
 * @return true on success, false on failure.
 * 
 * @note Caller is responsible for handle validity and access rights.
 */
bool TerminateProcess(HANDLE hProcess, DWORD exitCode, Error* err) noexcept {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"TerminateProcess", ERROR_INVALID_HANDLE,
            L"Invalid process handle.");
        return false;
    }

    if (!::TerminateProcess(hProcess, exitCode)) {
        SetWin32Error(err, L"TerminateProcess");
        return false;
    }
    return true;
}

/**
 * @brief Terminates a process and all of its descendant processes.
 * 
 * Builds a process tree and terminates processes in reverse order
 * (children before parents) to avoid orphaned processes.
 * 
 * @param rootPid Root process ID of the tree to terminate.
 * @param exitCode Exit code for all terminated processes.
 * @param err Optional error output.
 * @return true if all processes terminated successfully, false if any failed.
 * 
 * @note System processes (PID 0, 4) and current process are skipped.
 */
bool TerminateProcessTree(ProcessId rootPid, DWORD exitCode, Error* err) noexcept {
    // Build parent-child relationship map
    std::unordered_multimap<ProcessId, ProcessId> tree;
    
    // Create process snapshot with RAII
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return false;
    }
    auto snapGuard = make_unique_handle(hSnap);  // RAII for snapshot handle

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapGuard.get(), &pe)) {
        do {
            // Map parent PID -> child PID
            tree.emplace(pe.th32ParentProcessID, pe.th32ProcessID);
        } while (Process32NextW(snapGuard.get(), &pe));
    }

    // Build ordered list of processes to terminate using DFS
    std::vector<ProcessId> stack;
    std::vector<ProcessId> order;
    std::unordered_set<ProcessId> visited;

    try {
        stack.reserve(64);
        order.reserve(64);
        stack.push_back(rootPid);
    } catch (const std::bad_alloc&) {
        SetWin32Error(err, L"TerminateProcessTree", ERROR_NOT_ENOUGH_MEMORY,
            L"Failed to allocate memory for process tree traversal.");
        return false;
    }

    while (!stack.empty()) {
        const ProcessId pid = stack.back();
        stack.pop_back();

        if (visited.insert(pid).second) {
            order.push_back(pid);
            
            // Add all children to stack
            auto range = tree.equal_range(pid);
            for (auto it = range.first; it != range.second; ++it) {
                stack.push_back(it->second);
            }
        }
    }

    // Reverse order so we terminate children before parents
    std::reverse(order.begin(), order.end());

    // Terminate all processes in order
    bool okAll = true;
    size_t failedCount = 0;

    for (const ProcessId pid : order) {
        // Skip system processes and current process
        if (pid == 0 || pid == 4 || pid == ::GetCurrentProcessId()) {
            continue;
        }
        
        // Skip already terminated processes
        if (!IsProcessRunning(pid)) {
            continue;
        }

        if (!TerminateProcess(pid, exitCode, nullptr)) {
            okAll = false;
            ++failedCount;
        }
    }

    if (!okAll) {
        SetWin32Error(err, L"TerminateProcessTree", ERROR_GEN_FAILURE, 
            L"Some processes in the tree could not be terminated.");
    }

    return okAll;
}

/**
 * @brief Waits for a process to exit.
 * 
 * @param pid Process ID to wait for.
 * @param timeoutMs Timeout in milliseconds (INFINITE for no timeout).
 * @param err Optional error output.
 * @return true if wait succeeded (process exited or timeout), false on error.
 */
bool WaitForProcess(ProcessId pid, DWORD timeoutMs, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return false;
    }
    
    const DWORD w = WaitForSingleObject(ph.Get(), timeoutMs);
    if (w == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject");
        return false;
    }
    return (w == WAIT_OBJECT_0) || (w == WAIT_TIMEOUT);
}

/**
 * @brief Waits for a process to exit using a handle.
 * 
 * @param hProcess Process handle with SYNCHRONIZE access.
 * @param timeoutMs Timeout in milliseconds (INFINITE for no timeout).
 * @param err Optional error output.
 * @return true if wait succeeded, false on error.
 */
bool WaitForProcess(HANDLE hProcess, DWORD timeoutMs, Error* err) noexcept {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"WaitForProcess", ERROR_INVALID_HANDLE,
            L"Invalid process handle.");
        return false;
    }

    const DWORD w = WaitForSingleObject(hProcess, timeoutMs);
    if (w == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject");
        return false;
    }
    return (w == WAIT_OBJECT_0) || (w == WAIT_TIMEOUT);
}

/**
 * @brief Retrieves the exit code of a process.
 * 
 * @param pid Process ID.
 * @param err Optional error output.
 * @return Exit code if available, std::nullopt on error.
 * 
 * @note Returns STILL_ACTIVE (259) if process is still running.
 */
[[nodiscard]]
std::optional<DWORD> GetProcessExitCode(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) {
        return std::nullopt;
    }
    
    DWORD code = 0;
    if (!GetExitCodeProcess(ph.Get(), &code)) {
        SetWin32Error(err, L"GetExitCodeProcess");
        return std::nullopt;
    }
    return code;
}



// ==========================================================
// Process Monitoring (Real-time)
// ==========================================================

ProcessMonitor::ProcessMonitor() noexcept = default;
ProcessMonitor::~ProcessMonitor() { Stop(nullptr); }

ProcessMonitor::ProcessMonitor(ProcessMonitor&& other) noexcept
    : m_running(other.m_running.load())
    , m_onProcessCreated(std::move(other.m_onProcessCreated))
    , m_onProcessTerminated(std::move(other.m_onProcessTerminated))
    , m_onModuleLoaded(std::move(other.m_onModuleLoaded))
    , m_onThreadCreated(std::move(other.m_onThreadCreated))
    , m_processFilter(std::move(other.m_processFilter))
    , m_nameFilter(std::move(other.m_nameFilter))
    , m_lastSnapshot(std::move(other.m_lastSnapshot)) {
    if (other.m_monitorThread.joinable()) {
        m_monitorThread = std::move(other.m_monitorThread);
    }
    other.m_running.store(false);
}

ProcessMonitor& ProcessMonitor::operator=(ProcessMonitor&& other) noexcept {
    if (this != &other) {
        if (m_monitorThread.joinable()) {
            m_running.store(false);
            m_monitorThread.join();
        }
        m_running.store(other.m_running.load());
        if (other.m_monitorThread.joinable()) {
            m_monitorThread = std::move(other.m_monitorThread);
        }
        m_onProcessCreated = std::move(other.m_onProcessCreated);
        m_onProcessTerminated = std::move(other.m_onProcessTerminated);
        m_onModuleLoaded = std::move(other.m_onModuleLoaded);
        m_onThreadCreated = std::move(other.m_onThreadCreated);
        m_processFilter = std::move(other.m_processFilter);
        m_nameFilter = std::move(other.m_nameFilter);
        m_lastSnapshot = std::move(other.m_lastSnapshot);
        other.m_running.store(false);
    }
    return *this;
}

bool ProcessMonitor::Start(Error* err) noexcept {
    if (m_running.load()) return true;
    m_running.store(true);
    try {
        m_monitorThread = std::thread([this] { monitorThread(); });
    }
    catch (...) {
        m_running.store(false);
        SetWin32Error(err, L"ProcessMonitor::Start", ERROR_OUTOFMEMORY, 
            L"Failed to start monitoring thread.");
        return false;
    }
    return true;
}

bool ProcessMonitor::Stop(Error* /*err*/) noexcept {
    if (!m_running.exchange(false)) return true;
    if (m_monitorThread.joinable()) m_monitorThread.join();
    return true;
}

void ProcessMonitor::monitorThread() noexcept {
    while (m_running.load()) {
        processSnapshot();
        for (int i = 0; i < 10 && m_running.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void ProcessMonitor::processSnapshot() noexcept {
    std::vector<ProcessId> current;
    EnumerateProcesses(current, nullptr);
    std::unordered_set<ProcessId> curSet(current.begin(), current.end());

    for (auto pid : curSet) {
        if (m_lastSnapshot.find(pid) == m_lastSnapshot.end()) {
            if (!m_processFilter.empty() && m_processFilter.find(pid) == m_processFilter.end()) continue;
            if (!m_nameFilter.empty()) {
                auto name = GetProcessName(pid, nullptr);
                bool ok = false;
                if (name) {
                    for (const auto& nf : m_nameFilter) {
                        if (WildcardMatchInsensitive(nf, *name)) { ok = true; break; }
                    }
                }
                if (!ok) continue;
            }
            if (m_onProcessCreated) {
                ProcessEvent e{};
                e.type = ProcessEventType::Created;
                e.pid = pid;
                e.timestamp = std::chrono::system_clock::now();
                m_onProcessCreated(e);
            }
        }
    }
    for (auto pid : m_lastSnapshot) {
        if (curSet.find(pid) == curSet.end()) {
            if (!m_processFilter.empty() && m_processFilter.find(pid) == m_processFilter.end()) continue;
            if (m_onProcessTerminated) {
                ProcessEvent e{};
                e.type = ProcessEventType::Terminated;
                e.pid = pid;
                e.timestamp = std::chrono::system_clock::now();
                m_onProcessTerminated(e);
            }
        }
    }
    m_lastSnapshot = std::move(curSet);
}

// ==========================================================
// Process Utilities
// ==========================================================

ProcessId GetProcessIdByName(std::wstring_view processName, Error* err) noexcept {
    std::vector<ProcessId> pids = GetProcessIdsByName(processName, err);
    if (pids.empty()) return 0;
    return pids.front();
}

std::vector<ProcessId> GetProcessIdsByName(std::wstring_view processName, Error* err) noexcept {
    std::vector<ProcessId> result;
    std::vector<ProcessId> pids;
    if (!EnumerateProcesses(pids, err)) return result;
    std::wstring target = ToLower(std::wstring(processName));
    for (auto pid : pids) {
        auto name = GetProcessName(pid, nullptr);
        if (name && ToLower(*name) == target) result.push_back(pid);
    }
    return result;
}

/**
 * @brief Terminates the first process found with the specified name.
 * 
 * @param processName Process name to search for (case-insensitive).
 * @param err Optional error output.
 * @return true if a process was terminated, false if not found or on error.
 */
bool KillProcessByName(std::wstring_view processName, Error* err) noexcept {
    if (processName.empty()) {
        SetWin32Error(err, L"KillProcessByName", ERROR_INVALID_PARAMETER,
            L"Process name cannot be empty.");
        return false;
    }

    auto pid = GetProcessIdByName(processName, err);
    if (pid == 0) {
        SetWin32Error(err, L"KillProcessByName", ERROR_NOT_FOUND, 
            L"No process found with the specified name.");
        return false;
    }
    return TerminateProcess(pid, 0, err);
}

/**
 * @brief Terminates all processes with the specified name.
 * 
 * @param processName Process name to search for (case-insensitive).
 * @param err Optional error output.
 * @return true if all matching processes were terminated, false otherwise.
 */
bool KillAllProcessesByName(std::wstring_view processName, Error* err) noexcept {
    if (processName.empty()) {
        SetWin32Error(err, L"KillAllProcessesByName", ERROR_INVALID_PARAMETER,
            L"Process name cannot be empty.");
        return false;
    }

    bool okAll = true;
    auto pids = GetProcessIdsByName(processName, nullptr);
    if (pids.empty()) {
        SetWin32Error(err, L"KillAllProcessesByName", ERROR_NOT_FOUND, 
            L"No processes found matching the specified name.");
        return false;
    }

    for (const ProcessId pid : pids) {
        if (!TerminateProcess(pid, 0, nullptr)) {
            okAll = false;
        }
    }

    if (!okAll) {
        SetWin32Error(err, L"KillAllProcessesByName", ERROR_GEN_FAILURE, 
            L"Some processes could not be terminated.");
    }
    return okAll;
}

std::optional<std::wstring> GetProcessOwner(ProcessId pid, Error* err) noexcept {
    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) return std::nullopt;
    return sec.userName;
}

std::optional<std::wstring> GetProcessSID(ProcessId pid, Error* err) noexcept {
    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) return std::nullopt;
    return sec.userSid;
}

std::optional<DWORD> GetProcessSessionId(ProcessId pid, Error* err) noexcept {
    DWORD sid = 0;
    if (!ProcessIdToSessionId(pid, &sid)) {
        SetWin32Error(err, L"ProcessIdToSessionId");
        return std::nullopt;
    }
    return sid;
}

bool IsProcessInJob(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    BOOL inJob = FALSE;
    if (!::IsProcessInJob(ph.Get(), nullptr, &inJob)) {
        SetWin32Error(err, L"IsProcessInJob");
        return false;
    }
    return inJob == TRUE;
}

bool IsProcessDebugged(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    BOOL debugged = FALSE;
    if (!::CheckRemoteDebuggerPresent(ph.Get(), &debugged)) {
        SetWin32Error(err, L"CheckRemoteDebuggerPresent");
        return false;
    }
    return debugged == TRUE;
}

// ==========================================================
// Advanced Features
// ==========================================================

// ==========================================================
// ETW Process Tracing Implementation
// ==========================================================

namespace {
    // ETW Session Management
    struct ETWSessionState {
        TRACEHANDLE sessionHandle = 0;
        TRACEHANDLE consumerHandle = 0;
        std::atomic<bool> isActive{ false };
        std::thread consumerThread;
        std::mutex mutex;
    };

    static ETWSessionState g_etwSession;

    // ETW Provider GUIDs
    constexpr GUID MicrosoftWindowsKernelProcessGuid = {
        0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}
    };

    // Event Types for Process Provider
    constexpr UCHAR ProcessStartOpcode = 1;
    constexpr UCHAR ProcessEndOpcode = 2;
    constexpr UCHAR ThreadStartOpcode = 3;
    constexpr UCHAR ThreadEndOpcode = 4;
    constexpr UCHAR ImageLoadOpcode = 10;

    // ETW Event Callback
    void WINAPI ProcessEventCallback(PEVENT_RECORD eventRecord) {
        if (!eventRecord) return;

        // Check if this is a process-related event
        if (IsEqualGUID(eventRecord->EventHeader.ProviderId, MicrosoftWindowsKernelProcessGuid)) {
            UCHAR opcode = eventRecord->EventHeader.EventDescriptor.Opcode;

            switch (opcode) {
            case ProcessStartOpcode: {
                // Process started
                // Can extract: PID, ParentPID, ImageFileName, CommandLine
                // Log or trigger callbacks here
                break;
            }
            case ProcessEndOpcode: {
                // Process terminated
                // Can extract: PID, ExitCode
                break;
            }
            case ThreadStartOpcode: {
                // Thread created
                // Can extract: TID, ProcessID
                break;
            }
            case ThreadEndOpcode: {
                // Thread terminated
                break;
            }
            case ImageLoadOpcode: {
                // Module/DLL loaded
                // Can extract: ImageBase, ImageSize, FileName
                break;
            }
            default:
                break;
            }
        }
    }

    // ETW Consumer Thread
    void ETWConsumerThreadProc() {
        if (g_etwSession.consumerHandle == 0) return;

        // Process trace events (blocking call)
        ULONG status = ProcessTrace(&g_etwSession.consumerHandle, 1, nullptr, nullptr);

        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            // Log error
        }
    }



    bool EnableETWProcessTracing(Error* err) noexcept {
        std::lock_guard<std::mutex> lock(g_etwSession.mutex);

        // Check if already running
        if (g_etwSession.isActive.load()) {
            SetWin32Error(err, L"EnableETWProcessTracing", ERROR_ALREADY_EXISTS,
                L"ETW process tracing is already active.");
            return false;
        }

        // Session name must be unique
        constexpr wchar_t sessionName[] = L"ShadowStrike-ProcessTrace";

        // Calculate required buffer size for EVENT_TRACE_PROPERTIES
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName) + sizeof(wchar_t);
        std::vector<BYTE> buffer(bufferSize, 0);

        auto* properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
        properties->Wnode.BufferSize = bufferSize;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 1; // Use QPC for timestamp
        properties->Wnode.Guid = MicrosoftWindowsKernelProcessGuid;

        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties->MaximumFileSize = 0; // No file logging
        properties->FlushTimer = 1; // Flush every second
        properties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD;

        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s(reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset),
            (bufferSize - properties->LoggerNameOffset) / sizeof(wchar_t),
            sessionName);

        // Start trace session
        TRACEHANDLE sessionHandle = 0;
        ULONG status = StartTraceW(&sessionHandle, sessionName, properties);

        if (status != ERROR_SUCCESS) {
            if (status == ERROR_ALREADY_EXISTS) {
                // Try to stop existing session and restart
                ControlTraceW(0, sessionName, properties, EVENT_TRACE_CONTROL_STOP);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                status = StartTraceW(&sessionHandle, sessionName, properties);
                if (status != ERROR_SUCCESS) {
                    SetWin32Error(err, L"StartTraceW", status,
                        L"Failed to start ETW trace session after stopping existing session.");
                    return false;
                }
            }
            else if (status == ERROR_ACCESS_DENIED) {
                SetWin32Error(err, L"StartTraceW", status,
                    L"Access denied. Administrator privileges required for ETW tracing.");
                return false;
            }
            else {
                SetWin32Error(err, L"StartTraceW", status,
                    L"Failed to start ETW trace session.");
                return false;
            }
        }

        g_etwSession.sessionHandle = sessionHandle;

        // Enable process provider
        status = EnableTraceEx2(
            sessionHandle,
            &MicrosoftWindowsKernelProcessGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD,
            0,
            0,
            nullptr
        );

        if (status != ERROR_SUCCESS) {
            // Cleanup session
            ControlTraceW(sessionHandle, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
            g_etwSession.sessionHandle = 0;

            SetWin32Error(err, L"EnableTraceEx2", status,
                L"Failed to enable process provider.");
            return false;
        }

        // Setup event consumer
        EVENT_TRACE_LOGFILEW logFile = {};
        logFile.LoggerName = const_cast<wchar_t*>(sessionName);
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = ProcessEventCallback;

        TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
        if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
            // Cleanup
            ControlTraceW(sessionHandle, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
            g_etwSession.sessionHandle = 0;

            SetWin32Error(err, L"OpenTraceW", GetLastError(),
                L"Failed to open trace consumer.");
            return false;
        }

        g_etwSession.consumerHandle = consumerHandle;

        // Start consumer thread
        try {
            g_etwSession.consumerThread = std::thread(ETWConsumerThreadProc);
            g_etwSession.isActive.store(true);
        }
        catch (...) {
            // Cleanup
            CloseTrace(consumerHandle);
            ControlTraceW(sessionHandle, nullptr, properties, EVENT_TRACE_CONTROL_STOP);
            g_etwSession.sessionHandle = 0;
            g_etwSession.consumerHandle = 0;

            SetWin32Error(err, L"EnableETWProcessTracing", ERROR_OUTOFMEMORY,
                L"Failed to create consumer thread.");
            return false;
        }

        return true;
    }

    bool DisableETWProcessTracing(Error* err) noexcept {
        std::lock_guard<std::mutex> lock(g_etwSession.mutex);

        if (!g_etwSession.isActive.load()) {
            SetWin32Error(err, L"DisableETWProcessTracing", ERROR_INVALID_STATE,
                L"ETW process tracing is not active.");
            return false;
        }

        g_etwSession.isActive.store(false);

        // Close consumer trace (this will unblock ProcessTrace)
        if (g_etwSession.consumerHandle != 0) {
            ULONG status = CloseTrace(g_etwSession.consumerHandle);
            if (status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING) {
                SetWin32Error(err, L"CloseTrace", status,
                    L"Failed to close trace consumer.");
            }
            g_etwSession.consumerHandle = 0;
        }

        // Wait for consumer thread to finish
        if (g_etwSession.consumerThread.joinable()) {
            g_etwSession.consumerThread.join();
        }

        // Stop trace session
        if (g_etwSession.sessionHandle != 0) {
            constexpr wchar_t sessionName[] = L"ShadowStrike-ProcessTrace";
            ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName) + sizeof(wchar_t);
            std::vector<BYTE> buffer(bufferSize, 0);

            auto* properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
            properties->Wnode.BufferSize = bufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ULONG status = ControlTraceW(g_etwSession.sessionHandle, sessionName, properties,
                EVENT_TRACE_CONTROL_STOP);

            if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
                SetWin32Error(err, L"ControlTraceW(STOP)", status,
                    L"Failed to stop trace session.");
                g_etwSession.sessionHandle = 0;
                return false;
            }

            g_etwSession.sessionHandle = 0;
        }

        return true;
    }
}
bool CreateProcessSnapshot(std::vector<ProcessInfo>& snapshot, Error* err) noexcept {
    snapshot.clear();
    std::vector<ProcessId> pids;
    if (!EnumerateProcesses(pids, err)) return false;
    for (auto pid : pids) {
        ProcessInfo pi{};
        if (GetProcessInfo(pid, pi, nullptr)) {
            snapshot.push_back(std::move(pi));
        }
    }
    return true;
}

bool CompareProcessSnapshots(const std::vector<ProcessInfo>& before,
    const std::vector<ProcessInfo>& after,
    std::vector<ProcessId>& added,
    std::vector<ProcessId>& removed,
    std::vector<ProcessId>& modified) noexcept {
    added.clear(); removed.clear(); modified.clear();
    std::unordered_map<ProcessId, const ProcessInfo*> mapBefore, mapAfter;
    for (auto& b : before) mapBefore[b.basic.pid] = &b;
    for (auto& a : after) mapAfter[a.basic.pid] = &a;

    for (auto& [pid, a] : mapAfter) {
        if (!mapBefore.count(pid)) added.push_back(pid);
    }
    for (auto& [pid, b] : mapBefore) {
        if (!mapAfter.count(pid)) removed.push_back(pid);
    }
    for (auto& [pid, a] : mapAfter) {
        auto it = mapBefore.find(pid);
        if (it != mapBefore.end()) {
            const auto* b = it->second;
            if (a->basic.executablePath != b->basic.executablePath ||
                a->basic.threadCount != b->basic.threadCount ||
                a->basic.handleCount != b->basic.handleCount) {
                modified.push_back(pid);
            }
        }
    }
    return true;
}

bool CreateProcessDump(ProcessId pid, std::wstring_view dumpFilePath, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err)) return false;

    HANDLE hFile = CreateFileW(std::wstring(dumpFilePath).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateFileW(dump)");
        return false;
    }
    auto fh = make_unique_handle(hFile);

    BOOL ok = MiniDumpWriteDump(ph.Get(), pid, fh.get(), MiniDumpWithFullMemory, nullptr, nullptr, nullptr);
    if (!ok) {
        SetWin32Error(err, L"MiniDumpWriteDump(Full)");
        return false;
    }
    return true;
}

bool CreateMiniDump(ProcessId pid, std::wstring_view dumpFilePath, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, err)) return false;

    HANDLE hFile = CreateFileW(std::wstring(dumpFilePath).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateFileW(minidump)");
        return false;
    }
    auto fh = make_unique_handle(hFile);

    BOOL ok = MiniDumpWriteDump(ph.Get(), pid, fh.get(), MiniDumpWithDataSegs, nullptr, nullptr, nullptr);
    if (!ok) {
        SetWin32Error(err, L"MiniDumpWriteDump(Mini)");
        return false;
    }
    return true;
}

// ==========================================================
// WMI Integration (Windows Management Instrumentation)
// ==========================================================

    // RAII wrapper for COM initialization
    class ComInitializer {
    public:
        ComInitializer() noexcept {
            m_hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            m_initialized = SUCCEEDED(m_hr);
        }

        ~ComInitializer() noexcept {
            if (m_initialized) {
                CoUninitialize();
            }
        }

        bool IsInitialized() const noexcept { return m_initialized; }
        HRESULT GetHResult() const noexcept { return m_hr; }

        ComInitializer(const ComInitializer&) = delete;
        ComInitializer& operator=(const ComInitializer&) = delete;

    private:
        HRESULT m_hr = E_FAIL;
        bool m_initialized = false;
    };

    // RAII wrapper for COM security initialization
    class ComSecurityInitializer {
    public:
        ComSecurityInitializer() noexcept {
            m_hr = CoInitializeSecurity(
                nullptr,                        // Security descriptor
                -1,                             // COM authentication
                nullptr,                        // Authentication services
                nullptr,                        // Reserved
                RPC_C_AUTHN_LEVEL_DEFAULT,      // Default authentication
                RPC_C_IMP_LEVEL_IMPERSONATE,    // Default Impersonation
                nullptr,                        // Authentication info
                EOAC_NONE,                      // Additional capabilities
                nullptr                         // Reserved
            );
            m_initialized = SUCCEEDED(m_hr);
        }

        bool IsInitialized() const noexcept { return m_initialized; }
        HRESULT GetHResult() const noexcept { return m_hr; }

    private:
        HRESULT m_hr = E_FAIL;
        bool m_initialized = false;
    };

    // Helper to convert VARIANT to std::wstring
    std::wstring VariantToWString(const VARIANT& var) {
        if (var.vt == VT_BSTR && var.bstrVal) {
            return std::wstring(var.bstrVal, SysStringLen(var.bstrVal));
        }
        else if (var.vt == VT_LPWSTR && var.bstrVal) {
            return std::wstring(var.bstrVal);
        }
        return L"";
    }

    // Helper to convert VARIANT to DWORD
    DWORD VariantToDWord(const VARIANT& var) {
        if (var.vt == VT_UI4) {
            return var.ulVal;
        }
        else if (var.vt == VT_I4) {
            return static_cast<DWORD>(var.lVal);
        }
        return 0;
    }

    // Helper to convert VARIANT to uint64_t
    uint64_t VariantToUInt64(const VARIANT& var) {
        if (var.vt == VT_UI8) {
            return var.ullVal;
        }
        else if (var.vt == VT_I8) {
            return static_cast<uint64_t>(var.llVal);
        }
        else if (var.vt == VT_BSTR) {
            // WMI sometimes returns uint64 as string
            try {
                return std::stoull(var.bstrVal);
            }
            catch (...) {
                return 0;
            }
        }
        return 0;
    }

    // Helper to get WMI property
    bool GetWmiProperty(IWbemClassObject* obj, const wchar_t* propName, VARIANT& var) {
        if (!obj || !propName) return false;
        VariantInit(&var);
        HRESULT hr = obj->Get(propName, 0, &var, nullptr, nullptr);
        return SUCCEEDED(hr);
    }

    // Convert WMI DateTime to FILETIME
    bool WmiDateTimeToFileTime(const std::wstring& wmiDateTime, FILETIME& ft) {
        // WMI DateTime format: yyyymmddHHMMSS.mmmmmmsUUU
        // Example: 20231215143025.500000+000
        if (wmiDateTime.length() < 14) return false;

        SYSTEMTIME st = {};
        try {
            st.wYear = static_cast<WORD>(std::stoi(wmiDateTime.substr(0, 4)));
            st.wMonth = static_cast<WORD>(std::stoi(wmiDateTime.substr(4, 2)));
            st.wDay = static_cast<WORD>(std::stoi(wmiDateTime.substr(6, 2)));
            st.wHour = static_cast<WORD>(std::stoi(wmiDateTime.substr(8, 2)));
            st.wMinute = static_cast<WORD>(std::stoi(wmiDateTime.substr(10, 2)));
            st.wSecond = static_cast<WORD>(std::stoi(wmiDateTime.substr(12, 2)));
            st.wMilliseconds = 0;

            return SystemTimeToFileTime(&st, &ft) == TRUE;
        }
        catch (...) {
            return false;
        }
    }


bool GetProcessInfoWMI(ProcessId pid, ProcessInfo& info, Error* err) noexcept {
    info = {};

    // Initialize COM
    ComInitializer comInit;
    if (!comInit.IsInitialized()) {
        SetWin32Error(err, L"GetProcessInfoWMI", ERROR_NOT_READY,
            L"Failed to initialize COM library.");
        return false;
    }

    // Initialize COM security
    ComSecurityInitializer comSecurity;
    if (!comSecurity.IsInitialized() && comSecurity.GetHResult() != RPC_E_TOO_LATE) {
        // RPC_E_TOO_LATE means security was already initialized, which is fine
        SetWin32Error(err, L"GetProcessInfoWMI", ERROR_NOT_READY,
            L"Failed to initialize COM security.");
        return false;
    }

    // Create WMI locator
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hr) || !pLoc) {
        SetWin32Error(err, L"CoCreateInstance(WbemLocator)", ERROR_NOT_READY,
            L"Failed to create WMI locator instance.");
        return false;
    }

    // Connect to WMI namespace
    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),    // WMI namespace
        nullptr,                     // User name (NULL = current user)
        nullptr,                     // User password (NULL = current)
        nullptr,                     // Locale
        0,                           // Security flags
        nullptr,                     // Authority
        nullptr,                     // Context object
        &pSvc                        // IWbemServices proxy
    );

    pLoc->Release();

    if (FAILED(hr) || !pSvc) {
        SetWin32Error(err, L"ConnectServer", ERROR_NOT_READY,
            L"Failed to connect to WMI namespace ROOT\\CIMV2.");
        return false;
    }

    // Set security levels on the proxy
    hr = CoSetProxyBlanket(
        pSvc,                          // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,             // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,              // RPC_C_AUTHZ_xxx
        nullptr,                       // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,        // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE,   // RPC_C_IMP_LEVEL_xxx
        nullptr,                       // client identity
        EOAC_NONE                      // proxy capabilities
    );

    if (FAILED(hr)) {
        pSvc->Release();
        SetWin32Error(err, L"CoSetProxyBlanket", ERROR_NOT_READY,
            L"Failed to set proxy security blanket.");
        return false;
    }

    // Build WQL query for specific process
    std::wostringstream query;
    query << L"SELECT * FROM Win32_Process WHERE ProcessId = " << pid;

    // Execute query
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.str().c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hr) || !pEnumerator) {
        pSvc->Release();
        SetWin32Error(err, L"ExecQuery", ERROR_NOT_READY,
            L"WMI query execution failed.");
        return false;
    }

    // Get the process object
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

    if (FAILED(hr) || uReturn == 0 || !pclsObj) {
        pEnumerator->Release();
        pSvc->Release();
        SetWin32Error(err, L"GetProcessInfoWMI", ERROR_NOT_FOUND,
            L"Process not found in WMI.");
        return false;
    }

    // Extract process information
    VARIANT vtProp;
    VariantInit(&vtProp);

    // Basic information
    info.basic.pid = pid;

    // Process name
    if (GetWmiProperty(pclsObj, L"Name", vtProp)) {
        info.basic.name = VariantToWString(vtProp);
        VariantClear(&vtProp);
    }

    // Executable path
    if (GetWmiProperty(pclsObj, L"ExecutablePath", vtProp)) {
        info.basic.executablePath = VariantToWString(vtProp);
        VariantClear(&vtProp);
    }

    // Command line
    if (GetWmiProperty(pclsObj, L"CommandLine", vtProp)) {
        info.basic.commandLine = VariantToWString(vtProp);
        VariantClear(&vtProp);
    }

    // Parent process ID
    if (GetWmiProperty(pclsObj, L"ParentProcessId", vtProp)) {
        info.basic.parentPid = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // Session ID
    if (GetWmiProperty(pclsObj, L"SessionId", vtProp)) {
        info.basic.sessionId = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // Thread count
    if (GetWmiProperty(pclsObj, L"ThreadCount", vtProp)) {
        info.basic.threadCount = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // Handle count
    if (GetWmiProperty(pclsObj, L"HandleCount", vtProp)) {
        info.basic.handleCount = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // Priority
    if (GetWmiProperty(pclsObj, L"Priority", vtProp)) {
        info.basic.basePriority = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // Creation date
    if (GetWmiProperty(pclsObj, L"CreationDate", vtProp)) {
        std::wstring dateStr = VariantToWString(vtProp);
        WmiDateTimeToFileTime(dateStr, info.basic.creationTime);
        VariantClear(&vtProp);
    }

    // Memory information
    if (GetWmiProperty(pclsObj, L"WorkingSetSize", vtProp)) {
        info.memory.workingSetSize = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"PeakWorkingSetSize", vtProp)) {
        info.memory.peakWorkingSetSize = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"PrivatePageCount", vtProp)) {
        info.memory.privateMemorySize = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"VirtualSize", vtProp)) {
        info.memory.virtualMemorySize = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"PeakVirtualSize", vtProp)) {
        info.memory.peakVirtualMemorySize = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"PageFaults", vtProp)) {
        info.memory.pageFaultCount = VariantToDWord(vtProp);
        VariantClear(&vtProp);
    }

    // I/O counters
    if (GetWmiProperty(pclsObj, L"ReadOperationCount", vtProp)) {
        info.io.readOperationCount = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"WriteOperationCount", vtProp)) {
        info.io.writeOperationCount = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"ReadTransferCount", vtProp)) {
        info.io.readTransferCount = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"WriteTransferCount", vtProp)) {
        info.io.writeTransferCount = VariantToUInt64(vtProp);
        VariantClear(&vtProp);
    }

    // CPU information
    if (GetWmiProperty(pclsObj, L"KernelModeTime", vtProp)) {
        info.cpu.kernelCpuTimeMs = VariantToUInt64(vtProp) / 10000; // Convert 100ns to ms
        VariantClear(&vtProp);
    }

    if (GetWmiProperty(pclsObj, L"UserModeTime", vtProp)) {
        info.cpu.userCpuTimeMs = VariantToUInt64(vtProp) / 10000; // Convert 100ns to ms
        VariantClear(&vtProp);
    }

    info.cpu.totalCpuTimeMs = info.cpu.kernelCpuTimeMs + info.cpu.userCpuTimeMs;

    // Get owner information using GetOwner method
    IWbemClassObject* pOutParams = nullptr;

    std::wstring wmiPath = L"Win32_Process.Handle=\"" + std::to_wstring(pid) + L"\"";
    hr = pSvc->ExecMethod(
        _bstr_t(wmiPath.c_str()),
        _bstr_t(L"GetOwner"),
        0,
        nullptr,
        nullptr,
        &pOutParams,
        nullptr
    );

    if (SUCCEEDED(hr) && pOutParams) {
        VARIANT vtDomain, vtUser;
        VariantInit(&vtDomain);
        VariantInit(&vtUser);

        if (GetWmiProperty(pOutParams, L"Domain", vtDomain) &&
            GetWmiProperty(pOutParams, L"User", vtUser)) {
            std::wstring domain = VariantToWString(vtDomain);
            std::wstring user = VariantToWString(vtUser);
            if (!domain.empty() && !user.empty()) {
                info.security.userName = domain + L"\\" + user;
            }
            VariantClear(&vtDomain);
            VariantClear(&vtUser);
        }

        pOutParams->Release();
    }

    // Cleanup
    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();

    // Fill in additional details using native APIs if available
    GetProcessMemoryInfo(pid, info.memory, nullptr);
    GetProcessCpuInfo(pid, info.cpu, nullptr);
    GetProcessSecurityInfo(pid, info.security, nullptr);
    EnumerateProcessModules(pid, info.modules, nullptr);
    EnumerateProcessThreads(pid, info.threads, nullptr);

    return true;
}

bool EnumerateProcessesWMI(std::vector<ProcessBasicInfo>& processes, Error* err) noexcept {
    processes.clear();

    // Initialize COM
    ComInitializer comInit;
    if (!comInit.IsInitialized()) {
        SetWin32Error(err, L"EnumerateProcessesWMI", ERROR_NOT_READY,
            L"Failed to initialize COM library.");
        return false;
    }

    // Initialize COM security
    ComSecurityInitializer comSecurity;
    if (!comSecurity.IsInitialized() && comSecurity.GetHResult() != RPC_E_TOO_LATE) {
        SetWin32Error(err, L"EnumerateProcessesWMI", ERROR_NOT_READY,
            L"Failed to initialize COM security.");
        return false;
    }

    // Create WMI locator
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hr) || !pLoc) {
        SetWin32Error(err, L"CoCreateInstance(WbemLocator)", ERROR_NOT_READY,
            L"Failed to create WMI locator instance.");
        return false;
    }

    // Connect to WMI namespace
    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &pSvc
    );

    pLoc->Release();

    if (FAILED(hr) || !pSvc) {
        SetWin32Error(err, L"ConnectServer", ERROR_NOT_READY,
            L"Failed to connect to WMI namespace ROOT\\CIMV2.");
        return false;
    }

    // Set security levels
    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        pSvc->Release();
        SetWin32Error(err, L"CoSetProxyBlanket", ERROR_NOT_READY,
            L"Failed to set proxy security blanket.");
        return false;
    }

    // Query all processes
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_Process"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hr) || !pEnumerator) {
        pSvc->Release();
        SetWin32Error(err, L"ExecQuery", ERROR_NOT_READY,
            L"WMI query execution failed.");
        return false;
    }

    // Enumerate processes
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;

    while (true) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(hr) || uReturn == 0 || !pclsObj) break;

        ProcessBasicInfo info{};
        VARIANT vtProp;
        VariantInit(&vtProp);

        // Process ID
        if (GetWmiProperty(pclsObj, L"ProcessId", vtProp)) {
            info.pid = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Process name
        if (GetWmiProperty(pclsObj, L"Name", vtProp)) {
            info.name = VariantToWString(vtProp);
            VariantClear(&vtProp);
        }

        // Executable path
        if (GetWmiProperty(pclsObj, L"ExecutablePath", vtProp)) {
            info.executablePath = VariantToWString(vtProp);
            VariantClear(&vtProp);
        }

        // Command line
        if (GetWmiProperty(pclsObj, L"CommandLine", vtProp)) {
            info.commandLine = VariantToWString(vtProp);
            VariantClear(&vtProp);
        }

        // Parent process ID
        if (GetWmiProperty(pclsObj, L"ParentProcessId", vtProp)) {
            info.parentPid = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Session ID
        if (GetWmiProperty(pclsObj, L"SessionId", vtProp)) {
            info.sessionId = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Thread count
        if (GetWmiProperty(pclsObj, L"ThreadCount", vtProp)) {
            info.threadCount = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Handle count
        if (GetWmiProperty(pclsObj, L"HandleCount", vtProp)) {
            info.handleCount = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Priority
        if (GetWmiProperty(pclsObj, L"Priority", vtProp)) {
            info.basePriority = VariantToDWord(vtProp);
            VariantClear(&vtProp);
        }

        // Creation date
        if (GetWmiProperty(pclsObj, L"CreationDate", vtProp)) {
            std::wstring dateStr = VariantToWString(vtProp);
            WmiDateTimeToFileTime(dateStr, info.creationTime);
            VariantClear(&vtProp);
        }

        // Mark system processes
        info.isSystemProcess = (info.pid == 0 || info.pid == 4);

        // Window title (requires additional query - skip for performance)
        // Can be retrieved separately if needed

        processes.push_back(std::move(info));
        pclsObj->Release();
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();

    return true;
}

        } // namespace ProcessUtils
    } // namespace Utils
} // namespace ShadowStrike