
#include "ProcessUtils.hpp"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include<evntrace.h>
#include<evntcons.h>
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

#include <processthreadsapi.h>
#include <tchar.h>
#include <powrprof.h>
#include <DbgHelp.h>
#include <sddl.h>
#include<winternl.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "tdh.lib") //For Event Decoding

namespace ShadowStrike {
    namespace Utils {
        namespace ProcessUtils {

            // ==========================================================
            // Internal helpers
            // ==========================================================

            namespace {

                using unique_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&::CloseHandle)>;

                inline unique_handle make_unique_handle(HANDLE h) noexcept {
                    return unique_handle(h, &::CloseHandle);
                }

                void SetWin32Error(Error* err, std::wstring_view ctx, DWORD code = ::GetLastError(), std::wstring_view customMsg = L"") noexcept {
                    if (!err) return;
                    err->Clear();
                    err->win32 = code;
                    err->context = ctx;
                    if (!customMsg.empty()) {
                        err->message.assign(customMsg);
                        return;
                    }

                    LPWSTR buf = nullptr;
                    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
                    if (FormatMessageW(flags, nullptr, code, 0, (LPWSTR)&buf, 0, nullptr) && buf) {
                        err->message.assign(buf);
                        LocalFree(buf);
                    }
                    else {
                        std::wostringstream os;
                        os << L"Win32 error " << code;
                        err->message = os.str();
                    }
                }

                void SetNtError(Error* err, std::wstring_view ctx, LONG status, std::wstring_view customMsg = L"") noexcept {
                    if (!err) return;
                    err->Clear();
                    err->ntstatus = status;
                    err->context = ctx;
                    if (!customMsg.empty()) {
                        err->message.assign(customMsg);
                    }
                    else {
                        std::wostringstream os;
                        os << L"NTSTATUS 0x" << std::hex << std::uppercase << (unsigned long)status;
                        err->message = os.str();
                    }
                }

                std::wstring ToLower(std::wstring s) {
                    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
                    return s;
                }

                std::wstring BaseName(const std::wstring& p) {
                    size_t pos = p.find_last_of(L"\\/");
                    if (pos == std::wstring::npos) return p;
                    return p.substr(pos + 1);
                }

                bool WildcardMatchInsensitive(std::wstring_view pattern, std::wstring_view text) {
                    auto p = ToLower(std::wstring(pattern));
                    auto t = ToLower(std::wstring(text));

                    size_t pi = 0, ti = 0, star = std::wstring::npos, mark = 0;
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
                    while (pi < p.size() && p[pi] == L'*') ++pi;
                    return pi == p.size();
                }

                template <typename F>
                void EnumerateTopLevelWindowsForPid(DWORD pid, F&& f) {
                    struct Ctx { DWORD pid; F* func; };
                    Ctx ctx{ pid, &f };
                    auto cb = [](HWND h, LPARAM lparam)->BOOL {
                        auto* c = reinterpret_cast<Ctx*>(lparam);
                        DWORD wpid = 0;
                        GetWindowThreadProcessId(h, &wpid);
                        if (wpid == c->pid) {
                            (*c->func)(h);
                        }
                        return TRUE;
                        };
                    EnumWindows(cb, reinterpret_cast<LPARAM>(&ctx));
                }

                bool GetMainWindowTitleForPid(DWORD pid, std::wstring& titleOut) {
                    std::wstring best;
                    EnumerateTopLevelWindowsForPid(pid, [&](HWND h) {
                        if (!IsWindowVisible(h)) return;
                        wchar_t buf[1024] = {};
                        int len = GetWindowTextW(h, buf, 1024);
                        if (len > 0) {
                            std::wstring t(buf, buf + len);
                            if (t.size() > best.size()) best = std::move(t);
                        }
                        });
                    if (!best.empty()) {
                        titleOut = std::move(best);
                        return true;
                    }
                    return false;
                }

                bool QueryFullImagePath(HANDLE hProcess, std::wstring& path) {
                    DWORD len = MAX_PATH;
                    std::wstring tmp(len, L'\0');
                    if (!QueryFullProcessImageNameW(hProcess, 0, tmp.data(), &len)) {
                        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                            tmp.resize(len + 1);
                            if (!QueryFullProcessImageNameW(hProcess, 0, tmp.data(), &len)) return false;
                        }
                        else {
                            return false;
                        }
                    }
                    tmp.resize(len);
                    path = std::move(tmp);
                    return true;
                }

                bool IsProcessWow64Cached(HANDLE hProcess, bool& isWow64) {
                    typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
                    static IsWow64Process2_t pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");

                    if (pIsWow64Process2) {
                        USHORT p, n;
                        if (!pIsWow64Process2(hProcess, &p, &n)) return false;
                        isWow64 = (p != IMAGE_FILE_MACHINE_UNKNOWN) && (p != n);
                        return true;
                    }
                    else {
                        BOOL wow = FALSE;
                        if (!IsWow64Process(hProcess, &wow)) return false;
                        isWow64 = (wow == TRUE);
                        return true;
                    }
                }

                bool IsCurrentOS64Bit() {
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

                bool GetProcessTimesMs(HANDLE hProcess, uint64_t& kernelMs, uint64_t& userMs) {
                    FILETIME ct{}, et{}, kt{}, ut{};
                    if (!GetProcessTimes(hProcess, &ct, &et, &kt, &ut)) return false;
                    auto ftToMs = [](const FILETIME& ft) -> uint64_t {
                        ULARGE_INTEGER u{};
                        u.LowPart = ft.dwLowDateTime;
                        u.HighPart = ft.dwHighDateTime;
                        return u.QuadPart / 10000ULL;
                        };
                    kernelMs = ftToMs(kt);
                    userMs = ftToMs(ut);
                    return true;
                }

                struct CpuSample {
                    uint64_t kernelMs = 0;
                    uint64_t userMs = 0;
                    uint64_t timestampMs = 0;
                    DWORD affinity = 0;
                    int priority = NORMAL_PRIORITY_CLASS;
                };
                std::mutex g_cpuMutex;
                std::unordered_map<DWORD, CpuSample> g_cpuPrev;

                uint64_t GetTickCount64Ms() {
                    return GetTickCount64();
                }

                template<typename T>
                bool SafeGetModuleInfo(HANDLE hProcess, HMODULE mod, T& mi) {
                    memset(&mi, 0, sizeof(T));
                    return GetModuleInformation(hProcess, mod, (MODULEINFO*)&mi, sizeof(T)) == TRUE;
                }

                using NtSuspendProcess_t = LONG(NTAPI*)(HANDLE);
                using NtResumeProcess_t = LONG(NTAPI*)(HANDLE);

                NtSuspendProcess_t GetNtSuspendProcess() {
                    static auto fn = reinterpret_cast<NtSuspendProcess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess"));
                    return fn;
                }
                NtResumeProcess_t GetNtResumeProcess() {
                    static auto fn = reinterpret_cast<NtResumeProcess_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"));
                    return fn;
                }

            } // anon namespace

            // ==========================================================
            // ProcessHandle RAII Implementation
            // ==========================================================

            ProcessHandle::ProcessHandle(ProcessId pid, DWORD desiredAccess, Error* err) noexcept {
                Open(pid, desiredAccess, err);
            }

            bool ProcessHandle::Open(ProcessId pid, DWORD desiredAccess, Error* err) noexcept {
                Close();
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
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == INVALID_HANDLE_VALUE) {
                    SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
                    return false;
                }
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (!Process32FirstW(hSnap, &pe)) {
                    SetWin32Error(err, L"Process32FirstW");
                    CloseHandle(hSnap);
                    return false;
                }
                do {
                    pids.push_back(pe.th32ProcessID);
                } while (Process32NextW(hSnap, &pe));
                CloseHandle(hSnap);
                return true;
            }

            bool GetProcessBasicInfo(ProcessId pid, ProcessBasicInfo& info, Error* err) noexcept {
                info = {};
                info.pid = pid;

                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe{};
                    pe.dwSize = sizeof(pe);
                    if (Process32FirstW(hSnap, &pe)) {
                        do {
                            if (pe.th32ProcessID == pid) {
                                info.parentPid = pe.th32ParentProcessID;
                                info.basePriority = pe.pcPriClassBase;
                                info.threadCount = pe.cntThreads;
                                info.name = pe.szExeFile;
                                break;
                            }
                        } while (Process32NextW(hSnap, &pe));
                    }
                    CloseHandle(hSnap);
                }

                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, nullptr)) {
                    if (err) SetWin32Error(err, L"OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)");
                    info.isSystemProcess = (pid == 4 || pid == 0);
                    return err == nullptr;
                }

                std::wstring fullPath;
                if (QueryFullImagePath(ph.Get(), fullPath)) {
                    info.executablePath = std::move(fullPath);
                    if (info.name.empty()) info.name = BaseName(info.executablePath);
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

                info.priorityClass = static_cast<int64_t>(GetPriorityClass(ph.Get()));

                bool wow = false;
                if (IsProcessWow64Cached(ph.Get(), wow)) {
                    info.isWow64 = wow;
                    info.is64Bit = IsCurrentOS64Bit() && !wow;
                }

                std::wstring title;
                if (GetMainWindowTitleForPid(pid, title)) {
                    info.windowTitle = std::move(title);
                    info.hasGUI = true;
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

                for (auto pid : pids) {
                    if (!options.includeIdleProcess && pid == 0) continue;
                    if (!options.includeCurrentProcess && pid == ::GetCurrentProcessId()) continue;

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
                    if (options.userFilter) {
                        ProcessSecurityInfo sec{};
                        if (GetProcessSecurityInfo(pid, sec, nullptr)) {
                            if (ToLower(sec.userName) != ToLower(*options.userFilter)) continue;
                        }
                        else {
                            continue;
                        }
                    }

                    processes.push_back(std::move(bi));
                }

                if (options.sortByName) {
                    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
                        return ToLower(a.name) < ToLower(b.name);
                        });
                }
                else if (options.sortByPid) {
                    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
                        return a.pid < b.pid;
                        });
                }
                else if (options.sortByMemoryUsage) {
                    for (auto& p : processes) {
                        ProcessMemoryInfo mi{};
                        if (QueryProcessMemoryInfo(p.pid, mi, nullptr)) {
                            p.handleCount = static_cast<DWORD>(mi.workingSetSize);
                        }
                    }
                    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
                        return a.handleCount > b.handleCount;
                        });
                }
                else if (options.sortByCpuUsage) {
                    for (auto& p : processes) {
                        ProcessCpuInfo ci{};
                        GetProcessCpuInfo(p.pid, ci, nullptr);
                        p.basePriority = static_cast<int64_t>(ci.cpuUsagePercent * 1000.0);
                    }
                    std::sort(processes.begin(), processes.end(), [](const auto& a, const auto& b) {
                        return a.basePriority > b.basePriority;
                        });
                }

                return true;
            }

            // ==========================================================
            // Process Information Retrieval
            // ==========================================================

            bool QueryProcessMemoryInfo(ProcessId pid, ProcessMemoryInfo& info, Error* err) noexcept {
                info = {};
                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, err)) return false;

                PROCESS_MEMORY_COUNTERS_EX pmc{};
                if (!::GetProcessMemoryInfo(ph.Get(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    SetWin32Error(err, L"GetProcessMemoryInfo");
                    return false;
                }
                info.workingSetSize = pmc.WorkingSetSize;
                info.peakWorkingSetSize = pmc.PeakWorkingSetSize;
                info.privateMemorySize = pmc.PrivateUsage;
                info.pageFaultCount = pmc.PageFaultCount;
                return true;
            }

            bool GetProcessIOCounters(ProcessId pid, ProcessIOCounters& io, Error* err) noexcept {
                io = {};
                ProcessHandle ph;
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

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
                if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

                DWORD_PTR affinity = 0, sysAffinity = 0;
                if (GetProcessAffinityMask(ph.Get(), &affinity, &sysAffinity)) {
                    info.affinityMask = static_cast<DWORD>(affinity);
                }
                info.priorityClass = GetPriorityClass(ph.Get());

                uint64_t kMs = 0, uMs = 0;
                if (!GetProcessTimesMs(ph.Get(), kMs, uMs)) {
                    SetWin32Error(err, L"GetProcessTimes");
                    return false;
                }

                const uint64_t now = GetTickCount64Ms();

                std::lock_guard<std::mutex> lock(g_cpuMutex);
                auto it = g_cpuPrev.find(pid);
                if (it != g_cpuPrev.end()) {
                    const auto& prev = it->second;
                    uint64_t dt = now - prev.timestampMs;
                    uint64_t dtotal = (kMs + uMs) - (prev.kernelMs + prev.userMs);

                    if (dt > 0) {
                        SYSTEM_INFO si{};
                        GetSystemInfo(&si);
                        uint64_t denom = dt * std::max<DWORD>(1, si.dwNumberOfProcessors);
                        double usage = denom ? (static_cast<double>(dtotal) / static_cast<double>(denom)) * 100.0 : 0.0;
                        info.totalCpuTimeMs = kMs + uMs;
                        info.kernelCpuTimeMs = kMs;
                        info.userCpuTimeMs = uMs;
                        info.cpuUsagePercent = std::clamp(usage, 0.0, 100.0);
                        if (dtotal) {
                            double kpart = static_cast<double>(kMs - prev.kernelMs) / static_cast<double>(dtotal);
                            info.kernelTimePercent = std::clamp(kpart * info.cpuUsagePercent, 0.0, 100.0);
                            info.userTimePercent = std::clamp(info.cpuUsagePercent - info.kernelTimePercent, 0.0, 100.0);
                        }
                    }
                    it->second = CpuSample{ kMs, uMs, now, static_cast<DWORD>(affinity), info.priorityClass };
                }
                else {
                    g_cpuPrev.emplace(pid, CpuSample{ kMs, uMs, now, static_cast<DWORD>(affinity), info.priorityClass });
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
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(ph.Get(), TOKEN_QUERY, &hToken)) {
        SetWin32Error(err, L"OpenProcessToken");
        return false;
    }
    auto token = make_unique_handle(hToken);

    // User information
    DWORD len = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    if (!GetTokenInformation(token.get(), TokenUser, buf.data(), static_cast<DWORD>(buf.size()), &len)) {
        SetWin32Error(err, L"GetTokenInformation(TokenUser)");
        return false;
    }
    auto tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
        sec.userSid = sidStr;
        LocalFree(sidStr);
    }

    WCHAR name[256], domain[256];
    DWORD cchName = 256, cchDomain = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(nullptr, tu->User.Sid, name, &cchName, domain, &cchDomain, &use)) {
        sec.userName = std::wstring(domain) + L"\\" + std::wstring(name);
    }

    // Integrity level
    len = 0;
    GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &len);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> il(len);
        if (GetTokenInformation(token.get(), TokenIntegrityLevel, il.data(), static_cast<DWORD>(il.size()), &len)) {
            auto til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(il.data());
            DWORD subAuthCount = *GetSidSubAuthorityCount(til->Label.Sid);
            DWORD rid = *GetSidSubAuthority(til->Label.Sid, subAuthCount - 1);
            if (rid < SECURITY_MANDATORY_MEDIUM_RID) sec.integrityLevel = L"Low";
            else if (rid < SECURITY_MANDATORY_HIGH_RID) sec.integrityLevel = L"Medium";
            else if (rid < SECURITY_MANDATORY_SYSTEM_RID) sec.integrityLevel = L"High";
            else sec.integrityLevel = L"System";
        }
    }

    // Elevation
    TOKEN_ELEVATION elev{};
    len = sizeof(elev);
    if (GetTokenInformation(token.get(), TokenElevation, &elev, sizeof(elev), &len)) {
        sec.isElevated = elev.TokenIsElevated != 0;
    }

    // Group membership: SYSTEM / SERVICE
    len = 0;
    GetTokenInformation(token.get(), TokenGroups, nullptr, 0, &len);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> gr(len);
        if (GetTokenInformation(token.get(), TokenGroups, gr.data(), static_cast<DWORD>(gr.size()), &len)) {
            auto tg = reinterpret_cast<TOKEN_GROUPS*>(gr.data());
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            PSID sidSystem = nullptr, sidService = nullptr;
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sidSystem);
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &sidService);
            for (DWORD i = 0; i < tg->GroupCount; i++) {
                if (sidSystem && EqualSid(tg->Groups[i].Sid, sidSystem)) sec.isRunningAsSystem = true;
                if (sidService && EqualSid(tg->Groups[i].Sid, sidService)) sec.isRunningAsService = true;
            }
            if (sidSystem) FreeSid(sidSystem);
            if (sidService) FreeSid(sidService);
        }
    }

    // Privileges
    len = 0;
    GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &len);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> pv(len);
        if (GetTokenInformation(token.get(), TokenPrivileges, pv.data(), static_cast<DWORD>(pv.size()), &len)) {
            auto tp = reinterpret_cast<TOKEN_PRIVILEGES*>(pv.data());
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                WCHAR privName[256]; DWORD cch = 256;
                if (LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, privName, &cch)) {
                    sec.enabledPrivileges.emplace_back(privName);
                    if (_wcsicmp(privName, L"SeDebugPrivilege") == 0) {
                        sec.hasSeDebugPrivilege = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                        if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                            sec.hasDebugPrivilege = true;
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
    QueryProcessMemoryInfo(pid, info.memory, nullptr);
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

std::optional<std::wstring> GetProcessCommandLine(ProcessId /*pid*/, Error* err) noexcept {
    if (err) SetWin32Error(err, L"GetProcessCommandLine", ERROR_NOT_SUPPORTED, L"Process Command Line is not supported at this version.");
    return std::nullopt;
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

std::optional<ProcessId> GetParentProcessId(ProcessId pid, Error* err) noexcept {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return std::nullopt;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(hSnap);
                return pe.th32ParentProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return std::nullopt;
}

bool GetChildProcesses(ProcessId parentPid, std::vector<ProcessId>& children, Error* err) noexcept {
    children.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return false;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid) children.push_back(pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
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
        
bool IsProcessRunning(ProcessId pid) noexcept {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    bool running = false;
    if (GetExitCodeProcess(h, &code)) {
        running = (code == STILL_ACTIVE);
    }
    CloseHandle(h);
    return running;
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
        SetWin32Error(err, L"NtQueryInformationProcess", ERROR_CALL_NOT_IMPLEMENTED, L"NtQueryInformationProcess failed to find.");
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
        SetWin32Error(err, L"GetProcessInformation", ERROR_CALL_NOT_IMPLEMENTED, L"ProcessProtectionLevel query is not supported.");
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

bool IsProcessSuspended(ProcessId pid, Error* /*err*/) noexcept {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool anyThread = false;
    bool anyRunning = false;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                anyThread = true;
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    DWORD prev = ::SuspendThread(hThread);
                    if (prev == (DWORD)-1) {
                        anyRunning = true;
                    }
                    else {
                        if (prev == 0) anyRunning = true;
                        ::ResumeThread(hThread);
                    }
                    CloseHandle(hThread);
                }
                else {
                    anyRunning = true;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
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
    if (auto fn = GetNtSuspendProcess()) {
        LONG st = fn(ph.Get());
        if (st != 0) { SetNtError(err, L"NtSuspendProcess", st); return false; }
        return true;
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)"); return false; }
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { ::SuspendThread(hThread); CloseHandle(hThread); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return true;
}

bool ResumeProcess(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, nullptr)) {
        if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    }
    if (auto fn = GetNtResumeProcess()) {
        LONG st = fn(ph.Get());
        if (st != 0) { SetNtError(err, L"NtResumeProcess", st); return false; }
        return true;
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)"); return false; }
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { while (::ResumeThread(hThread) > 0) {} CloseHandle(hThread); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
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
    SetWin32Error(err, L"GetModuleExportAddress", ERROR_NOT_SUPPORTED, L"Getting module export address is not supported.");
    return std::nullopt;
}

bool InjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err) noexcept {
    //check the existence of the DLL file 
    if (!FileUtils::Exists(std::wstring(dllPath))) {
        SetWin32Error(err, L"InjectDLL", ERROR_FILE_NOT_FOUND, L"Failed to find the DLL file.");
        return false;
    }

	//convert the dll path to full path
    std::wstring fullDllPath;
    {
        wchar_t buffer[MAX_PATH * 2] = {};
        DWORD len = GetFullPathNameW(dllPath.data(), MAX_PATH * 2, buffer, nullptr);
        if (len == 0) {
            SetWin32Error(err, L"GetFullPathNameW");
            return false;
        }
        fullDllPath.assign(buffer, len);
    }

	//Access to the target process
    ProcessHandle ph;
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_LIMITED_INFORMATION;

    if (!ph.Open(pid, desiredAccess, err)) {
		//if access denied, try to enable SeDebugPrivilege and retry
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                auto token = make_unique_handle(hToken);

                LUID luid{};
                if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
                    TOKEN_PRIVILEGES tp{};
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);

                    // Try Again
                    if (!ph.Open(pid, desiredAccess, err)) {
                        return false;
                    }
                }
                else {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }

	//check target process architecture (32-bit/64-bit)
    bool targetIs64Bit = false;
    if (!IsProcessWow64Cached(ph.Get(), targetIs64Bit)) {
        if (IsCurrentOS64Bit()) {
			targetIs64Bit = true; // Assume 64-bit if check fails on 64-bit OS
        }
    }
    else {
        if (IsCurrentOS64Bit()) {
			targetIs64Bit = !targetIs64Bit; // if not wow64, then it's 64-bit
        }
    }

    bool currentIs64Bit = false;
#if defined(_WIN64)
    currentIs64Bit = true;
#else
    BOOL wow = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow)) {
        currentIs64Bit = (wow == FALSE) && IsCurrentOS64Bit();
    }
#endif

    if (currentIs64Bit != targetIs64Bit) {
        SetWin32Error(err, L"InjectDLL", ERROR_BAD_EXE_FORMAT,
            L"target process architectures uncompatible (32-bit/64-bit).");
        return false;
    }

	// get the address of LoadLibraryW in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        SetWin32Error(err, L"GetModuleHandleW(kernel32)");
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        SetWin32Error(err, L"GetProcAddress(LoadLibraryW)");
        return false;
    }

	// allocate memory in the target process for the DLL path
    SIZE_T pathSize = (fullDllPath.size() + 1) * sizeof(wchar_t);
    void* pRemotePath = ::VirtualAllocEx(ph.Get(), nullptr, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        SetWin32Error(err, L"VirtualAllocEx");
        return false;
    }

	// Automatically free the allocated memory on function exit
    struct RemoteMemoryGuard {
        HANDLE hProcess;
        void* pAddress;
        ~RemoteMemoryGuard() {
            if (pAddress && hProcess) {
                ::VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
            }
        }
    } memGuard{ ph.Get(), pRemotePath };

	//write the dll path to the target process memory
    SIZE_T written = 0;
    if (!::WriteProcessMemory(ph.Get(), pRemotePath, fullDllPath.c_str(),
        pathSize, &written) || written != pathSize) {
        SetWin32Error(err, L"WriteProcessMemory");
        return false;
    }

	//Create remote thread in the target process to call LoadLibraryW with the DLL path
    HANDLE hThread = ::CreateRemoteThread(ph.Get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW),
        pRemotePath, 0, nullptr);
    if (!hThread) {
        SetWin32Error(err, L"CreateRemoteThread");
        return false;
    }
    auto thread = make_unique_handle(hThread);

	//Wait for thread to complete (max 10 seconds)
    DWORD waitResult = WaitForSingleObject(thread.get(), 10000);
    if (waitResult == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject(InjectThread)");
        return false;
    }

    if (waitResult == WAIT_TIMEOUT) {
        SetWin32Error(err, L"InjectDLL", ERROR_TIMEOUT,
            L"DLL injection thread zaman aþýmýna uðradý.");
        return false;
    }

	// Check the thread's exit code (which is the HMODULE returned by LoadLibraryW)
    DWORD exitCode = 0;
    if (!GetExitCodeThread(thread.get(), &exitCode)) {
        SetWin32Error(err, L"GetExitCodeThread");
        return false;
    }

	//exitcode is the HMODULE of the loaded DLL, if LoadLibraryW fails, it returns NULL (0)
    if (exitCode == 0) {
        SetWin32Error(err, L"InjectDLL", ERROR_MOD_NOT_FOUND,
            L"DLL hedef süreçte yüklenemedi (LoadLibraryW baþarýsýz).");
        return false;
    }

    // succesfull
    return true;
}

bool EjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err) noexcept {
    ///access to the target process
    ProcessHandle ph;
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION;

    if (!ph.Open(pid, desiredAccess, err)) {
		//Try to enable SeDebugPrivilege and retry if access denied
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                auto token = make_unique_handle(hToken);

                LUID luid{};
                if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
                    TOKEN_PRIVILEGES tp{};
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);

                    // Try again
                    if (!ph.Open(pid, desiredAccess, err)) {
                        return false;
                    }
                }
                else {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }

    // Find the DLL module in the target process
    std::wstring targetDllName = BaseName(std::wstring(dllPath));

    DWORD needed = 0;
    if (!EnumProcessModulesEx(ph.Get(), nullptr, 0, &needed, LIST_MODULES_ALL)) {
        SetWin32Error(err, L"EnumProcessModulesEx(size)");
        return false;
    }

    std::vector<HMODULE> modules(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(ph.Get(), modules.data(),
        static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
        &needed, LIST_MODULES_ALL)) {
        SetWin32Error(err, L"EnumProcessModulesEx(data)");
        return false;
    }

    // find the target DLL
    HMODULE hTargetModule = nullptr;
    wchar_t modulePath[MAX_PATH];
    for (HMODULE hMod : modules) {
        if (GetModuleFileNameExW(ph.Get(), hMod, modulePath, MAX_PATH)) {
            std::wstring modName = BaseName(std::wstring(modulePath));
            if (_wcsicmp(modName.c_str(), targetDllName.c_str()) == 0) {
                hTargetModule = hMod;
                break;
            }
        }
    }

    if (!hTargetModule) {
        SetWin32Error(err, L"EjectDLL", ERROR_MOD_NOT_FOUND,
            L"Belirtilen DLL hedef süreçte bulunamadý.");
        return false;
    }

	//get the address of FreeLibrary in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        SetWin32Error(err, L"GetModuleHandleW(kernel32)");
        return false;
    }

    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");
    if (!pFreeLibrary) {
        SetWin32Error(err, L"GetProcAddress(FreeLibrary)");
        return false;
    }

	// Create remote thread in the target process to call FreeLibrary with the module handle
    HANDLE hThread = ::CreateRemoteThread(ph.Get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pFreeLibrary),
        hTargetModule, 0, nullptr);
    if (!hThread) {
        SetWin32Error(err, L"CreateRemoteThread");
        return false;
    }
    auto thread = make_unique_handle(hThread);

	//wait for thread to complete (max 10 seconds)
    DWORD waitResult = WaitForSingleObject(thread.get(), 10000);
    if (waitResult == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject(EjectThread)");
        return false;
    }

    if (waitResult == WAIT_TIMEOUT) {
        SetWin32Error(err, L"EjectDLL", ERROR_TIMEOUT,
            L"DLL ejection thread zaman aþýmýna uðradý.");
        return false;
    }

	//Control the thread's exit code (which is the BOOL returned by FreeLibrary)
    DWORD exitCode = 0;
    if (!GetExitCodeThread(thread.get(), &exitCode)) {
        SetWin32Error(err, L"GetExitCodeThread");
        return false;
    }

	//FreeLibrary returns non-zero if successful, zero if fails
    if (exitCode == 0) {
        SetWin32Error(err, L"EjectDLL", ERROR_GEN_FAILURE,
            L"DLL hedef süreçten kaldýrýlamadý (FreeLibrary baþarýsýz).");
        return false;
    }

	// Verify if the DLL is really unloaded
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // short wait

    needed = 0;
    if (EnumProcessModulesEx(ph.Get(), nullptr, 0, &needed, LIST_MODULES_ALL)) {
        modules.resize(needed / sizeof(HMODULE));
        if (EnumProcessModulesEx(ph.Get(), modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
            &needed, LIST_MODULES_ALL)) {
            for (HMODULE hMod : modules) {
                if (GetModuleFileNameExW(ph.Get(), hMod, modulePath, MAX_PATH)) {
                    std::wstring modName = BaseName(std::wstring(modulePath));
                    if (_wcsicmp(modName.c_str(), targetDllName.c_str()) == 0) {
						//still loaded
                        if (err) {
                            err->win32 = ERROR_SUCCESS;
                            err->message = L"DLL FreeLibrary çaðrýldý ancak hala yüklü (muhtemelen birden fazla referans).";
                        }
                        return true;
                    }
                }
            }
        }
    }

	// DLL successfully unloaded
    return true;
}

// ==========================================================
// Thread Operations
// ==========================================================

bool EnumerateProcessThreads(ProcessId pid, std::vector<ProcessThreadInfo>& threads, Error* err) noexcept {
    threads.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)");
        return false;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                ProcessThreadInfo ti{};
                ti.tid = te.th32ThreadID;
                ti.ownerPid = te.th32OwnerProcessID;
                ti.basePriority = te.tpBasePri;

                HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    FILETIME ct{}, et{}, kt{}, ut{};
                    if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
                        ti.creationTime = ct;
                        ti.exitTime = et;
                        ti.kernelTime = kt;
                        ti.userTime = ut;
                    }
                    DWORD prev = ::SuspendThread(hThread);
                    if (prev != (DWORD)-1) {
                        ti.isSuspended = (prev > 0);
                        ::ResumeThread(hThread);
                    }
                    CloseHandle(hThread);
                }
                threads.push_back(std::move(ti));
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
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
    FILETIME ct{}, et{}, kt{}, ut{};
    if (GetThreadTimes(hThread, &ct, &et, &kt, &ut)) {
        ti.creationTime = ct;
        ti.exitTime = et;
        ti.kernelTime = kt;
        ti.userTime = ut;
    }
    DWORD prev = ::SuspendThread(hThread);
    if (prev != (DWORD)-1) {
        ti.isSuspended = (prev > 0);
        ::ResumeThread(hThread);
    }
    CloseHandle(hThread);
    return ti;
}

bool SuspendThread(ThreadId tid, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) { SetWin32Error(err, L"OpenThread"); return false; }
    DWORD r = ::SuspendThread(h);
    CloseHandle(h);
    if (r == (DWORD)-1) { SetWin32Error(err, L"SuspendThread"); return false; }
    return true;
}

bool ResumeThread(ThreadId tid, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) { SetWin32Error(err, L"OpenThread"); return false; }
    DWORD r = ::ResumeThread(h);
    CloseHandle(h);
    if (r == (DWORD)-1) { SetWin32Error(err, L"ResumeThread"); return false; }
    return true;
}

bool TerminateThread(ThreadId tid, DWORD exitCode, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_TERMINATE, FALSE, tid);
    if (!h) { SetWin32Error(err, L"OpenThread"); return false; }
    BOOL ok = ::TerminateThread(h, exitCode);
    CloseHandle(h);
    if (!ok) { SetWin32Error(err, L"TerminateThread"); return false; }
    return true;
}

bool SetThreadPriority(ThreadId tid, int priority, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
    if (!h) { SetWin32Error(err, L"OpenThread"); return false; }
    BOOL ok = ::SetThreadPriority(h, priority);
    CloseHandle(h);
    if (!ok) { SetWin32Error(err, L"SetThreadPriority"); return false; }
    return true;
}

bool SetThreadAffinity(ThreadId tid, DWORD_PTR affinityMask, Error* err) noexcept {
    HANDLE h = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) { SetWin32Error(err, L"OpenThread"); return false; }
    auto prev = ::SetThreadAffinityMask(h, affinityMask);
    CloseHandle(h);
    if (!prev) { SetWin32Error(err, L"SetThreadAffinityMask"); return false; }
    return true;
}


// ==========================================================
// Memory Operations
// ==========================================================

bool ReadProcessMemory(ProcessId pid, void* address, void* buffer, SIZE_T size,
    SIZE_T* bytesRead, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
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
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
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
    if (!outAddress) {
        SetWin32Error(err, L"AllocateProcessMemory", ERROR_INVALID_PARAMETER, L"outAddress null");
        return false;
    }
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    void* p = ::VirtualAllocEx(ph.Get(), nullptr, size, allocationType, protection);
    if (!p) {
        SetWin32Error(err, L"VirtualAllocEx");
        return false;
    }
    *outAddress = p;
    return true;
}

bool FreeProcessMemory(ProcessId pid, void* address, SIZE_T size, DWORD freeType, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    BOOL ok = ::VirtualFreeEx(ph.Get(), address, (freeType == MEM_RELEASE) ? 0 : size, freeType);
    if (!ok) {
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

bool EnumerateProcessHandles(ProcessId pid, std::vector<ProcessHandleInfo>& handles, Error* err) noexcept {
    handles.clear();

    // NtQuerySystemInformation için gerekli yapýlar ve fonksiyon tanýmlarý
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemHandleInformation = 16,
        SystemExtendedHandleInformation = 64
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    typedef NTSTATUS(NTAPI* NtQueryObject_t)(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength
        );

    
    constexpr OBJECT_INFORMATION_CLASS ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);

	//Get the functions from ntdll.dll
    static auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

    static auto NtQueryObject = reinterpret_cast<NtQueryObject_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));

    if (!NtQuerySystemInformation) {
        SetWin32Error(err, L"EnumerateProcessHandles", ERROR_CALL_NOT_IMPLEMENTED,
            L"NtQuerySystemInformation bulunamadý.");
        return false;
    }

	//set the initial buffer size
    ULONG bufferSize = 0x10000; // 64KB initial
    std::vector<BYTE> buffer;
    NTSTATUS status;

	//increase the buffer size until it is large enough dynamically
    do {
        buffer.resize(bufferSize);
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer.data(),
            bufferSize,
            &bufferSize
        );

        if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            bufferSize *= 2;
            if (bufferSize > 64 * 1024 * 1024) { // 64MB limit
                SetNtError(err, L"NtQuerySystemInformation", status,
                    L"Handle bilgisi için buffer çok büyük.");
                return false;
            }
        }
    } while (status == 0xC0000004);

    if (status != 0) {
        SetNtError(err, L"NtQuerySystemInformation", status);
        return false;
    }

    //Parse the handle information
    auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());

	//Filter the handles belonging to the target process
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        auto& entry = handleInfo->Handles[i];

        if (entry.UniqueProcessId != pid) continue;

        ProcessHandleInfo hi{};
        hi.handle = reinterpret_cast<HANDLE>(entry.HandleValue);
        hi.uniqueId = static_cast<HandleId>(entry.HandleValue);
        hi.type = entry.ObjectTypeIndex;
        hi.accessMask = entry.GrantedAccess;
        hi.attributes = entry.HandleAttributes;
        hi.isInheritable = (entry.HandleAttributes & 0x00000002) != 0; // OBJ_INHERIT
        hi.isProtected = (entry.HandleAttributes & 0x00000001) != 0;   // OBJ_PROTECT_CLOSE

		//Try to get the handle type name and handle name using NtQueryObject
        if (NtQueryObject) {
			//Duplicate the handle into the current process
            ProcessHandle ph;
            if (ph.Open(pid, PROCESS_DUP_HANDLE, nullptr)) {
                HANDLE dupHandle = nullptr;
                if (::DuplicateHandle(ph.Get(), hi.handle, GetCurrentProcess(),
                    &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    auto dupGuard = make_unique_handle(dupHandle);

					// Object type information
                    typedef struct _OBJECT_TYPE_INFORMATION {
                        UNICODE_STRING TypeName;
                        ULONG Reserved[22];
                    } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

                    BYTE typeBuffer[1024] = {};
                    ULONG returnLength = 0;

					// Add timeout Mechanism to avoid hangs
                    struct QueryContext {
                        NtQueryObject_t NtQueryObject;
                        HANDLE Handle;
                        PVOID Buffer;
                        ULONG BufferSize;
                        PULONG ReturnLength;
                        NTSTATUS Result;
                        std::atomic<bool> Completed;
                    };

                    QueryContext ctx{};
                    ctx.NtQueryObject = NtQueryObject;
                    ctx.Handle = dupHandle;
                    ctx.Buffer = typeBuffer;
                    ctx.BufferSize = sizeof(typeBuffer);
                    ctx.ReturnLength = &returnLength;
                    ctx.Result = 0;
                    ctx.Completed.store(false);

                    auto queryThread = std::thread([&ctx]() {
                        ctx.Result = ctx.NtQueryObject(
                            ctx.Handle,
                            ObjectTypeInformation,
                            ctx.Buffer,
                            ctx.BufferSize,
                            ctx.ReturnLength
                        );
                        ctx.Completed.store(true);
                        });

                    // 100ms timeout
                    auto start = std::chrono::steady_clock::now();
                    while (!ctx.Completed.load() &&
                        std::chrono::steady_clock::now() - start < std::chrono::milliseconds(100)) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }

                    if (ctx.Completed.load()) {
                        queryThread.join();
                        if (ctx.Result == 0) {
                            auto typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeBuffer);
                            if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
                                hi.typeName.assign(typeInfo->TypeName.Buffer,
                                    typeInfo->TypeName.Length / sizeof(WCHAR));
                            }
                        }
                    }
                    else {
						//terminate the thread if it is still running
                        queryThread.detach();
                        hi.typeName = L"Unknown (Timeout)";
                    }

					// Object name ( use with caution, can hang )
                    if (!hi.typeName.empty() &&
                        (hi.typeName == L"File" || hi.typeName == L"Key" ||
                            hi.typeName == L"Event" || hi.typeName == L"Mutant" ||
                            hi.typeName == L"Section")) {

                        typedef struct _OBJECT_NAME_INFORMATION {
                            UNICODE_STRING Name;
                        } OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

                        std::vector<BYTE> nameBuffer(4096);
                        returnLength = 0;

                        QueryContext nameCtx{};
                        nameCtx.NtQueryObject = NtQueryObject;
                        nameCtx.Handle = dupHandle;
                        nameCtx.Buffer = nameBuffer.data();
                        nameCtx.BufferSize = static_cast<ULONG>(nameBuffer.size());
                        nameCtx.ReturnLength = &returnLength;
                        nameCtx.Result = 0;
                        nameCtx.Completed.store(false);

                        auto nameThread = std::thread([&nameCtx, ObjectNameInformation]() {
                            nameCtx.Result = nameCtx.NtQueryObject(
                                nameCtx.Handle,
                                ObjectNameInformation, 
                                nameCtx.Buffer,
                                nameCtx.BufferSize,
                                nameCtx.ReturnLength
                            );
                            nameCtx.Completed.store(true);
                            });

                        start = std::chrono::steady_clock::now();
                        while (!nameCtx.Completed.load() &&
                            std::chrono::steady_clock::now() - start < std::chrono::milliseconds(100)) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        }

                        if (nameCtx.Completed.load()) {
                            nameThread.join();
                            if (nameCtx.Result == 0) {
                                auto nameInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(nameBuffer.data());
                                if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                                    hi.name.assign(nameInfo->Name.Buffer,
                                        nameInfo->Name.Length / sizeof(WCHAR));
                                }
                            }
                        }
                        else {
                            nameThread.detach();
                        }
                    }
                }
            }
        }

        handles.push_back(std::move(hi));
    }

    return true;
}

bool CloseProcessHandle(ProcessId pid, HANDLE handle, Error* err) noexcept {
	// Access the target process
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_DUP_HANDLE, err)) {
		//Try to enable SeDebugPrivilege and retry if access denied
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                auto token = make_unique_handle(hToken);

                LUID luid{};
                if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
                    TOKEN_PRIVILEGES tp{};
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);

					// Try Again
                    if (!ph.Open(pid, PROCESS_DUP_HANDLE, err)) {
                        return false;
                    }
                }
                else {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }
	// Duplicate the handle with DUPLICATE_CLOSE_SOURCE to close it in the target process
	//This is the safest way to close a handle in another process
    HANDLE dupHandle = nullptr;
    if (!::DuplicateHandle(
        ph.Get(),                           // Source process ( target process ) 
		handle,                             // the handle to close
		GetCurrentProcess(),                // Target process ( current process )
        &dupHandle,                         // Exit handle ( will be NULL)
		0,                                  // Wanted access (0 = same access)
		FALSE,                              // can get inherited
		DUPLICATE_CLOSE_SOURCE)) {          // Close the source handle

        SetWin32Error(err, L"DuplicateHandle(DUPLICATE_CLOSE_SOURCE)");
        return false;
    }

	//Duphandle should be null if successful
	//if not NULL something unexpected happened
    if (dupHandle != nullptr) {
        ::CloseHandle(dupHandle);
        SetWin32Error(err, L"CloseProcessHandle", ERROR_INVALID_HANDLE,
            L"Handle is closed but unexpectedly created.");
		return true; //but still we can consider it successful because handle is closed
    }

    return true;
}

bool DuplicateProcessHandle(ProcessId sourcePid, HANDLE sourceHandle,
    ProcessId targetPid, HANDLE* targetHandle,
    DWORD desiredAccess, bool inheritHandle,
    DWORD options, Error* err) noexcept {
    if (!targetHandle) {
        SetWin32Error(err, L"DuplicateProcessHandle", ERROR_INVALID_PARAMETER, L"targetHandle null");
        return false;
    }

    ProcessHandle src, dst;
    if (!src.Open(sourcePid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    if (!dst.Open(targetPid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

    HANDLE dup = nullptr;
    if (!::DuplicateHandle(src.Get(), sourceHandle, dst.Get(), &dup, desiredAccess, inheritHandle, options)) {
        SetWin32Error(err, L"DuplicateHandle");
        return false;
    }
    *targetHandle = dup;
    return true;
}

// ==========================================================
// Process Security & Privileges
// ==========================================================

bool EnableProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, bool enable, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(ph.Get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        SetWin32Error(err, L"OpenProcessToken");
        return false;
    }
    auto token = make_unique_handle(hToken);

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, std::wstring(privilegeName).c_str(), &luid)) {
        SetWin32Error(err, L"LookupPrivilegeValueW");
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        SetWin32Error(err, L"AdjustTokenPrivileges");
        return false;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        SetWin32Error(err, L"AdjustTokenPrivileges", ERROR_NOT_ALL_ASSIGNED, L"Ýstenen ayrýcalýk tokende bulunmuyor.");
        return false;
    }
    return true;
}

bool HasProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, Error* err) noexcept {
    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) return false;
    auto target = ToLower(std::wstring(privilegeName));
    for (const auto& p : sec.enabledPrivileges) {
        if (ToLower(p) == target) return true;
    }
    return false;
}

bool GetProcessPrivileges(ProcessId pid, std::vector<std::wstring>& privileges, Error* err) noexcept {
    privileges.clear();
    ProcessSecurityInfo sec{};
    if (!GetProcessSecurityInfo(pid, sec, err)) return false;
    privileges = sec.enabledPrivileges;
    return true;
}

bool ImpersonateProcess(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;

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

bool TerminateProcess(ProcessId pid, DWORD exitCode, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_TERMINATE, err)) return false;
    if (!::TerminateProcess(ph.Get(), exitCode)) {
        SetWin32Error(err, L"TerminateProcess");
        return false;
    }
    return true;
}

bool TerminateProcess(HANDLE hProcess, DWORD exitCode, Error* err) noexcept {
    if (!::TerminateProcess(hProcess, exitCode)) {
        SetWin32Error(err, L"TerminateProcess");
        return false;
    }
    return true;
}

bool TerminateProcessTree(ProcessId rootPid, DWORD exitCode, Error* err) noexcept {
    std::unordered_multimap<ProcessId, ProcessId> tree;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetWin32Error(err, L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)");
        return false;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            tree.emplace(pe.th32ParentProcessID, pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    std::vector<ProcessId> stack{ rootPid };
    std::vector<ProcessId> order;
    std::unordered_set<ProcessId> visited;
    while (!stack.empty()) {
        auto pid = stack.back(); stack.pop_back();
        if (visited.insert(pid).second) {
            order.push_back(pid);
            auto range = tree.equal_range(pid);
            for (auto it = range.first; it != range.second; ++it) {
                stack.push_back(it->second);
            }
        }
    }
    std::reverse(order.begin(), order.end());
    bool okAll = true;
    for (auto pid : order) {
        if (pid == 0 || pid == ::GetCurrentProcessId()) continue;
        if (!IsProcessRunning(pid)) continue;
        if (!TerminateProcess(pid, exitCode, nullptr)) okAll = false;
    }
    if (!okAll) SetWin32Error(err, L"TerminateProcessTree", ERROR_GEN_FAILURE, L"Bazý süreçler sonlandýrýlamadý.");
    return okAll;
}

bool WaitForProcess(ProcessId pid, DWORD timeoutMs, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, err)) return false;
    DWORD w = WaitForSingleObject(ph.Get(), timeoutMs);
    if (w == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject");
        return false;
    }
    return w == WAIT_OBJECT_0 || w == WAIT_TIMEOUT;
}

bool WaitForProcess(HANDLE hProcess, DWORD timeoutMs, Error* err) noexcept {
    DWORD w = WaitForSingleObject(hProcess, timeoutMs);
    if (w == WAIT_FAILED) {
        SetWin32Error(err, L"WaitForSingleObject");
        return false;
    }
    return w == WAIT_OBJECT_0 || w == WAIT_TIMEOUT;
}

std::optional<DWORD> GetProcessExitCode(ProcessId pid, Error* err) noexcept {
    ProcessHandle ph;
    if (!ph.Open(pid, PROCESS_QUERY_LIMITED_INFORMATION, err)) return std::nullopt;
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
        SetWin32Error(err, L"ProcessMonitor::Start", ERROR_OUTOFMEMORY, L"Ýzleme thread'i baþlatýlamadý.");
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

bool KillProcessByName(std::wstring_view processName, Error* err) noexcept {
    auto pid = GetProcessIdByName(processName, err);
    if (pid == 0) {
        SetWin32Error(err, L"KillProcessByName", ERROR_NOT_FOUND, L"Ýstenilen adla süreç bulunamadý.");
        return false;
    }
    return TerminateProcess(pid, 0, err);
}

bool KillAllProcessesByName(std::wstring_view processName, Error* err) noexcept {
    bool okAll = true;
    auto pids = GetProcessIdsByName(processName, nullptr);
    if (pids.empty()) {
        SetWin32Error(err, L"KillAllProcessesByName", ERROR_NOT_FOUND, L"Eþleþen süreç bulunamadý.");
        return false;
    }
    for (auto pid : pids) {
        if (!TerminateProcess(pid, 0, nullptr)) okAll = false;
    }
    if (!okAll) SetWin32Error(err, L"KillAllProcessesByName", ERROR_GEN_FAILURE, L"Bazý süreçler sonlandýrýlamadý.");
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
// Advanced Features - ETW Process Tracing
// ==========================================================

namespace {
	// Global state for ETW Session
    struct ETWProcessTracingState {
        TRACEHANDLE sessionHandle = 0;
        TRACEHANDLE consumerHandle = 0;
        std::atomic<bool> isRunning{ false };
        std::thread consumerThread;
        std::mutex mutex;

        // Callback functions
        std::function<void(const ProcessEvent&)> onProcessEvent;
    };

    static ETWProcessTracingState g_etwState;

    // ETW Event callback
    VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
        if (!pEventRecord) return;
        if (!g_etwState.isRunning.load()) return;

        // Process/Thread creation/termination events
        // Microsoft-Windows-Kernel-Process provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
        static const GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

        if (IsEqualGUID(pEventRecord->EventHeader.ProviderId, ProcessProviderGuid)) {
            ProcessEvent evt{};
            evt.timestamp = std::chrono::system_clock::now();
            evt.pid = pEventRecord->EventHeader.ProcessId;
            evt.tid = pEventRecord->EventHeader.ThreadId;

            // Event ID check
            switch (pEventRecord->EventHeader.EventDescriptor.Opcode) {
            case 1: // Process Start
                evt.type = ProcessEventType::Created;
                evt.description = L"Process created via ETW";
                break;
            case 2: // Process End
                evt.type = ProcessEventType::Terminated;
                evt.description = L"Process terminated via ETW";
                break;
            case 3: // Thread Start
                evt.type = ProcessEventType::ThreadCreated;
                evt.description = L"Thread created via ETW";
                break;
            case 4: // Thread End
                evt.type = ProcessEventType::ThreadTerminated;
                evt.description = L"Thread terminated via ETW";
                break;
            case 5: // Image Load (DLL/EXE)
                evt.type = ProcessEventType::ModuleLoaded;
                evt.description = L"Module loaded via ETW";
                break;
            default:
				return; // The event that we don't care about
            }

			// parse the event properties
            if (pEventRecord->UserDataLength > 0 && pEventRecord->UserData) {
                // Process ID
                if (pEventRecord->UserDataLength >= sizeof(DWORD)) {
                    DWORD targetPid = *reinterpret_cast<DWORD*>(pEventRecord->UserData);
                    evt.details[L"TargetPID"] = std::to_wstring(targetPid);
                }

                // Image name (if exists)
                if (pEventRecord->UserDataLength > sizeof(DWORD) + sizeof(DWORD)) {
                    wchar_t* imageName = reinterpret_cast<wchar_t*>(
                        static_cast<BYTE*>(pEventRecord->UserData) + sizeof(DWORD) * 2);

                    size_t maxLen = (pEventRecord->UserDataLength - sizeof(DWORD) * 2) / sizeof(wchar_t);
                    if (maxLen > 0) {
                        std::wstring name(imageName, wcsnlen(imageName, maxLen));
                        evt.details[L"ImageName"] = name;
                    }
                }
            }

			//invoke the user callback
            std::lock_guard<std::mutex> lock(g_etwState.mutex);
            if (g_etwState.onProcessEvent) {
                g_etwState.onProcessEvent(evt);
            }
        }
    }

    // ETW buffer callback
    ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW pLogFile) {
        return TRUE; // Continue processing
    }

    // ETW consumer thread function
    void ETWConsumerThread() {
        EVENT_TRACE_LOGFILEW traceLogFile{};
        ZeroMemory(&traceLogFile, sizeof(traceLogFile));

        traceLogFile.LoggerName = const_cast<LPWSTR>(L"ShadowStrikeProcessTrace");
        traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLogFile.EventRecordCallback = EventRecordCallback;
        traceLogFile.BufferCallback = BufferCallback;
        traceLogFile.Context = nullptr;

        //Open the Trace Session
        g_etwState.consumerHandle = OpenTraceW(&traceLogFile);
        if (g_etwState.consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
            SS_LOG_ERROR(L"ProcessUtils", L"OpenTrace failed: %d", GetLastError());
            g_etwState.isRunning.store(false);
            return;
        }

        // Event processing loop
        ULONG status = ProcessTrace(&g_etwState.consumerHandle, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            SS_LOG_ERROR(L"ProcessUtils", L"ProcessTrace failed: %d", status);
        }

        // Cleanup
        if (g_etwState.consumerHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(g_etwState.consumerHandle);
            g_etwState.consumerHandle = 0;
        }
    }
}

bool EnableETWProcessTracing(Error* err) noexcept {
    std::lock_guard<std::mutex> lock(g_etwState.mutex);

	//If Already Working, return
    if (g_etwState.isRunning.load()) {
        return true;
    }

	//get buffer ready for ETW session properties
    const size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<BYTE> buffer(bufferSize);
    auto* pSessionProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());

    ZeroMemory(pSessionProperties, bufferSize);
    pSessionProperties->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    pSessionProperties->Wnode.Guid = GUID_NULL;

    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->MaximumFileSize = 0; // No file output
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->BufferSize = 64; // KB
    pSessionProperties->MinimumBuffers = 20;
    pSessionProperties->MaximumBuffers = 200;
    pSessionProperties->FlushTimer = 1; // Second

	// Set the session name
    const wchar_t* sessionName = L"ShadowStrikeProcessTrace";
    wcscpy_s(reinterpret_cast<wchar_t*>(buffer.data() + pSessionProperties->LoggerNameOffset),
        512, sessionName);

	//Stop the existing session if any
    ULONG status = ControlTraceW(0, sessionName, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
	// ERROR_WMI_INSTANCE_NOT_FOUND is a expected error if the session does not exist

    // Open a new session
    status = StartTraceW(&g_etwState.sessionHandle, sessionName, pSessionProperties);
    if (status != ERROR_SUCCESS) {
        SetWin32Error(err, L"StartTraceW", status, L"ETW trace session baþlatýlamadý.");
        return false;
    }

    //Enable the provider
    GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

    // Enable parameters
    ENABLE_TRACE_PARAMETERS enableParams{};
    enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableParams.EnableProperty = EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;
    enableParams.ControlFlags = 0;
    enableParams.SourceId = GUID_NULL;
    enableParams.EnableFilterDesc = nullptr;
    enableParams.FilterDescCount = 0;

    status = EnableTraceEx2(
        g_etwState.sessionHandle,
        &ProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, // Log level
        0xFFFFFFFFFFFFFFFF,      // Any keyword
        0,                        // Match any keyword
        0,                        // Timeout (infinite)
        &enableParams
    );

    if (status != ERROR_SUCCESS) {
        //Clear the session
        ControlTraceW(g_etwState.sessionHandle, nullptr, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        g_etwState.sessionHandle = 0;

        SetWin32Error(err, L"EnableTraceEx2", status, L"ETW provider enable edilemedi.");
        return false;
    }

    // Create the consumer thread
    g_etwState.isRunning.store(true);
    try {
        g_etwState.consumerThread = std::thread(ETWConsumerThread);
    }
    catch (const std::exception&) {
		// Thread failed to start make sure to clean up
        g_etwState.isRunning.store(false);

        GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };
        EnableTraceEx2(g_etwState.sessionHandle, &ProcessProviderGuid,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nullptr);

        ControlTraceW(g_etwState.sessionHandle, nullptr, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        g_etwState.sessionHandle = 0;

        SetWin32Error(err, L"EnableETWProcessTracing", ERROR_OUTOFMEMORY,
            L"ETW consumer thread is not initialized");
        return false;
    }

    SS_LOG_INFO(L"ProcessUtils", L"ETW process tracing enabled successfully.");
    return true;
}

bool DisableETWProcessTracing(Error* err) noexcept {
    std::lock_guard<std::mutex> lock(g_etwState.mutex);

    // if already stopped
    if (!g_etwState.isRunning.load()) {
        return true;
    }

    //Stop watching
    g_etwState.isRunning.store(false);

	//Close the consumer tracing handle
    if (g_etwState.consumerHandle != INVALID_PROCESSTRACE_HANDLE && g_etwState.consumerHandle != 0) {
        CloseTrace(g_etwState.consumerHandle);
        g_etwState.consumerHandle = 0;
    }

	//wait for consumer thread to finish
    if (g_etwState.consumerThread.joinable()) {
        g_etwState.consumerThread.join();
    }

    //disable the provider
    if (g_etwState.sessionHandle != 0) {
        GUID ProcessProviderGuid = { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

        ULONG status = EnableTraceEx2(
            g_etwState.sessionHandle,
            &ProcessProviderGuid,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 0, nullptr
        );

        if (status != ERROR_SUCCESS) {
            SS_LOG_WARN(L"ProcessUtils", L"EnableTraceEx2 (disable) failed: %d", status);
        }
    }

    //Stop the session
    if (g_etwState.sessionHandle != 0) {
        const size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        std::vector<BYTE> buffer(bufferSize);
        auto* pSessionProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());

        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = ControlTraceW(
            g_etwState.sessionHandle,
            L"ShadowStrikeProcessTrace",
            pSessionProperties,
            EVENT_TRACE_CONTROL_STOP
        );

        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            SetWin32Error(err, L"ControlTraceW(STOP)", status, L"ETW session durdurulamadý.");
			// Even if stopping the session fails, we still clear the handle
        }

        g_etwState.sessionHandle = 0;
    }

    //Clear the callback
    g_etwState.onProcessEvent = nullptr;

    SS_LOG_INFO(L"ProcessUtils", L"ETW process tracing disabled successfully.");
    return true;
}

//helper function for setting ETW process event callback
bool SetETWProcessEventCallback(std::function<void(const ProcessEvent&)> callback, Error* err) noexcept {
    std::lock_guard<std::mutex> lock(g_etwState.mutex);

    if (!g_etwState.isRunning.load()) {
        SetWin32Error(err, L"SetETWProcessEventCallback", ERROR_INVALID_STATE,
            L"ETW tracing is not active.");
        return false;
    }

    g_etwState.onProcessEvent = std::move(callback);
    return true;
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

bool GetProcessInfoWMI(ProcessId /*pid*/, ProcessInfo& /*info*/, Error* err) noexcept {
    SetWin32Error(err, L"GetProcessInfoWMI", ERROR_NOT_SUPPORTED, L"WMI entegrasyonu bu sürümde etkin deðil.");
    return false;
}

bool EnumerateProcessesWMI(std::vector<ProcessBasicInfo>& /*processes*/, Error* err) noexcept {
    SetWin32Error(err, L"EnumerateProcessesWMI", ERROR_NOT_SUPPORTED, L"WMI entegrasyonu bu sürümde etkin deðil.");
    return false;
}

        } // namespace ProcessUtils
    } // namespace Utils
} // namespace ShadowStrike
