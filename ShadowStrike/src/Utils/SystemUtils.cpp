#include "SystemUtils.hpp"

#include <vector>
#include <string>
#include <cwchar>
#include <tlhelp32.h>
#include <intrin.h>
#include <VersionHelpers.h>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

namespace ShadowStrike {
	namespace Utils {
		namespace SystemUtils {

			//Helpers

            static std::wstring ToW(std::wstring_view sv) {
                return std::wstring(sv.data(), sv.size());
            }

            uint64_t NowFileTime100nsUTC() {
#ifdef _WIN32
                FILETIME ft{};
                
                if (HMODULE h = GetModuleHandleW(L"kernel32.dll")) {
                    using Fn = VOID(WINAPI*)(LPFILETIME);
                    if (auto p = reinterpret_cast<Fn>(GetProcAddress(h, "GetSystemTimePreciseAsFileTime"))) {
                        p(&ft);
                    }
                    else {
                        GetSystemTimeAsFileTime(&ft);
                    }
                }
                else {
                    GetSystemTimeAsFileTime(&ft);
                }
                ULARGE_INTEGER uli{};
                uli.LowPart = ft.dwLowDateTime;
                uli.HighPart = ft.dwHighDateTime;
                return uli.QuadPart;
#else
                return 0;
#endif
            }

            uint64_t UptimeMilliseconds() {
#ifdef _WIN32
                return static_cast<uint64_t>(::GetTickCount64());
#else
                return 0;
#endif
            }

            bool GetBasicSystemInfo(SYSTEM_INFO& out) {
#ifdef _WIN32
                if (IsWindowsXPOrGreater()) {
                    ::GetNativeSystemInfo(&out);
                }
                else {
                    ::GetSystemInfo(&out);
                }
                return true;
#else
                (void)out; return false;
#endif
            }

            static bool IsWow64Process2Safe(bool& isWow64, USHORT& processMachine) {
#ifdef _WIN32
                isWow64 = false;
                processMachine = 0;
                typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
                if (HMODULE h = GetModuleHandleW(L"kernel32.dll")) {
                    if (auto p = reinterpret_cast<IsWow64Process2_t>(GetProcAddress(h, "IsWow64Process2"))) {
                        USHORT nativeMachine = 0;
                        if (p(GetCurrentProcess(), &processMachine, &nativeMachine)) {
                            isWow64 = (processMachine != 0);
                            return true;
                        }
                    }
                }
                // Fallback
                BOOL wow = FALSE;
                if (::IsWow64Process(GetCurrentProcess(), &wow)) {
                    isWow64 = (wow != FALSE);
                    return true;
                }
#endif
                return false;
            }

            static std::wstring ArchToString(WORD arch) {
                switch (arch) {
                case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
                case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
                case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
                case PROCESSOR_ARCHITECTURE_ARM:   return L"ARM";
                default: return L"Unknown";
                }
            }


            bool QueryOSVersion(OSVersion& out) {
#ifdef _WIN32
				// Real version with RtlGetVersion
                typedef LONG(WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
                RTL_OSVERSIONINFOW vi{};
                vi.dwOSVersionInfoSize = sizeof(vi);

                bool ok = false;
                if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll")) {
                    if (auto p = reinterpret_cast<RtlGetVersion_t>(GetProcAddress(ntdll, "RtlGetVersion"))) {
                        ok = (p(&vi) == 0);
                    }
                }
                if (!ok) {
                    OSVERSIONINFOW ov{};
                    ov.dwOSVersionInfoSize = sizeof(ov);
#pragma warning(push)
#pragma warning(disable:4996)
                    if (!GetVersionExW(&ov)) {
                        SS_LOG_LAST_ERROR(L"SystemUtils", L"GetVersionExW failed");
                        return false;
                    }
#pragma warning(pop)
                    vi.dwMajorVersion = ov.dwMajorVersion;
                    vi.dwMinorVersion = ov.dwMinorVersion;
                    vi.dwBuildNumber = ov.dwBuildNumber;
                    vi.dwPlatformId = ov.dwPlatformId;
                    ok = true;
                }

                out.major = vi.dwMajorVersion;
                out.minor = vi.dwMinorVersion;
                out.build = vi.dwBuildNumber;
                out.platformId = vi.dwPlatformId;

				// 64-bit OS and WOW64 situation
                bool isWow = false;
                USHORT procMachine = 0;
                IsWow64Process2Safe(isWow, procMachine);
                out.isWow64Process = isWow;

                SYSTEM_INFO si{};
                GetBasicSystemInfo(si);
                out.is64BitOS = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

                // Edition/DisplayVersion/ProductName
                HKEY hKey = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                    wchar_t buf[256]; DWORD sz = sizeof(buf);
                    if (RegQueryValueExW(hKey, L"ProductName", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                        out.productName.assign(buf);
                    }
                    sz = sizeof(buf);
                    if (RegQueryValueExW(hKey, L"ReleaseId", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                        out.releaseId.assign(buf);
                    }
                    sz = sizeof(buf);
                    if (RegQueryValueExW(hKey, L"DisplayVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                        out.displayVersion.assign(buf);
                    }
                    sz = sizeof(buf);
                    if (RegQueryValueExW(hKey, L"EditionID", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                        out.editionId.assign(buf);
                    }
                    sz = sizeof(buf);
                    if (RegQueryValueExW(hKey, L"CurrentBuild", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
                        out.currentBuild.assign(buf);
                    }
                    RegCloseKey(hKey);
                }

                //Is server?
                out.isServer = IsWindowsServer();

                return true;
#else
                (void)out; return false;
#endif
            }



            bool QueryCpuInfo(CpuInfo& out) {
#ifdef _WIN32
                SYSTEM_INFO si{};
                GetBasicSystemInfo(si);

                out.architecture = ArchToString(si.wProcessorArchitecture);

                // Topology
                DWORD len = 0;
                if (!GetLogicalProcessorInformationEx(RelationAll, nullptr, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<uint8_t> buf(len);
                    if (GetLogicalProcessorInformationEx(RelationAll, reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data()), &len)) {
                        BYTE* p = buf.data();
                        BYTE* end = p + len;
                        while (p < end) {
                            auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(p);
                            switch (info->Relationship) {
                            case RelationProcessorCore:
                                out.coreCount++;
                                // ? FIX #1-2: Remove double counting - only use popcnt
                                for (WORD g = 0; g < info->Processor.GroupCount; ++g) {
                                    KAFFINITY mask = info->Processor.GroupMask[g].Mask;
#if defined(_WIN64)
                                    out.logicalProcessorCount += static_cast<DWORD>(__popcnt64(mask));
#else
                                    // ? FIX #3: Handle full 64-bit mask on x86
                                    DWORD low = static_cast<DWORD>(mask & 0xFFFFFFFFULL);
                                    DWORD high = static_cast<DWORD>((mask >> 32) & 0xFFFFFFFFULL);
                                    out.logicalProcessorCount += __popcnt(low) + __popcnt(high);
#endif
                                }
                                break;
                            case RelationProcessorPackage:
                                out.packageCount++;
                                break;
                            case RelationNumaNode:
                                out.numaNodeCount++;
                                break;
                            default:
                                break;
                            }
                            p += info->Size;
                        }
                     
                        if (out.logicalProcessorCount == 0)
                            out.logicalProcessorCount = si.dwNumberOfProcessors;
                    }
                    else {
                        SS_LOG_LAST_ERROR(L"SystemUtils", L"GetLogicalProcessorInformationEx failed");
                        out.logicalProcessorCount = si.dwNumberOfProcessors;
                    }
                }
                else {
                    out.logicalProcessorCount = si.dwNumberOfProcessors;
                }

#if defined(_M_IX86) || defined(_M_X64)
                int cpuInfo[4] = { 0 };
                char brand[49] = {};
                __cpuid(cpuInfo, 0x80000000);
                unsigned int nExIds = cpuInfo[0];
                if (nExIds >= 0x80000004) {
                    __cpuid(reinterpret_cast<int*>(cpuInfo), 0x80000002);
                    memcpy(brand + 0, cpuInfo, sizeof(cpuInfo));
                    __cpuid(reinterpret_cast<int*>(cpuInfo), 0x80000003);
                    memcpy(brand + 16, cpuInfo, sizeof(cpuInfo));
                    __cpuid(reinterpret_cast<int*>(cpuInfo), 0x80000004);
                    memcpy(brand + 32, cpuInfo, sizeof(cpuInfo));
                    // Trim
                    size_t blen = strnlen(brand, 48);
                    std::wstring wbrand(blen, L'\0');
                    MultiByteToWideChar(CP_ACP, 0, brand, static_cast<int>(blen), wbrand.data(), static_cast<int>(wbrand.size()));
                    out.brand = wbrand;
                }

                int f1[4] = { 0 }, f7[4] = { 0 };
                __cpuid(f1, 1);
                __cpuidex(f7, 7, 0);
                out.hasSSE2 = (f1[3] & (1 << 26)) != 0;
                out.hasSSE3 = (f1[2] & (1 << 0)) != 0;
                out.hasSSSE3 = (f1[2] & (1 << 9)) != 0;
                out.hasSSE41 = (f1[2] & (1 << 19)) != 0;
                out.hasSSE42 = (f1[2] & (1 << 20)) != 0;
                out.hasAVX = (f1[2] & (1 << 28)) != 0;
                out.hasAVX2 = (f7[1] & (1 << 5)) != 0;
#else
                out.brand.clear();
#endif
                return true;
#else
                (void)out; return false;
#endif
            }

            bool QueryMemoryInfo(MemoryInfo& out) {
#ifdef _WIN32
                MEMORYSTATUSEX ms{};
                ms.dwLength = sizeof(ms);
                if (!GlobalMemoryStatusEx(&ms)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GlobalMemoryStatusEx failed");
                    return false;
                }
                out.totalPhys = ms.ullTotalPhys;
                out.availPhys = ms.ullAvailPhys;
                out.totalPageFile = ms.ullTotalPageFile;
                out.availPageFile = ms.ullAvailPageFile;
                out.totalVirtual = ms.ullTotalVirtual;
                out.availVirtual = ms.ullAvailVirtual;

                ULONGLONG kb = 0;
                if (GetPhysicallyInstalledSystemMemory(&kb)) {
                    out.physInstalledKB = kb;
                }
                return true;
#else
                (void)out; return false;
#endif
            }

            static std::wstring IntegrityRidToName(DWORD rid) {
                switch (rid) {
                case SECURITY_MANDATORY_UNTRUSTED_RID:        return L"Untrusted";
                case SECURITY_MANDATORY_LOW_RID:              return L"Low";
                case SECURITY_MANDATORY_MEDIUM_RID:           return L"Medium";
                case SECURITY_MANDATORY_MEDIUM_PLUS_RID:      return L"MediumPlus";
                case SECURITY_MANDATORY_HIGH_RID:             return L"High";
                case SECURITY_MANDATORY_SYSTEM_RID:           return L"System";
                case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:return L"Protected";
                default: return L"Unknown";
                }
            }

            bool GetSecurityInfo(SecurityInfo& out) {
#ifdef _WIN32
                HANDLE hToken = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"OpenProcessToken failed");
                    return false;
                }

                // Elevation
                TOKEN_ELEVATION elev{};
                DWORD retLen = 0;
                if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &retLen)) {
                    out.isElevated = elev.TokenIsElevated != 0;
                }
                else {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GetTokenInformation(TokenElevation) failed");
                }

                // Integrity
                DWORD len = 0;
                GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &len);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > 0) {
                    std::vector<BYTE> buf(len);
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), len, &retLen)) {
                        auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
                        DWORD rid = *GetSidSubAuthority(til->Label.Sid, static_cast<DWORD>(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
                        out.integrityRid = rid;
                        out.integrityName = IntegrityRidToName(rid);
                    }
                    else {
                        SS_LOG_LAST_ERROR(L"SystemUtils", L"GetTokenInformation(TokenIntegrityLevel) failed");
                    }
                }
                CloseHandle(hToken);
                return true;
#else
                (void)out; return false;
#endif
            }


            bool EnablePrivilege(const wchar_t* privName, bool enable) {
#ifdef _WIN32
                if (!privName || !*privName) return false;
                HANDLE hToken = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"OpenProcessToken failed");
                    return false;
                }
                LUID luid{};
                if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"LookupPrivilegeValueW failed: %s", privName);
                    CloseHandle(hToken);
                    return false;
                }
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

                if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"AdjustTokenPrivileges failed: %s", privName);
                    CloseHandle(hToken);
                    return false;
                }
                // ? FIX #6: Check GetLastError BEFORE CloseHandle
                DWORD lastError = GetLastError();
                CloseHandle(hToken);
                return lastError == ERROR_SUCCESS;
#else
                (void)privName; (void)enable; return false;
#endif
            }

            bool IsDebuggerPresentSafe() {
#ifdef _WIN32
                return ::IsDebuggerPresent() != FALSE;
#else
                return false;
#endif
            }

            DWORD CurrentProcessId() {
#ifdef _WIN32
                return ::GetCurrentProcessId();
#else
                return 0;
#endif
            }

            std::optional<DWORD> GetParentProcessId(DWORD pid) {
#ifdef _WIN32
                if (pid == 0) pid = GetCurrentProcessId();
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap == INVALID_HANDLE_VALUE) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"CreateToolhelp32Snapshot failed");
                    return std::nullopt;
                }
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (!Process32FirstW(hSnap, &pe)) {
                    CloseHandle(hSnap);
                    return std::nullopt;
                }
                do {
                    if (pe.th32ProcessID == pid) {
                        DWORD ppid = pe.th32ParentProcessID;
                        CloseHandle(hSnap);
                        return ppid ? std::optional<DWORD>(ppid) : std::nullopt;
                    }
                } while (Process32NextW(hSnap, &pe));
                CloseHandle(hSnap);
                return std::nullopt;
#else
                (void)pid; return std::nullopt;
#endif
            }

            std::wstring GetExecutablePath() {
#ifdef _WIN32
                std::wstring path(512, L'\0');
                DWORD n = 0;
                for (;;) {
                    n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
                    if (n == 0) {
                        SS_LOG_LAST_ERROR(L"SystemUtils", L"GetModuleFileNameW failed");
                        return L"";
                    }
                    if (n < path.size() - 1) {
                        path.resize(n);
                        break;
                    }
                    path.resize(path.size() * 2);
                }
                return path;
#else
                return L"";
#endif
            }

            std::wstring GetModulePath(HMODULE mod) {
#ifdef _WIN32
                std::wstring path(512, L'\0');
                DWORD n = 0;
                for (;;) {
                    n = GetModuleFileNameW(mod, path.data(), static_cast<DWORD>(path.size()));
                    if (n == 0) {
                        SS_LOG_LAST_ERROR(L"SystemUtils", L"GetModuleFileNameW(mod) failed");
                        return L"";
                    }
                    if (n < path.size() - 1) {
                        path.resize(n);
                        break;
                    }
                    path.resize(path.size() * 2);
                }
                return path;
#else
                (void)mod; return L"";
#endif
            }



            std::wstring GetSystemDirectoryPath() {
#ifdef _WIN32
                wchar_t buf[MAX_PATH] = {};
                UINT n = GetSystemDirectoryW(buf, MAX_PATH);
                if (n == 0 || n >= MAX_PATH) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GetSystemDirectoryW failed");
                    return L"";
                }
                return std::wstring(buf, buf + n);
#else
                return L"";
#endif
            }

            std::wstring GetWindowsDirectoryPath() {
#ifdef _WIN32
                wchar_t buf[MAX_PATH] = {};
                UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
                if (n == 0 || n >= MAX_PATH) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GetWindowsDirectoryW failed");
                    return L"";
                }
                return std::wstring(buf, buf + n);
#else
                return L"";
#endif
            }

            std::wstring ExpandEnv(std::wstring_view s) {
#ifdef _WIN32
                std::wstring in = ToW(s);
                DWORD need = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
                // ? FIX #4: Handle need <= 1 case (empty string)
                if (need <= 1) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"ExpandEnvironmentStringsW size query failed");
                    return ToW(s);
                }
                std::wstring out(need, L'\0');
                DWORD n = ExpandEnvironmentStringsW(in.c_str(), out.data(), need);
                if (n == 0) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"ExpandEnvironmentStringsW failed");
                    return ToW(s);
                }
                if (!out.empty() && out.back() == L'\0') out.pop_back();
                return out;
#else
                return ToW(s);
#endif
            }

            std::wstring GetComputerNameDnsFullyQualified() {
#ifdef _WIN32
                DWORD sz = 0;
                GetComputerNameExW(ComputerNameDnsFullyQualified, nullptr, &sz);
                // ? FIX #5: Handle sz <= 1 case to prevent crash
                if (sz <= 1) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW size query failed");
                    return L"";
                }
                std::wstring name(sz, L'\0');
                if (GetComputerNameExW(ComputerNameDnsFullyQualified, name.data(), &sz)) {
                    if (!name.empty() && name.back() == L'\0') name.pop_back();
                    return name;
                }
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(FQDN) failed");
                return L"";
#else
                return L"";
#endif
            }

            std::wstring GetComputerNameDnsHostname() {
#ifdef _WIN32
                DWORD sz = 0;
                GetComputerNameExW(ComputerNameDnsHostname, nullptr, &sz);
                // ? FIX #5: Handle sz <= 1 case to prevent crash
                if (sz <= 1) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(Host) size query failed");
                    return L"";
                }
                std::wstring name(sz, L'\0');
                if (GetComputerNameExW(ComputerNameDnsHostname, name.data(), &sz)) {
                    if (!name.empty() && name.back() == L'\0') name.pop_back();
                    return name;
                }
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(Host) failed");
                return L"";
#else
                return L"";
#endif
            }

            bool SetProcessDpiAwarePerMonitorV2() {
#ifdef _WIN32
                HMODULE hUser = LoadLibraryW(L"user32.dll");
                if (!hUser) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"LoadLibrary(user32) failed");
                    return false;
                }
                using FnCtx = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
                using FnAware = BOOL(WINAPI*)();
                auto pSetCtx = reinterpret_cast<FnCtx>(GetProcAddress(hUser, "SetProcessDpiAwarenessContext"));
                if (pSetCtx) {
                    // PMv2 -> fallback PM -> system -> unaware
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif
                    if (pSetCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
                        FreeLibrary(hUser);
                        return true;
                    }
                    // Fallback per-monitor v1
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE ((DPI_AWARENESS_CONTEXT)-3)
#endif
                    if (pSetCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE)) {
                        FreeLibrary(hUser);
                        return true;
                    }
                }
                // Older fallback
                auto pSetAware = reinterpret_cast<FnAware>(GetProcAddress(hUser, "SetProcessDPIAware"));
                if (pSetAware && pSetAware()) {
                    FreeLibrary(hUser);
                    return true;
                }
                FreeLibrary(hUser);
                SS_LOG_WARN(L"SystemUtils", L"DPI awareness could not be enabled");
                return false;
#else
                return false;
#endif
            }



            bool SetProcessPriorityHigh() {
#ifdef _WIN32
                if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"SetPriorityClass(HIGH) failed");
                    return false;
                }
                return true;
#else
                return false;
#endif
            }

            bool SetCurrentThreadPriority(int priority) {
#ifdef _WIN32
                if (!SetThreadPriority(GetCurrentThread(), priority)) {
                    SS_LOG_LAST_ERROR(L"SystemUtils", L"SetThreadPriority failed");
                    return false;
                }
                return true;
#else
                (void)priority; return false;
#endif
            }

            bool QueryBootTime(FILETIME& bootTimeUtc) {
#ifdef _WIN32
                // System Time (UTC)
                FILETIME nowFt{};
                if (HMODULE h = GetModuleHandleW(L"kernel32.dll")) {
                    using Fn = VOID(WINAPI*)(LPFILETIME);
                    if (auto p = reinterpret_cast<Fn>(GetProcAddress(h, "GetSystemTimePreciseAsFileTime"))) {
                        p(&nowFt);
                    }
                    else {
                        GetSystemTimeAsFileTime(&nowFt);
                    }
                }
                else {
                    GetSystemTimeAsFileTime(&nowFt);
                }
                ULARGE_INTEGER uliNow{};
                uliNow.LowPart = nowFt.dwLowDateTime;
                uliNow.HighPart = nowFt.dwHighDateTime;

                // Uptime ms -> 100ns
                ULONGLONG upMs = GetTickCount64();
                ULONGLONG up100ns = upMs * 10000ULL;

                ULARGE_INTEGER uliBoot{};
                uliBoot.QuadPart = (uliNow.QuadPart >= up100ns) ? (uliNow.QuadPart - up100ns) : 0;
                bootTimeUtc.dwLowDateTime = uliBoot.LowPart;
                bootTimeUtc.dwHighDateTime = uliBoot.HighPart;
                return true;
#else
                (void)bootTimeUtc; return false;
#endif
            }



		}// namespace SystemUtils
	}// namespace Utils
}// namespace ShadowStrike