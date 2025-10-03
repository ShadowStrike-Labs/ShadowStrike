
#pragma once


#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <cstdint>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"


namespace ShadowStrike {

	namespace Utils {

		namespace SystemUtils {

            struct OSVersion {
                DWORD major = 0;
                DWORD minor = 0;
                DWORD build = 0;
                DWORD platformId = 0;
                bool  isServer = false;
                bool  is64BitOS = false;
                bool  isWow64Process = false; // current process
                std::wstring productName;     // Registry
                std::wstring releaseId;       // Legacy Windows 10
                std::wstring displayVersion;  // Windows 11/10 21H2+
                std::wstring editionId;
                std::wstring currentBuild;    // string representation
            };

            struct CpuInfo {
                DWORD logicalProcessorCount = 0;
                DWORD coreCount = 0;
                DWORD packageCount = 0;
                DWORD numaNodeCount = 0;
                std::wstring architecture; // "x64", "x86", "ARM64", ...
                std::wstring brand;        // CPUID brand string (x86/x64)
                bool hasSSE2 = false;
                bool hasSSE3 = false;
                bool hasSSSE3 = false;
                bool hasSSE41 = false;
                bool hasSSE42 = false;
                bool hasAVX = false;
                bool hasAVX2 = false;
            };

            struct MemoryInfo {
                ULONGLONG totalPhys = 0;
                ULONGLONG availPhys = 0;
                ULONGLONG totalPageFile = 0;
                ULONGLONG availPageFile = 0;
                ULONGLONG totalVirtual = 0;
                ULONGLONG availVirtual = 0;
                ULONGLONG physInstalledKB = 0; // GetPhysicallyInstalledSystemMemory
            };


            struct SecurityInfo {
                bool isElevated = false;
                DWORD integrityRid = 0;      // e.g. SECURITY_MANDATORY_MEDIUM_RID
                std::wstring integrityName;  // "Low/Medium/High/System/Protected"
            };

            //Time
            uint64_t NowFileTime100nsUTC();
            uint64_t UptimeMilliseconds();

            //System /OS
            bool QueryOSVersion(OSVersion& out);
            bool QueryCpuInfo(CpuInfo& out);
            bool QueryMemoryInfo(MemoryInfo& out);
            bool GetBasicSystemInfo(SYSTEM_INFO& out);

            //Process security
            bool GetSecurityInfo(SecurityInfo& out);
            bool EnablePrivilege(const wchar_t* privName, bool enable);
            bool IsDebuggerPresentSafe();

            //Process infos
            DWORD CurrentProcessId();
            std::optional<DWORD> GetParentProcessId(DWORD pid = 0);

            //Paths
            std::wstring GetExecutablePath();
            std::wstring GetModulePath(HMODULE mod = nullptr);
            std::wstring GetSystemDirectoryPath();
            std::wstring GetWindowsDirectoryPath();
            std::wstring ExpandEnv(std::wstring_view s);

            //Machine Name
            std::wstring GetComputerNameDnsFullyQualified();
            std::wstring GetComputerNameDnsHostname();

			//DPI Awareness
            bool SetProcessDpiAwarePerMonitorV2();

            //Affinity
            bool SetProcessPriorityHigh();
            bool SetCurrentThreadPriority(int priority);

            //System boot time
            bool QueryBootTime(FILETIME& bootTimeUtc);


		}// namespace SystemUtils
	}// namespace Utils
}// namespace ShadowStrike