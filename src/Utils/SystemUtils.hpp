
/**
 * @file SystemUtils.hpp
 * @brief System-level utility functions for Windows platform
 *
 * Provides comprehensive system information retrieval including:
 * - OS version and edition detection
 * - CPU topology and feature detection
 * - Memory statistics
 * - Process security and privilege management
 * - System paths and environment expansion
 * - DPI awareness and process priority control
 *
 * @note All functions are Windows-specific and provide fallbacks where appropriate.
 * @warning Some functions require elevated privileges to function correctly.
 *
 * @copyright ShadowStrike Security Suite
 */

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
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {
namespace Utils {
namespace SystemUtils {

    //=============================================================================
    // Constants
    //=============================================================================

    /** Maximum buffer size for path operations */
    inline constexpr size_t kMaxPathBufferSize = 32768;

    /** Maximum buffer size for registry string values */
    inline constexpr size_t kMaxRegistryValueSize = 512;

    /** Initial buffer size for path expansion */
    inline constexpr size_t kInitialPathBufferSize = 512;

    //=============================================================================
    // Data Structures
    //=============================================================================

    /**
     * @struct OSVersion
     * @brief Contains detailed Windows operating system version information
     *
     * Populated by QueryOSVersion() with information from both the kernel
     * and the Windows registry for comprehensive version detection.
     */
    struct OSVersion {
        DWORD major = 0;              ///< Major version number (e.g., 10 for Windows 10/11)
        DWORD minor = 0;              ///< Minor version number
        DWORD build = 0;              ///< Build number (e.g., 19045)
        DWORD platformId = 0;         ///< Platform identifier (VER_PLATFORM_*)
        bool  isServer = false;       ///< True if Windows Server edition
        bool  is64BitOS = false;      ///< True if 64-bit operating system
        bool  isWow64Process = false; ///< True if current process runs under WOW64
        std::wstring productName;     ///< Product name from registry (e.g., "Windows 11 Pro")
        std::wstring releaseId;       ///< Legacy release ID (e.g., "2009")
        std::wstring displayVersion;  ///< Display version (e.g., "23H2")
        std::wstring editionId;       ///< Edition ID (e.g., "Professional")
        std::wstring currentBuild;    ///< Build string from registry

        /**
         * @brief Resets all fields to default values
         */
        void Clear() noexcept {
            major = minor = build = platformId = 0;
            isServer = is64BitOS = isWow64Process = false;
            productName.clear();
            releaseId.clear();
            displayVersion.clear();
            editionId.clear();
            currentBuild.clear();
        }
    };

    /**
     * @struct CpuInfo
     * @brief Contains CPU topology and feature information
     *
     * Provides detailed information about processor architecture, core counts,
     * NUMA topology, and supported instruction set extensions (SSE, AVX).
     */
    struct CpuInfo {
        DWORD logicalProcessorCount = 0;  ///< Number of logical processors (threads)
        DWORD coreCount = 0;              ///< Number of physical cores
        DWORD packageCount = 0;           ///< Number of CPU packages/sockets
        DWORD numaNodeCount = 0;          ///< Number of NUMA nodes
        std::wstring architecture;        ///< Architecture string ("x64", "x86", "ARM64")
        std::wstring brand;               ///< CPU brand string from CPUID

        // SIMD feature flags
        bool hasSSE2 = false;   ///< SSE2 support (baseline for x64)
        bool hasSSE3 = false;   ///< SSE3 support
        bool hasSSSE3 = false;  ///< Supplemental SSE3 support
        bool hasSSE41 = false;  ///< SSE4.1 support
        bool hasSSE42 = false;  ///< SSE4.2 support
        bool hasAVX = false;    ///< AVX support
        bool hasAVX2 = false;   ///< AVX2 support

        /**
         * @brief Resets all fields to default values
         */
        void Clear() noexcept {
            logicalProcessorCount = coreCount = packageCount = numaNodeCount = 0;
            architecture.clear();
            brand.clear();
            hasSSE2 = hasSSE3 = hasSSSE3 = hasSSE41 = hasSSE42 = hasAVX = hasAVX2 = false;
        }
    };

    /**
     * @struct MemoryInfo
     * @brief Contains system memory statistics
     *
     * Provides information about physical memory, page file, and virtual
     * address space availability.
     */
    struct MemoryInfo {
        ULONGLONG totalPhys = 0;       ///< Total physical memory in bytes
        ULONGLONG availPhys = 0;       ///< Available physical memory in bytes
        ULONGLONG totalPageFile = 0;   ///< Total page file size in bytes
        ULONGLONG availPageFile = 0;   ///< Available page file space in bytes
        ULONGLONG totalVirtual = 0;    ///< Total virtual address space in bytes
        ULONGLONG availVirtual = 0;    ///< Available virtual address space in bytes
        ULONGLONG physInstalledKB = 0; ///< Physically installed RAM in KB

        /**
         * @brief Resets all fields to default values
         */
        void Clear() noexcept {
            totalPhys = availPhys = totalPageFile = availPageFile = 0;
            totalVirtual = availVirtual = physInstalledKB = 0;
        }
    };

    /**
     * @struct SecurityInfo
     * @brief Contains process security and integrity level information
     *
     * Provides information about process elevation status and
     * mandatory integrity level.
     */
    struct SecurityInfo {
        bool isElevated = false;      ///< True if process has elevated privileges
        DWORD integrityRid = 0;       ///< Integrity level RID (e.g., SECURITY_MANDATORY_MEDIUM_RID)
        std::wstring integrityName;   ///< Human-readable integrity level name

        /**
         * @brief Resets all fields to default values
         */
        void Clear() noexcept {
            isElevated = false;
            integrityRid = 0;
            integrityName.clear();
        }
    };

    //=============================================================================
    // Time Functions
    //=============================================================================

    /**
     * @brief Gets current UTC time as 100-nanosecond intervals since Jan 1, 1601
     * @return FILETIME value as uint64_t, or 0 on failure
     * @note Uses GetSystemTimePreciseAsFileTime when available for higher precision
     */
    [[nodiscard]] uint64_t NowFileTime100nsUTC() noexcept;

    /**
     * @brief Gets system uptime in milliseconds
     * @return Milliseconds since system boot, or 0 on non-Windows platforms
     * @note Uses GetTickCount64 which doesn't wrap like GetTickCount
     */
    [[nodiscard]] uint64_t UptimeMilliseconds() noexcept;

    //=============================================================================
    // System/OS Query Functions
    //=============================================================================

    /**
     * @brief Queries detailed operating system version information
     * @param[out] out OSVersion structure to populate
     * @return true on success, false on failure
     * @note Uses RtlGetVersion for accurate version detection (bypasses compatibility shim)
     */
    [[nodiscard]] bool QueryOSVersion(OSVersion& out) noexcept;

    /**
     * @brief Queries CPU topology and feature information
     * @param[out] out CpuInfo structure to populate
     * @return true on success, false on failure
     */
    [[nodiscard]] bool QueryCpuInfo(CpuInfo& out) noexcept;

    /**
     * @brief Queries system memory statistics
     * @param[out] out MemoryInfo structure to populate
     * @return true on success, false on failure
     */
    [[nodiscard]] bool QueryMemoryInfo(MemoryInfo& out) noexcept;

    /**
     * @brief Gets basic system information
     * @param[out] out SYSTEM_INFO structure to populate
     * @return true on success, false on failure
     * @note Uses GetNativeSystemInfo when available for accurate info on WOW64
     */
    [[nodiscard]] bool GetBasicSystemInfo(SYSTEM_INFO& out) noexcept;

    //=============================================================================
    // Process Security Functions
    //=============================================================================

    /**
     * @brief Gets security information for the current process
     * @param[out] out SecurityInfo structure to populate
     * @return true on success, false on failure
     */
    [[nodiscard]] bool GetSecurityInfo(SecurityInfo& out) noexcept;

    /**
     * @brief Enables or disables a privilege in the current process token
     * @param privName Privilege name (e.g., SE_DEBUG_NAME)
     * @param enable true to enable, false to disable
     * @return true if privilege was successfully adjusted
     * @warning Requires appropriate process rights to adjust privileges
     */
    [[nodiscard]] bool EnablePrivilege(const wchar_t* privName, bool enable) noexcept;

    /**
     * @brief Safely checks if a debugger is attached to the process
     * @return true if debugger is present
     */
    [[nodiscard]] bool IsDebuggerPresentSafe() noexcept;

    //=============================================================================
    // Process Information Functions
    //=============================================================================

    /**
     * @brief Gets the current process ID
     * @return Current process ID
     */
    [[nodiscard]] DWORD CurrentProcessId() noexcept;

    /**
     * @brief Gets the parent process ID of a given process
     * @param pid Process ID to query (0 for current process)
     * @return Parent process ID, or nullopt if not found or on error
     */
    [[nodiscard]] std::optional<DWORD> GetParentProcessId(DWORD pid = 0) noexcept;

    //=============================================================================
    // Path Functions
    //=============================================================================

    /**
     * @brief Gets the full path of the current executable
     * @return Executable path, or empty string on failure
     */
    [[nodiscard]] std::wstring GetExecutablePath() noexcept;

    /**
     * @brief Gets the full path of a loaded module
     * @param mod Module handle (nullptr for main executable)
     * @return Module path, or empty string on failure
     */
    [[nodiscard]] std::wstring GetModulePath(HMODULE mod = nullptr) noexcept;

    /**
     * @brief Gets the Windows system directory path
     * @return System directory path (e.g., "C:\\Windows\\System32"), or empty on failure
     */
    [[nodiscard]] std::wstring GetSystemDirectoryPath() noexcept;

    /**
     * @brief Gets the Windows directory path
     * @return Windows directory path (e.g., "C:\\Windows"), or empty on failure
     */
    [[nodiscard]] std::wstring GetWindowsDirectoryPath() noexcept;

    /**
     * @brief Expands environment variables in a string
     * @param s String containing environment variables (e.g., "%USERPROFILE%\\Documents")
     * @return Expanded string, or original string on failure
     */
    [[nodiscard]] std::wstring ExpandEnv(std::wstring_view s) noexcept;

    //=============================================================================
    // Computer Name Functions
    //=============================================================================

    /**
     * @brief Gets the fully qualified DNS name of the computer
     * @return FQDN, or empty string on failure
     */
    [[nodiscard]] std::wstring GetComputerNameDnsFullyQualified() noexcept;

    /**
     * @brief Gets the DNS hostname of the computer
     * @return Hostname, or empty string on failure
     */
    [[nodiscard]] std::wstring GetComputerNameDnsHostname() noexcept;

    //=============================================================================
    // DPI Awareness Functions
    //=============================================================================

    /**
     * @brief Sets DPI awareness to Per Monitor V2 (or best available fallback)
     * @return true if DPI awareness was successfully set
     * @note Should be called early in application startup
     */
    [[nodiscard]] bool SetProcessDpiAwarePerMonitorV2() noexcept;

    //=============================================================================
    // Process Priority Functions
    //=============================================================================

    /**
     * @brief Sets the current process priority to HIGH_PRIORITY_CLASS
     * @return true on success
     * @warning May affect system responsiveness; use with caution
     */
    [[nodiscard]] bool SetProcessPriorityHigh() noexcept;

    /**
     * @brief Sets the current thread priority
     * @param priority Thread priority value (THREAD_PRIORITY_*)
     * @return true on success
     */
    [[nodiscard]] bool SetCurrentThreadPriority(int priority) noexcept;

    //=============================================================================
    // System Boot Time Functions
    //=============================================================================

    /**
     * @brief Queries the system boot time in UTC
     * @param[out] bootTimeUtc FILETIME structure to receive boot time
     * @return true on success
     * @note Calculated from current time minus uptime; may have minor drift
     */
    [[nodiscard]] bool QueryBootTime(FILETIME& bootTimeUtc) noexcept;

} // namespace SystemUtils
} // namespace Utils
} // namespace ShadowStrike