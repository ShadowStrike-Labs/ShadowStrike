/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file SandboxEvasionDetector.cpp
 * @brief Behavioral detection of anti-sandbox evasion in target processes
 *
 * DESIGN PHILOSOPHY — DEFENDER PERSPECTIVE:
 *
 * This module detects MALWARE that attempts to evade sandbox analysis by
 * probing the host environment. The detector does NOT check if the host
 * IS a sandbox — that would be acting like malware.
 *
 * PRIMARY DETECTION: per-process behavioral analysis (PE imports, embedded
 * strings, code patterns indicating sandbox detection).
 *
 * HOST CONTEXT: hardware/timing/artifact checks provide scoring calibration
 * data — on a real sandbox, anti-sandbox probing is LESS suspicious.
 *
 * @note Thread-safe implementation using shared_mutex.
 * @note Follows PIMPL pattern for ABI stability.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "SandboxEvasionDetector.hpp"
#include "../Utils/CpuFeatures.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../PEParser/PEParser.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <bitset>
#include <future>
#include <mutex>
#include <numeric>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

// PhantomDisassembler for advanced hook detection and code analysis
#include <PhantomDisassembler/PhantomDisasm.hpp>

#ifdef _WIN32
#  include <intrin.h>
#  include <emmintrin.h>  // SSE2 intrinsics for fallback functions
#  include <TlHelp32.h>
#  include <Psapi.h>
#  include <ShlObj.h>
#  include <WbemIdl.h>
#  include <comdef.h>
#  include <SetupAPI.h>
#  include <devguid.h>
#  include <iphlpapi.h>
#  include <mmsystem.h>   // For waveOutGetNumDevs
#  pragma comment(lib, "wbemuuid.lib")
#  pragma comment(lib, "Setupapi.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "winmm.lib")  // For multimedia functions
#endif

// Define M_PI if not defined (not guaranteed in C++20)
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// =============================================================================
// ASSEMBLY FUNCTION FALLBACKS
// =============================================================================
// These fallback implementations are used when the assembly module is not
// linked (e.g., on non-Windows platforms or during testing). They provide
// equivalent functionality using C++ and compiler intrinsics where possible.
//
// MSVC linker directive /ALTERNATENAME automatically falls back to these
// if the primary assembly symbols are not found.
// =============================================================================

#ifdef _MSC_VER
#pragma comment(linker, "/ALTERNATENAME:GetPreciseRDTSC=Fallback_GetPreciseRDTSC")
#pragma comment(linker, "/ALTERNATENAME:GetPreciseRDTSCP=Fallback_GetPreciseRDTSCP")
#pragma comment(linker, "/ALTERNATENAME:MeasureRDTSCOverhead=Fallback_MeasureRDTSCOverhead")
#pragma comment(linker, "/ALTERNATENAME:MeasureCPUIDOverhead=Fallback_MeasureCPUIDOverhead")
#pragma comment(linker, "/ALTERNATENAME:MeasureSleepAcceleration=Fallback_MeasureSleepAcceleration")
#pragma comment(linker, "/ALTERNATENAME:CheckCuckooBackdoor=Fallback_CheckCuckooBackdoor")
#pragma comment(linker, "/ALTERNATENAME:MeasureTimingPrecision=Fallback_MeasureTimingPrecision")
// The shared fallback implements the SERIALIZED AVERAGED variant, which is
// stricter than this module's own single-sample routine, so a fallback build
// cannot weaken this check (task 206).
#pragma comment(linker, "/ALTERNATENAME:SandboxDetectSingleStepTiming=Fallback_DetectSingleStepTiming")
#pragma comment(linker, "/ALTERNATENAME:MeasureVMExitOverhead=Fallback_MeasureVMExitOverhead")
#pragma comment(linker, "/ALTERNATENAME:CalibrateTimingBaseline=Fallback_CalibrateTimingBaseline")
#pragma comment(linker, "/ALTERNATENAME:DetectTimingHook=Fallback_DetectTimingHook")
#pragma comment(linker, "/ALTERNATENAME:MeasureMemoryLatency=Fallback_MeasureMemoryLatency")
#pragma comment(linker, "/ALTERNATENAME:CheckHypervisorBit=Fallback_CheckHypervisorBit")
#pragma comment(linker, "/ALTERNATENAME:MeasureIntOverhead=Fallback_MeasureIntOverhead")
#pragma comment(linker, "/ALTERNATENAME:SandboxRDTSCDifference=Fallback_SandboxRDTSCDifference")
#pragma comment(linker, "/ALTERNATENAME:GetRDTSCFrequency=Fallback_GetRDTSCFrequency")
#pragma comment(linker, "/ALTERNATENAME:DetectRDTSCEmulation=Fallback_DetectRDTSCEmulation")
#endif

extern "C" {

/// Fallback: GetPreciseRDTSC using intrinsics
uint64_t Fallback_GetPreciseRDTSC(void) {
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    return __rdtsc();
#else
    return 0;
#endif
}

/// Fallback: GetPreciseRDTSCP using intrinsics
uint64_t Fallback_GetPreciseRDTSCP(uint32_t* processorId) {
#ifdef _WIN32
    unsigned int aux = 0;
    uint64_t tsc = ::ShadowStrike::Utils::CpuFeatures::ReadSerializedTsc(&aux);
    if (processorId) {
        *processorId = aux;
    }
    return tsc;
#else
    if (processorId) *processorId = 0;
    return 0;
#endif
}

/// Fallback: MeasureRDTSCOverhead
uint64_t Fallback_MeasureRDTSCOverhead(void) {
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    uint64_t start = __rdtsc();
    
    // Execute 100 RDTSC calls
    for (int i = 0; i < 100; ++i) {
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
        (void)__rdtsc();
    }
    
    __cpuid(cpuInfo, 0);
    uint64_t end = __rdtsc();
    return (end - start) / 1000;  // Average per call
#else
    return 0;
#endif
}

/// Fallback: MeasureCPUIDOverhead
uint64_t Fallback_MeasureCPUIDOverhead(void) {
#ifdef _WIN32
    int cpuInfo[4];
    uint64_t start = __rdtsc();
    
    // Execute 100 CPUID calls
    for (int i = 0; i < 100; ++i) {
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
        __cpuid(cpuInfo, 0);
    }
    
    uint64_t end = __rdtsc();
    return (end - start) / 1000;  // Average per call
#else
    return 0;
#endif
}

/// Fallback: MeasureSleepAcceleration
uint64_t Fallback_MeasureSleepAcceleration(uint32_t sleepMs) {
#ifdef _WIN32
    // SECURITY FIX: Explicit division-by-zero guard at point of use
    // Even though sleepMs < 100 is rejected, we add defense-in-depth
    if (sleepMs < 100 || sleepMs == 0) return 0;
    
    ULONGLONG startTicks = GetTickCount64();
    Sleep(sleepMs);
    ULONGLONG endTicks = GetTickCount64();
    
    ULONGLONG actualMs = endTicks - startTicks;
    
    // Calculate deviation percentage
    if (actualMs >= sleepMs) {
        return 0;  // No acceleration
    }
    
    // Division is safe: sleepMs guaranteed > 0 by guard above
    return ((sleepMs - actualMs) * 100) / sleepMs;
#else
    (void)sleepMs;
    return 0;
#endif
}

/// Fallback: CheckCuckooBackdoor
/// Note: Actual Cuckoo detection requires network socket operations
uint32_t Fallback_CheckCuckooBackdoor(void) {
    // This is a stub - real Cuckoo detection is done in C++ code
    return 0;
}

/// Fallback: MeasureTimingPrecision
uint64_t Fallback_MeasureTimingPrecision(void) {
#ifdef _WIN32
    uint64_t minDelta = UINT64_MAX;
    
    for (int i = 0; i < 100; ++i) {
        uint64_t t1 = __rdtsc();
        uint64_t t2 = __rdtsc();
        uint64_t delta = t2 - t1;
        if (delta < minDelta) {
            minDelta = delta;
        }
    }
    
    return minDelta;
#else
    return 0;
#endif
}

// NOTE: Fallback_DetectSingleStepTiming is provided by DebuggerEvasionDetector.cpp
// to avoid duplicate symbol errors when both TUs are linked together.

/// Fallback: MeasureVMExitOverhead
uint64_t Fallback_MeasureVMExitOverhead(void) {
#ifdef _WIN32
    uint64_t total = 0;
    int cpuInfo[4];
    
    // Test 1: CPUID overhead (causes VM exit)
    uint64_t start = __rdtsc();
    __cpuid(cpuInfo, 1);  // Leaf 1
    uint64_t end = __rdtsc();
    total += (end - start);
    
    // Test 2: Another CPUID
    start = __rdtsc();
    __cpuid(cpuInfo, 0);
    end = __rdtsc();
    total += (end - start);
    
    // Test 3: Memory fence instructions
    start = __rdtsc();
    _mm_sfence();
    _mm_lfence();
    _mm_mfence();
    end = __rdtsc();
    total += (end - start);
    
    return total;
#else
    return 0;
#endif
}

/// Fallback: CalibrateTimingBaseline
static uint64_t g_baselineRDTSC_fallback = 0;
static uint64_t g_baselineCPUID_fallback = 0;
static std::once_flag g_calibrationOnce_fallback;

void Fallback_CalibrateTimingBaseline(void) {
#ifdef _WIN32
    std::call_once(g_calibrationOnce_fallback, []() {
        // Measure RDTSC baseline
        uint64_t sum = 0;
        for (int i = 0; i < 10; ++i) {
            uint64_t start = __rdtsc();
            uint64_t end = __rdtsc();
            sum += (end - start);
        }
        g_baselineRDTSC_fallback = sum / 10;

        // Measure CPUID baseline
        int cpuInfo[4];
        sum = 0;
        for (int i = 0; i < 10; ++i) {
            uint64_t start = __rdtsc();
            __cpuid(cpuInfo, 0);
            uint64_t end = __rdtsc();
            sum += (end - start);
        }
        g_baselineCPUID_fallback = sum / 10;
    });
#endif
}

/// Fallback: DetectTimingHook
uint32_t Fallback_DetectTimingHook(void) {
#ifdef _WIN32
    uint64_t rdtsc1 = __rdtsc();
    
    unsigned int aux;
    uint64_t rdtscp = ::ShadowStrike::Utils::CpuFeatures::ReadSerializedTsc(&aux);
    
    // If difference is very large, timing may be hooked
    int64_t diff = static_cast<int64_t>(rdtscp) - static_cast<int64_t>(rdtsc1);
    if (diff < 0) diff = -diff;
    
    return (diff > 10000) ? 1 : 0;
#else
    return 0;
#endif
}

/// Fallback: MeasureMemoryLatency
uint64_t Fallback_MeasureMemoryLatency(void) {
#ifdef _WIN32
    // Allocate and flush memory - use alignas for proper alignment
    // THREAD-SAFETY: a single static buffer would be cache-line shared across
    // every concurrent caller (the system-wide scan calls this from worker
    // threads), serializing flushes and corrupting the latency measurement.
    // thread_local gives each thread an independent, aligned cache line.
    alignas(64) static thread_local volatile char buffer[4096];
    
    // Flush cache line
    _mm_clflush(const_cast<char*>(&buffer[0]));
    _mm_mfence();
    
    // Measure uncached access
    uint64_t start = __rdtsc();
    volatile char x = buffer[0];
    (void)x;
    _mm_lfence();
    uint64_t end = __rdtsc();
    
    return end - start;
#else
    return 0;
#endif
}

/// Fallback: CheckHypervisorBit
uint32_t Fallback_CheckHypervisorBit(void) {
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    
    // Check hypervisor bit (ECX bit 31)
    return (cpuInfo[2] & (1 << 31)) ? 1 : 0;
#else
    return 0;
#endif
}

/// Fallback: MeasureIntOverhead
uint64_t Fallback_MeasureIntOverhead(void) {
#ifdef _WIN32
    int cpuInfo[4];
    
    // Measure hypervisor CPUID leaf (may cause VM exit)
    __cpuid(cpuInfo, 0);
    uint64_t start = __rdtsc();
    __cpuid(cpuInfo, 0x40000000);  // Hypervisor leaf
    uint64_t end = __rdtsc();
    
    return end - start;
#else
    return 0;
#endif
}

/// Fallback: SandboxRDTSCDifference
uint64_t Fallback_SandboxRDTSCDifference(uint32_t iterations) {
#ifdef _WIN32
    if (iterations == 0) return 0;
    
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    uint64_t start = __rdtsc();
    
    // Busy loop
    for (uint32_t i = 0; i < iterations; ++i) {
        _mm_pause();
    }
    
    uint64_t end = __rdtsc();
    return end - start;
#else
    (void)iterations;
    return 0;
#endif
}

/// Fallback: GetRDTSCFrequency
uint64_t Fallback_GetRDTSCFrequency(void) {
#ifdef _WIN32
    int cpuInfo[4];
    
    // Try CPUID leaf 0x15 (TSC/Core Crystal Clock info)
    __cpuid(cpuInfo, 0x15);
    
    uint32_t denominator = cpuInfo[0];  // EAX
    uint32_t numerator = cpuInfo[1];    // EBX
    uint32_t frequency = cpuInfo[2];    // ECX
    
    if (numerator == 0 || denominator == 0) {
        return 0;  // Info not available
    }
    
    // TSC frequency = (ECX * EBX) / EAX
    if (frequency != 0) {
        return (static_cast<uint64_t>(frequency) * numerator) / denominator;
    }
    
    return 0;
#else
    return 0;
#endif
}

/// Fallback: DetectRDTSCEmulation
uint32_t Fallback_DetectRDTSCEmulation(void) {
#ifdef _WIN32
    // Take 3 consecutive RDTSC readings
    uint64_t t1 = __rdtsc();
    uint64_t t2 = __rdtsc();
    uint64_t t3 = __rdtsc();
    
    // Check for constant values (clear emulation sign)
    if (t1 == t2 || t2 == t3) {
        return 1;  // Emulation detected
    }
    
    // Check for suspicious constant increment
    uint64_t delta1 = t2 - t1;
    uint64_t delta2 = t3 - t2;
    
    // If deltas are exactly equal, suspicious (but not definitive)
    // Real CPUs have some jitter
    if (delta1 == delta2 && delta1 > 0) {
        // Additional check - very suspicious if this pattern repeats
        uint64_t t4 = __rdtsc();
        uint64_t delta3 = t4 - t3;
        if (delta3 == delta2) {
            return 1;  // Emulation very likely
        }
    }
    
    return 0;
#else
    return 0;
#endif
}

} // extern "C"

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // LOGGING CATEGORY
        // ============================================================================

        static constexpr const wchar_t* LOG_CATEGORY = L"SandboxEvasionDetector";

        // ============================================================================
        // INTERNAL CONSTANTS
        // ============================================================================

        namespace {
            // Known VM/Sandbox BIOS strings
            // CRITICAL FIX (Issue #2): Removed cloud providers to prevent false positives
            // AWS EC2, Azure, GCP are LEGITIMATE enterprise environments, not sandboxes
            // Only include strings that definitively indicate analysis sandbox environments
            constexpr std::wstring_view VM_BIOS_STRINGS[] = {
                L"VBOX",        // VirtualBox (often used for sandboxing)
                L"QEMU",        // QEMU (common in Cuckoo/CAPE)
                L"BOCHS",       // Bochs emulator (analysis tool)
                L"INNOTEK"      // Old VirtualBox identifier
                // REMOVED: L"VMWARE" - Used legitimately in enterprise (vSphere, Workstation)
                // REMOVED: L"VIRTUAL" - Too generic, matches legitimate VMs
                // REMOVED: L"PARALLELS" - Legitimate macOS virtualization
                // REMOVED: L"XEN" - Used by AWS, legitimate hypervisor
                // REMOVED: L"ORACLE" - OCI cloud is legitimate
                // REMOVED: L"AMAZON EC2" - AWS is legitimate enterprise cloud
                // REMOVED: L"MICROSOFT CORPORATION" - Azure is legitimate enterprise cloud
            };

            // Known DEFINITIVE sandbox/analysis environment strings
            // These indicate actual malware analysis sandboxes, not legitimate VMs
            constexpr std::wstring_view DEFINITIVE_SANDBOX_STRINGS[] = {
                L"CUCKOO",      // Cuckoo Sandbox
                L"CAPE",        // CAPE Sandbox
                L"JOEBOX",      // Joe Sandbox
                L"ANYRUN",      // ANY.RUN
                L"VMRAY",       // VMRay
                L"TRIA.GE",     // Triage sandbox
                L"HYBRID",      // Hybrid Analysis
                L"SANDBOX"      // Generic sandbox identifier
            };

            // Known VM/Sandbox MAC OUI prefixes (first 3 bytes)
            constexpr uint8_t VM_MAC_PREFIXES[][3] = {
                {0x00, 0x05, 0x69},  // VMware
                {0x00, 0x0C, 0x29},  // VMware
                {0x00, 0x1C, 0x14},  // VMware
                {0x00, 0x50, 0x56},  // VMware
                {0x08, 0x00, 0x27},  // VirtualBox
                {0x52, 0x54, 0x00},  // QEMU/KVM
                {0x00, 0x16, 0x3E},  // Xen
                {0x00, 0x1C, 0x42},  // Parallels
                {0x00, 0x03, 0xFF},  // Microsoft Hyper-V
                {0x00, 0x15, 0x5D},  // Microsoft Hyper-V
            };

            // Sandbox-specific usernames
            constexpr std::wstring_view SANDBOX_USERNAMES[] = {
                L"sandbox", L"virus", L"malware", L"maltest", L"test", L"sample",
                L"vboxuser", L"vmware", L"user", L"admin", L"administrator",
                L"currentuser", L"cuckoo", L"wilbert", L"analysis", L"analyst"
            };

            // Sandbox-specific computer names
            constexpr std::wstring_view SANDBOX_COMPUTERNAMES[] = {
                L"SANDBOX", L"VIRUS", L"MALWARE", L"MALTEST", L"TEST", L"SAMPLE",
                L"TEQUILABOOMBOOM", L"PC", L"DESKTOP", L"JOHN-PC", L"ANALYSIS",
                L"WIN7-PC", L"WIN10-PC", L"CUCKOO", L"VMWARE", L"VBOX"
            };

            // Suspicious driver names
            constexpr std::wstring_view SANDBOX_DRIVERS[] = {
                L"VBoxGuest", L"VBoxMouse", L"VBoxSF", L"VBoxVideo",
                L"vmci", L"vmhgfs", L"vmmouse", L"vmrawdsk", L"vmusbmouse",
                L"vmx_svga", L"vmxnet", L"vmware_vga",
                L"Hgfs", L"Vmhgfs", L"prl_boot", L"prl_fs", L"prl_memdev",
                L"xenevtchn", L"xennet", L"xensvc", L"xenvdb"
            };

            // Analysis tool window class names
            constexpr std::wstring_view ANALYSIS_WINDOW_CLASSES[] = {
                L"OLLYDBG", L"GBDYLLO", L"pediy06", L"IDA", L"WinDbgFrameClass",
                L"Zeta Debugger", L"Rock Debugger", L"ObsidianGUI", L"ID"
            };

            // Sleep acceleration detection threshold (>5% deviation)
            constexpr double TIMING_DEVIATION_THRESHOLD = 0.05;

            // Minimum expected timing for 100ms sleep (in 100ns units)
            constexpr int64_t EXPECTED_100MS_SLEEP = 100 * 10000;  // 100ms in 100ns

            // Callback ID counter
            static std::atomic<uint64_t> s_callbackIdCounter{ 1 };

            // -------------------------------------------------------------------------
            // Helper: Count files in a directory (non-recursive)
            // Used for system wear and tear analysis
            // -------------------------------------------------------------------------
            [[nodiscard]] size_t CountFilesInDirectory(std::wstring_view dirPath) noexcept {
                size_t count = 0;
#ifdef _WIN32
                if (dirPath.empty()) return 0;
                
                std::wstring searchPath(dirPath);
                if (searchPath.back() != L'\\' && searchPath.back() != L'/') {
                    searchPath += L'\\';
                }
                searchPath += L'*';
                
                WIN32_FIND_DATAW findData{};
                HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                if (hFind == INVALID_HANDLE_VALUE) {
                    return 0;
                }
                
                // Limit iteration to prevent denial of service on huge directories
                constexpr size_t MAX_FILE_COUNT = 100000;
                
                do {
                    // Skip . and ..
                    if (findData.cFileName[0] == L'.' && 
                        (findData.cFileName[1] == L'\0' || 
                         (findData.cFileName[1] == L'.' && findData.cFileName[2] == L'\0'))) {
                        continue;
                    }
                    
                    // Only count files, not directories
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        ++count;
                    }
                    
                    if (count >= MAX_FILE_COUNT) break;
                    
                } while (FindNextFileW(hFind, &findData));
                
                FindClose(hFind);
#else
                (void)dirPath;
#endif
                return count;
            }
        }

        // ============================================================================
        // PIMPL IMPLEMENTATION
        // ============================================================================

        struct SandboxEvasionDetector::Impl {
            // -------------------------------------------------------------------------
            // State
            // -------------------------------------------------------------------------
            std::atomic<bool> initialized{ false };
            std::atomic<bool> shutdownRequested{ false };

            // -------------------------------------------------------------------------
            // Configuration
            // -------------------------------------------------------------------------
            SandboxDetectorConfig config;
            mutable std::shared_mutex configMutex;

            // -------------------------------------------------------------------------
            // Thread Pool
            // -------------------------------------------------------------------------
            // DESIGN: writes (Initialize/Shutdown) and reads (ScanSystemAsync workers)
            // race on the shared_ptr instance itself, which is UB. Guard with a
            // dedicated shared_mutex and always return a *copy* to callers so they
            // hold their own strong reference for the duration of the work.
            std::shared_ptr<Utils::ThreadPool> threadPool;
            mutable std::shared_mutex threadPoolMutex;

            [[nodiscard]] std::shared_ptr<Utils::ThreadPool> GetThreadPool() const {
                std::shared_lock lock(threadPoolMutex);
                return threadPool;
            }

            void SetThreadPool(std::shared_ptr<Utils::ThreadPool> pool) {
                std::unique_lock lock(threadPoolMutex);
                threadPool = std::move(pool);
            }

            void ResetThreadPool() {
                std::shared_ptr<Utils::ThreadPool> doomed;
                {
                    std::unique_lock lock(threadPoolMutex);
                    doomed.swap(threadPool);
                }
                // Last reference released outside the lock so destructor side-effects
                // (worker join) cannot deadlock against another caller waiting on us.
            }

            // -------------------------------------------------------------------------
            // Cache
            // -------------------------------------------------------------------------
            std::optional<SandboxEvasionResult> cachedResult;
            std::chrono::system_clock::time_point cacheTimestamp;
            mutable std::shared_mutex cacheMutex;

            // -------------------------------------------------------------------------
            // Hardware Profile Cache
            // -------------------------------------------------------------------------
            std::optional<HardwareProfile> cachedHardwareProfile;
            std::chrono::system_clock::time_point hardwareProfileTimestamp;
            mutable std::shared_mutex hardwareProfileMutex;

            // -------------------------------------------------------------------------
            // Callbacks
            // -------------------------------------------------------------------------
            std::unordered_map<uint64_t, SandboxDetectionCallback> callbacks;
            mutable std::shared_mutex callbacksMutex;

            // -------------------------------------------------------------------------
            // TYPE B Process Analysis Callback
            // -------------------------------------------------------------------------
            SandboxEvasionDetector::ProcessSandboxCallback processDetectionCallback;

            // -------------------------------------------------------------------------
            // Statistics
            // -------------------------------------------------------------------------
            SandboxDetectorStats stats;

            // -------------------------------------------------------------------------
            // PhantomDisassembler Contexts
            // -------------------------------------------------------------------------
            Phantom::Disasm::Decoder decoder32{};
            Phantom::Disasm::Decoder decoder64{};
            Phantom::Disasm::Formatter formatter{};
            bool disasmInitialized{ false };

            // -------------------------------------------------------------------------
            // COM Initialization State
            // -------------------------------------------------------------------------
            // DESIGN: This TU does not currently call any IWbem/CoCreateInstance APIs,
            // but the helper is preserved for parity with sister evasion detectors and
            // so that follow-on WMI-backed checks integrate cleanly. CoUninitialize must
            // run on the same thread that called CoInitializeEx, so we pin the thread
            // ID at initialize time and refuse to tear COM down from another thread.
            bool comInitialized{ false };
            DWORD comInitThreadId{ 0 };
            mutable std::mutex comMutex;  // Protects COM init/uninit operations

            // -------------------------------------------------------------------------
            // Utility Methods
            // -------------------------------------------------------------------------

            void InitializeDisasm() noexcept {
                if (disasmInitialized) return;

                // Initialize 64-bit decoder (primary - our target platform)
                decoder64.Init(Phantom::Disasm::MachineMode::Long64);

                // Initialize 32-bit decoder (for analyzing 32-bit malware/WoW64 processes)
                decoder32.Init(Phantom::Disasm::MachineMode::Legacy32);

                // Initialize formatter for disassembly output
                formatter.Init(Phantom::Disasm::FormatterStyle::Intel);

                disasmInitialized = true;
                SS_LOG_DEBUG(LOG_CATEGORY, L"PhantomDisassembler initialized");
            }

            [[nodiscard]] Phantom::Disasm::Decoder* GetDecoder(bool is64Bit) noexcept {
                return is64Bit ? &decoder64 : &decoder32;
            }

            [[nodiscard]] bool IsCacheValid() const {
                std::shared_lock lock(cacheMutex);
                if (!cachedResult.has_value()) return false;

                auto now = std::chrono::system_clock::now();
                auto age = std::chrono::duration_cast<std::chrono::minutes>(now - cacheTimestamp);

                std::shared_lock cfgLock(configMutex);
                return age < config.cacheTTL;
            }

            void InitializeCOM() {
#ifdef _WIN32
                // THREAD-SAFETY FIX: Protect COM initialization with mutex
                // COM apartment model requires careful thread management.
                std::lock_guard<std::mutex> lock(comMutex);
                if (!comInitialized) {
                    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                    // Only S_OK / S_FALSE bump the apartment refcount that we own.
                    // RPC_E_CHANGED_MODE means another component already initialized
                    // COM in a different mode WITHOUT incrementing our reference, so
                    // calling CoUninitialize would tear down somebody else's apartment.
                    if (SUCCEEDED(hr)) {
                        comInitialized = true;
                        comInitThreadId = ::GetCurrentThreadId();
                        SS_LOG_DEBUG(LOG_CATEGORY,
                            L"COM initialized for sandbox detection on thread %lu",
                            static_cast<unsigned long>(comInitThreadId));
                    } else if (hr == RPC_E_CHANGED_MODE) {
                        SS_LOG_DEBUG(LOG_CATEGORY,
                            L"COM already initialized in different mode; not pairing CoUninitialize");
                    } else {
                        SS_LOG_WARN(LOG_CATEGORY, L"COM initialization failed: 0x%08lX",
                            static_cast<unsigned long>(hr));
                    }
                }
#endif
            }

            void UninitializeCOM() {
#ifdef _WIN32
                // THREAD-SAFETY FIX: Protect COM uninitialization with mutex.
                // CoUninitialize only affects its own thread's apartment. If invoked
                // from any other thread, it is a silent no-op and would leak our
                // apartment reference on the original thread. Refuse the call in
                // that case rather than corrupt state.
                std::lock_guard<std::mutex> lock(comMutex);
                if (comInitialized) {
                    const DWORD currentTid = ::GetCurrentThreadId();
                    if (currentTid != comInitThreadId) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"Skipping CoUninitialize: caller thread %lu != init thread %lu",
                            static_cast<unsigned long>(currentTid),
                            static_cast<unsigned long>(comInitThreadId));
                        return;
                    }
                    CoUninitialize();
                    comInitialized = false;
                    comInitThreadId = 0;
                    SS_LOG_DEBUG(LOG_CATEGORY, L"COM uninitialized");
                }
#endif
            }
        };

        // ============================================================================
        // SINGLETON INSTANCE
        // ============================================================================

        SandboxEvasionDetector& SandboxEvasionDetector::Instance() {
            static SandboxEvasionDetector instance;
            return instance;
        }

        // ============================================================================
        // CONSTRUCTOR / DESTRUCTOR
        // ============================================================================

        SandboxEvasionDetector::SandboxEvasionDetector()
            : m_impl(std::make_unique<Impl>()) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"SandboxEvasionDetector instance created");
        }

        SandboxEvasionDetector::~SandboxEvasionDetector() {
            Shutdown();
            SS_LOG_DEBUG(LOG_CATEGORY, L"SandboxEvasionDetector instance destroyed");
        }

        // ============================================================================
        // LIFECYCLE MANAGEMENT
        // ============================================================================

        bool SandboxEvasionDetector::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
            return Initialize(std::move(threadPool), SandboxDetectorConfig::CreateDefault());
        }

        bool SandboxEvasionDetector::Initialize(
            std::shared_ptr<Utils::ThreadPool> threadPool,
            const SandboxDetectorConfig& config
        ) {
            if (m_impl->initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(LOG_CATEGORY, L"SandboxEvasionDetector already initialized");
                return true;
            }

            if (!threadPool) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ThreadPool is null, cannot initialize");
                return false;
            }

            m_impl->SetThreadPool(std::move(threadPool));

            {
                std::unique_lock lock(m_impl->configMutex);
                m_impl->config = config;
            }

            // Initialize COM for WMI queries
            m_impl->InitializeCOM();

            // Initialize PhantomDisassembler for advanced hook detection
            m_impl->InitializeDisasm();

            m_impl->shutdownRequested.store(false, std::memory_order_release);
            m_impl->initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(LOG_CATEGORY, L"SandboxEvasionDetector initialized successfully");
            return true;
        }

        void SandboxEvasionDetector::Shutdown() {
            if (!m_impl->initialized.load(std::memory_order_acquire)) {
                return;
            }

            m_impl->shutdownRequested.store(true, std::memory_order_release);

            // Clear callbacks
            {
                std::unique_lock lock(m_impl->callbacksMutex);
                m_impl->callbacks.clear();
            }

            // Clear caches
            {
                std::unique_lock lock(m_impl->cacheMutex);
                m_impl->cachedResult.reset();
            }

            {
                std::unique_lock lock(m_impl->hardwareProfileMutex);
                m_impl->cachedHardwareProfile.reset();
            }

            m_impl->UninitializeCOM();
            m_impl->ResetThreadPool();
            m_impl->initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(LOG_CATEGORY, L"SandboxEvasionDetector shutdown complete");
        }

        bool SandboxEvasionDetector::IsInitialized() const noexcept {
            return m_impl->initialized.load(std::memory_order_acquire);
        }

        void SandboxEvasionDetector::UpdateConfig(const SandboxDetectorConfig& config) {
            std::unique_lock lock(m_impl->configMutex);
            m_impl->config = config;
            SS_LOG_DEBUG(LOG_CATEGORY, L"Configuration updated");
        }

        SandboxDetectorConfig SandboxEvasionDetector::GetConfig() const {
            std::shared_lock lock(m_impl->configMutex);
            return m_impl->config;
        }

        // ============================================================================
        // FULL SYSTEM SCAN
        // ============================================================================




        // ============================================================================
        // INDIVIDUAL ANALYSIS METHODS
        // ============================================================================







        // ============================================================================
        // SPECIFIC CHECKS
        // ============================================================================







        // ============================================================================
        // CALLBACKS
        // ============================================================================



        const SandboxDetectorStats& SandboxEvasionDetector::GetStats() const {
            return m_impl->stats;
        }

        void SandboxEvasionDetector::ResetStats() {
            m_impl->stats.Reset();
            SS_LOG_DEBUG(LOG_CATEGORY, L"Statistics reset");
        }




        // ============================================================================
        // INTERNAL CHECK METHODS
        // ============================================================================



















        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================



        // ============================================================================
        // TYPE B: Per-Process Sandbox Evasion Analysis
        // ============================================================================

        // Known sandbox-detection API imports to look for in target processes
        namespace SandboxDetectionAPIs {
            static constexpr const char* HARDWARE_APIS[] = {
                "GlobalMemoryStatusEx", "GetSystemInfo", "GetNativeSystemInfo",
                "GetDiskFreeSpaceExW", "GetDiskFreeSpaceExA",
                "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx",
                "SetupDiGetClassDevsW", "SetupDiEnumDeviceInfo",
                "GetDeviceCaps"
            };

            static constexpr const char* TIMING_APIS[] = {
                "GetTickCount", "GetTickCount64",
                "QueryPerformanceCounter", "QueryPerformanceFrequency",
                "NtQuerySystemTime", "GetSystemTimeAsFileTime"
            };

            static constexpr const char* ENVIRONMENT_APIS[] = {
                "GetSystemMetrics", "EnumDisplayDevicesW", "EnumDisplaySettingsW",
                "GetComputerNameW", "GetComputerNameA",
                "GetUserNameW", "GetUserNameA",
                "GetTimeZoneInformation", "GetLocaleInfoW",
                "GetUserDefaultLCID", "GetSystemDefaultLCID"
            };

            static constexpr const char* ARTIFACT_APIS[] = {
                "GetModuleHandleW", "GetModuleHandleA",
                "OpenMutexW", "OpenMutexA",
                "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
                "EnumServicesStatusExW",
                "RegOpenKeyExW", "RegQueryValueExW",
                "FindFirstFileW", "FindNextFileW"
            };

            static constexpr const char* HUMAN_INTERACTION_APIS[] = {
                "GetCursorPos", "GetAsyncKeyState", "GetKeyState",
                "GetLastInputInfo", "GetForegroundWindow",
                "GetWindowTextW", "EnumWindows",
                "SetWindowsHookExW"
            };
        } // namespace SandboxDetectionAPIs

        // Known sandbox-related strings to scan for in target process memory
        namespace SandboxStrings {
            static const std::vector<std::wstring> SANDBOX_DLLS = {
                L"sbiedll.dll", L"api_log.dll", L"dir_watch.dll",
                L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll",
                L"SbieDll.dll", L"SxIn.dll", L"Sf2.dll",
                L"snxhk.dll", L"cmdvrt32.dll", L"cmdvrt64.dll"
            };

            static const std::vector<std::wstring> SANDBOX_PROCESSES = {
                L"vmsrvc.exe", L"vboxservice.exe", L"vboxtray.exe",
                L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
                L"wireshark.exe", L"procmon.exe", L"procmon64.exe",
                L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe",
                L"idaq.exe", L"idaq64.exe", L"pestudio.exe",
                L"regmon.exe", L"filemon.exe", L"autoruns.exe",
                L"agent.py", L"analyzer.py"
            };

            static const std::vector<std::wstring> SANDBOX_MUTEXES = {
                L"CuckooMutex", L"SbieSandbox", L"SBIE_BOXED_",
                L"JoeBoxMutex", L"Anubis_Sandbox",
                L"ThreatExpert", L"HookSwitchMutex"
            };

            static const std::vector<std::wstring> VM_VENDOR_STRINGS = {
                L"VMware", L"VirtualBox", L"QEMU", L"Xen",
                L"Virtual HD", L"VBOX HARDDISK",
                L"VMware Virtual", L"VMWARE", L"innotek GmbH",
                L"Oracle Corporation", L"Parallels"
            };

            static const std::vector<std::wstring> SANDBOX_REGISTRY_PATHS = {
                L"SOFTWARE\\Oracle\\VirtualBox",
                L"SOFTWARE\\VMware, Inc.\\VMware Tools",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
                L"SYSTEM\\CurrentControlSet\\Services\\vmci",
                L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
                L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
                L"HARDWARE\\Description\\System\\SystemBiosVersion"
            };
        } // namespace SandboxStrings

        bool SandboxEvasionDetector::AnalyzeProcess(
            HANDLE hProcess,
            uint32_t processId,
            ProcessSandboxResult& result,
            const ProcessSandboxConfig& config
        ) {
            if (!m_impl->initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SandboxEvasionDetector not initialized");
                return false;
            }

            auto startTime = std::chrono::steady_clock::now();
            result = ProcessSandboxResult{};
            result.processId = processId;

            try {
                // Get process path for PE analysis
                std::wstring processPath;
                if (!config.kernelContext.imagePath.empty()) {
                    processPath = config.kernelContext.imagePath;
                } else {
                    wchar_t pathBuf[MAX_PATH] = {};
                    DWORD pathSize = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, pathBuf, &pathSize)) {
                        processPath = pathBuf;
                    }
                }

                bool is64Bit = true;
                {
                    BOOL isWow64 = FALSE;
                    if (IsWow64Process(hProcess, &isWow64)) {
                        is64Bit = !isWow64;
                    }
                }

                // TYPE B Check 1: Import analysis
                if (config.checkImports && !processPath.empty()) {
                    CheckTargetSandboxImports(hProcess, processPath, result);
                }

                // TYPE B Check 2: Memory string scan
                if (config.checkMemoryStrings) {
                    CheckTargetSandboxStrings(hProcess, result, config.maxMemoryScanBytes);
                }

                // TYPE B Check 3: Code pattern analysis (RDTSC, CPUID, etc.)
                if (config.checkCodePatterns && !processPath.empty()) {
                    CheckTargetTimingPatterns(hProcess, processPath, is64Bit, result, config.maxCodeScanBytes);
                }

                // Calculate final score
                CalculateProcessEvasionScore(result);

                auto endTime = std::chrono::steady_clock::now();
                result.analysisDurationUs = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        endTime - startTime).count());

                // Fire callback if evasion detected
                if (result.hasEvasionCapability) {
                    std::shared_lock lock(m_impl->configMutex);
                    if (m_impl->processDetectionCallback) {
                        try {
                            m_impl->processDetectionCallback(result);
                        } catch (...) {
                            SS_LOG_ERROR(LOG_CATEGORY, L"Exception in process sandbox detection callback");
                        }
                    }
                }

                m_impl->stats.totalScans.fetch_add(1, std::memory_order_relaxed);
                if (result.hasEvasionCapability) {
                    m_impl->stats.sandboxesDetected.fetch_add(1, std::memory_order_relaxed);
                }
                // EMA of per-process analysis duration (alpha = 1/8) — see ScanSystem
                // for the matching update on full-system scans.
                {
                    uint64_t prev = m_impl->stats.avgAnalysisDurationUs.load(std::memory_order_relaxed);
                    for (;;) {
                        const uint64_t next = (prev == 0)
                            ? result.analysisDurationUs
                            : prev - (prev >> 3) + (result.analysisDurationUs >> 3);
                        if (m_impl->stats.avgAnalysisDurationUs.compare_exchange_weak(
                                prev, next, std::memory_order_relaxed)) {
                            break;
                        }
                    }
                }

                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"Process sandbox analysis PID %lu: score=%.1f evasive=%ls duration=%lluus",
                    processId, result.evasionScore,
                    result.hasEvasionCapability ? L"YES" : L"NO",
                    result.analysisDurationUs);

                return true;
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess failed for PID %lu: %hs", processId, e.what());
                return false;
            }
            catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess failed for PID %lu: unknown exception", processId);
                return false;
            }
        }

        bool SandboxEvasionDetector::AnalyzeProcess(
            uint32_t processId,
            ProcessSandboxResult& result,
            const ProcessSandboxConfig& config
        ) {
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                SS_LOG_WARN(LOG_CATEGORY, L"Cannot open process %lu for sandbox analysis: %lu",
                    processId, GetLastError());
                return false;
            }

            // RAII guard so the handle is released on every path, including any
            // future code that adds early returns. Replaces the prior dead-code
            // try/catch (CloseHandle was already unconditional after the try block).
            struct HandleGuard {
                HANDLE h;
                ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
            } guard{ hProcess };

            return AnalyzeProcess(hProcess, processId, result, config);
        }

        void SandboxEvasionDetector::SetProcessDetectionCallback(ProcessSandboxCallback callback) {
            std::unique_lock lock(m_impl->configMutex);
            m_impl->processDetectionCallback = std::move(callback);
        }

        void SandboxEvasionDetector::CheckTargetSandboxImports(
            HANDLE hProcess,
            const std::wstring& processPath,
            ProcessSandboxResult& result
        ) {
            try {
                PEParser::PEParser parser;
                PEParser::PEInfo peInfo;

                if (!parser.ParseFile(processPath, peInfo, nullptr)) {
                    return;
                }

                std::vector<PEParser::ImportInfo> imports;
                if (!parser.ParseImports(imports, nullptr)) {
                    return;
                }

                // Build a set of all imported function names for fast lookup
                std::unordered_set<std::string> importedFunctions;
                for (const auto& dll : imports) {
                    for (const auto& func : dll.functions) {
                        if (!func.byOrdinal && !func.name.empty()) {
                            importedFunctions.insert(func.name);
                        }
                    }
                }

                // Check hardware fingerprinting APIs
                for (const auto& api : SandboxDetectionAPIs::HARDWARE_APIS) {
                    if (importedFunctions.count(api)) {
                        result.imports.hardwareFingerprinting.push_back(
                            Utils::StringUtils::ToWide(api));
                    }
                }

                // Check timing APIs
                for (const auto& api : SandboxDetectionAPIs::TIMING_APIS) {
                    if (importedFunctions.count(api)) {
                        result.imports.timingAPIs.push_back(
                            Utils::StringUtils::ToWide(api));
                    }
                }

                // Check environment query APIs
                for (const auto& api : SandboxDetectionAPIs::ENVIRONMENT_APIS) {
                    if (importedFunctions.count(api)) {
                        result.imports.environmentQueries.push_back(
                            Utils::StringUtils::ToWide(api));
                    }
                }

                // Check artifact detection APIs
                for (const auto& api : SandboxDetectionAPIs::ARTIFACT_APIS) {
                    if (importedFunctions.count(api)) {
                        result.imports.artifactChecks.push_back(
                            Utils::StringUtils::ToWide(api));
                    }
                }

                // Check human interaction detection APIs
                for (const auto& api : SandboxDetectionAPIs::HUMAN_INTERACTION_APIS) {
                    if (importedFunctions.count(api)) {
                        result.imports.humanInteractionChecks.push_back(
                            Utils::StringUtils::ToWide(api));
                    }
                }

                // Score based on COMBINATION of suspicious imports
                // Individual APIs like GetTickCount are benign; it's the combination that matters
                float importScore = 0.0f;
                size_t hwCount = result.imports.hardwareFingerprinting.size();
                size_t timCount = result.imports.timingAPIs.size();
                size_t envCount = result.imports.environmentQueries.size();
                size_t artCount = result.imports.artifactChecks.size();
                size_t humCount = result.imports.humanInteractionChecks.size();

                // Hardware fingerprinting: 3+ APIs is suspicious
                if (hwCount >= 3) importScore += 15.0f;
                else if (hwCount >= 2) importScore += 5.0f;

                // Timing + hardware combination = sandbox detection pattern
                if (timCount >= 2 && hwCount >= 2) importScore += 20.0f;

                // Artifact checking APIs (GetModuleHandle + OpenMutex + process enumeration)
                if (artCount >= 4) importScore += 15.0f;
                else if (artCount >= 2) importScore += 5.0f;

                // Human interaction checking
                if (humCount >= 3) importScore += 15.0f;
                else if (humCount >= 2) importScore += 5.0f;

                // Environment fingerprinting
                if (envCount >= 3) importScore += 10.0f;

                // Cross-category combinations (strongest signal)
                size_t categoriesHit = 0;
                if (hwCount >= 2) categoriesHit++;
                if (timCount >= 2) categoriesHit++;
                if (artCount >= 2) categoriesHit++;
                if (humCount >= 2) categoriesHit++;
                if (envCount >= 2) categoriesHit++;

                if (categoriesHit >= 4) importScore += 25.0f;
                else if (categoriesHit >= 3) importScore += 15.0f;
                else if (categoriesHit >= 2) importScore += 5.0f;

                result.imports.score = std::min(importScore, 100.0f);
            }
            catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"CheckTargetSandboxImports: Exception for PID %lu", result.processId);
            }
        }

        void SandboxEvasionDetector::CheckTargetSandboxStrings(
            HANDLE hProcess,
            ProcessSandboxResult& result,
            size_t maxScanBytes
        ) {
            try {
                MEMORY_BASIC_INFORMATION mbi = {};
                uint8_t* address = nullptr;
                size_t totalScanned = 0;
                constexpr size_t SCAN_BUFFER_SIZE = 64 * 1024; // 64KB chunks
                std::vector<uint8_t> buffer(SCAN_BUFFER_SIZE);

                constexpr size_t MAX_STRING_FINDINGS = 200;

                while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (totalScanned >= maxScanBytes) break;

                    // Pointer overflow guard
                    uintptr_t nextAddr = reinterpret_cast<uintptr_t>(address) + mbi.RegionSize;
                    if (nextAddr < reinterpret_cast<uintptr_t>(address)) break;
                    address = reinterpret_cast<uint8_t*>(nextAddr);

                    // Only scan committed, readable regions
                    if (mbi.State != MEM_COMMIT) continue;
                    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;

                    // Cap per-region scan
                    size_t regionScanSize = std::min<size_t>(mbi.RegionSize, 1024 * 1024);
                    size_t offset = 0;

                    while (offset < regionScanSize) {
                        size_t chunkSize = std::min(SCAN_BUFFER_SIZE, regionScanSize - offset);
                        SIZE_T bytesRead = 0;

                        void* readAddr = reinterpret_cast<void*>(
                            reinterpret_cast<uintptr_t>(mbi.BaseAddress) + offset);

                        if (!ReadProcessMemory(hProcess, readAddr, buffer.data(), chunkSize, &bytesRead) ||
                            bytesRead == 0) {
                            break;
                        }

                        totalScanned += bytesRead;

                        // Scan for wide strings (most Windows APIs use wide strings)
                        std::wstring_view wideView(
                            reinterpret_cast<const wchar_t*>(buffer.data()),
                            bytesRead / sizeof(wchar_t));

                        // Check sandbox DLL names
                        for (const auto& dll : SandboxStrings::SANDBOX_DLLS) {
                            if (result.strings.sandboxDLLNames.size() >= MAX_STRING_FINDINGS) break;
                            if (wideView.find(dll) != std::wstring_view::npos) {
                                if (std::find(result.strings.sandboxDLLNames.begin(),
                                    result.strings.sandboxDLLNames.end(), dll) ==
                                    result.strings.sandboxDLLNames.end()) {
                                    result.strings.sandboxDLLNames.push_back(dll);
                                }
                            }
                        }

                        // Check sandbox process names
                        for (const auto& proc : SandboxStrings::SANDBOX_PROCESSES) {
                            if (result.strings.sandboxProcessNames.size() >= MAX_STRING_FINDINGS) break;
                            if (wideView.find(proc) != std::wstring_view::npos) {
                                if (std::find(result.strings.sandboxProcessNames.begin(),
                                    result.strings.sandboxProcessNames.end(), proc) ==
                                    result.strings.sandboxProcessNames.end()) {
                                    result.strings.sandboxProcessNames.push_back(proc);
                                }
                            }
                        }

                        // Check sandbox mutex names
                        for (const auto& mutex : SandboxStrings::SANDBOX_MUTEXES) {
                            if (result.strings.sandboxMutexNames.size() >= MAX_STRING_FINDINGS) break;
                            if (wideView.find(mutex) != std::wstring_view::npos) {
                                if (std::find(result.strings.sandboxMutexNames.begin(),
                                    result.strings.sandboxMutexNames.end(), mutex) ==
                                    result.strings.sandboxMutexNames.end()) {
                                    result.strings.sandboxMutexNames.push_back(mutex);
                                }
                            }
                        }

                        // Check VM vendor strings
                        for (const auto& vm : SandboxStrings::VM_VENDOR_STRINGS) {
                            if (result.strings.vmVendorStrings.size() >= MAX_STRING_FINDINGS) break;
                            if (wideView.find(vm) != std::wstring_view::npos) {
                                if (std::find(result.strings.vmVendorStrings.begin(),
                                    result.strings.vmVendorStrings.end(), vm) ==
                                    result.strings.vmVendorStrings.end()) {
                                    result.strings.vmVendorStrings.push_back(vm);
                                }
                            }
                        }

                        // Check sandbox registry paths
                        for (const auto& reg : SandboxStrings::SANDBOX_REGISTRY_PATHS) {
                            if (result.strings.sandboxRegistryPaths.size() >= MAX_STRING_FINDINGS) break;
                            if (wideView.find(reg) != std::wstring_view::npos) {
                                if (std::find(result.strings.sandboxRegistryPaths.begin(),
                                    result.strings.sandboxRegistryPaths.end(), reg) ==
                                    result.strings.sandboxRegistryPaths.end()) {
                                    result.strings.sandboxRegistryPaths.push_back(reg);
                                }
                            }
                        }

                        // Also check ANSI strings
                        std::string_view ansiView(
                            reinterpret_cast<const char*>(buffer.data()), bytesRead);

                        // Check for sandbox product names in ANSI
                        for (const auto& product : SandboxStrings::SANDBOX_PROCESSES) {
                            if (result.strings.sandboxProcessNames.size() >= MAX_STRING_FINDINGS) break;
                            std::string ansiProduct = Utils::StringUtils::ToNarrow(product);
                            if (ansiView.find(ansiProduct) != std::string_view::npos) {
                                if (std::find(result.strings.sandboxProcessNames.begin(),
                                    result.strings.sandboxProcessNames.end(), product) ==
                                    result.strings.sandboxProcessNames.end()) {
                                    result.strings.sandboxProcessNames.push_back(product);
                                }
                            }
                        }

                        offset += bytesRead;
                    }
                }

                // Score based on string findings
                float stringScore = 0.0f;
                size_t dllCount = result.strings.sandboxDLLNames.size();
                size_t procCount = result.strings.sandboxProcessNames.size();
                size_t mutexCount = result.strings.sandboxMutexNames.size();
                size_t vmCount = result.strings.vmVendorStrings.size();
                size_t regCount = result.strings.sandboxRegistryPaths.size();

                // Sandbox DLL strings are strong indicators
                if (dllCount >= 3) stringScore += 30.0f;
                else if (dllCount >= 1) stringScore += 15.0f;

                // Process name strings
                if (procCount >= 5) stringScore += 20.0f;
                else if (procCount >= 2) stringScore += 10.0f;

                // Mutex names (very specific to sandbox detection)
                if (mutexCount >= 2) stringScore += 25.0f;
                else if (mutexCount >= 1) stringScore += 15.0f;

                // VM vendor strings (moderate signal — could be legitimate VM tools)
                if (vmCount >= 3) stringScore += 10.0f;
                else if (vmCount >= 1) stringScore += 5.0f;

                // Registry paths
                if (regCount >= 3) stringScore += 15.0f;
                else if (regCount >= 1) stringScore += 8.0f;

                result.strings.score = std::min(stringScore, 100.0f);
            }
            catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"CheckTargetSandboxStrings: Exception for PID %lu", result.processId);
            }
        }

        void SandboxEvasionDetector::CheckTargetTimingPatterns(
            HANDLE hProcess,
            const std::wstring& processPath,
            bool is64Bit,
            ProcessSandboxResult& result,
            size_t maxCodeScanBytes
        ) {
            try {
                if (!m_impl->disasmInitialized) {
                    return;
                }

                PEParser::PEParser parser;
                PEParser::PEInfo peInfo;

                if (!parser.ParseFile(processPath, peInfo, nullptr)) {
                    return;
                }

                // Get target module base
                constexpr DWORD MAX_MODULES = 256;
                HMODULE hModules[MAX_MODULES] = {};
                DWORD cbNeeded = 0;

                if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL) ||
                    cbNeeded == 0) {
                    return;
                }

                HMODULE hTargetModule = nullptr;
                DWORD moduleCount = static_cast<DWORD>(
                    std::min<size_t>(cbNeeded / sizeof(HMODULE), MAX_MODULES));
                for (DWORD i = 0; i < moduleCount; ++i) {
                    wchar_t modPath[MAX_PATH] = {};
                    if (GetModuleFileNameExW(hProcess, hModules[i], modPath, MAX_PATH)) {
                        if (_wcsicmp(modPath, processPath.c_str()) == 0) {
                            hTargetModule = hModules[i];
                            break;
                        }
                    }
                }
                if (!hTargetModule) return;

                size_t totalCodeScanned = 0;

                Phantom::Disasm::Decoder* decoder = m_impl->GetDecoder(is64Bit);

                for (const auto& section : peInfo.sections) {
                    if (!section.hasCode) continue;
                    if (totalCodeScanned >= maxCodeScanBytes) break;

                    // CORRECTNESS FIX: when reading from a *loaded* image, the in-memory
                    // section is sized by virtualSize (rawSize is the on-disk size and
                    // is often smaller — sometimes 0 for .bss-style sections — which
                    // would clamp the scan and miss code that only exists at runtime).
                    size_t scanSize = std::min<size_t>(section.virtualSize, 1024 * 1024);
                    if (scanSize == 0) continue;
                    std::vector<uint8_t> codeBuffer(scanSize);
                    SIZE_T bytesRead = 0;

                    void* sectionAddr = reinterpret_cast<void*>(
                        reinterpret_cast<uintptr_t>(hTargetModule) + section.virtualAddress);

                    if (!ReadProcessMemory(hProcess, sectionAddr, codeBuffer.data(), scanSize, &bytesRead) ||
                        bytesRead == 0) {
                        continue;
                    }

                    totalCodeScanned += bytesRead;

                    // Disassemble and look for sandbox-detection instruction patterns
                    Phantom::Disasm::DecodedInstruction instruction;
                    Phantom::Disasm::DecodedOperand operands[Phantom::Disasm::MAX_OPERANDS];
                    size_t disOffset = 0;
                    bool lastWasRDTSC = false;
                    size_t instructionsSinceRDTSC = 0;

                    while (disOffset < bytesRead) {
                        if (Phantom::Disasm::IsSuccess(
                            decoder->DecodeFull(codeBuffer.data() + disOffset,
                            bytesRead - disOffset, instruction, operands))) {

                            switch (instruction.mnemonic) {
                            case Phantom::Disasm::Mnemonic::RDTSC:
                            case Phantom::Disasm::Mnemonic::RDTSCP:
                                result.codePatterns.rdtscInstructions++;
                                if (lastWasRDTSC && instructionsSinceRDTSC <= 20) {
                                    // RDTSC sandwich pattern — strong sandbox detection signal
                                    result.codePatterns.timingSandwiches++;
                                }
                                lastWasRDTSC = true;
                                instructionsSinceRDTSC = 0;
                                break;

                            case Phantom::Disasm::Mnemonic::CPUID:
                                result.codePatterns.cpuidInstructions++;
                                // CPUID near RDTSC = VM exit measurement
                                if (lastWasRDTSC && instructionsSinceRDTSC <= 10) {
                                    result.codePatterns.vmExitProbes++;
                                }
                                break;

                            case Phantom::Disasm::Mnemonic::IN_INST:
                                // IN instruction — check for VMware backdoor port 0x5658
                                if (instruction.operand_count >= 2 &&
                                    operands[1].type == Phantom::Disasm::OperandType::IMMEDIATE &&
                                    operands[1].imm.value.u == 0x5658) {
                                    result.codePatterns.portProbes++;
                                }
                                break;

                            default:
                                if (lastWasRDTSC) {
                                    instructionsSinceRDTSC++;
                                    if (instructionsSinceRDTSC > 50) {
                                        lastWasRDTSC = false;
                                    }
                                }
                                break;
                            }

                            disOffset += instruction.length;
                        } else {
                            disOffset++;
                        }
                    }
                }

                // Score based on code pattern findings
                float codeScore = 0.0f;

                // RDTSC sandwich is a very strong signal
                if (result.codePatterns.timingSandwiches >= 3) codeScore += 35.0f;
                else if (result.codePatterns.timingSandwiches >= 1) codeScore += 20.0f;

                // VM exit probes (CPUID near RDTSC)
                if (result.codePatterns.vmExitProbes >= 2) codeScore += 25.0f;
                else if (result.codePatterns.vmExitProbes >= 1) codeScore += 15.0f;

                // Port probes (VMware backdoor)
                if (result.codePatterns.portProbes >= 1) codeScore += 20.0f;

                // Excessive CPUID usage (beyond normal)
                if (result.codePatterns.cpuidInstructions >= 10) codeScore += 10.0f;

                // Many RDTSC instructions
                if (result.codePatterns.rdtscInstructions >= 20) codeScore += 10.0f;

                result.codePatterns.score = std::min(codeScore, 100.0f);
            }
            catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"CheckTargetTimingPatterns: Exception for PID %lu", result.processId);
            }
        }

        void SandboxEvasionDetector::CalculateProcessEvasionScore(ProcessSandboxResult& result) {
            // Weighted combination of all three analysis scores
            constexpr float IMPORT_WEIGHT = 0.30f;
            constexpr float STRING_WEIGHT = 0.40f;
            constexpr float CODE_WEIGHT = 0.30f;

            result.evasionScore = std::min(100.0f,
                result.imports.score * IMPORT_WEIGHT +
                result.strings.score * STRING_WEIGHT +
                result.codePatterns.score * CODE_WEIGHT);

            // Threshold for evasion capability
            constexpr float EVASION_THRESHOLD = 25.0f;
            result.hasEvasionCapability = (result.evasionScore >= EVASION_THRESHOLD);

            // Add MITRE ATT&CK mappings
            if (result.imports.score > 0 || result.strings.score > 0 || result.codePatterns.score > 0) {
                result.mitreIds.push_back("T1497");      // Virtualization/Sandbox Evasion
                result.mitreIds.push_back("T1497.001");  // System Checks
            }
            if (result.codePatterns.timingSandwiches > 0 || result.codePatterns.vmExitProbes > 0) {
                result.mitreIds.push_back("T1497.003");  // Time Based Evasion
            }
            if (!result.strings.sandboxProcessNames.empty() || !result.imports.artifactChecks.empty()) {
                result.mitreIds.push_back("T1057");      // Process Discovery
            }
            if (!result.strings.sandboxRegistryPaths.empty()) {
                result.mitreIds.push_back("T1012");      // Query Registry
            }
            if (!result.imports.humanInteractionChecks.empty()) {
                result.mitreIds.push_back("T1497.002");  // User Activity Based Checks
            }
        }

    } // namespace AntiEvasion
} // namespace ShadowStrike
