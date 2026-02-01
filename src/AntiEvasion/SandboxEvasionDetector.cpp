/**
 * @file SandboxEvasionDetector.cpp
 * @brief Enterprise-grade implementation of sandbox evasion detection.
 *
 * This module implements comprehensive detection of techniques used by malware
 * to identify and evade automated analysis sandboxes. Detection covers:
 * - Hardware fingerprinting (RAM, CPU, disk, GPU)
 * - System wear and tear analysis
 * - Human interaction verification
 * - Sandbox artifact detection (DLLs, processes, mutexes, registry)
 * - Environment analysis (screen, locale, devices)
 * - Timing-based detection
 * - Network characteristics
 *
 * @note Thread-safe implementation using shared_mutex.
 * @note Follows PIMPL pattern for ABI stability.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "SandboxEvasionDetector.hpp"
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

// Zydis Disassembler for advanced hook detection and code analysis
#include <Zydis/Zydis.h>

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
#  include<iphlpapi.h>
#  pragma comment(lib, "wbemuuid.lib")
#  pragma comment(lib, "Setupapi.lib")
#  pragma comment(lib, "iphlpapi.lib")
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
#pragma comment(linker, "/ALTERNATENAME:DetectSingleStepTiming=Fallback_DetectSingleStepTiming")
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
    uint64_t tsc = __rdtscp(&aux);
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
    if (sleepMs < 100) return 0;
    
    ULONGLONG startTicks = GetTickCount64();
    Sleep(sleepMs);
    ULONGLONG endTicks = GetTickCount64();
    
    ULONGLONG actualMs = endTicks - startTicks;
    
    // Calculate deviation percentage
    if (actualMs >= sleepMs) {
        return 0;  // No acceleration
    }
    
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

/// Fallback: DetectSingleStepTiming
uint32_t Fallback_DetectSingleStepTiming(void) {
#ifdef _WIN32
    uint64_t start = __rdtsc();
    
    // Execute known number of simple operations
    volatile int x = 0;
    for (int i = 0; i < 20; ++i) {
        x++;
    }
    
    uint64_t end = __rdtsc();
    
    // If > 1000 cycles for 20 simple increments, likely single-stepping
    return (end - start > 1000) ? 1 : 0;
#else
    return 0;
#endif
}

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
static bool g_calibrationDone_fallback = false;

void Fallback_CalibrateTimingBaseline(void) {
#ifdef _WIN32
    if (g_calibrationDone_fallback) return;
    
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
    
    g_calibrationDone_fallback = true;
#endif
}

/// Fallback: DetectTimingHook
uint32_t Fallback_DetectTimingHook(void) {
#ifdef _WIN32
    uint64_t rdtsc1 = __rdtsc();
    
    unsigned int aux;
    uint64_t rdtscp = __rdtscp(&aux);
    
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
    alignas(64) static volatile char buffer[4096];
    
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
            std::shared_ptr<Utils::ThreadPool> threadPool;

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
            // Statistics
            // -------------------------------------------------------------------------
            SandboxDetectorStats stats;

            // -------------------------------------------------------------------------
            // Zydis Disassembler Contexts
            // -------------------------------------------------------------------------
            ZydisDecoder decoder32{};
            ZydisDecoder decoder64{};
            ZydisFormatter formatter{};
            bool zydisInitialized{ false };

            // -------------------------------------------------------------------------
            // COM Initialization State
            // -------------------------------------------------------------------------
            bool comInitialized{ false };

            // -------------------------------------------------------------------------
            // Utility Methods
            // -------------------------------------------------------------------------

            void InitializeZydis() noexcept {
                if (zydisInitialized) return;

                // Initialize 64-bit decoder (primary - our target platform)
                ZydisDecoderInit(&decoder64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

                // Initialize 32-bit decoder (for analyzing 32-bit malware/WoW64 processes)
                ZydisDecoderInit(&decoder32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

                // Initialize formatter for disassembly output
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

                zydisInitialized = true;
                SS_LOG_DEBUG(LOG_CATEGORY, L"Zydis disassembler initialized");
            }

            [[nodiscard]] ZydisDecoder* GetDecoder(bool is64Bit) noexcept {
                return is64Bit ? &decoder64 : &decoder32;
            }

            [[nodiscard]] bool IsCacheValid() const noexcept {
                std::shared_lock lock(cacheMutex);
                if (!cachedResult.has_value()) return false;

                auto now = std::chrono::system_clock::now();
                auto age = std::chrono::duration_cast<std::chrono::minutes>(now - cacheTimestamp);

                std::shared_lock cfgLock(configMutex);
                return age < config.cacheTTL;
            }

            void InitializeCOM() {
#ifdef _WIN32
                if (!comInitialized) {
                    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
                        comInitialized = true;
                    }
                }
#endif
            }

            void UninitializeCOM() {
#ifdef _WIN32
                if (comInitialized) {
                    CoUninitialize();
                    comInitialized = false;
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

            m_impl->threadPool = std::move(threadPool);

            {
                std::unique_lock lock(m_impl->configMutex);
                m_impl->config = config;
            }

            // Initialize COM for WMI queries
            m_impl->InitializeCOM();

            // Initialize Zydis disassembler for advanced hook detection
            m_impl->InitializeZydis();

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
            m_impl->threadPool.reset();
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

        SandboxEvasionResult SandboxEvasionDetector::ScanSystem() {
            if (!m_impl->initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Detector not initialized");
                SandboxEvasionResult result;
                result.errorMessage = L"Detector not initialized";
                return result;
            }

            // Check cache first
            SandboxDetectorConfig currentConfig;
            {
                std::shared_lock lock(m_impl->configMutex);
                currentConfig = m_impl->config;
            }

            if (currentConfig.enableCache && m_impl->IsCacheValid()) {
                m_impl->stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                std::shared_lock lock(m_impl->cacheMutex);
                SS_LOG_DEBUG(LOG_CATEGORY, L"Returning cached result");
                return *m_impl->cachedResult;
            }

            m_impl->stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);

            // Perform full scan
            SandboxEvasionResult result;
            result.analysisStartTime = std::chrono::system_clock::now();

            SS_LOG_INFO(LOG_CATEGORY, L"Starting comprehensive sandbox detection scan");

            auto startTime = std::chrono::steady_clock::now();

            // Run all checks based on configuration
            if (currentConfig.checkHardware) {
                CheckHardwareSpecs(result);
            }

            if (currentConfig.checkTiming) {
                CheckUptime(result);
            }

            if (currentConfig.checkArtifacts) {
                CheckLoadedModules(result);
                CheckNamedObjects(result);
                CheckProcesses(result);
                CheckServices(result);
                CheckAPIHooks(result);
            }

            if (currentConfig.checkWearAndTear) {
                CheckSystemWearAndTear(result);
            }

            if (currentConfig.checkEnvironment) {
                CheckScreenResolution(result);
                CheckRegistry(result);
            }

            if (currentConfig.checkFileSystem) {
                CheckFileSystem(result);
            }

            if (currentConfig.checkNetwork) {
                CheckNetworkCharacteristics(result);
            }

            // Human interaction check is optional and blocking
            if (currentConfig.checkHumanInteraction) {
                auto interactionAnalysis = AnalyzeHumanInteraction(currentConfig.humanInteractionMonitorMs);
                result.humanInteraction = interactionAnalysis;
                result.humanInteractionScore = interactionAnalysis.humanConfidence;
            }

            // Calculate final probability and identify sandbox
            CalculateProbability(result);
            IdentifySandboxProduct(result);
            AddMitreMappings(result);

            auto endTime = std::chrono::steady_clock::now();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - startTime).count();
            result.analysisComplete = true;

            // Update statistics
            m_impl->stats.totalScans.fetch_add(1, std::memory_order_relaxed);
            if (result.isSandboxLikely) {
                m_impl->stats.sandboxesDetected.fetch_add(1, std::memory_order_relaxed);
                if (result.isDefinitive) {
                    m_impl->stats.definitiveDetections.fetch_add(1, std::memory_order_relaxed);
                }
                if (result.identifiedSandbox != SandboxProduct::Unknown) {
                    size_t productIndex = static_cast<size_t>(result.identifiedSandbox);
                    if (productIndex < 256) {
                        m_impl->stats.detectionsByProduct[productIndex].fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // Update cache
            UpdateCache(result);

            // Invoke callbacks
            InvokeCallbacks(result);

            SS_LOG_INFO(LOG_CATEGORY,
                L"Sandbox scan complete: Probability=%.1f%%, IsSandbox=%ls, Duration=%llums",
                result.probability,
                result.isSandboxLikely ? L"true" : L"false",
                result.analysisDurationMs);

            return result;
        }

        bool SandboxEvasionDetector::ScanSystemAsync(std::function<void(SandboxEvasionResult)> callback) {
            if (!m_impl->initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Detector not initialized");
                return false;
            }

            if (!m_impl->threadPool) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ThreadPool not available");
                return false;
            }

            // Capture callback and queue async scan
            m_impl->threadPool->Enqueue([this, cb = std::move(callback)]() {
                auto result = ScanSystem();
                if (cb) {
                    cb(std::move(result));
                }
            });

            SS_LOG_DEBUG(LOG_CATEGORY, L"Async sandbox scan queued");
            return true;
        }

        bool SandboxEvasionDetector::QuickScan() {
            if (!m_impl->initialized.load(std::memory_order_acquire)) {
                return false;
            }

            SS_LOG_DEBUG(LOG_CATEGORY, L"Performing quick sandbox scan");

            // Quick checks - only the most reliable indicators
            // 1. Check for sandbox DLLs
            if (IsSandboxDLLLoaded(KnownSandboxDLLs::SBIEDLL) ||
                IsSandboxDLLLoaded(KnownSandboxDLLs::CUCKOOMON) ||
                IsSandboxDLLLoaded(KnownSandboxDLLs::SNXHK) ||
                IsSandboxDLLLoaded(KnownSandboxDLLs::VMRAY) ||
                IsSandboxDLLLoaded(KnownSandboxDLLs::JOEBOX)) {
                SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Sandbox DLL detected");
                return true;
            }

            // 2. Check for sandbox mutexes
            if (DoesMutexExist(KnownSandboxMutexes::SANDBOXIE) ||
                DoesMutexExist(KnownSandboxMutexes::CUCKOO) ||
                DoesMutexExist(KnownSandboxMutexes::JOEBOX) ||
                DoesMutexExist(KnownSandboxMutexes::VMRAY)) {
                SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Sandbox mutex detected");
                return true;
            }

            // 3. Check for sandbox processes
            if (IsSandboxProcessRunning(KnownSandboxProcesses::SANDBOXIE_CONTROL) ||
                IsSandboxProcessRunning(KnownSandboxProcesses::JOEBOX_SERVER) ||
                IsSandboxProcessRunning(KnownSandboxProcesses::WINDOWS_SANDBOX)) {
                SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Sandbox process detected");
                return true;
            }

            // 4. Quick hardware check
#ifdef _WIN32
            MEMORYSTATUSEX memStatus{};
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                if (memStatus.ullTotalPhys < SandboxConstants::SUSPICIOUS_RAM_BYTES) {
                    SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Suspicious RAM size detected");
                    return true;
                }
            }

            SYSTEM_INFO sysInfo{};
            GetSystemInfo(&sysInfo);
            if (sysInfo.dwNumberOfProcessors <= SandboxConstants::SUSPICIOUS_CPU_CORES) {
                SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Suspicious CPU core count detected");
                return true;
            }

            // 5. Quick uptime check
            uint64_t uptime = GetSystemUptime();
            if (uptime < SandboxConstants::VERY_SUSPICIOUS_UPTIME_MS) {
                SS_LOG_INFO(LOG_CATEGORY, L"Quick scan: Very short uptime detected");
                return true;
            }
#endif

            SS_LOG_DEBUG(LOG_CATEGORY, L"Quick scan: No sandbox indicators detected");
            return false;
        }

        // ============================================================================
        // INDIVIDUAL ANALYSIS METHODS
        // ============================================================================

        HardwareProfile SandboxEvasionDetector::AnalyzeHardware() {
            HardwareProfile profile;

#ifdef _WIN32
            // -------------------------------------------------------------------------
            // Memory Information
            // -------------------------------------------------------------------------
            MEMORYSTATUSEX memStatus{};
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                profile.totalRAM = memStatus.ullTotalPhys;
                profile.availableRAM = memStatus.ullAvailPhys;
                profile.virtualMemoryLimit = memStatus.ullTotalVirtual;
            }

            // -------------------------------------------------------------------------
            // CPU Information
            // -------------------------------------------------------------------------
            SYSTEM_INFO sysInfo{};
            GetSystemInfo(&sysInfo);
            profile.logicalProcessors = sysInfo.dwNumberOfProcessors;

            // Get physical core count via GetLogicalProcessorInformation
            DWORD bufferLen = 0;
            GetLogicalProcessorInformation(nullptr, &bufferLen);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufferLen > 0) {
                std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> buffer(
                    bufferLen / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                if (GetLogicalProcessorInformation(buffer.data(), &bufferLen)) {
                    uint32_t physicalCores = 0;
                    for (const auto& info : buffer) {
                        if (info.Relationship == RelationProcessorCore) {
                            ++physicalCores;
                        }
                    }
                    profile.physicalCores = physicalCores;
                }
            }

            // CPU model string via CPUID
            std::array<int, 4> cpuInfo{};
            char cpuBrand[49] = {};
            __cpuid(cpuInfo.data(), 0x80000000);
            if (static_cast<unsigned int>(cpuInfo[0]) >= 0x80000004) {
                __cpuid(reinterpret_cast<int*>(cpuBrand), 0x80000002);
                __cpuid(reinterpret_cast<int*>(cpuBrand + 16), 0x80000003);
                __cpuid(reinterpret_cast<int*>(cpuBrand + 32), 0x80000004);
                profile.cpuModel = Utils::StringUtils::ToWide(cpuBrand);
            }

            // CPU vendor
            __cpuid(cpuInfo.data(), 0);
            char vendor[13] = {};
            *reinterpret_cast<int*>(vendor) = cpuInfo[1];
            *reinterpret_cast<int*>(vendor + 4) = cpuInfo[3];
            *reinterpret_cast<int*>(vendor + 8) = cpuInfo[2];
            profile.cpuVendor = Utils::StringUtils::ToWide(vendor);

            // -------------------------------------------------------------------------
            // Storage Information
            // -------------------------------------------------------------------------
            wchar_t systemDrive[MAX_PATH];
            if (GetWindowsDirectoryW(systemDrive, MAX_PATH)) {
                systemDrive[3] = L'\0';  // "C:\"
                ULARGE_INTEGER freeBytesAvailable{}, totalBytes{}, freeBytes{};
                if (GetDiskFreeSpaceExW(systemDrive, &freeBytesAvailable, &totalBytes, &freeBytes)) {
                    profile.totalDiskSpace = totalBytes.QuadPart;
                    profile.freeDiskSpace = freeBytes.QuadPart;
                }
            }

            // Disk count via DeviceIoControl (simplified)
            profile.diskCount = 1;  // Assume at least one

            // -------------------------------------------------------------------------
            // Graphics Information
            // -------------------------------------------------------------------------
            DISPLAY_DEVICEW displayDevice{};
            displayDevice.cb = sizeof(displayDevice);
            if (EnumDisplayDevicesW(nullptr, 0, &displayDevice, 0)) {
                profile.gpuPresent = true;
                profile.gpuModel = displayDevice.DeviceString;
            }

            // -------------------------------------------------------------------------
            // Network Adapters
            // -------------------------------------------------------------------------
            ULONG adaptersSize = 0;
            GetAdaptersInfo(nullptr, &adaptersSize);
            if (adaptersSize > 0) {
                std::vector<uint8_t> buffer(adaptersSize);
                PIP_ADAPTER_INFO adapters = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
                if (GetAdaptersInfo(adapters, &adaptersSize) == ERROR_SUCCESS) {
                    uint32_t adapterCount = 0;
                    for (PIP_ADAPTER_INFO adapter = adapters; adapter; adapter = adapter->Next) {
                        ++adapterCount;
                        if (adapter->Type == MIB_IF_TYPE_ETHERNET) {
                            profile.physicalNICPresent = true;
                        }
                        if (adapter->Type == IF_TYPE_IEEE80211) {
                            profile.wifiPresent = true;
                        }
                    }
                    profile.networkAdapterCount = adapterCount;
                }
            }

            // -------------------------------------------------------------------------
            // USB Device History (from registry)
            // -------------------------------------------------------------------------
            HKEY usbKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                0, KEY_READ, &usbKey) == ERROR_SUCCESS) {
                DWORD subkeyCount = 0;
                RegQueryInfoKeyW(usbKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                profile.usbHistoryCount = subkeyCount;
                RegCloseKey(usbKey);
            }

            // -------------------------------------------------------------------------
            // BIOS Information (from registry)
            // -------------------------------------------------------------------------
            HKEY biosKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                0, KEY_READ, &biosKey) == ERROR_SUCCESS) {

                wchar_t valueBuffer[256];
                DWORD bufferSize = sizeof(valueBuffer);
                DWORD valueType;

                if (RegQueryValueExW(biosKey, L"SystemManufacturer", nullptr, &valueType,
                    reinterpret_cast<LPBYTE>(valueBuffer), &bufferSize) == ERROR_SUCCESS) {
                    profile.systemManufacturer = valueBuffer;
                }

                bufferSize = sizeof(valueBuffer);
                if (RegQueryValueExW(biosKey, L"SystemProductName", nullptr, &valueType,
                    reinterpret_cast<LPBYTE>(valueBuffer), &bufferSize) == ERROR_SUCCESS) {
                    profile.systemModel = valueBuffer;
                }

                bufferSize = sizeof(valueBuffer);
                if (RegQueryValueExW(biosKey, L"BIOSVendor", nullptr, &valueType,
                    reinterpret_cast<LPBYTE>(valueBuffer), &bufferSize) == ERROR_SUCCESS) {
                    profile.biosVendor = valueBuffer;
                }

                bufferSize = sizeof(valueBuffer);
                if (RegQueryValueExW(biosKey, L"BIOSVersion", nullptr, &valueType,
                    reinterpret_cast<LPBYTE>(valueBuffer), &bufferSize) == ERROR_SUCCESS) {
                    profile.biosVersion = valueBuffer;
                }

                RegCloseKey(biosKey);
            }

            // -------------------------------------------------------------------------
            // Audio Device Detection
            // -------------------------------------------------------------------------
            UINT waveOutDevs = waveOutGetNumDevs();
            profile.audioDevicePresent = (waveOutDevs > 0);

            // -------------------------------------------------------------------------
            // Calculate Suspicion Score
            // -------------------------------------------------------------------------
            float suspicionScore = 0.0f;

            if (profile.totalRAM < SandboxConstants::MIN_RAM_BYTES) {
                suspicionScore += 15.0f;
                profile.issues.push_back(L"Low RAM: " + std::to_wstring(profile.totalRAM / (1024 * 1024)) + L" MB");
            }
            if (profile.totalRAM < SandboxConstants::SUSPICIOUS_RAM_BYTES) {
                suspicionScore += 10.0f;
            }

            if (profile.logicalProcessors <= SandboxConstants::SUSPICIOUS_CPU_CORES) {
                suspicionScore += 15.0f;
                profile.issues.push_back(L"Low CPU cores: " + std::to_wstring(profile.logicalProcessors));
            }

            if (profile.totalDiskSpace < SandboxConstants::MIN_DISK_BYTES) {
                suspicionScore += 10.0f;
                profile.issues.push_back(L"Small disk: " + std::to_wstring(profile.totalDiskSpace / (1024 * 1024 * 1024)) + L" GB");
            }

            if (profile.usbHistoryCount < 3) {
                suspicionScore += 10.0f;
                profile.issues.push_back(L"Few USB devices in history: " + std::to_wstring(profile.usbHistoryCount));
            }

            if (!profile.audioDevicePresent) {
                suspicionScore += 5.0f;
                profile.issues.push_back(L"No audio device detected");
            }

            // Check BIOS strings for VM indicators
            // FIX (Issue #2): Reduced suspicion score for generic VMs, high score only for definitive sandboxes
            std::wstring biosCombo = profile.biosVendor + L" " + profile.systemManufacturer + L" " + profile.systemModel;
            std::transform(biosCombo.begin(), biosCombo.end(), biosCombo.begin(), ::towupper);
            
            // First check for DEFINITIVE sandbox strings (high confidence)
            bool definiteSandboxFound = false;
            for (const auto& sandboxStr : DEFINITIVE_SANDBOX_STRINGS) {
                if (biosCombo.find(sandboxStr) != std::wstring::npos) {
                    suspicionScore += 40.0f;  // High confidence - definitive sandbox
                    profile.issues.push_back(L"Known sandbox environment detected: " + std::wstring(sandboxStr));
                    definiteSandboxFound = true;
                    break;
                }
            }

            // Only check generic VM strings if no definitive sandbox found
            if (!definiteSandboxFound) {
                for (const auto& vmStr : VM_BIOS_STRINGS) {
                    if (biosCombo.find(vmStr) != std::wstring::npos) {
                        // Lower score for generic VM detection - VMs are common in enterprise
                        suspicionScore += 10.0f;  // Reduced from 20.0f
                        profile.issues.push_back(L"VM BIOS string detected: " + std::wstring(vmStr));
                        break;
                    }
                }
            }

            profile.suspicionScore = std::min(100.0f, suspicionScore);
            profile.isSandboxLike = (suspicionScore >= 50.0f);  // Raised threshold from 40.0f
#endif

            // Cache the hardware profile
            {
                std::unique_lock lock(m_impl->hardwareProfileMutex);
                m_impl->cachedHardwareProfile = profile;
                m_impl->hardwareProfileTimestamp = std::chrono::system_clock::now();
            }

            return profile;
        }

        WearAndTearAnalysis SandboxEvasionDetector::AnalyzeWearAndTear() {
            WearAndTearAnalysis analysis;

#ifdef _WIN32
            // -------------------------------------------------------------------------
            // Recent Documents
            // -------------------------------------------------------------------------
            wchar_t recentPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, 0, recentPath))) {
                analysis.recentDocumentsCount = Utils::FileUtils::CountFilesInDirectory(recentPath);
            }

            // -------------------------------------------------------------------------
            // Desktop Files
            // -------------------------------------------------------------------------
            wchar_t desktopPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktopPath))) {
                analysis.desktopFileCount = Utils::FileUtils::CountFilesInDirectory(desktopPath);
            }

            // -------------------------------------------------------------------------
            // Downloads Folder
            // -------------------------------------------------------------------------
            wchar_t profilePath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profilePath))) {
                std::wstring downloadsPath = std::wstring(profilePath) + L"\\Downloads";
                analysis.downloadsFileCount = Utils::FileUtils::CountFilesInDirectory(downloadsPath);
            }

            // -------------------------------------------------------------------------
            // Documents Folder
            // -------------------------------------------------------------------------
            wchar_t documentsPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath))) {
                analysis.documentsFileCount = Utils::FileUtils::CountFilesInDirectory(documentsPath);
            }

            // -------------------------------------------------------------------------
            // Pictures Folder
            // -------------------------------------------------------------------------
            wchar_t picturesPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_MYPICTURES, nullptr, 0, picturesPath))) {
                analysis.picturesFileCount = Utils::FileUtils::CountFilesInDirectory(picturesPath);
            }

            // -------------------------------------------------------------------------
            // Installed Programs (from registry)
            // -------------------------------------------------------------------------
            HKEY uninstallKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0, KEY_READ, &uninstallKey) == ERROR_SUCCESS) {
                DWORD subkeyCount = 0;
                RegQueryInfoKeyW(uninstallKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                analysis.installedProgramCount = subkeyCount;
                RegCloseKey(uninstallKey);
            }

            // Also check Wow6432Node for 32-bit apps on 64-bit systems
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0, KEY_READ, &uninstallKey) == ERROR_SUCCESS) {
                DWORD subkeyCount = 0;
                RegQueryInfoKeyW(uninstallKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                analysis.installedProgramCount += subkeyCount;
                RegCloseKey(uninstallKey);
            }

            // -------------------------------------------------------------------------
            // Prefetch Files
            // -------------------------------------------------------------------------
            wchar_t windowsPath[MAX_PATH];
            if (GetWindowsDirectoryW(windowsPath, MAX_PATH)) {
                std::wstring prefetchPath = std::wstring(windowsPath) + L"\\Prefetch";
                analysis.prefetchFileCount = Utils::FileUtils::CountFilesInDirectory(prefetchPath);
            }

            // -------------------------------------------------------------------------
            // Temp Files
            // -------------------------------------------------------------------------
            wchar_t tempPath[MAX_PATH];
            if (GetTempPathW(MAX_PATH, tempPath)) {
                analysis.tempFileCount = Utils::FileUtils::CountFilesInDirectory(tempPath);
            }

            // -------------------------------------------------------------------------
            // User Profile Count
            // -------------------------------------------------------------------------
            HKEY profileListKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                0, KEY_READ, &profileListKey) == ERROR_SUCCESS) {
                DWORD subkeyCount = 0;
                RegQueryInfoKeyW(profileListKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                // Subtract system profiles (typically 3-4: LocalService, NetworkService, etc.)
                analysis.userProfileCount = (subkeyCount > 4) ? (subkeyCount - 4) : 1;
                RegCloseKey(profileListKey);
            }

            // -------------------------------------------------------------------------
            // Font Count
            // -------------------------------------------------------------------------
            wchar_t fontsPath[MAX_PATH];
            if (GetWindowsDirectoryW(fontsPath, MAX_PATH)) {
                wcscat_s(fontsPath, L"\\Fonts");
                analysis.fontCount = Utils::FileUtils::CountFilesInDirectory(fontsPath);
            }

            // -------------------------------------------------------------------------
            // Custom Wallpaper Check
            // -------------------------------------------------------------------------
            wchar_t wallpaperPath[MAX_PATH] = {};
            SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, wallpaperPath, 0);
            analysis.customWallpaper = (wcslen(wallpaperPath) > 0);

            // -------------------------------------------------------------------------
            // Calculate Usage Score
            // -------------------------------------------------------------------------
            float usageScore = 0.0f;

            // Recent documents contribution
            if (analysis.recentDocumentsCount >= 50) usageScore += 15.0f;
            else if (analysis.recentDocumentsCount >= 20) usageScore += 10.0f;
            else if (analysis.recentDocumentsCount >= 5) usageScore += 5.0f;

            // Desktop files contribution
            if (analysis.desktopFileCount >= 20) usageScore += 10.0f;
            else if (analysis.desktopFileCount >= 5) usageScore += 5.0f;

            // Installed programs contribution
            if (analysis.installedProgramCount >= 50) usageScore += 20.0f;
            else if (analysis.installedProgramCount >= 30) usageScore += 15.0f;
            else if (analysis.installedProgramCount >= 15) usageScore += 10.0f;

            // Prefetch files contribution
            if (analysis.prefetchFileCount >= 100) usageScore += 15.0f;
            else if (analysis.prefetchFileCount >= 50) usageScore += 10.0f;
            else if (analysis.prefetchFileCount >= 20) usageScore += 5.0f;

            // Temp files contribution
            if (analysis.tempFileCount >= 500) usageScore += 10.0f;
            else if (analysis.tempFileCount >= 100) usageScore += 5.0f;

            // Fonts contribution
            if (analysis.fontCount >= 300) usageScore += 10.0f;
            else if (analysis.fontCount >= 200) usageScore += 5.0f;

            // Wallpaper contribution
            if (analysis.customWallpaper) usageScore += 5.0f;

            // User profiles contribution
            if (analysis.userProfileCount >= 3) usageScore += 10.0f;
            else if (analysis.userProfileCount >= 2) usageScore += 5.0f;

            analysis.usageScore = std::min(100.0f, usageScore);
            analysis.appearsFresh = (usageScore < 30.0f);

            // Generate issues
            if (analysis.recentDocumentsCount < SandboxConstants::MIN_RECENT_DOCUMENTS) {
                analysis.issues.push_back(L"Few recent documents: " + std::to_wstring(analysis.recentDocumentsCount));
            }
            if (analysis.desktopFileCount < SandboxConstants::MIN_DESKTOP_FILES) {
                analysis.issues.push_back(L"Empty desktop");
            }
            if (analysis.installedProgramCount < SandboxConstants::MIN_INSTALLED_PROGRAMS) {
                analysis.issues.push_back(L"Few installed programs: " + std::to_wstring(analysis.installedProgramCount));
            }
            if (analysis.prefetchFileCount < 20) {
                analysis.issues.push_back(L"Few prefetch files: " + std::to_wstring(analysis.prefetchFileCount));
            }
#endif

            return analysis;
        }

        EnvironmentAnalysis SandboxEvasionDetector::AnalyzeEnvironment() {
            EnvironmentAnalysis analysis;

#ifdef _WIN32
            // -------------------------------------------------------------------------
            // Screen Resolution
            // -------------------------------------------------------------------------
            auto [width, height] = GetScreenResolution();
            analysis.screenWidth = width;
            analysis.screenHeight = height;

            // Check for typical sandbox resolutions
            if ((width == 800 && height == 600) ||
                (width == 1024 && height == 768) ||
                (width == 1280 && height == 720)) {
                analysis.isVMResolution = true;
            }

            // -------------------------------------------------------------------------
            // Color Depth
            // -------------------------------------------------------------------------
            HDC hdc = GetDC(nullptr);
            if (hdc) {
                analysis.colorDepth = GetDeviceCaps(hdc, BITSPIXEL);
                ReleaseDC(nullptr, hdc);
            }

            // -------------------------------------------------------------------------
            // Monitor Count
            // -------------------------------------------------------------------------
            analysis.monitorCount = GetSystemMetrics(SM_CMONITORS);

            // -------------------------------------------------------------------------
            // DPI
            // -------------------------------------------------------------------------
            analysis.dpi = GetDeviceCaps(GetDC(nullptr), LOGPIXELSX);

            // -------------------------------------------------------------------------
            // Timezone
            // -------------------------------------------------------------------------
            TIME_ZONE_INFORMATION tzInfo{};
            GetTimeZoneInformation(&tzInfo);
            analysis.timezone = tzInfo.StandardName;

            // -------------------------------------------------------------------------
            // Locale
            // -------------------------------------------------------------------------
            wchar_t localeName[LOCALE_NAME_MAX_LENGTH];
            if (GetUserDefaultLocaleName(localeName, LOCALE_NAME_MAX_LENGTH)) {
                analysis.locale = localeName;
            }

            // -------------------------------------------------------------------------
            // Keyboard Layout
            // -------------------------------------------------------------------------
            HKL keyboardLayout = GetKeyboardLayout(0);
            wchar_t layoutName[KL_NAMELENGTH];
            if (GetKeyboardLayoutNameW(layoutName)) {
                analysis.keyboardLayout = layoutName;
            }

            // -------------------------------------------------------------------------
            // Computer Name
            // -------------------------------------------------------------------------
            wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
            if (GetComputerNameW(computerName, &size)) {
                analysis.computerName = computerName;
            }

            // -------------------------------------------------------------------------
            // Username
            // -------------------------------------------------------------------------
            wchar_t userName[UNLEN + 1];
            size = UNLEN + 1;
            if (GetUserNameW(userName, &size)) {
                analysis.userName = userName;
            }

            // -------------------------------------------------------------------------
            // Windows Version
            // -------------------------------------------------------------------------
            HKEY ntKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0, KEY_READ, &ntKey) == ERROR_SUCCESS) {

                // RAII guard for registry key
                auto regGuard = [](HKEY k) { if (k) RegCloseKey(k); };
                std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(regGuard)> keyGuard(ntKey, regGuard);

                wchar_t productName[256] = {};
                DWORD bufferSize = sizeof(productName);
                if (RegQueryValueExW(ntKey, L"ProductName", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(productName), &bufferSize) == ERROR_SUCCESS) {
                    // Ensure null-termination for safety
                    productName[255] = L'\0';
                    analysis.windowsVersion = productName;
                }

                // CRITICAL FIX (Issue #1): Buffer overflow vulnerability
                // Previous code: bufferSize = sizeof(buildNumber) (4 bytes) but wrote to buildStr[32]
                // Fixed: Use correct buffer size for the string buffer
                wchar_t buildStr[32] = {};
                bufferSize = sizeof(buildStr);  // Correct: 64 bytes (32 * sizeof(wchar_t))
                if (RegQueryValueExW(ntKey, L"CurrentBuildNumber", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(buildStr), &bufferSize) == ERROR_SUCCESS) {
                    // Ensure null-termination for safety
                    buildStr[31] = L'\0';
                    analysis.windowsBuild = static_cast<uint32_t>(_wtoi(buildStr));
                }

                // Key automatically closed by RAII guard
            }

            // -------------------------------------------------------------------------
            // Calculate Suspicion Score
            // -------------------------------------------------------------------------
            float suspicionScore = 0.0f;

            if (analysis.isVMResolution) {
                suspicionScore += 15.0f;
                analysis.issues.push_back(L"Typical VM/sandbox resolution: " +
                    std::to_wstring(width) + L"x" + std::to_wstring(height));
            }

            if (analysis.colorDepth < SandboxConstants::MIN_COLOR_DEPTH) {
                suspicionScore += 10.0f;
                analysis.issues.push_back(L"Low color depth: " + std::to_wstring(analysis.colorDepth) + L" bits");
            }

            if (analysis.monitorCount == 0) {
                suspicionScore += 20.0f;
                analysis.issues.push_back(L"No monitors detected");
            }

            // Check for suspicious usernames
            std::wstring lowerUsername = analysis.userName;
            std::transform(lowerUsername.begin(), lowerUsername.end(), lowerUsername.begin(), ::towlower);
            for (const auto& suspiciousName : SANDBOX_USERNAMES) {
                if (lowerUsername == suspiciousName) {
                    suspicionScore += 25.0f;
                    analysis.issues.push_back(L"Suspicious username: " + analysis.userName);
                    break;
                }
            }

            // Check for suspicious computer names
            std::wstring upperComputerName = analysis.computerName;
            std::transform(upperComputerName.begin(), upperComputerName.end(), upperComputerName.begin(), ::towupper);
            for (const auto& suspiciousName : SANDBOX_COMPUTERNAMES) {
                if (upperComputerName.find(suspiciousName) != std::wstring::npos) {
                    suspicionScore += 20.0f;
                    analysis.issues.push_back(L"Suspicious computer name: " + analysis.computerName);
                    break;
                }
            }

            analysis.suspicionScore = std::min(100.0f, suspicionScore);
#endif

            return analysis;
        }

        ArtifactAnalysis SandboxEvasionDetector::ScanArtifacts() {
            ArtifactAnalysis analysis;

#ifdef _WIN32
            // -------------------------------------------------------------------------
            // Check for Sandbox DLLs
            // -------------------------------------------------------------------------
            const std::wstring_view sandboxDLLs[] = {
                KnownSandboxDLLs::SBIEDLL,
                KnownSandboxDLLs::CUCKOOMON,
                KnownSandboxDLLs::SNXHK,
                KnownSandboxDLLs::VMRAY,
                KnownSandboxDLLs::JOEBOX,
                KnownSandboxDLLs::APIMON,
                KnownSandboxDLLs::GUARD32,
                KnownSandboxDLLs::GUARD64,
                KnownSandboxDLLs::WPEPRO,
                L"cmdvrt32.dll",     // Comodo
                L"cmdvrt64.dll",     // Comodo
                L"pstorec.dll",      // SunBelt Sandbox
                L"dir_watch.dll",    // Unknown sandbox
                L"wpespy.dll",       // WPE Pro
                L"dbghelp.dll",      // Common in analysis
            };

            for (const auto& dll : sandboxDLLs) {
                if (GetModuleHandleW(dll.data()) != nullptr) {
                    analysis.sandboxDLLs.push_back(std::wstring(dll));
                    ++analysis.suspiciousDLLCount;

                    // Identify specific products
                    if (dll == KnownSandboxDLLs::SBIEDLL) {
                        analysis.identifiedProducts.push_back(SandboxProduct::Sandboxie);
                    }
                    else if (dll == KnownSandboxDLLs::CUCKOOMON) {
                        analysis.identifiedProducts.push_back(SandboxProduct::Cuckoo);
                    }
                    else if (dll == KnownSandboxDLLs::SNXHK) {
                        analysis.identifiedProducts.push_back(SandboxProduct::AvastDeepScreen);
                    }
                    else if (dll == KnownSandboxDLLs::VMRAY) {
                        analysis.identifiedProducts.push_back(SandboxProduct::VMRay);
                    }
                    else if (dll == KnownSandboxDLLs::JOEBOX) {
                        analysis.identifiedProducts.push_back(SandboxProduct::JoeSandbox);
                    }
                }
            }

            // -------------------------------------------------------------------------
            // Check for Sandbox Processes
            // -------------------------------------------------------------------------
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);

                const std::wstring_view sandboxProcesses[] = {
                    KnownSandboxProcesses::JOEBOX_SERVER,
                    KnownSandboxProcesses::JOEBOX_CONTROL,
                    KnownSandboxProcesses::SANDBOXIE_CONTROL,
                    KnownSandboxProcesses::SANDBOXIE_SVC,
                    KnownSandboxProcesses::VMRAY_SVC,
                    KnownSandboxProcesses::WINDOWS_SANDBOX,
                    KnownSandboxProcesses::WIRESHARK,
                    KnownSandboxProcesses::PROCMON,
                    KnownSandboxProcesses::PROCMON64,
                    KnownSandboxProcesses::FIDDLER,
                    KnownSandboxProcesses::OLLYDBG,
                    KnownSandboxProcesses::X64DBG,
                    KnownSandboxProcesses::X32DBG,
                    KnownSandboxProcesses::IDA,
                    KnownSandboxProcesses::IDA64,
                    L"regmon.exe",
                    L"filemon.exe",
                    L"autoruns.exe",
                    L"tcpview.exe",
                    L"idaq.exe",
                    L"idaq64.exe",
                    L"immunitydebugger.exe",
                    L"windbg.exe",
                    L"dumpcap.exe",
                    L"hookexplorer.exe",
                    L"importrec.exe",
                    L"petools.exe",
                    L"lordpe.exe",
                    L"sysinspector.exe",
                    L"proc_analyzer.exe",
                    L"sysanalyzer.exe",
                    L"sniff_hit.exe",
                    L"joeboxserver.exe",
                    L"joeboxcontrol.exe",
                    L"ResourceHacker.exe",
                };

                if (Process32FirstW(snapshot, &pe)) {
                    do {
                        std::wstring processName = pe.szExeFile;
                        std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

                        for (const auto& sandboxProc : sandboxProcesses) {
                            std::wstring lowerSandboxProc(sandboxProc);
                            std::transform(lowerSandboxProc.begin(), lowerSandboxProc.end(), lowerSandboxProc.begin(), ::towlower);

                            if (processName == lowerSandboxProc) {
                                if (sandboxProc == KnownSandboxProcesses::WIRESHARK ||
                                    sandboxProc == KnownSandboxProcesses::PROCMON ||
                                    sandboxProc == KnownSandboxProcesses::PROCMON64 ||
                                    sandboxProc == KnownSandboxProcesses::FIDDLER ||
                                    sandboxProc == KnownSandboxProcesses::OLLYDBG ||
                                    sandboxProc == KnownSandboxProcesses::X64DBG ||
                                    sandboxProc == KnownSandboxProcesses::X32DBG ||
                                    sandboxProc == KnownSandboxProcesses::IDA ||
                                    sandboxProc == KnownSandboxProcesses::IDA64) {
                                    analysis.analysisToolProcesses.push_back(pe.szExeFile);
                                }
                                else {
                                    analysis.sandboxProcesses.push_back(pe.szExeFile);
                                }
                                ++analysis.suspiciousProcessCount;
                            }
                        }
                    } while (Process32NextW(snapshot, &pe));
                }
                CloseHandle(snapshot);
            }

            // -------------------------------------------------------------------------
            // Check for Sandbox Mutexes
            // -------------------------------------------------------------------------
            const std::wstring_view sandboxMutexes[] = {
                KnownSandboxMutexes::SANDBOXIE,
                KnownSandboxMutexes::CUCKOO,
                KnownSandboxMutexes::JOEBOX,
                KnownSandboxMutexes::VMRAY,
                L"Frz_State",           // Deep Freeze
                L"SBIE_BOXED_ServiceInitComplete_Mutex",  // Sandboxie
            };

            for (const auto& mutex : sandboxMutexes) {
                if (DoesMutexExist(mutex)) {
                    analysis.sandboxMutexes.push_back(std::wstring(mutex));
                }
            }

            // -------------------------------------------------------------------------
            // Check for Sandbox Registry Keys
            // -------------------------------------------------------------------------
            const std::pair<HKEY, std::wstring_view> sandboxRegistryKeys[] = {
                {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"},
                {HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools"},
                {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmci"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmmouse"},
                {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk"},
                {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wine"},
                {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Cuckoo"},
                {HKEY_CURRENT_USER, L"SOFTWARE\\Cuckoo"},
            };

            for (const auto& [hive, keyPath] : sandboxRegistryKeys) {
                HKEY hKey;
                if (RegOpenKeyExW(hive, keyPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    analysis.sandboxRegistryKeys.push_back(std::wstring(keyPath));
                    ++analysis.suspiciousRegistryCount;
                    RegCloseKey(hKey);
                }
            }

            // -------------------------------------------------------------------------
            // Check for Sandbox Files
            // -------------------------------------------------------------------------
            const std::wstring sandboxFiles[] = {
                L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
                L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
                L"C:\\Windows\\System32\\vboxdisp.dll",
                L"C:\\Windows\\System32\\vboxhook.dll",
                L"C:\\Windows\\System32\\vboxogl.dll",
                L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
                L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
                L"C:\\agent\\agent.py",            // Cuckoo
                L"C:\\cuckoo\\agent\\agent.py",    // Cuckoo
                L"C:\\sandbox\\starter.exe",
                L"C:\\analysis\\analyzer.py",
            };

            for (const auto& filePath : sandboxFiles) {
                if (GetFileAttributesW(filePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    analysis.sandboxFiles.push_back(filePath);
                }
            }

            // -------------------------------------------------------------------------
            // Calculate Results
            // -------------------------------------------------------------------------
            analysis.totalArtifactsFound = analysis.sandboxDLLs.size() +
                analysis.sandboxProcesses.size() +
                analysis.analysisToolProcesses.size() +
                analysis.sandboxMutexes.size() +
                analysis.sandboxRegistryKeys.size() +
                analysis.sandboxFiles.size();

            // Determine primary suspect
            if (!analysis.identifiedProducts.empty()) {
                analysis.primarySuspect = analysis.identifiedProducts[0];
            }

            // Calculate suspicion score
            analysis.suspicionScore = std::min(100.0f,
                static_cast<float>(analysis.sandboxDLLs.size()) * 25.0f +
                static_cast<float>(analysis.sandboxProcesses.size()) * 20.0f +
                static_cast<float>(analysis.analysisToolProcesses.size()) * 15.0f +
                static_cast<float>(analysis.sandboxMutexes.size()) * 25.0f +
                static_cast<float>(analysis.sandboxRegistryKeys.size()) * 10.0f +
                static_cast<float>(analysis.sandboxFiles.size()) * 15.0f);

            // Definitive detection if we found direct evidence
            analysis.definitiveDetection = !analysis.sandboxDLLs.empty() ||
                !analysis.sandboxMutexes.empty() ||
                !analysis.sandboxProcesses.empty();
#endif

            return analysis;
        }

        bool SandboxEvasionDetector::VerifyHumanInteraction(uint32_t monitoringDurationMs) {
            auto analysis = AnalyzeHumanInteraction(monitoringDurationMs);
            return analysis.result == InteractionResult::HumanDetected;
        }

        HumanInteractionAnalysis SandboxEvasionDetector::AnalyzeHumanInteraction(uint32_t monitoringDurationMs) {
            HumanInteractionAnalysis analysis;
            analysis.monitoringDurationMs = std::clamp(monitoringDurationMs,
                SandboxConstants::MIN_INTERACTION_MONITOR_MS,
                SandboxConstants::MAX_INTERACTION_MONITOR_MS);

            m_impl->stats.humanInteractionChecks.fetch_add(1, std::memory_order_relaxed);

#ifdef _WIN32
            analysis.startTime = std::chrono::steady_clock::now();

            // Mouse tracking data
            std::vector<std::pair<int32_t, int32_t>> mousePositions;
            std::vector<std::chrono::steady_clock::time_point> mouseTimestamps;
            POINT lastPos{};
            GetCursorPos(&lastPos);
            mousePositions.push_back({ lastPos.x, lastPos.y });
            mouseTimestamps.push_back(std::chrono::steady_clock::now());

            uint32_t sampleInterval = 50;  // Sample every 50ms
            uint32_t samples = analysis.monitoringDurationMs / sampleInterval;

            for (uint32_t i = 0; i < samples; ++i) {
                Sleep(sampleInterval);

                POINT currentPos{};
                GetCursorPos(&currentPos);

                if (currentPos.x != lastPos.x || currentPos.y != lastPos.y) {
                    ++analysis.mouseMovementCount;
                    int32_t dx = currentPos.x - lastPos.x;
                    int32_t dy = currentPos.y - lastPos.y;
                    analysis.mouseDistanceTraveled += static_cast<uint64_t>(
                        std::sqrt(static_cast<double>(dx * dx + dy * dy)));

                    mousePositions.push_back({ currentPos.x, currentPos.y });
                    mouseTimestamps.push_back(std::chrono::steady_clock::now());
                }

                lastPos = currentPos;

                // Check for clicks - use state change detection to avoid counting held buttons
                // GetAsyncKeyState bit 0x0001 indicates key was pressed since last call
                static bool lastLeftButton = false;
                static bool lastRightButton = false;
                
                bool leftDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
                bool rightDown = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
                
                if (leftDown && !lastLeftButton) {
                    ++analysis.leftClickCount;
                    ++analysis.mouseClickCount;
                }
                if (rightDown && !lastRightButton) {
                    ++analysis.rightClickCount;
                    ++analysis.mouseClickCount;
                }
                
                lastLeftButton = leftDown;
                lastRightButton = rightDown;

                // CRITICAL FIX (Issue #5): Keyboard input counting bug
                // Previous code counted EVERY held key each sample (Shift+A = 2 counts)
                // Fixed: Track state changes to count only NEW key presses
                static std::bitset<256> previousKeyStates;
                std::bitset<256> currentKeyStates;
                
                for (int key = 0x08; key <= 0xFE; ++key) {
                    if (GetAsyncKeyState(key) & 0x8000) {
                        currentKeyStates.set(key);
                    }
                }
                
                // Count only keys that transitioned from UP to DOWN
                for (int key = 0x08; key <= 0xFE; ++key) {
                    if (currentKeyStates[key] && !previousKeyStates[key]) {
                        ++analysis.keyPressCount;
                    }
                }
                
                previousKeyStates = currentKeyStates;
            }

            analysis.endTime = std::chrono::steady_clock::now();

            // Calculate mouse velocity
            if (!mouseTimestamps.empty() && mouseTimestamps.size() > 1) {
                auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    mouseTimestamps.back() - mouseTimestamps.front()).count();
                if (totalTime > 0) {
                    analysis.avgMouseVelocity = static_cast<double>(analysis.mouseDistanceTraveled) /
                        (static_cast<double>(totalTime) / 1000.0);
                }
            }

            // Calculate path entropy and straight line ratio
            if (mousePositions.size() >= 3) {
                analysis.pathEntropy = CalculateMousePathEntropy(mousePositions);
                analysis.straightLineRatio = CalculateStraightLineRatio(mousePositions);
            }

            // Determine result
            SandboxDetectorConfig currentConfig;
            {
                std::shared_lock lock(m_impl->configMutex);
                currentConfig = m_impl->config;
            }

            bool hasMovement = analysis.mouseMovementCount >= currentConfig.minMouseMovements;
            bool hasDistance = analysis.mouseDistanceTraveled >= currentConfig.minMouseDistance;
            bool hasNaturalPath = analysis.straightLineRatio < SandboxConstants::MAX_STRAIGHT_LINE_RATIO;

            if (hasMovement && hasDistance && hasNaturalPath) {
                analysis.result = InteractionResult::HumanDetected;
                analysis.humanConfidence = 80.0f + (analysis.pathEntropy * 20.0f);
            }
            else if (hasMovement && analysis.straightLineRatio >= SandboxConstants::MAX_STRAIGHT_LINE_RATIO) {
                analysis.result = InteractionResult::BotPatterns;
                analysis.botConfidence = 70.0f + (analysis.straightLineRatio * 30.0f);
            }
            else if (hasMovement) {
                analysis.result = InteractionResult::SimulatedInteraction;
                analysis.simulatedConfidence = 60.0f;
            }
            else {
                analysis.result = InteractionResult::NoInteraction;
                analysis.botConfidence = 90.0f;
            }

            analysis.humanConfidence = std::clamp(analysis.humanConfidence, 0.0f, 100.0f);
            analysis.botConfidence = std::clamp(analysis.botConfidence, 0.0f, 100.0f);
            analysis.analysisComplete = true;

            // Generate findings
            if (!hasMovement) {
                analysis.findings.push_back(L"No significant mouse movement detected");
            }
            if (analysis.straightLineRatio >= SandboxConstants::MAX_STRAIGHT_LINE_RATIO) {
                analysis.findings.push_back(L"Mouse movements appear robotic (high straight-line ratio)");
            }
            if (analysis.mouseClickCount == 0 && analysis.keyPressCount == 0) {
                analysis.findings.push_back(L"No user input (clicks/keys) detected");
            }
#else
            analysis.result = InteractionResult::Error;
            analysis.errorMessage = L"Human interaction analysis not supported on this platform";
#endif

            return analysis;
        }

        // ============================================================================
        // SPECIFIC CHECKS
        // ============================================================================

        bool SandboxEvasionDetector::IsSandboxProductDetected(SandboxProduct product) {
            auto artifacts = ScanArtifacts();

            for (const auto& detected : artifacts.identifiedProducts) {
                if (detected == product) {
                    return true;
                }
            }

            return false;
        }

        uint64_t SandboxEvasionDetector::GetSystemUptime() {
#ifdef _WIN32
            return GetTickCount64();
#else
            return 0;
#endif
        }

        std::pair<uint32_t, uint32_t> SandboxEvasionDetector::GetScreenResolution() {
#ifdef _WIN32
            int width = GetSystemMetrics(SM_CXSCREEN);
            int height = GetSystemMetrics(SM_CYSCREEN);
            return { static_cast<uint32_t>(width), static_cast<uint32_t>(height) };
#else
            return { 0, 0 };
#endif
        }

        bool SandboxEvasionDetector::IsSandboxDLLLoaded(std::wstring_view dllName) {
#ifdef _WIN32
            return GetModuleHandleW(dllName.data()) != nullptr;
#else
            return false;
#endif
        }

        bool SandboxEvasionDetector::IsSandboxProcessRunning(std::wstring_view processName) {
#ifdef _WIN32
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);

            std::wstring lowerTarget(processName);
            std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

            bool found = false;
            if (Process32FirstW(snapshot, &pe)) {
                do {
                    std::wstring currentProcess = pe.szExeFile;
                    std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), ::towlower);

                    if (currentProcess == lowerTarget) {
                        found = true;
                        break;
                    }
                } while (Process32NextW(snapshot, &pe));
            }

            CloseHandle(snapshot);
            return found;
#else
            return false;
#endif
        }

        bool SandboxEvasionDetector::DoesMutexExist(std::wstring_view mutexName) {
#ifdef _WIN32
            HANDLE mutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, mutexName.data());
            if (mutex != nullptr) {
                CloseHandle(mutex);
                return true;
            }
            return false;
#else
            return false;
#endif
        }

        // ============================================================================
        // CALLBACKS
        // ============================================================================

        uint64_t SandboxEvasionDetector::RegisterCallback(SandboxDetectionCallback callback) {
            if (!callback) {
                return 0;
            }

            uint64_t id = s_callbackIdCounter.fetch_add(1, std::memory_order_relaxed);

            std::unique_lock lock(m_impl->callbacksMutex);
            m_impl->callbacks[id] = std::move(callback);

            SS_LOG_DEBUG(LOG_CATEGORY, L"Callback registered with ID: %llu", id);
            return id;
        }

        bool SandboxEvasionDetector::UnregisterCallback(uint64_t callbackId) {
            std::unique_lock lock(m_impl->callbacksMutex);
            auto it = m_impl->callbacks.find(callbackId);
            if (it != m_impl->callbacks.end()) {
                m_impl->callbacks.erase(it);
                SS_LOG_DEBUG(LOG_CATEGORY, L"Callback unregistered: %llu", callbackId);
                return true;
            }
            return false;
        }

        // ============================================================================
        // STATISTICS & CACHE
        // ============================================================================

        SandboxDetectorStats SandboxEvasionDetector::GetStats() const {
            return m_impl->stats;
        }

        void SandboxEvasionDetector::ResetStats() {
            m_impl->stats.Reset();
            SS_LOG_DEBUG(LOG_CATEGORY, L"Statistics reset");
        }

        std::optional<SandboxEvasionResult> SandboxEvasionDetector::GetCachedResult() const {
            std::shared_lock lock(m_impl->cacheMutex);
            return m_impl->cachedResult;
        }

        void SandboxEvasionDetector::ClearCache() {
            std::unique_lock lock(m_impl->cacheMutex);
            m_impl->cachedResult.reset();
            SS_LOG_DEBUG(LOG_CATEGORY, L"Cache cleared");
        }

        std::optional<HardwareProfile> SandboxEvasionDetector::GetHardwareProfile() const {
            std::shared_lock lock(m_impl->hardwareProfileMutex);
            return m_impl->cachedHardwareProfile;
        }

        // ============================================================================
        // INTERNAL CHECK METHODS
        // ============================================================================

        void SandboxEvasionDetector::CheckHardwareSpecs(SandboxEvasionResult& result) {
            auto hardware = AnalyzeHardware();
            result.hardware = hardware;
            result.hardwareScore = 100.0f - hardware.suspicionScore;

            // Add indicators based on hardware findings
            if (hardware.totalRAM < SandboxConstants::SUSPICIOUS_RAM_BYTES) {
                AddIndicator(result, SandboxCheckType::RAMSize, SandboxIndicatorCategory::Hardware,
                    SandboxIndicatorSeverity::High, 3.0f, 85.0f,
                    L"Suspiciously low RAM detected",
                    L"RAM below typical user systems",
                    std::to_wstring(hardware.totalRAM / (1024 * 1024)) + L" MB",
                    L">= 4096 MB");
            }
            else if (hardware.totalRAM < SandboxConstants::MIN_RAM_BYTES) {
                AddIndicator(result, SandboxCheckType::RAMSize, SandboxIndicatorCategory::Hardware,
                    SandboxIndicatorSeverity::Medium, 2.0f, 60.0f,
                    L"Low RAM detected",
                    L"RAM below recommended minimum",
                    std::to_wstring(hardware.totalRAM / (1024 * 1024)) + L" MB",
                    L">= 4096 MB");
            }

            if (hardware.logicalProcessors <= SandboxConstants::SUSPICIOUS_CPU_CORES) {
                AddIndicator(result, SandboxCheckType::CPUCores, SandboxIndicatorCategory::Hardware,
                    SandboxIndicatorSeverity::High, 3.0f, 80.0f,
                    L"Single CPU core detected",
                    L"Most modern systems have multiple cores",
                    std::to_wstring(hardware.logicalProcessors),
                    L">= 2");
            }

            if (hardware.totalDiskSpace < SandboxConstants::SUSPICIOUS_DISK_BYTES) {
                AddIndicator(result, SandboxCheckType::DiskSize, SandboxIndicatorCategory::Hardware,
                    SandboxIndicatorSeverity::Medium, 2.0f, 70.0f,
                    L"Small disk detected",
                    L"Disk size typical of sandbox environments",
                    std::to_wstring(hardware.totalDiskSpace / (1024 * 1024 * 1024)) + L" GB",
                    L">= 80 GB");
            }

            if (!hardware.audioDevicePresent) {
                AddIndicator(result, SandboxCheckType::GPUPresence, SandboxIndicatorCategory::Hardware,
                    SandboxIndicatorSeverity::Low, 1.0f, 40.0f,
                    L"No audio device detected",
                    L"Absence of audio devices is common in sandboxes");
            }

            ++result.totalChecks;
            if (hardware.isSandboxLike) {
                ++result.failedChecks;
            }
            else {
                ++result.passedChecks;
            }
        }

        void SandboxEvasionDetector::CheckUptime(SandboxEvasionResult& result) {
            uint64_t uptime = GetSystemUptime();

            if (uptime < SandboxConstants::VERY_SUSPICIOUS_UPTIME_MS) {
                AddIndicator(result, SandboxCheckType::SystemUptime, SandboxIndicatorCategory::Timing,
                    SandboxIndicatorSeverity::High, 4.0f, 90.0f,
                    L"Very short system uptime",
                    L"System was recently booted, typical of fresh sandbox",
                    std::to_wstring(uptime / 1000) + L" seconds",
                    L">= 120 seconds",
                    SandboxProduct::Unknown, true);
                result.timingScore += 40.0f;
                ++result.failedChecks;
            }
            else if (uptime < SandboxConstants::SUSPICIOUS_UPTIME_MS) {
                AddIndicator(result, SandboxCheckType::SystemUptime, SandboxIndicatorCategory::Timing,
                    SandboxIndicatorSeverity::Medium, 2.5f, 70.0f,
                    L"Short system uptime",
                    L"System uptime below typical threshold",
                    std::to_wstring(uptime / 1000) + L" seconds",
                    L">= 300 seconds");
                result.timingScore += 25.0f;
                ++result.failedChecks;
            }
            else if (uptime < SandboxConstants::MIN_UPTIME_MS) {
                AddIndicator(result, SandboxCheckType::SystemUptime, SandboxIndicatorCategory::Timing,
                    SandboxIndicatorSeverity::Low, 1.5f, 50.0f,
                    L"Relatively short system uptime",
                    L"System uptime below minimum threshold",
                    std::to_wstring(uptime / 60000) + L" minutes",
                    L">= 10 minutes");
                result.timingScore += 15.0f;
            }
            else {
                ++result.passedChecks;
            }

            ++result.totalChecks;
        }

        void SandboxEvasionDetector::CheckLoadedModules(SandboxEvasionResult& result) {
#ifdef _WIN32
            const std::pair<std::wstring_view, SandboxProduct> sandboxDLLs[] = {
                {KnownSandboxDLLs::SBIEDLL, SandboxProduct::Sandboxie},
                {KnownSandboxDLLs::CUCKOOMON, SandboxProduct::Cuckoo},
                {KnownSandboxDLLs::SNXHK, SandboxProduct::AvastDeepScreen},
                {KnownSandboxDLLs::VMRAY, SandboxProduct::VMRay},
                {KnownSandboxDLLs::JOEBOX, SandboxProduct::JoeSandbox},
                {KnownSandboxDLLs::GUARD32, SandboxProduct::ComodoSandbox},
                {KnownSandboxDLLs::GUARD64, SandboxProduct::ComodoSandbox},
            };

            for (const auto& [dll, product] : sandboxDLLs) {
                if (GetModuleHandleW(dll.data()) != nullptr) {
                    AddIndicator(result, SandboxCheckType::SandboxDLLs, SandboxIndicatorCategory::Artifact,
                        SandboxIndicatorSeverity::Critical, 5.0f, 99.0f,
                        L"Sandbox DLL detected: " + std::wstring(dll),
                        L"Direct evidence of sandbox environment",
                        std::wstring(dll), L"Not loaded",
                        product, true);
                    result.artifactScore += 30.0f;
                    result.artifacts.sandboxDLLs.push_back(std::wstring(dll));
                    result.artifacts.identifiedProducts.push_back(product);
                    ++result.failedChecks;
                }
                else {
                    ++result.passedChecks;
                }
                ++result.totalChecks;
            }
#endif
        }

        void SandboxEvasionDetector::CheckSystemWearAndTear(SandboxEvasionResult& result) {
            auto wearAnalysis = AnalyzeWearAndTear();
            result.wearAndTear = wearAnalysis;
            result.wearAndTearScore = wearAnalysis.usageScore;

            if (wearAnalysis.appearsFresh) {
                AddIndicator(result, SandboxCheckType::InstalledPrograms, SandboxIndicatorCategory::WearAndTear,
                    SandboxIndicatorSeverity::Medium, 2.0f, 65.0f,
                    L"System appears freshly installed",
                    L"Minimal system usage indicators detected");
                ++result.failedChecks;
            }
            else {
                ++result.passedChecks;
            }

            if (wearAnalysis.installedProgramCount < SandboxConstants::MIN_INSTALLED_PROGRAMS) {
                AddIndicator(result, SandboxCheckType::InstalledPrograms, SandboxIndicatorCategory::WearAndTear,
                    SandboxIndicatorSeverity::Low, 1.5f, 55.0f,
                    L"Few installed programs",
                    L"Typical user systems have more software installed",
                    std::to_wstring(wearAnalysis.installedProgramCount),
                    L">= 20");
            }

            if (wearAnalysis.recentDocumentsCount < 5) {
                AddIndicator(result, SandboxCheckType::RecentDocuments, SandboxIndicatorCategory::WearAndTear,
                    SandboxIndicatorSeverity::Low, 1.0f, 45.0f,
                    L"Very few recent documents",
                    L"No document activity history",
                    std::to_wstring(wearAnalysis.recentDocumentsCount),
                    L">= 10");
            }

            ++result.totalChecks;
        }

        void SandboxEvasionDetector::CheckNamedObjects(SandboxEvasionResult& result) {
#ifdef _WIN32
            const std::pair<std::wstring_view, SandboxProduct> sandboxMutexes[] = {
                {KnownSandboxMutexes::SANDBOXIE, SandboxProduct::Sandboxie},
                {KnownSandboxMutexes::CUCKOO, SandboxProduct::Cuckoo},
                {KnownSandboxMutexes::JOEBOX, SandboxProduct::JoeSandbox},
                {KnownSandboxMutexes::VMRAY, SandboxProduct::VMRay},
            };

            for (const auto& [mutex, product] : sandboxMutexes) {
                if (DoesMutexExist(mutex)) {
                    AddIndicator(result, SandboxCheckType::SandboxMutexes, SandboxIndicatorCategory::Artifact,
                        SandboxIndicatorSeverity::Critical, 5.0f, 99.0f,
                        L"Sandbox mutex detected: " + std::wstring(mutex),
                        L"Direct evidence of sandbox environment",
                        std::wstring(mutex), L"Not present",
                        product, true);
                    result.artifactScore += 35.0f;
                    result.artifacts.sandboxMutexes.push_back(std::wstring(mutex));
                    ++result.failedChecks;
                }
                else {
                    ++result.passedChecks;
                }
                ++result.totalChecks;
            }
#endif
        }

        void SandboxEvasionDetector::CheckScreenResolution(SandboxEvasionResult& result) {
            auto [width, height] = GetScreenResolution();
            result.environment.screenWidth = width;
            result.environment.screenHeight = height;

            bool isSuspicious = false;

            if (width <= SandboxConstants::VERY_SUSPICIOUS_SCREEN_WIDTH &&
                height <= SandboxConstants::VERY_SUSPICIOUS_SCREEN_HEIGHT) {
                AddIndicator(result, SandboxCheckType::ScreenResolution, SandboxIndicatorCategory::Environment,
                    SandboxIndicatorSeverity::High, 3.0f, 85.0f,
                    L"Very low screen resolution",
                    L"800x600 is extremely common in sandboxes",
                    std::to_wstring(width) + L"x" + std::to_wstring(height),
                    L">= 1280x720");
                result.environmentScore += 25.0f;
                isSuspicious = true;
            }
            else if (width <= SandboxConstants::SUSPICIOUS_SCREEN_WIDTH &&
                height <= SandboxConstants::SUSPICIOUS_SCREEN_HEIGHT) {
                AddIndicator(result, SandboxCheckType::ScreenResolution, SandboxIndicatorCategory::Environment,
                    SandboxIndicatorSeverity::Medium, 2.0f, 65.0f,
                    L"Low screen resolution",
                    L"1024x768 is common in sandbox environments",
                    std::to_wstring(width) + L"x" + std::to_wstring(height),
                    L">= 1280x720");
                result.environmentScore += 15.0f;
                isSuspicious = true;
            }

            ++result.totalChecks;
            if (isSuspicious) {
                result.environment.isVMResolution = true;
                ++result.failedChecks;
            }
            else {
                ++result.passedChecks;
            }
        }

        void SandboxEvasionDetector::CheckProcesses(SandboxEvasionResult& result) {
            auto artifacts = ScanArtifacts();

            for (const auto& proc : artifacts.sandboxProcesses) {
                AddIndicator(result, SandboxCheckType::SandboxProcesses, SandboxIndicatorCategory::Artifact,
                    SandboxIndicatorSeverity::High, 4.0f, 90.0f,
                    L"Sandbox process detected: " + proc,
                    L"Sandbox control process running",
                    proc, L"Not running");
                ++result.failedChecks;
            }

            for (const auto& proc : artifacts.analysisToolProcesses) {
                AddIndicator(result, SandboxCheckType::AnalysisTools, SandboxIndicatorCategory::Artifact,
                    SandboxIndicatorSeverity::Medium, 2.5f, 75.0f,
                    L"Analysis tool detected: " + proc,
                    L"Common malware analysis tool running",
                    proc, L"Not running");
                ++result.failedChecks;
            }

            result.artifacts.sandboxProcesses = std::move(artifacts.sandboxProcesses);
            result.artifacts.analysisToolProcesses = std::move(artifacts.analysisToolProcesses);

            result.totalChecks += static_cast<uint32_t>(result.artifacts.sandboxProcesses.size() +
                result.artifacts.analysisToolProcesses.size());
            if (result.artifacts.sandboxProcesses.empty() && result.artifacts.analysisToolProcesses.empty()) {
                ++result.passedChecks;
                ++result.totalChecks;
            }
        }

        void SandboxEvasionDetector::CheckServices(SandboxEvasionResult& result) {
#ifdef _WIN32
            // Check for sandbox-related services
            const std::pair<std::wstring, SandboxProduct> sandboxServices[] = {
                {L"SbieSvc", SandboxProduct::Sandboxie},
                {L"VBoxService", SandboxProduct::GenericAnalysis},
                {L"VMTools", SandboxProduct::GenericAnalysis},
                {L"vmicheartbeat", SandboxProduct::GenericAnalysis},
            };

            SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (scManager) {
                for (const auto& [serviceName, product] : sandboxServices) {
                    SC_HANDLE service = OpenServiceW(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
                    if (service) {
                        SERVICE_STATUS status{};
                        if (QueryServiceStatus(service, &status)) {
                            if (status.dwCurrentState == SERVICE_RUNNING) {
                                AddIndicator(result, SandboxCheckType::SandboxServices, SandboxIndicatorCategory::Artifact,
                                    SandboxIndicatorSeverity::High, 3.5f, 85.0f,
                                    L"Sandbox service running: " + serviceName,
                                    L"Sandbox-related service detected",
                                    serviceName, L"Not running",
                                    product);
                                result.artifacts.sandboxServices.push_back(serviceName);
                                ++result.failedChecks;
                            }
                        }
                        CloseServiceHandle(service);
                    }
                    ++result.totalChecks;
                }
                CloseServiceHandle(scManager);
            }

            if (result.artifacts.sandboxServices.empty()) {
                ++result.passedChecks;
            }
#endif
        }

        void SandboxEvasionDetector::CheckRegistry(SandboxEvasionResult& result) {
            // Registry checks are included in AnalyzeEnvironment and ScanArtifacts
            auto env = AnalyzeEnvironment();
            result.environment = env;
            result.environmentScore = 100.0f - env.suspicionScore;

            if (!env.issues.empty()) {
                for (const auto& issue : env.issues) {
                    AddIndicator(result, SandboxCheckType::SandboxRegistry, SandboxIndicatorCategory::Environment,
                        SandboxIndicatorSeverity::Medium, 2.0f, 60.0f,
                        issue, L"Environment anomaly detected");
                }
                result.failedChecks += static_cast<uint32_t>(env.issues.size());
            }
            else {
                ++result.passedChecks;
            }

            result.totalChecks += static_cast<uint32_t>(env.issues.size()) + 1;
        }

        void SandboxEvasionDetector::CheckFileSystem(SandboxEvasionResult& result) {
            auto artifacts = ScanArtifacts();

            for (const auto& file : artifacts.sandboxFiles) {
                AddIndicator(result, SandboxCheckType::SandboxFiles, SandboxIndicatorCategory::FileSystem,
                    SandboxIndicatorSeverity::High, 3.5f, 88.0f,
                    L"Sandbox file detected: " + file,
                    L"File typically found in sandbox environments",
                    file, L"Not present");
                ++result.failedChecks;
            }

            result.artifacts.sandboxFiles = std::move(artifacts.sandboxFiles);

            ++result.totalChecks;
            if (result.artifacts.sandboxFiles.empty()) {
                ++result.passedChecks;
            }
        }

        void SandboxEvasionDetector::CheckAPIHooks(SandboxEvasionResult& result) {
#ifdef _WIN32
            // Check for inline hooks on common APIs using Zydis disassembler
            const std::pair<const char*, const char*> criticalAPIs[] = {
                {"ntdll.dll", "NtQueryInformationProcess"},
                {"ntdll.dll", "NtQuerySystemInformation"},
                {"ntdll.dll", "NtCreateFile"},
                {"ntdll.dll", "NtOpenProcess"},
                {"ntdll.dll", "NtQueryVirtualMemory"},
                {"ntdll.dll", "NtReadVirtualMemory"},
                {"ntdll.dll", "NtWriteVirtualMemory"},
                {"ntdll.dll", "NtDelayExecution"},
                {"kernel32.dll", "IsDebuggerPresent"},
                {"kernel32.dll", "GetTickCount"},
                {"kernel32.dll", "GetTickCount64"},
                {"kernel32.dll", "QueryPerformanceCounter"},
                {"kernel32.dll", "GetSystemTimeAsFileTime"},
                {"kernel32.dll", "CreateFileW"},
                {"kernel32.dll", "ReadFile"},
                {"kernel32.dll", "VirtualAlloc"},
                {"kernel32.dll", "VirtualProtect"},
            };

            // Ensure Zydis is initialized
            if (!m_impl->zydisInitialized) {
                m_impl->InitializeZydis();
            }

            size_t hookedCount = 0;
            constexpr size_t MAX_PROLOGUE_BYTES = 32;  // Analyze first 32 bytes of each function

            for (const auto& [module, function] : criticalAPIs) {
                HMODULE hMod = GetModuleHandleA(module);
                if (!hMod) continue;

                FARPROC proc = GetProcAddress(hMod, function);
                if (!proc) continue;

                const uint8_t* funcBytes = reinterpret_cast<const uint8_t*>(proc);

                // Use Zydis to properly disassemble and detect hooks
                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                // Decode the first instruction
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    m_impl->GetDecoder(true),  // 64-bit (we're on Win10/11 x64)
                    funcBytes,
                    MAX_PROLOGUE_BYTES,
                    &instruction,
                    operands))) {
                    continue;
                }

                bool isHooked = false;
                std::wstring hookType;

                // Check for common hook patterns:
                // 1. JMP rel32 (E9 xx xx xx xx) - 5 byte near jump
                // 2. JMP [rip+disp32] (FF 25 xx xx xx xx) - 6 byte indirect jump
                // 3. MOV RAX, imm64; JMP RAX - 12 byte trampoline
                // 4. PUSH addr; RET - push/ret gadget
                // 5. INT 3 (CC) - breakpoint hook

                switch (instruction.mnemonic) {
                    case ZYDIS_MNEMONIC_JMP:
                        // Any JMP as first instruction is suspicious
                        isHooked = true;
                        if (instruction.length == 5 && funcBytes[0] == 0xE9) {
                            hookType = L"JMP rel32 (inline hook)";
                        } else if (instruction.length == 6 && funcBytes[0] == 0xFF && funcBytes[1] == 0x25) {
                            hookType = L"JMP [RIP+disp32] (indirect hook)";
                        } else {
                            hookType = L"JMP instruction (hook)";
                        }
                        break;

                    case ZYDIS_MNEMONIC_CALL:
                        // CALL as first instruction can be a hook
                        isHooked = true;
                        hookType = L"CALL instruction (detour)";
                        break;

                    case ZYDIS_MNEMONIC_PUSH:
                        // Check for PUSH addr; RET pattern
                        if (instruction.operand_count > 0 &&
                            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            // Decode next instruction to check for RET
                            ZydisDecodedInstruction nextInstr;
                            ZydisDecodedOperand nextOps[ZYDIS_MAX_OPERAND_COUNT];
                            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                                m_impl->GetDecoder(true),
                                funcBytes + instruction.length,
                                MAX_PROLOGUE_BYTES - instruction.length,
                                &nextInstr,
                                nextOps))) {
                                if (nextInstr.mnemonic == ZYDIS_MNEMONIC_RET) {
                                    isHooked = true;
                                    hookType = L"PUSH/RET gadget (hook)";
                                }
                            }
                        }
                        break;

                    case ZYDIS_MNEMONIC_INT3:
                        isHooked = true;
                        hookType = L"INT3 breakpoint (debug hook)";
                        break;

                    case ZYDIS_MNEMONIC_INT:
                        if (instruction.operand_count > 0 &&
                            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            operands[0].imm.value.u == 0x2D) {
                            isHooked = true;
                            hookType = L"INT 2D (debug hook)";
                        }
                        break;

                    case ZYDIS_MNEMONIC_MOV:
                        // Check for MOV RAX, imm64 pattern (often followed by JMP RAX)
                        if (instruction.operand_count >= 2 &&
                            operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            operands[0].reg.value == ZYDIS_REGISTER_RAX &&
                            operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            // Decode subsequent instructions looking for JMP RAX
                            size_t offset = instruction.length;
                            for (int i = 0; i < 3 && offset < MAX_PROLOGUE_BYTES; ++i) {
                                ZydisDecodedInstruction scanInstr;
                                ZydisDecodedOperand scanOps[ZYDIS_MAX_OPERAND_COUNT];
                                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                                    m_impl->GetDecoder(true),
                                    funcBytes + offset,
                                    MAX_PROLOGUE_BYTES - offset,
                                    &scanInstr,
                                    scanOps))) {
                                    break;
                                }
                                if (scanInstr.mnemonic == ZYDIS_MNEMONIC_JMP &&
                                    scanOps[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                    scanOps[0].reg.value == ZYDIS_REGISTER_RAX) {
                                    isHooked = true;
                                    hookType = L"MOV RAX, imm64; JMP RAX (trampoline)";
                                    break;
                                }
                                offset += scanInstr.length;
                            }
                        }
                        break;

                    default:
                        // For ntdll syscall stubs, the expected pattern is:
                        // MOV R10, RCX; MOV EAX, syscall_number
                        // If we see something else entirely, it might be patched
                        if (strstr(module, "ntdll") != nullptr) {
                            // Check if this looks like a normal syscall stub
                            bool looksNormal = false;
                            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                instruction.operand_count >= 2) {
                                // MOV R10, RCX is expected
                                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                    operands[0].reg.value == ZYDIS_REGISTER_R10) {
                                    looksNormal = true;
                                }
                            }
                            // If it doesn't look normal and it's not a standard instruction,
                            // flag for review (but don't mark as definitively hooked)
                        }
                        break;
                }

                if (isHooked) {
                    ++hookedCount;
                    std::wstring apiName = Utils::StringUtils::ToWide(
                        std::string(module) + "!" + function);
                    result.artifacts.hookedAPIs.push_back(apiName + L" - " + hookType);

                    SS_LOG_WARN(LOG_CATEGORY,
                        L"API hook detected: %ls (%ls)",
                        apiName.c_str(), hookType.c_str());
                }
            }

            if (hookedCount > 0) {
                AddIndicator(result, SandboxCheckType::HookDetection, SandboxIndicatorCategory::Artifact,
                    SandboxIndicatorSeverity::High, 4.0f, 85.0f,
                    L"API hooks detected: " + std::to_wstring(hookedCount) + L" functions",
                    L"Inline hooks indicate monitoring/sandbox environment",
                    std::to_wstring(hookedCount) + L" hooks", L"0 hooks");
                result.artifacts.apiHooksDetected = true;
                result.artifacts.hookedAPICount = hookedCount;
                ++result.failedChecks;
            }
            else {
                ++result.passedChecks;
            }

            ++result.totalChecks;
#endif
        }

        void SandboxEvasionDetector::CheckNetworkCharacteristics(SandboxEvasionResult& result) {
#ifdef _WIN32
            // Check for VM MAC address prefixes
            ULONG adaptersSize = 0;
            GetAdaptersInfo(nullptr, &adaptersSize);

            if (adaptersSize > 0) {
                std::vector<uint8_t> buffer(adaptersSize);
                PIP_ADAPTER_INFO adapters = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

                if (GetAdaptersInfo(adapters, &adaptersSize) == ERROR_SUCCESS) {
                    for (PIP_ADAPTER_INFO adapter = adapters; adapter; adapter = adapter->Next) {
                        if (adapter->AddressLength >= 3) {
                            for (const auto& vmPrefix : VM_MAC_PREFIXES) {
                                if (adapter->Address[0] == vmPrefix[0] &&
                                    adapter->Address[1] == vmPrefix[1] &&
                                    adapter->Address[2] == vmPrefix[2]) {

                                    wchar_t macStr[32];
                                    swprintf_s(macStr, L"%02X:%02X:%02X:*",
                                        adapter->Address[0], adapter->Address[1], adapter->Address[2]);

                                    AddIndicator(result, SandboxCheckType::MACAddress, SandboxIndicatorCategory::Network,
                                        SandboxIndicatorSeverity::Medium, 2.5f, 75.0f,
                                        L"VM/Sandbox MAC address prefix detected",
                                        L"Network adapter has known virtual machine OUI",
                                        macStr, L"Physical adapter OUI");
                                    result.networkScore += 20.0f;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            ++result.totalChecks;
            ++result.passedChecks;  // Not definitive by itself
#endif
        }

        void SandboxEvasionDetector::CalculateProbability(SandboxEvasionResult& result) {
            SandboxDetectorConfig currentConfig;
            {
                std::shared_lock lock(m_impl->configMutex);
                currentConfig = m_impl->config;
            }

            // Gather category scores
            std::vector<float> scores = {
                100.0f - result.hardware.suspicionScore,           // Hardware (inverted)
                result.wearAndTear.usageScore,                     // Wear and tear
                result.humanInteraction.has_value() ?
                    result.humanInteraction->humanConfidence : 50.0f,  // Human interaction
                100.0f - result.environment.suspicionScore,        // Environment (inverted)
                100.0f - result.artifacts.suspicionScore,          // Artifacts (inverted)
                100.0f - result.timingScore,                       // Timing (inverted)
                100.0f - result.networkScore,                      // Network (inverted)
            };

            std::vector<float> weights = {
                currentConfig.hardwareWeight,
                currentConfig.wearAndTearWeight,
                currentConfig.humanInteractionWeight,
                currentConfig.environmentWeight,
                currentConfig.artifactWeight,
                currentConfig.timingWeight,
                currentConfig.networkWeight,
            };

            // Calculate weighted "clean" probability (higher = less likely sandbox)
            float cleanProbability = CalculateWeightedProbability(scores, weights);

            // Sandbox probability is inverse
            result.probability = 100.0f - cleanProbability;

            // Boost probability if definitive artifacts found
            bool hasDefinitiveEvidence = result.artifacts.definitiveDetection;
            for (const auto& indicator : result.indicators) {
                if (indicator.isConclusive) {
                    hasDefinitiveEvidence = true;
                    break;
                }
            }

            if (hasDefinitiveEvidence) {
                result.probability = std::max(result.probability, 95.0f);
                result.isDefinitive = true;
            }

            // Clamp probability
            result.probability = std::clamp(result.probability, 0.0f, 100.0f);

            // Determine if sandbox is likely based on threshold
            result.isSandboxLikely = result.probability >= currentConfig.probabilityThreshold;

            // Calculate confidence based on number of checks and consistency
            float checksRatio = (result.totalChecks > 0) ?
                static_cast<float>(result.failedChecks + result.passedChecks) / static_cast<float>(result.totalChecks) : 0.0f;
            result.confidence = checksRatio * 100.0f;

            // Adjust confidence based on indicator severity distribution
            size_t criticalCount = 0, highCount = 0;
            for (const auto& indicator : result.indicators) {
                if (indicator.severity == SandboxIndicatorSeverity::Critical) ++criticalCount;
                else if (indicator.severity == SandboxIndicatorSeverity::High) ++highCount;
            }

            if (criticalCount > 0) {
                result.confidence = std::min(100.0f, result.confidence + 20.0f);
            }
            if (highCount >= 3) {
                result.confidence = std::min(100.0f, result.confidence + 10.0f);
            }

            // Generate summary message
            if (result.isSandboxLikely) {
                result.summaryMessages.push_back(L"Sandbox environment detected with " +
                    std::to_wstring(static_cast<int>(result.probability)) + L"% probability");
            }
            else {
                result.summaryMessages.push_back(L"No sandbox detected (probability: " +
                    std::to_wstring(static_cast<int>(result.probability)) + L"%)");
            }
        }

        void SandboxEvasionDetector::IdentifySandboxProduct(SandboxEvasionResult& result) {
            // Count product identifications
            std::unordered_map<SandboxProduct, int> productVotes;

            for (const auto& indicator : result.indicators) {
                if (indicator.suspectedProduct != SandboxProduct::Unknown) {
                    productVotes[indicator.suspectedProduct]++;
                }
            }

            for (const auto& product : result.artifacts.identifiedProducts) {
                productVotes[product] += 2;  // Artifact identification is stronger
            }

            // Find product with most votes
            SandboxProduct bestProduct = SandboxProduct::Unknown;
            int maxVotes = 0;

            for (const auto& [product, votes] : productVotes) {
                if (votes > maxVotes) {
                    maxVotes = votes;
                    bestProduct = product;
                }
            }

            result.identifiedSandbox = bestProduct;

            // Collect all suspected products
            for (const auto& [product, votes] : productVotes) {
                result.suspectedProducts.push_back(product);
            }

            // Set sandbox name
            if (bestProduct != SandboxProduct::Unknown) {
                result.sandboxName = Utils::StringUtils::ToWide(SandboxProductToString(bestProduct));
            }

            // Multiple sandboxes?
            if (productVotes.size() > 1) {
                result.identifiedSandbox = SandboxProduct::Multiple;
                result.sandboxName = L"Multiple sandbox indicators";
            }
        }

        void SandboxEvasionDetector::AddMitreMappings(SandboxEvasionResult& result) {
            std::unordered_set<std::string> uniqueMitre;

            for (const auto& indicator : result.indicators) {
                const char* mitre = SandboxCheckToMitre(indicator.checkType);
                if (mitre && strlen(mitre) > 0) {
                    uniqueMitre.insert(mitre);
                }
            }

            result.mitreIds.assign(uniqueMitre.begin(), uniqueMitre.end());

            // Primary tactic is always Defense Evasion for sandbox detection
            result.mitreTactic = "TA0005";
        }

        void SandboxEvasionDetector::AddIndicator(
            SandboxEvasionResult& result,
            SandboxCheckType checkType,
            SandboxIndicatorCategory category,
            SandboxIndicatorSeverity severity,
            float weight,
            float confidence,
            const std::wstring& description,
            const std::wstring& technicalDetails,
            const std::wstring& observedValue,
            const std::wstring& expectedValue,
            SandboxProduct suspectedProduct,
            bool isConclusive
        ) {
            if (result.indicators.size() >= SandboxConstants::MAX_INDICATORS) {
                SS_LOG_WARN(LOG_CATEGORY, L"Maximum indicator limit reached, skipping: %ls", description.c_str());
                return;
            }

            SandboxIndicator indicator;
            indicator.checkType = checkType;
            indicator.category = category;
            indicator.severity = severity;
            indicator.weight = weight;
            indicator.confidence = confidence;
            indicator.suspectedProduct = suspectedProduct;
            indicator.description = description;
            indicator.technicalDetails = technicalDetails;
            indicator.observedValue = observedValue;
            indicator.expectedValue = expectedValue;
            indicator.mitreId = SandboxCheckToMitre(checkType);
            indicator.detectionTime = std::chrono::system_clock::now();
            indicator.isConclusive = isConclusive;

            result.indicators.push_back(std::move(indicator));
        }

        void SandboxEvasionDetector::UpdateCache(const SandboxEvasionResult& result) {
            std::unique_lock lock(m_impl->cacheMutex);
            m_impl->cachedResult = result;
            m_impl->cacheTimestamp = std::chrono::system_clock::now();
        }

        void SandboxEvasionDetector::InvokeCallbacks(const SandboxEvasionResult& result) {
            std::shared_lock lock(m_impl->callbacksMutex);
            for (const auto& [id, callback] : m_impl->callbacks) {
                if (callback) {
                    try {
                        callback(result);
                    }
                    catch (const std::exception& e) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Callback %llu threw exception: %hs", id, e.what());
                    }
                }
            }
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        double CalculateMousePathEntropy(
            const std::vector<std::pair<int32_t, int32_t>>& movements
        ) noexcept {
            if (movements.size() < 3) return 0.0;

            // Calculate angles between consecutive segments
            std::vector<double> angles;
            angles.reserve(movements.size() - 2);

            for (size_t i = 1; i < movements.size() - 1; ++i) {
                double dx1 = static_cast<double>(movements[i].first - movements[i - 1].first);
                double dy1 = static_cast<double>(movements[i].second - movements[i - 1].second);
                double dx2 = static_cast<double>(movements[i + 1].first - movements[i].first);
                double dy2 = static_cast<double>(movements[i + 1].second - movements[i].second);

                double len1 = std::sqrt(dx1 * dx1 + dy1 * dy1);
                double len2 = std::sqrt(dx2 * dx2 + dy2 * dy2);

                if (len1 > 0.001 && len2 > 0.001) {
                    double dot = dx1 * dx2 + dy1 * dy2;
                    double cosAngle = dot / (len1 * len2);
                    cosAngle = std::clamp(cosAngle, -1.0, 1.0);
                    angles.push_back(std::acos(cosAngle));
                }
            }

            if (angles.empty()) return 0.0;

            // Calculate entropy of angle distribution
            // Bin angles into 8 buckets (0-45, 45-90, etc.)
            constexpr int BUCKETS = 8;
            std::array<int, BUCKETS> histogram{};

            for (double angle : angles) {
                int bucket = static_cast<int>((angle / M_PI) * BUCKETS);
                bucket = std::clamp(bucket, 0, BUCKETS - 1);
                histogram[bucket]++;
            }

            // Shannon entropy
            double entropy = 0.0;
            double total = static_cast<double>(angles.size());

            for (int count : histogram) {
                if (count > 0) {
                    double p = static_cast<double>(count) / total;
                    entropy -= p * std::log2(p);
                }
            }

            // Normalize to 0-1 (max entropy = log2(BUCKETS))
            return entropy / std::log2(BUCKETS);
        }

        double CalculateStraightLineRatio(
            const std::vector<std::pair<int32_t, int32_t>>& movements
        ) noexcept {
            if (movements.size() < 2) return 1.0;

            // Calculate actual path length
            double pathLength = 0.0;
            for (size_t i = 1; i < movements.size(); ++i) {
                double dx = static_cast<double>(movements[i].first - movements[i - 1].first);
                double dy = static_cast<double>(movements[i].second - movements[i - 1].second);
                pathLength += std::sqrt(dx * dx + dy * dy);
            }

            // Calculate straight-line distance
            double dx = static_cast<double>(movements.back().first - movements.front().first);
            double dy = static_cast<double>(movements.back().second - movements.front().second);
            double straightDistance = std::sqrt(dx * dx + dy * dy);

            if (pathLength < 0.001) return 1.0;

            // Ratio of straight distance to path length (1.0 = perfectly straight)
            return straightDistance / pathLength;
        }

    } // namespace AntiEvasion
} // namespace ShadowStrike
