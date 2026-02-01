/**
 * @file SandboxEvasionDetector.hpp
 * @brief Enterprise-grade detection of automated malware analysis sandbox evasion techniques.
 *
 * This module provides comprehensive detection of techniques used by malware to identify
 * and evade automated analysis sandboxes such as Cuckoo, Joe Sandbox, ANY.RUN, Hybrid Analysis,
 * VirusTotal, Windows Sandbox, and enterprise sandbox solutions.
 *
 * =============================================================================
 * DETECTED TECHNIQUES (MITRE ATT&CK T1497.001 - System Checks)
 * =============================================================================
 *
 * 1. HUMAN INTERACTION DETECTION:
 *    - Mouse movement patterns and click analysis
 *    - Keyboard input monitoring
 *    - Window focus/interaction patterns
 *    - Clipboard activity monitoring
 *    - User activity timing analysis
 *
 * 2. HARDWARE FINGERPRINTING:
 *    - RAM size (sandboxes often < 4GB)
 *    - CPU core count (sandboxes often ≤ 2 cores)
 *    - Disk size and type (sandboxes often < 80GB)
 *    - GPU presence and capabilities
 *    - USB device history
 *    - Network adapter count and types
 *    - BIOS/UEFI information
 *
 * 3. SYSTEM WEAR AND TEAR:
 *    - Recent documents count
 *    - Browser history depth
 *    - Desktop/Downloads file count
 *    - Installed program count
 *    - Temp file age distribution
 *    - Event log depth
 *    - System restore point count
 *    - User profile count and age
 *
 * 4. TIMING ANALYSIS:
 *    - System uptime (sandboxes often < 10 minutes)
 *    - Process creation timestamps
 *    - System install date
 *    - Last boot time patterns
 *
 * 5. SANDBOX ARTIFACT DETECTION:
 *    - Known sandbox DLLs (sbiedll.dll, dbghelp.dll hooks)
 *    - Sandbox-specific registry keys
 *    - Analysis tool processes
 *    - Known sandbox mutexes/named pipes
 *    - Agent service detection
 *    - Hook detection in system DLLs
 *
 * 6. ENVIRONMENT CHECKS:
 *    - Screen resolution (sandboxes often 800x600 or 1024x768)
 *    - Color depth limitations
 *    - Audio device presence
 *    - Printer/scanner presence
 *    - Monitor count and arrangement
 *    - Timezone and locale consistency
 *
 * 7. NETWORK CHARACTERISTICS:
 *    - DNS resolver analysis
 *    - Gateway/router fingerprinting
 *    - External IP geolocation
 *    - Network latency patterns
 *    - Blocked port detection
 *
 * 8. FILE SYSTEM ANALYSIS:
 *    - System32 file count and timestamps
 *    - Program Files diversity
 *    - User profile completeness
 *    - Document metadata analysis
 *
 * =============================================================================
 * KNOWN SANDBOX PRODUCTS DETECTED
 * =============================================================================
 *
 * | Sandbox              | Detection Methods                              |
 * |---------------------|------------------------------------------------|
 * | Cuckoo Sandbox      | Agent process, cuckoomon.dll, network patterns |
 * | Joe Sandbox         | joeboxserver, joeboxcontrol processes          |
 * | ANY.RUN             | anyrun artifacts, characteristic timeouts      |
 * | Hybrid Analysis     | Falcon agent, specific registry keys           |
 * | VirusTotal          | VT-specific behaviors, timing patterns         |
 * | Windows Sandbox     | WindowsSandbox.exe, container markers          |
 * | Sandboxie           | SbieDll.dll, SBIE mutex                        |
 * | Comodo Sandbox      | cmdvirth.exe, guard32.dll                      |
 * | Avast DeepScreen    | snxhk.dll, specific hooks                      |
 * | VMRay               | VMRay agent, vboxservice patterns              |
 * | CAPE Sandbox        | cape_handler, analysis artifacts               |
 * | FireEye AX          | AX agent, network signatures                   |
 * | Triage              | Hatching artifacts                             |
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     SandboxEvasionDetector                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
 * │  │ Human Interaction│  │Hardware Profiler│  │ Artifact Scanner│         │
 * │  │ - Mouse/Keyboard │  │ - RAM/CPU/Disk  │  │ - DLLs/Mutexes  │         │
 * │  │ - Timing         │  │ - GPU/Network   │  │ - Processes     │         │
 * │  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
 * │           │                   │                   │                     │
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
 * │  │ Wear & Tear     │  │ Environment     │  │ Network Analyzer │         │
 * │  │ - Documents     │  │ - Screen        │  │ - DNS/Gateway    │         │
 * │  │ - History       │  │ - Devices       │  │ - Latency        │         │
 * │  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
 * │           │                   │                   │                     │
 * │           └───────────────────┼───────────────────┘                     │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │   Scoring Engine    │                              │
 * │                    │  - Weight system    │                              │
 * │                    │  - Correlation      │                              │
 * │                    │  - Threshold calc   │                              │
 * │                    └─────────────────────┘                              │
 * │                               │                                         │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │  Result Aggregator  │                              │
 * │                    │  - MITRE mapping    │                              │
 * │                    │  - Sandbox ID       │                              │
 * │                    └─────────────────────┘                              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @note Thread-safe for all public methods.
 * @note Some checks require administrator privileges for full accuracy.
 *
 * @see VMEvasionDetector for VM-specific detection
 * @see EnvironmentEvasionDetector for broader environment checks
 * @see TimeBasedEvasionDetector for timing-based evasion
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

 // ============================================================================
 // INFRASTRUCTURE INCLUDES
 // ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process enumeration
#include "../Utils/SystemUtils.hpp"           // System information
#include "../Utils/RegistryUtils.hpp"         // Registry artifacts
#include "../Utils/FileUtils.hpp"             // File system checks
#include "../PatternStore/PatternStore.hpp"   // Sandbox patterns

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// =============================================================================
// ASSEMBLY FUNCTION DECLARATIONS (SandboxEvasionDetector_x64.asm)
// =============================================================================
// These functions provide low-level timing and environment detection that
// cannot be reliably implemented in C++ due to:
// - Precise instruction sequencing requirements
// - Need to avoid compiler optimizations
// - Direct access to CPU features (RDTSC, CPUID, RDPMC)
// - Detection of VM/hypervisor timing anomalies
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Gets RDTSC value with full serialization for accurate measurement.
/// @return 64-bit TSC value
uint64_t GetPreciseRDTSC(void);

/// @brief Gets RDTSCP value which is self-serializing.
/// @param processorId Optional pointer to receive processor ID (can be NULL)
/// @return 64-bit TSC value
uint64_t GetPreciseRDTSCP(uint32_t* processorId);

/// @brief Measures the overhead of RDTSC instructions.
/// @return Measured overhead in cycles (high = likely VM)
uint64_t MeasureRDTSCOverhead(void);

/// @brief Measures CPUID instruction overhead.
/// @return Measured overhead in cycles (high = likely VM)
uint64_t MeasureCPUIDOverhead(void);

/// @brief Detects sandbox sleep acceleration/patching.
/// @param sleepMs Sleep duration in milliseconds
/// @return Deviation percentage (0 = exact, >50 = likely patched)
uint64_t MeasureSleepAcceleration(uint32_t sleepMs);

/// @brief Detects Cuckoo sandbox backdoor communication.
/// @return 1 if Cuckoo indicators found, 0 otherwise
uint32_t CheckCuckooBackdoor(void);

/// @brief Measures the precision of RDTSC timing.
/// @return Minimum timing delta (high values = emulation)
uint64_t MeasureTimingPrecision(void);

/// @brief Detects timing-based debuggers via instruction timing analysis.
/// @return 1 if single-stepping detected, 0 otherwise
uint32_t DetectSingleStepTiming(void);

/// @brief Comprehensive VM detection via multiple timing measurements.
/// @return Combined overhead score (higher = more likely VM)
uint64_t MeasureVMExitOverhead(void);

/// @brief Establishes baseline timing values for detection.
void CalibrateTimingBaseline(void);

/// @brief Detects if timing functions are hooked.
/// @return 1 if timing hook detected, 0 otherwise
uint32_t DetectTimingHook(void);

/// @brief Measures memory access latency.
/// @return Memory access latency in cycles
uint64_t MeasureMemoryLatency(void);

/// @brief Checks CPUID hypervisor present bit.
/// @return 1 if hypervisor bit set, 0 otherwise
uint32_t CheckHypervisorBit(void);

/// @brief Measures interrupt handling overhead.
/// @return Interrupt overhead measurement
uint64_t MeasureIntOverhead(void);

/// @brief Computes RDTSC difference over a known delay.
/// @param iterations Number of loop iterations
/// @return Total RDTSC difference
uint64_t SandboxRDTSCDifference(uint32_t iterations);

/// @brief Estimates RDTSC frequency using CPUID.
/// @return Estimated frequency in Hz (0 if unavailable)
uint64_t GetRDTSCFrequency(void);

/// @brief Detects RDTSC emulation by checking for unrealistic values.
/// @return 1 if emulation detected, 0 otherwise
uint32_t DetectRDTSCEmulation(void);

#ifdef __cplusplus
}
#endif

// Forward declarations to avoid header pollution
namespace ShadowStrike::Utils {
    class ThreadPool;
    class TimerManager;
    namespace ProcessUtils {
        struct ProcessInfo;
        struct ProcessModuleInfo;
    }
    namespace FileUtils {
        struct FileInfo;
    }
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // FORWARD DECLARATIONS
        // ============================================================================

        class SandboxEvasionDetector;
        struct SandboxEvasionResult;
        struct SandboxIndicator;

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace SandboxConstants {
            // -------------------------------------------------------------------------
            // Hardware Thresholds
            // -------------------------------------------------------------------------
            // CRITICAL FIX (Issue #3): Reduced thresholds to prevent false positives
            // Modern cloud instances and containers legitimately have low resources:
            // - AWS t3.micro: 1GB RAM, 2 vCPU (FREE TIER)
            // - Azure B1s: 1GB RAM, 1 vCPU
            // - Kubernetes pods: Often have 512MB-2GB memory limits
            // - Docker containers: Resource-constrained by design
            // - IoT/Edge devices: 1-2GB RAM common

            /// @brief Minimum RAM size for non-sandbox system (bytes)
            /// Reduced from 4GB to 1GB to accommodate cloud instances
            constexpr uint64_t MIN_RAM_BYTES = 1ULL * 1024 * 1024 * 1024;  // 1GB (was 4GB)

            /// @brief Suspicious RAM threshold (likely sandbox)
            /// Reduced from 2GB to 512MB - only truly tiny VMs are suspicious
            constexpr uint64_t SUSPICIOUS_RAM_BYTES = 512ULL * 1024 * 1024;  // 512MB (was 2GB)

            /// @brief Minimum CPU cores for non-sandbox system
            /// Reduced to 1 - single-core VMs are legitimate (containers, edge)
            constexpr uint32_t MIN_CPU_CORES = 1;  // was 2

            /// @brief Suspicious CPU core count
            /// 0 cores is impossible, so this effectively disables CPU-based detection alone
            constexpr uint32_t SUSPICIOUS_CPU_CORES = 0;  // was 1

            /// @brief Minimum disk size for non-sandbox system (bytes)
            /// Reduced from 80GB to 20GB - containers use small disks
            constexpr uint64_t MIN_DISK_BYTES = 20ULL * 1024 * 1024 * 1024;  // 20GB (was 80GB)

            /// @brief Suspicious disk size
            /// Reduced from 40GB to 8GB - only very small disks are suspicious
            constexpr uint64_t SUSPICIOUS_DISK_BYTES = 8ULL * 1024 * 1024 * 1024;  // 8GB (was 40GB)

            // -------------------------------------------------------------------------
            // Timing Thresholds
            // -------------------------------------------------------------------------

            /// @brief Minimum uptime for non-sandbox system (milliseconds)
            constexpr uint64_t MIN_UPTIME_MS = 10 * 60 * 1000;  // 10 minutes

            /// @brief Suspicious uptime threshold
            constexpr uint64_t SUSPICIOUS_UPTIME_MS = 5 * 60 * 1000;  // 5 minutes

            /// @brief Very suspicious uptime (likely fresh sandbox)
            constexpr uint64_t VERY_SUSPICIOUS_UPTIME_MS = 2 * 60 * 1000;  // 2 minutes

            /// @brief Minimum system install age (days)
            constexpr uint32_t MIN_INSTALL_AGE_DAYS = 7;

            // -------------------------------------------------------------------------
            // Wear and Tear Thresholds
            // -------------------------------------------------------------------------

            /// @brief Minimum recent documents for non-sandbox
            constexpr size_t MIN_RECENT_DOCUMENTS = 10;

            /// @brief Minimum desktop files for non-sandbox
            constexpr size_t MIN_DESKTOP_FILES = 5;

            /// @brief Minimum installed programs for non-sandbox
            constexpr size_t MIN_INSTALLED_PROGRAMS = 20;

            /// @brief Minimum browser history entries
            constexpr size_t MIN_BROWSER_HISTORY = 50;

            /// @brief Minimum temp files for non-sandbox
            constexpr size_t MIN_TEMP_FILES = 100;

            /// @brief Minimum event log entries
            constexpr size_t MIN_EVENT_LOG_ENTRIES = 1000;

            // -------------------------------------------------------------------------
            // Screen/Display Thresholds
            // -------------------------------------------------------------------------

            /// @brief Suspicious screen width
            constexpr uint32_t SUSPICIOUS_SCREEN_WIDTH = 1024;

            /// @brief Very suspicious screen width
            constexpr uint32_t VERY_SUSPICIOUS_SCREEN_WIDTH = 800;

            /// @brief Suspicious screen height
            constexpr uint32_t SUSPICIOUS_SCREEN_HEIGHT = 768;

            /// @brief Very suspicious screen height  
            constexpr uint32_t VERY_SUSPICIOUS_SCREEN_HEIGHT = 600;

            /// @brief Minimum color depth (bits)
            constexpr uint32_t MIN_COLOR_DEPTH = 24;

            // -------------------------------------------------------------------------
            // Human Interaction Thresholds
            // -------------------------------------------------------------------------

            /// @brief Default monitoring duration for human interaction (ms)
            constexpr uint32_t DEFAULT_INTERACTION_MONITOR_MS = 5000;

            /// @brief Minimum monitoring duration (ms)
            constexpr uint32_t MIN_INTERACTION_MONITOR_MS = 1000;

            /// @brief Maximum monitoring duration (ms)
            constexpr uint32_t MAX_INTERACTION_MONITOR_MS = 60000;

            /// @brief Minimum mouse movements for human presence
            constexpr uint32_t MIN_MOUSE_MOVEMENTS = 5;

            /// @brief Minimum mouse movement distance (pixels)
            constexpr uint32_t MIN_MOUSE_DISTANCE = 100;

            /// @brief Maximum straight-line ratio (bot detection)
            constexpr double MAX_STRAIGHT_LINE_RATIO = 0.9;

            // -------------------------------------------------------------------------
            // Detection Limits
            // -------------------------------------------------------------------------

            /// @brief Maximum indicators to store
            constexpr size_t MAX_INDICATORS = 500;

            /// @brief Maximum sandbox artifacts to track
            constexpr size_t MAX_ARTIFACTS = 200;

            /// @brief Result cache TTL
            constexpr std::chrono::minutes RESULT_CACHE_TTL{ 10 };

            /// @brief Probability threshold for sandbox detection
            constexpr float SANDBOX_PROBABILITY_THRESHOLD = 60.0f;

            /// @brief High confidence threshold
            constexpr float HIGH_CONFIDENCE_THRESHOLD = 80.0f;
        }

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Known sandbox products that can be detected.
         */
        enum class SandboxProduct : uint16_t {
            /// @brief Unknown/unidentified sandbox
            Unknown = 0,

            // -------------------------------------------------------------------------
            // Open Source Sandboxes (1-49)
            // -------------------------------------------------------------------------

            /// @brief Cuckoo Sandbox (open source)
            Cuckoo = 1,

            /// @brief CAPE Sandbox (Cuckoo fork)
            CAPE = 2,

            /// @brief Drakvuf Sandbox
            Drakvuf = 3,

            /// @brief LiSa Sandbox
            LiSa = 4,

            // -------------------------------------------------------------------------
            // Commercial Sandboxes (50-99)
            // -------------------------------------------------------------------------

            /// @brief Joe Sandbox
            JoeSandbox = 50,

            /// @brief ANY.RUN Interactive Sandbox
            AnyRun = 51,

            /// @brief Hybrid Analysis (CrowdStrike)
            HybridAnalysis = 52,

            /// @brief VirusTotal Sandbox
            VirusTotal = 53,

            /// @brief VMRay Analyzer
            VMRay = 54,

            /// @brief FireEye AX
            FireEyeAX = 55,

            /// @brief Palo Alto WildFire
            WildFire = 56,

            /// @brief Cisco Threat Grid
            ThreatGrid = 57,

            /// @brief Triage (Hatching)
            Triage = 58,

            /// @brief Intezer Analyze
            Intezer = 59,

            /// @brief Lastline Analyst
            Lastline = 60,

            /// @brief Recorded Future Sandbox
            RecordedFuture = 61,

            // -------------------------------------------------------------------------
            // Desktop Sandboxes (100-149)
            // -------------------------------------------------------------------------

            /// @brief Sandboxie (Sophos)
            Sandboxie = 100,

            /// @brief Windows Sandbox
            WindowsSandbox = 101,

            /// @brief Comodo Virtual Desktop
            ComodoSandbox = 102,

            /// @brief Avast/AVG DeepScreen
            AvastDeepScreen = 103,

            /// @brief Bitdefender Active Threat Control
            BitdefenderATC = 104,

            /// @brief Kaspersky Safe Run
            KasperskySafeRun = 105,

            /// @brief Norton Sandbox
            NortonSandbox = 106,

            /// @brief ESET LiveGuard
            ESETLiveGuard = 107,

            // -------------------------------------------------------------------------
            // Enterprise Sandboxes (150-199)
            // -------------------------------------------------------------------------

            /// @brief CrowdStrike Falcon Sandbox
            FalconSandbox = 150,

            /// @brief Microsoft Defender for Endpoint
            DefenderATP = 151,

            /// @brief Carbon Black Cloud
            CarbonBlack = 152,

            /// @brief SentinelOne Deep Visibility
            SentinelOne = 153,

            /// @brief Cybereason Sandbox
            Cybereason = 154,

            /// @brief Sophos Intercept X
            SophosInterceptX = 155,

            /// @brief Trend Micro Deep Discovery
            TrendMicroDD = 156,

            /// @brief McAfee Advanced Threat Defense
            McAfeeATD = 157,

            // -------------------------------------------------------------------------
            // Research/Custom (200-254)
            // -------------------------------------------------------------------------

            /// @brief Generic analysis environment
            GenericAnalysis = 200,

            /// @brief Custom/internal sandbox
            CustomSandbox = 201,

            /// @brief Reserved
            Reserved = 254,

            /// @brief Multiple sandboxes detected
            Multiple = 255
        };

        /**
         * @brief Category of sandbox evasion indicator.
         */
        enum class SandboxIndicatorCategory : uint8_t {
            /// @brief Unknown category
            Unknown = 0,

            /// @brief Human interaction related
            HumanInteraction = 1,

            /// @brief Hardware fingerprinting
            Hardware = 2,

            /// @brief System wear and tear
            WearAndTear = 3,

            /// @brief Timing-based detection
            Timing = 4,

            /// @brief Sandbox artifact detection
            Artifact = 5,

            /// @brief Environment/display checks
            Environment = 6,

            /// @brief Network characteristics
            Network = 7,

            /// @brief File system analysis
            FileSystem = 8,

            /// @brief Process/service analysis
            Process = 9,

            /// @brief Registry analysis
            Registry = 10,

            /// @brief Driver/kernel analysis
            Kernel = 11
        };

        /**
         * @brief Severity of sandbox indicator.
         */
        enum class SandboxIndicatorSeverity : uint8_t {
            /// @brief Informational (common in normal systems too)
            Info = 0,

            /// @brief Low (slightly unusual)
            Low = 25,

            /// @brief Medium (suspicious)
            Medium = 50,

            /// @brief High (strong indicator)
            High = 75,

            /// @brief Critical (definitive sandbox marker)
            Critical = 100
        };

        /**
         * @brief Type of sandbox detection check.
         */
        enum class SandboxCheckType : uint8_t {
            /// @brief Unknown check type
            Unknown = 0,

            // -------------------------------------------------------------------------
            // Hardware Checks (1-29)
            // -------------------------------------------------------------------------

            /// @brief RAM size check
            RAMSize = 1,

            /// @brief CPU core count check
            CPUCores = 2,

            /// @brief Disk size check
            DiskSize = 3,

            /// @brief GPU presence/capabilities
            GPUPresence = 4,

            /// @brief Network adapter count
            NetworkAdapters = 5,

            /// @brief USB device history
            USBHistory = 6,

            /// @brief BIOS information
            BIOSInfo = 7,

            /// @brief Motherboard info
            MotherboardInfo = 8,

            /// @brief CPU model/features
            CPUModel = 9,

            /// @brief Storage type (SSD vs HDD)
            StorageType = 10,

            // -------------------------------------------------------------------------
            // Human Interaction Checks (30-49)
            // -------------------------------------------------------------------------

            /// @brief Mouse movement pattern
            MouseMovement = 30,

            /// @brief Mouse click pattern
            MouseClicks = 31,

            /// @brief Keyboard input
            KeyboardInput = 32,

            /// @brief Window focus changes
            WindowFocus = 33,

            /// @brief Clipboard activity
            ClipboardActivity = 34,

            /// @brief User idle time
            UserIdleTime = 35,

            /// @brief Scroll wheel usage
            ScrollWheel = 36,

            // -------------------------------------------------------------------------
            // Timing Checks (50-69)
            // -------------------------------------------------------------------------

            /// @brief System uptime
            SystemUptime = 50,

            /// @brief System install date
            InstallDate = 51,

            /// @brief Last boot time
            LastBootTime = 52,

            /// @brief Process creation times
            ProcessTimes = 53,

            /// @brief System time consistency
            TimeConsistency = 54,

            // -------------------------------------------------------------------------
            // Wear and Tear Checks (70-99)
            // -------------------------------------------------------------------------

            /// @brief Recent documents count
            RecentDocuments = 70,

            /// @brief Desktop file count
            DesktopFiles = 71,

            /// @brief Downloads folder analysis
            DownloadsFolder = 72,

            /// @brief Browser history
            BrowserHistory = 73,

            /// @brief Installed programs
            InstalledPrograms = 74,

            /// @brief Temp file analysis
            TempFiles = 75,

            /// @brief Event log depth
            EventLogDepth = 76,

            /// @brief Restore points
            RestorePoints = 77,

            /// @brief User profile count
            UserProfiles = 78,

            /// @brief Cookie/cache presence
            BrowserCache = 79,

            /// @brief Email client data
            EmailData = 80,

            /// @brief Media files
            MediaFiles = 81,

            // -------------------------------------------------------------------------
            // Environment Checks (100-129)
            // -------------------------------------------------------------------------

            /// @brief Screen resolution
            ScreenResolution = 100,

            /// @brief Color depth
            ColorDepth = 101,

            /// @brief Monitor count
            MonitorCount = 102,

            /// @brief Audio device presence
            AudioDevices = 103,

            /// @brief Printer presence
            Printers = 104,

            /// @brief Timezone consistency
            Timezone = 105,

            /// @brief Locale settings
            Locale = 106,

            /// @brief Font count
            FontCount = 107,

            /// @brief Wallpaper check
            Wallpaper = 108,

            /// @brief Theme/visual settings
            VisualSettings = 109,

            // -------------------------------------------------------------------------
            // Artifact Checks (130-169)
            // -------------------------------------------------------------------------

            /// @brief Sandbox DLLs
            SandboxDLLs = 130,

            /// @brief Sandbox processes
            SandboxProcesses = 131,

            /// @brief Sandbox services
            SandboxServices = 132,

            /// @brief Sandbox mutexes
            SandboxMutexes = 133,

            /// @brief Sandbox named pipes
            SandboxNamedPipes = 134,

            /// @brief Sandbox registry keys
            SandboxRegistry = 135,

            /// @brief Sandbox files
            SandboxFiles = 136,

            /// @brief Hook detection
            HookDetection = 137,

            /// @brief Agent detection
            AgentDetection = 138,

            /// @brief Analysis tool detection
            AnalysisTools = 139,

            // -------------------------------------------------------------------------
            // Network Checks (170-199)
            // -------------------------------------------------------------------------

            /// @brief DNS resolver analysis
            DNSResolver = 170,

            /// @brief Gateway fingerprint
            GatewayFingerprint = 171,

            /// @brief External IP analysis
            ExternalIP = 172,

            /// @brief Network latency
            NetworkLatency = 173,

            /// @brief Blocked ports
            BlockedPorts = 174,

            /// @brief Internet connectivity
            InternetConnectivity = 175,

            /// @brief MAC address analysis
            MACAddress = 176,

            // -------------------------------------------------------------------------
            // File System Checks (200-229)
            // -------------------------------------------------------------------------

            /// @brief System32 analysis
            System32Analysis = 200,

            /// @brief Program Files diversity
            ProgramFilesDiversity = 201,

            /// @brief User profile completeness
            ProfileCompleteness = 202,

            /// @brief Document metadata
            DocumentMetadata = 203,

            /// @brief File timestamps
            FileTimestamps = 204,

            /// @brief Hidden files
            HiddenFiles = 205
        };

        /**
         * @brief Human interaction analysis result.
         */
        enum class InteractionResult : uint8_t {
            /// @brief No analysis performed
            NotAnalyzed = 0,

            /// @brief Human interaction detected
            HumanDetected = 1,

            /// @brief No interaction detected (likely sandbox)
            NoInteraction = 2,

            /// @brief Bot-like patterns detected
            BotPatterns = 3,

            /// @brief Simulated interaction detected
            SimulatedInteraction = 4,

            /// @brief Analysis timed out
            Timeout = 5,

            /// @brief Analysis error
            Error = 6
        };

        /**
         * @brief Get string representation of sandbox product.
         */
        [[nodiscard]] constexpr const char* SandboxProductToString(SandboxProduct product) noexcept {
            switch (product) {
            case SandboxProduct::Unknown:           return "Unknown";
            case SandboxProduct::Cuckoo:            return "Cuckoo Sandbox";
            case SandboxProduct::CAPE:              return "CAPE Sandbox";
            case SandboxProduct::Drakvuf:           return "Drakvuf";
            case SandboxProduct::LiSa:              return "LiSa Sandbox";
            case SandboxProduct::JoeSandbox:        return "Joe Sandbox";
            case SandboxProduct::AnyRun:            return "ANY.RUN";
            case SandboxProduct::HybridAnalysis:    return "Hybrid Analysis";
            case SandboxProduct::VirusTotal:        return "VirusTotal";
            case SandboxProduct::VMRay:             return "VMRay";
            case SandboxProduct::FireEyeAX:         return "FireEye AX";
            case SandboxProduct::WildFire:          return "Palo Alto WildFire";
            case SandboxProduct::ThreatGrid:        return "Cisco Threat Grid";
            case SandboxProduct::Triage:            return "Triage (Hatching)";
            case SandboxProduct::Intezer:           return "Intezer Analyze";
            case SandboxProduct::Lastline:          return "Lastline";
            case SandboxProduct::RecordedFuture:    return "Recorded Future";
            case SandboxProduct::Sandboxie:         return "Sandboxie";
            case SandboxProduct::WindowsSandbox:    return "Windows Sandbox";
            case SandboxProduct::ComodoSandbox:     return "Comodo Sandbox";
            case SandboxProduct::AvastDeepScreen:   return "Avast DeepScreen";
            case SandboxProduct::BitdefenderATC:    return "Bitdefender ATC";
            case SandboxProduct::KasperskySafeRun:  return "Kaspersky Safe Run";
            case SandboxProduct::NortonSandbox:     return "Norton Sandbox";
            case SandboxProduct::ESETLiveGuard:     return "ESET LiveGuard";
            case SandboxProduct::FalconSandbox:     return "CrowdStrike Falcon Sandbox";
            case SandboxProduct::DefenderATP:       return "Microsoft Defender ATP";
            case SandboxProduct::CarbonBlack:       return "Carbon Black";
            case SandboxProduct::SentinelOne:       return "SentinelOne";
            case SandboxProduct::Cybereason:        return "Cybereason";
            case SandboxProduct::SophosInterceptX:  return "Sophos Intercept X";
            case SandboxProduct::TrendMicroDD:      return "Trend Micro Deep Discovery";
            case SandboxProduct::McAfeeATD:         return "McAfee ATD";
            case SandboxProduct::GenericAnalysis:   return "Generic Analysis Environment";
            case SandboxProduct::CustomSandbox:     return "Custom Sandbox";
            case SandboxProduct::Multiple:          return "Multiple Sandboxes";
            default:                                return "Unknown";
            }
        }

        /**
         * @brief Get string representation of indicator category.
         */
        [[nodiscard]] constexpr const char* SandboxIndicatorCategoryToString(SandboxIndicatorCategory category) noexcept {
            switch (category) {
            case SandboxIndicatorCategory::Unknown:          return "Unknown";
            case SandboxIndicatorCategory::HumanInteraction: return "Human Interaction";
            case SandboxIndicatorCategory::Hardware:         return "Hardware";
            case SandboxIndicatorCategory::WearAndTear:      return "Wear and Tear";
            case SandboxIndicatorCategory::Timing:           return "Timing";
            case SandboxIndicatorCategory::Artifact:         return "Artifact";
            case SandboxIndicatorCategory::Environment:      return "Environment";
            case SandboxIndicatorCategory::Network:          return "Network";
            case SandboxIndicatorCategory::FileSystem:       return "File System";
            case SandboxIndicatorCategory::Process:          return "Process";
            case SandboxIndicatorCategory::Registry:         return "Registry";
            case SandboxIndicatorCategory::Kernel:           return "Kernel";
            default:                                         return "Unknown";
            }
        }

        /**
         * @brief Get MITRE ATT&CK technique ID for sandbox evasion.
         */
        [[nodiscard]] constexpr const char* SandboxCheckToMitre(SandboxCheckType checkType) noexcept {
            // Most sandbox evasion maps to T1497.001 (System Checks)
            switch (checkType) {
            case SandboxCheckType::MouseMovement:
            case SandboxCheckType::MouseClicks:
            case SandboxCheckType::KeyboardInput:
            case SandboxCheckType::WindowFocus:
                return "T1497.001";  // System Checks - User Activity

            case SandboxCheckType::SystemUptime:
            case SandboxCheckType::InstallDate:
            case SandboxCheckType::LastBootTime:
                return "T1497.003";  // Time Based Evasion

            case SandboxCheckType::SandboxDLLs:
            case SandboxCheckType::SandboxProcesses:
            case SandboxCheckType::SandboxServices:
            case SandboxCheckType::HookDetection:
                return "T1497.001";  // System Checks - Software Detection

            default:
                return "T1497.001";  // Default to System Checks
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Individual sandbox indicator/finding.
         */
        struct SandboxIndicator {
            /// @brief Type of check that produced this indicator
            SandboxCheckType checkType = SandboxCheckType::Unknown;

            /// @brief Category of the indicator
            SandboxIndicatorCategory category = SandboxIndicatorCategory::Unknown;

            /// @brief Severity of the indicator
            SandboxIndicatorSeverity severity = SandboxIndicatorSeverity::Info;

            /// @brief Weight/score contribution (0.0 - 10.0)
            float weight = 1.0f;

            /// @brief Confidence in this indicator (0.0 - 100.0)
            float confidence = 0.0f;

            /// @brief Suspected sandbox product (if identifiable)
            SandboxProduct suspectedProduct = SandboxProduct::Unknown;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details
            std::wstring technicalDetails;

            /// @brief Observed value
            std::wstring observedValue;

            /// @brief Expected/normal value
            std::wstring expectedValue;

            /// @brief MITRE ATT&CK technique ID
            std::string mitreId;

            /// @brief Detection timestamp
            std::chrono::system_clock::time_point detectionTime{};

            /// @brief Whether this indicator alone is conclusive
            bool isConclusive = false;
        };

        /**
         * @brief Hardware profile of the analyzed system.
         */
        struct HardwareProfile {
            // -------------------------------------------------------------------------
            // Memory
            // -------------------------------------------------------------------------

            /// @brief Total physical RAM (bytes)
            uint64_t totalRAM = 0;

            /// @brief Available RAM (bytes)
            uint64_t availableRAM = 0;

            /// @brief Virtual memory limit (bytes)
            uint64_t virtualMemoryLimit = 0;

            // -------------------------------------------------------------------------
            // CPU
            // -------------------------------------------------------------------------

            /// @brief Logical processor count
            uint32_t logicalProcessors = 0;

            /// @brief Physical core count
            uint32_t physicalCores = 0;

            /// @brief CPU model string
            std::wstring cpuModel;

            /// @brief CPU vendor (Intel, AMD, etc.)
            std::wstring cpuVendor;

            /// @brief CPU frequency (MHz)
            uint32_t cpuFrequencyMHz = 0;

            /// @brief CPU features bitmask
            uint64_t cpuFeatures = 0;

            // -------------------------------------------------------------------------
            // Storage
            // -------------------------------------------------------------------------

            /// @brief Total disk space (bytes)
            uint64_t totalDiskSpace = 0;

            /// @brief Free disk space (bytes)
            uint64_t freeDiskSpace = 0;

            /// @brief Disk count
            uint32_t diskCount = 0;

            /// @brief Primary disk type (SSD, HDD, Virtual)
            std::wstring primaryDiskType;

            /// @brief Disk serial number
            std::wstring diskSerial;

            // -------------------------------------------------------------------------
            // Graphics
            // -------------------------------------------------------------------------

            /// @brief GPU present
            bool gpuPresent = false;

            /// @brief GPU model
            std::wstring gpuModel;

            /// @brief GPU vendor
            std::wstring gpuVendor;

            /// @brief Video RAM (bytes)
            uint64_t videoRAM = 0;

            // -------------------------------------------------------------------------
            // Network
            // -------------------------------------------------------------------------

            /// @brief Network adapter count
            uint32_t networkAdapterCount = 0;

            /// @brief Physical NIC present
            bool physicalNICPresent = false;

            /// @brief WiFi adapter present
            bool wifiPresent = false;

            /// @brief Bluetooth present
            bool bluetoothPresent = false;

            // -------------------------------------------------------------------------
            // Peripherals
            // -------------------------------------------------------------------------

            /// @brief USB device count (current)
            uint32_t usbDeviceCount = 0;

            /// @brief USB device history count
            uint32_t usbHistoryCount = 0;

            /// @brief Audio device present
            bool audioDevicePresent = false;

            /// @brief Webcam present
            bool webcamPresent = false;

            /// @brief Printer count
            uint32_t printerCount = 0;

            // -------------------------------------------------------------------------
            // BIOS/Firmware
            // -------------------------------------------------------------------------

            /// @brief BIOS vendor
            std::wstring biosVendor;

            /// @brief BIOS version
            std::wstring biosVersion;

            /// @brief BIOS date
            std::wstring biosDate;

            /// @brief System manufacturer
            std::wstring systemManufacturer;

            /// @brief System model
            std::wstring systemModel;

            /// @brief System serial
            std::wstring systemSerial;

            // -------------------------------------------------------------------------
            // Analysis Results
            // -------------------------------------------------------------------------

            /// @brief Hardware suspicion score (0.0 - 100.0)
            float suspicionScore = 0.0f;

            /// @brief Whether hardware profile is sandbox-like
            bool isSandboxLike = false;

            /// @brief Specific hardware issues found
            std::vector<std::wstring> issues;
        };

        /**
         * @brief System wear and tear analysis results.
         */
        struct WearAndTearAnalysis {
            // -------------------------------------------------------------------------
            // Document Counts
            // -------------------------------------------------------------------------

            /// @brief Recent documents count
            size_t recentDocumentsCount = 0;

            /// @brief Desktop file count
            size_t desktopFileCount = 0;

            /// @brief Downloads folder file count
            size_t downloadsFileCount = 0;

            /// @brief Documents folder file count
            size_t documentsFileCount = 0;

            /// @brief Pictures folder file count
            size_t picturesFileCount = 0;

            // -------------------------------------------------------------------------
            // Browser Data
            // -------------------------------------------------------------------------

            /// @brief Total browser history entries
            size_t browserHistoryCount = 0;

            /// @brief Browser cookie count
            size_t browserCookieCount = 0;

            /// @brief Saved password count
            size_t savedPasswordCount = 0;

            /// @brief Browser bookmark count
            size_t bookmarkCount = 0;

            /// @brief Browser extensions count
            size_t browserExtensionCount = 0;

            // -------------------------------------------------------------------------
            // System Metrics
            // -------------------------------------------------------------------------

            /// @brief Installed program count
            size_t installedProgramCount = 0;

            /// @brief Windows update count
            size_t windowsUpdateCount = 0;

            /// @brief Event log entry count
            size_t eventLogEntryCount = 0;

            /// @brief Prefetch file count
            size_t prefetchFileCount = 0;

            /// @brief Temp file count
            size_t tempFileCount = 0;

            /// @brief Recycle bin item count
            size_t recycleBinCount = 0;

            /// @brief Restore point count
            size_t restorePointCount = 0;

            /// @brief User profile count
            size_t userProfileCount = 0;

            // -------------------------------------------------------------------------
            // Font/Theme
            // -------------------------------------------------------------------------

            /// @brief Installed font count
            size_t fontCount = 0;

            /// @brief Custom themes present
            bool customThemesPresent = false;

            /// @brief Custom wallpaper set
            bool customWallpaper = false;

            // -------------------------------------------------------------------------
            // Communication Data
            // -------------------------------------------------------------------------

            /// @brief Email account configured
            bool emailConfigured = false;

            /// @brief IM apps installed count
            size_t imAppsCount = 0;

            // -------------------------------------------------------------------------
            // Analysis Results
            // -------------------------------------------------------------------------

            /// @brief Wear and tear score (0.0 - 100.0, higher = more used)
            float usageScore = 0.0f;

            /// @brief Whether system appears freshly installed
            bool appearsFresh = false;

            /// @brief Specific wear issues
            std::vector<std::wstring> issues;
        };

        /**
         * @brief Human interaction analysis results.
         */
        struct HumanInteractionAnalysis {
            // -------------------------------------------------------------------------
            // Monitoring Parameters
            // -------------------------------------------------------------------------

            /// @brief Monitoring duration (milliseconds)
            uint32_t monitoringDurationMs = 0;

            /// @brief Analysis start time
            std::chrono::steady_clock::time_point startTime{};

            /// @brief Analysis end time
            std::chrono::steady_clock::time_point endTime{};

            // -------------------------------------------------------------------------
            // Mouse Analysis
            // -------------------------------------------------------------------------

            /// @brief Total mouse movements detected
            uint32_t mouseMovementCount = 0;

            /// @brief Total mouse distance traveled (pixels)
            uint64_t mouseDistanceTraveled = 0;

            /// @brief Mouse click count (all buttons)
            uint32_t mouseClickCount = 0;

            /// @brief Left click count
            uint32_t leftClickCount = 0;

            /// @brief Right click count
            uint32_t rightClickCount = 0;

            /// @brief Double click count
            uint32_t doubleClickCount = 0;

            /// @brief Scroll wheel events
            uint32_t scrollWheelEvents = 0;

            /// @brief Average mouse velocity (pixels/second)
            double avgMouseVelocity = 0.0;

            /// @brief Maximum mouse velocity
            double maxMouseVelocity = 0.0;

            /// @brief Straight line ratio (bot indicator, 0.0-1.0)
            double straightLineRatio = 0.0;

            /// @brief Mouse path entropy (randomness measure)
            double pathEntropy = 0.0;

            // -------------------------------------------------------------------------
            // Keyboard Analysis
            // -------------------------------------------------------------------------

            /// @brief Total key presses
            uint32_t keyPressCount = 0;

            /// @brief Unique keys pressed
            uint32_t uniqueKeysPressed = 0;

            /// @brief Average typing speed (keys/minute)
            double avgTypingSpeed = 0.0;

            /// @brief Key press timing variance
            double keyTimingVariance = 0.0;

            // -------------------------------------------------------------------------
            // Window/Focus Analysis
            // -------------------------------------------------------------------------

            /// @brief Window focus changes
            uint32_t windowFocusChanges = 0;

            /// @brief Applications interacted with
            uint32_t applicationsInteracted = 0;

            /// @brief Clipboard operations
            uint32_t clipboardOperations = 0;

            // -------------------------------------------------------------------------
            // Results
            // -------------------------------------------------------------------------

            /// @brief Overall interaction result
            InteractionResult result = InteractionResult::NotAnalyzed;

            /// @brief Human presence confidence (0.0 - 100.0)
            float humanConfidence = 0.0f;

            /// @brief Bot/automation confidence (0.0 - 100.0)
            float botConfidence = 0.0f;

            /// @brief Simulated interaction confidence
            float simulatedConfidence = 0.0f;

            /// @brief Analysis successful
            bool analysisComplete = false;

            /// @brief Error message (if any)
            std::wstring errorMessage;

            /// @brief Detailed findings
            std::vector<std::wstring> findings;
        };

        /**
         * @brief Environment analysis results.
         */
        struct EnvironmentAnalysis {
            // -------------------------------------------------------------------------
            // Display
            // -------------------------------------------------------------------------

            /// @brief Primary screen width (pixels)
            uint32_t screenWidth = 0;

            /// @brief Primary screen height (pixels)
            uint32_t screenHeight = 0;

            /// @brief Color depth (bits)
            uint32_t colorDepth = 0;

            /// @brief Monitor count
            uint32_t monitorCount = 0;

            /// @brief DPI setting
            uint32_t dpi = 0;

            /// @brief Screen is standard VM resolution
            bool isVMResolution = false;

            // -------------------------------------------------------------------------
            // Locale/Time
            // -------------------------------------------------------------------------

            /// @brief System timezone
            std::wstring timezone;

            /// @brief System locale
            std::wstring locale;

            /// @brief Keyboard layout
            std::wstring keyboardLayout;

            /// @brief Date format
            std::wstring dateFormat;

            /// @brief Time format
            std::wstring timeFormat;

            /// @brief Timezone consistent with IP geolocation
            bool timezoneConsistent = true;

            // -------------------------------------------------------------------------
            // System Info
            // -------------------------------------------------------------------------

            /// @brief Computer name
            std::wstring computerName;

            /// @brief Domain/workgroup
            std::wstring domain;

            /// @brief User name
            std::wstring userName;

            /// @brief Windows version
            std::wstring windowsVersion;

            /// @brief Windows build number
            uint32_t windowsBuild = 0;

            /// @brief Is Windows activated
            bool windowsActivated = false;

            // -------------------------------------------------------------------------
            // Analysis Results
            // -------------------------------------------------------------------------

            /// @brief Environment suspicion score (0.0 - 100.0)
            float suspicionScore = 0.0f;

            /// @brief Issues found
            std::vector<std::wstring> issues;
        };

        /**
         * @brief Sandbox artifact analysis results.
         */
        struct ArtifactAnalysis {
            // -------------------------------------------------------------------------
            // DLLs
            // -------------------------------------------------------------------------

            /// @brief Sandbox DLLs detected
            std::vector<std::wstring> sandboxDLLs;

            /// @brief Hook DLLs detected
            std::vector<std::wstring> hookDLLs;

            /// @brief Suspicious DLL count
            size_t suspiciousDLLCount = 0;

            // -------------------------------------------------------------------------
            // Processes
            // -------------------------------------------------------------------------

            /// @brief Sandbox processes detected
            std::vector<std::wstring> sandboxProcesses;

            /// @brief Analysis tool processes
            std::vector<std::wstring> analysisToolProcesses;

            /// @brief Suspicious process count
            size_t suspiciousProcessCount = 0;

            // -------------------------------------------------------------------------
            // Services
            // -------------------------------------------------------------------------

            /// @brief Sandbox services detected
            std::vector<std::wstring> sandboxServices;

            /// @brief Suspicious service count
            size_t suspiciousServiceCount = 0;

            // -------------------------------------------------------------------------
            // Named Objects
            // -------------------------------------------------------------------------

            /// @brief Sandbox mutexes detected
            std::vector<std::wstring> sandboxMutexes;

            /// @brief Sandbox named pipes detected
            std::vector<std::wstring> sandboxNamedPipes;

            /// @brief Sandbox events detected
            std::vector<std::wstring> sandboxEvents;

            // -------------------------------------------------------------------------
            // Registry
            // -------------------------------------------------------------------------

            /// @brief Sandbox registry keys detected
            std::vector<std::wstring> sandboxRegistryKeys;

            /// @brief Suspicious registry value count
            size_t suspiciousRegistryCount = 0;

            // -------------------------------------------------------------------------
            // Files
            // -------------------------------------------------------------------------

            /// @brief Sandbox files detected
            std::vector<std::wstring> sandboxFiles;

            /// @brief Sandbox directories detected
            std::vector<std::wstring> sandboxDirectories;

            // -------------------------------------------------------------------------
            // Hook Detection
            // -------------------------------------------------------------------------

            /// @brief API hooks detected
            bool apiHooksDetected = false;

            /// @brief Hooked API count
            size_t hookedAPICount = 0;

            /// @brief Hooked APIs
            std::vector<std::wstring> hookedAPIs;

            // -------------------------------------------------------------------------
            // Results
            // -------------------------------------------------------------------------

            /// @brief Identified sandbox products
            std::vector<SandboxProduct> identifiedProducts;

            /// @brief Primary suspected sandbox
            SandboxProduct primarySuspect = SandboxProduct::Unknown;

            /// @brief Artifact suspicion score (0.0 - 100.0)
            float suspicionScore = 0.0f;

            /// @brief Total artifacts found
            size_t totalArtifactsFound = 0;

            /// @brief Definitive sandbox detection (conclusive evidence)
            bool definitiveDetection = false;
        };

        /**
         * @brief Comprehensive sandbox evasion analysis result.
         */
        struct SandboxEvasionResult {
            // -------------------------------------------------------------------------
            // Core Detection Status
            // -------------------------------------------------------------------------

            /// @brief Whether sandbox is likely (based on threshold)
            bool isSandboxLikely = false;

            /// @brief Sandbox probability (0.0 - 100.0)
            float probability = 0.0f;

            /// @brief Overall confidence in detection
            float confidence = 0.0f;

            /// @brief Whether detection is definitive/conclusive
            bool isDefinitive = false;

            // -------------------------------------------------------------------------
            // Identified Sandbox
            // -------------------------------------------------------------------------

            /// @brief Primary identified sandbox product
            SandboxProduct identifiedSandbox = SandboxProduct::Unknown;

            /// @brief All suspected sandbox products
            std::vector<SandboxProduct> suspectedProducts;

            /// @brief Sandbox product name (string)
            std::wstring sandboxName;

            // -------------------------------------------------------------------------
            // Detailed Analysis Results
            // -------------------------------------------------------------------------

            /// @brief Hardware profile analysis
            HardwareProfile hardware;

            /// @brief Wear and tear analysis
            WearAndTearAnalysis wearAndTear;

            /// @brief Human interaction analysis (if performed)
            std::optional<HumanInteractionAnalysis> humanInteraction;

            /// @brief Environment analysis
            EnvironmentAnalysis environment;

            /// @brief Artifact analysis
            ArtifactAnalysis artifacts;

            // -------------------------------------------------------------------------
            // Indicators
            // -------------------------------------------------------------------------

            /// @brief All detected indicators
            std::vector<SandboxIndicator> indicators;

            /// @brief Summary messages
            std::vector<std::wstring> summaryMessages;

            /// @brief Failed check count
            uint32_t failedChecks = 0;

            /// @brief Passed check count
            uint32_t passedChecks = 0;

            /// @brief Total checks performed
            uint32_t totalChecks = 0;

            // -------------------------------------------------------------------------
            // Category Scores
            // -------------------------------------------------------------------------

            /// @brief Hardware score (0.0 - 100.0)
            float hardwareScore = 0.0f;

            /// @brief Wear and tear score
            float wearAndTearScore = 0.0f;

            /// @brief Human interaction score
            float humanInteractionScore = 0.0f;

            /// @brief Environment score
            float environmentScore = 0.0f;

            /// @brief Artifact score
            float artifactScore = 0.0f;

            /// @brief Timing score
            float timingScore = 0.0f;

            /// @brief Network score
            float networkScore = 0.0f;

            // -------------------------------------------------------------------------
            // MITRE ATT&CK
            // -------------------------------------------------------------------------

            /// @brief MITRE technique IDs detected
            std::vector<std::string> mitreIds;

            /// @brief Primary MITRE tactic
            std::string mitreTactic = "TA0005";  // Defense Evasion

            // -------------------------------------------------------------------------
            // Metadata
            // -------------------------------------------------------------------------

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime{};

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime{};

            /// @brief Analysis duration (milliseconds)
            uint64_t analysisDurationMs = 0;

            /// @brief Analysis completed successfully
            bool analysisComplete = false;

            /// @brief Error message (if any)
            std::wstring errorMessage;

            // -------------------------------------------------------------------------
            // Utility Methods
            // -------------------------------------------------------------------------

            /**
             * @brief Get human-readable summary.
             */
            [[nodiscard]] std::wstring GetSummary() const {
                std::wstring summary;
                summary.reserve(256);

                if (isSandboxLikely) {
                    summary = L"SANDBOX DETECTED: ";
                    if (identifiedSandbox != SandboxProduct::Unknown) {
                        summary += std::wstring(sandboxName);
                    }
                    else {
                        summary += L"Unknown sandbox";
                    }
                    summary += L" (Probability: " + std::to_wstring(static_cast<int>(probability)) + L"%)";
                }
                else {
                    summary = L"No sandbox detected (Probability: " +
                        std::to_wstring(static_cast<int>(probability)) + L"%)";
                }

                return summary;
            }

            /**
             * @brief Check if specific category detected issues.
             */
            [[nodiscard]] bool HasCategoryIssues(SandboxIndicatorCategory category) const noexcept {
                for (const auto& indicator : indicators) {
                    if (indicator.category == category &&
                        indicator.severity >= SandboxIndicatorSeverity::Medium) {
                        return true;
                    }
                }
                return false;
            }

            /**
             * @brief Get indicator count by category.
             */
            [[nodiscard]] size_t GetIndicatorCount(SandboxIndicatorCategory category) const noexcept {
                size_t count = 0;
                for (const auto& indicator : indicators) {
                    if (indicator.category == category) {
                        ++count;
                    }
                }
                return count;
            }

            /**
             * @brief Get highest severity indicator.
             */
            [[nodiscard]] std::optional<SandboxIndicator> GetHighestSeverityIndicator() const {
                if (indicators.empty()) return std::nullopt;

                const SandboxIndicator* highest = &indicators[0];
                for (const auto& indicator : indicators) {
                    if (static_cast<uint8_t>(indicator.severity) >
                        static_cast<uint8_t>(highest->severity)) {
                        highest = &indicator;
                    }
                }
                return *highest;
            }

            /**
             * @brief Clear all result data.
             */
            void Clear() noexcept {
                isSandboxLikely = false;
                probability = 0.0f;
                confidence = 0.0f;
                isDefinitive = false;
                identifiedSandbox = SandboxProduct::Unknown;
                suspectedProducts.clear();
                sandboxName.clear();
                hardware = HardwareProfile{};
                wearAndTear = WearAndTearAnalysis{};
                humanInteraction.reset();
                environment = EnvironmentAnalysis{};
                artifacts = ArtifactAnalysis{};
                indicators.clear();
                summaryMessages.clear();
                failedChecks = 0;
                passedChecks = 0;
                totalChecks = 0;
                hardwareScore = 0.0f;
                wearAndTearScore = 0.0f;
                humanInteractionScore = 0.0f;
                environmentScore = 0.0f;
                artifactScore = 0.0f;
                timingScore = 0.0f;
                networkScore = 0.0f;
                mitreIds.clear();
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                analysisComplete = false;
                errorMessage.clear();
            }
        };

        /**
         * @brief Configuration for sandbox evasion detection.
         */
        struct SandboxDetectorConfig {
            // -------------------------------------------------------------------------
            // General Settings
            // -------------------------------------------------------------------------

            /// @brief Enable detection
            bool enabled = true;

            /// @brief Probability threshold for sandbox detection
            float probabilityThreshold = SandboxConstants::SANDBOX_PROBABILITY_THRESHOLD;

            /// @brief Enable result caching
            bool enableCache = true;

            /// @brief Cache TTL
            std::chrono::minutes cacheTTL = SandboxConstants::RESULT_CACHE_TTL;

            // -------------------------------------------------------------------------
            // Check Categories
            // -------------------------------------------------------------------------

            /// @brief Enable hardware checks
            bool checkHardware = true;

            /// @brief Enable wear and tear checks
            bool checkWearAndTear = true;

            /// @brief Enable human interaction checks
            bool checkHumanInteraction = true;

            /// @brief Enable environment checks
            bool checkEnvironment = true;

            /// @brief Enable artifact checks
            bool checkArtifacts = true;

            /// @brief Enable timing checks
            bool checkTiming = true;

            /// @brief Enable network checks
            bool checkNetwork = true;

            /// @brief Enable file system checks
            bool checkFileSystem = true;

            // -------------------------------------------------------------------------
            // Hardware Thresholds
            // -------------------------------------------------------------------------

            /// @brief Minimum RAM (bytes)
            uint64_t minRAM = SandboxConstants::MIN_RAM_BYTES;

            /// @brief Minimum CPU cores
            uint32_t minCPUCores = SandboxConstants::MIN_CPU_CORES;

            /// @brief Minimum disk size (bytes)
            uint64_t minDiskSize = SandboxConstants::MIN_DISK_BYTES;

            // -------------------------------------------------------------------------
            // Timing Thresholds
            // -------------------------------------------------------------------------

            /// @brief Minimum uptime (milliseconds)
            uint64_t minUptime = SandboxConstants::MIN_UPTIME_MS;

            /// @brief Minimum install age (days)
            uint32_t minInstallAgeDays = SandboxConstants::MIN_INSTALL_AGE_DAYS;

            // -------------------------------------------------------------------------
            // Wear and Tear Thresholds
            // -------------------------------------------------------------------------

            /// @brief Minimum recent documents
            size_t minRecentDocuments = SandboxConstants::MIN_RECENT_DOCUMENTS;

            /// @brief Minimum installed programs
            size_t minInstalledPrograms = SandboxConstants::MIN_INSTALLED_PROGRAMS;

            /// @brief Minimum browser history
            size_t minBrowserHistory = SandboxConstants::MIN_BROWSER_HISTORY;

            // -------------------------------------------------------------------------
            // Human Interaction Settings
            // -------------------------------------------------------------------------

            /// @brief Default monitoring duration (milliseconds)
            uint32_t humanInteractionMonitorMs = SandboxConstants::DEFAULT_INTERACTION_MONITOR_MS;

            /// @brief Minimum mouse movements required
            uint32_t minMouseMovements = SandboxConstants::MIN_MOUSE_MOVEMENTS;

            /// @brief Minimum mouse distance required (pixels)
            uint32_t minMouseDistance = SandboxConstants::MIN_MOUSE_DISTANCE;

            // -------------------------------------------------------------------------
            // Screen Thresholds
            // -------------------------------------------------------------------------

            /// @brief Suspicious screen width
            uint32_t suspiciousScreenWidth = SandboxConstants::SUSPICIOUS_SCREEN_WIDTH;

            /// @brief Suspicious screen height
            uint32_t suspiciousScreenHeight = SandboxConstants::SUSPICIOUS_SCREEN_HEIGHT;

            // -------------------------------------------------------------------------
            // Weight Configuration
            // -------------------------------------------------------------------------

            /// @brief Hardware category weight
            float hardwareWeight = 1.5f;

            /// @brief Wear and tear category weight
            float wearAndTearWeight = 1.0f;

            /// @brief Human interaction category weight
            float humanInteractionWeight = 2.0f;

            /// @brief Environment category weight
            float environmentWeight = 1.0f;

            /// @brief Artifact category weight
            float artifactWeight = 3.0f;

            /// @brief Timing category weight
            float timingWeight = 1.2f;

            /// @brief Network category weight
            float networkWeight = 0.8f;

            // -------------------------------------------------------------------------
            // Factory Methods
            // -------------------------------------------------------------------------

            /**
             * @brief Create default configuration.
             */
            [[nodiscard]] static SandboxDetectorConfig CreateDefault() noexcept {
                return SandboxDetectorConfig{};
            }

            /**
             * @brief Create high-sensitivity configuration.
             */
            [[nodiscard]] static SandboxDetectorConfig CreateHighSensitivity() noexcept {
                SandboxDetectorConfig config;
                config.probabilityThreshold = 40.0f;
                config.minRAM = 8ULL * 1024 * 1024 * 1024;
                config.minCPUCores = 4;
                config.minDiskSize = 120ULL * 1024 * 1024 * 1024;
                config.minUptime = 30 * 60 * 1000;  // 30 minutes
                config.minRecentDocuments = 20;
                config.minInstalledPrograms = 50;
                return config;
            }

            /**
             * @brief Create fast/minimal configuration.
             */
            [[nodiscard]] static SandboxDetectorConfig CreateFast() noexcept {
                SandboxDetectorConfig config;
                config.checkHumanInteraction = false;
                config.checkNetwork = false;
                config.checkFileSystem = false;
                config.checkWearAndTear = false;
                return config;
            }
        };

        /**
         * @brief Statistics for sandbox detection.
         */
        struct SandboxDetectorStats {
            /// @brief Total scans performed
            std::atomic<uint64_t> totalScans{ 0 };

            /// @brief Sandboxes detected
            std::atomic<uint64_t> sandboxesDetected{ 0 };

            /// @brief Definitive detections
            std::atomic<uint64_t> definitiveDetections{ 0 };

            /// @brief Human interaction checks performed
            std::atomic<uint64_t> humanInteractionChecks{ 0 };

            /// @brief Cache hits
            std::atomic<uint64_t> cacheHits{ 0 };

            /// @brief Cache misses
            std::atomic<uint64_t> cacheMisses{ 0 };

            /// @brief Average analysis duration (microseconds)
            std::atomic<uint64_t> avgAnalysisDurationUs{ 0 };

            /// @brief Detection counts by product
            std::array<std::atomic<uint64_t>, 256> detectionsByProduct{};

            /**
             * @brief Reset all statistics.
             */
            void Reset() noexcept {
                totalScans.store(0, std::memory_order_relaxed);
                sandboxesDetected.store(0, std::memory_order_relaxed);
                definitiveDetections.store(0, std::memory_order_relaxed);
                humanInteractionChecks.store(0, std::memory_order_relaxed);
                cacheHits.store(0, std::memory_order_relaxed);
                cacheMisses.store(0, std::memory_order_relaxed);
                avgAnalysisDurationUs.store(0, std::memory_order_relaxed);
                for (auto& count : detectionsByProduct) {
                    count.store(0, std::memory_order_relaxed);
                }
            }
        };

        /**
         * @brief Callback for sandbox detection notifications.
         */
        using SandboxDetectionCallback = std::function<void(const SandboxEvasionResult&)>;

        // ============================================================================
        // KNOWN SANDBOX ARTIFACTS
        // ============================================================================

        /**
         * @brief Known sandbox DLLs to detect.
         */
        namespace KnownSandboxDLLs {
            /// @brief Sandboxie DLL
            constexpr std::wstring_view SBIEDLL = L"SbieDll.dll";

            /// @brief Cuckoo monitor DLL
            constexpr std::wstring_view CUCKOOMON = L"cuckoomon.dll";

            /// @brief Avast sandbox hook
            constexpr std::wstring_view SNXHK = L"snxhk.dll";

            /// @brief VMRay DLL
            constexpr std::wstring_view VMRAY = L"vmray_api.dll";

            /// @brief Joe Sandbox DLL
            constexpr std::wstring_view JOEBOX = L"joeboxcontrol.dll";

            /// @brief API Monitor DLL
            constexpr std::wstring_view APIMON = L"apimonitor.dll";

            /// @brief Comodo guard DLL
            constexpr std::wstring_view GUARD32 = L"guard32.dll";

            /// @brief Comodo guard DLL (64-bit)
            constexpr std::wstring_view GUARD64 = L"guard64.dll";

            /// @brief WPE Pro DLL
            constexpr std::wstring_view WPEPRO = L"wpepro.dll";

            /// @brief x64dbg plugin DLL
            constexpr std::wstring_view X64DBG = L"x64dbg.dll";
        }

        /**
         * @brief Known sandbox process names.
         */
        namespace KnownSandboxProcesses {
            constexpr std::wstring_view CUCKOO_AGENT = L"agent.py";
            constexpr std::wstring_view PYTHON_CUCKOO = L"python.exe";
            constexpr std::wstring_view JOEBOX_SERVER = L"joeboxserver.exe";
            constexpr std::wstring_view JOEBOX_CONTROL = L"joeboxcontrol.exe";
            constexpr std::wstring_view SANDBOXIE_CONTROL = L"SbieCtrl.exe";
            constexpr std::wstring_view SANDBOXIE_SVC = L"SbieSvc.exe";
            constexpr std::wstring_view ANYRUN = L"anyrun.exe";
            constexpr std::wstring_view VMRAY_SVC = L"vmray-service.exe";
            constexpr std::wstring_view WINDOWS_SANDBOX = L"WindowsSandboxClient.exe";
            constexpr std::wstring_view WIRESHARK = L"Wireshark.exe";
            constexpr std::wstring_view PROCMON = L"Procmon.exe";
            constexpr std::wstring_view PROCMON64 = L"Procmon64.exe";
            constexpr std::wstring_view FIDDLER = L"Fiddler.exe";
            constexpr std::wstring_view OLLYDBG = L"ollydbg.exe";
            constexpr std::wstring_view X64DBG = L"x64dbg.exe";
            constexpr std::wstring_view X32DBG = L"x32dbg.exe";
            constexpr std::wstring_view IDA = L"ida.exe";
            constexpr std::wstring_view IDA64 = L"ida64.exe";
        }

        /**
         * @brief Known sandbox mutexes.
         */
        namespace KnownSandboxMutexes {
            constexpr std::wstring_view SANDBOXIE = L"Sandboxie_SingleInstanceMutex_Control";
            constexpr std::wstring_view CUCKOO = L"CuckooMutex";
            constexpr std::wstring_view JOEBOX = L"JoeBoxMutex";
            constexpr std::wstring_view VMRAY = L"VMRayMutex";
        }

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade sandbox evasion detector.
         *
         * Provides comprehensive detection of malware sandbox evasion techniques
         * including hardware profiling, wear and tear analysis, human interaction
         * verification, artifact scanning, and environment checks.
         *
         * Thread Safety: All public methods are thread-safe.
         *
         * Usage Example:
         * @code
         * auto& detector = SandboxEvasionDetector::Instance();
         *
         * // Initialize with custom configuration
         * SandboxDetectorConfig config = SandboxDetectorConfig::CreateHighSensitivity();
         * detector.Initialize(threadPool, config);
         *
         * // Perform full system scan
         * auto result = detector.ScanSystem();
         * if (result.isSandboxLikely) {
         *     LOG_WARN(L"Sandbox detected: {} ({}%)",
         *              SandboxProductToString(result.identifiedSandbox),
         *              result.probability);
         * }
         *
         * // Verify human presence
         * bool humanPresent = detector.VerifyHumanInteraction(5000);
         *
         * // Get hardware profile
         * auto hwProfile = detector.GetHardwareProfile();
         *
         * detector.Shutdown();
         * @endcode
         */
        class SandboxEvasionDetector {
        public:
            // =========================================================================
            // Singleton Access
            // =========================================================================

            /**
             * @brief Get the singleton instance.
             * @return Reference to the global SandboxEvasionDetector instance.
             * @note Thread-safe (Meyers' singleton).
             */
            [[nodiscard]] static SandboxEvasionDetector& Instance();

            // Non-copyable, non-movable
            SandboxEvasionDetector(const SandboxEvasionDetector&) = delete;
            SandboxEvasionDetector& operator=(const SandboxEvasionDetector&) = delete;
            SandboxEvasionDetector(SandboxEvasionDetector&&) = delete;
            SandboxEvasionDetector& operator=(SandboxEvasionDetector&&) = delete;

            // =========================================================================
            // Lifecycle Management
            // =========================================================================

            /**
             * @brief Initialize the detector with default configuration.
             * @param threadPool Shared pointer to thread pool for async operations.
             * @return true on success, false on failure.
             */
            [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

            /**
             * @brief Initialize the detector with custom configuration.
             * @param threadPool Shared pointer to thread pool.
             * @param config Detection configuration.
             * @return true on success, false on failure.
             */
            [[nodiscard]] bool Initialize(
                std::shared_ptr<Utils::ThreadPool> threadPool,
                const SandboxDetectorConfig& config
            );

            /**
             * @brief Shutdown the detector and release resources.
             */
            void Shutdown();

            /**
             * @brief Check if detector is initialized.
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            /**
             * @brief Update configuration at runtime.
             * @param config New configuration.
             */
            void UpdateConfig(const SandboxDetectorConfig& config);

            /**
             * @brief Get current configuration.
             */
            [[nodiscard]] SandboxDetectorConfig GetConfig() const;

            // =========================================================================
            // Full System Scan
            // =========================================================================

            /**
             * @brief Performs a comprehensive system scan for sandbox characteristics.
             * @return Complete analysis result.
             * @note This may take several seconds depending on configuration.
             */
            [[nodiscard]] SandboxEvasionResult ScanSystem();

            /**
             * @brief Perform async system scan.
             * @param callback Callback invoked when scan completes.
             * @return true if scan started successfully.
             */
            [[nodiscard]] bool ScanSystemAsync(std::function<void(SandboxEvasionResult)> callback);

            /**
             * @brief Quick scan with minimal checks.
             * @return true if sandbox likely, false otherwise.
             * @note Faster but less comprehensive than ScanSystem().
             */
            [[nodiscard]] bool QuickScan();

            // =========================================================================
            // Individual Analysis Methods
            // =========================================================================

            /**
             * @brief Analyze hardware profile.
             * @return Hardware analysis results.
             */
            [[nodiscard]] HardwareProfile AnalyzeHardware();

            /**
             * @brief Analyze system wear and tear.
             * @return Wear and tear analysis results.
             */
            [[nodiscard]] WearAndTearAnalysis AnalyzeWearAndTear();

            /**
             * @brief Analyze environment characteristics.
             * @return Environment analysis results.
             */
            [[nodiscard]] EnvironmentAnalysis AnalyzeEnvironment();

            /**
             * @brief Scan for sandbox artifacts.
             * @return Artifact analysis results.
             */
            [[nodiscard]] ArtifactAnalysis ScanArtifacts();

            /**
             * @brief Monitors user input to verify human presence.
             * @param monitoringDurationMs Duration to monitor (milliseconds).
             * @return true if human interaction pattern is detected.
             */
            [[nodiscard]] bool VerifyHumanInteraction(
                uint32_t monitoringDurationMs = SandboxConstants::DEFAULT_INTERACTION_MONITOR_MS
            );

            /**
             * @brief Detailed human interaction analysis.
             * @param monitoringDurationMs Duration to monitor.
             * @return Detailed interaction analysis results.
             */
            [[nodiscard]] HumanInteractionAnalysis AnalyzeHumanInteraction(
                uint32_t monitoringDurationMs = SandboxConstants::DEFAULT_INTERACTION_MONITOR_MS
            );

            // =========================================================================
            // Specific Checks
            // =========================================================================

            /**
             * @brief Check if specific sandbox product is detected.
             * @param product Sandbox product to check for.
             * @return true if product is detected.
             */
            [[nodiscard]] bool IsSandboxProductDetected(SandboxProduct product);

            /**
             * @brief Get system uptime.
             * @return System uptime in milliseconds.
             */
            [[nodiscard]] uint64_t GetSystemUptime();

            /**
             * @brief Get screen resolution.
             * @return Pair of (width, height) in pixels.
             */
            [[nodiscard]] std::pair<uint32_t, uint32_t> GetScreenResolution();

            /**
             * @brief Check for specific sandbox DLL.
             * @param dllName DLL name to check.
             * @return true if DLL is loaded.
             */
            [[nodiscard]] bool IsSandboxDLLLoaded(std::wstring_view dllName);

            /**
             * @brief Check for specific sandbox process.
             * @param processName Process name to check.
             * @return true if process is running.
             */
            [[nodiscard]] bool IsSandboxProcessRunning(std::wstring_view processName);

            /**
             * @brief Check for specific mutex.
             * @param mutexName Mutex name to check.
             * @return true if mutex exists.
             */
            [[nodiscard]] bool DoesMutexExist(std::wstring_view mutexName);

            // =========================================================================
            // Callbacks
            // =========================================================================

            /**
             * @brief Register callback for sandbox detection.
             * @param callback Callback function.
             * @return Registration ID.
             */
            [[nodiscard]] uint64_t RegisterCallback(SandboxDetectionCallback callback);

            /**
             * @brief Unregister callback.
             * @param callbackId ID returned by RegisterCallback.
             * @return true if callback was found and removed.
             */
            bool UnregisterCallback(uint64_t callbackId);

            // =========================================================================
            // Statistics & Cache
            // =========================================================================

            /**
             * @brief Get detection statistics.
             */
            [[nodiscard]] SandboxDetectorStats GetStats() const;

            /**
             * @brief Reset statistics.
             */
            void ResetStats();

            /**
             * @brief Get cached result (if available).
             * @return Cached result or nullopt.
             */
            [[nodiscard]] std::optional<SandboxEvasionResult> GetCachedResult() const;

            /**
             * @brief Clear result cache.
             */
            void ClearCache();

            /**
             * @brief Get current hardware profile (cached).
             */
            [[nodiscard]] std::optional<HardwareProfile> GetHardwareProfile() const;

        private:
            // =========================================================================
            // Private Constructor (Singleton)
            // =========================================================================

            SandboxEvasionDetector();
            ~SandboxEvasionDetector();

            // =========================================================================
            // Internal Check Methods
            // =========================================================================

            /**
             * @brief Check hardware specifications.
             */
            void CheckHardwareSpecs(SandboxEvasionResult& result);

            /**
             * @brief Check system uptime.
             */
            void CheckUptime(SandboxEvasionResult& result);

            /**
             * @brief Check for sandbox DLLs in loaded modules.
             */
            void CheckLoadedModules(SandboxEvasionResult& result);

            /**
             * @brief Check system wear and tear indicators.
             */
            void CheckSystemWearAndTear(SandboxEvasionResult& result);

            /**
             * @brief Check for known sandbox named objects.
             */
            void CheckNamedObjects(SandboxEvasionResult& result);

            /**
             * @brief Check screen resolution and display settings.
             */
            void CheckScreenResolution(SandboxEvasionResult& result);

            /**
             * @brief Check running processes for sandbox indicators.
             */
            void CheckProcesses(SandboxEvasionResult& result);

            /**
             * @brief Check services for sandbox indicators.
             */
            void CheckServices(SandboxEvasionResult& result);

            /**
             * @brief Check registry for sandbox artifacts.
             */
            void CheckRegistry(SandboxEvasionResult& result);

            /**
             * @brief Check file system for sandbox artifacts.
             */
            void CheckFileSystem(SandboxEvasionResult& result);

            /**
             * @brief Check for API hooks.
             */
            void CheckAPIHooks(SandboxEvasionResult& result);

            /**
             * @brief Check network characteristics.
             */
            void CheckNetworkCharacteristics(SandboxEvasionResult& result);

            /**
             * @brief Calculate final probability from all checks.
             */
            void CalculateProbability(SandboxEvasionResult& result);

            /**
             * @brief Identify specific sandbox product.
             */
            void IdentifySandboxProduct(SandboxEvasionResult& result);

            /**
             * @brief Add MITRE ATT&CK mappings.
             */
            void AddMitreMappings(SandboxEvasionResult& result);

            /**
             * @brief Add indicator to result.
             */
            void AddIndicator(
                SandboxEvasionResult& result,
                SandboxCheckType checkType,
                SandboxIndicatorCategory category,
                SandboxIndicatorSeverity severity,
                float weight,
                float confidence,
                const std::wstring& description,
                const std::wstring& technicalDetails = L"",
                const std::wstring& observedValue = L"",
                const std::wstring& expectedValue = L"",
                SandboxProduct suspectedProduct = SandboxProduct::Unknown,
                bool isConclusive = false
            );

            /**
             * @brief Update cache with result.
             */
            void UpdateCache(const SandboxEvasionResult& result);

            /**
             * @brief Invoke registered callbacks.
             */
            void InvokeCallbacks(const SandboxEvasionResult& result);

            // =========================================================================
            // Internal Data (PIMPL)
            // =========================================================================

            struct Impl;
            std::unique_ptr<Impl> m_impl;
        };

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Calculate weighted sandbox probability.
         * @param scores Vector of category scores (0.0 - 100.0).
         * @param weights Vector of category weights.
         * @return Weighted probability (0.0 - 100.0).
         */
        [[nodiscard]] inline float CalculateWeightedProbability(
            const std::vector<float>& scores,
            const std::vector<float>& weights
        ) noexcept {
            if (scores.empty() || scores.size() != weights.size()) return 0.0f;

            float weightedSum = 0.0f;
            float totalWeight = 0.0f;

            for (size_t i = 0; i < scores.size(); ++i) {
                weightedSum += scores[i] * weights[i];
                totalWeight += weights[i];
            }

            return (totalWeight > 0.0f) ? (weightedSum / totalWeight) : 0.0f;
        }

        /**
         * @brief Determine severity from score.
         * @param score Score (0.0 - 100.0).
         * @return Corresponding severity level.
         */
        [[nodiscard]] inline SandboxIndicatorSeverity ScoreToSeverity(float score) noexcept {
            if (score >= 90.0f) return SandboxIndicatorSeverity::Critical;
            if (score >= 70.0f) return SandboxIndicatorSeverity::High;
            if (score >= 40.0f) return SandboxIndicatorSeverity::Medium;
            if (score >= 15.0f) return SandboxIndicatorSeverity::Low;
            return SandboxIndicatorSeverity::Info;
        }

        /**
         * @brief Calculate mouse path entropy.
         * @param movements Vector of (x, y) coordinates.
         * @return Entropy value (higher = more random/human-like).
         */
        [[nodiscard]] double CalculateMousePathEntropy(
            const std::vector<std::pair<int32_t, int32_t>>& movements
        ) noexcept;

        /**
         * @brief Calculate straight line ratio for mouse path.
         * @param movements Vector of (x, y) coordinates.
         * @return Ratio (0.0 - 1.0, higher = more linear/bot-like).
         */
        [[nodiscard]] double CalculateStraightLineRatio(
            const std::vector<std::pair<int32_t, int32_t>>& movements
        ) noexcept;

    } // namespace AntiEvasion
} // namespace ShadowStrike