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
 * ============================================================================
 * ShadowStrike Core Process - MEMORY SCANNER (The Surgeon)
 * ============================================================================
 *
 * @file MemoryScanner.hpp
 * @brief Enterprise-grade volatile memory inspection for malware detection.
 *
 * Traditional AVs only scan files on disk. Modern threats (Fileless Malware,
 * Reflective DLL Injection, Meterpreter, Cobalt Strike beacons) live entirely
 * in RAM. This module provides comprehensive in-memory threat detection.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Virtual Memory Traversal**
 *    - Walk VAD (Virtual Address Descriptor) tree
 *    - Enumerate all memory regions
 *    - Track allocations over time
 *    - Detect hidden regions
 *
 * 2. **Protection-Based Filtering**
 *    - Scan executable (RX/RWX) pages
 *    - Detect suspicious protection changes
 *    - Find unbacked executable memory
 *    - Track PAGE_GUARD usage
 *
 * 3. **Pattern Matching**
 *    - YARA rule integration
 *    - Shellcode signature matching
 *    - API hashing detection
 *    - String extraction
 *
 * 4. **Behavioral Indicators**
 *    - PE header detection in memory
 *    - Reflective loader patterns
 *    - Beacon patterns (sleep, jitter)
 *    - C2 communication patterns
 *
 * 5. **Forensic Analysis**
 *    - Memory dump creation
 *    - Region extraction
 *    - Timeline reconstruction
 *    - Evidence preservation
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          TARGET PROCESS                                      │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    Virtual Address Space                             │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │   │
 * │  │  │ .text   │ │ .data   │ │  Heap   │ │  Stack  │ │ Private │       │   │
 * │  │  │ (RX)    │ │ (RW)    │ │ (RW)    │ │ (RW)    │ │ (RWX!)  │       │   │
 * │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └────┬────┘       │   │
 * │  │                                                        │ SUSPICIOUS │   │
 * │  └────────────────────────────────────────────────────────┼────────────┘   │
 * │                                                           │                 │
 * └───────────────────────────────────────────────────────────┼─────────────────┘
 *                                                             │
 * ════════════════════════════════════════════════════════════╪═════════════════
 *                                                             │
 * ┌───────────────────────────────────────────────────────────┼─────────────────┐
 * │                                                           ▼                 │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                       MemoryScanner                                  │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────────────────────────────────────────────────┐    │   │
 * │  │  │                   Region Enumerator                          │    │   │
 * │  │  │  - VirtualQueryEx walk                                       │    │   │
 * │  │  │  - Filter by protection                                      │    │   │
 * │  │  │  - Prioritize suspicious regions                             │    │   │
 * │  │  └─────────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                       │   │
 * │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │   │
 * │  │  │   YARA     │  │ Shellcode  │  │    PE      │  │  String    │    │   │
 * │  │  │  Scanner   │  │  Patterns  │  │  Detector  │  │ Extractor  │    │   │
 * │  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │   │
 * │  │        │               │               │               │           │   │
 * │  │        └───────────────┴───────────────┴───────────────┘           │   │
 * │  │                                   │                                 │   │
 * │  │  ┌────────────────────────────────▼────────────────────────────┐   │   │
 * │  │  │                   Detection Aggregator                       │   │   │
 * │  │  │  - Combine findings                                          │   │   │
 * │  │  │  - Calculate confidence                                      │   │   │
 * │  │  │  - Generate verdicts                                         │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │                           SCANNER PROCESS                                    │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * DETECTION TECHNIQUES
 * =============================================================================
 *
 * | Technique                | Detection Method                               |
 * |--------------------------|------------------------------------------------|
 * | Fileless Malware         | Unbacked executable private memory             |
 * | Reflective DLL           | PE headers in non-image memory                 |
 * | Cobalt Strike Beacon     | Sleep patterns + beacon config extraction      |
 * | Meterpreter              | Stage patterns + reflective loader signatures  |
 * | Shellcode                | NOP sleds, API hashes, syscall stubs           |
 * | Process Hollowing        | Unmapped main module + replaced content        |
 * | Module Stomping          | Modified image sections                        |
 * | .NET In-Memory           | CLR patterns + assembly load indicators        |
 *
 * =============================================================================
 * SUSPICIOUS MEMORY INDICATORS
 * =============================================================================
 *
 * | Indicator                    | Risk  | Description                        |
 * |------------------------------|-------|------------------------------------|
 * | RWX Private Memory           | High  | Writable + executable (no image)   |
 * | Unbacked Executable          | High  | Executable without file backing    |
 * | PE in Non-Image Memory       | Crit  | PE header in heap/private          |
 * | Modified Image Section       | Med   | Image .text differs from disk      |
 * | Large Private Executable     | High  | >1MB private executable region     |
 * | Hidden/Unlinked Module       | Crit  | Module not in PEB.Ldr              |
 * | API Hash Patterns            | Med   | Known shellcode API resolution     |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Description                          | Detection Method         |
 * |-----------|--------------------------------------|--------------------------|
 * | T1055     | Process Injection                    | Foreign code in memory   |
 * | T1620     | Reflective Code Loading              | PE in non-image memory   |
 * | T1059     | Command and Scripting                | Script in memory         |
 * | T1106     | Native API                           | Direct syscall patterns  |
 * | T1027     | Obfuscated Files                     | Encrypted payloads       |
 *
 * @note Thread-safe for all public methods
 * @note Requires SeDebugPrivilege for cross-process scanning
 *
 * @see PatternStore for signature matching
 * @see EmulationEngine for dynamic analysis
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/ProcessUtils.hpp"       // Process/memory access
#include "../../Utils/HashUtils.hpp"          // Memory content hashing
#include "../../PatternStore/PatternStore.hpp" // YARA/shellcode patterns
#include "../../SignatureStore/SignatureStore.hpp" // Malware signatures
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IOC lookups
#include "../../Whitelist/WhiteListStore.hpp" // Trusted modules

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
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

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace PatternStore {
        class PatternIndex;
    }
    namespace Core {
        namespace Engine {
            class EmulationEngine;
            class ThreatDetector;
        }
    }
}

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class MemoryScanner;
struct MemoryRegion;
struct MemoryScanResult;
struct MemoryThreat;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace MemoryScannerConstants {
    // -------------------------------------------------------------------------
    // Scanning Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum memory to scan per process
    constexpr size_t MAX_SCAN_SIZE_PER_PROCESS = 2ULL * 1024 * 1024 * 1024;  // 2 GB
    
    /// @brief Maximum region size to scan
    constexpr size_t MAX_REGION_SIZE = 256 * 1024 * 1024;  // 256 MB
    
    /// @brief Read buffer size
    constexpr size_t READ_BUFFER_SIZE = 64 * 1024;  // 64 KB
    
    /// @brief Maximum YARA matches per region
    constexpr size_t MAX_YARA_MATCHES_PER_REGION = 100;
    
    // -------------------------------------------------------------------------
    // Detection Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Minimum shellcode size
    constexpr size_t MIN_SHELLCODE_SIZE = 16;
    
    /// @brief Large private executable threshold
    constexpr size_t LARGE_PRIVATE_EXEC_THRESHOLD = 1024 * 1024;  // 1 MB
    
    /// @brief Entropy threshold for encrypted content
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.0;
    
    /// @brief NOP sled minimum length
    constexpr size_t MIN_NOP_SLED_LENGTH = 16;
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief RWX private memory score
    constexpr double RWX_PRIVATE_SCORE = 70.0;
    
    /// @brief Unbacked executable score
    constexpr double UNBACKED_EXEC_SCORE = 80.0;
    
    /// @brief PE in non-image memory score
    constexpr double PE_IN_MEMORY_SCORE = 95.0;
    
    /// @brief Hidden module score
    constexpr double HIDDEN_MODULE_SCORE = 90.0;
    
    /// @brief YARA match score
    constexpr double YARA_MATCH_SCORE = 75.0;
    
    /// @brief Shellcode pattern score
    constexpr double SHELLCODE_PATTERN_SCORE = 85.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Memory region type.
 */
enum class MemoryType : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Image (loaded module)
    Image = 1,
    
    /// @brief Mapped file
    Mapped = 2,
    
    /// @brief Private memory
    Private = 3,
    
    /// @brief Stack
    Stack = 4,
    
    /// @brief Heap
    Heap = 5,
    
    /// @brief PEB/TEB
    ProcessEnvironment = 6
};

/**
 * @brief Memory region state.
 */
enum class MemoryState : uint8_t {
    /// @brief Committed
    Committed = 0,
    
    /// @brief Reserved
    Reserved = 1,
    
    /// @brief Free
    Free = 2
};

/**
 * @brief Memory protection type.
 */
enum class MemoryProtection : uint8_t {
    /// @brief No access
    NoAccess = 0,
    
    /// @brief Read only
    ReadOnly = 1,
    
    /// @brief Read/Write
    ReadWrite = 2,
    
    /// @brief Read/Execute
    ReadExecute = 3,
    
    /// @brief Read/Write/Execute (suspicious)
    ReadWriteExecute = 4,
    
    /// @brief Execute only
    ExecuteOnly = 5,
    
    /// @brief Copy on write
    CopyOnWrite = 6,
    
    /// @brief Guard page
    Guard = 7
};

/**
 * @brief Memory threat type.
 */
enum class MemoryThreatType : uint16_t {
    /// @brief No threat
    None = 0,
    
    /// @brief Generic malware
    Malware = 1,
    
    /// @brief Shellcode
    Shellcode = 2,
    
    /// @brief Reflective DLL
    ReflectiveDLL = 3,
    
    /// @brief PE injection
    PEInjection = 4,
    
    /// @brief .NET in-memory
    DotNetInMemory = 5,
    
    /// @brief Cobalt Strike beacon
    CobaltStrikeBeacon = 6,
    
    /// @brief Meterpreter
    Meterpreter = 7,
    
    /// @brief Empire agent
    Empire = 8,
    
    /// @brief Mimikatz
    Mimikatz = 9,
    
    /// @brief Process hollowing
    ProcessHollowing = 10,
    
    /// @brief Module stomping
    ModuleStomping = 11,
    
    /// @brief Hidden module
    HiddenModule = 12,
    
    /// @brief Suspicious code
    SuspiciousCode = 13,
    
    /// @brief Encrypted payload
    EncryptedPayload = 14,
    
    /// @brief API hashing shellcode
    APIHashing = 15,
    
    /// @brief Syscall stub
    SyscallStub = 16
};

/**
 * @brief Scan mode.
 */
enum class ScanMode : uint8_t {
    /// @brief Quick scan (executable regions only)
    Quick = 0,
    
    /// @brief Normal scan (executable + suspicious)
    Normal = 1,
    
    /// @brief Deep scan (all committed memory)
    Deep = 2,
    
    /// @brief Forensic scan (with evidence collection)
    Forensic = 3
};

/**
 * @brief Get string for MemoryThreatType.
 */
[[nodiscard]] constexpr const char* MemoryThreatTypeToString(MemoryThreatType type) noexcept;

/**
 * @brief Get MITRE technique for memory threat.
 */
[[nodiscard]] constexpr const char* MemoryThreatToMitre(MemoryThreatType type) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Memory region descriptor.
 */
struct MemoryRegion {
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Region size
    size_t size = 0;
    
    /// @brief Memory type
    MemoryType type = MemoryType::Unknown;
    
    /// @brief Memory state
    MemoryState state = MemoryState::Free;
    
    /// @brief Current protection
    MemoryProtection protection = MemoryProtection::NoAccess;
    
    /// @brief Initial protection (at allocation)
    MemoryProtection initialProtection = MemoryProtection::NoAccess;
    
    /// @brief Allocation base
    uintptr_t allocationBase = 0;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is writable
    bool isWritable = false;
    
    /// @brief Is private (not file-backed)
    bool isPrivate = false;
    
    /// @brief Associated module (if Image)
    std::wstring moduleName;
    
    /// @brief Associated file (if Mapped)
    std::wstring mappedFile;
    
    /// @brief Thread ID (if Stack)
    uint32_t threadId = 0;
    
    /// @brief Contains PE header
    bool containsPE = false;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Suspicion reason
    std::string suspicionReason;
};

/**
 * @brief Memory threat detection.
 */
struct MemoryThreat {
    /// @brief Threat ID
    uint64_t threatId = 0;
    
    /// @brief Detection timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Threat type
    MemoryThreatType threatType = MemoryThreatType::None;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Region base address
    uintptr_t regionBase = 0;
    
    /// @brief Region size
    size_t regionSize = 0;
    
    /// @brief Detection offset within region
    size_t detectionOffset = 0;
    
    /// @brief Detection size
    size_t detectionSize = 0;
    
    /// @brief Memory protection
    MemoryProtection protection = MemoryProtection::NoAccess;
    
    /// @brief Memory type
    MemoryType memoryType = MemoryType::Unknown;
    
    /// @brief Rule/signature that matched
    std::string matchedRule;
    
    /// @brief Rule category
    std::string ruleCategory;
    
    /// @brief Confidence (0-100)
    double confidence = 0.0;
    
    /// @brief Risk score (0-100)
    double riskScore = 0.0;
    
    /// @brief MITRE technique
    std::string mitreTechnique;
    
    /// @brief Detection details
    std::wstring details;
    
    /// @brief Extracted strings (if any)
    std::vector<std::string> extractedStrings;
    
    /// @brief Evidence preview (first N bytes)
    std::vector<uint8_t> evidencePreview;
    
    /// @brief PE info (if detected)
    struct PEInfo {
        bool valid = false;
        uintptr_t imageBase = 0;
        size_t imageSize = 0;
        uintptr_t entryPoint = 0;
        uint16_t machine = 0;
        uint16_t characteristics = 0;
        std::string imphash;
    } peInfo;
};

/**
 * @brief Region scan result.
 */
struct RegionScanResult {
    /// @brief Region scanned
    MemoryRegion region;
    
    /// @brief Scan timestamp
    std::chrono::system_clock::time_point scanTime{};
    
    /// @brief Was scanned successfully
    bool scanned = false;
    
    /// @brief Skip reason (if not scanned)
    std::string skipReason;
    
    /// @brief Threats found
    std::vector<MemoryThreat> threats;
    
    /// @brief YARA matches
    std::vector<std::pair<std::string, size_t>> yaraMatches;
    
    /// @brief Pattern matches
    std::vector<std::pair<std::string, size_t>> patternMatches;
    
    /// @brief Contains shellcode indicators
    bool hasShellcodeIndicators = false;
    
    /// @brief Contains PE header
    bool containsPE = false;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Scan time (microseconds)
    uint64_t scanTimeUs = 0;
};

/**
 * @brief Full process scan result.
 */
struct MemoryScanResult {
    /// @brief Scan ID
    uint64_t scanId = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Scan mode
    ScanMode scanMode = ScanMode::Normal;
    
    /// @brief Scan start time
    std::chrono::system_clock::time_point startTime{};
    
    /// @brief Scan end time
    std::chrono::system_clock::time_point endTime{};
    
    /// @brief Scan completed
    bool completed = false;
    
    /// @brief Error message (if not completed)
    std::wstring errorMessage;
    
    /// @brief Total regions enumerated
    size_t totalRegions = 0;
    
    /// @brief Regions scanned
    size_t regionsScanned = 0;
    
    /// @brief Regions skipped
    size_t regionsSkipped = 0;
    
    /// @brief Total bytes scanned
    size_t bytesScanned = 0;
    
    /// @brief Total threats found
    size_t threatsFound = 0;
    
    /// @brief Threats by type
    std::map<MemoryThreatType, size_t> threatsByType;
    
    /// @brief All threats
    std::vector<MemoryThreat> threats;
    
    /// @brief Per-region results (optional, for forensic mode)
    std::vector<RegionScanResult> regionResults;
    
    /// @brief Suspicious regions found
    std::vector<MemoryRegion> suspiciousRegions;
    
    /// @brief Total scan time (milliseconds)
    uint64_t totalScanTimeMs = 0;
    
    /// @brief Overall risk score
    double overallRiskScore = 0.0;
    
    /// @brief Is clean (no threats)
    [[nodiscard]] bool IsClean() const noexcept {
        return threatsFound == 0;
    }
};

/**
 * @brief Shellcode analysis result.
 */
struct ShellcodeAnalysis {
    /// @brief Is likely shellcode
    bool isShellcode = false;
    
    /// @brief Confidence (0-100)
    double confidence = 0.0;
    
    /// @brief Contains NOP sled
    bool hasNOPSled = false;
    
    /// @brief NOP sled length
    size_t nopSledLength = 0;
    
    /// @brief Contains API hashing
    bool hasAPIHashing = false;
    
    /// @brief Detected API hash algorithm
    std::string apiHashAlgorithm;
    
    /// @brief Contains syscall stubs
    bool hasSyscallStubs = false;
    
    /// @brief Contains GetPC technique
    bool hasGetPC = false;
    
    /// @brief Contains decoder stub
    bool hasDecoder = false;
    
    /// @brief Estimated architecture
    std::string architecture;  // "x86", "x64", "mixed"
    
    /// @brief Matched shellcode family
    std::string family;
    
    /// @brief Decoded content (if decoder found)
    std::vector<uint8_t> decodedContent;
};

/**
 * @brief Configuration for memory scanner.
 */
struct MemoryScannerConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable scanning
    bool enabled = true;
    
    /// @brief Default scan mode
    ScanMode defaultMode = ScanMode::Normal;
    
    /// @brief Enable YARA scanning
    bool enableYARA = true;
    
    /// @brief Enable pattern matching
    bool enablePatternMatching = true;
    
    /// @brief Enable shellcode detection
    bool enableShellcodeDetection = true;
    
    // -------------------------------------------------------------------------
    // Region Filtering
    // -------------------------------------------------------------------------
    
    /// @brief Scan executable regions
    bool scanExecutable = true;
    
    /// @brief Scan RWX regions (always scan these)
    bool scanRWX = true;
    
    /// @brief Scan private memory
    bool scanPrivate = true;
    
    /// @brief Scan mapped files
    bool scanMapped = false;
    
    /// @brief Scan image sections
    bool scanImages = true;
    
    /// @brief Scan modified image sections
    bool scanModifiedImages = true;
    
    // -------------------------------------------------------------------------
    // Performance Settings
    // -------------------------------------------------------------------------
    
    /// @brief Maximum memory per process (bytes)
    size_t maxScanSizePerProcess = MemoryScannerConstants::MAX_SCAN_SIZE_PER_PROCESS;
    
    /// @brief Maximum region size (bytes)
    size_t maxRegionSize = MemoryScannerConstants::MAX_REGION_SIZE;
    
    /// @brief Parallel scan threads
    uint32_t parallelThreads = 4;
    
    /// @brief Scan timeout (milliseconds)
    uint32_t scanTimeoutMs = 60000;
    
    // -------------------------------------------------------------------------
    // Detection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Entropy threshold for flagging
    double entropyThreshold = MemoryScannerConstants::HIGH_ENTROPY_THRESHOLD;
    
    /// @brief Minimum confidence to report
    double minReportConfidence = 50.0;
    
    /// @brief Extract strings from threats
    bool extractStrings = true;
    
    /// @brief Maximum strings to extract
    size_t maxStringsExtracted = 100;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static MemoryScannerConfig CreateDefault() noexcept {
        return MemoryScannerConfig{};
    }
    
    /**
     * @brief Create quick scan configuration.
     */
    [[nodiscard]] static MemoryScannerConfig CreateQuick() noexcept {
        MemoryScannerConfig config;
        config.defaultMode = ScanMode::Quick;
        config.scanPrivate = false;
        config.scanMapped = false;
        config.scanImages = false;
        config.extractStrings = false;
        return config;
    }
    
    /**
     * @brief Create deep scan configuration.
     */
    [[nodiscard]] static MemoryScannerConfig CreateDeep() noexcept {
        MemoryScannerConfig config;
        config.defaultMode = ScanMode::Deep;
        config.scanMapped = true;
        config.scanImages = true;
        config.maxScanSizePerProcess = 4ULL * 1024 * 1024 * 1024;  // 4 GB
        config.scanTimeoutMs = 300000;  // 5 minutes
        return config;
    }
    
    /**
     * @brief Create forensic configuration.
     */
    [[nodiscard]] static MemoryScannerConfig CreateForensic() noexcept {
        MemoryScannerConfig config = CreateDeep();
        config.defaultMode = ScanMode::Forensic;
        config.extractStrings = true;
        config.maxStringsExtracted = 1000;
        return config;
    }
};

/**
 * @brief Memory scanner statistics.
 */
struct MemoryScannerStats {
    /// @brief Total scans performed
    std::atomic<uint64_t> totalScans{ 0 };
    
    /// @brief Total processes scanned
    std::atomic<uint64_t> processesScanned{ 0 };
    
    /// @brief Total regions scanned
    std::atomic<uint64_t> regionsScanned{ 0 };
    
    /// @brief Total bytes scanned
    std::atomic<uint64_t> bytesScanned{ 0 };
    
    /// @brief Total threats found
    std::atomic<uint64_t> threatsFound{ 0 };
    
    /// @brief Shellcode detections
    std::atomic<uint64_t> shellcodeDetections{ 0 };
    
    /// @brief PE detections
    std::atomic<uint64_t> peDetections{ 0 };
    
    /// @brief YARA matches
    std::atomic<uint64_t> yaraMatches{ 0 };
    
    /// @brief Pattern matches
    std::atomic<uint64_t> patternMatches{ 0 };
    
    /// @brief Scan errors
    std::atomic<uint64_t> scanErrors{ 0 };
    
    /// @brief Average scan time (milliseconds)
    std::atomic<uint64_t> avgScanTimeMs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalScans.store(0, std::memory_order_relaxed);
        processesScanned.store(0, std::memory_order_relaxed);
        regionsScanned.store(0, std::memory_order_relaxed);
        bytesScanned.store(0, std::memory_order_relaxed);
        threatsFound.store(0, std::memory_order_relaxed);
        shellcodeDetections.store(0, std::memory_order_relaxed);
        peDetections.store(0, std::memory_order_relaxed);
        yaraMatches.store(0, std::memory_order_relaxed);
        patternMatches.store(0, std::memory_order_relaxed);
        scanErrors.store(0, std::memory_order_relaxed);
        avgScanTimeMs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using MemoryThreatCallback = std::function<void(const MemoryThreat&)>;
using ScanProgressCallback = std::function<void(uint32_t pid, size_t regionsScanned, size_t totalRegions)>;
using ScanCompleteCallback = std::function<void(const MemoryScanResult&)>;
using RegionCallback = std::function<bool(const MemoryRegion&)>;  // Return false to skip

// ============================================================================
// MAIN MEMORY SCANNER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade volatile memory scanner.
 *
 * Provides comprehensive in-memory threat detection including fileless
 * malware, reflective DLL injection, and shellcode.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& scanner = MemoryScanner::Instance();
 * 
 * // Initialize
 * MemoryScannerConfig config = MemoryScannerConfig::CreateDefault();
 * scanner.Initialize(threadPool, config);
 * 
 * // Set pattern index
 * scanner.SetPatternIndex(&PatternIndex::Instance());
 * 
 * // Register callbacks
 * scanner.RegisterThreatCallback([](const MemoryThreat& threat) {
 *     LOG_ALERT("Memory threat: {} in {} at 0x{:X}",
 *               MemoryThreatTypeToString(threat.threatType),
 *               threat.processName, threat.regionBase);
 * });
 * 
 * // Scan a process
 * auto result = scanner.ScanProcessMemory(targetPid);
 * if (!result.IsClean()) {
 *     LOG_WARN("Found {} threats in process {}", result.threatsFound, targetPid);
 *     for (const auto& threat : result.threats) {
 *         LOG_INFO("  - {}: {}", threat.matchedRule, threat.details);
 *     }
 * }
 * 
 * // Scan specific region
 * if (scanner.ScanRegion(pid, suspiciousAddress, regionSize)) {
 *     LOG_INFO("Region contains threats");
 * }
 * 
 * // Quick shellcode check
 * auto analysis = scanner.AnalyzeForShellcode(codeBytes);
 * if (analysis.isShellcode) {
 *     LOG_WARN("Shellcode detected (confidence: {}%)", analysis.confidence);
 * }
 * 
 * scanner.Shutdown();
 * @endcode
 */
class MemoryScanner {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static MemoryScanner& Instance();

    // Non-copyable, non-movable
    MemoryScanner(const MemoryScanner&) = delete;
    MemoryScanner& operator=(const MemoryScanner&) = delete;
    MemoryScanner(MemoryScanner&&) = delete;
    MemoryScanner& operator=(MemoryScanner&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the scanner.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const MemoryScannerConfig& config
    );

    /**
     * @brief Shutdown the scanner.
     */
    void Shutdown();

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const MemoryScannerConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] MemoryScannerConfig GetConfig() const;

    // =========================================================================
    // Process Scanning
    // =========================================================================

    /**
     * @brief Scan entire process memory.
     */
    [[nodiscard]] MemoryScanResult ScanProcessMemory(uint32_t pid);

    /**
     * @brief Scan process memory with mode.
     */
    [[nodiscard]] MemoryScanResult ScanProcessMemory(uint32_t pid, ScanMode mode);

    /**
     * @brief Scan process memory with callback.
     */
    uint32_t ScanProcessMemory(
        uint32_t pid,
        std::function<void(const std::string& rule, uintptr_t addr)> matchCallback
    );

    /**
     * @brief Scan multiple processes.
     */
    [[nodiscard]] std::vector<MemoryScanResult> ScanProcesses(const std::vector<uint32_t>& pids);

    /**
     * @brief Scan all processes.
     */
    [[nodiscard]] std::vector<MemoryScanResult> ScanAllProcesses();

    // =========================================================================
    // Region Scanning
    // =========================================================================

    /**
     * @brief Scan specific memory region.
     */
    [[nodiscard]] bool ScanRegion(uint32_t pid, uintptr_t baseAddress, size_t size);

    /**
     * @brief Scan region and get detailed result.
     */
    [[nodiscard]] RegionScanResult ScanRegionDetailed(
        uint32_t pid,
        uintptr_t baseAddress,
        size_t size
    );

    /**
     * @brief Scan data buffer (no process context).
     */
    [[nodiscard]] std::vector<MemoryThreat> ScanBuffer(
        std::span<const uint8_t> data,
        uintptr_t virtualAddress = 0
    );

    // =========================================================================
    // Region Enumeration
    // =========================================================================

    /**
     * @brief Enumerate all memory regions for process.
     */
    [[nodiscard]] std::vector<MemoryRegion> EnumerateRegions(uint32_t pid) const;

    /**
     * @brief Enumerate executable regions.
     */
    [[nodiscard]] std::vector<MemoryRegion> EnumerateExecutableRegions(uint32_t pid) const;

    /**
     * @brief Enumerate suspicious regions.
     */
    [[nodiscard]] std::vector<MemoryRegion> EnumerateSuspiciousRegions(uint32_t pid) const;

    /**
     * @brief Get region info at address.
     */
    [[nodiscard]] std::optional<MemoryRegion> GetRegionInfo(
        uint32_t pid,
        uintptr_t address
    ) const;

    // =========================================================================
    // Analysis
    // =========================================================================

    /**
     * @brief Analyze buffer for shellcode.
     */
    [[nodiscard]] ShellcodeAnalysis AnalyzeForShellcode(std::span<const uint8_t> data) const;

    /**
     * @brief Check if buffer contains PE header.
     */
    [[nodiscard]] bool ContainsPE(std::span<const uint8_t> data) const;

    /**
     * @brief Parse PE from memory.
     */
    [[nodiscard]] std::optional<MemoryThreat::PEInfo> ParsePE(std::span<const uint8_t> data) const;

    /**
     * @brief Calculate entropy.
     */
    [[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) const;

    /**
     * @brief Extract strings from buffer.
     */
    [[nodiscard]] std::vector<std::string> ExtractStrings(
        std::span<const uint8_t> data,
        size_t minLength = 4
    ) const;

    /**
     * @brief Check for API hashing patterns.
     */
    [[nodiscard]] bool CheckAPIHashing(std::span<const uint8_t> data) const;

    // =========================================================================
    // Memory Reading
    // =========================================================================

    /**
     * @brief Read process memory safely.
     */
    [[nodiscard]] std::vector<uint8_t> ReadMemory(
        uint32_t pid,
        uintptr_t address,
        size_t size
    ) const;

    /**
     * @brief Read process memory with handle.
     */
    [[nodiscard]] std::vector<uint8_t> ReadMemory(
        HANDLE processHandle,
        uintptr_t address,
        size_t size
    ) const;

    /**
     * @brief Dump region to file.
     */
    bool DumpRegion(
        uint32_t pid,
        uintptr_t address,
        size_t size,
        const std::wstring& outputPath
    ) const;

    /**
     * @brief Create full memory dump.
     */
    bool CreateMemoryDump(uint32_t pid, const std::wstring& outputPath) const;

    // =========================================================================
    // YARA Integration
    // =========================================================================

    /**
     * @brief Load YARA rules from file.
     */
    bool LoadYARARules(const std::wstring& rulesPath);

    /**
     * @brief Load YARA rules from string.
     */
    bool LoadYARARulesFromString(const std::string& rules);

    /**
     * @brief Get loaded YARA rule count.
     */
    [[nodiscard]] size_t GetYARARuleCount() const;

    /**
     * @brief Unload all YARA rules.
     */
    void UnloadYARARules();

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] MemoryScannerStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register threat callback.
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(MemoryThreatCallback callback);

    /**
     * @brief Unregister threat callback.
     */
    bool UnregisterThreatCallback(uint64_t callbackId);

    /**
     * @brief Register scan progress callback.
     */
    [[nodiscard]] uint64_t RegisterProgressCallback(ScanProgressCallback callback);

    /**
     * @brief Unregister progress callback.
     */
    bool UnregisterProgressCallback(uint64_t callbackId);

    /**
     * @brief Register scan complete callback.
     */
    [[nodiscard]] uint64_t RegisterCompleteCallback(ScanCompleteCallback callback);

    /**
     * @brief Unregister complete callback.
     */
    bool UnregisterCompleteCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set pattern index.
     */
    void SetPatternIndex(PatternStore::PatternIndex* index);

    /**
     * @brief Set emulation engine.
     */
    void SetEmulationEngine(Core::Engine::EmulationEngine* engine);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    MemoryScanner();
    ~MemoryScanner();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Check if region should be scanned.
     */
    bool ShouldScanRegion(const MemoryRegion& region, ScanMode mode) const;

    /**
     * @brief Scan region with YARA.
     */
    std::vector<std::pair<std::string, size_t>> ScanWithYARA(
        std::span<const uint8_t> data
    ) const;

    /**
     * @brief Scan region with patterns.
     */
    std::vector<std::pair<std::string, size_t>> ScanWithPatterns(
        std::span<const uint8_t> data
    ) const;

    /**
     * @brief Detect shellcode patterns.
     */
    std::vector<MemoryThreat> DetectShellcode(
        uint32_t pid,
        const MemoryRegion& region,
        std::span<const uint8_t> data
    ) const;

    /**
     * @brief Invoke threat callbacks.
     */
    void InvokeThreatCallbacks(const MemoryThreat& threat);

    /**
     * @brief Invoke progress callbacks.
     */
    void InvokeProgressCallbacks(uint32_t pid, size_t current, size_t total);

    /**
     * @brief Invoke complete callbacks.
     */
    void InvokeCompleteCallbacks(const MemoryScanResult& result);

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
 * @brief Convert Windows protection flags to MemoryProtection.
 */
[[nodiscard]] MemoryProtection WindowsProtectionToEnum(uint32_t protect) noexcept;

/**
 * @brief Check if protection is executable.
 */
[[nodiscard]] bool IsProtectionExecutable(uint32_t protect) noexcept;

/**
 * @brief Check if protection is writable.
 */
[[nodiscard]] bool IsProtectionWritable(uint32_t protect) noexcept;

/**
 * @brief Check if protection is RWX.
 */
[[nodiscard]] bool IsProtectionRWX(uint32_t protect) noexcept;

/**
 * @brief Get module list for process.
 */
[[nodiscard]] std::vector<std::pair<std::wstring, uintptr_t>> GetProcessModules(uint32_t pid) noexcept;

/**
 * @brief Check if address is within a module.
 */
[[nodiscard]] bool IsAddressInModule(uint32_t pid, uintptr_t address) noexcept;

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
