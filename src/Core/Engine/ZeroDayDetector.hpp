/**
 * ============================================================================
 * ShadowStrike NGAV - ZERO DAY DETECTOR MODULE
 * ============================================================================
 *
 * @file ZeroDayDetector.hpp
 * @brief Enterprise-grade detection of zero-day exploits, shellcode, and
 *        previously unknown vulnerabilities using advanced heuristics.
 *
 * Provides comprehensive exploit detection focusing on exploit primitives
 * and techniques rather than specific payloads.
 *
 * ZERO DAY DETECTION CAPABILITIES:
 * =================================
 *
 * 1. SHELLCODE DETECTION
 *    - NOP sled detection
 *    - GetPC/GetEIP tricks
 *    - Syscall patterns
 *    - Decoder stubs
 *    - Egg hunters
 *
 * 2. HEAP EXPLOITATION
 *    - Heap spray detection
 *    - Heap feng shui
 *    - Use-After-Free patterns
 *    - Type confusion
 *    - Double-free detection
 *
 * 3. STACK EXPLOITATION
 *    - Buffer overflow detection
 *    - Stack pivoting
 *    - ROP chain detection
 *    - JOP chain detection
 *    - Canary bypass attempts
 *
 * 4. MEMORY CORRUPTION
 *    - Arbitrary write detection
 *    - Info leak patterns
 *    - ASLR bypass techniques
 *    - DEP bypass detection
 *    - CFG bypass attempts
 *
 * 5. CVE CORRELATION
 *    - Known exploit patterns
 *    - CVE database lookup
 *    - Vulnerability scoring
 *    - MITRE ATT&CK mapping
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../../Utils/Logger.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class ZeroDayDetectorImpl;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ZeroDayConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Minimum NOP sled length
    inline constexpr size_t MIN_NOP_SLED_LENGTH = 16;
    
    /// @brief Heap spray threshold (allocations)
    inline constexpr size_t HEAP_SPRAY_THRESHOLD = 100;
    
    /// @brief ROP gadget chain threshold
    inline constexpr size_t ROP_CHAIN_THRESHOLD = 5;
    
    /// @brief Maximum buffer analysis size (64 MB)
    inline constexpr size_t MAX_BUFFER_SIZE = 64 * 1024 * 1024;
    
    /// @brief Shellcode entropy threshold
    inline constexpr float SHELLCODE_ENTROPY_THRESHOLD = 5.5f;

}  // namespace ZeroDayConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Exploit type
 */
enum class ExploitType : uint8_t {
    Unknown             = 0,
    StackOverflow       = 1,
    HeapOverflow        = 2,
    HeapSpray           = 3,
    UseAfterFree        = 4,
    DoubleFree          = 5,
    TypeConfusion       = 6,
    IntegerOverflow     = 7,
    FormatString        = 8,
    ROPChain            = 9,
    JOPChain            = 10,
    Shellcode           = 11,
    StackPivot          = 12,
    InfoLeak            = 13,
    ArbitraryRead       = 14,
    ArbitraryWrite      = 15,
    ASLRBypass          = 16,
    DEPBypass           = 17,
    CFGBypass           = 18,
    KernelExploit       = 19,
    PrivilegeEscalation = 20
};

/**
 * @brief Shellcode type
 */
enum class ShellcodeType : uint8_t {
    Unknown         = 0,
    ConnectBack     = 1,    ///< Reverse shell
    BindShell       = 2,    ///< Bind shell
    Downloader      = 3,    ///< Download and execute
    Stager          = 4,    ///< Multi-stage loader
    Egg_Hunter      = 5,    ///< Egg hunter shellcode
    Meterpreter     = 6,    ///< Metasploit meterpreter
    CobaltStrike    = 7,    ///< Cobalt Strike beacon
    Custom          = 8
};

/**
 * @brief ROP gadget type
 */
enum class GadgetType : uint8_t {
    Unknown         = 0,
    PopRet          = 1,    ///< pop reg; ret
    MoveRet         = 2,    ///< mov reg, reg; ret
    AddRet          = 3,    ///< add reg, val; ret
    XchgRet         = 4,    ///< xchg reg, reg; ret
    WriteWhat       = 5,    ///< mov [reg], reg; ret
    StackPivot      = 6,    ///< xchg esp, reg; ret
    Syscall         = 7,    ///< syscall; ret
    JmpReg          = 8,    ///< jmp reg
    CallReg         = 9     ///< call reg
};

/**
 * @brief Severity level
 */
enum class ExploitSeverity : uint8_t {
    Low             = 0,
    Medium          = 1,
    High            = 2,
    Critical        = 3
};

/**
 * @brief Detection confidence
 */
enum class DetectionConfidence : uint8_t {
    Low             = 0,    ///< Possible false positive
    Medium          = 1,    ///< Likely exploit
    High            = 2,    ///< Very likely exploit
    Certain         = 3     ///< Confirmed exploit pattern
};

/**
 * @brief Detector status
 */
enum class ZeroDayStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Analyzing       = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief ROP gadget info
 */
struct ROPGadget {
    /// @brief Gadget address
    uint64_t address = 0;
    
    /// @brief Gadget type
    GadgetType type = GadgetType::Unknown;
    
    /// @brief Gadget bytes
    std::vector<uint8_t> bytes;
    
    /// @brief Disassembly
    std::string disassembly;
    
    /// @brief Module containing gadget
    std::string module;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief ROP chain info
 */
struct ROPChainInfo {
    /// @brief Gadgets in chain
    std::vector<ROPGadget> gadgets;
    
    /// @brief Chain start address
    uint64_t startAddress = 0;
    
    /// @brief Estimated purpose
    std::string purpose;
    
    /// @brief Is complete chain
    bool isComplete = false;
    
    /// @brief Target API (if detectable)
    std::string targetAPI;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Shellcode info
 */
struct ShellcodeInfo {
    /// @brief Shellcode type
    ShellcodeType type = ShellcodeType::Unknown;
    
    /// @brief Start offset
    uint64_t startOffset = 0;
    
    /// @brief Size
    size_t size = 0;
    
    /// @brief Entropy
    float entropy = 0.0f;
    
    /// @brief Has NOP sled
    bool hasNopSled = false;
    
    /// @brief NOP sled length
    size_t nopSledLength = 0;
    
    /// @brief Has GetPC
    bool hasGetPC = false;
    
    /// @brief Has decoder stub
    bool hasDecoderStub = false;
    
    /// @brief Is encoded
    bool isEncoded = false;
    
    /// @brief Encoding type (if detected)
    std::string encodingType;
    
    /// @brief Target platform
    std::string platform;
    
    /// @brief Network indicators (IPs, ports)
    std::vector<std::string> networkIndicators;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Heap spray info
 */
struct HeapSprayInfo {
    /// @brief Pattern detected
    std::vector<uint8_t> pattern;
    
    /// @brief Number of allocations
    size_t allocationCount = 0;
    
    /// @brief Total size sprayed
    size_t totalSize = 0;
    
    /// @brief Spray value (e.g., 0x0c0c0c0c)
    uint32_t sprayValue = 0;
    
    /// @brief Contains shellcode
    bool containsShellcode = false;
    
    /// @brief Contains ROP
    bool containsROP = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Memory corruption info
 */
struct MemoryCorruptionInfo {
    /// @brief Corruption type
    std::string corruptionType;
    
    /// @brief Target address
    uint64_t targetAddress = 0;
    
    /// @brief Source address
    uint64_t sourceAddress = 0;
    
    /// @brief Written value
    std::optional<uint64_t> writtenValue;
    
    /// @brief Leaked value
    std::optional<uint64_t> leakedValue;
    
    /// @brief Vulnerable function
    std::string vulnerableFunction;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief CVE match info
 */
struct CVEMatch {
    /// @brief CVE ID
    std::string cveId;
    
    /// @brief CVE description
    std::string description;
    
    /// @brief CVSS score
    float cvssScore = 0.0f;
    
    /// @brief Affected product
    std::string affectedProduct;
    
    /// @brief Exploit pattern matched
    std::string matchedPattern;
    
    /// @brief Confidence
    float confidence = 0.0f;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Zero-day detection result
 */
struct ZeroDayResult {
    /// @brief Was exploit detected
    bool detected = false;
    
    /// @brief Exploit type
    ExploitType type = ExploitType::Unknown;
    
    /// @brief Severity
    ExploitSeverity severity = ExploitSeverity::Low;
    
    /// @brief Detection confidence
    DetectionConfidence confidence = DetectionConfidence::Low;
    
    /// @brief Offset where detected
    uint64_t offset = 0;
    
    /// @brief Description
    std::string description;
    
    /// @brief Shellcode info (if detected)
    std::optional<ShellcodeInfo> shellcodeInfo;
    
    /// @brief ROP chain info (if detected)
    std::optional<ROPChainInfo> ropChainInfo;
    
    /// @brief Heap spray info (if detected)
    std::optional<HeapSprayInfo> heapSprayInfo;
    
    /// @brief Memory corruption info
    std::optional<MemoryCorruptionInfo> corruptionInfo;
    
    /// @brief CVE matches
    std::vector<CVEMatch> cveMatches;
    
    /// @brief MITRE ATT&CK techniques
    std::set<std::string> mitreIds;
    
    /// @brief Additional indicators
    std::vector<std::string> indicators;
    
    /// @brief Analysis time (microseconds)
    uint64_t analysisTimeUs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Analysis options
 */
struct ZeroDayAnalysisOptions {
    /// @brief Enable shellcode detection
    bool detectShellcode = true;
    
    /// @brief Enable ROP detection
    bool detectROP = true;
    
    /// @brief Enable heap spray detection
    bool detectHeapSpray = true;
    
    /// @brief Enable memory corruption detection
    bool detectMemoryCorruption = true;
    
    /// @brief Maximum analysis time (milliseconds)
    uint32_t maxAnalysisTimeMs = 10000;
    
    /// @brief Minimum confidence to report
    DetectionConfidence minConfidence = DetectionConfidence::Low;
    
    /// @brief CVE correlation
    bool correlateCVE = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct ZeroDayStatistics {
    std::atomic<uint64_t> totalAnalyses{0};
    std::atomic<uint64_t> exploitsDetected{0};
    std::atomic<uint64_t> shellcodeDetected{0};
    std::atomic<uint64_t> ropChainsDetected{0};
    std::atomic<uint64_t> heapSpraysDetected{0};
    std::atomic<uint64_t> corruptionsDetected{0};
    std::atomic<uint64_t> cveMatches{0};
    std::atomic<uint64_t> falsePositives{0};
    std::array<std::atomic<uint64_t>, 32> byExploitType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ZeroDayConfiguration {
    /// @brief Enable zero-day detection
    bool enabled = true;
    
    /// @brief Default analysis options
    ZeroDayAnalysisOptions defaultOptions;
    
    /// @brief Worker threads
    uint32_t workerThreads = 2;
    
    /// @brief Enable learning mode
    bool learningMode = false;
    
    /// @brief CVE database path
    fs::path cveDatabasePath;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DetectionCallback = std::function<void(const ZeroDayResult& result)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// ZERO DAY DETECTOR CLASS
// ============================================================================

/**
 * @class ZeroDayDetector
 * @brief Enterprise zero-day detection
 */
class ZeroDayDetector final {
public:
    [[nodiscard]] static ZeroDayDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ZeroDayDetector(const ZeroDayDetector&) = delete;
    ZeroDayDetector& operator=(const ZeroDayDetector&) = delete;
    ZeroDayDetector(ZeroDayDetector&&) = delete;
    ZeroDayDetector& operator=(ZeroDayDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ZeroDayConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ZeroDayStatus GetStatus() const noexcept;

    // ========================================================================
    // BUFFER ANALYSIS
    // ========================================================================
    
    /// @brief Analyze buffer for exploit patterns
    [[nodiscard]] ZeroDayResult AnalyzeBuffer(const std::vector<uint8_t>& buffer);
    
    /// @brief Analyze buffer with options
    [[nodiscard]] ZeroDayResult AnalyzeBuffer(
        std::span<const uint8_t> buffer,
        const ZeroDayAnalysisOptions& options = {});
    
    /// @brief Analyze file
    [[nodiscard]] ZeroDayResult AnalyzeFile(const fs::path& filePath, const ZeroDayAnalysisOptions& options = {});

    // ========================================================================
    // STACK ANALYSIS
    // ========================================================================
    
    /// @brief Analyze stack for ROP gadgets
    [[nodiscard]] ZeroDayResult AnalyzeStack(const std::vector<uintptr_t>& stackDump);
    
    /// @brief Analyze stack with module info
    [[nodiscard]] ZeroDayResult AnalyzeStack(
        std::span<const uintptr_t> stackDump,
        const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges);

    // ========================================================================
    // SHELLCODE DETECTION
    // ========================================================================
    
    /// @brief Detect shellcode in buffer
    [[nodiscard]] std::optional<ShellcodeInfo> DetectShellcode(std::span<const uint8_t> buffer);
    
    /// @brief Check for NOP sled
    [[nodiscard]] bool IsNopSled(std::span<const uint8_t> buffer);
    
    /// @brief Check for GetPC trick
    [[nodiscard]] bool HasGetPC(std::span<const uint8_t> buffer);
    
    /// @brief Check for decoder stub
    [[nodiscard]] bool HasDecoderStub(std::span<const uint8_t> buffer);

    // ========================================================================
    // ROP DETECTION
    // ========================================================================
    
    /// @brief Detect ROP chain
    [[nodiscard]] std::optional<ROPChainInfo> DetectROPChain(
        std::span<const uintptr_t> addresses,
        const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges);
    
    /// @brief Find ROP gadgets in module
    [[nodiscard]] std::vector<ROPGadget> FindGadgets(std::span<const uint8_t> moduleData, uintptr_t baseAddress);

    // ========================================================================
    // HEAP ANALYSIS
    // ========================================================================
    
    /// @brief Detect heap spray
    [[nodiscard]] std::optional<HeapSprayInfo> DetectHeapSpray(
        const std::vector<std::pair<uintptr_t, size_t>>& allocations);
    
    /// @brief Analyze heap allocation patterns
    [[nodiscard]] bool IsHeapSprayPattern(std::span<const uint8_t> data);

    // ========================================================================
    // CVE CORRELATION
    // ========================================================================
    
    /// @brief Lookup matching CVEs
    [[nodiscard]] std::vector<CVEMatch> LookupCVE(const ZeroDayResult& result);
    
    /// @brief Get CVE info
    [[nodiscard]] std::optional<CVEMatch> GetCVEInfo(const std::string& cveId);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterDetectionCallback(DetectionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ZeroDayStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ZeroDayDetector();
    ~ZeroDayDetector();
    
    bool IsNopSledInternal(const std::vector<uint8_t>& buffer);
    bool HasGetPCInternal(const std::vector<uint8_t>& buffer);
    
    std::unique_ptr<ZeroDayDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetExploitTypeName(ExploitType type) noexcept;
[[nodiscard]] std::string_view GetShellcodeTypeName(ShellcodeType type) noexcept;
[[nodiscard]] std::string_view GetGadgetTypeName(GadgetType type) noexcept;
[[nodiscard]] std::string_view GetExploitSeverityName(ExploitSeverity severity) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence confidence) noexcept;

/// @brief Calculate buffer entropy
[[nodiscard]] float CalculateEntropy(std::span<const uint8_t> data);

/// @brief Is potential shellcode based on heuristics
[[nodiscard]] bool IsPotentialShellcode(std::span<const uint8_t> data);

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ZERODAY_ANALYZE(buffer) \
    ::ShadowStrike::Core::Engine::ZeroDayDetector::Instance().AnalyzeBuffer(buffer)

#define SS_ZERODAY_STACK(stack) \
    ::ShadowStrike::Core::Engine::ZeroDayDetector::Instance().AnalyzeStack(stack)
