/**
 * ============================================================================
 * ShadowStrike NGAV - POLYMORPHIC DETECTOR MODULE
 * ============================================================================
 *
 * @file PolymorphicDetector.hpp
 * @brief Enterprise-grade detection of polymorphic, metamorphic, and
 *        self-modifying malware engines with code normalization.
 *
 * Provides advanced detection capabilities for malware that changes its
 * code structure to evade signature-based detection.
 *
 * POLYMORPHIC DETECTION CAPABILITIES:
 * ====================================
 *
 * 1. CODE NORMALIZATION
 *    - Register renaming
 *    - Instruction substitution
 *    - Junk code removal
 *    - Dead code elimination
 *    - CFG normalization
 *
 * 2. POLYMORPHIC ENGINE DETECTION
 *    - Known engine signatures
 *    - Decryption loop detection
 *    - XOR pattern analysis
 *    - Key extraction
 *    - Mutation tracking
 *
 * 3. METAMORPHIC ANALYSIS
 *    - Instruction permutation
 *    - Equivalent instruction detection
 *    - Code transposition
 *    - Subroutine reordering
 *
 * 4. FUZZY MATCHING
 *    - Fuzzy hash integration
 *    - TLSH similarity
 *    - Normalized hash matching
 *    - Family clustering
 *
 * 5. BEHAVIORAL PATTERNS
 *    - Self-decryption detection
 *    - Code modification patterns
 *    - Memory unpacking
 *    - API obfuscation
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
#include "../../HashStore/HashStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class PolymorphicDetectorImpl;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PolyConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum code size to analyze (16 MB)
    inline constexpr size_t MAX_CODE_SIZE = 16 * 1024 * 1024;
    
    /// @brief Maximum normalization iterations
    inline constexpr uint32_t MAX_NORMALIZATION_PASSES = 10;
    
    /// @brief Minimum code size for analysis
    inline constexpr size_t MIN_CODE_SIZE = 32;
    
    /// @brief Fuzzy hash similarity threshold
    inline constexpr uint32_t FUZZY_THRESHOLD = 70;
    
    /// @brief Decryption loop detection threshold
    inline constexpr uint32_t DECRYPT_LOOP_THRESHOLD = 5;

}  // namespace PolyConstants

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
 * @brief Polymorphic engine type
 */
enum class PolyEngineType : uint8_t {
    Unknown         = 0,
    Mistfall        = 1,
    EPC             = 2,
    SMEG            = 3,
    Dark_Avenger    = 4,
    One_Half        = 5,
    IDEA            = 6,
    TPE             = 7,
    MtE             = 8,     ///< Mutation Engine
    NED             = 9,     ///< NuKE Encryption Device
    DAME            = 10,    ///< Dark Angel's Multiple Encryptor
    VCL             = 11,    ///< Virus Creation Lab
    Phalcon_Skism   = 12,
    Custom          = 13
};

/**
 * @brief Mutation type
 */
enum class MutationType : uint8_t {
    None            = 0,
    RegisterSwap    = 1,
    InstructionSub  = 2,    ///< Equivalent instruction substitution
    JunkInsertion   = 3,
    CodeReorder     = 4,
    LoopUnroll      = 5,
    Encryption      = 6,
    Compression     = 7,
    Combined        = 8
};

/**
 * @brief Normalization level
 */
enum class NormalizationLevel : uint8_t {
    None            = 0,
    Basic           = 1,    ///< NOP removal, dead code
    Standard        = 2,    ///< + Register normalization
    Aggressive      = 3,    ///< + Instruction substitution
    Full            = 4     ///< All normalizations
};

/**
 * @brief Detection confidence
 */
enum class DetectionConfidence : uint8_t {
    None            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Certain         = 4
};

/**
 * @brief Detector status
 */
enum class PolyDetectorStatus : uint8_t {
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
 * @brief Decryption loop info
 */
struct DecryptionLoopInfo {
    /// @brief Loop start address
    uint64_t loopStart = 0;
    
    /// @brief Loop end address
    uint64_t loopEnd = 0;
    
    /// @brief Loop iterations (if determinable)
    uint32_t iterations = 0;
    
    /// @brief XOR key (if found)
    std::optional<std::vector<uint8_t>> xorKey;
    
    /// @brief Decrypted region start
    uint64_t decryptedStart = 0;
    
    /// @brief Decrypted region size
    size_t decryptedSize = 0;
    
    /// @brief Algorithm detected
    std::string algorithm;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Junk code region
 */
struct JunkCodeRegion {
    /// @brief Start offset
    size_t startOffset = 0;
    
    /// @brief End offset
    size_t endOffset = 0;
    
    /// @brief Size
    size_t size = 0;
    
    /// @brief Pattern type
    std::string patternType;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Normalization result
 */
struct NormalizationResult {
    /// @brief Normalized code
    std::vector<uint8_t> normalizedCode;
    
    /// @brief Original size
    size_t originalSize = 0;
    
    /// @brief Normalized size
    size_t normalizedSize = 0;
    
    /// @brief Reduction ratio
    float reductionRatio = 0.0f;
    
    /// @brief Junk code regions removed
    std::vector<JunkCodeRegion> junkRegions;
    
    /// @brief Instructions removed
    uint32_t instructionsRemoved = 0;
    
    /// @brief Passes performed
    uint32_t passesPerformed = 0;
    
    /// @brief Processing time (milliseconds)
    uint32_t processingTimeMs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Fuzzy hash match
 */
struct FuzzyHashMatch {
    /// @brief Match score (0-100)
    uint32_t score = 0;
    
    /// @brief Matched hash
    std::string matchedHash;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Family name
    std::string familyName;
    
    /// @brief Variant
    std::string variant;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Polymorphic analysis result
 */
struct PolyResult {
    /// @brief Is polymorphic
    bool isPolymorphic = false;
    
    /// @brief Is metamorphic
    bool isMetamorphic = false;
    
    /// @brief Engine type
    PolyEngineType engineType = PolyEngineType::Unknown;
    
    /// @brief Engine name
    std::string engineName;
    
    /// @brief Mutation types detected
    std::set<MutationType> mutations;
    
    /// @brief Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Normalized body
    std::vector<uint8_t> normalizedBody;
    
    /// @brief Normalization result
    NormalizationResult normalizationInfo;
    
    /// @brief Decryption loops found
    std::vector<DecryptionLoopInfo> decryptionLoops;
    
    /// @brief Fuzzy hash matches
    std::vector<FuzzyHashMatch> fuzzyMatches;
    
    /// @brief Fuzzy hash (of normalized code)
    std::string fuzzyHash;
    
    /// @brief TLSH hash (of normalized code)
    std::string tlshHash;
    
    /// @brief Threat family (if identified)
    std::string threatFamily;
    
    /// @brief Analysis time (milliseconds)
    uint32_t analysisTimeMs = 0;
    
    /// @brief Additional indicators
    std::vector<std::string> indicators;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Analysis options
 */
struct PolyAnalysisOptions {
    /// @brief Normalization level
    NormalizationLevel normalizationLevel = NormalizationLevel::Standard;
    
    /// @brief Enable fuzzy matching
    bool enableFuzzyMatching = true;
    
    /// @brief Fuzzy hash threshold
    uint32_t fuzzyThreshold = PolyConstants::FUZZY_THRESHOLD;
    
    /// @brief Enable decryption loop detection
    bool detectDecryptionLoops = true;
    
    /// @brief Maximum analysis time (milliseconds)
    uint32_t maxAnalysisTimeMs = 30000;
    
    /// @brief Extract decrypted payload
    bool extractDecryptedPayload = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct PolyStatistics {
    std::atomic<uint64_t> totalAnalyses{0};
    std::atomic<uint64_t> polymorphicDetected{0};
    std::atomic<uint64_t> metamorphicDetected{0};
    std::atomic<uint64_t> fuzzyMatches{0};
    std::atomic<uint64_t> decryptionLoopsFound{0};
    std::atomic<uint64_t> normalizationOperations{0};
    std::atomic<uint64_t> junkCodeRemoved{0};
    std::array<std::atomic<uint64_t>, 16> byEngineType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PolymorphicConfiguration {
    /// @brief Enable polymorphic detection
    bool enabled = true;
    
    /// @brief Default analysis options
    PolyAnalysisOptions defaultOptions;
    
    /// @brief Worker threads
    uint32_t workerThreads = 2;
    
    /// @brief Enable result caching
    bool enableCaching = true;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTtlSeconds = 3600;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AnalysisCallback = std::function<void(const PolyResult& result)>;
using FuzzyMatchCallback = std::function<void(const FuzzyHashMatch& match)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// POLYMORPHIC DETECTOR CLASS
// ============================================================================

/**
 * @class PolymorphicDetector
 * @brief Enterprise polymorphic detection
 */
class PolymorphicDetector final {
public:
    [[nodiscard]] static PolymorphicDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PolymorphicDetector(const PolymorphicDetector&) = delete;
    PolymorphicDetector& operator=(const PolymorphicDetector&) = delete;
    PolymorphicDetector(PolymorphicDetector&&) = delete;
    PolymorphicDetector& operator=(PolymorphicDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PolymorphicConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] PolyDetectorStatus GetStatus() const noexcept;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Analyze code for polymorphic properties
    [[nodiscard]] PolyResult Analyze(const std::vector<uint8_t>& code);
    
    /// @brief Analyze with span
    [[nodiscard]] PolyResult Analyze(std::span<const uint8_t> code, const PolyAnalysisOptions& options = {});
    
    /// @brief Analyze file
    [[nodiscard]] PolyResult AnalyzeFile(const fs::path& filePath, const PolyAnalysisOptions& options = {});
    
    /// @brief Async analyze
    void AnalyzeAsync(std::span<const uint8_t> code, AnalysisCallback callback, const PolyAnalysisOptions& options = {});

    // ========================================================================
    // NORMALIZATION
    // ========================================================================
    
    /// @brief Normalize instructions (legacy)
    [[nodiscard]] std::vector<uint8_t> NormalizeInstructions(const std::vector<uint8_t>& input);
    
    /// @brief Normalize with options
    [[nodiscard]] NormalizationResult NormalizeCode(
        std::span<const uint8_t> code,
        NormalizationLevel level = NormalizationLevel::Standard);
    
    /// @brief Remove junk code
    [[nodiscard]] std::vector<uint8_t> RemoveJunkCode(std::span<const uint8_t> code);
    
    /// @brief Normalize registers
    [[nodiscard]] std::vector<uint8_t> NormalizeRegisters(std::span<const uint8_t> code);

    // ========================================================================
    // ENGINE DETECTION
    // ========================================================================
    
    /// @brief Detect polymorphic engine
    [[nodiscard]] std::optional<PolyEngineType> DetectEngine(std::span<const uint8_t> code);
    
    /// @brief Get engine name
    [[nodiscard]] std::string GetEngineName(PolyEngineType engine) const;
    
    /// @brief Detect mutation types
    [[nodiscard]] std::set<MutationType> DetectMutations(std::span<const uint8_t> code);

    // ========================================================================
    // DECRYPTION ANALYSIS
    // ========================================================================
    
    /// @brief Find decryption loops
    [[nodiscard]] std::vector<DecryptionLoopInfo> FindDecryptionLoops(std::span<const uint8_t> code);
    
    /// @brief Extract XOR key
    [[nodiscard]] std::optional<std::vector<uint8_t>> ExtractXORKey(std::span<const uint8_t> code);
    
    /// @brief Decrypt payload
    [[nodiscard]] std::optional<std::vector<uint8_t>> DecryptPayload(
        std::span<const uint8_t> encryptedData,
        const std::vector<uint8_t>& key);

    // ========================================================================
    // FUZZY MATCHING
    // ========================================================================
    
    /// @brief Match with fuzzy hash database
    [[nodiscard]] std::vector<FuzzyHashMatch> FuzzyMatch(std::span<const uint8_t> normalizedCode);
    
    /// @brief Calculate fuzzy hash
    [[nodiscard]] std::string CalculateFuzzyHash(std::span<const uint8_t> data);
    
    /// @brief Calculate TLSH hash
    [[nodiscard]] std::string CalculateTLSH(std::span<const uint8_t> data);
    
    /// @brief Compare fuzzy hashes
    [[nodiscard]] uint32_t CompareFuzzyHash(const std::string& hash1, const std::string& hash2);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterFuzzyMatchCallback(FuzzyMatchCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] PolyStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PolymorphicDetector();
    ~PolymorphicDetector();
    
    std::unique_ptr<PolymorphicDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPolyEngineTypeName(PolyEngineType engine) noexcept;
[[nodiscard]] std::string_view GetMutationTypeName(MutationType mutation) noexcept;
[[nodiscard]] std::string_view GetNormalizationLevelName(NormalizationLevel level) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence confidence) noexcept;

/// @brief Is code potentially polymorphic (quick check)
[[nodiscard]] bool IsPotentiallyPolymorphic(std::span<const uint8_t> code);

/// @brief Get entropy of code section
[[nodiscard]] float GetCodeEntropy(std::span<const uint8_t> code);

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_POLY_ANALYZE(code) \
    ::ShadowStrike::Core::Engine::PolymorphicDetector::Instance().Analyze(code)

#define SS_IS_POLYMORPHIC(code) \
    ::ShadowStrike::Core::Engine::PolymorphicDetector::Instance().Analyze(code).isPolymorphic
