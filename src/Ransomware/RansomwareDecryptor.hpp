/**
 * ============================================================================
 * ShadowStrike Ransomware Recovery - RANSOMWARE DECRYPTOR ENGINE
 * ============================================================================
 *
 * @file RansomwareDecryptor.hpp
 * @brief Enterprise-grade ransomware decryption and file recovery engine
 *        for restoring files encrypted by known ransomware families.
 *
 * This module provides comprehensive decryption capabilities for files
 * encrypted by ransomware families with known or leaked encryption keys,
 * flawed cryptographic implementations, or available decryption tools.
 *
 * DECRYPTION CAPABILITIES:
 * ========================
 *
 * 1. KEY-BASED DECRYPTION
 *    - Leaked master keys
 *    - Law enforcement key releases
 *    - Attacker-released keys
 *    - Key derivation from artifacts
 *
 * 2. CRYPTOGRAPHIC WEAKNESSES
 *    - Weak PRNG exploitation
 *    - Key reuse detection
 *    - IV/nonce vulnerabilities
 *    - Implementation flaws
 *
 * 3. FILE RECOVERY
 *    - Partial decryption
 *    - Header reconstruction
 *    - Footer recovery
 *    - Metadata restoration
 *
 * 4. FAMILY IDENTIFICATION
 *    - Extension analysis
 *    - Ransom note parsing
 *    - Magic byte detection
 *    - Encryption artifact analysis
 *
 * 5. BATCH OPERATIONS
 *    - Directory scanning
 *    - Recursive decryption
 *    - Progress tracking
 *    - Error handling
 *
 * 6. VALIDATION
 *    - Pre-decryption verification
 *    - Post-decryption validation
 *    - File integrity checking
 *    - Type verification
 *
 * SUPPORTED FAMILIES:
 * ===================
 * - TeslaCrypt (all versions)
 * - GandCrab v4/v5
 * - Shade/Troldesh
 * - Crysis/Dharma (some variants)
 * - STOP/Djvu (offline keys)
 * - Jigsaw
 * - And more...
 *
 * @note Never pay ransoms - always check for available decryptors first.
 * @note Decryption requires proper key material for each family.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, GDPR
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
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>

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

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Security/CryptoManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class RansomwareDecryptorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DecryptorConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum file size for decryption
    inline constexpr uint64_t MAX_FILE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
    
    /// @brief Maximum files in batch
    inline constexpr size_t MAX_BATCH_FILES = 100000;
    
    /// @brief Maximum decryptors loaded
    inline constexpr size_t MAX_DECRYPTORS = 100;
    
    /// @brief Maximum keys per family
    inline constexpr size_t MAX_KEYS_PER_FAMILY = 1000;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Per-file timeout (milliseconds)
    inline constexpr uint32_t FILE_TIMEOUT_MS = 300000;  // 5 minutes
    
    /// @brief Batch timeout (milliseconds)
    inline constexpr uint32_t BATCH_TIMEOUT_MS = 86400000;  // 24 hours

    // ========================================================================
    // CRYPTO
    // ========================================================================
    
    /// @brief Default buffer size
    inline constexpr size_t BUFFER_SIZE = 1024 * 1024;  // 1MB

}  // namespace DecryptorConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Decryption result status
 */
enum class DecryptionStatus : uint8_t {
    Success             = 0,    ///< Decryption successful
    PartialSuccess      = 1,    ///< Partial decryption
    Failed              = 2,    ///< Decryption failed
    UnknownFamily       = 3,    ///< Unknown ransomware family
    NoKeyAvailable      = 4,    ///< No decryption key available
    InvalidFile         = 5,    ///< Invalid encrypted file
    CorruptedFile       = 6,    ///< File is corrupted
    IOError             = 7,    ///< File I/O error
    Timeout             = 8,    ///< Operation timed out
    Cancelled           = 9,    ///< Operation cancelled
    AlreadyDecrypted    = 10    ///< File already decrypted
};

/**
 * @brief Ransomware family (extended list)
 */
enum class RansomwareFamily : uint16_t {
    Unknown             = 0,
    WannaCry            = 1,
    Locky               = 2,
    CryptoLocker        = 3,
    TeslaCrypt          = 4,
    TeslaCryptV2        = 5,
    TeslaCryptV3        = 6,
    TeslaCryptV4        = 7,
    Cerber              = 8,
    Petya               = 9,
    NotPetya            = 10,
    GandCrabV4          = 11,
    GandCrabV5          = 12,
    Shade               = 13,
    Troldesh            = 14,
    Crysis              = 15,
    Dharma              = 16,
    Phobos              = 17,
    STOP                = 18,
    Djvu                = 19,
    Jigsaw              = 20,
    BTCWare             = 21,
    GlobeImposter       = 22,
    SamSam              = 23,
    Ryuk                = 24,
    REvil               = 25,
    Maze                = 26,
    Conti               = 27,
    LockBit             = 28,
    BlackCat            = 29,
    Hive                = 30,
    Custom              = 0xFFFF
};

/**
 * @brief Key type
 */
enum class KeyType : uint8_t {
    Unknown         = 0,
    MasterKey       = 1,    ///< Master/global key
    SessionKey      = 2,    ///< Per-session key
    FileKey         = 3,    ///< Per-file key
    OfflineKey      = 4,    ///< Offline ID key
    OnlineKey       = 5,    ///< Online ID key
    DerivedKey      = 6     ///< Key derived from artifacts
};

/**
 * @brief Encryption algorithm
 */
enum class EncryptionAlgorithm : uint8_t {
    Unknown         = 0,
    AES128CBC       = 1,
    AES256CBC       = 2,
    AES128CTR       = 3,
    AES256CTR       = 4,
    AES128GCM       = 5,
    AES256GCM       = 6,
    RSA2048         = 7,
    RSA4096         = 8,
    ChaCha20        = 9,
    Salsa20         = 10,
    RC4             = 11,
    Blowfish        = 12,
    Twofish         = 13,
    Custom          = 255
};

/**
 * @brief Key source
 */
enum class KeySource : uint8_t {
    Unknown         = 0,
    Leaked          = 1,    ///< Leaked by attacker
    LawEnforcement  = 2,    ///< Released by LE
    Research        = 3,    ///< Security research
    Weakness        = 4,    ///< Cryptographic weakness
    UserProvided    = 5     ///< User-provided key
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Decrypting      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Encrypted file information
 */
struct EncryptedFileInfo {
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Original filename (if recoverable)
    std::wstring originalName;
    
    /// @brief Encrypted extension
    std::wstring encryptedExtension;
    
    /// @brief Original extension (if known)
    std::wstring originalExtension;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Identified family
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Encryption algorithm
    EncryptionAlgorithm algorithm = EncryptionAlgorithm::Unknown;
    
    /// @brief Encryption header (first bytes)
    std::vector<uint8_t> header;
    
    /// @brief File hash (SHA256)
    Hash256 fileHash{};
    
    /// @brief Victim ID (if present)
    std::string victimId;
    
    /// @brief Can be decrypted
    bool canDecrypt = false;
    
    /// @brief Confidence in identification
    double confidence = 0.0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Decryption key
 */
struct DecryptionKey {
    /// @brief Key ID
    std::string keyId;
    
    /// @brief Key type
    KeyType keyType = KeyType::Unknown;
    
    /// @brief Key source
    KeySource source = KeySource::Unknown;
    
    /// @brief Target family
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Algorithm
    EncryptionAlgorithm algorithm = EncryptionAlgorithm::Unknown;
    
    /// @brief Key data
    std::vector<uint8_t> keyData;
    
    /// @brief IV/nonce (if applicable)
    std::vector<uint8_t> iv;
    
    /// @brief RSA private key (PEM format)
    std::string rsaPrivateKey;
    
    /// @brief Valid from date
    SystemTimePoint validFrom;
    
    /// @brief Valid until date
    SystemTimePoint validUntil;
    
    /// @brief Victim IDs this key works for
    std::vector<std::string> victimIds;
    
    /// @brief Is master key (works for all victims)
    bool isMasterKey = false;
    
    /// @brief Notes
    std::string notes;
    
    /**
     * @brief Check if key is valid for file
     */
    [[nodiscard]] bool IsValidFor(const EncryptedFileInfo& file) const;
    
    /**
     * @brief Serialize to JSON (excluding sensitive data)
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Decryption result
 */
struct DecryptionResult {
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Decrypted file path
    std::wstring decryptedPath;
    
    /// @brief Status
    DecryptionStatus status = DecryptionStatus::Failed;
    
    /// @brief Family
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Key used
    std::string keyId;
    
    /// @brief Duration (milliseconds)
    uint64_t durationMs = 0;
    
    /// @brief Original size
    uint64_t originalSize = 0;
    
    /// @brief Decrypted size
    uint64_t decryptedSize = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Validation passed
    bool validationPassed = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Batch decryption result
 */
struct BatchDecryptionResult {
    /// @brief Batch ID
    std::string batchId;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Total files
    uint64_t totalFiles = 0;
    
    /// @brief Files decrypted
    uint64_t filesDecrypted = 0;
    
    /// @brief Files failed
    uint64_t filesFailed = 0;
    
    /// @brief Files skipped
    uint64_t filesSkipped = 0;
    
    /// @brief Total bytes processed
    uint64_t bytesProcessed = 0;
    
    /// @brief Individual results
    std::vector<DecryptionResult> results;
    
    /// @brief Overall success rate
    [[nodiscard]] double GetSuccessRate() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Ransom note information
 */
struct RansomNoteInfo {
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Family
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Bitcoin address
    std::string bitcoinAddress;
    
    /// @brief Contact email
    std::string contactEmail;
    
    /// @brief TOR URL
    std::string torUrl;
    
    /// @brief Victim ID
    std::string victimId;
    
    /// @brief Ransom amount
    std::string ransomAmount;
    
    /// @brief Deadline
    std::optional<SystemTimePoint> deadline;
    
    /// @brief Full note text
    std::wstring noteText;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Decryptor configuration
 */
struct RansomwareDecryptorConfiguration {
    /// @brief Key database path
    std::wstring keyDatabasePath;
    
    /// @brief Backup before decryption
    bool backupBeforeDecrypt = true;
    
    /// @brief Backup directory
    std::wstring backupDirectory;
    
    /// @brief Validate after decryption
    bool validateAfterDecrypt = true;
    
    /// @brief Delete encrypted after success
    bool deleteEncryptedOnSuccess = false;
    
    /// @brief Restore original name
    bool restoreOriginalName = true;
    
    /// @brief Preserve timestamps
    bool preserveTimestamps = true;
    
    /// @brief Maximum concurrent decryptions
    uint32_t maxConcurrent = 4;
    
    /// @brief Per-file timeout (milliseconds)
    uint32_t fileTimeoutMs = DecryptorConstants::FILE_TIMEOUT_MS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Decryptor statistics
 */
struct DecryptorStatistics {
    /// @brief Files analyzed
    std::atomic<uint64_t> filesAnalyzed{0};
    
    /// @brief Files decrypted
    std::atomic<uint64_t> filesDecrypted{0};
    
    /// @brief Files failed
    std::atomic<uint64_t> filesFailed{0};
    
    /// @brief Bytes decrypted
    std::atomic<uint64_t> bytesDecrypted{0};
    
    /// @brief Families identified
    std::array<std::atomic<uint64_t>, 32> familiesIdentified{};
    
    /// @brief Keys loaded
    std::atomic<uint64_t> keysLoaded{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Progress callback
using DecryptionProgressCallback = std::function<void(
    const std::wstring& file, uint64_t processed, uint64_t total)>;

/// @brief Completion callback
using DecryptionCompleteCallback = std::function<void(const DecryptionResult&)>;

/// @brief Batch progress callback
using BatchProgressCallback = std::function<void(
    uint64_t filesProcessed, uint64_t totalFiles)>;

// ============================================================================
// RANSOMWARE DECRYPTOR CLASS
// ============================================================================

/**
 * @class RansomwareDecryptor
 * @brief Enterprise-grade ransomware decryption engine
 *
 * Provides comprehensive decryption capabilities for files encrypted
 * by known ransomware families with available decryption keys.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& decryptor = RansomwareDecryptor::Instance();
 *     
 *     // Identify family
 *     auto family = decryptor.IdentifyFamily(L"C:\\Infected");
 *     
 *     // Decrypt file
 *     if (decryptor.DecryptFile(L"C:\\file.locky", "Locky")) {
 *         // Success!
 *     }
 * @endcode
 */
class RansomwareDecryptor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static RansomwareDecryptor& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    RansomwareDecryptor(const RansomwareDecryptor&) = delete;
    RansomwareDecryptor& operator=(const RansomwareDecryptor&) = delete;
    RansomwareDecryptor(RansomwareDecryptor&&) = delete;
    RansomwareDecryptor& operator=(RansomwareDecryptor&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize decryptor
     */
    [[nodiscard]] bool Initialize(const RansomwareDecryptorConfiguration& config = {});
    
    /**
     * @brief Shutdown decryptor
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DECRYPTION OPERATIONS
    // ========================================================================
    
    /**
     * @brief Decrypt a file using known family keys
     * @param filePath Path to encrypted file
     * @param familyName Family name (e.g., "TeslaCrypt")
     * @return True if decryption successful
     */
    [[nodiscard]] bool DecryptFile(const std::wstring& filePath,
                                   const std::string& familyName);
    
    /**
     * @brief Decrypt file with detailed result
     */
    [[nodiscard]] DecryptionResult DecryptFileEx(std::wstring_view filePath,
                                                 RansomwareFamily family);
    
    /**
     * @brief Decrypt file with specific key
     */
    [[nodiscard]] DecryptionResult DecryptFileWithKey(std::wstring_view filePath,
                                                      const DecryptionKey& key);
    
    /**
     * @brief Decrypt all files in directory
     */
    [[nodiscard]] BatchDecryptionResult DecryptDirectory(std::wstring_view dirPath,
                                                         RansomwareFamily family,
                                                         bool recursive = true);
    
    /**
     * @brief Decrypt multiple files
     */
    [[nodiscard]] BatchDecryptionResult DecryptFiles(
        std::span<const std::wstring> filePaths,
        RansomwareFamily family);
    
    /**
     * @brief Cancel ongoing decryption
     */
    void CancelDecryption();
    
    // ========================================================================
    // FAMILY IDENTIFICATION
    // ========================================================================
    
    /**
     * @brief Identify ransomware family from folder
     * @param folderPath Path to infected folder
     * @return Family name
     */
    [[nodiscard]] std::string IdentifyFamily(const std::wstring& folderPath);
    
    /**
     * @brief Identify family from folder (returns enum)
     */
    [[nodiscard]] RansomwareFamily IdentifyFamilyEnum(std::wstring_view folderPath);
    
    /**
     * @brief Identify family from file
     */
    [[nodiscard]] RansomwareFamily IdentifyFamilyFromFile(std::wstring_view filePath);
    
    /**
     * @brief Identify family from extension
     */
    [[nodiscard]] RansomwareFamily IdentifyFamilyFromExtension(
        std::wstring_view extension);
    
    /**
     * @brief Analyze encrypted file
     */
    [[nodiscard]] EncryptedFileInfo AnalyzeFile(std::wstring_view filePath);
    
    /**
     * @brief Scan directory for encrypted files
     */
    [[nodiscard]] std::vector<EncryptedFileInfo> ScanDirectory(
        std::wstring_view dirPath, bool recursive = true);
    
    // ========================================================================
    // RANSOM NOTE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Find ransom notes in directory
     */
    [[nodiscard]] std::vector<RansomNoteInfo> FindRansomNotes(
        std::wstring_view dirPath, bool recursive = true);
    
    /**
     * @brief Parse ransom note
     */
    [[nodiscard]] RansomNoteInfo ParseRansomNote(std::wstring_view filePath);
    
    // ========================================================================
    // KEY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Load keys from database
     */
    [[nodiscard]] bool LoadKeyDatabase(std::wstring_view path);
    
    /**
     * @brief Add decryption key
     */
    void AddKey(const DecryptionKey& key);
    
    /**
     * @brief Remove key
     */
    void RemoveKey(const std::string& keyId);
    
    /**
     * @brief Get keys for family
     */
    [[nodiscard]] std::vector<DecryptionKey> GetKeysForFamily(
        RansomwareFamily family) const;
    
    /**
     * @brief Get key count
     */
    [[nodiscard]] size_t GetKeyCount() const noexcept;
    
    /**
     * @brief Check if decryption is available for family
     */
    [[nodiscard]] bool IsDecryptionAvailable(RansomwareFamily family) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set progress callback
     */
    void SetProgressCallback(DecryptionProgressCallback callback);
    
    /**
     * @brief Set completion callback
     */
    void SetCompleteCallback(DecryptionCompleteCallback callback);
    
    /**
     * @brief Set batch progress callback
     */
    void SetBatchProgressCallback(BatchProgressCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] DecryptorStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Get supported families
     */
    [[nodiscard]] std::vector<RansomwareFamily> GetSupportedFamilies() const;
    
    /**
     * @brief Get family name
     */
    [[nodiscard]] static std::string_view GetFamilyName(RansomwareFamily family) noexcept;
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    RansomwareDecryptor();
    ~RansomwareDecryptor();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<RansomwareDecryptorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get decryption status name
 */
[[nodiscard]] std::string_view GetDecryptionStatusName(DecryptionStatus status) noexcept;

/**
 * @brief Get key type name
 */
[[nodiscard]] std::string_view GetKeyTypeName(KeyType type) noexcept;

/**
 * @brief Get algorithm name
 */
[[nodiscard]] std::string_view GetAlgorithmName(EncryptionAlgorithm algo) noexcept;

/**
 * @brief Get key source name
 */
[[nodiscard]] std::string_view GetKeySourceName(KeySource source) noexcept;

/**
 * @brief Get known extensions for family
 */
[[nodiscard]] std::vector<std::wstring> GetFamilyExtensions(RansomwareFamily family);

/**
 * @brief Get known ransom note filenames for family
 */
[[nodiscard]] std::vector<std::wstring> GetFamilyRansomNotes(RansomwareFamily family);

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Decrypt file
 */
#define SS_DECRYPT_FILE(path, family) \
    ::ShadowStrike::Ransomware::RansomwareDecryptor::Instance().DecryptFile((path), (family))

/**
 * @brief Identify family
 */
#define SS_IDENTIFY_FAMILY(path) \
    ::ShadowStrike::Ransomware::RansomwareDecryptor::Instance().IdentifyFamily(path)
