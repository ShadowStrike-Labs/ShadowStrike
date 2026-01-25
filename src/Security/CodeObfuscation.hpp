/**
 * ============================================================================
 * ShadowStrike Security - CODE OBFUSCATION ENGINE
 * ============================================================================
 *
 * @file CodeObfuscation.hpp
 * @brief Enterprise-grade code obfuscation and anti-analysis system for
 *        protecting ShadowStrike internal logic from reverse engineering,
 *        static analysis, and tampering.
 *
 * This module implements sophisticated obfuscation techniques to protect
 * sensitive antivirus code, signatures, and detection logic from malware
 * authors attempting to evade detection.
 *
 * OBFUSCATION CAPABILITIES:
 * =========================
 *
 * 1. STRING ENCRYPTION
 *    - Compile-time string encryption
 *    - Runtime decryption only when needed
 *    - Multiple encryption algorithms
 *    - Key rotation support
 *    - Stack-only decrypted strings
 *
 * 2. CONTROL FLOW OBFUSCATION
 *    - Control flow flattening
 *    - Opaque predicates
 *    - Dead code insertion
 *    - Bogus control flow
 *    - Mixed boolean-arithmetic
 *
 * 3. DATA OBFUSCATION
 *    - Constant encoding
 *    - Array splitting
 *    - Variable substitution
 *    - Structure reorganization
 *    - Pointer arithmetic obfuscation
 *
 * 4. CODE TRANSFORMATION
 *    - Instruction substitution
 *    - Code virtualization
 *    - Metamorphic code generation
 *    - Function inlining/outlining
 *    - Code permutation
 *
 * 5. VM-BASED PROTECTION
 *    - Custom bytecode interpreter
 *    - Encrypted instruction handlers
 *    - Dynamic dispatch
 *    - Stack-based execution
 *    - Register virtualization
 *
 * 6. ANTI-ANALYSIS
 *    - Anti-disassembly tricks
 *    - Self-modifying code
 *    - Timing-based checks
 *    - Environment detection
 *    - Integrity verification
 *
 * 7. API OBFUSCATION
 *    - Dynamic API resolution
 *    - Import hiding
 *    - Syscall obfuscation
 *    - Hash-based lookups
 *    - Delayed resolution
 *
 * USAGE:
 * ======
 * - OBFUSCATED_STR("sensitive") - Encrypted string literal
 * - OBFUSCATED_WSTR(L"sensitive") - Encrypted wide string
 * - OBFUSCATED_INT(12345) - Obfuscated integer constant
 * - PROTECTED_CALL(func, args) - Obfuscated function call
 *
 * @warning Obfuscation is not a security boundary - use defense in depth.
 * @note Performance impact varies by obfuscation level.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <type_traits>
#include <utility>

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
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class CodeObfuscationImpl;
    class CryptoManager;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ObfuscationConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // ENCRYPTION
    // ========================================================================
    
    /// @brief Default XOR key for compile-time encryption
    inline constexpr uint64_t DEFAULT_XOR_KEY = 0xDEADBEEFCAFEBABEULL;
    
    /// @brief String encryption key size
    inline constexpr size_t STRING_KEY_SIZE = 32;
    
    /// @brief Maximum encrypted string length
    inline constexpr size_t MAX_ENCRYPTED_STRING_LENGTH = 4096;

    // ========================================================================
    // VM CONFIGURATION
    // ========================================================================
    
    /// @brief VM stack size
    inline constexpr size_t VM_STACK_SIZE = 4096;
    
    /// @brief VM register count
    inline constexpr size_t VM_REGISTER_COUNT = 16;
    
    /// @brief Maximum bytecode size
    inline constexpr size_t MAX_BYTECODE_SIZE = 1 * 1024 * 1024;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum cached decrypted strings
    inline constexpr size_t MAX_CACHED_STRINGS = 100;
    
    /// @brief Maximum protected functions
    inline constexpr size_t MAX_PROTECTED_FUNCTIONS = 500;
    
    /// @brief API hash table size
    inline constexpr size_t API_HASH_TABLE_SIZE = 256;

}  // namespace ObfuscationConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Obfuscation level
 */
enum class ObfuscationLevel : uint8_t {
    None        = 0,    ///< No obfuscation
    Light       = 1,    ///< String encryption only
    Medium      = 2,    ///< String + control flow
    Heavy       = 3,    ///< Full obfuscation
    Maximum     = 4     ///< Maximum protection + VM
};

/**
 * @brief String encryption algorithm
 */
enum class StringEncryptionAlgorithm : uint8_t {
    None        = 0,
    XOR         = 1,    ///< Simple XOR (fast)
    RC4         = 2,    ///< RC4 stream cipher
    AES_128     = 3,    ///< AES-128-CTR
    ChaCha20    = 4,    ///< ChaCha20
    Custom      = 5     ///< Custom algorithm
};

/**
 * @brief Control flow transformation
 */
enum class ControlFlowTransform : uint32_t {
    None                = 0x00000000,
    Flattening          = 0x00000001,
    OpaquePredicates    = 0x00000002,
    DeadCodeInsertion   = 0x00000004,
    BogusControlFlow    = 0x00000008,
    IndirectBranches    = 0x00000010,
    SwitchTable         = 0x00000020,
    
    Basic               = Flattening | OpaquePredicates,
    Standard            = Basic | DeadCodeInsertion | IndirectBranches,
    Full                = 0xFFFFFFFF
};

inline constexpr ControlFlowTransform operator|(ControlFlowTransform a, ControlFlowTransform b) noexcept {
    return static_cast<ControlFlowTransform>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Data obfuscation method
 */
enum class DataObfuscationMethod : uint32_t {
    None                = 0x00000000,
    ConstantEncoding    = 0x00000001,
    ArraySplitting      = 0x00000002,
    PointerArithmetic   = 0x00000004,
    VariableSubstitution= 0x00000008,
    MixedBooleanArith   = 0x00000010,
    
    Standard            = ConstantEncoding | PointerArithmetic | MixedBooleanArith
};

inline constexpr DataObfuscationMethod operator|(DataObfuscationMethod a, DataObfuscationMethod b) noexcept {
    return static_cast<DataObfuscationMethod>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief VM instruction
 */
enum class VMInstruction : uint8_t {
    NOP         = 0x00,
    PUSH        = 0x01,
    POP         = 0x02,
    ADD         = 0x03,
    SUB         = 0x04,
    MUL         = 0x05,
    DIV         = 0x06,
    XOR         = 0x07,
    AND         = 0x08,
    OR          = 0x09,
    NOT         = 0x0A,
    SHL         = 0x0B,
    SHR         = 0x0C,
    JMP         = 0x10,
    JZ          = 0x11,
    JNZ         = 0x12,
    JL          = 0x13,
    JG          = 0x14,
    CALL        = 0x20,
    RET         = 0x21,
    LOAD        = 0x30,
    STORE       = 0x31,
    LOADR       = 0x32,
    STORER      = 0x33,
    SYSCALL     = 0x40,
    APICALL     = 0x41,
    CMP         = 0x50,
    TEST        = 0x51,
    HALT        = 0xFF
};

/**
 * @brief API obfuscation method
 */
enum class APIObfuscationMethod : uint8_t {
    None            = 0,
    HashBased       = 1,    ///< Hash-based API resolution
    Encrypted       = 2,    ///< Encrypted API names
    Dynamic         = 3,    ///< Dynamic resolution at runtime
    Syscall         = 4,    ///< Direct syscall (ntdll bypass)
    Combined        = 5     ///< Multiple methods
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// COMPILE-TIME STRING ENCRYPTION UTILITIES
// ============================================================================

namespace detail {

/**
 * @brief Compile-time XOR encryption key generator
 */
template<size_t N>
constexpr auto GenerateKey(uint64_t seed) {
    std::array<uint8_t, N> key{};
    uint64_t state = seed;
    for (size_t i = 0; i < N; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        key[i] = static_cast<uint8_t>(state >> 33);
    }
    return key;
}

/**
 * @brief Compile-time encrypted string holder
 */
template<size_t N>
class EncryptedString {
public:
    constexpr EncryptedString(const char (&str)[N], uint64_t key) noexcept 
        : m_key(key) {
        for (size_t i = 0; i < N; ++i) {
            m_data[i] = str[i] ^ static_cast<char>((key >> ((i % 8) * 8)) & 0xFF);
        }
    }
    
    std::string Decrypt() const noexcept {
        std::string result(N - 1, '\0');
        for (size_t i = 0; i < N - 1; ++i) {
            result[i] = m_data[i] ^ static_cast<char>((m_key >> ((i % 8) * 8)) & 0xFF);
        }
        return result;
    }
    
    [[nodiscard]] constexpr size_t Size() const noexcept { return N - 1; }

private:
    char m_data[N]{};
    uint64_t m_key;
};

/**
 * @brief Compile-time encrypted wide string holder
 */
template<size_t N>
class EncryptedWString {
public:
    constexpr EncryptedWString(const wchar_t (&str)[N], uint64_t key) noexcept 
        : m_key(key) {
        for (size_t i = 0; i < N; ++i) {
            m_data[i] = str[i] ^ static_cast<wchar_t>((key >> ((i % 4) * 16)) & 0xFFFF);
        }
    }
    
    std::wstring Decrypt() const noexcept {
        std::wstring result(N - 1, L'\0');
        for (size_t i = 0; i < N - 1; ++i) {
            result[i] = m_data[i] ^ static_cast<wchar_t>((m_key >> ((i % 4) * 16)) & 0xFFFF);
        }
        return result;
    }
    
    [[nodiscard]] constexpr size_t Size() const noexcept { return N - 1; }

private:
    wchar_t m_data[N]{};
    uint64_t m_key;
};

/**
 * @brief Compile-time integer obfuscation
 */
template<typename T, T Value, uint64_t Key>
struct ObfuscatedInt {
    static constexpr T Encoded = Value ^ static_cast<T>(Key);
    
    [[nodiscard]] static constexpr T Get() noexcept {
        return Encoded ^ static_cast<T>(Key);
    }
};

}  // namespace detail

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Obfuscation configuration
 */
struct ObfuscationConfiguration {
    /// @brief Global obfuscation level
    ObfuscationLevel level = ObfuscationLevel::Medium;
    
    /// @brief String encryption algorithm
    StringEncryptionAlgorithm stringAlgorithm = StringEncryptionAlgorithm::ChaCha20;
    
    /// @brief Control flow transformations
    ControlFlowTransform controlFlowTransforms = ControlFlowTransform::Standard;
    
    /// @brief Data obfuscation methods
    DataObfuscationMethod dataObfuscation = DataObfuscationMethod::Standard;
    
    /// @brief API obfuscation method
    APIObfuscationMethod apiObfuscation = APIObfuscationMethod::HashBased;
    
    /// @brief Enable VM-based protection
    bool enableVM = false;
    
    /// @brief Enable anti-disassembly
    bool enableAntiDisassembly = true;
    
    /// @brief Enable self-modifying code
    bool enableSelfModifying = false;
    
    /// @brief Cache decrypted strings
    bool cacheStrings = false;
    
    /// @brief Clear cached strings after use
    bool clearCacheAfterUse = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Create from level
     */
    static ObfuscationConfiguration FromLevel(ObfuscationLevel level);
};

/**
 * @brief Protected function metadata
 */
struct ProtectedFunction {
    /// @brief Function identifier
    std::string id;
    
    /// @brief Function name (encrypted)
    std::vector<uint8_t> encryptedName;
    
    /// @brief Function address
    void* address = nullptr;
    
    /// @brief Original code (for integrity checking)
    std::vector<uint8_t> originalCode;
    
    /// @brief Code hash
    std::array<uint8_t, 32> codeHash{};
    
    /// @brief Protection level
    ObfuscationLevel level = ObfuscationLevel::Medium;
    
    /// @brief Is virtualized
    bool isVirtualized = false;
    
    /// @brief Bytecode (for VM execution)
    std::vector<uint8_t> bytecode;
    
    /// @brief Registration time
    TimePoint registeredAt = Clock::now();
};

/**
 * @brief API resolution entry
 */
struct APIEntry {
    /// @brief API name hash
    uint32_t hash = 0;
    
    /// @brief Module name (encrypted)
    std::vector<uint8_t> moduleName;
    
    /// @brief Function name (encrypted)
    std::vector<uint8_t> functionName;
    
    /// @brief Resolved address
    void* address = nullptr;
    
    /// @brief Is resolved
    bool isResolved = false;
    
    /// @brief Last resolution time
    TimePoint resolvedAt;
};

/**
 * @brief VM execution context
 */
struct VMContext {
    /// @brief Program counter
    size_t pc = 0;
    
    /// @brief Stack
    std::vector<uint64_t> stack;
    
    /// @brief Registers
    std::array<uint64_t, ObfuscationConstants::VM_REGISTER_COUNT> registers{};
    
    /// @brief Flags (zero, carry, sign, overflow)
    uint32_t flags = 0;
    
    /// @brief Bytecode
    std::span<const uint8_t> bytecode;
    
    /// @brief Is running
    bool running = false;
    
    /// @brief Return value
    uint64_t returnValue = 0;
    
    /**
     * @brief Reset context
     */
    void Reset() noexcept;
    
    /**
     * @brief Push value to stack
     */
    void Push(uint64_t value);
    
    /**
     * @brief Pop value from stack
     */
    [[nodiscard]] uint64_t Pop();
};

/**
 * @brief Obfuscation statistics
 */
struct ObfuscationStatistics {
    /// @brief Strings encrypted
    std::atomic<uint64_t> stringsEncrypted{0};
    
    /// @brief Strings decrypted
    std::atomic<uint64_t> stringsDecrypted{0};
    
    /// @brief Functions protected
    std::atomic<uint64_t> functionsProtected{0};
    
    /// @brief VM instructions executed
    std::atomic<uint64_t> vmInstructionsExecuted{0};
    
    /// @brief APIs resolved
    std::atomic<uint64_t> apisResolved{0};
    
    /// @brief Integrity checks
    std::atomic<uint64_t> integrityChecks{0};
    
    /// @brief Integrity violations
    std::atomic<uint64_t> integrityViolations{0};
    
    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{0};
    
    /// @brief Cache misses
    std::atomic<uint64_t> cacheMisses{0};
    
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

/// @brief Integrity violation callback
using IntegrityCallback = std::function<void(const ProtectedFunction&)>;

/// @brief API resolution callback
using APIResolveCallback = std::function<void*(const std::string& module, 
                                               const std::string& function)>;

// ============================================================================
// CODE OBFUSCATION ENGINE CLASS
// ============================================================================

/**
 * @class CodeObfuscation
 * @brief Enterprise-grade code obfuscation engine
 *
 * Provides comprehensive code protection including string encryption,
 * control flow obfuscation, VM-based protection, and anti-analysis.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& obfuscator = CodeObfuscation::Instance();
 *     
 *     // Decrypt encrypted string
 *     auto str = obfuscator.DecryptString(encryptedData);
 *     
 *     // Use macros for compile-time encryption
 *     auto sensitive = OBFUSCATED_STR("password123");
 * @endcode
 */
class CodeObfuscation final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static CodeObfuscation& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    CodeObfuscation(const CodeObfuscation&) = delete;
    CodeObfuscation& operator=(const CodeObfuscation&) = delete;
    CodeObfuscation(CodeObfuscation&&) = delete;
    CodeObfuscation& operator=(CodeObfuscation&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize obfuscation engine
     */
    [[nodiscard]] bool Initialize(const ObfuscationConfiguration& config = {});
    
    /**
     * @brief Shutdown obfuscation engine
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
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const ObfuscationConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] ObfuscationConfiguration GetConfiguration() const;
    
    /**
     * @brief Set obfuscation level
     */
    void SetLevel(ObfuscationLevel level);
    
    /**
     * @brief Get obfuscation level
     */
    [[nodiscard]] ObfuscationLevel GetLevel() const noexcept;
    
    // ========================================================================
    // STRING ENCRYPTION/DECRYPTION
    // ========================================================================
    
    /**
     * @brief Decrypt a string literal at runtime
     */
    [[nodiscard]] static std::string DecryptString(const std::vector<uint8_t>& encrypted);
    
    /**
     * @brief Decrypt string with key
     */
    [[nodiscard]] std::string DecryptString(std::span<const uint8_t> encrypted,
                                            std::span<const uint8_t> key);
    
    /**
     * @brief Decrypt wide string
     */
    [[nodiscard]] std::wstring DecryptWString(std::span<const uint8_t> encrypted,
                                              std::span<const uint8_t> key);
    
    /**
     * @brief Encrypt string at runtime
     */
    [[nodiscard]] std::vector<uint8_t> EncryptString(std::string_view str);
    
    /**
     * @brief Encrypt string with algorithm
     */
    [[nodiscard]] std::vector<uint8_t> EncryptString(std::string_view str,
                                                     StringEncryptionAlgorithm algorithm,
                                                     std::span<const uint8_t> key = {});
    
    /**
     * @brief Encrypt wide string
     */
    [[nodiscard]] std::vector<uint8_t> EncryptWString(std::wstring_view str);
    
    /**
     * @brief Get cached decrypted string (if caching enabled)
     */
    [[nodiscard]] std::optional<std::string> GetCachedString(uint32_t id) const;
    
    /**
     * @brief Clear string cache
     */
    void ClearStringCache();
    
    // ========================================================================
    // INTEGER OBFUSCATION
    // ========================================================================
    
    /**
     * @brief Encode integer
     */
    template<typename T>
    [[nodiscard]] T EncodeInt(T value, uint64_t key = ObfuscationConstants::DEFAULT_XOR_KEY) const {
        static_assert(std::is_integral_v<T>, "T must be an integral type");
        return value ^ static_cast<T>(key);
    }
    
    /**
     * @brief Decode integer
     */
    template<typename T>
    [[nodiscard]] T DecodeInt(T encoded, uint64_t key = ObfuscationConstants::DEFAULT_XOR_KEY) const {
        static_assert(std::is_integral_v<T>, "T must be an integral type");
        return encoded ^ static_cast<T>(key);
    }
    
    // ========================================================================
    // FUNCTION PROTECTION
    // ========================================================================
    
    /**
     * @brief Register function for protection
     */
    [[nodiscard]] std::string ProtectFunction(void* functionAddress, 
                                              std::string_view name,
                                              size_t codeSize,
                                              ObfuscationLevel level = ObfuscationLevel::Medium);
    
    /**
     * @brief Unprotect function
     */
    [[nodiscard]] bool UnprotectFunction(const std::string& functionId);
    
    /**
     * @brief Check function integrity
     */
    [[nodiscard]] bool VerifyFunctionIntegrity(const std::string& functionId);
    
    /**
     * @brief Check all protected functions
     */
    [[nodiscard]] std::vector<std::string> VerifyAllFunctions();
    
    /**
     * @brief Get protected function info
     */
    [[nodiscard]] std::optional<ProtectedFunction> GetProtectedFunction(
        const std::string& functionId) const;
    
    /**
     * @brief List all protected functions
     */
    [[nodiscard]] std::vector<ProtectedFunction> ListProtectedFunctions() const;
    
    // ========================================================================
    // API OBFUSCATION
    // ========================================================================
    
    /**
     * @brief Register API for obfuscated resolution
     */
    void RegisterAPI(std::string_view moduleName, std::string_view functionName);
    
    /**
     * @brief Resolve API by hash
     */
    [[nodiscard]] void* ResolveAPI(uint32_t hash);
    
    /**
     * @brief Resolve API by encrypted names
     */
    [[nodiscard]] void* ResolveAPI(std::span<const uint8_t> encryptedModule,
                                   std::span<const uint8_t> encryptedFunction);
    
    /**
     * @brief Calculate API hash
     */
    [[nodiscard]] static uint32_t HashAPI(std::string_view moduleName, 
                                          std::string_view functionName);
    
    /**
     * @brief Set custom API resolver
     */
    void SetAPIResolver(APIResolveCallback callback);
    
    /**
     * @brief Clear API cache
     */
    void ClearAPICache();
    
    // ========================================================================
    // VM PROTECTION
    // ========================================================================
    
    /**
     * @brief Virtualize function (convert to bytecode)
     */
    [[nodiscard]] std::vector<uint8_t> VirtualizeFunction(void* functionAddress,
                                                          size_t codeSize);
    
    /**
     * @brief Execute bytecode
     */
    [[nodiscard]] uint64_t ExecuteBytecode(std::span<const uint8_t> bytecode,
                                           std::span<const uint64_t> args = {});
    
    /**
     * @brief Create VM context
     */
    [[nodiscard]] VMContext CreateVMContext();
    
    /**
     * @brief Execute single VM instruction
     */
    void ExecuteVMInstruction(VMContext& context);
    
    /**
     * @brief Run VM until halt
     */
    [[nodiscard]] uint64_t RunVM(VMContext& context);
    
    // ========================================================================
    // ANTI-ANALYSIS
    // ========================================================================
    
    /**
     * @brief Insert anti-disassembly
     */
    void InsertAntiDisassembly();
    
    /**
     * @brief Check for analysis tools
     */
    [[nodiscard]] bool DetectAnalysisEnvironment() const;
    
    /**
     * @brief Timing-based anti-debug check
     */
    [[nodiscard]] bool TimingAntiDebug() const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set integrity violation callback
     */
    void SetIntegrityCallback(IntegrityCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] ObfuscationStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
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
    
    CodeObfuscation();
    ~CodeObfuscation();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<CodeObfuscationImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get obfuscation level name
 */
[[nodiscard]] std::string_view GetObfuscationLevelName(ObfuscationLevel level) noexcept;

/**
 * @brief Get string encryption algorithm name
 */
[[nodiscard]] std::string_view GetStringEncryptionAlgorithmName(
    StringEncryptionAlgorithm algorithm) noexcept;

/**
 * @brief Get API obfuscation method name
 */
[[nodiscard]] std::string_view GetAPIObfuscationMethodName(
    APIObfuscationMethod method) noexcept;

// ============================================================================
// COMPILE-TIME ENCRYPTION MACROS
// ============================================================================

/**
 * @brief Compile-time encryption key based on __LINE__ and __COUNTER__
 */
#define SS_OBFUSCATION_KEY(seed) \
    (::ShadowStrike::Security::ObfuscationConstants::DEFAULT_XOR_KEY ^ \
     static_cast<uint64_t>(seed) ^ \
     (static_cast<uint64_t>(__LINE__) << 32))

/**
 * @brief Encrypted string literal (decrypted at runtime)
 */
#define OBFUSCATED_STR(str) \
    ([]() -> std::string { \
        constexpr auto encrypted = ::ShadowStrike::Security::detail::EncryptedString< \
            sizeof(str)>(str, SS_OBFUSCATION_KEY(__COUNTER__)); \
        return encrypted.Decrypt(); \
    }())

/**
 * @brief Encrypted wide string literal (decrypted at runtime)
 */
#define OBFUSCATED_WSTR(str) \
    ([]() -> std::wstring { \
        constexpr auto encrypted = ::ShadowStrike::Security::detail::EncryptedWString< \
            sizeof(str)/sizeof(wchar_t)>(str, SS_OBFUSCATION_KEY(__COUNTER__)); \
        return encrypted.Decrypt(); \
    }())

/**
 * @brief Obfuscated integer constant
 */
#define OBFUSCATED_INT(value) \
    (::ShadowStrike::Security::detail::ObfuscatedInt<decltype(value), value, \
        SS_OBFUSCATION_KEY(__COUNTER__)>::Get())

/**
 * @brief Protected function call
 */
#define PROTECTED_CALL(func, ...) \
    ([&]() { \
        if (::ShadowStrike::Security::CodeObfuscation::Instance().DetectAnalysisEnvironment()) { \
            return decltype(func(__VA_ARGS__)){}; \
        } \
        return func(__VA_ARGS__); \
    }())

/**
 * @brief API call by hash
 */
#define API_CALL(module, func, type, ...) \
    reinterpret_cast<type>(::ShadowStrike::Security::CodeObfuscation::Instance().ResolveAPI( \
        ::ShadowStrike::Security::CodeObfuscation::HashAPI(module, func)))(__VA_ARGS__)

}  // namespace Security
}  // namespace ShadowStrike
