/**
 * ============================================================================
 * ShadowStrike Security - MEMORY PROTECTION ENGINE
 * ============================================================================
 *
 * @file MemoryProtection.hpp
 * @brief Enterprise-grade memory protection system for securing ShadowStrike
 *        process memory from external reading, modification, and dumping.
 *
 * This module implements comprehensive memory protection mechanisms to prevent
 * malware from analyzing, tampering with, or extracting sensitive data from
 * the antivirus process memory.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. ADDRESS SPACE LAYOUT RANDOMIZATION (ASLR)
 *    - High entropy ASLR enforcement
 *    - Dynamic base address randomization
 *    - Stack randomization
 *    - Heap randomization
 *    - Image load randomization
 *
 * 2. DATA EXECUTION PREVENTION (DEP)
 *    - Permanent DEP enforcement
 *    - NX bit enforcement
 *    - CFG (Control Flow Guard) integration
 *    - CET (Control-flow Enforcement Technology) support
 *
 * 3. SECURE MEMORY ALLOCATION
 *    - Encrypted-at-rest buffers for sensitive data
 *    - Zero-on-free secure deallocator
 *    - Guarded heap allocations
 *    - Non-paged secure memory for keys
 *    - Memory locking (prevent paging)
 *
 * 4. ANTI-DUMPING PROTECTION
 *    - PE header obfuscation
 *    - Section permission manipulation
 *    - IAT/EAT protection
 *    - Debug directory removal
 *    - TLS callback protection
 *
 * 5. CODE INTEGRITY
 *    - Code section CRC monitoring
 *    - Inline hook detection
 *    - Patch detection
 *    - Self-modifying code protection
 *    - Relocation protection
 *
 * 6. HEAP PROTECTION
 *    - Heap corruption detection
 *    - Heap overflow protection
 *    - Use-after-free detection
 *    - Double-free detection
 *    - Heap metadata protection
 *
 * 7. STACK PROTECTION
 *    - Stack canary monitoring
 *    - Stack buffer overflow detection
 *    - Return address protection
 *    - Shadow stack support
 *    - Safe exception handling
 *
 * 8. SENSITIVE DATA PROTECTION
 *    - Credential isolation
 *    - Key material protection
 *    - Configuration data encryption
 *    - Secure string handling
 *    - Memory scrubbing
 *
 * 9. VIRTUAL MEMORY PROTECTION
 *    - Page permission monitoring
 *    - Guard page implementation
 *    - Working set protection
 *    - Memory region protection
 *    - VAD (Virtual Address Descriptor) monitoring
 *
 * 10. ANTI-ANALYSIS PROTECTION
 *     - Memory scanning detection
 *     - Pattern scanning countermeasures
 *     - Signature evasion
 *     - Runtime unpacker detection
 *
 * MEMORY TYPES:
 * =============
 * - Executable Code: Protected from modification, monitored for hooks
 * - Read-only Data: Protected from writes, integrity verified
 * - Read-write Data: Encrypted sensitive portions, monitored changes
 * - Stack: Canaries, overflow protection, shadow stack
 * - Heap: Guarded allocations, metadata protection
 *
 * @note Some features require kernel-mode driver support.
 * @note Full protection may impact performance for high-frequency allocations.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
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
#include <thread>
#include <future>
#include <span>
#include <bitset>
#include <new>
#include <type_traits>

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
#  include <memoryapi.h>
#  include <Psapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class MemoryProtectionImpl;
    class SecureAllocatorImpl;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MemoryProtectionConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // MEMORY LIMITS
    // ========================================================================
    
    /// @brief Maximum secure allocations tracked
    inline constexpr size_t MAX_SECURE_ALLOCATIONS = 10000;
    
    /// @brief Maximum protected memory regions
    inline constexpr size_t MAX_PROTECTED_REGIONS = 500;
    
    /// @brief Maximum integrity check regions
    inline constexpr size_t MAX_INTEGRITY_REGIONS = 100;
    
    /// @brief Default secure pool size (1 MB)
    inline constexpr size_t DEFAULT_SECURE_POOL_SIZE = 1 * 1024 * 1024;
    
    /// @brief Maximum secure pool size (100 MB)
    inline constexpr size_t MAX_SECURE_POOL_SIZE = 100 * 1024 * 1024;
    
    /// @brief Minimum allocation size for secure allocator
    inline constexpr size_t MIN_SECURE_ALLOCATION = 16;
    
    /// @brief Maximum allocation size for secure allocator
    inline constexpr size_t MAX_SECURE_ALLOCATION = 16 * 1024 * 1024;
    
    /// @brief Alignment for secure allocations
    inline constexpr size_t SECURE_ALLOCATION_ALIGNMENT = 16;

    // ========================================================================
    // CANARY VALUES
    // ========================================================================
    
    /// @brief Stack canary magic value
    inline constexpr uint64_t STACK_CANARY_MAGIC = 0xDEADBEEFCAFEBABEULL;
    
    /// @brief Heap canary magic value
    inline constexpr uint64_t HEAP_CANARY_MAGIC = 0xFEEDFACE12345678ULL;
    
    /// @brief Guard page fill value
    inline constexpr uint8_t GUARD_PAGE_FILL = 0xCD;
    
    /// @brief Free memory fill value
    inline constexpr uint8_t FREE_MEMORY_FILL = 0xDD;
    
    /// @brief Uninitialized memory fill value
    inline constexpr uint8_t UNINIT_MEMORY_FILL = 0xCC;

    // ========================================================================
    // MONITORING INTERVALS
    // ========================================================================
    
    /// @brief Integrity check interval (milliseconds)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 30000;
    
    /// @brief Heap validation interval (milliseconds)
    inline constexpr uint32_t HEAP_VALIDATION_INTERVAL_MS = 60000;
    
    /// @brief Stack canary check interval (milliseconds)
    inline constexpr uint32_t STACK_CHECK_INTERVAL_MS = 10000;

    // ========================================================================
    // HASH SIZES
    // ========================================================================
    
    inline constexpr size_t CRC32_SIZE = 4;
    inline constexpr size_t SHA256_SIZE = 32;

    // ========================================================================
    // ENCRYPTION
    // ========================================================================
    
    /// @brief Encryption key size (AES-256)
    inline constexpr size_t ENCRYPTION_KEY_SIZE = 32;
    
    /// @brief Encryption IV size
    inline constexpr size_t ENCRYPTION_IV_SIZE = 16;
    
    /// @brief Encryption block size
    inline constexpr size_t ENCRYPTION_BLOCK_SIZE = 16;

    // ========================================================================
    // PAGE SIZES
    // ========================================================================
    
    /// @brief Standard page size
    inline constexpr size_t PAGE_SIZE = 4096;
    
    /// @brief Large page size
    inline constexpr size_t LARGE_PAGE_SIZE = 2 * 1024 * 1024;

}  // namespace MemoryProtectionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Milliseconds = std::chrono::milliseconds;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Memory protection level
 */
enum class ProtectionLevel : uint8_t {
    Disabled    = 0,    ///< No protection (testing only)
    Minimal     = 1,    ///< Basic protection
    Standard    = 2,    ///< Standard protection
    Enhanced    = 3,    ///< Enhanced protection
    Maximum     = 4     ///< Maximum protection
};

/**
 * @brief Memory region type
 */
enum class MemoryRegionType : uint8_t {
    Unknown     = 0,
    Code        = 1,    ///< Executable code
    ReadOnly    = 2,    ///< Read-only data
    ReadWrite   = 3,    ///< Read-write data
    Stack       = 4,    ///< Thread stack
    Heap        = 5,    ///< Heap memory
    Mapped      = 6,    ///< Memory-mapped file
    Reserved    = 7,    ///< Reserved memory
    Guard       = 8     ///< Guard page
};

/**
 * @brief Memory page protection flags
 */
enum class PageProtection : uint32_t {
    NoAccess            = 0x00000001,
    ReadOnly            = 0x00000002,
    ReadWrite           = 0x00000004,
    WriteCopy           = 0x00000008,
    Execute             = 0x00000010,
    ExecuteRead         = 0x00000020,
    ExecuteReadWrite    = 0x00000040,
    ExecuteWriteCopy    = 0x00000080,
    Guard               = 0x00000100,
    NoCache             = 0x00000200,
    WriteCombine        = 0x00000400,
    TargetsInvalid      = 0x40000000,
    TargetsNoUpdate     = 0x40000000
};

inline constexpr PageProtection operator|(PageProtection a, PageProtection b) noexcept {
    return static_cast<PageProtection>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Memory allocation type
 */
enum class AllocationType : uint8_t {
    Standard    = 0,    ///< Standard allocation
    Secure      = 1,    ///< Secure allocation (zeroed on free)
    Encrypted   = 2,    ///< Encrypted at rest
    Locked      = 3,    ///< Non-pageable
    Guarded     = 4     ///< Guard pages around allocation
};

/**
 * @brief Integrity status
 */
enum class IntegrityStatus : uint8_t {
    Unknown     = 0,
    Valid       = 1,
    Modified    = 2,
    Corrupted   = 3,
    Hooked      = 4
};

/**
 * @brief Protection event type
 */
enum class ProtectionEventType : uint32_t {
    None                = 0x00000000,
    MemoryWrite         = 0x00000001,
    MemoryRead          = 0x00000002,
    PermissionChange    = 0x00000004,
    AllocationAttempt   = 0x00000008,
    FreeAttempt         = 0x00000010,
    IntegrityViolation  = 0x00000020,
    CanaryCorruption    = 0x00000040,
    HeapCorruption      = 0x00000080,
    StackOverflow       = 0x00000100,
    HookDetected        = 0x00000200,
    DumpAttempt         = 0x00000400,
    ScanDetected        = 0x00000800,
    
    All                 = 0xFFFFFFFF
};

inline constexpr ProtectionEventType operator|(ProtectionEventType a, ProtectionEventType b) noexcept {
    return static_cast<ProtectionEventType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Response to protection event
 */
enum class ProtectionResponse : uint32_t {
    None        = 0x00000000,
    Log         = 0x00000001,
    Alert       = 0x00000002,
    Block       = 0x00000004,
    Repair      = 0x00000008,
    Terminate   = 0x00000010,
    Escalate    = 0x00000020,
    
    Passive     = Log | Alert,
    Active      = Log | Alert | Block | Repair,
    Aggressive  = Log | Alert | Block | Repair | Terminate
};

inline constexpr ProtectionResponse operator|(ProtectionResponse a, ProtectionResponse b) noexcept {
    return static_cast<ProtectionResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

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
// STRUCTURES
// ============================================================================

/**
 * @brief Memory protection configuration
 */
struct MemoryProtectionConfiguration {
    /// @brief Protection level
    ProtectionLevel level = ProtectionLevel::Standard;
    
    /// @brief Enable ASLR enforcement
    bool enableASLR = true;
    
    /// @brief Enable DEP enforcement
    bool enableDEP = true;
    
    /// @brief Enable CFG
    bool enableCFG = true;
    
    /// @brief Enable secure allocator
    bool enableSecureAllocator = true;
    
    /// @brief Secure pool size
    size_t securePoolSize = MemoryProtectionConstants::DEFAULT_SECURE_POOL_SIZE;
    
    /// @brief Enable anti-dump protection
    bool enableAntiDump = true;
    
    /// @brief Enable code integrity monitoring
    bool enableCodeIntegrity = true;
    
    /// @brief Integrity check interval (milliseconds)
    uint32_t integrityCheckIntervalMs = MemoryProtectionConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Enable heap protection
    bool enableHeapProtection = true;
    
    /// @brief Enable stack protection
    bool enableStackProtection = true;
    
    /// @brief Enable guard pages
    bool enableGuardPages = true;
    
    /// @brief Enable memory encryption for sensitive data
    bool enableMemoryEncryption = true;
    
    /// @brief Enable anti-scan protection
    bool enableAntiScan = true;
    
    /// @brief Default protection response
    ProtectionResponse defaultResponse = ProtectionResponse::Active;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /// @brief Send telemetry
    bool sendTelemetry = true;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Create from protection level
     */
    static MemoryProtectionConfiguration FromLevel(ProtectionLevel level);
};

/**
 * @brief Protected memory region information
 */
struct ProtectedRegion {
    /// @brief Region identifier
    std::string id;
    
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Region size
    size_t size = 0;
    
    /// @brief Region type
    MemoryRegionType type = MemoryRegionType::Unknown;
    
    /// @brief Page protection
    PageProtection protection = PageProtection::NoAccess;
    
    /// @brief Expected CRC32
    uint32_t expectedCrc32 = 0;
    
    /// @brief Expected SHA-256
    std::array<uint8_t, 32> expectedSha256{};
    
    /// @brief Current CRC32
    uint32_t currentCrc32 = 0;
    
    /// @brief Integrity status
    IntegrityStatus status = IntegrityStatus::Unknown;
    
    /// @brief Is critical region
    bool isCritical = false;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Last verified
    TimePoint lastVerified;
    
    /// @brief Violation count
    uint32_t violationCount = 0;
    
    /// @brief Module name (if applicable)
    std::wstring moduleName;
    
    /// @brief Section name (if applicable)
    std::string sectionName;
};

/**
 * @brief Secure allocation information
 */
struct SecureAllocation {
    /// @brief Allocation address
    void* address = nullptr;
    
    /// @brief Allocation size
    size_t size = 0;
    
    /// @brief Actual allocated size (including guards)
    size_t allocatedSize = 0;
    
    /// @brief Allocation type
    AllocationType type = AllocationType::Standard;
    
    /// @brief Is memory locked (non-pageable)
    bool isLocked = false;
    
    /// @brief Is memory encrypted
    bool isEncrypted = false;
    
    /// @brief Has guard pages
    bool hasGuardPages = false;
    
    /// @brief Allocation timestamp
    TimePoint allocatedAt = Clock::now();
    
    /// @brief Allocation call site (for debugging)
    uintptr_t callSite = 0;
    
    /// @brief Thread ID that allocated
    uint32_t allocatorThreadId = 0;
};

/**
 * @brief Memory protection event
 */
struct ProtectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event type
    ProtectionEventType type = ProtectionEventType::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Affected address
    uintptr_t address = 0;
    
    /// @brief Affected size
    size_t size = 0;
    
    /// @brief Affected region ID
    std::string regionId;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source thread ID
    uint32_t sourceThreadId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Response taken
    ProtectionResponse responseTaken = ProtectionResponse::None;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Was repaired
    bool wasRepaired = false;
    
    /// @brief Event description
    std::string description;
    
    /// @brief Additional context
    std::unordered_map<std::string, std::string> context;
    
    /**
     * @brief Get event summary
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Memory region information
 */
struct MemoryRegionInfo {
    /// @brief Base address
    uintptr_t baseAddress = 0;
    
    /// @brief Region size
    size_t regionSize = 0;
    
    /// @brief Allocation base
    uintptr_t allocationBase = 0;
    
    /// @brief Allocation size
    size_t allocationSize = 0;
    
    /// @brief Protection
    uint32_t protection = 0;
    
    /// @brief State
    uint32_t state = 0;
    
    /// @brief Type
    uint32_t type = 0;
    
    /// @brief Region type classification
    MemoryRegionType regionType = MemoryRegionType::Unknown;
    
    /// @brief Module name (if mapped)
    std::wstring moduleName;
};

/**
 * @brief Heap information
 */
struct HeapInfo {
    /// @brief Heap handle
    void* heapHandle = nullptr;
    
    /// @brief Total size
    size_t totalSize = 0;
    
    /// @brief Committed size
    size_t committedSize = 0;
    
    /// @brief Uncommitted size
    size_t uncommittedSize = 0;
    
    /// @brief Block count
    size_t blockCount = 0;
    
    /// @brief Is default heap
    bool isDefaultHeap = false;
    
    /// @brief Is secure heap
    bool isSecureHeap = false;
    
    /// @brief Heap flags
    uint32_t flags = 0;
};

/**
 * @brief Stack information
 */
struct StackInfo {
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Stack base
    uintptr_t stackBase = 0;
    
    /// @brief Stack limit
    uintptr_t stackLimit = 0;
    
    /// @brief Stack size
    size_t stackSize = 0;
    
    /// @brief Current stack pointer
    uintptr_t currentSP = 0;
    
    /// @brief Stack usage
    size_t stackUsage = 0;
    
    /// @brief Has canary
    bool hasCanary = false;
    
    /// @brief Canary intact
    bool canaryIntact = true;
};

/**
 * @brief Memory protection statistics
 */
struct MemoryProtectionStatistics {
    /// @brief Total protected regions
    std::atomic<uint64_t> totalProtectedRegions{0};
    
    /// @brief Total secure allocations
    std::atomic<uint64_t> totalSecureAllocations{0};
    
    /// @brief Total secure memory bytes
    std::atomic<uint64_t> totalSecureBytes{0};
    
    /// @brief Total integrity checks
    std::atomic<uint64_t> totalIntegrityChecks{0};
    
    /// @brief Integrity violations detected
    std::atomic<uint64_t> integrityViolations{0};
    
    /// @brief Memory writes blocked
    std::atomic<uint64_t> memoryWritesBlocked{0};
    
    /// @brief Heap corruptions detected
    std::atomic<uint64_t> heapCorruptionsDetected{0};
    
    /// @brief Stack overflows detected
    std::atomic<uint64_t> stackOverflowsDetected{0};
    
    /// @brief Hooks detected
    std::atomic<uint64_t> hooksDetected{0};
    
    /// @brief Dump attempts blocked
    std::atomic<uint64_t> dumpAttemptsBlocked{0};
    
    /// @brief Scan attempts detected
    std::atomic<uint64_t> scanAttemptsDetected{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last event time
    TimePoint lastEventTime;
    
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

/// @brief Callback for protection events
using ProtectionEventCallback = std::function<void(const ProtectionEvent&)>;

/// @brief Callback for integrity violations
using IntegrityCallback = std::function<void(const ProtectedRegion&)>;

/// @brief Callback for heap corruption
using HeapCorruptionCallback = std::function<void(const HeapInfo&)>;

/// @brief Callback for stack overflow
using StackOverflowCallback = std::function<void(const StackInfo&)>;

// ============================================================================
// SECURE ALLOCATOR TEMPLATE
// ============================================================================

/**
 * @class SecureAllocator
 * @brief STL-compatible secure allocator
 *
 * Provides secure memory allocation with automatic zeroing on deallocation.
 */
template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;
    
    template<typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };
    
    SecureAllocator() noexcept = default;
    
    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}
    
    [[nodiscard]] pointer allocate(size_type n);
    void deallocate(pointer p, size_type n) noexcept;
    
    template<typename U, typename... Args>
    void construct(U* p, Args&&... args) {
        ::new(static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }
    
    template<typename U>
    void destroy(U* p) noexcept {
        p->~U();
    }
};

template<typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return true;
}

template<typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return false;
}

// ============================================================================
// SECURE STRING TYPE
// ============================================================================

/// @brief Secure string type that zeros memory on destruction
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

/// @brief Secure wide string type
using SecureWString = std::basic_string<wchar_t, std::char_traits<wchar_t>, SecureAllocator<wchar_t>>;

/// @brief Secure byte vector type
using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

// ============================================================================
// MEMORY PROTECTION ENGINE CLASS
// ============================================================================

/**
 * @class MemoryProtection
 * @brief Enterprise-grade memory protection engine
 *
 * Provides comprehensive memory protection including ASLR, DEP, secure
 * allocation, anti-dump, code integrity, heap/stack protection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& memProtection = MemoryProtection::Instance();
 *     
 *     MemoryProtectionConfiguration config;
 *     config.level = ProtectionLevel::Enhanced;
 *     config.enableMemoryEncryption = true;
 *     
 *     if (!memProtection.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize memory protection");
 *     }
 *     
 *     // Apply process hardening
 *     memProtection.ApplyProcessHardening();
 *     
 *     // Allocate secure memory
 *     void* secureBuffer = memProtection.AllocateSecure(1024);
 *     // ... use buffer ...
 *     memProtection.FreeSecure(secureBuffer, 1024);
 *     
 *     // Protect a code region
 *     memProtection.ProtectCodeRegion("engine", codeBase, codeSize);
 * @endcode
 */
class MemoryProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static MemoryProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    MemoryProtection(const MemoryProtection&) = delete;
    MemoryProtection& operator=(const MemoryProtection&) = delete;
    MemoryProtection(MemoryProtection&&) = delete;
    MemoryProtection& operator=(MemoryProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize memory protection
     */
    [[nodiscard]] bool Initialize(const MemoryProtectionConfiguration& config = {});
    
    /**
     * @brief Initialize with protection level
     */
    [[nodiscard]] bool Initialize(ProtectionLevel level);
    
    /**
     * @brief Shutdown memory protection
     */
    void Shutdown(std::string_view authorizationToken);
    
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
    [[nodiscard]] bool SetConfiguration(const MemoryProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] MemoryProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection level
     */
    void SetProtectionLevel(ProtectionLevel level);
    
    /**
     * @brief Get protection level
     */
    [[nodiscard]] ProtectionLevel GetProtectionLevel() const noexcept;
    
    // ========================================================================
    // PROCESS HARDENING
    // ========================================================================
    
    /**
     * @brief Apply process memory hardening
     */
    void ApplyProcessHardening();
    
    /**
     * @brief Enable ASLR for current process
     */
    [[nodiscard]] bool EnableASLR();
    
    /**
     * @brief Check if ASLR is enabled
     */
    [[nodiscard]] bool IsASLREnabled() const;
    
    /**
     * @brief Enable DEP for current process
     */
    [[nodiscard]] bool EnableDEP();
    
    /**
     * @brief Check if DEP is enabled
     */
    [[nodiscard]] bool IsDEPEnabled() const;
    
    /**
     * @brief Enable CFG for current process
     */
    [[nodiscard]] bool EnableCFG();
    
    /**
     * @brief Check if CFG is enabled
     */
    [[nodiscard]] bool IsCFGEnabled() const;
    
    // ========================================================================
    // SECURE MEMORY ALLOCATION
    // ========================================================================
    
    /**
     * @brief Allocate secure memory
     * @param size Size to allocate
     * @return Pointer to allocated memory (nullptr on failure)
     */
    [[nodiscard]] void* AllocateSecure(size_t size);
    
    /**
     * @brief Allocate secure memory with specific type
     * @param size Size to allocate
     * @param type Allocation type
     * @return Pointer to allocated memory
     */
    [[nodiscard]] void* AllocateSecure(size_t size, AllocationType type);
    
    /**
     * @brief Free secure memory
     * @param ptr Pointer to free
     * @param size Size of allocation
     */
    void FreeSecure(void* ptr, size_t size);
    
    /**
     * @brief Reallocate secure memory
     */
    [[nodiscard]] void* ReallocateSecure(void* ptr, size_t oldSize, size_t newSize);
    
    /**
     * @brief Allocate encrypted memory
     * @param size Size to allocate
     * @return Pointer to encrypted allocation
     */
    [[nodiscard]] void* AllocateEncrypted(size_t size);
    
    /**
     * @brief Free encrypted memory
     */
    void FreeEncrypted(void* ptr, size_t size);
    
    /**
     * @brief Allocate locked (non-pageable) memory
     */
    [[nodiscard]] void* AllocateLocked(size_t size);
    
    /**
     * @brief Free locked memory
     */
    void FreeLocked(void* ptr, size_t size);
    
    /**
     * @brief Allocate memory with guard pages
     */
    [[nodiscard]] void* AllocateGuarded(size_t size);
    
    /**
     * @brief Free guarded memory
     */
    void FreeGuarded(void* ptr, size_t size);
    
    /**
     * @brief Get secure allocation info
     */
    [[nodiscard]] std::optional<SecureAllocation> GetSecureAllocationInfo(void* ptr) const;
    
    /**
     * @brief Get all secure allocations
     */
    [[nodiscard]] std::vector<SecureAllocation> GetAllSecureAllocations() const;
    
    /**
     * @brief Get total secure memory usage
     */
    [[nodiscard]] size_t GetSecureMemoryUsage() const;
    
    // ========================================================================
    // MEMORY REGION PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect memory region
     */
    [[nodiscard]] bool ProtectRegion(std::string_view id, uintptr_t address, size_t size,
                                     MemoryRegionType type = MemoryRegionType::Code);
    
    /**
     * @brief Unprotect memory region
     */
    [[nodiscard]] bool UnprotectRegion(std::string_view id, std::string_view authorizationToken);
    
    /**
     * @brief Protect code region with integrity monitoring
     */
    [[nodiscard]] bool ProtectCodeRegion(std::string_view id, uintptr_t address, size_t size);
    
    /**
     * @brief Protect current module's code section
     */
    [[nodiscard]] bool ProtectSelfCode();
    
    /**
     * @brief Check if region is protected
     */
    [[nodiscard]] bool IsRegionProtected(uintptr_t address) const;
    
    /**
     * @brief Get protected region info
     */
    [[nodiscard]] std::optional<ProtectedRegion> GetProtectedRegion(std::string_view id) const;
    
    /**
     * @brief Get all protected regions
     */
    [[nodiscard]] std::vector<ProtectedRegion> GetAllProtectedRegions() const;
    
    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verify memory region integrity
     */
    [[nodiscard]] IntegrityStatus VerifyRegionIntegrity(std::string_view id);
    
    /**
     * @brief Verify all protected regions
     */
    [[nodiscard]] std::vector<std::pair<std::string, IntegrityStatus>> VerifyAllIntegrity();
    
    /**
     * @brief Force integrity check
     */
    void ForceIntegrityCheck();
    
    /**
     * @brief Update region baseline
     */
    [[nodiscard]] bool UpdateRegionBaseline(std::string_view id, std::string_view authorizationToken);
    
    // ========================================================================
    // ANTI-DUMP PROTECTION
    // ========================================================================
    
    /**
     * @brief Enable anti-dump protection
     */
    [[nodiscard]] bool EnableAntiDump();
    
    /**
     * @brief Disable anti-dump protection
     */
    void DisableAntiDump(std::string_view authorizationToken);
    
    /**
     * @brief Check if anti-dump is enabled
     */
    [[nodiscard]] bool IsAntiDumpEnabled() const;
    
    /**
     * @brief Obfuscate PE headers
     */
    [[nodiscard]] bool ObfuscatePEHeaders();
    
    /**
     * @brief Restore PE headers (for debugging)
     */
    [[nodiscard]] bool RestorePEHeaders(std::string_view authorizationToken);
    
    // ========================================================================
    // HEAP PROTECTION
    // ========================================================================
    
    /**
     * @brief Enable heap protection
     */
    [[nodiscard]] bool EnableHeapProtection();
    
    /**
     * @brief Validate heap integrity
     */
    [[nodiscard]] bool ValidateHeapIntegrity();
    
    /**
     * @brief Get heap information
     */
    [[nodiscard]] std::vector<HeapInfo> GetHeapInfo() const;
    
    /**
     * @brief Create secure heap
     */
    [[nodiscard]] void* CreateSecureHeap(size_t initialSize);
    
    /**
     * @brief Destroy secure heap
     */
    void DestroySecureHeap(void* heapHandle);
    
    // ========================================================================
    // STACK PROTECTION
    // ========================================================================
    
    /**
     * @brief Enable stack protection for thread
     */
    [[nodiscard]] bool EnableStackProtection(uint32_t threadId = 0);
    
    /**
     * @brief Verify stack canary
     */
    [[nodiscard]] bool VerifyStackCanary(uint32_t threadId = 0);
    
    /**
     * @brief Get stack information
     */
    [[nodiscard]] StackInfo GetStackInfo(uint32_t threadId = 0);
    
    /**
     * @brief Get all thread stack info
     */
    [[nodiscard]] std::vector<StackInfo> GetAllStackInfo();
    
    // ========================================================================
    // MEMORY QUERY
    // ========================================================================
    
    /**
     * @brief Query memory region information
     */
    [[nodiscard]] std::optional<MemoryRegionInfo> QueryMemoryRegion(uintptr_t address);
    
    /**
     * @brief Enumerate all memory regions
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> EnumerateMemoryRegions();
    
    /**
     * @brief Get memory protection for address
     */
    [[nodiscard]] PageProtection GetPageProtection(uintptr_t address);
    
    /**
     * @brief Set memory protection for range
     */
    [[nodiscard]] bool SetPageProtection(uintptr_t address, size_t size, PageProtection protection);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register protection event callback
     */
    [[nodiscard]] uint64_t RegisterEventCallback(ProtectionEventCallback callback);
    
    /**
     * @brief Unregister event callback
     */
    void UnregisterEventCallback(uint64_t callbackId);
    
    /**
     * @brief Register integrity callback
     */
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);
    
    /**
     * @brief Unregister integrity callback
     */
    void UnregisterIntegrityCallback(uint64_t callbackId);
    
    /**
     * @brief Register heap corruption callback
     */
    [[nodiscard]] uint64_t RegisterHeapCorruptionCallback(HeapCorruptionCallback callback);
    
    /**
     * @brief Unregister heap corruption callback
     */
    void UnregisterHeapCorruptionCallback(uint64_t callbackId);
    
    /**
     * @brief Register stack overflow callback
     */
    [[nodiscard]] uint64_t RegisterStackOverflowCallback(StackOverflowCallback callback);
    
    /**
     * @brief Unregister stack overflow callback
     */
    void UnregisterStackOverflowCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] MemoryProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get event history
     */
    [[nodiscard]] std::vector<ProtectionEvent> GetEventHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear event history
     */
    void ClearEventHistory(std::string_view authorizationToken);
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test protection mechanisms
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Secure zero memory
     */
    static void SecureZeroMemory(void* ptr, size_t size);
    
    /**
     * @brief Compare memory in constant time
     */
    [[nodiscard]] static bool ConstantTimeCompare(const void* a, const void* b, size_t size);
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    MemoryProtection();
    ~MemoryProtection();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<MemoryProtectionImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get protection level name
 */
[[nodiscard]] std::string_view GetProtectionLevelName(ProtectionLevel level) noexcept;

/**
 * @brief Get memory region type name
 */
[[nodiscard]] std::string_view GetMemoryRegionTypeName(MemoryRegionType type) noexcept;

/**
 * @brief Get integrity status name
 */
[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept;

/**
 * @brief Get allocation type name
 */
[[nodiscard]] std::string_view GetAllocationTypeName(AllocationType type) noexcept;

/**
 * @brief Format page protection for display
 */
[[nodiscard]] std::string FormatPageProtection(PageProtection protection);

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class SecureBuffer
 * @brief RAII wrapper for secure memory allocation
 */
class SecureBuffer final {
public:
    explicit SecureBuffer(size_t size);
    SecureBuffer(size_t size, AllocationType type);
    ~SecureBuffer();
    
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    [[nodiscard]] void* Data() noexcept { return m_data; }
    [[nodiscard]] const void* Data() const noexcept { return m_data; }
    [[nodiscard]] size_t Size() const noexcept { return m_size; }
    [[nodiscard]] bool IsValid() const noexcept { return m_data != nullptr; }
    
    template<typename T>
    [[nodiscard]] T* As() noexcept { return static_cast<T*>(m_data); }
    
    template<typename T>
    [[nodiscard]] const T* As() const noexcept { return static_cast<const T*>(m_data); }

private:
    void* m_data = nullptr;
    size_t m_size = 0;
    AllocationType m_type = AllocationType::Secure;
};

/**
 * @class ProtectedRegionGuard
 * @brief RAII wrapper for temporary region protection
 */
class ProtectedRegionGuard final {
public:
    ProtectedRegionGuard(std::string_view id, uintptr_t address, size_t size);
    ~ProtectedRegionGuard();
    
    ProtectedRegionGuard(const ProtectedRegionGuard&) = delete;
    ProtectedRegionGuard& operator=(const ProtectedRegionGuard&) = delete;
    
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }

private:
    std::string m_id;
    bool m_protected = false;
    std::string m_authToken;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Apply process hardening
 */
#define SS_HARDEN_PROCESS() \
    ::ShadowStrike::Security::MemoryProtection::Instance().ApplyProcessHardening()

/**
 * @brief Secure zero memory
 */
#define SS_SECURE_ZERO(ptr, size) \
    ::ShadowStrike::Security::MemoryProtection::SecureZeroMemory((ptr), (size))

/**
 * @brief Allocate secure buffer on stack (compile-time size)
 */
#define SS_SECURE_BUFFER(name, size) \
    ::ShadowStrike::Security::SecureBuffer name(size)
