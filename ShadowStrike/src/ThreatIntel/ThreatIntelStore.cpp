/**
 * @file ThreatIntelStore.cpp
 * @brief Enterprise-grade Threat Intelligence Store - Implementation
 *
 * This is the main implementation of the ShadowStrike Threat Intelligence module.
 * Provides unified access to IOC lookups, feed management, and threat analytics.
 *
 * Architecture:
 * - Memory-mapped database for zero-copy, nanosecond-level access
 * - Multi-tier caching strategy (thread-local → shared → database)
 * - Lock-free concurrent reads with atomic operations
 * - SIMD-optimized batch operations
 * - Automatic feed updates with rate limiting
 * - Real-time reputation scoring
 *
 * Performance Targets (CrowdStrike Falcon / Microsoft Defender ATP quality):
 * - Hash lookup: <100ns average (cache hit < 50ns)
 * - IP lookup: <500ns average
 * - Domain lookup: <1µs average
 * - Batch lookup (1000 items): <1ms
 * - Feed update: <10s for 1M entries
 *
 * Thread Safety:
 * - Lock-free reads for cached/indexed data
 * - Reader-writer locks for database modifications
 * - Atomic statistics with memory_order_relaxed
 * - Per-thread caching eliminates contention
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#include "ThreatIntelStore.hpp"
#include "ThreatIntelDatabase.hpp"
#include "ThreatIntelIndex.hpp"
#include "ThreatIntelLookup.hpp"
#include "ThreatIntelIOCManager.hpp"
#include "ThreatIntelImporter.hpp"
#include "ThreatIntelExporter.hpp"
#include "ThreatIntelFeedManager.hpp"
#include "ReputationCache.hpp"

#include "../Utils/Logger.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/Timer.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Compile-Time Validations
// ============================================================================

static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
static_assert(sizeof(IN6_ADDR) == 16, "IN6_ADDR must be 16 bytes");

// Default TTL for IOC entries (30 days in seconds)
constexpr uint64_t DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60;

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

/**
 * @brief Convert string to IPv4Address
 * 
 * Safe parsing without exceptions. Handles CIDR notation.
 * 
 * @param str IPv4 address string (e.g., "192.168.1.1" or "10.0.0.0/8")
 * @return Parsed IPv4Address or nullopt on failure
 */
[[nodiscard]] std::optional<IPv4Address> ParseIPv4(std::string_view str) noexcept {
    if (str.empty() || str.size() > 18) {  // Max: "255.255.255.255/32"
        return std::nullopt;
    }
    
    IPv4Address addr{};
    addr.prefixLength = 32;  // Default full address
    
    // Check for CIDR notation
    size_t slashPos = str.find('/');
    std::string_view ipPart = (slashPos != std::string_view::npos) 
        ? str.substr(0, slashPos) 
        : str;
    
    // Parse CIDR prefix if present
    if (slashPos != std::string_view::npos) {
        std::string_view prefixStr = str.substr(slashPos + 1);
        if (prefixStr.empty() || prefixStr.size() > 2) {
            return std::nullopt;
        }
        
        uint32_t prefix = 0;
        for (char c : prefixStr) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            prefix = prefix * 10 + static_cast<uint32_t>(c - '0');
        }
        
        if (prefix > 32) {
            return std::nullopt;
        }
        addr.prefixLength = static_cast<uint8_t>(prefix);
    }
    
    // Parse octets safely without exceptions
    uint32_t result = 0;
    int octetIndex = 0;
    uint32_t currentOctet = 0;
    size_t digitCount = 0;
    
    for (size_t i = 0; i <= ipPart.size(); ++i) {
        if (i == ipPart.size() || ipPart[i] == '.') {
            // Validate octet
            if (digitCount == 0 || currentOctet > 255 || octetIndex >= 4) {
                return std::nullopt;
            }
            
            result = (result << 8) | currentOctet;
            ++octetIndex;
            currentOctet = 0;
            digitCount = 0;
        } else {
            char c = ipPart[i];
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            
            currentOctet = currentOctet * 10 + static_cast<uint32_t>(c - '0');
            ++digitCount;
            
            // Prevent overflow and leading zeros check
            if (digitCount > 3 || currentOctet > 255) {
                return std::nullopt;
            }
        }
    }
    
    if (octetIndex != 4) {
        return std::nullopt;
    }
    
    addr.address = result;
    return addr;
}

/**
 * @brief Convert string to IPv6Address
 * 
 * Safe parsing using Windows InetPtonA. Handles CIDR notation.
 * 
 * @param str IPv6 address string (e.g., "::1" or "2001:db8::/32")
 * @return Parsed IPv6Address or nullopt on failure
 */
[[nodiscard]] std::optional<IPv6Address> ParseIPv6(std::string_view str) noexcept {
    // Validate input length (min "::" = 2, max with CIDR ~50)
    if (str.size() < 2 || str.size() > 50) {
        return std::nullopt;
    }
    
    IPv6Address addr{};
    addr.prefixLength = 128;  // Default full address
    
    // Check for CIDR notation
    size_t slashPos = str.find('/');
    std::string_view ipPart = (slashPos != std::string_view::npos) 
        ? str.substr(0, slashPos) 
        : str;
    
    // Parse CIDR prefix if present
    if (slashPos != std::string_view::npos) {
        std::string_view prefixStr = str.substr(slashPos + 1);
        if (prefixStr.empty() || prefixStr.size() > 3) {
            return std::nullopt;
        }
        
        uint32_t prefix = 0;
        for (char c : prefixStr) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            prefix = prefix * 10 + static_cast<uint32_t>(c - '0');
        }
        
        if (prefix > 128) {
            return std::nullopt;
        }
        addr.prefixLength = static_cast<uint8_t>(prefix);
    }
    
    // Use Windows API for IPv6 parsing (thread-safe)
    // Create null-terminated string for API
    if (ipPart.size() >= 46) {  // INET6_ADDRSTRLEN is 46
        return std::nullopt;
    }
    
    char ipBuffer[46] = {0};
    std::memcpy(ipBuffer, ipPart.data(), ipPart.size());
    
    IN6_ADDR in6addr{};
    if (InetPtonA(AF_INET6, ipBuffer, &in6addr) != 1) {
        return std::nullopt;
    }
    
    static_assert(sizeof(addr.address) >= 16, "IPv6 address buffer too small");
    std::memcpy(addr.address.data(), in6addr.u.Byte, 16);
    
    return addr;
}

/**
 * @brief Detect hash algorithm from hex string length
 * 
 * @param hashHex Hex-encoded hash string
 * @return Detected algorithm or MD5 as conservative fallback
 */
[[nodiscard]] constexpr HashAlgorithm DetectHashAlgorithm(size_t hexLength) noexcept {
    switch (hexLength) {
        case 32:  return HashAlgorithm::MD5;      // 16 bytes = 32 hex chars
        case 40:  return HashAlgorithm::SHA1;     // 20 bytes = 40 hex chars
        case 64:  return HashAlgorithm::SHA256;   // 32 bytes = 64 hex chars
        case 128: return HashAlgorithm::SHA512;   // 64 bytes = 128 hex chars
        default:  return HashAlgorithm::SHA256;   // Conservative fallback for unknown
    }
}

/**
 * @brief Parse hash string to HashValue
 * 
 * Converts hex-encoded hash string to HashValue structure.
 * Auto-detects algorithm from length if not specified.
 * 
 * @param algorithm Algorithm name (empty string for auto-detect)
 * @param hashHex Hex-encoded hash string
 * @return Parsed HashValue or nullopt on failure
 */
[[nodiscard]] std::optional<HashValue> ParseHash(std::string_view algorithm, std::string_view hashHex) noexcept {
    // Validate hex string length (must be even)
    if (hashHex.empty() || hashHex.length() % 2 != 0 || hashHex.length() > 128) {
        return std::nullopt;
    }
    
    HashValue hash{};
    
    // Determine algorithm - check explicit algorithm first
    if (algorithm == "MD5" || algorithm == "md5") {
        hash.algorithm = HashAlgorithm::MD5;
    } else if (algorithm == "SHA1" || algorithm == "sha1" || algorithm == "SHA-1") {
        hash.algorithm = HashAlgorithm::SHA1;
    } else if (algorithm == "SHA256" || algorithm == "sha256" || algorithm == "SHA-256") {
        hash.algorithm = HashAlgorithm::SHA256;
    } else if (algorithm == "SHA384" || algorithm == "sha384" || algorithm == "SHA-384") {
        hash.algorithm = HashAlgorithm::SHA256;  // Store as SHA256, closest match
    } else if (algorithm == "SHA512" || algorithm == "sha512" || algorithm == "SHA-512") {
        hash.algorithm = HashAlgorithm::SHA512;
    } else {
        // Auto-detect from length
        hash.algorithm = DetectHashAlgorithm(hashHex.length());
    }
    
    // Parse hex string to bytes manually (no exceptions)
    const size_t byteCount = hashHex.length() / 2;
    if (byteCount > hash.data.size()) {
        return std::nullopt;
    }
    
    auto hexDigit = [](char c) noexcept -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;  // Invalid
    };
    
    for (size_t i = 0; i < byteCount; ++i) {
        const int high = hexDigit(hashHex[i * 2]);
        const int low = hexDigit(hashHex[i * 2 + 1]);
        
        if (high < 0 || low < 0) {
            return std::nullopt;  // Invalid hex character
        }
        
        hash.data[i] = static_cast<uint8_t>((high << 4) | low);
    }
    
    hash.length = static_cast<uint8_t>(byteCount);
    
    return hash;
}

/**
 * @brief Get current Unix timestamp in seconds
 */
[[nodiscard]] inline uint64_t GetUnixTimestamp() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

/**
 * @brief Get high-resolution timestamp in nanoseconds
 * 
 * Uses QueryPerformanceCounter with cached frequency for efficiency.
 * Thread-safe due to static initialization guarantees.
 */
[[nodiscard]] inline uint64_t GetNanoseconds() noexcept {
    // Cache frequency - initialized once, thread-safe in C++11+
    static const uint64_t frequency = []() noexcept -> uint64_t {
        LARGE_INTEGER freq;
        if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
            return 1;  // Fallback to prevent division by zero
        }
        return static_cast<uint64_t>(freq.QuadPart);
    }();
    
    LARGE_INTEGER counter;
    if (!QueryPerformanceCounter(&counter)) {
        return 0;  // Error case
    }
    
    // Convert to nanoseconds with overflow protection
    // counter * 1e9 / frequency, but avoid overflow
    const uint64_t seconds = static_cast<uint64_t>(counter.QuadPart) / frequency;
    const uint64_t remainder = static_cast<uint64_t>(counter.QuadPart) % frequency;
    
    return seconds * 1000000000ULL + (remainder * 1000000000ULL) / frequency;
}

} // anonymous namespace

// ============================================================================
// ThreatIntelStore::Impl - Internal Implementation (Pimpl Pattern)
// ============================================================================

class ThreatIntelStore::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    // Non-copyable, non-movable
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    // ========================================================================
    // Core Subsystems
    // ========================================================================

    /// @brief Memory-mapped database
    std::unique_ptr<ThreatIntelDatabase> database;

    /// @brief Multi-dimensional index structures
    std::unique_ptr<ThreatIntelIndex> index;

    /// @brief Unified lookup interface
    std::unique_ptr<ThreatIntelLookup> lookup;

    /// @brief IOC management
    std::unique_ptr<ThreatIntelIOCManager> iocManager;

    /// @brief High-speed reputation cache
    std::unique_ptr<ReputationCache> cache;

    /// @brief Feed manager for automatic updates
    std::unique_ptr<ThreatIntelFeedManager> feedManager;

    /// @brief Threat intelligence importer
    std::unique_ptr<ThreatIntelImporter> importer;

    /// @brief Threat intelligence exporter
    std::unique_ptr<ThreatIntelExporter> exporter;

    // ========================================================================
    // Configuration
    // ========================================================================

    /// @brief Store configuration
    StoreConfig config;

    // ========================================================================
    // Statistics & Monitoring
    // ========================================================================

    /// @brief Store statistics
    StoreStatistics stats;

    /// @brief Statistics lock
    mutable std::shared_mutex statsMutex;

    // ========================================================================
    // Event Callbacks
    // ========================================================================

    /// @brief Event callback map
    std::unordered_map<size_t, StoreEventCallback> eventCallbacks;

    /// @brief Next callback ID
    size_t nextCallbackId{1};

    /// @brief Event callback lock
    mutable std::mutex callbackMutex;

    // ========================================================================
    // Thread Safety
    // ========================================================================

    /// @brief Main read-write lock
    mutable std::shared_mutex rwLock;

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * @brief Fire event to registered callbacks
     * 
     * Iterates through all registered callbacks and invokes them.
     * Exceptions from callbacks are caught and suppressed.
     * Thread-safe: acquires lock on callbackMutex.
     * 
     * @param event Event to fire to callbacks
     */
    void FireEvent(const StoreEvent& event) noexcept {
        std::lock_guard<std::mutex> lock(callbackMutex);
        for (const auto& [id, callback] : eventCallbacks) {
            if (!callback) {
                continue;  // Skip null callbacks
            }
            try {
                callback(event);
            } catch (...) {
                // Swallow exceptions from user callbacks to prevent propagation
                // In production, consider logging callback failures
            }
        }
    }

    /**
     * @brief Update statistics from subsystems
     * 
     * Aggregates statistics from all initialized subsystems.
     * Thread-safe: acquires exclusive lock on statsMutex.
     */
    void UpdateStatistics() noexcept {
        std::unique_lock<std::shared_mutex> lock(statsMutex);

        try {
            if (database && database->IsOpen()) {
                auto dbStats = database->GetStats();
                stats.databaseSizeBytes = dbStats.mappedSize;
                stats.totalIOCEntries = dbStats.entryCount;
            }

            if (cache) {
                auto cacheStats = cache->GetStatistics();
                stats.cacheSizeBytes = cacheStats.memoryUsageBytes;
                stats.cacheHits.store(cacheStats.cacheHits, std::memory_order_relaxed);
                stats.cacheMisses.store(cacheStats.cacheMisses, std::memory_order_relaxed);
            }

            if (index) {
                auto indexStats = index->GetStatistics();
                stats.totalHashEntries = indexStats.hashEntries;
                stats.totalIPEntries = indexStats.ipv4Entries + indexStats.ipv6Entries;
                stats.totalDomainEntries = indexStats.domainEntries;
                stats.totalURLEntries = indexStats.urlEntries;
                stats.totalEmailEntries = indexStats.emailEntries;
            }

            stats.lastUpdateAt = std::chrono::system_clock::now();
        } catch (...) {
            // Statistics update failed - non-critical, continue
        }
    }

    /**
     * @brief Convert ThreatLookupResult to store-level StoreLookupResult format
     * 
     * Maps fields from internal ThreatLookupResult to public StoreLookupResult.
     * All fields are copied by value - no ownership transfer.
     * 
     * @param tlResult Internal lookup result
     * @return Public StoreLookupResult structure
     */
    [[nodiscard]] StoreLookupResult ConvertLookupResult(
        const ThreatLookupResult& tlResult
    ) const noexcept {
        StoreLookupResult result;
        result.found = tlResult.found;
        result.fromCache = (tlResult.source == ThreatLookupResult::Source::SharedCache ||
                           tlResult.source == ThreatLookupResult::Source::ThreadLocalCache);
        result.latencyNs = tlResult.latencyNs;
        result.reputation = tlResult.reputation;
        result.confidence = tlResult.confidence;
        result.category = tlResult.category;
        result.primarySource = tlResult.primarySource;
        result.sourceFlags = tlResult.sourceFlags;
        result.score = tlResult.threatScore;
        result.firstSeen = tlResult.firstSeen;
        result.lastSeen = tlResult.lastSeen;
        result.entry = tlResult.entry;
        return result;
    }
};

// ============================================================================
// ThreatIntelStore - Public Interface Implementation
// ============================================================================

ThreatIntelStore::ThreatIntelStore()
    : m_impl(std::make_unique<Impl>()) {
}

ThreatIntelStore::~ThreatIntelStore() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool ThreatIntelStore::Initialize(const StoreConfig& config) {
    if (m_isInitialized.load(std::memory_order_acquire)) {
        return false; // Already initialized
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    try {
        m_impl->config = config;

        // Initialize logger
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Info,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Initializing ThreatIntelStore with database: %s",
            config.databasePath.c_str()
        );

        // Create database directory if needed
        std::filesystem::path dbPath(config.databasePath);
        if (dbPath.has_parent_path()) {
            std::filesystem::create_directories(dbPath.parent_path());
        }

        // Initialize memory-mapped database
        m_impl->database = std::make_unique<ThreatIntelDatabase>();
        
        DatabaseConfig dbConfig;
        dbConfig.filePath = config.databasePath;
        dbConfig.initialSize = config.initialDatabaseSize;
        dbConfig.maxSize = config.maxDatabaseSize;
        dbConfig.enableWAL = config.enableWAL;
        dbConfig.walPath = config.walPath;
        dbConfig.verifyOnOpen = config.verifyIntegrityOnLoad;
        dbConfig.prefaultPages = true; // Always prefault for performance

        if (!m_impl->database->Open(dbConfig)) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to open database: %s",
                config.databasePath.c_str()
            );
            return false;
        }

        // Initialize reputation cache with options
        m_impl->cache = std::make_unique<ReputationCache>(config.cacheOptions);
        auto cacheInitErr = m_impl->cache->Initialize();
        if (cacheInitErr.code != ThreatIntelError::Success) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to initialize reputation cache"
            );
            return false;
        }

        // Initialize index structures
        m_impl->index = std::make_unique<ThreatIntelIndex>();
        const auto* header = m_impl->database->GetHeader();
        if (!header) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to get database header"
            );
            return false;
        }

        // Create memory-mapped view for index
        MemoryMappedView view;
        view.baseAddress = const_cast<void*>(static_cast<const void*>(header));
        view.fileSize = m_impl->database->GetMappedSize();

        IndexBuildOptions indexOpts = IndexBuildOptions::Default();
        auto initError = m_impl->index->Initialize(view, header, indexOpts);
        if (initError.code != ThreatIntelError::Success) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to initialize index: %S",
                initError.message.c_str()
            );
            return false;
        }

        // Initialize IOC manager
        m_impl->iocManager = std::make_unique<ThreatIntelIOCManager>();
        auto iocInitErr = m_impl->iocManager->Initialize(m_impl->database.get());
        if (iocInitErr.code != ThreatIntelError::Success) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to initialize IOC manager"
            );
            return false;
        }

        // Initialize unified lookup interface
        m_impl->lookup = std::make_unique<ThreatIntelLookup>();
        LookupConfig lookupConfig = LookupConfig::CreateHighPerformance();
        lookupConfig.enableExternalAPI = false; // External APIs managed by feed manager
        
        if (!m_impl->lookup->Initialize(
            lookupConfig,
            this,
            m_impl->index.get(),
            m_impl->iocManager.get(),
            m_impl->cache.get()
        )) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Error,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to initialize lookup interface"
            );
            return false;
        }

        // Initialize importer/exporter (no explicit initialization needed)
        m_impl->importer = std::make_unique<ThreatIntelImporter>();
        m_impl->exporter = std::make_unique<ThreatIntelExporter>();

        // Initialize feed manager with default config
        ThreatIntelFeedManager::Config feedCfg{}; // Default config
        m_impl->feedManager = std::make_unique<ThreatIntelFeedManager>();
        if (!m_impl->feedManager->Initialize(feedCfg)) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Warn,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"Failed to initialize feed manager (non-critical)"
            );
        }

        // Initialize statistics
        m_impl->stats.createdAt = std::chrono::system_clock::now();
        m_impl->stats.lastUpdateAt = m_impl->stats.createdAt;
        m_impl->UpdateStatistics();

        m_isInitialized.store(true, std::memory_order_release);

        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Info,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"ThreatIntelStore initialized successfully with %llu IOC entries",
            m_impl->stats.totalIOCEntries
        );

        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Exception during initialization: %S",
            ex.what()
        );
        return false;
    } catch (...) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Unknown exception during initialization"
        );
        return false;
    }
}

bool ThreatIntelStore::Initialize() {
    return Initialize(StoreConfig::CreateDefault());
}

void ThreatIntelStore::Shutdown() {
    if (!m_isInitialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Shutting down ThreatIntelStore"
    );

    // Stop feed updates
    if (m_impl->feedManager) {
        // Feed manager will be shut down via destructor
    }

    // Flush pending changes
    if (m_impl->database && m_impl->database->IsOpen()) {
        m_impl->database->Flush();
    }

    // Shutdown subsystems in reverse order
    m_impl->lookup.reset();
    m_impl->feedManager.reset();
    m_impl->exporter.reset();
    m_impl->importer.reset();
    m_impl->iocManager.reset();
    m_impl->index.reset();
    m_impl->cache.reset();
    
    if (m_impl->database) {
        m_impl->database->Close();
        m_impl->database.reset();
    }

    // Clear callbacks
    {
        std::lock_guard<std::mutex> cbLock(m_impl->callbackMutex);
        m_impl->eventCallbacks.clear();
    }

    m_isInitialized.store(false, std::memory_order_release);

    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"ThreatIntelStore shutdown complete"
    );
}

bool ThreatIntelStore::IsInitialized() const noexcept {
    return m_isInitialized.load(std::memory_order_acquire);
}

// ============================================================================
// IOC Lookups
// ============================================================================

StoreLookupResult ThreatIntelStore::LookupHash(
    std::string_view algorithm,
    std::string_view hashValue,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto startTime = GetNanoseconds();

    // Parse hash
    auto hashOpt = ParseHash(algorithm, hashValue);
    if (!hashOpt.has_value()) {
        return StoreLookupResult{};
    }

    // Perform lookup through unified lookup interface
    auto tlResult = m_impl->lookup->LookupHash(hashOpt.value());
    auto result = m_impl->Impl::ConvertLookupResult(tlResult);
    
    // Update statistics
    m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);
    if (result.found) {
        m_impl->stats.databaseHits.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_impl->stats.databaseMisses.fetch_add(1, std::memory_order_relaxed);
    }
    
    const auto latency = GetNanoseconds() - startTime;
    m_impl->stats.totalLookupTimeNs.fetch_add(latency, std::memory_order_relaxed);
    m_impl->stats.lastLookupAt = std::chrono::system_clock::now();

    // Update min/max latency
    uint64_t currentMin = m_impl->stats.minLookupTimeNs.load(std::memory_order_relaxed);
    while (latency < currentMin) {
        if (m_impl->stats.minLookupTimeNs.compare_exchange_weak(
            currentMin, latency, std::memory_order_relaxed)) {
            break;
        }
    }

    uint64_t currentMax = m_impl->stats.maxLookupTimeNs.load(std::memory_order_relaxed);
    while (latency > currentMax) {
        if (m_impl->stats.maxLookupTimeNs.compare_exchange_weak(
            currentMax, latency, std::memory_order_relaxed)) {
            break;
        }
    }

    return result;
}

StoreLookupResult ThreatIntelStore::LookupHash(
    uint64_t hashHigh,
    uint64_t hashLow,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    // Convert to HashValue structure (assume SHA256 from 128-bit input)
    HashValue hash{};
    hash.algorithm = HashAlgorithm::SHA256;
    hash.length = 32;
    
    // Store as big-endian
    for (int i = 0; i < 8; ++i) {
        hash.data[i] = static_cast<uint8_t>((hashHigh >> (56 - i * 8)) & 0xFF);
        hash.data[8 + i] = static_cast<uint8_t>((hashLow >> (56 - i * 8)) & 0xFF);
    }

    auto tlResult = m_impl->lookup->LookupHash(hash, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv4(
    std::string_view address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupIPv4(address, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv4(
    uint32_t address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupIPv4(address, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv6(
    std::string_view address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupIPv6(address, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv6(
    uint64_t addressHigh,
    uint64_t addressLow,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    IPv6Address addr{};
    addr.prefixLength = 128;
    
    // Convert to byte array (big-endian)
    for (int i = 0; i < 8; ++i) {
        addr.address[i] = static_cast<uint8_t>((addressHigh >> (56 - i * 8)) & 0xFF);
        addr.address[8 + i] = static_cast<uint8_t>((addressLow >> (56 - i * 8)) & 0xFF);
    }

    auto tlResult = m_impl->lookup->LookupIPv6(addr, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupDomain(
    std::string_view domain,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupDomain(domain, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupURL(
    std::string_view url,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupURL(url, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupEmail(
    std::string_view email,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->LookupEmail(email, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupJA3(
    std::string_view fingerprint,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->Lookup(IOCType::JA3, fingerprint, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupCVE(
    std::string_view cveId,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->Lookup(IOCType::CVE, cveId, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIOC(
    IOCType iocType,
    std::string_view value,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    auto tlResult = m_impl->lookup->Lookup(iocType, value, options);
    return m_impl->Impl::ConvertLookupResult(tlResult);
}

// ============================================================================
// Batch Lookups
// ============================================================================

BatchLookupResult ThreatIntelStore::BatchLookupHashes(
    std::string_view algorithm,
    std::span<const std::string> hashes,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = GetNanoseconds();
    
    result.totalProcessed = hashes.size();
    result.results.reserve(hashes.size());

    for (const auto& hashStr : hashes) {
        auto StoreLookupResult = LookupHash(algorithm, hashStr, options);
        
        // Convert StoreLookupResult to ThreatLookupResult for internal storage
        ThreatLookupResult tlr{};
        tlr.found = StoreLookupResult.found;
        tlr.reputation = StoreLookupResult.reputation;
        tlr.confidence = StoreLookupResult.confidence;
        tlr.category = StoreLookupResult.category;
        tlr.latencyNs = StoreLookupResult.latencyNs;
        tlr.primarySource = StoreLookupResult.primarySource;
        tlr.sourceFlags = StoreLookupResult.sourceFlags;
        tlr.threatScore = StoreLookupResult.score;
        tlr.firstSeen = StoreLookupResult.firstSeen;
        tlr.lastSeen = StoreLookupResult.lastSeen;
        tlr.entry = StoreLookupResult.entry;
        result.results.push_back(tlr);

        if (StoreLookupResult.found) {
            ++result.foundCount;
            
            if (StoreLookupResult.fromCache) {
                ++result.sharedCacheHits;
            } else {
                ++result.databaseHits;
            }

            if (StoreLookupResult.IsMalicious()) {
                ++result.maliciousCount;
            } else if (StoreLookupResult.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;

    return result;
}

BatchLookupResult ThreatIntelStore::BatchLookupIPv4(
    std::span<const std::string> addresses,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = GetNanoseconds();
    
    result.totalProcessed = addresses.size();
    result.results.reserve(addresses.size());

    std::vector<std::string_view> views;
    views.reserve(addresses.size());
    for (const auto& addr : addresses) {
        views.push_back(addr);
    }

    auto tlResult = m_impl->lookup->BatchLookupIPv4(views, options);
    
    for (const auto& tr : tlResult.results) {
        result.results.push_back(tr);  // Store ThreatLookupResult directly
        auto lr = m_impl->Impl::ConvertLookupResult(tr);

        if (lr.found) {
            ++result.foundCount;
            if (lr.fromCache) {
                ++result.sharedCacheHits;
            } else {
                ++result.databaseHits;
            }
            
            if (lr.IsMalicious()) {
                ++result.maliciousCount;
            } else if (lr.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;

    return result;
}

BatchLookupResult ThreatIntelStore::BatchLookupDomains(
    std::span<const std::string> domains,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = GetNanoseconds();
    
    result.totalProcessed = domains.size();
    result.results.reserve(domains.size());

    std::vector<std::string_view> views;
    views.reserve(domains.size());
    for (const auto& domain : domains) {
        views.push_back(domain);
    }

    auto tlResult = m_impl->lookup->BatchLookupDomains(views, options);
    
    for (const auto& tr : tlResult.results) {
        result.results.push_back(tr);  // Store ThreatLookupResult directly
        auto lr = m_impl->Impl::ConvertLookupResult(tr);

        if (lr.found) {
            ++result.foundCount;
            if (lr.fromCache) {
                ++result.sharedCacheHits;
            } else {
                ++result.databaseHits;
            }
            
            if (lr.IsMalicious()) {
                ++result.maliciousCount;
            } else if (lr.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;

    return result;
}

BatchLookupResult ThreatIntelStore::BatchLookupIOCs(
    std::span<const std::pair<IOCType, std::string>> iocs,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = GetNanoseconds();
    
    result.totalProcessed = iocs.size();
    result.results.reserve(iocs.size());

    for (const auto& [type, value] : iocs) {
        auto StoreLookupResult = LookupIOC(type, value, options);
        
        // Convert StoreLookupResult to ThreatLookupResult for internal storage
        ThreatLookupResult tlr{};
        tlr.found = StoreLookupResult.found;
        tlr.reputation = StoreLookupResult.reputation;
        tlr.confidence = StoreLookupResult.confidence;
        tlr.category = StoreLookupResult.category;
        tlr.latencyNs = StoreLookupResult.latencyNs;
        tlr.primarySource = StoreLookupResult.primarySource;
        tlr.sourceFlags = StoreLookupResult.sourceFlags;
        tlr.threatScore = StoreLookupResult.score;
        tlr.firstSeen = StoreLookupResult.firstSeen;
        tlr.lastSeen = StoreLookupResult.lastSeen;
        tlr.entry = StoreLookupResult.entry;
        result.results.push_back(tlr);

        if (StoreLookupResult.found) {
            ++result.foundCount;
            
            if (StoreLookupResult.fromCache) {
                ++result.sharedCacheHits;
            } else {
                ++result.databaseHits;
            }

            if (StoreLookupResult.IsMalicious()) {
                ++result.maliciousCount;
            } else if (StoreLookupResult.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;

    return result;
}

// ============================================================================
// IOC Management
// ============================================================================

bool ThreatIntelStore::AddIOC(const IOCEntry& entry) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    IOCAddOptions addOpts;
    auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
    
    if (opResult.success) {
        m_impl->stats.totalImportedEntries.fetch_add(1, std::memory_order_relaxed);
        
        // Fire event
        StoreEvent event;
        event.type = StoreEventType::IOCAdded;
        event.timestamp = std::chrono::system_clock::now();
        event.entry = entry;
        event.iocType = entry.type;
        m_impl->FireEvent(event);
    }

    return opResult.success;
}

bool ThreatIntelStore::AddIOC(
    IOCType type,
    std::string_view value,
    ReputationLevel reputation,
    ThreatIntelSource source
) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return false;
    }

    // Create IOCEntry from parameters
    IOCEntry entry{};
    entry.type = type;
    entry.reputation = reputation;
    entry.source = source;
    entry.confidence = ConfidenceLevel::Medium;
    entry.category = ThreatCategory::Unknown;
    entry.firstSeen = GetUnixTimestamp();
    entry.lastSeen = entry.firstSeen;
    entry.expirationTime = entry.firstSeen + DEFAULT_TTL_SECONDS;
    entry.flags = IOCFlags::HasExpiration;

    // Parse value based on type
    switch (type) {
        case IOCType::IPv4: {
            auto addr = ParseIPv4(value);
            if (!addr.has_value()) return false;
            entry.value.ipv4 = addr.value();
            break;
        }
        case IOCType::IPv6: {
            auto addr = ParseIPv6(value);
            if (!addr.has_value()) return false;
            entry.value.ipv6 = addr.value();
            break;
        }
        case IOCType::FileHash: {
            // Auto-detect algorithm
            auto hash = ParseHash("", value);
            if (!hash.has_value()) return false;
            entry.value.hash = hash.value();
            break;
        }
        case IOCType::Domain:
        case IOCType::URL:
        case IOCType::Email:
        default: {
            // String-based IOCs need string pool allocation
            // This is handled by the IOCManager
            break;
        }
    }

    return AddIOC(entry);
}

bool ThreatIntelStore::UpdateIOC(const IOCEntry& entry) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    auto opResult = m_impl->iocManager->UpdateIOC(entry);
    
    if (opResult.success) {
        // Fire event
        StoreEvent event;
        event.type = StoreEventType::IOCUpdated;
        event.timestamp = std::chrono::system_clock::now();
        event.entry = entry;
        event.iocType = entry.type;
        m_impl->FireEvent(event);
    }

    return opResult.success;
}

bool ThreatIntelStore::RemoveIOC(IOCType type, std::string_view value) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    // Call DeleteIOC with type and value
    auto opResult = m_impl->iocManager->DeleteIOC(type, std::string(value));
    
    if (opResult.success) {
        // Fire event
        StoreEvent event;
        event.type = StoreEventType::IOCRemoved;
        event.timestamp = std::chrono::system_clock::now();
        event.iocType = type;
        m_impl->FireEvent(event);
    }

    return opResult.success;
}

size_t ThreatIntelStore::BulkAddIOCs(std::span<const IOCEntry> entries) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return 0;
    }

    // Empty span check - early exit optimization
    if (entries.empty()) {
        return 0;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    size_t added = 0;
    IOCAddOptions addOpts;
    for (const auto& entry : entries) {
        auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
        if (opResult.success) {
            ++added;
        }
    }

    // Update statistics atomically
    if (added > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(added, std::memory_order_relaxed);
        
        // Fire bulk event to notify listeners
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.iocType = std::nullopt;  // Mixed types in bulk - no specific type
        m_impl->FireEvent(event);
    }

    return added;
}

ThreatIntelStore::BulkAddStatsResult ThreatIntelStore::BulkAddIOCsWithStats(
    std::span<const IOCEntry> entries) noexcept {
    
    BulkAddStatsResult result;
    result.totalProcessed = entries.size();
    
    if (!IsInitialized() || !m_impl->iocManager) {
        result.errorCount = entries.size();
        return result;
    }
    
    // Empty span - early exit
    if (entries.empty()) {
        return result;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);
    
    IOCAddOptions addOpts;
    
    for (const auto& entry : entries) {
        // Validate entry before processing
        if (entry.value[0] == '\0' || entry.type == IOCType::Unknown) {
            ++result.skippedEntries;
            continue;
        }
        
        // Check if entry already exists using lookup interface
        StoreLookupOptions lookupOpts = StoreLookupOptions::FastLookup();
        lookupOpts.cacheResult = false;
        lookupOpts.includeMetadata = false;
        
        auto lookupResult = m_impl->lookup->Lookup(entry.type, entry.value, lookupOpts);
        
        if (lookupResult.found) {
            // Entry exists - try to update if newer
            // For now, count as updated (actual update logic depends on IOCManager)
            auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
            if (opResult.success) {
                ++result.updatedEntries;
            } else {
                ++result.errorCount;
            }
        } else {
            // New entry - add it
            auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
            if (opResult.success) {
                ++result.newEntries;
            } else {
                ++result.errorCount;
            }
        }
    }
    
    // Update statistics atomically
    const size_t totalAdded = result.newEntries + result.updatedEntries;
    if (totalAdded > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(totalAdded, std::memory_order_relaxed);
        
        // Fire bulk event to notify listeners
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.iocType = std::nullopt;
        m_impl->FireEvent(event);
    }
    
    return result;
}

bool ThreatIntelStore::HasIOC(IOCType type, std::string_view value) const noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return false;
    }

    // Use shared lock for read-only operation
    std::shared_lock<std::shared_mutex> lock(m_impl->rwLock);

    // Perform lookup through the lookup interface directly
    // Note: m_impl->lookup methods are const-correct and thread-safe
    // Use fast lookup options for existence check
    StoreLookupOptions opts = StoreLookupOptions::FastLookup();
    opts.cacheResult = false;  // Don't modify cache for existence check
    opts.includeMetadata = false;
    
    auto tlResult = m_impl->lookup->Lookup(type, value, opts);
    return tlResult.found;
}

// ============================================================================
// Feed Management
// ============================================================================

bool ThreatIntelStore::AddFeed(const FeedConfig& config) noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return false;
    }

    // Convert FeedConfig to ThreatFeedConfig
    ThreatFeedConfig feedCfg;
    feedCfg.feedId = config.feedId;
    feedCfg.name = config.name;
    // Note: ThreatFeedConfig may not have url and updateIntervalHours fields
    feedCfg.enabled = config.enabled;
    
    return m_impl->feedManager->AddFeed(feedCfg);
}

bool ThreatIntelStore::RemoveFeed(const std::string& feedId) noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return false;
    }

    return m_impl->feedManager->RemoveFeed(feedId);
}

bool ThreatIntelStore::EnableFeed(const std::string& feedId) noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return false;
    }

    return m_impl->feedManager->EnableFeed(feedId);
}

bool ThreatIntelStore::DisableFeed(const std::string& feedId) noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return false;
    }

    return m_impl->feedManager->DisableFeed(feedId);
}

bool ThreatIntelStore::UpdateFeed(const std::string& feedId) noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return false;
    }

    // Create minimal config for update
    ThreatFeedConfig cfg{};
    cfg.feedId = feedId;
    return m_impl->feedManager->UpdateFeed(feedId, cfg);
}

size_t ThreatIntelStore::UpdateAllFeeds() noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return 0;
    }

    // Update all feeds - manual iteration
    // Note: GetAllFeedIds not available, iterate manually or return 0
    return 0;
}

std::optional<FeedStatus> ThreatIntelStore::GetFeedStatus(const std::string& feedId) const noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return std::nullopt;
    }

    // Get feed status from manager
    // Note: GetFeedStatus returns FeedSyncStatus enum, not a struct
    // Return empty status
    FeedStatus status;
    status.feedId = feedId;
    status.enabled = true;
    status.isUpdating = false;
    status.totalEntriesImported = 0;
    status.errorCount = 0;
    
    return status;
}

std::vector<FeedStatus> ThreatIntelStore::GetAllFeedStatuses() const noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return {};
    }

    // Return empty vector - GetAllFeedIds not available
    return {};
}

void ThreatIntelStore::StartFeedUpdates() noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return;
    }

    // Feed manager handles auto-updates internally
    // Start periodic updates via timer or background thread
}

void ThreatIntelStore::StopFeedUpdates() noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return;
    }

    // Feed manager handles shutdown via destructor
}

// ============================================================================
// Import/Export
// ============================================================================

ImportResult ThreatIntelStore::ImportSTIX(
    const std::wstring& filePath,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    
    if (!IsInitialized() || !m_impl->importer) {
        return result;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    [[maybe_unused]] const auto startTime = std::chrono::steady_clock::now();

    // TODO: Implement actual STIX import
    // result = m_impl->importer->ImportFromFile(filePath, ImportFormat::STIX21);

    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
    }

    return result;
}

ImportResult ThreatIntelStore::ImportCSV(
    const std::wstring& filePath,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    
    if (!IsInitialized() || !m_impl->importer) {
        return result;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    [[maybe_unused]] const auto startTime = std::chrono::steady_clock::now();

    // TODO: Implement actual CSV import
    // result = m_impl->importer->ImportFromFile(filePath, ImportFormat::CSV);

    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
    }

    return result;
}

ImportResult ThreatIntelStore::ImportJSON(
    const std::wstring& filePath,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    
    if (!IsInitialized() || !m_impl->importer) {
        return result;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    [[maybe_unused]] const auto startTime = std::chrono::steady_clock::now();

    // TODO: Implement actual JSON import
    // result = m_impl->importer->ImportFromFile(filePath, ImportFormat::JSON);

    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
    }

    return result;
}

ImportResult ThreatIntelStore::ImportPlainText(
    const std::wstring& filePath,
    IOCType iocType,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    
    if (!IsInitialized() || !m_impl->importer) {
        return result;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    [[maybe_unused]] const auto startTime = std::chrono::steady_clock::now();

    // TODO: Implement actual PlainText import
    // result = m_impl->importer->ImportFromFile(filePath, ImportFormat::PlainText);

    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
    }

    return result;
}

ExportResult ThreatIntelStore::Export(
    const std::wstring& filePath,
    const ExportOptions& options
) noexcept {
    ExportResult result;
    result.success = false;
    result.totalExported = 0;
    result.bytesWritten = 0;
    
    if (!IsInitialized() || !m_impl->exporter) {
        result.errorMessage = "Store not initialized or exporter unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Output file path is empty";
        return result;
    }

    std::shared_lock<std::shared_mutex> lock(m_impl->rwLock);

    [[maybe_unused]] const auto startTime = std::chrono::steady_clock::now();

    // TODO: Implement actual export
    // result = m_impl->exporter->ExportToFile(filePath, options.format);

    if (result.success && result.totalExported > 0) {
        m_impl->stats.totalExportedEntries.fetch_add(result.totalExported, std::memory_order_relaxed);
    }

    return result;
}

// ============================================================================
// Maintenance Operations
// ============================================================================

/**
 * @brief Compacts the database to reclaim unused space.
 * 
 * This operation defragments the database file and reduces its size.
 * Should be called periodically during low-activity periods.
 * 
 * @return Number of bytes reclaimed by the compaction operation
 * @note Thread-safe: Uses exclusive lock during compaction
 * @warning This operation may take significant time for large databases
 */
size_t ThreatIntelStore::Compact() noexcept {
    if (!IsInitialized() || !m_impl->database) {
        return 0;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    const size_t reclaimedBytes = m_impl->database->Compact();
    
    // Fire maintenance event if bytes were reclaimed
    if (reclaimedBytes > 0) {
        StoreEvent event;
        event.type = StoreEventType::DatabaseCompacted;
        event.timestamp = std::chrono::system_clock::now();
        m_impl->FireEvent(event);
    }
    
    return reclaimedBytes;
}

/**
 * @brief Verifies the integrity of the threat intelligence store.
 * 
 * This method performs comprehensive verification of both the database
 * and index components. Database integrity is verified first, followed
 * by index verification if available.
 * 
 * @return true if both database and index are valid, false otherwise
 * @note Thread-safe: Uses shared lock for concurrent read access
 * @note Database must be initialized before calling this method
 */
bool ThreatIntelStore::VerifyIntegrity() const noexcept {
    if (!IsInitialized() || !m_impl->database) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(m_impl->rwLock);

    // Verify database integrity first (primary data source)
    const bool dbIntegrity = m_impl->database->VerifyIntegrity();
    
    // If database is corrupt, no need to verify index
    if (!dbIntegrity) {
        return false;
    }
    
    // Verify index if present
    if (m_impl->index) {
        auto verifyError = m_impl->index->Verify();
        return verifyError.code == ThreatIntelError::Success;
    }

    return true;  // Database valid, no index to verify
}

bool ThreatIntelStore::RebuildIndexes() noexcept {
    if (!IsInitialized() || !m_impl->index || !m_impl->database) {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    // Get all entries from database
    const IOCEntry* entries = m_impl->database->GetEntries();
    const size_t entryCount = m_impl->database->GetEntryCount();

    // Early exit conditions - nothing to rebuild is still success
    if (entryCount == 0) {
        return true;
    }

    // Validate pointer is valid when count > 0
    if (!entries) {
        return false;  // Invalid state: non-zero count with null pointer
    }

    // Allocate vector with exception safety
    std::vector<IOCEntry> entryVec;
    try {
        entryVec.reserve(entryCount);
        entryVec.assign(entries, entries + entryCount);
    } catch (const std::exception&) {
        return false;  // Memory allocation failure
    }
    
    auto rebuildError = m_impl->index->RebuildAll(entryVec);
    
    return rebuildError.code == ThreatIntelError::Success;
}

void ThreatIntelStore::Flush() noexcept {
    if (!IsInitialized()) {
        return;
    }

    // Use unique_lock since Flush operations may write to disk
    // and require exclusive access to prevent data corruption
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    if (m_impl->database && m_impl->database->IsOpen()) {
        m_impl->database->Flush();
    }

    if (m_impl->index) {
        m_impl->index->Flush();
    }
}

/**
 * @brief Evicts expired entries from the reputation cache.
 * 
 * This method removes cache entries that have exceeded their TTL.
 * Should be called periodically to maintain cache efficiency.
 * 
 * @return Number of entries evicted from the cache
 * @note Thread-safe: Cache internally handles its own locking
 * @note Does not affect persistent database entries
 */
size_t ThreatIntelStore::EvictExpiredEntries() noexcept {
    if (!IsInitialized() || !m_impl || !m_impl->cache) {
        return 0;
    }

    return m_impl->cache->EvictExpired();
}

size_t ThreatIntelStore::PurgeOldEntries(std::chrono::hours maxAge) noexcept {
    if (!IsInitialized() || !m_impl->iocManager) {
        return 0;
    }

    // Validate maxAge is positive and within reasonable bounds
    if (maxAge.count() <= 0) {
        return 0;  // Invalid max age
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    const uint64_t currentTime = GetUnixTimestamp();
    const uint64_t maxAgeSeconds = static_cast<uint64_t>(maxAge.count()) * 3600ULL;
    
    // Prevent underflow: if maxAgeSeconds >= currentTime, nothing to purge
    if (maxAgeSeconds >= currentTime) {
        return 0;  // All entries would be in valid time range
    }
    
    [[maybe_unused]] const uint64_t cutoffTime = currentTime - maxAgeSeconds;

    // Purge via IOC manager
    size_t purged = 0;
    // Note: PurgeOldEntries not available, would need to implement cleanup logic
    return purged;
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

StoreStatistics ThreatIntelStore::GetStatistics() const noexcept {
    if (!IsInitialized() || !m_impl) {
        return StoreStatistics{};
    }

    // Update statistics before returning
    const_cast<Impl*>(m_impl.get())->UpdateStatistics();

    // Return copy under lock to ensure consistency
    std::shared_lock<std::shared_mutex> lock(m_impl->statsMutex);
    return m_impl->stats;
}

/**
 * @brief Retrieves cache performance statistics.
 * 
 * Returns detailed statistics about cache hit rates, memory usage,
 * and eviction counts.
 * 
 * @return CacheStatistics structure with current cache metrics
 * @note Returns empty statistics if store not initialized
 */
CacheStatistics ThreatIntelStore::GetCacheStatistics() const noexcept {
    if (!IsInitialized() || !m_impl || !m_impl->cache) {
        return CacheStatistics{};
    }

    return m_impl->cache->GetStatistics();
}

/**
 * @brief Resets all statistical counters to their initial values.
 * 
 * This method atomically resets all performance and operational statistics.
 * The reset is performed under exclusive lock to ensure consistency.
 * 
 * @note Thread-safe: Uses unique lock for exclusive access
 * @note minLookupTimeNs is reset to UINT64_MAX (no minimum recorded)
 */
void ThreatIntelStore::ResetStatistics() noexcept {
    if (!IsInitialized() || !m_impl) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(m_impl->statsMutex);

    // Reset all counters atomically with relaxed ordering
    // (strict ordering not required for statistics)
    m_impl->stats.totalLookups.store(0, std::memory_order_relaxed);
    m_impl->stats.cacheHits.store(0, std::memory_order_relaxed);
    m_impl->stats.cacheMisses.store(0, std::memory_order_relaxed);
    m_impl->stats.databaseHits.store(0, std::memory_order_relaxed);
    m_impl->stats.databaseMisses.store(0, std::memory_order_relaxed);
    m_impl->stats.totalLookupTimeNs.store(0, std::memory_order_relaxed);
    m_impl->stats.minLookupTimeNs.store(UINT64_MAX, std::memory_order_relaxed);
    m_impl->stats.maxLookupTimeNs.store(0, std::memory_order_relaxed);
    m_impl->stats.totalImportedEntries.store(0, std::memory_order_relaxed);
    m_impl->stats.totalExportedEntries.store(0, std::memory_order_relaxed);
}

// ============================================================================
// Event Handling
// ============================================================================

size_t ThreatIntelStore::RegisterEventCallback(StoreEventCallback callback) noexcept {
    if (!callback) {
        return 0;  // Invalid callback
    }

    std::lock_guard<std::mutex> lock(m_impl->callbackMutex);

    // Prevent callback ID overflow (extremely unlikely but safe)
    if (m_impl->nextCallbackId == SIZE_MAX) {
        return 0;  // Cannot allocate new ID
    }
    
    const size_t id = m_impl->nextCallbackId++;
    
    try {
        m_impl->eventCallbacks[id] = std::move(callback);
    } catch (...) {
        return 0;  // Allocation failed
    }
    
    return id;
}

void ThreatIntelStore::UnregisterEventCallback(size_t callbackId) noexcept {
    std::lock_guard<std::mutex> lock(m_impl->callbackMutex);
    m_impl->eventCallbacks.erase(callbackId);
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<ThreatIntelStore> CreateThreatIntelStore() {
    try {
        auto store = std::make_unique<ThreatIntelStore>();
        if (!store->Initialize()) {
            return nullptr;
        }
        return store;
    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<ThreatIntelStore> CreateThreatIntelStore(const StoreConfig& config) {
    try {
        auto store = std::make_unique<ThreatIntelStore>();
        if (!store->Initialize(config)) {
            return nullptr;
        }
        return store;
    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<ThreatIntelStore> CreateHighPerformanceThreatIntelStore() {
    try {
        auto store = std::make_unique<ThreatIntelStore>();
        if (!store->Initialize(StoreConfig::CreateHighPerformance())) {
            return nullptr;
        }
        return store;
    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<ThreatIntelStore> CreateLowMemoryThreatIntelStore() {
    try {
        auto store = std::make_unique<ThreatIntelStore>();
        if (!store->Initialize(StoreConfig::CreateLowMemory())) {
            return nullptr;
        }
        return store;
    } catch (...) {
        return nullptr;
    }
}

} // namespace ThreatIntel
} // namespace ShadowStrike
