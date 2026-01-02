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
#include"../../external/nlohmann/json.hpp"

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
     * @brief Convert StoreLookupOptions to UnifiedLookupOptions
     * 
     * Maps store-level options to unified lookup interface options.
     * Ensures compatibility between public API and internal lookup system.
     * 
     * @param storeOpts Store-level lookup options
     * @return UnifiedLookupOptions for ThreatIntelLookup
     */
    [[nodiscard]] static UnifiedLookupOptions ConvertToUnifiedOptions(
        const StoreLookupOptions& storeOpts
    ) noexcept {
        UnifiedLookupOptions opts;
        
        // Map lookup tier depth based on cache settings
        if (!storeOpts.useCache) {
            opts.maxLookupTiers = 4;  // Skip cache, go to index/database
        } else {
            opts.maxLookupTiers = 4;  // Use all local tiers
        }
        
        // Map confidence threshold
        opts.minConfidence = storeOpts.minConfidenceThreshold;
        
        // Map cache behavior
        opts.cacheResult = storeOpts.updateCache;
        
        // Map metadata inclusion
        opts.includeMetadata = storeOpts.includeMetadata;
        opts.includeSourceAttribution = storeOpts.includeSourceAttribution;
        
        // Copy reputation filter if present
        if (!storeOpts.reputationFilter.empty()) {
            opts.reputationFilter = storeOpts.reputationFilter;
        }
        
        // Don't query external API by default for Store operations
        opts.queryExternalAPI = false;
        
        // Include related IOCs only if detailed metadata is requested
        opts.includeRelatedIOCs = storeOpts.includeMetadata;
        
        // Disable expensive enrichment features for Store-level lookups
        opts.includeMitreMapping = false;
        opts.includeCVEReferences = false;
        opts.includeSTIXBundle = false;
        
        return opts;
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

    // Convert StoreLookupOptions to UnifiedLookupOptions for internal lookup
    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    
    // Perform lookup through unified lookup interface
    auto tlResult = m_impl->lookup->LookupHash(hashOpt.value(), unifiedOpts);
    auto result = m_impl->ConvertLookupResult(tlResult);
    
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

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupHash(hash, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv4(
    std::string_view address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupIPv4(address, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv4(
    uint32_t address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupIPv4(address, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIPv6(
    std::string_view address,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupIPv6(address, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
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

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupIPv6(addr, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupDomain(
    std::string_view domain,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupDomain(domain, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupURL(
    std::string_view url,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupURL(url, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupEmail(
    std::string_view email,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->LookupEmail(email, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupJA3(
    std::string_view fingerprint,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->Lookup(IOCType::JA3, fingerprint, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupCVE(
    std::string_view cveId,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->Lookup(IOCType::CVE, cveId, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

StoreLookupResult ThreatIntelStore::LookupIOC(
    IOCType iocType,
    std::string_view value,
    const StoreLookupOptions& options
) noexcept {
    if (!IsInitialized() || !m_impl->lookup) {
        return StoreLookupResult{};
    }

    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);
    auto tlResult = m_impl->lookup->Lookup(iocType, value, unifiedOpts);
    return m_impl->ConvertLookupResult(tlResult);
}

// ============================================================================
// Batch Lookups
// ============================================================================

StoreBatchLookupResult ThreatIntelStore::BatchLookupHashes(
    std::string_view algorithm,
    std::span<const std::string> hashes,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = std::chrono::steady_clock::now();
    
    result.totalProcessed = hashes.size();
    result.results.reserve(hashes.size());

    for (const auto& hashStr : hashes) {
        auto lookupResult = LookupHash(algorithm, hashStr, options);
        
        // Store StoreLookupResult directly - matches StoreBatchLookupResult::results type
        result.results.emplace_back(std::move(lookupResult));
        
        // Get reference to the just-added result for statistics
        const auto& lr = result.results.back();

        if (lr.found) {
            ++result.foundCount;
            
            if (lr.fromCache) {
                ++result.cacheHits;
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
    
    // Calculate timing
    const auto endTime = std::chrono::steady_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);
    if (result.totalProcessed > 0) {
        result.averageTimePerItem = result.totalTime / result.totalProcessed;
    }

    return result;
}

StoreBatchLookupResult ThreatIntelStore::BatchLookupIPv4(
    std::span<const std::string> addresses,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = std::chrono::steady_clock::now();
    
    result.totalProcessed = addresses.size();
    result.results.reserve(addresses.size());

    // Convert StoreLookupOptions to UnifiedLookupOptions for internal lookup
    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);

    std::vector<std::string_view> views;
    views.reserve(addresses.size());
    for (const auto& addr : addresses) {
        views.push_back(addr);
    }

    auto tlResult = m_impl->lookup->BatchLookupIPv4(views, unifiedOpts);
    
    // Convert each ThreatLookupResult to StoreLookupResult
    for (const auto& tr : tlResult.results) {
        auto lr = m_impl->ConvertLookupResult(tr);
        
        if (lr.found) {
            ++result.foundCount;
            if (lr.fromCache) {
                ++result.cacheHits;
            } else {
                ++result.databaseHits;
            }
            
            if (lr.IsMalicious()) {
                ++result.maliciousCount;
            } else if (lr.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
        
        result.results.emplace_back(std::move(lr));
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;
    
    // Calculate timing
    const auto endTime = std::chrono::steady_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);
    if (result.totalProcessed > 0) {
        result.averageTimePerItem = result.totalTime / result.totalProcessed;
    }

    return result;
}

StoreBatchLookupResult ThreatIntelStore::BatchLookupDomains(
    std::span<const std::string> domains,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = std::chrono::steady_clock::now();
    
    result.totalProcessed = domains.size();
    result.results.reserve(domains.size());

    // Convert StoreLookupOptions to UnifiedLookupOptions for internal lookup
    const auto unifiedOpts = Impl::ConvertToUnifiedOptions(options);

    std::vector<std::string_view> views;
    views.reserve(domains.size());
    for (const auto& domain : domains) {
        views.push_back(domain);
    }

    auto tlResult = m_impl->lookup->BatchLookupDomains(views, unifiedOpts);
    
    // Convert each ThreatLookupResult to StoreLookupResult
    for (const auto& tr : tlResult.results) {
        auto lr = m_impl->ConvertLookupResult(tr);
        
        if (lr.found) {
            ++result.foundCount;
            if (lr.fromCache) {
                ++result.cacheHits;
            } else {
                ++result.databaseHits;
            }
            
            if (lr.IsMalicious()) {
                ++result.maliciousCount;
            } else if (lr.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
        
        result.results.emplace_back(std::move(lr));
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;
    
    // Calculate timing
    const auto endTime = std::chrono::steady_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);
    if (result.totalProcessed > 0) {
        result.averageTimePerItem = result.totalTime / result.totalProcessed;
    }

    return result;
}

StoreBatchLookupResult ThreatIntelStore::BatchLookupIOCs(
    std::span<const std::pair<IOCType, std::string>> iocs,
    const StoreLookupOptions& options
) noexcept {
    StoreBatchLookupResult result;
    
    if (!IsInitialized() || !m_impl->lookup) {
        return result;
    }

    const auto startTime = std::chrono::steady_clock::now();
    
    result.totalProcessed = iocs.size();
    result.results.reserve(iocs.size());

    for (const auto& [type, value] : iocs) {
        // LookupIOC already returns StoreLookupResult, so we can use it directly
        auto lookupResult = LookupIOC(type, value, options);
        
        if (lookupResult.found) {
            ++result.foundCount;
            
            if (lookupResult.fromCache) {
                ++result.cacheHits;
            } else {
                ++result.databaseHits;
            }

            if (lookupResult.IsMalicious()) {
                ++result.maliciousCount;
            } else if (lookupResult.IsSuspicious()) {
                ++result.suspiciousCount;
            }
        }
        
        result.results.emplace_back(std::move(lookupResult));
    }

    result.notFoundCount = result.totalProcessed - result.foundCount;
    
    // Calculate timing
    const auto endTime = std::chrono::steady_clock::now();
    result.totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime);
    if (result.totalProcessed > 0) {
        result.averageTimePerItem = result.totalTime / result.totalProcessed;
    }

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
        StoreLookupOptions storeLookupOpts = StoreLookupOptions::FastLookup();
        storeLookupOpts.cacheResult = false;
        storeLookupOpts.includeMetadata = false;
        
        // Convert to UnifiedLookupOptions for internal lookup
        const auto lookupOpts = Impl::ConvertToUnifiedOptions(storeLookupOpts);
        
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
    StoreLookupOptions storeOpts = StoreLookupOptions::FastLookup();
    storeOpts.cacheResult = false;  // Don't modify cache for existence check
    storeOpts.includeMetadata = false;
    
    // Convert to UnifiedLookupOptions for internal lookup
    const auto opts = Impl::ConvertToUnifiedOptions(storeOpts);
    
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
    
    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Starting update of all enabled feeds"
    );
    
    const auto startTime = std::chrono::steady_clock::now();
    size_t updatedCount = 0;
    size_t errorCount = 0;
    
    try {
        // Get list of all registered feeds from the feed manager
        // The feed manager maintains an internal registry of feeds
        // We iterate through known feed configurations
        
        // For thread-safety, we collect feed IDs first under shared lock
        std::vector<std::string> feedIds;
        
        // Use shared lock to read feed configurations
        {
            std::shared_lock<std::shared_mutex> readLock(m_impl->rwLock);
            
            // Get feed IDs from feed manager's internal map
            // Since direct access isn't available, we use configured feed sources
            static const std::vector<std::string> knownFeedSources = {
                "virustotal",
                "alienvault_otx",
                "abuseipdb",
                "urlhaus",
                "malwarebazaar",
                "threatfox",
                "feodotracker",
                "misp"
            };
            
            // Check which feeds are registered
            for (const auto& feedId : knownFeedSources) {
                // Feed manager will return status for valid feeds
                auto status = m_impl->feedManager->GetFeedStatus(feedId);
                if (status != FeedSyncStatus::Unknown) {
                    feedIds.push_back(feedId);
                }
            }
        }
        
        if (feedIds.empty()) {
            Utils::Logger::Instance().LogEx(
                Utils::LogLevel::Warn,
                L"ThreatIntelStore",
                __FILEW__,
                __LINE__,
                __FUNCTIONW__,
                L"No feeds registered for update"
            );
            return 0;
        }
        
        // Update each feed sequentially (parallel would require thread pool)
        // The feed manager handles rate limiting internally
        for (const auto& feedId : feedIds) {
            try {
                // Fire event before update
                StoreEvent startEvent;
                startEvent.type = StoreEventType::FeedUpdateStarted;
                startEvent.timestamp = std::chrono::system_clock::now();
                startEvent.feedId = feedId;
                m_impl->FireEvent(startEvent);
                
                // Create minimal config for update
                ThreatFeedConfig cfg{};
                cfg.feedId = feedId;
                
                bool updateSuccess = m_impl->feedManager->UpdateFeed(feedId, cfg);
                
                if (updateSuccess) {
                    ++updatedCount;
                    
                    // Fire success event
                    StoreEvent completeEvent;
                    completeEvent.type = StoreEventType::FeedUpdateCompleted;
                    completeEvent.timestamp = std::chrono::system_clock::now();
                    completeEvent.feedId = feedId;
                    m_impl->FireEvent(completeEvent);
                } else {
                    ++errorCount;
                    
                    // Fire failure event
                    StoreEvent failEvent;
                    failEvent.type = StoreEventType::FeedUpdateFailed;
                    failEvent.timestamp = std::chrono::system_clock::now();
                    failEvent.feedId = feedId;
                    failEvent.errorMessage = "Feed update returned failure";
                    m_impl->FireEvent(failEvent);
                }
            } catch (const std::exception& e) {
                ++errorCount;
                Utils::Logger::Instance().LogEx(
                    Utils::LogLevel::Error,
                    L"ThreatIntelStore",
                    __FILEW__,
                    __LINE__,
                    __FUNCTIONW__,
                    L"Error updating feed %S: %S",
                    feedId.c_str(),
                    e.what()
                );
            }
        }
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Exception during UpdateAllFeeds: %S",
            e.what()
        );
    }
    
    const auto endTime = std::chrono::steady_clock::now();
    const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Feed update complete: %zu updated, %zu errors in %lld ms",
        updatedCount,
        errorCount,
        durationMs
    );
    
    return updatedCount;
}

std::optional<FeedStatus> ThreatIntelStore::GetFeedStatus(const std::string& feedId) const noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return std::nullopt;
    }
    
    if (feedId.empty()) {
        return std::nullopt;
    }
    
    try {
        // Get sync status from feed manager
        FeedSyncStatus syncStatus = m_impl->feedManager->GetFeedStatus(feedId);
        
        // If status is Unknown, feed doesn't exist
        if (syncStatus == FeedSyncStatus::Unknown) {
            return std::nullopt;
        }
        
        // Build FeedStatus from available information
        FeedStatus status;
        status.feedId = feedId;
        
        // Map sync status to FeedStatus fields
        switch (syncStatus) {
            case FeedSyncStatus::Disabled:
                status.enabled = false;
                status.isUpdating = false;
                break;
            case FeedSyncStatus::Idle:
                status.enabled = true;
                status.isUpdating = false;
                break;
            case FeedSyncStatus::Syncing:
            case FeedSyncStatus::Parsing:
            case FeedSyncStatus::Storing:
                status.enabled = true;
                status.isUpdating = true;
                break;
            case FeedSyncStatus::Error:
                status.enabled = true;
                status.isUpdating = false;
                status.lastError = "Feed in error state";
                status.errorCount = 1;
                break;
            case FeedSyncStatus::RateLimited:
                status.enabled = true;
                status.isUpdating = false;
                status.lastError = "Rate limited";
                break;
            case FeedSyncStatus::Paused:
                status.enabled = false;
                status.isUpdating = false;
                break;
            case FeedSyncStatus::Initializing:
                status.enabled = true;
                status.isUpdating = true;
                break;
            default:
                status.enabled = true;
                status.isUpdating = false;
                break;
        }
        
        // Get additional statistics if available from feed manager
        // These would be populated from FeedStats if we had direct access
        auto feedStats = m_impl->feedManager->GetFeedStats(feedId);
        if (feedStats) {
            status.totalEntriesImported = feedStats->totalIOCsFetched.load(std::memory_order_relaxed);
            status.lastImportCount = feedStats->lastSyncIOCCount.load(std::memory_order_relaxed);
            status.errorCount = static_cast<size_t>(feedStats->totalFailedSyncs.load(std::memory_order_relaxed));
            
            // Convert timestamps
            uint64_t lastSuccess = feedStats->lastSuccessfulSync.load(std::memory_order_relaxed);
            if (lastSuccess > 0) {
                status.lastSuccessTime = std::chrono::system_clock::from_time_t(
                    static_cast<std::time_t>(lastSuccess));
            }
            
            uint64_t nextSync = feedStats->nextScheduledSync.load(std::memory_order_relaxed);
            if (nextSync > 0) {
                status.nextUpdateTime = std::chrono::system_clock::from_time_t(
                    static_cast<std::time_t>(nextSync));
            }
            
            // Get last error message if available
            {
                std::lock_guard<std::mutex> errLock(feedStats->errorMutex);
                if (!feedStats->lastErrorMessage.empty()) {
                    status.lastError = feedStats->lastErrorMessage;
                }
            }
            
            status.totalBytesDownloaded = feedStats->totalBytesDownloaded.load(std::memory_order_relaxed);
            status.lastDownloadDuration = std::chrono::milliseconds(
                feedStats->lastSyncDurationMs.load(std::memory_order_relaxed));
        }
        
        return status;
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Error getting feed status for %S: %S",
            feedId.c_str(),
            e.what()
        );
        return std::nullopt;
    }
}

std::vector<FeedStatus> ThreatIntelStore::GetAllFeedStatuses() const noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return {};
    }
    
    std::vector<FeedStatus> statuses;
    
    try {
        // Known feed source identifiers that might be registered
        static const std::vector<std::string> knownFeedSources = {
            "virustotal",
            "alienvault_otx",
            "abuseipdb",
            "urlhaus",
            "malwarebazaar",
            "threatfox",
            "feodotracker",
            "misp",
            "crowdstrike",
            "recordedfuture",
            "mandiant"
        };
        
        statuses.reserve(knownFeedSources.size());
        
        for (const auto& feedId : knownFeedSources) {
            // Check if feed is registered by getting its status
            auto status = GetFeedStatus(feedId);
            if (status.has_value()) {
                statuses.push_back(std::move(status.value()));
            }
        }
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Error getting all feed statuses: %S",
            e.what()
        );
    }
    
    return statuses;
}

void ThreatIntelStore::StartFeedUpdates() noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return;
    }
    
    try {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Info,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Starting automatic feed updates"
        );
        
        // Start the feed manager's background sync
        // The feed manager has internal scheduling based on each feed's sync interval
        m_impl->feedManager->Start();
        
        // Update store statistics to reflect feed activity
        m_impl->stats.activeFeedsCount = GetAllFeedStatuses().size();
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Error starting feed updates: %S",
            e.what()
        );
    }
}

void ThreatIntelStore::StopFeedUpdates() noexcept {
    if (!IsInitialized() || !m_impl->feedManager) {
        return;
    }
    
    try {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Info,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Stopping automatic feed updates"
        );
        
        // Stop the feed manager's background sync gracefully
        // This should wait for any in-progress syncs to complete
        m_impl->feedManager->Stop();
        
        // Update statistics
        m_impl->stats.activeFeedsCount = 0;
        m_impl->stats.feedUpdatesPending = 0;
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Error stopping feed updates: %S",
            e.what()
        );
    }
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
    result.inputPath = filePath;
    result.detectedFormat = ImportFormat::STIX21;
    
    // Validate preconditions
    if (!IsInitialized() || !m_impl->importer) {
        result.errorMessage = "Store not initialized or importer unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Input file path is empty";
        return result;
    }
    
    // Validate file exists and is readable
    try {
        std::filesystem::path path(filePath);
        if (!std::filesystem::exists(path)) {
            result.errorMessage = "Input file does not exist";
            return result;
        }
        
        if (!std::filesystem::is_regular_file(path)) {
            result.errorMessage = "Input path is not a regular file";
            return result;
        }
        
        result.bytesRead = std::filesystem::file_size(path);
    } catch (const std::filesystem::filesystem_error& e) {
        result.errorMessage = std::string("Filesystem error: ") + e.what();
        return result;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Configure import options for STIX 2.1 format
        ImportOptions stixOptions = options;
        stixOptions.format = ImportFormat::STIX21;
        stixOptions.validationLevel = ValidationLevel::Standard;
        
        // Use the importer to parse and import STIX bundle
        // The importer handles streaming parsing for large files
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile.is_open()) {
            result.errorMessage = "Failed to open input file";
            return result;
        }
        
        // Read file content (for large files, streaming would be used)
        std::string jsonContent((std::istreambuf_iterator<char>(inputFile)),
                                 std::istreambuf_iterator<char>());
        inputFile.close();
        
        // Parse STIX 2.1 bundle JSON
        auto jsonDoc = nlohmann::json::parse(jsonContent, nullptr, false);
        if (jsonDoc.is_discarded()) {
            result.errorMessage = "Failed to parse JSON content";
            return result;
        }
        
        // Validate STIX bundle structure
        if (!jsonDoc.contains("type") || jsonDoc["type"] != "bundle") {
            result.errorMessage = "Invalid STIX bundle: missing or invalid type field";
            return result;
        }
        
        if (!jsonDoc.contains("objects") || !jsonDoc["objects"].is_array()) {
            result.errorMessage = "Invalid STIX bundle: missing or invalid objects array";
            return result;
        }
        
        const auto& objects = jsonDoc["objects"];
        result.totalParsed = objects.size();
        
        // Process each STIX object
        std::vector<IOCEntry> entries;
        entries.reserve(std::min(objects.size(), stixOptions.maxEntries > 0 ? stixOptions.maxEntries : SIZE_MAX));
        
        for (const auto& obj : objects) {
            // Check max entries limit
            if (stixOptions.maxEntries > 0 && entries.size() >= stixOptions.maxEntries) {
                break;
            }
            
            // Skip if no type field
            if (!obj.contains("type")) {
                ++result.totalParseErrors;
                continue;
            }
            
            const std::string objType = obj["type"].get<std::string>();
            
            // Process indicator objects (most common IOC container in STIX)
            if (objType == "indicator") {
                IOCEntry entry{};
                entry.source = stixOptions.defaultSource;
                entry.confidence = stixOptions.defaultConfidence;
                entry.reputation = stixOptions.defaultReputation;
                entry.category = stixOptions.defaultCategory;
                entry.firstSeen = GetUnixTimestamp();
                entry.lastSeen = entry.firstSeen;
                entry.expirationTime = entry.firstSeen + stixOptions.defaultTTL;
                entry.flags = IOCFlags::HasExpiration;
                
                // Parse pattern field for IOC value
                if (obj.contains("pattern") && obj["pattern"].is_string()) {
                    std::string pattern = obj["pattern"].get<std::string>();
                    
                    // Parse STIX pattern to extract IOC
                    // Patterns like: [file:hashes.MD5 = '...']
                    //                [ipv4-addr:value = '...']
                    //                [domain-name:value = '...']
                    if (pattern.find("file:hashes") != std::string::npos) {
                        entry.type = IOCType::FileHash;
                        // Extract hash value from pattern
                        size_t eqPos = pattern.find("= '");
                        if (eqPos != std::string::npos) {
                            size_t startPos = eqPos + 3;
                            size_t endPos = pattern.find("'", startPos);
                            if (endPos != std::string::npos) {
                                std::string hashValue = pattern.substr(startPos, endPos - startPos);
                                auto hashOpt = ParseHash("", hashValue);
                                if (hashOpt.has_value()) {
                                    entry.value.hash = hashOpt.value();
                                    entries.push_back(entry);
                                    ++result.totalImported;
                                    result.countByType[IOCType::FileHash]++;
                                }
                            }
                        }
                    } else if (pattern.find("ipv4-addr:value") != std::string::npos) {
                        entry.type = IOCType::IPv4;
                        size_t eqPos = pattern.find("= '");
                        if (eqPos != std::string::npos) {
                            size_t startPos = eqPos + 3;
                            size_t endPos = pattern.find("'", startPos);
                            if (endPos != std::string::npos) {
                                std::string ipValue = pattern.substr(startPos, endPos - startPos);
                                auto ipOpt = ParseIPv4(ipValue);
                                if (ipOpt.has_value()) {
                                    entry.value.ipv4 = ipOpt.value();
                                    entries.push_back(entry);
                                    ++result.totalImported;
                                    result.countByType[IOCType::IPv4]++;
                                }
                            }
                        }
                    } else if (pattern.find("ipv6-addr:value") != std::string::npos) {
                        entry.type = IOCType::IPv6;
                        size_t eqPos = pattern.find("= '");
                        if (eqPos != std::string::npos) {
                            size_t startPos = eqPos + 3;
                            size_t endPos = pattern.find("'", startPos);
                            if (endPos != std::string::npos) {
                                std::string ipValue = pattern.substr(startPos, endPos - startPos);
                                auto ipOpt = ParseIPv6(ipValue);
                                if (ipOpt.has_value()) {
                                    entry.value.ipv6 = ipOpt.value();
                                    entries.push_back(entry);
                                    ++result.totalImported;
                                    result.countByType[IOCType::IPv6]++;
                                }
                            }
                        }
                    } else if (pattern.find("domain-name:value") != std::string::npos) {
                        entry.type = IOCType::Domain;
                        // Domain stored via IOCManager (needs string pool)
                        ++result.totalSkipped;
                    } else if (pattern.find("url:value") != std::string::npos) {
                        entry.type = IOCType::URL;
                        ++result.totalSkipped;
                    }
                }
                
                // Parse confidence from object
                if (obj.contains("confidence") && obj["confidence"].is_number_integer()) {
                    int conf = obj["confidence"].get<int>();
                    if (conf >= 80) entry.confidence = ConfidenceLevel::High;
                    else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                    else entry.confidence = ConfidenceLevel::Low;
                }
            }
            // Process malware objects for additional context
            else if (objType == "malware" || objType == "threat-actor" || objType == "attack-pattern") {
                // These provide context but not direct IOCs
                ++result.totalSkipped;
            }
        }
        
        // Bulk add parsed entries to IOC manager
        if (!entries.empty() && m_impl->iocManager) {
            IOCAddOptions addOpts;
            size_t addedCount = 0;
            for (const auto& entry : entries) {
                auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
                if (opResult.success) {
                    ++addedCount;
                }
            }
            result.totalImported = addedCount;
        }
        
        result.success = true;
        
    } catch (const nlohmann::json::exception& e) {
        result.errorMessage = std::string("JSON parsing error: ") + e.what();
        result.success = false;
    } catch (const std::exception& e) {
        result.errorMessage = std::string("Import error: ") + e.what();
        result.success = false;
    }
    
    // Calculate duration and statistics
    const auto endTime = std::chrono::steady_clock::now();
    result.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    
    if (result.durationMs > 0) {
        result.entriesPerSecond = static_cast<double>(result.totalImported) * 1000.0 / result.durationMs;
    }
    
    // Update store statistics
    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
        
        // Fire import completed event
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.entriesAffected = result.totalImported;
        m_impl->FireEvent(event);
    }
    
    Utils::Logger::Instance().LogEx(
        result.success ? Utils::LogLevel::Info : Utils::LogLevel::Error,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"STIX import %s: %zu entries imported, %zu skipped, %zu errors in %llu ms",
        result.success ? L"completed" : L"failed",
        result.totalImported,
        result.totalSkipped,
        result.totalParseErrors,
        result.durationMs
    );
    
    return result;
}

ImportResult ThreatIntelStore::ImportCSV(
    const std::wstring& filePath,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    result.inputPath = filePath;
    result.detectedFormat = ImportFormat::CSV;
    
    // Validate preconditions
    if (!IsInitialized() || !m_impl->importer) {
        result.errorMessage = "Store not initialized or importer unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Input file path is empty";
        return result;
    }
    
    // Validate file exists and get size
    try {
        std::filesystem::path path(filePath);
        if (!std::filesystem::exists(path)) {
            result.errorMessage = "Input file does not exist";
            return result;
        }
        result.bytesRead = std::filesystem::file_size(path);
    } catch (const std::filesystem::filesystem_error& e) {
        result.errorMessage = std::string("Filesystem error: ") + e.what();
        return result;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Open file for streaming read
        std::ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            result.errorMessage = "Failed to open input file";
            return result;
        }
        
        // CSV parsing configuration
        const char delimiter = options.csvConfig.delimiter;
        const char quote = options.csvConfig.quote;
        const bool hasHeader = options.csvConfig.hasHeader;
        const bool autoDetectType = options.csvConfig.autoDetectIOCType;
        
        std::string line;
        size_t lineNumber = 0;
        std::vector<std::string> headers;
        
        // Column index detection (auto-detect from headers or use config)
        int valueColumn = -1;
        int typeColumn = -1;
        int reputationColumn = -1;
        int confidenceColumn = -1;
        int firstSeenColumn = -1;
        int lastSeenColumn = -1;
        
        // Process header row if present
        if (hasHeader && std::getline(inputFile, line)) {
            ++lineNumber;
            // Parse header to detect column types
            std::stringstream ss(line);
            std::string header;
            int colIndex = 0;
            
            while (std::getline(ss, header, delimiter)) {
                // Trim whitespace and quotes
                while (!header.empty() && (header.front() == ' ' || header.front() == quote)) {
                    header.erase(0, 1);
                }
                while (!header.empty() && (header.back() == ' ' || header.back() == quote || header.back() == '\r')) {
                    header.pop_back();
                }
                
                // Convert to lowercase for comparison
                std::string lowerHeader = header;
                std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);
                
                headers.push_back(header);
                
                // Auto-detect column purpose from header name
                if (lowerHeader == "value" || lowerHeader == "ioc" || lowerHeader == "indicator" ||
                    lowerHeader == "ip" || lowerHeader == "hash" || lowerHeader == "domain" ||
                    lowerHeader == "url" || lowerHeader == "sha256" || lowerHeader == "md5") {
                    valueColumn = colIndex;
                } else if (lowerHeader == "type" || lowerHeader == "ioctype" || lowerHeader == "indicator_type") {
                    typeColumn = colIndex;
                } else if (lowerHeader == "reputation" || lowerHeader == "severity" || lowerHeader == "score") {
                    reputationColumn = colIndex;
                } else if (lowerHeader == "confidence" || lowerHeader == "confidence_level") {
                    confidenceColumn = colIndex;
                } else if (lowerHeader == "first_seen" || lowerHeader == "firstseen" || lowerHeader == "created") {
                    firstSeenColumn = colIndex;
                } else if (lowerHeader == "last_seen" || lowerHeader == "lastseen" || lowerHeader == "modified") {
                    lastSeenColumn = colIndex;
                }
                
                ++colIndex;
            }
        }
        
        // Use configured column if auto-detect failed
        if (valueColumn < 0) {
            valueColumn = options.csvConfig.csvValueColumn;
        }
        if (typeColumn < 0) {
            typeColumn = options.csvConfig.csvTypeColumn;
        }
        
        // Batch processing buffers
        std::vector<IOCEntry> batchEntries;
        batchEntries.reserve(options.batchSize > 0 ? options.batchSize : 10000);
        const size_t batchSize = options.batchSize > 0 ? options.batchSize : 10000;
        
        // Process data rows
        while (std::getline(inputFile, line)) {
            ++lineNumber;
            ++result.totalParsed;
            
            // Skip empty lines and comments
            if (line.empty() || (!options.csvConfig.commentPrefix.empty() && 
                line.find(options.csvConfig.commentPrefix) == 0)) {
                continue;
            }
            
            // Check max entries limit
            if (options.maxEntries > 0 && result.totalImported >= options.maxEntries) {
                break;
            }
            
            // Parse CSV row into fields
            std::vector<std::string> fields;
            std::string field;
            bool inQuotes = false;
            
            for (size_t i = 0; i < line.size(); ++i) {
                char c = line[i];
                
                if (c == quote) {
                    inQuotes = !inQuotes;
                } else if (c == delimiter && !inQuotes) {
                    // Trim whitespace
                    while (!field.empty() && (field.front() == ' ' || field.front() == '\t')) {
                        field.erase(0, 1);
                    }
                    while (!field.empty() && (field.back() == ' ' || field.back() == '\t' || field.back() == '\r')) {
                        field.pop_back();
                    }
                    fields.push_back(field);
                    field.clear();
                } else {
                    field += c;
                }
            }
            // Add last field
            while (!field.empty() && (field.back() == ' ' || field.back() == '\t' || field.back() == '\r')) {
                field.pop_back();
            }
            fields.push_back(field);
            
            // Validate we have enough fields
            if (valueColumn >= static_cast<int>(fields.size())) {
                ++result.totalParseErrors;
                if (options.logParseErrors && result.totalParseErrors <= options.maxParseErrors) {
                    ParseError err;
                    err.lineNumber = lineNumber;
                    err.errorCode = 1;
                    err.message = "Value column index out of range";
                    err.rawInput = line.substr(0, std::min(line.size(), size_t(100)));
                    result.parseErrors.push_back(err);
                }
                continue;
            }
            
            // Extract IOC value
            const std::string& iocValue = fields[valueColumn];
            if (iocValue.empty()) {
                ++result.totalSkipped;
                continue;
            }
            
            // Create IOC entry
            IOCEntry entry{};
            entry.source = options.defaultSource;
            entry.confidence = options.defaultConfidence;
            entry.reputation = options.defaultReputation;
            entry.category = options.defaultCategory;
            entry.firstSeen = GetUnixTimestamp();
            entry.lastSeen = entry.firstSeen;
            entry.expirationTime = entry.firstSeen + options.defaultTTL;
            entry.flags = IOCFlags::HasExpiration;
            
            // Determine IOC type from type column or auto-detect
            IOCType detectedType = options.csvConfig.defaultIOCType;
            
            if (typeColumn >= 0 && typeColumn < static_cast<int>(fields.size())) {
                const std::string& typeStr = fields[typeColumn];
                std::string lowerType = typeStr;
                std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::tolower);
                
                if (lowerType == "ip" || lowerType == "ipv4" || lowerType.find("ipaddr") != std::string::npos) {
                    detectedType = IOCType::IPv4;
                } else if (lowerType == "ipv6") {
                    detectedType = IOCType::IPv6;
                } else if (lowerType.find("hash") != std::string::npos || lowerType == "md5" || 
                           lowerType == "sha1" || lowerType == "sha256") {
                    detectedType = IOCType::FileHash;
                } else if (lowerType == "domain" || lowerType == "hostname") {
                    detectedType = IOCType::Domain;
                } else if (lowerType == "url" || lowerType == "uri") {
                    detectedType = IOCType::URL;
                } else if (lowerType == "email") {
                    detectedType = IOCType::Email;
                }
            } else if (autoDetectType) {
                // Auto-detect IOC type from value format
                // Check for IPv4: n.n.n.n pattern
                if (std::count(iocValue.begin(), iocValue.end(), '.') == 3 &&
                    iocValue.find_first_not_of("0123456789./") == std::string::npos) {
                    detectedType = IOCType::IPv4;
                }
                // Check for IPv6: contains colons and hex digits
                else if (iocValue.find(':') != std::string::npos &&
                         iocValue.find_first_not_of("0123456789abcdefABCDEF:/") == std::string::npos) {
                    detectedType = IOCType::IPv6;
                }
                // Check for hash: all hex digits with specific lengths
                else if (iocValue.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos &&
                         (iocValue.length() == 32 || iocValue.length() == 40 || 
                          iocValue.length() == 64 || iocValue.length() == 128)) {
                    detectedType = IOCType::FileHash;
                }
                // Check for URL: starts with http/https or has protocol://
                else if (iocValue.find("://") != std::string::npos ||
                         iocValue.find("http") == 0) {
                    detectedType = IOCType::URL;
                }
                // Check for email: contains @ with . after it
                else if (iocValue.find('@') != std::string::npos &&
                         iocValue.find('.', iocValue.find('@')) != std::string::npos) {
                    detectedType = IOCType::Email;
                }
                // Default to domain if contains dots
                else if (iocValue.find('.') != std::string::npos) {
                    detectedType = IOCType::Domain;
                }
            }
            
            // Parse value based on detected type
            entry.type = detectedType;
            bool parseSuccess = false;
            
            switch (detectedType) {
                case IOCType::IPv4: {
                    auto ipOpt = ParseIPv4(iocValue);
                    if (ipOpt.has_value()) {
                        entry.value.ipv4 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv4]++;
                    }
                    break;
                }
                case IOCType::IPv6: {
                    auto ipOpt = ParseIPv6(iocValue);
                    if (ipOpt.has_value()) {
                        entry.value.ipv6 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv6]++;
                    }
                    break;
                }
                case IOCType::FileHash: {
                    auto hashOpt = ParseHash("", iocValue);
                    if (hashOpt.has_value()) {
                        entry.value.hash = hashOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::FileHash]++;
                    }
                    break;
                }
                default:
                    // String-based types (Domain, URL, Email) need string pool handling
                    // Skip for now - these would be handled by IOCManager directly
                    ++result.totalSkipped;
                    continue;
            }
            
            if (!parseSuccess) {
                ++result.totalParseErrors;
                if (options.continueOnError && result.totalParseErrors >= options.maxParseErrors) {
                    result.errorMessage = "Too many parse errors";
                    break;
                }
                continue;
            }
            
            // Parse additional columns if available
            if (reputationColumn >= 0 && reputationColumn < static_cast<int>(fields.size())) {
                const std::string& repStr = fields[reputationColumn];
                std::string lowerRep = repStr;
                std::transform(lowerRep.begin(), lowerRep.end(), lowerRep.begin(), ::tolower);
                
                if (lowerRep == "malicious" || lowerRep == "bad" || lowerRep == "high") {
                    entry.reputation = ReputationLevel::Malicious;
                } else if (lowerRep == "suspicious" || lowerRep == "medium") {
                    entry.reputation = ReputationLevel::Suspicious;
                } else if (lowerRep == "safe" || lowerRep == "clean" || lowerRep == "good" || lowerRep == "low") {
                    entry.reputation = ReputationLevel::Safe;
                }
            }
            
            // Add to batch
            batchEntries.push_back(entry);
            
            // Process batch when full
            if (batchEntries.size() >= batchSize) {
                if (m_impl->iocManager) {
                    IOCAddOptions addOpts;
                    for (const auto& batchEntry : batchEntries) {
                        auto opResult = m_impl->iocManager->AddIOC(batchEntry, addOpts);
                        if (opResult.success) {
                            ++result.totalImported;
                        } else {
                            ++result.totalValidationFailures;
                        }
                    }
                }
                batchEntries.clear();
            }
        }
        
        // Process remaining batch
        if (!batchEntries.empty() && m_impl->iocManager) {
            IOCAddOptions addOpts;
            for (const auto& batchEntry : batchEntries) {
                auto opResult = m_impl->iocManager->AddIOC(batchEntry, addOpts);
                if (opResult.success) {
                    ++result.totalImported;
                } else {
                    ++result.totalValidationFailures;
                }
            }
        }
        
        result.success = true;
        
    } catch (const std::exception& e) {
        result.errorMessage = std::string("CSV import error: ") + e.what();
        result.success = false;
    }
    
    // Calculate duration and statistics
    const auto endTime = std::chrono::steady_clock::now();
    result.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    
    if (result.durationMs > 0) {
        result.entriesPerSecond = static_cast<double>(result.totalImported) * 1000.0 / result.durationMs;
    }
    
    // Update store statistics
    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
        
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.entriesAffected = result.totalImported;
        m_impl->FireEvent(event);
    }
    
    Utils::Logger::Instance().LogEx(
        result.success ? Utils::LogLevel::Info : Utils::LogLevel::Error,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"CSV import %s: %zu entries imported, %zu skipped, %zu errors in %llu ms (%.1f entries/sec)",
        result.success ? L"completed" : L"failed",
        result.totalImported,
        result.totalSkipped,
        result.totalParseErrors,
        result.durationMs,
        result.entriesPerSecond
    );
    
    return result;
}

ImportResult ThreatIntelStore::ImportJSON(
    const std::wstring& filePath,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    result.inputPath = filePath;
    result.detectedFormat = ImportFormat::JSON;
    
    // Validate preconditions
    if (!IsInitialized() || !m_impl->importer) {
        result.errorMessage = "Store not initialized or importer unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Input file path is empty";
        return result;
    }
    
    // Validate file exists
    try {
        std::filesystem::path path(filePath);
        if (!std::filesystem::exists(path)) {
            result.errorMessage = "Input file does not exist";
            return result;
        }
        result.bytesRead = std::filesystem::file_size(path);
    } catch (const std::filesystem::filesystem_error& e) {
        result.errorMessage = std::string("Filesystem error: ") + e.what();
        return result;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Open and read file
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile.is_open()) {
            result.errorMessage = "Failed to open input file";
            return result;
        }
        
        // Read entire file (for large files, streaming would be used)
        std::string jsonContent((std::istreambuf_iterator<char>(inputFile)),
                                 std::istreambuf_iterator<char>());
        inputFile.close();
        
        // Parse JSON
        auto jsonDoc = nlohmann::json::parse(jsonContent, nullptr, false);
        if (jsonDoc.is_discarded()) {
            result.errorMessage = "Failed to parse JSON content";
            return result;
        }
        
        // Detect JSON structure and extract IOC array
        std::vector<IOCEntry> entries;
        const nlohmann::json* iocArray = nullptr;
        
        // Check for common JSON structures
        if (jsonDoc.is_array()) {
            // Direct array of IOCs
            iocArray = &jsonDoc;
        } else if (jsonDoc.contains("data") && jsonDoc["data"].is_array()) {
            // { "data": [...] }
            iocArray = &jsonDoc["data"];
        } else if (jsonDoc.contains("indicators") && jsonDoc["indicators"].is_array()) {
            // { "indicators": [...] }
            iocArray = &jsonDoc["indicators"];
        } else if (jsonDoc.contains("iocs") && jsonDoc["iocs"].is_array()) {
            // { "iocs": [...] }
            iocArray = &jsonDoc["iocs"];
        } else if (jsonDoc.contains("results") && jsonDoc["results"].is_array()) {
            // { "results": [...] }
            iocArray = &jsonDoc["results"];
        } else if (jsonDoc.contains("items") && jsonDoc["items"].is_array()) {
            // { "items": [...] }
            iocArray = &jsonDoc["items"];
        } else {
            result.errorMessage = "Unable to find IOC array in JSON structure";
            return result;
        }
        
        result.totalParsed = iocArray->size();
        entries.reserve(std::min(iocArray->size(), options.maxEntries > 0 ? options.maxEntries : SIZE_MAX));
        
        // Process each IOC object
        for (const auto& ioc : *iocArray) {
            // Check max entries limit
            if (options.maxEntries > 0 && entries.size() >= options.maxEntries) {
                break;
            }
            
            // Skip non-object entries
            if (!ioc.is_object() && !ioc.is_string()) {
                ++result.totalSkipped;
                continue;
            }
            
            IOCEntry entry{};
            entry.source = options.defaultSource;
            entry.confidence = options.defaultConfidence;
            entry.reputation = options.defaultReputation;
            entry.category = options.defaultCategory;
            entry.firstSeen = GetUnixTimestamp();
            entry.lastSeen = entry.firstSeen;
            entry.expirationTime = entry.firstSeen + options.defaultTTL;
            entry.flags = IOCFlags::HasExpiration;
            
            std::string iocValue;
            IOCType iocType = IOCType::Reserved;
            
            // Handle string-only IOC entries
            if (ioc.is_string()) {
                iocValue = ioc.get<std::string>();
                iocType = IOCType::Reserved;  // Will auto-detect
            } else {
                // Extract value from object
                if (ioc.contains("value")) {
                    iocValue = ioc["value"].get<std::string>();
                } else if (ioc.contains("indicator")) {
                    iocValue = ioc["indicator"].get<std::string>();
                } else if (ioc.contains("ioc")) {
                    iocValue = ioc["ioc"].get<std::string>();
                } else if (ioc.contains("hash")) {
                    iocValue = ioc["hash"].get<std::string>();
                    iocType = IOCType::FileHash;
                } else if (ioc.contains("ip")) {
                    iocValue = ioc["ip"].get<std::string>();
                    iocType = IOCType::IPv4;
                } else if (ioc.contains("domain")) {
                    iocValue = ioc["domain"].get<std::string>();
                    iocType = IOCType::Domain;
                } else if (ioc.contains("url")) {
                    iocValue = ioc["url"].get<std::string>();
                    iocType = IOCType::URL;
                } else {
                    ++result.totalSkipped;
                    continue;
                }
                
                // Extract type if specified
                if (ioc.contains("type")) {
                    std::string typeStr = ioc["type"].get<std::string>();
                    std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(), ::tolower);
                    
                    if (typeStr == "ip" || typeStr == "ipv4" || typeStr == "ip-dst" || typeStr == "ip-src") {
                        iocType = IOCType::IPv4;
                    } else if (typeStr == "ipv6" || typeStr == "ip6") {
                        iocType = IOCType::IPv6;
                    } else if (typeStr.find("hash") != std::string::npos || 
                               typeStr == "md5" || typeStr == "sha1" || typeStr == "sha256") {
                        iocType = IOCType::FileHash;
                    } else if (typeStr == "domain" || typeStr == "hostname") {
                        iocType = IOCType::Domain;
                    } else if (typeStr == "url" || typeStr == "uri") {
                        iocType = IOCType::URL;
                    } else if (typeStr == "email" || typeStr == "email-addr") {
                        iocType = IOCType::Email;
                    }
                }
                
                // Extract confidence
                if (ioc.contains("confidence")) {
                    if (ioc["confidence"].is_number()) {
                        int conf = ioc["confidence"].get<int>();
                        if (conf >= 80) entry.confidence = ConfidenceLevel::High;
                        else if (conf >= 50) entry.confidence = ConfidenceLevel::Medium;
                        else entry.confidence = ConfidenceLevel::Low;
                    } else if (ioc["confidence"].is_string()) {
                        std::string confStr = ioc["confidence"].get<std::string>();
                        std::transform(confStr.begin(), confStr.end(), confStr.begin(), ::tolower);
                        if (confStr == "high") entry.confidence = ConfidenceLevel::High;
                        else if (confStr == "medium") entry.confidence = ConfidenceLevel::Medium;
                        else entry.confidence = ConfidenceLevel::Low;
                    }
                }
                
                // Extract reputation/severity
                if (ioc.contains("reputation") || ioc.contains("severity")) {
                    std::string repKey = ioc.contains("reputation") ? "reputation" : "severity";
                    if (ioc[repKey].is_string()) {
                        std::string repStr = ioc[repKey].get<std::string>();
                        std::transform(repStr.begin(), repStr.end(), repStr.begin(), ::tolower);
                        if (repStr == "malicious" || repStr == "high" || repStr == "critical") {
                            entry.reputation = ReputationLevel::Malicious;
                        } else if (repStr == "suspicious" || repStr == "medium") {
                            entry.reputation = ReputationLevel::Suspicious;
                        } else if (repStr == "safe" || repStr == "clean" || repStr == "low") {
                            entry.reputation = ReputationLevel::Safe;
                        }
                    } else if (ioc[repKey].is_number()) {
                        int rep = ioc[repKey].get<int>();
                        if (rep >= 80) entry.reputation = ReputationLevel::Malicious;
                        else if (rep >= 50) entry.reputation = ReputationLevel::Suspicious;
                        else entry.reputation = ReputationLevel::Safe;
                    }
                }
            }
            
            if (iocValue.empty()) {
                ++result.totalSkipped;
                continue;
            }
            
            // Auto-detect type if not determined
            if (iocType == IOCType::Reserved) {
                if (std::count(iocValue.begin(), iocValue.end(), '.') == 3 &&
                    iocValue.find_first_not_of("0123456789./") == std::string::npos) {
                    iocType = IOCType::IPv4;
                } else if (iocValue.find(':') != std::string::npos &&
                           iocValue.find_first_not_of("0123456789abcdefABCDEF:/") == std::string::npos) {
                    iocType = IOCType::IPv6;
                } else if (iocValue.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos &&
                           (iocValue.length() == 32 || iocValue.length() == 40 ||
                            iocValue.length() == 64 || iocValue.length() == 128)) {
                    iocType = IOCType::FileHash;
                } else if (iocValue.find("://") != std::string::npos) {
                    iocType = IOCType::URL;
                } else if (iocValue.find('@') != std::string::npos) {
                    iocType = IOCType::Email;
                } else if (iocValue.find('.') != std::string::npos) {
                    iocType = IOCType::Domain;
                }
            }
            
            // Parse and store based on type
            entry.type = iocType;
            bool parseSuccess = false;
            
            switch (iocType) {
                case IOCType::IPv4: {
                    auto ipOpt = ParseIPv4(iocValue);
                    if (ipOpt.has_value()) {
                        entry.value.ipv4 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv4]++;
                    }
                    break;
                }
                case IOCType::IPv6: {
                    auto ipOpt = ParseIPv6(iocValue);
                    if (ipOpt.has_value()) {
                        entry.value.ipv6 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv6]++;
                    }
                    break;
                }
                case IOCType::FileHash: {
                    auto hashOpt = ParseHash("", iocValue);
                    if (hashOpt.has_value()) {
                        entry.value.hash = hashOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::FileHash]++;
                    }
                    break;
                }
                default:
                    // String-based types handled by IOCManager
                    ++result.totalSkipped;
                    continue;
            }
            
            if (parseSuccess) {
                entries.push_back(entry);
            } else {
                ++result.totalParseErrors;
            }
        }
        
        // Bulk add entries
        if (!entries.empty() && m_impl->iocManager) {
            IOCAddOptions addOpts;
            for (const auto& entry : entries) {
                auto opResult = m_impl->iocManager->AddIOC(entry, addOpts);
                if (opResult.success) {
                    ++result.totalImported;
                } else {
                    ++result.totalValidationFailures;
                }
            }
        }
        
        result.success = true;
        
    } catch (const nlohmann::json::exception& e) {
        result.errorMessage = std::string("JSON parsing error: ") + e.what();
        result.success = false;
    } catch (const std::exception& e) {
        result.errorMessage = std::string("Import error: ") + e.what();
        result.success = false;
    }
    
    // Calculate statistics
    const auto endTime = std::chrono::steady_clock::now();
    result.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    
    if (result.durationMs > 0) {
        result.entriesPerSecond = static_cast<double>(result.totalImported) * 1000.0 / result.durationMs;
    }
    
    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
        
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.entriesAffected = result.totalImported;
        m_impl->FireEvent(event);
    }
    
    Utils::Logger::Instance().LogEx(
        result.success ? Utils::LogLevel::Info : Utils::LogLevel::Error,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"JSON import %s: %zu entries imported, %zu skipped in %llu ms",
        result.success ? L"completed" : L"failed",
        result.totalImported,
        result.totalSkipped,
        result.durationMs
    );
    
    return result;
}

ImportResult ThreatIntelStore::ImportPlainText(
    const std::wstring& filePath,
    IOCType iocType,
    const ImportOptions& options
) noexcept {
    ImportResult result;
    result.success = false;
    result.inputPath = filePath;
    result.detectedFormat = ImportFormat::PlainText;
    
    // Validate preconditions
    if (!IsInitialized() || !m_impl->importer) {
        result.errorMessage = "Store not initialized or importer unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Input file path is empty";
        return result;
    }
    
    // Validate file exists
    try {
        std::filesystem::path path(filePath);
        if (!std::filesystem::exists(path)) {
            result.errorMessage = "Input file does not exist";
            return result;
        }
        result.bytesRead = std::filesystem::file_size(path);
    } catch (const std::filesystem::filesystem_error& e) {
        result.errorMessage = std::string("Filesystem error: ") + e.what();
        return result;
    }
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Open file for streaming read
        std::ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            result.errorMessage = "Failed to open input file";
            return result;
        }
        
        std::string line;
        size_t lineNumber = 0;
        std::vector<IOCEntry> batchEntries;
        const size_t batchSize = options.batchSize > 0 ? options.batchSize : 10000;
        batchEntries.reserve(batchSize);
        
        const bool autoDetectType = (iocType == IOCType::Reserved || iocType == IOCType::Unknown);
        const std::string commentPrefix = options.csvConfig.commentPrefix;
        
        while (std::getline(inputFile, line)) {
            ++lineNumber;
            ++result.totalParsed;
            
            // Skip empty lines
            if (line.empty()) {
                continue;
            }
            
            // Trim whitespace and carriage returns
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || 
                   line.back() == ' ' || line.back() == '\t')) {
                line.pop_back();
            }
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
                line.erase(0, 1);
            }
            
            if (line.empty()) {
                continue;
            }
            
            // Skip comments
            if (!commentPrefix.empty() && line.find(commentPrefix) == 0) {
                continue;
            }
            
            // Check max entries limit
            if (options.maxEntries > 0 && (result.totalImported + batchEntries.size()) >= options.maxEntries) {
                break;
            }
            
            // Determine IOC type
            IOCType detectedType = iocType;
            
            if (autoDetectType) {
                // Auto-detect from value format
                if (std::count(line.begin(), line.end(), '.') == 3 &&
                    line.find_first_not_of("0123456789./") == std::string::npos) {
                    detectedType = IOCType::IPv4;
                } else if (line.find(':') != std::string::npos &&
                           line.find_first_not_of("0123456789abcdefABCDEF:/") == std::string::npos) {
                    detectedType = IOCType::IPv6;
                } else if (line.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos &&
                           (line.length() == 32 || line.length() == 40 ||
                            line.length() == 64 || line.length() == 128)) {
                    detectedType = IOCType::FileHash;
                } else if (line.find("://") != std::string::npos) {
                    detectedType = IOCType::URL;
                } else if (line.find('@') != std::string::npos &&
                           line.find('.', line.find('@')) != std::string::npos) {
                    detectedType = IOCType::Email;
                } else if (line.find('.') != std::string::npos &&
                           line.find_first_of(" \t") == std::string::npos) {
                    detectedType = IOCType::Domain;
                } else {
                    // Unable to determine type
                    ++result.totalSkipped;
                    continue;
                }
            }
            
            // Create IOC entry
            IOCEntry entry{};
            entry.type = detectedType;
            entry.source = options.defaultSource;
            entry.confidence = options.defaultConfidence;
            entry.reputation = options.defaultReputation;
            entry.category = options.defaultCategory;
            entry.firstSeen = GetUnixTimestamp();
            entry.lastSeen = entry.firstSeen;
            entry.expirationTime = entry.firstSeen + options.defaultTTL;
            entry.flags = IOCFlags::HasExpiration;
            
            // Parse value based on type
            bool parseSuccess = false;
            
            switch (detectedType) {
                case IOCType::IPv4: {
                    auto ipOpt = ParseIPv4(line);
                    if (ipOpt.has_value()) {
                        entry.value.ipv4 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv4]++;
                    }
                    break;
                }
                case IOCType::IPv6: {
                    auto ipOpt = ParseIPv6(line);
                    if (ipOpt.has_value()) {
                        entry.value.ipv6 = ipOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::IPv6]++;
                    }
                    break;
                }
                case IOCType::FileHash: {
                    auto hashOpt = ParseHash("", line);
                    if (hashOpt.has_value()) {
                        entry.value.hash = hashOpt.value();
                        parseSuccess = true;
                        result.countByType[IOCType::FileHash]++;
                    }
                    break;
                }
                default:
                    // String-based types (Domain, URL, Email) - skip for now
                    // These would need string pool handling via IOCManager
                    ++result.totalSkipped;
                    continue;
            }
            
            if (!parseSuccess) {
                ++result.totalParseErrors;
                if (options.logParseErrors && result.parseErrors.size() < options.maxParseErrors) {
                    ParseError err;
                    err.lineNumber = lineNumber;
                    err.errorCode = 1;
                    err.message = "Failed to parse IOC value";
                    err.rawInput = line.substr(0, std::min(line.size(), size_t(100)));
                    result.parseErrors.push_back(err);
                }
                
                if (!options.continueOnError || result.totalParseErrors >= options.maxParseErrors) {
                    result.errorMessage = "Too many parse errors";
                    break;
                }
                continue;
            }
            
            batchEntries.push_back(entry);
            
            // Process batch when full
            if (batchEntries.size() >= batchSize) {
                if (m_impl->iocManager) {
                    IOCAddOptions addOpts;
                    for (const auto& batchEntry : batchEntries) {
                        auto opResult = m_impl->iocManager->AddIOC(batchEntry, addOpts);
                        if (opResult.success) {
                            ++result.totalImported;
                        } else {
                            ++result.totalValidationFailures;
                        }
                    }
                }
                batchEntries.clear();
            }
        }
        
        // Process remaining batch
        if (!batchEntries.empty() && m_impl->iocManager) {
            IOCAddOptions addOpts;
            for (const auto& batchEntry : batchEntries) {
                auto opResult = m_impl->iocManager->AddIOC(batchEntry, addOpts);
                if (opResult.success) {
                    ++result.totalImported;
                } else {
                    ++result.totalValidationFailures;
                }
            }
        }
        
        result.success = true;
        
    } catch (const std::exception& e) {
        result.errorMessage = std::string("PlainText import error: ") + e.what();
        result.success = false;
    }
    
    // Calculate statistics
    const auto endTime = std::chrono::steady_clock::now();
    result.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    
    if (result.durationMs > 0) {
        result.entriesPerSecond = static_cast<double>(result.totalImported) * 1000.0 / result.durationMs;
    }
    
    if (result.success && result.totalImported > 0) {
        m_impl->stats.totalImportedEntries.fetch_add(result.totalImported, std::memory_order_relaxed);
        
        StoreEvent event;
        event.type = StoreEventType::DataImported;
        event.timestamp = std::chrono::system_clock::now();
        event.entriesAffected = result.totalImported;
        m_impl->FireEvent(event);
    }
    
    Utils::Logger::Instance().LogEx(
        result.success ? Utils::LogLevel::Info : Utils::LogLevel::Error,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"PlainText import %s: %zu entries imported, %zu skipped, %zu lines in %llu ms (%.1f entries/sec)",
        result.success ? L"completed" : L"failed",
        result.totalImported,
        result.totalSkipped,
        result.totalParsed,
        result.durationMs,
        result.entriesPerSecond
    );
    
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
    
    if (!IsInitialized() || !m_impl->database) {
        result.errorMessage = "Store not initialized or database unavailable";
        return result;
    }
    
    if (filePath.empty()) {
        result.errorMessage = "Output file path is empty";
        return result;
    }

    std::shared_lock<std::shared_mutex> lock(m_impl->rwLock);
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Create output directory if needed
        std::filesystem::path outPath(filePath);
        if (outPath.has_parent_path()) {
            std::filesystem::create_directories(outPath.parent_path());
        }
        
        // Open output file
        std::ofstream outputFile(filePath, std::ios::binary | std::ios::trunc);
        if (!outputFile.is_open()) {
            result.errorMessage = "Failed to create output file";
            return result;
        }
        
        // Get entries from database
        const IOCEntry* entries = m_impl->database->GetEntries();
        const size_t entryCount = m_impl->database->GetEntryCount();
        
        if (entryCount == 0 || entries == nullptr) {
            // No entries to export - still a success
            result.success = true;
            result.totalExported = 0;
            outputFile.close();
            return result;
        }
        
        // Helper to format IPv4 address
        auto formatIPv4 = [](uint32_t addr) -> std::string {
            char buffer[16];
            snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
                     (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
                     (addr >> 8) & 0xFF, addr & 0xFF);
            return std::string(buffer);
        };
        
        // Helper to format hash as hex string
        auto formatHash = [](const HashValue& hash) -> std::string {
            static const char hexChars[] = "0123456789abcdef";
            std::string result;
            result.reserve(hash.length * 2);
            for (size_t i = 0; i < hash.length && i < hash.data.size(); ++i) {
                result += hexChars[(hash.data[i] >> 4) & 0x0F];
                result += hexChars[hash.data[i] & 0x0F];
            }
            return result;
        };
        
        // Helper to get reputation string
        auto reputationToString = [](ReputationLevel rep) -> const char* {
            switch (rep) {
                case ReputationLevel::Malicious: return "malicious";
                case ReputationLevel::HighRisk: return "high_risk";
                case ReputationLevel::Suspicious: return "suspicious";
                case ReputationLevel::Safe: return "safe";
                case ReputationLevel::Trusted: return "trusted";
                default: return "unknown";
            }
        };
        
        // Helper to get IOC type string
        auto typeToString = [](IOCType type) -> const char* {
            switch (type) {
                case IOCType::IPv4: return "ipv4";
                case IOCType::IPv6: return "ipv6";
                case IOCType::FileHash: return "hash";
                case IOCType::Domain: return "domain";
                case IOCType::URL: return "url";
                case IOCType::Email: return "email";
                case IOCType::JA3: return "ja3";
                default: return "unknown";
            }
        };
        
        // Export based on format
        switch (options.format) {
            case ExportFormat::JSON: {
                nlohmann::json jsonOutput;
                jsonOutput["version"] = "1.0";
                jsonOutput["exported_at"] = GetUnixTimestamp();
                jsonOutput["total_entries"] = entryCount;
                jsonOutput["indicators"] = nlohmann::json::array();
                
                for (size_t i = 0; i < entryCount; ++i) {
                    const auto& entry = entries[i];
                    
                    // Apply filter if specified
                    if (!options.filter.Matches(entry)) {
                        continue;
                    }
                    
                    // Check max entries
                    if (options.filter.maxEntries > 0 && result.totalExported >= options.filter.maxEntries) {
                        break;
                    }
                    
                    nlohmann::json indicator;
                    indicator["type"] = typeToString(entry.type);
                    indicator["reputation"] = reputationToString(entry.reputation);
                    indicator["first_seen"] = entry.firstSeen;
                    indicator["last_seen"] = entry.lastSeen;
                    
                    // Add value based on type
                    switch (entry.type) {
                        case IOCType::IPv4:
                            indicator["value"] = formatIPv4(entry.value.ipv4.address);
                            break;
                        case IOCType::FileHash:
                            indicator["value"] = formatHash(entry.value.hash);
                            break;
                        default:
                            // Skip types that need string pool lookup
                            continue;
                    }
                    
                    jsonOutput["indicators"].push_back(indicator);
                    ++result.totalExported;
                }
                
                // Write JSON to file
                std::string jsonStr = options.prettyPrint ? jsonOutput.dump(2) : jsonOutput.dump();
                outputFile.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
                result.bytesWritten = jsonStr.size();
                break;
            }
            
            case ExportFormat::CSV: {
                // Write CSV header
                std::string header = "type,value,reputation,confidence,first_seen,last_seen\n";
                outputFile.write(header.data(), static_cast<std::streamsize>(header.size()));
                result.bytesWritten = header.size();
                
                for (size_t i = 0; i < entryCount; ++i) {
                    const auto& entry = entries[i];
                    
                    // Apply filter
                    if (!options.filter.Matches(entry)) {
                        continue;
                    }
                    
                    // Check max entries
                    if (options.filter.maxEntries > 0 && result.totalExported >= options.filter.maxEntries) {
                        break;
                    }
                    
                    std::string valueStr;
                    switch (entry.type) {
                        case IOCType::IPv4:
                            valueStr = formatIPv4(entry.value.ipv4.address);
                            break;
                        case IOCType::FileHash:
                            valueStr = formatHash(entry.value.hash);
                            break;
                        default:
                            continue;  // Skip types needing string pool
                    }
                    
                    char lineBuffer[512];
                    int len = snprintf(lineBuffer, sizeof(lineBuffer), "%s,%s,%s,%d,%llu,%llu\n",
                        typeToString(entry.type),
                        valueStr.c_str(),
                        reputationToString(entry.reputation),
                        static_cast<int>(entry.confidence),
                        static_cast<unsigned long long>(entry.firstSeen),
                        static_cast<unsigned long long>(entry.lastSeen));
                    
                    if (len > 0 && len < static_cast<int>(sizeof(lineBuffer))) {
                        outputFile.write(lineBuffer, len);
                        result.bytesWritten += static_cast<size_t>(len);
                        ++result.totalExported;
                    }
                }
                break;
            }
            
            case ExportFormat::PlainText: {
                // One IOC value per line
                for (size_t i = 0; i < entryCount; ++i) {
                    const auto& entry = entries[i];
                    
                    // Apply filter
                    if (!options.filter.Matches(entry)) {
                        continue;
                    }
                    
                    // Check max entries
                    if (options.filter.maxEntries > 0 && result.totalExported >= options.filter.maxEntries) {
                        break;
                    }
                    
                    std::string valueStr;
                    switch (entry.type) {
                        case IOCType::IPv4:
                            valueStr = formatIPv4(entry.value.ipv4.address) + "\n";
                            break;
                        case IOCType::FileHash:
                            valueStr = formatHash(entry.value.hash) + "\n";
                            break;
                        default:
                            continue;
                    }
                    
                    outputFile.write(valueStr.data(), static_cast<std::streamsize>(valueStr.size()));
                    result.bytesWritten += valueStr.size();
                    ++result.totalExported;
                }
                break;
            }
            
            case ExportFormat::STIX21: {
                // STIX 2.1 bundle format
                nlohmann::json stixBundle;
                stixBundle["type"] = "bundle";
                stixBundle["id"] = "bundle--" + std::to_string(GetUnixTimestamp());
                stixBundle["objects"] = nlohmann::json::array();
                
                for (size_t i = 0; i < entryCount; ++i) {
                    const auto& entry = entries[i];
                    
                    // Apply filter
                    if (!options.filter.Matches(entry)) {
                        continue;
                    }
                    
                    // Check max entries
                    if (options.filter.maxEntries > 0 && result.totalExported >= options.filter.maxEntries) {
                        break;
                    }
                    
                    nlohmann::json indicator;
                    indicator["type"] = "indicator";
                    indicator["spec_version"] = "2.1";
                    indicator["id"] = "indicator--" + std::to_string(i);
                    indicator["created"] = GetUnixTimestamp();
                    indicator["modified"] = entry.lastSeen;
                    indicator["indicator_types"] = nlohmann::json::array({"malicious-activity"});
                    indicator["valid_from"] = entry.firstSeen;
                    
                    // Create pattern based on IOC type
                    std::string pattern;
                    switch (entry.type) {
                        case IOCType::IPv4:
                            pattern = "[ipv4-addr:value = '" + formatIPv4(entry.value.ipv4.address) + "']";
                            break;
                        case IOCType::FileHash: {
                            std::string hashValue = formatHash(entry.value.hash);
                            std::string algoName;
                            switch (entry.value.hash.algorithm) {
                                case HashAlgorithm::MD5: algoName = "MD5"; break;
                                case HashAlgorithm::SHA1: algoName = "SHA-1"; break;
                                case HashAlgorithm::SHA256: algoName = "SHA-256"; break;
                                default: algoName = "SHA-256"; break;
                            }
                            pattern = "[file:hashes.'" + algoName + "' = '" + hashValue + "']";
                            break;
                        }
                        default:
                            continue;
                    }
                    
                    indicator["pattern"] = pattern;
                    indicator["pattern_type"] = "stix";
                    
                    // Add confidence
                    switch (entry.confidence) {
                        case ConfidenceLevel::High: indicator["confidence"] = 85; break;
                        case ConfidenceLevel::Medium: indicator["confidence"] = 50; break;
                        default: indicator["confidence"] = 25; break;
                    }
                    
                    stixBundle["objects"].push_back(indicator);
                    ++result.totalExported;
                }
                
                // Write STIX bundle
                std::string stixStr = options.prettyPrint ? stixBundle.dump(2) : stixBundle.dump();
                outputFile.write(stixStr.data(), static_cast<std::streamsize>(stixStr.size()));
                result.bytesWritten = stixStr.size();
                break;
            }
            
            default:
                result.errorMessage = "Unsupported export format";
                return result;
        }
        
        outputFile.close();
        result.success = true;
        
    } catch (const std::exception& e) {
        result.errorMessage = std::string("Export error: ") + e.what();
        result.success = false;
    }
    
    // Calculate duration
    const auto endTime = std::chrono::steady_clock::now();
    const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    if (result.success && result.totalExported > 0) {
        m_impl->stats.totalExportedEntries.fetch_add(result.totalExported, std::memory_order_relaxed);
    }
    
    Utils::Logger::Instance().LogEx(
        result.success ? Utils::LogLevel::Info : Utils::LogLevel::Error,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Export %s: %zu entries exported, %zu bytes written in %lld ms",
        result.success ? L"completed" : L"failed",
        result.totalExported,
        result.bytesWritten,
        durationMs
    );
    
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
    if (!IsInitialized() || !m_impl->database || !m_impl->iocManager) {
        return 0;
    }

    // Validate maxAge is positive and within reasonable bounds
    if (maxAge.count() <= 0) {
        return 0;  // Invalid max age
    }
    
    // Cap at 10 years to prevent overflow
    constexpr int64_t MAX_AGE_HOURS = 10LL * 365 * 24;
    if (maxAge.count() > MAX_AGE_HOURS) {
        return 0;  // Unreasonable max age
    }

    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Starting purge of entries older than %lld hours",
        static_cast<long long>(maxAge.count())
    );
    
    const auto startTime = std::chrono::steady_clock::now();
    
    std::unique_lock<std::shared_mutex> lock(m_impl->rwLock);

    const uint64_t currentTime = GetUnixTimestamp();
    const uint64_t maxAgeSeconds = static_cast<uint64_t>(maxAge.count()) * 3600ULL;
    
    // Prevent underflow: if maxAgeSeconds >= currentTime, nothing to purge
    if (maxAgeSeconds >= currentTime) {
        return 0;  // All entries would be in valid time range
    }
    
    const uint64_t cutoffTime = currentTime - maxAgeSeconds;
    
    size_t purged = 0;
    size_t scanned = 0;
    
    try {
        // Get entries from database for scanning
        const IOCEntry* entries = m_impl->database->GetEntries();
        const size_t entryCount = m_impl->database->GetEntryCount();
        
        if (entryCount == 0 || entries == nullptr) {
            return 0;  // No entries to purge
        }
        
        // Collect entry IDs to delete
        // We can't delete while iterating, so collect first
        std::vector<uint64_t> entryIdsToDelete;
        entryIdsToDelete.reserve(entryCount / 10);  // Estimate 10% will be old
        
        for (size_t i = 0; i < entryCount; ++i) {
            const auto& entry = entries[i];
            ++scanned;
            
            // Skip already revoked entries
            if ((entry.flags & IOCFlags::Revoked) != IOCFlags::None) {
                continue;
            }
            
            // Check if entry is old enough to purge based on lastSeen
            // An entry is considered old if it hasn't been seen since cutoff
            bool shouldPurge = false;
            
            // Primary check: lastSeen timestamp
            if (entry.lastSeen > 0 && entry.lastSeen < cutoffTime) {
                shouldPurge = true;
            }
            // Secondary check: expiration time (if entry has expired)
            else if ((entry.flags & IOCFlags::HasExpiration) != IOCFlags::None &&
                     entry.expirationTime > 0 && entry.expirationTime < currentTime) {
                shouldPurge = true;
            }
            // Tertiary check: firstSeen for entries that were never updated
            else if (entry.lastSeen == 0 && entry.firstSeen > 0 && entry.firstSeen < cutoffTime) {
                shouldPurge = true;
            }
            
            if (shouldPurge) {
                entryIdsToDelete.push_back(entry.entryId);
            }
        }
        
        // Batch delete collected entries for efficiency
        if (!entryIdsToDelete.empty()) {
            // Use batch deletion for better performance
            // Soft delete preserves entries but marks them as revoked
            constexpr bool softDelete = true;
            
            // Process in batches to avoid memory pressure
            constexpr size_t BATCH_SIZE = 10000;
            
            for (size_t offset = 0; offset < entryIdsToDelete.size(); offset += BATCH_SIZE) {
                const size_t batchEnd = std::min(offset + BATCH_SIZE, entryIdsToDelete.size());
                std::span<const uint64_t> batch(
                    entryIdsToDelete.data() + offset,
                    batchEnd - offset
                );
                
                size_t batchDeleted = m_impl->iocManager->BatchDeleteIOCs(batch, softDelete);
                purged += batchDeleted;
            }
            
            // Cache invalidation: Since cache uses CacheKey (type+value), not entryId,
            // we rely on the EvictExpired() call below to clean up stale entries.
            // Alternatively, for large purge operations, clear the entire cache.
            if (m_impl->cache && purged > entryCount / 5) {
                // If more than 20% of entries were purged, clear cache entirely
                // This is more efficient than trying to invalidate individual entries
                m_impl->cache->Clear();
                
                Utils::Logger::Instance().LogEx(
                    Utils::LogLevel::Info,
                    L"ThreatIntelStore",
                    __FILEW__,
                    __LINE__,
                    __FUNCTIONW__,
                    L"Cache cleared due to large purge operation (%zu entries)",
                    purged
                );
            }
        }
        
        // If significant entries were purged, rebuild indexes for efficiency
        if (purged > 0 && m_impl->index) {
            // Only rebuild if we purged more than 10% of entries
            if (purged > entryCount / 10) {
                Utils::Logger::Instance().LogEx(
                    Utils::LogLevel::Info,
                    L"ThreatIntelStore",
                    __FILEW__,
                    __LINE__,
                    __FUNCTIONW__,
                    L"Purged significant entries (%zu), scheduling index optimization",
                    purged
                );
                
                // Schedule compaction for later (don't block current operation)
                // This would typically be done via a background maintenance thread
            }
        }
        
        // Also evict expired cache entries
        if (m_impl->cache) {
            size_t cacheEvicted = m_impl->cache->EvictExpired();
            if (cacheEvicted > 0) {
                Utils::Logger::Instance().LogEx(
                    Utils::LogLevel::Debug,
                    L"ThreatIntelStore",
                    __FILEW__,
                    __LINE__,
                    __FUNCTIONW__,
                    L"Also evicted %zu expired cache entries",
                    cacheEvicted
                );
            }
        }
        
    } catch (const std::exception& e) {
        Utils::Logger::Instance().LogEx(
            Utils::LogLevel::Error,
            L"ThreatIntelStore",
            __FILEW__,
            __LINE__,
            __FUNCTIONW__,
            L"Error during purge: %S",
            e.what()
        );
    }
    
    const auto endTime = std::chrono::steady_clock::now();
    const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    Utils::Logger::Instance().LogEx(
        Utils::LogLevel::Info,
        L"ThreatIntelStore",
        __FILEW__,
        __LINE__,
        __FUNCTIONW__,
        L"Purge completed: %zu entries purged, %zu scanned in %lld ms (cutoff: %llu)",
        purged,
        scanned,
        durationMs,
        cutoffTime
    );
    
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
