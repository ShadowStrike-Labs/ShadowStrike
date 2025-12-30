/**
 * @file ThreatIntelDatabase.hpp
 * @brief Memory-mapped database operations for Threat Intelligence Store
 *
 * This module provides low-level database operations:
 * - Memory-mapped file management
 * - Database creation and initialization
 * - File extension and remapping
 * - Integrity verification
 * - Flush and sync operations
 *
 * Uses Windows Memory-Mapped Files for zero-copy, nanosecond-level access.
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <string>
#include <string_view>
#include <memory>
#include <optional>
#include <atomic>
#include <shared_mutex>
#include <vector>

// Forward declare Windows types to avoid header pollution
struct _SECURITY_ATTRIBUTES;

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Constants
// ============================================================================

/// Default database alignment (4KB page size)
constexpr size_t DATABASE_PAGE_SIZE = 4096;

/// Minimum database size (1 MB)
constexpr size_t DATABASE_MIN_SIZE = 1024 * 1024;

/// Maximum database size (100 GB)
constexpr size_t DATABASE_MAX_SIZE = 100ULL * 1024 * 1024 * 1024;

/// Default initial database size (100 MB)
constexpr size_t DATABASE_DEFAULT_INITIAL_SIZE = 100 * 1024 * 1024;

/// Database growth increment (100 MB)
constexpr size_t DATABASE_GROWTH_INCREMENT = 100 * 1024 * 1024;

// ============================================================================
// Database Configuration
// ============================================================================

/**
 * @brief Configuration for database operations
 */
struct DatabaseConfig {
    /// Path to the database file
    std::wstring filePath;
    
    /// Initial size for new databases
    size_t initialSize = DATABASE_DEFAULT_INITIAL_SIZE;
    
    /// Maximum allowed database size (0 = unlimited up to DATABASE_MAX_SIZE)
    size_t maxSize = 0;
    
    /// Open in read-only mode
    bool readOnly = false;
    
    /// Create database if it doesn't exist
    bool createIfNotExists = true;
    
    /// Verify integrity on open
    bool verifyOnOpen = true;
    
    /// Enable write-ahead logging (WAL)
    bool enableWAL = false;
    
    /// WAL file path (empty = derive from filePath)
    std::wstring walPath;
    
    /// Pre-fault pages into memory on open
    bool prefaultPages = false;
    
    /// Use large pages if available (requires admin privileges)
    bool useLargePages = false;
    
    /**
     * @brief Create default configuration
     */
    static DatabaseConfig CreateDefault(const std::wstring& path) {
        DatabaseConfig config;
        config.filePath = path;
        return config;
    }
    
    /**
     * @brief Create high-performance configuration
     */
    static DatabaseConfig CreateHighPerformance(const std::wstring& path) {
        DatabaseConfig config;
        config.filePath = path;
        config.initialSize = 1024 * 1024 * 1024; // 1 GB
        config.prefaultPages = true;
        config.useLargePages = true;
        return config;
    }
    
    /**
     * @brief Create read-only configuration
     */
    static DatabaseConfig CreateReadOnly(const std::wstring& path) {
        DatabaseConfig config;
        config.filePath = path;
        config.readOnly = true;
        config.createIfNotExists = false;
        return config;
    }
};

// ============================================================================
// Database Statistics
// ============================================================================

/**
 * @brief Statistics for database operations
 */
struct DatabaseStats {
    /// Current mapped size in bytes
    size_t mappedSize = 0;
    
    /// Current file size on disk
    size_t fileSize = 0;
    
    /// Number of entries in database
    size_t entryCount = 0;
    
    /// Maximum entries capacity
    size_t maxEntries = 0;
    
    /// Number of times database was extended
    uint32_t extensionCount = 0;
    
    /// Number of flush operations
    uint32_t flushCount = 0;
    
    /// Total bytes written
    uint64_t totalBytesWritten = 0;
    
    /// Total bytes read
    uint64_t totalBytesRead = 0;
    
    /// Database creation timestamp
    uint64_t createdTimestamp = 0;
    
    /// Last modification timestamp
    uint64_t lastModifiedTimestamp = 0;
    
    /// Is database open
    bool isOpen = false;
    
    /// Is database read-only
    bool isReadOnly = false;
    
    /**
     * @brief Calculate fill percentage
     */
    [[nodiscard]] double FillPercentage() const noexcept {
        return maxEntries > 0 ? (static_cast<double>(entryCount) / maxEntries) * 100.0 : 0.0;
    }
};

// ============================================================================
// MappedRegion - Memory-mapped region handle
// ============================================================================

/**
 * @brief Represents a memory-mapped region of the database
 *
 * RAII wrapper for memory-mapped file views. Automatically unmaps
 * on destruction.
 */
class MappedRegion {
public:
    MappedRegion() = default;
    ~MappedRegion();
    
    // Non-copyable
    MappedRegion(const MappedRegion&) = delete;
    MappedRegion& operator=(const MappedRegion&) = delete;
    
    // Movable
    MappedRegion(MappedRegion&& other) noexcept;
    MappedRegion& operator=(MappedRegion&& other) noexcept;
    
    /**
     * @brief Check if region is valid
     */
    [[nodiscard]] bool IsValid() const noexcept { return m_baseAddress != nullptr; }
    
    /**
     * @brief Get base address of mapped region
     */
    [[nodiscard]] void* BaseAddress() const noexcept { return m_baseAddress; }
    
    /**
     * @brief Get size of mapped region
     */
    [[nodiscard]] size_t Size() const noexcept { return m_size; }
    
    /**
     * @brief Check if region is read-only
     */
    [[nodiscard]] bool IsReadOnly() const noexcept { return m_readOnly; }
    
    /**
     * @brief Get typed pointer to base address
     */
    template<typename T>
    [[nodiscard]] T* As() const noexcept {
        return static_cast<T*>(m_baseAddress);
    }
    
    /**
     * @brief Get typed pointer at offset
     */
    template<typename T>
    [[nodiscard]] T* At(size_t offset) const noexcept {
        if (offset + sizeof(T) > m_size) return nullptr;
        return reinterpret_cast<T*>(static_cast<uint8_t*>(m_baseAddress) + offset);
    }
    
    /**
     * @brief Flush region to disk
     */
    bool Flush(size_t offset = 0, size_t length = 0) noexcept;
    
    /**
     * @brief Close and unmap the region
     */
    void Close() noexcept;
    
private:
    friend class ThreatIntelDatabase;
    
    void* m_baseAddress = nullptr;
    size_t m_size = 0;
    bool m_readOnly = false;
    
    // Windows handles (stored as void* to avoid Windows.h in header)
    void* m_fileHandle = nullptr;
    void* m_mappingHandle = nullptr;
};

// ============================================================================
// ThreatIntelDatabase Class
// ============================================================================

/**
 * @brief Memory-mapped database for threat intelligence storage
 *
 * Provides high-performance, memory-mapped access to the threat intelligence
 * database. All operations are thread-safe with reader-writer locking.
 *
 * Usage:
 * @code
 * ThreatIntelDatabase db;
 * if (db.Open(DatabaseConfig::CreateDefault(L"threats.db"))) {
 *     auto* header = db.GetHeader();
 *     auto* entries = db.GetEntries();
 *     // ... use database
 *     db.Close();
 * }
 * @endcode
 */
class ThreatIntelDatabase {
public:
    ThreatIntelDatabase();
    ~ThreatIntelDatabase();
    
    // Non-copyable, non-movable
    ThreatIntelDatabase(const ThreatIntelDatabase&) = delete;
    ThreatIntelDatabase& operator=(const ThreatIntelDatabase&) = delete;
    ThreatIntelDatabase(ThreatIntelDatabase&&) = delete;
    ThreatIntelDatabase& operator=(ThreatIntelDatabase&&) = delete;
    
    // =========================================================================
    // Database Lifecycle
    // =========================================================================
    
    /**
     * @brief Open or create a database
     * @param config Database configuration
     * @return true if successful
     */
    [[nodiscard]] bool Open(const DatabaseConfig& config) noexcept;
    
    /**
     * @brief Open database with path only (default config)
     * @param path Database file path
     * @return true if successful
     */
    [[nodiscard]] bool Open(const std::wstring& path) noexcept;
    
    /**
     * @brief Close the database
     */
    void Close() noexcept;
    
    /**
     * @brief Check if database is open
     */
    [[nodiscard]] bool IsOpen() const noexcept;
    
    /**
     * @brief Check if database is read-only
     */
    [[nodiscard]] bool IsReadOnly() const noexcept;
    
    // =========================================================================
    // Database Access
    // =========================================================================
    
    /**
     * @brief Get database header (read-only)
     * @return Pointer to header or nullptr if not open
     */
    [[nodiscard]] const ThreatIntelDatabaseHeader* GetHeader() const noexcept;
    
    /**
     * @brief Get mutable database header
     * @return Pointer to header or nullptr if not open/read-only
     */
    [[nodiscard]] ThreatIntelDatabaseHeader* GetMutableHeader() noexcept;
    
    /**
     * @brief Get entries array (read-only)
     * @return Pointer to first entry or nullptr if not open
     */
    [[nodiscard]] const IOCEntry* GetEntries() const noexcept;
    
    /**
     * @brief Get mutable entries array
     * @return Pointer to first entry or nullptr if not open/read-only
     */
    [[nodiscard]] IOCEntry* GetMutableEntries() noexcept;
    
    /**
     * @brief Get entry at index
     * @param index Entry index
     * @return Pointer to entry or nullptr if out of bounds
     */
    [[nodiscard]] const IOCEntry* GetEntry(size_t index) const noexcept;
    
    /**
     * @brief Get mutable entry at index
     * @param index Entry index
     * @return Pointer to entry or nullptr if out of bounds/read-only
     */
    [[nodiscard]] IOCEntry* GetMutableEntry(size_t index) noexcept;
    
    /**
     * @brief Find an existing entry by value and type
     * @param value IOC value to search for
     * @param type IOC type to match
     * @return Index of found entry or SIZE_MAX if not found
     * 
     * @note This performs a linear scan of all entries.
     *       For large databases, use an index structure for O(1) lookup.
     *       Thread-safe with shared lock during iteration.
     */
    [[nodiscard]] size_t FindEntry(std::string_view value, IOCType type) const noexcept;
    
    /**
     * @brief Check if an entry with given value and type exists
     * @param value IOC value to check
     * @param type IOC type to match
     * @return true if entry exists
     */
    [[nodiscard]] bool HasEntry(std::string_view value, IOCType type) const noexcept {
        return FindEntry(value, type) != SIZE_MAX;
    }
    
    /**
     * @brief Add entry to deduplication index
     * @param index Index of the entry in the database
     * @param value IOC value for indexing
     * @param type IOC type for indexing
     * 
     * @note This is a placeholder for future hash-based index implementation.
     *       Currently a no-op as FindEntry uses linear scan.
     *       Enterprise deployments should implement a proper hash index
     *       using std::unordered_map<uint64_t, std::vector<size_t>> for O(1) lookup.
     */
    void AddToIndex(size_t index, std::string_view value, IOCType type) noexcept;
    
    /**
     * @brief Format IOCEntry value for index lookup
     * @param entry The IOC entry containing the value
     * @return String representation suitable for FindEntry/AddToIndex
     * 
     * This converts the union-based IOCValue to a string representation
     * that can be used with the hash-based index.
     */
    [[nodiscard]] static std::string FormatIOCValueForIndex(const IOCEntry& entry) noexcept;
    
    /**
     * @brief Find entry by IOCEntry (convenience overload)
     * @param entry Entry to search for
     * @return Index of found entry or SIZE_MAX if not found
     */
    [[nodiscard]] size_t FindEntry(const IOCEntry& entry) const noexcept;
    
    /**
     * @brief Get current entry count
     */
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    
    /**
     * @brief Get maximum entry capacity
     */
    [[nodiscard]] size_t GetMaxEntries() const noexcept;
    
    /**
     * @brief Get current mapped size
     */
    [[nodiscard]] size_t GetMappedSize() const noexcept;
    
    /**
     * @brief Get data offset (where entries begin)
     */
    [[nodiscard]] size_t GetDataOffset() const noexcept;
    
    // =========================================================================
    // Database Modification
    // =========================================================================
    
    /**
     * @brief Allocate space for a new entry
     * @return Index of new entry or SIZE_MAX if full
     *
     * Automatically extends database if needed and possible.
     */
    [[nodiscard]] size_t AllocateEntry() noexcept;
    
    /**
     * @brief Allocate space for multiple entries
     * @param count Number of entries to allocate
     * @return Starting index or SIZE_MAX if cannot allocate
     */
    [[nodiscard]] size_t AllocateEntries(size_t count) noexcept;
    
    /**
     * @brief Update entry count in header
     * @param count New entry count
     * @return true if successful
     */
    bool SetEntryCount(size_t count) noexcept;
    
    /**
     * @brief Increment entry count atomically
     * @return New entry count
     */
    size_t IncrementEntryCount() noexcept;
    
    // =========================================================================
    // Database Size Management
    // =========================================================================
    
    /**
     * @brief Extend database to new size
     * @param newSize New size in bytes (will be aligned to page size)
     * @return true if successful
     */
    [[nodiscard]] bool Extend(size_t newSize) noexcept;
    
    /**
     * @brief Extend database by a given amount
     * @param additionalBytes Additional bytes to add
     * @return true if successful
     */
    [[nodiscard]] bool ExtendBy(size_t additionalBytes) noexcept;
    
    /**
     * @brief Ensure capacity for at least N more entries
     * @param additionalEntries Number of additional entries needed
     * @return true if capacity is available
     */
    [[nodiscard]] bool EnsureCapacity(size_t additionalEntries) noexcept;
    
    /**
     * @brief Compact database by removing deleted entries
     * @return Number of bytes reclaimed
     */
    [[nodiscard]] size_t Compact() noexcept;
    
    // =========================================================================
    // Persistence Operations
    // =========================================================================
    
    /**
     * @brief Flush all changes to disk
     * @return true if successful
     */
    bool Flush() noexcept;
    
    /**
     * @brief Flush specific range to disk
     * @param offset Start offset
     * @param length Length to flush (0 = to end)
     * @return true if successful
     */
    bool FlushRange(size_t offset, size_t length) noexcept;
    
    /**
     * @brief Sync file to disk (fsync)
     * @return true if successful
     */
    bool Sync() noexcept;
    
    // =========================================================================
    // Integrity Operations
    // =========================================================================
    
    /**
     * @brief Verify database integrity
     * @return true if database is valid
     */
    [[nodiscard]] bool VerifyIntegrity() const noexcept;
    
    /**
     * @brief Verify header checksum
     * @return true if header is valid
     */
    [[nodiscard]] bool VerifyHeaderChecksum() const noexcept;
    
    /**
     * @brief Update header checksum
     * @return true if successful
     */
    bool UpdateHeaderChecksum() noexcept;
    
    /**
     * @brief Update last modified timestamp
     */
    void UpdateTimestamp() noexcept;
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    /**
     * @brief Get database statistics
     */
    [[nodiscard]] DatabaseStats GetStats() const noexcept;
    
    /**
     * @brief Get database file path
     */
    [[nodiscard]] const std::wstring& GetFilePath() const noexcept;
    
private:
    // =========================================================================
    // Private Implementation
    // =========================================================================
    
    /**
     * @brief Create a new database file
     */
    [[nodiscard]] bool CreateDatabase(const DatabaseConfig& config) noexcept;
    
    /**
     * @brief Open an existing database file
     */
    [[nodiscard]] bool OpenExisting(const DatabaseConfig& config) noexcept;
    
    /**
     * @brief Initialize header for new database
     */
    void InitializeHeader(size_t fileSize) noexcept;
    
    /**
     * @brief Remap the database after extension
     */
    [[nodiscard]] bool Remap(size_t newSize) noexcept;
    
    /**
     * @brief Align size to page boundary
     */
    [[nodiscard]] static size_t AlignToPage(size_t size) noexcept;
    
    /**
     * @brief Calculate maximum entries based on current mapped size
     * @return Maximum number of IOCEntry structures that can fit
     */
    [[nodiscard]] size_t CalculateMaxEntries() const noexcept;
    
    /**
     * @brief Internal integrity verification (caller must hold lock)
     */
    [[nodiscard]] bool VerifyIntegrityInternal() const noexcept;
    
    /**
     * @brief Internal header checksum verification (caller must hold lock)
     */
    [[nodiscard]] bool VerifyHeaderChecksumInternal() const noexcept;
    
    /**
     * @brief Compute hash key for value indexing
     * @param value IOC value string
     * @param type IOC type for disambiguation
     * @return 64-bit hash key using FNV-1a algorithm
     */
    [[nodiscard]] static uint64_t ComputeIndexHash(std::string_view value, IOCType type) noexcept;
    
    /**
     * @brief Load hash index from database memory
     * Called after Open() to rebuild in-memory index
     */
    void RebuildHashIndex() noexcept;
    
    // =========================================================================
    // Member Variables
    // =========================================================================
    
    /// Current configuration
    DatabaseConfig m_config;
    
    /// Mapped region
    MappedRegion m_region;
    
    /// Header pointer (cached)
    ThreatIntelDatabaseHeader* m_header = nullptr;
    
    /// Entries pointer (cached)
    IOCEntry* m_entries = nullptr;
    
    /// Is database open
    std::atomic<bool> m_isOpen{false};
    
    /// Read-write lock for thread safety
    mutable std::shared_mutex m_mutex;
    
    /// Statistics
    mutable DatabaseStats m_stats;
    
    // =========================================================================
    // ENTERPRISE-GRADE HASH INDEX FOR O(1) LOOKUPS
    // =========================================================================
    
    /**
     * @brief Hash bucket entry for collision chain
     * 
     * Uses separate chaining for collision resolution.
     * Each bucket contains indices of entries with matching hash.
     */
    struct HashBucketEntry {
        size_t entryIndex;          ///< Index into m_entries array
        uint64_t fullHash;          ///< Full 64-bit hash for verification
    };
    
    /// Number of hash buckets (power of 2 for fast modulo)
    static constexpr size_t HASH_BUCKET_COUNT = 65536;  // 64K buckets
    
    /// Maximum entries per bucket before warning
    static constexpr size_t MAX_BUCKET_DEPTH = 100;
    
    /**
     * @brief In-memory hash index for O(1) average lookup
     * 
     * Maps: hash(value + type) % HASH_BUCKET_COUNT -> list of entry indices
     * 
     * Memory overhead: ~8 bytes per entry for index storage
     * Lookup complexity: O(1) average, O(n/BUCKET_COUNT) worst case
     */
    std::vector<std::vector<HashBucketEntry>> m_hashIndex;
    
    /// Flag indicating if hash index is built
    bool m_hashIndexBuilt = false;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Check if a database file exists
 */
[[nodiscard]] bool DatabaseFileExists(const std::wstring& path) noexcept;

/**
 * @brief Delete a database file
 */
[[nodiscard]] bool DeleteDatabaseFile(const std::wstring& path) noexcept;

/**
 * @brief Get database file size
 */
[[nodiscard]] std::optional<size_t> GetDatabaseFileSize(const std::wstring& path) noexcept;

/**
 * @brief Create a backup of the database
 */
[[nodiscard]] bool BackupDatabase(const std::wstring& sourcePath, 
                                   const std::wstring& backupPath) noexcept;

} // namespace ThreatIntel
} // namespace ShadowStrike
