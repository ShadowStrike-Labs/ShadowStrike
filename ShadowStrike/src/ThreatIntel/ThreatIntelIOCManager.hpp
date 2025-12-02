/*
 * ============================================================================
 * ShadowStrike ThreatIntelIOCManager - ENTERPRISE-GRADE IOC MANAGEMENT
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade IOC (Indicator of Compromise) Manager for the ShadowStrike
 * Threat Intelligence platform. Provides unified management interface for all
 * IOC operations with CrowdStrike Falcon / Microsoft Defender ATP quality.
 *
 * Key Features:
 * - Unified IOC CRUD operations with atomic transactions
 * - Batch insert/update/delete with sub-millisecond performance
 * - Automatic deduplication and conflict resolution
 * - TTL (Time-To-Live) management and automatic expiration
 * - Relationship tracking between related IOCs
 * - Version control and audit logging for compliance
 * - STIX 2.1 bundle support for industry interoperability
 * - Real-time validation and normalization
 * - Multi-threaded batch operations with lock-free reads
 *
 * Performance Targets:
 * - Single IOC add: <500ns average
 * - Batch IOC add (1000 items): <5ms total
 * - IOC update: <300ns average
 * - IOC delete: <200ns average
 * - Deduplication check: <100ns average (bloom filter + hash table)
 * - Relationship query: <1µs average
 * - Version history query: <2µs average
 *
 * Thread Safety:
 * - Lock-free reads for maximum throughput
 * - Copy-on-write (COW) for modifications
 * - MVCC (Multi-Version Concurrency Control) for consistency
 * - Atomic operations for counters and flags
 *
 * Architecture:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │ ThreatIntelIOCManager (Main Facade)                                    │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ - IOC Lifecycle Management (Add/Update/Delete)                         │
 * │ - Deduplication Engine (Bloom Filter + Hash Table)                     │
 * │ - TTL Manager (Automatic Expiration)                                   │
 * │ - Relationship Graph (Related IOC tracking)                            │
 * │ - Version Control System (Audit Trail)                                 │
 * │ - Batch Processor (Parallel Operations)                                │
 * │ - Validation Engine (Real-time Checking)                               │
 * │ - Normalization Engine (Canonical Form)                                │
 * │ - STIX Converter (STIX 2.1 Import/Export)                              │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * - ThreatIntelStore: Main storage interface
 * - ThreatIntelDatabase: Low-level database operations
 * - ThreatIntelIndex: Fast lookup operations
 * - ThreatIntelFeedManager: Feed integration
 *
 * This module is designed for billion-dollar enterprise deployments at
 * Microsoft, Google, Apple, Amazon scale. Do not underestimate the
 * quality requirements. Every line must meet CrowdStrike Falcon standards.
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include "ThreatIntelDatabase.hpp"

#include <atomic>
#include <chrono>
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

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ThreatIntelIOCManager;
class IOCValidator;
class IOCNormalizer;
class IOCDeduplicator;
class IOCRelationshipGraph;
class IOCVersionControl;
class STIXConverter;

// ============================================================================
// IOC OPERATION RESULT
// ============================================================================

/**
 * @brief Result of an IOC management operation
 */
struct IOCOperationResult {
    /// @brief Success flag
    bool success{false};
    
    /// @brief Entry ID (for successful operations)
    uint64_t entryId{0};
    
    /// @brief Error code
    ThreatIntelError errorCode{ThreatIntelError::Success};
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Affected entry count (for batch operations)
    uint32_t affectedCount{0};
    
    /// @brief Operation duration in nanoseconds
    uint64_t durationNs{0};
    
    /// @brief Was entry a duplicate
    bool wasDuplicate{false};
    
    /// @brief Was entry updated (vs created)
    bool wasUpdated{false};
    
    /// @brief Factory for success
    [[nodiscard]] static IOCOperationResult Success(uint64_t id = 0) noexcept {
        IOCOperationResult result;
        result.success = true;
        result.entryId = id;
        return result;
    }
    
    /// @brief Factory for error
    [[nodiscard]] static IOCOperationResult Error(
        ThreatIntelError code,
        std::string_view message
    ) noexcept {
        IOCOperationResult result;
        result.success = false;
        result.errorCode = code;
        result.errorMessage = message;
        return result;
    }
    
    /// @brief Factory for duplicate
    [[nodiscard]] static IOCOperationResult Duplicate(uint64_t existingId) noexcept {
        IOCOperationResult result;
        result.success = true;
        result.entryId = existingId;
        result.wasDuplicate = true;
        return result;
    }
};

// ============================================================================
// IOC ADD/UPDATE OPTIONS
// ============================================================================

/**
 * @brief Options for adding or updating IOCs
 */
struct IOCAddOptions {
    /// @brief Overwrite existing entry if duplicate found
    bool overwriteIfExists{true};
    
    /// @brief Update entry if exists (merge metadata)
    bool updateIfExists{true};
    
    /// @brief Skip validation (use with caution)
    bool skipValidation{false};
    
    /// @brief Skip normalization
    bool skipNormalization{false};
    
    /// @brief Skip deduplication check
    bool skipDeduplication{false};
    
    /// @brief Auto-generate entry ID
    bool autoGenerateId{true};
    
    /// @brief Apply TTL (Time-To-Live)
    bool applyTTL{true};
    
    /// @brief Default TTL in seconds (0 = use system default)
    uint32_t defaultTTL{0};
    
    /// @brief Update relationship graph
    bool updateRelationships{true};
    
    /// @brief Create audit log entry
    bool createAuditLog{true};
    
    /// @brief Conflict resolution strategy
    enum class ConflictStrategy : uint8_t {
        KeepExisting,      ///< Keep existing entry, ignore new
        ReplaceWithNew,    ///< Replace with new entry
        MergeMetadata,     ///< Merge metadata, prefer newer
        PreferHigherRep,   ///< Prefer entry with higher reputation
        PreferMoreSources  ///< Prefer entry with more sources
    } conflictStrategy{ConflictStrategy::MergeMetadata};
    
    /**
     * @brief Create default options
     */
    [[nodiscard]] static IOCAddOptions Default() noexcept {
        return IOCAddOptions{};
    }
    
    /**
     * @brief Create fast options (skip validation/normalization)
     */
    [[nodiscard]] static IOCAddOptions Fast() noexcept {
        IOCAddOptions opts;
        opts.skipValidation = true;
        opts.skipNormalization = true;
        opts.createAuditLog = false;
        return opts;
    }
    
    /**
     * @brief Create strict options (full validation)
     */
    [[nodiscard]] static IOCAddOptions Strict() noexcept {
        IOCAddOptions opts;
        opts.overwriteIfExists = false;
        opts.updateIfExists = false;
        opts.skipValidation = false;
        opts.skipNormalization = false;
        opts.skipDeduplication = false;
        return opts;
    }
};

/**
 * @brief Options for batch IOC operations
 */
struct IOCBatchOptions {
    /// @brief Base add options for each entry
    IOCAddOptions addOptions;
    
    /// @brief Stop on first error
    bool stopOnError{false};
    
    /// @brief Parallel processing (multi-threaded)
    bool parallel{true};
    
    /// @brief Number of worker threads (0 = auto-detect)
    uint32_t workerThreads{0};
    
    /// @brief Progress callback (processed, total)
    std::function<void(size_t, size_t)> progressCallback;
    
    /// @brief Error callback (index, error)
    std::function<void(size_t, const IOCOperationResult&)> errorCallback;
    
    /// @brief Batch size for chunking
    size_t chunkSize{1000};
    
    /// @brief Sort entries before processing (improves locality)
    bool sortBeforeProcessing{true};
    
    /**
     * @brief Create default batch options
     */
    [[nodiscard]] static IOCBatchOptions Default() noexcept {
        return IOCBatchOptions{};
    }
    
    /**
     * @brief Create high-throughput options
     */
    [[nodiscard]] static IOCBatchOptions HighThroughput() noexcept {
        IOCBatchOptions opts;
        opts.addOptions = IOCAddOptions::Fast();
        opts.parallel = true;
        opts.stopOnError = false;
        opts.sortBeforeProcessing = true;
        return opts;
    }
};

// ============================================================================
// IOC QUERY OPTIONS
// ============================================================================

/**
 * @brief Options for querying IOCs
 */
struct IOCQueryOptions {
    /// @brief Include expired entries
    bool includeExpired{false};
    
    /// @brief Include revoked entries
    bool includeRevoked{false};
    
    /// @brief Include disabled entries
    bool includeDisabled{false};
    
    /// @brief Minimum reputation level
    ReputationLevel minReputation{ReputationLevel::Unknown};
    
    /// @brief Minimum confidence level
    ConfidenceLevel minConfidence{ConfidenceLevel::None};
    
    /// @brief Filter by source (0 = any)
    ThreatIntelSource sourceFilter{ThreatIntelSource::Unknown};
    
    /// @brief Filter by category (0 = any)
    ThreatCategory categoryFilter{ThreatCategory::Unknown};
    
    /// @brief Maximum results (0 = unlimited)
    uint32_t maxResults{0};
    
    /// @brief Include full entry data
    bool includeFullEntry{true};
    
    /// @brief Include related IOCs
    bool includeRelated{false};
    
    /// @brief Include version history
    bool includeVersionHistory{false};
    
    /**
     * @brief Create default query options
     */
    [[nodiscard]] static IOCQueryOptions Default() noexcept {
        return IOCQueryOptions{};
    }
    
    /**
     * @brief Create active-only query
     */
    [[nodiscard]] static IOCQueryOptions ActiveOnly() noexcept {
        IOCQueryOptions opts;
        opts.includeExpired = false;
        opts.includeRevoked = false;
        opts.includeDisabled = false;
        return opts;
    }
};

// ============================================================================
// IOC RELATIONSHIP
// ============================================================================

/**
 * @brief Relationship type between IOCs
 */
enum class IOCRelationType : uint8_t {
    Unknown = 0,
    
    // Hierarchical relationships
    ParentOf,              ///< This IOC is parent of target
    ChildOf,               ///< This IOC is child of target
    
    // Association relationships
    RelatedTo,             ///< General association
    SameFamily,            ///< Same malware family
    SameCampaign,          ///< Same threat campaign
    SameActor,             ///< Same threat actor
    
    // Network relationships
    ConnectsTo,            ///< Network connection
    ResolvesTo,            ///< DNS resolution
    HostedOn,              ///< Hosted on infrastructure
    ServedBy,              ///< Served by C2
    
    // File relationships
    DroppedBy,             ///< Dropped by malware
    Downloads,             ///< Downloads other malware
    Executes,              ///< Executes another file
    
    // Context relationships
    IndicatesPresenceOf,   ///< Indicates presence
    PrerequisiteOf,        ///< Prerequisite for attack
    FollowedBy,            ///< Temporal sequence
    
    // STIX relationships
    Uses,                  ///< Uses (STIX relationship)
    Targets,               ///< Targets (STIX relationship)
    Impersonates,          ///< Impersonates (STIX relationship)
    OriginatesFrom,        ///< Originates from (STIX relationship)
    BasedOn,               ///< Based on (STIX relationship)
    DerivedFrom,           ///< Derived from (STIX relationship)
    DuplicateOf,           ///< Duplicate of (STIX relationship)
    
    Custom = 255           ///< Custom relationship type
};

/**
 * @brief Relationship between two IOCs
 */
struct IOCRelationship {
    /// @brief Source entry ID
    uint64_t sourceEntryId{0};
    
    /// @brief Target entry ID
    uint64_t targetEntryId{0};
    
    /// @brief Relationship type
    IOCRelationType relationType{IOCRelationType::Unknown};
    
    /// @brief Confidence of relationship
    ConfidenceLevel confidence{ConfidenceLevel::None};
    
    /// @brief Description (optional)
    std::string description;
    
    /// @brief Relationship weight (for graph algorithms)
    float weight{1.0f};
    
    /// @brief Creation timestamp
    uint64_t createdTime{0};
    
    /// @brief Source of relationship information
    ThreatIntelSource source{ThreatIntelSource::Unknown};
};

// ============================================================================
// IOC VERSION ENTRY
// ============================================================================

/**
 * @brief Version history entry for an IOC
 */
struct IOCVersionEntry {
    /// @brief Version number (monotonically increasing)
    uint32_t version{0};
    
    /// @brief Entry ID
    uint64_t entryId{0};
    
    /// @brief Timestamp of this version
    uint64_t timestamp{0};
    
    /// @brief User/system that made the change
    std::string modifiedBy;
    
    /// @brief Change description
    std::string changeDescription;
    
    /// @brief Previous reputation
    ReputationLevel previousReputation{ReputationLevel::Unknown};
    
    /// @brief New reputation
    ReputationLevel newReputation{ReputationLevel::Unknown};
    
    /// @brief Operation type (Created/Updated/Deleted)
    enum class OperationType : uint8_t {
        Created,
        Updated,
        Deleted,
        Restored
    } operationType{OperationType::Created};
    
    /// @brief Full entry snapshot (optional, for point-in-time recovery)
    std::optional<IOCEntry> entrySnapshot;
};

// ============================================================================
// IOC STATISTICS
// ============================================================================

/**
 * @brief Statistics for IOC management operations
 */
struct IOCManagerStatistics {
    // Entry counts by type
    std::atomic<uint64_t> totalEntries{0};
    std::atomic<uint64_t> activeEntries{0};
    std::atomic<uint64_t> expiredEntries{0};
    std::atomic<uint64_t> revokedEntries{0};
    
    // Operation counts
    std::atomic<uint64_t> totalAdds{0};
    std::atomic<uint64_t> totalUpdates{0};
    std::atomic<uint64_t> totalDeletes{0};
    std::atomic<uint64_t> totalQueries{0};
    
    // Deduplication statistics
    std::atomic<uint64_t> duplicatesDetected{0};
    std::atomic<uint64_t> duplicatesMerged{0};
    
    // Performance statistics (nanoseconds)
    std::atomic<uint64_t> totalOperationTimeNs{0};
    std::atomic<uint64_t> minOperationTimeNs{UINT64_MAX};
    std::atomic<uint64_t> maxOperationTimeNs{0};
    
    // Relationship statistics
    std::atomic<uint64_t> totalRelationships{0};
    std::atomic<uint64_t> relationshipQueriesTotal{0};
    
    // Version control statistics
    std::atomic<uint64_t> totalVersions{0};
    std::atomic<uint64_t> versionQueries{0};
    
    // Batch operation statistics
    std::atomic<uint64_t> batchOperations{0};
    std::atomic<uint64_t> batchEntriesProcessed{0};
    std::atomic<uint64_t> batchErrors{0};
    
    // Validation statistics
    std::atomic<uint64_t> validationErrors{0};
    std::atomic<uint64_t> normalizationApplied{0};
    
    // Copy constructor - manually copy atomic members
    IOCManagerStatistics() = default;
    
    IOCManagerStatistics(const IOCManagerStatistics& other) noexcept
        : totalEntries(other.totalEntries.load(std::memory_order_relaxed))
        , activeEntries(other.activeEntries.load(std::memory_order_relaxed))
        , expiredEntries(other.expiredEntries.load(std::memory_order_relaxed))
        , revokedEntries(other.revokedEntries.load(std::memory_order_relaxed))
        , totalAdds(other.totalAdds.load(std::memory_order_relaxed))
        , totalUpdates(other.totalUpdates.load(std::memory_order_relaxed))
        , totalDeletes(other.totalDeletes.load(std::memory_order_relaxed))
        , totalQueries(other.totalQueries.load(std::memory_order_relaxed))
        , duplicatesDetected(other.duplicatesDetected.load(std::memory_order_relaxed))
        , duplicatesMerged(other.duplicatesMerged.load(std::memory_order_relaxed))
        , totalOperationTimeNs(other.totalOperationTimeNs.load(std::memory_order_relaxed))
        , minOperationTimeNs(other.minOperationTimeNs.load(std::memory_order_relaxed))
        , maxOperationTimeNs(other.maxOperationTimeNs.load(std::memory_order_relaxed))
        , totalRelationships(other.totalRelationships.load(std::memory_order_relaxed))
        , relationshipQueriesTotal(other.relationshipQueriesTotal.load(std::memory_order_relaxed))
        , totalVersions(other.totalVersions.load(std::memory_order_relaxed))
        , versionQueries(other.versionQueries.load(std::memory_order_relaxed))
        , batchOperations(other.batchOperations.load(std::memory_order_relaxed))
        , batchEntriesProcessed(other.batchEntriesProcessed.load(std::memory_order_relaxed))
        , batchErrors(other.batchErrors.load(std::memory_order_relaxed))
        , validationErrors(other.validationErrors.load(std::memory_order_relaxed))
        , normalizationApplied(other.normalizationApplied.load(std::memory_order_relaxed))
    {}
    
    /**
     * @brief Calculate average operation time
     */
    [[nodiscard]] uint64_t AverageOperationTimeNs() const noexcept {
        const uint64_t total = totalAdds + totalUpdates + totalDeletes;
        return total > 0 ? totalOperationTimeNs.load() / total : 0;
    }
    
    /**
     * @brief Calculate deduplication rate
     */
    [[nodiscard]] double DeduplicationRate() const noexcept {
        const uint64_t total = totalAdds.load();
        return total > 0 ? 
            static_cast<double>(duplicatesDetected.load()) / total : 0.0;
    }
};

// ============================================================================
// IOC BULK IMPORT RESULT
// ============================================================================

/**
 * @brief Result of a bulk import operation
 */
struct IOCBulkImportResult {
    /// @brief Total entries processed
    size_t totalProcessed{0};
    
    /// @brief Successfully added
    size_t successCount{0};
    
    /// @brief Updated existing entries
    size_t updatedCount{0};
    
    /// @brief Skipped (duplicates)
    size_t skippedCount{0};
    
    /// @brief Failed validation
    size_t failedCount{0};
    
    /// @brief Total duration
    std::chrono::milliseconds duration{0};
    
    /// @brief Individual results (optional, for debugging)
    std::vector<IOCOperationResult> results;
    
    /// @brief Error summary
    std::unordered_map<ThreatIntelError, uint32_t> errorCounts;
    
    /**
     * @brief Calculate success rate
     */
    [[nodiscard]] double SuccessRate() const noexcept {
        return totalProcessed > 0 ?
            static_cast<double>(successCount) / totalProcessed : 0.0;
    }
    
    /**
     * @brief Calculate throughput (entries per second)
     */
    [[nodiscard]] double Throughput() const noexcept {
        if (duration.count() == 0) return 0.0;
        return (static_cast<double>(totalProcessed) / duration.count()) * 1000.0;
    }
};

// ============================================================================
// THREATINTELIOCMANAGER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade IOC Manager
 *
 * Main facade for all IOC management operations. Thread-safe with lock-free
 * reads and COW writes. Optimized for high-throughput batch operations.
 *
 * Usage:
 * @code
 * ThreatIntelIOCManager manager;
 * if (manager.Initialize(database, index)) {
 *     // Add single IOC
 *     IOCEntry entry = CreateMaliciousIPEntry("192.168.1.100");
 *     auto result = manager.AddIOC(entry);
 *     
 *     // Batch add
 *     std::vector<IOCEntry> entries = LoadIOCsFromFeed();
 *     auto batchResult = manager.BatchAddIOCs(entries);
 *     
 *     // Query relationships
 *     auto related = manager.GetRelatedIOCs(entryId);
 * }
 * @endcode
 */
class ThreatIntelIOCManager final {
public:
    /**
     * @brief Constructor
     */
    ThreatIntelIOCManager();
    
    /**
     * @brief Destructor
     */
    ~ThreatIntelIOCManager();
    
    // Non-copyable, non-movable
    ThreatIntelIOCManager(const ThreatIntelIOCManager&) = delete;
    ThreatIntelIOCManager& operator=(const ThreatIntelIOCManager&) = delete;
    ThreatIntelIOCManager(ThreatIntelIOCManager&&) = delete;
    ThreatIntelIOCManager& operator=(ThreatIntelIOCManager&&) = delete;
    
    // =========================================================================
    // INITIALIZATION
    // =========================================================================
    
    /**
     * @brief Initialize the IOC manager
     * @param database Database instance
     * @return Success status
     */
    [[nodiscard]] StoreError Initialize(
        ThreatIntelDatabase* database
    ) noexcept;
    
    /**
     * @brief Check if manager is initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Shutdown the manager
     */
    void Shutdown() noexcept;
    
    // =========================================================================
    // IOC LIFECYCLE - SINGLE OPERATIONS
    // =========================================================================
    
    /**
     * @brief Add a new IOC entry
     * @param entry IOC entry to add
     * @param options Add options
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult AddIOC(
        const IOCEntry& entry,
        const IOCAddOptions& options = IOCAddOptions::Default()
    ) noexcept;
    
    /**
     * @brief Update an existing IOC entry
     * @param entry Updated IOC entry
     * @param options Update options
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult UpdateIOC(
        const IOCEntry& entry,
        const IOCAddOptions& options = IOCAddOptions::Default()
    ) noexcept;
    
    /**
     * @brief Delete an IOC entry by ID
     * @param entryId Entry ID to delete
     * @param softDelete Soft delete (mark as revoked) vs hard delete
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult DeleteIOC(
        uint64_t entryId,
        bool softDelete = true
    ) noexcept;
    
    /**
     * @brief Delete an IOC entry by type and value
     * @param type IOC type
     * @param value IOC value
     * @param softDelete Soft delete vs hard delete
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult DeleteIOC(
        IOCType type,
        std::string_view value,
        bool softDelete = true
    ) noexcept;
    
    /**
     * @brief Restore a soft-deleted IOC
     * @param entryId Entry ID to restore
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult RestoreIOC(uint64_t entryId) noexcept;
    
    // =========================================================================
    // IOC LIFECYCLE - BATCH OPERATIONS
    // =========================================================================
    
    /**
     * @brief Batch add multiple IOCs
     * @param entries IOC entries to add
     * @param options Batch options
     * @return Bulk import result
     */
    [[nodiscard]] IOCBulkImportResult BatchAddIOCs(
        std::span<const IOCEntry> entries,
        const IOCBatchOptions& options = IOCBatchOptions::Default()
    ) noexcept;
    
    /**
     * @brief Batch update multiple IOCs
     * @param entries Updated IOC entries
     * @param options Batch options
     * @return Bulk import result
     */
    [[nodiscard]] IOCBulkImportResult BatchUpdateIOCs(
        std::span<const IOCEntry> entries,
        const IOCBatchOptions& options = IOCBatchOptions::Default()
    ) noexcept;
    
    /**
     * @brief Batch delete multiple IOCs by ID
     * @param entryIds Entry IDs to delete
     * @param softDelete Soft delete vs hard delete
     * @return Number of entries deleted
     */
    [[nodiscard]] size_t BatchDeleteIOCs(
        std::span<const uint64_t> entryIds,
        bool softDelete = true
    ) noexcept;
    
    // =========================================================================
    // IOC QUERY OPERATIONS
    // =========================================================================
    
    /**
     * @brief Get IOC entry by ID
     * @param entryId Entry ID
     * @param options Query options
     * @return IOC entry if found
     */
    [[nodiscard]] std::optional<IOCEntry> GetIOC(
        uint64_t entryId,
        const IOCQueryOptions& options = IOCQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Find IOC by type and value
     * @param type IOC type
     * @param value IOC value
     * @param options Query options
     * @return IOC entry if found
     */
    [[nodiscard]] std::optional<IOCEntry> FindIOC(
        IOCType type,
        std::string_view value,
        const IOCQueryOptions& options = IOCQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Query IOCs by criteria
     * @param options Query options
     * @return Vector of matching IOC entries
     */
    [[nodiscard]] std::vector<IOCEntry> QueryIOCs(
        const IOCQueryOptions& options
    ) const noexcept;
    
    /**
     * @brief Check if IOC exists
     * @param type IOC type
     * @param value IOC value
     * @return true if IOC exists
     */
    [[nodiscard]] bool ExistsIOC(
        IOCType type,
        std::string_view value
    ) const noexcept;
    
    /**
     * @brief Get total IOC count
     * @param includeExpired Include expired entries
     * @param includeRevoked Include revoked entries
     * @return Total count
     */
    [[nodiscard]] size_t GetIOCCount(
        bool includeExpired = false,
        bool includeRevoked = false
    ) const noexcept;
    
    // =========================================================================
    // RELATIONSHIP MANAGEMENT
    // =========================================================================
    
    /**
     * @brief Add relationship between two IOCs
     * @param sourceId Source IOC entry ID
     * @param targetId Target IOC entry ID
     * @param relationType Relationship type
     * @param confidence Confidence level
     * @return true if added successfully
     */
    [[nodiscard]] bool AddRelationship(
        uint64_t sourceId,
        uint64_t targetId,
        IOCRelationType relationType,
        ConfidenceLevel confidence = ConfidenceLevel::Medium
    ) noexcept;
    
    /**
     * @brief Remove relationship
     * @param sourceId Source IOC entry ID
     * @param targetId Target IOC entry ID
     * @param relationType Relationship type (optional, 0 = remove all)
     * @return true if removed
     */
    [[nodiscard]] bool RemoveRelationship(
        uint64_t sourceId,
        uint64_t targetId,
        IOCRelationType relationType = IOCRelationType::Unknown
    ) noexcept;
    
    /**
     * @brief Get all relationships for an IOC
     * @param entryId Entry ID
     * @return Vector of relationships
     */
    [[nodiscard]] std::vector<IOCRelationship> GetRelationships(
        uint64_t entryId
    ) const noexcept;
    
    /**
     * @brief Get related IOCs
     * @param entryId Entry ID
     * @param relationType Filter by relationship type (0 = all)
     * @param maxDepth Maximum traversal depth (1 = direct only)
     * @return Vector of related IOC entry IDs
     */
    [[nodiscard]] std::vector<uint64_t> GetRelatedIOCs(
        uint64_t entryId,
        IOCRelationType relationType = IOCRelationType::Unknown,
        uint32_t maxDepth = 1
    ) const noexcept;
    
    /**
     * @brief Find shortest path between two IOCs
     * @param sourceId Source IOC
     * @param targetId Target IOC
     * @return Vector of entry IDs forming the path (empty if no path)
     */
    [[nodiscard]] std::vector<uint64_t> FindPath(
        uint64_t sourceId,
        uint64_t targetId
    ) const noexcept;
    
    // =========================================================================
    // VERSION CONTROL
    // =========================================================================
    
    /**
     * @brief Get version history for an IOC
     * @param entryId Entry ID
     * @param maxVersions Maximum versions to return (0 = all)
     * @return Vector of version entries
     */
    [[nodiscard]] std::vector<IOCVersionEntry> GetVersionHistory(
        uint64_t entryId,
        uint32_t maxVersions = 0
    ) const noexcept;
    
    /**
     * @brief Get IOC at specific version
     * @param entryId Entry ID
     * @param version Version number
     * @return IOC entry at that version if found
     */
    [[nodiscard]] std::optional<IOCEntry> GetIOCVersion(
        uint64_t entryId,
        uint32_t version
    ) const noexcept;
    
    /**
     * @brief Revert IOC to previous version
     * @param entryId Entry ID
     * @param version Version to revert to
     * @return Operation result
     */
    [[nodiscard]] IOCOperationResult RevertIOC(
        uint64_t entryId,
        uint32_t version
    ) noexcept;
    
    // =========================================================================
    // TTL MANAGEMENT
    // =========================================================================
    
    /**
     * @brief Set TTL for an IOC
     * @param entryId Entry ID
     * @param ttlSeconds TTL in seconds
     * @return true if successful
     */
    [[nodiscard]] bool SetIOCTTL(
        uint64_t entryId,
        uint32_t ttlSeconds
    ) noexcept;
    
    /**
     * @brief Renew TTL for an IOC
     * @param entryId Entry ID
     * @param additionalSeconds Additional seconds to add
     * @return true if successful
     */
    [[nodiscard]] bool RenewIOCTTL(
        uint64_t entryId,
        uint32_t additionalSeconds
    ) noexcept;
    
    /**
     * @brief Remove all expired IOCs
     * @return Number of expired IOCs removed
     */
    [[nodiscard]] size_t PurgeExpiredIOCs() noexcept;
    
    /**
     * @brief Get expiring IOCs
     * @param withinSeconds Get IOCs expiring within N seconds
     * @return Vector of entry IDs
     */
    [[nodiscard]] std::vector<uint64_t> GetExpiringIOCs(
        uint32_t withinSeconds = 3600
    ) const noexcept;
    
    // =========================================================================
    // VALIDATION & NORMALIZATION
    // =========================================================================
    
    /**
     * @brief Validate an IOC entry
     * @param entry IOC entry to validate
     * @param errorMessage Output error message if validation fails
     * @return true if valid
     */
    [[nodiscard]] bool ValidateIOC(
        const IOCEntry& entry,
        std::string& errorMessage
    ) const noexcept;
    
    /**
     * @brief Normalize an IOC value
     * @param type IOC type
     * @param value IOC value
     * @return Normalized value
     */
    [[nodiscard]] std::string NormalizeIOCValue(
        IOCType type,
        std::string_view value
    ) const noexcept;
    
    /**
     * @brief Parse and validate IOC value
     * @param type IOC type
     * @param value IOC value
     * @param entry Output IOC entry
     * @return true if parsing succeeded
     */
    [[nodiscard]] bool ParseIOC(
        IOCType type,
        std::string_view value,
        IOCEntry& entry
    ) const noexcept;
    
    // =========================================================================
    // DEDUPLICATION
    // =========================================================================
    
    /**
     * @brief Check for duplicate IOC
     * @param type IOC type
     * @param value IOC value
     * @return Entry ID of duplicate if found
     */
    [[nodiscard]] std::optional<uint64_t> FindDuplicate(
        IOCType type,
        std::string_view value
    ) const noexcept;
    
    /**
     * @brief Merge duplicate IOCs
     * @param keepEntryId Entry ID to keep
     * @param mergeEntryId Entry ID to merge and delete
     * @return true if merged successfully
     */
    [[nodiscard]] bool MergeDuplicates(
        uint64_t keepEntryId,
        uint64_t mergeEntryId
    ) noexcept;
    
    /**
     * @brief Find all duplicate IOCs in database
     * @return Map of duplicate groups (canonical ID -> duplicate IDs)
     */
    [[nodiscard]] std::unordered_map<uint64_t, std::vector<uint64_t>>
    FindAllDuplicates() const noexcept;
    
    /**
     * @brief Auto-merge all duplicates
     * @param dryRun Preview only, don't actually merge
     * @return Number of duplicates merged
     */
    [[nodiscard]] size_t AutoMergeDuplicates(bool dryRun = false) noexcept;
    
    // =========================================================================
    // STIX SUPPORT
    // =========================================================================
    
    /**
     * @brief Import IOCs from STIX 2.1 bundle
     * @param stixBundle STIX bundle JSON
     * @param options Batch options
     * @return Import result
     */
    [[nodiscard]] IOCBulkImportResult ImportSTIXBundle(
        std::string_view stixBundle,
        const IOCBatchOptions& options = IOCBatchOptions::Default()
    ) noexcept;
    
    /**
     * @brief Export IOCs to STIX 2.1 bundle
     * @param entryIds Entry IDs to export (empty = all)
     * @param options Query options for filtering
     * @return STIX bundle JSON
     */
    [[nodiscard]] std::string ExportSTIXBundle(
        std::span<const uint64_t> entryIds = {},
        const IOCQueryOptions& options = IOCQueryOptions::Default()
    ) const noexcept;
    
    // =========================================================================
    // STATISTICS & MAINTENANCE
    // =========================================================================
    
    /**
     * @brief Get manager statistics
     */
    [[nodiscard]] IOCManagerStatistics GetStatistics() const noexcept;
    
    /**
     * @brief Reset statistics counters
     */
    void ResetStatistics() noexcept;
    
    /**
     * @brief Optimize internal data structures
     * @return true if optimization succeeded
     */
    [[nodiscard]] bool Optimize() noexcept;
    
    /**
     * @brief Verify data integrity
     * @param errorMessages Output error messages
     * @return true if all checks passed
     */
    [[nodiscard]] bool VerifyIntegrity(
        std::vector<std::string>& errorMessages
    ) const noexcept;
    
    /**
     * @brief Get memory usage in bytes
     */
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    
private:
    // =========================================================================
    // PRIVATE IMPLEMENTATION (Pimpl Pattern)
    // =========================================================================
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Initialization flag
    std::atomic<bool> m_initialized{false};
    
    // Reader-writer lock for thread safety
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Convert IOC relationship type to string
 */
[[nodiscard]] const char* IOCRelationTypeToString(IOCRelationType type) noexcept;

/**
 * @brief Parse IOC relationship type from string
 */
[[nodiscard]] std::optional<IOCRelationType> ParseIOCRelationType(
    std::string_view str
) noexcept;

/**
 * @brief Calculate hash of IOC value for deduplication
 */
[[nodiscard]] uint64_t CalculateIOCHash(
    IOCType type,
    std::string_view value
) noexcept;

/**
 * @brief Validate IOC type/value combination
 */
[[nodiscard]] bool ValidateIOCTypeValue(
    IOCType type,
    std::string_view value,
    std::string& errorMessage
) noexcept;

} // namespace ThreatIntel
} // namespace ShadowStrike
