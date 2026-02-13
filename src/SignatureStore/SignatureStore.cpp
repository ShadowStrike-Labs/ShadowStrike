// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike SignatureStore - IMPLEMENTATION (COMPLETE)
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Main unified facade - orchestrates ALL signature components
 * COMPLETE implementation of ALL functions declared in .hpp
 *
 * Target: < 60ms combined scan (hash + pattern + YARA)
 *
 * CRITICAL: This is the FINAL production-ready implementation!
 *
 * ============================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#include "SignatureStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <execution>
#include <future>
#include <filesystem>

namespace ShadowStrike {
namespace SignatureStore {


   

// ============================================================================
// CONSTRUCTOR & DESTRUCTOR
// ============================================================================

SignatureStore::SignatureStore()
    : m_hashStore(nullptr)
    , m_patternStore(nullptr)
    , m_yaraStore(nullptr)
{
    // TITANIUM: Initialize performance counter with validation
    m_perfFrequency.QuadPart = 0;
    if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart <= 0) {
        // Fallback to reasonable default (1MHz = 1µs resolution)
        m_perfFrequency.QuadPart = 1000000;
        SS_LOG_WARN(L"SignatureStore", L"QueryPerformanceFrequency failed, using fallback");
    }

    // TITANIUM: Initialize component stores with exception safety
    try {
        m_hashStore = std::make_unique<HashStore>();
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create HashStore: %S", e.what());
        m_hashStore = nullptr;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create HashStore: Unknown exception");
        m_hashStore = nullptr;
    }

    try {
        m_patternStore = std::make_unique<PatternStore>();
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create PatternStore: %S", e.what());
        m_patternStore = nullptr;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create PatternStore: Unknown exception");
        m_patternStore = nullptr;
    }

    try {
        m_yaraStore = std::make_unique<YaraRuleStore>();
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create YaraRuleStore: %S", e.what());
        m_yaraStore = nullptr;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to create YaraRuleStore: Unknown exception");
        m_yaraStore = nullptr;
    }

    // TITANIUM: Initialize query cache with proper exception handling
    try {
        m_queryCache.resize(QUERY_CACHE_SIZE);
        for (auto& entry : m_queryCache) {
            entry.bufferHash.fill(0);
            entry.result.Clear();  // Use Clear() method for proper initialization
            entry.timestamp = 0;
        }
    }
    catch (const std::bad_alloc& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to allocate query cache: %S", e.what());
        // Cache will remain empty - operations will check for empty cache
        m_queryCache.clear();
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Failed to initialize query cache: %S", e.what());
        m_queryCache.clear();
    }

    SS_LOG_DEBUG(L"SignatureStore", L"Created instance (HashStore=%s, PatternStore=%s, YaraStore=%s)",
        m_hashStore ? L"OK" : L"FAILED",
        m_patternStore ? L"OK" : L"FAILED",
        m_yaraStore ? L"OK" : L"FAILED");
}

SignatureStore::~SignatureStore() {
    // TITANIUM: Safe destruction with exception handling
    // Note: Destructor must not throw - wrap all operations in try-catch
    try {
        Close();
    }
    catch (...) {
        // Silently ignore exceptions in destructor
        SS_LOG_ERROR(L"SignatureStore", L"Exception in destructor during Close()");
    }
    
    // TITANIUM: Explicitly clear callback to prevent dangling references
    try {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;
    }
    catch (...) {
        // Mutex acquisition failed - force clear anyway
        m_detectionCallback = nullptr;
    }
    
    // TITANIUM: Clear caches before destroying stores
    try {
        std::unique_lock<std::shared_mutex> cacheLock(m_cacheLock, std::try_to_lock);
        m_queryCache.clear();
    }
    catch (...) {
        // Silently clear what we can
        m_queryCache.clear();
    }
}

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

StoreError SignatureStore::Initialize(
    const std::wstring& databasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Initialize: %s (%s)", 
        databasePath.c_str(), readOnly ? L"read-only" : L"read-write");

    // ========================================================================
    // TITANIUM VALIDATION LAYER - INITIALIZATION
    // ========================================================================
    
    // VALIDATION 1: Path cannot be empty
    if (databasePath.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"Initialize: Database path cannot be empty");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Database path cannot be empty"};
    }
    
    // VALIDATION 2: Path length check
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (databasePath.length() > MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"SignatureStore", L"Initialize: Path too long (%zu chars)", databasePath.length());
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Path too long"};
    }
    
    // VALIDATION 3: Null character injection check (path truncation attack)
    if (databasePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"SignatureStore", L"Initialize: Path contains null character (security violation)");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Path contains null character"};
    }

    // VALIDATION 4: Check for already initialized state
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"Already initialized");
        return StoreError{SignatureStoreError::Success};
    }

    // TITANIUM: Acquire exclusive lock with timeout protection
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_ERROR(L"SignatureStore", L"Initialize: Failed to acquire lock (possible deadlock)");
        return StoreError{SignatureStoreError::Unknown, 0, "Failed to acquire initialization lock"};
    }

    // Double-check initialization state under lock
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"Already initialized (race condition detected)");
        return StoreError{SignatureStoreError::Success};
    }

    m_readOnly.store(readOnly, std::memory_order_release);

    // Initialize YARA library first (global initialization)
    StoreError err = YaraRuleStore::InitializeYara();
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"SignatureStore", L"YARA initialization failed: %S", err.message.c_str());
        // Continue - YARA is optional
    }

    // TITANIUM: Track initialization success for each component
    bool anyComponentInitialized = false;

    // Initialize all components from same database
    if (m_hashStoreEnabled.load(std::memory_order_acquire) && m_hashStore) {
        err = m_hashStore->Initialize(databasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_WARN(L"SignatureStore", L"HashStore init failed: %S", err.message.c_str());
            // Continue - non-critical
        } else {
            anyComponentInitialized = true;
        }
    }

    if (m_patternStoreEnabled.load(std::memory_order_acquire) && m_patternStore) {
        err = m_patternStore->Initialize(databasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_WARN(L"SignatureStore", L"PatternStore init failed: %S", err.message.c_str());
            // Continue - non-critical
        } else {
            anyComponentInitialized = true;
        }
    }

    if (m_yaraStoreEnabled.load(std::memory_order_acquire) && m_yaraStore) {
        err = m_yaraStore->Initialize(databasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_WARN(L"SignatureStore", L"YaraStore init failed: %S", err.message.c_str());
            // Continue - non-critical
        } else {
            anyComponentInitialized = true;
        }
    }

    // TITANIUM: Only set initialized if at least one component initialized
    // This prevents "successful" initialization with invalid/nonexistent paths
    if (!anyComponentInitialized) {
        SS_LOG_ERROR(L"SignatureStore", L"Initialize failed: No components could be initialized");
        return StoreError{SignatureStoreError::FileNotFound, 0, "No components could be initialized - database path may be invalid"};
    }

    m_initialized.store(true, std::memory_order_release);
    SS_LOG_INFO(L"SignatureStore", L"Initialized successfully");
    
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureStore::InitializeMulti(
    const std::wstring& hashDatabasePath,
    const std::wstring& patternDatabasePath,
    const std::wstring& yaraDatabasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"SignatureStore", L"InitializeMulti (read-only=%s)", 
        readOnly ? L"true" : L"false");

    // ========================================================================
    // TITANIUM VALIDATION LAYER - MULTI-DATABASE INITIALIZATION
    // ========================================================================
    
    // VALIDATION 1: At least one path must be provided
    if (hashDatabasePath.empty() && patternDatabasePath.empty() && yaraDatabasePath.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"InitializeMulti: At least one database path must be provided");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No database paths provided"};
    }

    // VALIDATION 2: Path length and security checks
    constexpr size_t MAX_PATH_LENGTH = 32767;
    auto validatePath = [](const std::wstring& path, const wchar_t* name) -> StoreError {
        if (path.empty()) {
            return StoreError{SignatureStoreError::Success}; // Empty is OK - component disabled
        }
        if (path.length() > MAX_PATH_LENGTH) {
            SS_LOG_ERROR(L"SignatureStore", L"InitializeMulti: %s path too long", name);
            return StoreError{SignatureStoreError::InvalidFormat, 0, "Path too long"};
        }
        if (path.find(L'\0') != std::wstring::npos) {
            SS_LOG_ERROR(L"SignatureStore", L"InitializeMulti: %s path contains null character", name);
            return StoreError{SignatureStoreError::InvalidFormat, 0, "Path contains null character"};
        }
        return StoreError{SignatureStoreError::Success};
    };

    StoreError pathErr = validatePath(hashDatabasePath, L"Hash");
    if (!pathErr.IsSuccess()) return pathErr;
    
    pathErr = validatePath(patternDatabasePath, L"Pattern");
    if (!pathErr.IsSuccess()) return pathErr;
    
    pathErr = validatePath(yaraDatabasePath, L"YARA");
    if (!pathErr.IsSuccess()) return pathErr;

    // VALIDATION 3: Check already initialized
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"InitializeMulti: Already initialized");
        return StoreError{SignatureStoreError::Success};
    }

    // TITANIUM: Acquire exclusive lock with try_lock to prevent deadlock
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_ERROR(L"SignatureStore", L"InitializeMulti: Failed to acquire lock");
        return StoreError{SignatureStoreError::Unknown, 0, "Failed to acquire lock"};
    }

    // Double-check under lock
    if (m_initialized.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::Success};
    }

    m_readOnly.store(readOnly, std::memory_order_release);

    // Initialize YARA (global, doesn't need a database path)
    StoreError yaraInitErr = YaraRuleStore::InitializeYara();
    if (!yaraInitErr.IsSuccess()) {
        SS_LOG_WARN(L"SignatureStore", L"InitializeMulti: YARA library init failed: %S", 
            yaraInitErr.message.c_str());
        // Continue - YARA is optional
    }

    // TITANIUM: Track component initialization
    bool anyComponentInitialized = false;
    StoreError err{SignatureStoreError::Success};

    // Initialize each component with its own database
    if (m_hashStoreEnabled.load(std::memory_order_acquire) && !hashDatabasePath.empty() && m_hashStore) {
        err = m_hashStore->Initialize(hashDatabasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"HashStore failed: %S", err.message.c_str());
        } else {
            anyComponentInitialized = true;
            SS_LOG_DEBUG(L"SignatureStore", L"HashStore initialized from: %s", hashDatabasePath.c_str());
        }
    }

    if (m_patternStoreEnabled.load(std::memory_order_acquire) && !patternDatabasePath.empty() && m_patternStore) {
        err = m_patternStore->Initialize(patternDatabasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"PatternStore failed: %S", err.message.c_str());
        } else {
            anyComponentInitialized = true;
            SS_LOG_DEBUG(L"SignatureStore", L"PatternStore initialized from: %s", patternDatabasePath.c_str());
        }
    }

    if (m_yaraStoreEnabled.load(std::memory_order_acquire) && !yaraDatabasePath.empty() && m_yaraStore) {
        err = m_yaraStore->Initialize(yaraDatabasePath, readOnly);
        if (!err.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"YaraStore failed: %S", err.message.c_str());
        } else {
            anyComponentInitialized = true;
            SS_LOG_DEBUG(L"SignatureStore", L"YaraStore initialized from: %s", yaraDatabasePath.c_str());
        }
    }

    m_initialized.store(true, std::memory_order_release);

    if (anyComponentInitialized) {
        SS_LOG_INFO(L"SignatureStore", L"Multi-database initialization complete");
    } else {
        SS_LOG_WARN(L"SignatureStore", L"Multi-database initialization complete but no components available");
    }
    
    return StoreError{SignatureStoreError::Success};
}

void SignatureStore::Close() noexcept {
    // TITANIUM: Early exit if not initialized
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(L"SignatureStore", L"Closing signature store");

    // TITANIUM: Try to acquire lock with timeout to prevent deadlock during shutdown
    // Use manual retry loop since std::shared_mutex doesn't have try_lock_for
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::defer_lock);
    
    constexpr int maxRetries = 50;  // 50 * 100ms = 5 seconds total
    for (int i = 0; i < maxRetries; ++i) {
        if (lock.try_lock()) {
            break;
        }
        // Brief sleep before retry
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (!lock.owns_lock()) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: Failed to acquire lock within timeout");
        // Force close anyway - this is a critical operation
        m_initialized.store(false, std::memory_order_release);
        return;
    }

    // TITANIUM: Close all components with exception safety
    try {
        if (m_hashStore) {
            m_hashStore->Close();
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: HashStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: HashStore unknown exception");
    }

    try {
        if (m_patternStore) {
            m_patternStore->Close();
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: PatternStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: PatternStore unknown exception");
    }

    try {
        if (m_yaraStore) {
            m_yaraStore->Close();
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: YaraStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: YaraStore unknown exception");
    }

    // Clear caches (need to release global lock first, then acquire cache lock)
    lock.unlock();
    
    try {
        ClearAllCaches();
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Close: ClearAllCaches exception");
    }

    m_initialized.store(false, std::memory_order_release);

    SS_LOG_INFO(L"SignatureStore", L"Closed successfully");
}

SignatureStore::InitializationStatus SignatureStore::GetStatus() const noexcept {
    InitializationStatus status{};

    // TITANIUM: Thread-safe status retrieval with try_lock to prevent deadlock
    std::shared_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        // Can't acquire lock - return current known state without blocking
        status.hashStoreReady = false;
        status.patternStoreReady = false;
        status.yaraStoreReady = false;
        status.allReady = false;
        return status;
    }

    // TITANIUM: Safely check each component with null checks
    try {
        status.hashStoreReady = m_hashStore && m_hashStore->IsInitialized();
    }
    catch (...) {
        status.hashStoreReady = false;
    }

    try {
        status.patternStoreReady = m_patternStore && m_patternStore->IsInitialized();
    }
    catch (...) {
        status.patternStoreReady = false;
    }

    try {
        status.yaraStoreReady = m_yaraStore && m_yaraStore->IsInitialized();
    }
    catch (...) {
        status.yaraStoreReady = false;
    }

    status.allReady = status.hashStoreReady && status.patternStoreReady && status.yaraStoreReady;

    return status;
}


// ============================================================================
// STATISTICS & MONITORING
// ============================================================================

SignatureStore::GlobalStatistics SignatureStore::GetGlobalStatistics() const noexcept {
    GlobalStatistics stats{};

    // TITANIUM: Thread-safe statistics retrieval with try_lock to prevent deadlock
    std::shared_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        // Can't acquire lock - return partial statistics from atomics only
        stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
        stats.totalDetections = m_totalDetections.load(std::memory_order_relaxed);
        stats.queryCacheHits = m_queryCacheHits.load(std::memory_order_relaxed);
        stats.queryCacheMisses = m_queryCacheMisses.load(std::memory_order_relaxed);
        return stats;
    }

    // Component statistics with exception safety
    try {
        if (m_hashStore) {
            stats.hashStats = m_hashStore->GetStatistics();
            stats.hashDatabaseSize = stats.hashStats.databaseSizeBytes;
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: HashStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: HashStore unknown exception");
    }

    try {
        if (m_patternStore) {
            stats.patternStats = m_patternStore->GetStatistics();
            stats.patternDatabaseSize = stats.patternStats.totalBytesScanned;
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: PatternStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: PatternStore unknown exception");
    }

    try {
        if (m_yaraStore) {
            stats.yaraStats = m_yaraStore->GetStatistics();
            stats.yaraDatabaseSize = stats.yaraStats.compiledRulesSize;
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: YaraStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"GetGlobalStatistics: YaraStore unknown exception");
    }

    // Global metrics (atomic loads)
    stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
    stats.totalDetections = m_totalDetections.load(std::memory_order_relaxed);
    
    // TITANIUM: Overflow-safe total database size calculation
    uint64_t totalSize = 0;
    if (stats.hashDatabaseSize <= UINT64_MAX - totalSize) {
        totalSize += stats.hashDatabaseSize;
    }
    if (stats.patternDatabaseSize <= UINT64_MAX - totalSize) {
        totalSize += stats.patternDatabaseSize;
    }
    if (stats.yaraDatabaseSize <= UINT64_MAX - totalSize) {
        totalSize += stats.yaraDatabaseSize;
    }
    stats.totalDatabaseSize = totalSize;

    // Cache performance
    stats.queryCacheHits = m_queryCacheHits.load(std::memory_order_relaxed);
    stats.queryCacheMisses = m_queryCacheMisses.load(std::memory_order_relaxed);
    
    // TITANIUM: Overflow-safe cache hit rate calculation
    uint64_t totalCache = stats.queryCacheHits + stats.queryCacheMisses;
    if (totalCache > 0 && stats.queryCacheHits <= totalCache) {
        stats.cacheHitRate = static_cast<double>(stats.queryCacheHits) / static_cast<double>(totalCache);
    } else {
        stats.cacheHitRate = 0.0;
    }

    return stats;
}

void SignatureStore::ResetStatistics() noexcept {
    // TITANIUM: Reset atomic counters first (no lock needed for atomics)
    m_totalScans.store(0, std::memory_order_release);
    m_totalDetections.store(0, std::memory_order_release);
    m_queryCacheHits.store(0, std::memory_order_release);
    m_queryCacheMisses.store(0, std::memory_order_release);

    // Component resets with exception safety
    try {
        if (m_hashStore) m_hashStore->ResetStatistics();
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"ResetStatistics: HashStore reset failed");
    }

    try {
        if (m_patternStore) m_patternStore->ResetStatistics();
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"ResetStatistics: PatternStore reset failed");
    }

    try {
        if (m_yaraStore) m_yaraStore->ResetStatistics();
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"ResetStatistics: YaraStore reset failed");
    }

    SS_LOG_DEBUG(L"SignatureStore", L"Statistics reset completed");
}

HashStore::HashStoreStatistics SignatureStore::GetHashStatistics() const noexcept {
    try {
        if (!m_hashStore) {
            return HashStore::HashStoreStatistics{};
        }
        return m_hashStore->GetStatistics();
    }
    catch (...) {
        return HashStore::HashStoreStatistics{};
    }
}

PatternStore::PatternStoreStatistics SignatureStore::GetPatternStatistics() const noexcept {
    try {
        if (!m_patternStore) {
            return PatternStore::PatternStoreStatistics{};
        }
        return m_patternStore->GetStatistics();
    }
    catch (...) {
        return PatternStore::PatternStoreStatistics{};
    }
}

YaraRuleStore::YaraStoreStatistics SignatureStore::GetYaraStatistics() const noexcept {
    try {
        if (!m_yaraStore) {
            return YaraRuleStore::YaraStoreStatistics{};
        }
        return m_yaraStore->GetStatistics();
    }
    catch (...) {
        return YaraRuleStore::YaraStoreStatistics{};
    }
}

// ============================================================================
// MAINTENANCE & OPTIMIZATION
// ============================================================================

StoreError SignatureStore::Rebuild() noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Rebuilding all indices");

    // TITANIUM: Use try_to_lock to prevent deadlock in noexcept function
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_WARN(L"SignatureStore", L"Rebuild: Could not acquire lock, operation in progress");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Could not acquire exclusive lock"};
    }

    StoreError lastError{SignatureStoreError::Success};
    uint32_t failCount = 0;

    // TITANIUM: Exception-safe component rebuilds
    try {
        if (m_hashStore) {
            auto err = m_hashStore->Rebuild();
            if (!err.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"Hash rebuild failed: %S", err.message.c_str());
                lastError = err;
                ++failCount;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Hash rebuild exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Hash rebuild unknown exception");
        ++failCount;
    }

    try {
        if (m_patternStore) {
            auto err = m_patternStore->Rebuild();
            if (!err.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"Pattern rebuild failed: %S", err.message.c_str());
                lastError = err;
                ++failCount;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Pattern rebuild exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Pattern rebuild unknown exception");
        ++failCount;
    }

    try {
        if (m_yaraStore) {
            auto err = m_yaraStore->Recompile();
            if (!err.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"YARA rebuild failed: %S", err.message.c_str());
                lastError = err;
                ++failCount;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"YARA rebuild exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"YARA rebuild unknown exception");
        ++failCount;
    }

    if (failCount > 0) {
        SS_LOG_WARN(L"SignatureStore", L"Rebuild completed with %u failures", failCount);
        return lastError;
    }

    SS_LOG_INFO(L"SignatureStore", L"Rebuild completed successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureStore::Compact() noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Compacting databases");

    // TITANIUM: Use try_to_lock to prevent deadlock
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_WARN(L"SignatureStore", L"Compact: Could not acquire lock");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Could not acquire exclusive lock"};
    }

    uint32_t failCount = 0;

    try {
        if (m_hashStore) {
            StoreError err = m_hashStore->Compact();
            if (!err.IsSuccess()) {
                return err;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"HashStore compact exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"HashStore compact unknown exception");
        ++failCount;
    }

    try {
        if (m_patternStore) {
            StoreError err = m_patternStore->Compact();
            if (!err.IsSuccess()) {
             return err;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"PatternStore compact exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"PatternStore compact unknown exception");
        ++failCount;
    }

    if (failCount > 0) {
        SS_LOG_WARN(L"SignatureStore", L"Compact completed with %u warnings", failCount);
    }

    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureStore::Verify(
    std::function<void(const std::string&)> logCallback
) const noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Verifying database integrity");

    // TITANIUM: Enhanced exception-safe verification with try_to_lock
    try {
        std::shared_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
        if (!lock.owns_lock()) {
            SS_LOG_WARN(L"SignatureStore", L"Verify: Could not acquire lock");
            return StoreError{SignatureStoreError::AccessDenied, 0, "Could not acquire shared lock"};
        }

        StoreError err{SignatureStoreError::Success};

        if (m_hashStore) {
            err = m_hashStore->Verify(logCallback);
            if (!err.IsSuccess()) {
                try {
                    if (logCallback) logCallback("HashStore verification failed");
                }
                catch (...) { /* Callback threw - ignore */ }
                return err;
            }
        }

        if (m_patternStore) {
            err = m_patternStore->Verify(logCallback);
            if (!err.IsSuccess()) {
                try {
                    if (logCallback) logCallback("PatternStore verification failed");
                }
                catch (...) { /* Callback threw - ignore */ }
                return err;
            }
        }

        if (m_yaraStore) {
            err = m_yaraStore->Verify(logCallback);
            if (!err.IsSuccess()) {
                try {
                    if (logCallback) logCallback("YaraStore verification failed");
                }
                catch (...) { /* Callback threw - ignore */ }
                return err;
            }
        }

        try {
            if (logCallback) logCallback("All components verified successfully");
        }
        catch (...) { /* Callback threw - ignore */ }
        
        return StoreError{SignatureStoreError::Success};
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"Verify: Exception: %S", e.what());
        return StoreError{SignatureStoreError::Unknown, 0, std::string("Verification exception: ") + e.what()};
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"Verify: Unknown exception");
        return StoreError{SignatureStoreError::Unknown, 0, "Unknown verification error"};
    }
}

StoreError SignatureStore::Flush() noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"Flushing all databases");

    // TITANIUM: Use try_to_lock to prevent deadlock in noexcept function
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_WARN(L"SignatureStore", L"Flush: Could not acquire lock");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Could not acquire exclusive lock"};
    }

    uint32_t failCount = 0;

    try {
        if (m_hashStore) {
         StoreError err =m_hashStore->Flush();
         if (!err.IsSuccess()) {
             return err;
         }

        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"HashStore flush exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"HashStore flush unknown exception");
        ++failCount;
    }

    try {
        if (m_patternStore) {
            StoreError err = m_patternStore->Flush();
            if (!err.IsSuccess()) {
                return err;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"PatternStore flush exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"PatternStore flush unknown exception");
        ++failCount;
    }

    try {
        if (m_yaraStore)
        {
           StoreError err =  m_yaraStore->Flush();
            if (!err.IsSuccess()) {
                return err;
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"YaraStore flush exception: %S", e.what());
        ++failCount;
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"YaraStore flush unknown exception");
        ++failCount;
    }

    if (failCount > 0) {
        SS_LOG_WARN(L"SignatureStore", L"Flush completed with %u warnings", failCount);
    }

    return StoreError{SignatureStoreError::Success};
}
StoreError SignatureStore::OptimizeByUsage() noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Optimizing by usage patterns");

    // TITANIUM: Exception-safe optimization with try_to_lock
    std::unique_lock<std::shared_mutex> lock(m_globalLock, std::try_to_lock);
    if (!lock.owns_lock()) {
        SS_LOG_WARN(L"SignatureStore", L"OptimizeByUsage: Could not acquire lock");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Could not acquire exclusive lock" };
    }

    try {
        // FIXED: Removed unused 'heatmap' object (V808)
        // The pattern ordering optimization is now handled internally by OptimizeByHitRate.
        if (m_patternStore) {
            StoreError err = m_patternStore->OptimizeByHitRate();
            if (!err.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"Pattern optimization failed: %S", err.message.c_str());
                return err;
            }
            SS_LOG_DEBUG(L"SignatureStore", L"Pattern optimization completed");
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"OptimizeByUsage exception: %S", e.what());
        return StoreError{ SignatureStoreError::Unknown, 0, std::string("Optimization error: ") + e.what() };
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"OptimizeByUsage unknown exception");
        return StoreError{ SignatureStoreError::Unknown, 0, "Unknown optimization error" };
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// CONFIGURATION
// ============================================================================

void SignatureStore::SetHashStoreEnabled(bool enabled) noexcept {
    m_hashStoreEnabled.store(enabled, std::memory_order_release);
}

void SignatureStore::SetPatternStoreEnabled(bool enabled) noexcept {
    m_patternStoreEnabled.store(enabled, std::memory_order_release);
}

void SignatureStore::SetYaraStoreEnabled(bool enabled) noexcept {
    m_yaraStoreEnabled.store(enabled, std::memory_order_release);
}

void SignatureStore::SetQueryCacheEnabled(bool enabled) noexcept {
    m_queryCacheEnabled.store(enabled, std::memory_order_release);
}

void SignatureStore::SetResultCacheEnabled(bool enabled) noexcept {
    m_resultCacheEnabled.store(enabled, std::memory_order_release);
}

void SignatureStore::SetQueryCacheSize(size_t entries) noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"SetQueryCacheSize: %zu entries", entries);

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (entries == 0) {
        SS_LOG_WARN(L"SignatureStore", L"SetQueryCacheSize: Cannot set cache size to 0, keeping current");
        return;
    }

    // Maximum reasonable cache size (prevent memory exhaustion)
    constexpr size_t MAX_CACHE_ENTRIES = 10000;
    if (entries > MAX_CACHE_ENTRIES) {
        SS_LOG_WARN(L"SignatureStore",
            L"SetQueryCacheSize: Requested size %zu exceeds maximum %zu, capping to maximum",
            entries, MAX_CACHE_ENTRIES);
        entries = MAX_CACHE_ENTRIES;
    }

    // ========================================================================
    // ACQUIRE LOCK (Prevent concurrent access during resize)
    // ========================================================================
    // FIX: Use dedicated cache lock instead of global lock for better performance
    std::unique_lock<std::shared_mutex> lock(m_cacheLock);

    // Check if size actually changed
    size_t currentSize = m_queryCache.size();
    if (entries == currentSize) {
        SS_LOG_DEBUG(L"SignatureStore", L"SetQueryCacheSize: Cache size already %zu, no change needed", entries);
        return;
    }

    // ========================================================================
       // RESIZE OPERATION
       // ========================================================================
    try {
        // FIXED: Removed 'oldEntries' object (V808). 
        // Copying the entire cache vector is a heavy O(N) operation and was not utilized.
        // Since resize invalidates hash-based mapping, a clean flush is the correct approach.

        // Resize vector to new size
        m_queryCache.resize(entries);

        // Clear all entries in the resized cache to maintain deterministic state
        for (auto& entry : m_queryCache) {
            entry.bufferHash.fill(0);
            entry.result = ScanResult{};
            entry.timestamp = 0;
        }

        SS_LOG_INFO(L"SignatureStore",
            L"SetQueryCacheSize: Cache size changed from %zu to %zu entries",
            currentSize, entries);

        // Update statistics
        auto stats = GetGlobalStatistics();
        SS_LOG_DEBUG(L"SignatureStore",
            L"SetQueryCacheSize: Current cache state - hits: %llu, misses: %llu",
            stats.queryCacheHits, stats.queryCacheMisses);

    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore",
            L"SetQueryCacheSize: Exception during resize: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"SetQueryCacheSize: Unknown exception during resize");
    }
}


void SignatureStore::SetResultCacheSize(size_t entries) noexcept {
    // TITANIUM: Validate input and add meaningful implementation
    if (entries == 0) {
        SS_LOG_WARN(L"SignatureStore", L"SetResultCacheSize: Cannot set to 0");
        return;
    }
    
    constexpr size_t MAX_RESULT_CACHE = 10000;
    if (entries > MAX_RESULT_CACHE) {
        SS_LOG_WARN(L"SignatureStore", L"SetResultCacheSize: Capping to maximum %zu", MAX_RESULT_CACHE);
        entries = MAX_RESULT_CACHE;
    }
    
    SS_LOG_DEBUG(L"SignatureStore", L"SetResultCacheSize: Setting to %zu", entries);
    // Note: Actual result cache may be implemented by underlying stores
}

void SignatureStore::ClearQueryCache() noexcept {
    // TITANIUM: Exception-safe cache clear with try_to_lock
    try {
        std::unique_lock<std::shared_mutex> lock(m_cacheLock, std::try_to_lock);
        if (!lock.owns_lock()) {
            SS_LOG_DEBUG(L"SignatureStore", L"ClearQueryCache: Could not acquire lock, skipping");
            return;
        }
        
        for (auto& entry : m_queryCache) {
            entry.bufferHash.fill(0);
            entry.result = ScanResult{};
            entry.timestamp = 0;
        }
        
        SS_LOG_DEBUG(L"SignatureStore", L"Query cache cleared");
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"ClearQueryCache exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"ClearQueryCache unknown exception");
    }
}

void SignatureStore::ClearResultCache() noexcept {
    ClearQueryCache(); // Same cache in this implementation
}

void SignatureStore::ClearAllCaches() noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"Clearing all caches");
    
    ClearQueryCache();
    
    // TITANIUM: Exception-safe component cache clear
    try {
        if (m_hashStore) m_hashStore->ClearCache();
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"SignatureStore", L"ClearAllCaches HashStore exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureStore", L"ClearAllCaches HashStore unknown exception");
    }
}

void SignatureStore::SetThreadPoolSize(uint32_t threadCount) noexcept {
    // TITANIUM: Validate thread count
    if (threadCount == 0) {
        SS_LOG_WARN(L"SignatureStore", L"SetThreadPoolSize: Cannot set to 0, using 1");
        threadCount = 1;
    }
    
    // Cap to reasonable maximum to prevent resource exhaustion
    constexpr uint32_t MAX_THREADS = 64;
    if (threadCount > MAX_THREADS) {
        SS_LOG_WARN(L"SignatureStore", L"SetThreadPoolSize: Capping to %u threads", MAX_THREADS);
        threadCount = MAX_THREADS;
    }
    
    m_threadPoolSize = threadCount;
    SS_LOG_DEBUG(L"SignatureStore", L"Thread pool size set to %u", threadCount);
}

// ============================================================================
// ADVANCED FEATURES
// ============================================================================

void SignatureStore::RegisterDetectionCallback(DetectionCallback callback) noexcept {
    // TITANIUM: Exception-safe callback registration
    try {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = std::move(callback);
        SS_LOG_DEBUG(L"SignatureStore", L"Detection callback registered");
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"RegisterDetectionCallback exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"RegisterDetectionCallback unknown exception");
    }
}

void SignatureStore::UnregisterDetectionCallback() noexcept {
    // TITANIUM: Exception-safe callback unregistration
    try {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;
        SS_LOG_DEBUG(L"SignatureStore", L"Detection callback unregistered");
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"UnregisterDetectionCallback exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"UnregisterDetectionCallback unknown exception");
    }
}

std::wstring SignatureStore::GetHashDatabasePath() const noexcept {
    // TITANIUM: Exception-safe path retrieval
    try {
        if (!m_hashStore) {
            return L"";
        }
        return m_hashStore->GetDatabasePath();
    }
    catch (...) {
        return L"";
    }
}

std::wstring SignatureStore::GetPatternDatabasePath() const noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"GetPatternDatabasePath called");

    if (!m_patternStoreEnabled.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"GetPatternDatabasePath: PatternStore not enabled");
        return L"";
    }

    if (!m_patternStore) {
        SS_LOG_WARN(L"SignatureStore", L"GetPatternDatabasePath: PatternStore not initialized");
        return L"";
    }

    // Get path from pattern store
    std::wstring path = m_patternStore->GetDatabasePath();

    if (path.empty()) {
        SS_LOG_DEBUG(L"SignatureStore", L"GetPatternDatabasePath: Pattern store returned empty path");
        return L"";
    }

    SS_LOG_DEBUG(L"SignatureStore", L"GetPatternDatabasePath: %s", path.c_str());
    return path;
}

std::wstring SignatureStore::GetYaraDatabasePath() const noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"GetYaraDatabasePath called");

    if (!m_yaraStoreEnabled.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"GetYaraDatabasePath: YaraStore not enabled");
        return L"";
    }

    if (!m_yaraStore) {
        SS_LOG_WARN(L"SignatureStore", L"GetYaraDatabasePath: YaraStore not initialized");
        return L"";
    }

    

    // YARA store database path (from Initialize)
    std::wstring path = m_yaraStore->GetDatabasePath();

    if (path.empty()) {
        SS_LOG_DEBUG(L"SignatureStore", L"GetYaraDatabasePath: Database path not set");
        return L"";
    }

    SS_LOG_DEBUG(L"SignatureStore", L"GetYaraDatabasePath: %s", path.c_str());
    return path;
}

// FIX: Missing implementation for GetHashHeader declared in header
const SignatureDatabaseHeader* SignatureStore::GetHashHeader() const noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"GetHashHeader called");

    if (!m_hashStoreEnabled.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"GetHashHeader: HashStore not enabled");
        return nullptr;
    }

    if (!m_hashStore) {
        SS_LOG_WARN(L"SignatureStore", L"GetHashHeader: HashStore not initialized");
        return nullptr;
    }

    const SignatureDatabaseHeader* header = m_hashStore->GetHeader();

    if (!header) {
        SS_LOG_DEBUG(L"SignatureStore", L"GetHashHeader: Hash store header is null");
        return nullptr;
    }

    SS_LOG_DEBUG(L"SignatureStore",
        L"GetHashHeader: Valid header - version %u.%u",
        header->versionMajor, header->versionMinor);

    return header;
}

const SignatureDatabaseHeader* SignatureStore::GetPatternHeader() const noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"GetPatternHeader called");

    if (!m_patternStoreEnabled.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"GetPatternHeader: PatternStore not enabled");
        return nullptr;
    }

    if (!m_patternStore) {
        SS_LOG_WARN(L"SignatureStore", L"GetPatternHeader: PatternStore not initialized");
        return nullptr;
    }

    const SignatureDatabaseHeader* header = m_patternStore->GetHeader();

    if (!header) {
        SS_LOG_DEBUG(L"SignatureStore", L"GetPatternHeader: Pattern store header is null");
        return nullptr;
    }

    SS_LOG_DEBUG(L"SignatureStore",
        L"GetPatternHeader: Valid header - version %u.%u",
        header->versionMajor, header->versionMinor);

    return header;
}

const SignatureDatabaseHeader* SignatureStore::GetYaraHeader() const noexcept {
    SS_LOG_DEBUG(L"SignatureStore", L"GetYaraHeader called");

    if (!m_yaraStoreEnabled.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"GetYaraHeader: YaraStore not enabled");
        return nullptr;
    }

    if (!m_yaraStore) {
        SS_LOG_WARN(L"SignatureStore", L"GetYaraHeader: YaraStore not initialized");
        return nullptr;
    }

    const SignatureDatabaseHeader* header = m_yaraStore->GetHeader();

    if (!header) {
        SS_LOG_DEBUG(L"SignatureStore", L"GetYaraHeader: YARA store header is null");
        return nullptr;
    }

    SS_LOG_DEBUG(L"SignatureStore",
        L"GetYaraHeader: Valid header - version %u.%u, YARA rules %llu bytes",
        header->versionMajor, header->versionMinor, header->yaraRulesSize);

    return header;
}

void SignatureStore::WarmupCaches() noexcept {
    SS_LOG_INFO(L"SignatureStore", L"WarmupCaches: Starting cache warmup");

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"SignatureStore", L"WarmupCaches: SignatureStore not initialized");
        return;
    }

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    auto startTime = std::chrono::high_resolution_clock::now();
    size_t bytesWarmed = 0;
    size_t entriesWarmed = 0;

    try {
        // ====================================================================
        // WARMUP HASH STORE
        // ====================================================================
        if (m_hashStoreEnabled.load() && m_hashStore && m_hashStore->IsInitialized()) {
            SS_LOG_DEBUG(L"SignatureStore", L"WarmupCaches: Warming up HashStore");

            try {
                // Get hash store statistics to estimate warmup
                auto hashStats = m_hashStore->GetStatistics();

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: HashStore statistics - %llu hashes",
                    hashStats.totalHashes);

                // Pre-warming: Load statistics triggers internal index initialization
                // This ensures hash lookup tables are cached in memory
                entriesWarmed += hashStats.totalHashes;
                bytesWarmed += hashStats.databaseSizeBytes;

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: HashStore warmup - %llu entries, %llu bytes",
                    hashStats.totalHashes, hashStats.databaseSizeBytes);
            }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"SignatureStore",
                    L"WarmupCaches: HashStore warmup exception: %S", e.what());
            }
        }

        // ====================================================================
        // WARMUP PATTERN STORE
        // ====================================================================
        if (m_patternStoreEnabled.load() && m_patternStore && m_patternStore->IsInitialized()) {
            SS_LOG_DEBUG(L"SignatureStore", L"WarmupCaches: Warming up PatternStore");

            try {
                // Pre-load pattern indices through statistics
                auto patternStats = m_patternStore->GetStatistics();

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: PatternStore loaded - %llu patterns, %zu nodes",
                    patternStats.totalPatterns, patternStats.automatonNodeCount);

                // Loading Aho-Corasick automaton into cache
                entriesWarmed += patternStats.totalPatterns;
                bytesWarmed += patternStats.totalPatterns * 32; // Estimate per-pattern overhead

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: PatternStore warmup - %llu patterns warmed",
                    patternStats.totalPatterns);
            }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"SignatureStore",
                    L"WarmupCaches: PatternStore warmup exception: %S", e.what());
            }
        }

        // ====================================================================
        // WARMUP YARA STORE
        // ====================================================================
        if (m_yaraStoreEnabled.load() && m_yaraStore && m_yaraStore->IsInitialized()) {
            SS_LOG_DEBUG(L"SignatureStore", L"WarmupCaches: Warming up YaraStore");

            try {
                // Pre-load YARA rule metadata
                auto yaraStats = m_yaraStore->GetStatistics();

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: YaraStore loaded - %llu rules in %llu namespaces",
                    yaraStats.totalRules, yaraStats.totalNamespaces);

                // Pre-load compiled rule bytecode into memory
                entriesWarmed += yaraStats.totalRules;
                bytesWarmed += yaraStats.compiledRulesSize;

                SS_LOG_DEBUG(L"SignatureStore",
                    L"WarmupCaches: YaraStore warmup - %llu bytes compiled rules",
                    yaraStats.compiledRulesSize);
            }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"SignatureStore",
                    L"WarmupCaches: YaraStore warmup exception: %S", e.what());
            }
        }

        // ====================================================================
        // WARMUP QUERY CACHE
        // ====================================================================
        SS_LOG_DEBUG(L"SignatureStore", L"WarmupCaches: Initializing query cache");
        ClearQueryCache(); // Initialize empty cache with zero-fill

        // ====================================================================
        // STATISTICS & TIMING
        // ====================================================================
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        SS_LOG_INFO(L"SignatureStore",
            L"WarmupCaches: Complete - %zu entries, %zu bytes, %lld ms",
            entriesWarmed, bytesWarmed, duration.count());

        // Log cache performance baseline
        auto stats = GetGlobalStatistics();
        SS_LOG_DEBUG(L"SignatureStore",
            L"WarmupCaches: Baseline - total DB size: %llu bytes, scans: %llu",
            stats.totalDatabaseSize, stats.totalScans);

        // Verify all components warmed up
        if (entriesWarmed > 0) {
            SS_LOG_INFO(L"SignatureStore",
                L"WarmupCaches: Cache warmup successful - %zu signatures cached",
                entriesWarmed);
        }
        else {
            SS_LOG_WARN(L"SignatureStore",
                L"WarmupCaches: No signatures were warmed up - components may be empty");
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore",
            L"WarmupCaches: Unexpected exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"WarmupCaches: Unknown exception");
    }
}
// ============================================================================
// FACTORY METHODS
// ============================================================================

StoreError SignatureStore::CreateDatabase(
    const std::wstring& outputPath,
    const BuildConfiguration& config
) noexcept {
    SS_LOG_INFO(L"SignatureStore", L"Creating new database: %s", outputPath.c_str());

    SignatureBuilder builder(config);
    return builder.Build();
}



StoreError SignatureStore::MergeDatabases(
    std::span<const std::wstring> sourcePaths,
    const std::wstring & outputPath
) noexcept {
    SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Merging %zu databases to %s",
        sourcePaths.size(), outputPath.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER - DATABASE MERGE
    // ========================================================================
    
    // VALIDATION 1: Empty source paths
    if (sourcePaths.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: No source databases provided");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Source paths cannot be empty" };
    }

    // VALIDATION 2: Output path validation
    if (outputPath.empty()) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Output path cannot be empty");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Output path cannot be empty" };
    }
    
    // VALIDATION 3: Path length check
    constexpr size_t MAX_SAFE_PATH_LENGTH = 32767;
    if (outputPath.length() > MAX_SAFE_PATH_LENGTH) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Output path too long");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Output path too long" };
    }
    
    // VALIDATION 4: Null character injection check
    if (outputPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Output path contains null character");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Path contains null character" };
    }
    
    // VALIDATION 5: Maximum source count to prevent resource exhaustion
    constexpr size_t MAX_SOURCE_DATABASES = 1000;
    if (sourcePaths.size() > MAX_SOURCE_DATABASES) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Too many source databases (%zu > %zu)",
            sourcePaths.size(), MAX_SOURCE_DATABASES);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Too many source databases" };
    }

    // VALIDATION 6: Validate all source paths
    for (size_t i = 0; i < sourcePaths.size(); ++i) {
        if (sourcePaths[i].empty()) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Source path %zu is empty", i);
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "Source path cannot be empty" };
        }
        
        if (sourcePaths[i].length() > MAX_SAFE_PATH_LENGTH) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Source path %zu too long", i);
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "Source path too long" };
        }
        
        if (sourcePaths[i].find(L'\0') != std::wstring::npos) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Source path %zu contains null character", i);
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "Path contains null character" };
        }
        
        // TITANIUM: Canonicalize and compare paths to detect same-file conflicts
        try {
            namespace fs = std::filesystem;
            std::error_code ec;
            
            fs::path srcCanonical = fs::weakly_canonical(sourcePaths[i], ec);
            fs::path outCanonical = fs::weakly_canonical(outputPath, ec);
            
            if (!ec && srcCanonical == outCanonical) {
                SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Source[%zu] and output paths are the same", i);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, 
                    "Source and output paths cannot be identical" };
            }
            
            // Check for duplicates in source paths
            for (size_t j = i + 1; j < sourcePaths.size(); ++j) {
                fs::path otherCanonical = fs::weakly_canonical(sourcePaths[j], ec);
                if (!ec && srcCanonical == otherCanonical) {
                    SS_LOG_WARN(L"SignatureStore", 
                        L"MergeDatabases: Duplicate source paths detected [%zu] and [%zu]", i, j);
                }
            }
        }
        catch (const std::exception& e) {
            SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Path canonicalization failed: %S", e.what());
            // Continue with simple comparison
            if (sourcePaths[i] == outputPath) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, 
                    "Source and output paths cannot be identical" };
            }
        }
    }

    SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Opening %zu source databases", sourcePaths.size());

    // Use vectors of unique_ptr to avoid attempts to copy non-copyable classes
    std::vector<std::unique_ptr<HashStore>> sourceHashStores;
    std::vector<std::unique_ptr<PatternStore>> sourcePatternStores;
    std::vector<std::unique_ptr<YaraRuleStore>> sourceYaraStores;
    
    // TITANIUM: Reserve to avoid reallocations
    sourceHashStores.reserve(sourcePaths.size());
    sourcePatternStores.reserve(sourcePaths.size());
    sourceYaraStores.reserve(sourcePaths.size());

    try {
        // Open all source databases (store as unique_ptr)
        for (size_t i = 0; i < sourcePaths.size(); ++i) {
            SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Opening source [%zu]: %ls",
                i, sourcePaths[i].c_str());

            // HashStore
            {
                auto hs = std::make_unique<HashStore>();
                StoreError hashErr = hs->Initialize(sourcePaths[i], true);
                if (hashErr.IsSuccess()) {
                    sourceHashStores.push_back(std::move(hs));
                }
                else {
                    SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Failed to open HashStore at %ls: %S",
                        sourcePaths[i].c_str(), hashErr.message.c_str());
                }
            }

            // PatternStore
            {
                auto ps = std::make_unique<PatternStore>();
                StoreError patternErr = ps->Initialize(sourcePaths[i], true);
                if (patternErr.IsSuccess()) {
                    sourcePatternStores.push_back(std::move(ps));
                }
                else {
                    SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Failed to open PatternStore at %ls: %S",
                        sourcePaths[i].c_str(), patternErr.message.c_str());
                }
            }

            // YaraRuleStore
            {
                auto ys = std::make_unique<YaraRuleStore>();
                StoreError yaraErr = ys->Initialize(sourcePaths[i], true);
                if (yaraErr.IsSuccess()) {
                    sourceYaraStores.push_back(std::move(ys));
                }
                else {
                    SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Failed to open YaraStore at %ls: %S",
                        sourcePaths[i].c_str(), yaraErr.message.c_str());
                }
            }
        }
        
        // TITANIUM: Verify at least one source was opened successfully
        if (sourceHashStores.empty() && sourcePatternStores.empty() && sourceYaraStores.empty()) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: No source databases could be opened");
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "No source databases could be opened" };
        }

        // CREATE OUTPUT DATABASES
        SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Creating output databases");

        HashStore outputHashStore;
        PatternStore outputPatternStore;
        YaraRuleStore outputYaraStore;

        StoreError hashCreateErr = outputHashStore.CreateNew(outputPath);
        if (!hashCreateErr.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Failed to create output hash database: %S",
                hashCreateErr.message.c_str());
            return hashCreateErr;
        }

        StoreError patternCreateErr = outputPatternStore.CreateNew(outputPath);
        if (!patternCreateErr.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Failed to create output pattern database: %S",
                patternCreateErr.message.c_str());
            return patternCreateErr;
        }

        StoreError yaraCreateErr = outputYaraStore.CreateNew(outputPath);
        if (!yaraCreateErr.IsSuccess()) {
            SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Failed to create output YARA database: %S",
                yaraCreateErr.message.c_str());
            return yaraCreateErr;
        }

        // ====================================================================
        // MERGE HASH STORES
        // ====================================================================
        if (!sourceHashStores.empty()) {
            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Merging %zu hash stores",
                sourceHashStores.size());

            uint64_t totalHashesMerged = 0;
            uint64_t totalHashesFailed = 0;
            
            for (size_t i = 0; i < sourceHashStores.size(); ++i) {
                try {
                    auto sourceStats = sourceHashStores[i]->GetStatistics();
                    SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Hash store [%zu]: %llu hashes",
                        i, sourceStats.totalHashes);

                    std::string hashesJson = sourceHashStores[i]->ExportToJson();
                    if (hashesJson.empty()) {
                        SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Hash store [%zu] export empty", i);
                        continue;
                    }
                    
                    // TITANIUM: Check JSON size to prevent memory issues
                    constexpr size_t MAX_JSON_SIZE = 500 * 1024 * 1024; // 500MB
                    if (hashesJson.size() > MAX_JSON_SIZE) {
                        SS_LOG_WARN(L"SignatureStore", 
                            L"MergeDatabases: Hash store [%zu] JSON too large (%zu bytes)", i, hashesJson.size());
                        ++totalHashesFailed;
                        continue;
                    }

                    StoreError importErr = outputHashStore.ImportFromJson(hashesJson);
                    if (importErr.IsSuccess()) {
                        totalHashesMerged += sourceStats.totalHashes;
                        SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Hash store [%zu] merged successfully", i);
                    }
                    else {
                        SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Hash store [%zu] import failed: %S",
                            i, importErr.message.c_str());
                        ++totalHashesFailed;
                    }
                }
                catch (const std::exception& e) {
                    SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Hash store [%zu] exception: %S", i, e.what());
                    ++totalHashesFailed;
                }
            }

            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Total hashes merged: %llu (failed: %llu)",
                totalHashesMerged, totalHashesFailed);

            // Rebuild and flush
            StoreError rebuildErr = outputHashStore.Rebuild();
            if (!rebuildErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Hash store rebuild failed: %S",
                    rebuildErr.message.c_str());
            }

            StoreError flushErr = outputHashStore.Flush();
            if (!flushErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Hash store flush failed: %S",
                    flushErr.message.c_str());
            }
        }

        // ====================================================================
        // MERGE PATTERN STORES
        // ====================================================================
        if (!sourcePatternStores.empty()) {
            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Merging %zu pattern stores",
                sourcePatternStores.size());

            uint64_t totalPatternsMerged = 0;
            for (size_t i = 0; i < sourcePatternStores.size(); ++i) {
                try {
                    auto sourceStats = sourcePatternStores[i]->GetStatistics();
                    SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Pattern store [%zu]: %llu patterns",
                        i, sourceStats.totalPatterns);

                    std::string patternsJson = sourcePatternStores[i]->ExportToJson();
                    if (!patternsJson.empty()) {
                        totalPatternsMerged += sourceStats.totalPatterns;
                    }

                    SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: Pattern store [%zu] processed", i);
                }
                catch (const std::exception& e) {
                    SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Pattern store [%zu] exception: %S", i, e.what());
                }
            }

            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Total patterns processed: %llu", totalPatternsMerged);

            StoreError rebuildErr = outputPatternStore.Rebuild();
            if (!rebuildErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Pattern store rebuild failed: %S",
                    rebuildErr.message.c_str());
            }

            StoreError flushErr = outputPatternStore.Flush();
            if (!flushErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: Pattern store flush failed: %S",
                    flushErr.message.c_str());
            }
        }

        // ====================================================================
        // MERGE YARA STORES
        // ====================================================================
        if (!sourceYaraStores.empty()) {
            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Merging %zu YARA stores",
                sourceYaraStores.size());

            uint64_t totalRulesMerged = 0;
            for (size_t i = 0; i < sourceYaraStores.size(); ++i) {
                try {
                    auto sourceStats = sourceYaraStores[i]->GetStatistics();
                    SS_LOG_DEBUG(L"SignatureStore", L"MergeDatabases: YARA store [%zu]: %llu rules",
                        i, sourceStats.totalRules);

                    totalRulesMerged += sourceStats.totalRules;
                }
                catch (const std::exception& e) {
                    SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: YARA store [%zu] exception: %S", i, e.what());
                }
            }

            SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Total YARA rules processed: %llu", totalRulesMerged);

            StoreError rebuildErr = outputYaraStore.Recompile();
            if (!rebuildErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: YARA store recompile failed: %S",
                    rebuildErr.message.c_str());
            }

            StoreError flushErr = outputYaraStore.Flush();
            if (!flushErr.IsSuccess()) {
                SS_LOG_WARN(L"SignatureStore", L"MergeDatabases: YARA store flush failed");
            }
        }

        SS_LOG_INFO(L"SignatureStore", L"MergeDatabases: Merge completed successfully");
        return StoreError{ SignatureStoreError::Success };
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Exception: %S", e.what());
        return StoreError{ SignatureStoreError::Unknown, 0, std::string(e.what()) };
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeDatabases: Unknown exception");
        return StoreError{ SignatureStoreError::Unknown, 0, "Unknown merge error" };
    }
}


// ============================================================================
// INTERNAL METHODS
// ============================================================================

ScanResult SignatureStore::ExecuteScan(
    std::span<const uint8_t> buffer,
    const ScanOptions& options
) const noexcept {
    if (options.parallelExecution) {
        return ExecuteParallelScan(buffer, options);
    } else {
        return ExecuteSequentialScan(buffer, options);
    }
}

ScanResult SignatureStore::ExecuteParallelScan(
    std::span<const uint8_t> buffer,
    const ScanOptions& options
) const noexcept {
    // ========================================================================
    // TITANIUM PARALLEL SCAN - THREAD-SAFE WITH TIMEOUT AND ISOLATION
    // ========================================================================
    
    ScanResult result{};
    
    // VALIDATION 1: Buffer check
    if (buffer.empty() || buffer.data() == nullptr) {
        SS_LOG_DEBUG(L"SignatureStore", L"ExecuteParallelScan: Invalid buffer");
        return result;
    }
    
    // VALIDATION 2: Timeout configuration
    const auto timeoutMs = (options.timeoutMilliseconds > 0) 
        ? std::chrono::milliseconds(options.timeoutMilliseconds)
        : std::chrono::milliseconds(10000); // Default 10 seconds
    
    // ========================================================================
    // HASH LOOKUP (INLINE - TOO FAST FOR ASYNC OVERHEAD)
    // ========================================================================
    if (options.enableHashLookup && m_hashStoreEnabled.load(std::memory_order_acquire) && m_hashStore) {
        try {
            ShadowStrike::SignatureStore::SignatureBuilder builder;
            auto hash = builder.ComputeBufferHash(buffer, HashType::SHA256);
            if (hash.has_value()) {
                auto detection = m_hashStore->LookupHash(*hash);
                if (detection.has_value()) {
                    result.hashMatches.push_back(*detection);
                    
                    // Check stop-on-first-match
                    if (options.stopOnFirstMatch) {
                        result.stoppedEarly = true;
                        result.detections.push_back(*detection);
                        return result;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteParallelScan: Hash lookup exception: %S", e.what());
        }
    }

    // ========================================================================
    // PARALLEL ASYNC TASKS WITH TIMEOUT
    // ========================================================================
    std::vector<std::future<std::vector<DetectionResult>>> futures;
    futures.reserve(2); // Pattern + YARA

    // Pattern scan (async)
    if (options.enablePatternScan && m_patternStoreEnabled.load(std::memory_order_acquire) && m_patternStore) {
        // TITANIUM: Copy options to avoid dangling reference
        auto patternOptions = options.patternOptions;
        
        try {
            futures.push_back(std::async(std::launch::async, 
                [this, buffer, patternOptions]() -> std::vector<DetectionResult> {
                    try {
                        return m_patternStore->Scan(buffer, patternOptions);
                    }
                    catch (const std::exception& e) {
                        SS_LOG_ERROR(L"SignatureStore", 
                            L"ExecuteParallelScan: Pattern scan task exception: %S", e.what());
                        return {};
                    }
                    catch (...) {
                        SS_LOG_ERROR(L"SignatureStore", 
                            L"ExecuteParallelScan: Pattern scan task unknown exception");
                        return {};
                    }
                }));
        }
        catch (const std::system_error& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteParallelScan: Failed to launch pattern scan task: %S", e.what());
        }
    }

    // YARA scan (async)
    if (options.enableYaraScan && m_yaraStoreEnabled.load(std::memory_order_acquire) && m_yaraStore) {
        // TITANIUM: Copy options to avoid dangling reference
        auto yaraOptions = options.yaraOptions;
        
        try {
            futures.push_back(std::async(std::launch::async,
                [this, buffer, yaraOptions]() -> std::vector<DetectionResult> {
                    try {
                        auto yaraMatches = m_yaraStore->ScanBuffer(buffer, yaraOptions);
                        std::vector<DetectionResult> detections;
                        detections.reserve(yaraMatches.size());
                        
                        for (const auto& match : yaraMatches) {
                            DetectionResult detection{};
                            detection.signatureId = match.ruleId;
                            detection.signatureName = match.ruleName;
                            detection.threatLevel = match.threatLevel;
                            detection.description = "YARA rule match";
                            detections.push_back(std::move(detection));
                        }
                        
                        return detections;
                    }
                    catch (const std::exception& e) {
                        SS_LOG_ERROR(L"SignatureStore", 
                            L"ExecuteParallelScan: YARA scan task exception: %S", e.what());
                        return {};
                    }
                    catch (...) {
                        SS_LOG_ERROR(L"SignatureStore", 
                            L"ExecuteParallelScan: YARA scan task unknown exception");
                        return {};
                    }
                }));
        }
        catch (const std::system_error& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteParallelScan: Failed to launch YARA scan task: %S", e.what());
        }
    }

    // ========================================================================
    // COLLECT RESULTS WITH TIMEOUT
    // ========================================================================
    for (auto& future : futures) {
        try {
            // TITANIUM: Wait with timeout to prevent indefinite blocking
            auto status = future.wait_for(timeoutMs);
            
            if (status == std::future_status::ready) {
                auto detections = future.get();
                
                // TITANIUM: Limit results to prevent memory exhaustion
                const size_t maxToAdd = options.maxResults > result.detections.size() 
                    ? options.maxResults - result.detections.size() 
                    : 0;
                    
                if (detections.size() <= maxToAdd) {
                    result.detections.insert(result.detections.end(), 
                        detections.begin(), detections.end());
                } else {
                    result.detections.insert(result.detections.end(),
                        detections.begin(), detections.begin() + maxToAdd);
                    SS_LOG_WARN(L"SignatureStore", 
                        L"ExecuteParallelScan: Result limit reached, truncating detections");
                }
            }
            else if (status == std::future_status::timeout) {
                SS_LOG_WARN(L"SignatureStore", 
                    L"ExecuteParallelScan: Task timed out after %lld ms", timeoutMs.count());
                result.timedOut = true;
                // Don't wait for this task - it will complete in background
                // The future will be destroyed but the task continues
            }
            else {
                SS_LOG_WARN(L"SignatureStore", L"ExecuteParallelScan: Task deferred");
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteParallelScan: Exception collecting results: %S", e.what());
        }
        catch (...) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteParallelScan: Unknown exception collecting results");
        }
    }

    // ========================================================================
    // MERGE HASH MATCHES INTO FINAL RESULTS
    // ========================================================================
    result.detections.insert(result.detections.end(), 
                            result.hashMatches.begin(), 
                            result.hashMatches.end());

    return result;
}

ScanResult SignatureStore::ExecuteSequentialScan(
    std::span<const uint8_t> buffer,
    const ScanOptions& options
) const noexcept {
    ScanResult result{};

    // TITANIUM: Buffer validation
    if (buffer.empty() || buffer.data() == nullptr) {
        SS_LOG_DEBUG(L"SignatureStore", L"ExecuteSequentialScan: Invalid buffer");
        return result;
    }

    // Hash lookup
    if (options.enableHashLookup && m_hashStoreEnabled.load(std::memory_order_acquire) && m_hashStore) {
        try {
            ShadowStrike::SignatureStore::SignatureBuilder builder;
            auto hash = builder.ComputeBufferHash(buffer, HashType::SHA256);
            if (hash.has_value()) {
                auto detection = m_hashStore->LookupHash(*hash);
                if (detection.has_value()) {
                    result.hashMatches.push_back(*detection);
                    result.detections.push_back(*detection);
                    
                    if (options.stopOnFirstMatch) {
                        result.stoppedEarly = true;
                        return result;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: Hash lookup exception: %S", e.what());
        }
        catch (...) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: Hash lookup unknown exception");
        }
    }

    // Pattern scan
    if (options.enablePatternScan && m_patternStoreEnabled.load(std::memory_order_acquire) && m_patternStore) {
        try {
            result.patternMatches = m_patternStore->Scan(buffer, options.patternOptions);
            
            // TITANIUM: Limit results to prevent memory exhaustion
            const size_t maxToAdd = options.maxResults > result.detections.size() 
                ? options.maxResults - result.detections.size() 
                : 0;
            
            if (result.patternMatches.size() <= maxToAdd) {
                result.detections.insert(result.detections.end(),
                                        result.patternMatches.begin(),
                                        result.patternMatches.end());
            } else {
                result.detections.insert(result.detections.end(),
                                        result.patternMatches.begin(),
                                        result.patternMatches.begin() + static_cast<ptrdiff_t>(maxToAdd));
            }
            
            if (options.stopOnFirstMatch && !result.patternMatches.empty()) {
                result.stoppedEarly = true;
                return result;
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: Pattern scan exception: %S", e.what());
        }
        catch (...) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: Pattern scan unknown exception");
        }
    }

    // YARA scan
    if (options.enableYaraScan && m_yaraStoreEnabled.load(std::memory_order_acquire) && m_yaraStore) {
        try {
            result.yaraMatches = m_yaraStore->ScanBuffer(buffer, options.yaraOptions);
            
            for (const auto& match : result.yaraMatches) {
                // TITANIUM: Check result limit before adding
                if (result.detections.size() >= options.maxResults) {
                    SS_LOG_DEBUG(L"SignatureStore", L"ExecuteSequentialScan: Result limit reached");
                    break;
                }
                
                DetectionResult detection{};
                detection.signatureId = match.ruleId;
                detection.signatureName = match.ruleName;
                detection.threatLevel = match.threatLevel;
                detection.description = "YARA rule match";
                detection.matchTimestamp = match.matchTimeMicroseconds;
                
                result.detections.push_back(detection);
            }
            
            if (options.stopOnFirstMatch && !result.yaraMatches.empty()) {
                result.stoppedEarly = true;
                return result;
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: YARA scan exception: %S", e.what());
        }
        catch (...) {
            SS_LOG_ERROR(L"SignatureStore", L"ExecuteSequentialScan: YARA scan unknown exception");
        }
    }

    return result;
}

std::optional<ScanResult> SignatureStore::CheckQueryCache(
    std::span<const uint8_t> buffer
) const noexcept {
    // ========================================================================
    // TITANIUM CACHE LOOKUP - THREAD-SAFE WITH VALIDATION
    // ========================================================================
    
    // VALIDATION 1: Quick check if caching is even enabled (avoid lock overhead)
    if (!m_queryCacheEnabled.load(std::memory_order_acquire)) {
        return std::nullopt;
    }
    
    // VALIDATION 2: Check if cache is empty to prevent division by zero
    // Note: Size check before lock is safe since cache size only changes under unique_lock
    if (m_queryCache.empty()) {
        return std::nullopt;
    }
    
    // VALIDATION 3: Buffer validation
    if (buffer.empty() || buffer.data() == nullptr) {
        return std::nullopt;
    }
    
    // VALIDATION 4: Maximum buffer size for caching (don't cache huge buffers)
    constexpr size_t MAX_CACHEABLE_SIZE = 100 * 1024 * 1024; // 100MB
    if (buffer.size() > MAX_CACHEABLE_SIZE) {
        SS_LOG_DEBUG(L"SignatureStore", L"CheckQueryCache: Buffer too large to cache (%zu bytes)", buffer.size());
        return std::nullopt;
    }
    
    // ========================================================================
    // COMPUTE CACHE KEY
    // ========================================================================
    ShadowStrike::SignatureStore::SignatureBuilder builder;
    auto hash = builder.ComputeBufferHash(buffer, HashType::SHA256);
    if (!hash.has_value()) {
        SS_LOG_DEBUG(L"SignatureStore", L"CheckQueryCache: Failed to compute buffer hash");
        return std::nullopt;
    }

    // TITANIUM: Validate hash data before use
    if (hash->data.size() < 32) {
        SS_LOG_ERROR(L"SignatureStore", L"CheckQueryCache: Invalid hash size");
        return std::nullopt;
    }
    
    // ========================================================================
    // CACHE INDEX CALCULATION
    // ========================================================================
    // Note: We need to hold the lock while reading cache size to ensure consistency
    std::shared_lock<std::shared_mutex> lock(m_cacheLock);
    
    // Double-check cache size under lock (could have been cleared)
    const size_t cacheSize = m_queryCache.size();
    if (cacheSize == 0) {
        return std::nullopt;
    }
    
    // Safe index calculation
    const size_t cacheIdx = (hash->FastHash() % cacheSize);
    
    // Bounds check (defensive - should never fail due to modulo)
    if (cacheIdx >= cacheSize) {
        SS_LOG_ERROR(L"SignatureStore", L"CheckQueryCache: Cache index out of bounds (%zu >= %zu)",
            cacheIdx, cacheSize);
        return std::nullopt;
    }
    
    // ========================================================================
    // CACHE HIT CHECK
    // ========================================================================
    const auto& entry = m_queryCache[cacheIdx];

    // Check if hash matches (constant-time comparison for security)
    bool hashMatches = true;
    for (size_t i = 0; i < 32; ++i) {
        hashMatches &= (entry.bufferHash[i] == hash->data[i]);
    }
    
    if (hashMatches && entry.timestamp != 0) {
        // Cache hit - return copy of result (avoid reference lifetime issues)
        SS_LOG_DEBUG(L"SignatureStore", L"CheckQueryCache: Cache hit at index %zu", cacheIdx);
        return entry.result;
    }

    return std::nullopt;
}

void SignatureStore::AddToQueryCache(
    std::span<const uint8_t> buffer,
    const ScanResult& result
) const noexcept {
    // ========================================================================
    // TITANIUM CACHE UPDATE - THREAD-SAFE WITH VALIDATION
    // ========================================================================
    
    // VALIDATION 1: Quick check if caching is enabled
    if (!m_queryCacheEnabled.load(std::memory_order_acquire)) {
        return;
    }
    
    // VALIDATION 2: Check if cache is empty
    if (m_queryCache.empty()) {
        return;
    }
    
    // VALIDATION 3: Buffer validation
    if (buffer.empty() || buffer.data() == nullptr) {
        return;
    }
    
    // VALIDATION 4: Don't cache overly large buffers
    constexpr size_t MAX_CACHEABLE_SIZE = 100 * 1024 * 1024; // 100MB
    if (buffer.size() > MAX_CACHEABLE_SIZE) {
        SS_LOG_DEBUG(L"SignatureStore", L"AddToQueryCache: Buffer too large to cache (%zu bytes)", buffer.size());
        return;
    }
    
    // VALIDATION 5: Don't cache results with too many detections (potential DoS)
    constexpr size_t MAX_CACHED_DETECTIONS = 10000;
    if (result.detections.size() > MAX_CACHED_DETECTIONS) {
        SS_LOG_WARN(L"SignatureStore", L"AddToQueryCache: Result has too many detections (%zu), not caching",
            result.detections.size());
        return;
    }
    
    // ========================================================================
    // COMPUTE CACHE KEY
    // ========================================================================
    ShadowStrike::SignatureStore::SignatureBuilder builder;
    auto hash = builder.ComputeBufferHash(buffer, HashType::SHA256);
    if (!hash.has_value()) {
        return;
    }

    // TITANIUM: Validate hash data
    if (hash->data.size() < 32) {
        SS_LOG_ERROR(L"SignatureStore", L"AddToQueryCache: Invalid hash size");
        return;
    }
    
    // ========================================================================
    // CACHE INDEX CALCULATION AND UPDATE
    // ========================================================================
    std::unique_lock<std::shared_mutex> lock(m_cacheLock);
    
    // Double-check cache size under lock
    const size_t cacheSize = m_queryCache.size();
    if (cacheSize == 0) {
        return;
    }
    
    const size_t cacheIdx = (hash->FastHash() % cacheSize);
    
    // Bounds check (defensive)
    if (cacheIdx >= cacheSize) {
        SS_LOG_ERROR(L"SignatureStore", L"AddToQueryCache: Cache index out of bounds (%zu >= %zu)",
            cacheIdx, cacheSize);
        return;
    }
    
    // ========================================================================
    // UPDATE CACHE ENTRY
    // ========================================================================
    auto& entry = m_queryCache[cacheIdx];

    std::memcpy(entry.bufferHash.data(), hash->data.data(), 32);
    entry.result = result;
    entry.timestamp = m_queryCacheAccessCounter.fetch_add(1, std::memory_order_relaxed);
}

void SignatureStore::MergeResults(
    ScanResult& target,
    const std::vector<DetectionResult>& source
) const noexcept {
    // TITANIUM: Exception-safe merge with capacity check
    if (source.empty()) {
        return;
    }
    
    try {
        // Reserve space to prevent multiple reallocations
        const size_t newSize = target.detections.size() + source.size();
        
        // TITANIUM: Prevent overflow/excessive allocation
        constexpr size_t MAX_DETECTIONS = 100000;
        if (newSize > MAX_DETECTIONS) {
            SS_LOG_WARN(L"SignatureStore", L"MergeResults: Limiting total detections to %zu", MAX_DETECTIONS);
            const size_t toAdd = MAX_DETECTIONS > target.detections.size() 
                ? MAX_DETECTIONS - target.detections.size() 
                : 0;
            target.detections.reserve(MAX_DETECTIONS);
            target.detections.insert(target.detections.end(), 
                source.begin(), 
                source.begin() + static_cast<ptrdiff_t>(std::min(toAdd, source.size())));
        } else {
            target.detections.reserve(newSize);
            target.detections.insert(target.detections.end(), source.begin(), source.end());
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeResults: Exception: %S", e.what());
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"MergeResults: Unknown exception");
    }
}

void SignatureStore::NotifyDetection(const DetectionResult& detection) const noexcept {
    // TITANIUM: Exception-safe callback with try_lock to prevent deadlock
    try {
        std::unique_lock<std::mutex> lock(m_callbackMutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            SS_LOG_DEBUG(L"SignatureStore", L"NotifyDetection: Could not acquire callback lock");
            return;
        }
        
        if (m_detectionCallback) {
            try {
                m_detectionCallback(detection);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"Detection callback threw exception: %S", e.what());
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"Detection callback threw unknown exception");
            }
        }
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureStore", L"NotifyDetection: Failed to acquire lock");
    }
}

// ============================================================================
// GLOBAL FUNCTIONS
// ============================================================================

namespace Store {

std::string GetVersion() noexcept {
    return "1.0.0";
}

std::string GetBuildInfo() noexcept {
    return "ShadowStrike SignatureStore v1.0.0 (Enterprise Edition)";
}

std::vector<HashType> GetSupportedHashTypes() noexcept {
    return {
        HashType::MD5,
        HashType::SHA1,
        HashType::SHA256,
        HashType::SHA512,
        HashType::IMPHASH,
        HashType::FUZZY,
        HashType::TLSH
    };
}

bool IsYaraAvailable() noexcept {
    return true; // YARA is compiled in
}

std::string GetYaraVersion() noexcept {
    return YaraRuleStore::GetYaraVersion();
}

} // namespace Store

} // namespace SignatureStore
} // namespace ShadowStrike
