/**
 * CacheDB Usage Examples for Bitdefender ShadowStrike
 * 
 * This file demonstrates real-world usage patterns for the CacheDB system
 * in an enterprise antivirus application.
 */

#include "../src/Database/CacheDB.hpp"
#include "../src/Utils/CacheManager.hpp"

using namespace ShadowStrike::Database;

// ============================================================================
// Example 1: Basic Setup and Configuration
// ============================================================================
void Example_BasicSetup() {
    SS_LOG_INFO(L"Example", L"=== Basic Setup ===");
    
    // Configure CacheDB for production use
    CacheDB::Config config;
    config.cachePath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\Cache";
    config.dbPath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\cache.db";
    
    // Memory settings
    config.maxCacheEntries = 100000;              // 100k entries in memory
    config.maxCacheBytes = 256ULL * 1024 * 1024; // 256MB RAM
    config.defaultTTL = std::chrono::hours(24);   // 24 hour default
    
    // Database settings
    config.enableWAL = true;                      // Write-Ahead Logging
    config.dbCacheSizeKB = 20 * 1024;            // 20MB DB cache
    
    // Strategy: Write-through for data integrity
    config.writeStrategy = CacheDB::WriteStrategy::WriteThrough;
    config.cachePolicy = CacheDB::CachePolicy::CacheFirst;
    
    // Warm-up cache on startup
    config.warmupOnStartup = true;
    config.warmupMaxEntries = 10000;
    
    // Initialize
    DatabaseError err;
    if (!CacheDB::Instance().Initialize(config, &err)) {
        SS_LOG_ERROR(L"Example", L"Initialization failed: %ls", err.message.c_str());
        return;
    }
    
    SS_LOG_INFO(L"Example", L"CacheDB initialized successfully");
}

// ============================================================================
// Example 2: Threat Definition Caching
// ============================================================================
void Example_ThreatCaching() {
    SS_LOG_INFO(L"Example", L"=== Threat Definition Caching ===");
    
    // Simulate storing threat definitions
    struct ThreatDefinition {
        std::wstring hash;
        std::wstring name;
        int severity;
        std::wstring action;
    };
    
    std::vector<ThreatDefinition> threats = {
        {L"a1b2c3d4e5f6", L"Trojan.Win32.Generic", 9, L"Quarantine"},
        {L"f6e5d4c3b2a1", L"Virus.Win32.Sality", 8, L"Remove"},
        {L"1234567890ab", L"Ransomware.Win32.WannaCry", 10, L"Block"}
    };
    
    DatabaseError err;
    
    // Store threat definitions with 48-hour TTL
    for (const auto& threat : threats) {
        std::wstring key = L"threat:hash:" + threat.hash;
        std::wstring value = threat.name + L"|" + 
                            std::to_wstring(threat.severity) + L"|" + 
                            threat.action;
        
        if (CacheDB::Instance().PutString(key, value, std::chrono::hours(48), &err)) {
            SS_LOG_DEBUG(L"Example", L"Stored threat: %ls", threat.name.c_str());
        }
    }
    
    // Fast lookup during file scan
    std::wstring testHash = L"a1b2c3d4e5f6";
    std::wstring key = L"threat:hash:" + testHash;
    std::wstring info;
    
    if (CacheDB::Instance().GetString(key, info, &err)) {
        SS_LOG_INFO(L"Example", L"Threat found: %ls", info.c_str());
        // Process threat (quarantine, block, etc.)
    } else {
        SS_LOG_INFO(L"Example", L"Threat not in cache - query threat database");
    }
}

// ============================================================================
// Example 3: Scan Result Caching
// ============================================================================
void Example_ScanResults() {
    SS_LOG_INFO(L"Example", L"=== Scan Result Caching ===");
    
    // Simulate scan result structure
    struct ScanResult {
        std::wstring filePath;
        bool isThreat;
        std::wstring threatName;
        int64_t scanTime;
        std::vector<uint8_t> metadata;
    };
    
    // Store scan result
    ScanResult result;
    result.filePath = L"C:\\Windows\\System32\\test.exe";
    result.isThreat = false;
    result.threatName = L"Clean";
    result.scanTime = std::time(nullptr);
    result.metadata = {0x01, 0x02, 0x03};
    
    // Serialize (simplified)
    std::vector<uint8_t> serialized;
    serialized.insert(serialized.end(), 
        reinterpret_cast<const uint8_t*>(result.filePath.data()),
        reinterpret_cast<const uint8_t*>(result.filePath.data() + result.filePath.size()));
    serialized.insert(serialized.end(), result.metadata.begin(), result.metadata.end());
    
    std::wstring key = L"scan:" + result.filePath;
    
    DatabaseError err;
    if (CacheDB::Instance().Put(key, serialized, std::chrono::hours(24), &err)) {
        SS_LOG_INFO(L"Example", L"Scan result cached for: %ls", result.filePath.c_str());
    }
    
    // Retrieve cached scan result
    std::vector<uint8_t> cached;
    if (CacheDB::Instance().Get(key, cached, &err)) {
        SS_LOG_INFO(L"Example", L"Retrieved cached scan result (%zu bytes)", cached.size());
        // Use cached result instead of re-scanning
    }
}

// ============================================================================
// Example 4: Batch Operations for Performance
// ============================================================================
void Example_BatchOperations() {
    SS_LOG_INFO(L"Example", L"=== Batch Operations ===");
    
    // Prepare 1000 threat signatures
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> batch;
    batch.reserve(1000);
    
    for (int i = 0; i < 1000; ++i) {
        std::wstring key = L"signature:batch:" + std::to_wstring(i);
        std::vector<uint8_t> signature;
        
        // Generate fake signature
        for (int j = 0; j < 32; ++j) {
            signature.push_back(static_cast<uint8_t>(rand() % 256));
        }
        
        batch.emplace_back(std::move(key), std::move(signature));
    }
    
    // Batch insert (much faster than 1000 individual puts)
    auto start = std::chrono::steady_clock::now();
    
    DatabaseError err;
    if (CacheDB::Instance().PutBatch(batch, std::chrono::hours(48), &err)) {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        SS_LOG_INFO(L"Example", L"Batch inserted 1000 entries in %lld ms", duration.count());
    } else {
        SS_LOG_ERROR(L"Example", L"Batch insert failed: %ls", err.message.c_str());
    }
    
    // Batch retrieve
    std::vector<std::wstring> keys;
    for (int i = 0; i < 10; ++i) {
        keys.push_back(L"signature:batch:" + std::to_wstring(i));
    }
    
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> results;
    if (CacheDB::Instance().GetBatch(keys, results, &err)) {
        SS_LOG_INFO(L"Example", L"Batch retrieved %zu entries", results.size());
    }
}

// ============================================================================
// Example 5: Prefix-Based Management
// ============================================================================
void Example_PrefixOperations() {
    SS_LOG_INFO(L"Example", L"=== Prefix-Based Operations ===");
    
    DatabaseError err;
    
    // Store categorized threats
    CacheDB::Instance().PutString(L"threat:virus:sality", 
        L"Virus.Win32.Sality|Severity:8", std::chrono::hours(48), &err);
    CacheDB::Instance().PutString(L"threat:virus:conficker", 
        L"Worm.Win32.Conficker|Severity:9", std::chrono::hours(48), &err);
    CacheDB::Instance().PutString(L"threat:trojan:emotet", 
        L"Trojan.Win32.Emotet|Severity:9", std::chrono::hours(48), &err);
    CacheDB::Instance().PutString(L"threat:ransomware:wannacry", 
        L"Ransomware.Win32.WannaCry|Severity:10", std::chrono::hours(48), &err);
    
    // Get all virus threats
    auto virusKeys = CacheDB::Instance().GetKeysByPrefix(L"threat:virus:");
    SS_LOG_INFO(L"Example", L"Found %zu virus threats:", virusKeys.size());
    for (const auto& key : virusKeys) {
        std::wstring value;
        if (CacheDB::Instance().GetString(key, value, &err)) {
            SS_LOG_INFO(L"Example", L"  %ls = %ls", key.c_str(), value.c_str());
        }
    }
    
    // Remove all trojan threats
    if (CacheDB::Instance().RemoveByPrefix(L"threat:trojan:", &err)) {
        SS_LOG_INFO(L"Example", L"Removed all trojan threats");
    }
    
    // Pattern matching
    auto allThreats = CacheDB::Instance().GetKeysByPattern(L"threat:%");
    SS_LOG_INFO(L"Example", L"Total threats in cache: %zu", allThreats.size());
}

// ============================================================================
// Example 6: Write Strategy Comparison
// ============================================================================
void Example_WriteStrategies() {
    SS_LOG_INFO(L"Example", L"=== Write Strategy Comparison ===");
    
    const size_t NUM_WRITES = 1000;
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> testData;
    
    // Prepare test data
    for (size_t i = 0; i < NUM_WRITES; ++i) {
        std::wstring key = L"perf:test:" + std::to_wstring(i);
        std::vector<uint8_t> data(1024, static_cast<uint8_t>(i % 256));  // 1KB
        testData.emplace_back(std::move(key), std::move(data));
    }
    
    // Test Write-Through
    {
        CacheDB::Instance().SetWriteStrategy(CacheDB::WriteStrategy::WriteThrough);
        auto start = std::chrono::steady_clock::now();
        
        for (const auto& [key, data] : testData) {
            CacheDB::Instance().Put(key, data, std::chrono::hours(1));
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        SS_LOG_INFO(L"Example", L"Write-Through: %lld ms for %zu writes", 
                    duration.count(), NUM_WRITES);
    }
    
    // Clear
    CacheDB::Instance().RemoveByPrefix(L"perf:test:", nullptr);
    
    // Test Write-Behind
    {
        CacheDB::Instance().SetWriteStrategy(CacheDB::WriteStrategy::WriteBehind);
        auto start = std::chrono::steady_clock::now();
        
        for (const auto& [key, data] : testData) {
            CacheDB::Instance().Put(key, data, std::chrono::hours(1));
        }
        
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        SS_LOG_INFO(L"Example", L"Write-Behind: %lld ms for %zu writes (in-memory only)", 
                    duration.count(), NUM_WRITES);
        
        // Flush to DB
        DatabaseError err;
        start = std::chrono::steady_clock::now();
        CacheDB::Instance().FlushPendingWrites(&err);
        end = std::chrono::steady_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        SS_LOG_INFO(L"Example", L"Flush to database: %lld ms", duration.count());
    }
}

// ============================================================================
// Example 7: Statistics and Monitoring
// ============================================================================
void Example_Statistics() {
    SS_LOG_INFO(L"Example", L"=== Statistics and Monitoring ===");
    
    // Perform some operations
    DatabaseError err;
    for (int i = 0; i < 100; ++i) {
        std::wstring key = L"stats:test:" + std::to_wstring(i);
        std::wstring value = L"Test value " + std::to_wstring(i);
        CacheDB::Instance().PutString(key, value, std::chrono::hours(1), &err);
    }
    
    // Read some (simulate cache hits)
    for (int i = 0; i < 50; ++i) {
        std::wstring key = L"stats:test:" + std::to_wstring(i);
        std::wstring value;
        CacheDB::Instance().GetString(key, value, &err);
    }
    
    // Read non-existent (simulate cache misses)
    for (int i = 200; i < 210; ++i) {
        std::wstring key = L"stats:test:" + std::to_wstring(i);
        std::wstring value;
        CacheDB::Instance().GetString(key, value, &err);
    }
    
    // Get statistics
    auto stats = CacheDB::Instance().GetStatistics();
    
    SS_LOG_INFO(L"Example", L"=== Cache Statistics ===");
    SS_LOG_INFO(L"Example", L"Cache Hits: %llu", stats.cacheHits);
    SS_LOG_INFO(L"Example", L"Cache Misses: %llu", stats.cacheMisses);
    SS_LOG_INFO(L"Example", L"Cache Hit Rate: %.2f%%", stats.cacheHitRate);
    SS_LOG_INFO(L"Example", L"Cache Writes: %llu", stats.cacheWrites);
    SS_LOG_INFO(L"Example", L"Cache Evictions: %llu", stats.cacheEvictions);
    SS_LOG_INFO(L"Example", L"");
    SS_LOG_INFO(L"Example", L"DB Reads: %llu", stats.dbReads);
    SS_LOG_INFO(L"Example", L"DB Writes: %llu", stats.dbWrites);
    SS_LOG_INFO(L"Example", L"DB Deletes: %llu", stats.dbDeletes);
    SS_LOG_INFO(L"Example", L"");
    SS_LOG_INFO(L"Example", L"Current Cache Size: %.2f MB", 
                stats.currentCacheSize / (1024.0 * 1024.0));
    SS_LOG_INFO(L"Example", L"Max Cache Size: %.2f MB", 
                stats.maxCacheSize / (1024.0 * 1024.0));
    SS_LOG_INFO(L"Example", L"DB Size: %.2f MB", 
                stats.dbSize / (1024.0 * 1024.0));
}

// ============================================================================
// Example 8: Maintenance Operations
// ============================================================================
void Example_Maintenance() {
    SS_LOG_INFO(L"Example", L"=== Maintenance Operations ===");
    
    DatabaseError err;
    
    // Check database integrity
    if (CacheDB::Instance().CheckIntegrity(&err)) {
        SS_LOG_INFO(L"Example", L"✓ Database integrity: OK");
    } else {
        SS_LOG_ERROR(L"Example", L"✗ Database integrity: FAILED");
    }
    
    // Optimize database (remove expired, analyze, etc.)
    SS_LOG_INFO(L"Example", L"Running optimization...");
    if (CacheDB::Instance().Optimize(&err)) {
        SS_LOG_INFO(L"Example", L"✓ Database optimized");
    }
    
    // Vacuum to reclaim space
    SS_LOG_INFO(L"Example", L"Running vacuum...");
    if (CacheDB::Instance().Vacuum(&err)) {
        SS_LOG_INFO(L"Example", L"✓ Database vacuumed");
    }
    
    // Sync cache with database
    SS_LOG_INFO(L"Example", L"Synchronizing cache...");
    if (CacheDB::Instance().Sync(&err)) {
        SS_LOG_INFO(L"Example", L"✓ Cache synchronized");
    }
}

// ============================================================================
// Example 9: Multi-Threaded Access
// ============================================================================
void Example_MultiThreaded() {
    SS_LOG_INFO(L"Example", L"=== Multi-Threaded Access ===");
    
    const int NUM_THREADS = 10;
    const int OPS_PER_THREAD = 100;
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    auto workerFunc = [&](int threadId) {
        DatabaseError err;
        int localSuccess = 0;
        
        for (int i = 0; i < OPS_PER_THREAD; ++i) {
            std::wstring key = L"thread:" + std::to_wstring(threadId) + 
                              L":op:" + std::to_wstring(i);
            std::wstring value = L"Data from thread " + std::to_wstring(threadId);
            
            // Write
            if (CacheDB::Instance().PutString(key, value, std::chrono::minutes(30), &err)) {
                // Read back
                std::wstring retrieved;
                if (CacheDB::Instance().GetString(key, retrieved, &err)) {
                    if (retrieved == value) {
                        localSuccess++;
                    }
                }
            }
        }
        
        successCount.fetch_add(localSuccess, std::memory_order_relaxed);
    };
    
    // Start threads
    auto start = std::chrono::steady_clock::now();
    
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back(workerFunc, i);
    }
    
    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    int totalOps = NUM_THREADS * OPS_PER_THREAD;
    SS_LOG_INFO(L"Example", L"Multi-threaded test completed:");
    SS_LOG_INFO(L"Example", L"  Threads: %d", NUM_THREADS);
    SS_LOG_INFO(L"Example", L"  Total Operations: %d", totalOps);
    SS_LOG_INFO(L"Example", L"  Successful: %d", successCount.load());
    SS_LOG_INFO(L"Example", L"  Time: %lld ms", duration.count());
    SS_LOG_INFO(L"Example", L"  Throughput: %.2f ops/sec", 
                (totalOps * 1000.0) / duration.count());
}

// ============================================================================
// Example 10: Graceful Shutdown
// ============================================================================
void Example_Shutdown() {
    SS_LOG_INFO(L"Example", L"=== Graceful Shutdown ===");
    
    // Get final statistics
    auto stats = CacheDB::Instance().GetStatistics();
    SS_LOG_INFO(L"Example", L"Final statistics:");
    SS_LOG_INFO(L"Example", L"  Total cache hits: %llu", stats.cacheHits);
    SS_LOG_INFO(L"Example", L"  Total DB operations: %llu", 
                stats.dbReads + stats.dbWrites + stats.dbDeletes);
    
    // Flush any pending writes
    DatabaseError err;
    SS_LOG_INFO(L"Example", L"Flushing pending writes...");
    if (CacheDB::Instance().FlushPendingWrites(&err)) {
        SS_LOG_INFO(L"Example", L"✓ Pending writes flushed");
    }
    
    // Shutdown
    SS_LOG_INFO(L"Example", L"Shutting down CacheDB...");
    CacheDB::Instance().Shutdown();
    SS_LOG_INFO(L"Example", L"✓ CacheDB shut down gracefully");
}

// ============================================================================
// Main Example Runner
// ============================================================================
void RunAllCacheDBExamples() {
    SS_LOG_INFO(L"Examples", L"========================================");
    SS_LOG_INFO(L"Examples", L"  CacheDB Examples for ShadowStrike");
    SS_LOG_INFO(L"Examples", L"========================================");
    SS_LOG_INFO(L"Examples", L"");
    
    Example_BasicSetup();
    Example_ThreatCaching();
    Example_ScanResults();
    Example_BatchOperations();
    Example_PrefixOperations();
    Example_WriteStrategies();
    Example_Statistics();
    Example_Maintenance();
    Example_MultiThreaded();
    Example_Shutdown();
    
    SS_LOG_INFO(L"Examples", L"");
    SS_LOG_INFO(L"Examples", L"========================================");
    SS_LOG_INFO(L"Examples", L"  All examples completed successfully");
    SS_LOG_INFO(L"Examples", L"========================================");
}
