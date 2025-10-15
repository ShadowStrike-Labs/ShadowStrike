# CacheDB - Hybrid Caching System for ShadowStrike Security

## Overview

**CacheDB** is a high-performance, hybrid caching system that combines the speed of in-memory caching with the persistence of database storage. It's specifically designed for  ShadowStrike antivirus application to provide:

- **Fast access** to frequently used data (memory cache)
- **Persistence** across application restarts (database storage)
- **Flexibility** with multiple caching strategies
- **Reliability** with ACID transactions and data integrity

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
└─────────────────────┬───────────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │       CacheDB API       │
         └────────────┬────────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
┌───────▼────────┐         ┌────────▼────────┐
│  CacheManager  │         │ DatabaseManager │
│  (In-Memory)   │         │   (SQLite DB)   │
└────────────────┘         └─────────────────┘
```

### Components

1. **CacheDB** (API Layer)
   - Unified interface for caching operations
   - Strategy management (write-through, write-back, write-behind)
   - Statistics and monitoring
   - Batch operations

2. **CacheManager** (Memory Layer)
   - LRU eviction policy
   - TTL support with sliding expiration
   - Fast in-memory access
   - Optional persistence to disk

3. **DatabaseManager** (Persistence Layer)
   - SQLite database backend
   - ACID transactions
   - Full-text search capabilities
   - Connection pooling

## Features

### Caching Strategies

#### 1. Write-Through (Default)
- Writes go to both cache and database **immediately**
- **Pros**: Data consistency, immediate persistence
- **Cons**: Slower writes (waits for DB)
- **Best for**: Critical data that must be persisted

```cpp
config.writeStrategy = CacheDB::WriteStrategy::WriteThrough;
```

#### 2. Write-Back
- Writes go to cache **immediately**, database **asynchronously**
- **Pros**: Fast writes, good for bursts
- **Cons**: Potential data loss if crash before flush
- **Best for**: High-frequency updates, less critical data

```cpp
config.writeStrategy = CacheDB::WriteStrategy::WriteBack;
```

#### 3. Write-Behind
- Writes go to cache immediately, batched to database
- **Pros**: Fastest writes, reduced DB load
- **Cons**: Higher data loss risk
- **Best for**: Analytics, logging, non-critical data

```cpp
config.writeStrategy = CacheDB::WriteStrategy::WriteBehind;
config.writeBehindBatchSize = 100;
config.writeBehindFlushInterval = std::chrono::seconds(5);
```

### Cache Policies

#### 1. Cache-First (Default)
- Try memory cache first
- Fallback to database on miss
- Populate cache with DB data
- **Best for**: Most use cases

#### 2. Database-First
- Always query database
- Update cache after DB read
- **Best for**: Frequently changing data

#### 3. Cache-Only
- Only use memory cache
- No database reads
- **Best for**: Temporary session data

#### 4. Database-Only
- Bypass memory cache entirely
- Direct database access
- **Best for**: Large blobs, audit logs

## Database Schema

```sql
CREATE TABLE cache_entries (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL,
    expire_timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    accessed_at INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE INDEX idx_cache_expire ON cache_entries(expire_timestamp);
CREATE INDEX idx_cache_accessed ON cache_entries(accessed_at DESC);
```

## Usage Examples

### Basic Initialization

```cpp
using namespace ShadowStrike::Database;

// Configure CacheDB
CacheDB::Config config;
config.cachePath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\Cache";
config.dbPath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\cache.db";
config.maxCacheEntries = 100000;
config.maxCacheBytes = 256ULL * 1024 * 1024;  // 256MB
config.writeStrategy = CacheDB::WriteStrategy::WriteThrough;
config.cachePolicy = CacheDB::CachePolicy::CacheFirst;
config.warmupOnStartup = true;

// Initialize
DatabaseError err;
if (!CacheDB::Instance().Initialize(config, &err)) {
    SS_LOG_ERROR(L"App", L"Failed to initialize CacheDB: %ls", err.message.c_str());
    return false;
}

SS_LOG_INFO(L"App", L"CacheDB initialized successfully");
```

### Storing and Retrieving Data

#### Binary Data
```cpp
// Store binary data
std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
std::wstring key = L"malware_signature_123";

DatabaseError err;
if (!CacheDB::Instance().Put(key, data, std::chrono::hours(24), &err)) {
    SS_LOG_ERROR(L"App", L"Put failed: %ls", err.message.c_str());
}

// Retrieve binary data
std::vector<uint8_t> retrieved;
if (CacheDB::Instance().Get(key, retrieved, &err)) {
    SS_LOG_INFO(L"App", L"Retrieved %zu bytes", retrieved.size());
} else {
    SS_LOG_ERROR(L"App", L"Get failed: %ls", err.message.c_str());
}
```

#### String Data
```cpp
// Store string
std::wstring key = L"threat_info_trojan_abc";
std::wstring value = L"Trojan.Win32.Generic - High severity threat";

if (CacheDB::Instance().PutString(key, value, std::chrono::hours(12))) {
    SS_LOG_INFO(L"App", L"String stored successfully");
}

// Retrieve string
std::wstring retrieved;
if (CacheDB::Instance().GetString(key, retrieved)) {
    SS_LOG_INFO(L"App", L"Retrieved: %ls", retrieved.c_str());
}
```

### Batch Operations

```cpp
// Prepare batch data
std::vector<std::pair<std::wstring, std::vector<uint8_t>>> entries;

for (int i = 0; i < 1000; ++i) {
    std::wstring key = L"scan_result_" + std::to_wstring(i);
    std::vector<uint8_t> data = generateScanResult(i);
    entries.emplace_back(std::move(key), std::move(data));
}

// Batch insert (much faster than individual puts)
DatabaseError err;
if (CacheDB::Instance().PutBatch(entries, std::chrono::hours(24), &err)) {
    SS_LOG_INFO(L"App", L"Batch inserted %zu entries", entries.size());
}

// Batch retrieve
std::vector<std::wstring> keys = {L"scan_result_0", L"scan_result_1", L"scan_result_2"};
std::vector<std::pair<std::wstring, std::vector<uint8_t>>> results;

if (CacheDB::Instance().GetBatch(keys, results, &err)) {
    SS_LOG_INFO(L"App", L"Retrieved %zu entries", results.size());
}
```

### Prefix-Based Operations

```cpp
// Store threat definitions with common prefix
CacheDB::Instance().PutString(L"threat:virus:sality", L"...", std::chrono::hours(48));
CacheDB::Instance().PutString(L"threat:virus:conficker", L"...", std::chrono::hours(48));
CacheDB::Instance().PutString(L"threat:trojan:emotet", L"...", std::chrono::hours(48));

// Get all virus threats
auto virusKeys = CacheDB::Instance().GetKeysByPrefix(L"threat:virus:");
SS_LOG_INFO(L"App", L"Found %zu virus threats", virusKeys.size());

// Remove all trojan threats
DatabaseError err;
if (CacheDB::Instance().RemoveByPrefix(L"threat:trojan:", &err)) {
    SS_LOG_INFO(L"App", L"Removed all trojan threats");
}
```

### Pattern Matching (SQL LIKE)

```cpp
// Find all entries matching pattern
auto keys = CacheDB::Instance().GetKeysByPattern(L"scan_result_%");
SS_LOG_INFO(L"App", L"Found %zu scan results", keys.size());

// Wildcard in middle
auto keys2 = CacheDB::Instance().GetKeysByPattern(L"threat:_:emotet");
```

### Cache Management

```cpp
DatabaseError err;

// Force flush pending writes (write-back/write-behind)
if (CacheDB::Instance().FlushPendingWrites(&err)) {
    SS_LOG_INFO(L"App", L"Flushed pending writes to database");
}

// Synchronize cache with database
if (CacheDB::Instance().Sync(&err)) {
    SS_LOG_INFO(L"App", L"Cache synchronized");
}

// Refresh cache from database (clears memory, reloads from DB)
if (CacheDB::Instance().RefreshCache(&err)) {
    SS_LOG_INFO(L"App", L"Cache refreshed from database");
}

// Invalidate specific entry
CacheDB::Instance().InvalidateCache(L"threat:virus:old_signature");

// Warm up cache on demand
if (CacheDB::Instance().WarmUpCache(10000, &err)) {
    SS_LOG_INFO(L"App", L"Cache warmed up with top 10k entries");
}
```

### Statistics and Monitoring

```cpp
auto stats = CacheDB::Instance().GetStatistics();

SS_LOG_INFO(L"Stats", L"Cache Performance:");
SS_LOG_INFO(L"Stats", L"  Cache Hits: %llu", stats.cacheHits);
SS_LOG_INFO(L"Stats", L"  Cache Misses: %llu", stats.cacheMisses);
SS_LOG_INFO(L"Stats", L"  Hit Rate: %.2f%%", stats.cacheHitRate);
SS_LOG_INFO(L"Stats", L"  Cache Size: %zu bytes", stats.currentCacheSize);
SS_LOG_INFO(L"Stats", L"  DB Size: %llu bytes", stats.dbSize);
SS_LOG_INFO(L"Stats", L"  DB Reads: %llu", stats.dbReads);
SS_LOG_INFO(L"Stats", L"  DB Writes: %llu", stats.dbWrites);

// Reset statistics
CacheDB::Instance().ResetStatistics();
```

### Maintenance Operations

```cpp
DatabaseError err;

// Check database integrity
if (CacheDB::Instance().CheckIntegrity(&err)) {
    SS_LOG_INFO(L"Maint", L"Database integrity: OK");
} else {
    SS_LOG_ERROR(L"Maint", L"Database corruption detected!");
}

// Optimize database (analyze, delete expired, etc.)
if (CacheDB::Instance().Optimize(&err)) {
    SS_LOG_INFO(L"Maint", L"Database optimized");
}

// Vacuum database (reclaim space)
if (CacheDB::Instance().Vacuum(&err)) {
    SS_LOG_INFO(L"Maint", L"Database vacuumed");
}
```

### Dynamic Strategy Changes

```cpp
// Change strategy at runtime
CacheDB::Instance().SetWriteStrategy(CacheDB::WriteStrategy::WriteBehind);
CacheDB::Instance().SetCachePolicy(CacheDB::CachePolicy::CacheFirst);

// Get current configuration
auto config = CacheDB::Instance().GetConfig();
SS_LOG_INFO(L"Config", L"Max cache entries: %zu", config.maxCacheEntries);
```

## Real-World Use Cases for Antivirus

### 1. Threat Definition Caching

```cpp
// Store threat definitions
std::wstring key = L"threat:sha256:" + fileHash;
std::wstring threatInfo = L"Trojan.Win32.Generic|Severity:9|Action:Quarantine";

CacheDB::Instance().PutString(key, threatInfo, std::chrono::hours(48));

// Quick lookup during scan
std::wstring info;
if (CacheDB::Instance().GetString(key, info)) {
    // Threat found in cache - fast!
    processThreat(info);
} else {
    // Not in cache - query cloud/definitions
    info = queryThreatDatabase(fileHash);
    CacheDB::Instance().PutString(key, info, std::chrono::hours(48));
}
```

### 2. Scan Result Caching

```cpp
// Cache scan results per file
std::wstring fileKey = L"scan:" + filePath;
ScanResult result = performDetailedScan(filePath);

// Serialize result
std::vector<uint8_t> serialized = serializeScanResult(result);
CacheDB::Instance().Put(fileKey, serialized, std::chrono::hours(24));

// Next scan - check cache first
std::vector<uint8_t> cached;
if (CacheDB::Instance().Get(fileKey, cached)) {
    ScanResult result = deserializeScanResult(cached);
    if (!fileModifiedSince(result.scanTime)) {
        return result;  // Use cached result
    }
}
```

### 3. Whitelist/Blacklist

```cpp
// Whitelist known-good files
std::wstring whitelistKey = L"whitelist:" + fileHash;
CacheDB::Instance().PutString(whitelistKey, L"Microsoft Corporation|Signed", 
                               std::chrono::hours(72));

// Fast whitelist check
if (CacheDB::Instance().Contains(whitelistKey)) {
    // File is whitelisted - skip scanning
    return ScanResult::Safe;
}

// Blacklist known threats
std::wstring blacklistKey = L"blacklist:" + fileHash;
CacheDB::Instance().PutString(blacklistKey, L"Known Malware", 
                               std::chrono::hours(168));  // 1 week
```

### 4. Configuration Caching

```cpp
// Cache expensive-to-compute configurations
std::wstring configKey = L"config:scan_settings";
std::wstring settings = loadAndValidateSettings();

CacheDB::Instance().PutString(configKey, settings, std::chrono::minutes(30));

// Retrieve cached config
std::wstring cached;
if (!CacheDB::Instance().GetString(configKey, cached)) {
    cached = loadAndValidateSettings();
    CacheDB::Instance().PutString(configKey, cached, std::chrono::minutes(30));
}
```

### 5. Temporary Session Data

```cpp
// Use cache-only policy for session data
CacheDB::Instance().SetCachePolicy(CacheDB::CachePolicy::CacheOnly);

std::wstring sessionKey = L"session:" + sessionId;
std::wstring sessionData = serializeSession(currentSession);

CacheDB::Instance().PutString(sessionKey, sessionData, std::chrono::minutes(60));

// Session data only in memory - not persisted
```

## Performance Tuning

### Memory Configuration

```cpp
// For systems with limited memory
config.maxCacheBytes = 64ULL * 1024 * 1024;  // 64MB
config.maxCacheEntries = 10000;

// For high-memory systems
config.maxCacheBytes = 1024ULL * 1024 * 1024;  // 1GB
config.maxCacheEntries = 500000;
```

### Write Strategy Selection

```cpp
// Critical data (virus definitions)
config.writeStrategy = CacheDB::WriteStrategy::WriteThrough;

// High-frequency data (scan results)
config.writeStrategy = CacheDB::WriteStrategy::WriteBehind;
config.writeBehindBatchSize = 1000;
config.writeBehindFlushInterval = std::chrono::seconds(10);
```

### Database Optimization

```cpp
// Enable WAL mode for better concurrency
config.enableWAL = true;

// Increase DB cache
config.dbCacheSizeKB = 50 * 1024;  // 50MB

// Periodic maintenance
std::thread maintenanceThread([]() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::hours(1));
        
        DatabaseError err;
        CacheDB::Instance().Optimize(&err);
    }
});
```

## Best Practices

### 1. Always Handle Errors

```cpp
DatabaseError err;
if (!CacheDB::Instance().Put(key, data, ttl, &err)) {
    SS_LOG_ERROR(L"App", L"Cache put failed: %ls (code: %d)", 
                 err.message.c_str(), err.sqliteCode);
    // Implement fallback logic
}
```

### 2. Choose Appropriate TTL

```cpp
// Short TTL for volatile data
CacheDB::Instance().Put(key, data, std::chrono::minutes(5));

// Long TTL for stable data
CacheDB::Instance().Put(key, data, std::chrono::days(7));

// Permanent (very long TTL)
CacheDB::Instance().Put(key, data, std::chrono::hours(24 * 365));
```

### 3. Use Batch Operations

```cpp
// ❌ BAD: Individual operations
for (const auto& entry : entries) {
    CacheDB::Instance().Put(entry.key, entry.data, ttl);  // Slow!
}

// ✅ GOOD: Batch operation
CacheDB::Instance().PutBatch(entries, ttl);  // Much faster!
```

### 4. Prefix Your Keys

```cpp
// Organize keys hierarchically
L"threat:virus:name"
L"threat:trojan:name"
L"scan:file:path"
L"config:setting:name"

// Easy to find and remove groups
auto allThreats = CacheDB::Instance().GetKeysByPrefix(L"threat:");
```

### 5. Monitor Statistics

```cpp
// Regularly check hit rate
auto stats = CacheDB::Instance().GetStatistics();
if (stats.cacheHitRate < 50.0) {
    SS_LOG_WARN(L"Perf", L"Low cache hit rate: %.2f%%", stats.cacheHitRate);
    // Consider increasing cache size or adjusting TTL
}
```

### 6. Graceful Shutdown

```cpp
// Before application exit
DatabaseError err;
CacheDB::Instance().FlushPendingWrites(&err);  // Ensure all writes complete
CacheDB::Instance().Shutdown();                 // Clean shutdown
```

## Thread Safety

CacheDB is **fully thread-safe**:

```cpp
// Multiple threads can safely access CacheDB
std::vector<std::thread> threads;

for (int i = 0; i < 10; ++i) {
    threads.emplace_back([i]() {
        std::wstring key = L"thread_" + std::to_wstring(i);
        std::vector<uint8_t> data = generateData();
        
        CacheDB::Instance().Put(key, data, std::chrono::hours(1));
        
        std::vector<uint8_t> retrieved;
        CacheDB::Instance().Get(key, retrieved);
    });
}

for (auto& t : threads) {
    t.join();
}
```

## Error Handling

### Error Codes

```cpp
DatabaseError err;
if (!CacheDB::Instance().Put(key, data, ttl, &err)) {
    switch (err.sqliteCode) {
        case SQLITE_FULL:
            SS_LOG_ERROR(L"DB", L"Database full!");
            // Clean up old entries
            break;
            
        case SQLITE_BUSY:
            SS_LOG_WARN(L"DB", L"Database busy, retrying...");
            // Retry after delay
            break;
            
        case SQLITE_CORRUPT:
            SS_LOG_FATAL(L"DB", L"Database corrupted!");
            // Restore from backup
            break;
            
        default:
            SS_LOG_ERROR(L"DB", L"Unknown error: %d", err.sqliteCode);
            break;
    }
}
```

## Troubleshooting

### High Memory Usage

```cpp
// Reduce cache size
CacheDB::Instance().SetMaxBytes(128ULL * 1024 * 1024);  // 128MB

// Force eviction
CacheDB::Instance().InvalidateAllCache();
```

### Slow Performance

```cpp
// Check statistics
auto stats = CacheDB::Instance().GetStatistics();
SS_LOG_INFO(L"Perf", L"Avg cache read: %lld ms", stats.avgCacheReadTime.count());
SS_LOG_INFO(L"Perf", L"Avg DB read: %lld ms", stats.avgDbReadTime.count());

// Optimize database
DatabaseError err;
CacheDB::Instance().Optimize(&err);

// Increase cache size
// Adjust write strategy
```

### Database Lock Errors

```cpp
// Use write-behind to reduce contention
config.writeStrategy = CacheDB::WriteStrategy::WriteBehind;

// Or increase busy timeout
DatabaseConfig dbConfig;
dbConfig.busyTimeoutMs = 60000;  // 60 seconds
```

---

**Version**: 1.0  
**Last Updated**: 2025  
**Maintained by**: ShadowStrike Team
