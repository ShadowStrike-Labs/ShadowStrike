# DatabaseManager - Production-Ready Database Module for ShadowStrike

## Overview

The `DatabaseManager` is an enterprise-grade database management system built specifically for  ShadowStrike antivirus project. It provides a robust, thread-safe, and high-performance interface to SQLite databases with advanced features required for security applications.

## Key Features

### 1. **Enterprise-Grade Architecture**
- Singleton pattern for global access
- Connection pooling for optimal resource utilization
- Prepared statement caching for performance
- Full thread-safety with minimal lock contention
- RAII-based transaction management

### 2. **Security Features**
- Parameterized queries (SQL injection prevention)
- Secure delete (data overwriting)
- Integrity checking
- Automated backups with rotation
- Support for database encryption (SQLCipher ready)

### 3. **Performance Optimization**
- Write-Ahead Logging (WAL) for better concurrency
- Memory-mapped I/O
- Configurable cache sizes
- Prepared statement caching
- Batch insert operations

### 4. **Reliability**
- ACID-compliant transactions
- Savepoint support
- Automatic rollback on errors
- Database integrity checks
- Corruption detection

## Architecture Components

### Core Classes

#### `DatabaseManager`
Main singleton class that manages all database operations.

```cpp
static DatabaseManager& Instance();
bool Initialize(const DatabaseConfig& config, DatabaseError* err = nullptr);
void Shutdown();
```

#### `ConnectionPool`
Manages a pool of database connections for efficient resource usage.

- Maintains minimum and maximum connection limits
- Automatic connection creation on demand
- Connection timeout handling
- Graceful shutdown

#### `PreparedStatementCache`
LRU cache for prepared statements to improve query performance.

- Automatic eviction of least-recently-used statements
- Configurable cache size
- Thread-safe access

#### `Transaction` (RAII)
Automatic transaction management with commit/rollback.

```cpp
auto trans = db.BeginTransaction();
// ... database operations ...
trans->Commit();  // or automatic rollback on destruction
```

#### `QueryResult`
Type-safe result set iteration.

```cpp
auto result = db.Query("SELECT * FROM threats");
while (result.Next()) {
    int64_t id = result.GetInt64("id");
    std::wstring name = result.GetWString("name");
}
```

## Configuration

### DatabaseConfig Structure

```cpp
struct DatabaseConfig {
    // File paths
    std::wstring databasePath;
    std::wstring backupDirectory;
    
    // Performance settings
    bool enableWAL = true;
    size_t pageSizeBytes = 4096;
    size_t cacheSizeKB = 10240;
    size_t mmapSizeMB = 256;
    int busyTimeoutMs = 30000;
    
    // Connection pooling
    size_t maxConnections = 10;
    size_t minConnections = 2;
    std::chrono::milliseconds connectionTimeout = std::chrono::seconds(30);
    
    // Security
    bool enableForeignKeys = true;
    bool enableSecureDelete = true;
    bool encryptionEnabled = false;
    std::vector<uint8_t> encryptionKey;
    
    // Backup
    bool autoBackup = true;
    std::chrono::hours backupInterval = std::chrono::hours(24);
    size_t maxBackupCount = 7;
    
    // SQLite pragmas
    std::wstring journalMode = L"WAL";
    std::wstring synchronousMode = L"NORMAL";
};
```

### Recommended Production Settings

```cpp
DatabaseConfig config;
config.databasePath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\av.db";
config.enableWAL = true;              // Essential for concurrent access
config.enableSecureDelete = true;     // Security requirement
config.cacheSizeKB = 20480;          // 20MB for better performance
config.maxConnections = 10;           // Based on expected concurrent users
config.backupInterval = std::chrono::hours(24);  // Daily backups
```

## Database Schema

### Threat Definitions Table
Stores malware signatures and patterns.

```sql
CREATE TABLE threat_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    severity INTEGER NOT NULL DEFAULT 0,
    signature BLOB,
    pattern TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
```

### Scan History Table
Records of completed scans.

```sql
CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    scan_path TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
```

### Detected Threats Table
Individual threats found during scans.

```sql
CREATE TABLE detected_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    file_path TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    action_taken TEXT,
    file_hash TEXT,
    file_size INTEGER,
    detected_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
);
```

### Quarantine Table
Files in quarantine.

```sql
CREATE TABLE quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    file_hash TEXT,
    file_size INTEGER,
    quarantined_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    restored BOOLEAN DEFAULT 0,
    restored_at INTEGER
);
```

### Whitelist Table
Trusted files and paths.

```sql
CREATE TABLE whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    reason TEXT,
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
```

### System Events Table
Application events and logs.

```sql
CREATE TABLE system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
```

## Common Operations

### 1. Inserting Data

#### Single Insert (Parameterized)
```cpp
DatabaseError err;
bool success = DatabaseManager::Instance().ExecuteWithParams(
    "INSERT INTO threat_definitions (name, type, severity) VALUES (?, ?, ?)",
    &err,
    "Trojan.Win32.Generic",
    "Trojan",
    5
);
```

#### Batch Insert (High Performance)
```cpp
struct ThreatData {
    std::string name;
    std::string type;
    int severity;
};

std::vector<ThreatData> threats = { /* ... */ };

bool success = DatabaseManager::Instance().BatchInsert(
    "threat_definitions",
    {"name", "type", "severity"},
    threats.size(),
    [&threats](SQLite::Statement& stmt, size_t row) {
        stmt.bind(1, threats[row].name);
        stmt.bind(2, threats[row].type);
        stmt.bind(3, threats[row].severity);
    },
    &err
);
```

### 2. Querying Data

#### Simple Query
```cpp
auto result = DatabaseManager::Instance().Query(
    "SELECT * FROM threat_definitions ORDER BY severity DESC"
);

while (result.Next()) {
    int64_t id = result.GetInt64("id");
    std::wstring name = result.GetWString("name");
    int severity = result.GetInt("severity");
    // Process results...
}
```

#### Parameterized Query
```cpp
auto result = DatabaseManager::Instance().QueryWithParams(
    "SELECT * FROM detected_threats WHERE scan_id = ? AND severity >= ?",
    &err,
    scanId,
    5
);
```

### 3. Transactions

#### Basic Transaction
```cpp
auto trans = DatabaseManager::Instance().BeginTransaction();
if (!trans || !trans->IsActive()) {
    // Handle error
    return;
}

// Perform operations...
DatabaseManager::Instance().ExecuteWithParams(...);

if (trans->Commit(&err)) {
    // Success
} else {
    // Automatic rollback on error
}
```

#### Transaction with Savepoints
```cpp
auto trans = DatabaseManager::Instance().BeginTransaction();

// Operation 1
DatabaseManager::Instance().Execute("...");

// Create savepoint before risky operation
trans->CreateSavepoint("checkpoint");

// Risky operation
if (!DatabaseManager::Instance().Execute("...")) {
    trans->RollbackToSavepoint("checkpoint");
} else {
    trans->ReleaseSavepoint("checkpoint");
}

trans->Commit();
```

### 4. Working with BLOBs

```cpp
// Store binary data
std::vector<uint8_t> signature = {0x4D, 0x5A, 0x90, 0x00};
DatabaseManager::Instance().ExecuteWithParams(
    "UPDATE threat_definitions SET signature = ? WHERE id = ?",
    &err,
    signature,
    threatId
);

// Retrieve binary data
auto result = DatabaseManager::Instance().QueryWithParams(
    "SELECT signature FROM threat_definitions WHERE id = ?",
    &err,
    threatId
);

if (result.Next()) {
    std::vector<uint8_t> sig = result.GetBlob("signature");
}
```

## Maintenance Operations

### Database Integrity Check
```cpp
std::vector<std::wstring> issues;
if (!DatabaseManager::Instance().CheckIntegrity(issues, &err)) {
    for (const auto& issue : issues) {
        SS_LOG_ERROR(L"DB", L"Integrity issue: %ls", issue.c_str());
    }
}
```

### Optimization
```cpp
// Analyze and optimize
DatabaseManager::Instance().Analyze();
DatabaseManager::Instance().Optimize();
```

### Vacuum (Reclaim Space)
```cpp
DatabaseManager::Instance().Vacuum();
```

### Manual Backup
```cpp
std::wstring backupPath = L"C:\\Backups\\av_backup.db";
DatabaseManager::Instance().BackupToFile(backupPath, &err);
```

### Restore from Backup
```cpp
DatabaseManager::Instance().RestoreFromFile(backupPath, &err);
```

## Error Handling

### DatabaseError Structure
```cpp
struct DatabaseError {
    int sqliteCode;           // SQLite error code
    int extendedCode;         // Extended error code
    std::wstring message;     // Human-readable message
    std::wstring query;       // Query that caused error
    std::wstring context;     // Context information
    
    bool HasError() const;
    void Clear();
};
```

### Proper Error Handling
```cpp
DatabaseError err;
if (!DatabaseManager::Instance().Execute("...", &err)) {
    SS_LOG_ERROR(L"DB", L"Operation failed: %ls (code: %d, context: %ls)",
                 err.message.c_str(), err.sqliteCode, err.context.c_str());
    
    // Take corrective action based on error code
    switch (err.sqliteCode) {
        case SQLITE_BUSY:
            // Retry after delay
            break;
        case SQLITE_CORRUPT:
            // Restore from backup
            break;
        // ... handle other cases
    }
}
```

## Performance Considerations

### 1. Use Transactions for Multiple Operations
```cpp
// SLOW: Multiple individual operations
for (int i = 0; i < 1000; ++i) {
    db.Execute("INSERT INTO ...");  // Each is a separate transaction
}

// FAST: Single transaction
auto trans = db.BeginTransaction();
for (int i = 0; i < 1000; ++i) {
    db.Execute("INSERT INTO ...");
}
trans->Commit();  // 100x faster!
```

### 2. Use Prepared Statements for Repeated Queries
The statement cache handles this automatically, but for best performance:

```cpp
// Good: Parameterized query (cached automatically)
for (int i = 0; i < 1000; ++i) {
    db.ExecuteWithParams("INSERT INTO threats VALUES (?)", &err, data[i]);
}
```

### 3. Use Batch Inserts
```cpp
db.BatchInsert("table", {"col1", "col2"}, rowCount, bindFunc);
// Much faster than individual inserts
```

### 4. Create Appropriate Indices
```cpp
db.Execute("CREATE INDEX IF NOT EXISTS idx_threats_name ON threat_definitions(name)");
db.Execute("CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_history(start_time DESC)");
```

### 5. Monitor Performance
```cpp
auto stats = DatabaseManager::Instance().GetStats();
SS_LOG_INFO(L"DB", L"Total queries: %lld, DB size: %llu bytes",
            stats.totalQueries, stats.totalSize);
```

## Schema Migration

### Version Tracking
```cpp
int currentVersion = DatabaseManager::Instance().GetSchemaVersion();
SS_LOG_INFO(L"DB", L"Current schema version: %d", currentVersion);
```

### Upgrade Schema
```cpp
const int TARGET_VERSION = 2;
if (currentVersion < TARGET_VERSION) {
    if (DatabaseManager::Instance().UpgradeSchema(currentVersion, TARGET_VERSION, &err)) {
        SS_LOG_INFO(L"DB", L"Schema upgraded to version %d", TARGET_VERSION);
    }
}
```

### Implementing Migrations
Edit `DatabaseManager::executeSchemaMigration()`:

```cpp
switch (version) {
    case 1:
        // Initial schema (already created)
        break;
        
    case 2:
        // Add new column
        db.exec("ALTER TABLE threat_definitions ADD COLUMN risk_score INTEGER DEFAULT 0");
        db.exec("CREATE INDEX idx_risk_score ON threat_definitions(risk_score)");
        break;
        
    case 3:
        // Add new table
        db.exec("CREATE TABLE threat_categories (...)");
        break;
}
```

## Thread Safety

### Concurrent Access Patterns

#### Multiple Readers (Safe)
```cpp
// Thread 1
auto result1 = db.Query("SELECT * FROM threats WHERE type = 'Virus'");

// Thread 2 (simultaneous)
auto result2 = db.Query("SELECT * FROM threats WHERE type = 'Trojan'");
```

#### Reader + Writer (Safe with WAL)
```cpp
// Thread 1 (Reading)
auto result = db.Query("SELECT * FROM threats");

// Thread 2 (Writing - concurrent with WAL enabled)
db.Execute("INSERT INTO threats ...");
```

#### Multiple Writers (Serialized by SQLite)
```cpp
// Thread 1
db.Execute("INSERT INTO threats ...");

// Thread 2 (waits for Thread 1 to complete)
db.Execute("UPDATE threats ...");
```

## Security Best Practices

1. **Always Use Parameterized Queries**
   ```cpp
   // NEVER DO THIS:
   std::wstring query = L"SELECT * FROM threats WHERE name = '" + userName + L"'";
   
   // ALWAYS DO THIS:
   db.QueryWithParams("SELECT * FROM threats WHERE name = ?", &err, userName);
   ```

2. **Enable Secure Delete**
   ```cpp
   config.enableSecureDelete = true;  // Overwrites deleted data
   ```

3. **Regular Integrity Checks**
   ```cpp
   // Run daily or after crashes
   std::vector<std::wstring> issues;
   db.CheckIntegrity(issues);
   ```

4. **Automated Backups**
   ```cpp
   config.autoBackup = true;
   config.backupInterval = std::chrono::hours(24);
   ```

5. **File System Permissions**
   - Database file: Read/Write for SYSTEM only
   - Backup directory: Restricted access
   - Use Windows ACLs to enforce permissions

6. **Encryption (SQLCipher)**
   ```cpp
   config.encryptionEnabled = true;
   config.encryptionKey = CryptoUtils::GenerateKey256();
   ```

## Troubleshooting

### Common Issues

#### 1. Database is Locked (SQLITE_BUSY)
**Solution**: Increase busyTimeoutMs or check for long-running transactions

```cpp
config.busyTimeoutMs = 30000;  // 30 seconds
```

#### 2. Database is Corrupted (SQLITE_CORRUPT)
**Solution**: Restore from backup

```cpp
if (err.sqliteCode == SQLITE_CORRUPT) {
    db.RestoreFromFile(lastGoodBackupPath);
}
```

#### 3. Out of Memory
**Solution**: Reduce cache size or use streaming queries

```cpp
config.cacheSizeKB = 5120;  // Reduce to 5MB
```

#### 4. Slow Queries
**Solution**: Add indices and analyze query plans

```cpp
auto result = db.Query("EXPLAIN QUERY PLAN SELECT ...");
// Check if indices are being used
```

## Monitoring and Diagnostics

### Database Statistics
```cpp
auto stats = db.GetStats();
SS_LOG_INFO(L"DB Stats",
    L"Size: %.2f MB, Pages: %zu, Free: %zu, Queries: %lld",
    stats.totalSize / (1024.0 * 1024.0),
    stats.pageCount,
    stats.freePages,
    stats.totalQueries
);
```

### Connection Pool Status
```cpp
size_t available = pool.AvailableConnections();
size_t total = pool.TotalConnections();
SS_LOG_INFO(L"Pool", L"Connections: %zu available, %zu total", available, total);
```

## Shutdown Procedure

Always call `Shutdown()` before application exit:

```cpp
// Before application termination
DatabaseManager::Instance().Shutdown();
```

This ensures:
- All connections are closed properly
- Background threads are stopped
- Pending transactions are completed
- Cache is cleared
- No resource leaks

## Support and Contact

For issues specific to this implementation:
- Check the logs first (SS_LOG_* macros output to logger)
- Review error codes in DatabaseError structure
- Consult SQLite documentation for error code meanings

---

**Version**: 1.0  
**Last Updated**: 2025  
**Maintained by**:  ShadowStrike 
