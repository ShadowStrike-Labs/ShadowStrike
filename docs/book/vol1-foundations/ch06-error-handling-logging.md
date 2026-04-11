# Chapter 6: Error Handling & Logging Infrastructure

> *"A security product that fails silently is worse than no security product at all — it creates a false sense of protection."*

---

## 6.1 Error Handling Philosophy

ShadowStrike follows three rules for error handling:

1. **Never fail silently** — every error is logged, categorized, and actionable
2. **Never crash the host** — a security product crash leaves the system unprotected
3. **Never leak information** — error messages must not expose internal state to attackers

The error strategy varies by context:

| Context | Strategy | Rationale |
|---------|----------|-----------|
| Initialization | Return `bool` or structured result | Caller decides whether to abort or degrade |
| Hot-path scanning | Return `std::optional<T>` or error enum | No exceptions on critical performance paths |
| Background tasks | Catch-all with logging | Task failure must not crash the pool |
| I/O operations | Return error codes + context | Specific error codes enable targeted recovery |
| Kernel communication | NTSTATUS propagation | Kernel errors must map to user-visible states |

---

## 6.2 The Logger — Architecture

### 6.2.1 Design Decisions

The Logger (`src/Shared_modules/Utils/Logger.hpp`) is the single most critical infrastructure component. If the logger fails, the entire system operates blind. Design choices reflect this:

- **Meyers' Singleton** — guaranteed thread-safe initialization, zero-cost access
- **Asynchronous by default** — logging never blocks the caller
- **Multiple output targets** — console, file, Windows Event Log (simultaneously)
- **Back-pressure policies** — graceful degradation under log flood
- **Automatic rotation** — prevents unbounded disk consumption
- **JSON Lines support** — machine-parseable for SIEM integration

```
Caller Thread(s)                    Logger Worker Thread
    │                                      │
    ├─ Logger::Info("scan complete")       │
    │   ├─ Build LogItem                   │
    │   ├─ Enqueue(item)  ───────→  [Queue]│
    │   └─ return immediately              │
    │                                      ├─ Dequeue(item)
    │                                      ├─ FormatPrefix() or FormatAsJson()
    │                                      ├─ WriteConsole(item)
    │                                      ├─ WriteFile(item)
    │                                      ├─ WriteEventLog(item)
    │                                      └─ RotateIfNeeded()
    │                                      │
    ├─ Logger::Error("scan failed")        │
    │   ├─ Build LogItem                   │
    │   ├─ Enqueue(item) ────────→  [Queue]│
    │   ├─ flushLevel reached? → Flush()   │
    │   └─ return                          │
    │                                      │
```

### 6.2.2 Singleton Access

```cpp
class Logger {
public:
    [[nodiscard]] static Logger& Instance();
    // Meyers' Singleton — thread-safe, lazy initialization, zero overhead

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};
```

---

## 6.3 Log Levels

```cpp
enum class LogLevel : uint8_t {
    Trace = 0,   // Verbose debugging: memory allocations, lock acquisitions
    Debug = 1,   // Development: function entry/exit, intermediate state
    Info  = 2,   // Operational: scan results, service start/stop
    Warn  = 3,   // Degraded: retry attempts, resource pressure
    Error = 4,   // Failure: scan error, database corruption
    Fatal = 5    // Critical: unrecoverable, service must restart
};
```

**Level Selection Guidelines:**

| Level | Production | Development | Example |
|-------|------------|-------------|---------|
| Trace | OFF | ON | `"Acquired shared lock on HashStore"` |
| Debug | OFF | ON | `"ScanFile entered: path=C:\\Users\\...\\test.exe"` |
| Info | ON | ON | `"Signature database loaded: 1,247,833 entries"` |
| Warn | ON | ON | `"ThreadPool queue at 87% capacity, throttling"` |
| Error | ON | ON | `"Failed to open file for scanning: ACCESS_DENIED"` |
| Fatal | ON | ON | `"SignatureStore corruption detected, initiating recovery"` |

> ⚠️ **Security Note:** Never log file contents, user data, passwords, encryption keys, or memory addresses at any level. Log the **event** and **error code**, not the **data**. A log file is an attack surface — if exfiltrated, it should reveal operational status, not secrets.

---

## 6.4 Logger Configuration

### 6.4.1 LoggerConfig Structure

```cpp
struct LoggerConfig {
    // Queue & Back-Pressure
    size_t maxQueueSize = 1000;
    BackPressurePolicy bpPolicy = BackPressurePolicy::DropOldest;

    // Output Targets
    bool async = true;           // Async logging (recommended)
    bool toConsole = true;       // Console output
    bool toFile = true;          // File output
    bool toEventLog = false;     // Windows Event Log

    // Formatting
    bool jsonLines = false;      // JSON Lines format
    bool useUtcTime = true;      // UTC timestamps
    bool includeSrcLocation = true;  // File/line/function
    bool includeProcThreadId = true; // PID/TID

    // File Settings
    std::wstring logDirectory = L"logs";
    std::wstring baseFileName = L"ShadowStrike";
    size_t maxFileSizeBytes = 10 * 1024 * 1024;  // 10 MB
    size_t maxFileCount = 10;    // 10 rotated files = 100 MB max

    // Severity Control
    LogLevel minimalLevel = LogLevel::Info;
    LogLevel flushLevel = LogLevel::Error;
    std::wstring eventLogSource = L"ShadowStrike";
};
```

### 6.4.2 Back-Pressure Policies

When the logging queue is full (e.g., during a scan storm generating thousands of events):

```cpp
enum class BackPressurePolicy {
    Block,         // Wait for space — guarantees delivery, may slow caller
    DropOldest,    // Remove oldest queued message — keeps recent context (DEFAULT)
    DropNewest     // Discard incoming message — preserves historical context
};
```

> 📌 **Key Insight:** `DropOldest` is the default because in security forensics, **recent events** are almost always more valuable than old ones. If the system is under attack and generating thousands of events, the most recent events provide the current attack state. The oldest events are context — useful but less critical than knowing what's happening right now.

---

## 6.5 Log Output Formats

### 6.5.1 Text Format (Default)

```
2025-01-15T14:23:47.123Z [INFO ] [ScanEngine  ] [PID:4832 TID:7120] Scan completed: CLEAN (2.3ms) | ScanEngine.cpp:847 ScanFile
2025-01-15T14:23:47.125Z [WARN ] [ThreadPool  ] [PID:4832 TID:7124] Queue at 87% capacity | ThreadPool.cpp:412 Enqueue
2025-01-15T14:23:47.127Z [ERROR] [FileSystem  ] [PID:4832 TID:7120] Access denied: Win32 error 5 | FileUtils.cpp:231 OpenFile
```

Format breakdown:
```
{UTC timestamp} [{LEVEL}] [{category}] [{PID:xxxx TID:xxxx}] {message} | {file}:{line} {function}
```

### 6.5.2 JSON Lines Format

When `jsonLines = true`, each log entry is a single JSON object per line — ideal for SIEM ingestion (Splunk, Elastic, Sentinel):

```json
{"ts":"2025-01-15T14:23:47.123Z","level":"INFO","cat":"ScanEngine","pid":4832,"tid":7120,"msg":"Scan completed: CLEAN (2.3ms)","file":"ScanEngine.cpp","line":847,"fn":"ScanFile"}
{"ts":"2025-01-15T14:23:47.125Z","level":"WARN","cat":"ThreadPool","pid":4832,"tid":7124,"msg":"Queue at 87% capacity","file":"ThreadPool.cpp","line":412,"fn":"Enqueue"}
```

> 📊 **Performance Note:** JSON formatting is ~3× slower than text formatting due to string escaping (`EscapeJson()`). This cost is paid on the background worker thread, never on the caller's thread — the async queue absorbs the formatting latency.

---

## 6.6 Logging APIs

### 6.6.1 Extended Format (Primary API)

The primary logging API includes full source context:

```cpp
void Logger::LogEx(
    LogLevel level,
    const wchar_t* category,      // Module name: L"ScanEngine", L"HashStore"
    const wchar_t* file,          // Source file: L"ScanEngine.cpp"
    int line,                     // Line number: 847
    const wchar_t* function,      // Function name: L"ScanFile"
    const wchar_t* format, ...    // printf-style format string
);
```

Typical usage via macro:

```cpp
#define LOG_INFO(category, fmt, ...) \
    Logger::Instance().LogEx(LogLevel::Info, category, \
        __FILEW__, __LINE__, __FUNCTIONW__, fmt, ##__VA_ARGS__)

// In code:
LOG_INFO(L"ScanEngine", L"Scan completed: %s (%llu us)", 
    verdictStr, scanDurationUs);
```

### 6.6.2 Windows Error Logging

For Win32 API failures, the logger automatically formats the error code:

```cpp
void Logger::LogWinErrorEx(
    LogLevel level,
    const wchar_t* category,
    const wchar_t* file, int line, const wchar_t* function,
    DWORD errorCode,
    const wchar_t* contextFormat, ...
);
```

This produces output like:
```
[ERROR] [FileSystem] Failed to open: ACCESS_DENIED (Win32: 5) | FileUtils.cpp:231
```

### 6.6.3 Convenience Functions (Narrow String)

For quick logging without source location (useful in utility code):

```cpp
Logger::Info("Signature database loaded: {} entries", count);
Logger::Warn("Cache miss rate: {:.1f}%", missRate);
Logger::Error("Connection failed after {} retries", retryCount);
```

These use C++20 `std::format_string` for compile-time format string validation:

```cpp
template<typename... Args> requires (sizeof...(Args) > 0)
static void Info(std::format_string<Args...> fmt, Args&&... args);
```

> 💡 **Advanced C++ Note:** `std::format_string<Args...>` performs compile-time validation of the format string against the argument types. If you write `Logger::Info("count: {}", "hello")` but the code expects an integer, the compiler rejects it. This eliminates an entire class of format-string bugs that plague `printf`-style APIs.

---

## 6.7 Scoped Timing (RAII Performance Logging)

### 6.7.1 Logger::Scope

The `Scope` class provides automatic function timing using RAII:

```cpp
class Logger::Scope {
public:
    Scope(const wchar_t* category,
          const wchar_t* file, int line, const wchar_t* function,
          const wchar_t* messageOnEnter = L"Enter",
          LogLevel level = LogLevel::Debug);
    ~Scope();
    // Non-copyable, non-movable
};
```

**Usage:**

```cpp
EngineResult ScanEngine::ScanFile(const ScanContext& ctx) {
    Logger::Scope scope(L"ScanEngine", __FILEW__, __LINE__, __FUNCTIONW__);
    // ... scan logic ...
}
// Destructor logs: "[DEBUG] [ScanEngine] Exit ScanFile (2.341 ms)"
```

**Implementation:** Uses `QueryPerformanceCounter` and `QueryPerformanceFrequency` for sub-microsecond precision. The high-resolution timer avoids the 15.6ms granularity of `GetTickCount64`.

---

## 6.8 LogItem Structure

Every log message is packaged into a `LogItem` before queuing:

```cpp
struct LogItem {
    LogLevel level = LogLevel::Info;
    std::wstring category;       // Module name
    std::wstring message;        // Formatted message
    std::wstring file;           // Source file
    std::wstring function;       // Function name
    int line = 0;                // Line number
    uint32_t pid = 0;            // Process ID (GetCurrentProcessId)
    uint32_t tid = 0;            // Thread ID (GetCurrentThreadId)
    uint64_t ts_100ns = 0;      // FILETIME in 100-nanosecond units
    DWORD winError = 0;          // Associated Win32 error code
};
```

> 🔬 **Deep Dive:** The timestamp uses `FILETIME` 100-nanosecond units (epochs from January 1, 1601) rather than `std::chrono` because: (1) it's the native Windows time format, (2) it maps directly to ETW trace timestamps, (3) it avoids the overhead of chrono-to-FILETIME conversion when writing to the Windows Event Log.

---

## 6.9 File Rotation

### 6.9.1 Rotation Policy

Log files rotate based on size (not time), controlled by two parameters:

```cpp
size_t maxFileSizeBytes = 10 * 1024 * 1024;  // 10 MB per file
size_t maxFileCount = 10;                      // Keep 10 files
```

**Maximum disk usage:** `maxFileSizeBytes × maxFileCount` = 100 MB default.

### 6.9.2 Rotation Sequence

```
ShadowStrike.log       ← Current (active writes)
ShadowStrike.1.log     ← Previous (most recent rotated)
ShadowStrike.2.log     ← Older
...
ShadowStrike.9.log     ← Oldest (will be deleted on next rotation)
```

**Rotation Algorithm:**

```
Before each write:
    if (currentFileSize + nextWriteBytes > maxFileSizeBytes):
        Close current file
        Delete ShadowStrike.{maxFileCount-1}.log if exists
        Rename ShadowStrike.{N}.log → ShadowStrike.{N+1}.log  (N = max-2 → 0)
        Rename ShadowStrike.log → ShadowStrike.1.log
        Create new ShadowStrike.log
```

---

## 6.10 Windows Event Log Integration

When `toEventLog = true`, the logger writes to the Windows Application Event Log:

```cpp
void Logger::WriteEventLog(const LogItem& item) {
    // Maps LogLevel to Windows Event types:
    // Fatal/Error  → EVENTLOG_ERROR_TYPE
    // Warn         → EVENTLOG_WARNING_TYPE
    // Info/Debug   → EVENTLOG_INFORMATION_TYPE
}
```

Events appear under the source name specified by `eventLogSource` (default: `"ShadowStrike"`):

```
Event Viewer → Windows Logs → Application
Source: ShadowStrike
Level:  Error
Message: [FileSystem] Access denied: Win32 error 5 | FileUtils.cpp:231
```

> 📌 **Key Insight:** Windows Event Log integration enables enterprise SIEM collection via Windows Event Forwarding (WEF) without requiring the SIEM to parse log files. This is critical for enterprise deployments where centralized log collection is mandatory.

---

## 6.11 Internal Mechanics

### 6.11.1 Queue Management

```cpp
void Logger::Enqueue(LogItem&& item) {
    // Lock-based queue with back-pressure policy
    std::unique_lock<std::mutex> lock(m_queueMutex);

    if (m_queue.size() >= m_config.maxQueueSize) {
        switch (m_config.bpPolicy) {
            case BackPressurePolicy::Block:
                m_cv.wait(lock, [&]{ return m_queue.size() < m_config.maxQueueSize; });
                break;
            case BackPressurePolicy::DropOldest:
                m_queue.pop_front();  // Remove oldest
                break;
            case BackPressurePolicy::DropNewest:
                return;  // Discard this message
        }
    }

    m_queue.push_back(std::move(item));
    m_cv.notify_one();  // Wake worker thread
}
```

### 6.11.2 Worker Loop

```cpp
void Logger::WorkerLoop() {
    LogItem item;
    while (!m_shutdown || !m_queue.empty()) {
        if (!Dequeue(item)) continue;

        if (m_config.toConsole)  WriteConsole(item);
        if (m_config.toFile)     WriteFile(item);
        if (m_config.toEventLog) WriteEventLog(item);
    }
}
```

### 6.11.3 Flush Semantics

```cpp
void Logger::Flush() {
    // Signal the worker to process all pending items
    // Wait until queue is empty
    // Flush file handle (FlushFileBuffers)
}
```

Flush is triggered automatically when:
- A message at `flushLevel` or above is logged (default: Error)
- `Shutdown()` is called
- `Flush()` is called explicitly

---

## 6.12 Error Handling Patterns in ShadowStrike

### 6.12.1 Return Code Pattern (Performance-Critical)

```cpp
// Used in hot paths: scanning, pattern matching, hash lookup
[[nodiscard]] bool HashStore::Lookup(
    const std::string& hash,
    HashResult& result) const noexcept
{
    std::shared_lock lock(m_mutex);
    auto it = m_index.find(hash);
    if (it == m_index.end()) return false;
    result = it->second;
    return true;
}
```

### 6.12.2 Optional Pattern (Query Operations)

```cpp
// Used for lookups that may legitimately return nothing
[[nodiscard]] std::optional<ThreatInfo> ThreatIntelStore::QueryIOC(
    const std::string& ioc) const
{
    std::shared_lock lock(m_mutex);
    auto result = m_index.Find(ioc);
    if (!result) return std::nullopt;
    return ThreatInfo{*result};
}
```

### 6.12.3 Structured Result Pattern (Complex Operations)

```cpp
// Used for operations with rich error context
struct EncryptionResult {
    bool success;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;        // For AEAD modes
    std::vector<uint8_t> iv;         // Generated IV
    std::string errorMessage;         // If success == false
    uint32_t errorCode;               // Platform error code
};

EncryptionResult CryptoManager::Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algo);
```

### 6.12.4 Exception Pattern (Initialization / Configuration)

```cpp
// Used only during initialization — never on hot paths
void ScanEngine::Initialize(const EngineConfig& config) {
    if (!config.signatureDbPath.empty()) {
        if (!m_sigStore.Load(config.signatureDbPath)) {
            throw std::runtime_error(
                "Failed to load signature database: " +
                WideToNarrow(config.signatureDbPath));
        }
    }
}
```

> 📌 **Key Insight:** ShadowStrike uses **exceptions only during initialization and shutdown** — never in the scanning hot path. This is a deliberate performance decision: exception handling has zero overhead when no exception is thrown (on MSVC with `/EHsc`), but the **possibility** of exceptions prevents certain compiler optimizations. Hot-path code returns `bool`, `optional`, or structured results.

---

## 6.13 Summary

| Component | Key Feature | Enterprise Value |
|-----------|-------------|-----------------|
| Logger Singleton | Meyers' pattern, async queue | Zero-overhead access, non-blocking |
| Log Levels | 6 levels (Trace → Fatal) | Appropriate verbosity per environment |
| JSON Lines | Machine-parseable format | Direct SIEM integration |
| File Rotation | Size-based, configurable count | Bounded disk usage (100 MB default) |
| Back-Pressure | 3 policies (Block/DropOldest/DropNewest) | Graceful degradation under load |
| Event Log | Windows native integration | WEF/SIEM collection |
| Scoped Timing | RAII with QueryPerformanceCounter | Sub-microsecond profiling |
| Error Strategy | Context-dependent (bool/optional/struct/exception) | Performance + clarity |

---

*Previous: [Chapter 5 — Threading Model & Concurrency](ch05-threading-model.md)*
*Next: [Chapter 7 — Security Architecture & Threat Model](ch07-security-architecture.md)*
