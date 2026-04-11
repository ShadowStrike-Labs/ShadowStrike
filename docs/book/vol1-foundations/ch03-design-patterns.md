# Chapter 3: Design Patterns & Conventions

> *"Patterns are not about writing clever code. They are about writing predictable code."*

---

## 3.1 Why Patterns Matter in Security Software

In a security product, consistency is a safety mechanism. When every module follows the same patterns for memory management, threading, and error handling, the attack surface for implementation bugs shrinks dramatically. A reviewer who understands the patterns can spot violations instantly.

ShadowStrike uses a small set of well-understood design patterns, applied consistently across all 1,298 source files. This chapter documents each pattern, explains why it was chosen, and shows real examples from the codebase.

---

## 3.2 The Meyers Singleton

### What It Is

A thread-safe singleton that uses C++11's guarantee that function-local static variables are initialized exactly once, even under concurrent access.

### Why ShadowStrike Uses It

Several infrastructure components must exist as exactly one instance per process: the Logger, the ThreadPool, the ScanEngine. The Meyers Singleton provides:

1. **Thread-safe initialization** — guaranteed by the C++ standard (§6.7)
2. **Lazy construction** — created on first use, not at static initialization time
3. **No manual locking** — no double-checked locking pattern, no `std::call_once`
4. **Deterministic destruction** — destroyed in reverse order of construction

### Real Example: Logger

From `src/Shared_modules/Utils/Logger.hpp`:

```cpp
class Logger {
public:
    /**
     * @brief Get the singleton Logger instance.
     * @return Reference to the global Logger instance
     */
    [[nodiscard]] static Logger& Instance();

    /**
     * @brief Initialize the logger with configuration.
     *
     * Must be called before logging for configured behavior.
     * If not called, logger auto-initializes with console-only defaults.
     */
    bool Initialize(const LoggerConfig& cfg);

    // ... logging methods ...

    // Prevent copying and moving
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

private:
    Logger();  // Private constructor
    ~Logger();
};
```

The implementation (in `Logger.cpp`):

```cpp
Logger& Logger::Instance() {
    static Logger instance;  // Meyers Singleton
    return instance;
}
```

### Usage Pattern

```cpp
// Anywhere in the codebase:
Logger::Instance().Log(LogLevel::Info, L"ScanEngine", L"Scan completed in {}ms", elapsed);

// Or using the convenience macro:
LOG_INFO(L"ScanEngine", L"Scan completed in {}ms", elapsed);
```

> 💡 **Advanced C++ Note:** The `static Logger instance;` line is thread-safe because C++11 §6.7 states: "If control enters the declaration concurrently while the variable is being initialized, the concurrent execution shall wait for completion of the initialization." The compiler generates the synchronization code. This is more efficient than `std::call_once` and simpler than double-checked locking — both of which ShadowStrike explicitly avoids.

### The Rule

> 📌 **Convention:** Every singleton in ShadowStrike uses the Meyers pattern. No global variables. No double-checked locking. No `std::call_once` for singletons. The `Instance()` method returns a reference, never a pointer.

### Where It's Used

| Class | File | Purpose |
|-------|------|---------|
| `Logger` | `Utils/Logger.hpp` | Centralized async logging |
| `ThreadPool` | `Utils/ThreadPool.hpp` | Work-stealing task execution |
| `ScanEngine` | `Core/Engine/ScanEngine.hpp` | Detection orchestrator |
| `ConfigManager` | `Config/CortexConfig.hpp` | Centralized configuration |

---

## 3.3 PIMPL (Pointer to Implementation)

### What It Is

The PIMPL idiom hides a class's implementation behind a forward-declared inner class, stored as a `std::unique_ptr`. The header exposes only the public interface; all private data members and methods live in the `.cpp` file.

### Why ShadowStrike Uses It

1. **ABI Stability** — Adding private members doesn't change the header, so dependent modules don't need recompilation
2. **Compilation Speed** — Headers include fewer dependencies, reducing transitive includes
3. **Information Hiding** — Implementation details don't leak into the public API
4. **Binary Compatibility** — Critical for a security product where updates must not break running processes

### Real Example: ScanEngine

From `src/Shared_modules/Core/Engine/ScanEngine.hpp`:

```cpp
namespace ShadowStrike::Core::Engine {

class ScanEngine {
public:
    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] static ScanEngine& Instance();
    [[nodiscard]] bool Initialize(const EngineConfig& config);
    void Shutdown();

    // ========================================================================
    // SCANNING API
    // ========================================================================

    [[nodiscard]] ScanResult ScanFile(const std::wstring& filePath,
                                       const ScanContext& context);

    [[nodiscard]] std::future<ScanResult> ScanFileAsync(
        const std::wstring& filePath,
        const ScanContext& context);

    // ... more public methods ...

    // ========================================================================
    // INTERNAL IMPLEMENTATION (PIMPL)
    // ========================================================================

    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Core::Engine
```

The `Impl` class (in `ScanEngine.cpp`) contains all the heavy dependencies:

```cpp
class ScanEngine::Impl {
public:
    // Dependencies — none of these appear in the header
    std::unique_ptr<SignatureStore> m_signatureStore;
    std::unique_ptr<WhitelistStore> m_whitelistStore;
    std::unique_ptr<HashStore> m_hashStore;
    std::unique_ptr<ThreatIntelDatabase> m_threatIntel;
    std::unique_ptr<YaraRuleStore> m_yaraStore;

    // Thread safety
    mutable std::shared_mutex m_scanMutex;

    // Configuration
    EngineConfig m_config;

    // Statistics
    std::atomic<uint64_t> m_totalScans{0};
    std::atomic<uint64_t> m_detections{0};
    std::atomic<uint64_t> m_cacheHits{0};
};
```

### The Rule

> 📌 **Convention:** Any class with more than two or three private data members, or any class that would pull heavy headers into its own header, uses PIMPL. The `Impl` class is always named `Impl` and stored as `std::unique_ptr<Impl> m_impl`.

---

## 3.4 RAII (Resource Acquisition Is Initialization)

### What It Is

RAII ties resource lifetime to object lifetime. When the object is constructed, it acquires the resource. When the object is destroyed (including via stack unwinding), it releases the resource. No `try`/`finally`, no manual cleanup.

### Why It's Non-Negotiable

In a security product:

- A file handle leak can prevent scanning
- A mutex left locked can deadlock the detection pipeline
- A memory leak under load can exhaust the working set and degrade protection
- A missed cleanup on an error path is a vulnerability

RAII eliminates entire categories of bugs by making cleanup automatic and exception-safe.

### Real Examples

#### Scoped Logging Timer

From `src/Shared_modules/Utils/Logger.hpp`:

```cpp
class Logger::Scope {
public:
    Scope(const wchar_t* module, const char* file,
          int line, const char* func)
        : m_module(module), m_file(file),
          m_line(line), m_func(func),
          m_start(std::chrono::steady_clock::now()) {}

    ~Scope() {
        auto elapsed = std::chrono::steady_clock::now() - m_start;
        auto ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(elapsed).count();
        Logger::Instance().Log(LogLevel::Debug, m_module,
            L"[{}:{}] {} completed in {}ms",
            m_file, m_line, m_func, ms);
    }

    // Non-copyable, non-movable
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

private:
    const wchar_t* m_module;
    const char* m_file;
    int m_line;
    const char* m_func;
    std::chrono::steady_clock::time_point m_start;
};
```

Usage:

```cpp
ScanResult ScanEngine::ScanFile(const std::wstring& filePath,
                                 const ScanContext& context) {
    Logger::Scope scope(L"ScanEngine", __FILE__, __LINE__, __FUNCTION__);

    // ... scanning logic ...
    // Scope destructor automatically logs elapsed time,
    // even if an exception is thrown
}
```

#### Smart Pointer Ownership

ShadowStrike uses C++ smart pointers exclusively:

```cpp
// CORRECT: Unique ownership (the default)
std::unique_ptr<PEInfo> info = PEParser::Parse(filePath);

// CORRECT: Shared ownership (only when truly shared)
std::shared_ptr<SignatureStore> store = GetSharedStore();

// CORRECT: Non-owning reference
std::span<const uint8_t> buffer = GetFileBuffer();

// FORBIDDEN: Raw new/delete
auto* ptr = new PEInfo();  // ❌ NEVER
delete ptr;                 // ❌ NEVER
```

### The Rule

> 📌 **Convention:** Every resource in ShadowStrike is managed by RAII. No manual `lock`/`unlock`. No manual `new`/`delete`. No `CloseHandle` without a wrapper. If you see raw resource management in a code review, it is a bug.

---

## 3.5 Thread Safety Model

### The Assumption

**All code in ShadowStrike assumes multi-threaded execution.** The ThreadPool can dispatch tasks to any thread. The kernel driver sends messages from multiple threads simultaneously. The ScanEngine processes concurrent scan requests.

### The Concurrency Primitives

ShadowStrike uses a layered approach to concurrency:

| Level | Primitive | When |
|-------|-----------|------|
| **Lock-free** | `std::atomic<>` | Counters, flags, statistics |
| **Read-heavy** | `std::shared_mutex` | Data stores (many readers, rare writers) |
| **Write-heavy** | `std::mutex` | Task queues, configuration updates |
| **Signaling** | `std::condition_variable` | Producer-consumer (ThreadPool, Logger) |
| **One-shot** | `std::latch` | Initialization barriers |
| **Reusable** | `std::barrier` | Phase synchronization |
| **Bounded** | `std::counting_semaphore` | Resource limits |

### Real Example: ThreadPool Statistics

From `src/Shared_modules/Utils/ThreadPool.hpp`:

```cpp
/**
 * All counters are atomic for thread-safe access without external locking.
 * Use relaxed memory ordering for statistics that don't need strict ordering.
 */
struct TaskStatistics {
    std::atomic<uint64_t> enqueuedCount{0};
    std::atomic<uint64_t> completedCount{0};
    std::atomic<uint64_t> failedCount{0};
    std::atomic<uint64_t> cancelledCount{0};
    std::atomic<uint64_t> timedOutCount{0};

    std::atomic<uint64_t> totalExecutionTimeMs{0};
    std::atomic<uint64_t> totalWaitTimeMs{0};
    std::atomic<uint64_t> minExecutionTimeMs{
        std::numeric_limits<uint64_t>::max()};
    std::atomic<uint64_t> maxExecutionTimeMs{0};

    void Reset() noexcept;
};
```

> 💡 **Advanced C++ Note:** Why `std::atomic<uint64_t>` instead of a mutex protecting a plain `uint64_t`? Because statistics are updated from every worker thread on every task completion. A mutex here would create contention. Atomic operations on x64 use hardware instructions (`lock xadd`, `lock cmpxchg`) that are orders of magnitude faster than mutex acquire/release cycles for simple counter updates. The tradeoff is that you cannot atomically update *two* counters simultaneously — but for independent statistics, that's acceptable.

### The Shared Mutex Pattern

For data stores where reads vastly outnumber writes (e.g., scanning a file against a hash database that's updated once per hour):

```cpp
class HashStore {
    mutable std::shared_mutex m_mutex;
    // ... data ...

public:
    // Multiple threads can read simultaneously
    [[nodiscard]] bool Lookup(const HashValue& hash) const {
        std::shared_lock lock(m_mutex);  // Shared (read) lock
        return m_index.find(hash) != m_index.end();
    }

    // Only one thread can write at a time
    bool Insert(const HashValue& hash, const ThreatInfo& info) {
        std::unique_lock lock(m_mutex);  // Exclusive (write) lock
        return m_index.emplace(hash, info).second;
    }
};
```

### The Rule

> 📌 **Convention:** Prefer `std::shared_mutex` for read-heavy data. Use `std::atomic<>` for counters and flags. Use `std::mutex` only when the critical section involves multiple operations that must be atomic together. Never use `volatile` for synchronization — it is not a threading primitive in C++.

---

## 3.6 The `[[nodiscard]]` Convention

### What It Is

The `[[nodiscard]]` attribute causes a compiler warning when a function's return value is ignored. In ShadowStrike, it is used on every function where ignoring the return value would be a bug.

### Why It Matters

Consider:

```cpp
scanEngine.Initialize(config);  // Did it succeed?
hashStore.Lookup(hash);         // Was it found?
file.Open(path);                // Was the file accessible?
```

Without `[[nodiscard]]`, these calls compile silently even when the return value is ignored. In a security product, an unchecked initialization failure means the protection isn't actually running.

### Where It's Applied

```cpp
// Functions that return success/failure
[[nodiscard]] bool Initialize(const EngineConfig& config);

// Functions that return computed results
[[nodiscard]] ScanResult ScanFile(const std::wstring& path);

// Functions that return optional values
[[nodiscard]] std::optional<ThreatInfo> LookupThreat(const HashValue& hash);

// Singleton accessors (ignoring the reference is always a bug)
[[nodiscard]] static Logger& Instance();
```

### The Rule

> 📌 **Convention:** Every function where ignoring the return value would be a bug — which in practice means *every non-void function* — is marked `[[nodiscard]]`. The only exceptions are fire-and-forget methods like `Log()` where the caller genuinely doesn't need to check success.

---

## 3.7 Namespace Convention

ShadowStrike uses nested namespaces to organize code:

```cpp
namespace ShadowStrike {
    namespace Core {
        namespace Engine {
            class ScanEngine { ... };
        }
        namespace FileSystem {
            class FileHasher { ... };
        }
        namespace Network {
            class NetworkMonitor { ... };
        }
    }
    namespace Detection {
        namespace HashStore {
            class HashStore { ... };
        }
        namespace SignatureStore {
            class SignatureStore { ... };
        }
    }
    namespace Utils {
        class Logger { ... };
        class ThreadPool { ... };
    }
}
```

### The Rule

> 📌 **Convention:** The top-level namespace is always `ShadowStrike`. Module families get a second-level namespace (`Core`, `Detection`, `Utils`, `RealTime`, etc.). Individual modules get a third-level namespace matching the directory name. This mirrors the directory structure.

---

## 3.8 Error Handling Strategy

ShadowStrike uses a hybrid error handling approach:

### Return Codes for Expected Failures

File not found, access denied, invalid input — these are expected conditions, not exceptions:

```cpp
[[nodiscard]] bool HashStore::CreateNew(
    const std::wstring& path, uint64_t maxEntries) {
    if (path.empty()) {
        Logger::Instance().Log(LogLevel::Error, L"HashStore",
            L"CreateNew failed: empty path");
        return false;
    }
    // ...
}
```

### Exceptions for Programmer Errors

Violated preconditions, impossible states, corrupted data structures:

```cpp
void SignatureStore::AddRule(const std::string& rule) {
    if (!m_initialized) {
        throw std::logic_error(
            "SignatureStore::AddRule called before Initialize");
    }
    // ...
}
```

### `std::optional` for Optional Results

When the absence of a result is not an error:

```cpp
[[nodiscard]] std::optional<ThreatInfo>
ThreatIntelDatabase::LookupHash(const HashValue& hash) const {
    std::shared_lock lock(m_mutex);
    auto it = m_hashIndex.find(hash);
    if (it == m_hashIndex.end()) {
        return std::nullopt;  // Not found is not an error
    }
    return it->second;
}
```

### The Logging Contract

Every error is logged with context:

```cpp
// CORRECT: Specific, actionable, traceable
Logger::Instance().Log(LogLevel::Error, L"HashStore",
    L"Failed to open database at '{}': Win32 error {}",
    path, GetLastError());

// WRONG: Vague, unhelpful
Logger::Instance().Log(LogLevel::Error, L"HashStore",
    L"Failed");  // ❌ No context, no actionability
```

### The Rule

> 📌 **Convention:** Return `bool` or error codes for expected failures. Throw exceptions for programmer errors. Use `std::optional<>` for "not found" results. Always log errors with full context (what failed, where, why). Never log sensitive data (file contents, encryption keys, user credentials).

---

## 3.9 Memory Management Rules

### The Smart Pointer Hierarchy

| Type | When | Example |
|------|------|---------|
| `std::unique_ptr<T>` | Default for owned objects | `std::unique_ptr<Impl> m_impl;` |
| `std::shared_ptr<T>` | Only when ownership is genuinely shared | Shared data stores accessed by multiple engines |
| `std::span<T>` | Zero-copy view of contiguous data | `std::span<const uint8_t> buffer` |
| `std::string_view` | Zero-copy view of string data | `std::string_view name` |
| `T&` | Non-owning reference (cannot be null) | Function parameters |
| `T*` | Non-owning, nullable pointer | Optional output parameters (rare) |

### Allocation Caps

Security software must defend against resource exhaustion:

```cpp
// Cap allocations to prevent memory bombs
static constexpr size_t MAX_FILE_SCAN_SIZE = 256 * 1024 * 1024;  // 256 MB
static constexpr size_t MAX_PATTERN_COUNT = 1'000'000;
static constexpr size_t MAX_HASH_ENTRIES = 50'000'000;

bool ScanEngine::ScanFile(const std::wstring& path) {
    auto fileSize = GetFileSize(path);
    if (fileSize > MAX_FILE_SCAN_SIZE) {
        Logger::Instance().Log(LogLevel::Warn, L"ScanEngine",
            L"File '{}' exceeds scan size limit ({} bytes)", path, fileSize);
        return true;  // Skip, don't crash
    }
    // ...
}
```

### The Rule

> 📌 **Convention:** No raw `new`/`delete`. Prefer `unique_ptr` by default. Use `span<>` for buffer views. Cap every allocation. Validate every size before allocating.

---

## 3.10 The File & Directory Convention

### Source Organization

```
src/Shared_modules/
└── ModuleFamily/          # e.g., HashStore, PatternStore
    ├── Module.hpp         # Public interface (PIMPL if complex)
    ├── Module.cpp         # Implementation
    ├── ModuleTypes.hpp    # Types, enums, constants (if needed)
    └── ModuleUtils.cpp    # Internal utilities (if needed)
```

### Header Include Order

```cpp
// 1. Own header (verifies self-sufficiency)
#include "HashStore.hpp"

// 2. ShadowStrike headers
#include "Utils/Logger.hpp"
#include "Utils/FileUtils.hpp"

// 3. Third-party headers
#include <pugixml.hpp>
#include <sqlite3.h>

// 4. Standard library headers
#include <string>
#include <vector>
#include <memory>
#include <mutex>
```

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Class names | PascalCase | `ScanEngine`, `HashStore` |
| Method names | PascalCase | `ScanFile()`, `Initialize()` |
| Member variables | `m_` prefix + camelCase | `m_impl`, `m_scanMutex` |
| Local variables | camelCase | `fileSize`, `scanResult` |
| Constants | UPPER_SNAKE_CASE | `MAX_FILE_SIZE`, `DEFAULT_TIMEOUT` |
| Namespaces | PascalCase | `ShadowStrike::Core::Engine` |
| Enum values | PascalCase | `LogLevel::Error`, `ThreatLevel::High` |
| File names | PascalCase | `ScanEngine.hpp`, `BehaviorBlocker.cpp` |

---

## 3.11 The Kernel Code Convention

The kernel driver (`PhantomSensor`) follows different conventions because it uses C, not C++:

| Element | Convention | Example |
|---------|-----------|---------|
| Functions | `Ps_` prefix + PascalCase | `Ps_ProcessNotifyCallback` |
| Structures | `PS_` prefix + UPPER_SNAKE_CASE | `PS_PROCESS_CONTEXT` |
| Constants | `PS_` prefix + UPPER_SNAKE_CASE | `PS_MAX_PATH_LENGTH` |
| Global state | Structure with `g_` prefix | `g_DriverData` |
| Memory tags | Four-character codes | `'PsSn'` (PhantomSensor) |

> ⚠️ **Security Note:** The kernel driver uses C-style memory management (`ExAllocatePool2`, `ExFreePool`) because C++ operators `new`/`delete` are not available in kernel mode. Every allocation uses a pool tag for leak detection, and every allocation path has a corresponding free path verified through code review and Driver Verifier.

---

## 3.12 Summary: The Pattern Checklist

When writing or reviewing ShadowStrike code, verify:

| # | Check | Pattern |
|---|-------|---------|
| 1 | Is the singleton Meyers-style? | § 3.2 |
| 2 | Does the complex class use PIMPL? | § 3.3 |
| 3 | Are all resources RAII-managed? | § 3.4 |
| 4 | Is the code thread-safe? | § 3.5 |
| 5 | Are return values `[[nodiscard]]`? | § 3.6 |
| 6 | Are namespaces correct? | § 3.7 |
| 7 | Are errors logged with context? | § 3.8 |
| 8 | Are allocations capped? | § 3.9 |
| 9 | Is the include order correct? | § 3.10 |
| 10 | Is naming consistent? | § 3.10 |

If any answer is "no," it's a code review finding.

---

*Previous: [Chapter 2 — System Architecture Overview](ch02-architecture-overview.md)*
*Next: [Chapter 4 — The Build System](ch04-build-system.md)*
