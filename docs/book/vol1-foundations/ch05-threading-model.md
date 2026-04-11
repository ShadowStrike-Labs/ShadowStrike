# Chapter 5: Threading Model & Concurrency

> *"In a security product, a deadlock is as dangerous as a missed detection — the system stops protecting."*

---

## 5.1 Concurrency Philosophy

ShadowStrike operates in an inherently concurrent environment:

- **Kernel callbacks** fire on any thread, at any IRQL, at any time
- **File system operations** generate thousands of IRP events per second
- **Scan operations** must run parallel to user workflows without visible lag
- **Behavioral analysis** correlates events across processes in real-time

The threading model is built on three non-negotiable principles:

1. **Reads are concurrent, writes are exclusive** — `std::shared_mutex` everywhere
2. **No manual lock/unlock** — RAII lock guards prevent every possible miss-unlock path
3. **No blocking on the hot path** — real-time scan decisions must complete in <5ms

---

## 5.2 The ThreadPool Engine

### 5.2.1 Architecture Overview

The ShadowStrike ThreadPool (`src/Shared_modules/Utils/ThreadPool.hpp`) is a feature-complete work-stealing thread pool with:

- **Priority scheduling** — critical tasks preempt background work
- **Work stealing** — idle threads steal from busy workers' queues
- **Dynamic scaling** — pool grows/shrinks based on load
- **Deadlock detection** — background monitor identifies stalled threads
- **ETW integration** — every pool event emits a structured ETW trace
- **Cancellation tokens** — cooperative task cancellation
- **Batch submission** — vectorized parallel-for patterns

```
┌─────────────────────────────────────────────────────────┐
│                    ThreadPool                             │
│                                                           │
│  ┌─────────────────────────────────┐                     │
│  │    PriorityTaskQueue (Global)    │  ← Submit()        │
│  │  ┌──────┬──────┬──────┬──────┐  │                     │
│  │  │Crit  │High  │Normal│Low   │  │                     │
│  │  └──┬───┴──┬───┴──┬───┴──┬───┘  │                     │
│  └─────┼──────┼──────┼──────┼──────┘                     │
│        └──────┴──────┴──────┘                             │
│              ↓          ↓          ↓                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                 │
│  │Worker[0] │ │Worker[1] │ │Worker[N] │  ← Steal()      │
│  │ Thread   │ │ Thread   │ │ Thread   │                  │
│  └──────────┘ └──────────┘ └──────────┘                  │
│        ↓          ↓          ↓                            │
│  ┌──────────────────────────────────┐                    │
│  │   ETWTracingManager              │  → ETW Provider    │
│  │   DeadlockDetector               │  → Alert System    │
│  │   TaskStatistics                 │  → Health Report   │
│  └──────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

### 5.2.2 Constants and Limits

The pool enforces hard limits to prevent resource exhaustion:

```cpp
namespace ThreadPoolConstants {
    static constexpr size_t kMaxThreads = 1024;
    static constexpr size_t kMaxQueueSize = 1000000;
    static constexpr std::chrono::milliseconds kDefaultIdleTimeout{30000};     // 30s
    static constexpr std::chrono::milliseconds kDefaultTaskTimeout{300000};    // 5 min
    static constexpr size_t kDefaultStackSize = 1024 * 1024;                  // 1 MB
    static constexpr size_t kDefaultMaxMemoryPerThread = 100 * 1024 * 1024;   // 100 MB
    static constexpr std::chrono::milliseconds kDefaultDeadlockCheckInterval{5000};
    static constexpr std::chrono::seconds kInactivityThreshold{30};
    static constexpr double kQueueOverflowThreshold = 0.9;                    // 90%
    static constexpr double kDeadlockSuspiciousRatio = 0.5;                   // 50%
    static constexpr double kHealthySuccessRate = 95.0;                       // 95%
}
```

> ⚠️ **Security Note:** The `kMaxQueueSize` of 1 million tasks prevents memory exhaustion if an attacker floods the system with scan requests. The `kQueueOverflowThreshold` at 90% triggers back-pressure **before** the queue is full, preventing the abrupt failure cliff that happens at exactly 100%.

### 5.2.3 Task Priority System

Tasks are classified into five priority levels that map to scanning urgency:

```cpp
enum class TaskPriority : uint8_t {
    Critical = 0,   // Real-time threat scanning — kernel IRP callback
    High     = 1,   // User-initiated scan — "Scan this file now"
    Normal   = 2,   // Background processing — scheduled scans
    Low      = 3,   // Maintenance — database compaction, log rotation
    Idle     = 4    // Idle-time only — prefetching, precomputation
};
```

The priority queue is a `std::priority_queue` with a custom comparator that sorts by priority value (lower number = higher priority), with FIFO ordering within the same priority level using the monotonically-increasing `taskId`:

```
Critical [0] ─────────────┐
                           ├──→ Pop() returns highest priority first
High     [1] ─────────────┤
                           ├──→ Within same priority: FIFO by taskId
Normal   [2] ─────────────┤
                           │
Low      [3] ─────────────┤
                           │
Idle     [4] ─────────────┘
```

### 5.2.4 Thread Pool Configuration

The `ThreadPoolConfig` structure provides comprehensive tuning:

**Core Thread Settings:**

| Parameter | Default | Range | Purpose |
|-----------|---------|-------|---------|
| `minThreads` | CPU count | [2, 1024] | Minimum worker threads |
| `maxThreads` | 2× CPU count | [4, 1024] | Maximum worker threads |
| `maxQueueSize` | 10,000 | [1, 1M] | Maximum queued tasks |
| `ABSOLUTE_MIN_THREADS` | 2 | Fixed | Hard minimum |
| `MIN_THREAD_LIMIT` | 4 | Fixed | Minimum for `maxThreads` |

**Thread Lifetime:**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `threadIdleTimeout` | 30 seconds | Idle thread reclamation time |
| `taskTimeout` | 5 minutes | Maximum single-task execution time |

**Performance Tuning:**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `enableThreadAffinity` | `true` | Pin threads to CPU cores (round-robin) |
| `enablePriorityBoost` | `false` | Boost priority for completing tasks |
| `enableETW` | `true` | Emit ETW traces for all pool events |
| `enablePerformanceCounters` | `true` | Collect throughput metrics |

**Resource Limits:**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `maxMemoryPerThread` | 100 MB | Per-thread memory ceiling |
| `stackSizePerThread` | 1 MB | Worker thread stack size |
| `threadPriority` | `THREAD_PRIORITY_NORMAL` | Windows thread priority |

**Work Stealing:**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `enableWorkStealing` | `true` | Load balancing via task theft |
| `workStealingThreshold` | 3 | Minimum queue depth before stealing triggers |

**Diagnostics:**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `enableDeadlockDetection` | `true` | Background deadlock monitoring |
| `enableTaskProfiling` | `true` | Task execution timing |
| `deadlockCheckInterval` | 5 seconds | Deadlock check frequency |
| `threadNamePrefix` | `L"ShadowStrike-Worker"` | Debugger-visible thread name |

All configuration values are validated via `Validate()` before the pool starts. Invalid configurations (e.g., `minThreads > maxThreads`) are rejected at initialization time — the pool never operates in an inconsistent state.

---

## 5.3 Task Lifecycle

### 5.3.1 TaskContext

Every task carries a `TaskContext` that provides metadata, cancellation, and timing:

```cpp
struct TaskContext {
    uint64_t taskId;                    // Monotonic, lock-free generation
    TaskPriority priority;              // Scheduling priority
    steady_clock::time_point enqueueTime;  // When task was submitted
    steady_clock::time_point startTime;    // When execution began
    source_location location;           // C++20 source location (file/line/function)
    std::string description;            // Human-readable task name
    shared_ptr<atomic<bool>> cancellationToken;  // Cooperative cancellation
    std::chrono::milliseconds timeout;  // Optional per-task timeout
};
```

> 💡 **Advanced C++ Note:** The `source_location` parameter uses C++20's `std::source_location::current()` as a default argument. This captures the caller's file, line, and function at the **call site**, not inside the ThreadPool — so every task knows exactly where it was submitted from. This is invaluable for debugging stalled or failed tasks.

### 5.3.2 Task Submission

The pool offers six submission patterns, each using C++20 concepts for compile-time validation:

**1. Basic Submission:**

```cpp
auto future = pool.Submit(
    [](const TaskContext& ctx) -> ScanResult {
        return ScanFile(ctx, filePath);
    },
    TaskPriority::Critical,
    "RealTimeScan"
);
```

**2. Submission with Additional Arguments:**

```cpp
auto future = pool.Submit(
    [](const TaskContext& ctx, const std::wstring& path, bool deep) {
        return DeepScanFile(ctx, path, deep);
    },
    filePath,
    true  // deep scan
);
```

**3. Submission with Timeout:**

```cpp
auto future = pool.SubmitWithTimeout(
    std::chrono::seconds{10},
    [](TaskContext ctx) { return AnalyzeProcess(ctx); },
    TaskPriority::High,
    "ProcessAnalysis"
);
```

**4. Cancellable Submission:**

```cpp
auto token = ThreadPool::CreateCancellationToken();
auto future = pool.SubmitCancellable(
    token,
    [](TaskContext ctx) { /* Long operation */ },
    TaskPriority::Normal,
    "FullSystemScan"
);

// Later, if user clicks "Cancel":
token->store(true, std::memory_order_relaxed);
```

**5. Batch Submission:**

```cpp
std::vector<std::wstring> filePaths = GetAllFiles(directory);
auto futures = pool.SubmitBatch(
    [](const TaskContext& ctx, const std::wstring& path) {
        return QuickScanFile(ctx, path);
    },
    filePaths,
    TaskPriority::Normal
);
```

**6. Parallel For:**

```cpp
pool.ParallelFor<size_t>(0, fileCount,
    [&files](const TaskContext& ctx, size_t index) {
        ScanFile(ctx, files[index]);
    },
    TaskPriority::Normal
);
```

### 5.3.3 Task Execution Flow

```
Submit()
    │
    ├─ Generate taskId (atomic fetch_add, relaxed)
    ├─ Create TaskContext with source_location
    ├─ Wrap into TaskWrapper (type-erased)
    ├─ Push to PriorityTaskQueue
    │   ├─ Queue full? → Apply BackPressurePolicy
    │   │   ├─ Block:       wait on condition variable
    │   │   ├─ DropOldest:  pop oldest task, log warning
    │   │   └─ DropNewest:  discard incoming task, log warning
    │   └─ Update peakQueueSize (CAS loop)
    ├─ Increment pendingTasks (atomic)
    ├─ ETW: LogTaskEvent(TaskEnqueued)
    └─ Notify condition variable → wakes one worker

WorkerThread::Run()
    │
    ├─ Set thread name (SetThreadDescription API)
    ├─ Apply CPU affinity (SetThreadAffinityMask, round-robin)
    ├─ ETW: LogThreadEvent(ThreadCreated)
    │
    └─ Loop:
        ├─ Try Pop() from global queue
        ├─ No task? → Try Steal() from other workers
        ├─ Still nothing? → Wait on CV (10ms timeout)
        │
        ├─ Got task:
        │   ├─ Set busy_ = true
        │   ├─ Record startTime
        │   ├─ ETW: LogTaskEvent(TaskStarted)
        │   ├─ task.Execute()
        │   │   ├─ Call user function
        │   │   ├─ Catch exceptions → set in promise
        │   │   └─ Update statistics
        │   ├─ Set busy_ = false
        │   ├─ ETW: LogTaskEvent(TaskCompleted)
        │   └─ Update lastActivityTime_
        │
        └─ Check running_ flag → exit if false
```

---

## 5.4 Work Stealing

When a worker's local queue is empty, it doesn't just sleep — it **steals** tasks from other workers' queues:

```
Worker[0]: [T1, T2, T3, T4, T5]    ← Heavy load
Worker[1]: [T6]                      ← Light load
Worker[2]: []                        ← Idle

Worker[2] calls Steal():
  → Scans allWorkers_ vector
  → Finds Worker[0] has queue size > workStealingThreshold (3)
  → Pops T5 from Worker[0]'s queue
  → Worker[2] now executes T5
```

Work stealing activates only when a worker's queue depth exceeds `workStealingThreshold` (default: 3). This prevents thrashing on lightly-loaded systems while ensuring load balance under heavy scan workloads.

---

## 5.5 Statistics and Health Monitoring

### 5.5.1 Task Statistics

All counters use `std::atomic<uint64_t>` with `std::memory_order_relaxed` — exact counts aren't needed in real-time, but zero contention is:

```cpp
struct TaskStatistics {
    std::atomic<uint64_t> enqueuedCount{0};
    std::atomic<uint64_t> completedCount{0};
    std::atomic<uint64_t> failedCount{0};
    std::atomic<uint64_t> cancelledCount{0};
    std::atomic<uint64_t> timedOutCount{0};
    std::atomic<uint64_t> totalExecutionTimeMs{0};
    std::atomic<uint64_t> totalWaitTimeMs{0};
    std::atomic<uint64_t> minExecutionTimeMs{UINT64_MAX};
    std::atomic<uint64_t> maxExecutionTimeMs{0};

    [[nodiscard]] double GetAverageExecutionTimeMs() const noexcept;
    [[nodiscard]] double GetAverageWaitTimeMs() const noexcept;
    [[nodiscard]] double GetSuccessRate() const noexcept;  // 0-100%
};
```

> 📊 **Performance Note:** Using `memory_order_relaxed` on statistics counters is deliberate. These counters are read by health monitoring (every 5 seconds) and ETW events — neither requires sequential consistency. The relaxed ordering avoids cache-line bouncing that would degrade scan throughput on the hot path.

### 5.5.2 Thread Statistics

```cpp
struct ThreadStatistics {
    std::atomic<size_t> currentThreadCount{0};
    std::atomic<size_t> peakThreadCount{0};
    std::atomic<size_t> activeThreadCount{0};    // Currently executing tasks
    std::atomic<size_t> idleThreadCount{0};      // Waiting for work
    std::atomic<uint64_t> totalThreadsCreated{0};
    std::atomic<uint64_t> totalThreadsDestroyed{0};
    std::atomic<uint64_t> threadCreationFailures{0};
    std::atomic<uint64_t> threadExceptions{0};   // Uncaught exceptions
};
```

### 5.5.3 Performance Metrics

```cpp
struct PerformanceMetrics {
    std::atomic<size_t> currentQueueSize{0};
    std::atomic<size_t> peakQueueSize{0};
    std::atomic<uint64_t> tasksPerSecond{0};
    std::atomic<uint64_t> bytesProcessed{0};
    std::atomic<double> cpuUtilization{0.0};     // 0-100
    std::atomic<uint64_t> memoryUsage{0};        // Bytes
    std::atomic<uint64_t> totalUptime{0};        // Seconds

    void UpdateThroughput(uint64_t completedTasks,
                         std::chrono::milliseconds elapsed) noexcept;
};
```

### 5.5.4 Health Reports

The pool provides two diagnostic reports:

```cpp
std::string GetStatisticsReport() const;
// Sample output:
//   ThreadPool Statistics:
//     Tasks: 142,847 enqueued, 142,831 completed, 12 failed, 4 cancelled
//     Threads: 16 current (8 active, 8 idle), peak: 24
//     Queue: 0/10000 (peak: 847)
//     Success rate: 99.99%
//     Avg execution: 2.3ms, Avg wait: 0.1ms

std::string GetHealthReport() const;
// Sample output:
//   Health: HEALTHY
//     Success rate: 99.99% (threshold: 95%)
//     Deadlocks detected: 0
//     Queue utilization: 0% (threshold: 90%)
//     Memory: 42 MB / 1600 MB limit
```

---

## 5.6 ETW Integration

### 5.6.1 Provider Architecture

The ThreadPool registers as an ETW provider with GUID:

```
{A5F3D1E2-8B4C-4D5E-9F6A-1B2C3D4E5F6A}
```

This allows administrators to trace pool behavior using Windows Performance Recorder (WPR), PerfView, or custom ETW consumers:

```powershell
# Capture ThreadPool ETW traces:
logman start ShadowStrikePool -p "{A5F3D1E2-8B4C-4D5E-9F6A-1B2C3D4E5F6A}" -o pool.etl

# ... reproduce the issue ...

logman stop ShadowStrikePool
```

### 5.6.2 Event Catalog

All 20 pool events are strongly typed:

```cpp
enum class ETWEventId : uint8_t {
    ThreadPoolCreated     = 1,   // Pool initialization
    ThreadPoolDestroyed   = 2,   // Pool shutdown
    ThreadCreated         = 3,   // Worker thread spawned
    ThreadDestroyed       = 4,   // Worker thread exited
    TaskEnqueued          = 5,   // Task added to queue
    TaskStarted           = 6,   // Task execution began
    TaskCompleted         = 7,   // Task completed successfully
    TaskFailed            = 8,   // Task threw exception
    ThreadException       = 9,   // Uncaught worker exception
    PoolPaused            = 10,  // Pool paused (Pause())
    PoolResumed           = 11,  // Pool resumed (Resume())
    PoolResized           = 12,  // Thread count changed
    ThreadStarved         = 13,  // Worker starved for tasks
    QueueOverflow         = 14,  // Queue full, back-pressure applied
    PerformanceMetrics    = 15,  // Periodic metrics snapshot
    ThreadPriorityChanged = 16,  // Worker priority adjusted
    ThreadAffinityChanged = 17,  // Worker CPU affinity changed
    TaskCancelled         = 18,  // Task cancelled via token
    DeadlockDetected      = 19,  // Deadlock detector triggered
    MemoryPressure        = 20   // Memory limit approached
};
```

Each event includes severity level:

```cpp
enum class ETWLevel : uint8_t {
    LogAlways    = 0,    // Always logged
    Critical     = 1,    // Deadlock, crash-imminent
    Error        = 2,    // Task failure, exception
    Warning      = 3,    // Queue overflow, starvation
    Information  = 4,    // Normal lifecycle events
    Verbose      = 5     // Detailed task timing
};
```

---

## 5.7 Deadlock Detection

### 5.7.1 Detection Algorithm

The `DeadlockDetector` runs on a background timer (default: every 5 seconds) and monitors thread activity:

```
For each registered thread:
    elapsed = now - lastActivityTime
    if elapsed > kInactivityThreshold (30s):
        mark thread as suspicious

if suspicious_count / total_threads > kDeadlockSuspiciousRatio (50%):
    → DEADLOCK DETECTED
    → Log all suspicious thread IDs
    → ETW: DeadlockDetected (Critical)
    → Invoke health report for diagnostics
```

**Thread Registration:**

```cpp
void RegisterThread(DWORD threadId);     // Called on worker start
void UnregisterThread(DWORD threadId);   // Called on worker stop
void UpdateThreadActivity(DWORD threadId); // Called after each task
```

**Activity Tracking:**

```cpp
struct ThreadActivityInfo {
    DWORD threadId;
    steady_clock::time_point lastActivity;
    std::atomic<bool> active{true};
};
```

> 🔬 **Deep Dive:** The detector uses `std::shared_mutex` for the thread registry — activity updates are read-shared (occur on every task completion), while the periodic check loop takes an exclusive lock only to scan for deadlocks. This means activity tracking has zero contention during normal operation.

---

## 5.8 Concurrency Primitives Used Throughout ShadowStrike

### 5.8.1 Mutex Hierarchy

| Primitive | Used For | Example Module |
|-----------|----------|----------------|
| `std::shared_mutex` | Read-heavy data (signatures, whitelist) | `SignatureStore`, `HashStore` |
| `std::mutex` | Write-heavy or small critical sections | `Logger`, `QuarantineManager` |
| `std::recursive_mutex` | Callback chains that may re-enter | `BehaviorAnalyzer` |
| `std::atomic<T>` | Counters, flags, CAS operations | `TaskStatistics` |
| `std::condition_variable` | Task notification, shutdown signaling | `ThreadPool`, `Logger` |
| `std::latch` | One-shot synchronization barriers | `Initialize()` completion |
| `std::barrier` | Multi-phase synchronization | Batch scan wave completion |
| `std::counting_semaphore` | Resource limiting | Concurrent file handle limit |

### 5.8.2 Lock Guard Patterns

ShadowStrike never uses manual `lock()`/`unlock()`. All locking uses RAII guards:

```cpp
// Read access (multiple readers concurrently):
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache.find(key);
}

// Write access (exclusive):
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_cache[key] = value;
}

// Conditional wait (writer):
{
    std::unique_lock<std::mutex> lock(m_queueMutex);
    m_cv.wait(lock, [this] { return !m_queue.empty() || m_shutdown; });
}
```

### 5.8.3 Lock Ordering Convention

To prevent deadlocks in multi-lock scenarios, ShadowStrike follows a strict acquisition order:

```
1. Configuration locks (LoggerConfig, EngineConfig)
2. Store locks (SignatureStore, HashStore, WhitelistStore)
3. Cache locks (ScanCache, ReputationCache)
4. Queue locks (ThreadPool queue, Logger queue)
5. Statistics locks (TaskStatistics, PerformanceMetrics)
```

A module at level N never acquires a lock at level ≤N while already holding a lock. This is enforced by code review, not runtime checking — but the deadlock detector provides a safety net.

---

## 5.9 Kernel-Mode Threading

In the kernel driver (`PhantomSensor`), threading rules are fundamentally different:

| User-Mode Concept | Kernel-Mode Equivalent |
|-------------------|----------------------|
| `std::thread` | `PsCreateSystemThread` |
| `std::mutex` | `FAST_MUTEX`, `ERESOURCE` |
| `std::shared_mutex` | `ERESOURCE` (shared/exclusive) |
| `std::atomic` | `InterlockedIncrement64` |
| `std::condition_variable` | `KeWaitForSingleObject` + `KEVENT` |
| `ThreadPool::Submit` | `IoQueueWorkItem` |
| `std::latch` | `KeWaitForMultipleObjects` |

The kernel driver uses its own thread pool implementation (`PhantomSensor/Sync/`) based on `IO_WORKITEM` and system worker threads. See **Volume 2: The Kernel Sentinel** for details.

---

## 5.10 Summary

| Component | Key Feature | Critical for |
|-----------|-------------|-------------|
| ThreadPool | Work-stealing priority queue | Scan throughput |
| TaskPriority | 5-level priority system | Real-time response |
| ETWTracingManager | 20 structured event types | Field diagnostics |
| DeadlockDetector | 50% inactivity threshold | Reliability |
| Statistics | Lock-free atomic counters | Health monitoring |
| Cancellation | Cooperative tokens + futures | User experience |

The threading model ensures ShadowStrike can scan thousands of files per second while remaining responsive to real-time kernel callbacks — the foundation everything else is built on.

---

*Previous: [Chapter 4 — The Build System](ch04-build-system.md)*
*Next: [Chapter 6 — Error Handling & Logging Infrastructure](ch06-error-handling-logging.md)*
