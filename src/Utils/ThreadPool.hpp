/**
 * @file ThreadPool.hpp
 * @brief Enterprise-grade thread pool implementation with ETW tracing support
 *
 * This file provides a comprehensive thread pool implementation designed for
 * high-performance, mission-critical security applications. Features include:
 * - Priority-based task scheduling
 * - Work stealing for load balancing
 * - ETW (Event Tracing for Windows) integration
 * - Deadlock detection
 * - Cancellation token support
 * - Comprehensive statistics and metrics
 *
 * @note This implementation is Windows-specific and uses Windows APIs.
 * @warning Thread pool operations are not signal-safe.
 *
 * @copyright ShadowStrike Security Suite
 */

#pragma once

#ifndef SHADOWSTRIKE_THREADPOOL_HPP
#define SHADOWSTRIKE_THREADPOOL_HPP

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#endif // _WIN32

#include <Windows.h>
#include <evntprov.h>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>
#include <memory>
#include <chrono>
#include <string>
#include <unordered_map>
#include <optional>
#include <concepts>
#include <type_traits>
#include <source_location>
#include <span>
#include <ranges>
#include <latch>
#include <barrier>
#include <semaphore>
#include <shared_mutex>
#include <cstdint>
#include <limits>

namespace ShadowStrike::Utils {

//=============================================================================
// Constants
//=============================================================================

namespace ThreadPoolConstants {
    /** Maximum allowed number of worker threads */
    inline constexpr size_t kMaxThreads = 1024;

    /** Maximum queue size to prevent memory exhaustion */
    inline constexpr size_t kMaxQueueSize = 1000000;

    /** Default idle timeout for worker threads (30 seconds) */
    inline constexpr std::chrono::milliseconds kDefaultIdleTimeout{30000};

    /** Default task timeout (5 minutes) */
    inline constexpr std::chrono::milliseconds kDefaultTaskTimeout{300000};

    /** Default stack size per thread (1 MB) */
    inline constexpr size_t kDefaultStackSize = 1024 * 1024;

    /** Default max memory per thread (100 MB) */
    inline constexpr size_t kDefaultMaxMemoryPerThread = 100 * 1024 * 1024;

    /** Default deadlock check interval (5 seconds) */
    inline constexpr std::chrono::milliseconds kDefaultDeadlockCheckInterval{5000};

    /** Suspicious thread inactivity threshold (30 seconds) */
    inline constexpr std::chrono::seconds kInactivityThreshold{30};

    /** Queue overflow threshold percentage */
    inline constexpr double kQueueOverflowThreshold = 0.9;

    /** Deadlock detection suspicious ratio */
    inline constexpr double kDeadlockSuspiciousRatio = 0.5;

    /** Health check success rate threshold */
    inline constexpr double kHealthySuccessRate = 95.0;
} // namespace ThreadPoolConstants

//=============================================================================
// ETW Provider GUID and Event Descriptors
//=============================================================================

/**
 * ETW Provider GUID for ShadowStrike ThreadPool
 * {A5F3D1E2-8B4C-4D5E-9F6A-1B2C3D4E5F6A}
 */
inline constexpr GUID SHADOWSTRIKE_THREADPOOL_PROVIDER = 
    { 0xa5f3d1e2, 0x8b4c, 0x4d5e, { 0x9f, 0x6a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a } };

/**
 * @enum ETWEventId
 * @brief ETW Event identifiers for ThreadPool diagnostics
 */
enum class ETWEventId : uint8_t {
    ThreadPoolCreated = 1,      ///< Thread pool instance created
    ThreadPoolDestroyed = 2,    ///< Thread pool instance destroyed
    ThreadCreated = 3,          ///< Worker thread created
    ThreadDestroyed = 4,        ///< Worker thread destroyed
    TaskEnqueued = 5,           ///< Task added to queue
    TaskStarted = 6,            ///< Task execution started
    TaskCompleted = 7,          ///< Task execution completed successfully
    TaskFailed = 8,             ///< Task execution failed with exception
    ThreadException = 9,        ///< Worker thread caught exception
    PoolPaused = 10,            ///< Thread pool paused
    PoolResumed = 11,           ///< Thread pool resumed
    PoolResized = 12,           ///< Thread pool size changed
    ThreadStarved = 13,         ///< Thread starvation detected
    QueueOverflow = 14,         ///< Task queue near or at capacity
    PerformanceMetrics = 15,    ///< Periodic performance metrics
    ThreadPriorityChanged = 16, ///< Thread priority modified
    ThreadAffinityChanged = 17, ///< Thread affinity mask changed
    TaskCancelled = 18,         ///< Task was cancelled before completion
    DeadlockDetected = 19,      ///< Potential deadlock detected
    MemoryPressure = 20         ///< High memory usage warning
};

/**
 * @enum ETWLevel
 * @brief ETW Event severity levels
 */
enum class ETWLevel : uint8_t {
    LogAlways = 0,    ///< Always logged
    Critical = 1,     ///< Critical errors
    Error = 2,        ///< Errors
    Warning = 3,      ///< Warnings
    Information = 4,  ///< Informational
    Verbose = 5       ///< Verbose/debug
};

//=============================================================================
// Task Priority System
//=============================================================================

/**
 * @enum TaskPriority
 * @brief Task scheduling priority levels
 *
 * Lower values indicate higher priority. Tasks with higher priority
 * are dequeued and executed before lower priority tasks.
 */
enum class TaskPriority : uint8_t {
    Critical = 0,  ///< Highest priority - real-time threat scanning
    High = 1,      ///< High priority - user-initiated operations
    Normal = 2,    ///< Normal priority - background processing
    Low = 3,       ///< Low priority - scheduled maintenance
    Idle = 4       ///< Lowest priority - idle-time operations
};

//=============================================================================
// Thread Pool Configuration
//=============================================================================

/**
 * @struct ThreadPoolConfig
 * @brief Configuration options for ThreadPool initialization
 *
 * This structure contains all configurable parameters for the thread pool.
 * Use Validate() to check if the configuration is valid before use.
 */
struct ThreadPoolConfig {
    //-------------------------------------------------------------------------
    // Core Thread Pool Settings
    //-------------------------------------------------------------------------
    
    /** Absolute floor for the minimum number of threads */
    static constexpr size_t ABSOLUTE_MIN_THREADS = 2;

    /** Minimum allowed capacity for max threads */
    static constexpr size_t MIN_THREAD_LIMIT = 4;

	/** Minimum number of worker threads */
    size_t minThreads = std::max<size_t>(ABSOLUTE_MIN_THREADS, std::thread::hardware_concurrency());

	/** Maximum number of worker threads */
    size_t maxThreads = std::max(MIN_THREAD_LIMIT, static_cast<size_t>(std::thread::hardware_concurrency() * 2));
    
    /** Maximum number of tasks in the queue */
    size_t maxQueueSize = 10000;
    
    //-------------------------------------------------------------------------
    // Thread Lifetime Settings
    //-------------------------------------------------------------------------
    
    /** Idle timeout before thread can be terminated */
    std::chrono::milliseconds threadIdleTimeout{ThreadPoolConstants::kDefaultIdleTimeout};
    
    /** Maximum time a task can execute before timeout */
    std::chrono::milliseconds taskTimeout{ThreadPoolConstants::kDefaultTaskTimeout};
    
    //-------------------------------------------------------------------------
    // Performance Tuning
    //-------------------------------------------------------------------------
    
    /** Enable thread affinity assignment */
    bool enableThreadAffinity = true;
    
    /** Enable priority boost for completing tasks */
    bool enablePriorityBoost = false;
    
    /** Enable ETW event tracing */
    bool enableETW = true;
    
    /** Enable performance counter collection */
    bool enablePerformanceCounters = true;
    
    //-------------------------------------------------------------------------
    // Resource Limits
    //-------------------------------------------------------------------------
    
    /** Maximum memory allocation per thread */
    size_t maxMemoryPerThread = ThreadPoolConstants::kDefaultMaxMemoryPerThread;
    
    /** Stack size for each worker thread */
    size_t stackSizePerThread = ThreadPoolConstants::kDefaultStackSize;
    
    //-------------------------------------------------------------------------
    // Thread Priority
    //-------------------------------------------------------------------------
    
    /** Default thread priority for worker threads */
    int threadPriority = THREAD_PRIORITY_NORMAL;
    
    //-------------------------------------------------------------------------
    // Debugging and Diagnostics
    //-------------------------------------------------------------------------
    
    /** Enable deadlock detection monitoring */
    bool enableDeadlockDetection = true;
    
    /** Enable task execution profiling */
    bool enableTaskProfiling = true;
    
    /** Interval between deadlock detection checks */
    std::chrono::milliseconds deadlockCheckInterval{ThreadPoolConstants::kDefaultDeadlockCheckInterval};
    
    //-------------------------------------------------------------------------
    // Thread Naming
    //-------------------------------------------------------------------------
    
    /** Prefix for worker thread names (visible in debugger) */
    std::wstring threadNamePrefix = L"ShadowStrike-Worker";
    
    //-------------------------------------------------------------------------
    // Work Stealing
    //-------------------------------------------------------------------------
    
    /** Enable work stealing between worker threads */
    bool enableWorkStealing = true;
    
    /** Minimum queue depth before work stealing activates */
    size_t workStealingThreshold = 3;
    
    //-------------------------------------------------------------------------
    // Methods
    //-------------------------------------------------------------------------
    
    /**
     * @brief Validates the configuration parameters
     * @return true if configuration is valid, false otherwise
     */
    [[nodiscard]] bool Validate() const noexcept;
};

//=============================================================================
// Task Statistics
//=============================================================================

/**
 * @struct TaskStatistics
 * @brief Tracks task execution statistics
 *
 * All counters are atomic for thread-safe access without external locking.
 * Use relaxed memory ordering for statistics that don't need strict ordering.
 */
struct TaskStatistics {
    /** Total number of tasks enqueued */
    std::atomic<uint64_t> enqueuedCount{0};
    
    /** Number of tasks completed successfully */
    std::atomic<uint64_t> completedCount{0};
    
    /** Number of tasks that failed with exceptions */
    std::atomic<uint64_t> failedCount{0};
    
    /** Number of tasks cancelled before execution */
    std::atomic<uint64_t> cancelledCount{0};
    
    /** Number of tasks that exceeded timeout */
    std::atomic<uint64_t> timedOutCount{0};
    
    /** Cumulative execution time in milliseconds */
    std::atomic<uint64_t> totalExecutionTimeMs{0};
    
    /** Cumulative wait time in queue in milliseconds */
    std::atomic<uint64_t> totalWaitTimeMs{0};
    
    /** Minimum task execution time in milliseconds */
    std::atomic<uint64_t> minExecutionTimeMs{std::numeric_limits<uint64_t>::max()};
    
    /** Maximum task execution time in milliseconds */
    std::atomic<uint64_t> maxExecutionTimeMs{0};
    
    /** Resets all statistics to initial values */
    void Reset() noexcept;
    
    /** @return Average task execution time in milliseconds, or 0 if no tasks completed */
    [[nodiscard]] double GetAverageExecutionTimeMs() const noexcept;
    
    /** @return Average time tasks spend in queue in milliseconds */
    [[nodiscard]] double GetAverageWaitTimeMs() const noexcept;
    
    /** @return Percentage of tasks completed successfully (0-100) */
    [[nodiscard]] double GetSuccessRate() const noexcept;
};

//=============================================================================
// Thread Statistics
//=============================================================================

/**
 * @struct ThreadStatistics
 * @brief Tracks worker thread statistics
 */
struct ThreadStatistics {
    /** Current number of active worker threads */
    std::atomic<size_t> currentThreadCount{0};
    
    /** Peak number of concurrent threads */
    std::atomic<size_t> peakThreadCount{0};
    
    /** Number of threads currently executing tasks */
    std::atomic<size_t> activeThreadCount{0};
    
    /** Number of idle threads waiting for work */
    std::atomic<size_t> idleThreadCount{0};
    
    /** Total threads created during pool lifetime */
    std::atomic<uint64_t> totalThreadsCreated{0};
    
    /** Total threads destroyed during pool lifetime */
    std::atomic<uint64_t> totalThreadsDestroyed{0};
    
    /** Number of thread creation failures */
    std::atomic<uint64_t> threadCreationFailures{0};
    
    /** Number of exceptions caught by worker threads */
    std::atomic<uint64_t> threadExceptions{0};
    
    /** Resets all statistics to initial values */
    void Reset() noexcept;
};

//=============================================================================
// Performance Metrics
//=============================================================================

/**
 * @struct PerformanceMetrics
 * @brief Real-time performance monitoring data
 */
struct PerformanceMetrics {
    /** Current number of tasks in queue */
    std::atomic<size_t> currentQueueSize{0};
    
    /** Peak queue size observed */
    std::atomic<size_t> peakQueueSize{0};
    
    /** Estimated tasks completed per second */
    std::atomic<uint64_t> tasksPerSecond{0};
    
    /** Total bytes processed by tasks */
    std::atomic<uint64_t> bytesProcessed{0};
    
    /** Estimated CPU utilization (0-100) */
    std::atomic<double> cpuUtilization{0.0};
    
    /** Current memory usage in bytes */
    std::atomic<uint64_t> memoryUsage{0};
    
    /** Time point when pool was started */
    std::chrono::steady_clock::time_point startTime{std::chrono::steady_clock::now()};
    
    /** Total uptime in seconds */
    std::atomic<uint64_t> totalUptime{0};
    
    /** Resets all metrics to initial values */
    void Reset() noexcept;
    
    /**
     * @brief Updates throughput calculation
     * @param completedTasks Number of tasks completed
     * @param elapsed Time elapsed since last update
     */
    void UpdateThroughput(uint64_t completedTasks, 
                         std::chrono::milliseconds elapsed) noexcept;
};

//=============================================================================
// Task Context
//=============================================================================

/**
 * @struct TaskContext
 * @brief Context information passed to each task during execution
 *
 * TaskContext provides tasks with:
 * - Unique task identifier
 * - Priority information
 * - Timing information (enqueue/start times)
 * - Source location for debugging
 * - Cancellation token for cooperative cancellation
 * - Optional timeout
 */
struct TaskContext {
    /** Unique identifier for this task */
    uint64_t taskId{0};
    
    /** Task priority level */
    TaskPriority priority{TaskPriority::Normal};
    
    /** Time when task was added to queue */
    std::chrono::steady_clock::time_point enqueueTime{std::chrono::steady_clock::now()};
    
    /** Time when task execution started */
    std::chrono::steady_clock::time_point startTime{};
    
    /** Source location where task was submitted */
    std::source_location location{std::source_location::current()};
    
    /** Human-readable task description */
    std::string description;
    
    /** Shared cancellation token for cooperative cancellation */
    std::shared_ptr<std::atomic<bool>> cancellationToken;
    
    /** Optional timeout for task execution */
    std::optional<std::chrono::milliseconds> timeout;
    
    /** Default constructor */
    TaskContext();
    
    /**
     * @brief Construct with priority and description
     * @param prio Task priority
     * @param desc Task description
     * @param loc Source location (auto-captured)
     */
    explicit TaskContext(TaskPriority prio, 
                        std::string desc = "",
                        std::source_location loc = std::source_location::current());
    
    /**
     * @brief Check if task has been cancelled
     * @return true if cancellation was requested
     */
    [[nodiscard]] bool IsCancelled() const noexcept;
    
    /**
     * @brief Request task cancellation
     * @note This is cooperative - task must check IsCancelled()
     */
    void Cancel() noexcept;
    
    /**
     * @brief Get time spent waiting in queue
     * @return Wait time as milliseconds
     */
    [[nodiscard]] std::chrono::milliseconds GetWaitTime() const noexcept;
};

//=============================================================================
// Task Wrapper Template
//=============================================================================

/**
 * @class Task
 * @brief Type-safe task wrapper with future support
 *
 * Task wraps a callable with its associated context and provides
 * a shared_future for retrieving the result.
 *
 * @tparam ResultType The return type of the task function
 */
template<typename ResultType>
class Task {
public:
    using TaskFunction = std::function<ResultType(const TaskContext&)>;
    
    /** Default constructor - creates invalid task */
    Task() = default;
    
    /**
     * @brief Construct task from callable
     * @tparam Func Callable type
     * @param func The callable to execute
     * @param ctx Task context
     */
    template<typename Func>
    Task(Func&& func, TaskContext ctx) 
        : function_(std::forward<Func>(func))
        , context_(std::move(ctx))
        , promise_(std::make_shared<std::promise<ResultType>>())
        , future_(promise_->get_future().share())
    {}
    
    /**
     * @brief Execute the task
     * @note Sets the promise with result or exception
     */
    void Execute() {
        if (!function_) {
            return; // Invalid task
        }
        
        try {
            context_.startTime = std::chrono::steady_clock::now();
            
            if constexpr (std::is_void_v<ResultType>) {
                function_(context_);
                promise_->set_value();
            } else {
                auto result = function_(context_);
                promise_->set_value(std::move(result));
            }
        } catch (...) {
            try {
                promise_->set_exception(std::current_exception());
            } catch (...) {
                // Promise already satisfied - ignore
            }
        }
    }
    
    /** @return Shared future for task result */
    [[nodiscard]] std::shared_future<ResultType> GetFuture() const noexcept {
        return future_;
    }
    
    /** @return Const reference to task context */
    [[nodiscard]] const TaskContext& GetContext() const noexcept {
        return context_;
    }
    
    /** @return Mutable reference to task context */
    [[nodiscard]] TaskContext& GetContext() noexcept {
        return context_;
    }
    
    /** @return true if task has a valid callable */
    [[nodiscard]] bool IsValid() const noexcept {
        return function_ != nullptr;
    }
    
    /** Request task cancellation */
    void Cancel() noexcept {
        context_.Cancel();
    }
    
    /** @return true if task was cancelled */
    [[nodiscard]] bool IsCancelled() const noexcept {
        return context_.IsCancelled();
    }
    
private:
    TaskFunction function_;
    TaskContext context_;
    std::shared_ptr<std::promise<ResultType>> promise_;
    std::shared_future<ResultType> future_;
};

//=============================================================================
// Type-Erased Task Wrapper
//=============================================================================

/**
 * @class TaskWrapper
 * @brief Type-erased task wrapper for queue storage
 *
 * TaskWrapper allows storing tasks of any return type in the same queue
 * by erasing the type information and storing only the executor.
 */
class TaskWrapper {
public:
    /** Default constructor - creates empty wrapper */
    TaskWrapper() = default;
    
    /**
     * @brief Construct from typed Task
     * @tparam ResultType Task result type
     * @param task The task to wrap
     */
    template<typename ResultType>
    explicit TaskWrapper(Task<ResultType> task)
        : executor_([t = std::move(task)]() mutable { t.Execute(); })
        , context_(task.GetContext())
    {}
    
    /** Execute the wrapped task */
    void Execute() {
        if (executor_) {
            executor_();
        }
    }
    
    /** @return Const reference to task context */
    [[nodiscard]] const TaskContext& GetContext() const noexcept {
        return context_;
    }
    
    /** @return Mutable reference to task context */
    [[nodiscard]] TaskContext& GetContext() noexcept {
        return context_;
    }
    
    /** @return true if task was cancelled */
    [[nodiscard]] bool IsCancelled() const noexcept {
        return context_.IsCancelled();
    }
    
    /** Request task cancellation */
    void Cancel() noexcept {
        context_.Cancel();
    }
    
    /** @return true if wrapper contains a valid task */
    [[nodiscard]] bool IsValid() const noexcept {
        return executor_ != nullptr;
    }
    
private:
    std::function<void()> executor_;
    TaskContext context_;
};

// ============================================================================
// Priority Queue for Tasks
// ============================================================================
class PriorityTaskQueue {
public:
    explicit PriorityTaskQueue(size_t maxSize = 10000);
    ~PriorityTaskQueue() = default;
    
    // Non-copyable, moveable
    PriorityTaskQueue(const PriorityTaskQueue&) = delete;
    PriorityTaskQueue& operator=(const PriorityTaskQueue&) = delete;
    PriorityTaskQueue(PriorityTaskQueue&&) noexcept = default;
    PriorityTaskQueue& operator=(PriorityTaskQueue&&) noexcept = default;
    
    bool Push(TaskWrapper task);
    std::optional<TaskWrapper> Pop();
    std::optional<TaskWrapper> TryPop();
    std::optional<TaskWrapper> Steal(); // For work stealing
    
    [[nodiscard]] size_t Size() const noexcept;
    [[nodiscard]] bool IsEmpty() const noexcept;
    [[nodiscard]] bool IsFull() const noexcept;
    [[nodiscard]] size_t GetMaxSize() const noexcept;
    
    void Clear();
    void SetMaxSize(size_t maxSize);
    
private:
    struct TaskComparator {
        bool operator()(const TaskWrapper& lhs, const TaskWrapper& rhs) const {
            // Higher priority value = lower priority in queue (min-heap)
            return static_cast<uint8_t>(lhs.GetContext().priority) > 
                   static_cast<uint8_t>(rhs.GetContext().priority);
        }
    };
    
    std::priority_queue<TaskWrapper, std::vector<TaskWrapper>, TaskComparator> queue_;
    mutable std::mutex mutex_;
    size_t maxSize_;
};

// ============================================================================
// Worker Thread
// ============================================================================

class ETWTracingManager;  // Forward declaration

class WorkerThread {
public:
    explicit WorkerThread(
        size_t threadId,
        PriorityTaskQueue& globalQueue,
        std::vector<std::unique_ptr<WorkerThread>>& allWorkers,
        const ThreadPoolConfig& config,
        std::atomic<size_t>& pendingTasks,
        ETWTracingManager* etwManager = nullptr
    );
    ~WorkerThread();
    
    // Non-copyable, non-moveable
    WorkerThread(const WorkerThread&) = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;
    WorkerThread(WorkerThread&&) = delete;
    WorkerThread& operator=(WorkerThread&&) = delete;
    
    void Start();
    void Stop();
    void Pause();
    void Resume();
    
    [[nodiscard]] bool IsRunning() const noexcept;
    [[nodiscard]] bool IsBusy() const noexcept;
    [[nodiscard]] bool IsPaused() const noexcept;
    [[nodiscard]] size_t GetThreadId() const noexcept;
    [[nodiscard]] DWORD GetSystemThreadId() const noexcept;
    [[nodiscard]] uint64_t GetTasksProcessed() const noexcept;
    
    void SetPriority(int priority);
    void SetAffinity(DWORD_PTR affinityMask);
    
private:
   
    void WorkerLoop();
    bool TryStealWork(TaskWrapper& task);
    void ExecuteTask(TaskWrapper& task);
    void SetThreadName(const std::wstring& name);
    void LogETWEvent(ETWEventId eventId, const std::wstring& message, ETWLevel level);
    
    size_t threadId_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> busy_{false};
    std::atomic<uint64_t> tasksProcessed_{0};
    
    PriorityTaskQueue& globalQueue_;
    std::vector<std::unique_ptr<WorkerThread>>& allWorkers_;
    const ThreadPoolConfig& config_;

    ETWTracingManager* etwManager_;

    std::atomic<size_t>& pendingTasks_;
    
    DWORD systemThreadId_{0};
    std::chrono::steady_clock::time_point lastActivityTime_;
    
    // Performance tracking
    std::atomic<uint64_t> executionTimeMs_{0};
    std::atomic<uint64_t> idleTimeMs_{0};

    std::condition_variable cv_;
	std::mutex cvMutex_;
};

// ============================================================================
// ETW Tracing Manager
// ============================================================================
class ETWTracingManager {
public:
    ETWTracingManager();
    ~ETWTracingManager();
    
    // Non-copyable, non-moveable
    ETWTracingManager(const ETWTracingManager&) = delete;
    ETWTracingManager& operator=(const ETWTracingManager&) = delete;
    ETWTracingManager(ETWTracingManager&&) = delete;
    ETWTracingManager& operator=(ETWTracingManager&&) = delete;
    
    [[nodiscard]] bool Initialize();
    void Shutdown();
    
    void LogEvent(ETWEventId eventId, ETWLevel level, 
                 const std::wstring& message,
                 std::span<const BYTE> additionalData = {});
    
    void LogTaskEvent(ETWEventId eventId, uint64_t taskId, 
                     const std::string& taskDescription,
                     uint64_t durationMs = 0);
    
    void LogThreadEvent(ETWEventId eventId, DWORD threadId, 
                       const std::wstring& message);
    
    void LogPerformanceMetrics(const PerformanceMetrics& metrics,
                              const TaskStatistics& taskStats,
                              const ThreadStatistics& threadStats);
    
    [[nodiscard]] bool IsEnabled() const noexcept;
    
private:
    REGHANDLE registrationHandle_{0};
    std::atomic<bool> enabled_{false};
    mutable std::mutex mutex_;
};

// ============================================================================
// Deadlock Detector
// ============================================================================
class DeadlockDetector {
public:
    DeadlockDetector();
    ~DeadlockDetector();
    
    void Start(std::chrono::milliseconds checkInterval);
    void Stop();
    
    void RegisterThread(DWORD threadId);
    void UnregisterThread(DWORD threadId);
    void UpdateThreadActivity(DWORD threadId);
    
    [[nodiscard]] bool IsDeadlockDetected() const noexcept;
    [[nodiscard]] std::vector<DWORD> GetSuspiciousThreads() const;
    
private:
    void DetectionLoop();
    bool CheckForDeadlock();
    
    struct ThreadActivityInfo {
        DWORD threadId;
        std::chrono::steady_clock::time_point lastActivity;
        std::atomic<bool> active{true};

        ThreadActivityInfo(DWORD id, std::chrono::steady_clock::time_point time, bool isActive = true)
            : threadId(id)
            , lastActivity(time)
            , active(isActive)
        {
        }

        ThreadActivityInfo()
            : threadId(0)
            , lastActivity(std::chrono::steady_clock::now())
            , active(false)
        {
        }

    };
    
    std::unordered_map<DWORD, ThreadActivityInfo> threadActivity_;
    mutable std::shared_mutex activityMutex_;
    
    std::thread detectionThread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> deadlockDetected_{false};
    std::chrono::milliseconds checkInterval_;
};

// ============================================================================
// Main Thread Pool Class
// ============================================================================
class ThreadPool {
public:
    // Constructor and Destructor
    explicit ThreadPool(ThreadPoolConfig config = ThreadPoolConfig{});
    ~ThreadPool();
    
    // Non-copyable, non-moveable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
    
    // ========================================================================
    // Lifecycle Management
    // ========================================================================
    
    [[nodiscard]] bool Initialize();
    void Shutdown(bool waitForCompletion = true);
    void Pause();
    void Resume();
    
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] bool IsShutdown() const noexcept;
    [[nodiscard]] bool IsPaused() const noexcept;
    
    // ========================================================================
    // Task Submission
    // ========================================================================
    
	//Submit without args
    template<typename Func>
        requires std::invocable<Func, const TaskContext&>
    [[nodiscard]] auto Submit(
        Func&& func,
        TaskPriority priority = TaskPriority::Normal,
        std::string description = "",
        std::source_location location = std::source_location::current()
    ) -> std::shared_future<std::invoke_result_t<Func, const TaskContext&>>;

	//Submit with args
    template<typename Func, typename... Args>
        requires (sizeof...(Args) > 0) && std::invocable<Func, const TaskContext&, Args...>
    [[nodiscard]] auto Submit(
        Func&& func,
        Args&&... args
    ) -> std::shared_future<std::invoke_result_t<Func, const TaskContext&, Args...>>;

    // Submit with explicit timeout
    template<typename Func, typename... Args>
        requires std::invocable<Func, TaskContext, Args...>
    [[nodiscard]] auto SubmitWithTimeout(
        std::chrono::milliseconds timeout,
        Func&& func,
        Args&&... args,
        TaskPriority priority = TaskPriority::Normal,
        std::string description = "",
        std::source_location location = std::source_location::current()
    ) -> std::shared_future<std::invoke_result_t<Func, TaskContext, Args...>>;
    
    // Submit with cancellation token
    template<typename Func, typename... Args>
        requires std::invocable<Func, TaskContext, Args...>
    [[nodiscard]] auto SubmitCancellable(
        std::shared_ptr<std::atomic<bool>> cancellationToken,
        Func&& func,
        Args&&... args,
        TaskPriority priority = TaskPriority::Normal,
        std::string description = "",
        std::source_location location = std::source_location::current()
    ) -> std::shared_future<std::invoke_result_t<Func, TaskContext, Args...>>;
    
    // Batch submission
    template<typename Func, typename InputRange>
        requires std::invocable<Func, const TaskContext&, std::ranges::range_value_t<InputRange>>
    [[nodiscard]] auto SubmitBatch(
        Func&& func,
        InputRange&& inputs,
        TaskPriority priority = TaskPriority::Normal
    ) -> std::vector<std::shared_future<std::invoke_result_t<Func, const TaskContext&,
        std::ranges::range_value_t<InputRange>>>>;
    
    // Parallel for loop
    // Parallel for loop
    template<typename IndexType, typename Func>
        requires std::integral<IndexType>&& std::invocable<Func, const TaskContext&, IndexType>
    void ParallelFor(
        IndexType start,
        IndexType end,
        Func&& func,
        TaskPriority priority = TaskPriority::Normal 
    );
    
    // ========================================================================
    // Thread Pool Management
    // ========================================================================
    
    void IncreaseThreadCount(size_t count);
    void DecreaseThreadCount(size_t count);
    void SetThreadCount(size_t count);
    
    [[nodiscard]] size_t GetThreadCount() const noexcept;
    [[nodiscard]] size_t GetActiveThreadCount() const noexcept;
    [[nodiscard]] size_t GetIdleThreadCount() const noexcept;
    
    void SetThreadPriority(int priority);
    void SetThreadAffinity(DWORD_PTR affinityMask);
    
    // ========================================================================
    // Queue Management
    // ========================================================================
    
    [[nodiscard]] size_t GetQueueSize() const noexcept;
    [[nodiscard]] size_t GetQueueCapacity() const noexcept;
    [[nodiscard]] bool IsQueueFull() const noexcept;
    [[nodiscard]] bool IsQueueEmpty() const noexcept;
    
    void ClearQueue();
    void SetQueueCapacity(size_t capacity);
    
    // ========================================================================
    // Statistics and Metrics
    // ========================================================================
    
    [[nodiscard]] const TaskStatistics& GetTaskStatistics() const noexcept;
    [[nodiscard]] const ThreadStatistics& GetThreadStatistics() const noexcept;
    [[nodiscard]] const PerformanceMetrics& GetPerformanceMetrics() const noexcept;
    
    void ResetStatistics();
    
    [[nodiscard]] std::string GetStatisticsReport() const;
    [[nodiscard]] std::string GetHealthReport() const;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    [[nodiscard]] const ThreadPoolConfig& GetConfig() const noexcept;
    void UpdateConfig(const ThreadPoolConfig& config);
    
    // ========================================================================
    // Utilities
    // ========================================================================
    
    void WaitForAll();
    bool WaitForAll(std::chrono::milliseconds timeout);
    
    [[nodiscard]] std::optional<std::exception_ptr> GetLastException() const noexcept;
    
    // Create a cancellation token
    [[nodiscard]] static std::shared_ptr<std::atomic<bool>> CreateCancellationToken();
    
private:
    // ========================================================================
    // Internal Helper Methods
    // ========================================================================
    
    void CreateWorkerThreads(size_t count);
    void DestroyWorkerThreads(size_t count);
    void MonitoringLoop();
    void UpdateMetrics();
    void CheckThreadHealth();
    void HandleOverflow();
    void OptimizeThreadCount();
    
    template<typename ResultType>
    bool EnqueueTask(Task<ResultType> task);
    
    void LogETWEvent(ETWEventId eventId, const std::wstring& message, 
                    ETWLevel level = ETWLevel::Information);
    
    // ========================================================================
    // Member Variables
    // ========================================================================
    
    // Configuration
    ThreadPoolConfig config_;
    
    // Thread management
    std::vector<std::unique_ptr<WorkerThread>> workers_;
    std::vector<std::unique_ptr<PriorityTaskQueue>> queues_;
    mutable std::shared_mutex workersMutex_;
    
    // Task queue
    PriorityTaskQueue globalQueue_;
    
    // State management
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> paused_{false};
    
    // Statistics
    TaskStatistics taskStats_;
    ThreadStatistics threadStats_;
    PerformanceMetrics perfMetrics_;
    
    // ETW Tracing
    std::unique_ptr<ETWTracingManager> etwManager_;
    
    // Deadlock Detection
    std::unique_ptr<DeadlockDetector> deadlockDetector_;
    
    // Monitoring
    std::thread monitoringThread_;
    std::atomic<bool> monitoringActive_{false};
    
    // Exception handling
    mutable std::mutex exceptionMutex_;
    std::exception_ptr lastException_;
    
    // Task ID generator
    std::atomic<uint64_t> nextTaskId_{1};
    
    // Synchronization for shutdown
    std::counting_semaphore<> taskCompletionSemaphore_{0};
    std::atomic<size_t> pendingTasks_{0};
};

// ============================================================================
// Template Implementation
// ============================================================================

// ============================================================================
// Submit Implementation - Without args
// ============================================================================
template<typename Func>
    requires std::invocable<Func, const TaskContext&>
auto ThreadPool::Submit(
    Func&& func,
    TaskPriority priority,
    std::string description,
    std::source_location location
) -> std::shared_future<std::invoke_result_t<Func, const TaskContext&>>
{
    using ResultType = std::invoke_result_t<Func, const TaskContext&>;

    if (shutdown_.load(std::memory_order_acquire)) {
        throw std::runtime_error("ThreadPool is shut down");
    }

    TaskContext context(priority, std::move(description), location);
    context.taskId = nextTaskId_.fetch_add(1, std::memory_order_relaxed);

    Task<ResultType> task(std::forward<Func>(func), std::move(context));
    auto future = task.GetFuture();

    if (!EnqueueTask(std::move(task))) {
        throw std::runtime_error("Failed to enqueue task: queue is full");
    }

    return future;
}

// ============================================================================
// Submit Implementation - With args
// ============================================================================
template<typename Func, typename... Args>
    requires (sizeof...(Args) > 0) && std::invocable<Func, const TaskContext&, Args...>
auto ThreadPool::Submit(
    Func&& func,
    Args&&... args
) -> std::shared_future<std::invoke_result_t<Func, const TaskContext&, Args...>>
{
    using ResultType = std::invoke_result_t<Func, const TaskContext&, Args...>;

    if (shutdown_.load(std::memory_order_acquire)) {
        throw std::runtime_error("ThreadPool is shut down");
    }

    // Args'l� versiyonda default priority/description
    TaskContext context(TaskPriority::Normal, "");
    context.taskId = nextTaskId_.fetch_add(1, std::memory_order_relaxed);

    auto boundFunc = [func = std::forward<Func>(func),
        ... args = std::forward<Args>(args)]
        (const TaskContext& ctx) mutable -> ResultType {
        return func(ctx, args...);
        };

    Task<ResultType> task(std::move(boundFunc), std::move(context));
    auto future = task.GetFuture();

    if (!EnqueueTask(std::move(task))) {
        throw std::runtime_error("Failed to enqueue task: queue is full");
    }

    return future;
}
template<typename Func, typename... Args>
    requires std::invocable<Func, TaskContext, Args...>
auto ThreadPool::SubmitWithTimeout(
    std::chrono::milliseconds timeout,
    Func&& func,
    Args&&... args,
    TaskPriority priority,
    std::string description,
    std::source_location location
) -> std::shared_future<std::invoke_result_t<Func, TaskContext, Args...>> {
    
    using ResultType = std::invoke_result_t<Func, TaskContext, Args...>;
    
    if (shutdown_.load(std::memory_order_acquire)) {
        throw std::runtime_error("ThreadPool is shut down");
    }
    
    // Create task context with timeout
    TaskContext context(priority, std::move(description), location);
    context.taskId = nextTaskId_.fetch_add(1, std::memory_order_relaxed);
    context.timeout = timeout;
    
    // Bind arguments and add timeout logic
    auto boundFunc = [func = std::forward<Func>(func),
                     ... args = std::forward<Args>(args),
                     timeout]
                     (const TaskContext& ctx) mutable -> ResultType {
        auto startTime = std::chrono::steady_clock::now();
        
        // Execute with timeout check
        if constexpr (std::is_void_v<ResultType>) {
            func(ctx, args...);
            
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                throw std::runtime_error("Task execution timed out");
            }
        } else {
            auto result = func(ctx, args...);
            
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                throw std::runtime_error("Task execution timed out");
            }
            
            return result;
        }
    };
    
    // Create task
    Task<ResultType> task(std::move(boundFunc), std::move(context));
    auto future = task.GetFuture();
    
    // Enqueue task
    if (!EnqueueTask(std::move(task))) {
        throw std::runtime_error("Failed to enqueue task: queue is full");
    }
    
    return future;
}

template<typename Func, typename... Args>
    requires std::invocable<Func, TaskContext, Args...>
auto ThreadPool::SubmitCancellable(
    std::shared_ptr<std::atomic<bool>> cancellationToken,
    Func&& func,
    Args&&... args,
    TaskPriority priority,
    std::string description,
    std::source_location location
) -> std::shared_future<std::invoke_result_t<Func, TaskContext, Args...>> {
    
    using ResultType = std::invoke_result_t<Func, TaskContext, Args...>;
    
    if (shutdown_.load(std::memory_order_acquire)) {
        throw std::runtime_error("ThreadPool is shut down");
    }
    
    // Create task context with cancellation token
    TaskContext context(priority, std::move(description), location);
    context.taskId = nextTaskId_.fetch_add(1, std::memory_order_relaxed);
    context.cancellationToken = cancellationToken;
    
    // Bind arguments with cancellation check
    auto boundFunc = [func = std::forward<Func>(func),
                     ... args = std::forward<Args>(args),
                     token = cancellationToken]
                     (const TaskContext& ctx) mutable -> ResultType {
        if (token->load(std::memory_order_acquire)) {
            throw std::runtime_error("Task was cancelled");
        }
        
        return func(ctx, args...);
    };
    
    // Create task
    Task<ResultType> task(std::move(boundFunc), std::move(context));
    auto future = task.GetFuture();
    
    // Enqueue task
    if (!EnqueueTask(std::move(task))) {
        throw std::runtime_error("Failed to enqueue task: queue is full");
    }
    
    return future;
}

template<typename Func, typename InputRange>
    requires std::invocable<Func, const TaskContext&, std::ranges::range_value_t<InputRange>>
auto ThreadPool::SubmitBatch(
    Func&& func,
    InputRange&& inputs,
    TaskPriority priority
)->std::vector<std::shared_future<std::invoke_result_t<Func, const TaskContext&,
    std::ranges::range_value_t<InputRange>>>> {

    using InputType = std::ranges::range_value_t<InputRange>;
    using ResultType = std::invoke_result_t<Func, const TaskContext&, InputType>;

    std::vector<std::shared_future<ResultType>> futures;
    futures.reserve(std::ranges::size(inputs));

    size_t index = 0;
    for (auto&& input : inputs) {
        // Args'l� Submit �a��r (func + input args olarak)
        futures.push_back(Submit(func, std::forward<decltype(input)>(input)));
    }

    return futures;
}

template<typename IndexType, typename Func>
    requires std::integral<IndexType>&& std::invocable<Func, const TaskContext&, IndexType>
void ThreadPool::ParallelFor(
    IndexType start,
    IndexType end,
    Func&& func,
    TaskPriority priority
) {
    if (start >= end) {
        return;
    }

    const size_t threadCount = GetThreadCount();
    const IndexType range = end - start;
    const IndexType chunkSize = std::max(IndexType(1), range / static_cast<IndexType>(threadCount));

    std::vector<std::shared_future<void>> futures;

    for (IndexType i = start; i < end; i += chunkSize) {
        IndexType chunkEnd = std::min(i + chunkSize, end);

        auto chunkFunc = [func, i, chunkEnd](const TaskContext& ctx) {
            for (IndexType idx = i; idx < chunkEnd; ++idx) {
                if (ctx.IsCancelled()) {
                    break;
                }
                func(ctx, idx);
            }
            };

        auto description = "ParallelFor [" + std::to_string(i) + ", " +
            std::to_string(chunkEnd) + ")";

        futures.push_back(Submit(std::move(chunkFunc), priority, std::move(description)));
    }

    for (auto& future : futures) {
        future.wait();
    }
}
template<typename ResultType>
bool ThreadPool::EnqueueTask(Task<ResultType> task) {
    if (shutdown_.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Update statistics
    taskStats_.enqueuedCount.fetch_add(1, std::memory_order_relaxed);
    pendingTasks_.fetch_add(1, std::memory_order_release);
    
    // Wrap task
    TaskWrapper wrapper(std::move(task));
    
    // Try to enqueue
    bool enqueued = globalQueue_.Push(std::move(wrapper));
    
    if (!enqueued) {
        taskStats_.enqueuedCount.fetch_sub(1, std::memory_order_relaxed);
        pendingTasks_.fetch_sub(1, std::memory_order_release);
        
        // Log overflow
        LogETWEvent(ETWEventId::QueueOverflow, 
                   L"Task queue is full", 
                   ETWLevel::Warning);
        return false;
    }
    
    // Update metrics
    perfMetrics_.currentQueueSize.fetch_add(1, std::memory_order_relaxed);
    auto currentSize = perfMetrics_.currentQueueSize.load(std::memory_order_relaxed);
    
    // Update peak
    size_t expected = perfMetrics_.peakQueueSize.load(std::memory_order_relaxed);
    while (currentSize > expected && 
           !perfMetrics_.peakQueueSize.compare_exchange_weak(expected, currentSize,
                                                             std::memory_order_relaxed)) {
        // Loop until we successfully update or another thread updates with a larger value
    }
    
    // Log ETW event
    if (etwManager_ && etwManager_->IsEnabled()) {
        etwManager_->LogTaskEvent(ETWEventId::TaskEnqueued, 
                                  wrapper.GetContext().taskId,
                                  wrapper.GetContext().description);
    }
    
    return true;
}

} // namespace ShadowStrike::Utils

#endif // SHADOWSTRIKE_THREADPOOL_HPP