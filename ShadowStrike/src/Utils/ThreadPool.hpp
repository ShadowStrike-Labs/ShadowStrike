#pragma once

#ifdef _WIN32
#define NOMINMAX
#endif// _WIN32

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
#include<shared_mutex>

// Forward declarations
namespace ShadowStrike::Utils {

// ============================================================================
// ETW Provider GUID and Event Descriptors
// ============================================================================
// {A5F3D1E2-8B4C-4D5E-9F6A-1B2C3D4E5F6A}
static constexpr GUID SHADOWSTRIKE_THREADPOOL_PROVIDER = 
    { 0xa5f3d1e2, 0x8b4c, 0x4d5e, { 0x9f, 0x6a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a } };

// ETW Event IDs
enum class ETWEventId : UCHAR {
    ThreadPoolCreated = 1,
    ThreadPoolDestroyed = 2,
    ThreadCreated = 3,
    ThreadDestroyed = 4,
    TaskEnqueued = 5,
    TaskStarted = 6,
    TaskCompleted = 7,
    TaskFailed = 8,
    ThreadException = 9,
    PoolPaused = 10,
    PoolResumed = 11,
    PoolResized = 12,
    ThreadStarved = 13,
    QueueOverflow = 14,
    PerformanceMetrics = 15,
    ThreadPriorityChanged = 16,
    ThreadAffinityChanged = 17,
    TaskCancelled = 18,
    DeadlockDetected = 19,
    MemoryPressure = 20
};

// ETW Event Levels
enum class ETWLevel : UCHAR {
    LogAlways = 0,
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5
};

// ============================================================================
// Task Priority System
// ============================================================================
enum class TaskPriority : uint8_t {
    Critical = 0,    // Real-time scanning threats
    High = 1,        // User-initiated scans
    Normal = 2,      // Background scans
    Low = 3,         // Scheduled maintenance
    Idle = 4         // Idle-time operations
};

// ============================================================================
// Thread Pool Configuration
// ============================================================================
struct ThreadPoolConfig {
    // Core thread pool settings
    size_t minThreads = 4;
    size_t maxThreads = std::thread::hardware_concurrency() * 2;
    size_t maxQueueSize = 10000;
    
    // Thread lifetime settings
    std::chrono::milliseconds threadIdleTimeout{30000}; // 30 seconds
    std::chrono::milliseconds taskTimeout{300000};      // 5 minutes
    
    // Performance tuning
    bool enableThreadAffinity = true;
    bool enablePriorityBoost = false;
    bool enableETW = true;
    bool enablePerformanceCounters = true;
    
    // Resource limits
    size_t maxMemoryPerThread = 100 * 1024 * 1024; // 100 MB
    size_t stackSizePerThread = 1024 * 1024;       // 1 MB
    
    // Thread priority
    int threadPriority = THREAD_PRIORITY_NORMAL;
    
    // Debugging and diagnostics
    bool enableDeadlockDetection = true;
    bool enableTaskProfiling = true;
    std::chrono::milliseconds deadlockCheckInterval{5000};
    
    // Thread naming
    std::wstring threadNamePrefix = L"ShadowStrike-Worker";
    
    // Work stealing
    bool enableWorkStealing = true;
    size_t workStealingThreshold = 3;
    
    // Validation
    [[nodiscard]] bool Validate() const noexcept;
};

// ============================================================================
// Task Statistics
// ============================================================================
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
    
    void Reset() noexcept;
    [[nodiscard]] double GetAverageExecutionTimeMs() const noexcept;
    [[nodiscard]] double GetAverageWaitTimeMs() const noexcept;
    [[nodiscard]] double GetSuccessRate() const noexcept;
};

// ============================================================================
// Thread Statistics
// ============================================================================
struct ThreadStatistics {
    std::atomic<size_t> currentThreadCount{0};
    std::atomic<size_t> peakThreadCount{0};
    std::atomic<size_t> activeThreadCount{0};
    std::atomic<size_t> idleThreadCount{0};
    
    std::atomic<uint64_t> totalThreadsCreated{0};
    std::atomic<uint64_t> totalThreadsDestroyed{0};
    
    std::atomic<uint64_t> threadCreationFailures{0};
    std::atomic<uint64_t> threadExceptions{0};
    
    void Reset() noexcept;
};

// ============================================================================
// Performance Metrics
// ============================================================================
struct PerformanceMetrics {
    // Queue metrics
    std::atomic<size_t> currentQueueSize{0};
    std::atomic<size_t> peakQueueSize{0};
    
    // Throughput metrics
    std::atomic<uint64_t> tasksPerSecond{0};
    std::atomic<uint64_t> bytesProcessed{0};
    
    // Resource utilization
    std::atomic<double> cpuUtilization{0.0};
    std::atomic<uint64_t> memoryUsage{0};
    
    // Timing metrics
    std::chrono::steady_clock::time_point startTime;
    std::atomic<uint64_t> totalUptime{0};
    
    void Reset() noexcept;
    void UpdateThroughput(uint64_t completedTasks, 
                         std::chrono::milliseconds elapsed) noexcept;
};

// ============================================================================
// Task Context
// ============================================================================
struct TaskContext {
    uint64_t taskId;
    TaskPriority priority;
    std::chrono::steady_clock::time_point enqueueTime;
    std::chrono::steady_clock::time_point startTime;
    std::source_location location;
    std::string description;
    
    // Cancellation support
    std::shared_ptr<std::atomic<bool>> cancellationToken;
    
    // Timeout support
    std::optional<std::chrono::milliseconds> timeout;
    
    TaskContext();
    explicit TaskContext(TaskPriority prio, 
                        std::string desc = "",
                        std::source_location loc = std::source_location::current());
    
    [[nodiscard]] bool IsCancelled() const noexcept;
    void Cancel() noexcept;
    [[nodiscard]] std::chrono::milliseconds GetWaitTime() const noexcept;
};

// ============================================================================
// Task Wrapper
// ============================================================================
template<typename ResultType>
class Task {
public:
    using TaskFunction = std::function<ResultType(const TaskContext&)>;
    
    Task() = default;
    
    template<typename Func>
    Task(Func&& func, TaskContext ctx) 
        : function_(std::forward<Func>(func))
        , context_(std::move(ctx))
        , promise_(std::make_shared<std::promise<ResultType>>())
        , future_(promise_->get_future().share())
    {}
    
    void Execute() {
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
            promise_->set_exception(std::current_exception());
        }
    }
    
    [[nodiscard]] std::shared_future<ResultType> GetFuture() const noexcept {
        return future_;
    }
    
    [[nodiscard]] const TaskContext& GetContext() const noexcept {
        return context_;
    }
    
    [[nodiscard]] TaskContext& GetContext() noexcept {
        return context_;
    }
    
    [[nodiscard]] bool IsValid() const noexcept {
        return function_ != nullptr;
    }
    
    void Cancel() noexcept {
        context_.Cancel();
    }
    
    [[nodiscard]] bool IsCancelled() const noexcept {
        return context_.IsCancelled();
    }
    
private:
    TaskFunction function_;
    TaskContext context_;
    std::shared_ptr<std::promise<ResultType>> promise_;
    std::shared_future<ResultType> future_;
};

// Type-erased task wrapper for queue storage
class TaskWrapper {
public:
    template<typename ResultType>
    explicit TaskWrapper(Task<ResultType> task)
        : executor_([t = std::move(task)]() mutable { t.Execute(); })
        , context_(task.GetContext())
    {}
    
    void Execute() {
        executor_();
    }
    
    [[nodiscard]] const TaskContext& GetContext() const noexcept {
        return context_;
    }
    
    [[nodiscard]] TaskContext& GetContext() noexcept {
        return context_;
    }
    
    [[nodiscard]] bool IsCancelled() const noexcept {
        return context_.IsCancelled();
    }
    
    void Cancel() noexcept {
        context_.Cancel();
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

    // Args'lý versiyonda default priority/description
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
        // Args'lý Submit çaðýr (func + input args olarak)
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

