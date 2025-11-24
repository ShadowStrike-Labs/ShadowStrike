#include "ThreadPool.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <format>
#include <processthreadsapi.h>
#include <winternl.h>
#include <Psapi.h>


#pragma comment(lib, "Advapi32.lib")  // For ETW
#pragma comment(lib, "ntdll.lib")     // For NT APIs

namespace ShadowStrike::Utils {

// ============================================================================
// ThreadPoolConfig Implementation
// ============================================================================

bool ThreadPoolConfig::Validate() const noexcept {
    if (minThreads == 0 || minThreads > maxThreads) {
        return false;
    }
    
    if (maxThreads == 0 || maxThreads > 1024) { // Reasonable upper limit
        return false;
    }
    
    if (maxQueueSize == 0 || maxQueueSize > 1000000) {
        return false;
    }
    
    if (threadIdleTimeout.count() < 0 || taskTimeout.count() < 0) {
        return false;
    }
    
    if (maxMemoryPerThread == 0 || stackSizePerThread == 0) {
        return false;
    }
    
    if (enableDeadlockDetection && deadlockCheckInterval.count() <= 0) {
        return false;
    }
    
    if (threadNamePrefix.empty()) {
        return false;
    }
    
    return true;
}

// ============================================================================
// TaskStatistics Implementation
// ============================================================================

void TaskStatistics::Reset() noexcept {
    enqueuedCount.store(0, std::memory_order_relaxed);
    completedCount.store(0, std::memory_order_relaxed);
    failedCount.store(0, std::memory_order_relaxed);
    cancelledCount.store(0, std::memory_order_relaxed);
    timedOutCount.store(0, std::memory_order_relaxed);
    
    totalExecutionTimeMs.store(0, std::memory_order_relaxed);
    totalWaitTimeMs.store(0, std::memory_order_relaxed);
    
    minExecutionTimeMs.store(UINT64_MAX, std::memory_order_relaxed);
    maxExecutionTimeMs.store(0, std::memory_order_relaxed);
}

double TaskStatistics::GetAverageExecutionTimeMs() const noexcept {
    const uint64_t completed = completedCount.load(std::memory_order_relaxed);
    if (completed == 0) {
        return 0.0;
    }
    
    const uint64_t totalTime = totalExecutionTimeMs.load(std::memory_order_relaxed);
    return static_cast<double>(totalTime) / static_cast<double>(completed);
}

double TaskStatistics::GetAverageWaitTimeMs() const noexcept {
    const uint64_t completed = completedCount.load(std::memory_order_relaxed);
    if (completed == 0) {
        return 0.0;
    }
    
    const uint64_t totalWait = totalWaitTimeMs.load(std::memory_order_relaxed);
    return static_cast<double>(totalWait) / static_cast<double>(completed);
}

double TaskStatistics::GetSuccessRate() const noexcept {
    const uint64_t total = enqueuedCount.load(std::memory_order_relaxed);
    if (total == 0) {
        return 0.0;
    }
    
    const uint64_t completed = completedCount.load(std::memory_order_relaxed);
    return (static_cast<double>(completed) / static_cast<double>(total)) * 100.0;
}

// ============================================================================
// ThreadStatistics Implementation
// ============================================================================

void ThreadStatistics::Reset() noexcept {
    // Don't reset currentThreadCount as it reflects actual state
    peakThreadCount.store(currentThreadCount.load(std::memory_order_relaxed), 
                          std::memory_order_relaxed);
    activeThreadCount.store(0, std::memory_order_relaxed);
    idleThreadCount.store(currentThreadCount.load(std::memory_order_relaxed), 
                          std::memory_order_relaxed);
    
    totalThreadsCreated.store(0, std::memory_order_relaxed);
    totalThreadsDestroyed.store(0, std::memory_order_relaxed);
    
    threadCreationFailures.store(0, std::memory_order_relaxed);
    threadExceptions.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PerformanceMetrics Implementation
// ============================================================================

void PerformanceMetrics::Reset() noexcept {
    currentQueueSize.store(0, std::memory_order_relaxed);
    peakQueueSize.store(0, std::memory_order_relaxed);
    
    tasksPerSecond.store(0, std::memory_order_relaxed);
    bytesProcessed.store(0, std::memory_order_relaxed);
    
    cpuUtilization.store(0.0, std::memory_order_relaxed);
    memoryUsage.store(0, std::memory_order_relaxed);
    
    startTime = std::chrono::steady_clock::now();
    totalUptime.store(0, std::memory_order_relaxed);
}

void PerformanceMetrics::UpdateThroughput(
    uint64_t completedTasks, 
    std::chrono::milliseconds elapsed
) noexcept {
    if (elapsed.count() == 0) {
        return;
    }
    
    // Calculate tasks per second
    const double seconds = static_cast<double>(elapsed.count()) / 1000.0;
    const uint64_t tps = static_cast<uint64_t>(
        static_cast<double>(completedTasks) / seconds
    );
    
    tasksPerSecond.store(tps, std::memory_order_relaxed);
}

// ============================================================================
// TaskContext Implementation
// ============================================================================

TaskContext::TaskContext()
    : taskId(0)
    , priority(TaskPriority::Normal)
    , enqueueTime(std::chrono::steady_clock::now())
    , startTime{}
    , location(std::source_location::current())
    , description("")
    , cancellationToken(nullptr)
    , timeout(std::nullopt)
{}

TaskContext::TaskContext(
    TaskPriority prio,
    std::string desc,
    std::source_location loc
)
    : taskId(0)
    , priority(prio)
    , enqueueTime(std::chrono::steady_clock::now())
    , startTime{}
    , location(loc)
    , description(std::move(desc))
    , cancellationToken(nullptr)
    , timeout(std::nullopt)
{}

bool TaskContext::IsCancelled() const noexcept {
    if (!cancellationToken) {
        return false;
    }
    return cancellationToken->load(std::memory_order_acquire);
}

void TaskContext::Cancel() noexcept {
    if (cancellationToken) {
        cancellationToken->store(true, std::memory_order_release);
    }
}

std::chrono::milliseconds TaskContext::GetWaitTime() const noexcept {
    const auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - enqueueTime
    );
}

// ============================================================================
// PriorityTaskQueue Implementation
// ============================================================================

PriorityTaskQueue::PriorityTaskQueue(size_t maxSize)
    : maxSize_(maxSize)
{}

bool PriorityTaskQueue::Push(TaskWrapper task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.size() >= maxSize_) {
        return false;
    }
    
    queue_.push(std::move(task));
    return true;
}

std::optional<TaskWrapper> PriorityTaskQueue::Pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    TaskWrapper task = std::move(const_cast<TaskWrapper&>(queue_.top()));
    queue_.pop();
    
    return task;
}

std::optional<TaskWrapper> PriorityTaskQueue::TryPop() {
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    
    if (!lock.owns_lock() || queue_.empty()) {
        return std::nullopt;
    }
    
    TaskWrapper task = std::move(const_cast<TaskWrapper&>(queue_.top()));
    queue_.pop();
    
    return task;
}

std::optional<TaskWrapper> PriorityTaskQueue::Steal() {
    // For work stealing, try non-blocking pop
    return TryPop();
}

size_t PriorityTaskQueue::Size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool PriorityTaskQueue::IsEmpty() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

bool PriorityTaskQueue::IsFull() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size() >= maxSize_;
}

size_t PriorityTaskQueue::GetMaxSize() const noexcept {
    return maxSize_;
}

void PriorityTaskQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear the queue by creating a new empty one
    std::priority_queue<TaskWrapper, std::vector<TaskWrapper>, TaskComparator> emptyQueue;
    std::swap(queue_, emptyQueue);
}

void PriorityTaskQueue::SetMaxSize(size_t maxSize) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxSize_ = maxSize;
}

// ============================================================================
// ETWTracingManager Implementation
// ============================================================================

ETWTracingManager::ETWTracingManager()
    : registrationHandle_(0)
    , enabled_(false)
{}

ETWTracingManager::~ETWTracingManager() {
    Shutdown();
}

bool ETWTracingManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (enabled_.load(std::memory_order_acquire)) {
        return true; // Already initialized
    }
    
    // Register ETW provider
    const ULONG result = EventRegister(
        &SHADOWSTRIKE_THREADPOOL_PROVIDER,
        nullptr,  // No callback
        nullptr,  // No callback context
        &registrationHandle_
    );
    
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    enabled_.store(true, std::memory_order_release);
    return true;
}

void ETWTracingManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    if (registrationHandle_ != 0) {
        EventUnregister(registrationHandle_);
        registrationHandle_ = 0;
    }
    
    enabled_.store(false, std::memory_order_release);
}

void ETWTracingManager::LogEvent(
    ETWEventId eventId,
    ETWLevel level,
    const std::wstring& message,
    std::span<const BYTE> additionalData
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    EVENT_DESCRIPTOR eventDescriptor;
    EventDescCreate(
        &eventDescriptor,
        static_cast<USHORT>(eventId),
        0,  // Version
        0,  // Channel
        static_cast<UCHAR>(level),
        0,  // Opcode
        0,  // Task
        0   // Keyword
    );
    
    // Prepare event data
    EVENT_DATA_DESCRIPTOR dataDescriptors[2];
    ULONG descriptorCount = 0;
    
    // Add message
    if (!message.empty()) {
        EventDataDescCreate(
            &dataDescriptors[descriptorCount++],
            message.c_str(),
            static_cast<ULONG>((message.length() + 1) * sizeof(wchar_t))
        );
    }
    
    // Add additional data if provided
    if (!additionalData.empty()) {
        EventDataDescCreate(
            &dataDescriptors[descriptorCount++],
            additionalData.data(),
            static_cast<ULONG>(additionalData.size())
        );
    }
    
    // Write event
    EventWrite(
        registrationHandle_,
        &eventDescriptor,
        descriptorCount,
        descriptorCount > 0 ? dataDescriptors : nullptr
    );
}

void ETWTracingManager::LogTaskEvent(
    ETWEventId eventId,
    uint64_t taskId,
    const std::string& taskDescription,
    uint64_t durationMs
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    // Convert description to wide string
    std::wstring wideDesc(taskDescription.begin(), taskDescription.end());
    
    // Format message
    std::wstring message = std::format(
        L"Task {} [{}]: {} (Duration: {}ms)",
        taskId,
        wideDesc,
        static_cast<int>(eventId),
        durationMs
    );
    
    LogEvent(eventId, ETWLevel::Verbose, message);
}

void ETWTracingManager::LogThreadEvent(
    ETWEventId eventId,
    DWORD threadId,
    const std::wstring& message
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    std::wstring fullMessage = std::format(
        L"Thread {}: {}",
        threadId,
        message
    );
    
    LogEvent(eventId, ETWLevel::Information, fullMessage);
}

void ETWTracingManager::LogPerformanceMetrics(
    const PerformanceMetrics& metrics,
    const TaskStatistics& taskStats,
    const ThreadStatistics& threadStats
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    std::wstring message = std::format(
        L"Performance Metrics - Queue: {}/{}, Tasks: {}/{}/{}, "
        L"Threads: {}/{}/{}, TPS: {}, CPU: {:.2f}%, Mem: {} bytes",
        metrics.currentQueueSize.load(std::memory_order_relaxed),
        metrics.peakQueueSize.load(std::memory_order_relaxed),
        taskStats.completedCount.load(std::memory_order_relaxed),
        taskStats.failedCount.load(std::memory_order_relaxed),
        taskStats.enqueuedCount.load(std::memory_order_relaxed),
        threadStats.currentThreadCount.load(std::memory_order_relaxed),
        threadStats.activeThreadCount.load(std::memory_order_relaxed),
        threadStats.peakThreadCount.load(std::memory_order_relaxed),
        metrics.tasksPerSecond.load(std::memory_order_relaxed),
        metrics.cpuUtilization.load(std::memory_order_relaxed),
        metrics.memoryUsage.load(std::memory_order_relaxed)
    );
    
    LogEvent(ETWEventId::PerformanceMetrics, ETWLevel::Information, message);
}

bool ETWTracingManager::IsEnabled() const noexcept {
    return enabled_.load(std::memory_order_acquire);
}

// ============================================================================
// DeadlockDetector Implementation
// ============================================================================

DeadlockDetector::DeadlockDetector()
    : checkInterval_(5000)
{}

DeadlockDetector::~DeadlockDetector() {
    Stop();
}

void DeadlockDetector::Start(std::chrono::milliseconds checkInterval) {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return; // Already running
    }
    
    checkInterval_ = checkInterval;
    deadlockDetected_.store(false, std::memory_order_release);
    
    detectionThread_ = std::thread([this]() {
        DetectionLoop();
    });
}

void DeadlockDetector::Stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running
    }
    
    if (detectionThread_.joinable()) {
        detectionThread_.join();
    }
}

void DeadlockDetector::RegisterThread(DWORD threadId) {
    std::unique_lock<std::shared_mutex> lock(activityMutex_);

	//if thread already exists, update its activity
    auto it = threadActivity_.find(threadId);
    if (it != threadActivity_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        it->second.active.store(true, std::memory_order_release);
        return;
    }

	//Add new thread activity info
    threadActivity_.try_emplace(
        threadId,                              // map key
        threadId,                              // ThreadActivityInfo constructor arg 1
        std::chrono::steady_clock::now(),     // ThreadActivityInfo constructor arg 2
        true                                   // ThreadActivityInfo constructor arg 3
    );
}

void DeadlockDetector::UnregisterThread(DWORD threadId) {
    std::unique_lock<std::shared_mutex> lock(activityMutex_);
    threadActivity_.erase(threadId);
}

void DeadlockDetector::UpdateThreadActivity(DWORD threadId) {
    std::shared_lock<std::shared_mutex> lock(activityMutex_);
    
    auto it = threadActivity_.find(threadId);
    if (it != threadActivity_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        it->second.active.store(true, std::memory_order_release);
    }
}

bool DeadlockDetector::IsDeadlockDetected() const noexcept {
    return deadlockDetected_.load(std::memory_order_acquire);
}

std::vector<DWORD> DeadlockDetector::GetSuspiciousThreads() const {
    std::shared_lock<std::shared_mutex> lock(activityMutex_);
    
    std::vector<DWORD> suspicious;
    const auto now = std::chrono::steady_clock::now();
    const auto threshold = std::chrono::seconds(30); // 30 seconds inactivity
    
    for (const auto& [threadId, info] : threadActivity_) {
        const auto inactiveTime = now - info.lastActivity;
        if (inactiveTime > threshold && info.active.load(std::memory_order_acquire)) {
            suspicious.push_back(threadId);
        }
    }
    
    return suspicious;
}

void DeadlockDetector::DetectionLoop() {
    while (running_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(checkInterval_);
        
        if (CheckForDeadlock()) {
            deadlockDetected_.store(true, std::memory_order_release);
        }
    }
}

bool DeadlockDetector::CheckForDeadlock() {
    const auto suspicious = GetSuspiciousThreads();
    
    // If more than 50% of threads are suspicious, potential deadlock
    std::shared_lock<std::shared_mutex> lock(activityMutex_);
    const size_t totalThreads = threadActivity_.size();
    lock.unlock();
    
    if (totalThreads == 0) {
        return false;
    }
    
    const double suspiciousRatio = static_cast<double>(suspicious.size()) / 
                                   static_cast<double>(totalThreads);
    
    return suspiciousRatio > 0.5; // More than 50% inactive
}

// ============================================================================
// WorkerThread Implementation
// ============================================================================

WorkerThread::WorkerThread(
    size_t threadId,
    PriorityTaskQueue& globalQueue,
    std::vector<std::unique_ptr<WorkerThread>>& allWorkers,
    const ThreadPoolConfig& config,
    std::atomic<size_t>& pendingTasks,  
    ETWTracingManager* etwManager /*= nullptr*/
)
    : threadId_(threadId)
    , globalQueue_(globalQueue)
    , allWorkers_(allWorkers)
    , config_(config)
    , pendingTasks_(pendingTasks)  
    , etwManager_(etwManager)
    , systemThreadId_(0)
    , lastActivityTime_(std::chrono::steady_clock::now())
{
}
WorkerThread::~WorkerThread() {
    Stop();
}

void WorkerThread::Start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return; // Already running
    }
    
    thread_ = std::thread([this]() {
        WorkerLoop();
    });
    
    // Wait for thread to initialize
    while (systemThreadId_ == 0) {
        std::this_thread::yield();
    }
}

void WorkerThread::Stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running
    }
    //wake up worker thread
    cv_.notify_one();
    
    if (thread_.joinable()) {
        thread_.join();
    }
}

void WorkerThread::Pause() {
    paused_.store(true, std::memory_order_release);
}

void WorkerThread::Resume() {
    paused_.store(false, std::memory_order_release);
}

bool WorkerThread::IsRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
}

bool WorkerThread::IsBusy() const noexcept {
    return busy_.load(std::memory_order_acquire);
}

bool WorkerThread::IsPaused() const noexcept {
    return paused_.load(std::memory_order_acquire);
}

size_t WorkerThread::GetThreadId() const noexcept {
    return threadId_;
}

DWORD WorkerThread::GetSystemThreadId() const noexcept {
    return systemThreadId_;
}

uint64_t WorkerThread::GetTasksProcessed() const noexcept {
    return tasksProcessed_.load(std::memory_order_acquire);
}

void WorkerThread::SetPriority(int priority) {
    if (thread_.native_handle()) {
        SetThreadPriority(thread_.native_handle(), priority);
        
        std::wstring message = std::format(
            L"Worker {} priority changed to {}",
            threadId_,
            priority
        );
        LogETWEvent(ETWEventId::ThreadPriorityChanged, message, ETWLevel::Information);
    }
}

void WorkerThread::SetAffinity(DWORD_PTR affinityMask) {
    if (thread_.native_handle()) {
        SetThreadAffinityMask(thread_.native_handle(), affinityMask);
        
        std::wstring message = std::format(
            L"Worker {} affinity changed to 0x{:X}",
            threadId_,
            affinityMask
        );
        LogETWEvent(ETWEventId::ThreadAffinityChanged, message, ETWLevel::Information);
    }
}

void WorkerThread::WorkerLoop() {
    // Initialize thread
    systemThreadId_ = GetCurrentThreadId();
    
    // Set thread name
    std::wstring threadName = std::format(
        L"{}-{}",
        config_.threadNamePrefix,
        threadId_
    );
    SetThreadName(threadName);
    
    // Set thread priority
    if (config_.threadPriority != THREAD_PRIORITY_NORMAL) {
        SetThreadPriority(GetCurrentThread(), config_.threadPriority);
    }
    
    // Set thread affinity if enabled
    if (config_.enableThreadAffinity) {
        const DWORD_PTR affinityMask = 1ULL << (threadId_ % std::thread::hardware_concurrency());
        SetThreadAffinityMask(GetCurrentThread(), affinityMask);
    }
    
    // Log thread creation
    LogETWEvent(
        ETWEventId::ThreadCreated,
        std::format(L"Worker thread {} started", threadId_),
        ETWLevel::Information
    );
    
    // Main work loop
    while (running_.load(std::memory_order_acquire)) {
        // Check if paused
        if (paused_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Try to get task from local queue
        auto taskOpt = globalQueue_.Pop();

        // If no task in local queue, try work stealing
        if (!taskOpt && config_.enableWorkStealing) {
            TaskWrapper stolenTask{ Task<void>() };
            if (TryStealWork(stolenTask)) {
                taskOpt = std::move(stolenTask);
            }
        }

        if (taskOpt) {
            // Execute task
            ExecuteTask(taskOpt.value());
            lastActivityTime_ = std::chrono::steady_clock::now();
        }
        else {
            std::unique_lock<std::mutex> lock(cvMutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(10), [this] {
                return !running_.load(std::memory_order_acquire);
                });
        }
    }
    // Log thread destruction
    LogETWEvent(
        ETWEventId::ThreadDestroyed,
        std::format(L"Worker thread {} stopped", threadId_),
        ETWLevel::Information
    );
}

bool WorkerThread::TryStealWork(TaskWrapper& task) {
    if (!config_.enableWorkStealing) {
        return false;
    }
    
    // Try to steal from other workers
    for (auto& worker : allWorkers_) {
        if (worker.get() == this) {
            continue; // Skip self
        }
        
        if (!worker->IsRunning()) {
            continue;
        }
        
        // Try to steal a task
        auto stolenTask = worker->globalQueue_.Steal();
        if (stolenTask) {
            task = std::move(stolenTask.value());
            return true;
        }
    }
    
    return false;
}

void WorkerThread::ExecuteTask(TaskWrapper& task) {
    busy_.store(true, std::memory_order_release);
    
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Check if task is cancelled before execution
        if (task.IsCancelled()) {
            LogETWEvent(
                ETWEventId::TaskCancelled,
                std::format(L"Task {} cancelled before execution", task.GetContext().taskId),
                ETWLevel::Warning
            );
            
            busy_.store(false, std::memory_order_release);
            pendingTasks_.fetch_sub(1, std::memory_order_release);
            return;
        }
        
        // Log task start
        LogETWEvent(
            ETWEventId::TaskStarted,
            std::format(L"Worker {} executing task {}", threadId_, task.GetContext().taskId),
            ETWLevel::Verbose
        );
        
        // Execute the task
        task.Execute();
        
        // Calculate execution time
        const auto endTime = std::chrono::steady_clock::now();
        const auto executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime
        );
        
        executionTimeMs_.fetch_add(executionTime.count(), std::memory_order_relaxed);
        tasksProcessed_.fetch_add(1, std::memory_order_relaxed);
        
        // Log task completion
        LogETWEvent(
            ETWEventId::TaskCompleted,
            std::format(
                L"Worker {} completed task {} in {}ms",
                threadId_,
                task.GetContext().taskId,
                executionTime.count()
            ),
            ETWLevel::Verbose
        );
        
    } catch (const std::exception& ex) {
        // Log exception
        std::string exMsg = ex.what();
        std::wstring wideMsg(exMsg.begin(), exMsg.end());
        
        LogETWEvent(
            ETWEventId::TaskFailed,
            std::format(
                L"Worker {} task {} failed: {}",
                threadId_,
                task.GetContext().taskId,
                wideMsg
            ),
            ETWLevel::Error
        );
        
    } catch (...) {
        // Unknown exception
        LogETWEvent(
            ETWEventId::ThreadException,
            std::format(L"Worker {} encountered unknown exception", threadId_),
            ETWLevel::Critical
        );
    }
    
    busy_.store(false, std::memory_order_release);
    pendingTasks_.fetch_sub(1, std::memory_order_release);
}

void WorkerThread::SetThreadName(const std::wstring& name) {
    // Use SetThreadDescription (Windows 10 1607+)
    typedef HRESULT(WINAPI* SetThreadDescriptionFunc)(HANDLE, PCWSTR);
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        auto setThreadDesc = reinterpret_cast<SetThreadDescriptionFunc>(
            GetProcAddress(kernel32, "SetThreadDescription")
        );
        
        if (setThreadDesc && thread_.native_handle()) {
            setThreadDesc(thread_.native_handle(), name.c_str());
        }
    }
}

void WorkerThread::LogETWEvent(
    ETWEventId eventId,
    const std::wstring& message,
    ETWLevel level
) {
    // Check if ETW manager is available and enabled
    if (!etwManager_ || !etwManager_->IsEnabled()) {
        return;
    }

    try {
        // Format the message with worker thread information
        std::wstring formattedMessage = std::format(
            L"[Worker-{}:TID-{}] {}",
            threadId_,
            systemThreadId_,
            message
        );

        // Log the event through the ETW manager
        etwManager_->LogEvent(eventId, level, formattedMessage);

    }
    catch (const std::exception& ex) {
        // ETW logging failed - don't propagate the exception
        // In production, we don't want logging failures to crash the worker
        // Silently ignore or use fallback logging mechanism
        (void)ex; // Suppress unused variable warning

        // Optional: Could write to Windows Event Log or debug output
#ifdef _DEBUG
        std::wstring errorMsg = std::format(
            L"WorkerThread::LogETWEvent failed for Worker {}: {}",
            threadId_,
            std::wstring(ex.what(), ex.what() + strlen(ex.what())).c_str()
        );
        OutputDebugStringW(errorMsg.c_str());
#endif
    }
    catch (...) {
        // Catch all other exceptions
#ifdef _DEBUG
        std::wstring errorMsg = std::format(
            L"WorkerThread::LogETWEvent failed for Worker {} with unknown exception",
            threadId_
        );
        OutputDebugStringW(errorMsg.c_str());
#endif
    }
}


// ============================================================================
// ThreadPool Implementation
// ============================================================================

ThreadPool::ThreadPool(ThreadPoolConfig config)
    : config_(std::move(config))
    , globalQueue_(config_.maxQueueSize)
{
    if (!config_.Validate()) {
        throw std::invalid_argument("Invalid ThreadPool configuration");
    }
}

ThreadPool::~ThreadPool() {
    Shutdown(true);
}

bool ThreadPool::Initialize() {
    if (initialized_.exchange(true, std::memory_order_acq_rel)) {
        return true;
    }

    try {
        perfMetrics_.startTime = std::chrono::steady_clock::now();
        perfMetrics_.Reset();

        if (config_.enableETW) {
            etwManager_ = std::make_unique<ETWTracingManager>();
            if (!etwManager_->Initialize()) {
                etwManager_.reset();
            }
        }

        if (config_.enableDeadlockDetection) {
            deadlockDetector_ = std::make_unique<DeadlockDetector>();
            deadlockDetector_->Start(config_.deadlockCheckInterval);
        }

        CreateWorkerThreads(config_.minThreads);

        monitoringActive_.store(true, std::memory_order_release);
        monitoringThread_ = std::thread([this]() {
            MonitoringLoop();
            });

        LogETWEvent(
            ETWEventId::ThreadPoolCreated,
            std::format(L"ThreadPool initialized with {} threads", config_.minThreads),
            ETWLevel::Information
        );

        return true;

    }
    catch (...) {
        initialized_.store(false, std::memory_order_release);
        Shutdown(false);
        throw;
    }
}

void ThreadPool::Shutdown(bool waitForCompletion) {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    LogETWEvent(ETWEventId::ThreadPoolDestroyed, L"ThreadPool shutting down", ETWLevel::Information);

    if (waitForCompletion) {
        WaitForAll();
    }
    else {
        globalQueue_.Clear();
    }

    monitoringActive_.store(false, std::memory_order_release);
    if (monitoringThread_.joinable()) {
        monitoringThread_.join();
    }

    DestroyWorkerThreads(workers_.size());

    if (deadlockDetector_) {
        deadlockDetector_->Stop();
        deadlockDetector_.reset();
    }

    if (etwManager_) {
        etwManager_->Shutdown();
        etwManager_.reset();
    }

    initialized_.store(false, std::memory_order_release);
}

void ThreadPool::Pause() {
    if (paused_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }

    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->Pause();
    }

    LogETWEvent(ETWEventId::PoolPaused, L"ThreadPool paused", ETWLevel::Information);
}

void ThreadPool::Resume() {
    if (!paused_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->Resume();
    }

    LogETWEvent(ETWEventId::PoolResumed, L"ThreadPool resumed", ETWLevel::Information);
}

bool ThreadPool::IsInitialized() const noexcept {
    return initialized_.load(std::memory_order_acquire);
}

bool ThreadPool::IsShutdown() const noexcept {
    return shutdown_.load(std::memory_order_acquire);
}

bool ThreadPool::IsPaused() const noexcept {
    return paused_.load(std::memory_order_acquire);
}

void ThreadPool::IncreaseThreadCount(size_t count) {
    if (count == 0) return;

    std::unique_lock<std::shared_mutex> lock(workersMutex_);
    const size_t currentCount = workers_.size();
    const size_t newCount = std::min(currentCount + count, config_.maxThreads);
    const size_t actualIncrease = newCount - currentCount;

    if (actualIncrease > 0) {
        CreateWorkerThreads(actualIncrease);
        LogETWEvent(ETWEventId::PoolResized,
            std::format(L"ThreadPool increased by {} threads to {}", actualIncrease, newCount),
            ETWLevel::Information);
    }
}

void ThreadPool::DecreaseThreadCount(size_t count) {
    if (count == 0) return;

    std::unique_lock<std::shared_mutex> lock(workersMutex_);
    const size_t currentCount = workers_.size();
    count = std::min(count, currentCount);

    const size_t newCount = std::max(currentCount - count, config_.minThreads);
    const size_t actualDecrease = currentCount - newCount;

    if (actualDecrease > 0) {
        DestroyWorkerThreads(actualDecrease);
        LogETWEvent(ETWEventId::PoolResized,
            std::format(L"ThreadPool decreased by {} threads to {}", actualDecrease, newCount),
            ETWLevel::Information);
    }
}

void ThreadPool::SetThreadCount(size_t count) {
    count = std::clamp(count, config_.minThreads, config_.maxThreads);

    std::unique_lock<std::shared_mutex> lock(workersMutex_);
    const size_t currentCount = workers_.size();

    if (count > currentCount) {
        CreateWorkerThreads(count - currentCount);
    }
    else if (count < currentCount) {
        DestroyWorkerThreads(currentCount - count);
    }

    LogETWEvent(ETWEventId::PoolResized,
        std::format(L"ThreadPool resized to {} threads", count),
        ETWLevel::Information);
}

size_t ThreadPool::GetThreadCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    return workers_.size();
}

size_t ThreadPool::GetActiveThreadCount() const noexcept {
    return threadStats_.activeThreadCount.load(std::memory_order_acquire);
}

size_t ThreadPool::GetIdleThreadCount() const noexcept {
    return threadStats_.idleThreadCount.load(std::memory_order_acquire);
}

void ThreadPool::SetThreadPriority(int priority) {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->SetPriority(priority);
    }
    config_.threadPriority = priority;
}

void ThreadPool::SetThreadAffinity(DWORD_PTR affinityMask) {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->SetAffinity(affinityMask);
    }
}

size_t ThreadPool::GetQueueSize() const noexcept {
    return globalQueue_.Size();
}

size_t ThreadPool::GetQueueCapacity() const noexcept {
    return globalQueue_.GetMaxSize();
}

bool ThreadPool::IsQueueFull() const noexcept {
    return globalQueue_.IsFull();
}

bool ThreadPool::IsQueueEmpty() const noexcept {
    return globalQueue_.IsEmpty();
}

void ThreadPool::ClearQueue() {
    const size_t clearedCount = globalQueue_.Size();
    globalQueue_.Clear();
    perfMetrics_.currentQueueSize.store(0, std::memory_order_release);
    if (clearedCount > 0) {
        pendingTasks_.fetch_sub(clearedCount, std::memory_order_release);
    }
}

void ThreadPool::SetQueueCapacity(size_t capacity) {
    globalQueue_.SetMaxSize(capacity);
    config_.maxQueueSize = capacity;
}

const TaskStatistics& ThreadPool::GetTaskStatistics() const noexcept {
    return taskStats_;
}

const ThreadStatistics& ThreadPool::GetThreadStatistics() const noexcept {
    return threadStats_;
}

const PerformanceMetrics& ThreadPool::GetPerformanceMetrics() const noexcept {
    return perfMetrics_;
}

void ThreadPool::ResetStatistics() {
    taskStats_.Reset();
    threadStats_.Reset();
    perfMetrics_.Reset();
}

std::string ThreadPool::GetStatisticsReport() const {
    std::ostringstream report;

    report << "=== ThreadPool Statistics Report ===\n\n";
    report << "Task Statistics:\n";
    report << "  Enqueued: " << taskStats_.enqueuedCount.load(std::memory_order_relaxed) << "\n";
    report << "  Completed: " << taskStats_.completedCount.load(std::memory_order_relaxed) << "\n";
    report << "  Failed: " << taskStats_.failedCount.load(std::memory_order_relaxed) << "\n";
    report << "  Cancelled: " << taskStats_.cancelledCount.load(std::memory_order_relaxed) << "\n";
    report << "  Timed Out: " << taskStats_.timedOutCount.load(std::memory_order_relaxed) << "\n";
    report << "  Success Rate: " << std::fixed << std::setprecision(2) << taskStats_.GetSuccessRate() << "%\n";
    report << "  Avg Execution Time: " << std::fixed << std::setprecision(2) << taskStats_.GetAverageExecutionTimeMs() << " ms\n";
    report << "  Avg Wait Time: " << std::fixed << std::setprecision(2) << taskStats_.GetAverageWaitTimeMs() << " ms\n";
    report << "  Min Execution Time: " << taskStats_.minExecutionTimeMs.load(std::memory_order_relaxed) << " ms\n";
    report << "  Max Execution Time: " << taskStats_.maxExecutionTimeMs.load(std::memory_order_relaxed) << " ms\n\n";

    report << "Thread Statistics:\n";
    report << "  Current Threads: " << threadStats_.currentThreadCount.load(std::memory_order_relaxed) << "\n";
    report << "  Peak Threads: " << threadStats_.peakThreadCount.load(std::memory_order_relaxed) << "\n";
    report << "  Active Threads: " << threadStats_.activeThreadCount.load(std::memory_order_relaxed) << "\n";
    report << "  Idle Threads: " << threadStats_.idleThreadCount.load(std::memory_order_relaxed) << "\n";
    report << "  Total Created: " << threadStats_.totalThreadsCreated.load(std::memory_order_relaxed) << "\n";
    report << "  Total Destroyed: " << threadStats_.totalThreadsDestroyed.load(std::memory_order_relaxed) << "\n";
    report << "  Creation Failures: " << threadStats_.threadCreationFailures.load(std::memory_order_relaxed) << "\n";
    report << "  Exceptions: " << threadStats_.threadExceptions.load(std::memory_order_relaxed) << "\n\n";

    report << "Performance Metrics:\n";
    report << "  Queue Size: " << perfMetrics_.currentQueueSize.load(std::memory_order_relaxed) << "\n";
    report << "  Peak Queue Size: " << perfMetrics_.peakQueueSize.load(std::memory_order_relaxed) << "\n";
    report << "  Tasks Per Second: " << perfMetrics_.tasksPerSecond.load(std::memory_order_relaxed) << "\n";
    report << "  CPU Utilization: " << std::fixed << std::setprecision(2) << perfMetrics_.cpuUtilization.load(std::memory_order_relaxed) << "%\n";
    report << "  Memory Usage: " << (perfMetrics_.memoryUsage.load(std::memory_order_relaxed) / (1024 * 1024)) << " MB\n";

    const auto uptime = std::chrono::steady_clock::now() - perfMetrics_.startTime;
    const auto uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();
    report << "  Uptime: " << uptimeSeconds << " seconds\n";

    return report.str();
}

std::string ThreadPool::GetHealthReport() const {
    std::ostringstream report;

    report << "=== ThreadPool Health Report ===\n\n";

    const bool isHealthy =
        !shutdown_.load(std::memory_order_acquire) &&
        initialized_.load(std::memory_order_acquire) &&
        threadStats_.currentThreadCount.load(std::memory_order_relaxed) >= config_.minThreads &&
        taskStats_.GetSuccessRate() > 95.0 &&
        (!deadlockDetector_ || !deadlockDetector_->IsDeadlockDetected());

    report << "Status: " << (isHealthy ? "HEALTHY" : "UNHEALTHY") << "\n\n";

    report << "Checks:\n";
    report << "  [" << (initialized_.load(std::memory_order_acquire) ? "✓" : "✗") << "] Initialized\n";
    report << "  [" << (!shutdown_.load(std::memory_order_acquire) ? "✓" : "✗") << "] Not Shutdown\n";
    report << "  [" << (threadStats_.currentThreadCount.load(std::memory_order_relaxed) >= config_.minThreads ? "✓" : "✗") << "] Minimum Threads\n";
    report << "  [" << (taskStats_.GetSuccessRate() > 95.0 ? "✓" : "✗") << "] Task Success Rate > 95%\n";

    if (deadlockDetector_) {
        const bool noDeadlock = !deadlockDetector_->IsDeadlockDetected();
        report << "  [" << (noDeadlock ? "✓" : "✗") << "] No Deadlock Detected\n";

        if (!noDeadlock) {
            auto suspicious = deadlockDetector_->GetSuspiciousThreads();
            report << "    Suspicious Threads: ";
            for (auto tid : suspicious) {
                report << tid << " ";
            }
            report << "\n";
        }
    }

    report << "\nResource Utilization:\n";
    const double queueUsage = static_cast<double>(globalQueue_.Size()) / static_cast<double>(config_.maxQueueSize) * 100.0;
    report << "  Queue Usage: " << std::fixed << std::setprecision(1) << queueUsage << "%\n";

    const double threadUsage = static_cast<double>(threadStats_.activeThreadCount.load(std::memory_order_relaxed)) /
        static_cast<double>(threadStats_.currentThreadCount.load(std::memory_order_relaxed)) * 100.0;
    report << "  Thread Usage: " << std::fixed << std::setprecision(1) << threadUsage << "%\n";

    return report.str();
}

const ThreadPoolConfig& ThreadPool::GetConfig() const noexcept {
    return config_;
}

void ThreadPool::UpdateConfig(const ThreadPoolConfig& config) {
    if (!config.Validate()) {
        throw std::invalid_argument("Invalid ThreadPool configuration");
    }

    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    if (config.maxQueueSize != config_.maxQueueSize) {
        globalQueue_.SetMaxSize(config.maxQueueSize);
    }

    const size_t currentThreads = workers_.size();
    if (currentThreads < config.minThreads) {
        CreateWorkerThreads(config.minThreads - currentThreads);
    }
    else if (currentThreads > config.maxThreads) {
        DestroyWorkerThreads(currentThreads - config.maxThreads);
    }

    if (config.enableDeadlockDetection && !deadlockDetector_) {
        deadlockDetector_ = std::make_unique<DeadlockDetector>();
        deadlockDetector_->Start(config.deadlockCheckInterval);
    }
    else if (!config.enableDeadlockDetection && deadlockDetector_) {
        deadlockDetector_->Stop();
        deadlockDetector_.reset();
    }

    config_ = config;
}

void ThreadPool::WaitForAll() {
    while (pendingTasks_.load(std::memory_order_acquire) > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool ThreadPool::WaitForAll(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (pendingTasks_.load(std::memory_order_acquire) > 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return true;
}

std::optional<std::exception_ptr> ThreadPool::GetLastException() const noexcept {
    std::lock_guard<std::mutex> lock(exceptionMutex_);
    if (lastException_) {
        return lastException_;
    }
    return std::nullopt;
}

std::shared_ptr<std::atomic<bool>> ThreadPool::CreateCancellationToken() {
    return std::make_shared<std::atomic<bool>>(false);
}

void ThreadPool::CreateWorkerThreads(size_t count) {
    for (size_t i = 0; i < count; ++i) {
        try {
            const size_t threadId = workers_.size();
            auto queue = std::make_unique<PriorityTaskQueue>(config_.maxQueueSize);
            auto worker = std::make_unique<WorkerThread>(
                threadId,
                globalQueue_,
                workers_,
                config_,
                pendingTasks_,  
                etwManager_.get()
            );

            worker->Start();

            if (deadlockDetector_) {
                deadlockDetector_->RegisterThread(worker->GetSystemThreadId());
            }

            workers_.push_back(std::move(worker));
            queues_.push_back(std::move(queue));

            threadStats_.currentThreadCount.fetch_add(1, std::memory_order_relaxed);
            threadStats_.totalThreadsCreated.fetch_add(1, std::memory_order_relaxed);

            const size_t current = threadStats_.currentThreadCount.load(std::memory_order_relaxed);
            size_t expected = threadStats_.peakThreadCount.load(std::memory_order_relaxed);
            while (current > expected &&
                !threadStats_.peakThreadCount.compare_exchange_weak(expected, current, std::memory_order_relaxed)) {
            }

        }
        catch (...) {
            threadStats_.threadCreationFailures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(exceptionMutex_);
            lastException_ = std::current_exception();
            throw;
        }
    }
}

void ThreadPool::DestroyWorkerThreads(size_t count) {
    if (count > workers_.size()) {
        count = workers_.size();
    }

    
    std::vector<std::unique_ptr<WorkerThread>> workersToDestroy;
    workersToDestroy.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        auto& worker = workers_.back();

        if (deadlockDetector_) {
            deadlockDetector_->UnregisterThread(worker->GetSystemThreadId());
        }

        
        workersToDestroy.push_back(std::move(workers_.back()));

        workers_.pop_back();
        queues_.pop_back();

        threadStats_.currentThreadCount.fetch_sub(1, std::memory_order_relaxed);
        threadStats_.totalThreadsDestroyed.fetch_add(1, std::memory_order_relaxed);
    }

    
}
void ThreadPool::MonitoringLoop() {
    auto lastMetricsUpdate = std::chrono::steady_clock::now();
    auto lastHealthCheck = std::chrono::steady_clock::now();

    while (monitoringActive_.load(std::memory_order_acquire)) {
        const auto now = std::chrono::steady_clock::now();

        if (now - lastMetricsUpdate >= std::chrono::seconds(1)) {
            UpdateMetrics();
            lastMetricsUpdate = now;
        }

        if (now - lastHealthCheck >= std::chrono::seconds(5)) {
            CheckThreadHealth();
            lastHealthCheck = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ThreadPool::UpdateMetrics() {
    const auto now = std::chrono::steady_clock::now();
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - perfMetrics_.startTime);
    perfMetrics_.totalUptime.store(uptime.count(), std::memory_order_relaxed);

    const auto completed = taskStats_.completedCount.load(std::memory_order_relaxed);
    perfMetrics_.UpdateThroughput(completed, std::chrono::milliseconds(uptime.count() * 1000));

    size_t activeCount = 0;
    size_t idleCount = 0;

    {
        std::shared_lock<std::shared_mutex> lock(workersMutex_);
        for (const auto& worker : workers_) {
            if (worker->IsBusy()) {
                ++activeCount;
            }
            else {
                ++idleCount;
            }
        }
    }

    threadStats_.activeThreadCount.store(activeCount, std::memory_order_relaxed);
    threadStats_.idleThreadCount.store(idleCount, std::memory_order_relaxed);
    perfMetrics_.currentQueueSize.store(globalQueue_.Size(), std::memory_order_relaxed);

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        perfMetrics_.memoryUsage.store(pmc.WorkingSetSize, std::memory_order_relaxed);
    }

    if (etwManager_ && etwManager_->IsEnabled() && config_.enablePerformanceCounters) {
        etwManager_->LogPerformanceMetrics(perfMetrics_, taskStats_, threadStats_);
    }
}

void ThreadPool::CheckThreadHealth() {
    const size_t queueSize = globalQueue_.Size();
    const size_t idleThreads = threadStats_.idleThreadCount.load(std::memory_order_relaxed);

    if (queueSize > 0 && idleThreads == 0) {
        LogETWEvent(ETWEventId::ThreadStarved,
            std::format(L"Thread starvation detected: {} tasks queued, 0 idle threads", queueSize),
            ETWLevel::Warning);
        OptimizeThreadCount();
    }

    const double queueUsage = static_cast<double>(queueSize) / static_cast<double>(config_.maxQueueSize);
    if (queueUsage > 0.9) {
        LogETWEvent(ETWEventId::QueueOverflow,
            std::format(L"Queue near capacity: {:.1f}% full", queueUsage * 100.0),
            ETWLevel::Warning);
    }

    if (deadlockDetector_ && deadlockDetector_->IsDeadlockDetected()) {
        auto suspicious = deadlockDetector_->GetSuspiciousThreads();
        std::wstring threadList;
        for (auto tid : suspicious) {
            threadList += std::to_wstring(tid) + L" ";
        }
        LogETWEvent(ETWEventId::DeadlockDetected,
            std::format(L"Potential deadlock detected in threads: {}", threadList),
            ETWLevel::Critical);
    }
}

void ThreadPool::HandleOverflow() {
    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    const size_t currentThreads = workers_.size();
    if (currentThreads < config_.maxThreads) {
        const size_t additionalThreads = std::min(config_.maxThreads - currentThreads, size_t(4));
        CreateWorkerThreads(additionalThreads);
        LogETWEvent(ETWEventId::PoolResized,
            std::format(L"Overflow: Added {} threads (total: {})", additionalThreads, workers_.size()),
            ETWLevel::Warning);
    }
}

void ThreadPool::OptimizeThreadCount() {
    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    const size_t queueSize = globalQueue_.Size();
    const size_t currentThreads = workers_.size();
    const size_t idleThreads = threadStats_.idleThreadCount.load(std::memory_order_relaxed);

    if (queueSize > currentThreads * 2 && currentThreads < config_.maxThreads) {
        const size_t neededThreads = std::min((queueSize / 2) - currentThreads, config_.maxThreads - currentThreads);
        if (neededThreads > 0) {
            CreateWorkerThreads(neededThreads);
        }
    }
    else if (idleThreads > currentThreads / 2 && currentThreads > config_.minThreads) {
        const size_t excessThreads = std::min(idleThreads - (currentThreads / 4), currentThreads - config_.minThreads);
        if (excessThreads > 0) {
            DestroyWorkerThreads(excessThreads);
        }
    }
}

void ThreadPool::LogETWEvent(ETWEventId eventId, const std::wstring& message, ETWLevel level) {
    if (etwManager_ && etwManager_->IsEnabled()) {
        etwManager_->LogEvent(eventId, level, message);
    }
}

} // namespace ShadowStrike::Utils
