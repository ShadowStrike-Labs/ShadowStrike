// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file ThreadPool.cpp
 * @brief Implementation of enterprise-grade thread pool
 *
 * This file implements the ThreadPool class and all supporting classes
 * for high-performance task scheduling and execution.
 *
 * Key implementation details:
 * - Lock-free atomic operations where possible
 * - RAII for all resource management
 * - Exception-safe task execution
 * - ETW tracing for diagnostics
 * - Cooperative cancellation support
 *
 * @copyright ShadowStrike Security Suite
 */
#include "ThreadPool.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <format>
#include <cstring>
#include <processthreadsapi.h>
#include <winternl.h>
#include <Psapi.h>

#pragma comment(lib, "Advapi32.lib")  // For ETW
#pragma comment(lib, "ntdll.lib")     // For NT APIs

namespace ShadowStrike::Utils {

//=============================================================================
// ThreadPoolConfig Implementation
//=============================================================================

bool ThreadPoolConfig::Validate() const noexcept {
    // Validate thread counts
    if (minThreads == 0) {
        return false;
    }
    
    if (maxThreads == 0 || maxThreads > ThreadPoolConstants::kMaxThreads) {
        return false;
    }
    
    if (minThreads > maxThreads) {
        return false;
    }
    
    // Validate queue size
    if (maxQueueSize == 0 || maxQueueSize > ThreadPoolConstants::kMaxQueueSize) {
        return false;
    }
    
    // Validate timeouts (negative values are invalid)
    if (threadIdleTimeout.count() < 0 || taskTimeout.count() < 0) {
        return false;
    }
    
    // Validate resource limits
    if (maxMemoryPerThread == 0 || stackSizePerThread == 0) {
        return false;
    }
    
    // Validate deadlock detection interval
    if (enableDeadlockDetection && deadlockCheckInterval.count() <= 0) {
        return false;
    }
    
    // Validate thread name prefix
    if (threadNamePrefix.empty()) {
        return false;
    }
    
    return true;
}

//=============================================================================
// TaskStatistics Implementation
//=============================================================================

void TaskStatistics::Reset() noexcept {
    enqueuedCount.store(0, std::memory_order_relaxed);
    completedCount.store(0, std::memory_order_relaxed);
    failedCount.store(0, std::memory_order_relaxed);
    cancelledCount.store(0, std::memory_order_relaxed);
    timedOutCount.store(0, std::memory_order_relaxed);
    
    totalExecutionTimeMs.store(0, std::memory_order_relaxed);
    totalWaitTimeMs.store(0, std::memory_order_relaxed);
    
    minExecutionTimeMs.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
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

//=============================================================================
// ThreadStatistics Implementation
//=============================================================================

void ThreadStatistics::Reset() noexcept {
    // Don't reset currentThreadCount as it reflects actual state
    const size_t current = currentThreadCount.load(std::memory_order_relaxed);
    peakThreadCount.store(current, std::memory_order_relaxed);
    activeThreadCount.store(0, std::memory_order_relaxed);
    idleThreadCount.store(current, std::memory_order_relaxed);
    
    totalThreadsCreated.store(0, std::memory_order_relaxed);
    totalThreadsDestroyed.store(0, std::memory_order_relaxed);
    
    threadCreationFailures.store(0, std::memory_order_relaxed);
    threadExceptions.store(0, std::memory_order_relaxed);
}

//=============================================================================
// PerformanceMetrics Implementation
//=============================================================================

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
    // Avoid division by zero
    if (elapsed.count() <= 0) {
        return;
    }
    
    // Calculate tasks per second with overflow protection
    const double seconds = static_cast<double>(elapsed.count()) / 1000.0;
    if (seconds > 0.0) {
        const double tpsDouble = static_cast<double>(completedTasks) / seconds;
        // Clamp to valid uint64_t range
        const uint64_t tps = (tpsDouble >= 0.0 && tpsDouble <= static_cast<double>(std::numeric_limits<uint64_t>::max()))
            ? static_cast<uint64_t>(tpsDouble)
            : 0;
        tasksPerSecond.store(tps, std::memory_order_relaxed);
    }
}

//=============================================================================
// TaskContext Implementation
//=============================================================================

/**
 * @brief Default constructor for TaskContext.
 * 
 * Initializes with default values:
 * - taskId: 0
 * - priority: Normal
 * - enqueueTime: current time
 * - No cancellation token
 * - No timeout
 */
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

/**
 * @brief Construct TaskContext with specified parameters.
 * 
 * @param prio Task priority level.
 * @param desc Task description for debugging/logging.
 * @param loc Source location where task was created.
 */
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

/**
 * @brief Check if the task has been cancelled.
 * @return true if cancelled, false otherwise.
 * 
 * @thread_safety Lock-free atomic read.
 */
bool TaskContext::IsCancelled() const noexcept {
    if (!cancellationToken) {
        return false;
    }
    return cancellationToken->load(std::memory_order_acquire);
}

/**
 * @brief Cancel the task.
 * 
 * @thread_safety Lock-free atomic write.
 * @note Has no effect if no cancellation token is set.
 */
void TaskContext::Cancel() noexcept {
    if (cancellationToken) {
        cancellationToken->store(true, std::memory_order_release);
    }
}

/**
 * @brief Get the time the task has been waiting in the queue.
 * @return Wait time as milliseconds duration.
 */
std::chrono::milliseconds TaskContext::GetWaitTime() const noexcept {
    const auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - enqueueTime
    );
}

//=============================================================================
// PriorityTaskQueue Implementation
//=============================================================================

/**
 * @brief Construct a priority task queue with maximum capacity.
 * @param maxSize Maximum number of tasks the queue can hold.
 * 
 * @note Minimum capacity is 1 to ensure queue is always usable.
 */
PriorityTaskQueue::PriorityTaskQueue(size_t maxSize)
    : maxSize_(maxSize > 0 ? maxSize : 1) // Ensure minimum size of 1
{}

/**
 * @brief Push a task onto the queue.
 * @param task The task to enqueue.
 * @return true if successful, false if queue is full or allocation failed.
 * 
 * @thread_safety Thread-safe with mutex protection.
 */
bool PriorityTaskQueue::Push(TaskWrapper task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check capacity before push
    if (queue_.size() >= maxSize_) {
        return false;
    }
    
    try {
        queue_.push(std::move(task));
        return true;
    } catch (...) {
        // Memory allocation failure - propagate as return value
        return false;
    }
}

/**
 * @brief Pop the highest priority task from the queue (blocking lock).
 * @return Optional containing task if available, nullopt if queue is empty.
 * 
 * @thread_safety Thread-safe with mutex protection.
 */
std::optional<TaskWrapper> PriorityTaskQueue::Pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (queue_.empty()) {
        return std::nullopt;
    }
    
    try {
        // Move from top (const_cast is safe here as we're removing the element)
        TaskWrapper task = std::move(const_cast<TaskWrapper&>(queue_.top()));
        queue_.pop();
        return task;
    } catch (...) {
        return std::nullopt;
    }
}

/**
 * @brief Try to pop a task without blocking.
 * @return Optional containing task if available and lock acquired, nullopt otherwise.
 * 
 * @thread_safety Non-blocking, uses try_lock.
 */
std::optional<TaskWrapper> PriorityTaskQueue::TryPop() {
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    
    if (!lock.owns_lock() || queue_.empty()) {
        return std::nullopt;
    }
    
    try {
        TaskWrapper task = std::move(const_cast<TaskWrapper&>(queue_.top()));
        queue_.pop();
        return task;
    } catch (...) {
        return std::nullopt;
    }
}

/**
 * @brief Steal a task from this queue (for work stealing).
 * @return Optional containing task if available, nullopt otherwise.
 * 
 * @note Currently delegates to TryPop for non-blocking behavior.
 */
std::optional<TaskWrapper> PriorityTaskQueue::Steal() {
    // Work stealing uses non-blocking pop
    return TryPop();
}

/**
 * @brief Get the current number of tasks in the queue.
 * @return Queue size.
 */
size_t PriorityTaskQueue::Size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

/**
 * @brief Check if the queue is empty.
 * @return true if empty, false otherwise.
 */
bool PriorityTaskQueue::IsEmpty() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

/**
 * @brief Check if the queue is at capacity.
 * @return true if full, false otherwise.
 */
bool PriorityTaskQueue::IsFull() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size() >= maxSize_;
}

/**
 * @brief Get the maximum queue capacity.
 * @return Maximum size.
 */
size_t PriorityTaskQueue::GetMaxSize() const noexcept {
    // maxSize_ can change via SetMaxSize, lock for consistency
    std::lock_guard<std::mutex> lock(mutex_);
    return maxSize_;
}

/**
 * @brief Clear all tasks from the queue.
 * 
 * Uses swap idiom for efficient clearing.
 */
void PriorityTaskQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear the queue by swapping with empty queue (efficient)
    std::priority_queue<TaskWrapper, std::vector<TaskWrapper>, TaskComparator> emptyQueue;
    std::swap(queue_, emptyQueue);
}

/**
 * @brief Set the maximum queue capacity.
 * @param maxSize New maximum size (minimum 1).
 */
void PriorityTaskQueue::SetMaxSize(size_t maxSize) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxSize_ = (maxSize > 0) ? maxSize : 1;
}

//=============================================================================
// ETWTracingManager Implementation
//=============================================================================

ETWTracingManager::ETWTracingManager()
    : registrationHandle_(0)
    , enabled_(false)
{}

ETWTracingManager::~ETWTracingManager() {
    Shutdown();
}

bool ETWTracingManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already initialized
    if (enabled_.load(std::memory_order_acquire)) {
        return true;
    }
    
    // Register ETW provider
    const ULONG result = ::EventRegister(
        &SHADOWSTRIKE_THREADPOOL_PROVIDER,
        nullptr,  // No callback function
        nullptr,  // No callback context
        &registrationHandle_
    );
    
    if (result != ERROR_SUCCESS) {
        registrationHandle_ = 0;
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
        ::EventUnregister(registrationHandle_);
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
    // Early exit if not enabled
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    // Create event descriptor
    EVENT_DESCRIPTOR eventDescriptor{};
    ::EventDescCreate(
        &eventDescriptor,
        static_cast<USHORT>(eventId),
        0,                              // Version
        0,                              // Channel
        static_cast<UCHAR>(level),
        0,                              // Opcode
        0,                              // Task
        0                               // Keyword
    );
    
    // Prepare event data descriptors (max 2)
    EVENT_DATA_DESCRIPTOR dataDescriptors[2]{};
    ULONG descriptorCount = 0;
    
    // Add message string if not empty
    if (!message.empty()) {
        const size_t messageBytes = (message.length() + 1) * sizeof(wchar_t);
        // Validate size fits in ULONG
        if (messageBytes <= std::numeric_limits<ULONG>::max()) {
            ::EventDataDescCreate(
                &dataDescriptors[descriptorCount],
                message.c_str(),
                static_cast<ULONG>(messageBytes)
            );
            ++descriptorCount;
        }
    }
    
    // Add additional data if provided
    if (!additionalData.empty()) {
        if (additionalData.size() <= std::numeric_limits<ULONG>::max()) {
            ::EventDataDescCreate(
                &dataDescriptors[descriptorCount],
                additionalData.data(),
                static_cast<ULONG>(additionalData.size())
            );
            ++descriptorCount;
        }
    }
    
    // Write event (ignore return value - ETW failures are non-critical)
    ::EventWrite(
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
    
    try {
        // Safely convert description to wide string
        std::wstring wideDesc;
        wideDesc.reserve(taskDescription.size());
        for (char c : taskDescription) {
            wideDesc.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
        }
        
        // Format message
        std::wstring message = std::format(
            L"Task {} [{}]: EventId={} (Duration: {}ms)",
            taskId,
            wideDesc,
            static_cast<int>(eventId),
            durationMs
        );
        
        LogEvent(eventId, ETWLevel::Verbose, message);
    } catch (...) {
        // ETW logging failures are non-critical
    }
}

void ETWTracingManager::LogThreadEvent(
    ETWEventId eventId,
    DWORD threadId,
    const std::wstring& message
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    try {
        std::wstring fullMessage = std::format(
            L"Thread {}: {}",
            threadId,
            message
        );
        
        LogEvent(eventId, ETWLevel::Information, fullMessage);
    } catch (...) {
        // ETW logging failures are non-critical
    }
}

void ETWTracingManager::LogPerformanceMetrics(
    const PerformanceMetrics& metrics,
    const TaskStatistics& taskStats,
    const ThreadStatistics& threadStats
) {
    if (!enabled_.load(std::memory_order_acquire)) {
        return;
    }
    
    try {
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
    } catch (...) {
        // ETW logging failures are non-critical
    }
}

bool ETWTracingManager::IsEnabled() const noexcept {
    return enabled_.load(std::memory_order_acquire);
}

//=============================================================================
// DeadlockDetector Implementation
//=============================================================================

/**
 * @brief Default constructor initializing the deadlock detector.
 * 
 * Sets default check interval to 5000ms for periodic deadlock monitoring.
 * Detector starts in stopped state and must be explicitly started.
 */
DeadlockDetector::DeadlockDetector()
    : checkInterval_(5000)
{}

/**
 * @brief Destructor ensuring clean shutdown.
 * 
 * Stops the detection thread if running to prevent resource leaks.
 */
DeadlockDetector::~DeadlockDetector() {
    Stop();
}

/**
 * @brief Start the deadlock detection monitoring.
 * @param checkInterval Interval between deadlock checks.
 * 
 * @thread_safety Thread-safe, uses atomic exchange for state management.
 * @note Multiple calls are idempotent - only first call starts detection.
 */
void DeadlockDetector::Start(std::chrono::milliseconds checkInterval) {
    // Atomic check-and-set to prevent multiple starts
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return; // Already running - idempotent
    }
    
    // Validate and store check interval (minimum 100ms to prevent CPU thrashing)
    checkInterval_ = (checkInterval.count() >= 100) 
        ? checkInterval 
        : std::chrono::milliseconds(100);
    
    deadlockDetected_.store(false, std::memory_order_release);
    
    // Start detection thread
    detectionThread_ = std::thread([this]() {
        DetectionLoop();
    });
}

/**
 * @brief Stop the deadlock detection monitoring.
 * 
 * @thread_safety Thread-safe, ensures clean thread shutdown.
 * @note Multiple calls are idempotent - only first call stops detection.
 */
void DeadlockDetector::Stop() {
    // Atomic check-and-clear to prevent multiple stops
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running - idempotent
    }
    
    // Wait for detection thread to complete
    if (detectionThread_.joinable()) {
        detectionThread_.join();
    }
}

/**
 * @brief Register a thread for deadlock monitoring.
 * @param threadId The Windows thread ID to monitor.
 * 
 * If the thread is already registered, updates its activity timestamp.
 * 
 * @thread_safety Thread-safe with exclusive lock on activity map.
 */
void DeadlockDetector::RegisterThread(DWORD threadId) {
    std::unique_lock<std::shared_mutex> lock(activityMutex_);

    // If thread already exists, update its activity timestamp
    auto it = threadActivity_.find(threadId);
    if (it != threadActivity_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        it->second.active.store(true, std::memory_order_release);
        return;
    }

    // Add new thread activity tracking entry
    threadActivity_.try_emplace(
        threadId,                              // Map key (thread ID)
        threadId,                              // ThreadActivityInfo.threadId
        std::chrono::steady_clock::now(),     // ThreadActivityInfo.lastActivity
        true                                   // ThreadActivityInfo.active
    );
}

/**
 * @brief Unregister a thread from deadlock monitoring.
 * @param threadId The Windows thread ID to stop monitoring.
 * 
 * @thread_safety Thread-safe with exclusive lock on activity map.
 */
void DeadlockDetector::UnregisterThread(DWORD threadId) {
    std::unique_lock<std::shared_mutex> lock(activityMutex_);
    threadActivity_.erase(threadId);
}

/**
 * @brief Update the activity timestamp for a monitored thread.
 * @param threadId The Windows thread ID to update.
 * 
 * Called by worker threads to indicate they are still actively processing.
 * 
 * @thread_safety Thread-safe with shared lock (allows concurrent updates).
 */
void DeadlockDetector::UpdateThreadActivity(DWORD threadId) {
    std::shared_lock<std::shared_mutex> lock(activityMutex_);
    
    auto it = threadActivity_.find(threadId);
    if (it != threadActivity_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        it->second.active.store(true, std::memory_order_release);
    }
}

/**
 * @brief Check if a deadlock has been detected.
 * @return true if deadlock detected, false otherwise.
 * 
 * @thread_safety Lock-free atomic read.
 */
bool DeadlockDetector::IsDeadlockDetected() const noexcept {
    return deadlockDetected_.load(std::memory_order_acquire);
}

/**
 * @brief Get list of threads suspected of being in a deadlock.
 * @return Vector of Windows thread IDs that have been inactive too long.
 * 
 * Threads inactive for more than 30 seconds while marked as active
 * are considered suspicious for potential deadlock.
 * 
 * @thread_safety Thread-safe with shared lock on activity map.
 */
std::vector<DWORD> DeadlockDetector::GetSuspiciousThreads() const {
    std::shared_lock<std::shared_mutex> lock(activityMutex_);
    
    std::vector<DWORD> suspicious;
    const auto now = std::chrono::steady_clock::now();
    
    // Inactivity threshold: 30 seconds without activity update
    constexpr auto threshold = std::chrono::seconds(30);
    
    // Reserve to avoid reallocations (assume worst case)
    suspicious.reserve(threadActivity_.size());
    
    for (const auto& [threadId, info] : threadActivity_) {
        const auto inactiveTime = now - info.lastActivity;
        // Thread is suspicious if inactive but marked as active
        if (inactiveTime > threshold && info.active.load(std::memory_order_acquire)) {
            suspicious.push_back(threadId);
        }
    }
    
    return suspicious;
}

/**
 * @brief Main detection loop running in dedicated thread.
 * 
 * Periodically checks for deadlock conditions until stopped.
 */
void DeadlockDetector::DetectionLoop() {
    while (running_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(checkInterval_);
        
        // Check before processing to respect stop request
        if (!running_.load(std::memory_order_acquire)) {
            break;
        }
        
        if (CheckForDeadlock()) {
            deadlockDetected_.store(true, std::memory_order_release);
        }
    }
}

/**
 * @brief Perform deadlock detection analysis.
 * @return true if potential deadlock detected, false otherwise.
 * 
 * Detection heuristic: If more than 50% of monitored threads are
 * inactive (suspicious), a potential deadlock is flagged.
 */
bool DeadlockDetector::CheckForDeadlock() {
    const auto suspicious = GetSuspiciousThreads();
    
    // Get total thread count with minimal lock scope
    size_t totalThreads = 0;
    {
        std::shared_lock<std::shared_mutex> lock(activityMutex_);
        totalThreads = threadActivity_.size();
    }
    
    // No threads = no deadlock
    if (totalThreads == 0) {
        return false;
    }
    
    // Calculate ratio of suspicious threads
    const double suspiciousRatio = static_cast<double>(suspicious.size()) / 
                                   static_cast<double>(totalThreads);
    
    // Deadlock threshold: more than 50% of threads inactive
    constexpr double kDeadlockThreshold = 0.5;
    return suspiciousRatio > kDeadlockThreshold;
}

//=============================================================================
// WorkerThread Implementation
//=============================================================================

/**
 * @brief Construct a new worker thread.
 * 
 * @param threadId Logical thread ID within the pool (0-based).
 * @param globalQueue Reference to the shared task queue.
 * @param allWorkers Reference to all worker threads (for work stealing).
 * @param config Thread pool configuration settings.
 * @param pendingTasks Atomic counter for pending tasks.
 * @param etwManager Optional ETW tracing manager (may be nullptr).
 * 
 * @note Constructor does not start the thread. Call Start() explicitly.
 */
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

/**
 * @brief Destructor ensuring clean worker shutdown.
 */
WorkerThread::~WorkerThread() {
    Stop();
}

/**
 * @brief Start the worker thread.
 * 
 * @thread_safety Thread-safe through atomic exchange.
 * @note Multiple calls are idempotent.
 * @note Blocks briefly until thread initialization completes.
 */
void WorkerThread::Start() {
    // Atomic check-and-set prevents multiple starts
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return; // Already running - idempotent
    }
    
    thread_ = std::thread([this]() {
        WorkerLoop();
    });
    
    // Wait for thread to initialize and set its system thread ID
    // This ensures GetSystemThreadId() returns valid value after Start() returns
    while (systemThreadId_ == 0) {
        std::this_thread::yield();
    }
}

/**
 * @brief Stop the worker thread.
 * 
 * @thread_safety Thread-safe through atomic exchange.
 * @note Multiple calls are idempotent.
 * @note Blocks until thread fully terminates.
 */
void WorkerThread::Stop() {
    // Atomic check-and-clear prevents multiple stops
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running - idempotent
    }
    
    // Wake up the worker thread if waiting on condition variable
    cv_.notify_one();
    
    // Wait for clean thread termination
    if (thread_.joinable()) {
        thread_.join();
    }
}

/**
 * @brief Pause the worker thread.
 * 
 * Worker will complete current task but won't pick up new tasks.
 */
void WorkerThread::Pause() {
    paused_.store(true, std::memory_order_release);
}

/**
 * @brief Resume a paused worker thread.
 */
void WorkerThread::Resume() {
    paused_.store(false, std::memory_order_release);
}

/**
 * @brief Check if the worker is running.
 * @return true if running, false otherwise.
 */
bool WorkerThread::IsRunning() const noexcept {
    return running_.load(std::memory_order_acquire);
}

/**
 * @brief Check if the worker is currently executing a task.
 * @return true if busy, false otherwise.
 */
bool WorkerThread::IsBusy() const noexcept {
    return busy_.load(std::memory_order_acquire);
}

/**
 * @brief Check if the worker is paused.
 * @return true if paused, false otherwise.
 */
bool WorkerThread::IsPaused() const noexcept {
    return paused_.load(std::memory_order_acquire);
}

/**
 * @brief Get the logical thread ID within the pool.
 * @return Zero-based thread index.
 */
size_t WorkerThread::GetThreadId() const noexcept {
    return threadId_;
}

/**
 * @brief Get the Windows system thread ID.
 * @return System thread ID, or 0 if thread not yet started.
 */
DWORD WorkerThread::GetSystemThreadId() const noexcept {
    return systemThreadId_;
}

/**
 * @brief Get the total number of tasks this worker has processed.
 * @return Task count.
 */
uint64_t WorkerThread::GetTasksProcessed() const noexcept {
    return tasksProcessed_.load(std::memory_order_acquire);
}

/**
 * @brief Set the thread priority.
 * @param priority Windows thread priority constant.
 * 
 * @note Only takes effect if thread is running.
 */
void WorkerThread::SetPriority(int priority) {
    if (thread_.native_handle()) {
        ::SetThreadPriority(thread_.native_handle(), priority);
        
        LogETWEvent(
            ETWEventId::ThreadPriorityChanged,
            std::format(L"Worker {} priority changed to {}", threadId_, priority),
            ETWLevel::Information
        );
    }
}

/**
 * @brief Set the thread CPU affinity mask.
 * @param affinityMask CPU affinity bitmask.
 * 
 * @note Only takes effect if thread is running.
 */
void WorkerThread::SetAffinity(DWORD_PTR affinityMask) {
    if (thread_.native_handle()) {
        ::SetThreadAffinityMask(thread_.native_handle(), affinityMask);
        
        LogETWEvent(
            ETWEventId::ThreadAffinityChanged,
            std::format(L"Worker {} affinity changed to 0x{:X}", threadId_, affinityMask),
            ETWLevel::Information
        );
    }
}

/**
 * @brief Main worker thread loop.
 * 
 * Initializes thread settings (name, priority, affinity) then continuously
 * processes tasks from the global queue or via work stealing.
 * 
 * @note Runs in dedicated thread context.
 */
void WorkerThread::WorkerLoop() {
    // Initialize thread - capture system thread ID immediately
    systemThreadId_ = ::GetCurrentThreadId();
    
    // Set descriptive thread name for debugger visibility
    std::wstring threadName = std::format(
        L"{}-{}",
        config_.threadNamePrefix,
        threadId_
    );
    SetThreadName(threadName);
    
    // Apply thread priority if non-default
    if (config_.threadPriority != THREAD_PRIORITY_NORMAL) {
        ::SetThreadPriority(::GetCurrentThread(), config_.threadPriority);
    }
    
    // Apply CPU affinity if enabled (round-robin across cores)
    if (config_.enableThreadAffinity) {
        const auto coreCount = std::thread::hardware_concurrency();
        if (coreCount > 0) {
            const DWORD_PTR affinityMask = 1ULL << (threadId_ % coreCount);
            ::SetThreadAffinityMask(::GetCurrentThread(), affinityMask);
        }
    }
    
    // Log thread creation via ETW
    LogETWEvent(
        ETWEventId::ThreadCreated,
        std::format(L"Worker thread {} started (TID: {})", threadId_, systemThreadId_),
        ETWLevel::Information
    );
    
    // Constants for wait timing
    constexpr auto kPauseSleepDuration = std::chrono::milliseconds(100);
    constexpr auto kIdleWaitDuration = std::chrono::milliseconds(10);
    
    // Main work loop
    while (running_.load(std::memory_order_acquire)) {
        // Handle paused state - sleep briefly and recheck
        if (paused_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(kPauseSleepDuration);
            continue;
        }

        // Try to get task from global queue
        auto taskOpt = globalQueue_.Pop();

        // If no task in global queue, attempt work stealing
        if (!taskOpt && config_.enableWorkStealing) {
            TaskWrapper stolenTask{ Task<void>() };
            if (TryStealWork(stolenTask)) {
                taskOpt = std::move(stolenTask);
            }
        }

        if (taskOpt) {
            // Execute the task and update activity timestamp
            ExecuteTask(taskOpt.value());
            lastActivityTime_ = std::chrono::steady_clock::now();
        }
        else {
            // No work available - wait on condition variable
            std::unique_lock<std::mutex> lock(cvMutex_);
            cv_.wait_for(lock, kIdleWaitDuration, [this] {
                return !running_.load(std::memory_order_acquire);
            });
        }
    }
    
    // Log thread destruction via ETW
    LogETWEvent(
        ETWEventId::ThreadDestroyed,
        std::format(L"Worker thread {} stopped", threadId_),
        ETWLevel::Information
    );
}

/**
 * @brief Attempt to steal work from another worker.
 * @param task Output parameter for stolen task.
 * @return true if work was successfully stolen, false otherwise.
 * 
 * Work stealing enables better load balancing across workers.
 */
bool WorkerThread::TryStealWork(TaskWrapper& task) {
    // Early exit if work stealing is disabled
    if (!config_.enableWorkStealing) {
        return false;
    }
    
    // Try to steal from other workers' queues
    for (auto& worker : allWorkers_) {
        // Skip self
        if (worker.get() == this) {
            continue;
        }
        
        // Skip workers that aren't running
        if (!worker->IsRunning()) {
            continue;
        }
        
        // Attempt to steal a task from this worker's global queue reference
        auto stolenTask = worker->globalQueue_.Steal();
        if (stolenTask) {
            task = std::move(stolenTask.value());
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Execute a task with comprehensive monitoring and error handling.
 * @param task The task wrapper to execute.
 * 
 * Handles task cancellation, execution timing, success/failure tracking,
 * and ETW event logging.
 */
void WorkerThread::ExecuteTask(TaskWrapper& task) {
    // Mark worker as busy
    busy_.store(true, std::memory_order_release);
    
    const auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Check cancellation before execution
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
        
        // Update statistics (relaxed ordering sufficient for counters)
        executionTimeMs_.fetch_add(
            static_cast<uint64_t>(executionTime.count()), 
            std::memory_order_relaxed
        );
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
        // Handle known exception type - safely convert to wide string
        std::wstring wideMsg;
        try {
            const std::string exMsg = ex.what();
            wideMsg.reserve(exMsg.size());
            for (char c : exMsg) {
                wideMsg.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
            }
        } catch (...) {
            wideMsg = L"<exception message unavailable>";
        }
        
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
        // Handle unknown exception type
        LogETWEvent(
            ETWEventId::ThreadException,
            std::format(L"Worker {} encountered unknown exception", threadId_),
            ETWLevel::Critical
        );
    }
    
    // Always clear busy flag and decrement pending count
    busy_.store(false, std::memory_order_release);
    pendingTasks_.fetch_sub(1, std::memory_order_release);

        
    
    
    busy_.store(false, std::memory_order_release);
    pendingTasks_.fetch_sub(1, std::memory_order_release);
}

/**
 * @brief Set the thread name for debugger visibility.
 * @param name The name to assign to the thread.
 * 
 * Uses SetThreadDescription API (Windows 10 1607+) for thread naming.
 * Silently fails on older Windows versions.
 */
void WorkerThread::SetThreadName(const std::wstring& name) {
    // Use SetThreadDescription API (available Windows 10 1607+)
    // Dynamically load to maintain compatibility with older Windows
    using SetThreadDescriptionFunc = HRESULT(WINAPI*)(HANDLE, PCWSTR);
    
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        return; // Unexpected but handle gracefully
    }
    
    auto setThreadDesc = reinterpret_cast<SetThreadDescriptionFunc>(
        ::GetProcAddress(kernel32, "SetThreadDescription")
    );
    
    if (setThreadDesc && thread_.native_handle()) {
        // Ignore return value - thread naming is best-effort
        setThreadDesc(thread_.native_handle(), name.c_str());
    }
}

/**
 * @brief Log an ETW event from this worker thread.
 * @param eventId The ETW event identifier.
 * @param message The event message.
 * @param level The event severity level.
 * 
 * Handles ETW manager availability and exceptions gracefully.
 * ETW logging failures are non-critical and won't affect task execution.
 */
void WorkerThread::LogETWEvent(
    ETWEventId eventId,
    const std::wstring& message,
    ETWLevel level
) {
    // Early exit if ETW manager is unavailable or disabled
    if (!etwManager_ || !etwManager_->IsEnabled()) {
        return;
    }

    try {
        // Format message with worker thread identification
        std::wstring formattedMessage = std::format(
            L"[Worker-{}:TID-{}] {}",
            threadId_,
            systemThreadId_,
            message
        );

        // Log through the ETW manager
        etwManager_->LogEvent(eventId, level, formattedMessage);

    }
    catch (const std::exception& ex) {
        // ETW logging failure - non-critical, don't propagate
        (void)ex; // Suppress unused variable warning

#ifdef _DEBUG
        // Debug builds: output to debugger
        try {
            std::wstring errorMsg = std::format(
                L"WorkerThread::LogETWEvent failed for Worker {}: exception occurred",
                threadId_
            );
            ::OutputDebugStringW(errorMsg.c_str());
        } catch (...) {
            // Even debug output failed - give up silently
        }
#endif
    }
    catch (...) {
        // Unknown exception - also non-critical
#ifdef _DEBUG
        try {
            std::wstring errorMsg = std::format(
                L"WorkerThread::LogETWEvent failed for Worker {} with unknown exception",
                threadId_
            );
            ::OutputDebugStringW(errorMsg.c_str());
        } catch (...) {
            // Even debug output failed - give up silently
        }
#endif
    }
}


//=============================================================================
// ThreadPool Implementation
//=============================================================================

/**
 * @brief Construct a ThreadPool with the specified configuration.
 * @param config Thread pool configuration settings.
 * @throws std::invalid_argument if configuration is invalid.
 * 
 * @note Constructor only validates config. Call Initialize() to start the pool.
 */
ThreadPool::ThreadPool(ThreadPoolConfig config)
    : config_(std::move(config))
    , globalQueue_(config_.maxQueueSize)
{
    if (!config_.Validate()) {
        throw std::invalid_argument("Invalid ThreadPool configuration");
    }
}

/**
 * @brief Destructor ensuring complete pool shutdown.
 * 
 * Waits for all pending tasks to complete before destroying resources.
 */
ThreadPool::~ThreadPool() {
    Shutdown(true);
}

/**
 * @brief Initialize the thread pool and start worker threads.
 * @return true if initialization successful, false otherwise.
 * @throws Propagates any exception from worker thread creation.
 * 
 * @thread_safety Thread-safe through atomic initialization flag.
 * @note Multiple calls are idempotent.
 */
bool ThreadPool::Initialize() {
    // Atomic check-and-set prevents multiple initializations
    if (initialized_.exchange(true, std::memory_order_acq_rel)) {
        return true;  // Already initialized - idempotent
    }

    try {
        // Initialize timing baseline
        perfMetrics_.startTime = std::chrono::steady_clock::now();
        perfMetrics_.Reset();

        // Initialize ETW tracing if enabled
        if (config_.enableETW) {
            etwManager_ = std::make_unique<ETWTracingManager>();
            if (!etwManager_->Initialize()) {
                // ETW initialization failure is non-critical
                etwManager_.reset();
            }
        }

        // Initialize deadlock detection if enabled
        if (config_.enableDeadlockDetection) {
            deadlockDetector_ = std::make_unique<DeadlockDetector>();
            deadlockDetector_->Start(config_.deadlockCheckInterval);
        }

        // Create initial worker threads
        CreateWorkerThreads(config_.minThreads);

        // Start monitoring thread
        monitoringActive_.store(true, std::memory_order_release);
        monitoringThread_ = std::thread([this]() {
            MonitoringLoop();
        });

        // Log successful initialization
        LogETWEvent(
            ETWEventId::ThreadPoolCreated,
            std::format(L"ThreadPool initialized with {} threads", config_.minThreads),
            ETWLevel::Information
        );

        return true;

    }
    catch (...) {
        // Roll back on failure
        initialized_.store(false, std::memory_order_release);
        Shutdown(false);
        throw;
    }
}

/**
 * @brief Shutdown the thread pool.
 * @param waitForCompletion If true, wait for pending tasks to complete.
 * 
 * @thread_safety Thread-safe through atomic shutdown flag.
 * @note Multiple calls are idempotent.
 */
void ThreadPool::Shutdown(bool waitForCompletion) {
    // Atomic check-and-set prevents multiple shutdowns
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already shutting down - idempotent
    }

    LogETWEvent(ETWEventId::ThreadPoolDestroyed, L"ThreadPool shutting down", ETWLevel::Information);

    // Handle pending tasks
    if (waitForCompletion) {
        WaitForAll();
    }
    else {
        globalQueue_.Clear();
    }

    // Stop monitoring thread
    monitoringActive_.store(false, std::memory_order_release);
    if (monitoringThread_.joinable()) {
        monitoringThread_.join();
    }

    // Destroy all worker threads
    {
        std::unique_lock<std::shared_mutex> lock(workersMutex_);
        DestroyWorkerThreads(workers_.size());
    }

    // Stop deadlock detector
    if (deadlockDetector_) {
        deadlockDetector_->Stop();
        deadlockDetector_.reset();
    }

    // Shutdown ETW manager
    if (etwManager_) {
        etwManager_->Shutdown();
        etwManager_.reset();
    }

    initialized_.store(false, std::memory_order_release);
}

/**
 * @brief Pause all worker threads.
 * 
 * Workers will complete current tasks but won't pick up new ones.
 */
void ThreadPool::Pause() {
    if (paused_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already paused
    }

    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->Pause();
    }

    LogETWEvent(ETWEventId::PoolPaused, L"ThreadPool paused", ETWLevel::Information);
}

/**
 * @brief Resume all paused worker threads.
 */
void ThreadPool::Resume() {
    if (!paused_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Not paused
    }

    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->Resume();
    }

    LogETWEvent(ETWEventId::PoolResumed, L"ThreadPool resumed", ETWLevel::Information);
}

/**
 * @brief Check if the thread pool is initialized.
 * @return true if initialized and ready, false otherwise.
 */
bool ThreadPool::IsInitialized() const noexcept {
    return initialized_.load(std::memory_order_acquire);
}

/**
 * @brief Check if the thread pool is shutting down or has shut down.
 * @return true if shutdown initiated, false otherwise.
 */
bool ThreadPool::IsShutdown() const noexcept {
    return shutdown_.load(std::memory_order_acquire);
}

/**
 * @brief Check if the thread pool is paused.
 * @return true if paused, false otherwise.
 */
bool ThreadPool::IsPaused() const noexcept {
    return paused_.load(std::memory_order_acquire);
}

/**
 * @brief Increase the number of worker threads.
 * @param count Number of threads to add.
 * 
 * Respects the maxThreads configuration limit.
 */
void ThreadPool::IncreaseThreadCount(size_t count) {
    if (count == 0) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(workersMutex_);
    const size_t currentCount = workers_.size();
    const size_t newCount = std::min(currentCount + count, config_.maxThreads);
    const size_t actualIncrease = newCount - currentCount;

    if (actualIncrease > 0) {
        CreateWorkerThreads(actualIncrease);
        LogETWEvent(
            ETWEventId::PoolResized,
            std::format(L"ThreadPool increased by {} threads to {}", actualIncrease, newCount),
            ETWLevel::Information
        );
    }
}

/**
 * @brief Decrease the number of worker threads.
 * @param count Number of threads to remove.
 * 
 * Respects the minThreads configuration limit.
 */
void ThreadPool::DecreaseThreadCount(size_t count) {
    if (count == 0) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(workersMutex_);
    const size_t currentCount = workers_.size();
    
    // Clamp to available threads
    const size_t clampedCount = std::min(count, currentCount);
    const size_t newCount = std::max(currentCount - clampedCount, config_.minThreads);
    const size_t actualDecrease = currentCount - newCount;

    if (actualDecrease > 0) {
        DestroyWorkerThreads(actualDecrease);
        LogETWEvent(
            ETWEventId::PoolResized,
            std::format(L"ThreadPool decreased by {} threads to {}", actualDecrease, newCount),
            ETWLevel::Information
        );
    }
}

/**
 * @brief Set the exact number of worker threads.
 * @param count Desired thread count.
 * 
 * Count is clamped to [minThreads, maxThreads] range.
 */
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

    LogETWEvent(
        ETWEventId::PoolResized,
        std::format(L"ThreadPool resized to {} threads", count),
        ETWLevel::Information
    );
}

/**
 * @brief Get the current number of worker threads.
 * @return Thread count.
 */
size_t ThreadPool::GetThreadCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    return workers_.size();
}

/**
 * @brief Get the number of threads currently executing tasks.
 * @return Active thread count.
 */
size_t ThreadPool::GetActiveThreadCount() const noexcept {
    return threadStats_.activeThreadCount.load(std::memory_order_acquire);
}

/**
 * @brief Get the number of threads waiting for work.
 * @return Idle thread count.
 */
size_t ThreadPool::GetIdleThreadCount() const noexcept {
    return threadStats_.idleThreadCount.load(std::memory_order_acquire);
}

/**
 * @brief Set the priority for all worker threads.
 * @param priority Windows thread priority constant.
 */
void ThreadPool::SetThreadPriority(int priority) {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->SetPriority(priority);
    }
    config_.threadPriority = priority;
}

/**
 * @brief Set the CPU affinity mask for all worker threads.
 * @param affinityMask CPU affinity bitmask.
 */
void ThreadPool::SetThreadAffinity(DWORD_PTR affinityMask) {
    std::shared_lock<std::shared_mutex> lock(workersMutex_);
    for (auto& worker : workers_) {
        worker->SetAffinity(affinityMask);
    }
}

/**
 * @brief Get the current number of tasks in the queue.
 * @return Queue size.
 */
size_t ThreadPool::GetQueueSize() const noexcept {
    return globalQueue_.Size();
}

/**
 * @brief Get the maximum queue capacity.
 * @return Maximum queue size.
 */
size_t ThreadPool::GetQueueCapacity() const noexcept {
    return globalQueue_.GetMaxSize();
}

/**
 * @brief Check if the task queue is at capacity.
 * @return true if queue is full, false otherwise.
 */
bool ThreadPool::IsQueueFull() const noexcept {
    return globalQueue_.IsFull();
}

/**
 * @brief Check if the task queue is empty.
 * @return true if queue is empty, false otherwise.
 */
bool ThreadPool::IsQueueEmpty() const noexcept {
    return globalQueue_.IsEmpty();
}

/**
 * @brief Clear all pending tasks from the queue.
 * 
 * @warning Tasks that are already executing will complete.
 *          Only queued tasks are removed.
 */
void ThreadPool::ClearQueue() {
    const size_t clearedCount = globalQueue_.Size();
    globalQueue_.Clear();
    perfMetrics_.currentQueueSize.store(0, std::memory_order_release);
    
    // Safely decrement pending tasks count
    if (clearedCount > 0) {
        // Use compare-exchange to avoid underflow
        size_t expected = pendingTasks_.load(std::memory_order_relaxed);
        while (expected > 0) {
            const size_t newValue = (expected >= clearedCount) ? (expected - clearedCount) : 0;
            if (pendingTasks_.compare_exchange_weak(expected, newValue, std::memory_order_release)) {
                break;
            }
        }
    }
}

/**
 * @brief Set the maximum queue capacity.
 * @param capacity New maximum queue size.
 */
void ThreadPool::SetQueueCapacity(size_t capacity) {
    globalQueue_.SetMaxSize(capacity);
    config_.maxQueueSize = capacity;
}

/**
 * @brief Get task execution statistics.
 * @return Reference to task statistics.
 */
const TaskStatistics& ThreadPool::GetTaskStatistics() const noexcept {
    return taskStats_;
}

/**
 * @brief Get thread statistics.
 * @return Reference to thread statistics.
 */
const ThreadStatistics& ThreadPool::GetThreadStatistics() const noexcept {
    return threadStats_;
}

/**
 * @brief Get performance metrics.
 * @return Reference to performance metrics.
 */
const PerformanceMetrics& ThreadPool::GetPerformanceMetrics() const noexcept {
    return perfMetrics_;
}

/**
 * @brief Reset all statistics counters to zero.
 * 
 * @note Does not affect current pool state or pending tasks.
 */
void ThreadPool::ResetStatistics() {
    taskStats_.Reset();
    threadStats_.Reset();
    perfMetrics_.Reset();
}

/**
 * @brief Generate a detailed statistics report.
 * @return Formatted statistics report string.
 */
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

/**
 * @brief Generate a health status report.
 * @return Formatted health report string.
 * 
 * Evaluates pool health based on:
 * - Initialization state
 * - Shutdown state
 * - Minimum thread count
 * - Task success rate (>95%)
 * - Deadlock detection status
 */
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

/**
 * @brief Get the current thread pool configuration.
 * @return Reference to configuration.
 */
const ThreadPoolConfig& ThreadPool::GetConfig() const noexcept {
    return config_;
}

/**
 * @brief Update the thread pool configuration.
 * @param config New configuration settings.
 * @throws std::invalid_argument if configuration is invalid.
 * 
 * Dynamically adjusts pool settings including thread count,
 * queue size, and deadlock detection.
 */
void ThreadPool::UpdateConfig(const ThreadPoolConfig& config) {
    if (!config.Validate()) {
        throw std::invalid_argument("Invalid ThreadPool configuration");
    }

    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    // Update queue size if changed
    if (config.maxQueueSize != config_.maxQueueSize) {
        globalQueue_.SetMaxSize(config.maxQueueSize);
    }

    // Adjust thread count to match new constraints
    const size_t currentThreads = workers_.size();
    if (currentThreads < config.minThreads) {
        CreateWorkerThreads(config.minThreads - currentThreads);
    }
    else if (currentThreads > config.maxThreads) {
        DestroyWorkerThreads(currentThreads - config.maxThreads);
    }

    // Handle deadlock detection changes
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

/**
 * @brief Wait for all pending tasks to complete (blocking).
 * 
 * @note This method blocks indefinitely until all tasks complete.
 */
void ThreadPool::WaitForAll() {
    constexpr auto kPollInterval = std::chrono::milliseconds(10);
    
    while (pendingTasks_.load(std::memory_order_acquire) > 0) {
        std::this_thread::sleep_for(kPollInterval);
    }
}

/**
 * @brief Wait for all pending tasks with timeout.
 * @param timeout Maximum time to wait.
 * @return true if all tasks completed, false if timeout expired.
 */
bool ThreadPool::WaitForAll(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    constexpr auto kPollInterval = std::chrono::milliseconds(10);

    while (pendingTasks_.load(std::memory_order_acquire) > 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;  // Timeout expired
        }
        std::this_thread::sleep_for(kPollInterval);
    }

    return true;
}

/**
 * @brief Get the last exception that occurred during task execution.
 * @return Optional exception pointer, or nullopt if no exception.
 */
std::optional<std::exception_ptr> ThreadPool::GetLastException() const noexcept {
    std::lock_guard<std::mutex> lock(exceptionMutex_);
    if (lastException_) {
        return lastException_;
    }
    return std::nullopt;
}

/**
 * @brief Create a cancellation token for task cancellation.
 * @return Shared pointer to atomic bool (initially false).
 * 
 * Set the atomic bool to true to cancel tasks using this token.
 */
std::shared_ptr<std::atomic<bool>> ThreadPool::CreateCancellationToken() {
    return std::make_shared<std::atomic<bool>>(false);
}

/**
 * @brief Create and start new worker threads.
 * @param count Number of threads to create.
 * 
 * @throws Propagates exceptions from thread creation.
 * @note Caller must hold workersMutex_ exclusive lock.
 */
void ThreadPool::CreateWorkerThreads(size_t count) {
    for (size_t i = 0; i < count; ++i) {
        try {
            const size_t threadId = workers_.size();
            
            // Create per-worker queue (for potential future work stealing optimization)
            auto queue = std::make_unique<PriorityTaskQueue>(config_.maxQueueSize);
            
            // Create worker thread
            auto worker = std::make_unique<WorkerThread>(
                threadId,
                globalQueue_,
                workers_,
                config_,
                pendingTasks_,  
                etwManager_.get()
            );

            worker->Start();

            // Register for deadlock monitoring if enabled
            if (deadlockDetector_) {
                deadlockDetector_->RegisterThread(worker->GetSystemThreadId());
            }

            workers_.push_back(std::move(worker));
            queues_.push_back(std::move(queue));

            // Update statistics
            threadStats_.currentThreadCount.fetch_add(1, std::memory_order_relaxed);
            threadStats_.totalThreadsCreated.fetch_add(1, std::memory_order_relaxed);

            // Update peak thread count atomically
            const size_t current = threadStats_.currentThreadCount.load(std::memory_order_relaxed);
            size_t expected = threadStats_.peakThreadCount.load(std::memory_order_relaxed);
            while (current > expected) {
                if (threadStats_.peakThreadCount.compare_exchange_weak(
                        expected, current, std::memory_order_relaxed)) {
                    break;
                }
            }

        }
        catch (...) {
            threadStats_.threadCreationFailures.fetch_add(1, std::memory_order_relaxed);
            
            // Store exception for later retrieval
            std::lock_guard<std::mutex> lock(exceptionMutex_);
            lastException_ = std::current_exception();
            throw;
        }
    }
}

/**
 * @brief Stop and destroy worker threads.
 * @param count Number of threads to destroy.
 * 
 * Removes threads from the back of the worker list (LIFO).
 * 
 * @note Caller must hold workersMutex_ exclusive lock.
 */
void ThreadPool::DestroyWorkerThreads(size_t count) {
    // Clamp to available workers
    count = std::min(count, workers_.size());
    
    // Collect workers to destroy (to join outside potential lock scope)
    std::vector<std::unique_ptr<WorkerThread>> workersToDestroy;
    workersToDestroy.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        auto& worker = workers_.back();

        // Unregister from deadlock monitoring
        if (deadlockDetector_) {
            deadlockDetector_->UnregisterThread(worker->GetSystemThreadId());
        }

        // Move to destruction list
        workersToDestroy.push_back(std::move(workers_.back()));

        workers_.pop_back();
        queues_.pop_back();

        // Update statistics
        threadStats_.currentThreadCount.fetch_sub(1, std::memory_order_relaxed);
        threadStats_.totalThreadsDestroyed.fetch_add(1, std::memory_order_relaxed);
    }

    // Workers are stopped and joined when unique_ptr destructs
}
/**
 * @brief Main monitoring loop running in dedicated thread.
 * 
 * Periodically updates metrics (every 1 second) and checks health (every 5 seconds).
 */
void ThreadPool::MonitoringLoop() {
    auto lastMetricsUpdate = std::chrono::steady_clock::now();
    auto lastHealthCheck = std::chrono::steady_clock::now();

    // Monitoring intervals
    constexpr auto kMetricsInterval = std::chrono::seconds(1);
    constexpr auto kHealthCheckInterval = std::chrono::seconds(5);
    constexpr auto kSleepInterval = std::chrono::milliseconds(100);

    while (monitoringActive_.load(std::memory_order_acquire)) {
        const auto now = std::chrono::steady_clock::now();

        // Update performance metrics every second
        if (now - lastMetricsUpdate >= kMetricsInterval) {
            UpdateMetrics();
            lastMetricsUpdate = now;
        }

        // Check thread health every 5 seconds
        if (now - lastHealthCheck >= kHealthCheckInterval) {
            CheckThreadHealth();
            lastHealthCheck = now;
        }

        std::this_thread::sleep_for(kSleepInterval);
    }
}

/**
 * @brief Update performance metrics.
 * 
 * Updates uptime, throughput, thread states, queue size, and memory usage.
 */
void ThreadPool::UpdateMetrics() {
    const auto now = std::chrono::steady_clock::now();
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - perfMetrics_.startTime);
    perfMetrics_.totalUptime.store(static_cast<uint64_t>(uptime.count()), std::memory_order_relaxed);

    // Calculate throughput
    const auto completed = taskStats_.completedCount.load(std::memory_order_relaxed);
    perfMetrics_.UpdateThroughput(
        completed, 
        std::chrono::milliseconds(static_cast<int64_t>(uptime.count()) * 1000)
    );

    // Count active and idle threads
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

    // Query process memory usage
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (::GetProcessMemoryInfo(
            ::GetCurrentProcess(), 
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), 
            sizeof(pmc))) {
        perfMetrics_.memoryUsage.store(pmc.WorkingSetSize, std::memory_order_relaxed);
    }

    // Log metrics via ETW if enabled
    if (etwManager_ && etwManager_->IsEnabled() && config_.enablePerformanceCounters) {
        etwManager_->LogPerformanceMetrics(perfMetrics_, taskStats_, threadStats_);
    }
}

/**
 * @brief Check thread pool health and detect issues.
 * 
 * Detects thread starvation, queue overflow, and potential deadlocks.
 */
void ThreadPool::CheckThreadHealth() {
    const size_t queueSize = globalQueue_.Size();
    const size_t idleThreads = threadStats_.idleThreadCount.load(std::memory_order_relaxed);

    // Detect thread starvation: tasks queued but no idle threads
    if (queueSize > 0 && idleThreads == 0) {
        LogETWEvent(
            ETWEventId::ThreadStarved,
            std::format(L"Thread starvation detected: {} tasks queued, 0 idle threads", queueSize),
            ETWLevel::Warning
        );
        OptimizeThreadCount();
    }

    // Detect queue near overflow
    const double queueUsage = (config_.maxQueueSize > 0) 
        ? (static_cast<double>(queueSize) / static_cast<double>(config_.maxQueueSize))
        : 0.0;
        
    if (queueUsage > 0.9) {
        LogETWEvent(
            ETWEventId::QueueOverflow,
            std::format(L"Queue near capacity: {:.1f}% full", queueUsage * 100.0),
            ETWLevel::Warning
        );
    }

    // Check for deadlock
    if (deadlockDetector_ && deadlockDetector_->IsDeadlockDetected()) {
        auto suspicious = deadlockDetector_->GetSuspiciousThreads();
        std::wstring threadList;
        threadList.reserve(suspicious.size() * 12);  // Pre-allocate for thread IDs
        
        for (auto tid : suspicious) {
            threadList += std::to_wstring(tid) + L" ";
        }
        
        LogETWEvent(
            ETWEventId::DeadlockDetected,
            std::format(L"Potential deadlock detected in threads: {}", threadList),
            ETWLevel::Critical
        );
    }
}

/**
 * @brief Handle queue overflow by adding threads.
 * 
 * Adds up to 4 threads when queue overflow is detected.
 */
void ThreadPool::HandleOverflow() {
    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    const size_t currentThreads = workers_.size();
    if (currentThreads < config_.maxThreads) {
        // Add threads in response to overflow (max 4 at a time)
        constexpr size_t kMaxOverflowThreads = 4;
        const size_t additionalThreads = std::min(
            config_.maxThreads - currentThreads, 
            kMaxOverflowThreads
        );
        
        CreateWorkerThreads(additionalThreads);
        
        LogETWEvent(
            ETWEventId::PoolResized,
            std::format(L"Overflow: Added {} threads (total: {})", additionalThreads, workers_.size()),
            ETWLevel::Warning
        );
    }
}

/**
 * @brief Dynamically optimize thread count based on workload.
 * 
 * Increases threads when queue is growing, decreases when idle.
 */
void ThreadPool::OptimizeThreadCount() {
    std::unique_lock<std::shared_mutex> lock(workersMutex_);

    const size_t queueSize = globalQueue_.Size();
    const size_t currentThreads = workers_.size();
    const size_t idleThreads = threadStats_.idleThreadCount.load(std::memory_order_relaxed);

    // Scale up: queue is more than 2x thread count
    if (queueSize > currentThreads * 2 && currentThreads < config_.maxThreads) {
        const size_t neededThreads = std::min(
            (queueSize / 2) - currentThreads, 
            config_.maxThreads - currentThreads
        );
        
        if (neededThreads > 0) {
            CreateWorkerThreads(neededThreads);
        }
    }
    // Scale down: more than half of threads are idle
    else if (idleThreads > currentThreads / 2 && currentThreads > config_.minThreads) {
        const size_t excessThreads = std::min(
            idleThreads - (currentThreads / 4), 
            currentThreads - config_.minThreads
        );
        
        if (excessThreads > 0) {
            DestroyWorkerThreads(excessThreads);
        }
    }
}

/**
 * @brief Log an event via ETW.
 * @param eventId The ETW event identifier.
 * @param message The event message.
 * @param level The event severity level.
 */
void ThreadPool::LogETWEvent(ETWEventId eventId, const std::wstring& message, ETWLevel level) {
    if (etwManager_ && etwManager_->IsEnabled()) {
        etwManager_->LogEvent(eventId, level, message);
    }
}

} // namespace ShadowStrike::Utils
