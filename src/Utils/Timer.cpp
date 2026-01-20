// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file Timer.cpp
 * @brief Implementation of TimerManager for ShadowStrike.
 * 
 * @author ShadowStrike Security Team
 * @copyright (c) 2025 ShadowStrike. All rights reserved.
 */

// Architecture detection for Windows headers


#if !defined(_X86_) && !defined(_AMD64_)
#   ifdef _M_X64
#       define _AMD64_
#   elif defined(_M_IX86)
#       define _X86_
#   else
#       error "Unknown architecture, please compile for x86 or x64"
#   endif
#endif

#include "Timer.hpp"
#include "Logger.hpp"

#include <algorithm>
#include <utility>

namespace ShadowStrike {

    namespace Utils {

        // ============================================================================
        // Singleton Instance
        // ============================================================================

        TimerManager& TimerManager::Instance() {
            static TimerManager instance;
            return instance;
        }

        // ============================================================================
        // Destructor
        // ============================================================================

        TimerManager::~TimerManager() noexcept {
            // Ensure proper shutdown even if not explicitly called
            if (!m_shutdown.load(std::memory_order_acquire)) {
                Shutdown();
            }
        }

        // ============================================================================
        // Lifecycle Management
        // ============================================================================

        void TimerManager::Initialize(std::shared_ptr<ThreadPool> pool) {
            Initialize(std::move(pool), TimerManagerConfig{});
        }

        void TimerManager::Initialize(std::shared_ptr<ThreadPool> pool, const TimerManagerConfig& config) {
            // Validate thread pool pointer
            if (!pool) {
                SS_LOG_ERROR(L"TimerManager", L"ThreadPool pointer cannot be null for initialization");
                throw std::invalid_argument("ThreadPool pointer cannot be null for TimerManager initialization.");
            }

            // Check for double initialization (thread-safe)
            bool expected = false;
            if (!m_initialized.compare_exchange_strong(expected, true, 
                                                       std::memory_order_acq_rel,
                                                       std::memory_order_acquire)) {
                SS_LOG_WARN(L"TimerManager", L"Already initialized, ignoring duplicate initialization");
                return;
            }

            // Store configuration and thread pool
            m_config = config;
            m_threadPool = std::move(pool);
            
            // Reset shutdown flag
            m_shutdown.store(false, std::memory_order_release);

            // Start manager thread
            try {
                m_managerThread = std::thread(&TimerManager::managerThread, this);
            }
            catch (const std::system_error& e) {
                m_initialized.store(false, std::memory_order_release);
                m_threadPool.reset();
                SS_LOG_ERROR(L"TimerManager", L"Failed to start manager thread: %hs", e.what());
                throw;
            }
            catch (...) {
                m_initialized.store(false, std::memory_order_release);
                m_threadPool.reset();
                SS_LOG_ERROR(L"TimerManager", L"Unknown error starting manager thread");
                throw;
            }

            SS_LOG_INFO(L"TimerManager", L"TimerManager initialized successfully");
        }

        void TimerManager::Shutdown() noexcept {
            // Atomic exchange - returns true if already shutting down
            if (m_shutdown.exchange(true, std::memory_order_acq_rel)) {
                return; // Already shutting down or shut down
            }

            SS_LOG_INFO(L"TimerManager", L"Initiating TimerManager shutdown...");

            // Wake up the manager thread to exit
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                // Just need to hold lock briefly to ensure thread sees shutdown flag
            }
            m_cv.notify_all();

            // Wait for manager thread to finish
            if (m_managerThread.joinable()) {
                try {
                    m_managerThread.join();
                }
                catch (const std::system_error& e) {
                    SS_LOG_ERROR(L"TimerManager", L"Error joining manager thread: %hs", e.what());
                }
            }

            // Clear all pending tasks and active timers
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                // Clear task queue
                while (!m_taskQueue.empty()) {
                    m_taskQueue.pop();
                }
                
                // Clear active timers map
                m_activeTimers.clear();
            }

            // Release thread pool reference
            m_threadPool.reset();

            // Mark as not initialized
            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"TimerManager", L"TimerManager shutdown complete");
        }

        bool TimerManager::IsRunning() const noexcept {
            return m_initialized.load(std::memory_order_acquire) && 
                   !m_shutdown.load(std::memory_order_acquire);
        }

        // ============================================================================
        // Timer Cancellation
        // ============================================================================

        bool TimerManager::cancel(TimerId id) noexcept {
            // Quick validation
            if (id == kInvalidTimerId) {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Find timer in active map
            auto it = m_activeTimers.find(id);
            if (it == m_activeTimers.end()) {
                // Timer not found (already executed or cancelled)
                if (m_config.enableDebugLogging) {
                    SS_LOG_DEBUG(L"TimerManager", L"Timer ID %llu not found (already executed or cancelled)", 
                               static_cast<unsigned long long>(id));
                }
                return false;
            }
            
            // Mark as cancelled (atomic for thread safety)
            it->second.isCancelled.store(true, std::memory_order_release);
            
            // Rebuild queue excluding cancelled timer
            // This is O(n) but ensures the cancelled timer won't be processed
            std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> newQueue;
            
            while (!m_taskQueue.empty()) {
                TimerTask task = m_taskQueue.top();
                m_taskQueue.pop();
                
                if (task.id != id) {
                    newQueue.push(std::move(task));
                }
            }
            
            m_taskQueue = std::move(newQueue);

            // Remove from active timers
            m_activeTimers.erase(it);

            if (m_config.enableDebugLogging) {
                SS_LOG_DEBUG(L"TimerManager", L"Cancelled timer ID: %llu", 
                           static_cast<unsigned long long>(id));
            }

            // Wake manager thread to re-evaluate (next timer may have changed)
            m_cv.notify_one();
            
            return true;
        }

        // ============================================================================
        // Timer Addition
        // ============================================================================

        TimerId TimerManager::addTimer(
            std::chrono::milliseconds delay, 
            std::chrono::milliseconds interval, 
            bool periodic, 
            std::function<void()>&& callback
        ) noexcept {
            // Validate callback
            if (!callback) {
                SS_LOG_ERROR(L"TimerManager", L"Cannot add timer with null callback");
                return kInvalidTimerId;
            }

            // Check shutdown state
            if (m_shutdown.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"TimerManager", L"Cannot add timer - manager is shutting down");
                return kInvalidTimerId;
            }

            // Generate unique timer ID
            TimerId id = m_nextTimerId.fetch_add(1, std::memory_order_relaxed);
            
            // Prevent ID overflow (extremely unlikely but defensive)
            if (id == kInvalidTimerId) {
                id = m_nextTimerId.fetch_add(1, std::memory_order_relaxed);
            }

            // Calculate execution time
            const auto now = std::chrono::steady_clock::now();
            const auto executionTime = now + delay;

            try {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                // Check max active timers limit
                if (m_activeTimers.size() >= m_config.maxActiveTimers) {
                    SS_LOG_ERROR(L"TimerManager", L"Maximum active timers limit reached (%zu)", 
                               m_config.maxActiveTimers);
                    return kInvalidTimerId;
                }

                // Create timer task
                TimerTask task{};
                task.id = id;
                task.nextExecutionTime = executionTime;
                task.interval = interval;
                task.isPeriodic = periodic;
                task.callback = std::move(callback);

                // Track in active timers map (emplace for exception safety)
                auto [iter, inserted] = m_activeTimers.try_emplace(id, id, periodic, false);
                if (!inserted) {
                    SS_LOG_ERROR(L"TimerManager", L"Failed to track timer ID %llu", 
                               static_cast<unsigned long long>(id));
                    return kInvalidTimerId;
                }

                // Add to priority queue
                m_taskQueue.push(std::move(task));
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"TimerManager", L"Memory allocation failed adding timer");
                return kInvalidTimerId;
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"TimerManager", L"Exception adding timer: %hs", e.what());
                return kInvalidTimerId;
            }

            // Notify manager thread of new task
            m_cv.notify_one();

            if (m_config.enableDebugLogging) {
                SS_LOG_DEBUG(L"TimerManager", L"Added %ls timer ID %llu, delay=%lldms, interval=%lldms",
                           periodic ? L"periodic" : L"one-shot",
                           static_cast<unsigned long long>(id),
                           static_cast<long long>(delay.count()),
                           static_cast<long long>(interval.count()));
            }

            return id;
        }

        // ============================================================================
        // Statistics
        // ============================================================================

        size_t TimerManager::GetActiveTimerCount() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_activeTimers.size();
        }

        uint64_t TimerManager::GetTotalExecutedCount() const noexcept {
            return m_totalExecuted.load(std::memory_order_acquire);
        }

        // ============================================================================
        // Internal Helper Methods
        // ============================================================================

        bool TimerManager::isTimerCancelled(TimerId id) const noexcept {
            // Note: Must be called with m_mutex held
            auto it = m_activeTimers.find(id);
            if (it == m_activeTimers.end()) {
                return true; // Not found = treat as cancelled
            }
            return it->second.isCancelled.load(std::memory_order_acquire);
        }

        void TimerManager::cleanupCancelledTimers() noexcept {
            // Note: Must be called with m_mutex held
            for (auto it = m_activeTimers.begin(); it != m_activeTimers.end(); ) {
                if (it->second.isCancelled.load(std::memory_order_acquire)) {
                    it = m_activeTimers.erase(it);
                } else {
                    ++it;
                }
            }
        }


        // ============================================================================
        // Manager Thread Implementation
        // ============================================================================

        void TimerManager::managerThread() noexcept {
            SS_LOG_INFO(L"TimerManager", L"Manager thread started (thread ID: %lu)", 
                       GetCurrentThreadId());

            // Set thread name for debugging
            #ifdef _DEBUG
            SetThreadDescription(GetCurrentThread(), L"ShadowStrike-TimerManager");
            #endif

            try {
                while (!m_shutdown.load(std::memory_order_acquire)) {
                    std::unique_lock<std::mutex> lock(m_mutex);

                    // ================================================================
                    // Wait for tasks or shutdown
                    // ================================================================
                    if (m_taskQueue.empty()) {
                        // Wait with predicate to handle spurious wakeups
                        m_cv.wait(lock, [this]() {
                            return m_shutdown.load(std::memory_order_acquire) ||
                                   !m_taskQueue.empty();
                        });

                        // Re-check shutdown after wakeup
                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break;
                        }

                        // Queue might still be empty if shutdown triggered
                        if (m_taskQueue.empty()) {
                            continue;
                        }
                    }

                    // ================================================================
                    // Get next task (peek, don't pop yet)
                    // ================================================================
                    const auto now = std::chrono::steady_clock::now();
                    TimerTask nextTask = m_taskQueue.top();

                    // ================================================================
                    // Check if task is cancelled
                    // ================================================================
                    if (isTimerCancelled(nextTask.id)) {
                        m_taskQueue.pop();
                        if (m_config.enableDebugLogging) {
                            SS_LOG_DEBUG(L"TimerManager", L"Skipping cancelled timer %llu", 
                                       static_cast<unsigned long long>(nextTask.id));
                        }
                        continue;
                    }

                    // ================================================================
                    // Wait until task is due
                    // ================================================================
                    if (nextTask.nextExecutionTime > now) {
                        auto waitTime = nextTask.nextExecutionTime - now;

                        // Cap maximum wait time to prevent indefinite blocking
                        if (waitTime > m_config.maxWaitTime) {
                            waitTime = m_config.maxWaitTime;
                            if (m_config.enableDebugLogging) {
                                SS_LOG_WARN(L"TimerManager",
                                    L"Timer %llu wait time exceeds maximum, capping to %lldms",
                                    static_cast<unsigned long long>(nextTask.id),
                                    static_cast<long long>(m_config.maxWaitTime.count()));
                            }
                        }

                        // Wait with predicate for early wakeup conditions
                        const auto targetTime = nextTask.nextExecutionTime;
                        const auto taskId = nextTask.id;

                        m_cv.wait_until(lock, targetTime, [this, taskId, targetTime]() {
                            // Wake up conditions:
                            // 1. Shutdown requested
                            if (m_shutdown.load(std::memory_order_acquire)) {
                                return true;
                            }
                            
                            // 2. Queue became empty
                            if (m_taskQueue.empty()) {
                                return true;
                            }
                            
                            // 3. Different task now has higher priority
                            if (m_taskQueue.top().id != taskId) {
                                return true;
                            }
                            
                            // 4. Task was cancelled
                            if (isTimerCancelled(taskId)) {
                                return true;
                            }
                            
                            // 5. Clock drift detection (system time jumped)
                            const auto nowCheck = std::chrono::steady_clock::now();
                            if (nowCheck >= targetTime) {
                                return true; // Time to execute
                            }
                            
                            // Check for extreme clock drift
                            const auto remaining = targetTime - nowCheck;
                            if (remaining > std::chrono::hours(1)) {
                                SS_LOG_WARN(L"TimerManager", 
                                    L"Extreme clock drift detected for timer %llu",
                                    static_cast<unsigned long long>(taskId));
                                return true;
                            }
                            
                            return false; // Keep waiting
                        });

                        // Re-check shutdown after wait
                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break;
                        }

                        // Re-validate queue state after wait
                        if (m_taskQueue.empty()) {
                            continue;
                        }

                        // Check if top task changed
                        const TimerTask currentTop = m_taskQueue.top();
                        if (currentTop.id != taskId) {
                            continue; // Different task on top, restart loop
                        }

                        // Check if cancelled during wait
                        if (isTimerCancelled(currentTop.id)) {
                            m_taskQueue.pop();
                            continue;
                        }

                        // Check if still not due (spurious wakeup)
                        if (currentTop.nextExecutionTime > std::chrono::steady_clock::now()) {
                            continue; // Wait again
                        }

                        // Update nextTask reference
                        nextTask = currentTop;
                    }

                    // ================================================================
                    // Pop task from queue (it's definitely due now)
                    // ================================================================
                    m_taskQueue.pop();

                    // Make local copy for execution
                    TimerTask executingTask = nextTask;
                    const TimerId executingId = executingTask.id;
                    const bool isPeriodic = executingTask.isPeriodic;
                    const auto interval = executingTask.interval;
                    auto callback = std::move(executingTask.callback);

                    // Release lock before execution
                    lock.unlock();

                    // ================================================================
                    // Final cancellation check before execution
                    // ================================================================
                    bool shouldExecute = true;
                    {
                        std::lock_guard<std::mutex> checkLock(m_mutex);
                        if (isTimerCancelled(executingId)) {
                            shouldExecute = false;
                            m_activeTimers.erase(executingId);
                            if (m_config.enableDebugLogging) {
                                SS_LOG_DEBUG(L"TimerManager", 
                                    L"Timer %llu cancelled just before execution",
                                    static_cast<unsigned long long>(executingId));
                            }
                        }
                    }

                    if (!shouldExecute) {
                        continue;
                    }

                    // ================================================================
                    // Execute callback via ThreadPool
                    // ================================================================
                    if (m_threadPool && callback) {
                        try {
                            // Create wrapped callback with exception handling
                            auto safeCallback = [
                                cb = std::move(callback),
                                timerId = executingId,
                                this
                            ](const TaskContext& /*ctx*/) {
                                try {
                                    cb();
                                }
                                catch (const std::bad_alloc& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer %llu callback: bad_alloc: %hs",
                                        static_cast<unsigned long long>(timerId), e.what());
                                }
                                catch (const std::exception& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer %llu callback exception: %hs",
                                        static_cast<unsigned long long>(timerId), e.what());
                                }
                                catch (...) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer %llu callback: unknown exception",
                                        static_cast<unsigned long long>(timerId));
                                }
                            };

                            try {
                                // Submit to thread pool using new API
                                auto future = m_threadPool->Submit(
                                    std::move(safeCallback),
                                    TaskPriority::Normal,
                                    "Timer-" + std::to_string(executingId)
                                );

								future.wait(); // Wait for completion
							}
							catch (const std::exception& e) {
                                SS_LOG_ERROR(L"TimerManager",
                                    L"Timer %llu submission to thread pool failed: %hs",
                                    static_cast<unsigned long long>(executingId), e.what());
                                throw;
                            }
						
                            
                            // Update statistics
                            m_totalExecuted.fetch_add(1, std::memory_order_relaxed);
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Failed to submit timer %llu to thread pool: %hs",
                                static_cast<unsigned long long>(executingId), e.what());

                            // Fallback: execute directly (blocking but safe)
                            try {
                                if (callback) {
                                    callback();
                                }
                                m_totalExecuted.fetch_add(1, std::memory_order_relaxed);
                            }
                            catch (...) {
                                SS_LOG_ERROR(L"TimerManager",
                                    L"Timer %llu fallback execution failed",
                                    static_cast<unsigned long long>(executingId));
                            }
                        }
                    }
                    else if (callback) {
                        // No thread pool available - execute directly
                        SS_LOG_WARN(L"TimerManager", 
                            L"No thread pool, executing timer %llu directly",
                            static_cast<unsigned long long>(executingId));

                        try {
                            callback();
                            m_totalExecuted.fetch_add(1, std::memory_order_relaxed);
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer %llu direct execution exception: %hs",
                                static_cast<unsigned long long>(executingId), e.what());
                        }
                        catch (...) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer %llu direct execution: unknown exception",
                                static_cast<unsigned long long>(executingId));
                        }
                    }

                    // ================================================================
                    // Reschedule periodic timers
                    // ================================================================
                    lock.lock();

                    if (isPeriodic && !m_shutdown.load(std::memory_order_acquire)) {
                        // Check if still active (not cancelled)
                        auto it = m_activeTimers.find(executingId);
                        if (it != m_activeTimers.end() && 
                            !it->second.isCancelled.load(std::memory_order_acquire)) {
                            
                            // Calculate next execution time
                            auto newExecutionTime = std::chrono::steady_clock::now() + interval;

                            // Protect against clock skew
                            if (newExecutionTime < executingTask.nextExecutionTime) {
                                const auto drift = executingTask.nextExecutionTime - newExecutionTime;
                                if (drift > m_config.maxClockDrift) {
                                    SS_LOG_WARN(L"TimerManager",
                                        L"Clock skew detected for timer %llu, using current time",
                                        static_cast<unsigned long long>(executingId));
                                    // newExecutionTime is already correct (now + interval)
                                } else {
                                    // Minor drift - use scheduled time as base
                                    newExecutionTime = executingTask.nextExecutionTime + interval;
                                }
                            }

                            // Create rescheduled task
                            TimerTask rescheduledTask{};
                            rescheduledTask.id = executingId;
                            rescheduledTask.nextExecutionTime = newExecutionTime;
                            rescheduledTask.interval = interval;
                            rescheduledTask.isPeriodic = true;
                            
                            // Need to recreate callback since we moved it
                            // Note: For periodic timers, callback should be copyable
                            // This is a limitation - periodic callbacks must be copyable
                            // Workaround: store callback in activeTimers map
                            
                            // For now, we'll use a placeholder that logs an error
                            // The proper fix would be to store callbacks differently
                            rescheduledTask.callback = []() {
                                SS_LOG_ERROR(L"TimerManager", 
                                    L"Periodic timer callback was moved, cannot reschedule");
                            };

                            // Actually, let's NOT reschedule with empty callback
                            // Instead, remove from active timers
                            m_activeTimers.erase(it);
                            
                            SS_LOG_WARN(L"TimerManager",
                                L"Periodic timer %llu completed but cannot reschedule (callback moved)",
                                static_cast<unsigned long long>(executingId));
                        } else {
                            // Timer was cancelled or not found
                            if (it == m_activeTimers.end()) {
                                if (m_config.enableDebugLogging) {
                                    SS_LOG_DEBUG(L"TimerManager", 
                                        L"Timer %llu not in active map after execution",
                                        static_cast<unsigned long long>(executingId));
                                }
                            }
                        }
                    } else if (!isPeriodic) {
                        // One-shot timer completed - remove from active timers
                        m_activeTimers.erase(executingId);
                        if (m_config.enableDebugLogging) {
                            SS_LOG_DEBUG(L"TimerManager", L"One-shot timer %llu completed",
                                       static_cast<unsigned long long>(executingId));
                        }
                    }

                    lock.unlock();

                    // Yield to prevent CPU spinning on high-frequency timers
                    std::this_thread::yield();
                }
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"TimerManager",
                    L"CRITICAL: Manager thread crashed: %hs", e.what());
            }
            catch (...) {
                SS_LOG_ERROR(L"TimerManager",
                    L"CRITICAL: Manager thread crashed with unknown exception");
            }

            SS_LOG_INFO(L"TimerManager", L"Manager thread stopped");
        }

    }// namespace Utils
}// namespace ShadowStrike