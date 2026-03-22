/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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

            // Validate configuration
            if (config.maxActiveTimers == 0) {
                SS_LOG_ERROR(L"TimerManager", L"maxActiveTimers must be > 0");
                throw std::invalid_argument("TimerManagerConfig::maxActiveTimers must be > 0");
            }
            if (config.maxWaitTime <= std::chrono::milliseconds(0)) {
                SS_LOG_ERROR(L"TimerManager", L"maxWaitTime must be positive");
                throw std::invalid_argument("TimerManagerConfig::maxWaitTime must be positive");
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

            // Clear all pending tasks, active timers, and release thread pool under lock
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                // Clear task queue
                while (!m_taskQueue.empty()) {
                    m_taskQueue.pop();
                }
                
                // Clear active timers map
                m_activeTimers.clear();

                // Release thread pool reference under lock (prevents race with managerThread)
                m_threadPool.reset();
            }

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

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                // Find timer in active map
                auto it = m_activeTimers.find(id);
                if (it == m_activeTimers.end()) {
                    if (m_config.enableDebugLogging) {
                        SS_LOG_DEBUG(L"TimerManager", L"Timer ID %llu not found (already executed or cancelled)", 
                                   static_cast<unsigned long long>(id));
                    }
                    return false;
                }
                
                // Mark as cancelled — managerThread skips cancelled entries at queue top
                it->second->isCancelled.store(true, std::memory_order_release);

                // Erase from map immediately to free capacity (isTimerCancelled returns
                // true for absent entries, so orphaned queue entries drain correctly)
                m_activeTimers.erase(it);
            }

            // Notify outside lock to avoid spurious wake→block→wake cycle
            m_cv.notify_one();

            if (m_config.enableDebugLogging) {
                SS_LOG_DEBUG(L"TimerManager", L"Cancelled timer ID: %llu", 
                           static_cast<unsigned long long>(id));
            }
            
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

            // Generate unique timer ID (CAS loop to skip kInvalidTimerId)
            TimerId id;
            do {
                id = m_nextTimerId.fetch_add(1, std::memory_order_relaxed);
            } while (id == kInvalidTimerId);

            // Calculate execution time
            const auto now = std::chrono::steady_clock::now();
            const auto executionTime = now + delay;

            try {
                // Shared callback — periodic timers reuse across firings
                auto sharedCallback = std::make_shared<std::function<void()>>(std::move(callback));

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
                task.callback = sharedCallback;

                // Track in active timers map (unique_ptr — non-movable metadata)
                auto meta = std::make_unique<TimerMetadata>(id, periodic, sharedCallback);
                auto [iter, inserted] = m_activeTimers.try_emplace(id, std::move(meta));
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
            if (it == m_activeTimers.end() || !it->second) {
                return true; // Not found = treat as cancelled
            }
            return it->second->isCancelled.load(std::memory_order_acquire);
        }



        // ============================================================================
        // Manager Thread Implementation
        // ============================================================================

        void TimerManager::managerThread() noexcept {
            SS_LOG_INFO(L"TimerManager", L"Manager thread started (thread ID: %lu)", 
                       GetCurrentThreadId());

            // Set thread name for debugging (useful in Release crash dumps too)
            SetThreadDescription(GetCurrentThread(), L"ShadowStrike-TimerManager");

            try {
                while (!m_shutdown.load(std::memory_order_acquire)) {
                    std::unique_lock<std::mutex> lock(m_mutex);

                    // ================================================================
                    // Wait for tasks or shutdown
                    // ================================================================
                    if (m_taskQueue.empty()) {
                        m_cv.wait(lock, [this]() {
                            return m_shutdown.load(std::memory_order_acquire) ||
                                   !m_taskQueue.empty();
                        });

                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break;
                        }

                        if (m_taskQueue.empty()) {
                            continue;
                        }
                    }

                    // ================================================================
                    // Drain cancelled entries from queue top (lazy cancellation)
                    // ================================================================
                    while (!m_taskQueue.empty() && isTimerCancelled(m_taskQueue.top().id)) {
                        const auto cancelledId = m_taskQueue.top().id;
                        m_taskQueue.pop();
                        m_activeTimers.erase(cancelledId);
                    }

                    if (m_taskQueue.empty()) {
                        continue;
                    }

                    // ================================================================
                    // Peek next task
                    // ================================================================
                    const auto now = std::chrono::steady_clock::now();
                    const auto& topRef = m_taskQueue.top();
                    const auto taskId = topRef.id;

                    // ================================================================
                    // Wait until task is due (with correct maxWaitTime cap)
                    // ================================================================
                    if (topRef.nextExecutionTime > now) {
                        const auto cappedTarget = std::min(
                            topRef.nextExecutionTime,
                            now + m_config.maxWaitTime);

                        m_cv.wait_until(lock, cappedTarget, [this, taskId]() {
                            if (m_shutdown.load(std::memory_order_acquire)) {
                                return true;
                            }
                            if (m_taskQueue.empty()) {
                                return true;
                            }
                            // Wake if a different (earlier) task was inserted or this was cancelled
                            if (m_taskQueue.top().id != taskId) {
                                return true;
                            }
                            if (isTimerCancelled(taskId)) {
                                return true;
                            }
                            return false;
                        });

                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break;
                        }

                        // Re-validate: queue may be empty, top may have changed, or not yet due
                        if (m_taskQueue.empty()) {
                            continue;
                        }
                        if (m_taskQueue.top().id != taskId) {
                            continue;
                        }
                        if (isTimerCancelled(taskId)) {
                            m_taskQueue.pop();
                            m_activeTimers.erase(taskId);
                            continue;
                        }
                        if (m_taskQueue.top().nextExecutionTime > std::chrono::steady_clock::now()) {
                            continue; // Spurious wakeup or maxWaitTime cap — loop again
                        }
                    }

                    // ================================================================
                    // Pop task — it's due now
                    // ================================================================
                    TimerTask firingTask = std::move(const_cast<TimerTask&>(m_taskQueue.top()));
                    m_taskQueue.pop();

                    const TimerId executingId = firingTask.id;
                    const bool isPeriodic = firingTask.isPeriodic;
                    const auto interval = firingTask.interval;
                    auto sharedCb = firingTask.callback; // shared_ptr copy (cheap refcount bump)

                    // Take a local copy of thread pool shared_ptr under lock (TM2 race fix)
                    auto pool = m_threadPool;

                    // ================================================================
                    // Reschedule periodic timer BEFORE execution (avoids callback-moved problem)
                    // ================================================================
                    if (isPeriodic && !m_shutdown.load(std::memory_order_acquire)) {
                        auto metaIt = m_activeTimers.find(executingId);
                        if (metaIt != m_activeTimers.end() && metaIt->second &&
                            !metaIt->second->isCancelled.load(std::memory_order_acquire)) {
                            
                            TimerTask rescheduled{};
                            rescheduled.id = executingId;
                            rescheduled.nextExecutionTime = std::chrono::steady_clock::now() + interval;
                            rescheduled.interval = interval;
                            rescheduled.isPeriodic = true;
                            rescheduled.callback = sharedCb; // same shared_ptr — callback lives on
                            m_taskQueue.push(std::move(rescheduled));
                        }
                    } else if (!isPeriodic) {
                        // One-shot: remove from active map after firing
                        m_activeTimers.erase(executingId);
                    }

                    // Release lock before execution
                    lock.unlock();

                    // ================================================================
                    // Execute callback via ThreadPool (fire-and-forget, no future.wait)
                    // ================================================================
                    if (pool && sharedCb && *sharedCb) {
                        try {
                            auto safeCallback = [
                                cb = sharedCb,
                                timerId = executingId
                            ](const TaskContext& /*ctx*/) {
                                try {
                                    (*cb)();
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

                            // Fire-and-forget — no future.wait() to avoid starvation (TM4 fix)
                            (void)pool->Submit(
                                std::move(safeCallback),
                                TaskPriority::Normal,
                                "Timer-" + std::to_string(executingId)
                            );

                            m_totalExecuted.fetch_add(1, std::memory_order_relaxed);
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Failed to submit timer %llu to thread pool: %hs",
                                static_cast<unsigned long long>(executingId), e.what());

                            // Fallback: execute directly using sharedCb (NOT moved-from)
                            try {
                                (*sharedCb)();
                                m_totalExecuted.fetch_add(1, std::memory_order_relaxed);
                            }
                            catch (...) {
                                SS_LOG_ERROR(L"TimerManager",
                                    L"Timer %llu fallback execution failed",
                                    static_cast<unsigned long long>(executingId));
                            }
                        }
                    }
                    else if (sharedCb && *sharedCb) {
                        // No thread pool available — execute directly
                        SS_LOG_WARN(L"TimerManager", 
                            L"No thread pool, executing timer %llu directly",
                            static_cast<unsigned long long>(executingId));
                        try {
                            (*sharedCb)();
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