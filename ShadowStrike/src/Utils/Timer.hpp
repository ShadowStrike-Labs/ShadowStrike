/**
 * @file Timer.hpp
 * @brief Enterprise-grade timer management system for ShadowStrike.
 * 
 * Provides a singleton TimerManager class that schedules and executes
 * one-shot and periodic timer tasks using a ThreadPool for execution.
 * 
 * Features:
 * - Thread-safe timer scheduling and cancellation
 * - Periodic and one-shot timer support
 * - Integration with ThreadPool for efficient task execution
 * - Robust cancellation with race condition protection
 * - Clock drift and skew detection
 * 
 * @author ShadowStrike Security Team
 * @copyright (c) 2025 ShadowStrike. All rights reserved.
 */

#pragma once

#include <functional>
#include <chrono>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <queue>
#include <unordered_map>
#include <optional>
#include <cstdint>

#include "ThreadPool.hpp"


namespace ShadowStrike {

    namespace Utils {

        /// Unique identifier for timer tasks (64-bit for large-scale usage)
        using TimerId = uint64_t;

        /// Invalid timer ID constant
        inline constexpr TimerId kInvalidTimerId = 0;

        // ============================================================================
        // TimerManager Configuration
        // ============================================================================

        /**
         * @brief Configuration options for TimerManager.
         */
        struct TimerManagerConfig {
            /// Maximum wait time for any single timer (prevents indefinite blocking)
            std::chrono::milliseconds maxWaitTime{ std::chrono::minutes(5) };
            
            /// Maximum allowed clock drift before adjustment
            std::chrono::seconds maxClockDrift{ 60 };
            
            /// Enable detailed debug logging
            bool enableDebugLogging = false;
            
            /// Maximum number of active timers allowed
            size_t maxActiveTimers = 100000;
        };

        // ============================================================================
        // TimerManager Class
        // ============================================================================

        /**
         * @brief Singleton timer management system.
         * 
         * TimerManager provides a centralized facility for scheduling and
         * executing timer-based tasks. It uses the ThreadPool for efficient
         * callback execution and provides robust cancellation support.
         * 
         * Thread Safety: All public methods are thread-safe.
         * 
         * Usage:
         * @code
         * auto& timer = TimerManager::Instance();
         * timer.Initialize(threadPool);
         * 
         * // One-shot timer
         * auto id1 = timer.runOnce(std::chrono::seconds(5), []() {
         *     // Called after 5 seconds
         * });
         * 
         * // Periodic timer
         * auto id2 = timer.runPeriodic(std::chrono::seconds(1), []() {
         *     // Called every second
         * });
         * 
         * // Cancel timer
         * timer.cancel(id1);
         * 
         * timer.Shutdown();
         * @endcode
         */
        class TimerManager {
        public:
            // ========================================================================
            // Singleton Access
            // ========================================================================

            /**
             * @brief Gets the singleton instance of TimerManager.
             * @return Reference to the singleton instance.
             * @note Thread-safe (uses Meyers' singleton pattern).
             */
            [[nodiscard]] static TimerManager& Instance();

            // Prevent copy and move
            TimerManager(const TimerManager&) = delete;
            TimerManager& operator=(const TimerManager&) = delete;
            TimerManager(TimerManager&&) = delete;
            TimerManager& operator=(TimerManager&&) = delete;

            // ========================================================================
            // Lifecycle Management
            // ========================================================================

            /**
             * @brief Initializes the TimerManager with a ThreadPool.
             * @param pool Shared pointer to the ThreadPool for task execution.
             * @throws std::invalid_argument if pool is null.
             * @note Must be called before any timer operations.
             * @note Safe to call multiple times (subsequent calls are no-ops).
             */
            void Initialize(std::shared_ptr<ThreadPool> pool);

            /**
             * @brief Initializes the TimerManager with custom configuration.
             * @param pool Shared pointer to the ThreadPool for task execution.
             * @param config Configuration options for the timer manager.
             * @throws std::invalid_argument if pool is null.
             */
            void Initialize(std::shared_ptr<ThreadPool> pool, const TimerManagerConfig& config);

            /**
             * @brief Shuts down the TimerManager.
             * 
             * Cancels all pending timers and stops the manager thread.
             * Blocks until all resources are released.
             * 
             * @note Safe to call multiple times.
             * @note Automatically called in destructor if not explicitly called.
             */
            void Shutdown() noexcept;

            /**
             * @brief Checks if the TimerManager is initialized and running.
             * @return true if initialized and not shutdown.
             */
            [[nodiscard]] bool IsRunning() const noexcept;

            // ========================================================================
            // Timer Scheduling
            // ========================================================================

            /**
             * @brief Schedules a one-shot timer.
             * @tparam F Callable type.
             * @tparam Args Argument types for the callable.
             * @param delay Time delay before execution.
             * @param f Callable to execute.
             * @param args Arguments to pass to the callable.
             * @return Timer ID for cancellation, or kInvalidTimerId on failure.
             */
            template<typename F, typename... Args>
            [[nodiscard]] TimerId runOnce(std::chrono::milliseconds delay, F&& f, Args&&... args);

            /**
             * @brief Schedules a periodic timer.
             * @tparam F Callable type.
             * @tparam Args Argument types for the callable.
             * @param interval Interval between executions.
             * @param f Callable to execute.
             * @param args Arguments to pass to the callable.
             * @return Timer ID for cancellation, or kInvalidTimerId on failure.
             */
            template<typename F, typename... Args>
            [[nodiscard]] TimerId runPeriodic(std::chrono::milliseconds interval, F&& f, Args&&... args);

            /**
             * @brief Cancels a scheduled timer.
             * @param id Timer ID to cancel.
             * @return true if the timer was found and cancelled, false otherwise.
             */
            bool cancel(TimerId id) noexcept;

            // ========================================================================
            // Statistics
            // ========================================================================

            /**
             * @brief Gets the number of active (pending) timers.
             * @return Number of active timers.
             */
            [[nodiscard]] size_t GetActiveTimerCount() const noexcept;

            /**
             * @brief Gets the total number of timers executed since initialization.
             * @return Total executed timer count.
             */
            [[nodiscard]] uint64_t GetTotalExecutedCount() const noexcept;

        private:
            // ========================================================================
            // Private Constructor/Destructor (Singleton)
            // ========================================================================

            TimerManager() = default;
            ~TimerManager() noexcept;

            // ========================================================================
            // Internal Data Structures
            // ========================================================================

            /**
             * @brief Internal representation of a scheduled timer task.
             */
            struct TimerTask {
                TimerId id = kInvalidTimerId;
                std::chrono::steady_clock::time_point nextExecutionTime{};
                std::chrono::milliseconds interval{ 0 };
                bool isPeriodic = false;
                std::function<void()> callback;

                /// Min-heap comparison (earliest time first)
                [[nodiscard]] bool operator>(const TimerTask& other) const noexcept {
                    return nextExecutionTime > other.nextExecutionTime;
                }
            };

            /**
             * @brief Metadata for tracking active timers.
             * 
             * Provides thread-safe cancellation tracking without modifying
             * the priority queue directly.
             */
            struct TimerMetadata {
                TimerId id = kInvalidTimerId;
                bool isPeriodic = false;
                std::atomic<bool> isCancelled{ false };
                std::chrono::steady_clock::time_point creationTime{};

                /// Default constructor
                TimerMetadata() noexcept = default;

                /// Parameterized constructor
                TimerMetadata(TimerId id_, bool periodic_, bool cancelled_ = false) noexcept
                    : id(id_)
                    , isPeriodic(periodic_)
                    , isCancelled(cancelled_)
                    , creationTime(std::chrono::steady_clock::now())
                {}

                // Non-copyable (due to atomic member)
                TimerMetadata(const TimerMetadata&) = delete;
                TimerMetadata& operator=(const TimerMetadata&) = delete;

                // Moveable
                TimerMetadata(TimerMetadata&& other) noexcept
                    : id(other.id)
                    , isPeriodic(other.isPeriodic)
                    , isCancelled(other.isCancelled.load(std::memory_order_acquire))
                    , creationTime(other.creationTime)
                {}

                TimerMetadata& operator=(TimerMetadata&& other) noexcept {
                    if (this != &other) {
                        id = other.id;
                        isPeriodic = other.isPeriodic;
                        isCancelled.store(other.isCancelled.load(std::memory_order_acquire), 
                                         std::memory_order_release);
                        creationTime = other.creationTime;
                    }
                    return *this;
                }
            };

            // ========================================================================
            // Internal Methods
            // ========================================================================

            /// Main manager thread loop
            void managerThread() noexcept;

            /// Adds a new timer to the queue
            [[nodiscard]] TimerId addTimer(
                std::chrono::milliseconds delay, 
                std::chrono::milliseconds interval, 
                bool periodic, 
                std::function<void()>&& callback
            ) noexcept;

            /// Checks if a timer is cancelled
            [[nodiscard]] bool isTimerCancelled(TimerId id) const noexcept;

            /// Removes cancelled timers from active map
            void cleanupCancelledTimers() noexcept;

            // ========================================================================
            // Member Variables
            // ========================================================================

            /// Shutdown flag (atomic for lock-free check)
            std::atomic<bool> m_shutdown{ false };

            /// Initialization flag
            std::atomic<bool> m_initialized{ false };

            /// Manager thread
            std::thread m_managerThread;

            /// Thread pool for task execution
            std::shared_ptr<ThreadPool> m_threadPool;

            /// Configuration
            TimerManagerConfig m_config;

            /// Priority queue of timer tasks (min-heap by execution time)
            std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> m_taskQueue;

            /// Active timer metadata for cancellation tracking
            std::unordered_map<TimerId, TimerMetadata> m_activeTimers;

            /// Mutex for thread-safe access to queue and map
            mutable std::mutex m_mutex;

            /// Condition variable for manager thread wake-up
            std::condition_variable m_cv;

            /// Next timer ID (atomic for lock-free generation)
            std::atomic<TimerId> m_nextTimerId{ 1 };

            /// Statistics: total executed timers
            std::atomic<uint64_t> m_totalExecuted{ 0 };
        };

        // ============================================================================
        // Template Implementations
        // ============================================================================

        template<typename F, typename... Args>
        TimerId TimerManager::runOnce(std::chrono::milliseconds delay, F&& f, Args&&... args) {
            // Validate delay
            if (delay.count() < 0) {
                return kInvalidTimerId;
            }

            // Check if shutdown
            if (m_shutdown.load(std::memory_order_acquire)) {
                return kInvalidTimerId;
            }

            // Bind arguments to create a void() callable
            try {
                auto boundTask = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
                return addTimer(delay, std::chrono::milliseconds{ 0 }, false, 
                               std::function<void()>(std::move(boundTask)));
            }
            catch (const std::bad_alloc&) {
                return kInvalidTimerId;
            }
            catch (...) {
                return kInvalidTimerId;
            }
        }

        template<typename F, typename... Args>
        TimerId TimerManager::runPeriodic(std::chrono::milliseconds interval, F&& f, Args&&... args) {
            // Validate interval (must be positive)
            if (interval.count() <= 0) {
                return kInvalidTimerId;
            }

            // Check if shutdown
            if (m_shutdown.load(std::memory_order_acquire)) {
                return kInvalidTimerId;
            }

            // Bind arguments to create a void() callable
            try {
                auto boundTask = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
                return addTimer(interval, interval, true, 
                               std::function<void()>(std::move(boundTask)));
            }
            catch (const std::bad_alloc&) {
                return kInvalidTimerId;
            }
            catch (...) {
                return kInvalidTimerId;
            }
        }

    }// namespace Utils

}// namespace ShadowStrike