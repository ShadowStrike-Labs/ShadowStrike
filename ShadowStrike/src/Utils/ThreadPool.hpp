#pragma once

#include <atomic>
#include <condition_variable>
#include <concepts>
#include <coroutine>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>
#include <string>
#include <chrono>
#include <optional>

namespace ShadowStrike::Utils {

    /**
     * @brief Task priority levels for scheduling in the thread pool
     * 
     * Higher values indicate higher priority. Critical tasks are executed before
     * high priority tasks, which are executed before normal priority tasks, etc.
     */
    enum class TaskPriority : uint8_t {
        CRITICAL = 4,  // For critical security operations (e.g., threat detection)
        HIGH = 3,      // For high-priority operations (e.g., real-time scanning)
        NORMAL = 2,    // For normal operations (e.g., scheduled scans)
        LOW = 1,       // For low-priority background operations
        IDLE = 0       // For idle-time operations (e.g., cleanup, optimization)
    };

    /**
     * @brief Exception thrown when a task fails to execute
     */
    class TaskExecutionException : public std::runtime_error {
    public:
        explicit TaskExecutionException(const std::string& message)
            : std::runtime_error(message) {}
    };

    /**
     * @brief Exception thrown when attempting operations on a shutdown thread pool
     */
    class ThreadPoolShutdownException : public std::runtime_error {
    public:
        explicit ThreadPoolShutdownException(const std::string& message)
            : std::runtime_error(message) {}
    };

    /**
     * @brief Statistics about thread pool performance and state
     */
    struct ThreadPoolStatistics {
        size_t active_threads;           // Currently active worker threads
        size_t idle_threads;             // Currently idle worker threads
        size_t total_threads;            // Total number of threads in pool
        size_t queued_tasks;             // Number of tasks waiting in queue
        size_t completed_tasks;          // Total number of completed tasks
        size_t failed_tasks;             // Total number of failed tasks
        size_t peak_queue_size;          // Maximum queue size reached
        std::chrono::milliseconds avg_task_duration;  // Average task execution time
        double thread_utilization;       // Thread utilization percentage (0.0-1.0)
    };

    /**
     * @brief C++20 concept for callable types that can be used as tasks
     */
    template<typename F, typename... Args>
    concept Callable = std::invocable<F, Args...>;

    /**
     * @brief Production-grade, thread-safe thread pool implementation
     * 
     * This thread pool is designed for enterprise-level security applications with:
     * - Thread-safe task submission and execution
     * - Priority-based task scheduling
     * - Graceful shutdown with pending task handling
     * - Exception handling and error recovery
     * - Performance monitoring and statistics
     * - Memory-safe operations using smart pointers
     * - C++20 features (concepts, coroutines support)
     * 
     * @note This class is thread-safe and can be safely used from multiple threads
     */
    class ThreadPool {
    public:
        /**
         * @brief Constructs a thread pool with specified number of worker threads
         * 
         * @param num_threads Number of worker threads to create. If 0, uses hardware concurrency
         * @param enable_monitoring Enable performance monitoring and statistics collection
         * 
         * @throws std::invalid_argument if num_threads is negative
         */
        explicit ThreadPool(size_t num_threads = 0, bool enable_monitoring = true);

        /**
         * @brief Destructor - ensures graceful shutdown of all threads
         * 
         * Waits for all queued tasks to complete before destroying the pool
         */
        ~ThreadPool();

        // Disable copy operations to prevent resource management issues
        ThreadPool(const ThreadPool&) = delete;
        ThreadPool& operator=(const ThreadPool&) = delete;

        // Enable move operations for efficient resource transfer
        ThreadPool(ThreadPool&& other) noexcept;
        ThreadPool& operator=(ThreadPool&& other) noexcept;

        /**
         * @brief Submits a task with normal priority to the thread pool
         * 
         * @tparam F Callable type (function, lambda, functor)
         * @tparam Args Argument types for the callable
         * @param func The function to execute
         * @param args Arguments to pass to the function
         * @return std::future<ReturnType> Future object to retrieve the result
         * 
         * @throws ThreadPoolShutdownException if the pool is shutting down
         * 
         * @example
         * auto future = pool.submit([]{ return 42; });
         * int result = future.get();
         */
        template<Callable F, typename... Args>
        auto submit(F&& func, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;

        /**
         * @brief Submits a task with specified priority to the thread pool
         * 
         * @tparam F Callable type (function, lambda, functor)
         * @tparam Args Argument types for the callable
         * @param priority Priority level for the task
         * @param func The function to execute
         * @param args Arguments to pass to the function
         * @return std::future<ReturnType> Future object to retrieve the result
         * 
         * @throws ThreadPoolShutdownException if the pool is shutting down
         * 
         * @example
         * auto future = pool.submit_priority(TaskPriority::HIGH, [](int x) { return x * 2; }, 21);
         * int result = future.get(); // result = 42
         */
        template<Callable F, typename... Args>
        auto submit_priority(TaskPriority priority, F&& func, Args&&... args) 
            -> std::future<std::invoke_result_t<F, Args...>>;

        /**
         * @brief Submits multiple tasks with the same priority
         * 
         * @tparam Container Container type holding callables
         * @param priority Priority level for all tasks
         * @param tasks Container of tasks to submit
         * @return std::vector<std::future<void>> Futures for all submitted tasks
         */
        template<typename Container>
        auto submit_bulk(TaskPriority priority, Container&& tasks) 
            -> std::vector<std::future<void>>;

        /**
         * @brief Submits a task that will be executed after a specified delay
         * 
         * @tparam F Callable type
         * @tparam Args Argument types
         * @param delay Duration to wait before executing the task
         * @param func The function to execute
         * @param args Arguments to pass to the function
         * @return std::future<ReturnType> Future object to retrieve the result
         */
        template<Callable F, typename... Args>
        auto submit_delayed(std::chrono::milliseconds delay, F&& func, Args&&... args)
            -> std::future<std::invoke_result_t<F, Args...>>;

        /**
         * @brief Initiates graceful shutdown of the thread pool
         * 
         * Prevents new task submissions and allows queued tasks to complete
         * 
         * @param wait_for_completion If true, blocks until all tasks are completed
         */
        void shutdown(bool wait_for_completion = true);

        /**
         * @brief Initiates immediate shutdown of the thread pool
         * 
         * Cancels pending tasks and stops worker threads as soon as possible
         */
        void shutdown_now();

        /**
         * @brief Waits for all queued tasks to complete
         * 
         * @param timeout Maximum time to wait. If nullopt, waits indefinitely
         * @return true if all tasks completed within timeout, false otherwise
         */
        bool wait_for_completion(std::optional<std::chrono::milliseconds> timeout = std::nullopt);

        /**
         * @brief Checks if the thread pool is currently shutting down
         * 
         * @return true if shutdown has been initiated, false otherwise
         */
        [[nodiscard]] bool is_shutdown() const noexcept;

        /**
         * @brief Gets the number of worker threads in the pool
         * 
         * @return Number of worker threads
         */
        [[nodiscard]] size_t get_thread_count() const noexcept;

        /**
         * @brief Gets the current number of queued tasks
         * 
         * @return Number of tasks waiting to be executed
         */
        [[nodiscard]] size_t get_queue_size() const noexcept;

        /**
         * @brief Gets the number of currently active (running) threads
         * 
         * @return Number of threads currently executing tasks
         */
        [[nodiscard]] size_t get_active_thread_count() const noexcept;

        /**
         * @brief Gets comprehensive statistics about thread pool performance
         * 
         * @return ThreadPoolStatistics struct containing performance metrics
         * @throws std::runtime_error if monitoring is not enabled
         */
        [[nodiscard]] ThreadPoolStatistics get_statistics() const;

        /**
         * @brief Resets all statistics counters to zero
         */
        void reset_statistics() noexcept;

        /**
         * @brief Dynamically adjusts the number of worker threads
         * 
         * @param new_thread_count Desired number of threads
         * @note Excess threads will finish their current task before terminating
         */
        void resize(size_t new_thread_count);

        /**
         * @brief Pauses all task execution without shutting down
         * 
         * @note Tasks remain in the queue and will resume when unpause() is called
         */
        void pause();

        /**
         * @brief Resumes task execution after pause()
         */
        void unpause();

        /**
         * @brief Checks if the thread pool is currently paused
         * 
         * @return true if paused, false otherwise
         */
        [[nodiscard]] bool is_paused() const noexcept;

        /**
         * @brief Clears all pending tasks from the queue
         * 
         * @return Number of tasks that were removed
         * @note Only removes tasks that haven't started executing yet
         */
        size_t clear_queue();

    private:
        /**
         * @brief Internal task wrapper that includes priority and metadata
         */
        struct Task {
            std::function<void()> func;
            TaskPriority priority;
            uint64_t submission_id;  // For FIFO ordering within same priority
            std::chrono::steady_clock::time_point submission_time;

            // Comparison operator for priority queue (higher priority first)
            bool operator<(const Task& other) const {
                if (priority != other.priority) {
                    return priority < other.priority;  // Lower enum value = lower priority
                }
                return submission_id > other.submission_id;  // FIFO for same priority
            }
        };

        /**
         * @brief Worker thread main function
         * 
         * Continuously fetches and executes tasks from the queue until shutdown
         * 
         * @param thread_index Index of this worker thread
         */
        void worker_thread(size_t thread_index);

        /**
         * @brief Safely adds a task to the priority queue
         * 
         * @param task Task to add
         * @throws ThreadPoolShutdownException if pool is shutting down
         */
        void enqueue_task(Task&& task);

        /**
         * @brief Attempts to fetch a task from the queue
         * 
         * @return Optional task if available, nullopt if queue is empty or shutting down
         */
        std::optional<Task> try_dequeue_task();

        /**
         * @brief Updates performance statistics (thread-safe)
         * 
         * @param task_duration Duration of the completed task
         * @param success Whether the task completed successfully
         */
        void update_statistics(std::chrono::microseconds task_duration, bool success);

        /**
         * @brief Exception handler for task execution failures
         * 
         * @param exception_ptr Pointer to the caught exception
         */
        void handle_task_exception(std::exception_ptr exception_ptr) noexcept;

        // Thread management
        std::vector<std::thread> workers_;
        std::vector<std::atomic<bool>> thread_active_;  // Per-thread activity status

        // Task queue and synchronization
        std::priority_queue<Task> task_queue_;
        mutable std::mutex queue_mutex_;
        std::condition_variable queue_condition_;
        std::condition_variable completion_condition_;

        // State management
        std::atomic<bool> shutdown_flag_{false};
        std::atomic<bool> shutdown_now_flag_{false};
        std::atomic<bool> paused_flag_{false};
        std::atomic<uint64_t> next_submission_id_{0};
        std::atomic<size_t> active_thread_count_{0};

        // Statistics tracking
        bool monitoring_enabled_;
        mutable std::mutex stats_mutex_;
        std::atomic<uint64_t> completed_task_count_{0};
        std::atomic<uint64_t> failed_task_count_{0};
        std::atomic<size_t> peak_queue_size_{0};
        std::atomic<uint64_t> total_task_duration_us_{0};  // Microseconds
    };

    // ============================================================================
    // Template method implementations
    // ============================================================================

    template<Callable F, typename... Args>
    auto ThreadPool::submit(F&& func, Args&&... args) 
        -> std::future<std::invoke_result_t<F, Args...>> 
    {
        return submit_priority(TaskPriority::NORMAL, std::forward<F>(func), std::forward<Args>(args)...);
    }

    template<Callable F, typename... Args>
    auto ThreadPool::submit_priority(TaskPriority priority, F&& func, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>> 
    {
        using ReturnType = std::invoke_result_t<F, Args...>;

        // Check if pool is shutting down
        if (shutdown_flag_.load(std::memory_order_acquire)) {
            throw ThreadPoolShutdownException("Cannot submit task: thread pool is shutting down");
        }

        // Create a packaged task with bound arguments
        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            std::bind(std::forward<F>(func), std::forward<Args>(args)...)
        );

        // Get the future before moving the task
        std::future<ReturnType> result = task->get_future();

        // Create task wrapper with exception handling
        Task wrapped_task{
            [task]() {
                try {
                    (*task)();
                } catch (...) {
                    // The exception will be captured in the future
                    try {
                        (*task)();
                    } catch (...) {
                        // Second attempt to capture exception in future
                    }
                }
            },
            priority,
            next_submission_id_.fetch_add(1, std::memory_order_relaxed),
            std::chrono::steady_clock::now()
        };

        // Enqueue the task
        enqueue_task(std::move(wrapped_task));

        return result;
    }

    template<typename Container>
    auto ThreadPool::submit_bulk(TaskPriority priority, Container&& tasks)
        -> std::vector<std::future<void>> 
    {
        std::vector<std::future<void>> futures;
        futures.reserve(std::size(tasks));

        for (auto&& task : tasks) {
            futures.push_back(submit_priority(priority, std::forward<decltype(task)>(task)));
        }

        return futures;
    }

    template<Callable F, typename... Args>
    auto ThreadPool::submit_delayed(std::chrono::milliseconds delay, F&& func, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>> 
    {
        using ReturnType = std::invoke_result_t<F, Args...>;

        // Create a delayed task wrapper
        auto delayed_task = [
            delay, 
            func = std::forward<F>(func), 
            args_tuple = std::make_tuple(std::forward<Args>(args)...)
        ]() mutable -> ReturnType {
            std::this_thread::sleep_for(delay);
            return std::apply(std::move(func), std::move(args_tuple));
        };

        return submit(std::move(delayed_task));
    }

} // namespace ShadowStrike::Utils
