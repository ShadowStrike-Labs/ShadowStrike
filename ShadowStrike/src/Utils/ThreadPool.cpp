#include "ThreadPool.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>
#include <iomanip>

// Platform-specific headers for thread control
#ifdef _WIN32
    #include <windows.h>
    #include <processthreadsapi.h>
#elif defined(__linux__)
    #include <pthread.h>
    #include <sched.h>
    #include <unistd.h>
#endif

namespace ShadowStrike::Utils {

    // ============================================================================
    // Internal Helper Functions - Production Logging & Platform Control
    // ============================================================================

    namespace {
        /**
         * @brief Sets thread name for debugging (platform-specific)
         */
        void set_thread_name(const std::string& name) {
#ifdef _WIN32
            std::wstring wide_name(name.begin(), name.end());
            SetThreadDescription(GetCurrentThread(), wide_name.c_str());
#elif defined(__linux__)
            pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
#endif
        }

        /**
         * @brief Gets CPU core count with fallback
         */
        size_t get_cpu_core_count() {
            size_t count = std::thread::hardware_concurrency();
            return (count > 0) ? count : 4;
        }

        /**
         * @brief Thread-safe logging (replace with your logging framework)
         */
        void log_message(const std::string& level, const std::string& message) {
            std::ostringstream oss;
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            oss << "[" << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") << "] "
                << "[" << level << "] [ThreadPool] " << message << std::endl;
            std::cout << oss.str();
        }
    }

    // ============================================================================
    // Constructor & Destructor
    // ============================================================================

    ThreadPool::ThreadPool(size_t num_threads, bool enable_monitoring)
        : monitoring_enabled_(enable_monitoring)
    {
        const size_t thread_count = (num_threads == 0) ? get_cpu_core_count() : num_threads;
        
        if (thread_count == 0) {
            throw std::invalid_argument("Failed to determine hardware concurrency");
        }

        const size_t max_threads = 256;
        if (thread_count > max_threads) {
            std::ostringstream oss;
            oss << "Thread count (" << thread_count << ") exceeds max (" << max_threads << ")";
            throw std::invalid_argument(oss.str());
        }

        log_message("INFO", "Init ThreadPool: " + std::to_string(thread_count) + " threads");

        workers_.reserve(thread_count);
        thread_active_.reserve(thread_count);

        for (size_t i = 0; i < thread_count; ++i) {
            thread_active_.emplace_back(false);
        }

        try {
            for (size_t i = 0; i < thread_count; ++i) {
                workers_.emplace_back(&ThreadPool::worker_thread, this, i);
            }
            log_message("INFO", "ThreadPool initialized successfully");
        }
        catch (const std::system_error& e) {
            log_message("ERROR", std::string("Thread creation failed: ") + e.what());
            shutdown_flag_.store(true, std::memory_order_release);
            queue_condition_.notify_all();
            for (auto& w : workers_) {
                if (w.joinable()) w.join();
            }
            throw std::runtime_error(std::string("Worker thread creation failed: ") + e.what());
        }
    }

    ThreadPool::~ThreadPool() {
        log_message("INFO", "Destroying ThreadPool");
        try {
            shutdown(true);
        }
        catch (const std::exception& e) {
            log_message("ERROR", std::string("Destruction error: ") + e.what());
        }
        catch (...) {
            log_message("ERROR", "Unknown destruction error");
        }
        log_message("INFO", "ThreadPool destroyed");
    }

    // ============================================================================
    // Move Semantics
    // ============================================================================

    ThreadPool::ThreadPool(ThreadPool&& other) noexcept
        : workers_(std::move(other.workers_))
        , thread_active_(std::move(other.thread_active_))
        , task_queue_(std::move(other.task_queue_))
        , monitoring_enabled_(other.monitoring_enabled_)
    {
        shutdown_flag_.store(other.shutdown_flag_.load(std::memory_order_acquire), std::memory_order_release);
        shutdown_now_flag_.store(other.shutdown_now_flag_.load(std::memory_order_acquire), std::memory_order_release);
        paused_flag_.store(other.paused_flag_.load(std::memory_order_acquire), std::memory_order_release);
        next_submission_id_.store(other.next_submission_id_.load(std::memory_order_acquire), std::memory_order_release);
        active_thread_count_.store(other.active_thread_count_.load(std::memory_order_acquire), std::memory_order_release);
        completed_task_count_.store(other.completed_task_count_.load(std::memory_order_acquire), std::memory_order_release);
        failed_task_count_.store(other.failed_task_count_.load(std::memory_order_acquire), std::memory_order_release);
        peak_queue_size_.store(other.peak_queue_size_.load(std::memory_order_acquire), std::memory_order_release);
        total_task_duration_us_.store(other.total_task_duration_us_.load(std::memory_order_acquire), std::memory_order_release);
        other.shutdown_flag_.store(true, std::memory_order_release);
        log_message("INFO", "Move constructor");
    }

    ThreadPool& ThreadPool::operator=(ThreadPool&& other) noexcept {
        if (this != &other) {
            log_message("INFO", "Move assignment");
            try {
                shutdown(true);
            }
            catch (...) {
                log_message("ERROR", "Move assignment shutdown error");
            }
            workers_ = std::move(other.workers_);
            thread_active_ = std::move(other.thread_active_);
            task_queue_ = std::move(other.task_queue_);
            monitoring_enabled_ = other.monitoring_enabled_;
            shutdown_flag_.store(other.shutdown_flag_.load(std::memory_order_acquire), std::memory_order_release);
            shutdown_now_flag_.store(other.shutdown_now_flag_.load(std::memory_order_acquire), std::memory_order_release);
            paused_flag_.store(other.paused_flag_.load(std::memory_order_acquire), std::memory_order_release);
            next_submission_id_.store(other.next_submission_id_.load(std::memory_order_acquire), std::memory_order_release);
            active_thread_count_.store(other.active_thread_count_.load(std::memory_order_acquire), std::memory_order_release);
            completed_task_count_.store(other.completed_task_count_.load(std::memory_order_acquire), std::memory_order_release);
            failed_task_count_.store(other.failed_task_count_.load(std::memory_order_acquire), std::memory_order_release);
            peak_queue_size_.store(other.peak_queue_size_.load(std::memory_order_acquire), std::memory_order_release);
            total_task_duration_us_.store(other.total_task_duration_us_.load(std::memory_order_acquire), std::memory_order_release);
            other.shutdown_flag_.store(true, std::memory_order_release);
        }
        return *this;
    }

    // ============================================================================
    // Lifecycle Management
    // ============================================================================

    void ThreadPool::shutdown(bool wait_for_tasks) {
        log_message("INFO", std::string("Shutdown (wait=") + (wait_for_tasks ? "true" : "false") + ")");
        
        bool expected = false;
        if (!shutdown_flag_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            log_message("WARN", "Already shutting down");
            return;
        }

        if (wait_for_tasks) {
            log_message("INFO", "Waiting for task completion...");
            const bool ok = this->wait_for_completion(std::nullopt);
            log_message("INFO", ok ? "Tasks completed" : "Wait interrupted");
        }

        queue_condition_.notify_all();
        log_message("INFO", "Joining threads...");
        
        size_t joined = 0;
        for (auto& w : workers_) {
            if (w.joinable()) {
                try {
                    w.join();
                    ++joined;
                }
                catch (const std::exception& e) {
                    log_message("ERROR", std::string("Join error: ") + e.what());
                }
            }
        }

        log_message("INFO", "Joined " + std::to_string(joined) + " threads");
        workers_.clear();
        thread_active_.clear();
        log_message("INFO", "Shutdown complete");
    }

    void ThreadPool::shutdown_now() {
        log_message("WARN", "Immediate shutdown - discarding tasks");
        
        shutdown_flag_.store(true, std::memory_order_release);
        shutdown_now_flag_.store(true, std::memory_order_release);

        size_t discarded = 0;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            while (!task_queue_.empty()) {
                task_queue_.pop();
                ++discarded;
            }
        }

        log_message("WARN", "Discarded " + std::to_string(discarded) + " tasks");
        queue_condition_.notify_all();

        size_t joined = 0;
        for (auto& w : workers_) {
            if (w.joinable()) {
                try {
                    w.join();
                    ++joined;
                }
                catch (const std::exception& e) {
                    log_message("ERROR", std::string("Join error: ") + e.what());
                }
            }
        }

        log_message("INFO", "Force-joined " + std::to_string(joined) + " threads");
        workers_.clear();
        thread_active_.clear();
    }

    bool ThreadPool::wait_for_completion(std::optional<std::chrono::milliseconds> timeout) {
        if (timeout.has_value()) {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            const bool ok = completion_condition_.wait_for(lock, timeout.value(), [this] {
                return task_queue_.empty() && active_thread_count_.load(std::memory_order_acquire) == 0;
            });
            if (!ok) {
                log_message("WARN", "Timeout after " + std::to_string(timeout.value().count()) + "ms");
            }
            return ok;
        }
        
        std::unique_lock<std::mutex> lock(queue_mutex_);
        completion_condition_.wait(lock, [this] {
            return task_queue_.empty() && active_thread_count_.load(std::memory_order_acquire) == 0;
        });
        return true;
    }

    // ============================================================================
    // Query Methods
    // ============================================================================

    bool ThreadPool::is_shutdown() const noexcept {
        return shutdown_flag_.load(std::memory_order_acquire);
    }

    size_t ThreadPool::get_thread_count() const noexcept {
        return workers_.size();
    }

    size_t ThreadPool::get_queue_size() const noexcept {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return task_queue_.size();
    }

    size_t ThreadPool::get_active_thread_count() const noexcept {
        return active_thread_count_.load(std::memory_order_acquire);
    }

    bool ThreadPool::is_paused() const noexcept {
        return paused_flag_.load(std::memory_order_acquire);
    }

    // ============================================================================
    // Statistics
    // ============================================================================

    ThreadPoolStatistics ThreadPool::get_statistics() const {
        if (!monitoring_enabled_) {
            throw std::runtime_error("Monitoring not enabled");
        }

        std::lock_guard<std::mutex> lock(stats_mutex_);
        ThreadPoolStatistics stats{};
        
        stats.active_threads = active_thread_count_.load(std::memory_order_acquire);
        stats.total_threads = workers_.size();
        stats.idle_threads = stats.total_threads - stats.active_threads;

        {
            std::lock_guard<std::mutex> qlock(queue_mutex_);
            stats.queued_tasks = task_queue_.size();
        }

        stats.completed_tasks = completed_task_count_.load(std::memory_order_acquire);
        stats.failed_tasks = failed_task_count_.load(std::memory_order_acquire);
        stats.peak_queue_size = peak_queue_size_.load(std::memory_order_acquire);

        const uint64_t total_us = total_task_duration_us_.load(std::memory_order_acquire);
        const uint64_t completed = stats.completed_tasks;
        
        stats.avg_task_duration = (completed > 0) 
            ? std::chrono::milliseconds(total_us / completed / 1000)
            : std::chrono::milliseconds(0);

        stats.thread_utilization = (stats.total_threads > 0)
            ? static_cast<double>(stats.active_threads) / static_cast<double>(stats.total_threads)
            : 0.0;

        return stats;
    }

    void ThreadPool::reset_statistics() noexcept {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        completed_task_count_.store(0, std::memory_order_release);
        failed_task_count_.store(0, std::memory_order_release);
        peak_queue_size_.store(0, std::memory_order_release);
        total_task_duration_us_.store(0, std::memory_order_release);
        log_message("INFO", "Statistics reset");
    }

    // ============================================================================
    // Dynamic Management
    // ============================================================================

    void ThreadPool::resize(size_t new_count) {
        if (new_count == 0) {
            throw std::invalid_argument("Thread count must be > 0");
        }

        const size_t current = workers_.size();
        if (new_count == current) return;

        log_message("INFO", "Resize: " + std::to_string(current) + " -> " + std::to_string(new_count));
        std::lock_guard<std::mutex> lock(queue_mutex_);

        if (new_count > current) {
            try {
                for (size_t i = 0; i < (new_count - current); ++i) {
                    const size_t idx = workers_.size();
                    thread_active_.emplace_back(false);
                    workers_.emplace_back(&ThreadPool::worker_thread, this, idx);
                }
                log_message("INFO", "Added " + std::to_string(new_count - current) + " threads");
            }
            catch (const std::exception& e) {
                log_message("ERROR", std::string("Resize failed: ") + e.what());
                throw;
            }
        } else {
            log_message("WARN", "Thread reduction not fully implemented");
        }
    }

    void ThreadPool::pause() {
        const bool was_paused = paused_flag_.exchange(true, std::memory_order_acq_rel);
        if (!was_paused) {
            log_message("INFO", "Paused");
        }
    }

    void ThreadPool::unpause() {
        const bool was_paused = paused_flag_.exchange(false, std::memory_order_acq_rel);
        if (was_paused) {
            queue_condition_.notify_all();
            log_message("INFO", "Unpaused");
        }
    }

    size_t ThreadPool::clear_queue() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        size_t cleared = 0;
        while (!task_queue_.empty()) {
            task_queue_.pop();
            ++cleared;
        }
        log_message("INFO", "Cleared " + std::to_string(cleared) + " tasks");
        return cleared;
    }

    // ============================================================================
    // Worker Thread Implementation
    // ============================================================================

    void ThreadPool::worker_thread(size_t thread_index) {
        std::ostringstream name;
        name << "ShadowStrike-Worker-" << thread_index;
        set_thread_name(name.str());
        log_message("DEBUG", "Worker-" + std::to_string(thread_index) + " started");

        while (true) {
            std::optional<Task> task_opt = try_dequeue_task();

            if (!task_opt.has_value()) {
                if (shutdown_flag_.load(std::memory_order_acquire)) {
                    break;
                }
                continue;
            }

            while (paused_flag_.load(std::memory_order_acquire)) {
                std::this_thread::yield();
                if (shutdown_flag_.load(std::memory_order_acquire)) {
                    log_message("DEBUG", "Worker-" + std::to_string(thread_index) + " exit during pause");
                    return;
                }
            }

            thread_active_[thread_index].store(true, std::memory_order_release);
            active_thread_count_.fetch_add(1, std::memory_order_acq_rel);

            const auto start = std::chrono::steady_clock::now();
            bool success = true;

            try {
                task_opt->func();
            }
            catch (const std::exception& e) {
                success = false;
                log_message("ERROR", std::string("Task failed: ") + e.what());
                handle_task_exception(std::current_exception());
            }
            catch (...) {
                success = false;
                log_message("ERROR", "Task failed: unknown exception");
                handle_task_exception(std::current_exception());
            }

            const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start
            );

            if (monitoring_enabled_) {
                update_statistics(duration, success);
            }

            thread_active_[thread_index].store(false, std::memory_order_release);
            active_thread_count_.fetch_sub(1, std::memory_order_acq_rel);
            completion_condition_.notify_all();
        }

        log_message("DEBUG", "Worker-" + std::to_string(thread_index) + " exiting");
    }

    void ThreadPool::enqueue_task(Task&& task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);

            if (shutdown_flag_.load(std::memory_order_acquire)) {
                throw ThreadPoolShutdownException("Cannot enqueue: shutting down");
            }

            task_queue_.push(std::move(task));

            const size_t sz = task_queue_.size();
            size_t peak = peak_queue_size_.load(std::memory_order_acquire);
            
            while (sz > peak && !peak_queue_size_.compare_exchange_weak(
                peak, sz, std::memory_order_acq_rel, std::memory_order_acquire)) {
            }
        }

        queue_condition_.notify_one();
    }

    std::optional<ThreadPool::Task> ThreadPool::try_dequeue_task() {
        std::unique_lock<std::mutex> lock(queue_mutex_);

        queue_condition_.wait(lock, [this] {
            return !task_queue_.empty() || 
                   shutdown_flag_.load(std::memory_order_acquire) ||
                   shutdown_now_flag_.load(std::memory_order_acquire);
        });

        const bool shut = shutdown_flag_.load(std::memory_order_acquire);
        const bool shut_now = shutdown_now_flag_.load(std::memory_order_acquire);

        if (shut || shut_now) {
            if (task_queue_.empty()) return std::nullopt;
            if (shut_now) return std::nullopt;
        }

        if (task_queue_.empty()) return std::nullopt;

        Task task = std::move(const_cast<Task&>(task_queue_.top()));
        task_queue_.pop();
        return task;
    }

    void ThreadPool::update_statistics(std::chrono::microseconds duration, bool success) {
        if (success) {
            completed_task_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            failed_task_count_.fetch_add(1, std::memory_order_relaxed);
        }

        total_task_duration_us_.fetch_add(
            static_cast<uint64_t>(duration.count()),
            std::memory_order_relaxed
        );
    }

    void ThreadPool::handle_task_exception(std::exception_ptr eptr) noexcept {
        try {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        }
        catch (const std::exception& e) {
            log_message("ERROR", std::string("Exception: ") + e.what());
            try {
                log_message("DEBUG", std::string("Type: ") + typeid(e).name());
            }
            catch (...) {
            }
        }
        catch (...) {
            log_message("ERROR", "Unknown exception type");
        }
    }

} // namespace ShadowStrike::Utils
