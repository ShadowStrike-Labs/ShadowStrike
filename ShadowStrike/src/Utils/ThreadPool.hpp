#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>
#include <unordered_map>
#include <threadpoolapiset.h>
#ifdef _WIN32
#define NOMINMAX
#endif // _WIN32

#include <Windows.h>
#include <evntprov.h>
#include <cstdarg>
#include <chrono>

namespace ShadowStrike {
    namespace Utils {

        // Task priority levels
        enum class TaskPriority : uint8_t {
            Critical = 0,
            High = 1,
            Normal = 2,
            Low = 3,
            Background = 4
        };

        struct ThreadPoolStatistics {
            size_t threadCount = 0;
            size_t activeThreads = 0;
            size_t pendingHighPriorityTasks = 0;
            size_t pendingNormalTasks = 0;
            size_t pendingLowPriorityTasks = 0;
            size_t totalTasksProcessed = 0;
            size_t peakQueueSize = 0;
            double avgExecutionTimeMs = 0.0;
            uint64_t memoryUsage = 0;
        };

        using TaskId = uint64_t;
        using TaskGroupId = uint64_t;

        class ThreadPool {
        public:
            enum class CpuSubsystem {
                Default,
                Scanner,
                RealTime,
                NetworkMonitor,
                Maintenance
            };

            struct ThreadPoolConfig {
                size_t threadCount = 0;
                size_t maxQueueSize = 10000;
                size_t threadStackSize = 0;
                bool useWindowsThreadPool = false;
                bool setThreadPriority = true;
                int threadPriority = THREAD_PRIORITY_NORMAL;
                bool useDynamicThreadCount = false;
                size_t maxThreadCount = 0;
                bool bindToHardware = false;
                CpuSubsystem cpuSubsystem = CpuSubsystem::Default;
                std::wstring poolName = L"ShadowStrike_ThreadPool";
                bool enableProfiling = true;
                bool enableLogging = true;
                bool enableTaskCancellation = true;
                bool useBarrierScheduling = false;
            };

            explicit ThreadPool(const ThreadPoolConfig& config = ThreadPoolConfig());
            explicit ThreadPool(size_t threadCount, std::wstring poolName = L"ShadowStrike_ThreadPool");
            ~ThreadPool();

            // No copy or move
            ThreadPool(const ThreadPool&) = delete;
            ThreadPool& operator=(const ThreadPool&) = delete;
            ThreadPool(ThreadPool&&) = delete;
            ThreadPool& operator=(ThreadPool&&) = delete;

            // Standard task submission
            template <typename F, typename... Args>
            auto submit(F&& f, Args&&... args)
                -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;

            // Submit task with priority
            template <typename F, typename... Args>
            auto submitWithPriority(TaskPriority priority, F&& f, Args&&... args)
                -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;

            // Group task submission
            template <typename F, typename... Args>
            auto submitToGroup(TaskGroupId groupId, F&& f, Args&&... args)
                -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>;

            // Asynchronous task submission (try)
            template <typename F, typename... Args>
            auto trySubmit(F&& f, Args&&... args)
                -> std::optional<std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>>;

            // Wait / control
            void waitForAll();
            void waitForGroup(TaskGroupId groupId);
            void cancelGroup(TaskGroupId groupId); // name aligned with cpp: cancelGroup
            TaskGroupId createTaskGroup(const std::wstring& groupName = L"");

            struct TaskGroupInfo {
                TaskGroupId id;
                std::wstring name;
                size_t pendingTasks;
                size_t completedTasks;
                bool isCancelled;
            };

            std::optional<TaskGroupInfo> getTaskGroupInfo(TaskGroupId groupId) const;

            void pause();
            void resume();
            [[nodiscard]] bool isPaused() const noexcept;
            void shutdown(bool wait = true);

            void resize(size_t newThreadCount);

            [[nodiscard]] ThreadPoolStatistics getStatistics() const;
            [[nodiscard]] size_t activeThreadCount() const noexcept;
            [[nodiscard]] size_t queueSize() const noexcept;
            [[nodiscard]] size_t threadCount() const noexcept;
            [[nodiscard]] bool isActive() const noexcept;

            // ETW
            void registerETWProvider();
            void unregisterETWProvider();

        private:
            using TaskFunction = std::function<void()>;

            struct Task {
                TaskId id = 0;
                TaskGroupId groupId = 0;
                TaskPriority priority = TaskPriority::Normal;
                TaskFunction function;
                std::chrono::steady_clock::time_point enqueueTime;

                Task() = default;
                Task(TaskId id, TaskGroupId groupId, TaskPriority priority, TaskFunction&& func)
                    : id(id), groupId(groupId), priority(priority), function(std::move(func)),
                    enqueueTime(std::chrono::steady_clock::now()) {
                }
            };

            struct TaskGroup {
                std::wstring name;
                std::atomic<size_t> pendingTasks{ 0 };
                std::atomic<size_t> completedTasks{ 0 };
                std::atomic<bool> isCancelled{ false };
                std::condition_variable completionCv;
            };

            // helpers
            void initialize();
            void workerThread(size_t threadIndex);
            Task getNextTask();
            void setThreadName(HANDLE threadHandle, const std::wstring& name) const;
            void bindThreadToCore(size_t threadIndex);
            void initializeThread(size_t threadIndex);
            void updateStatistics();

            void logThreadPoolEvent(const wchar_t* category, const wchar_t* format, ...);

            // members
            std::vector<std::thread> m_threads;
            std::vector<HANDLE> m_threadHandles;
            std::deque<Task> m_highPriorityQueue;
            std::deque<Task> m_normalPriorityQueue;
            std::deque<Task> m_lowPriorityQueue;

            mutable std::mutex m_queueMutex;
            mutable std::mutex m_groupMutex;
            std::condition_variable m_taskCv;
            std::condition_variable m_waitAllCv;

            std::atomic<bool> m_paused{ false };
            std::atomic<bool> m_shutdown{ false };
            std::atomic<TaskId> m_nextTaskId{ 1 };
            std::atomic<TaskGroupId> m_nextGroupId{ 1 };
            std::atomic<size_t> m_activeThreads{ 0 };
            std::atomic<size_t> m_totalTasksProcessed{ 0 };
            std::atomic<size_t> m_peakQueueSize{ 0 };
            std::atomic<uint64_t> m_totalExecutionTimeMs{ 0 };

            std::unordered_map<TaskGroupId, std::shared_ptr<TaskGroup>> m_taskGroups;
            ThreadPoolConfig m_config;
            ThreadPoolStatistics m_stats;

            // Windows ETW Provider
            REGHANDLE m_etwProvider{ 0 };
        };

        // ------------------- Template Implementations ------------------- //

        template <typename F, typename... Args>
        auto ThreadPool::submit(F&& f, Args&&... args)
            -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
        {
            return submitWithPriority(TaskPriority::Normal, std::forward<F>(f), std::forward<Args>(args)...);
        }

        template <typename F, typename... Args>
        auto ThreadPool::submitWithPriority(TaskPriority priority, F&& f, Args&&... args)
            -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
        {
            using ReturnType = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;
            using PackagedTask = std::packaged_task<ReturnType()>;

            // EARLY SHUTDOWN CHECK (no lock needed)
            if (m_shutdown.load(std::memory_order_acquire)) {
                throw std::runtime_error("ThreadPool is shutting down, cannot accept new tasks");
            }

            auto bound = std::bind(std::forward<F>(f), std::forward<Args>(args)...);

            auto task = std::make_shared<PackagedTask>(
                [bound]() mutable -> ReturnType {
                    if constexpr (std::is_void_v<ReturnType>) {
                        bound();
                    }
                    else {
                        return bound();
                    }
                }
            );

            std::future<ReturnType> result = task->get_future();
            TaskId taskId = m_nextTaskId.fetch_add(1, std::memory_order_relaxed);

            {
                std::unique_lock<std::mutex> lock(m_queueMutex);

                // IMPROVED WAIT WITH PROPER SHUTDOWN HANDLING
                if (m_config.maxQueueSize > 0) {
                    bool waitResult = m_taskCv.wait_for(lock, std::chrono::seconds(30), [this]() {
                        size_t total = m_highPriorityQueue.size() +
                            m_normalPriorityQueue.size() +
                            m_lowPriorityQueue.size();
                        return m_shutdown.load(std::memory_order_acquire) ||
                            total < m_config.maxQueueSize;
                        });

                    // TIMEOUT CHECK
                    if (!waitResult) {
                        throw std::runtime_error("ThreadPool queue wait timeout (30s) - possible deadlock");
                    }

                    // DOUBLE-CHECK SHUTDOWN AFTER WAKE
                    if (m_shutdown.load(std::memory_order_acquire)) {
                        throw std::runtime_error("ThreadPool is shutting down, cannot accept new tasks");
                    }

                    // VERIFY SPACE STILL AVAILABLE (another thread might have filled queue)
                    size_t total = m_highPriorityQueue.size() +
                        m_normalPriorityQueue.size() +
                        m_lowPriorityQueue.size();

                    if (total >= m_config.maxQueueSize) {
                        // Try one more time with short timeout
                        if (!m_taskCv.wait_for(lock, std::chrono::milliseconds(100), [this]() {
                            size_t t = m_highPriorityQueue.size() +
                                m_normalPriorityQueue.size() +
                                m_lowPriorityQueue.size();
                            return m_shutdown.load(std::memory_order_acquire) ||
                                t < m_config.maxQueueSize;
                            })) {
                            throw std::runtime_error("ThreadPool queue is full");
                        }
                    }
                }

                auto taskWrapper = [task]() { (*task)(); };
                Task newTask(taskId, 0, priority, std::move(taskWrapper));

                switch (priority) {
                case TaskPriority::Critical:
                case TaskPriority::High:
                    m_highPriorityQueue.push_back(std::move(newTask));
                    break;
                case TaskPriority::Normal:
                    m_normalPriorityQueue.push_back(std::move(newTask));
                    break;
                case TaskPriority::Low:
                case TaskPriority::Background:
                    m_lowPriorityQueue.push_back(std::move(newTask));
                    break;
                }

                // ATOMIC PEAK UPDATE
                size_t totalSize = m_highPriorityQueue.size() +
                    m_normalPriorityQueue.size() +
                    m_lowPriorityQueue.size();
                size_t oldPeak = m_peakQueueSize.load(std::memory_order_relaxed);
                while (oldPeak < totalSize &&
                    !m_peakQueueSize.compare_exchange_weak(oldPeak, totalSize,
                        std::memory_order_release, std::memory_order_relaxed)) {
                    // CAS loop
                }
            }

            m_taskCv.notify_one();

            if (m_config.enableLogging) {
                logThreadPoolEvent(L"ThreadPool", L"Task submitted with priority %d, ID: %llu",
                    static_cast<int>(priority), static_cast<unsigned long long>(taskId));
            }

            return result;
        }

        template<typename F, typename... Args>
        auto ThreadPool::submitToGroup(TaskGroupId groupId, F&& f, Args&&... args)
            -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
        {
            using ReturnType = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;
            using PackagedTask = std::packaged_task<ReturnType()>;

            std::shared_ptr<TaskGroup> group;
            {
                std::lock_guard<std::mutex> lock(m_groupMutex);
                auto it = m_taskGroups.find(groupId);
                if (it == m_taskGroups.end()) {
                    throw std::invalid_argument("Invalid task group ID");
                }
                group = it->second;
            }

            auto bound = std::bind(std::forward<F>(f), std::forward<Args>(args)...);

            auto task = std::make_shared<PackagedTask>(
                [bound]() mutable -> ReturnType {
                    if constexpr (std::is_void_v<ReturnType>) {
                        bound();
                    }
                    else {
                        return bound();
                    }
                }
            );

            std::future<ReturnType> result = task->get_future();

            if (m_shutdown.load(std::memory_order_relaxed)) {
                throw std::runtime_error("ThreadPool is shutting down, cannot accept new tasks");
            }

            TaskId taskId = m_nextTaskId.fetch_add(1, std::memory_order_relaxed);

            // increment pending BEFORE queuing
            group->pendingTasks.fetch_add(1, std::memory_order_relaxed);

            {
                std::unique_lock<std::mutex> lock(m_queueMutex);

                // wrapper checks cancellation and updates group counters AFTER execution
                auto taskWrapper = [task, group, this, taskId]() {
                    if (group->isCancelled.load(std::memory_order_relaxed)) {
                        if (m_config.enableLogging) {
                            logThreadPoolEvent(L"ThreadPool", L"Task %llu in group cancelled", static_cast<unsigned long long>(taskId));
                        }
                    }
                    else {
                        (*task)();
                    }

                    // decrement pending and increment completed (old value returned)
                    size_t oldPending = group->pendingTasks.fetch_sub(1, std::memory_order_relaxed);
                    group->completedTasks.fetch_add(1, std::memory_order_relaxed);
                    if (oldPending == 1) { // was 1 -> now zero
                        group->completionCv.notify_all();
                    }
                    };

                Task newTask(taskId, groupId, TaskPriority::Normal, std::move(taskWrapper));
                m_normalPriorityQueue.push_back(std::move(newTask));

                size_t totalSize = m_highPriorityQueue.size() + m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
                size_t oldPeak = m_peakQueueSize.load(std::memory_order_relaxed);
                while (oldPeak < totalSize && !m_peakQueueSize.compare_exchange_weak(oldPeak, totalSize)) {}
            }

            m_taskCv.notify_one();

            if (m_config.enableLogging) {
                logThreadPoolEvent(L"ThreadPool", L"Task submitted to group %llu, ID: %llu",
                    static_cast<unsigned long long>(groupId), static_cast<unsigned long long>(taskId));
            }

            return result;
        }

        template<typename F, typename... Args>
        auto ThreadPool::trySubmit(F&& f, Args&&... args)
            -> std::optional<std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>>
        {
            using ReturnType = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;
            using PackagedTask = std::packaged_task<ReturnType()>;

            if (m_shutdown.load(std::memory_order_relaxed)) {
                return std::nullopt;
            }

            auto bound = std::bind(std::forward<F>(f), std::forward<Args>(args)...);

            auto task = std::make_shared<PackagedTask>(
                [bound]() mutable -> ReturnType {
                    if constexpr (std::is_void_v<ReturnType>) {
                        bound();
                    }
                    else {
                        return bound();
                    }
                }
            );

            std::future<ReturnType> result = task->get_future();

            TaskId taskId = m_nextTaskId.fetch_add(1, std::memory_order_relaxed);

            {
                std::lock_guard<std::mutex> lock(m_queueMutex);

                if (m_config.maxQueueSize > 0) {
                    size_t totalSize = m_highPriorityQueue.size() + m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
                    if (totalSize >= m_config.maxQueueSize) {
                        return std::nullopt;
                    }
                }

                auto taskWrapper = [task]() { (*task)(); };
                Task newTask(taskId, 0, TaskPriority::Normal, std::move(taskWrapper));
                m_normalPriorityQueue.push_back(std::move(newTask));

                size_t totalSize = m_highPriorityQueue.size() + m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
                size_t oldPeak = m_peakQueueSize.load(std::memory_order_relaxed);
                while (oldPeak < totalSize && !m_peakQueueSize.compare_exchange_weak(oldPeak, totalSize)) {}
            }

            m_taskCv.notify_one();

            if (m_config.enableLogging) {
                logThreadPoolEvent(L"ThreadPool", L"Task trySubmit successful, ID: %llu", static_cast<unsigned long long>(taskId));
            }

            return result;
        }

    } // namespace Utils
} // namespace ShadowStrike
