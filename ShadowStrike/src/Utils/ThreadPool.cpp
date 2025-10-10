
#if !defined(_X86_) && !defined(_AMD64_)
#ifdef _M_X64
#define _AMD64_
#elif defined(_M_IX86)
#define _X86_
#else
#error "Unknown architecture, please compile for x86 or x64"
#endif
#endif

#include "ThreadPool.hpp"
#include "Logger.hpp"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <array>
#include <processthreadsapi.h>

// ETW Event Provider GUID 
#define INITGUID
#include <evntprov.h>
#include <evntrace.h>

//  ETW Provider GUID for shadowStrike thread pool
// {7A8F98C2-8740-49E5-B9F3-D418B78D25EB}
DEFINE_GUID(ShadowStrikeThreadPoolProvider,
    0x7a8f98c2, 0x8740, 0x49e5, 0xb9, 0xf3, 0xd4, 0x18, 0xb7, 0x8d, 0x25, 0xeb);

namespace ShadowStrike {
    namespace Utils {

        // ETW Task identifiers
        enum ThreadPoolEventId {
            ThreadPoolCreated = 1,
            ThreadPoolDestroyed = 2,
            ThreadPoolTaskSubmitted = 3,
            ThreadPoolTaskStarted = 4,
            ThreadPoolTaskCompleted = 5,
            ThreadPoolThreadCreated = 6,
            ThreadPoolThreadDestroyed = 7,
            ThreadPoolPaused = 8,
            ThreadPoolResumed = 9,
            ThreadPoolResized = 10,
            ThreadPoolGroupCreated = 11,
            ThreadPoolGroupWaitComplete = 12,
            ThreadPoolGroupCancelled = 13
        };

		//*** Global ETW event descriptors ***
        static const EVENT_DESCRIPTOR g_evt_ThreadPoolCreated = { static_cast<USHORT>(ThreadPoolCreated), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_ThreadPoolDestroyed = { static_cast<USHORT>(ThreadPoolDestroyed), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_TaskSubmitted = { static_cast<USHORT>(ThreadPoolTaskSubmitted), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_TaskStarted = { static_cast<USHORT>(ThreadPoolTaskStarted), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_TaskCompleted = { static_cast<USHORT>(ThreadPoolTaskCompleted), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_ThreadCreated = { static_cast<USHORT>(ThreadPoolThreadCreated), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_ThreadDestroyed = { static_cast<USHORT>(ThreadPoolThreadDestroyed), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_Paused = { static_cast<USHORT>(ThreadPoolPaused), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_Resumed = { static_cast<USHORT>(ThreadPoolResumed), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_Resized = { static_cast<USHORT>(ThreadPoolResized), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_GroupCreated = { static_cast<USHORT>(ThreadPoolGroupCreated), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_GroupWaitComplete = { static_cast<USHORT>(ThreadPoolGroupWaitComplete), 0, 0, 4, 0, 0, 0 };
        static const EVENT_DESCRIPTOR g_evt_GroupCancelled = { static_cast<USHORT>(ThreadPoolGroupCancelled), 0, 0, 4, 0, 0, 0 };

        ThreadPool::ThreadPool(const ThreadPoolConfig& config)
            : m_config(config)
        {
            initialize();
        }

        ThreadPool::ThreadPool(size_t threadCount, std::wstring poolName)
        {
            m_config.threadCount = threadCount;
            m_config.poolName = std::move(poolName);
            initialize();
        }

        ThreadPool::~ThreadPool()
        {
            shutdown(true);
            unregisterETWProvider();
        }

        void ThreadPool::initialize()
        {
            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Initializing ThreadPool with %zu threads, name: %s",
                    m_config.threadCount, m_config.poolName.c_str());
            }

            // Save the ETW Provider
            if (m_config.enableProfiling) {
                registerETWProvider();
            }

            //Calculate the thread count if 0 (default)
            if (m_config.threadCount == 0) {
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                m_config.threadCount = sysInfo.dwNumberOfProcessors;

                // Cpu reservation based on subsystem
                if (m_config.cpuSubsystem != CpuSubsystem::Default) {
                    //Use less threads for real-time operations
                    if (m_config.cpuSubsystem == CpuSubsystem::RealTime) {
                        m_config.threadCount = std::max<size_t>(1, m_config.threadCount / 4);
                    }
                    //Use more threads for scanning operations
                    else if (m_config.cpuSubsystem == CpuSubsystem::Scanner) {
                        m_config.threadCount = std::max<size_t>(1, (m_config.threadCount * 3) / 4);
                    }
                }
            }

            //Start the threads
            m_threads.reserve(m_config.threadCount);
            m_threadHandles.reserve(m_config.threadCount);

            for (size_t i = 0; i < m_config.threadCount; ++i) {
                m_threads.emplace_back([this, i]() { workerThread(i); });

                //Save the thread handle
                HANDLE threadHandle = m_threads.back().native_handle();
                m_threadHandles.push_back(threadHandle);

                // Thread starting operations
                initializeThread(i);
            }

            //send ETW event
            if (m_etwProvider != 0) {
                // Use fixed width types for ETW
                const wchar_t* poolNamePtr = m_config.poolName.c_str();
                ULONG poolNameBytes = static_cast<ULONG>((m_config.poolName.length() + 1) * sizeof(wchar_t));
                ULONG threadCountUL = static_cast<ULONG>(m_config.threadCount);

                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], poolNamePtr, poolNameBytes);
                EventDataDescCreate(&eventData[1], &threadCountUL, sizeof(threadCountUL));

                EventWrite(m_etwProvider, &g_evt_ThreadPoolCreated, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"ThreadPool initialized with %zu threads", m_config.threadCount);
            }
        }

        void ThreadPool::initializeThread(size_t threadIndex) {
            HANDLE threadHandle = m_threadHandles[threadIndex];

            // set the thread name
            std::wstringstream ss;
            ss << m_config.poolName << L"-" << threadIndex;
            setThreadName(threadHandle, ss.str());

            //set the thread priority
            if (m_config.setThreadPriority) {
                SetThreadPriority(threadHandle, m_config.threadPriority);
            }

            //bind the thread to a specific core
            if (m_config.bindToHardware) {
                bindThreadToCore(threadIndex);
            }

            // change the thread stack size (informational only)
            if (m_config.threadStackSize > 0) {
                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"Thread %zu created with custom stack size: %zu",
                        threadIndex, m_config.threadStackSize);
                }
            }

            // send the ETW event
            if (m_etwProvider != 0) {
                ULONG threadIndexUL = static_cast<ULONG>(threadIndex);
                DWORD threadId = GetThreadId(threadHandle); // may return 0 on error

                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &threadIndexUL, sizeof(threadIndexUL));
                EventDataDescCreate(&eventData[1], &threadId, sizeof(threadId));

                EventWrite(m_etwProvider, &g_evt_ThreadCreated, _countof(eventData), eventData);
            }
        }

        void ThreadPool::bindThreadToCore(size_t threadIndex) {

            HANDLE threadHandle = m_threadHandles[threadIndex];
            DWORD_PTR mask = 0;

            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);

            // Simple round-robin core assignment
            size_t coreIndex = threadIndex % sysInfo.dwNumberOfProcessors;

            //different CPU subsystems can have different core assignments
            switch (m_config.cpuSubsystem) {
            case CpuSubsystem::RealTime:
                coreIndex = 0;
                break;
            case CpuSubsystem::Scanner:
                if (sysInfo.dwNumberOfProcessors > 1)
                    coreIndex = (threadIndex % (sysInfo.dwNumberOfProcessors - 1)) + 1;
                else
                    coreIndex = 0;
                break;
            case CpuSubsystem::NetworkMonitor:
                coreIndex = sysInfo.dwNumberOfProcessors / 2;
                break;
            default:
                coreIndex = threadIndex % sysInfo.dwNumberOfProcessors;
            }

            mask = (static_cast<DWORD_PTR>(1) << coreIndex);

            // set affinity (returns previous mask or 0 on error)
            SetThreadAffinityMask(threadHandle, mask);

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Thread %zu bound to core %zu", threadIndex, coreIndex);
            }
        }

        void ThreadPool::setThreadName(HANDLE threadHandle, const std::wstring& name) const {
            using SetThreadDescriptionFunc = HRESULT(WINAPI*)(HANDLE, PCWSTR);

            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (!kernel32) return;

            auto setThreadDescFunc = reinterpret_cast<SetThreadDescriptionFunc>(
                GetProcAddress(kernel32, "SetThreadDescription"));

            if (setThreadDescFunc) {
                setThreadDescFunc(threadHandle, name.c_str());
            }
        }

        void ThreadPool::workerThread(size_t threadIndex) {
            // ENTIRE WORKER WRAPPED IN TRY-CATCH
            try {
                std::wstringstream threadName;
                threadName << m_config.poolName << L"-" << threadIndex;

                if (m_config.enableLogging) {
                    SS_LOG_DEBUG(L"ThreadPool", L"Thread %zu (%s) started", threadIndex, threadName.str().c_str());
                }

                while (!m_shutdown.load(std::memory_order_acquire)) {
                    Task task;
                    bool hasTask = false;

                    // SAFE TASK RETRIEVAL WITH EXCEPTION HANDLING
                    try {
                        std::unique_lock<std::mutex> lock(m_queueMutex);

                        m_taskCv.wait(lock, [this]() {
                            return m_shutdown.load(std::memory_order_acquire) ||
                                (!m_paused.load(std::memory_order_acquire) &&
                                    (!m_highPriorityQueue.empty() ||
                                        !m_normalPriorityQueue.empty() ||
                                        !m_lowPriorityQueue.empty()));
                            });

                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break;
                        }

                        if (!m_paused.load(std::memory_order_acquire)) {
                            task = getNextTask();
                            hasTask = (task.function != nullptr);
                        }
                    }
                    catch (const std::exception& e) {
                        if (m_config.enableLogging) {
                            SS_LOG_ERROR(L"ThreadPool", L"Worker %zu: Exception in task retrieval: %hs",
                                threadIndex, e.what());
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }
                    catch (...) {
                        if (m_config.enableLogging) {
                            SS_LOG_ERROR(L"ThreadPool", L"Worker %zu: Unknown exception in task retrieval",
                                threadIndex);
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }

                    // Process the task
                    if (hasTask && task.function) {
                        auto startTime = std::chrono::steady_clock::now();

                        // ETW event for task started
                        if (m_etwProvider != 0) {
                            ULONGLONG taskId = static_cast<ULONGLONG>(task.id);
                            ULONG threadIdx = static_cast<ULONG>(threadIndex);
                            ULONG priorityUL = static_cast<ULONG>(static_cast<uint8_t>(task.priority));
                            const wchar_t* poolNamePtr = m_config.poolName.c_str();
                            ULONG poolNameBytes = static_cast<ULONG>((m_config.poolName.length() + 1) * sizeof(wchar_t));
                            ULONG threadCountUL = static_cast<ULONG>(m_config.threadCount);

                            EVENT_DATA_DESCRIPTOR eventData[5];
                            EventDataDescCreate(&eventData[0], &taskId, sizeof(taskId));
                            EventDataDescCreate(&eventData[1], &threadIdx, sizeof(threadIdx));
                            EventDataDescCreate(&eventData[2], &priorityUL, sizeof(priorityUL));
                            EventDataDescCreate(&eventData[3], poolNamePtr, poolNameBytes);
                            EventDataDescCreate(&eventData[4], &threadCountUL, sizeof(threadCountUL));

                            EventWrite(m_etwProvider, &g_evt_TaskStarted, _countof(eventData), eventData);
                        }

                        // INCREMENT ACTIVE COUNTER
                        m_activeThreads.fetch_add(1, std::memory_order_release);

                        bool taskSucceeded = false;

                        // EXECUTE TASK WITH COMPREHENSIVE EXCEPTION HANDLING
                        try {
                            task.function();
                            taskSucceeded = true;
                        }
                        catch (const std::bad_alloc& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_ERROR(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw bad_alloc (out of memory): %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (const std::runtime_error& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_ERROR(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw runtime_error: %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (const std::exception& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_ERROR(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw exception: %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (...) {
                            if (m_config.enableLogging) {
                                SS_LOG_ERROR(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw unknown exception",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id));
                            }
                        }

                        auto endTime = std::chrono::steady_clock::now();
                        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

                        // UPDATE STATISTICS
                        m_totalExecutionTimeMs.fetch_add(static_cast<uint64_t>(durationMs), std::memory_order_relaxed);
                        m_totalTasksProcessed.fetch_add(1, std::memory_order_relaxed);
                        m_activeThreads.fetch_sub(1, std::memory_order_release);

                        // NOTIFY WAITERS IF ALL WORK DONE
                        if (m_activeThreads.load(std::memory_order_acquire) == 0) {
                            std::lock_guard<std::mutex> lock(m_queueMutex);
                            if (m_highPriorityQueue.empty() &&
                                m_normalPriorityQueue.empty() &&
                                m_lowPriorityQueue.empty()) {
                                m_waitAllCv.notify_all();
                            }
                        }

                        // ETW event - task completed
                        if (m_etwProvider != 0) {
                            ULONGLONG taskId = static_cast<ULONGLONG>(task.id);
                            ULONG threadIdx = static_cast<ULONG>(threadIndex);
                            ULONGLONG durationUL = static_cast<ULONGLONG>(durationMs);

                            EVENT_DATA_DESCRIPTOR eventData[3];
                            EventDataDescCreate(&eventData[0], &taskId, sizeof(taskId));
                            EventDataDescCreate(&eventData[1], &threadIdx, sizeof(threadIdx));
                            EventDataDescCreate(&eventData[2], &durationUL, sizeof(durationUL));

                            EventWrite(m_etwProvider, &g_evt_TaskCompleted, _countof(eventData), eventData);
                        }

                        // Logging for slow or critical tasks
                        if (m_config.enableLogging &&
                            (durationMs > 1000 || task.priority == TaskPriority::Critical)) {
                            SS_LOG_DEBUG(L"ThreadPool",
                                L"Task %llu completed in %lld ms (priority: %d, success: %d)",
                                static_cast<unsigned long long>(task.id),
                                static_cast<long long>(durationMs),
                                static_cast<int>(task.priority),
                                taskSucceeded ? 1 : 0);
                        }

                        // Update stats
                        try {
                            updateStatistics();
                        }
                        catch (...) {
                            // Ignore stats update failures
                        }
                    }
                }

                if (m_config.enableLogging) {
                    SS_LOG_DEBUG(L"ThreadPool", L"Thread %zu exiting normally", threadIndex);
                }

                // ETW event - thread closed
                if (m_etwProvider != 0) {
                    ULONG threadIdx = static_cast<ULONG>(threadIndex);
                    EVENT_DATA_DESCRIPTOR eventData[1];
                    EventDataDescCreate(&eventData[0], &threadIdx, sizeof(threadIdx));
                    EventWrite(m_etwProvider, &g_evt_ThreadDestroyed, _countof(eventData), eventData);
                }

            }
            catch (const std::exception& e) {
                // CATASTROPHIC FAILURE - LOG AND EXIT GRACEFULLY
                if (m_config.enableLogging) {
                    SS_LOG_ERROR(L"ThreadPool",
                        L"CRITICAL: Worker thread %zu crashed: %hs",
                        threadIndex, e.what());
                }

                // Try to decrement active counter if it was incremented
                size_t activeCount = m_activeThreads.load(std::memory_order_acquire);
                if (activeCount > 0) {
                    m_activeThreads.fetch_sub(1, std::memory_order_release);
                }

            }
            catch (...) {
                if (m_config.enableLogging) {
                    SS_LOG_ERROR(L"ThreadPool",
                        L"CRITICAL: Worker thread %zu crashed with unknown exception",
                        threadIndex);
                }

                size_t activeCount = m_activeThreads.load(std::memory_order_acquire);
                if (activeCount > 0) {
                    m_activeThreads.fetch_sub(1, std::memory_order_release);
                }
            }
        }

       ThreadPool::Task ThreadPool::getNextTask()
        {
            if (!m_highPriorityQueue.empty()) {
                Task task = std::move(m_highPriorityQueue.front());
                m_highPriorityQueue.pop_front();
                return task;
            }

            if (!m_normalPriorityQueue.empty()) {
                Task task = std::move(m_normalPriorityQueue.front());
                m_normalPriorityQueue.pop_front();
                return task;
            }

            if (!m_lowPriorityQueue.empty()) {
                Task task = std::move(m_lowPriorityQueue.front());
                m_lowPriorityQueue.pop_front();
                return task;
            }

            // Shouldn't happen, but return a no-op
            return Task(0, 0, TaskPriority::Normal, []() {});
        }

        void ThreadPool::registerETWProvider()
        {
            if (m_etwProvider == 0) {
                ULONG result = EventRegister(&ShadowStrikeThreadPoolProvider, nullptr, nullptr, &m_etwProvider);
                if (result != ERROR_SUCCESS) {
                    if (m_config.enableLogging) {
                        SS_LOG_WARN(L"ThreadPool", L"Failed to register ETW provider, error: %lu", result);
                    }
                    m_etwProvider = 0;
                }
                else if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ETW provider registered successfully");
                }
            }
        }

        void ThreadPool::unregisterETWProvider()
        {
            if (m_etwProvider != 0) {
                EventUnregister(m_etwProvider);
                m_etwProvider = 0;

                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ETW provider unregistered");
                }
            }
        }

        void ThreadPool::updateStatistics()
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);

            m_stats.threadCount = m_threads.size();
            m_stats.activeThreads = m_activeThreads.load(std::memory_order_relaxed);
            m_stats.pendingHighPriorityTasks = m_highPriorityQueue.size();
            m_stats.pendingNormalTasks = m_normalPriorityQueue.size();
            m_stats.pendingLowPriorityTasks = m_lowPriorityQueue.size();
            m_stats.totalTasksProcessed = m_totalTasksProcessed.load(std::memory_order_relaxed);
            m_stats.peakQueueSize = m_peakQueueSize.load(std::memory_order_relaxed);

            uint64_t totalTasks = m_stats.totalTasksProcessed;
            uint64_t totalTime = m_totalExecutionTimeMs.load(std::memory_order_relaxed);

            if (totalTasks > 0) {
                m_stats.avgExecutionTimeMs = static_cast<double>(totalTime) / totalTasks;
            }

            size_t estimatedTaskSize = sizeof(Task) * 3;
            m_stats.memoryUsage = (m_highPriorityQueue.size() + m_normalPriorityQueue.size() +
                m_lowPriorityQueue.size()) * estimatedTaskSize;
        }

        ThreadPoolStatistics ThreadPool::getStatistics() const
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            return m_stats;
        }

        size_t ThreadPool::activeThreadCount() const noexcept
        {
            return m_activeThreads.load(std::memory_order_relaxed);
        }

        size_t ThreadPool::queueSize() const noexcept
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            return m_highPriorityQueue.size() + m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
        }

        size_t ThreadPool::threadCount() const noexcept
        {
            return m_threads.size();
        }

        bool ThreadPool::isActive() const noexcept
        {
            return !m_shutdown.load(std::memory_order_relaxed);
        }

        bool ThreadPool::isPaused() const noexcept
        {
            return m_paused.load(std::memory_order_relaxed);
        }

        void ThreadPool::pause()
        {
            bool expected = false;
            if (m_paused.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ThreadPool paused");
                }

                // ETW event
                if (m_etwProvider != 0) {
                    EVENT_DATA_DESCRIPTOR eventData[1];
                    ULONG queueSz = static_cast<ULONG>(queueSize());
                    EventDataDescCreate(&eventData[0], &queueSz, sizeof(queueSz));

                    EventWrite(m_etwProvider, &g_evt_Paused, _countof(eventData), eventData);
                }
            }
        }

        void ThreadPool::resume()
        {
            bool expected = true;
            if (m_paused.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
                m_taskCv.notify_all();

                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ThreadPool resumed");
                }

                if (m_etwProvider != 0) {
                    EventWrite(m_etwProvider, &g_evt_Resumed, 0, nullptr);
                }
            }
        }


        void ThreadPool::shutdown(bool wait)
        {
            //IDEMPOTENT SHUTDOWN WITH CAS
            bool expected = false;
            if (!m_shutdown.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
                // Already shutting down
                if (m_config.enableLogging) {
                    SS_LOG_WARN(L"ThreadPool", L"Shutdown already in progress");
                }
                return;
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"ThreadPool shutting down (wait=%s)...",
                    wait ? L"true" : L"false");
            }

            // WAKE ALL WAITING THREADS
            m_taskCv.notify_all();
            m_waitAllCv.notify_all();

            if (wait) {
                // WAIT FOR PENDING TASKS TO COMPLETE (with timeout)
                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);

                    // If paused, resume to allow tasks to complete
                    if (m_paused.load(std::memory_order_acquire)) {
                        m_paused.store(false, std::memory_order_release);
                        m_taskCv.notify_all();
                    }

                    // Wait for all tasks to complete with timeout
                    bool completed = m_waitAllCv.wait_for(lock, std::chrono::seconds(30), [this]() {
                        return m_highPriorityQueue.empty() &&
                            m_normalPriorityQueue.empty() &&
                            m_lowPriorityQueue.empty() &&
                            m_activeThreads.load(std::memory_order_acquire) == 0;
                        });

                    if (!completed && m_config.enableLogging) {
                        SS_LOG_WARN(L"ThreadPool",
                            L"Shutdown timeout waiting for tasks. Remaining: High=%zu, Normal=%zu, Low=%zu, Active=%zu",
                            m_highPriorityQueue.size(),
                            m_normalPriorityQueue.size(),
                            m_lowPriorityQueue.size(),
                            m_activeThreads.load(std::memory_order_acquire));
                    }
                }

                // TIMEOUT-BASED JOIN WITH FORCE TERMINATION
                constexpr auto JOIN_TIMEOUT = std::chrono::seconds(30);
                auto deadline = std::chrono::steady_clock::now() + JOIN_TIMEOUT;

                std::vector<size_t> hungThreadIndices;

                for (size_t i = 0; i < m_threads.size(); ++i) {
                    auto& thread = m_threads[i];

                    if (!thread.joinable()) {
                        continue;
                    }

                    auto timeRemaining = deadline - std::chrono::steady_clock::now();

                    if (timeRemaining <= std::chrono::seconds(0)) {
                        // Timeout exceeded
                        if (m_config.enableLogging) {
                            SS_LOG_WARN(L"ThreadPool",
                                L"WARNING: Thread %zu join timeout, attempting force termination", i);
                        }

                        hungThreadIndices.push_back(i);

                        // FORCE TERMINATE HUNG THREAD (Windows-specific)
                        if (i < m_threadHandles.size() && m_threadHandles[i]) {
                            DWORD exitCode = 0;
                            if (::GetExitCodeThread(m_threadHandles[i], &exitCode) &&
                                exitCode == STILL_ACTIVE) {
                                ::TerminateThread(m_threadHandles[i], ERROR_TIMEOUT);
                            }
                            ::CloseHandle(m_threadHandles[i]);
                            m_threadHandles[i] = nullptr;
                        }

                        thread.detach(); // Prevent join() crash
                        continue;
                    }

                    // TRY JOIN WITH POLLING (std::thread doesn't have timed_join)
                    bool joined = false;
                    auto joinStart = std::chrono::steady_clock::now();

                    while (std::chrono::steady_clock::now() - joinStart < timeRemaining) {
                        // Check if thread is still running (Windows-specific)
                        if (i < m_threadHandles.size() && m_threadHandles[i]) {
                            DWORD exitCode = 0;
                            if (::GetExitCodeThread(m_threadHandles[i], &exitCode)) {
                                if (exitCode != STILL_ACTIVE) {
                                    // Thread finished
                                    thread.join();
                                    joined = true;
                                    break;
                                }
                            }
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }

                    if (!joined) {
                        // Final attempt to join
                        if (thread.joinable()) {
                            try {
                                thread.join();
                                joined = true;
                            }
                            catch (const std::system_error& e) {
                                if (m_config.enableLogging) {
                                    SS_LOG_ERROR(L"ThreadPool",
                                        L"Thread %zu join failed: error %d", i, e.code().value());
                                }
                                thread.detach();
                            }
                        }
                    }

                    if (joined && m_config.enableLogging) {
                        SS_LOG_DEBUG(L"ThreadPool", L"Thread %zu joined successfully", i);
                    }
                }

                // REPORT HUNG THREADS
                if (!hungThreadIndices.empty() && m_config.enableLogging) {
                    SS_LOG_ERROR(L"ThreadPool",
                        L"WARNING: %zu thread(s) were forcibly terminated",
                        hungThreadIndices.size());
                }

            }
            else {
                // NON-WAIT MODE: DETACH ALL THREADS
                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"Detaching %zu threads (no wait)", m_threads.size());
                }

                for (auto& thread : m_threads) {
                    if (thread.joinable()) {
                        thread.detach();
                    }
                }
            }

            // CLEANUP RESOURCES
            m_threads.clear();

            for (auto handle : m_threadHandles) {
                if (handle && handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(handle);
                }
            }
            m_threadHandles.clear();

            // CLEAR ALL QUEUES
            {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_highPriorityQueue.clear();
                m_normalPriorityQueue.clear();
                m_lowPriorityQueue.clear();
            }

            // ETW EVENT - THREAD POOL DESTROYED
            if (m_etwProvider != 0) {
                ULONG totalTasks = static_cast<ULONG>(m_totalTasksProcessed.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[1];
                EventDataDescCreate(&eventData[0], &totalTasks, sizeof(totalTasks));
                EventWrite(m_etwProvider, &g_evt_ThreadPoolDestroyed, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"ThreadPool shut down successfully, processed %llu tasks",
                    static_cast<unsigned long long>(m_totalTasksProcessed.load(std::memory_order_relaxed)));
            }
        }

        void ThreadPool::resize(size_t newThreadCount)
        {
            if (newThreadCount == 0 || newThreadCount == m_threads.size() ||
                m_shutdown.load(std::memory_order_relaxed)) {
                return;
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Resizing thread pool from %zu to %zu threads",
                    m_threads.size(), newThreadCount);
            }

            // Lowering the thread count
            if (newThreadCount < m_threads.size()) {
                size_t threadsToRemove = m_threads.size() - newThreadCount;

				// 1.set shutdown flag and wake all threads
                {
                    std::lock_guard<std::mutex> lock(m_queueMutex);
                    m_shutdown.store(true, std::memory_order_relaxed);
                }
				m_taskCv.notify_all(); // Wake all threads to let them exit

				// 2. Only join the excess threads
                for (size_t i = 0; i < threadsToRemove; ++i) {
                    if (m_threads.back().joinable()) {
                        m_threads.back().join();
                    }
                    m_threads.pop_back();
                    m_threadHandles.pop_back();
                }

                // 3.Make the pool Active again
                {
                    std::lock_guard<std::mutex> lock(m_queueMutex);
                    m_shutdown.store(false, std::memory_order_relaxed);
                }
				//Remaining threads should be notified to continue working
                m_taskCv.notify_all();
            }
			// increasing the thread count
            else {
                size_t threadsToAdd = newThreadCount - m_threads.size();
                size_t currentSize = m_threads.size();

                for (size_t i = 0; i < threadsToAdd; ++i) {
                    size_t threadIndex = currentSize + i;
                    m_threads.emplace_back([this, threadIndex]() { workerThread(threadIndex); });
                    HANDLE threadHandle = m_threads.back().native_handle();
                    m_threadHandles.push_back(threadHandle);
                    initializeThread(threadIndex);
                }
            }

            if (m_etwProvider != 0) {
                ULONG oldSize = static_cast<ULONG>(m_config.threadCount); //Use the old config value
                ULONG newSize = static_cast<ULONG>(newThreadCount);
                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &oldSize, sizeof(oldSize));
                EventDataDescCreate(&eventData[1], &newSize, sizeof(newSize));
                EventWrite(m_etwProvider, &g_evt_Resized, _countof(eventData), eventData);
            }

		   
            m_config.threadCount = newThreadCount;

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Thread pool resized to %zu threads", m_threads.size());
            }
        }

        TaskGroupId ThreadPool::createTaskGroup(const std::wstring& groupName)
        {
            std::lock_guard<std::mutex> lock(m_groupMutex);

            TaskGroupId groupId = m_nextGroupId.fetch_add(1, std::memory_order_relaxed);
            auto group = std::make_shared<TaskGroup>();
            group->name = groupName.empty() ? L"Group-" + std::to_wstring(groupId) : groupName;

            m_taskGroups[groupId] = group;

            // ETW event
            if (m_etwProvider != 0) {
                EVENT_DATA_DESCRIPTOR eventData[2];
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                const wchar_t* namePtr = group->name.c_str();
                ULONG nameBytes = static_cast<ULONG>((group->name.length() + 1) * sizeof(wchar_t));
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], namePtr, nameBytes);
                EventWrite(m_etwProvider, &g_evt_GroupCreated, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Created task group %llu: %s",
                    static_cast<unsigned long long>(groupId), group->name.c_str());
            }

            return groupId;
        }

        std::optional<ThreadPool::TaskGroupInfo> ThreadPool::getTaskGroupInfo(TaskGroupId groupId) const
        {
            std::lock_guard<std::mutex> lock(m_groupMutex);

            auto it = m_taskGroups.find(groupId);
            if (it == m_taskGroups.end()) {
                return std::nullopt;
            }

            const auto& group = it->second;

            TaskGroupInfo info;
            info.id = groupId;
            info.name = group->name;
            info.pendingTasks = group->pendingTasks.load(std::memory_order_relaxed);
            info.completedTasks = group->completedTasks.load(std::memory_order_relaxed);
            info.isCancelled = group->isCancelled.load(std::memory_order_relaxed);

            return info;
        }

        void ThreadPool::waitForGroup(TaskGroupId groupId)
        {
            std::shared_ptr<TaskGroup> group;

            {
                std::lock_guard<std::mutex> lock(m_groupMutex);
                auto it = m_taskGroups.find(groupId);
                if (it == m_taskGroups.end()) {
                    throw std::invalid_argument("Invalid task group ID");
                }
                group = it->second;
            }

            // Wait on group's completion CV; use group's own mutex to avoid races
            std::unique_lock<std::mutex> lock(m_groupMutex);
            group->completionCv.wait(lock, [&group]() {
                return group->pendingTasks.load(std::memory_order_relaxed) == 0;
                });

            // ETW event
            if (m_etwProvider != 0) {
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                ULONG completed = static_cast<ULONG>(group->completedTasks.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], &completed, sizeof(completed));
                EventWrite(m_etwProvider, &g_evt_GroupWaitComplete, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Completed waiting for task group %llu, completed tasks: %zu",
                    static_cast<unsigned long long>(groupId), group->completedTasks.load(std::memory_order_relaxed));
            }
        }

        void ThreadPool::cancelGroup(TaskGroupId groupId)
        {
            std::shared_ptr<TaskGroup> group;

            {
                std::lock_guard<std::mutex> lock(m_groupMutex);
                auto it = m_taskGroups.find(groupId);
                if (it == m_taskGroups.end()) {
                    throw std::invalid_argument("Invalid task group ID");
                }
                group = it->second;
            }

            group->isCancelled.store(true, std::memory_order_release);

            if (m_etwProvider != 0) {
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                ULONG pending = static_cast<ULONG>(group->pendingTasks.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], &pending, sizeof(pending));
                EventWrite(m_etwProvider, &g_evt_GroupCancelled, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Cancelled task group %llu, pending tasks: %zu",
                    static_cast<unsigned long long>(groupId), group->pendingTasks.load(std::memory_order_relaxed));
            }
        }

        void ThreadPool::waitForAll()
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            m_waitAllCv.wait(lock, [this]() {
                return (m_highPriorityQueue.empty() && m_normalPriorityQueue.empty() &&
                    m_lowPriorityQueue.empty() &&
                    m_activeThreads.load(std::memory_order_relaxed) == 0) ||
                    m_shutdown.load(std::memory_order_relaxed);
                });

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Completed waiting for all tasks");
            }
        }

        void ThreadPool::logThreadPoolEvent(const wchar_t* category, const wchar_t* format, ...)
        {
            if (!m_config.enableLogging) return;

            va_list args;
            va_start(args, format);
            std::wstring message = ShadowStrike::Utils::Logger::FormatMessageV(format, args);
            va_end(args);

            ShadowStrike::Utils::Logger::Instance().LogMessage(
                ShadowStrike::Utils::LogLevel::Debug,
                category,
                message
            );
        }

    } // namespace Utils
} // namespace ShadowStrike
