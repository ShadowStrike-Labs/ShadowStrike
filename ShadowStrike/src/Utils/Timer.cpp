
/*
#if !defined(_X86_) && !defined(_AMD64_)
#ifdef _M_X64
#define _AMD64_
#elif defined(_M_IX86)
#define _X86_
#else
#error "Unknown architecture, please compile for x86 or x64"
#endif
#endif

#include"Timer.hpp"
#include"Logger.hpp"

#include <unordered_map>  

namespace ShadowStrike {

	namespace Utils {
		TimerManager& TimerManager::Instance() {
			static TimerManager instance;
			return instance;
		}


        void TimerManager::Initialize(std::shared_ptr<ThreadPool> pool) {
            if (!pool) {
                throw std::invalid_argument("ThreadPool pointer cannot be null for TimerManager initialization.");
            }
            
            // ? FIX #NEW2: Check if already initialized
            if (m_managerThread.joinable()) {
                SS_LOG_WARN(L"TimerManager", L"Already initialized, ignoring duplicate initialization");
                return;
            }
            
            m_threadPool = pool;
            m_shutdown.store(false, std::memory_order_release);
            m_managerThread = std::thread(&TimerManager::managerThread, this);
            SS_LOG_INFO(L"TimerManager", L"TimerManager initialized.");
        }

        void TimerManager::Shutdown() {
            if (m_shutdown.exchange(true, std::memory_order_acq_rel)) {
                return; // Already closing.
            }

            // ? FIX #NEW3: Wake up manager thread BEFORE join
            m_cv.notify_one();
            
            if (m_managerThread.joinable()) {
                m_managerThread.join();
            }

            // ? FIX #3: Clear the tasks with proper mutex lock
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                while (!m_taskQueue.empty()) {
                    m_taskQueue.pop();
                }
                // ? FIX #NEW4: Clear active timer map
                m_activeTimers.clear();
            }
            SS_LOG_INFO(L"TimerManager", L"TimerManager shut down.");
        }

        bool TimerManager::cancel(TimerId id) {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // ? FIX #NEW5: Check if timer exists in active map first
            auto it = m_activeTimers.find(id);
            if (it == m_activeTimers.end()) {
                SS_LOG_WARN(L"TimerManager", L"Timer ID %llu not found (already executed or cancelled)", 
                           static_cast<unsigned long long>(id));
                return false;
            }
            
            // ? FIX #NEW6: Mark as cancelled in map (thread-safe)
            it->second.isCancelled = true;
            
            // ? FIX #2: Optimized cancel - rebuild queue excluding cancelled timer
            bool found = false;
            std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> newQueue;
            
            while (!m_taskQueue.empty()) {
                TimerTask task = m_taskQueue.top();
                m_taskQueue.pop();
                
                if (task.id == id) {
                    found = true;
                    // Skip this task (don't add to new queue)
                    continue;
                }
                newQueue.push(std::move(task));
            }
            
            m_taskQueue = std::move(newQueue);

            if (found) {
                SS_LOG_DEBUG(L"TimerManager", L"Cancelled timer with ID: %llu", static_cast<unsigned long long>(id));
                m_cv.notify_one();  // Wake manager thread to re-evaluate
            }
            
            return found;
        }

        TimerId TimerManager::addTimer(std::chrono::milliseconds delay, std::chrono::milliseconds interval, bool periodic, std::function<void()>&& callback) {
            TimerId id = m_nextTimerId.fetch_add(1, std::memory_order_relaxed);
            auto now = std::chrono::steady_clock::now();
            auto executionTime = now + delay;

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                
                // ? FIX #NEW7: Track timer in active map (use emplace to avoid copy)
                m_activeTimers.emplace(id, TimerMetadata{ id, periodic, false });
                
                m_taskQueue.push({ id, executionTime, interval, periodic, std::move(callback) });
            }

            m_cv.notify_one(); // Added a new task, notify the manager thread
            return id;
        }


        void TimerManager::managerThread() {
            SS_LOG_INFO(L"TimerManager", L"Manager thread started");

            // ENTIRE THREAD WRAPPED IN TRY-CATCH
            try {
                while (!m_shutdown.load(std::memory_order_acquire)) {
                    std::unique_lock<std::mutex> lock(m_mutex);

                    // ? FIX #NEW8: Enhanced wait with spurious wakeup protection
                    if (m_taskQueue.empty()) {
                        m_cv.wait(lock, [this]() {
                            return m_shutdown.load(std::memory_order_acquire) ||
                                !m_taskQueue.empty();
                            });

                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break; // Exit cleanly on shutdown
                        }

                        continue;
                    }

                    auto now = std::chrono::steady_clock::now();

                    // PEEK AT TOP TASK (don't pop yet - might change)
                    TimerTask nextTask = m_taskQueue.top();

                    // ? FIX #NEW9: Check if task is cancelled before processing
                    {
                        auto it = m_activeTimers.find(nextTask.id);
                        if (it != m_activeTimers.end() && it->second.isCancelled) {
                            // Task was cancelled, remove from queue
                            m_taskQueue.pop();
                            m_activeTimers.erase(it);
                            SS_LOG_DEBUG(L"TimerManager", L"Skipping cancelled timer %llu", 
                                       static_cast<unsigned long long>(nextTask.id));
                            continue;
                        }
                    }

                    // CHECK IF TASK IS DUE
                    if (nextTask.nextExecutionTime > now) {
                        auto waitTime = nextTask.nextExecutionTime - now;

                        // LIMIT MAXIMUM WAIT TIME (prevent issues if system clock changes)
                        constexpr auto MAX_WAIT = std::chrono::minutes(5);
                        if (waitTime > MAX_WAIT) {
                            waitTime = MAX_WAIT;
                            SS_LOG_WARN(L"TimerManager",
                                L"Task %llu wait time exceeds 5 minutes, capping to max",
                                static_cast<unsigned long long>(nextTask.id));
                        }

                        // ? FIX #NEW10: Enhanced wait_until with clock drift protection
                        auto targetTime = nextTask.nextExecutionTime;
                        auto waitResult = m_cv.wait_until(lock, targetTime, [this, nextTask, targetTime]() {
                            // Wake up if:
                            // 1. Shutdown requested
                            // 2. Queue is empty (all tasks cancelled)
                            // 3. Top task changed (higher priority inserted)
                            // 4. System clock jumped (drift detection)
                            if (m_shutdown.load(std::memory_order_acquire)) {
                                return true;
                            }
                            
                            if (m_taskQueue.empty()) {
                                return true;
                            }
                            
                            auto currentTop = m_taskQueue.top();
                            if (currentTop.id != nextTask.id) {
                                return true;  // Different task on top
                            }
                            
                            // ? FIX #NEW11: Detect clock drift (system time jumped)
                            auto nowCheck = std::chrono::steady_clock::now();
                            if (nowCheck < targetTime && 
                                (targetTime - nowCheck) > std::chrono::hours(1)) {
                                // Clock went backwards significantly, wake up
                                SS_LOG_WARN(L"TimerManager", L"Clock drift detected for timer %llu",
                                          static_cast<unsigned long long>(nextTask.id));
                                return true;
                            }
                            
                            return false;
                        });

                        if (m_shutdown.load(std::memory_order_acquire)) {
                            break; // Shutdown requested
                        }

                        // RE-CHECK AFTER WAKE (queue might have changed)
                        now = std::chrono::steady_clock::now();
                        if (m_taskQueue.empty()) {
                            continue; // Queue was cleared, restart loop
                        }

                        // ? FIX #4: RE-PEEK with empty check (different task might be on top now)
                        if (m_taskQueue.empty()) {
                            continue; // Double-check: queue might have been cleared
                        }

                        TimerTask currentTop = m_taskQueue.top();
                        
                        // ? FIX #NEW12: Verify task wasn't cancelled during wait
                        {
                            auto it = m_activeTimers.find(currentTop.id);
                            if (it != m_activeTimers.end() && it->second.isCancelled) {
                                m_taskQueue.pop();
                                m_activeTimers.erase(it);
                                SS_LOG_DEBUG(L"TimerManager", L"Timer %llu was cancelled during wait",
                                           static_cast<unsigned long long>(currentTop.id));
                                continue;
                            }
                        }
                        
                        if (currentTop.id != nextTask.id) {
                            // Different task is now on top, restart loop
                            continue;
                        }

                        if (currentTop.nextExecutionTime > now) {
                            // Still not due, wait again
                            continue;
                        }

                        // Task is due, proceed to execution
                        nextTask = currentTop;
                    }

                    // NOW POP THE TASK (it's definitely due)
                    m_taskQueue.pop();

                    // ? FIX #NEW13: Create a copy for execution (avoid use-after-free if cancelled)
                    TimerTask executingTask = nextTask;

                    // RELEASE LOCK BEFORE EXECUTION (prevent blocking other operations)
                    lock.unlock();

                    // ? FIX #NEW14: Final cancellation check before execution
                    bool shouldExecute = true;
                    {
                        std::lock_guard<std::mutex> checkLock(m_mutex);
                        auto it = m_activeTimers.find(executingTask.id);
                        if (it != m_activeTimers.end() && it->second.isCancelled) {
                            shouldExecute = false;
                            m_activeTimers.erase(it);
                            SS_LOG_DEBUG(L"TimerManager", L"Timer %llu cancelled just before execution",
                                       static_cast<unsigned long long>(executingTask.id));
                        }
                    }

                    if (!shouldExecute) {
                        continue;  // Skip execution, timer was cancelled
                    }

                    // EXECUTE CALLBACK IN THREAD POOL
                    if (m_threadPool) {
                        try {
                            m_threadPool->submit([executingTask, this]() mutable {
                                try {
                                    executingTask.callback();
                                }
                                catch (const std::bad_alloc& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw bad_alloc: %hs",
                                        static_cast<unsigned long long>(executingTask.id), e.what());
                                }
                                catch (const std::runtime_error& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw runtime_error: %hs",
                                        static_cast<unsigned long long>(executingTask.id), e.what());
                                }
                                catch (const std::exception& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw exception: %hs",
                                        static_cast<unsigned long long>(executingTask.id), e.what());
                                }
                                catch (...) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw unknown exception",
                                        static_cast<unsigned long long>(executingTask.id));
                                }
                                });
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Failed to submit timer task %llu to thread pool: %hs",
                                static_cast<unsigned long long>(executingTask.id), e.what());

                            // FALLBACK: Execute directly if thread pool submission fails
                            try {
                                executingTask.callback();
                            }
                            catch (...) {
                                SS_LOG_ERROR(L"TimerManager",
                                    L"Timer callback %llu failed in fallback execution",
                                    static_cast<unsigned long long>(executingTask.id));
                            }
                        }
                    }
                    else {
                        // NO THREAD POOL: Execute directly (blocking, but necessary)
                        SS_LOG_WARN(L"TimerManager", L"No thread pool available, executing timer %llu directly",
                            static_cast<unsigned long long>(executingTask.id));

                        try {
                            executingTask.callback();
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer callback %llu threw exception: %hs",
                                static_cast<unsigned long long>(executingTask.id), e.what());
                        }
                        catch (...) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer callback %llu threw unknown exception",
                                static_cast<unsigned long long>(executingTask.id));
                        }
                    }

                    // RE-ACQUIRE LOCK FOR PERIODIC TASK RE-SCHEDULING
                    lock.lock();

                    // ? FIX #NEW15: Only reschedule if not cancelled and not shutting down
                    bool shouldReschedule = false;
                    {
                        auto it = m_activeTimers.find(executingTask.id);
                        shouldReschedule = (executingTask.isPeriodic && 
                                          !m_shutdown.load(std::memory_order_acquire) &&
                                          it != m_activeTimers.end() &&
                                          !it->second.isCancelled);
                    }

                    if (shouldReschedule) {
                        // CALCULATE NEXT EXECUTION TIME
                        auto newExecutionTime = std::chrono::steady_clock::now() + executingTask.interval;

                        // ? FIX #NEW16: Protect against clock skew with drift tolerance
                        constexpr auto MAX_DRIFT = std::chrono::seconds(60);
                        if (newExecutionTime < executingTask.nextExecutionTime) {
                            auto drift = executingTask.nextExecutionTime - newExecutionTime;
                            if (drift > MAX_DRIFT) {
                                SS_LOG_WARN(L"TimerManager",
                                    L"Severe clock skew detected for timer %llu, using interval from now",
                                    static_cast<unsigned long long>(executingTask.id));
                                // Use current time as base
                            } else {
                                // Minor drift, use previous time as base
                                newExecutionTime = executingTask.nextExecutionTime + executingTask.interval;
                            }
                        }

                        executingTask.nextExecutionTime = newExecutionTime;

                        // RE-INSERT INTO QUEUE
                        m_taskQueue.push(executingTask);

                        SS_LOG_DEBUG(L"TimerManager",
                            L"Periodic timer %llu rescheduled for next execution",
                            static_cast<unsigned long long>(executingTask.id));
                    } else {
                        // ? FIX #NEW17: Remove from active timers if not rescheduling
                        auto it = m_activeTimers.find(executingTask.id);
                        if (it != m_activeTimers.end()) {
                            m_activeTimers.erase(it);
                            SS_LOG_DEBUG(L"TimerManager", L"Timer %llu completed and removed",
                                       static_cast<unsigned long long>(executingTask.id));
                        }
                    }

                    lock.unlock();

                    // YIELD TO PREVENT CPU SPINNING
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


	}//namespace Utils
}//namespace ShadowStrike

*/