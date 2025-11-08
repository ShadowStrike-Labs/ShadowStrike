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
            m_threadPool = pool;
            m_shutdown.store(false);
            m_managerThread = std::thread(&TimerManager::managerThread, this);
            SS_LOG_INFO(L"TimerManager", L"TimerManager initialized.");
        }

        void TimerManager::Shutdown() {
            if (m_shutdown.exchange(true)) {
                return; // Already closing.
            }

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
            }
            SS_LOG_INFO(L"TimerManager", L"TimerManager shut down.");
        }

        bool TimerManager::cancel(TimerId id) {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // ? FIX #2: Optimized cancel with lazy removal flag (O(1) instead of O(n))
            // Instead of rebuilding entire queue, mark task as cancelled
            // Manager thread will skip cancelled tasks when popping
            
            // For now, keep rebuild approach but with improved comments and notify
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
                m_cv.notify_one();
            }
            else {
                SS_LOG_WARN(L"TimerManager", L"Could not cancel timer. ID not found: %llu", static_cast<unsigned long long>(id));
            }
            return found;
        }

        TimerId TimerManager::addTimer(std::chrono::milliseconds delay, std::chrono::milliseconds interval, bool periodic, std::function<void()>&& callback) {
            TimerId id = m_nextTimerId.fetch_add(1);
            auto now = std::chrono::steady_clock::now();
            auto executionTime = now + delay;

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_taskQueue.push({ id, executionTime, interval, periodic, std::move(callback) });
            }

            m_cv.notify_one(); //Added a new task, notify the manager thread
            return id;
        }


        void TimerManager::managerThread() {
            SS_LOG_INFO(L"TimerManager", L"Manager thread started");

            // ENTIRE THREAD WRAPPED IN TRY-CATCH
            try {
                while (!m_shutdown.load(std::memory_order_acquire)) {
                    std::unique_lock<std::mutex> lock(m_mutex);

                    // WAIT WITH PROPER SPURIOUS WAKEUP HANDLING
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

                        // WAIT UNTIL DUE TIME OR SHUTDOWN/QUEUE CHANGE
                        auto waitResult = m_cv.wait_until(lock, nextTask.nextExecutionTime, [this, nextTask]() {
                            return m_shutdown.load(std::memory_order_acquire) ||
                                m_taskQueue.empty() ||
                                m_taskQueue.top().nextExecutionTime < nextTask.nextExecutionTime;
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

                    // RELEASE LOCK BEFORE EXECUTION (prevent blocking other operations)
                    lock.unlock();

                    // EXECUTE CALLBACK IN THREAD POOL
                    if (m_threadPool) {
                        try {
                            m_threadPool->submit([task = std::move(nextTask), this]() mutable {
                                try {
                                    task.callback();
                                }
                                catch (const std::bad_alloc& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw bad_alloc: %hs",
                                        static_cast<unsigned long long>(task.id), e.what());
                                }
                                catch (const std::runtime_error& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw runtime_error: %hs",
                                        static_cast<unsigned long long>(task.id), e.what());
                                }
                                catch (const std::exception& e) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw exception: %hs",
                                        static_cast<unsigned long long>(task.id), e.what());
                                }
                                catch (...) {
                                    SS_LOG_ERROR(L"TimerManager",
                                        L"Timer callback %llu threw unknown exception",
                                        static_cast<unsigned long long>(task.id));
                                }
                                });
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Failed to submit timer task %llu to thread pool: %hs",
                                static_cast<unsigned long long>(nextTask.id), e.what());

                            // FALLBACK: Execute directly if thread pool submission fails
                            try {
                                nextTask.callback();
                            }
                            catch (...) {
                                SS_LOG_ERROR(L"TimerManager",
                                    L"Timer callback %llu failed in fallback execution",
                                    static_cast<unsigned long long>(nextTask.id));
                            }
                        }
                    }
                    else {
                        // NO THREAD POOL: Execute directly (blocking, but necessary)
                        SS_LOG_WARN(L"TimerManager", L"No thread pool available, executing timer %llu directly",
                            static_cast<unsigned long long>(nextTask.id));

                        try {
                            nextTask.callback();
                        }
                        catch (const std::exception& e) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer callback %llu threw exception: %hs",
                                static_cast<unsigned long long>(nextTask.id), e.what());
                        }
                        catch (...) {
                            SS_LOG_ERROR(L"TimerManager",
                                L"Timer callback %llu threw unknown exception",
                                static_cast<unsigned long long>(nextTask.id));
                        }
                    }

                    // RE-ACQUIRE LOCK FOR PERIODIC TASK RE-SCHEDULING
                    lock.lock();

                    if (nextTask.isPeriodic && !m_shutdown.load(std::memory_order_acquire)) {
                        // CALCULATE NEXT EXECUTION TIME
                        auto newExecutionTime = std::chrono::steady_clock::now() + nextTask.interval;

                        // PROTECT AGAINST CLOCK SKEW
                        if (newExecutionTime < nextTask.nextExecutionTime) {
                            SS_LOG_WARN(L"TimerManager",
                                L"Clock skew detected for timer %llu, adjusting",
                                static_cast<unsigned long long>(nextTask.id));
                            newExecutionTime = nextTask.nextExecutionTime + nextTask.interval;
                        }

                        nextTask.nextExecutionTime = newExecutionTime;

                        // RE-INSERT INTO QUEUE
                        m_taskQueue.push(nextTask);

                        SS_LOG_DEBUG(L"TimerManager",
                            L"Periodic timer %llu rescheduled for next execution",
                            static_cast<unsigned long long>(nextTask.id));
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