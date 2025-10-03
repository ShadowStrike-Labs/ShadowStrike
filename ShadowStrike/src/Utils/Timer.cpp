
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

            //Clear the tasks in the queue
            std::lock_guard<std::mutex> lock(m_mutex);
            while (!m_taskQueue.empty()) {
                m_taskQueue.pop();
            }
            SS_LOG_INFO(L"TimerManager", L"TimerManager shut down.");
        }

        bool TimerManager::cancel(TimerId id) {
            std::lock_guard<std::mutex> lock(m_mutex);
			//This implementation does not removes the working tasks, its only removing the tasks in the queue.
            

            bool found = false;
            std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> newQueue;
            while (!m_taskQueue.empty()) {
                TimerTask task = m_taskQueue.top();
                m_taskQueue.pop();
                if (task.id == id) {
                    found = true;
                    continue; // Bu görevi atla
                }
                newQueue.push(task);
            }
            m_taskQueue = std::move(newQueue);

            if (found) {
                SS_LOG_DEBUG(L"TimerManager", L"Cancelled timer with ID: %llu", static_cast<unsigned long long>(id));
                m_cv.notify_one(); // Kuyruk deðiþti, bekleme süresini yeniden hesapla
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
            while (!m_shutdown.load()) {
                std::unique_lock<std::mutex> lock(m_mutex);

                if (m_taskQueue.empty()) {
					//if the queue is empty, wait until a new task is added or shutdown is signaled
                    m_cv.wait(lock, [this] { return m_shutdown.load() || !m_taskQueue.empty(); });
                }
                else {
                    auto nextExecutionTime = m_taskQueue.top().nextExecutionTime;
                    auto now = std::chrono::steady_clock::now();

                    if (now >= nextExecutionTime) {
						// Get the task to execute
                        TimerTask task = m_taskQueue.top();
                        m_taskQueue.pop();
						lock.unlock(); //send the task to threadpool by unlocking the mutex

						//Send the task to threadpool
                        m_threadPool->submit([callback = task.callback]() {
                            try {
                                callback();
                            }
                            catch (const std::exception& e) {
                                SS_LOG_ERROR(L"TimerManager", L"Exception in timer callback: %hs", e.what());
                            }
                            catch (...) {
                                SS_LOG_ERROR(L"TimerManager", L"Unknown exception in timer callback.");
                            }
                            });

                        lock.lock(); //Get the mutex again.
                        if (task.isPeriodic) {
							// If its periodic, calculate the other execution time and re-add to the queue.
                            task.nextExecutionTime += task.interval;
                            m_taskQueue.push(task);
                        }
                    }
                    else {
                        //Wait until the next tasks's execution time.
                        m_cv.wait_until(lock, nextExecutionTime, [this, nextExecutionTime] {
                            return m_shutdown.load() || m_taskQueue.empty() || m_taskQueue.top().nextExecutionTime < nextExecutionTime;
                            });
                    }
                }
            }
        }


	}//namespace Utils
}//namespace ShadowStrike