
/*
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

#include "ThreadPool.hpp"


namespace ShadowStrike {

	namespace Utils {

		using TimerId = uint64_t;

		//TimerManager, is a singleton class for managing the scheduled tasks
		//uses ThreadPool to execute the tasks

		class TimerManager {
		public:

			static TimerManager& Instance();

			//no copy or move
			TimerManager(const TimerManager&) = delete;
			TimerManager& operator=(const TimerManager&) = delete;
			TimerManager(TimerManager&&) = delete;
			TimerManager& operator=(TimerManager&&) = delete;

			//A threadpool starts the timermanager
			void Initialize(std::shared_ptr<ThreadPool> pool);

			void Shutdown();

			//Schedules a task to be executed after a delay
			template<typename F, typename... Args>
			TimerId runOnce(std::chrono::milliseconds delay, F&& f, Args&&... args);

			//Schedules a task to be executed periodically
			template<typename F, typename... Args>
			TimerId runPeriodic(std::chrono::milliseconds interval, F&& f, Args&&... args);

			//cancels a scheduled task
			bool cancel(TimerId id);

		private:

			//Special constructor for singleton pattern 
			TimerManager() = default;
			~TimerManager() {
				if (!m_shutdown) {
					Shutdown();
				}
			}

			struct TimerTask {
				TimerId id;
				std::chrono::steady_clock::time_point nextExecutionTime;
				std::chrono::milliseconds interval;
				bool isPeriodic;
				std::function<void()> callback;

				// Comparison operator for priority queue (min-heap based on nextExecutionTime)
				bool operator>(const TimerTask& other) const {
					return nextExecutionTime > other.nextExecutionTime;
				}
			};

			// ? FIX #NEW18: Metadata for tracking active timers (race condition protection)
			struct TimerMetadata {
				TimerId id;
				bool isPeriodic;
				std::atomic<bool> isCancelled{ false };

				// ? FIX #NEW21: Explicit constructors for atomic member
				TimerMetadata() = default;
				TimerMetadata(TimerId id_, bool periodic_, bool cancelled_)
					: id(id_), isPeriodic(periodic_), isCancelled(cancelled_) {}

				// ? FIX #NEW22: Delete copy, allow move
				TimerMetadata(const TimerMetadata&) = delete;
				TimerMetadata& operator=(const TimerMetadata&) = delete;
				TimerMetadata(TimerMetadata&& other) noexcept
					: id(other.id), isPeriodic(other.isPeriodic),
					isCancelled(other.isCancelled.load()) {}
				TimerMetadata& operator=(TimerMetadata&& other) noexcept {
					if (this != &other) {
						id = other.id;
						isPeriodic = other.isPeriodic;
						isCancelled.store(other.isCancelled.load());
					}
					return *this;
				}
			};

			//main core for the timermanager
			void managerThread();


			//adds a new timer
			TimerId addTimer(std::chrono::milliseconds delay, std::chrono::milliseconds interval, bool periodic, std::function<void()>&& callback);

			std::atomic<bool> m_shutdown{ false };
			std::thread m_managerThread;
			std::shared_ptr<ThreadPool> m_threadPool;

			std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> m_taskQueue;
			std::unordered_map<TimerId, TimerMetadata> m_activeTimers;  // ? FIX #NEW19: Track active timers
			mutable std::mutex m_mutex;
			std::condition_variable m_cv;
			std::atomic<TimerId> m_nextTimerId{ 1 };

		};

		// --- Template Implementations ---

		template<typename F, typename... Args>
		TimerId TimerManager::runOnce(std::chrono::milliseconds delay, F&& f, Args&&... args) {
			auto task = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
			return addTimer(delay, std::chrono::milliseconds(0), false, std::function<void()>(task));
		}

		template<typename F, typename... Args>
		TimerId TimerManager::runPeriodic(std::chrono::milliseconds interval, F&& f, Args&&... args) {
			auto task = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
			return addTimer(interval, interval, true, std::function<void()>(task));
		}



	}// namespace Utils
	
}// namespace ShadowStrike

*/