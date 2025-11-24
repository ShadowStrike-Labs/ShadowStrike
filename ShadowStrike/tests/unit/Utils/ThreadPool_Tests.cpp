#include <gtest/gtest.h>
#include "../../../src/Utils/ThreadPool.hpp"
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <algorithm>
#include <numeric>

using namespace ShadowStrike::Utils;
using namespace std::chrono_literals;

// ============================================================================
// Basic Functionality Tests
// ============================================================================

/**
 * @brief Test thread pool construction and basic properties
 */
TEST(ThreadPoolTest, Construction) {
    // Test default construction (uses hardware concurrency)
    ThreadPool pool1;
    EXPECT_GT(pool1.get_thread_count(), 0u);
    EXPECT_FALSE(pool1.is_shutdown());
    EXPECT_EQ(pool1.get_active_thread_count(), 0u);
    EXPECT_EQ(pool1.get_queue_size(), 0u);

    // Test construction with specific thread count
    ThreadPool pool2(4);
    EXPECT_EQ(pool2.get_thread_count(), 4u);
    EXPECT_FALSE(pool2.is_shutdown());

    // Test construction with monitoring disabled
    ThreadPool pool3(2, false);
    EXPECT_EQ(pool3.get_thread_count(), 2u);
}

/**
 * @brief Test basic task submission and execution
 */
TEST(ThreadPoolTest, BasicTaskSubmission) {
    ThreadPool pool(2);
    
    std::atomic<int> counter{0};
    
    // Submit simple task
    auto future = pool.submit([&counter]() {
        counter.fetch_add(1, std::memory_order_relaxed);
        return 42;
    });

    // Wait for result
    ASSERT_EQ(future.get(), 42);
    EXPECT_EQ(counter.load(), 1);
}

/**
 * @brief Test task submission with arguments
 */
TEST(ThreadPoolTest, TaskWithArguments) {
    ThreadPool pool(2);
    
    auto future = pool.submit([](int a, int b) {
        return a + b;
    }, 10, 32);

    EXPECT_EQ(future.get(), 42);
}

/**
 * @brief Test multiple concurrent tasks
 */
TEST(ThreadPoolTest, MultipleConcurrentTasks) {
    ThreadPool pool(4);
    
    std::atomic<int> counter{0};
    std::vector<std::future<void>> futures;

    // Submit 100 tasks
    for (int i = 0; i < 100; ++i) {
        futures.push_back(pool.submit([&counter]() {
            counter.fetch_add(1, std::memory_order_relaxed);
        }));
    }

    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.get();
    }

    EXPECT_EQ(counter.load(), 100);
}

// ============================================================================
// Priority-Based Scheduling Tests
// ============================================================================

/**
 * @brief Test priority-based task execution
 */
TEST(ThreadPoolTest, PriorityScheduling) {
    ThreadPool pool(1);  // Single thread to ensure ordering
    
    std::vector<int> execution_order;
    std::mutex order_mutex;

    // Submit tasks with different priorities
    auto low_future = pool.submit_priority(TaskPriority::LOW, [&]() {
        std::this_thread::sleep_for(10ms);  // Ensure other tasks are queued
    });

    // Give time for first task to start
    std::this_thread::sleep_for(5ms);

    // Now submit tasks that should execute in priority order
    auto normal_future = pool.submit_priority(TaskPriority::NORMAL, [&]() {
        std::lock_guard<std::mutex> lock(order_mutex);
        execution_order.push_back(2);
    });

    auto high_future = pool.submit_priority(TaskPriority::HIGH, [&]() {
        std::lock_guard<std::mutex> lock(order_mutex);
        execution_order.push_back(3);
    });

    auto critical_future = pool.submit_priority(TaskPriority::CRITICAL, [&]() {
        std::lock_guard<std::mutex> lock(order_mutex);
        execution_order.push_back(4);
    });

    // Wait for all tasks
    low_future.get();
    normal_future.get();
    high_future.get();
    critical_future.get();

    // Verify execution order (CRITICAL > HIGH > NORMAL)
    ASSERT_EQ(execution_order.size(), 3u);
    EXPECT_EQ(execution_order[0], 4);  // CRITICAL first
    EXPECT_EQ(execution_order[1], 3);  // HIGH second
    EXPECT_EQ(execution_order[2], 2);  // NORMAL third
}

/**
 * @brief Test bulk task submission
 */
TEST(ThreadPoolTest, BulkSubmission) {
    ThreadPool pool(4);
    
    std::atomic<int> counter{0};
    std::vector<std::function<void()>> tasks;

    for (int i = 0; i < 50; ++i) {
        tasks.push_back([&counter]() {
            counter.fetch_add(1, std::memory_order_relaxed);
        });
    }

    auto futures = pool.submit_bulk(TaskPriority::NORMAL, tasks);

    // Wait for all tasks
    for (auto& future : futures) {
        future.get();
    }

    EXPECT_EQ(counter.load(), 50);
}

// ============================================================================
// Exception Handling Tests
// ============================================================================

/**
 * @brief Test exception propagation through futures
 */
TEST(ThreadPoolTest, ExceptionPropagation) {
    ThreadPool pool(2);
    
    auto future = pool.submit([]() -> int {
        throw std::runtime_error("Test exception");
        return 42;
    });

    EXPECT_THROW(future.get(), std::runtime_error);
}

/**
 * @brief Test thread pool stability after task exception
 */
TEST(ThreadPoolTest, StabilityAfterException) {
    ThreadPool pool(2);
    
    // Submit task that throws
    auto future1 = pool.submit([]() {
        throw std::runtime_error("Test exception");
    });

    EXPECT_THROW(future1.get(), std::runtime_error);

    // Verify pool still works
    auto future2 = pool.submit([]() { return 42; });
    EXPECT_EQ(future2.get(), 42);
}

// ============================================================================
// Shutdown and Lifecycle Tests
// ============================================================================

/**
 * @brief Test graceful shutdown
 */
TEST(ThreadPoolTest, GracefulShutdown) {
    ThreadPool pool(2);
    
    std::atomic<int> completed{0};
    std::vector<std::future<void>> futures;

    // Submit tasks
    for (int i = 0; i < 10; ++i) {
        futures.push_back(pool.submit([&completed]() {
            std::this_thread::sleep_for(10ms);
            completed.fetch_add(1, std::memory_order_relaxed);
        }));
    }

    // Graceful shutdown (waits for tasks)
    pool.shutdown(true);

    EXPECT_TRUE(pool.is_shutdown());
    EXPECT_EQ(completed.load(), 10);  // All tasks completed
}

/**
 * @brief Test immediate shutdown
 */
TEST(ThreadPoolTest, ImmediateShutdown) {
    ThreadPool pool(2);
    
    std::atomic<int> completed{0};

    // Submit many tasks
    for (int i = 0; i < 100; ++i) {
        try {
            pool.submit([&completed]() {
                std::this_thread::sleep_for(10ms);
                completed.fetch_add(1, std::memory_order_relaxed);
            });
        } catch (const ThreadPoolShutdownException&) {
            // Expected after shutdown begins
            break;
        }
    }

    // Immediate shutdown (cancels pending)
    pool.shutdown_now();

    EXPECT_TRUE(pool.is_shutdown());
    EXPECT_LT(completed.load(), 100);  // Not all tasks completed
}

/**
 * @brief Test task submission after shutdown
 */
TEST(ThreadPoolTest, SubmitAfterShutdown) {
    ThreadPool pool(2);
    pool.shutdown(true);

    EXPECT_THROW({
        pool.submit([]() { return 42; });
    }, ThreadPoolShutdownException);
}

/**
 * @brief Test wait_for_completion with timeout
 */
TEST(ThreadPoolTest, WaitForCompletionWithTimeout) {
    ThreadPool pool(1);
    
    // Submit long-running task
    pool.submit([]() {
        std::this_thread::sleep_for(500ms);
    });

    // Wait with short timeout (should fail)
    bool completed = pool.wait_for_completion(100ms);
    EXPECT_FALSE(completed);

    // Wait with long timeout (should succeed)
    completed = pool.wait_for_completion(1000ms);
    EXPECT_TRUE(completed);
}

// ============================================================================
// Statistics and Monitoring Tests
// ============================================================================

/**
 * @brief Test statistics collection
 */
TEST(ThreadPoolTest, StatisticsCollection) {
    ThreadPool pool(4, true);  // Enable monitoring
    
    // Submit tasks
    std::vector<std::future<void>> futures;
    for (int i = 0; i < 20; ++i) {
        futures.push_back(pool.submit([]() {
            std::this_thread::sleep_for(10ms);
        }));
    }

    // Wait for completion
    for (auto& future : futures) {
        future.get();
    }

    // Get statistics
    auto stats = pool.get_statistics();
    
    EXPECT_EQ(stats.total_threads, 4u);
    EXPECT_EQ(stats.completed_tasks, 20u);
    EXPECT_EQ(stats.failed_tasks, 0u);
    EXPECT_GT(stats.avg_task_duration.count(), 0);
}

/**
 * @brief Test statistics reset
 */
TEST(ThreadPoolTest, StatisticsReset) {
    ThreadPool pool(2, true);
    
    // Submit and complete some tasks
    auto future = pool.submit([]() { return 42; });
    future.get();

    auto stats1 = pool.get_statistics();
    EXPECT_GT(stats1.completed_tasks, 0u);

    // Reset statistics
    pool.reset_statistics();

    auto stats2 = pool.get_statistics();
    EXPECT_EQ(stats2.completed_tasks, 0u);
}

/**
 * @brief Test statistics without monitoring enabled
 */
TEST(ThreadPoolTest, StatisticsWithoutMonitoring) {
    ThreadPool pool(2, false);  // Disable monitoring
    
    EXPECT_THROW({
        pool.get_statistics();
    }, std::runtime_error);
}

// ============================================================================
// Dynamic Management Tests
// ============================================================================

/**
 * @brief Test pause and unpause functionality
 */
TEST(ThreadPoolTest, PauseAndUnpause) {
    ThreadPool pool(2);
    
    std::atomic<int> counter{0};

    // Submit task
    auto future = pool.submit([&counter]() {
        counter.fetch_add(1, std::memory_order_relaxed);
    });

    future.get();
    EXPECT_EQ(counter.load(), 1);

    // Pause pool
    pool.pause();
    EXPECT_TRUE(pool.is_paused());

    // Submit task while paused
    auto future2 = pool.submit([&counter]() {
        counter.fetch_add(1, std::memory_order_relaxed);
    });

    // Give some time to ensure task doesn't execute while paused
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(counter.load(), 1);  // Task not executed yet

    // Unpause
    pool.unpause();
    EXPECT_FALSE(pool.is_paused());

    future2.get();
    EXPECT_EQ(counter.load(), 2);  // Task now executed
}

/**
 * @brief Test queue clearing
 */
TEST(ThreadPoolTest, ClearQueue) {
    ThreadPool pool(1);  // Single thread
    
    // Submit long-running task to block the thread
    pool.submit([]() {
        std::this_thread::sleep_for(200ms);
    });

    // Give time for first task to start
    std::this_thread::sleep_for(50ms);

    // Submit multiple tasks that will be queued
    for (int i = 0; i < 10; ++i) {
        pool.submit([]() {
            std::this_thread::sleep_for(10ms);
        });
    }

    // Clear the queue
    size_t cleared = pool.clear_queue();
    EXPECT_GT(cleared, 0u);
}

// ============================================================================
// Delayed Task Tests
// ============================================================================

/**
 * @brief Test delayed task execution
 */
TEST(ThreadPoolTest, DelayedTask) {
    ThreadPool pool(2);
    
    auto start_time = std::chrono::steady_clock::now();
    
    auto future = pool.submit_delayed(100ms, []() {
        return 42;
    });

    int result = future.get();
    auto elapsed = std::chrono::steady_clock::now() - start_time;

    EXPECT_EQ(result, 42);
    EXPECT_GE(elapsed, 100ms);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

/**
 * @brief Stress test with many concurrent submissions
 */
TEST(ThreadPoolTest, ConcurrentSubmissions) {
    ThreadPool pool(8);
    
    std::atomic<int> counter{0};
    std::vector<std::thread> submitter_threads;

    // Create multiple threads submitting tasks
    for (int t = 0; t < 4; ++t) {
        submitter_threads.emplace_back([&pool, &counter]() {
            for (int i = 0; i < 100; ++i) {
                pool.submit([&counter]() {
                    counter.fetch_add(1, std::memory_order_relaxed);
                });
            }
        });
    }

    // Wait for all submitter threads
    for (auto& thread : submitter_threads) {
        thread.join();
    }

    // Wait for all tasks to complete
    pool.wait_for_completion();

    EXPECT_EQ(counter.load(), 400);
}

/**
 * @brief Test move construction
 */
TEST(ThreadPoolTest, MoveConstruction) {
    ThreadPool pool1(4);
    
    auto future = pool1.submit([]() { return 42; });
    
    // Move construct
    ThreadPool pool2(std::move(pool1));
    
    EXPECT_EQ(pool2.get_thread_count(), 4u);
    EXPECT_EQ(future.get(), 42);
}

/**
 * @brief Test move assignment
 */
TEST(ThreadPoolTest, MoveAssignment) {
    ThreadPool pool1(4);
    ThreadPool pool2(2);
    
    auto future = pool1.submit([]() { return 42; });
    
    // Move assign
    pool2 = std::move(pool1);
    
    EXPECT_EQ(pool2.get_thread_count(), 4u);
    EXPECT_EQ(future.get(), 42);
}

// ============================================================================
// Edge Cases and Error Conditions
// ============================================================================

/**
 * @brief Test with zero initial threads (should use hardware concurrency)
 */
TEST(ThreadPoolTest, ZeroThreadCount) {
    ThreadPool pool(0);
    EXPECT_GT(pool.get_thread_count(), 0u);
    
    auto future = pool.submit([]() { return 42; });
    EXPECT_EQ(future.get(), 42);
}

/**
 * @brief Test queue size tracking
 */
TEST(ThreadPoolTest, QueueSizeTracking) {
    ThreadPool pool(1);  // Single thread
    
    // Submit long-running task to occupy the thread
    auto blocking_future = pool.submit([]() {
        std::this_thread::sleep_for(200ms);
    });

    // Give time for blocking task to start
    std::this_thread::sleep_for(50ms);

    // Submit tasks that will be queued
    std::vector<std::future<void>> futures;
    for (int i = 0; i < 5; ++i) {
        futures.push_back(pool.submit([]() {}));
    }

    // Check queue size
    size_t queue_size = pool.get_queue_size();
    EXPECT_GT(queue_size, 0u);

    // Wait for all tasks
    blocking_future.get();
    for (auto& future : futures) {
        future.get();
    }

    EXPECT_EQ(pool.get_queue_size(), 0u);
}

/**
 * @brief Performance benchmark test
 */
TEST(ThreadPoolTest, PerformanceBenchmark) {
    ThreadPool pool(std::thread::hardware_concurrency());
    
    const int num_tasks = 10000;
    std::atomic<int> counter{0};
    
    auto start = std::chrono::steady_clock::now();
    
    std::vector<std::future<void>> futures;
    for (int i = 0; i < num_tasks; ++i) {
        futures.push_back(pool.submit([&counter]() {
            counter.fetch_add(1, std::memory_order_relaxed);
        }));
    }

    for (auto& future : futures) {
        future.get();
    }

    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_EQ(counter.load(), num_tasks);
    
    // Log performance metrics (optional)
    std::cout << "Executed " << num_tasks << " tasks in " << ms << "ms" << std::endl;
    std::cout << "Throughput: " << (num_tasks * 1000.0 / ms) << " tasks/second" << std::endl;
}

// ============================================================================
// Main Test Entry Point
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
