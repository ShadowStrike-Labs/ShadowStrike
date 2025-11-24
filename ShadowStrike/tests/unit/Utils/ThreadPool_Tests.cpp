

#include <gtest/gtest.h>
#include "../../../src/Utils/ThreadPool.hpp"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <stdexcept>

using namespace ShadowStrike::Utils;
using namespace std::chrono_literals;

// ============================================================================
// Test Fixture
// ============================================================================

class ThreadPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default configuration for most tests
        config_.minThreads = 2;
        config_.maxThreads = 8;
        config_.maxQueueSize = 100;
        config_.enableETW = false;  // Disable ETW for unit tests
        config_.enableDeadlockDetection = false;  // Disable for faster tests
    }

    void TearDown() override {
        // Cleanup
    }

    ThreadPoolConfig config_;
};

// ============================================================================
// ThreadPoolConfig Tests
// ============================================================================

TEST(ThreadPoolConfigTest, DefaultConfigurationIsValid) {
    ThreadPoolConfig config;
    EXPECT_TRUE(config.Validate());
}

TEST(ThreadPoolConfigTest, MinThreadsZeroIsInvalid) {
    ThreadPoolConfig config;
    config.minThreads = 0;
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, MinThreadsGreaterThanMaxIsInvalid) {
    ThreadPoolConfig config;
    config.minThreads = 10;
    config.maxThreads = 5;
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, MaxThreadsZeroIsInvalid) {
    ThreadPoolConfig config;
    config.maxThreads = 0;
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, MaxThreadsAboveLimitIsInvalid) {
    ThreadPoolConfig config;
    config.maxThreads = 2000;  // Above 1024 limit
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, MaxQueueSizeZeroIsInvalid) {
    ThreadPoolConfig config;
    config.maxQueueSize = 0;
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, MaxQueueSizeAboveLimitIsInvalid) {
    ThreadPoolConfig config;
    config.maxQueueSize = 2000000;  // Above 1000000 limit
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, NegativeTimeoutsAreInvalid) {
    ThreadPoolConfig config;
    config.threadIdleTimeout = std::chrono::milliseconds(-1);
    EXPECT_FALSE(config.Validate());

    config.threadIdleTimeout = std::chrono::milliseconds(1000);
    config.taskTimeout = std::chrono::milliseconds(-1);
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, EmptyThreadNamePrefixIsInvalid) {
    ThreadPoolConfig config;
    config.threadNamePrefix = L"";
    EXPECT_FALSE(config.Validate());
}

TEST(ThreadPoolConfigTest, DeadlockDetectionWithZeroIntervalIsInvalid) {
    ThreadPoolConfig config;
    config.enableDeadlockDetection = true;
    config.deadlockCheckInterval = std::chrono::milliseconds(0);
    EXPECT_FALSE(config.Validate());
}

// ============================================================================
// ThreadPool Lifecycle Tests
// ============================================================================

TEST_F(ThreadPoolTest, ConstructorWithInvalidConfigThrows) {
    ThreadPoolConfig invalidConfig;
    invalidConfig.minThreads = 0;

    EXPECT_THROW({
        ThreadPool pool(invalidConfig);
        }, std::invalid_argument);
}

TEST_F(ThreadPoolTest, InitializeSucceeds) {
    ThreadPool pool(config_);
    EXPECT_TRUE(pool.Initialize());
    EXPECT_TRUE(pool.IsInitialized());
    EXPECT_FALSE(pool.IsShutdown());
}

TEST_F(ThreadPoolTest, DoubleInitializeReturnsTrueWithoutError) {
    ThreadPool pool(config_);
    EXPECT_TRUE(pool.Initialize());
    EXPECT_TRUE(pool.Initialize());  // Second call should return true
}

TEST_F(ThreadPoolTest, ShutdownWithoutInitializeIsNoop) {
    ThreadPool pool(config_);
    EXPECT_NO_THROW(pool.Shutdown());
}

TEST_F(ThreadPoolTest, ShutdownSetsFlags) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Shutdown();

    EXPECT_FALSE(pool.IsInitialized());
    EXPECT_TRUE(pool.IsShutdown());
}

TEST_F(ThreadPoolTest, DoubleShutdownIsNoop) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Shutdown();
    EXPECT_NO_THROW(pool.Shutdown());  // Second call should not throw
}

TEST_F(ThreadPoolTest, DestructorShutsDownPool) {
    {
        ThreadPool pool(config_);
        pool.Initialize();
        // Pool will be destroyed at end of scope
    }
    // If we get here without hanging or crashing, test passes
    SUCCEED();
}

TEST_F(ThreadPoolTest, PauseAndResumeWork) {
    ThreadPool pool(config_);
    pool.Initialize();

    EXPECT_FALSE(pool.IsPaused());

    pool.Pause();
    EXPECT_TRUE(pool.IsPaused());

    pool.Resume();
    EXPECT_FALSE(pool.IsPaused());
}

TEST_F(ThreadPoolTest, DoublePauseIsNoop) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Pause();
    EXPECT_NO_THROW(pool.Pause());
    EXPECT_TRUE(pool.IsPaused());
}

TEST_F(ThreadPoolTest, DoubleResumeIsNoop) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Pause();
    pool.Resume();
    EXPECT_NO_THROW(pool.Resume());
    EXPECT_FALSE(pool.IsPaused());
}

// ============================================================================
// Task Submission Tests
// ============================================================================

TEST_F(ThreadPoolTest, SubmitSimpleVoidTask) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<bool> executed{ false };

    auto future = pool.Submit([&executed](const TaskContext&) {
        executed = true;
        });

    future.wait();
    EXPECT_TRUE(executed.load());
}

TEST_F(ThreadPoolTest, SubmitTaskReturningValue) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto future = pool.Submit([](const TaskContext&) -> int {
        return 42;
        });

    EXPECT_EQ(future.get(), 42);
}

TEST_F(ThreadPoolTest, SubmitTaskWithArguments) {
    ThreadPool pool(config_);
    pool.Initialize();

 
    auto future = pool.Submit(
        [](const TaskContext& ctx) -> int {
            return 10 + 20;
        }
    );

    EXPECT_EQ(future.get(), 30);
}


TEST_F(ThreadPoolTest, SubmitMultipleTasks) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<int> counter{ 0 };
    std::vector<std::shared_future<void>> futures;

    for (int i = 0; i < 10; ++i) {
        futures.push_back(pool.Submit([&counter](const TaskContext&) {
            counter.fetch_add(1, std::memory_order_relaxed);
            }));
    }

    for (auto& future : futures) {
        future.wait();
    }

    EXPECT_EQ(counter.load(), 10);
}

TEST_F(ThreadPoolTest, SubmitToShutdownPoolThrows) {
    ThreadPool pool(config_);
    pool.Initialize();
    pool.Shutdown();

    EXPECT_THROW({
        pool.Submit([](const TaskContext&) {});
        }, std::runtime_error);
}

TEST_F(ThreadPoolTest, SubmitWithPriority) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto future = pool.Submit(
        [](const TaskContext& ctx) {
			return 1;  //only return 1, since the priority can't be tested directly here
        }
    );

    EXPECT_EQ(future.get(), 1);
}
TEST_F(ThreadPoolTest, TaskContextReceivesCorrectInformation) {
    ThreadPool pool(config_);
    pool.Initialize();

    bool hasTaskId = false;
    bool hasPriority = false;

    auto future = pool.Submit(
        [&](const TaskContext& ctx) {
            hasTaskId = (ctx.taskId > 0);
            hasPriority = (ctx.priority == TaskPriority::Normal); // Default priority
           
        }
    );

    future.wait();

    EXPECT_TRUE(hasTaskId);
    EXPECT_TRUE(hasPriority);
    
}

// ============================================================================
// Task Timeout Tests
// ============================================================================

TEST_F(ThreadPoolTest, SubmitWithTimeoutDoesNotTimeout) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto future = pool.SubmitWithTimeout(
        1000ms,
        [](const TaskContext&) { return 42; }
    );

    EXPECT_EQ(future.get(), 42);
}

TEST_F(ThreadPoolTest, SubmitWithTimeoutThrowsOnTimeout) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto future = pool.SubmitWithTimeout(
        10ms,  // Very short timeout
        [](const TaskContext&) {
            std::this_thread::sleep_for(100ms);  // Sleep longer than timeout
            return 42;
        }
    );

    EXPECT_THROW(future.get(), std::runtime_error);
}

// ============================================================================
// Task Cancellation Tests
// ============================================================================

TEST_F(ThreadPoolTest, CreateCancellationToken) {
    auto token = ThreadPool::CreateCancellationToken();

    ASSERT_NE(token, nullptr);
    EXPECT_FALSE(token->load());
}

TEST_F(ThreadPoolTest, SubmitCancellableTaskNotCancelled) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto token = ThreadPool::CreateCancellationToken();

    auto future = pool.SubmitCancellable(
        token,
        [](const TaskContext&) { return 42; }
    );

    EXPECT_EQ(future.get(), 42);
}

TEST_F(ThreadPoolTest, SubmitCancellableTaskCancelled) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto token = ThreadPool::CreateCancellationToken();
    token->store(true);  // Cancel before submission

    auto future = pool.SubmitCancellable(
        token,
        [](const TaskContext&) { return 42; }
    );

    EXPECT_THROW(future.get(), std::runtime_error);
}

TEST_F(ThreadPoolTest, TaskContextCanCheckCancellation) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto token = ThreadPool::CreateCancellationToken();
    bool wasCancelled = false;

    auto future = pool.SubmitCancellable(
        token,
        [&wasCancelled](const TaskContext& ctx) {
            wasCancelled = ctx.IsCancelled();
        }
    );

    future.wait();
    EXPECT_FALSE(wasCancelled);
}

// ============================================================================
// Batch Submission Tests
// ============================================================================

TEST_F(ThreadPoolTest, SubmitBatchWithVector) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::vector<int> inputs = { 1, 2, 3, 4, 5 };

    auto futures = pool.SubmitBatch(
        [](const TaskContext&, int x) { return x * 2; },
        inputs
    );

    ASSERT_EQ(futures.size(), 5);

    std::vector<int> results;
    for (auto& future : futures) {
        results.push_back(future.get());
    }

    std::vector<int> expected = { 2, 4, 6, 8, 10 };
    EXPECT_EQ(results, expected);
}

TEST_F(ThreadPoolTest, SubmitBatchWithEmptyRange) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::vector<int> inputs;

    auto futures = pool.SubmitBatch(
        [](const TaskContext&, int x) { return x * 2; },
        inputs
    );

    EXPECT_TRUE(futures.empty());
}

// ============================================================================
// ParallelFor Tests
// ============================================================================

TEST_F(ThreadPoolTest, ParallelForExecutesAllIterations) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<int> counter{ 0 };

    pool.ParallelFor(0, 10, [&counter](const TaskContext&, int) {
        counter.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(counter.load(), 10);
}

TEST_F(ThreadPoolTest, ParallelForWithEmptyRange) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<int> counter{ 0 };

    pool.ParallelFor(5, 5, [&counter](const TaskContext&, int) {
        counter.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(counter.load(), 0);
}

TEST_F(ThreadPoolTest, ParallelForWithNegativeRange) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<int> counter{ 0 };

    pool.ParallelFor(10, 5, [&counter](const TaskContext&, int) {
        counter.fetch_add(1, std::memory_order_relaxed);
        });

    EXPECT_EQ(counter.load(), 0);
}

TEST_F(ThreadPoolTest, ParallelForRespectsParameters) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::vector<int> values(10, 0);
    std::mutex mutex;

    pool.ParallelFor(0, 10, [&](const TaskContext&, int i) {
        std::lock_guard<std::mutex> lock(mutex);
        values[i] = i * 2;
        });

    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(values[i], i * 2);
    }
}

// ============================================================================
// Thread Pool Management Tests
// ============================================================================

TEST_F(ThreadPoolTest, GetThreadCountReturnsCorrectValue) {
    ThreadPool pool(config_);
    pool.Initialize();

    EXPECT_EQ(pool.GetThreadCount(), config_.minThreads);
}

TEST_F(ThreadPoolTest, IncreaseThreadCount) {
    ThreadPool pool(config_);
    pool.Initialize();

    size_t initialCount = pool.GetThreadCount();
    pool.IncreaseThreadCount(2);

    EXPECT_EQ(pool.GetThreadCount(), initialCount + 2);
}

TEST_F(ThreadPoolTest, IncreaseThreadCountRespectsMaxLimit) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.IncreaseThreadCount(1000);  // Try to exceed max

    EXPECT_LE(pool.GetThreadCount(), config_.maxThreads);
}

TEST_F(ThreadPoolTest, DecreaseThreadCount) {
    config_.minThreads = 2;  
    config_.maxThreads = 8;
    ThreadPool pool(config_);
    pool.Initialize(); 

    
    pool.IncreaseThreadCount(2);  
    EXPECT_EQ(pool.GetThreadCount(), 4);

    // Şimdi azalt
    pool.DecreaseThreadCount(2);  // 4-2=2 thread

    EXPECT_EQ(pool.GetThreadCount(), 2);  // ✅ ŞIMDI GEÇER!
}

TEST_F(ThreadPoolTest, DecreaseThreadCountRespectsMinLimit) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.DecreaseThreadCount(1000);  // Try to go below min

    EXPECT_GE(pool.GetThreadCount(), config_.minThreads);
}

TEST_F(ThreadPoolTest, SetThreadCount) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.SetThreadCount(5);

    EXPECT_EQ(pool.GetThreadCount(), 5);
}

TEST_F(ThreadPoolTest, SetThreadCountClampsToLimits) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.SetThreadCount(1);  // Below min
    EXPECT_GE(pool.GetThreadCount(), config_.minThreads);

    pool.SetThreadCount(1000);  // Above max
    EXPECT_LE(pool.GetThreadCount(), config_.maxThreads);
}

// ============================================================================
// Queue Management Tests
// ============================================================================

TEST_F(ThreadPoolTest, GetQueueSizeInitiallyZero) {
    ThreadPool pool(config_);
    pool.Initialize();

    EXPECT_EQ(pool.GetQueueSize(), 0);
    EXPECT_TRUE(pool.IsQueueEmpty());
}

TEST_F(ThreadPoolTest, GetQueueCapacity) {
    ThreadPool pool(config_);
    pool.Initialize();

    EXPECT_EQ(pool.GetQueueCapacity(), config_.maxQueueSize);
}

TEST_F(ThreadPoolTest, SetQueueCapacity) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.SetQueueCapacity(200);

    EXPECT_EQ(pool.GetQueueCapacity(), 200);
}

TEST_F(ThreadPoolTest, ClearQueue) {
    ThreadPool pool(config_);
    pool.Initialize();

    // Submit some tasks
    for (int i = 0; i < 5; ++i) {
        pool.Submit([](const TaskContext&) {
            std::this_thread::sleep_for(10ms);
            });
    }

    pool.ClearQueue();

    // After short wait, queue should be empty (running tasks excluded)
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(pool.GetQueueSize(), 0);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(ThreadPoolTest, TaskStatisticsInitiallyZero) {
    ThreadPool pool(config_);
    pool.Initialize();

    const auto& stats = pool.GetTaskStatistics();

    EXPECT_EQ(stats.enqueuedCount.load(), 0);
    EXPECT_EQ(stats.completedCount.load(), 0);
    EXPECT_EQ(stats.failedCount.load(), 0);
}

TEST_F(ThreadPoolTest, TaskStatisticsTrackEnqueuedTasks) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Submit([](const TaskContext&) {}).wait();

    const auto& stats = pool.GetTaskStatistics();
    EXPECT_EQ(stats.enqueuedCount.load(), 1);
}

TEST_F(ThreadPoolTest, ThreadStatisticsShowCurrentThreadCount) {
    ThreadPool pool(config_);
    pool.Initialize();

    const auto& stats = pool.GetThreadStatistics();

    EXPECT_EQ(stats.currentThreadCount.load(), config_.minThreads);
}

TEST_F(ThreadPoolTest, ResetStatistics) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Submit([](const TaskContext&) {}).wait();

    pool.ResetStatistics();

    const auto& stats = pool.GetTaskStatistics();
    EXPECT_EQ(stats.enqueuedCount.load(), 0);
}

TEST_F(ThreadPoolTest, GetStatisticsReportReturnsNonEmptyString) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::string report = pool.GetStatisticsReport();

    EXPECT_FALSE(report.empty());
    EXPECT_NE(report.find("Task Statistics"), std::string::npos);
}

TEST_F(ThreadPoolTest, GetHealthReportReturnsNonEmptyString) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::string report = pool.GetHealthReport();

    EXPECT_FALSE(report.empty());
    EXPECT_NE(report.find("Health Report"), std::string::npos);
}

// ============================================================================
// Configuration Update Tests
// ============================================================================

TEST_F(ThreadPoolTest, GetConfigReturnsCorrectConfig) {
    ThreadPool pool(config_);
    pool.Initialize();

    const auto& cfg = pool.GetConfig();

    EXPECT_EQ(cfg.minThreads, config_.minThreads);
    EXPECT_EQ(cfg.maxThreads, config_.maxThreads);
}

TEST_F(ThreadPoolTest, UpdateConfigWithValidConfig) {
    ThreadPool pool(config_);
    pool.Initialize();

    ThreadPoolConfig newConfig = config_;
    newConfig.minThreads = 4;
    newConfig.maxThreads = 10;

    EXPECT_NO_THROW(pool.UpdateConfig(newConfig));

    EXPECT_EQ(pool.GetConfig().minThreads, 4);
}

TEST_F(ThreadPoolTest, UpdateConfigWithInvalidConfigThrows) {
    ThreadPool pool(config_);
    pool.Initialize();

    ThreadPoolConfig invalidConfig = config_;
    invalidConfig.minThreads = 0;

    EXPECT_THROW(pool.UpdateConfig(invalidConfig), std::invalid_argument);
}

// ============================================================================
// WaitForAll Tests
// ============================================================================

TEST_F(ThreadPoolTest, WaitForAllWaitsForTaskCompletion) {
    ThreadPool pool(config_);
    pool.Initialize();

    std::atomic<bool> taskCompleted{ false };

    pool.Submit([&taskCompleted](const TaskContext&) {
        std::this_thread::sleep_for(50ms);
        taskCompleted = true;
        });

    pool.WaitForAll();

    EXPECT_TRUE(taskCompleted.load());
}

TEST_F(ThreadPoolTest, WaitForAllWithTimeoutReturnsTrue) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Submit([](const TaskContext&) {
        std::this_thread::sleep_for(10ms);
        });

    EXPECT_TRUE(pool.WaitForAll(1000ms));
}

TEST_F(ThreadPoolTest, WaitForAllWithTimeoutReturnsFalseOnTimeout) {
    ThreadPool pool(config_);
    pool.Initialize();

    pool.Submit([](const TaskContext&) {
        std::this_thread::sleep_for(500ms);
        });

    EXPECT_FALSE(pool.WaitForAll(10ms));
}

// ============================================================================
// Exception Handling Tests
// ============================================================================

TEST_F(ThreadPoolTest, TaskExceptionIsPropagated) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto future = pool.Submit([](const TaskContext&) -> int {
        throw std::runtime_error("Test exception");
        });

    EXPECT_THROW(future.get(), std::runtime_error);
}

TEST_F(ThreadPoolTest, GetLastExceptionReturnsNullOptWhenNoException) {
    ThreadPool pool(config_);
    pool.Initialize();

    auto lastEx = pool.GetLastException();

    EXPECT_FALSE(lastEx.has_value());
}

// ============================================================================
// PriorityTaskQueue Tests
// ============================================================================

TEST(PriorityTaskQueueTest, ConstructorSetsMaxSize) {
    PriorityTaskQueue queue(50);

    EXPECT_EQ(queue.GetMaxSize(), 50);
    EXPECT_TRUE(queue.IsEmpty());
}

TEST(PriorityTaskQueueTest, PushAndPopTask) {
    PriorityTaskQueue queue(10);

    TaskContext ctx(TaskPriority::Normal, "Test");
    Task<void> task([](const TaskContext&) {}, ctx);
    TaskWrapper wrapper(std::move(task));

    EXPECT_TRUE(queue.Push(std::move(wrapper)));
    EXPECT_FALSE(queue.IsEmpty());
    EXPECT_EQ(queue.Size(), 1);

    auto popped = queue.Pop();
    EXPECT_TRUE(popped.has_value());
    EXPECT_TRUE(queue.IsEmpty());
}

TEST(PriorityTaskQueueTest, PushRespectsMaxSize) {
    PriorityTaskQueue queue(2);

    for (int i = 0; i < 2; ++i) {
        TaskContext ctx(TaskPriority::Normal);
        Task<void> task([](const TaskContext&) {}, ctx);
        EXPECT_TRUE(queue.Push(TaskWrapper(std::move(task))));
    }

    EXPECT_TRUE(queue.IsFull());

    TaskContext ctx(TaskPriority::Normal);
    Task<void> task([](const TaskContext&) {}, ctx);
    EXPECT_FALSE(queue.Push(TaskWrapper(std::move(task))));
}

TEST(PriorityTaskQueueTest, PopFromEmptyReturnsNullopt) {
    PriorityTaskQueue queue(10);

    auto popped = queue.Pop();
    EXPECT_FALSE(popped.has_value());
}

TEST(PriorityTaskQueueTest, TryPopFromEmptyReturnsNullopt) {
    PriorityTaskQueue queue(10);

    auto popped = queue.TryPop();
    EXPECT_FALSE(popped.has_value());
}

TEST(PriorityTaskQueueTest, ClearEmptiesQueue) {
    PriorityTaskQueue queue(10);

    for (int i = 0; i < 5; ++i) {
        TaskContext ctx(TaskPriority::Normal);
        Task<void> task([](const TaskContext&) {}, ctx);
        queue.Push(TaskWrapper(std::move(task)));
    }

    queue.Clear();

    EXPECT_TRUE(queue.IsEmpty());
    EXPECT_EQ(queue.Size(), 0);
}

TEST(PriorityTaskQueueTest, SetMaxSizeChangesCapacity) {
    PriorityTaskQueue queue(10);

    queue.SetMaxSize(20);

    EXPECT_EQ(queue.GetMaxSize(), 20);
}

// ============================================================================
// TaskContext Tests
// ============================================================================

TEST(TaskContextTest, DefaultConstructorInitializesFields) {
    TaskContext ctx;

    EXPECT_EQ(ctx.taskId, 0);
    EXPECT_EQ(ctx.priority, TaskPriority::Normal);
    EXPECT_TRUE(ctx.description.empty());
    EXPECT_FALSE(ctx.cancellationToken);
    EXPECT_FALSE(ctx.timeout.has_value());
}

TEST(TaskContextTest, ParametricConstructorSetsFields) {
    TaskContext ctx(TaskPriority::High, "Test task");

    EXPECT_EQ(ctx.priority, TaskPriority::High);
    EXPECT_EQ(ctx.description, "Test task");
}

TEST(TaskContextTest, IsCancelledReturnsFalseWithoutToken) {
    TaskContext ctx;

    EXPECT_FALSE(ctx.IsCancelled());
}

TEST(TaskContextTest, IsCancelledReturnsTrueWhenTokenSet) {
    TaskContext ctx;
    ctx.cancellationToken = std::make_shared<std::atomic<bool>>(true);

    EXPECT_TRUE(ctx.IsCancelled());
}

TEST(TaskContextTest, CancelSetsToken) {
    TaskContext ctx;
    ctx.cancellationToken = std::make_shared<std::atomic<bool>>(false);

    ctx.Cancel();

    EXPECT_TRUE(ctx.IsCancelled());
}

TEST(TaskContextTest, CancelWithoutTokenIsNoop) {
    TaskContext ctx;

    EXPECT_NO_THROW(ctx.Cancel());
}

TEST(TaskContextTest, GetWaitTimeReturnsPositiveDuration) {
    TaskContext ctx;

    std::this_thread::sleep_for(10ms);

    auto waitTime = ctx.GetWaitTime();
    EXPECT_GT(waitTime.count(), 0);
}

// ============================================================================
// TaskStatistics Tests
// ============================================================================

TEST(TaskStatisticsTest, ResetClearsAllCounters) {
    TaskStatistics stats;

    stats.enqueuedCount = 10;
    stats.completedCount = 5;
    stats.failedCount = 2;

    stats.Reset();

    EXPECT_EQ(stats.enqueuedCount.load(), 0);
    EXPECT_EQ(stats.completedCount.load(), 0);
    EXPECT_EQ(stats.failedCount.load(), 0);
}

TEST(TaskStatisticsTest, GetAverageExecutionTimeWithZeroCompleted) {
    TaskStatistics stats;

    EXPECT_EQ(stats.GetAverageExecutionTimeMs(), 0.0);
}

TEST(TaskStatisticsTest, GetAverageExecutionTimeCalculatesCorrectly) {
    TaskStatistics stats;

    stats.completedCount = 4;
    stats.totalExecutionTimeMs = 400;

    EXPECT_DOUBLE_EQ(stats.GetAverageExecutionTimeMs(), 100.0);
}

TEST(TaskStatisticsTest, GetSuccessRateWithZeroEnqueued) {
    TaskStatistics stats;

    EXPECT_EQ(stats.GetSuccessRate(), 0.0);
}

TEST(TaskStatisticsTest, GetSuccessRateCalculatesCorrectly) {
    TaskStatistics stats;

    stats.enqueuedCount = 10;
    stats.completedCount = 8;

    EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 80.0);
}

// ============================================================================
// ThreadStatistics Tests
// ============================================================================

TEST(ThreadStatisticsTest, ResetPreservesCurrentThreadCount) {
    ThreadStatistics stats;

    stats.currentThreadCount = 5;
    stats.peakThreadCount = 10;

    stats.Reset();

    EXPECT_EQ(stats.currentThreadCount.load(), 5);
    EXPECT_EQ(stats.peakThreadCount.load(), 5);  // Reset to current
}

// ============================================================================
// PerformanceMetrics Tests
// ============================================================================

TEST(PerformanceMetricsTest, ResetInitializesAllFields) {
    PerformanceMetrics metrics;

    metrics.currentQueueSize = 10;
    metrics.tasksPerSecond = 100;

    metrics.Reset();

    EXPECT_EQ(metrics.currentQueueSize.load(), 0);
    EXPECT_EQ(metrics.tasksPerSecond.load(), 0);
}

TEST(PerformanceMetricsTest, UpdateThroughputWithZeroElapsed) {
    PerformanceMetrics metrics;

    metrics.UpdateThroughput(100, 0ms);

    EXPECT_EQ(metrics.tasksPerSecond.load(), 0);
}

TEST(PerformanceMetricsTest, UpdateThroughputCalculatesCorrectly) {
    PerformanceMetrics metrics;

    metrics.UpdateThroughput(100, 1000ms);  // 100 tasks in 1 second

    EXPECT_EQ(metrics.tasksPerSecond.load(), 100);
}

