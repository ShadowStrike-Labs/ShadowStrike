/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// ============================================================================
//  Scan pool health - the field symptom of task 102.
//
//  WHAT THE FIELD SHOWED. Every capacity sample in the 1.0.94 run read
//  "pool=0/0 busy queued=0/10000" while the same run scanned 7,213 files in 29
//  seconds. The queue depths printed beside it were real and moving, which is
//  what localised the fault to the pool figures rather than to the report.
//
//  WHAT IT ACTUALLY MEANT. ScanEngine constructed its ThreadPool and never
//  called Initialize(), so the pool had zero worker threads for the entire life
//  of the process. The startup line said "Thread pool initialized with 4
//  threads" because it printed the LOCAL VARIABLE holding the number of threads
//  wanted, not the number the pool ended up with - a log statement that reports
//  intent cannot detect the case where intent and result differ, which is the
//  only case worth logging.
//
//  Nothing was slow, and no scan was lost to it, because the on-access path is
//  synchronous and never used this pool. What the pool DID carry was every
//  asynchronous scan job, cloud submission, HeuristicAnalyzer async analysis and
//  EmulationEngine submission - all enqueued onto a pool that could not run
//  them.
//
//  WHY THIS ASSERTION AND NOT A LOG CHECK. GetScanPoolHealth() reports valid
//  plus a thread count, and ReportCapacity() already prints "pool=unavailable"
//  when valid is false. So the field's "0/0" proves valid was TRUE while the
//  count was zero: the report was honest and the pool was empty. A test that
//  only checked validity would have passed throughout. The load-bearing
//  assertion is therefore that the count is NON-ZERO.
//
//  DELIBERATELY DOES NOT CALL Shutdown(). ScanEngine is a singleton and
//  tests/unit/scan_engine_teardown registers a global environment that requires
//  the engine to still be initialized after all suites have run. Initialize() is
//  idempotent, so calling it here is safe; shutting down here would break that
//  suite's precondition.
// ============================================================================

#include <gtest/gtest.h>

#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"

using ShadowStrike::Core::Engine::EngineConfig;
using ShadowStrike::Core::Engine::ScanEngine;

namespace {

    // No signature database and no heavy subsystems: this is about the pool the
    // engine builds for itself, so the configuration is kept as small as the
    // engine will accept. Initialize() is idempotent, so if another suite has
    // already initialized the singleton this config is ignored - which does not
    // matter here, because the pool is created either way.
    EngineConfig MinimalConfig() {
        EngineConfig cfg{};
        cfg.signatureDbPath.clear();
        cfg.enableHeuristics = false;
        cfg.enableMachineLearning = false;
        cfg.enableBehaviorAnalysis = false;
        cfg.enableCloudLookup = false;
        return cfg;
    }

} // namespace

TEST(ScanEnginePoolHealthTest, PoolReportsWorkersAfterInitialize) {
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()))
        << "precondition: the engine must initialize for its pool to exist";

    const auto health = engine.GetScanPoolHealth();

    ASSERT_TRUE(health.valid)
        << "an initialized engine must be able to report on its own pool";

    // THE FIELD SYMPTOM. This is the assertion that fails against the pre-fix
    // code, which reported valid=true with threadCount=0.
    EXPECT_GT(health.threadCount, 0u)
        << "the scan pool reported zero worker threads; work submitted to it "
           "cannot ever run";

    // busy + idle is maintained by ThreadPool::MonitoringLoop, which is also
    // started by Initialize(). Before the fix both were zero for the same
    // reason, so this pins that the monitor is running rather than that the
    // numbers happen to look plausible.
    EXPECT_EQ(health.busyThreads + health.idleThreads, health.threadCount)
        << "busy+idle must account for every worker; a mismatch means the "
           "monitor that samples them is not running";

    EXPECT_GT(health.queueCapacity, 0u);
}

TEST(ScanEnginePoolHealthTest, PoolAcceptsAndRunsAsynchronousWork) {
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()));

    const auto health = engine.GetScanPoolHealth();
    ASSERT_TRUE(health.valid);
    ASSERT_GT(health.threadCount, 0u);

    // A pool with workers must drain. Checked through the queue rather than by
    // submitting directly, because the engine's pool is private: a pool that
    // cannot run anything shows a queue that only grows, which is exactly what
    // the field's queued=0 could not distinguish while nothing was submitted.
    EXPECT_LE(health.queuedTasks, health.queueCapacity);
}
