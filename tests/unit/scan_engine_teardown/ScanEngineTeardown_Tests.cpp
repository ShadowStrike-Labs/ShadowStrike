// ============================================================================
//  ScanEngine teardown
//
//  Covers the defect closed by task 68: a process that called
//  ScanEngine::Initialize() and exited without Shutdown() died with an access
//  violation AFTER all of its work had succeeded.
//
//  THE ROOT CAUSE, because it decides what a useful test looks like here:
//
//  ScanEngine is a function-local static. Impl::Initialize() is the first code
//  in the process to touch ExecutableAnalyzer::Instance() and
//  PhantomCortex::Instance(), so their construction COMPLETES after ScanEngine's
//  does. Block-scope statics are destroyed in reverse order of completed
//  construction, so both are destroyed BEFORE ScanEngine - and Impl::Shutdown()
//  called Instance().Shutdown() on each of them. Reached from the destructor,
//  those are dereferences of storage whose object has already been destroyed.
//
//  So the failure is not "the engine did not clean up". It is "the engine's
//  cleanup reached outside itself at a time when nothing outside itself is left".
//  The fix scopes the destructor to owned resources only.
//
//  WHY THE REAL ASSERTION HERE IS THE PROCESS EXIT CODE:
//
//  Nothing inside a test can observe a fault that happens during static
//  destruction - by then every test has reported, gtest has printed PASSED, and
//  main has returned. The only observable is the exit code, which is why this
//  defect survived: a non-zero exit with zero failing tests is the least
//  diagnosable CI failure there is.
//
//  The global environment below therefore leaves the engine INITIALIZED on
//  purpose, after all tests have run. gtest guarantees Environment::TearDown runs
//  after every suite, so this happens on every run regardless of suite ordering,
//  and phantom-tests returning 0 is the assertion. Remove the fix and this
//  executable goes back to exiting 0xC0000005 while reporting every test passed.
// ============================================================================

#include <gtest/gtest.h>

#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"

using ShadowStrike::Core::Engine::EngineConfig;
using ShadowStrike::Core::Engine::ScanEngine;

namespace {

    // No signature database: these cases are about lifecycle, and opening a 64 MB
    // database would make them about something else.
    EngineConfig LifecycleOnlyConfig() {
        EngineConfig cfg{};
        cfg.signatureDbPath.clear();
        return cfg;
    }

    // Leaves the engine initialized once all tests are done, so that process exit
    // runs the destructor with work still outstanding - the exact condition that
    // used to fault. Deliberately does NOT call Shutdown().
    class LeaveEngineInitializedAtExit : public ::testing::Environment {
    public:
        void TearDown() override {
            // The success of THIS call is the precondition for the whole guard, and it
            // is asserted rather than assumed. During development of this fix the
            // engine could not be re-initialized after a shutdown, so Initialize()
            // here returned false, the engine was not actually initialized at exit,
            // the destructor took its trivial path, and the executable exited 0 while
            // testing nothing at all. A guard that silently stops guarding is worse
            // than no guard, because it reads as evidence.
            EXPECT_TRUE(ScanEngine::Instance().Initialize(LifecycleOnlyConfig()))
                << "could not leave the engine initialized, so the process-exit "
                   "teardown path is NOT being exercised by this run";
        }
    };

    // Registered during static initialization, which runs before main and therefore
    // before RUN_ALL_TESTS.
    const auto* const kLeaveInitialized =
        ::testing::AddGlobalTestEnvironment(new LeaveEngineInitializedAtExit());

} // namespace

// ---------------------------------------------------------------------------
// Shutdown is idempotent and complete
// ---------------------------------------------------------------------------

TEST(ScanEngineTeardown, ShutdownIsIdempotent) {
    auto& engine = ScanEngine::Instance();

    ASSERT_TRUE(engine.Initialize(LifecycleOnlyConfig()));
    EXPECT_TRUE(engine.IsInitialized());

    engine.Shutdown();
    EXPECT_FALSE(engine.IsInitialized());

    // A second call must be a no-op rather than a second teardown. The destructor
    // now always calls into the same path, so if this were not idempotent every
    // properly shut down process would tear down twice at exit.
    engine.Shutdown();
    EXPECT_FALSE(engine.IsInitialized());
}

TEST(ScanEngineTeardown, ShutdownOnAnUninitializedEngineIsSafe) {
    auto& engine = ScanEngine::Instance();

    engine.Shutdown();
    ASSERT_FALSE(engine.IsInitialized());

    engine.Shutdown();
    EXPECT_FALSE(engine.IsInitialized());
}

TEST(ScanEngineTeardown, EngineCanBeReinitializedAfterShutdown) {
    auto& engine = ScanEngine::Instance();

    ASSERT_TRUE(engine.Initialize(LifecycleOnlyConfig()));
    engine.Shutdown();
    ASSERT_FALSE(engine.IsInitialized());

    // Shutdown must leave the object reusable, not merely quiet. The teardown now
    // stops the shared worker pool explicitly, so a re-Initialize has to build a
    // new one rather than hand back a pool that has already been drained and
    // joined - a pool in that state accepts no work and would make every
    // subsequent scan fail while the engine reported itself initialized.
    EXPECT_TRUE(engine.Initialize(LifecycleOnlyConfig()));
    EXPECT_TRUE(engine.IsInitialized());

    engine.Shutdown();
    EXPECT_FALSE(engine.IsInitialized());
}
