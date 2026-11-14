// ============================================================================
// QuarantineTermination_Tests.cpp
//
// CanTerminateProcess decides which processes holding a file open the
// quarantine path may terminate. Two field defects shaped these tests:
//
//   task 385  the 1.0.133 VM run convicted the service's own executable, found
//             the service itself holding it open, and tried to terminate it;
//   task 387  LocalSystem processes read as not-SYSTEM, so they were terminable.
//
// Termination is never attempted here: the decision is a pure query, and the
// child used as the positive control is created suspended and terminated by
// the test itself.
// ============================================================================
#include "pch.h"
#include <gtest/gtest.h>
#include <Windows.h>
#include "../../../src/PhantomCore/Core/Engine/QuarantineManager.hpp"

namespace ShadowStrike::Core::Engine::Test {

TEST(QuarantineTerminationTest, ThisProcessIsNeverATerminationCandidate) {
    EXPECT_FALSE(CanTerminateProcess(::GetCurrentProcessId()))
        << "the quarantine path must never terminate the product itself";
}

TEST(QuarantineTerminationTest, IdleAndSystemAreNeverCandidates) {
    EXPECT_FALSE(CanTerminateProcess(0));
    EXPECT_FALSE(CanTerminateProcess(4));
}

TEST(QuarantineTerminationTest, AnOrdinaryChildProcessStaysTerminable) {
    // Positive control: the guards must not refuse every process, or locked
    // malware could never be released for quarantine.
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmd[] = L"cmd.exe /c exit 0";
    ASSERT_TRUE(::CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                                 CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                 nullptr, nullptr, &si, &pi))
        << "CreateProcessW failed: " << ::GetLastError();

    const bool terminable = CanTerminateProcess(pi.dwProcessId);

    ::TerminateProcess(pi.hProcess, 0);
    ::WaitForSingleObject(pi.hProcess, 5000);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);

    EXPECT_TRUE(terminable) << "an unprivileged child of the test was judged untouchable";
}

}  // namespace ShadowStrike::Core::Engine::Test
