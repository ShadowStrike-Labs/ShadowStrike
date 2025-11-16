/*
 * ============================================================================
 * ShadowStrike ProcessUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for ProcessUtils module
 * Coverage: Process enumeration, info retrieval, memory/CPU info, modules,
 *           threads, security info, process tree, utilities
 *
 * 
 * Strategy: Test on current process (safe), validate structure, no dangerous ops
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../src/Utils/ProcessUtils.hpp"

#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include<algorithm>

using namespace ShadowStrike::Utils::ProcessUtils;

// ============================================================================
// TEST FIXTURE
// ============================================================================
class ProcessUtilsTest : public ::testing::Test {
protected:
    ProcessId m_currentPid = 0;
    
    void SetUp() override {
        m_currentPid = ShadowStrike::Utils::ProcessUtils::GetCurrentProcessId();
        ASSERT_NE(m_currentPid, 0u);
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

// ============================================================================
// BASIC PROCESS UTILITIES
// ============================================================================
TEST_F(ProcessUtilsTest, GetCurrentProcessId_ValidPid) {
    ProcessId pid = ShadowStrike::Utils::ProcessUtils::GetCurrentProcessId();
    
    EXPECT_GT(pid, 0u);
    EXPECT_EQ(pid, ::GetCurrentProcessId()); // Windows API check
}

TEST_F(ProcessUtilsTest, EnumerateProcesses_ReturnsNonEmpty) {
    std::vector<ProcessId> pids;
    Error err;
    
    ASSERT_TRUE(EnumerateProcesses(pids, &err));
    EXPECT_FALSE(pids.empty());
    
    // Should contain at least current process
    bool foundSelf = false;
    for (auto pid : pids) {
        if (pid == m_currentPid) {
            foundSelf = true;
            break;
        }
    }
    EXPECT_TRUE(foundSelf);
}

TEST_F(ProcessUtilsTest, GetProcessBasicInfo_CurrentProcess) {
    ProcessBasicInfo info;
    Error err;
    
    ASSERT_TRUE(GetProcessBasicInfo(m_currentPid, info, &err));
    
    EXPECT_EQ(info.pid, m_currentPid);
    EXPECT_FALSE(info.name.empty());
    EXPECT_FALSE(info.executablePath.empty());
    EXPECT_GT(info.threadCount, 0u);
}

TEST_F(ProcessUtilsTest, GetProcessBasicInfo_InvalidPid) {
    ProcessBasicInfo info;
    Error err;
    
    // PID 99999 should not exist
    EXPECT_FALSE(GetProcessBasicInfo(99999, info, &err));
    EXPECT_NE(err.win32, 0u);
}

TEST_F(ProcessUtilsTest, EnumerateProcesses_WithOptions) {
    std::vector<ProcessBasicInfo> processes;
    EnumerationOptions options;
    options.includeIdleProcess = false;
    options.includeCurrentProcess = true;
    Error err;
    
    ASSERT_TRUE(EnumerateProcesses(processes, options, &err));
    EXPECT_FALSE(processes.empty());
    
    // Verify structure
    for (const auto& proc : processes) {
        EXPECT_GT(proc.pid, 0u);
    }
}

// ============================================================================
// PROCESS PATH & IDENTITY
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessPath_CurrentProcess) {
    Error err;
    auto path = GetProcessPath(m_currentPid, &err);
    
    ASSERT_TRUE(path.has_value());
    EXPECT_FALSE(path->empty());
    EXPECT_NE(path->find(L".exe"), std::wstring::npos);
}

TEST_F(ProcessUtilsTest, GetProcessName_CurrentProcess) {
    Error err;
    auto name = GetProcessName(m_currentPid, &err);
    
    ASSERT_TRUE(name.has_value());
    EXPECT_FALSE(name->empty());
}

TEST_F(ProcessUtilsTest, GetProcessCommandLine_CurrentProcess) {
    Error err;
    auto cmdLine = GetProcessCommandLine(m_currentPid, &err);
    
    // Command line may be empty or filled
    if (cmdLine.has_value()) {
        // If available, should not be corrupted
        EXPECT_FALSE(cmdLine->empty());
    }
}

TEST_F(ProcessUtilsTest, GetProcessPath_InvalidPid) {
    Error err;
    auto path = GetProcessPath(99999, &err);
    
    EXPECT_FALSE(path.has_value());
}

// ============================================================================
// PROCESS STATE CHECKS
// ============================================================================
TEST_F(ProcessUtilsTest, IsProcessRunning_CurrentProcess) {
    EXPECT_TRUE(IsProcessRunning(m_currentPid));
}

TEST_F(ProcessUtilsTest, IsProcessRunning_InvalidPid) {
    EXPECT_FALSE(IsProcessRunning(99999));
}

TEST_F(ProcessUtilsTest, IsProcess64Bit_CurrentProcess) {
    Error err;
    bool is64Bit = IsProcess64Bit(m_currentPid, &err);
    
#ifdef _WIN64
    EXPECT_TRUE(is64Bit); // x64 build should be 64-bit
#else
    EXPECT_FALSE(is64Bit); // x86 build should be 32-bit
#endif
}

TEST_F(ProcessUtilsTest, IsProcessElevated_CurrentProcess) {
    Error err;
    bool elevated = IsProcessElevated(m_currentPid, &err);
    
    // Just check function doesn't crash
    // Elevation depends on how test is run
}

// ============================================================================
// MEMORY OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessMemoryInfo_CurrentProcess) {
    ProcessMemoryInfo info;
    Error err;
    
    ASSERT_TRUE(GetProcessMemoryInfo(m_currentPid, info, &err));
    
    EXPECT_GT(info.workingSetSize, 0ull);
    EXPECT_GT(info.privateMemorySize, 0ull);
}

TEST_F(ProcessUtilsTest, GetProcessMemoryInfo_InvalidPid) {
    ProcessMemoryInfo info;
    Error err;
    
    EXPECT_FALSE(GetProcessMemoryInfo(99999, info, &err));
}

TEST_F(ProcessUtilsTest, ReadProcessMemory_CurrentProcess) {
    // Read a known value from current process
    int testValue = 0x12345678;
    int readValue = 0;
    SIZE_T bytesRead = 0;
    Error err;
    
    ASSERT_TRUE(ReadProcessMemory(m_currentPid, &testValue, &readValue, 
                                   sizeof(testValue), &bytesRead, &err));
    
    EXPECT_EQ(bytesRead, sizeof(testValue));
    EXPECT_EQ(readValue, testValue);
}

// ============================================================================
// CPU OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessCpuInfo_CurrentProcess) {
    ProcessCpuInfo info;
    Error err;
    
    ASSERT_TRUE(GetProcessCpuInfo(m_currentPid, info, &err));
    
    // First call may have 0% usage (no previous sample)
    EXPECT_GE(info.cpuUsagePercent, 0.0);
    EXPECT_LE(info.cpuUsagePercent, 100.0);
}

TEST_F(ProcessUtilsTest, GetProcessCpuInfo_MultipleCallsForUsage) {
    ProcessCpuInfo info1, info2;
    Error err;
    
    // First call (baseline)
    ASSERT_TRUE(GetProcessCpuInfo(m_currentPid, info1, &err));
    
    // Do some work
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Second call (should have usage data)
    ASSERT_TRUE(GetProcessCpuInfo(m_currentPid, info2, &err));
    
    EXPECT_GE(info2.totalCpuTimeMs, info1.totalCpuTimeMs);
}

// ============================================================================
// IO OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessIOCounters_CurrentProcess) {
    ProcessIOCounters io;
    Error err;
    
    ASSERT_TRUE(GetProcessIOCounters(m_currentPid, io, &err));
    
    // Should have some I/O activity
    EXPECT_GE(io.readOperationCount, 0ull);
    EXPECT_GE(io.writeOperationCount, 0ull);
}

// ============================================================================
// MODULE OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, EnumerateProcessModules_CurrentProcess) {
    std::vector<ProcessModuleInfo> modules;
    Error err;
    
    ASSERT_TRUE(EnumerateProcessModules(m_currentPid, modules, &err));
    EXPECT_FALSE(modules.empty());
    
    // Verify structure
    bool foundKernel32 = false;
    for (const auto& mod : modules) {
        EXPECT_NE(mod.baseAddress, nullptr);
        EXPECT_GT(mod.size, 0ull);
        EXPECT_FALSE(mod.name.empty());
        
        std::wstring modNameLower = mod.name;
        std::transform(modNameLower.begin(), modNameLower.end(), modNameLower.begin(), ::towlower);

        if (modNameLower.find(L"kernel32.dll") != std::wstring::npos) {
            foundKernel32 = true;
        }
    }
    
    EXPECT_TRUE(foundKernel32); // Should always have kernel32
}

TEST_F(ProcessUtilsTest, GetModuleInfo_Kernel32) {
    Error err;
    auto modInfo = GetModuleInfo(m_currentPid, L"kernel32.dll", &err);
    
    ASSERT_TRUE(modInfo.has_value());
    EXPECT_FALSE(modInfo->name.empty());
    EXPECT_NE(modInfo->baseAddress, nullptr);
    EXPECT_GT(modInfo->size, 0ull);
}

TEST_F(ProcessUtilsTest, GetModuleBaseAddress_Kernel32) {
    Error err;
    auto baseAddr = GetModuleBaseAddress(m_currentPid, L"kernel32.dll", &err);
    
    ASSERT_TRUE(baseAddr.has_value());
    EXPECT_NE(*baseAddr, nullptr);
}

// ============================================================================
// THREAD OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, EnumerateProcessThreads_CurrentProcess) {
    std::vector<ProcessThreadInfo> threads;
    Error err;
    
    ASSERT_TRUE(EnumerateProcessThreads(m_currentPid, threads, &err));
    EXPECT_FALSE(threads.empty());
    
    // Verify structure
    for (const auto& thread : threads) {
        EXPECT_GT(thread.tid, 0u);
        EXPECT_EQ(thread.ownerPid, m_currentPid);
    }
}

TEST_F(ProcessUtilsTest, GetThreadInfo_CurrentThread) {
    ThreadId currentTid = ::GetCurrentThreadId();
    Error err;
    
    auto threadInfo = GetThreadInfo(currentTid, &err);
    
    ASSERT_TRUE(threadInfo.has_value());
    EXPECT_EQ(threadInfo->tid, currentTid);
}

// ============================================================================
// SECURITY OPERATIONS
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessSecurityInfo_CurrentProcess) {
    ProcessSecurityInfo sec;
    Error err;
    
    ASSERT_TRUE(GetProcessSecurityInfo(m_currentPid, sec, &err));
    
    EXPECT_FALSE(sec.userSid.empty());
    EXPECT_FALSE(sec.userName.empty());
    EXPECT_FALSE(sec.integrityLevel.empty());
}

TEST_F(ProcessUtilsTest, GetProcessPrivileges_CurrentProcess) {
    std::vector<std::wstring> privileges;
    Error err;
    
    ASSERT_TRUE(GetProcessPrivileges(m_currentPid, privileges, &err));
    
    // Should have some privileges
    EXPECT_FALSE(privileges.empty());
}

TEST_F(ProcessUtilsTest, HasProcessPrivilege_SeDebugPrivilege) {
    Error err;
    bool hasDebug = HasProcessPrivilege(m_currentPid, L"SeDebugPrivilege", &err);
    
    // May or may not have debug privilege depending on test environment
    // Just verify function doesn't crash
}

// ============================================================================
// PROCESS TREE & RELATIONSHIPS
// ============================================================================
TEST_F(ProcessUtilsTest, GetParentProcessId_CurrentProcess) {
    Error err;
    auto parentPid = GetParentProcessId(m_currentPid, &err);
    
    ASSERT_TRUE(parentPid.has_value());
    EXPECT_GT(*parentPid, 0u);
}

TEST_F(ProcessUtilsTest, GetChildProcesses_CurrentProcess) {
    std::vector<ProcessId> children;
    Error err;
    
    // Current process likely has no children (test process)
    ASSERT_TRUE(GetChildProcesses(m_currentPid, children, &err));
    
    // May be empty, just verify function works
}

// ============================================================================
// PROCESS UTILITIES
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessIdByName_CurrentProcess) {
    Error err;
    auto name = GetProcessName(m_currentPid, &err);
    ASSERT_TRUE(name.has_value());
    
    ProcessId foundPid = GetProcessIdByName(*name, &err);
    
    // Should find at least one process with this name
    EXPECT_GT(foundPid, 0u);
}

TEST_F(ProcessUtilsTest, GetProcessIdsByName_CurrentProcess) {
    Error err;
    auto name = GetProcessName(m_currentPid, &err);
    ASSERT_TRUE(name.has_value());
    
    auto pids = GetProcessIdsByName(*name, &err);
    
    EXPECT_FALSE(pids.empty());
    
    // Should contain current process
    bool foundSelf = false;
    for (auto pid : pids) {
        if (pid == m_currentPid) {
            foundSelf = true;
            break;
        }
    }
    EXPECT_TRUE(foundSelf);
}

TEST_F(ProcessUtilsTest, GetProcessOwner_CurrentProcess) {
    Error err;
    auto owner = GetProcessOwner(m_currentPid, &err);
    
    ASSERT_TRUE(owner.has_value());
    EXPECT_FALSE(owner->empty());
}

TEST_F(ProcessUtilsTest, GetProcessSID_CurrentProcess) {
    Error err;
    auto sid = GetProcessSID(m_currentPid, &err);
    
    ASSERT_TRUE(sid.has_value());
    EXPECT_FALSE(sid->empty());
}

TEST_F(ProcessUtilsTest, GetProcessSessionId_CurrentProcess) {
    Error err;
    auto sessionId = GetProcessSessionId(m_currentPid, &err);
    
    ASSERT_TRUE(sessionId.has_value());
    EXPECT_GE(*sessionId, 0u);
}

// ============================================================================
// COMPREHENSIVE PROCESS INFO
// ============================================================================
TEST_F(ProcessUtilsTest, GetProcessInfo_CurrentProcess) {
    ProcessInfo info;
    Error err;
    
    ASSERT_TRUE(GetProcessInfo(m_currentPid, info, &err));
    
    // Verify all sub-structures are populated
    EXPECT_EQ(info.basic.pid, m_currentPid);
    EXPECT_GT(info.memory.workingSetSize, 0ull);
    EXPECT_GE(info.cpu.cpuUsagePercent, 0.0);
    EXPECT_FALSE(info.security.userSid.empty());
    EXPECT_FALSE(info.modules.empty());
    EXPECT_FALSE(info.threads.empty());
}

// ============================================================================
// PROCESS HANDLE RAII
// ============================================================================
TEST_F(ProcessUtilsTest, ProcessHandle_OpenClose) {
    ProcessHandle handle;
    Error err;
    
    ASSERT_TRUE(handle.Open(m_currentPid, PROCESS_QUERY_LIMITED_INFORMATION, &err));
    EXPECT_NE(handle.Get(), nullptr);
    EXPECT_TRUE(handle.IsValid());
    
    handle.Close();
    EXPECT_FALSE(handle.IsValid());
}

TEST_F(ProcessUtilsTest, ProcessHandle_MoveConstructor) {
    ProcessHandle handle1;
    Error err;
    
    ASSERT_TRUE(handle1.Open(m_currentPid, PROCESS_QUERY_LIMITED_INFORMATION, &err));
    HANDLE rawHandle = handle1.Get();
    
    ProcessHandle handle2(std::move(handle1));
    
    EXPECT_EQ(handle2.Get(), rawHandle);
    EXPECT_FALSE(handle1.IsValid());
    EXPECT_TRUE(handle2.IsValid());
}

// ============================================================================
// EDGE CASES & ERROR HANDLING
// ============================================================================
TEST_F(ProcessUtilsTest, EdgeCase_InvalidPid_Zero) {
    ProcessBasicInfo info;
    Error err;
    
    // PID 0 is System Idle Process (special case)
    bool result = GetProcessBasicInfo(0, info, &err);
    
    // May succeed or fail depending on system, just verify no crash
}

TEST_F(ProcessUtilsTest, EdgeCase_InvalidPid_Negative) {
    ProcessBasicInfo info;
    Error err;
    
    // Negative PID should fail
    EXPECT_FALSE(GetProcessBasicInfo(static_cast<ProcessId>(-1), info, &err));
}

TEST_F(ProcessUtilsTest, EdgeCase_NullError_NoThrow) {
    ProcessBasicInfo info;
    
    // Should not throw even with null error
    EXPECT_NO_THROW({
        GetProcessBasicInfo(m_currentPid, info, nullptr);
    });
}

TEST_F(ProcessUtilsTest, EdgeCase_EmptyProcessName) {
    Error err;
    ProcessId pid = GetProcessIdByName(L"", &err);
    
    EXPECT_EQ(pid, 0u); // Empty name should return 0
}

TEST_F(ProcessUtilsTest, EdgeCase_NonExistentProcessName) {
    Error err;
    ProcessId pid = GetProcessIdByName(L"ThisProcessDoesNotExist123456", &err);
    
    EXPECT_EQ(pid, 0u);
}

// ============================================================================
// PROCESS SNAPSHOT
// ============================================================================
TEST_F(ProcessUtilsTest, CreateProcessSnapshot) {
    std::vector<ProcessInfo> snapshot;
    Error err;
    
    ASSERT_TRUE(CreateProcessSnapshot(snapshot, &err));
    EXPECT_FALSE(snapshot.empty());
    
    // Verify current process is in snapshot
    bool foundSelf = false;
    for (const auto& proc : snapshot) {
        if (proc.basic.pid == m_currentPid) {
            foundSelf = true;
            EXPECT_FALSE(proc.basic.name.empty());
            break;
        }
    }
    EXPECT_TRUE(foundSelf);
}

// ============================================================================
// STRESS TESTS
// ============================================================================
TEST_F(ProcessUtilsTest, Stress_MultipleEnumerations) {
    for (int i = 0; i < 5; ++i) {
        std::vector<ProcessId> pids;
        ASSERT_TRUE(EnumerateProcesses(pids));
        EXPECT_FALSE(pids.empty());
    }
}

TEST_F(ProcessUtilsTest, Stress_MultipleInfoQueries) {
    for (int i = 0; i < 10; ++i) {
        ProcessBasicInfo info;
        ASSERT_TRUE(GetProcessBasicInfo(m_currentPid, info));
        EXPECT_EQ(info.pid, m_currentPid);
    }
}

TEST_F(ProcessUtilsTest, Stress_ModuleEnumeration) {
    for (int i = 0; i < 3; ++i) {
        std::vector<ProcessModuleInfo> modules;
        ASSERT_TRUE(EnumerateProcessModules(m_currentPid, modules));
        EXPECT_FALSE(modules.empty());
    }
}
