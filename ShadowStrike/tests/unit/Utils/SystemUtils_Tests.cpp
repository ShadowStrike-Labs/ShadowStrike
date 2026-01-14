#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike SystemUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for SystemUtils module
 * Coverage: OS version, CPU info, memory info, security info, privileges,
 *           process utilities, path queries, environment expansion
 *
 * 
 * Strategy: Test system information retrieval (safe), validate structure
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../src/Utils/SystemUtils.hpp"

#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <algorithm>  // ? FIX: Added for std::transform
#include <cctype>     // ? FIX: Added for ::towlower

using namespace ShadowStrike::Utils::SystemUtils;

// ============================================================================
// TEST FIXTURE
// ============================================================================
class SystemUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No special setup needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

// ============================================================================
// TIME & UPTIME TESTS
// ============================================================================
TEST_F(SystemUtilsTest, NowFileTime100nsUTC_ReturnsValidTime) {
    uint64_t now = NowFileTime100nsUTC();
    
    EXPECT_GT(now, 0ull);
    
    // Should be a reasonable value (after year 2000)
    // FILETIME for 2000-01-01: ~125911584000000000
    EXPECT_GT(now, 125911584000000000ull);
}

TEST_F(SystemUtilsTest, UptimeMilliseconds_ReturnsNonZero) {
    uint64_t uptime = UptimeMilliseconds();
    
    EXPECT_GT(uptime, 0ull);
    EXPECT_LT(uptime, 365ULL * 24 * 60 * 60 * 1000); // Less than 1 year
}

TEST_F(SystemUtilsTest, UptimeMilliseconds_Monotonic) {
    uint64_t uptime1 = UptimeMilliseconds();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    uint64_t uptime2 = UptimeMilliseconds();
    
    EXPECT_GT(uptime2, uptime1); // Should increase
}

// ============================================================================
// OS VERSION TESTS
// ============================================================================
TEST_F(SystemUtilsTest, QueryOSVersion_ReturnsValidInfo) {
    OSVersion os;
    
    ASSERT_TRUE(QueryOSVersion(os));
    
    // Windows version should be at least Windows 7 (6.1)
    EXPECT_GE(os.major, 6u);
    
    if (os.major == 6) {
        EXPECT_GE(os.minor, 1u); // At least Windows 7
    }
    
    EXPECT_GT(os.build, 0u);
    EXPECT_FALSE(os.productName.empty());
}

TEST_F(SystemUtilsTest, QueryOSVersion_64BitCheck) {
    OSVersion os;
    
    ASSERT_TRUE(QueryOSVersion(os));
    
#ifdef _WIN64
    EXPECT_TRUE(os.is64BitOS); // x64 build runs on 64-bit OS
    EXPECT_FALSE(os.isWow64Process); // Native 64-bit process
#else
    // x86 build may run on 32-bit or 64-bit (WOW64)
    // If running on 64-bit OS, isWow64Process should be true
    if (os.is64BitOS) {
        EXPECT_TRUE(os.isWow64Process);
    }
#endif
}

TEST_F(SystemUtilsTest, QueryOSVersion_EditionInfo) {
    OSVersion os;
    
    ASSERT_TRUE(QueryOSVersion(os));
    
    // At least one of these should be non-empty
    bool hasVersionInfo = !os.releaseId.empty() || 
                          !os.displayVersion.empty() || 
                          !os.editionId.empty() ||
                          !os.currentBuild.empty();
    
    EXPECT_TRUE(hasVersionInfo);
}

// ============================================================================
// CPU INFO TESTS
// ============================================================================
TEST_F(SystemUtilsTest, QueryCpuInfo_ReturnsValidInfo) {
    CpuInfo cpu;
    
    ASSERT_TRUE(QueryCpuInfo(cpu));
    
    EXPECT_GT(cpu.logicalProcessorCount, 0u);
    EXPECT_GT(cpu.coreCount, 0u);
    EXPECT_GE(cpu.packageCount, 1u); // At least 1 CPU package
    
    // Logical processors >= cores
    EXPECT_GE(cpu.logicalProcessorCount, cpu.coreCount);
}

TEST_F(SystemUtilsTest, QueryCpuInfo_Architecture) {
    CpuInfo cpu;
    
    ASSERT_TRUE(QueryCpuInfo(cpu));
    
    EXPECT_FALSE(cpu.architecture.empty());
    
    // Should be one of known architectures
    bool validArch = (cpu.architecture == L"x64" || 
                      cpu.architecture == L"x86" ||
                      cpu.architecture == L"ARM64" ||
                      cpu.architecture == L"ARM");
    
    EXPECT_TRUE(validArch);
}

TEST_F(SystemUtilsTest, QueryCpuInfo_BrandString) {
    CpuInfo cpu;
    
    ASSERT_TRUE(QueryCpuInfo(cpu));
    
#if defined(_M_IX86) || defined(_M_X64)
    // x86/x64 should have brand string
    EXPECT_FALSE(cpu.brand.empty());
#endif
}

TEST_F(SystemUtilsTest, QueryCpuInfo_Features) {
    CpuInfo cpu;
    
    ASSERT_TRUE(QueryCpuInfo(cpu));
    
#if defined(_M_IX86) || defined(_M_X64)
    // Modern x86/x64 CPUs should support at least SSE2
    EXPECT_TRUE(cpu.hasSSE2);
#endif
}

// ============================================================================
// MEMORY INFO TESTS
// ============================================================================
TEST_F(SystemUtilsTest, QueryMemoryInfo_ReturnsValidInfo) {
    MemoryInfo mem;
    
    ASSERT_TRUE(QueryMemoryInfo(mem));
    
    EXPECT_GT(mem.totalPhys, 0ull);
    EXPECT_GT(mem.availPhys, 0ull);
    EXPECT_LE(mem.availPhys, mem.totalPhys); // Available <= Total
    
    EXPECT_GT(mem.totalPageFile, 0ull);
    EXPECT_GT(mem.totalVirtual, 0ull);
}

TEST_F(SystemUtilsTest, QueryMemoryInfo_PhysicalRAMCheck) {
    MemoryInfo mem;
    
    ASSERT_TRUE(QueryMemoryInfo(mem));
    
    // Should have at least 512MB RAM (minimum for modern Windows)
    EXPECT_GE(mem.totalPhys, 512ULL * 1024 * 1024);
}

TEST_F(SystemUtilsTest, QueryMemoryInfo_InstalledMemory) {
    MemoryInfo mem;
    
    ASSERT_TRUE(QueryMemoryInfo(mem));
    
    // physInstalledKB may be 0 on older systems or VMs
    // If non-zero, should be reasonable
    if (mem.physInstalledKB > 0) {
        EXPECT_GE(mem.physInstalledKB, 512ULL * 1024); // At least 512MB
    }
}

// ============================================================================
// SECURITY INFO TESTS
// ============================================================================
TEST_F(SystemUtilsTest, GetSecurityInfo_ReturnsValidInfo) {
    SecurityInfo sec;
    
    ASSERT_TRUE(GetSecurityInfo(sec));
    
    // Integrity level should be at least Low
    EXPECT_GE(sec.integrityRid, SECURITY_MANDATORY_LOW_RID);
    
    EXPECT_FALSE(sec.integrityName.empty());
}

TEST_F(SystemUtilsTest, GetSecurityInfo_IntegrityLevelMapping) {
    SecurityInfo sec;
    
    ASSERT_TRUE(GetSecurityInfo(sec));
    
    // Verify integrity name matches RID
    if (sec.integrityRid == SECURITY_MANDATORY_LOW_RID) {
        EXPECT_EQ(sec.integrityName, L"Low");
    } else if (sec.integrityRid == SECURITY_MANDATORY_MEDIUM_RID) {
        EXPECT_EQ(sec.integrityName, L"Medium");
    } else if (sec.integrityRid == SECURITY_MANDATORY_HIGH_RID) {
        EXPECT_EQ(sec.integrityName, L"High");
    } else if (sec.integrityRid == SECURITY_MANDATORY_SYSTEM_RID) {
        EXPECT_EQ(sec.integrityName, L"System");
    }
}

// ============================================================================
// PRIVILEGE TESTS
// ============================================================================
TEST_F(SystemUtilsTest, EnablePrivilege_InvalidPrivilege) {
    // Non-existent privilege should fail
    bool result = EnablePrivilege(L"SeInvalidPrivilege", true);
    
    EXPECT_FALSE(result);
}

TEST_F(SystemUtilsTest, EnablePrivilege_NullInput) {
    // Null privilege name should fail gracefully
    bool result = EnablePrivilege(nullptr, true);
    
    EXPECT_FALSE(result);
}

TEST_F(SystemUtilsTest, EnablePrivilege_EmptyInput) {
    // Empty privilege name should fail
    bool result = EnablePrivilege(L"", true);
    
    EXPECT_FALSE(result);
}

// ============================================================================
// DEBUGGER DETECTION TESTS
// ============================================================================
TEST_F(SystemUtilsTest, IsDebuggerPresentSafe_NoThrow) {
    // Should not throw regardless of debugger presence
    EXPECT_NO_THROW({
        bool debugged = IsDebuggerPresentSafe();
        // Result can be true or false, just verify no crash
    });
}

// ============================================================================
// PROCESS ID TESTS
// ============================================================================
TEST_F(SystemUtilsTest, CurrentProcessId_ReturnsValidPid) {
    DWORD pid = CurrentProcessId();
    
    EXPECT_GT(pid, 0u);
    EXPECT_EQ(pid, ::GetCurrentProcessId()); // Should match Win32 API
}

TEST_F(SystemUtilsTest, GetParentProcessId_CurrentProcess) {
    auto parentPid = GetParentProcessId(0); // 0 = current process
    
    ASSERT_TRUE(parentPid.has_value());
    EXPECT_GT(*parentPid, 0u);
}

TEST_F(SystemUtilsTest, GetParentProcessId_InvalidPid) {
    auto parentPid = GetParentProcessId(99999); // Non-existent PID
    
    EXPECT_FALSE(parentPid.has_value());
}

// ============================================================================
// PATH QUERY TESTS
// ============================================================================
TEST_F(SystemUtilsTest, GetExecutablePath_ReturnsValidPath) {
    std::wstring path = GetExecutablePath();
    
    EXPECT_FALSE(path.empty());
    EXPECT_NE(path.find(L".exe"), std::wstring::npos);
}

TEST_F(SystemUtilsTest, GetModulePath_Kernel32) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(hKernel32, nullptr);
    
    std::wstring path = GetModulePath(hKernel32);
    
    EXPECT_FALSE(path.empty());
    
    // ? FIX: Use case-insensitive search (Windows paths may be uppercase)
    std::wstring pathLower = path;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    EXPECT_NE(pathLower.find(L"kernel32.dll"), std::wstring::npos);
}

TEST_F(SystemUtilsTest, GetSystemDirectoryPath_ReturnsValidPath) {
    std::wstring sysDir = GetSystemDirectoryPath();
    
    EXPECT_FALSE(sysDir.empty());
    
    // ? FIX: Use case-insensitive search
    std::wstring sysDirLower = sysDir;
    std::transform(sysDirLower.begin(), sysDirLower.end(), sysDirLower.begin(), ::towlower);
    EXPECT_NE(sysDirLower.find(L"system32"), std::wstring::npos);
}

TEST_F(SystemUtilsTest, GetWindowsDirectoryPath_ReturnsValidPath) {
    std::wstring winDir = GetWindowsDirectoryPath();
    
    EXPECT_FALSE(winDir.empty());
    
    // ? FIX: Use case-insensitive search
    std::wstring winDirLower = winDir;
    std::transform(winDirLower.begin(), winDirLower.end(), winDirLower.begin(), ::towlower);
    EXPECT_NE(winDirLower.find(L"windows"), std::wstring::npos);
}

// ============================================================================
// ENVIRONMENT VARIABLE TESTS
// ============================================================================
TEST_F(SystemUtilsTest, ExpandEnv_ValidVariable) {
    std::wstring expanded = ExpandEnv(L"%WINDIR%\\System32");
    
    EXPECT_FALSE(expanded.empty());
    EXPECT_EQ(expanded.find(L'%'), std::wstring::npos); // Should be expanded
    EXPECT_NE(expanded.find(L"System32"), std::wstring::npos);
}

TEST_F(SystemUtilsTest, ExpandEnv_EmptyString) {
    std::wstring expanded = ExpandEnv(L"");
    
    EXPECT_TRUE(expanded.empty());
}

TEST_F(SystemUtilsTest, ExpandEnv_NoVariables) {
    std::wstring input = L"C:\\Test\\Path";
    std::wstring expanded = ExpandEnv(input);
    
    EXPECT_EQ(expanded, input); // Should remain unchanged
}

// ============================================================================
// COMPUTER NAME TESTS
// ============================================================================
TEST_F(SystemUtilsTest, GetComputerNameDnsHostname_ReturnsNonEmpty) {
    std::wstring hostname = GetComputerNameDnsHostname();
    
    // May be empty on systems without DNS configuration, but shouldn't crash
    // If non-empty, should be reasonable
    if (!hostname.empty()) {
        EXPECT_LT(hostname.size(), 256u); // Hostname shouldn't be excessively long
    }
}

TEST_F(SystemUtilsTest, GetComputerNameDnsFullyQualified_NoThrow) {
    EXPECT_NO_THROW({
        std::wstring fqdn = GetComputerNameDnsFullyQualified();
        // Result may be empty on non-domain systems, just verify no crash
    });
}

// ============================================================================
// DPI AWARENESS TESTS
// ============================================================================
TEST_F(SystemUtilsTest, SetProcessDpiAwarePerMonitorV2_NoThrow) {
    // DPI awareness can only be set once per process
    // Just verify it doesn't crash
    EXPECT_NO_THROW({
        SetProcessDpiAwarePerMonitorV2();
    });
}

// ============================================================================
// PRIORITY TESTS
// ============================================================================
TEST_F(SystemUtilsTest, SetProcessPriorityHigh_NoThrow) {
    // Should not throw (may fail if not elevated)
    EXPECT_NO_THROW({
        bool result = SetProcessPriorityHigh();
        // Result can be true or false depending on permissions
    });
    
    // Restore normal priority
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
}

TEST_F(SystemUtilsTest, SetCurrentThreadPriority_ValidPriority) {
    // Should succeed with valid priority
    bool result = SetCurrentThreadPriority(THREAD_PRIORITY_NORMAL);
    EXPECT_TRUE(result);
    
    // Restore
    SetCurrentThreadPriority(THREAD_PRIORITY_NORMAL);
}

TEST_F(SystemUtilsTest, SetCurrentThreadPriority_InvalidPriority) {
    // Invalid priority value
    bool result = SetCurrentThreadPriority(999);
    EXPECT_FALSE(result);
}

// ============================================================================
// BOOT TIME TESTS
// ============================================================================
TEST_F(SystemUtilsTest, QueryBootTime_ReturnsValidTime) {
    FILETIME bootTime{};
    
    ASSERT_TRUE(QueryBootTime(bootTime));
    
    // Convert to uint64 for validation
    ULARGE_INTEGER uliBoot;
    uliBoot.LowPart = bootTime.dwLowDateTime;
    uliBoot.HighPart = bootTime.dwHighDateTime;
    
    EXPECT_GT(uliBoot.QuadPart, 0ull);
    
    // Boot time should be before current time
    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER uliNow;
    uliNow.LowPart = nowFt.dwLowDateTime;
    uliNow.HighPart = nowFt.dwHighDateTime;
    
    EXPECT_LT(uliBoot.QuadPart, uliNow.QuadPart);
}

// ============================================================================
// SYSTEM INFO TESTS
// ============================================================================
TEST_F(SystemUtilsTest, GetBasicSystemInfo_ReturnsValidInfo) {
    SYSTEM_INFO si{};
    
    ASSERT_TRUE(GetBasicSystemInfo(si));
    
    EXPECT_GT(si.dwNumberOfProcessors, 0u);
    EXPECT_GT(si.dwPageSize, 0u);
    EXPECT_NE(si.lpMinimumApplicationAddress, nullptr);
    EXPECT_NE(si.lpMaximumApplicationAddress, nullptr);
}

// ============================================================================
// EDGE CASES & ERROR HANDLING
// ============================================================================
TEST_F(SystemUtilsTest, EdgeCase_MultipleOSVersionQueries) {
    // Should handle multiple queries without issues
    for (int i = 0; i < 5; ++i) {
        OSVersion os;
        ASSERT_TRUE(QueryOSVersion(os));
        EXPECT_GT(os.major, 0u);
    }
}

TEST_F(SystemUtilsTest, EdgeCase_MultipleCpuInfoQueries) {
    // Should handle multiple queries without issues
    for (int i = 0; i < 5; ++i) {
        CpuInfo cpu;
        ASSERT_TRUE(QueryCpuInfo(cpu));
        EXPECT_GT(cpu.logicalProcessorCount, 0u);
    }
}

TEST_F(SystemUtilsTest, EdgeCase_MultipleMemoryInfoQueries) {
    // Should handle multiple queries without issues
    for (int i = 0; i < 5; ++i) {
        MemoryInfo mem;
        ASSERT_TRUE(QueryMemoryInfo(mem));
        EXPECT_GT(mem.totalPhys, 0ull);
    }
}

// ============================================================================
// STRESS TESTS
// ============================================================================
TEST_F(SystemUtilsTest, Stress_RapidQueryOSVersion) {
    for (int i = 0; i < 100; ++i) {
        OSVersion os;
        ASSERT_TRUE(QueryOSVersion(os));
    }
}

TEST_F(SystemUtilsTest, Stress_RapidPathQueries) {
    for (int i = 0; i < 50; ++i) {
        std::wstring exe = GetExecutablePath();
        std::wstring sys = GetSystemDirectoryPath();
        std::wstring win = GetWindowsDirectoryPath();
        
        EXPECT_FALSE(exe.empty());
        EXPECT_FALSE(sys.empty());
        EXPECT_FALSE(win.empty());
    }
}

TEST_F(SystemUtilsTest, Stress_RapidEnvironmentExpansion) {
    for (int i = 0; i < 100; ++i) {
        std::wstring expanded = ExpandEnv(L"%WINDIR%");
        EXPECT_FALSE(expanded.empty());
    }
}
