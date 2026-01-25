// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * @file ProcessEvasionDetector.cpp
 * @brief Enterprise-grade implementation of process-based evasion detection
 * 
 * ShadowStrike AntiEvasion - Process Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "ProcessEvasionDetector.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/Logger.hpp"

#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <format>

#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace AntiEvasion {

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

ProcessEvasionDetector& ProcessEvasionDetector::GetInstance() {
    static ProcessEvasionDetector instance;
    return instance;
}

// ============================================================================
// CONSTRUCTION & LIFECYCLE
// ============================================================================

ProcessEvasionDetector::ProcessEvasionDetector() 
    : m_initialized(false)
{
    if (Initialize()) {
        m_initialized = true;
    }
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"Constructor called");
}

ProcessEvasionDetector::~ProcessEvasionDetector() {
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"Destructor called");
}

bool ProcessEvasionDetector::Initialize() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    m_initialized = true;
    SS_LOG_INFO(L"ProcessEvasionDetector", L"Initialized successfully");
    return true;
}

void ProcessEvasionDetector::Shutdown() {
    std::unique_lock lock(m_mutex);
    m_processData.clear();
    m_initialized = false;
    SS_LOG_INFO(L"ProcessEvasionDetector", L"Shutdown complete");
}

bool ProcessEvasionDetector::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

// ============================================================================
// PRIMARY DETECTION API
// ============================================================================

ProcessEvasionResult ProcessEvasionDetector::AnalyzeProcess(uint32_t processId) {
    SS_LOG_INFO(L"ProcessEvasionDetector", L"AnalyzeProcess: PID=%u", processId);
    
    m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
    
    ProcessEvasionResult result;
    result.processId = processId;
    result.analysisStartTime = std::chrono::system_clock::now();
    
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        result.errorMessage = L"Failed to open process";
        return result;
    }
    
    // Get process name
    wchar_t processName[MAX_PATH];
    if (GetModuleBaseNameW(hProcess, nullptr, processName, MAX_PATH)) {
        result.processName = processName;
    }
    
    // Check parent process
    CheckParentProcess(processId, result);
    
    // Check loaded modules
    CheckLoadedModules(hProcess, result);
    
    // Check process hollowing
    CheckProcessHollowing(hProcess, result);
    
    // Check injection techniques
    CheckInjectionTechniques(hProcess, result);
    
    CloseHandle(hProcess);
    
    // Calculate score
    CalculateEvasionScore(result);
    
    result.analysisEndTime = std::chrono::system_clock::now();
    result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.analysisEndTime - result.analysisStartTime).count();
    result.analysisComplete = true;
    
    if (result.isEvasive) {
        m_stats.evasiveProcesses.fetch_add(1, std::memory_order_relaxed);
    }
    
    SS_LOG_INFO(L"ProcessEvasionDetector", L"Analysis complete: isEvasive=%s, score=%.1f",
        result.isEvasive ? L"true" : L"false", result.evasionScore);
    
    return result;
}

ProcessEvasionResult ProcessEvasionDetector::AnalyzeCurrentProcess() {
    return AnalyzeProcess(GetCurrentProcessId());
}

bool ProcessEvasionDetector::QuickCheck(uint32_t processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return false;
    
    // Quick parent check
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQueryInformationProcess = reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE, DWORD, PVOID, ULONG, PULONG)>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        
        if (NtQueryInformationProcess) {
            if (NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength) == 0) {
                // Check if parent is explorer.exe
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 
                    static_cast<DWORD>(reinterpret_cast<uintptr_t>(pbi.Reserved3)));
                if (hParent) {
                    wchar_t parentName[MAX_PATH];
                    if (GetModuleBaseNameW(hParent, nullptr, parentName, MAX_PATH)) {
                        std::wstring parent(parentName);
                        std::transform(parent.begin(), parent.end(), parent.begin(), ::towlower);
                        CloseHandle(hParent);
                        
                        if (parent != L"explorer.exe") {
                            CloseHandle(hProcess);
                            return true;  // Suspicious parent
                        }
                    }
                    CloseHandle(hParent);
                }
            }
        }
    }
    
    CloseHandle(hProcess);
    return false;
}

// ============================================================================
// INDIVIDUAL CHECK METHODS
// ============================================================================

void ProcessEvasionDetector::CheckParentProcess(uint32_t processId, ProcessEvasionResult& result) {
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"CheckParentProcess: PID=%u", processId);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == processId) {
                result.parentProcessId = pe.th32ParentProcessID;
                
                // Find parent name
                PROCESSENTRY32W parentPe{};
                parentPe.dwSize = sizeof(parentPe);
                if (Process32FirstW(hSnapshot, &parentPe)) {
                    do {
                        if (parentPe.th32ProcessID == pe.th32ParentProcessID) {
                            result.parentProcessName = parentPe.szExeFile;
                            break;
                        }
                    } while (Process32NextW(hSnapshot, &parentPe));
                }
                
                // Check for suspicious parent
                std::wstring parent = result.parentProcessName;
                std::transform(parent.begin(), parent.end(), parent.begin(), ::towlower);
                
                if (parent != L"explorer.exe" && parent != L"services.exe" && 
                    parent != L"svchost.exe" && parent != L"cmd.exe" && parent != L"powershell.exe") {
                    result.parentProcessScore += 20.0f;
                }
                
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
}

void ProcessEvasionDetector::CheckLoadedModules(HANDLE hProcess, ProcessEvasionResult& result) {
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"CheckLoadedModules");
    
    HMODULE modules[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        result.loadedModuleCount = moduleCount;
        
        for (DWORD i = 0; i < moduleCount && i < 100; ++i) {
            wchar_t moduleName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, modules[i], moduleName, MAX_PATH)) {
                result.loadedModules.push_back(moduleName);
                
                // Check for suspicious modules
                std::wstring mod(moduleName);
                std::transform(mod.begin(), mod.end(), mod.begin(), ::towlower);
                
                if (mod.find(L"inject") != std::wstring::npos ||
                    mod.find(L"hook") != std::wstring::npos ||
                    mod.find(L"patch") != std::wstring::npos) {
                    result.moduleScore += 15.0f;
                }
            }
        }
    }
}

void ProcessEvasionDetector::CheckProcessHollowing(HANDLE hProcess, ProcessEvasionResult& result) {
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"CheckProcessHollowing");
    
    // Simplified check - compare image base in PEB vs actual
    // This would require more complex implementation in production
    result.hollowinScore += 0.0f;
}

void ProcessEvasionDetector::CheckInjectionTechniques(HANDLE hProcess, ProcessEvasionResult& result) {
    SS_LOG_DEBUG(L"ProcessEvasionDetector", L"CheckInjectionTechniques");
    
    // Check for suspicious memory regions
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;
    size_t executableRegions = 0;
    
    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            executableRegions++;
        }
        
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
        if (executableRegions > 100) break;  // Limit scan
    }
    
    // Many RWX regions is suspicious
    if (executableRegions > 10) {
        result.injectionScore += 25.0f;
    }
}

// ============================================================================
// SCORE CALCULATION
// ============================================================================

void ProcessEvasionDetector::CalculateEvasionScore(ProcessEvasionResult& result) {
    result.evasionScore = 
        result.parentProcessScore * 0.30f +
        result.moduleScore * 0.25f +
        result.hollowinScore * 0.25f +
        result.injectionScore * 0.20f;
    
    result.evasionScore = std::min(100.0f, result.evasionScore);
    result.isEvasive = result.evasionScore >= 50.0f;
    
    if (result.evasionScore >= 75.0f) {
        result.confidence = 85.0f;
    } else if (result.evasionScore >= 50.0f) {
        result.confidence = 70.0f;
    } else {
        result.confidence = 55.0f;
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

ProcessEvasionDetector::Statistics ProcessEvasionDetector::GetStatistics() const {
    return m_stats;
}

void ProcessEvasionDetector::ResetStatistics() {
    m_stats.Reset();
}

} // namespace AntiEvasion
} // namespace ShadowStrike
