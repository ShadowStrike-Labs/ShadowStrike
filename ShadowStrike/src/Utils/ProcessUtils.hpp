#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <TlHelp32.h>
#  include <Psapi.h>
#  include <winternl.h>
#  pragma comment(lib, "psapi.lib")
#  pragma comment(lib, "advapi32.lib")
#endif

#include "Logger.hpp"
#include "SystemUtils.hpp"
#include "FileUtils.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace ProcessUtils {

            // ============================================================================
            // Forward Declarations & Type Aliases
            // ============================================================================

            using ProcessId = DWORD;
            using ThreadId = DWORD;
            using HandleId = uint64_t;

            // ============================================================================
            // Error Handling
            // ============================================================================

            struct Error {
                DWORD win32 = ERROR_SUCCESS;
                LONG ntstatus = 0;
                std::wstring message;
                std::wstring context;

                bool HasError() const noexcept { return win32 != ERROR_SUCCESS || ntstatus != 0; }
                void Clear() noexcept { win32 = ERROR_SUCCESS; ntstatus = 0; message.clear(); context.clear(); }
            };

            // ============================================================================
            // Process Information Structures
            // ============================================================================

            struct ProcessBasicInfo {
                ProcessId pid = 0;
                ProcessId parentPid = 0;
                std::wstring name;                    // Process name (e.g., "notepad.exe")
                std::wstring executablePath;          // Full path
                std::wstring commandLine;             // Command line arguments
                std::wstring currentDirectory;        // Working directory
                std::wstring windowTitle;             // Main window title (if exists)

                DWORD sessionId = 0;
                DWORD threadCount = 0;
                DWORD handleCount = 0;

                int64_t priorityClass = 0;
                int64_t basePriority = 0;

                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};

                bool is64Bit = false;
                bool isWow64 = false;
                bool isCritical = false;
                bool isProtected = false;              // PPL/PsPM
                bool isImmersive = false;              // UWP/Modern app
                bool isSystemProcess = false;
                bool hasGUI = false;
            };

            struct ProcessMemoryInfo {
                SIZE_T workingSetSize = 0;             // Current physical memory
                SIZE_T peakWorkingSetSize = 0;
                SIZE_T privateMemorySize = 0;          // Private bytes
                SIZE_T virtualMemorySize = 0;
                SIZE_T peakVirtualMemorySize = 0;
                SIZE_T pagedPoolUsage = 0;
                SIZE_T nonPagedPoolUsage = 0;
                SIZE_T pageFaultCount = 0;

                // Additional metrics
                SIZE_T committedMemorySize = 0;
                SIZE_T sharedMemorySize = 0;
            };

            struct ProcessIOCounters {
                uint64_t readOperationCount = 0;
                uint64_t writeOperationCount = 0;
                uint64_t otherOperationCount = 0;
                uint64_t readTransferCount = 0;       // Bytes
                uint64_t writeTransferCount = 0;
                uint64_t otherTransferCount = 0;
            };

            struct ProcessCpuInfo {
                double cpuUsagePercent = 0.0;          // Total CPU usage (0-100)
                double kernelTimePercent = 0.0;
                double userTimePercent = 0.0;
                uint64_t totalCpuTimeMs = 0;
                uint64_t kernelCpuTimeMs = 0;
                uint64_t userCpuTimeMs = 0;
                DWORD affinityMask = 0;
                int priorityClass = NORMAL_PRIORITY_CLASS;
            };

            struct ProcessSecurityInfo {
                std::wstring userName;                 // Domain\User
                std::wstring userSid;                  // SID string
                std::wstring integrityLevel;           // Low/Medium/High/System
                bool isElevated = false;
                bool isRunningAsService = false;
                bool isRunningAsSystem = false;
                bool hasDebugPrivilege = false;
                bool hasSeDebugPrivilege = false;
                std::vector<std::wstring> enabledPrivileges;
            };

            struct ProcessModuleInfo {
                std::wstring name;                     // Module name (e.g., "kernel32.dll")
                std::wstring path;                     // Full path
                void* baseAddress = nullptr;
                SIZE_T size = 0;
                void* entryPoint = nullptr;
                DWORD loadCount = 0;
                bool isSigned = false;
                bool isSystemModule = false;
                std::wstring companyName;
                std::wstring fileVersion;
                std::wstring productVersion;
            };

            struct ProcessThreadInfo {
                ThreadId tid = 0;
                ProcessId ownerPid = 0;
                int basePriority = 0;
                DWORD threadState = 0;                 // Running/Waiting/Terminated
                DWORD waitReason = 0;
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                void* startAddress = nullptr;
                void* stackBase = nullptr;
                void* stackLimit = nullptr;
                SIZE_T stackSize = 0;
                bool isSuspended = false;
            };

            struct ProcessHandleInfo {
                HANDLE handle = nullptr;
                HandleId uniqueId = 0;
                DWORD type = 0;                        // File/Process/Thread/Registry etc.
                std::wstring typeName;
                std::wstring name;                     // Object name
                DWORD accessMask = 0;
                DWORD attributes = 0;
                bool isInheritable = false;
                bool isProtected = false;
            };

            struct ProcessNetworkInfo {
                std::vector<std::wstring> openPorts;
                std::vector<std::wstring> activeConnections;
                uint64_t bytesSent = 0;
                uint64_t bytesReceived = 0;
            };

            struct ProcessEnvironmentBlock {
                std::wstring imagePathName;
                std::wstring commandLine;
                std::wstring currentDirectory;
                std::unordered_map<std::wstring, std::wstring> environmentVariables;
                void* pebAddress = nullptr;
            };

            // Comprehensive process information (all-in-one)
            struct ProcessInfo {
                ProcessBasicInfo basic;
                ProcessMemoryInfo memory;
                ProcessIOCounters io;
                ProcessCpuInfo cpu;
                ProcessSecurityInfo security;
                ProcessEnvironmentBlock peb;
                std::vector<ProcessModuleInfo> modules;
                std::vector<ProcessThreadInfo> threads;
                std::vector<ProcessHandleInfo> handles;
                ProcessNetworkInfo network;
            };

            // ============================================================================
            // Process Enumeration Options
            // ============================================================================

            struct EnumerationOptions {
                bool includeSystemProcesses = true;
                bool includeProtectedProcesses = false;
                bool includeIdleProcess = false;
                bool includeCurrentProcess = true;
                bool sortByName = false;
                bool sortByPid = false;
                bool sortByCpuUsage = false;
                bool sortByMemoryUsage = false;
                std::optional<std::wstring> nameFilter;        // Wildcard filter (e.g., "chrome*")
                std::optional<DWORD> sessionFilter;            // Filter by session ID
                std::optional<std::wstring> userFilter;        // Filter by user name
            };

            // ============================================================================
            // Process Monitoring Structures
            // ============================================================================

            enum class ProcessEventType : uint8_t {
                Created,
                Terminated,
                ModuleLoaded,
                ModuleUnloaded,
                ThreadCreated,
                ThreadTerminated,
                HandleOpened,
                HandleClosed,
                MemoryAllocated,
                MemoryFreed,
                RegistryAccessed,
                FileAccessed,
                NetworkActivity
            };

            struct ProcessEvent {
                ProcessEventType type;
                ProcessId pid;
                ThreadId tid = 0;
                std::chrono::system_clock::time_point timestamp;
                std::wstring description;
                std::unordered_map<std::wstring, std::wstring> details;
            };

            using ProcessEventCallback = std::function<void(const ProcessEvent&)>;

            // ============================================================================
            // Process Creation Structures
            // ============================================================================

            enum class ProcessCreationFlags : uint32_t {
                None = 0,
                CreateSuspended = CREATE_SUSPENDED,
                CreateNoWindow = CREATE_NO_WINDOW,
                CreateNewConsole = CREATE_NEW_CONSOLE,
                CreateNewProcessGroup = CREATE_NEW_PROCESS_GROUP,
                DebugProcess = DEBUG_PROCESS,
                DebugOnlyThisProcess = DEBUG_ONLY_THIS_PROCESS,
                DetachedProcess = DETACHED_PROCESS,
                InheritParentAffinity = INHERIT_PARENT_AFFINITY,
                ExtendedStartupInfo = EXTENDED_STARTUPINFO_PRESENT
            };

            struct ProcessStartupInfo {
                std::wstring workingDirectory;
                std::wstring desktopName;
                std::wstring windowTitle;
                DWORD windowShowState = SW_SHOWNORMAL;
                COORD windowPosition = { 0, 0 };
                COORD windowSize = { 0, 0 };
                bool redirectStdInput = false;
                bool redirectStdOutput = false;
                bool redirectStdError = false;
                HANDLE hStdInput = nullptr;
                HANDLE hStdOutput = nullptr;
                HANDLE hStdError = nullptr;
            };

            struct ProcessCreationResult {
                ProcessId pid = 0;
                ThreadId mainThreadId = 0;
                HANDLE hProcess = nullptr;
                HANDLE hThread = nullptr;
                DWORD exitCode = 0;
                bool succeeded = false;
                std::wstring errorMessage;
            };

            // ============================================================================
            // Process Injection Structures (for security analysis)
            // ============================================================================

            enum class InjectionMethod : uint8_t {
                None,
                CreateRemoteThread,
                QueueUserAPC,
                SetWindowsHookEx,
                SetThreadContext,
                ProcessHollowing,
                AtomBombing,
                DoppelGanging,
                ThreadExecution,
                SuspendInjectResume
            };

            struct InjectionDetectionResult {
                bool detected = false;
                InjectionMethod method = InjectionMethod::None;
                ProcessId sourcePid = 0;
                ProcessId targetPid = 0;
                void* injectedAddress = nullptr;
                SIZE_T injectedSize = 0;
                std::wstring injectedModulePath;
                std::chrono::system_clock::time_point detectionTime;
                std::wstring description;
            };

            // ============================================================================
            // Process Analysis Structures
            // ============================================================================

            struct ProcessBehaviorAnalysis {
                bool isLikelyMalware = false;
                double suspicionScore = 0.0;            // 0.0 - 1.0
                std::vector<std::wstring> suspiciousBehaviors;
                std::vector<std::wstring> anomalies;

                // Behavioral indicators
                bool hasCodeInjection = false;
                bool hasHollowedProcess = false;
                bool hasHiddenThreads = false;
                bool hasUnusualNetworkActivity = false;
                bool hasRegistryPersistence = false;
                bool hasFileSystemChanges = false;
                bool hasPrivilegeEscalation = false;
                bool hasAntiDebugging = false;
                bool hasAntiAnalysis = false;
                bool hasEncryptedSections = false;
                bool hasPackedExecutable = false;
            };

            struct ProcessDependencyGraph {
                ProcessId rootPid;
                std::unordered_map<ProcessId, std::vector<ProcessId>> childProcesses;
                std::unordered_map<ProcessId, ProcessBasicInfo> processInfo;
                std::unordered_set<ProcessId> orphanedProcesses;
            };

            // ============================================================================
            // Core Process Operations
            // ============================================================================

            // Process Enumeration
            bool EnumerateProcesses(std::vector<ProcessId>& pids, Error* err = nullptr) noexcept;
            bool EnumerateProcesses(std::vector<ProcessBasicInfo>& processes,
                const EnumerationOptions& options = EnumerationOptions{},
                Error* err = nullptr) noexcept;

            // Process Information Retrieval
            bool GetProcessBasicInfo(ProcessId pid, ProcessBasicInfo& info, Error* err = nullptr) noexcept;
            bool QueryProcessMemoryInfo(ProcessId pid, ProcessMemoryInfo& info, Error* err = nullptr) noexcept;
            bool GetProcessCpuInfo(ProcessId pid, ProcessCpuInfo& info, Error* err = nullptr) noexcept;
            bool GetProcessIOCounters(ProcessId pid, ProcessIOCounters& info, Error* err = nullptr) noexcept;
            bool GetProcessSecurityInfo(ProcessId pid, ProcessSecurityInfo& info, Error* err = nullptr) noexcept;
            bool GetProcessInfo(ProcessId pid, ProcessInfo& info, Error* err = nullptr) noexcept;

            // Process Path & Identity
            std::optional<std::wstring> GetProcessPath(ProcessId pid, Error* err = nullptr) noexcept;
            std::optional<std::wstring> GetProcessCommandLine(ProcessId pid, Error* err = nullptr) noexcept;
            std::optional<std::wstring> GetProcessName(ProcessId pid, Error* err = nullptr) noexcept;
            std::optional<std::wstring> GetProcessWindowTitle(ProcessId pid, Error* err = nullptr) noexcept;

            // Process Tree & Relationships
            std::optional<ProcessId> GetParentProcessId(ProcessId pid, Error* err = nullptr) noexcept;
            bool GetChildProcesses(ProcessId parentPid, std::vector<ProcessId>& children, Error* err = nullptr) noexcept;
            bool BuildProcessTree(ProcessDependencyGraph& graph, Error* err = nullptr) noexcept;

            // Process Existence & State
            bool IsProcessRunning(ProcessId pid) noexcept;
            bool IsProcessRunning(std::wstring_view processName) noexcept;
            bool IsProcess64Bit(ProcessId pid, Error* err = nullptr) noexcept;
            bool IsProcessElevated(ProcessId pid, Error* err = nullptr) noexcept;
            bool IsProcessCritical(ProcessId pid, Error* err = nullptr) noexcept;
            bool IsProcessProtected(ProcessId pid, Error* err = nullptr) noexcept;
            bool IsProcessSuspended(ProcessId pid, Error* err = nullptr) noexcept;

            // ============================================================================
            // Process Creation & Termination
            // ============================================================================

            bool CreateProcess(std::wstring_view executablePath,
                std::wstring_view arguments,
                ProcessCreationResult& result,
                const ProcessStartupInfo& startupInfo = ProcessStartupInfo{},
                ProcessCreationFlags flags = ProcessCreationFlags::None,
                Error* err = nullptr) noexcept;

            bool CreateProcessAsUser(std::wstring_view executablePath,
                std::wstring_view arguments,
                HANDLE hUserToken,
                ProcessCreationResult& result,
                const ProcessStartupInfo& startupInfo = ProcessStartupInfo{},
                ProcessCreationFlags flags = ProcessCreationFlags::None,
                Error* err = nullptr) noexcept;

            bool CreateProcessWithToken(std::wstring_view executablePath,
                std::wstring_view arguments,
                HANDLE hToken,
                ProcessCreationResult& result,
                Error* err = nullptr) noexcept;

            bool TerminateProcess(ProcessId pid, DWORD exitCode = 0, Error* err = nullptr) noexcept;
            bool TerminateProcess(HANDLE hProcess, DWORD exitCode = 0, Error* err = nullptr) noexcept;
            bool TerminateProcessTree(ProcessId rootPid, DWORD exitCode = 0, Error* err = nullptr) noexcept;

            bool WaitForProcess(ProcessId pid, DWORD timeoutMs = INFINITE, Error* err = nullptr) noexcept;
            bool WaitForProcess(HANDLE hProcess, DWORD timeoutMs = INFINITE, Error* err = nullptr) noexcept;
            std::optional<DWORD> GetProcessExitCode(ProcessId pid, Error* err = nullptr) noexcept;

            // ============================================================================
            // Process Control & Manipulation
            // ============================================================================

            bool SuspendProcess(ProcessId pid, Error* err = nullptr) noexcept;
            bool ResumeProcess(ProcessId pid, Error* err = nullptr) noexcept;

            bool SetProcessPriority(ProcessId pid, DWORD priorityClass, Error* err = nullptr) noexcept;
            bool SetProcessAffinity(ProcessId pid, DWORD_PTR affinityMask, Error* err = nullptr) noexcept;
            bool SetProcessWorkingSetSize(ProcessId pid, SIZE_T minSize, SIZE_T maxSize, Error* err = nullptr) noexcept;

            // ============================================================================
            // Module Operations
            // ============================================================================

            bool EnumerateProcessModules(ProcessId pid, std::vector<ProcessModuleInfo>& modules, Error* err = nullptr) noexcept;
            std::optional<ProcessModuleInfo> GetModuleInfo(ProcessId pid, std::wstring_view moduleName, Error* err = nullptr) noexcept;
            std::optional<void*> GetModuleBaseAddress(ProcessId pid, std::wstring_view moduleName, Error* err = nullptr) noexcept;
            std::optional<void*> GetModuleExportAddress(ProcessId pid, std::wstring_view moduleName,
                std::string_view exportName, Error* err = nullptr) noexcept;

            bool InjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err = nullptr) noexcept;
            bool EjectDLL(ProcessId pid, std::wstring_view dllPath, Error* err = nullptr) noexcept;

            // ============================================================================
            // Thread Operations
            // ============================================================================

            bool EnumerateProcessThreads(ProcessId pid, std::vector<ProcessThreadInfo>& threads, Error* err = nullptr) noexcept;
            std::optional<ProcessThreadInfo> GetThreadInfo(ThreadId tid, Error* err = nullptr) noexcept;

            bool SuspendThread(ThreadId tid, Error* err = nullptr) noexcept;
            bool ResumeThread(ThreadId tid, Error* err = nullptr) noexcept;
            bool TerminateThread(ThreadId tid, DWORD exitCode = 0, Error* err = nullptr) noexcept;

            bool SetThreadPriority(ThreadId tid, int priority, Error* err = nullptr) noexcept;
            bool SetThreadAffinity(ThreadId tid, DWORD_PTR affinityMask, Error* err = nullptr) noexcept;

            // ============================================================================
            // Memory Operations
            // ============================================================================

            bool ReadProcessMemory(ProcessId pid, void* address, void* buffer, SIZE_T size,
                SIZE_T* bytesRead = nullptr, Error* err = nullptr) noexcept;
            bool WriteProcessMemory(ProcessId pid, void* address, const void* buffer, SIZE_T size,
                SIZE_T* bytesWritten = nullptr, Error* err = nullptr) noexcept;

            bool AllocateProcessMemory(ProcessId pid, SIZE_T size, void** outAddress,
                DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
                DWORD protection = PAGE_READWRITE, Error* err = nullptr) noexcept;
            bool FreeProcessMemory(ProcessId pid, void* address, SIZE_T size = 0,
                DWORD freeType = MEM_RELEASE, Error* err = nullptr) noexcept;

            bool ProtectProcessMemory(ProcessId pid, void* address, SIZE_T size,
                DWORD newProtection, DWORD* oldProtection = nullptr,
                Error* err = nullptr) noexcept;

            bool QueryProcessMemoryRegion(ProcessId pid, void* address,
                MEMORY_BASIC_INFORMATION& mbi, Error* err = nullptr) noexcept;

            // ============================================================================
            // Handle Operations
            // ============================================================================

            bool EnumerateProcessHandles(ProcessId pid, std::vector<ProcessHandleInfo>& handles, Error* err = nullptr) noexcept;
            bool CloseProcessHandle(ProcessId pid, HANDLE handle, Error* err = nullptr) noexcept;
            bool DuplicateProcessHandle(ProcessId sourcePid, HANDLE sourceHandle,
                ProcessId targetPid, HANDLE* targetHandle,
                DWORD desiredAccess = 0, bool inheritHandle = false,
                DWORD options = DUPLICATE_SAME_ACCESS, Error* err = nullptr) noexcept;

            // ============================================================================
            // Process Security & Privileges
            // ============================================================================

            bool EnableProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, bool enable = true, Error* err = nullptr) noexcept;
            bool HasProcessPrivilege(ProcessId pid, std::wstring_view privilegeName, Error* err = nullptr) noexcept;
            bool GetProcessPrivileges(ProcessId pid, std::vector<std::wstring>& privileges, Error* err = nullptr) noexcept;

            bool ImpersonateProcess(ProcessId pid, Error* err = nullptr) noexcept;
            bool RevertToSelf(Error* err = nullptr) noexcept;

            // ============================================================================
            // Process Monitoring (Real-time)
            // ============================================================================

            class ProcessMonitor {
            public:
                ProcessMonitor() noexcept;
                ~ProcessMonitor();

                // No copy, allow move
                ProcessMonitor(const ProcessMonitor&) = delete;
                ProcessMonitor& operator=(const ProcessMonitor&) = delete;
                ProcessMonitor(ProcessMonitor&&) noexcept;
                ProcessMonitor& operator=(ProcessMonitor&&) noexcept;

                // Start/Stop monitoring
                bool Start(Error* err = nullptr) noexcept;
                bool Stop(Error* err = nullptr) noexcept;
                bool IsRunning() const noexcept { return m_running; }

                // Event callbacks
                void OnProcessCreated(ProcessEventCallback callback) noexcept { m_onProcessCreated = std::move(callback); }
                void OnProcessTerminated(ProcessEventCallback callback) noexcept { m_onProcessTerminated = std::move(callback); }
                void OnModuleLoaded(ProcessEventCallback callback) noexcept { m_onModuleLoaded = std::move(callback); }
                void OnThreadCreated(ProcessEventCallback callback) noexcept { m_onThreadCreated = std::move(callback); }

                // Filtering
                void AddProcessFilter(ProcessId pid) noexcept { m_processFilter.insert(pid); }
                void RemoveProcessFilter(ProcessId pid) noexcept { m_processFilter.erase(pid); }
                void ClearProcessFilters() noexcept { m_processFilter.clear(); }

                void AddNameFilter(std::wstring_view name) noexcept { m_nameFilter.emplace(name); }
                void RemoveNameFilter(std::wstring_view name) noexcept { m_nameFilter.erase(std::wstring(name)); }
                void ClearNameFilters() noexcept { m_nameFilter.clear(); }

            private:
                void monitorThread() noexcept;
                void processSnapshot() noexcept;

                std::atomic<bool> m_running{ false };
                std::thread m_monitorThread;

                ProcessEventCallback m_onProcessCreated;
                ProcessEventCallback m_onProcessTerminated;
                ProcessEventCallback m_onModuleLoaded;
                ProcessEventCallback m_onThreadCreated;

                std::unordered_set<ProcessId> m_processFilter;
                std::unordered_set<std::wstring> m_nameFilter;
                std::unordered_set<ProcessId> m_lastSnapshot;

                mutable std::mutex m_mutex;
            };

            // ============================================================================
            // Process Utilities
            // ============================================================================

            ProcessId GetCurrentProcessId() noexcept;
            ProcessId GetProcessIdByName(std::wstring_view processName, Error* err = nullptr) noexcept;
            std::vector<ProcessId> GetProcessIdsByName(std::wstring_view processName, Error* err = nullptr) noexcept;

            bool KillProcessByName(std::wstring_view processName, Error* err = nullptr) noexcept;
            bool KillAllProcessesByName(std::wstring_view processName, Error* err = nullptr) noexcept;

            std::optional<std::wstring> GetProcessOwner(ProcessId pid, Error* err = nullptr) noexcept;
            std::optional<std::wstring> GetProcessSID(ProcessId pid, Error* err = nullptr) noexcept;
            std::optional<DWORD> GetProcessSessionId(ProcessId pid, Error* err = nullptr) noexcept;

            bool IsProcessInJob(ProcessId pid, Error* err = nullptr) noexcept;
            bool IsProcessDebugged(ProcessId pid, Error* err = nullptr) noexcept;

            // ============================================================================
            // Process Handle Management (RAII)
            // ============================================================================

            class ProcessHandle {
            public:
                ProcessHandle() noexcept = default;
                explicit ProcessHandle(ProcessId pid, DWORD desiredAccess = PROCESS_ALL_ACCESS, Error* err = nullptr) noexcept;
                explicit ProcessHandle(HANDLE handle) noexcept : m_handle(handle) {}
                ~ProcessHandle() { Close(); }

                // No copy, allow move
                ProcessHandle(const ProcessHandle&) = delete;
                ProcessHandle& operator=(const ProcessHandle&) = delete;
                ProcessHandle(ProcessHandle&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
                ProcessHandle& operator=(ProcessHandle&& other) noexcept {
                    if (this != &other) { Close(); m_handle = other.m_handle; other.m_handle = nullptr; }
                    return *this;
                }

                bool Open(ProcessId pid, DWORD desiredAccess = PROCESS_ALL_ACCESS, Error* err = nullptr) noexcept;
                void Close() noexcept;

                [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
                [[nodiscard]] bool IsValid() const noexcept { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }

                operator HANDLE() const noexcept { return m_handle; }
                explicit operator bool() const noexcept { return IsValid(); }

            private:
                HANDLE m_handle = nullptr;
            };

            // ============================================================================
            // Advanced Features
            // ============================================================================

            // ETW (Event Tracing for Windows) Integration
            bool EnableETWProcessTracing(Error* err = nullptr) noexcept;
            bool DisableETWProcessTracing(Error* err = nullptr) noexcept;

            // Process Snapshot
            bool CreateProcessSnapshot(std::vector<ProcessInfo>& snapshot, Error* err = nullptr) noexcept;
            bool CompareProcessSnapshots(const std::vector<ProcessInfo>& before,
                const std::vector<ProcessInfo>& after,
                std::vector<ProcessId>& added,
                std::vector<ProcessId>& removed,
                std::vector<ProcessId>& modified) noexcept;

            // Process Dump
            bool CreateProcessDump(ProcessId pid, std::wstring_view dumpFilePath, Error* err = nullptr) noexcept;
            bool CreateMiniDump(ProcessId pid, std::wstring_view dumpFilePath, Error* err = nullptr) noexcept;

            // WMI Integration
            bool GetProcessInfoWMI(ProcessId pid, ProcessInfo& info, Error* err = nullptr) noexcept;
            bool EnumerateProcessesWMI(std::vector<ProcessBasicInfo>& processes, Error* err = nullptr) noexcept;

        } // namespace ProcessUtils
    } // namespace Utils
} // namespace ShadowStrike