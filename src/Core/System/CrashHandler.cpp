/**
 * ============================================================================
 * ShadowStrike Core System - CRASH HANDLER IMPLEMENTATION
 * ============================================================================
 *
 * @file CrashHandler.cpp
 * @brief Enterprise-grade crash handling, diagnostics, and recovery engine.
 *
 * This module provides comprehensive crash handling including structured
 * exception handling (SEH), minidump generation, stack trace capture, symbol
 * resolution, and automatic recovery to ensure maximum antivirus reliability.
 *
 * Key Capabilities:
 * - Windows SEH integration (SetUnhandledExceptionFilter, Vectored handlers)
 * - Minidump creation with MiniDumpWriteDump
 * - Stack trace capture with StackWalk64 and symbol resolution
 * - Register state snapshot from CONTEXT structure
 * - Crash analysis and categorization
 * - Automatic recovery and restart
 * - Watchdog integration
 * - Comprehensive telemetry
 *
 * Exception Handling Architecture:
 * 1. Vectored Exception Handler (first chance)
 * 2. SEH handlers (structured)
 * 3. C++ exception handlers (try/catch)
 * 4. Unhandled exception filter (last resort)
 * 5. CRT handlers (pure virtual, invalid parameter, abort)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "CrashHandler.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/HashUtils.hpp"

// Windows headers
#include <windows.h>
#include <DbgHelp.h>
#include <psapi.h>
#include <signal.h>
#include <eh.h>
#include <new.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// Standard library
#include <algorithm>
#include <format>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <ctime>

namespace ShadowStrike {
namespace Core {
namespace System {

namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Converts Windows exception code to ExceptionType.
 */
ExceptionType MapExceptionCode(DWORD code) noexcept {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return ExceptionType::AccessViolation;
        case EXCEPTION_STACK_OVERFLOW: return ExceptionType::StackOverflow;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return ExceptionType::ArrayBoundsExceeded;
        case EXCEPTION_ILLEGAL_INSTRUCTION: return ExceptionType::IllegalInstruction;
        case EXCEPTION_PRIV_INSTRUCTION: return ExceptionType::PrivilegedInstruction;
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return ExceptionType::IntegerDivideByZero;
        case EXCEPTION_INT_OVERFLOW: return ExceptionType::IntegerOverflow;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return ExceptionType::FloatDivideByZero;
        case EXCEPTION_INVALID_HANDLE: return ExceptionType::InvalidHandle;
        case STATUS_HEAP_CORRUPTION: return ExceptionType::HeapCorruption;
        case EXCEPTION_GUARD_PAGE: return ExceptionType::GuardPage;
        default: return ExceptionType::Unknown;
    }
}

/**
 * @brief Gets human-readable exception description.
 */
std::wstring GetExceptionDescription(DWORD code) noexcept {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
            return L"Access violation (read/write to invalid memory)";
        case EXCEPTION_STACK_OVERFLOW:
            return L"Stack overflow (recursion or excessive stack usage)";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            return L"Array bounds exceeded";
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            return L"Illegal instruction (corrupted code or data execution)";
        case EXCEPTION_PRIV_INSTRUCTION:
            return L"Privileged instruction executed in user mode";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            return L"Integer division by zero";
        case EXCEPTION_INT_OVERFLOW:
            return L"Integer overflow";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            return L"Floating-point division by zero";
        case EXCEPTION_INVALID_HANDLE:
            return L"Invalid handle used";
        case STATUS_HEAP_CORRUPTION:
            return L"Heap corruption detected";
        case EXCEPTION_GUARD_PAGE:
            return L"Guard page violation";
        default:
            return std::format(L"Unknown exception (code: 0x{:08X})", code);
    }
}

/**
 * @brief Gets module name from address.
 */
std::wstring GetModuleFromAddress(uintptr_t address) noexcept {
    HMODULE hModule = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          reinterpret_cast<LPCWSTR>(address), &hModule)) {
        wchar_t modulePath[MAX_PATH];
        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH)) {
            fs::path path(modulePath);
            return path.filename().wstring();
        }
    }
    return L"<unknown>";
}

/**
 * @brief Safely reads memory.
 */
bool SafeReadMemory(const void* address, void* buffer, size_t size) noexcept {
    __try {
        memcpy(buffer, address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/**
 * @brief Generates unique crash ID.
 */
std::wstring GenerateCrashId() {
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);

    std::ostringstream oss;
    oss << "CRASH_"
        << std::put_time(std::localtime(&nowTime), "%Y%m%d_%H%M%S")
        << "_" << GetCurrentProcessId()
        << "_" << GetCurrentThreadId();

    return Utils::StringUtils::Utf8ToWide(oss.str());
}

/**
 * @brief Gets MINIDUMP_TYPE from DumpType.
 */
MINIDUMP_TYPE GetMinidumpType(DumpType type) noexcept {
    switch (type) {
        case DumpType::Mini:
            return MiniDumpNormal;

        case DumpType::Normal:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpWithDataSegs |
                MiniDumpWithHandleData |
                MiniDumpWithThreadInfo);

        case DumpType::WithDataSegments:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpWithDataSegs |
                MiniDumpWithHandleData |
                MiniDumpWithProcessThreadData);

        case DumpType::WithFullMemory:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpWithFullMemory |
                MiniDumpWithHandleData |
                MiniDumpWithThreadInfo |
                MiniDumpWithProcessThreadData);

        case DumpType::WithHandleData:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpWithHandleData |
                MiniDumpWithFullMemoryInfo);

        case DumpType::WithThreadInfo:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpWithThreadInfo |
                MiniDumpWithProcessThreadData);

        case DumpType::FilterMemory:
            return static_cast<MINIDUMP_TYPE>(
                MiniDumpFilterMemory |
                MiniDumpWithDataSegs);

        default:
            return MiniDumpNormal;
    }
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

CrashHandlerConfig CrashHandlerConfig::CreateDefault() noexcept {
    CrashHandlerConfig config;

    // Get temp directory for dumps
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        config.dumpDirectory = std::wstring(tempPath) + L"ShadowStrike\\Dumps\\";
    } else {
        config.dumpDirectory = L"C:\\ProgramData\\ShadowStrike\\Dumps\\";
    }

    config.createDumpOnCrash = true;
    config.defaultDumpType = DumpType::Normal;
    config.maxDumpFiles = 10;
    config.compressDumps = false;

    config.defaultRecoveryAction = RecoveryAction::NotifyWatchdog;
    config.enableAutoRestart = true;
    config.maxRestartAttempts = 3;
    config.restartCooldown = std::chrono::milliseconds(60000);

    config.enableCrashReporting = false;
    config.includeMemoryDump = false;

    config.breakOnCrash = false;
    config.logStackTrace = true;

    return config;
}

CrashHandlerConfig CrashHandlerConfig::CreateDebug() noexcept {
    CrashHandlerConfig config = CreateDefault();

    config.defaultDumpType = DumpType::WithFullMemory;
    config.breakOnCrash = true;
    config.logStackTrace = true;
    config.enableAutoRestart = false;
    config.compressDumps = false;

    return config;
}

CrashHandlerConfig CrashHandlerConfig::CreateProduction() noexcept {
    CrashHandlerConfig config = CreateDefault();

    config.defaultDumpType = DumpType::FilterMemory;
    config.maxDumpFiles = 5;
    config.compressDumps = true;

    config.enableCrashReporting = true;
    config.includeMemoryDump = false;

    config.enableAutoRestart = true;
    config.maxRestartAttempts = 3;

    config.breakOnCrash = false;
    config.logStackTrace = false;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void CrashHandlerStatistics::Reset() noexcept {
    totalCrashes.store(0, std::memory_order_relaxed);
    recoveredCrashes.store(0, std::memory_order_relaxed);
    fatalCrashes.store(0, std::memory_order_relaxed);
    dumpsCreated.store(0, std::memory_order_relaxed);
    dumpsUploaded.store(0, std::memory_order_relaxed);
    restartAttempts.store(0, std::memory_order_relaxed);
    handledExceptions.store(0, std::memory_order_relaxed);

    accessViolations.store(0, std::memory_order_relaxed);
    stackOverflows.store(0, std::memory_order_relaxed);
    heapCorruptions.store(0, std::memory_order_relaxed);
    cppExceptions.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterPreCrash(PreCrashCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_preCrashCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterPostCrash(PostCrashCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_postCrashCallbacks[id] = std::move(callback);
        return id;
    }

    void SetRecovery(RecoveryCallback callback) {
        std::unique_lock lock(m_mutex);
        m_recoveryCallback = std::move(callback);
    }

    bool UnregisterPreCrash(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_preCrashCallbacks.erase(id) > 0;
    }

    bool UnregisterPostCrash(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_postCrashCallbacks.erase(id) > 0;
    }

    void InvokePreCrash(const CrashContext& context) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_preCrashCallbacks) {
            try {
                callback(context);
            } catch (const std::exception& e) {
                Logger::Error("PreCrashCallback exception: {}", e.what());
            }
        }
    }

    void InvokePostCrash(const CrashReport& report) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_postCrashCallbacks) {
            try {
                callback(report);
            } catch (const std::exception& e) {
                Logger::Error("PostCrashCallback exception: {}", e.what());
            }
        }
    }

    RecoveryAction InvokeRecovery(const CrashContext& context) {
        std::shared_lock lock(m_mutex);
        if (m_recoveryCallback) {
            try {
                return m_recoveryCallback(context);
            } catch (const std::exception& e) {
                Logger::Error("RecoveryCallback exception: {}", e.what());
            }
        }
        return RecoveryAction::None;
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, PreCrashCallback> m_preCrashCallbacks;
    std::unordered_map<uint64_t, PostCrashCallback> m_postCrashCallbacks;
    RecoveryCallback m_recoveryCallback;
};

// ============================================================================
// CRASH HISTORY MANAGER
// ============================================================================

class CrashHistoryManager {
public:
    void AddCrash(const CrashReport& report) {
        std::unique_lock lock(m_mutex);
        m_history.push_back(report);

        // Limit history size
        if (m_history.size() > 100) {
            m_history.erase(m_history.begin());
        }
    }

    std::vector<CrashReport> GetHistory() const {
        std::shared_lock lock(m_mutex);
        return m_history;
    }

    std::optional<CrashReport> GetLast() const {
        std::shared_lock lock(m_mutex);
        if (!m_history.empty()) {
            return m_history.back();
        }
        return std::nullopt;
    }

    void Clear() {
        std::unique_lock lock(m_mutex);
        m_history.clear();
    }

    uint64_t GetNextSequence() {
        return m_nextSequence.fetch_add(1, std::memory_order_relaxed);
    }

private:
    mutable std::shared_mutex m_mutex;
    std::vector<CrashReport> m_history;
    std::atomic<uint64_t> m_nextSequence{ 1 };
};

// ============================================================================
// SYMBOL RESOLVER
// ============================================================================

class SymbolResolver {
public:
    SymbolResolver() {
        m_process = GetCurrentProcess();

        // Initialize symbol handler
        DWORD options = SymGetOptions();
        options |= SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS;
        SymSetOptions(options);

        if (SymInitialize(m_process, nullptr, TRUE)) {
            m_initialized = true;
            Logger::Info("SymbolResolver: Symbol handler initialized");
        } else {
            Logger::Error("SymbolResolver: SymInitialize failed: {}", GetLastError());
        }
    }

    ~SymbolResolver() {
        if (m_initialized) {
            SymCleanup(m_process);
        }
    }

    bool ResolveSymbol(uint64_t address, std::wstring& moduleName,
                      std::wstring& functionName, std::wstring& sourceFile,
                      uint32_t& lineNumber, uint64_t& displacement) {
        if (!m_initialized) return false;

        // Get module
        IMAGEHLP_MODULEW64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);

        if (SymGetModuleInfoW64(m_process, address, &moduleInfo)) {
            moduleName = moduleInfo.ModuleName;
        } else {
            moduleName = GetModuleFromAddress(static_cast<uintptr_t>(address));
        }

        // Get function
        alignas(64) char buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)];
        auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 disp = 0;
        if (SymFromAddrW(m_process, address, &disp, symbol)) {
            functionName = symbol->Name;
            displacement = disp;
        } else {
            functionName = L"<unknown>";
            displacement = 0;
        }

        // Get source line
        IMAGEHLP_LINEW64 line = {};
        line.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);

        DWORD lineDisp = 0;
        if (SymGetLineFromAddrW64(m_process, address, &lineDisp, &line)) {
            sourceFile = line.FileName;
            lineNumber = line.LineNumber;
        } else {
            sourceFile.clear();
            lineNumber = 0;
        }

        return true;
    }

private:
    HANDLE m_process;
    bool m_initialized{ false };
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class CrashHandlerImpl {
public:
    CrashHandlerImpl() = default;
    ~CrashHandlerImpl() {
        Shutdown();
    }

    // Prevent copying
    CrashHandlerImpl(const CrashHandlerImpl&) = delete;
    CrashHandlerImpl& operator=(const CrashHandlerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const CrashHandlerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("CrashHandler: Initializing...");

            m_config = config;

            // Create dump directory
            if (!m_config.dumpDirectory.empty()) {
                fs::create_directories(m_config.dumpDirectory);
            }

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_historyManager = std::make_unique<CrashHistoryManager>();
            m_symbolResolver = std::make_unique<SymbolResolver>();

            // Install exception handlers
            InstallHandlers();

            m_uptime = std::chrono::steady_clock::now();
            m_initialized = true;

            Logger::Info("CrashHandler: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) return;

        Logger::Info("CrashHandler: Shutting down...");

        // Uninstall handlers
        UninstallHandlers();

        m_initialized = false;

        Logger::Info("CrashHandler: Shutdown complete");
    }

    // ========================================================================
    // DUMP CREATION
    // ========================================================================

    DumpFileInfo CreateDump(DumpType type, const std::wstring& reason) {
        DumpFileInfo info;

        try {
            // Generate filename
            auto crashId = GenerateCrashId();
            fs::path dumpPath = fs::path(m_config.dumpDirectory) /
                               (crashId + L"_" + reason + L".dmp");

            info.filePath = dumpPath.wstring();
            info.dumpType = type;
            info.creationTime = std::chrono::system_clock::now();

            // Create minidump
            HANDLE hFile = CreateFileW(
                dumpPath.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                Logger::Error("CrashHandler: Failed to create dump file: {}",
                    Utils::StringUtils::WideToUtf8(dumpPath.wstring()));
                return info;
            }

            MINIDUMP_TYPE minidumpType = GetMinidumpType(type);

            BOOL success = MiniDumpWriteDump(
                GetCurrentProcess(),
                GetCurrentProcessId(),
                hFile,
                minidumpType,
                nullptr,
                nullptr,
                nullptr
            );

            CloseHandle(hFile);

            if (success) {
                // Get file size
                if (fs::exists(dumpPath)) {
                    info.fileSizeBytes = fs::file_size(dumpPath);

                    // Calculate hash
                    auto fileBytes = Utils::FileUtils::ReadFileBytes(dumpPath.wstring());
                    if (!fileBytes.empty()) {
                        auto hash = Utils::HashUtils::SHA256(
                            std::span<const uint8_t>(fileBytes.data(), fileBytes.size())
                        );

                        std::ostringstream oss;
                        for (auto byte : hash) {
                            oss << std::hex << std::setw(2) << std::setfill('0')
                                << static_cast<int>(byte);
                        }
                        info.sha256Hash = oss.str();
                    }
                }

                m_stats.dumpsCreated.fetch_add(1, std::memory_order_relaxed);

                Logger::Info("CrashHandler: Created dump: {} ({} bytes)",
                    Utils::StringUtils::WideToUtf8(dumpPath.wstring()),
                    info.fileSizeBytes);
            } else {
                Logger::Error("CrashHandler: MiniDumpWriteDump failed: {}", GetLastError());
            }

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::CreateDump: {}", e.what());
        }

        return info;
    }

    DumpFileInfo CreateProcessDump(uint32_t processId, DumpType type) {
        DumpFileInfo info;

        try {
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                processId
            );

            if (!hProcess) {
                Logger::Error("CrashHandler: Failed to open process {}", processId);
                return info;
            }

            // Generate filename
            fs::path dumpPath = fs::path(m_config.dumpDirectory) /
                               std::format(L"Process_{}.dmp", processId);

            info.filePath = dumpPath.wstring();
            info.dumpType = type;
            info.creationTime = std::chrono::system_clock::now();

            HANDLE hFile = CreateFileW(
                dumpPath.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                CloseHandle(hProcess);
                return info;
            }

            MINIDUMP_TYPE minidumpType = GetMinidumpType(type);

            BOOL success = MiniDumpWriteDump(
                hProcess,
                processId,
                hFile,
                minidumpType,
                nullptr,
                nullptr,
                nullptr
            );

            CloseHandle(hFile);
            CloseHandle(hProcess);

            if (success) {
                if (fs::exists(dumpPath)) {
                    info.fileSizeBytes = fs::file_size(dumpPath);
                }
                m_stats.dumpsCreated.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::CreateProcessDump: {}", e.what());
        }

        return info;
    }

    std::vector<DumpFileInfo> GetDumpFiles() const {
        std::vector<DumpFileInfo> dumps;

        try {
            if (!fs::exists(m_config.dumpDirectory)) {
                return dumps;
            }

            for (const auto& entry : fs::directory_iterator(m_config.dumpDirectory)) {
                if (entry.is_regular_file() && entry.path().extension() == L".dmp") {
                    DumpFileInfo info;
                    info.filePath = entry.path().wstring();
                    info.fileSizeBytes = entry.file_size();

                    auto ftime = entry.last_write_time();
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                    );
                    info.creationTime = sctp;

                    dumps.push_back(info);
                }
            }

            // Sort by creation time (newest first)
            std::sort(dumps.begin(), dumps.end(),
                [](const DumpFileInfo& a, const DumpFileInfo& b) {
                    return a.creationTime > b.creationTime;
                });

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::GetDumpFiles: {}", e.what());
        }

        return dumps;
    }

    uint32_t CleanupOldDumps(std::chrono::hours maxAge) {
        uint32_t deleted = 0;

        try {
            auto dumps = GetDumpFiles();
            auto now = std::chrono::system_clock::now();

            for (const auto& dump : dumps) {
                auto age = std::chrono::duration_cast<std::chrono::hours>(
                    now - dump.creationTime
                );

                if (age > maxAge) {
                    if (fs::remove(dump.filePath)) {
                        deleted++;
                    }
                }
            }

            // Also enforce max file count
            if (dumps.size() > m_config.maxDumpFiles) {
                for (size_t i = m_config.maxDumpFiles; i < dumps.size(); ++i) {
                    if (fs::remove(dumps[i].filePath)) {
                        deleted++;
                    }
                }
            }

            if (deleted > 0) {
                Logger::Info("CrashHandler: Cleaned up {} old dump files", deleted);
            }

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::CleanupOldDumps: {}", e.what());
        }

        return deleted;
    }

    // ========================================================================
    // CRASH ANALYSIS
    // ========================================================================

    CrashContext AnalyzeException(void* exceptionPointers) const {
        CrashContext context;

        try {
            auto* ep = static_cast<EXCEPTION_POINTERS*>(exceptionPointers);
            if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) {
                return context;
            }

            auto* record = ep->ExceptionRecord;
            auto* ctx = ep->ContextRecord;

            // Exception info
            context.exceptionCode = record->ExceptionCode;
            context.exceptionType = MapExceptionCode(record->ExceptionCode);
            context.exceptionAddress = reinterpret_cast<uint64_t>(record->ExceptionAddress);
            context.exceptionDescription = GetExceptionDescription(record->ExceptionCode);

            // Access violation specifics
            if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                record->NumberParameters >= 2) {
                context.isWriteViolation = (record->ExceptionInformation[0] == 1);
                context.accessAddress = record->ExceptionInformation[1];
            }

            // Process/thread info
            context.processId = GetCurrentProcessId();
            context.threadId = GetCurrentThreadId();

            wchar_t processPath[MAX_PATH];
            if (GetModuleFileNameW(nullptr, processPath, MAX_PATH)) {
                fs::path path(processPath);
                context.processName = path.filename().wstring();
            }

            // Module info
            context.faultingModule = GetModuleFromAddress(
                static_cast<uintptr_t>(context.exceptionAddress)
            );

            // Register state
#ifdef _M_X64
            context.registers.rax = ctx->Rax;
            context.registers.rbx = ctx->Rbx;
            context.registers.rcx = ctx->Rcx;
            context.registers.rdx = ctx->Rdx;
            context.registers.rsi = ctx->Rsi;
            context.registers.rdi = ctx->Rdi;
            context.registers.rsp = ctx->Rsp;
            context.registers.rbp = ctx->Rbp;
            context.registers.r8 = ctx->R8;
            context.registers.r9 = ctx->R9;
            context.registers.r10 = ctx->R10;
            context.registers.r11 = ctx->R11;
            context.registers.r12 = ctx->R12;
            context.registers.r13 = ctx->R13;
            context.registers.r14 = ctx->R14;
            context.registers.r15 = ctx->R15;
            context.registers.rip = ctx->Rip;
            context.registers.rflags = ctx->EFlags;
            context.registers.cs = ctx->SegCs;
            context.registers.ds = ctx->SegDs;
            context.registers.es = ctx->SegEs;
            context.registers.fs = ctx->SegFs;
            context.registers.gs = ctx->SegGs;
            context.registers.ss = ctx->SegSs;
#else
            context.registers.eax = ctx->Eax;
            context.registers.ebx = ctx->Ebx;
            context.registers.ecx = ctx->Ecx;
            context.registers.edx = ctx->Edx;
            context.registers.esi = ctx->Esi;
            context.registers.edi = ctx->Edi;
            context.registers.esp = ctx->Esp;
            context.registers.ebp = ctx->Ebp;
            context.registers.eip = ctx->Eip;
            context.registers.eflags = ctx->EFlags;
#endif

            // Capture stack trace
            context.stackTrace = CaptureStackTraceFromContext(ctx);

            // Memory around crash
#ifdef _M_X64
            uint64_t rip = ctx->Rip;
            uint64_t rsp = ctx->Rsp;
#else
            uint64_t rip = ctx->Eip;
            uint64_t rsp = ctx->Esp;
#endif

            // Read 128 bytes around RIP
            context.memoryNearRIP.resize(128);
            SafeReadMemory(reinterpret_cast<void*>(rip - 64),
                          context.memoryNearRIP.data(), 128);

            // Read 256 bytes around RSP
            context.memoryNearRSP.resize(256);
            SafeReadMemory(reinterpret_cast<void*>(rsp),
                          context.memoryNearRSP.data(), 256);

            // Timing
            context.crashTime = std::chrono::system_clock::now();
            context.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_uptime
            );

            // Determine severity
            switch (context.exceptionType) {
                case ExceptionType::AccessViolation:
                case ExceptionType::StackOverflow:
                case ExceptionType::HeapCorruption:
                    context.severity = CrashSeverity::Fatal;
                    break;
                case ExceptionType::IllegalInstruction:
                case ExceptionType::PrivilegedInstruction:
                    context.severity = CrashSeverity::Critical;
                    break;
                case ExceptionType::IntegerDivideByZero:
                case ExceptionType::FloatDivideByZero:
                    context.severity = CrashSeverity::NonCritical;
                    break;
                default:
                    context.severity = CrashSeverity::Critical;
                    break;
            }

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::AnalyzeException: {}", e.what());
        }

        return context;
    }

    std::vector<StackFrame> CaptureStackTrace(uint32_t maxFrames) const {
        void* stack[128];
        WORD frameCount = CaptureStackBackTrace(0, std::min(maxFrames, 128u), stack, nullptr);

        std::vector<StackFrame> frames;
        frames.reserve(frameCount);

        for (WORD i = 0; i < frameCount; ++i) {
            StackFrame frame;
            frame.instructionPointer = reinterpret_cast<uint64_t>(stack[i]);

            // Resolve symbol
            if (m_symbolResolver) {
                m_symbolResolver->ResolveSymbol(
                    frame.instructionPointer,
                    frame.moduleName,
                    frame.functionName,
                    frame.sourceFile,
                    frame.lineNumber,
                    frame.displacement
                );
            }

            frames.push_back(frame);
        }

        return frames;
    }

    std::vector<StackFrame> CaptureThreadStackTrace(uint32_t threadId, uint32_t maxFrames) const {
        std::vector<StackFrame> frames;

        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                                    THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread) {
            return frames;
        }

        if (SuspendThread(hThread) == (DWORD)-1) {
            CloseHandle(hThread);
            return frames;
        }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;

        if (GetThreadContext(hThread, &ctx)) {
            frames = CaptureStackTraceFromContext(&ctx);
        }

        ResumeThread(hThread);
        CloseHandle(hThread);

        return frames;
    }

    // ========================================================================
    // CRASH HISTORY
    // ========================================================================

    std::vector<CrashReport> GetCrashHistory() const {
        return m_historyManager->GetHistory();
    }

    std::optional<CrashReport> GetLastCrash() const {
        return m_historyManager->GetLast();
    }

    void ClearCrashHistory() {
        m_historyManager->Clear();
    }

    // ========================================================================
    // WATCHDOG INTEGRATION
    // ========================================================================

    void RegisterWatchdog(uint32_t watchdogProcessId) {
        std::unique_lock lock(m_mutex);
        m_watchdogPid = watchdogProcessId;
        Logger::Info("CrashHandler: Registered watchdog PID {}", watchdogProcessId);
    }

    void SendHeartbeat() {
        // Simplified - would send IPC message to watchdog
        m_lastHeartbeat = std::chrono::steady_clock::now();
    }

    void NotifyWatchdogRestart() {
        if (m_watchdogPid == 0) return;

        // Simplified - would send restart notification to watchdog
        Logger::Info("CrashHandler: Notifying watchdog of restart");
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterPreCrashCallback(PreCrashCallback callback) {
        return m_callbackManager->RegisterPreCrash(std::move(callback));
    }

    void UnregisterPreCrashCallback(uint64_t callbackId) {
        m_callbackManager->UnregisterPreCrash(callbackId);
    }

    uint64_t RegisterPostCrashCallback(PostCrashCallback callback) {
        return m_callbackManager->RegisterPostCrash(std::move(callback));
    }

    void UnregisterPostCrashCallback(uint64_t callbackId) {
        m_callbackManager->UnregisterPostCrash(callbackId);
    }

    void SetRecoveryCallback(RecoveryCallback callback) {
        m_callbackManager->SetRecovery(std::move(callback));
    }

    // ========================================================================
    // MANUAL CRASH SIMULATION
    // ========================================================================

    [[noreturn]] void TriggerCrash(ExceptionType type) {
        Logger::Warn("CrashHandler: Triggering simulated crash (type: {})",
            static_cast<int>(type));

        switch (type) {
            case ExceptionType::AccessViolation: {
                volatile int* ptr = nullptr;
                *ptr = 42;
                break;
            }
            case ExceptionType::IntegerDivideByZero: {
                volatile int x = 42;
                volatile int y = 0;
                volatile int z = x / y;
                (void)z;
                break;
            }
            case ExceptionType::StackOverflow: {
                TriggerCrash(type);  // Infinite recursion
                break;
            }
            case ExceptionType::IllegalInstruction: {
                __ud2();  // Invalid opcode
                break;
            }
            case ExceptionType::CppException: {
                throw std::runtime_error("Simulated C++ exception");
            }
            case ExceptionType::Abort: {
                std::abort();
            }
            default: {
                volatile int* ptr = nullptr;
                *ptr = 42;
                break;
            }
        }

        std::abort();  // Unreachable
    }

    [[noreturn]] void TriggerAssertion(const char* expression, const char* file, int line) {
        Logger::Critical("ASSERTION FAILED: {} at {}:{}", expression, file, line);

        // Create crash context
        CrashContext context;
        context.exceptionType = ExceptionType::Assertion;
        context.exceptionDescription = std::format(L"Assertion failed: {}",
            Utils::StringUtils::Utf8ToWide(expression));
        context.processId = GetCurrentProcessId();
        context.threadId = GetCurrentThreadId();
        context.crashTime = std::chrono::system_clock::now();
        context.severity = CrashSeverity::Fatal;

        // Handle crash
        HandleCrashInternal(context, nullptr);

        std::abort();
    }

    // ========================================================================
    // FEATURE CONTROL
    // ========================================================================

    void DisableHandling() noexcept {
        m_handlingEnabled.store(false, std::memory_order_release);
        Logger::Info("CrashHandler: Crash handling disabled");
    }

    void EnableHandling() noexcept {
        m_handlingEnabled.store(true, std::memory_order_release);
        Logger::Info("CrashHandler: Crash handling enabled");
    }

    bool IsHandlingEnabled() const noexcept {
        return m_handlingEnabled.load(std::memory_order_acquire);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const CrashHandlerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void InstallHandlers() {
        // Vectored exception handler (first chance)
        m_vehHandle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);

        // Unhandled exception filter (last resort)
        m_prevUnhandledFilter = SetUnhandledExceptionFilter(UnhandledExceptionFilter);

        // C runtime handlers
        _set_purecall_handler(PureCallHandler);
        _set_invalid_parameter_handler(InvalidParameterHandler);

        // Signal handlers
        signal(SIGABRT, SignalHandler);
        signal(SIGFPE, SignalHandler);
        signal(SIGILL, SignalHandler);
        signal(SIGSEGV, SignalHandler);

        Logger::Info("CrashHandler: Exception handlers installed");
    }

    void UninstallHandlers() noexcept {
        if (m_vehHandle) {
            RemoveVectoredExceptionHandler(m_vehHandle);
            m_vehHandle = nullptr;
        }

        if (m_prevUnhandledFilter) {
            SetUnhandledExceptionFilter(m_prevUnhandledFilter);
            m_prevUnhandledFilter = nullptr;
        }
    }

    static LONG WINAPI VectoredExceptionHandler(EXCEPTION_POINTERS* ep) {
        auto& instance = GetImpl();

        if (!instance.IsHandlingEnabled()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        instance.m_stats.handledExceptions.fetch_add(1, std::memory_order_relaxed);

        // Let debugger handle first
        if (IsDebuggerPresent()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Analyze exception
        CrashContext context = instance.AnalyzeException(ep);

        // Update type-specific stats
        switch (context.exceptionType) {
            case ExceptionType::AccessViolation:
                instance.m_stats.accessViolations.fetch_add(1, std::memory_order_relaxed);
                break;
            case ExceptionType::StackOverflow:
                instance.m_stats.stackOverflows.fetch_add(1, std::memory_order_relaxed);
                break;
            case ExceptionType::HeapCorruption:
                instance.m_stats.heapCorruptions.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }

        // Handle crash
        instance.HandleCrashInternal(context, ep);

        return EXCEPTION_EXECUTE_HANDLER;
    }

    static LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* ep) {
        auto& instance = GetImpl();

        if (!instance.IsHandlingEnabled()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        CrashContext context = instance.AnalyzeException(ep);
        instance.HandleCrashInternal(context, ep);

        return EXCEPTION_EXECUTE_HANDLER;
    }

    static void __cdecl PureCallHandler() {
        auto& instance = GetImpl();

        CrashContext context;
        context.exceptionType = ExceptionType::PureVirtualCall;
        context.exceptionDescription = L"Pure virtual function call";
        context.severity = CrashSeverity::Fatal;

        instance.HandleCrashInternal(context, nullptr);

        std::abort();
    }

    static void __cdecl InvalidParameterHandler(
        const wchar_t* expression,
        const wchar_t* function,
        const wchar_t* file,
        unsigned int line,
        uintptr_t reserved) {

        auto& instance = GetImpl();

        CrashContext context;
        context.exceptionType = ExceptionType::InvalidParameter;
        context.exceptionDescription = std::format(L"Invalid parameter: {}",
            expression ? expression : L"<unknown>");
        context.severity = CrashSeverity::Critical;

        instance.HandleCrashInternal(context, nullptr);

        std::abort();
    }

    static void __cdecl SignalHandler(int signal) {
        auto& instance = GetImpl();

        CrashContext context;
        context.exceptionType = ExceptionType::Abort;
        context.exceptionDescription = std::format(L"Signal {}", signal);
        context.severity = CrashSeverity::Fatal;

        instance.HandleCrashInternal(context, nullptr);

        std::abort();
    }

    void HandleCrashInternal(const CrashContext& context, void* exceptionPointers) {
        try {
            m_stats.totalCrashes.fetch_add(1, std::memory_order_relaxed);

            Logger::Critical("CRASH DETECTED: {} at 0x{:X}",
                Utils::StringUtils::WideToUtf8(context.exceptionDescription),
                context.exceptionAddress);

            // Invoke pre-crash callbacks
            m_callbackManager->InvokePreCrash(context);

            // Create crash report
            CrashReport report;
            report.reportId = GenerateCrashId();
            report.crashSequence = m_historyManager->GetNextSequence();
            report.context = context;
            report.osVersion = L"Windows 10/11";  // Simplified
            report.avVersion = L"ShadowStrike 3.0.0";
            report.reportTime = std::chrono::system_clock::now();

            // Create minidump
            if (m_config.createDumpOnCrash) {
                report.dumpFile = CreateDump(m_config.defaultDumpType, L"Crash");
            }

            // Add to history
            m_historyManager->AddCrash(report);

            // Determine recovery action
            RecoveryAction action = m_callbackManager->InvokeRecovery(context);
            if (action == RecoveryAction::None) {
                action = m_config.defaultRecoveryAction;
            }

            report.actionTaken = action;

            // Execute recovery
            switch (action) {
                case RecoveryAction::RestartService:
                    NotifyWatchdogRestart();
                    m_stats.restartAttempts.fetch_add(1, std::memory_order_relaxed);
                    break;

                case RecoveryAction::RestartProcess:
                    m_stats.restartAttempts.fetch_add(1, std::memory_order_relaxed);
                    // Would restart process
                    break;

                case RecoveryAction::NotifyWatchdog:
                    NotifyWatchdogRestart();
                    break;

                default:
                    break;
            }

            // Invoke post-crash callbacks
            m_callbackManager->InvokePostCrash(report);

            // Update fatal crash count
            if (context.severity == CrashSeverity::Fatal) {
                m_stats.fatalCrashes.fetch_add(1, std::memory_order_relaxed);
            } else {
                m_stats.recoveredCrashes.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Critical("CrashHandler::HandleCrashInternal: Exception during crash handling: {}",
                e.what());
        }
    }

    std::vector<StackFrame> CaptureStackTraceFromContext(CONTEXT* ctx) const {
        std::vector<StackFrame> frames;

        try {
            HANDLE hProcess = GetCurrentProcess();
            HANDLE hThread = GetCurrentThread();

#ifdef _M_X64
            STACKFRAME64 stackFrame = {};
            stackFrame.AddrPC.Offset = ctx->Rip;
            stackFrame.AddrPC.Mode = AddrModeFlat;
            stackFrame.AddrFrame.Offset = ctx->Rbp;
            stackFrame.AddrFrame.Mode = AddrModeFlat;
            stackFrame.AddrStack.Offset = ctx->Rsp;
            stackFrame.AddrStack.Mode = AddrModeFlat;

            DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#else
            STACKFRAME64 stackFrame = {};
            stackFrame.AddrPC.Offset = ctx->Eip;
            stackFrame.AddrPC.Mode = AddrModeFlat;
            stackFrame.AddrFrame.Offset = ctx->Ebp;
            stackFrame.AddrFrame.Mode = AddrModeFlat;
            stackFrame.AddrStack.Offset = ctx->Esp;
            stackFrame.AddrStack.Mode = AddrModeFlat;

            DWORD machineType = IMAGE_FILE_MACHINE_I386;
#endif

            for (uint32_t i = 0; i < 64; ++i) {
                if (!StackWalk64(
                    machineType,
                    hProcess,
                    hThread,
                    &stackFrame,
                    ctx,
                    nullptr,
                    SymFunctionTableAccess64,
                    SymGetModuleBase64,
                    nullptr)) {
                    break;
                }

                if (stackFrame.AddrPC.Offset == 0) {
                    break;
                }

                StackFrame frame;
                frame.instructionPointer = stackFrame.AddrPC.Offset;
                frame.returnAddress = stackFrame.AddrReturn.Offset;
                frame.framePointer = stackFrame.AddrFrame.Offset;

                // Resolve symbol
                if (m_symbolResolver) {
                    m_symbolResolver->ResolveSymbol(
                        frame.instructionPointer,
                        frame.moduleName,
                        frame.functionName,
                        frame.sourceFile,
                        frame.lineNumber,
                        frame.displacement
                    );
                }

                frames.push_back(frame);
            }

        } catch (const std::exception& e) {
            Logger::Error("CrashHandler::CaptureStackTraceFromContext: {}", e.what());
        }

        return frames;
    }

    static CrashHandlerImpl& GetImpl() {
        return *CrashHandler::Instance().m_impl;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    CrashHandlerConfig m_config;

    // Handlers
    void* m_vehHandle{ nullptr };
    LPTOP_LEVEL_EXCEPTION_FILTER m_prevUnhandledFilter{ nullptr };

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<CrashHistoryManager> m_historyManager;
    std::unique_ptr<SymbolResolver> m_symbolResolver;

    // Watchdog
    uint32_t m_watchdogPid{ 0 };
    std::chrono::steady_clock::time_point m_lastHeartbeat;

    // State
    std::atomic<bool> m_handlingEnabled{ true };
    std::chrono::steady_clock::time_point m_uptime;

    // Statistics
    mutable CrashHandlerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

CrashHandler::CrashHandler()
    : m_impl(std::make_unique<CrashHandlerImpl>()) {
}

CrashHandler::~CrashHandler() = default;

CrashHandler& CrashHandler::Instance() {
    static CrashHandler instance;
    return instance;
}

bool CrashHandler::Initialize(const CrashHandlerConfig& config) {
    return m_impl->Initialize(config);
}

void CrashHandler::Shutdown() noexcept {
    m_impl->Shutdown();
}

DumpFileInfo CrashHandler::CreateDump(DumpType type, const std::wstring& reason) {
    return m_impl->CreateDump(type, reason);
}

DumpFileInfo CrashHandler::CreateProcessDump(uint32_t processId, DumpType type) {
    return m_impl->CreateProcessDump(processId, type);
}

std::vector<DumpFileInfo> CrashHandler::GetDumpFiles() const {
    return m_impl->GetDumpFiles();
}

uint32_t CrashHandler::CleanupOldDumps(std::chrono::hours maxAge) {
    return m_impl->CleanupOldDumps(maxAge);
}

CrashContext CrashHandler::AnalyzeException(void* exceptionPointers) const {
    return m_impl->AnalyzeException(exceptionPointers);
}

std::vector<StackFrame> CrashHandler::CaptureStackTrace(uint32_t maxFrames) const {
    return m_impl->CaptureStackTrace(maxFrames);
}

std::vector<StackFrame> CrashHandler::CaptureThreadStackTrace(uint32_t threadId, uint32_t maxFrames) const {
    return m_impl->CaptureThreadStackTrace(threadId, maxFrames);
}

std::vector<CrashReport> CrashHandler::GetCrashHistory() const {
    return m_impl->GetCrashHistory();
}

std::optional<CrashReport> CrashHandler::GetLastCrash() const {
    return m_impl->GetLastCrash();
}

void CrashHandler::ClearCrashHistory() {
    m_impl->ClearCrashHistory();
}

void CrashHandler::RegisterWatchdog(uint32_t watchdogProcessId) {
    m_impl->RegisterWatchdog(watchdogProcessId);
}

void CrashHandler::SendHeartbeat() {
    m_impl->SendHeartbeat();
}

void CrashHandler::NotifyWatchdogRestart() {
    m_impl->NotifyWatchdogRestart();
}

uint64_t CrashHandler::RegisterPreCrashCallback(PreCrashCallback callback) {
    return m_impl->RegisterPreCrashCallback(std::move(callback));
}

void CrashHandler::UnregisterPreCrashCallback(uint64_t callbackId) {
    m_impl->UnregisterPreCrashCallback(callbackId);
}

uint64_t CrashHandler::RegisterPostCrashCallback(PostCrashCallback callback) {
    return m_impl->RegisterPostCrashCallback(std::move(callback));
}

void CrashHandler::UnregisterPostCrashCallback(uint64_t callbackId) {
    m_impl->UnregisterPostCrashCallback(callbackId);
}

void CrashHandler::SetRecoveryCallback(RecoveryCallback callback) {
    m_impl->SetRecoveryCallback(std::move(callback));
}

[[noreturn]] void CrashHandler::TriggerCrash(ExceptionType type) {
    m_impl->TriggerCrash(type);
}

[[noreturn]] void CrashHandler::TriggerAssertion(const char* expression, const char* file, int line) {
    m_impl->TriggerAssertion(expression, file, line);
}

void CrashHandler::DisableHandling() noexcept {
    m_impl->DisableHandling();
}

void CrashHandler::EnableHandling() noexcept {
    m_impl->EnableHandling();
}

bool CrashHandler::IsHandlingEnabled() const noexcept {
    return m_impl->IsHandlingEnabled();
}

const CrashHandlerStatistics& CrashHandler::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void CrashHandler::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
