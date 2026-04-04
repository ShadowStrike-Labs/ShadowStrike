/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APITypes.hpp — Win32/NT type definitions, status codes, and API handler contracts
 *
 * This file defines the type system for Windows API emulation WITHOUT
 * depending on <windows.h>. Every type here is a self-contained reproduction
 * of the corresponding Win32/NT type, sized exactly as the real OS expects.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Errors.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <variant>
#include <optional>
#include <array>

namespace Phantom {

// Forward declarations
class VirtualMemory;
class CPUState;
class HandleTable;
class APIDispatcher;
class ExportResolver;
class ImportResolver;
enum class BehaviorFlag : uint32_t;

// ============================================================================
// Guest-side Win32/NT Primitive Types
// ============================================================================
// These match the sizes/semantics of real Windows types in the guest environment.
// They are NOT host types — they represent values inside the emulated process.

using GuestHandle    = uint64_t;    // HANDLE (always 64-bit in our address space)
using GuestDword     = uint32_t;    // DWORD
using GuestBool      = int32_t;     // BOOL (Win32 BOOL is int, not bool)
using GuestWord      = uint16_t;    // WORD
using GuestLong      = int32_t;     // LONG
using GuestUlong     = uint32_t;    // ULONG
using GuestUlongPtr  = uint64_t;    // ULONG_PTR (pointer-sized)
using GuestSizeT     = uint64_t;    // SIZE_T
using GuestNtStatus  = int32_t;     // NTSTATUS
using GuestHResult   = int32_t;     // HRESULT
using GuestLargeInt  = int64_t;     // LARGE_INTEGER

// Special HANDLE sentinel values (matching Windows)
static constexpr GuestHandle kInvalidHandleValue = static_cast<GuestHandle>(-1);
static constexpr GuestHandle kNullHandle         = 0;
static constexpr GuestHandle kCurrentProcess     = static_cast<GuestHandle>(-1);
static constexpr GuestHandle kCurrentThread      = static_cast<GuestHandle>(-2);

// Pseudo-handles for stdin/stdout/stderr
static constexpr GuestHandle kStdInputHandle     = static_cast<GuestHandle>(-10);
static constexpr GuestHandle kStdOutputHandle    = static_cast<GuestHandle>(-11);
static constexpr GuestHandle kStdErrorHandle     = static_cast<GuestHandle>(-12);

// ============================================================================
// NTSTATUS Codes
// ============================================================================
// Severity: bits 31-30 (00=success, 01=info, 10=warning, 11=error)

namespace NT {
    static constexpr GuestNtStatus STATUS_SUCCESS                 = 0x00000000;
    static constexpr GuestNtStatus STATUS_PENDING                 = 0x00000103;
    static constexpr GuestNtStatus STATUS_BUFFER_OVERFLOW         = static_cast<int32_t>(0x80000005);
    static constexpr GuestNtStatus STATUS_NO_MORE_ENTRIES         = static_cast<int32_t>(0x8000001A);
    static constexpr GuestNtStatus STATUS_UNSUCCESSFUL            = static_cast<int32_t>(0xC0000001);
    static constexpr GuestNtStatus STATUS_NOT_IMPLEMENTED         = static_cast<int32_t>(0xC0000002);
    static constexpr GuestNtStatus STATUS_INVALID_INFO_CLASS      = static_cast<int32_t>(0xC0000003);
    static constexpr GuestNtStatus STATUS_INFO_LENGTH_MISMATCH    = static_cast<int32_t>(0xC0000004);
    static constexpr GuestNtStatus STATUS_ACCESS_VIOLATION        = static_cast<int32_t>(0xC0000005);
    static constexpr GuestNtStatus STATUS_INVALID_HANDLE          = static_cast<int32_t>(0xC0000008);
    static constexpr GuestNtStatus STATUS_INVALID_PARAMETER       = static_cast<int32_t>(0xC000000D);
    static constexpr GuestNtStatus STATUS_NO_SUCH_FILE            = static_cast<int32_t>(0xC000000F);
    static constexpr GuestNtStatus STATUS_END_OF_FILE             = static_cast<int32_t>(0xC0000011);
    static constexpr GuestNtStatus STATUS_NO_MEMORY               = static_cast<int32_t>(0xC0000017);
    static constexpr GuestNtStatus STATUS_CONFLICTING_ADDRESSES   = static_cast<int32_t>(0xC0000018);
    static constexpr GuestNtStatus STATUS_ACCESS_DENIED           = static_cast<int32_t>(0xC0000022);
    static constexpr GuestNtStatus STATUS_BUFFER_TOO_SMALL        = static_cast<int32_t>(0xC0000023);
    static constexpr GuestNtStatus STATUS_OBJECT_TYPE_MISMATCH    = static_cast<int32_t>(0xC0000024);
    static constexpr GuestNtStatus STATUS_OBJECT_NAME_NOT_FOUND   = static_cast<int32_t>(0xC0000034);
    static constexpr GuestNtStatus STATUS_OBJECT_NAME_COLLISION   = static_cast<int32_t>(0xC0000035);
    static constexpr GuestNtStatus STATUS_OBJECT_PATH_NOT_FOUND   = static_cast<int32_t>(0xC000003A);
    static constexpr GuestNtStatus STATUS_OBJECT_PATH_SYNTAX_BAD  = static_cast<int32_t>(0xC000003B);
    static constexpr GuestNtStatus STATUS_SHARING_VIOLATION       = static_cast<int32_t>(0xC0000043);
    static constexpr GuestNtStatus STATUS_INSUFFICIENT_RESOURCES  = static_cast<int32_t>(0xC000009A);
    static constexpr GuestNtStatus STATUS_NOT_SUPPORTED           = static_cast<int32_t>(0xC00000BB);
    static constexpr GuestNtStatus STATUS_ILLEGAL_FUNCTION        = static_cast<int32_t>(0xC00000AF);
    static constexpr GuestNtStatus STATUS_PRIVILEGE_NOT_HELD      = static_cast<int32_t>(0xC0000061);
    static constexpr GuestNtStatus STATUS_PROCEDURE_NOT_FOUND     = static_cast<int32_t>(0xC000007A);
    static constexpr GuestNtStatus STATUS_DLL_NOT_FOUND           = static_cast<int32_t>(0xC0000135);
    static constexpr GuestNtStatus STATUS_ENTRYPOINT_NOT_FOUND    = static_cast<int32_t>(0xC0000139);
    static constexpr GuestNtStatus STATUS_DLL_INIT_FAILED         = static_cast<int32_t>(0xC0000142);
    static constexpr GuestNtStatus STATUS_PORT_NOT_SET            = static_cast<int32_t>(0xC0000353);
    static constexpr GuestNtStatus STATUS_NOT_FOUND               = static_cast<int32_t>(0xC0000225);
    static constexpr GuestNtStatus STATUS_TIMEOUT                 = 0x00000102;

    [[nodiscard]] constexpr bool NT_SUCCESS(GuestNtStatus s) noexcept { return s >= 0; }
    [[nodiscard]] constexpr bool NT_ERROR(GuestNtStatus s) noexcept { return s < 0; }

    // NtQuerySystemInformation classes
    enum class SystemInformationClass : uint32_t {
        SystemBasicInformation           = 0,
        SystemProcessorInformation       = 1,
        SystemPerformanceInformation     = 2,
        SystemTimeOfDayInformation       = 3,
        SystemProcessInformation         = 5,
        SystemModuleInformation          = 11,
        SystemHandleInformation          = 16,
        SystemObjectInformation          = 17,
        SystemKernelDebuggerInformation  = 35,
        SystemFirmwareTableInformation   = 76,
        SystemCodeIntegrityInformation   = 103,
    };

    // NtQueryInformationProcess classes
    enum class ProcessInformationClass : uint32_t {
        ProcessBasicInformation          = 0,
        ProcessDebugPort                 = 7,
        ProcessWow64Information          = 26,
        ProcessImageFileName             = 27,
        ProcessBreakOnTermination        = 29,
        ProcessDebugObjectHandle         = 30,
        ProcessDebugFlags                = 31,
        ProcessImageFileNameWin32        = 43,
    };

    // Memory allocation types
    static constexpr uint32_t MEM_COMMIT      = 0x1000;
    static constexpr uint32_t MEM_RESERVE     = 0x2000;
    static constexpr uint32_t MEM_DECOMMIT    = 0x4000;
    static constexpr uint32_t MEM_RELEASE     = 0x8000;
    static constexpr uint32_t MEM_RESET       = 0x80000;
    static constexpr uint32_t MEM_TOP_DOWN    = 0x100000;
    static constexpr uint32_t MEM_WRITE_WATCH = 0x200000;
    static constexpr uint32_t MEM_LARGE_PAGES = 0x20000000;

    // Memory protection constants
    static constexpr uint32_t PAGE_NOACCESS          = 0x01;
    static constexpr uint32_t PAGE_READONLY          = 0x02;
    static constexpr uint32_t PAGE_READWRITE         = 0x04;
    static constexpr uint32_t PAGE_WRITECOPY         = 0x08;
    static constexpr uint32_t PAGE_EXECUTE           = 0x10;
    static constexpr uint32_t PAGE_EXECUTE_READ      = 0x20;
    static constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
    static constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
    static constexpr uint32_t PAGE_GUARD             = 0x100;
    static constexpr uint32_t PAGE_NOCACHE           = 0x200;
    static constexpr uint32_t PAGE_WRITECOMBINE      = 0x400;

    // File access rights
    static constexpr uint32_t FILE_READ_DATA         = 0x0001;
    static constexpr uint32_t FILE_WRITE_DATA        = 0x0002;
    static constexpr uint32_t FILE_APPEND_DATA       = 0x0004;
    static constexpr uint32_t FILE_READ_EA           = 0x0008;
    static constexpr uint32_t FILE_WRITE_EA          = 0x0010;
    static constexpr uint32_t FILE_EXECUTE           = 0x0020;
    static constexpr uint32_t FILE_READ_ATTRIBUTES   = 0x0080;
    static constexpr uint32_t FILE_WRITE_ATTRIBUTES  = 0x0100;
    static constexpr uint32_t GENERIC_READ           = 0x80000000;
    static constexpr uint32_t GENERIC_WRITE          = 0x40000000;
    static constexpr uint32_t GENERIC_EXECUTE        = 0x20000000;
    static constexpr uint32_t GENERIC_ALL            = 0x10000000;

    // File share mode
    static constexpr uint32_t FILE_SHARE_READ   = 0x01;
    static constexpr uint32_t FILE_SHARE_WRITE  = 0x02;
    static constexpr uint32_t FILE_SHARE_DELETE = 0x04;

    // File creation disposition
    static constexpr uint32_t CREATE_NEW        = 1;
    static constexpr uint32_t CREATE_ALWAYS     = 2;
    static constexpr uint32_t OPEN_EXISTING     = 3;
    static constexpr uint32_t OPEN_ALWAYS       = 4;
    static constexpr uint32_t TRUNCATE_EXISTING = 5;

    // Registry key access
    static constexpr uint32_t KEY_QUERY_VALUE    = 0x0001;
    static constexpr uint32_t KEY_SET_VALUE      = 0x0002;
    static constexpr uint32_t KEY_CREATE_SUB_KEY = 0x0004;
    static constexpr uint32_t KEY_ENUMERATE_SUB_KEYS = 0x0008;
    static constexpr uint32_t KEY_NOTIFY         = 0x0010;
    static constexpr uint32_t KEY_ALL_ACCESS     = 0x000F003F;
    static constexpr uint32_t KEY_READ           = 0x00020019;
    static constexpr uint32_t KEY_WRITE          = 0x00020006;

    // Registry value types
    static constexpr uint32_t REG_NONE      = 0;
    static constexpr uint32_t REG_SZ        = 1;
    static constexpr uint32_t REG_EXPAND_SZ = 2;
    static constexpr uint32_t REG_BINARY    = 3;
    static constexpr uint32_t REG_DWORD     = 4;
    static constexpr uint32_t REG_MULTI_SZ  = 7;
    static constexpr uint32_t REG_QWORD     = 11;

    // Process access rights
    static constexpr uint32_t PROCESS_TERMINATE         = 0x0001;
    static constexpr uint32_t PROCESS_CREATE_THREAD     = 0x0002;
    static constexpr uint32_t PROCESS_VM_OPERATION      = 0x0008;
    static constexpr uint32_t PROCESS_VM_READ           = 0x0010;
    static constexpr uint32_t PROCESS_VM_WRITE          = 0x0020;
    static constexpr uint32_t PROCESS_DUP_HANDLE        = 0x0040;
    static constexpr uint32_t PROCESS_CREATE_PROCESS    = 0x0080;
    static constexpr uint32_t PROCESS_QUERY_INFORMATION = 0x0400;
    static constexpr uint32_t PROCESS_ALL_ACCESS        = 0x001FFFFF;

    // Thread access rights
    static constexpr uint32_t THREAD_TERMINATE         = 0x0001;
    static constexpr uint32_t THREAD_SUSPEND_RESUME    = 0x0002;
    static constexpr uint32_t THREAD_GET_CONTEXT       = 0x0008;
    static constexpr uint32_t THREAD_SET_CONTEXT       = 0x0010;
    static constexpr uint32_t THREAD_QUERY_INFORMATION = 0x0040;
    static constexpr uint32_t THREAD_ALL_ACCESS        = 0x001FFFFF;

} // namespace NT

// ============================================================================
// Win32 Error Codes
// ============================================================================

namespace Win32 {
    static constexpr GuestDword ERROR_SUCCESS             = 0;
    static constexpr GuestDword ERROR_INVALID_FUNCTION    = 1;
    static constexpr GuestDword ERROR_FILE_NOT_FOUND      = 2;
    static constexpr GuestDword ERROR_PATH_NOT_FOUND      = 3;
    static constexpr GuestDword ERROR_TOO_MANY_OPEN_FILES = 4;
    static constexpr GuestDword ERROR_ACCESS_DENIED       = 5;
    static constexpr GuestDword ERROR_INVALID_HANDLE      = 6;
    static constexpr GuestDword ERROR_NOT_ENOUGH_MEMORY   = 8;
    static constexpr GuestDword ERROR_OUTOFMEMORY         = 14;
    static constexpr GuestDword ERROR_INVALID_DRIVE       = 15;
    static constexpr GuestDword ERROR_NO_MORE_FILES       = 18;
    static constexpr GuestDword ERROR_NOT_READY           = 21;
    static constexpr GuestDword ERROR_SHARING_VIOLATION   = 32;
    static constexpr GuestDword ERROR_HANDLE_EOF          = 38;
    static constexpr GuestDword ERROR_NOT_SUPPORTED       = 50;
    static constexpr GuestDword ERROR_INVALID_PARAMETER   = 87;
    static constexpr GuestDword ERROR_INSUFFICIENT_BUFFER = 122;
    static constexpr GuestDword ERROR_INVALID_NAME        = 123;
    static constexpr GuestDword ERROR_MOD_NOT_FOUND       = 126;
    static constexpr GuestDword ERROR_PROC_NOT_FOUND      = 127;
    static constexpr GuestDword ERROR_ALREADY_EXISTS      = 183;
    static constexpr GuestDword ERROR_MORE_DATA           = 234;
    static constexpr GuestDword ERROR_NO_MORE_ITEMS       = 259;
    static constexpr GuestDword ERROR_NOACCESS            = 998;
    static constexpr GuestDword ERROR_NOT_FOUND           = 1168;
    static constexpr GuestDword WAIT_TIMEOUT              = 258;
    static constexpr GuestDword WAIT_OBJECT_0             = 0;
    static constexpr GuestDword WAIT_ABANDONED            = 0x80;
    static constexpr GuestDword WAIT_FAILED               = 0xFFFFFFFF;
    static constexpr GuestDword STILL_ACTIVE              = 259;

    // Translate NTSTATUS → Win32 error code (common mappings)
    [[nodiscard]] constexpr GuestDword NtStatusToWin32(GuestNtStatus status) noexcept {
        switch (static_cast<uint32_t>(status)) {
            case 0x00000000: return ERROR_SUCCESS;
            case 0xC000000D: return ERROR_INVALID_PARAMETER;
            case 0xC0000008: return ERROR_INVALID_HANDLE;
            case 0xC000000F: return ERROR_FILE_NOT_FOUND;
            case 0xC0000022: return ERROR_ACCESS_DENIED;
            case 0xC0000017: return ERROR_NOT_ENOUGH_MEMORY;
            case 0xC0000034: return ERROR_FILE_NOT_FOUND;
            case 0xC000003A: return ERROR_PATH_NOT_FOUND;
            case 0xC0000043: return ERROR_SHARING_VIOLATION;
            case 0xC00000BB: return ERROR_NOT_SUPPORTED;
            default:         return ERROR_INVALID_FUNCTION;
        }
    }
} // namespace Win32

// ============================================================================
// Handle Types — Discriminated handle entries for the HandleTable
// ============================================================================

enum class HandleType : uint8_t {
    Invalid = 0,
    File,
    Directory,
    RegistryKey,
    Process,
    Thread,
    Mutex,
    Event,
    Semaphore,
    Section,        // Memory-mapped file
    Token,
    Pipe,
    Mailslot,
    Socket,
    Timer,
    Module,         // Loaded DLL reference
    Job,
};

// Resource associated with a handle entry
struct FileHandleData {
    std::wstring path;
    uint32_t     accessMask   = 0;
    uint32_t     shareMode    = 0;
    uint64_t     filePosition = 0;
    uint64_t     fileSize     = 0;
    bool         isDirectory  = false;
    bool         isReadOnly   = false;
};

struct RegistryKeyHandleData {
    std::wstring path;
    uint32_t     accessMask   = 0;
    bool         isVolatile   = false;
};

struct ProcessHandleData {
    uint32_t     pid          = 0;
    uint32_t     accessMask   = 0;
    bool         isSelf       = false;
    GuestAddress imageBase    = 0;
};

struct ThreadHandleData {
    uint32_t     tid          = 0;
    uint32_t     ownerPid     = 0;
    uint32_t     accessMask   = 0;
    bool         suspended    = false;
};

struct SyncObjectData {
    std::wstring name;
    bool         signaled     = false;
    int32_t      count        = 0;    // Semaphore count, mutex recursion depth
};

struct SectionData {
    std::wstring name;
    uint64_t     maxSize      = 0;
    uint32_t     protection   = 0;
    GuestAddress mappedBase   = 0;
    GuestSize    mappedSize   = 0;
};

struct SocketData {
    int32_t      family       = 0;    // AF_INET, AF_INET6
    int32_t      type         = 0;    // SOCK_STREAM, SOCK_DGRAM
    int32_t      protocol     = 0;
    std::string  remoteAddr;
    uint16_t     remotePort   = 0;
    std::string  localAddr;
    uint16_t     localPort    = 0;
    bool         connected    = false;
    bool         listening    = false;
    bool         bound        = false;
};

struct ModuleHandleData {
    std::wstring name;
    GuestAddress imageBase   = 0;
    GuestSize    imageSize   = 0;
};

// Variant holding any handle-associated resource data
using HandleData = std::variant<
    std::monostate,              // Invalid/empty
    FileHandleData,
    RegistryKeyHandleData,
    ProcessHandleData,
    ThreadHandleData,
    SyncObjectData,
    SectionData,
    SocketData,
    ModuleHandleData
>;

// ============================================================================
// APIContext — Passed to every API handler
// ============================================================================
// The unified context that gives handlers access to:
// - CPU registers (reading args, writing return values)
// - Guest memory (reading/writing buffers)
// - Handle table (creating/looking up handles)
// - Configuration (behavior toggles, environment faking)
// - Per-thread TLS (last error, etc.)

struct ThreadLocalState {
    GuestDword lastError    = 0;
    uint32_t   threadId     = 0;
    GuestAddress tebAddress = 0;
};

class APIContext {
public:
    APIContext(CPUState& cpu, VirtualMemory& mem, HandleTable& handles,
              const EmulationConfig& config, ThreadLocalState& tls,
              APIDispatcher* dispatcher = nullptr) noexcept
        : m_cpu(cpu), m_mem(mem), m_handles(handles), m_config(config),
          m_tls(tls), m_dispatcher(dispatcher) {}

    // === Register Access ===
    [[nodiscard]] CPUState&       CPU()     noexcept { return m_cpu; }
    [[nodiscard]] const CPUState& CPU()     const noexcept { return m_cpu; }
    [[nodiscard]] VirtualMemory&  Memory()  noexcept { return m_mem; }
    [[nodiscard]] HandleTable&    Handles() noexcept { return m_handles; }
    [[nodiscard]] const EmulationConfig& Config() const noexcept { return m_config; }
    [[nodiscard]] ThreadLocalState& TLS()   noexcept { return m_tls; }
    [[nodiscard]] APIDispatcher*   Dispatcher() const noexcept { return m_dispatcher; }

    // === Argument Extraction (calling-convention-aware) ===
    // x64 Windows: RCX, RDX, R8, R9, then stack (RSP+0x28, RSP+0x30, ...)
    // x86 stdcall: all on stack (ESP+4, ESP+8, ...)
    [[nodiscard]] uint64_t GetArg(uint32_t index) const noexcept;
    [[nodiscard]] uint32_t GetArg32(uint32_t index) const noexcept;
    [[nodiscard]] GuestAddress GetArgPtr(uint32_t index) const noexcept;

    // Read a guest string argument (ANSI, null-terminated)
    [[nodiscard]] std::string ReadAnsiString(GuestAddress addr, uint32_t maxLen = 4096) const noexcept;
    // Read a guest wide string argument (UTF-16LE, null-terminated)
    [[nodiscard]] std::wstring ReadWideString(GuestAddress addr, uint32_t maxChars = 2048) const noexcept;
    // Read a UNICODE_STRING structure (Length, MaximumLength, Buffer)
    [[nodiscard]] std::wstring ReadUnicodeString(GuestAddress addr) const noexcept;

    // Write a string to guest memory
    [[nodiscard]] ErrorCode WriteAnsiString(GuestAddress addr, std::string_view str,
                                            uint32_t maxLen) noexcept;
    [[nodiscard]] ErrorCode WriteWideString(GuestAddress addr, std::wstring_view str,
                                            uint32_t maxChars) noexcept;

    // === Return Value ===
    void SetReturn(uint64_t value) noexcept;
    void SetReturn32(uint32_t value) noexcept;
    void SetReturnBool(bool value) noexcept;     // Win32 BOOL: TRUE=1, FALSE=0
    void SetReturnHandle(GuestHandle h) noexcept;
    void SetReturnNtStatus(GuestNtStatus status) noexcept;

    // === Last Error ===
    void SetLastError(GuestDword err) noexcept;
    [[nodiscard]] GuestDword GetLastError() const noexcept;

    // === Convenience: Fail with Win32 error and return FALSE/INVALID_HANDLE ===
    void FailWithError(GuestDword err) noexcept;
    void FailWithInvalidHandle(GuestDword err) noexcept;

    // === Stack cleanup (for x86 stdcall: pop N bytes from stack after return) ===
    void CleanupStack(uint32_t bytes) noexcept;

    // === Mode queries ===
    [[nodiscard]] bool Is64Bit() const noexcept;

    // === Per-call behavioral annotations ===
    void AddBehaviorFlag(BehaviorFlag flag) noexcept {
        m_behaviorFlags |= static_cast<uint32_t>(flag);
    }
    void AddBehaviorFlags(BehaviorFlag flags) noexcept {
        m_behaviorFlags |= static_cast<uint32_t>(flags);
    }
    [[nodiscard]] BehaviorFlag GetBehaviorFlags() const noexcept {
        return static_cast<BehaviorFlag>(m_behaviorFlags);
    }

private:
    CPUState&              m_cpu;
    VirtualMemory&         m_mem;
    HandleTable&           m_handles;
    const EmulationConfig& m_config;
    ThreadLocalState&      m_tls;
    APIDispatcher*         m_dispatcher = nullptr;
    uint32_t               m_behaviorFlags = 0;
};

// ============================================================================
// API Handler Function Signature
// ============================================================================
// Every emulated API function has this signature. It receives the full context
// and returns true if the call was handled (execution continues), or false
// if execution should stop (e.g., ExitProcess).

using APIHandlerFn = bool(*)(APIContext& ctx);

// ============================================================================
// API Registration Entry
// ============================================================================
// Used by DLL handler modules to register their functions with APIDispatcher.

struct APIRegistration {
    const char* dllName;         // e.g., "kernel32.dll"
    const char* funcName;        // e.g., "CreateFileW"
    APIHandlerFn handler;        // Function pointer to handler
    uint8_t argCount;            // Number of parameters (for logging)
    bool isCritical;             // If true, failure to resolve is a hard error
};

// ============================================================================
// API Call Classification (for behavioral analysis)
// ============================================================================

enum class APICategory : uint8_t {
    FileSystem       = 0,
    Registry         = 1,
    Process          = 2,
    Thread           = 3,
    Memory           = 4,
    Network          = 5,
    Crypto           = 6,
    Security         = 7,
    ModuleLoading    = 8,
    Synchronization  = 9,
    SystemInfo       = 10,
    AntiDebug        = 11,
    AntiVM           = 12,
    COM              = 13,
    Service          = 14,
    Environment      = 15,
    Time             = 16,
    Console          = 17,
    Unknown          = 255,
};

// Behavioral flags raised by API call patterns
enum class BehaviorFlag : uint32_t {
    None                    = 0,
    FileDropped             = 1 << 0,
    RegistryPersistence     = 1 << 1,
    ProcessInjection        = 1 << 2,
    RemoteThreadCreation    = 1 << 3,
    MemoryManipulation      = 1 << 4,
    NetworkC2               = 1 << 5,
    AntiAnalysis            = 1 << 6,
    PrivilegeEscalation     = 1 << 7,
    CredentialAccess        = 1 << 8,
    DefenseEvasion          = 1 << 9,
    CodeInjection           = 1 << 10,
    ProcessHollowing        = 1 << 11,
    DLLInjection            = 1 << 12,
    Keylogging              = 1 << 13,
    ScreenCapture           = 1 << 14,
    ServiceManipulation     = 1 << 15,
    WMIExecution            = 1 << 16,
    PowershellExecution     = 1 << 17,
    SuspiciousAPI           = 1 << 18,
};

[[nodiscard]] constexpr BehaviorFlag operator|(BehaviorFlag a, BehaviorFlag b) noexcept {
    return static_cast<BehaviorFlag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
[[nodiscard]] constexpr BehaviorFlag operator&(BehaviorFlag a, BehaviorFlag b) noexcept {
    return static_cast<BehaviorFlag>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
[[nodiscard]] constexpr bool HasFlag(BehaviorFlag flags, BehaviorFlag check) noexcept {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(check)) != 0;
}

// ============================================================================
// Extended API Call Record (for the analysis engine)
// ============================================================================

struct APICallDetail {
    uint32_t      ordinal         = 0;        // Internal ordinal
    const char*   dllName         = nullptr;   // DLL name (points into static storage)
    const char*   funcName        = nullptr;   // Function name (points into static storage)
    APICategory   category        = APICategory::Unknown;
    BehaviorFlag  behaviorFlags   = BehaviorFlag::None;
    GuestAddress  returnAddress   = 0;        // Caller return address
    uint64_t      args[8]         = {};       // First 8 args
    uint64_t      returnValue     = 0;        // Value returned in RAX/EAX
    uint32_t      argCount        = 0;
    uint32_t      instructionNum  = 0;        // Instruction count when called
    uint16_t      threadId        = 0;
    bool          wasBlocked      = false;    // True if we blocked/faked this call
    bool          succeeded       = false;    // True if NT_SUCCESS or Win32 return ≠ 0
};

// Maximum API calls tracked per session before ring-buffer overwrite
static constexpr uint32_t kMaxAPICallLog = 256 * 1024;  // 256K entries

// ============================================================================
// Windows PAGE_xxx → MemProt conversion
// ============================================================================

[[nodiscard]] constexpr MemProt Win32ProtToMemProt(uint32_t win32Prot) noexcept {
    uint32_t base = win32Prot & 0xFF;
    MemProt result = MemProt::None;

    switch (base) {
        case NT::PAGE_READONLY:          result = MemProt::Read; break;
        case NT::PAGE_READWRITE:         result = MemProt::RW; break;
        case NT::PAGE_WRITECOPY:         result = MemProt::RW; break;
        case NT::PAGE_EXECUTE:           result = MemProt::Execute; break;
        case NT::PAGE_EXECUTE_READ:      result = MemProt::RX; break;
        case NT::PAGE_EXECUTE_READWRITE: result = MemProt::RWX; break;
        case NT::PAGE_EXECUTE_WRITECOPY: result = MemProt::RWX; break;
        case NT::PAGE_NOACCESS:
        default:                         result = MemProt::None; break;
    }

    if (win32Prot & NT::PAGE_GUARD)
        result = result | MemProt::Guard;
    if (win32Prot & NT::PAGE_NOCACHE)
        result = result | MemProt::NoCache;

    return result;
}

[[nodiscard]] constexpr uint32_t MemProtToWin32(MemProt prot) noexcept {
    uint32_t result = NT::PAGE_NOACCESS;
    bool r = HasProt(prot, MemProt::Read);
    bool w = HasProt(prot, MemProt::Write);
    bool x = HasProt(prot, MemProt::Execute);

    if (x && w)       result = NT::PAGE_EXECUTE_READWRITE;
    else if (x && r)  result = NT::PAGE_EXECUTE_READ;
    else if (x)       result = NT::PAGE_EXECUTE;
    else if (w)       result = NT::PAGE_READWRITE;
    else if (r)       result = NT::PAGE_READONLY;

    if (HasProt(prot, MemProt::Guard))   result |= NT::PAGE_GUARD;
    if (HasProt(prot, MemProt::NoCache)) result |= NT::PAGE_NOCACHE;

    return result;
}

} // namespace Phantom
