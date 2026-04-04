/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileAPI.cpp — Kernel32 file I/O API implementations
 *
 * All file operations run against a virtual file system: no real host I/O
 * is performed. Paths are normalized, handles are tracked in HandleTable,
 * and behavioral flags (FileDropped, DefenseEvasion) are raised via the
 * dispatcher's post-call behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "FileAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <cctype>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint64_t kMaxReadWriteSize        = 16ULL * 1024 * 1024;
static constexpr uint32_t kMaxPathChars            = 1024;
static constexpr uint64_t kDefaultVirtualFileSize  = 65536;

// Win32 file attribute constants
static constexpr uint32_t FILE_ATTRIBUTE_READONLY  = 0x00000001;
static constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
static constexpr uint32_t FILE_ATTRIBUTE_NORMAL    = 0x00000080;
static constexpr uint32_t INVALID_FILE_ATTRIBUTES  = 0xFFFFFFFF;

// Win32 SetFilePointer constants
static constexpr uint32_t FILE_BEGIN   = 0;
static constexpr uint32_t FILE_CURRENT = 1;
static constexpr uint32_t FILE_END     = 2;
static constexpr uint32_t INVALID_SET_FILE_POINTER = 0xFFFFFFFF;

// WIN32_FIND_DATAW struct layout constants (x64)
// Total size: 592 bytes
static constexpr uint32_t kFindDataSize = 592;

// ============================================================================
// Path normalization
// ============================================================================

static std::wstring NormalizePath(const std::wstring& raw) noexcept {
    std::wstring path = raw;

    // Strip extended-length prefix
    static constexpr std::wstring_view kPrefix1 = L"\\\\?\\";
    if (path.size() > kPrefix1.size() &&
        std::wstring_view(path).substr(0, kPrefix1.size()) == kPrefix1) {
        path = path.substr(kPrefix1.size());
    }

    // Normalize forward slashes to backslashes
    for (auto& ch : path) {
        if (ch == L'/') ch = L'\\';
    }

    // Remove trailing backslash (unless root like "C:\")
    if (path.size() > 3 && path.back() == L'\\') {
        path.pop_back();
    }

    return path;
}

static std::wstring AnsiToWide(const std::string& ansi) noexcept {
    std::wstring result;
    result.reserve(ansi.size());
    for (char c : ansi) {
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return result;
}

// Check if a file path looks like an executable (PE)
static bool IsExecutablePath(const std::wstring& path) noexcept {
    if (path.size() < 4) return false;
    auto ext = path.substr(path.size() - 4);
    for (auto& c : ext) {
        if (c >= L'A' && c <= L'Z') c += 32;
    }
    return ext == L".exe" || ext == L".dll" || ext == L".sys" ||
           ext == L".scr" || ext == L".ocx" || ext == L".drv";
}

// Build the temp path from config
static std::wstring BuildTempPath(const EmulationConfig& config) noexcept {
    std::wstring tempPath = L"C:\\Users\\";
    tempPath += config.userName;
    tempPath += L"\\AppData\\Local\\Temp\\";
    return tempPath;
}

// ============================================================================
// Internal: CreateFile core logic (shared by A and W variants)
// ============================================================================

static bool CreateFileCore(APIContext& ctx, const std::wstring& rawPath,
                           uint32_t access, uint32_t shareMode,
                           uint32_t creationDisp) {
    if (rawPath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    std::wstring normalizedPath = NormalizePath(rawPath);

    // Determine default file size based on creation disposition
    uint64_t fileSize = kDefaultVirtualFileSize;
    bool isDir = false;

    // Heuristic: directories typically end without an extension
    if (normalizedPath.find(L'.') == std::wstring::npos &&
        normalizedPath.size() > 3) {
        isDir = true;
        fileSize = 0;
    }

    // Build handle data
    FileHandleData fhd;
    fhd.path       = normalizedPath;
    fhd.accessMask = access;
    fhd.shareMode  = shareMode;
    fhd.fileSize   = fileSize;
    fhd.isDirectory = isDir;
    fhd.isReadOnly  = !(access & NT::GENERIC_WRITE) && !(access & NT::FILE_WRITE_DATA);

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(
        isDir ? HandleType::Directory : HandleType::File,
        std::move(fhd));

    if (gh == kNullHandle) {
        ctx.FailWithInvalidHandle(Win32::ERROR_TOO_MANY_OPEN_FILES);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(gh);
    return true;
}

// ============================================================================
// CreateFileA — lpFileName(0), dwDesiredAccess(1), dwShareMode(2),
//               lpSecurityAttributes(3), dwCreationDisposition(4),
//               dwFlagsAndAttributes(5), hTemplateFile(6)
// ============================================================================

bool HandleCreateFileA(APIContext& ctx) {
    const auto lpFileName  = ctx.GetArgPtr(0);
    const auto dwAccess    = ctx.GetArg32(1);
    const auto dwShareMode = ctx.GetArg32(2);
    // arg3 = lpSecurityAttributes (ignored)
    const auto dwCreation  = ctx.GetArg32(4);
    // arg5 = dwFlagsAndAttributes (ignored for virtual FS)
    // arg6 = hTemplateFile (ignored)

    if (lpFileName == 0) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string ansiPath = ctx.ReadAnsiString(lpFileName, kMaxPathChars);
    if (ansiPath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    return CreateFileCore(ctx, AnsiToWide(ansiPath), dwAccess, dwShareMode, dwCreation);
}

// ============================================================================
// CreateFileW — same args as CreateFileA but wide string
// ============================================================================

bool HandleCreateFileW(APIContext& ctx) {
    const auto lpFileName  = ctx.GetArgPtr(0);
    const auto dwAccess    = ctx.GetArg32(1);
    const auto dwShareMode = ctx.GetArg32(2);
    const auto dwCreation  = ctx.GetArg32(4);

    if (lpFileName == 0) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring widePath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    if (widePath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    return CreateFileCore(ctx, widePath, dwAccess, dwShareMode, dwCreation);
}

// ============================================================================
// ReadFile — hFile(0), lpBuffer(1), nNumberOfBytesToRead(2),
//            lpNumberOfBytesRead(3), lpOverlapped(4)
// ============================================================================

bool HandleReadFile(APIContext& ctx) {
    const auto hFile          = ctx.GetArg(0);
    const auto lpBuffer       = ctx.GetArgPtr(1);
    auto       nBytesToRead   = ctx.GetArg32(2);
    const auto lpBytesReadPtr = ctx.GetArgPtr(3);
    // arg4 = lpOverlapped (ignored)

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        if (lpBytesReadPtr != 0) {
            ctx.Memory().WriteU32(lpBytesReadPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    if (lpBuffer == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    nBytesToRead = static_cast<uint32_t>(
        std::min(static_cast<uint64_t>(nBytesToRead), kMaxReadWriteSize));

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    if (!fhd) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Compute how many bytes are available
    uint64_t remaining = 0;
    if (fhd->filePosition < fhd->fileSize) {
        remaining = fhd->fileSize - fhd->filePosition;
    }

    uint32_t bytesToReturn = static_cast<uint32_t>(
        std::min(static_cast<uint64_t>(nBytesToRead), remaining));

    if (bytesToReturn == 0) {
        // EOF
        if (lpBytesReadPtr != 0) {
            ctx.Memory().WriteU32(lpBytesReadPtr, 0);
        }
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnBool(true);
        return true;
    }

    // Write fake data (zeroed) to the guest buffer
    auto& mem = ctx.Memory();
    std::vector<uint8_t> fakeData(bytesToReturn, 0);
    if (mem.Write(lpBuffer, fakeData.data(), bytesToReturn) != ErrorCode::Success) {
        if (lpBytesReadPtr != 0) {
            mem.WriteU32(lpBytesReadPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    // Update file position
    handles.Modify<FileHandleData>(hFile, [&](FileHandleData& fd) {
        fd.filePosition += bytesToReturn;
    });

    if (lpBytesReadPtr != 0) {
        mem.WriteU32(lpBytesReadPtr, bytesToReturn);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WriteFile — hFile(0), lpBuffer(1), nNumberOfBytesToWrite(2),
//             lpNumberOfBytesWritten(3), lpOverlapped(4)
// ============================================================================

bool HandleWriteFile(APIContext& ctx) {
    const auto hFile             = ctx.GetArg(0);
    const auto lpBuffer          = ctx.GetArgPtr(1);
    auto       nBytesToWrite     = ctx.GetArg32(2);
    const auto lpBytesWrittenPtr = ctx.GetArgPtr(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        if (lpBytesWrittenPtr != 0) {
            ctx.Memory().WriteU32(lpBytesWrittenPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    if (lpBuffer == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    nBytesToWrite = static_cast<uint32_t>(
        std::min(static_cast<uint64_t>(nBytesToWrite), kMaxReadWriteSize));

    // Update file position and size
    handles.Modify<FileHandleData>(hFile, [&](FileHandleData& fd) {
        fd.filePosition += nBytesToWrite;
        if (fd.filePosition > fd.fileSize) {
            fd.fileSize = fd.filePosition;
        }
    });

    if (lpBytesWrittenPtr != 0) {
        ctx.Memory().WriteU32(lpBytesWrittenPtr, nBytesToWrite);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CloseHandle — hObject(0)
// ============================================================================

bool HandleCloseHandle(APIContext& ctx) {
    const auto hObject = ctx.GetArg(0);

    // Pseudo-handles cannot be closed
    if (hObject == kCurrentProcess || hObject == kCurrentThread ||
        hObject == kStdInputHandle || hObject == kStdOutputHandle ||
        hObject == kStdErrorHandle) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnBool(true);
        return true;
    }

    auto& handles = ctx.Handles();
    if (!handles.Close(hObject)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// DeleteFileA — lpFileName(0)
// ============================================================================

bool HandleDeleteFileA(APIContext& ctx) {
    const auto lpFileName = ctx.GetArgPtr(0);

    if (lpFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Read and validate path — we track it for behavioral analysis
    std::string ansiPath = ctx.ReadAnsiString(lpFileName, kMaxPathChars);
    if (ansiPath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // File deletion always succeeds in our virtual FS
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// DeleteFileW — lpFileName(0)
// ============================================================================

bool HandleDeleteFileW(APIContext& ctx) {
    const auto lpFileName = ctx.GetArgPtr(0);

    if (lpFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring widePath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    if (widePath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// MoveFileA — lpExistingFileName(0), lpNewFileName(1)
// ============================================================================

bool HandleMoveFileA(APIContext& ctx) {
    const auto lpExisting = ctx.GetArgPtr(0);
    const auto lpNew      = ctx.GetArgPtr(1);

    if (lpExisting == 0 || lpNew == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Read paths for behavioral tracking (captured by dispatcher)
    ctx.ReadAnsiString(lpExisting, kMaxPathChars);
    ctx.ReadAnsiString(lpNew, kMaxPathChars);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// MoveFileW — lpExistingFileName(0), lpNewFileName(1)
// ============================================================================

bool HandleMoveFileW(APIContext& ctx) {
    const auto lpExisting = ctx.GetArgPtr(0);
    const auto lpNew      = ctx.GetArgPtr(1);

    if (lpExisting == 0 || lpNew == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.ReadWideString(lpExisting, kMaxPathChars);
    ctx.ReadWideString(lpNew, kMaxPathChars);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CopyFileA — lpExistingFileName(0), lpNewFileName(1), bFailIfExists(2)
// ============================================================================

bool HandleCopyFileA(APIContext& ctx) {
    const auto lpExisting = ctx.GetArgPtr(0);
    const auto lpNew      = ctx.GetArgPtr(1);

    if (lpExisting == 0 || lpNew == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.ReadAnsiString(lpExisting, kMaxPathChars);
    ctx.ReadAnsiString(lpNew, kMaxPathChars);

    // CopyFile succeeds — behavioral flags raised by dispatcher
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CopyFileW — lpExistingFileName(0), lpNewFileName(1), bFailIfExists(2)
// ============================================================================

bool HandleCopyFileW(APIContext& ctx) {
    const auto lpExisting = ctx.GetArgPtr(0);
    const auto lpNew      = ctx.GetArgPtr(1);

    if (lpExisting == 0 || lpNew == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.ReadWideString(lpExisting, kMaxPathChars);
    ctx.ReadWideString(lpNew, kMaxPathChars);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetFileSize — hFile(0), lpFileSizeHigh(1)
// ============================================================================

bool HandleGetFileSize(APIContext& ctx) {
    const auto hFile         = ctx.GetArg(0);
    const auto lpFileSizeHi  = ctx.GetArgPtr(1);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(INVALID_SET_FILE_POINTER);
        return true;
    }

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    if (!fhd) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(INVALID_SET_FILE_POINTER);
        return true;
    }

    const uint32_t low  = static_cast<uint32_t>(fhd->fileSize & 0xFFFFFFFF);
    const uint32_t high = static_cast<uint32_t>(fhd->fileSize >> 32);

    if (lpFileSizeHi != 0) {
        ctx.Memory().WriteU32(lpFileSizeHi, high);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(low);
    return true;
}

// ============================================================================
// GetFileSizeEx — hFile(0), lpFileSize(1)
// ============================================================================

bool HandleGetFileSizeEx(APIContext& ctx) {
    const auto hFile      = ctx.GetArg(0);
    const auto lpFileSize = ctx.GetArgPtr(1);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    if (lpFileSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    if (!fhd) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Memory().WriteU64(lpFileSize, fhd->fileSize);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SetFilePointer — hFile(0), lDistanceToMove(1), lpDistanceToMoveHigh(2),
//                  dwMoveMethod(3)
// ============================================================================

bool HandleSetFilePointer(APIContext& ctx) {
    const auto hFile           = ctx.GetArg(0);
    const auto lDistanceLow   = static_cast<int32_t>(ctx.GetArg32(1));
    const auto lpDistanceHigh = ctx.GetArgPtr(2);
    const auto dwMoveMethod   = ctx.GetArg32(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(INVALID_SET_FILE_POINTER);
        return true;
    }

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    if (!fhd) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(INVALID_SET_FILE_POINTER);
        return true;
    }

    int64_t distance = lDistanceLow;
    if (lpDistanceHigh != 0) {
        uint32_t highPart = 0;
        ctx.Memory().ReadU32(lpDistanceHigh, highPart);
        distance = (static_cast<int64_t>(highPart) << 32) | static_cast<uint32_t>(lDistanceLow);
    }

    int64_t newPos = 0;
    switch (dwMoveMethod) {
        case FILE_BEGIN:
            newPos = distance;
            break;
        case FILE_CURRENT:
            newPos = static_cast<int64_t>(fhd->filePosition) + distance;
            break;
        case FILE_END:
            newPos = static_cast<int64_t>(fhd->fileSize) + distance;
            break;
        default:
            ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
            ctx.SetReturn(INVALID_SET_FILE_POINTER);
            return true;
    }

    if (newPos < 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn(INVALID_SET_FILE_POINTER);
        return true;
    }

    const uint64_t finalPos = static_cast<uint64_t>(newPos);

    handles.Modify<FileHandleData>(hFile, [&](FileHandleData& fd) {
        fd.filePosition = finalPos;
    });

    if (lpDistanceHigh != 0) {
        ctx.Memory().WriteU32(lpDistanceHigh, static_cast<uint32_t>(finalPos >> 32));
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(static_cast<uint32_t>(finalPos & 0xFFFFFFFF));
    return true;
}

// ============================================================================
// SetFilePointerEx — hFile(0), liDistanceToMove(1), lpNewFilePointer(2),
//                    dwMoveMethod(3)
// ============================================================================

bool HandleSetFilePointerEx(APIContext& ctx) {
    const auto hFile          = ctx.GetArg(0);
    const auto liDistance     = static_cast<int64_t>(ctx.GetArg(1));
    const auto lpNewPointer  = ctx.GetArgPtr(2);
    const auto dwMoveMethod  = ctx.GetArg32(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    if (!fhd) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    int64_t newPos = 0;
    switch (dwMoveMethod) {
        case FILE_BEGIN:
            newPos = liDistance;
            break;
        case FILE_CURRENT:
            newPos = static_cast<int64_t>(fhd->filePosition) + liDistance;
            break;
        case FILE_END:
            newPos = static_cast<int64_t>(fhd->fileSize) + liDistance;
            break;
        default:
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
    }

    if (newPos < 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    const uint64_t finalPos = static_cast<uint64_t>(newPos);

    handles.Modify<FileHandleData>(hFile, [&](FileHandleData& fd) {
        fd.filePosition = finalPos;
    });

    if (lpNewPointer != 0) {
        ctx.Memory().WriteU64(lpNewPointer, finalPos);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetFileAttributesA — lpFileName(0)
// ============================================================================

bool HandleGetFileAttributesA(APIContext& ctx) {
    const auto lpFileName = ctx.GetArgPtr(0);

    if (lpFileName == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn(INVALID_FILE_ATTRIBUTES);
        return true;
    }

    std::string ansiPath = ctx.ReadAnsiString(lpFileName, kMaxPathChars);
    if (ansiPath.empty()) {
        ctx.SetLastError(Win32::ERROR_INVALID_NAME);
        ctx.SetReturn(INVALID_FILE_ATTRIBUTES);
        return true;
    }

    // Return FILE_ATTRIBUTE_NORMAL for most files
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(FILE_ATTRIBUTE_NORMAL);
    return true;
}

// ============================================================================
// GetFileAttributesW — lpFileName(0)
// ============================================================================

bool HandleGetFileAttributesW(APIContext& ctx) {
    const auto lpFileName = ctx.GetArgPtr(0);

    if (lpFileName == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn(INVALID_FILE_ATTRIBUTES);
        return true;
    }

    std::wstring widePath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    if (widePath.empty()) {
        ctx.SetLastError(Win32::ERROR_INVALID_NAME);
        ctx.SetReturn(INVALID_FILE_ATTRIBUTES);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(FILE_ATTRIBUTE_NORMAL);
    return true;
}

// ============================================================================
// FindFirstFileA — lpFileName(0), lpFindFileData(1)
// ============================================================================

bool HandleFindFirstFileA(APIContext& ctx) {
    const auto lpFileName    = ctx.GetArgPtr(0);
    const auto lpFindData    = ctx.GetArgPtr(1);

    if (lpFileName == 0 || lpFindData == 0) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string ansiPath = ctx.ReadAnsiString(lpFileName, kMaxPathChars);
    if (ansiPath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // Zero the entire WIN32_FIND_DATA structure
    auto& mem = ctx.Memory();
    std::vector<uint8_t> zeroed(kFindDataSize, 0);

    // Set dwFileAttributes = FILE_ATTRIBUTE_NORMAL at offset 0
    const uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
    std::memcpy(zeroed.data(), &attrs, 4);

    if (mem.Write(lpFindData, zeroed.data(), kFindDataSize) != ErrorCode::Success) {
        ctx.FailWithInvalidHandle(Win32::ERROR_NOACCESS);
        return true;
    }

    // Create a directory search handle
    FileHandleData fhd;
    fhd.path       = AnsiToWide(ansiPath);
    fhd.isDirectory = true;
    fhd.filePosition = 1; // Indicates first result already returned

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(HandleType::Directory, std::move(fhd));
    if (gh == kNullHandle) {
        ctx.FailWithInvalidHandle(Win32::ERROR_TOO_MANY_OPEN_FILES);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(gh);
    return true;
}

// ============================================================================
// FindFirstFileW — lpFileName(0), lpFindFileData(1)
// ============================================================================

bool HandleFindFirstFileW(APIContext& ctx) {
    const auto lpFileName    = ctx.GetArgPtr(0);
    const auto lpFindData    = ctx.GetArgPtr(1);

    if (lpFileName == 0 || lpFindData == 0) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring widePath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    if (widePath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    auto& mem = ctx.Memory();
    std::vector<uint8_t> zeroed(kFindDataSize, 0);
    const uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
    std::memcpy(zeroed.data(), &attrs, 4);

    if (mem.Write(lpFindData, zeroed.data(), kFindDataSize) != ErrorCode::Success) {
        ctx.FailWithInvalidHandle(Win32::ERROR_NOACCESS);
        return true;
    }

    FileHandleData fhd;
    fhd.path       = widePath;
    fhd.isDirectory = true;
    fhd.filePosition = 1;

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(HandleType::Directory, std::move(fhd));
    if (gh == kNullHandle) {
        ctx.FailWithInvalidHandle(Win32::ERROR_TOO_MANY_OPEN_FILES);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(gh);
    return true;
}

// ============================================================================
// FindNextFileA/W — hFindFile(0), lpFindFileData(1)
// ============================================================================
// In our virtual FS there is only ever one result per enumeration.
// Return ERROR_NO_MORE_FILES on the second call.

bool HandleFindNextFileA(APIContext& ctx) {
    const auto hFindFile  = ctx.GetArg(0);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFindFile, HandleType::Directory);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // No more files after the first result
    ctx.SetLastError(Win32::ERROR_NO_MORE_FILES);
    ctx.SetReturnBool(false);
    return true;
}

bool HandleFindNextFileW(APIContext& ctx) {
    return HandleFindNextFileA(ctx);
}

// ============================================================================
// FindClose — hFindFile(0)
// ============================================================================

bool HandleFindClose(APIContext& ctx) {
    const auto hFindFile = ctx.GetArg(0);

    auto& handles = ctx.Handles();
    if (!handles.Close(hFindFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetTempPathA — nBufferLength(0), lpBuffer(1)
// ============================================================================

bool HandleGetTempPathA(APIContext& ctx) {
    const auto nBufferLen = ctx.GetArg32(0);
    const auto lpBuffer   = ctx.GetArgPtr(1);

    if (lpBuffer == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring wideTempPath = BuildTempPath(ctx.Config());

    // Convert to ANSI for the A variant
    std::string ansiTemp;
    ansiTemp.reserve(wideTempPath.size());
    for (wchar_t wc : wideTempPath) {
        ansiTemp.push_back(static_cast<char>(wc & 0xFF));
    }

    // Return value is the length without NUL if buffer is big enough,
    // or required length with NUL if buffer is too small
    const uint32_t required = static_cast<uint32_t>(ansiTemp.size() + 1);

    if (nBufferLen < required) {
        ctx.SetReturn32(required);
        return true;
    }

    ctx.WriteAnsiString(lpBuffer, ansiTemp, nBufferLen);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(static_cast<uint32_t>(ansiTemp.size()));
    return true;
}

// ============================================================================
// GetTempPathW — nBufferLength(0), lpBuffer(1)
// ============================================================================

bool HandleGetTempPathW(APIContext& ctx) {
    const auto nBufferLen = ctx.GetArg32(0);
    const auto lpBuffer   = ctx.GetArgPtr(1);

    if (lpBuffer == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring tempPath = BuildTempPath(ctx.Config());

    const uint32_t required = static_cast<uint32_t>(tempPath.size() + 1);

    if (nBufferLen < required) {
        ctx.SetReturn32(required);
        return true;
    }

    ctx.WriteWideString(lpBuffer, tempPath, nBufferLen);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(static_cast<uint32_t>(tempPath.size()));
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterFileAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "CreateFileA",
          HandleCreateFileA, 7, true },
        { "kernel32.dll", "CreateFileW",
          HandleCreateFileW, 7, true },
        { "kernel32.dll", "ReadFile",
          HandleReadFile, 5, true },
        { "kernel32.dll", "WriteFile",
          HandleWriteFile, 5, true },
        { "kernel32.dll", "CloseHandle",
          HandleCloseHandle, 1, true },
        { "kernel32.dll", "DeleteFileA",
          HandleDeleteFileA, 1, false },
        { "kernel32.dll", "DeleteFileW",
          HandleDeleteFileW, 1, false },
        { "kernel32.dll", "MoveFileA",
          HandleMoveFileA, 2, false },
        { "kernel32.dll", "MoveFileW",
          HandleMoveFileW, 2, false },
        { "kernel32.dll", "CopyFileA",
          HandleCopyFileA, 3, false },
        { "kernel32.dll", "CopyFileW",
          HandleCopyFileW, 3, false },
        { "kernel32.dll", "GetFileSize",
          HandleGetFileSize, 2, false },
        { "kernel32.dll", "GetFileSizeEx",
          HandleGetFileSizeEx, 2, false },
        { "kernel32.dll", "SetFilePointer",
          HandleSetFilePointer, 4, false },
        { "kernel32.dll", "SetFilePointerEx",
          HandleSetFilePointerEx, 4, false },
        { "kernel32.dll", "GetFileAttributesA",
          HandleGetFileAttributesA, 1, false },
        { "kernel32.dll", "GetFileAttributesW",
          HandleGetFileAttributesW, 1, false },
        { "kernel32.dll", "FindFirstFileA",
          HandleFindFirstFileA, 2, false },
        { "kernel32.dll", "FindFirstFileW",
          HandleFindFirstFileW, 2, false },
        { "kernel32.dll", "FindNextFileA",
          HandleFindNextFileA, 2, false },
        { "kernel32.dll", "FindNextFileW",
          HandleFindNextFileW, 2, false },
        { "kernel32.dll", "FindClose",
          HandleFindClose, 1, false },
        { "kernel32.dll", "GetTempPathA",
          HandleGetTempPathA, 2, false },
        { "kernel32.dll", "GetTempPathW",
          HandleGetTempPathW, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32
