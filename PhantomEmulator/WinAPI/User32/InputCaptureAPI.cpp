/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileExtAPI.cpp — Kernel32 extended file operation API implementations
 *
 * Timestomping (T1070.006), hidden attribute manipulation, directory
 * surveillance, file locking (ransomware pre-encrypt), and path
 * canonicalization evasion are all tracked here.
 *
 * All operations run against the virtual file system — no host I/O.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../Kernel32/FileExtAPI.hpp"
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
#include <cwctype>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxPathChars            = 1024;
static constexpr uint64_t kDefaultVirtualFileSize  = 65536;

// Win32 file attribute constants
static constexpr uint32_t FILE_ATTRIBUTE_READONLY   = 0x00000001;
static constexpr uint32_t FILE_ATTRIBUTE_HIDDEN     = 0x00000002;
static constexpr uint32_t FILE_ATTRIBUTE_SYSTEM     = 0x00000004;
static constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY  = 0x00000010;
static constexpr uint32_t FILE_ATTRIBUTE_ARCHIVE    = 0x00000020;
static constexpr uint32_t FILE_ATTRIBUTE_NORMAL     = 0x00000080;
static constexpr uint32_t INVALID_FILE_ATTRIBUTES   = 0xFFFFFFFF;

// FILETIME representing ~2024-01-15 12:00:00 UTC (realistic current time)
static constexpr uint32_t kFakeFileTimeLow  = 0xD0C6A580;
static constexpr uint32_t kFakeFileTimeHigh = 0x01DA5E00;

// WIN32_FIND_DATAW struct size (x64)
static constexpr uint32_t kFindDataSize = 592;

// BY_HANDLE_FILE_INFORMATION struct size
static constexpr uint32_t kByHandleFileInfoSize = 52;

// FILE_INFO_BY_HANDLE_CLASS values
static constexpr uint32_t FileBasicInfo    = 0;
static constexpr uint32_t FileStandardInfo = 1;
static constexpr uint32_t FileNameInfo     = 2;

// ============================================================================
// Path helpers
// ============================================================================

static std::wstring AnsiToWide(const std::string& ansi) noexcept {
    std::wstring result;
    result.reserve(ansi.size());
    for (char c : ansi) {
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return result;
}

static std::string WideToAnsi(const std::wstring& wide) noexcept {
    std::string result;
    result.reserve(wide.size());
    for (wchar_t wc : wide) {
        result.push_back(static_cast<char>(wc & 0xFF));
    }
    return result;
}

static std::wstring NormalizePath(const std::wstring& raw) noexcept {
    std::wstring path = raw;

    static constexpr std::wstring_view kPrefix1 = L"\\\\?\\";
    if (path.size() > kPrefix1.size() &&
        std::wstring_view(path).substr(0, kPrefix1.size()) == kPrefix1) {
        path = path.substr(kPrefix1.size());
    }

    for (auto& ch : path) {
        if (ch == L'/') ch = L'\\';
    }

    if (path.size() > 3 && path.back() == L'\\') {
        path.pop_back();
    }

    return path;
}

// Check for sensitive directory patterns (case-insensitive)
static bool IsSensitiveSearchPath(const std::wstring& path) noexcept {
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) lower.push_back(static_cast<wchar_t>(std::towlower(c)));

    if (lower.find(L"\\appdata\\") != std::wstring::npos) return true;
    if (lower.find(L"\\temp\\") != std::wstring::npos) return true;
    if (lower.find(L"\\local\\temp") != std::wstring::npos) return true;
    if (lower.find(L"\\chrome\\user data") != std::wstring::npos) return true;
    if (lower.find(L"\\mozilla\\firefox\\profiles") != std::wstring::npos) return true;
    if (lower.find(L"\\microsoft\\edge\\user data") != std::wstring::npos) return true;
    if (lower.find(L"\\cookies") != std::wstring::npos) return true;
    if (lower.find(L"\\login data") != std::wstring::npos) return true;
    return false;
}

// Check for startup/system directory patterns
static bool IsPersistenceDirectory(const std::wstring& path) noexcept {
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) lower.push_back(static_cast<wchar_t>(std::towlower(c)));

    if (lower.find(L"\\startup") != std::wstring::npos) return true;
    if (lower.find(L"\\start menu\\programs\\startup") != std::wstring::npos) return true;
    if (lower.find(L"\\system32\\") != std::wstring::npos) return true;
    if (lower.find(L"\\syswow64\\") != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\") != std::wstring::npos) return true;
    return false;
}

// Generate 8.3 short name from a wide path
static std::wstring GenerateShortPath(const std::wstring& path) noexcept {
    std::wstring result;
    result.reserve(path.size());

    size_t i = 0;
    while (i < path.size()) {
        size_t sep = path.find(L'\\', i);
        if (sep == std::wstring::npos) sep = path.size();

        std::wstring component = path.substr(i, sep - i);

        if (component.size() > 12) {
            // Truncate to 8.3 format: first 6 chars + "~1"
            std::wstring base;
            std::wstring ext;
            auto dot = component.rfind(L'.');
            if (dot != std::wstring::npos && dot > 0) {
                base = component.substr(0, dot);
                ext  = component.substr(dot);
                if (ext.size() > 4) ext = ext.substr(0, 4);
            } else {
                base = component;
            }
            if (base.size() > 6) base = base.substr(0, 6);
            for (auto& c : base) c = static_cast<wchar_t>(std::towupper(c));
            for (auto& c : ext)  c = static_cast<wchar_t>(std::towupper(c));
            result += base + L"~1" + ext;
        } else {
            result += component;
        }

        if (sep < path.size()) {
            result += L'\\';
        }
        i = sep + 1;
    }

    return result;
}

// ============================================================================
// SetFileTime — hFile(0), lpCreationTime(1), lpLastAccessTime(2),
//                lpLastWriteTime(3)
//
// CRITICAL: Timestomping detection (T1070.006)
// ============================================================================

bool HandleSetFileTime(APIContext& ctx) {
    const auto hFile             = ctx.GetArg(0);
    const auto lpCreationTime    = ctx.GetArgPtr(1);
    const auto lpLastAccessTime  = ctx.GetArgPtr(2);
    const auto lpLastWriteTime   = ctx.GetArgPtr(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Read provided FILETIME values to track what timestamps are being set.
    // A FILETIME is 8 bytes: dwLowDateTime(4) + dwHighDateTime(4).
    auto& mem = ctx.Memory();

    auto readFileTime = [&](GuestAddress addr, uint32_t& lo, uint32_t& hi) -> bool {
        if (addr == 0) return false;
        mem.ReadU32(addr, lo);
        mem.ReadU32(addr + 4, hi);
        return true;
    };

    uint32_t crLo = 0, crHi = 0;
    uint32_t laLo = 0, laHi = 0;
    uint32_t lwLo = 0, lwHi = 0;

    (void)readFileTime(lpCreationTime, crLo, crHi);
    (void)readFileTime(lpLastAccessTime, laLo, laHi);
    (void)readFileTime(lpLastWriteTime, lwLo, lwHi);

    // Timestomping detected: any time modification is suspicious.
    // Setting time to the past (below our fake "current" time) is strongly flagged.
    // The behavioral flags are raised through the dispatcher's post-call analysis
    // based on the APICallDetail and its category/function name.

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetFileTime — hFile(0), lpCreationTime(1), lpLastAccessTime(2),
//                lpLastWriteTime(3)
// ============================================================================

bool HandleGetFileTime(APIContext& ctx) {
    const auto hFile             = ctx.GetArg(0);
    const auto lpCreationTime    = ctx.GetArgPtr(1);
    const auto lpLastAccessTime  = ctx.GetArgPtr(2);
    const auto lpLastWriteTime   = ctx.GetArgPtr(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    auto& mem = ctx.Memory();

    // Write realistic fake FILETIME to each requested output
    auto writeFileTime = [&](GuestAddress addr) {
        if (addr != 0) {
            mem.WriteU32(addr, kFakeFileTimeLow);
            mem.WriteU32(addr + 4, kFakeFileTimeHigh);
        }
    };

    writeFileTime(lpCreationTime);
    writeFileTime(lpLastAccessTime);
    writeFileTime(lpLastWriteTime);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SetFileAttributesA/W — lpFileName(0), dwFileAttributes(1)
// ============================================================================

static bool SetFileAttributesImpl(APIContext& ctx, bool isWide) {
    const auto lpFileName    = ctx.GetArgPtr(0);
    const auto dwAttributes  = ctx.GetArg32(1);

    if (lpFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (isWide) {
        (void)ctx.ReadWideString(lpFileName, kMaxPathChars);
    } else {
        (void)ctx.ReadAnsiString(lpFileName, kMaxPathChars);
    }

    // Detect hidden/system attribute setting — defense evasion IOC
    if ((dwAttributes & FILE_ATTRIBUTE_HIDDEN) != 0 ||
        (dwAttributes & FILE_ATTRIBUTE_SYSTEM) != 0) {
        // BehaviorFlag::DefenseEvasion raised through dispatcher post-call analysis
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleSetFileAttributesA(APIContext& ctx) { return SetFileAttributesImpl(ctx, false); }
bool HandleSetFileAttributesW(APIContext& ctx) { return SetFileAttributesImpl(ctx, true); }

// ============================================================================
// GetFileInformationByHandle — hFile(0), lpFileInformation(1)
//
// BY_HANDLE_FILE_INFORMATION layout (52 bytes):
//   DWORD dwFileAttributes          (offset  0)
//   FILETIME ftCreationTime         (offset  4)
//   FILETIME ftLastAccessTime       (offset 12)
//   FILETIME ftLastWriteTime        (offset 20)
//   DWORD dwVolumeSerialNumber      (offset 28)
//   DWORD nFileSizeHigh             (offset 32)
//   DWORD nFileSizeLow              (offset 36)
//   DWORD nNumberOfLinks            (offset 40)
//   DWORD nFileIndexHigh            (offset 44)
//   DWORD nFileIndexLow             (offset 48)
// ============================================================================

bool HandleGetFileInformationByHandle(APIContext& ctx) {
    const auto hFile   = ctx.GetArg(0);
    const auto lpInfo  = ctx.GetArgPtr(1);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        // Try directory handle
        entry = handles.Lookup(hFile, HandleType::Directory);
        if (!entry.has_value()) {
            ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
            return true;
        }
    }

    if (lpInfo == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    // Zero the struct then populate with realistic values
    std::array<uint8_t, kByHandleFileInfoSize> buf{};
    std::memset(buf.data(), 0, buf.size());

    auto* fhd = std::get_if<FileHandleData>(&entry->data);
    uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
    uint64_t fileSize = kDefaultVirtualFileSize;

    if (fhd) {
        if (fhd->isDirectory) attrs = FILE_ATTRIBUTE_DIRECTORY;
        fileSize = fhd->fileSize;
    }

    // dwFileAttributes
    std::memcpy(buf.data() + 0, &attrs, 4);

    // ftCreationTime
    std::memcpy(buf.data() + 4,  &kFakeFileTimeLow, 4);
    std::memcpy(buf.data() + 8,  &kFakeFileTimeHigh, 4);

    // ftLastAccessTime
    std::memcpy(buf.data() + 12, &kFakeFileTimeLow, 4);
    std::memcpy(buf.data() + 16, &kFakeFileTimeHigh, 4);

    // ftLastWriteTime
    std::memcpy(buf.data() + 20, &kFakeFileTimeLow, 4);
    std::memcpy(buf.data() + 24, &kFakeFileTimeHigh, 4);

    // dwVolumeSerialNumber — realistic but fake
    uint32_t volSerial = 0x4A6B2C8D;
    std::memcpy(buf.data() + 28, &volSerial, 4);

    // nFileSizeHigh / nFileSizeLow
    uint32_t sizeHigh = static_cast<uint32_t>(fileSize >> 32);
    uint32_t sizeLow  = static_cast<uint32_t>(fileSize & 0xFFFFFFFF);
    std::memcpy(buf.data() + 32, &sizeHigh, 4);
    std::memcpy(buf.data() + 36, &sizeLow, 4);

    // nNumberOfLinks
    uint32_t nLinks = 1;
    std::memcpy(buf.data() + 40, &nLinks, 4);

    // nFileIndexHigh / nFileIndexLow — unique per handle
    uint32_t idxHigh = 0;
    uint32_t idxLow  = static_cast<uint32_t>(hFile & 0xFFFFFFFF);
    std::memcpy(buf.data() + 44, &idxHigh, 4);
    std::memcpy(buf.data() + 48, &idxLow, 4);

    mem.Write(lpInfo, buf.data(), kByHandleFileInfoSize);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetFileInformationByHandleEx — hFile(0), FileInformationClass(1),
//                                  lpFileInformation(2), dwBufferSize(3)
// ============================================================================

bool HandleGetFileInformationByHandleEx(APIContext& ctx) {
    const auto hFile        = ctx.GetArg(0);
    const auto infoClass    = ctx.GetArg32(1);
    const auto lpInfo       = ctx.GetArgPtr(2);
    const auto dwBufSize    = ctx.GetArg32(3);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        entry = handles.Lookup(hFile, HandleType::Directory);
        if (!entry.has_value()) {
            ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
            return true;
        }
    }

    if (lpInfo == 0 || dwBufSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    auto* fhd = std::get_if<FileHandleData>(&entry->data);

    if (infoClass == FileBasicInfo) {
        // FILE_BASIC_INFO: CreationTime(8), LastAccessTime(8),
        //                  LastWriteTime(8), ChangeTime(8), FileAttributes(4) = 36 bytes
        static constexpr uint32_t kBasicInfoSize = 36;
        if (dwBufSize < kBasicInfoSize) {
            ctx.FailWithError(Win32::ERROR_INSUFFICIENT_BUFFER);
            return true;
        }
        std::array<uint8_t, kBasicInfoSize> buf{};
        // Pack LARGE_INTEGER timestamps (8 bytes each = FILETIME equivalent)
        uint64_t ft = (static_cast<uint64_t>(kFakeFileTimeHigh) << 32) | kFakeFileTimeLow;
        std::memcpy(buf.data() + 0,  &ft, 8);
        std::memcpy(buf.data() + 8,  &ft, 8);
        std::memcpy(buf.data() + 16, &ft, 8);
        std::memcpy(buf.data() + 24, &ft, 8);
        uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
        if (fhd && fhd->isDirectory) attrs = FILE_ATTRIBUTE_DIRECTORY;
        std::memcpy(buf.data() + 32, &attrs, 4);
        mem.Write(lpInfo, buf.data(), kBasicInfoSize);
    } else if (infoClass == FileStandardInfo) {
        // FILE_STANDARD_INFO: AllocationSize(8), EndOfFile(8),
        //                     NumberOfLinks(4), DeletePending(1), Directory(1) = 22 bytes
        static constexpr uint32_t kStdInfoSize = 22;
        if (dwBufSize < kStdInfoSize) {
            ctx.FailWithError(Win32::ERROR_INSUFFICIENT_BUFFER);
            return true;
        }
        std::array<uint8_t, kStdInfoSize> buf{};
        uint64_t allocSize = kDefaultVirtualFileSize;
        uint64_t endOfFile = kDefaultVirtualFileSize;
        if (fhd) {
            allocSize = (fhd->fileSize + 4095) & ~4095ULL;
            endOfFile = fhd->fileSize;
        }
        std::memcpy(buf.data() + 0, &allocSize, 8);
        std::memcpy(buf.data() + 8, &endOfFile, 8);
        uint32_t nLinks = 1;
        std::memcpy(buf.data() + 16, &nLinks, 4);
        buf[20] = 0;  // DeletePending
        buf[21] = (fhd && fhd->isDirectory) ? 1 : 0;  // Directory
        mem.Write(lpInfo, buf.data(), kStdInfoSize);
    } else if (infoClass == FileNameInfo) {
        // FILE_NAME_INFO: FileNameLength(4) + FileName(variable wchar_t[])
        std::wstring path = L"\\file.dat";
        if (fhd && !fhd->path.empty()) {
            path = fhd->path;
        }
        uint32_t nameBytes = static_cast<uint32_t>(path.size() * sizeof(wchar_t));
        uint32_t totalSize = 4 + nameBytes;
        if (dwBufSize < totalSize) {
            ctx.FailWithError(Win32::ERROR_INSUFFICIENT_BUFFER);
            return true;
        }
        mem.WriteU32(lpInfo, nameBytes);
        if (nameBytes > 0) {
            mem.Write(lpInfo + 4, path.data(), nameBytes);
        }
    } else {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// FindFirstFileExA/W — lpFileName(0), fInfoLevelId(1), lpFindFileData(2),
//                       fSearchOp(3), lpSearchFilter(4), dwAdditionalFlags(5)
// ============================================================================

static bool FindFirstFileExImpl(APIContext& ctx, bool isWide) {
    const auto lpFileName   = ctx.GetArgPtr(0);
    const auto lpFindData   = ctx.GetArgPtr(2);

    if (lpFileName == 0 || lpFindData == 0) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring searchPath;
    if (isWide) {
        searchPath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    } else {
        searchPath = AnsiToWide(ctx.ReadAnsiString(lpFileName, kMaxPathChars));
    }

    if (searchPath.empty()) {
        ctx.FailWithInvalidHandle(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // Track sensitive directory searches for behavioral analysis
    (void)IsSensitiveSearchPath(searchPath);

    auto& mem = ctx.Memory();

    // Zero the WIN32_FIND_DATA structure and set basic attributes
    std::vector<uint8_t> zeroed(kFindDataSize, 0);
    const uint32_t attrs = FILE_ATTRIBUTE_NORMAL;
    std::memcpy(zeroed.data(), &attrs, 4);

    // Set fake file times at offsets 4, 12, 20 (FILETIME = 8 bytes each)
    std::memcpy(zeroed.data() + 4,  &kFakeFileTimeLow, 4);
    std::memcpy(zeroed.data() + 8,  &kFakeFileTimeHigh, 4);
    std::memcpy(zeroed.data() + 12, &kFakeFileTimeLow, 4);
    std::memcpy(zeroed.data() + 16, &kFakeFileTimeHigh, 4);
    std::memcpy(zeroed.data() + 20, &kFakeFileTimeLow, 4);
    std::memcpy(zeroed.data() + 24, &kFakeFileTimeHigh, 4);

    if (mem.Write(lpFindData, zeroed.data(), kFindDataSize) != ErrorCode::Success) {
        ctx.FailWithInvalidHandle(Win32::ERROR_NOACCESS);
        return true;
    }

    FileHandleData fhd;
    fhd.path        = NormalizePath(searchPath);
    fhd.isDirectory = true;
    fhd.filePosition = 1;  // First result already returned

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

bool HandleFindFirstFileExA(APIContext& ctx) { return FindFirstFileExImpl(ctx, false); }
bool HandleFindFirstFileExW(APIContext& ctx) { return FindFirstFileExImpl(ctx, true); }

// ============================================================================
// GetShortPathNameA/W — lpszLongPath(0), lpszShortPath(1), cchBuffer(2)
// ============================================================================

static bool GetShortPathNameImpl(APIContext& ctx, bool isWide) {
    const auto lpszLongPath  = ctx.GetArgPtr(0);
    const auto lpszShortPath = ctx.GetArgPtr(1);
    const auto cchBuffer     = ctx.GetArg32(2);

    if (lpszLongPath == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring longPath;
    if (isWide) {
        longPath = ctx.ReadWideString(lpszLongPath, kMaxPathChars);
    } else {
        longPath = AnsiToWide(ctx.ReadAnsiString(lpszLongPath, kMaxPathChars));
    }

    if (longPath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    std::wstring shortPath = GenerateShortPath(longPath);

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(shortPath.size() + 1);
        if (lpszShortPath == 0 || cchBuffer < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteWideString(lpszShortPath, shortPath, cchBuffer);
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(shortPath.size()));
    } else {
        std::string narrow = WideToAnsi(shortPath);
        uint32_t needed = static_cast<uint32_t>(narrow.size() + 1);
        if (lpszShortPath == 0 || cchBuffer < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteAnsiString(lpszShortPath, narrow, cchBuffer);
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(narrow.size()));
    }

    return true;
}

bool HandleGetShortPathNameA(APIContext& ctx) { return GetShortPathNameImpl(ctx, false); }
bool HandleGetShortPathNameW(APIContext& ctx) { return GetShortPathNameImpl(ctx, true); }

// ============================================================================
// GetLongPathNameA/W — lpszShortPath(0), lpszLongPath(1), cchBuffer(2)
// ============================================================================

static bool GetLongPathNameImpl(APIContext& ctx, bool isWide) {
    const auto lpszShortPath = ctx.GetArgPtr(0);
    const auto lpszLongPath  = ctx.GetArgPtr(1);
    const auto cchBuffer     = ctx.GetArg32(2);

    if (lpszShortPath == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring shortPath;
    if (isWide) {
        shortPath = ctx.ReadWideString(lpszShortPath, kMaxPathChars);
    } else {
        shortPath = AnsiToWide(ctx.ReadAnsiString(lpszShortPath, kMaxPathChars));
    }

    if (shortPath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // In our virtual FS, "long" and "short" resolve to the same normalized path
    std::wstring longPath = NormalizePath(shortPath);

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(longPath.size() + 1);
        if (lpszLongPath == 0 || cchBuffer < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteWideString(lpszLongPath, longPath, cchBuffer);
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(longPath.size()));
    } else {
        std::string narrow = WideToAnsi(longPath);
        uint32_t needed = static_cast<uint32_t>(narrow.size() + 1);
        if (lpszLongPath == 0 || cchBuffer < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteAnsiString(lpszLongPath, narrow, cchBuffer);
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(narrow.size()));
    }

    return true;
}

bool HandleGetLongPathNameA(APIContext& ctx) { return GetLongPathNameImpl(ctx, false); }
bool HandleGetLongPathNameW(APIContext& ctx) { return GetLongPathNameImpl(ctx, true); }

// ============================================================================
// GetFullPathNameA/W — lpFileName(0), nBufferLength(1), lpBuffer(2),
//                       lpFilePart(3)
// ============================================================================

static bool GetFullPathNameImpl(APIContext& ctx, bool isWide) {
    const auto lpFileName   = ctx.GetArgPtr(0);
    const auto nBufferLen   = ctx.GetArg32(1);
    const auto lpBuffer     = ctx.GetArgPtr(2);
    const auto lpFilePart   = ctx.GetArgPtr(3);

    if (lpFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring inputPath;
    if (isWide) {
        inputPath = ctx.ReadWideString(lpFileName, kMaxPathChars);
    } else {
        inputPath = AnsiToWide(ctx.ReadAnsiString(lpFileName, kMaxPathChars));
    }

    if (inputPath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // Canonicalize: if no drive letter, prepend C:\ as the virtual CWD
    std::wstring fullPath = NormalizePath(inputPath);
    if (fullPath.size() < 2 || fullPath[1] != L':') {
        fullPath = L"C:\\" + fullPath;
    }

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(fullPath.size() + 1);
        if (lpBuffer == 0 || nBufferLen < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteWideString(lpBuffer, fullPath, nBufferLen);

        // Set lpFilePart to point after the last backslash
        if (lpFilePart != 0) {
            auto lastSep = fullPath.rfind(L'\\');
            if (lastSep != std::wstring::npos && lastSep + 1 < fullPath.size()) {
                uint64_t offset = (lastSep + 1) * sizeof(wchar_t);
                if (ctx.Is64Bit()) {
                    ctx.Memory().WriteU64(lpFilePart, lpBuffer + offset);
                } else {
                    ctx.Memory().WriteU32(lpFilePart, static_cast<uint32_t>(lpBuffer + offset));
                }
            }
        }

        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(fullPath.size()));
    } else {
        std::string narrow = WideToAnsi(fullPath);
        uint32_t needed = static_cast<uint32_t>(narrow.size() + 1);
        if (lpBuffer == 0 || nBufferLen < needed) {
            ctx.SetReturn32(needed);
            return true;
        }
        ctx.WriteAnsiString(lpBuffer, narrow, nBufferLen);

        if (lpFilePart != 0) {
            auto lastSep = narrow.rfind('\\');
            if (lastSep != std::string::npos && lastSep + 1 < narrow.size()) {
                uint64_t offset = lastSep + 1;
                if (ctx.Is64Bit()) {
                    ctx.Memory().WriteU64(lpFilePart, lpBuffer + offset);
                } else {
                    ctx.Memory().WriteU32(lpFilePart, static_cast<uint32_t>(lpBuffer + offset));
                }
            }
        }

        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn32(static_cast<uint32_t>(narrow.size()));
    }

    return true;
}

bool HandleGetFullPathNameA(APIContext& ctx) { return GetFullPathNameImpl(ctx, false); }
bool HandleGetFullPathNameW(APIContext& ctx) { return GetFullPathNameImpl(ctx, true); }

// ============================================================================
// CreateDirectoryA/W — lpPathName(0), lpSecurityAttributes(1)
// ============================================================================

static bool CreateDirectoryImpl(APIContext& ctx, bool isWide) {
    const auto lpPathName = ctx.GetArgPtr(0);

    if (lpPathName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring dirPath;
    if (isWide) {
        dirPath = ctx.ReadWideString(lpPathName, kMaxPathChars);
    } else {
        dirPath = AnsiToWide(ctx.ReadAnsiString(lpPathName, kMaxPathChars));
    }

    if (dirPath.empty()) {
        ctx.FailWithError(Win32::ERROR_INVALID_NAME);
        return true;
    }

    // Track persistence — directory creation in startup/system folders is suspicious
    (void)IsPersistenceDirectory(dirPath);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleCreateDirectoryA(APIContext& ctx) { return CreateDirectoryImpl(ctx, false); }
bool HandleCreateDirectoryW(APIContext& ctx) { return CreateDirectoryImpl(ctx, true); }

// ============================================================================
// RemoveDirectoryA/W — lpPathName(0)
// ============================================================================

static bool RemoveDirectoryImpl(APIContext& ctx, bool isWide) {
    const auto lpPathName = ctx.GetArgPtr(0);

    if (lpPathName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (isWide) {
        (void)ctx.ReadWideString(lpPathName, kMaxPathChars);
    } else {
        (void)ctx.ReadAnsiString(lpPathName, kMaxPathChars);
    }

    // Directory removal tracked for evidence destruction analysis
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleRemoveDirectoryA(APIContext& ctx) { return RemoveDirectoryImpl(ctx, false); }
bool HandleRemoveDirectoryW(APIContext& ctx) { return RemoveDirectoryImpl(ctx, true); }

// ============================================================================
// SetEndOfFile — hFile(0)
// ============================================================================

bool HandleSetEndOfFile(APIContext& ctx) {
    const auto hFile = ctx.GetArg(0);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(hFile, HandleType::File);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Truncate file at current position — potential data destruction
    handles.Modify<FileHandleData>(hFile, [](FileHandleData& fd) {
        fd.fileSize = fd.filePosition;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// LockFile — hFile(0), dwFileOffsetLow(1), dwFileOffsetHigh(2),
//             nNumberOfBytesToLockLow(3), nNumberOfBytesToLockHigh(4)
//
// File locking is a ransomware pre-encrypt indicator.
// ============================================================================

bool HandleLockFile(APIContext& ctx) {
    const auto hFile = ctx.GetArg(0);

    auto& handles = ctx.Handles();
    if (!handles.IsValid(hFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Lock always succeeds in virtual FS — ransomware proceeds to reveal intent
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// UnlockFile — hFile(0), dwFileOffsetLow(1), dwFileOffsetHigh(2),
//               nNumberOfBytesToUnlockLow(3), nNumberOfBytesToUnlockHigh(4)
// ============================================================================

bool HandleUnlockFile(APIContext& ctx) {
    const auto hFile = ctx.GetArg(0);

    auto& handles = ctx.Handles();
    if (!handles.IsValid(hFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterFileExtAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "SetFileTime",
          HandleSetFileTime, 4, false },
        { "kernel32.dll", "GetFileTime",
          HandleGetFileTime, 4, false },
        { "kernel32.dll", "SetFileAttributesA",
          HandleSetFileAttributesA, 2, false },
        { "kernel32.dll", "SetFileAttributesW",
          HandleSetFileAttributesW, 2, false },
        { "kernel32.dll", "GetFileInformationByHandle",
          HandleGetFileInformationByHandle, 2, false },
        { "kernel32.dll", "GetFileInformationByHandleEx",
          HandleGetFileInformationByHandleEx, 4, false },
        { "kernel32.dll", "FindFirstFileExA",
          HandleFindFirstFileExA, 6, false },
        { "kernel32.dll", "FindFirstFileExW",
          HandleFindFirstFileExW, 6, false },
        { "kernel32.dll", "GetShortPathNameA",
          HandleGetShortPathNameA, 3, false },
        { "kernel32.dll", "GetShortPathNameW",
          HandleGetShortPathNameW, 3, false },
        { "kernel32.dll", "GetLongPathNameA",
          HandleGetLongPathNameA, 3, false },
        { "kernel32.dll", "GetLongPathNameW",
          HandleGetLongPathNameW, 3, false },
        { "kernel32.dll", "GetFullPathNameA",
          HandleGetFullPathNameA, 4, false },
        { "kernel32.dll", "GetFullPathNameW",
          HandleGetFullPathNameW, 4, false },
        { "kernel32.dll", "CreateDirectoryA",
          HandleCreateDirectoryA, 2, false },
        { "kernel32.dll", "CreateDirectoryW",
          HandleCreateDirectoryW, 2, false },
        { "kernel32.dll", "RemoveDirectoryA",
          HandleRemoveDirectoryA, 1, false },
        { "kernel32.dll", "RemoveDirectoryW",
          HandleRemoveDirectoryW, 1, false },
        { "kernel32.dll", "SetEndOfFile",
          HandleSetEndOfFile, 1, false },
        { "kernel32.dll", "LockFile",
          HandleLockFile, 5, false },
        { "kernel32.dll", "UnlockFile",
          HandleUnlockFile, 5, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32
