/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtFile.cpp — Nt* file / IO syscall implementations
 *
 * All file operations run against a virtual file system: no real host I/O
 * is performed. Paths are normalized, handles are tracked in HandleTable,
 * and behavioral flags (FileDropped, DefenseEvasion) are raised.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtFile.hpp"
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

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint64_t kMaxReadWriteSize    = 16ULL * 1024 * 1024; // 16 MB
static constexpr uint64_t kMaxPathChars        = 1024;
static constexpr uint64_t kDefaultVirtualFileSize = 65536;

// FileInformationClass values for NtSetInformationFile / NtQueryInformationFile
static constexpr uint32_t kFileBasicInformation       = 4;
static constexpr uint32_t kFileStandardInformation    = 5;
static constexpr uint32_t kFileNameInformation        = 9;
static constexpr uint32_t kFilePositionInformation    = 14;
static constexpr uint32_t kFileDispositionInformation = 13;

// NtCreateFile CreateDisposition values (NT-style, different from Win32)
static constexpr uint32_t kFileSupersede    = 0;
static constexpr uint32_t kFileOpen         = 1;
static constexpr uint32_t kFileCreate       = 2;
static constexpr uint32_t kFileOpenIf       = 3;
static constexpr uint32_t kFileOverwrite    = 4;
static constexpr uint32_t kFileOverwriteIf  = 5;

// IoStatusBlock helper
static void WriteIoStatus(VirtualMemory& mem, GuestAddress iosbAddr,
                          GuestNtStatus status, uint64_t info) noexcept {
    if (iosbAddr == 0) return;
    mem.WriteU32(iosbAddr, static_cast<uint32_t>(status));
    mem.WriteU64(iosbAddr + 8, info);
}

// ============================================================================
// Path normalization
// ============================================================================
// Converts NT-style object paths to a canonical form:
//   \??\C:\Windows\... → C:\Windows\...
//   \Device\HarddiskVolume1\Windows\... → C:\Windows\...
//   \SystemRoot\... → C:\Windows\...

static std::wstring NormalizePath(const std::wstring& raw) noexcept {
    std::wstring path = raw;

    // Strip leading NT object-manager prefixes
    static constexpr std::wstring_view kPrefix1 = L"\\??\\";
    static constexpr std::wstring_view kPrefix2 = L"\\\\?\\";

    if (path.size() > kPrefix1.size() &&
        std::wstring_view(path).substr(0, kPrefix1.size()) == kPrefix1) {
        path = path.substr(kPrefix1.size());
    } else if (path.size() > kPrefix2.size() &&
               std::wstring_view(path).substr(0, kPrefix2.size()) == kPrefix2) {
        path = path.substr(kPrefix2.size());
    }

    // \Device\HarddiskVolumeN\... → C:\...
    static constexpr std::wstring_view kDevicePrefix = L"\\Device\\HarddiskVolume";
    if (path.size() > kDevicePrefix.size() &&
        std::wstring_view(path).substr(0, kDevicePrefix.size()) == kDevicePrefix) {
        auto rest = path.substr(kDevicePrefix.size());
        // Skip the volume number digit(s) and backslash
        size_t pos = 0;
        while (pos < rest.size() && rest[pos] >= L'0' && rest[pos] <= L'9') ++pos;
        if (pos < rest.size() && rest[pos] == L'\\') ++pos;
        path = L"C:\\" + rest.substr(pos);
    }

    // \SystemRoot\... → C:\Windows\...
    static constexpr std::wstring_view kSysRoot = L"\\SystemRoot\\";
    if (path.size() >= kSysRoot.size() &&
        std::wstring_view(path).substr(0, kSysRoot.size()) == kSysRoot) {
        path = L"C:\\Windows\\" + path.substr(kSysRoot.size());
    } else if (path == L"\\SystemRoot") {
        path = L"C:\\Windows";
    }

    // Normalize forward slashes to backslashes
    for (auto& ch : path) {
        if (ch == L'/') ch = L'\\';
    }

    return path;
}

// ============================================================================
// Guest structure reading helpers
// ============================================================================

// Read OBJECT_ATTRIBUTES → UNICODE_STRING → file path from guest memory (x64).
// OBJECT_ATTRIBUTES x64 layout:
//   +0x00 uint32_t Length
//   +0x08 uint64_t RootDirectory
//   +0x10 uint64_t ObjectName (-> UNICODE_STRING)
//   +0x18 uint32_t Attributes
//   +0x20 uint64_t SecurityDescriptor
//   +0x28 uint64_t SecurityQualityOfService
//
// UNICODE_STRING x64 layout:
//   +0x00 uint16_t Length  (byte count, not including NUL)
//   +0x02 uint16_t MaximumLength
//   +0x08 uint64_t Buffer

static std::wstring ReadObjectAttributesPath(APIContext& ctx,
                                             GuestAddress oaAddr) noexcept {
    if (oaAddr == 0) return {};

    auto& mem = ctx.Memory();

    // Read ObjectName pointer from OBJECT_ATTRIBUTES
    uint64_t unicodeStringAddr = 0;
    if (mem.ReadU64(oaAddr + 0x10, unicodeStringAddr) != ErrorCode::Success) {
        return {};
    }
    if (unicodeStringAddr == 0) return {};

    // Read UNICODE_STRING fields
    uint16_t byteLength = 0;
    uint64_t bufferAddr = 0;
    if (mem.ReadU16(unicodeStringAddr, byteLength) != ErrorCode::Success) {
        return {};
    }
    if (mem.ReadU64(unicodeStringAddr + 0x08, bufferAddr) != ErrorCode::Success) {
        return {};
    }
    if (bufferAddr == 0 || byteLength == 0) return {};

    // Cap to prevent absurd allocations
    const uint32_t charCount = byteLength / 2;
    if (charCount > kMaxPathChars) return {};

    // Read the wide-char buffer
    std::wstring result;
    result.resize(charCount);
    if (mem.Read(bufferAddr, result.data(),
                 static_cast<uint32_t>(charCount * sizeof(wchar_t))) != ErrorCode::Success) {
        return {};
    }

    return result;
}

// ============================================================================
// NtCreateFile
// ============================================================================
// Args (11): *FileHandle, DesiredAccess, *ObjectAttributes, *IoStatusBlock,
//            *AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
//            CreateOptions, *EaBuffer, EaLength

bool HandleNtCreateFile(APIContext& ctx) {
    const auto fileHandlePtr  = ctx.GetArgPtr(0);
    const auto desiredAccess  = ctx.GetArg32(1);
    const auto objAttrPtr     = ctx.GetArgPtr(2);
    const auto ioStatusPtr    = ctx.GetArgPtr(3);
    // arg4 = AllocationSize (rarely used)
    // arg5 = FileAttributes
    const auto shareAccess    = ctx.GetArg32(6);
    const auto createDisp     = ctx.GetArg32(7);
    // arg8 = CreateOptions
    // arg9 = EaBuffer (ignored)
    // arg10 = EaLength (ignored)

    if (fileHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Read file path from OBJECT_ATTRIBUTES chain
    std::wstring rawPath = ReadObjectAttributesPath(ctx, objAttrPtr);
    if (rawPath.empty()) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_OBJECT_PATH_SYNTAX_BAD, 0);
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_PATH_SYNTAX_BAD);
        return true;
    }

    std::wstring normalizedPath = NormalizePath(rawPath);

    // Determine behavior based on CreateDisposition
    // In our virtual FS, most opens succeed since malware expects system DLLs etc.
    bool isCreating = (createDisp == kFileCreate ||
                       createDisp == kFileSupersede ||
                       createDisp == kFileOverwrite ||
                       createDisp == kFileOverwriteIf);
    bool isOpening  = (createDisp == kFileOpen ||
                       createDisp == kFileOpenIf ||
                       createDisp == kFileOverwriteIf);

    // Default virtual file size (for DLL stubs, config files malware probes)
    uint64_t virtualFileSize = kDefaultVirtualFileSize;
    bool isDir = false;

    // Heuristic: if path looks like a well-known system DLL, give it a
    // plausible size. If it's a temp path or unknown, use default.
    if (normalizedPath.find(L"\\Windows\\System32\\") != std::wstring::npos ||
        normalizedPath.find(L"\\windows\\system32\\") != std::wstring::npos) {
        virtualFileSize = 512 * 1024; // 512 KB typical for system DLLs
    }

    // Build handle data
    FileHandleData fd;
    fd.path         = normalizedPath;
    fd.accessMask   = desiredAccess;
    fd.shareMode    = shareAccess;
    fd.filePosition = 0;
    fd.fileSize     = virtualFileSize;
    fd.isDirectory  = isDir;
    fd.isReadOnly   = !(desiredAccess & (NT::FILE_WRITE_DATA | NT::GENERIC_WRITE));

    auto& handles = ctx.Handles();
    GuestHandle gh = handles.Create(HandleType::File, std::move(fd));

    if (gh == kNullHandle) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr,
                      NT::STATUS_INSUFFICIENT_RESOURCES, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    auto& mem = ctx.Memory();
    mem.WriteU64(fileHandlePtr, gh);

    // IoStatusBlock: Information = FILE_OPENED (1) or FILE_CREATED (2)
    uint64_t ioInfo = isCreating ? 2 : 1;
    WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, ioInfo);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtReadFile
// ============================================================================
// Args (9): FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
//           Buffer, Length, *ByteOffset, Key

bool HandleNtReadFile(APIContext& ctx) {
    const auto fileHandle = ctx.GetArg(0);
    // arg1-3: Event, APC (not emulated)
    const auto ioStatusPtr = ctx.GetArgPtr(4);
    const auto bufferAddr  = ctx.GetArgPtr(5);
    auto       length      = ctx.GetArg32(6);
    const auto byteOffPtr  = ctx.GetArgPtr(7);
    // arg8 = Key (ignored)

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(fileHandle, HandleType::File);
    if (!entry.has_value()) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_HANDLE, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* fd = std::get_if<FileHandleData>(&entry->data);
    if (!fd) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_OBJECT_TYPE_MISMATCH, 0);
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_TYPE_MISMATCH);
        return true;
    }

    if (bufferAddr == 0 || length == 0) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_PARAMETER, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Cap length
    if (length > kMaxReadWriteSize) {
        length = static_cast<uint32_t>(kMaxReadWriteSize);
    }

    auto& mem = ctx.Memory();

    // Resolve file offset
    uint64_t offset = fd->filePosition;
    if (byteOffPtr != 0) {
        uint64_t explicitOff = 0;
        if (mem.ReadU64(byteOffPtr, explicitOff) == ErrorCode::Success) {
            // Special value -1 / -2 means "use current position"
            if (explicitOff != static_cast<uint64_t>(-1) &&
                explicitOff != static_cast<uint64_t>(-2)) {
                offset = explicitOff;
            }
        }
    }

    // Check for EOF
    if (offset >= fd->fileSize) {
        WriteIoStatus(mem, ioStatusPtr, NT::STATUS_END_OF_FILE, 0);
        ctx.SetReturnNtStatus(NT::STATUS_END_OF_FILE);
        return true;
    }

    // Calculate actual bytes to return
    uint64_t remaining = fd->fileSize - offset;
    uint32_t bytesRead = static_cast<uint32_t>(std::min<uint64_t>(length, remaining));

    // Virtual file: fill buffer with zeros (stub content for DLL stubs etc.)
    // Real sample data would be injected via a VirtualFileSystem layer;
    // here we provide a zero-fill so the emulated code gets valid memory.
    std::vector<uint8_t> fakeBuf(bytesRead, 0);
    if (mem.Write(bufferAddr, fakeBuf.data(), bytesRead) != ErrorCode::Success) {
        WriteIoStatus(mem, ioStatusPtr, NT::STATUS_ACCESS_VIOLATION, 0);
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    // Advance file position
    const uint64_t newPos = offset + bytesRead;
    handles.Modify<FileHandleData>(fileHandle, [newPos](FileHandleData& f) {
        f.filePosition = newPos;
    });

    WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, bytesRead);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtWriteFile
// ============================================================================
// Args (9): FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
//           Buffer, Length, *ByteOffset, Key

bool HandleNtWriteFile(APIContext& ctx) {
    const auto fileHandle  = ctx.GetArg(0);
    // arg1-3: Event, APC
    const auto ioStatusPtr = ctx.GetArgPtr(4);
    const auto bufferAddr  = ctx.GetArgPtr(5);
    auto       length      = ctx.GetArg32(6);
    const auto byteOffPtr  = ctx.GetArgPtr(7);
    // arg8 = Key

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(fileHandle, HandleType::File);
    if (!entry.has_value()) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_HANDLE, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* fd = std::get_if<FileHandleData>(&entry->data);
    if (!fd) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_OBJECT_TYPE_MISMATCH, 0);
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_TYPE_MISMATCH);
        return true;
    }

    if (bufferAddr == 0 || length == 0) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_PARAMETER, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    if (length > kMaxReadWriteSize) {
        length = static_cast<uint32_t>(kMaxReadWriteSize);
    }

    auto& mem = ctx.Memory();

    // Resolve offset
    uint64_t offset = fd->filePosition;
    if (byteOffPtr != 0) {
        uint64_t explicitOff = 0;
        if (mem.ReadU64(byteOffPtr, explicitOff) == ErrorCode::Success) {
            if (explicitOff != static_cast<uint64_t>(-1) &&
                explicitOff != static_cast<uint64_t>(-2)) {
                offset = explicitOff;
            }
        }
    }

    // We don't actually store the written data in the virtual FS for now,
    // but we DO validate that the source buffer is readable (detecting
    // access violations) and track the write for behavioral analysis.
    std::vector<uint8_t> scratch(length);
    if (mem.Read(bufferAddr, scratch.data(), length) != ErrorCode::Success) {
        WriteIoStatus(mem, ioStatusPtr, NT::STATUS_ACCESS_VIOLATION, 0);
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    // Update file position and size
    const uint64_t endPos = offset + length;
    const uint64_t newSize = std::max(fd->fileSize, endPos);
    handles.Modify<FileHandleData>(fileHandle,
        [endPos, newSize](FileHandleData& f) {
            f.filePosition = endPos;
            f.fileSize     = newSize;
        });

    // The dispatcher's behavioral layer will raise FileDropped based on the
    // API metadata in kKnownAPIs. No additional flag logic needed here.

    WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, length);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtClose
// ============================================================================
// Args: Handle

bool HandleNtClose(APIContext& ctx) {
    const auto handle = ctx.GetArg(0);

    // Pseudo-handles are not closeable
    if (handle == kCurrentProcess || handle == kCurrentThread ||
        handle == kStdInputHandle || handle == kStdOutputHandle ||
        handle == kStdErrorHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    if (handle == kNullHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto& handles = ctx.Handles();
    if (handles.Close(handle)) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
    }
    return true;
}

// ============================================================================
// NtSetInformationFile
// ============================================================================
// Args (5): FileHandle, *IoStatusBlock, *FileInformation, Length,
//           FileInformationClass

bool HandleNtSetInformationFile(APIContext& ctx) {
    const auto fileHandle  = ctx.GetArg(0);
    const auto ioStatusPtr = ctx.GetArgPtr(1);
    const auto infoPtr     = ctx.GetArgPtr(2);
    const auto infoLength  = ctx.GetArg32(3);
    const auto infoClass   = ctx.GetArg32(4);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(fileHandle, HandleType::File);
    if (!entry.has_value()) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_HANDLE, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto& mem = ctx.Memory();

    switch (infoClass) {
        case kFileDispositionInformation: {
            // BOOLEAN DeleteFile at offset 0
            if (infoPtr == 0 || infoLength < 1) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INVALID_PARAMETER, 0);
                ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
                return true;
            }
            // Delete-on-close is a defense-evasion signal (self-deletion).
            // The behavior flag is raised by the dispatcher based on API metadata.
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, 0);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        case kFilePositionInformation: {
            // LARGE_INTEGER CurrentByteOffset at offset 0
            if (infoPtr == 0 || infoLength < 8) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INVALID_PARAMETER, 0);
                ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
                return true;
            }
            uint64_t newPos = 0;
            if (mem.ReadU64(infoPtr, newPos) != ErrorCode::Success) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_ACCESS_VIOLATION, 0);
                ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
                return true;
            }
            handles.Modify<FileHandleData>(fileHandle,
                [newPos](FileHandleData& f) { f.filePosition = newPos; });
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, 0);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        default:
            // Unsupported classes: succeed silently (no-op)
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, 0);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
    }
}

// ============================================================================
// NtQueryInformationFile
// ============================================================================
// Args (5): FileHandle, *IoStatusBlock, *FileInformation, Length,
//           FileInformationClass

bool HandleNtQueryInformationFile(APIContext& ctx) {
    const auto fileHandle  = ctx.GetArg(0);
    const auto ioStatusPtr = ctx.GetArgPtr(1);
    const auto infoPtr     = ctx.GetArgPtr(2);
    const auto infoLength  = ctx.GetArg32(3);
    const auto infoClass   = ctx.GetArg32(4);

    auto& handles = ctx.Handles();
    auto entry = handles.Lookup(fileHandle, HandleType::File);
    if (!entry.has_value()) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_INVALID_HANDLE, 0);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* fd = std::get_if<FileHandleData>(&entry->data);
    if (!fd) {
        WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_OBJECT_TYPE_MISMATCH, 0);
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_TYPE_MISMATCH);
        return true;
    }

    auto& mem = ctx.Memory();

    switch (infoClass) {
        case kFileStandardInformation: {
            // FILE_STANDARD_INFORMATION (x64 = 24 bytes):
            //   +0x00 LARGE_INTEGER AllocationSize
            //   +0x08 LARGE_INTEGER EndOfFile
            //   +0x10 ULONG         NumberOfLinks
            //   +0x14 BOOLEAN       DeletePending
            //   +0x15 BOOLEAN       Directory
            static constexpr uint32_t kStdInfoSize = 24;
            if (infoPtr == 0 || infoLength < kStdInfoSize) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INFO_LENGTH_MISMATCH, 0);
                ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
                return true;
            }
            uint8_t buf[kStdInfoSize] = {};
            const uint64_t allocSize = AlignUp(fd->fileSize, kPageSize);
            std::memcpy(buf + 0x00, &allocSize, 8);
            std::memcpy(buf + 0x08, &fd->fileSize, 8);
            const uint32_t numLinks = 1;
            std::memcpy(buf + 0x10, &numLinks, 4);
            buf[0x14] = 0; // DeletePending = false
            buf[0x15] = fd->isDirectory ? 1 : 0;
            mem.Write(infoPtr, buf, kStdInfoSize);
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, kStdInfoSize);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        case kFileBasicInformation: {
            // FILE_BASIC_INFORMATION (40 bytes):
            //   +0x00 LARGE_INTEGER CreationTime
            //   +0x08 LARGE_INTEGER LastAccessTime
            //   +0x10 LARGE_INTEGER LastWriteTime
            //   +0x18 LARGE_INTEGER ChangeTime
            //   +0x20 ULONG         FileAttributes
            static constexpr uint32_t kBasicInfoSize = 40;
            if (infoPtr == 0 || infoLength < kBasicInfoSize) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INFO_LENGTH_MISMATCH, 0);
                ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
                return true;
            }
            uint8_t buf[kBasicInfoSize] = {};
            // Fake FILETIME: Jan 15 2024, 10:00 UTC in 100-ns ticks since 1601
            constexpr uint64_t kFakeTime = 133500000000000000ULL;
            std::memcpy(buf + 0x00, &kFakeTime, 8);
            std::memcpy(buf + 0x08, &kFakeTime, 8);
            std::memcpy(buf + 0x10, &kFakeTime, 8);
            std::memcpy(buf + 0x18, &kFakeTime, 8);
            const uint32_t attrs = fd->isDirectory ? 0x10u : 0x20u; // DIRECTORY : ARCHIVE
            std::memcpy(buf + 0x20, &attrs, 4);
            mem.Write(infoPtr, buf, kBasicInfoSize);
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, kBasicInfoSize);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        case kFileNameInformation: {
            // FILE_NAME_INFORMATION:
            //   +0x00 ULONG FileNameLength (bytes)
            //   +0x04 WCHAR FileName[1]
            const uint32_t nameByteLen =
                static_cast<uint32_t>(fd->path.size() * sizeof(wchar_t));
            const uint32_t structSize = 4 + nameByteLen;
            if (infoPtr == 0 || infoLength < structSize) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_BUFFER_TOO_SMALL, 0);
                ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
                return true;
            }
            mem.WriteU32(infoPtr, nameByteLen);
            mem.Write(infoPtr + 4, fd->path.data(), nameByteLen);
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, structSize);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        case kFilePositionInformation: {
            // LARGE_INTEGER CurrentByteOffset
            if (infoPtr == 0 || infoLength < 8) {
                WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INFO_LENGTH_MISMATCH, 0);
                ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
                return true;
            }
            mem.WriteU64(infoPtr, fd->filePosition);
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_SUCCESS, 8);
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
            return true;
        }

        default:
            WriteIoStatus(mem, ioStatusPtr, NT::STATUS_INVALID_INFO_CLASS, 0);
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
            return true;
    }
}

// ============================================================================
// NtQueryDirectoryFile
// ============================================================================
// Args (11): FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
//            *FileInformation, Length, FileInformationClass,
//            ReturnSingleEntry, *FileName, RestartScan

bool HandleNtQueryDirectoryFile(APIContext& ctx) {
    // arg4 = IoStatusBlock
    const auto ioStatusPtr = ctx.GetArgPtr(4);

    // Virtual FS: no real directory contents to enumerate.
    WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_NO_MORE_ENTRIES, 0);
    ctx.SetReturnNtStatus(NT::STATUS_NO_MORE_ENTRIES);
    return true;
}

// ============================================================================
// NtDeviceIoControlFile
// ============================================================================
// Args (10): FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
//            IoControlCode, *InputBuffer, InputBufferLength,
//            *OutputBuffer, OutputBufferLength

bool HandleNtDeviceIoControlFile(APIContext& ctx) {
    const auto ioStatusPtr = ctx.GetArgPtr(4);
    // arg5 = IoControlCode — tracked for behavioral analysis by the dispatcher

    // We don't emulate any specific device IOCTLs.
    WriteIoStatus(ctx.Memory(), ioStatusPtr, NT::STATUS_NOT_SUPPORTED, 0);
    ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtFile(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ntdll.dll", "NtCreateFile",
          HandleNtCreateFile, 11, true },
        { "ntdll.dll", "NtReadFile",
          HandleNtReadFile, 9, true },
        { "ntdll.dll", "NtWriteFile",
          HandleNtWriteFile, 9, true },
        { "ntdll.dll", "NtClose",
          HandleNtClose, 1, true },
        { "ntdll.dll", "NtSetInformationFile",
          HandleNtSetInformationFile, 5, false },
        { "ntdll.dll", "NtQueryInformationFile",
          HandleNtQueryInformationFile, 5, false },
        { "ntdll.dll", "NtQueryDirectoryFile",
          HandleNtQueryDirectoryFile, 11, false },
        { "ntdll.dll", "NtDeviceIoControlFile",
          HandleNtDeviceIoControlFile, 10, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ntdll
