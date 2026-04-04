/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualFileSystem.hpp — Centralized virtual file system backing store
 *
 * Provides a complete virtual directory tree mimicking a real Windows 10
 * installation with file content simulation, path normalization, CRUD
 * operations, directory enumeration, and anti-evasion guarantees.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <memory>
#include <functional>

namespace Phantom::VirtualOS {

// ============================================================================
// File Attribute Constants (match Windows FILE_ATTRIBUTE_* values)
// ============================================================================

namespace FileAttr {
    static constexpr uint32_t ReadOnly   = 0x00000001;
    static constexpr uint32_t Hidden     = 0x00000002;
    static constexpr uint32_t System     = 0x00000004;
    static constexpr uint32_t Directory  = 0x00000010;
    static constexpr uint32_t Archive    = 0x00000020;
    static constexpr uint32_t Normal     = 0x00000080;
    static constexpr uint32_t Temporary  = 0x00000100;
}

// ============================================================================
// CREATE_DISPOSITION Values
// ============================================================================

namespace CreateDisposition {
    static constexpr uint32_t CreateNew        = 1;
    static constexpr uint32_t CreateAlways     = 2;
    static constexpr uint32_t OpenExisting     = 3;
    static constexpr uint32_t OpenAlways       = 4;
    static constexpr uint32_t TruncateExisting = 5;
}

// ============================================================================
// File Access Modes (match GENERIC_* constants)
// ============================================================================

namespace FileAccess {
    static constexpr uint32_t Read    = 0x80000000;
    static constexpr uint32_t Write   = 0x40000000;
    static constexpr uint32_t Execute = 0x20000000;
    static constexpr uint32_t All     = 0x10000000;
}

// ============================================================================
// Seek Origins
// ============================================================================

enum class SeekOrigin : uint32_t {
    Begin   = 0,    // FILE_BEGIN
    Current = 1,    // FILE_CURRENT
    End     = 2,    // FILE_END
};

// ============================================================================
// Virtual File Entry — A single node in the virtual file system tree
// ============================================================================

struct VirtualFileEntry {
    std::wstring          name;
    std::wstring          fullPath;
    uint32_t              attributes     = FileAttr::Normal;
    uint64_t              fileSize       = 0;
    uint64_t              creationTime   = 0;   // FILETIME (100-ns since 1601)
    uint64_t              lastWriteTime  = 0;
    uint64_t              lastAccessTime = 0;
    std::vector<uint8_t>  content;              // Actual bytes (malware-written files)
    bool                  isPrePopulated = true; // true = system file (metadata only)
};

// ============================================================================
// Directory Entry — Returned by directory enumeration
// ============================================================================

struct DirectoryEntry {
    std::wstring name;
    uint32_t     attributes;
    uint64_t     fileSize;
    uint64_t     creationTime;
    uint64_t     lastWriteTime;
    uint64_t     lastAccessTime;
};

// ============================================================================
// Open File State — Per-handle state for an open file
// ============================================================================

struct OpenFileState {
    std::wstring path;
    uint32_t     access      = 0;
    uint64_t     position    = 0;
    bool         isDirectory = false;
};

// ============================================================================
// Find State — Per-handle state for FindFirstFile/FindNextFile enumeration
// ============================================================================

struct FindState {
    std::vector<DirectoryEntry> entries;
    size_t                      currentIndex = 0;
};

// ============================================================================
// VirtualFileSystem — Meyers' Singleton
// ============================================================================

class VirtualFileSystem {
public:
    [[nodiscard]] static VirtualFileSystem& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === File Operations ===

    [[nodiscard]] std::optional<uint32_t> OpenFile(
        std::wstring_view path,
        uint32_t access,
        uint32_t shareMode,
        uint32_t disposition) noexcept;

    bool CloseFile(uint32_t fileId) noexcept;

    [[nodiscard]] uint32_t ReadFile(
        uint32_t fileId,
        uint8_t* buffer,
        uint32_t bytesToRead) noexcept;

    [[nodiscard]] uint32_t WriteFile(
        uint32_t fileId,
        const uint8_t* buffer,
        uint32_t bytesToWrite) noexcept;

    [[nodiscard]] int64_t SetFilePointer(
        uint32_t fileId,
        int64_t distance,
        SeekOrigin origin) noexcept;

    [[nodiscard]] std::optional<uint64_t> GetFileSize(uint32_t fileId) const noexcept;

    // === Path-based Operations ===

    bool DeleteFile(std::wstring_view path) noexcept;
    bool MoveFile(std::wstring_view oldPath, std::wstring_view newPath) noexcept;
    bool CopyFile(std::wstring_view srcPath, std::wstring_view dstPath) noexcept;

    [[nodiscard]] bool Exists(std::wstring_view path) const noexcept;
    [[nodiscard]] std::optional<uint32_t> GetAttributes(std::wstring_view path) const noexcept;
    [[nodiscard]] std::optional<VirtualFileEntry> GetFileInfo(std::wstring_view path) const noexcept;

    // === Directory Operations ===

    bool CreateDirectory(std::wstring_view path) noexcept;

    [[nodiscard]] std::optional<uint32_t> FindFirst(
        std::wstring_view pattern,
        DirectoryEntry& firstEntry) noexcept;

    [[nodiscard]] bool FindNext(uint32_t findId, DirectoryEntry& nextEntry) noexcept;

    void FindClose(uint32_t findId) noexcept;

    // === Path Utilities ===

    [[nodiscard]] static std::wstring NormalizePath(std::wstring_view path) noexcept;
    [[nodiscard]] std::wstring GetTempPath() const noexcept;

    // === IOC Tracking ===

    [[nodiscard]] std::vector<std::wstring> GetMalwareCreatedFiles() const noexcept;
    [[nodiscard]] std::vector<std::wstring> GetMalwareDeletedFiles() const noexcept;

private:
    VirtualFileSystem() noexcept = default;
    VirtualFileSystem(const VirtualFileSystem&) = delete;
    VirtualFileSystem& operator=(const VirtualFileSystem&) = delete;

    void PopulateDefaultFileSystem(const EmulationConfig& config) noexcept;
    void AddSystemDirectory(std::wstring_view path) noexcept;
    void AddSystemFile(std::wstring_view path, uint64_t size,
                       uint32_t attrs = FileAttr::Normal) noexcept;

    [[nodiscard]] static bool WildcardMatch(
        std::wstring_view pattern,
        std::wstring_view name) noexcept;

    [[nodiscard]] static uint64_t SystemFileTime() noexcept;
    [[nodiscard]] static std::vector<uint8_t> GeneratePEStub(bool isDll, bool is64bit) noexcept;

    // Resource caps
    static constexpr uint32_t kMaxFileCount       = 10'000;
    static constexpr uint64_t kMaxPerFileContent   = 64ULL * 1024 * 1024;
    static constexpr uint64_t kMaxTotalContent     = 256ULL * 1024 * 1024;

    mutable std::shared_mutex m_mutex;

    std::map<std::wstring, VirtualFileEntry, std::less<>> m_files;

    std::unordered_map<uint32_t, OpenFileState> m_openFiles;
    uint32_t m_nextFileId = 1;

    std::unordered_map<uint32_t, FindState> m_findHandles;
    uint32_t m_nextFindId = 1;

    std::vector<std::wstring> m_malwareCreatedFiles;
    std::vector<std::wstring> m_malwareDeletedFiles;

    uint64_t m_totalContentSize = 0;
    bool m_initialized = false;
    std::wstring m_userName;
};

} // namespace Phantom::VirtualOS
