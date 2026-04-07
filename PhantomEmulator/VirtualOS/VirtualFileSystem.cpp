/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualFileSystem.cpp — Complete virtual filesystem implementation
 *
 * Provides a realistic Windows 10 Pro file system tree with path
 * normalization, content simulation, CRUD operations, directory
 * enumeration with wildcard matching, and anti-evasion guarantees.
 *
 * Architecture notes:
 * ------------------
 *   - Single std::shared_mutex guards all internal state.  Reads (Exists,
 *     GetAttributes, GetFileInfo, GetFileSize, IOC accessors) take a
 *     shared_lock.  Writes (Open, Close, Read, Write, Delete, Move,
 *     Copy, FindFirst/Next/Close, Initialize, Reset) take a unique_lock.
 *
 *   - File paths are stored in a std::map<wstring, ...> with std::less<>
 *     transparent comparator for wstring_view lookups.  All keys are
 *     lowercase to provide case-insensitive semantics.
 *
 *   - Pre-populated entries carry metadata only (size, attributes,
 *     timestamps).  Actual content (PE stubs) is generated on demand
 *     during ReadFile, avoiding millions of stub allocations at init.
 *
 *   - IOC tracking records every file path created, modified, or deleted
 *     by the emulated sample.  These lists are harvested after the
 *     session by the behavior analysis pipeline.
 *
 *   - Resource caps prevent the emulated sample from exhausting host
 *     memory: 10 000 max file entries, 64 MB per-file content, 256 MB
 *     total content across the session.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VirtualFileSystem.hpp"
#include "SystemDLLContent.hpp"

#include <algorithm>
#include <cstring>
#include <cwctype>

namespace Phantom::VirtualOS {

// ============================================================================
// Internal Constants
// ============================================================================

namespace {

// Jan 15, 2024 08:30:00 UTC in FILETIME (100-ns intervals since Jan 1, 1601)
static constexpr uint64_t kSystemFileTime = 133'500'402'000'000'000ULL;

// PE timestamp corresponding to the same date (Unix epoch-based)
static constexpr uint32_t kPETimestamp = 0x65A5C8A0;

static constexpr uint64_t KB = 1024;
static constexpr uint64_t MB = 1024 * 1024;
static constexpr uint64_t GB = 1024 * 1024 * 1024;

// ============================================================================
// Little-Endian Write Helpers (for PE stub generation)
// ============================================================================

void WriteU16LE(std::vector<uint8_t>& buf, size_t offset, uint16_t value) noexcept {
    if (offset + 1 >= buf.size()) return;
    buf[offset]     = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

void WriteU32LE(std::vector<uint8_t>& buf, size_t offset, uint32_t value) noexcept {
    if (offset + 3 >= buf.size()) return;
    buf[offset]     = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buf[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void WriteU64LE(std::vector<uint8_t>& buf, size_t offset, uint64_t value) noexcept {
    if (offset + 7 >= buf.size()) return;
    for (int i = 0; i < 8; ++i) {
        buf[offset + static_cast<size_t>(i)] =
            static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

// ============================================================================
// Extension Classification
// ============================================================================

[[nodiscard]] bool IsPEExtension(std::wstring_view path) noexcept {
    auto dot = path.rfind(L'.');
    if (dot == std::wstring_view::npos) return false;
    auto ext = path.substr(dot);
    return ext == L".dll" || ext == L".exe" || ext == L".sys" ||
           ext == L".drv" || ext == L".ocx" || ext == L".cpl";
}

[[nodiscard]] std::wstring ExtractFileName(std::wstring_view path) noexcept {
    auto sep = path.rfind(L'\\');
    if (sep == std::wstring_view::npos) return std::wstring(path);
    return std::wstring(path.substr(sep + 1));
}

} // anonymous namespace

// ============================================================================
// Static Utility: Path Normalization
// ============================================================================
//
// Converts any Windows path format to the canonical internal form used as
// the key in m_files.  Handles the following input formats:
//
//   Win32:        C:\Windows\System32\ntdll.dll       → as-is
//   Extended:     \\?\C:\Windows\System32\ntdll.dll   → strip \\?\ prefix
//   NT Object:    \??\C:\Windows\System32\ntdll.dll   → strip \??\ prefix
//   NT Device:    \Device\HarddiskVolume3\Windows\... → C:\Windows\...
//   SystemRoot:   \SystemRoot\System32\ntdll.dll      → C:\Windows\System32\...
//   Relative:     system32\ntdll.dll                  → C:\Windows\System32\...
//   Forward-slash: C:/Windows/System32/ntdll.dll      → backslash form
//   Mixed:        \??\C:/Windows\\System32/ntdll.dll  → all cases combined
//
// Post-processing:
//   - Entire path lowercased (case-insensitive matching)
//   - Consecutive backslashes collapsed
//   - Dot-segments (., ..) resolved
//   - Trailing backslashes removed (root "c:" preserved)

std::wstring VirtualFileSystem::NormalizePath(std::wstring_view path) noexcept {
    if (path.empty()) return {};

    std::wstring result(path);

    // Step 1: Forward slashes → backslashes
    for (auto& ch : result) {
        if (ch == L'/') ch = L'\\';
    }

    // Step 2: Strip NT-style prefixes
    //
    // Windows paths appear in many forms depending on the API layer:
    //   - \\?\ (Win32 extended-length path prefix)
    //   - \??\ (NT object manager prefix, used by NtCreateFile etc.)
    //   - \Device\HarddiskVolumeN\ (NT device path, common in driver-level APIs)
    //   - \SystemRoot\ (NT symbolic link to Windows directory)
    //
    // All forms must be normalized to a canonical C:\... path for internal
    // consistency. Prefix detection is case-insensitive to handle all
    // variations seen in real malware samples.

    // Helper: case-insensitive prefix comparison
    auto ciStartsWith = [](const std::wstring& str, const wchar_t* prefix, size_t len) -> bool {
        if (str.size() < len) return false;
        for (size_t i = 0; i < len; ++i) {
            wchar_t a = static_cast<wchar_t>(
                std::towlower(static_cast<std::wint_t>(str[i])));
            wchar_t b = static_cast<wchar_t>(
                std::towlower(static_cast<std::wint_t>(prefix[i])));
            if (a != b) return false;
        }
        return true;
    };

    //   \\?\ (extended-length path prefix — 4 chars: \, \, ?, \)
    if (result.size() >= 4 && result[0] == L'\\' && result[1] == L'\\' &&
        result[2] == L'?' && result[3] == L'\\') {
        result.erase(0, 4);
    }
    //   \??\ (NT object manager prefix — 4 chars: \, ?, ?, \)
    else if (result.size() >= 4 && result[0] == L'\\' && result[1] == L'?' &&
             result[2] == L'?' && result[3] == L'\\') {
        result.erase(0, 4);
    }
    //   \Device\HarddiskVolumeN\ → C:\  (case-insensitive)
    else if (ciStartsWith(result, L"\\Device\\", 8)) {
        // Skip past the volume component (\Device\HarddiskVolume3)
        auto thirdSlash = result.find(L'\\', 8);
        if (thirdSlash != std::wstring::npos) {
            result = L"C:" + result.substr(thirdSlash);
        } else {
            result = L"C:";
        }
    }
    //   \SystemRoot\... → C:\Windows\...  (case-insensitive)
    else if (ciStartsWith(result, L"\\SystemRoot\\", 12)) {
        result = L"C:\\Windows\\" + result.substr(12);
    }
    //   \SystemRoot (no trailing slash) → C:\Windows
    else if (ciStartsWith(result, L"\\SystemRoot", 11) && result.size() == 11) {
        result = L"C:\\Windows";
    }

    // Step 3: Detect relative paths (no drive letter and no UNC prefix)
    bool hasDrive = (result.size() >= 2 && std::iswalpha(result[0]) && result[1] == L':');
    bool isAbsolute = hasDrive || (result.size() >= 2 && result[0] == L'\\' && result[1] == L'\\');

    if (!isAbsolute) {
        // Strip leading .\ if present
        if (result.size() >= 2 && result[0] == L'.' && result[1] == L'\\') {
            result.erase(0, 2);
        }
        // Relative → resolve against C:\Windows\System32
        result = L"C:\\Windows\\System32\\" + result;
    }

    // Step 4: Lowercase the entire path
    for (auto& ch : result) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(ch)));
    }

    // Step 5: Collapse consecutive backslashes (except the first two for UNC \\server)
    std::wstring collapsed;
    collapsed.reserve(result.size());
    bool prevWasSlash = false;
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i] == L'\\') {
            if (!prevWasSlash) {
                collapsed += L'\\';
            }
            prevWasSlash = true;
        } else {
            collapsed += result[i];
            prevWasSlash = false;
        }
    }
    result = std::move(collapsed);

    // Step 6: Resolve . and .. path components
    std::vector<std::wstring> components;
    size_t start = 0;

    // Preserve the drive prefix "c:" as the first component
    if (result.size() >= 2 && std::iswalpha(result[0]) && result[1] == L':') {
        components.emplace_back(result.substr(0, 2));
        start = 2;
        if (start < result.size() && result[start] == L'\\') ++start;
    }

    while (start < result.size()) {
        auto sep = result.find(L'\\', start);
        if (sep == std::wstring::npos) sep = result.size();

        std::wstring comp = result.substr(start, sep - start);
        start = sep + 1;

        if (comp == L"." || comp.empty()) {
            continue;
        } else if (comp == L"..") {
            if (components.size() > 1) {
                components.pop_back();
            }
        } else {
            components.push_back(std::move(comp));
        }
    }

    // Step 7: Rebuild the path
    if (components.empty()) return {};
    result = components[0];
    for (size_t i = 1; i < components.size(); ++i) {
        result += L'\\';
        result += components[i];
    }

    // Step 8: Remove trailing backslash (but preserve "c:" root form)
    while (result.size() > 2 && result.back() == L'\\') {
        result.pop_back();
    }

    return result;
}

// ============================================================================
// Static Utility: Wildcard Matching (case-insensitive)
// ============================================================================
//
// Implements Win32 FindFirstFile wildcard semantics:
//   - '*' matches zero or more characters
//   - '?' matches exactly one character
//   - '*.*' matches ALL files (Windows convention, including no extension)
//
// Uses an iterative star-backtrack algorithm, O(n·m) worst case but
// typically O(n+m) on realistic patterns.

bool VirtualFileSystem::WildcardMatch(
    std::wstring_view pattern,
    std::wstring_view name) noexcept
{
    // *.* matches everything (Windows convention)
    if (pattern == L"*.*" || pattern == L"*") return true;

    size_t pi = 0, ni = 0;
    size_t starPi = std::wstring_view::npos;
    size_t starNi = 0;

    while (ni < name.size()) {
        if (pi < pattern.size()) {
            wchar_t pc = static_cast<wchar_t>(
                std::towlower(static_cast<std::wint_t>(pattern[pi])));
            wchar_t nc = static_cast<wchar_t>(
                std::towlower(static_cast<std::wint_t>(name[ni])));

            if (pc == nc || pc == L'?') {
                ++pi;
                ++ni;
                continue;
            }
            if (pc == L'*') {
                starPi = pi;
                starNi = ni;
                ++pi;
                continue;
            }
        }

        if (starPi != std::wstring_view::npos) {
            pi = starPi + 1;
            ++starNi;
            ni = starNi;
        } else {
            return false;
        }
    }

    // Consume trailing stars in pattern
    while (pi < pattern.size() && pattern[pi] == L'*') ++pi;
    return pi == pattern.size();
}

// ============================================================================
// Static Utility: System File Timestamp
// ============================================================================

uint64_t VirtualFileSystem::SystemFileTime() noexcept {
    return kSystemFileTime;
}

// ============================================================================
// Static Utility: Minimal Valid PE Stub Generator
// ============================================================================
//
// Produces a 512-byte buffer containing:
//   - IMAGE_DOS_HEADER with valid MZ magic and e_lfanew at 0x80
//   - PE signature at 0x80
//   - COFF File Header (Machine, NumberOfSections, Characteristics)
//   - Optional Header with correct PE32/PE32+ magic
//   - One .text section header
//
// This is sufficient to pass PE validation checks that malware performs
// when verifying loaded system DLLs via ReadFile / MapViewOfFile.

std::vector<uint8_t> VirtualFileSystem::GeneratePEStub(
    bool isDll,
    bool is64bit) noexcept
{
    constexpr size_t kStubSize = 512;
    std::vector<uint8_t> stub(kStubSize, 0);

    // --- IMAGE_DOS_HEADER ---
    WriteU16LE(stub, 0x00, 0x5A4D);           // e_magic  = "MZ"
    WriteU16LE(stub, 0x02, 0x0090);           // e_cblp   (last page bytes)
    WriteU16LE(stub, 0x04, 0x0003);           // e_cp     (pages)
    WriteU16LE(stub, 0x08, 0x0004);           // e_minalloc
    WriteU16LE(stub, 0x0A, 0xFFFF);           // e_maxalloc
    WriteU16LE(stub, 0x10, 0x00B8);           // e_sp
    WriteU16LE(stub, 0x18, 0x0040);           // e_lfarlc (reloc table offset)
    WriteU32LE(stub, 0x3C, 0x00000080);       // e_lfanew → PE header at 0x80

    // --- PE Signature at 0x80 ---
    WriteU32LE(stub, 0x80, 0x00004550);       // "PE\0\0"

    // --- COFF File Header at 0x84 ---
    WriteU16LE(stub, 0x84, is64bit ? static_cast<uint16_t>(0x8664)
                                   : static_cast<uint16_t>(0x014C));
    WriteU16LE(stub, 0x86, 0x0001);           // NumberOfSections
    WriteU32LE(stub, 0x88, kPETimestamp);     // TimeDateStamp
    // PointerToSymbolTable = 0, NumberOfSymbols = 0 (already zeroed)
    uint16_t optHdrSize = is64bit ? 0x00F0 : 0x00E0;
    WriteU16LE(stub, 0x94, optHdrSize);       // SizeOfOptionalHeader
    uint16_t characteristics = 0x0022;        // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    if (isDll) characteristics |= 0x2000;     // IMAGE_FILE_DLL
    WriteU16LE(stub, 0x96, characteristics);

    // --- Optional Header at 0x98 ---
    constexpr size_t kOptBase = 0x98;

    WriteU16LE(stub, kOptBase + 0x00,
               is64bit ? static_cast<uint16_t>(0x020B)
                       : static_cast<uint16_t>(0x010B));
    stub[kOptBase + 0x02] = 14;               // MajorLinkerVersion (MSVC 14.x)
    stub[kOptBase + 0x03] = 36;               // MinorLinkerVersion
    WriteU32LE(stub, kOptBase + 0x04, 0x0200);// SizeOfCode
    WriteU32LE(stub, kOptBase + 0x08, 0x0200);// SizeOfInitializedData
    WriteU32LE(stub, kOptBase + 0x10, 0x1000);// AddressOfEntryPoint
    WriteU32LE(stub, kOptBase + 0x14, 0x1000);// BaseOfCode

    if (is64bit) {
        // PE32+: ImageBase at offset +0x18 (8 bytes), no BaseOfData
        WriteU64LE(stub, kOptBase + 0x18, 0x0000000180000000ULL);
        WriteU32LE(stub, kOptBase + 0x20, 0x1000);     // SectionAlignment
        WriteU32LE(stub, kOptBase + 0x24, 0x0200);     // FileAlignment
        WriteU16LE(stub, kOptBase + 0x28, 10);          // MajorOperatingSystemVersion
        WriteU16LE(stub, kOptBase + 0x2A, 0);           // MinorOperatingSystemVersion
        WriteU16LE(stub, kOptBase + 0x2C, 10);          // MajorImageVersion
        WriteU16LE(stub, kOptBase + 0x2E, 0);           // MinorImageVersion
        WriteU16LE(stub, kOptBase + 0x30, 6);           // MajorSubsystemVersion
        WriteU16LE(stub, kOptBase + 0x32, 0);           // MinorSubsystemVersion
        WriteU32LE(stub, kOptBase + 0x38, 0x3000);      // SizeOfImage
        WriteU32LE(stub, kOptBase + 0x3C, 0x0200);      // SizeOfHeaders
        WriteU16LE(stub, kOptBase + 0x44, 3);            // Subsystem (CONSOLE)
        WriteU16LE(stub, kOptBase + 0x46, 0x8160);       // DllCharacteristics
        WriteU64LE(stub, kOptBase + 0x48, 0x00100000);   // SizeOfStackReserve
        WriteU64LE(stub, kOptBase + 0x50, 0x00001000);   // SizeOfStackCommit
        WriteU64LE(stub, kOptBase + 0x58, 0x00100000);   // SizeOfHeapReserve
        WriteU64LE(stub, kOptBase + 0x60, 0x00001000);   // SizeOfHeapCommit
        WriteU32LE(stub, kOptBase + 0x6C, 16);           // NumberOfRvaAndSizes
    } else {
        // PE32: BaseOfData at +0x18 (4 bytes), ImageBase at +0x1C (4 bytes)
        WriteU32LE(stub, kOptBase + 0x18, 0x2000);       // BaseOfData
        WriteU32LE(stub, kOptBase + 0x1C, 0x10000000);   // ImageBase
        WriteU32LE(stub, kOptBase + 0x20, 0x1000);       // SectionAlignment
        WriteU32LE(stub, kOptBase + 0x24, 0x0200);       // FileAlignment
        WriteU16LE(stub, kOptBase + 0x28, 10);            // MajorOperatingSystemVersion
        WriteU16LE(stub, kOptBase + 0x2A, 0);             // MinorOperatingSystemVersion
        WriteU16LE(stub, kOptBase + 0x2C, 10);            // MajorImageVersion
        WriteU16LE(stub, kOptBase + 0x2E, 0);             // MinorImageVersion
        WriteU16LE(stub, kOptBase + 0x30, 6);             // MajorSubsystemVersion
        WriteU16LE(stub, kOptBase + 0x32, 0);             // MinorSubsystemVersion
        WriteU32LE(stub, kOptBase + 0x38, 0x3000);        // SizeOfImage
        WriteU32LE(stub, kOptBase + 0x3C, 0x0200);        // SizeOfHeaders
        WriteU16LE(stub, kOptBase + 0x44, 3);              // Subsystem (CONSOLE)
        WriteU16LE(stub, kOptBase + 0x46, 0x8160);         // DllCharacteristics
        WriteU32LE(stub, kOptBase + 0x48, 0x00100000);     // SizeOfStackReserve
        WriteU32LE(stub, kOptBase + 0x4C, 0x00001000);     // SizeOfStackCommit
        WriteU32LE(stub, kOptBase + 0x50, 0x00100000);     // SizeOfHeapReserve
        WriteU32LE(stub, kOptBase + 0x54, 0x00001000);     // SizeOfHeapCommit
        WriteU32LE(stub, kOptBase + 0x5C, 16);             // NumberOfRvaAndSizes
    }

    // --- .text Section Header (immediately after Optional Header) ---
    size_t secOff = kOptBase + optHdrSize;
    if (secOff + 40 <= kStubSize) {
        stub[secOff + 0] = '.';
        stub[secOff + 1] = 't';
        stub[secOff + 2] = 'e';
        stub[secOff + 3] = 'x';
        stub[secOff + 4] = 't';
        WriteU32LE(stub, secOff + 8,  0x0200);     // VirtualSize
        WriteU32LE(stub, secOff + 12, 0x1000);     // VirtualAddress
        WriteU32LE(stub, secOff + 16, 0x0200);     // SizeOfRawData
        WriteU32LE(stub, secOff + 20, 0x0200);     // PointerToRawData
        WriteU32LE(stub, secOff + 36, 0x60000020); // CODE | EXECUTE | READ
    }

    return stub;
}

// ============================================================================
// Singleton
// ============================================================================

VirtualFileSystem& VirtualFileSystem::Instance() noexcept {
    static VirtualFileSystem instance;
    return instance;
}

// ============================================================================
// Initialize / Reset
// ============================================================================
//
// Initialize() populates the virtual filesystem with a realistic Windows 10
// directory tree based on the given EmulationConfig (user name, etc.).
// It is idempotent: calling it multiple times has no effect after the
// first call.  The caller (emulation session) must call Reset() before
// re-initializing with different config.
//
// Reset() tears down all VFS state: file tree, open handles, find handles,
// and IOC tracking lists.  It also resets all ID counters.  This is called
// at session end before the VFS singleton is reused for the next sample.

void VirtualFileSystem::Initialize(const EmulationConfig& config) noexcept {
    std::unique_lock lock(m_mutex);

    if (m_initialized) return;

    m_userName = config.userName;
    for (auto& ch : m_userName) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(ch)));
    }

    PopulateDefaultFileSystem(config);
    m_initialized = true;
}

void VirtualFileSystem::Reset() noexcept {
    std::unique_lock lock(m_mutex);

    m_files.clear();
    m_openFiles.clear();
    m_findHandles.clear();
    m_malwareCreatedFiles.clear();
    m_malwareDeletedFiles.clear();

    m_nextFileId = 1;
    m_nextFindId = 1;
    m_totalContentSize = 0;
    m_initialized = false;
    m_userName.clear();
}

// ============================================================================
// Internal: AddSystemDirectory / AddSystemFile
// ============================================================================

void VirtualFileSystem::AddSystemDirectory(std::wstring_view path) noexcept {
    if (m_files.size() >= kMaxFileCount) return;

    std::wstring normalized(path);
    for (auto& ch : normalized) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(ch)));
    }

    VirtualFileEntry entry;
    entry.name      = ExtractFileName(normalized);
    entry.fullPath  = normalized;
    entry.attributes = FileAttr::Directory;
    entry.creationTime   = kSystemFileTime;
    entry.lastWriteTime  = kSystemFileTime;
    entry.lastAccessTime = kSystemFileTime;
    entry.isPrePopulated = true;

    m_files.emplace(std::move(normalized), std::move(entry));
}

void VirtualFileSystem::AddSystemFile(
    std::wstring_view path,
    uint64_t size,
    uint32_t attrs) noexcept
{
    if (m_files.size() >= kMaxFileCount) return;

    std::wstring normalized(path);
    for (auto& ch : normalized) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(ch)));
    }

    VirtualFileEntry entry;
    entry.name           = ExtractFileName(normalized);
    entry.fullPath       = normalized;
    entry.attributes     = attrs;
    entry.fileSize       = size;
    entry.creationTime   = kSystemFileTime;
    entry.lastWriteTime  = kSystemFileTime;
    entry.lastAccessTime = kSystemFileTime;
    entry.isPrePopulated = true;

    m_files.emplace(std::move(normalized), std::move(entry));
}

// ============================================================================
// PopulateDefaultFileSystem — Builds the entire virtual Windows 10 tree
// ============================================================================
//
// Populates a realistic Windows 10 Pro 22H2 (build 19045) filesystem tree.
// The goal is to be indistinguishable from a genuine corporate endpoint
// when malware enumerates files, reads DLL headers, or checks for sandbox
// artifacts.
//
// Anti-evasion contract (MUST NEVER be violated):
//   - NO VirtualBox artifacts  (VBoxGuest*, VBoxMouse, VBoxSF, VBoxTray)
//   - NO VMware artifacts      (vmtools, vmhgfs, vmci, vmxnet, vm3dgl)
//   - NO QEMU artifacts        (qemu-ga, virtio-*.sys, vioser.sys)
//   - NO Hyper-V guest files   (integ*.sys, vmicheartbeat, vmicshutdown)
//   - NO analysis tools        (python.exe, perl.exe, ruby.exe)
//   - NO reversing tools       (wireshark, procmon, processhacker,
//                                x64dbg, ollydbg, ida*, ghidra*)
//   - NO sandbox markers       (sandbox.*, analysis.*, malware.*,
//                                sample.*, cuckoo*, sbie*)
//   - NO suspicious paths      (c:\agent\, c:\sandbox\, c:\tools\)
//
// File sizes are approximate matches to Windows 10 22H2 with the latest
// cumulative update.  Timestamps are uniform (Jan 15 2024 patch cycle).
// DLL files return a valid MZ+PE header when read.

void VirtualFileSystem::PopulateDefaultFileSystem(
    const EmulationConfig& config) noexcept
{
    // ----------------------------------------------------------------
    // Drive root
    // ----------------------------------------------------------------
    AddSystemDirectory(L"c:");

    // ----------------------------------------------------------------
    // C:\Windows and sub-directories
    // ----------------------------------------------------------------
    AddSystemDirectory(L"c:\\windows");
    AddSystemDirectory(L"c:\\windows\\system32");
    AddSystemDirectory(L"c:\\windows\\system32\\drivers");
    AddSystemDirectory(L"c:\\windows\\system32\\config");
    AddSystemDirectory(L"c:\\windows\\system32\\wbem");
    AddSystemDirectory(L"c:\\windows\\system32\\wbem\\repository");
    AddSystemDirectory(L"c:\\windows\\system32\\en-us");
    AddSystemDirectory(L"c:\\windows\\system32\\spool");
    AddSystemDirectory(L"c:\\windows\\system32\\spool\\drivers");
    AddSystemDirectory(L"c:\\windows\\system32\\tasks");
    AddSystemDirectory(L"c:\\windows\\system32\\catroot");
    AddSystemDirectory(L"c:\\windows\\system32\\catroot\\{f750e6c3-38ee-11d1-85e5-00c04fc295ee}");
    AddSystemDirectory(L"c:\\windows\\system32\\catroot2");
    AddSystemDirectory(L"c:\\windows\\system32\\catroot2\\{f750e6c3-38ee-11d1-85e5-00c04fc295ee}");
    AddSystemDirectory(L"c:\\windows\\system32\\catroot2\\{127d0a1d-4ef2-11d1-8608-00c04fc295ee}");
    AddSystemDirectory(L"c:\\windows\\system32\\driverstore");
    AddSystemDirectory(L"c:\\windows\\system32\\winevt");
    AddSystemDirectory(L"c:\\windows\\system32\\winevt\\logs");
    AddSystemDirectory(L"c:\\windows\\system32\\windowspowershell");
    AddSystemDirectory(L"c:\\windows\\system32\\windowspowershell\\v1.0");
    AddSystemDirectory(L"c:\\windows\\syswow64");
    AddSystemDirectory(L"c:\\windows\\syswow64\\drivers");
    AddSystemDirectory(L"c:\\windows\\inf");
    AddSystemDirectory(L"c:\\windows\\fonts");
    AddSystemDirectory(L"c:\\windows\\temp");
    AddSystemDirectory(L"c:\\windows\\logs");
    AddSystemDirectory(L"c:\\windows\\winsxs");
    AddSystemDirectory(L"c:\\windows\\prefetch");
    AddSystemDirectory(L"c:\\windows\\servicing");
    AddSystemDirectory(L"c:\\windows\\assembly");
    AddSystemDirectory(L"c:\\windows\\microsoft.net");
    AddSystemDirectory(L"c:\\windows\\microsoft.net\\framework");
    AddSystemDirectory(L"c:\\windows\\microsoft.net\\framework\\v4.0.30319");
    AddSystemDirectory(L"c:\\windows\\microsoft.net\\framework64");
    AddSystemDirectory(L"c:\\windows\\microsoft.net\\framework64\\v4.0.30319");
    AddSystemDirectory(L"c:\\windows\\globalization");
    AddSystemDirectory(L"c:\\windows\\rescache");
    AddSystemDirectory(L"c:\\windows\\resources");
    AddSystemDirectory(L"c:\\windows\\security");
    AddSystemDirectory(L"c:\\windows\\schemas");
    AddSystemDirectory(L"c:\\windows\\appcompat");
    AddSystemDirectory(L"c:\\windows\\apppatch");
    AddSystemDirectory(L"c:\\windows\\debug");
    AddSystemDirectory(L"c:\\windows\\diagnostics");
    AddSystemDirectory(L"c:\\windows\\downloaded program files");
    AddSystemDirectory(L"c:\\windows\\ime");
    AddSystemDirectory(L"c:\\windows\\installer");
    AddSystemDirectory(L"c:\\windows\\livekernelreports");
    AddSystemDirectory(L"c:\\windows\\media");
    AddSystemDirectory(L"c:\\windows\\migration");
    AddSystemDirectory(L"c:\\windows\\pla");
    AddSystemDirectory(L"c:\\windows\\policydefinitions");
    AddSystemDirectory(L"c:\\windows\\registration");
    AddSystemDirectory(L"c:\\windows\\softwareDistribution");
    AddSystemDirectory(L"c:\\windows\\speechonecore");
    AddSystemDirectory(L"c:\\windows\\tracing");
    AddSystemDirectory(L"c:\\windows\\web");
    AddSystemDirectory(L"c:\\windows\\web\\wallpaper");
    AddSystemDirectory(L"c:\\windows\\cursors");
    AddSystemDirectory(L"c:\\windows\\help");

    // ----------------------------------------------------------------
    // Program Files
    // ----------------------------------------------------------------
    AddSystemDirectory(L"c:\\program files");
    AddSystemDirectory(L"c:\\program files\\common files");
    AddSystemDirectory(L"c:\\program files\\common files\\system");
    AddSystemDirectory(L"c:\\program files\\internet explorer");
    AddSystemDirectory(L"c:\\program files\\windows defender");
    AddSystemDirectory(L"c:\\program files\\windows mail");
    AddSystemDirectory(L"c:\\program files\\windows media player");
    AddSystemDirectory(L"c:\\program files\\windows nt");
    AddSystemDirectory(L"c:\\program files\\windows nt\\accessories");

    AddSystemDirectory(L"c:\\program files (x86)");
    AddSystemDirectory(L"c:\\program files (x86)\\common files");
    AddSystemDirectory(L"c:\\program files (x86)\\common files\\system");
    AddSystemDirectory(L"c:\\program files (x86)\\common files\\system\\ado");
    AddSystemDirectory(L"c:\\program files (x86)\\internet explorer");
    AddSystemDirectory(L"c:\\program files (x86)\\microsoft");

    // ----------------------------------------------------------------
    // User profile (dynamic based on config userName)
    // ----------------------------------------------------------------
    AddSystemDirectory(L"c:\\users");
    AddSystemDirectory(L"c:\\users\\public");
    AddSystemDirectory(L"c:\\users\\default");

    std::wstring userRoot = L"c:\\users\\" + m_userName;
    AddSystemDirectory(userRoot);
    AddSystemDirectory(userRoot + L"\\desktop");
    AddSystemDirectory(userRoot + L"\\documents");
    AddSystemDirectory(userRoot + L"\\downloads");
    AddSystemDirectory(userRoot + L"\\pictures");
    AddSystemDirectory(userRoot + L"\\videos");
    AddSystemDirectory(userRoot + L"\\music");
    AddSystemDirectory(userRoot + L"\\favorites");
    AddSystemDirectory(userRoot + L"\\contacts");
    AddSystemDirectory(userRoot + L"\\links");
    AddSystemDirectory(userRoot + L"\\saved games");
    AddSystemDirectory(userRoot + L"\\searches");
    AddSystemDirectory(userRoot + L"\\appdata");
    AddSystemDirectory(userRoot + L"\\appdata\\local");
    AddSystemDirectory(userRoot + L"\\appdata\\local\\temp");
    AddSystemDirectory(userRoot + L"\\appdata\\local\\microsoft");
    AddSystemDirectory(userRoot + L"\\appdata\\local\\microsoft\\windows");
    AddSystemDirectory(userRoot + L"\\appdata\\local\\microsoft\\windows\\temporary internet files");
    AddSystemDirectory(userRoot + L"\\appdata\\local\\packages");
    AddSystemDirectory(userRoot + L"\\appdata\\locallow");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows\\start menu");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows\\recent");
    AddSystemDirectory(userRoot + L"\\appdata\\roaming\\microsoft\\windows\\templates");

    // ----------------------------------------------------------------
    // ProgramData
    // ----------------------------------------------------------------
    AddSystemDirectory(L"c:\\programdata");
    AddSystemDirectory(L"c:\\programdata\\microsoft");
    AddSystemDirectory(L"c:\\programdata\\microsoft\\windows");
    AddSystemDirectory(L"c:\\programdata\\microsoft\\windows\\start menu");
    AddSystemDirectory(L"c:\\programdata\\microsoft\\windows\\start menu\\programs");
    AddSystemDirectory(L"c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup");

    // ================================================================
    //  FILES — C:\Windows root executables and system files
    // ================================================================
    AddSystemFile(L"c:\\windows\\explorer.exe",   5 * MB + 120 * KB);
    AddSystemFile(L"c:\\windows\\notepad.exe",    201 * KB);
    AddSystemFile(L"c:\\windows\\regedit.exe",    402 * KB);
    AddSystemFile(L"c:\\windows\\write.exe",      11 * KB);
    AddSystemFile(L"c:\\windows\\hh.exe",         18 * KB);
    AddSystemFile(L"c:\\windows\\helppane.exe",   1 * MB + 40 * KB);
    AddSystemFile(L"c:\\windows\\splwow64.exe",   130 * KB);
    AddSystemFile(L"c:\\windows\\winhlp32.exe",   10 * KB);
    AddSystemFile(L"c:\\windows\\system.ini",     219,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\win.ini",         92);
    AddSystemFile(L"c:\\windows\\setupact.log",   300 * KB);
    AddSystemFile(L"c:\\windows\\bootstat.dat",   67 * KB,
                  FileAttr::Hidden | FileAttr::System);

    // Font files that malware sometimes enumerates to detect sandboxes
    AddSystemFile(L"c:\\windows\\fonts\\arial.ttf",       1 * MB);
    AddSystemFile(L"c:\\windows\\fonts\\arialbd.ttf",     780 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\ariali.ttf",      680 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\times.ttf",       850 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\timesbd.ttf",     780 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\cour.ttf",        700 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\calibri.ttf",     740 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\calibrib.ttf",    610 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\consola.ttf",     510 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\segoeui.ttf",    1200 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\segoeuib.ttf",   1000 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\tahoma.ttf",      700 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\verdana.ttf",     600 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\wingding.ttf",    250 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\symbol.ttf",      180 * KB);
    AddSystemFile(L"c:\\windows\\fonts\\webdings.ttf",    230 * KB);

    // ================================================================
    //  FILES — C:\Windows\System32  DLLs  (~100 entries)
    // ================================================================
    //
    // Compact helpers to keep the table readable.
    auto sys32 = [&](const wchar_t* name, uint64_t sz, uint32_t attr = FileAttr::Normal) {
        AddSystemFile(std::wstring(L"c:\\windows\\system32\\") + name, sz, attr);
    };

    // Core OS DLLs
    sys32(L"ntdll.dll",            2100 * KB);
    sys32(L"kernel32.dll",          800 * KB);
    sys32(L"kernelbase.dll",       3200 * KB);
    sys32(L"advapi32.dll",          700 * KB);
    sys32(L"user32.dll",           1700 * KB);
    sys32(L"gdi32.dll",             150 * KB);
    sys32(L"gdi32full.dll",        1100 * KB);
    sys32(L"ws2_32.dll",             90 * KB);
    sys32(L"wininet.dll",          1200 * KB);
    sys32(L"winhttp.dll",           600 * KB);
    sys32(L"shell32.dll",         22000 * KB);
    sys32(L"ole32.dll",            1500 * KB);
    sys32(L"oleaut32.dll",          800 * KB);
    sys32(L"comctl32.dll",         6000 * KB);
    sys32(L"msvcrt.dll",            800 * KB);
    sys32(L"crypt32.dll",          2800 * KB);
    sys32(L"secur32.dll",            50 * KB);
    sys32(L"shlwapi.dll",           350 * KB);
    sys32(L"urlmon.dll",           1400 * KB);
    sys32(L"rpcrt4.dll",           1300 * KB);
    sys32(L"sspicli.dll",           200 * KB);
    sys32(L"bcrypt.dll",            200 * KB);
    sys32(L"ncrypt.dll",            150 * KB);
    sys32(L"psapi.dll",              10 * KB);
    sys32(L"version.dll",            40 * KB);
    sys32(L"iphlpapi.dll",          200 * KB);
    sys32(L"dnsapi.dll",            300 * KB);
    sys32(L"netapi32.dll",          400 * KB);
    sys32(L"wintrust.dll",          400 * KB);
    sys32(L"setupapi.dll",         4500 * KB);

    // C Runtime / MSVC redist
    sys32(L"msvcp140.dll",          600 * KB);
    sys32(L"vcruntime140.dll",      100 * KB);
    sys32(L"vcruntime140_1.dll",     40 * KB);
    sys32(L"ucrtbase.dll",         1200 * KB);

    // .NET
    sys32(L"mscoree.dll",           500 * KB);
    sys32(L"clr.dll",              8000 * KB);
    sys32(L"mscorlib.ni.dll",     15000 * KB);

    // COM / Shell / UI
    sys32(L"combase.dll",          3500 * KB);
    sys32(L"sechost.dll",           600 * KB);
    sys32(L"profapi.dll",            80 * KB);
    sys32(L"cfgmgr32.dll",          300 * KB);
    sys32(L"powrprof.dll",          200 * KB);
    sys32(L"shcore.dll",            700 * KB);
    sys32(L"kernel.appcore.dll",     60 * KB);
    sys32(L"msctf.dll",            1500 * KB);
    sys32(L"uxtheme.dll",           700 * KB);
    sys32(L"dwmapi.dll",            150 * KB);
    sys32(L"imm32.dll",             200 * KB);
    sys32(L"normaliz.dll",            5 * KB);
    sys32(L"propsys.dll",          1500 * KB);
    sys32(L"clbcatq.dll",           350 * KB);

    // Crypto
    sys32(L"cryptbase.dll",          40 * KB);
    sys32(L"cryptsp.dll",           100 * KB);
    sys32(L"rsaenh.dll",            350 * KB);
    sys32(L"cryptnet.dll",          130 * KB);
    sys32(L"cryptdll.dll",           40 * KB);
    sys32(L"schannel.dll",          400 * KB);
    sys32(L"dpapi.dll",             100 * KB);
    sys32(L"msasn1.dll",             60 * KB);

    // Networking
    sys32(L"mswsock.dll",           350 * KB);
    sys32(L"nsi.dll",                30 * KB);
    sys32(L"winnsi.dll",             30 * KB);
    sys32(L"wsock32.dll",            20 * KB);
    sys32(L"fwpuclnt.dll",          400 * KB);
    sys32(L"firewallapi.dll",       800 * KB);

    // Security
    sys32(L"ntmarta.dll",           180 * KB);
    sys32(L"authz.dll",             200 * KB);
    sys32(L"samcli.dll",            100 * KB);
    sys32(L"samlib.dll",            130 * KB);
    sys32(L"wkscli.dll",             80 * KB);
    sys32(L"netutils.dll",           30 * KB);
    sys32(L"srvcli.dll",            150 * KB);

    // Misc
    sys32(L"wtsapi32.dll",           40 * KB);
    sys32(L"userenv.dll",           170 * KB);
    sys32(L"wevtapi.dll",           250 * KB);
    sys32(L"taskschd.dll",          400 * KB);
    sys32(L"oleacc.dll",            400 * KB);
    sys32(L"apphelp.dll",           800 * KB);
    sys32(L"sfc.dll",                10 * KB);
    sys32(L"sfc_os.dll",             60 * KB);
    sys32(L"msi.dll",              4000 * KB);
    sys32(L"wer.dll",               400 * KB);
    sys32(L"iertutil.dll",         2800 * KB);
    sys32(L"xmllite.dll",           250 * KB);
    sys32(L"dbghelp.dll",          1800 * KB);
    sys32(L"imagehlp.dll",           80 * KB);
    sys32(L"cabinet.dll",           100 * KB);
    sys32(L"wldap32.dll",           350 * KB);
    sys32(L"mpr.dll",               100 * KB);
    sys32(L"winmm.dll",             200 * KB);
    sys32(L"fltlib.dll",             40 * KB);
    sys32(L"gpapi.dll",             200 * KB);
    sys32(L"credui.dll",            250 * KB);
    sys32(L"coml2.dll",             500 * KB);
    sys32(L"msv1_0.dll",            350 * KB);
    sys32(L"ktmw32.dll",             30 * KB);
    sys32(L"windows.storage.dll",  7000 * KB);
    sys32(L"mfplat.dll",           1500 * KB);
    sys32(L"wintypes.dll",         1000 * KB);
    sys32(L"d3d11.dll",            2000 * KB);
    sys32(L"dxgi.dll",             1000 * KB);
    sys32(L"winsta.dll",             70 * KB);
    sys32(L"winspool.drv",          700 * KB);

    // Additional System32 DLLs — WinSock / HTTP / RPC layer
    sys32(L"webio.dll",             350 * KB);
    sys32(L"winrnr.dll",             25 * KB);
    sys32(L"dhcpcsvc.dll",          100 * KB);
    sys32(L"dhcpcsvc6.dll",          70 * KB);
    sys32(L"rasadhlp.dll",           20 * KB);
    sys32(L"FWPUCLNT.DLL",         400 * KB);

    // Additional System32 DLLs — Diagnostics / ETW
    sys32(L"wevtsvc.dll",           450 * KB);
    sys32(L"tdh.dll",               320 * KB);
    sys32(L"wmiutils.dll",          100 * KB);
    sys32(L"wbemcore.dll",         1100 * KB);
    sys32(L"wbemprox.dll",           40 * KB);
    sys32(L"wbemcomn.dll",          450 * KB);
    sys32(L"fastprox.dll",          900 * KB);

    // Additional System32 DLLs — Locale / NLS / Globalization
    sys32(L"nlsdata0000.dll",       200 * KB);
    sys32(L"C_1252.NLS",             66 * KB);
    sys32(L"locale.nls",           3200 * KB);
    sys32(L"sortdefault.nls",       900 * KB);
    sys32(L"KernelBase.dll.mui",    200 * KB);

    // Additional System32 DLLs — Task Scheduler / Services
    sys32(L"schedsvc.dll",          800 * KB);
    sys32(L"ubpm.dll",              700 * KB);
    sys32(L"es.dll",                350 * KB);
    sys32(L"eventlog.dll",          150 * KB);

    // Additional System32 DLLs — Security / Token
    sys32(L"wdigest.dll",           200 * KB);
    sys32(L"kerberos.dll",          800 * KB);
    sys32(L"lsasrv.dll",           1800 * KB);
    sys32(L"samsrv.dll",            700 * KB);
    sys32(L"logoncli.dll",          200 * KB);

    // System EXEs in System32
    sys32(L"ntoskrnl.exe",         11000 * KB, FileAttr::System);
    sys32(L"cmd.exe",                400 * KB);
    sys32(L"conhost.exe",            700 * KB);
    sys32(L"csrss.exe",              15 * KB);
    sys32(L"svchost.exe",            50 * KB);
    sys32(L"services.exe",          400 * KB);
    sys32(L"lsass.exe",              60 * KB);
    sys32(L"smss.exe",              150 * KB);
    sys32(L"wininit.exe",           400 * KB);
    sys32(L"winlogon.exe",          700 * KB);
    sys32(L"taskmgr.exe",          1200 * KB);
    sys32(L"rundll32.exe",           70 * KB);
    sys32(L"msiexec.exe",            60 * KB);
    sys32(L"reg.exe",                80 * KB);
    sys32(L"sc.exe",                 80 * KB);
    sys32(L"tasklist.exe",            80 * KB);
    sys32(L"taskkill.exe",            80 * KB);
    sys32(L"wbem\\wmic.exe",        500 * KB);
    sys32(L"powershell.exe",        450 * KB);
    sys32(L"attrib.exe",             20 * KB);
    sys32(L"certutil.exe",          1400 * KB);
    sys32(L"bitsadmin.exe",          200 * KB);
    sys32(L"mshta.exe",              14 * KB);
    sys32(L"regsvr32.exe",           20 * KB);
    sys32(L"cscript.exe",           170 * KB);
    sys32(L"wscript.exe",           170 * KB);
    sys32(L"dllhost.exe",            25 * KB);
    sys32(L"dwm.exe",               120 * KB);
    sys32(L"spoolsv.exe",            80 * KB);
    sys32(L"searchindexer.exe",     900 * KB);
    sys32(L"sihost.exe",            100 * KB);
    sys32(L"fontdrvhost.exe",        20 * KB);
    sys32(L"ctfmon.exe",             15 * KB);
    sys32(L"consent.exe",           200 * KB);

    // ================================================================
    //  FILES — C:\Windows\System32\drivers  (~20 entries)
    // ================================================================
    auto drv = [&](const wchar_t* name, uint64_t sz) {
        AddSystemFile(
            std::wstring(L"c:\\windows\\system32\\drivers\\") + name,
            sz, FileAttr::System);
    };

    drv(L"ntfs.sys",          2100 * KB);
    drv(L"tcpip.sys",         3000 * KB);
    drv(L"fltmgr.sys",         500 * KB);
    drv(L"ndis.sys",          1200 * KB);
    drv(L"disk.sys",           150 * KB);
    drv(L"volsnap.sys",        400 * KB);
    drv(L"classpnp.sys",       200 * KB);
    drv(L"partmgr.sys",        150 * KB);
    drv(L"mountmgr.sys",       100 * KB);
    drv(L"acpi.sys",           500 * KB);
    drv(L"pcw.sys",             50 * KB);
    drv(L"msrpc.sys",          350 * KB);
    drv(L"ksecdd.sys",         150 * KB);
    drv(L"cng.sys",            700 * KB);
    drv(L"ksecpkg.sys",        200 * KB);
    drv(L"npfs.sys",            50 * KB);
    drv(L"msfs.sys",            50 * KB);
    drv(L"tdx.sys",            150 * KB);
    drv(L"netbt.sys",          250 * KB);
    drv(L"afd.sys",            600 * KB);
    drv(L"http.sys",           1000 * KB);
    drv(L"volmgr.sys",         100 * KB);
    drv(L"wdf01000.sys",       800 * KB);
    drv(L"wdfldr.sys",         100 * KB);
    drv(L"fvevol.sys",         600 * KB);
    drv(L"rdyboost.sys",       250 * KB);
    drv(L"iorate.sys",          50 * KB);
    drv(L"storport.sys",       500 * KB);
    drv(L"stornvme.sys",       150 * KB);
    drv(L"clipsp.sys",         500 * KB);
    drv(L"dxgkrnl.sys",       3000 * KB);
    drv(L"watchdog.sys",        70 * KB);

    // ================================================================
    //  FILES — C:\Windows\SysWOW64  (32-bit mirrors, smaller sizes)
    // ================================================================
    auto wow64 = [&](const wchar_t* name, uint64_t sz) {
        AddSystemFile(
            std::wstring(L"c:\\windows\\syswow64\\") + name, sz);
    };

    wow64(L"ntdll.dll",           1700 * KB);
    wow64(L"kernel32.dll",         680 * KB);
    wow64(L"kernelbase.dll",      2600 * KB);
    wow64(L"advapi32.dll",         560 * KB);
    wow64(L"user32.dll",          1500 * KB);
    wow64(L"gdi32.dll",            120 * KB);
    wow64(L"ws2_32.dll",            75 * KB);
    wow64(L"shell32.dll",        20000 * KB);
    wow64(L"ole32.dll",           1300 * KB);
    wow64(L"oleaut32.dll",         660 * KB);
    wow64(L"msvcrt.dll",           660 * KB);
    wow64(L"crypt32.dll",         2400 * KB);
    wow64(L"rpcrt4.dll",          1100 * KB);
    wow64(L"shlwapi.dll",          280 * KB);
    wow64(L"combase.dll",         2900 * KB);
    wow64(L"sechost.dll",          480 * KB);
    wow64(L"ucrtbase.dll",        1000 * KB);
    wow64(L"msvcp140.dll",         480 * KB);
    wow64(L"vcruntime140.dll",      80 * KB);
    wow64(L"wininet.dll",         1000 * KB);
    wow64(L"winhttp.dll",          480 * KB);
    wow64(L"wintrust.dll",         320 * KB);
    wow64(L"setupapi.dll",        3600 * KB);
    wow64(L"bcrypt.dll",           160 * KB);
    wow64(L"ncrypt.dll",           120 * KB);
    wow64(L"sspicli.dll",          160 * KB);
    wow64(L"cryptbase.dll",         35 * KB);
    wow64(L"imm32.dll",            160 * KB);
    wow64(L"psapi.dll",              8 * KB);
    wow64(L"version.dll",           32 * KB);
    wow64(L"iphlpapi.dll",         160 * KB);
    wow64(L"dnsapi.dll",           240 * KB);
    wow64(L"netapi32.dll",         320 * KB);
    wow64(L"profapi.dll",           64 * KB);
    wow64(L"mswsock.dll",          280 * KB);
    wow64(L"wsock32.dll",           16 * KB);

    // ================================================================
    //  FILES — Program Files
    // ================================================================
    AddSystemFile(L"c:\\program files\\internet explorer\\iexplore.exe",
                  814 * KB);
    AddSystemFile(L"c:\\program files\\windows defender\\msmpeng.exe",
                  120 * KB, FileAttr::System);
    AddSystemFile(L"c:\\program files\\windows defender\\mpclient.dll",
                  5 * MB);
    AddSystemFile(L"c:\\program files\\windows defender\\mpcommu.dll",
                  350 * KB);
    AddSystemFile(L"c:\\program files\\windows defender\\mpsvc.dll",
                  800 * KB);
    AddSystemFile(L"c:\\program files\\windows defender\\mpengine.dll",
                  16 * MB, FileAttr::System);
    AddSystemFile(L"c:\\program files\\windows media player\\wmplayer.exe",
                  300 * KB);
    AddSystemFile(L"c:\\program files\\windows media player\\wmpnscfg.exe",
                  70 * KB);
    AddSystemFile(L"c:\\program files\\windows nt\\accessories\\wordpad.exe",
                  2 * MB);

    AddSystemFile(L"c:\\program files (x86)\\internet explorer\\iexplore.exe",
                  810 * KB);
    AddSystemFile(L"c:\\program files (x86)\\common files\\system\\ado\\msado15.dll",
                  200 * KB);

    // ================================================================
    //  FILES — Root-level system files (metadata only, no real content)
    // ================================================================
    AddSystemFile(L"c:\\pagefile.sys",  2 * GB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\hiberfil.sys",  4 * GB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\swapfile.sys",  256 * MB,
                  FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — User profile items that malware commonly checks/drops
    // ================================================================
    AddSystemFile(userRoot + L"\\desktop\\desktop.ini", 282,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(userRoot + L"\\documents\\desktop.ini", 402,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(userRoot + L"\\ntuser.dat", 40 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(userRoot + L"\\ntuser.dat.log1", 1 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(userRoot + L"\\ntuser.dat.log2", 1 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(userRoot + L"\\appdata\\local\\iconcache.db", 24 * MB,
                  FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — Windows\System32\config (registry hives)
    // ================================================================
    // Malware often checks for registry hive sizes to detect sandboxes.
    AddSystemFile(L"c:\\windows\\system32\\config\\system",    40 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\config\\software",  80 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\config\\sam",        1 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\config\\security",   1 * MB,
                  FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\config\\default",    1 * MB,
                  FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — PowerShell
    // ================================================================
    AddSystemFile(
        L"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        450 * KB);
    AddSystemFile(
        L"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell_ise.exe",
        520 * KB);
    AddSystemFile(
        L"c:\\windows\\system32\\windowspowershell\\v1.0\\system.management.automation.dll",
        8 * MB);

    // ================================================================
    //  FILES — WBEM (WMI — frequently used by malware for enumeration)
    // ================================================================
    AddSystemFile(L"c:\\windows\\system32\\wbem\\wmic.exe",      500 * KB);
    AddSystemFile(L"c:\\windows\\system32\\wbem\\wmiprvse.exe",  400 * KB);
    AddSystemFile(L"c:\\windows\\system32\\wbem\\repository\\objects.data",
                  50 * MB, FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\wbem\\repository\\index.btr",
                  600 * KB, FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\wbem\\repository\\mapping3.map",
                  1 * MB, FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — ProgramData
    // ================================================================
    AddSystemFile(
        L"c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\desktop.ini",
        174, FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — .NET Framework assemblies (malware using .NET Reflection)
    // ================================================================
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework\\v4.0.30319\\clr.dll",
        8000 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework\\v4.0.30319\\mscorlib.dll",
        5500 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework\\v4.0.30319\\system.dll",
        3600 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework\\v4.0.30319\\system.core.dll",
        1400 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\clr.dll",
        8200 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\mscorlib.dll",
        5700 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\system.dll",
        3800 * KB);
    AddSystemFile(
        L"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\system.core.dll",
        1500 * KB);

    // ================================================================
    //  FILES — INF files (hardware/driver configuration)
    // ================================================================
    AddSystemFile(L"c:\\windows\\inf\\setupapi.dev.log",  1 * MB);
    AddSystemFile(L"c:\\windows\\inf\\setupapi.app.log",  500 * KB);

    // ================================================================
    //  FILES — Windows security catalog files
    // ================================================================
    AddSystemFile(L"c:\\windows\\system32\\catroot\\{f750e6c3-38ee-11d1-85e5-00c04fc295ee}\\nt5.cat",
                  800 * KB, FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\catroot\\{f750e6c3-38ee-11d1-85e5-00c04fc295ee}\\nt5inf.cat",
                  200 * KB, FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\catroot2\\{f750e6c3-38ee-11d1-85e5-00c04fc295ee}\\catdb",
                  4 * MB, FileAttr::Hidden | FileAttr::System);
    AddSystemFile(L"c:\\windows\\system32\\catroot2\\{127d0a1d-4ef2-11d1-8608-00c04fc295ee}\\catdb",
                  2 * MB, FileAttr::Hidden | FileAttr::System);

    // ================================================================
    //  FILES — ETW / Event logs (malware checks these for timestamps)
    // ================================================================
    AddSystemFile(
        L"c:\\windows\\system32\\winevt\\logs\\application.evtx",
        20 * MB, FileAttr::System);
    AddSystemFile(
        L"c:\\windows\\system32\\winevt\\logs\\system.evtx",
        20 * MB, FileAttr::System);
    AddSystemFile(
        L"c:\\windows\\system32\\winevt\\logs\\security.evtx",
        128 * MB, FileAttr::System);
    AddSystemFile(
        L"c:\\windows\\system32\\winevt\\logs\\microsoft-windows-sysmon%4operational.evtx",
        30 * MB, FileAttr::System);
}

// ============================================================================
// OpenFile
// ============================================================================
//
// Implements Win32 CreateFile / NtCreateFile disposition semantics:
//
//   CreateNew (1)        — Fail if exists, create otherwise
//   CreateAlways (2)     — Truncate if exists, create if not
//   OpenExisting (3)     — Fail if not exists, open otherwise
//   OpenAlways (4)       — Open if exists, create if not
//   TruncateExisting (5) — Fail if not exists, truncate and open otherwise
//
// Returns a VFS file ID on success (not a guest HANDLE — the HandleTable
// layer wraps this in a typed handle).  Returns nullopt on failure.
//
// Newly created files are tracked as malware IOCs for post-emulation
// analysis.  Files are NOT created if the total entry count exceeds
// kMaxFileCount (10 000), preventing resource exhaustion attacks.

std::optional<uint32_t> VirtualFileSystem::OpenFile(
    std::wstring_view path,
    uint32_t access,
    uint32_t /*shareMode*/,
    uint32_t disposition) noexcept
{
    std::unique_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return std::nullopt;

    auto it = m_files.find(normalized);
    bool exists = (it != m_files.end());

    switch (disposition) {
        case CreateDisposition::CreateNew: {
            if (exists) return std::nullopt;

            if (m_files.size() >= kMaxFileCount) return std::nullopt;

            VirtualFileEntry entry;
            entry.name           = ExtractFileName(normalized);
            entry.fullPath       = normalized;
            entry.attributes     = FileAttr::Archive;
            entry.creationTime   = kSystemFileTime;
            entry.lastWriteTime  = kSystemFileTime;
            entry.lastAccessTime = kSystemFileTime;
            entry.isPrePopulated = false;

            it = m_files.emplace(normalized, std::move(entry)).first;
            m_malwareCreatedFiles.push_back(normalized);
            break;
        }

        case CreateDisposition::CreateAlways: {
            if (exists) {
                // Truncate existing content
                auto& entry = it->second;
                m_totalContentSize -= entry.content.size();
                entry.content.clear();
                entry.fileSize       = 0;
                entry.lastWriteTime  = kSystemFileTime;
                entry.isPrePopulated = false;
                m_malwareCreatedFiles.push_back(normalized);
            } else {
                if (m_files.size() >= kMaxFileCount) return std::nullopt;

                VirtualFileEntry entry;
                entry.name           = ExtractFileName(normalized);
                entry.fullPath       = normalized;
                entry.attributes     = FileAttr::Archive;
                entry.creationTime   = kSystemFileTime;
                entry.lastWriteTime  = kSystemFileTime;
                entry.lastAccessTime = kSystemFileTime;
                entry.isPrePopulated = false;

                it = m_files.emplace(normalized, std::move(entry)).first;
                m_malwareCreatedFiles.push_back(normalized);
            }
            break;
        }

        case CreateDisposition::OpenExisting: {
            if (!exists) return std::nullopt;
            break;
        }

        case CreateDisposition::OpenAlways: {
            if (!exists) {
                if (m_files.size() >= kMaxFileCount) return std::nullopt;

                VirtualFileEntry entry;
                entry.name           = ExtractFileName(normalized);
                entry.fullPath       = normalized;
                entry.attributes     = FileAttr::Archive;
                entry.creationTime   = kSystemFileTime;
                entry.lastWriteTime  = kSystemFileTime;
                entry.lastAccessTime = kSystemFileTime;
                entry.isPrePopulated = false;

                it = m_files.emplace(normalized, std::move(entry)).first;
                m_malwareCreatedFiles.push_back(normalized);
            }
            break;
        }

        case CreateDisposition::TruncateExisting: {
            if (!exists) return std::nullopt;

            auto& entry = it->second;
            m_totalContentSize -= entry.content.size();
            entry.content.clear();
            entry.fileSize       = 0;
            entry.lastWriteTime  = kSystemFileTime;
            break;
        }

        default:
            return std::nullopt;
    }

    // Create open-file state
    uint32_t fileId = m_nextFileId++;
    OpenFileState state;
    state.path        = normalized;
    state.access      = access;
    state.position    = 0;
    state.isDirectory = (it->second.attributes & FileAttr::Directory) != 0;

    m_openFiles.emplace(fileId, std::move(state));
    return fileId;
}

// ============================================================================
// CloseFile — Release an open file handle
// ============================================================================
//
// Removes the OpenFileState entry from the open-files map.
// Does NOT flush or sync any pending writes (all writes are synchronous
// in the VFS).  Returns false if the file ID was not found.

bool VirtualFileSystem::CloseFile(uint32_t fileId) noexcept {
    std::unique_lock lock(m_mutex);
    return m_openFiles.erase(fileId) > 0;
}

// ============================================================================
// ReadFile
// ============================================================================
//
// Five content paths (checked in order):
//
// 1. Real content (malware-written files): serves bytes from the content
//    vector, zero-fills beyond stored content up to fileSize.
//
// 2. Known system DLLs (ntdll.dll, kernel32.dll, etc.): generates a
//    4096-byte realistic PE image via GenerateRealisticContent() with
//    correct export directory, version resources, section table, and
//    profile-specific ImageBase/SizeOfImage.  Returns zeroes for the
//    remainder up to the file's declared size.
//
// 3. Unknown PE files (.dll, .exe, .sys, .drv): generates a 512-byte
//    generic PE stub with valid MZ/PE signatures, returns zeroes beyond.
//
// 4. Known non-PE files (hosts, system.ini, win.ini): returns static
//    file content matching a real Windows installation.
//
// 5. Other pre-populated files: returns zeroes.
//
// The read position is advanced by the number of bytes returned.
// Reading past EOF returns 0 bytes (no error).

uint32_t VirtualFileSystem::ReadFile(
    uint32_t fileId,
    uint8_t* buffer,
    uint32_t bytesToRead) noexcept
{
    if (!buffer || bytesToRead == 0) return 0;

    std::unique_lock lock(m_mutex);

    auto stateIt = m_openFiles.find(fileId);
    if (stateIt == m_openFiles.end()) return 0;

    auto& state = stateIt->second;

    auto fileIt = m_files.find(state.path);
    if (fileIt == m_files.end()) return 0;

    auto& entry = fileIt->second;

    if (state.isDirectory) return 0;

    uint64_t pos  = state.position;
    uint64_t size = entry.fileSize;
    if (pos >= size) return 0;

    uint64_t available = size - pos;
    uint32_t toRead = static_cast<uint32_t>(
        std::min<uint64_t>(bytesToRead, available));

    if (!entry.content.empty()) {
        // File has real content (malware-written or modified)
        uint32_t contentAvail = 0;
        if (pos < entry.content.size()) {
            contentAvail = static_cast<uint32_t>(
                std::min<uint64_t>(toRead, entry.content.size() - pos));
            std::memcpy(buffer, entry.content.data() + pos, contentAvail);
        }
        // Zero-fill beyond stored content up to fileSize
        if (contentAvail < toRead) {
            std::memset(buffer + contentAvail, 0, toRead - contentAvail);
        }
    } else if (entry.isPrePopulated && IsPEExtension(entry.fullPath)) {
        // --- Realistic DLL content for known system DLLs ---
        auto* dllProfile = GetDLLProfile(entry.fullPath);
        if (dllProfile) {
            bool inWow64 = entry.fullPath.find(L"syswow64") != std::wstring::npos;
            auto realistic = GenerateRealisticContent(*dllProfile, !inWow64);

            uint32_t realRead = 0;
            if (pos < realistic.size()) {
                realRead = static_cast<uint32_t>(
                    std::min<uint64_t>(toRead, realistic.size() - pos));
                std::memcpy(buffer, realistic.data() + pos, realRead);
            }
            if (realRead < toRead) {
                std::memset(buffer + realRead, 0, toRead - realRead);
            }
        } else {
            // Fall through to generic PE stub for unknown DLLs
            bool inWow64 = entry.fullPath.find(L"syswow64") != std::wstring::npos;
            bool isDll   = !entry.fullPath.ends_with(L".exe");
            auto stub    = GeneratePEStub(isDll, !inWow64);

            uint32_t stubRead = 0;
            if (pos < stub.size()) {
                stubRead = static_cast<uint32_t>(
                    std::min<uint64_t>(toRead, stub.size() - pos));
                std::memcpy(buffer, stub.data() + pos, stubRead);
            }
            if (stubRead < toRead) {
                std::memset(buffer + stubRead, 0, toRead - stubRead);
            }
        }
    } else if (entry.isPrePopulated) {
        // --- Static file content for known non-PE files ---
        auto staticContent = GetStaticFileContent(entry.fullPath);
        if (!staticContent.empty()) {
            uint32_t staticRead = 0;
            if (pos < staticContent.size()) {
                staticRead = static_cast<uint32_t>(
                    std::min<uint64_t>(toRead, staticContent.size() - pos));
                std::memcpy(buffer, staticContent.data() + pos, staticRead);
            }
            if (staticRead < toRead) {
                std::memset(buffer + staticRead, 0, toRead - staticRead);
            }
        } else {
            // Non-PE pre-populated files with no known content → zeroes
            std::memset(buffer, 0, toRead);
        }
    } else {
        std::memset(buffer, 0, toRead);
    }

    state.position += toRead;
    return toRead;
}

// ============================================================================
// WriteFile
// ============================================================================
//
// Stores content bytes into the file's content vector and advances the
// write position.  Enforces two caps:
//
//   - Per-file cap:  64 MB (kMaxPerFileContent)
//   - Total VFS cap: 256 MB (kMaxTotalContent) across all file content
//
// These caps prevent a malicious sample from exhausting host memory by
// writing very large files or many small files inside the emulation
// session.
//
// On the first write to a pre-populated system file, the entry is
// converted from metadata-only to mutable content storage and marked
// as malware-modified for IOC tracking.
//
// Access control: the file must have been opened with GENERIC_WRITE or
// GENERIC_ALL access.  Writes to directories are silently rejected.

uint32_t VirtualFileSystem::WriteFile(
    uint32_t fileId,
    const uint8_t* buffer,
    uint32_t bytesToWrite) noexcept
{
    if (!buffer || bytesToWrite == 0) return 0;

    std::unique_lock lock(m_mutex);

    auto stateIt = m_openFiles.find(fileId);
    if (stateIt == m_openFiles.end()) return 0;

    auto& state = stateIt->second;

    if (!(state.access & FileAccess::Write) &&
        !(state.access & FileAccess::All)) {
        return 0;
    }

    auto fileIt = m_files.find(state.path);
    if (fileIt == m_files.end()) return 0;

    auto& entry = fileIt->second;

    if (state.isDirectory) return 0;

    // Determine the required content size after this write
    uint64_t endPos = state.position + bytesToWrite;

    // Per-file content cap
    if (endPos > kMaxPerFileContent) {
        if (state.position >= kMaxPerFileContent) return 0;
        bytesToWrite = static_cast<uint32_t>(kMaxPerFileContent - state.position);
        endPos = kMaxPerFileContent;
    }

    // Total VFS content cap
    uint64_t currentEntrySize = entry.content.size();
    uint64_t newEntrySize     = std::max<uint64_t>(currentEntrySize, endPos);
    uint64_t growth           = newEntrySize - currentEntrySize;

    if (growth > 0 && m_totalContentSize + growth > kMaxTotalContent) {
        // Clamp the write to what fits within the global cap
        uint64_t allowable = kMaxTotalContent - m_totalContentSize;
        if (allowable == 0) return 0;
        uint64_t maxEnd = currentEntrySize + allowable;
        if (endPos > maxEnd) {
            if (state.position >= maxEnd) return 0;
            bytesToWrite = static_cast<uint32_t>(maxEnd - state.position);
            endPos = state.position + bytesToWrite;
            newEntrySize = std::max<uint64_t>(currentEntrySize, endPos);
            growth = newEntrySize - currentEntrySize;
        }
    }

    // Convert pre-populated file to mutable content on first write
    if (entry.isPrePopulated) {
        entry.isPrePopulated = false;
    }

    // Grow the content vector if needed
    if (newEntrySize > currentEntrySize) {
        entry.content.resize(static_cast<size_t>(newEntrySize), 0);
        m_totalContentSize += growth;
    }

    // Write data
    std::memcpy(entry.content.data() + state.position, buffer, bytesToWrite);

    state.position = state.position + bytesToWrite;

    // Update file size metadata if the write extended the file
    if (endPos > entry.fileSize) {
        entry.fileSize = endPos;
    }
    entry.lastWriteTime = kSystemFileTime;

    // Track as malware-modified if not already tracked
    auto& created = m_malwareCreatedFiles;
    if (std::find(created.begin(), created.end(), state.path) == created.end()) {
        created.push_back(state.path);
    }

    return bytesToWrite;
}

// ============================================================================
// SetFilePointer
// ============================================================================
//
// Moves the file read/write position.  Supports all three origins:
//   - Begin:   newPos = distance
//   - Current: newPos = position + distance
//   - End:     newPos = fileSize  + distance  (distance typically negative)
//
// Returns the new absolute position on success, -1 on error.
// Setting position beyond EOF is allowed (sparse write semantics).

int64_t VirtualFileSystem::SetFilePointer(
    uint32_t fileId,
    int64_t distance,
    SeekOrigin origin) noexcept
{
    std::unique_lock lock(m_mutex);

    auto stateIt = m_openFiles.find(fileId);
    if (stateIt == m_openFiles.end()) return -1;

    auto& state = stateIt->second;

    auto fileIt = m_files.find(state.path);
    if (fileIt == m_files.end()) return -1;

    int64_t newPos = 0;

    switch (origin) {
        case SeekOrigin::Begin:
            newPos = distance;
            break;

        case SeekOrigin::Current:
            newPos = static_cast<int64_t>(state.position) + distance;
            break;

        case SeekOrigin::End:
            newPos = static_cast<int64_t>(fileIt->second.fileSize) + distance;
            break;

        default:
            return -1;
    }

    if (newPos < 0) return -1;

    state.position = static_cast<uint64_t>(newPos);
    return newPos;
}

// ============================================================================
// GetFileSize — Query the logical file size for an open handle
// ============================================================================
//
// Returns the declared fileSize from the VirtualFileEntry metadata.
// For pre-populated system files this is the realistic Windows file
// size; for malware-created files it reflects writes performed so far.

std::optional<uint64_t> VirtualFileSystem::GetFileSize(uint32_t fileId) const noexcept {
    std::shared_lock lock(m_mutex);

    auto stateIt = m_openFiles.find(fileId);
    if (stateIt == m_openFiles.end()) return std::nullopt;

    auto fileIt = m_files.find(stateIt->second.path);
    if (fileIt == m_files.end()) return std::nullopt;

    return fileIt->second.fileSize;
}

// ============================================================================
// DeleteFile
// ============================================================================
//
// Removes a file from the virtual filesystem.  Constraints:
//   - Pre-populated system files CANNOT be deleted (realistic behavior;
//     Windows protects system files via WFP/WRP).
//   - Directories cannot be deleted through this API (use RemoveDirectory).
//   - Deleted files are recorded in m_malwareDeletedFiles for IOC tracking.
//   - Content memory is reclaimed from the total content budget.

bool VirtualFileSystem::DeleteFile(std::wstring_view path) noexcept {
    std::unique_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return false;

    auto it = m_files.find(normalized);
    if (it == m_files.end()) return false;

    // Block deletion of pre-populated system files (realistic behavior)
    if (it->second.isPrePopulated) return false;

    // Cannot delete directories through DeleteFile
    if (it->second.attributes & FileAttr::Directory) return false;

    // Track for IOC
    m_malwareDeletedFiles.push_back(normalized);

    // Reclaim content memory
    m_totalContentSize -= it->second.content.size();

    m_files.erase(it);
    return true;
}

// ============================================================================
// MoveFile
// ============================================================================
//
// Renames or moves a file within the VFS.  Constraints:
//   - Pre-populated system files cannot be moved (Windows protection).
//   - Destination must not already exist (no overwrite semantics).
//   - The move is tracked as a malware IOC (new path recorded).
//   - Directory moves are supported (the entry is just re-keyed).

bool VirtualFileSystem::MoveFile(
    std::wstring_view oldPath,
    std::wstring_view newPath) noexcept
{
    std::unique_lock lock(m_mutex);

    std::wstring oldNorm = NormalizePath(oldPath);
    std::wstring newNorm = NormalizePath(newPath);
    if (oldNorm.empty() || newNorm.empty()) return false;

    auto srcIt = m_files.find(oldNorm);
    if (srcIt == m_files.end()) return false;

    // Block renaming pre-populated system files
    if (srcIt->second.isPrePopulated) return false;

    // Destination must not exist
    if (m_files.count(newNorm) > 0) return false;

    if (m_files.size() >= kMaxFileCount) return false;

    // Move the entry
    VirtualFileEntry entry = std::move(srcIt->second);
    m_files.erase(srcIt);

    entry.name     = ExtractFileName(newNorm);
    entry.fullPath = newNorm;
    entry.lastWriteTime = kSystemFileTime;

    m_files.emplace(newNorm, std::move(entry));

    // Track for IOC
    m_malwareCreatedFiles.push_back(newNorm);

    return true;
}

// ============================================================================
// CopyFile
// ============================================================================
//
// Creates a deep copy of a source file at a new destination path.
//   - Destination must not already exist.
//   - Content bytes are duplicated (counted against total VFS cap).
//   - The copied file is marked as non-pre-populated and tracked for IOC.

bool VirtualFileSystem::CopyFile(
    std::wstring_view srcPath,
    std::wstring_view dstPath) noexcept
{
    std::unique_lock lock(m_mutex);

    std::wstring srcNorm = NormalizePath(srcPath);
    std::wstring dstNorm = NormalizePath(dstPath);
    if (srcNorm.empty() || dstNorm.empty()) return false;

    auto srcIt = m_files.find(srcNorm);
    if (srcIt == m_files.end()) return false;

    if (m_files.count(dstNorm) > 0) return false;

    if (m_files.size() >= kMaxFileCount) return false;

    // Check total content cap for the copy
    uint64_t contentBytes = srcIt->second.content.size();
    if (contentBytes > 0 && m_totalContentSize + contentBytes > kMaxTotalContent) {
        return false;
    }

    VirtualFileEntry entry = srcIt->second;  // Deep copy
    entry.name         = ExtractFileName(dstNorm);
    entry.fullPath     = dstNorm;
    entry.isPrePopulated = false;
    entry.lastWriteTime  = kSystemFileTime;

    m_totalContentSize += entry.content.size();
    m_files.emplace(dstNorm, std::move(entry));

    // Track for IOC
    m_malwareCreatedFiles.push_back(dstNorm);

    return true;
}

// ============================================================================
// Exists — Check if a path resolves to any entry in the VFS
// ============================================================================
//
// Normalizes the input path and performs a case-insensitive lookup.
// Returns true for both files and directories.

bool VirtualFileSystem::Exists(std::wstring_view path) const noexcept {
    std::shared_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return false;

    return m_files.count(normalized) > 0;
}

// ============================================================================
// GetAttributes — Return FILE_ATTRIBUTE_* flags for a path
// ============================================================================
//
// Returns the attribute bitmask on success, nullopt if the path does
// not exist.  This maps to GetFileAttributesW in the WinAPI layer.

std::optional<uint32_t> VirtualFileSystem::GetAttributes(
    std::wstring_view path) const noexcept
{
    std::shared_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return std::nullopt;

    auto it = m_files.find(normalized);
    if (it == m_files.end()) return std::nullopt;

    return it->second.attributes;
}

// ============================================================================
// GetFileInfo — Return a full metadata snapshot for a path
// ============================================================================
//
// Returns a copy of the VirtualFileEntry WITHOUT the content vector
// (which may be very large for malware-written files).  Callers that
// need content should use ReadFile through an open handle.

std::optional<VirtualFileEntry> VirtualFileSystem::GetFileInfo(
    std::wstring_view path) const noexcept
{
    std::shared_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return std::nullopt;

    auto it = m_files.find(normalized);
    if (it == m_files.end()) return std::nullopt;

    // Return a copy without the content vector (expensive to copy)
    VirtualFileEntry result;
    result.name           = it->second.name;
    result.fullPath       = it->second.fullPath;
    result.attributes     = it->second.attributes;
    result.fileSize       = it->second.fileSize;
    result.creationTime   = it->second.creationTime;
    result.lastWriteTime  = it->second.lastWriteTime;
    result.lastAccessTime = it->second.lastAccessTime;
    result.isPrePopulated = it->second.isPrePopulated;
    // content intentionally left empty for performance

    return result;
}

// ============================================================================
// CreateDirectory
// ============================================================================
//
// Creates a new empty directory.  The parent directory must already exist
// (no recursive creation).  Directories created by the emulated process
// are NOT marked as pre-populated, allowing them to be deleted/renamed.

bool VirtualFileSystem::CreateDirectory(std::wstring_view path) noexcept {
    std::unique_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(path);
    if (normalized.empty()) return false;

    // Already exists
    if (m_files.count(normalized) > 0) return false;

    if (m_files.size() >= kMaxFileCount) return false;

    // Verify parent directory exists
    auto lastSep = normalized.rfind(L'\\');
    if (lastSep != std::wstring::npos && lastSep > 2) {
        std::wstring parentPath = normalized.substr(0, lastSep);
        auto parentIt = m_files.find(parentPath);
        if (parentIt == m_files.end()) return false;
        if (!(parentIt->second.attributes & FileAttr::Directory)) return false;
    }

    VirtualFileEntry entry;
    entry.name           = ExtractFileName(normalized);
    entry.fullPath       = normalized;
    entry.attributes     = FileAttr::Directory;
    entry.creationTime   = kSystemFileTime;
    entry.lastWriteTime  = kSystemFileTime;
    entry.lastAccessTime = kSystemFileTime;
    entry.isPrePopulated = false;

    m_files.emplace(std::move(normalized), std::move(entry));

    return true;
}

// ============================================================================
// FindFirst / FindNext / FindClose — Directory Enumeration
// ============================================================================
//
// Implements the Windows FindFirstFile / FindNextFile enumeration model.
//
// FindFirst:
//   1. Normalizes the search pattern (e.g., "C:\Windows\System32\*.dll")
//   2. Splits into directory path + wildcard component
//   3. Verifies the directory exists
//   4. Scans the sorted map using lower_bound for an efficient prefix
//      walk, filtering direct children that match the wildcard
//   5. Snapshots the full result set (insulates from concurrent mutations)
//   6. Returns the first entry and a find-handle ID
//
// FindNext:
//   Advances the cursor in the snapshot, returning the next entry.
//
// FindClose:
//   Releases the snapshot and reclaims memory.

std::optional<uint32_t> VirtualFileSystem::FindFirst(
    std::wstring_view pattern,
    DirectoryEntry& firstEntry) noexcept
{
    std::unique_lock lock(m_mutex);

    std::wstring normalized = NormalizePath(pattern);
    if (normalized.empty()) return std::nullopt;

    // Split into directory path and wildcard component
    auto lastSep = normalized.rfind(L'\\');
    std::wstring dirPath;
    std::wstring wildcard;

    if (lastSep != std::wstring::npos) {
        dirPath  = normalized.substr(0, lastSep);
        wildcard = normalized.substr(lastSep + 1);
    } else {
        // Bare wildcard — search in current directory (System32)
        dirPath  = L"c:\\windows\\system32";
        wildcard = normalized;
    }

    // Verify the directory exists
    auto dirIt = m_files.find(dirPath);
    if (dirIt == m_files.end()) return std::nullopt;
    if (!(dirIt->second.attributes & FileAttr::Directory)) return std::nullopt;

    // Enumerate direct children matching the wildcard
    std::wstring prefix = dirPath + L"\\";
    std::vector<DirectoryEntry> results;

    auto it = m_files.lower_bound(prefix);
    while (it != m_files.end()) {
        // Check prefix match
        if (it->first.size() <= prefix.size() ||
            it->first.compare(0, prefix.size(), prefix) != 0) {
            break;
        }

        // Verify direct child (no additional backslash after prefix)
        auto rest = std::wstring_view(it->first).substr(prefix.size());
        if (rest.find(L'\\') != std::wstring_view::npos) {
            ++it;
            continue;
        }

        // Apply wildcard filter
        if (WildcardMatch(wildcard, rest)) {
            DirectoryEntry de;
            de.name           = it->second.name;
            de.attributes     = it->second.attributes;
            de.fileSize       = it->second.fileSize;
            de.creationTime   = it->second.creationTime;
            de.lastWriteTime  = it->second.lastWriteTime;
            de.lastAccessTime = it->second.lastAccessTime;
            results.push_back(std::move(de));
        }

        ++it;
    }

    if (results.empty()) return std::nullopt;

    // Snapshot the first entry for the caller
    firstEntry = results[0];

    // Store find state
    uint32_t findId = m_nextFindId++;
    FindState fs;
    fs.entries      = std::move(results);
    fs.currentIndex = 1;  // Next call returns index 1

    m_findHandles.emplace(findId, std::move(fs));
    return findId;
}

bool VirtualFileSystem::FindNext(
    uint32_t findId,
    DirectoryEntry& nextEntry) noexcept
{
    std::unique_lock lock(m_mutex);

    auto it = m_findHandles.find(findId);
    if (it == m_findHandles.end()) return false;

    auto& fs = it->second;
    if (fs.currentIndex >= fs.entries.size()) return false;

    nextEntry = fs.entries[fs.currentIndex];
    ++fs.currentIndex;
    return true;
}

void VirtualFileSystem::FindClose(uint32_t findId) noexcept {
    std::unique_lock lock(m_mutex);
    m_findHandles.erase(findId);
}

// ============================================================================
// GetTempPath — Returns the emulated user's Temp directory
// ============================================================================
//
// Maps to GetTempPathW.  Returns mixed-case path matching Windows
// convention (uppercase drive letter, original case for username).
// Malware commonly calls this to determine a drop location.

std::wstring VirtualFileSystem::GetTempPath() const noexcept {
    std::shared_lock lock(m_mutex);

    if (m_userName.empty()) {
        return L"C:\\Users\\Default\\AppData\\Local\\Temp\\";
    }
    // Return mixed-case path (as Windows would)
    return L"C:\\Users\\" + m_userName + L"\\AppData\\Local\\Temp\\";
}

// ============================================================================
// IOC Tracking Accessors
// ============================================================================
//
// These methods return a snapshot of the IOC lists built during emulation.
// The behavior analysis pipeline harvests these after the session to:
//   - Identify malware drop paths (GetMalwareCreatedFiles)
//   - Detect file-system cleanup / evidence destruction (GetMalwareDeletedFiles)
//
// Both return copies under a shared_lock for thread safety.

std::vector<std::wstring> VirtualFileSystem::GetMalwareCreatedFiles() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_malwareCreatedFiles;
}

std::vector<std::wstring> VirtualFileSystem::GetMalwareDeletedFiles() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_malwareDeletedFiles;
}

} // namespace Phantom::VirtualOS
