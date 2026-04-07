/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SystemDLLContent.hpp — Realistic system DLL PE content generation
 *
 * Generates structurally valid PE images for known Windows system DLLs,
 * including correct export directories, version resources, section tables,
 * and file metadata.  Defeats malware anti-evasion checks that validate
 * PE header layout, export tables, and file sizes of loaded system DLLs.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace Phantom::VirtualOS {

// ============================================================================
// DLL Export Entry — A single exported function name + ordinal
// ============================================================================

struct DLLExportEntry {
    const char* name;
    uint16_t    ordinal;
    uint32_t    rva;
};

// ============================================================================
// DLL Content Profile — Metadata describing a known system DLL
// ============================================================================

struct DLLContentProfile {
    const wchar_t*         dllName;
    uint64_t               realFileSize;
    uint32_t               characteristics;
    uint32_t               timeDateStamp;
    uint64_t               imageBase;
    uint32_t               sizeOfImage;
    uint32_t               checksum;
    const DLLExportEntry*  exports;
    uint32_t               exportCount;
    uint16_t               majorVersion;
    uint16_t               minorVersion;
    uint16_t               buildNumber;
};

// ============================================================================
// Public API
// ============================================================================

/// Generate a realistic 4096-byte PE image for the given DLL profile.
/// Includes DOS header, PE signature, COFF header, optional header with
/// correct ImageBase/SizeOfImage, 5 section headers (.text, .rdata, .data,
/// .rsrc, .reloc), export directory with real export names, and a version
/// resource block.  The caller zero-fills from 4096 up to realFileSize.
[[nodiscard]] std::vector<uint8_t> GenerateRealisticContent(
    const DLLContentProfile& profile, bool is64bit) noexcept;

/// Look up the profile for a known Windows system DLL by filename.
/// Returns nullptr if the DLL is not in the known-profile database.
[[nodiscard]] const DLLContentProfile* GetDLLProfile(
    std::wstring_view dllName) noexcept;

/// Return static file content for known non-PE system files
/// (hosts, system.ini, win.ini).  Returns empty vector if unknown.
[[nodiscard]] std::vector<uint8_t> GetStaticFileContent(
    std::wstring_view path) noexcept;

} // namespace Phantom::VirtualOS
