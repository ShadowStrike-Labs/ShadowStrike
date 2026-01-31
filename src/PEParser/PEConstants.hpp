#pragma once
/**
 * @file PEConstants.hpp
 * @brief PE (Portable Executable) format constants and security limits.
 *
 * Defines all PE magic numbers, flags, and security-critical limits
 * for safe parsing of potentially hostile PE files.
 *
 * @note All limits are carefully chosen to prevent DoS attacks while
 *       supporting legitimate PE files.
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>

namespace ShadowStrike {
namespace PEParser {

// ============================================================================
// DOS Header Constants
// ============================================================================

/// DOS signature "MZ" (little-endian)
inline constexpr uint16_t DOS_SIGNATURE = 0x5A4D;

/// Minimum valid e_lfanew offset (past DOS header)
inline constexpr int32_t MIN_LFANEW = 0x40;

/// Maximum e_lfanew to prevent scanning entire large files
inline constexpr int32_t MAX_LFANEW = 0x10000000; // 256MB

// ============================================================================
// NT Headers Constants
// ============================================================================

/// PE signature "PE\0\0" (little-endian)
inline constexpr uint32_t NT_SIGNATURE = 0x00004550;

/// Optional header magic for PE32
inline constexpr uint16_t PE32_MAGIC = 0x10B;

/// Optional header magic for PE32+
inline constexpr uint16_t PE64_MAGIC = 0x20B;

/// ROM image magic (rarely used)
inline constexpr uint16_t ROM_MAGIC = 0x107;

// ============================================================================
// Machine Types
// ============================================================================

namespace Machine {
    inline constexpr uint16_t UNKNOWN     = 0x0000;
    inline constexpr uint16_t TARGET_HOST = 0x0001;  // Host machine (useful for WoW64)
    inline constexpr uint16_t I386        = 0x014C;  // Intel 386+
    inline constexpr uint16_t R3000       = 0x0162;  // MIPS little-endian
    inline constexpr uint16_t R4000       = 0x0166;  // MIPS little-endian
    inline constexpr uint16_t R10000      = 0x0168;  // MIPS little-endian
    inline constexpr uint16_t WCEMIPSV2   = 0x0169;  // MIPS little-endian WCE v2
    inline constexpr uint16_t ALPHA       = 0x0184;  // Alpha_AXP
    inline constexpr uint16_t SH3         = 0x01A2;  // SH3 little-endian
    inline constexpr uint16_t SH3DSP      = 0x01A3;  // SH3DSP
    inline constexpr uint16_t SH3E        = 0x01A4;  // SH3E little-endian
    inline constexpr uint16_t SH4         = 0x01A6;  // SH4 little-endian
    inline constexpr uint16_t SH5         = 0x01A8;  // SH5
    inline constexpr uint16_t ARM         = 0x01C0;  // ARM little-endian
    inline constexpr uint16_t THUMB       = 0x01C2;  // ARM Thumb
    inline constexpr uint16_t ARMNT       = 0x01C4;  // ARM Thumb-2 (Windows RT)
    inline constexpr uint16_t AM33        = 0x01D3;  // Matsushita AM33
    inline constexpr uint16_t POWERPC     = 0x01F0;  // PowerPC little-endian
    inline constexpr uint16_t POWERPCFP   = 0x01F1;  // PowerPC with FP
    inline constexpr uint16_t IA64        = 0x0200;  // Intel Itanium
    inline constexpr uint16_t MIPS16      = 0x0266;  // MIPS16
    inline constexpr uint16_t ALPHA64     = 0x0284;  // ALPHA64/AXP64
    inline constexpr uint16_t MIPSFPU     = 0x0366;  // MIPS with FPU
    inline constexpr uint16_t MIPSFPU16   = 0x0466;  // MIPS16 with FPU
    inline constexpr uint16_t TRICORE     = 0x0520;  // Infineon
    inline constexpr uint16_t CEF         = 0x0CEF;  // CEF
    inline constexpr uint16_t EBC         = 0x0EBC;  // EFI Byte Code
    inline constexpr uint16_t AMD64       = 0x8664;  // AMD64 (x64)
    inline constexpr uint16_t M32R        = 0x9041;  // M32R little-endian
    inline constexpr uint16_t ARM64       = 0xAA64;  // ARM64
    inline constexpr uint16_t CEE         = 0xC0EE;  // CEE
} // namespace Machine

// ============================================================================
// File Header Characteristics
// ============================================================================

namespace FileCharacteristics {
    inline constexpr uint16_t RELOCS_STRIPPED         = 0x0001;
    inline constexpr uint16_t EXECUTABLE_IMAGE        = 0x0002;
    inline constexpr uint16_t LINE_NUMS_STRIPPED      = 0x0004;
    inline constexpr uint16_t LOCAL_SYMS_STRIPPED     = 0x0008;
    inline constexpr uint16_t AGGRESSIVE_WS_TRIM      = 0x0010;  // Obsolete
    inline constexpr uint16_t LARGE_ADDRESS_AWARE     = 0x0020;
    inline constexpr uint16_t RESERVED_0040           = 0x0040;
    inline constexpr uint16_t BYTES_REVERSED_LO       = 0x0080;  // Obsolete
    inline constexpr uint16_t MACHINE_32BIT           = 0x0100;
    inline constexpr uint16_t DEBUG_STRIPPED          = 0x0200;
    inline constexpr uint16_t REMOVABLE_RUN_FROM_SWAP = 0x0400;
    inline constexpr uint16_t NET_RUN_FROM_SWAP       = 0x0800;
    inline constexpr uint16_t SYSTEM_FILE             = 0x1000;
    inline constexpr uint16_t DLL                     = 0x2000;
    inline constexpr uint16_t UP_SYSTEM_ONLY          = 0x4000;
    inline constexpr uint16_t BYTES_REVERSED_HI       = 0x8000;  // Obsolete
} // namespace FileCharacteristics

// ============================================================================
// Section Characteristics
// ============================================================================

namespace SectionCharacteristics {
    inline constexpr uint32_t TYPE_NO_PAD            = 0x00000008;
    inline constexpr uint32_t CNT_CODE               = 0x00000020;
    inline constexpr uint32_t CNT_INITIALIZED_DATA   = 0x00000040;
    inline constexpr uint32_t CNT_UNINITIALIZED_DATA = 0x00000080;
    inline constexpr uint32_t LNK_OTHER              = 0x00000100;
    inline constexpr uint32_t LNK_INFO               = 0x00000200;
    inline constexpr uint32_t LNK_REMOVE             = 0x00000800;
    inline constexpr uint32_t LNK_COMDAT             = 0x00001000;
    inline constexpr uint32_t GPREL                  = 0x00008000;
    inline constexpr uint32_t MEM_PURGEABLE          = 0x00020000;
    inline constexpr uint32_t MEM_16BIT              = 0x00020000;
    inline constexpr uint32_t MEM_LOCKED             = 0x00040000;
    inline constexpr uint32_t MEM_PRELOAD            = 0x00080000;
    inline constexpr uint32_t ALIGN_1BYTES           = 0x00100000;
    inline constexpr uint32_t ALIGN_2BYTES           = 0x00200000;
    inline constexpr uint32_t ALIGN_4BYTES           = 0x00300000;
    inline constexpr uint32_t ALIGN_8BYTES           = 0x00400000;
    inline constexpr uint32_t ALIGN_16BYTES          = 0x00500000;
    inline constexpr uint32_t ALIGN_32BYTES          = 0x00600000;
    inline constexpr uint32_t ALIGN_64BYTES          = 0x00700000;
    inline constexpr uint32_t ALIGN_128BYTES         = 0x00800000;
    inline constexpr uint32_t ALIGN_256BYTES         = 0x00900000;
    inline constexpr uint32_t ALIGN_512BYTES         = 0x00A00000;
    inline constexpr uint32_t ALIGN_1024BYTES        = 0x00B00000;
    inline constexpr uint32_t ALIGN_2048BYTES        = 0x00C00000;
    inline constexpr uint32_t ALIGN_4096BYTES        = 0x00D00000;
    inline constexpr uint32_t ALIGN_8192BYTES        = 0x00E00000;
    inline constexpr uint32_t ALIGN_MASK             = 0x00F00000;
    inline constexpr uint32_t LNK_NRELOC_OVFL        = 0x01000000;
    inline constexpr uint32_t MEM_DISCARDABLE        = 0x02000000;
    inline constexpr uint32_t MEM_NOT_CACHED         = 0x04000000;
    inline constexpr uint32_t MEM_NOT_PAGED          = 0x08000000;
    inline constexpr uint32_t MEM_SHARED             = 0x10000000;
    inline constexpr uint32_t MEM_EXECUTE            = 0x20000000;
    inline constexpr uint32_t MEM_READ               = 0x40000000;
    inline constexpr uint32_t MEM_WRITE              = 0x80000000;
} // namespace SectionCharacteristics

// ============================================================================
// Subsystem Types
// ============================================================================

namespace Subsystem {
    inline constexpr uint16_t UNKNOWN                  = 0;
    inline constexpr uint16_t NATIVE                   = 1;
    inline constexpr uint16_t WINDOWS_GUI              = 2;
    inline constexpr uint16_t WINDOWS_CUI              = 3;
    inline constexpr uint16_t OS2_CUI                  = 5;
    inline constexpr uint16_t POSIX_CUI                = 7;
    inline constexpr uint16_t NATIVE_WINDOWS           = 8;
    inline constexpr uint16_t WINDOWS_CE_GUI           = 9;
    inline constexpr uint16_t EFI_APPLICATION          = 10;
    inline constexpr uint16_t EFI_BOOT_SERVICE_DRIVER  = 11;
    inline constexpr uint16_t EFI_RUNTIME_DRIVER       = 12;
    inline constexpr uint16_t EFI_ROM                  = 13;
    inline constexpr uint16_t XBOX                     = 14;
    inline constexpr uint16_t WINDOWS_BOOT_APPLICATION = 16;
    inline constexpr uint16_t XBOX_CODE_CATALOG        = 17;
} // namespace Subsystem

// ============================================================================
// DLL Characteristics
// ============================================================================

namespace DllCharacteristics {
    inline constexpr uint16_t HIGH_ENTROPY_VA       = 0x0020;
    inline constexpr uint16_t DYNAMIC_BASE          = 0x0040;  // ASLR
    inline constexpr uint16_t FORCE_INTEGRITY       = 0x0080;
    inline constexpr uint16_t NX_COMPAT             = 0x0100;  // DEP
    inline constexpr uint16_t NO_ISOLATION          = 0x0200;
    inline constexpr uint16_t NO_SEH                = 0x0400;
    inline constexpr uint16_t NO_BIND               = 0x0800;
    inline constexpr uint16_t APPCONTAINER          = 0x1000;
    inline constexpr uint16_t WDM_DRIVER            = 0x2000;
    inline constexpr uint16_t GUARD_CF              = 0x4000;  // Control Flow Guard
    inline constexpr uint16_t TERMINAL_SERVER_AWARE = 0x8000;
} // namespace DllCharacteristics

// ============================================================================
// Data Directory Indices
// ============================================================================

namespace DataDirectory {
    inline constexpr size_t EXPORT         = 0;
    inline constexpr size_t IMPORT         = 1;
    inline constexpr size_t RESOURCE       = 2;
    inline constexpr size_t EXCEPTION      = 3;
    inline constexpr size_t SECURITY       = 4;
    inline constexpr size_t BASERELOC      = 5;
    inline constexpr size_t DEBUG          = 6;
    inline constexpr size_t ARCHITECTURE   = 7;  // Reserved, must be 0
    inline constexpr size_t GLOBALPTR      = 8;
    inline constexpr size_t TLS            = 9;
    inline constexpr size_t LOAD_CONFIG    = 10;
    inline constexpr size_t BOUND_IMPORT   = 11;
    inline constexpr size_t IAT            = 12;
    inline constexpr size_t DELAY_IMPORT   = 13;
    inline constexpr size_t COM_DESCRIPTOR = 14;  // CLR/.NET
    inline constexpr size_t RESERVED       = 15;
    inline constexpr size_t MAX_ENTRIES    = 16;
} // namespace DataDirectory

// ============================================================================
// Relocation Types
// ============================================================================

// NOTE: Windows SDK wingdi.h defines ABSOLUTE, HIGH, LOW as macros.
// We use RELOC_ prefix to avoid conflicts.
namespace RelocationType {
    inline constexpr uint16_t RELOC_ABSOLUTE       = 0;
    inline constexpr uint16_t RELOC_HIGH           = 1;
    inline constexpr uint16_t RELOC_LOW            = 2;
    inline constexpr uint16_t RELOC_HIGHLOW        = 3;
    inline constexpr uint16_t RELOC_HIGHADJ        = 4;
    inline constexpr uint16_t RELOC_MACHINE_SPECIFIC_5 = 5;
    inline constexpr uint16_t RELOC_RESERVED       = 6;
    inline constexpr uint16_t RELOC_MACHINE_SPECIFIC_7 = 7;
    inline constexpr uint16_t RELOC_MACHINE_SPECIFIC_8 = 8;
    inline constexpr uint16_t RELOC_MACHINE_SPECIFIC_9 = 9;
    inline constexpr uint16_t RELOC_DIR64          = 10;  // x64
} // namespace RelocationType

// ============================================================================
// Debug Types
// ============================================================================

namespace DebugType {
    inline constexpr uint32_t UNKNOWN        = 0;
    inline constexpr uint32_t COFF           = 1;
    inline constexpr uint32_t CODEVIEW       = 2;
    inline constexpr uint32_t FPO            = 3;
    inline constexpr uint32_t MISC           = 4;
    inline constexpr uint32_t EXCEPTION      = 5;
    inline constexpr uint32_t FIXUP          = 6;
    inline constexpr uint32_t OMAP_TO_SRC    = 7;
    inline constexpr uint32_t OMAP_FROM_SRC  = 8;
    inline constexpr uint32_t BORLAND        = 9;
    inline constexpr uint32_t RESERVED10     = 10;
    inline constexpr uint32_t CLSID          = 11;
    inline constexpr uint32_t VC_FEATURE     = 12;
    inline constexpr uint32_t POGO           = 13;
    inline constexpr uint32_t ILTCG          = 14;
    inline constexpr uint32_t MPX            = 15;
    inline constexpr uint32_t REPRO          = 16;
    inline constexpr uint32_t EMBEDDEDPDB    = 17;
    inline constexpr uint32_t PDBCHECKSUM    = 19;
    inline constexpr uint32_t EX_DLLCHARACTERISTICS = 20;
} // namespace DebugType

// ============================================================================
// Security Limits - Critical for DoS Prevention
// ============================================================================

namespace Limits {
    /// Maximum file size we'll attempt to parse (2GB)
    inline constexpr size_t MAX_FILE_SIZE = 2ULL * 1024ULL * 1024ULL * 1024ULL;

    /// Maximum number of sections (Windows loader limit is 96, we allow more for analysis)
    inline constexpr uint16_t MAX_SECTIONS = 256;

    /// Maximum section name length (fixed in PE format)
    inline constexpr size_t MAX_SECTION_NAME = 8;

    /// Maximum DLL name length
    inline constexpr size_t MAX_DLL_NAME = 512;

    /// Maximum function name length
    inline constexpr size_t MAX_FUNCTION_NAME = 4096;

    /// Maximum import descriptors (prevent infinite loops)
    inline constexpr size_t MAX_IMPORT_DESCRIPTORS = 10000;

    /// Maximum imports per DLL
    inline constexpr size_t MAX_IMPORTS_PER_DLL = 100000;

    /// Maximum exports
    inline constexpr size_t MAX_EXPORTS = 100000;

    /// Maximum relocation entries
    inline constexpr size_t MAX_RELOCATIONS = 10000000;

    /// Maximum relocation blocks
    inline constexpr size_t MAX_RELOCATION_BLOCKS = 100000;

    /// Maximum TLS callbacks
    inline constexpr size_t MAX_TLS_CALLBACKS = 1000;

    /// Maximum resource directory depth
    inline constexpr uint32_t MAX_RESOURCE_DEPTH = 32;

    /// Maximum resource entries per directory
    inline constexpr size_t MAX_RESOURCE_ENTRIES = 10000;

    /// Maximum total resources
    inline constexpr size_t MAX_TOTAL_RESOURCES = 100000;

    /// Maximum debug directory entries
    inline constexpr size_t MAX_DEBUG_ENTRIES = 100;

    /// Maximum Rich header entries
    inline constexpr size_t MAX_RICH_ENTRIES = 1000;

    /// Maximum string length for any string read from PE
    inline constexpr size_t MAX_STRING_LENGTH = 65536;

    /// Minimum valid file alignment
    inline constexpr uint32_t MIN_FILE_ALIGNMENT = 512;

    /// Maximum valid file alignment
    inline constexpr uint32_t MAX_FILE_ALIGNMENT = 65536;

    /// Minimum valid section alignment
    inline constexpr uint32_t MIN_SECTION_ALIGNMENT = 1;

    /// Maximum valid section alignment
    inline constexpr uint32_t MAX_SECTION_ALIGNMENT = 0x10000000;

    /// Minimum DOS header size
    inline constexpr size_t MIN_DOS_HEADER_SIZE = 64;

    /// Minimum PE file size (DOS header + PE signature + minimal headers)
    inline constexpr size_t MIN_PE_FILE_SIZE = 128;

    /// Maximum optional header size (prevent overflow in section table offset calc)
    inline constexpr uint16_t MAX_OPTIONAL_HEADER_SIZE = 1024;
} // namespace Limits

// ============================================================================
// Rich Header Constants
// ============================================================================

namespace RichHeader {
    /// "DanS" signature marking start of Rich header (XOR'd)
    inline constexpr uint32_t DANS_SIGNATURE = 0x536E6144;

    /// "Rich" signature marking end of Rich header
    inline constexpr uint32_t RICH_SIGNATURE = 0x68636952;
} // namespace RichHeader

// ============================================================================
// .NET/CLR Constants
// ============================================================================

namespace DotNet {
    /// CLR header signature
    inline constexpr uint32_t COMIMAGE_FLAGS_ILONLY           = 0x00000001;
    inline constexpr uint32_t COMIMAGE_FLAGS_32BITREQUIRED    = 0x00000002;
    inline constexpr uint32_t COMIMAGE_FLAGS_IL_LIBRARY       = 0x00000004;
    inline constexpr uint32_t COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008;
    inline constexpr uint32_t COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010;
    inline constexpr uint32_t COMIMAGE_FLAGS_TRACKDEBUGDATA   = 0x00010000;
    inline constexpr uint32_t COMIMAGE_FLAGS_32BITPREFERRED   = 0x00020000;
} // namespace DotNet

} // namespace PEParser
} // namespace ShadowStrike
