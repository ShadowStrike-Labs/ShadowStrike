#pragma once
/**
 * @file PETypes.hpp
 * @brief Safe PE structure definitions with explicit packing.
 *
 * These structures mirror the Windows PE format with:
 * - Explicit #pragma pack(1) for correct alignment
 * - No padding bytes
 * - Safe for direct memory mapping
 *
 * @warning Never trust values read from these structures without validation.
 *          All fields can be malicious in hostile PE files.
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>
#include <array>

namespace ShadowStrike {
namespace PEParser {

#pragma pack(push, 1)

// ============================================================================
// DOS Header (64 bytes)
// ============================================================================

/**
 * @brief DOS header structure at the start of every PE file.
 *
 * @note e_lfanew is SIGNED and can be negative (attack vector).
 *       Always validate before use.
 */
struct DosHeader {
    uint16_t e_magic;      ///< Magic number (must be 0x5A4D = "MZ")
    uint16_t e_cblp;       ///< Bytes on last page of file
    uint16_t e_cp;         ///< Pages in file
    uint16_t e_crlc;       ///< Relocations
    uint16_t e_cparhdr;    ///< Size of header in paragraphs
    uint16_t e_minalloc;   ///< Minimum extra paragraphs needed
    uint16_t e_maxalloc;   ///< Maximum extra paragraphs needed
    uint16_t e_ss;         ///< Initial (relative) SS value
    uint16_t e_sp;         ///< Initial SP value
    uint16_t e_csum;       ///< Checksum
    uint16_t e_ip;         ///< Initial IP value
    uint16_t e_cs;         ///< Initial (relative) CS value
    uint16_t e_lfarlc;     ///< File address of relocation table
    uint16_t e_ovno;       ///< Overlay number
    uint16_t e_res[4];     ///< Reserved words
    uint16_t e_oemid;      ///< OEM identifier
    uint16_t e_oeminfo;    ///< OEM information
    uint16_t e_res2[10];   ///< Reserved words
    int32_t  e_lfanew;     ///< File address of NT headers (SIGNED!)
};

static_assert(sizeof(DosHeader) == 64, "DosHeader must be 64 bytes");

// ============================================================================
// File Header (20 bytes)
// ============================================================================

/**
 * @brief COFF file header, immediately after PE signature.
 */
struct FileHeader {
    uint16_t Machine;              ///< Target machine type
    uint16_t NumberOfSections;     ///< Number of sections
    uint32_t TimeDateStamp;        ///< Unix timestamp when file was created
    uint32_t PointerToSymbolTable; ///< File offset of COFF symbol table
    uint32_t NumberOfSymbols;      ///< Number of symbols in symbol table
    uint16_t SizeOfOptionalHeader; ///< Size of optional header
    uint16_t Characteristics;      ///< File characteristics flags
};

static_assert(sizeof(FileHeader) == 20, "FileHeader must be 20 bytes");

// ============================================================================
// Data Directory Entry (8 bytes)
// ============================================================================

/**
 * @brief Data directory entry describing location and size of a table.
 */
struct DataDirectoryEntry {
    uint32_t VirtualAddress;  ///< RVA of the table
    uint32_t Size;            ///< Size of the table in bytes
};

static_assert(sizeof(DataDirectoryEntry) == 8, "DataDirectoryEntry must be 8 bytes");

// ============================================================================
// Optional Header (PE32 - 96 bytes without data directories)
// ============================================================================

/**
 * @brief PE32 (32-bit) optional header.
 */
struct OptionalHeader32 {
    uint16_t Magic;                   ///< Magic number (0x10B for PE32)
    uint8_t  MajorLinkerVersion;      ///< Linker major version
    uint8_t  MinorLinkerVersion;      ///< Linker minor version
    uint32_t SizeOfCode;              ///< Sum of all code sections
    uint32_t SizeOfInitializedData;   ///< Sum of all initialized data sections
    uint32_t SizeOfUninitializedData; ///< Sum of all uninitialized data sections
    uint32_t AddressOfEntryPoint;     ///< RVA of entry point
    uint32_t BaseOfCode;              ///< RVA of code section start
    uint32_t BaseOfData;              ///< RVA of data section start (PE32 only)
    uint32_t ImageBase;               ///< Preferred base address
    uint32_t SectionAlignment;        ///< Section alignment in memory
    uint32_t FileAlignment;           ///< Section alignment in file
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;       ///< Reserved, must be 0
    uint32_t SizeOfImage;             ///< Size of image in memory
    uint32_t SizeOfHeaders;           ///< Size of headers (rounded up)
    uint32_t CheckSum;                ///< Image checksum
    uint16_t Subsystem;               ///< Subsystem type
    uint16_t DllCharacteristics;      ///< DLL characteristics flags
    uint32_t SizeOfStackReserve;      ///< Stack reserve size
    uint32_t SizeOfStackCommit;       ///< Stack commit size
    uint32_t SizeOfHeapReserve;       ///< Heap reserve size
    uint32_t SizeOfHeapCommit;        ///< Heap commit size
    uint32_t LoaderFlags;             ///< Reserved, must be 0
    uint32_t NumberOfRvaAndSizes;     ///< Number of data directories
    // Data directories follow (up to 16)
};

static_assert(sizeof(OptionalHeader32) == 96, "OptionalHeader32 must be 96 bytes");

// ============================================================================
// Optional Header (PE32+ / 64-bit - 112 bytes without data directories)
// ============================================================================

/**
 * @brief PE32+ (64-bit) optional header.
 */
struct OptionalHeader64 {
    uint16_t Magic;                   ///< Magic number (0x20B for PE32+)
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    // Note: No BaseOfData in PE32+
    uint64_t ImageBase;               ///< 64-bit preferred base
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;      ///< 64-bit stack reserve
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    // Data directories follow
};

static_assert(sizeof(OptionalHeader64) == 112, "OptionalHeader64 must be 112 bytes");

// ============================================================================
// Section Header (40 bytes)
// ============================================================================

/**
 * @brief Section header describing a PE section.
 */
struct SectionHeader {
    uint8_t  Name[8];             ///< Section name (NOT null-terminated if 8 chars)
    uint32_t VirtualSize;         ///< Virtual size (or PhysicalAddress for objects)
    uint32_t VirtualAddress;      ///< RVA of section in memory
    uint32_t SizeOfRawData;       ///< Size of section data in file
    uint32_t PointerToRawData;    ///< File offset of section data
    uint32_t PointerToRelocations;///< File offset of relocations
    uint32_t PointerToLinenumbers;///< File offset of line numbers
    uint16_t NumberOfRelocations; ///< Number of relocations
    uint16_t NumberOfLinenumbers; ///< Number of line numbers
    uint32_t Characteristics;     ///< Section flags
};

static_assert(sizeof(SectionHeader) == 40, "SectionHeader must be 40 bytes");

// ============================================================================
// Import Directory Entry (20 bytes)
// ============================================================================

/**
 * @brief Import directory table entry.
 */
struct ImportDescriptor {
    union {
        uint32_t Characteristics;      ///< 0 for terminating null import descriptor
        uint32_t OriginalFirstThunk;   ///< RVA to original unbound IAT
    };
    uint32_t TimeDateStamp;            ///< Time/date stamp (0 if not bound)
    uint32_t ForwarderChain;           ///< Forwarder chain index (-1 if no forwarders)
    uint32_t Name;                     ///< RVA of DLL name string
    uint32_t FirstThunk;               ///< RVA of IAT (thunk table)
};

static_assert(sizeof(ImportDescriptor) == 20, "ImportDescriptor must be 20 bytes");

// ============================================================================
// Import Lookup Table Entry
// ============================================================================

/**
 * @brief 32-bit import lookup/address table entry.
 */
struct ThunkData32 {
    union {
        uint32_t ForwarderString;  ///< RVA of forwarder string
        uint32_t Function;         ///< Memory address of function
        uint32_t Ordinal;          ///< Ordinal value if MSB set
        uint32_t AddressOfData;    ///< RVA of IMAGE_IMPORT_BY_NAME
    } u1;
};

/**
 * @brief 64-bit import lookup/address table entry.
 */
struct ThunkData64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    } u1;
};

/// Ordinal flag for 32-bit imports (bit 31)
inline constexpr uint32_t ORDINAL_FLAG32 = 0x80000000;

/// Ordinal flag for 64-bit imports (bit 63)
inline constexpr uint64_t ORDINAL_FLAG64 = 0x8000000000000000ULL;

// ============================================================================
// Import By Name (variable size)
// ============================================================================

/**
 * @brief Import by name structure (followed by null-terminated name).
 */
struct ImportByName {
    uint16_t Hint;    ///< Index into export name table (optimization)
    char     Name[1]; ///< Variable-length null-terminated name
};

// ============================================================================
// Export Directory (40 bytes)
// ============================================================================

/**
 * @brief Export directory table.
 */
struct ExportDirectory {
    uint32_t Characteristics;      ///< Reserved, must be 0
    uint32_t TimeDateStamp;        ///< Time/date stamp
    uint16_t MajorVersion;         ///< Major version number
    uint16_t MinorVersion;         ///< Minor version number
    uint32_t Name;                 ///< RVA of DLL name
    uint32_t Base;                 ///< Starting ordinal number
    uint32_t NumberOfFunctions;    ///< Number of entries in EAT
    uint32_t NumberOfNames;        ///< Number of name pointers
    uint32_t AddressOfFunctions;   ///< RVA of export address table
    uint32_t AddressOfNames;       ///< RVA of name pointer table
    uint32_t AddressOfNameOrdinals;///< RVA of ordinal table
};

static_assert(sizeof(ExportDirectory) == 40, "ExportDirectory must be 40 bytes");

// ============================================================================
// Base Relocation Block (8 bytes header)
// ============================================================================

/**
 * @brief Base relocation block header.
 */
struct BaseRelocation {
    uint32_t VirtualAddress;  ///< RVA of page to apply relocations
    uint32_t SizeOfBlock;     ///< Total size including header and entries
    // Followed by WORD entries: high 4 bits = type, low 12 bits = offset
};

static_assert(sizeof(BaseRelocation) == 8, "BaseRelocation must be 8 bytes");

// ============================================================================
// TLS Directory
// ============================================================================

/**
 * @brief 32-bit TLS directory.
 */
struct TLSDirectory32 {
    uint32_t StartAddressOfRawData;   ///< VA of TLS template start
    uint32_t EndAddressOfRawData;     ///< VA of TLS template end
    uint32_t AddressOfIndex;          ///< VA of TLS index variable
    uint32_t AddressOfCallBacks;      ///< VA of TLS callback array
    uint32_t SizeOfZeroFill;          ///< Size of zero-filled area
    uint32_t Characteristics;         ///< Alignment characteristics
};

static_assert(sizeof(TLSDirectory32) == 24, "TLSDirectory32 must be 24 bytes");

/**
 * @brief 64-bit TLS directory.
 */
struct TLSDirectory64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

static_assert(sizeof(TLSDirectory64) == 40, "TLSDirectory64 must be 40 bytes");

// ============================================================================
// Debug Directory Entry (28 bytes)
// ============================================================================

/**
 * @brief Debug directory entry.
 */
struct DebugDirectory {
    uint32_t Characteristics;     ///< Reserved, must be 0
    uint32_t TimeDateStamp;       ///< Time/date stamp
    uint16_t MajorVersion;        ///< Major version
    uint16_t MinorVersion;        ///< Minor version
    uint32_t Type;                ///< Debug type
    uint32_t SizeOfData;          ///< Size of debug data
    uint32_t AddressOfRawData;    ///< RVA of debug data
    uint32_t PointerToRawData;    ///< File offset of debug data
};

static_assert(sizeof(DebugDirectory) == 28, "DebugDirectory must be 28 bytes");

// ============================================================================
// Resource Directory (16 bytes)
// ============================================================================

/**
 * @brief Resource directory table.
 */
struct ResourceDirectory {
    uint32_t Characteristics;     ///< Resource flags (usually 0)
    uint32_t TimeDateStamp;       ///< Time/date stamp
    uint16_t MajorVersion;        ///< Major version
    uint16_t MinorVersion;        ///< Minor version
    uint16_t NumberOfNamedEntries;///< Number of named entries
    uint16_t NumberOfIdEntries;   ///< Number of ID entries
    // Followed by ResourceDirectoryEntry array
};

static_assert(sizeof(ResourceDirectory) == 16, "ResourceDirectory must be 16 bytes");

/**
 * @brief Resource directory entry (8 bytes).
 */
struct ResourceDirectoryEntry {
    union {
        struct {
            uint32_t NameOffset : 31;   ///< Offset to name string
            uint32_t NameIsString : 1;  ///< 1 if name is string
        };
        uint32_t Name;                  ///< Name or ID
        uint16_t Id;                    ///< Integer ID (if NameIsString == 0)
    };
    union {
        uint32_t OffsetToData;          ///< Offset to data entry
        struct {
            uint32_t OffsetToDirectory : 31; ///< Offset to subdirectory
            uint32_t DataIsDirectory : 1;    ///< 1 if points to directory
        };
    };
};

static_assert(sizeof(ResourceDirectoryEntry) == 8, "ResourceDirectoryEntry must be 8 bytes");

/**
 * @brief Resource data entry (16 bytes).
 */
struct ResourceDataEntry {
    uint32_t OffsetToData;  ///< RVA of resource data
    uint32_t Size;          ///< Size of resource data
    uint32_t CodePage;      ///< Code page for resource
    uint32_t Reserved;      ///< Reserved, must be 0
};

static_assert(sizeof(ResourceDataEntry) == 16, "ResourceDataEntry must be 16 bytes");

// ============================================================================
// CLR/.NET Header (72 bytes)
// ============================================================================

/**
 * @brief CLR 2.0 header for .NET assemblies.
 */
struct CLRHeader {
    uint32_t cb;                          ///< Size of header
    uint16_t MajorRuntimeVersion;         ///< Major runtime version
    uint16_t MinorRuntimeVersion;         ///< Minor runtime version
    DataDirectoryEntry MetaData;          ///< Metadata directory
    uint32_t Flags;                       ///< Flags
    union {
        uint32_t EntryPointToken;         ///< Entry point token
        uint32_t EntryPointRVA;           ///< Entry point RVA
    };
    DataDirectoryEntry Resources;         ///< Resources directory
    DataDirectoryEntry StrongNameSignature;///< Strong name signature
    DataDirectoryEntry CodeManagerTable;  ///< Code manager table
    DataDirectoryEntry VTableFixups;      ///< VTable fixups
    DataDirectoryEntry ExportAddressTableJumps;
    DataDirectoryEntry ManagedNativeHeader;
};

static_assert(sizeof(CLRHeader) == 72, "CLRHeader must be 72 bytes");

// ============================================================================
// Delay Import Descriptor (32 bytes)
// ============================================================================

/**
 * @brief Delay-load import descriptor.
 */
struct DelayImportDescriptor {
    uint32_t Attributes;          ///< Attributes (must be 0 or 1)
    uint32_t DllNameRVA;          ///< RVA of DLL name
    uint32_t ModuleHandleRVA;     ///< RVA of module handle
    uint32_t ImportAddressTableRVA;///< RVA of delay IAT
    uint32_t ImportNameTableRVA;  ///< RVA of delay INT
    uint32_t BoundImportAddressTableRVA;
    uint32_t UnloadInformationTableRVA;
    uint32_t TimeDateStamp;
};

static_assert(sizeof(DelayImportDescriptor) == 32, "DelayImportDescriptor must be 32 bytes");

// ============================================================================
// Bound Import (8 bytes header)
// ============================================================================

/**
 * @brief Bound import descriptor.
 */
struct BoundImportDescriptor {
    uint32_t TimeDateStamp;       ///< Time/date stamp of bound DLL
    uint16_t OffsetModuleName;    ///< Offset to module name from start
    uint16_t NumberOfModuleForwarderRefs;
};

static_assert(sizeof(BoundImportDescriptor) == 8, "BoundImportDescriptor must be 8 bytes");

// ============================================================================
// Load Config Directory (varies by architecture, minimum shown)
// ============================================================================

/**
 * @brief Minimal load configuration directory (32-bit).
 * @note Full structure is much larger and version-dependent.
 */
struct LoadConfigDirectory32 {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t GlobalFlagsClear;
    uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint32_t DeCommitFreeBlockThreshold;
    uint32_t DeCommitTotalFreeThreshold;
    uint32_t LockPrefixTable;
    uint32_t MaximumAllocationSize;
    uint32_t VirtualMemoryThreshold;
    uint32_t ProcessHeapFlags;
    uint32_t ProcessAffinityMask;
    uint16_t CSDVersion;
    uint16_t DependentLoadFlags;
    uint32_t EditList;
    uint32_t SecurityCookie;
    uint32_t SEHandlerTable;
    uint32_t SEHandlerCount;
    // Additional fields in newer versions...
};

/**
 * @brief Minimal load configuration directory (64-bit).
 */
struct LoadConfigDirectory64 {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t GlobalFlagsClear;
    uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint64_t DeCommitFreeBlockThreshold;
    uint64_t DeCommitTotalFreeThreshold;
    uint64_t LockPrefixTable;
    uint64_t MaximumAllocationSize;
    uint64_t VirtualMemoryThreshold;
    uint64_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion;
    uint16_t DependentLoadFlags;
    uint64_t EditList;
    uint64_t SecurityCookie;
    uint64_t SEHandlerTable;
    uint64_t SEHandlerCount;
    // Additional fields in newer versions...
};

#pragma pack(pop)

} // namespace PEParser
} // namespace ShadowStrike
