/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PEStructures.hpp — Portable Executable format definitions
 *
 * Zero-dependency PE format structures for parsing PE32/PE64 executables.
 * These are our own definitions — no reliance on <windows.h> for portability
 * and to avoid pulling in the massive Win32 header tree.
 *
 * Every constant and structure is verified against the PE/COFF specification
 * (Microsoft PE Format, Rev 11.0).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace Phantom::PE {

// ============================================================================
// Constants
// ============================================================================

static constexpr uint16_t kDOSMagic           = 0x5A4D;     // 'MZ'
static constexpr uint32_t kNTSignature        = 0x00004550;  // 'PE\0\0'
static constexpr uint16_t kPE32Magic          = 0x010B;
static constexpr uint16_t kPE64Magic          = 0x020B;
static constexpr uint16_t kROMImageMagic      = 0x0107;

// Machine types
static constexpr uint16_t kMachineI386        = 0x014C;
static constexpr uint16_t kMachineAMD64       = 0x8664;
static constexpr uint16_t kMachineARM         = 0x01C0;
static constexpr uint16_t kMachineARM64       = 0xAA64;

// File characteristics
static constexpr uint16_t kCharRelocsStripped    = 0x0001;
static constexpr uint16_t kCharExecutableImage   = 0x0002;
static constexpr uint16_t kCharLargeAddressAware = 0x0020;
static constexpr uint16_t kChar32BitMachine      = 0x0100;
static constexpr uint16_t kCharDLL               = 0x2000;
static constexpr uint16_t kCharSystem            = 0x1000;

// DLL characteristics
static constexpr uint16_t kDllCharHighEntropyVA  = 0x0020;
static constexpr uint16_t kDllCharDynamicBase    = 0x0040;
static constexpr uint16_t kDllCharForceIntegrity = 0x0080;
static constexpr uint16_t kDllCharNXCompat       = 0x0100;
static constexpr uint16_t kDllCharNoIsolation    = 0x0200;
static constexpr uint16_t kDllCharNoSEH          = 0x0400;
static constexpr uint16_t kDllCharNoBind         = 0x0800;
static constexpr uint16_t kDllCharAppContainer   = 0x1000;
static constexpr uint16_t kDllCharWDMDriver      = 0x2000;
static constexpr uint16_t kDllCharGuardCF        = 0x4000;
static constexpr uint16_t kDllCharTermServerAware = 0x8000;

// Section characteristics
static constexpr uint32_t kSecContainsCode       = 0x00000020;
static constexpr uint32_t kSecContainsInitData   = 0x00000040;
static constexpr uint32_t kSecContainsUninitData = 0x00000080;
static constexpr uint32_t kSecLinkInfo           = 0x00000200;
static constexpr uint32_t kSecLinkRemove         = 0x00000800;
static constexpr uint32_t kSecLinkComdat         = 0x00001000;
static constexpr uint32_t kSecNoDeferSpecExc     = 0x00004000;
static constexpr uint32_t kSecGpRelative         = 0x00008000;
static constexpr uint32_t kSecAlign1             = 0x00100000;
static constexpr uint32_t kSecAlign2             = 0x00200000;
static constexpr uint32_t kSecAlign4             = 0x00300000;
static constexpr uint32_t kSecAlign8             = 0x00400000;
static constexpr uint32_t kSecAlign16            = 0x00500000;
static constexpr uint32_t kSecAlign32            = 0x00600000;
static constexpr uint32_t kSecAlign64            = 0x00700000;
static constexpr uint32_t kSecAlign128           = 0x00800000;
static constexpr uint32_t kSecAlign256           = 0x00900000;
static constexpr uint32_t kSecAlign512           = 0x00A00000;
static constexpr uint32_t kSecAlign1024          = 0x00B00000;
static constexpr uint32_t kSecAlign2048          = 0x00C00000;
static constexpr uint32_t kSecAlign4096          = 0x00D00000;
static constexpr uint32_t kSecAlign8192          = 0x00E00000;
static constexpr uint32_t kSecAlignMask          = 0x00F00000;
static constexpr uint32_t kSecLinkNRelocOvfl     = 0x01000000;
static constexpr uint32_t kSecMemDiscardable     = 0x02000000;
static constexpr uint32_t kSecMemNotCached       = 0x04000000;
static constexpr uint32_t kSecMemNotPaged        = 0x08000000;
static constexpr uint32_t kSecMemShared          = 0x10000000;
static constexpr uint32_t kSecMemExecute         = 0x20000000;
static constexpr uint32_t kSecMemRead            = 0x40000000;
static constexpr uint32_t kSecMemWrite           = 0x80000000;

// Data directory indices
static constexpr uint32_t kDirExport             = 0;
static constexpr uint32_t kDirImport             = 1;
static constexpr uint32_t kDirResource           = 2;
static constexpr uint32_t kDirException          = 3;
static constexpr uint32_t kDirSecurity           = 4;
static constexpr uint32_t kDirBaseReloc          = 5;
static constexpr uint32_t kDirDebug              = 6;
static constexpr uint32_t kDirArchitecture       = 7;
static constexpr uint32_t kDirGlobalPtr          = 8;
static constexpr uint32_t kDirTLS                = 9;
static constexpr uint32_t kDirLoadConfig         = 10;
static constexpr uint32_t kDirBoundImport        = 11;
static constexpr uint32_t kDirIAT                = 12;
static constexpr uint32_t kDirDelayImport        = 13;
static constexpr uint32_t kDirCLRRuntime         = 14;
static constexpr uint32_t kDirReserved           = 15;
static constexpr uint32_t kMaxDataDirectories    = 16;

// Base relocation types (high 4 bits of relocation entry)
static constexpr uint16_t kRelocAbsolute         = 0;   // Padding (skip)
static constexpr uint16_t kRelocHigh             = 1;   // High 16 bits
static constexpr uint16_t kRelocLow              = 2;   // Low 16 bits
static constexpr uint16_t kRelocHighLow          = 3;   // Full 32-bit
static constexpr uint16_t kRelocHighAdj          = 4;   // High 16 bits + adjustment
static constexpr uint16_t kRelocMIPSJmpAddr      = 5;   // MIPS jump address
static constexpr uint16_t kRelocDir64            = 10;  // Full 64-bit address

// Import lookup table flags
static constexpr uint32_t kImportByOrdinal32     = 0x80000000;
static constexpr uint64_t kImportByOrdinal64     = 0x8000000000000000ULL;
static constexpr uint32_t kOrdinalMask16         = 0xFFFF;

// Subsystem types
static constexpr uint16_t kSubsystemNative       = 1;
static constexpr uint16_t kSubsystemWindowsGUI   = 2;
static constexpr uint16_t kSubsystemWindowsCUI   = 3;
static constexpr uint16_t kSubsystemOS2CUI       = 5;
static constexpr uint16_t kSubsystemPosixCUI     = 7;
static constexpr uint16_t kSubsystemEFIApp       = 10;
static constexpr uint16_t kSubsystemEFIBootDrv   = 11;
static constexpr uint16_t kSubsystemEFIRuntimeDrv = 12;
static constexpr uint16_t kSubsystemEFIROM       = 13;

// Limits (anti-evasion/anti-DoS)
static constexpr uint32_t kMaxSections           = 96;
static constexpr uint32_t kMaxImportDLLs         = 256;
static constexpr uint32_t kMaxImportsPerDLL      = 16384;
static constexpr uint32_t kMaxExports            = 65536;
static constexpr uint32_t kMaxRelocBlocks        = 65536;
static constexpr uint32_t kMaxRelocsPerBlock     = 4096;
static constexpr uint32_t kMaxTLSCallbacks       = 64;
static constexpr uint32_t kMaxResourceDepth      = 8;
static constexpr uint32_t kMaxResourceEntries    = 4096;
static constexpr uint32_t kMaxPEFileSize         = 256 * 1024 * 1024; // 256 MB
static constexpr uint32_t kMaxSectionNameLen     = 8;
static constexpr uint32_t kMaxDLLNameLen         = 260;
static constexpr uint32_t kMaxExportNameLen      = 4096;

// ============================================================================
// PE Structures (packed, matching on-disk layout)
// ============================================================================

#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic;           // 'MZ'
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;          // File offset to PE signature
};
static_assert(sizeof(DOSHeader) == 64, "DOSHeader must be 64 bytes");

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
static_assert(sizeof(FileHeader) == 20, "FileHeader must be 20 bytes");

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};
static_assert(sizeof(DataDirectory) == 8, "DataDirectory must be 8 bytes");

struct OptionalHeader32 {
    uint16_t      Magic;                    // 0x010B
    uint8_t       MajorLinkerVersion;
    uint8_t       MinorLinkerVersion;
    uint32_t      SizeOfCode;
    uint32_t      SizeOfInitializedData;
    uint32_t      SizeOfUninitializedData;
    uint32_t      AddressOfEntryPoint;
    uint32_t      BaseOfCode;
    uint32_t      BaseOfData;
    uint32_t      ImageBase;
    uint32_t      SectionAlignment;
    uint32_t      FileAlignment;
    uint16_t      MajorOperatingSystemVersion;
    uint16_t      MinorOperatingSystemVersion;
    uint16_t      MajorImageVersion;
    uint16_t      MinorImageVersion;
    uint16_t      MajorSubsystemVersion;
    uint16_t      MinorSubsystemVersion;
    uint32_t      Win32VersionValue;
    uint32_t      SizeOfImage;
    uint32_t      SizeOfHeaders;
    uint32_t      CheckSum;
    uint16_t      Subsystem;
    uint16_t      DllCharacteristics;
    uint32_t      SizeOfStackReserve;
    uint32_t      SizeOfStackCommit;
    uint32_t      SizeOfHeapReserve;
    uint32_t      SizeOfHeapCommit;
    uint32_t      LoaderFlags;
    uint32_t      NumberOfRvaAndSizes;
    DataDirectory DataDirectories[kMaxDataDirectories];
};
static_assert(sizeof(OptionalHeader32) == 224, "OptionalHeader32 must be 224 bytes");

struct OptionalHeader64 {
    uint16_t      Magic;                    // 0x020B
    uint8_t       MajorLinkerVersion;
    uint8_t       MinorLinkerVersion;
    uint32_t      SizeOfCode;
    uint32_t      SizeOfInitializedData;
    uint32_t      SizeOfUninitializedData;
    uint32_t      AddressOfEntryPoint;
    uint32_t      BaseOfCode;
    uint64_t      ImageBase;
    uint32_t      SectionAlignment;
    uint32_t      FileAlignment;
    uint16_t      MajorOperatingSystemVersion;
    uint16_t      MinorOperatingSystemVersion;
    uint16_t      MajorImageVersion;
    uint16_t      MinorImageVersion;
    uint16_t      MajorSubsystemVersion;
    uint16_t      MinorSubsystemVersion;
    uint32_t      Win32VersionValue;
    uint32_t      SizeOfImage;
    uint32_t      SizeOfHeaders;
    uint32_t      CheckSum;
    uint16_t      Subsystem;
    uint16_t      DllCharacteristics;
    uint64_t      SizeOfStackReserve;
    uint64_t      SizeOfStackCommit;
    uint64_t      SizeOfHeapReserve;
    uint64_t      SizeOfHeapCommit;
    uint32_t      LoaderFlags;
    uint32_t      NumberOfRvaAndSizes;
    DataDirectory DataDirectories[kMaxDataDirectories];
};
static_assert(sizeof(OptionalHeader64) == 240, "OptionalHeader64 must be 240 bytes");

struct NTHeaders32 {
    uint32_t         Signature;
    FileHeader       FileHdr;
    OptionalHeader32 OptionalHdr;
};

struct NTHeaders64 {
    uint32_t         Signature;
    FileHeader       FileHdr;
    OptionalHeader64 OptionalHdr;
};

struct SectionHeader {
    char     Name[kMaxSectionNameLen];
    uint32_t VirtualSize;           // Misc.VirtualSize
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
static_assert(sizeof(SectionHeader) == 40, "SectionHeader must be 40 bytes");

struct ExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;                  // RVA to DLL name
    uint32_t Base;                  // Ordinal base
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;    // RVA to function address array
    uint32_t AddressOfNames;        // RVA to name pointer array
    uint32_t AddressOfNameOrdinals; // RVA to ordinal array
};
static_assert(sizeof(ExportDirectory) == 40, "ExportDirectory must be 40 bytes");

struct ImportDescriptor {
    uint32_t OriginalFirstThunk;    // RVA to Import Lookup Table (ILT)
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                  // RVA to DLL name string
    uint32_t FirstThunk;            // RVA to Import Address Table (IAT)
};
static_assert(sizeof(ImportDescriptor) == 20, "ImportDescriptor must be 20 bytes");

struct ImportByName {
    uint16_t Hint;
    char     Name[1];               // Variable-length null-terminated string
};

struct BaseRelocation {
    uint32_t VirtualAddress;        // Page RVA
    uint32_t SizeOfBlock;           // Total size of this block (including header)
};
static_assert(sizeof(BaseRelocation) == 8, "BaseRelocation must be 8 bytes");

struct TLSDirectory32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};
static_assert(sizeof(TLSDirectory32) == 24, "TLSDirectory32 must be 24 bytes");

struct TLSDirectory64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};
static_assert(sizeof(TLSDirectory64) == 40, "TLSDirectory64 must be 40 bytes");

struct ResourceDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};
static_assert(sizeof(ResourceDirectory) == 16, "ResourceDirectory must be 16 bytes");

struct ResourceDirectoryEntry {
    uint32_t NameOrId;              // If bit 31 set: RVA to name string; else: integer ID
    uint32_t OffsetToDataOrSubdir;  // If bit 31 set: offset to subdir; else: offset to data entry
};
static_assert(sizeof(ResourceDirectoryEntry) == 8, "ResourceDirectoryEntry must be 8 bytes");

struct ResourceDataEntry {
    uint32_t OffsetToData;          // RVA to resource data
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};
static_assert(sizeof(ResourceDataEntry) == 16, "ResourceDataEntry must be 16 bytes");

struct DelayImportDescriptor {
    uint32_t Attributes;
    uint32_t DllNameRVA;
    uint32_t ModuleHandleRVA;
    uint32_t ImportAddressTableRVA;
    uint32_t ImportNameTableRVA;
    uint32_t BoundImportAddressTableRVA;
    uint32_t UnloadInformationTableRVA;
    uint32_t TimeDateStamp;
};
static_assert(sizeof(DelayImportDescriptor) == 32, "DelayImportDescriptor must be 32 bytes");

struct DebugDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};
static_assert(sizeof(DebugDirectory) == 28, "DebugDirectory must be 28 bytes");

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
    uint32_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion;
    uint16_t DependentLoadFlags;
    uint32_t EditList;
    uint32_t SecurityCookie;
    uint32_t SEHandlerTable;
    uint32_t SEHandlerCount;
    uint32_t GuardCFCheckFunctionPointer;
    uint32_t GuardCFDispatchFunctionPointer;
    uint32_t GuardCFFunctionTable;
    uint32_t GuardCFFunctionCount;
    uint32_t GuardFlags;
};

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
    uint64_t GuardCFCheckFunctionPointer;
    uint64_t GuardCFDispatchFunctionPointer;
    uint64_t GuardCFFunctionTable;
    uint64_t GuardCFFunctionCount;
    uint32_t GuardFlags;
};

#pragma pack(pop)

// ============================================================================
// Helper: Section characteristics → MemProt
// ============================================================================

static constexpr uint8_t SectionToMemProt(uint32_t characteristics) noexcept {
    uint8_t prot = 0;
    if (characteristics & kSecMemRead)    prot |= 0x01; // MemProt::Read
    if (characteristics & kSecMemWrite)   prot |= 0x02; // MemProt::Write
    if (characteristics & kSecMemExecute) prot |= 0x04; // MemProt::Execute
    if (prot == 0) prot = 0x01; // Default to readable
    return prot;
}

// ============================================================================
// Helper: Safe bounds checking for RVA lookups
// ============================================================================

[[nodiscard]] constexpr bool IsRVAInBounds(uint32_t rva, uint32_t size,
                                            uint32_t regionBase, uint32_t regionSize) noexcept {
    if (size == 0) return false;
    // Overflow-safe: check that rva >= regionBase AND rva+size-1 < regionBase+regionSize
    if (rva < regionBase) return false;
    uint32_t offset = rva - regionBase;
    return offset <= regionSize && (regionSize - offset) >= size;
}

[[nodiscard]] constexpr bool IsFileOffsetValid(uint32_t offset, uint32_t size,
                                                uint32_t fileSize) noexcept {
    if (size == 0) return true; // Zero-sized read is trivially valid
    return offset < fileSize && (fileSize - offset) >= size;
}

} // namespace Phantom::PE
