/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CLRTypes.hpp — Shared .NET/CLR type definitions
 *
 * Common structures, enumerations, and constants used across all CLR
 * emulation modules: MetadataParser, MSILDisassembler, MSILInterpreter,
 * and DotNetAnalyzer.
 *
 * References:
 *   ECMA-335 (6th Edition) — Common Language Infrastructure
 *   Microsoft PE/COFF Specification — .NET Metadata
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <variant>

namespace Phantom::CLR {

// ============================================================================
// PE .NET Directory Structures (ECMA-335 §II.25)
// ============================================================================

/// IMAGE_COR20_HEADER — The CLR runtime header pointed to by
/// DataDirectory[14] (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR).
struct COR20Header {
    uint32_t cb;                     // Size of this header (72 bytes)
    uint16_t majorRuntimeVersion;    // Minimum CLR version required
    uint16_t minorRuntimeVersion;
    uint32_t metadataRVA;            // RVA to metadata root
    uint32_t metadataSize;           // Size of metadata
    uint32_t flags;                  // COMIMAGE_FLAGS
    uint32_t entryPointToken;        // MethodDef or File token
    uint32_t resourcesRVA;           // RVA to .NET resources
    uint32_t resourcesSize;
    uint32_t strongNameRVA;          // RVA to strong name signature
    uint32_t strongNameSize;
    uint32_t codeManagerTableRVA;
    uint32_t codeManagerTableSize;
    uint32_t vtableFixupsRVA;
    uint32_t vtableFixupsSize;
    uint32_t exportAddressTableRVA;
    uint32_t exportAddressTableSize;
    uint32_t managedNativeHeaderRVA;
    uint32_t managedNativeHeaderSize;
};

/// COMIMAGE_FLAGS bitmask
namespace COR20Flags {
    static constexpr uint32_t ILOnly            = 0x00000001;
    static constexpr uint32_t Requires32Bit     = 0x00000002;
    static constexpr uint32_t ILLibrary         = 0x00000004;
    static constexpr uint32_t StrongNameSigned  = 0x00000008;
    static constexpr uint32_t NativeEntryPoint  = 0x00000010;
    static constexpr uint32_t TrackDebugData    = 0x00010000;
    static constexpr uint32_t Prefers32Bit      = 0x00020000;
}

// ============================================================================
// Metadata Root Header (ECMA-335 §II.24.2.1)
// ============================================================================

struct MetadataRoot {
    uint32_t signature;              // Magic: 0x424A5342 ("BSJB")
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t reserved;
    uint32_t versionLength;          // Length of version string (padded to 4)
    std::string versionString;       // CLR version (e.g., "v4.0.30319")
    uint16_t flags;
    uint16_t streamCount;
};

static constexpr uint32_t kMetadataSignature = 0x424A5342; // "BSJB"

// ============================================================================
// Metadata Stream Headers (ECMA-335 §II.24.2.2)
// ============================================================================

struct StreamHeader {
    uint32_t    offset;              // Offset from metadata root
    uint32_t    size;                // Size of the stream
    std::string name;                // Stream name (#~, #Strings, #Blob, #GUID, #US)
};

// ============================================================================
// Metadata Table IDs (ECMA-335 §II.22)
// ============================================================================

enum class MetadataTableId : uint8_t {
    Module              = 0x00,
    TypeRef             = 0x01,
    TypeDef             = 0x02,
    FieldPtr            = 0x03,
    Field               = 0x04,
    MethodPtr           = 0x05,
    MethodDef           = 0x06,
    ParamPtr            = 0x07,
    Param               = 0x08,
    InterfaceImpl       = 0x09,
    MemberRef           = 0x0A,
    Constant            = 0x0B,
    CustomAttribute     = 0x0C,
    FieldMarshal        = 0x0D,
    DeclSecurity        = 0x0E,
    ClassLayout         = 0x0F,
    FieldLayout          = 0x10,
    StandAloneSig       = 0x11,
    EventMap            = 0x12,
    EventPtr            = 0x13,
    Event               = 0x14,
    PropertyMap         = 0x15,
    PropertyPtr         = 0x16,
    Property            = 0x17,
    MethodSemantics     = 0x18,
    MethodImpl          = 0x19,
    ModuleRef           = 0x1A,
    TypeSpec            = 0x1B,
    ImplMap             = 0x1C,
    FieldRVA            = 0x1D,
    EncLog              = 0x1E,
    EncMap              = 0x1F,
    Assembly            = 0x20,
    AssemblyProcessor   = 0x21,
    AssemblyOS          = 0x22,
    AssemblyRef         = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOS       = 0x25,
    File                = 0x26,
    ExportedType        = 0x27,
    ManifestResource    = 0x28,
    NestedClass         = 0x29,
    GenericParam        = 0x2A,
    MethodSpec          = 0x2B,
    GenericParamConstraint = 0x2C,
    MaxTable            = 0x2D
};

static constexpr uint32_t kMaxMetadataTables = static_cast<uint32_t>(MetadataTableId::MaxTable);
static constexpr uint32_t kMetadataTokenRowMask = 0x00FFFFFFu;
static constexpr uint32_t kMaxMetadataTokenRow = kMetadataTokenRowMask;

/**
 * @brief Validates an ECMA-335 metadata table identifier.
 *
 * Thread safety: pure value helper. Failure contract: returns false for
 * out-of-range table bytes decoded from hostile or malformed metadata tokens.
 */
[[nodiscard]] constexpr bool IsValidMetadataTableId(MetadataTableId table) noexcept {
    return static_cast<uint32_t>(table) < kMaxMetadataTables;
}

// ============================================================================
// Metadata Token Encoding (ECMA-335 §II.22)
// ============================================================================

/**
 * @brief ECMA-335 metadata token: upper 8 bits table ID, lower 24 bits 1-based row index.
 *
 * Tokens are commonly attacker-controlled when parsing managed malware. The
 * helpers below never truncate row IDs silently and map invalid table bytes to
 * MetadataTableId::MaxTable so switch statements can reject them explicitly.
 * Thread safety: immutable value type.
 */
struct MetadataToken {
    uint32_t raw = 0;

    [[nodiscard]] MetadataTableId Table() const noexcept {
        const auto table = static_cast<MetadataTableId>((raw >> 24) & 0xFFu);
        return IsValidMetadataTableId(table) ? table : MetadataTableId::MaxTable;
    }
    [[nodiscard]] uint32_t Row() const noexcept { return raw & kMetadataTokenRowMask; }
    [[nodiscard]] bool IsNull() const noexcept { return raw == 0; }
    [[nodiscard]] bool IsValid() const noexcept {
        return !IsNull() && IsValidMetadataTableId(Table()) && Row() != 0;
    }

    static MetadataToken Make(MetadataTableId table, uint32_t row) noexcept {
        if (!IsValidMetadataTableId(table) || row == 0 || row > kMaxMetadataTokenRow) {
            return {};
        }
        return { (static_cast<uint32_t>(table) << 24) | row };
    }
};

// ============================================================================
// Parsed Metadata Row Types
// ============================================================================

struct TypeDefRow {
    uint32_t    flags = 0;
    std::string typeName;
    std::string typeNamespace;
    uint32_t    extendsCodedIndex = 0; // TypeDefOrRef coded index
    uint32_t    fieldList = 0;         // Index into Field table
    uint32_t    methodList = 0;        // Index into MethodDef table
};

struct MethodDefRow {
    uint32_t    rva = 0;              // RVA of IL method body
    uint16_t    implFlags = 0;
    uint16_t    flags = 0;
    std::string name;
    uint32_t    signatureIndex = 0;   // Index into #Blob heap
    uint32_t    paramList = 0;        // Index into Param table
};

struct MemberRefRow {
    uint32_t    classCodedIndex = 0;  // MemberRefParent coded index
    std::string name;
    uint32_t    signatureIndex = 0;
};

struct TypeRefRow {
    uint32_t    resolutionScope = 0;  // ResolutionScope coded index
    std::string typeName;
    std::string typeNamespace;
};

struct AssemblyRefRow {
    uint16_t    majorVersion = 0;
    uint16_t    minorVersion = 0;
    uint16_t    buildNumber = 0;
    uint16_t    revisionNumber = 0;
    uint32_t    flags = 0;
    uint32_t    publicKeyOrTokenIndex = 0;
    std::string name;
    std::string culture;
    uint32_t    hashValueIndex = 0;
};

struct ImplMapRow {
    uint16_t    mappingFlags = 0;
    uint32_t    memberForwardedIndex = 0; // MemberForwarded coded index
    std::string importName;
    uint32_t    importScopeIndex = 0;     // Index into ModuleRef table
};

struct ModuleRefRow {
    std::string name;
};

struct AssemblyRow {
    uint32_t    hashAlgId = 0;
    uint16_t    majorVersion = 0;
    uint16_t    minorVersion = 0;
    uint16_t    buildNumber = 0;
    uint16_t    revisionNumber = 0;
    uint32_t    flags = 0;
    uint32_t    publicKeyIndex = 0;
    std::string name;
    std::string culture;
};

struct FieldRVARow {
    uint32_t rva = 0;
    uint32_t fieldIndex = 0;          // Index into Field table
};

// ============================================================================
// Method Body Header Types (ECMA-335 §II.25.4)
// ============================================================================

/// Method header format enumeration
enum class MethodHeaderType : uint8_t {
    TinyFormat  = 0x02,               // 1-byte header, no locals, max 64 bytes
    FatFormat   = 0x03,               // 12-byte header, locals, exceptions
};

struct TinyMethodHeader {
    uint8_t  codeSize;                // Code size in bytes (max 63)
};

struct FatMethodHeader {
    uint16_t flags;                   // Flags (0x3 = Fat, 0x8 = MoreSects, 0x10 = InitLocals)
    uint16_t maxStack;
    uint32_t codeSize;
    uint32_t localVarSigToken;        // StandAloneSig token for local variables
};

static constexpr uint16_t kFatFormatFlag      = 0x0003;
static constexpr uint16_t kMoreSectionsFlag   = 0x0008;
static constexpr uint16_t kInitLocalsFlag     = 0x0010;

// ============================================================================
// MSIL Opcode Enumeration (ECMA-335 §III.1)
// ============================================================================

enum class MSILOpcode : uint16_t {
    // Single-byte opcodes (0x00 - 0xFE)
    Nop             = 0x0000,
    Break           = 0x0001,
    Ldarg_0         = 0x0002,
    Ldarg_1         = 0x0003,
    Ldarg_2         = 0x0004,
    Ldarg_3         = 0x0005,
    Ldloc_0         = 0x0006,
    Ldloc_1         = 0x0007,
    Ldloc_2         = 0x0008,
    Ldloc_3         = 0x0009,
    Stloc_0         = 0x000A,
    Stloc_1         = 0x000B,
    Stloc_2         = 0x000C,
    Stloc_3         = 0x000D,
    Ldarg_S         = 0x000E,
    Ldarga_S        = 0x000F,
    Starg_S         = 0x0010,
    Ldloc_S         = 0x0011,
    Ldloca_S        = 0x0012,
    Stloc_S         = 0x0013,
    Ldnull          = 0x0014,
    Ldc_I4_M1       = 0x0015,
    Ldc_I4_0        = 0x0016,
    Ldc_I4_1        = 0x0017,
    Ldc_I4_2        = 0x0018,
    Ldc_I4_3        = 0x0019,
    Ldc_I4_4        = 0x001A,
    Ldc_I4_5        = 0x001B,
    Ldc_I4_6        = 0x001C,
    Ldc_I4_7        = 0x001D,
    Ldc_I4_8        = 0x001E,
    Ldc_I4_S        = 0x001F,
    Ldc_I4          = 0x0020,
    Ldc_I8          = 0x0021,
    Ldc_R4          = 0x0022,
    Ldc_R8          = 0x0023,
    Dup             = 0x0025,
    Pop             = 0x0026,
    Jmp             = 0x0027,
    Call            = 0x0028,
    Calli           = 0x0029,
    Ret             = 0x002A,
    Br_S            = 0x002B,
    Brfalse_S       = 0x002C,
    Brtrue_S        = 0x002D,
    Beq_S           = 0x002E,
    Bge_S           = 0x002F,
    Bgt_S           = 0x0030,
    Ble_S           = 0x0031,
    Blt_S           = 0x0032,
    Bne_Un_S        = 0x0033,
    Bge_Un_S        = 0x0034,
    Bgt_Un_S        = 0x0035,
    Ble_Un_S        = 0x0036,
    Blt_Un_S        = 0x0037,
    Br              = 0x0038,
    Brfalse         = 0x0039,
    Brtrue          = 0x003A,
    Beq             = 0x003B,
    Bge             = 0x003C,
    Bgt             = 0x003D,
    Ble             = 0x003E,
    Blt             = 0x003F,
    Bne_Un          = 0x0040,
    Bge_Un          = 0x0041,
    Bgt_Un          = 0x0042,
    Ble_Un          = 0x0043,
    Blt_Un          = 0x0044,
    Switch          = 0x0045,
    Ldind_I1        = 0x0046,
    Ldind_U1        = 0x0047,
    Ldind_I2        = 0x0048,
    Ldind_U2        = 0x0049,
    Ldind_I4        = 0x004A,
    Ldind_U4        = 0x004B,
    Ldind_I8        = 0x004C,
    Ldind_I         = 0x004D,
    Ldind_R4        = 0x004E,
    Ldind_R8        = 0x004F,
    Ldind_Ref       = 0x0050,
    Stind_Ref       = 0x0051,
    Stind_I1        = 0x0052,
    Stind_I2        = 0x0053,
    Stind_I4        = 0x0054,
    Stind_I8        = 0x0055,
    Stind_R4        = 0x0056,
    Stind_R8        = 0x0057,
    Add             = 0x0058,
    Sub             = 0x0059,
    Mul             = 0x005A,
    Div             = 0x005B,
    Div_Un          = 0x005C,
    Rem             = 0x005D,
    Rem_Un          = 0x005E,
    And             = 0x005F,
    Or              = 0x0060,
    Xor             = 0x0061,
    Shl             = 0x0062,
    Shr             = 0x0063,
    Shr_Un          = 0x0064,
    Neg             = 0x0065,
    Not             = 0x0066,
    Conv_I1         = 0x0067,
    Conv_I2         = 0x0068,
    Conv_I4         = 0x0069,
    Conv_I8         = 0x006A,
    Conv_R4         = 0x006B,
    Conv_R8         = 0x006C,
    Conv_U4         = 0x006D,
    Conv_U8         = 0x006E,
    Callvirt        = 0x006F,
    Cpobj           = 0x0070,
    Ldobj           = 0x0071,
    Ldstr           = 0x0072,
    Newobj          = 0x0073,
    Castclass       = 0x0074,
    Isinst          = 0x0075,
    Conv_R_Un       = 0x0076,
    Unbox           = 0x0079,
    Throw           = 0x007A,
    Ldfld           = 0x007B,
    Ldflda          = 0x007C,
    Stfld           = 0x007D,
    Ldsfld          = 0x007E,
    Ldsflda         = 0x007F,
    Stsfld          = 0x0080,
    Stobj           = 0x0081,
    Conv_Ovf_I1_Un  = 0x0082,
    Conv_Ovf_I2_Un  = 0x0083,
    Conv_Ovf_I4_Un  = 0x0084,
    Conv_Ovf_I8_Un  = 0x0085,
    Conv_Ovf_U1_Un  = 0x0086,
    Conv_Ovf_U2_Un  = 0x0087,
    Conv_Ovf_U4_Un  = 0x0088,
    Conv_Ovf_U8_Un  = 0x0089,
    Conv_Ovf_I_Un   = 0x008A,
    Conv_Ovf_U_Un   = 0x008B,
    Box             = 0x008C,
    Newarr          = 0x008D,
    Ldlen           = 0x008E,
    Ldelema         = 0x008F,
    Ldelem_I1       = 0x0090,
    Ldelem_U1       = 0x0091,
    Ldelem_I2       = 0x0092,
    Ldelem_U2       = 0x0093,
    Ldelem_I4       = 0x0094,
    Ldelem_U4       = 0x0095,
    Ldelem_I8       = 0x0096,
    Ldelem_I        = 0x0097,
    Ldelem_R4       = 0x0098,
    Ldelem_R8       = 0x0099,
    Ldelem_Ref      = 0x009A,
    Stelem_I        = 0x009B,
    Stelem_I1       = 0x009C,
    Stelem_I2       = 0x009D,
    Stelem_I4       = 0x009E,
    Stelem_I8       = 0x009F,
    Stelem_R4       = 0x00A0,
    Stelem_R8       = 0x00A1,
    Stelem_Ref      = 0x00A2,
    Ldelem          = 0x00A3,
    Stelem          = 0x00A4,
    Unbox_Any       = 0x00A5,
    Conv_Ovf_I1     = 0x00B3,
    Conv_Ovf_U1     = 0x00B4,
    Conv_Ovf_I2     = 0x00B5,
    Conv_Ovf_U2     = 0x00B6,
    Conv_Ovf_I4     = 0x00B7,
    Conv_Ovf_U4     = 0x00B8,
    Conv_Ovf_I8     = 0x00B9,
    Conv_Ovf_U8     = 0x00BA,
    Refanyval       = 0x00C2,
    Ckfinite        = 0x00C3,
    Mkrefany        = 0x00C6,
    Ldtoken         = 0x00D0,
    Conv_U2         = 0x00D1,
    Conv_U1         = 0x00D2,
    Conv_I          = 0x00D3,
    Conv_Ovf_I      = 0x00D4,
    Conv_Ovf_U      = 0x00D5,
    Add_Ovf         = 0x00D6,
    Add_Ovf_Un      = 0x00D7,
    Mul_Ovf         = 0x00D8,
    Mul_Ovf_Un      = 0x00D9,
    Sub_Ovf         = 0x00DA,
    Sub_Ovf_Un      = 0x00DB,
    Endfinally      = 0x00DC,
    Leave           = 0x00DD,
    Leave_S         = 0x00DE,
    Stind_I         = 0x00DF,
    Conv_U          = 0x00E0,
    Prefix7         = 0x00F8,
    Prefix6         = 0x00F9,
    Prefix5         = 0x00FA,
    Prefix4         = 0x00FB,
    Prefix3         = 0x00FC,
    Prefix2         = 0x00FD,
    PrefixFE        = 0x00FE,   // Two-byte opcode prefix
    Prefixref       = 0x00FF,

    // Two-byte opcodes (0xFE xx)
    Arglist         = 0xFE00,
    Ceq             = 0xFE01,
    Cgt             = 0xFE02,
    Cgt_Un          = 0xFE03,
    Clt             = 0xFE04,
    Clt_Un          = 0xFE05,
    Ldftn           = 0xFE06,
    Ldvirtftn       = 0xFE07,
    Ldarg           = 0xFE09,
    Ldarga          = 0xFE0A,
    Starg           = 0xFE0B,
    Ldloc           = 0xFE0C,
    Ldloca          = 0xFE0D,
    Stloc           = 0xFE0E,
    Localloc        = 0xFE0F,
    Endfilter       = 0xFE11,
    Unaligned       = 0xFE12,
    Volatile        = 0xFE13,
    Tail            = 0xFE14,
    Initobj         = 0xFE15,
    Constrained     = 0xFE16,
    Cpblk           = 0xFE17,
    Initblk         = 0xFE18,
    Rethrow         = 0xFE1A,
    Sizeof          = 0xFE1C,
    Refanytype      = 0xFE1D,
    Readonly        = 0xFE1E,

    // Sentinel for invalid/unknown
    INVALID         = 0xFFFF,
};

// ============================================================================
// MSIL Instruction Operand Types (ECMA-335 §III.1.2)
// ============================================================================

enum class MSILOperandType : uint8_t {
    None,           // No operand
    InlineI,        // 32-bit integer
    InlineI8,       // 64-bit integer
    InlineR,        // 64-bit float (double)
    ShortInlineR,   // 32-bit float
    InlineMethod,   // 32-bit metadata token (MethodDef or MemberRef)
    InlineField,    // 32-bit metadata token (Field or MemberRef)
    InlineType,     // 32-bit metadata token (TypeDef, TypeRef, or TypeSpec)
    InlineString,   // 32-bit token into #US heap
    InlineSig,      // 32-bit token (StandAloneSig)
    InlineTok,      // 32-bit generic metadata token
    ShortInlineVar, // 8-bit local variable or argument index
    InlineVar,      // 16-bit local variable or argument index
    ShortInlineBr,  // 8-bit signed branch offset
    InlineBr,       // 32-bit signed branch offset
    InlineSwitch,   // Count + N × 32-bit branch offsets
    ShortInlineI,   // 8-bit integer
};

// ============================================================================
// Decoded MSIL Instruction
// ============================================================================

struct MSILInstruction {
    uint32_t        offset = 0;                    // Byte offset from method start
    MSILOpcode      opcode = MSILOpcode::INVALID;  // Decoded opcode
    MSILOperandType operandType = MSILOperandType::None;
    uint32_t        size = 0;                      // Total instruction size in bytes

    // Operand value (depends on operandType)
    union {
        int32_t     i32;
        int64_t     i64;
        float       f32;
        double      f64;
        uint32_t    token;           // Metadata token
        int32_t     branchOffset;    // Relative branch target
        uint8_t     varIndex8;       // Short variable index
        uint16_t    varIndex16;      // Variable index
        int8_t      shortI;          // ShortInlineI
    } operand{};

    // For switch: multiple branch targets
    std::vector<int32_t> switchTargets;
};

// ============================================================================
// .NET Behavioral Analysis Types
// ============================================================================

/// Detected .NET API call category for behavioral analysis
enum class DotNetAPICategory : uint8_t {
    Unknown = 0,

    // Execution & Loading
    AssemblyLoad,          // Assembly.Load, Assembly.LoadFrom
    AssemblyLoadRaw,       // Assembly.Load(byte[]) — in-memory loading
    ReflectionInvoke,      // MethodInfo.Invoke, Delegate.DynamicInvoke
    DynamicCompile,        // CSharpCodeProvider.CompileAssemblyFromSource
    ProcessStart,          // Process.Start, ProcessStartInfo

    // File I/O
    FileRead,              // File.ReadAllBytes, StreamReader, etc.
    FileWrite,             // File.WriteAllBytes, StreamWriter, etc.
    FileDelete,            // File.Delete, Directory.Delete
    PathManipulation,      // Path.GetTempPath, Path.Combine

    // Network
    WebDownload,           // WebClient.DownloadString/Data, HttpClient
    SocketConnect,         // TcpClient, Socket.Connect
    DnsResolve,            // Dns.GetHostAddresses

    // Crypto
    SymmetricEncrypt,      // AES, Rijndael, DES, RC4
    AsymmetricEncrypt,     // RSA, DSA
    HashCompute,           // SHA256, MD5, SHA1
    RandomGenerate,        // RNGCryptoServiceProvider

    // Registry
    RegistryRead,          // Registry.GetValue, RegistryKey.OpenSubKey
    RegistryWrite,         // Registry.SetValue

    // WMI
    WmiQuery,              // ManagementObjectSearcher, WqlObjectQuery

    // Interop
    PInvoke,               // DllImport / Platform Invoke
    MarshalCopy,           // Marshal.Copy, Marshal.AllocHGlobal
    UnsafeCode,            // Unsafe pointer manipulation

    // Evasion
    SleepDelay,            // Thread.Sleep, Task.Delay
    EnvironmentQuery,      // Environment.MachineName, Environment.UserName
    AntiDebug,             // Debugger.IsAttached, Debugger.IsLogging
    AntiVM,                // WMI hardware queries, MAC address checks
};

/// A detected .NET API call during MSIL analysis
struct DotNetAPICall {
    DotNetAPICategory category = DotNetAPICategory::Unknown;
    std::string       className;      // e.g., "System.Reflection.Assembly"
    std::string       methodName;     // e.g., "Load"
    MetadataToken     token;
    uint32_t          ilOffset = 0;   // IL offset where the call occurs
    std::string       resolvedTarget; // Fully resolved "Namespace.Class::Method"
};

/// .NET obfuscation technique detection
enum class DotNetObfuscation : uint8_t {
    None = 0,
    StringEncryption,      // Encrypted string literals
    ControlFlowFlattening, // Switch-based control flow obfuscation
    MethodProxying,        // Proxy delegate methods
    AntiTamper,            // Anti-tamper protection (checksum validation)
    AntiDecompile,         // Invalid IL / metadata corruption
    NameObfuscation,       // Unicode/garbage method/type names
    ResourceEncryption,    // Encrypted embedded resources
    VirtualizationProtect, // Virtualized code (DNGuard, KoiVM)
    MixedModeAssembly,     // C++/CLI mixed native + managed
    MethodBodyEncryption,  // Encrypted method bodies decrypted at runtime
};

/// P/Invoke import discovered in .NET assembly
struct DotNetPInvoke {
    std::string moduleName;   // DLL name (e.g., "kernel32.dll")
    std::string importName;   // Function name (e.g., "VirtualAlloc")
    std::string managedName;  // .NET method name that wraps it
    MetadataToken methodToken{};
};

/// Embedded resource in .NET assembly
struct DotNetResource {
    std::string name;
    uint32_t    offset = 0;
    uint32_t    size = 0;
    double      entropy = 0.0;  // Shannon entropy of resource data
    bool        isEncrypted = false; // entropy > 7.0 threshold
};

// ============================================================================
// .NET Analysis Result (collected into PhantomEmulationResult)
// ============================================================================

struct DotNetAnalysisResult {
    // Assembly identity
    std::string assemblyName;
    std::string assemblyVersion;
    std::string targetFramework;     // Parsed from assembly attributes
    bool        isILOnly = false;
    bool        is32BitPreferred = false;

    // Metadata statistics
    uint32_t typeDefCount    = 0;
    uint32_t methodDefCount  = 0;
    uint32_t memberRefCount  = 0;
    uint32_t assemblyRefCount = 0;
    uint32_t stringCount     = 0;       // Count of user strings (#US heap)
    uint32_t resourceCount   = 0;

    // Referenced assemblies
    std::vector<std::string> referencedAssemblies;

    // Defined types (capped for output sanity)
    std::vector<std::string> definedTypes;

    // Suspicious API calls detected in MSIL
    std::vector<DotNetAPICall> suspiciousAPICalls;

    // P/Invoke imports (native DLL calls from managed code)
    std::vector<DotNetPInvoke> pInvokeImports;

    // Embedded resources with entropy analysis
    std::vector<DotNetResource> resources;

    // Obfuscation indicators
    std::vector<DotNetObfuscation> obfuscationIndicators;
    std::string detectedObfuscator;  // e.g., "ConfuserEx v1.6.0"

    // Extracted strings from MSIL (deobfuscated or plaintext)
    std::vector<std::string> extractedStrings;

    // Entry point method
    std::string entryPointMethod;

    // Threat indicators
    bool hasReflectionLoading  = false;  // Assembly.Load(byte[])
    bool hasDynamicInvocation  = false;  // MethodInfo.Invoke
    bool hasProcessCreation    = false;  // Process.Start
    bool hasNetworkActivity    = false;  // WebClient/HttpClient/Socket
    bool hasCryptoUsage        = false;  // Any crypto API
    bool hasAntiAnalysis       = false;  // Debugger.IsAttached etc.
    bool hasPInvokeSuspicious  = false;  // VirtualAlloc, CreateRemoteThread, etc.
};

// ============================================================================
// Limits & Safety Constants
// ============================================================================

static constexpr uint32_t kMaxParsedTypes       = 10000;
static constexpr uint32_t kMaxParsedMethods      = 50000;
static constexpr uint32_t kMaxParsedStrings      = 100000;
static constexpr uint32_t kMaxILMethodBodySize   = 16 * 1024 * 1024;  // 16 MB
static constexpr uint32_t kMaxInterpretedInstr   = 5'000'000;
static constexpr uint32_t kMaxEvalStackDepth     = 1024;
static constexpr uint32_t kMaxCallDepth          = 256;
static constexpr uint32_t kMaxSwitchTargets      = 4096;
static constexpr uint32_t kMaxResources          = 1024;
static constexpr uint32_t kMaxExtractedStrings   = 10000;
static constexpr uint32_t kMaxPInvokeImports     = 1024;

} // namespace Phantom::CLR
