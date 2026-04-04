/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * UnpackingEngine.hpp — Generic unpacking via emulation-based W→X heuristics
 *
 * Detects and extracts packed/encrypted malware payloads through:
 *   - W→X transition monitoring (write to memory, then execute it)
 *   - Known packer signature detection (100+ packers)
 *   - Multi-layer unpacking (e.g. UPX wrapped in Themida)
 *   - Original Entry Point (OEP) detection via scored heuristic fusion
 *   - Memory snapshot management per unpack layer
 *   - Import Address Table reconstruction from API call traces
 *   - Shannon entropy tracking as an unpacking progress indicator
 *   - Clean PE file extraction from emulated guest memory
 *   - VM deobfuscation engine (FinFisher, Themida, VMProtect, etc.)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <utility>

namespace Phantom {

// Forward declarations — defined in Core/Memory/
class VirtualMemory;
class MemoryTracker;

// ============================================================================
// Known Packer Identifiers
// ============================================================================

enum class PackerType : uint8_t {
    Unknown = 0,
    // --- Original packers (1–30) ---
    UPX,
    ASPack,
    PECompact,
    Themida,
    VMProtect,
    Armadillo,
    MPRESS,
    Petite,
    FSG,
    MEW,
    NsPack,
    PEtite,
    Obsidium,
    ExeCryptor,
    ASProtect,
    tElock,
    PESpin,
    MoleBox,
    BoxedApp,
    Enigma,
    StarForce,
    SafeDisc,
    SecuROM,
    CodeVirtualizer,
    PackerCustom,
    DotNetObfuscator,
    AutoIt,
    NSIS,
    InnoSetup,
    PyInstaller,

    // --- Commercial protectors ---
    PELock,
    ACProtect,
    SafeEngine,
    WinLicense,
    CodeWall,
    PrivateEXE,
    PCGuard,
    GameGuard,
    Denuvo,

    // --- VMProtect/Themida version variants ---
    VMProtect1x,
    VMProtect2x,
    ThemidaV1,
    ThemidaV2,

    // --- Packers ---
    RLPack,
    nPack,
    WinUpack,
    JDPack,
    BeRoEXE,
    Packman,
    YodaCrypt,
    PEBundle,
    DotFixNice,
    PEX,
    AlexProtect,
    AntiCrack,
    kkrunchy,
    CrunchCexe,
    UPXModified,

    // --- .NET / Managed ---
    ConfuserEx,
    Dotfuscator,

    // --- Scripting languages ---
    AutoHotkey,
    PyArmor,
    Cython,

    // --- Go binary ---
    GoBinary,

    // --- Installer / SFX ---
    SevenZipSFX,
    WinRARSFX,
    WinZipSFX,
    InstallShield,
    WiseInstaller,

    // --- VM-based protectors ---
    TigerVMP,
    ReWolf,

    // --- Additional protectors ---
    ExeCryptorV2,
    PECompactV3,
    PetiteV21,
    PetiteV22,
    PetiteV23,
    NSISVariant,
    InnoSetupVariant,
    ElectronASAR,
    SmartAssembly,
    Eazfuscator,
    BabelNet,
    DNGuard,
    NetReactor,
    MaxtoCode,
    Agile,
    Xenocode,
    Spoon,
    BoxedAppVariant,
    MoleBoxUltra,
    PECompactV2,
    UPXScrambled,
    ASPackV2,
    NSPackV3,
    MPRESSv2,
    FSGv2,
    MEWv11,
    PESpinV1,
    tElockV098,
    ObsidiumV1,
    ArmadilloV9,
    ThemidaV3,
};

/// Human-readable name for a packer type.
[[nodiscard]] const char* PackerTypeName(PackerType type) noexcept;

// ============================================================================
// VM Architecture Identifiers (for virtualized/obfuscated code)
// ============================================================================

enum class VMArch : uint8_t {
    Unknown = 0,
    FinFisher,        ///< Complex: 32 virtual registers, stack-based
    Themida,          ///< CISC-like VM with ~120 handlers
    VMProtect,        ///< RISC-like VM, variable handler count
    CodeVirtualizer,  ///< Oreans (same family as Themida)
    TigerVMP,         ///< Chinese packer, register-based VM
    ReWolf,           ///< Open-source VM protector
    Custom,           ///< Unknown/custom VM detected by heuristics
};

// ============================================================================
// VM Handler Classification
// ============================================================================

enum class VMHandlerType : uint8_t {
    Unknown = 0,
    VMAdd, VMSub, VMMul, VMDiv,
    VMAnd, VMOr, VMXor, VMNot, VMShl, VMShr, VMRol, VMRor,
    VMPush, VMPop, VMLoad, VMStore,
    VMJmp, VMJcc, VMCall, VMRet,
    VMNop, VMVmExit, VMVmEntry,
    VMSyscall, VMObfuscated,
};

// ============================================================================
// VM Handler Info — describes a single virtual instruction handler
// ============================================================================

struct VMHandlerInfo {
    GuestAddress address;            ///< Handler entry address
    uint8_t      opcodeValue;        ///< Virtual opcode this handler processes
    uint16_t     instructionCount;   ///< x86 instructions in handler body
    VMHandlerType handlerType;       ///< Classified type
};

// ============================================================================
// VM Analysis Result — aggregate output from AnalyzeVirtualMachine()
// ============================================================================

struct VMAnalysisResult {
    VMArch       architecture       = VMArch::Unknown;
    float        confidence         = 0.0f;       ///< 0.0-1.0
    GuestAddress vmEntryPoint       = 0;           ///< Where native code enters the VM
    GuestAddress vmDispatcher       = 0;           ///< The main dispatcher loop
    GuestAddress vmHandlerTable     = 0;           ///< Base of handler pointer array
    uint32_t     handlerCount       = 0;           ///< Number of detected handlers
    uint32_t     virtualRegCount    = 0;           ///< Detected virtual register count
    bool         usesIndirectDispatch = false;      ///< JMP [table + index*8] pattern
    bool         usesComputedGoto    = false;       ///< ADD reg, offset; JMP reg pattern
    bool         hasOpaquePredicates = false;       ///< Anti-analysis: always-true/false
    bool         hasHandlerReordering = false;      ///< Handlers not sequential
    std::vector<VMHandlerInfo> handlers;
};

// ============================================================================
// OEP Detection Method
// ============================================================================

enum class OEPMethod : uint8_t {
    WXTransition,        ///< Standard W→X page transition
    TailJump,            ///< Long unconditional jump after a decoder loop
    APICallAfterDecode,  ///< First API call following a long API-free sequence
    EntropyDrop,         ///< Shannon entropy drops significantly
    IATReconstruction,   ///< Import Address Table becomes structurally valid
    StackFrame,          ///< Standard function prologue at a new location
    SectionEntry,        ///< Execution enters .text after being in a packer section
    UserDefined,         ///< Breakpoint set externally by the caller
};

// ============================================================================
// UnpackLayer — State captured at each unpacking stage
// ============================================================================

struct UnpackLayer {
    uint32_t     layerIndex          = 0;
    GuestAddress entryPoint          = 0;      ///< Entry point of this layer
    GuestAddress oep                 = 0;      ///< Detected OEP (0 = not yet found)
    OEPMethod    oepMethod           = OEPMethod::WXTransition;
    PackerType   packer              = PackerType::Unknown;
    double       entropyBefore       = 0.0;    ///< Entropy when layer started
    double       entropyAfter        = 0.0;    ///< Entropy at OEP detection
    uint64_t     instructionsExecuted = 0;
    uint64_t     wxTransitions       = 0;
    GuestAddress codeBase            = 0;      ///< Base of unpacked code region
    GuestSize    codeSize            = 0;      ///< Size of unpacked code region
    std::vector<uint8_t> dumpedPE;             ///< Extracted PE (may be empty)
    bool         importTableValid    = false;
    bool         isComplete          = false;
};

// ============================================================================
// UnpackConfig — Tuning knobs for the unpacking engine
// ============================================================================

struct UnpackConfig {
    uint32_t maxLayers                  = 16;
    uint64_t maxInstructionsPerLayer    = 50'000'000;
    uint32_t minOEPInstructions         = 50;
    double   entropyThreshold           = 7.0;
    double   entropyDropThreshold       = 1.5;
    bool     captureEveryLayer          = true;
    bool     enableImportReconstruction = true;
    bool     enablePackerDetection      = true;
    uint32_t maxDumpSize                = 64u * 1024u * 1024u;
};

// ============================================================================
// UnpackingEngine
// ============================================================================
//
// Usage:
//   1. Construct with an EmulationConfig.
//   2. Wire OnWXTransition / OnInstruction / OnProtectionChange / OnAPICall
//      into the emulation loop callbacks.
//   3. After emulation, query GetFinalOEP(), GetLayers(), DumpPE(), etc.
//
// Thread-safety: all public methods are safe to call from any thread.
// The event callbacks are expected to be called from the emulation thread;
// the query / analysis methods may be called from a monitoring thread.

class UnpackingEngine {
public:
    explicit UnpackingEngine(const EmulationConfig& config) noexcept;
    ~UnpackingEngine() noexcept;

    UnpackingEngine(const UnpackingEngine&) = delete;
    UnpackingEngine& operator=(const UnpackingEngine&) = delete;
    UnpackingEngine(UnpackingEngine&&) noexcept;
    UnpackingEngine& operator=(UnpackingEngine&&) noexcept;

    // === Event Callbacks (called by the emulation loop) ====================

    /// Notify that execution entered a page that was previously written.
    void OnWXTransition(const VirtualMemory& memory,
                        const MemoryTracker& tracker,
                        GuestAddress page,
                        GuestAddress rip,
                        uint64_t instrCount) noexcept;

    /// Lightweight per-instruction callback — only does real work while
    /// unpacking is being tracked.
    void OnInstruction(GuestAddress rip, uint64_t instrCount) noexcept;

    /// Called when VirtualProtect changes protection on a region.
    void OnProtectionChange(GuestAddress base, GuestSize size,
                            MemProt oldProt, MemProt newProt) noexcept;

    /// Called whenever an emulated API call is dispatched.
    void OnAPICall(const char* funcName, uint64_t instrCount) noexcept;

    // === Layer Management ==================================================

    [[nodiscard]] uint32_t                      GetCurrentLayer()  const noexcept;
    [[nodiscard]] const std::vector<UnpackLayer>& GetLayers()      const noexcept;
    [[nodiscard]] bool                          IsUnpacking()      const noexcept;
    [[nodiscard]] bool                          IsComplete()       const noexcept;

    // === OEP Detection =====================================================

    [[nodiscard]] GuestAddress GetFinalOEP()   const noexcept;
    [[nodiscard]] OEPMethod    GetOEPMethod()  const noexcept;

    // === Packer Detection ==================================================

    /// Scan PE headers and code at imageBase for known packer signatures.
    [[nodiscard]] PackerType DetectPacker(const VirtualMemory& memory,
                                          GuestAddress imageBase,
                                          GuestSize imageSize) const noexcept;

    // === VM Analysis =======================================================

    /// Detect if the binary contains virtualized code (FinFisher, Themida,
    /// VMProtect, CodeVirtualizer, etc.) by locating VM entry points,
    /// dispatcher loops, and handler tables.
    [[nodiscard]] VMAnalysisResult AnalyzeVirtualMachine(
        const VirtualMemory& memory,
        GuestAddress imageBase,
        GuestSize imageSize) const noexcept;

    /// Get the detected VM architecture from the most recent analysis.
    [[nodiscard]] VMArch GetDetectedVM() const noexcept;

    // === PE Dumping ========================================================

    /// Reconstruct a valid PE file from guest memory.
    [[nodiscard]] std::vector<uint8_t> DumpPE(const VirtualMemory& memory,
                                               GuestAddress imageBase,
                                               GuestSize imageSize) const noexcept;

    // === Import Reconstruction =============================================

    /// Validate or rebuild the IAT using tracked API call patterns.
    [[nodiscard]] bool ReconstructImports(VirtualMemory& memory,
                                          GuestAddress imageBase,
                                          GuestSize imageSize) noexcept;

    // === Entropy Tracking ==================================================

    [[nodiscard]] double GetCurrentEntropy() const noexcept;
    [[nodiscard]] std::vector<std::pair<uint64_t, double>>
                  GetEntropyHistory() const noexcept;

    // === Control ===========================================================

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
