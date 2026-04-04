/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PELoader.cpp — PE32/PE64 image loader orchestrator implementation
 *
 * Full PE loading pipeline: parse → validate → allocate → map → relocate →
 * resolve imports → TLS → stack/heap → PEB/TEB. Every step validates input
 * under the assumption of hostile, nation-state-grade adversarial binaries.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "PELoader.hpp"
#include "ExportResolver.hpp"
#include "ImportResolver.hpp"
#include "RelocApplier.hpp"
#include "TLSHandler.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom {

// ============================================================================
// Anonymous helpers
// ============================================================================

namespace {

// 32-bit address space layout constants (64-bit layout lives in WinConst)
constexpr GuestAddress kStackBase32     = 0x00F00000;
constexpr GuestAddress kHeapBase32      = 0x00200000;
constexpr GuestAddress kDllStartBase32  = 0x60000000;
constexpr GuestAddress kDllStartBase64  = 0x0000000180000000ULL;

// Sentinel return addresses written on the stack
constexpr uint64_t kSentinelReturn64 = 0xDEAD'DEAD'DEAD'DEADULL;
constexpr uint32_t kSentinelReturn32 = 0xDEAD'DEAD;

// DLL_PROCESS_ATTACH for DllMain
constexpr uint32_t kDllProcessAttach = 1;

// LDR_DATA offset within the PEB page
constexpr uint32_t kLdrDataOffset        = 0x400;
// ProcessParameters offset within the PEB page
constexpr uint32_t kProcessParamsOffset  = 0x600;

// Safely assign an error detail string (noexcept-safe)
void SetDetail(std::string& target, std::string_view msg) noexcept {
    try { target.assign(msg); } catch (...) {}
}

// Write a scalar value at a specific offset from a base guest address
template <typename T>
ErrorCode WriteAt(VirtualMemory& mem, GuestAddress base, uint32_t offset, T value) noexcept {
    return mem.Write(base + offset, &value, sizeof(T));
}

[[nodiscard]] bool IsTarget64(EmulationTarget t) noexcept {
    return t == EmulationTarget::PE64 ||
           t == EmulationTarget::DLL64 ||
           t == EmulationTarget::Shellcode64;
}

[[nodiscard]] bool IsTargetDLL(EmulationTarget t) noexcept {
    return t == EmulationTarget::DLL32 || t == EmulationTarget::DLL64;
}

[[nodiscard]] bool IsTargetShellcode(EmulationTarget t) noexcept {
    return t == EmulationTarget::Shellcode32 || t == EmulationTarget::Shellcode64;
}

} // anonymous namespace

// ============================================================================
// Constructor
// ============================================================================

PELoader::PELoader(VirtualMemory& memory,
                   ExportResolver& exports,
                   ImportResolver& imports) noexcept
    : m_memory(memory)
    , m_exports(exports)
    , m_imports(imports)
    , m_nextDLLBase(0)
{}

// ============================================================================
// Load — Full PE loading pipeline for the main executable
// ============================================================================

PELoader::LoadResult PELoader::Load(ByteSpan peData,
                                    const EmulationConfig& config) noexcept
{
    LoadResult result{};

    // ---- 1. Parse PE -------------------------------------------------------
    auto parseResult = PEParser::Parse(peData);
    if (!parseResult.Ok()) {
        result.error = parseResult.error;
        SetDetail(result.errorDetail, "PE parsing failed");
        return result;
    }
    result.image.parsedPE = std::move(parseResult.pe);
    const auto& pe = result.image.parsedPE;

    // ---- 2. Validate target matches config ---------------------------------
    const bool configIs64 = IsTarget64(config.target);
    if (pe.is64Bit != configIs64) {
        result.error = ErrorCode::UnsupportedMachine;
        SetDetail(result.errorDetail,
                  pe.is64Bit ? "PE is 64-bit but config expects 32-bit"
                             : "PE is 32-bit but config expects 64-bit");
        return result;
    }
    if (pe.is64Bit && pe.machine != PE::kMachineAMD64) {
        result.error = ErrorCode::UnsupportedMachine;
        SetDetail(result.errorDetail, "64-bit PE has unsupported machine type");
        return result;
    }
    if (!pe.is64Bit && pe.machine != PE::kMachineI386) {
        result.error = ErrorCode::UnsupportedMachine;
        SetDetail(result.errorDetail, "32-bit PE has unsupported machine type");
        return result;
    }
    if (IsTargetShellcode(config.target)) {
        result.error = ErrorCode::InvalidPEHeader;
        SetDetail(result.errorDetail, "Use ShellcodeLoader for shellcode targets");
        return result;
    }

    result.image.is64Bit = pe.is64Bit;
    result.image.isDLL   = pe.isDLL;
    result.image.target  = config.target;

    // Validate image size against config limits
    const GuestSize imageSize = static_cast<GuestSize>(pe.sizeOfImage);
    if (imageSize == 0 || imageSize > config.maxGuestMemory) {
        result.error = ErrorCode::PETooLarge;
        SetDetail(result.errorDetail, "PE image size exceeds memory limit");
        return result;
    }

    // Initialize DLL base addresses on first load
    if (m_nextDLLBase == 0) {
        m_nextDLLBase = pe.is64Bit ? kDllStartBase64 : kDllStartBase32;
    }

    // ---- 3. Allocate image memory ------------------------------------------
    GuestAddress actualBase = 0;
    {
        auto err = AllocateImageMemory(pe, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to allocate image memory");
            return result;
        }
    }
    result.image.imageBase = actualBase;

    const bool needsReloc = (actualBase != pe.imageBase);

    // ---- 4. Map headers ----------------------------------------------------
    {
        auto err = MapHeaders(pe, peData, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to map PE headers");
            return result;
        }
    }

    // ---- 5. Map sections (all as RW initially for reloc/import patching) ---
    {
        auto err = MapSections(pe, peData, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to map PE sections");
            return result;
        }
        result.image.sectionsLoaded = static_cast<uint32_t>(pe.sections.size());
        result.image.totalMapped    = imageSize;
    }

    // ---- 6. Apply relocations (if loaded at different base) ----------------
    if (needsReloc) {
        if (!pe.hasRelocations) {
            result.error = ErrorCode::RelocApplyFail;
            SetDetail(result.errorDetail,
                      "PE requires relocation but has no relocation data");
            return result;
        }

        const auto& relocDir = pe.dataDirectories[PE::kDirBaseReloc];
        auto relocResult = RelocApplier::Apply(
            actualBase,
            pe.imageBase,
            relocDir.VirtualAddress,
            relocDir.Size,
            m_memory);

        if (!relocResult.Ok()) {
            result.error = relocResult.error;
            SetDetail(result.errorDetail, "Relocation application failed");
            return result;
        }
    }

    // ---- 7. Resolve imports ------------------------------------------------
    {
        auto importResult = m_imports.ResolveAll(
            actualBase, m_memory, peData, result.image.is64Bit);
        result.image.imports = std::move(importResult);
    }

    // ---- 8. Apply correct section protections (after patching) -------------
    {
        auto err = ApplySectionProtections(pe, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to apply section protections");
            return result;
        }
    }

    // ---- 9. Parse TLS -----------------------------------------------------
    if (pe.hasTLS && pe.numberOfDataDirectories > PE::kDirTLS) {
        const auto& tlsDir = pe.dataDirectories[PE::kDirTLS];
        if (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) {
            result.image.tlsInfo = TLSHandler::Parse(
                actualBase, tlsDir.VirtualAddress, tlsDir.Size,
                m_memory, result.image.is64Bit);
        }
    }

    // ---- 10. Set up stack --------------------------------------------------
    {
        auto err = SetupStack(result.image, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to allocate stack");
            return result;
        }
    }

    // ---- 11. Set up heap ---------------------------------------------------
    {
        auto err = SetupHeap(result.image, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to allocate heap");
            return result;
        }
    }

    // ---- 12. Create PEB (anti-evasion critical) ----------------------------
    {
        auto err = CreatePEB(result.image, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to create PEB");
            return result;
        }
    }

    // ---- 13. Create TEB (anti-evasion critical) ----------------------------
    {
        auto err = CreateTEB(result.image, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to create TEB");
            return result;
        }
    }

    // ---- 14. Validate and set entry point ----------------------------------
    result.image.entryPoint = actualBase + pe.entryPointRVA;
    if (pe.entryPointRVA == 0 && !pe.isDLL) {
        result.error = ErrorCode::InvalidEntryPoint;
        SetDetail(result.errorDetail, "PE has no entry point");
        return result;
    }
    if (pe.entryPointRVA >= pe.sizeOfImage) {
        result.error = ErrorCode::InvalidEntryPoint;
        SetDetail(result.errorDetail, "Entry point RVA exceeds image size");
        return result;
    }

    return result;
}

// ============================================================================
// LoadDLL — Simplified loader for dependency DLLs
// ============================================================================

PELoader::LoadResult PELoader::LoadDLL(ByteSpan peData,
                                        std::string_view dllName) noexcept
{
    LoadResult result{};

    // ---- 1. Parse PE -------------------------------------------------------
    auto parseResult = PEParser::Parse(peData);
    if (!parseResult.Ok()) {
        result.error = parseResult.error;
        SetDetail(result.errorDetail, "DLL PE parsing failed");
        return result;
    }
    result.image.parsedPE = std::move(parseResult.pe);
    const auto& pe = result.image.parsedPE;

    result.image.is64Bit = pe.is64Bit;
    result.image.isDLL   = true;
    result.image.target  = pe.is64Bit ? EmulationTarget::DLL64
                                      : EmulationTarget::DLL32;

    // Initialize DLL base if not yet set
    if (m_nextDLLBase == 0) {
        m_nextDLLBase = pe.is64Bit ? kDllStartBase64 : kDllStartBase32;
    }

    // ---- 2. Allocate at m_nextDLLBase --------------------------------------
    const GuestSize alignedImageSize = AlignUp(
        static_cast<GuestSize>(pe.sizeOfImage), kPageSize);

    if (alignedImageSize == 0 || alignedImageSize > PE::kMaxPEFileSize) {
        result.error = ErrorCode::PETooLarge;
        SetDetail(result.errorDetail, "DLL image size invalid");
        return result;
    }

    auto baseOpt = m_memory.Allocate(m_nextDLLBase, alignedImageSize, MemProt::RW);
    GuestAddress actualBase = 0;
    if (baseOpt) {
        actualBase = *baseOpt;
    } else {
        // Preferred DLL base unavailable; find any free region
        baseOpt = m_memory.Allocate(0, alignedImageSize, MemProt::RW);
        if (!baseOpt) {
            result.error = ErrorCode::OutOfMemory;
            SetDetail(result.errorDetail, "Failed to allocate DLL image memory");
            return result;
        }
        actualBase = *baseOpt;
    }
    result.image.imageBase = actualBase;

    // Advance next DLL base (64KB alignment granularity, like Windows)
    m_nextDLLBase = AlignUp(actualBase + alignedImageSize, 0x10000);

    // ---- 3. Map headers + sections -----------------------------------------
    {
        auto err = MapHeaders(pe, peData, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to map DLL headers");
            return result;
        }
    }
    {
        auto err = MapSections(pe, peData, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to map DLL sections");
            return result;
        }
        result.image.sectionsLoaded = static_cast<uint32_t>(pe.sections.size());
        result.image.totalMapped    = alignedImageSize;
    }

    // ---- 4. Apply relocations (DLLs almost always need relocation) ---------
    if (actualBase != pe.imageBase && pe.hasRelocations) {
        const auto& relocDir = pe.dataDirectories[PE::kDirBaseReloc];
        if (relocDir.VirtualAddress != 0 && relocDir.Size != 0) {
            auto relocResult = RelocApplier::Apply(
                actualBase,
                pe.imageBase,
                relocDir.VirtualAddress,
                relocDir.Size,
                m_memory);

            if (!relocResult.Ok()) {
                result.error = relocResult.error;
                SetDetail(result.errorDetail, "DLL relocation failed");
                return result;
            }
        }
    }

    // ---- 5. Apply section protections --------------------------------------
    {
        auto err = ApplySectionProtections(pe, actualBase);
        if (err != ErrorCode::Success) {
            result.error = err;
            SetDetail(result.errorDetail, "Failed to apply DLL section protections");
            return result;
        }
    }

    // ---- 6. Register exports via ExportResolver ----------------------------
    {
        auto regErr = m_exports.RegisterModule(actualBase, dllName, peData);
        // Non-fatal: DLL with no exports or parse issue still loads
        static_cast<void>(regErr);
    }

    // Entry point for DLLs (DllMain)
    if (pe.entryPointRVA != 0 && pe.entryPointRVA < pe.sizeOfImage) {
        result.image.entryPoint = actualBase + pe.entryPointRVA;
    }

    return result;
}

// ============================================================================
// PrepareCPUState — Configure CPU registers for execution start
// ============================================================================

void PELoader::PrepareCPUState(CPU& cpu,
                               const LoadedImage& image,
                               const EmulationConfig& config) noexcept
{
    auto& state = cpu.State();

    if (image.is64Bit) {
        // ---- 64-bit mode setup ----
        cpu.Reset64();
        state.SetRIP(image.entryPoint);

        // Stack: simulate a CALL that pushed a return address.
        // x64 ABI: RSP must be 16-byte aligned BEFORE the CALL instruction.
        // After CALL pushes return address, RSP % 16 == 8.
        // We also provide 32 bytes of shadow space above the return address.
        GuestAddress rsp = AlignDown(image.stackTop, 16);
        rsp -= 0x28; // 32-byte shadow space + 8-byte return address

        // Write sentinel return address at [RSP]
        m_memory.WriteU64(rsp, kSentinelReturn64);
        state.SetReg64(GPR::RSP, rsp);

        // Zero all general-purpose registers except RSP
        state.SetReg64(GPR::RAX, 0);
        state.SetReg64(GPR::RCX, 0);
        state.SetReg64(GPR::RDX, 0);
        state.SetReg64(GPR::RBX, 0);
        state.SetReg64(GPR::RBP, 0);
        state.SetReg64(GPR::RSI, 0);
        state.SetReg64(GPR::RDI, 0);
        state.SetReg64(GPR::R8,  0);
        state.SetReg64(GPR::R9,  0);
        state.SetReg64(GPR::R10, 0);
        state.SetReg64(GPR::R11, 0);
        state.SetReg64(GPR::R12, 0);
        state.SetReg64(GPR::R13, 0);
        state.SetReg64(GPR::R14, 0);
        state.SetReg64(GPR::R15, 0);

        // DLL entry: set up DllMain(hinstDLL, fdwReason, lpvReserved)
        if (image.isDLL) {
            state.SetReg64(GPR::RCX, image.imageBase);        // hinstDLL
            state.SetReg64(GPR::RDX, kDllProcessAttach);      // fdwReason
            state.SetReg64(GPR::R8,  0);                      // lpvReserved
        }

        // GS segment base → TEB (critical for anti-evasion)
        state.SetSegmentBase(SegReg::GS, image.tebAddress);

        // Set CS to 64-bit long mode segment
        state.SetSegmentSelector(SegReg::CS, 0x33);
        state.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
        state.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;

    } else {
        // ---- 32-bit mode setup ----
        cpu.Reset32();
        state.SetRIP(image.entryPoint);

        GuestAddress esp = AlignDown(image.stackTop, 4);

        if (image.isDLL) {
            // Push DllMain args right-to-left: lpvReserved, fdwReason, hinstDLL
            esp -= 4;
            m_memory.WriteU32(esp, 0);  // lpvReserved
            esp -= 4;
            m_memory.WriteU32(esp, kDllProcessAttach);  // fdwReason
            esp -= 4;
            m_memory.WriteU32(esp, static_cast<uint32_t>(image.imageBase));  // hinstDLL
        }

        // Push sentinel return address
        esp -= 4;
        m_memory.WriteU32(esp, kSentinelReturn32);

        state.SetReg32(GPR::RSP, static_cast<uint32_t>(esp));

        // Zero all general-purpose registers except ESP
        state.SetReg32(GPR::RAX, 0);
        state.SetReg32(GPR::RCX, 0);
        state.SetReg32(GPR::RDX, 0);
        state.SetReg32(GPR::RBX, 0);
        state.SetReg32(GPR::RBP, 0);
        state.SetReg32(GPR::RSI, 0);
        state.SetReg32(GPR::RDI, 0);

        // FS segment base → TEB (32-bit uses FS, not GS)
        state.SetSegmentBase(SegReg::FS, image.tebAddress);

        // Set CS to 32-bit protected mode segment
        state.SetSegmentSelector(SegReg::CS, 0x23);
        state.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = false;
        state.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = true;
    }
}

// ============================================================================
// AllocateImageMemory — Reserve guest address space for the PE image
// ============================================================================

ErrorCode PELoader::AllocateImageMemory(const ParsedPE& pe,
                                        GuestAddress& actualBase) noexcept
{
    const GuestSize imageSize = AlignUp(
        static_cast<GuestSize>(pe.sizeOfImage), kPageSize);

    if (imageSize == 0) {
        return ErrorCode::MalformedPE;
    }

    // Try preferred ImageBase first
    auto result = m_memory.Allocate(pe.imageBase, imageSize, MemProt::RW);
    if (result) {
        actualBase = *result;
        return ErrorCode::Success;
    }

    // Preferred base unavailable — find any free region
    result = m_memory.Allocate(0, imageSize, MemProt::RW);
    if (!result) {
        return ErrorCode::OutOfMemory;
    }

    actualBase = *result;
    return ErrorCode::Success;
}

// ============================================================================
// MapHeaders — Copy PE headers into guest memory
// ============================================================================

ErrorCode PELoader::MapHeaders(const ParsedPE& pe,
                               ByteSpan peData,
                               GuestAddress actualBase) noexcept
{
    if (pe.sizeOfHeaders == 0) {
        return ErrorCode::MalformedPE;
    }

    // Bound check: sizeOfHeaders must not exceed the file data
    const uint32_t headerBytes = std::min(
        pe.sizeOfHeaders,
        static_cast<uint32_t>(peData.size()));

    if (headerBytes == 0) {
        return ErrorCode::MalformedPE;
    }

    auto err = m_memory.MapRegion(
        actualBase,
        peData.data(),
        headerBytes,
        static_cast<GuestSize>(pe.sizeOfHeaders),
        MemProt::RW);  // RW initially; set to Read-only after patching

    return err;
}

// ============================================================================
// MapSections — Copy each PE section into guest memory
// ============================================================================

ErrorCode PELoader::MapSections(const ParsedPE& pe,
                                ByteSpan peData,
                                GuestAddress actualBase) noexcept
{
    for (const auto& section : pe.sections) {
        if (section.virtualSize == 0 && section.rawDataSize == 0) {
            continue; // Skip empty sections
        }

        const GuestAddress sectionBase = actualBase + section.virtualAddress;
        const GuestSize    virtualSize = static_cast<GuestSize>(section.virtualSize);

        // Validate section doesn't exceed image bounds
        if (section.virtualAddress >= pe.sizeOfImage) {
            return ErrorCode::SectionOverflow;
        }
        if (static_cast<uint64_t>(section.virtualAddress) + virtualSize >
            static_cast<uint64_t>(pe.sizeOfImage)) {
            return ErrorCode::SectionOverflow;
        }

        // Determine how much raw data to copy
        uint32_t copySize = 0;
        const uint8_t* sourceData = nullptr;

        if (section.rawDataSize > 0 && section.rawDataOffset > 0) {
            // Validate raw data bounds against the file
            if (section.rawDataOffset >= peData.size()) {
                return ErrorCode::MalformedPE;
            }
            const uint64_t available =
                peData.size() - section.rawDataOffset;
            copySize = static_cast<uint32_t>(
                std::min(static_cast<uint64_t>(section.rawDataSize), available));
            // Don't copy more than virtualSize
            copySize = std::min(copySize, section.virtualSize);
            sourceData = peData.data() + section.rawDataOffset;
        }

        // Map section: copy raw data, zero-fill remainder, apply RW initially
        auto err = m_memory.MapRegion(
            sectionBase,
            sourceData,
            copySize,
            virtualSize,
            MemProt::RW);  // RW for relocation/import patching; corrected later

        if (err != ErrorCode::Success) {
            return err;
        }
    }

    return ErrorCode::Success;
}

// ============================================================================
// ApplySectionProtections — Set correct R/W/X after relocation and import
//                           patching is complete
// ============================================================================

ErrorCode PELoader::ApplySectionProtections(const ParsedPE& pe,
                                            GuestAddress imageBase) noexcept
{
    // Headers: read-only
    const GuestSize headerSize = AlignUp(
        static_cast<GuestSize>(pe.sizeOfHeaders), kPageSize);
    if (headerSize > 0) {
        m_memory.Protect(imageBase, headerSize, MemProt::Read);
    }

    for (const auto& section : pe.sections) {
        if (section.virtualSize == 0) continue;

        const GuestAddress sectionBase = imageBase + section.virtualAddress;
        const GuestSize    sectionSize = AlignUp(
            static_cast<GuestSize>(section.virtualSize), kPageSize);

        const auto prot = static_cast<MemProt>(
            PE::SectionToMemProt(section.characteristics));

        if (!m_memory.Protect(sectionBase, sectionSize, prot)) {
            return ErrorCode::InvalidAddress;
        }
    }

    return ErrorCode::Success;
}

// ============================================================================
// SetupStack — Allocate stack with guard page at bottom
// ============================================================================

ErrorCode PELoader::SetupStack(LoadedImage& image,
                               const EmulationConfig& config) noexcept
{
    const GuestSize stackSize = AlignUp(
        config.stackSize > 0 ? config.stackSize : kStackSize, kPageSize);

    // Choose stack base address based on bitness
    const GuestAddress preferredStackBase =
        image.is64Bit ? WinConst::kStackBase64 : kStackBase32;

    auto stackOpt = m_memory.Allocate(preferredStackBase, stackSize, MemProt::RW);
    if (!stackOpt) {
        // Try any free region
        stackOpt = m_memory.Allocate(0, stackSize, MemProt::RW);
        if (!stackOpt) {
            return ErrorCode::OutOfMemory;
        }
    }

    image.stackBase = *stackOpt;
    image.stackTop  = image.stackBase + stackSize;

    // Guard page at the bottom of the stack for overflow detection
    m_memory.Protect(image.stackBase, kPageSize, MemProt::RW | MemProt::Guard);

    return ErrorCode::Success;
}

// ============================================================================
// SetupHeap — Allocate initial process heap region
// ============================================================================

ErrorCode PELoader::SetupHeap(LoadedImage& image,
                              const EmulationConfig& config) noexcept
{
    const GuestSize heapSize = AlignUp(
        config.heapSize > 0 ? config.heapSize : kHeapInitial, kPageSize);

    const GuestAddress preferredHeapBase =
        image.is64Bit ? WinConst::kProcessHeapBase64 : kHeapBase32;

    auto heapOpt = m_memory.Allocate(preferredHeapBase, heapSize, MemProt::RW);
    if (!heapOpt) {
        heapOpt = m_memory.Allocate(0, heapSize, MemProt::RW);
        if (!heapOpt) {
            return ErrorCode::OutOfMemory;
        }
    }

    image.heapBase = *heapOpt;
    return ErrorCode::Success;
}

// ============================================================================
// CreatePEB — Build a fake Process Environment Block
//
// The PEB is CRITICAL for anti-evasion. Malware constantly reads it to:
//   - Check BeingDebugged (offset 0x002)
//   - Check NtGlobalFlag (anti-debug)
//   - Walk Ldr→InLoadOrderModuleList to find DLL bases
//   - Read ProcessHeap to detect heap flags
//   - Read OS version info
//
// Layout must match Windows 10/11 x64 or x86 depending on target bitness.
// ============================================================================

ErrorCode PELoader::CreatePEB(LoadedImage& image,
                              const EmulationConfig& config) noexcept
{
    const GuestAddress pebAddr =
        image.is64Bit ? WinConst::kPEBAddress64 : WinConst::kPEBAddress64;
    // PEB and TEB addresses fit in 32-bit range; same constant works for both

    // Allocate one page for PEB + LDR_DATA + ProcessParameters
    auto pebOpt = m_memory.Allocate(pebAddr, kPageSize, MemProt::RW);
    if (!pebOpt) {
        pebOpt = m_memory.Allocate(0, kPageSize, MemProt::RW);
        if (!pebOpt) return ErrorCode::OutOfMemory;
    }
    image.pebAddress = *pebOpt;

    const GuestAddress peb = image.pebAddress;
    const GuestAddress ldrAddr = peb + kLdrDataOffset;
    const GuestAddress paramsAddr = peb + kProcessParamsOffset;

    ErrorCode err = ErrorCode::Success;

    if (image.is64Bit) {
        // ================================================================
        // x64 PEB layout (Windows 10 22H2)
        // ================================================================

        // +0x002: BeingDebugged = 0 (anti-debug: malware checks this first)
        err = WriteAt(m_memory, peb, 0x002, static_cast<uint8_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x008: Mutant = -1 (default process mutex handle)
        err = WriteAt(m_memory, peb, 0x008, static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL));
        if (err != ErrorCode::Success) return err;

        // +0x010: ImageBaseAddress
        err = WriteAt(m_memory, peb, 0x010, image.imageBase);
        if (err != ErrorCode::Success) return err;

        // +0x018: Ldr (pointer to PEB_LDR_DATA)
        err = WriteAt(m_memory, peb, 0x018, ldrAddr);
        if (err != ErrorCode::Success) return err;

        // +0x020: ProcessParameters
        err = WriteAt(m_memory, peb, 0x020, paramsAddr);
        if (err != ErrorCode::Success) return err;

        // +0x030: ProcessHeap
        err = WriteAt(m_memory, peb, 0x030, image.heapBase);
        if (err != ErrorCode::Success) return err;

        // +0x0BC: NumberOfProcessors
        err = WriteAt(m_memory, peb, 0x0BC, config.processorCount);
        if (err != ErrorCode::Success) return err;

        // +0x0E8: OSMajorVersion = 10
        err = WriteAt(m_memory, peb, 0x0E8, static_cast<uint32_t>(10));
        if (err != ErrorCode::Success) return err;

        // +0x0EC: OSMinorVersion = 0
        err = WriteAt(m_memory, peb, 0x0EC, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x0F0: OSBuildNumber = 19045 (Win10 22H2)
        err = WriteAt(m_memory, peb, 0x0F0, static_cast<uint16_t>(config.osBuildNumber));
        if (err != ErrorCode::Success) return err;

        // +0x0F2: OSCSDVersion = 0
        err = WriteAt(m_memory, peb, 0x0F2, static_cast<uint16_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x0F4: OSPlatformId = 2 (VER_PLATFORM_WIN32_NT)
        err = WriteAt(m_memory, peb, 0x0F4, static_cast<uint32_t>(2));
        if (err != ErrorCode::Success) return err;

        // +0x118: NtGlobalFlag = 0 (CRITICAL: anti-debug check)
        // Debuggers set FLG_HEAP_ENABLE_TAIL_CHECK etc. We ensure zero.
        err = WriteAt(m_memory, peb, 0x118, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // ---- PEB_LDR_DATA at ldrAddr (x64) ----
        // Empty circular lists (list heads point to themselves)

        // +0x000: Length
        err = WriteAt(m_memory, ldrAddr, 0x000, static_cast<uint32_t>(0x58));
        if (err != ErrorCode::Success) return err;

        // +0x004: Initialized = TRUE
        err = WriteAt(m_memory, ldrAddr, 0x004, static_cast<uint8_t>(1));
        if (err != ErrorCode::Success) return err;

        // InLoadOrderModuleList (offset 0x010): Flink and Blink → self
        const GuestAddress inLoadOrderListHead = ldrAddr + 0x010;
        err = WriteAt(m_memory, ldrAddr, 0x010, inLoadOrderListHead);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x018, inLoadOrderListHead);
        if (err != ErrorCode::Success) return err;

        // InMemoryOrderModuleList (offset 0x020): Flink and Blink → self
        const GuestAddress inMemOrderListHead = ldrAddr + 0x020;
        err = WriteAt(m_memory, ldrAddr, 0x020, inMemOrderListHead);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x028, inMemOrderListHead);
        if (err != ErrorCode::Success) return err;

        // InInitializationOrderModuleList (offset 0x030): Flink and Blink → self
        const GuestAddress inInitOrderListHead = ldrAddr + 0x030;
        err = WriteAt(m_memory, ldrAddr, 0x030, inInitOrderListHead);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x038, inInitOrderListHead);
        if (err != ErrorCode::Success) return err;

        // ---- RTL_USER_PROCESS_PARAMETERS at paramsAddr (x64) ----
        // +0x000: MaximumLength
        err = WriteAt(m_memory, paramsAddr, 0x000, static_cast<uint32_t>(0x200));
        if (err != ErrorCode::Success) return err;

        // +0x004: Length
        err = WriteAt(m_memory, paramsAddr, 0x004, static_cast<uint32_t>(0x200));
        if (err != ErrorCode::Success) return err;

        // +0x008: Flags = RTL_USER_PROC_PARAMS_NORMALIZED (1)
        err = WriteAt(m_memory, paramsAddr, 0x008, static_cast<uint32_t>(1));
        if (err != ErrorCode::Success) return err;

        // +0x00C: DebugFlags = 0 (anti-debug)
        err = WriteAt(m_memory, paramsAddr, 0x00C, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

    } else {
        // ================================================================
        // x86 PEB layout (Windows 10 22H2)
        // ================================================================

        // +0x002: BeingDebugged = 0
        err = WriteAt(m_memory, peb, 0x002, static_cast<uint8_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x004: Mutant = -1
        err = WriteAt(m_memory, peb, 0x004, static_cast<uint32_t>(0xFFFFFFFF));
        if (err != ErrorCode::Success) return err;

        // +0x008: ImageBaseAddress
        err = WriteAt(m_memory, peb, 0x008, static_cast<uint32_t>(image.imageBase));
        if (err != ErrorCode::Success) return err;

        // +0x00C: Ldr
        err = WriteAt(m_memory, peb, 0x00C, static_cast<uint32_t>(ldrAddr));
        if (err != ErrorCode::Success) return err;

        // +0x010: ProcessParameters
        err = WriteAt(m_memory, peb, 0x010, static_cast<uint32_t>(paramsAddr));
        if (err != ErrorCode::Success) return err;

        // +0x018: ProcessHeap
        err = WriteAt(m_memory, peb, 0x018, static_cast<uint32_t>(image.heapBase));
        if (err != ErrorCode::Success) return err;

        // +0x064: NumberOfProcessors
        err = WriteAt(m_memory, peb, 0x064, config.processorCount);
        if (err != ErrorCode::Success) return err;

        // +0x068: NtGlobalFlag = 0
        err = WriteAt(m_memory, peb, 0x068, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x0A4: OSMajorVersion = 10
        err = WriteAt(m_memory, peb, 0x0A4, static_cast<uint32_t>(10));
        if (err != ErrorCode::Success) return err;

        // +0x0A8: OSMinorVersion = 0
        err = WriteAt(m_memory, peb, 0x0A8, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x0AC: OSBuildNumber = 19045
        err = WriteAt(m_memory, peb, 0x0AC, static_cast<uint16_t>(config.osBuildNumber));
        if (err != ErrorCode::Success) return err;

        // +0x0AE: OSCSDVersion = 0
        err = WriteAt(m_memory, peb, 0x0AE, static_cast<uint16_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x0B0: OSPlatformId = 2
        err = WriteAt(m_memory, peb, 0x0B0, static_cast<uint32_t>(2));
        if (err != ErrorCode::Success) return err;

        // ---- PEB_LDR_DATA at ldrAddr (x86) ----

        // +0x000: Length
        err = WriteAt(m_memory, ldrAddr, 0x000, static_cast<uint32_t>(0x30));
        if (err != ErrorCode::Success) return err;

        // +0x004: Initialized = TRUE
        err = WriteAt(m_memory, ldrAddr, 0x004, static_cast<uint8_t>(1));
        if (err != ErrorCode::Success) return err;

        // InLoadOrderModuleList (offset 0x00C): Flink and Blink → self
        const uint32_t inLoadOrderListHead32 = static_cast<uint32_t>(ldrAddr + 0x00C);
        err = WriteAt(m_memory, ldrAddr, 0x00C, inLoadOrderListHead32);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x010, inLoadOrderListHead32);
        if (err != ErrorCode::Success) return err;

        // InMemoryOrderModuleList (offset 0x014): Flink and Blink → self
        const uint32_t inMemOrderListHead32 = static_cast<uint32_t>(ldrAddr + 0x014);
        err = WriteAt(m_memory, ldrAddr, 0x014, inMemOrderListHead32);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x018, inMemOrderListHead32);
        if (err != ErrorCode::Success) return err;

        // InInitializationOrderModuleList (offset 0x01C): Flink and Blink → self
        const uint32_t inInitOrderListHead32 = static_cast<uint32_t>(ldrAddr + 0x01C);
        err = WriteAt(m_memory, ldrAddr, 0x01C, inInitOrderListHead32);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x020, inInitOrderListHead32);
        if (err != ErrorCode::Success) return err;

        // ---- RTL_USER_PROCESS_PARAMETERS at paramsAddr (x86) ----
        err = WriteAt(m_memory, paramsAddr, 0x000, static_cast<uint32_t>(0x100));
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, paramsAddr, 0x004, static_cast<uint32_t>(0x100));
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, paramsAddr, 0x008, static_cast<uint32_t>(1));
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, paramsAddr, 0x00C, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;
    }

    return ErrorCode::Success;
}

// ============================================================================
// CreateTEB — Build a fake Thread Environment Block
//
// The TEB is accessed via GS:[0] (x64) or FS:[0] (x86). Malware reads:
//   - TEB.Self to find its own TEB address
//   - TEB→PEB to find the PEB (then walks Ldr lists)
//   - TEB.StackBase / StackLimit for anti-analysis stack checks
// ============================================================================

ErrorCode PELoader::CreateTEB(LoadedImage& image,
                              const EmulationConfig& config) noexcept
{
    const GuestAddress tebAddr =
        image.is64Bit ? WinConst::kTEBAddress64 : WinConst::kTEBAddress64;

    auto tebOpt = m_memory.Allocate(tebAddr, kPageSize, MemProt::RW);
    if (!tebOpt) {
        tebOpt = m_memory.Allocate(0, kPageSize, MemProt::RW);
        if (!tebOpt) return ErrorCode::OutOfMemory;
    }
    image.tebAddress = *tebOpt;

    const GuestAddress teb = image.tebAddress;
    ErrorCode err = ErrorCode::Success;

    if (image.is64Bit) {
        // ================================================================
        // x64 TEB layout (Windows 10 22H2)
        // ================================================================

        // +0x000: ExceptionList (NT_TIB) = 0 (x64 uses unwind tables, not SEH chain)
        err = WriteAt(m_memory, teb, 0x000, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x008: StackBase (high address — top of stack)
        err = WriteAt(m_memory, teb, 0x008, image.stackTop);
        if (err != ErrorCode::Success) return err;

        // +0x010: StackLimit (low address — bottom of committed stack, above guard)
        const GuestAddress stackLimit = image.stackBase + kPageSize; // above guard page
        err = WriteAt(m_memory, teb, 0x010, stackLimit);
        if (err != ErrorCode::Success) return err;

        // +0x018: SubSystemTib = 0
        err = WriteAt(m_memory, teb, 0x018, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x020: FiberData / Version = 0x1E00 (version indicator)
        err = WriteAt(m_memory, teb, 0x020, static_cast<uint64_t>(0x1E00));
        if (err != ErrorCode::Success) return err;

        // +0x028: ArbitraryUserPointer = 0
        err = WriteAt(m_memory, teb, 0x028, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x030: Self (points to TEB itself — CRITICAL for GS:[0x30] access)
        err = WriteAt(m_memory, teb, 0x030, teb);
        if (err != ErrorCode::Success) return err;

        // +0x038: EnvironmentPointer = 0
        err = WriteAt(m_memory, teb, 0x038, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x040: ClientId.UniqueProcess (fake PID)
        err = WriteAt(m_memory, teb, 0x040, static_cast<uint64_t>(4096));
        if (err != ErrorCode::Success) return err;

        // +0x048: ClientId.UniqueThread (fake TID)
        err = WriteAt(m_memory, teb, 0x048, static_cast<uint64_t>(4100));
        if (err != ErrorCode::Success) return err;

        // +0x060: PEB pointer
        err = WriteAt(m_memory, teb, 0x060, image.pebAddress);
        if (err != ErrorCode::Success) return err;

        // +0x068: LastErrorValue = 0
        err = WriteAt(m_memory, teb, 0x068, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

    } else {
        // ================================================================
        // x86 TEB layout (Windows 10 22H2)
        // ================================================================

        // +0x000: ExceptionList = 0xFFFFFFFF (end of SEH chain)
        err = WriteAt(m_memory, teb, 0x000, static_cast<uint32_t>(0xFFFFFFFF));
        if (err != ErrorCode::Success) return err;

        // +0x004: StackBase (high address)
        err = WriteAt(m_memory, teb, 0x004, static_cast<uint32_t>(image.stackTop));
        if (err != ErrorCode::Success) return err;

        // +0x008: StackLimit (low address, above guard page)
        const uint32_t stackLimit32 =
            static_cast<uint32_t>(image.stackBase + kPageSize);
        err = WriteAt(m_memory, teb, 0x008, stackLimit32);
        if (err != ErrorCode::Success) return err;

        // +0x00C: SubSystemTib = 0
        err = WriteAt(m_memory, teb, 0x00C, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x010: FiberData / Version
        err = WriteAt(m_memory, teb, 0x010, static_cast<uint32_t>(0x1E00));
        if (err != ErrorCode::Success) return err;

        // +0x014: ArbitraryUserPointer = 0
        err = WriteAt(m_memory, teb, 0x014, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x018: Self (FS:[0x18] → TEB)
        err = WriteAt(m_memory, teb, 0x018, static_cast<uint32_t>(teb));
        if (err != ErrorCode::Success) return err;

        // +0x020: EnvironmentPointer = 0
        err = WriteAt(m_memory, teb, 0x020, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // +0x024: ClientId.UniqueProcess
        err = WriteAt(m_memory, teb, 0x024, static_cast<uint32_t>(4096));
        if (err != ErrorCode::Success) return err;

        // +0x028: ClientId.UniqueThread
        err = WriteAt(m_memory, teb, 0x028, static_cast<uint32_t>(4100));
        if (err != ErrorCode::Success) return err;

        // +0x030: PEB pointer
        err = WriteAt(m_memory, teb, 0x030, static_cast<uint32_t>(image.pebAddress));
        if (err != ErrorCode::Success) return err;

        // +0x034: LastErrorValue = 0
        err = WriteAt(m_memory, teb, 0x034, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;
    }

    return ErrorCode::Success;
}

} // namespace Phantom
