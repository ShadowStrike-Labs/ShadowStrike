/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * UnpackingEngine.cpp — Generic unpacking engine implementation
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "UnpackingEngine.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Core/Memory/MemoryTracker.hpp"
#include "../Core/Loader/PEStructures.hpp"
#include "../Common/Errors.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <functional>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// PackerTypeName
// ============================================================================

const char* PackerTypeName(PackerType type) noexcept {
    switch (type) {
        case PackerType::Unknown:           return "Unknown";
        case PackerType::UPX:               return "UPX";
        case PackerType::ASPack:            return "ASPack";
        case PackerType::PECompact:         return "PECompact";
        case PackerType::Themida:           return "Themida/WinLicense";
        case PackerType::VMProtect:         return "VMProtect";
        case PackerType::Armadillo:         return "Armadillo";
        case PackerType::MPRESS:            return "MPRESS";
        case PackerType::Petite:            return "Petite";
        case PackerType::FSG:               return "FSG";
        case PackerType::MEW:               return "MEW";
        case PackerType::NsPack:            return "NsPack";
        case PackerType::PEtite:            return "PEtite";
        case PackerType::Obsidium:          return "Obsidium";
        case PackerType::ExeCryptor:        return "ExeCryptor";
        case PackerType::ASProtect:         return "ASProtect";
        case PackerType::tElock:            return "tElock";
        case PackerType::PESpin:            return "PESpin";
        case PackerType::MoleBox:           return "MoleBox";
        case PackerType::BoxedApp:          return "BoxedApp";
        case PackerType::Enigma:            return "Enigma Protector";
        case PackerType::StarForce:         return "StarForce";
        case PackerType::SafeDisc:          return "SafeDisc";
        case PackerType::SecuROM:           return "SecuROM";
        case PackerType::CodeVirtualizer:   return "CodeVirtualizer";
        case PackerType::PackerCustom:      return "Custom/Unknown Packer";
        case PackerType::DotNetObfuscator:  return ".NET Obfuscator";
        case PackerType::AutoIt:            return "AutoIt";
        case PackerType::NSIS:              return "NSIS Installer";
        case PackerType::InnoSetup:         return "Inno Setup";
        case PackerType::PyInstaller:       return "PyInstaller";
        // Commercial protectors
        case PackerType::PELock:            return "PELock";
        case PackerType::ACProtect:         return "ACProtect";
        case PackerType::SafeEngine:        return "SafeEngine";
        case PackerType::WinLicense:        return "WinLicense";
        case PackerType::CodeWall:          return "CodeWall";
        case PackerType::PrivateEXE:        return "PrivateEXE Protector";
        case PackerType::PCGuard:           return "PC Guard";
        case PackerType::GameGuard:         return "GameGuard";
        case PackerType::Denuvo:            return "Denuvo";
        case PackerType::VMProtect1x:       return "VMProtect 1.x";
        case PackerType::VMProtect2x:       return "VMProtect 2.x";
        case PackerType::ThemidaV1:         return "Themida v1";
        case PackerType::ThemidaV2:         return "Themida v2";
        // Packers
        case PackerType::RLPack:            return "RLPack";
        case PackerType::nPack:             return "nPack";
        case PackerType::WinUpack:          return "WinUpack";
        case PackerType::JDPack:            return "JDPack";
        case PackerType::BeRoEXE:           return "BeRoEXE Packer";
        case PackerType::Packman:           return "Packman";
        case PackerType::YodaCrypt:         return "Yoda's Crypter";
        case PackerType::PEBundle:          return "PEBundle";
        case PackerType::DotFixNice:        return "DotFix NiceProtect";
        case PackerType::PEX:               return "PEX";
        case PackerType::AlexProtect:       return "Alex Protector";
        case PackerType::AntiCrack:         return "AntiCrack Protector";
        case PackerType::kkrunchy:          return "kkrunchy";
        case PackerType::CrunchCexe:        return "Crunch/Cexe";
        case PackerType::UPXModified:       return "UPX (Modified)";
        // .NET / Managed
        case PackerType::ConfuserEx:        return "ConfuserEx";
        case PackerType::Dotfuscator:       return "Dotfuscator";
        // Scripting
        case PackerType::AutoHotkey:        return "AutoHotkey";
        case PackerType::PyArmor:           return "PyArmor";
        case PackerType::Cython:            return "Cython Compiled";
        // Go
        case PackerType::GoBinary:          return "Go Binary";
        // Installer/SFX
        case PackerType::SevenZipSFX:       return "7-Zip SFX";
        case PackerType::WinRARSFX:         return "WinRAR SFX";
        case PackerType::WinZipSFX:         return "WinZip SFX";
        case PackerType::InstallShield:     return "InstallShield";
        case PackerType::WiseInstaller:     return "Wise Installer";
        // VM-based
        case PackerType::TigerVMP:          return "TigerVMP";
        case PackerType::ReWolf:            return "ReWolf";
        // Additional
        case PackerType::ExeCryptorV2:      return "ExeCryptor 2.x";
        case PackerType::PECompactV3:       return "PECompact v3";
        case PackerType::PetiteV21:         return "Petite 2.1";
        case PackerType::PetiteV22:         return "Petite 2.2";
        case PackerType::PetiteV23:         return "Petite 2.3";
        case PackerType::NSISVariant:       return "NSIS (Variant)";
        case PackerType::InnoSetupVariant:  return "Inno Setup (Variant)";
        case PackerType::ElectronASAR:      return "Electron ASAR";
        case PackerType::SmartAssembly:     return "SmartAssembly";
        case PackerType::Eazfuscator:       return "Eazfuscator.NET";
        case PackerType::BabelNet:          return "Babel .NET";
        case PackerType::DNGuard:           return "DNGuard HVM";
        case PackerType::NetReactor:        return ".NET Reactor";
        case PackerType::MaxtoCode:         return "MaxtoCode";
        case PackerType::Agile:             return "Agile.NET";
        case PackerType::Xenocode:          return "Xenocode";
        case PackerType::Spoon:             return "Spoon (Turbo)";
        case PackerType::BoxedAppVariant:   return "BoxedApp (Variant)";
        case PackerType::MoleBoxUltra:      return "MoleBox Ultra";
        case PackerType::PECompactV2:       return "PECompact v2";
        case PackerType::UPXScrambled:      return "UPX (Scrambled)";
        case PackerType::ASPackV2:          return "ASPack v2";
        case PackerType::NSPackV3:          return "NsPack v3";
        case PackerType::MPRESSv2:          return "MPRESS v2";
        case PackerType::FSGv2:             return "FSG v2";
        case PackerType::MEWv11:            return "MEW v11";
        case PackerType::PESpinV1:          return "PESpin v1";
        case PackerType::tElockV098:        return "tElock v0.98";
        case PackerType::ObsidiumV1:        return "Obsidium v1";
        case PackerType::ArmadilloV9:       return "Armadillo v9";
        case PackerType::ThemidaV3:         return "Themida v3";
    }
    return "Unknown";
}

// ============================================================================
// Anonymous namespace — helpers, signatures, constants
// ============================================================================

namespace {

// --------------------------------------------------------------------------
// Container caps
// --------------------------------------------------------------------------

static constexpr uint32_t kMaxOEPCandidates    = 256;
static constexpr uint32_t kMaxEntropyHistory    = 10'000;
static constexpr uint32_t kMaxTrackedAPICalls   = 100'000;
static constexpr uint32_t kMaxProtChanges       = 10'000;
static constexpr uint32_t kMaxImportEntries     = 10'000;
static constexpr uint32_t kMaxSectionsCap       = 96;
static constexpr uint32_t kMaxEPReadBytes       = 64;
static constexpr uint64_t kEntropyCheckInterval = 10'000;
static constexpr uint64_t kOEPConfirmMultiplier = 200;
static constexpr uint32_t kMaxDataScanSize      = 4u * 1024u * 1024u;
static constexpr uint32_t kOutputFileAlignment  = 0x200;
static constexpr uint32_t kMaxStringSearch      = 64u * 1024u;

// --------------------------------------------------------------------------
// Shannon entropy
// --------------------------------------------------------------------------

[[nodiscard]] double ShannonEntropy(const uint8_t* data, size_t len) noexcept {
    if (!data || len == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    const double invLen = 1.0 / static_cast<double>(len);
    double entropy = 0.0;
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        const double p = static_cast<double>(freq[i]) * invLen;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// Compute entropy of a region in guest memory, reading page by page.
[[nodiscard]] double ComputeGuestEntropy(const VirtualMemory& memory,
                                          GuestAddress addr,
                                          GuestSize size) noexcept {
    if (size == 0) return 0.0;
    if (size > kMaxDataScanSize) size = kMaxDataScanSize;

    std::array<uint64_t, 256> freq{};
    uint64_t totalBytes = 0;

    GuestAddress cur = addr;
    GuestSize remaining = size;
    while (remaining > 0) {
        const uint8_t* ptr = memory.GetHostReadPtr(cur);
        if (!ptr) {
            const GuestSize skip = kPageSize - (cur & kPageMask);
            const GuestSize advance = std::min(skip, remaining);
            cur += advance;
            remaining -= advance;
            continue;
        }

        const uint32_t pageOff = static_cast<uint32_t>(cur & kPageMask);
        const uint32_t canRead = static_cast<uint32_t>(kPageSize - pageOff);
        const uint32_t toRead  = static_cast<uint32_t>(std::min<GuestSize>(canRead, remaining));

        for (uint32_t i = 0; i < toRead; ++i) {
            freq[ptr[i]]++;
        }
        totalBytes += toRead;
        cur += toRead;
        remaining -= toRead;
    }

    if (totalBytes == 0) return 0.0;

    const double invLen = 1.0 / static_cast<double>(totalBytes);
    double entropy = 0.0;
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        const double p = static_cast<double>(freq[i]) * invLen;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// --------------------------------------------------------------------------
// Guest memory reading helpers (const-correct, page-crossing-safe)
// --------------------------------------------------------------------------

[[nodiscard]] bool ReadGuestBytes(const VirtualMemory& memory,
                                   GuestAddress addr,
                                   void* dst,
                                   uint32_t count) noexcept {
    auto* out = static_cast<uint8_t*>(dst);
    GuestAddress cur = addr;
    uint32_t remaining = count;

    while (remaining > 0) {
        const uint8_t* ptr = memory.GetHostReadPtr(cur);
        if (!ptr) return false;

        const uint32_t pageOff = static_cast<uint32_t>(cur & kPageMask);
        const uint32_t canRead = static_cast<uint32_t>(kPageSize - pageOff);
        const uint32_t toRead  = std::min(canRead, remaining);

        std::memcpy(out, ptr, toRead);
        out += toRead;
        cur += toRead;
        remaining -= toRead;
    }
    return true;
}

// --------------------------------------------------------------------------
// Byte pattern matching (0x00 mask byte = wildcard)
// --------------------------------------------------------------------------

struct BytePattern {
    const uint8_t* bytes;
    const uint8_t* mask;
    uint8_t        length;
};

[[nodiscard]] bool MatchPattern(const uint8_t* data, uint32_t dataLen,
                                 const BytePattern& pattern) noexcept {
    if (!data || dataLen < pattern.length) return false;
    for (uint8_t i = 0; i < pattern.length; ++i) {
        if ((data[i] & pattern.mask[i]) != pattern.bytes[i]) return false;
    }
    return true;
}

[[nodiscard]] bool SearchPatternInRegion(const VirtualMemory& memory,
                                          GuestAddress base,
                                          GuestSize size,
                                          const BytePattern& pattern) noexcept {
    if (pattern.length == 0 || size < pattern.length) return false;
    const GuestSize scanLimit = std::min(size, static_cast<GuestSize>(kMaxDataScanSize));

    uint8_t buf[64];
    if (pattern.length > sizeof(buf)) return false;

    for (GuestSize off = 0; off + pattern.length <= scanLimit; off += kPageSize) {
        const GuestSize blockEnd = std::min(off + kPageSize, scanLimit);
        for (GuestSize pos = off; pos + pattern.length <= blockEnd; ++pos) {
            if (ReadGuestBytes(memory, base + pos, buf, pattern.length)) {
                if (MatchPattern(buf, pattern.length, pattern)) return true;
            }
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// String search in guest memory
// --------------------------------------------------------------------------

[[nodiscard]] bool FindStringInMemory(const VirtualMemory& memory,
                                       GuestAddress base,
                                       GuestSize size,
                                       const char* needle,
                                       uint32_t needleLen) noexcept {
    if (!needle || needleLen == 0 || size < needleLen) return false;
    const GuestSize scanSize = std::min(size, static_cast<GuestSize>(kMaxDataScanSize));

    GuestAddress cur = base;
    GuestSize remaining = scanSize;
    while (remaining >= needleLen) {
        const uint8_t* ptr = memory.GetHostReadPtr(cur);
        if (!ptr) {
            const GuestSize skip = kPageSize - (cur & kPageMask);
            const GuestSize advance = std::min(skip, remaining);
            cur += advance;
            remaining -= advance;
            continue;
        }

        const uint32_t pageOff  = static_cast<uint32_t>(cur & kPageMask);
        const uint32_t canScan  = static_cast<uint32_t>(kPageSize - pageOff);
        const uint32_t blockLen = static_cast<uint32_t>(std::min<GuestSize>(canScan, remaining));

        if (blockLen >= needleLen) {
            for (uint32_t i = 0; i + needleLen <= blockLen; ++i) {
                if (std::memcmp(ptr + i, needle, needleLen) == 0) return true;
            }
        }

        const uint32_t advance = (blockLen > needleLen) ? (blockLen - needleLen + 1) : 1;
        cur += advance;
        remaining -= std::min<GuestSize>(advance, remaining);
    }
    return false;
}

[[nodiscard]] inline bool FindStr(const VirtualMemory& memory,
                                   GuestAddress base, GuestSize size,
                                   const char* s) noexcept {
    return FindStringInMemory(memory, base, size, s,
                              static_cast<uint32_t>(std::strlen(s)));
}

// --------------------------------------------------------------------------
// Section info read from guest memory
// --------------------------------------------------------------------------

struct SectionReadInfo {
    char         name[9]{};
    uint32_t     virtualAddress   = 0;
    uint32_t     virtualSize      = 0;
    uint32_t     rawDataSize      = 0;
    uint32_t     characteristics  = 0;
};

struct PEHeaderInfo {
    bool     is64Bit           = false;
    uint32_t entryPointRVA     = 0;
    uint32_t sizeOfImage       = 0;
    uint32_t sizeOfHeaders     = 0;
    uint32_t fileAlignment     = 0;
    uint32_t sectionAlignment  = 0;
    uint32_t timestamp         = 0;
    uint32_t eLfanew           = 0;
    uint16_t numSections       = 0;
    uint16_t dllCharacteristics = 0;
    uint32_t numberOfRvaAndSizes = 0;
    PE::DataDirectory dataDirectories[PE::kMaxDataDirectories]{};
    std::vector<SectionReadInfo> sections;
};

[[nodiscard]] bool ReadPEHeaders(const VirtualMemory& memory,
                                  GuestAddress imageBase,
                                  PEHeaderInfo& info) noexcept {
    PE::DOSHeader dos{};
    if (!ReadGuestBytes(memory, imageBase, &dos, sizeof(dos))) return false;
    if (dos.e_magic != PE::kDOSMagic) return false;
    if (dos.e_lfanew < static_cast<int32_t>(sizeof(PE::DOSHeader)) ||
        dos.e_lfanew > 0x1000) return false;

    const GuestAddress ntAddr = imageBase + static_cast<uint32_t>(dos.e_lfanew);
    info.eLfanew = static_cast<uint32_t>(dos.e_lfanew);

    uint32_t sig = 0;
    if (!ReadGuestBytes(memory, ntAddr, &sig, 4)) return false;
    if (sig != PE::kNTSignature) return false;

    PE::FileHeader fileHdr{};
    if (!ReadGuestBytes(memory, ntAddr + 4, &fileHdr, sizeof(fileHdr))) return false;

    info.timestamp   = fileHdr.TimeDateStamp;
    info.numSections = fileHdr.NumberOfSections;
    if (info.numSections > kMaxSectionsCap) info.numSections = kMaxSectionsCap;

    const GuestAddress optAddr = ntAddr + 4 + sizeof(PE::FileHeader);
    uint16_t magic = 0;
    if (!ReadGuestBytes(memory, optAddr, &magic, 2)) return false;

    if (magic == PE::kPE64Magic) {
        info.is64Bit = true;
        PE::OptionalHeader64 opt{};
        if (!ReadGuestBytes(memory, optAddr, &opt, sizeof(opt))) return false;
        info.entryPointRVA       = opt.AddressOfEntryPoint;
        info.sizeOfImage         = opt.SizeOfImage;
        info.sizeOfHeaders       = opt.SizeOfHeaders;
        info.fileAlignment       = opt.FileAlignment;
        info.sectionAlignment    = opt.SectionAlignment;
        info.dllCharacteristics  = opt.DllCharacteristics;
        info.numberOfRvaAndSizes = opt.NumberOfRvaAndSizes;
        const uint32_t dirCount  = std::min(opt.NumberOfRvaAndSizes,
                                             static_cast<uint32_t>(PE::kMaxDataDirectories));
        std::memcpy(info.dataDirectories, opt.DataDirectories,
                    dirCount * sizeof(PE::DataDirectory));
    } else if (magic == PE::kPE32Magic) {
        info.is64Bit = false;
        PE::OptionalHeader32 opt{};
        if (!ReadGuestBytes(memory, optAddr, &opt, sizeof(opt))) return false;
        info.entryPointRVA       = opt.AddressOfEntryPoint;
        info.sizeOfImage         = opt.SizeOfImage;
        info.sizeOfHeaders       = opt.SizeOfHeaders;
        info.fileAlignment       = opt.FileAlignment;
        info.sectionAlignment    = opt.SectionAlignment;
        info.dllCharacteristics  = opt.DllCharacteristics;
        info.numberOfRvaAndSizes = opt.NumberOfRvaAndSizes;
        const uint32_t dirCount  = std::min(opt.NumberOfRvaAndSizes,
                                             static_cast<uint32_t>(PE::kMaxDataDirectories));
        std::memcpy(info.dataDirectories, opt.DataDirectories,
                    dirCount * sizeof(PE::DataDirectory));
    } else {
        return false;
    }

    if (info.fileAlignment == 0) info.fileAlignment = 0x200;
    if (info.sectionAlignment == 0) info.sectionAlignment = 0x1000;

    const GuestAddress secTableAddr = optAddr + fileHdr.SizeOfOptionalHeader;
    info.sections.clear();
    info.sections.reserve(info.numSections);

    for (uint16_t i = 0; i < info.numSections; ++i) {
        PE::SectionHeader sh{};
        const GuestAddress shAddr = secTableAddr +
            static_cast<GuestAddress>(i) * sizeof(PE::SectionHeader);
        if (!ReadGuestBytes(memory, shAddr, &sh, sizeof(sh))) break;

        SectionReadInfo si;
        std::memcpy(si.name, sh.Name, 8);
        si.name[8]          = '\0';
        si.virtualAddress   = sh.VirtualAddress;
        si.virtualSize      = sh.VirtualSize;
        si.rawDataSize      = sh.SizeOfRawData;
        si.characteristics  = sh.Characteristics;
        info.sections.push_back(si);
    }

    return !info.sections.empty();
}

[[nodiscard]] bool HasSectionNamed(const std::vector<SectionReadInfo>& secs,
                                    const char* name) noexcept {
    for (const auto& s : secs) {
        if (std::strncmp(s.name, name, 8) == 0) return true;
    }
    return false;
}

[[nodiscard]] int32_t FindSectionIndex(const std::vector<SectionReadInfo>& secs,
                                        const char* name) noexcept {
    for (size_t i = 0; i < secs.size(); ++i) {
        if (std::strncmp(secs[i].name, name, 8) == 0)
            return static_cast<int32_t>(i);
    }
    return -1;
}

[[nodiscard]] int32_t FindSectionByRVA(const std::vector<SectionReadInfo>& secs,
                                        uint32_t rva) noexcept {
    for (size_t i = 0; i < secs.size(); ++i) {
        if (rva >= secs[i].virtualAddress &&
            rva < secs[i].virtualAddress + std::max(secs[i].virtualSize, 1u)) {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

// --------------------------------------------------------------------------
// Entry-point byte patterns for known packers
// --------------------------------------------------------------------------

// UPX: pushad; lea esi,[??]; lea edi,[??]; push edi
static constexpr uint8_t kEP_UPX1_B[] = {
    0x60, 0xBE, 0x00, 0x00, 0x00, 0x00,
    0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x57
};
static constexpr uint8_t kEP_UPX1_M[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// ASPack: pushad; call +3; jmp/nop cascade
static constexpr uint8_t kEP_ASPack_B[] = {
    0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB
};
static constexpr uint8_t kEP_ASPack_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// MPRESS: pushad; call $+5; pop eax
static constexpr uint8_t kEP_MPRESS_B[] = {
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58
};
static constexpr uint8_t kEP_MPRESS_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// FSG: xchg [??],esp; popad
static constexpr uint8_t kEP_FSG_B[] = {
    0x87, 0x25, 0x00, 0x00, 0x00, 0x00, 0x61
};
static constexpr uint8_t kEP_FSG_M[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// MEW: mov esi,[??]; lodsw; push eax
static constexpr uint8_t kEP_MEW_B[] = {
    0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x50
};
static constexpr uint8_t kEP_MEW_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// NsPack: pushfd; pushad; call $+5
static constexpr uint8_t kEP_NsPack_B[] = {
    0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_NsPack_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// tElock: jmp rel32 then zeroes
static constexpr uint8_t kEP_tElock_B[] = {
    0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_tElock_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// PESpin: jmp short forward then encrypted
static constexpr uint8_t kEP_PESpin_B[] = {
    0xEB, 0x01, 0x00, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_PESpin_M[] = {
    0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// ASProtect: push ebp; call ??
static constexpr uint8_t kEP_ASProtect_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_ASProtect_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// Obsidium: push ebp; mov ebp, esp; push ecx; push SEH handler
static constexpr uint8_t kEP_Obsidium_B[] = {
    0xEB, 0x02, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_Obsidium_M[] = {
    0xFF, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// ExeCryptor: variant — push imm32; ret
static constexpr uint8_t kEP_ExeCryptor_B[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_ExeCryptor_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// ── Expanded EP byte patterns ────────────────────────────────────────────

// Themida v3: pushad; mov ebx,[esp+24h]; ...
static constexpr uint8_t kEP_ThemidaV3_B[] = {
    0x60, 0x8B, 0x5C, 0x24, 0x24, 0x8B, 0x73, 0x00
};
static constexpr uint8_t kEP_ThemidaV3_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
};

// Themida v1: push eax; push addr; jmp
static constexpr uint8_t kEP_ThemidaV1_B[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0B, 0xC0
};
static constexpr uint8_t kEP_ThemidaV1_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// Themida v2: similar entry via high-entropy section
static constexpr uint8_t kEP_ThemidaV2_B[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_ThemidaV2_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// VMProtect v3: push imm32; call rel32
static constexpr uint8_t kEP_VMPv3_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_VMPv3_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// VMProtect 1.x: jmp rel32 to vmp section
static constexpr uint8_t kEP_VMP1x_B[] = {
    0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_VMP1x_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// VMProtect 2.x: push imm; call delta+5
static constexpr uint8_t kEP_VMP2x_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_VMP2x_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00
};

// Enigma Protector: push ebp; mov ebp,esp; push -1; push addr
static constexpr uint8_t kEP_Enigma_B[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_Enigma_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// PELock: push [addr]; call rel32; pop ...
static constexpr uint8_t kEP_PELock_B[] = {
    0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_PELock_M[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// Armadillo: push addr; push addr; call dword ptr
static constexpr uint8_t kEP_Armadillo_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15
};
static constexpr uint8_t kEP_Armadillo_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// ACProtect: push eax; pushfd; push addr
static constexpr uint8_t kEP_ACProtect_B[] = {
    0x50, 0x9C, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8
};
static constexpr uint8_t kEP_ACProtect_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// ExeCryptor v2.x: E9 XX XX XX XX CC CC CC
static constexpr uint8_t kEP_ExeCryptorV2_B[] = {
    0xE9, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC
};
static constexpr uint8_t kEP_ExeCryptorV2_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// SafeEngine: push esp; pop ebp; push addr; call
static constexpr uint8_t kEP_SafeEngine_B[] = {
    0x54, 0x5D, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8
};
static constexpr uint8_t kEP_SafeEngine_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// WinLicense: same family as Themida — distinct EP variant
static constexpr uint8_t kEP_WinLicense_B[] = {
    0xEB, 0x00, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x1C, 0x24
};
static constexpr uint8_t kEP_WinLicense_M[] = {
    0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// CodeWall: push imm; mov eax,[addr]
static constexpr uint8_t kEP_CodeWall_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_CodeWall_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// PrivateEXE Protector: push ebp; mov ebp,esp; sub esp,0Ch
static constexpr uint8_t kEP_PrivateEXE_B[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C
};
static constexpr uint8_t kEP_PrivateEXE_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// PC Guard: push addr; ret; then encrypted blob
static constexpr uint8_t kEP_PCGuard_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00
};
static constexpr uint8_t kEP_PCGuard_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00
};

// GameGuard: push imm; jmp rel32
static constexpr uint8_t kEP_GameGuard_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_GameGuard_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// Denuvo: call rel; push imm
static constexpr uint8_t kEP_Denuvo_B[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_Denuvo_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// UPX modified: pushad; mov esi,[addr]; lea edi,[addr]
static constexpr uint8_t kEP_UPXMod_B[] = {
    0x60, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x3D, 0x00, 0x00
};
static constexpr uint8_t kEP_UPXMod_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
};

// UPX scrambled: variant with xor-based delta decode before standard stub
static constexpr uint8_t kEP_UPXScram_B[] = {
    0xEB, 0x00, 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_UPXScram_M[] = {
    0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// PECompact v2: push imm; call rel
static constexpr uint8_t kEP_PECompactV2_B[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_PECompactV2_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// PECompact v3: similar but with 64-bit awareness
static constexpr uint8_t kEP_PECompactV3_B[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35
};
static constexpr uint8_t kEP_PECompactV3_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

// Petite v2.1: mov ecx,imm; push esi; mov esi,[esp+08]
static constexpr uint8_t kEP_PetiteV21_B[] = {
    0xB9, 0x00, 0x00, 0x00, 0x00, 0x56, 0x8B, 0x74, 0x24, 0x08
};
static constexpr uint8_t kEP_PetiteV21_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Petite v2.2: push ebp; push esi; push imm
static constexpr uint8_t kEP_PetiteV22_B[] = {
    0x55, 0x56, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8
};
static constexpr uint8_t kEP_PetiteV22_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// Petite v2.3: push imm; jmp
static constexpr uint8_t kEP_PetiteV23_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0x64, 0xFF, 0x35
};
static constexpr uint8_t kEP_PetiteV23_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// kkrunchy: xor eax,eax; push eax; push imm
static constexpr uint8_t kEP_kkrunchy_B[] = {
    0x33, 0xC0, 0x50, 0x68, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_kkrunchy_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// Crunch/Cexe: push addr; push addr; ret
static constexpr uint8_t kEP_CrunchCexe_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3
};
static constexpr uint8_t kEP_CrunchCexe_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// RLPack: push addr; call rel; pop ebx
static constexpr uint8_t kEP_RLPack_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B
};
static constexpr uint8_t kEP_RLPack_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// nPack: push ebp; mov ebp,esp; push ecx
static constexpr uint8_t kEP_nPack_B[] = {
    0x55, 0x8B, 0xEC, 0x51, 0x53, 0x56, 0x57
};
static constexpr uint8_t kEP_nPack_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// WinUpack/Upack: push addr; jmp rel
static constexpr uint8_t kEP_WinUpack_B[] = {
    0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x8B, 0xF8
};
static constexpr uint8_t kEP_WinUpack_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// JDPack: push addr; mov eax,addr; call eax
static constexpr uint8_t kEP_JDPack_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0
};
static constexpr uint8_t kEP_JDPack_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// BeRoEXE Packer: push imm; call rel32; sub [esp+4]
static constexpr uint8_t kEP_BeRoEXE_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x6C, 0x24
};
static constexpr uint8_t kEP_BeRoEXE_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF
};

// Packman: push ebp; push esi; call delta
static constexpr uint8_t kEP_Packman_B[] = {
    0x55, 0x56, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E
};
static constexpr uint8_t kEP_Packman_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// YodaCrypt: pushad; xor edx,edx; call $+5; pop edx
static constexpr uint8_t kEP_YodaCrypt_B[] = {
    0x60, 0x33, 0xD2, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A
};
static constexpr uint8_t kEP_YodaCrypt_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// PEBundle: push addr; call rel; add esp
static constexpr uint8_t kEP_PEBundle_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4
};
static constexpr uint8_t kEP_PEBundle_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// DotFix NiceProtect: push ebp; call forward
static constexpr uint8_t kEP_DotFixNice_B[] = {
    0x55, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED
};
static constexpr uint8_t kEP_DotFixNice_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// PEX: pushad; push imm; call $+5
static constexpr uint8_t kEP_PEX_B[] = {
    0x60, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_PEX_M[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Alex Protector: push ebp; mov ebp,esp; sub esp
static constexpr uint8_t kEP_AlexProtect_B[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x60, 0xE8
};
static constexpr uint8_t kEP_AlexProtect_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF
};

// AntiCrack Protector: pushad; call $+5; pop ebx
static constexpr uint8_t kEP_AntiCrack_B[] = {
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB
};
static constexpr uint8_t kEP_AntiCrack_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// TigerVMP: push rbp; mov rbp,rsp; push imm; jmp
static constexpr uint8_t kEP_TigerVMP_B[] = {
    0x55, 0x48, 0x89, 0xE5, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE9
};
static constexpr uint8_t kEP_TigerVMP_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// ReWolf: push imm; pushad; call $+5
static constexpr uint8_t kEP_ReWolf_B[] = {
    0x68, 0x00, 0x00, 0x00, 0x00, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_ReWolf_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// FinFisher VM entry: pushad; mov ebp,esp; sub esp,??; mov esi,[ebp+const]
static constexpr uint8_t kEP_FinFisher_B[] = {
    0x60, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x8B, 0x75
};
static constexpr uint8_t kEP_FinFisher_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF
};

// ASPack v2: pushad; call $+5; pop ebp; sub ebp,??
static constexpr uint8_t kEP_ASPackV2_B[] = {
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED
};
static constexpr uint8_t kEP_ASPackV2_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// NsPack v3: pushfd; pushad; push eax; call $+5
static constexpr uint8_t kEP_NSPackV3_B[] = {
    0x9C, 0x60, 0x50, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_NSPackV3_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// MPRESS v2: pushad; mov esi,[addr]; lea edi,[esi+??]
static constexpr uint8_t kEP_MPRESSv2_B[] = {
    0x60, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x7E
};
static constexpr uint8_t kEP_MPRESSv2_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// FSG v2: xchg eax,[esp]; popad; mov eax,[addr]
static constexpr uint8_t kEP_FSGv2_B[] = {
    0x87, 0x04, 0x24, 0x61, 0xA1, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_FSGv2_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// MEW v11: push edi; push esi; mov esi,[addr]; lodsw
static constexpr uint8_t kEP_MEWv11_B[] = {
    0x57, 0x56, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD
};
static constexpr uint8_t kEP_MEWv11_M[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// PESpin v1: jmp short; junk; pushad; call
static constexpr uint8_t kEP_PESpinV1_B[] = {
    0xEB, 0x01, 0x68, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_PESpinV1_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// tElock v0.98: jmp rel32; NUL-padding; then encrypted
static constexpr uint8_t kEP_tElockV098_B[] = {
    0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_tElockV098_M[] = {
    0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Obsidium v1: jmp short 2; trash; call $+5
static constexpr uint8_t kEP_ObsidiumV1_B[] = {
    0xEB, 0x02, 0xCD, 0x20, 0xE8, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint8_t kEP_ObsidiumV1_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};

// Armadillo v9: push ebp; mov ebp,esp; push -1; push addr; push addr
static constexpr uint8_t kEP_ArmadilloV9_B[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x00, 0x68
};
static constexpr uint8_t kEP_ArmadilloV9_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF
};

// ── VM dispatcher patterns (for AnalyzeVirtualMachine) ──────────────────

// Dispatcher: MOVZX reg,BYTE PTR [ESI]; SHL reg,2; JMP [table+reg]
static constexpr uint8_t kVMDisp_MovzxEsi_B[] = {
    0x0F, 0xB6, 0x06
};
static constexpr uint8_t kVMDisp_MovzxEsi_M[] = {
    0xFF, 0xFF, 0xFF
};

// Dispatcher: MOVZX reg,BYTE PTR [RSI]; (64-bit variant)
static constexpr uint8_t kVMDisp_MovzxRsi_B[] = {
    0x0F, 0xB6, 0x0E
};
static constexpr uint8_t kVMDisp_MovzxRsi_M[] = {
    0xFF, 0xFF, 0xFF
};

// Indirect dispatch: JMP DWORD PTR [reg*4+base]
static constexpr uint8_t kVMDisp_JmpTable32_B[] = {
    0xFF, 0x24, 0x85
};
static constexpr uint8_t kVMDisp_JmpTable32_M[] = {
    0xFF, 0xFF, 0xFF
};

// Indirect dispatch 64-bit: JMP QWORD PTR [reg*8+base]
static constexpr uint8_t kVMDisp_JmpTable64_B[] = {
    0xFF, 0x24, 0xC5
};
static constexpr uint8_t kVMDisp_JmpTable64_M[] = {
    0xFF, 0xFF, 0xFF
};

// Standard function prologue (used for OEP detection, not packer detection)
// push rbp; mov rbp, rsp (64-bit)
static constexpr uint8_t kPrologue64_B[] = {
    0x55, 0x48, 0x89, 0xE5
};
static constexpr uint8_t kPrologue64_M[] = {
    0xFF, 0xFF, 0xFF, 0xFF
};

// push ebp; mov ebp, esp (32-bit)
static constexpr uint8_t kPrologue32_B[] = {
    0x55, 0x8B, 0xEC
};
static constexpr uint8_t kPrologue32_M[] = {
    0xFF, 0xFF, 0xFF
};

// sub rsp, imm8 (64-bit common)
static constexpr uint8_t kSubRsp_B[] = {
    0x48, 0x83, 0xEC
};
static constexpr uint8_t kSubRsp_M[] = {
    0xFF, 0xFF, 0xFF
};

// --------------------------------------------------------------------------
// DLL name lookup for import reconstruction
// --------------------------------------------------------------------------

struct FuncDLLEntry {
    const char* funcName;
    const char* dllName;
};

static constexpr FuncDLLEntry kFuncDLLMap[] = {
    // kernel32.dll
    {"CreateFileA",           "kernel32.dll"},
    {"CreateFileW",           "kernel32.dll"},
    {"ReadFile",              "kernel32.dll"},
    {"WriteFile",             "kernel32.dll"},
    {"CloseHandle",           "kernel32.dll"},
    {"VirtualAlloc",          "kernel32.dll"},
    {"VirtualFree",           "kernel32.dll"},
    {"VirtualProtect",        "kernel32.dll"},
    {"GetProcAddress",        "kernel32.dll"},
    {"LoadLibraryA",          "kernel32.dll"},
    {"LoadLibraryW",          "kernel32.dll"},
    {"LoadLibraryExA",        "kernel32.dll"},
    {"LoadLibraryExW",        "kernel32.dll"},
    {"FreeLibrary",           "kernel32.dll"},
    {"GetModuleHandleA",      "kernel32.dll"},
    {"GetModuleHandleW",      "kernel32.dll"},
    {"GetModuleFileNameA",    "kernel32.dll"},
    {"GetModuleFileNameW",    "kernel32.dll"},
    {"CreateProcessA",        "kernel32.dll"},
    {"CreateProcessW",        "kernel32.dll"},
    {"ExitProcess",           "kernel32.dll"},
    {"TerminateProcess",      "kernel32.dll"},
    {"GetCurrentProcess",     "kernel32.dll"},
    {"GetCurrentProcessId",   "kernel32.dll"},
    {"GetCurrentThreadId",    "kernel32.dll"},
    {"CreateThread",          "kernel32.dll"},
    {"Sleep",                 "kernel32.dll"},
    {"SleepEx",               "kernel32.dll"},
    {"GetTickCount",          "kernel32.dll"},
    {"GetTickCount64",        "kernel32.dll"},
    {"QueryPerformanceCounter","kernel32.dll"},
    {"GetSystemTimeAsFileTime","kernel32.dll"},
    {"GetSystemInfo",         "kernel32.dll"},
    {"IsDebuggerPresent",     "kernel32.dll"},
    {"CheckRemoteDebuggerPresent","kernel32.dll"},
    {"OutputDebugStringA",    "kernel32.dll"},
    {"OutputDebugStringW",    "kernel32.dll"},
    {"GetLastError",          "kernel32.dll"},
    {"SetLastError",          "kernel32.dll"},
    {"HeapAlloc",             "kernel32.dll"},
    {"HeapFree",              "kernel32.dll"},
    {"HeapCreate",            "kernel32.dll"},
    {"GetProcessHeap",        "kernel32.dll"},
    {"GlobalAlloc",           "kernel32.dll"},
    {"GlobalFree",            "kernel32.dll"},
    {"LocalAlloc",            "kernel32.dll"},
    {"LocalFree",             "kernel32.dll"},
    {"GetCommandLineA",       "kernel32.dll"},
    {"GetCommandLineW",       "kernel32.dll"},
    {"GetEnvironmentVariableA","kernel32.dll"},
    {"GetEnvironmentVariableW","kernel32.dll"},
    {"SetEnvironmentVariableA","kernel32.dll"},
    {"SetEnvironmentVariableW","kernel32.dll"},
    {"GetTempPathA",          "kernel32.dll"},
    {"GetTempPathW",          "kernel32.dll"},
    {"GetWindowsDirectoryA",  "kernel32.dll"},
    {"GetWindowsDirectoryW",  "kernel32.dll"},
    {"GetSystemDirectoryA",   "kernel32.dll"},
    {"GetSystemDirectoryW",   "kernel32.dll"},
    {"CreateMutexA",          "kernel32.dll"},
    {"CreateMutexW",          "kernel32.dll"},
    {"OpenMutexA",            "kernel32.dll"},
    {"ReleaseMutex",          "kernel32.dll"},
    {"WaitForSingleObject",   "kernel32.dll"},
    {"CreateEventA",          "kernel32.dll"},
    {"CreateEventW",          "kernel32.dll"},
    {"SetEvent",              "kernel32.dll"},
    {"ResetEvent",            "kernel32.dll"},
    {"DeleteFileA",           "kernel32.dll"},
    {"DeleteFileW",           "kernel32.dll"},
    {"CopyFileA",             "kernel32.dll"},
    {"CopyFileW",             "kernel32.dll"},
    {"MoveFileA",             "kernel32.dll"},
    {"MoveFileW",             "kernel32.dll"},
    {"FindFirstFileA",        "kernel32.dll"},
    {"FindFirstFileW",        "kernel32.dll"},
    {"FindNextFileA",         "kernel32.dll"},
    {"FindNextFileW",         "kernel32.dll"},
    {"FindClose",             "kernel32.dll"},
    {"GetFileSize",           "kernel32.dll"},
    {"GetFileSizeEx",         "kernel32.dll"},
    {"SetFilePointer",        "kernel32.dll"},
    {"DeviceIoControl",       "kernel32.dll"},
    {"CreateFileMappingA",    "kernel32.dll"},
    {"MapViewOfFile",         "kernel32.dll"},
    {"UnmapViewOfFile",       "kernel32.dll"},
    {"FlushFileBuffers",      "kernel32.dll"},
    {"GetFileAttributesA",    "kernel32.dll"},
    {"GetFileAttributesW",    "kernel32.dll"},
    {"WideCharToMultiByte",   "kernel32.dll"},
    {"MultiByteToWideChar",   "kernel32.dll"},
    {"lstrlenA",              "kernel32.dll"},
    {"lstrlenW",              "kernel32.dll"},
    {"lstrcmpA",              "kernel32.dll"},
    {"lstrcmpW",              "kernel32.dll"},
    {"lstrcpyA",              "kernel32.dll"},
    {"lstrcatA",              "kernel32.dll"},
    {"GetVersionExA",         "kernel32.dll"},
    {"GetVersionExW",         "kernel32.dll"},
    {"GetVersion",            "kernel32.dll"},
    // ntdll.dll
    {"NtCreateFile",                "ntdll.dll"},
    {"NtAllocateVirtualMemory",     "ntdll.dll"},
    {"NtProtectVirtualMemory",      "ntdll.dll"},
    {"NtFreeVirtualMemory",         "ntdll.dll"},
    {"NtWriteVirtualMemory",        "ntdll.dll"},
    {"NtReadVirtualMemory",         "ntdll.dll"},
    {"NtQueryInformationProcess",   "ntdll.dll"},
    {"NtQuerySystemInformation",    "ntdll.dll"},
    {"NtClose",                     "ntdll.dll"},
    {"NtOpenProcess",               "ntdll.dll"},
    {"NtCreateSection",             "ntdll.dll"},
    {"NtMapViewOfSection",          "ntdll.dll"},
    {"NtUnmapViewOfSection",        "ntdll.dll"},
    {"NtCreateThreadEx",            "ntdll.dll"},
    {"NtDelayExecution",            "ntdll.dll"},
    {"NtSetInformationThread",      "ntdll.dll"},
    {"RtlInitUnicodeString",        "ntdll.dll"},
    {"RtlDecompressBuffer",         "ntdll.dll"},
    {"LdrLoadDll",                  "ntdll.dll"},
    {"LdrGetProcedureAddress",      "ntdll.dll"},
    {"RtlGetVersion",               "ntdll.dll"},
    {"NtQueryVirtualMemory",        "ntdll.dll"},
    // advapi32.dll
    {"RegOpenKeyExA",         "advapi32.dll"},
    {"RegOpenKeyExW",         "advapi32.dll"},
    {"RegQueryValueExA",      "advapi32.dll"},
    {"RegQueryValueExW",      "advapi32.dll"},
    {"RegSetValueExA",        "advapi32.dll"},
    {"RegSetValueExW",        "advapi32.dll"},
    {"RegCloseKey",           "advapi32.dll"},
    {"RegCreateKeyExA",       "advapi32.dll"},
    {"RegCreateKeyExW",       "advapi32.dll"},
    {"RegDeleteKeyA",         "advapi32.dll"},
    {"RegDeleteValueA",       "advapi32.dll"},
    {"OpenProcessToken",      "advapi32.dll"},
    {"AdjustTokenPrivileges", "advapi32.dll"},
    {"LookupPrivilegeValueA", "advapi32.dll"},
    {"CreateServiceA",        "advapi32.dll"},
    {"CreateServiceW",        "advapi32.dll"},
    {"OpenSCManagerA",        "advapi32.dll"},
    {"OpenSCManagerW",        "advapi32.dll"},
    {"StartServiceA",         "advapi32.dll"},
    {"CryptAcquireContextA",  "advapi32.dll"},
    {"CryptEncrypt",          "advapi32.dll"},
    {"CryptDecrypt",          "advapi32.dll"},
    {"CryptGenRandom",        "advapi32.dll"},
    {"CryptCreateHash",       "advapi32.dll"},
    {"CryptHashData",         "advapi32.dll"},
    {"CryptDeriveKey",        "advapi32.dll"},
    {"CryptDestroyKey",       "advapi32.dll"},
    {"CryptReleaseContext",   "advapi32.dll"},
    // ws2_32.dll
    {"WSAStartup",           "ws2_32.dll"},
    {"WSACleanup",           "ws2_32.dll"},
    {"socket",               "ws2_32.dll"},
    {"connect",              "ws2_32.dll"},
    {"send",                 "ws2_32.dll"},
    {"recv",                 "ws2_32.dll"},
    {"bind",                 "ws2_32.dll"},
    {"listen",               "ws2_32.dll"},
    {"accept",               "ws2_32.dll"},
    {"closesocket",          "ws2_32.dll"},
    {"select",               "ws2_32.dll"},
    {"gethostbyname",        "ws2_32.dll"},
    {"getaddrinfo",          "ws2_32.dll"},
    {"WSAGetLastError",      "ws2_32.dll"},
    {"ioctlsocket",          "ws2_32.dll"},
    {"setsockopt",           "ws2_32.dll"},
    {"inet_addr",            "ws2_32.dll"},
    {"htons",                "ws2_32.dll"},
    {"ntohs",                "ws2_32.dll"},
    {"inet_ntoa",            "ws2_32.dll"},
    // user32.dll
    {"MessageBoxA",          "user32.dll"},
    {"MessageBoxW",          "user32.dll"},
    {"GetDesktopWindow",     "user32.dll"},
    {"FindWindowA",          "user32.dll"},
    {"FindWindowW",          "user32.dll"},
    {"GetForegroundWindow",  "user32.dll"},
    {"ShowWindow",           "user32.dll"},
    {"PostMessageA",         "user32.dll"},
    {"SendMessageA",         "user32.dll"},
    {"SetWindowsHookExA",    "user32.dll"},
    {"GetKeyboardState",     "user32.dll"},
    {"GetAsyncKeyState",     "user32.dll"},
    {"RegisterClassExA",     "user32.dll"},
    {"CreateWindowExA",      "user32.dll"},
    {"DefWindowProcA",       "user32.dll"},
    {"GetSystemMetrics",     "user32.dll"},
    {"EnumWindows",          "user32.dll"},
    // shell32.dll
    {"ShellExecuteA",        "shell32.dll"},
    {"ShellExecuteW",        "shell32.dll"},
    {"ShellExecuteExA",      "shell32.dll"},
    {"ShellExecuteExW",      "shell32.dll"},
    {"SHGetFolderPathA",     "shell32.dll"},
    {"SHGetFolderPathW",     "shell32.dll"},
    {"SHGetSpecialFolderPathA","shell32.dll"},
    // wininet/winhttp
    {"InternetOpenA",        "wininet.dll"},
    {"InternetOpenW",        "wininet.dll"},
    {"InternetOpenUrlA",     "wininet.dll"},
    {"InternetReadFile",     "wininet.dll"},
    {"InternetConnectA",     "wininet.dll"},
    {"HttpOpenRequestA",     "wininet.dll"},
    {"HttpSendRequestA",     "wininet.dll"},
    {"InternetCloseHandle",  "wininet.dll"},
    {"WinHttpOpen",          "winhttp.dll"},
    {"WinHttpConnect",       "winhttp.dll"},
    {"WinHttpOpenRequest",   "winhttp.dll"},
    {"WinHttpSendRequest",   "winhttp.dll"},
    {"WinHttpReceiveResponse","winhttp.dll"},
    {"WinHttpReadData",      "winhttp.dll"},
    {"WinHttpCloseHandle",   "winhttp.dll"},
    // urlmon.dll
    {"URLDownloadToFileA",   "urlmon.dll"},
    {"URLDownloadToFileW",   "urlmon.dll"},
    // ole32.dll
    {"CoInitializeEx",       "ole32.dll"},
    {"CoCreateInstance",     "ole32.dll"},
    {"CoUninitialize",       "ole32.dll"},
    // msvcrt / ucrt
    {"malloc",               "msvcrt.dll"},
    {"free",                 "msvcrt.dll"},
    {"memcpy",               "msvcrt.dll"},
    {"memset",               "msvcrt.dll"},
    {"strlen",               "msvcrt.dll"},
    {"strcmp",               "msvcrt.dll"},
    {"strcpy",               "msvcrt.dll"},
    {"sprintf",              "msvcrt.dll"},
    {"printf",               "msvcrt.dll"},
    {"fopen",                "msvcrt.dll"},
    {"fclose",               "msvcrt.dll"},
    {"fread",                "msvcrt.dll"},
    {"fwrite",               "msvcrt.dll"},
};

[[nodiscard]] const char* LookupDLLForFunc(const char* funcName) noexcept {
    if (!funcName) return "unknown.dll";

    // Check for "dll!func" format
    const char* bang = std::strchr(funcName, '!');
    if (bang) return "unknown.dll"; // Already has DLL prefix handled by caller

    for (const auto& entry : kFuncDLLMap) {
        if (std::strcmp(funcName, entry.funcName) == 0) return entry.dllName;
    }
    return "unknown.dll";
}

// --------------------------------------------------------------------------
// Align helpers
// --------------------------------------------------------------------------

[[nodiscard]] constexpr uint32_t AlignUp32(uint32_t val, uint32_t alignment) noexcept {
    if (alignment == 0) return val;
    return (val + alignment - 1) & ~(alignment - 1);
}

// --------------------------------------------------------------------------
// Tail-jump detection: scan for JMP rel32 at the given address
// Returns the absolute target if this is a long jump (>4KB distance), else 0.
// --------------------------------------------------------------------------

[[nodiscard]] GuestAddress DetectTailJump(const VirtualMemory& memory,
                                           GuestAddress rip) noexcept {
    uint8_t buf[16]{};
    if (!ReadGuestBytes(memory, rip, buf, 6)) return 0;

    // E9 rel32 — near relative jump
    if (buf[0] == 0xE9) {
        int32_t rel = 0;
        std::memcpy(&rel, buf + 1, 4);
        const GuestAddress target = rip + 5 + static_cast<int64_t>(rel);
        const int64_t distance = static_cast<int64_t>(target) - static_cast<int64_t>(rip);
        if (distance > 4096 || distance < -4096) {
            return target;
        }
    }

    // FF /4 — indirect jump (jmp [reg+disp]) — can also be a tail jump
    // but harder to resolve; skip for now.

    // 48 FF 25 rel32 — 64-bit RIP-relative jump
    if (buf[0] == 0x48 && buf[1] == 0xFF && buf[2] == 0x25) {
        int32_t rel = 0;
        std::memcpy(&rel, buf + 3, 4);
        const GuestAddress ptrAddr = rip + 7 + static_cast<int64_t>(rel);
        uint64_t target = 0;
        if (ReadGuestBytes(memory, ptrAddr, &target, 8)) {
            const int64_t distance = static_cast<int64_t>(target) - static_cast<int64_t>(rip);
            if (distance > 4096 || distance < -4096) {
                return target;
            }
        }
    }

    return 0;
}

// --------------------------------------------------------------------------
// Section-entry check: is the given RVA in a section named ".text"?
// --------------------------------------------------------------------------

[[nodiscard]] bool IsInTextSection(const std::vector<SectionReadInfo>& secs,
                                    uint32_t rva) noexcept {
    for (const auto& s : secs) {
        if ((std::strncmp(s.name, ".text", 5) == 0 ||
             (s.characteristics & PE::kSecContainsCode)) &&
            rva >= s.virtualAddress &&
            rva < s.virtualAddress + std::max(s.virtualSize, 1u))
        {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// VM Analysis constants
// --------------------------------------------------------------------------

static constexpr uint32_t kVMMaxHandlers       = 512;
static constexpr uint32_t kVMMaxScanBytes      = 64u * 1024u;
static constexpr uint32_t kVMMinHandlerInstrs  = 3;
static constexpr uint32_t kVMMaxHandlerInstrs  = 2048;
static constexpr uint32_t kVMMinHandlerCount   = 10;
static constexpr uint32_t kVMTableScanWindow   = 4096;

// Section-name to PackerType mapping for supplementary section-based detection
struct SectionPackerMapping {
    const char* sectionName;
    PackerType  packerType;
};

static constexpr SectionPackerMapping kSectionPackerMap[] = {
    {".vmp0",    PackerType::VMProtect},
    {".vmp1",    PackerType::VMProtect},
    {".vmp2",    PackerType::VMProtect},
    {".themida", PackerType::Themida},
    {".winlice", PackerType::Themida},
    {"WinLice",  PackerType::WinLicense},
    {".enigma1", PackerType::Enigma},
    {".enigma2", PackerType::Enigma},
    {".aspack",  PackerType::ASPack},
    {".adata",   PackerType::ASProtect},
    {".perplex", PackerType::PELock},
    {".petite",  PackerType::Petite},
    {".MPRESS1", PackerType::MPRESS},
    {".MPRESS2", PackerType::MPRESS},
    {".nsp0",    PackerType::NsPack},
    {".nsp1",    PackerType::NsPack},
    {".nsp2",    PackerType::NsPack},
    {".packed",  PackerType::PackerCustom},
    {".cv0",     PackerType::CodeVirtualizer},
    {".cv1",     PackerType::CodeVirtualizer},
    {".cvirt",   PackerType::CodeVirtualizer},
    {".aspr",    PackerType::ASProtect},
    {".pespin",  PackerType::PESpin},
    {".taz",     PackerType::PESpin},
    {".sforce",  PackerType::StarForce},
    {".securom", PackerType::SecuROM},
    {".srom",    PackerType::SecuROM},
    {".bxpck",   PackerType::BoxedApp},
    {".mole",    PackerType::MoleBox},
    {".stxt",    PackerType::SafeDisc},
    {".arma",    PackerType::Armadillo},
    {".ndata",   PackerType::NSIS},
    {".boot",    PackerType::Themida},
    {".tiger",   PackerType::TigerVMP},
    {".rwolf",   PackerType::ReWolf},
};

// Section-name to VMArch mapping for VM detection
struct SectionVMMapping {
    const char* sectionName;
    VMArch      arch;
    float       score;
};

static constexpr SectionVMMapping kSectionVMMap[] = {
    {".vmp0",    VMArch::VMProtect,       0.40f},
    {".vmp1",    VMArch::VMProtect,       0.40f},
    {".vmp2",    VMArch::VMProtect,       0.25f},
    {".themida", VMArch::Themida,         0.45f},
    {".winlice", VMArch::Themida,         0.40f},
    {".boot",    VMArch::Themida,         0.20f},
    {".cv0",     VMArch::CodeVirtualizer, 0.40f},
    {".cv1",     VMArch::CodeVirtualizer, 0.40f},
    {".cvirt",   VMArch::CodeVirtualizer, 0.35f},
    {".tiger",   VMArch::TigerVMP,        0.45f},
    {".rwolf",   VMArch::ReWolf,          0.45f},
};

// --------------------------------------------------------------------------
// VM bytecode fetch detection: scan for MOVZX fetches typical of VM dispatch
// --------------------------------------------------------------------------

[[nodiscard]] bool ScanForMovzxFetch(const VirtualMemory& memory,
                                      GuestAddress base,
                                      GuestSize size,
                                      GuestAddress& outAddr) noexcept {
    const GuestSize scanLimit = std::min(size, static_cast<GuestSize>(kVMMaxScanBytes));
    uint8_t buf[16]{};

    const BytePattern movzxEsi = {kVMDisp_MovzxEsi_B, kVMDisp_MovzxEsi_M, 3};
    const BytePattern movzxRsi = {kVMDisp_MovzxRsi_B, kVMDisp_MovzxRsi_M, 3};

    for (GuestSize off = 0; off + 16 <= scanLimit; ++off) {
        if (!ReadGuestBytes(memory, base + off, buf, 16)) continue;

        if (MatchPattern(buf, 16, movzxEsi) || MatchPattern(buf, 16, movzxRsi)) {
            // Check if followed within next 13 bytes by a JMP [table] pattern
            const BytePattern jmpTbl32 = {kVMDisp_JmpTable32_B, kVMDisp_JmpTable32_M, 3};
            const BytePattern jmpTbl64 = {kVMDisp_JmpTable64_B, kVMDisp_JmpTable64_M, 3};

            for (uint32_t ahead = 3; ahead + 3 <= 16; ++ahead) {
                if (MatchPattern(buf + ahead, 16 - ahead, jmpTbl32) ||
                    MatchPattern(buf + ahead, 16 - ahead, jmpTbl64))
                {
                    outAddr = base + off;
                    return true;
                }
            }
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// Scan for consecutive PUSH instructions (>8) followed by indirect JMP
// Typical VM entry: save all registers then jump to dispatcher
// --------------------------------------------------------------------------

[[nodiscard]] bool ScanForVMEntryPushSequence(const VirtualMemory& memory,
                                               GuestAddress base,
                                               GuestSize size,
                                               GuestAddress& outEntry) noexcept {
    const GuestSize scanLimit = std::min(size, static_cast<GuestSize>(kVMMaxScanBytes));
    uint8_t buf[32]{};

    for (GuestSize off = 0; off + 32 <= scanLimit; ++off) {
        if (!ReadGuestBytes(memory, base + off, buf, 32)) continue;

        // Count consecutive PUSHes: 0x50-0x57, 0x60 (PUSHAD), 0x9C (PUSHFD)
        uint32_t pushCount = 0;
        uint32_t i = 0;
        while (i < 24) {
            if ((buf[i] >= 0x50 && buf[i] <= 0x57) ||
                buf[i] == 0x60 || buf[i] == 0x9C)
            {
                pushCount += (buf[i] == 0x60) ? 8 : 1;
                i += 1;
            } else if (buf[i] == 0x68) {
                // push imm32
                pushCount += 1;
                i += 5;
            } else {
                break;
            }
        }

        if (pushCount >= 8 && i < 30) {
            // Check for indirect JMP after push sequence
            if (buf[i] == 0xFF &&
                (buf[i + 1] == 0xE0 || buf[i + 1] == 0xE1 ||
                 buf[i + 1] == 0xE2 || buf[i + 1] == 0xE3 ||
                 buf[i + 1] == 0xE6 || buf[i + 1] == 0xE7 ||
                 (buf[i + 1] & 0x38) == 0x20))
            {
                outEntry = base + off;
                return true;
            }
            // Also check for JMP rel32 after push sequence
            if (buf[i] == 0xE9) {
                outEntry = base + off;
                return true;
            }
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// Extract handler addresses from a jump table in guest memory
// --------------------------------------------------------------------------

[[nodiscard]] uint32_t ExtractHandlerTable(const VirtualMemory& memory,
                                            GuestAddress tableBase,
                                            GuestAddress imageBase,
                                            GuestSize imageSize,
                                            bool is64Bit,
                                            std::vector<VMHandlerInfo>& handlers) noexcept {
    const uint32_t entrySize = is64Bit ? 8 : 4;
    const uint32_t maxEntries = std::min(static_cast<uint32_t>(kVMMaxHandlers),
                                          kVMTableScanWindow / entrySize);
    uint32_t validCount = 0;
    uint32_t consecutive_invalid = 0;

    handlers.clear();
    handlers.reserve(256);

    for (uint32_t i = 0; i < maxEntries && consecutive_invalid < 5; ++i) {
        GuestAddress entry = 0;
        if (is64Bit) {
            uint64_t raw = 0;
            if (!ReadGuestBytes(memory, tableBase + i * entrySize, &raw, 8)) break;
            entry = raw;
        } else {
            uint32_t raw = 0;
            if (!ReadGuestBytes(memory, tableBase + i * entrySize, &raw, 4)) break;
            entry = raw;
        }

        // Validate: handler should be within the image
        if (entry < imageBase || entry >= imageBase + imageSize) {
            consecutive_invalid++;
            continue;
        }
        consecutive_invalid = 0;

        VMHandlerInfo info{};
        info.address = entry;
        info.opcodeValue = static_cast<uint8_t>(i);
        info.instructionCount = 0;
        info.handlerType = VMHandlerType::Unknown;
        handlers.push_back(info);
        validCount++;
    }

    return validCount;
}

// --------------------------------------------------------------------------
// Classify a handler by scanning its x86 body
// --------------------------------------------------------------------------

[[nodiscard]] VMHandlerType ClassifyHandler(const VirtualMemory& memory,
                                             GuestAddress handlerAddr,
                                             uint16_t& outInstrCount) noexcept {
    uint8_t buf[256]{};
    if (!ReadGuestBytes(memory, handlerAddr, buf, sizeof(buf))) {
        return VMHandlerType::Unknown;
    }

    outInstrCount = 0;

    // Simple heuristic instruction scan: count opcodes and look for patterns
    bool hasAdd = false, hasSub = false, hasMul = false, hasDiv = false;
    bool hasAnd = false, hasOr = false, hasXor = false, hasNot = false;
    bool hasShl = false, hasShr = false, hasRol = false, hasRor = false;
    bool hasPush = false, hasPop = false;
    bool hasMemLoad = false, hasMemStore = false;
    bool hasCall = false, hasRet = false;
    bool hasJmp = false, hasJcc = false;

    uint32_t pos = 0;
    while (pos < sizeof(buf) - 2 && outInstrCount < kVMMaxHandlerInstrs) {
        const uint8_t op = buf[pos];
        outInstrCount++;

        // ADD patterns
        if (op == 0x01 || op == 0x03 || (op >= 0x00 && op <= 0x05 && (op & 1)))
            hasAdd = true;
        // SUB patterns
        if (op == 0x29 || op == 0x2B || op == 0x2D)
            hasSub = true;
        // AND/OR/XOR/NOT via group opcode
        if (op == 0x21 || op == 0x23 || op == 0x25)
            hasAnd = true;
        if (op == 0x09 || op == 0x0B || op == 0x0D)
            hasOr = true;
        if (op == 0x31 || op == 0x33 || op == 0x35)
            hasXor = true;
        if (op == 0xF7 && pos + 1 < sizeof(buf) && (buf[pos + 1] & 0x38) == 0x10)
            hasNot = true;
        // IMUL
        if (op == 0xF7 && pos + 1 < sizeof(buf) && (buf[pos + 1] & 0x38) == 0x28)
            hasMul = true;
        if (op == 0x0F && pos + 1 < sizeof(buf) && buf[pos + 1] == 0xAF)
            hasMul = true;
        // IDIV
        if (op == 0xF7 && pos + 1 < sizeof(buf) && (buf[pos + 1] & 0x38) == 0x38)
            hasDiv = true;
        // Shift/Rotate
        if (op == 0xC1 || op == 0xD1 || op == 0xD3) {
            if (pos + 1 < sizeof(buf)) {
                uint8_t modrm = buf[pos + 1];
                uint8_t reg = (modrm >> 3) & 7;
                if (reg == 4) hasShl = true;
                if (reg == 5) hasShr = true;
                if (reg == 0) hasRol = true;
                if (reg == 1) hasRor = true;
            }
        }
        // PUSH/POP
        if ((op >= 0x50 && op <= 0x57) || op == 0x68 || op == 0x6A || op == 0x60)
            hasPush = true;
        if ((op >= 0x58 && op <= 0x5F) || op == 0x61)
            hasPop = true;
        // MOV mem->reg (load)
        if (op == 0x8B)
            hasMemLoad = true;
        // MOV reg->mem (store)
        if (op == 0x89)
            hasMemStore = true;
        // CALL
        if (op == 0xE8 || (op == 0xFF && pos + 1 < sizeof(buf) &&
                           (buf[pos + 1] & 0x38) == 0x10))
            hasCall = true;
        // RET
        if (op == 0xC3 || op == 0xC2 || op == 0xCB) {
            hasRet = true;
            break; // End of handler
        }
        // JMP (unconditional) — could be return to dispatcher
        if (op == 0xE9 || op == 0xEB || (op == 0xFF && pos + 1 < sizeof(buf) &&
                                          (buf[pos + 1] & 0x38) == 0x20))
        {
            hasJmp = true;
            break; // End of handler
        }
        // Jcc
        if ((op >= 0x70 && op <= 0x7F) || (op == 0x0F && pos + 1 < sizeof(buf) &&
                                             buf[pos + 1] >= 0x80 && buf[pos + 1] <= 0x8F))
            hasJcc = true;

        // Advance: simplified — single-byte advance for most opcodes
        pos++;
    }

    // Classification priority: specific operations > generic
    if (hasCall && !hasAdd && !hasSub && !hasAnd)
        return VMHandlerType::VMSyscall;
    if (hasRet && outInstrCount <= 5)
        return VMHandlerType::VMRet;
    if (hasAdd && !hasSub && !hasMul)
        return VMHandlerType::VMAdd;
    if (hasSub && !hasAdd && !hasMul)
        return VMHandlerType::VMSub;
    if (hasMul)
        return VMHandlerType::VMMul;
    if (hasDiv)
        return VMHandlerType::VMDiv;
    if (hasAnd && !hasOr && !hasXor)
        return VMHandlerType::VMAnd;
    if (hasOr && !hasAnd && !hasXor)
        return VMHandlerType::VMOr;
    if (hasXor && !hasAnd && !hasOr)
        return VMHandlerType::VMXor;
    if (hasNot)
        return VMHandlerType::VMNot;
    if (hasShl) return VMHandlerType::VMShl;
    if (hasShr) return VMHandlerType::VMShr;
    if (hasRol) return VMHandlerType::VMRol;
    if (hasRor) return VMHandlerType::VMRor;
    if (hasPush && !hasPop && !hasMemLoad && !hasMemStore)
        return VMHandlerType::VMPush;
    if (hasPop && !hasPush && !hasMemLoad && !hasMemStore)
        return VMHandlerType::VMPop;
    if (hasMemLoad && !hasMemStore)
        return VMHandlerType::VMLoad;
    if (hasMemStore && !hasMemLoad)
        return VMHandlerType::VMStore;
    if (hasJcc)
        return VMHandlerType::VMJcc;
    if (hasJmp && outInstrCount <= 3)
        return VMHandlerType::VMJmp;
    if (outInstrCount <= 2)
        return VMHandlerType::VMNop;

    return VMHandlerType::Unknown;
}

// --------------------------------------------------------------------------
// Detect opaque predicates: always-true/false conditional branches
// --------------------------------------------------------------------------

[[nodiscard]] bool DetectOpaquePredicates(const VirtualMemory& memory,
                                           GuestAddress base,
                                           GuestSize size) noexcept {
    const GuestSize scanLimit = std::min(size, static_cast<GuestSize>(kVMMaxScanBytes));
    uint8_t buf[16]{};
    uint32_t opaqueCount = 0;

    for (GuestSize off = 0; off + 8 <= scanLimit; off += 4) {
        if (!ReadGuestBytes(memory, base + off, buf, 8)) continue;

        // Pattern: XOR reg,reg; JZ/JNZ (always zero → always jumps/never jumps)
        if (buf[0] == 0x33 && (buf[1] & 0xC0) == 0xC0 &&
            ((buf[1] >> 3) & 7) == (buf[1] & 7))
        {
            if (buf[2] == 0x74 || buf[2] == 0x75) {
                opaqueCount++;
            }
        }

        // Pattern: CMP reg,reg; JZ (always equal)
        if (buf[0] == 0x3B && (buf[1] & 0xC0) == 0xC0 &&
            ((buf[1] >> 3) & 7) == (buf[1] & 7))
        {
            if (buf[2] == 0x74 || buf[2] == 0x75) {
                opaqueCount++;
            }
        }

        // Pattern: PUSH imm; POP reg; TEST reg,reg; JZ (imm != 0 → never zero)
        if (buf[0] == 0x6A && buf[1] != 0x00 &&
            (buf[2] >= 0x58 && buf[2] <= 0x5F))
        {
            if (buf[3] == 0x85 && buf[5] == 0x74) {
                opaqueCount++;
            }
        }
    }

    return opaqueCount >= 3;
}

} // anonymous namespace

// ============================================================================
// Impl definition
// ============================================================================

struct UnpackingEngine::Impl {
    // Configuration
    UnpackConfig config{};

    // Layer state
    std::vector<UnpackLayer> layers;
    uint32_t currentLayerIdx = UINT32_MAX;
    bool     unpacking       = false;
    bool     complete        = false;

    // Final OEP
    GuestAddress finalOEP       = 0;
    OEPMethod    finalOEPMethod = OEPMethod::WXTransition;

    // OEP candidate scoring
    struct OEPCandidate {
        GuestAddress address     = 0;
        OEPMethod    method      = OEPMethod::WXTransition;
        double       score       = 0.0;
        uint64_t     instrStamp  = 0;
        bool         confirmed   = false;
    };
    std::vector<OEPCandidate> oepCandidates;

    // Instruction tracking
    uint64_t     totalInstructions    = 0;
    uint64_t     layerStartInstr      = 0;
    uint64_t     lastEntropyCheckInstr = 0;
    GuestAddress prevRip              = 0;

    // API call tracking
    struct APIRecord {
        std::string name;
        uint64_t    instrCount = 0;
    };
    std::vector<APIRecord> apiLog;
    uint64_t lastAPIInstr            = 0;
    uint64_t instrSinceLastAPICall    = 0;

    // W→X state
    GuestAddress lastWXPage  = 0;
    GuestAddress lastWXRip   = 0;
    uint64_t     lastWXInstr = 0;

    // Entropy
    double currentEntropy = 0.0;
    double previousEntropy = 0.0;
    std::vector<std::pair<uint64_t, double>> entropyHistory;

    // Protection changes
    struct ProtRecord {
        GuestAddress base    = 0;
        GuestSize    size    = 0;
        MemProt      oldProt = MemProt::None;
        MemProt      newProt = MemProt::None;
    };
    std::vector<ProtRecord> protLog;

    // Cached image info for OEP heuristics
    GuestAddress cachedImageBase = 0;
    GuestSize    cachedImageSize = 0;
    std::vector<SectionReadInfo> cachedSections;
    uint32_t     cachedEPRVA     = 0;
    bool         cachedIs64Bit   = false;

    // Import reconstruction data
    struct ImportInfo {
        std::string dllName;
        std::string funcName;
    };
    std::vector<ImportInfo> trackedImports;
    bool importDataReady = false;

    // Thread safety
    mutable std::shared_mutex mutex;

    // VM analysis state
    VMArch detectedVM = VMArch::Unknown;

    // --- Internal helpers ---

    void BeginNewLayer(GuestAddress ep, uint64_t instrCount,
                       const VirtualMemory& memory,
                       GuestAddress imageBase, GuestSize imageSize) noexcept;
    void FinalizeCurrentLayer(double entropyAfter) noexcept;
    void AddOEPCandidate(GuestAddress addr, OEPMethod method,
                         double score, uint64_t instrCount) noexcept;
    void ConfirmOEP(GuestAddress addr, OEPMethod method) noexcept;
    void RecordImport(const char* funcName) noexcept;

    [[nodiscard]] bool CheckStandardPrologue(const VirtualMemory& memory,
                                              GuestAddress rip) const noexcept;
};

// --------------------------------------------------------------------------
// Impl helper implementations
// --------------------------------------------------------------------------

void UnpackingEngine::Impl::BeginNewLayer(
    GuestAddress ep, uint64_t instrCount,
    const VirtualMemory& memory,
    GuestAddress imageBase, GuestSize imageSize) noexcept
{
    // Finalize the previous layer if active
    if (currentLayerIdx < layers.size() && !layers[currentLayerIdx].isComplete) {
        const double ent = ComputeGuestEntropy(memory, imageBase, imageSize);
        FinalizeCurrentLayer(ent);
    }

    // Cap layers
    if (layers.size() >= config.maxLayers) {
        complete = true;
        return;
    }

    UnpackLayer layer{};
    layer.layerIndex          = static_cast<uint32_t>(layers.size());
    layer.entryPoint          = ep;
    layer.oep                 = ep;
    layer.oepMethod           = OEPMethod::WXTransition;
    layer.entropyBefore       = ComputeGuestEntropy(memory, imageBase, imageSize);
    layer.codeBase            = PageBase(ep);
    layer.codeSize            = kPageSize;
    layers.push_back(std::move(layer));

    currentLayerIdx   = static_cast<uint32_t>(layers.size() - 1);
    layerStartInstr   = instrCount;
    lastEntropyCheckInstr = instrCount;
    instrSinceLastAPICall = 0;
    lastAPIInstr          = instrCount;
}

void UnpackingEngine::Impl::FinalizeCurrentLayer(double entropyAfter) noexcept {
    if (currentLayerIdx >= layers.size()) return;

    auto& layer = layers[currentLayerIdx];
    layer.entropyAfter        = entropyAfter;
    layer.instructionsExecuted = totalInstructions - layerStartInstr;
    layer.isComplete          = true;
}

void UnpackingEngine::Impl::AddOEPCandidate(
    GuestAddress addr, OEPMethod method,
    double score, uint64_t instrCount) noexcept
{
    if (oepCandidates.size() >= kMaxOEPCandidates) {
        // Evict lowest-scoring candidate
        auto it = std::min_element(oepCandidates.begin(), oepCandidates.end(),
            [](const OEPCandidate& a, const OEPCandidate& b) {
                return a.score < b.score;
            });
        if (it != oepCandidates.end() && it->score < score) {
            *it = {addr, method, score, instrCount, false};
        }
        return;
    }

    // Check if we already have a candidate at this address — boost it
    for (auto& c : oepCandidates) {
        if (c.address == addr) {
            c.score = std::max(c.score, score);
            return;
        }
    }

    oepCandidates.push_back({addr, method, score, instrCount, false});
}

void UnpackingEngine::Impl::ConfirmOEP(GuestAddress addr, OEPMethod method) noexcept {
    finalOEP       = addr;
    finalOEPMethod = method;
    complete       = true;

    if (currentLayerIdx < layers.size()) {
        layers[currentLayerIdx].oep       = addr;
        layers[currentLayerIdx].oepMethod = method;
    }
}

void UnpackingEngine::Impl::RecordImport(const char* funcName) noexcept {
    if (!funcName || trackedImports.size() >= kMaxImportEntries) return;

    const char* dllName = LookupDLLForFunc(funcName);

    // Avoid duplicates
    for (const auto& imp : trackedImports) {
        if (imp.funcName == funcName && imp.dllName == dllName) return;
    }

    trackedImports.push_back({dllName, funcName});
}

bool UnpackingEngine::Impl::CheckStandardPrologue(
    const VirtualMemory& memory, GuestAddress rip) const noexcept
{
    uint8_t buf[16]{};
    if (!ReadGuestBytes(memory, rip, buf, sizeof(buf))) return false;

    const BytePattern p64  = {kPrologue64_B, kPrologue64_M, 4};
    const BytePattern p32  = {kPrologue32_B, kPrologue32_M, 3};
    const BytePattern pSub = {kSubRsp_B,     kSubRsp_M,     3};

    return MatchPattern(buf, sizeof(buf), p64)
        || MatchPattern(buf, sizeof(buf), p32)
        || MatchPattern(buf, sizeof(buf), pSub);
}

// ============================================================================
// Construction / Destruction / Move
// ============================================================================

UnpackingEngine::UnpackingEngine(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>())
{
    m_impl->config.maxLayers              = config.maxUnpackLayers;
    m_impl->config.entropyThreshold       = config.entropyThreshold;
    m_impl->config.minOEPInstructions     = config.minOEPInstructions;
    m_impl->config.captureEveryLayer      = config.captureUnpackLayers;
    m_impl->config.enablePackerDetection  = config.enableUnpacking;
    m_impl->config.enableImportReconstruction = config.enableUnpacking;

    m_impl->layers.reserve(config.maxUnpackLayers);
    m_impl->oepCandidates.reserve(32);
    m_impl->apiLog.reserve(1024);
    m_impl->entropyHistory.reserve(256);
    m_impl->protLog.reserve(256);
    m_impl->trackedImports.reserve(256);
}

UnpackingEngine::~UnpackingEngine() noexcept = default;

UnpackingEngine::UnpackingEngine(UnpackingEngine&&) noexcept = default;
UnpackingEngine& UnpackingEngine::operator=(UnpackingEngine&&) noexcept = default;

// ============================================================================
// OnWXTransition
// ============================================================================

void UnpackingEngine::OnWXTransition(
    const VirtualMemory& memory,
    const MemoryTracker& tracker,
    GuestAddress page,
    GuestAddress rip,
    uint64_t instrCount) noexcept
{
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->complete) return;
    if (m_impl->layers.size() >= m_impl->config.maxLayers) {
        m_impl->complete = true;
        return;
    }

    m_impl->lastWXPage  = page;
    m_impl->lastWXRip   = rip;
    m_impl->lastWXInstr = instrCount;

    // Track W→X count for current layer
    if (m_impl->currentLayerIdx < m_impl->layers.size()) {
        m_impl->layers[m_impl->currentLayerIdx].wxTransitions++;
    }

    if (!m_impl->unpacking) {
        // First ever W→X transition — enter unpacking mode
        m_impl->unpacking = true;
        m_impl->totalInstructions = instrCount;

        // Layer 0: the packer code that just ran
        {
            UnpackLayer packerLayer{};
            packerLayer.layerIndex          = 0;
            packerLayer.entryPoint          = 0;
            packerLayer.instructionsExecuted = instrCount;
            packerLayer.wxTransitions       = 1;
            packerLayer.isComplete          = true;
            packerLayer.entropyBefore       = ComputeGuestEntropy(memory, page, kPageSize);
            packerLayer.entropyAfter        = packerLayer.entropyBefore;
            m_impl->layers.push_back(std::move(packerLayer));
        }

        // Detect packer on the image around the W→X target
        // (imageBase approximation: align down to 64KB boundary for common PE bases)
        GuestAddress approxBase = page & ~static_cast<GuestAddress>(0xFFFF);
        if (approxBase == 0) approxBase = page;

        // Layer 1: the newly-unpacked code
        m_impl->BeginNewLayer(rip, instrCount, memory, approxBase, kPageSize * 16);

        // OEP candidate: W→X target
        m_impl->AddOEPCandidate(rip, OEPMethod::WXTransition, 0.7, instrCount);

        // Check for standard prologue at target — boosts OEP confidence
        if (m_impl->CheckStandardPrologue(memory, rip)) {
            m_impl->AddOEPCandidate(rip, OEPMethod::StackFrame, 0.3, instrCount);
        }
    } else {
        // Subsequent W→X during active unpacking
        // This may indicate:
        // 1. Multi-layer unpacking (packer within packer)
        // 2. Internal W→X within the same packer
        // 3. Self-modifying code in the unpacked payload

        const uint64_t instrSinceLastWX = instrCount - m_impl->layerStartInstr;

        // If we've run fewer instructions than minOEPInstructions since the last
        // W→X, this is likely intra-packer activity — update candidate in-place
        if (instrSinceLastWX < m_impl->config.minOEPInstructions) {
            // Replace the current candidate — this W→X is more recent
            m_impl->AddOEPCandidate(rip, OEPMethod::WXTransition, 0.7, instrCount);

            // Update the current layer's OEP to point to the newest target
            if (m_impl->currentLayerIdx < m_impl->layers.size()) {
                m_impl->layers[m_impl->currentLayerIdx].oep       = rip;
                m_impl->layers[m_impl->currentLayerIdx].codeBase  = PageBase(rip);
            }
        } else {
            // Enough instructions ran since the last layer started —
            // this is a new unpacking layer (multi-layer packing)

            const GuestAddress approxBase = PageBase(rip) & ~static_cast<GuestAddress>(0xFFFF);
            m_impl->BeginNewLayer(rip, instrCount, memory,
                                  approxBase ? approxBase : PageBase(rip),
                                  kPageSize * 16);

            m_impl->AddOEPCandidate(rip, OEPMethod::WXTransition, 0.7, instrCount);

            if (m_impl->CheckStandardPrologue(memory, rip)) {
                m_impl->AddOEPCandidate(rip, OEPMethod::StackFrame, 0.3, instrCount);
            }
        }
    }

    // --- Record entropy at transition point ---
    {
        const double ent = ComputeGuestEntropy(memory, page, kPageSize * 4);
        m_impl->currentEntropy = ent;
        if (m_impl->entropyHistory.size() < kMaxEntropyHistory) {
            m_impl->entropyHistory.emplace_back(instrCount, ent);
        }

        // Entropy drop heuristic: if entropy dropped significantly from previous
        // measurement, this may indicate decompression/decryption completed.
        if (m_impl->previousEntropy > 0.0 &&
            (m_impl->previousEntropy - ent) > m_impl->config.entropyDropThreshold)
        {
            m_impl->AddOEPCandidate(rip, OEPMethod::EntropyDrop, 0.5, instrCount);
        }
        m_impl->previousEntropy = ent;
    }

    // --- Cache PE section info for section-entry heuristic ---
    if (m_impl->cachedSections.empty()) {
        PEHeaderInfo cachedHdr{};
        // Try common image bases
        for (const GuestAddress base : {
                 page & ~static_cast<GuestAddress>(0xFFFF),
                 static_cast<GuestAddress>(0x00400000),
                 static_cast<GuestAddress>(0x0000000140000000ULL)}) {
            if (base == 0) continue;
            if (ReadPEHeaders(memory, base, cachedHdr)) {
                m_impl->cachedSections  = cachedHdr.sections;
                m_impl->cachedImageBase = base;
                m_impl->cachedImageSize = cachedHdr.sizeOfImage;
                m_impl->cachedEPRVA     = cachedHdr.entryPointRVA;
                m_impl->cachedIs64Bit   = cachedHdr.is64Bit;
                break;
            }
        }
    }

    // --- Section-entry heuristic ---
    if (!m_impl->cachedSections.empty() && m_impl->cachedImageBase != 0) {
        const uint32_t ripRVA = static_cast<uint32_t>(rip - m_impl->cachedImageBase);
        if (IsInTextSection(m_impl->cachedSections, ripRVA)) {
            m_impl->AddOEPCandidate(rip, OEPMethod::SectionEntry, 0.5, instrCount);
        }
    }

    // --- Tail-jump heuristic: check if the instruction at the W→X transition
    //     was reached via a long jump (typical packer tail jump to OEP) ---
    {
        // Read a few bytes before the current RIP to see if we arrived via a
        // long jump from a distant location.
        // We check the prevRip: if prevRip was far away (>4KB), treat as tail jump.
        if (m_impl->prevRip != 0) {
            const int64_t distance = static_cast<int64_t>(rip) -
                                     static_cast<int64_t>(m_impl->prevRip);
            if (distance > 4096 || distance < -4096) {
                // This W→X was reached by a long jump — strong OEP signal
                m_impl->AddOEPCandidate(rip, OEPMethod::TailJump, 0.8, instrCount);
            }
        }

        // Also check if the W→X target itself begins with a tail jump
        const GuestAddress tailTarget = DetectTailJump(memory, rip);
        if (tailTarget != 0) {
            m_impl->AddOEPCandidate(tailTarget, OEPMethod::TailJump, 0.8, instrCount);
        }
    }
}

void UnpackingEngine::OnInstruction(GuestAddress rip,
                                     uint64_t instrCount) noexcept
{
    // Fast bail — avoid lock overhead when not actively tracking
    if (!m_impl->unpacking || m_impl->complete) return;

    std::unique_lock lock(m_impl->mutex);

    m_impl->totalInstructions = instrCount;
    m_impl->prevRip           = rip;

    if (m_impl->currentLayerIdx >= m_impl->layers.size()) return;
    auto& layer = m_impl->layers[m_impl->currentLayerIdx];

    const uint64_t layerInstrs = instrCount - m_impl->layerStartInstr;
    layer.instructionsExecuted = layerInstrs;

    // Update code region bounds
    const GuestAddress ripPage = PageBase(rip);
    if (layer.codeBase == 0) {
        layer.codeBase = ripPage;
        layer.codeSize = kPageSize;
    } else if (ripPage < layer.codeBase) {
        layer.codeSize += (layer.codeBase - ripPage);
        layer.codeBase = ripPage;
    } else if (ripPage >= layer.codeBase + layer.codeSize) {
        layer.codeSize = (ripPage - layer.codeBase) + kPageSize;
    }

    // Track instructions since last API call (for decoder-loop detection)
    m_impl->instrSinceLastAPICall = instrCount - m_impl->lastAPIInstr;

    // --- OEP confirmation logic ---
    // After enough instructions execute at the W→X target without another
    // W→X transition, and we have a high-scoring candidate, confirm the OEP.
    if (layerInstrs >= m_impl->config.minOEPInstructions) {
        // Find the best candidate for the current layer
        Impl::OEPCandidate* best = nullptr;
        for (auto& c : m_impl->oepCandidates) {
            if (!c.confirmed && c.instrStamp >= m_impl->layerStartInstr) {
                if (!best || c.score > best->score) {
                    best = &c;
                }
            }
        }

        if (best) {
            // Check confirmation criteria from the scoring spec:
            // 1. Any single heuristic > 0.7 → accept
            // 2. Sum of top 2 heuristic scores > 1.0 → accept
            // 3. Enough instructions ran → accept with moderate score

            const bool singleHighScore = (best->score >= 0.7);
            const bool longRunning = (layerInstrs >= m_impl->config.minOEPInstructions *
                                      kOEPConfirmMultiplier);

            // Collect all candidate scores for the same address to check top-2 sum
            bool topTwoConfirm = false;
            {
                std::array<double, 8> scores{};
                uint32_t scoreCount = 0;
                for (const auto& c : m_impl->oepCandidates) {
                    if (c.address == best->address && scoreCount < scores.size()) {
                        scores[scoreCount++] = c.score;
                    }
                }
                if (scoreCount >= 2) {
                    std::sort(scores.begin(), scores.begin() + scoreCount,
                              std::greater<double>());
                    topTwoConfirm = (scores[0] + scores[1] > 1.0);
                }
            }

            const bool moderateScore = (best->score >= 0.5 &&
                                        layerInstrs >= m_impl->config.minOEPInstructions * 5);

            if (singleHighScore || topTwoConfirm || longRunning || moderateScore) {
                best->confirmed = true;
                m_impl->ConfirmOEP(best->address, best->method);
            }
        }
    }

    // Layer instruction limit
    if (layerInstrs >= m_impl->config.maxInstructionsPerLayer) {
        layer.isComplete = true;
        m_impl->complete = true;

        if (m_impl->finalOEP == 0 && layer.oep != 0) {
            m_impl->finalOEP       = layer.oep;
            m_impl->finalOEPMethod = layer.oepMethod;
        }
    }
}

// ============================================================================
// OnProtectionChange
// ============================================================================

void UnpackingEngine::OnProtectionChange(
    GuestAddress base, GuestSize size,
    MemProt oldProt, MemProt newProt) noexcept
{
    if (!m_impl->unpacking && !HasProt(newProt, MemProt::Execute)) return;

    std::unique_lock lock(m_impl->mutex);

    if (m_impl->protLog.size() < kMaxProtChanges) {
        m_impl->protLog.push_back({base, size, oldProt, newProt});
    }

    // If a region gains Execute permission after being Writable,
    // this is a VirtualProtect-based W→X transition (common in packers
    // that use VirtualProtect instead of writing to RWX pages).
    const bool wasWritable  = HasProt(oldProt, MemProt::Write);
    const bool nowExecutable = HasProt(newProt, MemProt::Execute);

    if (wasWritable && nowExecutable && !HasProt(oldProt, MemProt::Execute)) {
        // This is a protection-based W→X — the actual execution will be caught
        // by OnWXTransition when code runs here. But we note it for scoring.
        if (m_impl->currentLayerIdx < m_impl->layers.size()) {
            m_impl->layers[m_impl->currentLayerIdx].wxTransitions++;
        }
    }
}

// ============================================================================
// OnAPICall
// ============================================================================

void UnpackingEngine::OnAPICall(const char* funcName,
                                 uint64_t instrCount) noexcept
{
    if (!funcName) return;

    std::unique_lock lock(m_impl->mutex);

    // Track for import reconstruction
    if (m_impl->config.enableImportReconstruction) {
        m_impl->RecordImport(funcName);
    }

    // Record in API log (capped)
    if (m_impl->apiLog.size() < kMaxTrackedAPICalls) {
        m_impl->apiLog.push_back({funcName, instrCount});
    }

    // --- OEP heuristic: APICallAfterDecode ---
    // If we're in an active unpacking layer and this is the first API call
    // after a long API-free sequence (the decoder loop), the OEP is near.
    if (m_impl->unpacking && !m_impl->complete &&
        m_impl->currentLayerIdx < m_impl->layers.size())
    {
        const uint64_t instrGap = instrCount - m_impl->lastAPIInstr;

        // A gap of >500 instructions without API calls suggests a decoder loop
        // just completed. The return address of this call is near the OEP.
        if (instrGap > 500 && m_impl->lastWXInstr > 0) {
            const uint64_t instrSinceWX = instrCount - m_impl->lastWXInstr;
            if (instrSinceWX < m_impl->config.maxInstructionsPerLayer) {
                m_impl->AddOEPCandidate(
                    m_impl->lastWXRip,
                    OEPMethod::APICallAfterDecode,
                    0.6,
                    instrCount);

                // Boost the W→X candidate if it exists
                for (auto& c : m_impl->oepCandidates) {
                    if (c.address == m_impl->lastWXRip &&
                        c.method == OEPMethod::WXTransition) {
                        c.score = std::min(c.score + 0.3, 1.5);
                    }
                }
            }
        }
    }

    m_impl->lastAPIInstr          = instrCount;
    m_impl->instrSinceLastAPICall = 0;
}

// ============================================================================
// Layer Management
// ============================================================================

uint32_t UnpackingEngine::GetCurrentLayer() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->currentLayerIdx;
}

const std::vector<UnpackLayer>& UnpackingEngine::GetLayers() const noexcept {
    // Note: caller must not hold this reference across mutations.
    // Safe for analysis after emulation completes.
    return m_impl->layers;
}

bool UnpackingEngine::IsUnpacking() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->unpacking;
}

bool UnpackingEngine::IsComplete() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->complete;
}

// ============================================================================
// OEP Detection
// ============================================================================

GuestAddress UnpackingEngine::GetFinalOEP() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->finalOEP;
}

OEPMethod UnpackingEngine::GetOEPMethod() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->finalOEPMethod;
}

// ============================================================================
// Packer Detection — 30+ packer signatures
// ============================================================================

PackerType UnpackingEngine::DetectPacker(
    const VirtualMemory& memory,
    GuestAddress imageBase,
    GuestSize imageSize) const noexcept
{
    PEHeaderInfo hdr{};
    if (!ReadPEHeaders(memory, imageBase, hdr)) return PackerType::Unknown;

    // Read entry point bytes
    uint8_t epBytes[kMaxEPReadBytes]{};
    const GuestAddress epAddr = imageBase + hdr.entryPointRVA;
    const bool haveEP = ReadGuestBytes(memory, epAddr, epBytes, kMaxEPReadBytes);

    // Determine which section the EP is in
    const int32_t epSectionIdx = FindSectionByRVA(hdr.sections, hdr.entryPointRVA);
    const bool epInLastSection = (epSectionIdx >= 0 &&
        static_cast<size_t>(epSectionIdx) == hdr.sections.size() - 1);

    // Compute entropy of the code section (first section with execute flag)
    double codeEntropy = 0.0;
    for (const auto& sec : hdr.sections) {
        if (sec.characteristics & PE::kSecMemExecute) {
            const GuestAddress secAddr = imageBase + sec.virtualAddress;
            const GuestSize secSize = std::min<GuestSize>(sec.virtualSize, kMaxDataScanSize);
            codeEntropy = ComputeGuestEntropy(memory, secAddr, secSize);
            break;
        }
    }

    // Scoring accumulators per packer
    struct Detection {
        PackerType type   = PackerType::Unknown;
        float      score  = 0.0f;
    };
    static constexpr uint32_t kMaxDetections = 128;
    std::array<Detection, kMaxDetections> dets{};
    uint32_t detCount = 0;

    auto AddScore = [&](PackerType type, float score) {
        for (uint32_t i = 0; i < detCount; ++i) {
            if (dets[i].type == type) {
                dets[i].score += score;
                return;
            }
        }
        if (detCount < kMaxDetections) {
            dets[detCount++] = {type, score};
        }
    };

    // =======================================================================
    // 1. UPX
    // =======================================================================
    if (HasSectionNamed(hdr.sections, "UPX0"))    AddScore(PackerType::UPX, 0.35f);
    if (HasSectionNamed(hdr.sections, "UPX1"))    AddScore(PackerType::UPX, 0.35f);
    if (HasSectionNamed(hdr.sections, "UPX2"))    AddScore(PackerType::UPX, 0.15f);
    if (haveEP) {
        const BytePattern upxEP = {kEP_UPX1_B, kEP_UPX1_M, sizeof(kEP_UPX1_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, upxEP))
            AddScore(PackerType::UPX, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "UPX!"))
        AddScore(PackerType::UPX, 0.25f);
    // Alternative overlay marker
    {
        static constexpr uint8_t upxAlt[] = {0x50, 0x55, 0x50, 0x58, 0x21}; // "PUPX!"
        const BytePattern altPat = {upxAlt, upxAlt, 5}; // exact match
        static constexpr uint8_t altMask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const BytePattern altP = {upxAlt, altMask, 5};
        if (SearchPatternInRegion(memory, imageBase, imageSize, altP))
            AddScore(PackerType::UPX, 0.15f);
    }

    // =======================================================================
    // 2. ASPack
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".aspack")) AddScore(PackerType::ASPack, 0.45f);
    if (HasSectionNamed(hdr.sections, ".adata"))  AddScore(PackerType::ASPack, 0.30f);
    if (haveEP) {
        const BytePattern asEP = {kEP_ASPack_B, kEP_ASPack_M, sizeof(kEP_ASPack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, asEP))
            AddScore(PackerType::ASPack, 0.40f);
    }

    // =======================================================================
    // 3. PECompact
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".pec"))    AddScore(PackerType::PECompact, 0.35f);
    if (HasSectionNamed(hdr.sections, "pec1"))    AddScore(PackerType::PECompact, 0.35f);
    if (HasSectionNamed(hdr.sections, "pec2"))    AddScore(PackerType::PECompact, 0.30f);
    if (FindStr(memory, imageBase, imageSize, "PEC2"))
        AddScore(PackerType::PECompact, 0.25f);
    if (FindStr(memory, imageBase, imageSize, "PECompact2"))
        AddScore(PackerType::PECompact, 0.35f);

    // =======================================================================
    // 4. Themida / WinLicense
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".themida"))  AddScore(PackerType::Themida, 0.60f);
    if (HasSectionNamed(hdr.sections, "WinLice"))   AddScore(PackerType::Themida, 0.50f);
    if (HasSectionNamed(hdr.sections, ".winlice"))  AddScore(PackerType::Themida, 0.50f);
    if (epInLastSection)                            AddScore(PackerType::Themida, 0.10f);
    if (codeEntropy > 7.5)                          AddScore(PackerType::Themida, 0.10f);
    // Themida uses custom TLS callbacks
    if (hdr.numberOfRvaAndSizes > PE::kDirTLS &&
        hdr.dataDirectories[PE::kDirTLS].VirtualAddress != 0 &&
        hdr.dataDirectories[PE::kDirTLS].Size > 0)
    {
        AddScore(PackerType::Themida, 0.08f);
    }
    // Large .rsrc section with high entropy
    for (const auto& sec : hdr.sections) {
        if (std::strncmp(sec.name, ".rsrc", 5) == 0 && sec.virtualSize > 512 * 1024) {
            const GuestAddress rsrcAddr = imageBase + sec.virtualAddress;
            const double rsrcEnt = ComputeGuestEntropy(memory, rsrcAddr,
                std::min<GuestSize>(sec.virtualSize, kMaxDataScanSize));
            if (rsrcEnt > 7.0) AddScore(PackerType::Themida, 0.15f);
        }
    }

    // =======================================================================
    // 5. VMProtect
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".vmp0"))   AddScore(PackerType::VMProtect, 0.45f);
    if (HasSectionNamed(hdr.sections, ".vmp1"))   AddScore(PackerType::VMProtect, 0.45f);
    if (HasSectionNamed(hdr.sections, ".vmp2"))   AddScore(PackerType::VMProtect, 0.25f);
    // EP in VMP section
    if (epSectionIdx >= 0) {
        const char* epSecName = hdr.sections[static_cast<size_t>(epSectionIdx)].name;
        if (std::strncmp(epSecName, ".vmp", 4) == 0)
            AddScore(PackerType::VMProtect, 0.30f);
    }
    if (codeEntropy > 7.5) AddScore(PackerType::VMProtect, 0.05f);

    // =======================================================================
    // 6. Armadillo
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "ArmadilloArgs"))
        AddScore(PackerType::Armadillo, 0.60f);
    if (FindStr(memory, imageBase, imageSize, "Armadillo"))
        AddScore(PackerType::Armadillo, 0.35f);
    if (HasSectionNamed(hdr.sections, ".arma"))   AddScore(PackerType::Armadillo, 0.40f);
    if (codeEntropy > 7.0) AddScore(PackerType::Armadillo, 0.05f);

    // =======================================================================
    // 7. MPRESS
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".MPRESS1")) AddScore(PackerType::MPRESS, 0.45f);
    if (HasSectionNamed(hdr.sections, ".MPRESS2")) AddScore(PackerType::MPRESS, 0.45f);
    if (haveEP) {
        const BytePattern mpEP = {kEP_MPRESS_B, kEP_MPRESS_M, sizeof(kEP_MPRESS_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, mpEP))
            AddScore(PackerType::MPRESS, 0.30f);
    }

    // =======================================================================
    // 8. Petite
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".petite"))  AddScore(PackerType::Petite, 0.55f);
    if (FindStr(memory, imageBase, imageSize, "Petite"))
        AddScore(PackerType::Petite, 0.30f);

    // =======================================================================
    // 9. FSG
    // =======================================================================
    if (haveEP) {
        const BytePattern fsgEP = {kEP_FSG_B, kEP_FSG_M, sizeof(kEP_FSG_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, fsgEP))
            AddScore(PackerType::FSG, 0.55f);
    }
    // EP in second section with small high-entropy first section
    if (hdr.sections.size() >= 2 && epSectionIdx == 1) {
        if (hdr.sections[0].virtualSize < 4096) {
            const GuestAddress s0Addr = imageBase + hdr.sections[0].virtualAddress;
            const double s0Ent = ComputeGuestEntropy(memory, s0Addr,
                hdr.sections[0].virtualSize);
            if (s0Ent > 7.0) AddScore(PackerType::FSG, 0.35f);
        }
    }

    // =======================================================================
    // 10. MEW
    // =======================================================================
    if (HasSectionNamed(hdr.sections, "MEW"))     AddScore(PackerType::MEW, 0.50f);
    if (haveEP) {
        const BytePattern mewEP = {kEP_MEW_B, kEP_MEW_M, sizeof(kEP_MEW_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, mewEP))
            AddScore(PackerType::MEW, 0.40f);
    }

    // =======================================================================
    // 11. NsPack
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".nsp0"))   AddScore(PackerType::NsPack, 0.45f);
    if (HasSectionNamed(hdr.sections, ".nsp1"))   AddScore(PackerType::NsPack, 0.45f);
    if (haveEP) {
        const BytePattern nsEP = {kEP_NsPack_B, kEP_NsPack_M, sizeof(kEP_NsPack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, nsEP))
            AddScore(PackerType::NsPack, 0.30f);
    }

    // =======================================================================
    // 12. PEtite (variant spelling)
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".petite"))  AddScore(PackerType::PEtite, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "PEtite"))
        AddScore(PackerType::PEtite, 0.35f);

    // =======================================================================
    // 13. Obsidium
    // =======================================================================
    if (haveEP) {
        const BytePattern obsEP = {kEP_Obsidium_B, kEP_Obsidium_M, sizeof(kEP_Obsidium_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, obsEP))
            AddScore(PackerType::Obsidium, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "Obsidium"))
        AddScore(PackerType::Obsidium, 0.55f);
    // Large overlay-like regions with high entropy
    if (hdr.sections.size() >= 3 && codeEntropy > 7.2)
        AddScore(PackerType::Obsidium, 0.10f);

    // =======================================================================
    // 14. ExeCryptor
    // =======================================================================
    if (haveEP) {
        const BytePattern ecEP = {kEP_ExeCryptor_B, kEP_ExeCryptor_M,
                                   sizeof(kEP_ExeCryptor_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ecEP))
            AddScore(PackerType::ExeCryptor, 0.30f);
    }
    if (FindStr(memory, imageBase, imageSize, "ExeCryptor"))
        AddScore(PackerType::ExeCryptor, 0.55f);
    // Multiple TLS callbacks
    if (hdr.numberOfRvaAndSizes > PE::kDirTLS &&
        hdr.dataDirectories[PE::kDirTLS].Size > sizeof(PE::TLSDirectory64))
    {
        AddScore(PackerType::ExeCryptor, 0.10f);
    }

    // =======================================================================
    // 15. ASProtect
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".aspr"))   AddScore(PackerType::ASProtect, 0.50f);
    if (haveEP) {
        const BytePattern aspEP = {kEP_ASProtect_B, kEP_ASProtect_M,
                                    sizeof(kEP_ASProtect_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, aspEP))
            AddScore(PackerType::ASProtect, 0.30f);
    }
    if (FindStr(memory, imageBase, imageSize, "ASProtect"))
        AddScore(PackerType::ASProtect, 0.40f);

    // =======================================================================
    // 16. tElock
    // =======================================================================
    if (haveEP) {
        const BytePattern tlEP = {kEP_tElock_B, kEP_tElock_M, sizeof(kEP_tElock_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, tlEP))
            AddScore(PackerType::tElock, 0.35f);
    }
    if (hdr.timestamp == 0) AddScore(PackerType::tElock, 0.20f);
    if (FindStr(memory, imageBase, imageSize, "tElock"))
        AddScore(PackerType::tElock, 0.40f);

    // =======================================================================
    // 17. PESpin
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".pespin"))  AddScore(PackerType::PESpin, 0.50f);
    if (HasSectionNamed(hdr.sections, ".taz"))     AddScore(PackerType::PESpin, 0.35f);
    if (haveEP) {
        const BytePattern psEP = {kEP_PESpin_B, kEP_PESpin_M, sizeof(kEP_PESpin_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, psEP))
            AddScore(PackerType::PESpin, 0.35f);
    }

    // =======================================================================
    // 18. MoleBox
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".mole"))    AddScore(PackerType::MoleBox, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "MoleBox"))
        AddScore(PackerType::MoleBox, 0.45f);

    // =======================================================================
    // 19. BoxedApp
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".bxpck"))   AddScore(PackerType::BoxedApp, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "BoxedApp"))
        AddScore(PackerType::BoxedApp, 0.50f);

    // =======================================================================
    // 20. Enigma Protector
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".enigma1")) AddScore(PackerType::Enigma, 0.45f);
    if (HasSectionNamed(hdr.sections, ".enigma2")) AddScore(PackerType::Enigma, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "Enigma protector"))
        AddScore(PackerType::Enigma, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "Enigma Protector"))
        AddScore(PackerType::Enigma, 0.45f);

    // =======================================================================
    // 21. StarForce
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "StarForce"))
        AddScore(PackerType::StarForce, 0.60f);
    if (HasSectionNamed(hdr.sections, ".sforce"))  AddScore(PackerType::StarForce, 0.45f);

    // =======================================================================
    // 22. SafeDisc
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".stxt"))    AddScore(PackerType::SafeDisc, 0.40f);
    if (FindStr(memory, imageBase, imageSize, "BoG_"))
        AddScore(PackerType::SafeDisc, 0.35f);
    if (FindStr(memory, imageBase, imageSize, "SafeDisc"))
        AddScore(PackerType::SafeDisc, 0.45f);

    // =======================================================================
    // 23. SecuROM
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".securom")) AddScore(PackerType::SecuROM, 0.50f);
    if (HasSectionNamed(hdr.sections, ".srom"))    AddScore(PackerType::SecuROM, 0.35f);
    if (FindStr(memory, imageBase, imageSize, "SecuROM"))
        AddScore(PackerType::SecuROM, 0.50f);

    // =======================================================================
    // 24. CodeVirtualizer (Oreans family, related to Themida)
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".cv"))      AddScore(PackerType::CodeVirtualizer, 0.35f);
    if (HasSectionNamed(hdr.sections, ".cvirt"))   AddScore(PackerType::CodeVirtualizer, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "CodeVirtualizer"))
        AddScore(PackerType::CodeVirtualizer, 0.50f);

    // =======================================================================
    // 25. .NET Obfuscators (ConfuserEx, Babel, Dotfuscator, etc.)
    // =======================================================================
    // Presence of CLR runtime header indicates .NET
    if (hdr.numberOfRvaAndSizes > PE::kDirCLRRuntime &&
        hdr.dataDirectories[PE::kDirCLRRuntime].VirtualAddress != 0 &&
        hdr.dataDirectories[PE::kDirCLRRuntime].Size > 0)
    {
        // .NET binary — check for obfuscation indicators
        AddScore(PackerType::DotNetObfuscator, 0.20f);

        // High entropy in .text suggests encrypted method bodies
        if (codeEntropy > 7.0) AddScore(PackerType::DotNetObfuscator, 0.25f);

        // ConfuserEx signature
        if (FindStr(memory, imageBase, imageSize, "ConfuserEx"))
            AddScore(PackerType::DotNetObfuscator, 0.45f);
        if (FindStr(memory, imageBase, imageSize, "Confuser"))
            AddScore(PackerType::DotNetObfuscator, 0.30f);
        if (FindStr(memory, imageBase, imageSize, "Babel"))
            AddScore(PackerType::DotNetObfuscator, 0.30f);
        if (FindStr(memory, imageBase, imageSize, "Dotfuscator"))
            AddScore(PackerType::DotNetObfuscator, 0.30f);
        if (FindStr(memory, imageBase, imageSize, "SmartAssembly"))
            AddScore(PackerType::DotNetObfuscator, 0.30f);
        if (FindStr(memory, imageBase, imageSize, "Eazfuscator"))
            AddScore(PackerType::DotNetObfuscator, 0.30f);
        if (FindStr(memory, imageBase, imageSize, ".cctor"))
            AddScore(PackerType::DotNetObfuscator, 0.10f);
    }

    // =======================================================================
    // 26. AutoIt compiled scripts
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "AU3!"))
        AddScore(PackerType::AutoIt, 0.55f);
    if (FindStr(memory, imageBase, imageSize, ">>>AUTOIT"))
        AddScore(PackerType::AutoIt, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "AutoIt"))
        AddScore(PackerType::AutoIt, 0.25f);

    // =======================================================================
    // 27. NSIS Installer
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Nullsoft"))
        AddScore(PackerType::NSIS, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "NSIS"))
        AddScore(PackerType::NSIS, 0.35f);
    if (FindStr(memory, imageBase, imageSize, "NullsoftInst"))
        AddScore(PackerType::NSIS, 0.40f);

    // =======================================================================
    // 28. Inno Setup
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Inno Setup"))
        AddScore(PackerType::InnoSetup, 0.60f);
    if (FindStr(memory, imageBase, imageSize, "InnoSetup"))
        AddScore(PackerType::InnoSetup, 0.50f);

    // =======================================================================
    // 29. PyInstaller
    // =======================================================================
    {
        // MEI signature near end of image
        static constexpr uint8_t pyMEI[] = {
            0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E
        };
        static constexpr uint8_t pyMask[] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        const BytePattern pyPat = {pyMEI, pyMask, 8};
        if (SearchPatternInRegion(memory, imageBase, imageSize, pyPat))
            AddScore(PackerType::PyInstaller, 0.55f);
    }
    if (FindStr(memory, imageBase, imageSize, "PyInstaller"))
        AddScore(PackerType::PyInstaller, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "pyi-"))
        AddScore(PackerType::PyInstaller, 0.20f);

    // =======================================================================
    // 30. Custom/heuristic packer detection
    // =======================================================================
    // If code entropy is very high and EP is in a non-standard section,
    // flag as a custom packer.
    if (codeEntropy > m_impl->config.entropyThreshold) {
        if (epInLastSection || epSectionIdx > 0) {
            AddScore(PackerType::PackerCustom, 0.30f);
        }
        if (hdr.sections.size() <= 2 && codeEntropy > 7.5) {
            AddScore(PackerType::PackerCustom, 0.25f);
        }
    }
    // All sections with high entropy (fully encrypted binary)
    {
        uint32_t highEntSections = 0;
        for (const auto& sec : hdr.sections) {
            if (sec.virtualSize < 256) continue;
            const GuestAddress sAddr = imageBase + sec.virtualAddress;
            const double sEnt = ComputeGuestEntropy(memory, sAddr,
                std::min<GuestSize>(sec.virtualSize, kMaxDataScanSize / 4));
            if (sEnt > 7.2) highEntSections++;
        }
        if (highEntSections >= 2) AddScore(PackerType::PackerCustom, 0.20f);
    }

    // =======================================================================
    // 31. Section-name-based supplementary detection
    // =======================================================================
    for (const auto& mapping : kSectionPackerMap) {
        if (HasSectionNamed(hdr.sections, mapping.sectionName)) {
            AddScore(mapping.packerType, 0.30f);
        }
    }

    // =======================================================================
    // 32. Themida v3
    // =======================================================================
    if (haveEP) {
        const BytePattern thV3 = {kEP_ThemidaV3_B, kEP_ThemidaV3_M, sizeof(kEP_ThemidaV3_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, thV3))
            AddScore(PackerType::ThemidaV3, 0.45f);
    }
    if (HasSectionNamed(hdr.sections, ".themida")) AddScore(PackerType::ThemidaV3, 0.30f);

    // =======================================================================
    // 33. Themida v1/v2
    // =======================================================================
    if (haveEP) {
        const BytePattern thV1 = {kEP_ThemidaV1_B, kEP_ThemidaV1_M, sizeof(kEP_ThemidaV1_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, thV1))
            AddScore(PackerType::ThemidaV1, 0.40f);
        const BytePattern thV2 = {kEP_ThemidaV2_B, kEP_ThemidaV2_M, sizeof(kEP_ThemidaV2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, thV2))
            AddScore(PackerType::ThemidaV2, 0.40f);
    }

    // =======================================================================
    // 34. VMProtect v3 / 1.x / 2.x
    // =======================================================================
    if (haveEP) {
        const BytePattern vmpV3 = {kEP_VMPv3_B, kEP_VMPv3_M, sizeof(kEP_VMPv3_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, vmpV3))
            AddScore(PackerType::VMProtect, 0.40f);

        const BytePattern vmp1x = {kEP_VMP1x_B, kEP_VMP1x_M, sizeof(kEP_VMP1x_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, vmp1x)) {
            // VMP 1.x uses a simple JMP to vmp section
            if (epSectionIdx >= 0 &&
                std::strncmp(hdr.sections[static_cast<size_t>(epSectionIdx)].name, ".vmp", 4) == 0)
                AddScore(PackerType::VMProtect1x, 0.55f);
        }

        const BytePattern vmp2x = {kEP_VMP2x_B, kEP_VMP2x_M, sizeof(kEP_VMP2x_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, vmp2x))
            AddScore(PackerType::VMProtect2x, 0.45f);
    }

    // =======================================================================
    // 35. Enigma Protector EP
    // =======================================================================
    if (haveEP) {
        const BytePattern enEP = {kEP_Enigma_B, kEP_Enigma_M, sizeof(kEP_Enigma_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, enEP))
            AddScore(PackerType::Enigma, 0.35f);
    }

    // =======================================================================
    // 36. PELock
    // =======================================================================
    if (haveEP) {
        const BytePattern plEP = {kEP_PELock_B, kEP_PELock_M, sizeof(kEP_PELock_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, plEP))
            AddScore(PackerType::PELock, 0.40f);
    }
    if (HasSectionNamed(hdr.sections, ".perplex")) AddScore(PackerType::PELock, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "PELock"))
        AddScore(PackerType::PELock, 0.40f);

    // =======================================================================
    // 37. Armadillo EP variant
    // =======================================================================
    if (haveEP) {
        const BytePattern armEP = {kEP_Armadillo_B, kEP_Armadillo_M, sizeof(kEP_Armadillo_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, armEP))
            AddScore(PackerType::Armadillo, 0.40f);

        const BytePattern armV9 = {kEP_ArmadilloV9_B, kEP_ArmadilloV9_M, sizeof(kEP_ArmadilloV9_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, armV9))
            AddScore(PackerType::ArmadilloV9, 0.45f);
    }

    // =======================================================================
    // 38. ACProtect
    // =======================================================================
    if (haveEP) {
        const BytePattern acEP = {kEP_ACProtect_B, kEP_ACProtect_M, sizeof(kEP_ACProtect_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, acEP))
            AddScore(PackerType::ACProtect, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "ACProtect"))
        AddScore(PackerType::ACProtect, 0.45f);

    // =======================================================================
    // 39. ExeCryptor v2.x
    // =======================================================================
    if (haveEP) {
        const BytePattern ecV2 = {kEP_ExeCryptorV2_B, kEP_ExeCryptorV2_M, sizeof(kEP_ExeCryptorV2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ecV2))
            AddScore(PackerType::ExeCryptorV2, 0.40f);
    }

    // =======================================================================
    // 40. SafeEngine
    // =======================================================================
    if (haveEP) {
        const BytePattern seEP = {kEP_SafeEngine_B, kEP_SafeEngine_M, sizeof(kEP_SafeEngine_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, seEP))
            AddScore(PackerType::SafeEngine, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "SafeEngine"))
        AddScore(PackerType::SafeEngine, 0.50f);

    // =======================================================================
    // 41. WinLicense
    // =======================================================================
    if (haveEP) {
        const BytePattern wlEP = {kEP_WinLicense_B, kEP_WinLicense_M, sizeof(kEP_WinLicense_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, wlEP))
            AddScore(PackerType::WinLicense, 0.40f);
    }
    if (HasSectionNamed(hdr.sections, ".winlice")) AddScore(PackerType::WinLicense, 0.45f);

    // =======================================================================
    // 42. CodeWall
    // =======================================================================
    if (haveEP) {
        const BytePattern cwEP = {kEP_CodeWall_B, kEP_CodeWall_M, sizeof(kEP_CodeWall_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, cwEP))
            AddScore(PackerType::CodeWall, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "CodeWall"))
        AddScore(PackerType::CodeWall, 0.50f);

    // =======================================================================
    // 43. PrivateEXE Protector
    // =======================================================================
    if (haveEP) {
        const BytePattern peEP = {kEP_PrivateEXE_B, kEP_PrivateEXE_M, sizeof(kEP_PrivateEXE_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, peEP))
            AddScore(PackerType::PrivateEXE, 0.30f);
    }
    if (FindStr(memory, imageBase, imageSize, "PrivateExe"))
        AddScore(PackerType::PrivateEXE, 0.50f);

    // =======================================================================
    // 44. PC Guard
    // =======================================================================
    if (haveEP) {
        const BytePattern pgEP = {kEP_PCGuard_B, kEP_PCGuard_M, sizeof(kEP_PCGuard_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pgEP))
            AddScore(PackerType::PCGuard, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "PC Guard"))
        AddScore(PackerType::PCGuard, 0.50f);

    // =======================================================================
    // 45. GameGuard
    // =======================================================================
    if (haveEP) {
        const BytePattern ggEP = {kEP_GameGuard_B, kEP_GameGuard_M, sizeof(kEP_GameGuard_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ggEP))
            AddScore(PackerType::GameGuard, 0.30f);
    }
    if (FindStr(memory, imageBase, imageSize, "GameGuard"))
        AddScore(PackerType::GameGuard, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "nProtect"))
        AddScore(PackerType::GameGuard, 0.40f);

    // =======================================================================
    // 46. Denuvo
    // =======================================================================
    if (haveEP) {
        const BytePattern dnEP = {kEP_Denuvo_B, kEP_Denuvo_M, sizeof(kEP_Denuvo_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, dnEP))
            AddScore(PackerType::Denuvo, 0.25f);
    }
    if (FindStr(memory, imageBase, imageSize, "denuvo"))
        AddScore(PackerType::Denuvo, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "Denuvo"))
        AddScore(PackerType::Denuvo, 0.45f);

    // =======================================================================
    // 47. UPX Modified / Scrambled
    // =======================================================================
    if (haveEP) {
        const BytePattern uxm = {kEP_UPXMod_B, kEP_UPXMod_M, sizeof(kEP_UPXMod_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, uxm))
            AddScore(PackerType::UPXModified, 0.40f);
        const BytePattern uxs = {kEP_UPXScram_B, kEP_UPXScram_M, sizeof(kEP_UPXScram_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, uxs))
            AddScore(PackerType::UPXScrambled, 0.40f);
    }
    // Modified UPX: has UPX sections but no "UPX!" marker (stripped)
    if (HasSectionNamed(hdr.sections, "UPX0") && HasSectionNamed(hdr.sections, "UPX1")) {
        if (!FindStr(memory, imageBase, imageSize, "UPX!"))
            AddScore(PackerType::UPXModified, 0.35f);
    }

    // =======================================================================
    // 48. PECompact v2 / v3
    // =======================================================================
    if (haveEP) {
        const BytePattern pcV2 = {kEP_PECompactV2_B, kEP_PECompactV2_M, sizeof(kEP_PECompactV2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pcV2))
            AddScore(PackerType::PECompactV2, 0.45f);
        const BytePattern pcV3 = {kEP_PECompactV3_B, kEP_PECompactV3_M, sizeof(kEP_PECompactV3_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pcV3))
            AddScore(PackerType::PECompactV3, 0.40f);
    }

    // =======================================================================
    // 49. Petite versions
    // =======================================================================
    if (haveEP) {
        const BytePattern ptV21 = {kEP_PetiteV21_B, kEP_PetiteV21_M, sizeof(kEP_PetiteV21_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ptV21))
            AddScore(PackerType::PetiteV21, 0.45f);
        const BytePattern ptV22 = {kEP_PetiteV22_B, kEP_PetiteV22_M, sizeof(kEP_PetiteV22_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ptV22))
            AddScore(PackerType::PetiteV22, 0.45f);
        const BytePattern ptV23 = {kEP_PetiteV23_B, kEP_PetiteV23_M, sizeof(kEP_PetiteV23_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ptV23))
            AddScore(PackerType::PetiteV23, 0.45f);
    }

    // =======================================================================
    // 50. kkrunchy
    // =======================================================================
    if (haveEP) {
        const BytePattern kkEP = {kEP_kkrunchy_B, kEP_kkrunchy_M, sizeof(kEP_kkrunchy_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, kkEP))
            AddScore(PackerType::kkrunchy, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "kkrunchy"))
        AddScore(PackerType::kkrunchy, 0.50f);

    // =======================================================================
    // 51. Crunch/Cexe
    // =======================================================================
    if (haveEP) {
        const BytePattern crEP = {kEP_CrunchCexe_B, kEP_CrunchCexe_M, sizeof(kEP_CrunchCexe_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, crEP))
            AddScore(PackerType::CrunchCexe, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "Cexe"))
        AddScore(PackerType::CrunchCexe, 0.40f);

    // =======================================================================
    // 52. RLPack
    // =======================================================================
    if (haveEP) {
        const BytePattern rlEP = {kEP_RLPack_B, kEP_RLPack_M, sizeof(kEP_RLPack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, rlEP))
            AddScore(PackerType::RLPack, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "RLPack"))
        AddScore(PackerType::RLPack, 0.45f);

    // =======================================================================
    // 53. nPack
    // =======================================================================
    if (haveEP) {
        const BytePattern npEP = {kEP_nPack_B, kEP_nPack_M, sizeof(kEP_nPack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, npEP))
            AddScore(PackerType::nPack, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "nPack"))
        AddScore(PackerType::nPack, 0.45f);

    // =======================================================================
    // 54. WinUpack/Upack
    // =======================================================================
    if (haveEP) {
        const BytePattern upEP = {kEP_WinUpack_B, kEP_WinUpack_M, sizeof(kEP_WinUpack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, upEP))
            AddScore(PackerType::WinUpack, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "Upack"))
        AddScore(PackerType::WinUpack, 0.40f);
    if (FindStr(memory, imageBase, imageSize, "WinUpack"))
        AddScore(PackerType::WinUpack, 0.45f);

    // =======================================================================
    // 55. JDPack
    // =======================================================================
    if (haveEP) {
        const BytePattern jdEP = {kEP_JDPack_B, kEP_JDPack_M, sizeof(kEP_JDPack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, jdEP))
            AddScore(PackerType::JDPack, 0.40f);
    }

    // =======================================================================
    // 56. BeRoEXE Packer
    // =======================================================================
    if (haveEP) {
        const BytePattern brEP = {kEP_BeRoEXE_B, kEP_BeRoEXE_M, sizeof(kEP_BeRoEXE_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, brEP))
            AddScore(PackerType::BeRoEXE, 0.45f);
    }
    if (FindStr(memory, imageBase, imageSize, "BeRoEXE"))
        AddScore(PackerType::BeRoEXE, 0.45f);

    // =======================================================================
    // 57. Packman
    // =======================================================================
    if (haveEP) {
        const BytePattern pmEP = {kEP_Packman_B, kEP_Packman_M, sizeof(kEP_Packman_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pmEP))
            AddScore(PackerType::Packman, 0.40f);
    }

    // =======================================================================
    // 58. YodaCrypt
    // =======================================================================
    if (haveEP) {
        const BytePattern ycEP = {kEP_YodaCrypt_B, kEP_YodaCrypt_M, sizeof(kEP_YodaCrypt_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ycEP))
            AddScore(PackerType::YodaCrypt, 0.45f);
    }
    if (FindStr(memory, imageBase, imageSize, "Yoda"))
        AddScore(PackerType::YodaCrypt, 0.35f);

    // =======================================================================
    // 59. PEBundle
    // =======================================================================
    if (haveEP) {
        const BytePattern pbEP = {kEP_PEBundle_B, kEP_PEBundle_M, sizeof(kEP_PEBundle_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pbEP))
            AddScore(PackerType::PEBundle, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "PEBundle"))
        AddScore(PackerType::PEBundle, 0.45f);

    // =======================================================================
    // 60. DotFix NiceProtect
    // =======================================================================
    if (haveEP) {
        const BytePattern dfEP = {kEP_DotFixNice_B, kEP_DotFixNice_M, sizeof(kEP_DotFixNice_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, dfEP))
            AddScore(PackerType::DotFixNice, 0.40f);
    }
    if (FindStr(memory, imageBase, imageSize, "NiceProtect"))
        AddScore(PackerType::DotFixNice, 0.45f);

    // =======================================================================
    // 61. PEX
    // =======================================================================
    if (haveEP) {
        const BytePattern pxEP = {kEP_PEX_B, kEP_PEX_M, sizeof(kEP_PEX_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, pxEP))
            AddScore(PackerType::PEX, 0.35f);
    }

    // =======================================================================
    // 62. Alex Protector
    // =======================================================================
    if (haveEP) {
        const BytePattern axEP = {kEP_AlexProtect_B, kEP_AlexProtect_M, sizeof(kEP_AlexProtect_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, axEP))
            AddScore(PackerType::AlexProtect, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "AlexProtector"))
        AddScore(PackerType::AlexProtect, 0.50f);

    // =======================================================================
    // 63. AntiCrack Protector
    // =======================================================================
    if (haveEP) {
        const BytePattern acrkEP = {kEP_AntiCrack_B, kEP_AntiCrack_M, sizeof(kEP_AntiCrack_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, acrkEP))
            AddScore(PackerType::AntiCrack, 0.40f);
    }

    // =======================================================================
    // 64. ConfuserEx (specific .NET detection)
    // =======================================================================
    if (hdr.numberOfRvaAndSizes > PE::kDirCLRRuntime &&
        hdr.dataDirectories[PE::kDirCLRRuntime].VirtualAddress != 0)
    {
        if (FindStr(memory, imageBase, imageSize, "ConfuserEx"))
            AddScore(PackerType::ConfuserEx, 0.60f);
        if (FindStr(memory, imageBase, imageSize, "Confuser"))
            AddScore(PackerType::ConfuserEx, 0.35f);
    }

    // =======================================================================
    // 65. Dotfuscator
    // =======================================================================
    if (hdr.numberOfRvaAndSizes > PE::kDirCLRRuntime &&
        hdr.dataDirectories[PE::kDirCLRRuntime].VirtualAddress != 0)
    {
        if (FindStr(memory, imageBase, imageSize, "Dotfuscator"))
            AddScore(PackerType::Dotfuscator, 0.55f);
    }

    // =======================================================================
    // 66. SmartAssembly / Eazfuscator / Babel / DNGuard / .NET Reactor
    // =======================================================================
    if (hdr.numberOfRvaAndSizes > PE::kDirCLRRuntime &&
        hdr.dataDirectories[PE::kDirCLRRuntime].VirtualAddress != 0)
    {
        if (FindStr(memory, imageBase, imageSize, "SmartAssembly"))
            AddScore(PackerType::SmartAssembly, 0.55f);
        if (FindStr(memory, imageBase, imageSize, "Eazfuscator"))
            AddScore(PackerType::Eazfuscator, 0.55f);
        if (FindStr(memory, imageBase, imageSize, "Babel"))
            AddScore(PackerType::BabelNet, 0.40f);
        if (FindStr(memory, imageBase, imageSize, "DNGuard"))
            AddScore(PackerType::DNGuard, 0.55f);
        if (FindStr(memory, imageBase, imageSize, ".NET Reactor"))
            AddScore(PackerType::NetReactor, 0.55f);
        if (FindStr(memory, imageBase, imageSize, "NetReactor"))
            AddScore(PackerType::NetReactor, 0.45f);
        if (FindStr(memory, imageBase, imageSize, "MaxtoCode"))
            AddScore(PackerType::MaxtoCode, 0.55f);
        if (FindStr(memory, imageBase, imageSize, "Agile.NET"))
            AddScore(PackerType::Agile, 0.55f);
        if (FindStr(memory, imageBase, imageSize, "Xenocode"))
            AddScore(PackerType::Xenocode, 0.50f);
    }

    // =======================================================================
    // 67. AutoHotkey compiled
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "AutoHotkey"))
        AddScore(PackerType::AutoHotkey, 0.55f);
    if (FindStr(memory, imageBase, imageSize, ">AUTOHOTKEY"))
        AddScore(PackerType::AutoHotkey, 0.45f);

    // =======================================================================
    // 68. PyArmor
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "pyarmor"))
        AddScore(PackerType::PyArmor, 0.55f);
    if (FindStr(memory, imageBase, imageSize, "PyArmor"))
        AddScore(PackerType::PyArmor, 0.55f);

    // =======================================================================
    // 69. Cython compiled
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Cython"))
        AddScore(PackerType::Cython, 0.40f);
    if (FindStr(memory, imageBase, imageSize, "__pyx_"))
        AddScore(PackerType::Cython, 0.35f);

    // =======================================================================
    // 70. Go binary
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "go.buildid"))
        AddScore(PackerType::GoBinary, 0.55f);
    if (FindStr(memory, imageBase, imageSize, "__go_buildinfo"))
        AddScore(PackerType::GoBinary, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "runtime.main"))
        AddScore(PackerType::GoBinary, 0.25f);
    if (HasSectionNamed(hdr.sections, ".symtab"))
        AddScore(PackerType::GoBinary, 0.15f);

    // =======================================================================
    // 71. 7-Zip SFX
    // =======================================================================
    {
        static constexpr uint8_t k7zSig[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
        static constexpr uint8_t k7zMask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const BytePattern szPat = {k7zSig, k7zMask, 6};
        if (SearchPatternInRegion(memory, imageBase, imageSize, szPat))
            AddScore(PackerType::SevenZipSFX, 0.55f);
    }
    if (FindStr(memory, imageBase, imageSize, "7-Zip"))
        AddScore(PackerType::SevenZipSFX, 0.30f);

    // =======================================================================
    // 72. WinRAR SFX
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "RAR!"))
        AddScore(PackerType::WinRARSFX, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "WinRAR SFX"))
        AddScore(PackerType::WinRARSFX, 0.45f);
    {
        static constexpr uint8_t kRarSig[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
        static constexpr uint8_t kRarMask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const BytePattern rarPat = {kRarSig, kRarMask, 6};
        if (SearchPatternInRegion(memory, imageBase, imageSize, rarPat))
            AddScore(PackerType::WinRARSFX, 0.40f);
    }

    // =======================================================================
    // 73. WinZip SFX
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "WinZip"))
        AddScore(PackerType::WinZipSFX, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "WZSFX"))
        AddScore(PackerType::WinZipSFX, 0.40f);

    // =======================================================================
    // 74. InstallShield
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "InstallShield"))
        AddScore(PackerType::InstallShield, 0.55f);
    if (FindStr(memory, imageBase, imageSize, "iKernel"))
        AddScore(PackerType::InstallShield, 0.30f);

    // =======================================================================
    // 75. Wise Installer
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Wise"))
        AddScore(PackerType::WiseInstaller, 0.25f);
    if (FindStr(memory, imageBase, imageSize, "WiseMain"))
        AddScore(PackerType::WiseInstaller, 0.50f);

    // =======================================================================
    // 76. NSIS Variants
    // =======================================================================
    if (HasSectionNamed(hdr.sections, ".ndata"))  AddScore(PackerType::NSISVariant, 0.45f);
    if (HasSectionNamed(hdr.sections, ".ndata2")) AddScore(PackerType::NSISVariant, 0.40f);

    // =======================================================================
    // 77. Inno Setup Variants
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Inno Setup Setup Data"))
        AddScore(PackerType::InnoSetupVariant, 0.60f);

    // =======================================================================
    // 78. Electron ASAR
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "electron.asar"))
        AddScore(PackerType::ElectronASAR, 0.55f);
    if (FindStr(memory, imageBase, imageSize, "app.asar"))
        AddScore(PackerType::ElectronASAR, 0.35f);

    // =======================================================================
    // 79. TigerVMP
    // =======================================================================
    if (haveEP) {
        const BytePattern tvEP = {kEP_TigerVMP_B, kEP_TigerVMP_M, sizeof(kEP_TigerVMP_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, tvEP))
            AddScore(PackerType::TigerVMP, 0.40f);
    }
    if (HasSectionNamed(hdr.sections, ".tiger"))  AddScore(PackerType::TigerVMP, 0.50f);

    // =======================================================================
    // 80. ReWolf
    // =======================================================================
    if (haveEP) {
        const BytePattern rwEP = {kEP_ReWolf_B, kEP_ReWolf_M, sizeof(kEP_ReWolf_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, rwEP))
            AddScore(PackerType::ReWolf, 0.35f);
    }
    if (FindStr(memory, imageBase, imageSize, "ReWolf"))
        AddScore(PackerType::ReWolf, 0.50f);

    // =======================================================================
    // 81-90. Version-specific EP patterns
    // =======================================================================
    if (haveEP) {
        const BytePattern asV2 = {kEP_ASPackV2_B, kEP_ASPackV2_M, sizeof(kEP_ASPackV2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, asV2))
            AddScore(PackerType::ASPackV2, 0.45f);

        const BytePattern nsV3 = {kEP_NSPackV3_B, kEP_NSPackV3_M, sizeof(kEP_NSPackV3_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, nsV3))
            AddScore(PackerType::NSPackV3, 0.45f);

        const BytePattern mpV2 = {kEP_MPRESSv2_B, kEP_MPRESSv2_M, sizeof(kEP_MPRESSv2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, mpV2))
            AddScore(PackerType::MPRESSv2, 0.45f);

        const BytePattern fgV2 = {kEP_FSGv2_B, kEP_FSGv2_M, sizeof(kEP_FSGv2_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, fgV2))
            AddScore(PackerType::FSGv2, 0.50f);

        const BytePattern mwV11 = {kEP_MEWv11_B, kEP_MEWv11_M, sizeof(kEP_MEWv11_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, mwV11))
            AddScore(PackerType::MEWv11, 0.45f);

        const BytePattern psV1 = {kEP_PESpinV1_B, kEP_PESpinV1_M, sizeof(kEP_PESpinV1_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, psV1))
            AddScore(PackerType::PESpinV1, 0.45f);

        const BytePattern tlV098 = {kEP_tElockV098_B, kEP_tElockV098_M, sizeof(kEP_tElockV098_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, tlV098))
            AddScore(PackerType::tElockV098, 0.40f);

        const BytePattern obV1 = {kEP_ObsidiumV1_B, kEP_ObsidiumV1_M, sizeof(kEP_ObsidiumV1_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, obV1))
            AddScore(PackerType::ObsidiumV1, 0.40f);

        const BytePattern ffEP = {kEP_FinFisher_B, kEP_FinFisher_M, sizeof(kEP_FinFisher_B)};
        if (MatchPattern(epBytes, kMaxEPReadBytes, ffEP))
            AddScore(PackerType::PackerCustom, 0.35f);
    }

    // =======================================================================
    // 91+. Spoon/Turbo, MoleBox Ultra, BoxedApp variant
    // =======================================================================
    if (FindStr(memory, imageBase, imageSize, "Spoon"))
        AddScore(PackerType::Spoon, 0.35f);
    if (FindStr(memory, imageBase, imageSize, "TurboStudio"))
        AddScore(PackerType::Spoon, 0.45f);
    if (FindStr(memory, imageBase, imageSize, "MoleBox Ultra"))
        AddScore(PackerType::MoleBoxUltra, 0.50f);
    if (FindStr(memory, imageBase, imageSize, "BoxedApp"))
        AddScore(PackerType::BoxedAppVariant, 0.40f);

    // =======================================================================
    // Select best detection
    // =======================================================================
    static constexpr float kDetectionThreshold = 0.55f;

    PackerType bestType  = PackerType::Unknown;
    float      bestScore = 0.0f;

    for (uint32_t i = 0; i < detCount; ++i) {
        if (dets[i].score > bestScore) {
            bestScore = dets[i].score;
            bestType  = dets[i].type;
        }
    }

    return (bestScore >= kDetectionThreshold) ? bestType : PackerType::Unknown;
}

// ============================================================================
// PE Dumping — Extract a valid PE file from guest memory
// ============================================================================

std::vector<uint8_t> UnpackingEngine::DumpPE(
    const VirtualMemory& memory,
    GuestAddress imageBase,
    GuestSize imageSize) const noexcept
{
    std::vector<uint8_t> result;

    PEHeaderInfo hdr{};
    if (!ReadPEHeaders(memory, imageBase, hdr)) return result;

    if (hdr.sizeOfImage == 0 || hdr.sizeOfImage > m_impl->config.maxDumpSize) return result;

    const uint32_t fileAlignment = std::max(hdr.fileAlignment, 0x200u);
    const uint32_t sectionAlignment = std::max(hdr.sectionAlignment, 0x1000u);

    // --- Phase 1: Read original headers from guest memory ---
    const uint32_t headerSize = AlignUp32(hdr.sizeOfHeaders, fileAlignment);
    std::vector<uint8_t> headers(headerSize, 0);
    ReadGuestBytes(memory, imageBase, headers.data(),
                   std::min(hdr.sizeOfHeaders, headerSize));

    // --- Phase 2: Compute new file layout ---
    struct SectionLayout {
        uint32_t fileOffset  = 0;
        uint32_t fileSize    = 0;
        uint32_t virtualAddr = 0;
        uint32_t virtualSize = 0;
    };
    std::vector<SectionLayout> layout;
    layout.reserve(hdr.sections.size());

    uint32_t currentFileOffset = headerSize;
    for (const auto& sec : hdr.sections) {
        SectionLayout sl;
        sl.virtualAddr = sec.virtualAddress;
        sl.virtualSize = sec.virtualSize;
        sl.fileSize    = AlignUp32(std::max(sec.virtualSize, 1u), fileAlignment);
        sl.fileOffset  = currentFileOffset;

        // Prevent runaway sizes
        if (sl.fileSize > m_impl->config.maxDumpSize ||
            currentFileOffset > m_impl->config.maxDumpSize - sl.fileSize)
        {
            break;
        }

        layout.push_back(sl);
        currentFileOffset += sl.fileSize;
    }

    const uint32_t totalFileSize = currentFileOffset;
    if (totalFileSize > m_impl->config.maxDumpSize) return result;

    // --- Phase 3: Allocate output buffer ---
    try {
        result.resize(totalFileSize, 0);
    } catch (...) {
        return {};
    }

    // --- Phase 4: Write headers ---
    std::memcpy(result.data(), headers.data(),
                std::min<size_t>(headerSize, headers.size()));

    // --- Phase 5: Patch section headers in the output ---
    PE::DOSHeader dos{};
    std::memcpy(&dos, result.data(), sizeof(dos));
    const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
    const uint32_t fileHdrOff = ntOffset + 4;
    const uint32_t optHdrOff  = fileHdrOff + sizeof(PE::FileHeader);

    PE::FileHeader fh{};
    std::memcpy(&fh, result.data() + fileHdrOff, sizeof(fh));
    const uint32_t secTableOff = optHdrOff + fh.SizeOfOptionalHeader;

    for (size_t i = 0; i < layout.size() && i < hdr.sections.size(); ++i) {
        const uint32_t shOff = secTableOff +
            static_cast<uint32_t>(i) * sizeof(PE::SectionHeader);
        if (shOff + sizeof(PE::SectionHeader) > headerSize) break;

        PE::SectionHeader sh{};
        std::memcpy(&sh, result.data() + shOff, sizeof(sh));

        sh.SizeOfRawData    = layout[i].fileSize;
        sh.PointerToRawData = layout[i].fileOffset;
        sh.VirtualSize      = layout[i].virtualSize;

        std::memcpy(result.data() + shOff, &sh, sizeof(sh));
    }

    // --- Phase 6: Patch optional header fields ---
    if (hdr.is64Bit) {
        if (optHdrOff + sizeof(PE::OptionalHeader64) <= headerSize) {
            PE::OptionalHeader64 opt{};
            std::memcpy(&opt, result.data() + optHdrOff, sizeof(opt));
            opt.SizeOfImage   = AlignUp32(
                layout.empty() ? headerSize :
                    (layout.back().virtualAddr + layout.back().virtualSize),
                sectionAlignment);
            opt.SizeOfHeaders = headerSize;
            opt.FileAlignment = fileAlignment;

            // Patch entry point to detected OEP if available
            {
                std::shared_lock lock(m_impl->mutex);
                if (m_impl->finalOEP != 0 && m_impl->finalOEP > imageBase) {
                    const uint64_t oepRVA = m_impl->finalOEP - imageBase;
                    if (oepRVA < UINT32_MAX) {
                        opt.AddressOfEntryPoint = static_cast<uint32_t>(oepRVA);
                    }
                }
            }

            std::memcpy(result.data() + optHdrOff, &opt, sizeof(opt));
        }
    } else {
        if (optHdrOff + sizeof(PE::OptionalHeader32) <= headerSize) {
            PE::OptionalHeader32 opt{};
            std::memcpy(&opt, result.data() + optHdrOff, sizeof(opt));
            opt.SizeOfImage   = AlignUp32(
                layout.empty() ? headerSize :
                    (layout.back().virtualAddr + layout.back().virtualSize),
                sectionAlignment);
            opt.SizeOfHeaders = headerSize;
            opt.FileAlignment = fileAlignment;

            {
                std::shared_lock lock(m_impl->mutex);
                if (m_impl->finalOEP != 0 && m_impl->finalOEP > imageBase) {
                    const uint64_t oepRVA = m_impl->finalOEP - imageBase;
                    if (oepRVA < UINT32_MAX) {
                        opt.AddressOfEntryPoint = static_cast<uint32_t>(oepRVA);
                    }
                }
            }

            std::memcpy(result.data() + optHdrOff, &opt, sizeof(opt));
        }
    }

    // --- Phase 7: Copy section data from guest memory ---
    for (size_t i = 0; i < layout.size(); ++i) {
        const auto& sl = layout[i];
        if (sl.fileOffset + sl.fileSize > totalFileSize) break;

        const GuestAddress secVA = imageBase + sl.virtualAddr;
        const uint32_t readSize  = std::min(sl.virtualSize, sl.fileSize);

        // Read page-by-page into the output buffer
        uint32_t bytesRead = 0;
        while (bytesRead < readSize) {
            const GuestAddress readAddr = secVA + bytesRead;
            const uint8_t* ptr = memory.GetHostReadPtr(readAddr);
            if (!ptr) {
                // Unmapped page — leave as zeroes
                const uint32_t skip = static_cast<uint32_t>(
                    kPageSize - (readAddr & kPageMask));
                bytesRead += std::min(skip, readSize - bytesRead);
                continue;
            }

            const uint32_t pageOff  = static_cast<uint32_t>(readAddr & kPageMask);
            const uint32_t canCopy  = static_cast<uint32_t>(kPageSize - pageOff);
            const uint32_t toCopy   = std::min(canCopy, readSize - bytesRead);
            const uint32_t destOff  = sl.fileOffset + bytesRead;

            if (destOff + toCopy <= totalFileSize) {
                std::memcpy(result.data() + destOff, ptr, toCopy);
            }
            bytesRead += toCopy;
        }
    }

    return result;
}

// ============================================================================
// Import Reconstruction
// ============================================================================

bool UnpackingEngine::ReconstructImports(
    VirtualMemory& memory,
    GuestAddress imageBase,
    GuestSize imageSize) noexcept
{
    std::unique_lock lock(m_impl->mutex);

    // --- Step 1: Try to validate the existing import directory ---
    PEHeaderInfo hdr{};
    if (!ReadPEHeaders(memory, imageBase, hdr)) return false;

    bool existingIATValid = false;

    if (hdr.numberOfRvaAndSizes > PE::kDirImport &&
        hdr.dataDirectories[PE::kDirImport].VirtualAddress != 0 &&
        hdr.dataDirectories[PE::kDirImport].Size >= sizeof(PE::ImportDescriptor))
    {
        const GuestAddress importDirAddr = imageBase +
            hdr.dataDirectories[PE::kDirImport].VirtualAddress;
        const uint32_t maxDescs = hdr.dataDirectories[PE::kDirImport].Size /
            sizeof(PE::ImportDescriptor);
        const uint32_t capDescs = std::min(maxDescs, static_cast<uint32_t>(PE::kMaxImportDLLs));

        uint32_t validDescs = 0;
        uint32_t validEntries = 0;

        for (uint32_t d = 0; d < capDescs; ++d) {
            PE::ImportDescriptor desc{};
            const GuestAddress descAddr = importDirAddr +
                static_cast<GuestAddress>(d) * sizeof(PE::ImportDescriptor);
            if (!ReadGuestBytes(memory, descAddr, &desc, sizeof(desc))) break;

            // Null terminator
            if (desc.Name == 0 && desc.FirstThunk == 0) break;

            // Validate DLL name RVA
            if (desc.Name == 0 || desc.Name > hdr.sizeOfImage) continue;

            char dllName[PE::kMaxDLLNameLen]{};
            const GuestAddress nameAddr = imageBase + desc.Name;
            if (!ReadGuestBytes(memory, nameAddr, dllName, sizeof(dllName) - 1)) continue;
            dllName[PE::kMaxDLLNameLen - 1] = '\0';

            // Basic sanity: DLL name should contain printable chars
            bool nameValid = false;
            for (uint32_t c = 0; c < sizeof(dllName) && dllName[c]; ++c) {
                if (dllName[c] >= ' ' && dllName[c] <= '~') {
                    nameValid = true;
                } else if (dllName[c] != '\0') {
                    nameValid = false;
                    break;
                }
            }
            if (!nameValid) continue;

            // Check IAT entries
            if (desc.FirstThunk != 0 && desc.FirstThunk < hdr.sizeOfImage) {
                const GuestAddress iatBase = imageBase + desc.FirstThunk;
                const uint32_t entrySize = hdr.is64Bit ? 8 : 4;
                uint32_t entryCount = 0;
                static constexpr uint32_t kMaxIATScan = 4096;

                for (uint32_t e = 0; e < kMaxIATScan; ++e) {
                    uint64_t thunk = 0;
                    const GuestAddress thunkAddr = iatBase +
                        static_cast<GuestAddress>(e) * entrySize;
                    if (!ReadGuestBytes(memory, thunkAddr, &thunk, entrySize)) break;
                    if (thunk == 0) break;
                    entryCount++;
                }

                if (entryCount > 0) {
                    validEntries += entryCount;
                    validDescs++;
                }
            }
        }

        existingIATValid = (validDescs >= 1 && validEntries >= 1);
    }

    if (existingIATValid) {
        // Existing IAT parses correctly
        if (m_impl->currentLayerIdx < m_impl->layers.size()) {
            m_impl->layers[m_impl->currentLayerIdx].importTableValid = true;
        }
        m_impl->importDataReady = true;
        return true;
    }

    // --- Step 2: Build import info from tracked API calls ---
    if (m_impl->trackedImports.empty()) return false;

    // Group imports by DLL
    struct DLLImports {
        std::string dllName;
        std::vector<std::string> functions;
    };
    std::vector<DLLImports> dllGroups;

    for (const auto& imp : m_impl->trackedImports) {
        bool found = false;
        for (auto& grp : dllGroups) {
            if (grp.dllName == imp.dllName) {
                // Avoid duplicate functions
                bool alreadyHas = false;
                for (const auto& f : grp.functions) {
                    if (f == imp.funcName) { alreadyHas = true; break; }
                }
                if (!alreadyHas) {
                    grp.functions.push_back(imp.funcName);
                }
                found = true;
                break;
            }
        }
        if (!found) {
            DLLImports newGrp;
            newGrp.dllName = imp.dllName;
            newGrp.functions.push_back(imp.funcName);
            dllGroups.push_back(std::move(newGrp));
        }
    }

    if (dllGroups.empty()) return false;

    // --- Step 3: Build a new import section in memory ---
    // Layout:
    //   [Import Directory Table]  - array of IMAGE_IMPORT_DESCRIPTOR + null terminator
    //   [ILT/IAT entries]         - per-DLL thunk arrays + null terminators
    //   [Hint/Name entries]       - hint (2 bytes) + function name string (padded to even)
    //   [DLL name strings]        - null-terminated DLL names

    const uint32_t entrySize = hdr.is64Bit ? 8u : 4u;
    const uint32_t numDlls   = static_cast<uint32_t>(dllGroups.size());

    // Calculate sizes
    const uint32_t iddSize = (numDlls + 1) * sizeof(PE::ImportDescriptor);

    uint32_t totalThunks = 0;
    for (const auto& grp : dllGroups) {
        totalThunks += static_cast<uint32_t>(grp.functions.size()) + 1; // +1 null terminator
    }
    // ILT and IAT are separate copies
    const uint32_t thunkTableSize = totalThunks * entrySize;
    const uint32_t bothThunkTables = thunkTableSize * 2; // ILT + IAT

    uint32_t hintNameSize = 0;
    for (const auto& grp : dllGroups) {
        for (const auto& fn : grp.functions) {
            // 2 bytes hint + name + null + padding to even
            uint32_t entryLen = 2 + static_cast<uint32_t>(fn.size()) + 1;
            if (entryLen & 1) entryLen++;
            hintNameSize += entryLen;
        }
    }

    uint32_t dllNameSize = 0;
    for (const auto& grp : dllGroups) {
        dllNameSize += static_cast<uint32_t>(grp.dllName.size()) + 1;
    }

    const uint32_t totalImportSize = AlignUp32(
        iddSize + bothThunkTables + hintNameSize + dllNameSize, kOutputFileAlignment);

    if (totalImportSize > 1024 * 1024) return false; // Sanity cap at 1MB

    // Find a free region for the import section
    // Place it at the end of the image (next aligned address after sizeOfImage)
    const GuestAddress importBase = imageBase +
        AlignUp32(hdr.sizeOfImage, hdr.sectionAlignment);

    // Allocate space in guest memory
    auto allocResult = memory.Allocate(importBase, totalImportSize, MemProt::RW);
    if (!allocResult.has_value()) return false;
    const GuestAddress importVA = allocResult.value();
    const uint32_t importRVA = static_cast<uint32_t>(importVA - imageBase);

    // Build the import section data
    std::vector<uint8_t> importData(totalImportSize, 0);

    // Current offsets (all relative to importRVA)
    const uint32_t iddOffset      = 0;
    const uint32_t iltOffset      = iddSize;
    const uint32_t iatOffset      = iddSize + thunkTableSize;
    const uint32_t hintNameOffset = iddSize + bothThunkTables;
    uint32_t dllNameOffset        = iddSize + bothThunkTables + hintNameSize;

    uint32_t curILTOff      = iltOffset;
    uint32_t curIATOff      = iatOffset;
    uint32_t curHintNameOff = hintNameOffset;
    uint32_t curDllNameOff  = dllNameOffset;

    for (uint32_t d = 0; d < numDlls; ++d) {
        const auto& grp = dllGroups[d];

        // Write DLL name
        const uint32_t dllNameRVA = importRVA + curDllNameOff;
        std::memcpy(importData.data() + curDllNameOff, grp.dllName.c_str(),
                    grp.dllName.size() + 1);
        curDllNameOff += static_cast<uint32_t>(grp.dllName.size()) + 1;

        // Write import descriptor
        PE::ImportDescriptor idd{};
        idd.OriginalFirstThunk = importRVA + curILTOff;
        idd.Name               = dllNameRVA;
        idd.FirstThunk         = importRVA + curIATOff;
        const uint32_t iddPos  = iddOffset + d * sizeof(PE::ImportDescriptor);
        std::memcpy(importData.data() + iddPos, &idd, sizeof(idd));

        // Write thunk entries
        for (const auto& fn : grp.functions) {
            // Write Hint/Name entry
            const uint32_t hintNameRVA = importRVA + curHintNameOff;
            uint16_t hint = 0;
            std::memcpy(importData.data() + curHintNameOff, &hint, 2);
            std::memcpy(importData.data() + curHintNameOff + 2,
                        fn.c_str(), fn.size() + 1);
            uint32_t hnEntrySize = 2 + static_cast<uint32_t>(fn.size()) + 1;
            if (hnEntrySize & 1) hnEntrySize++;
            curHintNameOff += hnEntrySize;

            // Write ILT thunk (points to Hint/Name)
            if (hdr.is64Bit) {
                uint64_t thunk = static_cast<uint64_t>(hintNameRVA);
                std::memcpy(importData.data() + curILTOff, &thunk, 8);
                std::memcpy(importData.data() + curIATOff, &thunk, 8);
                curILTOff += 8;
                curIATOff += 8;
            } else {
                uint32_t thunk = hintNameRVA;
                std::memcpy(importData.data() + curILTOff, &thunk, 4);
                std::memcpy(importData.data() + curIATOff, &thunk, 4);
                curILTOff += 4;
                curIATOff += 4;
            }
        }

        // Null terminator thunks
        curILTOff += entrySize;
        curIATOff += entrySize;
    }

    // Write the import data to guest memory
    if (memory.Write(importVA, importData.data(), totalImportSize) != ErrorCode::Success) {
        return false;
    }

    // Update the PE import directory to point to our new section.
    const uint32_t eLfanew = hdr.eLfanew;

    if (hdr.is64Bit) {
        const uint32_t dirOff = eLfanew + 4 + sizeof(PE::FileHeader) +
            offsetof(PE::OptionalHeader64, DataDirectories) +
            PE::kDirImport * sizeof(PE::DataDirectory);
        PE::DataDirectory importDir{};
        importDir.VirtualAddress = importRVA;
        importDir.Size           = iddSize;
        memory.Write(imageBase + dirOff, &importDir, sizeof(importDir));
    } else {
        const uint32_t dirOff = eLfanew + 4 + sizeof(PE::FileHeader) +
            offsetof(PE::OptionalHeader32, DataDirectories) +
            PE::kDirImport * sizeof(PE::DataDirectory);
        PE::DataDirectory importDir{};
        importDir.VirtualAddress = importRVA;
        importDir.Size           = iddSize;
        memory.Write(imageBase + dirOff, &importDir, sizeof(importDir));
    }

    // Mark success
    if (m_impl->currentLayerIdx < m_impl->layers.size()) {
        m_impl->layers[m_impl->currentLayerIdx].importTableValid = true;
    }
    m_impl->importDataReady = true;

    // Add OEP candidate with IAT reconstruction score
    if (m_impl->lastWXRip != 0) {
        m_impl->AddOEPCandidate(m_impl->lastWXRip, OEPMethod::IATReconstruction,
                                0.8, m_impl->totalInstructions);
    }

    return true;
}

// ============================================================================
// Entropy Tracking
// ============================================================================

double UnpackingEngine::GetCurrentEntropy() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->currentEntropy;
}

std::vector<std::pair<uint64_t, double>> UnpackingEngine::GetEntropyHistory() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->entropyHistory;
}

// ============================================================================
// Reset
// ============================================================================

void UnpackingEngine::Reset() noexcept {
    std::unique_lock lock(m_impl->mutex);

    m_impl->layers.clear();
    m_impl->currentLayerIdx = UINT32_MAX;
    m_impl->unpacking       = false;
    m_impl->complete        = false;
    m_impl->finalOEP        = 0;
    m_impl->finalOEPMethod  = OEPMethod::WXTransition;
    m_impl->oepCandidates.clear();
    m_impl->totalInstructions    = 0;
    m_impl->layerStartInstr      = 0;
    m_impl->lastEntropyCheckInstr = 0;
    m_impl->prevRip              = 0;
    m_impl->apiLog.clear();
    m_impl->lastAPIInstr          = 0;
    m_impl->instrSinceLastAPICall = 0;
    m_impl->lastWXPage  = 0;
    m_impl->lastWXRip   = 0;
    m_impl->lastWXInstr = 0;
    m_impl->currentEntropy  = 0.0;
    m_impl->previousEntropy = 0.0;
    m_impl->entropyHistory.clear();
    m_impl->protLog.clear();
    m_impl->trackedImports.clear();
    m_impl->importDataReady  = false;
    m_impl->cachedSections.clear();
    m_impl->cachedImageBase  = 0;
    m_impl->cachedImageSize  = 0;
    m_impl->cachedEPRVA      = 0;
    m_impl->cachedIs64Bit    = false;
    m_impl->detectedVM       = VMArch::Unknown;
}

// ============================================================================
// VM Analysis — Detect virtualized code (FinFisher, Themida, VMProtect, etc.)
// ============================================================================

VMAnalysisResult UnpackingEngine::AnalyzeVirtualMachine(
    const VirtualMemory& memory,
    GuestAddress imageBase,
    GuestSize imageSize) const noexcept
{
    VMAnalysisResult result{};

    PEHeaderInfo hdr{};
    if (!ReadPEHeaders(memory, imageBase, hdr)) return result;

    // --- Phase 1: Section-name-based VM identification ---
    struct VMScore {
        VMArch arch;
        float  score;
    };
    static constexpr uint32_t kMaxVMCandidates = 8;
    std::array<VMScore, kMaxVMCandidates> vmScores{};
    uint32_t vmCount = 0;

    auto AddVMScore = [&](VMArch arch, float score) {
        for (uint32_t i = 0; i < vmCount; ++i) {
            if (vmScores[i].arch == arch) {
                vmScores[i].score += score;
                return;
            }
        }
        if (vmCount < kMaxVMCandidates) {
            vmScores[vmCount++] = {arch, score};
        }
    };

    for (const auto& mapping : kSectionVMMap) {
        if (HasSectionNamed(hdr.sections, mapping.sectionName)) {
            AddVMScore(mapping.arch, mapping.score);
        }
    }

    // String-based VM identification
    if (FindStr(memory, imageBase, imageSize, "VMProtect"))
        AddVMScore(VMArch::VMProtect, 0.30f);
    if (FindStr(memory, imageBase, imageSize, "Themida"))
        AddVMScore(VMArch::Themida, 0.30f);
    if (FindStr(memory, imageBase, imageSize, "WinLicense"))
        AddVMScore(VMArch::Themida, 0.25f);
    if (FindStr(memory, imageBase, imageSize, "CodeVirtualizer"))
        AddVMScore(VMArch::CodeVirtualizer, 0.30f);
    if (FindStr(memory, imageBase, imageSize, "TigerVMP"))
        AddVMScore(VMArch::TigerVMP, 0.30f);

    // --- Phase 2: Scan executable sections for VM entry patterns ---
    GuestAddress vmEntryAddr = 0;
    GuestAddress dispatchAddr = 0;
    bool foundDispatcher = false;
    bool foundVMEntry = false;

    for (const auto& sec : hdr.sections) {
        if (!(sec.characteristics & PE::kSecMemExecute)) continue;

        const GuestAddress secBase = imageBase + sec.virtualAddress;
        const GuestSize secSize = std::min<GuestSize>(sec.virtualSize, kVMMaxScanBytes);

        // Detect VM entry: multiple PUSHes followed by indirect JMP
        if (!foundVMEntry) {
            if (ScanForVMEntryPushSequence(memory, secBase, secSize, vmEntryAddr)) {
                foundVMEntry = true;
                result.vmEntryPoint = vmEntryAddr;
                AddVMScore(VMArch::Custom, 0.15f);
            }
        }

        // Detect dispatcher loop: MOVZX fetch + JMP [table]
        if (!foundDispatcher) {
            if (ScanForMovzxFetch(memory, secBase, secSize, dispatchAddr)) {
                foundDispatcher = true;
                result.vmDispatcher = dispatchAddr;
                result.usesIndirectDispatch = true;
                AddVMScore(VMArch::Custom, 0.20f);
            }
        }

        // Check for FinFisher entry pattern
        {
            uint8_t buf[16]{};
            const BytePattern ffPat = {kEP_FinFisher_B, kEP_FinFisher_M, sizeof(kEP_FinFisher_B)};
            for (GuestSize off = 0; off + 16 <= std::min(secSize, static_cast<GuestSize>(4096)); off += 4) {
                if (ReadGuestBytes(memory, secBase + off, buf, 16)) {
                    if (MatchPattern(buf, 16, ffPat)) {
                        AddVMScore(VMArch::FinFisher, 0.30f);
                        result.virtualRegCount = 32;
                        break;
                    }
                }
            }
        }
    }

    // --- Phase 3: EP-based VM detection ---
    {
        uint8_t epBytes[kMaxEPReadBytes]{};
        const GuestAddress epAddr = imageBase + hdr.entryPointRVA;
        if (ReadGuestBytes(memory, epAddr, epBytes, kMaxEPReadBytes)) {
            // VMProtect: EP is JMP into .vmp section
            if (epBytes[0] == 0xE9) {
                const int32_t epSection = FindSectionByRVA(hdr.sections, hdr.entryPointRVA);
                if (epSection >= 0) {
                    int32_t rel = 0;
                    std::memcpy(&rel, epBytes + 1, 4);
                    const uint32_t targetRVA = hdr.entryPointRVA + 5 + static_cast<uint32_t>(rel);
                    const int32_t targetSec = FindSectionByRVA(hdr.sections, targetRVA);
                    if (targetSec >= 0 && targetSec != epSection &&
                        std::strncmp(hdr.sections[static_cast<size_t>(targetSec)].name, ".vmp", 4) == 0)
                    {
                        AddVMScore(VMArch::VMProtect, 0.25f);
                    }
                }
            }

            // Themida: EP in high-entropy section with pushad or mov
            const BytePattern thV3 = {kEP_ThemidaV3_B, kEP_ThemidaV3_M, sizeof(kEP_ThemidaV3_B)};
            if (MatchPattern(epBytes, kMaxEPReadBytes, thV3)) {
                AddVMScore(VMArch::Themida, 0.20f);
            }
        }
    }

    // --- Phase 4: Handler table extraction ---
    if (foundDispatcher) {
        // Read bytes at dispatcher to find the table base address
        uint8_t dispBuf[32]{};
        if (ReadGuestBytes(memory, dispatchAddr, dispBuf, 32)) {
            // Scan forward in the dispatcher for JMP [reg*4+base] / JMP [reg*8+base]
            for (uint32_t i = 0; i + 7 < 32; ++i) {
                // FF 24 85 <addr32> — JMP DWORD PTR [EAX*4+base]
                // FF 24 C5 <addr32> — JMP DWORD PTR [EAX*8+base]
                if (dispBuf[i] == 0xFF &&
                    (dispBuf[i + 1] == 0x24) &&
                    (dispBuf[i + 2] == 0x85 || dispBuf[i + 2] == 0xC5 ||
                     dispBuf[i + 2] == 0x8D || dispBuf[i + 2] == 0xCD))
                {
                    uint32_t tableAddr = 0;
                    std::memcpy(&tableAddr, dispBuf + i + 3, 4);

                    // For 32-bit: table address is absolute
                    // For 64-bit: table address might be RIP-relative
                    GuestAddress tableBase = tableAddr;
                    if (hdr.is64Bit && tableAddr < 0x10000) {
                        // RIP-relative addressing
                        tableBase = dispatchAddr + i + 7 + static_cast<int32_t>(tableAddr);
                    }

                    if (tableBase >= imageBase && tableBase < imageBase + imageSize) {
                        result.vmHandlerTable = tableBase;
                        result.handlerCount = ExtractHandlerTable(
                            memory, tableBase, imageBase, imageSize,
                            hdr.is64Bit, result.handlers);
                    }
                    break;
                }
            }
        }
    }

    // --- Phase 5: Handler classification ---
    for (auto& handler : result.handlers) {
        uint16_t instrCount = 0;
        handler.handlerType = ClassifyHandler(memory, handler.address, instrCount);
        handler.instructionCount = instrCount;
    }

    // --- Phase 6: Detect opaque predicates ---
    for (const auto& sec : hdr.sections) {
        if (!(sec.characteristics & PE::kSecMemExecute)) continue;
        const GuestAddress secBase = imageBase + sec.virtualAddress;
        const GuestSize secSize = std::min<GuestSize>(sec.virtualSize, kVMMaxScanBytes);
        if (DetectOpaquePredicates(memory, secBase, secSize)) {
            result.hasOpaquePredicates = true;
            AddVMScore(VMArch::Custom, 0.10f);
            break;
        }
    }

    // --- Phase 7: Detect handler reordering ---
    if (result.handlers.size() >= kVMMinHandlerCount) {
        uint32_t outOfOrder = 0;
        for (size_t i = 1; i < result.handlers.size(); ++i) {
            if (result.handlers[i].address < result.handlers[i - 1].address) {
                outOfOrder++;
            }
        }
        if (outOfOrder > result.handlers.size() / 3) {
            result.hasHandlerReordering = true;
            AddVMScore(VMArch::Custom, 0.10f);
        }
    }

    // --- Phase 8: Detect computed goto (threaded dispatch) ---
    // Check if handlers end with fetch-next-opcode + JMP instead of JMP-back-to-dispatcher
    if (result.handlers.size() >= kVMMinHandlerCount) {
        uint32_t threadedCount = 0;
        uint8_t tailBuf[16]{};
        for (const auto& handler : result.handlers) {
            if (handler.instructionCount < kVMMinHandlerInstrs) continue;
            // Read tail of handler: look for MOVZX + JMP pattern at end
            const GuestAddress tailAddr = handler.address +
                std::min<uint32_t>(handler.instructionCount * 2, 128);
            if (ReadGuestBytes(memory, tailAddr, tailBuf, 16)) {
                for (uint32_t j = 0; j + 6 < 16; ++j) {
                    if (tailBuf[j] == 0x0F && tailBuf[j + 1] == 0xB6) {
                        threadedCount++;
                        break;
                    }
                }
            }
        }
        if (threadedCount > result.handlers.size() / 2) {
            result.usesComputedGoto = true;
            AddVMScore(VMArch::Custom, 0.10f);
        }
    }

    // --- Phase 9: Virtual register count estimation ---
    if (result.virtualRegCount == 0 && foundDispatcher) {
        // Estimate from handler analysis: count distinct memory offset patterns
        // FinFisher ~32, Themida ~16-32, VMProtect ~16
        if (result.handlerCount >= 100) {
            result.virtualRegCount = 32;
        } else if (result.handlerCount >= 40) {
            result.virtualRegCount = 16;
        } else if (result.handlerCount >= 20) {
            result.virtualRegCount = 8;
        }
    }

    // --- Phase 10: Confidence scoring ---
    // Handler table found with >20 entries: +0.3
    if (result.handlerCount > 20)
        AddVMScore(VMArch::Custom, 0.30f);
    // Dispatcher loop with indirect dispatch: +0.2
    if (result.usesIndirectDispatch)
        AddVMScore(VMArch::Custom, 0.20f);
    // Opaque predicates: +0.1
    if (result.hasOpaquePredicates)
        AddVMScore(VMArch::Custom, 0.10f);
    // Handler reordering: +0.1
    if (result.hasHandlerReordering)
        AddVMScore(VMArch::Custom, 0.10f);

    // --- Phase 11: Architecture-specific handler count refinement ---
    for (uint32_t i = 0; i < vmCount; ++i) {
        if (vmScores[i].arch == VMArch::FinFisher) {
            if (result.handlerCount >= 60 && result.handlerCount <= 80)
                vmScores[i].score += 0.15f;
        } else if (vmScores[i].arch == VMArch::Themida) {
            if (result.handlerCount >= 100 && result.handlerCount <= 120)
                vmScores[i].score += 0.15f;
        } else if (vmScores[i].arch == VMArch::VMProtect) {
            if (result.handlerCount >= 40 && result.handlerCount <= 200)
                vmScores[i].score += 0.10f;
        } else if (vmScores[i].arch == VMArch::CodeVirtualizer) {
            if (result.handlerCount >= 40 && result.handlerCount <= 60)
                vmScores[i].score += 0.15f;
        }
    }

    // --- Phase 12: Select best VM architecture ---
    VMArch bestArch = VMArch::Unknown;
    float  bestScore = 0.0f;

    for (uint32_t i = 0; i < vmCount; ++i) {
        if (vmScores[i].score > bestScore) {
            bestScore = vmScores[i].score;
            bestArch  = vmScores[i].arch;
        }
    }

    // Minimum confidence threshold for positive VM detection
    static constexpr float kVMConfidenceThreshold = 0.35f;

    if (bestScore >= kVMConfidenceThreshold && bestArch != VMArch::Unknown) {
        result.architecture = bestArch;
        result.confidence = std::min(bestScore, 1.0f);
    } else if (bestScore >= kVMConfidenceThreshold) {
        // If only "Custom" scored high enough, report it
        result.architecture = VMArch::Custom;
        result.confidence = std::min(bestScore, 1.0f);
    }

    // Store detected VM in Impl for GetDetectedVM()
    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->detectedVM = result.architecture;
    }

    return result;
}

VMArch UnpackingEngine::GetDetectedVM() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->detectedVM;
}

} // namespace Phantom
