/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ImportResolver.cpp — PE import table resolver with API hook integration
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ImportResolver.hpp"
#include "ExportResolver.hpp"
#include "PEParser.hpp"
#include "PEStructures.hpp"
#include "../Memory/VirtualMemory.hpp"

#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <shared_mutex>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

// Stride between auto-allocated hook addresses (8 bytes = pointer width for x64)
static constexpr GuestAddress kHookStride = 8;

// ============================================================================
// ASCII-only lowercase (no locale dependency)
// ============================================================================

static char ToLowerASCII(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

static bool IsSafeDLLNameChar(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    if (uc <= 0x20 || uc >= 0x7F) {
        return false;
    }
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

static bool AddGuestAddress(GuestAddress base, GuestAddress offset, GuestAddress& out) noexcept {
    if (offset > (std::numeric_limits<GuestAddress>::max)() - base) {
        return false;
    }
    out = base + offset;
    return true;
}

// ============================================================================
// Safe value reader from ByteSpan (avoids alignment issues via memcpy)
// ============================================================================

template <typename T>
[[nodiscard]] static bool ReadFromSpan(
    ByteSpan data, uint32_t offset, T& out) noexcept
{
    // Overflow-safe: offset + sizeof(T) could wrap on 32-bit, but data.size()
    // is size_t which is 64-bit on our target (Win64).
    if (static_cast<uint64_t>(offset) + sizeof(T) > data.size()) {
        return false;
    }
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

// ============================================================================
// NormalizeDLLName — lowercase, strip path, ensure ".dll" extension
// ============================================================================

std::string ImportResolver::NormalizeDLLName(std::string_view name) noexcept {
    try {
        if (name.empty()) {
            return {};
        }

        // Strip path components
        const auto lastSep = name.find_last_of("\\/");
        if (lastSep != std::string_view::npos) {
            name = name.substr(lastSep + 1);
        }

        if (name.empty() || name.size() > PE::kMaxDLLNameLen) {
            return {};
        }

        for (const char c : name) {
            if (!IsSafeDLLNameChar(c)) {
                return {};
            }
        }

        std::string result;
        result.reserve(name.size() + 4);

        for (const char c : name) {
            result += ToLowerASCII(c);
        }

        if (result.size() < 4 || result.compare(result.size() - 4, 4, ".dll") != 0) {
            if (result.size() > PE::kMaxDLLNameLen - 4U) {
                return {};
            }
            result += ".dll";
        }

        return result;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// MakeHookKey — "dllname!funcname" composite key for hook lookup
// ============================================================================

std::string ImportResolver::MakeHookKey(
    std::string_view dll, std::string_view func) noexcept
{
    try {
        auto normDll = NormalizeDLLName(dll);
        if (normDll.empty() || func.empty() || func.size() > PE::kMaxExportNameLen) {
            return {};
        }

        std::string key;
        key.reserve(normDll.size() + 1 + func.size());
        key = std::move(normDll);
        key += '!';
        // Export names are case-sensitive per PE spec — preserve casing
        key.append(func.data(), func.size());
        return key;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// MakeOrdinalKey — "dllname!#ordinal" composite key for hook lookup
// ============================================================================

std::string ImportResolver::MakeOrdinalKey(
    std::string_view dll, uint16_t ordinal) noexcept
{
    try {
        auto normDll = NormalizeDLLName(dll);
        if (normDll.empty()) {
            return {};
        }

        // "dllname.dll!#12345" — max ordinal string is 5 chars
        std::string key;
        key.reserve(normDll.size() + 7);
        key = std::move(normDll);
        key += "!#";
        key += std::to_string(ordinal);
        return key;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// Constructor
// ============================================================================

ImportResolver::ImportResolver(const ExportResolver& exports) noexcept
    : m_exports(exports)
{
}

// ============================================================================
// SetAPIHookRange — Configure auto-allocation address range
// ============================================================================

void ImportResolver::SetAPIHookRange(
    GuestAddress base, GuestSize size) noexcept
{
    std::unique_lock lock(m_mutex);
    m_hookBase     = base;
    m_hookSize     = size;
    m_nextHookAddr = base;
}

// ============================================================================
// RegisterAPIHook — Register a named API hook
// ============================================================================

void ImportResolver::RegisterAPIHook(
    std::string_view dllName,
    std::string_view funcName,
    GuestAddress hookAddress) noexcept
{
    try {
        auto key = MakeHookKey(dllName, funcName);
        if (!key.empty() && hookAddress != 0) {
            std::unique_lock lock(m_mutex);
            m_hooksByName[std::move(key)] = hookAddress;
        }
    } catch (const std::bad_alloc&) {
        // Preserve the noexcept contract; unresolved imports will fall back to
        // exports or auto-hook allocation during ResolveAll().
    }
}

// ============================================================================
// RegisterAPIHookByOrdinal — Register an ordinal API hook
// ============================================================================

void ImportResolver::RegisterAPIHookByOrdinal(
    std::string_view dllName,
    uint16_t ordinal,
    GuestAddress hookAddress) noexcept
{
    try {
        auto key = MakeOrdinalKey(dllName, ordinal);
        if (!key.empty() && hookAddress != 0) {
            std::unique_lock lock(m_mutex);
            m_hooksByOrdinal[std::move(key)] = hookAddress;
        }
    } catch (const std::bad_alloc&) {
        // Preserve the noexcept contract; unresolved imports will fall back to
        // exports or auto-hook allocation during ResolveAll().
    }
}

// ============================================================================
// GetHookAddress — Query a registered hook by name
// ============================================================================

std::optional<GuestAddress> ImportResolver::GetHookAddress(
    std::string_view dllName,
    std::string_view funcName) const noexcept
{
    auto key = MakeHookKey(dllName, funcName);
    if (key.empty()) {
        return std::nullopt;
    }

    std::shared_lock lock(m_mutex);
    const auto it = m_hooksByName.find(key);
    if (it != m_hooksByName.end()) {
        return it->second;
    }

    return std::nullopt;
}

// ============================================================================
// ResolveAll — Walk the PE import directory and resolve every import
// ============================================================================
//
// Strategy:
//   1. Parse PE headers from peData to locate the import directory and build
//      a section table for RVA→file-offset conversion.
//   2. Walk ImportDescriptor array from peData (raw file — unmodified ILT).
//   3. For each thunk entry:
//        a. Check registered API hooks first (m_hooksByName / m_hooksByOrdinal).
//        b. Fall back to ExportResolver for real export addresses.
//        c. If still unresolved, auto-allocate a hook address from the
//           hook range so the API dispatcher can intercept the call.
//        d. If hook range is exhausted, record as failed import.
//   4. Write resolved addresses into the IAT in guest memory.
//

ImportResolution ImportResolver::ResolveAll(
    GuestAddress imageBase,
    VirtualMemory& memory,
    ByteSpan peData,
    bool is64Bit) noexcept
{
    ImportResolution result{};

    if (peData.empty()) {
        return result;
    }

    std::unique_lock lock(m_mutex);

    try {

    // ----------------------------------------------------------------
    // Parse PE for section table and data directory locations
    // ----------------------------------------------------------------
    const auto parseResult = PEParser::Parse(peData);
    if (!parseResult.Ok()) {
        return result;
    }

    const auto& pe = parseResult.pe;

    // ----------------------------------------------------------------
    // Locate import directory
    // ----------------------------------------------------------------
    if (pe.numberOfDataDirectories <= PE::kDirImport) {
        return result; // No import directory — nothing to resolve
    }

    const auto& importDirEntry = pe.dataDirectories[PE::kDirImport];
    if (importDirEntry.VirtualAddress == 0 || importDirEntry.Size == 0) {
        return result;
    }

    const auto importDirFO = PEParser::RVAToFileOffset(pe, importDirEntry.VirtualAddress);
    if (!importDirFO) {
        return result;
    }

    const uint32_t ptrSize = is64Bit ? 8 : 4;
    uint64_t importDirEndFO = static_cast<uint64_t>(*importDirFO) + importDirEntry.Size;
    if (importDirEndFO < *importDirFO) {
        return result;
    }
    if (importDirEndFO > peData.size()) {
        importDirEndFO = peData.size();
    }

    // ----------------------------------------------------------------
    // Walk ImportDescriptor array
    // ----------------------------------------------------------------
    for (uint32_t descIdx = 0; descIdx < PE::kMaxImportDLLs; ++descIdx) {

        // Compute file offset of this ImportDescriptor
        const uint64_t descFileOffset64 =
            static_cast<uint64_t>(*importDirFO) +
            static_cast<uint64_t>(descIdx) * sizeof(PE::ImportDescriptor);

        if (descFileOffset64 + sizeof(PE::ImportDescriptor) > importDirEndFO) {
            break; // Descriptor array extends past file bounds
        }
        const auto descFileOffset = static_cast<uint32_t>(descFileOffset64);

        // Read the descriptor
        PE::ImportDescriptor desc{};
        std::memcpy(&desc, peData.data() + descFileOffset, sizeof(PE::ImportDescriptor));

        // All-zero descriptor is the terminating sentinel
        if (desc.OriginalFirstThunk == 0 &&
            desc.TimeDateStamp      == 0 &&
            desc.ForwarderChain     == 0 &&
            desc.Name               == 0 &&
            desc.FirstThunk         == 0) {
            break;
        }

        // ----------------------------------------------------------------
        // Read DLL name from peData
        // ----------------------------------------------------------------
        if (desc.Name == 0) {
            continue; // Malformed descriptor — skip
        }

        const auto dllNameFO = PEParser::RVAToFileOffset(pe, desc.Name);
        if (!dllNameFO) {
            continue;
        }

        const std::string dllName = PEParser::ReadString(
            peData, *dllNameFO, PE::kMaxDLLNameLen);
        if (dllName.empty()) {
            continue;
        }

        const auto normalDll = NormalizeDLLName(dllName);
        if (normalDll.empty()) {
            continue;
        }

        // ----------------------------------------------------------------
        // Determine ILT and IAT RVAs
        // ----------------------------------------------------------------
        // OriginalFirstThunk (ILT) has the unmodified import lookup entries.
        // FirstThunk (IAT) is where we write resolved addresses.
        // If OriginalFirstThunk is 0, fall back to FirstThunk for both
        // (the PE was linked without a separate ILT).
        const uint32_t iltRVA = (desc.OriginalFirstThunk != 0)
                                ? desc.OriginalFirstThunk
                                : desc.FirstThunk;
        const uint32_t iatRVA = desc.FirstThunk;

        if (iltRVA == 0 || iatRVA == 0) {
            continue;
        }

        // Convert ILT RVA → file offset for reading thunk entries from peData
        const auto iltFO = PEParser::RVAToFileOffset(pe, iltRVA);
        if (!iltFO) {
            continue;
        }

        // ----------------------------------------------------------------
        // Walk thunk entries for this DLL
        // ----------------------------------------------------------------
        for (uint32_t thunkIdx = 0; thunkIdx < PE::kMaxImportsPerDLL; ++thunkIdx) {

            // File offset of this thunk entry in the ILT
            const uint64_t thunkFileOffset64 =
                static_cast<uint64_t>(*iltFO) +
                static_cast<uint64_t>(thunkIdx) * ptrSize;

            if (thunkFileOffset64 + ptrSize > peData.size()) {
                break;
            }
            const auto thunkFileOffset = static_cast<uint32_t>(thunkFileOffset64);

            // Read the thunk value (4 or 8 bytes depending on PE bitness)
            uint64_t thunkValue = 0;
            if (is64Bit) {
                if (!ReadFromSpan(peData, thunkFileOffset, thunkValue)) {
                    break;
                }
            } else {
                uint32_t thunk32 = 0;
                if (!ReadFromSpan(peData, thunkFileOffset, thunk32)) {
                    break;
                }
                thunkValue = thunk32;
            }

            // Zero thunk terminates the import list for this DLL
            if (thunkValue == 0) {
                break;
            }

            // --------------------------------------------------------
            // Decode the thunk: ordinal import vs. name import
            // --------------------------------------------------------
            bool     isByOrdinal = false;
            uint16_t importOrdinal = 0;
            uint16_t importHint = 0;
            std::string importName;

            if (is64Bit) {
                isByOrdinal = (thunkValue & PE::kImportByOrdinal64) != 0;
            } else {
                isByOrdinal = (thunkValue & PE::kImportByOrdinal32) != 0;
            }

            if (isByOrdinal) {
                importOrdinal = static_cast<uint16_t>(thunkValue & PE::kOrdinalMask16);
            } else {
                // Hint/Name RVA — mask off the ordinal flag bit
                const uint32_t hintNameRVA = is64Bit
                    ? static_cast<uint32_t>(thunkValue & 0x7FFFFFFFULL)
                    : static_cast<uint32_t>(thunkValue & 0x7FFFFFFFUL);

                const auto hintNameFO = PEParser::RVAToFileOffset(pe, hintNameRVA);
                if (!hintNameFO) {
                    // Record as failed — can't read the import name
                    std::string failDesc = normalDll + "!<invalid_hint_rva_0x";
                    // Simple hex conversion for the RVA
                    char hexBuf[9]{};
                    for (int nibble = 7; nibble >= 0; --nibble) {
                        const uint32_t digit = (hintNameRVA >> (nibble * 4)) & 0xF;
                        hexBuf[7 - nibble] = static_cast<char>(
                            digit < 10 ? '0' + digit : 'a' + digit - 10);
                    }
                    failDesc += hexBuf;
                    failDesc += '>';
                    result.failedImports.push_back(std::move(failDesc));
                    ++result.totalFailed;
                    continue;
                }

                // Read hint (2 bytes) then name string
                if (!ReadFromSpan(peData, *hintNameFO, importHint)) {
                    result.failedImports.push_back(
                        normalDll + "!<truncated_hint>");
                    ++result.totalFailed;
                    continue;
                }

                importName = PEParser::ReadString(
                    peData,
                    *hintNameFO + static_cast<uint32_t>(sizeof(uint16_t)),
                    PE::kMaxExportNameLen);

                if (importName.empty()) {
                    result.failedImports.push_back(
                        normalDll + "!<empty_name>");
                    ++result.totalFailed;
                    continue;
                }
            }

            // --------------------------------------------------------
            // Resolve the import
            // --------------------------------------------------------
            GuestAddress resolvedAddr = 0;
            bool isHooked = false;

            // Priority 1: Registered API hooks
            if (isByOrdinal) {
                const auto hookKey = MakeOrdinalKey(normalDll, importOrdinal);
                if (!hookKey.empty()) {
                    const auto hookIt = m_hooksByOrdinal.find(hookKey);
                    if (hookIt != m_hooksByOrdinal.end()) {
                        resolvedAddr = hookIt->second;
                        isHooked = true;
                    }
                }
            } else {
                const auto hookKey = MakeHookKey(normalDll, importName);
                if (!hookKey.empty()) {
                    const auto hookIt = m_hooksByName.find(hookKey);
                    if (hookIt != m_hooksByName.end()) {
                        resolvedAddr = hookIt->second;
                        isHooked = true;
                    }
                }
            }

            // Priority 2: ExportResolver (real exports from loaded modules)
            if (resolvedAddr == 0) {
                std::optional<GuestAddress> exportAddr;
                if (isByOrdinal) {
                    exportAddr = m_exports.ResolveByOrdinal(normalDll, importOrdinal);
                } else {
                    exportAddr = m_exports.ResolveByName(normalDll, importName);
                }

                if (exportAddr.has_value() && *exportAddr != 0) {
                    resolvedAddr = *exportAddr;
                }
            }

            // Priority 3: Auto-allocate a hook address
            if (resolvedAddr == 0) {
                bool allocated = false;

                if (m_hookBase != 0 && m_hookSize >= kHookStride) {
                    // Overflow-safe: hookEnd = m_hookBase + m_hookSize
                    GuestAddress hookEnd = 0;
                    GuestAddress nextHookEnd = 0;
                    if (AddGuestAddress(m_hookBase, m_hookSize, hookEnd) &&
                        AddGuestAddress(m_nextHookAddr, kHookStride, nextHookEnd)) {
                        if (m_nextHookAddr >= m_hookBase &&
                            nextHookEnd <= hookEnd) {
                            resolvedAddr   = m_nextHookAddr;
                            m_nextHookAddr = nextHookEnd;
                            isHooked       = true;
                            allocated      = true;
                        }
                    }
                }

                if (!allocated) {
                    // Truly unresolvable — record failure
                    std::string failDesc;
                    if (isByOrdinal) {
                        failDesc = normalDll + "!#" + std::to_string(importOrdinal);
                    } else {
                        failDesc = normalDll + "!" + importName;
                    }
                    result.failedImports.push_back(std::move(failDesc));
                    ++result.totalFailed;
                    continue;
                }
            }

            // --------------------------------------------------------
            // Write resolved address into IAT in guest memory
            // --------------------------------------------------------
            GuestAddress iatBaseAddr = 0;
            GuestAddress iatSlotAddr = 0;
            const auto thunkOffset = static_cast<GuestAddress>(thunkIdx) * ptrSize;
            if (!AddGuestAddress(imageBase, static_cast<GuestAddress>(iatRVA), iatBaseAddr) ||
                !AddGuestAddress(iatBaseAddr, thunkOffset, iatSlotAddr)) {
                std::string failDesc;
                if (isByOrdinal) {
                    failDesc = normalDll + "!#" + std::to_string(importOrdinal) +
                               " (IAT address overflow)";
                } else {
                    failDesc = normalDll + "!" + importName +
                               " (IAT address overflow)";
                }
                result.failedImports.push_back(std::move(failDesc));
                ++result.totalFailed;
                continue;
            }

            ErrorCode writeErr = ErrorCode::Success;
            if (is64Bit) {
                writeErr = memory.WriteU64(iatSlotAddr, resolvedAddr);
            } else {
                if (resolvedAddr > (std::numeric_limits<uint32_t>::max)()) {
                    std::string failDesc;
                    if (isByOrdinal) {
                        failDesc = normalDll + "!#" + std::to_string(importOrdinal) +
                                   " (resolved address exceeds 32-bit VA)";
                    } else {
                        failDesc = normalDll + "!" + importName +
                                   " (resolved address exceeds 32-bit VA)";
                    }
                    result.failedImports.push_back(std::move(failDesc));
                    ++result.totalFailed;
                    continue;
                }
                writeErr = memory.WriteU32(
                    iatSlotAddr, static_cast<uint32_t>(resolvedAddr));
            }

            if (writeErr != ErrorCode::Success) {
                // IAT write failed — record but continue resolving others
                std::string failDesc;
                if (isByOrdinal) {
                    failDesc = normalDll + "!#" + std::to_string(importOrdinal) +
                               " (IAT write failed)";
                } else {
                    failDesc = normalDll + "!" + importName +
                               " (IAT write failed)";
                }
                result.failedImports.push_back(std::move(failDesc));
                ++result.totalFailed;
                continue;
            }

            // --------------------------------------------------------
            // Record successful resolution
            // --------------------------------------------------------
            ImportResolution::ResolvedEntry entry{};
            entry.iatSlotAddress  = iatSlotAddr;
            entry.resolvedAddress = resolvedAddr;
            entry.dllName         = normalDll;
            entry.isHooked        = isHooked;
            entry.byOrdinal       = isByOrdinal;

            if (isByOrdinal) {
                entry.ordinal  = importOrdinal;
                entry.funcName = "#" + std::to_string(importOrdinal);
            } else {
                entry.funcName = std::move(importName);
                entry.ordinal  = importHint;
            }

            result.resolved.push_back(std::move(entry));
            ++result.totalResolved;

        } // end thunk loop

    } // end descriptor loop

    return result;
    } catch (const std::bad_alloc&) {
        return result;
    }
}

} // namespace Phantom
