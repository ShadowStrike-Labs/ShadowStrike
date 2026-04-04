/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ExportResolver.cpp — PE export directory parser and multi-module export database
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ExportResolver.hpp"
#include "PEParser.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom {

// ============================================================================
// Constants
// ============================================================================

static constexpr uint32_t kMaxForwarderDepth = 8;

// ============================================================================
// ASCII-only lowercase (no locale dependency, PE names are always ASCII)
// ============================================================================

static char ToLowerASCII(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// ============================================================================
// NormalizeDLLName — lowercase, strip path, ensure ".dll" extension
// ============================================================================

std::string ExportResolver::NormalizeDLLName(std::string_view name) noexcept {
    if (name.empty()) {
        return {};
    }

    // Strip any path components (backslash or forward slash)
    const auto lastSep = name.find_last_of("\\/");
    if (lastSep != std::string_view::npos) {
        name = name.substr(lastSep + 1);
    }

    if (name.empty()) {
        return {};
    }

    // Cap input length to prevent excessive allocation from hostile data
    if (name.size() > PE::kMaxDLLNameLen) {
        name = name.substr(0, PE::kMaxDLLNameLen);
    }

    std::string result;
    result.reserve(name.size() + 4);

    for (const char c : name) {
        result += ToLowerASCII(c);
    }

    // Ensure ".dll" extension if not present
    if (result.size() < 4 || result.compare(result.size() - 4, 4, ".dll") != 0) {
        result += ".dll";
    }

    return result;
}

// ============================================================================
// RegisterModule — Parse export directory and populate lookup maps
// ============================================================================

ErrorCode ExportResolver::RegisterModule(
    GuestAddress imageBase,
    std::string_view moduleName,
    ByteSpan data) noexcept
{
    if (data.empty()) {
        return ErrorCode::MalformedPE;
    }

    if (moduleName.empty()) {
        return ErrorCode::MalformedPE;
    }

    const auto normalName = NormalizeDLLName(moduleName);
    if (normalName.empty()) {
        return ErrorCode::MalformedPE;
    }

    // ----------------------------------------------------------------
    // Use PEParser for PE validation and section table (reuse infra)
    // ----------------------------------------------------------------
    const auto parseResult = PEParser::Parse(data);
    if (!parseResult.Ok()) {
        return parseResult.error;
    }

    const auto& pe = parseResult.pe;

    // Prepare module entry (registered even if no exports — for GetModuleBase)
    ModuleExports modExports;
    modExports.imageBase     = imageBase;
    modExports.canonicalName = std::string(moduleName);

    // ----------------------------------------------------------------
    // Locate export directory
    // ----------------------------------------------------------------
    if (pe.numberOfDataDirectories <= PE::kDirExport) {
        m_modules[normalName] = std::move(modExports);
        return ErrorCode::Success;
    }

    const auto& exportDirEntry = pe.dataDirectories[PE::kDirExport];
    if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size == 0) {
        m_modules[normalName] = std::move(modExports);
        return ErrorCode::Success;
    }

    // Convert export directory RVA → file offset
    const auto exportDirFO = PEParser::RVAToFileOffset(pe, exportDirEntry.VirtualAddress);
    if (!exportDirFO) {
        return ErrorCode::MalformedPE;
    }

    const auto fileSize = static_cast<uint32_t>(data.size());

    if (!PE::IsFileOffsetValid(*exportDirFO, sizeof(PE::ExportDirectory), fileSize)) {
        return ErrorCode::MalformedPE;
    }

    PE::ExportDirectory expDir{};
    std::memcpy(&expDir, data.data() + *exportDirFO, sizeof(PE::ExportDirectory));

    modExports.ordinalBase = expDir.Base;

    // ----------------------------------------------------------------
    // Validate and cap counts (anti-DoS)
    // ----------------------------------------------------------------
    uint32_t numFunctions = expDir.NumberOfFunctions;
    uint32_t numNames     = expDir.NumberOfNames;

    if (numFunctions > PE::kMaxExports) {
        numFunctions = PE::kMaxExports;
    }
    if (numNames > PE::kMaxExports) {
        numNames = PE::kMaxExports;
    }
    // Per PE spec, NumberOfNames cannot exceed NumberOfFunctions
    if (numNames > numFunctions) {
        return ErrorCode::MalformedPE;
    }

    if (numFunctions == 0) {
        m_modules[normalName] = std::move(modExports);
        return ErrorCode::Success;
    }

    // ----------------------------------------------------------------
    // Get file offset for AddressOfFunctions array
    // ----------------------------------------------------------------
    if (expDir.AddressOfFunctions == 0) {
        return ErrorCode::MalformedPE;
    }

    const auto funcArrayFO = PEParser::RVAToFileOffset(pe, expDir.AddressOfFunctions);
    if (!funcArrayFO) {
        return ErrorCode::MalformedPE;
    }

    const uint32_t funcArrayBytes = numFunctions * sizeof(uint32_t);
    // Overflow check: numFunctions is capped at 65536, sizeof(uint32_t)=4 → max 262144
    if (!PE::IsFileOffsetValid(*funcArrayFO, funcArrayBytes, fileSize)) {
        return ErrorCode::MalformedPE;
    }

    // ----------------------------------------------------------------
    // Get name and ordinal arrays (only if named exports exist)
    // ----------------------------------------------------------------
    std::optional<uint32_t> nameArrayFO;
    std::optional<uint32_t> ordArrayFO;

    if (numNames > 0) {
        if (expDir.AddressOfNames == 0 || expDir.AddressOfNameOrdinals == 0) {
            return ErrorCode::MalformedPE;
        }

        nameArrayFO = PEParser::RVAToFileOffset(pe, expDir.AddressOfNames);
        ordArrayFO  = PEParser::RVAToFileOffset(pe, expDir.AddressOfNameOrdinals);

        if (!nameArrayFO || !ordArrayFO) {
            return ErrorCode::MalformedPE;
        }

        const uint32_t nameArrayBytes = numNames * sizeof(uint32_t);
        const uint32_t ordArrayBytes  = numNames * sizeof(uint16_t);

        if (!PE::IsFileOffsetValid(*nameArrayFO, nameArrayBytes, fileSize) ||
            !PE::IsFileOffsetValid(*ordArrayFO, ordArrayBytes, fileSize)) {
            return ErrorCode::MalformedPE;
        }
    }

    // ----------------------------------------------------------------
    // Export directory RVA bounds for forwarded-export detection.
    // A function RVA that falls within [exportDirRVA, exportDirRVA+size)
    // is a pointer to a forwarder string, not actual code.
    // ----------------------------------------------------------------
    const uint32_t exportRVAStart = exportDirEntry.VirtualAddress;
    const uint32_t exportRVAEnd   = exportDirEntry.VirtualAddress + exportDirEntry.Size;
    // Guard against overflow in exportRVAEnd
    const bool exportRangeValid = (exportRVAEnd >= exportRVAStart);

    // Pre-allocate maps
    modExports.byOrdinal.reserve(numFunctions);
    if (numNames > 0) {
        modExports.byName.reserve(numNames);
    }

    // ----------------------------------------------------------------
    // Walk AddressOfFunctions — populate ordinal map
    // ----------------------------------------------------------------
    for (uint32_t i = 0; i < numFunctions; ++i) {
        uint32_t funcRVA = 0;
        const uint32_t funcEntryOffset = *funcArrayFO + i * sizeof(uint32_t);
        std::memcpy(&funcRVA, data.data() + funcEntryOffset, sizeof(uint32_t));

        if (funcRVA == 0) {
            continue; // Unused ordinal slot
        }

        // Compute ordinal, validate it fits in uint16_t
        const uint32_t ordVal = i + expDir.Base;
        if (ordVal > 0xFFFF) {
            continue; // Invalid ordinal — skip
        }
        const auto ordinal = static_cast<uint16_t>(ordVal);

        ExportEntry entry{};

        // Forwarded export: function RVA points within the export directory
        if (exportRangeValid && funcRVA >= exportRVAStart && funcRVA < exportRVAEnd) {
            const auto fwdFO = PEParser::RVAToFileOffset(pe, funcRVA);
            if (fwdFO) {
                entry.forwarder = PEParser::ReadString(
                    data, *fwdFO, PE::kMaxExportNameLen);
            }
            entry.address = 0;
        } else {
            entry.address = imageBase + static_cast<GuestAddress>(funcRVA);
        }

        modExports.byOrdinal[ordinal] = entry;
    }

    // ----------------------------------------------------------------
    // Walk AddressOfNames / AddressOfNameOrdinals — populate name map
    // ----------------------------------------------------------------
    for (uint32_t i = 0; i < numNames; ++i) {
        uint32_t nameRVA = 0;
        uint16_t ordIndex = 0;

        const uint32_t nameEntryOffset = *nameArrayFO + i * sizeof(uint32_t);
        const uint32_t ordEntryOffset  = *ordArrayFO  + i * sizeof(uint16_t);

        std::memcpy(&nameRVA,  data.data() + nameEntryOffset, sizeof(uint32_t));
        std::memcpy(&ordIndex, data.data() + ordEntryOffset,  sizeof(uint16_t));

        // Validate ordinal index against function array bounds
        if (ordIndex >= numFunctions) {
            continue;
        }

        // Read the export name string
        const auto nameFO = PEParser::RVAToFileOffset(pe, nameRVA);
        if (!nameFO) {
            continue;
        }

        std::string exportName = PEParser::ReadString(
            data, *nameFO, PE::kMaxExportNameLen);
        if (exportName.empty()) {
            continue;
        }

        // Read the corresponding function RVA
        uint32_t funcRVA = 0;
        const uint32_t funcEntryOffset = *funcArrayFO + ordIndex * sizeof(uint32_t);
        std::memcpy(&funcRVA, data.data() + funcEntryOffset, sizeof(uint32_t));

        ExportEntry entry{};

        if (funcRVA == 0) {
            continue; // Invalid function entry
        }

        if (exportRangeValid && funcRVA >= exportRVAStart && funcRVA < exportRVAEnd) {
            const auto fwdFO = PEParser::RVAToFileOffset(pe, funcRVA);
            if (fwdFO) {
                entry.forwarder = PEParser::ReadString(
                    data, *fwdFO, PE::kMaxExportNameLen);
            }
            entry.address = 0;
        } else {
            entry.address = imageBase + static_cast<GuestAddress>(funcRVA);
        }

        modExports.byName[std::move(exportName)] = entry;
    }

    // ----------------------------------------------------------------
    // Store module (replaces existing registration if any)
    // ----------------------------------------------------------------
    m_modules[normalName] = std::move(modExports);
    return ErrorCode::Success;
}

// ============================================================================
// ResolveByName — Case-sensitive export name lookup (per PE spec)
// ============================================================================

std::optional<GuestAddress> ExportResolver::ResolveByName(
    std::string_view dllName,
    std::string_view funcName) const noexcept
{
    if (dllName.empty() || funcName.empty()) {
        return std::nullopt;
    }

    const auto normalName = NormalizeDLLName(dllName);
    const auto modIt = m_modules.find(normalName);
    if (modIt == m_modules.end()) {
        return std::nullopt;
    }

    const auto& mod = modIt->second;
    const auto it = mod.byName.find(std::string(funcName));
    if (it == mod.byName.end()) {
        return std::nullopt;
    }

    const auto& entry = it->second;

    // Transparently resolve forwarded exports
    if (!entry.forwarder.empty()) {
        return ResolveForwarderInternal(entry.forwarder, 0);
    }

    if (entry.address == 0) {
        return std::nullopt;
    }

    return entry.address;
}

// ============================================================================
// ResolveByOrdinal — Direct ordinal lookup
// ============================================================================

std::optional<GuestAddress> ExportResolver::ResolveByOrdinal(
    std::string_view dllName,
    uint16_t ordinal) const noexcept
{
    if (dllName.empty()) {
        return std::nullopt;
    }

    const auto normalName = NormalizeDLLName(dllName);
    const auto modIt = m_modules.find(normalName);
    if (modIt == m_modules.end()) {
        return std::nullopt;
    }

    const auto& mod = modIt->second;
    const auto it = mod.byOrdinal.find(ordinal);
    if (it == mod.byOrdinal.end()) {
        return std::nullopt;
    }

    const auto& entry = it->second;

    if (!entry.forwarder.empty()) {
        return ResolveForwarderInternal(entry.forwarder, 0);
    }

    if (entry.address == 0) {
        return std::nullopt;
    }

    return entry.address;
}

// ============================================================================
// ResolveForwarder — Public entry point for forwarder string resolution
// ============================================================================

std::optional<GuestAddress> ExportResolver::ResolveForwarder(
    std::string_view forwarderString) const noexcept
{
    return ResolveForwarderInternal(forwarderString, 0);
}

// ============================================================================
// ResolveForwarderInternal — Recursive resolution with depth cap
// ============================================================================
//
// Forwarder string format: "DLLName.ExportName" or "DLLName.#Ordinal"
// DLLName does NOT include the ".dll" extension (NormalizeDLLName appends it).
// Ordinal forwarders start with '#': e.g., "NTDLL.#42"
//
// Recursion is capped to prevent infinite chains from circular forwarders
// (which would indicate a malformed or adversarial PE).

std::optional<GuestAddress> ExportResolver::ResolveForwarderInternal(
    std::string_view forwarderString,
    uint32_t depth) const noexcept
{
    if (depth >= kMaxForwarderDepth) {
        return std::nullopt;
    }

    if (forwarderString.empty()) {
        return std::nullopt;
    }

    // Cap forwarder string length to prevent excessive processing
    if (forwarderString.size() > PE::kMaxExportNameLen) {
        return std::nullopt;
    }

    // Split on the first '.' — DLL part vs function/ordinal part
    const auto dotPos = forwarderString.find('.');
    if (dotPos == std::string_view::npos || dotPos == 0) {
        return std::nullopt;
    }

    const auto dllPart  = forwarderString.substr(0, dotPos);
    const auto funcPart = forwarderString.substr(dotPos + 1);
    if (funcPart.empty()) {
        return std::nullopt;
    }

    const auto normalDll = NormalizeDLLName(dllPart);
    if (normalDll.empty()) {
        return std::nullopt;
    }

    const auto modIt = m_modules.find(normalDll);
    if (modIt == m_modules.end()) {
        return std::nullopt;
    }

    const auto& mod = modIt->second;

    // ----------------------------------------------------------------
    // Ordinal forwarder: "DLL.#42"
    // ----------------------------------------------------------------
    if (funcPart[0] == '#') {
        const auto ordStr = funcPart.substr(1);
        if (ordStr.empty()) {
            return std::nullopt;
        }

        // Parse ordinal value with overflow protection
        uint32_t ordVal = 0;
        for (const char c : ordStr) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            const uint32_t next = ordVal * 10 + static_cast<uint32_t>(c - '0');
            if (next < ordVal) {
                return std::nullopt; // Overflow
            }
            ordVal = next;
        }

        if (ordVal > 0xFFFF) {
            return std::nullopt;
        }

        const auto ordinal = static_cast<uint16_t>(ordVal);
        const auto it = mod.byOrdinal.find(ordinal);
        if (it == mod.byOrdinal.end()) {
            return std::nullopt;
        }

        const auto& entry = it->second;
        if (!entry.forwarder.empty()) {
            return ResolveForwarderInternal(entry.forwarder, depth + 1);
        }

        return entry.address != 0 ? std::optional(entry.address) : std::nullopt;
    }

    // ----------------------------------------------------------------
    // Name forwarder: "DLL.FunctionName"
    // ----------------------------------------------------------------
    const auto it = mod.byName.find(std::string(funcPart));
    if (it == mod.byName.end()) {
        return std::nullopt;
    }

    const auto& entry = it->second;
    if (!entry.forwarder.empty()) {
        return ResolveForwarderInternal(entry.forwarder, depth + 1);
    }

    return entry.address != 0 ? std::optional(entry.address) : std::nullopt;
}

// ============================================================================
// GetModuleBase — Retrieve a registered module's image base address
// ============================================================================

std::optional<GuestAddress> ExportResolver::GetModuleBase(
    std::string_view dllName) const noexcept
{
    if (dllName.empty()) {
        return std::nullopt;
    }

    const auto normalName = NormalizeDLLName(dllName);
    const auto it = m_modules.find(normalName);
    if (it == m_modules.end()) {
        return std::nullopt;
    }

    return it->second.imageBase;
}

// ============================================================================
// HasModule — Check if a module is registered
// ============================================================================

bool ExportResolver::HasModule(std::string_view dllName) const noexcept {
    if (dllName.empty()) {
        return false;
    }

    const auto normalName = NormalizeDLLName(dllName);
    return m_modules.find(normalName) != m_modules.end();
}

// ============================================================================
// GetModuleNames — Return all registered module canonical names
// ============================================================================

std::vector<std::string> ExportResolver::GetModuleNames() const {
    std::vector<std::string> names;
    names.reserve(m_modules.size());

    for (const auto& [key, mod] : m_modules) {
        names.push_back(mod.canonicalName);
    }

    return names;
}

} // namespace Phantom
