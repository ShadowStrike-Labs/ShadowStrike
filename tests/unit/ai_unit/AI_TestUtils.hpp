#pragma once

/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for PhantomCortex unit tests.
 *
 * These helpers intentionally build deterministic, in-memory fixtures so the
 * AI tests validate production contracts without depending on external files,
 * model downloads, or mutable system state.
 */

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "../../../src/Shared_modules/PEParser/PEConstants.hpp"
#include "../../../src/Shared_modules/PEParser/PETypes.hpp"

namespace ShadowStrike::AI::Test {

namespace fs = std::filesystem;

class ScopedTempDir final {
public:
    explicit ScopedTempDir(std::wstring_view prefix) {
        wchar_t tempPath[MAX_PATH]{};
        const DWORD charsWritten = ::GetTempPathW(MAX_PATH, tempPath);
        if (charsWritten == 0 || charsWritten >= MAX_PATH) {
            root_ = fs::temp_directory_path() / L"ShadowStrike_AITests_Fallback";
        } else {
            root_ = tempPath;
        }

        static std::atomic_uint64_t counter{0};
        const uint64_t uniqueId = (static_cast<uint64_t>(::GetCurrentProcessId()) << 32)
            | counter.fetch_add(1, std::memory_order_relaxed);

        root_ /= std::wstring(prefix) + std::to_wstring(::GetTickCount64()) + L"_" + std::to_wstring(uniqueId);
        fs::create_directories(root_);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    ~ScopedTempDir() {
        if (!root_.empty()) {
            std::error_code ec;
            fs::remove_all(root_, ec);
        }
    }

    [[nodiscard]] const fs::path& Path() const noexcept {
        return root_;
    }

    [[nodiscard]] fs::path File(std::wstring_view name) const {
        return root_ / fs::path{name};
    }

    [[nodiscard]] fs::path CreateDir(std::wstring_view name) const {
        const fs::path dirPath = root_ / fs::path{name};
        fs::create_directories(dirPath);
        return dirPath;
    }

private:
    fs::path root_;
};

inline void WriteBinaryFile(const fs::path& path, std::span<const uint8_t> bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        throw std::runtime_error("Failed to open binary output file");
    }

    if (!bytes.empty()) {
        stream.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }

    if (!stream.good()) {
        throw std::runtime_error("Failed to write binary output file");
    }
}

inline std::vector<uint8_t> ReadBinaryFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("Failed to open binary input file");
    }

    return std::vector<uint8_t>(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
}

template <typename T>
inline void WriteStruct(std::vector<uint8_t>& bytes, const size_t offset, const T& value) {
    const size_t requiredSize = offset + sizeof(T);
    if (bytes.size() < requiredSize) {
        bytes.resize(requiredSize, 0);
    }
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

inline constexpr uint32_t AlignUp(const uint32_t value, const uint32_t alignment) noexcept {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

struct MinimalPeOptions {
    std::vector<uint8_t> sectionPayload;
    std::string sectionName = ".text";
    bool hasDebugDirectory = true;
    bool hasBaseRelocations = true;
    bool hasResources = true;
    bool hasSignature = true;
    bool hasTls = true;
    bool hasExports = true;
};

inline std::vector<uint8_t> BuildMinimalPe32(const MinimalPeOptions& options = {}) {
    using namespace ShadowStrike::PEParser;

    constexpr uint32_t kPeOffset = 0x80;
    constexpr uint32_t kFileAlignment = 0x200;
    constexpr uint32_t kSectionAlignment = 0x1000;
    constexpr uint32_t kRawDataOffset = 0x200;
    constexpr uint32_t kSectionRva = 0x1000;

    std::vector<uint8_t> payload = options.sectionPayload;
    if (payload.empty()) {
        payload.push_back(0x90);
    }

    const uint32_t rawSize = AlignUp(static_cast<uint32_t>(payload.size()), kFileAlignment);
    const uint32_t fileSize = kRawDataOffset + rawSize;
    std::vector<uint8_t> bytes(fileSize, 0);

    DosHeader dos{};
    dos.e_magic = DOS_SIGNATURE;
    dos.e_cblp = 0x90;
    dos.e_cp = 3;
    dos.e_cparhdr = 4;
    dos.e_maxalloc = 0xFFFF;
    dos.e_sp = 0xB8;
    dos.e_lfarlc = 0x40;
    dos.e_lfanew = static_cast<int32_t>(kPeOffset);
    WriteStruct(bytes, 0, dos);

    const uint32_t signature = NT_SIGNATURE;
    WriteStruct(bytes, kPeOffset, signature);

    FileHeader fileHeader{};
    fileHeader.Machine = Machine::I386;
    fileHeader.NumberOfSections = 1;
    fileHeader.SizeOfOptionalHeader = static_cast<uint16_t>(
        sizeof(OptionalHeader32) + DataDirectory::MAX_ENTRIES * sizeof(DataDirectoryEntry));
    fileHeader.Characteristics = FileCharacteristics::EXECUTABLE_IMAGE
        | FileCharacteristics::MACHINE_32BIT;
    WriteStruct(bytes, kPeOffset + sizeof(signature), fileHeader);

    OptionalHeader32 optionalHeader{};
    optionalHeader.Magic = PE32_MAGIC;
    optionalHeader.MajorLinkerVersion = 14;
    optionalHeader.SizeOfCode = rawSize;
    optionalHeader.AddressOfEntryPoint = kSectionRva;
    optionalHeader.BaseOfCode = kSectionRva;
    optionalHeader.BaseOfData = kSectionRva;
    optionalHeader.ImageBase = 0x00400000;
    optionalHeader.SectionAlignment = kSectionAlignment;
    optionalHeader.FileAlignment = kFileAlignment;
    optionalHeader.MajorOperatingSystemVersion = 6;
    optionalHeader.MinorOperatingSystemVersion = 1;
    optionalHeader.MajorSubsystemVersion = 6;
    optionalHeader.MinorSubsystemVersion = 1;
    optionalHeader.SizeOfImage = AlignUp(kSectionRva + std::max<uint32_t>(1u, static_cast<uint32_t>(payload.size())),
                                         kSectionAlignment);
    optionalHeader.SizeOfHeaders = kRawDataOffset;
    optionalHeader.Subsystem = Subsystem::WINDOWS_CUI;
    optionalHeader.DllCharacteristics = DllCharacteristics::DYNAMIC_BASE | DllCharacteristics::NX_COMPAT;
    optionalHeader.SizeOfStackReserve = 0x100000;
    optionalHeader.SizeOfStackCommit = 0x1000;
    optionalHeader.SizeOfHeapReserve = 0x100000;
    optionalHeader.SizeOfHeapCommit = 0x1000;
    optionalHeader.NumberOfRvaAndSizes = DataDirectory::MAX_ENTRIES;

    const size_t optionalOffset = kPeOffset + sizeof(signature) + sizeof(FileHeader);
    WriteStruct(bytes, optionalOffset, optionalHeader);

    std::array<DataDirectoryEntry, DataDirectory::MAX_ENTRIES> directories{};
    if (options.hasExports) {
        directories[DataDirectory::EXPORT] = {kSectionRva + 0x40u, 64u};
    }
    if (options.hasResources) {
        directories[DataDirectory::RESOURCE] = {kSectionRva + 0x80u, 128u};
    }
    if (options.hasSignature) {
        directories[DataDirectory::SECURITY] = {kRawDataOffset + 0x40u, 256u};
    }
    if (options.hasBaseRelocations) {
        directories[DataDirectory::BASERELOC] = {kSectionRva + 0x100u, 64u};
    }
    if (options.hasDebugDirectory) {
        directories[DataDirectory::DEBUG] = {kSectionRva + 0x140u, 28u};
    }
    if (options.hasTls) {
        directories[DataDirectory::TLS] = {kSectionRva + 0x180u, 24u};
    }

    const size_t directoriesOffset = optionalOffset + sizeof(OptionalHeader32);
    for (size_t i = 0; i < directories.size(); ++i) {
        WriteStruct(bytes, directoriesOffset + i * sizeof(DataDirectoryEntry), directories[i]);
    }

    SectionHeader sectionHeader{};
    const size_t nameLength = std::min<size_t>(options.sectionName.size(), sizeof(sectionHeader.Name));
    std::memcpy(sectionHeader.Name, options.sectionName.data(), nameLength);
    sectionHeader.VirtualSize = static_cast<uint32_t>(payload.size());
    sectionHeader.VirtualAddress = kSectionRva;
    sectionHeader.SizeOfRawData = rawSize;
    sectionHeader.PointerToRawData = kRawDataOffset;
    sectionHeader.Characteristics = SectionCharacteristics::CNT_CODE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::MEM_EXECUTE;

    const size_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
    WriteStruct(bytes, sectionOffset, sectionHeader);

    std::copy(payload.begin(), payload.end(), bytes.begin() + kRawDataOffset);
    return bytes;
}

}  // namespace ShadowStrike::AI::Test
