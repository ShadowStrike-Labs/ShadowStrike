/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for deterministic PEParser unit tests.
 */

#pragma once

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

#include "../../../src/PhantomCore/PEParser/PEConstants.hpp"
#include "../../../src/PhantomCore/PEParser/PETypes.hpp"

namespace ShadowStrike::PEParser::Test {

namespace fs = std::filesystem;

class ScopedTempDir final {
public:
    explicit ScopedTempDir(std::wstring_view prefix) {
        wchar_t buffer[MAX_PATH]{};
        const DWORD length = ::GetTempPathW(MAX_PATH, buffer);
        if (length == 0 || length >= MAX_PATH) {
            throw std::runtime_error("GetTempPathW failed");
        }

        m_path = fs::path(buffer) / UniqueWide(prefix);
        std::error_code ec;
        if (!fs::create_directories(m_path, ec) && ec) {
            throw std::runtime_error("Failed to create temporary directory");
        }
    }

    ~ScopedTempDir() {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    [[nodiscard]] const fs::path& Path() const noexcept {
        return m_path;
    }

    [[nodiscard]] fs::path File(std::wstring_view name) const {
        return m_path / fs::path(name);
    }

private:
    fs::path m_path;

    [[nodiscard]] static std::wstring UniqueWide(std::wstring_view prefix) {
        static std::atomic_uint64_t counter{0};
        return std::wstring(prefix) +
               std::to_wstring(::GetCurrentProcessId()) + L"_" +
               std::to_wstring(counter.fetch_add(1, std::memory_order_relaxed));
    }
};

inline void WriteAllBytes(const fs::path& path, std::span<const uint8_t> bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        throw std::runtime_error("Failed to create binary file");
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
        throw std::runtime_error("Failed to write binary file");
    }
}

struct SyntheticPEOptions {
    bool pe64 = false;
    bool dll = false;
    bool driver = false;
    bool highEntropyText = false;
    bool writableExecutableText = false;
    bool includeImportDirectory = false;
    bool includeRichHeader = false;
    bool includeSecurityDirectory = false;
    bool includeDotNetDirectory = false;
    bool includeOverlay = false;
    bool useValidChecksum = false;
    bool useInvalidChecksum = false;
    uint32_t timeDateStamp = 1704067201u;  // 2024-01-01 UTC + 1s
    uint16_t subsystem = Subsystem::WINDOWS_CUI;
    uint16_t dllCharacteristics =
        DllCharacteristics::DYNAMIC_BASE |
        DllCharacteristics::NX_COMPAT |
        DllCharacteristics::GUARD_CF |
        DllCharacteristics::NO_SEH;
};

inline constexpr size_t kDosHeaderSize = sizeof(DosHeader);
inline constexpr size_t kNtHeadersOffset = 0x80;
inline constexpr size_t kSizeOfHeaders = 0x200;
inline constexpr uint32_t kSectionVirtualAddress = 0x1000;
inline constexpr uint32_t kSectionVirtualSize = 0x300;
inline constexpr uint32_t kSectionRawAddress = 0x200;
inline constexpr uint32_t kSectionRawSize = 0x200;
inline constexpr uint32_t kSectionAlignment = 0x1000;
inline constexpr uint32_t kFileAlignment = 0x200;
inline constexpr size_t kSectionContentSize = kSectionRawSize;

template <typename T>
void WriteObject(std::vector<uint8_t>& buffer, size_t offset, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>, "WriteObject requires trivially copyable types");
    if (offset + sizeof(T) > buffer.size()) {
        buffer.resize(offset + sizeof(T), 0);
    }
    std::memcpy(buffer.data() + offset, &value, sizeof(T));
}

inline void WriteBytes(std::vector<uint8_t>& buffer, size_t offset, std::span<const uint8_t> bytes) {
    if (offset + bytes.size() > buffer.size()) {
        buffer.resize(offset + bytes.size(), 0);
    }
    std::memcpy(buffer.data() + offset, bytes.data(), bytes.size());
}

inline void WriteCString(std::vector<uint8_t>& buffer, size_t offset, std::string_view text) {
    if (offset + text.size() + 1 > buffer.size()) {
        buffer.resize(offset + text.size() + 1, 0);
    }
    std::memcpy(buffer.data() + offset, text.data(), text.size());
    buffer[offset + text.size()] = 0;
}

[[nodiscard]] inline constexpr size_t AlignUp(size_t value, size_t alignment) noexcept {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

[[nodiscard]] inline constexpr size_t OptionalHeaderSize(bool pe64) noexcept {
    return pe64
        ? sizeof(OptionalHeader64) + (DataDirectory::MAX_ENTRIES * sizeof(DataDirectoryEntry))
        : sizeof(OptionalHeader32) + (DataDirectory::MAX_ENTRIES * sizeof(DataDirectoryEntry));
}

[[nodiscard]] inline constexpr size_t OptionalHeaderOffset() noexcept {
    return kNtHeadersOffset + sizeof(uint32_t) + sizeof(FileHeader);
}

[[nodiscard]] inline constexpr size_t DataDirectoryTableOffset(bool pe64) noexcept {
    return OptionalHeaderOffset() + (pe64 ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32));
}

[[nodiscard]] inline constexpr size_t SectionTableOffset(bool pe64) noexcept {
    return OptionalHeaderOffset() + OptionalHeaderSize(pe64);
}

[[nodiscard]] inline constexpr size_t ChecksumFieldOffset() noexcept {
    return OptionalHeaderOffset() + offsetof(OptionalHeader32, CheckSum);
}

[[nodiscard]] inline uint32_t ComputePeChecksum(const std::vector<uint8_t>& image) {
    const size_t fileSize = image.size();
    const size_t checksumOffset = ChecksumFieldOffset();

    uint32_t acc = 0;
    for (size_t offset = 0; offset + 1 < fileSize; offset += 2) {
        if (offset == checksumOffset || offset == checksumOffset + 2) {
            continue;
        }

        const uint16_t word =
            static_cast<uint16_t>(image[offset]) |
            (static_cast<uint16_t>(image[offset + 1]) << 8);
        acc += word;
        acc = (acc >> 16) + (acc & 0xFFFFu);
    }

    if ((fileSize & 1u) != 0) {
        acc += image.back();
        acc = (acc >> 16) + (acc & 0xFFFFu);
    }

    acc = (acc & 0xFFFFu) + (acc >> 16);
    acc += static_cast<uint32_t>(fileSize);
    acc = (acc & 0xFFFFu) + (acc >> 16);
    return acc & 0xFFFFu;
}

inline void WriteDataDirectoryEntry(
    std::vector<uint8_t>& image,
    bool pe64,
    size_t index,
    uint32_t rva,
    uint32_t size) {
    const DataDirectoryEntry entry{rva, size};
    WriteObject(image, DataDirectoryTableOffset(pe64) + index * sizeof(DataDirectoryEntry), entry);
}

inline void PopulateSectionData(
    std::vector<uint8_t>& image,
    const SyntheticPEOptions& options,
    uint32_t& importDescriptorRva,
    uint32_t& importDescriptorSize,
    uint32_t& comDescriptorRva,
    uint32_t& comDescriptorSize) {
    std::vector<uint8_t> section(kSectionContentSize, options.highEntropyText ? 0 : 0x90);
    if (options.highEntropyText) {
        for (size_t index = 0; index < section.size(); ++index) {
            section[index] = static_cast<uint8_t>(index & 0xFFu);
        }
    }

    if (options.includeImportDirectory) {
        constexpr size_t descriptorOffset = 0x00;
        constexpr size_t thunkOffset32 = 0x28;
        constexpr size_t thunkOffset64 = 0x28;
        const size_t iatOffset = options.pe64 ? 0x38 : 0x30;
        constexpr size_t dllNameOffset = 0x50;
        constexpr size_t importByNameOffset = 0x70;

        const uint32_t descriptorRva = kSectionVirtualAddress + static_cast<uint32_t>(descriptorOffset);
        const uint32_t intRva = kSectionVirtualAddress + static_cast<uint32_t>(options.pe64 ? thunkOffset64 : thunkOffset32);
        const uint32_t iatRva = kSectionVirtualAddress + static_cast<uint32_t>(iatOffset);
        const uint32_t dllNameRva = kSectionVirtualAddress + static_cast<uint32_t>(dllNameOffset);
        const uint32_t importByNameRva = kSectionVirtualAddress + static_cast<uint32_t>(importByNameOffset);

        ImportDescriptor descriptor{};
        descriptor.OriginalFirstThunk = intRva;
        descriptor.Name = dllNameRva;
        descriptor.FirstThunk = iatRva;
        WriteObject(section, descriptorOffset, descriptor);
        WriteObject(section, descriptorOffset + sizeof(ImportDescriptor), ImportDescriptor{});

        if (options.pe64) {
            const uint64_t thunk = importByNameRva;
            WriteObject(section, thunkOffset64, thunk);
            WriteObject(section, thunkOffset64 + sizeof(uint64_t), uint64_t{0});
            WriteObject(section, iatOffset, thunk);
            WriteObject(section, iatOffset + sizeof(uint64_t), uint64_t{0});
        } else {
            const uint32_t thunk = importByNameRva;
            WriteObject(section, thunkOffset32, thunk);
            WriteObject(section, thunkOffset32 + sizeof(uint32_t), uint32_t{0});
            WriteObject(section, iatOffset, thunk);
            WriteObject(section, iatOffset + sizeof(uint32_t), uint32_t{0});
        }

        WriteCString(section, dllNameOffset, "KERNEL32.dll");

        const uint16_t hint = 0;
        WriteObject(section, importByNameOffset, hint);
        WriteCString(section, importByNameOffset + sizeof(uint16_t), "ExitProcess");

        importDescriptorRva = descriptorRva;
        importDescriptorSize = static_cast<uint32_t>(sizeof(ImportDescriptor) * 2);
    }

    if (options.includeDotNetDirectory) {
        constexpr size_t clrOffset = 0xA0;
        CLRHeader clr{};
        clr.cb = sizeof(CLRHeader);
        WriteObject(section, clrOffset, clr);
        comDescriptorRva = kSectionVirtualAddress + static_cast<uint32_t>(clrOffset);
        comDescriptorSize = sizeof(CLRHeader);
    }

    WriteBytes(image, kSectionRawAddress, section);
}

[[nodiscard]] inline std::vector<uint8_t> BuildSyntheticPE(const SyntheticPEOptions& options) {
    std::vector<uint8_t> image(kSizeOfHeaders + kSectionRawSize, 0);

    DosHeader dos{};
    dos.e_magic = DOS_SIGNATURE;
    dos.e_lfanew = static_cast<int32_t>(kNtHeadersOffset);
    WriteObject(image, 0, dos);

    if (options.includeRichHeader) {
        constexpr uint32_t xorKey = 0xA5A5A5A5u;
        constexpr uint16_t buildId = 0x1234u;
        constexpr uint16_t productId = 0x5678u;
        constexpr uint32_t useCount = 9u;
        const uint32_t encodedId = (static_cast<uint32_t>(buildId) << 16) | productId;

        WriteObject(image, 0x40, RichHeader::DANS_SIGNATURE ^ xorKey);
        WriteObject(image, 0x44, uint32_t{0});
        WriteObject(image, 0x48, uint32_t{0});
        WriteObject(image, 0x4C, uint32_t{0});
        WriteObject(image, 0x50, encodedId ^ xorKey);
        WriteObject(image, 0x54, useCount ^ xorKey);
        WriteObject(image, 0x58, xorKey);
        WriteObject(image, 0x5C, xorKey);
        WriteObject(image, 0x60, RichHeader::RICH_SIGNATURE);
        WriteObject(image, 0x64, xorKey);
    }

    WriteObject(image, kNtHeadersOffset, NT_SIGNATURE);

    FileHeader fileHeader{};
    fileHeader.Machine = options.pe64 ? Machine::AMD64 : Machine::I386;
    fileHeader.NumberOfSections = 1;
    fileHeader.TimeDateStamp = options.timeDateStamp;
    fileHeader.SizeOfOptionalHeader = static_cast<uint16_t>(OptionalHeaderSize(options.pe64));
    fileHeader.Characteristics = FileCharacteristics::EXECUTABLE_IMAGE;
    if (!options.pe64) {
        fileHeader.Characteristics |= FileCharacteristics::MACHINE_32BIT;
    }
    if (options.dll) {
        fileHeader.Characteristics |= FileCharacteristics::DLL;
    }
    WriteObject(image, kNtHeadersOffset + sizeof(uint32_t), fileHeader);

    const uint16_t subsystem = options.driver ? Subsystem::NATIVE : options.subsystem;
    const uint16_t dllCharacteristics = options.dllCharacteristics;

    if (options.pe64) {
        OptionalHeader64 optional{};
        optional.Magic = PE64_MAGIC;
        optional.MajorLinkerVersion = 14;
        optional.MinorLinkerVersion = 30;
        optional.SizeOfCode = kSectionRawSize;
        optional.AddressOfEntryPoint = kSectionVirtualAddress;
        optional.BaseOfCode = kSectionVirtualAddress;
        optional.ImageBase = 0x140000000ULL;
        optional.SectionAlignment = kSectionAlignment;
        optional.FileAlignment = kFileAlignment;
        optional.MajorOperatingSystemVersion = 10;
        optional.MinorOperatingSystemVersion = 0;
        optional.MajorSubsystemVersion = 10;
        optional.MinorSubsystemVersion = 0;
        optional.SizeOfImage = static_cast<uint32_t>(
            AlignUp(kSectionVirtualAddress + kSectionVirtualSize, kSectionAlignment));
        optional.SizeOfHeaders = kSizeOfHeaders;
        optional.Subsystem = subsystem;
        optional.DllCharacteristics = dllCharacteristics;
        optional.SizeOfStackReserve = 0x100000;
        optional.SizeOfStackCommit = 0x1000;
        optional.SizeOfHeapReserve = 0x100000;
        optional.SizeOfHeapCommit = 0x1000;
        optional.NumberOfRvaAndSizes = DataDirectory::MAX_ENTRIES;
        WriteObject(image, OptionalHeaderOffset(), optional);
    } else {
        OptionalHeader32 optional{};
        optional.Magic = PE32_MAGIC;
        optional.MajorLinkerVersion = 14;
        optional.MinorLinkerVersion = 30;
        optional.SizeOfCode = kSectionRawSize;
        optional.AddressOfEntryPoint = kSectionVirtualAddress;
        optional.BaseOfCode = kSectionVirtualAddress;
        optional.BaseOfData = kSectionVirtualAddress;
        optional.ImageBase = 0x400000;
        optional.SectionAlignment = kSectionAlignment;
        optional.FileAlignment = kFileAlignment;
        optional.MajorOperatingSystemVersion = 10;
        optional.MinorOperatingSystemVersion = 0;
        optional.MajorSubsystemVersion = 10;
        optional.MinorSubsystemVersion = 0;
        optional.SizeOfImage = static_cast<uint32_t>(
            AlignUp(kSectionVirtualAddress + kSectionVirtualSize, kSectionAlignment));
        optional.SizeOfHeaders = kSizeOfHeaders;
        optional.Subsystem = subsystem;
        optional.DllCharacteristics = dllCharacteristics;
        optional.SizeOfStackReserve = 0x100000;
        optional.SizeOfStackCommit = 0x1000;
        optional.SizeOfHeapReserve = 0x100000;
        optional.SizeOfHeapCommit = 0x1000;
        optional.NumberOfRvaAndSizes = DataDirectory::MAX_ENTRIES;
        WriteObject(image, OptionalHeaderOffset(), optional);
    }

    SectionHeader section{};
    constexpr std::array<uint8_t, 8> kTextName = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    std::copy(kTextName.begin(), kTextName.end(), section.Name);
    section.VirtualSize = kSectionVirtualSize;
    section.VirtualAddress = kSectionVirtualAddress;
    section.SizeOfRawData = kSectionRawSize;
    section.PointerToRawData = kSectionRawAddress;
    section.Characteristics =
        SectionCharacteristics::CNT_CODE |
        SectionCharacteristics::MEM_READ |
        SectionCharacteristics::MEM_EXECUTE;
    if (options.writableExecutableText) {
        section.Characteristics |= SectionCharacteristics::MEM_WRITE;
    }
    WriteObject(image, SectionTableOffset(options.pe64), section);

    uint32_t importDescriptorRva = 0;
    uint32_t importDescriptorSize = 0;
    uint32_t comDescriptorRva = 0;
    uint32_t comDescriptorSize = 0;
    PopulateSectionData(
        image,
        options,
        importDescriptorRva,
        importDescriptorSize,
        comDescriptorRva,
        comDescriptorSize);

    if (importDescriptorRva != 0) {
        WriteDataDirectoryEntry(
            image,
            options.pe64,
            DataDirectory::IMPORT,
            importDescriptorRva,
            importDescriptorSize);
    }

    if (comDescriptorRva != 0) {
        WriteDataDirectoryEntry(
            image,
            options.pe64,
            DataDirectory::COM_DESCRIPTOR,
            comDescriptorRva,
            comDescriptorSize);
    }

    if (options.includeOverlay) {
        const size_t overlayOffset = image.size();
        image.resize(image.size() + 256, 0);
        for (size_t index = 0; index < 256; ++index) {
            image[overlayOffset + index] = static_cast<uint8_t>(index);
        }
    }

    if (options.includeSecurityDirectory) {
        const uint32_t certificateOffset = static_cast<uint32_t>(image.size());
        image.resize(image.size() + 8, 0);

        const uint32_t length = 8;
        const uint16_t revision = WinCert::REVISION_2_0;
        const uint16_t certificateType = WinCert::TYPE_PKCS;
        WriteObject(image, certificateOffset, length);
        WriteObject(image, certificateOffset + sizeof(uint32_t), revision);
        WriteObject(image, certificateOffset + sizeof(uint32_t) + sizeof(uint16_t), certificateType);

        WriteDataDirectoryEntry(
            image,
            options.pe64,
            DataDirectory::SECURITY,
            certificateOffset,
            length);
    }

    if (options.useValidChecksum) {
        const uint32_t checksum = ComputePeChecksum(image);
        WriteObject(image, ChecksumFieldOffset(), checksum);
    } else if (options.useInvalidChecksum) {
        const uint32_t checksum = 1;
        WriteObject(image, ChecksumFieldOffset(), checksum);
    }

    return image;
}

[[nodiscard]] inline std::vector<uint8_t> BuildMinimalPE32(
    const SyntheticPEOptions& overrides = {}) {
    SyntheticPEOptions options = overrides;
    options.pe64 = false;
    return BuildSyntheticPE(options);
}

[[nodiscard]] inline std::vector<uint8_t> BuildMinimalPE64(
    const SyntheticPEOptions& overrides = {}) {
    SyntheticPEOptions options = overrides;
    options.pe64 = true;
    return BuildSyntheticPE(options);
}

}  // namespace ShadowStrike::PEParser::Test
