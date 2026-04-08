/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "pch.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <vector>

namespace ShadowStrike::Tests::CoreFileSystem {

namespace fs = std::filesystem;

inline std::wstring MakeUniqueWideName(std::wstring_view prefix) {
    GUID guid{};
    if (FAILED(::CoCreateGuid(&guid))) {
        return std::wstring(prefix) + L"_fallback";
    }

    wchar_t buffer[80]{};
    swprintf_s(
        buffer,
        L"%ls_%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        std::wstring(prefix).c_str(),
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
    return buffer;
}

inline std::vector<uint8_t> Bytes(std::string_view text) {
    return { text.begin(), text.end() };
}

inline std::vector<uint8_t> BuildMinimalPe64Image() {
    std::vector<uint8_t> buffer(0x200, 0);
    buffer[0] = 'M';
    buffer[1] = 'Z';

    const uint32_t peOffset = 0x80;
    std::memcpy(buffer.data() + 0x3C, &peOffset, sizeof(peOffset));

    buffer[0x80] = 'P';
    buffer[0x81] = 'E';
    buffer[0x82] = 0;
    buffer[0x83] = 0;

    const size_t coffOffset = 0x84;
    const uint16_t machine = 0x8664;  // AMD64
    const uint16_t optionalHeaderSize = 0;
    const uint16_t characteristics = 0;

    std::memcpy(buffer.data() + coffOffset, &machine, sizeof(machine));
    std::memcpy(buffer.data() + coffOffset + 16, &optionalHeaderSize, sizeof(optionalHeaderSize));
    std::memcpy(buffer.data() + coffOffset + 18, &characteristics, sizeof(characteristics));

    return buffer;
}

inline std::vector<uint8_t> BuildZipOfficeBuffer(std::string_view officeDirectory) {
    std::vector<uint8_t> buffer{
        'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x21, 0x00
    };

    auto appendAscii = [&buffer](std::string_view text) {
        buffer.insert(buffer.end(), text.begin(), text.end());
    };

    appendAscii("[Content_Types].xml");
    appendAscii(officeDirectory);
    appendAscii("/document.xml");
    return buffer;
}

inline std::string MakeHexHash(char fill, char suffix = '\0') {
    std::string hash(64, fill);
    if (suffix != '\0') {
        hash.back() = suffix;
    }
    return hash;
}

class TempDirectoryFixture : public ::testing::Test {
protected:
    void SetUp() override {
        testRoot_ = fs::temp_directory_path() / fs::path(MakeUniqueWideName(L"ShadowStrike_CoreFileSystem_UT"));
        std::error_code ec;
        fs::create_directories(testRoot_, ec);
        ASSERT_FALSE(ec) << "Failed to create test root: " << testRoot_.string() << " error=" << ec.message();
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(testRoot_, ec);
    }

    [[nodiscard]] fs::path MakePath(std::wstring_view relative) const {
        return testRoot_ / fs::path(std::wstring(relative));
    }

    [[nodiscard]] fs::path CreateDirectory(std::wstring_view relative) const {
        const fs::path fullPath = MakePath(relative);
        std::error_code ec;
        fs::create_directories(fullPath, ec);
        EXPECT_FALSE(ec) << "Failed to create directory: " << fullPath.string() << " error=" << ec.message();
        return fullPath;
    }

    [[nodiscard]] fs::path WriteBytes(std::wstring_view relative, std::span<const uint8_t> bytes) const {
        const fs::path fullPath = MakePath(relative);
        std::error_code ec;
        fs::create_directories(fullPath.parent_path(), ec);
        EXPECT_FALSE(ec) << "Failed to create parent directory for: " << fullPath.string();

        std::ofstream stream(fullPath, std::ios::binary | std::ios::trunc);
        if (!stream.is_open()) {
            ADD_FAILURE() << "Unable to open file for writing: " << fullPath.string();
            return fullPath;
        }

        if (!bytes.empty()) {
            stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        }

        EXPECT_TRUE(stream.good()) << "Failed to write bytes to: " << fullPath.string();
        return fullPath;
    }

    [[nodiscard]] fs::path WriteText(std::wstring_view relative, std::string_view text) const {
        const auto bytes = Bytes(text);
        return WriteBytes(relative, bytes);
    }

    fs::path testRoot_;
};

}  // namespace ShadowStrike::Tests::CoreFileSystem
