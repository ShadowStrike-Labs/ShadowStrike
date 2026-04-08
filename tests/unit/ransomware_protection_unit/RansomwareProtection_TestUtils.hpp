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

#include <filesystem>
#include <fstream>
#include <sstream>
#include <span>
#include <string_view>
#include <vector>

namespace ShadowStrike::Tests::RansomwareProtection {

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
    return std::vector<uint8_t>(text.begin(), text.end());
}

inline bool ContainsPid(const std::vector<uint32_t>& pids, uint32_t pid) {
    return std::find(pids.begin(), pids.end(), pid) != pids.end();
}

class TempDirectoryFixture : public ::testing::Test {
protected:
    void SetUp() override {
        testRoot_ =
            fs::temp_directory_path() / fs::path(MakeUniqueWideName(L"ShadowStrike_Ransomware_UT"));

        std::error_code ec;
        fs::create_directories(testRoot_, ec);
        ASSERT_FALSE(ec) << "Failed to create test root: " << testRoot_.string()
                         << " error=" << ec.message();
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
        EXPECT_FALSE(ec) << "Failed to create directory: " << fullPath.string()
                         << " error=" << ec.message();
        return fullPath;
    }

    [[nodiscard]] fs::path WriteText(std::wstring_view relative, std::string_view text) const {
        const fs::path fullPath = MakePath(relative);
        std::error_code ec;
        fs::create_directories(fullPath.parent_path(), ec);
        EXPECT_FALSE(ec) << "Failed to create parent directory for: " << fullPath.string();

        std::ofstream stream(fullPath, std::ios::binary | std::ios::trunc);
        if (!stream.is_open()) {
            ADD_FAILURE() << "Unable to open file for writing: " << fullPath.string();
            return fullPath;
        }

        stream.write(text.data(), static_cast<std::streamsize>(text.size()));
        EXPECT_TRUE(stream.good()) << "Failed to write test file: " << fullPath.string();
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
            stream.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
        }

        EXPECT_TRUE(stream.good()) << "Failed to write binary test file: " << fullPath.string();
        return fullPath;
    }

    [[nodiscard]] std::string ReadTextFile(const fs::path& path) const {
        std::ifstream stream(path, std::ios::binary);
        if (!stream.is_open()) {
            ADD_FAILURE() << "Unable to open file for reading: " << path.string();
            return {};
        }

        std::ostringstream buffer;
        buffer << stream.rdbuf();
        return buffer.str();
    }

    [[nodiscard]] std::vector<uint8_t> ReadBytes(const fs::path& path) const {
        std::ifstream stream(path, std::ios::binary);
        if (!stream.is_open()) {
            ADD_FAILURE() << "Unable to open file for reading: " << path.string();
            return {};
        }

        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>());
    }

    fs::path testRoot_;
};

}  // namespace ShadowStrike::Tests::RansomwareProtection
