/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"

#include "PhantomCore/Update/IUpdateTransport.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <fstream>
#include <atomic>
#include <shared_mutex>
#include <algorithm>
#include <sstream>

namespace ShadowStrike::Update {

static constexpr const wchar_t* kLogCategory = L"LocalTransport";
static constexpr size_t kCopyBufferSize = 64 * 1024;  // 64 KB copy chunks
static constexpr size_t kMaxManifestSize = 4 * 1024 * 1024;  // 4 MB limit

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct LocalFolderTransport::Impl {
    fs::path                  stagingDir;
    mutable std::shared_mutex mtx;
    std::atomic<bool>         cancelled{false};
};

// ============================================================================
// Construction / Destruction
// ============================================================================

LocalFolderTransport::LocalFolderTransport(fs::path stagingDir)
    : m_impl(std::make_unique<Impl>())
{
    m_impl->stagingDir = std::move(stagingDir);
    SS_LOG_INFO(kLogCategory, L"Created with staging dir: %s",
        m_impl->stagingDir.wstring().c_str());
}

LocalFolderTransport::~LocalFolderTransport() {
    SS_LOG_DEBUG(kLogCategory, L"Destroying LocalFolderTransport");
}

// ============================================================================
// IUpdateTransport Interface
// ============================================================================

bool LocalFolderTransport::IsAvailable() const {
    std::shared_lock lock(m_impl->mtx);
    std::error_code ec;
    const bool exists = fs::exists(m_impl->stagingDir, ec);
    if (ec) {
        SS_LOG_WARN(kLogCategory, L"IsAvailable check failed: %hs", ec.message().c_str());
        return false;
    }
    if (!exists) {
        SS_LOG_DEBUG(kLogCategory, L"Staging directory does not exist: %s",
            m_impl->stagingDir.wstring().c_str());
        return false;
    }
    const bool isDir = fs::is_directory(m_impl->stagingDir, ec);
    if (ec || !isDir) {
        SS_LOG_WARN(kLogCategory, L"Staging path is not a directory: %s",
            m_impl->stagingDir.wstring().c_str());
        return false;
    }
    return true;
}

std::string_view LocalFolderTransport::GetName() const noexcept {
    return "LocalFolderTransport";
}

std::vector<RemotePackageInfo> LocalFolderTransport::QueryAvailablePackages(
    std::string_view /*channel*/)
{
    std::shared_lock lock(m_impl->mtx);
    std::vector<RemotePackageInfo> packages;

    std::error_code ec;
    if (!fs::exists(m_impl->stagingDir, ec) || ec) {
        SS_LOG_WARN(kLogCategory, L"Staging dir not found for query: %s",
            m_impl->stagingDir.wstring().c_str());
        return packages;
    }

    // Scan for package files: .pkg, .delta, .spkg (ShadowStrike package)
    static constexpr std::wstring_view kPackageExtensions[] = {
        L".pkg", L".delta", L".spkg", L".ssdp"
    };

    for (const auto& entry : fs::directory_iterator(m_impl->stagingDir, ec)) {
        if (ec) {
            SS_LOG_WARN(kLogCategory, L"Directory iteration error: %hs", ec.message().c_str());
            break;
        }
        if (!entry.is_regular_file(ec) || ec) continue;

        const auto ext = entry.path().extension().wstring();
        bool isPackage = false;
        for (const auto& pext : kPackageExtensions) {
            if (_wcsicmp(ext.c_str(), pext.data()) == 0) {
                isPackage = true;
                break;
            }
        }
        if (!isPackage) continue;

        // Validate file size before processing
        const auto fileSize = entry.file_size(ec);
        if (ec || fileSize == 0) continue;

        RemotePackageInfo info;
        info.packageId   = entry.path().stem().string();
        info.size        = fileSize;
        info.downloadUrl = entry.path().string();
        info.isDelta     = (_wcsicmp(ext.c_str(), L".delta") == 0 ||
                           _wcsicmp(ext.c_str(), L".ssdp") == 0);

        // Compute checksum for integrity metadata
        try {
            std::vector<uint8_t> digest;
            ShadowStrike::Utils::HashUtils::Error hashErr;
            if (ShadowStrike::Utils::HashUtils::ComputeFile(
                    ShadowStrike::Utils::HashUtils::Algorithm::SHA256,
                    entry.path().wstring(),
                    digest,
                    &hashErr))
            {
                info.checksum = ShadowStrike::Utils::HashUtils::ToHexLower(digest);
            } else {
                SS_LOG_WARN(kLogCategory,
                    L"Failed to compute SHA-256 for %s (win32=%lu, nt=0x%08X)",
                    entry.path().wstring().c_str(),
                    static_cast<unsigned long>(hashErr.win32),
                    static_cast<unsigned int>(hashErr.ntstatus));
            }
        } catch (...) {
            SS_LOG_WARN(kLogCategory, L"Failed to compute hash for: %s",
                entry.path().wstring().c_str());
        }

        // Check for accompanying .manifest with version info
        auto manifestPath = entry.path();
        manifestPath.replace_extension(L".manifest");
        if (fs::exists(manifestPath, ec) && !ec) {
            auto manifestSize = fs::file_size(manifestPath, ec);
            if (!ec && manifestSize > 0 && manifestSize < kMaxManifestSize) {
                std::ifstream mf(manifestPath, std::ios::binary);
                if (mf) {
                    std::string content(static_cast<size_t>(manifestSize), '\0');
                    mf.read(content.data(), static_cast<std::streamsize>(manifestSize));
                    // Simple key=value parsing for version and mandatory flag
                    if (auto pos = content.find("version="); pos != std::string::npos) {
                        auto start = pos + 8;
                        auto end   = content.find('\n', start);
                        if (end == std::string::npos) end = content.size();
                        info.version = content.substr(start, end - start);
                        // Trim CR
                        if (!info.version.empty() && info.version.back() == '\r')
                            info.version.pop_back();
                    }
                    if (content.find("mandatory=true") != std::string::npos)
                        info.isMandatory = true;
                }
            }
        }

        packages.push_back(std::move(info));
        SS_LOG_DEBUG(kLogCategory, L"Found package: %hs (%.2f MB, delta=%d)",
            packages.back().packageId.c_str(),
            static_cast<double>(packages.back().size) / (1024.0 * 1024.0),
            packages.back().isDelta ? 1 : 0);
    }

    SS_LOG_INFO(kLogCategory, L"QueryAvailablePackages: found %zu packages in staging dir",
        packages.size());
    return packages;
}

TransportResult LocalFolderTransport::FetchPackage(
    std::string_view url,
    const fs::path& destination,
    TransportProgressCallback progress)
{
    m_impl->cancelled.store(false, std::memory_order_release);

    TransportResult result;
    const auto startTime = std::chrono::steady_clock::now();

    // Resolve source path
    fs::path sourcePath;
    {
        std::shared_lock lock(m_impl->mtx);
        sourcePath = fs::path(std::string(url));

        // If url is not absolute, resolve relative to staging dir
        if (!sourcePath.is_absolute()) {
            sourcePath = m_impl->stagingDir / sourcePath;
        }
    }

    SS_LOG_INFO(kLogCategory, L"FetchPackage: %s -> %s",
        sourcePath.wstring().c_str(), destination.wstring().c_str());

    // Validate source
    std::error_code ec;
    if (!fs::exists(sourcePath, ec) || ec) {
        result.errorMessage = "Source file not found: " + sourcePath.string();
        result.errorCode    = ERROR_FILE_NOT_FOUND;
        SS_LOG_ERROR(kLogCategory, L"Source not found: %s", sourcePath.wstring().c_str());
        return result;
    }

    const auto totalSize = fs::file_size(sourcePath, ec);
    if (ec || totalSize == 0) {
        result.errorMessage = "Cannot read source file size";
        result.errorCode    = ERROR_READ_FAULT;
        SS_LOG_ERROR(kLogCategory, L"Cannot read source size: %s", sourcePath.wstring().c_str());
        return result;
    }

    // Ensure destination directory exists
    auto destDir = destination.parent_path();
    if (!destDir.empty()) {
        fs::create_directories(destDir, ec);
        if (ec) {
            result.errorMessage = "Cannot create destination directory: " + ec.message();
            result.errorCode    = ERROR_PATH_NOT_FOUND;
            SS_LOG_ERROR(kLogCategory, L"Cannot create dest dir: %hs", ec.message().c_str());
            return result;
        }
    }

    // Open source and destination
    std::ifstream src(sourcePath, std::ios::binary);
    if (!src) {
        result.errorMessage = "Cannot open source file";
        result.errorCode    = ERROR_OPEN_FAILED;
        SS_LOG_ERROR(kLogCategory, L"Cannot open source: %s", sourcePath.wstring().c_str());
        return result;
    }

    std::ofstream dst(destination, std::ios::binary | std::ios::trunc);
    if (!dst) {
        result.errorMessage = "Cannot open destination file";
        result.errorCode    = ERROR_OPEN_FAILED;
        SS_LOG_ERROR(kLogCategory, L"Cannot open destination: %s", destination.wstring().c_str());
        return result;
    }

    // Copy with progress reporting
    auto buffer = std::make_unique<char[]>(kCopyBufferSize);
    uint64_t bytesCopied = 0;
    auto lastProgressTime = std::chrono::steady_clock::now();

    while (src && dst) {
        // Check cancellation
        if (m_impl->cancelled.load(std::memory_order_acquire)) {
            dst.close();
            fs::remove(destination, ec);
            result.errorMessage = "Fetch cancelled by user";
            result.errorCode    = ERROR_CANCELLED;
            SS_LOG_INFO(kLogCategory, L"FetchPackage cancelled after %llu bytes", bytesCopied);
            return result;
        }

        src.read(buffer.get(), kCopyBufferSize);
        const auto bytesRead = src.gcount();
        if (bytesRead <= 0) break;

        dst.write(buffer.get(), bytesRead);
        if (!dst) {
            result.errorMessage = "Write error to destination";
            result.errorCode    = ERROR_WRITE_FAULT;
            dst.close();
            fs::remove(destination, ec);
            SS_LOG_ERROR(kLogCategory, L"Write error after %llu bytes", bytesCopied);
            return result;
        }

        bytesCopied += static_cast<uint64_t>(bytesRead);

        // Report progress (throttled to ~100ms intervals)
        if (progress) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastProgressTime).count();
            if (elapsed >= 100 || bytesCopied >= totalSize) {
                lastProgressTime = now;
                TransportProgress prog;
                prog.bytesTransferred = bytesCopied;
                prog.totalBytes       = totalSize;
                prog.progressPercent  = static_cast<uint8_t>(
                    totalSize > 0 ? (bytesCopied * 100 / totalSize) : 0);

                auto totalElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - startTime).count();
                if (totalElapsed > 0) {
                    prog.speedBps = static_cast<uint64_t>(
                        bytesCopied * 1000ULL / static_cast<uint64_t>(totalElapsed));
                }
                if (prog.speedBps > 0 && bytesCopied < totalSize) {
                    prog.etaSeconds = static_cast<uint32_t>(
                        (totalSize - bytesCopied) / prog.speedBps);
                }

                try { progress(prog); } catch (...) {}
            }
        }
    }

    dst.close();
    src.close();

    // Verify copied size matches
    auto destSize = fs::file_size(destination, ec);
    if (ec || destSize != totalSize) {
        fs::remove(destination, ec);
        result.errorMessage = "Size mismatch after copy";
        result.errorCode    = ERROR_FILE_CORRUPT;
        SS_LOG_ERROR(kLogCategory, L"Size mismatch: expected %llu, got %llu",
            totalSize, destSize);
        return result;
    }

    auto endTime = std::chrono::steady_clock::now();
    result.success          = true;
    result.localPath        = destination;
    result.bytesTransferred = bytesCopied;
    result.durationMs       = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());

    SS_LOG_INFO(kLogCategory, L"FetchPackage complete: %llu bytes in %u ms",
        bytesCopied, result.durationMs);
    return result;
}

void LocalFolderTransport::CancelFetch() {
    m_impl->cancelled.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"Fetch cancellation requested");
}

bool LocalFolderTransport::IsCancelled() const noexcept {
    return m_impl->cancelled.load(std::memory_order_acquire);
}

// ============================================================================
// Additional Methods
// ============================================================================

void LocalFolderTransport::SetStagingDirectory(const fs::path& dir) {
    std::unique_lock lock(m_impl->mtx);
    m_impl->stagingDir = dir;
    SS_LOG_INFO(kLogCategory, L"Staging directory updated: %s", dir.wstring().c_str());
}

const fs::path& LocalFolderTransport::GetStagingDirectory() const noexcept {
    // No lock needed — caller should not race with SetStagingDirectory
    return m_impl->stagingDir;
}

} // namespace ShadowStrike::Update
