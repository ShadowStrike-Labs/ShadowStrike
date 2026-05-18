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
/**
 * ============================================================================
 * ShadowStrike NGAV - UPDATE TRANSPORT ABSTRACTION
 * ============================================================================
 *
 * @file IUpdateTransport.hpp
 * @brief Abstract transport interface for update package delivery.
 *
 * Decouples update logic from delivery mechanism. Implementations:
 *   - LocalFolderTransport: Reads packages from local/network staging directory
 *   - (Future) HttpTransport: Downloads from update.shadowstrike.io CDN
 *   - (Future) P2PTransport: Peer-to-peer mesh for enterprise LAN distribution
 *
 * DESIGN PRINCIPLES:
 *   - Pure virtual interface — no implementation details in header
 *   - Progress reporting via callback for UI integration
 *   - Cancellation support for responsive user experience
 *   - Resume support for large downloads over unreliable connections
 *   - All operations are synchronous; callers run them on background threads
 *
 * SECURITY:
 *   - Transport only delivers bytes — verification is caller's responsibility
 *   - No trust placed in metadata from transport (sizes, hashes re-verified)
 *   - TLS/certificate pinning is transport implementation concern
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>
#include <filesystem>
#include <chrono>
#include <memory>

namespace ShadowStrike::Update {

namespace fs = std::filesystem;

// ============================================================================
// TRANSPORT DATA TYPES
// ============================================================================

/**
 * @brief Progress information for an ongoing transport operation.
 */
struct TransportProgress {
    uint64_t bytesTransferred = 0;
    uint64_t totalBytes       = 0;
    uint8_t  progressPercent  = 0;
    uint64_t speedBps         = 0;
    uint32_t etaSeconds       = 0;
};

/**
 * @brief Result of a transport fetch operation.
 */
struct TransportResult {
    bool        success      = false;
    fs::path    localPath;             ///< Where the fetched file was placed
    uint64_t    bytesTransferred = 0;
    uint32_t    durationMs       = 0;
    std::string errorMessage;
    int         errorCode        = 0;
};

/**
 * @brief Metadata about a remote package available for download.
 *
 * @note `checksum` is lowercase hexadecimal SHA-256 of the on-the-wire
 *       package bytes (64 hex characters). It is treated as opaque by
 *       the transport and re-verified by the caller after fetch; the
 *       transport never trusts it.
 */
struct RemotePackageInfo {
    std::string packageId;
    std::string version;
    uint64_t    size       = 0;
    std::string checksum;          ///< Lowercase SHA-256 hex (64 chars)
    std::string downloadUrl;
    bool        isDelta    = false;
    bool        isMandatory = false;
};

/// Progress callback for transport operations.
using TransportProgressCallback = std::function<void(const TransportProgress&)>;

// ============================================================================
// ABSTRACT TRANSPORT INTERFACE
// ============================================================================

/**
 * @brief Abstract interface for update package delivery.
 *
 * Implementations handle the actual data transfer mechanism while the
 * Update module handles verification, patching, and rollback.
 *
 * Thread safety:
 *   - All methods may be invoked concurrently from different threads.
 *   - A single FetchPackage call is NOT reentrant and must not be invoked
 *     concurrently from multiple threads against the same instance.
 *   - CancelFetch may be called from any thread at any time, including
 *     while FetchPackage is in progress.
 *   - Configuration mutators (e.g. SetStagingDirectory on
 *     LocalFolderTransport) may be invoked concurrently with read
 *     operations; implementations are responsible for internal
 *     synchronisation.
 *
 * Trust model:
 *   - The transport surface is treated as untrusted. Size, checksum and
 *     other metadata returned here MUST be re-verified by the caller
 *     against authenticated package metadata before the bytes are used.
 */
class IUpdateTransport {
public:
    virtual ~IUpdateTransport() = default;

    // Non-copyable, non-movable
    IUpdateTransport(const IUpdateTransport&) = delete;
    IUpdateTransport& operator=(const IUpdateTransport&) = delete;
    IUpdateTransport(IUpdateTransport&&) = delete;
    IUpdateTransport& operator=(IUpdateTransport&&) = delete;

    /**
     * @brief Check if the transport is available and operational.
     * @return true if transport can serve requests.
     */
    [[nodiscard]] virtual bool IsAvailable() const = 0;

    /**
     * @brief Get human-readable transport name for logging.
     */
    [[nodiscard]] virtual std::string_view GetName() const noexcept = 0;

    /**
     * @brief Query available packages from the update source.
     * @param channel Update channel (stable/beta/canary/enterprise).
     * @return List of available packages, empty on failure.
     */
    [[nodiscard]] virtual std::vector<RemotePackageInfo> QueryAvailablePackages(
        std::string_view channel) = 0;

    /**
     * @brief Fetch a package to a local destination.
     * @param url         Source URL or path identifier.
     * @param destination Local filesystem path to write the package.
     * @param progress    Optional progress callback.
     * @return Result of the fetch operation.
     */
    [[nodiscard]] virtual TransportResult FetchPackage(
        std::string_view url,
        const fs::path& destination,
        TransportProgressCallback progress = nullptr) = 0;

    /**
     * @brief Cancel any in-progress fetch operation.
     *
     * After cancellation, the current FetchPackage call returns with
     * success=false. Safe to call from any thread.
     */
    virtual void CancelFetch() = 0;

    /**
     * @brief Check if a cancel has been requested.
     */
    [[nodiscard]] virtual bool IsCancelled() const noexcept = 0;

protected:
    IUpdateTransport() = default;
};

// ============================================================================
// LOCAL FOLDER TRANSPORT (Default — for testing, air-gapped, and offline use)
// ============================================================================

/**
 * @brief Transport that reads packages from a local or network directory.
 *
 * Scans the configured staging directory for .pkg / .delta / .manifest files.
 * Used for:
 *   - Offline/air-gapped deployments
 *   - Enterprise network share distribution
 *   - Development and testing
 *   - Manual package deployment
 */
class LocalFolderTransport final : public IUpdateTransport {
public:
    /**
     * @brief Construct with staging directory path.
     * @param stagingDir Directory to scan for update packages.
     */
    explicit LocalFolderTransport(fs::path stagingDir);
    ~LocalFolderTransport() override;

    [[nodiscard]] bool IsAvailable() const override;
    [[nodiscard]] std::string_view GetName() const noexcept override;

    [[nodiscard]] std::vector<RemotePackageInfo> QueryAvailablePackages(
        std::string_view channel) override;

    [[nodiscard]] TransportResult FetchPackage(
        std::string_view url,
        const fs::path& destination,
        TransportProgressCallback progress = nullptr) override;

    void CancelFetch() override;
    [[nodiscard]] bool IsCancelled() const noexcept override;

    /**
     * @brief Set or change the staging directory.
     */
    void SetStagingDirectory(const fs::path& dir);

    /**
     * @brief Get current staging directory path.
     *
     * Returns a copy under internal lock so the result is safe to use
     * even if another thread races with SetStagingDirectory.
     */
    [[nodiscard]] fs::path GetStagingDirectory() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Update
