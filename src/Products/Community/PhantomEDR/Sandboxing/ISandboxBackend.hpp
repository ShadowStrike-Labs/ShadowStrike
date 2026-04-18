/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/Sandboxing/SandboxTypes.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

/// Interface for sandbox backends.
/// Community: LocalSandbox (Windows Job Object restricted token).
/// Pro/Enterprise: CloudSandbox (VM detonation service).
class ISandboxBackend {
public:
    virtual ~ISandboxBackend() = default;

    [[nodiscard]] virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    [[nodiscard]] virtual bool IsInitialized() const noexcept = 0;

    /// Submit a file for detonation. Returns submission ID or empty on failure.
    [[nodiscard]] virtual std::string Submit(const SandboxSubmission& submission) = 0;

    /// Cancel a pending/running detonation.
    [[nodiscard]] virtual bool Cancel(std::string_view submissionId) = 0;

    /// Get the current result for a submission.
    [[nodiscard]] virtual std::optional<DetonationResult> GetResult(std::string_view submissionId) const = 0;

    /// Get all results for a file hash.
    [[nodiscard]] virtual std::vector<DetonationResult> GetResultsByHash(std::string_view sha256) const = 0;

    /// Get the backend name (e.g. "LocalSandbox", "CloudSandbox").
    [[nodiscard]] virtual std::string_view BackendName() const noexcept = 0;

    /// Max concurrent detonations this backend supports.
    [[nodiscard]] virtual uint32_t MaxConcurrent() const noexcept = 0;

    /// Current number of active detonations.
    [[nodiscard]] virtual uint32_t ActiveCount() const noexcept = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
