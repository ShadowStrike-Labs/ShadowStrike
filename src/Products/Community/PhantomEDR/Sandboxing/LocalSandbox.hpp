/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/Sandboxing/ISandboxBackend.hpp"

#include <memory>

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

class LocalSandboxImpl;

/// Lightweight local sandbox using Windows Job Objects and restricted tokens.
/// Executes suspicious files in a heavily constrained process environment,
/// monitors filesystem/registry/network activity via ETW, then collects
/// behavioral artifacts for the SandboxAnalyzer.
class LocalSandbox final : public ISandboxBackend {
public:
    [[nodiscard]] static LocalSandbox& Instance();

    [[nodiscard]] bool Initialize() override;
    void Shutdown() override;
    [[nodiscard]] bool IsInitialized() const noexcept override;

    [[nodiscard]] std::string Submit(const SandboxSubmission& submission) override;
    [[nodiscard]] bool Cancel(std::string_view submissionId) override;
    [[nodiscard]] std::optional<DetonationResult> GetResult(std::string_view submissionId) const override;
    [[nodiscard]] std::vector<DetonationResult> GetResultsByHash(std::string_view sha256) const override;

    [[nodiscard]] std::string_view BackendName() const noexcept override;
    [[nodiscard]] uint32_t MaxConcurrent() const noexcept override;
    [[nodiscard]] uint32_t ActiveCount() const noexcept override;

private:
    LocalSandbox();
    ~LocalSandbox() override;
    LocalSandbox(const LocalSandbox&) = delete;
    LocalSandbox& operator=(const LocalSandbox&) = delete;
    LocalSandbox(LocalSandbox&&) = delete;
    LocalSandbox& operator=(LocalSandbox&&) = delete;
    std::unique_ptr<LocalSandboxImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
