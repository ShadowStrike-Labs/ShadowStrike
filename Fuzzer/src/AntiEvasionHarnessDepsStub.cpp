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
/*
 * Fuzzer-only dependency seam for the anti-evasion harness.
 *
 * The harness exercises the public anti-evasion detector interfaces without
 * pulling their full production implementations and dependencies into the
 * standalone fuzz-target compile. These definitions provide narrow, safe,
 * deterministic behavior for only the symbols the harness needs.
 */

#include "PhantomCore/AntiEvasion/PackerDetector.hpp"
#include "PhantomCore/AntiEvasion/VMEvasionDetector.hpp"

#include <memory>
#include <utility>

namespace ShadowStrike::AntiEvasion {

class PackerDetector::Impl {
public:
    bool initialized = false;
};

PackerDetector::PackerDetector() noexcept
    : m_impl(std::make_unique<Impl>())
{
}

PackerDetector::PackerDetector(
    std::shared_ptr<SignatureStore::SignatureStore>) noexcept
    : m_impl(std::make_unique<Impl>())
{
}

PackerDetector::PackerDetector(
    std::shared_ptr<SignatureStore::SignatureStore>,
    std::shared_ptr<PatternStore::PatternStore>,
    std::shared_ptr<HashStore::HashStore>) noexcept
    : m_impl(std::make_unique<Impl>())
{
}

PackerDetector::~PackerDetector() = default;

PackerDetector::PackerDetector(PackerDetector&&) noexcept = default;
PackerDetector& PackerDetector::operator=(PackerDetector&&) noexcept = default;

bool PackerDetector::Initialize(PackerError* err) noexcept {
    if (err != nullptr) {
        err->Clear();
    }

    m_impl->initialized = true;
    return true;
}

void PackerDetector::Shutdown() noexcept {
    m_impl->initialized = false;
}

bool PackerDetector::IsInitialized() const noexcept {
    return m_impl != nullptr && m_impl->initialized;
}

PackingInfo PackerDetector::AnalyzeBuffer(
    const uint8_t*,
    size_t size,
    const PackerAnalysisConfig& config,
    PackerError* err) noexcept
{
    if (err != nullptr) {
        err->Clear();
    }

    PackingInfo result{};
    result.fileSize = size;
    result.config = config;
    result.analysisComplete = true;
    return result;
}

struct VMEvasionDetector::Impl {};

VMEvasionDetector::VMEvasionDetector(
    std::shared_ptr<ThreatIntel::ThreatIntelStore>,
    const VMDetectionConfig&)
    : m_impl(std::make_unique<Impl>())
{
    Initialize();
}

VMEvasionDetector::VMEvasionDetector(
    std::shared_ptr<ThreatIntel::ThreatIntelStore>,
    std::shared_ptr<SignatureStore::SignatureStore>,
    const VMDetectionConfig&)
    : m_impl(std::make_unique<Impl>())
{
    Initialize();
}

VMEvasionDetector::~VMEvasionDetector() = default;

VMEvasionDetector::VMEvasionDetector(VMEvasionDetector&&) noexcept = default;
VMEvasionDetector& VMEvasionDetector::operator=(VMEvasionDetector&&) noexcept = default;

void VMEvasionDetector::Initialize() {
}

bool VMEvasionDetector::AnalyzeCodeBuffer(
    std::span<const uint8_t> buffer,
    uint64_t,
    bool,
    CodeAnalysisResult& result,
    const ExtendedAnalysisConfig&)
{
    result = CodeAnalysisResult{};
    result.totalInstructionsAnalyzed = buffer.empty() ? 0 : 1;
    return !buffer.empty();
}

}  // namespace ShadowStrike::AntiEvasion
