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
 * Fuzzer-only dependency seam for the AI feature extraction harness.
 *
 * The fuzzer target intentionally avoids linking the full PhantomCortex
 * implementation tree. These narrow definitions satisfy the harness link
 * surface while keeping execution deterministic and side-effect free.
 */

#include "PhantomCore/AI/CortexTypes.hpp"
#include "PhantomCore/AI/FeatureExtractor.hpp"

#include <optional>
#include <span>
#include <vector>

namespace ShadowStrike::AI {

struct FeatureExtractor::Impl {};

FeatureExtractor& FeatureExtractor::Instance() noexcept {
    static FeatureExtractor instance;
    return instance;
}

bool FeatureExtractor::Initialize() noexcept {
    return true;
}

std::optional<std::vector<float>> FeatureExtractor::ExtractPEFeatures(
    std::span<const uint8_t>) noexcept
{
    return std::vector<float>(CortexConstants::STATIC_FEATURE_COUNT, 0.0f);
}

std::optional<std::vector<float>> FeatureExtractor::ExtractBehavioralFeatures(
    std::span<const APICallRecord>) noexcept
{
    return std::vector<float>(CortexConstants::BEHAVIORAL_FEATURE_COUNT, 0.0f);
}

std::optional<std::vector<float>> FeatureExtractor::ExtractMemoryFeatures(
    const MemoryRegionInfo&) noexcept
{
    return std::vector<float>(CortexConstants::MEMORY_FEATURE_COUNT, 0.0f);
}

std::optional<std::vector<float>> FeatureExtractor::ExtractNetworkFeatures(
    const NetworkFlowInfo&) noexcept
{
    return std::vector<float>(CortexConstants::NETWORK_FEATURE_COUNT, 0.0f);
}

std::optional<std::vector<float>> FeatureExtractor::ExtractEmulationFeatures(
    std::span<const EmulationEvent>) noexcept
{
    return std::vector<float>(CortexConstants::EMULATION_FEATURE_COUNT, 0.0f);
}

}  // namespace ShadowStrike::AI
