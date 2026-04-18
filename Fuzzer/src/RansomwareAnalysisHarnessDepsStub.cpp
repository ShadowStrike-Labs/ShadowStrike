// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * Fuzzer-only dependency seam for the ransomware analysis harness.
 *
 * BehaviorHarnessDepsStub.cpp already provides the shared RansomwareDetector
 * singleton seam. This file adds only the remaining entropy helpers and the
 * family-specific detector seams required by RansomwareAnalysisHarness.
 */

#include "PhantomCore\RansomwareProtection\RansomwareDetector.hpp"
#include "PhantomCore\RansomwareProtection\WannaCryDetector.hpp"
#define DetectionConfidence LockyDetectionConfidence
#include "PhantomCore\RansomwareProtection\LockyDetector.hpp"
#undef DetectionConfidence

namespace ShadowStrike::Ransomware {

class WannaCryDetectorImpl {};
class LockyDetector::LockyDetectorImpl {};

std::atomic<bool> WannaCryDetector::s_instanceCreated{false};
std::atomic<bool> LockyDetector::s_instanceCreated{false};

bool RansomwareDetector::Initialize(const RansomwareDetectorConfiguration&) {
    return true;
}

double RansomwareDetector::CalculateEntropy(std::span<const uint8_t>) {
    return 0.0;
}

EntropyResult RansomwareDetector::AnalyzeEntropy(std::span<const uint8_t>) {
    return {};
}

bool RansomwareDetector::IsEncrypted(std::span<const uint8_t>) {
    return false;
}

WannaCryDetector& WannaCryDetector::Instance() noexcept {
    static WannaCryDetector instance;
    return instance;
}

bool WannaCryDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

WannaCryDetector::WannaCryDetector()
    : m_impl(std::make_unique<WannaCryDetectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

WannaCryDetector::~WannaCryDetector() = default;

bool WannaCryDetector::Initialize(const WannaCryDetectorConfiguration&) {
    return true;
}

bool WannaCryDetector::IsKillSwitchDomain(std::string_view) const {
    return false;
}

bool WannaCryDetector::IsWannaCryArtifact(std::wstring_view) const {
    return false;
}

bool WannaCryDetector::AnalyzeSMBTraffic(
    std::span<const uint8_t>,
    std::string_view,
    std::string_view)
{
    return false;
}

LockyDetector& LockyDetector::Instance() noexcept {
    static LockyDetector instance;
    return instance;
}

bool LockyDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

LockyDetector::LockyDetector()
    : m_impl(std::make_unique<LockyDetectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

LockyDetector::~LockyDetector() = default;

bool LockyDetector::Initialize(const LockyDetectorConfiguration&) {
    return true;
}

bool LockyDetector::IsLockyExtension(std::wstring_view) const {
    return false;
}

bool LockyDetector::IsLockyRansomNote(std::wstring_view) const {
    return false;
}

bool LockyDetector::IsLockyC2Domain(std::string_view) const {
    return false;
}

}  // namespace ShadowStrike::Ransomware
