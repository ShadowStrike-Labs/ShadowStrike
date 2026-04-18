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
 * Fuzzer-only dependency seam for script-scanner harnessing.
 *
 * The script scanner harness intentionally avoids linking the production script
 * scanner implementations and their optional communication / AMSI wiring. This
 * file provides narrow, deterministic definitions for only the symbols the
 * harness needs so the target remains hermetic and linker-complete.
 */

// Communication stubs only — script scanner symbols are in ScanEngineHarnessDepsStub.
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/Communication/IPCManager.hpp"
#include "PhantomCore/Communication/TelemetryCollector.hpp"
#include "PhantomCore/Scripts/JavaScriptScanner.hpp"
#include "PhantomCore/Scripts/PowerShellScanner.hpp"
#include "PhantomCore/Scripts/PythonScriptScanner.hpp"
#include "PhantomCore/Scripts/VBScriptScanner.hpp"

#include <atomic>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace {
}  // namespace

namespace ShadowStrike::Communication {

class AlertSystemImpl {};
class TelemetryCollectorImpl {};
class IPCManagerImpl {};
class FilterConnection {};
class ThreatIntelPusher {};

std::atomic<bool> AlertSystem::s_instanceCreated{false};
std::atomic<bool> TelemetryCollector::s_instanceCreated{false};
std::atomic<bool> IPCManager::s_instanceCreated{false};

AlertSystem& AlertSystem::Instance() noexcept {
    static AlertSystem instance;
    return instance;
}

bool AlertSystem::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

AlertSystem::AlertSystem()
    : m_impl(std::make_unique<AlertSystemImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

AlertSystem::~AlertSystem() = default;

std::string AlertSystem::RaiseAlert(const Alert&) {
    return {};
}

std::string AlertSystem::RaiseAlert(
    AlertSeverity,
    AlertType,
    const std::string&,
    const std::string&,
    const std::string&)
{
    return {};
}

TelemetryCollector& TelemetryCollector::Instance() noexcept {
    static TelemetryCollector instance;
    return instance;
}

bool TelemetryCollector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

TelemetryCollector::TelemetryCollector()
    : m_impl(std::make_unique<TelemetryCollectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

TelemetryCollector::~TelemetryCollector() = default;

void TelemetryCollector::RecordCustom(
    const std::string&,
    const std::map<std::string, std::string>&)
{
}

IPCManager& IPCManager::Instance() noexcept {
    static IPCManager instance;
    return instance;
}

bool IPCManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

IPCManager::IPCManager()
    : m_impl(std::make_unique<IPCManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

IPCManager::~IPCManager() = default;

bool IPCManager::IsFilterPortConnected() const noexcept {
    return false;
}

bool IPCManager::SendToKernel(
    const void*,
    size_t,
    void*,
    size_t* replySize,
    uint32_t)
{
    if (replySize != nullptr) {
        *replySize = 0;
    }
    return false;
}

bool IPCManager::ReplyToKernel(
    uint64_t,
    const SHADOWSTRIKE_SCAN_VERDICT_REPLY&)
{
    return false;
}

}  // namespace ShadowStrike::Communication

// Script scanner symbols (AMSIIntegration, PowerShellScanner, JavaScriptScanner,
// PythonScriptScanner, VBScriptScanner) are already provided by
// ScanEngineHarnessDepsStub.cpp — do NOT duplicate here.
// Only the *Memory / *Source scan overloads used by the harness but missing from
// ScanEngineHarnessDepsStub (which only stubs the *File variants) are added below.

namespace ShadowStrike::Scripts {

ScanResult PowerShellScanner::scanMemory(
    std::span<const char>,
    std::string_view,
    uint32_t)
{
    return {};
}

JSScanResult JavaScriptScanner::ScanMemory(
    std::span<const char>,
    std::string_view,
    uint32_t)
{
    return {};
}

PythonScanResult PythonScriptScanner::ScanSource(
    std::string_view,
    const std::string&)
{
    return {};
}

VBSScanResult VBScriptScanner::ScanSource(
    std::string_view,
    const std::string&)
{
    return {};
}

}  // namespace ShadowStrike::Scripts
