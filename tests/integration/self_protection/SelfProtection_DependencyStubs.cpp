/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Focused integration-test stubs for optional cross-subsystem services that the
 * self-protection stack can integrate with but that are outside this harness's
 * scope.
 *
 * The SelfProtection stack under test remains real:
 *   - CryptoManager
 *   - CertificateValidator
 *   - TamperProtection
 *   - SelfDefense
 *
 * These seams intentionally report "unavailable" so the production modules
 * follow their documented best-effort paths for telemetry, alerting, kernel IPC,
 * and signature side services without pulling unrelated dependency trees into
 * this folder-scoped build.
 */

#include "pch.h"

#include "../../../src/Shared_modules/Communication/AlertSystem.hpp"
#include "../../../src/Shared_modules/Communication/TelemetryCollector.hpp"
#include "../../../src/Shared_modules/Communication/IPCManager.hpp"
#include "../../../src/Shared_modules/SelfProtection/DigitalSignatureValidator.hpp"

namespace ShadowStrike {
namespace Communication {

class AlertSystemImpl {};
class TelemetryCollectorImpl {};
class FilterConnection {};
class ThreatIntelPusher {};
class IPCManagerImpl {};

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
    : m_impl(std::make_unique<AlertSystemImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

AlertSystem::~AlertSystem() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool AlertSystem::IsInitialized() const noexcept {
    return false;
}

std::string AlertSystem::RaiseAlert(
    AlertSeverity,
    AlertType,
    const std::string&,
    const std::string&,
    const std::string&) {
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
    : m_impl(std::make_unique<TelemetryCollectorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

TelemetryCollector::~TelemetryCollector() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool TelemetryCollector::IsInitialized() const noexcept {
    return false;
}

void TelemetryCollector::RecordCustom(
    const std::string&,
    const std::map<std::string, std::string>&) {
}

IPCManager& IPCManager::Instance() noexcept {
    static IPCManager instance;
    return instance;
}

bool IPCManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

IPCManager::IPCManager()
    : m_impl(std::make_unique<IPCManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
    m_status.store(IPCStatus::Uninitialized, std::memory_order_release);
}

IPCManager::~IPCManager() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool IPCManager::IsFilterPortConnected() const noexcept {
    return false;
}

bool IPCManager::SendToKernel(
    const void*,
    size_t,
    void*,
    size_t*,
    uint32_t) {
    return false;
}

void IPCManager::RegisterGenericHandler(GenericMessageCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_genericHandler = std::move(handler);
}

}  // namespace Communication

namespace Security {

class DigitalSignatureValidatorImpl {};

std::atomic<bool> DigitalSignatureValidator::s_instanceCreated{false};

DigitalSignatureValidator& DigitalSignatureValidator::Instance() noexcept {
    static DigitalSignatureValidator instance;
    return instance;
}

bool DigitalSignatureValidator::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

DigitalSignatureValidator::DigitalSignatureValidator()
    : m_impl(std::make_unique<DigitalSignatureValidatorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

DigitalSignatureValidator::~DigitalSignatureValidator() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool DigitalSignatureValidator::IsInitialized() const noexcept {
    return false;
}

SignatureInfo DigitalSignatureValidator::VerifyFile(const std::wstring&) {
    return {};
}

}  // namespace Security
}  // namespace ShadowStrike
