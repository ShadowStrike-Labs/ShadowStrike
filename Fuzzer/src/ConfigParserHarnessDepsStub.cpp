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
 * Fuzzer-only dependency seam for configuration and policy parser harnessing.
 *
 * The config parser harness only needs lightweight configuration and policy
 * entry points. Linking the production managers would pull in database, sync,
 * and platform wiring that is outside this target. Provide deterministic
 * singleton and parser definitions here so the harness stays narrow.
 */

#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Config/PolicyManager.hpp"

#include <atomic>
#include <memory>
#include <optional>
#include <string>

namespace {

std::atomic<bool> g_configManagerInitialized{false};
std::atomic<bool> g_policyManagerInitialized{false};

}  // namespace

namespace ShadowStrike::Config {

class ConfigManagerImpl {};
class PolicyManagerImpl {};

std::atomic<bool> ConfigManager::s_instanceCreated{false};
std::atomic<bool> PolicyManager::s_instanceCreated{false};

ConfigManager& ConfigManager::Instance() noexcept {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ConfigManager::ConfigManager()
    : m_impl(std::make_unique<ConfigManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

ConfigManager::~ConfigManager() = default;

bool ConfigManager::Initialize(const ConfigManagerConfiguration&) {
    g_configManagerInitialized.store(true, std::memory_order_release);
    return true;
}

bool ConfigManager::Initialize(const std::wstring&) {
    g_configManagerInitialized.store(true, std::memory_order_release);
    return true;
}

void ConfigManager::Shutdown() {
    g_configManagerInitialized.store(false, std::memory_order_release);
}

bool ConfigManager::IsInitialized() const noexcept {
    return g_configManagerInitialized.load(std::memory_order_acquire);
}

void ConfigManager::ResetToDefaults(ConfigLayer) {
}

bool ConfigManager::ImportFromJson(const std::string&, ConfigLayer) {
    return true;
}

ConfigValue ParseConfigValue(const std::string&, ValueType expectedType) {
    switch (expectedType) {
    case ValueType::Boolean:
        return false;
    case ValueType::Integer:
        return int64_t{0};
    case ValueType::UInteger:
        return uint64_t{0};
    case ValueType::Float:
        return 0.0;
    case ValueType::String:
        return std::string{};
    case ValueType::WString:
        return std::wstring{};
    case ValueType::StringList:
        return std::vector<std::string>{};
    case ValueType::IntList:
        return std::vector<int64_t>{};
    case ValueType::Map:
        return std::map<std::string, std::string>{};
    case ValueType::Binary:
    case ValueType::Null:
    case ValueType::Unknown:
    default:
        return std::monostate{};
    }
}

PolicyManager& PolicyManager::Instance() noexcept {
    static PolicyManager instance;
    return instance;
}

bool PolicyManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

PolicyManager::PolicyManager()
    : m_impl(std::make_unique<PolicyManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

PolicyManager::~PolicyManager() = default;

bool PolicyManager::Initialize(const PolicyManagerConfiguration&) {
    g_policyManagerInitialized.store(true, std::memory_order_release);
    return true;
}

void PolicyManager::Shutdown() {
    g_policyManagerInitialized.store(false, std::memory_order_release);
}

bool PolicyManager::IsInitialized() const noexcept {
    return g_policyManagerInitialized.load(std::memory_order_acquire);
}

std::optional<Policy> ParsePolicyFromJson(const std::string&) {
    return Policy{};
}

std::optional<Policy> ParsePolicyFromXml(const std::string&) {
    return Policy{};
}

}  // namespace ShadowStrike::Config
