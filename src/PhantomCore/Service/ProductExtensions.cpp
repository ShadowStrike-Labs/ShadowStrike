/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ProductExtensions.cpp
 * @brief Implementation of the product extension registration hook.
 */

#include "pch.h"
#include "ProductExtensions.hpp"

#include "../Utils/Logger.hpp"

namespace ShadowStrike {
namespace Service {

namespace {
constexpr const wchar_t* kLogCategory = L"ProductExtensions";
constexpr std::size_t kMaxProductNameLength = 64;
}  // namespace

ProductExtensions& ProductExtensions::Instance() noexcept {
    static ProductExtensions s_instance;
    return s_instance;
}

void ProductExtensions::SetProductEntry(std::string_view productName,
                                        InitializeFn initializeAndStart,
                                        ShutdownFn shutdown) noexcept {
    // Defensive copies; callers are allowed to pass temporary lambdas.
    try {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_registered.load(std::memory_order_acquire)) {
            // Duplicate registration is almost certainly a build configuration
            // error: two product entry TUs linked into the same binary. We log
            // and refuse to overwrite so the first product wins deterministically.
            std::wstring existing(m_productName.begin(), m_productName.end());
            std::wstring attempted(productName.begin(), productName.end());
            SS_LOG_FATAL(kLogCategory,
                L"Duplicate product registration rejected: already have '%ls', attempted '%ls'",
                existing.c_str(), attempted.c_str());
            return;
        }

        if (!initializeAndStart || !shutdown) {
            SS_LOG_FATAL(kLogCategory,
                L"Product registration rejected: null lifecycle callback(s)");
            return;
        }

        // Truncate defensively. The product name is logged but never used for
        // file paths or security decisions, so this is just hygiene.
        std::string name(productName);
        if (name.size() > kMaxProductNameLength) {
            name.resize(kMaxProductNameLength);
        }

        m_productName = std::move(name);
        m_initStart = std::move(initializeAndStart);
        m_shutdown = std::move(shutdown);
        m_registered.store(true, std::memory_order_release);
    } catch (...) {
        // Static-init-time registration cannot safely propagate exceptions.
        // The logger itself may not yet be live; fail silent.
    }
}

bool ProductExtensions::InitializeProduct() noexcept {
    InitializeFn fn;
    std::string name;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_registered.load(std::memory_order_acquire)) {
            SS_LOG_INFO(kLogCategory,
                L"No product extension registered; PhantomCore running engine-only");
            return true;
        }
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(kLogCategory,
                L"Product extension already initialized; ignoring duplicate call");
            return true;
        }
        fn = m_initStart;
        name = m_productName;
    }

    SS_LOG_INFO(kLogCategory, L"Initializing product extension: %hs", name.c_str());

    bool ok = false;
    try {
        ok = fn();
    } catch (const std::exception& e) {
        SS_LOG_FATAL(kLogCategory,
            L"Product '%hs' threw during initialize: %hs", name.c_str(), e.what());
        return false;
    } catch (...) {
        SS_LOG_FATAL(kLogCategory,
            L"Product '%hs' threw unknown exception during initialize", name.c_str());
        return false;
    }

    if (!ok) {
        SS_LOG_ERROR(kLogCategory,
            L"Product '%hs' reported initialize failure", name.c_str());
        return false;
    }

    m_initialized.store(true, std::memory_order_release);
    SS_LOG_INFO(kLogCategory,
        L"Product extension '%hs' initialized successfully", name.c_str());
    return true;
}

void ProductExtensions::ShutdownProduct() noexcept {
    ShutdownFn fn;
    std::string name;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_registered.load(std::memory_order_acquire)) {
            return;  // Nothing to shut down.
        }
        if (!m_initialized.load(std::memory_order_acquire)) {
            // Registered but never initialized; nothing meaningful to do.
            return;
        }
        fn = m_shutdown;
        name = m_productName;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down product extension: %hs", name.c_str());

    try {
        fn();
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory,
            L"Product '%hs' threw during shutdown: %hs", name.c_str(), e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Product '%hs' threw unknown exception during shutdown", name.c_str());
    }

    m_initialized.store(false, std::memory_order_release);
}

bool ProductExtensions::HasProduct() const noexcept {
    return m_registered.load(std::memory_order_acquire);
}

std::string ProductExtensions::ProductName() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_productName;
}

bool ProductExtensions::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

}  // namespace Service
}  // namespace ShadowStrike
