/**
 * @file FilterPortGate.cpp
 * @brief Implementation of the process-wide minifilter connect gate.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#include "pch.h"
#include "FilterPortGate.hpp"

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <fltUser.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace ShadowStrike::Communication::FilterPortGate {

namespace {

/// Minimum spacing between two connects.
///
/// ConnectNotify holds ClientPortLock exclusive and drains any queued messages
/// for the new client, so the driver needs a moment afterwards to release the
/// lock and let blocked callbacks through. This gap is what turns a pile-up into
/// an orderly sequence; it is short enough to be invisible during startup (a
/// handful of connections) and long enough that the I/O path is never starved.
constexpr auto kMinConnectSpacing = std::chrono::milliseconds(120);

std::mutex                                     g_gate;
std::chrono::steady_clock::time_point          g_lastConnect{};
std::atomic<unsigned long>                     g_connectCount{ 0 };

}  // namespace

HRESULT Connect(
    const std::wstring& portName,
    const void*         context,
    WORD                contextSize,
    HANDLE*             outPort,
    const char*         callerTag) noexcept
{
    if (outPort == nullptr) {
        return E_INVALIDARG;
    }

    std::lock_guard<std::mutex> lock(g_gate);

    // Space this connect from the previous one. Only ever waits when another
    // subsystem connected moments ago, which is exactly the pile-up case.
    if (g_lastConnect.time_since_epoch().count() != 0) {
        const auto elapsed = std::chrono::steady_clock::now() - g_lastConnect;
        if (elapsed < kMinConnectSpacing) {
            const auto remaining = kMinConnectSpacing - elapsed;
            Utils::Logger::Debug(
                "[FilterPortGate] Spacing connect from '{}' by {} ms",
                callerTag != nullptr ? callerTag : "unknown",
                std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count());
            std::this_thread::sleep_for(remaining);
        }
    }

    HANDLE hPort = nullptr;
    const HRESULT hr = ::FilterConnectCommunicationPort(
        portName.c_str(),
        0,
        context,
        contextSize,
        nullptr,
        &hPort);

    g_lastConnect = std::chrono::steady_clock::now();

    if (SUCCEEDED(hr)) {
        *outPort = hPort;
        const unsigned long n =
            g_connectCount.fetch_add(1, std::memory_order_relaxed) + 1;
        Utils::Logger::Info(
            "[FilterPortGate] '{}' connected to the sensor port (connection {} this session)",
            callerTag != nullptr ? callerTag : "unknown", n);
    } else {
        *outPort = nullptr;
        Utils::Logger::Warn(
            "[FilterPortGate] '{}' could not connect to the sensor port: 0x{:08X}",
            callerTag != nullptr ? callerTag : "unknown",
            static_cast<unsigned long>(hr));
    }

    return hr;
}

unsigned long ConnectCount() noexcept {
    return g_connectCount.load(std::memory_order_relaxed);
}

}  // namespace ShadowStrike::Communication::FilterPortGate
