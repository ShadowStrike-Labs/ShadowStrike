/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelIPCBridge.hpp — Receives emulation samples from PhantomSensor kernel driver
 *
 * Implements a named-pipe server on \\.\pipe\PhantomSensorEmulation that accepts
 * EmulationRequest messages from the kernel driver, dispatches them to the
 * registered emulation handler, and returns EmulationResponse results.
 *
 * Features:
 *   - Overlapped I/O for async named pipe operations
 *   - Up to 16 concurrent client connections
 *   - Rate limiting (100 requests/second)
 *   - Max sample size: 256 MB
 *   - Graceful shutdown with connection draining
 *   - Protocol versioning and magic validation
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>

// Forward declarations — Phantom types
namespace Phantom {
    enum class EmulationTarget : uint8_t;
    struct EmulationConfig;
}

namespace Phantom::Integration {

struct PhantomEmulationResult;

// ============================================================================
// IPC Protocol Constants
// ============================================================================

static constexpr uint32_t kRequestMagic           = 0x50484D54; // "PHMT"
static constexpr uint32_t kResponseMagic           = 0x50484D52; // "PHMR"
static constexpr uint32_t kProtocolVersion         = 1;
static constexpr uint32_t kMaxConcurrentSessions   = 16;
static constexpr uint64_t kMaxSampleSize           = 256ULL * 1024 * 1024; // 256 MB
static constexpr uint32_t kMaxRequestsPerSecond    = 100;
static constexpr uint32_t kDefaultTimeoutMs        = 30'000;
static constexpr uint32_t kMaxJsonDetailSize       = 16 * 1024 * 1024; // 16 MB

// ============================================================================
// Wire-format structures (packed, no padding)
// ============================================================================

#pragma pack(push, 1)

struct EmulationRequest {
    uint32_t magic;
    uint32_t version;
    uint32_t requestId;
    uint32_t sampleType;      // 0=PE, 1=Shellcode32, 2=Shellcode64, 3=Buffer
    uint64_t sampleSize;
    uint32_t priority;        // 0=Low, 1=Normal, 2=High, 3=Critical
    uint32_t timeout;         // ms, 0=use default
    uint64_t originPID;
    uint64_t originTID;
    uint8_t  sha256[32];
    uint32_t flags;
    uint32_t reserved[4];
};

struct EmulationResponse {
    uint32_t magic;
    uint32_t version;
    uint32_t requestId;
    uint32_t verdict;         // 0=Clean … 4=Critical
    float    threatScore;
    float    confidence;
    uint32_t exitReason;
    uint64_t instrExecuted;
    uint32_t apiCallCount;
    uint32_t alertCount;
    uint32_t mitreTechCount;
    uint32_t iocCount;
    uint32_t unpackLayers;
    uint32_t flags;
    uint32_t detailsSize;
    uint32_t reserved[4];
};

#pragma pack(pop)

// Request flag bits
static constexpr uint32_t kFlagDeepScan        = 0x01;
static constexpr uint32_t kFlagUnpackOnly       = 0x02;
static constexpr uint32_t kFlagNoNetwork        = 0x04;
static constexpr uint32_t kFlagCaptureMemory    = 0x08;
static constexpr uint32_t kFlagHighPriority     = 0x10;

// Response flag bits
static constexpr uint32_t kRespFlagMalicious    = 0x01;
static constexpr uint32_t kRespFlagUnpacked     = 0x02;
static constexpr uint32_t kRespFlagEvasive      = 0x04;
static constexpr uint32_t kRespFlagTruncated    = 0x08;

// ============================================================================
// KernelIPCBridge
// ============================================================================

class KernelIPCBridge {
public:
    KernelIPCBridge();
    ~KernelIPCBridge();

    KernelIPCBridge(const KernelIPCBridge&) = delete;
    KernelIPCBridge& operator=(const KernelIPCBridge&) = delete;

    /// Callback signature: receives sample data, sample type, and config.
    /// Returns a PhantomEmulationResult.
    using EmulationHandler = std::function<PhantomEmulationResult(
        std::span<const uint8_t> sampleData,
        Phantom::EmulationTarget sampleType,
        const Phantom::EmulationConfig& config)>;

    /// Start listening for emulation requests from the kernel driver.
    [[nodiscard]] bool Start(Phantom::EmulationConfig defaultConfig);

    /// Stop listening and drain active connections.
    void Stop() noexcept;

    /// Whether the bridge is actively listening.
    [[nodiscard]] bool IsRunning() const noexcept;

    /// Register the handler invoked for each emulation request.
    void SetHandler(EmulationHandler handler) noexcept;

    /// Total requests processed since Start().
    [[nodiscard]] uint64_t GetRequestsProcessed() const noexcept;

    /// Requests currently in-flight.
    [[nodiscard]] uint64_t GetRequestsPending() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom::Integration
