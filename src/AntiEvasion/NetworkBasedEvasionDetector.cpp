// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * @file NetworkBasedEvasionDetector.cpp
 * @brief Enterprise-grade implementation of network-based evasion detection
 * 
 * ShadowStrike AntiEvasion - Network-Based Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "NetworkBasedEvasionDetector.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/Logger.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <format>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace ShadowStrike {
namespace AntiEvasion {

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

NetworkBasedEvasionDetector& NetworkBasedEvasionDetector::GetInstance() {
    static NetworkBasedEvasionDetector instance;
    return instance;
}

// ============================================================================
// CONSTRUCTION & LIFECYCLE
// ============================================================================

NetworkBasedEvasionDetector::NetworkBasedEvasionDetector() 
    : m_initialized(false)
{
    if (Initialize()) {
        m_initialized = true;
    }
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"Constructor called");
}

NetworkBasedEvasionDetector::~NetworkBasedEvasionDetector() {
    Shutdown();
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"Destructor called");
}

bool NetworkBasedEvasionDetector::Initialize() {
    std::unique_lock lock(m_mutex);
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SS_LOG_ERROR(L"NetworkBasedEvasionDetector", L"WSAStartup failed");
        return false;
    }
    
    m_stats.Reset();
    m_initialized = true;
    
    SS_LOG_INFO(L"NetworkBasedEvasionDetector", L"Initialized successfully");
    return true;
}

void NetworkBasedEvasionDetector::Shutdown() {
    std::unique_lock lock(m_mutex);
    
    m_cachedResult.reset();
    WSACleanup();
    m_initialized = false;
    
    SS_LOG_INFO(L"NetworkBasedEvasionDetector", L"Shutdown complete");
}

bool NetworkBasedEvasionDetector::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

// ============================================================================
// PRIMARY DETECTION API
// ============================================================================

NetworkEvasionResult NetworkBasedEvasionDetector::AnalyzeNetwork() {
    SS_LOG_INFO(L"NetworkBasedEvasionDetector", L"AnalyzeNetwork starting");
    
    m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
    
    NetworkEvasionResult result;
    result.analysisStartTime = std::chrono::system_clock::now();
    
    // Check internet connectivity
    CheckInternetConnectivity(result);
    
    // Check DNS resolution
    CheckDNSResolution(result);
    
    // Check network adapters
    CheckNetworkAdapters(result);
    
    // Check for proxy/interception
    CheckProxyInterception(result);
    
    // Calculate score
    CalculateEvasionScore(result);
    
    result.analysisEndTime = std::chrono::system_clock::now();
    result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.analysisEndTime - result.analysisStartTime).count();
    result.analysisComplete = true;
    
    if (result.isEvasive) {
        m_stats.evasiveNetworks.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Cache result
    {
        std::unique_lock lock(m_mutex);
        m_cachedResult = result;
    }
    
    SS_LOG_INFO(L"NetworkBasedEvasionDetector", L"Analysis complete: isEvasive=%s, score=%.1f",
        result.isEvasive ? L"true" : L"false", result.evasionScore);
    
    return result;
}

bool NetworkBasedEvasionDetector::QuickCheck() {
    // Quick internet connectivity check
    return InternetCheckConnectionW(L"http://www.microsoft.com", FLAG_ICC_FORCE_CONNECTION, 0) == FALSE;
}

// ============================================================================
// INDIVIDUAL CHECK METHODS
// ============================================================================

void NetworkBasedEvasionDetector::CheckInternetConnectivity(NetworkEvasionResult& result) {
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"CheckInternetConnectivity");
    
    result.connectivityInfo.hasInternet = 
        InternetCheckConnectionW(L"http://www.microsoft.com", FLAG_ICC_FORCE_CONNECTION, 0) != FALSE;
    
    if (!result.connectivityInfo.hasInternet) {
        result.connectivityScore += 30.0f;
    }
}

void NetworkBasedEvasionDetector::CheckDNSResolution(NetworkEvasionResult& result) {
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"CheckDNSResolution");
    
    // Try to resolve a known domain
    struct addrinfo hints{}, *addrResult = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo("www.google.com", "80", &hints, &addrResult);
    
    result.dnsInfo.canResolve = (ret == 0);
    
    if (addrResult) {
        if (addrResult->ai_family == AF_INET) {
            auto* sockaddr_ipv4 = reinterpret_cast<struct sockaddr_in*>(addrResult->ai_addr);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipStr, INET_ADDRSTRLEN);
            result.dnsInfo.resolvedAddress = std::wstring(ipStr, ipStr + strlen(ipStr));
        }
        freeaddrinfo(addrResult);
    }
    
    if (!result.dnsInfo.canResolve) {
        result.dnsScore += 25.0f;
    }
}

void NetworkBasedEvasionDetector::CheckNetworkAdapters(NetworkEvasionResult& result) {
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"CheckNetworkAdapters");
    
    ULONG bufferSize = 15000;
    std::vector<uint8_t> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
        uint32_t adapterCount = 0;
        
        for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            adapterCount++;
            
            // Check for loopback only
            if (pAdapter->Type == MIB_IF_TYPE_LOOPBACK) {
                result.adapterScore += 10.0f;
            }
        }
        
        result.adapterInfo.adapterCount = adapterCount;
        
        // Very few adapters is suspicious
        if (adapterCount <= 1) {
            result.adapterScore += 20.0f;
        }
    }
}

void NetworkBasedEvasionDetector::CheckProxyInterception(NetworkEvasionResult& result) {
    SS_LOG_DEBUG(L"NetworkBasedEvasionDetector", L"CheckProxyInterception");
    
    // Check for proxy settings in registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD proxyEnable = 0;
        DWORD dataSize = sizeof(proxyEnable);
        
        if (RegQueryValueExW(hKey, L"ProxyEnable", nullptr, nullptr, 
            reinterpret_cast<LPBYTE>(&proxyEnable), &dataSize) == ERROR_SUCCESS) {
            
            result.proxyInfo.proxyEnabled = (proxyEnable != 0);
            
            if (proxyEnable) {
                wchar_t proxyServer[256] = {0};
                dataSize = sizeof(proxyServer);
                
                if (RegQueryValueExW(hKey, L"ProxyServer", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(proxyServer), &dataSize) == ERROR_SUCCESS) {
                    result.proxyInfo.proxyServer = proxyServer;
                }
                
                result.proxyScore += 25.0f;
            }
        }
        
        RegCloseKey(hKey);
    }
}

// ============================================================================
// SCORE CALCULATION
// ============================================================================

void NetworkBasedEvasionDetector::CalculateEvasionScore(NetworkEvasionResult& result) {
    result.evasionScore = 
        result.connectivityScore * 0.30f +
        result.dnsScore * 0.25f +
        result.adapterScore * 0.25f +
        result.proxyScore * 0.20f;
    
    result.evasionScore = std::min(100.0f, result.evasionScore);
    result.isEvasive = result.evasionScore >= 50.0f;
    
    if (result.evasionScore >= 70.0f) {
        result.confidence = 80.0f;
    } else if (result.evasionScore >= 50.0f) {
        result.confidence = 65.0f;
    } else {
        result.confidence = 50.0f;
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

NetworkBasedEvasionDetector::Statistics NetworkBasedEvasionDetector::GetStatistics() const {
    return m_stats;
}

void NetworkBasedEvasionDetector::ResetStatistics() {
    m_stats.Reset();
}

// ============================================================================
// CACHE
// ============================================================================

std::optional<NetworkEvasionResult> NetworkBasedEvasionDetector::GetCachedResult() const {
    std::shared_lock lock(m_mutex);
    return m_cachedResult;
}

void NetworkBasedEvasionDetector::ClearCache() {
    std::unique_lock lock(m_mutex);
    m_cachedResult.reset();
}

} // namespace AntiEvasion
} // namespace ShadowStrike
