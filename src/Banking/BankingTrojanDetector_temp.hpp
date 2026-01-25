/*******************************************************************************
 * Project: ShadowStrike Next-Generation AntiVirus (NGAV)
 * File: BankingTrojanDetector.hpp
 * 
 * Description:
 *     Enterprise-grade banking trojan detection system for identifying and
 *     neutralizing sophisticated financial malware including Zeus, Emotet,
 *     TrickBot, Dridex, QakBot, Gozi, Carberp, SpyEye, and emerging variants.
 *     
 *     This module implements multi-layered detection using behavioral analysis,
 *     signature matching, heuristic algorithms, memory forensics, API hooking
 *     detection, web injection identification, and machine learning models.
 *     
 *     Designed to compete with CrowdStrike Falcon, Kaspersky, BitDefender at
 *     enterprise scale with millions of endpoints.
 * 
 * Copyright (c) 2025 ShadowStrike Security
 * All Rights Reserved.
 * 
 * Version: 1.0.0
 * Author: ShadowStrike Security Team
 * Date: 2025-01-25
 * 
 * Security Classification: CRITICAL
 * Compliance: PCI-DSS 4.0, SOC 2 Type II, ISO 27001
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <span>
#include <concepts>
#include <ranges>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
#include <expected>
#include <filesystem>

#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelLookup.hpp"
#include "../Whitelist/WhiteListStore.hpp"

namespace ShadowStrike::Banking {
