/*
 * ============================================================================
 * ShadowStrike - PRECOMPILED HEADER
 * ============================================================================
 * Target: Ultra-fast compilation for enterprise-scale codebase.
 * Includes: Stable STL, Windows SDK, and Core Framework headers.
 * ============================================================================
 */

#ifndef PCH_H
#define PCH_H

#pragma once

 // Windows API - Stripped for performance
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <objbase.h>

// C++20 Standard Library - Core & Containers
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <span>
#include <optional>
#include <variant>
#include <expected> // C++23 style or equivalent
#include <cstdint>
#include <algorithm>
#include <iterator>
#include <type_traits>
#include <concepts>
#include <format>

// C++20 - Concurrency & Time
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
#include <chrono>

// Performance & Memory
#include <limits>
#include <bit>
#include <ranges>

// Testing Framework (Commonly used in ShadowStrike)
#include <gtest/gtest.h>
#include <gmock/gmock.h>


#endif // PCH_H