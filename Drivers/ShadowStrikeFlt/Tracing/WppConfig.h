/**
 * ============================================================================
 * ShadowStrike NGAV - WPP CONFIGURATION
 * ============================================================================
 *
 * @file WppConfig.h
 * @brief WPP configuration macros.
 *
 * Customizes WPP behavior, including time stamping and custom types.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

//
// Define custom types if needed
//

//
// Example: MAC address tracing
//
// DEFINE_CPLUSPLUS_TYPE(MACADDR, const UINT8*, ItemMACAddr, "s", 1, PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8);
//

//
// Ensure we don't have conflicts with other definitions
//
#ifndef WPP_COMPATIBILITY_MODE
#define WPP_COMPATIBILITY_MODE
#endif

//
// Driver specific macros
//

#define WPP_CHECK_FOR_NULL_STRING  // Check for NULL strings in arguments
