/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS EXCLUSION HELPER
 * ============================================================================
 *
 * @file ProcessExclusion.c
 * @brief Helper for checking process exclusions efficiently.
 *
 * Strategy:
 * 1. On Process Creation (ProcessNotify.c), check if the image path matches exclusion.
 * 2. If matched, tag the EPROCESS or add PID to a "Trusted PID" bitmask/hashset.
 * 3. In I/O callbacks, simply check the PID against the trusted set.
 *
 * This avoids doing string comparison on every I/O operation.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ExclusionManager.h"

//
// Placeholder for PID-bitmap implementation.
//
