/**
 * ============================================================================
 * ShadowStrike NGAV - HANDLE PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file HandleProtection.c
 * @brief Additional logic for handle protection operations.
 *
 * Currently, most handle protection logic is consolidated in SelfProtect.c
 * within the Object Callback routine. This file is reserved for future expansion
 * or specific handle table manipulation if ObRegisterCallbacks is insufficient.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SelfProtect.h"

//
// This file is currently a placeholder for advanced handle enumeration/stripping techniques
// if we decide to implement DKOM-style protection (Direct Kernel Object Manipulation),
// though ObRegisterCallbacks is the supported/safe way.
//
// For now, the implementation resides in SelfProtect.c:ShadowStrikeObPreCallback
//
