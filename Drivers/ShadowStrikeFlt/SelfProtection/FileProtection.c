/**
 * ============================================================================
 * ShadowStrike NGAV - FILE PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file FileProtection.c
 * @brief Logic for determining if a file operation targets protected files.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SelfProtect.h"
#include "../../Core/Globals.h"

//
// Note: Actual blocking of IRP_MJ_CREATE / IRP_MJ_SET_INFORMATION happens in
// the FileSystem/PreCreate.c and PreSetInfo.c callbacks, which call
// ShadowStrikeIsProtectedFile() defined in SelfProtect.c.
//
// This file is reserved for complex path parsing or NTFS stream protection logic
// that might be needed in the future.
//
