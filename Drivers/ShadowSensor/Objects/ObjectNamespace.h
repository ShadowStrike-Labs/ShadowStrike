/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT NAMESPACE HEADER
 * ============================================================================
 * @brief Manages private object namespace for secure driver communication.
 */
#ifndef SHADOWSTRIKE_OBJECT_NAMESPACE_H
#define SHADOWSTRIKE_OBJECT_NAMESPACE_H

#include <ntddk.h>

NTSTATUS ShadowCreatePrivateNamespace(VOID);
VOID ShadowDestroyPrivateNamespace(VOID);

#endif
