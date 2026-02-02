/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT NAMESPACE IMPLEMENTATION
 * ============================================================================
 */
#include "ObjectNamespace.h"

NTSTATUS ShadowCreatePrivateNamespace(VOID) {
    // TODO: ZwCreateDirectoryObject for \ShadowStrike
    return STATUS_SUCCESS;
}

VOID ShadowDestroyPrivateNamespace(VOID) {
}
