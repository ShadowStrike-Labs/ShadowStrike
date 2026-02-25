/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file KernelProcessTypes.h
 * @brief User-mode process structures for kernel-mode PEB/LDR access.
 *
 * These structures are not defined in WDK kernel headers. They mirror the
 * well-documented user-mode layout published in Microsoft documentation
 * and Windows Internals. Required by any kernel driver that walks the
 * PEB module list (e.g., to locate ntdll.dll).
 *
 * Used by: SyscallMonitor, HeavensGateDetector, DirectSyscallDetector,
 *          CallstackAnalyzer, NtdllIntegrity, ROPDetector, ThreadNotify
 *
 * IMPORTANT: These are minimal partial definitions containing only the
 * fields we access. Do NOT cast to these types and assume full layout
 * beyond the fields defined here.
 *
 * Reference: Windows Internals 7th Ed., Microsoft PEB documentation,
 *            ntdll.dll public symbols.
 */

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// UNDOCUMENTED KERNEL API — PsGetProcessPeb
// ============================================================================
//
// Exported by ntoskrnl.exe but not declared in WDK headers.
// Resolved at link time; available on all NT 6.0+ (Vista through Win11).
// Returns the user-mode PEB address for the given process.
// The returned pointer is in the target process's address space —
// the caller MUST attach to the process (KeStackAttachProcess) before
// dereferencing.
//

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(
    _In_ PEPROCESS Process
);

// ============================================================================
// LDR_DATA_TABLE_ENTRY — PEB module list entry (partial)
// ============================================================================
//
// Each loaded module in the process address space has an entry in the
// PEB loader data lists. We define only the fields needed for module
// enumeration (base address, size, name).
//
// The full structure is significantly larger (~250 bytes on x64) but
// we only access fields at stable, well-known offsets from the start.
//

typedef struct _KM_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY      InLoadOrderLinks;       // offset 0x00
    LIST_ENTRY      InMemoryOrderLinks;     // offset 0x10 (x64)
    LIST_ENTRY      InInitializationOrderLinks; // offset 0x20 (x64)
    PVOID           DllBase;                // offset 0x30 (x64)
    PVOID           EntryPoint;             // offset 0x38 (x64)
    ULONG           SizeOfImage;            // offset 0x40 (x64)
    UNICODE_STRING  FullDllName;            // offset 0x48 (x64)
    UNICODE_STRING  BaseDllName;            // offset 0x58 (x64)
} KM_LDR_DATA_TABLE_ENTRY, *PKM_LDR_DATA_TABLE_ENTRY;

// ============================================================================
// PEB_LDR_DATA — PEB loader data (partial)
// ============================================================================
//
// Contains the three linked lists of loaded modules.
// Only InLoadOrderModuleList and InMemoryOrderModuleList are commonly used.
//

typedef struct _KM_PEB_LDR_DATA {
    ULONG           Length;                         // offset 0x00
    BOOLEAN         Initialized;                    // offset 0x04
    PVOID           SsHandle;                       // offset 0x08
    LIST_ENTRY      InLoadOrderModuleList;          // offset 0x10 (x64)
    LIST_ENTRY      InMemoryOrderModuleList;        // offset 0x20 (x64)
    LIST_ENTRY      InInitializationOrderModuleList;// offset 0x30 (x64)
} KM_PEB_LDR_DATA, *PKM_PEB_LDR_DATA;

// ============================================================================
// PEB — Process Environment Block (partial, x64 layout)
// ============================================================================
//
// The PEB is mapped into every process's address space at a fixed location.
// We define the minimal prefix needed to access the Ldr pointer.
//
// The actual PEB is ~500+ bytes. We only need the Ldr field at offset 0x18.
// Fields before Ldr are included to maintain correct struct layout.
//

typedef struct _KM_PEB {
    BOOLEAN         InheritedAddressSpace;      // offset 0x00
    BOOLEAN         ReadImageFileExecOptions;   // offset 0x01
    BOOLEAN         BeingDebugged;              // offset 0x02
    BOOLEAN         BitField;                   // offset 0x03
    UCHAR           Padding0[4];                // offset 0x04 (x64 alignment)
    HANDLE          Mutant;                     // offset 0x08
    PVOID           ImageBaseAddress;            // offset 0x10
    PKM_PEB_LDR_DATA Ldr;                       // offset 0x18 — this is what we need
} KM_PEB, *PKM_PEB;

//
// Convenience: size constants for ProbeForRead validation.
// Use these instead of sizeof(PEB) which would only be our partial struct.
// These reflect the minimum safe probe size.
//
#define KM_PEB_PROBE_SIZE           (FIELD_OFFSET(KM_PEB, Ldr) + sizeof(PVOID))
#define KM_PEB_LDR_PROBE_SIZE      sizeof(KM_PEB_LDR_DATA)
#define KM_LDR_ENTRY_PROBE_SIZE    sizeof(KM_LDR_DATA_TABLE_ENTRY)

//
// Maximum number of modules to walk to prevent infinite loops on corrupted lists.
// A healthy Windows process typically loads 50-200 modules.
// Cap at 4096 to handle edge cases while preventing hangs.
//
#define KM_MAX_MODULE_WALK_COUNT    4096

#ifdef __cplusplus
}
#endif
