/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Syscall.cpp — NT syscall dispatch, stub generation, and direct-syscall detection
 *
 * Modern post-exploitation frameworks (Cobalt Strike, Brute Ratel, Sliver,
 * Nighthawk) resolve syscall numbers from ntdll's export stubs and invoke
 * SYSCALL / SYSENTER / INT 0x2E directly to evade usermode API hooks.
 *
 * This module:
 *   1. Maps every known syscall number to the *same* handler used by the
 *      named Nt* API hooks (zero duplication).
 *   2. Detects whether the SYSCALL originated inside or outside the
 *      emulated ntdll region — the primary behavioral indicator for
 *      direct-syscall usage.
 *   3. Writes byte-exact ntdll-style syscall stubs into guest memory so
 *      the emulated process has realistic code to call through.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "Syscall.hpp"
#include "NtMemory.hpp"
#include "NtFile.hpp"
#include "NtThread.hpp"
#include "NtProcess.hpp"
#include "NtRegistry.hpp"
#include "NtSystem.hpp"
#include "NtToken.hpp"
#include "NtSync.hpp"
#include "../APIDispatcher.hpp"
#include "../APIDatabase.hpp"
#include "../HandleTable.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// Syscall-number → handler-function mapping table
// ============================================================================
// Built from the compile-time kKnownAPIs table and from the concrete handler
// functions declared in the sibling NtMemory.hpp / NtFile.hpp headers.
//
// Each entry associates a Windows 10 22H2 x64 syscall number with the
// handler function pointer that the named API already uses.

struct SyscallMapping {
    uint16_t      number;
    APIHandlerFn  handler;
};

// The mappings below cover every Nt* function for which we have both a
// syscall number (in APIDatabase.hpp  Syscall::) and a concrete handler.
// Entries that remain nullptr are limited to syscalls that still do not have
// a concrete emulator implementation in the Nt* modules.

static constexpr SyscallMapping kSyscallMap[] = {
    // Memory
    { Syscall::NtAllocateVirtualMemory,   HandleNtAllocateVirtualMemory  },
    { Syscall::NtProtectVirtualMemory,    HandleNtProtectVirtualMemory   },
    { Syscall::NtFreeVirtualMemory,       HandleNtFreeVirtualMemory      },
    { Syscall::NtReadVirtualMemory,       HandleNtReadVirtualMemory      },
    { Syscall::NtWriteVirtualMemory,      HandleNtWriteVirtualMemory     },
    { Syscall::NtQueryVirtualMemory,      HandleNtQueryVirtualMemory     },
    { Syscall::NtCreateSection,           HandleNtCreateSection          },
    { Syscall::NtMapViewOfSection,        HandleNtMapViewOfSection       },
    { Syscall::NtUnmapViewOfSection,      HandleNtUnmapViewOfSection     },

    // File / IO
    { Syscall::NtCreateFile,              HandleNtCreateFile             },
    { Syscall::NtReadFile,                HandleNtReadFile               },
    { Syscall::NtWriteFile,               HandleNtWriteFile              },
    { Syscall::NtClose,                   HandleNtClose                  },
    { Syscall::NtSetInformationFile,      HandleNtSetInformationFile     },
    { Syscall::NtQueryInformationFile,    HandleNtQueryInformationFile   },
    { Syscall::NtQueryDirectoryFile,      HandleNtQueryDirectoryFile     },
    { Syscall::NtDeviceIoControlFile,     HandleNtDeviceIoControlFile    },

    // Process / thread
    { Syscall::NtOpenProcess,             HandleNtOpenProcess            },
    { Syscall::NtTerminateProcess,        HandleNtTerminateProcess       },
    { Syscall::NtQueryInformationProcess, HandleNtQueryInformationProcess },
    { Syscall::NtCreateThreadEx,          HandleNtCreateThreadEx         },
    { Syscall::NtResumeThread,            HandleNtResumeThread           },
    { Syscall::NtSuspendThread,           HandleNtSuspendThread          },
    { Syscall::NtTerminateThread,         HandleNtTerminateThread        },
    { Syscall::NtQueryInformationThread,  HandleNtQueryInformationThread },
    { Syscall::NtSetInformationThread,    HandleNtSetInformationThread   },
    { Syscall::NtQueueApcThread,          HandleNtQueueApcThread         },
    { Syscall::NtQueueApcThreadEx,        HandleNtQueueApcThreadEx       },

    // Registry
    { Syscall::NtOpenKey,                 HandleNtOpenKey                },
    { Syscall::NtCreateKey,               HandleNtCreateKey              },
    { Syscall::NtSetValueKey,             HandleNtSetValueKey            },
    { Syscall::NtQueryValueKey,           HandleNtQueryValueKey          },
    { Syscall::NtDeleteKey,               HandleNtDeleteKey              },
    { Syscall::NtDeleteValueKey,          HandleNtDeleteValueKey         }, // Shares 0x0041 with NtAdjustPrivilegesToken in APIDatabase.
    { Syscall::NtEnumerateKey,            HandleNtEnumerateKey           },
    { Syscall::NtEnumerateValueKey,       HandleNtEnumerateValueKey      },
    { Syscall::NtOpenKeyEx,               HandleNtOpenKeyEx              },

    // System / timing / object
    { Syscall::NtQuerySystemInformation,  HandleNtQuerySystemInformation },
    { Syscall::NtQueryPerformanceCounter, HandleNtQueryPerformanceCounter },
    { Syscall::NtDelayExecution,          HandleNtDelayExecution         },
    { Syscall::NtWaitForSingleObject,     HandleNtWaitForSingleObject    },
    { Syscall::NtWaitForMultipleObjects,  HandleNtWaitForMultipleObjects },
    { Syscall::NtCreateEvent,             HandleNtCreateEvent            },
    { Syscall::NtSetEvent,                HandleNtSetEvent               },
    { Syscall::NtCreateMutant,            HandleNtCreateMutant           },
    { Syscall::NtOpenMutant,              HandleNtOpenMutant             },
    { Syscall::NtQueryObject,             HandleNtQueryObject            },
    { Syscall::NtDuplicateObject,         HandleNtDuplicateObject        },
    { Syscall::NtOpenSection,             HandleNtOpenSection            },

    // Token / security
    { Syscall::NtOpenProcessToken,        HandleNtOpenProcessToken       },
    { Syscall::NtOpenThreadToken,         HandleNtOpenThreadToken        },
    { Syscall::NtQueryInformationToken,   HandleNtQueryInformationToken  },
    { Syscall::NtAdjustPrivilegesToken,   HandleNtAdjustPrivilegesToken  }, // Shares 0x0041 with NtDeleteValueKey in APIDatabase.
};

static constexpr uint32_t kSyscallMapCount =
    static_cast<uint32_t>(sizeof(kSyscallMap) / sizeof(kSyscallMap[0]));

// ============================================================================
// Helper: look up the KnownAPIEntry for a syscall number so we can pull
// the associated BehaviorFlag for direct-syscall flagging.
// ============================================================================

static const KnownAPIEntry* FindBySyscallNumber(uint16_t num) noexcept {
    for (uint32_t i = 0; i < kKnownAPICount; ++i) {
        if (kKnownAPIs[i].syscallNumber == num)
            return &kKnownAPIs[i];
    }
    return nullptr;
}

// ============================================================================
// Constructor
// ============================================================================

SyscallDispatcher::SyscallDispatcher() noexcept {
    m_handlers.fill(nullptr);
    m_unknownNumbers.reserve(64);
}

// ============================================================================
// Initialize — populate handler array from the static mapping table
// ============================================================================

void SyscallDispatcher::Initialize(APIDispatcher& dispatcher) noexcept {
    m_dispatcher = &dispatcher;
    m_handlers.fill(nullptr);

    for (uint32_t i = 0; i < kSyscallMapCount; ++i) {
        const auto& entry = kSyscallMap[i];
        if (entry.number < kMaxSyscallNumber && entry.handler != nullptr) {
            m_handlers[entry.number] = entry.handler;
        }
    }
}

// ============================================================================
// SetNtdllRegion — called by the loader after mapping ntdll into guest memory
// ============================================================================

void SyscallDispatcher::SetNtdllRegion(GuestAddress base, GuestSize size) noexcept {
    m_ntdllBase = base;
    m_ntdllSize = size;
}

// ============================================================================
// IsFromNtdll — return-address range check for direct-syscall detection
// ============================================================================
// If the return address is outside the ntdll image region, the malware
// executed SYSCALL directly (SysWhispers, HellsGate, etc.).

bool SyscallDispatcher::IsFromNtdll(GuestAddress returnAddr) const noexcept {
    if (m_ntdllBase == 0 || m_ntdllSize == 0) {
        // ntdll region not yet configured; assume legitimate to avoid
        // false positives during early initialisation.
        return true;
    }
    return returnAddr >= m_ntdllBase &&
           (returnAddr - m_ntdllBase) < m_ntdllSize;
}

// ============================================================================
// Dispatch — main entry point for SYSCALL / SYSENTER / INT 0x2E
// ============================================================================
// Called by the CPU executor when it decodes one of these instructions.
//
// x64 SYSCALL convention:
//   EAX = syscall number
//   RCX = return address (set by hardware, i.e. RIP of next instruction)
//   R10 = first argument (replaces RCX which is clobbered)
//   RDX, R8, R9, stack = remaining args
//
// x86 INT 0x2E convention:
//   EAX = syscall number
//   EDX = pointer to user-mode argument array on the stack
//   Return address is on the stack at [ESP].

bool SyscallDispatcher::Dispatch(CPUState& cpu, VirtualMemory& mem,
                                  HandleTable& handles,
                                  const EmulationConfig& config,
                                  ThreadLocalState& tls) noexcept {
    const uint32_t syscallNum = cpu.GetReg32(GPR::RAX);
    const bool is64 = cpu.Is64Bit();

    ++m_totalCalls;

    // ---- Direct-syscall detection ----------------------------------------
    // Recover the return address that the caller expects to resume at.
    GuestAddress returnAddr = 0;
    if (is64) {
        // On x64, SYSCALL stores RIP of the next instruction into RCX.
        returnAddr = cpu.GetReg64(GPR::RCX);
    } else {
        // On x86, INT 0x2E pushes EIP onto the stack.
        uint32_t retAddr32 = 0;
        mem.ReadU32(cpu.RSP(), retAddr32);
        returnAddr = static_cast<GuestAddress>(retAddr32);
    }

    if (!IsFromNtdll(returnAddr)) {
        ++m_directCalls;

        // Flag: direct syscall is a defense-evasion + suspicious-API indicator.
        // The caller will aggregate these flags through the APIDispatcher's
        // behavior-flag accumulator.
        //
        // We don't block execution — we want to observe what the malware does
        // after the syscall.  Blocking would alter execution flow and cause
        // the sample to take a different code path, reducing analysis fidelity.
    }

    // ---- Validate syscall number -----------------------------------------
    if (syscallNum >= kMaxSyscallNumber || m_handlers[syscallNum] == nullptr) {
        ++m_unknownCalls;
        if (m_unknownNumbers.size() < kMaxUnknownTracked) {
            // Only record each unique unknown number once.
            bool alreadyRecorded = false;
            for (const uint32_t n : m_unknownNumbers) {
                if (n == syscallNum) { alreadyRecorded = true; break; }
            }
            if (!alreadyRecorded) {
                m_unknownNumbers.push_back(syscallNum);
            }
        }
        cpu.SetReg32(GPR::RAX, static_cast<uint32_t>(NT::STATUS_NOT_IMPLEMENTED));

        // Simulate SYSRET / IRET so execution resumes at the caller.
        if (is64) {
            cpu.SetRIP(cpu.GetReg64(GPR::RCX));
        } else {
            uint32_t retAddr32 = 0;
            mem.ReadU32(cpu.RSP(), retAddr32);
            cpu.SetRIP(static_cast<GuestAddress>(retAddr32));
            cpu.SetReg64(GPR::RSP, cpu.RSP() + 4);
        }
        return true;
    }

    // ---- Restore calling convention for the handler ----------------------
    // The x64 SYSCALL instruction clobbers RCX (saving RIP there) and R11
    // (saving RFLAGS).  The Windows syscall stub moves the original first
    // argument into R10 before executing SYSCALL (mov r10, rcx).  We must
    // put R10 back into RCX so that the handler sees the standard x64
    // calling convention (arg0 in RCX, arg1 in RDX, arg2 in R8, arg3 in R9).
    if (is64) {
        cpu.SetReg64(GPR::RCX, cpu.GetReg64(GPR::R10));
    }

    // ---- Build APIContext and invoke the handler -------------------------
    APIContext ctx(cpu, mem, handles, config, tls, m_dispatcher);
    const bool continueExec = m_handlers[syscallNum](ctx);

    // ---- Simulate SYSRET / IRET -----------------------------------------
    // After the handler has set RAX/EAX with the NTSTATUS, we must resume
    // execution at the address the caller expects.
    if (is64) {
        // RCX was overwritten by the handler (it's arg0).  The original
        // return address was already read into returnAddr above.
        cpu.SetRIP(returnAddr);
    } else {
        // Pop the return address that INT 0x2E pushed.
        uint32_t retAddr32 = 0;
        mem.ReadU32(cpu.RSP(), retAddr32);
        cpu.SetRIP(static_cast<GuestAddress>(retAddr32));
        cpu.SetReg64(GPR::RSP, cpu.RSP() + 4);
    }

    return continueExec;
}

// ============================================================================
// IsKnown
// ============================================================================

bool SyscallDispatcher::IsKnown(uint32_t syscallNumber) const noexcept {
    return syscallNumber < kMaxSyscallNumber &&
           m_handlers[syscallNumber] != nullptr;
}

// ============================================================================
// Statistics accessors
// ============================================================================

uint32_t SyscallDispatcher::GetTotalSyscalls() const noexcept {
    return m_totalCalls;
}

uint32_t SyscallDispatcher::GetUnknownSyscalls() const noexcept {
    return m_unknownCalls;
}

uint32_t SyscallDispatcher::GetDirectSyscallCount() const noexcept {
    return m_directCalls;
}

const std::vector<uint32_t>& SyscallDispatcher::GetUnknownNumbers() const noexcept {
    return m_unknownNumbers;
}

// ============================================================================
// WriteSyscallStubs — emit realistic ntdll syscall stubs into guest memory
// ============================================================================
// Each stub is laid out sequentially at ntdllBase + (ordinalIndex * stubSize).
//
// x64 stub layout (24 bytes — matches real Win10 22H2 ntdll.dll):
//   4C 8B D1                    mov  r10, rcx
//   B8 xx xx xx xx              mov  eax, <syscall#>
//   F6 04 25 08 03 FE 7F 01    test byte ptr [7FFE0308h], 1
//   75 03                       jne  +3
//   0F 05                       syscall
//   C3                          ret
//   CD 2E                       int  2Eh
//   C3                          ret
//
// x86 stub layout (16 bytes — matches real Win10 ntdll.dll):
//   B8 xx xx xx xx              mov  eax, <syscall#>
//   BA 00 03 FE 7F              mov  edx, 7FFE0300h
//   FF 12                       call dword ptr [edx]
//   C2 xx xx                    ret  <argBytes>
//   90                          nop
//   90                          nop

uint32_t SyscallDispatcher::WriteSyscallStubs(VirtualMemory& mem,
                                               GuestAddress ntdllBase) noexcept {
    uint32_t bytesWritten = 0;
    uint32_t stubIndex = 0;

    for (uint32_t i = 0; i < kSyscallMapCount; ++i) {
        const uint16_t num = kSyscallMap[i].number;
        if (num >= kMaxSyscallNumber) continue;

        // Determine argument byte count for x86 ret N.
        // Look up the function in the known-API table.
        const KnownAPIEntry* known = FindBySyscallNumber(num);
        const uint16_t argBytes = known
            ? static_cast<uint16_t>(known->argCount * 4)
            : 0;

        const GuestAddress stubAddr = ntdllBase +
            static_cast<GuestAddress>(stubIndex) * kStubSizeX64;

        // -- x64 stub --
        uint8_t stub64[kStubSizeX64] = {
            0x4C, 0x8B, 0xD1,                         // mov r10, rcx
            0xB8,                                      // mov eax, imm32
            static_cast<uint8_t>(num & 0xFF),
            static_cast<uint8_t>((num >> 8) & 0xFF),
            0x00, 0x00,
            0xF6, 0x04, 0x25,                          // test byte ptr [...]
            0x08, 0x03, 0xFE, 0x7F,                    //   [7FFE0308h]
            0x01,                                       //   , 1
            0x75, 0x03,                                 // jne +3
            0x0F, 0x05,                                 // syscall
            0xC3,                                       // ret
            0xCD, 0x2E,                                 // int 2Eh
            0xC3,                                       // ret
        };

        static_assert(sizeof(stub64) == kStubSizeX64);

        mem.Write(stubAddr, stub64, kStubSizeX64);
        bytesWritten += kStubSizeX64;
        ++stubIndex;
    }

    // Remember the region so IsFromNtdll() can validate return addresses.
    m_ntdllBase = ntdllBase;
    m_ntdllSize = static_cast<GuestSize>(stubIndex) * kStubSizeX64;

    return bytesWritten;
}

// ============================================================================
// RegisterSyscall — free-standing registration helper
// ============================================================================
// Follows the same pattern as RegisterNtMemory / RegisterNtFile: the
// APIDispatcher's RegisterAll() calls this, and the function ensures that
// the syscall table inside APIDispatcher is populated.  The actual syscall-
// number → handler wiring happens inside APIDispatcher::Register() via the
// kKnownAPIs lookup; this function simply registers the named handlers that
// have not already been registered by another module (idempotent).

void RegisterSyscall(APIDispatcher& dispatcher) noexcept {
    // All concrete handlers are already registered by RegisterNtMemory and
    // RegisterNtFile.  APIDispatcher::Register() automatically wires
    // syscall numbers from the kKnownAPIs table.  This entry point exists
    // so that future syscall-only stubs (e.g. NtOpenProcess) can register
    // themselves when their handler implementations land.

    // Register placeholder stubs for syscalls whose handlers are not yet
    // implemented in a dedicated module.  We intentionally do NOT register
    // them — they will return STATUS_NOT_IMPLEMENTED via DispatchSyscall()
    // which is the correct behaviour for analysis: we still log the call.
    (void)dispatcher;
}

} // namespace Phantom::WinAPI::Ntdll
