; ShadowStrike - Enterprise NGAV/EDR Platform
; Copyright (C) 2026 ShadowStrike Security
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU Affero General Public License as published
; by the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU Affero General Public License for more details.
;
; You should have received a copy of the GNU Affero General Public License
; along with this program. If not, see <https://www.gnu.org/licenses/>.
; ==============================================================================
; VMEvasionDetector_x64.asm
; Enterprise-grade x64 assembly functions for VM detection
;
; ShadowStrike AntiEvasion - VM Evasion Detection Module
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; VM-SPECIFIC FUNCTIONS (defined here):
; - CheckVMwareBackdoor: VMware I/O port backdoor communication
; - CheckHyperVBackdoor: Hyper-V hypercall interface detection
; - GetExtendedCPUIDInfo: Extended CPUID queries with all registers
; - DetectVMCALL: Intel VT-x hypercall detection
; - DetectVMMCALL: AMD-V hypercall detection
; - CheckCPUIDLeafRange: Validates hypervisor CPUID leaf range
;
; SHARED FUNCTIONS (defined in EnvironmentEvasionDetector_x64.asm):
; - CheckCPUIDHypervisorBit, GetCPUIDVendorString
; - MeasureRDTSCTimingDelta, MeasureRDTSCPTiming, MeasureCPUIDTiming
; - MeasureInstructionTiming
; - GetIDTBase, GetGDTBase, GetLDTSelector, GetTRSelector
; - GetIDTAndGDTInfo, CheckSegmentLimits
;
; CALLING CONVENTION: Microsoft x64 calling convention
; - First 4 args: RCX, RDX, R8, R9
; - Return: RAX (integers), XMM0 (floats)
; - Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
; - Callee-saved: RBX, RBP, RDI, RSI, RSP, R12-R15
; ==============================================================================

; ==============================================================================
; SHARED SYMBOL IMPORTS
;
; These functions are defined in EnvironmentEvasionDetector_x64.asm.
; EXTERNDEF tells MASM they exist in another translation unit so the
; VMEvasionDetector C++ code can still reference them via extern "C".
; ==============================================================================
EXTERNDEF CheckCPUIDHypervisorBit:PROC
EXTERNDEF GetCPUIDVendorString:PROC
EXTERNDEF MeasureRDTSCTimingDelta:PROC
EXTERNDEF MeasureRDTSCPTiming:PROC
EXTERNDEF MeasureCPUIDTiming:PROC
EXTERNDEF MeasureInstructionTiming:PROC
EXTERNDEF GetIDTBase:PROC
EXTERNDEF GetGDTBase:PROC
EXTERNDEF GetLDTSelector:PROC
EXTERNDEF GetTRSelector:PROC
EXTERNDEF GetIDTAndGDTInfo:PROC
EXTERNDEF CheckSegmentLimits:PROC

; ==============================================================================
; VM-SPECIFIC PUBLIC SYMBOL EXPORTS
; ==============================================================================
PUBLIC GetExtendedCPUIDInfo
PUBLIC CheckCPUIDLeafRange
PUBLIC CheckVMwareBackdoor
PUBLIC CheckHyperVBackdoor
PUBLIC DetectVMCALL
PUBLIC DetectVMMCALL

.CODE

; ==============================================================================
; CheckVMwareBackdoor
; Performs the VMware backdoor I/O port check
;
; Arguments:
;   RCX = uint32_t* pEax (Input/Output)
;   RDX = uint32_t* pEbx (Input/Output)
;   R8  = uint32_t* pEcx (Input/Output)
;   R9  = uint32_t* pEdx (Input/Output)
;
; extern "C" void CheckVMwareBackdoor(uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx) noexcept;
; ==============================================================================
CheckVMwareBackdoor PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    ; Validate all 4 pointer parameters — caller must not pass NULL
    test rcx, rcx
    jz vmware_backdoor_fail
    test rdx, rdx
    jz vmware_backdoor_fail
    test r8, r8
    jz vmware_backdoor_fail
    test r9, r9
    jz vmware_backdoor_fail

    mov r10, rcx                ; Save pEax
    mov r11, rdx                ; Save pEbx

    ; Load input values
    mov eax, dword ptr [r10]
    mov ebx, dword ptr [r11]
    mov ecx, dword ptr [r8]
    mov edx, dword ptr [r9]

    ; Execute VMware backdoor instruction (IN EAX, DX)
    in eax, dx

    ; Store output values
    mov dword ptr [r10], eax
    mov dword ptr [r11], ebx
    mov dword ptr [r8], ecx
    mov dword ptr [r9], edx

    pop rbx
    ret

vmware_backdoor_fail:
    pop rbx
    ret
CheckVMwareBackdoor ENDP

; ==============================================================================
; CheckHyperVBackdoor
; Checks for Hyper-V specific hypercall interface
;
; Hyper-V exposes hypercalls through CPUID leaf 0x40000001
;
; Returns:
;   RAX = Hyper-V interface signature (0 if not Hyper-V)
;
; extern "C" uint32_t CheckHyperVBackdoor() noexcept;
; ==============================================================================
CheckHyperVBackdoor PROC
    push rbx

    ; First check if hypervisor is present
    mov eax, 1
    cpuid
    bt ecx, 31                  ; Test hypervisor bit
    jnc hyperv_not_present

    ; Get hypervisor vendor
    mov eax, 40000000h
    cpuid

    ; Check if this is Hyper-V ("Microsoft Hv")
    ; EBX = "Micr" = 0x7263694D
    cmp ebx, 7263694Dh
    jne hyperv_not_present

    ; Get Hyper-V interface signature from leaf 0x40000001
    mov eax, 40000001h
    cpuid
    ; EAX contains the interface signature
    ; "Hv#1" = 0x31237648 for Hyper-V

    pop rbx
    ret

hyperv_not_present:
    xor eax, eax
    pop rbx
    ret
CheckHyperVBackdoor ENDP

; ==============================================================================
; GetExtendedCPUIDInfo
; Retrieves extended CPUID information for VM detection
;
; Arguments:
;   RCX = uint32_t leaf
;   RDX = uint32_t subleaf
;   R8  = uint32_t* pEax (Output)
;   R9  = uint32_t* pEbx (Output)
;   Stack: uint32_t* pEcx, uint32_t* pEdx
;
; Returns:
;   RAX = 1 if successful
;
; extern "C" bool GetExtendedCPUIDInfo(uint32_t leaf, uint32_t subleaf,
;                                       uint32_t* eax, uint32_t* ebx,
;                                       uint32_t* ecx, uint32_t* edx) noexcept;
; ==============================================================================
GetExtendedCPUIDInfo PROC
    push rbx
    push rdi
    push rsi

    ; Save output pointers
    mov r10, r8                 ; pEax
    mov r11, r9                 ; pEbx
    mov rdi, rcx                ; Save leaf
    mov rsi, rdx                ; Save subleaf

    ; Load leaf and subleaf
    mov eax, edi                ; leaf
    mov ecx, esi                ; subleaf

    ; Execute CPUID
    cpuid

    ; Store EAX result
    test r10, r10
    jz skip_store_eax
    mov dword ptr [r10], eax
skip_store_eax:

    ; Store EBX result
    test r11, r11
    jz skip_store_ebx
    mov dword ptr [r11], ebx
skip_store_ebx:

    ; Get stack parameters for pEcx and pEdx
    ; =========================================================================
    ; STACK OFFSET FIX: Correct Microsoft x64 calling convention
    ; =========================================================================
    ; When this function is entered, the stack contains:
    ;   [RSP+0]   = Return address (8 bytes)
    ;   [RSP+8]   = Shadow space for RCX (8 bytes) - caller allocated
    ;   [RSP+16]  = Shadow space for RDX (8 bytes) - caller allocated
    ;   [RSP+24]  = Shadow space for R8 (8 bytes) - caller allocated
    ;   [RSP+32]  = Shadow space for R9 (8 bytes) - caller allocated
    ;   [RSP+40]  = 5th parameter (pEcx)
    ;   [RSP+48]  = 6th parameter (pEdx)
    ;
    ; After our 3 pushes (RBX, RDI, RSI = 24 bytes), stack offsets become:
    ;   5th param at [RSP + 24 + 40] = [RSP + 64]
    ;   6th param at [RSP + 24 + 48] = [RSP + 72]
    ; =========================================================================
    mov r10, qword ptr [rsp + 64]   ; pEcx (5th param)
    test r10, r10
    jz skip_store_ecx
    mov dword ptr [r10], ecx
skip_store_ecx:

    mov r10, qword ptr [rsp + 72]   ; pEdx (6th param)
    test r10, r10
    jz skip_store_edx
    mov dword ptr [r10], edx
skip_store_edx:

    mov rax, 1                  ; Success

    pop rsi
    pop rdi
    pop rbx
    ret
GetExtendedCPUIDInfo ENDP

; ==============================================================================
; DetectVMCALL
; Attempts to execute VMCALL instruction (Intel VT-x hypercall)
;
; Note: This WILL cause #UD exception on most systems. Caller MUST use SEH.
;
; Returns:
;   RAX = 1 if VMCALL executed (likely in VM), 0 otherwise (never reached on exception)
;
; extern "C" bool DetectVMCALL() noexcept;
; ==============================================================================
DetectVMCALL PROC
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    ; Execute VMCALL (Intel hypercall)
    ; This causes #UD on non-VMX systems or VM exit in Intel VMs
    vmcall

    ; If we reach here, we're in a VM that handled it
    mov rax, 1
    ret
DetectVMCALL ENDP

; ==============================================================================
; DetectVMMCALL
; Attempts to execute VMMCALL instruction (AMD-V hypercall)
;
; Note: This WILL cause #UD exception on most systems. Caller MUST use SEH.
;
; Returns:
;   RAX = 1 if VMMCALL executed (likely in AMD VM)
;
; extern "C" bool DetectVMMCALL() noexcept;
; ==============================================================================
DetectVMMCALL PROC
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    ; Execute VMMCALL (AMD hypercall)
    vmmcall

    mov rax, 1
    ret
DetectVMMCALL ENDP

; ==============================================================================
; CheckCPUIDLeafRange
; Validates hypervisor CPUID leaf range (0x40000000 - 0x400000FF)
;
; Returns:
;   RAX = Maximum hypervisor CPUID leaf supported (0 if no hypervisor)
;
; extern "C" uint32_t CheckCPUIDLeafRange() noexcept;
; ==============================================================================
CheckCPUIDLeafRange PROC
    push rbx

    ; First check if hypervisor bit is set
    mov eax, 1
    cpuid
    bt ecx, 31
    jnc no_hypervisor_leaf

    ; Query maximum hypervisor leaf
    mov eax, 40000000h
    cpuid
    ; EAX contains max leaf

    ; Validate range (should be 0x40000000 - 0x400000FF)
    cmp eax, 40000000h
    jb no_hypervisor_leaf
    cmp eax, 400000FFh
    ja no_hypervisor_leaf

    ; Return max leaf in EAX
    pop rbx
    ret

no_hypervisor_leaf:
    xor eax, eax
    pop rbx
    ret
CheckCPUIDLeafRange ENDP

END
