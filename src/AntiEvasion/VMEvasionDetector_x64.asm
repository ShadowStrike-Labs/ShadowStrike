; ==============================================================================
; VMEvasionDetector_x64.asm
; Low-level x64 assembly functions for VM detection
;
; ShadowStrike AntiEvasion - VM Evasion Detection Module
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; FUNCTIONS:
; - CheckCPUIDHypervisorBit: Checks CPUID leaf 0x1, ECX bit 31 for hypervisor
; - GetCPUIDVendorString: Retrieves 12-byte vendor string from CPUID 0x40000000
; - MeasureRDTSCTimingDelta: Measures RDTSC timing variance (VM overhead detection)
; - GetIDTBase: Retrieves IDT base address via SIDT instruction
; - GetGDTBase: Retrieves GDT base address via SGDT instruction
; - GetLDTSelector: Retrieves LDT selector via SLDT instruction
;
; CALLING CONVENTION: Microsoft x64 calling convention
; - First 4 args: RCX, RDX, R8, R9
; - Return: RAX (integers), XMM0 (floats)
; - Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
; - Callee-saved: RBX, RBP, RDI, RSI, RSP, R12-R15
; ==============================================================================

.CODE

; ==============================================================================
; CheckCPUIDHypervisorBit
; Checks if the hypervisor present bit is set in CPUID
;
; Leaf 0x1, ECX bit 31: Hypervisor Present Bit
; Returns: RAX = 1 if hypervisor detected, 0 if bare metal
;
; extern "C" bool CheckCPUIDHypervisorBit() noexcept;
; ==============================================================================
CheckCPUIDHypervisorBit PROC
    push rbx                    ; Save RBX (callee-saved)
    push rcx                    ; Save RCX (will be clobbered by CPUID)

    ; Execute CPUID with leaf 0x1
    mov eax, 1                  ; CPUID leaf 0x1 (Processor Info and Feature Bits)
    xor ecx, ecx                ; Clear ECX (subleaf = 0)
    cpuid                       ; EAX=version, EBX=brand, ECX=features, EDX=features

    ; Check bit 31 of ECX (hypervisor present bit)
    bt ecx, 31                  ; Bit test: CF = ECX[31]
    jc hypervisor_detected      ; Jump if carry flag set (bit 31 = 1)

    ; No hypervisor detected
    xor rax, rax                ; Return false (0)
    jmp exit_proc

hypervisor_detected:
    mov rax, 1                  ; Return true (1)

exit_proc:
    pop rcx                     ; Restore RCX
    pop rbx                     ; Restore RBX
    ret
CheckCPUIDHypervisorBit ENDP

; ==============================================================================
; GetCPUIDVendorString
; Retrieves the 12-byte hypervisor vendor string from CPUID leaf 0x40000000
;
; Leaf 0x40000000: Hypervisor CPUID Information Leaf
; - EBX+ECX+EDX = 12-byte vendor ID string (e.g., "VMwareVMware", "Microsoft Hv")
;
; Arguments:
;   RCX = char* buffer (output buffer, minimum 13 bytes for null terminator)
;   RDX = size_t bufferSize (should be >= 13)
;
; extern "C" void GetCPUIDVendorString(char* buffer, size_t bufferSize) noexcept;
; ==============================================================================
GetCPUIDVendorString PROC
    push rbx                    ; Save RBX (callee-saved)
    push rdi                    ; Save RDI (callee-saved)
    push rsi                    ; Save RSI (callee-saved)

    ; Validate buffer pointer and size
    test rcx, rcx               ; Check if buffer is NULL
    jz exit_get_vendor
    cmp rdx, 13                 ; Check if buffer is large enough
    jl exit_get_vendor

    mov rdi, rcx                ; RDI = buffer pointer

    ; Execute CPUID with leaf 0x40000000 (Hypervisor Vendor String)
    mov eax, 40000000h          ; CPUID leaf 0x40000000
    xor ecx, ecx                ; Clear ECX (subleaf = 0)
    cpuid                       ; EAX=max hypervisor leaf, EBX/ECX/EDX=vendor string

    ; Store vendor string (12 bytes total: EBX, ECX, EDX)
    ; Format: [EBX bytes 0-3][ECX bytes 0-3][EDX bytes 0-3]

    ; Store EBX (first 4 bytes)
    mov [rdi + 0], ebx          ; Bytes 0-3

    ; Store ECX (next 4 bytes) - use EDX instead (CPUID vendor format: EBX, EDX, ECX)
    mov [rdi + 4], edx          ; Bytes 4-7

    ; Store EDX (last 4 bytes) - use ECX
    mov [rdi + 8], ecx          ; Bytes 8-11

    ; Null-terminate the string
    mov byte ptr [rdi + 12], 0  ; Null terminator at position 12

exit_get_vendor:
    pop rsi                     ; Restore RSI
    pop rdi                     ; Restore RDI
    pop rbx                     ; Restore RBX
    ret
GetCPUIDVendorString ENDP

; ==============================================================================
; MeasureRDTSCTimingDelta
; Measures RDTSC timing variance to detect VM overhead
;
; VMs typically have higher RDTSC variance due to:
; - VM exit/entry overhead
; - Scheduling delays
; - CPU core migration
;
; Arguments:
;   ECX = uint32_t iterations (number of samples to take)
;
; Returns:
;   RAX = uint64_t total delta across all iterations
;
; extern "C" uint64_t MeasureRDTSCTimingDelta(uint32_t iterations) noexcept;
; ==============================================================================
MeasureRDTSCTimingDelta PROC
    push rbx                    ; Save RBX (callee-saved)
    push rsi                    ; Save RSI (callee-saved)
    push rdi                    ; Save RDI (callee-saved)

    ; Validate iterations
    test ecx, ecx               ; Check if iterations == 0
    jz exit_timing_zero
    cmp ecx, 10000h             ; Limit to 65536 iterations
    jg exit_timing_zero

    mov esi, ecx                ; RSI = iteration counter
    xor rdi, rdi                ; RDI = accumulated delta (0)

timing_loop:
    ; Serialize execution before first RDTSC
    cpuid                       ; CPUID serializes (clobbers EAX, EBX, ECX, EDX)

    ; First RDTSC measurement
    rdtsc                       ; EDX:EAX = timestamp counter
    mov ebx, eax                ; Save low 32 bits in EBX
    mov r8d, edx                ; Save high 32 bits in R8D

    ; Serialize execution again
    cpuid

    ; Second RDTSC measurement
    rdtsc                       ; EDX:EAX = timestamp counter

    ; Calculate delta (second - first)
    ; Combine EDX:EAX into 64-bit value
    shl rdx, 32                 ; Shift EDX left by 32 bits
    or rax, rdx                 ; RAX = EDX:EAX (second timestamp)

    ; Combine R8D:EBX into 64-bit value
    shl r8, 32                  ; Shift R8 left by 32 bits
    mov r9d, ebx                ; R9D = EBX (low 32 bits of first timestamp)
    or r8, r9                   ; R8 = first timestamp

    ; Delta = second - first
    sub rax, r8                 ; RAX = delta for this iteration
    add rdi, rax                ; Accumulate delta

    ; Decrement iteration counter
    dec esi
    jnz timing_loop             ; Continue if ESI != 0

    ; Return accumulated delta
    mov rax, rdi
    jmp exit_timing

exit_timing_zero:
    xor rax, rax                ; Return 0

exit_timing:
    pop rdi                     ; Restore RDI
    pop rsi                     ; Restore RSI
    pop rbx                     ; Restore RBX
    ret
MeasureRDTSCTimingDelta ENDP

; ==============================================================================
; GetIDTBase
; Retrieves the Interrupt Descriptor Table (IDT) base address
;
; The SIDT instruction stores the IDT register into memory:
; - Bytes 0-1: Limit (size - 1)
; - Bytes 2-9: Base address (64-bit on x64)
;
; VMs often relocate IDT to higher memory addresses.
;
; Returns:
;   RAX = IDT base address (64-bit)
;
; extern "C" uint64_t GetIDTBase() noexcept;
; ==============================================================================
GetIDTBase PROC
    sub rsp, 10h                ; Allocate 16 bytes on stack for IDTR

    ; Store IDT register to stack
    sidt [rsp]                  ; SIDT stores 10 bytes: 2-byte limit + 8-byte base

    ; Load base address from stack (skip first 2 bytes which are limit)
    mov rax, qword ptr [rsp + 2]; RAX = IDT base address (bytes 2-9)

    add rsp, 10h                ; Deallocate stack space
    ret
GetIDTBase ENDP

; ==============================================================================
; GetGDTBase
; Retrieves the Global Descriptor Table (GDT) base address
;
; The SGDT instruction stores the GDT register into memory:
; - Bytes 0-1: Limit (size - 1)
; - Bytes 2-9: Base address (64-bit on x64)
;
; VMs often relocate GDT to higher memory addresses.
;
; Returns:
;   RAX = GDT base address (64-bit)
;
; extern "C" uint64_t GetGDTBase() noexcept;
; ==============================================================================
GetGDTBase PROC
    sub rsp, 10h                ; Allocate 16 bytes on stack for GDTR

    ; Store GDT register to stack
    sgdt [rsp]                  ; SGDT stores 10 bytes: 2-byte limit + 8-byte base

    ; Load base address from stack (skip first 2 bytes which are limit)
    mov rax, qword ptr [rsp + 2]; RAX = GDT base address (bytes 2-9)

    add rsp, 10h                ; Deallocate stack space
    ret
GetGDTBase ENDP

; ==============================================================================
; GetLDTSelector
; Retrieves the Local Descriptor Table (LDT) selector
;
; The SLDT instruction stores the LDT selector (16-bit segment selector).
;
; On bare metal, LDT is rarely used (selector = 0).
; Some VMs may use LDT, resulting in non-zero selector.
;
; Returns:
;   RAX = LDT selector (16-bit value in lower 16 bits, upper bits = 0)
;
; extern "C" uint16_t GetLDTSelector() noexcept;
; ==============================================================================
GetLDTSelector PROC
    xor rax, rax                ; Clear RAX

    ; Store LDT selector to AX
    sldt ax                     ; SLDT stores 16-bit selector in AX

    ; RAX now contains the LDT selector in lower 16 bits
    ret
GetLDTSelector ENDP

END

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

    mov r10, rcx        ; Save pEax
    mov r11, rdx        ; Save pEbx
    ; r8 (pEcx) and r9 (pEdx) are safe to keep as they are separate registers from eax-edx

    ; Load input values
    mov eax, dword ptr [r10]
    mov ebx, dword ptr [r11]
    mov ecx, dword ptr [r8]
    mov edx, dword ptr [r9]

    ; Execute VMware backdoor instruction (IN EAX, DX)
    ; This will read from I/O port specified in DX.
    in eax, dx

    ; Store output values
    mov dword ptr [r10], eax
    mov dword ptr [r11], ebx
    mov dword ptr [r8], ecx
    mov dword ptr [r9], edx

    pop rbx
    ret
CheckVMwareBackdoor ENDP
