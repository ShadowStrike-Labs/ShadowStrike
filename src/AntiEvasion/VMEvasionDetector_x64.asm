; ==============================================================================
; VMEvasionDetector_x64.asm
; Enterprise-grade x64 assembly functions for VM detection
;
; ShadowStrike AntiEvasion - VM Evasion Detection Module
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; FUNCTIONS (Original):
; - CheckCPUIDHypervisorBit: Checks CPUID leaf 0x1, ECX bit 31 for hypervisor
; - GetCPUIDVendorString: Retrieves 12-byte vendor string from CPUID 0x40000000
; - MeasureRDTSCTimingDelta: Measures RDTSC timing variance (VM overhead detection)
; - GetIDTBase: Retrieves IDT base address via SIDT instruction
; - GetGDTBase: Retrieves GDT base address via SGDT instruction
; - GetLDTSelector: Retrieves LDT selector via SLDT instruction
; - CheckVMwareBackdoor: VMware I/O port backdoor communication
;
; FUNCTIONS (Enterprise Enhancement):
; - GetTRSelector: Retrieves Task Register selector via STR instruction (SWIZZ test)
; - MeasureCPUIDTiming: Measures CPUID instruction latency for VM detection
; - CheckVirtualBoxBackdoor: VirtualBox I/O port probe
; - CheckHyperVBackdoor: Hyper-V hypercall interface detection
; - GetExtendedCPUIDInfo: Extended CPUID queries with all registers
; - CheckSegmentLimits: Segment descriptor limit analysis
; - MeasureInstructionTiming: Generic instruction timing measurement
; - DetectVMCALL: Intel VT-x hypercall detection
; - DetectVMMCALL: AMD-V hypercall detection
; - GetMSR: Read Model-Specific Register (requires ring 0)
; - CheckCPUIDLeafRange: Validates hypervisor CPUID leaf range
;
; CALLING CONVENTION: Microsoft x64 calling convention
; - First 4 args: RCX, RDX, R8, R9
; - Return: RAX (integers), XMM0 (floats)
; - Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
; - Callee-saved: RBX, RBP, RDI, RSI, RSP, R12-R15
; ==============================================================================

; ==============================================================================
; PUBLIC SYMBOL EXPORTS
; 
; These PUBLIC declarations are REQUIRED for the linker to find these functions.
; Without PUBLIC, MASM treats procedures as internal-only symbols.
; ==============================================================================

; CPUID-based detection
PUBLIC CheckCPUIDHypervisorBit
PUBLIC GetCPUIDVendorString
PUBLIC GetExtendedCPUIDInfo
PUBLIC CheckCPUIDLeafRange

; Timing-based detection
PUBLIC MeasureRDTSCTimingDelta
PUBLIC MeasureRDTSCPTiming
PUBLIC MeasureCPUIDTiming
PUBLIC MeasureInstructionTiming

; Descriptor table analysis
PUBLIC GetIDTBase
PUBLIC GetGDTBase
PUBLIC GetLDTSelector
PUBLIC GetTRSelector
PUBLIC GetIDTAndGDTInfo
PUBLIC CheckSegmentLimits

; VM-specific backdoor detection
PUBLIC CheckVMwareBackdoor
PUBLIC CheckHyperVBackdoor
PUBLIC DetectVMCALL
PUBLIC DetectVMMCALL

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

    ; Store vendor string (12 bytes total: EBX, EDX, ECX - standard order)
    mov [rdi + 0], ebx          ; Bytes 0-3
    mov [rdi + 4], edx          ; Bytes 4-7
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
    xor eax, eax
    cpuid                       ; CPUID serializes (clobbers EAX, EBX, ECX, EDX)

    ; First RDTSC measurement
    rdtsc                       ; EDX:EAX = timestamp counter
    mov ebx, eax                ; Save low 32 bits in EBX
    mov r8d, edx                ; Save high 32 bits in R8D

    ; Serialize execution again
    xor eax, eax
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
CheckVMwareBackdoor ENDP

; ==============================================================================
; GetTRSelector (SWIZZ Test) - ENTERPRISE ENHANCEMENT
; Retrieves the Task Register (TR) selector via STR instruction
;
; The STR instruction stores the segment selector from the Task Register.
; In VMs, the TR selector may have different values than on bare metal.
; This is known as the "SWIZZ" test for VM detection.
;
; Returns:
;   RAX = TR selector (16-bit value in lower 16 bits)
;
; extern "C" uint16_t GetTRSelector() noexcept;
; ==============================================================================
GetTRSelector PROC
    xor rax, rax                ; Clear RAX

    ; Store Task Register selector to AX
    str ax                      ; STR stores 16-bit selector in AX

    ; RAX now contains the TR selector in lower 16 bits
    ret
GetTRSelector ENDP

; ==============================================================================
; MeasureCPUIDTiming - ENTERPRISE ENHANCEMENT
; Measures timing of CPUID instruction execution
;
; VMs have significantly higher CPUID latency due to VM exits.
; This function measures the cycle count for executing CPUID leaf 0.
;
; Arguments:
;   ECX = uint32_t iterations (number of CPUID executions to measure)
;
; Returns:
;   RAX = uint64_t total cycles for all CPUID executions
;
; extern "C" uint64_t MeasureCPUIDTiming(uint32_t iterations) noexcept;
; ==============================================================================
MeasureCPUIDTiming PROC
    push rbx                    ; Save RBX (callee-saved)
    push rsi                    ; Save RSI (callee-saved)
    push rdi                    ; Save RDI (callee-saved)
    push r12                    ; Save R12 (callee-saved)

    ; Validate iterations
    test ecx, ecx               ; Check if iterations == 0
    jz cpuid_timing_zero
    cmp ecx, 10000h             ; Limit to 65536 iterations
    jg cpuid_timing_zero

    mov esi, ecx                ; RSI = iteration counter
    xor rdi, rdi                ; RDI = accumulated cycles (0)

cpuid_timing_loop:
    ; Serialize before measurement
    xor eax, eax
    cpuid                       ; Serialize

    ; First RDTSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax                ; R12 = start timestamp

    ; Execute CPUID (the instruction we're measuring)
    xor eax, eax                ; Leaf 0
    cpuid

    ; Serialize after
    mfence

    ; Second RDTSC
    rdtsc
    shl rdx, 32
    or rax, rdx                 ; RAX = end timestamp

    ; Calculate delta
    sub rax, r12                ; RAX = cycles for this CPUID
    add rdi, rax                ; Accumulate

    ; Loop
    dec esi
    jnz cpuid_timing_loop

    mov rax, rdi                ; Return accumulated cycles
    jmp cpuid_timing_exit

cpuid_timing_zero:
    xor rax, rax                ; Return 0

cpuid_timing_exit:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
MeasureCPUIDTiming ENDP

; ==============================================================================
; CheckHyperVBackdoor - ENTERPRISE ENHANCEMENT
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
; GetExtendedCPUIDInfo - ENTERPRISE ENHANCEMENT
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
    mov r10, qword ptr [rsp + 64]   ; pEcx (5th param) - FIXED offset
    test r10, r10
    jz skip_store_ecx
    mov dword ptr [r10], ecx
skip_store_ecx:

    mov r10, qword ptr [rsp + 72]   ; pEdx (6th param) - FIXED offset
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
; CheckSegmentLimits - ENTERPRISE ENHANCEMENT
; Checks segment descriptor limits for VM detection
;
; Arguments:
;   RCX = uint32_t* pCSLimit (Output)
;   RDX = uint32_t* pDSLimit (Output)
;   R8  = uint32_t* pSSLimit (Output)
;
; Returns:
;   RAX = 1 if limits retrieved successfully, 0 on failure
;
; extern "C" bool CheckSegmentLimits(uint32_t* csLimit, uint32_t* dsLimit, uint32_t* ssLimit) noexcept;
; ==============================================================================
CheckSegmentLimits PROC
    push rbx
    push rdi
    push rsi

    mov rdi, rcx                ; Save pCSLimit
    mov rsi, rdx                ; Save pDSLimit

    ; Get CS limit
    mov ax, cs
    lsl eax, eax                ; Load Segment Limit
    jnz seg_limits_fail         ; ZF=0 means failure
    test rdi, rdi
    jz skip_cs_limit
    mov dword ptr [rdi], eax
skip_cs_limit:

    ; Get DS limit
    mov ax, ds
    lsl ebx, eax
    jnz seg_limits_fail
    test rsi, rsi
    jz skip_ds_limit
    mov dword ptr [rsi], ebx
skip_ds_limit:

    ; Get SS limit
    mov ax, ss
    lsl eax, eax
    jnz seg_limits_fail
    test r8, r8
    jz skip_ss_limit
    mov dword ptr [r8], eax
skip_ss_limit:

    mov rax, 1                  ; Success
    jmp seg_limits_exit

seg_limits_fail:
    xor rax, rax                ; Failure

seg_limits_exit:
    pop rsi
    pop rdi
    pop rbx
    ret
CheckSegmentLimits ENDP

; ==============================================================================
; MeasureInstructionTiming - ENTERPRISE ENHANCEMENT
; Generic timing measurement for instruction sequences
;
; Arguments:
;   ECX = uint32_t iterations
;   EDX = uint32_t instructionType (0=NOP, 1=CPUID, 2=RDMSR dummy)
;
; Returns:
;   RAX = uint64_t total cycles for all iterations
;
; extern "C" uint64_t MeasureInstructionTiming(uint32_t iterations, uint32_t instructionType) noexcept;
; ==============================================================================
MeasureInstructionTiming PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    test ecx, ecx
    jz instr_timing_zero
    cmp ecx, 10000h
    jg instr_timing_zero

    mov esi, ecx                ; iteration count
    mov r13d, edx               ; instruction type
    xor rdi, rdi                ; accumulated cycles

instr_timing_loop:
    ; Serialize
    xor eax, eax
    cpuid

    ; Start timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax

    ; Execute target instruction based on type
    cmp r13d, 0
    je instr_timing_nop
    cmp r13d, 1
    je instr_timing_cpuid
    jmp instr_timing_nop        ; Default to NOP

instr_timing_nop:
    ; Execute 16 NOPs as baseline
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jmp instr_timing_end

instr_timing_cpuid:
    xor eax, eax
    cpuid
    jmp instr_timing_end

instr_timing_end:
    ; Serialize
    mfence

    ; End timing
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r12
    add rdi, rax

    dec esi
    jnz instr_timing_loop

    mov rax, rdi
    jmp instr_timing_exit

instr_timing_zero:
    xor rax, rax

instr_timing_exit:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
MeasureInstructionTiming ENDP

; ==============================================================================
; DetectVMCALL - ENTERPRISE ENHANCEMENT
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
; DetectVMMCALL - ENTERPRISE ENHANCEMENT
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
; CheckCPUIDLeafRange - ENTERPRISE ENHANCEMENT
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

; ==============================================================================
; GetIDTAndGDTInfo - ENTERPRISE ENHANCEMENT
; Retrieves both IDT and GDT information in a single call
;
; Arguments:
;   RCX = uint64_t* pIDTBase (Output)
;   RDX = uint16_t* pIDTLimit (Output)
;   R8  = uint64_t* pGDTBase (Output)
;   R9  = uint16_t* pGDTLimit (Output)
;
; Returns:
;   RAX = 1 (always succeeds)
;
; extern "C" bool GetIDTAndGDTInfo(uint64_t* idtBase, uint16_t* idtLimit,
;                                   uint64_t* gdtBase, uint16_t* gdtLimit) noexcept;
; ==============================================================================
GetIDTAndGDTInfo PROC
    sub rsp, 20h                ; Allocate space for both IDTR and GDTR (16 bytes each)

    ; Get IDTR
    sidt [rsp]
    test rcx, rcx
    jz skip_idt_base
    mov rax, qword ptr [rsp + 2]
    mov qword ptr [rcx], rax
skip_idt_base:
    test rdx, rdx
    jz skip_idt_limit
    movzx eax, word ptr [rsp]
    mov word ptr [rdx], ax
skip_idt_limit:

    ; Get GDTR
    sgdt [rsp + 10h]
    test r8, r8
    jz skip_gdt_base
    mov rax, qword ptr [rsp + 12h]
    mov qword ptr [r8], rax
skip_gdt_base:
    test r9, r9
    jz skip_gdt_limit
    movzx eax, word ptr [rsp + 10h]
    mov word ptr [r9], ax
skip_gdt_limit:

    mov rax, 1
    add rsp, 20h
    ret
GetIDTAndGDTInfo ENDP

; ==============================================================================
; MeasureRDTSCPTiming - ENTERPRISE ENHANCEMENT
; Measures RDTSCP instruction timing (serializing version of RDTSC)
;
; RDTSCP is a serializing instruction that also returns processor ID.
; VMs may handle this differently than RDTSC.
;
; Arguments:
;   ECX = uint32_t iterations
;
; Returns:
;   RAX = uint64_t total cycles
;
; extern "C" uint64_t MeasureRDTSCPTiming(uint32_t iterations) noexcept;
; ==============================================================================
MeasureRDTSCPTiming PROC
    push rbx
    push rsi
    push rdi
    push r12

    test ecx, ecx
    jz rdtscp_timing_zero
    cmp ecx, 10000h
    jg rdtscp_timing_zero

    mov esi, ecx
    xor rdi, rdi

rdtscp_timing_loop:
    ; Use RDTSCP for serialized read
    rdtscp                      ; EDX:EAX = TSC, ECX = processor ID
    shl rdx, 32
    or rax, rdx
    mov r12, rax                ; Start time

    ; Small delay
    lfence

    ; Second RDTSCP
    rdtscp
    shl rdx, 32
    or rax, rdx

    sub rax, r12
    add rdi, rax

    dec esi
    jnz rdtscp_timing_loop

    mov rax, rdi
    jmp rdtscp_timing_exit

rdtscp_timing_zero:
    xor rax, rax

rdtscp_timing_exit:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
MeasureRDTSCPTiming ENDP

END
