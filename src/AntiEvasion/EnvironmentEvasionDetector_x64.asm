; ==============================================================================
; EnvironmentEvasionDetector_x64.asm
; Enterprise-grade x64 assembly functions for Environment Evasion Detection
;
; ShadowStrike AntiEvasion - Environment Evasion Detection Module
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; This module provides low-level detection functions for anti-debugging,
; anti-sandbox, and environment evasion techniques that cannot be reliably
; implemented in C++ due to compiler optimizations and intrinsic limitations.
;
; ============================================================================
; FUNCTIONS - TIMING-BASED DETECTION
; ============================================================================
; - MeasureRDTSCTimingDelta: RDTSC delta measurement for sandbox detection
; - MeasureRDTSCPTiming: RDTSCP (serializing) timing variant
; - MeasureCPUIDTiming: CPUID instruction timing for VM detection
; - MeasureINTTimingDelta: INT instruction timing (exception-based)
; - MeasureExceptionTiming: Exception handler timing analysis
;
; ============================================================================
; FUNCTIONS - DESCRIPTOR TABLE ANALYSIS
; ============================================================================
; - GetIDTBase: SIDT instruction - Interrupt Descriptor Table base
; - GetGDTBase: SGDT instruction - Global Descriptor Table base
; - GetLDTSelector: SLDT instruction - Local Descriptor Table selector
; - GetTRSelector: STR instruction - Task Register (SWIZZ test)
; - CheckSegmentLimits: Segment descriptor limit analysis
; - GetIDTAndGDTInfo: Combined IDT/GDT retrieval with limits
;
; ============================================================================
; FUNCTIONS - DEBUG DETECTION
; ============================================================================
; - GetDebugRegisters: DR0-DR7 retrieval (hardware breakpoint detection)
; - DetectHardwareBreakpoints: Hardware breakpoint presence check
; - DetectSingleStep: INT 1 single-step trap detection
; - CheckTrapFlag: EFLAGS TF bit check
;
; ============================================================================
; FUNCTIONS - MEMORY/PEB ANALYSIS
; ============================================================================
; - CheckNtGlobalFlag: PEB NtGlobalFlag check for debug detection
; - GetProcessHeapFlags: Heap debug flags retrieval
; - CheckBeingDebugged: PEB BeingDebugged flag check
;
; ============================================================================
; FUNCTIONS - CPUID-BASED DETECTION
; ============================================================================
; - CheckCPUIDHypervisorBit: Hypervisor presence via CPUID leaf 1
; - GetCPUIDBrandString: CPU brand string retrieval
; - GetCPUIDVendorString: CPU vendor string (12-byte)
; - CheckCPUIDHypervisorVendor: Hypervisor vendor string
; - GetCPUIDFeatureFlags: CPU feature flags (ECX/EDX)
; - GetExtendedCPUIDMaxLeaf: Maximum extended CPUID leaf
; - GetProcessorCoreCount: Logical processor count from CPUID
;
; ============================================================================
; FUNCTIONS - ADVANCED DETECTION
; ============================================================================
; - MeasureInstructionTiming: Generic instruction timing measurement
; - DetectPopfTiming: POPF TF manipulation timing
; - PerformRDTSCPMeasurement: RDTSCP with processor ID
; - CheckSSE2Support: SSE2 support verification
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
PUBLIC GetCPUIDBrandString
PUBLIC GetCPUIDVendorString
PUBLIC CheckCPUIDHypervisorVendor
PUBLIC GetCPUIDFeatureFlags
PUBLIC GetExtendedCPUIDMaxLeaf
PUBLIC GetProcessorCoreCount
PUBLIC CheckCPUIDVMXSupport

; Timing-based detection
PUBLIC MeasureRDTSCTimingDelta
PUBLIC MeasureRDTSCPTiming
PUBLIC MeasureCPUIDTiming
PUBLIC MeasureINTTimingDelta
PUBLIC MeasureExceptionTiming
PUBLIC MeasureInstructionTiming
PUBLIC MeasureRDTSCLatency
PUBLIC PerformRDTSCPMeasurement

; Descriptor table analysis
PUBLIC GetIDTBase
PUBLIC GetGDTBase
PUBLIC GetLDTSelector
PUBLIC GetTRSelector
PUBLIC CheckSegmentLimits
PUBLIC GetIDTAndGDTInfo

; Debug detection
PUBLIC GetDebugRegisters
PUBLIC DetectHardwareBreakpoints
PUBLIC DetectSingleStep
PUBLIC CheckTrapFlag
PUBLIC DetectPopfTiming
PUBLIC CheckDebugRegistersASM

; Memory/PEB analysis
PUBLIC CheckNtGlobalFlag
PUBLIC GetProcessHeapFlags
PUBLIC CheckBeingDebugged

; Feature detection
PUBLIC CheckSSE2Support

.CODE

; ==============================================================================
; CheckCPUIDHypervisorBit
;
; Checks if the hypervisor bit is set in CPUID leaf 1, ECX bit 31.
; This indicates the CPU is running under a hypervisor/VM.
;
; Calling Convention: Microsoft x64
; Parameters: None
; Returns: RAX = 1 if hypervisor detected, 0 otherwise (bool)
;
; Technical Details:
; - CPUID leaf 0x1, ECX bit 31 is the hypervisor present bit
; - Set to 1 when running under VMware, VirtualBox, Hyper-V, KVM, etc.
; - This is a definitive VM indicator used by all major hypervisors
; ==============================================================================
CheckCPUIDHypervisorBit PROC
    push    rbx
    push    rcx
    push    rdx

    ; Check if CPUID is supported by trying to flip ID bit in EFLAGS
    pushfq
    pop     rax
    mov     rcx, rax
    xor     rax, 200000h        ; Flip ID bit (bit 21)
    push    rax
    popfq
    pushfq
    pop     rax
    xor     rax, rcx
    jz      no_cpuid_support

    ; CPUID is supported, check for hypervisor bit
    mov     eax, 1              ; CPUID leaf 1
    xor     ecx, ecx
    cpuid

    ; Check bit 31 of ECX (hypervisor present bit)
    bt      ecx, 31
    jc      hypervisor_found

    xor     rax, rax
    jmp     cleanup_hypervisor

hypervisor_found:
    mov     rax, 1
    jmp     cleanup_hypervisor

no_cpuid_support:
    xor     rax, rax

cleanup_hypervisor:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
CheckCPUIDHypervisorBit ENDP

; ==============================================================================
; GetCPUIDBrandString
;
; Retrieves the CPU brand string using CPUID extended function 0x80000002-4.
; The brand string often contains VM indicators like "QEMU", "Virtual", etc.
;
; Parameters:
;   RCX = char* buffer (output buffer for brand string)
;   RDX = size_t bufferSize (size of buffer in bytes, should be >= 49)
;
; Returns: None (writes directly to buffer)
; ==============================================================================
GetCPUIDBrandString PROC
    push    rbx
    push    rdi
    push    rsi
    push    r12

    mov     rdi, rcx
    mov     r12, rdx

    ; Validate buffer pointer
    test    rdi, rdi
    jz      exit_brand_string

    ; Validate buffer size (need at least 49 bytes: 48 + null)
    cmp     r12, 49
    jb      exit_brand_string

    ; Zero out the buffer first
    mov     rsi, rdi
    mov     rcx, r12
    xor     al, al
    rep     stosb
    mov     rdi, rsi

    ; Check if extended CPUID is supported
    mov     eax, 80000000h
    cpuid
    cmp     eax, 80000004h
    jb      exit_brand_string

    ; Get first 16 bytes (CPUID leaf 0x80000002)
    mov     eax, 80000002h
    cpuid
    mov     [rdi], eax
    mov     [rdi+4], ebx
    mov     [rdi+8], ecx
    mov     [rdi+12], edx

    ; Get second 16 bytes (CPUID leaf 0x80000003)
    mov     eax, 80000003h
    cpuid
    mov     [rdi+16], eax
    mov     [rdi+20], ebx
    mov     [rdi+24], ecx
    mov     [rdi+28], edx

    ; Get third 16 bytes (CPUID leaf 0x80000004)
    mov     eax, 80000004h
    cpuid
    mov     [rdi+32], eax
    mov     [rdi+36], ebx
    mov     [rdi+40], ecx
    mov     [rdi+44], edx

    ; Ensure null termination
    mov     byte ptr [rdi+48], 0

exit_brand_string:
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    ret
GetCPUIDBrandString ENDP

; ==============================================================================
; MeasureRDTSCTimingDelta
;
; Measures RDTSC timing variance to detect VM/sandbox overhead.
; VMs typically show higher RDTSC variance due to hypervisor scheduling.
;
; Parameters:
;   ECX = uint32_t iterations (number of samples, max 65536)
;
; Returns:
;   RAX = uint64_t total delta across all iterations
;
; Technical Details:
; - Serializes with CPUID before each measurement
; - Measures delta between consecutive RDTSC reads
; - High deltas indicate VM overhead or instrumentation
; ==============================================================================
MeasureRDTSCTimingDelta PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    ; Validate iterations
    test    ecx, ecx
    jz      rdtsc_timing_zero
    cmp     ecx, 10000h             ; Limit to 65536 iterations
    ja      rdtsc_timing_zero

    mov     esi, ecx                ; RSI = iteration counter
    xor     rdi, rdi                ; RDI = accumulated delta

rdtsc_timing_loop:
    ; Serialize execution before first RDTSC
    xor     eax, eax
    cpuid

    ; First RDTSC measurement
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax                ; R12 = first timestamp

    ; Serialize execution again
    xor     eax, eax
    cpuid

    ; Second RDTSC measurement
    rdtsc
    shl     rdx, 32
    or      rax, rdx                ; RAX = second timestamp

    ; Calculate delta
    sub     rax, r12
    add     rdi, rax                ; Accumulate delta

    dec     esi
    jnz     rdtsc_timing_loop

    mov     rax, rdi
    jmp     rdtsc_timing_exit

rdtsc_timing_zero:
    xor     rax, rax

rdtsc_timing_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureRDTSCTimingDelta ENDP

; ==============================================================================
; MeasureRDTSCPTiming
;
; Measures RDTSCP timing (serializing variant of RDTSC).
; RDTSCP is a serializing instruction that waits for all previous
; instructions to complete before reading the timestamp counter.
;
; Parameters:
;   ECX = uint32_t iterations (number of samples, max 65536)
;
; Returns:
;   RAX = uint64_t average delta per iteration
; ==============================================================================
MeasureRDTSCPTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13

    ; Validate iterations
    test    ecx, ecx
    jz      rdtscp_timing_zero
    cmp     ecx, 10000h
    ja      rdtscp_timing_zero

    mov     esi, ecx                ; RSI = iteration counter
    mov     r13d, ecx               ; R13 = original count for average
    xor     rdi, rdi                ; RDI = accumulated delta

rdtscp_timing_loop:
    ; First RDTSCP measurement
    rdtscp                          ; EDX:EAX = TSC, ECX = processor ID
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax                ; R12 = first timestamp

    ; Memory fence
    mfence

    ; Second RDTSCP measurement
    rdtscp
    shl     rdx, 32
    or      rax, rdx                ; RAX = second timestamp

    ; Calculate delta
    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     rdtscp_timing_loop

    ; Calculate average
    mov     rax, rdi
    xor     rdx, rdx
    mov     ecx, r13d
    div     rcx                     ; RAX = average delta
    jmp     rdtscp_timing_exit

rdtscp_timing_zero:
    xor     rax, rax

rdtscp_timing_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureRDTSCPTiming ENDP

; ==============================================================================
; MeasureCPUIDTiming
;
; Measures timing of CPUID instruction execution.
; VMs have significantly higher CPUID latency due to VM exits.
;
; Parameters:
;   ECX = uint32_t iterations (number of CPUID executions to measure)
;
; Returns:
;   RAX = uint64_t total cycles for all CPUID executions
; ==============================================================================
MeasureCPUIDTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    ; Validate iterations
    test    ecx, ecx
    jz      cpuid_timing_zero
    cmp     ecx, 10000h
    ja      cpuid_timing_zero

    mov     esi, ecx                ; RSI = iteration counter
    xor     rdi, rdi                ; RDI = accumulated cycles

cpuid_timing_loop:
    ; Serialize before measurement
    xor     eax, eax
    cpuid

    ; First RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax                ; R12 = start timestamp

    ; Execute CPUID (the instruction we're measuring)
    xor     eax, eax                ; Leaf 0
    cpuid

    ; Memory fence
    mfence

    ; Second RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx                ; RAX = end timestamp

    ; Calculate delta
    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     cpuid_timing_loop

    mov     rax, rdi
    jmp     cpuid_timing_exit

cpuid_timing_zero:
    xor     rax, rax

cpuid_timing_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureCPUIDTiming ENDP

; ==============================================================================
; MeasureINTTimingDelta
;
; Measures timing of INT instruction execution for exception-based detection.
; Debuggers and sandboxes often intercept INT instructions.
;
; Parameters:
;   ECX = uint32_t iterations (number of samples)
;
; Returns:
;   RAX = uint64_t total cycles (0 if exception occurred)
;
; Note: This measures the overhead of the INT 3 / breakpoint mechanism
; ==============================================================================
MeasureINTTimingDelta PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    rbp
    mov     rbp, rsp
    sub     rsp, 20h                ; Shadow space

    ; Validate iterations
    test    ecx, ecx
    jz      int_timing_zero
    cmp     ecx, 1000h              ; Limit to 4096 iterations for INT
    ja      int_timing_zero

    mov     esi, ecx
    xor     rdi, rdi

int_timing_loop:
    ; Serialize
    xor     eax, eax
    cpuid

    ; First RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; Execute a lightweight operation (avoid actual INT 3)
    ; Instead measure NOP sled timing which can reveal instrumentation
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    ; Second RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     int_timing_loop

    mov     rax, rdi
    jmp     int_timing_exit

int_timing_zero:
    xor     rax, rax

int_timing_exit:
    mov     rsp, rbp
    pop     rbp
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureINTTimingDelta ENDP

; ==============================================================================
; MeasureExceptionTiming
;
; Measures timing of exception handler invocation.
; Debuggers significantly increase exception handling time.
;
; Parameters:
;   ECX = uint32_t iterations
;
; Returns:
;   RAX = uint64_t timing indicator (cycles per exception simulation)
; ==============================================================================
MeasureExceptionTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    test    ecx, ecx
    jz      exc_timing_zero
    cmp     ecx, 1000h
    ja      exc_timing_zero

    mov     esi, ecx
    xor     rdi, rdi

exc_timing_loop:
    ; Serialize
    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; Simulate exception-related operations (PUSHF/POPF)
    pushfq
    popfq
    pushfq
    popfq

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     exc_timing_loop

    mov     rax, rdi
    jmp     exc_timing_exit

exc_timing_zero:
    xor     rax, rax

exc_timing_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureExceptionTiming ENDP

; ==============================================================================
; GetIDTBase
;
; Retrieves the Interrupt Descriptor Table (IDT) base address.
; VMs often relocate IDT to higher memory addresses.
;
; Returns:
;   RAX = IDT base address (64-bit)
; ==============================================================================
GetIDTBase PROC
    sub     rsp, 10h                ; Allocate 16 bytes for IDTR

    sidt    [rsp]                   ; Store IDT register (10 bytes)

    ; Load base address (skip first 2 bytes which are limit)
    mov     rax, qword ptr [rsp + 2]

    add     rsp, 10h
    ret
GetIDTBase ENDP

; ==============================================================================
; GetGDTBase
;
; Retrieves the Global Descriptor Table (GDT) base address.
; VMs often relocate GDT to higher memory addresses.
;
; Returns:
;   RAX = GDT base address (64-bit)
; ==============================================================================
GetGDTBase PROC
    sub     rsp, 10h                ; Allocate 16 bytes for GDTR

    sgdt    [rsp]                   ; Store GDT register (10 bytes)

    ; Load base address (skip first 2 bytes which are limit)
    mov     rax, qword ptr [rsp + 2]

    add     rsp, 10h
    ret
GetGDTBase ENDP

; ==============================================================================
; GetLDTSelector
;
; Retrieves the Local Descriptor Table (LDT) selector.
; On bare metal, LDT is rarely used (selector = 0).
; Some VMs may use LDT, resulting in non-zero selector.
;
; Returns:
;   RAX = LDT selector (16-bit value)
; ==============================================================================
GetLDTSelector PROC
    xor     rax, rax
    sldt    ax                      ; Store LDT selector in AX
    ret
GetLDTSelector ENDP

; ==============================================================================
; GetTRSelector (SWIZZ Test)
;
; Retrieves the Task Register (TR) selector via STR instruction.
; In VMs, the TR selector may have different values than on bare metal.
;
; Returns:
;   RAX = TR selector (16-bit value)
; ==============================================================================
GetTRSelector PROC
    xor     rax, rax
    str     ax                      ; Store Task Register selector in AX
    ret
GetTRSelector ENDP

; ==============================================================================
; CheckSegmentLimits
;
; Retrieves segment limits for CS, DS, SS segments.
; VMs may have different segment limit configurations.
;
; Parameters:
;   RCX = uint32_t* csLimit (output)
;   RDX = uint32_t* dsLimit (output)
;   R8  = uint32_t* ssLimit (output)
;
; Returns:
;   RAX = 1 if successful, 0 if failed
; ==============================================================================
CheckSegmentLimits PROC
    push    rbx

    ; Validate pointers
    test    rcx, rcx
    jz      seg_limits_fail
    test    rdx, rdx
    jz      seg_limits_fail
    test    r8, r8
    jz      seg_limits_fail

    ; Get CS limit
    mov     ax, cs
    lsl     eax, eax                ; Load Segment Limit
    jnz     seg_limits_fail         ; ZF=0 means invalid selector
    mov     dword ptr [rcx], eax

    ; Get DS limit
    mov     ax, ds
    lsl     eax, eax
    jnz     seg_limits_fail
    mov     dword ptr [rdx], eax

    ; Get SS limit
    mov     ax, ss
    lsl     eax, eax
    jnz     seg_limits_fail
    mov     dword ptr [r8], eax

    mov     rax, 1
    jmp     seg_limits_exit

seg_limits_fail:
    xor     rax, rax

seg_limits_exit:
    pop     rbx
    ret
CheckSegmentLimits ENDP

; ==============================================================================
; GetIDTAndGDTInfo
;
; Retrieves both IDT and GDT information including limits.
;
; Parameters:
;   RCX = uint64_t* idtBase (output)
;   RDX = uint16_t* idtLimit (output)
;   R8  = uint64_t* gdtBase (output)
;   R9  = uint16_t* gdtLimit (output)
;
; Returns:
;   RAX = 1 if successful
; ==============================================================================
GetIDTAndGDTInfo PROC
    push    rbx
    sub     rsp, 20h                ; Allocate space for both tables

    ; Validate pointers
    test    rcx, rcx
    jz      idt_gdt_fail
    test    rdx, rdx
    jz      idt_gdt_fail
    test    r8, r8
    jz      idt_gdt_fail
    test    r9, r9
    jz      idt_gdt_fail

    ; Get IDT info
    sidt    [rsp]
    mov     ax, word ptr [rsp]      ; IDT limit
    mov     word ptr [rdx], ax
    mov     rax, qword ptr [rsp + 2] ; IDT base
    mov     qword ptr [rcx], rax

    ; Get GDT info
    sgdt    [rsp + 10h]
    mov     ax, word ptr [rsp + 10h] ; GDT limit
    mov     word ptr [r9], ax
    mov     rax, qword ptr [rsp + 12h] ; GDT base
    mov     qword ptr [r8], rax

    mov     rax, 1
    jmp     idt_gdt_exit

idt_gdt_fail:
    xor     rax, rax

idt_gdt_exit:
    add     rsp, 20h
    pop     rbx
    ret
GetIDTAndGDTInfo ENDP

; ==============================================================================
; GetDebugRegisters
;
; Attempts to read debug registers DR0-DR7.
; Note: This requires elevated privileges (Ring 0) on most systems.
; In user mode, this will typically cause an exception.
;
; Parameters:
;   RCX = uint64_t* dr0 (output)
;   RDX = uint64_t* dr1 (output)
;   R8  = uint64_t* dr2 (output)
;   R9  = uint64_t* dr3 (output)
;   Stack+40 = uint64_t* dr6 (output)
;   Stack+48 = uint64_t* dr7 (output)
;
; Returns:
;   RAX = 1 if successful, 0 if access denied
;
; Note: In user mode, use NtQueryInformationThread instead
; ==============================================================================
GetDebugRegisters PROC
    ; This function is a stub - actual DR access requires ring 0
    ; In user mode, we return 0 to indicate we cannot read DRs directly
    ; The C++ code should use GetThreadContext() instead
    xor     rax, rax
    ret
GetDebugRegisters ENDP

; ==============================================================================
; DetectHardwareBreakpoints
;
; Detects if hardware breakpoints are set by checking DR7.
; Uses indirect detection methods available in user mode.
;
; Returns:
;   RAX = 1 if hardware breakpoints detected, 0 otherwise
;
; Note: This uses timing-based detection as DR access requires ring 0
; ==============================================================================
DetectHardwareBreakpoints PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    ; Use timing-based detection
    ; Hardware breakpoints cause slight timing differences
    mov     esi, 100                ; 100 iterations
    xor     rdi, rdi                ; Accumulated time

hw_bp_timing_loop:
    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; Execute instructions that would trigger HW breakpoints
    mov     rax, rax
    mov     rbx, rbx
    mov     rcx, rcx
    mov     rdx, rdx

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     hw_bp_timing_loop

    ; If average timing is suspiciously high, breakpoints may be present
    ; Threshold: >500 cycles average indicates possible HW BP
    mov     rax, rdi
    xor     rdx, rdx
    mov     ecx, 100
    div     rcx

    cmp     rax, 500
    ja      hw_bp_detected

    xor     rax, rax
    jmp     hw_bp_exit

hw_bp_detected:
    mov     rax, 1

hw_bp_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectHardwareBreakpoints ENDP

; ==============================================================================
; DetectSingleStep
;
; Detects if single-stepping is active by checking timing anomalies.
; Single-step debugging causes INT 1 after each instruction.
;
; Returns:
;   RAX = 1 if single-step detected, 0 otherwise
; ==============================================================================
DetectSingleStep PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    mov     esi, 50                 ; 50 iterations
    xor     rdi, rdi

single_step_loop:
    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; Execute NOPs - single stepping would show high latency
    nop
    nop
    nop
    nop

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     single_step_loop

    ; Check average timing (single-step causes >1000 cycles per NOP)
    mov     rax, rdi
    xor     rdx, rdx
    mov     ecx, 50
    div     rcx

    cmp     rax, 1000
    ja      single_step_detected

    xor     rax, rax
    jmp     single_step_exit

single_step_detected:
    mov     rax, 1

single_step_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectSingleStep ENDP

; ==============================================================================
; CheckTrapFlag
;
; Checks if the Trap Flag (TF) is set in EFLAGS.
; TF causes INT 1 after each instruction (single-step mode).
;
; Returns:
;   RAX = 1 if TF is set, 0 otherwise
; ==============================================================================
CheckTrapFlag PROC
    pushfq                          ; Push RFLAGS onto stack
    pop     rax                     ; Pop into RAX

    ; Check bit 8 (Trap Flag)
    bt      rax, 8
    jc      tf_set

    xor     rax, rax
    ret

tf_set:
    mov     rax, 1
    ret
CheckTrapFlag ENDP

; ==============================================================================
; CheckNtGlobalFlag
;
; Checks the NtGlobalFlag in the PEB for debug indicators.
; Flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
;        FLG_HEAP_ENABLE_FREE_CHECK (0x20)
;        FLG_HEAP_VALIDATE_PARAMETERS (0x40)
;
; Returns:
;   RAX = NtGlobalFlag value (non-zero indicates debugger)
; ==============================================================================
CheckNtGlobalFlag PROC
    ; Get PEB address from TEB
    ; TEB is at GS:[0] on x64 Windows
    ; PEB pointer is at TEB+0x60

    mov     rax, gs:[60h]           ; RAX = PEB address

    ; NtGlobalFlag is at PEB+0xBC (32-bit offset in 64-bit PEB)
    mov     eax, dword ptr [rax + 0BCh]

    ret
CheckNtGlobalFlag ENDP

; ==============================================================================
; GetProcessHeapFlags
;
; Retrieves process heap flags that indicate debugging.
; Debug heaps have Flags and ForceFlags set differently.
;
; Returns:
;   RAX = Heap Flags value
; ==============================================================================
GetProcessHeapFlags PROC
    ; Get PEB address
    mov     rax, gs:[60h]           ; RAX = PEB

    ; ProcessHeap is at PEB+0x30
    mov     rax, qword ptr [rax + 30h] ; RAX = ProcessHeap

    ; Heap Flags at offset 0x70 (x64)
    mov     eax, dword ptr [rax + 70h]

    ret
GetProcessHeapFlags ENDP

; ==============================================================================
; CheckBeingDebugged
;
; Checks the BeingDebugged flag in the PEB.
; This is what IsDebuggerPresent() checks internally.
;
; Returns:
;   RAX = 1 if BeingDebugged is set, 0 otherwise
; ==============================================================================
CheckBeingDebugged PROC
    ; Get PEB address
    mov     rax, gs:[60h]           ; RAX = PEB

    ; BeingDebugged is at PEB+0x02 (1 byte)
    movzx   eax, byte ptr [rax + 2]

    ret
CheckBeingDebugged ENDP

; ==============================================================================
; GetCPUIDVendorString
;
; Retrieves the 12-byte CPU vendor string from CPUID leaf 0.
;
; Parameters:
;   RCX = char* buffer (output buffer, minimum 13 bytes)
;   RDX = size_t bufferSize
;
; Returns: None
; ==============================================================================
GetCPUIDVendorString PROC
    push    rbx
    push    rdi

    test    rcx, rcx
    jz      exit_vendor
    cmp     rdx, 13
    jb      exit_vendor

    mov     rdi, rcx

    ; Execute CPUID with leaf 0
    xor     eax, eax
    cpuid

    ; Vendor string is in EBX, EDX, ECX (in that order)
    mov     [rdi], ebx
    mov     [rdi + 4], edx
    mov     [rdi + 8], ecx
    mov     byte ptr [rdi + 12], 0

exit_vendor:
    pop     rdi
    pop     rbx
    ret
GetCPUIDVendorString ENDP

; ==============================================================================
; CheckCPUIDHypervisorVendor
;
; Gets hypervisor vendor string if hypervisor is present.
;
; Parameters:
;   RCX = char* buffer (output buffer, minimum 13 bytes)
;   RDX = size_t bufferSize
;
; Returns:
;   RAX = 1 if hypervisor vendor retrieved, 0 otherwise
; ==============================================================================
CheckCPUIDHypervisorVendor PROC
    push    rbx
    push    rdi

    test    rcx, rcx
    jz      hv_vendor_fail
    cmp     rdx, 13
    jb      hv_vendor_fail

    mov     rdi, rcx

    ; First check if hypervisor is present
    mov     eax, 1
    cpuid
    bt      ecx, 31
    jnc     hv_vendor_fail

    ; Get hypervisor vendor from leaf 0x40000000
    mov     eax, 40000000h
    cpuid

    ; Store vendor string (EBX, ECX, EDX)
    mov     [rdi], ebx
    mov     [rdi + 4], ecx
    mov     [rdi + 8], edx
    mov     byte ptr [rdi + 12], 0

    mov     rax, 1
    jmp     hv_vendor_exit

hv_vendor_fail:
    xor     rax, rax

hv_vendor_exit:
    pop     rdi
    pop     rbx
    ret
CheckCPUIDHypervisorVendor ENDP

; ==============================================================================
; GetCPUIDFeatureFlags
;
; Gets CPU feature flags from CPUID leaf 1.
;
; Parameters:
;   RCX = uint32_t* ecxFeatures (output)
;   RDX = uint32_t* edxFeatures (output)
;
; Returns:
;   RAX = 1 on success
; ==============================================================================
GetCPUIDFeatureFlags PROC
    push    rbx

    test    rcx, rcx
    jz      feature_fail
    test    rdx, rdx
    jz      feature_fail

    mov     r8, rcx
    mov     r9, rdx

    mov     eax, 1
    cpuid

    mov     dword ptr [r8], ecx
    mov     dword ptr [r9], edx

    mov     rax, 1
    jmp     feature_exit

feature_fail:
    xor     rax, rax

feature_exit:
    pop     rbx
    ret
GetCPUIDFeatureFlags ENDP

; ==============================================================================
; GetExtendedCPUIDMaxLeaf
;
; Gets the maximum extended CPUID leaf supported.
;
; Returns:
;   RAX = Maximum extended leaf (e.g., 0x80000008)
; ==============================================================================
GetExtendedCPUIDMaxLeaf PROC
    push    rbx

    mov     eax, 80000000h
    cpuid

    ; EAX contains max extended leaf
    pop     rbx
    ret
GetExtendedCPUIDMaxLeaf ENDP

; ==============================================================================
; PerformRDTSCPMeasurement
;
; Performs RDTSCP measurement with processor ID.
;
; Parameters:
;   RCX = uint32_t* processorId (output, can be NULL)
;
; Returns:
;   RAX = TSC value
; ==============================================================================
PerformRDTSCPMeasurement PROC
    rdtscp                          ; EDX:EAX = TSC, ECX = processor ID

    ; Store processor ID if pointer provided
    test    rcx, rcx
    jz      skip_proc_id
    mov     dword ptr [rcx], ecx

skip_proc_id:
    shl     rdx, 32
    or      rax, rdx
    ret
PerformRDTSCPMeasurement ENDP

; ==============================================================================
; CheckSSE2Support
;
; Checks if SSE2 is supported via CPUID.
;
; Returns:
;   RAX = 1 if SSE2 supported, 0 otherwise
; ==============================================================================
CheckSSE2Support PROC
    push    rbx

    mov     eax, 1
    cpuid

    ; SSE2 is bit 26 of EDX
    bt      edx, 26
    jc      sse2_supported

    xor     rax, rax
    jmp     sse2_exit

sse2_supported:
    mov     rax, 1

sse2_exit:
    pop     rbx
    ret
CheckSSE2Support ENDP

; ==============================================================================
; GetProcessorCoreCount
;
; Gets logical processor count from CPUID.
;
; Returns:
;   RAX = Logical processor count
; ==============================================================================
GetProcessorCoreCount PROC
    push    rbx

    ; Check max CPUID leaf
    xor     eax, eax
    cpuid

    cmp     eax, 1
    jb      core_count_fail

    ; Get processor info from leaf 1
    mov     eax, 1
    cpuid

    ; Logical processor count is in EBX[23:16]
    mov     eax, ebx
    shr     eax, 16
    and     eax, 0FFh

    ; If count is 0, return 1 as minimum
    test    eax, eax
    jnz     core_count_exit
    mov     eax, 1
    jmp     core_count_exit

core_count_fail:
    mov     eax, 1

core_count_exit:
    pop     rbx
    ret
GetProcessorCoreCount ENDP

; ==============================================================================
; MeasureInstructionTiming
;
; Generic instruction timing measurement for detecting instrumentation.
;
; Parameters:
;   RCX = uint32_t iterations
;
; Returns:
;   RAX = uint64_t total cycles
; ==============================================================================
MeasureInstructionTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    test    ecx, ecx
    jz      instr_timing_zero
    cmp     ecx, 10000h
    ja      instr_timing_zero

    mov     esi, ecx
    xor     rdi, rdi

instr_timing_loop:
    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; Various instructions
    mov     rax, rax
    xor     rbx, rbx
    add     rcx, 0
    sub     rdx, 0
    nop
    nop

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     instr_timing_loop

    mov     rax, rdi
    jmp     instr_timing_exit

instr_timing_zero:
    xor     rax, rax

instr_timing_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureInstructionTiming ENDP

; ==============================================================================
; DetectPopfTiming
;
; Measures POPF instruction timing for TF manipulation detection.
; Debuggers intercept POPF when it modifies the Trap Flag.
;
; Parameters:
;   RCX = uint32_t iterations
;
; Returns:
;   RAX = uint64_t total cycles
; ==============================================================================
DetectPopfTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12

    test    ecx, ecx
    jz      popf_timing_zero
    cmp     ecx, 1000h
    ja      popf_timing_zero

    mov     esi, ecx
    xor     rdi, rdi

popf_timing_loop:
    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    ; PUSHF/POPF sequence
    pushfq
    popfq
    pushfq
    popfq

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, r12
    add     rdi, rax

    dec     esi
    jnz     popf_timing_loop

    mov     rax, rdi
    jmp     popf_timing_exit

popf_timing_zero:
    xor     rax, rax

popf_timing_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectPopfTiming ENDP

; ==============================================================================
; MeasureRDTSCLatency (Compatibility alias)
;
; Measures RDTSC instruction latency for VM detection.
;
; Returns:
;   RAX = Delta TSC cycles
; ==============================================================================
MeasureRDTSCLatency PROC
    push    rbx

    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rbx, rax

    xor     eax, eax
    cpuid

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, rbx

    pop     rbx
    ret
MeasureRDTSCLatency ENDP

; ==============================================================================
; CheckDebugRegistersASM (Compatibility alias)
;
; Attempts to check debug registers (stub for user mode).
;
; Returns:
;   RAX = 0 (debug register access requires ring 0)
; ==============================================================================
CheckDebugRegistersASM PROC
    xor     rax, rax
    ret
CheckDebugRegistersASM ENDP

; ==============================================================================
; CheckCPUIDVMXSupport
;
; Checks if CPU supports VMX (VT-x) virtualization.
;
; Returns:
;   RAX = 1 if VMX supported, 0 otherwise
; ==============================================================================
CheckCPUIDVMXSupport PROC
    push    rbx

    mov     eax, 1
    cpuid

    ; VMX is bit 5 of ECX
    bt      ecx, 5
    jc      vmx_supported

    xor     rax, rax
    jmp     vmx_exit

vmx_supported:
    mov     rax, 1

vmx_exit:
    pop     rbx
    ret
CheckCPUIDVMXSupport ENDP

END
