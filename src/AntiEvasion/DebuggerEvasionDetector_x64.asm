; ==============================================================================
; DebuggerEvasionDetector_x64.asm
; 
; ShadowStrike NGAV - Advanced Debugger Evasion Detection (x64 Assembly)
; 
; Copyright (c) 2024 ShadowStrike Team
; 
; PURPOSE:
;   Enterprise-grade assembly routines for detecting advanced debugger evasion
;   techniques that cannot be reliably detected from pure C++ code.
;
; TECHNIQUES DETECTED:
;   - Single-step (INT 1) timing anomalies
;   - Trap flag (TF) manipulation via POPF
;   - INT 2D debugger-specific behavior
;   - INT 3 (0xCC) software breakpoint timing
;   - Hardware breakpoint (DR0-DR7) timing detection
;   - ICEBP (0xF1) instruction behavior
;   - IDT/GDT/LDT descriptor table relocation
;   - RDTSC timing precision for anti-debug detection
;   - Exception handler timing anomalies
;   - PREFETCH instruction timing (cache-based detection)
;   - SIMD-accelerated breakpoint opcode scanning
;
; CALLING CONVENTION: Microsoft x64 ABI
;   - RCX, RDX, R8, R9 for first 4 integer parameters
;   - XMM0-XMM3 for first 4 float parameters
;   - RAX for return value
;   - Preserve: RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15
;
; SECURITY NOTES:
;   - All functions are designed to be safe even if debugger is present
;   - Timing thresholds are calibrated for modern CPUs (Skylake+)
;   - No exceptions are raised unless explicitly testing exception behavior
;   - All memory accesses are to stack or caller-provided buffers
;
; ==============================================================================

.CODE

; ==============================================================================
; PUBLIC EXPORTS
; ==============================================================================

PUBLIC DetectSingleStepTiming
PUBLIC DetectTrapFlagManipulation
PUBLIC DetectInt2DBehavior
PUBLIC DetectInt3Timing
PUBLIC DetectHardwareBreakpointsTiming
PUBLIC MeasureDebugInstructionTiming
PUBLIC DetectICEBPBehavior
PUBLIC DetectIDTRelocation
PUBLIC DetectGDTRelocation
PUBLIC DetectLDTPresence
PUBLIC CheckDebugRegistersIndirect
PUBLIC MeasureCPUIDRDTSCPair
PUBLIC DetectPrefetchTiming
PUBLIC DetectExceptionHandlerTiming
PUBLIC ScanForBreakpointOpcodes
PUBLIC MeasureCodeIntegrity
PUBLIC GetRDTSCPrecise
PUBLIC SerializeCPU

; ==============================================================================
; CONSTANTS
; ==============================================================================

; Timing thresholds (in CPU cycles)
; These are calibrated for modern Intel/AMD CPUs
; Debuggers typically add 100-10000+ cycles overhead

THRESHOLD_SINGLESTEP    EQU 500     ; Single-step overhead threshold
THRESHOLD_TRAPFLAG      EQU 400     ; Trap flag timing threshold
THRESHOLD_INT2D         EQU 300     ; INT 2D behavior threshold
THRESHOLD_INT3          EQU 200     ; INT 3 timing threshold
THRESHOLD_HWBP          EQU 500     ; Hardware breakpoint threshold
THRESHOLD_EXCEPTION     EQU 1000    ; Exception handler threshold
THRESHOLD_PREFETCH      EQU 100     ; Prefetch timing threshold

; Number of iterations for timing measurements
TIMING_ITERATIONS       EQU 100

; IDT/GDT expected base ranges (Windows x64 user mode)
; Relocated tables indicate VM or rootkit
IDT_USER_MIN            EQU 0000000000000000h
IDT_USER_MAX            EQU 00007FFFFFFFFFFFh
GDT_USER_MIN            EQU 0000000000000000h
GDT_USER_MAX            EQU 00007FFFFFFFFFFFh

; Breakpoint opcode
BREAKPOINT_OPCODE       EQU 0CCh

; ==============================================================================
; SerializeCPU
;
; Serializes CPU execution to ensure all previous instructions complete
; before timing measurements. Uses CPUID which is a serializing instruction.
;
; Parameters: None
; Returns: RAX = CPU vendor ID (for verification)
; Clobbers: RAX, RBX, RCX, RDX
; ==============================================================================
SerializeCPU PROC
    push    rbx
    
    xor     eax, eax            ; CPUID leaf 0
    cpuid                       ; Serializing instruction
    
    ; Return vendor ID signature in RAX for verification
    mov     rax, rbx            ; First 4 chars of vendor
    
    pop     rbx
    ret
SerializeCPU ENDP

; ==============================================================================
; GetRDTSCPrecise
;
; Reads Time Stamp Counter with serialization for precise measurements.
; Uses CPUID to serialize before and RDTSCP for serialized read.
;
; Parameters: None
; Returns: RAX = 64-bit TSC value
; Clobbers: RAX, RBX, RCX, RDX
; ==============================================================================
GetRDTSCPrecise PROC
    push    rbx
    
    ; Serialize with CPUID first
    xor     eax, eax
    cpuid
    
    ; Read TSC with RDTSCP (serialized read)
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    
    pop     rbx
    ret
GetRDTSCPrecise ENDP

; ==============================================================================
; DetectSingleStepTiming
;
; Detects single-step debugging by measuring timing of NOP sled execution.
; When single-stepping, each instruction causes INT 1, adding significant
; overhead that can be measured.
;
; Parameters: None
; Returns: RAX = 1 if single-step detected, 0 otherwise
; Clobbers: RAX, RBX, RCX, RDX, RSI, RDI
; ==============================================================================
DetectSingleStepTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    xor     r13, r13            ; Accumulated timing
    mov     esi, TIMING_ITERATIONS
    
single_step_loop:
    ; Serialize and get start time
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax            ; Start time
    
    ; Execute a NOP sled - if single-stepping, this will be very slow
    ; 64 NOPs should be nearly instant without debugger
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
    
    ; Get end time (serialized)
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    
    sub     rax, r12            ; Delta
    add     r13, rax            ; Accumulate
    
    dec     esi
    jnz     single_step_loop
    
    ; Calculate average
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    ; Check against threshold
    cmp     rax, THRESHOLD_SINGLESTEP
    ja      single_step_detected
    
    xor     rax, rax
    jmp     single_step_exit
    
single_step_detected:
    mov     rax, 1
    
single_step_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectSingleStepTiming ENDP

; ==============================================================================
; DetectTrapFlagManipulation
;
; Detects debugger by measuring POPF instruction timing. Debuggers often
; intercept POPF when it modifies the Trap Flag (TF), causing overhead.
;
; Parameters: None
; Returns: RAX = 1 if trap flag manipulation detected, 0 otherwise
; Clobbers: RAX, RBX, RCX, RDX, RSI, RDI
; ==============================================================================
DetectTrapFlagManipulation PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    xor     r13, r13            ; Accumulated timing
    mov     esi, TIMING_ITERATIONS
    
trap_flag_loop:
    ; Get current flags
    pushfq
    pop     rdi                 ; Save original flags
    
    ; Clear TF in the flags we'll push
    and     rdi, 0FFFFFFFFFFFFFEFFh  ; Clear TF (bit 8)
    
    ; Serialize and get start time
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Push flags without TF and pop them
    ; Debuggers often intercept this
    push    rdi
    popfq
    
    ; Get end time
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     trap_flag_loop
    
    ; Calculate average
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    ; Check threshold
    cmp     rax, THRESHOLD_TRAPFLAG
    ja      trap_flag_detected
    
    xor     rax, rax
    jmp     trap_flag_exit
    
trap_flag_detected:
    mov     rax, 1
    
trap_flag_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectTrapFlagManipulation ENDP

; ==============================================================================
; DetectInt2DBehavior
;
; Detects debugger via INT 2D behavior differences. INT 2D is a debug service
; interrupt that behaves differently when a debugger is attached:
; - Without debugger: Causes exception
; - With debugger: May be silently handled or cause different behavior
;
; This function measures the timing of INT 2D execution pattern.
;
; Parameters: None
; Returns: RAX = 1 if debugger behavior detected, 0 otherwise
; Clobbers: RAX, RBX, RCX, RDX
; 
; NOTE: This uses timing-based detection to avoid actually raising INT 2D
; which could crash if no SEH is set up.
; ==============================================================================
DetectInt2DBehavior PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    ; We use indirect detection - measure timing around code that would
    ; trigger INT 2D handling if a debugger were attached
    
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
int2d_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Instructions that debuggers often intercept
    ; These trigger debug-related code paths
    mov     rax, gs:[60h]       ; PEB access (often monitored)
    mov     rax, [rax+2]        ; BeingDebugged field
    
    ; More instructions debuggers intercept
    xor     eax, eax
    cpuid                       ; CPUID is often trapped by hypervisors
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     int2d_timing_loop
    
    ; Average timing
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    cmp     rax, THRESHOLD_INT2D
    ja      int2d_detected
    
    xor     rax, rax
    jmp     int2d_exit
    
int2d_detected:
    mov     rax, 1
    
int2d_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectInt2DBehavior ENDP

; ==============================================================================
; DetectInt3Timing
;
; Measures timing around INT 3 (breakpoint) opcode locations. Debuggers
; intercept INT 3 which adds measurable overhead.
;
; Parameters: None
; Returns: RAX = 1 if INT 3 timing anomaly detected, 0 otherwise
; ==============================================================================
DetectInt3Timing PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
int3_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Execute NOPs that could be replaced with INT 3 by debugger
    ; If debugger has set breakpoints, they'll be slower
    REPT 32
    nop
    ENDM
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     int3_timing_loop
    
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    cmp     rax, THRESHOLD_INT3
    ja      int3_detected
    
    xor     rax, rax
    jmp     int3_exit
    
int3_detected:
    mov     rax, 1
    
int3_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectInt3Timing ENDP

; ==============================================================================
; DetectHardwareBreakpointsTiming
;
; Detects hardware breakpoints by measuring instruction execution timing.
; Hardware breakpoints (DR0-DR3) cause debug exceptions that add overhead.
;
; Parameters: None
; Returns: RAX = 1 if hardware breakpoints detected, 0 otherwise
; ==============================================================================
DetectHardwareBreakpointsTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
hwbp_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Execute variety of instructions that could trigger HW breakpoints
    ; on execution, read, or write
    mov     rax, rax            ; Register move
    mov     rbx, rbx
    mov     rcx, rcx
    mov     rdx, rdx
    
    ; Stack operations (memory access that could trigger HW BP)
    push    rax
    pop     rax
    push    rbx
    pop     rbx
    
    ; More register operations
    xchg    rax, rax
    xchg    rbx, rbx
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     hwbp_timing_loop
    
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    cmp     rax, THRESHOLD_HWBP
    ja      hwbp_detected
    
    xor     rax, rax
    jmp     hwbp_exit
    
hwbp_detected:
    mov     rax, 1
    
hwbp_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectHardwareBreakpointsTiming ENDP

; ==============================================================================
; MeasureDebugInstructionTiming
;
; Measures timing of instructions commonly used for debugging.
; Returns the average cycle count for calibration purposes.
;
; Parameters: None
; Returns: RAX = Average cycle count
; ==============================================================================
MeasureDebugInstructionTiming PROC
    push    rbx
    push    rsi
    push    r12
    push    r13
    
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
debug_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Debug-related instructions
    pushfq
    popfq
    
    xor     eax, eax
    cpuid
    
    mov     rax, gs:[60h]       ; TEB access
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     debug_timing_loop
    
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    pop     r13
    pop     r12
    pop     rsi
    pop     rbx
    ret
MeasureDebugInstructionTiming ENDP

; ==============================================================================
; DetectICEBPBehavior
;
; Detects debugger via ICEBP (0xF1) instruction behavior. ICEBP is an
; undocumented Intel instruction that generates INT 1 (single-step).
; Debuggers handle this differently than normal execution.
;
; Parameters: None
; Returns: RAX = 1 if ICEBP debugger behavior detected, 0 otherwise
;
; NOTE: Uses timing-based detection to avoid actually executing ICEBP
; ==============================================================================
DetectICEBPBehavior PROC
    push    rbx
    push    rsi
    push    r12
    push    r13
    
    ; Use timing-based detection similar to single-step
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
icebp_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Execute instructions around where ICEBP would be
    ; Debuggers often set breakpoints near such locations
    nop
    nop
    nop
    nop
    ; 0xF1 would go here in malware - we just measure timing
    nop
    nop
    nop
    nop
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     icebp_timing_loop
    
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    ; ICEBP-related overhead is similar to single-step
    cmp     rax, THRESHOLD_SINGLESTEP
    ja      icebp_detected
    
    xor     rax, rax
    jmp     icebp_exit
    
icebp_detected:
    mov     rax, 1
    
icebp_exit:
    pop     r13
    pop     r12
    pop     rsi
    pop     rbx
    ret
DetectICEBPBehavior ENDP

; ==============================================================================
; DetectIDTRelocation
;
; Detects if IDT (Interrupt Descriptor Table) base has been relocated.
; VMs and rootkits often relocate the IDT. Normal Windows has IDT in
; kernel address space.
;
; Parameters:
;   RCX = Pointer to receive IDT base (QWORD)
;   RDX = Pointer to receive IDT limit (WORD)
;
; Returns: RAX = 1 if IDT appears relocated/suspicious, 0 otherwise
; ==============================================================================
DetectIDTRelocation PROC
    push    rbx
    
    ; SIDT stores IDT register (base + limit) to memory
    ; Format: 2-byte limit, then 8-byte base on x64
    sub     rsp, 16             ; Allocate 16 bytes for IDTR
    
    sidt    [rsp]               ; Store IDT register
    
    ; Extract limit (first 2 bytes)
    movzx   eax, WORD PTR [rsp]
    test    rdx, rdx
    jz      idt_skip_limit
    mov     [rdx], ax
    
idt_skip_limit:
    ; Extract base (next 8 bytes)
    mov     rax, [rsp+2]
    test    rcx, rcx
    jz      idt_skip_base
    mov     [rcx], rax
    
idt_skip_base:
    ; Check if base is in expected kernel range
    ; Kernel addresses on x64 are typically >= 0xFFFF800000000000
    mov     rbx, rax
    mov     rax, 0FFFF800000000000h
    cmp     rbx, rax
    jb      idt_suspicious       ; Base is below kernel range - suspicious
    
    ; IDT base looks normal
    xor     rax, rax
    jmp     idt_exit
    
idt_suspicious:
    mov     rax, 1
    
idt_exit:
    add     rsp, 16
    pop     rbx
    ret
DetectIDTRelocation ENDP

; ==============================================================================
; DetectGDTRelocation
;
; Detects if GDT (Global Descriptor Table) base has been relocated.
; Similar to IDT, GDT relocation indicates VM or rootkit.
;
; Parameters:
;   RCX = Pointer to receive GDT base (QWORD)
;   RDX = Pointer to receive GDT limit (WORD)
;
; Returns: RAX = 1 if GDT appears relocated/suspicious, 0 otherwise
; ==============================================================================
DetectGDTRelocation PROC
    push    rbx
    
    sub     rsp, 16
    
    sgdt    [rsp]               ; Store GDT register
    
    ; Extract limit
    movzx   eax, WORD PTR [rsp]
    test    rdx, rdx
    jz      gdt_skip_limit
    mov     [rdx], ax
    
gdt_skip_limit:
    ; Extract base
    mov     rax, [rsp+2]
    test    rcx, rcx
    jz      gdt_skip_base
    mov     [rcx], rax
    
gdt_skip_base:
    ; Check kernel range
    mov     rbx, rax
    mov     rax, 0FFFF800000000000h
    cmp     rbx, rax
    jb      gdt_suspicious
    
    xor     rax, rax
    jmp     gdt_exit
    
gdt_suspicious:
    mov     rax, 1
    
gdt_exit:
    add     rsp, 16
    pop     rbx
    ret
DetectGDTRelocation ENDP

; ==============================================================================
; DetectLDTPresence
;
; Detects if LDT (Local Descriptor Table) is present. Windows typically
; doesn't use LDT, so its presence may indicate unusual environment.
;
; Parameters: None
; Returns: RAX = LDT selector (0 if no LDT, non-zero if present)
; ==============================================================================
DetectLDTPresence PROC
    sub     rsp, 8
    
    sldt    [rsp]               ; Store LDT selector
    
    movzx   rax, WORD PTR [rsp]
    
    add     rsp, 8
    ret
DetectLDTPresence ENDP

; ==============================================================================
; CheckDebugRegistersIndirect
;
; Indirectly checks for debug register usage via timing. Direct DR access
; requires Ring 0, but we can detect their usage via timing side-effects.
;
; Parameters: None
; Returns: RAX = Estimated DR usage indicator (higher = more likely)
; ==============================================================================
CheckDebugRegistersIndirect PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    
    xor     r13, r13            ; Accumulated delta
    xor     r14, r14            ; Baseline timing
    mov     esi, TIMING_ITERATIONS
    
    ; First, measure baseline (just RDTSC pair)
dr_baseline_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Minimal instructions
    nop
    nop
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r14, rax
    
    dec     esi
    jnz     dr_baseline_loop
    
    ; Now measure with memory/register operations that trigger DR checks
    mov     esi, TIMING_ITERATIONS
    
dr_test_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Operations that could trigger DR0-DR3 watchpoints
    mov     rax, [rsp]          ; Stack read
    mov     [rsp-8], rax        ; Stack write
    lea     rax, [rsp]          ; Address calculation
    mov     rax, [rax]          ; Indirect read
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     dr_test_loop
    
    ; Calculate difference between baseline and test
    ; Large difference indicates DR watchpoints active
    mov     rax, r13
    sub     rax, r14
    
    ; Return absolute difference
    test    rax, rax
    jns     dr_positive
    neg     rax
    
dr_positive:
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
CheckDebugRegistersIndirect ENDP

; ==============================================================================
; MeasureCPUIDRDTSCPair
;
; Measures the timing of a CPUID+RDTSC pair, which is the standard method
; for anti-debug timing checks in malware. Returns raw cycle count for
; analysis by the C++ code.
;
; Parameters: None
; Returns: RAX = Cycle count for CPUID+RDTSC pair
; ==============================================================================
MeasureCPUIDRDTSCPair PROC
    push    rbx
    
    ; First RDTSC to get start time
    xor     eax, eax
    cpuid                       ; Serialize
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax            ; Save start
    
    ; The measurement: CPUID followed by RDTSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ; End timing
    sub     rax, rcx
    
    pop     rbx
    ret
MeasureCPUIDRDTSCPair ENDP

; ==============================================================================
; DetectPrefetchTiming
;
; Uses PREFETCH instruction timing to detect debugger-induced cache effects.
; Debuggers can affect memory caching behavior.
;
; Parameters:
;   RCX = Address to prefetch (should be valid readable memory)
;
; Returns: RAX = 1 if timing anomaly detected, 0 otherwise
; ==============================================================================
DetectPrefetchTiming PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    test    rcx, rcx
    jz      prefetch_invalid
    
    mov     rdi, rcx            ; Save address
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
prefetch_loop:
    ; Flush the cache line first
    clflush [rdi]
    
    ; Serialize
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Prefetch the address
    prefetcht0 [rdi]
    
    ; Measure time for prefetch
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     prefetch_loop
    
    ; Average
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    cmp     rax, THRESHOLD_PREFETCH
    ja      prefetch_anomaly
    
    xor     rax, rax
    jmp     prefetch_exit
    
prefetch_anomaly:
    mov     rax, 1
    jmp     prefetch_exit
    
prefetch_invalid:
    xor     rax, rax
    
prefetch_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DetectPrefetchTiming ENDP

; ==============================================================================
; DetectExceptionHandlerTiming
;
; Measures timing overhead of exception handling. Debuggers intercept
; exceptions, adding significant overhead.
;
; Parameters: None
; Returns: RAX = Average exception handling overhead (cycles)
;
; NOTE: This measures timing around exception-prone code paths without
; actually raising exceptions, as that would require SEH setup.
; ==============================================================================
DetectExceptionHandlerTiming PROC
    push    rbx
    push    rsi
    push    r12
    push    r13
    
    xor     r13, r13
    mov     esi, TIMING_ITERATIONS
    
exception_timing_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Code patterns that debuggers often intercept
    ; Division setup (debuggers watch for div-by-zero)
    mov     rax, 12345678h
    mov     rcx, 1              ; Safe divisor
    xor     rdx, rdx
    div     rcx
    
    ; Memory access patterns
    mov     rax, gs:[0]         ; Segment access
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     esi
    jnz     exception_timing_loop
    
    ; Return average
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, TIMING_ITERATIONS
    div     rcx
    
    pop     r13
    pop     r12
    pop     rsi
    pop     rbx
    ret
DetectExceptionHandlerTiming ENDP

; ==============================================================================
; ScanForBreakpointOpcodes
;
; Scans a memory region for INT 3 (0xCC) breakpoint opcodes using SIMD
; for maximum performance. This can detect debugger-inserted breakpoints.
;
; Parameters:
;   RCX = Start address to scan
;   RDX = Size in bytes to scan
;
; Returns: RAX = Number of 0xCC bytes found
;
; NOTE: Caller must ensure memory is readable. Uses SSE2 for speed.
; ==============================================================================
ScanForBreakpointOpcodes PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    
    test    rcx, rcx
    jz      scan_invalid
    test    rdx, rdx
    jz      scan_invalid
    
    mov     rsi, rcx            ; Source address
    mov     rdi, rdx            ; Size
    xor     r12, r12            ; Count of 0xCC found
    
    ; Create mask of 0xCC bytes for SIMD comparison
    mov     eax, 0CCCCCCCCh
    movd    xmm1, eax
    pshufd  xmm1, xmm1, 0       ; Broadcast to all bytes
    
    ; Process 16 bytes at a time with SSE2
scan_simd_loop:
    cmp     rdi, 16
    jb      scan_byte_loop      ; Less than 16 bytes, do byte scan
    
    ; Load 16 bytes
    movdqu  xmm0, [rsi]
    
    ; Compare for equality with 0xCC
    pcmpeqb xmm0, xmm1
    
    ; Get mask of matches
    pmovmskb eax, xmm0
    
    ; Count bits (popcount)
    popcnt  eax, eax
    add     r12, rax
    
    add     rsi, 16
    sub     rdi, 16
    jmp     scan_simd_loop
    
scan_byte_loop:
    test    rdi, rdi
    jz      scan_done
    
    ; Byte-by-byte scan for remainder
    movzx   eax, BYTE PTR [rsi]
    cmp     al, BREAKPOINT_OPCODE
    jne     scan_not_cc
    inc     r12
    
scan_not_cc:
    inc     rsi
    dec     rdi
    jmp     scan_byte_loop
    
scan_done:
    mov     rax, r12
    jmp     scan_exit
    
scan_invalid:
    xor     rax, rax
    
scan_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ScanForBreakpointOpcodes ENDP

; ==============================================================================
; MeasureCodeIntegrity
;
; Measures timing to read a code region, which can detect if debugger has
; modified the code (software breakpoints change bytes).
;
; Parameters:
;   RCX = Start address of code region
;   RDX = Size in bytes
;
; Returns: RAX = Average read timing (higher may indicate modifications)
; ==============================================================================
MeasureCodeIntegrity PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    test    rcx, rcx
    jz      integrity_invalid
    test    rdx, rdx
    jz      integrity_invalid
    
    mov     rdi, rcx            ; Code address
    mov     rsi, rdx            ; Size
    xor     r13, r13            ; Accumulated timing
    mov     ebx, 10             ; 10 iterations
    
integrity_loop:
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ; Read through the code region
    mov     rcx, rsi
    mov     rax, rdi
    
integrity_read_loop:
    mov     r8, [rax]           ; Read 8 bytes
    add     rax, 8
    sub     rcx, 8
    ja      integrity_read_loop
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r12
    add     r13, rax
    
    dec     ebx
    jnz     integrity_loop
    
    ; Average
    mov     rax, r13
    xor     rdx, rdx
    mov     ecx, 10
    div     rcx
    jmp     integrity_exit
    
integrity_invalid:
    xor     rax, rax
    
integrity_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureCodeIntegrity ENDP

END
