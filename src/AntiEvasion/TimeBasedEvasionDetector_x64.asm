;; =============================================================================
;; TimeBasedEvasionDetector_x64.asm
;; =============================================================================
;; Enterprise-grade assembly routines for timing-based evasion detection.
;;
;; This module provides low-level CPU timing measurements that CANNOT be
;; reliably implemented in C++ due to:
;; - Compiler optimizations that reorder or eliminate timing instructions
;; - Instruction scheduling that adds variable overhead
;; - Need for precise CPUID serialization before RDTSC
;; - Detection of sub-microsecond VM exit latency
;;
;; These functions are CRITICAL for detecting:
;; - Virtual machine timing overhead (VM exits take ~1000-5000 cycles)
;; - Sandbox sleep acceleration/fast-forwarding
;; - Hypervisor presence via timing anomalies
;; - Single-step debugging via instruction timing
;; - RDTSC emulation in analysis environments
;;
;; =============================================================================
;; TIMING ATTACK DETECTION CAPABILITIES
;; =============================================================================
;;
;; 1. RDTSC-Based VM Detection:
;;    - MeasureRDTSCDelta: Measure raw RDTSC overhead
;;    - MeasureSerializedRDTSC: Measure with CPUID serialization
;;    - CompareRDTSCvRDTSCP: Detect inconsistent TSC implementations
;;
;; 2. CPUID-Based Detection:
;;    - MeasureCPUIDLatency: CPUID causes mandatory VM exit
;;    - CheckHypervisorLeaf: Query CPUID 0x40000000 for hypervisor
;;    - MeasureCPUIDVariance: Detect timing variance in VMs
;;
;; 3. Sleep Acceleration Detection:
;;    - MeasureSleepTiming: Compare TSC-based vs API-based sleep
;;    - DetectSleepAcceleration: Detect sandboxes that fast-forward Sleep()
;;    - CalibrateTimebase: Establish TSC frequency baseline
;;
;; 4. Instruction Timing:
;;    - MeasureInstructionTiming: Detect single-step debuggers
;;    - MeasureMemoryTiming: Detect memory virtualization overhead
;;    - MeasureIOTiming: Detect I/O port virtualization
;;
;; @author ShadowStrike Security Team
;; @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;; =============================================================================

OPTION CASEMAP:NONE

;; =============================================================================
;; PUBLIC EXPORTS
;; =============================================================================

PUBLIC TimingRDTSCDelta
PUBLIC TimingSerializedRDTSC
PUBLIC TimingCompareRDTSCvRDTSCP
PUBLIC TimingCPUIDLatency
PUBLIC TimingCheckHypervisorLeaf
PUBLIC TimingCPUIDVariance
PUBLIC TimingMeasureSleep
PUBLIC TimingDetectSleepAcceleration
PUBLIC TimingCalibrateTimebase
PUBLIC TimingMeasureInstructions
PUBLIC TimingMeasureMemory
PUBLIC TimingDetectSingleStep
PUBLIC TimingGetTSCFrequency
PUBLIC TimingGetPreciseRDTSC
PUBLIC TimingGetPreciseRDTSCP
PUBLIC TimingDetectVMExit
PUBLIC TimingMeasureHypervisor

;; External Windows API
EXTERN __imp_Sleep:QWORD
EXTERN __imp_GetTickCount64:QWORD
EXTERN __imp_QueryPerformanceCounter:QWORD
EXTERN __imp_QueryPerformanceFrequency:QWORD

.CONST
;; Detection thresholds (in CPU cycles)
RDTSC_NORMAL_OVERHEAD       EQU 50      ; Normal: ~20-50 cycles
RDTSC_VM_THRESHOLD          EQU 500     ; VM exit adds 500+ cycles
CPUID_NORMAL_OVERHEAD       EQU 200     ; Normal: ~100-200 cycles
CPUID_VM_THRESHOLD          EQU 1500    ; VM exit adds significant overhead
INSTRUCTION_TIMING_THRESHOLD EQU 100    ; Per-instruction threshold
SLEEP_DEVIATION_PERCENT     EQU 30      ; 30% deviation = acceleration
MEMORY_LATENCY_THRESHOLD    EQU 300     ; Memory virtualization overhead

;; Number of iterations for averaging
MEASUREMENT_ITERATIONS      EQU 100
VARIANCE_ITERATIONS         EQU 50

.DATA
;; Global calibration state
g_tscFrequency          DQ 0            ; TSC frequency in Hz
g_baselineRDTSC         DQ 0            ; Baseline RDTSC overhead
g_baselineCPUID         DQ 0            ; Baseline CPUID overhead  
g_calibrated            DD 0            ; Calibration complete flag

;; Memory test buffer (cache-line aligned)
ALIGN 64
g_testBuffer            DB 4096 DUP(0)

.CODE

;; =============================================================================
;; TimingGetPreciseRDTSC
;; =============================================================================
;; Gets RDTSC value with CPUID serialization.
;; This ensures no out-of-order execution affects the measurement.
;;
;; Prototype: uint64_t TimingGetPreciseRDTSC(void);
;; Returns: 64-bit TSC value
;; =============================================================================
TimingGetPreciseRDTSC PROC
    push    rbx
    push    rcx
    push    rdx
    
    ;; Serialize with CPUID (leaf 0)
    xor     eax, eax
    cpuid
    
    ;; Read TSC
    rdtsc
    
    ;; Combine EDX:EAX into RAX
    shl     rdx, 32
    or      rax, rdx
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
TimingGetPreciseRDTSC ENDP

;; =============================================================================
;; TimingGetPreciseRDTSCP
;; =============================================================================
;; Gets RDTSCP value (self-serializing) with optional processor ID.
;;
;; Prototype: uint64_t TimingGetPreciseRDTSCP(uint32_t* processorId);
;; Parameters:
;;   RCX - Optional pointer for processor ID (can be NULL)
;; Returns: 64-bit TSC value
;; =============================================================================
TimingGetPreciseRDTSCP PROC
    push    rbx
    
    mov     rbx, rcx        ; Save processor ID pointer
    
    ;; RDTSCP is self-serializing
    rdtscp
    
    ;; Store processor ID if pointer provided
    test    rbx, rbx
    jz      @F
    mov     DWORD PTR [rbx], ecx
@@:
    ;; Combine result
    shl     rdx, 32
    or      rax, rdx
    
    pop     rbx
    ret
TimingGetPreciseRDTSCP ENDP

;; =============================================================================
;; TimingRDTSCDelta
;; =============================================================================
;; Measures raw RDTSC instruction overhead (no serialization).
;; Returns average cycles for back-to-back RDTSC calls.
;;
;; Prototype: uint64_t TimingRDTSCDelta(void);
;; Returns: Average RDTSC overhead in cycles
;; =============================================================================
TimingRDTSCDelta PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    xor     rsi, rsi        ; Accumulator
    mov     ecx, MEASUREMENT_ITERATIONS
    
@MeasureLoop:
    ;; First RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax
    
    ;; Second RDTSC (immediate)
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ;; Accumulate delta
    sub     rax, rdi
    add     rsi, rax
    
    dec     ecx
    jnz     @MeasureLoop
    
    ;; Calculate average
    mov     rax, rsi
    xor     edx, edx
    mov     rcx, MEASUREMENT_ITERATIONS
    div     rcx
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingRDTSCDelta ENDP

;; =============================================================================
;; TimingSerializedRDTSC
;; =============================================================================
;; Measures RDTSC with proper CPUID serialization.
;; This is the gold-standard for VM detection.
;;
;; Prototype: uint64_t TimingSerializedRDTSC(void);
;; Returns: Average serialized RDTSC overhead in cycles
;; =============================================================================
TimingSerializedRDTSC PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    
    xor     rsi, rsi        ; Accumulator
    mov     r12d, MEASUREMENT_ITERATIONS
    
@SerialLoop:
    ;; Serialize + first RDTSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax
    
    ;; Serialize + second RDTSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ;; Accumulate delta
    sub     rax, rdi
    add     rsi, rax
    
    dec     r12d
    jnz     @SerialLoop
    
    ;; Calculate average
    mov     rax, rsi
    xor     edx, edx
    mov     rcx, MEASUREMENT_ITERATIONS
    div     rcx
    
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingSerializedRDTSC ENDP

;; =============================================================================
;; TimingCompareRDTSCvRDTSCP
;; =============================================================================
;; Compares RDTSC and RDTSCP timing.
;; Significant difference may indicate virtualization.
;;
;; Prototype: int64_t TimingCompareRDTSCvRDTSCP(void);
;; Returns: Difference (RDTSCP - RDTSC) in cycles
;; =============================================================================
TimingCompareRDTSCvRDTSCP PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Measure RDTSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax        ; Start
    
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    mov     rdi, rax        ; rdi = RDTSC delta
    
    ;; Measure RDTSCP
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax        ; Start
    
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi        ; rax = RDTSCP delta
    
    ;; Return difference
    sub     rax, rdi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingCompareRDTSCvRDTSCP ENDP

;; =============================================================================
;; TimingCPUIDLatency
;; =============================================================================
;; Measures CPUID instruction latency.
;; CPUID ALWAYS causes VM exit - high latency = VM.
;;
;; Prototype: uint64_t TimingCPUIDLatency(void);
;; Returns: Average CPUID overhead in cycles
;; =============================================================================
TimingCPUIDLatency PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    
    xor     rsi, rsi
    mov     r12d, MEASUREMENT_ITERATIONS
    
@CPUIDLoop:
    ;; Get start time
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax
    
    ;; Execute CPUID (causes VM exit)
    xor     eax, eax
    cpuid
    
    ;; Get end time
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ;; Accumulate
    sub     rax, rdi
    add     rsi, rax
    
    dec     r12d
    jnz     @CPUIDLoop
    
    ;; Average
    mov     rax, rsi
    xor     edx, edx
    mov     rcx, MEASUREMENT_ITERATIONS
    div     rcx
    
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingCPUIDLatency ENDP

;; =============================================================================
;; TimingCheckHypervisorLeaf
;; =============================================================================
;; Checks for hypervisor via CPUID leaf 0x40000000.
;; Returns hypervisor vendor string length (0 = no hypervisor).
;;
;; Prototype: uint32_t TimingCheckHypervisorLeaf(char* vendorOut);
;; Parameters:
;;   RCX - Buffer for vendor string (13 bytes min) or NULL
;; Returns: 1 if hypervisor present, 0 otherwise
;; =============================================================================
TimingCheckHypervisorLeaf PROC
    push    rbx
    push    rsi
    
    mov     rsi, rcx        ; Save output buffer
    
    ;; First check if hypervisor bit is set (CPUID.1:ECX.31)
    mov     eax, 1
    cpuid
    bt      ecx, 31
    jnc     @NoHypervisor
    
    ;; Query hypervisor leaf
    mov     eax, 40000000h
    cpuid
    
    ;; EBX:ECX:EDX contains vendor ID
    test    rsi, rsi
    jz      @SkipVendor
    
    mov     DWORD PTR [rsi], ebx
    mov     DWORD PTR [rsi+4], ecx
    mov     DWORD PTR [rsi+8], edx
    mov     BYTE PTR [rsi+12], 0
    
@SkipVendor:
    mov     eax, 1
    jmp     @HVReturn
    
@NoHypervisor:
    xor     eax, eax
    
@HVReturn:
    pop     rsi
    pop     rbx
    ret
TimingCheckHypervisorLeaf ENDP

;; =============================================================================
;; TimingCPUIDVariance
;; =============================================================================
;; Measures variance in CPUID timing.
;; VMs have higher variance due to scheduling.
;;
;; Prototype: uint64_t TimingCPUIDVariance(void);
;; Returns: Variance metric (higher = likely VM)
;; =============================================================================
TimingCPUIDVariance PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 8*VARIANCE_ITERATIONS  ; Stack space for measurements
    
    mov     r12, rsp        ; Pointer to measurements
    xor     r13d, r13d      ; Iteration counter
    xor     r14, r14        ; Sum for mean
    
@VarianceLoop:
    ;; Measure CPUID
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax
    
    xor     eax, eax
    cpuid
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rdi
    
    ;; Store measurement
    mov     QWORD PTR [r12 + r13*8], rax
    add     r14, rax
    
    inc     r13d
    cmp     r13d, VARIANCE_ITERATIONS
    jb      @VarianceLoop
    
    ;; Calculate mean
    mov     rax, r14
    xor     edx, edx
    mov     rcx, VARIANCE_ITERATIONS
    div     rcx
    mov     rdi, rax        ; rdi = mean
    
    ;; Calculate variance (sum of squared differences)
    xor     r14, r14        ; Variance accumulator
    xor     r13d, r13d
    
@VarianceCalc:
    mov     rax, QWORD PTR [r12 + r13*8]
    sub     rax, rdi        ; Difference from mean
    imul    rax, rax        ; Square it
    add     r14, rax
    
    inc     r13d
    cmp     r13d, VARIANCE_ITERATIONS
    jb      @VarianceCalc
    
    ;; Return variance
    mov     rax, r14
    xor     edx, edx
    mov     rcx, VARIANCE_ITERATIONS
    div     rcx
    
    add     rsp, 8*VARIANCE_ITERATIONS
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingCPUIDVariance ENDP

;; =============================================================================
;; TimingMeasureSleep
;; =============================================================================
;; Measures actual vs expected sleep duration using TSC.
;;
;; Prototype: uint64_t TimingMeasureSleep(uint32_t sleepMs);
;; Parameters:
;;   RCX - Requested sleep duration in milliseconds
;; Returns: Actual sleep duration in TSC cycles
;; =============================================================================
TimingMeasureSleep PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 40         ; Shadow space
    
    mov     r12d, ecx       ; Save sleep duration
    
    ;; Get start TSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    ;; Call Sleep
    mov     ecx, r12d
    call    QWORD PTR [__imp_Sleep]
    
    ;; Get end TSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ;; Return delta
    sub     rax, rsi
    
    add     rsp, 40
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TimingMeasureSleep ENDP

;; =============================================================================
;; TimingDetectSleepAcceleration
;; =============================================================================
;; Detects sandbox sleep acceleration.
;; Compares TSC-based measurement with GetTickCount64.
;;
;; Prototype: uint32_t TimingDetectSleepAcceleration(uint32_t sleepMs);
;; Parameters:
;;   RCX - Sleep duration to test (recommended: 500-1000ms)
;; Returns: Acceleration percentage (0 = no acceleration, >30 = likely sandbox)
;; =============================================================================
TimingDetectSleepAcceleration PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 48
    
    mov     r12d, ecx       ; Save requested sleep
    
    ;; Get start tick count
    call    QWORD PTR [__imp_GetTickCount64]
    mov     r13, rax
    
    ;; Sleep
    mov     ecx, r12d
    call    QWORD PTR [__imp_Sleep]
    
    ;; Get end tick count
    call    QWORD PTR [__imp_GetTickCount64]
    sub     rax, r13        ; Actual elapsed ms
    
    ;; Calculate deviation: (requested - actual) * 100 / requested
    mov     rdi, rax        ; rdi = actual
    
    cmp     rdi, r12        ; Compare actual vs requested
    jae     @NoAccel        ; actual >= requested = no acceleration
    
    ;; actual < requested - calculate acceleration percentage
    mov     rax, r12
    sub     rax, rdi        ; deviation = requested - actual
    imul    rax, 100
    xor     edx, edx
    div     r12             ; deviation percentage
    jmp     @AccelReturn
    
@NoAccel:
    xor     eax, eax
    
@AccelReturn:
    add     rsp, 48
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TimingDetectSleepAcceleration ENDP

;; =============================================================================
;; TimingCalibrateTimebase
;; =============================================================================
;; Calibrates TSC frequency using QueryPerformanceCounter.
;; Must be called before using frequency-dependent functions.
;;
;; Prototype: uint64_t TimingCalibrateTimebase(void);
;; Returns: TSC frequency in Hz
;; =============================================================================
TimingCalibrateTimebase PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 56
    
    ;; Check if already calibrated
    cmp     DWORD PTR [g_calibrated], 1
    je      @ReturnCached
    
    ;; Get QPC frequency
    lea     rcx, [rsp+32]
    call    QWORD PTR [__imp_QueryPerformanceFrequency]
    mov     r12, QWORD PTR [rsp+32]  ; QPC frequency
    
    ;; Get start QPC
    lea     rcx, [rsp+32]
    call    QWORD PTR [__imp_QueryPerformanceCounter]
    mov     rsi, QWORD PTR [rsp+32]  ; Start QPC
    
    ;; Get start TSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r13, rax                 ; Start TSC
    
    ;; Wait ~100ms using busy loop
    mov     ecx, 10000000
@BusyWait:
    pause
    dec     ecx
    jnz     @BusyWait
    
    ;; Get end TSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax                 ; End TSC
    
    ;; Get end QPC
    lea     rcx, [rsp+32]
    call    QWORD PTR [__imp_QueryPerformanceCounter]
    mov     rax, QWORD PTR [rsp+32]  ; End QPC
    sub     rax, rsi                 ; QPC delta
    
    ;; Calculate TSC frequency
    ;; TSC_freq = TSC_delta * QPC_freq / QPC_delta
    sub     rdi, r13                 ; TSC delta
    mov     rax, rdi
    imul    rax, r12                 ; TSC_delta * QPC_freq
    mov     rcx, rax
    sub     rcx, rsi
    xor     edx, edx
    mov     rbx, QWORD PTR [rsp+32]
    sub     rbx, rsi
    div     rbx                      ; / QPC_delta
    
    ;; Store result
    mov     QWORD PTR [g_tscFrequency], rax
    mov     DWORD PTR [g_calibrated], 1
    jmp     @CalibReturn
    
@ReturnCached:
    mov     rax, QWORD PTR [g_tscFrequency]
    
@CalibReturn:
    add     rsp, 56
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TimingCalibrateTimebase ENDP

;; =============================================================================
;; TimingMeasureInstructions
;; =============================================================================
;; Measures timing of a known instruction sequence.
;; Single-step debuggers add significant per-instruction overhead.
;;
;; Prototype: uint64_t TimingMeasureInstructions(void);
;; Returns: Cycles for 100 simple instructions
;; =============================================================================
TimingMeasureInstructions PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Get start time
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    ;; Execute 100 simple instructions
    ;; These should take ~1 cycle each on real hardware
    REPT 10
        xor     eax, eax
        inc     eax
        dec     eax
        nop
        xor     ebx, ebx
        inc     ebx
        dec     ebx
        nop
        xor     ecx, ecx
        nop
    ENDM
    
    ;; Get end time  
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingMeasureInstructions ENDP

;; =============================================================================
;; TimingMeasureMemory
;; =============================================================================
;; Measures memory access latency.
;; VM memory virtualization adds latency.
;;
;; Prototype: uint64_t TimingMeasureMemory(void);
;; Returns: Memory access latency in cycles
;; =============================================================================
TimingMeasureMemory PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Flush cache line
    lea     rdi, [g_testBuffer]
    clflush [rdi]
    mfence
    
    ;; Measure uncached access
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    ;; Access memory
    mov     rax, QWORD PTR [rdi]
    lfence
    
    ;; Get end time
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingMeasureMemory ENDP

;; =============================================================================
;; TimingDetectSingleStep
;; =============================================================================
;; Detects single-step debugging via timing.
;;
;; Prototype: uint32_t TimingDetectSingleStep(void);
;; Returns: 1 if single-stepping detected, 0 otherwise
;; =============================================================================
TimingDetectSingleStep PROC
    push    rbx
    push    rcx
    push    rsi
    
    ;; Measure timing for simple operations
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    ;; 20 simple instructions
    REPT 20
        nop
    ENDM
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    
    ;; > 500 cycles for 20 NOPs indicates single-stepping
    cmp     rax, 500
    ja      @SingleStepDetected
    
    xor     eax, eax
    jmp     @SSReturn
    
@SingleStepDetected:
    mov     eax, 1
    
@SSReturn:
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingDetectSingleStep ENDP

;; =============================================================================
;; TimingGetTSCFrequency
;; =============================================================================
;; Returns cached TSC frequency or estimates it.
;;
;; Prototype: uint64_t TimingGetTSCFrequency(void);
;; Returns: TSC frequency in Hz (0 if not calibrated)
;; =============================================================================
TimingGetTSCFrequency PROC
    push    rbx
    push    rcx
    push    rdx
    
    ;; Check if calibrated
    cmp     DWORD PTR [g_calibrated], 1
    jne     @TryEstimate
    
    mov     rax, QWORD PTR [g_tscFrequency]
    jmp     @FreqReturn
    
@TryEstimate:
    ;; Try CPUID leaf 0x15 for TSC info
    mov     eax, 15h
    cpuid
    
    test    ebx, ebx
    jz      @NoTSCInfo
    test    ecx, ecx
    jz      @NoTSCInfo
    
    ;; TSC frequency = ECX * EBX / EAX
    mov     r8d, eax
    imul    rbx, rcx
    mov     rax, rbx
    xor     edx, edx
    div     r8
    jmp     @FreqReturn
    
@NoTSCInfo:
    xor     eax, eax
    
@FreqReturn:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
TimingGetTSCFrequency ENDP

;; =============================================================================
;; TimingDetectVMExit
;; =============================================================================
;; Comprehensive VM detection using multiple timing sources.
;;
;; Prototype: uint32_t TimingDetectVMExit(uint64_t* details);
;; Parameters:
;;   RCX - Optional pointer to receive detailed measurements (3 uint64_t)
;; Returns: Confidence score 0-100 (>50 = likely VM)
;; =============================================================================
TimingDetectVMExit PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 40
    
    mov     r12, rcx        ; Save details pointer
    xor     r13d, r13d      ; Score accumulator
    
    ;; Test 1: RDTSC overhead
    call    TimingSerializedRDTSC
    mov     r14, rax        ; Save measurement
    
    cmp     rax, RDTSC_VM_THRESHOLD
    jb      @T1Pass
    add     r13d, 35        ; High confidence indicator
@T1Pass:
    
    ;; Test 2: CPUID latency
    call    TimingCPUIDLatency
    mov     rdi, rax
    
    cmp     rax, CPUID_VM_THRESHOLD
    jb      @T2Pass
    add     r13d, 40        ; Very high confidence
@T2Pass:
    
    ;; Test 3: Hypervisor bit
    xor     ecx, ecx
    call    TimingCheckHypervisorLeaf
    mov     rsi, rax
    
    test    eax, eax
    jz      @T3Pass
    add     r13d, 25        ; Definitive but not conclusive (could be WSL)
@T3Pass:
    
    ;; Store details if requested
    test    r12, r12
    jz      @NoDetails
    mov     QWORD PTR [r12], r14      ; RDTSC overhead
    mov     QWORD PTR [r12+8], rdi    ; CPUID overhead
    mov     QWORD PTR [r12+16], rsi   ; Hypervisor present
@NoDetails:
    
    ;; Cap score at 100
    cmp     r13d, 100
    jbe     @ScoreOk
    mov     r13d, 100
@ScoreOk:
    mov     eax, r13d
    
    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TimingDetectVMExit ENDP

;; =============================================================================
;; TimingMeasureHypervisor
;; =============================================================================
;; Measures timing characteristics specific to hypervisors.
;; Queries hypervisor CPUID leaves and measures overhead.
;;
;; Prototype: uint64_t TimingMeasureHypervisor(void);
;; Returns: Hypervisor overhead measurement (0 if no hypervisor)
;; =============================================================================
TimingMeasureHypervisor PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Check for hypervisor first
    mov     eax, 1
    cpuid
    bt      ecx, 31
    jnc     @NoHV
    
    ;; Measure hypervisor CPUID leaf timing
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    mov     eax, 40000000h
    cpuid
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    jmp     @HVMReturn
    
@NoHV:
    xor     eax, eax
    
@HVMReturn:
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
TimingMeasureHypervisor ENDP

END
