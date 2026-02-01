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

;; Memory test buffer (use ALIGN 16 which is supported in .DATA)
;; Note: ALIGN 64 not supported in .DATA segment, using 16 instead
ALIGN 16
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
    ;; Note: RCX, RDX are caller-saved in x64, no need to preserve
    ;; CPUID clobbers RAX, RBX, RCX, RDX - we save RBX as it's callee-saved
    
    ;; Serialize with CPUID (leaf 0)
    xor     eax, eax
    cpuid
    
    ;; Read TSC - clobbers EDX:EAX
    rdtsc
    
    ;; Combine EDX:EAX into RAX
    shl     rdx, 32
    or      rax, rdx
    
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
    ;; SECURITY FIX: Use proper signed arithmetic and cap squared values
    ;; to prevent overflow when variance is extreme (common in VMs)
    xor     r14, r14        ; Variance accumulator
    xor     r13d, r13d
    
@VarianceCalc:
    mov     rax, QWORD PTR [r12 + r13*8]
    ;; Calculate signed difference
    sub     rax, rdi        ; Difference from mean (signed)
    
    ;; OVERFLOW FIX: Cap difference to prevent overflow when squaring
    ;; Max safe value for squaring in 64-bit: 2^31 - 1 = ~2 billion
    ;; If |diff| > 2^31, cap it (extreme outlier anyway)
    mov     rcx, rax
    sar     rcx, 63         ; Sign extend to get mask (-1 for negative, 0 for positive)
    xor     rax, rcx        ; Conditional negate (abs value computation, step 1)
    sub     rax, rcx        ; Complete abs value computation
    
    ;; Cap at 2^31 - 1 to prevent overflow
    mov     rcx, 7FFFFFFFh
    cmp     rax, rcx
    cmova   rax, rcx        ; Cap if too large
    
    ;; Now safe to square (result fits in 64-bit)
    imul    rax, rax        ; Square it (result guaranteed < 2^62)
    
    ;; Check for accumulator overflow before adding
    mov     rcx, r14
    add     rcx, rax
    jc      @CapVariance    ; If carry, variance overflowed
    mov     r14, rcx
    jmp     @VarianceNext
    
@CapVariance:
    mov     r14, 0FFFFFFFFFFFFFFFFh  ; Saturate at max
    
@VarianceNext:
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
    
    ;; SECURITY FIX: Validate input - reject zero or excessively large sleep
    test    r12d, r12d
    jz      @NoAccel        ; Zero sleep = return 0
    cmp     r12d, 60000     ; Cap at 60 seconds (60000ms)
    ja      @NoAccel        ; Too large = don't bother measuring
    
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
    ;; OVERFLOW FIX: Check if deviation * 100 would overflow
    ;; Since r12d is capped at 60000, max deviation is 60000
    ;; 60000 * 100 = 6,000,000 - fits easily in 64-bit
    mov     rax, r12
    sub     rax, rdi        ; deviation = requested - actual
    imul    rax, 100        ; Safe due to cap above
    xor     edx, edx
    
    ;; SECURITY FIX: Check divisor before division
    test    r12, r12
    jz      @NoAccel        ; Should never happen due to earlier check, but defense-in-depth
    div     r12             ; deviation percentage
    
    ;; Cap result at 100%
    cmp     eax, 100
    jbe     @AccelReturn
    mov     eax, 100
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
;; SECURITY FIXES:
;; - Uses LOCK CMPXCHG for thread-safe calibration flag
;; - Uses Sleep() API instead of unreliable busy loop
;; - Uses 128-bit multiplication to prevent overflow
;; - Checks for division by zero before dividing
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
    push    r14
    push    r15
    sub     rsp, 72         ; Extra space for 128-bit intermediate
    
    ;; THREAD-SAFETY FIX: Use atomic compare-exchange for calibration check
    ;; Try to acquire calibration lock (0 -> 2 means "calibrating")
    xor     eax, eax        ; Expected: 0 (not calibrated)
    mov     ecx, 2          ; New value: 2 (calibrating in progress)
    lock cmpxchg DWORD PTR [g_calibrated], ecx
    
    ;; Check result
    cmp     eax, 1          ; Was it already calibrated (1)?
    je      @ReturnCached
    cmp     eax, 2          ; Is another thread calibrating (2)?
    je      @WaitForCalibration
    ;; We won the race (was 0, now 2) - proceed with calibration
    
    ;; Get QPC frequency
    lea     rcx, [rsp+48]
    call    QWORD PTR [__imp_QueryPerformanceFrequency]
    mov     r12, QWORD PTR [rsp+48]  ; QPC frequency
    
    ;; VALIDATION: QPC frequency must be > 0
    test    r12, r12
    jz      @CalibrationFailed
    
    ;; Get start QPC
    lea     rcx, [rsp+48]
    call    QWORD PTR [__imp_QueryPerformanceCounter]
    mov     rsi, QWORD PTR [rsp+48]  ; Start QPC
    
    ;; Get start TSC (serialized)
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r13, rax                 ; Start TSC
    
    ;; RELIABILITY FIX: Use Sleep() API instead of busy loop
    ;; Busy loop timing varies with CPU frequency and is unreliable
    mov     ecx, 100        ; Sleep for 100ms (reliable timing)
    call    QWORD PTR [__imp_Sleep]
    
    ;; Get end TSC (serialized)
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r14, rax                 ; End TSC
    
    ;; Get end QPC
    lea     rcx, [rsp+48]
    call    QWORD PTR [__imp_QueryPerformanceCounter]
    mov     r15, QWORD PTR [rsp+48]  ; End QPC
    
    ;; Calculate deltas
    sub     r14, r13                 ; TSC delta
    sub     r15, rsi                 ; QPC delta
    
    ;; SECURITY FIX: Check for zero QPC delta (division by zero)
    test    r15, r15
    jz      @CalibrationFailed
    
    ;; Calculate TSC frequency using 128-bit multiplication to prevent overflow
    ;; TSC_freq = (TSC_delta * QPC_freq) / QPC_delta
    ;;
    ;; OVERFLOW FIX: Use MUL for 128-bit result (RDX:RAX = RAX * r12)
    ;; Then divide 128-bit by 64-bit
    mov     rax, r14                 ; TSC delta
    mul     r12                      ; RDX:RAX = TSC_delta * QPC_freq (128-bit)
    
    ;; Now divide RDX:RAX by r15 (QPC delta)
    ;; DIV r64: RDX:RAX / r64 -> RAX=quotient, RDX=remainder
    div     r15                      ; RAX = TSC frequency
    
    ;; Sanity check: frequency should be between 100MHz and 10GHz
    mov     rcx, 100000000           ; 100 MHz minimum
    cmp     rax, rcx
    jb      @CalibrationFailed
    mov     rcx, 10000000000         ; 10 GHz maximum  
    cmp     rax, rcx
    ja      @CalibrationFailed
    
    ;; Store result atomically
    mov     QWORD PTR [g_tscFrequency], rax
    mov     r13, rax                 ; Save for return
    
    ;; THREAD-SAFETY: Mark calibration complete (2 -> 1)
    mov     DWORD PTR [g_calibrated], 1
    
    mov     rax, r13
    jmp     @CalibReturn
    
@WaitForCalibration:
    ;; Another thread is calibrating - spin until done
    mov     ecx, 10         ; Short sleep to avoid busy spin
    call    QWORD PTR [__imp_Sleep]
    
    ;; Check if calibration completed
    cmp     DWORD PTR [g_calibrated], 1
    jne     @WaitForCalibration
    ;; Fall through to return cached value
    
@ReturnCached:
    mov     rax, QWORD PTR [g_tscFrequency]
    jmp     @CalibReturn
    
@CalibrationFailed:
    ;; Calibration failed - reset flag and return default
    mov     DWORD PTR [g_calibrated], 0
    mov     rax, 3000000000          ; Default: 3 GHz (reasonable fallback)
    mov     QWORD PTR [g_tscFrequency], rax
    
@CalibReturn:
    add     rsp, 72
    pop     r15
    pop     r14
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
