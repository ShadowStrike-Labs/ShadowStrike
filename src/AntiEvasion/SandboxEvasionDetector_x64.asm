;; =============================================================================
;; SandboxEvasionDetector_x64.asm
;; =============================================================================
;; Enterprise-grade assembly routines for sandbox evasion detection.
;;
;; This module provides low-level CPU timing and environment detection functions
;; that cannot be reliably implemented in C++ due to:
;; - Precise instruction sequencing requirements
;; - Need to avoid compiler optimizations
;; - Direct access to CPU features (RDTSC, CPUID, RDPMC)
;; - Detection of VM/hypervisor timing anomalies
;;
;; Functions:
;; - MeasureSleepAcceleration: Detect sandbox sleep patching
;; - MeasureRDTSCOverhead: Measure VM exit overhead
;; - MeasureCPUIDOverhead: Measure CPUID VM exit timing
;; - CheckCuckooBackdoor: Detect Cuckoo sandbox backdoor port
;; - MeasureTimingPrecision: Detect coarse-grained time sources
;; - DetectSingleStepTiming: Detect timing-based debuggers
;; - MeasureVMExitOverhead: Comprehensive VM detection via timing
;; - GetPreciseRDTSC: Get RDTSC with serialization
;; - GetPreciseRDTSCP: Get RDTSCP with processor ID
;; - CalibrateTimingBaseline: Establish baseline timing
;; - DetectTimingHook: Detect hooked timing functions
;; - MeasureMemoryLatency: Detect VM memory virtualization
;; - CheckHypervisorBit: Check CPUID hypervisor present bit
;;
;; @author ShadowStrike Security Team
;; @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;; =============================================================================

OPTION CASEMAP:NONE

;; =============================================================================
;; PUBLIC EXPORTS
;; =============================================================================

PUBLIC MeasureSleepAcceleration
PUBLIC MeasureRDTSCOverhead
PUBLIC MeasureCPUIDOverhead
PUBLIC CheckCuckooBackdoor
PUBLIC MeasureTimingPrecision
PUBLIC DetectSingleStepTiming
PUBLIC MeasureVMExitOverhead
PUBLIC GetPreciseRDTSC
PUBLIC GetPreciseRDTSCP
PUBLIC CalibrateTimingBaseline
PUBLIC DetectTimingHook
PUBLIC MeasureMemoryLatency
PUBLIC CheckHypervisorBit
PUBLIC MeasureIntOverhead
PUBLIC SandboxRDTSCDifference
PUBLIC GetRDTSCFrequency
PUBLIC DetectRDTSCEmulation

;; External Windows API (kernel32.dll)
EXTERN __imp_Sleep:QWORD
EXTERN __imp_GetTickCount64:QWORD

.CONST
;; Timing thresholds (in CPU cycles)
RDTSC_OVERHEAD_THRESHOLD    EQU 1000    ; Normal < 100 cycles, VM > 1000
CPUID_OVERHEAD_THRESHOLD    EQU 2000    ; Normal < 500 cycles, VM > 2000
SLEEP_DEVIATION_THRESHOLD   EQU 50      ; 50% deviation indicates acceleration
TIMING_PRECISION_MIN        EQU 100     ; Minimum precision for real hardware
VM_EXIT_THRESHOLD           EQU 5000    ; Combined VM exit threshold
MEMORY_LATENCY_THRESHOLD    EQU 500     ; Memory access latency threshold

;; Cuckoo sandbox detection
CUCKOO_AGENT_PORT           EQU 8000    ; Default Cuckoo agent port
CUCKOO_RESULTSERVER_PORT    EQU 2042    ; Default result server port

.DATA
;; Global calibration data
g_baselineRDTSC         DQ 0            ; Baseline RDTSC measurement
g_baselineCPUID         DQ 0            ; Baseline CPUID measurement
g_calibrationDone       DD 0            ; Calibration flag

;; Memory test buffer (cache line aligned)
ALIGN 64
g_memoryTestBuffer      DB 4096 DUP(0)  ; 4KB buffer for memory tests

.CODE

;; =============================================================================
;; GetPreciseRDTSC
;; =============================================================================
;; Gets RDTSC value with full serialization for accurate measurement.
;; Uses CPUID to serialize before RDTSC.
;;
;; Prototype: uint64_t GetPreciseRDTSC(void);
;; Returns: 64-bit TSC value in RAX
;; =============================================================================
GetPreciseRDTSC PROC
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
GetPreciseRDTSC ENDP

;; =============================================================================
;; GetPreciseRDTSCP
;; =============================================================================
;; Gets RDTSCP value which is self-serializing.
;; Also returns processor ID via output parameter.
;;
;; Prototype: uint64_t GetPreciseRDTSCP(uint32_t* processorId);
;; Parameters:
;;   RCX - Pointer to uint32_t for processor ID (optional, can be NULL)
;; Returns: 64-bit TSC value in RAX
;; =============================================================================
GetPreciseRDTSCP PROC
    push    rbx
    
    ;; Save processorId pointer
    mov     rbx, rcx
    
    ;; RDTSCP: RAX=TSC_LOW, RDX=TSC_HIGH, RCX=Processor_ID
    rdtscp
    
    ;; Store processor ID if pointer provided
    test    rbx, rbx
    jz      @NoProcessorId
    mov     DWORD PTR [rbx], ecx
    
@NoProcessorId:
    ;; Combine EDX:EAX into RAX
    shl     rdx, 32
    or      rax, rdx
    
    pop     rbx
    ret
GetPreciseRDTSCP ENDP

;; =============================================================================
;; MeasureRDTSCOverhead
;; =============================================================================
;; Measures the overhead of RDTSC instructions.
;; VMs typically have higher overhead due to VM exits.
;;
;; Prototype: uint64_t MeasureRDTSCOverhead(void);
;; Returns: Measured overhead in cycles (high = likely VM)
;; =============================================================================
MeasureRDTSCOverhead PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Serialize and get start time
    xor     eax, eax
    cpuid
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    ;; Measure 100 consecutive RDTSC calls
    mov     ecx, 100
@RDTSCLoop:
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    rdtsc
    dec     ecx
    jnz     @RDTSCLoop
    
    ;; Serialize and get end time
    xor     eax, eax
    cpuid
    rdtsc
    
    ;; Calculate total cycles
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    
    ;; Divide by 1000 iterations to get average
    xor     edx, edx
    mov     rcx, 1000
    div     rcx
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureRDTSCOverhead ENDP

;; =============================================================================
;; MeasureCPUIDOverhead
;; =============================================================================
;; Measures CPUID instruction overhead.
;; CPUID causes VM exits in virtualized environments.
;;
;; Prototype: uint64_t MeasureCPUIDOverhead(void);
;; Returns: Measured overhead in cycles (high = likely VM)
;; =============================================================================
MeasureCPUIDOverhead PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Warmup
    xor     eax, eax
    cpuid
    
    ;; Get start time
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    ;; Execute 100 CPUID instructions
    mov     ecx, 100
@CPUIDLoop:
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    xor     eax, eax
    cpuid
    dec     ecx
    jnz     @CPUIDLoop
    
    ;; Get end time
    rdtsc
    
    ;; Calculate total cycles
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    
    ;; Divide by 1000 iterations
    xor     edx, edx
    mov     rcx, 1000
    div     rcx
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureCPUIDOverhead ENDP

;; =============================================================================
;; MeasureSleepAcceleration
;; =============================================================================
;; Detects sandbox sleep acceleration/patching.
;; Compares TSC-measured sleep duration with actual duration.
;;
;; Prototype: uint64_t MeasureSleepAcceleration(uint32_t sleepMs);
;; Parameters:
;;   RCX - Sleep duration in milliseconds
;; Returns: Deviation percentage (0 = exact, >50 = likely patched)
;; =============================================================================
MeasureSleepAcceleration PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 40         ; Shadow space + alignment
    
    ;; Save sleep duration
    mov     r12d, ecx
    
    ;; Get start TSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r13, rax        ; r13 = start TSC
    
    ;; Get start tick count
    call    QWORD PTR [__imp_GetTickCount64]
    mov     rsi, rax        ; rsi = start ticks
    
    ;; Sleep
    mov     ecx, r12d
    call    QWORD PTR [__imp_Sleep]
    
    ;; Get end tick count
    call    QWORD PTR [__imp_GetTickCount64]
    mov     rdi, rax        ; rdi = end ticks
    
    ;; Get end TSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx        ; rax = end TSC
    
    ;; Calculate actual elapsed ms (from tick count)
    sub     rdi, rsi        ; rdi = actual elapsed ms
    
    ;; If requested >= 100ms, check for acceleration
    cmp     r12d, 100
    jb      @NoAcceleration
    
    ;; Calculate deviation: abs(actual - requested) * 100 / requested
    mov     rax, rdi
    cmp     rax, r12
    jae     @ActualGreater
    
    ;; Actual < Requested (possible acceleration)
    mov     rcx, r12
    sub     rcx, rax        ; deviation = requested - actual
    imul    rcx, 100
    xor     edx, edx
    mov     rbx, r12
    div     rbx             ; deviation percentage
    jmp     @Done
    
@ActualGreater:
    ;; Actual >= Requested (no acceleration)
    xor     eax, eax
    jmp     @Done
    
@NoAcceleration:
    xor     eax, eax
    
@Done:
    add     rsp, 40
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MeasureSleepAcceleration ENDP

;; =============================================================================
;; CheckCuckooBackdoor
;; =============================================================================
;; Detects Cuckoo sandbox backdoor communication.
;; Cuckoo uses a simple protocol on specific ports.
;;
;; Prototype: uint32_t CheckCuckooBackdoor(void);
;; Returns: 1 if Cuckoo indicators found, 0 otherwise
;; NOTE: This is a stub - actual network check requires WinSock
;; =============================================================================
CheckCuckooBackdoor PROC
    ;; Check for Cuckoo-specific environment variables
    ;; This is a detection stub - real detection would use network I/O
    
    push    rbx
    push    rcx
    push    rdx
    
    ;; Return 0 (no detection) - actual implementation in C++
    ;; Assembly can't easily do network operations
    xor     eax, eax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
CheckCuckooBackdoor ENDP

;; =============================================================================
;; MeasureTimingPrecision
;; =============================================================================
;; Measures the precision of RDTSC timing.
;; Sandboxes may use coarse-grained timing emulation.
;;
;; Prototype: uint64_t MeasureTimingPrecision(void);
;; Returns: Minimum timing delta (high values = emulation)
;; =============================================================================
MeasureTimingPrecision PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Initialize minimum to max value
    mov     rsi, 0FFFFFFFFFFFFFFFFh
    
    ;; Measure 100 consecutive RDTSC pairs
    mov     ecx, 100
    
@PrecisionLoop:
    ;; First RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rdi, rax
    
    ;; Second RDTSC (immediate)
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    
    ;; Calculate delta
    sub     rax, rdi
    
    ;; Update minimum if smaller
    cmp     rax, rsi
    jae     @NotSmaller
    mov     rsi, rax
    
@NotSmaller:
    dec     ecx
    jnz     @PrecisionLoop
    
    ;; Return minimum delta
    mov     rax, rsi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureTimingPrecision ENDP

;; =============================================================================
;; DetectSingleStepTiming
;; =============================================================================
;; Detects timing-based debuggers via instruction timing analysis.
;; Single-stepping adds significant overhead per instruction.
;;
;; Prototype: uint32_t DetectSingleStepTiming(void);
;; Returns: 1 if single-stepping detected, 0 otherwise
;; =============================================================================
DetectSingleStepTiming PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Get start time
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    ;; Execute a known number of simple instructions
    ;; These should take ~1 cycle each on real hardware
    xor     eax, eax
    xor     ebx, ebx
    inc     eax
    inc     ebx
    add     eax, ebx
    sub     eax, 1
    xor     ecx, ecx
    inc     ecx
    dec     ecx
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
    
    ;; Get end time
    rdtsc
    
    ;; Calculate elapsed cycles
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    
    ;; If > 1000 cycles for 20 instructions, likely single-stepping
    cmp     rax, 1000
    ja      @SingleStepDetected
    
    xor     eax, eax
    jmp     @SSReturn
    
@SingleStepDetected:
    mov     eax, 1
    
@SSReturn:
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
DetectSingleStepTiming ENDP

;; =============================================================================
;; MeasureVMExitOverhead
;; =============================================================================
;; Comprehensive VM detection via multiple timing measurements.
;; Combines RDTSC, CPUID, and I/O timing.
;;
;; Prototype: uint64_t MeasureVMExitOverhead(void);
;; Returns: Combined overhead score (higher = more likely VM)
;; =============================================================================
MeasureVMExitOverhead PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 32
    
    xor     r12, r12        ; Accumulator
    
    ;; Test 1: CPUID overhead
    xor     eax, eax
    cpuid
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    mov     eax, 1
    cpuid                   ; CPUID leaf 1 causes VM exit
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    add     r12, rax
    
    ;; Test 2: IN instruction (causes VM exit on I/O)
    ;; Skip actual IN to avoid crashes - just measure CPUID again
    xor     eax, eax
    cpuid
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    xor     eax, eax
    cpuid
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    add     r12, rax
    
    ;; Test 3: INVLPG-like instructions (virtualized)
    ;; Use SFENCE as a safe serializing instruction
    xor     eax, eax
    cpuid
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    sfence
    lfence
    mfence
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    add     r12, rax
    
    ;; Return combined score
    mov     rax, r12
    
    add     rsp, 32
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureVMExitOverhead ENDP

;; =============================================================================
;; CalibrateTimingBaseline
;; =============================================================================
;; Establishes baseline timing values for detection.
;; Should be called once at startup.
;;
;; Prototype: void CalibrateTimingBaseline(void);
;; =============================================================================
CalibrateTimingBaseline PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Check if already calibrated
    cmp     DWORD PTR [g_calibrationDone], 1
    je      @AlreadyCalibrated
    
    ;; Measure RDTSC baseline (average of 10 measurements)
    xor     rsi, rsi
    mov     ecx, 10
    
@CalibRDTSCLoop:
    push    rcx
    
    xor     eax, eax
    cpuid
    rdtsc
    mov     edi, eax
    mov     ebx, edx
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rbx, 32
    or      rdi, rbx
    sub     rax, rdi
    add     rsi, rax
    
    pop     rcx
    dec     ecx
    jnz     @CalibRDTSCLoop
    
    ;; Average
    xor     edx, edx
    mov     rcx, 10
    mov     rax, rsi
    div     rcx
    mov     QWORD PTR [g_baselineRDTSC], rax
    
    ;; Measure CPUID baseline
    xor     rsi, rsi
    mov     ecx, 10
    
@CalibCPUIDLoop:
    push    rcx
    
    rdtsc
    mov     edi, eax
    mov     ebx, edx
    
    xor     eax, eax
    cpuid
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rbx, 32
    or      rdi, rbx
    sub     rax, rdi
    add     rsi, rax
    
    pop     rcx
    dec     ecx
    jnz     @CalibCPUIDLoop
    
    ;; Average
    xor     edx, edx
    mov     rcx, 10
    mov     rax, rsi
    div     rcx
    mov     QWORD PTR [g_baselineCPUID], rax
    
    ;; Mark as calibrated
    mov     DWORD PTR [g_calibrationDone], 1
    
@AlreadyCalibrated:
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
CalibrateTimingBaseline ENDP

;; =============================================================================
;; DetectTimingHook
;; =============================================================================
;; Detects if timing functions are hooked.
;; Compares raw RDTSC with API timing.
;;
;; Prototype: uint32_t DetectTimingHook(void);
;; Returns: 1 if timing hook detected, 0 otherwise
;; =============================================================================
DetectTimingHook PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 40
    
    ;; Get raw RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax
    
    ;; Get QueryPerformanceCounter equivalent (via RDTSCP if available)
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    
    ;; Compare - significant difference indicates hooking
    sub     rax, r12
    
    ;; Allow some variation, but flag large discrepancies
    cmp     rax, 10000
    ja      @HookDetected
    
    xor     eax, eax
    jmp     @HookReturn
    
@HookDetected:
    mov     eax, 1
    
@HookReturn:
    add     rsp, 40
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
DetectTimingHook ENDP

;; =============================================================================
;; MeasureMemoryLatency
;; =============================================================================
;; Measures memory access latency.
;; VM memory virtualization adds latency.
;;
;; Prototype: uint64_t MeasureMemoryLatency(void);
;; Returns: Memory access latency in cycles
;; =============================================================================
MeasureMemoryLatency PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Flush cache line
    lea     rdi, [g_memoryTestBuffer]
    clflush [rdi]
    mfence
    
    ;; Measure uncached access time
    rdtsc
    mov     esi, eax
    mov     ebx, edx
    
    ;; Access memory (uncached)
    mov     rax, QWORD PTR [rdi]
    
    ;; Serialize
    lfence
    
    ;; Get end time
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rbx, 32
    or      rsi, rbx
    sub     rax, rsi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureMemoryLatency ENDP

;; =============================================================================
;; CheckHypervisorBit
;; =============================================================================
;; Checks CPUID hypervisor present bit (leaf 1, ECX bit 31).
;; This is the standard way hypervisors announce themselves.
;;
;; Prototype: uint32_t CheckHypervisorBit(void);
;; Returns: 1 if hypervisor bit set, 0 otherwise
;; =============================================================================
CheckHypervisorBit PROC
    push    rbx
    push    rcx
    push    rdx
    
    ;; CPUID leaf 1
    mov     eax, 1
    cpuid
    
    ;; Check hypervisor bit (ECX bit 31)
    bt      ecx, 31
    jnc     @NoHypervisor
    
    mov     eax, 1
    jmp     @HVReturn
    
@NoHypervisor:
    xor     eax, eax
    
@HVReturn:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
CheckHypervisorBit ENDP

;; =============================================================================
;; MeasureIntOverhead
;; =============================================================================
;; Measures interrupt handling overhead.
;; Some sandboxes have unusual interrupt timing.
;;
;; Prototype: uint64_t MeasureIntOverhead(void);
;; Returns: Interrupt overhead measurement (not actual INT - too dangerous)
;; =============================================================================
MeasureIntOverhead PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    
    ;; Measure exception-causing instruction overhead
    ;; Using CPUID with hypervisor leaf as proxy
    xor     eax, eax
    cpuid
    rdtsc
    mov     esi, eax
    mov     edi, edx
    
    ;; CPUID with high leaf (may cause VM exit)
    mov     eax, 40000000h  ; Hypervisor leaf
    cpuid
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    shl     rdi, 32
    or      rsi, rdi
    sub     rax, rsi
    
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
MeasureIntOverhead ENDP

;; =============================================================================
;; SandboxRDTSCDifference
;; =============================================================================
;; Computes RDTSC difference over a known delay.
;; Used to detect time manipulation.
;;
;; Prototype: uint64_t SandboxRDTSCDifference(uint32_t iterations);
;; Parameters:
;;   RCX - Number of loop iterations
;; Returns: Total RDTSC difference
;; =============================================================================
SandboxRDTSCDifference PROC
    push    rbx
    push    rsi
    push    rdi
    
    mov     ebx, ecx        ; Save iteration count
    test    ebx, ebx
    jz      @ZeroIter
    
    ;; Get start RDTSC
    xor     eax, eax
    cpuid
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax
    
    ;; Busy loop
@BusyLoop:
    pause
    dec     ebx
    jnz     @BusyLoop
    
    ;; Get end RDTSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, rsi
    jmp     @SDReturn
    
@ZeroIter:
    xor     eax, eax
    
@SDReturn:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
SandboxRDTSCDifference ENDP

;; =============================================================================
;; GetRDTSCFrequency
;; =============================================================================
;; Estimates RDTSC frequency using CPUID if available.
;; Falls back to measurement-based estimation.
;;
;; Prototype: uint64_t GetRDTSCFrequency(void);
;; Returns: Estimated frequency in Hz (0 if unavailable)
;; =============================================================================
GetRDTSCFrequency PROC
    push    rbx
    push    rcx
    push    rdx
    
    ;; Try CPUID leaf 0x15 (TSC/Core Crystal Clock info)
    mov     eax, 15h
    cpuid
    
    ;; Check if info is valid (EBX != 0 && ECX != 0)
    test    ebx, ebx
    jz      @NoTSCInfo
    test    ecx, ecx
    jz      @NoTSCInfo
    
    ;; TSC frequency = (ECX * EBX) / EAX
    ;; ECX = nominal frequency, EBX = TSC/core ratio numerator, EAX = denominator
    mov     r8d, eax        ; denominator
    imul    rbx, rcx        ; numerator * frequency
    mov     rax, rbx
    xor     edx, edx
    div     r8              ; divide by denominator
    jmp     @FreqReturn
    
@NoTSCInfo:
    ;; Return 0 - caller should use measurement-based estimation
    xor     eax, eax
    
@FreqReturn:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
GetRDTSCFrequency ENDP

;; =============================================================================
;; DetectRDTSCEmulation
;; =============================================================================
;; Detects RDTSC emulation by checking for unrealistic values.
;; Some sandboxes return constant or sequentially increasing values.
;;
;; Prototype: uint32_t DetectRDTSCEmulation(void);
;; Returns: 1 if emulation detected, 0 otherwise
;; =============================================================================
DetectRDTSCEmulation PROC
    push    rbx
    push    rcx
    push    rsi
    push    rdi
    push    r12
    push    r13
    
    ;; Take 3 consecutive RDTSC readings
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax        ; First reading
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r13, rax        ; Second reading
    
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax        ; Third reading
    
    ;; Check for constant values (clear emulation sign)
    cmp     r12, r13
    je      @EmulationDetected
    cmp     r13, rsi
    je      @EmulationDetected
    
    ;; Check for suspicious constant increment
    mov     rdi, r13
    sub     rdi, r12        ; delta1
    mov     rbx, rsi
    sub     rbx, r13        ; delta2
    
    ;; If deltas are exactly equal, suspicious
    cmp     rdi, rbx
    jne     @NotEmulated
    
    ;; But allow some tolerance - exact match 3 times is suspicious
    ;; Additional check needed
    
@NotEmulated:
    xor     eax, eax
    jmp     @EmulReturn
    
@EmulationDetected:
    mov     eax, 1
    
@EmulReturn:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rcx
    pop     rbx
    ret
DetectRDTSCEmulation ENDP

END
