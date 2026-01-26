; ==============================================================================
; EnvironmentEvasionDetector_x64.asm
;
; ShadowStrike AntiEvasion - x64 Assembly Functions for Environment Detection
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; This module provides low-level CPUID-based VM/hypervisor detection functions
; that cannot be easily implemented in C++ due to compiler optimizations and
; intrinsic limitations.
;
; Functions exported:
; - CheckCPUIDHypervisorBit: Detects hypervisor presence via CPUID
; - GetCPUIDBrandString: Retrieves CPU brand string for VM detection
;
; Architecture: x64 (AMD64/Intel 64)
; Calling Convention: Microsoft x64 calling convention
; ==============================================================================

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
    ; Save registers (Microsoft x64 calling convention)
    push    rbx
    push    rcx
    push    rdx

    ; Check if CPUID is supported
    ; Try to flip bit 21 (ID bit) in EFLAGS
    pushfq                      ; Push RFLAGS onto stack
    pop     rax                 ; Pop into RAX
    mov     rcx, rax            ; Save original RFLAGS
    xor     rax, 200000h        ; Flip ID bit (bit 21)
    push    rax                 ; Push modified value
    popfq                       ; Pop into RFLAGS
    pushfq                      ; Push RFLAGS again
    pop     rax                 ; Pop into RAX
    xor     rax, rcx            ; Check if bit was flipped
    jz      no_cpuid            ; If zero, CPUID not supported

    ; CPUID is supported, check for hypervisor bit
    ; Execute CPUID with EAX=1 (Processor Info and Feature Bits)
    mov     eax, 1              ; CPUID leaf 1
    xor     ecx, ecx            ; Clear ECX
    cpuid                       ; Execute CPUID

    ; Check bit 31 of ECX (hypervisor present bit)
    bt      ecx, 31             ; Test bit 31
    jc      hypervisor_found    ; If carry flag set, hypervisor present

    ; No hypervisor detected
    xor     rax, rax            ; Return false (0)
    jmp     cleanup

hypervisor_found:
    mov     rax, 1              ; Return true (1)
    jmp     cleanup

no_cpuid:
    xor     rax, rax            ; Return false if CPUID not supported

cleanup:
    ; Restore registers
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
; Calling Convention: Microsoft x64
; Parameters:
;   RCX = char* buffer (output buffer for brand string)
;   RDX = size_t bufferSize (size of buffer in bytes, should be >= 49)
;
; Returns: None (writes directly to buffer)
;
; Technical Details:
; - Uses CPUID leaves 0x80000002, 0x80000003, 0x80000004
; - Each leaf returns 16 bytes of the brand string (in EAX, EBX, ECX, EDX)
; - Total brand string is 48 bytes + null terminator
; - VM brand strings often include: "QEMU Virtual CPU", "VirtualBox", etc.
; ==============================================================================
GetCPUIDBrandString PROC
    ; Save registers
    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13

    ; Save parameters
    mov     rdi, rcx            ; RDI = buffer pointer
    mov     r12, rdx            ; R12 = buffer size

    ; Validate buffer pointer
    test    rdi, rdi
    jz      exit_function       ; Exit if null pointer

    ; Validate buffer size (need at least 49 bytes: 48 + null)
    cmp     r12, 49
    jb      exit_function       ; Exit if buffer too small

    ; Zero out the buffer first
    mov     rsi, rdi
    mov     rcx, r12
    xor     al, al
    rep     stosb
    mov     rdi, rsi            ; Restore buffer pointer

    ; Check if extended CPUID is supported
    ; Execute CPUID with EAX=0x80000000 to get max extended leaf
    mov     eax, 80000000h
    cpuid
    cmp     eax, 80000004h      ; Check if leaf 0x80000004 is supported
    jb      exit_function       ; Exit if not supported

    ; Get first 16 bytes (CPUID leaf 0x80000002)
    mov     eax, 80000002h
    cpuid
    mov     [rdi], eax          ; Store EAX (bytes 0-3)
    mov     [rdi+4], ebx        ; Store EBX (bytes 4-7)
    mov     [rdi+8], ecx        ; Store ECX (bytes 8-11)
    mov     [rdi+12], edx       ; Store EDX (bytes 12-15)

    ; Get second 16 bytes (CPUID leaf 0x80000003)
    mov     eax, 80000003h
    cpuid
    mov     [rdi+16], eax       ; Store EAX (bytes 16-19)
    mov     [rdi+20], ebx       ; Store EBX (bytes 20-23)
    mov     [rdi+24], ecx       ; Store ECX (bytes 24-27)
    mov     [rdi+28], edx       ; Store EDX (bytes 28-31)

    ; Get third 16 bytes (CPUID leaf 0x80000004)
    mov     eax, 80000004h
    cpuid
    mov     [rdi+32], eax       ; Store EAX (bytes 32-35)
    mov     [rdi+36], ebx       ; Store EBX (bytes 36-39)
    mov     [rdi+40], ecx       ; Store ECX (bytes 40-43)
    mov     [rdi+44], edx       ; Store EDX (bytes 44-47)

    ; Ensure null termination
    mov     byte ptr [rdi+48], 0

exit_function:
    ; Restore registers
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    ret
GetCPUIDBrandString ENDP

; ==============================================================================
; Additional Advanced Detection Functions (Optional Extensions)
; ==============================================================================

; Note: The following functions are optional and can be uncommented if needed
; for more advanced VM detection capabilities.

; ==============================================================================
; CheckRDTSCTimingAnomaly
;
; Detects VM presence through RDTSC timing anomalies.
; VMs typically show higher variance in RDTSC measurements due to hypervisor
; scheduling and time slice allocation.
;
; This function is commented out but can be enabled for enhanced detection.
; ==============================================================================
; CheckRDTSCTimingAnomaly PROC
;     push    rbx
;     push    rcx
;     push    rdx
;
;     ; Measure RDTSC variance over multiple iterations
;     mov     rcx, 100            ; Number of samples
;     rdtsc                       ; Get initial timestamp
;     mov     rbx, rax            ; Save low 32 bits
;
; measure_loop:
;     rdtsc
;     sub     rax, rbx            ; Calculate delta
;     mov     rbx, rax            ; Update previous timestamp
;     ; (Add statistical analysis here)
;     loop    measure_loop
;
;     ; (Return 1 if anomaly detected, 0 otherwise)
;     xor     rax, rax
;
;     pop     rdx
;     pop     rcx
;     pop     rbx
;     ret
; CheckRDTSCTimingAnomaly ENDP

END
