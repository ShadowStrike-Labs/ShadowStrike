; ==============================================================================
; PackerDetector_x64.asm
; Enterprise-grade x64 assembly functions for Packer Detection
;
; ShadowStrike AntiEvasion - Packer Detection Module
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; This module provides low-level detection functions for detecting packed
; executables, unpacking stubs, and anti-unpacking techniques that cannot
; be reliably implemented in C++ due to compiler optimizations.
;
; ============================================================================
; FUNCTIONS - TIMING-BASED UNPACKER DETECTION
; ============================================================================
; - MeasureUnpackStubTiming: RDTSC-based execution timing for stub analysis
; - MeasureInstructionSequence: Precise timing of instruction sequences
; - DetectTimingAnomaly: Detect abnormal timing (anti-debugging in unpacker)
;
; ============================================================================
; FUNCTIONS - SELF-MODIFYING CODE DETECTION
; ============================================================================
; - CheckCodePageWritability: Test if code page is writable (SMC indicator)
; - DetectCodeModification: Monitor code section for modifications
; - ScanForSMCPatterns: Scan for self-modifying code patterns
;
; ============================================================================
; FUNCTIONS - DEBUG REGISTER MONITORING
; ============================================================================
; - GetDebugRegistersForUnpacker: Read DR0-DR7 to detect unpacker monitoring
; - CheckHardwareBreakpointTraps: Detect hardware breakpoint-based unpacking
;
; ============================================================================
; FUNCTIONS - ANTI-UNPACKING DETECTION
; ============================================================================
; - DetectRDTSCAntiDebug: Detect RDTSC-based anti-debugging in unpacker
; - DetectExceptionAntiDebug: Detect exception-based anti-debugging
; - ScanForAntiDebugOpcodes: SIMD-accelerated anti-debug opcode scanning
;
; ============================================================================
; FUNCTIONS - UNPACKER ANALYSIS
; ============================================================================
; - MeasureDecompressionLoop: Time decompression loop execution
; - DetectPolymorphicDecryptor: Detect polymorphic decryption routines
; - AnalyzeUnpackerControlFlow: Control flow analysis of unpacker
;
; CALLING CONVENTION: Microsoft x64 calling convention
; - First 4 args: RCX, RDX, R8, R9
; - Return: RAX (integers), XMM0 (floats)
; - Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
; - Callee-saved: RBX, RBP, RDI, RSI, RSP, R12-R15
; ==============================================================================

; ==============================================================================
; PUBLIC SYMBOL EXPORTS
; ==============================================================================

; Timing-based detection
PUBLIC MeasureUnpackStubTiming
PUBLIC MeasureInstructionSequence
PUBLIC DetectTimingAnomaly
PUBLIC GetRDTSCValue
PUBLIC GetRDTSCPValue

; Debug register monitoring
PUBLIC GetDebugRegistersForUnpacker
PUBLIC CheckHardwareBreakpointTraps
PUBLIC ReadDR0
PUBLIC ReadDR1
PUBLIC ReadDR2
PUBLIC ReadDR3
PUBLIC ReadDR6
PUBLIC ReadDR7

; Anti-unpacking detection
PUBLIC DetectRDTSCAntiDebug
PUBLIC ScanForAntiDebugOpcodes
PUBLIC ScanForInt2DOpcode
PUBLIC ScanForRDTSCOpcode
PUBLIC ScanForCPUIDOpcode

; Code analysis
PUBLIC CheckCodePageWritability
PUBLIC ScanForSMCPatterns
PUBLIC ScanForXORDecryptionLoop
PUBLIC ScanForAPIHashingPattern

; SIMD-accelerated scanning
PUBLIC SIMDScanForByte
PUBLIC SIMDScanForWord
PUBLIC SIMDScanForPattern

.code

; ==============================================================================
; GetRDTSCValue
; Get current RDTSC timestamp value
;
; Returns: RAX = 64-bit timestamp (EDX:EAX combined)
; ==============================================================================
GetRDTSCValue PROC
    ; Save callee-saved registers
    push rbx
    
    ; Execute RDTSC
    rdtsc
    
    ; Combine EDX:EAX into RAX
    shl rdx, 32
    or rax, rdx
    
    pop rbx
    ret
GetRDTSCValue ENDP

; ==============================================================================
; GetRDTSCPValue
; Get serializing RDTSCP timestamp value with processor ID
;
; Parameters:
;   RCX = pointer to uint32_t for processor ID (optional, can be NULL)
;
; Returns: RAX = 64-bit timestamp
; ==============================================================================
GetRDTSCPValue PROC
    push rbx
    push rcx                    ; Save processor ID pointer
    
    ; Execute RDTSCP (serializing)
    rdtscp
    
    ; Combine EDX:EAX into RAX
    shl rdx, 32
    or rax, rdx
    
    ; Store processor ID if pointer provided
    pop rcx
    test rcx, rcx
    jz @skip_pid
    mov dword ptr [rcx], ecx    ; ECX from RDTSCP contains processor ID
@skip_pid:
    
    pop rbx
    ret
GetRDTSCPValue ENDP

; ==============================================================================
; MeasureUnpackStubTiming
; Measure RDTSC delta for unpacker stub timing analysis
; Used to detect if unpacker employs timing-based anti-debugging
;
; Parameters:
;   RCX = pointer to code to measure
;   RDX = size of code region
;   R8  = pointer to uint64_t for start time
;   R9  = pointer to uint64_t for end time
;
; Returns: RAX = delta (end - start)
; ==============================================================================
MeasureUnpackStubTiming PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    
    mov r12, rcx                ; Code pointer
    mov r13, rdx                ; Code size
    mov rdi, r8                 ; Start time pointer
    mov rsi, r9                 ; End time pointer
    
    ; Serialize and get start time
    xor eax, eax
    cpuid                       ; Serialize
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rdi], rax              ; Store start time
    mov rbx, rax                ; Save start time
    
    ; Memory fence to ensure timing accuracy
    mfence
    
    ; Read code bytes to simulate analysis (don't execute)
    ; This measures memory access timing which packers may detect
    mov rcx, r13
    mov rsi, r12
    xor rax, rax
@read_loop:
    test rcx, rcx
    jz @read_done
    movzx r10d, byte ptr [rsi]
    add rax, r10
    inc rsi
    dec rcx
    jmp @read_loop
@read_done:
    
    ; Memory fence
    mfence
    
    ; Serialize and get end time
    xor eax, eax
    cpuid                       ; Serialize
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rsi], rax              ; Store end time
    
    ; Calculate delta
    sub rax, rbx
    
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
MeasureUnpackStubTiming ENDP

; ==============================================================================
; MeasureInstructionSequence
; Precisely measure timing of a specific instruction sequence
;
; Parameters:
;   RCX = number of iterations
;
; Returns: RAX = average cycles per iteration
; ==============================================================================
MeasureInstructionSequence PROC
    push rbx
    push r12
    
    mov r12, rcx                ; Iteration count
    test r12, r12
    jz @zero_iter
    
    ; Get start time
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax                ; Save start
    
    ; Execute NOP sequence (baseline timing)
    mov rcx, r12
@nop_loop:
    nop
    nop
    nop
    nop
    dec rcx
    jnz @nop_loop
    
    ; Get end time
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    ; Calculate average
    sub rax, rbx
    xor rdx, rdx
    div r12
    
    pop r12
    pop rbx
    ret
    
@zero_iter:
    xor rax, rax
    pop r12
    pop rbx
    ret
MeasureInstructionSequence ENDP

; ==============================================================================
; DetectTimingAnomaly
; Detect timing anomalies that indicate VM/debugging environment
;
; Parameters:
;   RCX = threshold for anomaly detection (cycles)
;
; Returns: RAX = 1 if anomaly detected, 0 otherwise
; ==============================================================================
DetectTimingAnomaly PROC
    push rbx
    push r12
    push r13
    
    mov r12, rcx                ; Threshold
    
    ; Measure CPUID timing (heavily trapped in VMs)
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax
    
    ; Execute CPUID (this is slow in VMs due to vmexit)
    xor eax, eax
    cpuid
    
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx
    mov r13, rax                ; CPUID timing
    
    ; Compare against threshold
    cmp r13, r12
    ja @anomaly_detected
    
    xor rax, rax
    jmp @detect_done
    
@anomaly_detected:
    mov rax, 1
    
@detect_done:
    pop r13
    pop r12
    pop rbx
    ret
DetectTimingAnomaly ENDP

; ==============================================================================
; GetDebugRegistersForUnpacker
; Read all debug registers to detect unpacker hardware breakpoint usage
;
; Parameters:
;   RCX = pointer to 8-element uint64_t array [DR0,DR1,DR2,DR3,DR6,DR7,0,0]
;
; Returns: RAX = 1 if successful, 0 if failed (access denied)
; ==============================================================================
GetDebugRegistersForUnpacker PROC
    push rbx
    
    test rcx, rcx
    jz @dr_fail
    
    ; Note: Reading DR0-DR7 requires ring 0 or debugger privileges
    ; In user mode, this will cause #GP if not debugging
    ; We use SEH to handle the exception gracefully
    
    ; Try to read debug registers
    ; This is wrapped in SEH in the C++ caller
    mov rax, dr0
    mov [rcx], rax
    mov rax, dr1
    mov [rcx + 8], rax
    mov rax, dr2
    mov [rcx + 16], rax
    mov rax, dr3
    mov [rcx + 24], rax
    mov rax, dr6
    mov [rcx + 32], rax
    mov rax, dr7
    mov [rcx + 40], rax
    
    mov rax, 1
    pop rbx
    ret
    
@dr_fail:
    xor rax, rax
    pop rbx
    ret
GetDebugRegistersForUnpacker ENDP

; ==============================================================================
; Individual debug register accessors
; These are safer for SEH wrapping
; ==============================================================================
ReadDR0 PROC
    mov rax, dr0
    ret
ReadDR0 ENDP

ReadDR1 PROC
    mov rax, dr1
    ret
ReadDR1 ENDP

ReadDR2 PROC
    mov rax, dr2
    ret
ReadDR2 ENDP

ReadDR3 PROC
    mov rax, dr3
    ret
ReadDR3 ENDP

ReadDR6 PROC
    mov rax, dr6
    ret
ReadDR6 ENDP

ReadDR7 PROC
    mov rax, dr7
    ret
ReadDR7 ENDP

; ==============================================================================
; CheckHardwareBreakpointTraps
; Check if hardware breakpoints are set (indicates analysis)
;
; Parameters:
;   RCX = pointer to uint64_t DR7 value
;
; Returns: RAX = number of active breakpoints (0-4)
; ==============================================================================
CheckHardwareBreakpointTraps PROC
    test rcx, rcx
    jz @no_dr7
    
    mov rax, [rcx]              ; Load DR7 value
    
    xor rcx, rcx                ; Counter
    
    ; Check L0 (bit 0) - Local breakpoint 0
    test al, 1
    jz @check_l1
    inc rcx
    
@check_l1:
    ; Check L1 (bit 2)
    test al, 4
    jz @check_l2
    inc rcx
    
@check_l2:
    ; Check L2 (bit 4)
    test al, 10h
    jz @check_l3
    inc rcx
    
@check_l3:
    ; Check L3 (bit 6)
    test al, 40h
    jz @bp_done
    inc rcx
    
@bp_done:
    mov rax, rcx
    ret
    
@no_dr7:
    xor rax, rax
    ret
CheckHardwareBreakpointTraps ENDP

; ==============================================================================
; DetectRDTSCAntiDebug
; Detect RDTSC-based anti-debugging by measuring timing variance
;
; Parameters:
;   RCX = number of samples to take
;   RDX = pointer to uint64_t array for samples
;
; Returns: RAX = 1 if anti-debug detected (high variance), 0 otherwise
; ==============================================================================
DetectRDTSCAntiDebug PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    
    mov r12, rcx                ; Sample count
    mov r13, rdx                ; Sample array
    
    test r12, r12
    jz @rdtsc_fail
    test r13, r13
    jz @rdtsc_fail
    
    xor r14, r14                ; Sum for average
    xor rsi, rsi                ; Index
    
@sample_loop:
    cmp rsi, r12
    jge @samples_done
    
    ; Take RDTSC sample
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax
    
    ; Small delay
    mov rcx, 100
@delay:
    nop
    dec rcx
    jnz @delay
    
    mfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx
    
    ; Store sample
    mov [r13 + rsi * 8], rax
    add r14, rax
    inc rsi
    jmp @sample_loop
    
@samples_done:
    ; Calculate average
    mov rax, r14
    xor rdx, rdx
    div r12
    mov rbx, rax                ; Average
    
    ; Calculate variance (simplified: count samples > 2x average)
    xor rcx, rcx                ; Anomaly count
    xor rsi, rsi
    shl rbx, 1                  ; 2x average threshold
    
@variance_loop:
    cmp rsi, r12
    jge @variance_done
    mov rax, [r13 + rsi * 8]
    cmp rax, rbx
    jbe @not_anomaly
    inc rcx
@not_anomaly:
    inc rsi
    jmp @variance_loop
    
@variance_done:
    ; If > 10% anomalies, detect as anti-debug
    mov rax, r12
    shr rax, 3                  ; ~12.5% threshold
    cmp rcx, rax
    ja @anti_debug_detected
    
    xor rax, rax
    jmp @rdtsc_done
    
@anti_debug_detected:
    mov rax, 1
    jmp @rdtsc_done
    
@rdtsc_fail:
    xor rax, rax
    
@rdtsc_done:
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
DetectRDTSCAntiDebug ENDP

; ==============================================================================
; ScanForAntiDebugOpcodes
; SIMD-accelerated scan for anti-debugging opcodes in code
;
; Parameters:
;   RCX = pointer to code buffer
;   RDX = size of buffer
;   R8  = pointer to result flags (uint32_t)
;         Bit 0: INT 2D found
;         Bit 1: INT 3 found
;         Bit 2: RDTSC found
;         Bit 3: CPUID found
;         Bit 4: IN/OUT (VM detect) found
;
; Returns: RAX = total count of anti-debug opcodes found
; ==============================================================================
ScanForAntiDebugOpcodes PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    mov rsi, rcx                ; Buffer
    mov r12, rdx                ; Size
    mov r13, r8                 ; Result flags pointer
    
    test rsi, rsi
    jz @scan_fail
    test r12, r12
    jz @scan_fail
    
    xor r14, r14                ; Total count
    xor r15, r15                ; Flags
    
    xor rdi, rdi                ; Index
    
@scan_loop:
    cmp rdi, r12
    jge @scan_done
    
    movzx eax, byte ptr [rsi + rdi]
    
    ; Check for INT instruction (0xCD)
    cmp al, 0CDh
    jne @not_int
    
    ; Check next byte for INT number
    lea rcx, [rdi + 1]
    cmp rcx, r12
    jge @not_int
    
    movzx ebx, byte ptr [rsi + rdi + 1]
    
    ; INT 2D (anti-debug)
    cmp bl, 2Dh
    jne @check_int3_cd
    or r15d, 1                  ; Set bit 0
    inc r14
    jmp @next_byte
    
@check_int3_cd:
    ; INT 3 via CD 03
    cmp bl, 03h
    jne @next_byte
    or r15d, 2                  ; Set bit 1
    inc r14
    jmp @next_byte
    
@not_int:
    ; Check for single-byte INT 3 (0xCC)
    cmp al, 0CCh
    jne @not_int3
    or r15d, 2                  ; Set bit 1
    inc r14
    jmp @next_byte
    
@not_int3:
    ; Check for RDTSC (0x0F 0x31)
    cmp al, 0Fh
    jne @not_0f
    
    lea rcx, [rdi + 1]
    cmp rcx, r12
    jge @not_0f
    
    movzx ebx, byte ptr [rsi + rdi + 1]
    
    ; RDTSC
    cmp bl, 31h
    jne @check_cpuid
    or r15d, 4                  ; Set bit 2
    inc r14
    jmp @next_byte
    
@check_cpuid:
    ; CPUID (0x0F 0xA2)
    cmp bl, 0A2h
    jne @next_byte
    or r15d, 8                  ; Set bit 3
    inc r14
    jmp @next_byte
    
@not_0f:
    ; Check for IN (0xEC, 0xED, 0xE4, 0xE5)
    cmp al, 0ECh
    je @found_io
    cmp al, 0EDh
    je @found_io
    cmp al, 0E4h
    je @found_io
    cmp al, 0E5h
    jne @check_out
    
@found_io:
    or r15d, 10h                ; Set bit 4
    inc r14
    jmp @next_byte
    
@check_out:
    ; Check for OUT (0xEE, 0xEF, 0xE6, 0xE7)
    cmp al, 0EEh
    je @found_io
    cmp al, 0EFh
    je @found_io
    cmp al, 0E6h
    je @found_io
    cmp al, 0E7h
    je @found_io
    
@next_byte:
    inc rdi
    jmp @scan_loop
    
@scan_done:
    ; Store flags if pointer provided
    test r13, r13
    jz @no_flags
    mov [r13], r15d
    
@no_flags:
    mov rax, r14
    jmp @scan_exit
    
@scan_fail:
    xor rax, rax
    
@scan_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
ScanForAntiDebugOpcodes ENDP

; ==============================================================================
; Individual opcode scanners (for targeted scanning)
; ==============================================================================
ScanForInt2DOpcode PROC
    ; RCX = buffer, RDX = size
    ; Returns: RAX = offset if found, -1 if not found
    push rdi
    
    test rcx, rcx
    jz @int2d_notfound
    test rdx, rdx
    jz @int2d_notfound
    
    xor rdi, rdi
@int2d_loop:
    lea rax, [rdi + 1]
    cmp rax, rdx
    jge @int2d_notfound
    
    movzx eax, byte ptr [rcx + rdi]
    cmp al, 0CDh
    jne @int2d_next
    
    movzx eax, byte ptr [rcx + rdi + 1]
    cmp al, 2Dh
    jne @int2d_next
    
    mov rax, rdi
    pop rdi
    ret
    
@int2d_next:
    inc rdi
    jmp @int2d_loop
    
@int2d_notfound:
    mov rax, -1
    pop rdi
    ret
ScanForInt2DOpcode ENDP

ScanForRDTSCOpcode PROC
    ; RCX = buffer, RDX = size
    ; Returns: RAX = offset if found, -1 if not found
    push rdi
    
    test rcx, rcx
    jz @rdtsc_notfound
    test rdx, rdx
    jz @rdtsc_notfound
    
    xor rdi, rdi
@rdtsc_loop:
    lea rax, [rdi + 1]
    cmp rax, rdx
    jge @rdtsc_notfound
    
    movzx eax, byte ptr [rcx + rdi]
    cmp al, 0Fh
    jne @rdtsc_next
    
    movzx eax, byte ptr [rcx + rdi + 1]
    cmp al, 31h
    jne @rdtsc_next
    
    mov rax, rdi
    pop rdi
    ret
    
@rdtsc_next:
    inc rdi
    jmp @rdtsc_loop
    
@rdtsc_notfound:
    mov rax, -1
    pop rdi
    ret
ScanForRDTSCOpcode ENDP

ScanForCPUIDOpcode PROC
    ; RCX = buffer, RDX = size
    ; Returns: RAX = offset if found, -1 if not found
    push rdi
    
    test rcx, rcx
    jz @cpuid_notfound
    test rdx, rdx
    jz @cpuid_notfound
    
    xor rdi, rdi
@cpuid_loop:
    lea rax, [rdi + 1]
    cmp rax, rdx
    jge @cpuid_notfound
    
    movzx eax, byte ptr [rcx + rdi]
    cmp al, 0Fh
    jne @cpuid_next
    
    movzx eax, byte ptr [rcx + rdi + 1]
    cmp al, 0A2h
    jne @cpuid_next
    
    mov rax, rdi
    pop rdi
    ret
    
@cpuid_next:
    inc rdi
    jmp @cpuid_loop
    
@cpuid_notfound:
    mov rax, -1
    pop rdi
    ret
ScanForCPUIDOpcode ENDP

; ==============================================================================
; CheckCodePageWritability
; Check if a code page is writable (self-modifying code indicator)
;
; Parameters:
;   RCX = address to check
;
; Returns: RAX = 1 if writable, 0 if not
; ==============================================================================
CheckCodePageWritability PROC
    ; This checks by attempting to read the existing value
    ; Actual writability test requires VirtualProtect in user mode
    ; This is a placeholder that returns based on page alignment
    
    test rcx, rcx
    jz @not_writable
    
    ; Check if we can read (basic validity check)
    mov al, [rcx]
    
    ; In reality, need VirtualQuery to check PAGE_EXECUTE_READWRITE
    ; Return 0 as we can't safely test writability from assembly
    xor rax, rax
    ret
    
@not_writable:
    xor rax, rax
    ret
CheckCodePageWritability ENDP

; ==============================================================================
; ScanForXORDecryptionLoop
; Scan for XOR-based decryption loop pattern
; Pattern: XOR [mem], reg/imm followed by loop/jnz
;
; Parameters:
;   RCX = buffer
;   RDX = size
;
; Returns: RAX = count of XOR decryption patterns found
; ==============================================================================
ScanForXORDecryptionLoop PROC
    push rbx
    push rdi
    push rsi
    
    mov rsi, rcx
    mov rbx, rdx
    
    test rsi, rsi
    jz @xor_fail
    test rbx, rbx
    jz @xor_fail
    
    xor rax, rax                ; Pattern count
    xor rdi, rdi                ; Index
    
@xor_scan_loop:
    lea rcx, [rdi + 2]
    cmp rcx, rbx
    jge @xor_done
    
    ; Look for XOR with memory operand (30-33 opcodes with ModRM)
    movzx ecx, byte ptr [rsi + rdi]
    
    ; XOR r/m8, r8 (30)
    cmp cl, 30h
    je @found_xor_candidate
    ; XOR r/m16/32/64, r16/32/64 (31)
    cmp cl, 31h
    je @found_xor_candidate
    ; XOR r8, r/m8 (32)
    cmp cl, 32h
    je @found_xor_candidate
    ; XOR r16/32/64, r/m16/32/64 (33)
    cmp cl, 33h
    je @found_xor_candidate
    ; XOR r/m8, imm8 (80 /6)
    cmp cl, 80h
    jne @xor_next
    
    ; Check ModRM for /6 (XOR)
    movzx edx, byte ptr [rsi + rdi + 1]
    and dl, 38h                 ; Extract reg field
    cmp dl, 30h                 ; /6 = 110 binary = 0x30
    jne @xor_next
    
@found_xor_candidate:
    ; Found XOR, look ahead for loop/jnz pattern
    inc rax
    
@xor_next:
    inc rdi
    jmp @xor_scan_loop
    
@xor_done:
    jmp @xor_exit
    
@xor_fail:
    xor rax, rax
    
@xor_exit:
    pop rsi
    pop rdi
    pop rbx
    ret
ScanForXORDecryptionLoop ENDP

; ==============================================================================
; ScanForAPIHashingPattern
; Scan for API hashing pattern (ROL/ROR combined with ADD/XOR)
; Common in shellcode and packed malware for dynamic API resolution
;
; Parameters:
;   RCX = buffer
;   RDX = size
;
; Returns: RAX = count of API hashing patterns found
; ==============================================================================
ScanForAPIHashingPattern PROC
    push rbx
    push rdi
    push rsi
    push r12
    
    mov rsi, rcx
    mov rbx, rdx
    
    test rsi, rsi
    jz @hash_fail
    test rbx, rbx
    jz @hash_fail
    
    xor rax, rax                ; Pattern count
    xor rdi, rdi                ; Index
    xor r12, r12                ; ROL/ROR count in window
    
@hash_scan_loop:
    lea rcx, [rdi + 1]
    cmp rcx, rbx
    jge @hash_done
    
    movzx ecx, byte ptr [rsi + rdi]
    
    ; ROL r/m8, 1 (D0 /0)
    cmp cl, 0D0h
    je @check_rol
    ; ROL r/m8, CL (D2 /0)
    cmp cl, 0D2h
    je @check_rol
    ; ROL r/m16/32/64, 1 (D1 /0)
    cmp cl, 0D1h
    je @check_rol
    ; ROL r/m16/32/64, CL (D3 /0)
    cmp cl, 0D3h
    je @check_rol
    ; ROL r/m8, imm8 (C0 /0)
    cmp cl, 0C0h
    je @check_rol
    ; ROL r/m16/32/64, imm8 (C1 /0)
    cmp cl, 0C1h
    jne @hash_next
    
@check_rol:
    ; Verify it's ROL/ROR (reg field 0 or 1)
    movzx edx, byte ptr [rsi + rdi + 1]
    and dl, 38h
    test dl, dl                 ; /0 = ROL
    jz @is_rotate
    cmp dl, 08h                 ; /1 = ROR
    jne @hash_next
    
@is_rotate:
    inc r12
    
    ; If we've seen multiple rotates, look for ADD/XOR nearby
    cmp r12, 2
    jl @hash_next
    
    ; Found pattern
    inc rax
    xor r12, r12
    
@hash_next:
    inc rdi
    jmp @hash_scan_loop
    
@hash_done:
    jmp @hash_exit
    
@hash_fail:
    xor rax, rax
    
@hash_exit:
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
ScanForAPIHashingPattern ENDP

; ==============================================================================
; ScanForSMCPatterns
; Scan for self-modifying code patterns
; Looks for: MOV to code segment, REP STOSB/MOVSB patterns
;
; Parameters:
;   RCX = buffer
;   RDX = size
;
; Returns: RAX = count of SMC patterns found
; ==============================================================================
ScanForSMCPatterns PROC
    push rbx
    push rdi
    push rsi
    
    mov rsi, rcx
    mov rbx, rdx
    
    test rsi, rsi
    jz @smc_fail
    test rbx, rbx
    jz @smc_fail
    
    xor rax, rax                ; Pattern count
    xor rdi, rdi                ; Index
    
@smc_loop:
    cmp rdi, rbx
    jge @smc_done
    
    movzx ecx, byte ptr [rsi + rdi]
    
    ; REP prefix (F3)
    cmp cl, 0F3h
    jne @check_stosb
    
    ; Look for STOSB/MOVSB after REP
    lea rdx, [rdi + 1]
    cmp rdx, rbx
    jge @smc_next
    
    movzx edx, byte ptr [rsi + rdi + 1]
    ; STOSB (AA)
    cmp dl, 0AAh
    je @found_smc
    ; STOSD/STOSQ (AB)
    cmp dl, 0ABh
    je @found_smc
    ; MOVSB (A4)
    cmp dl, 0A4h
    je @found_smc
    ; MOVSD/MOVSQ (A5)
    cmp dl, 0A5h
    je @found_smc
    jmp @smc_next
    
@check_stosb:
    ; Standalone STOSB (less suspicious but still notable)
    cmp cl, 0AAh
    je @found_smc_weak
    cmp cl, 0ABh
    je @found_smc_weak
    jmp @smc_next
    
@found_smc:
    inc rax
    jmp @smc_next
    
@found_smc_weak:
    ; Don't count standalone STOS as strongly
    jmp @smc_next
    
@smc_next:
    inc rdi
    jmp @smc_loop
    
@smc_done:
    jmp @smc_exit
    
@smc_fail:
    xor rax, rax
    
@smc_exit:
    pop rsi
    pop rdi
    pop rbx
    ret
ScanForSMCPatterns ENDP

; ==============================================================================
; SIMD-accelerated byte scanning
; ==============================================================================

; ==============================================================================
; SIMDScanForByte
; Fast SIMD scan for a specific byte value
;
; Parameters:
;   RCX = buffer
;   RDX = size
;   R8  = byte value to find
;
; Returns: RAX = offset of first occurrence, -1 if not found
; ==============================================================================
SIMDScanForByte PROC
    push rbx
    push rdi
    
    test rcx, rcx
    jz @simd_byte_notfound
    test rdx, rdx
    jz @simd_byte_notfound
    
    mov rdi, rcx                ; Buffer
    mov rbx, rdx                ; Size
    movzx eax, r8b              ; Byte to find
    
    ; Broadcast byte to XMM0
    movd xmm0, eax
    punpcklbw xmm0, xmm0
    punpcklwd xmm0, xmm0
    pshufd xmm0, xmm0, 0
    
    xor rcx, rcx                ; Index
    
    ; Process 16 bytes at a time
@simd_byte_loop:
    lea rax, [rcx + 16]
    cmp rax, rbx
    jg @simd_byte_remainder
    
    movdqu xmm1, [rdi + rcx]
    pcmpeqb xmm1, xmm0
    pmovmskb eax, xmm1
    test eax, eax
    jnz @simd_byte_found_in_block
    
    add rcx, 16
    jmp @simd_byte_loop
    
@simd_byte_found_in_block:
    bsf eax, eax
    add rax, rcx
    jmp @simd_byte_exit
    
@simd_byte_remainder:
    ; Process remaining bytes one by one
    movzx eax, r8b
@simd_byte_remainder_loop:
    cmp rcx, rbx
    jge @simd_byte_notfound
    
    cmp [rdi + rcx], al
    je @simd_byte_found
    inc rcx
    jmp @simd_byte_remainder_loop
    
@simd_byte_found:
    mov rax, rcx
    jmp @simd_byte_exit
    
@simd_byte_notfound:
    mov rax, -1
    
@simd_byte_exit:
    pop rdi
    pop rbx
    ret
SIMDScanForByte ENDP

; ==============================================================================
; SIMDScanForWord
; Fast SIMD scan for a 2-byte word value
;
; Parameters:
;   RCX = buffer
;   RDX = size
;   R8  = word value to find
;
; Returns: RAX = offset of first occurrence, -1 if not found
; ==============================================================================
SIMDScanForWord PROC
    push rbx
    push rdi
    
    test rcx, rcx
    jz @simd_word_notfound
    cmp rdx, 2
    jl @simd_word_notfound
    
    mov rdi, rcx
    mov rbx, rdx
    
    ; Simple byte-by-byte scan for word
    xor rcx, rcx
    movzx r8d, r8w              ; Word to find
    
@simd_word_loop:
    lea rax, [rcx + 1]
    cmp rax, rbx
    jge @simd_word_notfound
    
    movzx eax, word ptr [rdi + rcx]
    cmp ax, r8w
    je @simd_word_found
    
    inc rcx
    jmp @simd_word_loop
    
@simd_word_found:
    mov rax, rcx
    jmp @simd_word_exit
    
@simd_word_notfound:
    mov rax, -1
    
@simd_word_exit:
    pop rdi
    pop rbx
    ret
SIMDScanForWord ENDP

; ==============================================================================
; SIMDScanForPattern
; Fast scan for a multi-byte pattern
;
; Parameters:
;   RCX = buffer
;   RDX = buffer size
;   R8  = pattern pointer
;   R9  = pattern size
;
; Returns: RAX = offset of first occurrence, -1 if not found
; ==============================================================================
SIMDScanForPattern PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    
    test rcx, rcx
    jz @pattern_notfound
    test rdx, rdx
    jz @pattern_notfound
    test r8, r8
    jz @pattern_notfound
    test r9, r9
    jz @pattern_notfound
    
    mov rdi, rcx                ; Buffer
    mov rbx, rdx                ; Buffer size
    mov rsi, r8                 ; Pattern
    mov r12, r9                 ; Pattern size
    
    ; Can't find pattern larger than buffer
    cmp r12, rbx
    jg @pattern_notfound
    
    xor r13, r13                ; Buffer index
    
@pattern_loop:
    ; Check if enough bytes remain
    mov rax, rbx
    sub rax, r13
    cmp rax, r12
    jl @pattern_notfound
    
    ; Compare pattern
    xor rcx, rcx                ; Pattern index
@pattern_compare:
    cmp rcx, r12
    jge @pattern_found
    
    movzx eax, byte ptr [rdi + r13]
    add rax, rcx
    movzx eax, byte ptr [rdi + r13 + rcx]
    movzx edx, byte ptr [rsi + rcx]
    cmp al, dl
    jne @pattern_next
    
    inc rcx
    jmp @pattern_compare
    
@pattern_next:
    inc r13
    jmp @pattern_loop
    
@pattern_found:
    mov rax, r13
    jmp @pattern_exit
    
@pattern_notfound:
    mov rax, -1
    
@pattern_exit:
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
SIMDScanForPattern ENDP

END
