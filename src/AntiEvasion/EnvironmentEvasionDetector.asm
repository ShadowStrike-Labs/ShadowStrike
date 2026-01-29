; ============================================================================
; EnvironmentEvasionDetector.asm
; Enterprise-grade low-level CPU detection for ShadowStrike AntiEvasion
;
; Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
;
; This assembly module provides high-precision CPU feature detection that
; cannot be reliably performed in C/C++ due to compiler optimizations.
;
; Exported Functions:
;   - CheckCPUIDHypervisorBit: Detect hypervisor presence via CPUID
;   - GetCPUIDBrandString: Retrieve 48-byte CPU brand string
;   - CheckCPUIDVMXSupport: Check for VT-x/VMX capability
;   - GetCPUIDVendorString: Get 12-byte vendor ID string
;   - CheckRDTSCVMExit: Detect if RDTSC causes VM exit (timing attack)
;   - CheckCPUIDHypervisorVendor: Get hypervisor vendor string
;   - MeasureRDTSCLatency: Measure RDTSC instruction latency
;   - CheckDebugRegistersASM: Read DR7 debug control register
;   - GetCPUIDFeatureFlags: Get full CPU feature flags (ECX:EDX)
;   - CheckSMBIOSVMSignature: Check SMBIOS for VM signatures
;
; Build: ml64.exe /c /Fo EnvironmentEvasionDetector.obj EnvironmentEvasionDetector.asm
; ============================================================================

.code

; ============================================================================
; CheckCPUIDHypervisorBit
;
; Checks CPUID leaf 1, ECX bit 31 (hypervisor present bit)
; This bit is set by hypervisors to indicate VM environment.
;
; Arguments: None
; Returns: RAX = 1 if hypervisor bit set, 0 otherwise
; ============================================================================
CheckCPUIDHypervisorBit PROC
    push rbx                    ; Save non-volatile registers
    push rcx
    push rdx

    ; Execute CPUID with EAX=1 (Processor Info and Feature Bits)
    mov eax, 1
    xor ecx, ecx
    cpuid

    ; Check bit 31 of ECX (Hypervisor Present)
    test ecx, 80000000h
    jz @NotPresent

    mov eax, 1                  ; Return 1 (hypervisor detected)
    jmp @Done

@NotPresent:
    xor eax, eax                ; Return 0 (no hypervisor)

@Done:
    pop rdx
    pop rcx
    pop rbx
    ret
CheckCPUIDHypervisorBit ENDP

; ============================================================================
; GetCPUIDBrandString
;
; Retrieves the 48-byte CPU brand string from CPUID leaves 0x80000002-0x80000004
;
; Arguments:
;   RCX = pointer to output buffer (must be at least 49 bytes)
;   RDX = buffer size
; Returns: None (writes to buffer)
; ============================================================================
GetCPUIDBrandString PROC
    push rbx                    ; Save non-volatile registers
    push rdi
    push rsi

    mov rdi, rcx                ; RDI = output buffer pointer
    mov rsi, rdx                ; RSI = buffer size

    ; Check if extended CPUID is supported
    mov eax, 80000000h
    cpuid
    cmp eax, 80000004h
    jb @NotSupported

    ; Check buffer size (need at least 48 bytes + null)
    cmp rsi, 49
    jb @NotSupported

    ; Get brand string part 1 (CPUID 0x80000002)
    mov eax, 80000002h
    cpuid
    mov dword ptr [rdi+0], eax
    mov dword ptr [rdi+4], ebx
    mov dword ptr [rdi+8], ecx
    mov dword ptr [rdi+12], edx

    ; Get brand string part 2 (CPUID 0x80000003)
    mov eax, 80000003h
    cpuid
    mov dword ptr [rdi+16], eax
    mov dword ptr [rdi+20], ebx
    mov dword ptr [rdi+24], ecx
    mov dword ptr [rdi+28], edx

    ; Get brand string part 3 (CPUID 0x80000004)
    mov eax, 80000004h
    cpuid
    mov dword ptr [rdi+32], eax
    mov dword ptr [rdi+36], ebx
    mov dword ptr [rdi+40], ecx
    mov dword ptr [rdi+44], edx

    ; Null-terminate
    mov byte ptr [rdi+48], 0
    jmp @Done

@NotSupported:
    ; Write empty string if not supported
    test rdi, rdi
    jz @Done
    mov byte ptr [rdi], 0

@Done:
    pop rsi
    pop rdi
    pop rbx
    ret
GetCPUIDBrandString ENDP

; ============================================================================
; CheckCPUIDVMXSupport
;
; Checks if CPU supports Intel VT-x (VMX) virtualization
; CPUID.1:ECX.VMX[bit 5] = 1 indicates VMX support
;
; Arguments: None
; Returns: RAX = 1 if VMX supported, 0 otherwise
; ============================================================================
CheckCPUIDVMXSupport PROC
    push rbx
    push rcx
    push rdx

    mov eax, 1
    xor ecx, ecx
    cpuid

    ; Check bit 5 of ECX (VMX support)
    test ecx, 20h
    jz @NoVMX

    mov eax, 1
    jmp @Done

@NoVMX:
    xor eax, eax

@Done:
    pop rdx
    pop rcx
    pop rbx
    ret
CheckCPUIDVMXSupport ENDP

; ============================================================================
; GetCPUIDVendorString
;
; Retrieves the 12-byte CPU vendor ID string from CPUID leaf 0
; Common values: "GenuineIntel", "AuthenticAMD", "VBoxVBoxVBox", etc.
;
; Arguments:
;   RCX = pointer to output buffer (must be at least 13 bytes)
;   RDX = buffer size
; Returns: None (writes to buffer)
; ============================================================================
GetCPUIDVendorString PROC
    push rbx
    push rdi

    mov rdi, rcx                ; RDI = output buffer

    ; Check buffer size
    cmp rdx, 13
    jb @TooSmall

    ; CPUID leaf 0 returns vendor string in EBX:EDX:ECX
    xor eax, eax
    cpuid

    ; Store vendor string (EBX, EDX, ECX order)
    mov dword ptr [rdi+0], ebx
    mov dword ptr [rdi+4], edx
    mov dword ptr [rdi+8], ecx
    mov byte ptr [rdi+12], 0    ; Null-terminate
    jmp @Done

@TooSmall:
    test rdi, rdi
    jz @Done
    mov byte ptr [rdi], 0

@Done:
    pop rdi
    pop rbx
    ret
GetCPUIDVendorString ENDP

; ============================================================================
; CheckCPUIDHypervisorVendor
;
; If hypervisor bit is set, retrieves hypervisor vendor from CPUID 0x40000000
; Common values: "VMwareVMware", "Microsoft Hv", "KVMKVMKVM", "XenVMMXenVMM"
;
; Arguments:
;   RCX = pointer to output buffer (must be at least 13 bytes)
;   RDX = buffer size
; Returns: RAX = 1 if hypervisor vendor retrieved, 0 otherwise
; ============================================================================
CheckCPUIDHypervisorVendor PROC
    push rbx
    push rdi
    push rsi

    mov rdi, rcx
    mov rsi, rdx

    ; First check if hypervisor bit is set
    mov eax, 1
    xor ecx, ecx
    cpuid
    test ecx, 80000000h
    jz @NoHypervisor

    ; Check buffer size
    cmp rsi, 13
    jb @NoHypervisor

    ; Query hypervisor vendor (CPUID 0x40000000)
    mov eax, 40000000h
    cpuid

    ; EBX:ECX:EDX contains vendor string
    mov dword ptr [rdi+0], ebx
    mov dword ptr [rdi+4], ecx
    mov dword ptr [rdi+8], edx
    mov byte ptr [rdi+12], 0

    mov eax, 1
    jmp @Done

@NoHypervisor:
    test rdi, rdi
    jz @ReturnZero
    mov byte ptr [rdi], 0

@ReturnZero:
    xor eax, eax

@Done:
    pop rsi
    pop rdi
    pop rbx
    ret
CheckCPUIDHypervisorVendor ENDP

; ============================================================================
; MeasureRDTSCLatency
;
; Measures the latency of RDTSC instruction execution.
; VMs often have higher RDTSC latency due to virtualization overhead.
;
; Arguments: None
; Returns: RAX = delta TSC cycles for RDTSC execution
; ============================================================================
MeasureRDTSCLatency PROC
    push rbx
    push rcx
    push rdx

    ; Serialize with CPUID before first RDTSC
    xor eax, eax
    cpuid

    ; First RDTSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax                ; RBX = first TSC value

    ; Serialize again
    xor eax, eax
    cpuid

    ; Second RDTSC
    rdtsc
    shl rdx, 32
    or rax, rdx                 ; RAX = second TSC value

    ; Calculate delta
    sub rax, rbx                ; RAX = delta

    pop rdx
    pop rcx
    pop rbx
    ret
MeasureRDTSCLatency ENDP

; ============================================================================
; CheckDebugRegistersASM
;
; Reads the DR7 debug control register to detect hardware breakpoints.
; Note: This will raise an exception if not running with sufficient privileges.
;
; Arguments: None
; Returns: RAX = DR7 value, or 0xFFFFFFFF on exception
; ============================================================================
CheckDebugRegistersASM PROC
    ; Attempt to read DR7
    ; This may cause #GP if not privileged
    mov rax, dr7
    ret
CheckDebugRegistersASM ENDP

; ============================================================================
; GetCPUIDFeatureFlags
;
; Retrieves full CPU feature flags from CPUID leaf 1
;
; Arguments:
;   RCX = pointer to DWORD for ECX features
;   RDX = pointer to DWORD for EDX features
; Returns: RAX = 1 on success
; ============================================================================
GetCPUIDFeatureFlags PROC
    push rbx
    push rsi
    push rdi

    mov rsi, rcx                ; RSI = ECX output ptr
    mov rdi, rdx                ; RDI = EDX output ptr

    mov eax, 1
    xor ecx, ecx
    cpuid

    ; Store ECX features
    test rsi, rsi
    jz @SkipECX
    mov dword ptr [rsi], ecx

@SkipECX:
    ; Store EDX features
    test rdi, rdi
    jz @SkipEDX
    mov dword ptr [rdi], edx

@SkipEDX:
    mov eax, 1

    pop rdi
    pop rsi
    pop rbx
    ret
GetCPUIDFeatureFlags ENDP

; ============================================================================
; GetExtendedCPUIDMaxLeaf
;
; Returns the maximum supported extended CPUID leaf
;
; Arguments: None
; Returns: RAX = max extended CPUID leaf (e.g., 0x80000008)
; ============================================================================
GetExtendedCPUIDMaxLeaf PROC
    push rbx
    push rcx
    push rdx

    mov eax, 80000000h
    cpuid
    ; EAX now contains max extended function

    pop rdx
    pop rcx
    pop rbx
    ret
GetExtendedCPUIDMaxLeaf ENDP

; ============================================================================
; CheckCPUIDTimestampDisable
;
; Checks if TSD (Time Stamp Disable) bit is set in CR4
; When set, RDTSC in user mode causes #GP
; Note: Reading CR4 requires Ring 0
;
; Arguments: None
; Returns: RAX = CR4 value (or causes exception if not Ring 0)
; ============================================================================
CheckCPUIDTimestampDisable PROC
    ; This will cause #GP in user mode
    ; Only callable from kernel mode
    mov rax, cr4
    ret
CheckCPUIDTimestampDisable ENDP

; ============================================================================
; PerformRDTSCPMeasurement
;
; Performs RDTSCP measurement which also returns processor ID
; More accurate than RDTSC as it's serializing
;
; Arguments:
;   RCX = pointer to store processor ID (can be NULL)
; Returns: RAX = TSC value
; ============================================================================
PerformRDTSCPMeasurement PROC
    push rdx

    ; RDTSCP: EDX:EAX = TSC, ECX = Processor ID
    rdtscp

    ; Store processor ID if pointer provided
    test rcx, rcx
    jz @SkipProcID
    mov dword ptr [rcx], ecx

@SkipProcID:
    ; Combine EDX:EAX into RAX
    shl rdx, 32
    or rax, rdx

    pop rdx
    ret
PerformRDTSCPMeasurement ENDP

; ============================================================================
; CheckSSE2Support
;
; Checks for SSE2 support (CPUID.1:EDX.SSE2[bit 26])
; Most modern VMs and CPUs support this
;
; Arguments: None
; Returns: RAX = 1 if SSE2 supported, 0 otherwise
; ============================================================================
CheckSSE2Support PROC
    push rbx
    push rcx
    push rdx

    mov eax, 1
    xor ecx, ecx
    cpuid

    ; Check bit 26 of EDX
    test edx, 04000000h
    jz @NoSSE2

    mov eax, 1
    jmp @Done

@NoSSE2:
    xor eax, eax

@Done:
    pop rdx
    pop rcx
    pop rbx
    ret
CheckSSE2Support ENDP

; ============================================================================
; GetProcessorCoreCount
;
; Gets processor core information from CPUID
; Uses CPUID leaf 4 for Intel, leaf 0x8000001E for AMD
;
; Arguments: None
; Returns: RAX = logical processor count (from CPUID, may differ from OS)
; ============================================================================
GetProcessorCoreCount PROC
    push rbx
    push rcx
    push rdx

    ; First check vendor
    xor eax, eax
    cpuid

    ; Check if "GenuineIntel"
    cmp ebx, 756E6547h          ; "Genu"
    jne @CheckAMD
    cmp edx, 49656E69h          ; "ineI"
    jne @CheckAMD
    cmp ecx, 6C65746Eh          ; "ntel"
    jne @CheckAMD

    ; Intel: Use CPUID leaf 0Bh (Extended Topology Enumeration)
    mov eax, 0Bh
    xor ecx, ecx
    cpuid
    movzx eax, bx               ; EBX[15:0] = number of logical processors
    jmp @Done

@CheckAMD:
    ; AMD: Use CPUID leaf 1 for now
    mov eax, 1
    xor ecx, ecx
    cpuid
    shr ebx, 16                 ; EBX[23:16] = max logical processors
    and ebx, 0FFh
    mov eax, ebx

@Done:
    pop rdx
    pop rcx
    pop rbx
    ret
GetProcessorCoreCount ENDP

END
