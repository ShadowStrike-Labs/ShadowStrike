/*
    ShadowStrike Phantom - baseline technique rules
    ---------------------------------------------------------------------------
    Clean-room rules written for this project. No rule here is derived from
    another rule set, which matters because this product is AGPL-3.0 and much of
    the public YARA corpus carries non-commercial or share-alike terms that
    would restrict how it can be distributed.

    Scope note. These describe technique, not family. Family signatures date
    quickly and a from-scratch set of them would be worse than the behavioural
    and emulation engines this product already has. Technique rules earn their
    place by giving the cheap tier something to say before the expensive tiers
    are reached, and by tagging a sample so the deferred deep scan knows what to
    look for.

    Every rule is deliberately narrow. A rule that fires on everything is worse
    than no rule: it trains whoever reads the alerts to stop reading them.
*/

import "pe"

rule SS_Suspicious_PE_No_Sections_Named
{
    meta:
        author      = "ShadowStrike Labs"
        description = "PE whose section names are entirely non-standard, a common packer artefact"
        technique   = "T1027.002"
        severity    = "low"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections > 0 and
        pe.number_of_sections < 12 and
        for all i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name != ".text" and
            pe.sections[i].name != ".data" and
            pe.sections[i].name != ".rdata" and
            pe.sections[i].name != ".rsrc" and
            pe.sections[i].name != ".reloc" and
            pe.sections[i].name != ".pdata" and
            pe.sections[i].name != ".idata" and
            pe.sections[i].name != ".edata" and
            pe.sections[i].name != ".tls" and
            pe.sections[i].name != ".bss" and
            pe.sections[i].name != ".CRT" and
            pe.sections[i].name != ".didat"
        )
}

rule SS_PE_Writable_Executable_Section
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Section mapped both writable and executable, which legitimate compilers do not emit"
        technique   = "T1027"
        severity    = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections > 0 and
        for any i in (0 .. pe.number_of_sections - 1) : (
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) and
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) and
            pe.sections[i].raw_data_size > 0
        )
}

rule SS_PE_Entry_Point_Outside_Code_Section
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Entry point does not land in an executable section, typical of a hijacked or appended loader"
        technique   = "T1055.012"
        severity    = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.entry_point > 0 and
        pe.number_of_sections > 0 and
        not for any i in (0 .. pe.number_of_sections - 1) : (
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) and
            pe.entry_point >= pe.sections[i].raw_data_offset and
            pe.entry_point <  pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
        )
}

rule SS_Dynamic_API_Resolution_Only
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Imports resolve nothing but the loader pair used to fetch everything else at runtime"
        technique   = "T1027.007"
        severity    = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "LoadLibraryA") and
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.number_of_imported_functions < 12
}

rule SS_Process_Injection_Import_Set
{
    meta:
        author      = "ShadowStrike Labs"
        description = "The complete remote-write-and-execute import set in one binary"
        technique   = "T1055.002"
        severity    = "high"

    condition:
        uint16(0) == 0x5A4D and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("ntdll.dll", "NtAllocateVirtualMemory")
        ) and
        (
            pe.imports("kernel32.dll", "WriteProcessMemory") or
            pe.imports("ntdll.dll", "NtWriteVirtualMemory")
        ) and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx") or
            pe.imports("ntdll.dll", "RtlCreateUserThread") or
            pe.imports("kernel32.dll", "QueueUserAPC")
        )
}

rule SS_Direct_Syscall_Stub
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Hand-rolled syscall stub, the shape used to bypass user-mode hooks"
        technique   = "T1106"
        severity    = "high"

    strings:
        /*
            mov r10, rcx      4C 8B D1
            mov eax, imm32    B8 ?? ?? ?? ??
            syscall           0F 05
            ret               C3
        */
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

    condition:
        uint16(0) == 0x5A4D and $stub
}

rule SS_Shadow_Copy_Destruction
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Volume shadow copy deletion, the step ransomware takes before it is noticed"
        technique   = "T1490"
        severity    = "critical"

    strings:
        $vssadmin_a = "vssadmin"           ascii nocase
        $vssadmin_w = "vssadmin"           wide  nocase
        $delete_a   = "delete shadows"     ascii nocase
        $delete_w   = "delete shadows"     wide  nocase
        $wmic_a     = "shadowcopy delete"  ascii nocase
        $wmic_w     = "shadowcopy delete"  wide  nocase
        $bcdedit_a  = "recoveryenabled no" ascii nocase
        $bcdedit_w  = "recoveryenabled no" wide  nocase
        $wbadmin_a  = "wbadmin delete catalog" ascii nocase
        $wbadmin_w  = "wbadmin delete catalog" wide  nocase

    condition:
        (
            (($vssadmin_a or $vssadmin_w) and ($delete_a or $delete_w)) or
            $wmic_a or $wmic_w or
            $bcdedit_a or $bcdedit_w or
            $wbadmin_a or $wbadmin_w
        )
}

rule SS_AMSI_Bypass_Attempt
{
    meta:
        author      = "ShadowStrike Labs"
        description = "References the AMSI internals that bypasses patch, rather than the documented API"
        technique   = "T1562.001"
        severity    = "high"

    strings:
        $ctx_a  = "amsiInitFailed"        ascii nocase
        $ctx_w  = "amsiInitFailed"        wide  nocase
        $ctx2_a = "AmsiScanBuffer"        ascii
        $ctx2_w = "AmsiScanBuffer"        wide
        $ctx3_a = "AmsiUtils"             ascii nocase
        $ctx3_w = "AmsiUtils"             wide  nocase
        $patch  = "VirtualProtect"        ascii

    condition:
        ($ctx_a or $ctx_w or $ctx3_a or $ctx3_w) or
        (($ctx2_a or $ctx2_w) and $patch)
}

rule SS_PowerShell_Encoded_Command
{
    meta:
        author      = "ShadowStrike Labs"
        description = "PowerShell invoked with a base64 payload and visibility suppressed"
        technique   = "T1059.001"
        severity    = "high"

    strings:
        $ps_a  = "powershell"   ascii nocase
        $ps_w  = "powershell"   wide  nocase
        $enc1  = "-EncodedCommand" ascii nocase
        $enc1w = "-EncodedCommand" wide  nocase
        $enc2  = " -enc "       ascii nocase
        $enc2w = " -enc "       wide  nocase
        $hide  = "-WindowStyle Hidden" ascii nocase
        $hidew = "-WindowStyle Hidden" wide  nocase
        $nop   = "-NoProfile"   ascii nocase
        $nopw  = "-NoProfile"   wide  nocase

    condition:
        ($ps_a or $ps_w) and
        (
            ($enc1 or $enc1w or $enc2 or $enc2w) or
            (($hide or $hidew) and ($nop or $nopw))
        )
}

rule SS_Defender_Tamper_Attempt
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Disables the platform's own protection, a precursor step not an end in itself"
        technique   = "T1562.001"
        severity    = "high"

    strings:
        $rtp_a  = "DisableRealtimeMonitoring" ascii nocase
        $rtp_w  = "DisableRealtimeMonitoring" wide  nocase
        $av_a   = "DisableAntiSpyware"        ascii nocase
        $av_w   = "DisableAntiSpyware"        wide  nocase
        $excl_a = "Add-MpPreference"          ascii nocase
        $excl_w = "Add-MpPreference"          wide  nocase
        $svc_a  = "sc stop WinDefend"         ascii nocase
        $svc_w  = "sc stop WinDefend"         wide  nocase

    condition:
        any of them
}

rule SS_Credential_Store_Direct_Access
{
    meta:
        author      = "ShadowStrike Labs"
        description = "Reads the credential stores directly rather than through the platform API"
        technique   = "T1003.002"
        severity    = "critical"

    strings:
        $sam_a   = "\\Windows\\System32\\config\\SAM" ascii nocase
        $sam_w   = "\\Windows\\System32\\config\\SAM" wide  nocase
        $sec_a   = "\\Windows\\System32\\config\\SECURITY" ascii nocase
        $sec_w   = "\\Windows\\System32\\config\\SECURITY" wide  nocase
        $lsass_a = "lsass.exe"   ascii nocase
        $lsass_w = "lsass.exe"   wide  nocase
        $dump_a  = "MiniDumpWriteDump" ascii
        $ntds_a  = "ntds.dit"    ascii nocase
        $ntds_w  = "ntds.dit"    wide  nocase

    condition:
        $sam_a or $sam_w or $sec_a or $sec_w or $ntds_a or $ntds_w or
        (($lsass_a or $lsass_w) and $dump_a)
}
