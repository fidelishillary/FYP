/*
 * Example rules for the signature baseline (FR-09).
 *
 * These are a small starting set so the pipeline runs end to end. For the
 * dissertation, replace or extend them with an established public rule set
 * (for example Neo23x0/signature-base or Yara-Rules/rules), record its version
 * and date, and make sure it was published *before* your test samples so the
 * comparison is fair. Check each rule set's licence before committing it here.
 */
import "pe"

rule Packer_UPX_Sections
{
    meta:
        description = "UPX-packed executable (section names)"
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0 .. pe.number_of_sections - 1) : (pe.sections[i].name == "UPX0")
}

rule Suspicious_Process_Injection_Imports
{
    meta:
        description = "Imports the classic remote-thread injection triad"
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule Ransom_Note_Strings
{
    meta:
        description = "Common ransom-note phrases"
    strings:
        $a = "your files have been encrypted" nocase ascii wide
        $b = "bitcoin" nocase ascii wide
        $c = "decrypt" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $a and ($b or $c)
}
