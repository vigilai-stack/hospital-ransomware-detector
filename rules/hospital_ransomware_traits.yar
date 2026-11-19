/*
  Lab rules for ransomware traits.

  These rules match strings and file-name extensions. They do not identify a
  malware family, and they were not built from live malware samples.
  A match means "this file has a trait we look for." A person still has to
  decide what happened.
*/

rule Ransom_Note_Traits
{
    meta:
        author = "VigilAI Solutions"
        description = "Several ransom-note phrases in one file. Lab trait only, not family identification."
        severity = "high"

    strings:
        $a1 = "your files have been encrypted" nocase ascii
        $a2 = "do not rename" nocase ascii
        $a3 = "bitcoin" nocase ascii
        $a4 = "decryption key" nocase ascii

    condition:
        not filename endswith ".yar" and
        filesize < 500KB and
        3 of ($a*)
}

rule Suspicious_Extension_Trait
{
    meta:
        author = "VigilAI Solutions"
        description = "Extension that has shown up in public ransomware reports. A naming trait, not family identification."
        severity = "medium"

    condition:
        extension matches /\.(locked|encrypted|crypt|crypto|ryk|wncry)$/i
}
