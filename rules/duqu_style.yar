import "pe"

rule qyara_duqu_style {
  meta:
    author = "qYARA"
    generated = "2025-10-05"
    description = "Duqu-style hybrid (PE/MSI), GUID pipes & MSI artifacts"

  strings:
    // Named-pipe / GUID strings (wide)
    $p1 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
    $p2 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
    $p3 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide

    // MSI-related artifacts
    $msi1 = "MSI.dll" ascii
    $msi2 = "msi.dll" ascii
    $msi3 = "StartAction" ascii

    // Query patterns seen in MSI database usage
    $q1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
    $q2 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide

  condition:
    (
  (uint16(0) == 0x5A4D and (any of ($p*) or all of ($msi*)) and filesize < 100000)
)
or
(
  (uint32(0) == 0xE011CFD0 and (any of ($p*) or any of ($q*) or all of ($msi*)) and filesize < 20000000)
)
}
