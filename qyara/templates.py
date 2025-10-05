import os
import textwrap
import time

def rule_header(name: str, more_imports=None, meta=None):
    imports = ['import "pe"']
    if more_imports:
        for im in more_imports:
            if im not in imports:
                imports.append(im)
    meta = meta or {}
    meta_lines = [f'    author = "qYARA"', f'    generated = "{time.strftime("%Y-%m-%d")}"']
    for k, v in meta.items():
        meta_lines.append(f'    {k} = "{v}"')
    return " \n".join(imports) + f"""

rule {name} {{
  meta:
{os.linesep.join(meta_lines)}
"""

def rule_footer(condition: str) -> str:
    return f"""
  condition:
    {condition}
}}
"""

def _encoded_variants(txt: str, allow_xor=True, allow_b64=True) -> str:
    lines = []
    if allow_xor:
        lines.append(f'$x_{txt} = "{txt}" ascii wide xor')
    if allow_b64:
        lines.append(f'$b_{txt} = "{txt}" base64')
        lines.append(f'$bw_{txt} = "{txt}" base64wide')
    return "\n".join("    " + s for s in lines)

def tpl_process_injection(name="qyara_process_injection", pe_only=True, tighten=False):
    hdr = rule_header(
        name,
        more_imports=['import "pe"'],
        meta={"description": "Process injection scent (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)"}
    )
    strings = """
  strings:
    $s1 = "VirtualAllocEx" ascii wide nocase
    $s2 = "WriteProcessMemory" ascii wide nocase
    $s3 = "CreateRemoteThread" ascii wide nocase
"""
    cond_parts = []
    if pe_only:
        cond_parts.append("uint16(0) == 0x5A4D")  # MZ
        imports = [
            'pe.imports("KERNEL32.dll", "VirtualAllocEx")',
            'pe.imports("KERNEL32.dll", "WriteProcessMemory")',
            'pe.imports("KERNEL32.dll", "CreateRemoteThread")',
        ]
        if tighten:
            cond_parts.append("(all of ($s*) and " + " and ".join(imports) + ")")
        else:
            cond_parts.append("(all of ($s*) or (" + " and ".join(imports) + "))")
        cond_parts.append("filesize < 40MB")
    else:
        if tighten:
            cond_parts.append("all of ($s*)")
        else:
            cond_parts.append("any of ($s*)")

    cond = " and ".join(cond_parts)
    return hdr + strings + rule_footer(cond)

def tpl_process_injection_plus(name="qyara_process_injection_plus", pe_only=True, tighten=False):
    hdr = rule_header(
        name,
        more_imports=['import "pe"'],
        meta={"description": "Process injection (obfuscation-resistant) VirtualAllocEx/WriteProcessMemory/CreateRemoteThread"}
    )
    strings = f"""
  strings:
{_encoded_variants("VirtualAllocEx")}
{_encoded_variants("WriteProcessMemory")}
{_encoded_variants("CreateRemoteThread")}
"""
    cond_parts = []
    if pe_only:
        cond_parts.append("uint16(0) == 0x5A4D")
        imports = [
            'pe.imports("KERNEL32.dll", "VirtualAllocEx")',
            'pe.imports("KERNEL32.dll", "WriteProcessMemory")',
            'pe.imports("KERNEL32.dll", "CreateRemoteThread")',
        ]
        if tighten:
            cond_parts.append("(2 of ($x_* $b_* $bw_*) and " + " and ".join(imports) + ")")
        else:
            cond_parts.append("(2 of ($x_* $b_* $bw_*) or (" + " and ".join(imports) + "))")
        cond_parts.append("filesize < 40MB")
    else:
        cond_parts.append("2 of ($x_* $b_* $bw_*)")
    cond = " and ".join(cond_parts)
    return hdr + strings + rule_footer(cond)

def tpl_crc32(name="qyara_crc32_scent", pe_only=True, count=1, tighten=False):
    hdr = rule_header(name, meta={"description": "CRC32 scent (0xEDB88320) common in API-hash code"})
    strings = """
  strings:
    // 0xEDB88320 little-endian
    $crc32_le = { 20 83 B8 ED }
"""
    conds = []
    if pe_only:
        conds.append("uint16(0) == 0x5A4D")
        conds.append("filesize < 100MB")
    occ = f"#crc32_le >= {count}" if count > 1 else "$crc32_le"
    if tighten and pe_only:
        extra = ' for any i in (pe.number_of_imports): ( for any j in (pe.import_details[i].number_of_functions): true )'
        conds.append(f"({occ}){extra}")
    else:
        conds.append(occ)
    return hdr + strings + rule_footer(" and ".join(conds))

def tpl_murmurhash2(name="qyara_murmurhash2_scent", pe_only=True, count=1):
    hdr = rule_header(name, meta={"description": "MurmurHash2 scent (0x5BD1E995) common in API-hash code"})
    strings = """
  strings:
    // 0x5BD1E995 little-endian
    $murmur_le = { 95 E9 D1 5B }
"""
    conds = []
    if pe_only:
        conds.append("uint16(0) == 0x5A4D")
        conds.append("filesize < 100MB")
    occ = f"#murmur_le >= {count}" if count > 1 else "$murmur_le"
    conds.append(occ)
    return hdr + strings + rule_footer(" and ".join(conds))

def tpl_duqu_style(name="qyara_duqu_style", max_pe_size=100000, max_ole_size=20000000):
    hdr = rule_header(name, meta={"description": "Duqu-style hybrid (PE/MSI), GUID pipes & MSI artifacts"})
    strings = r"""
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
"""
    cond = textwrap.dedent(f"""
    (
      (uint16(0) == 0x5A4D and (any of ($p*) or all of ($msi*)) and filesize < {max_pe_size})
    )
    or
    (
      (uint32(0) == 0xE011CFD0 and (any of ($p*) or any of ($q*) or all of ($msi*)) and filesize < {max_ole_size})
    )
    """).strip()
    return hdr + strings + rule_footer(cond)

TEMPLATES = {
    "process_injection": tpl_process_injection,
    "process_injection_plus": tpl_process_injection_plus,
    "crc32": tpl_crc32,
    "murmurhash2": tpl_murmurhash2,
    "duqu_style": tpl_duqu_style,
}
