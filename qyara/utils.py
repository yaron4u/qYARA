import json
import time
from pathlib import Path

def explain_matches(match_list):
    explained = []
    for m in match_list:
        strings = []
        for sm in m.strings:
            if hasattr(sm, "identifier") and hasattr(sm, "instances"):
                ident = sm.identifier
                for inst in getattr(sm, "instances", []):
                    off = getattr(inst, "offset", None)
                    data = getattr(inst, "matched_data", None)
                    try:
                        if isinstance(data, (bytes, bytearray)):
                            preview_hex = data[:32].hex(" ")
                        else:
                            preview_hex = str(data)[:64]
                    except Exception:
                        preview_hex = "<bin>"
                    strings.append({"id": ident, "offset": off, "preview_hex": preview_hex})
            else:
                try:
                    off, ident, data = sm
                except Exception:
                    strings.append({"id": "<unknown>", "offset": None, "preview_hex": "<unknown>"})
                    continue
                try:
                    preview_hex = data[:32].hex(" ") if isinstance(data, (bytes, bytearray)) else str(data)[:64]
                except Exception:
                    preview_hex = "<bin>"
                strings.append({"id": ident, "offset": off, "preview_hex": preview_hex})

        explained.append({
            "rule": m.rule,
            "tags": list(getattr(m, "tags", [])),
            "meta": dict(getattr(m, "meta", {})),
            "matches": strings,
        })
    return explained

def write_file_bytes(path: Path, b: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(b)

def demo_samples(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    inj = b"Hello\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0qYARA"
    write_file_bytes(outdir / "injection.bin", inj)

    crc32_proto = bytes.fromhex("20 83 B8 ED")
    write_file_bytes(outdir / "crc32.bin", b"X"*64 + crc32_proto + b"Y"*64)

    murmur_proto = bytes.fromhex("95 E9 D1 5B")
    write_file_bytes(outdir / "murmur.bin", b"Z"*64 + murmur_proto + b"W"*64)

    duqu_str = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}".encode("utf-16le")
    msi_q = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'".encode("utf-16le")
    write_file_bytes(outdir / "duqu_like.ole", duqu_str + b"\x00\x00" + msi_q)

    print(f"[+] Wrote demo samples to: {outdir.resolve()}")

def selftest_proc():
    from .scanner import compile_rules_from_text
    marker = b"QYARA_TEST_MARKER_7e0b7f1c"
    global _QYARA_HOLD
    _QYARA_HOLD = marker * 4

    rule_text = f'''
rule qyara_selftest_memory {{
  meta: author="qYARA" generated="{time.strftime("%Y-%m-%d")}"
  strings:
    $m = "{marker.decode()}" ascii
  condition:
    $m
}}
'''
    rules = compile_rules_from_text(rule_text)
    res = rules.match(pid=os.getpid(), timeout=10)
    ok = any(m.rule == "qyara_selftest_memory" for m in res)
    print(f"[+] Self-test PID={os.getpid()} {'OK' if ok else 'FAILED'}")
    if res:
        print(json.dumps(explain_matches(res), indent=2))
    return 0 if ok else 1
