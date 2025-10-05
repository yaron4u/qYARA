import argparse
import json
import sys
from pathlib import Path

from .templates import TEMPLATES
from .scanner import scan_files, scan_process, _load_modules_data
from .utils import explain_matches, demo_samples, selftest_proc

BANNER = "qYARA • Quick YARA helper"

def main():
    ap = argparse.ArgumentParser(prog="qYARA", description=BANNER)
    sub = ap.add_subparsers(dest="cmd", required=True)

    # gen
    ap_gen = sub.add_parser("gen", help="Generate a YARA rule from a template")
    ap_gen.add_argument("--template", choices=TEMPLATES.keys(), required=True)
    ap_gen.add_argument("--name", default=None, help="Rule name (optional)")
    ap_gen.add_argument("--out", required=True, help="Write .yar file here")
    ap_gen.add_argument("--pe-only", action="store_true", help="Restrict to PE files (where supported)")
    ap_gen.add_argument("--tighten", action="store_true", help="Stricter conditions (reduce false positives)")
    ap_gen.add_argument("--count", type=int, default=1, help="Min occurrences for constants (crc32/murmur)")

    # scan-files
    ap_sf = sub.add_parser("scan-files", help="Scan a file/folder with rules")
    ap_sf.add_argument("--rules", required=True)
    ap_sf.add_argument("--path", required=True)
    ap_sf.add_argument("--recursive", action="store_true")
    ap_sf.add_argument("--fast", action="store_true", help="YARA fast mode")
    ap_sf.add_argument("--json", dest="json_out", help="Write results to JSON file")
    ap_sf.add_argument("--cuckoo-report", help="Cuckoo JSON to feed cuckoo module")
    ap_sf.add_argument("--deep", action="store_true", help="Unpack archives via yextend before scanning")

    # scan-proc
    ap_sp = sub.add_parser("scan-proc", help="Scan a process memory by PID")
    ap_sp.add_argument("--rules", required=True)
    ap_sp.add_argument("--pid", type=int, required=True)
    ap_sp.add_argument("--json", dest="json_out", help="Write results to JSON file")
    ap_sp.add_argument("--cuckoo-report", help="Cuckoo JSON to feed cuckoo module")

    # demo samples
    ap_demo = sub.add_parser("demo-samples", help="Write tiny files that trigger templates")
    ap_demo.add_argument("outdir")

    # selftest
    sub.add_parser("selftest-proc", help="Prove PID scanning works by matching a marker in this process")

    # test harness
    ap_test = sub.add_parser("test", help="Run TP/FP tests")
    ap_test.add_argument("--rules", required=True)
    ap_test.add_argument("--positives", required=True)
    ap_test.add_argument("--negatives", required=True)
    ap_test.add_argument("--json", dest="json_out")

    args = ap.parse_args()

    if args.cmd == "gen":
        fn = TEMPLATES[args.template]
        name = args.name or f"qyara_{args.template}"
        if args.template == "process_injection":
            rule = fn(name=name, pe_only=args.pe_only, tighten=args.tighten)
        elif args.template == "process_injection_plus":
            rule = fn(name=name, pe_only=args.pe_only, tighten=args.tighten)
        elif args.template == "crc32":
            rule = fn(name=name, pe_only=args.pe_only, count=args.count, tighten=args.tighten)
        elif args.template == "murmurhash2":
            rule = fn(name=name, pe_only=args.pe_only, count=args.count)
        elif args.template == "duqu_style":
            rule = fn(name=name)
        else:
            raise SystemExit("Unknown template")
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(rule, encoding="utf-8")
        print(f"[+] Wrote rule {name} -> {str(outp)}")
        print("-----")
        print(rule)

    elif args.cmd == "scan-files":
        mods = _load_modules_data(getattr(args, "cuckoo_report", None))
        res = scan_files(Path(args.rules), Path(args.path), recursive=args.recursive, fast=args.fast, show_progress=True, modules_data=mods, deep=getattr(args, "deep", False))
        human = []
        for p, matches in res:
            em = explain_matches(matches)
            human.append({"path": str(p), "matches": em})
        print(json.dumps(human, indent=2))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(human, indent=2), encoding="utf-8")
            print(f"[+] Wrote JSON -> {args.json_out}")

    elif args.cmd == "scan-proc":
        mods = _load_modules_data(getattr(args, "cuckoo_report", None))
        matches = scan_process(Path(args.rules), args.pid, modules_data=mods)
        em = explain_matches(matches)
        print(json.dumps(em, indent=2))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(em, indent=2), encoding="utf-8")
            print(f"[+] Wrote JSON -> {args.json_out}")

    elif args.cmd == "demo-samples":
        demo_samples(Path(args.outdir))

    elif args.cmd == "selftest-proc":
        sys.exit(selftest_proc())

    elif args.cmd == "test":
        pos = scan_files(Path(args.rules), Path(args.positives), recursive=True, fast=True, show_progress=True)
        neg = scan_files(Path(args.rules), Path(args.negatives), recursive=True, fast=True, show_progress=True)
        tp = sum(1 for _, m in pos if m)
        fn = sum(1 for _, m in pos if not m)
        fp = sum(1 for _, m in neg if m)
        tn = sum(1 for _, m in neg if not m)
        report = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
        print(json.dumps(report, indent=2))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"[+] Wrote JSON -> {args.json_out}")
