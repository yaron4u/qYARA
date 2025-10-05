import subprocess
import shutil
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import yara
except Exception as e:
    print("[!] Missing dependency: yara-python (pip install yara-python)")
    raise

def compile_rules_from_text(rule_text: str):
    try:
        return yara.compile(source=rule_text)
    except yara.Error as e:
        print("[!] YARA compile error:", e)
        raise

def compile_rules_from_file(path: Path):
    try:
        return yara.compile(filepath=str(path))
    except yara.Error as e:
        print("[!] YARA compile error:", e)
        raise

def _load_modules_data(path: str | None):
    if not path:
        return None
    try:
        b = Path(path).read_bytes()
        return {"cuckoo": b}
    except Exception as e:
        print(f"[!] Failed to read cuckoo report: {e}")
        return None

def _match_one_file(rules, p: Path, fast=False, modules_data=None):
    try:
        res = rules.match(filepath=str(p), fast=fast, modules_data=modules_data)
        return p, res
    except yara.Error as e:
        return p, []

def scan_files(rules_path: Path, target: Path, recursive=False, fast=False, workers=8, show_progress=False, modules_data=None, deep=False):
    rules = compile_rules_from_file(rules_path)
    temp_dir = None
    scan_root = target
    if deep:
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix="qyara_yextend_"))
            cmd = ["yextend", "-r", str(target), "-o", str(temp_dir)]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode != 0:
                print("[!] yextend failed; falling back to normal scan")
            else:
                scan_root = temp_dir
        except FileNotFoundError:
            print("[!] yextend not found on PATH; falling back to normal scan")
        except Exception as e:
            print(f"[!] yextend error: {e}; falling back to normal scan")
    try:
        if scan_root.is_file():
            paths = [scan_root]
        else:
            globber = scan_root.rglob("*") if recursive or deep else scan_root.glob("*")
            paths = [p for p in globber if p.is_file()]
        out = []
        with ThreadPoolExecutor(max_workers=workers) as tp:
            futs = [tp.submit(_match_one_file, rules, p, fast, modules_data) for p in paths]
            for i, fut in enumerate(as_completed(futs), 1):
                p, matches = fut.result()
                if matches:
                    out.append((p, matches))
                if show_progress and i % 250 == 0:
                    print(f"[.] Scanned {i} files...")
        return out
    finally:
        if temp_dir is not None:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

def scan_process(rules_path: Path, pid: int, timeout=30, modules_data=None):
    rules = compile_rules_from_file(rules_path)
    try:
        res = rules.match(pid=pid, timeout=timeout, modules_data=modules_data)
        return res
    except yara.TimeoutError:
        print("[!] YARA scan timed out")
        return []
    except yara.Error as e:
        print("[!] YARA error on PID scan:", e)
        return []
