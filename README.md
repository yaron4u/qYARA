# qYARA

YARA rule generator and scanner for malware hunters.

## Install

```bash
pip install -r requirements.txt
# optional: install yextend for deep archive scanning
```

## Generate Rules

```bash
# Basic process injection rule
python qyara.py gen --template process_injection --out rules/injection.yar

# Obfuscation-resistant version (XOR/Base64 variants)
python qyara.py gen --template process_injection_plus --out rules/injection_plus.yar --pe-only --tighten

# CRC32 hash detection
python qyara.py gen --template crc32 --out rules/crc32.yar --count 2

# MurmurHash2 detection
python qyara.py gen --template murmurhash2 --out rules/murmur.yar

# Duqu-style hybrid (PE/MSI)
python qyara.py gen --template duqu_style --out rules/duqu.yar
```

## Scan Files

```bash
# Scan directory
python qyara.py scan-files --rules rules/injection.yar --path ./samples --recursive

# Deep scan (unpacks archives first)
python qyara.py scan-files --rules rules/injection.yar --path ./samples --deep

# With Cuckoo behavioral analysis
python qyara.py scan-files --rules rules/behavior.yar --path ./samples --cuckoo-report cuckoo_report.json

# Export to JSON
python qyara.py scan-files --rules rules/injection.yar --path ./samples --json results.json
```

## Scan Process Memory

```bash
# Scan running process by PID
python qyara.py scan-proc --rules rules/injection.yar --pid 1234

# With Cuckoo integration
python qyara.py scan-proc --rules rules/behavior.yar --pid 1234 --cuckoo-report cuckoo_report.json
```

## Test Rule Quality

```bash
# Measure TP/FP rates
python qyara.py test --rules rules/injection.yar --positives ./malware --negatives ./goodware --json report.json
```

## Create Test Samples

```bash
# Generate demo files that trigger templates
python qyara.py demo-samples ./test_samples
```

## Verify Setup

```bash
# Test that PID scanning works
python qyara.py selftest-proc
```

## Templates

- `process_injection`: Basic VirtualAllocEx/WriteProcessMemory/CreateRemoteThread detection
- `process_injection_plus`: Obfuscation-resistant version with XOR/Base64 variants
- `crc32`: Detects CRC32 polynomial (0xEDB88320)
- `murmurhash2`: Detects MurmurHash2 constant (0x5BD1E995)
- `duqu_style`: Hybrid PE/MSI detection with named pipes and MSI artifacts

## Options

- `--pe-only`: Restrict to PE files only
- `--tighten`: Stricter conditions to reduce false positives
- `--recursive`: Scan subdirectories
- `--fast`: Use YARA fast mode
- `--deep`: Unpack archives before scanning (requires yextend)
- `--cuckoo-report`: Feed Cuckoo JSON for behavioral analysis
- `--json`: Export results to JSON file
