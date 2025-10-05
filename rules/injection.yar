import "pe"

rule qyara_process_injection {
  meta:
    author = "qYARA"
    generated = "2025-10-05"
    description = "Process injection scent (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)"

  strings:
    $s1 = "VirtualAllocEx" ascii wide nocase
    $s2 = "WriteProcessMemory" ascii wide nocase
    $s3 = "CreateRemoteThread" ascii wide nocase

  condition:
    any of ($s*)
}
