import "pe"

rule qyara_crc32 {
  meta:
    author = "qYARA"
    generated = "2025-10-05"
    description = "CRC32 scent (0xEDB88320) common in API-hash code"

  strings:
    // 0xEDB88320 little-endian
    $crc32_le = { 20 83 B8 ED }

  condition:
    $crc32_le
}
