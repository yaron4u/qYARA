import "pe"

rule qyara_murmurhash2 {
  meta:
    author = "qYARA"
    generated = "2025-10-05"
    description = "MurmurHash2 scent (0x5BD1E995) common in API-hash code"

  strings:
    // 0x5BD1E995 little-endian
    $murmur_le = { 95 E9 D1 5B }

  condition:
    uint16(0) == 0x5A4D and filesize < 100MB and $murmur_le
}
