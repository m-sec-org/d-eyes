rule Ransom_Chaos {
   meta:
      description= "Detect the risk of Ransomware Chaos Rule 1"
      hash1 = "08c82472215e1c5deda74584d2b685c04f4fa13c1d30cf3917f850f545bba82d"
      hash2 = "a61ee15abf9142f2e3f311cf4dd54d1b2d2c7feb633c75083a8006cd0572ed29"
   strings:
      $s1 = "Coinmama - hxxps://www.coinmama.com Bitpanda - hxxps://www.bitpanda.com" fullword wide
      $s2 = "read_it.txt" fullword wide
      $s3 = "<EncryptedKey>" fullword wide
      $s4 = "Your computer was infected with a ransomware virus." wide
   condition:
      ( uint16(0) == 0x5a4d and 2 of them
      ) or ( all of them )
}
