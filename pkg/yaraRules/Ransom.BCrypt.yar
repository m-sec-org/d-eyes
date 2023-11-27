rule Ransom_BCrypt {
   meta:
      description= "Detect the risk of Ransomware BCrypt Rule 1"
      hash1 = "9b710b07d9192d590ecf8be939ce8ff44e23e64569687f636995270c618582a7"
      hash2 = "e47e4060f7a53eb7851b4f9622dccead3594b4af759f882f700cb1737b5f09c5"
   strings:
      $s1 = "https://www.douban.com/note/693052956/" fullword ascii
      $s2 = "C:\\windows64.ntd" fullword ascii
      $s3 = "AliWorkbench.exe" fullword ascii
      $s4 = "C:\\windows64-2.ntd" fullword ascii
      $s5 = "/bEncrypt" fullword wide
      $s6 = "unname_1989\\" fullword wide
      $s7 = "libcef.dll" fullword wide
      $s8 = "C:\\123456789.txt" fullword ascii
      $s9 = "SearchCompterFileEncrypt.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and 2 of them
}
