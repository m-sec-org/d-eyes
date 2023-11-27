rule Ransom_Cryakl {
   meta:
      description = "Detect the risk of Ransomeware Cryakl Rule 1"
      hash1 = "735abbb3b5a1e7eeb625696c92c08ca4cfda110c1f6627524ade4f368a311bc0"
   strings:
      $s1 = "bin:com:exe:bat:png:bmp:dat:log:ini:dll:sys:|||QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" ascii
      $s2 = "README.txt" fullword wide
      $s3 = "/Create /RU SYSTEM /SC ONCE /TN VssDataRestore /F /RL HIGHEST /TR \"vssadmin delete shadows /all /quiet\" /st 00:00" fullword ascii
      $s4 = "schtasks" fullword ascii
      $s5 = "/Run /tn VssDataRestore" fullword ascii
      $s6 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      3 of them
}
