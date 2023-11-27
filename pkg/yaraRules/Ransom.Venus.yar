rule Ransom_Venus {
   meta:
      description= "Detect the risk of Ransomware Venus Rule 1"
      hash1 = "49fd52a3f3d1d46dc065217e588d1d29fba4d978cd8fdb2887fd603320540f71"
   strings:
      $s1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $s2 = "/c ping localhost -n 3 > nul & del %s" fullword ascii
      $s3 = " To take info, write ro email getdecrypt@disroot.org or  and put this key:" fullword ascii
      $s4 = "mainProductV2.0.exe" fullword ascii
      $s5 = " write ro email getdecrypt@disroot.org or " fullword wide
      $s6 = "README.txt" fullword wide
      $s7 = "getdecrypt@disroot.org" fullword wide
      $s8 = "franavru.xyz" fullword ascii
      $s9 = "All your files has been encrypted " fullword ascii
      $s10 = " All your files has been encrypted " fullword wide
      $s11 = "dumbdumb" fullword ascii
      $s12 = "sysrandom" fullword ascii
      $s13 = "%s%x%x%x%x.goodgame" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      5 of them
}
