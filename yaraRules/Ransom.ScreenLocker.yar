rule Ransom_ScreenLocker_Aug_3 {
   meta:
      description= "Detect the risk of Ransomware ScreenLocker Rule 1"
      hash1 = "71ec3df35bf0acdf1d7071fd15a8727da8eaff1a98f3e236e52290b92217c198"
   strings:
      $s1 = "get_ransomware" fullword ascii
      $s2 = "Ransomware" fullword ascii
      $s3 = "Zakazane" fullword ascii
      $Guid = "$d7a38334-313b-439e-a139-e7d2c97556c7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      (all of ($s*) or $Guid)
}
