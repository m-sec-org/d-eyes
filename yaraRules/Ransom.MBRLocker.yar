rule Ransom_MBRLocker {
   meta:
      description= "Detect the risk of Ransomware MBRLocker Rule 1"
   strings:
      $s1 = "PhysicalDrive0" nocase
      $s2 = "Your disk have a lock!" nocase
      $s3 = "Please input the unlock password!" nocase
      $s4 = {5bc678014e0d80fd8d858fc731384f4dff01ff01ff01ff01ff01}
      $s5 = {5bc678014e0d53ef4ee54e3a7a7a7684}
      $s6 = "jiesuo+qq"
      $s7 = "jiesuo+QQ"
      $x1 = {566A0068800000006A036A006A0168000000406828645900ff15????????8B}
      $x2 = "CreateFileA" fullword ascii
   condition:
      uint16(0) == 0x5a4d and $s1 and 3 of them
}

rule KillMBR {
    meta:
        description= "Detect the risk of Ransomware MBRLocker Rule 2"
    strings:
        $s1 = "\\\\.\\PhysicalDrive" ascii
        $s2 = "/logger.php" ascii
        $s3 = "Ooops! Your MBR was been rewritten" ascii
        $s4 = "No, this ransomware dont encrypt your files, erases it" ascii
    condition:
        uint16(0) == 0x5a4d and (2 of them and #s1 > 10)
}
