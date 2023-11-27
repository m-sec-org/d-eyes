rule Ransom_Babuk {
   meta:
      description= "Detect the risk of Ransomware Babuk Rule 1"
      hash1 = "5eb21c59b6a0df15be307fc5ef82464f3d9a56dff8f4214576c48dbc9d3fe7af"
      hash2 = "1f2edda243404918b78aa6123aa1fc5b18dd9506e4042c7a1547b565334527e1"
   strings:
      $mutex = "DoYouWantToHaveSexWithCuongDong" fullword ascii
      $mutex_api1 = "OpenMutexA" fullword ascii
      $mutex_api2 = "CreateMutexA" fullword ascii
      $delshadow1 = "/c vssadmin.exe delete shadows /all /quiet" wide
      $delshadow2 = "cmd.exe" wide
      $delshadow3 = "open" fullword wide
      $delshadow_api = "ShellExecuteW" fullword ascii
      $folder1 = "AppData" fullword wide
      $folder2 = "Boot" fullword wide
      $folder3 = "Windows.old" fullword wide
      $folder4 = "Tor Browser" fullword wide
      $folder5 = "$Recycle.Bin" fullword wide
      $note = "\\How To Restore Your Files.txt" fullword wide
      $encrypt = ".babyk" fullword wide
      $op1 = {C7 85 D0 FE FF FF 63 68 6F 75}
      $op2 = {C7 85 D4 FE FF FF 6E 67 20 64}
      $op3 = {C7 85 D8 FE FF FF 6F 6E 67 20}
      $op4 = {C7 85 DC FE FF FF 6C 6F 6F 6B}
      $op5 = {C7 85 E0 FE FF FF 73 20 6C 69}
      $op6 = {C7 85 E4 FE FF FF 6B 65 20 68}
      $op7 = {C7 85 E8 FE FF FF 6F 74 20 64}
      $op8 = {C7 85 EC FE FF FF 6F 67 21 21 68 80 00 00 00}
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (all of ($mutex*) or all of ($delshadow*) or all of ($folder*) or $note or $encrypt or 3 of ($op*))
}
