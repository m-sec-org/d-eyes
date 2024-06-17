rule Ransom_Lockbit {
   meta:
      description= "Detect the risk of Ransomware Lockbit Rule 1"
      hash1 = "717585e9605ac2a971b7c7537e6e311bab9db02ecc6451e0efada9b2ff38b474"
   strings:
      $x1 = "powershell.exe -Command \"Get-ADComputer -filter * -Searchbase '%s' | foreach{ Invoke-GPUpdate -computer $_.name -force -RandomD" wide
      $x2 = "cmd.exe /c \"shutdown.exe /r /f /t 0\"" fullword wide
      $x3 = "C:\\Windows\\System32\\taskkill.exe" fullword wide
      $s4 = "\"C:\\Windows\\system32\\mshta.exe\" \"%s\"" fullword wide
      $s5 = "<Exec><Command>%s</Command><Arguments>%s</Arguments></Exec>" fullword wide
      $s6 = " /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" fullword wide
      $s7 = "C:\\windows\\system32\\%02X%02X%02X.ico" fullword wide
      $s8 = "\\??\\C:\\windows\\system32\\%02X%02X%02X.ico" fullword wide
      $s9 = "%%DesktopDir%%\\%02X%02X%02X.exe" fullword wide
      $s10 = "%02X%02X%02X.exe" fullword wide
      $s11 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell\\Open\\Command" fullword wide
      $s12 = "You can provide us accounting data for the access to any company, for example, login and password to RDP, VPN, corporate email, " wide
      $s13 = "\\\\%s\\ROOT\\CIMV2" fullword wide
      $s14 = "https://tox.chat/download.html" fullword wide
      $s15 = "LDAP://CN=%s,CN=Policies,CN=System,DC=%s,DC=%s" fullword wide
      $s16 = "\\LockBit_Ransomware.hta" fullword wide
      $s17 = "https://bigblog.at" fullword wide
      $s18 = "\\NetworkShares.xml" fullword wide
      $s19 = "\\Services.xml" fullword wide
      $s20 = "RESTORE-MY-FILES.TXT" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      5 of them
}
