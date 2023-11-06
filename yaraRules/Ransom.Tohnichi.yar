rule Ransom_Tohnichi {
   meta:
      description= "Detect the risk of Ransomware Tohnichi Rule 1"
      hash1 = "863e4557e550dd89e5ca0e43c57a3fc1889145c76ec9787e97f76e959fc8e1e1"
      hash2 = "4d9a662a5d4d97a2c06b74552634c570b16e56c5c456c77ed1d640c23c70b600"
   strings:
      $x1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\vssadmin.exe" fullword wide
      $x2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe" fullword wide
      $x3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\powershell.exe" fullword wide
      $x4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wmic.exe" fullword wide
      $x5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbadmin.exe" fullword wide
      $x6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\bcdedit.exe" fullword wide
      $x7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\diskshadow.exe" fullword wide
      $x8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\net.exe" fullword wide
      $s9 = "\\sysnative\\cmd.exe" fullword wide
      $s10 = "fdhost.exe" fullword wide
      $s11 = "ReportingServecesService.exe" fullword wide
      $s12 = "A: * Download Tor Browser - https://www.torproject.org/" fullword ascii
      $s13 = "mysql.exe" fullword wide
      $s14 = "sqlwriter.exe" fullword wide
      $s15 = "ntdbsmgr.exe" fullword wide
      $s16 = "oracle.exe" fullword wide
      $s17 = "sqlserv.exe" fullword wide
      $s18 = "\\sysnative\\vssadmin.exe" fullword wide
      $s19 = "C:\\HOW TO RECOVER !!.TXT" fullword wide
      $s20 = "debugLog.txt" fullword wide
      $s21 = "/c ping 127.0.0.1 && del \"%s\" >> NUL" fullword wide
      $s22 = "bootfont.bin" fullword wide
      $s23 = "perflogs" fullword wide
      $s24 = "How to decrypt files.txt" fullword wide
      $s25 = "/c bcdedit /set {current} bootstatuspolicy ignoreallfailures" fullword wide
      $s26 = "Info added: %s%s" fullword wide
      $s27 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Raccine" fullword wide
      $s28 = " Type Descriptor'" fullword ascii
      $s29 = "bootsect.bak" fullword wide
      $s30 = "windows.old" fullword wide
      $s31 = "Invalid Handle (error: %d) for: %s" fullword wide
      $s32 = "IOCP Worker: Exit, overlap was NULL and completionKey == IOCP_STOP" fullword wide
      $s33 = "FirstFirstFileExW (error: %d) failed for %s" fullword wide
      $s34 = " constructor or from DllMain." fullword ascii
      $s35 = "All files on TOHNICHI network have been encrypted due to insufficient security." fullword ascii
      $s36 = "Encrypted:" fullword ascii
      $s37 = "WindowsPowerShell" fullword wide
      $s38 = "Starting file encryption: %s" fullword wide
      $s39 = "127.0.0.1/a.php" fullword wide
      $s40 = "%lld (%d%%)" fullword ascii
      $s41 = "programdata" fullword wide
      $s42 = "/c bcdedit /set {current} recoveryenabled no" fullword wide
      $s43 = " delete shadows /all /quiet" fullword wide
      $s44 = "Your personal identifier: {id}" fullword ascii
      $s45 = "id=%s&pcname=%s&dcname=%S" fullword ascii
      $s46 = "id=%s&disksinfo=%s" fullword ascii
      $s47 = "Windows Portable Devices" fullword wide
      $s48 = "Microsoft Analysis Services" fullword wide
      $s49 = "Core Runtime" fullword wide
      $s50 = "Microsoft ASP.NET" fullword wide
      $s51 = "Windows Microsoft.NET" fullword wide
      $s52 = "NTFS: failed to open %c drive" fullword wide
      $s53 = "NTFS: Failed to query USN journal (%c)" fullword wide
      $s54 = "%d (%d cores) IOCP workers started." fullword wide
      $s55 = "All files done. Only shares left." fullword wide
      $s56 = "   * Open link in Tor Browser http://eghv5cpdsmuj5e6tpyjk5icgq642hqubildf6yrfnqlq3rmsqk2zanid.onion/contact" fullword ascii
      $s57 = " Base Class Descriptor at (" fullword ascii
      $s58 = " Class Hierarchy Descriptor'" fullword ascii
      $s59 = "tor browser" fullword wide
      $s60 = "   Decryption of your files with the help of third parties may cause increased price or you can become a victim of a scam." fullword ascii
      $s61 = " Complete Object Locator'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( 10 of them )
}
