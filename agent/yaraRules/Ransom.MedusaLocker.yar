rule Ransom_MedusaLocker {
   meta:
      description= "Detect the risk of Ransomware MedusaLocker Rule 1"
      hash1 = "1e2335fef46f7320069623fff6702acb41c2877aff5fec83d94a561af37c3c7a"
   strings:
      $exts = ".exe,.dll,.sys,.ini,.lnk,.rdp,.encrypted,.READINSTRUCTIONS,.recoverme,.Readinstructions,.hivteam,.hiv,.386,.adv,.ani,.bat,.bin,." ascii
      $process1 = "wxServer.exe,wxServerView,sqlservr.exe,sqlmangr.exe,RAgui.exe,supervise.exe,Culture.exe,RTVscan.exe,Defwatch.exe,sqlbrowser.exe," ascii
      $process2 = "DtSrvr.exe,tomcat6.exe,java.exe,360se.exe,360doctor.exe,wdswfsafe.exe,fdlauncher.exe,fdhost.exe,GDscan.exe,ZhuDongFangYu.exe" fullword ascii
      $delshadows = "vssadmin.exe Delete Shadows /All /Quiet" fullword wide
      $s1 = "<!-- !!! dont changing this !!! -->" fullword ascii
      $s2 = "\\Users\\All Users" fullword wide
      $s3 = "[LOCKER] Kill processes" fullword wide
      $s4 = "  <!-- -->" fullword ascii
      $s5 = "[LOCKER] Is already running" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      3 of them
}
