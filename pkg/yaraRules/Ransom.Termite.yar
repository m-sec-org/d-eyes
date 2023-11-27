rule Ransom_Termite {
   meta:
      description= "Detect the risk of Ransomware Termite Rule 1"
      hash1 = "e6c015b5dc3312e08fb242b7979b59818ff1d3bef65afee4852534ed1edba5cd"
      hash2 = "14acfbc63214e30d80258e7a32a0e366b0029d2119efa5b9c7126195124b71ae"
      hash3 = "ac5d4062cc3514901312d7cc2691d71ec56ba71b55f02c3f1f9aebe94cb2fbea"
   strings:
      $s1 = "Payment.exe" fullword ascii
      $s2 = "Termite.exe" fullword ascii
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
      $s4 = "C:\\Windows\\Termite.exe" fullword ascii
      $s5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
      $s6 = "\\Shell\\Open\\Command\\" fullword ascii
      $s7 = "\\Payment.exe" fullword ascii
      $s8 = "\\Termite.exe" fullword ascii
      $s9 = "Software\\Microsoft\\PassWord" fullword ascii
      $s10 = "takeown /f \"**\"" fullword ascii
      $s11 = "\\TemporaryFile" fullword ascii
      $s12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and 8 of them
}
