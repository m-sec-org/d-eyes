rule Ransom_cryt0y {
   meta:
      description= "Detect the risk of Ransomware Cryt0y Rule 1"
      hash1 = "6d8dd5a564523b6f8597dd9009a74395bb48e5e1a85947157ced38034b20b6d4"
      hash2 = "fffc3cd304a280746276a3fa580a08f3de6aa2db4196c28ebd1c905607de0997"
   strings:
      $s1 = "You can decrypt, the encrypted files" ascii
      $s2 = "Asymmetric means that there are two different keys. This" ascii
      $s3 = "URL=file:///C:/ProgramData/anotherfile.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and any of them
}
