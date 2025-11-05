rule Ransom_NoCry {
   meta:
      description= "Detect the risk of Ransomware NoCry Rule 1"
      hash1 = "486f2053c32ba44eb2afaf87e1ba8d8db408ef09cb7d895f3a8dc0f4081a7467"
   strings:
      $a1 = "https://www.google.com/search?q=how+to+buy+bitcoin"
      $a2 = "C:\\Users\\ku5h2\\OneDrive\\Desktop\\NoCry Discord\\ransomeware\\obj\\Debug\\NoCry.pdb" fullword ascii
      $a3 = " worth of bitcoin to this address:"
      $a4 = "Ooooops All Your Files Are Encrypted ,NoCry"
      $a5 = "NoCry.Form4.resources"
      $a6 = "Decryption : Working * "
      $a7 = "Runcount.cry"
      $aop1 = {28 36 00 00 0A 00 1F FE 0A 18 0C 02 19 17 73 EE 00 00 0A 80 4E 00 00 04 19 0C 03 1A 18 73 EE 00 00 0A 80 4F 00 00}
      $b1 = "EncryptOrDecryptFile" fullword ascii
      $b2 = "bytKey" fullword ascii
      $b3 = "MD5HASH" fullword ascii
   condition:
      uint16(0) == 0x5a4d and (any of ($a*) or all of ($b*))
}

