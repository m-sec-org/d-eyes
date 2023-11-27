import "pe"
rule henry217 {
   meta:
      description= "Detect the risk of Ransomware henry217 Rule 1"
      hash1 = "8dd3fba314bdef96075961d8e0ee3a45d5a3030f89408d2b7f9d9fa5eedc66cd"
   strings:
      $s1 = "RansomeWare" ascii
      $s2 = "AESEncrypt" fullword ascii
      $s3 = {AE 5F 6F 8F C5 96 D1 9E}
      $s4 = {59 00 6F 00 75 00 72 00 20 00 66 00 69 00 6C 00 65 00}
      $s5 = {48 00 65 00 6C 00 6C 00 6F}
      $o1 = {68 00 65 00 6E 00 72 00 79 00 32 00 31 00 37}
      $o2 = {43 00 3A 00 5C 00 00 00 2E 00 73 00 79 00 73 00}
      $pdb = {44 3A 5C D4 B4 C2 EB 5C [2-60] 2E 70 64 62}
      $x1 = "RansomeWare.Form1.resources"
      $x2 = "76a60872-fdf3-466a-9d80-a853c3485b32" nocase ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and ((all of ($s*) or 1 of ($o*)) or (1 of ($s*) and $pdb) or 1 of ($x*)) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}

rule henry217_opcode {
   meta:
      description= "Detect the risk of Ransomware henry217 Rule 2"
      hash1 = "8dd3fba314bdef96075961d8e0ee3a45d5a3030f89408d2b7f9d9fa5eedc66cd"
   strings:
      $opcode1 = {1B300400A9000000020000111F208D270000010A281800000A03068E696F1900000A6F1A00000A06068E69281B00000A1F108D270000010B281800000A04078E696F1900000A6F1A00000A07078E69281B00000A140C281C00000A0D731D00000A130411040906076F1E00000A17731F00000A130511050216028E696F2000000A11056F2100000A11046F2200000A0CDE0C11052C0711056F2300000ADCDE0C11042C0711046F2300000ADCDE0526140CDE00082A00000001280000020069001D86000C00000000020057003D94000C000000000000500052A2000513000001}
      $opcode2 = {1B3005004F01000003000011036F2400000A0A16}
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (1 of them) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}
