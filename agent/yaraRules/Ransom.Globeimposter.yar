import "hash"
rule Globeimposter {
   meta:
      description = "Detect the risk of Ransomware Globeimposter Rule 1"
      hash1 = "e478fe703e64b417ed40b35dc5063e78afc00b26b867b12e648efd94d8be59cc"
   strings:
      $s1 = "fistulization7.dll" fullword ascii
      $s2 = "Husmandsforeningen.exe" fullword wide
      $s3 = "GetPrintProcessorDirectoryA" fullword ascii
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s5 = "AShell_NotifyIconA" fullword ascii
      $s6 = "EnumPortsA" fullword ascii
      $s7 = "Tittupping" fullword ascii
      $s8 = "Husmandsforeningen" fullword wide
      $s9 = "Slappendes" fullword ascii
      $s10 = "Cosmetics" fullword ascii
      $s11 = "Besindedes" fullword ascii
      $s12 = "Pimpstenens" fullword ascii
      $s13 = "Pneumatogenic" fullword ascii
      $s14 = "Epimorphosis8" fullword ascii
      $s15 = "Antistimulation4" fullword ascii
      $s16 = "Crithidia3" fullword ascii
      $s17 = "Teksthenvisningen5" fullword ascii
      $s18 = "Unpuddled7" fullword ascii
      $s19 = "Underfakturerings6" fullword ascii
      $s20 = "UY3 /i" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule Ransomware_Globeimposter {
   meta:
      description = "Detect the risk of Ransomware Globeimposter Rule 2"
      hash1 = "e478fe703e64b417ed40b35dc5063e78afc00b26b867b12e648efd94d8be59cc"
   strings:
      $s1 = "fistulization7.dll" fullword ascii
      $s2 = "Husmandsforeningen.exe" fullword wide
      $s3 = "GetPrintProcessorDirectoryA" fullword ascii
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s5 = "AShell_NotifyIconA" fullword ascii
      $s6 = "EnumPortsA" fullword ascii
      $s7 = "Tittupping" fullword ascii
      $s8 = "Husmandsforeningen" fullword wide
      $s9 = "Slappendes" fullword ascii
      $s10 = "Cosmetics" fullword ascii
      $s11 = "Besindedes" fullword ascii
      $s12 = "Pimpstenens" fullword ascii
      $s13 = "Pneumatogenic" fullword ascii
      $s14 = "Epimorphosis8" fullword ascii
      $s15 = "Antistimulation4" fullword ascii
      $s16 = "Crithidia3" fullword ascii
      $s17 = "Teksthenvisningen5" fullword ascii
      $s18 = "Unpuddled7" fullword ascii
      $s19 = "Underfakturerings6" fullword ascii
      $s20 = "UY3 /i" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      5 of them
}
rule win_globeimposter_auto {

    meta:
        description = "Detect the risk of Ransomware Globeimposter Rule 3"
    strings:
        $sequence_0 = { 0ff4d0 0f6e6604 0ff4e0 0f6e7608 0ff4f0 0f6e7e0c }
            // n = 6, score = 700
            //   0ff4d0               | pmuludq             mm2, mm0
            //   0f6e6604             | movd                mm4, dword ptr [esi + 4]
            //   0ff4e0               | pmuludq             mm4, mm0
            //   0f6e7608             | movd                mm6, dword ptr [esi + 8]
            //   0ff4f0               | pmuludq             mm6, mm0
            //   0f6e7e0c             | movd                mm7, dword ptr [esi + 0xc]

        $sequence_1 = { 45 8364241000 8d442410 50 6880000000 8d44241c }
            // n = 6, score = 700
            //   45                   | inc                 ebp
            //   8364241000           | and                 dword ptr [esp + 0x10], 0
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   6880000000           | push                0x80
            //   8d44241c             | lea                 eax, [esp + 0x1c]

        $sequence_2 = { 43 85d2 7e18 8d4e7c 8b41fc 3b01 }
            // n = 6, score = 700
            //   43                   | inc                 ebx
            //   85d2                 | test                edx, edx
            //   7e18                 | jle                 0x1a
            //   8d4e7c               | lea                 ecx, [esi + 0x7c]
            //   8b41fc               | mov                 eax, dword ptr [ecx - 4]
            //   3b01                 | cmp                 eax, dword ptr [ecx]

        $sequence_3 = { 8b450c 99 33c2 c745f401000000 }
            // n = 4, score = 700
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   99                   | cdq                 
            //   33c2                 | xor                 eax, edx
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1

        $sequence_4 = { 48 8bfb 2bf8 89442414 }
            // n = 4, score = 700
            //   48                   | dec                 eax
            //   8bfb                 | mov                 edi, ebx
            //   2bf8                 | sub                 edi, eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax

        $sequence_5 = { 5e 5b 5f 5d 83c420 c20c00 }
            // n = 6, score = 700
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   83c420               | add                 esp, 0x20
            //   c20c00               | ret                 0xc

        $sequence_6 = { 7e0e 8d4678 8928 41 8d4014 3b4e6c }
            // n = 6, score = 700
            //   7e0e                 | jle                 0x10
            //   8d4678               | lea                 eax, [esi + 0x78]
            //   8928                 | mov                 dword ptr [eax], ebp
            //   41                   | inc                 ecx
            //   8d4014               | lea                 eax, [eax + 0x14]
            //   3b4e6c               | cmp                 ecx, dword ptr [esi + 0x6c]

        $sequence_7 = { 7505 6ac4 58 eb2f }
            // n = 4, score = 700
            //   7505                 | jne                 7
            //   6ac4                 | push                -0x3c
            //   58                   | pop                 eax
            //   eb2f                 | jmp                 0x31

        $sequence_8 = { 8d0445ffffffff 8945f0 8d45fc 8945f8 8d45f0 50 }
            // n = 6, score = 700
            //   8d0445ffffffff       | lea                 eax, [eax*2 - 1]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_9 = { ff15???????? 85c0 7405 3975fc 7405 6afe 58 }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi
            //   7405                 | je                  7
            //   6afe                 | push                -2
            //   58                   | pop                 eax

    condition:
        7 of them and filesize < 327680
}

rule globeimposter_hash
{
   meta:
        description ="Detect the risk of globeimposter Rule 4"
   condition:
    hash.sha256(0,filesize) =="70866cee3b129918e2ace1870e66801bc25a18efd6a8c0234a63fccaee179b68" or
    hash.sha256(0,filesize) =="8b6993a935c33bbc028b2c72d7b2e769ff2cd5ad35331bc4d2dcce67a0c81569"
}
