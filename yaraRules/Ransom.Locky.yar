rule Ransom_Locky {
   meta:
      description= "Detect the risk of Ransomware Locky Rule 1"
      hash1 = "5606e9dc4ab113749953687adac6ddb7b19c864f6431bdcf0c5b0e2a98cca39e"
      hash2 = "8ff979f23f8bab94ce767d4760811bde66c556c0c56b72bb839d4d277b3703ad"
   strings:
      $s1 = "gefas.pdb" fullword ascii
      $s2 = "ggqfslmb" fullword ascii
      $s3 = "gr7shadtasghdj" fullword ascii
      $s4 = "ppgnui.dll" fullword ascii
      $s5 = "unqxfddunlkl" fullword ascii
      $s6 = "hpmeiokm" fullword ascii
      $s7 = "bdkc" fullword ascii
      $s8 = {47 41 41 00 63 65 73 73 68 3B 41 41 00 82 04 24}
      $s9 = {41 00 68 77 41 41 00 E8}
      $s10 = "sctrs.dll" fullword ascii
      $s11 = {61 8D 35 2E 41 41}
      $pack = {00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 E0 2E 64 65 63 00 00 00 00 00 00}
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them
}

rule win_locky_auto {

    meta:
      description= "Detect the risk of Ransomware Locky Rule 2"

    strings:
        $sequence_0 = { 33c9 8d8445e8fbffff c7461407000000 50 66890e 56 8d8de8fbffff }
            // n = 7, score = 2100
            //   33c9                 | xor                 ecx, ecx
            //   8d8445e8fbffff       | lea                 eax, [ebp + eax*2 - 0x418]
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7
            //   50                   | push                eax
            //   66890e               | mov                 word ptr [esi], cx
            //   56                   | push                esi
            //   8d8de8fbffff         | lea                 ecx, [ebp - 0x418]

        $sequence_1 = { 85c0 7528 38450c 751e ff15???????? }
            // n = 5, score = 2100
            //   85c0                 | test                eax, eax
            //   7528                 | jne                 0x2a
            //   38450c               | cmp                 byte ptr [ebp + 0xc], al
            //   751e                 | jne                 0x20
            //   ff15????????         |                     

        $sequence_2 = { 7430 3bc7 5f 732b ff75fc 83661000 }
            // n = 6, score = 2100
            //   7430                 | je                  0x32
            //   3bc7                 | cmp                 eax, edi
            //   5f                   | pop                 edi
            //   732b                 | jae                 0x2d
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   83661000             | and                 dword ptr [esi + 0x10], 0

        $sequence_3 = { eb02 8bce 3bc1 740e 48 ebea }
            // n = 6, score = 2100
            //   eb02                 | jmp                 4
            //   8bce                 | mov                 ecx, esi
            //   3bc1                 | cmp                 eax, ecx
            //   740e                 | je                  0x10
            //   48                   | dec                 eax
            //   ebea                 | jmp                 0xffffffec

        $sequence_4 = { 8365fc00 56 83c9ff 8bf0 }
            // n = 4, score = 2100
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   56                   | push                esi
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 33ff 8d75b8 e8???????? 57 ff15???????? cc }
            // n = 6, score = 2100
            //   33ff                 | xor                 edi, edi
            //   8d75b8               | lea                 esi, [ebp - 0x48]
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   cc                   | int3                

        $sequence_6 = { 99 5e f7fe 8bf0 81fe48922409 }
            // n = 5, score = 2100
            //   99                   | cdq                 
            //   5e                   | pop                 esi
            //   f7fe                 | idiv                esi
            //   8bf0                 | mov                 esi, eax
            //   81fe48922409         | cmp                 esi, 0x9249248

        $sequence_7 = { c3 8b00 85c0 7407 50 ff15???????? c3 }
            // n = 7, score = 2100
            //   c3                   | ret                 
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c3                   | ret                 

        $sequence_8 = { 8b442408 f7e1 03d3 5b c21000 e9???????? 8bff }
            // n = 7, score = 1400
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   f7e1                 | mul                 ecx
            //   03d3                 | add                 edx, ebx
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   e9????????           |                     
            //   8bff                 | mov                 edi, edi

        $sequence_9 = { e9???????? 90 31c0 e9???????? 90 }
            // n = 5, score = 700
            //   e9????????           |                     
            //   90                   | nop                 
            //   31c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   90                   | nop                 

        $sequence_10 = { 8d36 e9???????? 90 8d6d00 90 }
            // n = 5, score = 700
            //   8d36                 | lea                 esi, [esi]
            //   e9????????           |                     
            //   90                   | nop                 
            //   8d6d00               | lea                 ebp, [ebp]
            //   90                   | nop                 

        $sequence_11 = { 31c0 90 e9???????? 8d36 90 }
            // n = 5, score = 700
            //   31c0                 | xor                 eax, eax
            //   90                   | nop                 
            //   e9????????           |                     
            //   8d36                 | lea                 esi, [esi]
            //   90                   | nop                 

        $sequence_12 = { 90 e9???????? 90 59 e9???????? 90 }
            // n = 6, score = 700
            //   90                   | nop                 
            //   e9????????           |                     
            //   90                   | nop                 
            //   59                   | pop                 ecx
            //   e9????????           |                     
            //   90                   | nop                 

        $sequence_13 = { 5e c21000 8bff 55 8bec 33c0 8b4d08 }
            // n = 7, score = 700
            //   5e                   | pop                 esi
            //   c21000               | ret                 0x10
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_14 = { e8???????? e9???????? 8d09 e9???????? 90 }
            // n = 5, score = 700
            //   e8????????           |                     
            //   e9????????           |                     
            //   8d09                 | lea                 ecx, [ecx]
            //   e9????????           |                     
            //   90                   | nop                 

        $sequence_15 = { e9???????? 90 8d00 90 e9???????? 8d09 }
            // n = 6, score = 700
            //   e9????????           |                     
            //   90                   | nop                 
            //   8d00                 | lea                 eax, [eax]
            //   90                   | nop                 
            //   e9????????           |                     
            //   8d09                 | lea                 ecx, [ecx]

    condition:
        7 of them and filesize < 1122304
}

// From ClamAV
rule Win_Ransomware_Locky
{
   meta:
      description= "Detect the risk of Ransomware Locky Rule 3"
   strings:
      $a0 = { 558bec518d45??50ff15[4]50ff15[4]85c074158b4d??83f9027c0dff7488fcff15[4]59c9c333c0c9c3 }
      $a1 = { 558bec5156578d45??50ff15[4]50ff15[4]8bf085f6741b837d??027c15ff7604ff15[4]59568bf8ff15[4]eb0233ff8bc75f5ec9c3 }
      $a2 = { 8d45??5068[4]c745??47657454c745??69636b43c745??6f756e74c645??00ff15[4]50ff15[4]8945??ffd0 }
      $a3 = { F51A5B38A8AF95760C8CF179CB43474580A5E48E2D74EF4E56660CA4A2A1407D }
   condition:
      any of them
}
