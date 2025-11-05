rule Ransom_Thanos {
   meta:
      description= "Detect the risk of Ransomware Thanos Rule 1"
      hash1 = "4852f22df095db43f2a92e99384ff7667020413e74f67fcbd42fca16f8f96f4c"
      hash2 = "714f630043670cdab4475971a255d836a1366e417cd0b60053bf026551d62409"
   strings:
      $a1 = "Huahitec.exe" fullword wide
      $a2 = "Selected compression algorithm is not supported." fullword wide
      $a3 = "<Encrypt2>b__3f" fullword ascii
      $b1 = "F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" nocase ascii wide
      $b2 = "SimpleZip" fullword ascii
      $b3 = "CryptoStream" fullword ascii
      $s1 = "GetAesTransform" fullword ascii
      $s2 = "GetFromResource" fullword ascii
      $s3 = "CreateGetStringDelegate" fullword ascii
      $s4 = "<Encrypt2>b__40" fullword ascii
      $s5 = "Unknown Header" fullword wide
      $s6 = "SmartAssembly.Attributes" fullword ascii
      $s7 = "CompressionAlgorithm" fullword ascii
      $s8 = "hashtableLock" fullword ascii
      $s9 = "DoNotPruneAttribute" fullword ascii
      $s10 = "MemberRefsProxy" fullword ascii
      $s11 = "DoNotPruneTypeAttribute" fullword ascii
      $s12 = "SmartAssembly.Zip" fullword ascii
      $s13 = "Huahitec" fullword ascii
      $s14 = "GetCachedOrResource" fullword ascii
      $s15 = "<Killproc>b__5" fullword ascii
      $s16 = "<Killproc>b__4" fullword ascii
      $s17 = "PathLink" fullword ascii
      $x1 = "RijndaelManaged" fullword ascii
      $x2 = "Microsoft.VisualBasic" ascii
   condition:
      uint16(0) == 0x5a4d and 2 of ($a*) and 2 of ($b*) and 6 of ($s*) and all of ($x*)
}

rule win_hakbit_auto {

    meta:
        description= "Detect the risk of Ransomware Thanos Rule 2"
    strings:
        $sequence_0 = { 40 c1e004 8b4dfc 8d740104 8b45e4 c1e004 8b4dfc }
            // n = 7, score = 300
            //   40                   | inc                 eax
            //   c1e004               | shl                 eax, 4
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8d740104             | lea                 esi, [ecx + eax + 4]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   c1e004               | shl                 eax, 4
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_1 = { 8bec 51 51 c745f8010000c0 e8???????? 58 }
            // n = 6, score = 300
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   c745f8010000c0       | mov                 dword ptr [ebp - 8], 0xc0000001
            //   e8????????           |                     
            //   58                   | pop                 eax

        $sequence_2 = { 40 8945f4 837df403 7377 8b45f4 8b4dfc }
            // n = 6, score = 300
            //   40                   | inc                 eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df403             | cmp                 dword ptr [ebp - 0xc], 3
            //   7377                 | jae                 0x79
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { ff7508 8b45fc 83c018 ffd0 8945f8 837df800 0f8ca8000000 }
            // n = 7, score = 300
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c018               | add                 eax, 0x18
            //   ffd0                 | call                eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   0f8ca8000000         | jl                  0xae

        $sequence_4 = { 8b4dfc 8b44810c 2b450c 8945f0 8365ec00 eb07 8b45ec }
            // n = 7, score = 300
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b44810c             | mov                 eax, dword ptr [ecx + eax*4 + 0xc]
            //   2b450c               | sub                 eax, dword ptr [ebp + 0xc]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8365ec00             | and                 dword ptr [ebp - 0x14], 0
            //   eb07                 | jmp                 9
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_5 = { 88040a ebd2 e9???????? 8b45f8 5e c9 c21400 }
            // n = 7, score = 300
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   ebd2                 | jmp                 0xffffffd4
            //   e9????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c21400               | ret                 0x14

        $sequence_6 = { 8364010c00 8b45e8 c1e004 8b4dfc c644010800 8b45e8 c1e004 }
            // n = 7, score = 300
            //   8364010c00           | and                 dword ptr [ecx + eax + 0xc], 0
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   c1e004               | shl                 eax, 4
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c644010800           | mov                 byte ptr [ecx + eax + 8], 0
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   c1e004               | shl                 eax, 4

        $sequence_7 = { 51 c745f8010000c0 e8???????? 58 2500f0ffff 8945fc 837d1400 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   c745f8010000c0       | mov                 dword ptr [ebp - 8], 0xc0000001
            //   e8????????           |                     
            //   58                   | pop                 eax
            //   2500f0ffff           | and                 eax, 0xfffff000
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0

        $sequence_8 = { 33c9 8b55fc 66894c020a 8b45e8 c1e004 8b4dfc 8364010c00 }
            // n = 7, score = 300
            //   33c9                 | xor                 ecx, ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   66894c020a           | mov                 word ptr [edx + eax + 0xa], cx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   c1e004               | shl                 eax, 4
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8364010c00           | and                 dword ptr [ecx + eax + 0xc], 0

        $sequence_9 = { 0f8ca8000000 ff7508 8b45fc ff10 }
            // n = 4, score = 300
            //   0f8ca8000000         | jl                  0xae
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff10                 | call                dword ptr [eax]

    condition:
        7 of them and filesize < 656384
}
