rule MALWARE_Win_Phobos {
    meta:
      description = "Detect the risk  of Ransomware Phobos Rule 1"
    strings:
        $x1 = "\\\\?\\UNC\\\\\\e-" fullword wide
        $x2 = "\\\\?\\ :" fullword wide
        $x3 = "POST" fullword wide
        $s1 = "ELVL" fullword wide
        $s2 = /SUP\d{3}/ fullword wide
        $s3 = { 41 31 47 ?? 41 2b }
    condition:
        uint16(0) == 0x5a4d and all of ($x*) and 1 of ($s*)
}

rule win_phobos_auto {
    meta:
        description = "Detect the risk  of Ransomware Phobos Rule 2"
    strings:
        $sequence_0 = { 57 ff15???????? 8906 3bc7 7427 57 ff36 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8906                 | mov                 dword ptr [esi], eax
            //   3bc7                 | cmp                 eax, edi
            //   7427                 | je                  0x29
            //   57                   | push                edi
            //   ff36                 | push                dword ptr [esi]

        $sequence_1 = { 59 6a14 8d4304 50 57 e8???????? }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   6a14                 | push                0x14
            //   8d4304               | lea                 eax, [ebx + 4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_2 = { ff7508 ffd0 ff75f8 57 e8???????? 59 }
            // n = 6, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { 0f85b3000000 57 8d44242c 50 be08020000 56 }
            // n = 6, score = 100
            //   0f85b3000000         | jne                 0xb9
            //   57                   | push                edi
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   50                   | push                eax
            //   be08020000           | mov                 esi, 0x208
            //   56                   | push                esi

        $sequence_4 = { 8945e4 85c0 0f84c2000000 bf???????? be04010000 }
            // n = 5, score = 100
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   85c0                 | test                eax, eax
            //   0f84c2000000         | je                  0xc8
            //   bf????????           |                     
            //   be04010000           | mov                 esi, 0x104

        $sequence_5 = { 8b450c 83c414 85c0 7408 8b0e 8b4c3908 }
            // n = 6, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b4c3908             | mov                 ecx, dword ptr [ecx + edi + 8]

        $sequence_6 = { eb05 ff74bc3c 4f ff15???????? 3bfb 75f1 }
            // n = 6, score = 100
            //   eb05                 | jmp                 7
            //   ff74bc3c             | push                dword ptr [esp + edi*4 + 0x3c]
            //   4f                   | dec                 edi
            //   ff15????????         |                     
            //   3bfb                 | cmp                 edi, ebx
            //   75f1                 | jne                 0xfffffff3

        $sequence_7 = { 333c95d0b14000 8b55fc c1ea08 c1eb10 23d0 8b1495d0ad4000 23d8 }
            // n = 7, score = 100
            //   333c95d0b14000       | xor                 edi, dword ptr [edx*4 + 0x40b1d0]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c1ea08               | shr                 edx, 8
            //   c1eb10               | shr                 ebx, 0x10
            //   23d0                 | and                 edx, eax
            //   8b1495d0ad4000       | mov                 edx, dword ptr [edx*4 + 0x40add0]
            //   23d8                 | and                 ebx, eax

        $sequence_8 = { e8???????? be???????? 8d7c2428 a5 a5 a5 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   be????????           |                     
            //   8d7c2428             | lea                 edi, [esp + 0x28]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_9 = { 7703 83c020 c3 55 8bec 57 ff7508 }
            // n = 7, score = 100
            //   7703                 | ja                  5
            //   83c020               | add                 eax, 0x20
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 139264
}
