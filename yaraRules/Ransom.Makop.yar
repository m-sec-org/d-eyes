rule RANSOM_makop
{
    meta:
        description= "Detect the risk of Ransomware Makop Rule 1"
        hash = "008e4c327875110b96deef1dd8ef65cefa201fef60ca1cbb9ab51b5304e66fe1"
    strings:
        $pattern_0 = { 50 8d7c2420 e8???????? 84c0 0f84a6020000 8b742460 ba???????? }
        $pattern_1 = { 51 52 53 ffd5 85c0 746d 8b4c240c }
        $pattern_2 = { 7521 68000000f0 6a18 6a00 6a00 56 ff15???????? }
        $pattern_3 = { 83c40c 8d4e0c 51 66c7060802 66c746041066 c6460820 }
        $pattern_4 = { 51 ffd3 50 ffd7 8b4628 85c0 }
        $pattern_5 = { 85c9 741e 8b4508 8b4d0c 8a11 }
        $pattern_6 = { 83c002 6685c9 75f5 2bc6 d1f8 66390c46 8d3446 }
        $pattern_7 = { 895a2c 8b7f04 85ff 0f85f7feffff 55 6a00 }
        $pattern_8 = { 8b3d???????? 6a01 6a00 ffd7 50 ff15???????? }
        $pattern_9 = { 85c0 7407 50 ff15???????? }
   
    condition:

        7 of them and
        filesize < 237568
}

rule win_makop_ransomware_auto {

    meta:
        description= "Detect the risk of Ransomware Makop Rule 2"
    strings:
        $sequence_0 = { 6a04 8d542408 52 6a18 50 c744241400000000 ff15???????? }
            // n = 7, score = 100
            //   6a04                 | push                4
            //   8d542408             | lea                 edx, [esp + 8]
            //   52                   | push                edx
            //   6a18                 | push                0x18
            //   50                   | push                eax
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   ff15????????         |                     

        $sequence_1 = { 8d442410 e8???????? 6a00 6a00 6a00 6a00 }
            // n = 6, score = 100
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 7403 50 ffd6 8b442410 83f8ff 7403 }
            // n = 6, score = 100
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   83f8ff               | cmp                 eax, -1
            //   7403                 | je                  5

        $sequence_3 = { 57 6a2c 33db 53 ffd6 8b3d???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6a2c                 | push                0x2c
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   8b3d????????         |                     

        $sequence_4 = { 0fb74c1702 83c202 0fb7ee 2bcd 74e8 33ed 3bcd }
            // n = 7, score = 100
            //   0fb74c1702           | movzx               ecx, word ptr [edi + edx + 2]
            //   83c202               | add                 edx, 2
            //   0fb7ee               | movzx               ebp, si
            //   2bcd                 | sub                 ecx, ebp
            //   74e8                 | je                  0xffffffea
            //   33ed                 | xor                 ebp, ebp
            //   3bcd                 | cmp                 ecx, ebp

        $sequence_5 = { 7420 837c240c08 7219 8b442410 8b4c2414 50 51 }
            // n = 7, score = 100
            //   7420                 | je                  0x22
            //   837c240c08           | cmp                 dword ptr [esp + 0xc], 8
            //   7219                 | jb                  0x1b
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_6 = { 85c0 751a ff15???????? 8b4c2404 51 ff15???????? 32c0 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   751a                 | jne                 0x1c
            //   ff15????????         |                     
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al

        $sequence_7 = { 56 6a00 ffd7 50 ff15???????? 6a08 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a08                 | push                8

        $sequence_8 = { ffd3 50 ffd7 8b4628 85c0 741a b92c000000 }
            // n = 7, score = 100
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c
            //   b92c000000           | mov                 ecx, 0x2c

        $sequence_9 = { 8b442418 8b542414 8bcf e8???????? 85c0 0f84db020000 8b442414 }
            // n = 7, score = 100
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84db020000         | je                  0x2e1
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

    condition:
        7 of them and filesize < 107520
}

rule win_makop_ransomware_w0 {
    meta:
        description= "Detect the risk of Ransomware Makop Rule 3"

    strings:
        $str1 = "-%08X"
        $str2 = "MPR.dll"
        $str3 = "\\*.*" wide

        $dec1 = { 8b ?? ?? 6a 08 8d ?? ?? ?? 52 8d ?? ?? ?? 50 e8 ?? ?? ?? ?? 66 ?? ?? ?? ?? 66 ?? ?? ?? ?? 83 c4 0c 66 3b c1 76 ?? 0f b7 c9 0f b7 f8 2b f9 74 ?? 57 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8b d8 85 db 74 ?? 0f ?? ?? ?? ?? 03 ?? ?? 57 52 53 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? 55 ff ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 8b ?? ?? ?? 50 53 6a 00 6a 00 89 ?? 8b ?? ?? 6a 00 50 ff ?? ?? ?? ?? ?? 85 c0 75 ?? ff ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 33 c0 5f 5e 5d 5b 83 c4 0c c2 08 00}
        $start = {55 8b ec 83 e4 f8 a1 ?? ?? ?? ?? 81 ec 64 02 00 00 85 c0 53 56 57 74 ?? 6a 00 50 ff ?? ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? 0f ?? ?? ?? 8b ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 04 84 c0 0f ?? ?? ?? ?? ?? 8b ?? ?? 8d ?? ?? 8d ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8b f0 85 f6 0f ?? ?? ?? ?? ?? 8b ?? ?? 80 ?? ?? ?? 75 ?? 81 fb fa 00 00 00 72 ?? 8b ?? ?? ?? ?? ?? 8b de e8 ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 83 c7 04 8d ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? 8d ?? ?? ?? bf 05 00 00 00 eb ??}

    condition:
        ( uint16(0) == 0x5a4d and
        ( 4 of them )
        ) or ( all of them )
}

rule Makop_Ransomware {
   meta:
      description= "Detect the risk of Ransomware Makop Rule 4"
      hash1 = "082a2ce2dde8b3a50f2d499496879e85562ee949cb151c8052eaaa713cddd0f8"
   strings:
      $s1 = "MPR.dll" fullword ascii
      $s2 = "-%08X" fullword ascii
      $api1 = {43 72 79 70 74 47 65 6E 52 61 6E 64 6F 6D 00 00 CA 00 43 72 79 70 74 49 6D 70 6F 72 74 4B 65 79 00 00 BA 00 43 72 79 70 74 45 6E 63 72 79 70 74}
      $api2 = {B7 00 43 72 79 70 74 44 65 73 74 72 6F 79 4B 65 79 00 B4 00 43 72 79 70 74 44 65 63 72 79 70 74 00 00 B1 00 43 72 79 70 74 41 63 71 75 69 72 65 43 6F 6E 74 65 78 74 57}
      $api3 = {10 00 57 4E 65 74 43 6C 6F 73 65 45 6E 75 6D 00 3D 00 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 1C 00 57 4E 65 74 45 6E 75 6D 52 65 73 6F 75 72 63 65 57 00 4D 50 52 2E 64 6C 6C}
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      3 of them
}

rule Makop_Ransomware_2 {
   meta:
      description= "Detect the risk of Ransomware Makop Rule 5"
      hash1 = "082a2ce2dde8b3a50f2d499496879e85562ee949cb151c8052eaaa713cddd0f8"
   strings:
      $s1 = "CryptSetKeyParam" fullword ascii
      $s2 = "CryptImportKey" fullword ascii
      $opcode1 = {8B 44 24 08 8B 0E 57 6A 00 6A 00 6A 2C 50 51 FF 15 [4] 85 C0 75 0C}
      $opcode2 = {6A 00 52 6A 01 50 FF 15 [4] 85 C0}
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}
