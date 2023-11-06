rule Ransom_BadEncript {
   meta:
      description= "Detect the risk of Ransomware BadEncript Rule 1"
      hash1 = "3bba4636606843da8e3591682b4433bdc94085a1939bbdc35f10bbfd97ac3d3d"
   strings:
      $x1 = "c:\\users\\nikitos\\documents\\visual studio 2015\\Projects\\BadEncriptMBR\\Release\\BadEncriptMBR.pdb" fullword ascii
      $s2 = "DoctorPetrovic.org" fullword wide
      $s3 = "oh lol it failed" fullword ascii
      $s4 = "Allows DoctorPetrovic Scanner" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      (any of ($x*) or 2 of them)
}

rule win_badencript_auto {

    meta:
        description= "Detect the risk of Ransomware BadEncript Rule 2"

    strings:
        $sequence_0 = { 8bc1 83e13f c1f806 6bc930 8b048548414100 0fb6440828 }
            // n = 6, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   83e13f               | and                 ecx, 0x3f
            //   c1f806               | sar                 eax, 6
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048548414100       | mov                 eax, dword ptr [eax*4 + 0x414148]
            //   0fb6440828           | movzx               eax, byte ptr [eax + ecx + 0x28]

        $sequence_1 = { 8d7f08 8b048d04b54000 ffe0 f7c703000000 7413 8a06 8807 }
            // n = 7, score = 100
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d04b54000       | mov                 eax, dword ptr [ecx*4 + 0x40b504]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3
            //   7413                 | je                  0x15
            //   8a06                 | mov                 al, byte ptr [esi]
            //   8807                 | mov                 byte ptr [edi], al

        $sequence_2 = { 83c8ff eb07 8b04cdecfd4000 5f 5e 5b 8be5 }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb07                 | jmp                 9
            //   8b04cdecfd4000       | mov                 eax, dword ptr [ecx*8 + 0x40fdec]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_3 = { 83e03f c1f906 6bc030 03048d48414100 }
            // n = 4, score = 100
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bc030               | imul                eax, eax, 0x30
            //   03048d48414100       | add                 eax, dword ptr [ecx*4 + 0x414148]

        $sequence_4 = { 8b049548414100 804c182d04 ff4604 eb08 ff15???????? }
            // n = 5, score = 100
            //   8b049548414100       | mov                 eax, dword ptr [edx*4 + 0x414148]
            //   804c182d04           | or                  byte ptr [eax + ebx + 0x2d], 4
            //   ff4604               | inc                 dword ptr [esi + 4]
            //   eb08                 | jmp                 0xa
            //   ff15????????         |                     

        $sequence_5 = { 8b1c9d68d14000 56 6800080000 6a00 53 ff15???????? 8bf0 }
            // n = 7, score = 100
            //   8b1c9d68d14000       | mov                 ebx, dword ptr [ebx*4 + 0x40d168]
            //   56                   | push                esi
            //   6800080000           | push                0x800
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { 6a00 6a03 6a00 6a04 6800000010 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6800000010           | push                0x10000000

        $sequence_7 = { 33c0 3b0cc520db4000 7427 40 83f82d 72f1 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   3b0cc520db4000       | cmp                 ecx, dword ptr [eax*8 + 0x40db20]
            //   7427                 | je                  0x29
            //   40                   | inc                 eax
            //   83f82d               | cmp                 eax, 0x2d
            //   72f1                 | jb                  0xfffffff3

        $sequence_8 = { c1fa06 8bc6 83e03f 6bc830 8b049548414100 f644082801 }
            // n = 6, score = 100
            //   c1fa06               | sar                 edx, 6
            //   8bc6                 | mov                 eax, esi
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049548414100       | mov                 eax, dword ptr [edx*4 + 0x414148]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1

        $sequence_9 = { 8bc8 d1f9 6a41 5f 894df0 8b34cde8fd4000 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   d1f9                 | sar                 ecx, 1
            //   6a41                 | push                0x41
            //   5f                   | pop                 edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b34cde8fd4000       | mov                 esi, dword ptr [ecx*8 + 0x40fde8]

    condition:
        7 of them and filesize < 335872
}
