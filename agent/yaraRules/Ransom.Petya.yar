rule win_petya_auto {

    meta:
        description= "Detect the risk of Ransomware Petya Rule 1"
    strings:
        $sequence_0 = { 8d4e28 e8???????? 8d4e4c e8???????? }
            // n = 4, score = 600
            //   8d4e28               | lea                 ecx, [esi + 0x28]
            //   e8????????           |                     
            //   8d4e4c               | lea                 ecx, [esi + 0x4c]
            //   e8????????           |                     

        $sequence_1 = { 8bc6 c1e810 88442429 8bc6 c1e808 8844242a }
            // n = 6, score = 600
            //   8bc6                 | mov                 eax, esi
            //   c1e810               | shr                 eax, 0x10
            //   88442429             | mov                 byte ptr [esp + 0x29], al
            //   8bc6                 | mov                 eax, esi
            //   c1e808               | shr                 eax, 8
            //   8844242a             | mov                 byte ptr [esp + 0x2a], al

        $sequence_2 = { 0f42f2 6a04 56 e8???????? 8bd8 }
            // n = 5, score = 600
            //   0f42f2               | cmovb               esi, edx
            //   6a04                 | push                4
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { 6a04 6a20 c705????????20000000 e8???????? }
            // n = 4, score = 600
            //   6a04                 | push                4
            //   6a20                 | push                0x20
            //   c705????????20000000     |     
            //   e8????????           |                     

        $sequence_4 = { 51 83c050 03c7 53 50 e8???????? }
            // n = 6, score = 600
            //   51                   | push                ecx
            //   83c050               | add                 eax, 0x50
            //   03c7                 | add                 eax, edi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { e8???????? 8d4e10 e8???????? 8d4e1c e8???????? 8d4e28 e8???????? }
            // n = 7, score = 600
            //   e8????????           |                     
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   e8????????           |                     
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   e8????????           |                     
            //   8d4e28               | lea                 ecx, [esi + 0x28]
            //   e8????????           |                     

        $sequence_6 = { c7461001000000 33c0 5e 8be5 }
            // n = 4, score = 600
            //   c7461001000000       | mov                 dword ptr [esi + 0x10], 1
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp

        $sequence_7 = { 8bda c1e60e c1e017 33ff 0bf9 c1eb09 8b4c2424 }
            // n = 7, score = 600
            //   8bda                 | mov                 ebx, edx
            //   c1e60e               | shl                 esi, 0xe
            //   c1e017               | shl                 eax, 0x17
            //   33ff                 | xor                 edi, edi
            //   0bf9                 | or                  edi, ecx
            //   c1eb09               | shr                 ebx, 9
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]

        $sequence_8 = { 7617 53 33db 8b4e74 03cb }
            // n = 5, score = 600
            //   7617                 | jbe                 0x19
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   8b4e74               | mov                 ecx, dword ptr [esi + 0x74]
            //   03cb                 | add                 ecx, ebx

        $sequence_9 = { 8d4e10 e8???????? 8d4e1c e8???????? 8d4e28 e8???????? }
            // n = 6, score = 600
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   e8????????           |                     
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   e8????????           |                     
            //   8d4e28               | lea                 ecx, [esi + 0x28]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 229376
}

rule win_eternal_petya_auto {

    meta:
       description= "Detect the risk of Ransomware Petya Rule 2"
    strings:
        $sequence_0 = { 8bec 51 57 68000000f0 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   57                   | push                edi
            //   68000000f0           | push                0xf0000000

        $sequence_1 = { 68f0000000 6a40 ff15???????? 8bd8 }
            // n = 4, score = 400
            //   68f0000000           | push                0xf0
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_2 = { 57 68000000f0 6a18 33ff }
            // n = 4, score = 400
            //   57                   | push                edi
            //   68000000f0           | push                0xf0000000
            //   6a18                 | push                0x18
            //   33ff                 | xor                 edi, edi

        $sequence_3 = { 53 8d4644 50 53 6a02 }
            // n = 5, score = 400
            //   53                   | push                ebx
            //   8d4644               | lea                 eax, [esi + 0x44]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   6a02                 | push                2

        $sequence_4 = { 40 49 75f9 56 ff15???????? }
            // n = 5, score = 400
            //   40                   | inc                 eax
            //   49                   | dec                 ecx
            //   75f9                 | jne                 0xfffffffb
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_5 = { 53 6a21 8d460c 50 }
            // n = 4, score = 400
            //   53                   | push                ebx
            //   6a21                 | push                0x21
            //   8d460c               | lea                 eax, [esi + 0xc]
            //   50                   | push                eax

        $sequence_6 = { 50 8d8594f9ffff 50 894dac }
            // n = 4, score = 300
            //   50                   | push                eax
            //   8d8594f9ffff         | lea                 eax, [ebp - 0x66c]
            //   50                   | push                eax
            //   894dac               | mov                 dword ptr [ebp - 0x54], ecx

        $sequence_7 = { ff75f8 8945fc ff15???????? 56 56 6a02 56 }
            // n = 7, score = 300
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff15????????         |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a02                 | push                2
            //   56                   | push                esi

        $sequence_8 = { ff7608 03c1 50 ff15???????? }
            // n = 4, score = 300
            //   ff7608               | push                dword ptr [esi + 8]
            //   03c1                 | add                 eax, ecx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_9 = { 0fb7044a 6685c0 7412 0fb7444584 66890c47 0fb7044a 66ff444584 }
            // n = 7, score = 300
            //   0fb7044a             | movzx               eax, word ptr [edx + ecx*2]
            //   6685c0               | test                ax, ax
            //   7412                 | je                  0x14
            //   0fb7444584           | movzx               eax, word ptr [ebp + eax*2 - 0x7c]
            //   66890c47             | mov                 word ptr [edi + eax*2], cx
            //   0fb7044a             | movzx               eax, word ptr [edx + ecx*2]
            //   66ff444584           | inc                 word ptr [ebp + eax*2 - 0x7c]

        $sequence_10 = { 83e001 89412c 8b4320 c7403001000000 }
            // n = 4, score = 300
            //   83e001               | and                 eax, 1
            //   89412c               | mov                 dword ptr [ecx + 0x2c], eax
            //   8b4320               | mov                 eax, dword ptr [ebx + 0x20]
            //   c7403001000000       | mov                 dword ptr [eax + 0x30], 1

        $sequence_11 = { 8b4d0c 0fb71441 8955f0 3bd3 0f862fffffff 8b45cc }
            // n = 6, score = 300
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   0fb71441             | movzx               edx, word ptr [ecx + eax*2]
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   3bd3                 | cmp                 edx, ebx
            //   0f862fffffff         | jbe                 0xffffff35
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]

        $sequence_12 = { 2bc1 d1f8 8d440002 50 6a08 ffd6 50 }
            // n = 7, score = 300
            //   2bc1                 | sub                 eax, ecx
            //   d1f8                 | sar                 eax, 1
            //   8d440002             | lea                 eax, [eax + eax + 2]
            //   50                   | push                eax
            //   6a08                 | push                8
            //   ffd6                 | call                esi
            //   50                   | push                eax

        $sequence_13 = { 83e001 894304 8bc2 83e003 83e800 }
            // n = 5, score = 300
            //   83e001               | and                 eax, 1
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   8bc2                 | mov                 eax, edx
            //   83e003               | and                 eax, 3
            //   83e800               | sub                 eax, 0

        $sequence_14 = { 75f5 2bcf d1f9 8d1409 8bce 85d2 }
            // n = 6, score = 200
            //   75f5                 | jne                 0xfffffff7
            //   2bcf                 | sub                 ecx, edi
            //   d1f9                 | sar                 ecx, 1
            //   8d1409               | lea                 edx, [ecx + ecx]
            //   8bce                 | mov                 ecx, esi
            //   85d2                 | test                edx, edx

        $sequence_15 = { 50 ffd6 85c0 0f8480000000 8b95f4fdffff 8d8df8fdffff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f8480000000         | je                  0x86
            //   8b95f4fdffff         | mov                 edx, dword ptr [ebp - 0x20c]
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]

    condition:
        7 of them and filesize < 851968
}

rule win_eternal_petya_w0 {

    meta:
      description= "Detect the risk of Ransomware Petya Rule 3"
    strings:
        $encrypt_file = { 55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 8B 4F ?? 33 DB 8D 45 ?? 50 53 53 51 89 5D ?? 89  5D ?? 89 5D ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 55 ?? 53 53 6A ?? 53 53  68 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 8D  4D ?? 51 57 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 39 5D ?? 0F 84 ??  ?? ?? ?? 39 5D ?? 0F 84 ?? ?? ?? ?? 8D 55 ?? 52 56 FF 15 ?? ?? ?? ?? 8B 4F ?? 8B 45  ?? 83 C1 ?? 2B C1 19 5D ?? 89 45 ?? 89 5D ?? 78 ?? 7F ?? 3D ?? ?? ?? ?? 76 ?? B8 ??  ?? ?? ?? EB ?? C7 45 ?? ?? ?? ?? ?? 53 50 53 6A ?? 53 8B F8 56 89 45 ?? 89 7D ?? FF  15 ?? ?? ?? ?? 8B D8 85 DB 74 ?? 8B 55 ?? 52 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ??  8B F8 85 FF 74 ?? 8B 4D ?? 8B 55 ?? 8D 45 ?? 50 57 6A ?? 51 6A ?? 52 FF 15 ?? ?? ??  ?? 85 C0 74 ?? 8B 45 ?? 50 57 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 68 ?? ?? ?? ?? E8 ?? ??  ?? ?? 83 C4 ?? 57 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 7D ?? 8B 45 ?? 3B C7 73  ?? 2B F8 EB ?? 33 FF 8B 55 ?? 8B 42 ?? 8D 4C 38 ?? 6A ?? 51 E8 ?? ?? ?? ?? 8B 7D ??  83 C4 ?? 33 DB 56 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 39 5D ?? 74 ?? 39  5D ?? 75 ?? 8B 47 ?? 8B 35 ?? ?? ?? ?? 50 FF D6 8B 7F ?? 3B FB 74 ?? 57 FF D6 5F 5E  5B 8B E5 5D C3 }

        $main_encrypt = { 55 8B EC 56 6A ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 75 ?? 89 46 ?? 85 C0 0F 84  ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 7E ?? 57 FF  D3 85 C0 75 ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 6A ?? 6A ?? 6A ?? 6A ?? 57 FF  D3 85 C0 74 ?? 8B 07 8D 5E ?? 53 50 8B 46 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B  C6 E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 56 8D 4E ?? 6A ?? 51 E8 ??  ?? ?? ?? 8B 56 ?? 83 C4 ?? 52 FF 15 ?? ?? ?? ?? 8B 46 ?? 50 FF 15 ?? ?? ?? ?? 8B 0B  51 FF 15 ?? ?? ?? ?? 8B 17 6A ?? 52 FF 15 ?? ?? ?? ?? 8B 46 ?? 50 FF 15 ?? ?? ?? ??  5F 5B B9 ?? ?? ?? ?? 8D 46 ?? 8B FF C6 00 ?? 40 49 75 ?? 56 FF 15 ?? ?? ?? ?? 33 C0  5E 5D C2 ?? ?? }

        $encryption_loop = { 8B 7C 24 ?? 6A ?? 6A ?? 8D 43 ?? 50 33 C0 39 43 ?? 0F 95 C0 40 50 FF 15 ?? ?? ?? ??  85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? B9 ??  ?? ?? ?? 8D 44 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ??  75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 85 C0 0F 84 ?? ??  ?? ?? B9 ?? ?? ?? ?? 8D 44 24 ?? 8D 64 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ??  66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83  D8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? 51 57 8D 94 24 ?? ?? ?? ?? 52 FF 15 ?? ??  ?? ?? 85 C0 74 ?? 8B 44 24 ?? A8 ?? 74 ?? A9 ?? ?? ?? ?? 75 ?? 8D BC 24 ?? ?? ?? ??  E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 45 ?? 53 48 50 8B CF 51 E8 ?? ?? ?? ?? 83 C4 ?? EB ??  8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 8D 4C 24 ?? 8D 71 ?? 90 66 8B 11 83 C1 ?? 66 85 D2  75 ?? 2B CE D1 F9 8D 4C 4C ?? 3B C1 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D  94 24 ?? ?? ?? ?? 53 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 74 24 ?? 8D 44 24 ?? 50 56 FF 15  ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ??}

    condition:
        $encrypt_file and $main_encrypt and $encryption_loop 
}

rule Petya_Ransomware {
	meta:
		description= "Detect the risk of Ransomware Petya Rule 4"
		hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
	strings:
		$a1 = "<description>WinRAR SFX module</description>" fullword ascii

		$s1 = "BX-Proxy-Manual-Auth" fullword wide
		$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s3 = "X-HTTP-Attempts" fullword wide
		$s4 = "@CommandLineMode" fullword wide
		$s5 = "X-Retry-After" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and $a1 and 3 of ($s*)
}

rule Ransom_Petya {
meta:
   description= "Detect the risk of Ransomware Petya Rule 5"
strings:
    $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
    $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
    $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
condition:
    all of them
}
