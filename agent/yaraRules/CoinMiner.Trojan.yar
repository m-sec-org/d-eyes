import "pe"
rule CoinMiner01 {
    meta:
        description = "Detects the risk of CoinMiner Trojan rule 1"
        detail = "Detects coinminer payload"
    strings:
        $s1 = "-o pool." ascii wide
        $s2 = "--cpu-max-threads-hint" ascii wide
        $s3 = "-P stratum" ascii wide
        $s4 = "--farm-retries" ascii wide
        $dl = "github.com/ethereum-mining/ethminer/releases/download" ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or ($dl))
}

rule win_coinminer_auto {

    meta:
        description = "Detects the risk of CoinMiner Trojan rule 2"
    strings:
        $sequence_0 = { 56 85c0 7511 e8???????? 83c404 32c0 5e }
            // n = 7, score = 100
            //   56                   | push                esi
            //   85c0                 | test                eax, eax
            //   7511                 | jne                 0x13
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   32c0                 | xor                 al, al
            //   5e                   | pop                 esi

        $sequence_1 = { e8???????? 8d8c24500b0000 8bf0 e8???????? }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d8c24500b0000       | lea                 ecx, [esp + 0xb50]
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

        $sequence_2 = { 09c0 744a 8b5f04 48 8d8c3000700800 48 }
            // n = 6, score = 100
            //   09c0                 | or                  eax, eax
            //   744a                 | je                  0x4c
            //   8b5f04               | mov                 ebx, dword ptr [edi + 4]
            //   48                   | dec                 eax
            //   8d8c3000700800       | lea                 ecx, [eax + esi + 0x87000]
            //   48                   | dec                 eax

        $sequence_3 = { 8bf1 8b0d???????? 85ff 7527 85c9 7523 e8???????? }
            // n = 7, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   8b0d????????         |                     
            //   85ff                 | test                edi, edi
            //   7527                 | jne                 0x29
            //   85c9                 | test                ecx, ecx
            //   7523                 | jne                 0x25
            //   e8????????           |                     

        $sequence_4 = { 8bcb e8???????? 57 ff15???????? 5f b001 5b }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx

        $sequence_5 = { f30f6f05???????? 56 57 f30f7f442440 b920000000 be???????? f30f6f05???????? }
            // n = 7, score = 100
            //   f30f6f05????????     |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   f30f7f442440         | movdqu              xmmword ptr [esp + 0x40], xmm0
            //   b920000000           | mov                 ecx, 0x20
            //   be????????           |                     
            //   f30f6f05????????     |                     

        $sequence_6 = { 756e 56 e8???????? 83c404 33c0 5f }
            // n = 6, score = 100
            //   756e                 | jne                 0x70
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi

        $sequence_7 = { 6b45e430 8945e0 8d8098589000 8945e4 803800 8bc8 7435 }
            // n = 7, score = 100
            //   6b45e430             | imul                eax, dword ptr [ebp - 0x1c], 0x30
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8d8098589000         | lea                 eax, [eax + 0x905898]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   803800               | cmp                 byte ptr [eax], 0
            //   8bc8                 | mov                 ecx, eax
            //   7435                 | je                  0x37

        $sequence_8 = { 7314 33c0 8974241c 85f6 }
            // n = 4, score = 100
            //   7314                 | jae                 0x16
            //   33c0                 | xor                 eax, eax
            //   8974241c             | mov                 dword ptr [esp + 0x1c], esi
            //   85f6                 | test                esi, esi

        $sequence_9 = { 83c102 ebe2 8d8df8fdffff b8???????? 90 668b10 }
            // n = 6, score = 100
            //   83c102               | add                 ecx, 2
            //   ebe2                 | jmp                 0xffffffe4
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]
            //   b8????????           |                     
            //   90                   | nop                 
            //   668b10               | mov                 dx, word ptr [eax]

    condition:
        7 of them and filesize < 1523712
}

rule CoinMiner_imphash {
    meta:
        description = "Detects the risk of CoinMiner Trojan rule 3"
	condition:
		pe.imphash() == "563557d99523e4b1f8aab2eb9b79285e"
}

rule Trojan_CoinMiner {
   meta:
      description = "Detects the risk of CoinMiner Trojan rule 4"
      hash1 = "3bdac08131ba5138bcb5abaf781d6dc7421272ce926bc37fa27ca3eeddcec3c2"
      hash2 = "d60766c4e6e77de0818e59f687810f54a4e08505561a6bcc93c4180adb0f67e7"
   strings:
      $seq0 = { df 75 ab 7b 80 bf 83 c1 48 b3 18 74 70 01 24 5c }
      $seq1 = { 08 37 4e 6e 0f 50 0b 11 d0 98 0f a8 b8 27 47 4e }
      $seq2 = { bf 17 5a 08 09 ab 80 2f a1 b0 b1 da 47 9f e1 61 }
      $seq3 = { 53 36 34 b2 94 01 cc 05 8c 36 aa 8a 07 ff 06 1f }
      $seq4 = { 25 30 ae c4 44 d1 97 82 a5 06 05 63 07 02 28 3a }
      $seq5 = { 01 69 8e 1c 39 7b 11 56 38 0f 43 c8 5f a8 62 d0 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "e4290fa6afc89d56616f34ebbd0b1f2c" and 3 of ($seq*)
      ) 
}