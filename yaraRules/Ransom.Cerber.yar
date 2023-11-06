rule cerber3{
meta:
  description= "Detect the risk of Ransomware Cerber Rule 1"
strings:
  $a = {00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 03 6A  01 8B 85}
  $b = {68 3B DB 00 00 ?? ?? ?? ?? 00 ?? FF 15}
  
condition:
  1 of them 
}


rule cerber4{
meta:
  description= "Detect the risk of Ransomware Cerber Rule 2"
strings:
        $a = {8B 0D ?? ?? 43 00 51 8B 15 ?? ?? 43 00 52 E8 C9 04 00 00 83 C4 08 89 45 FC A1 ?? ?? 43 00 3B 05 ?? ?? 43 00 72 02}

condition:
        1 of them 
}


rule cerber5{
meta:
  description= "Detect the risk of Ransomware Cerber Rule 3"
strings:
  $a = {83 C4 04 A3 ?? ?? ?? 00 C7 45 ?? ?? ?? ?? 00 8B ?? ?? C6 0? 56 8B ?? ?? 5? 68 ?? ?? 4? 00 FF 15 ?? ?? 4? 00 50 FF 15 ?? ?? 4? 00 A3 ?? ?? 4? 00 68 1D 10 00 00 E8 ?? ?? FF FF 83 C4 04 ?? ?? ??}
  
condition:
  1 of them 
}


rule cerber5b{
meta:
  description= "Detect the risk of Ransomware Cerber Rule 4"
strings:
  $a={8B ?? ?8 ?? 4? 00 83 E? 02 89 ?? ?8 ?? 4? 00 68 ?C ?9 4? 00 [0-6] ?? ?? ?? ?? ?? ?8 ?? 4? 00 5? FF 15 ?? ?9 4? 00 89 45 ?4 83 7D ?4 00 75 02 EB 12 8B ?? ?0 83 C? 06 89 ?? ?0 B? DD 03 00 00 85}  
condition:
  $a
}

rule win_cerber_auto {

    meta:
       description= "Detect the risk of Ransomware Cerber Rule 5"

    strings:
        $sequence_0 = { eba0 47 3bf8 0f8c3effffff 5e 5b 5f }
            // n = 7, score = 1200
            //   eba0                 | jmp                 0xffffffa2
            //   47                   | inc                 edi
            //   3bf8                 | cmp                 edi, eax
            //   0f8c3effffff         | jl                  0xffffff44
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_1 = { ff750c e8???????? 59 59 84c0 74e9 8d45f8 }
            // n = 7, score = 1200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   74e9                 | je                  0xffffffeb
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_2 = { 8b4510 c6040200 4a 79f6 }
            // n = 4, score = 1200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   c6040200             | mov                 byte ptr [edx + eax], 0
            //   4a                   | dec                 edx
            //   79f6                 | jns                 0xfffffff8

        $sequence_3 = { 237878 899804010000 8b5864 23de 8b75fc }
            // n = 5, score = 1200
            //   237878               | and                 edi, dword ptr [eax + 0x78]
            //   899804010000         | mov                 dword ptr [eax + 0x104], ebx
            //   8b5864               | mov                 ebx, dword ptr [eax + 0x64]
            //   23de                 | and                 ebx, esi
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]

        $sequence_4 = { 6a00 ff36 ff15???????? bf02010000 3bc7 7561 }
            // n = 6, score = 1200
            //   6a00                 | push                0
            //   ff36                 | push                dword ptr [esi]
            //   ff15????????         |                     
            //   bf02010000           | mov                 edi, 0x102
            //   3bc7                 | cmp                 eax, edi
            //   7561                 | jne                 0x63

        $sequence_5 = { 7508 6a03 58 e9???????? 39860c010000 }
            // n = 5, score = 1200
            //   7508                 | jne                 0xa
            //   6a03                 | push                3
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   39860c010000         | cmp                 dword ptr [esi + 0x10c], eax

        $sequence_6 = { 75d9 8b45f8 5f 5e 5b c9 c3 }
            // n = 7, score = 1200
            //   75d9                 | jne                 0xffffffdb
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_7 = { 51 8d843078030000 50 e8???????? eb1d }
            // n = 5, score = 1200
            //   51                   | push                ecx
            //   8d843078030000       | lea                 eax, [eax + esi + 0x378]
            //   50                   | push                eax
            //   e8????????           |                     
            //   eb1d                 | jmp                 0x1f

    condition:
        7 of them and filesize < 573440
}

rule Ransom_Cerber {
   meta:
      description= "Detect the risk of Ransomware Cerber Rule 6"
   strings:
      $s0 = {558BEC83EC0C8B45088945FC8B4D0C89}
      $s1 = {8B45AB2603A9D1CBF8490724599ADA8F}
   condition:
      uint16(0) == 0x5a4d and all of them
 }
 