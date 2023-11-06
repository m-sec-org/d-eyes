import "pe"
import "hash"
rule Sodinokibi_Loader{

    meta:
        description = "Detect the risk of Ransomware Sodinokibi Rule 1"
        maltype = "Ransomware"

    strings:
        $string1 = "function Invoke-" nocase
        $string2 = "$ForceASLR" nocase
        $string3 = "$DoNotZeroMZ" nocase
        $string4 = "$RemoteScriptBlock" nocase
        $string5 = "$TypeBuilder" nocase
        $string6 = "$Win32Constants" nocase
        $string7 = "$OpenProcess" nocase
        $string8 = "$WaitForSingleObject" nocase
        $string9 = "$WriteProcessMemory" nocase
        $string10 = "$ReadProcessMemory" nocase
        $string11 = "$CreateRemoteThread" nocase
        $string12 = "$OpenThreadToken" nocase
        $string13 = "$AdjustTokenPrivileges" nocase
        $string14 = "$LookupPrivilegeValue" nocase
        $string15 = "$ImpersonateSelf" nocase
        $string16 = "-SignedIntAsUnsigned" nocase
        $string17 = "Get-Win32Types" nocase
        $string18 = "Get-Win32Functions" nocase
        $string19 = "Write-BytesToMemory" nocase
        $string20 = "Get-ProcAddress" nocase
        $string21 = "Enable-SeDebugPrivilege" nocase
        $string22 = "Get-ImageNtHeaders" nocase
        $string23 = "Get-PEBasicInfo" nocase
        $string24 = "Get-PEDetailedInfo" nocase
        $string25 = "Import-DllInRemoteProcess" nocase
        $string26 = "Get-RemoteProcAddress" nocase
        $string27 = "Update-MemoryAddresses" nocase
        $string28 = "Import-DllImports" nocase
        $string29 = "Get-VirtualProtectValue" nocase
        $string30 = "Update-MemoryProtectionFlags" nocase
        $string31 = "Update-ExeFunctions" nocase
        $string32 = "Copy-ArrayOfMemAddresses" nocase
        $string33 = "Get-MemoryProcAddress" nocase
        $string34 = "Invoke-MemoryLoadLibrary" nocase
        $string35 = "Invoke-MemoryFreeLibrary" nocase
        $string36 = "$PEBytes32" nocase
        $string37 = "TVqQAA"
        $string38 = "FromBase64String" nocase

    condition:
	uint16(0) == 0x5a4d and 30 of ($string*)

}

rule ransomware_sodinokibi {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 2"
      detail = "Using a recently disclosed vulnerability in Oracle WebLogic, criminals use it to install a new variant of ransomware called “Sodinokibi"
      hash4 = "9b62f917afa1c1a61e3be0978c8692dac797dd67ce0e5fd2305cc7c6b5fef392"

   strings:
      $x1 = "sodinokibi.exe" fullword wide
      $y0 = { 8d 85 6c ff ff ff 50 53 50 e8 62 82 00 00 83 c4 }
      $y1 = { e8 24 ea ff ff ff 75 08 8b ce e8 61 fc ff ff 8b }
      $y2 = { e8 01 64 ff ff ff b6 b0 }

   condition:

      ( uint16(0) == 0x5a4d and 
      filesize < 900KB and 
      pe.imphash() == "672b84df309666b9d7d2bc8cc058e4c2" and 
      ( 8 of them ) and 
      all of ($y*)) or 
      ( all of them )
}

rule Sodinokobi
{
    meta:
        description = "Detect the risk of Ransomware Sodinokibi Rule 3"
        detail = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
    strings:
        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}
rule win_revil_auto {

    meta:
        description = "Detect the risk of Ransomware Sodinokibi Rule 4"
    strings:
        $sequence_0 = { 8bb694000000 0fa4da0f c1e911 0bc2 c1e30f 8b5508 0bcb }
            // n = 7, score = 4200
            //   8bb694000000         | mov                 esi, dword ptr [esi + 0x94]
            //   0fa4da0f             | shld                edx, ebx, 0xf
            //   c1e911               | shr                 ecx, 0x11
            //   0bc2                 | or                  eax, edx
            //   c1e30f               | shl                 ebx, 0xf
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0bcb                 | or                  ecx, ebx

        $sequence_1 = { 2345e4 33c7 898bb8000000 8b4de0 8983bc000000 f7d1 }
            // n = 6, score = 4200
            //   2345e4               | and                 eax, dword ptr [ebp - 0x1c]
            //   33c7                 | xor                 eax, edi
            //   898bb8000000         | mov                 dword ptr [ebx + 0xb8], ecx
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8983bc000000         | mov                 dword ptr [ebx + 0xbc], eax
            //   f7d1                 | not                 ecx

        $sequence_2 = { 8b9f90000000 8bb788000000 8b978c000000 8945e0 8b477c 8945e4 8b8784000000 }
            // n = 7, score = 4200
            //   8b9f90000000         | mov                 ebx, dword ptr [edi + 0x90]
            //   8bb788000000         | mov                 esi, dword ptr [edi + 0x88]
            //   8b978c000000         | mov                 edx, dword ptr [edi + 0x8c]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b477c               | mov                 eax, dword ptr [edi + 0x7c]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b8784000000         | mov                 eax, dword ptr [edi + 0x84]

        $sequence_3 = { 50 51 e8???????? 894608 59 59 85c0 }
            // n = 7, score = 4200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_4 = { 6802020000 e8???????? 8bf0 59 }
            // n = 4, score = 4200
            //   6802020000           | push                0x202
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_5 = { 55 8bec 83ec10 8d45f0 50 6a0c }
            // n = 6, score = 4200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   6a0c                 | push                0xc

        $sequence_6 = { 897df8 83f803 7cca 8b4508 5f 5e }
            // n = 6, score = 4200
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   83f803               | cmp                 eax, 3
            //   7cca                 | jl                  0xffffffcc
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 57 8b7d0c 6685c9 742e 0fb71f 8bd7 6685db }
            // n = 7, score = 4200
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   6685c9               | test                cx, cx
            //   742e                 | je                  0x30
            //   0fb71f               | movzx               ebx, word ptr [edi]
            //   8bd7                 | mov                 edx, edi
            //   6685db               | test                bx, bx

        $sequence_8 = { 56 57 8b7d08 33f6 397708 7621 8b470c }
            // n = 7, score = 4200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   33f6                 | xor                 esi, esi
            //   397708               | cmp                 dword ptr [edi + 8], esi
            //   7621                 | jbe                 0x23
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]

        $sequence_9 = { ebca 6b45fc0c 8b4d0c 52 ff540808 59 85c0 }
            // n = 7, score = 4200
            //   ebca                 | jmp                 0xffffffcc
            //   6b45fc0c             | imul                eax, dword ptr [ebp - 4], 0xc
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   ff540808             | call                dword ptr [eax + ecx + 8]
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 155794432
}

rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 4"
      detail = "Detects REvil/Sodinokibi ransomware"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}

rule Ransom_Sodinokibi {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 5"
   strings:
      $s1 = "2!2&2>2K2R2Z2_2d2i2"
      $s2 = "ERR0R D0UBLE RUN!"
      $s3 = "4!5&575?5R5Z5~5"
      $s4 = "344<4E4Z4f4p4x4"
      $s5 = "?%?+?1?7?=?K?_?"
      $s6 = "DTrump4ever"
      $s7 = "3N,3NT3N|3"
      $s8 = {65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65}
      $s9 = {76 00 6D 00 63 00 6F 00 6D 00 70 00 75 00 74 00 65 00 2E 00 65 00 78 00 65}
      $s10 = {76 00 6D 00 6D 00 73 00 2E 00 65 00 78 00 65 00 00 00 00 00 76 00 6D 00 77 00 70 00 2E 00 65 00 78 00 65}
      $op1 = {55 8B EC 83 EC 10 B9 B5 04 00 00 53 56 8B 75 08 C1 E6 10 33 75 08 81 F6 CD 8E CD 99 8B C6 C1 E8 15 57 3B C1}
      $op2 = {55 8B EC 83 EC 44 56 8B 75 14 85 F6 0F 84 [4] 53 8B 5D 10 8D 4D BC 8B C3 2B C1 89 45 14}
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}

rule Ransom_Sodinokibi_2021_June {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 6"
   strings:
      $s1 = "ERR0R D0UBLE RUN!" fullword ascii
      $s2 = "DTrump4ever" fullword ascii
      $op3 = {558BEC83EC30568D45FCBE78124100506A036A10685B12000056E8375200}
      $op4 = {8B45088B4008A3D435410033C0405DC3558BEC8B45088B4008A3B4354100}
      $op5 = {558BEC5153568D45FC33F650E84E4000008BD85985DB74315733FF47397D}
      $op6 = {558BEC83EC0C894DF48B4DF4E80F0000008BE55DC3CCCCCCCCCCCCCCCCCC}
      $op7 = {8B45FCC700707543008B4DFCE8980800008BE55DC3CCCCCCCC558BEC5189}
      $op8 = {558BEC6AFF687867430064A100000000506489250000000083EC24894DD0}
      $op9 = {558BEC51894DFC8B45FCC700707543008B4DFCE8980800008BE55DC3CCCC}
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (2 of ($s*) or 2 of ($op*))
}

rule Ransom_Sodinokibi_Kaseya_supply_chain_attack {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 7"
   strings:
      $header = {4D 5A 90 00 03 00 00 00 04 00 00 00 
                 FF FF 00 00 B8 00 00 00 00 00 00 00 
                 40 00 00 00 00 00 00 00 00 00 00 00 
                 00 00 00 00 00 00 00 00 00 00 00 00 
                 00 00 00 00 00 00 00 00 00 00 00 00 
                 ?? ?? 00 00 0E 1F BA 0E 00 B4 09 CD 
                 21 B8 01 4C CD 21 54 68 69 73 20 70 
                 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 
                 74 20 62 65 20 72 75 6E 20 69 6E 20 
                 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 
                 24 00 00 00 00 00 00 00}
      $s1 = {64 68 4B 65 79 41 67 72 65 65 6D 65 6E 74 00 00 63 72 79 70 74 6F 70 72 6F 00 00 00 44 45 53 2D 45 43 42 00 63 72 79 70 74 6F 63 6F 6D 00 00 00 64 65 73 2D 65 63 62 00 69 64 2D 47 6F 73 74 52 33 34 31 31 2D 39 34 2D 77 69 74 68 2D 47 6F 73 74 52 33 34 31 30 2D 32 30 30 31 00 44 45 53 2D 43 46 42 00 47 4F 53 54 20 52 20 33 34 2E 31 31 2D 39 34 20 77 69 74 68 20 47 4F 53 54 20 52 20 33 34 2E 31 30 2D 32 30 30 31 00 00 64 65 73 2D 63 66 62}
      $s2 = {00 43 72 79 70 74 41 63 71 75 69 72 65 43 6F 6E 74 65 78 74 57 00 00 00 00 43 72 79 70 74 47 65 6E 52 61 6E 64 6F 6D 00 00 43 72 79 70 74 52 65 6C 65 61 73 65 43 6F 6E 74 65 78 74 00}
      $s3 = "MpSvc.dll" fullword ascii
      $s4 = {1F 42 72 6F 75 69 6C 6C 65 74 74 65 62 75 73 69 6E 65 73 73 40 6F 75 74 6C 6F 6F 6B 2E 63 6F 6D 30}
   condition:
      uint16(0) == 0x5a4d and $header at 0 and 3 of ($s*)
}

rule elf_REvil {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 8"
      detail = "detect the risk of elf REvil/Sodinokibi"
      hash1 = "3d375d0ead2b63168de86ca2649360d9dcff75b3e0ffa2cf1e50816ec92b3b7d"
      hash2 = "796800face046765bd79f267c56a6c93ee2800b76d7f38ad96e5acb92599fcd4"
      hash3 = "d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763"
      hash4 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
   strings:
      $s1 = "uname -a && echo \" | \" && hostname" fullword ascii
      $s2 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list | awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
      $s3 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list | awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
      $s4 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
      $s5 = "[%s] already encrypted" fullword ascii
      $s6 = "%d:%d: Comment not allowed here" fullword ascii
      $s7 = "json.txt" fullword ascii
      $s8 = "Error decoding user_id %d " fullword ascii
      $s9 = "Error read urandm line %d!" fullword ascii
      $s10 = "%d:%d: Unexpected EOF in block comment" fullword ascii
      $s11 = "%d:%d: Unexpected `%c` in comment opening sequence" fullword ascii
      $s12 = "File [%s] was encrypted" fullword ascii
      $s13 = "File [%s] was NOT encrypted" fullword ascii
      $s14 = "rand: try to read %hu but get %lu bytes" fullword ascii
      $s15 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
      $s16 = "Encrypting [%s]" fullword ascii
      $s17 = "Error decoding note_body %d " fullword ascii
      $s18 = "Error decoding sub_id %d " fullword ascii
      $s19 = "Error decoding master_pk %d " fullword ascii
      $s20 = "Error open urandm line %d!" fullword ascii
      $s21 = "%d:%d: EOF unexpected" fullword ascii
      $s22 = "fatal error malloc enc" fullword ascii
      $s23 = "iji iji iji iji ij|- - - - - -|ji iji ifi iji iji iji" fullword ascii
      $s24 = "iji iji iji iji ij| ENCRYPTED |ji iji ifi iji iji iji" fullword ascii
      $s25 = "Key inizialization error ... something wrong with config" fullword ascii
      $s26 = "ss kill --type=force --world-id=\" $1)}'" fullword ascii
      $s27 = "pkill -9 %s" fullword ascii
      $s28 = ".note.gnu.build-id" fullword ascii
      $s29 = "libpthread.so.0" fullword ascii
      $s30 = "File error " fullword ascii
      $s31 = "Path: %s " fullword ascii
      $s32 = "pthread_timedjoin_np" fullword ascii
      $s33 = "Error parse cfg" fullword ascii
      $s34 = "fatal error,master_pk size is bad %lu " fullword ascii
      $s35 = "[%s] is protected by os" fullword ascii
      $s36 = "n failurH" fullword ascii
      $s37 = ".eh_frame_hdr" fullword ascii
      $s38 = "fatal error, no cfg!" fullword ascii
      $s39 = "Error create note in dir %s" fullword ascii
      $s40 = "Error no json file!" fullword ascii
      $s41 = ".note.ABI-tag" fullword ascii
      $s42 = "--silent (-s) use for not stoping VMs mode" fullword ascii
      $x1 = "\",\"nname\":\"{EXT}-readme.txt\",\"rdmcnt\":" ascii
      $x2 = " without --path encrypts current dir" fullword ascii
   condition:
      ( uint16(0) == 0x457f and ( 8 of them and 1 of ($x*))
      ) or ( all of them )
}

rule APT_MAL_REvil_Kaseya_Jul21_1 {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 9"
      detail = "Detects malware used in the Kaseya supply chain attack"
      hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
      hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
      hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
      hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
   strings:
      $s1 = "Mpsvc.dll" wide fullword
      $s2 = ":0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:H<L<P<\\<`<" ascii fullword

      $op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
      $op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
      $op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
      $op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
      $op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      (
         pe.imphash() == "c36dcd2277c4a707a1a645d0f727542a" or
         2 of them
      )
}

rule APT_MAL_REvil_Kaseya_Jul21_2 {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 10"
      detail = "Detects malware used in the Kaseya supply chain attack"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
      hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
      hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }

      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and ( 2 of ($opa*) or 3 of them )
}

rule REvil_Decryptor {
   meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 11"
      detail = "Detects REvil's Decryptor/Sodinokibi"
   strings:
      $op1 = {558BEC833D4C0F410000568B7508750A837E0801}
      $op2 = {8B45088B4008A34C0F410033C0405DC3558BEC83}
      $op3 = {558BEC5153568D45FC33F650E8D51700008BD859}
      $op4 = {CCCCCCCCCCCCCCCCCCCCCCCC57565533FF33ED8B}
      $op5 = {8D8568FFFFFF50E8CE0700008D8568FFFFFF50E8}
      $x1 = {00 7B 22 61 6C 6C 22 3A 20 74 72 75 65 2C 20 22 6D 61 73 74 65 72 5F 73 6B 22 3A 20 22}
      $x2 = {22 2C 20 22 65 78 74 22 3A 20 5B}
   condition:
      uint16(0) == 0x5a4d and 2 of ($op*) and all of ($x*)
}
rule Sodinokibi_032021 {
    meta:
      description = "Detect the risk of Ransomware Sodinokibi Rule 12"
      detail = "Sodinokibi_032021: files - file DomainName.exe"
      hash1 = "2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c"
    strings:
      $s1 = "vmcompute.exe" fullword wide
      $s2 = "vmwp.exe" fullword wide
      $s3 = "bootcfg /raw /a /safeboot:network /id 1" fullword ascii
      $s4 = "bcdedit /set {current} safeboot network" fullword ascii
      $s5 = "7+a@P>:N:0!F$%I-6MBEFb M" fullword ascii
      $s6 = "jg:\"\\0=Z" fullword ascii
      $s7 = "ERR0R D0UBLE RUN!" fullword wide
      $s8 = "VVVVVPQ" fullword ascii
      $s9 = "VVVVVWQ" fullword ascii
      $s10 = "Running" fullword wide /* Goodware String - occured 159 times */
      $s11 = "expand 32-byte kexpand 16-byte k" fullword ascii
      $s12 = "9RFIT\"&" fullword ascii
      $s13 = "jZXVf9F" fullword ascii
      $s14 = "tCWWWhS=@" fullword ascii
      $s15 = "vmms.exe" fullword wide /* Goodware String - occured 1 times */
      $s16 = "JJwK9Zl" fullword ascii
      $s17 = "KkT37uf4nNh2PqUDwZqxcHUMVV3yBwSHO#K" fullword ascii
      $s18 = "0*090}0" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "5)5I5a5" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "7-7H7c7" fullword ascii /* Goodware String - occured 1 times */
    condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( pe.imphash() == "031931d2f2d921a9d906454d42f21be0" or 8 of them )
}

rule Sodinokibi_hash
{
   meta:
        description ="Detect the risk of Sodinokibi Rule 13"
   condition:
    hash.sha256(0,filesize) =="67c4d6f5844c2549e75b876cb32df8b22d2eae5611feeb37f9a2097d67cc623e"
}

