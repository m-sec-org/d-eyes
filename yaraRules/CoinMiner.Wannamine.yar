rule RULE_ETERNALBLUE_GENERIC_SHELLCODE
{
   meta:
      description = "Detect the risk of Wannamine Rule 1"
      detail = "Detecta una shellcode genérica de EternalBlue, con payload variable"
   strings:
      $sc = { 31 c0 40 0f 84 ?? ?? ?? ?? 60 e8 00 00 00 00 5b e8 23 00 00 00 b9
      76 01 00 00 0f 32 8d 7b 39 39 }
   condition:
      all of them
}

rule RULE_XMRIG
{
   meta:
      description = "Detect the risk of Wannamine Rule 2"
      detail = "Minero XMRig WannaMine"
   strings:
      $xmrig = "xmrig"
      $randomx = "randomx"
   condition:
      uint16(0) == 0x5A4D and
      all of them
}

rule CoinMiner_WannaMine_Opcodes
{
   meta:
      description = "Detect the risk of Wannamine Rule 3"
   strings:
      $s1 = {558BEC83EC10A05BE241008B550C8BCA}
      $s2 = {8B45008954243C03D081FAA00500000F}
      $s3 = {558BEC6AFF68786F410064A100000000}
   condition:
      uint16(0) == 0x5a4d and all of them
 }