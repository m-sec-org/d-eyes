rule Gafgyt_Generic_Botnet {
	meta:
		description = "Detect the risk of Botnet Malware Gafgyt Rule 1"
		hash0 = "2a18f2d59f172622e76d9d9b5c73393b"
		hash1 = "06de2d19862494be7dbcbcf20b3dbe3a"
		hash2 = "0fc30a802a07386f5cd4b18b47547979"
		hash3 = "be6865ccb948f2937fd25fe465e434da"
		hash4 = "c8d58acfe524a09d4df7ffbe4a43c429"
		hash5 = "0f979b4ae1209020dd2b672f9dad7398"
		hash6 = "45826c129bf3d3bd067e33cf7bef3883"
		hash7 = "79b9d4cea7972951efad765406459f5e"
		hash8 = "baad702930571c414b0e8896f8bb4a5f"
		hash9 = "11754a20e705dccf96f1a1def7220efc"
		hash10 = "67db9ed04d3b56f966a739fd40a47748"
	strings:
		$s0 = "busybox" fullword
		$s1 = "PONG!" fullword
		$s2 = "GETLOCALIP" fullword
		$s3 = "HTTPFLOOD" fullword
		$s4 = "LUCKYLILDUDE" fullword
		$s5 = "/dev/null"
		$s6 = "/etc/resolv.conf"
		$s7 = "/etc/config/resolv.conf"
	condition:
		all of them
}

rule Gafgyt_July_1 {
   meta:
	  description = "Detect the risk of Botnet Malware Gafgyt Rule 2"
      hash1 = "041db2cf6eac2a47ae4651751158838104e502ff33dcc7f5dd48472789870e6c"
      hash2 = "0839b33e2da179eac610673769e9568d1942877739cf4d990f3787672a4e9af1"
      hash3 = "2a1c1a22ed6989e9ba86f9a192834e0a35afec8026e8ecc0bb5c958d2892d46c"
      hash4 = "30b682ee7114bf68f881e641e9ab14c7d62c84f725e9cf5bfccb403aaa1fe8f7"
      hash5 = "3b9a35f7a0698b24d214818efd22235c995f1460fc55dd3ebd923ff0dca5370c"
      hash6 = "4110dd04db3932f1f03bdce6fa74f5298ffb429b816c7a8fce40f1cbb043e968"
      hash7 = "471b4d64420bdf2c8749c390a142ed449aff23b0d67609b268be044657501fa7"
      hash8 = "5a9f02031f0b3b1a2edaeae2d77b8c1f67de2b611449432c42c88f840d7a1d5c"
      hash9 = "78d9488d688f3b12181b54df0e9da3770e90a4a42a13db001fd211d16645a1bb"
      hash10 = "7f2aa6e5e1f1229fb18a15d1599a7a6014796cc7c08b26b9c4336a2048dc8928"
      hash11 = "805917658c7761debdaf18e83b54ec4e9ba645950c773ddd21d6cd8ba29b32d6"
      hash12 = "ae880c7dd79ebb1d626aea57152fdaa779d07d5b326d7f7fad1d42b637e5da84"
      hash13 = "b0d36c18bf900988d01828202ce1ab77949b9a8a29b264ea1639f170a6c9825b"
      hash14 = "c17bf892498ed1dce5db1b0f3d588774b8e82f2636f397b2456d15e7442781e6"
      hash15 = "c27e328d2fe6fd75066938f58c3359c5dbb9deea166c6a4d3b0397d295a3e8d5"
      hash16 = "df292a289d93136fbdd6ac0850b2c8845f967d9a9a3bd29a9386b39843b82eda"
      hash17 = "e07a008aaf0a0a2666a705a9756da5bc54be18e2a53a50eb7539f1143548a57f"
      hash18 = "0be1e96f318d98398861217a9754bc003e6861d84de8553cdbd87531db66e19b"
      hash19 = "2d049876c256e55ae48a1060c32f8d75b691525cd877556172f163fe39466001"
      hash20 = "3d8194b7853a1edbaa5d14b4b7a0323c5584b8a5c959efe830073e43d0b4418a"
      hash21 = "576bce5c1d1143b0e532333a28d37c98d65b271d651dbce86360d3e80460733f"
      hash22 = "b7c5895189c7f4e30984e2f0db703c2120909dccaa339e59795d3e732bca9340"
      hash23 = "db23bf90a7f0c69c3501876243ca2fe29e9208864dfa6f2b5d0dac51061a3d86"
      hash24 = "e1093d59bef8f260b0ca1ebe82c0635cc225e060b8d7296efe330ca7837e6d44"
      hash25 = "e29d1c2cbd64d0f1433602f2b63cf40e33b4376ac613e911a2160b268496164d"
      hash26 = "e6523f691d0b4a16cc1892ec4eb3ee113d62443317e337412b70e0cea3e106f7"
      hash27 = "ec9387b582e5a935094c6d165741d2c989e72afc3c6063a29e96153e97a74af3"
      hash28 = "ed2eaf4c44f83c7920b2d73cbe242b82cc92e3188d04b1bb8742783c49487da7"
   strings:
      $s1 = "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44" ascii
      $s2 = "/73x/6ax/x4a/x4b/x4d/x44/x20/x44/x57/x29/x5f/x20/x44/x57/x49/x4f/x57/x20/x57/x4f/x4b/x3c/x20/x57/x44/x4b/x20/x44/x29/x5f/x41/" fullword ascii
      $s3 = "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44" ascii
      $s4 = "/x4d/x20/x29/x28/x28/x22/x29/x45/x4f/x4b/x58/x50/x7b/x20/x5f/x57/x44/x44/x57/x44/" fullword ascii
      $s5 = "/x71/x3b/x38/x38/x20/x43/x57/x29/x57/x22/x29/x64/x32/x20/x4b/x58/x4b/x4b/x4c/x22/x44/x20/x2d/x44/x5f/" fullword ascii
      $s6 = "UDPBYPASS" fullword ascii
      $s7 = "Is a named type file" fullword ascii
      $s8 = "Structure needs cleaning" fullword ascii
      $s9 = "No XENIX semaphores available" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and 5 of them
}

rule Gafgyt_July_6 {
   meta:
      description = "Detect the risk of Botnet Malware Gafgyt Rule 3"
      author = "LightDefender"
      date = "2021-07-06"
      hash1 = "821d34f7978fc65fe3b570e86cce45edc921a6cbf02b127fb1263a8448a1f62a"
   strings:
      $s1 = "infected.log" fullword ascii
      $s2 = "Samael-DDoS-Attack" fullword ascii
      $s3 = "B0TK1LL" fullword ascii
      $s4 = "This Device Has Been Infected by Samael Botnet Made By ur0a :)" ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and 2 of them
}

rule elf_bashlite_auto {

    meta:
     description = "Detect the risk of Botnet Malware Gafgyt Rule 4"
    strings:
        $sequence_0 = { 21d0 3345fc c9 c3 55 }
            // n = 5, score = 300
            //   21d0                 | mov                 dword ptr [ebp - 4], 0
            //   3345fc               | mov                 edi, 0x512c00
            //   c9                   | inc                 esp
            //   c3                   | mov                 edi, esp
            //   55                   | mov                 edi, 0x512c00

        $sequence_1 = { e8???????? 89c2 89d0 c1e81f }
            // n = 4, score = 300
            //   e8????????           |                     
            //   89c2                 | mov                 byte ptr [ebx], 0
            //   89d0                 | sub                 eax, edx
            //   c1e81f               | cmp                 eax, dword ptr [esp + 0x7c]

        $sequence_2 = { e8???????? 8945ec 837dec00 750b 8b45ec }
            // n = 5, score = 300
            //   e8????????           |                     
            //   8945ec               | je                  0xffffff7c
            //   837dec00             | mov                 al, byte ptr [ebp - 0xf]
            //   750b                 | cmp                 al, 0xc0
            //   8b45ec               | mov                 al, byte ptr [ebp - 0xd]

        $sequence_3 = { f7d0 21d0 3345fc c9 }
            // n = 4, score = 300
            //   f7d0                 | mov                 ecx, eax
            //   21d0                 | dec                 eax
            //   3345fc               | mov                 edx, dword ptr [ebp - 0x40]
            //   c9                   | mov                 edi, 0x800

        $sequence_4 = { 750c e8???????? 8b00 83f804 }
            // n = 4, score = 300
            //   750c                 | cmp                 al, 0xfc
            //   e8????????           |                     
            //   8b00                 | jne                 0x18a
            //   83f804               | dec                 eax

        $sequence_5 = { eb0a c785ecefffff00000000 8b85ecefffff c9 c3 }
            // n = 5, score = 300
            //   eb0a                 | mov                 eax, dword ptr [eax]
            //   c785ecefffff00000000     | mov    dword ptr [ebp - 0x108], eax
            //   8b85ecefffff         | mov                 dword ptr [ebp - 0x10c], 0x8056e9e
            //   c9                   | mov                 dword ptr [ebp - 0x110], 5
            //   c3                   | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 8b85ecefffff c9 c3 55 }
            // n = 4, score = 300
            //   8b85ecefffff         | add                 eax, 0x41
            //   c9                   | mov                 byte ptr [ebx], al
            //   c3                   | mov                 dword ptr [ebp - 0x1c], edx
            //   55                   | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_7 = { c1f802 89c2 89d0 01c0 01d0 }
            // n = 5, score = 300
            //   c1f802               | mov                 dword ptr [ebp - 0x88], eax
            //   89c2                 | jmp                 0x159
            //   89d0                 | mov                 dword ptr [esp], eax
            //   01c0                 | mov                 ecx, eax
            //   01d0                 | or                  ecx, 0x800

        $sequence_8 = { 85c0 750c c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff }
            // n = 6, score = 300
            //   85c0                 | mov                 dword ptr [ebp - 0x4c], edx
            //   750c                 | dec                 eax
            //   c785ecefffff01000000     | mov    edi, dword ptr [ebp - 0x18]
            //   eb0a                 | mov                 ecx, dword ptr [ebp - 0x38]
            //   c785ecefffff00000000     | mov    edx, dword ptr [ebp - 0x3c]
            //   8b85ecefffff         | add                 dword ptr [ebp - 0x34], eax

        $sequence_9 = { 21d0 3345fc c9 c3 }
            // n = 4, score = 300
            //   21d0                 | mov                 eax, dword ptr [ebp - 0x1c]
            //   3345fc               | mov                 word ptr [eax + 0xa], dx
            //   c9                   | mov                 dword ptr [esp], 0
            //   c3                   | movzx               edx, ax

    condition:
        7 of them and filesize < 274018
}


rule Gafgyt_Botnet_generic : MALW
{
meta:
	description = "Detect the risk of Botnet Malware Gafgyt Rule 5"
	MD5 = "e3fac853203c3f1692af0101eaad87f1"
	SHA1 = "710781e62d49419a3a73624f4a914b2ad1684c6a"

strings:
	$etcTZ = "/bin/busybox;echo -e 'gayfgt'"
	$s2 = "/proc/net/route"
	$s3 = "admin"
	$s4 = "root"

condition:
	$etcTZ and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_oh : MALW
{
meta:
	description = "Detect the risk of Botnet Malware Gafgyt Rule 6"
	MD5 = "97f5edac312de349495cb4afd119d2a5"
	SHA1 = "916a51f2139f11e8be6247418dca6c41591f4557"

    strings:
            $s1 = "busyboxterrorist"
            $s2 = "BOGOMIPS"
            $s3 = "124.105.97.%d"
            $s4 = "fucknet"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_bash : MALW
{
meta:
     description = "Detect the risk of Botnet Malware Gafgyt Rule 7"
	 MD5 = "c8d58acfe524a09d4df7ffbe4a43c429"
	 SHA1 = "b41fefa8470f3b3657594af18d2ea4f6ac4d567f"

    strings:
            $s1 = "PONG!"
            $s2 = "GETLOCALIP"
            $s3 = "HTTPFLOOD"
            $s4 = "LUCKYLILDUDE"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_hoho : MALW
{
meta:
     description = "Detect the risk of Botnet Malware Gafgyt Rule 8"
     MD5 = "369c7c66224b343f624803d595aa1e09"
     SHA1 = "54519d2c124cb536ed0ddad5683440293d90934f"

    strings:
            $s1 = "PING"
            $s2 = "PRIVMSG"
            $s3 = "Remote IRC Bot"
            $s4 = "23.95.43.182"
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_jackmy : MALW
{
meta:
     description = "Detect the risk of Botnet Malware Gafgyt Rule 9"
     MD5 = "419b8a10a3ac200e7e8a0c141b8abfba"
     SHA1 = "5433a5768c5d22dabc4d133c8a1d192d525939d5"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "jackmy"         
            $s4 = "203.134.%d.%d"       
    condition:
            $s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_HIHI: MALW
{
meta:
     description = "Detect the risk of Botnet Malware Gafgyt Rule 10"
     MD5 = "cc99e8dd2067fd5702a4716164865c8a"
     SHA1 = "b9b316c1cc9f7a1bf8c70400861de08d95716e49"

    strings:
            $s1 = "PING"
            $s2 = "PONG"
            $s3 = "TELNET LOGIN CRACKED - %s:%s:%s"
            $s4 = "ADVANCEDBOT"
            $s5 = "46.166.185.92"
            $s6 = "LOLNOGTFO"

    condition:
            $s1 and $s2 and $s3 and $s4 and $s5 and $s6
}
