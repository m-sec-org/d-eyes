rule Ransom_CryptoLocker {
   meta:
      description= "Detect the risk of Ransomware CryptoLocker Rule 1"
   strings:
      $s1 = {558BEC83EC0C56C745F8240100008B45}
      $s2 = {8B45F82DE92E00002B45F48945F48D05}
   condition:
      uint16(0) == 0x5a4d and all of them
 }

rule Ransom_Cryptolocker_2 {
   meta:
      description= "Detect the risk of Ransomware CryptoLocker Rule 2"
   strings:
      $s1 = {8B454821E8306DCFFF63804528050000}
   condition:
      uint16(0) == 0x5a4d and all of them
 }

rule CryptoLocker {
    meta:
        description= "Detect the risk of Ransomware CryptoLocker Rule 3"
    strings:
        $x1 = "CryptoLocker" fullword wide
        $x2 = ".betarasite" fullword wide
        $x3 = "CMSTPBypass" fullword ascii
        $s1 = "CommandToExecute" fullword ascii
        $s2 = "SetInfFile" fullword ascii
        $s3 = "SchoolPrject1" ascii
        $s4 = "$730d5f64-bd57-47c1-9af4-d20aec714d02" fullword ascii
        $s5 = "Encrypt" fullword ascii
        $s6 = "Invalide Key! Please Try Again." fullword wide
        $s7 = "RegAsm" fullword wide
        $s8 = "Your key will be destroyed" wide
        $s9 = "encrypted using RC4 and RSA-2048" wide
        $c1 = "https://coinbase.com" fullword wide
        $c2 = "https://localbictoins.com" fullword wide
        $c3 = "https://bitpanda.com" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (2 of ($x*) and 5 of ($s*)) or (all of ($c*) and 1 of ($x*) and 2 of ($s*)))
}
