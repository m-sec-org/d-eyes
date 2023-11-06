rule Rule_Coinminer_ELF_Format {
   meta:
      description = "Detect the risk of CoinMiner ELF Rule 1"
      detail= "Detects Crypto Miner ELF format"
   strings:
      $str1 = "mining.set_difficulty" ascii
      $str2 = "mining.notify"  ascii
      $str3 = "GhostRider" ascii
      $str4 = "cn/turtle-lite" ascii
      $str5 = "spend-secret-key" ascii
   condition:
      uint16(0) == 0x457f and 
      4 of them      
}
