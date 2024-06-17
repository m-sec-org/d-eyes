import "hash"

rule RansomHouseRule1
{
   meta:
        description ="Detect the Malware of RansomHouse Rule 1, if you need help, call NSFOCUS's support team 400-8186868, please."
   condition:
        hash.sha256(0,filesize) =="f494629cab071bd384f7998014729d7537a9db0cf7d954b0ff74ea5235c11b1c"
}

rule RansomHouseRule2
{
   meta:
        description ="Detect the Malware of RansomHouse Rule 2, if you need help, call NSFOCUS's support team 400-8186868, please."
   condition:
        hash.sha256(0,filesize) =="f88c9366798cd5bd09bebf5b3e44f73c16825ae24dee2e89feeafe0875164348"
}

rule RansomHouseRule3{
   meta:
      description ="Detect the Malware of RansomHouse Rule 3, if you need help, call NSFOCUS's support team 400-8186868, please."
   strings:
      $s1 = "unknown error - system account operation failed" fullword ascii
      $s2 = "command not found - does the file exist? do you run it like ./commandname if the file is in the same folder?" fullword ascii
      $s3 = "warning - no output from process" fullword ascii
      $s4 = "failed to create file to run process" fullword ascii
      $s5 = "esxcli system account command not found" fullword ascii
      $s6 = "failed to start process" fullword ascii
      $s7 = "unknown error - operation failed" fullword ascii
      $s8 = "failed to chmod file to run process" fullword ascii
      $s9 = "Dear IT Department and Company Management! If you are reading this message, it means that your network infrastructure has been c" ascii
      $s10 = "esxcli --formatter=csv vm process list" fullword ascii
      $s11 = "process was killed by force" fullword ascii
      $s12 = "rm -rf /var/log/*.log" fullword ascii
      $s13 = "RunProcess" fullword ascii
      $s14 = "ps | grep sshd | grep -v -e grep -e root -e 12345 | awk '{print \"kill -9\", $2}' | sh " fullword ascii
      $s15 = "esxcli command not found" fullword ascii
      $s16 = "esxcli --formatter=csv system account list" fullword ascii
      $s17 = "esxcli --formatter=csv network ip interface ipv4 get" fullword ascii
      $s18 = "Dear IT Department and Company Management! If you are reading this message, it means that your network infrastructure has been c" ascii
      $s19 = "welcomeset" fullword ascii
      $s20 = "ompromised. Look for 'How To Restore Your Files.txt' document for more information." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule RansomHouseRule4{
   meta:
      description = "Detect the Malware of RansomHouse Rule 4, if you need help, call NSFOCUS's support team 400-8186868, please."
   strings:
      $s1 = "OxyKeyScout.exe" fullword wide 
      $s2 = "https://sectigo.com/CPS0" fullword ascii 
      $s3 = "https://sectigo.com/CPS0C" fullword ascii 
      $s4 = "N$.DlL" fullword ascii 
      $s5 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii 
      $s6 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii 
      $s7 = ",https://enigmaprotector.com/taggant/user.crl0" fullword ascii 
      $s8 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
      $s9 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii 
      $s10 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii 
      $s11 = "http://ocsp.sectigo.com0&" fullword ascii 
      $s12 = "http://ocsp.sectigo.com0" fullword ascii 
      $s13 = "support@oxygen-forensic.com0" fullword ascii 
      $s14 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii 
      $s15 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii 
      $s16 = "3http://crl.sectigo.com/SectigoRSATimeStampingCA.crl0t" fullword ascii 
      $s17 = "+https://enigmaprotector.com/taggant/spv.crl0" fullword ascii 
      $s18 = "3http://crt.sectigo.com/SectigoRSATimeStampingCA.crt0#" fullword ascii 
      $s19 = "NNkz:\"J" fullword ascii 
      $s20 = "ETCkW:\\" fullword ascii 
      $op0 = { a4 00 0c 01 c8 d4 f2 af 34 50 c5 1b 1b 55 03 fc }
      $op1 = { d3 0f 0c 01 34 0f 0c 01 }
      $op2 = { 54 41 47 47 00 30 00 00 b6 1a 00 00 01 00 30 82 }
   condition:
      uint16(0) == 0x5a4d and filesize < 244000KB and
      ( 8 of them and all of ($op*) )
}