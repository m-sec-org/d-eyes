import "hash"
rule blackmoon_hash
{
   meta:
        description ="Detect the risk of Malware blackmoon  Rule 1"
   condition:
        hash.md5(0,filesize) =="22E46CBCF02D78390D257AEE0FE26EDE" or
        hash.md5(0,filesize) =="65982DEB6AC30B9F1F4DAB1AA26A0D0E" or
        hash.md5(0,filesize) =="C4A73F3BBDD1E64EF146A232967B1BC5" or
        hash.md5(0,filesize) =="93EB67FDB2D0C767887C6F6284844386" or
        hash.md5(0,filesize) =="F73436646F905504027809A461D0A8D9" or
        hash.md5(0,filesize) =="63EC62319605B43D68EB25B9F84153C8" or
        hash.sha256(0,filesize) =="25f87c65a793186c7a9e1d8680ad7f32acb9bae4cb7284b98781b3a15f810ba2" or
        hash.sha256(0,filesize) =="a57980012b38dc89baab954e7da3fa7112dd52b2252a72f87ec2510a70d2ade7"

}

rule BLACKMOON_BANKER {
    meta:
        description ="Detect the risk of Malware blackmoon  Rule 2"
        detail = "blackmoon update"
        strings:
                $s1 = "BlackMoon RunTime Error:" nocase wide ascii
                $s2 = "\\system32\\rundll32.exe" wide ascii
                $s3 = "cmd.exe /c ipconfig /flushdns" wide ascii
                $s4 = "\\system32\\drivers\\etc\\hosts.ics" wide ascii
        condition:
                all of them

}

rule BlackMoon_2022
{
   meta:
        description ="Detect the risk of Malware blackmoon  Rule 3"
  strings:
    $s1 = "kongxin1123"
    $s2 = "m27p.com"
    $s3 = "jincpay.com"
    $s4 = "xiaoniu321.com"
  condition:
    hash.md5(0,filesize) == "22e46cbcf02d78390d257aee0fe26ede" or
    hash.md5(0,filesize) == "65982deb6ac30b9f1f4dab1aa26a0d0e" or
    hash.md5(0,filesize) == "93eb67fdb2d0c767887c6f6284844386" or
    hash.md5(0,filesize) == "c4a73f3bbdd1e64ef146a232967b1bc5" or
    hash.md5(0,filesize) == "f73436646f905504027809a461d0a8d9" or
    hash.md5(0,filesize) == "63ec62319605b43d68eb25b9f84153c8" or
    hash.md5(0,filesize) == "37C030456818878AF1DC8CE7928A504F" or
    $s1 or
    $s2 or
    $s3 or
    $s4
}