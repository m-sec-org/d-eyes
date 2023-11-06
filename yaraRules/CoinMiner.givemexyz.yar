import "hash"
rule givemexyz_family_hash
{
   meta:
        description ="Detect the risk of CoinMiner givemexyz Rule 1"
   condition:
        hash.sha256(0,filesize) =="599393e258d8ba7b8f8633e20c651868258827d3a43a4d0712125bc487eabf92" or
        hash.sha256(0,filesize) =="2c356d4621626e3de5f268aea9e7736840bbfcdc02e15d2b3cda1050f4f50798" or
        hash.sha256(0,filesize) =="2fc3be782b1803c6e1c17e386136e6b2fb7e5054e2a81eee8f866eeaa44beab1" or
        hash.sha256(0,filesize) =="8a877dc7afbfb6701ac42630c2adafb9ef46e8942e5b17372f07c892a7bee1b3" or
        hash.sha256(0,filesize) =="1225cc15a71886e5b11fca3dc3b4c4bcde39f4c7c9fbce6bad5e4d3ceee21b3a" or
        hash.sha256(0,filesize) =="11547e36146e0b0956758d48faeb19d4db5e737dc942bc7498ed86a8010bdc8b" or
        hash.sha256(0,filesize) =="86f57444e6f4a40378fd0959a54794c7384d04678f8c66dfb7801f3d0cfc0152" or
        hash.sha256(0,filesize) =="86859ad5e3115893e5878e91168367d564c1eb937af0d1e4c29dd38fb9647362" or
        hash.sha256(0,filesize) =="f8744257415d256512c8b2f3501be20a0a30e37357e71df3986e2918fd53ef5e" or
        hash.sha256(0,filesize) =="b6154d25b3aa3098f2cee790f5de5a727fc3549865a7aa2196579fe39a86de09" or
        hash.sha256(0,filesize) =="a5604893608cf08b7cbfb92d1cac20868808218b3cc453ca86da0abaeadc0537" or
        hash.sha256(0,filesize) =="f994135b5285cc481f2bfc213395e81c656542d1b6b5f23551565d524f3cdb89" or
        hash.sha256(0,filesize) =="ceb3a7a521dc830a603037c455ff61e8849235f74db3b5a482ad5dcf0a1cdbc5"
}


rule XmrigCnrigOptions: mining xmrig cnrig
{
    meta:
      description ="Detect the risk of CoinMiner givemexyz Rule 2"

    strings:
        $s1 = "--donate-level" ascii
        $s2 = "--nicehash" ascii
        $s3 = "--algo" ascii
        $s4 = "--threads" ascii
        $s5 = "--cpu-max-threads-hint" ascii
        $x = "xmrig" ascii fullword
    condition:
        3 of ($s*) and $x
}

import "hash"



// xmrig_md5_5_9_0
private rule tar_gz_5_9_0
{
    meta:
        description = "xmrig-5.9.0-xenial-x64.tar.gz"
    condition:
        hash.md5(0, filesize) == "b63ead42823ae63c93ac401e38937323"
}

private rule xmrig_5_9_0
{
    meta:
        description = "xmrig.elf"
    condition:
        hash.md5(0, filesize) == "d351de486d4bb4e80316e1524682c602"
}

private rule xmrig_notls_5_9_0
{
    meta:
        description = "xmrig-notls.elf"
    condition:
        hash.md5(0, filesize) == "187ed1d112e4a9dff0241368f2868615"
}


rule xmrig_md5_5_9_0: mining md5 xmrig
{
    meta:
       description ="Detect the risk of CoinMiner givemexyz Rule 3"
    condition:
        tar_gz_5_9_0 or xmrig_5_9_0 or xmrig_notls_5_9_0
}



// xmrig_md5_5_10_0
private rule tar_gz_5_10_0
{
    meta:
        description = "xmrig-5.10.0-xenial-x64.tar.gz"
    condition:
        hash.md5(0, filesize) == "416079fd0c7b45307556198f3f67754d"
}

private rule xmrig_5_10_0
{
    meta:
        description = "xmrig.elf"
    condition:
        hash.md5(0, filesize) == "3939395192972820ce2cf99db0c239d7"
}

private rule xmrig_notls_5_10_0
{
    meta:
        description = "xmrig-notls.elf"
    condition:
        hash.md5(0, filesize) == "0456ef39240c75e0862b30419d4c6359"
}


rule xmrig_md5_5_10_0: mining md5 xmrig
{
    meta:
      description ="Detect the risk of CoinMiner givemexyz Rule 4"
    condition:
        tar_gz_5_10_0 or xmrig_5_10_0 or xmrig_notls_5_10_0
}



// xmrig_md5_5_11_0
private rule tar_gz_5_11_0
{
    meta:
        description = "xmrig-5.11.0-xenial-x64.tar.gz"
    condition:
        hash.md5(0, filesize) == "abf7feaf1e456c0fc6e8f1e40af9211c"
}

private rule xmrig_5_11_0
{
    meta:
        description = "xmrig.elf"
    condition:
        hash.md5(0, filesize) == "56aec7d8d2aba5ba2b82930408f0b5d3"
}

private rule xmrig_notls_5_11_0
{
    meta:
        description = "xmrig-notls.elf"
    condition:
        hash.md5(0, filesize) == "9a5c0a5d960b676ba4db535f71ee7cef"
}


rule xmrig_md5_5_11_0: mining md5 xmrig
{
    meta:
       description ="Detect the risk of CoinMiner givemexyz Rule 5"
    condition:
        tar_gz_5_11_0 or xmrig_5_11_0 or xmrig_notls_5_11_0
}



// xmrig_md5_5_11_1
private rule tar_gz_5_11_1
{
    meta:
        description = "xmrig-5.11.1-xenial-x64.tar.gz"
    condition:
        hash.md5(0, filesize) == "820022ba985b4d21637bf6d3d1e53001"
}

private rule xmrig_5_11_1
{
    meta:
        description = "xmrig.elf"
    condition:
        hash.md5(0, filesize) == "0090962752b93454093239f770628006"
}

private rule xmrig_notls_5_11_1
{
    meta:
        description = "xmrig-notls.elf"
    condition:
        hash.md5(0, filesize) == "54158be61b8011a10d1a94432ead208c"
}


rule xmrig_md5_5_11_1: mining md5 xmrig
{
    meta:
        description ="Detect the risk of CoinMiner givemexyz Rule 6"
    condition:
        tar_gz_5_11_1 or xmrig_5_11_1 or xmrig_notls_5_11_1
}

rule xmrig_md5_samples_1: mining md5 xmrig
{
    meta:
         description ="Detect the risk of CoinMiner givemexyz Rule 7"
    condition:
        hash.md5(0, filesize) == "6f2a2ff340fc1307b65174a3451f8c9a"
}


rule xmrig_md5_samples_2: mining md5 xmrig
{
    meta:
        description ="Detect the risk of CoinMiner givemexyz Rule 8"
    condition:
        hash.md5(0, filesize) == "22a213bfd093c402312d75f5f471505e"
}

rule XmrigConfig: json mining xmrig
{
    meta:
        description ="Detect the risk of CoinMiner givemexyz Rule 9"
        detail = "xmrig config.json"
    strings:
        $ = "\"worker-id\":" ascii
        $ = "\"randomx\":" ascii
        $ = "\"donate-level\":" ascii
        $ = "\"rig-id\":" ascii
        $ = "\"donate-over-proxy\":" ascii
    condition:
        3 of them
}