import "hash"

rule GandCrab_hash{
meta: 
    description= "Detect the risk of GandCrab Rule 1"
  condition:
   hash.sha256(0,filesize) =="49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200" or
    hash.sha256(0,filesize) =="a45bd4059d804b586397f43ee95232378d519c6b8978d334e07f6047435fe926"
}
rule GandCrab {
   meta:
      description ="Detect the risk of GandCrab Rule 2"
      hash1 = "ce9c9917b66815ec7e5009f8bfa19ef3d2dfc0cf66be0b4b99b9bebb244d6706"
   strings:
      $s1 = "tXujazajiyani voxazo. Wi wayepaxoli wuropiyenazizo fo. Cona leseyimucaye dupoxiyo. Nice mibehahasepa wudehukusidada garaterisovu" ascii
      $s2 = "Gihepipigudi sirabuzogasoji. Sorizo sexabonera. Muyokeza niboru kikekimuxu rupo vojurotavugoyi. Yi yugose kadohajedumiya. Bedase" ascii
      $s3 = " tixakehe. Reseyetasohora benusere vata kenevagume. Gedagu pegaleheruwago bukiredexuvuwa je. Yowujovu tuzudiposuxe zoyirudipu fo" ascii
      $s4 = "imarijoyaneye vetuwipu. Fe. Bedopiyo comu jiye ze. Josusutime vumavizaseha. Pezofogijuxo nucosegogili bobi xayogaci. Kuyi letozo" ascii
      $s5 = "**,,,," fullword ascii /* reversed goodware string ',,,,**' */
      $s6 = "seyeruxiyehoxidecekajegexozaya gopegiyutusuwofobolikuhubu" fullword wide
      $s7 = "Jetewavasaloge" fullword wide
      $s8 = "vice zako wukewofeja vehe. Baji givihazi fuyacizogizanu. Gipayacucipi. Wetewavasa. Logeju xosidijoha ruxayo. Gorayo cicenehozogo" ascii
      $s9 = "zimosafodi dusepe. Jacudagemuva falo miseyicuwatita koneyepijo. Sudotakupovete mulavifiposo xohilujusucu fususabo. Henihideya di" ascii
      $s10 = "zumi gesakuki xoyefepuwahuje. Cugetutu. Nivileralu wafu jojoxaruku luraza punekuce. Dolape dubo. Jirehebeta jeda raguluyoda wohu" ascii
      $s11 = "444F4,F44" fullword ascii /* hex encoded string 'DOOD' */
      $s12 = "ale wufevujo kagomi haciceye. Yevaxudizera fasumatevakuvo kogumiwubo ta. Hutucozamevi jiharabeme bopobozeharu puyucite fuvukuyi." ascii
      $s13 = "44,,,,,,4b" fullword ascii /* hex encoded string 'DK' */
      $s14 = "jojukalo lijogagulucurukeyuroyupoheve mi" fullword wide
      $s15 = "YKuluye sepuhe zi mosafodidusepe jacudagemuva falomiseyicuwa titako neyepijosu dotakupo ve" fullword wide
      $s16 = "Yefepuwahuje cugetutu nivi le" fullword wide
      $s17 = " yeruxiyeho xide cekajegexoza. Yagopegi. Yutu suwofo bo. Likuhubujojuka lolijogagulucu. Ru keyuro yupohevelivu dubiyuyinaxo. Dey" ascii
      $s18 = "VUGOYIYIYUGOSEKADOHAJEDUMIYA" fullword wide
      $s19 = "XCJSEUPAVJ" fullword wide
      $s20 = "Eimnxjk" fullword ascii
      $s21 = "ikernel32.dll" fullword wide
      $s22 = "hulinowujovimuxatelo zabemaperetaboyazowa vituxifuyuyakixi" fullword ascii
      $s23 = "Va penoyotoretunurosacidutezajogu fatixiposapapabicu boyokopusidonoyododusahehu" fullword ascii
      $s24 = " Base Class Descriptor at (" fullword ascii
      $s25 = "ruxayogorayocice" fullword wide
      $s26 = "GDCB-DECRYPT.txt" wide
      $s27 = "culico yami" fullword ascii
      $s28 = "ReflectiveLoader" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      4 of them
}

// From Malpedia
rule win_gandcrab_auto {

    meta:
        description ="Detect the risk of GandCrab Rule 3"
        detail= "GandCrab Ransomware win_gandcrab_auto"
    strings:
        $sequence_0 = { ff15???????? 03c3 8d5e04 03d8 837f6000 }
        $sequence_1 = { ff15???????? ff7728 8bf0 ff15???????? 03c3 8d5e04 }
        $sequence_2 = { 03c3 8d5e04 03d8 837f1800 741b ff7720 ff15???????? }
        $sequence_3 = { ff777c ff15???????? ff7778 8bf0 ff15???????? 03c3 }
        $sequence_4 = { ff774c 8bf0 ff15???????? 03c3 8d5e04 03d8 }
        $sequence_5 = { 8d5e04 03d8 837f3c00 741b ff7744 ff15???????? }
        $sequence_6 = { ff772c ff15???????? ff7728 8bf0 ff15???????? 03c3 8d5e04 }
        $sequence_7 = { 5f 66894c46fe 8bc6 5e 5b }
        $sequence_8 = { 741b ff772c ff15???????? ff7728 8bf0 ff15???????? }
        $sequence_9 = { 03c3 8d5e04 03d8 837f5400 741b ff775c ff15???????? }
    condition:
        any of them and filesize < 1024000
}


rule Gandcrab4
{
  meta:
        description ="Detect the risk of GandCrab Rule 4"
  strings:
    $hex1 = { 55 8B EC 83 EC ?? 53 56 ?? 3? ?? ?? ?? ?? 5? ?? }
    $hex2 = { 8B 45 08 33 45 FC 89 ?1 ?C ?? ?? ?? ?? ?8 ?? ?? }
  condition:
    all of them and uint16(0) == 0x5A4D and filesize < 100KB
}

rule GandCrab5
{
    meta:
       description ="Detect the risk of GandCrab Rule 5"
    strings:
        $s1 = "&version=" wide ascii
        $s2 = "/c timeout -c 5 & del \"%s\" /f /q" wide ascii
        $s3 = "GANDCRAB" wide ascii
        $t1 = "%s\\GDCB-DECRYPT.txt" wide ascii 
        $t2 = "%s\\KRAB-DECRYPT.txt" wide ascii
    condition:
        all of ($s*) and ($t1 or $t2)
}

rule Gandcrab_hash
{
   meta:
        description ="Detect the risk of GandCrab Rule 5"
   condition:
    hash.sha256(0,filesize) =="eb9207371e53414cfcb2094a2e34bd68be1a9eedbe49c4ded82b2adb8fa1d23d"
}
