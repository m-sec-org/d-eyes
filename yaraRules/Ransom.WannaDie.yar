rule Ransom_WannaDie
{
   meta:
      description = "Detect the risk of Ransom.WannaDie Rule 1"
      hash1 = "295f01c0f93400b0bea4823457a1ca09329770c6e2fa2de44972940aba16f0b2"
      hash2 = "b0c40513ae3c7f9cb72ab2a5084f0ba479ec50b4a502e210903b14169d9426c6"
   strings:
      $s1 = "C:\\Users\\kashe\\source\\repos\\Microsoft System\\Microsoft System\\obj\\Debug\\Microsoft System.pdb" fullword ascii
      $s2 = " and your WannaDie-ID and then our service team will send you" ascii
      $s3 = "C:\\Users\\baddo\\Desktop\\CryptoWall\\CryptoWall\\obj\\Release\\wndi.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and any of them
}
