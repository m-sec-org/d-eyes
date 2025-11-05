rule Ransom_Zeppelin {
   meta:
     description= "Detect the risk of Ransomware Zeppelin Rule 1"
   strings:
      $op1 = {558BEC83C4E4538B1833C08945F05533D28BC3E8}
      $op2 = {555756535052546A076A0168DEFAED0E52FF2514}
      $op3 = {8B45088378F004721E8B45088178F40010000075}
      $op4 = {558BEC515356578945FC33D25568AF3D400064FF}
      $x = "TZeppelinU" ascii wide
   condition:
      uint16(0) == 0x5a4d and (all of ($op*) or ($x))
 }
