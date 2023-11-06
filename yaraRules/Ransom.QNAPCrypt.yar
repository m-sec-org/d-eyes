rule Ransom_QNAPCrypt {
   meta:
      description= "Detect the risk of Ransomware QNAPCrypt Rule 1"
      hash1 = "039a997681655004aed1cc4c6ee24bf112d79e4f3b823ccae96b4a32c5ed1b4c"
      hash2 = "0b851832f9383df7739cd28ccdfd59925e9af7203b035711a7d96bba34a9eb04"
      hash3 = "19448f9aa1fe6c07d52abc59d1657a7381cfdb4a4fa541279097cc9e9412964b"
      hash4 = "2fe577fd9c77d3bebdcf9bfc6416c3f9a12755964a8098744519709daf2b09ce"
      hash5 = "36cfb1a7c971041c9483e4f4e092372c9c1ab792cd9de7b821718ccd0dbb09c1"
   strings:
      $s1 = "1st.3ds.3fr.4db.4dd.602.a4p.a5w.abf.abw.act.adr.aep.aes.aex.aim.alx.ans.apk.apt.arj" ascii
      $s2 = ".arw.asa.asc.ase.asp.asr.att.aty.awm.awp.awt.aww.axd.bak.bar.bat.bay.bc6.bc7.big.bik.bin.bit.bkf.bkp.bml.bok.bpw.bsa.bwp.bz2.c++" ascii
      $s3 = ".swz.sxc.t12.t13.tar.tax.tbl.tbz.tcl.tgz.tib.tif.tor.tpl.txt.ucf.upk.url.vbd.vbo.vbs.vcf.vdf.vdi.vdw.vlp.vlx.vmx.vpk.vrt.vtf.w3x" ascii
      $s4 = "README_FOR_DECRYPT.txt" ascii
   condition:
      uint16(0) == 0x457f and any of them
}
