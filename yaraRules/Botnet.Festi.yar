rule festi_botnet_pdb {
	 meta:
		 description = "Detect the risk of Botnet Malware Festi Rule 1"
		 hash = "e55913523f5ae67593681ecb28d0fa1accee6739fdc3d52860615e1bc70dcb99"
	 strings:
	 	$pdb = "\\eclipse\\botnet\\drivers\\Bin\\i386\\kernel.pdb"
	 condition:
	 	uint16(0) == 0x5a4d and
	 	filesize < 80KB and
	 	any of them
}
