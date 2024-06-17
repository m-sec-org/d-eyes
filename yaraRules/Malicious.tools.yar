import "pe"
import "math"

rule Mimikatz_Memory_Rule_1 {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 1"
   strings:
      $s1 = "sekurlsa::msv" fullword ascii
       $s2 = "sekurlsa::wdigest" fullword ascii
       $s4 = "sekurlsa::kerberos" fullword ascii
       $s5 = "sekurlsa::tspkg" fullword ascii
       $s6 = "sekurlsa::livessp" fullword ascii
       $s7 = "sekurlsa::ssp" fullword ascii
       $s8 = "sekurlsa::logonPasswords" fullword ascii
       $s9 = "sekurlsa::process" fullword ascii
       $s10 = "ekurlsa::minidump" fullword ascii
       $s11 = "sekurlsa::pth" fullword ascii
       $s12 = "sekurlsa::tickets" fullword ascii
       $s13 = "sekurlsa::ekeys" fullword ascii
       $s14 = "sekurlsa::dpapi" fullword ascii
       $s15 = "sekurlsa::credman" fullword ascii
   condition:
      1 of them
}

rule Mimikatz_Memory_Rule_2 {
   meta:
       description = "Detect the risk of Malware Mimikatz Rule 2"
   strings:
      $s0 = "sekurlsa::" ascii
      $x1 = "cryptprimitives.pdb" ascii
      $x2 = "Now is t1O" ascii fullword
      $x4 = "ALICE123" ascii
      $x5 = "BOBBY456" ascii
   condition:
      $s0 and 2 of ($x*)
}

rule mimikatz
{
   meta:
       description = "Detect the risk of Malware Mimikatz Rule 3"

   strings:
      $exe_x86_1      = { 89 71 04 89 [0-3] 30 8d 04 bd }
      $exe_x86_2      = { 8b 4d e? 8b 45 f4 89 75 e? 89 01 85 ff 74 }

      $exe_x64_1      = { 33 ff 4? 89 37 4? 8b f3 45 85 c? 74}
      $exe_x64_2      = { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

      $sys_x86      = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
      $sys_x64      = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

   condition:
      (all of ($exe_x86_*)) or (all of ($exe_x64_*))
      or (any of ($sys_*))
}

rule wce
{
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 4"
   strings:
      $hex_legacy      = { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
      $hex_x86      = { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
      $hex_x64      = { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }
   condition:
      any of them
}

rule power_pe_injection
{
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 5"
   strings:
      $str_loadlib   = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
   condition:
      $str_loadlib
}

rule Mimikatz_Logfile
{
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 6"
   strings:
      $s1 = "SID               :" ascii fullword
      $s2 = "* NTLM     :" ascii fullword
      $s3 = "Authentication Id :" ascii fullword
      $s4 = "wdigest :" ascii fullword
   condition:
      all of them
}

rule Mimikatz_Strings {
   meta:
       description = "Detect the risk of Malware Mimikatz Rule 7"
   strings:
      $x1 = "sekurlsa::logonpasswords" fullword wide ascii
      $x2 = "List tickets in MIT/Heimdall ccache" fullword ascii wide
      $x3 = "kuhl_m_kerberos_ptt_file ; LsaCallKerberosPackage %08x" fullword ascii wide
      $x4 = "* Injecting ticket :" fullword wide ascii
      $x5 = "mimidrv.sys" fullword wide ascii
      $x6 = "Lists LM & NTLM credentials" fullword wide ascii
      $x7 = "\\_ kerberos -" fullword wide ascii
      $x8 = "* unknow   :" fullword wide ascii
      $x9 = "\\_ *Password replace ->" fullword wide ascii
      $x10 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS KO" ascii wide
      $x11 = "\\\\.\\mimidrv" wide ascii
      $x12 = "Switch to MINIDUMP :" fullword wide ascii
      $x13 = "[masterkey] with password: %s (%s user)" fullword wide
      $x14 = "Clear screen (doesn't work with redirections, like PsExec)" fullword wide
      $x15 = "** Session key is NULL! It means allowtgtsessionkey is not set to 1 **" fullword wide
      $x16 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " fullword wide
   condition:
      (
         ( uint16(0) == 0x5a4d and 1 of ($x*) ) or
         ( 3 of them )
      )
      and not pe.imphash() == "77eaeca738dd89410a432c6bd6459907"
}

rule AppInitHook {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 8"
   strings:
      $s0 = "\\Release\\AppInitHook.pdb" ascii
      $s1 = "AppInitHook.dll" fullword ascii
      $s2 = "mimikatz.exe" fullword wide
      $s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
      $s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
      $s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
      $s6 = "VoidFunc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1 {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 9"
   strings:
      $x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }
   condition:
      1 of them
}

rule HKTL_mimikatz_memssp_hookfn {
   meta:
       description = "Detect the risk of Malware Mimikatz Rule 10"
   strings: 
      $xc1 = { 48 81 EC A8 00 00 00 C7 84 24 88 00 00 00 ?? ?? 
               ?? ?? C7 84 24 8C 00 00 00 ?? ?? ?? ?? C7 84 24 
               90 00 00 00 ?? ?? ?? 00 C7 84 24 80 00 00 00 61 
               00 00 00 C7 44 24 40 5B 00 25 00 C7 44 24 44 30 
               00 38 00 C7 44 24 48 78 00 3A 00 C7 44 24 4C 25 
               00 30 00 C7 44 24 50 38 00 78 00 C7 44 24 54 5D 
               00 20 00 C7 44 24 58 25 00 77 00 C7 44 24 5C 5A 
               00 5C 00 C7 44 24 60 25 00 77 00 C7 44 24 64 5A 
               00 09 00 C7 44 24 68 25 00 77 00 C7 44 24 6C 5A 
               00 0A 00 C7 44 24 70 00 00 00 00 48 8D 94 24 80 
               00 00 00 48 8D 8C 24 88 00 00 00 48 B8 A0 7D ?? 
               ?? ?? ?? 00 00 FF D0 } 
   condition: 
      $xc1 
}

rule mimikatz_lsass_mdmp_file
{
  meta:
    description   = "Detect the risk of Malware Mimikatz Rule 11"

  strings:
    $lsass      = "System32\\lsass.exe" wide nocase

  condition:
    (uint32(0) == 0x504d444d) and $lsass
}

rule mimikatz_kirbi_ticket
{
  meta:
    description   = "Detect the risk of Malware Mimikatz Rule 12"

  strings:
    $asn1     = { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }

  condition:
    $asn1 at 0
}

rule lsadump
{
  meta:
    description   = "Detect the risk of Malware Mimikatz Rule 13"
    remarks   = "LSA dump programe (bootkey/syskey) - pwdump and others"
  strings:
    $str_sam_inc  = "\\Domains\\Account" ascii nocase
    $str_sam_exc  = "\\Domains\\Account\\Users\\Names\\" ascii nocase
    $hex_api_call = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
    $str_msv_lsa  = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
    $hex_bkey   = { 4b 53 53 4d [20-70] 05 00 01 00}

  condition:
    ($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey
}

rule mimilove {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 14"
   strings:
      $s1 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii 
      $s2 = "mimilove.exe" fullword wide 
      $s3 = " '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)" fullword wide 
      $s4 = "ERROR wmain ; OpenProcess (0x%08x)" fullword wide 
      $s5 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_LOGON_SESSION_TABLE_50 (0x%08x)" fullword wide 
      $s6 = "ERROR mimilove_lsasrv ; LogonSessionTable is NULL" fullword wide 
      $s7 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KERB_HASHPASSWORD_5 (0x%08x)" fullword wide 
      $s8 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_LOGON_SESSION_50 (0x%08x)" fullword wide 
      $s9 = "ERROR mimilove_kerberos ; KerbLogonSessionList is NULL" fullword wide 
      $s10 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_KEYS_LIST_5 (0x%08x)" fullword wide 
      $s11 = "ERROR kull_m_kernel_ioctl_handle ; DeviceIoControl (0x%08x) : 0x%08x" fullword wide 
      $s12 = "UndefinedLogonType" fullword wide 
      $s13 = "ERROR wmain ; GetVersionEx (0x%08x)" fullword wide 
      $s14 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_PRIMARY_CREDENTIALS (0x%08x)" fullword wide 
      $s15 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_CREDENTIALS (0x%08x)" fullword wide 
      $s16 = "KERBEROS Credentials (no tickets, sorry)" fullword wide 
      $s17 = "Copyright (c) 2007 - 2021 gentilkiwi (Benjamin DELPY)" fullword wide 
      $s18 = "benjamin@gentilkiwi.com0" fullword ascii 
      $s19 = " * Username : %wZ" fullword wide 
      $s20 = "http://subca.ocsp-certum.com01" fullword ascii 

      $op0 = { 89 45 cc 6a 34 8d 45 cc 50 8d 45 c4 8d 4d 80 50 }
      $op1 = { 89 45 b8 c7 45 bc f7 ff ff ff 89 5d d4 89 5d f4 }
      $op2 = { 89 45 d4 c7 45 d8 f8 ff ff ff 89 7d f0 89 7d f4 }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

rule mimi_anti {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 15"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii 
      $s2 = "mZXixFpg.exe" fullword wide 
      $s3 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii 
      $s4 = "Copyright (c) 2007 - 2020 bIJ9xgPw5o (eTZHxXXY 52DdH)" fullword wide 
      $s5 = "GcircTRv" fullword ascii 
      $s6 = "acossqrt" fullword ascii 
      $s7 = "baagqqq" fullword ascii 
      $s8 = "nnmdjjj" fullword ascii 
      $s9 = "jklmnop" fullword ascii 
      $s10 = "onoffalsey" fullword ascii 
      $s11 = "NCKeyD`<d" fullword ascii 
      $s12 = "lCorE.Proces" fullword ascii 
      $s13 = "RRR.uuu" fullword ascii 
      $s14 = " erroFail" fullword ascii 
      $s15 = "Q.0F:\\" fullword ascii 
      $s16 = ".c:%d:%" fullword ascii 
      $s17 = "CHPJHAT" fullword ascii 
      $s18 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii 
      $s19 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii 
      $s20 = " @-OPrAT" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and  8 of them
}

rule mimi_anti1 {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 16"
   strings:
      $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii 
      $s2 = "gSAMLIB.dll" fullword ascii 
      $s3 = "QVERSION.dll" fullword ascii 
      $s4 = "mimikatz.exe" fullword wide 
      $s5 = "yCRYPT32.dll" fullword ascii 
      $s6 = "YSHLWAPI.dll" fullword ascii 
      $s7 = "Pmsasn1.dll" fullword ascii 
      $s8 = "[cWINSTA.dll" fullword ascii 
      $s9 = "curity><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel" ascii 
      $s10 = "7http://sha256timestamp.ws.symantec.com/sha256/timestamp0" fullword ascii 
      $s11 = "www.microsoft.com0" fullword ascii 
      $s12 = "=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii 
      $s13 = "mimikatz" fullword wide 
      $s14 = "Copyright (c) 2007 - 2019 gentilkiwi (Benjamin DELPY)" fullword wide 
      $s15 = "mimikatz for Windows" fullword wide 
      $s16 = "U:\"QS6" fullword ascii 
      $s17 = "fjN.TRl" fullword ascii 
      $s18 = "^f:\"Oh" fullword ascii 
      $s19 = "QZ0S.aLe" fullword ascii 
      $s20 = "3%i:^3" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and 8 of them
}

rule mimi_anti2 {
   meta:
      description = "Detect the risk of Malware Mimikatz Rule 17"
   strings:
      $s1 = "mimikatz.exe" fullword wide 
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii 
      $s3 = "7http://sha256timestamp.ws.symantec.com/sha256/timestamp0" fullword ascii 
      $s4 = "www.microsoft.com0" fullword ascii 
      $s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii 
      $s6 = "mimikatz" fullword wide 
      $s7 = "Copyright (c) 2007 - 2019 gentilkiwi (Benjamin DELPY)" fullword wide 
      $s8 = "msncucx" fullword ascii 
      $s9 = "ashcjsm" fullword ascii 
      $s10 = "lsmcpst" fullword ascii 
      $s11 = "iRNG9+ >" fullword ascii 
      $s12 = "mzhn9+ " fullword ascii 
      $s13 = "mimikatz for Windows" fullword wide 
      $s14 = "yDT:\\pE" fullword ascii 
      $s15 = "RiRC<m" fullword ascii 
      $s16 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii 
      $s17 = "GEt:h5Wm" fullword ascii 
      $s18 = "Zlaocpz" fullword ascii 
      $s19 = "Qnsfqlc" fullword ascii 
      $s20 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and 8 of them
}


rule FrpRule1{
   meta:
      description = "Detect the risk of Malware Frp Rule 1"
   strings:
      $x1 = "casgstatus: waiting for Gwaiting but is Grunnablechacha20poly1305: bad nonce length passed to Openchacha20poly1305: bad nonce le" ascii 
      $x2 = "Unexpected argument to `immutable`VirtualQuery for stack base failed^((\\d{4}-)?\\d{3}-\\d{3}(-\\d{1})?)?$adding nil Certificate" ascii 
      $x3 = "28421709430404007434844970703125: day-of-year does not match dayAssociate to %v blocked by rulesCertAddCertificateContextToStore" ascii 
      $x4 = "webpackJsonp([0],[function(e,t,o){var r=o(159);\"string\"==typeof r&&(r=[[e.i,r,\"\"]]);var n={hmr:!0};n.transform=void 0,n.inse" ascii 
      $x5 = " 2020 Denis Pushkarev (zloirock.ru)\"})},function(e,t){var o=Math.ceil,r=Math.floor;e.exports=function(e){return isNaN(e=+e)?0:(" ascii 
      $x6 = "target must be an absolute URL or an absolute path: %qtls: certificate used with invalid signature algorithmtls: client indicate" ascii 
      $x7 = "entersyscallexcludesrunefloat32Slicefloat64SlicegcBitsArenasgcpacertracegetaddrinfowhost is downhtml_encodedhttp2debug=1http2deb" ascii 
      $x8 = "Go pointer stored into non-Go memoryHeader called after Handler finishedHijack failed on protocol switch: %vIA5String contains i" ascii 
      $x9 = " because it doesn't contain any IP SANs2006-01-02 15:04:05.999999999 -0700 MST277555756156289135105907917022705078125Bad param n" ascii 
      $x10 = "Subject: AMDisbetter!AuthenticAMDBidi_ControlCIDR addressCONTINUATIONCentaurHaulsCoCreateGuidContent TypeContent-TypeCookie.Valu" ascii 
      $x11 = "Simply type handle tcp work connection, use_encryption: %t, use_compression: %treconstruction required as one or more required d" ascii 
      $x12 = "Unexpected argument to `proxy-revalidate`WriteHeader called after Handler finished[ERR] yamux: Invalid protocol version: %dasn1:" ascii 
      $x13 = "getenv before env initgzip: invalid checksumheadTailIndex overflowheader field %q = %q%shpack: string too longhttp2: frame too l" ascii 
      $x15 = "InitiateSystemShutdownExWIsValidSecurityDescriptorKaliningrad Standard TimeMiddle East Standard TimeNew Zealand Standard TimeNor" ascii 
      $x16 = ".WithDeadline(.in-addr.arpa.127.0.0.1:70001907348632812595367431640625: extra text: <not Stringer>Accept-CharsetCertCloseStoreCo" ascii 
      $x17 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrectgo with non-empty framehttp2: handle" ascii 
      $x18 = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-3[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$x509: signature check attempts limit reached while" ascii 
      $x19 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=plugin_http_userplugin_unix_pathproxy-connectionquoted-printable" ascii 
      $x20 = "span set block with unpopped elements found in resettls: internal error: session ticket keys unavailabletls: private key type do" ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 32000KB and 6 of ( $x* )
}

rule FrpRule2{
   meta:
      description = "Detect the risk of Malware Frp Rule 2"
   strings:
      $x1 = "Unexpected argument to `immutable`^((\\d{4}-)?\\d{3}-\\d{3}(-\\d{1})?)?$adding nil Certificate to CertPoolbad scalar length: %d," ascii 
      $x2 = "webpackJsonp([0],[function(e,t,o){var r=o(159);\"string\"==typeof r&&(r=[[e.i,r,\"\"]]);var n={hmr:!0};n.transform=void 0,n.inse" ascii 
      $x3 = "/etc/pki/tls/certs/ca-bundle.crt28421709430404007434844970703125: day-of-year does not match dayAssociate to %v blocked by rules" ascii 
      $x4 = " 2020 Denis Pushkarev (zloirock.ru)\"})},function(e,t){var o=Math.ceil,r=Math.floor;e.exports=function(e){return isNaN(e=+e)?0:(" ascii 
      $x5 = "bytes.Buffer: reader returned negative count from Readcertificate is not valid for requested server name: %wcryptobyte: Builder " ascii 
      $x6 = "got CONTINUATION for stream %d; expected stream %dheartbeat goroutine for udp work connection closedhttp: putIdleConn: CloseIdle" ascii 
      $x7 = "strings.Builder.Grow: negative countsyntax error scanning complex numbertls: keys must have at least one keytls: server did not " ascii 
      $x8 = "Go pointer stored into non-Go memoryHeader called after Handler finishedHijack failed on protocol switch: %vIA5String contains i" ascii 
      $x9 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii 
      $x10 = "heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid indexed representation index %dlocal_port " ascii 
      $x11 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii 
      $x12 = "casgstatus: waiting for Gwaiting but is Grunnablechacha20poly1305: bad nonce length passed to Openchacha20poly1305: bad nonce le" ascii 
      $x13 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=plugin_http_userplugin_unix_pathproxy-connectionquoted-printable" ascii 
      $x14 = "Only unicode is supportedPost webhook failed %s %dShellCompDirectiveDefaultShellCompDirectiveNoSpaceUnrecognized address type^(?" ascii 
      $x15 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Error while parsing flags from args %v: %sFa" ascii 
      $x16 = "getenv before env initgzip: invalid checksumheadTailIndex overflowheader field %q = %q%shpack: string too longhttp2: frame too l" ascii 
      $x17 = "span set block with unpopped elements found in resettls: internal error: session ticket keys unavailabletls: private key type do" ascii 
      $x18 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii 
      $x19 = "Unexpected argument to `proxy-revalidate`WriteHeader called after Handler finished[ERR] yamux: Invalid protocol version: %dasn1:" ascii 
      $x20 = " to non-Go memory , locked to thread/etc/nsswitch.conf/etc/pki/tls/certs298023223876953125404 page not found407 Not authorized: " ascii 
   condition:
      uint16(0) == 0x457f and filesize < 31000KB and
      6 of ($x*)
}

rule VenomRule1 {
   meta:
      description = "Detect the risk of Malware Venom Rule 1"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii 
      $x2 = "CertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedStartServiceCtrlDispatcherW[-]Can not find targ" ascii 
      $x3 = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpen" ascii 
      $x4 = "127.0.0.1:%d152587890625762939453125Bidi_ControlCreateEventWGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempP" ascii 
      $x5 = "ssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status != _Pgcstop)x509: invalid elliptic curve private" ascii 
      $x6 = " > (den<<shift)/2syntax error scanning numberx509: unknown elliptic curve45474735088646411895751953125Central America Standard T" ascii 
      $x7 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waitx509: failed t" ascii 
      $x8 = " of unexported method previous allocCount=%s flag redefined: %s186264514923095703125931322574615478515625AdjustTokenPrivilegesAl" ascii 
      $x9 = "unknown network workbuf is empty initialHeapLive= spinningthreads=%%!%c(big.Int=%s)0123456789ABCDEFX0123456789abcdefx06010215040" ascii 
      $x10 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing" ascii 
      $x11 = "Variation_Selector[-]Read file error[-]Separator errorbad manualFreeListbufio: buffer fullconnection refusedcontext.Backgroundec" ascii 
      $x12 = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard TimeWaitForMultipleObjects[+]Remote connecti" ascii 
      $x13 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii 
      $x14 = " lockedg= lockedm= m->curg= method:  ms cpu,  not in [ runtime= s.limit= s.state= threads= u_a/u_g= wbuf1.n= wbuf2.n=%!(EXTRA (M" ascii 
      $x15 = "bytes.Buffer: reader returned negative count from Readfmt: scanning called UnreadRune with no rune availablegcControllerState.fi" ascii 
      $x16 = "et nodeaddress not a stack addressadministratively prohibitedc:\\windows\\system32\\cmd.exechannel number out of rangecommunicat" ascii 
      $x17 = "tifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availablenon-minimal lengthoperat" ascii 
      $x18 = "invalid network interface nameinvalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol" ascii 
      $x19 = "bad flushGen bad map statechannelEOFMsgdalTLDpSugct?disconnectMsgempty integerexchange fullfatal error: gethostbynamegetservbyna" ascii 
      $x20 = "structure needs cleaningunexpected exponent baseunexpected mantissa baseunknown channel type: %v bytes failed with errno= to unu" ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 3 of ($x*) 
}

rule VenomRule2 {
   meta:
      description = "Detect the risk of Malware Venom Rule 2"
   strings:
      $x1 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchregexp: Compile(remote I/O errorruntime:  g:  g=" ascii 
      $x2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625SIGSEGV: segmentation violation[-]D" ascii 
      $x3 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablethe node is " ascii 
      $x4 = "sync: WaitGroup misuse: Add called concurrently with Waitthe port %d is successfully listening on the remote node!The `password`" ascii 
      $x6 = " > (den<<shift)/2syntax error scanning numberunsupported compression for you should select node first454747350886464118957519531" ascii 
      $x8 = " of unexported method previous allocCount=%s flag redefined: %s186264514923095703125931322574615478515625Anatolian_HieroglyphsFl" ascii 
      $x9 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii 
      $x10 = " to unallocated span%%!%c(*big.Float=%s)/usr/share/zoneinfo/37252902984619140625: leftover defer sp=Bar pool was startedEgyptian" ascii 
      $x11 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625MapIter.Value called on exhausted iterator[-" ascii 
      $x12 = " H_T= H_a= H_g= MB,  W_a= and  cnt= h_a= h_g= h_t= max= ptr  siz= tab= top= u_a= u_g=%%%dd%s %d%s %s%s%dh%s:%d+ -- , ..., fp:/et" ascii 
      $x13 = "garbage collection scangcDrain phase incorrectinterrupted system callinvalid escape sequenceinvalid m->lockedInt = left over mar" ascii 
      $x15 = "unixpacketunknown pc  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing= ms clock" ascii 
      $s16 = "/dev/urandom127.0.0.1:%d127.0.0.1:53152587890625762939453125Bidi_ControlCIDR addressI/O possibleInstAltMatchJoin_ControlMeetei_M" ascii    
      $s18 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: unk" ascii 
      $s19 = "runtime:greyobject: checkmarks finds unexpected unmarked object obj=this file is too large(>100M), do you still want to upload i" ascii 
      $s20 = "bytes.Buffer: reader returned negative count from Readfmt: scanning called UnreadRune with no rune availablegcControllerState.fi" ascii 
   condition:
      uint16(0) == 0x457f and filesize < 9000KB and
      2 of ($x*) and 2 of ($s*)
}

rule VenomRule3 {
   meta:
      description = "Detect the risk of Malware Venom Rule 3"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangessh: unmarshal error for field %s of" ascii 
      $x2 = "Failed to deserialize context %sSIGFPE: floating-point exceptionSIGTTOU: background write to tty[+]Connect to a new node success" ascii 
      $x3 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Failed to parse goroutine ID out of %q: %vPR" ascii 
      $x4 = "%s flag redefined: %s186264514923095703125931322574615478515625Anatolian_HieroglyphsError: No such loggerFloat.SetFloat64(NaN)In" ascii 
      $x5 = "0123456789ABCDEFX0123456789abcdefx060102150405Z07001192092895507812559604644775390625: missing method ; SameSite=StrictCOMPRESSI" ascii 
      $x6 = "%{([a-z]+)(?::(.*?[^\\\\]))?}' to delete iptables rules.363797880709171295166015625DATA frame with stream ID 0G waiting list is " ascii 
      $x7 = "reflect.Value.Bytes of non-byte slicereflect.Value.Bytes of non-rune slicereflect.Value.Convert: value of type reflect: Bits of " ascii 
      $x8 = "heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid indexed representation index %dmismatched " ascii 
      $x9 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii 
      $x10 = "ssh connect to target node error: %sssh: StdinPipe after process startedssh: overflow reading version stringssh: tcpChan: deadli" ascii 
      $x11 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Network Authentication RequiredPRIO" ascii 
      $x12 = " > (den<<shift)/2syntax error scanning numbertls: bad X25519 public valueunexpected end of JSON inputunexpected protocol version" ascii 
      $x13 = "Time.MarshalBinary: zone offset has fractional minute[-]Socks consult transfer mode or parse target error:bufio.Scan: too many e" ascii 
      $x14 = "file descriptor in bad statefindrunnable: netpoll with pgchelperstart: bad m->helpgcgcstopm: negative nmspinninggeneral SOCKS se" ascii 
      $x15 = "protobuf tag not enough fields in reflect.FuncOf: too many argumentsreflect: Field index out of boundsreflect: Method index out " ascii 
      $x16 = "crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled%{time:2006-01-02 15:04:05.000000} %{level} %{modul" ascii 
      $x17 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: stat underflow: val runtime: sudog with non-nil cruntime: unk" ascii 
      $x18 = "got CONTINUATION for stream %d; expected stream %dhttp: not caching alternate protocol's connectionshttp: putIdleConn: CloseIdle" ascii 
      $x19 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii 
      $x20 = "a message with extensions, but no extensions field in bytes.Buffer: reader returned negative count from Readfmt: scanning called" ascii 
   condition:
      uint16(0) == 0x457f and filesize < 23000KB and
      10 of ($x*)
}


rule PystingerRule1 {
   meta:
      description = "Detect the risk of Malware Pystinger Rule 1"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii 
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii 
      $s3 = "Failed to get executable path." fullword ascii 
      $s4 = "Failed to execute script %s" fullword ascii 
      $s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii 
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii 
      $s7 = "Failed to get address for PyRun_SimpleString" fullword ascii 
      $s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii 
      $s9 = "Failed to get address for PyUnicode_Decode" fullword ascii 
      $s10 = "GVDVFVEVG" fullword ascii 
      $s11 = "Failed to get address for Py_NoSiteFlag" fullword ascii 
      $s12 = "Failed to get address for PySys_AddWarnOption" fullword ascii 
      $s13 = "Failed to get address for PyErr_Clear" fullword ascii 
      $s14 = "Failed to get address for Py_DecRef" fullword ascii 
      $s15 = "Failed to get address for PyEval_EvalCode" fullword ascii 
      $s16 = "Failed to get address for Py_BuildValue" fullword ascii 
      $s17 = "Failed to get address for PyErr_Print" fullword ascii 
      $s18 = "Failed to get address for _Py_char2wchar" fullword ascii 
      $s19 = "logging.config(" fullword ascii 
      $s20 = "Error loading Python DLL '%s'." fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and 8 of them
}

rule PystingerRule2 {
   meta:
      description = "Detect the risk of Malware Pystinger Rule 2"
   strings:
      $s1 = "Failed to execute script %s" fullword ascii 
      $s2 = "Fatal error: unable to decode the command line argument #%i" fullword ascii 
      $s3 = "logging.config(" fullword ascii 
      $s4 = "Failed to get _MEIPASS as PyObject." fullword ascii 
      $s5 = "Cannot dlsym for PyImport_ExecCodeModule" fullword ascii 
      $s6 = "pyi-bootloader-ignore-signals" fullword ascii 
      $s7 = "http.cookies(" fullword ascii 
      $s8 = "wsgiref.headers(" fullword ascii 
      $s9 = "Installing PYZ: Could not get sys.path" fullword ascii 
      $s10 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii 
      $s11 = "Error loading Python lib '%s': dlopen: %s" fullword ascii 
      $s12 = "pyi-runtime-tmpdir" fullword ascii 
      $s13 = "http.client(" fullword ascii 
      $s14 = "e /p p$p8p4p," fullword ascii 
      $s15 = "* s1_>" fullword ascii 
      $s16 = "Could not get __main__ module." fullword ascii 
      $s17 = "'6-2=2#232+" fullword ascii 
      $s18 = "bunicodedata.so" fullword ascii 
      $s19 = "boperator.so" fullword ascii 
      $s20 = "Could not get __main__ module's dict." fullword ascii 
   condition:
      uint16(0) == 0x457f and filesize < 19000KB and
      8 of them
}

rule EarthWormRule1
{
    meta:
       description = "Detect the risk of Malware EarthWorm Rule 1"
    strings:
        $elf = {7f 45 4c 46}
        $string_1 = "I_AM_NEW_RC_CMD_SOCK_CLIENT"
        $string_2 = "CONFIRM_YOU_ARE_SOCK_CLIENT"
        $string_3 = "SOCKSv4 Not Support now!"
        $string_4 = "rssocks cmd_socket OK!"

    condition:
        $elf at 0 and 2 of them
}

rule EarthWormRule2
{
 meta:
    description = "Detect the risk of Malware EarthWorm Rule 2"
    strings:
        $elf = {7f 45 4c 46}
        $string_1 = "File data send OK!"
        $string_2 = "please set the target first"
        $string_3 = "It support various OS or CPU.For example"
        $string_4 = "xxx -l [lport] -n [name]"

condition:
    $elf at 0 and 2 of them
}

rule EarthWormRule3{
   meta:
      description = "Detect the risk of Malware EarthWorm Rule 3"
   strings:
      $s1 = " ./ew -s lcx_tran --listenport 1080 -connhost xxx.xxx.xxx.xxx --connport 8888" fullword ascii 
      $s2 = " ./ew -s rssocks --refHost xxx.xxx.xxx.xxx --refPort 8888" fullword ascii 
      $s3 = " -d refhost set the reflection host address." fullword ascii 
      $s4 = " ./ew -s lcx_slave --refhost [ref_ip] --refport 1080 -connhost [connIP] --connport 8888" fullword ascii 
      $s5 = " -f connhost set the connect host address ." fullword ascii 
      $s6 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii 
      $s7 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii 
      $s8 = "Error : --> %d start server." fullword ascii 
      $s9 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii 
      $s10 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii 
      $s11 = "Error : bind port %d ." fullword ascii 
      $s12 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii 
      $s13 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii 
      $s14 = " Tcp ---> %s:%d " fullword ascii 
      $s15 = " ./ew -s lcx_listen --listenPort 1080 --refPort 8888" fullword ascii 
      $s16 = " ./ew -s ssocksd --listenport 1080" fullword ascii 
      $s17 = " -e refport set the reflection port." fullword ascii 
      $s18 = " -g connport set the connect port." fullword ascii 
      $s19 = "Error : Could not create socket [ port = %d ]." fullword ascii 
      $s20 = " ./ew -s rcsocks --listenPort 1080 --refPort 8888" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 8 of them
}

rule NPSRule1 {
   meta:
      description = "Detect the risk of Malware NPS Rule 1"
   strings:
      $x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii 
      $x2 = "FilledVerySmallSquare;Georgian Standard TimeGetControllerAndActionGetEnvironmentStringsWGetTimeZoneInformationHawaiian Standard " ascii 
      $x3 = "lock: lock countservice %s already existsservice function disabledslice bounds out of rangesnappy: unsupported inputsocket type " ascii 
      $x4 = "tag handle must contain alphanumerical characters onlytarget must be an absolute URL or an absolute path: %qtls: certificate use" ascii 
      $x5 = "%sidentifier on left side of :=ilnpv6 locator update messageinteger not minimally-encodedinternal error: took too muchinvalid bl" ascii 
      $x6 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthealth_check_max_failedhtml/template" ascii 
      $x7 = "Subject: AMDisbetter!AVX512BITALGAuthenticAMDBeegoVersionBidi_ControlCIDR addressCONTENT_TYPECONTINUATIONCentaurHaulsCircleMinus" ascii 
      $x8 = "sender tried to send more than declared Content-Length of %d bytestls: certificate private key (%T) does not implement crypto.Si" ascii 
      $x9 = "debugPtrmask.lockdecryption faileddeprecated formatdiscarded samplesdownharpoonright;entersyscallblockexec format errorexec: not" ascii 
      $x10 = "%s %s:%d s=%d, gp->status=, not pointer,\"filename\":\"-byte block (/([^.]+).(.+)/debug/pprof//etc/rc.d/K02/etc/rc.d/S9038146972" ascii 
      $x11 = "%s.%s.ka.acme.invalid(?m)^\\[[^\\[\\]\\r\\n]+\\](SpinLock::)?Unlock.*, levelBits[level] = 18626451492309570312593132257461547851" ascii 
      $x12 = "    beego.GlobalControllerRouter[\"acme/autocert: no token cert for %qacme: certificate chain is too deepacme: certificate chain" ascii 
      $x13 = "%s \"%s\"__restoreandslope;angmsdaa;angmsdab;angmsdac;angmsdad;angmsdae;angmsdaf;angmsdag;angmsdah;angrtvbd;approxeq;assets_jsat" ascii 
      $x14 = "WriteHeader called after Handler finishedapplication/vndnokiaconfiguration-messageasn1: internal error in parseTagAndLengthbinar" ascii 
      $x15 = "Stack traces of holders of contended mutexesapplication/x-bytecodeelisp=(compiled=elisp)cipher: NewGCM requires 128-bit block ci" ascii 
      $x16 = "%s.%s.acme.invalid(Mutex::)?Unlock.*, locked to thread/debug/pprof/trace1 or 2 expressions114.114.114.114:5329802322387695312540" ascii 
      $x17 = "runtime: typeBitsBulkBarrier without typeseconds and debug params are incompatiblesetCheckmarked and isCheckmarked disagreestart" ascii 
      $x18 = "UnsubscribeServiceChangeNotifications_cgo_notify_runtime_init_done missingacme/autocert: Manager.Prompt not setacme/autocert: ce" ascii 
      $x19 = "MapIter.Value called before NextMultiple ,inline maps in struct NtWow64QueryInformationProcess64SYSTEM\\CurrentControlSet\\Contr" ascii 
      $x20 = "            Method: \"bufio.Scanner: SplitFunc returns advance count beyond inputcannot create Encoder with more than 256 data+p" ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 36000KB and 3 of ( $x* )
}

rule NPSRule2 {
   meta:
      description = "Detect the risk of Malware NPS Rule 2"
   strings:
      $x1 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii 
      $x2 = "lock: lock countservice function disabledslice bounds out of rangesnappy: unsupported inputsocket type not supportedstartm: p ha" ascii 
      $x3 = "FilledVerySmallSquare;GetControllerAndActionInscriptional_ParthianInt.Scan: invalid verbMAX_CONCURRENT_STREAMSNegativeVeryThinSp" ascii 
      $x4 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii 
      $x5 = "_cgo_notify_runtime_init_done missingacme/autocert: Manager.Prompt not setacme/autocert: certificate cache missacme/autocert: un" ascii 
      $x6 = "acme/autocert: host %q not configured in HostWhitelistapplication/vnd.ms-powerpoint.template.macroEnabled.12bytes.Buffer: reader" ascii 
      $x7 = "debugPtrmask.lockdecryption faileddeprecated formatdiscarded samplesdownharpoonright;entersyscallblockexec format errorexec: not" ascii 
      $x8 = "Stack traces of holders of contended mutexesapplication/x-bytecodeelisp=(compiled=elisp)cipher: NewGCM requires 128-bit block ci" ascii 
      $x9 = "WriteHeader called after Handler finishedapplication/vndnokiaconfiguration-messageasn1: internal error in parseTagAndLengthbinar" ascii 
      $x10 = "x509: PKCS#8 wrapping contained private key with unknown algorithm: %vapplication/vnd.openxmlformats-officedocument.wordprocessi" ascii 
      $x11 = "%s.%s.acme.invalid(Mutex::)?Unlock.*, locked to thread/debug/pprof/trace/etc/nsswitch.conf/etc/openssl/certs/etc/pki/tls/certs1 " ascii 
      $x12 = "%s.%s.ka.acme.invalid(?m)^\\[[^\\[\\]\\r\\n]+\\](SpinLock::)?Unlock.*, levelBits[level] = 18626451492309570312593132257461547851" ascii 
      $x13 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrectgroup: unknown groupid health_check_" ascii 
      $x14 = "    beego.GlobalControllerRouter[\"acme/autocert: no token cert for %qacme: certificate chain is too deepacme: certificate chain" ascii 
      $x15 = "173472347597680709441192448139190673828125867361737988403547205962240695953369140625Failed to parse goroutine ID out of %q: %vLo" ascii 
      $x16 = "= but have  flushGen  for type  gfreecnt= pages at  returned  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepg" ascii 
      $x17 = "heap profile: *(\\d+): *(\\d+) *\\[ *(\\d+): *(\\d+) *\\] @ fragmentationzhttp2: Transport conn %p received error from processin" ascii 
      $x18 = "x509: unknown elliptic curvexz: block header not writtenxz: checksum error for blockxz: record %d is %v; want %vxz: unsupported " ascii 
      $x19 = "__gnu_cxx::new_allocator::allocateacme/autocert: expired certificateacme/autocert: missing certificateacme/autocert: missing ser" ascii 
      $x20 = "net/http: skip alternate protocolpad size larger than data payloadpseudo header field after regularraw string literal not termin" ascii 
   condition:
      uint16(0) == 0x457f and filesize < 35000KB and
      8 of ($x*)
}

rule FscanRule1 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 1"
   strings:
      $s1 = "3c4c5c6c7c" ascii 
      $s2 = "ze/processOp:ons7" fullword ascii 
      $s3 = "sbGVjdGlU" fullword ascii 
      $s4 = "LjgzODQxND" fullword ascii 
      $s5 = "5c%: && '!''%'(" fullword ascii 
      $s6 = "L21qb2wvZXBk" fullword ascii 
      $s7 = "d0d1d2d3d5" ascii 
      $s8 = "ransport" fullword ascii 
      $s9 = "templaL" fullword ascii 
      $s10 = "runbcdl" fullword ascii 
      $s11 = "dxqp.USw" fullword ascii 
      $s12 = "\\.2334\\" fullword ascii 
      $s13 = "pgdll547" fullword ascii 
      $s14 = "IDENTIF" fullword ascii 
      $s15 = "THPINGPEPLUSPORTS" fullword ascii 
      $s16 = "* YpINp" fullword ascii 
      $s17 = "u^sYnRJgeT" fullword ascii 
      $s18 = "%'W* -" fullword ascii 
      $s19 = "* I!-," fullword ascii 
      $s20 = "6c3a.5e78" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and 8 of them 
}

rule FscanRule2 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 2"
   strings:
      $s1 = "onmlkji" fullword ascii 
      $s2 = "pqrstu" fullword ascii 
      $s3 = "aGVycywgYW5" fullword ascii 
      $s4 = "U3ByaW5nQmxhZGU+" fullword ascii 
      $s5 = "MGFiY2RlZ" fullword ascii 
      $s6 = "YXBhY2hlL" fullword ascii 
      $s7 = "LjgzODQxNDMv" fullword ascii 
      $s8 = "ACLITEMP" fullword ascii 
      $s9 = "gethped" fullword ascii 
      $s10 = "bsddlln" fullword ascii 
      $s11 = "5c%: && '!''%" fullword ascii 
      $s12 = "IQtY:\\\\" fullword ascii 
      $s13 = "999!!!!" fullword ascii 
      $s14 = "\\2345\\." fullword ascii 
      $s15 = "*$xoLR:\\" fullword ascii 
      $s16 = "cceu:\"pt" fullword ascii 
      $s17 = ",getL0og" fullword ascii 
      $s18 = "%\"(5;-1," fullword ascii 
      $s19 = "* |iaH" fullword ascii 
      $s20 = "\";476837" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and 8 of them
}

rule FscanRule3 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 3"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii 
      $s2 = "ize/processOp" fullword ascii 
      $s3 = ".TGphdmEvdXR" fullword ascii 
      $s4 = "LjgzODQxNDM" fullword ascii 
      $s5 = "MGFiY2RlZ" fullword ascii 
      $s6 = "gethped" fullword ascii 
      $s7 = "CPRI * HTTP/2.0ZF" fullword ascii 
      $s8 = "\\:W!!!!" fullword ascii 
      $s9 = "333333i" fullword ascii 
      $s10 = "templaL" fullword ascii 
      $s11 = "U3ByaW5nQmxhZGU5" fullword ascii 
      $s12 = "GEYe\\h" fullword ascii 
      $s13 = "_/sys/kernel/mm/tf" fullword ascii 
      $s14 = "retkey " fullword ascii 
      $s15 = "4.3.3322!#6334" fullword ascii 
      $s16 = "2!0-3&023" fullword ascii 
      $s17 = "51`\"$$?." fullword ascii 
      $s18 = "]@`@%3\\0" fullword ascii 
      $s19 = "LoggyNF^" fullword ascii 
      $s20 = "4*+,<'-''.4" fullword ascii 
   condition:
      uint16(0) == 0x457f and filesize < 30000KB and
      8 of them
}

rule FscanRule4 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 4"

   strings:
      $x1 = "adding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, expected %dcan't parse %q as a decima" ascii 
      $x2 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeschema_and_data_statement_mixing_not" ascii 
      $x3 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchregexp: Compile(remote I/O error" ascii 
      $x4 = "ssh: overflow reading version stringssh: tcpChan: deadline not supportedstrings.Builder.Grow: negative countsyntax error scannin" ascii  
      $x6 = "heapBitsSetTypeGCProg: small allocationhttp: putIdleConn: keep alives disabledinvalid indexed representation index %dinvalid_arg" ascii  
      $x9 = "fdw_invalid_use_of_null_pointerfmt: unknown base; can't happenhttp2: connection error: %v: %vin literal null (expecting 'l')in l" ascii 
      $x10 = "Failed to send CommitXact with %vGODEBUG: no value specified for \"SIGCHLD: child status has changedSIGTTIN: background read fro" ascii 
      $x11 = "Closing TCP connectionDEBUG_HTTP2_GOROUTINESECDSAWithP256AndSHA256ECDSAWithP384AndSHA384ECDSAWithP521AndSHA512Entering Passive M" ascii 
      $x12 = "Command unrecognized.GSSAPI protocol errorInscriptional_PahlaviInternal Server ErrorOther_Grapheme_ExtendPrecondition RequiredRe" ascii 
      $x13 = "%v SSH public key was written successfully173472347597680709441192448139190673828125867361737988403547205962240695953369140625Ba" ascii 
      $x14 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii 
      $x15 = "x509: PKCS#8 wrapping contained private key with unknown algorithm: %vUnexpected character %c at index %d. Expected semi-colon o" ascii 
      $x16 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected ReadyForQueryunexpected buffer len=%vunknown " ascii 
      $x17 = "got CONTINUATION for stream %d; expected stream %dhttp: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trai" ascii 
      $x18 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii 
      $x19 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii 
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii 
   condition:
      uint16(0) == 0x457f and filesize < 22000KB and
      4 of ($x*)
}


rule FscanRule5 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 5"
   strings:
      $x1 = "Invalid field. Cannot determine length.Unable to find tree path for disconnectchain is not signed by an acceptable CAcipher: inc" ascii 
      $x2 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, exp" ascii 
      $x3 = "slice bounds out of range [:%x] with length %ysql/driver: couldn't convert %d into type boolsql/driver: couldn't convert %q into" ascii 
      $x4 = " > (den<<shift)/2string_data_right_truncationunexpected %q after error %sunexpected Parse response %qunexpected end of JSON inpu" ascii 
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchregexp: Compile(remote I/O error" ascii 
      $x6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii 
      $x7 = "ssh: unexpected packet in response to channel open: %Ttls: certificate used with invalid signature algorithmtls: found unknown p" ascii 
      $x8 = "Caucasus Standard TimeClosing TCP connectionConvertSidToStringSidWConvertStringSidToSidWCreateEnvironmentBlockCreateIoCompletion" ascii 
      $x9 = "Belarus Standard TimeCentral Standard TimeCommand unrecognized.Eastern Standard TimeGSSAPI protocol errorGetProfilesDirectoryWIn" ascii 
      $x10 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii 
      $x11 = "driver.ErrBadConn in checkBadConn. This should not happen.http2: client connection force closed via ClientConn.Closejson: cannot" ascii 
      $x12 = "Failed to send CommitXact with %vGODEBUG: no value specified for \"Sending NegotiateProtocol requestbad point length: %d, expect" ascii 
      $x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii 
      $x14 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii 
      $x15 = "entersyscallexit status failoverportgcBitsArenasgcpacertracegetaddrinfowgot token %vhmac-sha1-96host is downhttp2debug=1http2deb" ascii 
      $x16 = "INSERTBULKINT2VECTORIP addressKEEP_NULLSKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_Turk" ascii 
      $x17 = "[*]Not ExtendedNot ModifiedOPTS UTF8 ONPG_ATTRIBUTEPG_NODE_TREEPUSH_PROMISEPahawh_HmongRCodeRefusedRCodeSuccessREGNAMESPACEREGPR" ascii 
      $x18 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected ReadyForQueryunexpected buffer len=%vunknown " ascii 
      $x19 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii 
      $x20 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and 3 of ($x*) 
}

rule FscanRule6 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 6"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii 
      $s2 = "SZTZVZWZ2" fullword ascii 
      $s3 = "zODQxNDMxMjQz" fullword ascii 
      $s4 = " 6# $,\\6+ ," fullword ascii 
      $s5 = "templa" fullword ascii 
      $s6 = "I * HTTP/2.0" fullword ascii 
      $s7 = ">@ABCD" fullword ascii 
      $s8 = "prfaildmu" fullword ascii 
      $s9 = "i?master secretkey 6" fullword ascii 
      $s10 = "gethped2" fullword ascii 
      $s11 = "getL(og\"<" fullword ascii 
      $s12 = "~ 2!2\"2#2$2%2&2'2" fullword ascii 
      $s13 = "* O'RQ" fullword ascii 
      $s14 = "FtPh,NY" fullword ascii 
      $s15 = "fGet2r%" fullword ascii 
      $s16 = "myhostnaM9\"" fullword ascii 
      $s17 = "2!0-3&023" fullword ascii 
      $s18 = "(4 3%4'3\"" fullword ascii 
      $s19 = "%/41/2;-+-!4*" fullword ascii 
      $s20 = "xWORKLOG" fullword ascii 
   condition:
      uint16(0) == 0x457f and filesize < 20000KB and
      7 of them
}

rule FscanRule7 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 7"
   strings:
      $s1 = "RZSZTZVZW" fullword ascii 
      $s2 = "aGVycywgYW5" fullword ascii 
      $s3 = "e/processOp:ons7" fullword ascii 
      $s4 = "PROT_EXEC|PROT_WRITE failed." fullword ascii 
      $s5 = "OnRydWV9eb" fullword ascii 
      $s6 = "SRHR0cHM6Ly93" fullword ascii 
      $s7 = "=TT5uZnR0Ymhm" fullword ascii 
      $s8 = "UDUDUD" fullword ascii 
      $s9 = "master secretkey " fullword ascii 
      $s10 = "pqrst<" fullword ascii 
      $s11 = "L21qb2wvZXBk" fullword ascii 
      $s12 = "221222" ascii 
      $s13 = "3FCPRI * HTTP/2.0" fullword ascii 
      $s14 = "=>?@AB" fullword ascii 
      $s15 = "<$$$%%" fullword ascii 
      $s16 = "123456789ABCDEFtag:\"(" fullword ascii 
      $s17 = "\\2$1\\4$3." fullword ascii 
      $s18 = "Odum.AwY'j" fullword ascii 
      $s19 = "yaml.org,2" fullword ascii 
      $s20 = "ZZkt.agj" fullword ascii 
   condition:
      uint16(0) == 0x457f and filesize < 20000KB and
      8 of them
}

rule FscanRule8 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 8"
   strings:
      $s1 = "SZTZVZWZL" fullword ascii 
      $s2 = "XjEkfCxOE" fullword ascii 
      $s3 = "zODQxNDMxMjQz" fullword ascii 
      $s4 = "gethped" fullword ascii 
      $s5 = "templa" fullword ascii 
      $s6 = "prfaildmu" fullword ascii 
      $s7 = ".dllgq" fullword ascii 
      $s8 = "miNm.mmo" fullword ascii 
      $s9 = "dVyy:\\3" fullword ascii 
      $s10 = "\\4567\\." fullword ascii 
      $s11 = "FanX.PQX" fullword ascii 
      $s12 = "NTLMSSPH" fullword ascii 
      $s13 = "WSAGetOv" fullword ascii 
      $s14 = "*6:\"*\"F" fullword ascii 
      $s15 = "<2E2f@&`," fullword ascii 
      $s16 = "?2.16.840" fullword ascii 
      $s17 = "* B+xz" fullword ascii 
      $s18 = "~ ~'~(~,~-~/~3~6~" fullword ascii 
      $s19 = "4`6`7`8`$  " fullword ascii 
      $s20 = "\";476837" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and  3 of them 
}

rule FscanRule9 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 9"
   strings:
      $s1 = "xyyyyzy" fullword ascii 
      $s2 = ";<<<<=" fullword ascii 
      $s3 = "uzesslkukey" fullword ascii 
      $s4 = "NSpq.GSsql.DBv" fullword ascii 
      $s5 = "* )N,,+8," fullword ascii 
      $s6 = "* A1Q:" fullword ascii 
      $s7 = "\"zftpgE;fkgc " fullword ascii 
      $s8 = "wChCeye" fullword ascii 
      $s9 = "41/2;-+-!4*" fullword ascii 
      $s10 = "ANCELCIRCLE$Q" fullword ascii 
      $s11 = "!%(+.~4!1" fullword ascii 
      $s12 = "),.2-b0,/\"0" fullword ascii 
      $s13 = "nAX* -" fullword ascii 
      $s14 = "|FtprK!#pjHu" fullword ascii 
      $s15 = "(,4 \"0 '$@" fullword ascii 
      $s16 = "bsostsxs" fullword ascii 
      $s17 = "qrsuxyy" fullword ascii 
      $s18 = "rissedrub" fullword ascii 
      $s19 = "nopquwz" fullword ascii 
      $s20 = "zpcderiv" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and 4 of them 
}

rule FscanRule10 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 10"
   strings:
      $s1 = "aW5nQmxhZGU5c" fullword ascii 
      $s2 = "LjgzODQxNDM" fullword ascii 
      $s3 = "MGFiY2RlZ" fullword ascii 
      $s4 = "aGVycywgYW5m" fullword ascii 
      $s5 = "UDUDUD" fullword ascii 
      $s6 = "pqrst<" fullword ascii 
      $s7 = "templaLR" fullword ascii 
      $s8 = "RHR0cHM6Ly93" fullword ascii 
      $s9 = "221222" ascii 
      $s10 = "=>?@AB" fullword ascii 
      $s11 = "fprfaildmueat" fullword ascii 
      $s12 = "bsddll" fullword ascii 
      $s13 = " /y G)" fullword ascii 
      $s14 = "252D /267A " fullword ascii 
      $s15 = "$%&'()2!8@" fullword ascii 
      $s16 = "ftpgE;gc gj0m" fullword ascii 
      $s17 = "@>@5000@." fullword ascii 
      $s18 = "Q[SlogVm%" fullword ascii 
      $s19 = "$GrGet2k" fullword ascii 
      $s20 = "[ /s R" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and 8 of them
}

rule FscanRule11 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 11"
   strings:
      $s1 = "processOp:ons7" fullword ascii 
      $s2 = "PROT_EXEC|PROT_WRITE failed." fullword ascii 
      $s3 = "   !!!" fullword ascii 
      $s4 = "U3ByaW5nQmxhZGU" fullword ascii 
      $s5 = "MGFiY2RlZ" fullword ascii 
      $s6 = "aGVycywgYk" fullword ascii 
      $s7 = "UDUDUD" fullword ascii 
      $s8 = "PQQQQR" fullword ascii 
      $s9 = "bCPRI * HTTP/2.0#B0" fullword ascii 
      $s10 = "100101" ascii 
      $s11 = "templaL" fullword ascii 
      $s12 = "=>?@AB" fullword ascii 
      $s13 = "Z3Vlc3Q6P0" fullword ascii 
      $s14 = "\\.+2267_" fullword ascii 
      $s15 = "TueURIUTCVaiViaWedX:\"LX" fullword ascii 
      $s16 = "gethped8" fullword ascii 
      $s17 = " method:\"S" fullword ascii 
      $s18 = "O:\\yyyyd" fullword ascii 
      $s19 = "cretkey " fullword ascii 
      $s20 = "* LJD5LY" fullword ascii 
   condition:
      uint16(0) == 0x457f and filesize < 20000KB and
      8 of them
}

rule FscanRule12 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 12"
   strings:
      $s1 = "mTmVmWmZm" fullword ascii 
      $s2 = "templa" fullword ascii 
      $s3 = "yOip 2%S%oli" fullword ascii 
      $s4 = "\\5667\\." fullword ascii 
      $s5 = " (/7=E44." fullword ascii 
      $s6 = "~ ~'~(~,~-~/~3~6~" fullword ascii 
      $s7 = "lspyc.y" fullword ascii 
      $s8 = "* V-X<K" fullword ascii 
      $s9 = " $}3-4-3+e" fullword ascii 
      $s10 = "6F%}^6e\"" fullword ascii 
      $s11 = "2!0-3&023" fullword ascii 
      $s12 = "WSAGetOvY" fullword ascii 
      $s13 = "(BP - " fullword ascii 
      $s14 = "nIRC2n%+I" fullword ascii 
      $s15 = " 2!2\"2#2$2%2&2'2" fullword ascii 
      $s16 = "kernel32Il" fullword ascii 
      $s17 = "_\")2^2({" fullword ascii 
      $s18 = "41/2;-+-!4*" fullword ascii 
      $s19 = "[/\\2222]^_`(" fullword ascii 
      $s20 = ".IJm2g vZhIrCH" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and 7 of them
}

rule FscanRule13 {
   meta:
      description = "Detect the risk of Malware Fscan Rule 13"
   strings:
      $s1 = "cdefgi" fullword ascii 
      $s2 = "aGVycywgYW5" fullword ascii 
      $s3 = " YXNzd2Q=" fullword ascii 
      $s4 = "=TT5uZnR0YmhmL21qb2wvZXB" fullword ascii 
      $s5 = "sckddll" fullword ascii 
      $s6 = "gethped" fullword ascii 
      $s7 = "#yKey1keye\\s" fullword ascii 
      $s8 = "100101" ascii 
      $s9 = "templaL" fullword ascii 
      $s10 = "prfaildmu" fullword ascii 
      $s11 = "ddllnv" fullword ascii 
      $s12 = "KHrp:\"" fullword ascii 
      $s13 = "\\rr* -" fullword ascii 
      $s14 = "HPINGPEPLUSPORTSR" fullword ascii 
      $s15 = "Al.CmWftp.Ns" fullword ascii 
      $s16 = "'\"7\"C\"" fullword ascii 
      $s17 = "\"bGet2`,&Dtcx" fullword ascii 
      $s18 = "seuevexeyeze{e|e}e~e" fullword ascii 
      $s19 = "getL^OR" fullword ascii 
      $s20 = "####4?7;####%)" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and 7 of them
}

rule FscanRule14{
   meta:
      description = "Detect the risk of Malware Fscan Rule 14"
   strings:
      $s1 = "eempndnpy" fullword ascii 
      $s2 = "fedcba" ascii 
      $s3 = "aGVycywgYW5" fullword ascii 
      $s4 = " YXNzd2Q=" fullword ascii 
      $s5 = "0YmhmL21qb2wvZXBk" fullword ascii 
      $s6 = "ZDUiOnRydWV9e" fullword ascii 
      $s7 = "UDUDUD" fullword ascii 
      $s8 = "cm9vdDpyb" fullword ascii 
      $s9 = "irunbcd" fullword ascii 
      $s10 = "4,-./0" fullword ascii 
      $s11 = "IQtY:\\\\" fullword ascii 
      $s12 = "\\2345\\." fullword ascii 
      $s13 = "bsddll" fullword ascii 
      $s14 = "NTLMDSS" fullword ascii 
      $s15 = ",getL0og" fullword ascii 
      $s16 = "%\"(5;-1," fullword ascii 
      $s17 = "\";476837" fullword ascii 
      $s18 = "Slogj+!" fullword ascii 
      $s19 = "2!0-3&023" fullword ascii 
      $s20 = ",[$2222 (" fullword ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and 8 of them
}

rule FscanRule15{
   meta:
      description = "Detect the risk of Malware Fscan Rule 15"
   strings:
      $s1 = "onmlkji" fullword ascii 
      $s2 = "LjgzODQxNDM" fullword ascii 
      $s3 = "MGFiY2RlZ" fullword ascii 
      $s4 = "XjEkfCxOE" fullword ascii 
      $s5 = "YXBhY2hlL" fullword ascii 
      $s6 = "aGVycywgYW5m" fullword ascii 
      $s7 = "circrsy" fullword ascii 
      $s8 = "RHR0cHM6Ly93" fullword ascii 
      $s9 = "bE0kNSMAE" fullword ascii
      $s10 = "fsieye" fullword ascii 
      $s11 = "ECSHSfFHRSHSE.SUb" fullword ascii 
      $s12 = "HV -v >O" fullword ascii 
      $s13 = "B.CmWftp." fullword ascii 
      $s14 = "'57.4;2\\-" fullword ascii 
      $s15 = "seuevexeyeze{e|e}e~e" fullword ascii 
      $s16 = ",h1,p=,r=- -j" fullword ascii 
      $s17 = "2!0-3&023" fullword ascii 
      $s18 = "* m\\9P" fullword ascii 
      $s19 = ".g4CIRCLEDj" fullword ascii 
      $s20 = "* ::}A" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and 8 of them
}

private rule cobaltstrike_template_exe
{
    strings:
        $compiler = "mingw-w64 runtime failure" nocase

        $f1 = "VirtualQuery"   fullword
        $f2 = "VirtualProtect" fullword
        $f3 = "vfprintf"       fullword
        $f4 = "Sleep"          fullword
        $f5 = "GetTickCount"   fullword

        $c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        $compiler and
        all of ($f*) and
        all of ($c*)
}    



rule hacktool_windows_cobaltstrike_artifact_exe
{
    meta:
         description = "Detect the risk of  Malware Cobalt Strike Rule 1"
    condition:
        cobaltstrike_template_exe and
        filesize < 100KB and
        pe.sections[pe.section_index(".data")].raw_data_size > 512 and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset, 512 ) >= 7
}

private rule cobaltstrike_beacon_raw
{
    strings:
        $s1 = "%d is an x64 process (can't inject x86 content)" fullword
        $s2 = "Failed to impersonate logged on user %d (%u)" fullword
        $s3 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword
        $s4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword
        $s5 = "could not run command (w/ token) because of its length of %d bytes!" fullword
        $s6 = "could not write to process memory: %d" fullword
        $s7 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword
        $s8 = "Could not connect to pipe (%s): %d" fullword

        $b1 = "beacon.dll"     fullword
        $b2 = "beacon.x86.dll" fullword
        $b3 = "beacon.x64.dll" fullword

    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        (
            any of ($b*) or
            5 of ($s*)
        )
}

private rule cobaltstrike_beacon_exe
{
    condition:
        cobaltstrike_template_exe and
        filesize > 100KB and filesize < 500KB and
        pe.sections[pe.section_index(".data")].raw_data_size > 200000 and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset + 1024, 150000 ) >= 7 
}

private rule cobaltstrike_beacon_b64
{
    strings:
        $s1a = "JWQgaXMgYW4geDY0IHByb2Nlc3MgKGNhbid0IGluam"
        $s1b = "ZCBpcyBhbiB4NjQgcHJvY2VzcyAoY2FuJ3QgaW5qZW"
        $s1c = "IGlzIGFuIHg2NCBwcm9jZXNzIChjYW4ndCBpbmplY3"

        $s2a = "RmFpbGVkIHRvIGltcGVyc29uYXRlIGxvZ2dlZCBvbi"
        $s2b = "YWlsZWQgdG8gaW1wZXJzb25hdGUgbG9nZ2VkIG9uIH"
        $s2c = "aWxlZCB0byBpbXBlcnNvbmF0ZSBsb2dnZWQgb24gdX"

        $s3a = "cG93ZXJzaGVsbCAtbm9wIC1leGVjIGJ5cGFzcyAtRW"
        $s3b = "b3dlcnNoZWxsIC1ub3AgLWV4ZWMgYnlwYXNzIC1Fbm"
        $s3c = "d2Vyc2hlbGwgLW5vcCAtZXhlYyBieXBhc3MgLUVuY2"

        $s4a = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLk"
        $s4b = "RVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG"
        $s4c = "WCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3"

    condition:
        filesize < 1000KB and
        5 of ($s*)
}

rule hacktool_windows_cobaltstrike_beacon
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 2"
    condition:
        cobaltstrike_beacon_b64 or
        cobaltstrike_beacon_raw or
        cobaltstrike_beacon_exe
}

rule hacktool_windows_cobaltstrike_postexploitation
{
    meta:
       description = "Detect the risk of  Malware Cobalt Strike Rule 3"
    strings:
        $s1 = "\\devcenter\\aggressor\\external\\"

    condition:
        filesize > 10KB and filesize < 1000KB and
        all of ($s*)
}

rule hacktool_windows_cobaltstrike_powershell
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 4"
    strings:
        $ps1 = "Set-StrictMode -Version 2"
        $ps2 = "func_get_proc_address"
        $ps3 = "func_get_delegate_type"
        $ps4 = "FromBase64String"
        $ps5 = "VirtualAlloc"
        $ps6 = "var_code"
        $ps7 = "var_buffer"
        $ps8 = "var_hthread"

    condition:
        $ps1 at 0 and
        filesize < 1000KB and
        7 of ($ps*)
}

rule beacon32
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 5"
    strings:
        $name = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
    condition:
        uint16(0) == 0x5A4D and pe.entry_point == 0x8b0 and filesize > 277KB and filesize < 304KB and $name
}


rule ps
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 6"
    strings:
        $str1 = "$var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)"
        $str2 = "[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)"
    condition:
       uint16(0) != 0x5A4D and $str1 and $str2
}

rule CobaltStrike_hta_pe
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 7"
    strings:
        $reg1 = /var_tempexe = var_basedir & \"\\\" & \"[A-z]{1,20}.exe\"\s*Set var_stream = var_obj.CreateTextFile\(var_tempexe, true , false\)/
    condition:
       uint16(0) != 0x5A4D and  $reg1
}

rule hta_VBS
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 8"
    strings:
        $str = "myAr\"&\"ray \"&Chr(61)&\" Array\"&Chr(40)&Chr(45)&\"4\"&Chr(44)&Chr(45)&\"24\"&Chr(44)&Chr(45)&\"119\"&Chr(44)"
    condition:
       uint16(0) != 0x5A4D and  $str
}


rule hta_ps1
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 9"
    strings:
        $str = "var_shell.run \"powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8A"
    condition:
       uint16(0) != 0x5A4D and  $str
}

rule hacktool_windows_cobaltstrike_powershell_2
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 10"
    strings:
        $ps1 = "'System.dll'" ascii
        $ps2 = "Set-StrictMode -Version 2" ascii
        $ps3 = "GetProcAddress" ascii
        $ps4 = "start-job" ascii
        $ps5 = "VirtualAlloc" ascii
    condition:
        $ps2 at 0 and
        filesize < 1000KB and
        all of ($ps*)
}

rule hacktool_windows_cobaltstrike_in_memory
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 11"
    strings:
        $s1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s"
        $s2 = "powershell -nop -exec bypass -EncodedCommand \"%s\""
        $s3 = "%d is an x86 process (can't inject x64 content)"
        $s4 = "%d.%d    %s  %s  %s  %s"
        $s5 = "could not upload file: %d"
        $s7 = "KVK...................................0.-.n"
        $s8 = "%d is an x64 process (can't inject x86 content)"
        $op1 = {C7 45 F0 0? 00 00 00 E9 BF A3 BC FF}
    condition:
        6 of them
}

rule cobaltstrike_beacon_in_memory
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 12"
    strings:
        $s1 = "beacon.x64.dll" fullword
        $s2 = "F    %I64d   %02d/%02d/%02d %02d:%02d:%02d   %s" fullword
    condition:
        all of them
}

rule APT_CobaltStrike_Beacon_Indicator {
   meta:
      description = "Detect the risk of  Malware Cobalt Strike Rule 13"
   strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}
rule CobaltStrike_ShellCode
{
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 14"
    strings:
        $ = {8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B}
        $ = {68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 FF D5}
    condition:
        any of them
}

rule CobaltStrike_Payload
{
    meta:
        description ="Detect the risk of  Malware Cobalt Strike Rule 15"
    strings:
        $ = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
        $ = {B9 AA 26 00 00 31 D2 C7 44 24 28 5C 00 00 00 C7 44 24 24 65 00 00 00 C7 44 24 20 70 00 00 00 C7 44 24 1C 69 00 00 00 C7 44 24 18 70 00 00 00 F7 F1 C7 44 24 14 5C 00 00 00 C7 44 24 10 2E 00 00 00 C7 44 24 0C 5C 00 00 00 C7 44 24 08 5C 00 00 00 C7 44 24 04 44 40 40 00 C7 04 24 F0 53 40 00 89 54 24}
    condition:
        any of them
}

rule CobaltStrike_Malicious_HTA {
   meta:
      description = "Detect the risk of  Malware Cobalt Strike Rule 16"
   strings:
      $var_shell = "CreateObject(\"Wscript.Shell\")" nocase
      $RunPowerShell = "powershell -nop -w hidden -encodedcommand " nocase
      $DropFile = ".Write Chr(CLng(\"&H\" & Mid(" nocase
      $Obfuscator = "&\"Long\"&Chr(44)&" nocase
      $Script = "<script language=\"vbscript\">" nocase
   condition:
      $var_shell and $Script and 3 of them
}

rule CobaltStrike_imphashes {
   meta:
      description ="Detect the risk of  Malware Cobalt Strike Rule 17"
   condition:
      pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or pe.imphash() == "dc25ee78e2ef4d36faa0badf1e7461c9"
}

rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 18"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x00a3) == 0xe553a458 and
    uint32(@h01+0x00bd) == 0x0726774c and
    uint32(@h01+0x012f) == 0xc99cc96a and
    uint32(@h01+0x0198) == 0x56a2b5f0 and
    uint32(@h01+0x01a4) == 0xe035f044 and
    uint32(@h01+0x01e4) == 0xcc8e00f4
}

rule Cobaltbaltstrike_RAW_Payload_smb_stager_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 19"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x00a1) == 0xe553a458 and
    uint32(@h01+0x00c4) == 0xd4df7045 and
    uint32(@h01+0x00d2) == 0xe27d6f28 and
    uint32(@h01+0x00f8) == 0xbb5f9ead and
    uint32(@h01+0x010d) == 0xbb5f9ead and
    uint32(@h01+0x0131) == 0xfcddfac0 and
    uint32(@h01+0x0139) == 0x528796c6 and
    uint32(@h01+0x014b) == 0x56a2b5f0
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 20"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00ac) == 0x006b8029 and
    uint32(@h01+0x00bb) == 0xe0df0fea and
    uint32(@h01+0x00d5) == 0x6737dbc2 and
    uint32(@h01+0x00de) == 0xff38e9b7 and
    uint32(@h01+0x00e8) == 0xe13bec74 and
    uint32(@h01+0x00f1) == 0x614d6e75 and
    uint32(@h01+0x00fa) == 0x56a2b5f0 and
    uint32(@h01+0x0107) == 0x5fc8d902 and
    uint32(@h01+0x011a) == 0xe553a458 and
    uint32(@h01+0x0128) == 0x5fc8d902 and
    uint32(@h01+0x013d) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x64
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 21"
  strings:
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6737dbc2 and
    uint32(@h01+0x0150) == 0xff38e9b7 and
    uint32(@h01+0x0161) == 0xe13bec74 and
    uint32(@h01+0x016f) == 0x614d6e75 and
    uint32(@h01+0x0198) == 0x5fc8d902 and
    uint32(@h01+0x01b8) == 0xe553a458 and
    uint32(@h01+0x01d2) == 0x5fc8d902 and
    uint32(@h01+0x01ee) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 22"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00ac) == 0x006b8029 and
    uint32(@h01+0x00bb) == 0xe0df0fea and
    uint32(@h01+0x00d5) == 0x6174a599 and
    uint32(@h01+0x00e5) == 0x56a2b5f0 and
    uint32(@h01+0x00f2) == 0x5fc8d902 and
    uint32(@h01+0x0105) == 0xe553a458 and
    uint32(@h01+0x0113) == 0x5fc8d902
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x64
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 23"
  strings:
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6174a599 and
    uint32(@h01+0x016b) == 0x5fc8d902 and
    uint32(@h01+0x018b) == 0xe553a458 and
    uint32(@h01+0x01a5) == 0x5fc8d902 and
    uint32(@h01+0x01c1) == 0x614d6e75
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 24"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00aa) == 0xa779563a and
    uint32(@h01+0x00c6) == 0xc69f8957 and
    uint32(@h01+0x00de) == 0x3b2e55eb and
    uint32(@h01+0x00f2) == 0x7b18062d and
    uint32(@h01+0x010b) == 0x5de2c5aa and
    uint32(@h01+0x0114) == 0x315e2145 and
    uint32(@h01+0x0123) == 0x0be057b7 and
    uint32(@h01+0x02c4) == 0x56a2b5f0 and
    uint32(@h01+0x02d8) == 0xe553a458 and
    uint32(@h01+0x02f3) == 0xe2899612
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x64
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 25"
  strings:
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    uint32(@h01+0x00e9) == 0x0726774c and
    uint32(@h01+0x0101) == 0xa779563a and
    uint32(@h01+0x0120) == 0xc69f8957 and
    uint32(@h01+0x013f) == 0x3b2e55eb and
    uint32(@h01+0x0163) == 0x7b18062d and
    uint32(@h01+0x0308) == 0x56a2b5f0 and
    uint32(@h01+0x0324) == 0xe553a458 and
    uint32(@h01+0x0342) == 0xe2899612
}


rule Cobaltbaltstrike_RAW_Payload_https_stager_x86
{
  meta:
    description ="Detect the risk of  Malware Cobalt Strike Rule 26"
  strings:
    $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    uint32(@h01+0x009c) == 0x0726774c and
    uint32(@h01+0x00af) == 0xa779563a and
    uint32(@h01+0x00cb) == 0xc69f8957 and
    uint32(@h01+0x00e7) == 0x3b2e55eb and
    uint32(@h01+0x0100) == 0x869e4675 and
    uint32(@h01+0x0110) == 0x7b18062d and
    uint32(@h01+0x0129) == 0x5de2c5aa and
    uint32(@h01+0x0132) == 0x315e2145 and
    uint32(@h01+0x0141) == 0x0be057b7 and
    uint32(@h01+0x02e9) == 0x56a2b5f0 and
    uint32(@h01+0x02fd) == 0xe553a458 and
    uint32(@h01+0x0318) == 0xe2899612
}


rule Cobaltbaltstrike_RAW_Payload_https_stager_x64
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 27"
  strings:
    $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    uint32(@h01+0x00e9) == 0x0726774c and
    uint32(@h01+0x0101) == 0xa779563a and
    uint32(@h01+0x0123) == 0xc69f8957 and
    uint32(@h01+0x0142) == 0x3b2e55eb and
    uint32(@h01+0x016c) == 0x869e4675 and
    uint32(@h01+0x0186) == 0x7b18062d and
    uint32(@h01+0x032b) == 0x56a2b5f0 and
    uint32(@h01+0x0347) == 0xe553a458 and
    uint32(@h01+0x0365) == 0xe2899612
}

rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 28"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x0149) == 0xe5005300 and
    uint32(@h01+0x017d) == 0x07002600 and
    uint32(@h01+0x0261) == 0xc9009c00 and
    uint32(@h01+0x0333) == 0x5600a200 and
    uint32(@h01+0x034b) == 0xe0003500 and
    uint32(@h01+0x03cb) == 0xcc008e00
}

rule Cobaltbaltstrike_RAW_Payload_smb_stager_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 29"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x0145) == 0xe5005300 and
    uint32(@h01+0x018b) == 0xd400df00 and
    uint32(@h01+0x01a7) == 0xe2007d00 and
    uint32(@h01+0x01f3) == 0xbb005f00 and
    uint32(@h01+0x021d) == 0xbb005f00 and
    uint32(@h01+0x0265) == 0xfc00dd00 and
    uint32(@h01+0x0275) == 0x52008700 and
    uint32(@h01+0x0299) == 0x5600a200
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 30"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x015b) == 0x00006b00 and
    uint32(@h01+0x0179) == 0xe000df00 and
    uint32(@h01+0x01ad) == 0x67003700 and
    uint32(@h01+0x01bf) == 0xff003800 and
    uint32(@h01+0x01d3) == 0xe1003b00 and
    uint32(@h01+0x01e5) == 0x61004d00 and
    uint32(@h01+0x01f7) == 0x5600a200 and
    uint32(@h01+0x0211) == 0x5f00c800 and
    uint32(@h01+0x0237) == 0xe5005300 and
    uint32(@h01+0x0253) == 0x5f00c800 and
    uint32(@h01+0x027d) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x64_UTF16
{
  meta:
    description ="Detect the risk of  Malware Cobalt Strike Rule 31"
  strings:
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x0203) == 0x07002600 and
    uint32(@h01+0x0225) == 0x00006b00 and
    uint32(@h01+0x025d) == 0xe000df00 and
    uint32(@h01+0x0287) == 0x67003700 and
    uint32(@h01+0x02a3) == 0xff003800 and
    uint32(@h01+0x02c5) == 0xe1003b00 and
    uint32(@h01+0x02e1) == 0x61004d00 and
    uint32(@h01+0x0333) == 0x5f00c800 and
    uint32(@h01+0x0373) == 0xe5005300 and
    uint32(@h01+0x03a7) == 0x5f00c800 and
    uint32(@h01+0x03df) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 32"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x015b) == 0x00006b00 and
    uint32(@h01+0x0179) == 0xe000df00 and
    uint32(@h01+0x01ad) == 0x61007400 and
    uint32(@h01+0x01cd) == 0x5600a200 and
    uint32(@h01+0x01e7) == 0x5f00c800 and
    uint32(@h01+0x020d) == 0xe5005300 and
    uint32(@h01+0x0229) == 0x5f00c800
}

rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x64_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 33"
  strings:
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x0203) == 0x07002600 and
    uint32(@h01+0x0225) == 0x00006b00 and
    uint32(@h01+0x025d) == 0xe000df00 and
    uint32(@h01+0x0287) == 0x61007400 and
    uint32(@h01+0x02d9) == 0x5f00c800 and
    uint32(@h01+0x0319) == 0xe5005300 and
    uint32(@h01+0x034d) == 0x5f00c800 and
    uint32(@h01+0x0385) == 0x61004d00
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 34"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x0157) == 0xa7007900 and
    uint32(@h01+0x018f) == 0xc6009f00 and
    uint32(@h01+0x01bf) == 0x3b002e00 and
    uint32(@h01+0x01e7) == 0x7b001800 and
    uint32(@h01+0x0219) == 0x5d00e200 and
    uint32(@h01+0x022b) == 0x31005e00 and
    uint32(@h01+0x0249) == 0x0b00e000 and
    uint32(@h01+0x058b) == 0x5600a200 and
    uint32(@h01+0x05b3) == 0xe5005300 and
    uint32(@h01+0x05e9) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_http_stager_x64_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 35"
  strings:
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x01d5) == 0x07002600 and
    uint32(@h01+0x0205) == 0xa7007900 and
    uint32(@h01+0x0243) == 0xc6009f00 and
    uint32(@h01+0x0281) == 0x3b002e00 and
    uint32(@h01+0x02c9) == 0x7b001800 and
    uint32(@h01+0x0613) == 0x5600a200 and
    uint32(@h01+0x064b) == 0xe5005300 and
    uint32(@h01+0x0687) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_https_stager_x86_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 36"
  strings:
    $h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
  condition:
    uint32(@h01+0x013b) == 0x07002600 and
    uint32(@h01+0x0161) == 0xa7007900 and
    uint32(@h01+0x0199) == 0xc6009f00 and
    uint32(@h01+0x01d1) == 0x3b002e00 and
    uint32(@h01+0x0203) == 0x86009e00 and
    uint32(@h01+0x0223) == 0x7b001800 and
    uint32(@h01+0x0255) == 0x5d00e200 and
    uint32(@h01+0x0267) == 0x31005e00 and
    uint32(@h01+0x0285) == 0x0b00e000 and
    uint32(@h01+0x05d5) == 0x5600a200 and
    uint32(@h01+0x05fd) == 0xe5005300 and
    uint32(@h01+0x0633) == 0xe2008900
}

rule Cobaltbaltstrike_RAW_Payload_https_stager_x64_UTF16
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 37"
  strings:
    $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x01d5) == 0x07002600 and
    uint32(@h01+0x0205) == 0xa7007900 and
    uint32(@h01+0x0249) == 0xc6009f00 and
    uint32(@h01+0x0287) == 0x3b002e00 and
    uint32(@h01+0x02db) == 0x86009e00 and
    uint32(@h01+0x030f) == 0x7b001800 and
    uint32(@h01+0x0659) == 0x5600a200 and
    uint32(@h01+0x0691) == 0xe5005300 and
    uint32(@h01+0x06cd) == 0xe2008900
}

rule Cobaltbaltstrike_Payload_Encoded
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 38"
  strings:
    $s01 = "0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b" ascii wide nocase
    $s02 = "0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b" ascii wide nocase
    $s03 = "0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51" ascii wide nocase
    $s04 = "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51" ascii wide nocase
    $s05 = "fce8890000006089e531d2648b52308b" ascii wide nocase
    $s06 = "fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b" ascii wide nocase
    $s07 = "fc4883e4f0e8c8000000415141505251" ascii wide nocase
    $s08 = "fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51" ascii wide nocase
    $s09 = "/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJX" ascii wide
    $s10 = "/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHA" ascii wide
    $s11 = "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0" ascii wide
    $s12 = "32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLj" ascii wide
    $s13 = "/ADoAIkAAAAAAAAAYACJAOUAMQDSAGQAiwBSADAAiwBSAAwAiwBSABQAiwByACg" ascii wide
    $s14 = "/ABIAIMA5ADwAOgAyAAAAAAAAABBAFEAQQBQAFIAUQBWAEgAMQDSAGUASACLAFI" ascii wide
    $s15 = "3yPLI6ojIyMjIyMjQyOqI8YjEiPxI0cjqCNxIxMjqCNxIy8jqCNxIzcjqCNRIwsj" ascii wide
    $s16 = "3yNrI6AjxyPTI8sj6yMjIyMjIyNiI3IjYiNzI3EjciN1I2sjEiPxI0YjayOoI3Ej" ascii wide
    $s17 = "Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117" ascii wide
    $s18 = "Array(-4, -24, -119, 0, 0, 0, 96, -119, -27, 49, -46, 100, -117, 82, 48, -117" ascii wide
    $s19 = "Array(-4,72,-125,-28,-16,-24,-56,0,0,0,65,81,65,80,82,81" ascii wide
    $s20 = "Array(-4, 72, -125, -28, -16, -24, -56, 0, 0, 0, 65, 81, 65, 80, 82, 81" ascii wide
    $s21 = "Chr(-4)&Chr(-24)&Chr(-119)&Chr(0)&Chr(0)&Chr(0)&Chr(96)&Chr(-119)&Chr(-27)&\"1\"&Chr(-46)&\"d\"&Chr(-117)&\"R0\"&Chr(-117)" ascii wide
    $s22 = "Chr(-4)&\"H\"&Chr(-125)&Chr(-28)&Chr(-16)&Chr(-24)&Chr(-56)&Chr(0)&Chr(0)&Chr(0)&\"AQAPRQVH" ascii wide
    $s23 = "\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b" ascii wide nocase
    $s24 = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51" ascii wide nocase

  condition:
        any of them
}

rule Cobaltbaltstrike_strike_Payload_XORed
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 39"
  strings:
    $h01 = { 10 ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 61 61 61 61 }
  condition:
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFCE88900 or
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFC4883E4 or
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5AE800 or
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5A4152 or
    uint32be(@h01+8) ^ uint32be(@h01+16) == 0x90909090
}

rule Cobaltbaltstrike_Beacon_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 40"
  strings:
    $h01 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 ?? ?? ?? ?? FF D3 68 }
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule Cobaltbaltstrike_Beacon_x64
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 41"
  strings:
    $h01 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D EA FF FF FF 48 89 }
    $h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
    $h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
    $h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
  condition:
    $h01 and
    any of ($h1*)
}

rule Cobaltbaltstrike_Beacon_Encoded
{
  meta:
    description ="Detect the risk of  Malware Cobalt Strike Rule 42"
  strings:
    $s01 = "0x4d, 0x5a, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x89, 0xdf, 0x52, 0x45, 0x55, 0x89, 0xe5, 0x81" ascii wide nocase
    $s02 = "0x4d,0x5a,0xe8,0x00,0x00,0x00,0x00,0x5b,0x89,0xdf,0x52,0x45,0x55,0x89,0xe5,0x81" ascii wide nocase
    $s03 = "0x4d, 0x5a, 0x41, 0x52, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x20, 0x00, 0x00, 0x00, 0x48" ascii wide nocase
    $s04 = "0x4d,0x5a,0x41,0x52,0x55,0x48,0x89,0xe5,0x48,0x81,0xec,0x20,0x00,0x00,0x00,0x48" ascii wide nocase
    $s05 = "4d5ae8000000005b89df52455589e581" ascii wide nocase
    $s06 = "4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81" ascii wide nocase
    $s07 = "4d5a4152554889e54881ec2000000048" ascii wide nocase
    $s08 = "4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48" ascii wide nocase
    $s09 = "TVroAAAAAFuJ31JFVYnlg" ascii wide
    $s10 = "TVpBUlVIieVIgewgAAAAS" ascii wide
    $s11 = "bnnLIyMjI3iq/HFmdqrGo" ascii wide
    $s12 = "bnlicXZrqsZros8DIyMja" ascii wide
    $s13 = "TQBaAOgAAAAAAAAAAABbAIkA3wBSAEUAVQCJAOUAg" ascii wide
    $s14 = "TQBaAEEAUgBVAEgAiQDlAEgAgQDsACAAAAAAAAAAS" ascii wide
    $s15 = "biN5I2IjcSN2I2sjqiPGI2sjoiPPIwMjIyMjIyMja" ascii wide
    $s16 = "biN5I8sjIyMjIyMjIyN4I6oj/CNxI2YjdiOqI8Yjo" ascii wide
    $s17 = "Array(77,90,-24,0,0,0,0,91,-119,-33,82,69,85,-119,-27,-127" ascii wide
    $s18 = "Array(77, 90, -24, 0, 0, 0, 0, 91, -119, -33, 82, 69, 85, -119, -27, -127" ascii wide
    $s19 = "Array(77,90,65,82,85,72,-119,-27,72,-127,-20,32,0,0,0,72" ascii wide
    $s20 = "Array(77, 90, 65, 82, 85, 72, -119, -27, 72, -127, -20, 32, 0, 0, 0, 72" ascii wide
    $s21 = "MZ\"&Chr(-27)&Chr(0)&Chr(0)&Chr(0)&Chr(0)&Chr(91)&Chr(-119)&Chr(-33)&\"REU\"&Chr(-119)&Chr(-27)&Chr(-127)" ascii wide
    $s22 = "MZARUH\"&Chr(-119)&Chr(-27)&\"H\"&Chr(-127)&Chr(-20)&Chr(32)&Chr(0)&Chr(0)&Chr(0)&\"H" ascii wide
    $s23 = "\\x4d\\x5a\\xe8\\x00\\x00\\x00\\x00\\x5b\\x89\\xdf\\x52\\x45\\x55\\x89\\xe5\\x81" ascii wide nocase
    $s24 = "\\x4d\\x5a\\x41\\x52\\x55\\x48\\x89\\xe5\\x48\\x81\\xec\\x20\\x00\\x00\\x00\\x48" ascii wide nocase
  condition:
        any of them
}

rule Cobaltbaltstrike_Beacon_XORed_x86
{
  meta:
    description = "Detect the risk of  Malware Cobalt Strike Rule 43"
  strings:
        $h01 = { FC E8??000000 [0-32] EB27 ?? 8B?? 83??04 8B?? 31?? 83??04 ?? 8B?? 31?? 89?? 31?? 83??04 83??04 31?? 39?? 7402 EBEA ?? FF?? E8D4FFFFFF }
        $h02 = { FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }
        $h11 = { 7402 EB(E8|EA) ?? FF?? E8(D0|D4)FFFFFF }
  condition:
        any of ($h0*) and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5AE800 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5AE8 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}

rule Cobaltbaltstrike_Beacon_XORed_x64
{
  meta:
    description ="Detect the risk of  Malware Cobalt Strike Rule 44"
  strings:
    $h01 = { FC 4883E4F0 EB33 5D 8B4500 4883C504 8B4D00 31C1 4883C504 55 8B5500 31C2 895500 31D0 4883C504 83E904 31D2 39D1 7402 EBE7 58 FC 4883E4F0 FFD0 E8C8FFFFFF }
        $h11 = { FC 4883E4F0 FFD0 E8C8FFFFFF }
  condition:
        $h01 and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5A4152 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5A41 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}

rule CobaltStrike_Sleep_Decoder_Indicator {
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 45"
    strings:
        $sleep_decoder = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B 51 08 41 8B F0 48 8B EA 48 8B D9 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }
    condition:
        $sleep_decoder
}

rule CobaltStrike_C2_Encoded_XOR_Config_Indicator {
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 46"
    strings:
        $s000 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? ?? ?? 00 04 00 02 00 04 ?? ?? ?? ?? 00 05 00 01 00 02 ?? ?? }
        $s001 = { 01 00 01 00 01 03 ?? ?? 01 03 01 00 01 03 ?? ?? 01 02 01 03 01 05 ?? ?? ?? ?? 01 05 01 03 01 05 ?? ?? ?? ?? 01 04 01 00 01 03 ?? ?? }
        $s002 = { 02 03 02 03 02 00 ?? ?? 02 00 02 03 02 00 ?? ?? 02 01 02 00 02 06 ?? ?? ?? ?? 02 06 02 00 02 06 ?? ?? ?? ?? 02 07 02 03 02 00 ?? ?? }
        $s003 = { 03 02 03 02 03 01 ?? ?? 03 01 03 02 03 01 ?? ?? 03 00 03 01 03 07 ?? ?? ?? ?? 03 07 03 01 03 07 ?? ?? ?? ?? 03 06 03 02 03 01 ?? ?? }
        $s004 = { 04 05 04 05 04 06 ?? ?? 04 06 04 05 04 06 ?? ?? 04 07 04 06 04 00 ?? ?? ?? ?? 04 00 04 06 04 00 ?? ?? ?? ?? 04 01 04 05 04 06 ?? ?? }
        $s005 = { 05 04 05 04 05 07 ?? ?? 05 07 05 04 05 07 ?? ?? 05 06 05 07 05 01 ?? ?? ?? ?? 05 01 05 07 05 01 ?? ?? ?? ?? 05 00 05 04 05 07 ?? ?? }
        $s006 = { 06 07 06 07 06 04 ?? ?? 06 04 06 07 06 04 ?? ?? 06 05 06 04 06 02 ?? ?? ?? ?? 06 02 06 04 06 02 ?? ?? ?? ?? 06 03 06 07 06 04 ?? ?? }
        $s007 = { 07 06 07 06 07 05 ?? ?? 07 05 07 06 07 05 ?? ?? 07 04 07 05 07 03 ?? ?? ?? ?? 07 03 07 05 07 03 ?? ?? ?? ?? 07 02 07 06 07 05 ?? ?? }
        $s008 = { 08 09 08 09 08 0A ?? ?? 08 0A 08 09 08 0A ?? ?? 08 0B 08 0A 08 0C ?? ?? ?? ?? 08 0C 08 0A 08 0C ?? ?? ?? ?? 08 0D 08 09 08 0A ?? ?? }
        $s009 = { 09 08 09 08 09 0B ?? ?? 09 0B 09 08 09 0B ?? ?? 09 0A 09 0B 09 0D ?? ?? ?? ?? 09 0D 09 0B 09 0D ?? ?? ?? ?? 09 0C 09 08 09 0B ?? ?? }
        $s010 = { 0A 0B 0A 0B 0A 08 ?? ?? 0A 08 0A 0B 0A 08 ?? ?? 0A 09 0A 08 0A 0E ?? ?? ?? ?? 0A 0E 0A 08 0A 0E ?? ?? ?? ?? 0A 0F 0A 0B 0A 08 ?? ?? }
        $s011 = { 0B 0A 0B 0A 0B 09 ?? ?? 0B 09 0B 0A 0B 09 ?? ?? 0B 08 0B 09 0B 0F ?? ?? ?? ?? 0B 0F 0B 09 0B 0F ?? ?? ?? ?? 0B 0E 0B 0A 0B 09 ?? ?? }
        $s012 = { 0C 0D 0C 0D 0C 0E ?? ?? 0C 0E 0C 0D 0C 0E ?? ?? 0C 0F 0C 0E 0C 08 ?? ?? ?? ?? 0C 08 0C 0E 0C 08 ?? ?? ?? ?? 0C 09 0C 0D 0C 0E ?? ?? }
        $s013 = { 0D 0C 0D 0C 0D 0F ?? ?? 0D 0F 0D 0C 0D 0F ?? ?? 0D 0E 0D 0F 0D 09 ?? ?? ?? ?? 0D 09 0D 0F 0D 09 ?? ?? ?? ?? 0D 08 0D 0C 0D 0F ?? ?? }
        $s014 = { 0E 0F 0E 0F 0E 0C ?? ?? 0E 0C 0E 0F 0E 0C ?? ?? 0E 0D 0E 0C 0E 0A ?? ?? ?? ?? 0E 0A 0E 0C 0E 0A ?? ?? ?? ?? 0E 0B 0E 0F 0E 0C ?? ?? }
        $s015 = { 0F 0E 0F 0E 0F 0D ?? ?? 0F 0D 0F 0E 0F 0D ?? ?? 0F 0C 0F 0D 0F 0B ?? ?? ?? ?? 0F 0B 0F 0D 0F 0B ?? ?? ?? ?? 0F 0A 0F 0E 0F 0D ?? ?? }
        $s016 = { 10 11 10 11 10 12 ?? ?? 10 12 10 11 10 12 ?? ?? 10 13 10 12 10 14 ?? ?? ?? ?? 10 14 10 12 10 14 ?? ?? ?? ?? 10 15 10 11 10 12 ?? ?? }
        $s017 = { 11 10 11 10 11 13 ?? ?? 11 13 11 10 11 13 ?? ?? 11 12 11 13 11 15 ?? ?? ?? ?? 11 15 11 13 11 15 ?? ?? ?? ?? 11 14 11 10 11 13 ?? ?? }
        $s018 = { 12 13 12 13 12 10 ?? ?? 12 10 12 13 12 10 ?? ?? 12 11 12 10 12 16 ?? ?? ?? ?? 12 16 12 10 12 16 ?? ?? ?? ?? 12 17 12 13 12 10 ?? ?? }
        $s019 = { 13 12 13 12 13 11 ?? ?? 13 11 13 12 13 11 ?? ?? 13 10 13 11 13 17 ?? ?? ?? ?? 13 17 13 11 13 17 ?? ?? ?? ?? 13 16 13 12 13 11 ?? ?? }
        $s020 = { 14 15 14 15 14 16 ?? ?? 14 16 14 15 14 16 ?? ?? 14 17 14 16 14 10 ?? ?? ?? ?? 14 10 14 16 14 10 ?? ?? ?? ?? 14 11 14 15 14 16 ?? ?? }
        $s021 = { 15 14 15 14 15 17 ?? ?? 15 17 15 14 15 17 ?? ?? 15 16 15 17 15 11 ?? ?? ?? ?? 15 11 15 17 15 11 ?? ?? ?? ?? 15 10 15 14 15 17 ?? ?? }
        $s022 = { 16 17 16 17 16 14 ?? ?? 16 14 16 17 16 14 ?? ?? 16 15 16 14 16 12 ?? ?? ?? ?? 16 12 16 14 16 12 ?? ?? ?? ?? 16 13 16 17 16 14 ?? ?? }
        $s023 = { 17 16 17 16 17 15 ?? ?? 17 15 17 16 17 15 ?? ?? 17 14 17 15 17 13 ?? ?? ?? ?? 17 13 17 15 17 13 ?? ?? ?? ?? 17 12 17 16 17 15 ?? ?? }
        $s024 = { 18 19 18 19 18 1A ?? ?? 18 1A 18 19 18 1A ?? ?? 18 1B 18 1A 18 1C ?? ?? ?? ?? 18 1C 18 1A 18 1C ?? ?? ?? ?? 18 1D 18 19 18 1A ?? ?? }
        $s025 = { 19 18 19 18 19 1B ?? ?? 19 1B 19 18 19 1B ?? ?? 19 1A 19 1B 19 1D ?? ?? ?? ?? 19 1D 19 1B 19 1D ?? ?? ?? ?? 19 1C 19 18 19 1B ?? ?? }
        $s026 = { 1A 1B 1A 1B 1A 18 ?? ?? 1A 18 1A 1B 1A 18 ?? ?? 1A 19 1A 18 1A 1E ?? ?? ?? ?? 1A 1E 1A 18 1A 1E ?? ?? ?? ?? 1A 1F 1A 1B 1A 18 ?? ?? }
        $s027 = { 1B 1A 1B 1A 1B 19 ?? ?? 1B 19 1B 1A 1B 19 ?? ?? 1B 18 1B 19 1B 1F ?? ?? ?? ?? 1B 1F 1B 19 1B 1F ?? ?? ?? ?? 1B 1E 1B 1A 1B 19 ?? ?? }
        $s028 = { 1C 1D 1C 1D 1C 1E ?? ?? 1C 1E 1C 1D 1C 1E ?? ?? 1C 1F 1C 1E 1C 18 ?? ?? ?? ?? 1C 18 1C 1E 1C 18 ?? ?? ?? ?? 1C 19 1C 1D 1C 1E ?? ?? }
        $s029 = { 1D 1C 1D 1C 1D 1F ?? ?? 1D 1F 1D 1C 1D 1F ?? ?? 1D 1E 1D 1F 1D 19 ?? ?? ?? ?? 1D 19 1D 1F 1D 19 ?? ?? ?? ?? 1D 18 1D 1C 1D 1F ?? ?? }
        $s030 = { 1E 1F 1E 1F 1E 1C ?? ?? 1E 1C 1E 1F 1E 1C ?? ?? 1E 1D 1E 1C 1E 1A ?? ?? ?? ?? 1E 1A 1E 1C 1E 1A ?? ?? ?? ?? 1E 1B 1E 1F 1E 1C ?? ?? }
        $s031 = { 1F 1E 1F 1E 1F 1D ?? ?? 1F 1D 1F 1E 1F 1D ?? ?? 1F 1C 1F 1D 1F 1B ?? ?? ?? ?? 1F 1B 1F 1D 1F 1B ?? ?? ?? ?? 1F 1A 1F 1E 1F 1D ?? ?? }
        $s032 = { 20 21 20 21 20 22 ?? ?? 20 22 20 21 20 22 ?? ?? 20 23 20 22 20 24 ?? ?? ?? ?? 20 24 20 22 20 24 ?? ?? ?? ?? 20 25 20 21 20 22 ?? ?? }
        $s033 = { 21 20 21 20 21 23 ?? ?? 21 23 21 20 21 23 ?? ?? 21 22 21 23 21 25 ?? ?? ?? ?? 21 25 21 23 21 25 ?? ?? ?? ?? 21 24 21 20 21 23 ?? ?? }
        $s034 = { 22 23 22 23 22 20 ?? ?? 22 20 22 23 22 20 ?? ?? 22 21 22 20 22 26 ?? ?? ?? ?? 22 26 22 20 22 26 ?? ?? ?? ?? 22 27 22 23 22 20 ?? ?? }
        $s035 = { 23 22 23 22 23 21 ?? ?? 23 21 23 22 23 21 ?? ?? 23 20 23 21 23 27 ?? ?? ?? ?? 23 27 23 21 23 27 ?? ?? ?? ?? 23 26 23 22 23 21 ?? ?? }
        $s036 = { 24 25 24 25 24 26 ?? ?? 24 26 24 25 24 26 ?? ?? 24 27 24 26 24 20 ?? ?? ?? ?? 24 20 24 26 24 20 ?? ?? ?? ?? 24 21 24 25 24 26 ?? ?? }
        $s037 = { 25 24 25 24 25 27 ?? ?? 25 27 25 24 25 27 ?? ?? 25 26 25 27 25 21 ?? ?? ?? ?? 25 21 25 27 25 21 ?? ?? ?? ?? 25 20 25 24 25 27 ?? ?? }
        $s038 = { 26 27 26 27 26 24 ?? ?? 26 24 26 27 26 24 ?? ?? 26 25 26 24 26 22 ?? ?? ?? ?? 26 22 26 24 26 22 ?? ?? ?? ?? 26 23 26 27 26 24 ?? ?? }
        $s039 = { 27 26 27 26 27 25 ?? ?? 27 25 27 26 27 25 ?? ?? 27 24 27 25 27 23 ?? ?? ?? ?? 27 23 27 25 27 23 ?? ?? ?? ?? 27 22 27 26 27 25 ?? ?? }
        $s040 = { 28 29 28 29 28 2A ?? ?? 28 2A 28 29 28 2A ?? ?? 28 2B 28 2A 28 2C ?? ?? ?? ?? 28 2C 28 2A 28 2C ?? ?? ?? ?? 28 2D 28 29 28 2A ?? ?? }
        $s041 = { 29 28 29 28 29 2B ?? ?? 29 2B 29 28 29 2B ?? ?? 29 2A 29 2B 29 2D ?? ?? ?? ?? 29 2D 29 2B 29 2D ?? ?? ?? ?? 29 2C 29 28 29 2B ?? ?? }
        $s042 = { 2A 2B 2A 2B 2A 28 ?? ?? 2A 28 2A 2B 2A 28 ?? ?? 2A 29 2A 28 2A 2E ?? ?? ?? ?? 2A 2E 2A 28 2A 2E ?? ?? ?? ?? 2A 2F 2A 2B 2A 28 ?? ?? }
        $s043 = { 2B 2A 2B 2A 2B 29 ?? ?? 2B 29 2B 2A 2B 29 ?? ?? 2B 28 2B 29 2B 2F ?? ?? ?? ?? 2B 2F 2B 29 2B 2F ?? ?? ?? ?? 2B 2E 2B 2A 2B 29 ?? ?? }
        $s044 = { 2C 2D 2C 2D 2C 2E ?? ?? 2C 2E 2C 2D 2C 2E ?? ?? 2C 2F 2C 2E 2C 28 ?? ?? ?? ?? 2C 28 2C 2E 2C 28 ?? ?? ?? ?? 2C 29 2C 2D 2C 2E ?? ?? }
        $s045 = { 2D 2C 2D 2C 2D 2F ?? ?? 2D 2F 2D 2C 2D 2F ?? ?? 2D 2E 2D 2F 2D 29 ?? ?? ?? ?? 2D 29 2D 2F 2D 29 ?? ?? ?? ?? 2D 28 2D 2C 2D 2F ?? ?? }
        $s046 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D 2E 2C 2E 2A ?? ?? ?? ?? 2E 2A 2E 2C 2E 2A ?? ?? ?? ?? 2E 2B 2E 2F 2E 2C ?? ?? }
        $s047 = { 2F 2E 2F 2E 2F 2D ?? ?? 2F 2D 2F 2E 2F 2D ?? ?? 2F 2C 2F 2D 2F 2B ?? ?? ?? ?? 2F 2B 2F 2D 2F 2B ?? ?? ?? ?? 2F 2A 2F 2E 2F 2D ?? ?? }
        $s048 = { 30 31 30 31 30 32 ?? ?? 30 32 30 31 30 32 ?? ?? 30 33 30 32 30 34 ?? ?? ?? ?? 30 34 30 32 30 34 ?? ?? ?? ?? 30 35 30 31 30 32 ?? ?? }
        $s049 = { 31 30 31 30 31 33 ?? ?? 31 33 31 30 31 33 ?? ?? 31 32 31 33 31 35 ?? ?? ?? ?? 31 35 31 33 31 35 ?? ?? ?? ?? 31 34 31 30 31 33 ?? ?? }
        $s050 = { 32 33 32 33 32 30 ?? ?? 32 30 32 33 32 30 ?? ?? 32 31 32 30 32 36 ?? ?? ?? ?? 32 36 32 30 32 36 ?? ?? ?? ?? 32 37 32 33 32 30 ?? ?? }
        $s051 = { 33 32 33 32 33 31 ?? ?? 33 31 33 32 33 31 ?? ?? 33 30 33 31 33 37 ?? ?? ?? ?? 33 37 33 31 33 37 ?? ?? ?? ?? 33 36 33 32 33 31 ?? ?? }
        $s052 = { 34 35 34 35 34 36 ?? ?? 34 36 34 35 34 36 ?? ?? 34 37 34 36 34 30 ?? ?? ?? ?? 34 30 34 36 34 30 ?? ?? ?? ?? 34 31 34 35 34 36 ?? ?? }
        $s053 = { 35 34 35 34 35 37 ?? ?? 35 37 35 34 35 37 ?? ?? 35 36 35 37 35 31 ?? ?? ?? ?? 35 31 35 37 35 31 ?? ?? ?? ?? 35 30 35 34 35 37 ?? ?? }
        $s054 = { 36 37 36 37 36 34 ?? ?? 36 34 36 37 36 34 ?? ?? 36 35 36 34 36 32 ?? ?? ?? ?? 36 32 36 34 36 32 ?? ?? ?? ?? 36 33 36 37 36 34 ?? ?? }
        $s055 = { 37 36 37 36 37 35 ?? ?? 37 35 37 36 37 35 ?? ?? 37 34 37 35 37 33 ?? ?? ?? ?? 37 33 37 35 37 33 ?? ?? ?? ?? 37 32 37 36 37 35 ?? ?? }
        $s056 = { 38 39 38 39 38 3A ?? ?? 38 3A 38 39 38 3A ?? ?? 38 3B 38 3A 38 3C ?? ?? ?? ?? 38 3C 38 3A 38 3C ?? ?? ?? ?? 38 3D 38 39 38 3A ?? ?? }
        $s057 = { 39 38 39 38 39 3B ?? ?? 39 3B 39 38 39 3B ?? ?? 39 3A 39 3B 39 3D ?? ?? ?? ?? 39 3D 39 3B 39 3D ?? ?? ?? ?? 39 3C 39 38 39 3B ?? ?? }
        $s058 = { 3A 3B 3A 3B 3A 38 ?? ?? 3A 38 3A 3B 3A 38 ?? ?? 3A 39 3A 38 3A 3E ?? ?? ?? ?? 3A 3E 3A 38 3A 3E ?? ?? ?? ?? 3A 3F 3A 3B 3A 38 ?? ?? }
        $s059 = { 3B 3A 3B 3A 3B 39 ?? ?? 3B 39 3B 3A 3B 39 ?? ?? 3B 38 3B 39 3B 3F ?? ?? ?? ?? 3B 3F 3B 39 3B 3F ?? ?? ?? ?? 3B 3E 3B 3A 3B 39 ?? ?? }
        $s060 = { 3C 3D 3C 3D 3C 3E ?? ?? 3C 3E 3C 3D 3C 3E ?? ?? 3C 3F 3C 3E 3C 38 ?? ?? ?? ?? 3C 38 3C 3E 3C 38 ?? ?? ?? ?? 3C 39 3C 3D 3C 3E ?? ?? }
        $s061 = { 3D 3C 3D 3C 3D 3F ?? ?? 3D 3F 3D 3C 3D 3F ?? ?? 3D 3E 3D 3F 3D 39 ?? ?? ?? ?? 3D 39 3D 3F 3D 39 ?? ?? ?? ?? 3D 38 3D 3C 3D 3F ?? ?? }
        $s062 = { 3E 3F 3E 3F 3E 3C ?? ?? 3E 3C 3E 3F 3E 3C ?? ?? 3E 3D 3E 3C 3E 3A ?? ?? ?? ?? 3E 3A 3E 3C 3E 3A ?? ?? ?? ?? 3E 3B 3E 3F 3E 3C ?? ?? }
        $s063 = { 3F 3E 3F 3E 3F 3D ?? ?? 3F 3D 3F 3E 3F 3D ?? ?? 3F 3C 3F 3D 3F 3B ?? ?? ?? ?? 3F 3B 3F 3D 3F 3B ?? ?? ?? ?? 3F 3A 3F 3E 3F 3D ?? ?? }
        $s064 = { 40 41 40 41 40 42 ?? ?? 40 42 40 41 40 42 ?? ?? 40 43 40 42 40 44 ?? ?? ?? ?? 40 44 40 42 40 44 ?? ?? ?? ?? 40 45 40 41 40 42 ?? ?? }
        $s065 = { 41 40 41 40 41 43 ?? ?? 41 43 41 40 41 43 ?? ?? 41 42 41 43 41 45 ?? ?? ?? ?? 41 45 41 43 41 45 ?? ?? ?? ?? 41 44 41 40 41 43 ?? ?? }
        $s066 = { 42 43 42 43 42 40 ?? ?? 42 40 42 43 42 40 ?? ?? 42 41 42 40 42 46 ?? ?? ?? ?? 42 46 42 40 42 46 ?? ?? ?? ?? 42 47 42 43 42 40 ?? ?? }
        $s067 = { 43 42 43 42 43 41 ?? ?? 43 41 43 42 43 41 ?? ?? 43 40 43 41 43 47 ?? ?? ?? ?? 43 47 43 41 43 47 ?? ?? ?? ?? 43 46 43 42 43 41 ?? ?? }
        $s068 = { 44 45 44 45 44 46 ?? ?? 44 46 44 45 44 46 ?? ?? 44 47 44 46 44 40 ?? ?? ?? ?? 44 40 44 46 44 40 ?? ?? ?? ?? 44 41 44 45 44 46 ?? ?? }
        $s069 = { 45 44 45 44 45 47 ?? ?? 45 47 45 44 45 47 ?? ?? 45 46 45 47 45 41 ?? ?? ?? ?? 45 41 45 47 45 41 ?? ?? ?? ?? 45 40 45 44 45 47 ?? ?? }
        $s070 = { 46 47 46 47 46 44 ?? ?? 46 44 46 47 46 44 ?? ?? 46 45 46 44 46 42 ?? ?? ?? ?? 46 42 46 44 46 42 ?? ?? ?? ?? 46 43 46 47 46 44 ?? ?? }
        $s071 = { 47 46 47 46 47 45 ?? ?? 47 45 47 46 47 45 ?? ?? 47 44 47 45 47 43 ?? ?? ?? ?? 47 43 47 45 47 43 ?? ?? ?? ?? 47 42 47 46 47 45 ?? ?? }
        $s072 = { 48 49 48 49 48 4A ?? ?? 48 4A 48 49 48 4A ?? ?? 48 4B 48 4A 48 4C ?? ?? ?? ?? 48 4C 48 4A 48 4C ?? ?? ?? ?? 48 4D 48 49 48 4A ?? ?? }
        $s073 = { 49 48 49 48 49 4B ?? ?? 49 4B 49 48 49 4B ?? ?? 49 4A 49 4B 49 4D ?? ?? ?? ?? 49 4D 49 4B 49 4D ?? ?? ?? ?? 49 4C 49 48 49 4B ?? ?? }
        $s074 = { 4A 4B 4A 4B 4A 48 ?? ?? 4A 48 4A 4B 4A 48 ?? ?? 4A 49 4A 48 4A 4E ?? ?? ?? ?? 4A 4E 4A 48 4A 4E ?? ?? ?? ?? 4A 4F 4A 4B 4A 48 ?? ?? }
        $s075 = { 4B 4A 4B 4A 4B 49 ?? ?? 4B 49 4B 4A 4B 49 ?? ?? 4B 48 4B 49 4B 4F ?? ?? ?? ?? 4B 4F 4B 49 4B 4F ?? ?? ?? ?? 4B 4E 4B 4A 4B 49 ?? ?? }
        $s076 = { 4C 4D 4C 4D 4C 4E ?? ?? 4C 4E 4C 4D 4C 4E ?? ?? 4C 4F 4C 4E 4C 48 ?? ?? ?? ?? 4C 48 4C 4E 4C 48 ?? ?? ?? ?? 4C 49 4C 4D 4C 4E ?? ?? }
        $s077 = { 4D 4C 4D 4C 4D 4F ?? ?? 4D 4F 4D 4C 4D 4F ?? ?? 4D 4E 4D 4F 4D 49 ?? ?? ?? ?? 4D 49 4D 4F 4D 49 ?? ?? ?? ?? 4D 48 4D 4C 4D 4F ?? ?? }
        $s078 = { 4E 4F 4E 4F 4E 4C ?? ?? 4E 4C 4E 4F 4E 4C ?? ?? 4E 4D 4E 4C 4E 4A ?? ?? ?? ?? 4E 4A 4E 4C 4E 4A ?? ?? ?? ?? 4E 4B 4E 4F 4E 4C ?? ?? }
        $s079 = { 4F 4E 4F 4E 4F 4D ?? ?? 4F 4D 4F 4E 4F 4D ?? ?? 4F 4C 4F 4D 4F 4B ?? ?? ?? ?? 4F 4B 4F 4D 4F 4B ?? ?? ?? ?? 4F 4A 4F 4E 4F 4D ?? ?? }
        $s080 = { 50 51 50 51 50 52 ?? ?? 50 52 50 51 50 52 ?? ?? 50 53 50 52 50 54 ?? ?? ?? ?? 50 54 50 52 50 54 ?? ?? ?? ?? 50 55 50 51 50 52 ?? ?? }
        $s081 = { 51 50 51 50 51 53 ?? ?? 51 53 51 50 51 53 ?? ?? 51 52 51 53 51 55 ?? ?? ?? ?? 51 55 51 53 51 55 ?? ?? ?? ?? 51 54 51 50 51 53 ?? ?? }
        $s082 = { 52 53 52 53 52 50 ?? ?? 52 50 52 53 52 50 ?? ?? 52 51 52 50 52 56 ?? ?? ?? ?? 52 56 52 50 52 56 ?? ?? ?? ?? 52 57 52 53 52 50 ?? ?? }
        $s083 = { 53 52 53 52 53 51 ?? ?? 53 51 53 52 53 51 ?? ?? 53 50 53 51 53 57 ?? ?? ?? ?? 53 57 53 51 53 57 ?? ?? ?? ?? 53 56 53 52 53 51 ?? ?? }
        $s084 = { 54 55 54 55 54 56 ?? ?? 54 56 54 55 54 56 ?? ?? 54 57 54 56 54 50 ?? ?? ?? ?? 54 50 54 56 54 50 ?? ?? ?? ?? 54 51 54 55 54 56 ?? ?? }
        $s085 = { 55 54 55 54 55 57 ?? ?? 55 57 55 54 55 57 ?? ?? 55 56 55 57 55 51 ?? ?? ?? ?? 55 51 55 57 55 51 ?? ?? ?? ?? 55 50 55 54 55 57 ?? ?? }
        $s086 = { 56 57 56 57 56 54 ?? ?? 56 54 56 57 56 54 ?? ?? 56 55 56 54 56 52 ?? ?? ?? ?? 56 52 56 54 56 52 ?? ?? ?? ?? 56 53 56 57 56 54 ?? ?? }
        $s087 = { 57 56 57 56 57 55 ?? ?? 57 55 57 56 57 55 ?? ?? 57 54 57 55 57 53 ?? ?? ?? ?? 57 53 57 55 57 53 ?? ?? ?? ?? 57 52 57 56 57 55 ?? ?? }
        $s088 = { 58 59 58 59 58 5A ?? ?? 58 5A 58 59 58 5A ?? ?? 58 5B 58 5A 58 5C ?? ?? ?? ?? 58 5C 58 5A 58 5C ?? ?? ?? ?? 58 5D 58 59 58 5A ?? ?? }
        $s089 = { 59 58 59 58 59 5B ?? ?? 59 5B 59 58 59 5B ?? ?? 59 5A 59 5B 59 5D ?? ?? ?? ?? 59 5D 59 5B 59 5D ?? ?? ?? ?? 59 5C 59 58 59 5B ?? ?? }
        $s090 = { 5A 5B 5A 5B 5A 58 ?? ?? 5A 58 5A 5B 5A 58 ?? ?? 5A 59 5A 58 5A 5E ?? ?? ?? ?? 5A 5E 5A 58 5A 5E ?? ?? ?? ?? 5A 5F 5A 5B 5A 58 ?? ?? }
        $s091 = { 5B 5A 5B 5A 5B 59 ?? ?? 5B 59 5B 5A 5B 59 ?? ?? 5B 58 5B 59 5B 5F ?? ?? ?? ?? 5B 5F 5B 59 5B 5F ?? ?? ?? ?? 5B 5E 5B 5A 5B 59 ?? ?? }
        $s092 = { 5C 5D 5C 5D 5C 5E ?? ?? 5C 5E 5C 5D 5C 5E ?? ?? 5C 5F 5C 5E 5C 58 ?? ?? ?? ?? 5C 58 5C 5E 5C 58 ?? ?? ?? ?? 5C 59 5C 5D 5C 5E ?? ?? }
        $s093 = { 5D 5C 5D 5C 5D 5F ?? ?? 5D 5F 5D 5C 5D 5F ?? ?? 5D 5E 5D 5F 5D 59 ?? ?? ?? ?? 5D 59 5D 5F 5D 59 ?? ?? ?? ?? 5D 58 5D 5C 5D 5F ?? ?? }
        $s094 = { 5E 5F 5E 5F 5E 5C ?? ?? 5E 5C 5E 5F 5E 5C ?? ?? 5E 5D 5E 5C 5E 5A ?? ?? ?? ?? 5E 5A 5E 5C 5E 5A ?? ?? ?? ?? 5E 5B 5E 5F 5E 5C ?? ?? }
        $s095 = { 5F 5E 5F 5E 5F 5D ?? ?? 5F 5D 5F 5E 5F 5D ?? ?? 5F 5C 5F 5D 5F 5B ?? ?? ?? ?? 5F 5B 5F 5D 5F 5B ?? ?? ?? ?? 5F 5A 5F 5E 5F 5D ?? ?? }
        $s096 = { 60 61 60 61 60 62 ?? ?? 60 62 60 61 60 62 ?? ?? 60 63 60 62 60 64 ?? ?? ?? ?? 60 64 60 62 60 64 ?? ?? ?? ?? 60 65 60 61 60 62 ?? ?? }
        $s097 = { 61 60 61 60 61 63 ?? ?? 61 63 61 60 61 63 ?? ?? 61 62 61 63 61 65 ?? ?? ?? ?? 61 65 61 63 61 65 ?? ?? ?? ?? 61 64 61 60 61 63 ?? ?? }
        $s098 = { 62 63 62 63 62 60 ?? ?? 62 60 62 63 62 60 ?? ?? 62 61 62 60 62 66 ?? ?? ?? ?? 62 66 62 60 62 66 ?? ?? ?? ?? 62 67 62 63 62 60 ?? ?? }
        $s099 = { 63 62 63 62 63 61 ?? ?? 63 61 63 62 63 61 ?? ?? 63 60 63 61 63 67 ?? ?? ?? ?? 63 67 63 61 63 67 ?? ?? ?? ?? 63 66 63 62 63 61 ?? ?? }
        $s100 = { 64 65 64 65 64 66 ?? ?? 64 66 64 65 64 66 ?? ?? 64 67 64 66 64 60 ?? ?? ?? ?? 64 60 64 66 64 60 ?? ?? ?? ?? 64 61 64 65 64 66 ?? ?? }
        $s101 = { 65 64 65 64 65 67 ?? ?? 65 67 65 64 65 67 ?? ?? 65 66 65 67 65 61 ?? ?? ?? ?? 65 61 65 67 65 61 ?? ?? ?? ?? 65 60 65 64 65 67 ?? ?? }
        $s102 = { 66 67 66 67 66 64 ?? ?? 66 64 66 67 66 64 ?? ?? 66 65 66 64 66 62 ?? ?? ?? ?? 66 62 66 64 66 62 ?? ?? ?? ?? 66 63 66 67 66 64 ?? ?? }
        $s103 = { 67 66 67 66 67 65 ?? ?? 67 65 67 66 67 65 ?? ?? 67 64 67 65 67 63 ?? ?? ?? ?? 67 63 67 65 67 63 ?? ?? ?? ?? 67 62 67 66 67 65 ?? ?? }
        $s104 = { 68 69 68 69 68 6A ?? ?? 68 6A 68 69 68 6A ?? ?? 68 6B 68 6A 68 6C ?? ?? ?? ?? 68 6C 68 6A 68 6C ?? ?? ?? ?? 68 6D 68 69 68 6A ?? ?? }
        $s105 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? }
        $s106 = { 6A 6B 6A 6B 6A 68 ?? ?? 6A 68 6A 6B 6A 68 ?? ?? 6A 69 6A 68 6A 6E ?? ?? ?? ?? 6A 6E 6A 68 6A 6E ?? ?? ?? ?? 6A 6F 6A 6B 6A 68 ?? ?? }
        $s107 = { 6B 6A 6B 6A 6B 69 ?? ?? 6B 69 6B 6A 6B 69 ?? ?? 6B 68 6B 69 6B 6F ?? ?? ?? ?? 6B 6F 6B 69 6B 6F ?? ?? ?? ?? 6B 6E 6B 6A 6B 69 ?? ?? }
        $s108 = { 6C 6D 6C 6D 6C 6E ?? ?? 6C 6E 6C 6D 6C 6E ?? ?? 6C 6F 6C 6E 6C 68 ?? ?? ?? ?? 6C 68 6C 6E 6C 68 ?? ?? ?? ?? 6C 69 6C 6D 6C 6E ?? ?? }
        $s109 = { 6D 6C 6D 6C 6D 6F ?? ?? 6D 6F 6D 6C 6D 6F ?? ?? 6D 6E 6D 6F 6D 69 ?? ?? ?? ?? 6D 69 6D 6F 6D 69 ?? ?? ?? ?? 6D 68 6D 6C 6D 6F ?? ?? }
        $s110 = { 6E 6F 6E 6F 6E 6C ?? ?? 6E 6C 6E 6F 6E 6C ?? ?? 6E 6D 6E 6C 6E 6A ?? ?? ?? ?? 6E 6A 6E 6C 6E 6A ?? ?? ?? ?? 6E 6B 6E 6F 6E 6C ?? ?? }
        $s111 = { 6F 6E 6F 6E 6F 6D ?? ?? 6F 6D 6F 6E 6F 6D ?? ?? 6F 6C 6F 6D 6F 6B ?? ?? ?? ?? 6F 6B 6F 6D 6F 6B ?? ?? ?? ?? 6F 6A 6F 6E 6F 6D ?? ?? }
        $s112 = { 70 71 70 71 70 72 ?? ?? 70 72 70 71 70 72 ?? ?? 70 73 70 72 70 74 ?? ?? ?? ?? 70 74 70 72 70 74 ?? ?? ?? ?? 70 75 70 71 70 72 ?? ?? }
        $s113 = { 71 70 71 70 71 73 ?? ?? 71 73 71 70 71 73 ?? ?? 71 72 71 73 71 75 ?? ?? ?? ?? 71 75 71 73 71 75 ?? ?? ?? ?? 71 74 71 70 71 73 ?? ?? }
        $s114 = { 72 73 72 73 72 70 ?? ?? 72 70 72 73 72 70 ?? ?? 72 71 72 70 72 76 ?? ?? ?? ?? 72 76 72 70 72 76 ?? ?? ?? ?? 72 77 72 73 72 70 ?? ?? }
        $s115 = { 73 72 73 72 73 71 ?? ?? 73 71 73 72 73 71 ?? ?? 73 70 73 71 73 77 ?? ?? ?? ?? 73 77 73 71 73 77 ?? ?? ?? ?? 73 76 73 72 73 71 ?? ?? }
        $s116 = { 74 75 74 75 74 76 ?? ?? 74 76 74 75 74 76 ?? ?? 74 77 74 76 74 70 ?? ?? ?? ?? 74 70 74 76 74 70 ?? ?? ?? ?? 74 71 74 75 74 76 ?? ?? }
        $s117 = { 75 74 75 74 75 77 ?? ?? 75 77 75 74 75 77 ?? ?? 75 76 75 77 75 71 ?? ?? ?? ?? 75 71 75 77 75 71 ?? ?? ?? ?? 75 70 75 74 75 77 ?? ?? }
        $s118 = { 76 77 76 77 76 74 ?? ?? 76 74 76 77 76 74 ?? ?? 76 75 76 74 76 72 ?? ?? ?? ?? 76 72 76 74 76 72 ?? ?? ?? ?? 76 73 76 77 76 74 ?? ?? }
        $s119 = { 77 76 77 76 77 75 ?? ?? 77 75 77 76 77 75 ?? ?? 77 74 77 75 77 73 ?? ?? ?? ?? 77 73 77 75 77 73 ?? ?? ?? ?? 77 72 77 76 77 75 ?? ?? }
        $s120 = { 78 79 78 79 78 7A ?? ?? 78 7A 78 79 78 7A ?? ?? 78 7B 78 7A 78 7C ?? ?? ?? ?? 78 7C 78 7A 78 7C ?? ?? ?? ?? 78 7D 78 79 78 7A ?? ?? }
        $s121 = { 79 78 79 78 79 7B ?? ?? 79 7B 79 78 79 7B ?? ?? 79 7A 79 7B 79 7D ?? ?? ?? ?? 79 7D 79 7B 79 7D ?? ?? ?? ?? 79 7C 79 78 79 7B ?? ?? }
        $s122 = { 7A 7B 7A 7B 7A 78 ?? ?? 7A 78 7A 7B 7A 78 ?? ?? 7A 79 7A 78 7A 7E ?? ?? ?? ?? 7A 7E 7A 78 7A 7E ?? ?? ?? ?? 7A 7F 7A 7B 7A 78 ?? ?? }
        $s123 = { 7B 7A 7B 7A 7B 79 ?? ?? 7B 79 7B 7A 7B 79 ?? ?? 7B 78 7B 79 7B 7F ?? ?? ?? ?? 7B 7F 7B 79 7B 7F ?? ?? ?? ?? 7B 7E 7B 7A 7B 79 ?? ?? }
        $s124 = { 7C 7D 7C 7D 7C 7E ?? ?? 7C 7E 7C 7D 7C 7E ?? ?? 7C 7F 7C 7E 7C 78 ?? ?? ?? ?? 7C 78 7C 7E 7C 78 ?? ?? ?? ?? 7C 79 7C 7D 7C 7E ?? ?? }
        $s125 = { 7D 7C 7D 7C 7D 7F ?? ?? 7D 7F 7D 7C 7D 7F ?? ?? 7D 7E 7D 7F 7D 79 ?? ?? ?? ?? 7D 79 7D 7F 7D 79 ?? ?? ?? ?? 7D 78 7D 7C 7D 7F ?? ?? }
        $s126 = { 7E 7F 7E 7F 7E 7C ?? ?? 7E 7C 7E 7F 7E 7C ?? ?? 7E 7D 7E 7C 7E 7A ?? ?? ?? ?? 7E 7A 7E 7C 7E 7A ?? ?? ?? ?? 7E 7B 7E 7F 7E 7C ?? ?? }
        $s127 = { 7F 7E 7F 7E 7F 7D ?? ?? 7F 7D 7F 7E 7F 7D ?? ?? 7F 7C 7F 7D 7F 7B ?? ?? ?? ?? 7F 7B 7F 7D 7F 7B ?? ?? ?? ?? 7F 7A 7F 7E 7F 7D ?? ?? }
        $s128 = { 80 81 80 81 80 82 ?? ?? 80 82 80 81 80 82 ?? ?? 80 83 80 82 80 84 ?? ?? ?? ?? 80 84 80 82 80 84 ?? ?? ?? ?? 80 85 80 81 80 82 ?? ?? }
        $s129 = { 81 80 81 80 81 83 ?? ?? 81 83 81 80 81 83 ?? ?? 81 82 81 83 81 85 ?? ?? ?? ?? 81 85 81 83 81 85 ?? ?? ?? ?? 81 84 81 80 81 83 ?? ?? }
        $s130 = { 82 83 82 83 82 80 ?? ?? 82 80 82 83 82 80 ?? ?? 82 81 82 80 82 86 ?? ?? ?? ?? 82 86 82 80 82 86 ?? ?? ?? ?? 82 87 82 83 82 80 ?? ?? }
        $s131 = { 83 82 83 82 83 81 ?? ?? 83 81 83 82 83 81 ?? ?? 83 80 83 81 83 87 ?? ?? ?? ?? 83 87 83 81 83 87 ?? ?? ?? ?? 83 86 83 82 83 81 ?? ?? }
        $s132 = { 84 85 84 85 84 86 ?? ?? 84 86 84 85 84 86 ?? ?? 84 87 84 86 84 80 ?? ?? ?? ?? 84 80 84 86 84 80 ?? ?? ?? ?? 84 81 84 85 84 86 ?? ?? }
        $s133 = { 85 84 85 84 85 87 ?? ?? 85 87 85 84 85 87 ?? ?? 85 86 85 87 85 81 ?? ?? ?? ?? 85 81 85 87 85 81 ?? ?? ?? ?? 85 80 85 84 85 87 ?? ?? }
        $s134 = { 86 87 86 87 86 84 ?? ?? 86 84 86 87 86 84 ?? ?? 86 85 86 84 86 82 ?? ?? ?? ?? 86 82 86 84 86 82 ?? ?? ?? ?? 86 83 86 87 86 84 ?? ?? }
        $s135 = { 87 86 87 86 87 85 ?? ?? 87 85 87 86 87 85 ?? ?? 87 84 87 85 87 83 ?? ?? ?? ?? 87 83 87 85 87 83 ?? ?? ?? ?? 87 82 87 86 87 85 ?? ?? }
        $s136 = { 88 89 88 89 88 8A ?? ?? 88 8A 88 89 88 8A ?? ?? 88 8B 88 8A 88 8C ?? ?? ?? ?? 88 8C 88 8A 88 8C ?? ?? ?? ?? 88 8D 88 89 88 8A ?? ?? }
        $s137 = { 89 88 89 88 89 8B ?? ?? 89 8B 89 88 89 8B ?? ?? 89 8A 89 8B 89 8D ?? ?? ?? ?? 89 8D 89 8B 89 8D ?? ?? ?? ?? 89 8C 89 88 89 8B ?? ?? }
        $s138 = { 8A 8B 8A 8B 8A 88 ?? ?? 8A 88 8A 8B 8A 88 ?? ?? 8A 89 8A 88 8A 8E ?? ?? ?? ?? 8A 8E 8A 88 8A 8E ?? ?? ?? ?? 8A 8F 8A 8B 8A 88 ?? ?? }
        $s139 = { 8B 8A 8B 8A 8B 89 ?? ?? 8B 89 8B 8A 8B 89 ?? ?? 8B 88 8B 89 8B 8F ?? ?? ?? ?? 8B 8F 8B 89 8B 8F ?? ?? ?? ?? 8B 8E 8B 8A 8B 89 ?? ?? }
        $s140 = { 8C 8D 8C 8D 8C 8E ?? ?? 8C 8E 8C 8D 8C 8E ?? ?? 8C 8F 8C 8E 8C 88 ?? ?? ?? ?? 8C 88 8C 8E 8C 88 ?? ?? ?? ?? 8C 89 8C 8D 8C 8E ?? ?? }
        $s141 = { 8D 8C 8D 8C 8D 8F ?? ?? 8D 8F 8D 8C 8D 8F ?? ?? 8D 8E 8D 8F 8D 89 ?? ?? ?? ?? 8D 89 8D 8F 8D 89 ?? ?? ?? ?? 8D 88 8D 8C 8D 8F ?? ?? }
        $s142 = { 8E 8F 8E 8F 8E 8C ?? ?? 8E 8C 8E 8F 8E 8C ?? ?? 8E 8D 8E 8C 8E 8A ?? ?? ?? ?? 8E 8A 8E 8C 8E 8A ?? ?? ?? ?? 8E 8B 8E 8F 8E 8C ?? ?? }
        $s143 = { 8F 8E 8F 8E 8F 8D ?? ?? 8F 8D 8F 8E 8F 8D ?? ?? 8F 8C 8F 8D 8F 8B ?? ?? ?? ?? 8F 8B 8F 8D 8F 8B ?? ?? ?? ?? 8F 8A 8F 8E 8F 8D ?? ?? }
        $s144 = { 90 91 90 91 90 92 ?? ?? 90 92 90 91 90 92 ?? ?? 90 93 90 92 90 94 ?? ?? ?? ?? 90 94 90 92 90 94 ?? ?? ?? ?? 90 95 90 91 90 92 ?? ?? }
        $s145 = { 91 90 91 90 91 93 ?? ?? 91 93 91 90 91 93 ?? ?? 91 92 91 93 91 95 ?? ?? ?? ?? 91 95 91 93 91 95 ?? ?? ?? ?? 91 94 91 90 91 93 ?? ?? }
        $s146 = { 92 93 92 93 92 90 ?? ?? 92 90 92 93 92 90 ?? ?? 92 91 92 90 92 96 ?? ?? ?? ?? 92 96 92 90 92 96 ?? ?? ?? ?? 92 97 92 93 92 90 ?? ?? }
        $s147 = { 93 92 93 92 93 91 ?? ?? 93 91 93 92 93 91 ?? ?? 93 90 93 91 93 97 ?? ?? ?? ?? 93 97 93 91 93 97 ?? ?? ?? ?? 93 96 93 92 93 91 ?? ?? }
        $s148 = { 94 95 94 95 94 96 ?? ?? 94 96 94 95 94 96 ?? ?? 94 97 94 96 94 90 ?? ?? ?? ?? 94 90 94 96 94 90 ?? ?? ?? ?? 94 91 94 95 94 96 ?? ?? }
        $s149 = { 95 94 95 94 95 97 ?? ?? 95 97 95 94 95 97 ?? ?? 95 96 95 97 95 91 ?? ?? ?? ?? 95 91 95 97 95 91 ?? ?? ?? ?? 95 90 95 94 95 97 ?? ?? }
        $s150 = { 96 97 96 97 96 94 ?? ?? 96 94 96 97 96 94 ?? ?? 96 95 96 94 96 92 ?? ?? ?? ?? 96 92 96 94 96 92 ?? ?? ?? ?? 96 93 96 97 96 94 ?? ?? }
        $s151 = { 97 96 97 96 97 95 ?? ?? 97 95 97 96 97 95 ?? ?? 97 94 97 95 97 93 ?? ?? ?? ?? 97 93 97 95 97 93 ?? ?? ?? ?? 97 92 97 96 97 95 ?? ?? }
        $s152 = { 98 99 98 99 98 9A ?? ?? 98 9A 98 99 98 9A ?? ?? 98 9B 98 9A 98 9C ?? ?? ?? ?? 98 9C 98 9A 98 9C ?? ?? ?? ?? 98 9D 98 99 98 9A ?? ?? }
        $s153 = { 99 98 99 98 99 9B ?? ?? 99 9B 99 98 99 9B ?? ?? 99 9A 99 9B 99 9D ?? ?? ?? ?? 99 9D 99 9B 99 9D ?? ?? ?? ?? 99 9C 99 98 99 9B ?? ?? }
        $s154 = { 9A 9B 9A 9B 9A 98 ?? ?? 9A 98 9A 9B 9A 98 ?? ?? 9A 99 9A 98 9A 9E ?? ?? ?? ?? 9A 9E 9A 98 9A 9E ?? ?? ?? ?? 9A 9F 9A 9B 9A 98 ?? ?? }
        $s155 = { 9B 9A 9B 9A 9B 99 ?? ?? 9B 99 9B 9A 9B 99 ?? ?? 9B 98 9B 99 9B 9F ?? ?? ?? ?? 9B 9F 9B 99 9B 9F ?? ?? ?? ?? 9B 9E 9B 9A 9B 99 ?? ?? }
        $s156 = { 9C 9D 9C 9D 9C 9E ?? ?? 9C 9E 9C 9D 9C 9E ?? ?? 9C 9F 9C 9E 9C 98 ?? ?? ?? ?? 9C 98 9C 9E 9C 98 ?? ?? ?? ?? 9C 99 9C 9D 9C 9E ?? ?? }
        $s157 = { 9D 9C 9D 9C 9D 9F ?? ?? 9D 9F 9D 9C 9D 9F ?? ?? 9D 9E 9D 9F 9D 99 ?? ?? ?? ?? 9D 99 9D 9F 9D 99 ?? ?? ?? ?? 9D 98 9D 9C 9D 9F ?? ?? }
        $s158 = { 9E 9F 9E 9F 9E 9C ?? ?? 9E 9C 9E 9F 9E 9C ?? ?? 9E 9D 9E 9C 9E 9A ?? ?? ?? ?? 9E 9A 9E 9C 9E 9A ?? ?? ?? ?? 9E 9B 9E 9F 9E 9C ?? ?? }
        $s159 = { 9F 9E 9F 9E 9F 9D ?? ?? 9F 9D 9F 9E 9F 9D ?? ?? 9F 9C 9F 9D 9F 9B ?? ?? ?? ?? 9F 9B 9F 9D 9F 9B ?? ?? ?? ?? 9F 9A 9F 9E 9F 9D ?? ?? }
        $s160 = { A0 A1 A0 A1 A0 A2 ?? ?? A0 A2 A0 A1 A0 A2 ?? ?? A0 A3 A0 A2 A0 A4 ?? ?? ?? ?? A0 A4 A0 A2 A0 A4 ?? ?? ?? ?? A0 A5 A0 A1 A0 A2 ?? ?? }
        $s161 = { A1 A0 A1 A0 A1 A3 ?? ?? A1 A3 A1 A0 A1 A3 ?? ?? A1 A2 A1 A3 A1 A5 ?? ?? ?? ?? A1 A5 A1 A3 A1 A5 ?? ?? ?? ?? A1 A4 A1 A0 A1 A3 ?? ?? }
        $s162 = { A2 A3 A2 A3 A2 A0 ?? ?? A2 A0 A2 A3 A2 A0 ?? ?? A2 A1 A2 A0 A2 A6 ?? ?? ?? ?? A2 A6 A2 A0 A2 A6 ?? ?? ?? ?? A2 A7 A2 A3 A2 A0 ?? ?? }
        $s163 = { A3 A2 A3 A2 A3 A1 ?? ?? A3 A1 A3 A2 A3 A1 ?? ?? A3 A0 A3 A1 A3 A7 ?? ?? ?? ?? A3 A7 A3 A1 A3 A7 ?? ?? ?? ?? A3 A6 A3 A2 A3 A1 ?? ?? }
        $s164 = { A4 A5 A4 A5 A4 A6 ?? ?? A4 A6 A4 A5 A4 A6 ?? ?? A4 A7 A4 A6 A4 A0 ?? ?? ?? ?? A4 A0 A4 A6 A4 A0 ?? ?? ?? ?? A4 A1 A4 A5 A4 A6 ?? ?? }
        $s165 = { A5 A4 A5 A4 A5 A7 ?? ?? A5 A7 A5 A4 A5 A7 ?? ?? A5 A6 A5 A7 A5 A1 ?? ?? ?? ?? A5 A1 A5 A7 A5 A1 ?? ?? ?? ?? A5 A0 A5 A4 A5 A7 ?? ?? }
        $s166 = { A6 A7 A6 A7 A6 A4 ?? ?? A6 A4 A6 A7 A6 A4 ?? ?? A6 A5 A6 A4 A6 A2 ?? ?? ?? ?? A6 A2 A6 A4 A6 A2 ?? ?? ?? ?? A6 A3 A6 A7 A6 A4 ?? ?? }
        $s167 = { A7 A6 A7 A6 A7 A5 ?? ?? A7 A5 A7 A6 A7 A5 ?? ?? A7 A4 A7 A5 A7 A3 ?? ?? ?? ?? A7 A3 A7 A5 A7 A3 ?? ?? ?? ?? A7 A2 A7 A6 A7 A5 ?? ?? }
        $s168 = { A8 A9 A8 A9 A8 AA ?? ?? A8 AA A8 A9 A8 AA ?? ?? A8 AB A8 AA A8 AC ?? ?? ?? ?? A8 AC A8 AA A8 AC ?? ?? ?? ?? A8 AD A8 A9 A8 AA ?? ?? }
        $s169 = { A9 A8 A9 A8 A9 AB ?? ?? A9 AB A9 A8 A9 AB ?? ?? A9 AA A9 AB A9 AD ?? ?? ?? ?? A9 AD A9 AB A9 AD ?? ?? ?? ?? A9 AC A9 A8 A9 AB ?? ?? }
        $s170 = { AA AB AA AB AA A8 ?? ?? AA A8 AA AB AA A8 ?? ?? AA A9 AA A8 AA AE ?? ?? ?? ?? AA AE AA A8 AA AE ?? ?? ?? ?? AA AF AA AB AA A8 ?? ?? }
        $s171 = { AB AA AB AA AB A9 ?? ?? AB A9 AB AA AB A9 ?? ?? AB A8 AB A9 AB AF ?? ?? ?? ?? AB AF AB A9 AB AF ?? ?? ?? ?? AB AE AB AA AB A9 ?? ?? }
        $s172 = { AC AD AC AD AC AE ?? ?? AC AE AC AD AC AE ?? ?? AC AF AC AE AC A8 ?? ?? ?? ?? AC A8 AC AE AC A8 ?? ?? ?? ?? AC A9 AC AD AC AE ?? ?? }
        $s173 = { AD AC AD AC AD AF ?? ?? AD AF AD AC AD AF ?? ?? AD AE AD AF AD A9 ?? ?? ?? ?? AD A9 AD AF AD A9 ?? ?? ?? ?? AD A8 AD AC AD AF ?? ?? }
        $s174 = { AE AF AE AF AE AC ?? ?? AE AC AE AF AE AC ?? ?? AE AD AE AC AE AA ?? ?? ?? ?? AE AA AE AC AE AA ?? ?? ?? ?? AE AB AE AF AE AC ?? ?? }
        $s175 = { AF AE AF AE AF AD ?? ?? AF AD AF AE AF AD ?? ?? AF AC AF AD AF AB ?? ?? ?? ?? AF AB AF AD AF AB ?? ?? ?? ?? AF AA AF AE AF AD ?? ?? }
        $s176 = { B0 B1 B0 B1 B0 B2 ?? ?? B0 B2 B0 B1 B0 B2 ?? ?? B0 B3 B0 B2 B0 B4 ?? ?? ?? ?? B0 B4 B0 B2 B0 B4 ?? ?? ?? ?? B0 B5 B0 B1 B0 B2 ?? ?? }
        $s177 = { B1 B0 B1 B0 B1 B3 ?? ?? B1 B3 B1 B0 B1 B3 ?? ?? B1 B2 B1 B3 B1 B5 ?? ?? ?? ?? B1 B5 B1 B3 B1 B5 ?? ?? ?? ?? B1 B4 B1 B0 B1 B3 ?? ?? }
        $s178 = { B2 B3 B2 B3 B2 B0 ?? ?? B2 B0 B2 B3 B2 B0 ?? ?? B2 B1 B2 B0 B2 B6 ?? ?? ?? ?? B2 B6 B2 B0 B2 B6 ?? ?? ?? ?? B2 B7 B2 B3 B2 B0 ?? ?? }
        $s179 = { B3 B2 B3 B2 B3 B1 ?? ?? B3 B1 B3 B2 B3 B1 ?? ?? B3 B0 B3 B1 B3 B7 ?? ?? ?? ?? B3 B7 B3 B1 B3 B7 ?? ?? ?? ?? B3 B6 B3 B2 B3 B1 ?? ?? }
        $s180 = { B4 B5 B4 B5 B4 B6 ?? ?? B4 B6 B4 B5 B4 B6 ?? ?? B4 B7 B4 B6 B4 B0 ?? ?? ?? ?? B4 B0 B4 B6 B4 B0 ?? ?? ?? ?? B4 B1 B4 B5 B4 B6 ?? ?? }
        $s181 = { B5 B4 B5 B4 B5 B7 ?? ?? B5 B7 B5 B4 B5 B7 ?? ?? B5 B6 B5 B7 B5 B1 ?? ?? ?? ?? B5 B1 B5 B7 B5 B1 ?? ?? ?? ?? B5 B0 B5 B4 B5 B7 ?? ?? }
        $s182 = { B6 B7 B6 B7 B6 B4 ?? ?? B6 B4 B6 B7 B6 B4 ?? ?? B6 B5 B6 B4 B6 B2 ?? ?? ?? ?? B6 B2 B6 B4 B6 B2 ?? ?? ?? ?? B6 B3 B6 B7 B6 B4 ?? ?? }
        $s183 = { B7 B6 B7 B6 B7 B5 ?? ?? B7 B5 B7 B6 B7 B5 ?? ?? B7 B4 B7 B5 B7 B3 ?? ?? ?? ?? B7 B3 B7 B5 B7 B3 ?? ?? ?? ?? B7 B2 B7 B6 B7 B5 ?? ?? }
        $s184 = { B8 B9 B8 B9 B8 BA ?? ?? B8 BA B8 B9 B8 BA ?? ?? B8 BB B8 BA B8 BC ?? ?? ?? ?? B8 BC B8 BA B8 BC ?? ?? ?? ?? B8 BD B8 B9 B8 BA ?? ?? }
        $s185 = { B9 B8 B9 B8 B9 BB ?? ?? B9 BB B9 B8 B9 BB ?? ?? B9 BA B9 BB B9 BD ?? ?? ?? ?? B9 BD B9 BB B9 BD ?? ?? ?? ?? B9 BC B9 B8 B9 BB ?? ?? }
        $s186 = { BA BB BA BB BA B8 ?? ?? BA B8 BA BB BA B8 ?? ?? BA B9 BA B8 BA BE ?? ?? ?? ?? BA BE BA B8 BA BE ?? ?? ?? ?? BA BF BA BB BA B8 ?? ?? }
        $s187 = { BB BA BB BA BB B9 ?? ?? BB B9 BB BA BB B9 ?? ?? BB B8 BB B9 BB BF ?? ?? ?? ?? BB BF BB B9 BB BF ?? ?? ?? ?? BB BE BB BA BB B9 ?? ?? }
        $s188 = { BC BD BC BD BC BE ?? ?? BC BE BC BD BC BE ?? ?? BC BF BC BE BC B8 ?? ?? ?? ?? BC B8 BC BE BC B8 ?? ?? ?? ?? BC B9 BC BD BC BE ?? ?? }
        $s189 = { BD BC BD BC BD BF ?? ?? BD BF BD BC BD BF ?? ?? BD BE BD BF BD B9 ?? ?? ?? ?? BD B9 BD BF BD B9 ?? ?? ?? ?? BD B8 BD BC BD BF ?? ?? }
        $s190 = { BE BF BE BF BE BC ?? ?? BE BC BE BF BE BC ?? ?? BE BD BE BC BE BA ?? ?? ?? ?? BE BA BE BC BE BA ?? ?? ?? ?? BE BB BE BF BE BC ?? ?? }
        $s191 = { BF BE BF BE BF BD ?? ?? BF BD BF BE BF BD ?? ?? BF BC BF BD BF BB ?? ?? ?? ?? BF BB BF BD BF BB ?? ?? ?? ?? BF BA BF BE BF BD ?? ?? }
        $s192 = { C0 C1 C0 C1 C0 C2 ?? ?? C0 C2 C0 C1 C0 C2 ?? ?? C0 C3 C0 C2 C0 C4 ?? ?? ?? ?? C0 C4 C0 C2 C0 C4 ?? ?? ?? ?? C0 C5 C0 C1 C0 C2 ?? ?? }
        $s193 = { C1 C0 C1 C0 C1 C3 ?? ?? C1 C3 C1 C0 C1 C3 ?? ?? C1 C2 C1 C3 C1 C5 ?? ?? ?? ?? C1 C5 C1 C3 C1 C5 ?? ?? ?? ?? C1 C4 C1 C0 C1 C3 ?? ?? }
        $s194 = { C2 C3 C2 C3 C2 C0 ?? ?? C2 C0 C2 C3 C2 C0 ?? ?? C2 C1 C2 C0 C2 C6 ?? ?? ?? ?? C2 C6 C2 C0 C2 C6 ?? ?? ?? ?? C2 C7 C2 C3 C2 C0 ?? ?? }
        $s195 = { C3 C2 C3 C2 C3 C1 ?? ?? C3 C1 C3 C2 C3 C1 ?? ?? C3 C0 C3 C1 C3 C7 ?? ?? ?? ?? C3 C7 C3 C1 C3 C7 ?? ?? ?? ?? C3 C6 C3 C2 C3 C1 ?? ?? }
        $s196 = { C4 C5 C4 C5 C4 C6 ?? ?? C4 C6 C4 C5 C4 C6 ?? ?? C4 C7 C4 C6 C4 C0 ?? ?? ?? ?? C4 C0 C4 C6 C4 C0 ?? ?? ?? ?? C4 C1 C4 C5 C4 C6 ?? ?? }
        $s197 = { C5 C4 C5 C4 C5 C7 ?? ?? C5 C7 C5 C4 C5 C7 ?? ?? C5 C6 C5 C7 C5 C1 ?? ?? ?? ?? C5 C1 C5 C7 C5 C1 ?? ?? ?? ?? C5 C0 C5 C4 C5 C7 ?? ?? }
        $s198 = { C6 C7 C6 C7 C6 C4 ?? ?? C6 C4 C6 C7 C6 C4 ?? ?? C6 C5 C6 C4 C6 C2 ?? ?? ?? ?? C6 C2 C6 C4 C6 C2 ?? ?? ?? ?? C6 C3 C6 C7 C6 C4 ?? ?? }
        $s199 = { C7 C6 C7 C6 C7 C5 ?? ?? C7 C5 C7 C6 C7 C5 ?? ?? C7 C4 C7 C5 C7 C3 ?? ?? ?? ?? C7 C3 C7 C5 C7 C3 ?? ?? ?? ?? C7 C2 C7 C6 C7 C5 ?? ?? }
        $s200 = { C8 C9 C8 C9 C8 CA ?? ?? C8 CA C8 C9 C8 CA ?? ?? C8 CB C8 CA C8 CC ?? ?? ?? ?? C8 CC C8 CA C8 CC ?? ?? ?? ?? C8 CD C8 C9 C8 CA ?? ?? }
        $s201 = { C9 C8 C9 C8 C9 CB ?? ?? C9 CB C9 C8 C9 CB ?? ?? C9 CA C9 CB C9 CD ?? ?? ?? ?? C9 CD C9 CB C9 CD ?? ?? ?? ?? C9 CC C9 C8 C9 CB ?? ?? }
        $s202 = { CA CB CA CB CA C8 ?? ?? CA C8 CA CB CA C8 ?? ?? CA C9 CA C8 CA CE ?? ?? ?? ?? CA CE CA C8 CA CE ?? ?? ?? ?? CA CF CA CB CA C8 ?? ?? }
        $s203 = { CB CA CB CA CB C9 ?? ?? CB C9 CB CA CB C9 ?? ?? CB C8 CB C9 CB CF ?? ?? ?? ?? CB CF CB C9 CB CF ?? ?? ?? ?? CB CE CB CA CB C9 ?? ?? }
        $s204 = { CC CD CC CD CC CE ?? ?? CC CE CC CD CC CE ?? ?? CC CF CC CE CC C8 ?? ?? ?? ?? CC C8 CC CE CC C8 ?? ?? ?? ?? CC C9 CC CD CC CE ?? ?? }
        $s205 = { CD CC CD CC CD CF ?? ?? CD CF CD CC CD CF ?? ?? CD CE CD CF CD C9 ?? ?? ?? ?? CD C9 CD CF CD C9 ?? ?? ?? ?? CD C8 CD CC CD CF ?? ?? }
        $s206 = { CE CF CE CF CE CC ?? ?? CE CC CE CF CE CC ?? ?? CE CD CE CC CE CA ?? ?? ?? ?? CE CA CE CC CE CA ?? ?? ?? ?? CE CB CE CF CE CC ?? ?? }
        $s207 = { CF CE CF CE CF CD ?? ?? CF CD CF CE CF CD ?? ?? CF CC CF CD CF CB ?? ?? ?? ?? CF CB CF CD CF CB ?? ?? ?? ?? CF CA CF CE CF CD ?? ?? }
        $s208 = { D0 D1 D0 D1 D0 D2 ?? ?? D0 D2 D0 D1 D0 D2 ?? ?? D0 D3 D0 D2 D0 D4 ?? ?? ?? ?? D0 D4 D0 D2 D0 D4 ?? ?? ?? ?? D0 D5 D0 D1 D0 D2 ?? ?? }
        $s209 = { D1 D0 D1 D0 D1 D3 ?? ?? D1 D3 D1 D0 D1 D3 ?? ?? D1 D2 D1 D3 D1 D5 ?? ?? ?? ?? D1 D5 D1 D3 D1 D5 ?? ?? ?? ?? D1 D4 D1 D0 D1 D3 ?? ?? }
        $s210 = { D2 D3 D2 D3 D2 D0 ?? ?? D2 D0 D2 D3 D2 D0 ?? ?? D2 D1 D2 D0 D2 D6 ?? ?? ?? ?? D2 D6 D2 D0 D2 D6 ?? ?? ?? ?? D2 D7 D2 D3 D2 D0 ?? ?? }
        $s211 = { D3 D2 D3 D2 D3 D1 ?? ?? D3 D1 D3 D2 D3 D1 ?? ?? D3 D0 D3 D1 D3 D7 ?? ?? ?? ?? D3 D7 D3 D1 D3 D7 ?? ?? ?? ?? D3 D6 D3 D2 D3 D1 ?? ?? }
        $s212 = { D4 D5 D4 D5 D4 D6 ?? ?? D4 D6 D4 D5 D4 D6 ?? ?? D4 D7 D4 D6 D4 D0 ?? ?? ?? ?? D4 D0 D4 D6 D4 D0 ?? ?? ?? ?? D4 D1 D4 D5 D4 D6 ?? ?? }
        $s213 = { D5 D4 D5 D4 D5 D7 ?? ?? D5 D7 D5 D4 D5 D7 ?? ?? D5 D6 D5 D7 D5 D1 ?? ?? ?? ?? D5 D1 D5 D7 D5 D1 ?? ?? ?? ?? D5 D0 D5 D4 D5 D7 ?? ?? }
        $s214 = { D6 D7 D6 D7 D6 D4 ?? ?? D6 D4 D6 D7 D6 D4 ?? ?? D6 D5 D6 D4 D6 D2 ?? ?? ?? ?? D6 D2 D6 D4 D6 D2 ?? ?? ?? ?? D6 D3 D6 D7 D6 D4 ?? ?? }
        $s215 = { D7 D6 D7 D6 D7 D5 ?? ?? D7 D5 D7 D6 D7 D5 ?? ?? D7 D4 D7 D5 D7 D3 ?? ?? ?? ?? D7 D3 D7 D5 D7 D3 ?? ?? ?? ?? D7 D2 D7 D6 D7 D5 ?? ?? }
        $s216 = { D8 D9 D8 D9 D8 DA ?? ?? D8 DA D8 D9 D8 DA ?? ?? D8 DB D8 DA D8 DC ?? ?? ?? ?? D8 DC D8 DA D8 DC ?? ?? ?? ?? D8 DD D8 D9 D8 DA ?? ?? }
        $s217 = { D9 D8 D9 D8 D9 DB ?? ?? D9 DB D9 D8 D9 DB ?? ?? D9 DA D9 DB D9 DD ?? ?? ?? ?? D9 DD D9 DB D9 DD ?? ?? ?? ?? D9 DC D9 D8 D9 DB ?? ?? }
        $s218 = { DA DB DA DB DA D8 ?? ?? DA D8 DA DB DA D8 ?? ?? DA D9 DA D8 DA DE ?? ?? ?? ?? DA DE DA D8 DA DE ?? ?? ?? ?? DA DF DA DB DA D8 ?? ?? }
        $s219 = { DB DA DB DA DB D9 ?? ?? DB D9 DB DA DB D9 ?? ?? DB D8 DB D9 DB DF ?? ?? ?? ?? DB DF DB D9 DB DF ?? ?? ?? ?? DB DE DB DA DB D9 ?? ?? }
        $s220 = { DC DD DC DD DC DE ?? ?? DC DE DC DD DC DE ?? ?? DC DF DC DE DC D8 ?? ?? ?? ?? DC D8 DC DE DC D8 ?? ?? ?? ?? DC D9 DC DD DC DE ?? ?? }
        $s221 = { DD DC DD DC DD DF ?? ?? DD DF DD DC DD DF ?? ?? DD DE DD DF DD D9 ?? ?? ?? ?? DD D9 DD DF DD D9 ?? ?? ?? ?? DD D8 DD DC DD DF ?? ?? }
        $s222 = { DE DF DE DF DE DC ?? ?? DE DC DE DF DE DC ?? ?? DE DD DE DC DE DA ?? ?? ?? ?? DE DA DE DC DE DA ?? ?? ?? ?? DE DB DE DF DE DC ?? ?? }
        $s223 = { DF DE DF DE DF DD ?? ?? DF DD DF DE DF DD ?? ?? DF DC DF DD DF DB ?? ?? ?? ?? DF DB DF DD DF DB ?? ?? ?? ?? DF DA DF DE DF DD ?? ?? }
        $s224 = { E0 E1 E0 E1 E0 E2 ?? ?? E0 E2 E0 E1 E0 E2 ?? ?? E0 E3 E0 E2 E0 E4 ?? ?? ?? ?? E0 E4 E0 E2 E0 E4 ?? ?? ?? ?? E0 E5 E0 E1 E0 E2 ?? ?? }
        $s225 = { E1 E0 E1 E0 E1 E3 ?? ?? E1 E3 E1 E0 E1 E3 ?? ?? E1 E2 E1 E3 E1 E5 ?? ?? ?? ?? E1 E5 E1 E3 E1 E5 ?? ?? ?? ?? E1 E4 E1 E0 E1 E3 ?? ?? }
        $s226 = { E2 E3 E2 E3 E2 E0 ?? ?? E2 E0 E2 E3 E2 E0 ?? ?? E2 E1 E2 E0 E2 E6 ?? ?? ?? ?? E2 E6 E2 E0 E2 E6 ?? ?? ?? ?? E2 E7 E2 E3 E2 E0 ?? ?? }
        $s227 = { E3 E2 E3 E2 E3 E1 ?? ?? E3 E1 E3 E2 E3 E1 ?? ?? E3 E0 E3 E1 E3 E7 ?? ?? ?? ?? E3 E7 E3 E1 E3 E7 ?? ?? ?? ?? E3 E6 E3 E2 E3 E1 ?? ?? }
        $s228 = { E4 E5 E4 E5 E4 E6 ?? ?? E4 E6 E4 E5 E4 E6 ?? ?? E4 E7 E4 E6 E4 E0 ?? ?? ?? ?? E4 E0 E4 E6 E4 E0 ?? ?? ?? ?? E4 E1 E4 E5 E4 E6 ?? ?? }
        $s229 = { E5 E4 E5 E4 E5 E7 ?? ?? E5 E7 E5 E4 E5 E7 ?? ?? E5 E6 E5 E7 E5 E1 ?? ?? ?? ?? E5 E1 E5 E7 E5 E1 ?? ?? ?? ?? E5 E0 E5 E4 E5 E7 ?? ?? }
        $s230 = { E6 E7 E6 E7 E6 E4 ?? ?? E6 E4 E6 E7 E6 E4 ?? ?? E6 E5 E6 E4 E6 E2 ?? ?? ?? ?? E6 E2 E6 E4 E6 E2 ?? ?? ?? ?? E6 E3 E6 E7 E6 E4 ?? ?? }
        $s231 = { E7 E6 E7 E6 E7 E5 ?? ?? E7 E5 E7 E6 E7 E5 ?? ?? E7 E4 E7 E5 E7 E3 ?? ?? ?? ?? E7 E3 E7 E5 E7 E3 ?? ?? ?? ?? E7 E2 E7 E6 E7 E5 ?? ?? }
        $s232 = { E8 E9 E8 E9 E8 EA ?? ?? E8 EA E8 E9 E8 EA ?? ?? E8 EB E8 EA E8 EC ?? ?? ?? ?? E8 EC E8 EA E8 EC ?? ?? ?? ?? E8 ED E8 E9 E8 EA ?? ?? }
        $s233 = { E9 E8 E9 E8 E9 EB ?? ?? E9 EB E9 E8 E9 EB ?? ?? E9 EA E9 EB E9 ED ?? ?? ?? ?? E9 ED E9 EB E9 ED ?? ?? ?? ?? E9 EC E9 E8 E9 EB ?? ?? }
        $s234 = { EA EB EA EB EA E8 ?? ?? EA E8 EA EB EA E8 ?? ?? EA E9 EA E8 EA EE ?? ?? ?? ?? EA EE EA E8 EA EE ?? ?? ?? ?? EA EF EA EB EA E8 ?? ?? }
        $s235 = { EB EA EB EA EB E9 ?? ?? EB E9 EB EA EB E9 ?? ?? EB E8 EB E9 EB EF ?? ?? ?? ?? EB EF EB E9 EB EF ?? ?? ?? ?? EB EE EB EA EB E9 ?? ?? }
        $s236 = { EC ED EC ED EC EE ?? ?? EC EE EC ED EC EE ?? ?? EC EF EC EE EC E8 ?? ?? ?? ?? EC E8 EC EE EC E8 ?? ?? ?? ?? EC E9 EC ED EC EE ?? ?? }
        $s237 = { ED EC ED EC ED EF ?? ?? ED EF ED EC ED EF ?? ?? ED EE ED EF ED E9 ?? ?? ?? ?? ED E9 ED EF ED E9 ?? ?? ?? ?? ED E8 ED EC ED EF ?? ?? }
        $s238 = { EE EF EE EF EE EC ?? ?? EE EC EE EF EE EC ?? ?? EE ED EE EC EE EA ?? ?? ?? ?? EE EA EE EC EE EA ?? ?? ?? ?? EE EB EE EF EE EC ?? ?? }
        $s239 = { EF EE EF EE EF ED ?? ?? EF ED EF EE EF ED ?? ?? EF EC EF ED EF EB ?? ?? ?? ?? EF EB EF ED EF EB ?? ?? ?? ?? EF EA EF EE EF ED ?? ?? }
        $s240 = { F0 F1 F0 F1 F0 F2 ?? ?? F0 F2 F0 F1 F0 F2 ?? ?? F0 F3 F0 F2 F0 F4 ?? ?? ?? ?? F0 F4 F0 F2 F0 F4 ?? ?? ?? ?? F0 F5 F0 F1 F0 F2 ?? ?? }
        $s241 = { F1 F0 F1 F0 F1 F3 ?? ?? F1 F3 F1 F0 F1 F3 ?? ?? F1 F2 F1 F3 F1 F5 ?? ?? ?? ?? F1 F5 F1 F3 F1 F5 ?? ?? ?? ?? F1 F4 F1 F0 F1 F3 ?? ?? }
        $s242 = { F2 F3 F2 F3 F2 F0 ?? ?? F2 F0 F2 F3 F2 F0 ?? ?? F2 F1 F2 F0 F2 F6 ?? ?? ?? ?? F2 F6 F2 F0 F2 F6 ?? ?? ?? ?? F2 F7 F2 F3 F2 F0 ?? ?? }
        $s243 = { F3 F2 F3 F2 F3 F1 ?? ?? F3 F1 F3 F2 F3 F1 ?? ?? F3 F0 F3 F1 F3 F7 ?? ?? ?? ?? F3 F7 F3 F1 F3 F7 ?? ?? ?? ?? F3 F6 F3 F2 F3 F1 ?? ?? }
        $s244 = { F4 F5 F4 F5 F4 F6 ?? ?? F4 F6 F4 F5 F4 F6 ?? ?? F4 F7 F4 F6 F4 F0 ?? ?? ?? ?? F4 F0 F4 F6 F4 F0 ?? ?? ?? ?? F4 F1 F4 F5 F4 F6 ?? ?? }
        $s245 = { F5 F4 F5 F4 F5 F7 ?? ?? F5 F7 F5 F4 F5 F7 ?? ?? F5 F6 F5 F7 F5 F1 ?? ?? ?? ?? F5 F1 F5 F7 F5 F1 ?? ?? ?? ?? F5 F0 F5 F4 F5 F7 ?? ?? }
        $s246 = { F6 F7 F6 F7 F6 F4 ?? ?? F6 F4 F6 F7 F6 F4 ?? ?? F6 F5 F6 F4 F6 F2 ?? ?? ?? ?? F6 F2 F6 F4 F6 F2 ?? ?? ?? ?? F6 F3 F6 F7 F6 F4 ?? ?? }
        $s247 = { F7 F6 F7 F6 F7 F5 ?? ?? F7 F5 F7 F6 F7 F5 ?? ?? F7 F4 F7 F5 F7 F3 ?? ?? ?? ?? F7 F3 F7 F5 F7 F3 ?? ?? ?? ?? F7 F2 F7 F6 F7 F5 ?? ?? }
        $s248 = { F8 F9 F8 F9 F8 FA ?? ?? F8 FA F8 F9 F8 FA ?? ?? F8 FB F8 FA F8 FC ?? ?? ?? ?? F8 FC F8 FA F8 FC ?? ?? ?? ?? F8 FD F8 F9 F8 FA ?? ?? }
        $s249 = { F9 F8 F9 F8 F9 FB ?? ?? F9 FB F9 F8 F9 FB ?? ?? F9 FA F9 FB F9 FD ?? ?? ?? ?? F9 FD F9 FB F9 FD ?? ?? ?? ?? F9 FC F9 F8 F9 FB ?? ?? }
        $s250 = { FA FB FA FB FA F8 ?? ?? FA F8 FA FB FA F8 ?? ?? FA F9 FA F8 FA FE ?? ?? ?? ?? FA FE FA F8 FA FE ?? ?? ?? ?? FA FF FA FB FA F8 ?? ?? }
        $s251 = { FB FA FB FA FB F9 ?? ?? FB F9 FB FA FB F9 ?? ?? FB F8 FB F9 FB FF ?? ?? ?? ?? FB FF FB F9 FB FF ?? ?? ?? ?? FB FE FB FA FB F9 ?? ?? }
        $s252 = { FC FD FC FD FC FE ?? ?? FC FE FC FD FC FE ?? ?? FC FF FC FE FC F8 ?? ?? ?? ?? FC F8 FC FE FC F8 ?? ?? ?? ?? FC F9 FC FD FC FE ?? ?? }
        $s253 = { FD FC FD FC FD FF ?? ?? FD FF FD FC FD FF ?? ?? FD FE FD FF FD F9 ?? ?? ?? ?? FD F9 FD FF FD F9 ?? ?? ?? ?? FD F8 FD FC FD FF ?? ?? }
        $s254 = { FE FF FE FF FE FC ?? ?? FE FC FE FF FE FC ?? ?? FE FD FE FC FE FA ?? ?? ?? ?? FE FA FE FC FE FA ?? ?? ?? ?? FE FB FE FF FE FC ?? ?? }
        $s255 = { FF FE FF FE FF FD ?? ?? FF FD FF FE FF FD ?? ?? FF FC FF FD FF FB ?? ?? ?? ?? FF FB FF FD FF FB ?? ?? ?? ?? FF FA FF FE FF FD ?? ?? }
        
        $fp1 = "ICSharpCode.Decompiler" wide
    condition:
        any of ($s*) and not 1 of ($fp*)
}

rule CobaltStrike_MZ_Launcher {
    meta:
        description = "Detect the risk of  Malware Cobalt Strike Rule 47"
    strings:
        $mz_launcher = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D }
    condition:
        $mz_launcher
}

rule CobaltStrike_Unmodifed_Beacon {
    meta:
        description ="Detect the risk of  Malware Cobalt Strike Rule 48"
    strings:
        $loader_export = "ReflectiveLoader"
        $exportname = "beacon.dll"
    condition:
        all of them
}


rule HKTL_CobaltStrike_Beacon_Strings {
   meta:
      description = "Detect the risk of  Malware Cobalt Strike Rule 49"
   strings:
      $s1 = "%02d/%02d/%02d %02d:%02d:%02d"
      $s2 = "Started service %s on %s"
      $s3 = "%s as %s\\%s: %d"
   condition:
      2 of them
}


rule HKTL_CobaltStrike_Beacon_4_2_Decrypt {
   meta:
      description = "Detect the risk of  Malware Cobalt Strike Rule 50"
   strings:
      $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
      $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
   condition:
      any of them
}

rule HKTL_Win_CobaltStrike  {
   meta:
      description ="Detect the risk of  Malware Cobalt Strike Rule 51"
   strings:
      $s1 = "%s (admin)" fullword
      $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
      $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
      $s4 = "%s as %s\\%s: %d" fullword
      $s5 = "%s&%s=%s" fullword
      $s6 = "rijndael" fullword
      $s7 = "(null)"
   condition:
      all of them
}