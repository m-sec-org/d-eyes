import "math"
rule webshell_php_generic
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 1"
	strings:
		$wfp_tiny1 = "escapeshellarg" fullword
		$wfp_tiny2 = "addslashes" fullword
		$gfp_tiny3 = "include \"./common.php\";" // xcache
		$gfp_tiny4 = "assert('FALSE');"
		$gfp_tiny5 = "assert(false);"
		$gfp_tiny6 = "assert(FALSE);"
		$gfp_tiny7 = "assert('array_key_exists("
		$gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
		$gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
		$gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
		$php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		$gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6  = "self.delete"
		$gen_bit_sus9  = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus47 = "Shell" fullword wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus51 = "suhosin" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		//$gen_bit_sus64 = "\"command\"" fullword wide ascii
		//$gen_bit_sus65 = "'command'" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7  = "Web Shell" nocase
		$gen_much_sus8  = "WebShell" nocase
		$gen_much_sus3  = "hidded shell" 
		$gen_much_sus4  = "WScript.Shell.1" nocase
		$gen_much_sus5  = "AspExec" 
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang" 
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		// self remove
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus78 = "suhosin.executor.disable_" wide ascii
		$gen_much_sus79 = "disabled_suhosin" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821= "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gif = { 47 49 46 38 }
		$cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
	condition:
		not ( 
			any of ( $gfp_tiny* ) 
		)
		and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and ( 
			any of ( $inp* ) 
		)
		and ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
		and 
		( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or 
		( ( 
		$gif at 0 or
		(
			filesize < 4KB and 
			(
				1 of ( $gen_much_sus* ) or
				2 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 20KB and 
			(
				2 of ( $gen_much_sus* ) or
				3 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 50KB and 
			(
				2 of ( $gen_much_sus* ) or
				4 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 100KB and 
			(
				2 of ( $gen_much_sus* ) or
				6 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 150KB and 
			(
				3 of ( $gen_much_sus* ) or
				7 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 500KB and 
			(
				4 of ( $gen_much_sus* ) or
				8 of ( $gen_bit_sus* )
			)
		) 
		)
		and 
		( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or 
		( filesize < 500KB and ( 
			4 of ( $cmpayload* ) 
		)
		) )
}

rule webshell_php_generic_callback
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 2"
	strings:
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		//$gfp_tiny1 = "addslashes" fullword
		//$gfp_tiny2 = "escapeshellarg" fullword
		$gfp_tiny3 = "include \"./common.php\";" // xcache
		$gfp_tiny4 = "assert('FALSE');"
		$gfp_tiny5 = "assert(false);"
		$gfp_tiny6 = "assert(FALSE);"
		$gfp_tiny7 = "assert('array_key_exists("
		$gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
		$gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
		$gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$callback1 = /\bob_start[\t ]*\([^)]/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback4 = /\barray_filter[\t ]*\([^)]/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback7 = /\barray_map[\t ]*\([^)]/ nocase wide ascii
		$callback8 = /\barray_reduce[\t ]*\([^)]/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback11 = /\barray_udiff[\t ]*\([^)]/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback14 = /\barray_uintersect[\t ]*\([^)]/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\t ]*\([^)]/ nocase wide ascii
		$callback16 = /\barray_walk[\t ]*\([^)]/ nocase wide ascii
		$callback17 = /\bassert_options[\t ]*\([^)]/ nocase wide ascii
		$callback18 = /\buasort[\t ]*\([^)]/ nocase wide ascii
		$callback19 = /\buksort[\t ]*\([^)]/ nocase wide ascii
		$callback20 = /\busort[\t ]*\([^)]/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\t ]*\([^)]/ nocase wide ascii
		$callback23 = /\biterator_apply[\t ]*\([^)]/ nocase wide ascii
		$callback24 = /\bcall_user_func[\t ]*\([^)]/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\t ]*\([^)]/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\t ]*\([^)]/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\t ]*\([^)]/ nocase wide ascii
		$callback28 = /\bset_error_handler[\t ]*\([^)]/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\t ]*\([^)]/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\t ]*\([^)]/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\t ]*\([^)]/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\t ]*\([^)]/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\t ]*\([^)]/ nocase wide ascii
		$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
		$cfp3 = "<?phpclass WPML" ascii
		$gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6  = "self.delete"
		$gen_bit_sus9  = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus47 = "Shell" fullword wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus51 = "suhosin" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		//$gen_bit_sus64 = "\"command\"" fullword wide ascii
		//$gen_bit_sus65 = "'command'" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7  = "Web Shell" nocase
		$gen_much_sus8  = "WebShell" nocase
		$gen_much_sus3  = "hidded shell" 
		$gen_much_sus4  = "WScript.Shell.1" nocase
		$gen_much_sus5  = "AspExec" 
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang" 
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus78 = "suhosin.executor.disable_" wide ascii
		$gen_much_sus79 = "disabled_suhosin" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821= "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gif = { 47 49 46 38 }
	condition:
		not ( 
			any of ( $gfp* ) 
		)
		and not ( 
			any of ( $gfp_tiny* ) 
		)
		and ( 
			any of ( $inp* ) 
		)
		and ( 
			not any of ( $cfp* ) and
		(
			any of ( $callback* )  or
			all of ( $m_callback* )
		) 
		)
		and 
		( filesize < 1000 or ( 
		$gif at 0 or
		(
			filesize < 4KB and 
			(
				1 of ( $gen_much_sus* ) or
				2 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 20KB and 
			(
				2 of ( $gen_much_sus* ) or
				3 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 50KB and 
			(
				2 of ( $gen_much_sus* ) or
				4 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 100KB and 
			(
				2 of ( $gen_much_sus* ) or
				6 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 150KB and 
			(
				3 of ( $gen_much_sus* ) or
				7 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 500KB and 
			(
				4 of ( $gen_much_sus* ) or
				8 of ( $gen_bit_sus* )
			)
		) 
		)
		)
}

rule webshell_php_base64_encoded_payloads
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 3"
	strings:
		$decode1 = "base64_decode" fullword nocase wide ascii
		$decode2 = "openssl_decrypt" fullword nocase wide ascii
		$one1 = "leGVj"
		$one2 = "V4ZW"
		$one3 = "ZXhlY"
		$one4 = "UAeABlAGMA"
		$one5 = "lAHgAZQBjA"
		$one6 = "ZQB4AGUAYw"
		$two1 = "zaGVsbF9leGVj"
		$two2 = "NoZWxsX2V4ZW"
		$two3 = "c2hlbGxfZXhlY"
		$two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
		$two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
		$two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
		$three1 = "wYXNzdGhyd"
		$three2 = "Bhc3N0aHJ1"
		$three3 = "cGFzc3Rocn"
		$three4 = "AAYQBzAHMAdABoAHIAdQ"
		$three5 = "wAGEAcwBzAHQAaAByAHUA"
		$three6 = "cABhAHMAcwB0AGgAcgB1A"
		$four1 = "zeXN0ZW"
		$four2 = "N5c3Rlb"
		$four3 = "c3lzdGVt"
		$four4 = "MAeQBzAHQAZQBtA"
		$four5 = "zAHkAcwB0AGUAbQ"
		$four6 = "cwB5AHMAdABlAG0A"
		$five1 = "wb3Blb"
		$five2 = "BvcGVu"
		$five3 = "cG9wZW"
		$five4 = "AAbwBwAGUAbg"
		$five5 = "wAG8AcABlAG4A"
		$five6 = "cABvAHAAZQBuA"
		$six1 = "wcm9jX29wZW"
		$six2 = "Byb2Nfb3Blb"
		$six3 = "cHJvY19vcGVu"
		$six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
		$six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
		$six6 = "cAByAG8AYwBfAG8AcABlAG4A"
		$seven1 = "wY250bF9leGVj"
		$seven2 = "BjbnRsX2V4ZW"
		$seven3 = "cGNudGxfZXhlY"
		$seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
		$seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
		$seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
		$eight1 = "ldmFs"
		$eight2 = "V2YW"
		$eight3 = "ZXZhb"
		$eight4 = "UAdgBhAGwA"
		$eight5 = "lAHYAYQBsA"
		$eight6 = "ZQB2AGEAbA"
		$nine1 = "hc3Nlcn"
		$nine2 = "Fzc2Vyd"
		$nine3 = "YXNzZXJ0"
		$nine4 = "EAcwBzAGUAcgB0A"
		$nine5 = "hAHMAcwBlAHIAdA"
		$nine6 = "YQBzAHMAZQByAHQA"
		$execu1 = "leGVjd"
		$execu2 = "V4ZWN1"
		$execu3 = "ZXhlY3"
		$esystem1 = "lc3lzdGVt"
		$esystem2 = "VzeXN0ZW"
		$esystem3 = "ZXN5c3Rlb"
		$opening1 = "vcGVuaW5n"
		$opening2 = "9wZW5pbm"
		$opening3 = "b3BlbmluZ"
		$fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
		$fp2 = "YXBpLnRlbGVncmFtLm9" 
		$fp3 = "GET /"
		$fp4 = "POST /"	
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 300KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and not any of ( $fp* ) and any of ( $decode* ) and 
		( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or 
		( any of ( $four* ) and not any of ( $esystem* ) ) or 
		( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule webshell_php_unknown_1
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 4"
	strings:
		$sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
		$sp1 = "=explode(chr(" wide ascii
		$sp2 = "; if (!function_exists('" wide ascii
		$sp3 = " = NULL; for(" wide ascii
	condition:
		filesize <300KB and all of ($sp*)
}

rule webshell_php_generic_eval
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 5"
	strings:
		$geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		// Log files
		$gfp_3 = " GET /"
		$gfp_4 = " POST /"		
	condition:
		filesize < 300KB and not ( 
			any of ( $gfp* ) 
		)
		and $geval
}

rule webshell_php_double_eval_tiny
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 6"

	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
		$fp1 = "clone" fullword wide ascii
		$fp2 = "* @assert" ascii
		$fp3 = "*@assert" ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize > 70 and filesize < 300 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and #payload >= 2 and not any of ( $fp* )
}

rule webshell_php_obfuscated
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 7"
	strings:
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$o1 = "chr(" nocase wide ascii
		$o2 = "chr (" nocase wide ascii
		$o3 = "goto" fullword nocase wide ascii
		$o4 = "\\x9" wide ascii
		$o5 = "\\x3" wide ascii
		$o6 = "\\61" wide ascii
		$o7 = "\\44" wide ascii
		$o8 = "\\112" wide ascii
		$o9 = "\\120" wide ascii
		$fp1 = "$goto" wide ascii
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
	condition:
		not ( 
			any of ( $gfp* ) 
		)
		and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and ( 
			
			not $fp1 and (
				(
						filesize < 20KB and 
						(
							( #o1+#o2 ) > 50 or
							#o3 > 10 or
							( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20 
						) 
				) or (
						filesize < 200KB and 
						(
							( #o1+#o2 ) > 200 or
							#o3 > 30 or
							( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30 
						) 

				)
			)
		)
		and ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
}

rule webshell_php_obfuscated_encoding
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 8"
	strings:
		$enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 700KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $enc* )
}

rule webshell_php_obfuscated_encoding_mixed_dec_and_hex
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 9"
	strings:
		$mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 700KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $mix* )
}

rule webshell_php_obfuscated_tiny
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 10"
	strings:
		$obf1 = /\w'\.'\w/ wide ascii
		$obf2 = /\w\"\.\"\w/ wide ascii
		$obf3 = "].$" wide ascii
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
	condition:
		filesize < 500 and not ( 
			any of ( $gfp* ) 
		)
		and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
		and 
		( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule webshell_php_obfuscated_str_replace
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 11"
	strings:
		$payload1 = "str_replace" fullword wide ascii
		$payload2 = "function" fullword wide ascii
		$goto = "goto" fullword wide ascii
		//$hex  = "\\x"
		$chr1  = "\\61" wide ascii
		$chr2  = "\\112" wide ascii
		$chr3  = "\\120" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 300KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $payload* ) and #goto > 1 and 
		( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule webshell_php_obfuscated_fopo
{
	meta: 
		description= "Detect the risk of malicious file (phpwebshell)  Rule 12"
	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
		$one1 = "7QGV2YWwo" wide ascii
		$one2 = "tAZXZhbC" wide ascii
		$one3 = "O0BldmFsK" wide ascii
		$one4 = "sAQABlAHYAYQBsACgA" wide ascii
		$one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
		$one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
		$two1 = "7QGFzc2VydC" wide ascii
		$two2 = "tAYXNzZXJ0K" wide ascii
		$two3 = "O0Bhc3NlcnQo" wide ascii
		$two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
		$two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
		$two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 3000KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and $payload and 
		( any of ( $one* ) or any of ( $two* ) )
}

rule webshell_php_gzinflated
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 13"
	strings:
		$payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
		$payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
		$payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase
		$fp1 = "YXBpLnRlbGVncmFtLm9" 
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 700KB and not ( 
			any of ( $gfp* ) 
		)
		and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and 1 of ( $payload* ) and not any of ( $fp* )
}

rule webshell_php_obfuscated_3
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 14"
	strings:
		$obf1 = "chr(" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$callback1 = /\bob_start[\t ]*\([^)]/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback4 = /\barray_filter[\t ]*\([^)]/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback7 = /\barray_map[\t ]*\([^)]/ nocase wide ascii
		$callback8 = /\barray_reduce[\t ]*\([^)]/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback11 = /\barray_udiff[\t ]*\([^)]/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback14 = /\barray_uintersect[\t ]*\([^)]/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\t ]*\([^)]/ nocase wide ascii
		$callback16 = /\barray_walk[\t ]*\([^)]/ nocase wide ascii
		$callback17 = /\bassert_options[\t ]*\([^)]/ nocase wide ascii
		$callback18 = /\buasort[\t ]*\([^)]/ nocase wide ascii
		$callback19 = /\buksort[\t ]*\([^)]/ nocase wide ascii
		$callback20 = /\busort[\t ]*\([^)]/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\t ]*\([^)]/ nocase wide ascii
		$callback23 = /\biterator_apply[\t ]*\([^)]/ nocase wide ascii
		$callback24 = /\bcall_user_func[\t ]*\([^)]/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\t ]*\([^)]/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\t ]*\([^)]/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\t ]*\([^)]/ nocase wide ascii
		$callback28 = /\bset_error_handler[\t ]*\([^)]/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\t ]*\([^)]/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\t ]*\([^)]/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\t ]*\([^)]/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\t ]*\([^)]/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\t ]*\([^)]/ nocase wide ascii
		$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
		$cfp3 = "<?phpclass WPML" ascii
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		$cobfs1 = "gzinflate" fullword nocase wide ascii
		$cobfs2 = "gzuncompress" fullword nocase wide ascii
		$cobfs3 = "gzdecode" fullword nocase wide ascii
		$cobfs4 = "base64_decode" fullword nocase wide ascii
		$cobfs5 = "pack" fullword nocase wide ascii
		$cobfs6 = "undecode" fullword nocase wide ascii
		$gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6  = "self.delete"
		$gen_bit_sus9  = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus47 = "Shell" fullword wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus51 = "suhosin" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7  = "Web Shell" nocase
		$gen_much_sus8  = "WebShell" nocase
		$gen_much_sus3  = "hidded shell" 
		$gen_much_sus4  = "WScript.Shell.1" nocase
		$gen_much_sus5  = "AspExec" 
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang" 
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus78 = "suhosin.executor.disable_" wide ascii
		$gen_much_sus79 = "disabled_suhosin" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821= "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gif = { 47 49 46 38 }
	condition:
		( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and 
		( ( 
			not any of ( $cfp* ) and
		(
			any of ( $callback* )  or
			all of ( $m_callback* )
		) 
		)
		or ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
		) and ( 
			any of ( $cobfs* ) 
		)
		and 
		( filesize < 1KB or 
		( filesize < 3KB and 
		( ( 
		$gif at 0 or
		(
			filesize < 4KB and 
			(
				1 of ( $gen_much_sus* ) or
				2 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 20KB and 
			(
				2 of ( $gen_much_sus* ) or
				3 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 50KB and 
			(
				2 of ( $gen_much_sus* ) or
				4 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 100KB and 
			(
				2 of ( $gen_much_sus* ) or
				6 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 150KB and 
			(
				3 of ( $gen_much_sus* ) or
				7 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 500KB and 
			(
				4 of ( $gen_much_sus* ) or
				8 of ( $gen_bit_sus* )
			)
		) 
		)
		or #obf1 > 10 ) ) )
}

rule webshell_php_includer_eval
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 15"
	strings:
		$payload1 = "eval" fullword wide ascii
		$payload2 = "assert" fullword wide ascii
		$include1 = "$_FILE" wide ascii
		$include2 = "include" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 200 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and 1 of ( $payload* ) and 1 of ( $include* )
}

rule webshell_php_includer_tiny
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 16"
	strings:
		$php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 100 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $php_include* )
}

rule webshell_php_dynamic
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 17"
	strings:
		$pd_fp1 = "whoops_add_stack_frame" wide ascii
		$pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(base64_decode/ wide ascii
	condition:
		filesize > 20 and filesize < 200 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and ( 
			any of ( $dynamic* ) 
		)
		and not any of ( $pd_fp* )
}

rule webshell_php_dynamic_big
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 18"
	strings:
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(base64_decode/ wide ascii
		$gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6  = "self.delete"
		$gen_bit_sus9  = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus47 = "Shell" fullword wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus51 = "suhosin" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7  = "Web Shell" nocase
		$gen_much_sus8  = "WebShell" nocase
		$gen_much_sus3  = "hidded shell" 
		$gen_much_sus4  = "WScript.Shell.1" nocase
		$gen_much_sus5  = "AspExec" 
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang" 
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus78 = "suhosin.executor.disable_" wide ascii
		$gen_much_sus79 = "disabled_suhosin" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821= "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gif = { 47 49 46 38 }
	condition:
		filesize < 500KB and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		uint16(0) == 0x4b50 
		)
		and ( 
			any of ( $new_php* ) or
		$php_short at 0 
		)
		and ( 
			any of ( $dynamic* ) 
		)
		and 
		( ( 
			
			filesize > 2KB and 
		(
			
			math.entropy(500, filesize-500) >= 5.7 and
			
			math.mean(500, filesize-500) > 80 and
		  
			math.deviation(500, filesize-500, 89.0) < 23
		) or (
			math.entropy(500, filesize-500) >= 7.7 and
			math.mean(500, filesize-500) > 120 and
			math.mean(500, filesize-500) < 136 and
			math.deviation(500, filesize-500, 89.0) > 65
		) 
		)
		or ( 
		$gif at 0 or
		(
			filesize < 4KB and 
			(
				1 of ( $gen_much_sus* ) or
				2 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 20KB and 
			(
				2 of ( $gen_much_sus* ) or
				3 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 50KB and 
			(
				2 of ( $gen_much_sus* ) or
				4 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 100KB and 
			(
				2 of ( $gen_much_sus* ) or
				6 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 150KB and 
			(
				3 of ( $gen_much_sus* ) or
				7 of ( $gen_bit_sus* )
			)
		) or (
			filesize < 500KB and 
			(
				4 of ( $gen_much_sus* ) or
				8 of ( $gen_bit_sus* )
			)
		) 
		)
		)
}

rule webshell_php_encoded_big
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 19"
	strings:
		$new_php1 = /<\?=[\w\s@$]/ wide ascii
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
	condition:
		filesize < 1000KB and ( 
			any of ( $new_php* ) or
		$php_short at 0 
		)
		and ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
		and ( 
			filesize > 2KB and 
		(
			math.entropy(500, filesize-500) >= 5.7 and
			math.mean(500, filesize-500) > 80 and
			math.deviation(500, filesize-500, 89.0) < 23
		) or (
			math.entropy(500, filesize-500) >= 7.7 and
			math.mean(500, filesize-500) > 120 and
			math.mean(500, filesize-500) < 136 and
			math.deviation(500, filesize-500, 89.0) > 65
		) 
		)
		
}

rule webshell_php_generic_backticks
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 20"
	strings:
		$backtick = /`[\t ]*\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and $backtick and filesize < 200
}

rule webshell_php_generic_backticks_obfuscated
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 21"
	strings:
		$s1 = /echo[\t ]*\(?`\$/ wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 500 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and $s1
}

rule webshell_php_by_string_known_webshell
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 22"
	strings:
		$pbs1 = "b374k shell" wide ascii
		$pbs2 = "b374k/b374k" wide ascii
		$pbs3 = "\"b374k" wide ascii
		$pbs4 = "$b374k(\"" wide ascii
		$pbs5 = "b374k " wide ascii
		$pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
		$pbs7 = "pwnshell" wide ascii
		$pbs8 = "reGeorg" fullword wide ascii
		$pbs9 = "Georg says, 'All seems fine" fullword wide ascii
		$pbs10 = "My PHP Shell - A very simple web shell" wide ascii
		$pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
		$pbs12 = "F4ckTeam" fullword wide ascii
		$pbs15 = "MulCiShell" fullword wide ascii
		$pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
		// <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
		$pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
		$pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
		$pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
		$pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
		$pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
		$pbs52 = "preg_replace(\"/[checksql]/e\""
		$pbs53 = "='http://www.zjjv.com'"
		$pbs54 = "=\"http://www.zjjv.com\""
		$pbs60 = /setting\["AccountType"\]\s?=\s?3/
		$pbs61 = "~+d()\"^\"!{+{}"
		$pbs62 = "use function \\eval as "
		$pbs63 = "use function \\assert as "
		$front1 = "<?php eval(" nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	condition:
		filesize < 500KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		// fp on jar with zero compression
		uint16(0) == 0x4b50 
		)
		and 
		( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule webshell_php_by_string_obfuscation
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 23"
	strings:
		$opbs13 = "{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" wide ascii
		$opbs14 = "/*-/*-*/\"" wide ascii
		$opbs16 = "'ev'.'al'" wide ascii
		$opbs17 = "'e'.'val'" wide ascii
		$opbs18 = "e'.'v'.'a'.'l" wide ascii
		$opbs19 = "bas'.'e6'." wide ascii
		$opbs20 = "ba'.'se6'." wide ascii
		$opbs21 = "as'.'e'.'6'" wide ascii
		$opbs22 = "gz'.'inf'." wide ascii
		$opbs23 = "gz'.'un'.'c" wide ascii
		$opbs24 = "e'.'co'.'d" wide ascii
		$opbs25 = "cr\".\"eat" wide ascii
		$opbs26 = "un\".\"ct" wide ascii
		$opbs27 = "'c'.'h'.'r'" wide ascii
		$opbs28 = "\"ht\".\"tp\".\":/\"" wide ascii
		$opbs29 = "\"ht\".\"tp\".\"s:" wide ascii
		$opbs31 = "'ev'.'al'" nocase wide ascii
		$opbs32 = "eval/*" nocase wide ascii
		$opbs33 = "eval(/*" nocase wide ascii
		$opbs34 = "eval(\"/*" nocase wide ascii
		$opbs36 = "assert/*" nocase wide ascii
		$opbs37 = "assert(/*" nocase wide ascii
		$opbs38 = "assert(\"/*" nocase wide ascii
		$opbs40 = "'ass'.'ert'" nocase wide ascii
		$opbs41 = "${'_'.$_}['_'](${'_'.$_}['__'])" wide ascii
		$opbs44 = "'s'.'s'.'e'.'r'.'t'" nocase wide ascii
		$opbs45 = "'P'.'O'.'S'.'T'" wide ascii
		$opbs46 = "'G'.'E'.'T'" wide ascii
		$opbs47 = "'R'.'E'.'Q'.'U'" wide ascii
		$opbs48 = "se'.(32*2)" nocase
		$opbs49 = "'s'.'t'.'r_'" nocase
		$opbs50 = "'ro'.'t13'" nocase
		$opbs51 = "c'.'od'.'e" nocase
		$opbs53 = "e'. 128/2 .'_' .'d"
		$opbs54 = "<?php                                                                                                                                                                                " //here I end
		$opbs55 = "=chr(99).chr(104).chr(114);$_"
		$opbs56 = "\\x47LOBAL"
		$opbs57 = "pay\".\"load"
		$opbs58 = "bas'.'e64"
		$opbs59 = "dec'.'ode"
		$opbs60 = "fla'.'te"
		$opbs70 = "riny($_CBFG["
		$opbs71 = "riny($_TRG["
		$opbs72 = "riny($_ERDHRFG["
		$opbs73 = "eval(str_rot13("
		$opbs74 = "\"p\".\"r\".\"e\".\"g\""
		$opbs75 = "$_'.'GET"
		$opbs76 = "'ev'.'al("
		$opbs77 = "\\x65\\x76\\x61\\x6c\\x28" wide ascii nocase
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	condition:
		filesize < 500KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $opbs* )
}

rule webshell_php_strings_susp
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 24"
	strings:
		$sstring1 = "eval(\"?>\"" nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
	condition:
		filesize < 700KB and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and not ( 
			any of ( $gfp* ) 
		)
		and 
		( 2 of ( $sstring* ) or 
		( 1 of ( $sstring* ) and ( 
			any of ( $inp* ) 
		)
		) )
}

rule webshell_php_in_htaccess
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 25"
	strings:
		$hta = "AddType application/x-httpd-php .htaccess" wide ascii
	condition:
		filesize <100KB and $hta
}

rule webshell_php_function_via_get
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 26"
	strings:
		$sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
		$sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
		$sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
		$sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
		$sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
		$sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	condition:
		filesize < 500KB and not ( 
			any of ( $gfp* ) 
		)
		and any of ( $sr* )
}

rule webshell_php_writer
{
	meta:
		description= "Detect the risk of malicious file (phpwebshell)  Rule 27"
	strings:
		$sus4 = "\"upload\"" wide ascii
		$sus5 = "\"Upload\"" wide ascii
		$sus6 = "gif89" wide ascii
		//$sus13= "<textarea " wide ascii
		$sus16= "Army" fullword wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$php_multi_write1 = "fopen(" wide ascii
		$php_multi_write2 = "fwrite(" wide ascii
		$php_write1 = "move_uploaded_file" fullword wide ascii
	condition:
		( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and ( 
			any of ( $inp* ) 
		)
		and ( 
		any of ( $php_write* ) or
		all of ( $php_multi_write* ) 
		)
		and 
		( filesize < 400 or 
		( filesize < 4000 and 1 of ( $sus* ) ) )
}

rule webshell_asp_writer
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 28"
	strings:
		$sus1 = "password" fullword wide ascii
		$sus2 = "pwd" fullword wide ascii
		$sus3 = "<asp:TextBox" fullword nocase wide ascii
		$sus4 = "\"upload\"" wide ascii
		$sus5 = "\"Upload\"" wide ascii
		$sus6 = "gif89" wide ascii
		$sus7 = "\"&\"" wide ascii
		$sus8 = "authkey" fullword wide ascii
		$sus9 = "AUTHKEY" fullword wide ascii
		$sus10= "test.asp" fullword wide ascii
		$sus11= "cmd.asp" fullword wide ascii
		$sus12= ".Write(Request." wide ascii
		$sus13= "<textarea " wide ascii
		$sus14= "\"unsafe" fullword wide ascii
		$sus15= "'unsafe" fullword wide ascii
		$sus16= "Army" fullword wide ascii
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii
		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>
		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>
		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = "<?php"
		$php2 = "<?="
		// avoid hitting jsp
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii
		$perl1 = "PerlScript" fullword
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		and 
		( filesize < 400 or 
		( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule webshell_asp_obfuscated
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 29"
	strings:
		$asp_obf1 = "/*-/*-*/" wide ascii
		$asp_obf2 = "u\"+\"n\"+\"s" wide ascii
		$asp_obf3 = "\"e\"+\"v" wide ascii
		$asp_obf4 = "a\"+\"l\"" wide ascii
		$asp_obf5 = "\"+\"(\"+\"" wide ascii
		$asp_obf6 = "q\"+\"u\"" wide ascii
		$asp_obf7 = "\"u\"+\"e" wide ascii
		$asp_obf8 = "/*//*/" wide ascii
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii
		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>
		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>
		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = "<?php"
		$php2 = "<?="
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii
		$perl1 = "PerlScript" fullword
		$asp_payload0  = "eval_r" fullword nocase wide ascii
		$asp_payload1  = /\beval\s/ nocase wide ascii
		$asp_payload2  = /\beval\(/ nocase wide ascii
		$asp_payload3  = /\beval\"\"/ nocase wide ascii
		// var Fla = {'E':eval};  Fla.E(code)
		$asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii
		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
		//$loop1 = "For "
		//$o1 = "chr(" nocase wide ascii
		//$o2 = "chr (" nocase wide ascii
		// not excactly a string function but also often used in obfuscation
		$o4 = "\\x8" wide ascii
		$o5 = "\\x9" wide ascii
		$o6 = "\\61" wide ascii
		$o7 = "\\44" wide ascii
		$o8 = "\\112" wide ascii
		$o9 = "\\120" wide ascii
		//$o10 = " & \"" wide ascii
		//$o11 = " += \"" wide ascii
		// used for e.g. "scr"&"ipt"
		$m_multi_one1 = "Replace(" wide ascii
		$m_multi_one2 = "Len(" wide ascii
		$m_multi_one3 = "Mid(" wide ascii
		$m_multi_one4 = "mid(" wide ascii
		$m_multi_one5 = ".ToString(" wide ascii
		/*
		$m_multi_one5 = "InStr(" wide ascii
		$m_multi_one6 = "Function" wide ascii
		$m_multi_two1 = "for each" wide ascii
		$m_multi_two2 = "split(" wide ascii
		$m_multi_two3 = " & chr(" wide ascii
		$m_multi_two4 = " & Chr(" wide ascii
		$m_multi_two5 = " & Chr (" wide ascii
		$m_multi_three1 = "foreach" fullword wide ascii
		$m_multi_three2 = "(char" wide ascii
		$m_multi_four1 = "FromBase64String(" wide ascii
		$m_multi_four2 = ".Replace(" wide ascii
		$m_multi_five1 = "String.Join(\"\"," wide ascii
		$m_multi_five2 = ".Trim(" wide ascii
		$m_any1 = " & \"2" wide ascii
		$m_any2 = " += \"2" wide ascii
		*/
		$m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
		$oo1 = /\w\"&\"\w/ wide ascii
		$oo2 = "*/\").Replace(\"/*" wide ascii
	condition:
		filesize < 100KB and ( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and 
		( ( ( 
			any of ( $asp_payload* ) or
		all of ( $asp_multi_payload_one* ) or
		all of ( $asp_multi_payload_two* ) or
		all of ( $asp_multi_payload_three* ) or
		all of ( $asp_multi_payload_four* ) or
		all of ( $asp_multi_payload_five* ) 
		)
		or ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		) and 
		( ( 
		(
			filesize < 100KB and 
			not any of ( $m_fp* ) and
			(
				//( #o1+#o2 ) > 50 or
				( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20 
			) 
		) or (
			filesize < 5KB and 
			(
				//( #o1+#o2 ) > 10 or
				( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
				(
					//( #o1+#o2 ) > 1 and
					( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3 
				)

			) 
		) or (
			filesize < 700 and 
			(
				//( #o1+#o2 ) > 1 or
				( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
				( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2 
			) 
		)  
		)
		or any of ( $asp_obf* ) ) or ( 
		(
			filesize < 100KB and 
			(
				( #oo1 ) > 2 or
				$oo2
			) 
		) or (
			filesize < 25KB and 
			(
				( #oo1 ) > 1
			) 
		) or (
			filesize < 1KB and 
			(
				( #oo1 ) > 0 
			) 
		)  
		)
		)
}

rule webshell_asp_generic_eval_on_input
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 30"
	strings:
		$payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
		$payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
		$payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
		$payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii
		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>
		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>
		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii
		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii
		$php1 = "<?php"
		$php2 = "<?="
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii
		$perl1 = "PerlScript" fullword
	condition:
		( filesize < 1100KB and ( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and any of ( $payload_and_input* ) ) or 
		( filesize < 100 and any of ( $payload_and_input* ) )
}

rule webshell_asp_nano
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 31"

	strings:
		$susasp1  = "/*-/*-*/"
		$susasp2  = "(\"%1"
		$susasp3  = /[Cc]hr\([Ss]tr\(/
		$susasp4  = "cmd.exe"
		$susasp5  = "cmd /c"
		$susasp7  = "FromBase64String"
		$susasp8  = "UmVxdWVzdC"
		$susasp9  = "cmVxdWVzdA"
		$susasp10 = "/*//*/"
		$susasp11 = "(\"/*/\""
		$susasp12 = "eval(eval("
		$fp1	  = "eval a"
		$fp2	  = "'Eval'"
		$fp3	  = "Eval(\""
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii


		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii


		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		
		$asp_payload0  = "eval_r" fullword nocase wide ascii
		$asp_payload1  = /\beval\s/ nocase wide ascii
		$asp_payload2  = /\beval\(/ nocase wide ascii
		$asp_payload3  = /\beval\"\"/ nocase wide ascii
		// var Fla = {'E':eval};  Fla.E(code)
		$asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii

		
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and 
		( ( 
			any of ( $asp_payload* ) or
		all of ( $asp_multi_payload_one* ) or
		all of ( $asp_multi_payload_two* ) or
		all of ( $asp_multi_payload_three* ) or
		all of ( $asp_multi_payload_four* ) or
		all of ( $asp_multi_payload_five* ) 
		)
		or ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		) and not any of ( $fp* ) and 
		( filesize < 200 or 
		( filesize < 1000 and any of ( $susasp* ) ) )
}

rule webshell_asp_encoded
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 32"

	strings:
		$encoded1 = "VBScript.Encode" nocase wide ascii
		$encoded2 = "JScript.Encode" nocase wide ascii
		$data1 = "#@~^" wide ascii
		$sus1 = "shell" nocase wide ascii
		$sus2 = "cmd" fullword wide ascii
		$sus3 = "password" fullword wide ascii
		$sus4 = "UserPass" fullword wide ascii
	
		$tagasp_short1 = /<%[^"]/ wide ascii
		// also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
		$tagasp_short2 = "%>" wide ascii


		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii


		$php1 = "<?php"
		$php2 = "<?="


		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
	condition:
		filesize < 500KB and ( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and any of ( $encoded* ) and any of ( $data* ) and 
		( any of ( $sus* ) or 
		( filesize < 20KB and #data1 > 4 ) or 
		( filesize < 700 and #data1 > 0 ) )
}

rule webshell_asp_encoded_aspcoding
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 33"

	strings:
		$encoded1 = "ASPEncodeDLL" fullword nocase wide ascii
		$encoded2 = ".Runt" nocase wide ascii
		$encoded3 = "Request" fullword nocase wide ascii
		$encoded4 = "Response" fullword nocase wide ascii
		$data1 = "AspCoding.EnCode" wide ascii
		//$sus1 = "shell" nocase wide ascii
		//$sus2 = "cmd" fullword wide ascii
		//$sus3 = "password" fullword wide ascii
		//$sus4 = "UserPass" fullword wide ascii
	
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii


		$php1 = "<?php"
		$php2 = "<?="


		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
	condition:
		filesize < 500KB and ( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and all of ( $encoded* ) and any of ( $data* )
}

rule webshell_asp_by_string
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 34"

	strings:
	  
		$asp_string1  = "tseuqer lave" wide ascii
		$asp_string2  = ":eval request(" wide ascii
		$asp_string3  = ":eval request(" wide ascii
		$asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
		$asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
		// e+k-v+k-a+k-l
		// e+x-v+x-a+x-l
		$asp_string6  = /e\+.-v\+.-a\+.-l/ wide ascii
		$asp_string7  = "r+x-e+x-q+x-u" wide ascii
		$asp_string8  = "add6bb58e139be10" fullword wide ascii
		$asp_string9  = "WebAdmin2Y.x.y(\"" wide ascii
		$asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
		$asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
		// Request.Item["
		$asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii

	   
		$asp_string13 = "UAdgBhAGwAKA" wide ascii
		$asp_string14 = "lAHYAYQBsACgA" wide ascii
		$asp_string15 = "ZQB2AGEAbAAoA" wide ascii
		
		$asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
		$asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
		$asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii

		$asp_string19 = "\"ev\"&\"al" wide ascii
		$asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
		$asp_string21 = "C\"&\"ont\"&\"" wide ascii
		$asp_string22 = "\"vb\"&\"sc" wide ascii
		$asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
		$asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
		$asp_string25 = "*/eval(" wide ascii
		$asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
		$asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
		$asp_string28 = "6877656D2B736972786677752B237E232C2A"  wide ascii
		$asp_string29 = "ws\"&\"cript.shell" wide ascii
		$asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
		$asp_string31 = "ASPShell - web based shell" wide ascii
		$asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
		$asp_string33 = "\"scr\"&\"ipt\"" wide ascii
		$asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
		$asp_string35 = "\"she\"&\"ll." wide ascii
		$asp_string36 = "LH\"&\"TTP" wide ascii
		$asp_string37 = "<title>Web Sniffer</title>" wide ascii
		$asp_string38 = "<title>WebSniff" wide ascii
		$asp_string39 = "cript\"&\"ing" wide ascii
		$asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
		$asp_string41 = "tcejbOetaerC.revreS" wide ascii
		$asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
		$asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
		$asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
		$asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
		$asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
		$asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii

	
	
		$tagasp_short1 = /<%[^"]/ wide ascii
		
		$tagasp_short2 = "%>" wide ascii

		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

	  
		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
	condition:
		filesize < 200KB and ( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and any of ( $asp_string* )
}

rule webshell_asp_sniffer
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 35"

	strings:
		$sniff1 = "Socket(" wide ascii
		$sniff2 = ".Bind(" wide ascii
		$sniff3 = ".SetSocketOption(" wide ascii
		$sniff4 = ".IOControl(" wide ascii
		$sniff5 = "PacketCaptureWriter" fullword wide ascii
	

		$tagasp_short1 = /<%[^"]/ wide ascii
	
		$tagasp_short2 = "%>" wide ascii


		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	

		// Request.BinaryRead
		// Request.Form
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii

		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii

		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and filesize < 30KB and all of ( $sniff* )
}

rule webshell_asp_generic_tiny
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 36"

	strings:
		$fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="


		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		
		// Request.BinaryRead
		// Request.Form
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		// dynamic form
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
		
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	
		
		$asp_payload0  = "eval_r" fullword nocase wide ascii
		$asp_payload1  = /\beval\s/ nocase wide ascii
		$asp_payload2  = /\beval\(/ nocase wide ascii
		$asp_payload3  = /\beval\"\"/ nocase wide ascii
		// var Fla = {'E':eval};  Fla.E(code)
		$asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

		
		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii

	
		
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and not 1 of ( $fp* ) and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		// fp on jar with zero compression
		uint16(0) == 0x4b50 
		)
		and 
		( filesize < 700 and 
		( ( 
			any of ( $asp_payload* ) or
		all of ( $asp_multi_payload_one* ) or
		all of ( $asp_multi_payload_two* ) or
		all of ( $asp_multi_payload_three* ) or
		all of ( $asp_multi_payload_four* ) or
		all of ( $asp_multi_payload_five* ) 
		)
		or ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		) )
}

rule webshell_asp_generic
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 37"

	strings:
		$asp_much_sus7  = "Web Shell" nocase
		$asp_much_sus8  = "WebShell" nocase
		$asp_much_sus3  = "hidded shell" 
		$asp_much_sus4  = "WScript.Shell.1" nocase
		$asp_much_sus5  = "AspExec" 
		$asp_much_sus14 = "\\pcAnywhere\\" nocase
		$asp_much_sus15 = "antivirus" nocase
		$asp_much_sus16 = "McAfee" nocase
		$asp_much_sus17 = "nishang" 
		$asp_much_sus18 = "\"unsafe" fullword wide ascii
		$asp_much_sus19 = "'unsafe" fullword wide ascii
		$asp_much_sus28 = "exploit" fullword wide ascii
		$asp_much_sus30 = "TVqQAAMAAA" wide ascii
		$asp_much_sus31 = "HACKED" fullword wide ascii
		$asp_much_sus32 = "hacked" fullword wide ascii
		$asp_much_sus33 = "hacker" wide ascii
		$asp_much_sus34 = "grayhat" nocase wide ascii
		$asp_much_sus35 = "Microsoft FrontPage" wide ascii
		$asp_much_sus36 = "Rootkit" wide ascii
		$asp_much_sus37 = "rootkit" wide ascii
		$asp_much_sus38 = "/*-/*-*/" wide ascii
		$asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$asp_much_sus40 = "\"e\"+\"v" wide ascii
		$asp_much_sus41 = "a\"+\"l\"" wide ascii
		$asp_much_sus42 = "\"+\"(\"+\"" wide ascii
		$asp_much_sus43 = "q\"+\"u\"" wide ascii
		$asp_much_sus44 = "\"u\"+\"e" wide ascii
		$asp_much_sus45 = "/*//*/" wide ascii
		$asp_much_sus46 = "(\"/*/\"" wide ascii
		$asp_much_sus47 = "eval(eval(" wide ascii
		$asp_much_sus48 = "Shell.Users" wide ascii
		$asp_much_sus49 = "PasswordType=Regular" wide ascii
		$asp_much_sus50 = "-Expire=0" wide ascii
		$asp_much_sus51 = "sh\"&\"el" wide ascii

		$asp_gen_sus1  = /:\s{0,20}eval}/ nocase wide ascii
		$asp_gen_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
		$asp_gen_sus6  = "self.delete"
		$asp_gen_sus9  = "\"cmd /c" nocase
		$asp_gen_sus10 = "\"cmd\"" nocase
		$asp_gen_sus11 = "\"cmd.exe" nocase
		$asp_gen_sus12 = "%comspec%" wide ascii
		$asp_gen_sus13 = "%COMSPEC%" wide ascii
	   
		$asp_gen_sus18 = "Hklm.GetValueNames();" nocase

		$asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$asp_gen_sus21 = "\"upload\"" wide ascii
		$asp_gen_sus22 = "\"Upload\"" wide ascii
		$asp_gen_sus25 = "shell_" wide ascii
		//$asp_gen_sus26 = "password" fullword wide ascii
		//$asp_gen_sus27 = "passw" fullword wide ascii
		$asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$asp_gen_sus30 = "serv-u" wide ascii
		$asp_gen_sus31 = "Serv-u" wide ascii
		$asp_gen_sus32 = "Army" fullword wide ascii

		$asp_slightly_sus1 = "<pre>" wide ascii
		$asp_slightly_sus2 = "<PRE>" wide ascii


		// "e"+"x"+"e"
		$asp_gen_obf1 = "\"+\"" wide ascii 

		$fp1 = "DataBinder.Eval"
		$fp2 = "B2BTools"
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="


		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	
		
		// Request.BinaryRead
		// Request.Form
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
		
		$asp_payload0  = "eval_r" fullword nocase wide ascii
		$asp_payload1  = /\beval\s/ nocase wide ascii
		$asp_payload2  = /\beval\(/ nocase wide ascii
		$asp_payload3  = /\beval\"\"/ nocase wide ascii
		$asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii


		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii

	

		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
	
		
		$tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		// fp on jar with zero compression
		uint16(0) == 0x4b50 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and ( 
			any of ( $asp_payload* ) or
		all of ( $asp_multi_payload_one* ) or
		all of ( $asp_multi_payload_two* ) or
		all of ( $asp_multi_payload_three* ) or
		all of ( $asp_multi_payload_four* ) or
		all of ( $asp_multi_payload_five* ) 
		)
		and not any of ( $fp* ) and 
		( ( filesize < 3KB and 
		( 1 of ( $asp_slightly_sus* ) ) ) or 
		( filesize < 25KB and 
		( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or 
		( #asp_gen_obf1 > 2 ) ) ) or 
		( filesize < 50KB and 
		( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or 
		( #asp_gen_obf1 > 6 ) ) ) or 
		( filesize < 150KB and 
		( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or 
		( #asp_gen_obf1 > 6 ) or 
		( ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		and 
		( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or 
		( #asp_gen_obf1 > 3 ) ) ) ) ) or 
		( filesize < 100KB and ( 
		any of ( $tagasp_capa_classid* ) 
		)
		) )
}

rule webshell_asp_generic_registry_reader
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 38"

	strings:
		$asp_reg1  = "Registry" fullword wide ascii
		$asp_reg2  = "LocalMachine" fullword wide ascii
		$asp_reg3  = "ClassesRoot" fullword wide ascii
		$asp_reg4  = "CurrentUser" fullword wide ascii
		$asp_reg5  = "Users" fullword wide ascii
		$asp_reg6  = "CurrentConfig" fullword wide ascii
		$asp_reg7  = "Microsoft.Win32" fullword wide ascii
		$asp_reg8  = "OpenSubKey" fullword wide ascii

		$sus1 = "shell" fullword nocase wide ascii
		$sus2 = "cmd.exe" fullword wide ascii
		$sus3 = "<form " wide ascii
		$sus4 = "<table " wide ascii
		$sus5 = "System.Security.SecurityException" wide ascii

		$fp1 = "Avira Operations GmbH" wide
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		

		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii

		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and 
		( filesize < 10KB or 
		( filesize < 150KB and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		) )
}

rule webshell_aspx_regeorg_csharp
{
	meta:
		description= "Detect the risk of malicious file (aspxwebsell)  Rule 39"

	strings:
		$input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
		$input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
		$sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
		$sa2 = "Response.AddHeader" fullword nocase wide ascii
		$sa3 = "Request.InputStream.Read" nocase wide ascii
		$sa4 = "Response.BinaryWrite" nocase wide ascii
		$sa5 = "Socket" nocase wide ascii
		$georg = "Response.Write(\"Georg says, 'All seems fine'\")"
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
	condition:
		filesize < 300KB and ( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and 
		( $georg or 
		( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule webshell_csharp_generic
{
	meta:
		description= "Detect the risk of malicious file (aspxwebsell)  Rule 40"

	strings:
		$input_http = "Request." nocase wide ascii
		$input_form1 = "<asp:" nocase wide ascii
		$input_form2 = ".text" nocase wide ascii
		$exec_proc1 = "new Process" nocase wide ascii
		$exec_proc2 = "start(" nocase wide ascii
		$exec_shell1 = "cmd.exe" nocase wide ascii
		$exec_shell2 = "powershell.exe" nocase wide ascii
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		// also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		// <% eval
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii


		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and filesize < 300KB and 
		( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

rule webshell_asp_runtime_compile
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 41"

	strings:
		$payload_reflection1 = "System.Reflection" nocase wide ascii
		$payload_reflection2 = "Assembly" fullword nocase wide ascii
		$payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
		$payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
		$payload_compile1 = "GenerateInMemory" nocase wide ascii
		$payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
		$payload_invoke1 = "Invoke" fullword nocase wide ascii
		$payload_invoke2 = "CreateInstance" fullword nocase wide ascii
		$rc_fp1 = "Request.MapPath"
		$rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii
	
		
	  
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii

		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		// dynamic form
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
	condition:
		filesize < 10KB and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and not any of ( $rc_fp* ) and 
		( ( all of ( $payload_reflection* ) and any of ( $payload_load_reflection* ) ) or all of ( $payload_compile* ) ) and any of ( $payload_invoke* )
}

rule webshell_asp_sql
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 42"

	strings:
		$sql1 = "SqlConnection" fullword wide ascii
		$sql2 = "SQLConnection" fullword wide ascii
		$sql3 = "System" fullword wide ascii
		$sql4 = "Data" fullword wide ascii
		$sql5 = "SqlClient" fullword wide ascii
		$sql6 = "SQLClient" fullword wide ascii
		$sql7 = "Open" fullword wide ascii
		$sql8 = "SqlCommand" fullword wide ascii
		$sql9 = "SQLCommand" fullword wide ascii

		$o_sql1 = "SQLOLEDB" fullword wide ascii
		$o_sql2 = "CreateObject" fullword wide ascii
		$o_sql3 = "open" fullword wide ascii

		$a_sql1 = "ADODB.Connection" fullword wide ascii
		$a_sql2 = "adodb.connection" fullword wide ascii
		$a_sql3 = "CreateObject" fullword wide ascii
		$a_sql4 = "createobject" fullword wide ascii
		$a_sql5 = "open" fullword wide ascii

		$c_sql1 = "System.Data.SqlClient" fullword wide ascii
		$c_sql2 = "sqlConnection" fullword wide ascii
		$c_sql3 = "open" fullword wide ascii

		$sus1 = "shell" fullword nocase wide ascii
		$sus2 = "xp_cmdshell" fullword nocase wide ascii
		$sus3 = "aspxspy" fullword nocase wide ascii
		$sus4 = "_KillMe" wide ascii
		$sus5 = "cmd.exe" fullword wide ascii
		$sus6 = "cmd /c" fullword wide ascii
		$sus7 = "net user" fullword wide ascii
		$sus8 = "\\x2D\\x3E\\x7C" wide ascii
		$sus9 = "Hacker" fullword wide ascii
		$sus10 = "hacker" fullword wide ascii
		$sus11 = "HACKER" fullword wide ascii
		$sus12 = "webshell" wide ascii
		$sus13 = "equest[\"sql\"]" wide ascii
		$sus14 = "equest(\"sql\")" wide ascii
		$sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
		$sus16 = "\"sqlCommand\"" wide ascii
		$sus17 = "\"sqlcommand\"" wide ascii

		//$slightly_sus1 = "select * from " wide ascii
		//$slightly_sus2 = "SELECT * FROM " wide ascii
		$slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
		$slightly_sus4 = "show columns from " wide ascii
		
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
	  
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		// avoid hitting php
		$php1 = "<?php"
		$php2 = "<?="

		// avoid hitting jsp
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		

		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		// base64 of Request.Form(
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		// dynamic form
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
	condition:
		( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and 
		( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and 
		( ( filesize < 150KB and any of ( $sus* ) ) or 
		( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule webshell_asp_scan_writable
{
	meta:
		description= "Detect the risk of malicious file (aspwebsell)  Rule 43"

	strings:
		$scan1 = "DirectoryInfo" nocase fullword wide ascii
		$scan2 = "GetDirectories" nocase fullword wide ascii
		$scan3 = "Create" nocase fullword wide ascii
		$scan4 = "File" nocase fullword wide ascii
		$scan5 = "System.IO" nocase fullword wide ascii
		
		$scan6 = "CanWrite" nocase fullword wide ascii
		$scan7 = "Delete" nocase fullword wide ascii


		$sus1 = "upload" nocase fullword wide ascii
		$sus2 = "shell" nocase wide ascii
		$sus3 = "orking directory" nocase fullword wide ascii
		$sus4 = "scan" nocase wide ascii
		
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii

		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii


		$php1 = "<?php"
		$php2 = "<?="


		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword

		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii

		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii

		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp   = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
	
	condition:
		filesize < 10KB and ( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and ( 
			any of ( $asp_input* ) or
		(
			$asp_xml_http and
			any of ( $asp_xml_method* )
		) or
		(
			any of ( $asp_form* ) and
			any of ( $asp_text* ) and
			$asp_asp
		) 
		)
		and 6 of ( $scan* ) and any of ( $sus* )
}

rule webshell_jsp_regeorg
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 44"

	strings:
		$jgeorg1 = "request" fullword wide ascii
		$jgeorg2 = "getHeader" fullword wide ascii
		$jgeorg3 = "X-CMD" fullword wide ascii
		$jgeorg4 = "X-STATUS" fullword wide ascii
		$jgeorg5 = "socket" fullword wide ascii
		$jgeorg6 = "FORWARD" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
	condition:
		filesize < 300KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and all of ( $jgeorg* )
}

rule webshell_jsp_http_proxy
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 45"

	strings:
		$jh1 = "OutputStream" fullword wide ascii
		$jh2 = "InputStream"  wide ascii
		$jh3 = "BufferedReader" fullword wide ascii
		$jh4 = "HttpRequest" fullword wide ascii
		$jh5 = "openConnection" fullword wide ascii
		$jh6 = "getParameter" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
	condition:
		filesize < 10KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and all of ( $jh* )
}

rule webshell_jsp_writer_nano
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 46"

	strings:
		$payload1 = ".write" wide ascii
		$payload2 = "getBytes" fullword wide ascii
	
		
		$input1 = "getParameter" fullword ascii wide
		// request.getHeaders
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
	condition:
		filesize < 200 and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and 2 of ( $payload* )
}

rule webshell_jsp_generic_tiny
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 47"

	strings:
		$payload1 = "ProcessBuilder" fullword wide ascii
		$payload2 = "URLClassLoader" fullword wide ascii
		$payload_rt1 = "Runtime" fullword wide ascii
		$payload_rt2 = "getRuntime" fullword wide ascii
		$payload_rt3 = "exec" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		$input1 = "getParameter" fullword ascii wide

		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 250 and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and 
		( 1 of ( $payload* ) or all of ( $payload_rt* ) )
}

rule webshell_jsp_generic
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 48"

	strings:
		$susp0 = "cmd" fullword nocase ascii wide
		$susp1 = "command" fullword nocase ascii wide
		$susp2 = "shell" fullword nocase ascii wide
		$susp3 = "download" fullword nocase ascii wide
		$susp4 = "upload" fullword nocase ascii wide
		$susp5 = "Execute" fullword nocase ascii wide
		$susp6 = "\"pwd\"" ascii wide
		$susp7 = "\"</pre>" ascii wide

		$fp1 = "command = \"cmd.exe /c set\";"
	
		
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		// request.getParameter
		$input1 = "getParameter" fullword ascii wide
		// request.getHeaders
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
		
		$payload1 = "ProcessBuilder" fullword ascii wide
		$payload2 = "processCmd" fullword ascii wide
		// Runtime.getRuntime().exec(
		$rt_payload1 = "Runtime" fullword ascii wide
		$rt_payload2 = "getRuntime" fullword ascii wide
		$rt_payload3 = "exec" fullword ascii wide
	
	condition:
		filesize < 300KB and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		// fp on jar with zero compression
		uint16(0) == 0x4b50 
		)
		and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and ( 
		1 of ( $payload* ) or
		all of ( $rt_payload* ) 
		)
		and not any of ( $fp* ) and any of ( $susp* )
}

rule webshell_jsp_generic_base64
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 49"

	strings:
		
		$one1 = "SdW50aW1l" wide ascii
		$one2 = "J1bnRpbW" wide ascii
		$one3 = "UnVudGltZ" wide ascii
		$one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
		$one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
		$one6 = "UgB1AG4AdABpAG0AZQ" wide ascii

		$two1 = "leGVj" wide ascii
		$two2 = "V4ZW" wide ascii
		$two3 = "ZXhlY" wide ascii
		$two4 = "UAeABlAGMA" wide ascii
		$two5 = "lAHgAZQBjA" wide ascii
		$two6 = "ZQB4AGUAYw" wide ascii

		$three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
		$three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
		$three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
		$three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
		$three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
		$three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii

	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	
	condition:
		( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		// fp on jar with zero compression
		uint16(0) == 0x4b50 
		)
		and filesize < 300KB and 
		( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule webshell_jsp_generic_processbuilder
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 50"

	strings:
		$exec = "ProcessBuilder" fullword wide ascii
		$start = "start" fullword wide ascii
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 2000 and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and $exec and $start
}

rule webshell_jsp_generic_reflection
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 51"

	strings:
		$ws_exec = "invoke" fullword wide ascii
		$ws_class = "Class" fullword wide ascii
		$fp = "SOAPConnection"
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 10KB and all of ( $ws_* ) and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and not $fp
}

rule webshell_jsp_generic_classloader
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 52"

	strings:
		$exec = "extends ClassLoader" wide ascii
		$class = "defineClass" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide

		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 10KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and $exec and $class
}

rule webshell_jsp_generic_encoded_shell
{
	meta:
		description= "Detect the risk of malicious file (jspwebsell)  Rule 53"
	strings:
		$sj0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
		$sj1 = /{ ?99, 109, 100}/ wide ascii
		$sj2 = /{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
		$sj3 = /{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
		$sj4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
		$sj5 = /{ ?101, 120, 101, 99 }/ wide ascii
		$sj6 = /{ ?103, 101, 116, 82, 117, 110/ wide ascii

	condition:
		filesize <300KB and any of ($sj*)
}

rule webshell_jsp_netspy
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 54"

	strings:
		$scan1 = "scan" nocase wide ascii
		$scan2 = "port" nocase wide ascii
		$scan3 = "web" fullword nocase wide ascii
		$scan4 = "proxy" fullword nocase wide ascii
		$scan5 = "http" fullword nocase wide ascii
		$scan6 = "https" fullword nocase wide ascii
		$write1 = "os.write" fullword wide ascii
		$write2 = "FileOutputStream" fullword wide ascii
		$write3 = "PrintWriter" fullword wide ascii
		$http = "java.net.HttpURLConnection" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 30KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule webshell_jsp_by_string
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 55"

	strings:
		$jstring1 = "<title>Boot Shell</title>" wide ascii
		$jstring2 = "String oraPWD=\"" wide ascii
		$jstring3 = "Owned by Chinese Hackers!" wide ascii
		$jstring4 = "AntSword JSP" wide ascii
		$jstring5 = "JSP Webshell</" wide ascii
		$jstring6 = "motoME722remind2012" wide ascii
		$jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
		$jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
		$jstring9 = "list.jsp = Directory & File View" wide ascii
		$jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
		$jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
		$jstring12 = "MiniWebCmdShell" fullword wide ascii
		$jstring13 = "pwnshell.jsp" fullword wide ascii
		$jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
		$jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
		$jstring16 = "GIF98a<%@page" wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		$dex   = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack  = { 50 41 43 4b 00 00 00 02 00 }
	
	condition:
		filesize < 100KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and not ( 
		uint16(0) == 0x5a4d or 
		$dex at 0 or 
		$pack at 0 or 
		uint16(0) == 0x4b50 
		)
		and any of ( $jstring* )
}


rule webshell_jsp_input_upload_write
{
	meta:
		description= "Detect the risk of malicious file (jspwebshell)  Rule 56"

	strings:
		$upload = "upload" nocase wide ascii
		$write1 = "os.write" fullword wide ascii
		$write2 = "FileOutputStream" fullword wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		// request.getParameter
		$input1 = "getParameter" fullword ascii wide
		// request.getHeaders
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 10KB and ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and $upload and 1 of ( $write* )
}

rule webshell_generic_os_strings
{
	meta:
		description= "Detect the risk of malicious file (websell)  Rule 57"

	strings:
		$fp1 = "http://evil.com/" wide ascii
		$fp2 = "denormalize('/etc/shadow" wide ascii
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		// also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		// <% eval
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="
		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		
		$php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 

		// of course the new tags should also match
		// already matched by "<?"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	
		
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		
		// windows = nocase
		$w1 = "net localgroup administrators" nocase wide ascii
		$w2 = "net user" nocase wide ascii
		$w3 = "/add" nocase wide ascii
		// linux stuff, case sensitive:
		$l1 = "/etc/shadow" wide ascii
		$l2 = "/etc/ssh/sshd_config" wide ascii
		$take_two1 = "net user" nocase wide ascii
		$take_two2 = "/add" nocase wide ascii
	
	condition:
		filesize < 70KB and 
		( ( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		or ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		or ( 
		$cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
		(
			$cjsp_short2 and (
				$cjsp_short1 in ( 0..1000 ) or
				$cjsp_short1 in ( filesize-1000..filesize ) 
			)
		) 
		)
		) and ( 
			filesize < 300KB and 
		not uint16(0) == 0x5a4d and (
			all of ( $w* ) or
			all of ( $l* ) or
			2 of ( $take_two* ) 
		) 
		)
		and not any of ( $fp* )
}

rule webshell_in_image
{
	meta:

	   description= "Detect the risk of malicious file (Webshell)  Rule 58"

	strings:
		$png = { 89 50 4E 47 }
		$jpg = { FF D8 FF E0 }
		$gif = { 47 49 46 38 }
		$gif2 = "gif89"
		$mdb = { 00 01 00 00 53 74 }
		//$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }
	
		
		$php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	
		
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		$php_multi_write1 = "fopen(" wide ascii
		$php_multi_write2 = "fwrite(" wide ascii
		$php_write1 = "move_uploaded_file" fullword wide ascii
	
		
		$cjsp1 = "<%" ascii wide
		$cjsp2 = "<jsp:" ascii wide
		$cjsp3 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp4 = "/jstl/core" ascii wide
	
		
		$payload1 = "ProcessBuilder" fullword ascii wide
		$payload2 = "processCmd" fullword ascii wide
		$rt_payload1 = "Runtime" fullword ascii wide
		$rt_payload2 = "getRuntime" fullword ascii wide
		$rt_payload3 = "exec" fullword ascii wide
	
		
		$tagasp_short1 = /<%[^"]/ wide ascii
		$tagasp_short2 = "%>" wide ascii

		
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

		// <%@ LANGUAGE = VBScript.encode%>
		// <%@ Language = "JScript" %>

		// <%@ WebHandler Language="C#" class="Handler" %>
		// <%@ WebService Language="C#" Class="Service" %>

		// <%@Page Language="Jscript"%>
		// <%@ Page Language = Jscript %>		   
		// <%@PAGE LANGUAGE=JSCRIPT%>
		// <%@ Page Language="Jscript" validateRequest="false" %>
		// <%@ Page Language = Jscript %>
		// <%@ Page Language="C#" %>
		// <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
		// <script runat="server" language="JScript">
		// <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
		// <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
		// <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

		$php1 = "<?php"
		$php2 = "<?="

		$jsp1 = "=\"java." wide ascii
		$jsp2 = "=\"javax." wide ascii
		$jsp3 = "java.lang." wide ascii
		$jsp4 = "public" fullword wide ascii
		$jsp5 = "throws" fullword wide ascii
		$jsp6 = "getValue" fullword wide ascii
		$jsp7 = "getBytes" fullword wide ascii

		$perl1 = "PerlScript" fullword
		
	
		
		$asp_payload0  = "eval_r" fullword nocase wide ascii
		$asp_payload1  = /\beval\s/ nocase wide ascii
		$asp_payload2  = /\beval\(/ nocase wide ascii
		$asp_payload3  = /\beval\"\"/ nocase wide ascii
		// var Fla = {'E':eval};  Fla.E(code)
		$asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
		$asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
		$asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
		$asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
		$asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
		$asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
		$asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
		$asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
		$asp_multi_payload_one2 = "addcode" fullword wide ascii
		$asp_multi_payload_one3 = /\.run\b/ wide ascii
		$asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
		$asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
		$asp_multi_payload_two3 = "BuildManager" fullword wide ascii
		$asp_multi_payload_three1 = "System.Diagnostics" wide ascii
		$asp_multi_payload_three2 = "Process" fullword wide ascii
		$asp_multi_payload_three3 = ".Start" wide ascii
		$asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
		$asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
		$asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

		$asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
		$asp_multi_payload_five2 = ".Start" nocase wide ascii
		$asp_multi_payload_five3 = ".Filename" nocase wide ascii
		$asp_multi_payload_five4 = ".Arguments" nocase wide ascii

	
		
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		$asp_always_write1 = /\.write/ nocase wide ascii
		$asp_always_write2 = /\.swrite/ nocase wide ascii
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		$asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
		$asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
		$asp_cr_write1 = "CreateObject(" fullword nocase wide ascii
		$asp_cr_write2 = "CreateObject (" fullword nocase wide ascii
		$asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
		$asp_streamwriter2 = "filestream" fullword nocase wide ascii
	
	condition:
		( $png at 0 or $jpg at 0 or $gif at 0 or $gif2 at 0 or $mdb at 0 ) and 
		( ( ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and 
		( ( 
			any of ( $cpayload* ) or
		all of ( $m_cpayload_preg_filter* ) 
		)
		or ( 
		any of ( $php_write* ) or
		all of ( $php_multi_write* ) 
		)
		) ) or 
		( ( 
			any of ( $cjsp* ) 
		)
		and ( 
		1 of ( $payload* ) or
		all of ( $rt_payload* ) 
		)
		) or 
		( ( 
		(
			any of ( $tagasp_long* ) or
		   
			any of ( $tagasp_classid* ) or
			(
				$tagasp_short1 and
				$tagasp_short2 in ( filesize-100..filesize ) 
			) or (
				$tagasp_short2 and (
					$tagasp_short1 in ( 0..1000 ) or
					$tagasp_short1 in ( filesize-1000..filesize ) 
				)
			) 
		) and not ( 
			(
				any of ( $perl* ) or
				$php1 at 0 or
				$php2 at 0 
			) or (
				( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
				)
		) 
		)
		and 
		( ( 
			any of ( $asp_payload* ) or
		all of ( $asp_multi_payload_one* ) or
		all of ( $asp_multi_payload_two* ) or
		all of ( $asp_multi_payload_three* ) or
		all of ( $asp_multi_payload_four* ) or
		all of ( $asp_multi_payload_five* ) 
		)
		or ( 
		any of ( $asp_always_write* ) and
		(
			any of ( $asp_write_way_one* ) and
			any of ( $asp_cr_write* )
		) or (
			any of ( $asp_streamwriter* )
		) 
		)
		) ) )
}

rule php_proxy {
   meta:
      description = "Detect the risk of malicious file (phpwebshell)  Rule 59"
   strings:
      $s1 = "  $result = file_get_contents($url, false, $context);" fullword ascii 
      $s2 = "  //$postdata = http_build_query($data);" fullword ascii 
      $s3 = "POST {$path} HTTP/1.1" fullword ascii 
      $s4 = "Host: {$host}:$port" fullword ascii 
      $s5 = "    // split the result header from the content" fullword ascii 
      $s6 = "HEADER;" fullword ascii 
      $s7 = "Content-Length: {$length}" fullword ascii 
      $s8 = "    $post_arg = file_get_contents(\"php://input\");" fullword ascii 
      $s9 = "if ($_SERVER['REQUEST_METHOD'] === 'GET') {" fullword ascii 
      $s10 = "function my_socket_post($url, $data)" fullword ascii 
      $s11 = "function post($url, $data)" fullword ascii 
      $s12 = "        curl_exec($ch);" fullword ascii 
      $s13 = "    $RemoteServer = $_POST['Remoteserver'];" fullword ascii 
      $s14 = "ini_set(\"display_errors\", \"On\");" fullword ascii 
      $s15 = "  $opts = array('http' =>" fullword ascii 
      $s16 = "    $fp = fsockopen($host, $port, $errno, $errstr, 3);" fullword ascii 
      $s17 = "             'header' => 'Content-type: application/x-www-form-urlencoded'," fullword ascii 
      $s18 = "        die (\"Error: Only HTTP request are supported !\");" fullword ascii 
      $s19 = "Content-Type: application/x-www-form-urlencoded\\r\\n" fullword ascii 
      $s20 = "        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_arg);" fullword ascii 
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      8 of them
}

rule aspx_proxy {
   meta:
      description = "Detect the risk of malicious file (aspxwebshell)  Rule 60"
   strings:
      $s1 = "        HttpWebRequest newrequest = (HttpWebRequest)WebRequest.Create(url+\"?\"+post_arg);" fullword ascii 
      $s2 = "        using (StreamReader reader = new StreamReader(newresponse.GetResponseStream()))" fullword ascii 
      $s3 = "    if (Request.HttpMethod == \"GET\")" fullword ascii 
      $s4 = "        {" fullword ascii 
      $s5 = "        string url = Remoteserver + Endpoint;" fullword ascii 
      $s6 = "        }" fullword ascii 
      $s7 = "<%@ Page Language=\"C#\" Debug=\"true\"%>" fullword ascii 
      $s8 = "        WebResponse newresponse = newrequest.GetResponse();" fullword ascii 
      $s9 = "            requestStream = newrequest.GetRequestStream();" fullword ascii 
      $s10 = "        int cont = Request.ContentLength;" fullword ascii 
      $s11 = "        String post_arg = Encoding.UTF8.GetString(buffer, 0, cont);" fullword ascii 
      $s12 = "        newrequest.Method = \"POST\";" fullword ascii 
      $s13 = "        System.IO.Stream s = Request.InputStream;" fullword ascii 
      $s14 = "            System.IO.Stream requestStream = null;" fullword ascii 
      $s15 = "        s.Read(buffer, 0, cont);" fullword ascii 
      $s16 = "        string Remoteserver = Request.Form[\"Remoteserver\"]; " fullword ascii 
      $s17 = "            backMsg = reader.ReadToEnd();" fullword ascii 
   condition:
      uint16(0) == 0xbbef and filesize < 4KB and
      8 of them
}