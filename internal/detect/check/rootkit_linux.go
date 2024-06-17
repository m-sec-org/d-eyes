//go:build linux

package check

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Rootkit struct {
	Name  string
	File  []string
	Dir   []string
	Ksyms []string
}

type RootKitRulesResult struct {
	Type string
	Name string
	Res  string
}

var W55808A = Rootkit{Name: "55808 Variant A", File: []string{"/tmp/.../r", "/tmp/.../a"}, Dir: nil, Ksyms: nil}

var AdoreRootkit = Rootkit{
	Name: "Adore Rootkit",
	File: []string{
		"/usr/secure", "/usr/doc/sys/qrt", "/usr/doc/sys/run", "/usr/doc/sys/crond",
		"/usr/sbin/kfd", "/usr/doc/kern/var", "/usr/doc/kern/string.o", "/usr/doc/kern/ava", "/usr/doc/kern/adore.o",
		"/var/log/ssh/old",
	},
	Dir: []string{
		"/lib/security/.config/ssh", "/usr/doc/kern", "/usr/doc/backup", "/usr/doc/backup/txt",
		"/lib/backup", "/lib/backup/txt", "/usr/doc/work", "/usr/doc/sys", "/var/log/ssh",
		"/usr/doc/.spool", "/usr/lib/kterm",
	}, Ksyms: nil,
}

var AjakitRootkit = Rootkit{
	Name: "AjaKit Rootkit", File: []string{
		"/dev/tux/.addr", "/dev/tux/.proc",
		"/dev/tux/.file", "/lib/.libgh-gh/cleaner", "/lib/.libgh-gh/Patch/patch", "/lib/.libgh-gh/sb0k",
	},
	Dir: []string{"/dev/tux", "/lib/.libgh-gh"}, Ksyms: nil,
}

var apaKitRootkit = Rootkit{Name: "aPa Kit Rootkit", File: []string{"/usr/share/.aPa"}, Dir: nil, Ksyms: nil}

var ApacheWorm = Rootkit{Name: "Apache Worm", File: []string{"/bin/.log"}, Dir: nil, Ksyms: nil}

var AmbientRootkit = Rootkit{
	Name: "Ambient Rootkit",
	File: []string{"/usr/lib/.ark?", "/dev/ptyxx/.log", "/dev/ptyxx/.file", "/dev/ptyxx/.proc", "/dev/ptyxx/.addr"},
	Dir:  []string{"/dev/ptyxx"}, Ksyms: nil,
}

var BalaurRootkit = Rootkit{
	Name: "Balaur Rootkit", File: []string{"/usr/lib/liblog.o"},
	Dir: []string{"/usr/lib/.kinetic", "/usr/lib/.egcs", "/usr/lib/.wormie"}, Ksyms: nil,
}

var BeastkitRootkit = Rootkit{
	Name: "Beastkit Rootkit",
	File: []string{
		"/usr/sbin/arobia", "/usr/sbin/idrun", "/usr/lib/elm/arobia/elm",
		"/usr/lib/elm/arobia/elm/hk", "/usr/lib/elm/arobia/elm/hk.pub",
		"/usr/lib/elm/arobia/elm/sc", "/usr/lib/elm/arobia/elm/sd.pp",
		"/usr/lib/elm/arobia/elm/sdco", "/usr/lib/elm/arobia/elm/srsd",
	},
	Dir: []string{"/lib/ldd.so/bktools"}, Ksyms: nil,
}

var bex2Rootkit = Rootkit{
	Name: "beX2 Rootkit", File: []string{"/usr/info/termcap.info-5.gz", "/usr/bin/sshd2"},
	Dir: []string{"/usr/include/bex"}, Ksyms: nil,
}

var BobkitRootkit = Rootkit{
	Name: "BOBkit Rootkit",
	File: []string{
		"/usr/sbin/ntpsx", "/usr/sbin/.../bkit-ava", "/usr/sbin/.../bkit-d", "/usr/sbin/.../bkit-shd",
		"/usr/sbin/.../bkit-f", "/usr/include/.../proc.h", "/usr/include/.../.bash_history",
		"/usr/include/.../bkit-get", "/usr/include/.../bkit-dl", "/usr/include/.../bkit-screen",
		"/usr/include/.../bkit-sleep", "/usr/lib/.../bkit-adore.o", "/usr/lib/.../ls",
		"/usr/lib/.../netstat", "/usr/lib/.../lsof", "/usr/lib/.../bkit-ssh/bkit-shdcfg",
		"/usr/lib/.../bkit-ssh/bkit-shhk", "/usr/lib/.../bkit-ssh/bkit-pw",
		"/usr/lib/.../bkit-ssh/bkit-shrs", "/usr/lib/.../bkit-ssh/bkit-mots",
		"/usr/lib/.../uconf.inv", "/usr/lib/.../psr", "/usr/lib/.../find",
		"/usr/lib/.../pstree", "/usr/lib/.../slocate", "/usr/lib/.../du", "/usr/lib/.../top",
	},
	Dir: []string{
		"/usr/sbin/...", "/usr/include/...", "/usr/include/.../.tmp", "/usr/lib/...",
		"/usr/lib/.../.ssh", "/usr/lib/.../bkit-ssh", "/usr/lib/.bkit-", "/tmp/.bkp",
	},
	Ksyms: nil,
}

var OsxBoonanaATrojan = Rootkit{
	Name: "OSX Boonana-A Trojan",
	File: []string{
		"/Library/StartupItems/OSXDriverUpdates/OSXDriverUpdates",
		"/Library/StartupItems/OSXDriverUpdates/StartupParameters.plist",
	},
	Dir: []string{"/var/root/.jnana"}, Ksyms: nil,
}

var cbRootkit = Rootkit{
	Name: "cb Rootkit",
	File: []string{
		"/dev/srd0", "/lib/libproc.so.2.0.6", "/dev/mounnt", "/etc/rc.d/init.d/init",
		"/usr/bin/.zeen/..%/cl", "/usr/bin/.zeen/..%/.x.tgz", "/usr/bin/.zeen/..%/statdx",
		"/usr/bin/.zeen/..%/wted", "/usr/bin/.zeen/..%/write", "/usr/bin/.zeen/..%/scan",
		"/usr/bin/.zeen/..%/sc", "/usr/bin/.zeen/..%/sl2", "/usr/bin/.zeen/..%/wroot",
		"/usr/bin/.zeen/..%/wscan", "/usr/bin/.zeen/..%/wu", "/usr/bin/.zeen/..%/v",
		"/usr/bin/.zeen/..%/read", "/usr/lib/sshrc", "/usr/lib/ssh_host_key",
		"/usr/lib/ssh_host_key.pub", "/usr/lib/ssh_random_seed", "/usr/lib/sshd_config",
		"/usr/lib/shosts.equiv", "/usr/lib/ssh_known_hosts", "/u/zappa/.ssh/pid",
		"/usr/bin/.system/..%/tcp.log", "/usr/bin/.zeen/..%/curatare/attrib",
		"/usr/bin/.zeen/..%/curatare/chattr", "/usr/bin/.zeen/..%/curatare/ps",
		"/usr/bin/.zeen/..%/curatare/pstree", "/usr/bin/.system/..%/.x/xC.o",
	},
	Dir: []string{
		"/usr/bin/.zeen", "/usr/bin/.zeen/..%/curatare", "/usr/bin/.zeen/..%/scan",
		"/usr/bin/.system/..%",
	}, Ksyms: nil,
}

var CinikWorm = Rootkit{Name: "CiNIK Worm", File: []string{"/tmp/.cinik"}, Dir: []string{"/tmp/.font-unix/.cinik"}, Ksyms: nil}

var CxRootkit = Rootkit{
	Name: "CX Rootkit",
	File: []string{
		"/usr/lib/ldlibso", "/usr/lib/configlibso", "/usr/lib/shklibso", "/usr/lib/randomlibso",
		"/usr/lib/ldlibstrings.so", "/usr/lib/ldlibdu.so", "/usr/lib/ldlibns.so", "/usr/include/db",
	},
	Dir: []string{"/usr/include/cxk"}, Ksyms: nil,
}

var AbuseKit = Rootkit{Name: "Abuse Kit", File: []string{"/dev/mdev", "/usr/lib/libX.a"}, Dir: nil, Ksyms: nil}

var DevilRootkit = Rootkit{
	Name: "Devil Rootkit",
	File: []string{
		"/var/lib/games/.src", "/dev/dsx", "/dev/caca", "/dev/pro", "/bin/bye",
		"/bin/homedir", "/usr/bin/xfss", "/usr/sbin/tzava",
		"/usr/doc/tar/.../.dracusor/stuff/holber",
		"/usr/doc/tar/.../.dracusor/stuff/sense",
		"/usr/doc/tar/.../.dracusor/stuff/clear",
		"/usr/doc/tar/.../.dracusor/stuff/tzava",
		"/usr/doc/tar/.../.dracusor/stuff/citeste",
		"/usr/doc/tar/.../.dracusor/stuff/killrk",
		"/usr/doc/tar/.../.dracusor/stuff/searchlog",
		"/usr/doc/tar/.../.dracusor/stuff/gaoaza",
		"/usr/doc/tar/.../.dracusor/stuff/cleaner",
		"/usr/doc/tar/.../.dracusor/stuff/shk",
		"/usr/doc/tar/.../.dracusor/stuff/srs",
		"/usr/doc/tar/.../.dracusor/utile.tgz",
		"/usr/doc/tar/.../.dracusor/webpage", "/usr/doc/tar/.../.dracusor/getpsy",
		"/usr/doc/tar/.../.dracusor/getbnc",
		"/usr/doc/tar/.../.dracusor/getemech",
		"/usr/doc/tar/.../.dracusor/localroot.sh",
		"/usr/doc/tar/.../.dracusor/stuff/old/sense",
	},
	Dir: []string{"/usr/doc/tar/.../.dracusor"}, Ksyms: nil,
}

var DiamorphineLkm = Rootkit{
	Name: "Diamorphine LKM", File: nil, Dir: nil,
	Ksyms: []string{"diamorphine", "module_hide", "module_hidden", "is_invisible", "hacked_getdents", "hacked_kill"},
}

var DicaKitRootkit = Rootkit{
	Name: "Dica-Kit Rootkit",
	File: []string{
		"/lib/.sso", "/lib/.so", "/var/run/...dica/clean", "/var/run/...dica/dxr",
		"/var/run/...dica/read", "/var/run/...dica/write", "/var/run/...dica/lf",
		"/var/run/...dica/xl", "/var/run/...dica/xdr", "/var/run/...dica/psg",
		"/var/run/...dica/secure", "/var/run/...dica/rdx", "/var/run/...dica/va",
		"/var/run/...dica/cl.sh", "/var/run/...dica/last.log", "/usr/bin/.etc",
		"/etc/sshd_config", "/etc/ssh_host_key", "/etc/ssh_random_seed",
	},
	Dir: []string{"/var/run/...dica", "/var/run/...dica/mh", "/var/run/...dica/scan"}, Ksyms: nil,
}

var Dreams_Rootkit = Rootkit{
	Name: "Dreams Rootkit",
	File: []string{
		"/dev/ttyoa", "/dev/ttyof", "/dev/ttyop", "/usr/bin/sense", "/usr/bin/sl2",
		"/usr/bin/logclear", "/usr/bin/(swapd)", "/usr/bin/initrd", "/usr/bin/crontabs",
		"/usr/bin/snfs", "/usr/lib/libsss", "/usr/lib/libsnf.log", "/usr/lib/libshtift/top",
		"/usr/lib/libshtift/ps", "/usr/lib/libshtift/netstat", "/usr/lib/libshtift/ls",
		"/usr/lib/libshtift/ifconfig", "/usr/include/linseed.h", "/usr/include/linpid.h",
		"/usr/include/linkey.h", "/usr/include/linconf.h", "/usr/include/iceseed.h",
		"/usr/include/icepid.h", "/usr/include/icekey.h", "/usr/include/iceconf.h",
	},
	Dir: []string{"/dev/ida/.hpd", "/usr/lib/libshtift"}, Ksyms: nil,
}

var Duarawkz_Rootkit = Rootkit{
	Name: "Duarawkz Rootkit", File: []string{"/usr/bin/duarawkz/loginpass"},
	Dir: []string{"/usr/bin/duarawkz"}, Ksyms: nil,
}

var Ebury_sshd_backdoor = Rootkit{
	Name: "Ebury sshd backdoor",
	File: []string{
		"/lib/libns2.so", "/lib64/libns2.so", "/lib/libns5.so", "/lib64/libns5.so",
		"/lib/libpw3.so", "/lib64/libpw3.so", "/lib/libpw5.so", "/lib64/libpw5.so",
		"/lib/libsbr.so", "/lib64/libsbr.so", "/lib/libslr.so", "/lib64/libslr.so",
		"/lib/tls/libkeyutils.so.1", "/lib64/tls/libkeyutils.so.1",
	},
	Dir: nil, Ksyms: nil,
}

var ENYE_LKM = Rootkit{
	Name: "ENYE LKM", File: []string{"/etc/.enyelkmHIDE^IT.ko", "/etc/.enyelkmOCULTAR.ko"},
	Dir: nil, Ksyms: nil,
}

var Flea_Rootkit = Rootkit{
	Name: "Flea Rootkit", File: []string{
		"/etc/ld.so.hash",
		"/lib/security/.config/ssh/sshd_config",
		"/lib/security/.config/ssh/ssh_host_key",
		"/lib/security/.config/ssh/ssh_host_key.pub",
		"/lib/security/.config/ssh/ssh_random_seed", "/usr/bin/ssh2d",
		"/usr/lib/ldlibns.so", "/usr/lib/ldlibps.so",
		"/usr/lib/ldlibpst.so",
		"/usr/lib/ldlibdu.so", "/usr/lib/ldlibct.so",
	},
	Dir: []string{"/lib/security/.config/ssh", "/dev/..0", "/dev/..0/backup"}, Ksyms: nil,
}

var FreeBSD_Rootkit = Rootkit{
	Name: "FreeBSD Rootkit",
	File: []string{
		"/dev/ptyp", "/dev/ptyq", "/dev/ptyr", "/dev/ptys", "/dev/ptyt",
		"/dev/fd/.88/freshb-bsd", "/dev/fd/.88/fresht", "/dev/fd/.88/zxsniff",
		"/dev/fd/.88/zxsniff.log", "/dev/fd/.99/.ttyf00", "/dev/fd/.99/.ttyp00",
		"/dev/fd/.99/.ttyq00", "/dev/fd/.99/.ttys00", "/dev/fd/.99/.pwsx00", "/etc/.acid",
		"/usr/lib/.fx/sched_host.2", "/usr/lib/.fx/random_d.2", "/usr/lib/.fx/set_pid.2",
		"/usr/lib/.fx/setrgrp.2", "/usr/lib/.fx/TOHIDE", "/usr/lib/.fx/cons.saver",
		"/usr/lib/.fx/adore/ava/ava", "/usr/lib/.fx/adore/adore/adore.ko", "/bin/sysback",
		"/usr/local/bin/sysback",
	},
	Dir: []string{"/dev/fd/.88", "/dev/fd/.99", "/usr/lib/.fx", "/usr/lib/.fx/adore"}, Ksyms: nil,
}

var Fu_Rootkit = Rootkit{
	Name: "Fu Rootkit", File: []string{"/sbin/xc", "/usr/include/ivtype.h", "/bin/.lib"},
	Dir: nil, Ksyms: nil,
}

var Fuckit_Rootkit = Rootkit{
	Name: "Fuckit Rootkit",
	File: []string{
		"/lib/libproc.so.2.0.7", "/dev/proc/.bash_profile", "/dev/proc/.bashrc",
		"/dev/proc/.cshrc", "/dev/proc/fuckit/hax0r", "/dev/proc/fuckit/hax0rshell",
		"/dev/proc/fuckit/config/lports", "/dev/proc/fuckit/config/rports",
		"/dev/proc/fuckit/config/rkconf", "/dev/proc/fuckit/config/password",
		"/dev/proc/fuckit/config/progs", "/dev/proc/fuckit/system-bins/init",
		"/usr/lib/libcps.a", "/usr/lib/libtty.a",
	},
	Dir: []string{"/dev/proc", "/dev/proc/fuckit", "/dev/proc/fuckit/system-bins", "/dev/proc/toolz"}, Ksyms: nil,
}

var GasKit_Rootkit = Rootkit{
	Name: "GasKit Rootkit", File: []string{"/dev/dev/gaskit/sshd/sshdd"},
	Dir: []string{"/dev/dev", "/dev/dev/gaskit", "/dev/dev/gaskit/sshd"}, Ksyms: nil,
}

var Heroin_LKM = Rootkit{Name: "Heroin LKM", File: nil, Dir: nil, Ksyms: []string{"heroin"}}

var HjC_Kit_Rootkit = Rootkit{Name: "HjC Kit Rootkit", File: nil, Dir: []string{"/dev/.hijackerz"}, Ksyms: nil}

var ignoKit_Rootkit = Rootkit{
	Name: "ignoKit Rootkit",
	File: []string{
		"/lib/defs/p", "/lib/defs/q", "/lib/defs/r", "/lib/defs/s", "/lib/defs/t",
		"/usr/lib/defs/p", "/usr/lib/defs/q", "/usr/lib/defs/r", "/usr/lib/defs/s",
		"/usr/lib/defs/t", "/usr/lib/.libigno/pkunsec",
		"/usr/lib/.libigno/.igno/psybnc/psybnc",
	},
	Dir: []string{"/usr/lib/.libigno", "/usr/lib/.libigno/.igno"}, Ksyms: nil,
}

var iLLogiC_Rootkit = Rootkit{
	Name: "iLLogiC Rootkit",
	File: []string{
		"/dev/kmod", "/dev/dos", "/usr/lib/crth.o", "/usr/lib/crtz.o", "/etc/ld.so.hash",
		"/usr/bin/sia", "/usr/bin/ssh2d", "/lib/security/.config/sn",
		"/lib/security/.config/iver", "/lib/security/.config/uconf.inv",
		"/lib/security/.config/ssh/ssh_host_key",
		"/lib/security/.config/ssh/ssh_host_key.pub", "/lib/security/.config/ssh/sshport",
		"/lib/security/.config/ssh/ssh_random_seed", "/lib/security/.config/ava",
		"/lib/security/.config/cleaner", "/lib/security/.config/lpsched",
		"/lib/security/.config/sz", "/lib/security/.config/rcp",
		"/lib/security/.config/patcher", "/lib/security/.config/pg",
		"/lib/security/.config/crypt", "/lib/security/.config/utime",
		"/lib/security/.config/wget", "/lib/security/.config/instmod",
		"/lib/security/.config/bin/find", "/lib/security/.config/bin/du",
		"/lib/security/.config/bin/ls", "/lib/security/.config/bin/psr",
		"/lib/security/.config/bin/netstat", "/lib/security/.config/bin/su",
		"/lib/security/.config/bin/ping", "/lib/security/.config/bin/passwd",
	},
	Dir: []string{
		"/lib/security/.config", "/lib/security/.config/ssh", "/lib/security/.config/bin",
		"/lib/security/.config/backup", "/root/%%%/.dir", "/root/%%%/.dir/mass-scan",
		"/root/%%%/.dir/flood",
	}, Ksyms: nil,
}

var OSX_Inqtana = Rootkit{
	Name: "OSX Inqtana Variant A",
	File: []string{
		"/Users/w0rm-support.tgz", "/Users/InqTest.class", "/Users/com.openbundle.plist",
		"/Users/com.pwned.plist", "/Users/libavetanaBT.jnilib",
	},
	Dir: []string{"/Users/de", "/Users/javax"}, Ksyms: nil,
}

var OSX_Inqtana2 = Rootkit{
	Name: "OSX Inqtana Variant B",
	File: []string{
		"/Users/w0rms.love.apples.tgz", "/Users/InqTest.class", "/Users/InqTest.java",
		"/Users/libavetanaBT.jnilib", "/Users/InqTanaHandler", "/Users/InqTanaHandler.bundle",
	},
	Dir: []string{"/Users/de", "/Users/javax"}, Ksyms: nil,
}

var OSX_Inqtana3 = Rootkit{
	Name: "OSX Inqtana Variant C",
	File: []string{
		"/Users/applec0re.tgz", "/Users/InqTest.class", "/Users/InqTest.java",
		"/Users/libavetanaBT.jnilib", "/Users/environment.plist", "/Users/pwned.c",
		"/Users/pwned.dylib",
	},
	Dir: []string{"/Users/de", "/Users/javax"}, Ksyms: nil,
}

var IntoXonia_NG_Rootkit = Rootkit{
	Name: "IntoXonia-NG Rootkit", File: nil, Dir: nil,
	Ksyms: []string{
		"funces", "ixinit", "tricks", "kernel_unlink", "rootme", "hide_module",
		"find_sys_call_tbl",
	},
}

var Irix_Rootkit = Rootkit{
	Name: "Irix Rootkit", File: nil,
	Dir: []string{"/dev/pts/01", "/dev/pts/01/backup", "/dev/pts/01/etc", "/dev/pts/01/tmp"}, Ksyms: nil,
}

var Jynx_Rootkit = Rootkit{
	Name: "Jynx Rootkit",
	File: []string{
		"/xochikit/bc", "/xochikit/ld_poison.so", "/omgxochi/bc", "/omgxochi/ld_poison.so",
		"/var/local/^^/bc", "/var/local/^^/ld_poison.so",
	},
	Dir: []string{"/xochikit", "/omgxochi", "/var/local/^^"}, Ksyms: nil,
}

var Jynx2_Rootkit = Rootkit{
	Name: "Jynx2 Rootkit", File: []string{"/XxJynx/reality.so"}, Dir: []string{"/XxJynx"},
	Ksyms: nil,
}

var KBeast_Rootkit = Rootkit{
	Name: "KBeast Rootkit",
	File: []string{"/usr/_h4x_/ipsecs-kbeast-v1.ko", "/usr/_h4x_/_h4x_bd", "/usr/_h4x_/acctlog"},
	Dir:  []string{"/usr/_h4x_"},
	Ksyms: []string{
		"h4x_delete_module", "h4x_getdents64", "h4x_kill", "h4x_open", "h4x_read",
		"h4x_rename", "h4x_rmdir", "h4x_tcp4_seq_show", "h4x_write",
	},
}

var OSX_Keydnap_backdoor = Rootkit{
	Name: "OSX Keydnap backdoor",
	File: []string{
		"/Applications/Transmission.app/Contents/Resources/License.rtf",
		"/Volumes/Transmission/Transmission.app/Contents/Resources/License.rtf",
		"/Library/LaunchAgents/com.apple.iCloud.sync.daemon.plist",
		"/Library/LaunchAgents/com.geticloud.icloud.photo.plist",
	},
	Dir: []string{"/Library/Application%Support/com.apple.iCloud.sync.daemon/"}, Ksyms: nil,
}

var Kitko_Rootkit = Rootkit{Name: "Kitko Rootkit", File: nil, Dir: []string{"/usr/src/redhat/SRPMS/..."}, Ksyms: nil}

var KNARK_FILES = Rootkit{
	Name: "Knark Rootkit", File: []string{"/proc/knark/pids"}, Dir: []string{"/proc/knark"},
	Ksyms: nil,
}

var KOMPLEX_FILES = Rootkit{
	Name: "OSX Komplex Trojan",
	File: []string{
		"/Users/Shared/.local/kextd", "/Users/Shared/com.apple.updates.plist",
		"/Users/Shared/start.sh",
	}, Dir: nil, Ksyms: nil,
}

var LINUXV_FILES = Rootkit{
	Name: "ld-linuxv rootkit", File: []string{"/lib/ld-linuxv.so.1"},
	Dir: []string{"/var/opt/_so_cache", "/var/opt/_so_cache/ld", "/var/opt/_so_cache/lc"}, Ksyms: nil,
}

var LION_FILES = Rootkit{
	Name: "Lion Worm", File: []string{
		"/bin/in.telnetd", "/bin/mjy",
		"/usr/man/man1/man1/lib/.lib/mjy",
		"/usr/man/man1/man1/lib/.lib/in.telnetd",
		"/usr/man/man1/man1/lib/.lib/.x", "/dev/.lib/lib/scan/1i0n.sh",
		"/dev/.lib/lib/scan/hack.sh", "/dev/.lib/lib/scan/bind",
		"/dev/.lib/lib/scan/randb", "/dev/.lib/lib/scan/scan.sh",
		"/dev/.lib/lib/scan/pscan", "/dev/.lib/lib/scan/star.sh",
		"/dev/.lib/lib/scan/bindx.sh", "/dev/.lib/lib/scan/bindname.log",
		"/dev/.lib/lib/1i0n.sh", "/dev/.lib/lib/lib/netstat",
		"/dev/.lib/lib/lib/dev/.1addr", "/dev/.lib/lib/lib/dev/.1logz",
		"/dev/.lib/lib/lib/dev/.1proc", "/dev/.lib/lib/lib/dev/.1file",
	},
	Dir: nil, Ksyms: nil,
}

var LOCKIT_FILES = Rootkit{
	Name: "Lockit Rootkit",
	File: []string{
		"/usr/lib/libmen.oo/.LJK2/ssh_config", "/usr/lib/libmen.oo/.LJK2/ssh_host_key",
		"/usr/lib/libmen.oo/.LJK2/ssh_host_key.pub",
		"/usr/lib/libmen.oo/.LJK2/ssh_random_seed*", "/usr/lib/libmen.oo/.LJK2/sshd_config",
		"/usr/lib/libmen.oo/.LJK2/backdoor/RK1bd", "/usr/lib/libmen.oo/.LJK2/backup/du",
		"/usr/lib/libmen.oo/.LJK2/backup/ifconfig",
		"/usr/lib/libmen.oo/.LJK2/backup/inetd.conf", "/usr/lib/libmen.oo/.LJK2/backup/locate",
		"/usr/lib/libmen.oo/.LJK2/backup/login", "/usr/lib/libmen.oo/.LJK2/backup/ls",
		"/usr/lib/libmen.oo/.LJK2/backup/netstat", "/usr/lib/libmen.oo/.LJK2/backup/ps",
		"/usr/lib/libmen.oo/.LJK2/backup/pstree", "/usr/lib/libmen.oo/.LJK2/backup/rc.sysinit",
		"/usr/lib/libmen.oo/.LJK2/backup/syslogd", "/usr/lib/libmen.oo/.LJK2/backup/tcpd",
		"/usr/lib/libmen.oo/.LJK2/backup/top", "/usr/lib/libmen.oo/.LJK2/clean/RK1sauber",
		"/usr/lib/libmen.oo/.LJK2/clean/RK1wted", "/usr/lib/libmen.oo/.LJK2/hack/RK1parse",
		"/usr/lib/libmen.oo/.LJK2/hack/RK1sniff", "/usr/lib/libmen.oo/.LJK2/hide/.RK1addr",
		"/usr/lib/libmen.oo/.LJK2/hide/.RK1dir", "/usr/lib/libmen.oo/.LJK2/hide/.RK1log",
		"/usr/lib/libmen.oo/.LJK2/hide/.RK1proc",
		"/usr/lib/libmen.oo/.LJK2/hide/RK1phidemod.c",
		"/usr/lib/libmen.oo/.LJK2/modules/README.modules",
		"/usr/lib/libmen.oo/.LJK2/modules/RK1hidem.c",
		"/usr/lib/libmen.oo/.LJK2/modules/RK1phide",
		"/usr/lib/libmen.oo/.LJK2/sshconfig/RK1ssh",
	},
	Dir: []string{"/usr/lib/libmen.oo/.LJK2"}, Ksyms: nil,
}

var MOKES_FILES = Rootkit{
	Name: "Mokes backdoor", File: []string{
		"/tmp/ss0-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}.sst",
		"/tmp/aa0-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}.aat",
		"/tmp/kk0-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}.kkt",
		"/tmp/dd0-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}{0-9}{0-9}{0-9}-{0-9}{0-9}{0-9}.ddt",
	},
	Dir: nil, Ksyms: nil,
}

var MRK_FILES = Rootkit{
	Name: "MRK RootKit",
	File: []string{
		"/dev/ida/.inet/pid", "/dev/ida/.inet/ssh_host_key", "/dev/ida/.inet/ssh_random_seed",
		"/dev/ida/.inet/tcp.log",
	}, Dir: []string{"/dev/ida/.inet", "/var/spool/cron/.sh"}, Ksyms: nil,
}

var MOODNT_FILES = Rootkit{
	Name: "Mood-NT Rootkit",
	File: []string{
		"/sbin/init__mood-nt-_-_cthulhu", "/_cthulhu/mood-nt.init", "/_cthulhu/mood-nt.conf",
		"/_cthulhu/mood-nt.sniff",
	}, Dir: []string{"/_cthulhu"}, Ksyms: nil,
}

var NIO_FILES = Rootkit{
	Name: "Ni0 Rootkit",
	File: []string{
		"/var/lock/subsys/...datafile.../...net...", "/var/lock/subsys/...datafile.../...port...",
		"/var/lock/subsys/...datafile.../...ps...", "/var/lock/subsys/...datafile.../...file...",
	},
	Dir: []string{"/tmp/waza", "/var/lock/subsys/...datafile...", "/usr/sbin/es"}, Ksyms: nil,
}

var OHHARA_FILES = Rootkit{
	Name: "Ohhara Rootkit",
	File: []string{"/var/lock/subsys/...datafile.../...datafile.../in.smbd.log"},
	Dir: []string{
		"/var/lock/subsys/...datafile...", "/var/lock/subsys/...datafile.../...datafile...",
		"/var/lock/subsys/...datafile.../...datafile.../bin",
		"/var/lock/subsys/...datafile.../...datafile.../usr/bin",
		"/var/lock/subsys/...datafile.../...datafile.../usr/sbin",
		"/var/lock/subsys/...datafile.../...datafile.../lib/security",
	}, Ksyms: nil,
}

var OPTICKIT_FILES = Rootkit{
	Name: "Optic Kit Rootkit", File: nil,
	Dir: []string{"/dev/tux", "/usr/bin/xchk", "/usr/bin/xsf", "/usr/bin/ssh2d"}, Ksyms: nil,
}

var OSXRK_FILES = Rootkit{
	Name: "OSXRK",
	File: []string{
		"/dev/.rk/nc", "/dev/.rk/diepu", "/dev/.rk/backd", "/Library/StartupItems/opener",
		"/Library/StartupItems/opener.sh", "/System/Library/StartupItems/opener",
		"/System/Library/StartupItems/opener.sh",
	},
	Dir: []string{"/dev/.rk", "/Users/LDAP-daemon", "/tmp/.work"}, Ksyms: nil,
}

var OZ_FILES = Rootkit{
	Name: "Oz Rootkit", File: []string{"/dev/.oz/.nap/rkit/terror"}, Dir: []string{"/dev/.oz"},
	Ksyms: nil,
}

var PHALANX_FILES = Rootkit{
	Name: "Phalanx Rootkit",
	File: []string{
		"/uNFuNF", "/etc/host.ph1", "/bin/host.ph1", "/usr/share/.home.ph1/phalanx",
		"/usr/share/.home.ph1/cb", "/usr/share/.home.ph1/kebab",
	},
	Dir: []string{"/usr/share/.home.ph1", "/usr/share/.home.ph1/tty"}, Ksyms: nil,
}

var PHALANX2_FILES = Rootkit{
	Name: "Phalanx2 Rootkit",
	File: []string{
		"/etc/khubd.p2/.p2rc", "/etc/khubd.p2/.phalanx2", "/etc/khubd.p2/.sniff",
		"/etc/khubd.p2/sshgrab.py", "/etc/lolzz.p2/.p2rc", "/etc/lolzz.p2/.phalanx2",
		"/etc/lolzz.p2/.sniff", "/etc/lolzz.p2/sshgrab.py", "/etc/cron.d/zupzzplaceholder",
		"/usr/lib/zupzz.p2/.p-2.3d", "/usr/lib/zupzz.p2/.p2rc",
	},
	Dir: []string{"/etc/khubd.p2", "/etc/lolzz.p2", "/usr/lib/zupzz.p2"}, Ksyms: nil,
}

var PORTACELO_FILES = Rootkit{
	Name: "Portacelo Rootkit",
	File: []string{
		"/var/lib/.../.ak", "/var/lib/.../.hk", "/var/lib/.../.rs", "/var/lib/.../.p",
		"/var/lib/.../getty", "/var/lib/.../lkt.o", "/var/lib/.../show",
		"/var/lib/.../nlkt.o", "/var/lib/.../ssshrc", "/var/lib/.../sssh_equiv",
		"/var/lib/.../sssh_known_hosts", "/var/lib/.../sssh_pid ~/.sssh/known_hosts",
	},
	Dir: nil, Ksyms: nil,
}

var PROTON_FILES = Rootkit{
	Name: "OSX Proton backdoor", File: []string{
		"Library/LaunchAgents/com.apple.xpcd.plist",
		"/Library/LaunchAgents/com.Eltima.UpdaterAgent.plist",
		"/Library/.rand/updateragent.app", "/tmp/Updater.app",
	},
	Dir: []string{"/Library/.rand", "/Library/.cachedir", "/Library/.random"}, Ksyms: nil,
}

var REDSTORM_FILES = Rootkit{
	Name: "R3dstorm Toolkit",
	File: []string{
		"/var/log/tk02/see_all", "/var/log/tk02/.scris", "/bin/.../sshd/sbin/sshd1",
		"/bin/.../hate/sk", "/bin/.../see_all",
	},
	Dir: []string{"/var/log/tk02", "/var/log/tk02/old", "/bin/..."}, Ksyms: nil,
}

var RHSHARPES_FILES = Rootkit{
	Name: "RH-Sharpe Rootkit",
	File: []string{
		"/bin/lps", "/usr/bin/lpstree", "/usr/bin/ltop", "/usr/bin/lkillall",
		"/usr/bin/ldu", "/usr/bin/lnetstat", "/usr/bin/wp", "/usr/bin/shad",
		"/usr/bin/vadim", "/usr/bin/slice", "/usr/bin/cleaner", "/usr/include/rpcsvc/du",
	},
	Dir: nil, Ksyms: nil,
}

var RSHA_FILES = Rootkit{
	Name: "RSHA Rootkit",
	File: []string{
		"/bin/kr4p", "/usr/bin/n3tstat", "/usr/bin/chsh2", "/usr/bin/slice2",
		"/usr/src/linux/arch/alpha/lib/.lib/.1proc", "/etc/rc.d/arch/alpha/lib/.lib/.1addr",
	},
	Dir: []string{"/etc/rc.d/rsha", "/etc/rc.d/arch/alpha/lib/.lib"}, Ksyms: nil,
}

var SHUTDOWN_FILES = Rootkit{
	Name: "Shutdown Rootkit",
	File: []string{
		"/usr/man/man5/..%/.dir/scannah/asus", "/usr/man/man5/..%/.dir/see",
		"/usr/man/man5/..%/.dir/nscd", "/usr/man/man5/..%/.dir/alpd", "/etc/rc.d/rc.local%",
	},
	Dir: []string{
		"/usr/man/man5/..%/.dir", "/usr/man/man5/..%/.dir/scannah",
		"/etc/rc.d/rc0.d/..%/.dir",
	}, Ksyms: nil,
}

var SCALPER_FILES = Rootkit{Name: "Scalper Worm", File: []string{"/tmp/.a", "/tmp/.uua"}, Dir: nil, Ksyms: nil}

var SHV4_FILES = Rootkit{
	Name: "SHV4 Rootkit",
	File: []string{
		"/etc/ld.so.hash", "/lib/libext-2.so.7", "/lib/lidps1.so", "/lib/libproc.a",
		"/lib/libproc.so.2.0.6", "/lib/ldd.so/tks", "/lib/ldd.so/tkp", "/lib/ldd.so/tksb",
		"/lib/security/.config/sshd", "/lib/security/.config/ssh/ssh_host_key",
		"/lib/security/.config/ssh/ssh_host_key.pub",
		"/lib/security/.config/ssh/ssh_random_seed", "/usr/include/file.h",
		"/usr/include/hosts.h", "/usr/include/lidps1.so", "/usr/include/log.h",
		"/usr/include/proc.h", "/usr/sbin/xntps", "/dev/srd0",
	},
	Dir: []string{"/lib/ldd.so", "/lib/security/.config", "/lib/security/.config/ssh"}, Ksyms: nil,
}

var SHV5_FILES = Rootkit{
	Name: "SHV5 Rootkit",
	File: []string{
		"/etc/sh.conf", "/lib/libproc.a", "/lib/libproc.so.2.0.6", "/lib/lidps1.so",
		"/lib/libsh.so/bash", "/usr/include/file.h", "/usr/include/hosts.h",
		"/usr/include/log.h", "/usr/include/proc.h", "/lib/libsh.so/shdcf2",
		"/lib/libsh.so/shhk", "/lib/libsh.so/shhk.pub", "/lib/libsh.so/shrs",
		"/usr/lib/libsh/.bashrc", "/usr/lib/libsh/shsb", "/usr/lib/libsh/hide",
		"/usr/lib/libsh/.sniff/shsniff", "/usr/lib/libsh/.sniff/shp", "/dev/srd0",
	},
	Dir:   []string{"/lib/libsh.so", "/usr/lib/libsh", "/usr/lib/libsh/utilz", "/usr/lib/libsh/.backup"},
	Ksyms: nil,
}

var SINROOTKIT_FILES = Rootkit{
	Name: "Sin Rootkit",
	File: []string{
		"/dev/.haos/haos1/.f/Denyed", "/dev/ttyoa", "/dev/ttyof", "/dev/ttyop",
		"/dev/ttyos", "/usr/lib/.lib", "/usr/lib/sn/.X", "/usr/lib/sn/.sys",
		"/usr/lib/ld/.X", "/usr/man/man1/...", "/usr/man/man1/.../.m",
		"/usr/man/man1/.../.w",
	},
	Dir: []string{"/usr/lib/sn", "/usr/lib/man1/...", "/dev/.haos"}, Ksyms: nil,
}

var SLAPPER_FILES = Rootkit{
	Name: "Slapper Worm",
	File: []string{
		"/tmp/.bugtraq", "/tmp/.uubugtraq", "/tmp/.bugtraq.c", "/tmp/httpd", "/tmp/.unlock",
		"/tmp/update", "/tmp/.cinik", "/tmp/.b",
	}, Dir: nil, Ksyms: nil,
}

var SNEAKIN_FILES = Rootkit{Name: "Sneakin Rootkit", File: nil, Dir: []string{"/tmp/.X11-unix/.../rk"}, Ksyms: nil}

var WANUKDOOR_FILES = Rootkit{
	Name: "Solaris Wanuk backdoor",
	File: []string{
		"/var/adm/sa/.adm/.lp-door.i86pc", "/var/adm/sa/.adm/.lp-door.sun4",
		"/var/spool/lp/admins/.lp-door.i86pc", "/var/spool/lp/admins/.lp-door.sun4",
		"/var/spool/lp/admins/lpshut", "/var/spool/lp/admins/lpsystem",
		"/var/spool/lp/admins/lpadmin", "/var/spool/lp/admins/lpmove",
		"/var/spool/lp/admins/lpusers", "/var/spool/lp/admins/lpfilter",
		"/var/spool/lp/admins/lpstat", "/var/spool/lp/admins/lpd",
		"/var/spool/lp/admins/lpsched", "/var/spool/lp/admins/lpc",
	},
	Dir: []string{"/var/adm/sa/.adm"}, Ksyms: nil,
}

var WANUKWORM_FILES = Rootkit{
	Name: "Solaris Wanuk Worm",
	File: []string{
		"/var/adm/.adm", "/var/adm/.i86pc", "/var/adm/.sun4", "/var/adm/sa/.adm",
		"/var/adm/sa/.adm/.i86pc", "/var/adm/sa/.adm/.sun4", "/var/adm/sa/.adm/.crontab",
		"/var/adm/sa/.adm/devfsadmd", "/var/adm/sa/.adm/svcadm", "/var/adm/sa/.adm/cfgadm",
		"/var/adm/sa/.adm/kadmind", "/var/adm/sa/.adm/zoneadmd", "/var/adm/sa/.adm/sadm",
		"/var/adm/sa/.adm/sysadm", "/var/adm/sa/.adm/dladm", "/var/adm/sa/.adm/bootadm",
		"/var/adm/sa/.adm/routeadm", "/var/adm/sa/.adm/uadmin", "/var/adm/sa/.adm/acctadm",
		"/var/adm/sa/.adm/cryptoadm", "/var/adm/sa/.adm/inetadm", "/var/adm/sa/.adm/logadm",
		"/var/adm/sa/.adm/nlsadmin", "/var/adm/sa/.adm/sacadm",
		"/var/adm/sa/.adm/syseventadmd", "/var/adm/sa/.adm/ttyadmd",
		"/var/adm/sa/.adm/consadmd", "/var/adm/sa/.adm/metadevadm", "/var/adm/sa/.i86pc",
		"/var/adm/sa/.sun4", "/var/adm/sa/acctadm", "/var/adm/sa/bootadm",
		"/var/adm/sa/cfgadm", "/var/adm/sa/consadmd", "/var/adm/sa/cryptoadm",
		"/var/adm/sa/devfsadmd", "/var/adm/sa/dladm", "/var/adm/sa/inetadm",
		"/var/adm/sa/kadmind", "/var/adm/sa/logadm", "/var/adm/sa/metadevadm",
		"/var/adm/sa/nlsadmin", "/var/adm/sa/routeadm", "/var/adm/sa/sacadm",
		"/var/adm/sa/sadm", "/var/adm/sa/svcadm", "/var/adm/sa/sysadm",
		"/var/adm/sa/syseventadmd", "/var/adm/sa/ttyadmd", "/var/adm/sa/uadmin",
		"/var/adm/sa/zoneadmd", "/var/spool/lp/admins/.lp/.crontab",
		"/var/spool/lp/admins/.lp/lpshut", "/var/spool/lp/admins/.lp/lpsystem",
		"/var/spool/lp/admins/.lp/lpadmin", "/var/spool/lp/admins/.lp/lpmove",
		"/var/spool/lp/admins/.lp/lpusers", "/var/spool/lp/admins/.lp/lpfilter",
		"/var/spool/lp/admins/.lp/lpstat", "/var/spool/lp/admins/.lp/lpd",
		"/var/spool/lp/admins/.lp/lpsched", "/var/spool/lp/admins/.lp/lpc",
	},
	Dir: []string{"/var/adm/sa/.adm", "/var/spool/lp/admins/.lp"}, Ksyms: nil,
}

var SPANISH_FILES = Rootkit{
	Name: "Spanish Rootkit",
	File: []string{
		"/dev/ptyq", "/bin/ad", "/bin/ava", "/bin/server", "/usr/sbin/rescue",
		"/usr/share/.../chrps", "/usr/share/.../chrifconfig", "/usr/share/.../netstat",
		"/usr/share/.../linsniffer", "/usr/share/.../charbd", "/usr/share/.../charbd2",
		"/usr/share/.../charbd3", "/usr/share/.../charbd4", "/usr/man/tmp/update.tgz",
		"/var/lib/rpm/db.rpm", "/var/cache/man/.cat", "/var/spool/lpd/remote/.lpq",
	},
	Dir: []string{"/usr/share/..."}, Ksyms: nil,
}

var SUCKIT_FILES = Rootkit{
	Name: "Suckit Rootkit",
	File: []string{
		"/sbin/initsk12", "/sbin/initxrk", "/usr/bin/null", "/usr/share/locale/sk/.sk12/sk",
		"/etc/rc.d/rc0.d/S23kmdac", "/etc/rc.d/rc1.d/S23kmdac", "/etc/rc.d/rc2.d/S23kmdac",
		"/etc/rc.d/rc3.d/S23kmdac", "/etc/rc.d/rc4.d/S23kmdac", "/etc/rc.d/rc5.d/S23kmdac",
		"/etc/rc.d/rc6.d/S23kmdac",
	},
	Dir: []string{
		"/dev/sdhu0/tehdrakg", "/etc/.MG", "/usr/share/locale/sk/.sk12",
		"/usr/lib/perl5/site_perl/i386-linux/auto/TimeDate/.packlist",
	}, Ksyms: nil,
}

var NSDAP_FILES = Rootkit{
	Name: "NSDAP Rootkit",
	File: []string{
		"/dev/pts/01/55su", "/dev/pts/01/55ps", "/dev/pts/01/55ping", "/dev/pts/01/55login",
		"/dev/pts/01/PATCHER_COMPLETED", "/dev/prom/sn.l", "/dev/prom/dos",
		"/usr/lib/vold/nsdap/.kit", "/usr/lib/vold/nsdap/defines",
		"/usr/lib/vold/nsdap/patcher", "/usr/lib/vold/nsdap/pg", "/usr/lib/vold/nsdap/cleaner",
		"/usr/lib/vold/nsdap/utime", "/usr/lib/vold/nsdap/crypt", "/usr/lib/vold/nsdap/findkit",
		"/usr/lib/vold/nsdap/sn2", "/usr/lib/vold/nsdap/sniffload",
		"/usr/lib/vold/nsdap/runsniff", "/usr/lib/lpset", "/usr/lib/lpstart",
		"/usr/bin/mc68000", "/usr/bin/mc68010", "/usr/bin/mc68020", "/usr/ucb/bin/ps",
		"/usr/bin/m68k", "/usr/bin/sun2", "/usr/bin/mc68030", "/usr/bin/mc68040",
		"/usr/bin/sun3", "/usr/bin/sun3x", "/usr/bin/lso", "/usr/bin/u370",
	},
	Dir: []string{"/dev/pts/01", "/dev/prom", "/usr/lib/vold/nsdap", "/.pat"}, Ksyms: nil,
}

var SUNOSROOTKIT_FILES = Rootkit{
	Name: "SunOS Rootkit",
	File: []string{
		"/etc/ld.so.hash", "/lib/libext-2.so.7", "/usr/bin/ssh2d", "/bin/xlogin",
		"/usr/lib/crth.o", "/usr/lib/crtz.o", "/sbin/login", "/lib/security/.config/sn",
		"/lib/security/.config/lpsched", "/dev/kmod", "/dev/dos",
	},
	Dir: nil, Ksyms: nil,
}

var SUPERKIT_FILES = Rootkit{
	Name: "Superkit Rootkit",
	File: []string{
		"/usr/man/.sman/sk/backsh", "/usr/man/.sman/sk/izbtrag", "/usr/man/.sman/sk/sksniff",
		"/var/www/cgi-bin/cgiback.cgi",
	}, Dir: []string{"/usr/man/.sman/sk"}, Ksyms: nil,
}

var TBD_FILES = Rootkit{Name: "TBD(Telnet Backdoor)", File: []string{"/usr/lib/.tbd"}, Dir: nil, Ksyms: nil}

var TELEKIT_FILES = Rootkit{
	Name: "TeLeKiT Rootkit",
	File: []string{
		"/usr/man/man3/.../TeLeKiT/bin/sniff", "/usr/man/man3/.../TeLeKiT/bin/telnetd",
		"/usr/man/man3/.../TeLeKiT/bin/teleulo", "/usr/man/man3/.../cl", "/dev/ptyr",
		"/dev/ptyp", "/dev/ptyq", "/dev/hda06", "/usr/info/libc1.so",
	},
	Dir:   []string{"/usr/man/man3/...", "/usr/man/man3/.../lsniff", "/usr/man/man3/.../TeLeKiT"},
	Ksyms: nil,
}

var TOGROOT_FILES = Rootkit{
	Name: "OSX Togroot Rootkit",
	File: []string{
		"/System/Library/Extensions/Togroot.kext/Contents/Info.plist",
		"/System/Library/Extensions/Togroot.kext/Contents/pbdevelopment.plist",
		"/System/Library/Extensions/Togroot.kext/Contents/MacOS/togrootkext",
	},
	Dir: []string{
		"/System/Library/Extensions/Togroot.kext",
		"/System/Library/Extensions/Togroot.kext/Contents",
		"/System/Library/Extensions/Togroot.kext/Contents/MacOS",
	}, Ksyms: nil,
}

var TORN_FILES = Rootkit{
	Name: "T0rn Rootkit",
	File: []string{
		"/dev/.lib/lib/lib/t0rns", "/dev/.lib/lib/lib/du", "/dev/.lib/lib/lib/ls",
		"/dev/.lib/lib/lib/t0rnsb", "/dev/.lib/lib/lib/ps", "/dev/.lib/lib/lib/t0rnp",
		"/dev/.lib/lib/lib/find", "/dev/.lib/lib/lib/ifconfig", "/dev/.lib/lib/lib/pg",
		"/dev/.lib/lib/lib/ssh.tgz", "/dev/.lib/lib/lib/top", "/dev/.lib/lib/lib/sz",
		"/dev/.lib/lib/lib/login", "/dev/.lib/lib/lib/in.fingerd", "/dev/.lib/lib/lib/1i0n.sh",
		"/dev/.lib/lib/lib/pstree", "/dev/.lib/lib/lib/in.telnetd", "/dev/.lib/lib/lib/mjy",
		"/dev/.lib/lib/lib/sush", "/dev/.lib/lib/lib/tfn", "/dev/.lib/lib/lib/name",
		"/dev/.lib/lib/lib/getip.sh", "/usr/info/.torn/sh*", "/usr/src/.puta/.1addr",
		"/usr/src/.puta/.1file", "/usr/src/.puta/.1proc", "/usr/src/.puta/.1logz",
		"/usr/info/.t0rn",
	},
	Dir: []string{
		"/dev/.lib", "/dev/.lib/lib", "/dev/.lib/lib/lib", "/dev/.lib/lib/lib/dev",
		"/dev/.lib/lib/scan", "/usr/src/.puta", "/usr/man/man1/man1", "/usr/man/man1/man1/lib",
		"/usr/man/man1/man1/lib/.lib", "/usr/man/man1/man1/lib/.lib/.backup",
	},
	Ksyms: nil,
}

var TRNKIT_FILES = Rootkit{
	Name: "trNkit Rootkit",
	File: []string{
		"/usr/lib/libbins.la", "/usr/lib/libtcs.so", "/dev/.ttpy/ulogin.sh",
		"/dev/.ttpy/tcpshell.sh", "/dev/.ttpy/bupdu", "/dev/.ttpy/buloc", "/dev/.ttpy/buloc1",
		"/dev/.ttpy/buloc2", "/dev/.ttpy/stat", "/dev/.ttpy/backps", "/dev/.ttpy/tree",
		"/dev/.ttpy/topk", "/dev/.ttpy/wold", "/dev/.ttpy/whoold", "/dev/.ttpy/backdoors",
	},
	Dir: nil, Ksyms: nil,
}

var TROJANIT_FILES = Rootkit{
	Name: "Trojanit Kit Rootkit",
	File: []string{"bin/.ls", "/bin/.ps", "/bin/.netstat", "/usr/bin/.nop", "/usr/bin/.who"}, Dir: nil,
	Ksyms: nil,
}

var TURTLE_FILES = Rootkit{Name: "Turtle Rootkit", File: []string{"/dev/turtle2dev"}, Dir: nil, Ksyms: nil}

var TUXTENDO_FILES = Rootkit{
	Name: "Tuxtendo Rootkit",
	File: []string{
		"/lib/libproc.so.2.0.7", "/usr/bin/xchk", "/usr/bin/xsf", "/dev/tux/suidsh",
		"/dev/tux/.addr", "/dev/tux/.cron", "/dev/tux/.file", "/dev/tux/.log",
		"/dev/tux/.proc", "/dev/tux/.iface", "/dev/tux/.pw", "/dev/tux/.df", "/dev/tux/.ssh",
		"/dev/tux/.tux", "/dev/tux/ssh2/sshd2_config", "/dev/tux/ssh2/hostkey",
		"/dev/tux/ssh2/hostkey.pub", "/dev/tux/ssh2/logo", "/dev/tux/ssh2/random_seed",
		"/dev/tux/backup/crontab", "/dev/tux/backup/df", "/dev/tux/backup/dir",
		"/dev/tux/backup/find", "/dev/tux/backup/ifconfig", "/dev/tux/backup/locate",
		"/dev/tux/backup/netstat", "/dev/tux/backup/ps", "/dev/tux/backup/pstree",
		"/dev/tux/backup/syslogd", "/dev/tux/backup/tcpd", "/dev/tux/backup/top",
		"/dev/tux/backup/updatedb", "/dev/tux/backup/vdir",
	},
	Dir: []string{"/dev/tux", "/dev/tux/ssh2", "/dev/tux/backup"}, Ksyms: nil,
}

var URK_FILES = Rootkit{
	Name: "Universal Rootkit",
	File: []string{
		"/dev/prom/sn.l", "/usr/lib/ldlibps.so", "/usr/lib/ldlibnet.so", "/dev/pts/01/uconf.inv",
		"/dev/pts/01/cleaner", "/dev/pts/01/bin/psniff", "/dev/pts/01/bin/du",
		"/dev/pts/01/bin/ls", "/dev/pts/01/bin/passwd", "/dev/pts/01/bin/ps",
		"/dev/pts/01/bin/psr", "/dev/pts/01/bin/su", "/dev/pts/01/bin/find",
		"/dev/pts/01/bin/netstat", "/dev/pts/01/bin/ping", "/dev/pts/01/bin/strings",
		"/dev/pts/01/bin/bash", "/usr/man/man1/xxxxxxbin/du", "/usr/man/man1/xxxxxxbin/ls",
		"/usr/man/man1/xxxxxxbin/passwd", "/usr/man/man1/xxxxxxbin/ps",
		"/usr/man/man1/xxxxxxbin/psr", "/usr/man/man1/xxxxxxbin/su",
		"/usr/man/man1/xxxxxxbin/find", "/usr/man/man1/xxxxxxbin/netstat",
		"/usr/man/man1/xxxxxxbin/ping", "/usr/man/man1/xxxxxxbin/strings",
		"/usr/man/man1/xxxxxxbin/bash", "/tmp/conf.inv",
	},
	Dir: []string{"/dev/prom", "/dev/pts/01", "/dev/pts/01/bin", "/usr/man/man1/xxxxxxbin"}, Ksyms: nil,
}

var VCKIT_FILES = Rootkit{
	Name: "VcKit Rootkit", File: nil,
	Dir:   []string{"/usr/include/linux/modules/lib.so", "/usr/include/linux/modules/lib.so/bin"},
	Ksyms: nil,
}

var VAMPIRE_FILES = Rootkit{
	Name: "Vampire Rootkit", File: nil, Dir: nil,
	Ksyms: []string{"new_getdents", "old_getdents", "should_hide_file_name", "should_hide_task_name"},
}

var VOLC_FILES = Rootkit{
	Name: "Volc Rootkit",
	File: []string{
		"/usr/bin/volc", "/usr/lib/volc/backdoor/divine", "/usr/lib/volc/linsniff",
		"/etc/rc.d/rc1.d/S25sysconf", "/etc/rc.d/rc2.d/S25sysconf", "/etc/rc.d/rc3.d/S25sysconf",
		"/etc/rc.d/rc4.d/S25sysconf", "/etc/rc.d/rc5.d/S25sysconf",
	},
	Dir: []string{
		"/var/spool/.recent", "/var/spool/.recent/.files", "/usr/lib/volc",
		"/usr/lib/volc/backup",
	}, Ksyms: nil,
}

var WEAPONX_FILES = Rootkit{
	Name: "weaponX", File: []string{"/System/Library/Extensions/WeaponX.kext"},
	Dir: []string{"/tmp/..."}, Ksyms: nil,
}

var XZIBIT_FILES = Rootkit{
	Name: "Xzibit Rootkit",
	File: []string{
		"/dev/dsx", "/dev/caca", "/dev/ida/.inet/linsniffer", "/dev/ida/.inet/logclear",
		"/dev/ida/.inet/sense", "/dev/ida/.inet/sl2", "/dev/ida/.inet/sshdu",
		"/dev/ida/.inet/s", "/dev/ida/.inet/ssh_host_key", "/dev/ida/.inet/ssh_random_seed",
		"/dev/ida/.inet/sl2new.c", "/dev/ida/.inet/tcp.log", "/home/httpd/cgi-bin/becys.cgi",
		"/usr/local/httpd/cgi-bin/becys.cgi", "/usr/local/apache/cgi-bin/becys.cgi",
		"/www/httpd/cgi-bin/becys.cgi", "/www/cgi-bin/becys.cgi",
	},
	Dir: []string{"/dev/ida/.inet"}, Ksyms: nil,
}

var XORGSUNOS_FILES = Rootkit{
	Name: "X-Org SunOS Rootkit",
	File: []string{
		"/usr/lib/libX.a/bin/tmpfl", "/usr/lib/libX.a/bin/rps", "/usr/bin/srload",
		"/usr/lib/libX.a/bin/sparcv7/rps", "/usr/sbin/modcheck",
	},
	Dir: []string{
		"/usr/lib/libX.a", "/usr/lib/libX.a/bin", "/usr/lib/libX.a/bin/sparcv7",
		"/usr/share/man...",
	}, Ksyms: nil,
}

var ZARWT_FILES = Rootkit{
	Name: "zaRwT.KiT Rootkit",
	File: []string{"/dev/rd/s/sendmeil", "/dev/ttyf", "/dev/ttyp", "/dev/ttyn", "/rk/tulz"},
	Dir:  []string{"/rk", "/dev/rd/s"}, Ksyms: nil,
}

var ZK_FILES = Rootkit{
	Name: "ZK Rootkit",
	File: []string{
		"/usr/share/.zk/zk", "/usr/X11R6/.zk/xfs", "/usr/X11R6/.zk/echo", "/etc/1ssue.net",
		"/etc/sysconfig/console/load.zk",
	},
	Dir: []string{"/usr/share/.zk", "/usr/X11R6/.zk"}, Ksyms: nil,
}

var LOGIN_BACKDOOR_FILES = Rootkit{
	Name: "Miscellaneous login backdoors", File: []string{"/bin/.login", "/sbin/.login"},
	Dir: nil, Ksyms: nil,
}

var Sniffer_FILES = Rootkit{
	Name: "Sniffer log",
	File: []string{"/usr/lib/libice.log", "/dev/prom/sn.l", "/dev/fd/.88/zxsniff.log"},
	Dir:  nil, Ksyms: nil,
}

var SUSPICIOUS_DIRS = Rootkit{
	Name: "Suspicious dir", File: nil, Dir: []string{"/usr/X11R6/bin/.,/copy", "/dev/rd/cdb"},
	Ksyms: nil,
}

var Apache_Door = Rootkit{
	Name: "Apache backdoor",
	File: []string{
		"/etc/apache2/mods-enabled/mod_rootme.so", "/etc/apache2/mods-enabled/mod_rootme2.so",
		"/etc/httpd/modules/mod_rootme.so", "/etc/httpd/modules/mod_rootme2.so",
		"/usr/apache/libexec/mod_rootme.so", "/usr/apache/libexec/mod_rootme2.so",
		"/usr/lib/modules/mod_rootme.so", "/usr/lib/modules/mod_rootme2.so",
		"/usr/local/apache/modules/mod_rootme.so", "/usr/local/apache/modules/mod_rootme2.so",
		"/usr/local/apache/conf/mod_rootme.so", "/usr/local/apache/conf/mod_rootme2.so",
		"/usr/local/etc/apache/mod_rootme.so", "/usr/local/etc/apache/mod_rootme2.so",
		"/etc/apache/mod_rootme.so", "/etc/apache/mod_rootme2.so",
		"/etc/httpd/conf/mod_rootme.so", "/etc/httpd/conf/mod_rootme2.so",
	}, Dir: nil,
	Ksyms: nil,
}

var rootkit_rules = []Rootkit{
	W55808A, AdoreRootkit, AjakitRootkit, apaKitRootkit, ApacheWorm, AmbientRootkit,
	BalaurRootkit, BeastkitRootkit, bex2Rootkit, BobkitRootkit, OsxBoonanaATrojan, CinikWorm, CxRootkit,
	AbuseKit, DevilRootkit, DiamorphineLkm, DicaKitRootkit, Dreams_Rootkit, Duarawkz_Rootkit, Ebury_sshd_backdoor,
	ENYE_LKM, Flea_Rootkit, FreeBSD_Rootkit, Fu_Rootkit, Fuckit_Rootkit, GasKit_Rootkit, Heroin_LKM, HjC_Kit_Rootkit,
	ignoKit_Rootkit, iLLogiC_Rootkit, OSX_Inqtana, OSX_Inqtana2, OSX_Inqtana3, IntoXonia_NG_Rootkit, Irix_Rootkit,
	Jynx_Rootkit, Jynx2_Rootkit, KBeast_Rootkit, OSX_Keydnap_backdoor, Kitko_Rootkit, KNARK_FILES, KOMPLEX_FILES,
	LINUXV_FILES, LION_FILES, LOCKIT_FILES, MOKES_FILES, MRK_FILES, MOODNT_FILES, NIO_FILES, OHHARA_FILES,
	OPTICKIT_FILES, OSXRK_FILES, OZ_FILES, PHALANX_FILES, PHALANX2_FILES, PORTACELO_FILES, PROTON_FILES, REDSTORM_FILES,
	RHSHARPES_FILES, RSHA_FILES, SHUTDOWN_FILES, SCALPER_FILES, SHV4_FILES, SHV5_FILES, SINROOTKIT_FILES, SLAPPER_FILES,
	SNEAKIN_FILES, WANUKDOOR_FILES, WANUKWORM_FILES, SPANISH_FILES, SUCKIT_FILES, NSDAP_FILES, SUNOSROOTKIT_FILES,
	SUPERKIT_FILES, TBD_FILES, TELEKIT_FILES, TOGROOT_FILES, TORN_FILES, TRNKIT_FILES, TROJANIT_FILES, TURTLE_FILES,
	TUXTENDO_FILES, URK_FILES, VCKIT_FILES, VAMPIRE_FILES, VOLC_FILES, WEAPONX_FILES, XZIBIT_FILES, XORGSUNOS_FILES,
	ZARWT_FILES, ZK_FILES, LOGIN_BACKDOOR_FILES, Sniffer_FILES, SUSPICIOUS_DIRS, Apache_Door,
}

var LKM_BADNAMES = []string{
	"adore.o", "bkit-adore.o", "cleaner.o", "flkm.o", "knark.o", "modhide.o", "mod_klgr.o",
	"phide_mod.o", "vlogger.o", "p2.ko", "rpldev.o", "xC.o", "strings.o", "wkmr26.o",
}

var kallsyms []string

var rootkit_results []RootKitRulesResult

var bad_lkm_results map[string]string

func RootkitCheck() {

	for _, rootkit := range rootkit_rules {
		check_rootkit_rules(rootkit)
	}

	check_bad_LKM()

	for _, result := range rootkit_results {
		if result.Type == "file" {
			fmt.Printf("检测到%s的恶意rootkit文件: %s\n", result.Name, result.Res)
		}
		if result.Type == "dir" {
			fmt.Printf("检测到%s的恶意rootkit目录: %s\n", result.Name, result.Res)
		}
		if result.Type == "kms" {
			fmt.Printf("检测到%s内核符号表特征: %s\n", result.Name, result.Res)
		}
	}
	for file := range bad_lkm_results {
		fmt.Printf("检测到内核模块可疑文件 %s \n", file)
	}
	if len(rootkit_results) == 0 && len(bad_lkm_results) == 0 {
		fmt.Println(color.Yellow.Sprint("主机Rootkit检测: [safe]"))

	}
}

func check_rootkit_rules(rootkit Rootkit) {
	for _, file := range rootkit.File {
		if PathExists(file) {
			rootkit_results = append(rootkit_results, RootKitRulesResult{Name: rootkit.Name, Type: "file", Res: file})
		}
	}
	for _, dir := range rootkit.Dir {
		if PathExists(dir) {
			rootkit_results = append(rootkit_results, RootKitRulesResult{Name: rootkit.Name, Type: "dir", Res: dir})
		}
	}
	get_kmsinfo()
	for _, kms := range kallsyms {
		for _, ksyms := range rootkit.Ksyms {
			if strings.Contains(kms, ksyms) {
				rootkit_results = append(rootkit_results, RootKitRulesResult{Name: rootkit.Name, Type: "kms", Res: kms})
			}
		}
	}
}

func check_bad_LKM() {
	bad_lkm_results = make(map[string]string)
	if !PathExists("/lib/modules/") {
		return
	}

	cmd := exec.Command(
		"bash", "-c",
		"find /lib/modules/ -name '*.so' -o -name '*.ko'  -o -name '*.ko.xz' 2>/dev/null",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err.Error())
	}
	infos := strings.Split(string(out), "\n")
	for _, file := range infos {
		for _, lkm := range LKM_BADNAMES {
			filename := filepath.Base(file)
			if lkm == filename {
				bad_lkm_results[file] = lkm
			}
		}
	}
}

func get_kmsinfo() {

	var cmd *exec.Cmd

	if PathExists("/proc/kallsyms") {
		cmd = exec.Command("bash", "-c", "cat /proc/kallsyms 2>/dev/null|awk '{print $3}'")
	} else if PathExists("/proc/ksyms") {
		cmd = exec.Command("bash", "-c", "cat /proc/ksyms")
	} else {
		return
	}

	out, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	kallsyms = strings.Split(string(out), "\n")

}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
