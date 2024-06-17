//go:build linux

package check

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/toolkits/slice"
)

func SetUid() bool {
	suspicious := false
	whitelist := []string{
		"pam_timestamp_check", "unix_chkpwd", "ping", "mount", "umount", "sudo", "su", "pt_chown", "ssh-keysign", "at", "passwd", "chsh", "crontab", "chfn",
		"usernetctl", "staprun", "newgrp", "chage", "dhcp", "helper", "pkexec", "top", "Xorg", "nvidia-modprobe", "quota", "login", "security_authtrampoline",
		"authopen", "traceroute6", "traceroute", "ps", "auth_pam_tool", "Xorg.wrap", "gpasswd", "mount.cifs", "mount.nfs", "ping6", "pppd", "fusermount3",
		"ntfs-3g",
	}
	c := exec.Command(
		"bash", "-c",
		"find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null",
	)

	output, err := c.CombinedOutput()

	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	fileInfos := strings.Split(string(output), "\n")
	if len(fileInfos) != 0 {
		suspicious = true
		fmt.Println("主机含有非常见suid程序，请确认")
	}
	for _, info := range fileInfos {
		if info == "" {
			continue
		}
		tmp := strings.Split(info, "/")
		if !slice.ContainsString(whitelist, tmp[len(tmp)-1]) {
			fmt.Println(info)
		}
	}

	return suspicious

}
