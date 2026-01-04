//go:build linux

package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
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
	res, err := cmdexec.Run(context.Background(), cmdexec.Request{
		Command:    "sh",
		Args:       []string{"-c", "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null"},
		Identifier: "detect.check SetUid",
	})

	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	fileInfos := strings.Split(res.Stdout, "\n")
	var suspiciousFiles []string
	for _, info := range fileInfos {
		if info == "" {
			continue
		}
		tmp := strings.Split(info, "/")
		if !slice.ContainsString(whitelist, tmp[len(tmp)-1]) {
			suspiciousFiles = append(suspiciousFiles, info)
		}
	}

	if len(suspiciousFiles) > 0 {
		suspicious = true
		fmt.Println("主机含有非常见suid程序，请确认")
		for _, path := range suspiciousFiles {
			fmt.Println(path)
		}
	}

	return suspicious

}
