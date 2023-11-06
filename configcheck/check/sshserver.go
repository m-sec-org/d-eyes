package check

import (
	"fmt"
	"os/exec"
	"strings"
)

func SshWrapper() bool {
	suspicious := false

	c := exec.Command("bash", "-c", "file /usr/sbin/sshd 2>/dev/null")
	output, err := c.CombinedOutput()
	if err != nil {
		fmt.Println(err.Error())
	}
	infos := strings.Split(string(output), "\n")
	if len(infos) == 0 {
		return suspicious
	}
	if !strings.Contains(infos[0], "ELF") && !strings.Contains(infos[0], "executable") {
		fmt.Println("/usr/sbin/sshd被篡改,文件非可执行文件")
		suspicious = true
	}

	return suspicious
}
