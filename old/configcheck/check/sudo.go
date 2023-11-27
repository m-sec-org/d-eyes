package check

import (
	"fmt"
	"os/exec"
	"strings"
)

func Sudo() bool {
	suspicious := false
	if FileExist("/etc/sudoers") {
		c := exec.Command(
			"bash", "-c",
			"cat /etc/sudoers 2>/dev/null |grep -v '#'|grep -v '%'|grep '(ALL\\|(root'|awk '{print $1}'",
		)
		output, err := c.CombinedOutput()
		if err != nil {
			fmt.Println(err.Error())
			return suspicious
		}
		shell_process3 := strings.Split(string(output), "\n")
		for _, user := range shell_process3 {
			if len(user) < 1 {
				continue
			}
			if user != "root" && user[0] != '%' {
				fmt.Printf("用户 %s 可通过sudo命令获取特权\n", user)
				suspicious = true
			}
		}
	}
	return suspicious
}
