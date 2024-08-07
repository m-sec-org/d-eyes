package check

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"os/exec"
	"strings"
)

func Sudo() bool {
	suspicious := false
	if utils.FileExist("/etc/sudoers") {
		c := exec.Command(
			"bash", "-c",
			"cat /etc/sudoers 2>/dev/null |grep -v '#'|grep -v '%'|grep '(ALL\\|(root'|awk '{print $1}'",
		)
		output, err := c.CombinedOutput()
		if err != nil {
			fmt.Println(err.Error())
			return false
		}
		shellProcess3 := strings.Split(string(output), "\n")
		for _, user := range shellProcess3 {
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
