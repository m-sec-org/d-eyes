//go:build linux

package check

import (
	"fmt"
	"os/exec"
	"strings"
)

func SuccessLoginDetail() {
	c := exec.Command("bash", "-c", "who /var/log/wtmp | awk '{print $1,$3\"-\"$4\"\",$5}'")
	out, err := c.CombinedOutput()
	if err != nil {
		fmt.Println("读取记录失败!")
		return
	}
	infos := strings.Split(string(out), "\n")
	infos = infos[:len(infos)-1]

	if len(infos) == 1 && infos[0] == "" {
		fmt.Println("未找到成功的登录信息.")
		return
	}
	sum := 0
	for i := len(infos) - 1; i >= 0; i-- {
		sum++
		success := strings.Split(infos[i], " ")
		fmt.Printf("User : %s    time : %s  IP : %s\n", success[0], success[1], success[2])
		if sum == 5 {
			return
		}
	}

}
