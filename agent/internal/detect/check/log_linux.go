//go:build linux

package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
)

func SuccessLoginDetail() {
	res, err := cmdexec.Run(context.Background(), cmdexec.Request{
		Command:    "who",
		Args:       []string{"/var/log/wtmp"},
		Identifier: "detect.check SuccessLoginDetail",
	})
	if err != nil {
		fmt.Println("读取记录失败!")
		return
	}
	infos := strings.Split(strings.TrimSpace(res.Stdout), "\n")

	if len(infos) == 1 && infos[0] == "" {
		fmt.Println("未找到成功的登录信息.")
		return
	}
	sum := 0
	for i := len(infos) - 1; i >= 0; i-- {
		success := strings.Fields(infos[i])
		if len(success) < 4 {
			continue
		}
		sum++
		timeValue := success[2] + "-" + success[3]
		ipValue := ""
		if len(success) >= 5 {
			ipValue = success[4]
		}
		fmt.Printf("User : %s    time : %s  IP : %s\n", success[0], timeValue, ipValue)
		if sum == 5 {
			return
		}
	}

}
