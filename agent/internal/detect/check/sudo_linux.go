package check

import (
	"fmt"

	"github.com/m-sec-org/d-eyes/agent/internal/utils"
	"os"
	"strings"
)

func Sudo() bool {
	suspicious := false
	if utils.FileExist("/etc/sudoers") {
		content, err := os.ReadFile("/etc/sudoers")
		if err != nil {
			fmt.Println(err.Error())
			return false
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			if strings.Contains(line, "#") {
				continue
			}
			if strings.Contains(line, "%") {
				continue
			}
			if !strings.Contains(line, "(ALL") && !strings.Contains(line, "(root") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			user := strings.TrimSpace(fields[0])
			if user == "" || user == "root" || strings.HasPrefix(user, "%") {
				continue
			}
			fmt.Printf("用户 %s 可通过sudo命令获取特权\n", user)
			suspicious = true
		}
	}
	return suspicious
}
