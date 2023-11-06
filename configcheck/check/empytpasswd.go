package check

import (
	"fmt"
	"os/exec"
	"strings"
)

func Empty() bool {
	suspicious := false

	if FileExist("/etc/shadow") {
		c := exec.Command("bash", "-c", "awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null")
		output, err := c.CombinedOutput()
		if err != nil {
			fmt.Println(err.Error())
		}
		shellProcess := strings.Split(string(output), "\n")
		sum := 0
		for _, user := range shellProcess {
			if user == "" {
				continue
			}
			sum++
			if sum == 1 {
				fmt.Println("")
			}
			fmt.Printf("存在空口令用户 %s\n", user)
			suspicious = true
		}
	}

	return suspicious
}
