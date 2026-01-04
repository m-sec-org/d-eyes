//go:build linux

package check

import (
	"bufio"
	"fmt"

	"github.com/m-sec-org/d-eyes/agent/internal/utils"
	"os"
	"strings"
)

func Empty() bool {
	suspicious := false

	if utils.FileExist("/etc/shadow") {
		file, err := os.Open("/etc/shadow")
		if err != nil {
			fmt.Println(err.Error())
			return false
		}
		defer file.Close()

		sum := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 2 {
				continue
			}
			if parts[1] != "" {
				continue
			}
			user := strings.TrimSpace(parts[0])
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
		if err := scanner.Err(); err != nil {
			fmt.Println(err.Error())
		}
	}

	return suspicious
}
