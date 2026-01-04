//go:build linux

package check

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/m-sec-org/d-eyes/agent/internal/utils"
	"os"
	"strings"
)

func AuthorizedKeys() bool {
	suspicious := false

	dirs, _ := os.ReadDir("/home")
	for _, dir := range dirs {

		if !dir.IsDir() {
			continue
		}

		suspicious2 := fileAnalysis("/home/"+dir.Name()+"/.ssh/authorized_keys", dir.Name())
		if suspicious2 {
			suspicious = true
		}
	}

	suspicious2 := fileAnalysis("/root/.ssh/authorized_keys", "root")
	if suspicious2 {
		suspicious = true
	}

	return suspicious
}

func fileAnalysis(file string, user string) bool {
	suspicious := false

	if utils.FileExist(file) {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("用户 %s 存在免密登录的证书，证书位置: %s \n", user, file)
			return true
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fmt.Printf("用户 %s 存在免密登录的证书，证书位置: %s \n", user, file)
			return true
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("用户 %s 存在免密登录的证书，证书位置: %s \n", user, file)
			return true
		}
	}
	return suspicious

}
