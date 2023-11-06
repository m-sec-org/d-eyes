package check

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
)

func AuthorizedKeys() bool {
	suspicious := false

	dirs, _ := ioutil.ReadDir("/home")
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

	if FileExist(file) {
		c := exec.Command(
			"bash", "-c",
			"cat "+file+" 2>/dev/null |awk '{print $3}'",
		)
		output, _ := c.CombinedOutput()
		shell_process3 := strings.Split(string(output), "\n")
		if len(shell_process3) > 0 {
			fmt.Printf("用户 %s 存在免密登录的证书，证书位置: %s \n", user, file)
		}
		suspicious = true
	}
	return suspicious

}
