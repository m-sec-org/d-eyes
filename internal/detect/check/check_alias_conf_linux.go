//go:build linux

package check

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"io/ioutil"
	"regexp"
	"strings"
)

func AliasConf() bool {
	suspicious := false

	var files = []string{"/root/.bashrc", "/root/.bash_profile", "/etc/bashrc", "/etc/profile", "/etc/bash.bashrc"}

	dirs, _ := ioutil.ReadDir("/home")
	for _, dir := range dirs {

		if !dir.IsDir() {
			continue
		}

		suspicious2 := aliasFileAnalysis("/home/" + dir.Name() + "/.bashrc")
		if suspicious2 {
			suspicious = true
		}

		suspicious2 = aliasFileAnalysis("/home/" + dir.Name() + "/.bash_profile")
		if suspicious2 {
			suspicious = true
		}

	}

	for _, file := range files {
		suspicious2 := aliasFileAnalysis(file)
		if suspicious2 {
			suspicious = true
		}
	}

	return suspicious
}

func aliasFileAnalysis(filepath string) bool {
	suspicious := false

	if !utils.FileExist(filepath) {
		return false
	}

	systems := []string{
		"ps", "strings", "netstat", "find", "echo", "iptables", "lastlog", "who", "ifconfig", "ssh", "top", "crontab", "adduser", "kill", "killall", "mv", "rm",
		"userdel", "cp", "locate", "ls", "show", "ll",
	}

	dat, _ := ioutil.ReadFile(filepath)
	fliest := strings.Split(string(dat), "\n")
	for _, line := range fliest {
		if len(line) > 5 && line[:5] == "alias" {
			for _, syscmd := range systems {

				reg := regexp.MustCompile("alias\\s+" + syscmd)
				dataSlice := reg.FindAll([]byte(line), -1)
				if dataSlice != nil {
					fmt.Printf("配置文件: %s | 存在可疑的alias设置: %s \n", filepath, line)
					suspicious = true
				}

			}
		} else if len(line) > 6 && line[:6] == "source" {
			fmt.Printf("配置文件: %s | 存在可疑的alias设置: %s \n", filepath, line)
			suspicious = true
		}
	}

	return suspicious
}
