package check

import (
	"fmt"
	"io/ioutil"
	"os"
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

		suspicious2 := alias_file_analysis("/home/" + dir.Name() + "/.bashrc")
		if suspicious2 {
			suspicious = true
		}

		suspicious2 = alias_file_analysis("/home/" + dir.Name() + "/.bash_profile")
		if suspicious2 {
			suspicious = true
		}

	}

	for _, file := range files {
		suspicious2 := alias_file_analysis(file)
		if suspicious2 {
			suspicious = true
		}
	}

	return suspicious
}

func alias_file_analysis(filepath string) bool {
	suspicious := false

	if !FileExist(filepath) {
		return suspicious
	}

	syscmds := []string{
		"ps", "strings", "netstat", "find", "echo", "iptables", "lastlog", "who", "ifconfig", "ssh", "top", "crontab", "adduser", "kill", "killall", "mv", "rm",
		"userdel", "cp", "locate", "ls", "show", "ll",
	}

	dat, _ := ioutil.ReadFile(filepath)
	flist := strings.Split(string(dat), "\n")
	for _, line := range flist {
		if len(line) > 5 && line[:5] == "alias" {
			for _, syscmd := range syscmds {

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

func FileExist(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
