//go:build linux

package utils

import (
	"io/ioutil"
	"strings"
)

func GetLinuxUser() (resultData []string) {
	dat, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return resultData
	}
	userList := strings.Split(string(dat), "\n")
	if len(userList) < 2 {
		return
	}
	for _, info := range userList[0 : len(userList)-1] {

		if strings.Contains(info, "/nologin") {
			continue
		}
		if strings.Contains(info, "/bin/false") {
			continue
		}
		s := strings.SplitN(info, ":", 2)
		resultData = append(resultData, s[0])
	}
	return resultData
}
