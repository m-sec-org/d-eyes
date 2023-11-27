package info

import (
	"fmt"

	"github.com/gookit/color"
	"github.com/yusufpapurcu/wmi"
)

func DisplayAllUsers() {

	users := GetWindowsUser()

	for _, user := range users {
		color.Greenp("* ")
		fmt.Println(user)
	}
}

type userAccount struct {
	Name        string // 用户名
	Description string // 用户描述
	Status      string // 用户状态
}

// GetUser 获取系统用户列表
func GetWindowsUser() (resultData []string) {

	var dst []userAccount
	err := wmi.Query("SELECT * FROM Win32_UserAccount where LocalAccount=TRUE", &dst)
	if err != nil {
		return resultData
	}
	for _, v := range dst {
		resultData = append(resultData, v.Name)
	}
	return resultData
}
