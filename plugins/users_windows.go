//go:build windows

package plugins

type userAccount struct {
	Name        string // 用户名
	Description string // 用户描述
	Status      string // 用户状态
}

func GetUsers() (resultData []string) {
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
