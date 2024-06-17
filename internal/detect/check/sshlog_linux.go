//go:build linux

package check

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/toolkits/slice"
)

type BaopoInfo struct {
	User string
	Ip   string
	Time string
}

// 爆破成功
var correctBaoInfos []BaopoInfo

// 所有C段爆破信息（超过阈值）
var baoInfo []BaopoInfo

// ip_failed_count:    单IP错误的次数，超过此错误代表发生了爆破行为
// ips_failed_count:   IP C段错误的次数，超过此错误代表发生了爆破行为
// correct_baopo_info: 记录爆破成功的信息

func SshAnalysis(log string, logDir string, ipFailedCount uint, ipsFailedCount uint) {

	if log == "" {
		dirFileDetect(logDir, ipFailedCount, ipsFailedCount)
	} else {
		attackDetect(log, ipFailedCount, ipsFailedCount)
	}

}

func dirFileDetect(logDir string, ipFailedCount uint, ipsFailedCount uint) {

	var files []string
	dirs, _ := ioutil.ReadDir(logDir)
	for _, dir := range dirs {
		if dir.IsDir() {
			continue
		}
		if strings.Contains(dir.Name(), "secure") {
			files = append(files, logDir+dir.Name())
		}

	}
	for _, file := range files {
		attackDetect(file, ipFailedCount, ipsFailedCount)
	}

}

func reRepeat(old []BaopoInfo) []string {
	var ipSum []string
	// 遍历数组
	for _, item := range old {
		if !slice.ContainsString(ipSum, item.Ip) {
			ipSum = append(ipSum, item.Ip)
		}
	}
	return ipSum
}

func filter(old map[string]uint, count uint) map[string]uint {

	var newDict map[string]uint
	newDict = make(map[string]uint)
	for key := range old {
		if old[key] > count {
			newDict[key] = old[key]
		}
	}
	return newDict
}

func counter(old []string) map[string]uint {

	var countDict map[string]uint
	countDict = make(map[string]uint)
	for _, item := range old {
		_, ok := countDict[item]
		if ok {
			countDict[item] += 1
		} else {
			countDict[item] = 1
		}
	}
	return countDict
}

func attackDetect(log string, ipFailedCount uint, ipsFailedCount uint) {
	// 账户错误特征
	usernameError := "Invalid user"
	// 账户正确密码错误特征
	usernameCorrect := "Failed password for"
	// 成功登陆
	usernamePasswordCorrect := "Accepted password for"
	// 所有错误登陆日志ip
	var failedIps []string
	// 登陆成功日志
	var correctInfos []BaopoInfo
	// 登录日志
	var loginInfos []BaopoInfo
	// C段ip登陆错误日志
	//var failed_c_ips []string

	_, filename := filepath.Split(log)
	year := ""
	if strings.Contains(filename, "secure-") && len(filename) == 15 {
		year = filename[7:11]
	}

	dat, err := ioutil.ReadFile(log)
	if err != nil {
		fmt.Println(err.Error())
	}
	lines := strings.Split(string(dat), "\n")

	for _, line := range lines {

		if strings.Contains(line, usernameError) && strings.Contains(line, "from") && strings.Contains(line, "sshd") {

			ip := strings.Split(strings.Split(line, ": ")[1], " ")[4]
			failedIps = append(failedIps, ip)
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			loginInfos = append(loginInfos, BaopoInfo{User: "", Ip: ip, Time: time})

		} else if strings.Contains(line, usernameCorrect) && strings.Contains(line, "from") && strings.Contains(line, "sshd") {

			strs := strings.Split(strings.TrimSpace(strings.Split(line, ": ")[1]), " ")
			ip := strs[len(strs)-4]
			failedIps = append(failedIps, ip)
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			loginInfos = append(loginInfos, BaopoInfo{User: "", Ip: ip, Time: time})

		} else if strings.Contains(line, usernamePasswordCorrect) && strings.Contains(line, "sshd") {

			ip := strings.Split(strings.Split(line, ": ")[1], " ")[5]
			user := strings.Split(strings.Split(line, ": ")[1], " ")[3]
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			correctInfos = append(correctInfos, BaopoInfo{User: user, Ip: ip, Time: time})

		}

	}

	// 记录登陆失败攻击源IP地址和尝试次数
	failedIpDict := filter(counter(failedIps), ipFailedCount)

	// 获取所有未爆破成功的ip信息
	for _, loginInfo := range loginInfos {
		for failed := range failedIpDict {
			if loginInfo.Ip == failed {
				baoInfo = append(baoInfo, loginInfo)
			}
		}

	}

	// 判断爆破行为是否成功:
	for _, correctInfo := range correctInfos {
		for failed := range failedIpDict {
			if correctInfo.Ip == failed {
				correctBaoInfos = append(correctBaoInfos, correctInfo)
			}
		}
	}

}

func SSHLog() {
	_, err := os.Lstat("/var/log/auth.log")
	if os.IsNotExist(err) {
		_, err := os.Lstat("/var/log/secure")
		if os.IsNotExist(err) {
			fmt.Println("Could't find SSH log !!!")
		} else {
			if !sshLogNotSafe("/var/log/secure", "") {
				fmt.Println(color.Yellow.Sprint("主机SSH登录爆破检测: [safe]"))

			}
		}
	} else {
		if !sshLogNotSafe("/var/log/auth.log", "") {
			fmt.Println(color.Yellow.Sprint("主机SSH登录爆破检测: [safe]"))

		}
	}
}

func sshLogNotSafe(log string, logDir string) bool {
	malice := false

	SshAnalysis(log, logDir, 10, 10)

	for _, info := range correctBaoInfos {
		user := info.User
		time := info.Time
		ip := info.Ip
		fmt.Printf("主机SSH被外部爆破且成功登录，时间: %s, ip: %s, 用户: %s\n", time, ip, user)
		malice = true
	}
	ipSum := reRepeat(baoInfo)
	if len(ipSum) != 0 {
		malice = true
		fmt.Println("以下", len(ipSum), "个IP尝试SSH登录爆破，建议封禁:")
		for _, ip := range ipSum {
			fmt.Print(ip + "、")
		}
		if len(ipSum) != 0 {
			fmt.Println("")
		}
	}

	return malice
}
