package check

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
	"github.com/toolkits/slice"
)

type BaopoInfo struct {
	User string
	Ip   string
	Time string
}

// 爆破成功
var correct_baopo_info []BaopoInfo

// 所有爆破的信息（超过阈值）
var baopo_info []BaopoInfo

//所有C段爆破信息（超过阈值）
//var c_baopo_info []BaopoInfo

// ip_failed_count:    单IP错误的次数，超过此错误代表发生了爆破行为
// ips_failed_count:   IP C段错误的次数，超过此错误代表发生了爆破行为
// correct_baopo_info: 记录爆破成功的信息

func SSH_Analysis(log string, log_dir string, ip_failed_count uint, ips_failed_count uint) {

	if log == "" {
		dir_file_detect(log_dir, ip_failed_count, ips_failed_count)
	} else {
		attack_detect(log, ip_failed_count, ips_failed_count)
	}

}

func dir_file_detect(log_dir string, ip_failed_count uint, ips_failed_count uint) {

	var files []string
	dirs, _ := ioutil.ReadDir(log_dir)
	for _, dir := range dirs {
		if dir.IsDir() {
			continue
		}
		if strings.Contains(dir.Name(), "secure") {
			files = append(files, log_dir+dir.Name())
		}

	}
	for _, file := range files {
		attack_detect(file, ip_failed_count, ips_failed_count)
	}

}

func reRepeat(old []BaopoInfo) []string {
	var ip_sum []string
	// 遍历数组
	for _, item := range old {
		if !slice.ContainsString(ip_sum, item.Ip) {
			ip_sum = append(ip_sum, item.Ip)
		}
	}
	return ip_sum
}

func filter(old map[string]uint, count uint) map[string]uint {

	var new_dict map[string]uint
	new_dict = make(map[string]uint)
	for key := range old {
		if old[key] > count {
			new_dict[key] = old[key]
		}
	}
	return new_dict
}

func counter(old []string) map[string]uint {

	var count_dict map[string]uint
	count_dict = make(map[string]uint)
	for _, item := range old {
		_, ok := count_dict[item]
		if ok {
			count_dict[item] += 1
		} else {
			count_dict[item] = 1
		}
	}
	return count_dict
}

func attack_detect(log string, ip_failed_count uint, ips_failed_count uint) {
	// 账户错误特征
	username_error := "Invalid user"
	// 账户正确密码错误特征
	username_correct := "Failed password for"
	// 成功登陆
	username_password_correct := "Accepted password for"
	// 所有错误登陆日志ip
	var failed_ips []string
	// 登陆成功日志
	var correct_infos []BaopoInfo
	// 登录日志
	var login_infos []BaopoInfo
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

		if strings.Contains(line, username_error) && strings.Contains(line, "from") && strings.Contains(line, "sshd") {

			ip := strings.Split(strings.Split(line, ": ")[1], " ")[4]
			failed_ips = append(failed_ips, ip)
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			login_infos = append(login_infos, BaopoInfo{User: "", Ip: ip, Time: time})

		} else if strings.Contains(line, username_correct) && strings.Contains(line, "from") && strings.Contains(line, "sshd") {

			strs := strings.Split(strings.TrimSpace(strings.Split(line, ": ")[1]), " ")
			ip := strs[len(strs)-4]
			failed_ips = append(failed_ips, ip)
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			login_infos = append(login_infos, BaopoInfo{User: "", Ip: ip, Time: time})

		} else if strings.Contains(line, username_password_correct) && strings.Contains(line, "sshd") {

			ip := strings.Split(strings.Split(line, ": ")[1], " ")[5]
			user := strings.Split(strings.Split(line, ": ")[1], " ")[3]
			time := strings.Join(strings.Split(strings.Replace(line, "  ", " ", -1), " ")[:3], " ") + " " + year
			correct_infos = append(correct_infos, BaopoInfo{User: user, Ip: ip, Time: time})

		}

	}

	// 记录登陆失败攻击源IP地址和尝试次数
	failed_ip_dict := filter(counter(failed_ips), ip_failed_count)

	// 获取所有未爆破成功的ip信息
	for _, login_info := range login_infos {
		for failed := range failed_ip_dict {
			if login_info.Ip == failed {
				baopo_info = append(baopo_info, login_info)
			}
		}

	}

	// 判断爆破行为是否成功:
	for _, correct_info := range correct_infos {
		for failed := range failed_ip_dict {
			if correct_info.Ip == failed {
				correct_baopo_info = append(correct_baopo_info, correct_info)
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
				color.Infoln("主机SSH登录爆破检测: [safe]")
			}
		}
	} else {
		if !sshLogNotSafe("/var/log/auth.log", "") {
			color.Infoln("主机SSH登录爆破检测: [safe]")
		}
	}
}

func sshLogNotSafe(log string, log_dir string) bool {
	malice := false

	SSH_Analysis(log, log_dir, 10, 10)

	for _, info := range correct_baopo_info {
		user := info.User
		time := info.Time
		ip := info.Ip
		fmt.Printf("主机SSH被外部爆破且成功登录，时间: %s, ip: %s, 用户: %s\n", time, ip, user)
		malice = true
	}
	ip_sum := reRepeat(baopo_info)
	if len(ip_sum) != 0 {
		malice = true
		fmt.Println("以下", len(ip_sum), "个IP尝试SSH登录爆破，建议封禁:")
		for _, ip := range ip_sum {
			fmt.Print(ip + "、")
		}
		if len(ip_sum) != 0 {
			fmt.Println("")
		}
	}

	return malice
}
