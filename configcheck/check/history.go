package check

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gookit/color"

	"d-eyes/configcheck/common"
)

var suspiciousHistory [][2]string

func HistoryCheck() {

	if HistoryFiles() {
		color.Infoln("主机历史命令检测: [safe]")
	} else {
		fmt.Println("历史存在可疑命令, 请确认:")
		for _, detail := range suspiciousHistory {
			fmt.Printf("[*]File: %s  Detail: %s\n", detail[0], detail[1])
		}
	}

}

func HistoryFiles() bool {

	filePath := []string{"/home/", "/root/.bash_history", "/Users/"}
	for _, path := range filePath {

		if !common.PathExists(path) {
			continue
		}

		dirs, err := os.ReadDir(path)

		if err != nil {
			fi, _ := os.Open(path)
			defer fi.Close()

			br := bufio.NewReader(fi)
			for {
				data, _, c := br.ReadLine()
				if c == io.EOF {
					break
				}
				line := strings.Replace(string(data), "\n", "", -1)
				contents := Shell(line)
				if contents == true {
					suspiciousHistory = append(suspiciousHistory, [2]string{path, line})
				}
			}
			continue
		}
		for _, dir := range dirs {
			subFile := path + dir.Name() + "/.bash_history"
			if !common.PathExists(subFile) {
				continue
			}

			fi, _ := os.Open(subFile)
			defer fi.Close()

			br := bufio.NewReader(fi)
			for {
				data, _, c := br.ReadLine()
				if c == io.EOF {
					break
				}
				line := strings.Replace(string(data), "\n", "", -1)
				contents := Shell(line)
				if contents {
					suspiciousHistory = append(suspiciousHistory, [2]string{subFile, line})
				}
			}
		}
	}
	if len(suspiciousHistory) == 0 {
		return true
	}
	return false
}

func Shell(content string) bool {

	if strings.Contains(content, "docker") {
		return false
	}

	if (strings.Contains(content, "sh") && (strings.Contains(content, "/dev/tcp/") ||
		strings.Contains(content, "telnet ") || strings.Contains(content, "nc ") ||
		(strings.Contains(content, "exec ") && strings.Contains(content, "socket")) ||
		strings.Contains(content, "curl ") || strings.Contains(content, "wget ") ||
		strings.Contains(content, "lynx "))) || strings.Contains(content, ".decode('base64')") || strings.Contains(content, "exec(base64.b64decode") ||
		(strings.Contains(content, "base64 ") && strings.Contains(content, "--decode") && strings.Contains(content, "python")) ||
		(strings.Contains(content, "base64 ") && strings.Contains(content, "-d") && strings.Contains(content, "bash")) ||
		(strings.Contains(content, "nc ") && strings.Contains(content, "-vv")) ||
		(strings.Contains(content, "ln ") && strings.Contains(content, "-sf") && strings.Contains(content, "/usr/sbin/sshd")) {

		return true
	} else if strings.Contains(content, "/dev/tcp/") && (strings.Contains(content, "exec ") ||
		strings.Contains(content, "ksh -c")) {
		return true
	} else if strings.Contains(content, "sh -i") {
		return true
	} else if strings.Contains(content, "exec ") && (strings.Contains(content, "socket.") ||
		strings.Contains(content, ".decode('base64')")) {
		return true
	} else if strings.Contains(content, "socket.socket") {
		return true
	} else if (strings.Contains(content, "wget ") || strings.Contains(content, "curl ")) &&
		(strings.Contains(content, " -O ") || strings.Contains(content, " -s ")) &&
		strings.Contains(content, " http") && (strings.Contains(content, "php ") ||
		strings.Contains(content, "perl ") || strings.Contains(content, "ruby ") ||
		strings.Contains(content, "python ") || strings.Contains(content, "sh ") ||
		strings.Contains(content, "bash ")) { // Ruby added
		return true
	} else {
		return false
	}

}
