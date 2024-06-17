package utils

import (
	"bufio"
	"fmt"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"io"
	"os"
	"strings"
)

func CheckShell(content string) bool {

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
func CheckFile(path string) bool {
	result := false
	_, err := os.Stat(path)
	if err != nil {
		return false
	}
	fr, _ := os.Open(path)
	buf := bufio.NewReader(fr)
	for {
		line, _, e := buf.ReadLine()

		if e == io.EOF {
			break
		}
		if len(string(line)) < 3 {
			continue
		}
		if string(line)[0] == '#' {
			continue
		}

		c := CheckShell(string(line))
		if c {
			fmt.Println(color.Green.Sprint("[*]File:", path, "Found:", string(line)))
			result = true
		}
	}
	return result
}
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
