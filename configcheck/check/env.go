package check

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"d-eyes/configcheck/common"
)

func checkBackdoor(tag string) bool {
	suspicious := false
	files := []string{
		"/root/.bashrc", "/root/.tcshrc", "/root/.bash_profile", "/root/.cshrc", "/root/.tcshrc",
		"/etc/bashrc", "/etc/profile", "/etc/profile.d/", "/etc/csh.login", "/etc/csh.cshrc",
	}

	homeFiles := []string{"/.bashrc", "/.bash_profile", "/.tcshrc", "/.cshrc", "/.tcshrc"}

	dirs, _ := ioutil.ReadDir("/home/")
	for _, subDir := range dirs {
		for _, homeFile := range homeFiles {
			subFile := "/home/" + subDir.Name() + homeFile
			info := checkTag(subFile, tag)
			if info {
				suspicious = true
			}
		}
	}
	for _, subFile := range files {

		s, err := os.Stat(subFile)
		if err != nil {
			continue
		}
		if s.IsDir() {
			filepath.Walk(
				subFile, func(path string, info fs.FileInfo, err error) error {

					if info.IsDir() {
						return nil
					} else {
						inf := checkTag(path, tag)
						if inf {
							suspicious = true
						}
					}
					return err
				},
			)
		} else {
			inf := checkTag(subFile, tag)
			if inf {
				suspicious = true
			}

		}
	}
	return suspicious
}

func checkTag(filename string, tag string) bool {
	result := false
	if !common.PathExists(filename) {
		return false
	}
	_, err := ioutil.ReadDir(filename)
	if err == nil {
		return false
	}

	fr, _ := os.Open(filename)
	defer fr.Close()
	br := bufio.NewReader(fr)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if strings.Contains(string(line), "export "+tag+"=") {
			fmt.Println("[*]File:", filename, " Found:", string(line))
			result = true
		}
	}
	return result
}

func checkEnv() bool {
	suspicious := false
	files := []string{
		"/root/.bashrc", "/root/.tcshrc", "/root/.bash_profile", "/root/.cshrc", "/root/.tcshrc",
		"/etc/bashrc", "/etc/profile", "/etc/csh.login", "/etc/csh.cshrc",
	}

	homeFiles := []string{"/.bashrc", "/.bash_profile", "/.tcshrc", "/.cshrc", "/.tcshrc"}

	dirs, _ := ioutil.ReadDir("/home/")
	for _, subDir := range dirs {
		for _, homeFile := range homeFiles {
			subFile := "/home/" + subDir.Name() + homeFile
			info1 := common.Check_file(subFile)
			if info1 {
				suspicious = true
			}

		}
	}
	for _, subFile := range files {

		s, err := os.Stat(subFile)
		if err != nil {
			continue
		}
		if s.IsDir() {
			filepath.Walk(
				subFile, func(path string, info fs.FileInfo, err error) error {

					if info.IsDir() {
						return nil
					} else {
						info1 := common.Check_file(path)
						if info1 {
							suspicious = true
						}
					}
					return err
				},
			)
		} else {
			info1 := common.Check_file(subFile)
			if info1 {
				suspicious = true
			}

		}
	}
	return suspicious
}

func LdPreloadCheck() bool {
	result := checkBackdoor("LD_PRELOAD")
	return result
}
func LdAoutPreloadCheck() bool {
	result := checkBackdoor("LD_AOUT_PRELOAD")
	return result
}
func LdElfPreloadCheck() bool {
	result := checkBackdoor("LD_ELF_PRELOAD")
	return result
}
func LdLibraryPathCheck() bool {
	result := checkBackdoor("LD_LIBRARY_PATH")
	return result
}
func PromptCommandCheck() bool {
	result := checkBackdoor("PROMPT_COMMAND")
	return result
}

func ExportCheck() bool {
	result := false
	tmp := checkBackdoor("PATH")
	tmp1 := checkEnv()
	if tmp {
		result = tmp
	} else {
		result = tmp1
	}
	return result
}

func TcpWrappersCheck() bool {
	result := common.Check_file("/etc/hosts.allow")
	return result
}

func LdSoPreload() bool {
	result := false
	if common.PathExists("/etc/ld.so.preload") {
		fr, _ := os.Open("/etc/ld.so.preload")
		defer fr.Close()
		buf := bufio.NewReader(fr)
		for {
			data, _, c := buf.ReadLine()
			if c == io.EOF {
				break
			}
			line := strings.Replace(string(data), "\n", "", -1)
			if line[0] == '#' {
				continue
			}
			if line[len(line)-3:] == ".so" {
				fmt.Println("[*]File: /etc/ld.so.preload, Found:", line)
				result = true
			} else {
				info := common.CheckShell(line)
				if info {
					fmt.Println("[*]File: /etc/ld.so.preload, Found:", line)
					result = true
				}
			}
		}
	}
	return result
}

func IntedCheck() bool {
	result := false
	if !common.PathExists("/etc/inetd.conf") {
		return false
	}

	fr, _ := os.Open("/etc/inetd.conf")
	defer fr.Close()
	buf := bufio.NewReader(fr)
	for {
		data, _, c := buf.ReadLine()
		if c == io.EOF {
			break
		}
		line := string(data)
		content := common.CheckShell(line)
		if content {
			fmt.Println("[*]File: /etc/inetd.conf, Found:", line)
			result = true
		}
	}

	return result
}

func XinetdCheck() bool {
	result := false
	if !common.PathExists("/etc/xinetd.conf") {
		return false
	}

	dirs, err := ioutil.ReadDir("/etc/xinetd.conf")
	if err != nil {
		return true
	}
	for _, dir := range dirs {
		subFile := "/etc/xinetd.conf" + dir.Name()
		fr, _ := os.Open(subFile)
		defer fr.Close()
		buf := bufio.NewReader(fr)
		for {
			data, _, c := buf.ReadLine()
			if c == io.EOF {
				break
			}
			line := string(data)
			content := common.CheckShell(line)
			if content {
				fmt.Println("[*]File: /etc/xinetd.conf, Found:", line)
				result = true
			}
		}
	}

	return result
}

func StartupCheck() bool {
	result := false
	var suspicious []bool
	init_path := []string{
		"/etc/init.d/", "/etc/rc.d/", "/etc/rc.local", "/usr/local/etc/rc.d",
		"/usr/local/etc/rc.local", "/etc/conf.d/local.start", "/etc/inittab", "/etc/systemd/system",
	}
	for _, path := range init_path {

		if !common.PathExists(path) {
			continue
		}
		filepath.Walk(
			path, func(p string, info fs.FileInfo, err error) error {
				if info.IsDir() {
					return nil
				}
				b := common.Check_file(p)
				if b {
					suspicious = append(suspicious, b)
				}
				return err
			},
		)

	}
	end := len(suspicious)
	if end != 0 {
		result = true
	}
	return result
}

func pam_check() bool {
	result := false

	if common.PathExists("/etc/ssh/sshd_config") {
		fr, _ := os.Open("/etc/ssh/sshd_config")
		defer fr.Close()

		bur := bufio.NewReader(fr)
		for {
			line, _, c := bur.ReadLine()
			if c == io.EOF {
				break
			}
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			if strings.Contains(string(line), "UsePAM") && strings.Contains(string(line), "yes") {
				fmt.Println("[*]File: /etc/ssh/sshd_config, PAM enabled !!!")
				result = true
			}
		}
	}
	return result
}
