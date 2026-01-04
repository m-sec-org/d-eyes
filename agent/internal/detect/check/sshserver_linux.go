package check

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func SshWrapper() bool {
	info, err := os.Stat("/usr/sbin/sshd")
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	if info.IsDir() {
		fmt.Println("/usr/sbin/sshd被篡改,文件非可执行文件")
		return true
	}

	file, err := os.Open("/usr/sbin/sshd")
	if err != nil {
		fmt.Println("/usr/sbin/sshd被篡改,文件非可执行文件")
		return true
	}
	defer file.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		fmt.Println("/usr/sbin/sshd被篡改,文件非可执行文件")
		return true
	}

	isELF := bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'})
	isExecutable := info.Mode()&0o111 != 0
	if !isELF && !isExecutable {
		fmt.Println("/usr/sbin/sshd被篡改,文件非可执行文件")
		return true
	}

	return false
}
