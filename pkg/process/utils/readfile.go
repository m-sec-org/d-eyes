package utils

import (
	"bufio"
	"os"
	"strings"
)

func ReadLindIp(fileName string) ([]string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewScanner(f)
	var result []string

	for {
		if !buf.Scan() {
			break
		}

		line := buf.Text()
		line = strings.TrimSpace(line)

		result = append(result, line)
	}

	return result, nil
}
