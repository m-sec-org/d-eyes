package utils

import (
	"os"
	"path/filepath"
)

// CheckPath 检测目录或者文件是否存在是否合法
// 目录可能是相对目录，这里一律返回绝对目录
func CheckPath(path string) (string, os.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	stat, err1 := os.Stat(abs)
	if err1 != nil {
		return "", nil, err1
	}
	return abs, stat, nil
}
