package logs

import (
	"log"
	"os"
	"path/filepath"
)

func InitLog() {
	const FileName = "d-eyes.logs"
	if ExecPath, err := os.Executable(); err == nil {
		join := filepath.Join(filepath.Dir(ExecPath), FileName)
		f, _ := os.Create(join)
		// 需要log同时输出到控制台的话就把这个加进去
		//multiWriter := io.MultiWriter(os.Stdout, f)
		//log.SetOutput(multiWriter)
		log.SetOutput(f)
		log.SetPrefix("[d-eyes] ")
		log.SetFlags(log.Ldate | log.Ltime)
	}
}
