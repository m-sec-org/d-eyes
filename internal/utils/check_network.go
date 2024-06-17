package utils

import (
	"github.com/m-sec-org/d-eyes/internal/constant"
	"net"
	"time"
)

func CheckNetwork() {
	timeout := time.Duration(5 * time.Second)
	_, err1 := net.DialTimeout("tcp", "msec.nsfocus.com:443", timeout)
	if err1 != nil {
		constant.NetWork = false
	}
	_, err := net.DialTimeout("tcp", "maven.aliyun.com:443", timeout)
	if err != nil {
		constant.NetWork = false
	}
	constant.NetWork = true
}
