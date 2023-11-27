package utils

import (
	"math/big"
	"net"
)

type IntIP struct {
	IP    string
	Intip int64
}

func (i *IntIP) toIntIp() int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(i.IP).To4())
	return ret.Int64()
}

func CheckIpInipconfig(ipList []string, ip string) bool {

	for _, hip := range ipList {
		if hip == ip {
			return true
		}
	}
	return false
}
