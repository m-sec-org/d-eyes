package assets

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func shouldSkipListen(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EACCES) || errors.Is(opErr.Err, syscall.EPERM) {
			return true
		}
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.EACCES) || errors.Is(sysErr.Err, syscall.EPERM) {
				return true
			}
		}
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EACCES) || errors.Is(sysErr.Err, syscall.EPERM) {
			return true
		}
	}
	return false
}
