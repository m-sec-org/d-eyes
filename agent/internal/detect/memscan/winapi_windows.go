//go:build windows

package memscan

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx    = modkernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

func virtualQueryEx(handle windows.Handle, addr uintptr, mbi *memoryBasicInformation) (uintptr, error) {
	if mbi == nil {
		return 0, syscall.EINVAL
	}
	r1, _, e1 := procVirtualQueryEx.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(mbi)),
		unsafe.Sizeof(*mbi),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, syscall.EINVAL
	}
	return r1, nil
}

func readProcessMemory(handle windows.Handle, addr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var bytesRead uintptr
	r1, _, e1 := procReadProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if r1 == 0 {
		if bytesRead > 0 {
			return int(bytesRead), e1
		}
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, syscall.EFAULT
	}
	return int(bytesRead), nil
}
