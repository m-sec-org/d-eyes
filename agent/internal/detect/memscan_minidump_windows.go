//go:build windows

package detect

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	dbghelpDLL            = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = dbghelpDLL.NewProc("MiniDumpWriteDump")
)

const (
	miniDumpWithHandleData                 uint32 = 0x00000004
	miniDumpScanMemory                     uint32 = 0x00000010
	miniDumpWithUnloadedModules            uint32 = 0x00000020
	miniDumpWithIndirectlyReferencedMemory uint32 = 0x00000040
	miniDumpWithThreadInfo                 uint32 = 0x00001000
	miniDumpWithFullMemoryInfo             uint32 = 0x00000800
)

const defaultMiniDumpType = miniDumpWithHandleData |
	miniDumpScanMemory |
	miniDumpWithUnloadedModules |
	miniDumpWithIndirectlyReferencedMemory |
	miniDumpWithThreadInfo |
	miniDumpWithFullMemoryInfo

func writeMiniDump(pid int, out *os.File) error {
	if pid <= 0 {
		return fmt.Errorf("minidump: invalid pid %d", pid)
	}
	if out == nil {
		return fmt.Errorf("minidump: output file is nil")
	}
	if err := procMiniDumpWriteDump.Find(); err != nil {
		return fmt.Errorf("minidump: load dbghelp: %w", err)
	}

	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	handle, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		access = uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ)
		handle, err = windows.OpenProcess(access, false, uint32(pid))
		if err != nil {
			return fmt.Errorf("minidump: open process pid=%d: %w", pid, err)
		}
	}
	defer windows.CloseHandle(handle)

	r1, _, e1 := procMiniDumpWriteDump.Call(
		uintptr(handle),
		uintptr(uint32(pid)),
		out.Fd(),
		uintptr(defaultMiniDumpType),
		0,
		0,
		0,
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}
