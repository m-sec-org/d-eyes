//go:build windows

package memscan

import (
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

var (
	procVirtualAlloc = modkernel32.NewProc("VirtualAlloc")
	procVirtualFree  = modkernel32.NewProc("VirtualFree")
)

const (
	memReserve = 0x2000
	memRelease = 0x8000
)

func virtualAllocRWX(size uintptr) (uintptr, error) {
	addr, _, e1 := procVirtualAlloc.Call(
		0,
		size,
		memCommit|memReserve,
		pageExecuteReadWrite,
	)
	if addr == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, syscall.EINVAL
	}
	return addr, nil
}

func virtualFree(addr uintptr) error {
	r1, _, e1 := procVirtualFree.Call(addr, 0, memRelease)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func TestSmokeWindowsOpenQueryReadRWX(t *testing.T) {
	addr, err := virtualAllocRWX(64 * 1024)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, virtualFree(addr))
	})

	payload := []byte("d-eyes-memscan-smoke")
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
	copy(dst, payload)

	proc, err := Open(os.Getpid())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, proc.Close())
	})

	region, ok, err := proc.api.Query(addr)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, isReadableCommitted(region))
	require.True(t, isRWXProtect(region.Protect))

	readBuf := make([]byte, len(payload))
	n, err := proc.api.Read(addr, readBuf)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, readBuf)
}
