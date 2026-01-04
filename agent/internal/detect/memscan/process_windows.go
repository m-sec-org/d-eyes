//go:build windows

package memscan

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

type Process struct {
	pid    uint32
	handle windows.Handle
	api    processAPI
}

func Open(pid int) (*Process, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("memscan: invalid pid %d", pid)
	}

	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	handle, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		access = uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ)
		handle, err = windows.OpenProcess(access, false, uint32(pid))
		if err != nil {
			return nil, fmt.Errorf("memscan: open process pid=%d: %w", pid, err)
		}
	}

	api := windowsProcessAPI{handle: handle}
	return &Process{
		pid:    uint32(pid),
		handle: handle,
		api:    api,
	}, nil
}

func (p *Process) Close() error {
	if p == nil || p.handle == 0 {
		return nil
	}
	return windows.CloseHandle(p.handle)
}

func (p *Process) Walk(ctx context.Context, opts Options, visit func(Chunk) error) (Stats, error) {
	if p == nil {
		return Stats{}, fmt.Errorf("memscan: process is nil")
	}
	return walk(ctx, p.api, opts, visit)
}

type windowsProcessAPI struct {
	handle windows.Handle
}

func (p windowsProcessAPI) Query(addr uintptr) (Region, bool, error) {
	var mbi memoryBasicInformation
	n, err := virtualQueryEx(p.handle, addr, &mbi)
	if n == 0 {
		if err == windows.ERROR_INVALID_PARAMETER {
			return Region{}, false, nil
		}
		if err == nil {
			return Region{}, false, nil
		}
		return Region{}, false, err
	}

	return Region{
		Base:    mbi.BaseAddress,
		Size:    mbi.RegionSize,
		State:   mbi.State,
		Protect: mbi.Protect,
		Type:    mbi.Type,
	}, true, nil
}

func (p windowsProcessAPI) Read(addr uintptr, buf []byte) (int, error) {
	return readProcessMemory(p.handle, addr, buf)
}
