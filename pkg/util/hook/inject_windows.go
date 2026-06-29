//go:build windows
// +build windows

package hook

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

const (
	processCreateThread = 0x0002
	processVMOperation  = 0x0008
	processVMWrite      = 0x0020
	processQueryInfo    = 0x0400
	processVMRead       = 0x0010

	memCommitLocal  = 0x1000
	memReserveLocal = 0x2000
	pageReadWrite   = 0x04
)

// InjectDLL loads dllPath into the remote process identified by pid using
// CreateRemoteThread(LoadLibraryW). Requires SeDebugPrivilege / Administrator
// for protected processes. Used to deploy schannel_hook.dll for SSPI plaintext.
func InjectDLL(pid uint32, dllPath string) error {
	if pid == 0 {
		return errors.New(errors.ErrCodeConfiguration, "pid is required for DLL injection")
	}
	abs, err := filepath.Abs(dllPath)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "resolve dll path", err)
	}

	if !IsProcessAlive(pid) {
		return errors.New(errors.ErrCodeProbeStart,
			"target process not found or not accessible (check --pid; use a live process $PID)").
			WithContext("pid", pid)
	}

	access := uint32(processCreateThread | processVMOperation | processVMWrite | processVMRead | processQueryInfo | windows.PROCESS_QUERY_LIMITED_INFORMATION)
	// Prefer full access; fall back if LIMITED-only token quirks reject the combo.
	hProcess, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		hProcess, err = windows.OpenProcess(
			processCreateThread|processVMOperation|processVMWrite|processVMRead|processQueryInfo,
			false, pid)
	}
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "OpenProcess", err).WithContext("pid", pid)
	}
	defer windows.CloseHandle(hProcess)

	pathUTF16, err := windows.UTF16FromString(abs)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "encode dll path", err)
	}
	nbytes := uintptr(len(pathUTF16) * 2)

	remote, err := virtualAllocEx(hProcess, nbytes)
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceAllocation, "VirtualAllocEx", err)
	}
	defer func() { _ = virtualFreeEx(hProcess, remote) }()

	written, err := writeProcessMemory(hProcess, remote, pathUTF16)
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceAllocation, "WriteProcessMemory", err)
	}
	if written != nbytes {
		return errors.New(errors.ErrCodeResourceAllocation, "WriteProcessMemory wrote incomplete path")
	}

	kernel32Handle, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceAllocation, "LoadLibrary kernel32", err)
	}
	defer windows.FreeLibrary(kernel32Handle)

	loadLibraryW, err := windows.GetProcAddress(kernel32Handle, "LoadLibraryW")
	if err != nil {
		return errors.Wrap(errors.ErrCodeResourceAllocation, "GetProcAddress LoadLibraryW", err)
	}

	thread, err := createRemoteThread(hProcess, loadLibraryW, remote)
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "CreateRemoteThread", err)
	}
	defer windows.CloseHandle(thread)

	_, err = windows.WaitForSingleObject(thread, 15000)
	if err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "WaitForSingleObject", err)
	}
	return nil
}

func virtualAllocEx(process windows.Handle, size uintptr) (uintptr, error) {
	proc := kernel32.NewProc("VirtualAllocEx")
	addr, _, err := proc.Call(
		uintptr(process),
		0,
		size,
		memCommitLocal|memReserveLocal,
		pageReadWrite,
	)
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

func virtualFreeEx(process windows.Handle, addr uintptr) error {
	proc := kernel32.NewProc("VirtualFreeEx")
	ret, _, err := proc.Call(uintptr(process), addr, 0, windows.MEM_RELEASE)
	if ret == 0 {
		return err
	}
	return nil
}

func writeProcessMemory(process windows.Handle, addr uintptr, data []uint16) (uintptr, error) {
	proc := kernel32.NewProc("WriteProcessMemory")
	var written uintptr
	ret, _, err := proc.Call(
		uintptr(process),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)*2),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return 0, err
	}
	return written, nil
}

func createRemoteThread(process windows.Handle, start, param uintptr) (windows.Handle, error) {
	proc := kernel32.NewProc("CreateRemoteThread")
	h, _, err := proc.Call(
		uintptr(process),
		0,
		0,
		start,
		param,
		0,
		0,
	)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

// EnumProcessIDs returns the list of running process IDs (best-effort).
func EnumProcessIDs() ([]uint32, error) {
	buf := make([]uint32, 4096)
	var needed uint32
	err := windows.EnumProcesses(buf, &needed)
	if err != nil {
		return nil, err
	}
	n := int(needed / 4)
	if n > len(buf) {
		n = len(buf)
	}
	out := make([]uint32, n)
	copy(out, buf[:n])
	return out, nil
}

// IsProcessAlive reports whether OpenProcess succeeds for pid.
func IsProcessAlive(pid uint32) bool {
	h, err := windows.OpenProcess(processQueryInfo, false, pid)
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}
