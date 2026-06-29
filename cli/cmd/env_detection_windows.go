//go:build windows
// +build windows

// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gojue/ecapture/internal/errors"
)

func detectKernel() error {
	// On Windows, we check the OS version instead of kernel version.
	// eCapture for Windows requires Windows 10 version 1809+ (build 17763+)
	// for ETW Schannel provider support and modern TLS features.
	ver := windows.RtlGetVersion()
	if ver == nil {
		return errors.New(errors.ErrCodeConfiguration, "failed to get Windows version")
	}

	// Windows 10 = MajorVersion 10, MinorVersion 0
	if ver.MajorVersion < 10 {
		return errors.New(errors.ErrCodeConfiguration, "Windows version is not supported. Requires Windows 10 (build 17763) or later").
			WithContext("major", ver.MajorVersion).
			WithContext("minor", ver.MinorVersion)
	}

	// Build 17763 = Windows 10 version 1809 (October 2018 Update)
	if ver.BuildNumber < 17763 {
		return errors.New(errors.ErrCodeConfiguration, "Windows 10 build is not supported. Requires build 17763 (version 1809) or later").
			WithContext("build", ver.BuildNumber)
	}

	return nil
}

func detectBpfCap() error {
	// On Windows, we check for administrator privileges instead of CAP_BPF.
	// ETW sessions and function hooking require elevated privileges.
	//
	// We use CheckTokenMembership directly instead of Token.IsMember because
	// the latter may fail in CI environments (e.g. GitHub Actions) with:
	//   "An attempt has been made to operate on an impersonation token by a
	//    thread that is not currently impersonating a client."
	// CheckTokenMembership with a NULL token handle uses the effective token
	// of the calling thread, which avoids the impersonation token issue.
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return errors.Wrap(errors.ErrCodeConfiguration, "failed to allocate admin SID", err)
	}
	defer windows.FreeSid(sid)

	// CheckTokenMembership(NULL, adminSid, &isMember)
	// NULL token => system uses the effective token of the current thread.
	advapi32 := windows.NewLazyDLL("advapi32.dll")
	procCheckTokenMembership := advapi32.NewProc("CheckTokenMembership")
	var isMember int32
	ret, _, callErr := procCheckTokenMembership.Call(
		0, // NULL token handle
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	if ret == 0 {
		return errors.Wrap(errors.ErrCodeConfiguration, "CheckTokenMembership failed", callErr)
	}

	if isMember == 0 {
		return errors.New(errors.ErrCodeConfiguration, "eCapture on Windows requires administrator privileges. Please run as Administrator")
	}

	// Check architecture
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New(errors.ErrCodeConfiguration, "unsupported CPU architecture. Only amd64 and arm64 are supported").
			WithContext("arch", runtime.GOARCH)
	}

	return nil
}

func detectEnv() error {
	if err := detectKernel(); err != nil {
		return err
	}

	if err := detectBpfCap(); err != nil {
		return err
	}

	return nil
}
