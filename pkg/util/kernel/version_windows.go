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

// Package kernel exposes kernel/OS version helpers used by eCapture.
//
// This file is the Windows implementation. It mirrors the type and
// function signatures declared in the Linux version file so the rest of
// the codebase can call kernel.HostVersion() / kernel.ParseVersion()
// without build-tag guards. On Windows, HostVersion() returns the
// operating system build number obtained via RtlGetVersion.
package kernel

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// Version is a numerical representation of an OS version. On Windows it
// carries the build number reported by RtlGetVersion.
type Version uint32

// String returns a string representing the version.
func (v Version) String() string {
	return fmt.Sprintf("Windows Build %d", uint32(v))
}

var (
	hostVersionOnce sync.Once
	hostVersion     Version
	hostVersionErr  error
)

// HostVersion returns the running kernel version of the host. On Windows
// this is the OS build number from RtlGetVersion.
func HostVersion() (Version, error) {
	hostVersionOnce.Do(func() {
		hostVersion, hostVersionErr = hostVersionWindows()
	})
	return hostVersion, hostVersionErr
}

// hostVersionWindows queries the OS for the current Windows build number.
// It is implemented as a separate function so it can be stubbed on other
// platforms (see version_nowindows.go) without duplicating the Version
// type and helper functions.
func hostVersionWindows() (Version, error) {
	ver := windows.RtlGetVersion()
	if ver == nil {
		return 0, ErrNonLinux
	}
	return Version(ver.BuildNumber), nil
}

// ParseVersion parses a string in the format of x.x.x to a Version.
func ParseVersion(s string) Version {
	var a, b, c byte
	_, err := fmt.Sscanf(s, "%d.%d.%d", &a, &b, &c)
	if err != nil {
		return Version(0)
	}
	return VersionCode(a, b, c)
}

// VersionCode returns a Version computed from the individual parts of a x.x.x version.
func VersionCode(major, minor, patch byte) Version {
	return Version((uint32(major) << 16) + (uint32(minor) << 8) + uint32(patch))
}
