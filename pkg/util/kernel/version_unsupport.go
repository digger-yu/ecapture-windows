//go:build !linux && !windows && !ecap_android
// +build !linux,!windows,!ecap_android

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
// This file is the build stub for platforms that are neither Linux nor
// Android (e.g. Windows, macOS, FreeBSD). eCapture only targets
// Linux/Android and Windows in production, but the Windows implementation
// lives in version_windows.go and so this file should not be compiled on
// Windows. Any other platform gets no-op stubs that satisfy the same
// exported surface as the Linux version.
//
// The naming and build tag here follow the existing convention in this
// package: see kernel_version_unsupport.go which uses the exact same
// "non-Linux, non-Android" tag set.
package kernel

import (
	"fmt"
	"sync"
)

// Version is a numerical representation of a kernel version.
type Version uint32

// String returns a string representing the version in x.x.x format.
func (v Version) String() string {
	return fmt.Sprintf("0.0.0")
}

var (
	hostVersionOnce sync.Once
	hostVersion     Version
	hostVersionErr  error
)

// HostVersion returns the running kernel version of the host. On
// unsupported platforms this returns ErrNonLinux.
func HostVersion() (Version, error) {
	hostVersionOnce.Do(func() {
		hostVersion, hostVersionErr = hostVersionWindows()
	})
	return hostVersion, hostVersionErr
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

// hostVersionWindows is a stub on unsupported platforms. The real Windows
// implementation lives in version_windows.go (gated by the `windows` tag,
// so the stub is not compiled in on Windows itself).
func hostVersionWindows() (Version, error) {
	return 0, ErrNonLinux
}
