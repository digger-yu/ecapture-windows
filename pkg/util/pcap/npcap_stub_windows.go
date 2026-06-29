//go:build windows && !pcap
// +build windows,!pcap

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

// Stub build of pkg/util/pcap. Compiled when the `pcap` build tag is NOT
// set, so the default cross-build (CGO_ENABLED=0, no Npcap SDK) still
// compiles. To enable pcap support use `-tags 'windows,pcap'` and install
// the Npcap SDK on the build host.
package pcap

import "errors"

// OnPacket is the type of the per-packet callback in Config. The stub
// declares it as func(any) to avoid pulling gopacket into this build;
// the real implementation in npcap_windows.go declares it as
// func(gopacket.Packet). Because the two files are gated by mutually
// exclusive build tags, only one declaration is ever compiled in.
type OnPacket = func(any)

// Config mirrors the real config; see npcap_windows.go for the real type.
type Config struct {
	IfName   string
	Filter   string
	Snaplen  int
	OnPacket OnPacket
}

// Capture is a placeholder for the Npcap-based packet capture. All
// methods return an error so the application fails fast with a clear
// message rather than triggering CGO link errors.
type Capture struct{}

// NewCapture returns an error because pcap mode was not compiled in.
func NewCapture(Config) (*Capture, error) { return nil, ErrPcapDisabled }

// Start returns an error.
func (*Capture) Start() error { return ErrPcapDisabled }

// Stop is a no-op.
func (*Capture) Stop() error { return nil }

// IsRunning always returns false.
func (*Capture) IsRunning() bool { return false }

// FindInterface returns an empty string.
func FindInterface() string { return "" }

// ErrPcapDisabled is returned from any Capture method when the `pcap`
// build tag is not set. It points the user at the build flag they need.
var ErrPcapDisabled = errors.New(
	"pcap mode is not enabled in this build; rebuild with `-tags pcap` and ensure the Npcap SDK is available",
)
