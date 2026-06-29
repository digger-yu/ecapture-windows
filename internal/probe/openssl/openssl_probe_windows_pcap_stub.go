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

// This file is the stub for the pcap integration of the openssl Windows
// probe. It is compiled when the `pcap` build tag is NOT set so that the
// default cross-build (CGO_ENABLED=0, no Npcap SDK) still compiles.
//
// The real implementation lives in openssl_probe_windows_pcap.go and
// uses github.com/google/gopacket/pcap which is CGO-based and requires
// the Npcap/WinPcap SDK to be available on the build host.
package openssl

import (
	"strings"

	"github.com/gojue/ecapture/internal/errors"
)

// startPcapCapture is a no-op stub. The real implementation (gated by
// the `pcap` build tag) opens an Npcap-based packet capture. In a build
// without pcap support, we surface a clear, actionable error so the user
// knows exactly what to do next.
func (p *Probe) startPcapCapture() error {
	msg := strings.Join([]string{
		"pcap mode is not available in this eCapture binary.",
		"",
		"This binary was built without the `pcap` build tag, so it does",
		"not include the Npcap-based packet capture integration.",
		"",
		"To enable pcap mode, you have two options:",
		"",
		"  1. Download a release with pcap support from",
		"     https://github.com/gojue/ecapture/releases.",
		"",
		"  2. Build from source with the Npcap SDK installed:",
		"       export NPCAP_SDK=/opt/npcap-sdk",
		"       make windows              (amd64)",
		"       make windows-arm64        (arm64)",
		"     pcap is enabled automatically when NPCAP_SDK is set.",
		"     This also requires MinGW-w64 on the build host.",
		"",
		"At runtime, pcap mode also requires Npcap to be installed on the",
		"target Windows host. Get it from https://npcap.com/ and enable",
		"\"WinPcap API-compatible mode\" during installation.",
	}, "\n")
	return errors.New(errors.ErrCodeProbeStart, msg)
}
