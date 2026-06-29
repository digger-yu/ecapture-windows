//go:build windows && pcap
// +build windows,pcap

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

// pcap-mode integration of the openssl Windows probe. Compiled only when
// both `windows` and `pcap` build tags are set; the default cross-build
// (CGO_ENABLED=0, no Npcap SDK) uses the stub in
// openssl_probe_windows_pcap_stub.go instead.
package openssl

import (
	"os"

	"github.com/google/gopacket"

	"github.com/gojue/ecapture/internal/errors"
	winpcap "github.com/gojue/ecapture/pkg/util/pcap"
)

// Common Npcap runtime DLL locations. Used by checkNpcapRuntime to give
// a clear error when Npcap is not installed.
var npcapDLLPaths = [...]string{
	`C:\Windows\System32\Npcap\wpcap.dll`,
	`C:\Windows\System32\wpcap.dll`,
	`C:\Windows\SysWOW64\Npcap\wpcap.dll`,
	`C:\Windows\SysWOW64\wpcap.dll`,
}

// checkNpcapRuntime returns an error if none of the well-known Npcap
// DLL paths exist on the system.
func checkNpcapRuntime() error {
	for _, p := range npcapDLLPaths {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	return errors.New(errors.ErrCodeProbeStart,
		"Npcap runtime was not detected. Install Npcap from https://npcap.com/ "+
			"and enable \"WinPcap API-compatible mode\" during installation.")
}

// startPcapCapture opens the Npcap capture device. Caller has already
// validated CaptureMode is pcap/pcapng.
func (p *Probe) startPcapCapture() error {
	if err := checkNpcapRuntime(); err != nil {
		return err
	}
	cap, err := winpcap.NewCapture(winpcap.Config{
		IfName:   p.config.Ifname,
		Filter:   p.config.PcapFilter,
		OnPacket: p.handlePcapPacket,
		Logger:   p.logger,
	})
	if err != nil {
		return err
	}
	if err := cap.Start(); err != nil {
		return err
	}
	p.pcapCapture = cap
	p.logger.Info().Str("interface", p.config.Ifname).Msg("Npcap capture started")
	return nil
}

// handlePcapPacket is the OnPacket callback: convert + dispatch.
func (p *Probe) handlePcapPacket(packet gopacket.Packet) {
	if err := p.dispatcher.Dispatch(NewPacketEventFromCapture(packet)); err != nil {
		p.logger.Warn().Err(err).Msg("Failed to dispatch pcap packet event")
	}
}
