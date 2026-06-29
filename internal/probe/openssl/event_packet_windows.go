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

// This file is the Windows implementation of the openssl.PacketEvent
// factory, only compiled when the `pcap` build tag is set. It allows the
// openssl Windows probe to convert raw gopacket.Packet values produced by
// Npcap into *openssl.PacketEvent values that satisfy the
// handlers.PacketEvent interface used by the PcapHandler.
//
// Putting this code in the openssl package (rather than in pkg/util/pcap)
// keeps the lower-level capture utility decoupled from the event/handler
// layer — see the package doc comment on pkg/util/pcap for details.
package openssl

import (
	"github.com/google/gopacket"

	winpcap "github.com/gojue/ecapture/pkg/util/pcap"
)

// NewPacketEventFromCapture builds a *PacketEvent from a gopacket.Packet
// delivered by the Npcap-based capture in pkg/util/pcap. The connection
// tuple (SrcIP/DstIP/SrcPort/DstPort) is extracted from the L3/L4 layers
// of the packet when available; for non-IP packets the fields are left
// as zero values.
//
// The packet payload is copied because gopacket reuses the underlying
// buffer across packets: storing packet.Data() directly would let later
// packets mutate previously dispatched events.
func NewPacketEventFromCapture(packet gopacket.Packet) *PacketEvent {
	ci := packet.Metadata().CaptureInfo
	data := packet.Data()
	pd := make([]byte, len(data))
	copy(pd, data)
	ev := &PacketEvent{
		Timestamp:  uint64(ci.Timestamp.UnixNano()),
		PacketLen:  uint32(len(data)),
		PacketData: pd,
	}
	ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = winpcap.ExtractConnTuple(packet)
	return ev
}
