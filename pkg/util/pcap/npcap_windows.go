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

// Package pcap provides a thin wrapper over github.com/google/gopacket/pcap
// for capturing raw network packets on Windows via Npcap/WinPcap.
//
// This file is the Windows implementation that is only compiled in when the
// `pcap` build tag is set. The build tag is required because gopacket/pcap
// uses CGO and depends on the Npcap/WinPcap SDK headers to be present on
// the build host.
//
// IMPORTANT: This package intentionally does NOT define any domain.Event
// implementations. Event types belong in the probe packages
// (e.g. internal/probe/openssl/event_packet_windows.go) that consume the
// captured packets, so the lower-level capture code stays decoupled from
// the event/handler layer. Callers supply an OnPacket callback that
// receives a parsed gopacket.Packet and is responsible for converting it
// into whatever domain.Event type matches their use case.
package pcap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/gojue/ecapture/internal/logger"
)

// Capture delivers raw network packets from an Npcap/WinPcap device.
//
// Capture is a low-level utility: it does NOT know how to construct
// domain.Event objects. The caller must provide an OnPacket callback that
// receives each gopacket.Packet and is responsible for converting it into
// the appropriate event type (e.g. openssl.PacketEvent).
type Capture struct {
	mu       sync.Mutex
	handle   *pcap.Handle
	ifName   string
	filter   string
	snaplen  int
	running  atomic.Bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	onPacket func(gopacket.Packet)
	logger   *logger.Logger
}

// Config holds configuration for a packet capture device.
//
// OnPacket is the only callback that runs for every captured packet and is
// expected to convert the gopacket.Packet into whatever event type the
// caller wants to dispatch.
type Config struct {
	IfName   string
	Filter   string
	Snaplen  int
	OnPacket func(gopacket.Packet)
	Logger   *logger.Logger
}

// NewCapture creates a new Npcap/WinPcap capture instance.
func NewCapture(cfg Config) (*Capture, error) {
	if cfg.IfName == "" {
		return nil, errors.New("interface name is required")
	}
	if cfg.OnPacket == nil {
		return nil, errors.New("OnPacket callback is required")
	}
	if cfg.Snaplen < 0 {
		return nil, errors.New("snaplen must be non-negative")
	}
	if cfg.Snaplen == 0 {
		cfg.Snaplen = 65535
	}
	return &Capture{
		ifName:   cfg.IfName,
		filter:   cfg.Filter,
		snaplen:  cfg.Snaplen,
		onPacket: cfg.OnPacket,
		logger:   cfg.Logger,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start opens the capture device and begins reading packets.
func (c *Capture) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running.Load() {
		return errors.New("capture already running")
	}

	handle, err := pcap.OpenLive(c.ifName, int32(c.snaplen), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open interface %q: %w", c.ifName, err)
	}

	if c.filter != "" {
		if err := handle.SetBPFFilter(c.filter); err != nil {
			handle.Close()
			return fmt.Errorf("set BPF filter %q: %w", c.filter, err)
		}
	}

	c.handle = handle
	c.running.Store(true)
	c.stopCh = make(chan struct{})
	c.wg.Add(1)
	go c.readLoop()

	if c.logger != nil {
		c.logger.Info().Str("interface", c.ifName).Str("filter", c.filter).Msg("Npcap capture started")
	}
	return nil
}

// Stop closes the capture handle and waits for the read loop to exit.
func (c *Capture) Stop() error {
	c.mu.Lock()
	if !c.running.Load() {
		c.mu.Unlock()
		return nil
	}
	c.running.Store(false)
	close(c.stopCh)
	handle := c.handle
	c.handle = nil
	c.mu.Unlock()

	if handle != nil {
		// Closing the handle unblocks the read loop.
		handle.Close()
	}
	c.wg.Wait()
	return nil
}

// IsRunning returns whether the capture is active.
func (c *Capture) IsRunning() bool { return c.running.Load() }

func (c *Capture) readLoop() {
	defer c.wg.Done()

	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for {
		select {
		case <-c.stopCh:
			return
		case packet, ok := <-src.Packets():
			if !ok {
				return
			}
			c.onPacket(packet)
		}
	}
}

// ExtractConnTuple extracts the L3/L4 connection tuple from a packet, when
// possible. It is provided as a convenience for callers that need to
// populate SrcIP/DstIP/SrcPort/DstPort fields on their event types. If
// either L3 or L4 layer is missing, the corresponding fields are zero.
func ExtractConnTuple(packet gopacket.Packet) (srcIP, dstIP string, srcPort, dstPort uint16) {
	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4 := ip4.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6 := ip6.(*layers.IPv6)
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		srcPort = uint16(u.SrcPort)
		dstPort = uint16(u.DstPort)
	}
	return
}

// FindInterface returns the first active non-loopback interface name, or an
// empty string if none is found.
func FindInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
			return iface.Name
		}
	}
	return ""
}
