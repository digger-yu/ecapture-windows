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

package etw

import (
	"encoding/binary"
	"unicode/utf16"
)

// Microsoft-Windows-Schannel-Events event IDs (manifest in schannel.dll).
// These are handshake / lifecycle metadata events. They do NOT carry TLS
// application plaintext or NSS-style keylog secrets.
const (
	SchannelEventAcquireCredentialHandleStart uint16 = 257
	SchannelEventAcquireCredentialHandleStop  uint16 = 258
	SchannelEventAcceptSecurityContextStart   uint16 = 513
	SchannelEventAcceptSecurityContextStop    uint16 = 514
	SchannelEventMemoryAllocationAllocate     uint16 = 769
	SchannelEventMemoryAllocationFree         uint16 = 770
	SchannelEventCAPI2CallsStart              uint16 = 1025
	SchannelEventCAPI2CallsStop               uint16 = 1026
	SchannelEventPKCryptoStart                uint16 = 1281
	SchannelEventPKCryptoStop                 uint16 = 1282
	SchannelEventPKCryptoInfoStart            uint16 = 1283
	SchannelEventPKCryptoInfoStop             uint16 = 1284
	SchannelEventFreeCredentialHandleStart    uint16 = 1537
	SchannelEventFreeCredentialHandleStop     uint16 = 1538
	SchannelEventDeleteSecurityContextStart   uint16 = 1793
	SchannelEventDeleteSecurityContextStop    uint16 = 1794
)

// Legacy / aspirational IDs kept for unit-test fixtures and older notes.
// They are NOT emitted by Microsoft-Windows-Schannel-Events.
const (
	SchannelEventHandshakeComplete     uint16 = 1
	SchannelEventHandshakeFailure      uint16 = 2
	SchannelEventHandshakeLogExtended  uint16 = 3
	SchannelEventSslLogEvent           uint16 = 4
	SchannelEventAlertReceived         uint16 = 5
	SchannelEventAlertSent             uint16 = 6
	SchannelEventClientAuthKeyExchange uint16 = 10
	SchannelEventServerAuthKeyExchange uint16 = 11
	SchannelEventSessionTicketReceived uint16 = 12
)

// SchannelProperties defines known property names in Schannel ETW events.
const (
	PropProtocol        = "Protocol"
	PropCipherSuite     = "CipherSuite"
	PropKeyLength       = "KeyLength"
	PropHashAlgorithm   = "HashAlgorithm"
	PropClientRandom    = "ClientRandom"
	PropServerRandom    = "ServerRandom"
	PropMasterSecret    = "MasterSecret"
	PropPeerCertIssuer  = "PeerCertificateIssuer"
	PropPeerCertSubject = "PeerCertificateSubject"
	PropTargetName      = "TargetName"
	PropRemoteAddress   = "RemoteAddress"
	PropRemotePort      = "RemotePort"
	PropProcessName     = "ProcessName"
	PropConnectionId    = "ConnectionId"
	PropAlertLevel      = "AlertLevel"
	PropAlertDesc       = "AlertDescription"
	PropEventName       = "EventName"
	PropReturnValue     = "ReturnValue"
	PropContextHandle   = "ContextHandle"
)

// TLS Protocol constants used in Schannel events.
const (
	ProtocolTLS10 uint32 = 0x000000C0
	ProtocolTLS11 uint32 = 0x00000300
	ProtocolTLS12 uint32 = 0x00000C00
	ProtocolTLS13 uint32 = 0x00003000
	ProtocolSSL30 uint32 = 0x00000030
)

// ProtocolName returns a human-readable name for a TLS protocol version.
func ProtocolName(protocol uint32) string {
	switch protocol {
	case ProtocolTLS13:
		return "TLS 1.3"
	case ProtocolTLS12:
		return "TLS 1.2"
	case ProtocolTLS11:
		return "TLS 1.1"
	case ProtocolTLS10:
		return "TLS 1.0"
	case ProtocolSSL30:
		return "SSL 3.0"
	default:
		return "Unknown"
	}
}

// Well-known cipher suite IDs.
const (
	CipherSuiteTLS_AES_128_GCM_SHA256       uint16 = 0x1301
	CipherSuiteTLS_AES_256_GCM_SHA384       uint16 = 0x1302
	CipherSuiteTLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	CipherSuiteTLS_ECDHE_RSA_AES256_GCM     uint16 = 0xC030
	CipherSuiteTLS_ECDHE_RSA_AES128_GCM     uint16 = 0xC02F
)

// SchannelEventName returns a stable name for known Schannel ETW event IDs.
func SchannelEventName(eventID uint16) string {
	switch eventID {
	case SchannelEventAcquireCredentialHandleStart:
		return "AcquireCredentialHandleStart"
	case SchannelEventAcquireCredentialHandleStop:
		return "AcquireCredentialHandleStop"
	case SchannelEventAcceptSecurityContextStart:
		return "AcceptSecurityContextStart"
	case SchannelEventAcceptSecurityContextStop:
		return "AcceptSecurityContextStop"
	case SchannelEventMemoryAllocationAllocate:
		return "MemoryAllocationAllocate"
	case SchannelEventMemoryAllocationFree:
		return "MemoryAllocationFree"
	case SchannelEventCAPI2CallsStart:
		return "CAPI2CallsStart"
	case SchannelEventCAPI2CallsStop:
		return "CAPI2CallsStop"
	case SchannelEventPKCryptoStart:
		return "PKCryptoStart"
	case SchannelEventPKCryptoStop:
		return "PKCryptoStop"
	case SchannelEventPKCryptoInfoStart:
		return "PKCrypto"
	case SchannelEventPKCryptoInfoStop:
		return "PKCryptoStop"
	case SchannelEventFreeCredentialHandleStart:
		return "FreeCredentialHandleStart"
	case SchannelEventFreeCredentialHandleStop:
		return "FreeCredentialHandleStop"
	case SchannelEventDeleteSecurityContextStart:
		return "DeleteSecurityContext"
	case SchannelEventDeleteSecurityContextStop:
		return "DeleteSecurityContextStop"
	case SchannelEventHandshakeComplete:
		return "HandshakeComplete"
	case SchannelEventHandshakeFailure:
		return "HandshakeFailure"
	case SchannelEventHandshakeLogExtended:
		return "HandshakeLogExtended"
	case SchannelEventSslLogEvent:
		return "SslLogEvent"
	case SchannelEventAlertReceived:
		return "AlertReceived"
	case SchannelEventAlertSent:
		return "AlertSent"
	default:
		return "SchannelEvent"
	}
}

// SchannelEvent is the parsed representation of a Schannel ETW event.
// Phase-1 capture is metadata-only: handshake / credential lifecycle fields.
// Plaintext AppData and master secrets are not available from this provider.
type SchannelEvent struct {
	EventId      uint16
	EventName    string
	Protocol     uint32
	CipherSuite  uint16
	KeyLength    uint32
	HashAlg      uint32
	ExchangeAlg  uint32
	ClientRandom []byte
	ServerRandom []byte
	MasterSecret []byte
	TargetName   string
	RemoteAddr   string
	RemotePort   uint16
	AlertLevel   uint8
	AlertDesc    uint8
	ReturnValue  uint32
	Raw          []byte
}

// ParseSchannelEvent parses the UserData of a Schannel ETW event and fills
// Properties on the supplied EventRecord.
func ParseSchannelEvent(event *EventRecord) *SchannelEvent {
	if event == nil {
		return nil
	}
	// Empty UserData is valid for many Schannel-Events (start opcodes).
	parsed := &SchannelEvent{
		EventId:   event.EventId,
		EventName: SchannelEventName(event.EventId),
		Raw:       append([]byte(nil), event.UserData...),
	}

	switch event.EventId {
	case SchannelEventDeleteSecurityContextStart:
		parseDeleteSecurityContext(event.UserData, parsed)
	case SchannelEventAcquireCredentialHandleStop,
		SchannelEventAcceptSecurityContextStop,
		SchannelEventFreeCredentialHandleStop:
		parseReturnValueEvent(event.UserData, parsed)
	case SchannelEventHandshakeComplete:
		parseHandshakeComplete(event.UserData, parsed)
	case SchannelEventHandshakeFailure:
		parseHandshakeFailure(event.UserData, parsed)
	case SchannelEventHandshakeLogExtended:
		parseHandshakeLogExtended(event.UserData, parsed)
	case SchannelEventSslLogEvent:
		parseSslLogEvent(event.UserData, parsed)
	case SchannelEventAlertReceived, SchannelEventAlertSent:
		parseAlertEvent(event.UserData, parsed)
	default:
		// Best-effort: many payloads embed a UTF-16 target / host name.
		if name, ok := extractUTF16String(event.UserData); ok {
			parsed.TargetName = name
		}
	}

	if event.Properties == nil {
		event.Properties = make(map[string]any)
	}
	event.Properties[PropEventName] = parsed.EventName
	if parsed.Protocol != 0 {
		event.Properties[PropProtocol] = parsed.Protocol
	}
	if parsed.CipherSuite != 0 {
		event.Properties[PropCipherSuite] = parsed.CipherSuite
	}
	if parsed.KeyLength != 0 {
		event.Properties[PropKeyLength] = parsed.KeyLength
	}
	if parsed.TargetName != "" {
		event.Properties[PropTargetName] = parsed.TargetName
	}
	if parsed.RemoteAddr != "" {
		event.Properties[PropRemoteAddress] = parsed.RemoteAddr
	}
	if parsed.RemotePort != 0 {
		event.Properties[PropRemotePort] = parsed.RemotePort
	}
	if len(parsed.ClientRandom) > 0 {
		event.Properties[PropClientRandom] = parsed.ClientRandom
	}
	if len(parsed.ServerRandom) > 0 {
		event.Properties[PropServerRandom] = parsed.ServerRandom
	}
	if len(parsed.MasterSecret) > 0 {
		event.Properties[PropMasterSecret] = parsed.MasterSecret
	}
	if parsed.AlertLevel != 0 || parsed.AlertDesc != 0 {
		event.Properties[PropAlertLevel] = parsed.AlertLevel
		event.Properties[PropAlertDesc] = parsed.AlertDesc
	}
	if parsed.ReturnValue != 0 || event.EventId == SchannelEventAcquireCredentialHandleStop ||
		event.EventId == SchannelEventAcceptSecurityContextStop {
		event.Properties[PropReturnValue] = parsed.ReturnValue
	}

	return parsed
}

func parseDeleteSecurityContext(data []byte, ev *SchannelEvent) {
	// Manifest layout (x64): ContextHandle (pointer) + TargetName (counted UTF-16).
	if len(data) < 8 {
		return
	}
	if name, ok := readCountedUTF16(data[8:]); ok {
		ev.TargetName = name
		return
	}
	if name, ok := extractUTF16String(data[8:]); ok {
		ev.TargetName = name
	}
}

func parseReturnValueEvent(data []byte, ev *SchannelEvent) {
	if len(data) >= 4 {
		ev.ReturnValue = binary.LittleEndian.Uint32(data[0:4])
	}
}

func parseHandshakeComplete(data []byte, ev *SchannelEvent) {
	if len(data) < 12 {
		return
	}
	ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
	ev.CipherSuite = binary.LittleEndian.Uint16(data[4:6])
	ev.KeyLength = binary.LittleEndian.Uint32(data[8:12])
	if len(data) >= 16 {
		ev.HashAlg = binary.LittleEndian.Uint32(data[12:16])
	}
}

func parseHandshakeFailure(data []byte, ev *SchannelEvent) {
	if len(data) >= 4 {
		ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
	}
	if len(data) >= 8 {
		ev.AlertLevel = data[4]
		ev.AlertDesc = data[5]
	}
}

func parseHandshakeLogExtended(data []byte, ev *SchannelEvent) {
	if len(data) < 64 {
		return
	}
	ev.ClientRandom = append([]byte(nil), data[0:32]...)
	ev.ServerRandom = append([]byte(nil), data[32:64]...)
	if len(data) > 64 {
		if name, ok := readCountedUTF16(data[64:]); ok {
			ev.TargetName = name
		}
	}
}

func parseSslLogEvent(data []byte, ev *SchannelEvent) {
	if len(data) < 4 {
		return
	}
	ev.Protocol = binary.LittleEndian.Uint32(data[0:4])
}

func parseAlertEvent(data []byte, ev *SchannelEvent) {
	if len(data) >= 2 {
		ev.AlertLevel = data[0]
		ev.AlertDesc = data[1]
	}
}

// readCountedUTF16 reads a uint16 length followed by a UTF-16LE string.
func readCountedUTF16(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	length := binary.LittleEndian.Uint16(data[0:2])
	if length == 0 || int(length)*2+2 > len(data) {
		return "", false
	}
	buf := make([]byte, int(length)*2)
	copy(buf, data[2:2+int(length)*2])
	s, err := decodeUTF16(buf)
	return s, err == nil && s != ""
}

// extractUTF16String finds a printable null-terminated UTF-16LE string in data.
func extractUTF16String(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] == 0 && data[i+1] == 0 {
			continue
		}
		// Require an ASCII-ish first character to avoid false positives.
		if data[i] < 0x20 || data[i] > 0x7e || data[i+1] != 0 {
			continue
		}
		end := i
		for end+1 < len(data) {
			if data[end] == 0 && data[end+1] == 0 {
				break
			}
			end += 2
		}
		if end <= i {
			continue
		}
		s, err := decodeUTF16(data[i:end])
		if err == nil && looksLikeHostOrPath(s) {
			return s, true
		}
	}
	return "", false
}

func looksLikeHostOrPath(s string) bool {
	if len(s) < 3 || len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// decodeUTF16 converts a UTF-16LE byte slice to a Go string.
func decodeUTF16(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", errInvalidUTF16
	}
	chars := make([]uint16, len(data)/2)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(chars)), nil
}

type utf16Error string

func (e utf16Error) Error() string { return string(e) }

const errInvalidUTF16 = utf16Error("invalid utf16 length")
