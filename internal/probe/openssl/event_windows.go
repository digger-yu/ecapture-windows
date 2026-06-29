//go:build windows
// +build windows

package openssl

import (
	"fmt"
	"unicode/utf8"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/pkg/util/etw"
)

// WindowsTLSEvent represents a TLS-related event captured via ETW Schannel
// metadata or (future) SSPI plaintext hooks.
//
// Phase-1 Schannel ETW events are handshake / credential lifecycle metadata
// only. They do not carry HTTP plaintext or NSS keylog secrets.
type WindowsTLSEvent struct {
	eventType  uint16
	processId  uint32
	threadId   uint32
	timestamp  int64
	properties map[string]any
	userData   []byte
	payload    []byte // optional plaintext from SSPI hook path
	direction  string // "send" / "recv" when payload is set
}

func (e *WindowsTLSEvent) DecodeFromBytes(data []byte) error { e.userData = data; return nil }
func (e *WindowsTLSEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (e *WindowsTLSEvent) Validate() error                   { return nil }
func (e *WindowsTLSEvent) StringHex() string                 { return fmt.Sprintf("%x", e.userData) }
func (e *WindowsTLSEvent) UUID() string {
	return fmt.Sprintf("win-tls-%d-%d-%d", e.processId, e.threadId, e.timestamp)
}

func (e *WindowsTLSEvent) String() string {
	eventName := ""
	if v, ok := e.properties[etw.PropEventName]; ok {
		eventName = fmt.Sprintf("%v", v)
	}
	if eventName == "" {
		eventName = etw.SchannelEventName(e.eventType)
	}

	protocol, cipher, target := "", "", ""
	if v, ok := e.properties[etw.PropProtocol]; ok {
		if proto, ok := v.(uint32); ok {
			protocol = etw.ProtocolName(proto)
		}
	}
	if v, ok := e.properties[etw.PropCipherSuite]; ok {
		cipher = fmt.Sprintf("%v", v)
	}
	if v, ok := e.properties[etw.PropTargetName]; ok {
		target = fmt.Sprintf("%v", v)
	}

	if len(e.payload) > 0 {
		preview := truncatePrintable(e.payload, 120)
		return fmt.Sprintf("PID:%d TID:%d %s %s len=%d data=%q",
			e.processId, e.threadId, eventName, e.direction, len(e.payload), preview)
	}

	return fmt.Sprintf("PID:%d TID:%d %s(%d) Proto:%s Cipher:%s Target:%s",
		e.processId, e.threadId, eventName, e.eventType, protocol, cipher, target)
}

func (e *WindowsTLSEvent) Clone() domain.Event {
	c := &WindowsTLSEvent{
		eventType: e.eventType, processId: e.processId,
		threadId: e.threadId, timestamp: e.timestamp,
		direction: e.direction,
	}
	if e.properties != nil {
		c.properties = make(map[string]any, len(e.properties))
		for k, v := range e.properties {
			c.properties[k] = v
		}
	}
	if e.userData != nil {
		c.userData = make([]byte, len(e.userData))
		copy(c.userData, e.userData)
	}
	if e.payload != nil {
		c.payload = make([]byte, len(e.payload))
		copy(c.payload, e.payload)
	}
	return c
}

func truncatePrintable(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return fmt.Sprintf("%x", b)
}
