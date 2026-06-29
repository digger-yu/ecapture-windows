//go:build windows
// +build windows

package hook

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gojue/ecapture/internal/errors"
)

// SSPIPipeName is kept for docs/compat; plaintext now uses a localhost TCP port
// advertised via SSPIPortFile (named pipes proved unreliable across integrity
// levels / CreateNamedPipe flag quirks on some hosts).
const SSPIPipeName = `\\.\pipe\ecapture-schannel`

// SSPIPortFile is written by eCapture with the decimal TCP port for the DLL.
func SSPIPortFile() string {
	return filepath.Join(os.TempDir(), "ecapture_schannel_port.txt")
}

// SSPICaptureMessage is one plaintext buffer captured from SSPI.
type SSPICaptureMessage struct {
	ProcessID uint32
	ThreadID  uint32
	Direction string // "send" (EncryptMessage) or "recv" (DecryptMessage)
	Data      []byte
}

// SSPIMessageHandler consumes plaintext messages from the companion DLL.
type SSPIMessageHandler func(SSPICaptureMessage)

// SSPIPipeServer listens for schannel_hook.dll plaintext frames (TCP).
type SSPIPipeServer struct {
	handler  SSPIMessageHandler
	closed   atomic.Bool
	wg       sync.WaitGroup
	ln       net.Listener
	port     int
	portFile string
}

// NewSSPIPipeServer starts a localhost TCP server and publishes the port.
func NewSSPIPipeServer(handler SSPIMessageHandler) (*SSPIPipeServer, error) {
	if handler == nil {
		return nil, errors.New(errors.ErrCodeConfiguration, "SSPI handler is required")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Wrap(errors.ErrCodeProbeStart, "listen SSPI TCP", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		_ = ln.Close()
		return nil, errors.New(errors.ErrCodeProbeStart, "invalid SSPI listen address")
	}
	portFile := SSPIPortFile()
	if err := os.WriteFile(portFile, []byte(strconv.Itoa(addr.Port)), 0644); err != nil {
		_ = ln.Close()
		return nil, errors.Wrap(errors.ErrCodeProbeStart, "write SSPI port file", err)
	}
	s := &SSPIPipeServer{
		handler:  handler,
		ln:       ln,
		port:     addr.Port,
		portFile: portFile,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Port returns the localhost TCP port the DLL should connect to.
func (s *SSPIPipeServer) Port() int { return s.port }

func (s *SSPIPipeServer) acceptLoop() {
	defer s.wg.Done()
	for !s.closed.Load() {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			s.readConn(conn)
		}(c)
	}
}

func (s *SSPIPipeServer) readConn(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 16)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		pid := binary.LittleEndian.Uint32(hdr[0:4])
		tid := binary.LittleEndian.Uint32(hdr[4:8])
		dirFlag := binary.LittleEndian.Uint32(hdr[8:12])
		length := binary.LittleEndian.Uint32(hdr[12:16])
		if length > 4<<20 {
			return
		}
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(c, payload); err != nil {
				return
			}
		}
		dir := "send"
		if dirFlag == 1 {
			dir = "recv"
		}
		if !s.closed.Load() {
			s.handler(SSPICaptureMessage{
				ProcessID: pid,
				ThreadID:  tid,
				Direction: dir,
				Data:      payload,
			})
		}
	}
}

// Close stops the TCP server and removes the port file.
func (s *SSPIPipeServer) Close() error {
	s.closed.Store(true)
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.portFile != "" {
		_ = os.Remove(s.portFile)
	}
	s.wg.Wait()
	return nil
}
