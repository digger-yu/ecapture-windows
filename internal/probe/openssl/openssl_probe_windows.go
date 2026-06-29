//go:build windows
// +build windows

package openssl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/factory"
	"github.com/gojue/ecapture/internal/logger"
	"github.com/gojue/ecapture/internal/output/writers"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/util/etw"
	"github.com/gojue/ecapture/pkg/util/hook"
	winpcap "github.com/gojue/ecapture/pkg/util/pcap"
)

// Probe implements TLS tracing for Windows using ETW Schannel metadata and
// optional SSPI plaintext hooks (via companion DLL injection).
type Probe struct {
	name      string
	logger    *logger.Logger
	config    *Config
	isRunning atomic.Bool

	etwSession  *etw.Session
	hookManager *hook.HookManager
	pcapCapture *winpcap.Capture
	dispatcher  domain.EventDispatcher
	sspiServer  *hook.SSPIPipeServer
}

func NewProbe() (*Probe, error) {
	return &Probe{name: string(factory.ProbeTypeOpenSSL)}, nil
}

func (p *Probe) Initialize(_ context.Context, cfg domain.Configuration) error {
	if cfg == nil {
		return errors.NewConfigurationError("configuration cannot be nil", nil)
	}
	if err := cfg.Validate(); err != nil {
		return errors.NewConfigurationError("invalid configuration", err)
	}

	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig
	p.logger = base.NewLogger(p.name, p.config.GetDebug())

	p.logger.Info().
		Uint64("pid", p.config.GetPid()).
		Bool("use_schannel", p.config.UseSchannel).
		Bool("hook_openssl", p.config.HookOpenSSL).
		Msg("Probe initialized")

	dispatcher, err := base.InitDispatcher(p.name, cfg)
	if err != nil {
		return err
	}
	p.dispatcher = dispatcher

	if p.config.CaptureMode == handlers.ModeKeylog || p.config.CaptureMode == handlers.ModeKey {
		// Schannel ETW does not expose master secrets. Keylog requires the
		// SSPI/LSASS extraction path (see docs/windows-roadmap.md).
		p.logger.Warn().
			Msg("Schannel ETW cannot export TLS secrets; -m keylog will stay empty until SSPI/LSASS key extraction is available")
		if keylogFile := p.config.GetKeylogFile(); keylogFile != "" {
			fw, err := writers.NewFileWriter(writers.FileWriterConfig{Path: keylogFile, Truncate: true})
			if err != nil {
				p.logger.Warn().Err(err).Msg("Failed to create keylog writer")
			} else {
				klWriter := writers.NewKeylogWriter(fw)
				if err := dispatcher.Register(handlers.NewKeylogHandler(klWriter)); err != nil {
					_ = klWriter.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "register keylog handler", err)
				}
				p.logger.Info().Str("keylog_file", keylogFile).Msg("Keylog handler registered (awaiting SSPI/LSASS secrets)")
			}
		}
	}

	if p.config.CaptureMode == handlers.ModePcap || p.config.CaptureMode == handlers.ModePcapng {
		if pcapFile := p.config.PcapFile; pcapFile != "" {
			fw, err := writers.NewFileWriter(writers.FileWriterConfig{Path: pcapFile, Truncate: true})
			if err != nil {
				p.logger.Warn().Err(err).Msg("Failed to create pcap file writer")
			} else {
				pcapHandler, err := handlers.NewPcapHandler(fw, p.config.Ifname, p.config.PcapFilter, p.logger)
				if err != nil {
					_ = fw.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "create pcap handler", err)
				}
				if err := dispatcher.Register(pcapHandler); err != nil {
					_ = pcapHandler.Close()
					return errors.Wrap(errors.ErrCodeEventDispatch, "register pcap handler", err)
				}
				p.logger.Info().Str("pcap_file", pcapFile).Str("interface", p.config.Ifname).Msg("Pcap handler registered")
			}
		}
	}

	return nil
}

func (p *Probe) Start(_ context.Context) error {
	if p.isRunning.Load() {
		return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeProbeStart, "probe already running"))
	}

	if !p.config.UseSchannel && !p.config.HookOpenSSL {
		return errors.NewProbeStartError(p.name, errors.New(errors.ErrCodeConfiguration,
			"no capture method enabled: set --schannel or --libssl to enable TLS capture"))
	}

	p.isRunning.Store(true)

	if p.config.UseSchannel {
		if err := p.startETWSession(); err != nil {
			_ = p.Stop(context.Background())
			return err
		}
		if err := p.startSSPIHookPath(); err != nil {
			// SSPI hook is optional enhancement for plaintext; keep ETW running.
			p.logger.Warn().Err(err).Msg("SSPI plaintext hook path not started; continuing with Schannel ETW metadata only")
		}
	}

	if p.config.HookOpenSSL {
		p.hookManager = hook.NewHookManager()
		if err := p.installOpenSSLHooks(); err != nil {
			_ = p.Stop(context.Background())
			return errors.NewProbeStartError(p.name, err)
		}
	}

	if p.config.CaptureMode == handlers.ModePcap || p.config.CaptureMode == handlers.ModePcapng {
		if err := p.startPcapCapture(); err != nil {
			_ = p.Stop(context.Background())
			return errors.NewProbeStartError(p.name, err)
		}
	}

	p.logger.Info().
		Str("capture_mode", p.config.CaptureMode).
		Bool("schannel", p.config.UseSchannel).
		Bool("openssl_hook", p.config.HookOpenSSL).
		Msg("Windows TLS probe started (Schannel ETW = handshake metadata; plaintext requires SSPI hook DLL)")
	return nil
}

func (p *Probe) startETWSession() error {
	session, err := etw.NewSession(etw.SessionConfig{
		SessionName: fmt.Sprintf("eCapture-%s-%d", p.name, time.Now().UnixNano()),
		Providers:   []etw.GUID{etw.SchannelProvider},
		Callback:    p.handleETWEvent,
	})
	if err != nil {
		return errors.NewProbeStartError(p.name, err)
	}
	if err := session.Start(); err != nil {
		return errors.NewProbeStartError(p.name, err)
	}
	p.etwSession = session
	p.logger.Info().
		Str("provider", etw.SchannelProvider.String()).
		Str("provider_name", "Microsoft-Windows-Schannel-Events").
		Msg("ETW Schannel session started (metadata only; no AppData plaintext)")
	return nil
}

func (p *Probe) handleETWEvent(event *etw.EventRecord) {
	// Do NOT filter Schannel ETW by --pid. Microsoft-Windows-Schannel-Events
	// often attributes events to PID 8 (System) / LSASS, not the client process.
	// --pid is used only for schannel_hook.dll injection (plaintext path).
	domainEvent := &WindowsTLSEvent{
		eventType:  event.EventId,
		processId:  event.ProcessId,
		threadId:   event.ThreadId,
		timestamp:  event.Timestamp,
		properties: event.Properties,
		userData:   event.UserData,
	}
	if err := p.dispatcher.Dispatch(domainEvent); err != nil {
		p.logger.Warn().Err(err).Msg("Failed to dispatch ETW event")
	}
}

func (p *Probe) startSSPIHookPath() error {
	targetPID := uint32(p.config.GetPid())
	server, err := hook.NewSSPIPipeServer(func(msg hook.SSPICaptureMessage) {
		if targetPID != 0 && msg.ProcessID != targetPID {
			return
		}
		ev := &WindowsTLSEvent{
			eventType: 0,
			processId: msg.ProcessID,
			threadId:  msg.ThreadID,
			timestamp: time.Now().UnixNano(),
			properties: map[string]any{
				etw.PropEventName: "SSPIAppData",
			},
			payload:   msg.Data,
			direction: msg.Direction,
		}
		if err := p.dispatcher.Dispatch(ev); err != nil {
			p.logger.Debug().Err(err).Msg("Failed to dispatch SSPI plaintext event")
		}
	})
	if err != nil {
		return err
	}
	p.sspiServer = server
	p.logger.Info().
		Int("tcp_port", server.Port()).
		Str("port_file", hook.SSPIPortFile()).
		Msg("SSPI plaintext TCP listener started")

	dllPath := p.resolveSchannelHookDLL()
	if dllPath == "" {
		p.logger.Info().
			Msg("schannel_hook.dll not found beside ecapture.exe; ETW metadata only. Build contrib/schannel_hook and place the DLL next to the binary for plaintext capture")
		return nil
	}

	if targetPID == 0 {
		p.logger.Info().
			Str("dll", dllPath).
			Msg("SSPI hook DLL found; pass --pid=<target> to inject into a Schannel process for plaintext capture")
		return nil
	}

	if !hook.IsProcessAlive(targetPID) {
		return errors.New(errors.ErrCodeProbeStart,
			fmt.Sprintf("target process pid=%d not found or not accessible; in the target PowerShell run $PID and pass that value to --pid", targetPID)).
			WithContext("pid", targetPID)
	}

	if err := hook.InjectDLL(targetPID, dllPath); err != nil {
		return errors.Wrap(errors.ErrCodeProbeStart, "inject schannel_hook.dll", err).
			WithContext("pid", targetPID).WithContext("dll", dllPath)
	}
	p.logger.Info().Uint32("pid", targetPID).Str("dll", dllPath).Msg("Injected schannel_hook.dll for SSPI plaintext capture")
	return nil
}

func (p *Probe) resolveSchannelHookDLL() string {
	candidates := []string{
		"schannel_hook.dll",
		filepath.Join("contrib", "schannel_hook", "schannel_hook.dll"),
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append([]string{
			filepath.Join(dir, "schannel_hook.dll"),
			filepath.Join(dir, "contrib", "schannel_hook", "schannel_hook.dll"),
		}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(c)
			if err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

func (p *Probe) installOpenSSLHooks() error {
	dllPath := p.config.OpenSSLDll
	if dllPath == "" {
		return nil
	}

	for _, fn := range []string{"SSL_read", "SSL_write"} {
		fn := fn
		if err := p.hookManager.AddHook(fn, hook.HookConfig{
			Module:   dllPath,
			FuncName: fn,
			Callback: func(addr uintptr, pid uint32, args []uintptr) {
				p.logger.Debug().Str("func", fn).Uint32("pid", pid).Msg("OpenSSL function intercepted (same-process only)")
			},
		}); err != nil {
			p.logger.Info().
				Str("func", fn).
				Err(err).
				Msg("OpenSSL inline hook not applied; use Schannel ETW metadata or schannel_hook.dll injection for capture")
		}
	}
	return nil
}

func (p *Probe) Stop(_ context.Context) error {
	if !p.isRunning.Load() {
		return nil
	}
	p.isRunning.Store(false)

	if p.sspiServer != nil {
		_ = p.sspiServer.Close()
		p.sspiServer = nil
	}
	if p.etwSession != nil {
		if err := p.etwSession.Stop(); err != nil {
			p.logger.Warn().Err(err).Msg("Failed to stop ETW session")
		}
	}
	if p.hookManager != nil {
		_ = p.hookManager.Close()
		p.hookManager = nil
	}
	if p.pcapCapture != nil {
		_ = p.pcapCapture.Stop()
		p.pcapCapture = nil
	}

	p.logger.Info().Msg("Windows TLS probe stopped")
	return nil
}

func (p *Probe) Close() error {
	_ = p.Stop(context.Background())
	p.isRunning.Store(false)
	base.CloseDispatcher(p.dispatcher, p.logger)
	p.logger.Info().Msg("Windows TLS probe closed")
	return nil
}

func (p *Probe) Name() string        { return p.name }
func (p *Probe) IsRunning() bool     { return p.isRunning.Load() }
func (p *Probe) Events() []*ebpf.Map { return nil }
