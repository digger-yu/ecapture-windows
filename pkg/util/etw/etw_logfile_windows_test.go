//go:build windows
// +build windows

package etw

import (
	"testing"
	"unsafe"
)

// These offsets must match EVENT_TRACE_LOGFILEW / TRACE_LOGFILE_HEADER on
// 64-bit Windows. A regression here silently breaks OpenTraceW consumption.
func TestEventTraceLogfileLayout(t *testing.T) {
	var lf eventTraceLogfile

	if off := unsafe.Offsetof(lf.LogFileName); off != 0 {
		t.Errorf("LogFileName offset = %d, want 0", off)
	}
	if off := unsafe.Offsetof(lf.LoggerName); off != 8 {
		t.Errorf("LoggerName offset = %d, want 8", off)
	}
	if off := unsafe.Offsetof(lf.ProcessTraceMode); off != 28 {
		t.Errorf("ProcessTraceMode offset = %d, want 28", off)
	}
	if off := unsafe.Offsetof(lf.CurrentEvent); off != 32 {
		t.Errorf("CurrentEvent offset = %d, want 32", off)
	}
	if off := unsafe.Offsetof(lf.EventCallback); off != 424 {
		t.Errorf("EventCallback offset = %d, want 424", off)
	}
	if off := unsafe.Offsetof(lf.Context); off != 440 {
		t.Errorf("Context offset = %d, want 440", off)
	}
}

func TestTraceLogfileHeaderHasTimezone(t *testing.T) {
	var h traceLogfileHeader
	// TRACE_LOGFILE_HEADER is large because of TIME_ZONE_INFORMATION.
	if unsafe.Sizeof(h) < 280 {
		t.Errorf("traceLogfileHeader size = %d, want >= 280", unsafe.Sizeof(h))
	}
}
