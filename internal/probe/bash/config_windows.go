//go:build windows
// +build windows

// The bash probe is not supported on Windows.
// This stub ensures the package compiles on Windows even though
// no probe functionality is available. The real implementation
// lives in bash_probe.go (tag: !windows).

package bash

import (
	"github.com/gojue/ecapture/internal/config"
)

// Config is a placeholder on Windows. The bash probe is not
// functional on this platform.
type Config struct {
	*config.BaseConfig
	ErrNo int `json:"errno"`
}

// NewConfig returns a minimal Config for Windows.
func NewConfig() *Config {
	return &Config{
		BaseConfig: config.NewBaseConfig(),
		ErrNo:      128,
	}
}
