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

package http

import (
	"github.com/gin-gonic/gin"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

// createGnutlsConfig - GnuTLS is not supported on Windows
func createGnutlsConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "GnuTLS probe not supported on Windows")
}

// createNsprConfig - NSPR is not supported on Windows
func createNsprConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "NSPR probe not supported on Windows")
}

// createBashConfig - Bash/shell capture is not supported on Windows
func createBashConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "bash probe not supported on Windows")
}

// createMysqlConfig - MySQL probe is not supported on Windows
func createMysqlConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "mysql probe not supported on Windows")
}

// createPostgresConfig - PostgreSQL probe is not supported on Windows
func createPostgresConfig(c *gin.Context) (domain.Configuration, error) {
	return nil, errors.New(errors.ErrCodeConfiguration, "postgres probe not supported on Windows")
}
