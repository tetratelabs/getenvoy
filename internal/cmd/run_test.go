// Copyright 2020 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	rootcmd "github.com/tetratelabs/getenvoy/internal/cmd"
	"github.com/tetratelabs/getenvoy/internal/globals"
	"github.com/tetratelabs/getenvoy/internal/test"
	"github.com/tetratelabs/getenvoy/internal/test/morerequire"
	"github.com/tetratelabs/getenvoy/internal/version"
)

// Runner allows us to not introduce dependency cycles on envoy.Runtime
type runner struct {
	c *cli.App
}

func (r *runner) Run(ctx context.Context, args []string) error {
	return r.c.RunContext(ctx, args)
}

// TestGetEnvoyRun executes envoy then cancels the context. This results in no stdout
func TestGetEnvoyRun(t *testing.T) {
	o, cleanup := setupTest(t)
	defer cleanup()

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	c := rootcmd.NewApp(o)

	args := []string{"getenvoy", "run", "-c", "envoy.yaml"}
	// tee the error stream so we can look for the "starting main dispatch loop" line without consuming it.
	errCopy := new(bytes.Buffer)
	c.ErrWriter = io.MultiWriter(stderr, errCopy)
	err := test.RequireRun(t, nil, &runner{c}, errCopy, args...)

	require.NoError(t, err)
	require.Empty(t, stdout)
	require.Equal(t, "initializing epoch 0\nstarting main dispatch loop\n", stderr.String())
}

func TestGetEnvoyRun_TeesConsoleToLogs(t *testing.T) {
	o, cleanup := setupTest(t)
	defer cleanup()

	c, stdout, stderr := newApp(o)
	o.Out = io.Discard         // stdout/stderr only includes what envoy writes, not our status messages
	o.DontArchiveRunDir = true // we need to read-back the log files
	runWithoutConfig(t, c)

	have, err := ioutil.ReadFile(filepath.Join(o.RunDir, "stdout.log"))
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String()) // sanity check
	require.Equal(t, stdout.String(), string(have))

	have, err = ioutil.ReadFile(filepath.Join(o.RunDir, "stderr.log"))
	require.NoError(t, err)
	require.NotEmpty(t, stderr.String()) // sanity check
	require.Equal(t, stderr.String(), string(have))
}

func TestGetEnvoyRun_ReadsHomeVersionFile(t *testing.T) {
	o, cleanup := setupTest(t)
	o.EnvoyVersion = "" // pretend this is an initial setup
	o.Out = new(bytes.Buffer)
	defer cleanup()

	require.NoError(t, os.WriteFile(filepath.Join(o.HomeDir, "version"), []byte(version.LastKnownEnvoy), 0600))

	c, _, _ := newApp(o)
	runWithoutConfig(t, c)

	// No implicit lookup
	require.NotContains(t, o.Out.(*bytes.Buffer).String(), "looking up latest version\n")
	require.Equal(t, version.LastKnownEnvoy, o.EnvoyVersion)
}

func TestGetEnvoyRun_CreatesHomeVersionFile(t *testing.T) {
	o, cleanup := setupTest(t)
	o.EnvoyVersion = "" // pretend this is an initial setup
	o.Out = new(bytes.Buffer)
	defer cleanup()

	// make sure first run where the home doesn't exist yet, works!
	require.NoError(t, os.RemoveAll(o.HomeDir))

	c, _, _ := newApp(o)
	runWithoutConfig(t, c)

	// We logged the implicit lookup
	require.Contains(t, o.Out.(*bytes.Buffer).String(), "looking up latest version\n")
	require.FileExists(t, filepath.Join(o.HomeDir, "version"))
	require.Equal(t, version.LastKnownEnvoy, o.EnvoyVersion)
}

// runWithoutConfig intentionally has envoy quit. This allows tests to not have to interrupt envoy to proceed.
func runWithoutConfig(t *testing.T, c *cli.App) {
	require.EqualError(t, c.Run([]string{"getenvoy", "run"}), "envoy exited with status: 1")
}

func TestGetEnvoyRun_ValidatesHomeVersion(t *testing.T) {
	o, cleanup := setupTest(t)
	o.Out = new(bytes.Buffer)
	defer cleanup()

	o.EnvoyVersion = ""
	require.NoError(t, os.WriteFile(filepath.Join(o.HomeDir, "version"), []byte("a.a.a"), 0600))

	c, _, _ := newApp(o)
	err := c.Run([]string{"getenvoy", "run"})

	// Verify the command failed with the expected error
	require.EqualError(t, err, fmt.Sprintf(`invalid version in "$GETENVOY_HOME/version": "a.a.a" should look like "%s"`, version.LastKnownEnvoy))
}

// TestGetEnvoyRun_ValidatesWorkingVersion duplicates logic in version_test.go to ensure a non-home version validates.
func TestGetEnvoyRun_ValidatesWorkingVersion(t *testing.T) {
	o, cleanup := setupTest(t)
	o.Out = new(bytes.Buffer)
	o.EnvoyVersion = ""
	defer cleanup()

	revertTempWd := morerequire.RequireChdirIntoTemp(t)
	defer revertTempWd()
	require.NoError(t, os.WriteFile(".envoy-version", []byte("b.b.b"), 0600))

	c, _, _ := newApp(o)
	err := c.Run([]string{"getenvoy", "run"})

	// Verify the command failed with the expected error
	require.EqualError(t, err, fmt.Sprintf(`invalid version in "$PWD/.envoy-version": "b.b.b" should look like "%s"`, version.LastKnownEnvoy))
}

func TestGetEnvoyRun_ErrsWhenVersionsServerDown(t *testing.T) {
	tempDir, deleteTempDir := morerequire.RequireNewTempDir(t)
	defer deleteTempDir()

	o := &globals.GlobalOpts{
		EnvoyVersionsURL: "https://127.0.0.1:9999",
		HomeDir:          tempDir,
		Out:              new(bytes.Buffer),
	}
	c, _, _ := newApp(o)
	err := c.Run([]string{"getenvoy", "run"})

	require.Contains(t, o.Out.(*bytes.Buffer).String(), "looking up latest version\n")
	require.Contains(t, err.Error(), fmt.Sprintf(`couldn't read latest version from %s`, o.EnvoyVersionsURL))
}
