// Copyright 2019 Tetrate
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

package getenvoy

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/mitchellh/go-homedir"
)

// New creates a new GetEnvoy binary.Runtime with the local file storage set to the home directory
func New() (*Runtime, error) {
	usrDir, err := homedir.Dir()
	local := filepath.Join(usrDir, ".getenvoy")
	return &Runtime{
		local:          local,
		wg:             &sync.WaitGroup{},
		signals:        make(chan os.Signal),
		preStart:       make([]preStartFunc, 0),
		preTermination: make([]preTerminationFunc, 0),
	}, err
}

// Runtime implements the GetEnvoy binary.Runtime
type Runtime struct {
	local    string
	debugDir string

	cmd     *exec.Cmd
	wg      *sync.WaitGroup
	signals chan os.Signal

	preStart       []preStartFunc
	preTermination []preTerminationFunc
}

type preStartFunc func() error
type preTerminationFunc func() error