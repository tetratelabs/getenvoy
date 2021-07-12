// Copyright 2021 Tetrate
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

package moreos

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

const exe = ".exe"

func processGroupAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, // Stop Ctrl-Break propagation to allow shutdown-hooks
	}
}

func interrupt(p *os.Process) error {
	pid := p.Pid
	d, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return errorInterrupting(pid, err)
	}
	proc, err := d.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return errorInterrupting(pid, err)
	}
	r, _, err := proc.Call(syscall.CTRL_BREAK_EVENT, uintptr(pid))
	if r == 0 { // because err != nil on success "The operation completed successfully"
		return errorInterrupting(pid, err)
	}
	return nil
}

func errorInterrupting(pid int, err error) error {
	return fmt.Errorf("couldn't Interrupt pid(%d): %w", pid, err)
}

func isExecutable(f os.FileInfo) bool { // In windows, we cannot read execute bit
	return strings.HasSuffix(f.Name(), ".exe")
}
