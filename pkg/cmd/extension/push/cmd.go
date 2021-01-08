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

package push

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tetratelabs/getenvoy/pkg/cmd/extension/common"
	"github.com/tetratelabs/getenvoy/pkg/extension/wasmimage"
	workspaces "github.com/tetratelabs/getenvoy/pkg/extension/workspace"
	"github.com/tetratelabs/getenvoy/pkg/extension/workspace/example/runtime"
	"github.com/tetratelabs/getenvoy/pkg/extension/workspace/toolchain"
)

// cmdOpts represents configuration options of the `push` command.
type cmdOpts struct {
	// toolchain to use to build the *.wasm file.
	toolchain common.ToolchainOpts
	// extension to use to specify the built *.wasm file.
	extension runtime.ExtensionOpts
	// pusher to use to specify options for pusher
	pusher wasmimage.PusherOpts
}

func newCmdOpts() *cmdOpts {
	return &cmdOpts{
		toolchain: common.ToolchainOpts{
			Name: toolchain.Default,
		},
		extension: runtime.ExtensionOpts{},
		pusher:    wasmimage.NewPusherOpts(),
	}
}

func (opts *cmdOpts) GetToolchainName() string {
	return opts.toolchain.Name
}

func (opts *cmdOpts) ApplyTo(interface{}) {}

func (opts *cmdOpts) Validate() error {
	if err := opts.toolchain.Validate(); err != nil {
		return err
	}

	return nil
}

// NewCmd returns a command that pushes the built extension.
func NewCmd() *cobra.Command {
	opts := newCmdOpts()
	cmd := &cobra.Command{
		Use:   "push <image-reference>",
		Short: "Push the built WASM extension to the OCI-compliant registry.",
		Long: `
Push the built WASM extension to the OCI-compliant registry. This command requires to login the target container registry with docker CLI`,
		Example: `
  # Push built WASM extension to the local docker registry.
  getenvoy extension push localhost:5000/test/image-name:tag`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			if len(args) == 0 {
				return errors.New("missing image-reference parameter")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			imageRef := args[0]
			var image *wasmimage.WasmImage
			if opts.extension.WasmFile != "" {
				image, err = wasmimage.NewWasmImage(imageRef, opts.extension.WasmFile)
				if err != nil {
					return err
				}
			} else {
				workspace, err := workspaces.GetCurrentWorkspace()
				if err != nil {
					return err
				}
				toolchain, err := common.LoadToolchain(workspace, opts)
				if err != nil {
					return err
				}
				image, err = toolchain.Package(imageRef)
				if err != nil {
					return err
				}
			}
			pusher, err := wasmimage.NewPusher(opts.pusher.AllowInsecure, opts.pusher.UseHTTP)
			if err != nil {
				return fmt.Errorf("failed to push the wasm image: %w", err)
			}
			desc, err := pusher.Push(image)
			if err != nil {
				return fmt.Errorf("failed to push the wasm image: %w", err)
			}

			fmt.Printf("Pushed %s\n", imageRef)
			fmt.Printf("digest: %s size: %d\n", desc.Digest, desc.Size)

			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&opts.toolchain.Name, "toolchain", opts.toolchain.Name,
		`Name of the toolchain to use, e.g. "default" toolchain that is backed by a Docker build container`)
	cmd.PersistentFlags().BoolVar(&opts.pusher.AllowInsecure, "allow-insecure", opts.pusher.AllowInsecure, `Allow insecure registry`)
	cmd.PersistentFlags().BoolVar(&opts.pusher.UseHTTP, "use-http", opts.pusher.UseHTTP, `Use HTTP for communication with registry`)
	cmd.PersistentFlags().StringVar(&opts.extension.WasmFile, "extension-file", opts.extension.WasmFile,
		`Use a pre-built *.wasm file`)
	cmd.PersistentFlags().StringVar(&opts.extension.Config.Source, "extension-config-file", opts.extension.Config.Source,
		`Use a custom extension config`)
	return cmd
}
