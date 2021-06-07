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

package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/tetratelabs/getenvoy/internal/globals"
)

const siteMarkdownFile = "../../site/usage.md"

// TestUsageMarkdownMatchesCommands is in the "cmd" package because changes here will drift siteMarkdownFile.
func TestUsageMarkdownMatchesCommands(t *testing.T) {
	// Use a custom markdown template
	old := cli.MarkdownDocTemplate
	defer func() { cli.MarkdownDocTemplate = old }()
	cli.MarkdownDocTemplate = `# GetEnvoy CLI Overview
{{ .App.UsageText }}

# Commands

| Name | Usage |
| ---- | ----- |
{{range $index, $cmd := .App.VisibleCommands}}{{if $index}}
{{end}}| {{$cmd.Name}} | {{$cmd.Usage}} |{{end}}
| --version, -v | Print the version of GetEnvoy |

# Environment Variables

| Name | Usage | Default |
| ---- | ----- | ------- |
{{range $index, $option := .App.VisibleFlags}}{{if $index}}
{{end}}| {{index $option.EnvVars 0}} | {{$option.Usage}} | {{$option.DefaultText}} |{{end}}
`
	a := NewApp(&globals.GlobalOpts{})
	want, err := a.ToMarkdown()
	require.NoError(t, err)
	want = strings.ReplaceAll(want, "   ", "") // remove leading indent until urfave/cli#1275

	have, err := os.ReadFile(siteMarkdownFile)
	require.NoError(t, err)
	require.Equal(t, want, string(have))
}
