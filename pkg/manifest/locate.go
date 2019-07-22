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

package manifest

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/tetratelabs/getenvoy-package/api"
)

// Key is the primary key used to locate Envoy builds in the manifest
type Key struct {
	Flavor                 string
	Version                string
	OperatingSystem        string
	OperatingSystemVersion string
}

func (k *Key) normalize() {
	k.Flavor = strings.ToLower(k.Flavor)
	k.Version = strings.ToLower(k.Version)
	k.OperatingSystem = strings.ToLower(k.OperatingSystem)
	k.OperatingSystemVersion = strings.ToLower(k.OperatingSystemVersion)
}

// Locate returns the location of the binary for the passed parameters from the passed manifest
// The build version is searched for as a prefix of the OperatingSystemVersion.
// If the OperatingSystemVersion is empty it returns the first build listed for that operating system
func Locate(key Key, manifestLocation string) (string, error) {
	if _, err := url.Parse(manifestLocation); err != nil {
		return "", errors.New("only URL manifest locations are supported")
	}
	manifest, err := fetch(manifestLocation)
	if err != nil {
		return "", err
	}

	key.normalize()
	// This is pretty horrible... Not sure there is a nicer way though.
	if manifest.Flavors[key.Flavor] != nil && manifest.Flavors[key.Flavor].Versions[key.Version] != nil {
		for _, os := range manifest.Flavors[key.Flavor].Versions[key.Version].OperatingSystems {
			if strings.EqualFold(os.Name.String(), key.OperatingSystem) {
				if build, found := locateBuildForVersion(key.OperatingSystemVersion, os.Builds); found {
					return build, nil
				}
			}
		}
	}
	return "", fmt.Errorf("unable to find matching build for %v", key)
}

func locateBuildForVersion(want string, builds []*api.Build) (string, bool) {
	if len(builds) == 0 {
		return "", false
	}
	if want == "" {
		return builds[0].DownloadLocationUrl, true
	}
	for _, build := range builds {
		for _, osVersion := range build.OperatingSystemVersions {
			if strings.HasPrefix(want, strings.ToLower(osVersion)) {
				return build.DownloadLocationUrl, true
			}
		}
	}
	return "", false
}
