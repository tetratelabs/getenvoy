# Copyright 2019 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ENVOY = standard:1.11.1
HUB ?= docker.io/getenvoy
TAG ?= dev

BUILD_DIR ?= build
BIN_DIR ?= $(BUILD_DIR)/bin
COVERAGE_DIR ?= $(BUILD_DIR)/coverage
COVERAGE_PROFILE := $(COVERAGE_DIR)/coverage.out
COVERAGE_REPORT := $(COVERAGE_DIR)/coverage.html

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

GO_LD_FLAGS := -ldflags="-s -w -X github.com/tetratelabs/getenvoy/pkg/version.version=$(TAG)"

TEST_PKG_LIST ?= ./pkg/...
GO_TEST_OPTS ?=
GO_TEST_EXTRA_OPTS ?=

# TODO(yskopets): include all packages into test run once blocking issues have been resolved, including
# * https://github.com/tetratelabs/getenvoy/issues/87 `go test -race` fails
# * https://github.com/tetratelabs/getenvoy/issues/88 `go test ./...` fails on Mac
# * https://github.com/tetratelabs/getenvoy/issues/89 `go test github.com/tetratelabs/getenvoy/pkg/binary/envoy/controlplane` removes `/tmp` dir
COVERAGE_PKG_LIST ?= $(shell go list ./pkg/... | grep -v -e github.com/tetratelabs/getenvoy/pkg/binary/envoy/controlplane -e github.com/tetratelabs/getenvoy/pkg/binary/envoy/debug)
GO_COVERAGE_OPTS ?= -covermode=atomic -coverpkg=./...
GO_COVERAGE_EXTRA_OPTS ?=

E2E_OPTS ?= -ginkgo.v
E2E_EXTRA_OPTS ?=

GOOSES := linux darwin
GOARCHS := amd64
BINARIES:= getenvoy e2e

GETENVOY_OUT_PATH = $(BIN_DIR)/$(1)/$(2)/getenvoy

define GEN_GETENVOY_BUILD_TARGET
.PHONY: $(call GETENVOY_OUT_PATH,$(1),$(2))
$(call GETENVOY_OUT_PATH,$(1),$(2)): generate
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build $(GO_LD_FLAGS) -o $(call GETENVOY_OUT_PATH,$(1),$(2)) ./cmd/getenvoy/main.go
endef
$(foreach os,$(GOOSES),$(foreach arch,$(GOARCHS),$(eval $(call GEN_GETENVOY_BUILD_TARGET,$(os),$(arch)))))

E2E_OUT_PATH = $(BIN_DIR)/$(1)/$(2)/e2e

define GEN_E2E_BUILD_TARGET
.PHONY: $(call E2E_OUT_PATH,$(1),$(2))
$(call E2E_OUT_PATH,$(1),$(2)):
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go test -c -o $(call E2E_OUT_PATH,$(1),$(2)) ./test/e2e
endef
$(foreach os,$(GOOSES),$(foreach arch,$(GOARCHS),$(eval $(call GEN_E2E_BUILD_TARGET,$(os),$(arch)))))

.PHONY: init
init: generate

.PHONY: deps
deps:
	go mod download

.PHONY: generate
generate: deps
	go generate ./pkg/...

.PHONY: build
build: $(call GETENVOY_OUT_PATH,$(GOOS),$(GOARCH))

.PHONY: docker
docker: $(call GETENVOY_OUT_PATH,linux,amd64)
	docker build -t $(HUB)/getenvoy:$(TAG) --build-arg reference=$(ENVOY) .

.PHONY: release.dryrun
release.dryrun:
	goreleaser release --skip-publish --snapshot --rm-dist

.PHONY: test
test:
	go test $(GO_TEST_OPTS) $(GO_TEST_EXTRA_OPTS) $(TEST_PKG_LIST)

.PHONY: e2e
e2e: $(call GETENVOY_OUT_PATH,$(GOOS),$(GOARCH)) $(call E2E_OUT_PATH,$(GOOS),$(GOARCH))
	E2E_GETENVOY_BINARY=$(PWD)/$(call GETENVOY_OUT_PATH,$(GOOS),$(GOARCH)) $(call E2E_OUT_PATH,$(GOOS),$(GOARCH)) $(GO_TEST_OPTS) $(GO_TEST_EXTRA_OPTS) $(E2E_OPTS) $(E2E_EXTRA_OPTS)

.PHONY: bin
bin: $(foreach binary,$(BINARIES), bin/$(binary))

.PHONY: bin/getenvoy
bin/getenvoy: $(foreach os,$(GOOSES),$(foreach arch,$(GOARCHS), $(call GETENVOY_OUT_PATH,$(os),$(arch))))

.PHONY: bin/e2e
bin/e2e: $(foreach os,$(GOOSES),$(foreach arch,$(GOARCHS), $(call E2E_OUT_PATH,$(os),$(arch))))

.PHONY: coverage
coverage:
	mkdir -p "$(shell dirname "$(COVERAGE_PROFILE)")"
	go test $(GO_COVERAGE_OPTS) $(GO_COVERAGE_EXTRA_OPTS) -coverprofile="$(COVERAGE_PROFILE)" $(COVERAGE_PKG_LIST)
	go tool cover -html="$(COVERAGE_PROFILE)" -o "$(COVERAGE_REPORT)"

.PHONY: builders
builders: builder.rust

.PHONY: builder.rust
builder.rust:
	docker build -t tetratelabs/getenvoy-extension-rust-builder:$(TAG) images/extension-builders/rust
