# Set the default goal
.DEFAULT_GOAL := build
MAKEFLAGS += --no-print-directory

DOCKER ?= docker
KIND ?= kind

export KUBECONFIG ?= ${HOME}/.kube/config

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GINKGO=$(GOBIN)/ginkgo

SOURCES := $(shell find . -name '*.go')

IMAGE_TAG := dev
STARBOARD_CLI_IMAGE := khulnasoft/starboard:$(IMAGE_TAG)
STARBOARD_OPERATOR_IMAGE := khulnasoft/starboard-operator:$(IMAGE_TAG)
STARBOARD_SCANNER_KHULNASOFT_IMAGE := khulnasoft/starboard-scanner-khulnasoft:$(IMAGE_TAG)
STARBOARD_OPERATOR_IMAGE_UBI8 := khulnasoft/starboard-operator:$(IMAGE_TAG)-ubi8
STARBOARD_OPERATOR_IMAGE_UBI8_FIPS := khulnasoft/starboard-operator:$(IMAGE_TAG)-ubi8-fips

MKDOCS_IMAGE := khulnasoft/mkdocs-material:starboard
MKDOCS_PORT := 8000

.PHONY: all
all: build

.PHONY: build
build: build-starboard-cli build-starboard-operator build-starboard-scanner-khulnasoft

## Builds the starboard binary
build-starboard-cli: $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/starboard ./cmd/starboard/main.go

## Builds the starboard-operator binary
build-starboard-operator: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-operator ./cmd/starboard-operator/main.go

## Builds the starboard-operator binary
build-starboard-operator-fips: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux GOEXPERIMENT=boringcrypto go build -tags fipsonly -o ./bin/starboard-operator-fips ./cmd/starboard-operator/main.go

## Builds the scanner-khulnasoft binary
build-starboard-scanner-khulnasoft: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-scanner-khulnasoft ./cmd/scanner-khulnasoft/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	@go install github.com/onsi/ginkgo/ginkgo

.PHONY: get-qtc
## Installs quicktemplate compiler
get-qtc:
	@go install github.com/valyala/quicktemplate/qtc

.PHONY: compile-templates
## Converts quicktemplate files (*.qtpl) into Go code
compile-templates: get-qtc
	$(GOBIN)/qtc

.PHONY: test
## Runs both unit and integration tests
test: unit-tests itests-starboard itests-starboard-operator

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: itests-starboard
## Runs integration tests for Starboard CLI with code coverage enabled
itests-starboard: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/khulnasoft/starboard/pkg/cmd,\
	github.com/khulnasoft/starboard/pkg/plugin,\
	github.com/khulnasoft/starboard/pkg/kube,\
	github.com/khulnasoft/starboard/pkg/kubebench,\
	github.com/khulnasoft/starboard/pkg/kubehunter,\
	github.com/khulnasoft/starboard/pkg/plugin/trivy,\
	github.com/khulnasoft/starboard/pkg/plugin/polaris,\
	github.com/khulnasoft/starboard/pkg/plugin/conftest,\
	github.com/khulnasoft/starboard/pkg/configauditreport,\
	github.com/khulnasoft/starboard/pkg/vulnerabilityreport \
	./itest/starboard

.PHONY: itests-starboard-operator
## Runs integration tests for Starboard Operator with code coverage enabled
itests-starboard-operator: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/khulnasoft/starboard/pkg/operator,\
	github.com/khulnasoft/starboard/pkg/operator/predicate,\
	github.com/khulnasoft/starboard/pkg/operator/controller,\
	github.com/khulnasoft/starboard/pkg/plugin,\
	github.com/khulnasoft/starboard/pkg/plugin/trivy,\
	github.com/khulnasoft/starboard/pkg/plugin/polaris,\
	github.com/khulnasoft/starboard/pkg/plugin/conftest,\
	github.com/khulnasoft/starboard/pkg/configauditreport,\
	github.com/khulnasoft/starboard/pkg/vulnerabilityreport,\
	github.com/khulnasoft/starboard/pkg/kubebench \
	./itest/starboard-operator

.PHONY: integration-operator-conftest
integration-operator-conftest: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/khulnasoft/starboard/pkg/operator,\
	github.com/khulnasoft/starboard/pkg/operator/predicate,\
	github.com/khulnasoft/starboard/pkg/operator/controller,\
	github.com/khulnasoft/starboard/pkg/plugin,\
	github.com/khulnasoft/starboard/pkg/plugin/conftest,\
	github.com/khulnasoft/starboard/pkg/configauditreport \
	./itest/starboard-operator/configauditreport/conftest

.PHONY: check-kubeconfig
check-kubeconfig:
ifndef KUBECONFIG
	$(error Environment variable KUBECONFIG is not set)
else
	@echo "KUBECONFIG=${KUBECONFIG}"
endif

## Removes build artifacts
clean:
	@rm -r ./bin 2> /dev/null || true
	@rm -r ./dist 2> /dev/null || true

## Builds Docker images for all binaries
docker-build: \
	docker-build-starboard-cli \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8 \
	docker-build-starboard-scanner-khulnasoft

## Builds Docker image for Starboard CLI
docker-build-starboard-cli: build-starboard-cli
	$(DOCKER) build --no-cache -t $(STARBOARD_CLI_IMAGE) -f build/starboard/Dockerfile bin

## Builds Docker image for Starboard operator
docker-build-starboard-operator: build-starboard-operator
	$(DOCKER) build --no-cache -t $(STARBOARD_OPERATOR_IMAGE) -f build/starboard-operator/Dockerfile bin

## Builds Docker image for Starboard operator ubi8
docker-build-starboard-operator-fips: build-starboard-operator-fips
	$(DOCKER) build --no-cache -f build/starboard-operator/Dockerfile.fips.ubi8 -t $(STARBOARD_OPERATOR_IMAGE_UBI8_FIPS) bin

## Builds Docker image for Starboard operator ubi8
docker-build-starboard-operator-ubi8: build-starboard-operator
	$(DOCKER) build --no-cache -f build/starboard-operator/Dockerfile.ubi8 -t $(STARBOARD_OPERATOR_IMAGE_UBI8) bin

## Builds Docker image for Khulnasoft scanner
docker-build-starboard-scanner-khulnasoft: build-starboard-scanner-khulnasoft
	$(DOCKER) build --no-cache -t $(STARBOARD_SCANNER_KHULNASOFT_IMAGE) -f build/scanner-khulnasoft/Dockerfile bin

kind-load-images: \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8
	$(KIND) load docker-image \
		$(STARBOARD_OPERATOR_IMAGE) \
		$(STARBOARD_OPERATOR_IMAGE_UBI8)

## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	$(DOCKER) build -t $(MKDOCS_IMAGE) -f build/mkdocs-material/Dockerfile bin
	$(DOCKER) run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

.PHONY: \
	clean \
	docker-build \
	docker-build-starboard-cli \
	docker-build-starboard-operator \
	docker-build-starboard-operator-ubi8 \
	docker-build-starboard-scanner-khulnasoft \
	kind-load-images \
	mkdocs-serve
