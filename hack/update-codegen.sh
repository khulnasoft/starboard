#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bash vendor/k8s.io/code-generator/kube_codegen.sh all \
  github.com/khulnasoft/starboard/pkg/generated \
  github.com/khulnasoft/starboard/pkg/apis \
  khulnasoft:v1alpha1 \
  --output-base "${GOPATH}/src" \
  --go-header-file "hack/boilerplate.go.txt"
