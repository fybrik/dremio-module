#!/usr/bin/env bash
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

: ${RELEASE:=main}
: ${TOOLBIN:=./hack/tools/bin}

${TOOLBIN}/yq eval --inplace ".version = \"$RELEASE\"" ./hello-world-read-module/Chart.yaml
${TOOLBIN}/yq eval --inplace ".image.tag = \"$RELEASE\"" ./hello-world-read-module/values.yaml
