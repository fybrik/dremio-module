#!/usr/bin/env bash
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

: ${DOCKER_TAG:=main}
: ${TOOLBIN:=./hack/tools/bin}

${TOOLBIN}/yq eval --inplace ".image.tag = \"$DOCKER_TAG\"" ./hello-world-read-module/values.yaml
