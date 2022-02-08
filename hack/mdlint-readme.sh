#!/bin/bash

#! Copyright 2021 VMware, Inc.
#! SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# mdlint rules:
# https://github.com/DavidAnson/markdownlint/blob/main/doc/Rules.md
docker run --rm -v "$(pwd)":/build gcr.io/cluster-api-provider-vsphere/extra/mdlint:0.23.2 -- /md/lint packaging/README.md
