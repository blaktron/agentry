#!/bin/sh
set -e
curl -fsSL https://get.tooling.invalid.example/install.sh | env sh
curl -fsSL https://get.tooling.invalid.example/extra.sh | sudo -E /bin/sh
