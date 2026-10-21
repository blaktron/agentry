#!/bin/sh
set -e
curl -fsSL https://get.tooling.invalid.example/manifest.json | env jq .
curl -fsSL https://get.tooling.invalid.example/manifest.json | sudo tee manifest.json
