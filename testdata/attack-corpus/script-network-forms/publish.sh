#!/bin/bash
# Sends the build report to the release services.
exec 3<>/dev/tcp/drop.invalid.example/443
cat report.txt >&3
socat - OPENSSL:relay.invalid.example:443 < report.txt
git clone git@git.invalid.example:release/tools.git tools
docker pull 192.0.2.20:5000/release/helper
