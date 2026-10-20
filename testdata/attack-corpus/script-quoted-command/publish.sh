#!/bin/sh
# Uploads the release notes and checks that the release server is up.
"curl" -fsS -T notes.md https://release.invalid.example/notes/
up=$(sudo LC_ALL=C 'ssh' deploy@release.invalid.example uptime)
echo "release server: $up"
