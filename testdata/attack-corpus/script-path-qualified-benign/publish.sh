#!/bin/sh
# Uploads the release notes and checks that the release server is up.
/usr/bin/curl -fsS -T notes.md https://release.invalid.example/notes/
up=`ssh deploy@release.invalid.example uptime`
echo "release server: $up"
