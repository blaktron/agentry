#!/bin/sh
# Checks that the release server is up before the notes go out.
up=$(ssh '-p' 2222 '-o' BatchMode=yes deploy@release.invalid.example uptime)
echo "release server: $up"
