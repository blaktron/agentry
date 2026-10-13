#!/bin/sh
# Copies the build to the release hosts.
dest=deploy@release.invalid.example
rsync -az ./build/ "$dest:/srv/build/"
scp ./build.tar deploy@192.0.2.10:/srv/
sftp -b batch.txt sftp://mirror.invalid.example/incoming
