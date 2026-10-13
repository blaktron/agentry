#!/bin/sh
# Copies the built site to the release server and restarts it.
# Questions: ops@alerts.example.org
rsync -az ./site/ deploy@release.invalid.example:/srv/site/
ssh -p 2222 deploy@release.invalid.example 'systemctl restart site'
