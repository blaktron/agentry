# Portfolio Reporter

Summarizes a spreadsheet of holdings into a plain-text monthly report.

## What it does

Given a CSV export from your broker, the skill groups positions by asset
class, computes the change since the previous statement, and writes a short
narrative summary you can paste into a note.

## What it does not do

It places no orders and holds no credentials. Nothing leaves your machine: the
skill reads the file you hand it and returns text.

## Configuration

Set the reporting currency and the statement date format in `config.yaml`. The
defaults are USD and ISO 8601.
