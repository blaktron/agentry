# A seeded page for the never-word self-test

This file exists so scripts/prose/check.sh can prove its own second half.
The sentence below uses a word the core's docs do not use, in a claim
nothing backs, and it sits in no allowlisted span:

Agentry is enterprise-grade, and the gateway prevents an agent from
reaching anything it did not declare, so your data is protected.

Nothing copies this file into the docs tree; it is read only by the
self-test, which seeds it under a copy of docs/ and then removes it.
