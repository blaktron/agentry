# injection-defense

A reviewer for untrusted documents: it reads a file the way an attacker hopes
an agent will, and reports the injection techniques it finds instead of
following them.

Useful before you hand a scraped page, a PDF, an issue body, or a
vendor-supplied instruction file to an agent that has real tool access.

## Capabilities: none

```yaml
capabilities: {}
```

No network, no filesystem writes, no subprocesses, no secrets. It reads what
you paste and writes a report.

## This agent is also a test

It discusses prompt injection in detail — override framing, exfiltration
directives, tool coercion, concealment techniques — which is exactly the shape
of content a careless scanner flags as malicious.

It is published as a first-party agent on purpose: if Agentry's own pipeline
ever refuses it, our precision has regressed. An agent *about* prompt-injection
defense has to remain publishable, and the same case lives in the scanner test
corpus as a benign lookalike.

## Install

```bash
agentry install agentry/injection-defense --target=claude-skill
```
