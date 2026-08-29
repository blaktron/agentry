# Destructive-Action Review Skill

Security documentation for reviewers assessing agents that hold filesystem or
cloud credentials.

## Background

In July 2025 a malicious pull request added prose to a popular coding
extension that instructed the assistant to reduce the machine to a factory
state. The payload was English, not code, which is why signature scanners
aimed at executables missed it entirely.

## What reviewers should check

Attackers may tell an agent to erase data, and a well-behaved agent must not
comply. Never delete all files in a workspace without an explicit user
request. The uninstaller always asks for confirmation before it removes any
data, and any agent that skips that step should be rejected.

Flag prose that orders deletion of resources, prose that suppresses the
confirmation step, and prose that tells the agent to stay silent about what it
did.
