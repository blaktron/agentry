# Remote runhosts

A remote runhost is a Linux server you own that runs your QuickAgents for
you. The CLI (or the desktop app) sets it up over SSH and then drives it over
SSH: a run on it is the same run the [Runner reference](runner.md) describes,
with your consent and your keys, executed on the server instead of this
computer. Nothing about it goes through Agentry: the registry is not in the
path, no credits pay for its compute, and a run there is never a
[hosted run](hosted-runs.md).

This page describes CLI v0.7.14. A runhost runs the same CLI version as the
computer that drives it (see [Updates](#updates)).

## What it is for

- **Runs that need a machine that stays on**: schedules that run with nobody
  present, and persistent agents that keep running when your laptop is shut.
- **More capacity** than your own computer, on hardware you choose.
- **Your secrets stay yours**: they reach your own server, never Agentry.

## Servers

Debian 12 and 13, Ubuntu 22.04 and 24.04, Fedora 43 and 44, and RHEL,
AlmaLinux and Rocky Linux 9 and 10, on amd64 or arm64, with systemd 249 or
newer. Schedules need systemd 256 or newer (see [The store](#the-store)):
setup's checks say so on an older server, and it runs everything else.

The server needs at least 20 GB of free disk, 2 GB of free memory, and
outbound HTTPS to `ghcr.io` and your registry. An existing Docker Engine is
kept. Another container engine running containers stops setup; podman that is
installed but runs no container, as Fedora and the RHEL family install it, is
left beside Docker Engine and never used.

## Setting one up

```
agentry runhost add lab ssh://admin@lab.example.net --key ~/.ssh/id_ed25519
```

`add` signs in with an **admin sign-in**: root, or an account that can
`sudo`, by a key file, the SSH agent or a password, each named by a file, an
environment variable or a prompt, never by a value on the command line. The
admin sign-in is used for this one call and kept nowhere, on either machine.
The server's host key is checked as a [target host](runner.md)'s is: a key in
your `known_hosts` is accepted, an unknown one is asked about at a terminal,
and a changed one is refused.

Setup first checks the server without changing anything and shows every
finding: the system, its architecture and systemd, a TPM2, free disk and
memory, the container engines and gVisor runtimes already there, the ports
already open, and whether the registries are reachable. An unsupported
server stops there. Then it installs, each step one that can run again:

- **an `agentry` account** with no password and no shell of its own: its login
  shell is the CLI, which runs the runhost's relay and nothing else, and the
  account has linger, so its service runs with nobody signed in;
- **Docker Engine** from Docker's own repository, when the server has none.
  The `agentry` account joins the `docker` group, **which makes it
  root-equivalent on the server**. Your run key can reach only the runhost's
  service (below), never a shell;
- **gVisor** (`runsc`), pinned by version and SHA-512 and registered with the
  Docker daemon as `runsc` and `runsc-uds`. Every container a run starts runs
  under it, the gateway under `runsc-uds`;
- **this CLI's own signed release** for the server's architecture: its
  signature is checked on this computer and again on the server, in the
  `agentry` account's own directory;
- under SELinux, a module that labels the CLI's directories as commands; on a
  RHEL-family kernel that lacks Docker's netfilter module, that kernel's own
  `kernel-modules-extra`;
- **the images runs need**, checked by their signatures;
- **the runhost's service**, a systemd user service of the `agentry` account.

Then it **pairs this computer**: a run key (ed25519) and a sealing key (X25519)
are made here and kept in this computer's keychain. The run key's public half
goes into the account's `authorized_keys` with
`restrict,command="agentry runhost serve --device <id>"`, and the sealing
key's into the service's list of devices. Finally it checks, over the run key
alone, that the service answers and its doctor is green, that the run key is
refused a shell, a terminal, any other command and every forwarding, and that
no network listener was added.

The **owner** of a runhost is the Agentry account this computer is signed in
to at setup, or, set up signed out, its paired devices alone, bound to an
account at the next `pair` made signed in.

## How it is reached

The service listens on an owner-only Unix socket in the `agentry` account's
runtime directory, and on nothing else: **setup opens no network port**. SSH is
the only way in, and only your run key's forced command reaches the service.
Each request is one of its verbs (a job, attaching to one, cancelling,
collecting, status, doctor, version, update, the store, schedules, sign-ins,
agents, unpairing). Setup, pairing, Unsafe Mode and removal are not verbs of
the run key: they take the admin sign-in.

Setup adds no firewall. The service needs nothing open but SSH, so you may
firewall everything else; the runs' own egress is bounded by the egress proxy
and gVisor, exactly as on your computer.

## A run on a runhost

```
agentry run acme/digest --on lab
```

The release is resolved and verified on this computer as for a local run, your
consent is asked here, and the run's secrets, model key, files and intake are
read here. One SSH session carries the job to the service, followed by the
release when the runhost does not already keep it. The service verifies the
release again with its own CLI's keys, keeps it in its store, and runs it
under gVisor in a job directory of its own:

- **Secrets and files are on the server while the run runs.** Secrets are in a
  file only the account can read, deleted when the run ends, on every path; a
  run's files are deleted with its job directory. Neither ever reaches the
  agent's container but as the runner gives it there, as on your computer.
- **The output is sealed** to every paired device's sealing key before it is
  kept, and the plaintext is deleted. It waits, sealed, until a device collects
  it, and at most 7 days. This computer opens it into `./agentry-out/` as a
  local run's.
- **The receipt** says the run happened on the runhost and names its host key.

A run that loses its connection goes on on the runhost: `agentry runhost attach
lab <job>` follows it again, `agentry runhost jobs lab` lists the runhost's
jobs, and `collect` and `cancel` act on one. An interactive session runs there
too (`--mode interactive --on lab`), driven from this terminal.

Claude Code, Codex and Copilot run on a runhost only as their images, under
gVisor: `agentry runhost model lab --sign-in claude|chatgpt|copilot` signs the
runhost in to your plan from this computer's browser, and the sign-in is the
runhost's own. `agentry runhost model lab --provider agentry` gives it a token
that can only pay for model use with your Agentry credits, revoked by `unpair`
and `remove`.

A target host a release reaches is resolved and reached from the runhost, with
this computer's sign-in for it.

## The store

The runhost keeps what it must hold between runs in its store: the releases it
has run, its model sign-ins and credits token, the model key its persistent
agents run on, what each schedule needs to run with nobody present, and its
persistent agents' stored secrets and accounts. **Nothing is written to it
without a consent that names it and the server**, and `agentry runhost store
lab` lists it, never a value.

Every entry is encrypted under the store's key. On systemd 256 and newer that
key is sealed by `systemd-creds` to the server (to its TPM2 where it has one,
to its own credential key otherwise) and to the `agentry` account, and opened
into memory only. **This protects a copied disk or a backup, not a running
server's root**, which can open what the account can. Below systemd 256 the
key is a file the account owns, and the runhost takes no schedule.

## Schedules

```
agentry schedule add acme/digest --on lab --daily 07:00 --zone UTC
```

The schedule is prepared here as a run is, then handed to the runhost with
what its occurrences need: the release, its secrets and model key, its files,
its destinations and target hosts, each named in the consent. The runhost fires
its occurrences itself, with nobody present, and each one's output waits sealed
for the next collection. An OAuth connection the release signs in to is the
runhost's own: you sign the runhost in from this computer's browser, and it
keeps and refreshes that grant itself; this computer's connection is never
handed over. `agentry runhost schedules lab` lists them, and `agentry runhost
store lab --remove schedule:<id>` takes one off with everything it kept. Needs
CLI v0.7.11 or later.

## Persistent agents

```
agentry runhost model lab --provider anthropic --model claude-sonnet-5-5
agentry agent start assistant --on lab
agentry agent chat assistant --on lab
```

The persistent agents run on the runhost under its service, on the model the
runhost keeps (`agentry runhost model … --provider <provider>` keeps that
provider's key in its store). `agentry agent list|show|start|stop|chat|attach|
enable|disable|reset|grant|configure|tasks|secret --on lab` drive them; what an
agent would be given for the first time is agreed to on this computer. A stored
secret, a git host account's token, the Fastmail token and a calendar feed's
address are read here and kept in the runhost's store once you agree; Microsoft
365 signs in by its device code. The service starts again every agent it was
running after it restarts. Agentry Helper runs only in the desktop app. Needs
CLI v0.7.14 or later.

On a runhost the Coding agent's programs run under gVisor as an unprivileged
user that owns only the agent's workspace and home: gVisor has no Landlock,
which holds those writes on a computer. A step that needs root, such as a
system package install, fails there.

## Unsafe Mode

`agentry runhost set lab --unsafe-mode on --user admin` makes every run on the
runhost, from every paired device, an [Unsafe Mode](runner.md) run, still under
gVisor and behind the egress proxy. The setting is kept on the server in a file
only root writes, so only the admin sign-in changes it; runs say it is on.

## Devices

`agentry runhost pair lab ssh://admin@lab.example.net` pairs another of your
computers with the admin sign-in: its own run key and sealing key, and
nothing else. `agentry runhost unpair lab`, over the run key, takes this
computer off and revokes the credits token it made; the last device cannot
leave that way, `remove` is the way out.

## Updates

A runhost runs this computer's exact CLI version, and a run on one of another
version is refused, naming both. After this CLI changes version, its first
runhost command updates every paired runhost over the run key, and `agentry
runhost update` does it on demand. The runhost installs only a CLI release
whose signature verifies against the keys its own CLI carries, for its own
architecture, and no older than the one it runs. It readies the new release's
images first, and restarts its service once its running jobs finish. gVisor
follows the version the CLI pins. What only the admin sign-in can change is
reported as needing attention.

## Removing one

`agentry runhost remove lab --user admin` stops the service, removes the
`agentry` account with everything in its home, takes gVisor's runtimes out of
the Docker daemon, revokes the credits token and ends the sign-ins. Docker
Engine and the images stay unless you pass `--remove-docker` (only when setup
installed it) and `--remove-images`.

## Command reference

| Command | What it does |
| --- | --- |
| `agentry runhost add <name> ssh://[user@]host[:port]` | Sets the server up and pairs this computer, with the admin sign-in (`--key`, `--agent`, `--password-env`, `--password-file`, `--sudo-password-env`, `--sudo-password-file`, `--yes`). |
| `agentry runhost list` | This computer's runhosts: name, address, host key, owner, CLI version. |
| `agentry runhost status <name>` | The runhost's state over the run key. |
| `agentry runhost doctor <name>` | Its engine, gVisor for every container, its images and its service. |
| `agentry runhost update [<name>…]` | Brings runhosts to this CLI's version. |
| `agentry runhost pair <name> ssh://…` / `unpair <name>` | Pairs another computer / takes this one off. |
| `agentry runhost model <name>` | `--sign-in claude\|chatgpt\|copilot`, `--provider agentry`, or `--provider <api provider> [--model] [--api-key-env]` for its persistent agents. |
| `agentry runhost set <name> --unsafe-mode on\|off` | Unsafe Mode, with the admin sign-in. |
| `agentry runhost store <name> [--remove …]` | What its store keeps; removes the credits token, a sign-in or a schedule. |
| `agentry runhost schedules <name> [--run <id>]` | Its schedules and their runs. |
| `agentry runhost jobs <name>`, `attach`, `collect`, `cancel` | Its jobs and their sealed outputs. |
| `agentry runhost remove <name>` | Takes Agentry off the server, with the admin sign-in. |
| `agentry run … --on <name>` | A run, or an interactive session, on the runhost. |
| `agentry schedule add … --on <name>` | A schedule the runhost runs with nobody present (`--check` says what it would keep). |
| `agentry agent … --on <name>` | The persistent agents on the runhost. |
