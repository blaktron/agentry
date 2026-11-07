# The person's computer: application servers and computer use

A QuickAgent can work an application on the computer a person runs it from,
such as Blender, through that application's MCP server and through computer
use of its windows, without leaving the sandbox. The release declares it in
its contract with one line, `capabilities.desktop`; the run reaches the
person's computer only through Agentry Desktop, which launches the
application's server as the person and answers each call. This page covers
the line, the catalogue of application servers it names, and what the
registry does with both. The manifest's other lines are in
[QuickAgents](quickagents.md#capabilities-the-security-contract).

## The line

```yaml
schemaVersion: "2"
capabilities:
  desktop:
    servers:
      - id: blender                 # an entry of the catalogue below
        tools: [get_scene_info, look, execute_blender_code]   # optional narrowing
    computerUse: app                # app or screen; leave it out for none
```

- **`servers`**: at most four entries of the catalogue of application
  servers, by id, each named once. An entry's `tools` narrows the run to
  some of the tools the catalogue gives it, at least one; without `tools`
  the run has every tool the catalogue gives. A narrowing can only take tools
  away: a tool the catalogue withholds or does not list is refused.
- **`computerUse`**: `app` lets the agent see and act in the windows of the
  applications it uses (or, with no server, one application the person picks
  when the run starts); `screen` gives it the whole display, and the
  consent says so in those words.
- The line needs a server or `computerUse`, and is a v2 field. Manifest rule
  **V19** refuses, naming the path, an id the catalogue does not hold, a
  duplicate id, more than four servers, a tool that is not the entry's or
  that the entry withholds, a duplicate or empty narrowing, a scope other
  than `app` or `screen`, and the line in a v1 manifest.
- The release names an entry, never a command, a path, a port or an address:
  what runs on the person's computer is the catalogue's pinned server, chosen
  from the id alone.

The line is for a run on the person's own computer or on their own runhost.
A run in Agentry never has it. A CLI or desktop that pins a core older than
this field refuses a manifest that carries it, naming the field.

## The catalogue of application servers

Each application a release may use has one entry, released with the core,
built into every client, and served at `GET /api/v1/desktop-apps`. An entry
holds:

| Field | Meaning |
|---|---|
| `id`, `application`, `platforms` | what the line names, the application, and the systems it is offered on |
| `server` | the installed server, pinned by ecosystem (`pypi`, `npm`), name and one exact version, and its source |
| `attachment` | `stdio`, a server Agentry Desktop launches and speaks MCP to over its standard input and output; or `loopback-http`, a server the application runs inside itself at an `http://127.0.0.1` `endpoint` |
| `launch` | for `stdio`, the command line, which holds the pinned version, and its environment |
| `listener` | the loopback port the application listens on for its server, checked before a run starts |
| `tools` | every tool a run may call, each with a class: `read` reads the application's state, `act` changes it or works inside it, `exec` runs code or commands the application interprets and asks the person before each call; `egress: true` marks a tool that reaches the hosts below |
| `withheld` | tools the server offers that no run is given |
| `egress` | the hosts the server or the application's add-on is known to reach from the person's computer |
| `steps` | what the person does once before the first run |

The classes are the catalogue's, never the server's own tool annotations,
which a server sets as it likes. An entry without an exact pin, a launch
that does not hold the pin, or a tool outside the three classes does not
load. A newer release of a server is not vetted until its entry moves to it.

### `blender`

| | |
|---|---|
| Server | PyPI `mcp-for-blender` 2.2.7 ([source](https://github.com/ahujasid/blender-mcp)), MIT |
| Launch | `uvx mcp-for-blender==2.2.7`, with `DISABLE_TELEMETRY=true` (no usage record is sent) and `BLENDER_MCP_SAFE_MODE=1` (the server screens the code it is given for file, process, network and persistence calls: a text screen, not a sandbox) |
| Listener | the Blender add-on's port, 9876 on loopback |
| `exec` | `execute_blender_code`: Python run inside the live Blender session, as the person |
| `act` | `generate_3d`, `import_asset` (both reach outside services) |
| `read` | `search_assets` (reaches outside services), `look`, `get_scene_info`, `get_addon_status` |
| Withheld | `disable_telemetry`, `record_trajectory_feedback`, and the viewer tools the server offers to its own chat apps (`search_mentions`, `open_viewport`, `viewport_latest`, `viewport_capture`, `viewport_pick`) |
| Egress | `api.polyhaven.com`, `cdn.polyhaven.com`, `api.sketchfab.com`, `api.poly.pizza`, `hyperhuman.deemos.com`, `queue.fal.run`, `api.meshy.ai`, `openapi.tripo3d.ai`, `openapi.tripo3d.com`, `ai3d.tencentcloudapi.com`, `hunyuan.tencentcloudapi.com`, `mcp-for-blender.com`, and the download addresses those services return |

Before the first run the person installs [uv](https://docs.astral.sh/uv/),
installs the add-on that comes with the server
(`uvx mcp-for-blender==2.2.7 install-addon`) and enables it in Blender's
preferences, and starts the add-on's server from the BlenderMCP tab of the
3D view's sidebar. The add-on listens on loopback without authentication:
anything on that computer that reaches the port can run Python in Blender.

## What the registry does with the line

- **Consent.** The line is part of the contract, so the install consent shows
  it ("uses Blender on your computer through its MCP server (7 tools, 1 runs
  code inside Blender; it reaches 12 hosts from your computer)", "can see and
  use Blender's windows on your computer"), and an upgrade that adds a
  server, lifts a narrowing or adds a tool to it, declares computer use, or
  moves `app` to `screen` asks again. A removed server, a narrower tool list
  and a smaller scope do not.
- **Policy.** The line is two capability tokens: `desktop` for any desktop
  line, and `computerUse` when it does computer use, so a publication policy
  can block or review either by name in `blockedCapabilities` or
  `requireHumanReview.whenCapabilities`. The catalogue's egress hosts for a
  server the line uses count as `network`, as a declared package server's
  own egress does. Under the platform baseline the line routes nothing to
  review by itself.
- **S6** reads an application server's tools in the instruction, named
  `<id>__<tool>` (`blender__execute_blender_code`) or by the desktop link's
  own server name (`agentry-desktop-blender__look`), against the line: a tool
  of a server the line does not declare, or one its narrowing leaves out, is
  a high `S6/ungranted-tool` finding naming `capabilities.desktop.servers`,
  and `agentry-desktop-computer__<tool>` without computer use names
  `capabilities.desktop.computerUse`.
- **S7** looks the catalogue's pin of every server the line uses up in OSV
  and in its package registry, as it looks up a declared server, and the
  daily sweep checks it again.
- **S9** reports `S9/new-desktop`, medium, for each thing a release newly
  does on the person's computer against the previous release, in the
  consent's words, and the catalogue's egress hosts as new hosts
  (`S9/new-egress`).
- **Search.** `GET /search?capability=desktop` finds the releases that
  declare the line.

## What the runner does with the line

A run that declares the line, from the CLI or the desktop app, binds to
Agentry Desktop before anything starts, and is refused there, exit 11 with
the reason `desktop-refused`, when no Agentry Desktop answers on the computer
(`desktop-unavailable`: "this QuickAgent uses Blender on your computer, which
needs Agentry Desktop running on this computer"), when an application or its
server is not ready (`desktop-not-installed`, with the step to take), when
computer use is not granted (`desktop-not-granted`), and always in a hosted
run (`hosted`). Then the sandbox is built as for any run, with its two routes
unchanged, plus one entry of the gateway's catalog per application server and
one for computer use: the runner image, with no network, run as the person,
held to the catalogue's tools. A relay container of the run's own carries
each tool call of those entries, and nothing else, to Agentry Desktop, which
answers it on the person's computer by the catalogue's class. Under a
sandboxed runtime the entries take `docker.gatewayRuntime` and the relay the
daemon's default, because a socket shared through a volume is a host socket
to gVisor.

The receipt says what reached the person's computer, in these keys:
`desktop.<id>` (the installed server, the tools allowed, the calls by class,
the refusals by reason, and that "the person's computer is outside the
run"), `desktop.computerUse` (the scope, the windows, and what the computer's
own system enforced, as Agentry Desktop states it), `desktop.transport`, and
one line a call in `receipts/desktop-<id>.log`. A call refused while the run
goes on (`desktop-paused`, `desktop-stopped`, `desktop-declined`,
`outside-window`) reaches the agent as that refusal and is counted, never the
run's own reason. The run keeps no screenshot. The containers, the transport
and every key are in [the runner](runner.md#the-persons-computer-capabilitiesdesktop).

## What no run can enforce

An installed server runs on the person's computer with that computer's
network and files. Blender's `execute_blender_code` is Python as the person,
and its asset and generation tools fetch from outside services. Nothing in a
run's sandbox holds any of that: the `exec` class asks the person before
each such call, the launch turns telemetry off and the code screen on, and
the catalogue names the hosts so the consent and the scan can.
