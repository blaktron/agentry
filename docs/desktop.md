# The person's computer: applications and computer use

A QuickAgent can work an application on the computer a person runs it from,
such as Blender, through that application's MCP server and through computer
use of its windows, without leaving the sandbox. The release declares it in
its contract with one line, `capabilities.desktop`, naming each application
by a short id; the run reaches the person's computer only through Agentry
Desktop, which answers each call with the application the person approved
on that computer. This page covers the line, what the registry does with
it, how Agentry Desktop resolves an id, and the presets of its library.
The manifest's other lines are in
[QuickAgents](quickagents.md#capabilities-the-security-contract).

## The line

```yaml
schemaVersion: "2"
capabilities:
  desktop:
    servers:
      - id: blender                 # an application, by its id
        tools: [get_scene_info, look, execute_blender_code]   # optional narrowing
      - id: kdenlive
        use: computer               # its windows only, through computer use
      - choose: true                # an application the person chooses at the start
        use: mcp
    computerUse: app                # app or screen; leave it out for none
```

- **`servers`**: at most four applications. Each is an `id` named once, or
  the one entry with `choose: true`, which asks the person to choose one of
  their applications when the run starts and names no id and no tools. An id
  is lowercase letters and digits in words joined by single hyphens, at most
  40 characters, and never `computer` or `chosen`, which name the desktop
  link's own entries. The registry holds no list of applications: the id is
  resolved on the person's computer, against the applications they approved
  in Agentry Desktop.
- **`use`**: what of the application the run uses: `mcp`, its MCP server;
  `computer`, its windows through computer use; `both`. Left out, it is the
  application's server, and its windows too when the line declares
  `computerUse`. `computer` and `both` need `computerUse`.
- **`tools`** narrows the run to some of the tools of the application's
  server, at least one; without `tools` the run has every tool the server
  lists. A narrowing can only take tools away, and only an entry that uses
  the server has one. Which tools a server lists is known only on the
  person's computer, so a run whose narrowing names a tool the server does
  not list is refused when it starts.
- **`computerUse`**: `app` lets the agent see and act in the windows of the
  applications whose windows it uses (or, when it names none, one
  application the person chooses when the run starts); `screen` gives it the
  whole display, and the consent says so in those words.
- The line needs an application or `computerUse`, and is a v2 field.
  Manifest rule **V19** refuses, naming the path, an id outside the grammar,
  an entry with neither an id nor `choose`, a duplicate id, a second
  chooser, a chooser with an id or tools, more than four applications, a
  `use` other than the three or one that needs `computerUse` without it, a
  narrowing of an application used through its windows only, a tool name
  outside letters, digits, hyphens and underscores, a duplicate or empty
  narrowing, a scope other than `app` or `screen`, and the line in a v1
  manifest.
- The release names an application, never a command, a path, a port or an
  address: what runs on the person's computer is the server the person
  approved for that application.

The line is for a run on the person's own computer or on their own runhost.
A run in Agentry never has it. A CLI or desktop that pins a core older than
this field refuses a manifest that carries it, naming the field, and one
older than `use` and `choose` refuses an entry that carries either.

## On the person's computer: approved applications and the library

The registry holds no list of applications. An id is resolved on the
person's computer by Agentry Desktop, against the applications the person
added to Settings → Your computer, each approved by them for its MCP
server, its windows, both or neither. Nothing is approved when it is
added.

- **An id the person's list has** is that application. A run that uses its
  server needs it approved for its server; a run that uses its windows
  needs computer use on and the application approved for its windows.
  Either missing refuses the run before it starts (`desktop-not-granted`),
  naming the switch.
- **An id the list does not have**, and a `choose: true` entry, are put to
  the person: the run setup shows the applications approved for that use,
  or Agentry Desktop asks in a dialog of its own for a run started from the
  `agentry` command, and the choice is remembered for that QuickAgent. With
  nothing chosen the run is refused (`desktop-not-installed`), naming the
  application to add.
- **What runs** is the server the person's list holds for the application:
  a command Agentry Desktop starts as the person (`stdio`), or an address on
  the computer's loopback the application serves (`loopback-http`). The run
  has every tool that server lists, or the release's narrowing, less the
  tools the person withheld; a narrowed tool the server does not list
  refuses the run, naming it.
- **Each call** is answered by the tool's class on the person's list:
  `read` reads the application's state, `act` changes it or works inside
  it, `exec` runs code or commands the application interprets. An `exec`
  call, and a call of a tool nobody has classed, asks the person first.
  The classes are the person's or the library's, never the server's own tool
  annotations, which a server sets as it likes.
- **Where the set-up came from** is told to the run (from the library, the
  library's changed by the person, or set up by the person), and the
  receipt says it. A machine's policy can keep runs to the library's
  applications as they come (`desktop.allowCustomServers: false`), which
  Unsafe Mode overrides.

**The library** is Agentry Desktop's set of presets: popular applications
whose set-up Agentry knows, which the person adds in one click and then
approves like any other. A preset pins one exact release of the
application's server, classes its tools, names the hosts it is known to
reach and the steps the person takes once, and gives the identifiers its
windows carry. The presets are examples, not a list of what is allowed:
any application with a local MCP server, or with windows, can be added.
Releases name a preset by its id, `blender` or `unreal`, below.

Agentry Desktop 0.7.28 and earlier, and the CLI before 0.7.35, bind only
`blender` and `unreal`.

### The `blender` preset

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

### The `unreal` preset

| | |
|---|---|
| Server | Unreal Engine's own Unreal MCP plugin (`ModelContextProtocol`), which comes with Unreal Engine 5.8 and is Experimental ([Epic's documentation](https://dev.epicgames.com/documentation/en-us/unreal-engine/unreal-mcp-in-unreal-editor)) |
| Attachment | `loopback-http`: the editor serves MCP itself at `http://127.0.0.1:8000/mcp`, which Agentry Desktop connects to; nothing is launched |
| Listener | the editor's port, 8000 on loopback |
| `act` | `call_tool`: calls one tool of the editor's toolsets (scene, actors, material instances, objects, and any toolset the project adds) |
| `read` | `list_toolsets`, `describe_toolset` |
| Egress | none known; a toolset the project adds can do what its author wrote |

Before the first run the person uses Unreal Engine 5.8 or later, enables the
Unreal MCP and All Toolsets plugins in the editor (Edit, Plugins) and restarts
it, and in Editor Preferences, General, Model Context Protocol, keeps Auto
Start Server on, the port 8000 and the path `/mcp`, and leaves Enable Tool
Search on, so the server offers its three tools. The plugin answers on
loopback without authentication: anything on that computer that reaches the
port can drive the open editor.

## What the registry does with the line

- **Consent.** The line is part of the contract, so the install consent shows
  it by id ("uses the application blender on your computer, through its MCP
  server (every tool it lists)", "can see and use the windows of blender on
  your computer"); Agentry Desktop, which resolves the id, adds what it
  knows of the application. An upgrade that adds an application, uses an
  application's server or windows it did not, lifts a narrowing or adds a
  tool to it, declares computer use, or moves `app` to `screen` asks again.
  A removed application, a narrower use or tool list and a smaller scope do
  not.
- **Policy.** The line is two capability tokens: `desktop` for any desktop
  line, and `computerUse` when it does computer use, so a publication policy
  can block or review either by name in `blockedCapabilities` or
  `requireHumanReview.whenCapabilities`. A line that uses any application's
  server also counts as `network`: that server runs on the person's
  computer with their network, and the registry cannot know what it
  reaches. An application used through its windows alone does not. Under
  the platform baseline the line routes nothing to review by itself.
- **S6** reads an application's tools in the instruction, named by the
  desktop link's own server name (`agentry-desktop-blender__look`), or by an
  id the line declares (`blender__execute_blender_code`), against the line: a
  tool of an application the line does not declare, of one it uses through
  its windows only, or one its narrowing leaves out, is a high
  `S6/ungranted-tool` finding naming `capabilities.desktop.servers`, and
  `agentry-desktop-computer__<tool>` without computer use names
  `capabilities.desktop.computerUse`. A bare `<id>__<tool>` for an id the
  line does not declare is read as a declared MCP server's. The tools of an
  application the person chooses are `agentry-desktop-chosen__<tool>`,
  given by an entry with `choose: true` that uses its server.
- **S7** asks no advisory database about the line: which server answers for
  an application is known only on the person's computer. It names each
  application whose server the line uses as not covered (`S7/osv-no-data`,
  medium, "the registry cannot know which, so nothing is looked up and what
  it reaches is not known"), and the daily sweep has nothing of the line to
  check.
- **S9** reports `S9/new-desktop`, medium, for each thing a release newly
  does on the person's computer against the previous release, in the
  consent's words.
- **Search.** `GET /search?capability=desktop` finds the releases that
  declare the line.

## What the runner does with the line

This is what the CLI and Agentry Desktop released so far do, for the
applications they carry, `blender` and `unreal`. A run that declares the
line, from the CLI or the desktop app, binds to
Agentry Desktop before anything starts, and is refused there, exit 11 with
the reason `desktop-refused`, when no Agentry Desktop answers on the computer
(`desktop-unavailable`: "this QuickAgent uses blender on your computer, which
needs Agentry Desktop running on this computer"), when an application is not
on the person's list or its server is not ready (`desktop-not-installed`,
with the step to take), when the person has not approved what the run uses
or computer use is off (`desktop-not-granted`), and always in a hosted run
(`hosted`). Then the sandbox is built as for any run, with its two routes
unchanged, plus one entry of the gateway's catalog per application server and
one for computer use: the runner image, with no network, run as the person,
held to the tools Agentry Desktop bound. A relay container of the run's own
carries each tool call of those entries, and nothing else, to Agentry
Desktop, which answers it on the person's computer by the tool's class on
the person's list. Under a
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
the registry, which cannot know what a person's server reaches, counts the
line as network and says so in the scan.
