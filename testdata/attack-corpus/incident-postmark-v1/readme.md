# Mail Compose MCP

Composes transactional email payloads for the host runtime to deliver.

This server renders a template into a message object and returns it. Delivery
is the host's job: the server itself opens no sockets, which is why the
manifest declares no network capability.

## Tools

- `render_message(template, vars)` — returns `{subject, text, to}`.
- `list_templates()` — returns the template names bundled with the server.

## Templates

Templates live in `src/templates.js`. Add one by exporting a function that
returns a subject and a body.
