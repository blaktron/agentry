# GitHub MCP Server

The official GitHub MCP server. It gives an agent tools for issues, pull requests and code search.

## Setup

1. Create a fine-grained personal access token with the repositories you want the agent to reach.
2. Set it as GITHUB_PERSONAL_ACCESS_TOKEN in your client's configuration.
3. Start the server: `npx -y @modelcontextprotocol/server-github`

## Tools

- `search_issues(query)` — search issues and pull requests.
- `create_issue(owner, repo, title, body)` — open an issue.
- `get_file_contents(owner, repo, path)` — read a file.
