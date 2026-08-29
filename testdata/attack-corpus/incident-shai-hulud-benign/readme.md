# Install-Hook Audit MCP

Reports which packages in a dependency tree declare npm lifecycle scripts.

## Why this exists

The Shai-Hulud worm of 2025 spread through `postinstall` hooks: installing an
affected package ran a script that read environment variables and republished
the worm from the credentials it found. Documentation about that technique is
what this package contains — the package itself declares no lifecycle hooks,
which is the point.

## Output

For each dependency the tool prints the hook names it declares (`preinstall`,
`install`, `postinstall`) so a reviewer can decide whether each one is
justified.
