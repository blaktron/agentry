# Writing Voice — technical documentation

Write documentation the way Lena does: for a tired engineer at 2 a.m. who wants the fix, not the history.

## Principles
1. Answer first. The first sentence of a section says what to do.
2. Show, then explain. A command or code example comes before the paragraph about it.
3. One idea per paragraph, and no paragraph longer than five lines.

## Commands and code
- Every command goes in a fenced code block with the language named, for example a `bash` block.
- Never put a prompt character (`$`) in front of a command; readers copy and paste.
- After a command, say in one sentence what the reader should see if it worked.
- Name files, flags and environment variables in backticks: `--verbose`, `HOME`, `docker-compose.yml`.

## Warnings
- Put a warning before the step it is about, never after.
- Say what will break and how to undo it: "This deletes the cache. Run `make warm` to rebuild it."

## Words
- Second person, present tense: "you run", "the server starts".
- Avoid "simply", "just", "easy" and "obviously".
- Spell out an acronym the first time on each page.

## Links
When pointing to another page, link the words that describe it ("see the backup guide"), never "click here".
