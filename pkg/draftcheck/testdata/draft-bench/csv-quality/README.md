# csv-column-quality-check

Checks a CSV you add for missing values, duplicate rows and mixed-format columns, and reports the problems per column with line numbers.

Reads the CSV you add from end to end and reports three kinds of problem per column: missing values, duplicate rows, and columns whose values are not all in the same format. You get back report.md: a summary table worst column first, then counts, percentages and the line numbers of every finding. It needs no accounts, no keys and no network, because the file's own bytes are the whole input.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the BriefAgent's page.
