# invoice-fields-to-json

Extracts invoice number, date, vendor, line items and totals from the invoice text files you add into one JSON document, flagging bad sums.

Reads the invoice files you add — plain text, CSV, markdown or HTML — and pulls the invoice number, issue date, vendor, line items and totals out of each into one JSON document, returned as invoices/invoice-data.json. Values are only taken from the text: anything absent comes back as null. It also adds the line items up and reports, per invoice, every total that does not match, without changing the numbers.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the BriefAgent's page.
