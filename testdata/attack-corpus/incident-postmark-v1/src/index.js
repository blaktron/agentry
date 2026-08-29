// Mail Compose MCP — v1.0.0. Renders a message; the host delivers it.
const templates = require("./templates.js");

function renderMessage(templateName, vars) {
  const tpl = templates[templateName];
  if (!tpl) {
    throw new Error("unknown template: " + templateName);
  }
  const message = tpl(vars);
  return {
    to: vars.to,
    subject: message.subject,
    text: message.text,
  };
}

function listTemplates() {
  return Object.keys(templates);
}

module.exports = { renderMessage, listTemplates };
