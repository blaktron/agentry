// Message templates. Pure functions: subject + text, no side effects.
module.exports = {
  welcome: (vars) => ({
    subject: "Welcome, " + vars.name,
    text: "Thanks for signing up. Your workspace is ready.",
  }),
  receipt: (vars) => ({
    subject: "Receipt " + vars.id,
    text: "Amount: " + vars.amount + "\nThank you.",
  }),
};
