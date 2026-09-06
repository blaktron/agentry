# Your account

Accounts on an Agentry registry are held by its **directory service** — a
dedicated identity provider that ships with the stack — rather than by the
registry itself. Passwords, sign-up, recovery, and multi-factor live there;
the registry keeps what it must own: your sessions, your tokens, and every
authorization decision.

## Creating an account

**Sign in → "Need an account? Sign up."** The form asks for a username
(lowercase letters and digits — it becomes your registry handle), a display
name, an email address, and a password (12 characters minimum, checked for
strength, not just shape). Sign-up is guarded by a CAPTCHA and a per-network
rate limit.

Your account is created **inactive** and stays that way until you click the
confirmation link mailed to you (it expires after 30 minutes). That is not
ceremony: the registry links identities to accounts by *verified* email, so
nothing you do — including signing in — works before the address is
confirmed. The link works on **any device** — sign up on your desktop, open
the mail on your phone, and you end up signed in on the phone.

## Signing in and out

**Sign in** goes straight to the directory service and returns you to the
page you started from — you see its login form and nothing else of it;
there is no directory "app panel" to land on, and the directory's own
address sends a browser back to the site. **Sign out** ends both sessions
— the registry's and the directory's — and returns you to the site, so
signing out actually signs you out without a second login screen.

Forgot your password? **"Forgot username or password?"** on the sign-in
page mails a reset link. The form gives the same answer whether or not the
address has an account, so it cannot be used to discover who is registered.
A reset proves you control the mailbox; it deliberately does **not**
reactivate an account an operator has deactivated.

## Password and two-factor authentication

Your password and authenticators are kept by the directory service, but
you manage them from **Settings → Authentication**
on the registry: change your password, add an authenticator app (TOTP),
add a security key or passkey, and remove an enrolled authenticator. Each
action opens one short step in the directory service and brings you
straight back to Settings; the page also lists what is enrolled. Publishing
to a public namespace requires a second factor on the account — the
registry accepts the directory's own evidence that you signed in with one.

## Notifications

**Settings → Profile → Notifications** decides how the registry's alerts reach you.
Email, per kind: a published version of yours declares an MCP server with a
newly known vulnerability; a published version is quarantined by a rescan;
a reviewer decides one of your submissions; an advisory naming one of your
BriefAgents is published; you are added to an organization. In the web app:
whether the dependency-alert banner shows on every page while one of your
versions has an open alert. Everything is on until you change it; your
dashboard lists open alerts whichever way the banner is set, and an
organization's webhooks and audit trail are not affected by your choices.

## Sessions

**Settings → Activity** lists what the account did lately — sign-ins,
tokens and keys created or revoked, profile changes, publishes, reviews,
each with the address and client it came from, so an action you do not
recognise stands out — and every browser session on the account with
its start time, last activity, address and user agent. Revoke one, or
**Sign out everywhere else** to end all but the current one. Revoking a
session invalidates its cookie immediately; it does not revoke personal
access tokens, which are listed and revoked separately.

## Personal access tokens

The CLI and other API clients authenticate with personal access tokens,
managed under **Settings → Authentication**. Tokens are scoped — `repo:read`,
`repo:write`, `agent:publish`, `agent:read`, `org:admin`, `review:act`,
`audit:read`, `user:profile` — and revocable individually; treat them like
the credentials they are.

Neither the **desktop app** nor the **CLI** asks you to paste one.
`agentry login` (on a terminal) and the desktop's "Sign in via browser"
open your browser, you sign in as usual, and one explicit approval page
hands the app a one-time code on a local listener; the app exchanges that
code for a scoped token from its own process, so the token itself never
appears in your browser. `agentry login --paste` still accepts a token from
Settings → Authentication for machines without a browser, and revoking
either kind later is the same list.

## SSH keys

**Settings → Authentication → SSH keys** registers public keys for `git clone
ssh://git@…/ns/name.git` and pushes over SSH, on instances that serve the
SSH transport. A key is worth repository read/write and the release tag
your role allows — never the API — and organizations that enforce SSO take
pushes only over HTTPS with an org-bound token.

## Organizations

Org membership, team roles, SAML/OIDC single sign-on (`/sso/<org>`), and
SCIM provisioning are configured by org admins under the org's admin pages.
A SAML or OIDC connection can be **tested** from the admin page before it
is enforced, and a SAML identity provider's single-logout request ends the
registry session too. Individual sign-in through the directory service
never grants org membership by itself.

## Deleting your account

Account erasure is an API call, `DELETE /api/v1/user`, described under
[API conventions](../api-conventions.md#account-erasure-gdpr): it purges
personal data, revokes every credential, asks you to choose what happens
to any published versions (they are yanked or transferred, never deleted),
and — where the operator has configured it — removes the sign-in account
from the directory service as well.
