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
page you started from. **Sign out** ends both sessions — the registry's and
the directory's — so signing out actually signs you out.

Forgot your password? **"Forgot username or password?"** on the sign-in
page mails a reset link. The form gives the same answer whether or not the
address has an account, so it cannot be used to discover who is registered.
A reset proves you control the mailbox; it deliberately does **not**
reactivate an account an operator has deactivated.

## Personal access tokens

The CLI and other API clients authenticate with personal access tokens,
managed under **Settings → Tokens**. Tokens are scoped (publishing, repo
access, profile) and revocable individually; treat them like the
credentials they are.

The **desktop app** never asks you to paste one. It opens your browser,
you sign in as usual, and one explicit approval page hands the app a
one-time code on a local listener; the app exchanges that code for a scoped
token from its own process, so the token itself never appears in your
browser. Revoking it later is the same Settings → Tokens list.

## Organizations

Org membership, team roles, SAML/OIDC single sign-on (`/sso/<org>`), and
SCIM provisioning are configured by org admins under the org's admin pages.
Individual sign-in through the directory service never grants org
membership by itself.
