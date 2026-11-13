# Installation and external Authentik integration

Invy is an OAuth2/OIDC relying party. Run your identity provider separately.
This repository deliberately does not provision an Authentik server or demo users.

## 1. Configure Invy

Install Docker Engine and Docker Compose, then clone the repository:

```sh
git clone git@github.com:rolfhansschmidt/invy.git
cd invy
cp .env.example .env
chmod 600 .env
```

Generate two independent long random values:

```sh
python3 -c 'import secrets; print("ADMIN_PASSWORD=" + secrets.token_urlsafe(48)); print("SESSION_SECRET=" + secrets.token_urlsafe(48))'
```

Replace those entries in `.env`. The generated admin password is used only at
`https://inventory.example.com/admin`. It is not an Authentik account password.
Do not use the example placeholder values or commit `.env` to Git.

Set `PUBLIC_URL` to the exact external origin, without a path or trailing slash,
e.g. `https://inventory.example.com`. For HTTPS set `SESSION_COOKIE_SECURE=true`.
Use false only for a local HTTP development setup. Production startup rejects
HTTPS with insecure cookies. The `__Host-` cookie prefix prevents sibling-domain
cookie injection; configure only the origin in `PUBLIC_URL`. `PUBLIC_URL` determines the
OAuth callback URL; untrusted Host/forwarded headers cannot change that callback.

`INVY_PORT` defaults to 8102 and `INVY_BIND_ADDRESS` to 127.0.0.1. Set `INVY_UID`
and `INVY_GID` to match the owner of `data/`. Only `/data` and a temporary filesystem
are writable in the container. The whole data folder is mounted, including its
administrator-only Git history and `.security.json` session/throttle registry.
Do not remove this registry to bypass a login throttle; deleting it revokes all
sessions and resets rate-limit state. Back it up with the data directory.

## 2. Create the Authentik application and provider

In your existing Authentik instance, open the admin interface:

1. Go to **Applications → Applications → Create with Provider**.
2. Set application name **Invy**, slug **invy**, and launch URL to
   `https://inventory.example.com`.
3. Choose **OAuth2/OpenID Provider**. Set a provider name such as **Invy**.
4. Select the desired authorization flow. The default implicit-consent provider
   authorization flow permits SSO without a separate consent screen; explicit
   consent is also compatible. Select the default provider invalidation flow
   if prompted. This is still the authorization-code grant, not the OAuth
   implicit grant.
5. Set **Client type: Confidential**. Keep or generate the **Client ID** and
   **Client Secret**; copy them to Invy's `.env` privately.
6. Enable **Authorization Code** if the provider version exposes grant-type
   selection. Invy uses PKCE S256. Password and implicit grants are not required.
7. Add this **strict** authorization redirect URI exactly:
   `https://inventory.example.com/auth/callback`. Do not use a wildcard or leave
   the redirect list empty. For an HTTP local test use the matching localhost URI
   instead, with the same `/auth/callback` path.
8. Select a signing key, such as **authentik Self-signed Certificate**, so ID
   tokens use asymmetric signatures verified against the provider's JWKS.
9. Select the default **openid**, **profile** and **email** scope mappings. Enable
   **Include claims in ID token**; Invy reads username and optional groups from
   the verified ID token. Keep issuer mode **per provider** for the usual setup.
10. Finish creation and ensure the application is linked to that provider.
11. In the application's policy/group/user bindings, allow only the users or groups
    that should access Invy. Those users receive read and edit access in Invy.

UI labels can vary between Authentik versions. The protocol settings above are
what matter. See the official [Authentik OAuth2 provider documentation](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
and [application documentation](https://docs.goauthentik.io/add-secure-apps/applications/).

## 3. Copy discovery and client settings

For application slug `invy`, the discovery document is normally:

```text
https://auth.example.com/application/o/invy/.well-known/openid-configuration
```

Open that document and copy its **issuer** value exactly, including its trailing
slash if present. With per-provider issuer mode this is normally
`https://auth.example.com/application/o/invy/`. Global issuer mode has a different
issuer, but the discovery URL still includes the application slug. Invy supports
that through the separate `OIDC_DISCOVERY_URL` override.

Set in `.env`:

```dotenv
PUBLIC_URL=https://inventory.example.com
SESSION_COOKIE_SECURE=true
OIDC_ISSUER_URL=https://auth.example.com/application/o/invy/
OIDC_DISCOVERY_URL=https://auth.example.com/application/o/invy/.well-known/openid-configuration
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_SCOPES=openid profile email
OIDC_USERNAME_CLAIM=preferred_username
OIDC_TOKEN_AUTH_METHOD=client_secret_basic
```

Authentik's default profile mapping supplies `preferred_username`. For another
OIDC provider, configure `OIDC_USERNAME_CLAIM` to its username claim. If absent,
Invy falls back to the stable subject (`sub`). Invy requires OIDC on top of OAuth2;
a generic OAuth2 service without signed ID tokens is not sufficient for login.

Optionally set `OIDC_ALLOWED_GROUPS=invy-users,inventory-admins` and
`OIDC_GROUPS_CLAIM=groups`. Invy permits membership in any listed group. Ensure
Authentik's profile/custom scope mapping emits this list in the ID token. Leave
`OIDC_ALLOWED_GROUPS` empty to rely only on Authentik's application bindings.

The public issuer and its discovery/JWKS/token endpoints must be reachable from
the Invy container with valid HTTPS certificates. Do not disable TLS verification.

## 4. Reverse proxy and start

Configure HTTPS on your public proxy, routing to the host's loopback port 8102.
If nginx shares this host, a typical internal HTTP virtual host is:

```nginx
server {
    listen 80;
    server_name inventory.example.com;
    client_max_body_size 8m;
    location / {
        proxy_pass http://127.0.0.1:8102;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Disable access logging of OAuth callback query strings as in
`deploy/nginx.conf`; authorization codes should not be recorded in access logs.

The public HTTPS terminator routes to this internal virtual host. The app uses
its configured `PUBLIC_URL` and Secure cookies rather than trusting incoming
forwarded protocol headers. If nginx terminates HTTPS itself, configure its TLS
listener and certificate instead. Do not make `/data` or `data/.git` web-accessible.

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f
```

For systemd-managed startup, adapt `deploy/invy.service`, install it in
`/etc/systemd/system/`, then run `systemctl daemon-reload` and
`systemctl enable --now invy.service`.

## 5. Verify

1. Open Invy in a private window: it must redirect through Authentik and return to
   Invy after login. The password form must appear only at `/admin`.
2. Edit a cell and save. On the host, `git -C data log -1 --format='%an: %s'` must
   show that user's username as author and commit message.
3. Open another browser while editing: it may view inventory but cannot acquire
   the editing lease until the first editor saves/cancels or its lease expires.
4. Sign out, visit `/admin`, and use `ADMIN_PASSWORD`. A changed save is attributed
   to `ADMIN_USERNAME` (default `admin`).
5. Restart the container and verify the inventory and Git history remain in `data/`.

A redirect mismatch usually means `PUBLIC_URL` and the provider's strict callback
URI differ. Issuer errors mean `OIDC_ISSUER_URL` does not match discovery's issuer
exactly. If sign-in succeeds but a user is denied, check application bindings,
allowed groups and the ID-token mappings. A missing provider fails closed with a
setup message while `/admin` remains usable. Authentik sessions are separate from
Invy's local session: Sign out ends Invy access, while a subsequent sign-in can
reuse the existing provider session.
