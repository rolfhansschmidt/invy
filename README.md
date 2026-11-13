# Invy

A simple shared inventory with spreadsheet editing, OIDC login, and single-editor locking.

## Run

```sh
cp .env.example .env
# Configure the passwords, public URL, and external OIDC provider in .env.
chmod 600 .env
docker compose up --build -d
```

Default address: `http://localhost:8102`. Use HTTPS for public access.
See [INSTALL.md](INSTALL.md) for configuration and Authentik integration.

Users sign in through the external provider. Local admin login is available at `/admin`.

## Data

The entire `data/` folder is mounted into the container. Inventory is stored in
`data/inventory.ods`; changed saves create Git commits in `data/.git` under the username.

Back up the whole `data/` folder. Stop the service before editing the ODS file manually.
