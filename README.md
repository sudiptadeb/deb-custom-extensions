# deb-custom-extensions

A small Go service that **hosts support-authored Chromium/Ulaa extensions for
force-install**. Point it at a directory of unpacked extension folders; for each
valid folder it signs a **CRX3**, derives a **stable extension ID**, and serves
the CRX plus an **Omaha update manifest** with the exact headers a managed
browser needs.

The support team writes the extension that solves a customer's request (e.g.
"block this one JavaScript file via `declarativeNetRequest`"), drops the folder
in, and hands the customer **one line** to paste into the Ulaa Enterprise
`ExtensionInstallForcelist` policy:

```
<extension_id>;https://<your-host>/updates/<name>.xml
```

## Why this instead of a CDN

Force-installed off-store extensions are delivered through the `update_url` half
of `ExtensionInstallForcelist` — an XML update manifest pointing at a CRX. The
CRX must be served as opaque bytes (correct `Content-Type`, no recompression, no
rewriting, no stale caching). A plain CDN typically can't guarantee those
headers, so this service serves both files itself:

- `/crx/<name>.crx` → `Content-Type: application/x-chrome-extension`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
- `/updates/<name>.xml` → `Content-Type: application/xml`, `Cache-Control: no-store`

Put it behind TLS termination (ALB / nginx / Caddy) and pass `-base-url` so the
manifest advertises the public HTTPS URL.

## Layout

```
extensions/              # one folder per extension (support team edits these)
  block-axa-endosos/
    manifest.json        # MV3 manifest with a declarative_net_request ruleset
    rules.json           # the block rules
data/keys/               # one persisted RSA key per extension (auto-created)
  block-axa-endosos.pem  # <-- BACK THIS UP. It is the extension's identity.
```

A folder is "valid" when it contains a `manifest.json` that parses and has a
non-empty `version`. Invalid folders are listed on the index page with the
reason, and are not served.

## Run

```sh
go run . -base-url https://ext.your-domain.com
# or build and ship a single static binary to EC2:
go build -o deb-custom-extensions .
./deb-custom-extensions -addr :8080 -base-url https://ext.your-domain.com
```

Open `http://localhost:8080/` for the dashboard: each extension shows its ID,
version, the ready-to-paste policy value, and the manifest/CRX links.

Flags:

| flag | default | meaning |
| --- | --- | --- |
| `-addr` | `:8080` | listen address |
| `-ext-dir` | `extensions` | directory of extension folders |
| `-key-dir` | `data/keys` | where signing keys are persisted (back up!) |
| `-base-url` | _(derived)_ | public base URL used in manifest links |
| `-scan-interval` | `15s` | how often to rescan for changes (`0` disables) |

The directory is rescanned every `-scan-interval`, on each visit to the index
page, and on `POST /reload`. New/changed folders go live automatically;
unchanged folders are not repacked.

## Adding an extension (support workflow)

1. Create `extensions/<slug>/` (slug = lowercase letters, digits, `-`, `_`).
2. Write `manifest.json` (Manifest V3) and any resources it needs.
3. Refresh the index page; copy the **policy value** to the customer.
4. The customer adds it to Ulaa Enterprise → `ExtensionInstallForcelist`.

### Updating a deployed extension

Bump `"version"` in `manifest.json` (e.g. `1.0.0` → `1.0.1`) and save. The
manifest advertises the new version and managed browsers pull the update on
their next poll. **Do not delete `data/keys/<slug>.pem`** — that file fixes the
extension ID; regenerating it would orphan every installed copy.

## The included example: blocking one JavaScript subresource

`extensions/block-axa-endosos/` answers the real customer case — block
`axa_endosos.js` while leaving the rest of `portal.axa.com.mx` working. This is
exactly the gap site-blocking can't fill: URL/site policies match the top-frame
address bar, not subresources. A `declarativeNetRequest` rule does:

```json
{
  "id": 1,
  "priority": 1,
  "action": { "type": "block" },
  "condition": {
    "urlFilter": "||portal.axa.com.mx/.../js/axa_endosos.js",
    "resourceTypes": ["script", "xmlhttprequest", "sub_frame"]
  }
}
```

To block the module's Fetch/XHR endpoints too, add more rules with the endpoint
paths in `urlFilter` and `"resourceTypes": ["xmlhttprequest"]`. The `block`
action needs only the `declarativeNetRequest` permission — no host permissions.

## Notes & limits

- **CRX3 / signing** is implemented from the spec in `internal/crx` (no external
  deps). `go test ./...` verifies a packed CRX against its own signature the way
  a Chromium client would, and checks ID stability.
- **Keys are the identity.** Treat `data/keys/` like secrets: restrict access and
  back it up. A lost key = new ID = every managed install breaks.
- **Folder name = URL slug.** Keep it to `[A-Za-z0-9_-]`.
- Ulaa is Chromium-based, so the policy name and update mechanism match Chrome's
  `ExtensionInstallForcelist`.
```
