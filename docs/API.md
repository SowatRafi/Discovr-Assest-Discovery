# Optional local REST API

The application is always a native desktop. The API has no website and starts disabled.
Choose **Tools → Local API integration → Enable local API**. Copy the displayed address
and token into your trusted local CMDB/integration client. Enabling grants inventory read/write
and scan control to clients holding that token. No other software is needed to use Discovr itself.

The address is a random port on `127.0.0.1`. Every `/api/` request must include
`X-Discovr-Token: <the displayed token>`. Send JSON mutations with `Content-Type: application/json`.
The token rotates on re-enable and is never put in a URL. The Host must exactly match the
displayed loopback address (or `localhost` with its port). Cross-origin access is not enabled.

| Method / path | Purpose / body |
| --- | --- |
| `GET /api/info` | Host and bundled-provider capabilities |
| `GET /api/state?since=0` | Version, count, jobs and recent activity; pass the last activity sequence as `since` |
| `GET /api/assets` | `{version, assets}`; each asset includes its stable session `_id` |
| `POST /api/assets/import` | A JSON list of asset objects, or `{ "assets": [...] }`; validates before merging |
| `DELETE /api/assets` | Clear inventory; rejected while scans run |
| `POST /api/scans` | Source-specific parameters below; returns a job ID |
| `POST /api/scans/<id>/cancel` | Cooperatively stop one scan, preserving streamed results |
| `POST /api/export` | `{ "format": "csv" }`, `json` or `html`; optional `ids` list filters assets |
| `POST /api/shutdown` | Disable the listener; does not close the desktop or cancel its existing jobs |

Example JSON body for a scan (replace the documentation address with your authorised target):

```json
{"kind":"network","target":"192.0.2.0/24","depth":"quick","intensity":"gentle","environment":"Lab"}
```

Source parameters mirror the native forms:

| `kind` | Parameters |
| --- | --- |
| `network` | Required `target`; optional `ports`, `depth` (`quick`/`standard`), `intensity` (`gentle`/`normal`/`aggressive`) |
| `passive` | `duration` in seconds, 10–3,600 |
| `ad` | Required `domain`, `username`, `password`; optional `dc`, boolean `ldaps`, `caFile` |
| `aws` | `accessKey`, `secretKey`, optional `sessionToken`, `profile`, `region` (default `all`) |
| `azure` | `tenantId`, `clientId`, `clientSecret`, optional `subscription` |
| `gcp` | `credentialsFile`, optional `project`, `zone` |

All support an optional `environment` label (maximum 80 characters). Credentials are used
for the job only and are not returned in job state. Existing SDK credentials can substitute
for explicit cloud credentials. There is no generic plugin loader or vendor-specific CMDB adapter.

For developers, this standard-library Python example retrieves assets from an already enabled
session. Python is needed only to run this example client, not to run Discovr:

```python
import json
from urllib.request import Request, urlopen

address = input("Address shown in Discovr: ").rstrip("/")
token = input("Session token: ")
request = Request(address + "/api/assets", headers={"X-Discovr-Token": token})
with urlopen(request, timeout=10) as response:
    assets = json.load(response)["assets"]
print(f"Received {len(assets)} assets")
```

Choose **Disable local API** when finished. Closing its dialog alone leaves the API enabled;
closing Discovr stops it. Disabling does not revoke work already accepted; use **Stop all**
for scans. Typical errors are `400` invalid input (with a `field` when applicable), `401`
missing/wrong token, `403` unexpected Host, and `404` unknown path. Requests are capped at
32 MB, imports at 65,536 assets, simultaneous scans at four and connections at 32.
