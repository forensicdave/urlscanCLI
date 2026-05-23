# urlscanCLI

A command-line tool for querying [urlscan.io](https://urlscan.io) to investigate domains, IP addresses, and hostnames. Supports defanged input formats commonly used in threat intelligence reports. Now supports freeform Urlscan search queries use the very extensive set of operators at https://urlscan.io/docs/search/ and brand related queries.

More information: <https://thrunter.org/urlscanCLI>

## Features

- **Domain search** — find previous scans of a domain, with WHOIS registration data and TLS certificate info
- **IP / CIDR search** — find scans observed at a specific IP address or subnet
- **Hostname API** — query the urlscan Hostname API for aggregated observation history (Passive DNS, Certificate Transparency, scan links, etc.)
- **Freeform search** — run arbitrary queries against the urlscan search index using Elasticsearch query syntax
- **Brand tracking** — list tracked phishing brands and view detection statistics per brand
- **Scan report** — fetch and display a full scan result by UUID or result URL
- **Submit for scanning** — submit a URL to urlscan.io and get the result UUID back (private by default)
- **API quota status** — check current rate-limit usage and remaining quota for your API key
- **SHA256 hash lookup** — find scans where a file with a given SHA256 hash was observed
- **Defanged input** — accepts defanged formats such as `example[.]com`, `hxxps://evil[.]com`, `1[.]2[.]3[.]4`, `2001[:]db8::1`
- **JSON output** — machine-readable output via `--json`
- **CSV output** — tabular export via `--csv` for spreadsheet and pipeline workflows
- **macOS Keychain** — store your API key securely, no plaintext config files
- **Debug mode** — inspect every API call with `--debug`

## Requirements

- Python 3.8+
- No third-party dependencies — uses the standard library only
- macOS (for Keychain support; the tool works on other platforms without it)

## Setup

### API key (recommended)

An API key is optional but increases rate limits. Get one free at <https://urlscan.io/user/signup>.

Save it to the macOS Keychain so you never have to pass it on the command line:

```
python3 urlscanCLI.py --save-key YOUR_API_KEY
```

To remove it later:

```
python3 urlscanCLI.py --delete-key
```

You can always override the stored key for a single run with `--api-key KEY`.

## Usage

```
python3 urlscanCLI.py [domain] [--ip ADDR] [--hostname HOST] [--search QUERY] [options]
```

Exactly one of `domain`, `--ip`, `--hostname`, `--scan`, `--urlscan`, `--hash`, or `--search` must be provided.

### Options

| Flag | Description |
|---|---|
| `domain` | Domain to search (positional argument) |
| `--ip ADDR` | IP address or CIDR range to search |
| `--hostname HOST` | Hostname to query via the Hostname API |
| `--scan SCANID` | Fetch a specific scan result by UUID or full result URL |
| `--urlscan URL` | Submit a URL for scanning (requires API key; default: private) |
| `--hash SHA256` | Search for scans containing a file with this SHA256 hash |
| `--search QUERY` | Run a freeform search query (Elasticsearch query syntax) |
| `--brands` | List all brands tracked by urlscan.io's phishing detection |
| `--brand KEY` | Show phishing tracking details for a specific brand key |
| `--public` | Submit with public visibility (use with `--urlscan`) |
| `--unlisted` | Submit with unlisted visibility (use with `--urlscan`) |
| `--wait` | After submitting, wait for the scan to finish and display the full report (use with `--urlscan`) |
| `--json` | Output results as JSON |
| `--csv` | Output scan results as CSV (mutually exclusive with `--json`) |
| `--size N` | Number of results to return (default: 10, max: 10000) |
| `--api-key KEY` | API key to use for this run (overrides keychain) |
| `--save-key KEY` | Save API key to macOS Keychain and exit |
| `--delete-key` | Remove saved API key from macOS Keychain and exit |
| `--status` | Show API quota and rate-limit status for the configured API key and exit |
| `--no-detail` | Skip fetching the full scan result (faster; omits WHOIS and cert data) |
| `--logdir DIR` | Save a copy of the output to a timestamped file in this directory |
| `--debug` / `--DEBUG` | Print debug information to stderr |

## Defanged input formats

The tool automatically normalises common defanging patterns before making any API calls:

| Defanged | Normalised |
|---|---|
| `example[.]com` | `example.com` |
| `example[dot]com` | `example.com` |
| `hxxps://evil[.]com/path` | `evil.com` |
| `1[.]2[.]3[.]4` | `1.2.3.4` |
| `1[.]2[.]3[.]0/24` | `1.2.3.0/24` |
| `2001[:]db8::1` | `2001:db8::1` |
| `2001[:]db8[::]/32` | `2001:db8::/32` |

## Examples

### Domain search

```
python3 urlscanCLI.py example.com
python3 urlscanCLI.py 'example[.]com'
python3 urlscanCLI.py 'hxxps://evil[.]com' --size 25
python3 urlscanCLI.py example.com --json
```

**Sample output:**

```
================================================================
  urlscan.io — urlscan.io
================================================================
  Total scans indexed: 10000   Showing: 2

----------------------------------------------------------------
  Domain Registration (WHOIS)
----------------------------------------------------------------
  Registrar      IONOS SE
  Created        2016-07-04
  Updated        2024-07-04
  Expires        2025-07-04
  Name Servers   ns1.ionos.co.uk, ns1012.ui-dns.com

----------------------------------------------------------------
  TLS Certificates (most recent scan)
----------------------------------------------------------------
  Subject:    urlscan.io
  Issuer:     E7
  Validity:   2026-03-09  →  2026-06-07

----------------------------------------------------------------
  Scan History
----------------------------------------------------------------
  [1] 2026-03-14 12:06:40 UTC
      URL:     https://urlscan.io/
      IP:      49.12.22.106 (DE)  AS24940 HETZNER-AS Hetzner Online GmbH, DE
      Server:  nginx
      Title:   URL and website scanner - urlscan.io
      Report:  https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/
================================================================
```

### IP address search

```
python3 urlscanCLI.py --ip 1.2.3.4
python3 urlscanCLI.py --ip '1[.]2[.]3[.]4'
python3 urlscanCLI.py --ip 192.168.1.0/24 --size 25
python3 urlscanCLI.py --ip 2001:db8::1
python3 urlscanCLI.py --ip '2001[:]db8[::]/32' --json
```

Returns scans where the page was served from that IP or subnet. TLS certificates from the most recent scan are shown; WHOIS is omitted as it is not meaningful for IP lookups.

**Sample output:**

```
================================================================
  urlscan.io — IP 49.12.22.106
================================================================
  Total scans indexed: 10000   Showing: 2

----------------------------------------------------------------
  TLS Certificates (most recent scan)
----------------------------------------------------------------
  Subject:    urlscan.io
  Issuer:     E7
  Validity:   2026-03-09  →  2026-06-07

----------------------------------------------------------------
  Scan History
----------------------------------------------------------------
  [1] 2026-03-14 12:06:40 UTC
      URL:     https://urlscan.io/
      IP:      49.12.22.106 (DE)  AS24940 HETZNER-AS Hetzner Online GmbH, DE
      Server:  nginx
      Title:   URL and website scanner - urlscan.io
      Report:  https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/
================================================================
```

### Hostname API

```
python3 urlscanCLI.py --hostname www.example.com
python3 urlscanCLI.py --hostname 'www.example[.]com' --json
```

Calls the urlscan Hostname API (`/api/v1/hostname/{host}/`), which returns aggregated historical observation data rather than a list of individual scan results. Useful for understanding when and how a hostname first appeared in public data sources.

**Sample output:**

```
================================================================
  urlscan.io Hostname — urlscan.io
================================================================
  Total records: 1000

----------------------------------------------------------------
  Activity Window
----------------------------------------------------------------
  First seen:  2016-09-07 21:42:00 UTC
  Last seen:   2026-03-14 12:50:42 UTC

----------------------------------------------------------------
  Observed In
----------------------------------------------------------------
  Direct scan
    First seen:  2018-02-02 14:06:39 UTC
    Last seen:   2026-03-14 12:47:05 UTC

  Passive DNS
    First seen:  2022-10-19 14:21:53 UTC
    Last seen:   2026-03-14 12:50:42 UTC

  Certificate Transparency
    First seen:  2016-09-07 21:42:00 UTC
    Last seen:   2026-03-09 07:17:39 UTC

  Certificate subject (in scan)
    First seen:  2017-02-08 19:44:32 UTC
    Last seen:   2026-03-14 12:47:05 UTC

  Hyperlink (in scan)
    First seen:  2017-03-10 16:44:21 UTC
    Last seen:   2026-03-14 12:30:59 UTC

================================================================
```

### Scan report

Fetch and display the full result for a specific scan by its UUID. Also accepts a complete result URL — the UUID is extracted automatically.

```
python3 urlscanCLI.py --scan 019cec3d-b942-7124-9337-15b39874e417
python3 urlscanCLI.py --scan https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/
python3 urlscanCLI.py --scan 019cec3d-b942-7124-9337-15b39874e417 --json
```

Text output includes: scan metadata (ID, time, method, visibility), verdict (overall score, urlscan engine, AV engines, community votes), page info (IP, ASN, geo, server, TLS, Umbrella rank), detected technologies, TLS certificates, observed IPs and domains with request counts, outbound links, resource summary, and direct links to the report, screenshot, and DOM capture.

With `--json` the raw API response is returned in full.

**Sample output:**

```
================================================================
  urlscan.io Scan Report
================================================================
  Scan ID:    019cec3d-b942-7124-9337-15b39874e417
  Scanned:    2026-03-14 12:06:40 UTC
  URL:        https://urlscan.io/
  Method:     manual  (web)
  Visibility: public

----------------------------------------------------------------
  Verdict
----------------------------------------------------------------
  Overall:    Clean  (score: 0)
  Engines:    0 malicious / 0 benign / 0 total

----------------------------------------------------------------
  Page
----------------------------------------------------------------
  URL         https://urlscan.io/
  Domain      urlscan.io
  IP          49.12.22.106
  Country     Falkenstein DE
  ASN         AS24940 HETZNER-AS Hetzner Online GmbH, DE
  Server      nginx
  Status      200
  Title       URL and website scanner - urlscan.io
  TLS         E7  (valid from 2026-03-09, 89 days remaining)
  Umbrella    rank #98,140

----------------------------------------------------------------
  Detected Technologies
----------------------------------------------------------------
  Bootstrap                     UI frameworks
  reCAPTCHA                     Security

...

----------------------------------------------------------------
  Report Links
----------------------------------------------------------------
  Report:     https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/
  Screenshot: https://urlscan.io/screenshots/019cec3d-b942-7124-9337-15b39874e417.png
  DOM:        https://urlscan.io/dom/019cec3d-b942-7124-9337-15b39874e417/
================================================================
```

### Submitting a URL for scanning

Submit any URL for scanning with `--urlscan`. An API key is required. The default visibility is **private**; use `--public` or `--unlisted` to change it. Defanged URLs are normalised before submission — the full path and query string are preserved, unlike domain lookups.

```
python3 urlscanCLI.py --urlscan https://example.com
python3 urlscanCLI.py --urlscan 'hxxps://evil[.]com/path?token=abc'
python3 urlscanCLI.py --urlscan https://example.com --public
python3 urlscanCLI.py --urlscan https://example.com --unlisted --json
```

**Sample output:**

```
================================================================
  urlscan.io — Scan Submitted
================================================================
  Message:    Submission successful
  URL:        https://example.com/
  Visibility: private

----------------------------------------------------------------
  Scan Result
----------------------------------------------------------------
  UUID:       019cec91-b5e7-708b-bf76-66d014d3b287
  Result URL: https://urlscan.io/result/019cec91-b5e7-708b-bf76-66d014d3b287/
  API URL:    https://urlscan.io/api/v1/result/019cec91-b5e7-708b-bf76-66d014d3b287/
================================================================
```

The scan runs asynchronously. Use `--scan <UUID>` to retrieve the result manually, or add `--wait` to have the tool poll automatically.

`--public`, `--unlisted`, and `--wait` are all only valid alongside `--urlscan`. `--public` and `--unlisted` are mutually exclusive with each other.

#### Waiting for results automatically

Add `--wait` to submit and block until the full report is available:

```
python3 urlscanCLI.py --urlscan https://example.com --wait
python3 urlscanCLI.py --urlscan https://example.com --wait --json --logdir ./logs
```

Behaviour:
- Submission info (UUID, result URL, visibility) is printed to **stderr**
- The tool waits **30 seconds** then checks for the result
- If not ready, it checks again every **15 seconds** until the scan completes
- The full scan report is printed to **stdout** (identical output to `--scan <UUID>`)
- Progress messages (`Waiting…`, `Not ready yet…`, `Scan complete.`) go to stderr, so stdout remains pipe-friendly

When used with `--logdir`, the final report is saved as a `SCAN_<UUID>` file (same naming as `--scan`).

### JSON output

All modes support `--json`. The top-level `query_type` field identifies the mode (`domain`, `ip`, `cidr`, `hostname`, or `search`).

**Domain:**
```json
{
  "query_type": "domain",
  "query": "example.com",
  "total": 42,
  "whois": { "registrar": "...", "created": "...", ... },
  "certificates": [ { "subject": "...", "issuer": "...", "valid_from": "...", "valid_to": "...", "san": [] } ],
  "scans": [
    {
      "scan_time": "2026-03-14T12:06:40.000Z",
      "url": "https://example.com/",
      "uuid": "...",
      "ip": "1.2.3.4",
      "country": "US",
      "asn": "AS12345",
      "asnname": "EXAMPLE-AS",
      "server": "nginx",
      "title": "Example Domain",
      "malicious": false,
      "score": 0,
      "report_url": "https://urlscan.io/result/.../"
    }
  ]
}
```

**Hostname:**
```json
{
  "query_type": "hostname",
  "query": "www.example.com",
  "total": 419,
  "sources": {
    "scan":             { "first_seen": "2018-09-12T18:03:39.407Z", "last_seen": "2026-03-09T02:06:35.399Z" },
    "pdns":             { "first_seen": "2022-10-19T14:22:11.157Z", "last_seen": "2026-03-14T00:21:07.906Z" },
    "ct":               { "first_seen": "2016-11-20T13:52:19.352Z", "last_seen": "2020-01-18T14:21:13.982Z" },
    "scan-cert-subject":{ "first_seen": "2017-02-08T19:44:32.000Z", "last_seen": "2026-03-14T12:47:05.000Z" },
    "scan-link":        { "first_seen": "2018-04-02T01:31:23.407Z", "last_seen": "2026-02-23T02:33:40.399Z" },
    "seenDates":        { "first_seen": "2016-11-20T13:52:19.352Z", "last_seen": "2026-03-14T00:21:07.906Z" }
  }
}
```

### SHA256 hash lookup

Search for scans where a specific file was observed using its SHA256 hash. Useful in malware triage workflows where you have a file hash and want to know if urlscan has captured any pages that served or referenced that file. The query runs against the `files.sha256` field in the urlscan search index.

```
python3 urlscanCLI.py --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
python3 urlscanCLI.py --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b --json
python3 urlscanCLI.py --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b --size 25
python3 urlscanCLI.py --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b --logdir ./logs
```

The hash must be exactly 64 hexadecimal characters. WHOIS and certificate enrichment are not fetched (they are not meaningful for hash lookups). The scan history output is otherwise identical to a domain or IP search.

**Sample output:**

```
================================================================
  urlscan.io — SHA256 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
================================================================
  Total scans indexed: 3   Showing: 3

----------------------------------------------------------------
  Scan History
----------------------------------------------------------------
  [1] 2026-03-14 09:31:22 UTC
      URL:     https://evil.example.com/payload.exe
      IP:      198.51.100.42 (US)  AS64496 EXAMPLE-ISP
      Server:  Apache
      Title:   File Download
      Report:  https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/

================================================================
```

**JSON output** (`--json`) includes `query_type: "hash"` for easy identification in pipelines:

```json
{
  "query_type": "hash",
  "query": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "total": 3,
  "scans": [
    {
      "scan_time": "2026-03-14T09:31:22.000Z",
      "url": "https://evil.example.com/payload.exe",
      "uuid": "019cec3d-b942-7124-9337-15b39874e417",
      "ip": "198.51.100.42",
      "country": "US",
      "asn": "AS64496",
      "asnname": "EXAMPLE-ISP",
      "server": "Apache",
      "title": "File Download",
      "malicious": false,
      "score": 0,
      "report_url": "https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/"
    }
  ]
}
```

### Freeform search

Run any query against the urlscan.io search API using Elasticsearch query syntax. This gives full access to all searchable fields and supports boolean operators, wildcards, and date ranges.

```
python3 urlscanCLI.py --search 'page.domain:example.com AND page.country:US'
python3 urlscanCLI.py --search 'task.tags:phishing'
python3 urlscanCLI.py --search 'page.server:nginx AND date:>2024-01-01' --size 50
python3 urlscanCLI.py --search 'page.asn:AS13335' --json
python3 urlscanCLI.py --search 'page.domain:example.com' --csv
python3 urlscanCLI.py --search 'filename:malware.exe OR page.title:*login*' --csv --logdir ./logs
```

Common search fields include:

| Field | Description |
|---|---|
| `page.domain` | Domain of the scanned page |
| `page.ip` | IP address the page resolved to |
| `page.url` | Full URL that was scanned |
| `page.server` | Server header value |
| `page.title` | Page title |
| `page.country` | Country code (two-letter, e.g. `US`, `DE`) |
| `page.asn` | ASN (e.g. `AS13335`) |
| `task.tags` | Tags applied to the scan |
| `date` | Scan date (supports ranges: `>2024-01-01`, `[2024-01-01 TO 2024-06-01]`) |
| `filename` | Name of a file observed in the scan |
| `files.sha256` | SHA256 hash of a file observed in the scan |

Combine with `AND`, `OR`, `NOT`, parentheses, and wildcards (`*`). For the full list of queryable fields, see the urlscan.io search documentation.

**Sample output:**

```
================================================================
  urlscan.io — page.domain:example.com AND page.server:cloudflare
================================================================
  Total scans indexed: 10000   Showing: 3

----------------------------------------------------------------
  Scan History
----------------------------------------------------------------
  [1] 2026-05-19 02:01:27 UTC
      URL:     https://example.com/
      IP:      104.20.23.154  AS13335 CLOUDFLARENET - Cloudflare, Inc., US
      Server:  cloudflare
      Title:   Example Domain
      Report:  https://urlscan.io/result/019e3df7-5880-77bd-82d2-7f0fc4fb7fcf/

================================================================
```

**JSON output** (`--json`) includes `query_type: "search"`:

```json
{
  "query_type": "search",
  "query": "page.domain:example.com AND page.server:cloudflare",
  "total": 10000,
  "scans": [
    {
      "scan_time": "2026-05-19T02:01:27.185Z",
      "url": "https://example.com/",
      "uuid": "019e3df7-5880-77bd-82d2-7f0fc4fb7fcf",
      "ip": "104.20.23.154",
      "country": "",
      "asn": "AS13335",
      "asnname": "CLOUDFLARENET - Cloudflare, Inc., US",
      "server": "cloudflare",
      "title": "Example Domain",
      "malicious": false,
      "score": 0,
      "report_url": "https://urlscan.io/result/019e3df7-5880-77bd-82d2-7f0fc4fb7fcf/"
    }
  ]
}
```

### CSV output

All search-based modes (domain, IP, hash, and freeform search) support `--csv` as an alternative to `--json`. CSV output produces a header row followed by one row per scan result, making it ideal for spreadsheet import, `csvkit` pipelines, or quick filtering with `cut`/`awk`.

```
python3 urlscanCLI.py example.com --csv
python3 urlscanCLI.py --ip 1.2.3.4 --csv
python3 urlscanCLI.py --search 'task.tags:phishing' --csv --size 100
python3 urlscanCLI.py --search 'page.domain:example.com' --csv --logdir ./logs
```

`--csv` and `--json` are mutually exclusive.

**Columns:** `scan_time`, `url`, `domain`, `ip`, `country`, `asn`, `asnname`, `server`, `title`, `malicious`, `score`, `report_url`

**Sample output:**

```
scan_time,url,domain,ip,country,asn,asnname,server,title,malicious,score,report_url
2026-05-19T02:01:27.185Z,https://example.com/,example.com,104.20.23.154,,AS13335,"CLOUDFLARENET - Cloudflare, Inc., US",cloudflare,Example Domain,False,0,https://urlscan.io/result/019e3df7-5880-77bd-82d2-7f0fc4fb7fcf/
2026-05-19T02:01:24.499Z,https://example.com/,example.com,2606:4700:10::6814:179a,,AS13335,"CLOUDFLARENET - Cloudflare, Inc., US",cloudflare,Example Domain,False,0,https://urlscan.io/result/019e3df7-4d6d-727f-a78a-dd505dbf1ac0/
```

When used with `--logdir`, the log file is saved with a `.csv` extension.

### Brand tracking

urlscan.io tracks phishing pages targeting well-known brands. The brand API requires a Pro API key.

#### Listing available brands

Use `--brands` to see all brands tracked by urlscan's phishing detection engine:

```
python3 urlscanCLI.py --brands
python3 urlscanCLI.py --brands --json
python3 urlscanCLI.py --brands --csv
```

**Sample output:**

```
================================================================
  urlscan.io — Tracked Brands
================================================================
  Total brands: 2491

----------------------------------------------------------------
  Brand                          Vertical             Country
----------------------------------------------------------------
  Generic                        Online               UN
  Smartsheets                    Online               US
  ESTA                           Government           US
  Canadian Government            Government           CA
  UK Government                  Government           GB
  Microsoft                      Consumer             US
  Google                         Online               US
  ...

================================================================
```

**CSV output** includes full detail: `key`, `name`, `vertical`, `country`, `region`, `keywords`, `domains`, `asns`.

#### Brand phishing detail

Use `--brand KEY` to view phishing detection statistics for a specific brand. The key is the brand identifier shown in `--brands --csv` output (e.g. `microsoft`, `google`, `paypal`):

```
python3 urlscanCLI.py --brand microsoft
python3 urlscanCLI.py --brand google --json
python3 urlscanCLI.py --brand paypal --csv
```

**Sample output:**

```
================================================================
  urlscan.io — Brand: Microsoft
================================================================
  Key:        microsoft
  Vertical:   Consumer
  Country:    US
  Keywords:   microsoft
  Domains:    accesscontrol.windows.net, account.live.com, azure.com, ...
              (+41 more)
  ASNs:       AS16839

----------------------------------------------------------------
  Phishing Detections
----------------------------------------------------------------
  Total detected: 1,208,210

----------------------------------------------------------------
  Most Recent Detection
----------------------------------------------------------------
  Time:       2026-05-19 02:28:01 UTC
  Report:     https://urlscan.io/result/019e3e0f-a44f-713d-bfca-cfc4148ef2ae/

================================================================
```

**JSON output** (`--json`) includes `query_type: "brand"` with full brand metadata, total detection count, and the most recent phishing scan:

```json
{
  "query_type": "brand",
  "query": "microsoft",
  "brand": {
    "name": "Microsoft",
    "key": "microsoft",
    "vertical": ["Consumer"],
    "country": ["us"],
    "terms": { "domains": ["azure.com", "live.com", "..."], "asns": ["AS16839"] }
  },
  "total": 1208210,
  "scans": [
    {
      "scan_time": "2026-05-19T02:28:01.261Z",
      "uuid": "019e3e0f-a44f-713d-bfca-cfc4148ef2ae",
      "report_url": "https://urlscan.io/result/019e3e0f-a44f-713d-bfca-cfc4148ef2ae/"
    }
  ]
}
```

### API quota status

Check current rate-limit usage for your API key with `--status`. An API key is required (from the keychain or `--api-key`). This option does not require a domain, IP, or any other target argument.

```
python3 urlscanCLI.py --status
python3 urlscanCLI.py --status --json
python3 urlscanCLI.py --status --logdir ./logs
```

**Sample output:**

```
================================================================
  urlscan.io — API Quota Status
================================================================
  Scope:        team

----------------------------------------------------------------
  Search
----------------------------------------------------------------
  minute     0 / 5,000       5,000 left  (0%)
  hour      15 / 50,000     49,985 left  (0%)  resets 2026-03-15T08:00:00.000Z
  day      421 / 150,000   149,579 left  (0%)  resets 2026-03-16T00:00:00.000Z
  Last activity: 2026-03-15T07:12:37.284Z  from 34.77.244.210

----------------------------------------------------------------
  Retrieve
----------------------------------------------------------------
  minute     0 / 1,000       1,000 left  (0%)
  hour       0 / 10,000     10,000 left  (0%)
  day       30 / 150,000   149,970 left  (0%)  resets 2026-03-16T00:00:00.000Z
  Last activity: 2026-03-15T06:36:10.874Z  from 34.79.120.104

...

----------------------------------------------------------------
  Account
----------------------------------------------------------------
  Plans:        livescan, pro
  Features:     country-select, genai, livescan/tier/base, tor
  Max results:  10,000
  Retention:    90 days

================================================================
```

With `--json` the raw API response is returned, including all quota windows, account features, queryable fields, and plan details.

### Debug mode

Prints every API call, response size, timing, keychain access, and data-extraction steps to stderr, leaving stdout clean for piping:

```
python3 urlscanCLI.py example.com --debug
python3 urlscanCLI.py example.com --DEBUG   # identical
python3 urlscanCLI.py example.com --debug --json 2>/dev/null | jq .
```

```
[DEBUG] urlscanCLI starting  debug=True
[DEBUG] Loading API key from keychain  service='urlscanCLI'  account='api-key'
[DEBUG] Keychain hit  key=0199...8c77
[DEBUG] API key source: keychain  key=0199...8c77
[DEBUG] Defang  'example.com'  (no changes)
[DEBUG] Resolved domain: 'example.com'
[DEBUG] Search query: 'page.domain:example.com'  size=10
[DEBUG] GET https://urlscan.io/api/v1/search/?q=page.domain%3Aexample.com&size=10
[DEBUG]     API key: 0199...8c77
[DEBUG]     HTTP 200  18432 bytes  1.24s
[DEBUG] Search returned 10 hits  total=523  has_more=True
...
```

## API endpoints used

| Mode | Endpoint |
|---|---|
| Domain search | `GET /api/v1/search/?q=page.domain:{domain}` |
| IP / CIDR search | `GET /api/v1/search/?q=page.ip:{ip}` (CIDR uses ES range syntax) |
| Freeform search (`--search`) | `GET /api/v1/search/?q={query}` |
| Available brands (`--brands`) | `GET /api/v1/pro/availableBrands` |
| Brand detail (`--brand`) | `GET /api/v1/pro/brands` |
| Scan detail (WHOIS, certs) | `GET /api/v1/result/{uuid}/` |
| Hostname | `GET /api/v1/hostname/{hostname}/` |
| Scan report (`--scan`) | `GET /api/v1/result/{uuid}/` |
| URL submission (`--urlscan`) | `POST /api/v1/scan/` |
| SHA256 hash lookup (`--hash`) | `GET /api/v1/search/?q=files.sha256:{hash}` |
| Quota status (`--status`) | `GET https://urlscan.io/user/quotas/` (not under `/api/v1/`) |

## Logging output

Use `--logdir DIR` to save a copy of every response to a file. The directory must already exist. A new file is created for each run using the naming scheme:

```
URLSCAN_<YYYYmmDD_HHMMSS>_<OPERATION>_<query>.<ext>
```

| Mode | OPERATION | query | ext |
|---|---|---|---|
| Domain search | `RESULTS` | domain name (dots → `_`) | `.txt` / `.json` / `.csv` |
| IP / CIDR search | `IP` | address (dots, `/` → `_`) | `.txt` / `.json` / `.csv` |
| Hostname API | `HOST` | hostname (dots → `_`) | `.txt` / `.json` |
| Scan report | `SCAN` | UUID (hyphens preserved) | `.txt` / `.json` |
| URL submission | `URLSCAN` | hostname from submitted URL | `.txt` / `.json` |
| SHA256 hash lookup | `HASH` | full SHA256 hex string | `.txt` / `.json` / `.csv` |
| Freeform search | `SEARCH` | query string (special chars → `_`) | `.txt` / `.json` / `.csv` |
| Brand list | `BRANDS` | *(none)* | `.txt` / `.json` / `.csv` |
| Brand detail | `BRAND` | brand key | `.txt` / `.json` / `.csv` |
| Quota status | `STATUS` | *(none)* | `.txt` / `.json` |

Examples:

```
URLSCAN_20260314_120640_RESULTS_evil_com.txt
URLSCAN_20260314_120641_IP_49_12_22_0_24.json
URLSCAN_20260314_120642_HOST_www_evil_com.txt
URLSCAN_20260314_120643_SCAN_019cec3d-b942-7124-9337-15b39874e417.txt
URLSCAN_20260314_120644_HASH_6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.txt
URLSCAN_20260314_120645_SEARCH_page_domain_example_com.csv
URLSCAN_20260314_120646_BRANDS.csv
URLSCAN_20260314_120647_BRAND_microsoft.txt
URLSCAN_20260314_120648_STATUS.txt
```

The log notification is written to stderr so it does not contaminate stdout pipelines. If the directory does not exist the tool exits with an error before making any API calls.

## Notes

- The urlscan.io API rate-limits unauthenticated requests. An API key is strongly recommended for regular use.
- The `--size` limit applies to the search modes (domain, IP, hash, and freeform search). The Hostname API always returns its full result set (up to 1000 records).
- WHOIS and certificate data are sourced from the most recent scan result and reflect what urlscan observed at that point in time.
- IPv6 addresses and CIDR ranges are automatically translated to Elasticsearch range query syntax, which the urlscan search API requires.
