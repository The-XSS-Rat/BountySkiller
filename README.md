# BountySkiller

Flask app with two tools:

1. **Hacktivity & writeup collector** (`/`) — pulls disclosed HackerOne hacktivity or bug
   bounty writeups from the last X months into JSON under `data/`.
2. **Hunt Buddy** (`/hunt`) — runs a full multi-class bug bounty hunt from one target
   profile, in the browser.

```
pip install -r requirements.txt
python app.py          # http://127.0.0.1:5000
```

## Sources (dropdown)

| id | what | notes |
|---|---|---|
| `all` | every source | failing sources are skipped, errors reported per source |
| `hackerone` | HackerOne Hacktivity | live GraphQL, no auth. Program filter + free-text query. Index caps deep paging at 10k rows |
| `pentesterland` | Pentester.land writeups archive | 6.4k curated writeups, but upstream stopped updating 2024-09-18 |
| `medium` | Medium tags: bug-bounty, bug-bounty-writeup, bugbounty, bug-bounty-tips | RSS exposes only ~10 newest per tag |
| `infosecwriteups` | InfoSec Write-ups | RSS, ~10 newest |
| `portswigger` | PortSwigger Research | RSS, ~40 newest |
| `intigriti` | Intigriti blog | RSS |
| `research_blogs` | Project Zero, Assetnote, Datadog Security Labs, samcurry.net | RSS/Atom |
| `google` | Google Programmable Search | needs API keys, max 100 results/query |

Google needs credentials — free tier is 100 queries/day:

```
export GOOGLE_API_KEY=...      # https://developers.google.com/custom-search/v1/introduction
export GOOGLE_CSE_ID=...       # https://programmablesearchengine.google.com/
```

Or pass `google_api_key` / `google_cse_id` as query params.

## Hunt Buddy (`/hunt`)

Browser front-end for the hunt orchestrator: paste a target profile, get a gap analysis,
run every applicable bug-class module, watch progress, read ranked findings.

```bash
HUNT_TOOLS=~/Bounty/claude-bug-bounty/tools python3 app.py
open http://127.0.0.1:5000/hunt
```

`HUNT_TOOLS` points at the [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
`tools/` directory, which supplies the engines. It defaults to `~/Bounty/claude-bug-bounty/tools`.

**Plan first.** The plan table shows every module, whether it can run, and the exact profile
key missing if it cannot:

| | module | class | missing input |
|---|---|---|---|
| RUN | `ssrf` | server-side request forgery | |
| SKIP | `bac` | broken access control | needs 2 authenticated identities, profile has 0 |
| SKIP | `jwt` | JWT forgery | no jwt token in the profile |

A skipped module is never reported as clean.

### Hunt API

- `POST /api/hunt/plan` — body is the profile JSON; returns the module gap analysis. No traffic.
- `POST /api/hunt/run` — `{"profile": {...}, "only": ["ssrf"], "dry_run": false}`
- `GET  /api/hunt/status` — live log, per-module progress, findings so far
- `GET  /api/hunt/report` — final ranked findings, plan, per-module errors

Scope is enforced by the engines themselves: `scope.domains` is required, and a request
outside it is blocked before the socket opens. The page refuses to start a run without one.

## Collector API

- `POST /api/fetch?source=all&months=6&program=nodejs&query=IDOR&min_bounty=500` — start job
- `GET /api/sources` — dropdown contents
- `GET /api/status` — progress, per-source counts, per-source errors
- `GET /api/reports` — newest result set
- `GET /api/files`, `GET /data/<name>` — download

## Output schema

```json
{
  "generated_at": "...", "source": "all", "months": 6, "cutoff": "...",
  "count": 483, "per_source": {"hackerone": 379, "medium": 38},
  "source_errors": {"google": "..."},
  "items": [{
    "source": "hackerone", "kind": "report",
    "title": "...", "url": "...", "published_at": "...",
    "author": "...", "program": "nodejs", "severity": "High",
    "bounty": 1337, "tags": ["Path Traversal", "CVE-2025-24293"],
    "extra": {"report_id": "...", "substate": "resolved", "votes": 11}
  }]
}
```

Items are de-duped by URL across sources and sorted newest-first.

## Gotchas

- HackerOne index field is `team_handle`, not `team.handle` — the latter silently returns 0 hits.
- RSS sources only expose recent posts, so `months=24` returns the same rows as `months=1` for them.
- `bounty` is often `null` — HackerOne only exposes amounts programs chose to disclose. `min_bounty` drops null-bounty rows.
- Requests are rate-limited (0.4s between HackerOne pages). Don't hammer.
