"""Data sources for bug bounty hacktivity / writeups.

Every source exposes fetch(months, cutoff, opts, progress) -> list[dict] using
the unified record schema:

    source, kind, title, url, published_at (ISO8601), author, program,
    severity, bounty, tags, extra
"""

import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
GRAPHQL_URL = "https://hackerone.com/graphql"
PAGE_SIZE = 100
MAX_OFFSET = 10000  # HackerOne index deep-paging cap


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def parse_ts(value):
    """Parse an ISO8601 / 'YYYY-MM-DD' / RFC822 timestamp into aware UTC."""
    if not value:
        return None
    value = value.strip()
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                dt = datetime.strptime(value[:10], "%Y-%m-%d")
            except ValueError:
                return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.isoformat() if dt else None


def strip_html(text):
    if not text:
        return None
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:400] or None


def record(source, kind, title, url, published_at, **kw):
    rec = {
        "source": source,
        "kind": kind,
        "title": title,
        "url": url,
        "published_at": published_at,
        "author": kw.get("author"),
        "program": kw.get("program"),
        "severity": kw.get("severity"),
        "bounty": kw.get("bounty"),
        "tags": kw.get("tags") or [],
        "extra": kw.get("extra") or {},
    }
    return rec


def http_get(url, **kw):
    kw.setdefault("timeout", 30)
    headers = {"User-Agent": UA, "Accept": "*/*"}
    headers.update(kw.pop("headers", {}))
    return requests.get(url, headers=headers, **kw)


# --------------------------------------------------------------------------- #
# HackerOne hacktivity (GraphQL)
# --------------------------------------------------------------------------- #
H1_QUERY = """
query HacktivitySearchQuery($queryString: String!, $size: Int, $from: Int, $sort: SortInput!) {
  search(index: CompleteHacktivityReportIndex, query_string: $queryString, from: $from, size: $size, sort: $sort) {
    total_count
    nodes {
      ... on HacktivityDocument {
        id
        _id
        reporter { id username name }
        cve_ids
        cwe
        severity_rating
        report { id _id title substate url disclosed_at }
        votes
        team { handle name url }
        total_awarded_amount
        latest_disclosable_action
        latest_disclosable_activity_at
        submitted_at
        disclosed_at
        has_collaboration
      }
    }
  }
}
"""


def h1_post(variables, retries=4):
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": variables,
        "query": H1_QUERY,
    }
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/json",
        "Origin": "https://hackerone.com",
        "Referer": "https://hackerone.com/hacktivity",
    }
    last = None
    for attempt in range(retries):
        try:
            resp = requests.post(GRAPHQL_URL, headers=headers, json=payload, timeout=45)
            if resp.status_code in (429, 502, 503, 504):
                last = f"HTTP {resp.status_code}"
                time.sleep(2 ** attempt * 2)
                continue
            resp.raise_for_status()
            body = resp.json()
            if body.get("errors"):
                raise RuntimeError(json.dumps(body["errors"])[:500])
            return body["data"]["search"]
        except requests.RequestException as exc:
            last = str(exc)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"HackerOne GraphQL failed: {last}")


def fetch_hackerone(months, cutoff, opts, progress=None):
    program = opts.get("program")
    query_string = "disclosed:true"
    if program:
        # NOTE: the index field is team_handle — 'team.handle' silently matches nothing.
        query_string += f" AND team_handle:{program}"
    if opts.get("query"):
        query_string += f" AND ({opts['query']})"

    out, seen, offset, scanned = [], set(), 0, 0
    while offset < MAX_OFFSET:
        data = h1_post(
            {
                "queryString": query_string,
                "size": PAGE_SIZE,
                "from": offset,
                "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"},
            }
        )
        nodes = [n for n in (data.get("nodes") or []) if n]
        if not nodes:
            break

        stop = False
        for node in nodes:
            scanned += 1
            report = node.get("report") or {}
            team = node.get("team") or {}
            reporter = node.get("reporter") or {}
            ts = parse_ts(node.get("latest_disclosable_activity_at") or node.get("disclosed_at"))
            if ts and ts < cutoff:
                stop = True
                continue
            rid = report.get("_id") or node.get("_id")
            if rid in seen:
                continue
            seen.add(rid)
            out.append(
                record(
                    "hackerone",
                    "report",
                    report.get("title"),
                    report.get("url"),
                    iso(ts),
                    author=reporter.get("username"),
                    program=team.get("handle"),
                    severity=node.get("severity_rating"),
                    bounty=node.get("total_awarded_amount"),
                    tags=[t for t in [node.get("cwe")] if t] + (node.get("cve_ids") or []),
                    extra={
                        "report_id": rid,
                        "substate": report.get("substate"),
                        "program_name": team.get("name"),
                        "program_url": team.get("url"),
                        "reporter_name": reporter.get("name"),
                        "votes": node.get("votes"),
                        "submitted_at": node.get("submitted_at"),
                        "disclosed_at": report.get("disclosed_at") or node.get("disclosed_at"),
                        "latest_action": node.get("latest_disclosable_action"),
                        "has_collaboration": node.get("has_collaboration"),
                    },
                )
            )
        if progress:
            progress(scanned, len(out))
        if stop or len(nodes) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
        time.sleep(0.4)
    return out


# --------------------------------------------------------------------------- #
# Pentester.land writeups archive
# --------------------------------------------------------------------------- #
PENTESTERLAND_URL = "https://pentester.land/writeups.json"


def fetch_pentesterland(months, cutoff, opts, progress=None):
    resp = http_get(PENTESTERLAND_URL, timeout=60)
    resp.raise_for_status()
    items = resp.json().get("data") or []
    out = []
    for i, item in enumerate(items):
        ts = parse_ts(item.get("PublicationDate") or item.get("AddedDate"))
        if ts is None or ts < cutoff:  # archive dates are reliable; undated rows are noise
            continue
        links = item.get("Links") or [{}]
        bounty = item.get("Bounty")
        if bounty in ("-", ""):
            bounty = None
        out.append(
            record(
                "pentesterland",
                "writeup",
                links[0].get("Title"),
                links[0].get("Link"),
                iso(ts),
                author=", ".join(item.get("Authors") or []) or None,
                program=", ".join(item.get("Programs") or []) or None,
                bounty=bounty,
                tags=item.get("Bugs") or [],
                extra={"added_date": item.get("AddedDate"), "all_links": links},
            )
        )
        if progress and i % 500 == 0:
            progress(i, len(out))
    return out


# --------------------------------------------------------------------------- #
# RSS/Atom writeup feeds
# --------------------------------------------------------------------------- #
FEED_SOURCES = {
    "medium": [
        "https://medium.com/feed/tag/bug-bounty",
        "https://medium.com/feed/tag/bug-bounty-writeup",
        "https://medium.com/feed/tag/bugbounty",
        "https://medium.com/feed/tag/bug-bounty-tips",
    ],
    "infosecwriteups": ["https://infosecwriteups.com/feed"],
    "portswigger": ["https://portswigger.net/research/rss"],
    "intigriti": ["https://blog.intigriti.com/feed/"],
    "research_blogs": [
        "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "https://blog.assetnote.io/feed.xml",
        "https://securitylabs.datadoghq.com/rss/feed.xml",
        "https://samcurry.net/api/feed.rss",
    ],
}
ATOM = "{http://www.w3.org/2005/Atom}"


def parse_feed(xml_text, source, cutoff):
    root = ET.fromstring(xml_text)
    out = []
    for item in root.findall("./channel/item"):
        ts = parse_ts(item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date"))
        if ts and ts < cutoff:
            continue
        cats = [c.text for c in item.findall("category") if c.text]
        out.append(
            record(
                source,
                "writeup",
                item.findtext("title"),
                item.findtext("link"),
                iso(ts),
                author=item.findtext("{http://purl.org/dc/elements/1.1/}creator"),
                tags=cats,
                extra={"summary": strip_html(item.findtext("description"))},
            )
        )
    for entry in root.findall(f"{ATOM}entry"):
        ts = parse_ts(entry.findtext(f"{ATOM}published") or entry.findtext(f"{ATOM}updated"))
        if ts and ts < cutoff:
            continue
        link = entry.find(f"{ATOM}link")
        out.append(
            record(
                source,
                "writeup",
                entry.findtext(f"{ATOM}title"),
                link.get("href") if link is not None else None,
                iso(ts),
                author=entry.findtext(f"{ATOM}author/{ATOM}name"),
                extra={"summary": strip_html(entry.findtext(f"{ATOM}summary"))},
            )
        )
    return out


def make_feed_fetcher(name):
    def fetch(months, cutoff, opts, progress=None):
        out, errors = [], []
        for i, url in enumerate(FEED_SOURCES[name]):
            try:
                resp = http_get(url, allow_redirects=True)
                resp.raise_for_status()
                out.extend(parse_feed(resp.text, name, cutoff))
            except (requests.RequestException, ET.ParseError) as exc:
                errors.append(f"{url}: {exc}")
            if progress:
                progress(i + 1, len(out))
        if not out and errors:
            raise RuntimeError("; ".join(errors)[:500])
        return out

    return fetch


# --------------------------------------------------------------------------- #
# Google Programmable Search (needs GOOGLE_API_KEY + GOOGLE_CSE_ID)
# --------------------------------------------------------------------------- #
GOOGLE_URL = "https://www.googleapis.com/customsearch/v1"
DEFAULT_GOOGLE_QUERY = "bug bounty writeup"


def fetch_google(months, cutoff, opts, progress=None):
    api_key = opts.get("google_api_key") or os.getenv("GOOGLE_API_KEY")
    cse_id = opts.get("google_cse_id") or os.getenv("GOOGLE_CSE_ID")
    if not api_key or not cse_id:
        raise RuntimeError(
            "Google source needs GOOGLE_API_KEY and GOOGLE_CSE_ID "
            "(https://developers.google.com/custom-search/v1/introduction)"
        )
    query = opts.get("query") or DEFAULT_GOOGLE_QUERY
    if opts.get("program"):
        query += f" {opts['program']}"

    out = []
    # The API caps free-text paging at start=91 (100 results).
    for start in range(1, 92, 10):
        params = {
            "key": api_key,
            "cx": cse_id,
            "q": query,
            "num": 10,
            "start": start,
            "dateRestrict": f"m{max(1, int(round(months)))}",
            "sort": "date",
        }
        resp = http_get(GOOGLE_URL, params=params)
        if resp.status_code == 400:
            raise RuntimeError(f"Google API rejected the request: {resp.text[:300]}")
        if resp.status_code in (403, 429):
            raise RuntimeError(f"Google API quota/permission error: {resp.text[:300]}")
        resp.raise_for_status()
        body = resp.json()
        items = body.get("items") or []
        for item in items:
            meta = ((item.get("pagemap") or {}).get("metatags") or [{}])[0]
            ts = parse_ts(
                meta.get("article:published_time")
                or meta.get("datepublished")
                or meta.get("og:updated_time")
                or ""
            )
            if ts and ts < cutoff:
                continue
            out.append(
                record(
                    "google",
                    "writeup",
                    item.get("title"),
                    item.get("link"),
                    iso(ts),
                    extra={"snippet": item.get("snippet"), "display_link": item.get("displayLink")},
                )
            )
        if progress:
            progress(start + len(items) - 1, len(out))
        if len(items) < 10:
            break
        time.sleep(0.3)
    return out


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
SOURCES = {
    "hackerone": {
        "label": "HackerOne Hacktivity (disclosed reports)",
        "fetch": fetch_hackerone,
        "note": "Live GraphQL. Supports program handle filter. Deep paging caps at 10k rows.",
    },
    "pentesterland": {
        "label": "Pentester.land writeups archive",
        "fetch": fetch_pentesterland,
        "note": "Curated archive, 6k+ writeups. Upstream stopped updating in Sep 2024.",
    },
    "medium": {
        "label": "Medium bug bounty tags",
        "fetch": make_feed_fetcher("medium"),
        "note": "RSS — only the ~10 newest posts per tag are exposed.",
    },
    "infosecwriteups": {
        "label": "InfoSec Write-ups",
        "fetch": make_feed_fetcher("infosecwriteups"),
        "note": "RSS — ~10 newest posts.",
    },
    "portswigger": {
        "label": "PortSwigger Research",
        "fetch": make_feed_fetcher("portswigger"),
        "note": "RSS — ~40 newest research posts.",
    },
    "intigriti": {
        "label": "Intigriti blog",
        "fetch": make_feed_fetcher("intigriti"),
        "note": "RSS.",
    },
    "research_blogs": {
        "label": "Research blogs (Project Zero, Assetnote, Datadog, samcurry)",
        "fetch": make_feed_fetcher("research_blogs"),
        "note": "RSS/Atom — newest posts from 4 security research blogs.",
    },
    "google": {
        "label": "Google Programmable Search (API key needed)",
        "fetch": fetch_google,
        "note": "Needs GOOGLE_API_KEY + GOOGLE_CSE_ID env vars. Max 100 results per query.",
    },
}
ALL = "all"


def source_list():
    items = [{"id": ALL, "label": "All sources", "note": "Runs every source, skips ones that fail."}]
    items += [{"id": k, "label": v["label"], "note": v["note"]} for k, v in SOURCES.items()]
    return items


def fetch_source(name, months, cutoff, opts, progress=None):
    if name not in SOURCES:
        raise KeyError(name)
    return SOURCES[name]["fetch"](months, cutoff, opts, progress)
