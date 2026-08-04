"""Bug bounty hacktivity / writeup collector — web app.

Pulls disclosed HackerOne hacktivity or bug bounty writeups (Google, RSS blogs,
Pentester.land) from the last X months and writes them to a JSON file.

Run:  python app.py   ->  http://127.0.0.1:5000
"""

import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template_string, request, send_from_directory

import sources as src
from hunt_web import hunt_bp

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

app = Flask(__name__)
app.register_blueprint(hunt_bp)   # /hunt — multi-class bug bounty orchestration

JOB = {
    "running": False,
    "status": "idle",
    "scanned": 0,
    "kept": 0,
    "months": None,
    "source": None,
    "per_source": {},
    "errors": {},
    "file": None,
    "error": None,
    "started_at": None,
    "finished_at": None,
}
JOB_LOCK = threading.Lock()


def bounty_value(raw):
    """Best-effort numeric bounty. Sources report '$500', 500.0, '-' or None."""
    if raw is None:
        return -1.0
    if isinstance(raw, (int, float)):
        return float(raw)
    digits = re.sub(r"[^0-9.]", "", str(raw))
    try:
        return float(digits) if digits else -1.0
    except ValueError:
        return -1.0


def cutoff_for(months):
    return datetime.now(timezone.utc) - timedelta(days=months * 30.44)


def collect(months, source, opts, on_progress=None):
    """Run one source (or all) and return (records, per_source counts, errors)."""
    cutoff = cutoff_for(months)
    names = list(src.SOURCES) if source == src.ALL else [source]

    records, counts, errors = [], {}, {}
    for name in names:
        def progress(scanned, kept, _name=name):
            if on_progress:
                on_progress(_name, scanned, kept)

        try:
            got = src.fetch_source(name, months, cutoff, opts, progress)
        except Exception as exc:  # noqa: BLE001 - one bad source must not kill the run
            errors[name] = str(exc)[:500]
            counts[name] = 0
            if source != src.ALL:
                raise
            continue
        counts[name] = len(got)
        records.extend(got)

    min_bounty = opts.get("min_bounty")
    if min_bounty is not None:
        records = [r for r in records if bounty_value(r.get("bounty")) >= min_bounty]

    # De-dup by URL across sources, keep the first (source order) hit.
    seen, deduped = set(), []
    for rec in records:
        key = (rec.get("url") or "").rstrip("/").lower() or json.dumps(rec, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)

    deduped.sort(key=lambda r: r.get("published_at") or "", reverse=True)
    return deduped, counts, errors, cutoff


def write_output(records, months, source, cutoff, opts, counts, errors):
    os.makedirs(DATA_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{source}_{months:g}m_{stamp}.json"
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "months": months,
        "cutoff": cutoff.isoformat(),
        "filters": {k: v for k, v in opts.items() if not k.startswith("google_")},
        "count": len(records),
        "per_source": counts,
        "source_errors": errors,
        "items": records,
    }
    with open(os.path.join(DATA_DIR, name), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(DATA_DIR, "latest.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    return name


def run_job(months, source, opts):
    def on_progress(name, scanned, kept):
        with JOB_LOCK:
            JOB["scanned"] = scanned
            JOB["per_source"][name] = kept
            JOB["kept"] = sum(JOB["per_source"].values())
            JOB["status"] = f"{name}: scanned {scanned}, kept {kept}"

    try:
        records, counts, errors, cutoff = collect(months, source, opts, on_progress)
        name = write_output(records, months, source, cutoff, opts, counts, errors)
        with JOB_LOCK:
            JOB["file"] = name
            JOB["kept"] = len(records)
            JOB["per_source"] = counts
            JOB["errors"] = errors
            JOB["status"] = f"done — {len(records)} items -> data/{name}"
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        with JOB_LOCK:
            JOB["error"] = str(exc)
            JOB["status"] = "failed"
    finally:
        with JOB_LOCK:
            JOB["running"] = False
            JOB["finished_at"] = datetime.now(timezone.utc).isoformat()


PAGE = """
<!doctype html>
<title>Bounty Skiller — hacktivity & writeup collector</title>
<style>
 body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;margin:40px auto;padding:0 20px;background:#0f1115;color:#e6e6e6}
 h1{font-size:22px} label{display:block;margin:14px 0 4px;color:#9aa4b2;font-size:13px}
 input,select{width:100%;padding:9px;border-radius:6px;border:1px solid #2a2f3a;background:#171a21;color:#e6e6e6}
 button{margin-top:18px;padding:10px 18px;border:0;border-radius:6px;background:#4f8cff;color:#fff;font-weight:600;cursor:pointer}
 button:disabled{opacity:.5;cursor:default}
 pre{background:#171a21;padding:14px;border-radius:8px;overflow:auto;border:1px solid #2a2f3a;max-height:420px}
 a{color:#4f8cff} .row{display:flex;gap:14px;flex-wrap:wrap} .row>div{flex:1;min-width:190px}
 .note{color:#7c8698;font-size:12px;margin-top:6px;min-height:16px}
</style>
<h1>Bug bounty hacktivity &amp; writeups → JSON</h1>
<p>Pick a source, pick how far back to go, get a JSON file under <code>data/</code>.
&nbsp;·&nbsp; <a href="/hunt">Hunt Buddy →</a></p>

<label>Source</label>
<select id="source" onchange="showNote()"></select>
<div class="note" id="note"></div>

<div class="row">
  <div><label>Months back</label><input id="months" type="number" value="6" min="1" max="120" step="1"></div>
  <div><label>Program / keyword (optional)</label><input id="program" placeholder="e.g. nodejs"></div>
  <div><label>Free-text query (optional)</label><input id="query" placeholder="e.g. IDOR account takeover"></div>
  <div><label>Min bounty $ (optional)</label><input id="minb" type="number" placeholder="0"></div>
</div>
<button id="go" onclick="start()">Fetch</button>
<pre id="out">idle</pre>

<script>
let SOURCES=[], timer=null;
async function init(){
  SOURCES=await (await fetch('/api/sources')).json();
  source.innerHTML=SOURCES.map(s=>`<option value="${s.id}">${s.label}</option>`).join('');
  showNote();
}
function showNote(){
  const s=SOURCES.find(x=>x.id===source.value); note.textContent=s?s.note:'';
}
async function start(){
  go.disabled=true;
  const q=new URLSearchParams({source:source.value,months:months.value,program:program.value,query:query.value,min_bounty:minb.value});
  const r=await fetch('/api/fetch?'+q,{method:'POST'});
  const j=await r.json();
  if(!r.ok){out.textContent=JSON.stringify(j,null,2);go.disabled=false;return;}
  timer=setInterval(poll,1200); poll();
}
async function poll(){
  const j=await (await fetch('/api/status')).json();
  out.textContent=JSON.stringify(j,null,2)+(j.file?"\\n\\nDownload: /data/"+j.file:"");
  if(!j.running){clearInterval(timer);go.disabled=false;}
}
init();
</script>
"""


@app.get("/")
def index():
    return render_template_string(PAGE)


@app.get("/api/sources")
def api_sources():
    return jsonify(src.source_list())


@app.post("/api/fetch")
def api_fetch():
    with JOB_LOCK:
        if JOB["running"]:
            return jsonify({"error": "a fetch is already running"}), 409

    source = (request.args.get("source") or src.ALL).strip()
    if source != src.ALL and source not in src.SOURCES:
        return jsonify({"error": f"unknown source '{source}'", "valid": [src.ALL] + list(src.SOURCES)}), 400

    try:
        months = float(request.args.get("months") or 6)
    except ValueError:
        return jsonify({"error": "months must be a number"}), 400
    if not 0 < months <= 120:
        return jsonify({"error": "months must be between 0 and 120"}), 400

    raw_min = (request.args.get("min_bounty") or "").strip()
    try:
        min_bounty = float(raw_min) if raw_min else None
    except ValueError:
        return jsonify({"error": "min_bounty must be a number"}), 400

    opts = {
        "program": (request.args.get("program") or "").strip() or None,
        "query": (request.args.get("query") or "").strip() or None,
        "min_bounty": min_bounty,
        "google_api_key": request.args.get("google_api_key") or None,
        "google_cse_id": request.args.get("google_cse_id") or None,
    }

    with JOB_LOCK:
        JOB.update(
            running=True,
            status="starting",
            scanned=0,
            kept=0,
            months=months,
            source=source,
            per_source={},
            errors={},
            file=None,
            error=None,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
    threading.Thread(target=run_job, args=(months, source, opts), daemon=True).start()
    return jsonify({"started": True, "source": source, "months": months, "filters": opts})


@app.get("/api/status")
def api_status():
    with JOB_LOCK:
        return jsonify(dict(JOB))


@app.get("/api/reports")
def api_reports():
    path = os.path.join(DATA_DIR, "latest.json")
    if not os.path.exists(path):
        return jsonify({"error": "no data yet — run a fetch first"}), 404
    with open(path, encoding="utf-8") as fh:
        return jsonify(json.load(fh))


@app.get("/api/files")
def api_files():
    if not os.path.isdir(DATA_DIR):
        return jsonify([])
    return jsonify(sorted(os.listdir(DATA_DIR), reverse=True))


@app.get("/data/<path:name>")
def download(name):
    return send_from_directory(DATA_DIR, name, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
